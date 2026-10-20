//! The app API in front of an app (`app.proxy`): requests that aren't the API's own (`ours`) go on to an upstream such
//! as Next.js on 127.0.0.1:3000, over a pool of kept-alive HTTP/1.1 connections. Bodies stream both ways (a page that
//! renders in pieces arrives in pieces), WebSocket upgrades are piped through, and the upstream learns who asked:
//! `X-Forwarded-For`, `-Proto` and `-Host`. Headers named `X-Sqz-…` are the API's to set: a client's are dropped.
//!
//! Also here: who a request is from when the API itself sits behind proxies of yours (`app.trustProxy`).
use crate::app::{full, Body};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::net::IpAddr;
use std::time::Duration;

/// Headers of one connection, not of the request (RFC 9110 7.6.1), and what this server handles itself (`Expect`).
const HOP: [&str; 10] = ["connection", "keep-alive", "proxy-connection", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "expect", "http2-settings"];

/// Whether a request is the app API's own: its endpoints, matched exactly, so an app's own `/api/…` routes still reach
/// the app. With `app.proxy` unset, everything is the API's (unknown paths get its 404).
pub(crate) fn ours(sql: &crate::sql::Sql, path: &str) -> bool {
    if sql.cfg.app.mcp.is_some() && (path == "/mcp" || path.starts_with("/oauth/") || path.starts_with("/.well-known/oauth-")) { return true; }
    if path.starts_with("/_sqz/") { return true; }
    let p: Vec<&str> = path.trim_matches('/').split('/').collect();
    matches!(p.as_slice(),
        ["api", "sql" | "batch" | "me" | "socket" | "client.js" | "files"] | ["api", "fn", _] | ["api", "files", _] | ["api", "auth", "sign-out" | "exchange" | "device"] | ["api", "auth", "device", "token"]
        | ["api", "auth", _, "sign-up" | "sign-in" | "methods"] | ["api", "auth", _, "oauth", _] | ["api", "auth", _, "oauth", _, "callback"])
}

/// The app behind the API: where it is, the pool of connections to it, and the requests it may have in flight at once
/// (each holds a connection until its response is through).
pub(crate) struct Upstream { client: Client<HttpConnector, Body>, base: String, wait: Duration, slots: std::sync::Arc<tokio::sync::Semaphore> }
impl Upstream {
    pub(crate) fn new(p: &crate::config::ProxyPolicy) -> Upstream {
        let mut c = HttpConnector::new(); c.set_nodelay(true); c.set_connect_timeout(Some(Duration::from_secs(5)));
        let client = Client::builder(TokioExecutor::new()).pool_idle_timeout(Duration::from_secs(30)).pool_max_idle_per_host(p.connections).build(c);
        Upstream { client, base: p.to.trim_end_matches('/').to_string(), wait: p.timeout, slots: std::sync::Arc::new(tokio::sync::Semaphore::new(p.connections)) }
    }
    /// Send `req` on to the app and its answer back. `client`: who the request is from; `tls`: whether it came over
    /// https; `set`: headers the API adds (`X-Sqz-…`).
    pub(crate) async fn forward(&self, mut req: hyper::Request<Incoming>, client: IpAddr, peer: IpAddr, trusted: bool, tls: bool, set: &[(String, String)]) -> hyper::Response<Body> {
        // a WebSocket only: another upgrade (h2c, say) would leave a raw tunnel to the app, its later requests seen by
        // no middleware and carrying whatever headers the client likes
        let upgrade = req.version() == hyper::Version::HTTP_11 && req.headers().get(hyper::header::UPGRADE).is_some_and(|u| u.as_bytes().eq_ignore_ascii_case(b"websocket"));
        let on_client = upgrade.then(|| hyper::upgrade::on(&mut req));
        let (parts, body) = req.into_parts();
        let target = format!("{}{}", self.base, parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/"));
        let host = parts.headers.get(hyper::header::HOST).and_then(|h| h.to_str().ok()).map(String::from).or_else(|| parts.uri.authority().map(|a| a.to_string())).unwrap_or_default();
        let mut headers = forwardable(&parts.headers, upgrade);
        // who asked: the chain a trusted proxy passed on, with that proxy; otherwise just the client. A client's own
        // Forwarded and X-Real-IP go too, unless a trusted proxy set them.
        let fields: Vec<&str> = parts.headers.get_all("x-forwarded-for").iter().filter_map(|v| v.to_str().ok()).collect();
        let chain = if trusted && !fields.is_empty() { format!("{}, {peer}", fields.join(", ")) } else { client.to_string() };
        let proto = parts.headers.get("x-forwarded-proto").and_then(|v| v.to_str().ok()).filter(|_| trusted).map(String::from).unwrap_or_else(|| if tls { "https" } else { "http" }.into());
        if !trusted { headers.remove("forwarded"); }
        for (k, v) in [("x-forwarded-for", chain), ("x-forwarded-proto", proto), ("x-forwarded-host", host.clone()), ("x-real-ip", client.to_string()), ("host", host)] { if let Ok(v) = HeaderValue::from_str(&v) { headers.insert(HeaderName::from_static(k), v); } }
        for (k, v) in set { if let (Ok(k), Ok(v)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(v)) { headers.insert(k, v); } }
        let mut out = hyper::Request::builder().method(parts.method).uri(target).version(hyper::Version::HTTP_11);
        *out.headers_mut().expect("a request") = headers;
        let Ok(out) = out.body(body.map_err(std::io::Error::other).boxed()) else { return page(400, "Bad request", "This request can't be passed on.") };
        // one of the app's slots, until the response (or the WebSocket) is through
        let Ok(Ok(slot)) = tokio::time::timeout(self.wait, self.slots.clone().acquire_owned()).await else { return page(503, "The app is busy", "Too many requests are waiting for the app behind this server. Try again in a moment.") };
        let mut res = match tokio::time::timeout(self.wait, self.client.request(out)).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) if e.is_connect() => return page(502, "The app isn't answering", "The app behind this server isn't running, or isn't listening where app.proxy says. Try again in a moment."),
            Ok(Err(_)) => return page(502, "The app failed", "The app behind this server broke off its answer."),
            Err(_) => return page(504, "The app is too slow", "The app behind this server didn't answer in time (app.proxy.timeout)."),
        };
        // a WebSocket (or another upgrade) the app accepted: from here on bytes, both ways
        if res.status() == hyper::StatusCode::SWITCHING_PROTOCOLS {
            if let Some(on_client) = on_client {
                let on_app = hyper::upgrade::on(&mut res);
                tokio::spawn(async move {
                    if let (Ok(a), Ok(b)) = (on_client.await, on_app.await) { let (mut a, mut b) = (TokioIo::new(a), TokioIo::new(b)); let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await; }
                    drop(slot);
                });
            }
            let (parts, _) = res.into_parts();
            return hyper::Response::from_parts(parts, full(Bytes::new()));
        }
        let (mut parts, body) = res.into_parts();
        parts.headers = forwardable(&parts.headers, false);
        // (the slot goes with the body: given back when the response has been sent, or abandoned)
        hyper::Response::from_parts(parts, body.map_err(move |e| { let _ = &slot; std::io::Error::other(e) }).boxed())
    }
}
/// The headers that go on: not those of the connection (nor any its `Connection` header names). An upgrade keeps
/// `Upgrade` and `Connection: upgrade`. (A client's `X-Sqz-…` are gone before this: `app::route`.)
fn forwardable(h: &HeaderMap, upgrade: bool) -> HeaderMap {
    let named: Vec<String> = h.get_all(hyper::header::CONNECTION).iter().filter_map(|v| v.to_str().ok()).flat_map(|v| v.split(',').map(|x| x.trim().to_ascii_lowercase())).collect();
    let mut out = HeaderMap::with_capacity(h.len());
    let mut cookies: Vec<&[u8]> = vec![];
    for (k, v) in h {
        let n = k.as_str();
        if HOP.contains(&n) || (named.iter().any(|x| x == n) && !(upgrade && n == "upgrade")) || (n == "upgrade" && !upgrade) { continue; }
        // HTTP/2 may split Cookie into several; HTTP/1.1 wants one
        if k == hyper::header::COOKIE { cookies.push(v.as_bytes()); continue; }
        out.append(k.clone(), v.clone());
    }
    // (as bytes: one cookie of the app's with bytes past ASCII must not cost the others)
    if !cookies.is_empty() { if let Ok(v) = HeaderValue::from_bytes(&cookies.join(&b"; "[..])) { out.insert(hyper::header::COOKIE, v); } }
    if upgrade { out.insert(hyper::header::CONNECTION, HeaderValue::from_static("upgrade")); }
    out
}
fn page(status: u16, title: &str, text: &str) -> hyper::Response<Body> {
    let html = format!("<!doctype html><meta charset=utf-8><meta name=viewport content=\"width=device-width\"><title>{title}</title><body style=\"font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:15vh auto;padding:0 16px\"><h1 style=\"font-size:20px\">{title}</h1><p>{text}</p>");
    hyper::Response::builder().status(status).header("content-type", "text/html; charset=utf-8").header("cache-control", "no-store").body(full(html)).expect("a page")
}

/// An address or a network (`10.0.0.0/8`, `fd00::/8`, `127.0.0.1`), for `app.trustProxy`.
#[derive(Clone, Debug, PartialEq)] pub struct Net { addr: IpAddr, bits: u8 }
impl Net {
    pub fn parse(s: &str) -> Result<Net, String> {
        let (a, bits) = match s.split_once('/') { Some((a, b)) => (a, Some(b.parse::<u8>().map_err(|_| format!("{s:?}: the prefix length is a number"))?)), None => (s, None) };
        let addr: IpAddr = a.trim().parse().map_err(|_| format!("{s:?} is not an IP address or network"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let bits = bits.unwrap_or(max); if bits > max { return Err(format!("{s:?}: at most /{max}")); }
        Ok(Net { addr, bits })
    }
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip { IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip), ip => ip };
        let mask = |n: u32, w: u32| if n == 0 { 0u128 } else { (!0u128) << (w - n) };
        match (self.addr, ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => { let m = mask(self.bits as u32, 32) as u32; u32::from(a) & m == u32::from(b) & m }
            (IpAddr::V6(a), IpAddr::V6(b)) => { let m = mask(self.bits as u32, 128); u128::from(a) & m == u128::from(b) & m }
            _ => false,
        }
    }
}
/// Who a request is from. A peer in `trusted` is a proxy of yours: walking its `X-Forwarded-For` from the end, the
/// client is the first address that isn't one of them (those before it are whatever the client sent). An entry that
/// can't be read ends the walk at the last address that could be vouched for.
pub(crate) fn client_ip(trusted: &[Net], peer: IpAddr, headers: &HeaderMap) -> IpAddr {
    let ours = |a: IpAddr| trusted.iter().any(|n| n.contains(a));
    if !ours(peer) { return peer; }
    let chain: Vec<String> = headers.get_all("x-forwarded-for").iter().filter_map(|v| v.to_str().ok()).flat_map(|v| v.split(',').map(|a| a.trim().to_string()).collect::<Vec<_>>()).collect();
    let mut hop = peer;
    for entry in chain.iter().rev() {
        let Some(a) = hop_addr(entry) else { return hop };
        if !ours(a) { return a; }
        hop = a;
    }
    hop
}
/// One `X-Forwarded-For` entry: an address, with or without a port (`1.2.3.4:80`, `[2001:db8::1]:443`).
fn hop_addr(e: &str) -> Option<IpAddr> {
    e.parse().ok().or_else(|| e.parse::<std::net::SocketAddr>().ok().map(|s| s.ip())).or_else(|| e.strip_prefix('[').and_then(|r| r.split_once(']')).and_then(|(a, _)| a.parse().ok()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn networks_and_the_client_behind_proxies() {
        let t: Vec<Net> = ["127.0.0.1", "10.0.0.0/8", "fd00::/8"].iter().map(|s| Net::parse(s).unwrap()).collect();
        assert!(t[1].contains("10.1.2.3".parse().unwrap()) && !t[1].contains("11.0.0.1".parse().unwrap()));
        assert!(t[2].contains("fd12::1".parse().unwrap()) && t[0].contains("::ffff:127.0.0.1".parse().unwrap()));
        assert!(Net::parse("1.2.3.4/33").is_err() && Net::parse("nope").is_err());
        let mut h = HeaderMap::new(); h.insert("x-forwarded-for", HeaderValue::from_static("6.6.6.6, 203.0.113.9, 10.0.0.2"));
        assert_eq!(client_ip(&t, "127.0.0.1".parse().unwrap(), &h), "203.0.113.9".parse::<IpAddr>().unwrap(), "the last untrusted address: the first is the client's own claim");
        assert_eq!(client_ip(&t, "198.51.100.1".parse().unwrap(), &h), "198.51.100.1".parse::<IpAddr>().unwrap(), "a peer that isn't trusted is the client, whatever it says");
        assert_eq!(client_ip(&t, "127.0.0.1".parse().unwrap(), &HeaderMap::new()), "127.0.0.1".parse::<IpAddr>().unwrap());
        // a proxy that writes ports, or an entry that isn't an address: never an address the client chose
        let with = |v: &'static str| { let mut h = HeaderMap::new(); h.insert("x-forwarded-for", HeaderValue::from_static(v)); h };
        assert_eq!(client_ip(&t, "127.0.0.1".parse().unwrap(), &with("198.51.100.7, 203.0.113.9:4444")), "203.0.113.9".parse::<IpAddr>().unwrap());
        assert_eq!(client_ip(&t, "127.0.0.1".parse().unwrap(), &with("198.51.100.7, [2001:db8::1]:443")), "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(client_ip(&t, "127.0.0.1".parse().unwrap(), &with("198.51.100.7, unknown, 10.0.0.2")), "10.0.0.2".parse::<IpAddr>().unwrap(), "past an unreadable entry: the proxy that wrote it");
    }
    #[test] fn headers_that_go_on() {
        let mut h = HeaderMap::new();
        for (k, v) in [("connection", "keep-alive, x-secret"), ("x-secret", "1"), ("keep-alive", "5"), ("cookie", "a=1"), ("accept", "text/html"), ("upgrade", "websocket"), ("expect", "100-continue")] { h.append(HeaderName::from_static(k), HeaderValue::from_static(v)); }
        h.append(hyper::header::COOKIE, HeaderValue::from_static("b=2"));
        let out = forwardable(&h, false);
        let names: Vec<&str> = out.keys().map(|k| k.as_str()).collect();
        assert_eq!(names, vec!["accept", "cookie"]);
        assert_eq!(out.get("cookie").unwrap(), "a=1; b=2");
        let up = forwardable(&h, true);
        assert_eq!((up.get("upgrade").unwrap(), up.get("connection").unwrap()), (&HeaderValue::from_static("websocket"), &HeaderValue::from_static("upgrade")));
    }
}
