//! The app API (`listen.app`): what a browser or mobile app talks to directly, with no server code of the
//! application's own. Users sign in here (password, or OAuth through a browser redirect), and then send SQL: every
//! statement runs as that user, under the row policies, live queries included.
//!
//! - `POST /api/auth/<table>/sign-up` `{fields, password}`, `POST /api/auth/<table>/sign-in` `{login, password}`,
//!   `POST /api/auth/sign-out`, `GET /api/me`, and `GET /api/auth/<table>/methods`: whether clients may sign up
//!   there, and the providers they may sign in with (for a sign-in page).
//! - `GET /api/auth/<table>/oauth/<provider>?return=<url>&challenge=<c>` sends the browser to the provider; the
//!   provider comes back to `…/callback`, which sends the browser to `return` with `#sqz_code=…`, a one-time code
//!   (60 s) that the client trades for a session at `POST /api/auth/exchange` `{code, verifier}` (the session token
//!   never sits in a URL or the history). The code works only with the verifier the starting page kept, whose
//!   SHA-256 is `challenge` (as in PKCE): a code someone else got for their own account and planted in a link
//!   signs nobody in.
//! - `POST /api/sql` `{sql, params}`, `POST /api/batch` `{statements: [{sql, params}…]}` (one transaction).
//! - `POST /api/fn/<name>` with the arguments as a JSON object: one of the app's functions (`functions.rs`), as the
//!   caller; `{result}`.
//! - `GET /api/socket`: a WebSocket carrying JSON messages: `auth`, `sql`, `batch`, `call`, `live` and `unlive`. A live
//!   query sends its rows at once and again whenever they change; one socket carries any number of them. `auth`
//!   with `token: null` signs the socket out, back to the anonymous role (if any).
//! - `GET /api/client.js`: the JavaScript client (`clients/js`), so a page imports it from its own server with no
//!   build step, at the server's own version.
//! - Anything else is a static file from `app.staticDir`, if set (the app itself), with `index.html` for paths
//!   without a file.
//!
//! From clients only SELECT, INSERT, UPDATE and DELETE are accepted (no DDL, no admin statements, transactions only
//! as a batch), results are capped at `app.maxRows`, and a request without a session acts as `app.anonymousRole`
//! or is refused. Browsers may call from `app.origins` (or the API's own origin); requests from other web pages are
//! refused, WebSockets included. Sign-up and sign-in are rate limited per client address. Clients make accounts
//! (by password or with a provider) only in the tables `app.signUp` lists, setting only the columns listed there
//! besides the login column; other tables are sign-in only.
//!
//! With `app.tls` it serves https and wss: your own certificate, or one from Let's Encrypt for `app.tls.domains`,
//! renewed in the background (see `tls.rs`).
//!
//! HTTP/1.1 and HTTP/2 (hyper; over TLS the browser picks), on one small runtime: connections are tasks, not threads,
//! so a connected user who is idle costs little more than their socket's buffers. Work that can block a thread (password hashing, a provider's token exchange, static
//! files, commits that wait for their fsync or the bucket) runs on the runtime's blocking pool.
use crate::config::Durability;
use crate::live::{Event, Subscription};
use crate::sql::{ColKind, Plan, Prepared, Session, Sql};
use crate::table::{ColType, Value};
use crate::util::{err_json, j_to_value, names, url_decode, value_json, Cols};
use serde_json::{json, Value as J};
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::{Frame, Incoming};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, Notify};
use tokio::time::timeout;

/// Idle connections (no request in flight, HTTP/2's included) and stalled writers are dropped after this long.
const IO_TIMEOUT: Duration = Duration::from_secs(60);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const SOCKET_TIMEOUT: Duration = Duration::from_secs(120);
const PING_EVERY: Duration = Duration::from_secs(30);
const MAX_LINE: u64 = 16 << 10;
const MAX_HEADERS: usize = 64;
const MAX_SQL: usize = 64 << 10;
const MAX_PARAMS: usize = 1000;
const MAX_BATCH: usize = 100;
const MAX_LIVES: usize = 64;
const CODE_TTL: Duration = Duration::from_secs(60);
const CLIENT_JS: &str = include_str!("../clients/js/index.js");
/// Messages a socket may have waiting to be written before its reader stops reading (the client is not keeping up).
const OUT_QUEUE: usize = 64;

/// Shared by every connection of one listener. `hashing`: sign-ups and sign-ins running at once (a password hash
/// takes 19 MB and a core); the rest wait here as tasks rather than as blocked threads.
/// `upstream`: the app behind the API (`app.proxy`); `tls`: whether the API speaks https.
/// `turns`: the app's code (functions, middleware, routes) runs on this runtime's threads, at most this many at once;
/// the rest wait as tasks, not threads, so a flood of one can't stall everything else.
struct AppState { limits: Mutex<HashMap<IpAddr, (f64, Instant)>>, codes: Mutex<HashMap<String, (J, String, Instant)>>, hashing: tokio::sync::Semaphore, links: Arc<Links>, mcp: crate::mcp::McpState, upstream: Option<crate::proxy::Upstream>, tls: bool, turns: tokio::sync::Semaphore, turn_wait: Duration }
/// Links to files: signed with this database's key (`files/link.key`), under `base` (`app.publicUrl`, or none: a link
/// relative to the API), and working for a `ttl`. A link's expiry is rounded to half the ttl, so the same file gets
/// the same link for a while and browsers can cache it.
pub(crate) struct Links { key: ring::hmac::Key, base: String, ttl: i64 }
impl Links {
    fn load(sql: &Sql) -> Result<Links, String> {
        let dir = sql.files_dir(); let p = dir.join("link.key");
        let key = match std::fs::read(&p) { Ok(k) if k.len() == 32 => k, _ => {
            std::fs::create_dir_all(&dir).map_err(|e| format!("files: {}: {e}", dir.display()))?;
            let mut k = [0u8; 32]; getrandom::fill(&mut k).expect("random");
            let mut o = std::fs::OpenOptions::new(); o.write(true).create(true).truncate(true);
            #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; o.mode(0o600); }
            o.open(&p).and_then(|mut f| { use std::io::Write; f.write_all(&k)?; f.sync_all() }).map_err(|e| format!("files: {}: {e}", p.display()))?;
            k.to_vec()
        } };
        Ok(Links { key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key), base: sql.cfg.app.public_url.clone().unwrap_or_default(), ttl: sql.cfg.app.file_link_ttl.as_secs() as i64 })
    }
    fn sig(&self, id: &str, exp: i64) -> String { ring::hmac::sign(&self.key, format!("{id}.{exp}").as_bytes()).as_ref()[..16].iter().map(|b| format!("{b:02x}")).collect() }
    fn url(&self, id: &str) -> String { let half = (self.ttl / 2).max(1); let exp = (now_secs() / half + 2) * half; format!("{}/api/files/{id}?e={exp}&s={}", self.base, self.sig(id, exp)) }
    /// Whether `e` and `s` are a link to `id` that still works.
    fn check(&self, id: &str, e: &str, s: &str) -> bool { e.parse::<i64>().is_ok_and(|exp| exp >= now_secs() && crate::net::same_secret(self.sig(id, exp).as_bytes(), s.as_bytes())) }
}
fn now_secs() -> i64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0) }
/// A FILE value as a client sees it: `{id, name, type, size, url}` (a file that is gone is `{id, url: null}`).
fn file_json(sql: &Sql, links: &Links, id: &str) -> J {
    match sql.file_meta(id) { Some(m) => json!({"id": m.id, "name": m.name, "type": m.ctype, "size": m.size, "url": links.url(id)}), None => json!({"id": id, "url": null}) }
}
/// A result's columns as a client sees them: names, types, and which are FILE or VECTOR columns.
struct Shape { cols: Cols, kinds: Vec<ColKind> }
impl Shape {
    fn of(sql: &Sql, p: &Prepared) -> Shape { let cols = sql.columns(p); let mut kinds = sql.column_kinds(p); kinds.resize(cols.len(), ColKind::Plain); Shape { cols, kinds } }
    fn rows(&self, sql: &Sql, links: &Links, rows: &[Vec<Value>]) -> Vec<J> {
        rows.iter().map(|r| J::Array(r.iter().enumerate().map(|(i, v)| match (v, self.kinds.get(i)) {
            (Value::Text(id), Some(ColKind::File)) => file_json(sql, links, id),
            // f32s as their shortest decimal (0.1, not 0.10000000149011612)
            (Value::Bytes(b), Some(ColKind::Vector)) => J::Array(crate::table::vector_floats(b).map(|f| format!("{f}").parse::<f64>().ok().and_then(serde_json::Number::from_f64).map(J::Number).unwrap_or(J::Null)).collect()),
            _ => value_json(v, self.cols.get(i).and_then(|c| c.1.as_ref())),
        }).collect())).collect()
    }
}
/// Whether statements may wait on something slow besides the CPU: a commit's fsync or the bucket, or (with
/// `[embed]`) the embeddings endpoint, which any statement may call through `embed()`. Those run off the runtime's
/// threads. (Deciding by the statement's text would be fooled by `embed (` or a JSON escape.)
fn sql_may_wait(sql: &Sql) -> bool { sql.cfg.durable != Durability::Visible || sql.cfg.embed.is_some() }
impl AppState {
    /// A token bucket per client address for sign-up, sign-in and code exchange: 10 at once, then one every 3 s.
    fn allow(&self, ip: IpAddr) -> bool {
        let mut m = self.limits.lock().unwrap();
        if m.len() > 100_000 { m.retain(|_, (_, at)| at.elapsed() < Duration::from_secs(60)); }
        // an IPv6 client by its /64: one host has a whole one to pick addresses from
        let ip = match ip { IpAddr::V6(v) if v.to_ipv4_mapped().is_none() => { let s = v.segments(); IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0)) } ip => ip };
        let (tokens, at) = m.entry(ip).or_insert((10.0, Instant::now()));
        *tokens = (*tokens + at.elapsed().as_secs_f64() / 3.0).min(10.0); *at = Instant::now();
        if *tokens >= 1.0 { *tokens -= 1.0; true } else { false }
    }
}

pub fn start(sql: Arc<Sql>, addr: &str) -> Result<crate::net::Listener, String> {
    if let Some(r) = &sql.cfg.app.anonymous_role { if !sql.acl.read().unwrap().roles.contains(r) { return Err(format!("app.anonymousRole: no such role {r}")); } }
    let fail = |e: io::Error| format!("listen.app {addr}: {e}");
    let std_listener = std::net::TcpListener::bind(addr).map_err(fail)?; std_listener.set_nonblocking(true).map_err(fail)?;
    let local = std_listener.local_addr().map_err(fail)?;
    let workers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).min(4);
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(workers).max_blocking_threads(64).thread_name("sqzdb-app").enable_all().build().map_err(fail)?;
    let listener = { let _in = rt.enter(); tokio::net::TcpListener::from_std(std_listener).map_err(fail)? };
    let tls = match &sql.cfg.app.tls { Some(p) => Some(Arc::new(crate::tls::Tls::start(p, &sql.db.dir, rt.handle())?)), None => None };
    if let Some(p) = sql.cfg.app.tls.as_ref().filter(|p| p.redirect.is_some()) {
        let to = p.redirect.clone().unwrap_or_default();
        let hosts = if !p.domains.is_empty() { p.domains.clone() } else { sql.cfg.app.public_url.as_deref().and_then(|u| u.split('/').nth(2)).map(|h| vec![h.split(':').next().unwrap_or(h).to_string()]).ok_or("app.tls.redirect: needs app.tls.domains or app.publicUrl, the host to send browsers to")? };
        let l = std::net::TcpListener::bind(&to).and_then(|l| l.set_nonblocking(true).map(|()| l)).map_err(|e| format!("app.tls.redirect {to}: {e}"))?;
        let l = { let _in = rt.enter(); tokio::net::TcpListener::from_std(l).map_err(|e| format!("app.tls.redirect {to}: {e}"))? };
        rt.spawn(crate::tls::redirect(l, hosts, Some(local.port()).filter(|p| *p != 443)));
    }
    let links = Arc::new(Links::load(&sql)?);
    let upstream = { let _in = rt.enter(); sql.cfg.app.proxy.as_ref().map(crate::proxy::Upstream::new) };
    let (sql_turns, turn_wait) = (sql.cfg.functions.instances, (sql.cfg.functions.timeout * 4).max(Duration::from_secs(5)));
    let weak = Arc::downgrade(&sql); drop(sql);
    let st = Arc::new(AppState { limits: Default::default(), codes: Default::default(), hashing: tokio::sync::Semaphore::new(workers), links, mcp: Default::default(), upstream, tls: tls.is_some(),
                                 turns: tokio::sync::Semaphore::new(sql_turns), turn_wait });
    Ok(crate::net::spawn_listener(local, move |stop| {
        rt.block_on(async move {
            loop {
                let accepted = listener.accept().await;
                if stop.load(Ordering::Relaxed) || weak.strong_count() == 0 { return; }
                match accepted {
                    Ok((stream, peer)) => {
                        stream.set_nodelay(true).ok();
                        let (w, st, tls) = (weak.clone(), st.clone(), tls.clone());
                        tokio::spawn(async move {
                            let Some(tls) = tls else { return serve(w, stream, peer.ip(), st, None).await };
                            let Ok(Ok(s)) = timeout(HANDSHAKE_TIMEOUT, tls.acceptor.accept(stream)).await else { return };
                            if s.get_ref().1.alpn_protocol() == Some(crate::tls::ACME_TLS_ALPN) { return; }   // a CA checking a domain: the handshake was the answer
                            let h2 = s.get_ref().1.alpn_protocol() == Some(b"h2");
                            serve(w, s, peer.ip(), st, Some(h2)).await
                        });
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,   // out of file descriptors, say: don't spin
                }
            }
        });
        rt.shutdown_timeout(Duration::from_secs(1));   // the connections end with the runtime
    }))
}

// ---------- HTTP ----------
pub(crate) struct Req { pub(crate) method: String, pub(crate) path: String, pub(crate) query: HashMap<String, String>, pub(crate) headers: HashMap<String, String>, pub(crate) body: Vec<u8> }
/// A request's head as the handlers take it (the body read apart): headers by lowercase name, a repeated one joined
/// (HTTP/2 may split Cookie), and `host` from the authority when HTTP/2 gave no Host header.
fn req_of(parts: &hyper::http::request::Parts, body: Vec<u8>) -> Req {
    let mut headers: HashMap<String, String> = HashMap::new();
    for (k, v) in &parts.headers {
        let v = String::from_utf8_lossy(v.as_bytes()).into_owned();
        match headers.get_mut(k.as_str()) { Some(e) => { e.push_str(if k == hyper::header::COOKIE { "; " } else { ", " }); e.push_str(&v); } None => { headers.insert(k.as_str().to_string(), v); } }
    }
    if !headers.contains_key("host") { if let Some(a) = parts.uri.authority() { headers.insert("host".into(), a.to_string()); } }
    let q = parts.uri.query().unwrap_or("");
    let query = q.split('&').filter(|s| !s.is_empty()).map(|kv| { let (k, v) = kv.split_once('=').unwrap_or((kv, "")); (url_decode(k), url_decode(v)) }).collect();
    Req { method: parts.method.as_str().to_string(), path: parts.uri.path().to_string(), query, headers, body }
}
/// A response body: all of it, or a stream (a file being downloaded).
pub(crate) type Body = http_body_util::combinators::BoxBody<Bytes, io::Error>;
pub(crate) fn full(b: impl Into<Bytes>) -> Body { Full::new(b.into()).map_err(|n| match n {}).boxed() }
/// A response the handlers wrote as HTTP/1.1 (`respond`), as hyper's: the status, the headers but those of the
/// connection and the length (hyper sets them, and HTTP/2 forbids the first), the body.
pub(crate) fn into_response(raw: Vec<u8>) -> hyper::Response<Body> {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(raw.len());
    let head = String::from_utf8_lossy(&raw[..end]).into_owned(); let len = raw.len();
    let body = Bytes::from(raw).slice((end + 4).min(len)..);
    let mut lines = head.split("\r\n");
    let status = lines.next().and_then(|l| l.split(' ').nth(1)).and_then(|s| s.parse::<u16>().ok()).unwrap_or(500);
    let mut b = hyper::Response::builder().status(status);
    for l in lines { if let Some((k, v)) = l.split_once(": ") { if !["content-length", "connection", "keep-alive", "transfer-encoding"].iter().any(|h| k.eq_ignore_ascii_case(h)) { b = b.header(k, v); } } }
    b.body(full(body)).unwrap_or_else(|_| hyper::Response::new(full("a response header that HTTP can't carry")))
}
fn reason(status: u16) -> &'static str { match status { 101 => "Switching Protocols", 200 => "OK", 204 => "No Content", 206 => "Partial Content", 302 => "Found", 304 => "Not Modified", 400 => "Bad Request", 401 => "Unauthorized", 403 => "Forbidden", 404 => "Not Found", 405 => "Method Not Allowed", 411 => "Length Required", 413 => "Payload Too Large", 416 => "Range Not Satisfiable", 429 => "Too Many Requests", _ => "Error" } }
/// A whole response, written in one piece: a response in fragments waits on the peer's delayed ACK for each one.
pub(crate) fn respond(status: u16, ctype: &str, body: &[u8], extra: &[(String, String)]) -> Vec<u8> {
    if extra.iter().any(|(k, v)| k.contains(['\r', '\n']) || v.contains(['\r', '\n'])) { return respond(500, "text/plain", b"a response header with a line break", &[]); }
    let mut out = format!("HTTP/1.1 {status} {}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nX-Content-Type-Options: nosniff\r\nConnection: keep-alive\r\n", reason(status), body.len());
    for (k, v) in extra { out.push_str(k); out.push_str(": "); out.push_str(v); out.push_str("\r\n"); }
    out.push_str("\r\n"); let mut out = out.into_bytes(); out.extend_from_slice(body); out
}
fn json_resp(status: u16, v: &J, extra: &[(String, String)]) -> Vec<u8> {
    let mut h = extra.to_vec(); h.push(("Cache-Control".into(), "no-store".into()));
    respond(status, "application/json", v.to_string().as_bytes(), &h)
}
fn status_of(e: &J) -> u16 { match e.get("code").and_then(|c| c.as_str()) { Some("AUTH") => 401, Some("DENIED") => 403, Some("RATE_LIMITED") => 429, _ => 400 } }
fn limited() -> J { json!({"error": "too many requests; slow down", "code": "RATE_LIMITED"}) }
fn fn_json(e: crate::functions::FnError) -> J { json!({"error": e.message, "code": e.code}) }
/// Call a function as `sess` (`anonymous`: the session is `app.anonymousRole`'s, not a sign-in): `{result}`.
pub(crate) fn call(sql: &Sql, sess: &mut Session, name: &str, args: &J, anonymous: bool) -> Result<J, J> { sql.call_function(sess, name, args, anonymous).map(|r| json!({"result": r})).map_err(fn_json) }
/// The page origin a browser request came from, if it may call: no Origin header (not a browser page, or a
/// same-origin navigation), the API's own host, `app.publicUrl`, or one of `app.origins` (`*`: any).
fn allowed_origin(sql: &Sql, req: &Req) -> Result<Option<String>, ()> {
    let Some(o) = req.headers.get("origin") else { return Ok(None) };
    let o = o.trim_end_matches('/').to_string();
    let host = req.headers.get("host").map(|h| h.as_str()).unwrap_or("");
    let same = o.strip_prefix("https://").or_else(|| o.strip_prefix("http://")).map(|h| h.eq_ignore_ascii_case(host)).unwrap_or(false);
    let cfg = &sql.cfg.app;
    if same || cfg.public_url.as_deref() == Some(o.as_str()) || cfg.origins.iter().any(|x| x == "*" || x.eq_ignore_ascii_case(&o)) { Ok(Some(o)) } else { Err(()) }
}
fn cors(origin: &Option<String>) -> Vec<(String, String)> {
    match origin { Some(o) => vec![("Access-Control-Allow-Origin".into(), o.clone()), ("Vary".into(), "Origin".into())], None => vec![] }
}
pub(crate) fn bearer(req: &Req) -> Option<String> { req.headers.get("authorization").and_then(|h| h.strip_prefix("Bearer ")).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) }
/// The session a request acts as: its token's user, the anonymous role, or nobody.
fn session_for(sql: &Sql, token: Option<&str>) -> Result<Session, J> {
    let mut s = Session::default();
    match token {
        Some(t) => sql.session_from_token(&mut s, t).map_err(err_json)?,
        None => match &sql.cfg.app.anonymous_role { Some(r) => sql.assume(&mut s, &[r.clone()], HashMap::new()).map_err(err_json)?, None => return Err(json!({"error": "session: sign in first", "code": "AUTH"})) },
    }
    Ok(s)
}
/// A socket's session before it signs in, and after it signs out: the anonymous role, if any.
fn anonymous_session(sql: &Sql) -> Session {
    let mut s = Session::default();
    if let Some(r) = &sql.cfg.app.anonymous_role { let _ = sql.assume(&mut s, &[r.clone()], HashMap::new()); }
    s
}
/// A statement a client may send: SELECT, INSERT, UPDATE or DELETE, of bounded size.
fn client_statement(sql: &Sql, text: &str) -> Result<Arc<Prepared>, J> {
    let text = text.trim().trim_end_matches(';');
    if text.is_empty() { return Err(json!({"error": "sql is required", "code": "ARGUMENTS"})); }
    if text.len() > MAX_SQL { return Err(json!({"error": format!("a statement from a client is at most {MAX_SQL} bytes"), "code": "ARGUMENTS"})); }
    let refuse = || json!({"error": "permission denied: clients send SELECT, INSERT, UPDATE and DELETE (a transaction is a batch)", "code": "DENIED"});
    if crate::sql::is_admin_stmt(text) { return Err(refuse()); }
    let p = sql.prepare(text).map_err(err_json)?;
    if !matches!(p.plan, Plan::Select(_) | Plan::Insert { .. } | Plan::Update { .. } | Plan::Delete { .. } | Plan::Const { .. }) { return Err(refuse()); }
    Ok(p)
}
fn params_of(v: &J) -> Result<Vec<Value>, J> {
    let a = match v.get("params") { None | Some(J::Null) => return Ok(vec![]), Some(J::Array(a)) => a, _ => return Err(json!({"error": "params is an array", "code": "ARGUMENTS"})) };
    if a.len() > MAX_PARAMS { return Err(json!({"error": format!("at most {MAX_PARAMS} parameters"), "code": "ARGUMENTS"})); }
    Ok(a.iter().map(j_to_value).collect())
}
/// Run one client statement as `sess`: `{columns, rows}` (plus `lastInsertId` for an INSERT).
pub(crate) fn run(sql: &Sql, links: &Links, sess: &mut Session, v: &J) -> Result<J, J> {
    let p = client_statement(sql, v.get("sql").and_then(|s| s.as_str()).unwrap_or(""))?;
    let params = params_of(v)?;
    let rows = sql.execute_s(sess, &p, &params).map_err(err_json)?;
    let max = sql.cfg.app.max_rows;
    if rows.len() > max { return Err(json!({"error": format!("the result has more than {max} rows (app.maxRows); add a LIMIT"), "code": "ARGUMENTS"})); }
    let shape = Shape::of(sql, &p);
    let mut out = json!({"columns": names(&shape.cols), "rows": shape.rows(sql, links, &rows)});
    if matches!(p.plan, Plan::Insert { .. }) { out["lastInsertId"] = sess.last_insert_key.as_ref().map(|k| value_json(k, None)).unwrap_or(J::Null); }
    Ok(out)
}
/// Several statements in one transaction: all or none.
pub(crate) fn run_batch(sql: &Sql, links: &Links, sess: &mut Session, v: &J) -> Result<J, J> {
    let list = v.get("statements").and_then(|s| s.as_array()).ok_or_else(|| json!({"error": "statements is an array of {sql, params}", "code": "ARGUMENTS"}))?;
    if list.len() > MAX_BATCH { return Err(json!({"error": format!("at most {MAX_BATCH} statements in a batch"), "code": "ARGUMENTS"})); }
    sql.exec_s(sess, "BEGIN", &[]).map_err(err_json)?;
    let mut results = vec![];
    for (i, st) in list.iter().enumerate() {
        // (ended directly, not by ROLLBACK through exec_s: a session whose sign-in ended meanwhile can't run that)
        match run(sql, links, sess, st) { Ok(r) => results.push(r), Err(mut e) => { sess.txn = None; e["statement"] = json!(i); return Err(e); } }
    }
    sql.exec_s(sess, "COMMIT", &[]).map_err(|e| { sess.txn = None; err_json(e) })?;
    Ok(json!({"results": results}))
}
/// The fields of a sign-up from a client: `table` must be open to sign-up (`app.signUp`), and each field is its login
/// column or one the table lists there. The column a user's role comes from is never a client's to set.
fn sign_up_fields(sql: &Sql, table: &str, v: &J) -> Result<Vec<(String, Value)>, J> {
    let denied = |m: String| json!({"error": format!("permission denied: {m}"), "code": "DENIED"});
    let Some(open) = sql.cfg.app.sign_up.get(&table.to_ascii_lowercase()) else { return Err(denied(format!("clients don't make accounts in {table} (app.signUp lists the tables they may)"))) };
    let (t, at) = sql.auth_table_of(table).map_err(err_json)?;
    let fields = match v.get("fields") { None | Some(J::Null) => return Ok(vec![]), Some(J::Object(m)) => m, _ => return Err(json!({"error": "fields is an object", "code": "ARGUMENTS"})) };
    fields.iter().map(|(k, x)| {
        let c = t.schema.col(k).ok_or_else(|| json!({"error": format!("no such column {k} in {table}"), "code": "SCHEMA"}))?;
        // a file is attached by its uploader, and someone signing up has uploaded nothing yet: they set it signed in
        if t.schema.columns[c].file { return Err(denied(format!("a sign-up can't set {k}, a FILE column; set it once signed in"))); }
        let role_col = matches!(at.role, crate::auth::RoleSrc::Column(r) if r == c);
        if role_col || (c != at.login && !open.iter().any(|o| t.schema.col(o) == Some(c))) { return Err(denied(format!("a sign-up may not set {k} (app.signUp.{table} lists the columns a client may set)"))); }
        Ok((k.clone(), j_to_value(x)))
    }).collect()
}
fn user_json(sql: &Sql, table: &str, user: &[(String, Value)]) -> J {
    let types: HashMap<String, ColType> = sql.db.table(table).map(|t| t.schema.columns.iter().map(|c| (c.name.clone(), c.ty.clone())).collect()).unwrap_or_default();
    J::Object(user.iter().map(|(k, v)| (k.clone(), value_json(v, types.get(k)))).collect())
}
fn signed_json(sql: &Sql, table: &str, si: &crate::auth::SignedIn) -> J { json!({"token": si.token, "user": user_json(sql, table, &si.user), "created": si.created}) }
/// A sign-in's answer: the token in the body, or (`cookie`) as the session cookie, out of the page's reach.
fn signed_reply(sql: &Sql, mut signed: J, cookie: bool, h: &[(String, String)]) -> Vec<u8> {
    if !cookie { return json_resp(200, &signed, h); }
    let token = signed.as_object_mut().and_then(|o| o.remove("token")).and_then(|t| t.as_str().map(String::from)).unwrap_or_default();
    let mut h = h.to_vec(); h.push(("Set-Cookie".into(), crate::signin::session_cookie(sql, &token)));
    json_resp(200, &signed, &h)
}
fn body_json(req: &Req) -> Result<J, J> { serde_json::from_slice(&req.body).map_err(|e| json!({"error": format!("bad JSON: {e}"), "code": "ARGUMENTS"})) }
pub(crate) fn cookie(req: &Req, name: &str) -> Option<String> { req.headers.get("cookie")?.split(';').filter_map(|c| c.trim().split_once('=')).find(|(k, _)| *k == name).map(|(_, v)| url_decode(v)) }
/// The PKCE-style challenge for a verifier: base64url (no padding) of its SHA-256.
pub(crate) fn challenge_of(verifier: &str) -> String { crate::util::base64(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref()).replace('+', "-").replace('/', "_").trim_end_matches('=').to_string() }
pub(crate) fn is_challenge(c: &str) -> bool { c.len() == 43 && c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') }
pub(crate) fn enc(s: &str) -> String { s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect() }
/// A URL to send the browser back to after a provider sign-in: on an allowed origin, so the API is no open redirect,
/// and printable ASCII only (it goes into a Location header).
pub(crate) fn return_ok(sql: &Sql, url: &str) -> bool {
    if !url.bytes().all(|b| (0x21..0x7f).contains(&b)) { return false; }
    let origin = match url.splitn(4, '/').collect::<Vec<_>>().as_slice() { [scheme, "", host, ..] if *scheme == "https:" || *scheme == "http:" => format!("{scheme}//{host}"), _ => return false };
    // under the API's OAuth server, only back to a sign-in in progress: its other URLs redirect on, and the sign-in's
    // code (in the fragment) would go with them
    if let Some(rest) = url.strip_prefix(origin.as_str()).filter(|r| r.starts_with("/oauth/")) {
        return rest.strip_prefix("/oauth/authorize?request=").is_some_and(|id| id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())) && sql.cfg.app.public_url.as_deref() == Some(origin.as_str());
    }
    let cfg = &sql.cfg.app;
    cfg.public_url.as_deref() == Some(origin.as_str()) || cfg.origins.iter().any(|x| x.eq_ignore_ascii_case(&origin))
}
pub(crate) fn redirect(to: &str, cookies: &[String]) -> Vec<u8> {
    let mut h: Vec<(String, String)> = vec![("Location".into(), to.into()), ("Cache-Control".into(), "no-store".into()), ("Referrer-Policy".into(), "no-referrer".into())];
    for c in cookies { h.push(("Set-Cookie".into(), c.clone())); }
    respond(302, "text/plain", b"", &h)
}
/// Requests whose handling can block a thread for a while: sign-in (password hashing; a provider's token exchange
/// runs a runtime of its own), static files, and SQL when commits wait for their fsync or the bucket.
fn blocks(sql: &Sql, req: &Req) -> bool {
    !req.path.starts_with("/api/") || req.path.starts_with("/api/auth/") || (req.method == "POST" && (sql_may_wait(sql) || req.path.starts_with("/api/fn/")))
}

/// One connection, plain or TLS: HTTP/1.1 (WebSockets included) or HTTP/2, as hyper serves them. The protocol is the
/// one TLS agreed on (`h2`), or, in the clear, what the first bytes say (HTTP/2's preface), read within
/// HANDSHAKE_TIMEOUT. A connection with no request in flight for IO_TIMEOUT is closed (HTTP/2's pings don't count), and
/// so is one whose peer stopped taking what it is sent (`Stalls`).
async fn serve<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(weak: Weak<Sql>, mut stream: S, ip: IpAddr, st: Arc<AppState>, h2: Option<bool>) {
    use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
    let (h2, pre) = match h2 {
        Some(h2) => (h2, vec![]),
        None => match timeout(HANDSHAKE_TIMEOUT, sniff(&mut stream)).await { Ok(Some(x)) => x, _ => return },
    };
    let act = Arc::new(Activity { busy: Default::default(), last: Mutex::new(Instant::now()) });
    let svc = { let act = act.clone(); hyper::service::service_fn(move |req| {
        let (weak, st, act) = (weak.clone(), st.clone(), act.clone());
        async move {
            act.busy.fetch_add(1, Ordering::Relaxed); *act.last.lock().unwrap() = Instant::now();
            let done = Done(act);   // until the response's body is through (or abandoned)
            let resp = route(&weak, &st, ip, req).await;
            Ok::<_, std::convert::Infallible>(resp.map(move |b| b.map_err(move |e| { let _ = &done; e }).boxed()))
        }
    }) };
    let io = TokioIo::new(Stalls { io: Rewind { pre, at: 0, io: stream }, wait: None });
    macro_rules! drive { ($conn:expr) => {{
        let conn = $conn; tokio::pin!(conn); let mut asked = false;
        loop {
            tokio::select! {
                _ = conn.as_mut() => return,
                _ = tokio::time::sleep(Duration::from_secs(5)) => if !asked && act.busy.load(Ordering::Relaxed) == 0 && act.last.lock().unwrap().elapsed() > IO_TIMEOUT { conn.as_mut().graceful_shutdown(); asked = true; },
            }
        }
    }}; }
    if h2 {
        let mut b = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
        b.timer(TokioTimer::new()).keep_alive_interval(PING_EVERY).keep_alive_timeout(Duration::from_secs(20)).max_concurrent_streams(256).max_header_list_size(MAX_LINE as u32 * 4);
        drive!(b.serve_connection(io, svc))
    } else {
        let mut b = hyper::server::conn::http1::Builder::new();
        b.timer(TokioTimer::new()).header_read_timeout(IO_TIMEOUT).max_buf_size(MAX_LINE as usize * 4).max_headers(MAX_HEADERS);
        drive!(b.serve_connection(io, svc).with_upgrades())
    }
}
/// HTTP/2 in the clear starts with this preface; anything else is HTTP/1.
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// Read until the first bytes are HTTP/2's preface, or can't be: (HTTP/2?, the bytes read). None: the peer left.
async fn sniff<S: AsyncRead + Unpin>(s: &mut S) -> Option<(bool, Vec<u8>)> {
    let (mut buf, mut have) = ([0u8; 24], 0);
    loop {
        let n = s.read(&mut buf[have..]).await.ok()?; if n == 0 { return None; }
        have += n;
        if !PREFACE.starts_with(&buf[..have]) { return Some((false, buf[..have].to_vec())); }
        if have == PREFACE.len() { return Some((true, buf.to_vec())); }
    }
}
/// What a connection is doing, for its idle watchdog: requests whose responses aren't through, and when one last began
/// or ended.
struct Activity { busy: std::sync::atomic::AtomicUsize, last: Mutex<Instant> }
struct Done(Arc<Activity>);
impl Drop for Done { fn drop(&mut self) { self.0.busy.fetch_sub(1, Ordering::Relaxed); *self.0.last.lock().unwrap() = Instant::now(); } }
/// The bytes `sniff` read, given back first.
struct Rewind<S> { pre: Vec<u8>, at: usize, io: S }
impl<S: AsyncRead + Unpin> AsyncRead for Rewind<S> {
    fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<io::Result<()>> {
        if self.at < self.pre.len() { let n = buf.remaining().min(self.pre.len() - self.at); let at = self.at; buf.put_slice(&self.pre[at..at + n]); self.at += n; return std::task::Poll::Ready(Ok(())); }
        std::pin::Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Rewind<S> {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, b: &[u8]) -> std::task::Poll<io::Result<usize>> { std::pin::Pin::new(&mut self.io).poll_write(cx, b) }
    fn poll_write_vectored(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, b: &[io::IoSlice<'_>]) -> std::task::Poll<io::Result<usize>> { std::pin::Pin::new(&mut self.io).poll_write_vectored(cx, b) }
    fn is_write_vectored(&self) -> bool { self.io.is_write_vectored() }
    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> { std::pin::Pin::new(&mut self.io).poll_flush(cx) }
    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> { std::pin::Pin::new(&mut self.io).poll_shutdown(cx) }
}
/// A connection whose writes the peer hasn't taken for IO_TIMEOUT fails (a client that stopped reading would otherwise
/// hold it, and what it was sent, for ever). Reads may wait: an idle connection is the watchdog's (`serve`).
struct Stalls<S> { io: S, wait: Option<std::pin::Pin<Box<tokio::time::Sleep>>> }
impl<S> Stalls<S> {
    fn stalled(&mut self, cx: &mut std::task::Context<'_>) -> bool { use std::future::Future; self.wait.get_or_insert_with(|| Box::pin(tokio::time::sleep(IO_TIMEOUT))).as_mut().poll(cx).is_ready() }
    fn after<T>(&mut self, cx: &mut std::task::Context<'_>, r: std::task::Poll<io::Result<T>>) -> std::task::Poll<io::Result<T>> {
        match r { std::task::Poll::Pending if self.stalled(cx) => std::task::Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, "the peer stopped reading"))), std::task::Poll::Pending => std::task::Poll::Pending, r => { self.wait = None; r } }
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for Stalls<S> {
    fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<io::Result<()>> { std::pin::Pin::new(&mut self.io).poll_read(cx, buf) }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Stalls<S> {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, b: &[u8]) -> std::task::Poll<io::Result<usize>> { let r = std::pin::Pin::new(&mut self.io).poll_write(cx, b); self.after(cx, r) }
    fn poll_write_vectored(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, b: &[io::IoSlice<'_>]) -> std::task::Poll<io::Result<usize>> { let r = std::pin::Pin::new(&mut self.io).poll_write_vectored(cx, b); self.after(cx, r) }
    fn is_write_vectored(&self) -> bool { self.io.is_write_vectored() }
    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> { let r = std::pin::Pin::new(&mut self.io).poll_flush(cx); self.after(cx, r) }
    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> { std::pin::Pin::new(&mut self.io).poll_shutdown(cx) }
}
/// A turn to run the app's code on this runtime (`AppState::turns`); None when none came free in time.
async fn turn(st: &AppState) -> Option<tokio::sync::SemaphorePermit<'_>> { timeout(st.turn_wait, st.turns.acquire()).await.ok()?.ok() }
fn busy() -> hyper::Response<Body> { into_response(json_resp(503, &json!({"error": "the server is busy running the app's code (functions.instances); try again", "code": "LIMIT"}), &[("Retry-After".into(), "1".into())])) }
/// The app's middleware and routes for one request: an answer, or the request to go on (with the headers middleware
/// left on it).
async fn handlers(sql: &Arc<Sql>, st: &AppState, ip: IpAddr, mut req: hyper::Request<Incoming>, max: usize) -> Result<hyper::Request<Incoming>, hyper::Response<Body>> {
    use crate::functions::{HttpOut, HttpReq};
    let Some(at) = crate::functions::match_path(req.uri().path()) else { return Err(into_response(respond(400, "text/plain", b"a path with . or .. segments, or an encoded slash", &[]))) };
    let host = host_of(&req);
    let (mut sess, user, roles) = handler_session(sql, req.headers(), host.as_deref());
    // the headers as handlers see them: HTTP/2's cookie fields as one Cookie header
    let pairs = |h: &hyper::HeaderMap| {
        let mut out: Vec<(String, String)> = h.iter().filter(|(k, _)| *k != hyper::header::COOKIE).map(|(k, v)| (k.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned())).collect();
        let c: Vec<String> = h.get_all(hyper::header::COOKIE).iter().map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned()).collect();
        if !c.is_empty() { out.push(("cookie".into(), c.join("; "))); }
        out
    };
    let mut h = HttpReq { method: req.method().as_str().to_string(), path: at.clone(), raw_path: req.uri().path().to_string(), query: req.uri().query().unwrap_or("").to_string(), headers: pairs(req.headers()), ip: ip.to_string(), params: vec![], body: None };
    let given = h.headers.clone();
    let answer = |r: Result<HttpOut, crate::functions::FnError>| -> Option<hyper::Response<Body>> {
        match r {
            Ok(HttpOut::Next(_)) => None,
            Ok(HttpOut::Respond { status, headers, body }) => {
                let mut b = hyper::Response::builder().status(status);
                let typed = headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type"));
                for (k, v) in &headers { if !["content-length", "connection", "keep-alive", "transfer-encoding"].iter().any(|x| k.eq_ignore_ascii_case(x)) { b = b.header(k.as_str(), v.as_str()); } }
                if !typed && !body.is_empty() { b = b.header("content-type", "text/plain; charset=utf-8"); }
                Some(b.body(full(body)).unwrap_or_else(|_| into_response(respond(500, "text/plain", b"a response header that HTTP can't carry", &[]))))
            }
            Err(e) => {
                let status = match e.code.as_str() { "AUTH" => 401, "DENIED" => 403, "NOT_FOUND" => 404, "LIMIT" => 503, "CONFLICT" => 409, "FUNCTION" => 500, _ => 400 };
                Some(into_response(json_resp(status, &json!({"error": e.message, "code": e.code}), &[])))
            }
        }
    };
    for (def, params) in sql.middleware_for(&at) {
        h.params = params;
        let Some(_turn) = turn(st).await else { return Err(busy()) };
        let r = tokio::task::block_in_place(|| sql.run_http(&mut sess, &def, &h, user.clone(), roles.clone()));
        if let Ok(HttpOut::Next(headers)) = &r { h.headers = headers.clone(); }
        if let Some(a) = answer(r) { return Err(a); }
    }
    if h.headers != given { let map = as_left(req.headers(), &given, &h.headers); *req.headers_mut() = map; }
    let Some((def, params)) = sql.route_for(&h.method, &at) else { return Ok(req) };
    let (_, mut body) = req.into_parts();
    h.params = params;
    h.body = Some(match read_body(&mut body, max).await { Ok(b) => b, Err(e) => return Err(into_response(json_resp(if e["code"] == "TOO_LARGE" { 413 } else { 400 }, &json!({"error": e["error"], "code": "ARGUMENTS"}), &[]))) });
    let Some(_turn) = turn(st).await else { return Err(busy()) };
    let r = tokio::task::block_in_place(|| sql.run_http(&mut sess, &def, &h, user, roles));
    Err(answer(r).unwrap_or_else(|| into_response(respond(204, "text/plain", b"", &[]))))
}
/// The headers as middleware left them, for what comes next: those it didn't change as they came, byte for byte (a
/// cookie needn't be UTF-8, and middleware saw it decoded), the rest as it set them.
fn as_left(came: &hyper::HeaderMap, given: &[(String, String)], left: &[(String, String)]) -> hyper::HeaderMap {
    let values = |hs: &[(String, String)], name: &str| -> Vec<String> { hs.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone()).collect() };
    let mut map = hyper::HeaderMap::new();
    let mut names: Vec<String> = left.iter().map(|(k, _)| k.to_ascii_lowercase()).collect(); names.sort(); names.dedup();
    for name in names {
        let Ok(k) = hyper::header::HeaderName::from_bytes(name.as_bytes()) else { continue };
        let now = values(left, &name);
        if now == values(given, &name) { for v in came.get_all(&k) { map.append(k.clone(), v.clone()); } continue; }
        for v in now { if let Ok(v) = hyper::header::HeaderValue::from_bytes(v.as_bytes()) { map.append(k.clone(), v); } }
    }
    map
}
/// Who middleware and routes act for: the session the request carries (cookie or bearer); else `app.anonymousRole`;
/// else no one, with no grants at all (`admin` is still the handler's to use). The user's row: only for a sign-in.
fn handler_session(sql: &Sql, headers: &hyper::HeaderMap, host: Option<&str>) -> (Session, Option<HashMap<String, Value>>, Vec<String>) {
    if let Some(t) = token_in(sql, headers, host) { let mut s = Session::default(); if sql.session_from_token(&mut s, &t).is_ok() { let (u, r) = (s.attrs.clone(), s.roles.clone()); return (s, Some(u), r); } }
    if let Some(r) = &sql.cfg.app.anonymous_role { let mut s = Session::default(); if sql.assume(&mut s, &[r.clone()], HashMap::new()).is_ok() { return (s, None, vec![r.clone()]); } }
    (Session { user: Some("(no one)".into()), ..Session::default() }, None, vec![])
}
/// The session token a request carries: `Authorization: Bearer …`, or the session cookie (from the API's own site;
/// read as bytes, so a cookie of the app's with other bytes in it doesn't hide it).
fn token_in(sql: &Sql, headers: &hyper::HeaderMap, host: Option<&str>) -> Option<String> {
    let bearer = headers.get(hyper::header::AUTHORIZATION).and_then(|h| h.to_str().ok()).and_then(|h| h.strip_prefix("Bearer ")).map(|t| t.trim().to_string());
    let name = crate::signin::session_name(sql);
    let ok = || crate::signin::cookie_origin_ok(sql, headers.get(hyper::header::ORIGIN).and_then(|o| o.to_str().ok()), host, headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()));
    let cookie = || headers.get_all(hyper::header::COOKIE).iter().map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned()).flat_map(|v| v.split(';').map(|c| c.trim().to_string()).collect::<Vec<_>>())
        .find_map(|c| c.split_once('=').filter(|(k, _)| *k == name).map(|(_, v)| url_decode(v))).filter(|_| ok());
    bearer.or_else(cookie).filter(|t| !t.is_empty())
}
/// The host a request was for: its Host header, or HTTP/2's authority.
fn host_of(req: &hyper::Request<Incoming>) -> Option<String> { req.headers().get(hyper::header::HOST).and_then(|h| h.to_str().ok()).map(String::from).or_else(|| req.uri().authority().map(|a| a.to_string())) }
/// Who a request for the app behind the API is from, for the app: `X-Sqz-User` (the user's key), `X-Sqz-Table` (the
/// table they sign in to: keys of two tables of users can be the same) and `X-Sqz-Roles`,
/// from the session the request carries (cookie or bearer); nothing for a request without one.
fn identity(sql: &Sql, headers: &hyper::HeaderMap, host: Option<&str>) -> Vec<(String, String)> {
    let Some(token) = token_in(sql, headers, host) else { return vec![] };
    let mut s = Session::default();
    if sql.session_from_token(&mut s, &token).is_err() { return vec![]; }
    let (table, key) = sql.token_owner(&token).ok().and_then(|o| o.split_once(':').map(|(t, k)| (t.to_ascii_lowercase(), k.to_string()))).unwrap_or_default();
    vec![("x-sqz-user".into(), key), ("x-sqz-table".into(), table), ("x-sqz-roles".into(), s.roles.join(","))]
}
/// A request's body, at most `max` bytes; past that, the rest is drained and the request refused.
async fn read_body(body: &mut Incoming, max: usize) -> Result<Vec<u8>, J> {
    let mut out = vec![];
    loop {
        let Ok(frame) = timeout(IO_TIMEOUT, body.frame()).await else { return Err(json!({"error": "the request body stalled", "code": "ARGUMENTS"})) };
        let Some(frame) = frame else { return Ok(out) };
        let Ok(frame) = frame else { return Err(json!({"error": "the request body did not arrive", "code": "ARGUMENTS"})) };
        if let Some(d) = frame.data_ref() {
            if out.len() + d.len() > max { drain(body).await; return Err(json!({"error": format!("the request is larger than {max} bytes (app.maxRequest)"), "code": "TOO_LARGE"})); }
            out.extend_from_slice(d);
        }
    }
}
/// After refusing a request whose body is still coming: read and drop the rest (up to 64 MB, for up to 10 s), so the
/// client gets to read the answer instead of a reset connection.
async fn drain(body: &mut Incoming) {
    let _ = timeout(Duration::from_secs(10), async { let mut n = 0usize; while let Some(Ok(f)) = body.frame().await { if let Some(d) = f.data_ref() { n += d.len(); if n > 64 << 20 { break; } } } }).await;
}
/// One request: the socket and files apart (they stream), the rest read whole (at most `app.maxRequest`) and answered
/// by `handle`, off the runtime's threads when it may block.
async fn route(weak: &Weak<Sql>, st: &Arc<AppState>, peer: IpAddr, mut req: hyper::Request<Incoming>) -> hyper::Response<Body> {
    let (method, path) = (req.method().as_str().to_string(), req.uri().path().to_string());
    let (max, ip, trusted, ours) = {
        let Some(sql) = weak.upgrade() else { return into_response(respond(503, "text/plain", b"shutting down", &[])) };
        let trusted = sql.cfg.app.trust_proxy.iter().any(|n| n.contains(peer));
        (sql.cfg.app.max_request, crate::proxy::client_ip(&sql.cfg.app.trust_proxy, peer, req.headers()), trusted, crate::proxy::ours(&sql, &path))
    };
    // a request for the app, not the API: a client's X-Sqz-… are dropped (only the API sets them), then the app's
    // middleware runs, and a route of the app's answers it, or it goes on (to the app behind, or a file)
    if !ours {
        let theirs: Vec<hyper::header::HeaderName> = req.headers().keys().filter(|k| k.as_str().starts_with("x-sqz-")).cloned().collect();
        for k in theirs { req.headers_mut().remove(k); }
        if let Some(sql) = weak.upgrade() {
            // the app's guards can't run: nothing of the app is served unguarded meanwhile
            if sql.functions_broken() { return into_response(respond(503, "text/html; charset=utf-8", b"<!doctype html><meta charset=utf-8><title>Unavailable</title><p>This site is unavailable: its server code (the deployed functions) doesn't load. The server's log says why.", &[("Cache-Control".into(), "no-store".into())])); }
            if sql.has_http() { req = match handlers(&sql, st, ip, req, max).await { Ok(r) => r, Err(answer) => return answer }; }
        }
    }
    let proxied = st.upstream.is_some() && !ours;
    if proxied {
        let host = host_of(&req); let who = weak.upgrade().map(|sql| identity(&sql, req.headers(), host.as_deref())).unwrap_or_default();
        return st.upstream.as_ref().expect("an upstream").forward(req, ip, peer, trusted, st.tls, &who).await;
    }
    if method == "GET" && path.trim_matches('/') == "api/socket" { return websocket(weak, st.links.clone(), req); }
    if method == "GET" && path == "/mcp" && weak.upgrade().is_some_and(|s| s.cfg.app.mcp.is_some()) { return mcp_events(weak, req); }
    if method == "POST" && path == "/api/files" { return upload(weak, st, req).await; }
    if (method == "GET" || method == "HEAD") && path.starts_with("/api/files/") { return download(weak, st, req).await; }
    let (parts, mut body) = req.into_parts();
    let body = match read_body(&mut body, max).await { Ok(b) => b, Err(e) => return into_response(json_resp(if e["code"] == "TOO_LARGE" { 413 } else { 400 }, &json!({"error": e["error"], "code": "ARGUMENTS"}), &[])) };
    let req = req_of(&parts, body);
    let Some(sql) = weak.upgrade() else { return into_response(respond(503, "text/plain", b"shutting down", &[])) };
    into_response(if req.method == "POST" && req.path.starts_with("/api/fn/") {
        // a function may run up to functions.timeout: this worker's other tasks move to another while it does, which
        // is cheaper per call than handing the call to the blocking pool and back; its turn first
        let Some(_turn) = turn(st).await else { return busy() };
        tokio::task::block_in_place(|| handle(&sql, st, ip, &req))
    } else if blocks(&sql, &req) {
        let hashes = req.method == "POST" && ((req.path.starts_with("/api/auth/") && (req.path.ends_with("/sign-up") || req.path.ends_with("/sign-in"))) || req.path == "/oauth/authorize" || req.path == "/_sqz/sign-in");   // the MCP and API sign-in pages hash too
        let _turn = if hashes { st.hashing.acquire().await.ok() } else { None };
        let st = st.clone();
        match tokio::task::spawn_blocking(move || handle(&sql, &st, ip, &req)).await { Ok(out) => out, Err(_) => respond(500, "text/plain", b"the request failed", &[]) }
    } else { handle(&sql, st, ip, &req) })
}

/// One HTTP request (not the socket): the whole response.
fn handle(sql: &Sql, st: &AppState, ip: IpAddr, req: &Req) -> Vec<u8> {
    if let Some(r) = crate::mcp::handle(sql, &st.mcp, &st.links, ip, &|| st.allow(ip), req) { return r; }
    if let Some(r) = crate::signin::handle(sql, ip, &|| st.allow(ip), req) { return r; }
    let api = req.path.starts_with("/api/");
    let origin = match allowed_origin(sql, req) { Ok(o) => o, Err(()) if api => return json_resp(403, &json!({"error": "permission denied: this origin may not call the API (app.origins)", "code": "DENIED"}), &[]), Err(()) => None };
    let h = cors(&origin);
    let reply = |r: Result<J, J>| match r { Ok(v) => json_resp(200, &v, &h), Err(e) => json_resp(status_of(&e), &e, &h) };
    let path: Vec<&str> = req.path.trim_matches('/').split('/').collect();
    match (req.method.as_str(), path.as_slice()) {
        ("OPTIONS", ["api", ..]) => { let mut h = h.clone(); h.extend([("Access-Control-Allow-Methods".into(), "GET, POST, OPTIONS".into()), ("Access-Control-Allow-Headers".into(), "Authorization, Content-Type".into()), ("Access-Control-Max-Age".into(), "600".into())]); respond(204, "text/plain", b"", &h) }
        ("POST", ["api", op @ ("sql" | "batch")]) => reply(body_json(req).and_then(|v| { let mut s = session_for(sql, crate::signin::token_of(sql, req).as_deref())?; if *op == "sql" { run(sql, &st.links, &mut s, &v) } else { run_batch(sql, &st.links, &mut s, &v) } })),
        ("POST", ["api", "fn", name]) => {
            let r = (if req.body.iter().all(|b| b.is_ascii_whitespace()) { Ok(J::Null) } else { body_json(req) }).and_then(|v| { let token = crate::signin::token_of(sql, req); let mut s = session_for(sql, token.as_deref())?; call(sql, &mut s, name, &v, token.is_none()) });
            match r { Err(e) if e["code"] == "NOT_FOUND" => json_resp(404, &e, &h), r => reply(r) }
        }
        ("GET", ["api", "me"]) => reply(session_for(sql, crate::signin::token_of(sql, req).as_deref()).map(|s| json!({"user": J::Object(s.attrs.iter().map(|(k, v)| (k.clone(), value_json(v, None))).collect()), "roles": s.roles}))),
        ("GET", ["api", "auth", table, "methods"]) => reply(sql.auth_table_of(table).map_err(err_json).map(|_| {
            let providers: Vec<&String> = if sql.cfg.app.public_url.is_some() { sql.cfg.auth.oauth.keys().collect() } else { vec![] };
            json!({"signUp": sql.cfg.app.sign_up.contains_key(&table.to_ascii_lowercase()), "providers": providers})
        })),
        ("POST", ["api", "auth", "sign-out"]) => {
            if let Some(t) = crate::signin::token_of(sql, req) { let _ = sql.sign_out(&t); }
            let mut h = h.clone(); if crate::app::cookie(req, crate::signin::session_name(sql)).is_some() { h.push(("Set-Cookie".into(), crate::signin::clear_session(sql))); }
            json_resp(200, &json!({}), &h)
        }
        // device login: a device (a CLI, a server) asks for a code, its user lets it in from a signed-in browser
        // (/_sqz/device), and it polls for its session
        ("POST", ["api", "auth", "device"]) => if !st.allow(ip) { json_resp(429, &limited(), &h) } else {
            let v = if req.body.iter().all(|b| b.is_ascii_whitespace()) { Ok(json!({})) } else { body_json(req) };
            match v.and_then(|v| sql.device_start(v.get("name").and_then(|n| n.as_str()).unwrap_or(""), &ip.to_string()).map_err(|e| json!({"error": e, "code": "LIMIT"}))) {
                // (no verification_uri_complete: a link that carries the code is a phishing link waiting to happen;
                // the user types the code their device shows)
                Ok((device, user)) => {
                    json_resp(200, &json!({"device_code": device, "user_code": user, "verification_uri": format!("{}/_sqz/device", crate::signin::site(sql, req)),
                        "expires_in": crate::auth::DEVICE_TTL.as_secs(), "interval": crate::auth::DEVICE_INTERVAL.as_secs()}), &h)
                }
                Err(e) => json_resp(status_of(&e), &e, &h),
            }
        },
        ("POST", ["api", "auth", "device", "token"]) => match body_json(req) {
            Ok(v) => match sql.device_poll(v.get("device_code").and_then(|c| c.as_str()).unwrap_or("")) {
                Ok((table, si)) => signed_reply(sql, signed_json(sql, &table, &si), false, &h),
                Err(code) => json_resp(400, &json!({"code": code, "error": match code {
                    "PENDING" => "waiting for the user to let this device in", "SLOW_DOWN" => "polling too often: wait the interval between polls",
                    "DENIED" => "the user did not let this device in", _ => "an unknown or expired device code: start again" }}), &h),
            },
            Err(e) => json_resp(status_of(&e), &e, &h),
        },
        ("POST", ["api", "auth", "exchange"]) => if !st.allow(ip) { json_resp(429, &limited(), &h) } else { body_json(req).and_then(|v| {
            let code = v.get("code").and_then(|c| c.as_str()).unwrap_or(""); let verifier = v.get("verifier").and_then(|c| c.as_str()).unwrap_or("");
            let held = st.codes.lock().unwrap().remove(code);   // one attempt per code, whatever the verifier
            match held {
                Some((signed, challenge, at)) if at.elapsed() < CODE_TTL && verifier.len() >= 43 && crate::net::same_secret(challenge_of(verifier).as_bytes(), challenge.as_bytes()) => Ok((signed, v.get("cookie") == Some(&J::Bool(true)))),
                _ => Err(json!({"error": "sign-in failed: an unknown or expired sign-in code, or one this page did not start; sign in again", "code": "AUTH"})),
            }
        }).map(|(signed, c)| signed_reply(sql, signed, c, &h)).unwrap_or_else(|e| json_resp(status_of(&e), &e, &h)) },
        ("POST", ["api", "auth", table, op @ ("sign-up" | "sign-in")]) => if !st.allow(ip) { json_resp(429, &limited(), &h) } else { body_json(req).and_then(|v| {
            let pw = v.get("password").and_then(|p| p.as_str()).unwrap_or("");
            let r = if *op == "sign-up" { sql.sign_up(table, &sign_up_fields(sql, table, &v)?, pw) } else { sql.sign_in(table, v.get("login").and_then(|l| l.as_str()).unwrap_or(""), pw) };
            r.map(|si| (signed_json(sql, table, &si), v.get("cookie") == Some(&J::Bool(true)))).map_err(err_json)
        }).map(|(signed, c)| signed_reply(sql, signed, c, &h)).unwrap_or_else(|e| json_resp(status_of(&e), &e, &h)) },
        ("GET", ["api", "auth", table, "oauth", provider]) => {
            let back = req.query.get("return").cloned().unwrap_or_default();
            let Some(base) = sql.cfg.app.public_url.clone() else { return json_resp(400, &json!({"error": "set app.publicUrl to sign in with a provider", "code": "CONFIG"}), &h) };
            // `cookie=1`: the session comes back as the session cookie, and the browser to `return` on this site (the
            // API's own sign-in page, the client in cookie mode); otherwise as a one-time code for the page to trade
            let cookie_mode = req.query.get("cookie").map(String::as_str) == Some("1");
            let back = if cookie_mode { crate::signin::back_to(sql, &back) } else { back };
            if !cookie_mode && !return_ok(sql, &back) { return json_resp(400, &json!({"error": "return must be a URL on one of app.origins", "code": "ARGUMENTS"}), &h); }
            let challenge = req.query.get("challenge").cloned().unwrap_or_default();
            if !cookie_mode && !is_challenge(&challenge) { return json_resp(400, &json!({"error": "challenge must be the base64url SHA-256 of a verifier the page keeps (the client's signInWith makes both)", "code": "ARGUMENTS"}), &h); }
            let callback = format!("{base}/api/auth/{table}/oauth/{provider}/callback");
            match sql.oauth_start(table, provider, &callback, None) {
                Ok(start) => {
                    let attrs = format!("Path=/api/auth/; HttpOnly; SameSite=Lax; Max-Age=600{}", if base.starts_with("https://") { "; Secure" } else { "" });
                    let mode = if cookie_mode { format!("sqz_mode=cookie; {attrs}") } else { format!("sqz_mode=; Path=/api/auth/; HttpOnly; Max-Age=0") };
                    let challenge = if is_challenge(&challenge) { challenge } else { String::new() };   // (it goes into a cookie: only ever a challenge)
                    redirect(&start.url, &[format!("sqz_oauth={}; {attrs}", start.cookie), format!("sqz_return={}; {attrs}", enc(&back)), format!("sqz_challenge={challenge}; {attrs}"), mode])
                }
                Err(e) => json_resp(400, &err_json(e), &h),
            }
        }
        ("GET", ["api", "auth", table, "oauth", provider, "callback"]) => {
            let cookie_mode = cookie(req, "sqz_mode").as_deref() == Some("cookie");
            let back = cookie(req, "sqz_return").map(|b| if cookie_mode { crate::signin::back_to(sql, &b) } else { b }).filter(|b| cookie_mode || return_ok(sql, b));
            let mut clear: Vec<String> = ["sqz_oauth", "sqz_return", "sqz_challenge", "sqz_mode"].iter().map(|c| format!("{c}=; Path=/api/auth/; HttpOnly; Max-Age=0")).collect();
            let challenge = cookie(req, "sqz_challenge").filter(|c| is_challenge(c));
            let result = match (req.query.get("error"), req.query.get("code"), req.query.get("state")) {
                (Some(e), _, _) => Err(format!("sign-in failed: the provider answered {e}")),
                _ if challenge.is_none() && !cookie_mode => Err("sign-in failed: this browser did not start this sign-in".into()),
                (None, Some(code), Some(state)) => { let create = sql.cfg.app.sign_up.contains_key(&table.to_ascii_lowercase()); sql.oauth_finish_as(table, provider, code, state, &cookie(req, "sqz_oauth").unwrap_or_default(), create) }
                _ => Err("sign-in failed: the provider sent no code".into()),
            };
            match (back, result) {
                // cookie mode: signed in where the sign-in started (the state cookie bound it to this browser)
                (Some(b), Ok(si)) if cookie_mode => { clear.push(crate::signin::session_cookie(sql, &si.token)); redirect(&b, &clear) }
                (Some(b), Err(e)) if cookie_mode => redirect(&format!("/_sqz/sign-in?return={}&error={}", enc(&b), enc(&e)), &clear),
                (Some(b), Ok(si)) => {
                    let code = { let mut raw = [0u8; 24]; getrandom::fill(&mut raw).expect("random"); raw.iter().map(|x| format!("{x:02x}")).collect::<String>() };
                    { let mut codes = st.codes.lock().unwrap(); codes.retain(|_, (_, _, at)| at.elapsed() < CODE_TTL); codes.insert(code.clone(), (signed_json(sql, table, &si), challenge.unwrap_or_default(), Instant::now())); }
                    redirect(&format!("{b}#sqz_code={code}"), &clear)
                }
                (Some(b), Err(e)) => redirect(&format!("{b}#sqz_error={}", enc(&e)), &clear),
                (None, r) => respond(400, "text/plain; charset=utf-8", match &r { Ok(_) => "sign-in finished, but the page to return to is gone; start again".as_bytes(), Err(e) => e.as_bytes() }, &[]),
            }
        }
        ("GET", ["api", "client.js"]) => { let mut h = h.clone(); h.push(("Cache-Control".into(), "no-cache".into())); respond(200, "text/javascript; charset=utf-8", CLIENT_JS.as_bytes(), &h) }
        ("GET", _) if !api => match &sql.cfg.app.static_dir { Some(dir) => static_file(dir, &req.path), None => respond(404, "text/plain", b"not found", &[]) },
        _ => json_resp(404, &json!({"error": "no such endpoint", "code": "ERROR"}), &h),
    }
}

// ---------- files: uploads, and downloads through signed links ----------
/// `POST /api/files?name=<file name>`, the bytes as the body (`Content-Type` its type): a new file owned by the
/// signed-in user, answered with the file as a query returns it. Streams to disk.
async fn upload(weak: &Weak<Sql>, st: &AppState, req: hyper::Request<Incoming>) -> hyper::Response<Body> {
    let Some(sql) = weak.upgrade() else { return into_response(respond(503, "text/plain", b"shutting down", &[])) };
    let (parts, mut body) = req.into_parts(); let head = req_of(&parts, vec![]);
    let origin = allowed_origin(&sql, &head);
    let h = cors(&origin.clone().unwrap_or(None)); let reply = |status: u16, v: J| into_response(json_resp(status, &v, &h));
    // refused before its bytes are read: the rest of them are drained first, so the client reads why
    let mut sess = Session::default();
    let ready = (|| -> Result<(u64, std::path::PathBuf), (u16, J)> {
        if origin.is_err() { return Err((403, json!({"error": "permission denied: this origin may not call the API (app.origins)", "code": "DENIED"}))); }
        let len = head.headers.get("content-length").and_then(|v| v.parse::<u64>().ok()).ok_or((411, json!({"error": "an upload needs a Content-Length", "code": "ARGUMENTS"})))?;
        let max = sql.cfg.app.file_max;
        if len > max { return Err((413, json!({"error": format!("the file is larger than {max} bytes (app.files.maxSize)"), "code": "ARGUMENTS"}))); }
        match crate::signin::token_of(&sql, &head) { Some(t) => sql.session_from_token(&mut sess, &t).map_err(|e| (401, err_json(e)))?, None => return Err((401, json!({"error": "session: sign in to upload files", "code": "AUTH"}))) }
        Ok((len, sql.file_staging().map_err(|e| (500, err_json(e)))?))
    })();
    let (len, staged) = match ready { Ok(x) => x, Err((status, e)) => { drain(&mut body).await; return reply(status, e); } };
    let copied = async {
        use sha2::Digest;
        let mut f = tokio::fs::File::create(&staged).await?; let mut hash = sha2::Sha256::new(); let mut got = 0u64;
        while got < len {
            let frame = timeout(IO_TIMEOUT, body.frame()).await.map_err(|_| io::Error::other("the upload stalled"))?;
            let Some(frame) = frame else { return Err(io::Error::other("the upload ended early")) };
            let Ok(data) = frame.map_err(io::Error::other)?.into_data() else { continue };
            if got + data.len() as u64 > len { return Err(io::Error::other("the upload is longer than its Content-Length")); }
            hash.update(&data); f.write_all(&data).await?; got += data.len() as u64;
        }
        if sql.db.durable { f.sync_all().await?; }
        Ok::<[u8; 32], io::Error>(hash.finalize().into())
    }.await;
    let sha = match copied { Ok(sha) => sha, Err(e) => { let _ = std::fs::remove_file(&staged); return reply(400, json!({"error": format!("upload: {e}"), "code": "ARGUMENTS"})) } };
    let name = head.query.get("name").cloned().unwrap_or_else(|| "file".into());
    let ctype = head.headers.get("content-type").cloned().unwrap_or_else(|| "application/octet-stream".into());
    let added = { let (sql, links) = (sql.clone(), st.links.clone());
        tokio::task::spawn_blocking(move || sql.file_add(&sess, &staged, &name, &ctype, len, sha).map(|m| file_json(&sql, &links, &m.id))).await };
    match added { Ok(Ok(v)) => reply(200, v), Ok(Err(e)) => reply(status_of(&err_json(e.clone())), err_json(e)), Err(_) => reply(500, json!({"error": "the upload failed", "code": "ERROR"})) }
}
/// Types a browser may show in place (with nosniff and a sandbox): anything else downloads as an attachment, so a
/// file can never be a page (HTML, SVG …) running on the API's origin.
fn inline_type(t: &str) -> bool {
    matches!(t, "image/png" | "image/jpeg" | "image/gif" | "image/webp" | "image/avif" | "image/bmp" | "application/pdf" | "text/plain") || t.starts_with("video/") || t.starts_with("audio/")
}
/// `GET /api/files/<id>?e=…&s=…`: the file, if the link is one a query handed out and still works. ETags, and
/// single byte ranges (seeking in a video); the bytes stream from disk.
/// MCP's event stream (`GET /mcp`): what the server tells an agent unasked. Here, that its tools changed (a deploy, or
/// other roles for its user), so it lists them again. A comment every 25 s keeps proxies from closing it; it ends
/// when the agent's token no longer holds, or the server stops.
fn mcp_events(weak: &Weak<Sql>, req: hyper::Request<Incoming>) -> hyper::Response<Body> {
    const CHANGED: &[u8] = b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n";
    struct Watch { weak: Weak<Sql>, token: String, sess: Session, version: u64, digest: u64, checked: Instant, beat: Instant }
    let Some(sql) = weak.upgrade() else { return into_response(respond(503, "text/plain", b"shutting down", &[])) };
    let (parts, _) = req.into_parts();
    let (sess, token, h) = match crate::mcp::events(&sql, &req_of(&parts, vec![])) { Ok(x) => x, Err(refused) => return into_response(refused) };
    let now = Instant::now();
    let w = Watch { weak: weak.clone(), token, version: sql.functions_version(), digest: crate::mcp::tools_digest(&sql, &sess), sess, checked: now, beat: now };
    drop(sql);
    let opened = futures_util::stream::once(async { Ok::<_, io::Error>(Frame::data(Bytes::from_static(b": open\n\n"))) });
    let events = futures_util::stream::unfold(w, |mut w| async move {
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let sql = w.weak.upgrade()?;
            let mut look = false;
            if w.checked.elapsed() > Duration::from_secs(30) {
                // the token still holds (and carries the roles its user has now)
                w.checked = Instant::now();
                let mut fresh = Session::default();
                if sql.mcp_session(&mut fresh, &w.token).is_err() { return None; }
                w.sess = fresh; look = true;
            }
            let v = sql.functions_version(); if v != w.version { w.version = v; look = true; }
            if look { let d = crate::mcp::tools_digest(&sql, &w.sess); if d != w.digest { w.digest = d; return Some((Ok(Frame::data(Bytes::from_static(CHANGED))), w)); } }
            if w.beat.elapsed() > Duration::from_secs(25) { w.beat = Instant::now(); return Some((Ok(Frame::data(Bytes::from_static(b": keep-alive\n\n"))), w)); }
        }
    });
    let mut b = hyper::Response::builder().status(200).header("content-type", "text/event-stream").header("cache-control", "no-store").header("x-accel-buffering", "no");
    for (k, v) in &h { b = b.header(k.as_str(), v.as_str()); }
    b.body(http_body_util::StreamBody::new(futures_util::StreamExt::chain(opened, events)).boxed()).unwrap_or_else(|_| into_response(respond(500, "text/plain", b"the stream failed", &[])))
}

async fn download(weak: &Weak<Sql>, st: &AppState, req: hyper::Request<Incoming>) -> hyper::Response<Body> {
    let Some(sql) = weak.upgrade() else { return into_response(respond(503, "text/plain", b"shutting down", &[])) };
    let (parts, _) = req.into_parts(); let req = req_of(&parts, vec![]);
    let origin = allowed_origin(&sql, &req).unwrap_or(None);   // a link is a capability: any page may show it, CORS only for allowed origins
    let mut h = cors(&origin);
    let id = req.path["/api/files/".len()..].to_string();
    let q = |k: &str| req.query.get(k).map(String::as_str).unwrap_or("");
    if !st.links.check(&id, q("e"), q("s")) { return into_response(json_resp(403, &json!({"error": "permission denied: this link is not one this server made, or it has expired; read the row again for a new one", "code": "DENIED"}), &h)); }
    let Some(m) = sql.file_meta(&id) else { return into_response(json_resp(404, &json!({"error": "no such file", "code": "NOT_FOUND"}), &h)) };
    let etag = format!("\"{}\"", m.sha256[..16].iter().map(|b| format!("{b:02x}")).collect::<String>());
    let age = q("e").parse::<i64>().unwrap_or(0) - now_secs();
    let disposition = if inline_type(&m.ctype) { "inline" } else { "attachment" };
    h.extend([("ETag".into(), etag.clone()), ("Cache-Control".into(), format!("private, max-age={age}, immutable")), ("Accept-Ranges".into(), "bytes".into()),
              ("Content-Disposition".into(), format!("{disposition}; filename*=UTF-8''{}", enc(&m.name))), ("Content-Security-Policy".into(), "default-src 'none'; sandbox".into()),
              ("Cross-Origin-Resource-Policy".into(), "cross-origin".into())]);
    let response = |status: u16, len: u64, h: &[(String, String)], body: Body| {
        let mut b = hyper::Response::builder().status(status).header("content-type", m.ctype.as_str()).header("content-length", len).header("x-content-type-options", "nosniff");
        for (k, v) in h { b = b.header(k.as_str(), v.as_str()); }
        b.body(body).unwrap_or_else(|_| into_response(respond(500, "text/plain", b"a response header that HTTP can't carry", &[])))
    };
    let empty = || full(Bytes::new());
    if req.headers.get("if-none-match").is_some_and(|v| v.split(',').any(|t| t.trim() == etag)) { return response(304, 0, &h, empty()); }
    let size = m.size as u64;
    let range = req.headers.get("range").and_then(|r| r.strip_prefix("bytes=")).filter(|r| !r.contains(',')).map(|r| {
        let (a, b) = r.split_once('-').unwrap_or((r, ""));
        match (a.trim().parse::<u64>().ok(), b.trim().parse::<u64>().ok()) { (Some(a), Some(b)) => (a, b.min(size.saturating_sub(1))), (Some(a), None) => (a, size.saturating_sub(1)), (None, Some(n)) => (size.saturating_sub(n), size.saturating_sub(1)), _ => (1, 0) }
    });
    let (status, start, end) = match range {
        None => (200, 0, size.saturating_sub(1)),
        Some((a, b)) if a <= b && b < size => { h.push(("Content-Range".into(), format!("bytes {a}-{b}/{size}"))); (206, a, b) }
        Some(_) => { h.push(("Content-Range".into(), format!("bytes */{size}"))); return response(416, 0, &h, empty()); }
    };
    let len = if size == 0 { 0 } else { end - start + 1 };
    if req.method == "HEAD" || len == 0 { return response(status, len, &h, empty()); }
    let file = async { use tokio::io::AsyncSeekExt; let mut f = tokio::fs::File::open(sql.file_path(&id)).await?; f.seek(std::io::SeekFrom::Start(start)).await?; Ok::<_, io::Error>(f) }.await;
    let Ok(file) = file else { return into_response(json_resp(404, &json!({"error": "the file is gone", "code": "NOT_FOUND"}), &h)) };
    let chunks = futures_util::stream::unfold((file, len), |(mut f, left)| async move {
        if left == 0 { return None; }
        let mut buf = vec![0u8; (64 << 10).min(left as usize)];
        match f.read(&mut buf).await {
            Ok(0) => Some((Err(io::Error::other("the file is shorter than its record")), (f, 0))),
            Ok(n) => { buf.truncate(n); Some((Ok(Frame::data(Bytes::from(buf))), (f, left - n as u64))) }
            Err(e) => Some((Err(e), (f, 0))),
        }
    });
    response(status, len, &h, http_body_util::StreamBody::new(chunks).boxed())
}

/// A file under `dir` (no `..`, no hidden files); a path without a file gets `index.html` (an app's own routes).
fn static_file(dir: &std::path::Path, path: &str) -> Vec<u8> {
    let not_found = || respond(404, "text/plain", b"not found", &[]);
    let rel = url_decode(path); let rel = rel.trim_start_matches('/');
    if rel.split('/').any(|s| s == ".." || s.starts_with('.')) || rel.contains('\\') || rel.contains('\0') { return not_found(); }
    let mut p = dir.join(if rel.is_empty() { "index.html" } else { rel });
    if p.is_dir() { p = p.join("index.html"); }
    if !p.is_file() { if rel.rsplit('/').next().map(|l| l.contains('.')).unwrap_or(false) { return not_found(); } p = dir.join("index.html"); }
    let Ok(body) = std::fs::read(&p) else { return not_found() };
    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
    let ct = match ext.as_str() { "html" | "htm" => "text/html; charset=utf-8", "js" | "mjs" => "text/javascript; charset=utf-8", "css" => "text/css; charset=utf-8", "json" | "map" => "application/json", "svg" => "image/svg+xml", "png" => "image/png", "jpg" | "jpeg" => "image/jpeg", "gif" => "image/gif", "webp" => "image/webp", "ico" => "image/x-icon", "wasm" => "application/wasm", "woff2" => "font/woff2", "txt" => "text/plain; charset=utf-8", _ => "application/octet-stream" };
    respond(200, ct, &body, &[("Cache-Control".into(), "no-cache".into())])
}

// ---------- WebSocket (RFC 6455): text frames carrying JSON ----------
fn ws_accept(key: &str) -> String { let d = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes()); crate::util::base64(d.as_ref()) }
fn frame(op: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(payload.len() + 10); f.push(0x80 | op);
    match payload.len() { n if n < 126 => f.push(n as u8), n if n <= 0xffff => { f.push(126); f.extend_from_slice(&(n as u16).to_be_bytes()); } n => { f.push(127); f.extend_from_slice(&(n as u64).to_be_bytes()); } }
    f.extend_from_slice(payload); f
}
/// One frame: (fin, opcode, unmasked payload). Client frames must be masked.
async fn read_frame(r: &mut (impl AsyncRead + Unpin), max: usize) -> io::Result<(bool, u8, Vec<u8>)> {
    let mut h = [0u8; 2]; r.read_exact(&mut h).await?;
    let (fin, op, masked) = (h[0] & 0x80 != 0, h[0] & 0x0f, h[1] & 0x80 != 0);
    let mut len = (h[1] & 0x7f) as u64;
    if len == 126 { let mut b = [0u8; 2]; r.read_exact(&mut b).await?; len = u16::from_be_bytes(b) as u64; } else if len == 127 { let mut b = [0u8; 8]; r.read_exact(&mut b).await?; len = u64::from_be_bytes(b); }
    if !masked { return Err(io::Error::other("a client frame must be masked")); }
    if len > max as u64 { return Err(io::Error::other("message too large")); }
    let mut mask = [0u8; 4]; r.read_exact(&mut mask).await?;
    let mut p = vec![0u8; len as usize]; r.read_exact(&mut p).await?;
    for (i, b) in p.iter_mut().enumerate() { *b ^= mask[i % 4]; }
    Ok((fin, op, p))
}
/// A socket's state, shared by its reader (messages in) and its writer (replies, live results and pings out).
struct Conn { sess: Mutex<Session>, signed_in: AtomicBool, lives: Mutex<HashMap<u64, (Subscription, Shape)>>, changed: Arc<Notify>, done: Notify, sql: Weak<Sql>, links: Arc<Links> }
enum Out { Text(J), Pong(Vec<u8>), Close(Vec<u8>) }

/// `GET /api/socket`: answer the upgrade (HTTP/1.1), then run the socket on the connection hyper hands over.
fn websocket(weak: &Weak<Sql>, links: Arc<Links>, mut req: hyper::Request<Incoming>) -> hyper::Response<Body> {
    let Some(sql) = weak.upgrade() else { return into_response(respond(503, "text/plain", b"shutting down", &[])) };
    let head = { let (parts, body) = req.into_parts(); let head = req_of(&parts, vec![]); req = hyper::Request::from_parts(parts, body); head };
    let upgrade = head.headers.get("upgrade").map(|u| u.eq_ignore_ascii_case("websocket")).unwrap_or(false);
    let Some(key) = head.headers.get("sec-websocket-key").filter(|_| upgrade) else { return into_response(json_resp(400, &json!({"error": "expected a WebSocket upgrade", "code": "ARGUMENTS"}), &[])) };
    if allowed_origin(&sql, &head).is_err() { return into_response(json_resp(403, &json!({"error": "permission denied: this origin may not call the API (app.origins)", "code": "DENIED"}), &[])); }
    // a session acts as the cookie's user, or as the anonymous role (if any) until an `auth` message names a token
    let s0 = match crate::signin::token_of(&sql, &head) { Some(t) => { let mut s = Session::default(); if sql.session_from_token(&mut s, &t).is_ok() { s } else { anonymous_session(&sql) } } None => anonymous_session(&sql) };
    drop(sql);
    let weak = weak.clone();
    tokio::spawn(async move {
        let Ok(up) = hyper::upgrade::on(req).await else { return };
        let (rd, w) = tokio::io::split(hyper_util::rt::TokioIo::new(up));
        socket(weak, BufReader::with_capacity(4 << 10, rd), w, s0, links).await
    });
    hyper::Response::builder().status(101).header("upgrade", "websocket").header("connection", "Upgrade").header("sec-websocket-accept", ws_accept(key)).body(full(Bytes::new())).expect("a 101")
}
/// A socket, once upgraded: messages in (the reader), replies and live results out (the writer).
async fn socket<R: AsyncRead + Unpin, W: AsyncWrite + Unpin + Send + 'static>(weak: Weak<Sql>, mut r: BufReader<R>, w: W, s0: Session, links: Arc<Links>) {
    let conn = Arc::new(Conn { signed_in: AtomicBool::new(s0.user.is_some()), sess: Mutex::new(s0), lives: Mutex::new(HashMap::new()), changed: Arc::new(Notify::new()), done: Notify::new(), sql: weak.clone(), links });
    let (tx, rx) = mpsc::channel(OUT_QUEUE);
    let writer = tokio::spawn(write_loop(conn.clone(), w, rx));
    tokio::select! { _ = read_loop(&weak, &conn, &mut r, &tx) => {}, _ = conn.done.notified() => {} }
    drop(tx); conn.lives.lock().unwrap().clear();
    let _ = writer.await;
}
/// The socket's reader: each message runs as the socket's session, and its replies queue for the writer.
async fn read_loop<R: AsyncRead + Unpin>(weak: &Weak<Sql>, conn: &Arc<Conn>, r: &mut BufReader<R>, tx: &mpsc::Sender<Out>) -> io::Result<()> {
    let mut msg: Vec<u8> = vec![]; let mut text = false;
    let Some(max) = weak.upgrade().map(|s| s.cfg.app.max_request) else { return Ok(()) };
    loop {
        let (fin, op, p) = timeout(SOCKET_TIMEOUT, read_frame(r, max)).await.map_err(|_| io::Error::other("the client went quiet"))??;
        match op {
            0x8 => { let _ = tx.send(Out::Close(p[..p.len().min(2)].to_vec())).await; return Ok(()); }
            0x9 => { if tx.send(Out::Pong(p)).await.is_err() { return Ok(()); } continue; }
            0xA => continue,
            0x1 => { msg.clear(); text = true; }
            0x0 if text => {}
            _ => return Err(io::Error::other("text frames only")),
        }
        msg.extend_from_slice(&p);
        if msg.len() > max { return Err(io::Error::other("message too large")); }
        if !fin { continue; }
        text = false;
        let Some(sql) = weak.upgrade() else { return Ok(()) };
        let (out, live) = match serde_json::from_slice::<J>(&msg) {
            Err(e) => (vec![json!({"error": format!("bad JSON: {e}"), "code": "ARGUMENTS"})], None),
            // may wait for an fsync or the embeddings endpoint, or run a function: off the runtime's threads
            Ok(v) if sql_may_wait(&sql) || v.get("op").and_then(|o| o.as_str()) == Some("call") => {
                let c = conn.clone();
                let Ok(x) = tokio::task::spawn_blocking(move || message(&sql, &c, &v)).await else { return Err(io::Error::other("a message failed")) };
                x
            }
            Ok(v) => { let x = message(&sql, conn, &v); drop(sql); x }
        };
        for m in out { if tx.send(Out::Text(m)).await.is_err() { return Ok(()); } }
        // a new live query delivers changes only once its first result is queued, so no change can overtake it
        if let Some((lid, sub, shape)) = live {
            let n = conn.changed.clone(); let mut lives = conn.lives.lock().unwrap();
            lives.insert(lid, (sub, shape)); lives[&lid].0.set_waker(Arc::new(move || n.notify_one()));
        }
    }
}
/// One message from a socket, run as its session: the replies, and a live query to deliver from once they are queued.
fn message(sql: &Arc<Sql>, conn: &Conn, v: &J) -> (Vec<J>, Option<(u64, Subscription, Shape)>) {
    let id = v.get("id").cloned().unwrap_or(J::Null);
    let reply = |mut out: J| -> J { out["id"] = id.clone(); out };
    let sign_in_first = || json!({"error": "session: sign in first", "code": "AUTH"});
    let signed_in = conn.signed_in.load(Ordering::Relaxed);
    match v.get("op").and_then(|o| o.as_str()).unwrap_or("") {
        "auth" => {
            // a token: act as its user from now on; `token: null`: sign out
            let r = match v.get("token") {
                Some(J::String(t)) => { let mut s = Session::default(); sql.session_from_token(&mut s, t).map(|()| (s, true)).map_err(err_json) }
                Some(J::Null) => { let s = anonymous_session(sql); let anonymous = s.user.is_some(); Ok((s, anonymous)) }
                _ => Err(json!({"error": "auth needs a token (null signs out)", "code": "ARGUMENTS"})),
            };
            match r {
                Ok((s, now_signed_in)) => {
                    // a new identity: live queries made as the old one end
                    let mut out: Vec<J> = conn.lives.lock().unwrap().drain().map(|(lid, _)| json!({"id": lid, "ended": true, "reason": "identity changed"})).collect();
                    let user = if s.token.is_some() { J::Object(s.attrs.iter().map(|(k, v)| (k.clone(), value_json(v, None))).collect()) } else { J::Null };
                    *conn.sess.lock().unwrap() = s; conn.signed_in.store(now_signed_in, Ordering::Relaxed);
                    out.push(reply(json!({"ok": true, "user": user}))); (out, None)
                }
                Err(e) => (vec![reply(e)], None),
            }
        }
        op @ ("sql" | "batch") => {
            let out = if !signed_in { Err(sign_in_first()) } else { let mut s = conn.sess.lock().unwrap(); if op == "sql" { run(sql, &conn.links, &mut s, v) } else { run_batch(sql, &conn.links, &mut s, v) } };
            (vec![reply(out.unwrap_or_else(|e| e))], None)
        }
        "call" => {
            let out = if !signed_in { Err(sign_in_first()) } else {
                let mut s = conn.sess.lock().unwrap(); let anonymous = s.token.is_none();
                call(sql, &mut s, v.get("name").and_then(|n| n.as_str()).unwrap_or(""), v.get("args").unwrap_or(&J::Null), anonymous)
            };
            (vec![reply(out.unwrap_or_else(|e| e))], None)
        }
        "live" => {
            let out = (|| -> Result<(J, u64, Subscription, Shape), J> {
                if !signed_in { return Err(sign_in_first()); }
                let lid = id.as_u64().ok_or_else(|| json!({"error": "a live query needs a numeric id", "code": "ARGUMENTS"}))?;
                if conn.lives.lock().unwrap().len() >= MAX_LIVES { return Err(json!({"error": format!("at most {MAX_LIVES} live queries per connection"), "code": "ARGUMENTS"})); }
                let p = client_statement(sql, v.get("sql").and_then(|s| s.as_str()).unwrap_or(""))?;
                if !matches!(p.plan, Plan::Select(_)) { return Err(json!({"error": "a live query is a SELECT", "code": "ARGUMENTS"})); }
                let params = params_of(v)?; let shape = Shape::of(sql, &p);
                let (sub, rows) = sql.reactor().watch(&conn.sess.lock().unwrap(), &p.text, &params).map_err(err_json)?;
                if rows.len() > sql.cfg.app.max_rows { return Err(json!({"error": format!("the result has more than {} rows (app.maxRows); add a LIMIT", sql.cfg.app.max_rows), "code": "ARGUMENTS"})); }
                let first = json!({"live": true, "initial": true, "columns": names(&shape.cols), "rows": shape.rows(sql, &conn.links, &rows)});
                Ok((first, lid, sub, shape))
            })();
            match out { Ok((first, lid, sub, shape)) => (vec![reply(first)], Some((lid, sub, shape))), Err(e) => (vec![reply(e)], None) }
        }
        "unlive" => { if let Some(lid) = id.as_u64() { conn.lives.lock().unwrap().remove(&lid); } (vec![reply(json!({"ok": true}))], None) }
        other => (vec![reply(json!({"error": format!("unknown op {other:?}: auth, sql, batch, call, live or unlive"), "code": "ARGUMENTS"}))], None),
    }
}
/// The socket's writer: replies in order, each live query's newest rows when they change, and a ping when idle.
async fn write_loop<W: AsyncWrite + Unpin + Send + 'static>(conn: Arc<Conn>, mut w: W, mut rx: mpsc::Receiver<Out>) {
    let mut ping = tokio::time::interval_at(tokio::time::Instant::now() + PING_EVERY, PING_EVERY);
    loop {
        let bytes = tokio::select! {
            biased;   // replies first: a live query's first result goes out before its changes
            m = rx.recv() => match m {
                Some(Out::Text(v)) => frame(0x1, v.to_string().as_bytes()),
                Some(Out::Pong(p)) => frame(0xA, &p),
                Some(Out::Close(p)) => { let _ = timeout(IO_TIMEOUT, w.write_all(&frame(0x8, &p))).await; break; }
                None => break,
            },
            _ = conn.changed.notified() => { let out: Vec<u8> = live_updates(&conn).iter().flat_map(|m| frame(0x1, m.to_string().as_bytes())).collect(); if out.is_empty() { continue; } out }
            _ = ping.tick() => frame(0x9, b""),
        };
        if !matches!(timeout(IO_TIMEOUT, w.write_all(&bytes)).await, Ok(Ok(()))) { break; }
    }
    conn.done.notify_one();   // the reader stops too
}
/// The newest rows of each live query that changed since the last call; one that fell behind (or whose session
/// ended) ends, and the client makes it again.
fn live_updates(conn: &Conn) -> Vec<J> {
    let mut out = vec![]; let mut ended = vec![];
    let Some(sql) = conn.sql.upgrade() else { return out };
    let mut lives = conn.lives.lock().unwrap();
    for (id, (sub, shape)) in lives.iter() {
        let mut newest = None;
        while let Some(ev) = sub.try_recv() { match ev { Event::Live { seq, rows, .. } => newest = Some((seq, rows)), Event::Overflow { .. } => { ended.push(*id); break; } Event::Change(_) => {} } }
        if let Some((seq, rows)) = newest { out.push(json!({"id": id, "live": true, "seq": seq, "columns": names(&shape.cols), "rows": shape.rows(&sql, &conn.links, &rows)})); }
    }
    for id in ended { lives.remove(&id); out.push(json!({"id": id, "ended": true, "reason": "the live query ended (signed out, the user changed, or it fell behind); make it again"})); }
    out
}
