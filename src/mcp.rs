//! MCP over HTTP (`app.mcp`): agents such as Claude (claude.ai and Claude Code) and ChatGPT connect to `/mcp` and act
//! as a user who signed in, with that user's grants and row policies. The app API is their OAuth 2.1 authorization
//! server, as the MCP specification asks:
//!   - discovery: protected-resource metadata (RFC 9728) and authorization-server metadata (RFC 8414);
//!   - an agent registers itself (RFC 7591): public clients only, PKCE with S256 only;
//!   - /oauth/authorize is a page: sign in (with a password, or a provider of `auth.oauth`), then allow or deny;
//!   - /oauth/token turns a code into an access token (an MCP-only session, `app.mcp.tokenTtl`) and a refresh token (one
//!     use; `app.mcp.grantTtl` unused). Both end with the user's sessions (a password change, a sign-out everywhere).
//! The tools: the app's functions the user may call (`functions.rs`, one tool each, their arguments as its schema), and
//! (unless `app.mcp.sql` is off) `describe` (what the user may use), `query` (one SELECT) and `execute` (INSERT, UPDATE
//! and DELETE, one or several in a transaction), with the statement rules of /api/sql.
use crate::app::{respond, run, run_batch, Links, Req};
use crate::sql::{Plan, Session, Sql, P_DELETE, P_INSERT, P_SELECT, P_UPDATE};
use serde_json::{json, Value as J};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const PENDING_TTL: Duration = Duration::from_secs(600);
const CODE_TTL: Duration = Duration::from_secs(60);
const PROTOCOLS: [&str; 3] = ["2025-11-25", "2025-06-18", "2025-03-26"];

/// Sign-ins in progress (an authorization request until it is allowed or denied) and codes not yet exchanged.
#[derive(Default)] pub struct McpState { pending: Mutex<HashMap<String, Pending>>, codes: Mutex<HashMap<String, Code>> }
/// `binding`: a secret only the browser that started the request holds (a cookie of its own), so a request's id alone
/// lets no one sign in to it or allow it: without it, someone who started a request could send its link to another
/// person and allow it themselves once that person signed in.
struct Pending { client: String, name: String, redirect: String, state: Option<String>, challenge: String, user: Option<(String, String)>, binding: String, ip: IpAddr, at: Instant }
/// Sign-ins in progress at most, in all and from one address.
const PENDING_MAX: usize = 10_000; const PENDING_PER_IP: usize = 20;
struct Code { client: String, redirect: String, challenge: String, user: String, at: Instant }

pub(crate) fn random_hex(n: usize) -> String { let mut b = vec![0u8; n]; getrandom::fill(&mut b).expect("random"); b.iter().map(|x| format!("{x:02x}")).collect() }
pub(crate) fn esc(s: &str) -> String { s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;") }
pub(crate) fn host_of(url: &str) -> String { url.split_once("://").map(|(_, r)| r.split(['/', '?', '#']).next().unwrap_or("").to_string()).unwrap_or_else(|| url.split(':').next().unwrap_or("").to_string()) }
fn base(sql: &Sql) -> String { sql.cfg.app.public_url.clone().unwrap_or_default() }
/// The cookie that binds a sign-in in progress to its browser (one per request, so two tabs don't collide). Lax, so it
/// comes back from a provider's sign-in.
fn binding_cookie(sql: &Sql, id: &str, value: &str, max_age: u64) -> String { format!("sqz_mcp_{id}={value}; Path=/oauth/authorize; HttpOnly; SameSite=Lax; Max-Age={max_age}{}", if base(sql).starts_with("https://") { "; Secure" } else { "" }) }
fn bound(req: &Req, id: &str, p: &Pending) -> bool { crate::app::cookie(req, &format!("sqz_mcp_{id}")).is_some_and(|c| crate::net::same_secret(c.as_bytes(), p.binding.as_bytes())) }
fn with_cookie(resp: Vec<u8>, cookie: &str) -> Vec<u8> { with_header(resp, &format!("Set-Cookie: {cookie}")) }
/// One more header, after the status line (responses here are built by `respond`, whose first line ends with \r\n).
fn with_header(mut resp: Vec<u8>, header: &str) -> Vec<u8> {
    if let Some(i) = resp.windows(2).position(|w| w == b"\r\n") { resp.splice(i..i, format!("\r\n{header}").into_bytes()); }
    resp
}
pub(crate) fn open() -> Vec<(String, String)> { vec![("Access-Control-Allow-Origin".into(), "*".into()), ("Access-Control-Expose-Headers".into(), "WWW-Authenticate, Mcp-Session-Id".into())] }
fn json_out(status: u16, v: &J) -> Vec<u8> { let mut h = open(); h.push(("Cache-Control".into(), "no-store".into())); respond(status, "application/json", v.to_string().as_bytes(), &h) }
fn oauth_err(status: u16, error: &str, desc: &str) -> Vec<u8> { json_out(status, &json!({"error": error, "error_description": desc})) }
/// A form body (application/x-www-form-urlencoded), or a JSON object's string fields.
fn form(req: &Req) -> HashMap<String, String> {
    if let Ok(J::Object(m)) = serde_json::from_slice::<J>(&req.body) { return m.into_iter().filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string()))).collect(); }
    String::from_utf8_lossy(&req.body).split('&').filter(|s| !s.is_empty()).map(|kv| { let (k, v) = kv.split_once('=').unwrap_or((kv, "")); (crate::util::url_decode(k), crate::util::url_decode(v)) }).collect()
}
/// The table people sign in to on the API's own pages (an agent's sign-in, `/_sqz/sign-in`): `app.mcp.users`, or the
/// only table with ENABLE AUTH.
pub(crate) fn users_table(sql: &Sql) -> Result<String, String> {
    if let Some(t) = sql.cfg.app.mcp.as_ref().and_then(|m| m.users.clone()) { return Ok(t); }
    let acl = sql.acl.read().unwrap(); let mut t: Vec<&String> = acl.auth.keys().collect(); t.sort();
    match t.as_slice() { [one] => Ok((*one).clone()), [] => Err("no table takes sign-ins yet (ALTER TABLE … ENABLE AUTH)".into()), _ => Err("several tables take sign-ins: set app.mcp.users to the one agents' users sign in to".into()) }
}
/// A redirect URI an agent may register: https, http on this machine, or an app's own scheme; never a fragment.
fn redirect_ok(u: &str) -> bool {
    if u.contains('#') || u.contains('\\') || u.len() > 500 || !u.bytes().all(|b| (0x21..0x7f).contains(&b)) { return false; }
    let Some((scheme, rest)) = u.split_once(':') else { return false };
    let scheme = scheme.to_ascii_lowercase();
    // no user@ in the authority: the page shows the host, and it must be where the browser goes
    if rest.strip_prefix("//").is_some_and(|r| r.split(['/', '?']).next().unwrap_or("").contains('@')) { return false; }
    match scheme.as_str() {
        "https" => rest.starts_with("//") && rest.len() > 2,
        "http" => { let h = host_of(u); let h = h.rsplit_once(':').filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit())).map(|(h, _)| h).unwrap_or(&h); matches!(h, "localhost" | "127.0.0.1" | "[::1]") }
        // a native app's own scheme: reverse DNS (RFC 8252 7.1, com.example.app:/), or one of the editors that use a short one
        "cursor" | "vscode" | "vscode-insiders" | "windsurf" | "zed" | "claude" => true,
        s => s.contains('.') && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b)),
    }
}
fn with_params(url: &str, params: &[(&str, &str)]) -> String {
    let q: Vec<String> = params.iter().map(|(k, v)| format!("{k}={}", crate::app::enc(v))).collect();
    format!("{url}{}{}", if url.contains('?') { '&' } else { '?' }, q.join("&"))
}
/// A redirect to an agent. It ends with '#': otherwise a browser carries the fragment of the URL it came from on to
/// the agent (Fetch spec), and a sign-in's fragment is a secret.
fn send_back(url: &str, params: &[(&str, &str)], cookies: &[String]) -> Vec<u8> { crate::app::redirect(&format!("{}#", with_params(url, params)), cookies) }
/// Does a redirect_uri match a registered one: exactly, or for http on this machine with any port (RFC 8252 7.3: a
/// native app gets a port when it starts).
fn redirect_matches(registered: &str, asked: &str) -> bool {
    if registered == asked { return true; }
    // strictly: the authority is the host, or the host, a colon and digits; nothing else (no user@, no stray colon)
    fn loopback(u: &str) -> Option<(&'static str, &str)> {
        if !redirect_ok(u) { return None; }
        let rest = u.strip_prefix("http://")?; let cut = rest.find(['/', '?']).unwrap_or(rest.len()); let (auth, path) = rest.split_at(cut);
        let host = ["localhost", "127.0.0.1", "[::1]"].into_iter().find(|h| auth.strip_prefix(h).is_some_and(|p| p.is_empty() || p.strip_prefix(':').is_some_and(|d| !d.is_empty() && d.len() <= 5 && d.bytes().all(|b| b.is_ascii_digit()))))?;
        Some((host, path))
    }
    matches!((loopback(registered), loopback(asked)), (Some(a), Some(b)) if a == b)
}
/// An address as the per-address limits count it: an IPv6 client by its /64 (a host has a whole one to choose from).
fn per_address(ip: IpAddr) -> IpAddr { match ip { IpAddr::V6(v) if v.to_ipv4_mapped().is_none() => { let s = v.segments(); IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0)) } ip => ip } }
/// A name as an agent gave it, made safe to show: no control or format characters (bidi overrides, zero-width).
fn clean_name(n: &str) -> String {
    n.chars().filter(|c| !c.is_control() && !matches!(*c as u32, 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2069 | 0xFEFF)).take(100).collect::<String>().trim().to_string()
}

/// Answer a request for the MCP endpoint, the OAuth server or their discovery documents; None for any other path,
/// or when `app.mcp` is off.
pub(crate) fn handle(sql: &Sql, st: &McpState, links: &Links, ip: IpAddr, allow: &dyn Fn() -> bool, req: &Req) -> Option<Vec<u8>> {
    let mcp = sql.cfg.app.mcp.as_ref()?;
    let path = req.path.as_str();
    if !(path == "/mcp" || path.starts_with("/oauth/") || path.starts_with("/.well-known/oauth-")) { return None; }
    if req.method == "OPTIONS" {
        let mut h = open(); h.extend([("Access-Control-Allow-Methods".into(), "GET, POST, DELETE, OPTIONS".into()), ("Access-Control-Allow-Headers".into(), "Authorization, Content-Type, Accept, Mcp-Session-Id, MCP-Protocol-Version, Last-Event-ID".into()), ("Access-Control-Max-Age".into(), "600".into())]);
        return Some(respond(204, "text/plain", b"", &h));
    }
    let b = base(sql);
    Some(match (req.method.as_str(), path) {
        ("GET", "/.well-known/oauth-protected-resource" | "/.well-known/oauth-protected-resource/mcp") => json_out(200, &json!({
            "resource": format!("{b}/mcp"), "authorization_servers": [b], "bearer_methods_supported": ["header"], "scopes_supported": ["sql"], "resource_name": host_of(&b) })),
        ("GET", "/.well-known/oauth-authorization-server" | "/.well-known/oauth-authorization-server/mcp") => json_out(200, &json!({
            "issuer": b, "authorization_endpoint": format!("{b}/oauth/authorize"), "token_endpoint": format!("{b}/oauth/token"),
            "registration_endpoint": format!("{b}/oauth/register"), "revocation_endpoint": format!("{b}/oauth/revoke"),
            "response_types_supported": ["code"], "grant_types_supported": ["authorization_code", "refresh_token"], "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"], "revocation_endpoint_auth_methods_supported": ["none"], "scopes_supported": ["sql"],
            "authorization_response_iss_parameter_supported": true })),
        ("POST", "/oauth/register") => if !allow() { let mut h = open(); h.push(("Retry-After".into(), "10".into())); respond(429, "application/json", br#"{"error":"temporarily_unavailable","error_description":"too many registrations from this address; try again shortly"}"#, &h) } else { register(sql, req) },
        ("GET", "/oauth/authorize") => authorize(sql, st, ip, req),
        ("POST", "/oauth/authorize") => decide(sql, st, allow, req),
        ("POST", "/oauth/token") => token(sql, st, mcp, req),
        ("POST", "/oauth/revoke") => { if let Some(t) = form(req).get("token") { sql.mcp_revoke(t); } json_out(200, &json!({})) }
        ("POST", "/mcp") => rpc(sql, links, mcp, req),
        // (GET with Accept: text/event-stream is the event stream, served by the app API itself: `events`)
        (_, "/mcp") => { let mut h = open(); h.push(("Allow".into(), "GET, POST, OPTIONS".into())); respond(405, "text/plain", b"POST a JSON-RPC message, or GET with Accept: text/event-stream for the event stream (no sessions to DELETE)", &h) }
        _ => respond(404, "text/plain", b"not found", &open()),
    })
}

// ---- the OAuth server

fn register(sql: &Sql, req: &Req) -> Vec<u8> {
    let Ok(v) = serde_json::from_slice::<J>(&req.body) else { return oauth_err(400, "invalid_client_metadata", "the body is a JSON object of client metadata") };
    let redirects: Vec<String> = v.get("redirect_uris").and_then(|r| r.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
    if redirects.is_empty() || redirects.len() > 10 { return oauth_err(400, "invalid_redirect_uri", "redirect_uris: one to ten URIs"); }
    if let Some(bad) = redirects.iter().find(|u| !redirect_ok(u)) { return oauth_err(400, "invalid_redirect_uri", &format!("{bad}: a redirect URI is https, http on this machine (localhost), or an app's own scheme, without a fragment")); }
    if redirects.iter().map(|r| r.len()).sum::<usize>() > 2000 { return oauth_err(400, "invalid_redirect_uri", "redirect_uris: 2,000 bytes at most in all"); }
    let name = clean_name(v.get("client_name").and_then(|n| n.as_str()).unwrap_or(""));
    let name = if name.is_empty() { host_of(&redirects[0]) } else { name };
    for (k, ok) in [("grant_types", ["authorization_code", "refresh_token"].as_slice()), ("response_types", ["code"].as_slice())] {
        if let Some(a) = v.get(k).and_then(|g| g.as_array()) { if let Some(x) = a.iter().filter_map(|x| x.as_str()).find(|x| !ok.contains(x)) { return oauth_err(400, "invalid_client_metadata", &format!("{k}: {x} is not supported")); } }
    }
    // a public client unless it asks for a secret (PKCE binds a code to its client either way)
    let method = match v.get("token_endpoint_auth_method").and_then(|m| m.as_str()) { None | Some("none") => "none", Some(m @ ("client_secret_post" | "client_secret_basic")) => m, Some(m) => return oauth_err(400, "invalid_client_metadata", &format!("token_endpoint_auth_method {m} is not supported (none, client_secret_post, client_secret_basic)")) };
    match sql.mcp_register(&name, &redirects, method) {
        Ok((id, secret)) => {
            let mut out = json!({ "client_id": id, "client_id_issued_at": crate::table::now_micros() / 1_000_000, "client_name": name, "redirect_uris": redirects,
                "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"], "token_endpoint_auth_method": method });
            if let Some(x) = secret { out["client_secret"] = json!(x); out["client_secret_expires_at"] = json!(0); }
            json_out(201, &out)
        }
        Err(e) => oauth_err(503, "temporarily_unavailable", &e),
    }
}

fn authorize(sql: &Sql, st: &McpState, ip: IpAddr, req: &Req) -> Vec<u8> {
    let q = &req.query;
    // back from a provider's sign-in: the request goes on where it was
    if let Some(id) = q.get("request") {
        let p = st.pending.lock().unwrap();
        return match p.get(id).filter(|p| p.at.elapsed() < PENDING_TTL) {
            Some(p) if bound(req, id, p) => sign_in_page(sql, id, p, None),
            Some(_) => error_page("This sign-in was started in another browser. Start again from the app you were connecting."),
            None => error_page("This sign-in has expired. Start again from the app you were connecting."),
        };
    }
    let client = q.get("client_id").cloned().unwrap_or_default();
    let Some((name, redirects)) = sql.mcp_client(&client) else { return error_page("The app asking to connect is not registered here. Connect it again from the app.") };
    let redirect = match q.get("redirect_uri") { Some(r) if redirects.iter().any(|x| redirect_matches(x, r)) => r.clone(), Some(_) => return error_page("The app asked to be sent back to an address it did not register. Nothing was sent to it."), None if redirects.len() == 1 => redirects[0].clone(), None => return error_page("The app did not say where to send you back.") };
    // from here on errors go back to the app (its address is known to be its own)
    let state = q.get("state").cloned();
    let back = |error: &str, desc: &str| { let mut p = vec![("error", error), ("error_description", desc)]; if let Some(s) = &state { p.push(("state", s)); } let b = base(sql); p.push(("iss", &b)); send_back(&redirect, &p, &[]) };
    if q.get("response_type").map(String::as_str) != Some("code") { return back("unsupported_response_type", "response_type must be code"); }
    let challenge = q.get("code_challenge").cloned().unwrap_or_default();
    if q.get("code_challenge_method").map(String::as_str) != Some("S256") || !crate::app::is_challenge(&challenge) { return back("invalid_request", "PKCE is required: code_challenge (S256) and code_challenge_method=S256"); }
    if let Some(r) = q.get("resource") { if !resource_ok(sql, r) { return back("invalid_target", "resource must be this server's MCP endpoint"); } }
    let (id, binding) = (random_hex(16), random_hex(32));
    let ip = per_address(ip);
    let p = Pending { client, name, redirect, state, challenge, user: None, binding, ip, at: Instant::now() };
    let shown = with_cookie(sign_in_page(sql, &id, &p, None), &binding_cookie(sql, &id, &p.binding, PENDING_TTL.as_secs()));
    let mut all = st.pending.lock().unwrap(); all.retain(|_, p| p.at.elapsed() < PENDING_TTL);
    if all.len() >= PENDING_MAX || all.values().filter(|x| x.ip == ip).count() >= PENDING_PER_IP { return page(503, "Can't connect", "<h1>Can't connect</h1><p>Too many sign-ins are in progress; try again in a few minutes.</p>", None); }
    all.insert(id, p);
    shown
}
fn resource_ok(sql: &Sql, r: &str) -> bool { let b = base(sql); let r = r.trim_end_matches('/'); r == format!("{b}/mcp") || r == b }

/// The sign-in page's form, the consent page's buttons: one POST to /oauth/authorize, `request` naming the sign-in.
fn decide(sql: &Sql, st: &McpState, allow: &dyn Fn() -> bool, req: &Req) -> Vec<u8> {
    let f = form(req);
    let id = f.get("request").cloned().unwrap_or_default();
    let expired = || error_page("This sign-in has expired. Start again from the app you were connecting.");
    match st.pending.lock().unwrap().get(&id) {
        Some(p) if p.at.elapsed() < PENDING_TTL && bound(req, &id, p) => {}
        Some(p) if p.at.elapsed() < PENDING_TTL => return error_page("This sign-in was started in another browser. Start again from the app you were connecting."),
        _ => return expired(),
    }
    let action = f.get("action").map(String::as_str).unwrap_or("");
    match action {
        "sign-in" | "continue" => {
            // checked without the lock (a password takes a while)
            let who: Result<(String, String), String> = (|| {
                if action == "sign-in" && !allow() { return Err("Too many sign-ins from here; wait a little and try again.".into()); }
                let table = users_table(sql)?;
                // a session made only to know who signed in: gone once read
                let token = if action == "sign-in" { sql.sign_in(&table, f.get("login").map(String::as_str).unwrap_or(""), f.get("password").map(String::as_str).unwrap_or(""))?.token } else { f.get("token").cloned().unwrap_or_default() };
                let mut s = Session::default();
                let who = sql.session_from_token(&mut s, &token).and_then(|()| sql.token_owner(&token));
                let _ = sql.sign_out(&token);
                let who = who?;
                if !who.split_once(':').is_some_and(|(t, _)| t.eq_ignore_ascii_case(&table)) { return Err(format!("sign in as a user of {table}")); }
                Ok((who, s.user.unwrap_or_default()))
            })();
            let mut all = st.pending.lock().unwrap();
            let Some(p) = all.get_mut(&id) else { return expired() };
            match who { Ok(u) => { p.user = Some(u); consent_page(sql, &id, p) } Err(e) => sign_in_page(sql, &id, p, Some(&e)) }
        }
        "allow" | "deny" => {
            let p = { let mut all = st.pending.lock().unwrap(); match all.get(&id) { Some(p) if bound(req, &id, p) => all.remove(&id), _ => None } };
            let Some(p) = p else { return expired() };
            let b = base(sql); let mut params: Vec<(&str, &str)> = vec![];
            let code = random_hex(24);
            match (action, &p.user) {
                ("allow", Some((owner, _))) => {
                    let mut codes = st.codes.lock().unwrap(); codes.retain(|_, c| c.at.elapsed() < CODE_TTL);
                    codes.insert(code.clone(), Code { client: p.client.clone(), redirect: p.redirect.clone(), challenge: p.challenge.clone(), user: owner.clone(), at: Instant::now() });
                    params.push(("code", &code));
                }
                ("allow", None) => return error_page("Sign in first."),
                _ => { params.push(("error", "access_denied")); params.push(("error_description", "the user did not allow it")); }
            }
            if let Some(s) = &p.state { params.push(("state", s)); } params.push(("iss", &b));
            send_back(&p.redirect, &params, &[binding_cookie(sql, &id, "", 0)])
        }
        _ => error_page("Nothing to do."),
    }
}

fn token(sql: &Sql, st: &McpState, mcp: &crate::config::McpPolicy, req: &Req) -> Vec<u8> {
    let f = form(req);
    // a client names itself (client_id), or authenticates with HTTP Basic (RFC 6749 2.3.1: both parts form-encoded)
    let basic = req.headers.get("authorization").and_then(|h| h.strip_prefix("Basic ")).and_then(|b| { use base64::Engine; base64::engine::general_purpose::STANDARD.decode(b.trim()).ok() }).and_then(|d| String::from_utf8(d).ok()).and_then(|s| s.split_once(':').map(|(id, x)| (crate::util::url_decode(id), crate::util::url_decode(x))));
    let client = basic.as_ref().map(|(id, _)| id.clone()).or_else(|| f.get("client_id").cloned()).unwrap_or_default();
    let secret = basic.as_ref().map(|(_, x)| x.clone()).or_else(|| f.get("client_secret").cloned());
    if !sql.mcp_client_ok(&client, secret.as_deref()) {
        let mut r = oauth_err(401, "invalid_client", "unknown client_id, or a wrong or missing client_secret; register again");
        if basic.is_some() { r = with_header(r, "WWW-Authenticate: Basic realm=\"oauth\""); }
        return r;
    }
    if let Some(r) = f.get("resource") { if !resource_ok(sql, r) { return oauth_err(400, "invalid_target", "resource must be this server's MCP endpoint"); } }
    let tokens = |r: Result<(String, String), String>| match r {
        Ok((access, refresh)) => json_out(200, &json!({"access_token": access, "token_type": "Bearer", "expires_in": mcp.token_ttl.as_secs(), "refresh_token": refresh, "scope": "sql"})),
        Err(e) => oauth_err(400, "invalid_grant", &e),
    };
    match f.get("grant_type").map(String::as_str) {
        Some("authorization_code") => {
            let held = st.codes.lock().unwrap().remove(f.get("code").map(String::as_str).unwrap_or(""));   // one attempt per code
            let Some(c) = held.filter(|c| c.at.elapsed() < CODE_TTL) else { return oauth_err(400, "invalid_grant", "the code is unknown, used already or expired"); };
            if c.client != client || f.get("redirect_uri").is_some_and(|r| *r != c.redirect) { return oauth_err(400, "invalid_grant", "the code was issued to another client or redirect_uri"); }
            let verifier = f.get("code_verifier").map(String::as_str).unwrap_or("");
            if !(43..=128).contains(&verifier.len()) || !crate::net::same_secret(crate::app::challenge_of(verifier).as_bytes(), c.challenge.as_bytes()) { return oauth_err(400, "invalid_grant", "code_verifier does not match the code_challenge"); }
            tokens(sql.mcp_issue(&client, &c.user, mcp.token_ttl, mcp.grant_ttl, None))
        }
        Some("refresh_token") => tokens(sql.mcp_refresh(&client, f.get("refresh_token").map(String::as_str).unwrap_or(""), mcp.token_ttl, mcp.grant_ttl).map(|(_, a, r)| (a, r))),
        _ => oauth_err(400, "unsupported_grant_type", "grant_type is authorization_code or refresh_token"),
    }
}

// ---- the pages (sign in, allow): no frames, a referrer only to this origin (so its forms post with their Origin), scripts only with this page's nonce

pub(crate) fn page(status: u16, title: &str, body: &str, script: Option<&str>) -> Vec<u8> {
    let nonce = random_hex(16);
    let html = format!(r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{t}</title><style>
:root {{ --bg:#f6f7f9; --card:#fff; --fg:#1b1f24; --dim:#5b6570; --line:#dfe3e8; --acc:#2563eb; --bad:#b42318 }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#0f1216; --card:#171b21; --fg:#e7eaee; --dim:#9aa4af; --line:#2a313a; --acc:#5b8def; --bad:#f97066 }} }}
* {{ box-sizing:border-box }} body {{ margin:0; min-height:100vh; display:grid; place-items:center; background:var(--bg); color:var(--fg); font:15px/1.5 system-ui, -apple-system, Segoe UI, sans-serif; padding:16px }}
main {{ width:100%; max-width:380px; background:var(--card); border:1px solid var(--line); border-radius:12px; padding:28px }}
h1 {{ font-size:20px; margin:0 0 6px }} p {{ margin:0 0 14px; color:var(--dim) }} b {{ color:var(--fg) }}
label {{ display:block; font-size:13px; color:var(--dim); margin:0 0 10px }} input {{ display:block; width:100%; margin-top:4px; padding:9px 10px; border:1px solid var(--line); border-radius:8px; background:transparent; color:var(--fg); font:inherit }}
button {{ width:100%; padding:10px; border-radius:8px; border:1px solid var(--acc); background:var(--acc); color:#fff; font:inherit; font-weight:600; cursor:pointer; margin-top:6px }}
button.alt {{ background:transparent; color:var(--fg); border-color:var(--line); font-weight:500 }} .or {{ text-align:center; font-size:12px; color:var(--dim); margin:14px 0 6px }}
.err {{ color:var(--bad); font-size:14px }} .small {{ font-size:12px; margin-top:16px }} form {{ margin:0 }}
</style></head><body><main>{body}</main>{s}</body></html>"#, t = esc(title), s = script.map(|js| format!("<script nonce=\"{nonce}\">{js}</script>")).unwrap_or_default());
    let csp = format!("default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-{nonce}'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'");
    respond(status, "text/html; charset=utf-8", html.as_bytes(), &[("Content-Security-Policy".into(), csp), ("X-Frame-Options".into(), "DENY".into()), ("Cache-Control".into(), "no-store".into()), ("Referrer-Policy".into(), "same-origin".into())])
}
fn error_page(msg: &str) -> Vec<u8> { page(400, "Can't connect", &format!("<h1>Can't connect</h1><p>{}</p>", esc(msg)), None) }
fn sign_in_page(sql: &Sql, id: &str, p: &Pending, err: Option<&str>) -> Vec<u8> {
    let table = match users_table(sql) { Ok(t) => t, Err(e) => return error_page(&e) };
    let login = sql.auth_table_of(&table).ok().map(|(t, a)| t.schema.columns[a.login].name.clone()).unwrap_or_else(|| "login".into());
    let host = host_of(&base(sql));
    let providers: Vec<&String> = sql.cfg.auth.oauth.keys().collect();
    let buttons: String = providers.iter().map(|n| format!(r#"<button class="alt" type="button" data-provider="{p}">Continue with {name}</button>"#, p = esc(n), name = esc(&title_case(n)))).collect();
    let body = format!(r#"<h1>Sign in to {host}</h1><p><b>{name}</b> wants to connect, as you.</p>{err}
<form method="post" action="/oauth/authorize"><input type="hidden" name="request" value="{id}"><input type="hidden" name="action" value="sign-in">
<label>{login_label}<input name="login" autocomplete="username" required autofocus></label><label>Password<input name="password" type="password" autocomplete="current-password" required></label><button>Sign in</button></form>
{or}{buttons}<form id="cont" method="post" action="/oauth/authorize" hidden><input type="hidden" name="request" value="{id}"><input type="hidden" name="action" value="continue"><input type="hidden" name="token"></form>
<p class="small">Next you choose whether to let it. It would act as you here: what you can see and change, nothing more.</p>"#,
        host = esc(&host), name = esc(&p.name), err = err.map(|e| format!(r#"<p class="err">{}</p>"#, esc(e))).unwrap_or_default(), id = esc(id), login_label = esc(&title_case(&login)), or = if providers.is_empty() { "" } else { r#"<div class="or">or</div>"# });
    let js = format!(r#"
const id = {id}, table = {table};
const b64 = (a) => btoa(String.fromCharCode(...new Uint8Array(a))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
for (const b of document.querySelectorAll('[data-provider]')) b.addEventListener('click', async () => {{
  const v = b64(crypto.getRandomValues(new Uint8Array(32))); sessionStorage.setItem('sqz_mcp_v', v);
  const c = b64(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(v)));
  location.href = '/api/auth/' + encodeURIComponent(table) + '/oauth/' + encodeURIComponent(b.dataset.provider) + '?return=' + encodeURIComponent(location.origin + '/oauth/authorize?request=' + id) + '&challenge=' + c;
}});
const h = new URLSearchParams(location.hash.slice(1));
if (h.get('sqz_error')) {{ const p = document.createElement('p'); p.className = 'err'; p.textContent = h.get('sqz_error'); document.querySelector('form').before(p); }}
if (h.get('sqz_code')) {{
  history.replaceState(null, '', location.pathname + location.search);
  fetch('/api/auth/exchange', {{ method: 'POST', headers: {{ 'content-type': 'application/json' }}, body: JSON.stringify({{ code: h.get('sqz_code'), verifier: sessionStorage.getItem('sqz_mcp_v') || '' }}) }})
    .then((r) => r.json()).then((j) => {{ if (j.token) {{ const f = document.getElementById('cont'); f.token.value = j.token; f.submit(); }} else {{ alert(j.error || 'sign-in failed'); }} }});
}}"#, id = J::String(id.into()), table = J::String(table));
    page(200, "Sign in", &body, Some(&js))
}
fn consent_page(sql: &Sql, id: &str, p: &Pending) -> Vec<u8> {
    let who = p.user.as_ref().map(|(_, l)| l.clone()).unwrap_or_default();
    let body = format!(r#"<h1>Allow {name}?</h1><p>Signed in as <b>{who}</b>.</p>
<p><b>{name}</b> could then read and change data in <b>{host}</b> as you: whatever you can see and change, nothing more. You go back to <b>{back}</b>.</p>
<form method="post" action="/oauth/authorize"><input type="hidden" name="request" value="{id}"><input type="hidden" name="action" value="allow"><button>Allow</button></form>
<form method="post" action="/oauth/authorize"><input type="hidden" name="request" value="{id}"><input type="hidden" name="action" value="deny"><button class="alt">Deny</button></form>
<p class="small">Changing your password, or signing out everywhere, disconnects it.</p>"#, name = esc(&p.name), who = esc(&who), host = esc(&host_of(&base(sql))), back = esc(&host_of(&p.redirect)), id = esc(id));
    page(200, "Allow access", &body, None)
}
pub(crate) fn title_case(s: &str) -> String { let mut c = s.chars(); match c.next() { Some(f) => f.to_uppercase().collect::<String>() + c.as_str(), None => String::new() } }

// ---- MCP: JSON-RPC over POST, one message per request

/// The agent a request to /mcp is from: its token's session, and the token. Refused (the answer to send): a page of
/// another origin (DNS rebinding: the transport spec), or no token, or one that no longer holds.
fn agent(sql: &Sql, req: &Req) -> Result<(Session, String), Vec<u8>> {
    let b = base(sql);
    let unauthorized = |e: Option<&str>| { let mut h = open(); h.push(("WWW-Authenticate".into(), format!("Bearer resource_metadata=\"{b}/.well-known/oauth-protected-resource/mcp\", scope=\"sql\"{}", e.map(|e| format!(", error=\"invalid_token\", error_description=\"{}\"", e.replace('"', "'"))).unwrap_or_default()))); respond(401, "application/json", br#"{"error":"sign in through this server's OAuth"}"#, &h) };
    // a page in a browser may call only from the API's own origin or app.origins (DNS rebinding: the transport spec)
    if let Some(o) = req.headers.get("origin") { let o = o.trim_end_matches('/'); if o != b && !sql.cfg.app.origins.iter().any(|x| x == "*" || x.eq_ignore_ascii_case(o)) { return Err(json_out(403, &json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32600, "message": "this origin may not call /mcp (app.origins)"}}))); } }
    let token = req.headers.get("authorization").and_then(|h| h.get(..7).filter(|p| p.eq_ignore_ascii_case("bearer ")).map(|_| h[7..].trim().to_string()));
    let Some(token) = token else { return Err(unauthorized(None)) };
    let mut sess = Session::default();
    if let Err(e) = sql.mcp_session(&mut sess, &token) { return Err(unauthorized(Some(&e))); }
    if let Some(v) = req.headers.get("mcp-protocol-version") { if !PROTOCOLS.contains(&v.as_str()) { return Err(json_out(400, &json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32600, "message": format!("unsupported MCP-Protocol-Version {v}")}}))); } }
    Ok((sess, token))
}

/// The event stream (`GET /mcp`, Accept: text/event-stream) for this request: the agent's session and token, and the
/// headers to answer with; or the refusal to send.
pub(crate) fn events(sql: &Sql, req: &Req) -> Result<(Session, String, Vec<(String, String)>), Vec<u8>> {
    if !req.headers.get("accept").is_some_and(|a| a.contains("text/event-stream")) { let mut h = open(); h.push(("Allow".into(), "GET, POST, OPTIONS".into())); return Err(respond(405, "text/plain", b"GET /mcp is the event stream: send Accept: text/event-stream", &h)); }
    let (sess, token) = agent(sql, req)?;
    Ok((sess, token, open()))
}
/// A fingerprint of the tools an agent's session sees: when it changes (a deploy, or other roles for its user), the
/// event stream tells the agent to list them again.
pub(crate) fn tools_digest(sql: &Sql, sess: &Session) -> u64 {
    use std::hash::{Hash, Hasher};
    let Some(mcp) = sql.cfg.app.mcp.as_ref() else { return 0 };
    let mut h = std::collections::hash_map::DefaultHasher::new(); tools(sql, sess, mcp).to_string().hash(&mut h); h.finish()
}

fn rpc(sql: &Sql, links: &Links, mcp: &crate::config::McpPolicy, req: &Req) -> Vec<u8> {
    let (mut sess, _) = match agent(sql, req) { Ok(x) => x, Err(refused) => return refused };
    let b = base(sql);
    let msg: J = match serde_json::from_slice(&req.body) { Ok(m) => m, Err(_) => return json_out(400, &json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "not JSON"}})) };
    if !msg.is_object() { return json_out(400, &json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32600, "message": "one JSON-RPC message per request"}})); }
    // a notification, or a response to us: accepted, nothing to answer
    let Some(id) = msg.get("id").cloned().filter(|_| msg.get("method").is_some()) else { return respond(202, "text/plain", b"", &open()) };
    let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let params = msg.get("params").cloned().unwrap_or(J::Null);
    let result: Result<J, (i64, String)> = match method {
        "initialize" => {
            let asked = params.get("protocolVersion").and_then(|v| v.as_str()).unwrap_or("");
            let has_fns = sql.function_defs().iter().any(|d| d.mcp && crate::functions::may_call(d, &sess, false));
            let instructions = match (has_fns, mcp.sql) {
                (true, true) => "A database you act on as the user who connected you. Its own tools carry out its operations with their rules: use them for what they cover. For anything else, describe lists the tables you may use, their columns and who you are (SESSION values that row policies compare with); then query (SELECT) and execute (INSERT, UPDATE, DELETE), with ? placeholders and values in params.",
                (true, false) => "A database you act on as the user who connected you, through its own tools: each carries out one operation, with its rules.",
                _ => "A SQL database you act on as the user who connected you. Start with describe: it lists the tables you may use, their columns, and who you are (SESSION values that row policies compare with). Then query (SELECT) and execute (INSERT, UPDATE, DELETE). Use ? placeholders and pass values in params.",
            };
            Ok(json!({ "protocolVersion": if PROTOCOLS.contains(&asked) { asked } else { PROTOCOLS[0] }, "capabilities": {"tools": {"listChanged": true}},
                "serverInfo": {"name": "sqzdb", "title": host_of(&b), "version": env!("CARGO_PKG_VERSION")}, "instructions": instructions }))
        }
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": tools(sql, &sess, mcp)})),
        "tools/call" => {
            let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            let out = if sql.function_defs().iter().any(|d| d.name == name && d.mcp) {
                // a function's result is any JSON; structured content is an object
                sql.call_function(&mut sess, name, &args, false).map(|v| if v.is_object() { v } else { json!({"result": v}) }).map_err(|e| e.message)
            } else if mcp.sql && matches!(name, "describe" | "query" | "execute") { call(sql, links, mcp, &mut sess, name, &args) }
            else { return json_out(200, &json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32602, "message": format!("no tool {name}")}})); };
            Ok(match out {
                Ok(v) => json!({"content": [{"type": "text", "text": v.to_string()}], "structuredContent": v, "isError": false}),
                Err(e) => json!({"content": [{"type": "text", "text": e}], "isError": true}),
            })
        }
        m => Err((-32601, format!("no method {m}"))),
    };
    json_out(200, &match result { Ok(r) => json!({"jsonrpc": "2.0", "id": id, "result": r}), Err((code, m)) => json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": m}}) })
}
/// The app's functions `sess` may call, those not marked `mcp: false`, then (with `app.mcp.sql`) the SQL tools.
fn tools(sql: &Sql, sess: &Session, mcp: &crate::config::McpPolicy) -> J {
    let mut out: Vec<J> = sql.function_defs().iter().filter(|d| d.mcp && crate::functions::may_call(d, sess, false)).map(|d| json!({
        "name": d.name, "title": title_case(&d.name), "description": d.description.clone().unwrap_or_else(|| format!("{} (from {})", d.name, d.file)),
        "inputSchema": crate::functions::input_schema(d), "annotations": {"readOnlyHint": d.read_only} })).collect();
    if mcp.sql { if let J::Array(t) = sql_tools() { out.extend(t); } }
    J::Array(out)
}
fn sql_tools() -> J {
    let params = json!({"type": "array", "description": "values for the ? placeholders, in order", "items": {}});
    json!([
        {"name": "describe", "title": "Describe the database",
         "description": "The tables you may use: columns (type, key, unique, references, default), what you may do with each (select, insert, update, delete), the row policies that limit which rows you see or change, and who you are (the SESSION values those policies compare with). Call it first.",
         "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false}, "annotations": {"readOnlyHint": true, "idempotentHint": true}},
        {"name": "query", "title": "Run a SELECT",
         "description": "Run one SELECT as you: your grants and row policies apply. Use ? placeholders and pass values in params. Returns {columns, rows}. Joins, GROUP BY, ORDER BY, LIMIT, subqueries, JSON -> and ->>, LIKE (case-sensitive) and ILIKE work as in Postgres or SQLite. Results are limited in size: add a LIMIT.",
         "inputSchema": {"type": "object", "properties": {"sql": {"type": "string", "description": "one SELECT"}, "params": params}, "required": ["sql"], "additionalProperties": false},
         "annotations": {"readOnlyHint": true}},
        {"name": "execute", "title": "Change data",
         "description": "Run INSERT, UPDATE or DELETE as you: one statement (sql, params), or several in one transaction (statements: [{sql, params}], all or none). RETURNING is supported. No CREATE, ALTER or GRANT: the schema is the application's. Returns each statement's result.",
         "inputSchema": {"type": "object", "properties": {"sql": {"type": "string"}, "params": params, "statements": {"type": "array", "items": {"type": "object", "properties": {"sql": {"type": "string"}, "params": params}, "required": ["sql"]}}}, "additionalProperties": false},
         "annotations": {"readOnlyHint": false, "destructiveHint": true}}
    ])
}
/// A result for an agent: each row an object keyed by column name (the app API sends arrays, for size).
fn objects(mut out: J) -> J {
    if let Some(list) = out.get_mut("results").and_then(|r| r.as_array_mut()) { for r in list.iter_mut() { *r = objects(r.take()); } return out; }
    let cols: Vec<String> = out.get("columns").and_then(|c| c.as_array()).map(|a| a.iter().map(|c| c.as_str().unwrap_or("").to_string()).collect()).unwrap_or_default();
    if let Some(rows) = out.get_mut("rows").and_then(|r| r.as_array_mut()) {
        for row in rows.iter_mut() { if let J::Array(vals) = row.take() { *row = J::Object(cols.iter().cloned().zip(vals).collect()); } }
    }
    out
}
fn call(sql: &Sql, links: &Links, mcp: &crate::config::McpPolicy, sess: &mut Session, name: &str, args: &J) -> Result<J, String> {
    let fail = |e: J| e.get("error").and_then(|m| m.as_str()).map(String::from).unwrap_or_else(|| e.to_string());
    let kind = |text: &str| sql.prepare(text).map(|p| match p.plan { Plan::Select(_) | Plan::Const { .. } => 1, Plan::Insert { .. } | Plan::Update { .. } | Plan::Delete { .. } => 2, _ => 0 });
    let rows_ok = |out: &J| match out.get("rows").and_then(|r| r.as_array()) { Some(r) if r.len() > mcp.max_rows => Err(format!("the result has {} rows, more than the {} an agent gets (app.mcp.maxRows): add a LIMIT or narrow the WHERE", r.len(), mcp.max_rows)), _ => Ok(()) };
    match name {
        "describe" => Ok(describe(sql, sess)),
        "query" => {
            let text = args.get("sql").and_then(|s| s.as_str()).ok_or("query needs sql")?;
            if kind(text)? != 1 { return Err("query runs one SELECT; change data with execute".into()); }
            let out = run(sql, links, sess, args).map_err(fail)?; rows_ok(&out)?; Ok(objects(out))
        }
        "execute" => {
            let one = |st: &J| -> Result<(), String> { let text = st.get("sql").and_then(|s| s.as_str()).ok_or("each statement needs sql")?; if kind(text)? != 2 { return Err(format!("execute runs INSERT, UPDATE and DELETE; read with query ({text})")); } Ok(()) };
            if let Some(list) = args.get("statements").and_then(|s| s.as_array()) {
                for st in list { one(st)?; }
                let out = run_batch(sql, links, sess, args).map_err(fail)?;
                for r in out.get("results").and_then(|r| r.as_array()).into_iter().flatten() { rows_ok(r)?; }
                Ok(objects(out))
            }
            else { one(args)?; let out = run(sql, links, sess, args).map_err(fail)?; rows_ok(&out)?; Ok(objects(out)) }
        }
        n => Err(format!("no tool {n}")),
    }
}
/// What `sess` may use: its tables with columns and privileges, the policies on them, and its SESSION values.
fn describe(sql: &Sql, sess: &Session) -> J {
    let acl = sql.acl.read().unwrap();
    let may = |table: &str| -> u8 { if sess.user.is_none() { return P_SELECT | P_INSERT | P_UPDATE | P_DELETE; } sess.roles.iter().fold(0, |m, r| m | acl.grants.get(&(r.clone(), table.to_lowercase())).copied().unwrap_or(0)) };
    let mut tables = vec![];
    for name in sql.db.table_names() {
        let Some(t) = sql.db.table(&name) else { continue };
        let m = may(&name); if m == 0 { continue; }
        let s = &t.schema;
        let cols: Vec<J> = s.columns.iter().enumerate().map(|(i, c)| {
            let mut o = json!({"name": c.name, "type": c.type_name(), "nullable": c.nullable});
            if i == s.pk { o["primaryKey"] = json!(true); if s.auto { o["automatic"] = json!(true); } }
            if s.unique == Some(i) { o["unique"] = json!(true); }
            if let Some(f) = s.fks.iter().find(|f| f.col == i) { o["references"] = json!(f.parent); }
            if c.default != crate::table::Value::Null { o["default"] = crate::util::value_json(&c.default, Some(&c.ty)); } else if let Some(g) = &c.generated { o["default"] = json!(g.sql()); }
            if c.embed.is_some() { o["generated"] = json!(true); }
            o
        }).collect();
        let ops: Vec<&str> = [(P_SELECT, "select"), (P_INSERT, "insert"), (P_UPDATE, "update"), (P_DELETE, "delete")].iter().filter(|(b, _)| m & b != 0).map(|(_, n)| *n).collect();
        let policies: Vec<String> = acl.policies.iter().filter(|p| p.table.eq_ignore_ascii_case(&name) && sess.roles.contains(&p.role)).map(|p| {
            let preds: Vec<String> = p.preds.iter().map(|(c, op, rhs)| format!("{c} {} {}", cmp_text(*op), match rhs { crate::sql::PolicyRhs::Lit(v) => crate::util::value_json(v, None).to_string(), crate::sql::PolicyRhs::Attr(a) => format!("SESSION.{a}") })).collect();
            format!("{}: {}", p.name, preds.join(" AND "))
        }).collect();
        tables.push(json!({"name": s.name, "may": ops, "columns": cols, "policies": policies}));
    }
    let me: serde_json::Map<String, J> = sess.attrs.iter().map(|(k, v)| (k.clone(), crate::util::value_json(v, None))).collect();
    json!({"you": {"user": sess.user, "roles": sess.roles, "session": me}, "tables": tables})
}
fn cmp_text(c: crate::sql::Cmp) -> &'static str { use crate::sql::Cmp::*; match c { Eq => "=", Ne => "<>", Lt => "<", Le => "<=", Gt => ">", Ge => ">=", IsNull => "IS NULL", IsNotNull => "IS NOT NULL", In => "IN", NotIn => "NOT IN" } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn redirect_uris_an_agent_may_register() {
        for ok in ["https://claude.ai/api/mcp/auth_callback", "https://chatgpt.com/connector_platform_oauth_redirect", "http://localhost:33418/callback", "http://127.0.0.1:6274/oauth/callback", "http://[::1]:8080/cb", "cursor://anysphere.cursor-retrieval/oauth/user-x/callback", "vscode://vscode.github-authentication/did-authenticate", "com.example.app:/oauth"] { assert!(redirect_ok(ok), "{ok}"); }
        for bad in ["http://example.com/cb", "http://localhost.evil.com/cb", "javascript:alert(1)", "data:text/html,x", "https://x.test/cb#frag", "https:/nohost", "file:///etc/passwd", "https://x.test/a b",
                    "https://claude.ai@evil.example/cb", "https://evil.example\\claude.ai/cb", "ms-msdt:/id", "search-ms:query=x", "intent://x", "jar:file:x"] { assert!(!redirect_ok(bad), "{bad}"); }
    }
    #[test] fn an_agents_access_ends_with_the_users_sessions() {
        use crate::table::Value;
        let d = std::env::temp_dir().join(format!("sqzdb-mcp-{}", std::process::id())); let _ = std::fs::remove_dir_all(&d);
        let s = Sql::open_with(&d, crate::config::Config::default()).unwrap();
        for q in ["CREATE TABLE users (id SERIAL PRIMARY KEY, email TEXT UNIQUE, role TEXT DEFAULT 'member')", "CREATE ROLE member", "ALTER TABLE users ENABLE AUTH (ROLE FROM role)"] { s.exec_s(&mut Session::default(), q, &[]).unwrap(); }
        let si = s.sign_up("users", &[("email".into(), Value::Text("ann@x".into()))], "the password 1").unwrap();
        let owner = s.token_owner(&si.token).unwrap(); assert_eq!(owner, "users:1");
        let (hour, month) = (Duration::from_secs(3600), Duration::from_secs(30 * 86400));
        let ok = |t: &str| s.mcp_session(&mut Session::default(), t).is_ok();
        let (a1, r1) = s.mcp_issue("mcpc_a", &owner, hour, month, None).unwrap();
        assert!(ok(&a1));
        assert!(s.session_from_token(&mut Session::default(), &a1).is_err(), "not an app session");
        assert!(!ok(&si.token), "and an app session is not an MCP token");
        // a refresh: a new pair, and the access token the old one came with ends
        let (who, a2, r2) = s.mcp_refresh("mcpc_a", &r1, hour, month).unwrap(); assert_eq!(who, owner);
        assert!(!ok(&a1) && ok(&a2));
        // r1 again: someone has a copy, so the whole sign-in ends (r2 and a2 with it)
        assert!(s.mcp_refresh("mcpc_a", &r1, hour, month).unwrap_err().contains("used before"));
        assert!(!ok(&a2)); assert!(s.mcp_refresh("mcpc_a", &r2, hour, month).is_err());
        let (_, other) = s.mcp_issue("mcpc_a", &owner, hour, month, None).unwrap(); assert!(s.mcp_refresh("mcpc_b", &other, hour, month).is_err(), "another client's");
        // revoking a refresh token ends its sign-in
        let (a3, r3) = s.mcp_issue("mcpc_a", &owner, hour, month, None).unwrap(); s.mcp_revoke(&r3); assert!(!ok(&a3)); assert!(s.mcp_refresh("mcpc_a", &r3, hour, month).is_err());
        // a password change ends both kinds
        let (a4, r4) = s.mcp_issue("mcpc_a", &owner, hour, month, None).unwrap();
        s.set_password("users", &Value::Int(1), "a new password 1").unwrap();
        assert!(!ok(&a4), "the access token");
        assert!(s.mcp_refresh("mcpc_a", &r4, hour, month).unwrap_err().contains("password change"), "the refresh token");
        drop(s); std::fs::remove_dir_all(&d).ok();
    }
    #[test] fn redirects_match_exactly_but_any_port_on_this_machine() {
        assert!(redirect_matches("https://claude.ai/api/mcp/auth_callback", "https://claude.ai/api/mcp/auth_callback"));
        assert!(!redirect_matches("https://claude.ai/api/mcp/auth_callback", "https://claude.ai/api/mcp/auth_callback/x"));
        assert!(redirect_matches("http://127.0.0.1/callback", "http://127.0.0.1:53682/callback"));
        assert!(redirect_matches("http://localhost:3000/cb", "http://localhost:4000/cb"));
        assert!(!redirect_matches("http://127.0.0.1/callback", "http://127.0.0.1:53682/other"));
        assert!(!redirect_matches("http://127.0.0.1/cb", "http://localhost/cb"));
        assert!(!redirect_matches("https://a.test/cb", "https://a.test:8443/cb"), "any port only on this machine");
        for sneaky in ["http://localhost:@evil.example/callback", "http://localhost:80@evil.example/callback", "http://localhost:x@evil.example/callback", "http://127.0.0.1:/callback", "http://localhost.evil.example/callback", "http://127.0.0.1:99999999/callback"] {
            assert!(!redirect_matches("http://localhost/callback", sneaky) && !redirect_matches("http://127.0.0.1/callback", sneaky), "{sneaky}");
        }
        assert_eq!(clean_name("Cla\u{202E}ude\u{200B} \u{7}"), "Claude");
    }
    #[test] fn pages_escape_what_an_agent_names_itself() {
        assert_eq!(esc(r#"<script>alert("x")</script>"#), "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;");
        assert_eq!(with_params("https://a.test/cb", &[("code", "x y"), ("state", "s&t")]), "https://a.test/cb?code=x%20y&state=s%26t");
        assert_eq!(with_params("https://a.test/cb?k=1", &[("code", "c")]), "https://a.test/cb?k=1&code=c");
    }
}
