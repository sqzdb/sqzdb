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
//! - `GET /api/socket`: a WebSocket carrying JSON messages: `auth`, `sql`, `batch`, `live` and `unlive`. A live
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
//! Connections are tasks on one small runtime, not threads, so a connected user who is idle costs little more than
//! their socket's buffers. Work that can block a thread (password hashing, a provider's token exchange, static
//! files, commits that wait for their fsync or the bucket) runs on the runtime's blocking pool.
use crate::config::Durability;
use crate::live::{Event, Subscription};
use crate::sql::{Plan, Prepared, Session, Sql};
use crate::table::{ColType, Value};
use crate::util::{err_json, j_to_value, names, row_json, url_decode, value_json, Cols};
use serde_json::{json, Value as J};
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, Notify};
use tokio::time::timeout;

/// Idle keep-alive connections and stalled writers are dropped after this long.
const IO_TIMEOUT: Duration = Duration::from_secs(60);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const SOCKET_TIMEOUT: Duration = Duration::from_secs(120);
const PING_EVERY: Duration = Duration::from_secs(30);
const MAX_BODY: usize = 1 << 20;
const MAX_LINE: u64 = 16 << 10;
const MAX_HEADERS: usize = 64;
const MAX_SQL: usize = 64 << 10;
const MAX_PARAMS: usize = 1000;
const MAX_BATCH: usize = 100;
const MAX_MESSAGE: usize = 1 << 20;
const MAX_LIVES: usize = 64;
const CODE_TTL: Duration = Duration::from_secs(60);
const CLIENT_JS: &str = include_str!("../clients/js/index.js");
/// Messages a socket may have waiting to be written before its reader stops reading (the client is not keeping up).
const OUT_QUEUE: usize = 64;

/// Shared by every connection of one listener. `hashing`: sign-ups and sign-ins running at once (a password hash
/// takes 19 MB and a core); the rest wait here as tasks rather than as blocked threads.
struct AppState { limits: Mutex<HashMap<IpAddr, (f64, Instant)>>, codes: Mutex<HashMap<String, (J, String, Instant)>>, hashing: tokio::sync::Semaphore }
impl AppState {
    /// A token bucket per client address for sign-up, sign-in and code exchange: 10 at once, then one every 3 s.
    fn allow(&self, ip: IpAddr) -> bool {
        let mut m = self.limits.lock().unwrap();
        if m.len() > 100_000 { m.retain(|_, (_, at)| at.elapsed() < Duration::from_secs(60)); }
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
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(workers).max_blocking_threads(64).thread_name("sqweezdb-app").enable_all().build().map_err(fail)?;
    let listener = { let _in = rt.enter(); tokio::net::TcpListener::from_std(std_listener).map_err(fail)? };
    let tls = match &sql.cfg.app.tls { Some(p) => Some(Arc::new(crate::tls::Tls::start(p, &sql.db.dir, rt.handle())?)), None => None };
    if let Some(p) = sql.cfg.app.tls.as_ref().filter(|p| p.redirect.is_some()) {
        let to = p.redirect.clone().unwrap_or_default();
        let hosts = if !p.domains.is_empty() { p.domains.clone() } else { sql.cfg.app.public_url.as_deref().and_then(|u| u.split('/').nth(2)).map(|h| vec![h.split(':').next().unwrap_or(h).to_string()]).ok_or("app.tls.redirect: needs app.tls.domains or app.publicUrl, the host to send browsers to")? };
        let l = std::net::TcpListener::bind(&to).and_then(|l| l.set_nonblocking(true).map(|()| l)).map_err(|e| format!("app.tls.redirect {to}: {e}"))?;
        let l = { let _in = rt.enter(); tokio::net::TcpListener::from_std(l).map_err(|e| format!("app.tls.redirect {to}: {e}"))? };
        rt.spawn(crate::tls::redirect(l, hosts, Some(local.port()).filter(|p| *p != 443)));
    }
    let weak = Arc::downgrade(&sql); drop(sql);
    let st = Arc::new(AppState { limits: Default::default(), codes: Default::default(), hashing: tokio::sync::Semaphore::new(workers) });
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
                            let Some(tls) = tls else { return serve(w, stream, peer.ip(), st).await };
                            let Ok(Ok(s)) = timeout(HANDSHAKE_TIMEOUT, tls.acceptor.accept(stream)).await else { return };
                            if s.get_ref().1.alpn_protocol() == Some(crate::tls::ACME_TLS_ALPN) { return; }   // a CA checking a domain: the handshake was the answer
                            serve(w, s, peer.ip(), st).await
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
struct Req { method: String, path: String, query: HashMap<String, String>, headers: HashMap<String, String>, body: Vec<u8> }
/// One CRLF/LF-terminated line of at most MAX_LINE bytes; `None` at a clean end of stream.
async fn read_line<R: AsyncRead + Unpin>(r: &mut BufReader<R>) -> io::Result<Option<String>> {
    let mut buf = Vec::new(); let n = (&mut *r).take(MAX_LINE).read_until(b'\n', &mut buf).await?;
    if n == 0 { return Ok(None); }
    if buf.last() != Some(&b'\n') { return Err(io::Error::other("request line or header too long")); }
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}
async fn read_req<R: AsyncRead + Unpin>(r: &mut BufReader<R>) -> io::Result<Option<Req>> {
    let Some(line) = read_line(r).await? else { return Ok(None) };
    let mut parts = line.split_whitespace(); let method = parts.next().unwrap_or("").to_string(); let target = parts.next().unwrap_or("/").to_string();
    let mut headers = HashMap::new();
    for n in 0.. {
        let Some(h) = read_line(r).await? else { return Ok(None) }; let h = h.trim_end(); if h.is_empty() { break; }
        if n >= MAX_HEADERS { return Err(io::Error::other("too many header lines")); }   // lines, not names: a repeated name must count too
        if let Some((k, v)) = h.split_once(':') { headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string()); }
    }
    let len: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    if len > MAX_BODY { return Err(io::Error::other("body too large")); }
    let mut body = vec![0u8; len]; if len > 0 { r.read_exact(&mut body).await?; }
    let (path, q) = match target.split_once('?') { Some((p, q)) => (p.to_string(), q.to_string()), None => (target.clone(), String::new()) };
    let query = q.split('&').filter(|s| !s.is_empty()).map(|kv| { let (k, v) = kv.split_once('=').unwrap_or((kv, "")); (url_decode(k), url_decode(v)) }).collect();
    Ok(Some(Req { method, path, query, headers, body }))
}
fn reason(status: u16) -> &'static str { match status { 101 => "Switching Protocols", 200 => "OK", 204 => "No Content", 302 => "Found", 400 => "Bad Request", 401 => "Unauthorized", 403 => "Forbidden", 404 => "Not Found", 405 => "Method Not Allowed", 413 => "Payload Too Large", 429 => "Too Many Requests", _ => "Error" } }
/// A whole response, written in one piece: a response in fragments waits on the peer's delayed ACK for each one.
fn respond(status: u16, ctype: &str, body: &[u8], extra: &[(String, String)]) -> Vec<u8> {
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
fn bearer(req: &Req) -> Option<String> { req.headers.get("authorization").and_then(|h| h.strip_prefix("Bearer ")).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) }
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
fn run(sql: &Sql, sess: &mut Session, v: &J) -> Result<J, J> {
    let p = client_statement(sql, v.get("sql").and_then(|s| s.as_str()).unwrap_or(""))?;
    let params = params_of(v)?;
    let rows = sql.execute_s(sess, &p, &params).map_err(err_json)?;
    let max = sql.cfg.app.max_rows;
    if rows.len() > max { return Err(json!({"error": format!("the result has more than {max} rows (app.maxRows); add a LIMIT"), "code": "ARGUMENTS"})); }
    let cols = sql.columns(&p);
    let mut out = json!({"columns": names(&cols), "rows": rows.iter().map(|r| row_json(&cols, r)).collect::<Vec<_>>()});
    if matches!(p.plan, Plan::Insert { .. }) { out["lastInsertId"] = sess.last_insert_key.as_ref().map(|k| value_json(k, None)).unwrap_or(J::Null); }
    Ok(out)
}
/// Several statements in one transaction: all or none.
fn run_batch(sql: &Sql, sess: &mut Session, v: &J) -> Result<J, J> {
    let list = v.get("statements").and_then(|s| s.as_array()).ok_or_else(|| json!({"error": "statements is an array of {sql, params}", "code": "ARGUMENTS"}))?;
    if list.len() > MAX_BATCH { return Err(json!({"error": format!("at most {MAX_BATCH} statements in a batch"), "code": "ARGUMENTS"})); }
    sql.exec_s(sess, "BEGIN", &[]).map_err(err_json)?;
    let mut results = vec![];
    for (i, st) in list.iter().enumerate() {
        match run(sql, sess, st) { Ok(r) => results.push(r), Err(mut e) => { let _ = sql.exec_s(sess, "ROLLBACK", &[]); e["statement"] = json!(i); return Err(e); } }
    }
    sql.exec_s(sess, "COMMIT", &[]).map_err(err_json)?;
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
fn body_json(req: &Req) -> Result<J, J> { serde_json::from_slice(&req.body).map_err(|e| json!({"error": format!("bad JSON: {e}"), "code": "ARGUMENTS"})) }
fn cookie(req: &Req, name: &str) -> Option<String> { req.headers.get("cookie")?.split(';').filter_map(|c| c.trim().split_once('=')).find(|(k, _)| *k == name).map(|(_, v)| url_decode(v)) }
/// The PKCE-style challenge for a verifier: base64url (no padding) of its SHA-256.
fn challenge_of(verifier: &str) -> String { crate::util::base64(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref()).replace('+', "-").replace('/', "_").trim_end_matches('=').to_string() }
fn is_challenge(c: &str) -> bool { c.len() == 43 && c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') }
fn enc(s: &str) -> String { s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect() }
/// A URL to send the browser back to after a provider sign-in: on an allowed origin, so the API is no open redirect,
/// and printable ASCII only (it goes into a Location header).
fn return_ok(sql: &Sql, url: &str) -> bool {
    if !url.bytes().all(|b| (0x21..0x7f).contains(&b)) { return false; }
    let origin = match url.splitn(4, '/').collect::<Vec<_>>().as_slice() { [scheme, "", host, ..] if *scheme == "https:" || *scheme == "http:" => format!("{scheme}//{host}"), _ => return false };
    let cfg = &sql.cfg.app;
    cfg.public_url.as_deref() == Some(origin.as_str()) || cfg.origins.iter().any(|x| x.eq_ignore_ascii_case(&origin))
}
fn redirect(to: &str, cookies: &[String]) -> Vec<u8> {
    let mut h: Vec<(String, String)> = vec![("Location".into(), to.into()), ("Cache-Control".into(), "no-store".into()), ("Referrer-Policy".into(), "no-referrer".into())];
    for c in cookies { h.push(("Set-Cookie".into(), c.clone())); }
    respond(302, "text/plain", b"", &h)
}
/// Requests whose handling can block a thread for a while: sign-in (password hashing; a provider's token exchange
/// runs a runtime of its own), static files, and SQL when commits wait for their fsync or the bucket.
fn blocks(sql: &Sql, req: &Req) -> bool {
    !req.path.starts_with("/api/") || req.path.starts_with("/api/auth/") || (sql.cfg.durable != Durability::Visible && req.method == "POST")
}

/// One connection, plain or TLS: HTTP requests until it closes, or a WebSocket.
async fn serve<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(weak: Weak<Sql>, stream: S, ip: IpAddr, st: Arc<AppState>) {
    let (rd, mut w) = tokio::io::split(stream); let mut r = BufReader::with_capacity(4 << 10, rd);
    loop {
        let Ok(Ok(Some(req))) = timeout(IO_TIMEOUT, read_req(&mut r)).await else { return };
        let Some(sql) = weak.upgrade() else { return };
        let close = req.headers.get("connection").map(|c| c.eq_ignore_ascii_case("close")).unwrap_or(false);
        if req.method == "GET" && req.path.trim_matches('/') == "api/socket" { drop(sql); return websocket(weak, r, w, req).await; }
        let out = if blocks(&sql, &req) {
            let hashes = req.method == "POST" && req.path.starts_with("/api/auth/") && (req.path.ends_with("/sign-up") || req.path.ends_with("/sign-in"));
            let _turn = if hashes { st.hashing.acquire().await.ok() } else { None };
            let st = st.clone();
            let Ok(out) = tokio::task::spawn_blocking(move || handle(&sql, &st, ip, &req)).await else { return };
            out
        } else { let out = handle(&sql, &st, ip, &req); drop(sql); out };
        if !matches!(timeout(IO_TIMEOUT, w.write_all(&out)).await, Ok(Ok(()))) || close { return; }
    }
}

/// One HTTP request (not the socket): the whole response.
fn handle(sql: &Sql, st: &AppState, ip: IpAddr, req: &Req) -> Vec<u8> {
    let api = req.path.starts_with("/api/");
    let origin = match allowed_origin(sql, req) { Ok(o) => o, Err(()) if api => return json_resp(403, &json!({"error": "permission denied: this origin may not call the API (app.origins)", "code": "DENIED"}), &[]), Err(()) => None };
    let h = cors(&origin);
    let reply = |r: Result<J, J>| match r { Ok(v) => json_resp(200, &v, &h), Err(e) => json_resp(status_of(&e), &e, &h) };
    let path: Vec<&str> = req.path.trim_matches('/').split('/').collect();
    match (req.method.as_str(), path.as_slice()) {
        ("OPTIONS", ["api", ..]) => { let mut h = h.clone(); h.extend([("Access-Control-Allow-Methods".into(), "GET, POST, OPTIONS".into()), ("Access-Control-Allow-Headers".into(), "Authorization, Content-Type".into()), ("Access-Control-Max-Age".into(), "600".into())]); respond(204, "text/plain", b"", &h) }
        ("POST", ["api", op @ ("sql" | "batch")]) => reply(body_json(req).and_then(|v| { let mut s = session_for(sql, bearer(req).as_deref())?; if *op == "sql" { run(sql, &mut s, &v) } else { run_batch(sql, &mut s, &v) } })),
        ("GET", ["api", "me"]) => reply(session_for(sql, bearer(req).as_deref()).map(|s| json!({"user": J::Object(s.attrs.iter().map(|(k, v)| (k.clone(), value_json(v, None))).collect()), "roles": s.roles}))),
        ("GET", ["api", "auth", table, "methods"]) => reply(sql.auth_table_of(table).map_err(err_json).map(|_| {
            let providers: Vec<&String> = if sql.cfg.app.public_url.is_some() { sql.cfg.auth.oauth.keys().collect() } else { vec![] };
            json!({"signUp": sql.cfg.app.sign_up.contains_key(&table.to_ascii_lowercase()), "providers": providers})
        })),
        ("POST", ["api", "auth", "sign-out"]) => { if let Some(t) = bearer(req) { let _ = sql.sign_out(&t); } json_resp(200, &json!({}), &h) }
        ("POST", ["api", "auth", "exchange"]) => reply(if !st.allow(ip) { Err(limited()) } else { body_json(req).and_then(|v| {
            let code = v.get("code").and_then(|c| c.as_str()).unwrap_or(""); let verifier = v.get("verifier").and_then(|c| c.as_str()).unwrap_or("");
            let held = st.codes.lock().unwrap().remove(code);   // one attempt per code, whatever the verifier
            match held {
                Some((signed, challenge, at)) if at.elapsed() < CODE_TTL && verifier.len() >= 43 && crate::net::same_secret(challenge_of(verifier).as_bytes(), challenge.as_bytes()) => Ok(signed),
                _ => Err(json!({"error": "sign-in failed: an unknown or expired sign-in code, or one this page did not start; sign in again", "code": "AUTH"})),
            }
        }) }),
        ("POST", ["api", "auth", table, op @ ("sign-up" | "sign-in")]) => reply(if !st.allow(ip) { Err(limited()) } else { body_json(req).and_then(|v| {
            let pw = v.get("password").and_then(|p| p.as_str()).unwrap_or("");
            let r = if *op == "sign-up" { sql.sign_up(table, &sign_up_fields(sql, table, &v)?, pw) } else { sql.sign_in(table, v.get("login").and_then(|l| l.as_str()).unwrap_or(""), pw) };
            r.map(|si| signed_json(sql, table, &si)).map_err(err_json)
        }) }),
        ("GET", ["api", "auth", table, "oauth", provider]) => {
            let back = req.query.get("return").cloned().unwrap_or_default();
            let Some(base) = sql.cfg.app.public_url.clone() else { return json_resp(400, &json!({"error": "set app.publicUrl to sign in with a provider", "code": "CONFIG"}), &h) };
            if !return_ok(sql, &back) { return json_resp(400, &json!({"error": "return must be a URL on one of app.origins", "code": "ARGUMENTS"}), &h); }
            let challenge = req.query.get("challenge").cloned().unwrap_or_default();
            if !is_challenge(&challenge) { return json_resp(400, &json!({"error": "challenge must be the base64url SHA-256 of a verifier the page keeps (the client's signInWith makes both)", "code": "ARGUMENTS"}), &h); }
            let callback = format!("{base}/api/auth/{table}/oauth/{provider}/callback");
            match sql.oauth_start(table, provider, &callback, None) {
                Ok(start) => {
                    let attrs = format!("Path=/api/auth/; HttpOnly; SameSite=Lax; Max-Age=600{}", if base.starts_with("https://") { "; Secure" } else { "" });
                    redirect(&start.url, &[format!("sqz_oauth={}; {attrs}", start.cookie), format!("sqz_return={}; {attrs}", enc(&back)), format!("sqz_challenge={challenge}; {attrs}")])
                }
                Err(e) => json_resp(400, &err_json(e), &h),
            }
        }
        ("GET", ["api", "auth", table, "oauth", provider, "callback"]) => {
            let back = cookie(req, "sqz_return").filter(|b| return_ok(sql, b));
            let clear: Vec<String> = ["sqz_oauth", "sqz_return", "sqz_challenge"].iter().map(|c| format!("{c}=; Path=/api/auth/; HttpOnly; Max-Age=0")).collect();
            let challenge = cookie(req, "sqz_challenge").filter(|c| is_challenge(c));
            let result = match (req.query.get("error"), req.query.get("code"), req.query.get("state")) {
                (Some(e), _, _) => Err(format!("sign-in failed: the provider answered {e}")),
                _ if challenge.is_none() => Err("sign-in failed: this browser did not start this sign-in".into()),
                (None, Some(code), Some(state)) => { let create = sql.cfg.app.sign_up.contains_key(&table.to_ascii_lowercase()); sql.oauth_finish_as(table, provider, code, state, &cookie(req, "sqz_oauth").unwrap_or_default(), create) }
                _ => Err("sign-in failed: the provider sent no code".into()),
            };
            match (back, result) {
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
async fn read_frame(r: &mut (impl AsyncRead + Unpin)) -> io::Result<(bool, u8, Vec<u8>)> {
    let mut h = [0u8; 2]; r.read_exact(&mut h).await?;
    let (fin, op, masked) = (h[0] & 0x80 != 0, h[0] & 0x0f, h[1] & 0x80 != 0);
    let mut len = (h[1] & 0x7f) as u64;
    if len == 126 { let mut b = [0u8; 2]; r.read_exact(&mut b).await?; len = u16::from_be_bytes(b) as u64; } else if len == 127 { let mut b = [0u8; 8]; r.read_exact(&mut b).await?; len = u64::from_be_bytes(b); }
    if !masked { return Err(io::Error::other("a client frame must be masked")); }
    if len > MAX_MESSAGE as u64 { return Err(io::Error::other("message too large")); }
    let mut mask = [0u8; 4]; r.read_exact(&mut mask).await?;
    let mut p = vec![0u8; len as usize]; r.read_exact(&mut p).await?;
    for (i, b) in p.iter_mut().enumerate() { *b ^= mask[i % 4]; }
    Ok((fin, op, p))
}
/// A socket's state, shared by its reader (messages in) and its writer (replies, live results and pings out).
struct Conn { sess: Mutex<Session>, signed_in: AtomicBool, lives: Mutex<HashMap<u64, (Subscription, Cols)>>, changed: Arc<Notify>, done: Notify }
enum Out { Text(J), Pong(Vec<u8>), Close(Vec<u8>) }

async fn websocket<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(weak: Weak<Sql>, mut r: BufReader<ReadHalf<S>>, mut w: WriteHalf<S>, req: Req) {
    let Some(sql) = weak.upgrade() else { return };
    let upgrade = req.headers.get("upgrade").map(|u| u.eq_ignore_ascii_case("websocket")).unwrap_or(false);
    let Some(key) = req.headers.get("sec-websocket-key").filter(|_| upgrade) else { let _ = w.write_all(&json_resp(400, &json!({"error": "expected a WebSocket upgrade", "code": "ARGUMENTS"}), &[])).await; return };
    if allowed_origin(&sql, &req).is_err() { let _ = w.write_all(&json_resp(403, &json!({"error": "permission denied: this origin may not call the API (app.origins)", "code": "DENIED"}), &[])).await; return; }
    // a session acts as the anonymous role (if any) until an `auth` message names a token
    let s0 = anonymous_session(&sql); drop(sql);
    let hello = format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n", ws_accept(key));
    if !matches!(timeout(IO_TIMEOUT, w.write_all(hello.as_bytes())).await, Ok(Ok(()))) { return; }
    let conn = Arc::new(Conn { signed_in: AtomicBool::new(s0.user.is_some()), sess: Mutex::new(s0), lives: Mutex::new(HashMap::new()), changed: Arc::new(Notify::new()), done: Notify::new() });
    let (tx, rx) = mpsc::channel(OUT_QUEUE);
    let writer = tokio::spawn(write_loop(conn.clone(), w, rx));
    tokio::select! { _ = read_loop(&weak, &conn, &mut r, &tx) => {}, _ = conn.done.notified() => {} }
    drop(tx); conn.lives.lock().unwrap().clear();
    let _ = writer.await;
}
/// The socket's reader: each message runs as the socket's session, and its replies queue for the writer.
async fn read_loop<R: AsyncRead + Unpin>(weak: &Weak<Sql>, conn: &Arc<Conn>, r: &mut BufReader<R>, tx: &mpsc::Sender<Out>) -> io::Result<()> {
    let mut msg: Vec<u8> = vec![]; let mut text = false;
    loop {
        let (fin, op, p) = timeout(SOCKET_TIMEOUT, read_frame(r)).await.map_err(|_| io::Error::other("the client went quiet"))??;
        match op {
            0x8 => { let _ = tx.send(Out::Close(p[..p.len().min(2)].to_vec())).await; return Ok(()); }
            0x9 => { if tx.send(Out::Pong(p)).await.is_err() { return Ok(()); } continue; }
            0xA => continue,
            0x1 => { msg.clear(); text = true; }
            0x0 if text => {}
            _ => return Err(io::Error::other("text frames only")),
        }
        msg.extend_from_slice(&p);
        if msg.len() > MAX_MESSAGE { return Err(io::Error::other("message too large")); }
        if !fin { continue; }
        text = false;
        let Some(sql) = weak.upgrade() else { return Ok(()) };
        let (out, live) = match serde_json::from_slice::<J>(&msg) {
            Err(e) => (vec![json!({"error": format!("bad JSON: {e}"), "code": "ARGUMENTS"})], None),
            Ok(v) if sql.cfg.durable != Durability::Visible => {   // a write may wait for its fsync: off the runtime's threads
                let c = conn.clone();
                let Ok(x) = tokio::task::spawn_blocking(move || message(&sql, &c, &v)).await else { return Err(io::Error::other("a message failed")) };
                x
            }
            Ok(v) => { let x = message(&sql, conn, &v); drop(sql); x }
        };
        for m in out { if tx.send(Out::Text(m)).await.is_err() { return Ok(()); } }
        // a new live query delivers changes only once its first result is queued, so no change can overtake it
        if let Some((lid, sub, cols)) = live {
            let n = conn.changed.clone(); let mut lives = conn.lives.lock().unwrap();
            lives.insert(lid, (sub, cols)); lives[&lid].0.set_waker(Arc::new(move || n.notify_one()));
        }
    }
}
/// One message from a socket, run as its session: the replies, and a live query to deliver from once they are queued.
fn message(sql: &Arc<Sql>, conn: &Conn, v: &J) -> (Vec<J>, Option<(u64, Subscription, Cols)>) {
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
            let out = if !signed_in { Err(sign_in_first()) } else { let mut s = conn.sess.lock().unwrap(); if op == "sql" { run(sql, &mut s, v) } else { run_batch(sql, &mut s, v) } };
            (vec![reply(out.unwrap_or_else(|e| e))], None)
        }
        "live" => {
            let out = (|| -> Result<(J, u64, Subscription, Cols), J> {
                if !signed_in { return Err(sign_in_first()); }
                let lid = id.as_u64().ok_or_else(|| json!({"error": "a live query needs a numeric id", "code": "ARGUMENTS"}))?;
                if conn.lives.lock().unwrap().len() >= MAX_LIVES { return Err(json!({"error": format!("at most {MAX_LIVES} live queries per connection"), "code": "ARGUMENTS"})); }
                let p = client_statement(sql, v.get("sql").and_then(|s| s.as_str()).unwrap_or(""))?;
                if !matches!(p.plan, Plan::Select(_)) { return Err(json!({"error": "a live query is a SELECT", "code": "ARGUMENTS"})); }
                let params = params_of(v)?; let cols = sql.columns(&p);
                let (sub, rows) = sql.reactor().watch(&conn.sess.lock().unwrap(), &p.text, &params).map_err(err_json)?;
                if rows.len() > sql.cfg.app.max_rows { return Err(json!({"error": format!("the result has more than {} rows (app.maxRows); add a LIMIT", sql.cfg.app.max_rows), "code": "ARGUMENTS"})); }
                let first = json!({"live": true, "initial": true, "columns": names(&cols), "rows": rows.iter().map(|r| row_json(&cols, r)).collect::<Vec<_>>()});
                Ok((first, lid, sub, cols))
            })();
            match out { Ok((first, lid, sub, cols)) => (vec![reply(first)], Some((lid, sub, cols))), Err(e) => (vec![reply(e)], None) }
        }
        "unlive" => { if let Some(lid) = id.as_u64() { conn.lives.lock().unwrap().remove(&lid); } (vec![reply(json!({"ok": true}))], None) }
        other => (vec![reply(json!({"error": format!("unknown op {other:?}: auth, sql, batch, live or unlive"), "code": "ARGUMENTS"}))], None),
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
    let mut lives = conn.lives.lock().unwrap();
    for (id, (sub, cols)) in lives.iter() {
        let mut newest = None;
        while let Some(ev) = sub.try_recv() { match ev { Event::Live { seq, rows, .. } => newest = Some((seq, rows)), Event::Overflow { .. } => { ended.push(*id); break; } Event::Change(_) => {} } }
        if let Some((seq, rows)) = newest { out.push(json!({"id": id, "live": true, "seq": seq, "columns": names(cols), "rows": rows.iter().map(|r| row_json(cols, r)).collect::<Vec<_>>()})); }
    }
    for id in ended { lives.remove(&id); out.push(json!({"id": id, "ended": true, "reason": "the live query ended (signed out, the user changed, or it fell behind); make it again"})); }
    out
}
