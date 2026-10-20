//! The web console (`listen.http`): one page compiled into the binary plus a small JSON API over HTTP/1.1, served by
//! the owning process. The page is public; every `/api/` call needs the listener's token (`Authorization: Bearer`,
//! or `?token=` for the event streams a browser cannot set headers on). Bind it to loopback unless you mean otherwise.
//! The console runs as the application session: it sees everything, like the application does.
use crate::live::Event;
use crate::sql::{ChangeOp, PolicyRhs, Session, Sql, P_DELETE, P_INSERT, P_SELECT, P_UPDATE};
use crate::table::Value;
use crate::util::{base64, err_json, j_to_value, names, row_json, url_decode, value_json, Cols};
use serde_json::{json, Value as J};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const PAGE: &str = include_str!("ui/index.html");

/// What `sqzdb serve` tells its console about its settings: the file they are kept in (which may not exist yet), and
/// the options its command line set, which win over the file and so are shown fixed. Unset (an embedded database):
/// the application's code configures it, and the console only shows that.
pub struct ServeSettings { pub path: std::path::PathBuf, pub flags: J }
static SERVE: std::sync::OnceLock<ServeSettings> = std::sync::OnceLock::new();
/// Saved since this process started (the settings in use are older than the file), and a restart asked for.
static SAVED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static RESTART: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// `sqzdb serve` hands its console the settings file and its flags; it restarts the process when asked.
pub fn serve_settings(path: std::path::PathBuf, flags: J) { let _ = SERVE.set(ServeSettings { path, flags }); }
/// Whether the console asked the server to restart (to start with the settings saved).
pub fn restart_requested() -> bool { RESTART.load(Relaxed) }
/// Keys whose values are secrets: shown as set or not (or as the `${VAR}` they come from), never sent back.
const SECRETS: &[&str] = &["secretKey", "passphrase", "clientSecret", "apiKey", "token"];
/// A secret's value as the console shows the file's text; saved back, it keeps the value the file has.
const HIDDEN: &str = "(hidden: unchanged)";
/// Secrets in JSON (the command line's options): masked, a `${VAR}` reference shown as it is.
fn mask_json(v: &mut J) { if let J::Object(m) = v { for (k, x) in m.iter_mut() { if SECRETS.contains(&k.as_str()) { if let J::String(s) = x { if !s.trim_start().starts_with("${") { *x = json!(HIDDEN); } } } else { mask_json(x); } } } }
/// Every secret in a file's text (outside `${VAR}` references), each with its dotted key: to mask, and to restore.
fn secrets_in(doc: &mut toml_edit::DocumentMut, mut each: impl FnMut(&str, &mut toml_edit::Value)) {
    fn walk(t: &mut dyn toml_edit::TableLike, at: &str, each: &mut dyn FnMut(&str, &mut toml_edit::Value)) {
        for (k, item) in t.iter_mut() {
            let here = if at.is_empty() { k.get().to_string() } else { format!("{at}.{}", k.get()) };
            match item {
                toml_edit::Item::Table(t) => walk(t, &here, each),
                toml_edit::Item::Value(toml_edit::Value::InlineTable(t)) => walk(t, &here, each),
                toml_edit::Item::Value(v) if SECRETS.contains(&k.get()) && v.as_str().is_some_and(|s| !s.trim_start().starts_with("${")) => each(&here, v),
                _ => {}
            }
        }
    }
    walk(doc.as_table_mut(), "", &mut each);
}
/// The file's text as the console shows it: secrets replaced by HIDDEN (comments and the rest as they are). A text
/// that doesn't parse shows no line that sets a secret.
fn masked_text(text: &str) -> String {
    match text.parse::<toml_edit::DocumentMut>() {
        Ok(mut doc) => { secrets_in(&mut doc, |_, v| { let d = v.decor().clone(); *v = HIDDEN.into(); *v.decor_mut() = d; }); doc.to_string() }
        Err(_) => text.lines().map(|l| if SECRETS.iter().any(|k| l.trim_start().starts_with(k)) { format!("# {} = (hidden: the file doesn't parse)", l.trim_start().split(['=', ' ']).next().unwrap_or("")) } else { l.to_string() }).collect::<Vec<_>>().join("\n"),
    }
}
/// A text the console sends back: each secret still HIDDEN takes the value the file has for that key.
fn unmasked_text(text: &str, current: &str) -> Result<String, String> {
    if !text.contains(HIDDEN) { return Ok(text.to_string()); }
    let mut have = std::collections::HashMap::new();
    if let Ok(mut doc) = current.parse::<toml_edit::DocumentMut>() { secrets_in(&mut doc, |k, v| { have.insert(k.to_string(), v.as_str().unwrap_or("").to_string()); }); }
    let mut doc = text.parse::<toml_edit::DocumentMut>().map_err(|e| e.to_string())?;
    let mut missing = None;
    secrets_in(&mut doc, |k, v| if v.as_str() == Some(HIDDEN) { match have.get(k) { Some(real) => { let d = v.decor().clone(); *v = real.as_str().into(); *v.decor_mut() = d; } None => { missing.get_or_insert(k.to_string()); } } });
    match missing { Some(k) => Err(format!("{k}: hidden, and the file has no value for it: type the value")), None => Ok(doc.to_string()) }
}
const MAX_BODY: usize = 1 << 20; const MAX_LINE: u64 = 16 << 10; const MAX_HEADERS: usize = 64;
/// Idle keep-alive connections and stalled writers are dropped after this long.
const IO_TIMEOUT: Duration = Duration::from_secs(60);

pub fn start(sql: Arc<Sql>, addr: &str, token: &str) -> Result<crate::net::Listener, String> {
    if token.is_empty() { return Err("listen.http needs listen.token".into()); }
    let listener = TcpListener::bind(addr).map_err(|e| format!("listen.http {addr}: {e}"))?;
    let weak = Arc::downgrade(&sql); drop(sql); let token: Arc<str> = Arc::from(token);
    crate::net::accept_tcp(listener, move |stream| {
        if weak.strong_count() == 0 { return false; }
        stream.set_nodelay(true).ok(); stream.set_read_timeout(Some(IO_TIMEOUT)).ok(); stream.set_write_timeout(Some(IO_TIMEOUT)).ok();
        let (w, t) = (weak.clone(), token.clone());
        std::thread::spawn(move || { let _ = serve(w, stream, &t); });
        true
    }).map_err(|e| format!("listen.http {addr}: {e}"))
}

struct Req { method: String, path: String, query: HashMap<String, String>, headers: HashMap<String, String>, body: Vec<u8> }
/// One CRLF/LF-terminated line of at most MAX_LINE bytes; `None` at a clean end of stream. Requests are read before
/// the token is checked, so nothing here may grow with what a client sends.
fn read_line_max(r: &mut BufReader<TcpStream>) -> std::io::Result<Option<String>> {
    let mut buf = Vec::new(); let n = r.by_ref().take(MAX_LINE).read_until(b'\n', &mut buf)?;
    if n == 0 { return Ok(None); }
    if buf.last() != Some(&b'\n') { return Err(std::io::Error::other("request line or header too long")); }
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}
fn read_req(r: &mut BufReader<TcpStream>) -> std::io::Result<Option<Req>> {
    let Some(line) = read_line_max(r)? else { return Ok(None) };
    let mut parts = line.split_whitespace(); let method = parts.next().unwrap_or("").to_string(); let target = parts.next().unwrap_or("/").to_string();
    let mut headers = HashMap::new();
    for n in 0.. {
        let Some(h) = read_line_max(r)? else { return Ok(None) }; let h = h.trim_end(); if h.is_empty() { break; }
        if n >= MAX_HEADERS { return Err(std::io::Error::other("too many header lines")); }   // lines, not names: a repeated name must count too
        if let Some((k, v)) = h.split_once(':') { headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string()); }
    }
    let len: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    if len > MAX_BODY { return Err(std::io::Error::other("body too large")); }
    let mut body = vec![0u8; len]; if len > 0 { r.read_exact(&mut body)?; }
    let (path, q) = match target.split_once('?') { Some((p, q)) => (p.to_string(), q.to_string()), None => (target.clone(), String::new()) };
    let query = q.split('&').filter(|s| !s.is_empty()).map(|kv| { let (k, v) = kv.split_once('=').unwrap_or((kv, "")); (url_decode(k), url_decode(v)) }).collect();
    Ok(Some(Req { method, path, query, headers, body }))
}
fn respond(w: &mut TcpStream, status: u16, ctype: &str, body: &[u8]) -> std::io::Result<()> {
    let reason = match status { 200 => "OK", 400 => "Bad Request", 401 => "Unauthorized", 404 => "Not Found", 405 => "Method Not Allowed", _ => "Error" };
    // one write per response: a response written in fragments waits on the peer's delayed ACK for each one
    let mut out = format!("HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: {}\r\nConnection: keep-alive\r\n\r\n", body.len(), csp()).into_bytes();
    out.extend_from_slice(body); w.write_all(&out)?; w.flush()
}
/// The page's own script is allowed by its SHA-256 hash and nothing else may run: no inline handlers, no injected
/// scripts, even if a value ever reached the markup unescaped.
fn csp() -> &'static str {
    static CSP: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    CSP.get_or_init(|| {
        use sha2::Digest;
        let script = PAGE.split_once("<script>").and_then(|(_, rest)| rest.split_once("</script>")).map(|(s, _)| s).unwrap_or("");
        let hash = base64(&sha2::Sha256::digest(script.as_bytes()));
        format!("default-src 'none'; script-src 'sha256-{hash}'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
    })
}
fn json_resp(w: &mut TcpStream, status: u16, v: &J) -> std::io::Result<()> { respond(w, status, "application/json", v.to_string().as_bytes()) }
fn authorized(req: &Req, token: &str) -> bool {
    let given = req.headers.get("authorization").and_then(|h| h.strip_prefix("Bearer ")).map(|s| s.trim().to_string()).or_else(|| req.query.get("token").cloned());
    given.map(|g| crate::net::same_secret(g.as_bytes(), token.as_bytes())).unwrap_or(false)
}

fn serve(weak: std::sync::Weak<Sql>, stream: TcpStream, token: &str) -> std::io::Result<()> {
    let mut r = BufReader::with_capacity(1 << 16, stream.try_clone()?); let mut w = stream;
    let mut sess = Session::default();
    loop {
        let Some(req) = read_req(&mut r)? else { return Ok(()) };
        let Some(sql) = weak.upgrade() else { return Ok(()) };   // held for this request only
        let close = req.headers.get("connection").map(|c| c.eq_ignore_ascii_case("close")).unwrap_or(false);
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/") | ("GET", "/index.html") => respond(&mut w, 200, "text/html; charset=utf-8", PAGE.as_bytes())?,
            (_, p) if p.starts_with("/api/") => {
                if !authorized(&req, token) { json_resp(&mut w, 401, &json!({"error": "token required", "code": "DENIED"}))?; }
                else {
                    match (req.method.as_str(), p) {
                        ("POST", "/api/sql") => { let v = api_sql(&sql, &mut sess, &req.body); json_resp(&mut w, if v.get("error").is_some() { 400 } else { 200 }, &v)? }
                        ("GET", "/api/tables") => json_resp(&mut w, 200, &api_tables(&sql))?,
                        ("GET", "/api/status") => json_resp(&mut w, 200, &api_status(&sql))?,
                        ("GET", "/api/acl") => json_resp(&mut w, 200, &api_acl(&sql))?,
                        ("GET", "/api/settings") => json_resp(&mut w, 200, &api_settings())?,
                        ("POST", "/api/settings") => { let (st, v) = api_save_settings(&req.body); json_resp(&mut w, st, &v)? }
                        ("POST", "/api/restart") => match restart_check() {
                            Err((st, e)) => json_resp(&mut w, st, &json!({"error": e, "code": if st == 409 { "CONFLICT" } else { "CONFIG" }}))?,
                            Ok(()) => { json_resp(&mut w, 200, &json!({"restarting": true}))?; std::thread::spawn(|| { std::thread::sleep(Duration::from_millis(150)); RESTART.store(true, Relaxed); }); }
                        },
                        ("GET", "/api/functions") => json_resp(&mut w, 200, &api_functions(&sql))?,
                        ("POST", "/api/functions") => { let (st, v) = api_deploy(&sql, &req.body); json_resp(&mut w, st, &v)? }
                        ("POST", "/api/functions/call") => { let (st, v) = api_call(&sql, &req.body); json_resp(&mut w, st, &v)? }
                        ("POST", "/api/backup/test") => json_resp(&mut w, 200, &api_backup_test(&sql))?,
                        ("POST", "/api/snapshot") => { let st = sql.snapshot(); json_resp(&mut w, 200, &json!({"rows": st.rows, "bytes": st.bytes, "secs": st.secs, "deletedSegments": st.deleted_segments}))? }
                        ("GET", "/api/live") => { drop(sql); return stream_events(&weak, &sess, &req, w, false) }
                        ("GET", "/api/changes") => { drop(sql); return stream_events(&weak, &sess, &req, w, true) }
                        _ => json_resp(&mut w, 404, &json!({"error": "no such endpoint", "code": "ERROR"}))?,
                    }
                }
            }
            _ => respond(&mut w, 404, "text/plain", b"not found")?,
        }
        if close { return Ok(()); }
    }
}

/// Check the configured bucket the way the uploader uses it (list, write, delete), step by step.
fn api_backup_test(sql: &Sql) -> J {
    let Some(b) = sql.cfg.backup.as_ref() else { return json!({"error": "backup is not configured", "code": "CONFIG"}) };
    let steps = crate::cloud::probe(&b.cloud());
    json!({ "ok": steps.iter().all(|s| s.1) && steps.len() == 3, "steps": steps.iter().map(|(name, ok, ms, err)| json!({"step": name, "ok": ok, "ms": ms, "error": if err.is_empty() { J::Null } else { json!(err) }})).collect::<Vec<_>>() })
}

fn api_sql(sql: &Sql, sess: &mut Session, body: &[u8]) -> J {
    let v: J = match serde_json::from_slice(body) { Ok(v) => v, Err(e) => return json!({"error": format!("bad JSON: {e}"), "code": "ARGUMENTS"}) };
    let text = v.get("sql").and_then(|s| s.as_str()).unwrap_or("").trim().trim_end_matches(';').to_string();
    if text.is_empty() { return json!({"error": "sql is required", "code": "ARGUMENTS"}); }
    let params: Vec<Value> = v.get("params").and_then(|p| p.as_array()).map(|a| a.iter().map(j_to_value).collect()).unwrap_or_default();
    let t = Instant::now();
    match sql.query(sess, &text, &params) {
        Ok((cols, rows)) => {
            let mut v = json!({ "columns": names(&cols), "types": cols.iter().map(|(_, t)| t.as_ref().map(|t| t.name())).collect::<Vec<_>>(), "rows": rows.iter().map(|r| row_json(&cols, r)).collect::<Vec<_>>(), "count": rows.len(), "ms": t.elapsed().as_secs_f64() * 1e3, "inTransaction": sess.txn.is_some() });
            if text.trim_start().get(..6).map(|w| w.eq_ignore_ascii_case("INSERT")).unwrap_or(false) { v["lastInsertId"] = sess.last_insert_key.as_ref().map(|k| value_json(k, None)).unwrap_or(J::Null); }
            v
        }
        Err(e) => err_json(e),
    }
}
fn api_tables(sql: &Sql) -> J {
    let mut sess = Session::default();
    J::Array(sql.db.table_names().iter().filter_map(|n| {
        let t = sql.db.table(n)?;
        let rows = sql.exec_s(&mut sess, &format!("SELECT count(*) FROM {n}"), &[]).ok().and_then(|r| r.first().and_then(|r| r.first()).and_then(|v| if let Value::Int(i) = v { Some(*i) } else { None })).unwrap_or(-1);
        Some(json!({ "name": t.schema.name, "rows": rows, "columns": t.schema.columns.iter().enumerate().map(|(i, c)| {
            let fk = t.schema.fks.iter().find(|f| f.col == i).map(|f| json!({"table": f.parent, "onDelete": match f.on_delete { crate::table::FkAction::Restrict => "RESTRICT", crate::table::FkAction::Cascade => "CASCADE", crate::table::FkAction::SetNull => "SET NULL" }}));
            let default = match &c.generated { Some(g) => json!(g.sql()), None => value_json(&c.default, Some(&c.ty)) };
            json!({"name": c.name, "type": c.type_name(), "nullable": c.nullable, "pk": i == t.schema.pk, "auto": i == t.schema.pk && t.schema.auto, "unique": t.schema.unique == Some(i), "default": default, "references": fk})
        }).collect::<Vec<_>>(), "foreignKeys": t.schema.fks.len() }))
    }).collect())
}
fn api_status(sql: &Sql) -> J {
    use crate::config::Durability;
    let (seq, durable, bytes) = { let s = sql.db.log.st.lock().unwrap(); (s.seq, s.durable, s.bytes) };
    let cfg = &sql.cfg;
    let backup = sql.backup_stats().map(|st| {
        let b = cfg.backup.as_ref(); let ms = |v: u64| if v == 0 { J::Null } else { json!(v) };
        let e = st.last_error(); let last_error = if e.is_empty() { J::Null } else { json!(e) };
        json!({ "bucket": b.map(|b| format!("{}/{}", b.bucket, b.prefix.trim_matches('/'))), "bucketName": b.map(|b| b.bucket.clone()), "prefix": b.map(|b| b.prefix.clone()),
            "endpoint": b.map(|b| b.endpoint.clone()), "region": b.map(|b| b.region.clone()), "encrypted": b.map(|b| b.passphrase.is_some()).unwrap_or(false), "compress": b.map(|b| b.compress).unwrap_or(true),
            "intervalMs": b.map(|b| b.interval.as_millis() as u64), "compactAfterMs": b.map(|b| b.compact_after.as_millis() as u64), "cloudDurable": matches!(cfg.durable, Durability::Cloud),
            "objects": st.puts.load(Relaxed), "bytes": st.bytes.load(Relaxed), "rawBytes": st.raw_bytes.load(Relaxed), "snapshots": st.snapshots.load(Relaxed), "merges": st.merges.load(Relaxed), "deletes": st.deletes.load(Relaxed),
            "cloudSeq": st.cloud_seq.load(Relaxed), "behind": seq.saturating_sub(st.cloud_seq.load(Relaxed)),
            "state": st.state(), "resumed": st.resumed.load(Relaxed), "okAt": ms(st.ok_at_ms.load(Relaxed)), "uploadAt": ms(st.upload_at_ms.load(Relaxed)), "errorAt": ms(st.err_at_ms.load(Relaxed)),
            "lastError": last_error, "failures": st.failures.load(Relaxed).min(1_000_000), "failuresTotal": st.failures_total.load(Relaxed), "now": crate::cloud::now_ms(),
            "files": sql.files_backup_stats().map(|f| json!({ "uploaded": f.uploaded.load(Relaxed), "bytes": f.bytes.load(Relaxed), "deleted": f.deleted.load(Relaxed), "fetched": f.fetched.load(Relaxed), "pending": f.pending.load(Relaxed), "missing": f.missing.load(Relaxed) })) })
    });
    json!({ "dir": sql.db.dir.display().to_string(), "durable": match cfg.durable { Durability::Visible => "visible", Durability::Fsync => "fsync", Durability::Cloud => "cloud" }, "seq": seq, "durableSeq": durable, "logBytes": bytes,
            "snapshotsByPolicy": sql.snapshots_taken(), "snapshotPolicy": {"logBytes": cfg.snapshot.log_bytes, "idleAfterMs": cfg.snapshot.idle_after.map(|d| d.as_millis() as u64)},
            "altersInProgress": sql.db.tables_with_shadow().iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(),
            "listen": {"socket": cfg.listen.socket.as_ref().map(|p| p.display().to_string()), "tcp": cfg.listen.tcp, "http": cfg.listen.http},
            "backup": backup, "followerApplied": sql.follower_applied(), "tables": sql.db.table_names().len(), "reactor": sql.live.get().map(|r| json!({"events": r.events.load(Relaxed), "reruns": r.reruns.load(Relaxed)})) })
}
fn cmp_sym(c: crate::sql::Cmp) -> &'static str { use crate::sql::Cmp::*; match c { Eq => "=", Ne => "<>", Lt => "<", Le => "<=", Gt => ">", Ge => ">=", IsNull => "IS NULL", IsNotNull => "IS NOT NULL", In => "IN", NotIn => "NOT IN" } }
// ---- settings: the server's configuration file, read and written here; applied by a restart

/// The settings file: its text, its values (secrets masked), which keys the command line fixes, and whether it was
/// saved since the server started.
fn api_settings() -> J {
    let Some(sv) = SERVE.get() else { return json!({"editable": false}) };
    let text = std::fs::read_to_string(&sv.path).unwrap_or_default();
    let mut values = toml::from_str::<toml::Value>(&text).ok().and_then(|v| serde_json::to_value(v).ok()).unwrap_or(json!({}));
    let mut secrets = serde_json::Map::new();
    fn mask(v: &mut J, at: &str, out: &mut serde_json::Map<String, J>) {
        let J::Object(m) = v else { return };
        for (k, x) in m.iter_mut() {
            let here = if at.is_empty() { k.clone() } else { format!("{at}.{k}") };
            if SECRETS.contains(&k.as_str()) { if let J::String(s) = x { out.insert(here, json!(if s.trim_start().starts_with("${") { s.clone() } else { String::new() })); *x = json!(""); } }
            else { mask(x, &here, out); }
        }
    }
    mask(&mut values, "", &mut secrets);
    let mut flags = sv.flags.clone(); mask_json(&mut flags);
    json!({"editable": true, "path": sv.path.display().to_string(), "exists": sv.path.exists(), "text": masked_text(&text), "values": values, "secrets": secrets,
           "flags": flags, "saved": SAVED.load(Relaxed)})
}
/// Save the settings: `{"text": …}` (the whole file), or `{"set": {"app.publicUrl": …, "backup": null, …}}` (keys
/// changed in the file as it is, comments and all; null removes one). Checked as the server would start with it
/// (its flags over it) before it is written; written whole (a temporary file, renamed), readable by its owner only.
fn api_save_settings(body: &[u8]) -> (u16, J) {
    let Some(sv) = SERVE.get() else { return (409, json!({"error": "this database's settings come from its application's code", "code": "CONFLICT"})) };
    let Ok(v) = serde_json::from_slice::<J>(body) else { return (400, json!({"error": "send {\"text\"} or {\"set\": {key: value}}", "code": "ARGUMENTS"})) };
    let current = std::fs::read_to_string(&sv.path).unwrap_or_default();
    let text = match (v.get("text").and_then(|t| t.as_str()), v.get("set").and_then(|s| s.as_object())) {
        (Some(t), _) => match unmasked_text(t, &current) { Ok(t) => t, Err(e) => return (400, json!({"error": e, "code": "CONFIG"})) },
        (None, Some(set)) => match patch_toml(&current, set) { Ok(t) => t, Err(e) => return (400, json!({"error": e, "code": "CONFIG"})) },
        _ => return (400, json!({"error": "send {\"text\"} or {\"set\": {key: value}}", "code": "ARGUMENTS"})),
    };
    if let Err(e) = crate::config::Config::check(&text, Some(&sv.flags.to_string())) { return (400, json!({"error": crate::config::scrub(&e, &text), "code": "CONFIG"})); }
    if text == current { return (200, json!({"saved": false, "text": masked_text(&text)})); }
    if sv.path.exists() { if let Err(e) = crate::config::private_file(&sv.path) { return (409, json!({"error": e, "code": "CONFIG"})); } }
    if let Err(e) = write_private(&sv.path, text.as_bytes()) { return (500, json!({"error": format!("{}: {e}", sv.path.display()), "code": "ERROR"})); }
    SAVED.store(true, Relaxed);
    (200, json!({"saved": true, "text": masked_text(&text)}))
}
/// Whether the server can restart into its settings file as it is now (it may have been edited by hand since): the
/// checks its start makes, so a restart never leaves it down.
fn restart_check() -> Result<(), (u16, String)> {
    let Some(sv) = SERVE.get() else { return Err((409, "this database runs inside its application: restart the application".into())) };
    if !sv.path.exists() { return Ok(()); }
    crate::config::private_file(&sv.path).map_err(|e| (409, e))?;
    let text = std::fs::read_to_string(&sv.path).map_err(|e| (409, format!("{}: {e}", sv.path.display())))?;
    crate::config::Config::check(&text, Some(&sv.flags.to_string())).map(|_| ()).map_err(|e| (400, format!("{}: {}", sv.path.display(), crate::config::scrub(&e, &text))))
}
/// Change keys of a TOML file's text in place (comments, order and the rest untouched): a dotted key to a value,
/// a table (an object), or nothing (null).
fn patch_toml(text: &str, set: &serde_json::Map<String, J>) -> Result<String, String> {
    use toml_edit::{Array, InlineTable, Item, Table, Value as TV};
    fn value(v: &J) -> Option<TV> { match v {
        J::String(s) => Some(s.as_str().into()), J::Bool(b) => Some((*b).into()),
        J::Number(n) => n.as_i64().map(TV::from).or_else(|| n.as_f64().map(TV::from)),
        J::Array(a) => Some(TV::Array(a.iter().filter_map(value).collect::<Array>())),
        J::Object(m) => { let mut t = InlineTable::new(); for (k, x) in m { if let Some(v) = value(x) { t.insert(k, v); } } Some(TV::InlineTable(t)) }
        J::Null => None } }
    fn item(v: &J) -> Option<Item> { match v {
        J::Object(m) => { let mut t = Table::new(); for (k, x) in m { if let Some(i) = item(x) { t.insert(k, i); } } Some(Item::Table(t)) }
        v => value(v).map(Item::Value) } }
    let mut doc: toml_edit::DocumentMut = text.parse().map_err(|e| format!("the file as it is: {e}"))?;
    for (key, v) in set {
        let parts: Vec<&str> = key.split('.').collect();
        if parts.iter().any(|p| p.is_empty()) { return Err(format!("{key}: not a key")); }
        let (last, parents) = parts.split_last().expect("a key");
        let mut t = doc.as_table_mut();
        for p in parents {
            if t.get(p).is_none() { if v.is_null() { break; } t.insert(p, Item::Table(Table::new())); }
            let it = t.get_mut(p).expect("there");
            if let Some(inline) = it.as_inline_table().cloned() { *it = Item::Table(inline.into_table()); }
            t = it.as_table_mut().ok_or_else(|| format!("{key}: {p} is not a table"))?;
        }
        if t.get(last).is_some() || !v.is_null() { match item(v) { Some(i) => { t.insert(last, i); } None => { t.remove(last); } } }
    }
    Ok(doc.to_string())
}
/// Write a file whole and readable by its owner only: a new temporary file next to it, then renamed over it.
fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension(format!("toml.{}.tmp", std::process::id()));
    let mut o = std::fs::OpenOptions::new(); o.write(true).create_new(true);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; o.mode(0o600); }
    let r = (|| { let mut f = o.open(&tmp)?; f.write_all(data)?; f.sync_all()?; std::fs::rename(&tmp, path) })();
    if r.is_err() { let _ = std::fs::remove_file(&tmp); }
    r
}

// ---- functions: what is deployed, deploying from here, and trying one as an identity

/// The deploy: its files as written, its exports, why it doesn't load (if it doesn't), where it comes from, and the
/// MCP endpoint agents reach its functions at.
fn api_functions(sql: &Sql) -> J {
    let dir = sql.cfg.functions.dir.as_ref().map(|d| d.display().to_string());
    let files: serde_json::Map<String, J> = sql.deployed_files().into_iter().map(|(k, v)| (k, J::String(v))).collect();
    json!({"files": files, "exports": sql.exports_json(), "broken": sql.functions_broken_reason(), "folder": dir, "watch": sql.cfg.functions.watch,
           "mcp": sql.cfg.app.mcp.as_ref().map(|m| json!({"url": sql.cfg.app.public_url.as_ref().map(|u| format!("{}/mcp", u.trim_end_matches('/'))), "sql": m.sql}))})
}
/// Deploy these files (`{"files": {path: source}}`), replacing the deploy in use; refused while a folder is the source.
fn api_deploy(sql: &Sql, body: &[u8]) -> (u16, J) {
    if let Some(d) = &sql.cfg.functions.dir { return (409, json!({"error": format!("the functions are deployed from {} (at start, and as it changes): edit the files there", d.display()), "code": "CONFLICT"})); }
    let files = serde_json::from_slice::<J>(body).ok().and_then(|v| v.get("files").and_then(|f| f.as_object()).map(|m| m.iter().map(|(k, s)| s.as_str().map(|s| (k.clone(), s.to_string()))).collect::<Option<Vec<_>>>())).flatten();
    let Some(files) = files else { return (400, json!({"error": "send {\"files\": {path: source}}", "code": "ARGUMENTS"})) };
    match sql.deploy_functions(&Session::default(), files) {
        Ok(d) => (200, json!({"functions": d.functions, "changed": d.changed})),
        Err(e) => (400, json!({"error": e, "code": "FUNCTION"})),
    }
}
/// Call a function as the app (`as` absent), or as an identity: `{"name", "args", "as": {"roles": […], "attrs": {…}}}`.
fn api_call(sql: &Sql, body: &[u8]) -> (u16, J) {
    let Ok(v) = serde_json::from_slice::<J>(body) else { return (400, json!({"error": "send {\"name\", \"args\", \"as\"}", "code": "ARGUMENTS"})) };
    let mut sess = Session::default();
    if let Some(who) = v.get("as").filter(|w| !w.is_null()) {
        if let Err(e) = sql.assume_json(&mut sess, &who.to_string()) { return (400, json!({"error": e, "code": "ARGUMENTS"})); }
    }
    let name = v.get("name").and_then(|n| n.as_str()).unwrap_or("");
    let t = Instant::now();
    match sql.call_function(&mut sess, name, v.get("args").unwrap_or(&json!({})), false) {
        Ok(r) => (200, json!({"result": r, "ms": t.elapsed().as_secs_f64() * 1000.0})),
        Err(e) => (400, json!({"error": e.message, "code": e.code})),
    }
}

fn cmds_str(m: u8) -> Vec<&'static str> { let mut v = vec![]; if m & P_SELECT != 0 { v.push("SELECT"); } if m & P_INSERT != 0 { v.push("INSERT"); } if m & P_UPDATE != 0 { v.push("UPDATE"); } if m & P_DELETE != 0 { v.push("DELETE"); } v }
fn api_acl(sql: &Sql) -> J {
    let a = sql.acl.read().unwrap();
    let mut roles: Vec<String> = a.roles.iter().cloned().collect(); roles.sort();
    let mut users: Vec<J> = a.users.iter().map(|(u, r)| json!({"name": u, "roles": r.roles, "attrs": r.attrs.iter().map(|(k, v)| (k.clone(), value_json(v, None))).collect::<serde_json::Map<_, _>>()})).collect();
    users.sort_by_key(|x| x["name"].as_str().unwrap_or("").to_string());
    let mut auth: Vec<J> = a.auth.iter().map(|(t, at)| {
        let cols = sql.db.table(t).map(|tb| tb.schema.columns.iter().map(|c| c.name.clone()).collect::<Vec<_>>()).unwrap_or_default();
        json!({"table": t, "login": cols.get(at.login), "role": match &at.role { crate::auth::RoleSrc::Column(c) => json!({"column": cols.get(*c)}), crate::auth::RoleSrc::Fixed(r) => json!({"fixed": r}) }})
    }).collect();
    auth.sort_by_key(|x| x["table"].as_str().unwrap_or("").to_string());
    json!({
        "roles": roles,
        "users": users,
        "auth": auth,
        "grants": a.grants.iter().map(|((role, table), m)| json!({"role": role, "table": table, "commands": cmds_str(*m)})).collect::<Vec<_>>(),
        "policies": a.policies.iter().map(|p| json!({"name": p.name, "table": p.table, "role": p.role, "commands": cmds_str(p.cmds), "using": p.preds.iter().map(|(c, cmp, rhs)| format!("{c} {} {}", cmp_sym(*cmp), match rhs { PolicyRhs::Lit(v) => value_json(v, None).to_string(), PolicyRhs::Attr(n) => format!("SESSION.{n}") })).collect::<Vec<_>>().join(" AND ")})).collect::<Vec<_>>(),
    })
}
/// Server-Sent Events: a live query (`/api/live`, the whole result on every change) or a change tail (`/api/changes`).
fn stream_events(weak: &std::sync::Weak<Sql>, sess: &Session, req: &Req, mut w: TcpStream, changes: bool) -> std::io::Result<()> {
    let Some(sql) = weak.upgrade() else { return Ok(()) };
    let text = req.query.get("sql").cloned().unwrap_or_default();
    let params: Vec<Value> = req.query.get("params").and_then(|p| serde_json::from_str::<J>(p).ok()).and_then(|v| v.as_array().map(|a| a.iter().map(j_to_value).collect())).unwrap_or_default();
    let cols: Cols = sql.prepare(&text).map(|p| sql.columns(&p)).unwrap_or_default();
    let (sub, initial) = if changes { match sql.reactor().subscribe(sess, &text, &params) { Ok(s) => (s, None), Err(e) => return json_resp(&mut w, 400, &err_json(e)) } }
                         else { match sql.reactor().watch(sess, &text, &params) { Ok((s, rows)) => (s, Some(rows)), Err(e) => return json_resp(&mut w, 400, &err_json(e)) } };
    w.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n")?;
    let send = |w: &mut TcpStream, v: J| -> std::io::Result<()> { w.write_all(format!("data: {v}\n\n").as_bytes())?; w.flush() };
    let types: Vec<Option<String>> = cols.iter().map(|(_, t)| t.as_ref().map(|t| t.name())).collect();
    if let Some(rows) = initial { send(&mut w, json!({"type": "rows", "columns": names(&cols), "types": types, "rows": rows.iter().map(|r| row_json(&cols, r)).collect::<Vec<_>>(), "initial": true}))?; }
    drop(sql);   // a stream must not keep the database open
    let mut table_cols: HashMap<String, Cols> = HashMap::new(); let mut quiet = Instant::now();
    loop {
        let ev = sub.recv_timeout(Duration::from_secs(1));
        if weak.strong_count() == 0 { return Ok(()); }
        if ev.is_some() { quiet = Instant::now(); }
        match ev {
            Some(Event::Live { seq, rows, added, removed }) => send(&mut w, json!({"type": "rows", "seq": seq, "columns": names(&cols), "types": types, "rows": rows.iter().map(|r| row_json(&cols, r)).collect::<Vec<_>>(), "added": added.len(), "removed": removed.len()}))?,
            Some(Event::Change(c)) => {
                let tc = table_cols.entry(c.table.clone()).or_insert_with(|| weak.upgrade().and_then(|s| s.db.table(&c.table)).map(|t| t.schema.columns.iter().map(|col| (col.name.clone(), Some(col.ty.clone()))).collect()).unwrap_or_default());
                send(&mut w, json!({"type": "change", "op": match c.op { ChangeOp::Insert => "insert", ChangeOp::Update => "update", ChangeOp::Delete => "delete" }, "table": c.table, "key": value_json(&c.pk, None), "seq": c.seq, "columns": names(tc), "row": c.row.as_ref().map(|r| row_json(tc, r))}))?
            }
            Some(Event::Overflow { last_seq }) => { send(&mut w, json!({"type": "overflow", "seq": last_seq}))?; return Ok(()); }
            None => if quiet.elapsed() >= Duration::from_secs(15) { w.write_all(b": keepalive\n\n")?; w.flush()?; quiet = Instant::now(); },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn base64_matches_rfc4648() { assert_eq!(base64(b""), ""); assert_eq!(base64(b"f"), "Zg=="); assert_eq!(base64(b"fo"), "Zm8="); assert_eq!(base64(b"foo"), "Zm9v"); assert_eq!(base64(b"foobar"), "Zm9vYmFy"); }
    /// The console changes keys of the settings file in place: comments, order and other keys stay; a section can be
    /// added whole or removed; and what it writes is checked as the server would load it.
    #[test] fn settings_are_changed_in_place() {
        let text = "# mine: keep this\n[app]\npublicUrl = \"http://127.0.0.1:8080\"  # here\n\n[backup]\nendpoint = \"https://s3.example\"\nbucket = \"b\"\naccessKey = \"a\"\nsecretKey = \"${S3_SECRET}\"\n";
        let set = |j: J| patch_toml(text, j.as_object().unwrap()).unwrap();
        let t = set(json!({"app.signUp": {"users": []}, "app.mcp": {}, "auth.sessionTtl": "7d"}));
        assert!(t.starts_with("# mine: keep this\n[app]\npublicUrl = \"http://127.0.0.1:8080\"  # here\n"), "{t}");
        assert!(t.contains("[app.signUp]\nusers = []") && t.contains("[app.mcp]") && t.contains("[auth]\nsessionTtl = \"7d\""), "{t}");
        assert!(t.contains("secretKey = \"${S3_SECRET}\""), "a reference to the environment stays as written");
        let t = set(json!({"backup": null, "app.publicUrl": null, "nothing.here": null}));
        assert!(!t.contains("[backup]") && !t.contains("publicUrl") && !t.contains("nothing"), "{t}");
        assert!(patch_toml("app = { publicUrl = \"x\" }\n", json!({"app.origins": ["*"]}).as_object().unwrap()).unwrap().contains("origins = [\"*\"]"), "an inline table becomes a table");
        assert!(patch_toml(text, json!({"app.publicUrl.x": 1}).as_object().unwrap()).is_err(), "a value is not a table");
        assert!(crate::config::Config::check("[functions]\ntimeout = \"0s\"\n", None).unwrap_err().contains("functions.timeout"));
        assert!(crate::config::Config::check("[app]\npublicUrl = \"http://127.0.0.1:8080\"\n[app.mcp]\n", Some(r#"{"listen": {"app": "127.0.0.1:8080"}}"#)).is_ok());
    }
    /// The file's text reaches the console with its secrets hidden (a `${VAR}` reference shown), and comes back with
    /// them as they were; an error never shows a value a reference brought in.
    #[test] fn secrets_stay_on_the_server() {
        let file = "# keys\n[backup]\nendpoint = \"https://s3.example\"\nsecretKey = \"s3cr3t-value\"  # the real one\npassphrase = \"${DB_PASS}\"\n\n[auth.oauth.google]\nclientId = \"id\"\nclientSecret = \"g-secret\"\n";
        let shown = masked_text(file);
        assert!(!shown.contains("s3cr3t-value") && !shown.contains("g-secret"), "{shown}");
        assert!(shown.contains(&format!("secretKey = \"{HIDDEN}\"  # the real one")) && shown.contains("passphrase = \"${DB_PASS}\""), "{shown}");
        let edited = shown.replace("endpoint = \"https://s3.example\"", "endpoint = \"https://s3.other\"");
        let back = unmasked_text(&edited, file).unwrap();
        assert_eq!(back, file.replace("https://s3.example", "https://s3.other"), "secrets as they were, the edit kept");
        assert!(unmasked_text(&format!("[app]\ntoken = \"{HIDDEN}\"\n"), file).unwrap_err().contains("app.token: hidden"));
        assert!(!masked_text("[backup\nsecretKey = \"leak\"\n").contains("leak"), "a file that doesn't parse shows no secret line");
        let mut flags = json!({"listen": {"token": "t0k3n", "http": "127.0.0.1:1"}}); mask_json(&mut flags);
        assert_eq!(flags, json!({"listen": {"token": HIDDEN, "http": "127.0.0.1:1"}}));
        // an error about a value from the environment names the reference, not the value
        let text = "[functions]\ntimeout = \"${HOME}\"\n";
        let e = crate::config::Config::check(text, None).unwrap_err();
        let home = std::env::var("HOME").unwrap(); assert!(home.len() >= 3);
        assert!(!crate::config::scrub(&e, text).contains(&home) && crate::config::scrub(&e, text).contains("${HOME}"), "{e}");
    }
    /// A settings file sqzdb reads without being told to must be its user's alone.
    #[cfg(unix)] #[test] fn an_unnamed_settings_file_is_its_users_alone() {
        use std::os::unix::fs::PermissionsExt;
        let p = std::env::temp_dir().join(format!("sqzdb-settings-{}.toml", std::process::id()));
        write_private(&p, b"").unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(crate::config::private_file(&p).is_ok());
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert!(crate::config::private_file(&p).unwrap_err().contains("others may write it"));
        std::fs::remove_file(&p).unwrap();
        assert!(crate::config::private_file(&std::env::temp_dir()).unwrap_err().contains("not a regular file"));
        // read through one handle: a link to a file of the user's own is refused all the same
        let real = std::env::temp_dir().join(format!("sqzdb-settings-real-{}.toml", std::process::id())); write_private(&real, b"[app]\n").unwrap();
        let link = std::env::temp_dir().join(format!("sqzdb-settings-link-{}.toml", std::process::id())); let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(crate::config::read_private(&link).unwrap_err().contains("a link isn't followed"));
        assert_eq!(crate::config::read_private(&real).unwrap(), "[app]\n");
        std::fs::remove_file(&link).unwrap(); std::fs::remove_file(&real).unwrap();
    }
    #[test] fn csp_allows_only_the_page_script() { let c = csp(); assert!(c.contains("script-src 'sha256-") && !c.contains("script-src 'unsafe-inline'")); assert!(PAGE.matches("<script>").count() == 1, "the hash covers exactly one inline script"); }
}
