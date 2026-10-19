//! C ABI for language bindings (Go via cgo, Python via PyO3/ctypes, Node via N-API or FFI). Cursor-free: a statement is
//! prepared once, executed with an array of values, and returns a result handle whose cells are read by index.
use crate::sql::{Prepared, Session, Sql};
use crate::table::Value;
use std::ffi::{c_char, c_int, CStr, CString};
use std::sync::Arc;

pub struct Db { sql: Arc<Sql>, err: std::sync::Mutex<CString> }
pub struct Stmt { p: Arc<Prepared> }
pub struct Sess { s: Session, err: CString }
pub struct Rows { rows: Vec<Vec<Value>>, strings: Vec<CString> }

/// A value crossing the boundary: tag 0 NULL, 1 INT (i), 2 DOUBLE (f), 3 TEXT (ptr,len), 4 BYTES (ptr,len), 5 BOOL (i).
#[repr(C)] #[derive(Clone, Copy)] pub struct CValue { pub tag: c_int, pub i: i64, pub f: f64, pub ptr: *const u8, pub len: usize }

fn set_err(db: &Db, e: String) { *db.err.lock().unwrap() = CString::new(e.replace('\0', " ")).unwrap(); }
unsafe fn cstr(p: *const c_char) -> String { if p.is_null() { String::new() } else { unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned() } }
fn to_value(v: &CValue) -> Value { unsafe { match v.tag { 1 => Value::Int(v.i), 2 => Value::Float(v.f), 3 => Value::Text(String::from_utf8_lossy(std::slice::from_raw_parts(v.ptr, v.len)).into_owned()), 4 => Value::Bytes(std::slice::from_raw_parts(v.ptr, v.len).to_vec()), 5 => Value::Bool(v.i != 0), _ => Value::Null } } }

static OPEN_ERR: std::sync::Mutex<Option<CString>> = std::sync::Mutex::new(None);
/// Open (or create) a database directory. `durable` != 0 waits for the disk on every commit. Null on failure.
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_open(path: *const c_char, durable: c_int) -> *mut Db {
    unsafe { sqzdb_open_with(path, if durable != 0 { c"{\"durable\":true}".as_ptr() } else { c"{}".as_ptr() }) }
}
/// Open (or create) with a JSON options document (the keys of `config.rs`: durable, create, backup, follow, snapshot,
/// listen, live, log, and configFile naming a TOML file with the same keys that the options override). Null on failure,
/// see `sqzdb_open_error`.
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_open_with(path: *const c_char, json: *const c_char) -> *mut Db {
    let path = std::path::PathBuf::from(unsafe { cstr(path) }); let json = unsafe { cstr(json) };
    let fail = |e: String| { *OPEN_ERR.lock().unwrap() = Some(CString::new(e.replace('\0', " ")).unwrap()); std::ptr::null_mut() };
    let cfg = match crate::config::Config::load(&path, Some(&json)) { Ok(c) => c, Err(e) => return fail(e) };
    match Sql::open_with(&path, cfg) { Ok(sql) => Box::into_raw(Box::new(Db { sql, err: std::sync::Mutex::new(CString::default()) })), Err(e) => fail(e) }
}
/// Why the last `sqzdb_open` / `sqzdb_open_with` returned null (valid until the next open).
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_open_error() -> *const c_char { let g = OPEN_ERR.lock().unwrap(); g.as_ref().map(|c| c.as_ptr()).unwrap_or(c"".as_ptr()) }
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_close(db: *mut Db) { if !db.is_null() { drop(unsafe { Box::from_raw(db) }); } }
/// The last error message of this database handle (valid until the next call).
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_last_error(db: *mut Db) -> *const c_char { let db = unsafe { &*db }; let g = db.err.lock().unwrap(); g.as_ptr() }
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_session(_db: *mut Db) -> *mut Sess { Box::into_raw(Box::new(Sess { s: Session::default(), err: CString::default() })) }
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_session_free(s: *mut Sess) { if !s.is_null() { drop(unsafe { Box::from_raw(s) }); } }
/// Bind a session to a user (access control). 0 on success.
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_login(db: *mut Db, s: *mut Sess, user: *const c_char) -> c_int { let (db, s) = unsafe { (&*db, &mut *s) }; match db.sql.login(&mut s.s, &unsafe { cstr(user) }) { Ok(()) => 0, Err(e) => { set_err(db, e); 1 } } }
/// Bind a session to an identity the application vouches for (its own login decided who is asking), given as JSON:
/// {"roles": ["customer"], "attrs": {"tenant": 42}}. Row policies read the attributes; no user is stored. 0 on success.
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_assume(db: *mut Db, s: *mut Sess, json: *const c_char) -> c_int { let (db, s) = unsafe { (&*db, &mut *s) }; match db.sql.assume_json(&mut s.s, &unsafe { cstr(json) }) { Ok(()) => 0, Err(e) => { set_err(db, e); 1 } } }
/// Prepare a statement; null on error (see sqzdb_last_error).
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_prepare(db: *mut Db, sql: *const c_char) -> *mut Stmt { let db = unsafe { &*db }; match db.sql.prepare(&unsafe { cstr(sql) }) { Ok(p) => Box::into_raw(Box::new(Stmt { p })), Err(e) => { set_err(db, e); std::ptr::null_mut() } } }
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_finalize(st: *mut Stmt) { if !st.is_null() { drop(unsafe { Box::from_raw(st) }); } }
/// Execute a prepared statement with `n` parameters. Returns a result handle (possibly with zero rows) or null on error.
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_exec(db: *mut Db, s: *mut Sess, st: *mut Stmt, params: *const CValue, n: c_int) -> *mut Rows {
    let (db, s, st) = unsafe { (&*db, &mut *s, &*st) };
    let params: Vec<Value> = if n > 0 { unsafe { std::slice::from_raw_parts(params, n as usize) }.iter().map(to_value).collect() } else { vec![] };
    match db.sql.execute_s(&mut s.s, &st.p, &params) { Ok(rows) => Box::into_raw(Box::new(Rows { rows, strings: vec![] })), Err(e) => { set_err(db, e.clone()); s.err = CString::new(e.replace('\0', " ")).unwrap(); std::ptr::null_mut() } }
}
/// Execute SQL text directly (admin statements, DDL, one-off queries).
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_exec_text(db: *mut Db, s: *mut Sess, sql: *const c_char, params: *const CValue, n: c_int) -> *mut Rows {
    let (db, s) = unsafe { (&*db, &mut *s) };
    let params: Vec<Value> = if n > 0 { unsafe { std::slice::from_raw_parts(params, n as usize) }.iter().map(to_value).collect() } else { vec![] };
    match db.sql.exec_s(&mut s.s, &unsafe { cstr(sql) }, &params) { Ok(rows) => Box::into_raw(Box::new(Rows { rows, strings: vec![] })), Err(e) => { set_err(db, e); std::ptr::null_mut() } }
}
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_rows_count(r: *mut Rows) -> c_int { unsafe { &*r }.rows.len() as c_int }
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_rows_cols(r: *mut Rows) -> c_int { let r = unsafe { &*r }; r.rows.first().map(|x| x.len()).unwrap_or(0) as c_int }
/// Read one cell. TEXT/BYTES pointers stay valid until the result is freed.
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_rows_get(r: *mut Rows, row: c_int, col: c_int, out: *mut CValue) -> c_int {
    let r = unsafe { &mut *r }; let Some(v) = r.rows.get(row as usize).and_then(|x| x.get(col as usize)) else { return 1 };
    let o = unsafe { &mut *out }; *o = CValue { tag: 0, i: 0, f: 0.0, ptr: std::ptr::null(), len: 0 };
    match v { Value::Null => {}, Value::Int(i) => { o.tag = 1; o.i = *i; } Value::Float(f) => { o.tag = 2; o.f = *f; } Value::Bool(b) => { o.tag = 5; o.i = *b as i64; } Value::Text(s) => { o.tag = 3; o.ptr = s.as_ptr(); o.len = s.len(); } Value::Bytes(b) => { o.tag = 4; o.ptr = b.as_ptr(); o.len = b.len(); } }
    0
}
/// Read every cell at once into `out` (row-major, rows*cols entries; the caller sizes it from count*cols). Returns the number written.
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_rows_all(r: *mut Rows, out: *mut CValue, cap: c_int) -> c_int {
    let r = unsafe { &mut *r }; let cols = r.rows.first().map(|x| x.len()).unwrap_or(0); let total = r.rows.len() * cols; if total > cap as usize { return -1; }
    let out = unsafe { std::slice::from_raw_parts_mut(out, total) }; let mut k = 0;
    for row in &r.rows { for v in row { let o = &mut out[k]; *o = CValue { tag: 0, i: 0, f: 0.0, ptr: std::ptr::null(), len: 0 }; match v { Value::Null => {}, Value::Int(i) => { o.tag = 1; o.i = *i; } Value::Float(f) => { o.tag = 2; o.f = *f; } Value::Bool(b) => { o.tag = 5; o.i = *b as i64; } Value::Text(s) => { o.tag = 3; o.ptr = s.as_ptr(); o.len = s.len(); } Value::Bytes(b) => { o.tag = 4; o.ptr = b.as_ptr(); o.len = b.len(); } } k += 1; } }
    total as c_int
}
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_rows_free(r: *mut Rows) { if !r.is_null() { drop(unsafe { Box::from_raw(r) }); } }
pub struct Sub { s: crate::live::Subscription }
/// Subscribe to the changes a single-table SELECT would see (its WHERE is the filter; the session's row policies apply).
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_subscribe(db: *mut Db, s: *mut Sess, sql: *const c_char, params: *const CValue, n: c_int) -> *mut Sub {
    let (db, s) = unsafe { (&*db, &*s) };
    let params: Vec<Value> = if n > 0 { unsafe { std::slice::from_raw_parts(params, n as usize) }.iter().map(to_value).collect() } else { vec![] };
    match db.sql.reactor().subscribe(&s.s, &unsafe { cstr(sql) }, &params) { Ok(sub) => Box::into_raw(Box::new(Sub { s: sub })), Err(e) => { set_err(db, e); std::ptr::null_mut() } }
}
/// Wait up to `timeout_ms` for the next event. Returns 0 and a one-row result [op (1 insert, 2 update, 3 delete), table, key, columns...],
/// 1 on timeout (no result), 2 when the subscription was dropped for falling behind (resubscribe).
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_sub_next(sub: *mut Sub, timeout_ms: c_int, out: *mut *mut Rows) -> c_int {
    let sub = unsafe { &*sub };
    match sub.s.recv_timeout(std::time::Duration::from_millis(timeout_ms.max(0) as u64)) {
        Some(crate::live::Event::Change(c)) => { let mut row = vec![Value::Int(match c.op { crate::sql::ChangeOp::Insert => 1, crate::sql::ChangeOp::Update => 2, crate::sql::ChangeOp::Delete => 3 }), Value::Text(c.table.clone()), c.pk.clone()]; if let Some(r) = &c.row { row.extend(r.iter().cloned()); } unsafe { *out = Box::into_raw(Box::new(Rows { rows: vec![row], strings: vec![] })); } 0 }
        Some(crate::live::Event::Overflow { .. }) => 2,
        Some(crate::live::Event::Live { .. }) => 1,
        None => 1,
    }
}
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_sub_free(sub: *mut Sub) { if !sub.is_null() { drop(unsafe { Box::from_raw(sub) }); } }
/// Take a snapshot (compaction + fast restart). Returns the number of rows written.
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_snapshot(db: *mut Db) -> i64 { unsafe { &*db }.sql.snapshot().rows as i64 }

/// Primary key of the last row this session inserted (an automatic id, or the one given); 0 before any insert.
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_last_insert_id(s: *mut Sess) -> i64 { if s.is_null() { 0 } else { unsafe { &*s }.s.last_insert_id } }

// ---------- sign-in (see auth.rs); structured values cross as JSON ----------
fn json_value(v: &serde_json::Value) -> Result<Value, String> {
    Ok(match v { serde_json::Value::Null => Value::Null, serde_json::Value::Bool(b) => Value::Bool(*b), serde_json::Value::String(s) => Value::Text(s.clone()),
        serde_json::Value::Number(n) => match n.as_i64() { Some(i) => Value::Int(i), None => Value::Float(n.as_f64().unwrap_or(f64::NAN)) }, _ => return Err("values are numbers, text, true/false or null".into()) })
}
fn signed_in_json(si: crate::auth::SignedIn) -> *mut c_char {
    let user: serde_json::Map<String, serde_json::Value> = si.user.into_iter().map(|(k, v)| (k, match v { Value::Null => serde_json::Value::Null, Value::Int(i) => i.into(), Value::Float(f) => serde_json::Number::from_f64(f).map(serde_json::Value::Number).unwrap_or(serde_json::Value::Null), Value::Bool(b) => b.into(), Value::Text(s) => s.into(), Value::Bytes(b) => b.iter().map(|x| format!("{x:02x}")).collect::<String>().into() })).collect();
    CString::new(serde_json::json!({ "token": si.token, "user": user, "created": si.created }).to_string()).unwrap().into_raw()
}
fn auth_result(db: &Db, r: Result<crate::auth::SignedIn, String>) -> *mut c_char { match r { Ok(si) => signed_in_json(si), Err(e) => { set_err(db, e); std::ptr::null_mut() } } }
fn auth_status(db: &Db, r: Result<(), String>) -> c_int { match r { Ok(()) => 0, Err(e) => { set_err(db, e); 1 } } }
/// Insert a user (`fields`: a JSON object that includes the login column) and set the password. Returns a JSON string
/// `{"token": …, "user": {…}}` to free with sqzdb_free_string, or null on error (see sqzdb_last_error).
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_sign_up(db: *mut Db, table: *const c_char, fields: *const c_char, password: *const c_char) -> *mut c_char {
    let db = unsafe { &*db };
    let f = (|| -> Result<Vec<(String, Value)>, String> { match serde_json::from_str::<serde_json::Value>(&unsafe { cstr(fields) }).map_err(|e| format!("fields: {e}"))? { serde_json::Value::Object(m) => m.iter().map(|(k, v)| Ok((k.clone(), json_value(v)?))).collect(), _ => Err("fields: a JSON object".into()) } })();
    auth_result(db, f.and_then(|f| db.sql.sign_up(&unsafe { cstr(table) }, &f, &unsafe { cstr(password) })))
}
/// Check a login and password; the result is as for sqzdb_sign_up.
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_sign_in(db: *mut Db, table: *const c_char, login: *const c_char, password: *const c_char) -> *mut c_char {
    let db = unsafe { &*db }; auth_result(db, db.sql.sign_in(&unsafe { cstr(table) }, &unsafe { cstr(login) }, &unsafe { cstr(password) }))
}
/// End one session (0); an unknown token is not an error.
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_sign_out(db: *mut Db, token: *const c_char) -> c_int { let db = unsafe { &*db }; auth_status(db, db.sql.sign_out(&unsafe { cstr(token) })) }
/// Set a user's password by primary key (`key`: a JSON number or string) and end their sessions.
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_set_password(db: *mut Db, table: *const c_char, key: *const c_char, password: *const c_char) -> c_int {
    let db = unsafe { &*db };
    let k = serde_json::from_str::<serde_json::Value>(&unsafe { cstr(key) }).map_err(|e| format!("key: {e}")).and_then(|v| json_value(&v));
    auth_status(db, k.and_then(|k| db.sql.set_password(&unsafe { cstr(table) }, &k, &unsafe { cstr(password) })))
}
/// End every session of a user (`key` as for sqzdb_set_password).
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_sign_out_everywhere(db: *mut Db, table: *const c_char, key: *const c_char) -> c_int {
    let db = unsafe { &*db };
    let k = serde_json::from_str::<serde_json::Value>(&unsafe { cstr(key) }).map_err(|e| format!("key: {e}")).and_then(|v| json_value(&v));
    auth_status(db, k.and_then(|k| db.sql.sign_out_everywhere(&unsafe { cstr(table) }, &k)))
}
/// Make the session act as the user a token belongs to (0), or 1 (see sqzdb_last_error).
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_use_token(db: *mut Db, s: *mut Sess, token: *const c_char) -> c_int { let (db, s) = unsafe { (&*db, &mut *s) }; auth_status(db, db.sql.session_from_token(&mut s.s, &unsafe { cstr(token) })) }
/// Begin a sign-in with an OAuth provider; `link` is a session token or null. Returns a JSON string `{"url": …,
/// "state": …, "cookie": …}` to free with sqzdb_free_string, or null on error. Keep `cookie` in an HttpOnly
/// cookie of the browser and pass it to sqzdb_oauth_finish.
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_oauth_start(db: *mut Db, table: *const c_char, provider: *const c_char, redirect: *const c_char, link: *const c_char) -> *mut c_char {
    let db = unsafe { &*db }; let l = if link.is_null() { None } else { Some(unsafe { cstr(link) }) };
    match db.sql.oauth_start(&unsafe { cstr(table) }, &unsafe { cstr(provider) }, &unsafe { cstr(redirect) }, l.as_deref().filter(|s| !s.is_empty())) {
        Ok(st) => CString::new(serde_json::json!({ "url": st.url, "state": st.state, "cookie": st.cookie }).to_string()).unwrap().into_raw(), Err(e) => { set_err(db, e); std::ptr::null_mut() } }
}
/// Finish it with the code and state from the provider's redirect; the result is as for sqzdb_sign_up.
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_oauth_finish(db: *mut Db, table: *const c_char, provider: *const c_char, code: *const c_char, state: *const c_char, cookie: *const c_char) -> *mut c_char {
    let db = unsafe { &*db }; auth_result(db, db.sql.oauth_finish(&unsafe { cstr(table) }, &unsafe { cstr(provider) }, &unsafe { cstr(code) }, &unsafe { cstr(state) }, &unsafe { cstr(cookie) }))
}
/// Free a string this library returned.
#[unsafe(no_mangle)] pub unsafe extern "C" fn sqzdb_free_string(p: *mut c_char) { if !p.is_null() { drop(unsafe { CString::from_raw(p) }); } }
