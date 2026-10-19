//! Functions: an application's own server-side code, in TypeScript or JavaScript, run inside the database. A folder
//! of modules (`[functions] dir`, or `DEPLOY FUNCTIONS` from the application) is checked, stored in the catalog (so it
//! is logged, snapshotted, backed up and replicated with the schema) and loaded into QuickJS. Each export made with
//! `fn()` from 'sqzdb/functions' is a function clients call by name: the app API (`POST /api/fn/<name>`), its socket,
//! MCP (one tool each) and the bindings (`db.call`).
//!
//!   import { fn } from 'sqzdb/functions'
//!   export const reportRun = fn({
//!     description: 'Report how a run ended',
//!     args: { runId: 'int', status: ['completed', 'failed'], outcome: 'text?' },
//!     roles: ['agent'],
//!     run({ db, admin, user }, { runId, status, outcome }) { … },
//!   })
//!
//! A call checks the arguments against `args`, then runs `run` in one transaction: it commits when `run` returns, rolls
//! back when it throws, and runs again from the start when another writer got there first. `db` acts as the caller,
//! under their grants and row policies; `admin` is the same transaction without them, for rules a caller must not get
//! around (they may not write the table themselves, only through the function). Who may call: `roles`, or anyone
//! signed in when it lists none (the anonymous role only when listed).
//!
//! The sandbox: no files, network, timers or processes; a time limit (`functions.timeout`) and a memory limit
//! (`functions.memory`) per call, and at most `functions.instances` calls at once. A statement that fails while
//! writing ends the call's transaction (it may have written some of its rows): a function can catch the error to
//! change it, not to carry on.
use crate::sql::{error_code, is_admin_stmt, ColKind, Plan, Prepared, Session, Sql};
use crate::table::{ColType, Value};
use rquickjs::function::{Opt, This};
use rquickjs::loader::{ImportAttributes, Loader, Resolver};
use rquickjs::{CatchResultExt, CaughtError, Context, Ctx, Exception, Function, Module, Object, Persistent, Runtime, Value as Js};
use serde_json::{json, Value as J};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant, SystemTime};

/// The catalog statement that holds a deploy: this prefix, then `{"files": {path: source}}`. A deploy replaces the one
/// before it, in the catalog too (`Sql::log_meta_replacing`).
pub const FUNCTIONS_META: &str = "DEPLOY FUNCTIONS ";
/// The SQL tools MCP gives agents: no function takes their names.
const RESERVED: [&str; 3] = ["describe", "query", "execute"];
const MAX_FILES: usize = 1000;
const MAX_SOURCE: usize = 8 << 20;
const BUILTIN: &str = "sqzdb/functions";
const ENTRY: &str = "__sqzdb_entry__.js";
/// A call that keeps losing to other writers gives up after this many runs.
const RETRIES: u32 = 50;
/// Loading a deploy's modules (their top-level code) may take this long.
const LOAD_TIME: Duration = Duration::from_secs(5);

const BUILTIN_SOURCE: &str = r#"const MARK = Symbol.for('sqzdb.function');
const mark = (def, kind) => {
  if (def === null || typeof def !== 'object' || typeof def.run !== 'function') throw new TypeError(`${kind === 'function' ? 'fn' : kind}() takes an object with run(ctx, …) { … }`);
  return Object.freeze({ ...def, [MARK]: kind });
};
export const fn = (def) => mark(def, 'function');
export const middleware = (def) => mark(def, 'middleware');
export const route = (def) => mark(def, 'route');
export const signIn = (req, page = '/_sqz/sign-in') => Response.redirect(`${page}?return=${encodeURIComponent(req.url)}`, 302);
export const Response = globalThis.Response, Headers = globalThis.Headers;
"#;
/// Made once per instance, before any of the deploy's code runs: what the engine needs from JavaScript itself, and
/// `console` (to the server's error output).
const HELPERS: &str = r#"(print, host) => {
  const MARK = Symbol.for('sqzdb.function');
  const hex = (b) => { let s = '0x'; for (const x of b) s += (x < 16 ? '0' : '') + x.toString(16); return s; };
  const replacer = (k, v) => typeof v === 'bigint' ? (Number.isSafeInteger(Number(v)) ? Number(v) : String(v)) : v instanceof Uint8Array ? hex(v) : v instanceof ArrayBuffer ? hex(new Uint8Array(v)) : v;
  const toJson = (v) => { const s = JSON.stringify(v, replacer); return s === undefined ? 'null' : s; };
  const show = (a) => a.map((x) => { if (typeof x === 'string') return x; try { return toJson(x); } catch { return String(x); } }).join(' ');
  globalThis.console = { log: (...a) => print(0, show(a)), info: (...a) => print(0, show(a)), debug: (...a) => print(0, show(a)), warn: (...a) => print(1, show(a)), error: (...a) => print(2, show(a)) };
  // the little of the Fetch API that middleware and routes use (QuickJS has none of it)
  class Headers {
    constructor(init) { this._m = new Map(); if (init) for (const [k, v] of (init instanceof Headers ? [...init.entries()] : Array.isArray(init) ? init : Object.entries(init))) this.append(k, v); }
    get(k) { k = String(k).toLowerCase(); const v = this._m.get(k); return v === undefined ? null : v.join(k === 'cookie' ? '; ' : ', '); }
    getSetCookie() { return [...(this._m.get('set-cookie') ?? [])]; }
    has(k) { return this._m.has(String(k).toLowerCase()); }
    set(k, v) { this._m.set(String(k).toLowerCase(), [String(v)]); }
    append(k, v) { k = String(k).toLowerCase(); const a = this._m.get(k); if (a) a.push(String(v)); else this._m.set(k, [String(v)]); }
    delete(k) { this._m.delete(String(k).toLowerCase()); }
    *entries() { for (const [k, vs] of this._m) for (const v of vs) yield [k, v]; }
    *keys() { for (const [k] of this.entries()) yield k; }
    *values() { for (const [, v] of this.entries()) yield v; }
    forEach(f) { for (const [k, v] of this.entries()) f(v, k, this); }
    [Symbol.iterator]() { return this.entries(); }
  }
  class Response {
    constructor(body = null, init = {}) { this.status = init.status ?? 200; this.statusText = init.statusText ?? ''; this.headers = new Headers(init.headers); this.body = body; }
    get ok() { return this.status >= 200 && this.status < 300; }
    static json(v, init = {}) { const r = new Response(toJson(v), init); if (!r.headers.has('content-type')) r.headers.set('content-type', 'application/json'); return r; }
    static redirect(url, status = 302) { return new Response(null, { status, headers: { location: String(url) } }); }
  }
  globalThis.Headers = Headers; globalThis.Response = Response;
  const dec = (s) => { try { return decodeURIComponent(s.replace(/\+/g, ' ')); } catch { return s; } };
  return {
    kind: (v) => v !== null && typeof v === 'object' && typeof v[MARK] === 'string' ? v[MARK] : null,
    meta: (v) => toJson({ kind: v[MARK], description: v.description, args: v.args, argOrder: v.args !== null && typeof v.args === 'object' ? Object.keys(v.args) : [], roles: v.roles, readOnly: v.readOnly, match: v.match, order: v.order, path: v.path, method: v.method }),
    // a request for middleware or a route: `text` and `bytes` its body (null for middleware, which gets the headers)
    request: (d, text, bytes) => {
      const headers = new Headers(d.headers); const cookies = {}, query = {};
      for (const c of (headers.get('cookie') ?? '').split(';')) { const i = c.indexOf('='); if (i > 0) cookies[c.slice(0, i).trim()] = dec(c.slice(i + 1).trim()); }
      for (const kv of d.query.split('&')) { if (!kv) continue; const i = kv.indexOf('='); query[dec(i < 0 ? kv : kv.slice(0, i))] = i < 0 ? '' : dec(kv.slice(i + 1)); }
      const body = (what) => { if (bytes === null) throw new TypeError(`middleware gets a request's headers, not its body (${what})`); };
      // path: as patterns matched it (decoded, normalized: what a check like startsWith('/admin') must see); url: as sent
      return { method: d.method, path: d.path, rawPath: d.rawPath, url: d.query ? `${d.rawPath}?${d.query}` : d.rawPath, query, params: d.params, headers, cookies, ip: d.ip,
        text: async () => (body('text()'), text ?? ''), json: async () => (body('json()'), JSON.parse(text ?? '')), bytes: async () => (body('bytes()'), bytes) };
    },
    // what a handler returned: a Response; nothing (middleware: go on, with the request's headers as they are now; a
    // route: 204); or a value, as JSON
    reply: (v, req, kind) => {
      if (v instanceof Response) { const b = v.body; return { next: false, status: v.status | 0, headers: [...v.headers.entries()], text: b == null ? null : b instanceof Uint8Array || b instanceof ArrayBuffer ? null : String(b), bytes: b instanceof Uint8Array ? b : b instanceof ArrayBuffer ? new Uint8Array(b) : null }; }
      if (v === undefined || v === null) return kind === 'middleware' ? { next: true, headers: [...req.headers.entries()] } : { next: false, status: 204, headers: [] };
      if (kind === 'middleware') throw new TypeError('middleware returns a Response, or nothing to let the request go on');
      return { next: false, status: 200, headers: [['content-type', 'application/json']], text: toJson(v) };
    },
    toJson,
    same: Object.is,
    // a call's own db and admin: they work during that call only (a function that keeps one gets an error later,
    // never another caller's identity)
    bind: (id) => { const mk = (admin) => Object.freeze({ get: (s, p) => host(id, admin, 0, s, p), all: (s, p) => host(id, admin, 1, s, p), run: (s, p) => host(id, admin, 2, s, p) }); return [mk(false), mk(true)]; },
  };
}"#;

/// An argument's type: one of the names `args` uses ('int', 'number', 'text', 'bool', 'uuid', 'json'), or one of a list
/// of texts.
#[derive(Clone, Debug, PartialEq)] pub enum ArgType { Int, Number, Text, Bool, Uuid, Json, OneOf(Vec<String>) }
impl ArgType {
    fn of(name: &str) -> Option<ArgType> { Some(match name { "int" => ArgType::Int, "number" => ArgType::Number, "text" => ArgType::Text, "bool" => ArgType::Bool, "uuid" => ArgType::Uuid, "json" => ArgType::Json, _ => return None }) }
    fn describe(&self) -> String { match self { ArgType::Int => "a whole number".into(), ArgType::Number => "a number".into(), ArgType::Text => "text".into(), ArgType::Bool => "true or false".into(), ArgType::Uuid => "a UUID".into(), ArgType::Json => "any JSON value".into(), ArgType::OneOf(v) => format!("one of {}", v.iter().map(|s| format!("{s:?}")).collect::<Vec<_>>().join(", ")) } }
    fn schema(&self) -> J { match self { ArgType::Int => json!({"type": "integer"}), ArgType::Number => json!({"type": "number"}), ArgType::Text => json!({"type": "string"}), ArgType::Bool => json!({"type": "boolean"}), ArgType::Uuid => json!({"type": "string", "format": "uuid"}), ArgType::Json => json!({}), ArgType::OneOf(v) => json!({"type": "string", "enum": v}) } }
}
#[derive(Clone, Debug)] pub struct Arg { pub name: String, pub ty: ArgType, pub optional: bool, pub description: Option<String> }
/// A function as deployed: what callers see of it.
#[derive(Clone, Debug)] pub struct Def { pub name: String, pub file: String, pub description: Option<String>, pub args: Vec<Arg>, pub roles: Option<Vec<String>>, pub read_only: bool, pub kind: Kind }
/// What an export is: a function clients call by name (`fn`), middleware that runs before requests to the paths it
/// matches go on (in `order`, then by file and name), or a route that answers requests itself (`route`).
#[derive(Clone, Debug, PartialEq)] pub enum Kind { Function, Middleware { matches: Vec<Pattern>, order: i64 }, Route { methods: Vec<String>, pattern: Pattern } }
/// A path pattern: literal segments, `:name` (one segment, as `req.params.name`), and a final `*` (any rest, or none:
/// `/admin/*` matches `/admin` too), compared with a request's path segment by segment, each decoded (`match_path`).
#[derive(Clone, Debug, PartialEq)] pub struct Pattern { segs: Vec<Seg>, rest: bool, pub text: String }
#[derive(Clone, Debug, PartialEq)] enum Seg { Lit(String), Param(String) }
impl Pattern {
    pub fn parse(p: &str) -> Result<Pattern, String> {
        if p == "*" { return Ok(Pattern { segs: vec![], rest: true, text: "*".into() }); }   // every path
        if !p.starts_with('/') { return Err(format!("{p:?}: a path starts with / (or is *, every path)")); }
        let parts: Vec<&str> = p.split('/').filter(|s| !s.is_empty()).collect();
        let (mut segs, mut rest) = (vec![], false);
        for (i, s) in parts.iter().enumerate() {
            if *s == "*" { if i + 1 != parts.len() { return Err(format!("{p:?}: * comes last")); } rest = true; }
            else if let Some(n) = s.strip_prefix(':') { if !valid_name(n) { return Err(format!("{p:?}: a parameter is :name, letters, digits and _")); } segs.push(Seg::Param(n.into())); }
            else if s.contains(['*', ':', '?', '#', '%', '\\']) || *s == "." || *s == ".." { return Err(format!("{p:?}: {s:?} is not a path segment")); }
            else { segs.push(Seg::Lit(s.to_string())); }
        }
        Ok(Pattern { segs, rest, text: p.into() })
    }
    /// The parameters, when `path` (from `match_path`) matches; `*` holds the rest.
    pub fn matches(&self, path: &str) -> Option<Vec<(String, String)>> {
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if parts.len() < self.segs.len() || (!self.rest && parts.len() != self.segs.len()) { return None; }
        let mut params = vec![];
        for (s, p) in self.segs.iter().zip(&parts) { match s { Seg::Lit(l) => if l != p { return None; }, Seg::Param(n) => params.push((n.clone(), p.to_string())) } }
        if self.rest { params.push(("*".into(), parts[self.segs.len()..].join("/"))); }
        Some(params)
    }
    /// Among routes that match one path: more literal segments first, then more parameters, then without `*`.
    fn rank(&self) -> (usize, usize, bool) { (self.segs.iter().filter(|s| matches!(s, Seg::Lit(_))).count(), self.segs.len(), !self.rest) }
}
/// The path middleware and routes match: each segment percent-decoded, empty ones dropped, and Next.js's data route for
/// a page (`/_next/data/<build>/<page>.json`) as that page. None: a path no browser sends (`.` or `..`, an encoded `/`
/// or `\`), refused rather than matched one way here and resolved another way behind.
pub fn match_path(raw: &str) -> Option<String> {
    let mut segs = vec![];
    for s in raw.split('/').filter(|s| !s.is_empty()) {
        let low = s.to_ascii_lowercase();
        if s.contains('\\') || low.contains("%2f") || low.contains("%5c") || low.contains("%00") { return None; }
        let d = pct_decode(s)?;
        if d == "." || d == ".." { return None; }
        segs.push(d);
    }
    if segs.len() >= 4 && segs[0] == "_next" && segs[1] == "data" { if let Some(last) = segs.last_mut().and_then(|l| l.strip_suffix(".json").map(String::from)) { let page: Vec<String> = segs[3..segs.len() - 1].iter().cloned().chain((last != "index").then_some(last)).collect(); return Some(format!("/{}", page.join("/"))); } }
    Some(format!("/{}", segs.join("/")))
}
fn pct_decode(s: &str) -> Option<String> {
    let b = s.as_bytes(); let mut out = Vec::with_capacity(b.len()); let mut i = 0;
    while i < b.len() { if b[i] == b'%' { let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?; out.push(u8::from_str_radix(h, 16).ok()?); i += 3; } else { out.push(b[i]); i += 1; } }
    String::from_utf8(out).ok()
}
/// A request for middleware or a route: `path` as patterns match it (`match_path`: decoded, normalized), `raw_path` as
/// sent, `params` from the pattern, `body` (a route's; None for middleware).
#[derive(Clone, Debug, Default)] pub struct HttpReq { pub method: String, pub path: String, pub raw_path: String, pub query: String, pub headers: Vec<(String, String)>, pub ip: String, pub params: Vec<(String, String)>, pub body: Option<Vec<u8>> }
/// What middleware or a route decided: go on (with the request's headers as the handler left them), or this response.
#[derive(Clone, Debug)] pub enum HttpOut { Next(Vec<(String, String)>), Respond { status: u16, headers: Vec<(String, String)>, body: Vec<u8> } }
enum Input<'a> { Args(&'a J), Http(&'a HttpReq, &'static str) }
enum Output { Json(J), Http(HttpOut) }
/// Why a call failed: NOT_FOUND, DENIED, ARGUMENTS, LIMIT (time or memory), CONFLICT (still losing to other writers),
/// FUNCTION (the function threw), the code of a database error the function let through, or the `code` its error set.
#[derive(Clone, Debug, PartialEq)] pub struct FnError { pub code: String, pub message: String }
impl FnError { pub fn new(code: &str, message: impl Into<String>) -> FnError { FnError { code: code.into(), message: message.into() } } }
impl std::fmt::Display for FnError { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(&self.message) } }
/// What a deploy left: the functions now deployed, and whether anything changed.
#[derive(Clone, Debug)] pub struct Deployed { pub functions: Vec<String>, pub changed: bool }

/// A deploy, compiled: each file's JavaScript (TypeScript with its types gone, and a map back to its lines), and the
/// functions. `version` tells instances made from an older deploy apart.
struct Bundle { version: u64, hash: String, names: Vec<String>, js: Arc<HashMap<String, String>>, maps: HashMap<String, oxc_sourcemap::SourceMap<'static>>, defs: Vec<Def>, middleware: Vec<usize>, routes: Vec<usize> }
/// Per database: the deploy in use (or why the one in the catalog failed to load), and the instances not in use.
/// `pending`: the latest deploy read back from the catalog, compiled when first needed (a restart replays every deploy
/// still in the log; only the last one is ever loaded).
#[derive(Default)] pub struct FunctionsState { bundle: RwLock<Option<Arc<Bundle>>>, broken: RwLock<Option<String>>, pending: Mutex<Option<String>>, pool: Mutex<Pool>, freed: Condvar, versions: AtomicU64, deploying: Mutex<()> }
#[derive(Default)] struct Pool { idle: Vec<Instance>, live: usize }
/// A QuickJS runtime with a deploy loaded, used by one call at a time. Its JavaScript handles drop before the context
/// and the runtime they live in (fields drop in order).
struct Instance { slots: Slots, ctx: Context, rt: Runtime, version: u64, deadline: Arc<AtomicU64> }
struct Slots { registry: Persistent<Object<'static>>, helpers: Persistent<Object<'static>> }
// The runtime, its context and the handles into it move between threads together, and only whole: the pool gives an
// instance to one call at a time, and QuickJS takes the stack of whichever thread enters it (`Context::with`).
unsafe impl Send for Instance {}
struct Limits { timeout: Duration, memory: usize }

fn now_ns() -> u64 { static BASE: OnceLock<Instant> = OnceLock::new(); BASE.get_or_init(Instant::now).elapsed().as_nanos() as u64 + 1 }

// ---------- the call in progress, for the `db` and `admin` objects (QuickJS runs on the caller's thread) ----------
struct Call { id: u64, sql: *const Sql, sess: *mut Session, read_only: bool, name: String, failed: Option<FnError>, conflicted: bool, memory: usize }
static CALL_IDS: AtomicU64 = AtomicU64::new(1);
thread_local! { static CALL: std::cell::Cell<*mut Call> = const { std::cell::Cell::new(std::ptr::null_mut()) }; }
/// Makes `call` the one `db` and `admin` act for until dropped.
struct Running(*mut Call);
impl Running { fn start(call: &mut Call) -> Running { let p = call as *mut Call; let prev = CALL.with(|c| c.replace(p)); Running(prev) } }
impl Drop for Running { fn drop(&mut self) { CALL.with(|c| c.set(self.0)); } }

/// `admin`: the session's transaction without its identity (no grants, no policies), given back however `f` ends.
struct Unmasked<'a> { sess: &'a mut Session, saved: Option<(Option<String>, Vec<String>, HashMap<String, Value>, Option<(String, u64)>, bool)> }
impl<'a> Unmasked<'a> {
    fn new(sess: &'a mut Session) -> Unmasked<'a> { let saved = (sess.user.take(), std::mem::take(&mut sess.roles), std::mem::take(&mut sess.attrs), sess.token.take(), std::mem::replace(&mut sess.assumed, false)); Unmasked { sess, saved: Some(saved) } }
}
impl Drop for Unmasked<'_> { fn drop(&mut self) { if let Some((u, r, a, t, s)) = self.saved.take() { self.sess.user = u; self.sess.roles = r; self.sess.attrs = a; self.sess.token = t; self.sess.assumed = s; } } }

fn throw(ctx: &Ctx<'_>, code: &str, msg: impl AsRef<str>) -> rquickjs::Error {
    match Exception::from_message(ctx.clone(), msg.as_ref()) { Ok(e) => { let _ = e.set("code", code); e.throw() } Err(e) => e }
}
/// A statement a function may run: SELECT, INSERT, UPDATE or DELETE (only SELECT in a read-only function).
fn statement(sql: &Sql, text: &str, read_only: bool) -> Result<Arc<Prepared>, FnError> {
    let text = text.trim().trim_end_matches(';');
    let refuse = || FnError::new("DENIED", "permission denied: functions run SELECT, INSERT, UPDATE and DELETE (the call is the transaction)");
    if is_admin_stmt(text) { return Err(refuse()); }
    let p = sql.prepare(text).map_err(|e| FnError::new(error_code(&e), e))?;
    match p.plan {
        Plan::Select(_) | Plan::Const { .. } => Ok(p),
        Plan::Insert { .. } | Plan::Update { .. } | Plan::Delete { .. } if !read_only => Ok(p),
        Plan::Insert { .. } | Plan::Update { .. } | Plan::Delete { .. } => Err(FnError::new("DENIED", "permission denied: a readOnly function runs SELECT only")),
        _ => Err(refuse()),
    }
}
/// `db.get`, `db.all` and `db.run` (`mode` 0, 1, 2), and the same on `admin`, for the call `id` made them for.
fn host<'js>(ctx: Ctx<'js>, id: f64, admin: bool, mode: i32, text: Js<'js>, params: Opt<Js<'js>>) -> rquickjs::Result<Js<'js>> {
    let ptr = CALL.with(|c| c.get());
    if ptr.is_null() { return Err(throw(&ctx, "ARGUMENTS", "db and admin work while a function runs, not when its module loads")); }
    let call = unsafe { &mut *ptr };
    if call.id as f64 != id { return Err(throw(&ctx, "ARGUMENTS", "this db is from an earlier call: db and admin work only during the call that received them")); }
    let params = params.0;
    let Some(text) = text.as_string().and_then(|s| s.to_string().ok()) else { return Err(throw(&ctx, "ARGUMENTS", "the first argument is the SQL text")) };
    if let Some(f) = &call.failed { return Err(throw(&ctx, &f.code, format!("this call's transaction already failed: {}", f.message))); }
    let params = params_of(&ctx, params)?;
    let sql = unsafe { &*call.sql }; let sess = unsafe { &mut *call.sess };
    let p = match statement(sql, &text, call.read_only) { Ok(p) => p, Err(e) => return Err(throw(&ctx, &e.code, e.message)) };
    let write = matches!(p.plan, Plan::Insert { .. } | Plan::Update { .. } | Plan::Delete { .. });
    let r = if admin { let u = Unmasked::new(sess); sql.execute_s(u.sess, &p, &params) } else { sql.execute_s(sess, &p, &params) };
    let rows = match r {
        Ok(rows) => rows,
        Err(e) => {
            let code = error_code(&e);
            // a write may have done part of its rows before failing: the transaction can't commit (a missing row did nothing)
            if code == "CONFLICT" { call.conflicted = true; }
            if code == "CONFLICT" || (write && code != "NOT_FOUND") { call.failed = Some(FnError::new(code, e.clone())); }
            return Err(throw(&ctx, code, e));
        }
    };
    if mode == 2 {
        let changes = match &p.plan {
            Plan::Insert { returning: Some(_), .. } | Plan::Update { returning: Some(_), .. } => rows.len() as i64,
            Plan::Insert { .. } | Plan::Update { .. } | Plan::Delete { .. } => rows.first().and_then(|r| r.first()).and_then(|v| if let Value::Int(n) = v { Some(*n) } else { None }).unwrap_or(0),
            _ => 0,
        };
        let o = Object::new(ctx.clone())?; o.set("changes", changes as f64)?;
        if matches!(p.plan, Plan::Insert { .. }) { if let Some(k) = &sess.last_insert_key { o.set("lastInsertId", to_js(&ctx, k, None, ColKind::Plain)?)?; } }
        return Ok(o.into_value());
    }
    // the rows are made outside QuickJS's memory limit: they may not be larger than it either
    let size: usize = rows.iter().map(|r| r.iter().map(|v| 16 + match v { Value::Text(t) => t.len(), Value::Bytes(b) => b.len(), _ => 0 }).sum::<usize>()).sum();
    if size > call.memory { return Err(throw(&ctx, "LIMIT", format!("the rows are larger than {} MB (functions.memory): add a LIMIT", call.memory >> 20))); }
    let (cols, kinds) = (sql.columns(&p), sql.column_kinds(&p));
    // each column's name made once for the statement, not once per row
    let width = rows.first().map(|r| r.len()).unwrap_or(0).max(cols.len());
    let names: Vec<rquickjs::Atom> = (0..width).map(|i| rquickjs::Atom::from_str(ctx.clone(), cols.get(i).map(|c| c.0.as_str()).unwrap_or(&format!("col{i}")))).collect::<rquickjs::Result<_>>()?;
    let row = |r: &[Value]| -> rquickjs::Result<Js<'js>> {
        let o = Object::new(ctx.clone())?;
        for (i, v) in r.iter().enumerate() { o.set(names[i].clone(), to_js(&ctx, v, cols.get(i).and_then(|c| c.1.as_ref()), kinds.get(i).copied().unwrap_or(ColKind::Plain))?)?; }
        Ok(o.into_value())
    };
    if mode == 0 { return match rows.first() { Some(r) => row(r), None => Ok(Js::new_null(ctx.clone())) }; }
    let a = rquickjs::Array::new(ctx.clone())?;
    for (i, r) in rows.iter().enumerate() { a.set(i, row(r)?)?; }
    Ok(a.into_value())
}
/// A value from the database as JavaScript sees it, as in the Node binding: INT a number (BigInt past 2^53), TIMESTAMP
/// a Date, BYTES a Uint8Array, a VECTOR an array of numbers, a FILE its id.
fn to_js<'js>(ctx: &Ctx<'js>, v: &Value, ty: Option<&ColType>, kind: ColKind) -> rquickjs::Result<Js<'js>> {
    Ok(match v {
        Value::Null => Js::new_null(ctx.clone()),
        Value::Bool(b) => Js::new_bool(ctx.clone(), *b),
        Value::Int(i) if matches!(ty, Some(ColType::Timestamp)) => { let date: rquickjs::Constructor = ctx.globals().get("Date")?; date.construct::<_, Js>((*i as f64 / 1000.0,))? }
        Value::Int(i) if i.unsigned_abs() <= 1 << 53 => Js::new_number(ctx.clone(), *i as f64),
        Value::Int(i) => rquickjs::BigInt::from_i64(ctx.clone(), *i)?.into_value(),
        Value::Float(f) => Js::new_float(ctx.clone(), *f),
        Value::Text(s) => rquickjs::String::from_str(ctx.clone(), s)?.into_value(),
        Value::Bytes(b) if kind == ColKind::Vector => { let a = rquickjs::Array::new(ctx.clone())?; for (i, f) in crate::table::vector_floats(b).enumerate() { a.set(i, f as f64)?; } a.into_value() }
        Value::Bytes(b) => rquickjs::TypedArray::<u8>::new_copy(ctx.clone(), b)?.into_value(),
    })
}
/// Parameters as the Node binding takes them: an array, one value, or nothing. Numbers that are whole become INT, a
/// Date a TIMESTAMP, a Uint8Array or ArrayBuffer BYTES, other objects and arrays their JSON text.
fn params_of<'js>(ctx: &Ctx<'js>, p: Option<Js<'js>>) -> rquickjs::Result<Vec<Value>> {
    let Some(p) = p.filter(|v| !v.is_undefined()) else { return Ok(vec![]) };
    let list: Vec<Js> = match p.as_array() { Some(a) => a.iter().collect::<rquickjs::Result<_>>()?, None => vec![p] };
    list.into_iter().map(|v| from_js(ctx, v)).collect()
}
fn from_js<'js>(ctx: &Ctx<'js>, v: Js<'js>) -> rquickjs::Result<Value> {
    use rquickjs::Type;
    Ok(match v.type_of() {
        Type::Undefined | Type::Null | Type::Uninitialized => Value::Null,
        Type::Bool => Value::Bool(v.as_bool().unwrap_or(false)),
        Type::Int => Value::Int(v.as_int().unwrap_or(0) as i64),
        Type::Float => { let f = v.as_float().unwrap_or(f64::NAN); if f.fract() == 0.0 && f.abs() <= 9007199254740992.0 { Value::Int(f as i64) } else { Value::Float(f) } }
        Type::String => Value::Text(v.as_string().map(|s| s.to_string()).transpose()?.unwrap_or_default()),
        Type::BigInt => Value::Int(v.into_big_int().map(|b| b.to_i64()).transpose()?.unwrap_or(0)),
        _ => {
            let Some(o) = v.as_object() else { return Err(throw(ctx, "TYPE", "unsupported parameter: pass a number, string, boolean, BigInt, Date, Uint8Array, null, or an object or array (as JSON)")) };
            let date: Object = ctx.globals().get("Date")?;
            if o.is_instance_of(&date) { let ms: f64 = o.get::<_, Function>("getTime")?.call((This(o.clone()),))?; return Ok(Value::Int((ms * 1000.0).round() as i64)); }
            // (as_bytes borrows the array's memory: copied at once, before any JavaScript can resize or detach it)
            if let Some(t) = rquickjs::TypedArray::<u8>::from_object(o.clone()).ok() { return Ok(Value::Bytes(unsafe { t.as_bytes() }.map(|b| b.to_vec()).unwrap_or_default())); }
            if let Some(b) = rquickjs::ArrayBuffer::from_object(o.clone()) { return Ok(Value::Bytes(unsafe { b.as_bytes() }.map(|b| b.to_vec()).unwrap_or_default())); }
            match ctx.json_stringify(v.clone())? { Some(s) => Value::Text(s.to_string()?), None => return Err(throw(ctx, "TYPE", "unsupported parameter: a function or symbol")) }
        }
    })
}
/// A function's result as JSON, as JSON.stringify makes it (toJSON where an object has one, so a Date is its ISO text;
/// functions and undefined left out of objects, null in arrays), and BigInt a number, bytes 0x-prefixed hex.
/// `budget`: the bytes the result may still take (it is built outside QuickJS's memory limit).
fn result_json<'js>(ctx: &Ctx<'js>, v: Js<'js>, depth: usize, budget: &mut usize) -> rquickjs::Result<J> {
    use rquickjs::Type;
    let hex = |b: &[u8]| -> J { J::String(std::iter::once("0x".to_string()).chain(b.iter().map(|x| format!("{x:02x}"))).collect()) };
    if depth > 64 { return Err(throw(ctx, "FUNCTION", "the result nests deeper than 64 levels (is it circular?)")); }
    let spend = |budget: &mut usize, n: usize| -> rquickjs::Result<()> { if *budget < n { return Err(throw(ctx, "LIMIT", "the result is larger than functions.memory")); } *budget -= n; Ok(()) };
    spend(budget, 16)?;
    Ok(match v.type_of() {
        Type::Null | Type::Undefined | Type::Uninitialized | Type::Function | Type::Constructor | Type::Symbol => J::Null,
        Type::Bool => J::Bool(v.as_bool().unwrap_or(false)),
        Type::Int => json!(v.as_int().unwrap_or(0)),
        Type::Float => { let f = v.as_float().unwrap_or(f64::NAN); if f.fract() == 0.0 && f.abs() <= 9007199254740992.0 { json!(f as i64) } else { serde_json::Number::from_f64(f).map(J::Number).unwrap_or(J::Null) } }
        Type::String => { let t = v.as_string().map(|s| s.to_string()).transpose()?.unwrap_or_default(); spend(budget, t.len())?; J::String(t) }
        Type::BigInt => json!(v.into_big_int().map(|b| b.to_i64()).transpose()?.unwrap_or(0)),
        Type::Array => { let a = v.into_array().expect("an array"); let mut out = Vec::with_capacity(a.len().min(1 << 16)); for x in a.iter::<Js>() { out.push(result_json(ctx, x?, depth + 1, budget)?); } J::Array(out) }
        _ => {
            let Some(o) = v.as_object() else { return Ok(J::Null) };
            // (as_bytes borrows the array's memory: copied at once)
            if let Ok(t) = rquickjs::TypedArray::<u8>::from_object(o.clone()) { let b = unsafe { t.as_bytes() }.unwrap_or_default(); spend(budget, b.len() * 2)?; return Ok(hex(b)); }
            if let Some(b) = rquickjs::ArrayBuffer::from_object(o.clone()) { let b = unsafe { b.as_bytes() }.unwrap_or_default(); spend(budget, b.len() * 2)?; return Ok(hex(b)); }
            if let Ok(f) = o.get::<_, Function>("toJSON") { return result_json(ctx, f.call((This(o.clone()),))?, depth + 1, budget); }
            let mut out = serde_json::Map::new();
            for kv in o.props::<String, Js>() {
                let (k, x) = kv?;
                if matches!(x.type_of(), Type::Undefined | Type::Function | Type::Constructor | Type::Symbol) { continue; }
                spend(budget, k.len())?; out.insert(k, result_json(ctx, x, depth + 1, budget)?);
            }
            J::Object(out)
        }
    })
}
fn print(level: i32, text: String) {
    let name = CALL.with(|c| { let p = c.get(); if p.is_null() { String::new() } else { format!(" {}", unsafe { &(*p).name }) } });
    let text: String = text.chars().take(10_000).collect();
    eprintln!("functions{name}{}: {text}", match level { 1 => " (warning)", 2 => " (error)", _ => "" });
}

// ---------- modules: a deploy's files, and the one module the engine provides ----------
#[derive(Clone)] struct Files(Arc<HashMap<String, String>>);
impl Resolver for Files {
    fn resolve<'js>(&mut self, _: &Ctx<'js>, base: &str, name: &str, _: Option<ImportAttributes<'js>>) -> rquickjs::Result<String> {
        if name == BUILTIN { return Ok(name.into()); }
        let refuse = |why: &str| rquickjs::Error::new_resolving_message(base, name, why.to_string());
        if !(name.starts_with("./") || name.starts_with("../")) { return Err(refuse("functions import files of their own folder (./file) and 'sqzdb/functions', no packages: they run in the database's sandbox")); }
        let mut parts: Vec<&str> = base.rsplit_once('/').map(|(d, _)| d.split('/').collect()).unwrap_or_default();
        for p in name.split('/') { match p { "." | "" => {} ".." => { if parts.pop().is_none() { return Err(refuse("outside the functions folder")); } } x => parts.push(x) } }
        let full = parts.join("/");
        let stem = full.strip_suffix(".js").or_else(|| full.strip_suffix(".mjs")).unwrap_or(&full);
        for c in [full.clone(), format!("{full}.ts"), format!("{full}.js"), format!("{full}/index.ts"), format!("{full}/index.js"), format!("{stem}.ts"), format!("{stem}.mts")] { if self.0.contains_key(&c) { return Ok(c); } }
        Err(refuse("no such file in the functions folder"))
    }
}
impl Loader for Files {
    fn load<'js>(&mut self, ctx: &Ctx<'js>, name: &str, _: Option<ImportAttributes<'js>>) -> rquickjs::Result<Module<'js, rquickjs::module::Declared>> {
        if name == BUILTIN { return Module::declare(ctx.clone(), name, BUILTIN_SOURCE); }
        let src = self.0.get(name).ok_or_else(|| rquickjs::Error::new_loading(name))?;
        Module::declare(ctx.clone(), name, src.as_bytes())
    }
}

/// TypeScript without its types (and a map from the JavaScript's lines back to the TypeScript's); JavaScript as it is.
fn strip(path: &str, src: &str) -> Result<(String, Option<oxc_sourcemap::SourceMap<'static>>), String> {
    if !(path.ends_with(".ts") || path.ends_with(".mts")) { return Ok((src.to_string(), None)); }
    use oxc_allocator::Allocator; use oxc_codegen::{Codegen, CodegenOptions}; use oxc_parser::Parser; use oxc_semantic::SemanticBuilder; use oxc_span::SourceType; use oxc_transformer::{TransformOptions, Transformer};
    let at = |d: &oxc_diagnostics::OxcDiagnostic| { let off = d.labels.first().map(|l| l.offset() as usize).unwrap_or(0).min(src.len()); let before = &src[..off]; format!("{path}:{}:{}: {}", before.matches('\n').count() + 1, before.rsplit('\n').next().unwrap_or("").chars().count() + 1, d.message) };
    let alloc = Allocator::default();
    let ret = Parser::new(&alloc, src, SourceType::ts()).parse();
    if let Some(d) = ret.diagnostics.iter().next() { return Err(at(d)); }
    let mut program = ret.program;
    let scoping = SemanticBuilder::new().with_excess_capacity(2.0).build(&program).semantic.into_scoping();
    let out = Transformer::new(&alloc, Path::new(path), &TransformOptions::default()).build_with_scoping(scoping, &mut program);
    if let Some(d) = out.diagnostics.iter().next() { return Err(at(d)); }
    let code = Codegen::new().with_options(CodegenOptions { source_map_path: Some(path.into()), ..CodegenOptions::default() }).build(&program);
    Ok((code.code, code.map.map(|m| m.into_owned())))
}
/// Where `file:line:col` of the JavaScript came from: its TypeScript's line and column.
fn source_at(b: &Bundle, file: &str, line: u32, col: u32) -> String {
    let Some(map) = b.maps.get(file) else { return format!("{file}:{line}:{col}") };
    let table = map.generate_lookup_table();
    match map.lookup_token(&table, line.saturating_sub(1), col.saturating_sub(1)) { Some(t) => format!("{file}:{}:{}", t.get_src_line() + 1, t.get_src_col() + 1), None => format!("{file}:{line}") }
}
/// The first place in a QuickJS stack that is one of the deploy's files, in its own lines.
fn first_frame(b: &Bundle, stack: &str) -> Option<String> {
    stack.lines().find_map(|l| {
        let inner = l.trim().rsplit_once('(').map(|(_, r)| r.trim_end_matches(')')).unwrap_or_else(|| l.trim().trim_start_matches("at ").trim());
        let mut it = inner.rsplitn(3, ':'); let (col, line, file) = (it.next()?.parse().ok()?, it.next()?.parse().ok()?, it.next()?);
        b.js.contains_key(file).then(|| source_at(b, file, line, col))
    })
}
/// A JavaScript error as a call's failure: its message (with where it happened, for errors that aren't a plain
/// Error a function threw on purpose) and its code.
fn failure(b: &Bundle, e: CaughtError<'_>) -> FnError {
    let code_ok = |c: &str| !c.is_empty() && c.len() <= 32 && c.starts_with(|ch: char| ch.is_ascii_uppercase()) && c.bytes().all(|x| x.is_ascii_uppercase() || x.is_ascii_digit() || x == b'_');
    match e {
        CaughtError::Exception(x) => {
            let msg = x.message().unwrap_or_default();
            let name: String = x.get::<_, Option<String>>("name").ok().flatten().unwrap_or_else(|| "Error".into());
            let code: Option<String> = x.get::<_, Option<String>>("code").ok().flatten().filter(|c| code_ok(c));
            let mut text = if name == "Error" { msg } else { format!("{name}: {msg}") };
            if name != "Error" { if let Some(at) = x.stack().and_then(|s| first_frame(b, &s)) { text = format!("{text} (at {at})"); } }
            FnError::new(code.as_deref().unwrap_or("FUNCTION"), text)
        }
        CaughtError::Value(v) => {
            if let Some(s) = v.as_string().and_then(|s| s.to_string().ok()) { return FnError::new("FUNCTION", s); }
            let get = |k: &str| v.as_object().and_then(|o| o.get::<_, Option<String>>(k).ok().flatten());
            match get("message") { Some(m) => FnError::new(get("code").filter(|c| code_ok(c)).as_deref().unwrap_or("FUNCTION"), m), None => FnError::new("FUNCTION", "the function threw a value that is not an Error") }
        }
        CaughtError::Error(e) => FnError::new("FUNCTION", e.to_string()),
    }
}

impl Instance {
    /// A runtime with the deploy's modules loaded, and the functions they export (file, name, metadata as JSON).
    fn new(b: &Bundle, limits: &Limits) -> Result<(Instance, Vec<(String, String, J)>), String> {
        let qe = |e: rquickjs::Error| format!("functions: {e}");
        let rt = Runtime::new().map_err(qe)?;
        rt.set_memory_limit(limits.memory); rt.set_max_stack_size(256 << 10);
        let deadline = Arc::new(AtomicU64::new(0));
        { let d = deadline.clone(); rt.set_interrupt_handler(Some(Box::new(move || { let t = d.load(Ordering::Relaxed); t != 0 && now_ns() > t }))); }
        let files = Files(b.js.clone()); rt.set_loader(files.clone(), files);
        let ctx = Context::full(&rt).map_err(qe)?;
        deadline.store(now_ns() + LOAD_TIME.as_nanos() as u64, Ordering::Relaxed);
        let loaded = ctx.with(|ctx| -> Result<(Slots, Vec<(String, String, J)>), String> {
            let fail = |e: CaughtError| { let f = failure(b, e); format!("{}{}", if f.message.contains(" (at ") { "" } else { "loading the modules: " }, f.message) };
            let make: Function = ctx.eval(HELPERS).catch(&ctx).map_err(fail)?;
            let helpers: Object = make.call((Function::new(ctx.clone(), print).map_err(qe)?, Function::new(ctx.clone(), host).map_err(qe)?)).catch(&ctx).map_err(fail)?;
            // one module that imports every file: each loads once, in the order their imports need
            let entry: String = b.names.iter().enumerate().map(|(i, n)| format!("import * as m{i} from {};\n", json!(format!("./{n}")))).collect::<String>() + &format!("export default [{}];\n", (0..b.names.len()).map(|i| format!("m{i}")).collect::<Vec<_>>().join(", "));
            let (m, done) = Module::declare(ctx.clone(), ENTRY, entry).catch(&ctx).map_err(fail)?.eval().catch(&ctx).map_err(fail)?;
            done.finish::<()>().catch(&ctx).map_err(fail)?;
            let list: rquickjs::Array = m.get("default").map_err(qe)?;
            let (kind, meta, same): (Function, Function, Function) = (helpers.get("kind").map_err(qe)?, helpers.get("meta").map_err(qe)?, helpers.get("same").map_err(qe)?);
            let registry = Object::new(ctx.clone()).map_err(qe)?; let mut found = vec![];
            for (i, ns) in list.iter::<Object>().enumerate() {
                let (ns, file) = (ns.map_err(qe)?, &b.names[i]);
                for key in ns.keys::<String>() {
                    let key = key.map_err(qe)?; let v: Js = ns.get(&key).map_err(qe)?;
                    if kind.call::<_, Option<String>>((v.clone(),)).map_err(qe)?.is_none() { continue; }
                    // `export default fn(…)` is named after its file
                    let name = if key == "default" { file.rsplit('/').next().unwrap_or(file).split('.').next().unwrap_or("").to_string() } else { key };
                    if let Some(prev) = registry.get::<_, Option<Js>>(&name).map_err(qe)? { if same.call::<_, bool>((prev, v.clone())).map_err(qe)? { continue; } return Err(format!("{file}: two functions are named {name}")); }
                    let m: String = meta.call((v.clone(),)).catch(&ctx).map_err(fail)?;
                    registry.set(&name, v).map_err(qe)?;
                    found.push((file.clone(), name, serde_json::from_str(&m).map_err(|e| format!("{file}: {e}"))?));
                }
            }
            Ok((Slots { registry: Persistent::save(&ctx, registry), helpers: Persistent::save(&ctx, helpers) }, found))
        });
        deadline.store(0, Ordering::Relaxed);
        let (slots, found) = loaded.map_err(|e| if e.contains("interrupted") { format!("loading the modules took longer than {}s (top-level code runs once per instance)", LOAD_TIME.as_secs()) } else { e })?;
        Ok((Instance { slots, ctx, rt, version: b.version, deadline }, found))
    }
    /// Run one function as `call` (whose transaction is open): its result as JSON, or why it failed; and whether the
    /// instance is spent (it hit a limit, or left work behind) and goes.
    fn invoke(&self, b: &Bundle, call: &mut Call, name: &str, input: &Input, user: Option<&HashMap<String, Value>>, roles: &[String], limits: &Limits) -> (Result<Output, FnError>, bool) {
        let mut spent = false;
        let memory = || FnError::new("LIMIT", format!("{name} used more than {} MB (functions.memory), or threw null", limits.memory >> 20));
        let late = || FnError::new("LIMIT", format!("{name} ran longer than {:?} (functions.timeout)", limits.timeout));
        let out = self.ctx.with(|ctx| -> Result<Output, FnError> {
            let qe = |e: rquickjs::Error| FnError::new("FUNCTION", e.to_string());
            let start = || -> Result<(Function, Object, Js, Object), FnError> {
                let registry = self.slots.registry.clone().restore(&ctx).map_err(qe)?; let helpers = self.slots.helpers.clone().restore(&ctx).map_err(qe)?;
                let def: Object = registry.get(name).map_err(qe)?; let run: Function = def.get("run").map_err(qe)?;
                let c = Object::new(ctx.clone()).map_err(qe)?;
                let both: rquickjs::Array = helpers.get::<_, Function>("bind").and_then(|f| f.call((call.id as f64,))).map_err(qe)?;
                c.set("db", both.get::<Js>(0).map_err(qe)?).map_err(qe)?; c.set("admin", both.get::<Js>(1).map_err(qe)?).map_err(qe)?;
                let u = match user { Some(attrs) => { let o = Object::new(ctx.clone()).map_err(qe)?; for (k, v) in attrs { o.set(k.as_str(), to_js(&ctx, v, None, ColKind::Plain).map_err(qe)?).map_err(qe)?; } o.into_value() } None => Js::new_null(ctx.clone()) };
                c.set("user", u).map_err(qe)?; c.set("roles", roles.to_vec()).map_err(qe)?;
                let a = match input {
                    Input::Args(args) => ctx.json_parse(args.to_string()).map_err(qe)?,
                    Input::Http(r, _) => http_request(&ctx, &helpers, r).map_err(qe)?,
                };
                Ok((run, c, a, helpers))
            };
            let (run, c, a, helpers) = start()?;
            let req = a.clone();
            let until = now_ns() + limits.timeout.as_nanos() as u64; self.deadline.store(until, Ordering::Relaxed);
            let on = Running::start(call);
            let r = run.call::<_, Js>((c, a)).and_then(|v| match v.as_promise() {
                // a promise that can't settle now never will in this call (no timers, no I/O): its continuation must
                // not run in a later caller's call, so the instance goes
                Some(p) => p.finish::<Js>().inspect_err(|e| if matches!(e, rquickjs::Error::WouldBlock) { spent = true; }),
                None => Ok(v),
            });
            // promise jobs the function left behind run now, inside its transaction: none may run in a later call
            while now_ns() < until && ctx.execute_pending_job() {}
            let mut budget = limits.memory;
            let r = r.and_then(|v| match input {
                Input::Args(_) => result_json(&ctx, v, 0, &mut budget).map(Output::Json),
                Input::Http(_, kind) => http_reply(&ctx, &helpers, v, req, kind, limits.memory).map(Output::Http),
            }).catch(&ctx);
            drop(on);
            // what went wrong is read while the time limit still holds: an error's message, code or stack may be a getter
            let out = match r {
                Ok(j) => Ok(j),
                Err(_) if now_ns() > until => { spent = true; Err(late()) }
                // out of memory: QuickJS's InternalError, or null when even that couldn't be made (JS_ThrowError2)
                Err(CaughtError::Exception(x)) if x.message().is_some_and(|m| m == "out of memory") => { spent = true; Err(memory()) }
                Err(CaughtError::Value(v)) if v.is_null() || v.type_of() == rquickjs::Type::Uninitialized => { spent = true; Err(memory()) }
                Err(CaughtError::Error(rquickjs::Error::WouldBlock)) => Err(FnError::new("FUNCTION", format!("{name} returned a promise that can't settle: a function has no timers or I/O to wait for"))),
                Err(e) => Err(failure(b, e)),
            };
            let out = if now_ns() > until { spent = true; Err(late()) } else { out };
            self.deadline.store(0, Ordering::Relaxed);
            out
        });
        // (asked outside `with`, which holds the runtime's lock)
        if self.rt.is_job_pending() { spent = true; }
        (out, spent)
    }
}

/// A request as middleware and routes get it (the helpers' `request`): its body as text where it is UTF-8, and as bytes.
fn http_request<'js>(ctx: &Ctx<'js>, helpers: &Object<'js>, r: &HttpReq) -> rquickjs::Result<Js<'js>> {
    let d = Object::new(ctx.clone())?;
    d.set("method", r.method.as_str())?; d.set("path", r.path.as_str())?; d.set("rawPath", r.raw_path.as_str())?; d.set("query", r.query.as_str())?; d.set("ip", r.ip.as_str())?;
    let hs = rquickjs::Array::new(ctx.clone())?;
    for (i, (k, v)) in r.headers.iter().enumerate() { let pair = rquickjs::Array::new(ctx.clone())?; pair.set(0, k.as_str())?; pair.set(1, v.as_str())?; hs.set(i, pair)?; }
    d.set("headers", hs)?;
    let ps = Object::new(ctx.clone())?; for (k, v) in &r.params { ps.set(k.as_str(), v.as_str())?; } d.set("params", ps)?;
    let (text, bytes) = match &r.body {
        Some(b) => (std::str::from_utf8(b).ok().map(|t| rquickjs::String::from_str(ctx.clone(), t).map(|s| s.into_value())).transpose()?.unwrap_or_else(|| Js::new_null(ctx.clone())), rquickjs::TypedArray::<u8>::new_copy(ctx.clone(), b)?.into_value()),
        None => (Js::new_null(ctx.clone()), Js::new_null(ctx.clone())),
    };
    helpers.get::<_, Function>("request")?.call((d, text, bytes))
}
/// What middleware or a route returned, through the helpers' `reply`: go on, or a response (at most `memory` bytes).
fn http_reply<'js>(ctx: &Ctx<'js>, helpers: &Object<'js>, v: Js<'js>, req: Js<'js>, kind: &str, memory: usize) -> rquickjs::Result<HttpOut> {
    let o: Object = helpers.get::<_, Function>("reply")?.call((v, req, kind))?;
    let headers: Vec<(String, String)> = o.get::<_, Vec<Vec<String>>>("headers")?.into_iter().filter(|p| p.len() == 2).map(|p| (p[0].clone(), p[1].clone())).collect();
    if o.get::<_, bool>("next")? { return Ok(HttpOut::Next(headers)); }
    let status: i32 = o.get("status")?;
    let body = match (o.get::<_, Option<String>>("text")?, o.get::<_, Option<Object>>("bytes")?) {
        (Some(t), _) => t.into_bytes(),
        // (as_bytes borrows the array's memory: copied at once)
        (None, Some(b)) => rquickjs::TypedArray::<u8>::from_object(b).ok().and_then(|t| unsafe { t.as_bytes() }.map(|x| x.to_vec())).unwrap_or_default(),
        _ => vec![],
    };
    if body.len() > memory { return Err(throw(ctx, "LIMIT", "the response is larger than functions.memory")); }
    if !(100..=599).contains(&status) { return Err(throw(ctx, "FUNCTION", format!("{status} is not an HTTP status"))); }
    Ok(HttpOut::Respond { status: status as u16, headers, body })
}

/// The files of a functions folder: every .ts, .mts, .js and .mjs under it (not .d.ts, *.test.* or *.spec.*, nor
/// node_modules or hidden entries), by path relative to it, in order.
pub fn read_folder(dir: &Path) -> Result<Vec<(String, String)>, String> {
    let mut out = vec![];
    fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, String)>) -> Result<(), String> {
        let mut entries: Vec<_> = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?.filter_map(|e| e.ok()).collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') || name == "node_modules" { continue; }
            let p = e.path();
            if p.is_dir() { walk(root, &p, out)?; continue; }
            if !is_module(&name) { continue; }
            let rel = p.strip_prefix(root).unwrap_or(&p).to_string_lossy().replace('\\', "/");
            out.push((rel, std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?));
            if out.len() > MAX_FILES { return Err(format!("{}: more than {MAX_FILES} files", root.display())); }
        }
        Ok(())
    }
    if !dir.is_dir() { return Err(format!("{}: no such folder", dir.display())); }
    walk(dir, dir, &mut out)?; Ok(out)
}
fn is_module(name: &str) -> bool {
    [".ts", ".mts", ".js", ".mjs"].iter().any(|x| name.ends_with(x)) && !name.ends_with(".d.ts") && !name.ends_with(".d.mts") && ![".test.", ".spec."].iter().any(|x| name.contains(x))
}
/// What a folder's files are, cheaply (path, size, modified): the watcher deploys when it changes.
pub type Fingerprint = Vec<(String, u64, Option<SystemTime>)>;
pub fn fingerprint(dir: &Path) -> Fingerprint {
    let mut out = vec![];
    fn walk(dir: &Path, out: &mut Vec<(String, u64, Option<SystemTime>)>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for e in rd.filter_map(|e| e.ok()) {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') || name == "node_modules" { continue; }
            let Ok(m) = e.metadata() else { continue };
            if m.is_dir() { walk(&e.path(), out); } else if is_module(&name) { out.push((e.path().to_string_lossy().into_owned(), m.len(), m.modified().ok())); }
        }
    }
    walk(dir, &mut out); out.sort(); out
}
fn valid_name(n: &str) -> bool { !n.is_empty() && n.len() <= 64 && n.starts_with(|c: char| c.is_ascii_alphabetic()) && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') }
/// A function's metadata, checked: what `fn()` was given besides `run`.
fn def_of(file: &str, name: &str, m: &J) -> Result<Def, String> {
    let at = format!("{file}: {name}");
    if !valid_name(name) { return Err(format!("{at}: a function's name is letters, digits and _ (at most 64), starting with a letter")); }
    if RESERVED.contains(&name) { return Err(format!("{at}: describe, query and execute are the names of MCP's SQL tools")); }
    let description = match m.get("description") { None | Some(J::Null) => None, Some(J::String(s)) if s.len() <= 4000 => Some(s.clone()), _ => return Err(format!("{at}: description is text (at most 4000 characters)")) };
    let read_only = match m.get("readOnly") { None | Some(J::Null) => false, Some(J::Bool(b)) => *b, _ => return Err(format!("{at}: readOnly is true or false")) };
    let roles = match m.get("roles") {
        None | Some(J::Null) => None,
        Some(J::Array(a)) if !a.is_empty() => Some(a.iter().map(|r| r.as_str().filter(|s| !s.is_empty()).map(String::from).ok_or_else(|| format!("{at}: roles is a list of role names"))).collect::<Result<Vec<_>, _>>()?),
        _ => return Err(format!("{at}: roles is a list of role names")),
    };
    let kind = match m.get("kind").and_then(|k| k.as_str()) {
        Some("middleware") => {
            if roles.is_some() { return Err(format!("{at}: middleware has no roles: it runs for every request it matches, and looks at ctx.user and ctx.roles itself")); }
            let list: Vec<String> = match m.get("match") { Some(J::String(p)) => vec![p.clone()], Some(J::Array(a)) if !a.is_empty() => a.iter().map(|x| x.as_str().map(String::from).ok_or_else(|| format!("{at}: match is a path pattern or a list of them"))).collect::<Result<_, _>>()?, _ => return Err(format!("{at}: match: the paths it runs for, such as '/dashboard/*' or ['/admin/*', '/settings']")) };
            let order = match m.get("order") { None | Some(J::Null) => 0, Some(o) => o.as_i64().ok_or_else(|| format!("{at}: order is a whole number (lower runs first)"))? };
            Kind::Middleware { matches: list.iter().map(|p| Pattern::parse(p).map_err(|e| format!("{at}: {e}"))).collect::<Result<_, _>>()?, order }
        }
        Some("route") => {
            let path = m.get("path").and_then(|p| p.as_str()).ok_or_else(|| format!("{at}: path: the path it answers, such as '/hooks/stripe' or '/jobs/:id'"))?;
            let methods: Vec<String> = match m.get("method") { None | Some(J::Null) => vec!["GET".into()], Some(J::String(x)) => vec![x.to_ascii_uppercase()], Some(J::Array(a)) if !a.is_empty() => a.iter().map(|x| x.as_str().map(|x| x.to_ascii_uppercase()).ok_or_else(|| format!("{at}: method is a method or a list of them"))).collect::<Result<_, _>>()?, _ => return Err(format!("{at}: method is a method or a list of them")) };
            if let Some(x) = methods.iter().find(|x| !["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"].contains(&x.as_str())) { return Err(format!("{at}: {x} is not a method a route takes")); }
            Kind::Route { methods, pattern: Pattern::parse(path).map_err(|e| format!("{at}: {e}"))? }
        }
        _ => Kind::Function,
    };
    if kind != Kind::Function && m.get("args").is_some_and(|a| !a.is_null()) { return Err(format!("{at}: middleware and routes take a request, not args")); }
    let mut args = vec![];
    match m.get("args") {
        None | Some(J::Null) => {}
        Some(J::Object(o)) => for (k, spec) in o {
            if !(valid_name(k) || k.starts_with('_') && valid_name(&k[1..])) { return Err(format!("{at}: argument {k:?}: names are letters, digits and _")); }
            let bad = || format!("{at}: argument {k}: a type ('int', 'number', 'text', 'bool', 'uuid' or 'json', with ? when it may be left out), a list of texts it may be, or {{ type, description, optional }}");
            let simple = |s: &str| -> Option<(ArgType, bool)> { let (t, opt) = match s.strip_suffix('?') { Some(t) => (t, true), None => (s, false) }; ArgType::of(t.trim()).map(|t| (t, opt)) };
            let one_of = |a: &Vec<J>| -> Option<ArgType> { let v: Vec<String> = a.iter().filter_map(|x| x.as_str().map(String::from)).collect(); (!v.is_empty() && v.len() == a.len()).then_some(ArgType::OneOf(v)) };
            let (ty, optional, description) = match spec {
                J::String(s) => { let (t, o) = simple(s).ok_or_else(bad)?; (t, o, None) }
                J::Array(a) => (one_of(a).ok_or_else(bad)?, false, None),
                J::Object(o) => {
                    let (ty, opt) = match (o.get("type"), o.get("enum")) { (Some(J::String(s)), None) => simple(s).ok_or_else(bad)?, (Some(J::Array(a)), None) | (None, Some(J::Array(a))) => (one_of(a).ok_or_else(bad)?, false), _ => return Err(bad()) };
                    let optional = match o.get("optional") { None => opt, Some(J::Bool(b)) => *b || opt, _ => return Err(bad()) };
                    let d = match o.get("description") { None => None, Some(J::String(s)) => Some(s.clone()), _ => return Err(bad()) };
                    (ty, optional, d)
                }
                _ => return Err(bad()),
            };
            args.push(Arg { name: k.clone(), ty, optional, description });
        },
        _ => return Err(format!("{at}: args is an object of argument names and types")),
    }
    // in the order the source lists them
    if let Some(order) = m.get("argOrder").and_then(|o| o.as_array()) { args.sort_by_key(|a| order.iter().position(|o| o.as_str() == Some(a.name.as_str())).unwrap_or(usize::MAX)); }
    Ok(Def { name: name.into(), file: file.into(), description, args, roles, read_only, kind })
}
fn is_uuid(s: &str) -> bool { s.len() == 36 && s.bytes().enumerate().all(|(i, b)| if [8, 13, 18, 23].contains(&i) { b == b'-' } else { b.is_ascii_hexdigit() }) }
/// The arguments of a call, checked against the function's `args`.
fn check_args(d: &Def, args: &J) -> Result<J, FnError> {
    let bad = |m: String| FnError::new("ARGUMENTS", m);
    let takes = || if d.args.is_empty() { "it takes none".to_string() } else { format!("it takes {}", d.args.iter().map(|a| a.name.as_str()).collect::<Vec<_>>().join(", ")) };
    let mut obj = match args { J::Null => serde_json::Map::new(), J::Object(m) => m.clone(), _ => return Err(bad(format!("{}: the arguments are an object of names and values", d.name))) };
    if let Some(k) = obj.keys().find(|k| !d.args.iter().any(|a| &a.name == *k)) { return Err(bad(format!("{} has no argument {k}: {}", d.name, takes()))); }
    for a in &d.args {
        let Some(v) = obj.get_mut(&a.name) else { if a.optional { continue; } return Err(bad(format!("{}: {} is required ({})", d.name, a.name, a.ty.describe()))) };
        if v.is_null() { if a.optional { continue; } return Err(bad(format!("{}: {} is required ({})", d.name, a.name, a.ty.describe()))); }
        let ok = match &a.ty {
            ArgType::Int => { if let Some(f) = v.as_f64().filter(|f| v.as_i64().is_none() && f.fract() == 0.0 && f.abs() <= 9007199254740992.0) { *v = json!(f as i64); } v.as_i64().is_some() }
            ArgType::Number => v.is_number(), ArgType::Text => v.is_string(), ArgType::Bool => v.is_boolean(), ArgType::Json => true,
            ArgType::Uuid => v.as_str().is_some_and(is_uuid),
            ArgType::OneOf(list) => v.as_str().is_some_and(|s| list.iter().any(|x| x == s)),
        };
        if !ok { return Err(bad(format!("{}: {} is {}, not {v}", d.name, a.name, a.ty.describe()))); }
    }
    Ok(J::Object(obj))
}
/// Whether `sess` may call `d`: the application always; others when they have one of its `roles`, or (when it lists
/// none) when they signed in.
pub fn may_call(d: &Def, sess: &Session, anonymous: bool) -> bool {
    if sess.user.is_none() { return true; }
    match &d.roles { Some(r) => sess.roles.iter().any(|x| r.contains(x)), None => !anonymous }
}
/// A function's arguments as JSON Schema, for MCP's `inputSchema`.
pub fn input_schema(d: &Def) -> J {
    let props: serde_json::Map<String, J> = d.args.iter().map(|a| { let mut s = a.ty.schema(); if let Some(t) = &a.description { s["description"] = json!(t); } (a.name.clone(), s) }).collect();
    let required: Vec<&str> = d.args.iter().filter(|a| !a.optional).map(|a| a.name.as_str()).collect();
    json!({"type": "object", "properties": props, "required": required, "additionalProperties": false})
}
fn bundle_text(files: &[(String, String)]) -> Result<String, String> {
    let mut map = BTreeMap::new(); let mut total = 0;
    for (p, src) in files {
        if p.is_empty() || p.starts_with('/') || p.contains('\\') || p.split('/').any(|s| s.is_empty() || s == "." || s == "..") || !is_module(p.rsplit('/').next().unwrap_or(p)) { return Err(format!("{p:?}: a file is a path inside the folder ending in .ts, .mts, .js or .mjs")); }
        total += src.len(); if total > MAX_SOURCE { return Err(format!("the files are more than {} MB", MAX_SOURCE >> 20)); }
        if map.insert(p.clone(), src.clone()).is_some() { return Err(format!("{p}: twice")); }
    }
    if map.len() > MAX_FILES { return Err(format!("more than {MAX_FILES} files")); }
    Ok(json!({"files": map}).to_string())
}
fn hash_of(text: &str) -> String { use sha2::Digest; sha2::Sha256::digest(text.as_bytes()).iter().map(|b| format!("{b:02x}")).collect() }

impl Sql {
    fn limits(&self) -> Limits { Limits { timeout: self.cfg.functions.timeout, memory: self.cfg.functions.memory } }
    /// Compile files into a deploy, with its first instance. `strict` (a deploy, not the catalog replayed): say which
    /// roles don't exist yet. (Not an error: an app opens its database, deploying its functions, before it makes its
    /// roles; a function for a role nobody has is one nobody can call.)
    fn compile_functions(&self, files: &[(String, String)], strict: bool) -> Result<(Bundle, Instance), String> {
        let mut js = HashMap::new(); let mut maps = HashMap::new();
        for (p, src) in files { let (code, map) = strip(p, src)?; js.insert(p.clone(), code); if let Some(m) = map { maps.insert(p.clone(), m); } }
        let text = bundle_text(files)?;
        let mut b = Bundle { version: self.functions.versions.fetch_add(1, Ordering::Relaxed) + 1, hash: hash_of(&text), names: files.iter().map(|f| f.0.clone()).collect(), js: Arc::new(js), maps, defs: vec![], middleware: vec![], routes: vec![] };
        let (inst, found) = Instance::new(&b, &self.limits())?;
        let mut defs: Vec<Def> = found.iter().map(|(f, n, m)| def_of(f, n, m)).collect::<Result<_, _>>()?;
        if strict { let acl = self.acl.read().unwrap(); for d in &defs { if let Some(r) = d.roles.iter().flatten().find(|r| !acl.roles.contains(*r)) { eprintln!("functions: {}: {} is for role {r}, which doesn't exist (yet)", d.file, d.name); } } }
        defs.sort_by(|a, b| a.name.cmp(&b.name));
        // routes: never on the API's own paths (they'd never be reached), and one per method and path
        let mut seen = std::collections::HashSet::new();
        for d in &defs {
            let pats: Vec<&Pattern> = match &d.kind { Kind::Function => continue, Kind::Middleware { matches, .. } => matches.iter().collect(), Kind::Route { pattern, .. } => vec![pattern] };
            for p in &pats { let probe: String = p.text.split('/').map(|s| if s.starts_with(':') || s == "*" { "x" } else { s }).collect::<Vec<_>>().join("/"); if crate::proxy::ours(self, &probe) && matches!(d.kind, Kind::Route { .. }) { return Err(format!("{}: {}: {} is the API's own path", d.file, d.name, p.text)); } }
            if let Kind::Route { methods, pattern } = &d.kind { for m in methods { if !seen.insert((m.clone(), pattern.text.clone())) { return Err(format!("{}: {}: another route is {m} {} too", d.file, d.name, pattern.text)); } } }
        }
        b.middleware = (0..defs.len()).filter(|&i| matches!(defs[i].kind, Kind::Middleware { .. })).collect();
        b.middleware.sort_by_key(|&i| (match defs[i].kind { Kind::Middleware { order, .. } => order, _ => 0 }, defs[i].file.clone(), defs[i].name.clone()));
        b.routes = (0..defs.len()).filter(|&i| matches!(defs[i].kind, Kind::Route { .. })).collect();
        b.defs = defs; Ok((b, inst))
    }
    fn install(&self, b: Bundle, inst: Instance) {
        let old: Vec<Instance> = { let mut p = self.functions.pool.lock().unwrap(); let old: Vec<Instance> = p.idle.drain(..).collect(); p.live -= old.len(); p.live += 1; p.idle.push(inst); old };
        *self.functions.bundle.write().unwrap() = Some(Arc::new(b)); *self.functions.broken.write().unwrap() = None;
        drop(old); self.functions.freed.notify_all();
    }
    /// Deploy functions: `files` are (path inside the folder, source). They replace every function deployed before;
    /// the same files again change nothing. Only the application deploys.
    pub fn deploy_functions(&self, sess: &Session, files: Vec<(String, String)>) -> Result<Deployed, String> {
        if sess.user.is_some() { return Err("permission denied: only the application deploys functions".into()); }
        let _one = self.functions.deploying.lock().unwrap();
        let text = bundle_text(&files)?;
        // the deploy the catalog holds: loaded if it is these files, dropped if these replace it
        if let Some(p) = self.functions.pending.lock().unwrap().take() { if p == text { self.load_catalog(&p); } }
        if let Some(b) = self.functions.bundle.read().unwrap().as_ref().filter(|b| b.hash == hash_of(&text)) { return Ok(Deployed { functions: b.defs.iter().map(|d| d.name.clone()).collect(), changed: false }); }
        let (b, inst) = self.compile_functions(&files, true)?;
        self.log_meta_replacing(FUNCTIONS_META, &format!("{FUNCTIONS_META}{text}"));
        let names = b.defs.iter().map(|d| d.name.clone()).collect();
        self.install(b, inst);
        Ok(Deployed { functions: names, changed: true })
    }
    /// Deploy the functions in a folder (see `read_folder`), as the application.
    pub fn deploy_functions_from(&self, dir: &Path) -> Result<Deployed, String> { self.deploy_functions(&Session::default(), read_folder(dir)?) }
    /// `DEPLOY FUNCTIONS {"files": {…}}` sent as a statement (the shell, TCP, a binding's exec): a row per function.
    pub(crate) fn deploy_statement(&self, sess: &Session, json: &str) -> Result<Vec<Vec<Value>>, String> {
        let v: J = serde_json::from_str(json).map_err(|e| format!("DEPLOY FUNCTIONS takes {{\"files\": {{path: source}}}}: {e}"))?;
        let files = v.get("files").and_then(|f| f.as_object()).ok_or("DEPLOY FUNCTIONS takes {\"files\": {path: source}}")?
            .iter().map(|(k, s)| s.as_str().map(|s| (k.clone(), s.to_string())).ok_or_else(|| format!("{k}: the source is text"))).collect::<Result<Vec<_>, _>>()?;
        Ok(self.deploy_functions(sess, files)?.functions.into_iter().map(|n| vec![Value::Text(n)]).collect())
    }
    /// A deploy read back from the catalog (replay, or a follower tailing the log): kept to load when first needed.
    pub(crate) fn functions_from_catalog(&self, json: &str) { *self.functions.pending.lock().unwrap() = Some(json.to_string()); }
    /// Load the catalog's deploy now, if one is waiting. Never fails: a deploy that no longer loads leaves the functions
    /// unavailable, saying why.
    fn settle_functions(&self) {
        if self.functions.pending.lock().unwrap().is_none() { return; }
        let _one = self.functions.deploying.lock().unwrap();
        if let Some(p) = self.functions.pending.lock().unwrap().take() { self.load_catalog(&p); }
    }
    fn load_catalog(&self, json: &str) {
        let files: Result<Vec<(String, String)>, String> = serde_json::from_str::<J>(json).map_err(|e| e.to_string()).and_then(|v| v.get("files").and_then(|f| f.as_object()).map(|m| m.iter().map(|(k, s)| (k.clone(), s.as_str().unwrap_or("").to_string())).collect()).ok_or_else(|| "no files".into()));
        match files.and_then(|f| self.compile_functions(&f, false)) {
            Ok((b, inst)) => self.install(b, inst),
            Err(e) => { eprintln!("functions: the deployed functions don't load: {e}"); *self.functions.bundle.write().unwrap() = None; *self.functions.broken.write().unwrap() = Some(e); }
        }
    }
    /// The functions deployed, by name.
    pub fn function_defs(&self) -> Vec<Def> { self.settle_functions(); self.functions.bundle.read().unwrap().as_ref().map(|b| b.defs.iter().filter(|d| d.kind == Kind::Function).cloned().collect()).unwrap_or_default() }
    /// Every export deployed: functions, middleware and routes.
    pub fn deployed(&self) -> Vec<Def> { self.settle_functions(); self.functions.bundle.read().unwrap().as_ref().map(|b| b.defs.clone()).unwrap_or_default() }
    /// An instance for a call: an idle one, a new one while fewer than `functions.instances` exist, or the next one
    /// freed, waiting at most a few calls' time limits.
    fn take_instance(&self, b: &Arc<Bundle>) -> Result<Instance, FnError> {
        let st = &self.functions; let max = self.cfg.functions.instances;
        let until = Instant::now() + (self.cfg.functions.timeout * 4).max(Duration::from_secs(5));
        let mut pool = st.pool.lock().unwrap();
        loop {
            if let Some(i) = pool.idle.iter().position(|i| i.version == b.version) { return Ok(pool.idle.swap_remove(i)); }
            if let Some(stale) = pool.idle.pop() { pool.live -= 1; drop(pool); drop(stale); pool = st.pool.lock().unwrap(); continue; }
            if pool.live < max {
                pool.live += 1; drop(pool);
                return Instance::new(b, &self.limits()).map(|(i, _)| i).map_err(|e| { st.pool.lock().unwrap().live -= 1; st.freed.notify_one(); FnError::new("FUNCTION", e) });
            }
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() { return Err(FnError::new("LIMIT", format!("all {max} instances are busy (functions.instances); try again"))); }
            pool = st.freed.wait_timeout(pool, left).unwrap().0;
        }
    }
    fn give_instance(&self, inst: Instance, keep: bool) {
        let current = self.functions.bundle.read().unwrap().as_ref().map(|b| b.version);
        let mut pool = self.functions.pool.lock().unwrap();
        if keep && current == Some(inst.version) { pool.idle.push(inst); drop(pool); } else { pool.live -= 1; drop(pool); drop(inst); }
        self.functions.freed.notify_one();
    }
    /// Call a function as `sess`, with `args` (a JSON object). Its own transaction, or the one `sess` has open (whose
    /// owner commits, and retries on CONFLICT; a failure dooms it). `anonymous`: the session acts as
    /// `app.anonymousRole`, not as someone who signed in.
    pub fn call_function(&self, sess: &mut Session, name: &str, args: &J, anonymous: bool) -> Result<J, FnError> {
        // who is calling, as of now: a session held across calls (a socket, a binding's handle) may have been signed
        // out or changed since it last ran anything
        self.check_identity(sess).map_err(|e| FnError::new(error_code(&e), e))?;
        let b = self.bundle_for(name)?;
        let Some(def) = b.defs.iter().find(|d| d.name == name && d.kind == Kind::Function) else { return Err(FnError::new("NOT_FOUND", format!("no function {name}"))) };
        if !may_call(def, sess, anonymous) { return Err(FnError::new("DENIED", format!("permission denied: {name} is for {}", def.roles.as_ref().map(|r| format!("the roles {}", r.join(", "))).unwrap_or_else(|| "signed-in users".into())))); }
        let args = check_args(def, args)?;
        let user = sess.user.is_some().then(|| sess.attrs.clone()); let roles = sess.roles.clone();
        match self.run_call(sess, &b, def, &Input::Args(&args), user, roles)? { Output::Json(j) => Ok(j), Output::Http(_) => unreachable!() }
    }
    fn bundle_for(&self, name: &str) -> Result<Arc<Bundle>, FnError> {
        self.settle_functions();
        self.functions.bundle.read().unwrap().clone().ok_or_else(|| match self.functions.broken.read().unwrap().clone() { Some(e) => FnError::new("FUNCTION", format!("the deployed functions don't load: {e}")), None => FnError::new("NOT_FOUND", format!("no function {name} (none are deployed)")) })
    }
    /// Whether the deploy in the catalog doesn't load (its functions, middleware and routes are unavailable).
    pub fn functions_broken(&self) -> bool { self.settle_functions(); self.functions.broken.read().unwrap().is_some() }
    /// Whether middleware or routes are deployed: requests for anything but the API's own paths go through them.
    pub fn has_http(&self) -> bool { self.settle_functions(); self.functions.bundle.read().unwrap().as_ref().is_some_and(|b| !b.middleware.is_empty() || !b.routes.is_empty()) }
    /// The middleware for a request to `path` (from `match_path`), in the order they run, with each one's parameters.
    pub fn middleware_for(&self, path: &str) -> Vec<(Def, Vec<(String, String)>)> {
        let Some(b) = self.functions.bundle.read().unwrap().clone() else { return vec![] };
        b.middleware.iter().filter_map(|&i| { let d = &b.defs[i]; let Kind::Middleware { matches, .. } = &d.kind else { return None }; matches.iter().find_map(|p| p.matches(path)).map(|ps| (d.clone(), ps)) }).collect()
    }
    /// The route that answers `method` `path`: of those that match, the most literal (`Pattern::rank`).
    pub fn route_for(&self, method: &str, path: &str) -> Option<(Def, Vec<(String, String)>)> {
        let b = self.functions.bundle.read().unwrap().clone()?;
        let method = if method == "HEAD" { "GET" } else { method };
        b.routes.iter().filter_map(|&i| { let d = &b.defs[i]; let Kind::Route { methods, pattern } = &d.kind else { return None }; if !methods.iter().any(|m| m == method || (m == "HEAD" && method == "GET")) { return None; } pattern.matches(path).map(|ps| (pattern.rank(), d.clone(), ps)) })
            .max_by_key(|(r, _, _)| *r).map(|(_, d, ps)| (d, ps))
    }
    /// Run middleware or a route for one request, as `sess`; `user`: the signed-in user's row (None: no one signed in).
    pub fn run_http(&self, sess: &mut Session, def: &Def, req: &HttpReq, user: Option<HashMap<String, Value>>, roles: Vec<String>) -> Result<HttpOut, FnError> {
        let b = self.bundle_for(&def.name)?;
        let Some(def) = b.defs.iter().find(|d| d.name == def.name && d.kind == def.kind) else { return Err(FnError::new("NOT_FOUND", format!("{} is no longer deployed", def.name))) };
        if let Some(r) = &def.roles {
            if user.is_none() { return Err(FnError::new("AUTH", "session: sign in first")); }
            if !roles.iter().any(|x| r.contains(x)) { return Err(FnError::new("DENIED", format!("permission denied: {} is for the roles {}", def.name, r.join(", ")))); }
        }
        let kind = if matches!(def.kind, Kind::Middleware { .. }) { "middleware" } else { "route" };
        match self.run_call(sess, &b, def, &Input::Http(req, kind), user, roles)? { Output::Http(h) => Ok(h), Output::Json(_) => unreachable!() }
    }
    /// One call, in its own transaction (or the one `sess` has open), run again when another writer got there first.
    fn run_call(&self, sess: &mut Session, b: &Arc<Bundle>, def: &Def, input: &Input, user: Option<HashMap<String, Value>>, roles: Vec<String>) -> Result<Output, FnError> {
        let fe = |e: String| FnError::new(error_code(&e), e);
        let name = def.name.as_str();
        let outer = sess.txn.is_some();
        let limits = self.limits();
        for attempt in 0.. {
            let inst = self.take_instance(b)?;
            if !outer { if let Err(e) = self.exec_s(sess, "BEGIN", &[]) { self.give_instance(inst, true); return Err(fe(e)); } }
            let mut call = Call { id: CALL_IDS.fetch_add(1, Ordering::Relaxed), sql: self as *const Sql, sess: sess as *mut Session, read_only: def.read_only, name: def.name.clone(), failed: None, conflicted: false, memory: limits.memory };
            let (r, spent) = inst.invoke(b, &mut call, name, input, user.as_ref(), &roles, &limits);
            self.give_instance(inst, !spent);
            let r = match (r, call.failed.take()) { (Ok(_), Some(f)) => Err(f), (r, _) => r };
            let lost = call.conflicted || matches!(&r, Err(e) if e.code == "CONFLICT");
            if outer {
                // its writes are in the caller's transaction: a failure there must not commit them
                if let (Err(e), Some(t)) = (&r, sess.txn.as_mut()) { t.doomed.get_or_insert_with(|| if lost { "Conflict: a function in this transaction lost to another writer".into() } else { format!("can't commit: {name} failed in the same transaction ({})", e.message) }); }
                return r;
            }
            match r {
                Ok(v) => match self.exec_s(sess, "COMMIT", &[]) {
                    Ok(_) => return Ok(v),
                    Err(e) => { sess.txn = None; if !(error_code(&e) == "CONFLICT" && attempt < RETRIES) { return Err(fe(e)); } }
                },
                // (not through exec_s: a session whose identity no longer checks out still ends its transaction)
                Err(e) => { sess.txn = None; if !(lost && attempt < RETRIES) { return Err(e); } }
            }
            // another writer got there first: run it again, after a short randomized pause
            let mut r = [0u8; 2]; let _ = getrandom::fill(&mut r);
            std::thread::sleep(Duration::from_micros((u16::from_le_bytes(r) as u64 * (100 << attempt.min(6))) >> 16));
        }
        unreachable!()
    }
}

/// Watches a functions folder and deploys it when it changes (once it has stayed the same for a poll, so a copy in
/// progress doesn't deploy half its files). A deploy that fails keeps the functions as they were.
pub struct Watcher { stop: Arc<AtomicBool>, thread: Option<std::thread::JoinHandle<()>> }
impl Watcher {
    /// `seen`: the folder as it was before the deploy that is in use read it (a change in between deploys again).
    pub fn start(sql: &Arc<Sql>, dir: std::path::PathBuf, seen: Fingerprint) -> Watcher {
        let stop = Arc::new(AtomicBool::new(false)); let (s, weak) = (stop.clone(), Arc::downgrade(sql));
        let thread = std::thread::Builder::new().name("sqzdb-functions".into()).spawn(move || {
            let mut seen = seen; let mut pending: Option<Fingerprint> = None;
            while !s.load(Ordering::Relaxed) {
                std::thread::park_timeout(Duration::from_millis(500));
                let now = fingerprint(&dir);
                if now == seen { pending = None; continue; }
                if pending.as_ref() != Some(&now) { pending = Some(now); continue; }
                seen = now; pending = None;
                let Some(sql) = weak.upgrade() else { return };
                match sql.deploy_functions_from(&dir) {
                    Ok(d) if d.changed => eprintln!("functions: deployed {} from {}: {}", d.functions.len(), dir.display(), d.functions.join(", ")),
                    Ok(_) => {}
                    Err(e) => eprintln!("functions: {} not deployed: {e}", dir.display()),
                }
            }
        }).expect("thread");
        Watcher { stop, thread: Some(thread) }
    }
}
// (the watcher's own thread may hold the last handle while it deploys, and close the database itself: it can't join itself)
impl Drop for Watcher { fn drop(&mut self) { self.stop.store(true, Ordering::Relaxed); if let Some(t) = self.thread.take() { t.thread().unpark(); if t.thread().id() != std::thread::current().id() { let _ = t.join(); } } } }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    fn tmp(n: &str) -> std::path::PathBuf { let d = std::env::temp_dir().join(format!("sqzdb-functions-{}-{n}", std::process::id())); let _ = std::fs::remove_dir_all(&d); d }
    fn open(dir: &Path, opts: &str) -> Arc<Sql> { Sql::open_with(dir, Config::from_json(opts).unwrap()).unwrap() }
    fn q(s: &Sql, sql: &str) -> Vec<Vec<Value>> { s.exec_s(&mut Session::default(), sql, &[]).unwrap_or_else(|e| panic!("{sql}: {e}")) }
    fn deploy(s: &Sql, files: &[(&str, &str)]) -> Result<Deployed, String> { s.deploy_functions(&Session::default(), files.iter().map(|(p, c)| (p.to_string(), c.to_string())).collect()) }
    fn agent(s: &Sql, uid: i64) -> Session { let mut sess = Session::default(); s.assume(&mut sess, &["agent".into()], HashMap::from([("uid".to_string(), Value::Int(uid))])).unwrap(); sess }
    fn call(s: &Sql, sess: &mut Session, name: &str, args: J) -> Result<J, FnError> { s.call_function(sess, name, &args, false) }

    const JOBS: &str = r#"
import { fn } from 'sqzdb/functions'
import { must } from './lib.ts'

interface Run { id: number; owner: number; status: string; outcome: string | null }
type Status = 'completed' | 'failed'

export const reportRun = fn({
  description: 'Report how a run ended',
  args: { runId: 'int', status: ['completed', 'failed'], outcome: 'text?' },
  roles: ['agent'],
  run({ db, admin, user }, { runId, status, outcome }: { runId: number; status: Status; outcome?: string }) {
    const run = db.get('SELECT * FROM runs WHERE id = ?', [runId]) as Run | null
    must(run, `no run ${runId}`)
    if (run.status !== 'running') throw Object.assign(new Error(`run ${runId} is ${run.status} already`), { code: 'ALREADY_FINISHED' })
    admin.run('UPDATE runs SET status = ?, outcome = ? WHERE id = ?', [status, outcome ?? null, runId])
    if (status === 'completed' && !outcome) throw new Error('a completed run needs an outcome')
    return { ok: true, by: user?.uid }
  },
})

export const counts = fn({
  readOnly: true,
  run({ db }) { return db.get('SELECT count(*) AS n FROM runs') },
})
"#;
    const LIB: &str = "export function must<T>(v: T | null | undefined, msg: string): asserts v is T {\n  if (v == null) throw new Error(msg)\n}\n";
    fn setup(s: &Sql) {
        for st in ["CREATE TABLE runs (id SERIAL PRIMARY KEY, owner INT, status TEXT, outcome TEXT)", "CREATE ROLE agent", "CREATE ROLE guest", "GRANT SELECT ON runs TO agent",
                   "CREATE POLICY mine ON runs FOR ALL TO agent USING (owner = SESSION.uid)", "INSERT INTO runs (owner, status) VALUES (1, 'running')", "INSERT INTO runs (owner, status) VALUES (2, 'running')"] { q(s, st); }
    }

    #[test] fn a_function_acts_as_its_caller_and_admin_does_what_the_caller_may_not() {
        let d = tmp("caller"); let s = open(&d, "{}"); setup(&s);
        let names = deploy(&s, &[("jobs.ts", JOBS), ("lib.ts", LIB)]).unwrap().functions;
        assert_eq!(names, vec!["counts", "reportRun"]);
        let mut a1 = agent(&s, 1);
        assert_eq!(call(&s, &mut a1, "reportRun", json!({"runId": 1, "status": "completed", "outcome": "done"})).unwrap(), json!({"ok": true, "by": 1}));
        assert_eq!(q(&s, "SELECT status, outcome FROM runs WHERE id = 1"), vec![vec![Value::Text("completed".into()), Value::Text("done".into())]]);
        // run 2 is someone else's: the policy hides it from db, so the function says there is no such run
        assert_eq!(call(&s, &mut a1, "reportRun", json!({"runId": 2, "status": "failed"})).unwrap_err(), FnError::new("FUNCTION", "no run 2"));
        // the agent can't write runs itself: only through the function and its rules
        assert!(s.exec_s(&mut a1, "UPDATE runs SET status = 'failed' WHERE id = 1", &[]).unwrap_err().starts_with("permission denied"));
        // a function's own code, and a rule broken after a write: nothing of the call stays
        assert_eq!(call(&s, &mut a1, "reportRun", json!({"runId": 1, "status": "failed"})).unwrap_err().code, "ALREADY_FINISHED");
        q(&s, "INSERT INTO runs (owner, status) VALUES (1, 'running')");
        assert_eq!(call(&s, &mut a1, "reportRun", json!({"runId": 3, "status": "completed"})).unwrap_err(), FnError::new("FUNCTION", "a completed run needs an outcome"));
        assert_eq!(q(&s, "SELECT status FROM runs WHERE id = 3"), vec![vec![Value::Text("running".into())]]);
        // read-only functions read
        assert_eq!(call(&s, &mut a1, "counts", json!({})).unwrap(), json!({"n": 2}), "the agent's policy shows its own two runs");
        assert_eq!(s.call_function(&mut Session::default(), "counts", &json!(null), false).unwrap(), json!({"n": 3}), "the application sees all");
    }

    #[test] fn roles_decide_who_may_call() {
        let d = tmp("roles"); let s = open(&d, "{}"); setup(&s);
        deploy(&s, &[("a.ts", "import { fn } from 'sqzdb/functions'\nexport const anyone = fn({ run: () => 'hi' })\nexport const guests = fn({ roles: ['guest'], run: () => 'welcome' })\nexport const agents = fn({ roles: ['agent'], run: () => 'ok' })\n")]).unwrap();
        let mut a = agent(&s, 1); let mut g = Session::default(); s.assume(&mut g, &["guest".into()], HashMap::new()).unwrap();
        assert_eq!(call(&s, &mut a, "anyone", json!({})).unwrap(), json!("hi"));
        assert_eq!(call(&s, &mut a, "guests", json!({})).unwrap_err().code, "DENIED");
        assert_eq!(call(&s, &mut a, "agents", json!({})).unwrap(), json!("ok"));
        // the anonymous role calls only what lists it
        assert_eq!(s.call_function(&mut g, "anyone", &json!({}), true).unwrap_err().code, "DENIED");
        assert_eq!(s.call_function(&mut g, "guests", &json!({}), true).unwrap(), json!("welcome"));
        assert_eq!(call(&s, &mut a, "nope", json!({})).unwrap_err().code, "NOT_FOUND");
        // a role made after the deploy: the function is callable from then on
        deploy(&s, &[("a.ts", "import { fn } from 'sqzdb/functions'\nexport const later = fn({ roles: ['later'], run: () => 'now' })\n")]).unwrap();
        q(&s, "CREATE ROLE later"); let mut l = Session::default(); s.assume(&mut l, &["later".into()], HashMap::new()).unwrap();
        assert_eq!(call(&s, &mut l, "later", json!({})).unwrap(), json!("now"));
    }

    #[test] fn arguments_are_checked_before_the_function_runs() {
        let d = tmp("args"); let s = open(&d, "{}");
        deploy(&s, &[("a.js", "import { fn } from 'sqzdb/functions'\nexport const f = fn({ args: { n: 'int', x: 'number?', t: { type: 'text', description: 'a name' }, k: ['a', 'b'], id: 'uuid?', any: 'json?', ok: 'bool?' }, run: (_, a) => a })\n")]).unwrap();
        let app = &mut Session::default(); let f = |s: &Sql, sess: &mut Session, a: J| s.call_function(sess, "f", &a, false);
        assert_eq!(f(&s, app, json!({"n": 2.0, "t": "x", "k": "a", "x": null})).unwrap(), json!({"n": 2, "t": "x", "k": "a", "x": null}));
        for (args, says) in [(json!({"t": "x", "k": "a"}), "n is required (a whole number)"), (json!({"n": 1.5, "t": "x", "k": "a"}), "n is a whole number, not 1.5"), (json!({"n": 1, "t": "x", "k": "c"}), "k is one of \"a\", \"b\", not \"c\""),
                             (json!({"n": 1, "t": "x", "k": "a", "id": "nope"}), "id is a UUID"), (json!({"n": 1, "t": "x", "k": "a", "extra": 1}), "f has no argument extra: it takes n, x, t, k, id, any, ok"), (json!([1]), "the arguments are an object")] {
            let e = f(&s, app, args).unwrap_err(); assert_eq!(e.code, "ARGUMENTS"); assert!(e.message.contains(says), "{} vs {says}", e.message);
        }
        let schema = input_schema(&s.function_defs()[0]);
        assert_eq!(schema["required"], json!(["n", "t", "k"])); assert_eq!(schema["properties"]["k"], json!({"type": "string", "enum": ["a", "b"]})); assert_eq!(schema["properties"]["t"]["description"], json!("a name"));
    }

    #[test] fn values_cross_into_javascript_and_back() {
        let d = tmp("values"); let s = open(&d, "{}");
        q(&s, "CREATE TABLE v (id SERIAL PRIMARY KEY, at TIMESTAMP, raw BYTES, big INT, doc TEXT)");
        deploy(&s, &[("v.ts", r#"import { fn } from 'sqzdb/functions'
export const roundTrip = fn({ run({ db }) {
  const id = db.run('INSERT INTO v (at, raw, big, doc) VALUES (?, ?, ?, ?)', [new Date('2026-10-15T19:30:00.123Z'), new Uint8Array([1, 2, 255]), 9007199254740993n, { a: [1, 2] }]).lastInsertId
  const r = db.get('SELECT * FROM v WHERE id = ?', id)
  return { id, isDate: r.at instanceof Date, at: r.at, raw: r.raw, isBytes: r.raw instanceof Uint8Array, big: r.big, bigType: typeof r.big, doc: JSON.parse(r.doc), none: db.get('SELECT * FROM v WHERE id = 99'), all: db.all('SELECT id FROM v').length }
} })"#)]).unwrap();
        assert_eq!(s.call_function(&mut Session::default(), "roundTrip", &json!({}), false).unwrap(),
            json!({"id": 1, "isDate": true, "at": "2026-10-15T19:30:00.123Z", "raw": "0x0102ff", "isBytes": true, "big": 9007199254740993_i64, "bigType": "bigint", "doc": {"a": [1, 2]}, "none": null, "all": 1}));
    }

    #[test] fn a_failed_write_ends_the_call_even_when_caught() {
        let d = tmp("failed"); let s = open(&d, "{}");
        q(&s, "CREATE TABLE u (id INT PRIMARY KEY, name TEXT)"); q(&s, "INSERT INTO u VALUES (1, 'a')");
        deploy(&s, &[("u.js", "import { fn } from 'sqzdb/functions'\nexport const f = fn({ run({ db }) { db.run('INSERT INTO u VALUES (2, ?)', ['b']); try { db.run('INSERT INTO u VALUES (1, ?)', ['dup']) } catch (e) { if (e.code !== 'DUPLICATE') throw e } return 'carried on' } })\nexport const g = fn({ run({ db }) { try { db.get('SELECT nope FROM u') } catch (e) { return 'a failed read is fine: ' + e.code } } })\n")]).unwrap();
        let e = s.call_function(&mut Session::default(), "f", &json!({}), false).unwrap_err();
        assert_eq!(e.code, "DUPLICATE", "{e:?}");
        assert_eq!(q(&s, "SELECT count(*) FROM u"), vec![vec![Value::Int(1)]], "row 2 went with the call");
        assert_eq!(s.call_function(&mut Session::default(), "g", &json!({}), false).unwrap(), json!("a failed read is fine: SCHEMA"));
    }

    #[test] fn limits_stop_a_function_and_the_next_call_works() {
        let d = tmp("limits"); let s = open(&d, r#"{"functions": {"timeout": "300ms", "memory": "16MB", "instances": 1}}"#);
        deploy(&s, &[("l.ts", "import { fn } from 'sqzdb/functions'\nexport const spin = fn({ run() { for (;;) {} } })\nexport const hog = fn({ run() { const a: string[] = []; for (;;) a.push('x'.repeat(1 << 20)) } })\nexport const deep = fn({ run() { const f = (n: number): number => f(n + 1) + 1; return f(0) } })\nexport const ok = fn({ run: () => 1 })\nexport const pending = fn({ async run() { await new Promise(() => {}) } })\n")]).unwrap();
        let app = &mut Session::default();
        let t = Instant::now(); let e = s.call_function(app, "spin", &json!({}), false).unwrap_err();
        assert_eq!(e.code, "LIMIT"); assert!(t.elapsed() < Duration::from_millis(2000), "{:?}", t.elapsed()); assert!(e.message.contains("longer than"), "{e:?}");
        let e = s.call_function(app, "hog", &json!({}), false).unwrap_err(); assert_eq!(e.code, "LIMIT", "{e:?}"); assert!(e.message.contains("16 MB"), "{e:?}");
        let e = s.call_function(app, "deep", &json!({}), false).unwrap_err(); assert_eq!(e.code, "FUNCTION"); assert!(e.message.contains("stack"), "{e:?}");
        assert_eq!(s.call_function(app, "ok", &json!({}), false).unwrap(), json!(1));
        assert!(s.call_function(app, "pending", &json!({}), false).is_err());
        assert_eq!(s.call_function(app, "ok", &json!({}), false).unwrap(), json!(1), "the instance count is back, and a fresh one works");
    }

    #[test] fn errors_point_at_the_typescript() {
        let d = tmp("lines"); let s = open(&d, "{}");
        // types, an interface and a type alias come before the bug, and are gone from the JavaScript
        let src = "import { fn } from 'sqzdb/functions'\ninterface A {\n  x: number\n}\ntype B = A | null\n\nexport const f = fn({\n  run(): number {\n    const b: B = null\n    return (b as any).x\n  },\n})\n";
        deploy(&s, &[("bug.ts", src)]).unwrap();
        let e = s.call_function(&mut Session::default(), "f", &json!({}), false).unwrap_err();
        assert!(e.message.starts_with("TypeError: ") && e.message.contains("(at bug.ts:10:"), "{e:?}");
        let e = deploy(&s, &[("bad.ts", "import { fn } from 'sqzdb/functions'\nexport const f = fn({ run() { return 1 +* 2 } })\n")]).unwrap_err();
        assert!(e.starts_with("bad.ts:2:"), "{e}");
        let e = deploy(&s, &[("pkg.ts", "import { z } from 'zod'\nexport const x = z\n")]).unwrap_err(); assert!(e.contains("no packages"), "{e}");
        let e = deploy(&s, &[("r.ts", "import { fn } from 'sqzdb/functions'\nexport const query = fn({ run() {} })\n")]).unwrap_err(); assert!(e.contains("names of MCP's SQL tools"), "{e}");
        let e = deploy(&s, &[("a.ts", "import { fn } from 'sqzdb/functions'\nexport const x = fn({ run() {} })\n"), ("b.ts", "import { fn } from 'sqzdb/functions'\nexport const x = fn({ run() {} })\n")]).unwrap_err(); assert!(e.contains("two functions are named x"), "{e}");
        // a failed deploy changes nothing
        assert_eq!(s.function_defs().len(), 1);
    }

    #[test] fn a_deploy_survives_restarts_and_replaces_the_one_before() {
        let d = tmp("restart");
        {
            let s = open(&d, "{}");
            deploy(&s, &[("a.ts", "import { fn } from 'sqzdb/functions'\nexport const one = fn({ run: () => 1 })\n")]).unwrap();
            assert!(!deploy(&s, &[("a.ts", "import { fn } from 'sqzdb/functions'\nexport const one = fn({ run: () => 1 })\n")]).unwrap().changed, "the same files change nothing");
            // as a statement, as the shell or a TCP client sends it; only the application may
            let rows = q(&s, &format!("DEPLOY FUNCTIONS {}", json!({"files": {"a.ts": "import { fn } from 'sqzdb/functions'\nexport const two = fn({ run: () => 2 })\nexport default fn({ run: () => 'named after the file' })\n"}})));
            assert_eq!(rows, vec![vec![Value::Text("a".into())], vec![Value::Text("two".into())]]);
            let mut a = Session::default(); q(&s, "CREATE ROLE agent"); s.assume(&mut a, &["agent".into()], HashMap::new()).unwrap();
            assert!(s.exec_s(&mut a, "DEPLOY FUNCTIONS {\"files\": {}}", &[]).unwrap_err().starts_with("permission denied"));
            assert_eq!(s.db.log.st.lock().unwrap().catalog.iter().filter(|c| c.starts_with(FUNCTIONS_META)).count(), 1, "the catalog keeps the latest deploy only");
        }
        { let s = open(&d, "{}"); assert_eq!(s.db.log.st.lock().unwrap().catalog.iter().filter(|c| c.starts_with(FUNCTIONS_META)).count(), 1, "and so does a restart");
          assert_eq!(s.call_function(&mut Session::default(), "two", &json!({}), false).unwrap(), json!(2)); assert_eq!(s.call_function(&mut Session::default(), "one", &json!({}), false).unwrap_err().code, "NOT_FOUND"); s.snapshot(); }
        { let s = open(&d, "{}"); assert_eq!(s.call_function(&mut Session::default(), "a", &json!({}), false).unwrap(), json!("named after the file")); }
    }

    #[test] fn conflicting_calls_run_again_and_lose_no_update() {
        let d = tmp("conflicts"); let s = open(&d, r#"{"functions": {"instances": 8}}"#);
        q(&s, "CREATE TABLE c (id INT PRIMARY KEY, n INT)"); q(&s, "INSERT INTO c VALUES (1, 0)");
        deploy(&s, &[("c.js", "import { fn } from 'sqzdb/functions'\nexport const bump = fn({ run({ db }) { const { n } = db.get('SELECT n FROM c WHERE id = 1'); db.run('UPDATE c SET n = ? WHERE id = 1', [n + 1]); return n + 1 } })\n")]).unwrap();
        let threads: Vec<_> = (0..8).map(|_| { let s = s.clone(); std::thread::spawn(move || { let mut sess = Session::default(); for _ in 0..200 { s.call_function(&mut sess, "bump", &json!({}), false).unwrap(); } }) }).collect();
        for t in threads { t.join().unwrap(); }
        assert_eq!(q(&s, "SELECT n FROM c WHERE id = 1"), vec![vec![Value::Int(1600)]]);
    }

    /// The review's race (E66): two runs of a job end at once; each updates its run, then counts the job's runs still
    /// running. Without the scan checked at commit both counted one and the job never reached review.
    #[test] fn concurrent_reports_still_move_every_job_to_review() {
        let d = tmp("race"); let s = open(&d, r#"{"functions": {"instances": 4}}"#);
        q(&s, "CREATE TABLE jobs (id INT PRIMARY KEY, status TEXT)"); q(&s, "CREATE TABLE runs (id INT PRIMARY KEY, job INT, status TEXT)"); q(&s, "CREATE INDEX runs_job ON runs (job)");
        for j in 0..300 { q(&s, &format!("INSERT INTO jobs VALUES ({j}, 'running')")); for k in 0..2 { q(&s, &format!("INSERT INTO runs VALUES ({}, {j}, 'running')", j * 2 + k)); } }
        deploy(&s, &[("r.js", "import { fn } from 'sqzdb/functions'\nexport const report = fn({ args: { run: 'int' }, run({ db }, { run }) { const r = db.get('SELECT job FROM runs WHERE id = ?', [run]); db.run(\"UPDATE runs SET status = 'failed' WHERE id = ?\", [run]); const left = db.get(\"SELECT count(*) AS n FROM runs WHERE job = ? AND status = 'running'\", [r.job]).n; if (left === 0) db.run(\"UPDATE jobs SET status = 'review' WHERE id = ?\", [r.job]); return left } })\n")]).unwrap();
        // the two runs of each job reported at the same moment
        let meet = Arc::new(std::sync::Barrier::new(2));
        let go = |k: i64| { let (s, meet) = (s.clone(), meet.clone()); std::thread::spawn(move || { let mut sess = Session::default(); for j in 0..300 { meet.wait(); s.call_function(&mut sess, "report", &json!({"run": j * 2 + k}), false).unwrap(); } }) };
        let (a, b) = (go(0), go(1)); a.join().unwrap(); b.join().unwrap();
        assert_eq!(q(&s, "SELECT count(*) FROM jobs WHERE status = 'review'"), vec![vec![Value::Int(300)]]);
    }
    #[test] fn a_read_by_unique_value_then_a_write_loses_no_update() {
        let d = tmp("unique"); let s = open(&d, r#"{"functions": {"instances": 8}}"#);
        q(&s, "CREATE TABLE c (id INT PRIMARY KEY, name TEXT UNIQUE, n INT)"); q(&s, "INSERT INTO c VALUES (1, 'counter', 0)");
        deploy(&s, &[("c.js", "import { fn } from 'sqzdb/functions'\nexport const bump = fn({ run({ db }) { const { id, n } = db.get(\"SELECT id, n FROM c WHERE name = 'counter'\"); db.run('UPDATE c SET n = ? WHERE id = ?', [n + 1, id]) } })\n")]).unwrap();
        let ts: Vec<_> = (0..8).map(|_| { let s = s.clone(); std::thread::spawn(move || { let mut sess = Session::default(); for _ in 0..100 { s.call_function(&mut sess, "bump", &json!({}), false).unwrap(); } }) }).collect();
        for t in ts { t.join().unwrap(); }
        assert_eq!(q(&s, "SELECT n FROM c WHERE id = 1"), vec![vec![Value::Int(800)]]);
    }
    #[test] fn a_held_session_is_checked_again_at_each_call() {
        let d = tmp("held"); let s = open(&d, "{}");
        for st in ["CREATE TABLE users (id SERIAL PRIMARY KEY, email TEXT UNIQUE, role TEXT DEFAULT 'boss')", "CREATE ROLE boss", "CREATE ROLE member", "ALTER TABLE users ENABLE AUTH (ROLE FROM role)"] { q(&s, st); }
        deploy(&s, &[("b.js", "import { fn } from 'sqzdb/functions'\nexport const secret = fn({ roles: ['boss'], run: ({ roles }) => roles })\nexport const anyone = fn({ run: ({ admin }) => admin.get('SELECT count(*) AS n FROM users').n })\n")]).unwrap();
        let si = s.sign_up("users", &[("email".into(), Value::Text("a@x".into()))], "the password 1").unwrap();
        let mut held = Session::default(); s.session_from_token(&mut held, &si.token).unwrap();
        assert_eq!(s.call_function(&mut held, "secret", &json!({}), false).unwrap(), json!(["boss"]));
        q(&s, "UPDATE users SET role = 'member' WHERE email = 'a@x'");
        assert_eq!(s.call_function(&mut held, "secret", &json!({}), false).unwrap_err().code, "DENIED", "demoted: the very next call");
        s.sign_out(&si.token).unwrap();
        assert_eq!(s.call_function(&mut held, "anyone", &json!({}), false).unwrap_err().code, "AUTH", "signed out");
        assert!(held.txn.is_none());
    }
    #[test] fn a_getter_in_an_error_is_held_to_the_time_limit() {
        let d = tmp("getter"); let s = open(&d, r#"{"functions": {"timeout": "200ms", "instances": 1}}"#);
        deploy(&s, &[("g.js", "import { fn } from 'sqzdb/functions'\nexport const sly = fn({ run() { throw { get message() { for (;;) {} } } } })\nexport const slier = fn({ run() { const e = new TypeError('x'); Object.defineProperty(e, 'code', { get() { for (;;) {} } }); throw e } })\nexport const ok = fn({ run: () => 1 })\n")]).unwrap();
        for f in ["sly", "slier"] { let t = Instant::now(); assert_eq!(s.call_function(&mut Session::default(), f, &json!({}), false).unwrap_err().code, "LIMIT", "{f}"); assert!(t.elapsed() < Duration::from_secs(3)); }
        assert_eq!(s.call_function(&mut Session::default(), "ok", &json!({}), false).unwrap(), json!(1), "the one instance is free again");
    }
    #[test] fn a_failure_inside_the_callers_transaction_dooms_it() {
        let d = tmp("doomed"); let s = open(&d, "{}");
        q(&s, "CREATE TABLE t (id INT PRIMARY KEY)");
        deploy(&s, &[("t.js", "import { fn } from 'sqzdb/functions'\nexport const half = fn({ run({ admin }) { admin.run('INSERT INTO t VALUES (1)'); throw new Error('no') } })\n")]).unwrap();
        let mut app = Session::default(); s.exec_s(&mut app, "BEGIN", &[]).unwrap();
        assert_eq!(s.call_function(&mut app, "half", &json!({}), false).unwrap_err().code, "FUNCTION");
        let e = s.exec_s(&mut app, "COMMIT", &[]).unwrap_err(); assert_eq!(error_code(&e), "TRANSACTION", "{e}");
        assert_eq!(q(&s, "SELECT count(*) FROM t"), vec![vec![Value::Int(0)]]);
    }
    #[test] fn results_and_rows_are_held_to_the_memory_limit() {
        let d = tmp("big"); let s = open(&d, r#"{"functions": {"memory": "8MB"}}"#);
        q(&s, "CREATE TABLE b (id INT PRIMARY KEY, body TEXT)");
        for i in 0..100 { s.exec_s(&mut Session::default(), "INSERT INTO b VALUES (?, ?)", &[Value::Int(i), Value::Text("x".repeat(100_000))]).unwrap(); }
        deploy(&s, &[("b.js", "import { fn } from 'sqzdb/functions'\nexport const wide = fn({ run: () => Array(400).fill('x'.repeat(1 << 20)) })\nexport const all = fn({ run: ({ db }) => db.all('SELECT * FROM b').length })\nexport const some = fn({ run: ({ db }) => db.all('SELECT * FROM b LIMIT 10').length })\n")]).unwrap();
        for f in ["wide", "all"] { let e = s.call_function(&mut Session::default(), f, &json!({}), false).unwrap_err(); assert_eq!(e.code, "LIMIT", "{f}: {e:?}"); }
        assert_eq!(s.call_function(&mut Session::default(), "some", &json!({}), false).unwrap(), json!(10));
    }
    #[test] fn nothing_of_one_call_runs_in_the_next() {
        let d = tmp("leak"); let s = open(&d, r#"{"functions": {"instances": 1}}"#);
        q(&s, "CREATE TABLE t (id INT PRIMARY KEY)");
        deploy(&s, &[("l.js", "import { fn } from 'sqzdb/functions'\nlet kept, resume\nexport const keep = fn({ run({ db }) { kept = db } })\nexport const useKept = fn({ run: () => kept.get('SELECT 1 AS x') })\nexport const wait = fn({ async run({ db }) { await new Promise((r) => { resume = r }); db.run('INSERT INTO t VALUES (999)') } })\nexport const wake = fn({ run() { if (resume) resume(); return !!resume } })\n")]).unwrap();
        s.call_function(&mut Session::default(), "keep", &json!({}), false).unwrap();
        let e = s.call_function(&mut Session::default(), "useKept", &json!({}), false).unwrap_err(); assert!(e.message.contains("earlier call"), "{e:?}");
        assert!(s.call_function(&mut Session::default(), "wait", &json!({}), false).unwrap_err().message.contains("can't settle"));
        assert_eq!(s.call_function(&mut Session::default(), "wake", &json!({}), false).unwrap(), json!(false), "the instance that waited is gone");
        assert_eq!(q(&s, "SELECT count(*) FROM t"), vec![vec![Value::Int(0)]]);
    }
    #[test] fn paths_are_matched_as_the_app_behind_will_resolve_them() {
        let p = Pattern::parse("/admin/*").unwrap();
        for (raw, m) in [("/admin", true), ("/admin/users/7", true), ("/administrator", false), ("/x/admin", false)] { assert_eq!(p.matches(&match_path(raw).unwrap()).is_some(), m, "{raw}"); }
        // what a browser never sends is refused; what is encoded is decoded first, as the app behind would
        for raw in ["/public/../admin", "/./admin", "/admin%2fx", "/a%5c..%5cadmin", "/a\\b", "/%2e%2e/admin", "/admin%00"] { assert_eq!(match_path(raw), None, "{raw}"); }
        assert_eq!(match_path("/adm%69n/x").as_deref(), Some("/admin/x"));
        assert_eq!(match_path("//admin//x/").as_deref(), Some("/admin/x"));
        // Next.js's data route for a page is that page
        assert_eq!(match_path("/_next/data/b1d/admin/users.json").as_deref(), Some("/admin/users"));
        assert_eq!(match_path("/_next/data/b1d/index.json").as_deref(), Some("/"));
        let r = Pattern::parse("/jobs/:id/runs/:run").unwrap();
        assert_eq!(r.matches(&match_path("/jobs/42/runs/a%20b").unwrap()), Some(vec![("id".into(), "42".into()), ("run".into(), "a b".into())]));
        for bad in ["admin", "/a/*/b", "/a/:", "/a/:1x", "/a/b%2f", "/a/.."] { assert!(Pattern::parse(bad).is_err(), "{bad}"); }
    }
    #[test] fn middleware_and_routes_answer_or_let_requests_on() {
        let d = tmp("http"); let s = open(&d, "{}"); setup(&s);
        let src = r#"import { middleware, route, signIn } from 'sqzdb/functions'
export const guard = middleware({ match: ['/dashboard/*'], order: 1, run({ user, roles, db }, req) {
  if (!user) return signIn(req)
  req.headers.set('x-plan', db.get('SELECT count(*) AS n FROM runs').n > 0 ? 'busy' : 'idle')
  req.headers.delete('x-drop')
} })
export const first = middleware({ match: '*', run(_, req) { if (req.headers.get('x-block')) return new Response('blocked', { status: 451 }) } })
export const job = route({ method: ['GET', 'POST'], path: '/jobs/:id', async run({ user }, req) {
  if (req.method === 'POST') return Response.json({ id: req.params.id, got: await req.json(), by: user?.uid ?? null }, { status: 201 })
  return { id: Number(req.params.id), q: req.query.q, cookie: req.cookies.k ?? null }
} })
export const anyJob = route({ path: '/jobs/*', run: (_, req) => new Response('rest: ' + req.params['*']) })
export const admin = route({ path: '/admin', roles: ['agent'], run: () => 'ok' })
export const bad = middleware({ match: '/oops', run: () => 'not a response' })
"#;
        deploy(&s, &[("h.ts", src)]).unwrap();
        assert!(s.has_http()); assert!(s.function_defs().is_empty(), "middleware and routes are no MCP tools");
        let names = |v: Vec<(Def, Vec<(String, String)>)>| v.into_iter().map(|(d, _)| d.name).collect::<Vec<_>>();
        assert_eq!(names(s.middleware_for("/dashboard/x")), vec!["first", "guard"], "order 0 before order 1");
        let req = |m: &str, path: &str, q: &str, h: &[(&str, &str)], body: Option<&str>| HttpReq { method: m.into(), path: path.into(), raw_path: path.into(), query: q.into(), headers: h.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(), ip: "203.0.113.1".into(), params: vec![], body: body.map(|b| b.as_bytes().to_vec()) };
        let run = |sess: &mut Session, def: &Def, r: &HttpReq, user: Option<HashMap<String, Value>>, roles: Vec<String>| s.run_http(sess, def, r, user, roles);
        let guard = s.middleware_for("/dashboard").into_iter().find(|(d, _)| d.name == "guard").unwrap().0;
        // no one signed in: to the sign-in page, and back here after
        match run(&mut Session::default(), &guard, &req("GET", "/dashboard", "tab=2", &[], None), None, vec![]).unwrap() {
            HttpOut::Respond { status, headers, .. } => { assert_eq!(status, 302); assert_eq!(headers, vec![("location".to_string(), "/_sqz/sign-in?return=%2Fdashboard%3Ftab%3D2".to_string())]); }
            o => panic!("{o:?}"),
        }
        // signed in: on, with a header it set and one it took away
        let mut a = agent(&s, 1);
        match run(&mut a, &guard, &req("GET", "/dashboard", "", &[("x-drop", "1"), ("accept", "text/html")], None), Some(HashMap::from([("uid".to_string(), Value::Int(1))])), vec!["agent".into()]).unwrap() {
            HttpOut::Next(h) => assert_eq!(h, vec![("accept".to_string(), "text/html".to_string()), ("x-plan".to_string(), "busy".to_string())]),
            o => panic!("{o:?}"),
        }
        // routes: the most literal match, params, query, cookies, a JSON body, a value as JSON
        let (job, params) = s.route_for("POST", "/jobs/7").unwrap(); assert_eq!(job.name, "job");
        let mut r = req("POST", "/jobs/7", "", &[], Some(r#"{"x":1}"#)); r.params = params;
        match run(&mut a, &job, &r, Some(HashMap::from([("uid".to_string(), Value::Int(1))])), vec!["agent".into()]).unwrap() {
            HttpOut::Respond { status, body, .. } => { assert_eq!(status, 201); assert_eq!(String::from_utf8(body).unwrap(), r#"{"id":"7","got":{"x":1},"by":1}"#); }
            o => panic!("{o:?}"),
        }
        let (job, params) = s.route_for("GET", "/jobs/7").unwrap(); let mut r = req("GET", "/jobs/7", "q=a%20b", &[("cookie", "k=v; z=1")], Some("")); r.params = params;
        match run(&mut Session::default(), &job, &r, None, vec![]).unwrap() { HttpOut::Respond { body, .. } => assert_eq!(String::from_utf8(body).unwrap(), r#"{"id":7,"q":"a b","cookie":"v"}"#), o => panic!("{o:?}") }
        assert_eq!(s.route_for("GET", "/jobs/7/runs").unwrap().0.name, "anyJob");
        assert!(s.route_for("DELETE", "/jobs/7").is_none());
        // a route's roles: who isn't signed in, who lacks them
        let (admin, _) = s.route_for("GET", "/admin").unwrap();
        assert_eq!(run(&mut Session::default(), &admin, &req("GET", "/admin", "", &[], Some("")), None, vec![]).unwrap_err().code, "AUTH");
        assert_eq!(run(&mut Session::default(), &admin, &req("GET", "/admin", "", &[], Some("")), Some(HashMap::new()), vec!["guest".into()]).unwrap_err().code, "DENIED");
        // middleware that returns something else is a bug, said as one
        let bad = s.middleware_for("/oops").into_iter().find(|(d, _)| d.name == "bad").unwrap().0;
        assert!(run(&mut Session::default(), &bad, &req("GET", "/oops", "", &[], None), None, vec![]).unwrap_err().message.contains("returns a Response"));
        // deploys that can't work
        for (src, says) in [("import { route } from 'sqzdb/functions'\nexport const r = route({ path: '/api/sql', run: () => 1 })\n", "the API's own path"),
                            ("import { route } from 'sqzdb/functions'\nexport const a = route({ path: '/x', run: () => 1 })\nexport const b = route({ path: '/x', run: () => 2 })\n", "another route is GET /x"),
                            ("import { middleware } from 'sqzdb/functions'\nexport const m = middleware({ match: '/x', args: { a: 'int' }, run() {} })\n", "take a request, not args"),
                            ("import { middleware } from 'sqzdb/functions'\nexport const m = middleware({ run() {} })\n", "match: the paths it runs for")] {
            let e = deploy(&s, &[("bad.ts", src)]).unwrap_err(); assert!(e.contains(says), "{e}");
        }
    }
    #[test] fn an_open_transaction_is_joined_not_committed() {
        let d = tmp("outer"); let s = open(&d, "{}");
        q(&s, "CREATE TABLE t (id INT PRIMARY KEY)");
        deploy(&s, &[("t.js", "import { fn } from 'sqzdb/functions'\nexport const add = fn({ args: { id: 'int' }, run({ db }, { id }) { db.run('INSERT INTO t VALUES (?)', [id]) } })\n")]).unwrap();
        let mut app = Session::default();
        s.exec_s(&mut app, "BEGIN", &[]).unwrap();
        s.call_function(&mut app, "add", &json!({"id": 1}), false).unwrap();
        s.exec_s(&mut app, "ROLLBACK", &[]).unwrap();
        assert_eq!(q(&s, "SELECT count(*) FROM t"), vec![vec![Value::Int(0)]]);
    }

    #[test] fn a_watched_folder_deploys_when_it_changes() {
        let d = tmp("watch"); let f = tmp("watch-src"); std::fs::create_dir_all(f.join("lib")).unwrap();
        std::fs::write(f.join("a.ts"), "import { fn } from 'sqzdb/functions'\nimport { two } from './lib/two'\nexport const one = fn({ run: () => two() - 1 })\n").unwrap();
        std::fs::write(f.join("lib/two.ts"), "export const two = (): number => 2\n").unwrap();
        std::fs::write(f.join("a.test.ts"), "this is not loaded").unwrap();
        let s = open(&d, &json!({"functions": f.to_string_lossy()}).to_string());
        assert_eq!(s.call_function(&mut Session::default(), "one", &json!({}), false).unwrap(), json!(1));
        std::fs::write(f.join("b.ts"), "import { fn } from 'sqzdb/functions'\nexport const three = fn({ run: () => 3 })\n").unwrap();
        let t = Instant::now();
        while s.function_defs().len() < 2 { assert!(t.elapsed() < Duration::from_secs(10), "not redeployed"); std::thread::sleep(Duration::from_millis(50)); }
        assert_eq!(s.call_function(&mut Session::default(), "three", &json!({}), false).unwrap(), json!(3));
        let t = Instant::now(); s.close(); assert!(t.elapsed() < Duration::from_millis(400), "closing waits for the watcher: {:?}", t.elapsed());
        // a folder that doesn't load fails the open
        std::fs::write(f.join("b.ts"), "export const = broken").unwrap();
        drop(s);
        assert!(Sql::open_with(&d, Config::from_json(&json!({"functions": f.to_string_lossy()}).to_string()).unwrap()).err().unwrap().starts_with("functions: b.ts:1:"));
    }
}
#[cfg(test)]
mod timing {
    use super::*;
    use crate::config::Config;
    /// What a call costs in the process, against the same statement sent directly: `cargo test --release --lib functions::timing -- --ignored --nocapture`
    #[test] #[ignore] fn a_call_against_its_statement() {
        let d = std::env::temp_dir().join(format!("sqzdb-functions-timing-{}", std::process::id())); let _ = std::fs::remove_dir_all(&d);
        let s = Sql::open_with(&d, Config::default()).unwrap(); let mut app = Session::default();
        for q in ["CREATE TABLE jobs (id SERIAL PRIMARY KEY, owner INT, title TEXT, status TEXT)", "CREATE ROLE member", "GRANT SELECT ON jobs TO member", "CREATE POLICY own ON jobs FOR ALL TO member USING (owner = SESSION.id)"] { s.exec_s(&mut app, q, &[]).unwrap(); }
        for i in 0..20 { s.exec_s(&mut app, "INSERT INTO jobs (owner, title, status) VALUES (?, ?, 'inbox')", &[Value::Int(i % 2), Value::Text(format!("job {i}"))]).unwrap(); }
        s.deploy_functions(&app, vec![("a.ts".into(), "import { fn } from 'sqzdb/functions'\nexport const myJobs = fn({ readOnly: true, run: ({ db }) => db.all('SELECT id, title, status FROM jobs ORDER BY id DESC LIMIT 50') })\nexport const nothing = fn({ run: () => null })\nexport const count = fn({ readOnly: true, run: ({ db }) => db.all('SELECT id, title, status FROM jobs ORDER BY id DESC LIMIT 50').length })\nexport const big = fn({ run: () => Array.from({ length: 10 }, (_, i) => ({ id: i, title: 'job ' + i, status: 'inbox' })) })\n".into())]).unwrap();
        let mut m = Session::default(); s.assume(&mut m, &["member".into()], HashMap::from([("id".to_string(), Value::Int(1))])).unwrap();
        let n = 50_000;
        let t = Instant::now(); for _ in 0..n { s.call_function(&mut m, "nothing", &json!({}), false).unwrap(); } let empty = t.elapsed() / n;
        let t = Instant::now(); for _ in 0..n { s.call_function(&mut m, "myJobs", &json!({}), false).unwrap(); } let call = t.elapsed() / n;
        let t = Instant::now(); for _ in 0..n { s.call_function(&mut m, "count", &json!({}), false).unwrap(); } let rows_in = t.elapsed() / n;
        let t = Instant::now(); for _ in 0..n { s.call_function(&mut m, "big", &json!({}), false).unwrap(); } let rows_out = t.elapsed() / n;
        println!("the rows into JavaScript, a number out: {rows_in:?}\nno SQL, 10 made-up rows out: {rows_out:?}");
        let p = s.prepare("SELECT id, title, status FROM jobs ORDER BY id DESC LIMIT 50").unwrap();
        let t = Instant::now(); for _ in 0..n { s.execute_s(&mut m, &p, &[]).unwrap(); } let direct = t.elapsed() / n;
        println!("a function that does nothing: {empty:?}\nmyJobs (10 rows): {call:?}\nits SELECT, directly: {direct:?}");
    }
}
