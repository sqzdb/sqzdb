//! The `sqzdb` command: `serve` a database directory (Unix socket, TCP, the web console), `shell` into one, and `deploy`
//! an app's functions to one.
#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;   // musl's allocator halves the engine's speed (E45)

use serde_json::{json, Map, Value as J};
use sqzdb::config::Config;
use sqzdb::net::Client;
use sqzdb::sql::{Session, Sql};
use sqzdb::table::{format_timestamp, ColType, Value};
use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn on_signal(_: libc::c_int) { STOP.store(true, Ordering::Relaxed); }

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("serve") => serve(&args[1..]),
        Some("shell") => shell(&args[1..]),
        Some("deploy") => deploy(&args[1..]),
        Some("version") | Some("--version") => println!("sqzdb {}", env!("CARGO_PKG_VERSION")),
        _ => usage(),
    }
}
fn usage() -> ! {
    eprintln!("usage:\n  sqzdb serve <dir> [--config <file.toml>] [--ui <addr>] [--tcp <addr>] [--socket <path>] [--app <addr>] [--domain <name>[,<name>...]] [--email <address>] [--token <secret>] [--functions <folder>] [--proxy <http://host:port>] [--durable]\n      Serve a database directory. --ui opens the web console (bind it to 127.0.0.1 unless you mean otherwise).\n      --app serves the app API to browsers and mobile apps (with --proxy, in front of your app: what isn't the API's goes on to it); with --domain, over https with a certificate from Let's Encrypt for\n      those names, renewed automatically (bind --app to port 443 of the address the names point to; --email for expiry notices).\n      --ui and --tcp need a token; without --token one is generated and printed once.
      Settings come from --config, or else <dir>/sqzdb.toml (yours alone): the console's Settings tab writes it and restarts the server.\n  sqzdb shell <dir>                      Open the directory in this process and run SQL interactively.\n  sqzdb shell <host:port> --token <t>    The same over TCP against a running server.\n  sqzdb deploy <folder> <dir>            Deploy the app's functions in <folder> (.ts, .js) to a database directory (not open elsewhere).\n  sqzdb deploy <folder> <host:port> --token <t>   The same to a running server, over its TCP port.\n      `serve --functions <folder>` deploys a folder when the server starts, and again whenever it changes.");
    std::process::exit(2)
}
fn flag(a: &[String], name: &str) -> Option<String> { a.iter().position(|s| s == name).and_then(|i| a.get(i + 1).cloned()) }
fn has(a: &[String], name: &str) -> bool { a.iter().any(|s| s == name) }
fn fail(e: impl std::fmt::Display) -> ! { eprintln!("sqzdb: {e}"); std::process::exit(1) }
fn random_token() -> String { let mut b = [0u8; 16]; std::fs::File::open("/dev/urandom").and_then(|mut f| std::io::Read::read_exact(&mut f, &mut b)).unwrap_or_else(|e| fail(format!("/dev/urandom: {e}"))); b.iter().map(|x| format!("{x:02x}")).collect() }

/// Every connected user holds a socket: take the hard limit on open files (a service often starts with 1,024).
fn raise_open_files() {
    unsafe { let mut r: libc::rlimit = std::mem::zeroed(); if libc::getrlimit(libc::RLIMIT_NOFILE, &mut r) == 0 && r.rlim_cur < r.rlim_max { r.rlim_cur = r.rlim_max; libc::setrlimit(libc::RLIMIT_NOFILE, &r); } }
}
fn serve(a: &[String]) {
    raise_open_files();
    let dir = a.first().filter(|s| !s.starts_with("--")).map(std::path::PathBuf::from).unwrap_or_else(|| usage());
    let mut opts = Map::new(); let mut listen = Map::new();
    // the settings: the file --config names; else the database's own sqzdb.toml (written by the console's Settings
    // tab), read only if it is this user's alone
    let settings = match flag(a, "--config") { Some(f) => std::path::PathBuf::from(f), None => dir.join("sqzdb.toml") };
    if flag(a, "--config").is_some() { opts.insert("configFile".into(), json!(settings.display().to_string())); }
    // (read once, through the handle that was checked)
    let own = if flag(a, "--config").is_none() && std::fs::symlink_metadata(&settings).is_ok() { Some(sqzdb::config::read_private(&settings).unwrap_or_else(|e| fail(e))) } else { None };
    let load = |opts: &Map<String, J>| -> Result<Config, String> {
        let json = J::Object(opts.clone()).to_string();
        match &own { Some(text) => Config::check(text, Some(&json)).map_err(|e| format!("{}: {}", settings.display(), sqzdb::config::scrub(&e, text))), None => Config::load(&dir, Some(&json)) }
    };
    if has(a, "--durable") { opts.insert("durable".into(), json!(true)); }
    if let Some(v) = flag(a, "--ui") { listen.insert("http".into(), json!(v)); }
    if let Some(v) = flag(a, "--tcp") { listen.insert("tcp".into(), json!(v)); }
    if let Some(v) = flag(a, "--socket") { listen.insert("socket".into(), json!(v)); }
    if let Some(v) = flag(a, "--app") { listen.insert("app".into(), json!(v)); }
    if let Some(v) = flag(a, "--functions") { opts.insert("functions".into(), json!(v)); }
    let mut app = Map::new();
    if let Some(v) = flag(a, "--proxy") { app.insert("proxy".into(), json!(v)); }
    let mut tls = Map::new();
    if let Some(d) = flag(a, "--domain") { tls.insert("domains".into(), json!(d.split(',').map(str::trim).filter(|x| !x.is_empty()).collect::<Vec<_>>())); }
    if let Some(e) = flag(a, "--email") { tls.insert("email".into(), json!(e)); }
    if !tls.is_empty() { app.insert("tls".into(), J::Object(tls)); }
    if !app.is_empty() { opts.insert("app".into(), J::Object(app)); }
    // a console or TCP port without a token of yours gets one: generated and printed (kept across a restart the console
    // asks for, so its page stays connected)
    let mut printed_token = None;
    let generated = || std::env::var("SQZDB_RESTART_TOKEN").ok().filter(|t| !t.is_empty()).unwrap_or_else(random_token);
    match flag(a, "--token") { Some(t) => { listen.insert("token".into(), json!(t)); } None => if listen.contains_key("http") || listen.contains_key("tcp") { let t = generated(); listen.insert("token".into(), json!(t.clone())); printed_token = Some(t); } }
    if !listen.is_empty() { opts.insert("listen".into(), J::Object(listen.clone())); }
    let flags = { let mut f = opts.clone(); f.remove("configFile"); J::Object(f) };
    let cfg = match load(&opts) {
        // the settings file opens a console or a TCP port and names no token: one is generated, as with --ui
        Err(e) if e.contains("needs listen.token") && printed_token.is_none() => {
            let t = generated(); listen.insert("token".into(), json!(t.clone())); printed_token = Some(t);
            opts.insert("listen".into(), J::Object(listen)); load(&opts).unwrap_or_else(|e| fail(e))
        }
        r => r.unwrap_or_else(|e| fail(e)),
    };
    sqzdb::ui::serve_settings(settings.clone(), flags);
    let t = Instant::now(); let sql = Sql::open_with(&dir, cfg.clone()).unwrap_or_else(|e| fail(e));
    let rows = sql.snapshot_rows();
    println!("sqzdb serving {} ({} tables, {} rows, opened in {:.0} ms)", dir.display(), sql.db.table_names().len(), rows, t.elapsed().as_secs_f64() * 1e3);
    println!("  durability: {:?}{}", cfg.durable, cfg.backup.as_ref().map(|b| format!("; backup to {}/{} every {:?}{}", b.bucket, b.prefix.trim_matches('/'), b.interval, if b.passphrase.is_some() { ", encrypted" } else { "" })).unwrap_or_default());
    if let Some(p) = &cfg.listen.socket { println!("  socket:     {}", p.display()); }
    if let Some(t) = &cfg.listen.tcp { println!("  tcp:        {t}"); }
    if let Some(h) = &cfg.listen.http { println!("  console:    http://{h}/"); }
    if let Some(h) = &cfg.listen.app {
        let url = match &cfg.app.tls { Some(_) => cfg.app.public_url.clone().unwrap_or_else(|| format!("https://{h}")), None => format!("http://{h}") };
        let tls = cfg.app.tls.as_ref().map(|t| if t.cert.is_some() { format!("  (on {h}, your certificate)") } else { format!("  (on {h}, certificate from {})", t.acme.split('/').nth(2).unwrap_or(&t.acme)) }).unwrap_or_default();
        println!("  app API:    {url}/api/{tls}{}", cfg.app.static_dir.as_ref().map(|d| format!("  (and the files in {})", d.display())).unwrap_or_default());
        if let Some(r) = cfg.app.tls.as_ref().and_then(|t| t.redirect.as_ref()) { println!("  redirect:   http://{r}/ to https"); }
        if let Some(p) = &cfg.app.proxy { println!("  proxy:      everything else to {}", p.to); }
    }
    if let Some(d) = &cfg.functions.dir { let names: Vec<String> = sql.function_defs().into_iter().map(|f| f.name).collect(); println!("  functions:  {} from {}{}: {}", names.len(), d.display(), if cfg.functions.watch { " (watched)" } else { "" }, names.join(", ")); }
    if let Some(t) = &printed_token { println!("  token:      {t}   (generated; pass --token to choose one)"); }
    println!("  settings:   {}{}", settings.display(), if settings.exists() { "" } else { "  (none yet: the console's Settings tab writes it)" });
    unsafe { libc::signal(libc::SIGINT, on_signal as libc::sighandler_t); libc::signal(libc::SIGTERM, on_signal as libc::sighandler_t); }
    while !STOP.load(Ordering::Relaxed) && !sqzdb::ui::restart_requested() { std::thread::sleep(Duration::from_millis(100)); }
    let t = Instant::now(); let st = sql.snapshot(); sql.close();
    println!("\nstopped: final snapshot of {} rows in {:.0} ms", st.rows, t.elapsed().as_secs_f64() * 1e3);
    if sqzdb::ui::restart_requested() && !STOP.load(Ordering::Relaxed) {
        // the console asked: this same command again, in this process (its id, and a service manager's view of it,
        // stay), now with the settings saved
        use std::os::unix::process::CommandExt;
        println!("restarting with the settings in {}", settings.display());
        let mut c = std::process::Command::new(std::env::current_exe().unwrap_or_else(|_| "sqzdb".into()));
        c.args(std::env::args_os().skip(1));
        if let Some(t) = &printed_token { c.env("SQZDB_RESTART_TOKEN", t); }
        fail(format!("restart: {}", c.exec()));
    }
}

/// `deploy <folder> <dir | host:port --token t>`: the folder's functions, as one `DEPLOY FUNCTIONS` statement.
fn deploy(a: &[String]) {
    let (Some(folder), Some(target)) = (a.first().filter(|s| !s.starts_with("--")), a.get(1).filter(|s| !s.starts_with("--"))) else { usage() };
    let files = sqzdb::functions::read_folder(std::path::Path::new(folder)).unwrap_or_else(|e| fail(e));
    let text = format!("{}{}", sqzdb::functions::FUNCTIONS_META, json!({"files": files.iter().cloned().collect::<std::collections::BTreeMap<String, String>>()}));
    let rows = if !std::path::Path::new(target).exists() && target.contains(':') {
        let token = flag(a, "--token").unwrap_or_else(|| usage());
        Client::connect_tcp(target, &token).unwrap_or_else(|e| fail(format!("{target}: {e}"))).exec(&text, &[]).unwrap_or_else(|e| fail(e))
    } else {
        let sql = Sql::open_with(std::path::Path::new(target), Config { create: false, ..Config::default() }).unwrap_or_else(|e| fail(e));
        let r = sql.exec_s(&mut Session::default(), &text, &[]).unwrap_or_else(|e| fail(e)); sql.close(); r
    };
    let names: Vec<String> = rows.iter().filter_map(|r| match r.first() { Some(Value::Text(n)) => Some(n.clone()), _ => None }).collect();
    println!("deployed {} function{} from {} ({} file{}): {}", names.len(), if names.len() == 1 { "" } else { "s" }, folder, files.len(), if files.len() == 1 { "" } else { "s" }, names.join(", "));
}

enum Conn { Local(Arc<Sql>, Session), Remote(Client) }
fn shell(a: &[String]) {
    let target = a.first().filter(|s| !s.starts_with("--")).cloned().unwrap_or_else(|| usage());
    let mut conn = if !std::path::Path::new(&target).exists() && target.contains(':') {
        let token = flag(a, "--token").unwrap_or_else(|| usage());
        Conn::Remote(Client::connect_tcp(&target, &token).unwrap_or_else(|e| fail(format!("{target}: {e}"))))
    } else { Conn::Local(Sql::open_with(std::path::Path::new(&target), Config::default()).unwrap_or_else(|e| fail(e)), Session::default()) };
    let mut out = std::io::stdout(); let stdin = std::io::stdin(); let mut buf = String::new();
    eprintln!("sqzdb shell: statements end with ';'   .tables   .quit");
    loop {
        eprint!("{}", if buf.is_empty() { "sqzdb> " } else { "      ... " }); let _ = std::io::stderr().flush();
        let mut line = String::new(); if stdin.lock().read_line(&mut line).unwrap_or(0) == 0 { break; }
        let l = line.trim();
        if buf.is_empty() && l.starts_with('.') { match l { ".quit" | ".exit" => break, ".tables" => { let t = Instant::now(); match &mut conn { Conn::Local(s, _) => { let rows: Vec<Vec<Value>> = s.db.table_names().into_iter().map(|n| vec![Value::Text(n)]).collect(); print_rows(&mut out, &[("table".into(), None)], &rows, t.elapsed()) } Conn::Remote(_) => eprintln!(".tables is not available over TCP yet; query the console's /api/tables") } } other => eprintln!("unknown command {other}") } continue; }
        if l.starts_with("--") { continue; }   // a comment line (lines are joined with spaces: it would swallow the next)
        buf.push_str(l); buf.push(' ');
        if !l.ends_with(';') { continue; }
        let text = buf.trim().trim_end_matches(';').trim().to_string(); buf.clear(); if text.is_empty() { continue; }
        let t = Instant::now();
        match &mut conn {
            Conn::Local(s, sess) => match s.query(sess, &text, &[]) { Ok((cols, rows)) => print_rows(&mut out, &cols, &rows, t.elapsed()), Err(e) => eprintln!("error [{}]: {e}", sqzdb::sql::error_code(&e)) },
            Conn::Remote(c) => match c.exec(&text, &[]) { Ok(rows) => print_rows(&mut out, &[], &rows, t.elapsed()), Err(e) => eprintln!("error [{}]: {e}", sqzdb::sql::error_code(&e)) },
        }
    }
}
fn show(v: &Value, ty: Option<&ColType>) -> String { match v { Value::Null => "NULL".into(), Value::Int(i) => if matches!(ty, Some(ColType::Timestamp)) { format_timestamp(*i) } else { i.to_string() }, Value::Float(f) => format!("{f}"), Value::Bool(b) => b.to_string(), Value::Text(s) => s.clone(), Value::Bytes(b) => format!("0x{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>()) } }
fn print_rows(out: &mut impl Write, cols: &[(String, Option<ColType>)], rows: &[Vec<Value>], el: Duration) {
    let ncol = cols.len().max(rows.first().map(|r| r.len()).unwrap_or(0));
    let cells: Vec<Vec<String>> = rows.iter().map(|r| r.iter().enumerate().map(|(i, v)| show(v, cols.get(i).and_then(|c| c.1.as_ref()))).collect()).collect();
    let head: Vec<String> = (0..ncol).map(|i| cols.get(i).map(|c| c.0.clone()).unwrap_or_else(|| format!("col{i}"))).collect();
    let width: Vec<usize> = (0..ncol).map(|i| cells.iter().map(|r| r.get(i).map(|s| s.chars().count()).unwrap_or(0)).chain(std::iter::once(head[i].chars().count())).max().unwrap_or(0).min(60)).collect();
    if ncol > 0 { let _ = writeln!(out, "{}", head.iter().enumerate().map(|(i, h)| format!("{:<w$}", h, w = width[i])).collect::<Vec<_>>().join("  ")); let _ = writeln!(out, "{}", width.iter().map(|w| "-".repeat(*w)).collect::<Vec<_>>().join("  ")); }
    for r in &cells { let _ = writeln!(out, "{}", r.iter().enumerate().map(|(i, c)| { let c: String = c.chars().take(60).collect(); format!("{:<w$}", c, w = width[i]) }).collect::<Vec<_>>().join("  ")); }
    let _ = writeln!(out, "({} row{}, {:.2} ms)", rows.len(), if rows.len() == 1 { "" } else { "s" }, el.as_secs_f64() * 1e3);
}
