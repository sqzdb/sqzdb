//! Experiment 53: a database per agent. 10,000 agents, each with its own database: created on demand with a schema, 20
//! memories written one at a time, the last 10 read back; then all agents open at once (memory per agent), random agents
//! working from 8 threads, every agent closed and reopened, disk per agent. sqzdb's tenant host, SQLite and Turso
//! 0.8.3 with a file per agent, and PocketBase with a process per agent (how PocketHost isolates tenants). Each engine runs
//! in its own child process so memory is measured cleanly, and every phase starts after a sync() and a pause.
//! Sync settings: SQLite and Turso run with synchronous=OFF (they never fsync); ours does not wait for fsync either but
//! by default fsyncs every write within half a millisecond, and is also run with log.syncDelay = 1 s (one fsync per
//! agent per second at most).
use rusqlite::{params, Connection};
use sqzdb::sql::Session;
use sqzdb::table::Value;
use sqzdb::tenants::TenantHost;
use sqzdb::util::Rng;
use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MEMS: i64 = 20;
/// E53_N (agents, default 10,000), E53_ROOT (default data/nocow/e53), E53_IDLE_MS (our log threads' idle exit, default 300).
fn env_or<T: std::str::FromStr>(k: &str, d: T) -> T { std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d) }
static NA_: std::sync::OnceLock<usize> = std::sync::OnceLock::new(); static ROOT_: std::sync::OnceLock<String> = std::sync::OnceLock::new();
#[allow(non_snake_case)] fn NA() -> usize { *NA_.get_or_init(|| env_or("E53_N", 10_000)) }
#[allow(non_snake_case)] fn ROOT() -> &'static str { ROOT_.get_or_init(|| env_or("E53_ROOT", "data/nocow/e53".to_string())) }
const INIT: &[&str] = &["CREATE TABLE memories (id SERIAL PRIMARY KEY, kind VARCHAR(16), body VARCHAR(400), at TIMESTAMP DEFAULT now())"];
const LAST10: &str = "SELECT id, body FROM memories ORDER BY id DESC LIMIT 10";
fn body(a: usize, m: i64) -> String { format!("agent {a} noted step {m}: the user prefers short answers and wants the report by Friday") }
fn rss_mb() -> f64 { let s = fs::read_to_string("/proc/self/status").unwrap(); s.lines().find(|l| l.starts_with("VmRSS:")).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse::<f64>().ok()).unwrap() / 1024.0 }
fn rss_of(pid: u32) -> f64 { fs::read_to_string(format!("/proc/{pid}/status")).ok().and_then(|s| s.lines().find(|l| l.starts_with("VmRSS:")).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse::<f64>().ok())).unwrap_or(0.0) / 1024.0 }
fn du_kb(p: &PathBuf) -> f64 { let o = Command::new("du").args(["-sk", p.to_str().unwrap()]).output().unwrap(); String::from_utf8_lossy(&o.stdout).split_whitespace().next().unwrap_or("0").parse().unwrap_or(0.0) }
fn line(e: &str, what: &str, v: String) { let e = if e == "sqzdb" { match delay() { Some(d) => format!("sqzdb {}ms", d.as_millis()), None => e.to_string() } } else { e.to_string() }; println!("{e:<15} {what:<46} {v}"); }
unsafe extern "C" { fn malloc_trim(pad: usize) -> i32; }
/// Flush the page cache and wait, so one phase's writeback does not stall the next (E50's lesson), then return freed heap.
static SPLIT: [AtomicU64; 3] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];
/// E53_SYNC_DELAY_MS: our log.syncDelay (0, the default, fsyncs each write right away).
fn delay() -> Option<Duration> { match env_or("E53_SYNC_DELAY_MS", 0u64) { 0 => None, ms => Some(Duration::from_millis(ms)) } }
fn settle() { unsafe { libc::sync(); } std::thread::sleep(Duration::from_secs(5)); unsafe { malloc_trim(0); } }

fn ours() {
    let root = PathBuf::from(format!("{}/ours", ROOT())); let _ = fs::remove_dir_all(&root);
    let mut host = TenantHost::new(&root, NA() + 1, Duration::from_millis(env_or("E53_IDLE_MS", 300)), false); host.sync_delay = delay();
    let host = Arc::new(host);
    let r0 = rss_mb(); let t0 = Instant::now();
    for a in 0..NA() {
        let s = host.get(&format!("a{a:05}"), INIT).unwrap(); let mut se = Session::default();
        for m in 1..=MEMS { s.exec_s(&mut se, "INSERT INTO memories (kind, body) VALUES ('note', ?)", &[Value::Text(body(a, m))]).unwrap(); }
        assert_eq!(s.exec_s(&mut se, LAST10, &[]).unwrap().len(), 10);
    }
    let spawn = t0.elapsed(); settle();
    line("sqzdb", "spawn: create + schema + 20 writes + read", format!("{:.0} us per agent ({:.2} s for {})", spawn.as_secs_f64() * 1e6 / NA() as f64, spawn.as_secs_f64(), NA()));
    line("sqzdb", "memory with every agent open", format!("{:.0} KB per agent ({:.0} MB for {})", (rss_mb() - r0) * 1024.0 / NA() as f64, rss_mb() - r0, NA()));
    line("sqzdb", "disk per agent (20 memories)", format!("{:.1} KB", du_kb(&root) / NA() as f64));
    let work = |host: &Arc<TenantHost>| -> f64 {
        let stop = Arc::new(AtomicBool::new(false)); let ops = Arc::new(AtomicU64::new(0));
        let hs: Vec<_> = (0..8u64).map(|k| { let (host, stop, ops) = (host.clone(), stop.clone(), ops.clone()); std::thread::spawn(move || { let mut rng = Rng(11 + k); let mut se = Session::default();
            while !stop.load(Ordering::Relaxed) { let a = (rng.next() % NA() as u64) as usize; let t0 = Instant::now(); let s = host.get(&format!("a{a:05}"), INIT).unwrap(); let t1 = Instant::now();
                s.exec_s(&mut se, "INSERT INTO memories (kind, body) VALUES ('note', ?)", &[Value::Text(body(a, 99))]).unwrap(); let t2 = Instant::now(); s.exec_s(&mut se, LAST10, &[]).unwrap(); let t3 = Instant::now(); ops.fetch_add(1, Ordering::Relaxed);
                if std::env::var_os("E53_SPLIT").is_some() { SPLIT[0].fetch_add((t1 - t0).as_nanos() as u64, Ordering::Relaxed); SPLIT[1].fetch_add((t2 - t1).as_nanos() as u64, Ordering::Relaxed); SPLIT[2].fetch_add((t3 - t2).as_nanos() as u64, Ordering::Relaxed); } } }) }).collect();
        std::thread::sleep(Duration::from_secs(4)); stop.store(true, Ordering::Relaxed); for h in hs { h.join().unwrap(); } let n = ops.load(Ordering::Relaxed);
        if std::env::var_os("E53_SPLIT").is_some() { eprintln!("split per step: get {:.1} us, insert {:.1} us, last-10 {:.1} us", SPLIT[0].load(Ordering::Relaxed) as f64 / n as f64 / 1e3, SPLIT[1].load(Ordering::Relaxed) as f64 / n as f64 / 1e3, SPLIT[2].load(Ordering::Relaxed) as f64 / n as f64 / 1e3); }
        n as f64 / 4.0 };
    line("sqzdb", "random agents, 8 threads: write + read last 10", format!("{:.0} agent steps/s", work(&host)));
    drop(host); settle();
    // reopen: a fresh host, every agent closed; open 2,000 agents and read their last 10
    let mut host = TenantHost::new(&root, NA() + 1, Duration::from_millis(env_or("E53_IDLE_MS", 300)), false); host.sync_delay = delay(); let host = Arc::new(host); let mut se = Session::default(); let t = Instant::now();
    for a in 0..2000 { let s = host.get(&format!("a{a:05}"), INIT).unwrap(); assert_eq!(s.exec_s(&mut se, LAST10, &[]).unwrap().len(), 10); }
    line("sqzdb", "reopen a closed agent + read last 10", format!("{:.0} us per agent", t.elapsed().as_secs_f64() * 1e6 / 2000.0));
    drop(host);
    let _ = fs::remove_dir_all(&root);
}

fn sqlite() {
    let root = PathBuf::from(format!("{}/sqlite", ROOT())); let _ = fs::remove_dir_all(&root); fs::create_dir_all(&root).unwrap();
    let r0 = rss_mb(); let t0 = Instant::now();
    let mut conns: Vec<std::sync::Mutex<Connection>> = Vec::with_capacity(NA());
    for a in 0..NA() {
        let c = Connection::open(root.join(format!("a{a:05}.db"))).unwrap();
        c.execute_batch("PRAGMA synchronous=OFF; PRAGMA journal_mode=WAL; CREATE TABLE memories (id INTEGER PRIMARY KEY, kind TEXT, body TEXT, at INTEGER DEFAULT (unixepoch('subsec')*1000000));").unwrap();
        { let mut st = c.prepare_cached("INSERT INTO memories (kind, body) VALUES ('note', ?)").unwrap(); for m in 1..=MEMS { st.execute(params![body(a, m)]).unwrap(); } }
        { let mut st = c.prepare_cached(LAST10).unwrap(); assert_eq!(st.query_map([], |r| r.get::<_, i64>(0)).unwrap().count(), 10); }
        c.busy_timeout(Duration::from_secs(10)).unwrap(); conns.push(std::sync::Mutex::new(c));
    }
    let spawn = t0.elapsed(); settle();
    line("sqlite", "spawn: create + schema + 20 writes + read", format!("{:.0} us per agent ({:.2} s for {})", spawn.as_secs_f64() * 1e6 / NA() as f64, spawn.as_secs_f64(), NA()));
    line("sqlite", "memory with every agent open", format!("{:.0} KB per agent ({:.0} MB for {})", (rss_mb() - r0) * 1024.0 / NA() as f64, rss_mb() - r0, NA()));
    line("sqlite", "disk per agent (20 memories)", format!("{:.1} KB", du_kb(&root) / NA() as f64));
    let conns = Arc::new(conns); let stop = Arc::new(AtomicBool::new(false)); let ops = Arc::new(AtomicU64::new(0));
    let hs: Vec<_> = (0..8u64).map(|k| { let (conns, stop, ops) = (conns.clone(), stop.clone(), ops.clone()); std::thread::spawn(move || { let mut rng = Rng(11 + k);
        while !stop.load(Ordering::Relaxed) { let a = (rng.next() % NA() as u64) as usize; let c = conns[a].lock().unwrap();
            c.prepare_cached("INSERT INTO memories (kind, body) VALUES ('note', ?)").unwrap().execute(params![body(a, 99)]).unwrap();
            let _ = c.prepare_cached(LAST10).unwrap().query_map([], |r| r.get::<_, i64>(0)).unwrap().count(); ops.fetch_add(1, Ordering::Relaxed); } }) }).collect();
    std::thread::sleep(Duration::from_secs(4)); stop.store(true, Ordering::Relaxed); for h in hs { h.join().unwrap(); }
    line("sqlite", "random agents, 8 threads: write + read last 10", format!("{:.0} agent steps/s", ops.load(Ordering::Relaxed) as f64 / 4.0));
    drop(conns); settle();
    let t = Instant::now();
    for a in 0..2000 { let c = Connection::open(root.join(format!("a{a:05}.db"))).unwrap(); let mut st = c.prepare(LAST10).unwrap(); assert_eq!(st.query_map([], |r| r.get::<_, i64>(0)).unwrap().count(), 10); }
    line("sqlite", "reopen a closed agent + read last 10", format!("{:.0} us per agent", t.elapsed().as_secs_f64() * 1e6 / 2000.0));
    let _ = fs::remove_dir_all(&root);
}

fn turso() {
    use turso::{Builder, Value as TV};
    let root = PathBuf::from(format!("{}/turso", ROOT())); let _ = fs::remove_dir_all(&root); fs::create_dir_all(&root).unwrap();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let r0 = rss_mb(); let t0 = Instant::now();
    let dbs: Vec<(turso::Database, turso::Connection)> = rt.block_on(async { let mut v = Vec::with_capacity(NA()); for a in 0..NA() {
        let db = Builder::new_local(root.join(format!("a{a:05}.db")).to_str().unwrap()).build().await.unwrap(); let c = db.connect().unwrap();
        c.execute("PRAGMA synchronous = OFF", ()).await.ok();
        c.execute("CREATE TABLE memories (id INTEGER PRIMARY KEY, kind TEXT, body TEXT, at INTEGER)", ()).await.unwrap();
        for m in 1..=MEMS { c.execute("INSERT INTO memories (kind, body, at) VALUES ('note', ?, 0)", vec![TV::Text(body(a, m))]).await.unwrap(); }
        let mut rows = c.query(LAST10, ()).await.unwrap(); let mut n = 0; while rows.next().await.unwrap().is_some() { n += 1; } assert_eq!(n, 10);
        v.push((db, c)); } v });
    let spawn = t0.elapsed(); settle();
    line("turso", "spawn: create + schema + 20 writes + read", format!("{:.0} us per agent ({:.2} s for {})", spawn.as_secs_f64() * 1e6 / NA() as f64, spawn.as_secs_f64(), NA()));
    line("turso", "memory with every agent open", format!("{:.0} KB per agent ({:.0} MB for {})", (rss_mb() - r0) * 1024.0 / NA() as f64, rss_mb() - r0, NA()));
    line("turso", "disk per agent (20 memories)", format!("{:.1} KB", du_kb(&root) / NA() as f64));
    let t = Instant::now(); let mut n = 0u64; let mut rng = Rng(11);
    rt.block_on(async { while t.elapsed() < Duration::from_secs(4) { let a = (rng.next() % NA() as u64) as usize; let c = &dbs[a].1;
        c.execute("INSERT INTO memories (kind, body, at) VALUES ('note', ?, 0)", vec![TV::Text(body(a, 99))]).await.unwrap();
        let mut rows = c.query(LAST10, ()).await.unwrap(); while rows.next().await.unwrap().is_some() {} n += 1; } });
    line("turso", "random agents, 1 thread: write + read last 10", format!("{:.0} agent steps/s", n as f64 / 4.0));
    drop(dbs); settle();
    // Its connections cannot move between threads, so for 8 threads each thread opens and works its own eighth of the agents.
    let go = Arc::new(std::sync::Barrier::new(9)); let stop = Arc::new(AtomicBool::new(false)); let ops = Arc::new(AtomicU64::new(0));
    let hs: Vec<_> = (0..8usize).map(|k| { let (root, go, stop, ops) = (root.clone(), go.clone(), stop.clone(), ops.clone()); std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async { let mut mine = vec![];
            for a in (k..NA()).step_by(8) { let db = Builder::new_local(root.join(format!("a{a:05}.db")).to_str().unwrap()).build().await.unwrap(); let c = db.connect().unwrap(); c.execute("PRAGMA synchronous = OFF", ()).await.ok(); mine.push((a, db, c)); }
            go.wait(); let mut rng = Rng(11 + k as u64);
            while !stop.load(Ordering::Relaxed) { let (a, _, c) = &mine[(rng.next() % mine.len() as u64) as usize];
                c.execute("INSERT INTO memories (kind, body, at) VALUES ('note', ?, 0)", vec![TV::Text(body(*a, 99))]).await.unwrap();
                let mut rows = c.query(LAST10, ()).await.unwrap(); while rows.next().await.unwrap().is_some() {} ops.fetch_add(1, Ordering::Relaxed); } }) }) }).collect();
    go.wait(); std::thread::sleep(Duration::from_secs(4)); stop.store(true, Ordering::Relaxed); for h in hs { h.join().unwrap(); }
    line("turso", "random agents, 8 threads: write + read last 10", format!("{:.0} agent steps/s (each thread owns an eighth of the agents)", ops.load(Ordering::Relaxed) as f64 / 4.0));
    settle();
    let t = Instant::now();
    rt.block_on(async { for a in 0..2000 { let db = Builder::new_local(root.join(format!("a{a:05}.db")).to_str().unwrap()).build().await.unwrap(); let c = db.connect().unwrap();
        let mut rows = c.query(LAST10, ()).await.unwrap(); let mut k = 0; while rows.next().await.unwrap().is_some() { k += 1; } assert_eq!(k, 10); } });
    line("turso", "reopen a closed agent + read last 10", format!("{:.0} us per agent", t.elapsed().as_secs_f64() * 1e6 / 2000.0));
    let _ = fs::remove_dir_all(&root);
}

/// PocketHost's model: a PocketBase process per tenant. Start K of them, time each until /api/health answers, and
/// measure the memory each holds while idle. (No collections or records: this is the floor of a tenant's cost.)
fn pocketbase() {
    const K: usize = 40; const PORT: u16 = 9300;
    let pb = fs::canonicalize("tools/pocketbase-0.40.5/pocketbase").unwrap_or_default(); let pb = pb.to_str().unwrap(); if pb.is_empty() { line("pocketbase", "skipped", "tools/pocketbase-0.40.5/pocketbase not found".into()); return; }
    let root = PathBuf::from(format!("{}/pocketbase", ROOT())); let _ = fs::remove_dir_all(&root); fs::create_dir_all(&root).unwrap();
    let mut kids: Vec<Child> = vec![]; let mut starts = vec![];
    for k in 0..K {
        let dir = root.join(format!("a{k:02}")); let t = Instant::now();
        let child = Command::new(pb).args(["serve", "--http", &format!("127.0.0.1:{}", PORT + k as u16), "--dir", dir.join("pb_data").to_str().unwrap()]).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let addr = format!("127.0.0.1:{}", PORT + k as u16);
        loop { if let Ok(mut s) = std::net::TcpStream::connect(&addr) { use std::io::{Read, Write}; let _ = s.write_all(b"GET /api/health HTTP/1.0\r\n\r\n"); let mut b = String::new(); let _ = s.read_to_string(&mut b); if b.starts_with("HTTP/1.0 200") || b.starts_with("HTTP/1.1 200") { break; } }
            if t.elapsed() > Duration::from_secs(20) { panic!("pocketbase {k} did not start"); } std::thread::sleep(Duration::from_millis(5)); }
        starts.push(t.elapsed().as_secs_f64() * 1e3); kids.push(child);
    }
    std::thread::sleep(Duration::from_secs(3));
    let mem: f64 = kids.iter().map(|c| rss_of(c.id())).sum::<f64>() / K as f64;
    starts.sort_by(|a, b| a.partial_cmp(b).unwrap());
    line("pocketbase", "spawn: start a process until it answers", format!("{:.0} ms per agent (median of {K}), slowest {:.0} ms", starts[K / 2], starts[K - 1]));
    line("pocketbase", "memory per idle process", format!("{:.0} MB per agent ({:.0} MB for {K}; {} would need {:.1} GB)", mem, mem * K as f64, NA(), mem * NA() as f64 / 1024.0));
    for mut c in kids { let _ = c.kill(); let _ = c.wait(); }
    line("pocketbase", "disk per idle agent (empty)", format!("{:.0} KB", du_kb(&root) / K as f64));
    let _ = fs::remove_dir_all(&root);
}

fn main() {
    match std::env::args().nth(1).as_deref() { Some("ours") => return ours(), Some("sqlite") => return sqlite(), Some("turso") => return turso(), Some("pocketbase") => return pocketbase(), _ => {} }
    println!("=== E53: a database per agent, {} agents x {MEMS} memories, each engine in its own process ===", NA());
    for (e, d) in [("ours", "0"), ("ours", "1000"), ("sqlite", "0"), ("turso", "0"), ("pocketbase", "0")] {
        let o = Command::new(std::env::current_exe().unwrap()).arg(e).env("E53_SYNC_DELAY_MS", d).stderr(Stdio::inherit()).output().unwrap(); print!("{}", String::from_utf8_lossy(&o.stdout));
        if !o.status.success() { println!("{e:<10} exited with {:?}", o.status.code()); }
    }
    let _ = fs::remove_dir_all(ROOT());
}
