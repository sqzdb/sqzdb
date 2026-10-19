//! Experiment 64: TEXT of any length. Writes and reads of 2 KB, 256 KB and 4 MB values against SQLite (WAL,
//! synchronous=NORMAL: the fsync follows, as sqweezdb's default does); an update of another column of a row holding a
//! 256 KB value (and the log it writes); memory per row for short text and for 1 KB values; a restart with 500 MB of
//! values; replaced values freed.
use sqweezdb::config::{Config, SnapshotPolicy};
use sqweezdb::sql::{Session, Sql};
use sqweezdb::table::Value;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const ROOT: &str = "data/nocow/e64";
fn fresh(name: &str) -> PathBuf { let p = Path::new(ROOT).join(name); let _ = std::fs::remove_dir_all(&p); std::fs::create_dir_all(Path::new(ROOT)).unwrap(); p }
fn open(dir: &Path) -> std::sync::Arc<Sql> { Sql::open_with(dir, Config { snapshot: SnapshotPolicy { log_bytes: None, idle_after: None }, ..Config::default() }).unwrap() }
fn app(sql: &Sql, q: &str, p: &[Value]) -> Vec<Vec<Value>> { sql.exec_s(&mut Session::default(), q, p).unwrap_or_else(|e| panic!("{q}: {e}")) }
fn text(n: usize, seed: usize) -> String { (0..n).map(|k| (b'a' + ((k * 31 + seed * 7 + k / 97) % 26) as u8) as char).collect() }
/// (anonymous, file-backed) resident MB
fn rss_split() -> (f64, f64) { let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default(); let get = |k: &str| s.lines().find(|l| l.starts_with(k)).and_then(|l| l.split_whitespace().nth(1)?.parse::<f64>().ok()).unwrap_or(0.0) / 1024.0; (get("RssAnon:"), get("RssFile:")) }
fn rss_mb() -> f64 { std::fs::read_to_string("/proc/self/status").ok().and_then(|s| s.lines().find(|l| l.starts_with("VmRSS:")).and_then(|l| l.split_whitespace().nth(1)?.parse::<f64>().ok())).unwrap_or(0.0) / 1024.0 }
fn log_bytes(dir: &Path) -> u64 { std::fs::read_dir(dir).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().starts_with("log.")).map(|e| e.metadata().unwrap().len()).sum() }
fn us(d: Duration, n: usize) -> f64 { d.as_secs_f64() * 1e6 / n as f64 }

fn main() {
    println!("=== E64: TEXT of any length ===");
    // ---- (c) memory: the row's field for short text, and values past it
    let d = fresh("c"); let sql = open(&d);
    app(&sql, "CREATE TABLE fixed (id INT PRIMARY KEY, name TEXT(255))", &[]); app(&sql, "CREATE TABLE any (id INT PRIMARY KEY, name TEXT)", &[]);
    let (a, b) = (sql.db.table("fixed").unwrap(), sql.db.table("any").unwrap());
    println!("(c) a row of (id INT, name ...): {} bytes with name TEXT(255), as TEXT meant before; {} bytes with TEXT (values up to 44 bytes in the row)", a.stride, b.stride);
    drop(a); drop(b);
    app(&sql, "CREATE TABLE docs (id INT PRIMARY KEY, body TEXT)", &[]);
    let ins = sql.prepare("INSERT INTO docs VALUES (?, ?)").unwrap(); let mut s = Session::default(); let rows = 100_000;
    let vals: Vec<String> = (0..64).map(|k| text(1024, k)).collect();
    let r0 = rss_mb(); for i in 0..rows { sql.execute_s(&mut s, &ins, &[Value::Int(i as i64), Value::Text(vals[i % 64].clone())]).unwrap(); } let r1 = rss_mb();
    println!("    100,000 values of 1 KB (98 MB of text), first thing in this process: it grew {:.0} MB, {:.0} bytes per value beyond its 1,024 (the row, its key, the store's entry)", r1 - r0, ((r1 - r0) * 1048576.0 / rows as f64) - 1024.0);
    drop(sql);

    // ---- (a) write, then read back by key
    println!("(a) one at a time, in this process: write a row, then read its value back by key");
    println!("    {:<8} {:>6}   {:>22}   {:>22}", "value", "rows", "sqweezdb write / read", "SQLite write / read");
    for (label, size, rows) in [("2 KB", 2 << 10, 20_000usize), ("256 KB", 256 << 10, 2_000), ("4 MB", 4 << 20, 100)] {
        let vals: Vec<String> = (0..16).map(|s| text(size, s)).collect();
        let d = fresh(&format!("a-{size}")); let sql = open(&d); app(&sql, "CREATE TABLE t (id INT PRIMARY KEY, n INT, body TEXT)", &[]);
        let ins = sql.prepare("INSERT INTO t VALUES (?, 0, ?)").unwrap(); let get = sql.prepare("SELECT body FROM t WHERE id = ?").unwrap(); let mut s = Session::default();
        let t = Instant::now(); for i in 0..rows { sql.execute_s(&mut s, &ins, &[Value::Int(i as i64), Value::Text(vals[i % 16].clone())]).unwrap(); } let w = t.elapsed();
        let t = Instant::now(); for i in 0..rows { let r = sql.execute_s(&mut s, &get, &[Value::Int(i as i64)]).unwrap(); assert!(matches!(&r[0][0], Value::Text(b) if b.len() == size)); } let r = t.elapsed();
        drop(sql);
        let lite = d.join("t.sqlite"); let c = rusqlite::Connection::open(&lite).unwrap();
        c.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; CREATE TABLE t (id INTEGER PRIMARY KEY, n INT, body TEXT)").unwrap();
        let t = Instant::now(); { let mut st = c.prepare("INSERT INTO t VALUES (?, 0, ?)").unwrap(); for i in 0..rows { st.execute(rusqlite::params![i as i64, vals[i % 16]]).unwrap(); } } let lw = t.elapsed();
        let t = Instant::now(); { let mut st = c.prepare("SELECT body FROM t WHERE id = ?").unwrap(); for i in 0..rows { let b: String = st.query_row([i as i64], |r| r.get(0)).unwrap(); assert_eq!(b.len(), size); } } let lr = t.elapsed();
        println!("    {label:<8} {rows:>6}   {:>9.1} / {:>8.1} µs   {:>9.1} / {:>8.1} µs", us(w, rows), us(r, rows), us(lw, rows), us(lr, rows));
    }

    // ---- (b) an update of another column of a row with a 256 KB value
    let d = fresh("b"); let sql = open(&d); app(&sql, "CREATE TABLE t (id INT PRIMARY KEY, n INT, body TEXT)", &[]);
    for i in 0..100 { app(&sql, "INSERT INTO t VALUES (?, 0, ?)", &[Value::Int(i), Value::Text(text(256 << 10, i as usize))]); }
    let upd = sql.prepare("UPDATE t SET n = n + 1 WHERE id = ?").unwrap(); let mut s = Session::default();
    std::thread::sleep(Duration::from_millis(200)); let before = log_bytes(&d); let n = 2_000;
    let t = Instant::now(); for i in 0..n { sql.execute_s(&mut s, &upd, &[Value::Int((i % 100) as i64)]).unwrap(); } let el = t.elapsed();
    std::thread::sleep(Duration::from_millis(300)); let per = (log_bytes(&d) - before) as f64 / n as f64;
    let tb = sql.db.table("t").unwrap(); let st = tb.schema.columns[2].store.clone().unwrap();
    println!("(b) UPDATE t SET n = n + 1 on rows holding a 256 KB value: {:.1} µs each; the log grows {:.0} KB per update (the row is logged whole); values in memory stay {} ({:.1} MB)", us(el, n), per / 1024.0, st.len(), st.bytes() as f64 / 1e6);
    let lite = d.join("t.sqlite"); let c = rusqlite::Connection::open(&lite).unwrap();
    c.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; CREATE TABLE t (id INTEGER PRIMARY KEY, n INT, body TEXT)").unwrap();
    { let mut st = c.prepare("INSERT INTO t VALUES (?, 0, ?)").unwrap(); for i in 0..100 { st.execute(rusqlite::params![i as i64, text(256 << 10, i as usize)]).unwrap(); } }
    let wal = |p: &Path| std::fs::metadata(p.with_extension("sqlite-wal")).map(|m| m.len()).unwrap_or(0);
    c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)").unwrap(); let wb = wal(&lite);
    let t = Instant::now(); { let mut st = c.prepare("UPDATE t SET n = n + 1 WHERE id = ?").unwrap(); for i in 0..n { st.execute([(i % 100) as i64]).unwrap(); } } let lel = t.elapsed();
    println!("    SQLite, the same: {:.1} µs each; its WAL grows {:.1} KB per update (the pages that changed)", us(lel, n), (wal(&lite).saturating_sub(wb)) as f64 / n as f64 / 1024.0);
    drop(c); drop(tb); drop(st); drop(sql);

    // ---- (d) restart with 500 MB of values, and (e) replaced values freed
    let d = fresh("d"); let sql = open(&d); app(&sql, "CREATE TABLE t (id INT PRIMARY KEY, body TEXT)", &[]);
    let ins = sql.prepare("INSERT INTO t VALUES (?, ?)").unwrap(); let mut s = Session::default();
    let vals: Vec<String> = (0..16).map(|k| text(256 << 10, k)).collect();
    for i in 0..2_000 { sql.execute_s(&mut s, &ins, &[Value::Int(i as i64), Value::Text(vals[i % 16].clone())]).unwrap(); }
    let t = Instant::now(); let snap = sql.snapshot(); let ts = t.elapsed(); drop(sql);
    let r0 = rss_split(); let t = Instant::now(); let sql = open(&d); let to = t.elapsed(); let r1 = rss_split();
    let t = Instant::now(); let ok = app(&sql, "SELECT count(*), sum(length(body)) FROM t", &[]); let tq = t.elapsed(); let r2 = rss_split();
    println!("(d) 2,000 values of 256 KB (524 MB): snapshot {:.2} s ({:.0} MB). Reopen {:.3} s: memory +{:.0} MB, file pages mapped +{:.0} MB (the values stay in the snapshot's mapping)", ts.as_secs_f64(), snap.bytes as f64 / 1e6, to.as_secs_f64(), r1.0 - r0.0, r1.1 - r0.1);
    println!("    reading every value ({:.2} s): memory +{:.0} MB, file pages +{:.0} MB, which the kernel can drop and read again; {:?}", tq.as_secs_f64(), r2.0 - r1.0, r2.1 - r1.1, ok[0]);
    let st = sql.db.table("t").unwrap().schema.columns[1].store.clone().unwrap();
    let upd = sql.prepare("UPDATE t SET body = ? WHERE id = ?").unwrap(); let before = st.bytes();
    let t = Instant::now(); for i in 0..2_000 { sql.execute_s(&mut s, &upd, &[Value::Text(vals[(i + 1) % 16].clone()), Value::Int(i as i64)]).unwrap(); } let tu = t.elapsed();
    let peak = st.bytes(); let t = Instant::now(); while st.bytes() > before + (1 << 20) && t.elapsed() < Duration::from_secs(10) { std::thread::sleep(Duration::from_millis(20)); sqweezdb::table::reclaim(); }
    println!("(e) each value replaced ({:.0} µs per UPDATE): values held {:.0} MB -> {:.0} MB at most -> {:.0} MB {:.1} s later (freed once no reader can hold them)", us(tu, 2_000), before as f64 / 1e6, peak as f64 / 1e6, st.bytes() as f64 / 1e6, t.elapsed().as_secs_f64());
    drop(st); drop(sql);
    let _ = std::fs::remove_dir_all(ROOT);
}
