//! Experiment 63: uploaded files in the backup bucket. A primary with an encrypted `[backup]` takes files; they reach
//! the bucket on their own (photos as they are, text compressed); a new node bootstraps from the bucket with the rows
//! and the files; deletions by the sweep reach the bucket; a restart puts the directory and the bucket back in
//! agreement; with durable = "cloud" an upload returns once its file is in the bucket. Costs: from an upload to the
//! bucket, 1,000 small files, one 50 MB file (and the memory it takes), a bootstrap. Local rclone S3 on 127.0.0.1:9000.
use sqweezdb::cloud::{clear_prefix, list_files, rt};
use sqweezdb::config::{Backup, Config, Durability, SnapshotPolicy};
use sqweezdb::files::FilesStats;
use sqweezdb::sql::{Session, Sql};
use sqweezdb::table::{now_micros, Value};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::{Duration, Instant};

const ROOT: &str = "data/nocow/e63"; const STORE: &str = "data/nocow/s3store"; const S3: &str = "127.0.0.1:9000";
fn backup_in(prefix: &str, bootstrap: bool) -> Backup { Backup { endpoint: format!("http://{S3}"), bucket: "sqweezdb".into(), prefix: prefix.into(), region: "us-east-1".into(), access_key: "minioadmin".into(), secret_key: "minioadmin".into(), passphrase: Some("e63-passphrase".into()), interval: Duration::from_millis(200), compress: true, compact_after: Duration::from_secs(60), compact_every: Duration::from_secs(30), bootstrap } }
fn backup(bootstrap: bool) -> Backup { backup_in("e63", bootstrap) }
fn open(dir: &Path, bootstrap: bool, durable: Durability) -> Arc<Sql> { open_in("e63", dir, bootstrap, durable) }
fn open_in(prefix: &str, dir: &Path, bootstrap: bool, durable: Durability) -> Arc<Sql> { Sql::open_with(dir, Config { backup: Some(backup_in(prefix, bootstrap)), durable, snapshot: SnapshotPolicy { log_bytes: None, idle_after: None }, ..Config::default() }).unwrap() }
fn fresh(name: &str) -> PathBuf { let p = Path::new(ROOT).join(name); let _ = std::fs::remove_dir_all(&p); p }
fn s3_server() -> Option<Child> {
    if TcpStream::connect(S3).is_ok() { return None; }
    std::fs::create_dir_all(format!("{STORE}/sqweezdb")).unwrap();
    let child = Command::new("tools/rclone").args(["serve", "s3", "--addr", S3, "--auth-key", "minioadmin,minioadmin", "--dir-cache-time", "1s", STORE]).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("tools/rclone");
    for _ in 0..100 { if TcpStream::connect(S3).is_ok() { return Some(child); } std::thread::sleep(Duration::from_millis(100)); }
    panic!("rclone did not come up");
}
fn app(sql: &Sql, q: &str, p: &[Value]) -> Vec<Vec<Value>> { sql.exec_s(&mut Session::default(), q, p).unwrap_or_else(|e| panic!("{q}: {e}")) }
fn noise(n: usize) -> Vec<u8> { let mut v = vec![0u8; n]; let mut x = 0x9e3779b97f4a7c15u64; for b in v.iter_mut() { x ^= x << 13; x ^= x >> 7; x ^= x << 17; *b = x as u8; } v }
fn put(sql: &Arc<Sql>, name: &str, ctype: &str, data: &[u8]) -> String { sql.file_put(&Session::default(), name, ctype, &mut &data[..], 1 << 30).unwrap().id }
fn stats(sql: &Sql) -> Arc<FilesStats> { sql.files_backup_stats().unwrap() }
fn until(what: &str, f: impl Fn() -> bool) { let t = Instant::now(); while !f() { assert!(t.elapsed() < Duration::from_secs(120), "waited for {what}"); std::thread::sleep(Duration::from_micros(200)); } }
/// The files in the bucket: id -> key.
fn bucket() -> Vec<(String, String)> { let c = backup(false).cloud(); let store = c.store(); rt().block_on(list_files(&*store, &c)).unwrap().into_iter().map(|(id, k)| (id, k.as_ref().to_string())).collect() }
fn object_size(key: &str) -> u64 { use object_store::ObjectStoreExt; let store = backup(false).cloud().store(); rt().block_on(store.head(&key.into())).unwrap().size }
fn peak_rss_mb() -> f64 { std::fs::read_to_string("/proc/self/status").ok().and_then(|s| s.lines().find(|l| l.starts_with("VmHWM:")).and_then(|l| l.split_whitespace().nth(1)?.parse::<f64>().ok())).unwrap_or(0.0) / 1024.0 }
fn pct(v: &mut [f64], p: f64) -> f64 { v.sort_by(|a, b| a.partial_cmp(b).unwrap()); v[((v.len() as f64 - 1.0) * p) as usize] }
fn caught_up(sql: &Sql) { let seq = sql.current_seq(); let st = sql.backup_stats().unwrap(); until("the log in the bucket", || st.cloud_seq.load(Relaxed) >= seq); until("the files in the bucket", || stats(sql).pending.load(Relaxed) == 0); }

fn main() {
    println!("=== E63: uploaded files in the backup bucket ===");
    let mut s3 = s3_server();
    // (the server's listings lag a deletion by up to a second)
    for p in ["e63", "e63-cloud", "e63-visible"] { clear_prefix(&backup_in(p, false).cloud()); } std::thread::sleep(Duration::from_millis(1500));
    let dir = fresh("primary"); let sql = open(&dir, false, Durability::Visible);
    app(&sql, "CREATE TABLE notes (id SERIAL PRIMARY KEY, body TEXT, attachment FILE)", &[]);

    // ---- (a) what goes up, and how it is stored
    let text: Vec<u8> = (0..60_000).flat_map(|i: u32| format!("{i}: a line of a log file someone attached\n").into_bytes()).collect();
    let (photo, notes) = (put(&sql, "cat.jpg", "image/jpeg", &noise(2 << 20)), put(&sql, "server.log", "text/plain", &text));
    for (body, f) in [("a photo", &photo), ("a log", &notes)] { app(&sql, "INSERT INTO notes (body, attachment) VALUES (?, ?)", &[Value::Text(body.into()), Value::Text(f.clone())]); }
    until("two files", || stats(&sql).uploaded.load(Relaxed) == 2);
    let objs = bucket(); let key = |id: &str| objs.iter().find(|(i, _)| i == id).map(|(_, k)| k.clone()).unwrap();
    let (pk, tk) = (key(&photo), key(&notes));
    println!("(a) a 2 MB photo is stored as {} ({:.2} MB: not compressed again, encrypted)", &pk[pk.find("files/").unwrap()..].replace(&photo, "<id>"), object_size(&pk) as f64 / 1e6);
    println!("    a {:.1} MB log file as {} ({:.2} MB: compressed, then encrypted)", text.len() as f64 / 1e6, &tk[tk.find("files/").unwrap()..].replace(&notes, "<id>"), object_size(&tk) as f64 / 1e6);
    assert!(pk.ends_with(&format!("{photo}.enc")) && tk.ends_with(&format!("{notes}.zst.enc")));

    // ---- (b) costs
    let mut lat = vec![]; let small = noise(100 << 10);
    for _ in 0..200 { let n = stats(&sql).uploaded.load(Relaxed); let t = Instant::now(); put(&sql, "p.jpg", "image/jpeg", &small); until("one file", || stats(&sql).uploaded.load(Relaxed) > n); lat.push(t.elapsed().as_secs_f64() * 1e3); }
    println!("(b) one 100 KB upload until its file is in the bucket: p50 {:.1} ms, p99 {:.1} ms", pct(&mut lat, 0.5), pct(&mut lat, 0.99));
    let n0 = stats(&sql).uploaded.load(Relaxed); let tiny = noise(10 << 10); let t = Instant::now();
    for _ in 0..1000 { put(&sql, "t.bin", "application/octet-stream", &tiny); }
    let took = t.elapsed(); until("1,000 files", || stats(&sql).uploaded.load(Relaxed) == n0 + 1000); let all = t.elapsed();
    println!("    1,000 files of 10 KB, uploaded as fast as they come: written in {:.0} ms, all in the bucket after {:.0} ms ({:.0} files/s)", took.as_secs_f64() * 1e3, all.as_secs_f64() * 1e3, 1000.0 / all.as_secs_f64());
    // generated as it is read, so the experiment itself never holds it
    struct Noise(usize, u64);
    impl std::io::Read for Noise { fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> { let n = b.len().min(self.0); for x in &mut b[..n] { self.1 ^= self.1 << 13; self.1 ^= self.1 >> 7; self.1 ^= self.1 << 17; *x = self.1 as u8; } self.0 -= n; Ok(n) } }
    let before = peak_rss_mb(); let t = Instant::now();
    let id = sql.file_put(&Session::default(), "video.mp4", "video/mp4", &mut Noise(50 << 20, 7), 1 << 30).unwrap().id;
    until("50 MB", || bucket().iter().any(|(i, _)| *i == id) && stats(&sql).pending.load(Relaxed) == 0);
    println!("    one 50 MB video: uploaded and in the bucket after {:.2} s; the process's peak memory grew {:.0} MB meanwhile (it goes up in 8 MB parts)", t.elapsed().as_secs_f64(), peak_rss_mb() - before);

    // ---- (c) a new node from the bucket: rows and files
    caught_up(&sql); let files = app(&sql, "SELECT count(*) FROM notes", &[]); let total = bucket().len(); drop(sql);
    let dir2 = fresh("node"); let t = Instant::now(); let node = open(&dir2, true, Durability::Visible); let el = t.elapsed();
    let same = [&photo, &notes].iter().all(|id| std::fs::read(sqweezdb::files::file_path_in(&dir, id)).unwrap() == std::fs::read(node.file_path(id)).unwrap());
    let here = std::fs::read_dir(dir2.join("files")).unwrap().flatten().filter(|d| d.file_name() != "tmp").map(|d| std::fs::read_dir(d.path()).unwrap().count()).sum::<usize>();
    println!("(c) a new node with an empty directory and bootstrap = true: open in {:.2} s with {} notes and {here} of {total} files, byte for byte the same: {same}", el.as_secs_f64(), match files[0][0] { Value::Int(n) => n, _ => -1 });
    assert!(same && here == total);
    std::thread::sleep(Duration::from_millis(300));
    let s = stats(&node); println!("    it then finds the bucket in agreement: {} uploaded, {} fetched, {} deleted", s.uploaded.load(Relaxed), s.fetched.load(Relaxed), s.deleted.load(Relaxed));
    assert_eq!(s.uploaded.load(Relaxed) + s.fetched.load(Relaxed) + s.deleted.load(Relaxed), 0);

    // ---- (d) deleted files leave the bucket
    app(&node, "DELETE FROM notes WHERE body = 'a photo'", &[]);
    let mut since = std::collections::HashMap::new(); let later = now_micros() + 25 * 3_600_000_000;
    node.files_sweep(later, &mut since).unwrap(); let (gone, bytes) = node.files_sweep(later + 3_600_000_001, &mut since).unwrap();
    until("the deletes", || stats(&node).deleted.load(Relaxed) == gone as u64);
    let left = bucket(); println!("(d) the sweep deletes {gone} files no row refers to ({:.0} MB); the bucket deletes them too: {} files left there, the photo gone: {}", bytes as f64 / 1e6, left.len(), !left.iter().any(|(i, _)| *i == photo));
    assert_eq!(left.len(), total - gone); assert_eq!(left.iter().map(|(i, _)| i.as_str()).collect::<Vec<_>>(), [notes.as_str()]);

    // ---- (e) a restart repairs the difference
    drop(node); std::fs::remove_file(sqweezdb::files::file_path_in(&dir2, &notes)).unwrap();
    let orphan = "0123abcd-89ab-4def-8123-456789abcdef"; { let c = backup(false).cloud(); let store = c.store(); let src = Path::new(ROOT).join("orphan"); std::fs::write(&src, b"no row has me").unwrap(); rt().block_on(sqweezdb::cloud::put_file(&*store, &c, orphan, &src, &Default::default())).unwrap(); }
    let node = open(&dir2, false, Durability::Visible);
    until("agreement", || stats(&node).fetched.load(Relaxed) == 1 && stats(&node).deleted.load(Relaxed) == 1);
    println!("(e) restarted without one of its files, and with an object of a file it never had in the bucket: fetched back {}, deleted {}; the file reads the same: {}", stats(&node).fetched.load(Relaxed), stats(&node).deleted.load(Relaxed), std::fs::read(node.file_path(&notes)).unwrap() == text);
    drop(node);

    // ---- (f) durable = "cloud"
    let dir3 = fresh("cloud"); let c = open_in("e63-cloud", &dir3, false, Durability::Cloud);
    let (mut cl, mut vis) = (vec![], vec![]);
    for _ in 0..100 { let t = Instant::now(); let id = put(&c, "p.jpg", "image/jpeg", &small); cl.push(t.elapsed().as_secs_f64() * 1e3); assert!(sqweezdb::files::file_path_in(&dir3, &id).exists()); }
    let in_bucket = { let c = backup_in("e63-cloud", false).cloud(); let store = c.store(); rt().block_on(list_files(&*store, &c)).unwrap().len() }; drop(c);
    let dir4 = fresh("visible"); let v = open_in("e63-visible", &dir4, false, Durability::Visible);
    for _ in 0..100 { let t = Instant::now(); put(&v, "p.jpg", "image/jpeg", &small); vis.push(t.elapsed().as_secs_f64() * 1e3); }
    drop(v);
    println!("(f) a 100 KB upload returns after {:.2} ms (p50) by default, {:.1} ms with durable = \"cloud\", where every file is in the bucket by then ({in_bucket} of 100)", pct(&mut vis, 0.5), pct(&mut cl, 0.5));
    assert_eq!(in_bucket, 100);

    for p in ["e63", "e63-cloud", "e63-visible"] { clear_prefix(&backup_in(p, false).cloud()); } let _ = std::fs::remove_dir_all(ROOT);
    if let Some(c) = s3.as_mut() { c.kill().ok(); }
}
