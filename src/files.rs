//! Files as a column (`FILE`). A FILE column holds a file's id, stored and compared as a UUID; the bytes live in the
//! database's `files/` directory, one file per id, written once and never changed. `_sqz_files`, a system table no
//! SQL can read, records each file's owner, name, type, size and SHA-256.
//!
//! - A write that sets a FILE column checks that the file exists. A signed-in user (not the application) may set it
//!   only to a file they uploaded within the last hour, or keep the one the row has: an id seen in someone else's
//!   row can't be copied into one's own.
//! - Reading goes through the rows: the app API hands out a signed link with each FILE value a query returns
//!   (`app.rs`), so whoever may read the row may fetch the file, under the same policies.
//! - A file no row refers to is deleted once it is a day old and has gone unreferenced for an hour: a scan of every
//!   FILE column, hourly, finds them. A file whose row changes or goes therefore stays up to a day.
//! - With a backup bucket, every file is uploaded to it as it arrives and deleted from it with the file
//!   (`FilesBackup`); a restore brings the files back with the rows.
use crate::cloud::{CloudConfig, CloudStats};
use crate::sql::{Session, Sql};
use crate::table::{decode_col, encode_row, now_micros, Database, Schema, Value};
use object_store::{path::Path as OPath, ObjectStore};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

pub const FILES: &str = "_sqz_files";
const DDL: &str = "CREATE TABLE _sqz_files (id UUID PRIMARY KEY, owner VARCHAR(200) NOT NULL, name VARCHAR(255) NOT NULL, type VARCHAR(127) NOT NULL, size INT NOT NULL, sha256 BYTES(32) NOT NULL, created TIMESTAMP NOT NULL)";
/// How long after its upload a signed-in user may still put a file in a row.
pub const ATTACH_WITHIN_US: i64 = 3600 * 1_000_000;
/// How old an unreferenced file must be, and how long it must have gone unreferenced, before it is deleted.
const KEEP_US: i64 = 24 * 3600 * 1_000_000;
const UNREFERENCED_US: i64 = 3600 * 1_000_000;
const GC_EVERY: Duration = Duration::from_secs(3600);

/// The writer of a statement's FILE values: `None` for the application, else the identity files are owned by.
pub(crate) struct FileWriter(Option<String>);
/// Per database: whether the hourly sweep runs.
#[derive(Default)] pub struct FilesState { gc: AtomicBool }

#[derive(Clone, Debug, PartialEq)] pub struct FileMeta { pub id: String, pub owner: String, pub name: String, pub ctype: String, pub size: i64, pub sha256: [u8; 32], pub created: i64 }

/// A file name as stored: its last path segment, printable, at most 250 bytes.
pub fn clean_name(n: &str) -> String {
    let base = n.rsplit(['/', '\\']).next().unwrap_or("");
    let mut out = String::new();
    for c in base.chars().filter(|c| !c.is_control() && *c != '"') { if out.len() + c.len_utf8() > 250 { break; } out.push(c); }
    let out = out.trim().to_string(); if out.is_empty() { "file".into() } else { out }
}
/// A media type as stored: `type/subtype` in lowercase, or `application/octet-stream`.
pub fn clean_type(t: &str) -> String {
    let t = t.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    if t.len() <= 127 && t.split('/').count() == 2 && !t.starts_with('/') && !t.ends_with('/') && t.bytes().all(|b| b.is_ascii_alphanumeric() || b"/+-.".contains(&b)) { t } else { "application/octet-stream".into() }
}
fn sha256_of(p: &Path) -> std::io::Result<[u8; 32]> {
    use sha2::Digest;
    let mut f = std::fs::File::open(p)?; let (mut h, mut buf) = (sha2::Sha256::new(), vec![0u8; 64 << 10]);
    loop { let n = f.read(&mut buf)?; if n == 0 { return Ok(h.finalize().into()); } h.update(&buf[..n]); }
}
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
fn new_id() -> String { let mut b = [0u8; 16]; getrandom::fill(&mut b).expect("random"); b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80; crate::table::format_uuid(&b) }

impl Sql {
    pub fn files_dir(&self) -> PathBuf { self.db.dir.join("files") }
    /// Where a file's bytes are: `files/<first two hex digits>/<id>`. `id` must be a canonical UUID (a FILE value).
    pub fn file_path(&self, id: &str) -> PathBuf { file_path_in(&self.db.dir, id) }
    fn files_table(&self) -> Result<Arc<crate::table::Table>, String> {
        if let Some(t) = self.db.table(FILES) { return Ok(t); }
        let _one = self.files_lock().lock().unwrap();
        if self.db.table(FILES).is_none() { self.create_system_table(DDL)?; }
        self.db.table(FILES).ok_or_else(|| "files: no _sqz_files".into())
    }
    fn files_lock(&self) -> &'static std::sync::Mutex<()> { static L: std::sync::Mutex<()> = std::sync::Mutex::new(()); &L }

    /// A new file from `src`, at most `max` bytes, owned by whoever `sess` is.
    pub fn file_put(self: &Arc<Self>, sess: &Session, name: &str, ctype: &str, src: &mut dyn Read, max: u64) -> Result<FileMeta, String> {
        let staged = self.file_staging()?;
        let written = (|| -> Result<(u64, [u8; 32]), String> {
            use sha2::Digest;
            let mut f = std::fs::File::create(&staged).map_err(|e| format!("files: {e}"))?; let mut h = sha2::Sha256::new();
            let (mut buf, mut size) = (vec![0u8; 64 << 10], 0u64);
            loop {
                let n = src.read(&mut buf).map_err(|e| format!("files: reading the upload: {e}"))?; if n == 0 { break; }
                size += n as u64; if size > max { return Err(format!("ARGUMENTS: the file is larger than {max} bytes")); }
                h.update(&buf[..n]); f.write_all(&buf[..n]).map_err(|e| format!("files: {e}"))?;
            }
            if self.db.durable { f.sync_all().map_err(|e| format!("files: {e}"))?; }
            Ok((size, h.finalize().into()))
        })();
        match written { Ok((size, sha)) => self.file_add(sess, &staged, name, ctype, size, sha), Err(e) => { let _ = std::fs::remove_file(&staged); Err(e) } }
    }
    /// A fresh path under `files/tmp/` to write a new file to, before `file_add`.
    pub fn file_staging(&self) -> Result<PathBuf, String> {
        let dir = self.files_dir().join("tmp"); std::fs::create_dir_all(&dir).map_err(|e| format!("files: {}: {e}", dir.display()))?;
        let mut b = [0u8; 12]; getrandom::fill(&mut b).expect("random"); Ok(dir.join(hex(&b)))
    }
    /// Record a staged file (written at a `file_staging` path, `size` bytes with this SHA-256) as a new file owned by
    /// whoever `sess` is, and move it into place.
    pub fn file_add(self: &Arc<Self>, sess: &Session, staged: &Path, name: &str, ctype: &str, size: u64, sha256: [u8; 32]) -> Result<FileMeta, String> {
        if !staged.starts_with(self.files_dir().join("tmp")) { return Err("files: a staged file is under files/tmp".into()); }
        let t = self.files_table()?;
        let meta = FileMeta { id: new_id(), owner: self.identity_of(sess), name: clean_name(name), ctype: clean_type(ctype), size: size as i64, sha256, created: now_micros() };
        let dest = self.file_path(&meta.id);
        let placed = std::fs::create_dir_all(dest.parent().unwrap()).and_then(|()| std::fs::rename(staged, &dest));
        if let Err(e) = placed { let _ = std::fs::remove_file(staged); return Err(format!("files: {e}")); }
        if self.db.durable { if let Ok(d) = std::fs::File::open(dest.parent().unwrap()) { let _ = d.sync_all(); } }
        let row = encode_row(&t.schema, &[Value::Text(meta.id.clone()), Value::Text(meta.owner.clone()), Value::Text(meta.name.clone()), Value::Text(meta.ctype.clone()), Value::Int(meta.size), Value::Bytes(sha256.to_vec()), Value::Int(meta.created)])?;
        if let Err(e) = t.insert(&row) { let _ = std::fs::remove_file(&dest); return Err(e.to_string()); }
        self.files_gc_start();
        self.file_to_bucket(&meta.id)?;
        Ok(meta)
    }
    /// Hand a new file to the backup, if there is one; with `durable = "cloud"`, return once it is in the bucket.
    fn file_to_bucket(&self, id: &str) -> Result<(), String> {
        let wait = self.cfg.durable == crate::config::Durability::Cloud;
        let rx = match self.services.lock().unwrap().as_ref().and_then(|s| s.files_backup.as_ref()) { Some(b) => b.put(id, wait), None => return Ok(()) };
        rx.map_or(Ok(()), |rx| rx.recv().unwrap_or_else(|_| Err("files: the backup stopped before the file reached the bucket".into())))
    }
    /// After a bootstrap: keep the downloaded files that are what `_sqz_files` recorded (their SHA-256), and remove the
    /// others, so that the backup's check at start fetches them again (and reports them if the bucket's copy is
    /// wrong). Returns (files checked, files removed).
    pub(crate) fn check_restored_files(&self) -> (usize, usize) {
        let mut rows = HashMap::new();
        if let Some(t) = self.db.table(FILES) { t.scan(|r| { if let Some(m) = meta_of(&t.schema, r) { rows.insert(m.id, m.sha256); } true }); }
        let (mut checked, mut removed) = (0, 0);
        let Ok(dirs) = std::fs::read_dir(self.files_dir()) else { return (0, 0) };
        for d in dirs.flatten().filter(|d| d.file_name() != "tmp" && d.path().is_dir()) {
            for f in std::fs::read_dir(d.path()).into_iter().flatten().flatten() {
                checked += 1;
                let id = f.file_name().to_string_lossy().into_owned();
                if rows.get(&id).is_some_and(|sha| sha256_of(&f.path()).is_ok_and(|h| h == *sha)) { continue; }
                eprintln!("files: {id} from the bucket is not a file this database recorded; removed"); let _ = std::fs::remove_file(f.path()); removed += 1;
            }
        }
        (checked, removed)
    }
    pub fn file_meta(&self, id: &str) -> Option<FileMeta> {
        let t = self.db.table(FILES)?; let k = t.schema.key_from_value(&Value::Text(id.to_string())).ok()?;
        t.with_pk(k, |r| meta_of(&t.schema, r)).flatten()
    }

    /// Who is writing FILE values in a statement, found once: the application, or a signed-in user's identity.
    pub(crate) fn file_writer(&self, sess: &Session) -> FileWriter { FileWriter(sess.user.as_ref().map(|_| self.identity_of(sess))) }
    /// The FILE values a write sets (`new`, replacing `old` for an UPDATE), checked: each file exists, and a
    /// signed-in user sets only files they uploaded within the last hour, or keeps the row's own.
    pub(crate) fn check_files(&self, w: &FileWriter, schema: &Schema, old: Option<&[u8]>, new: &[u8]) -> Result<(), String> {
        for (c, col) in schema.columns.iter().enumerate().filter(|(_, c)| c.file) {
            let Value::Text(id) = decode_col(schema, new, c) else { continue };   // NULL
            if old.is_some_and(|o| decode_col(schema, o, c) == Value::Text(id.clone())) { continue; }   // unchanged
            let m = self.file_meta(&id).ok_or_else(|| format!("NotFound: no file {id} for column {}", col.name))?;
            let Some(me) = &w.0 else { continue };   // the application may set any file
            if m.owner != *me || now_micros() - m.created > ATTACH_WITHIN_US {
                return Err(format!("permission denied: {} may be set to a file you uploaded in the last hour, or left as it is", col.name));
            }
        }
        Ok(())
    }

    /// Start the hourly sweep of unreferenced files (once per database, on its first file or at open).
    pub fn files_gc_start(self: &Arc<Self>) {
        if self.files.gc.swap(true, Ordering::AcqRel) { return; }
        let weak = Arc::downgrade(self);
        std::thread::Builder::new().name("sqweezdb-files".into()).spawn(move || {
            let mut since = HashMap::new(); let mut next = std::time::Instant::now() + Duration::from_secs(60);
            loop {
                std::thread::sleep(Duration::from_secs(1));
                let Some(sql) = weak.upgrade() else { return };
                if std::time::Instant::now() < next { continue; }
                if let Err(e) = sql.files_sweep(now_micros(), &mut since) { eprintln!("files: sweep: {e}"); }
                next = std::time::Instant::now() + GC_EVERY;
            }
        }).expect("a thread");
    }
    /// One sweep at time `now`: delete the files no FILE column refers to that are older than a day and were already
    /// unreferenced an hour ago (`since` remembers when each was first seen unreferenced). Returns (files, bytes) freed.
    pub fn files_sweep(&self, now: i64, since: &mut HashMap<String, i64>) -> Result<(usize, u64), String> {
        let Some(ft) = self.db.table(FILES) else { return Ok((0, 0)) };
        let mut referenced: HashSet<String> = HashSet::new();
        for name in self.db.table_names() {
            let Some(t) = self.db.table(&name) else { continue };
            let cols: Vec<usize> = t.schema.columns.iter().enumerate().filter(|(_, c)| c.file).map(|(i, _)| i).collect();
            if cols.is_empty() { continue; }
            t.scan(|row| { for &c in &cols { if let Value::Text(id) = decode_col(&t.schema, row, c) { referenced.insert(id); } } true });
        }
        let mut gone = vec![];
        ft.scan(|row| {
            if let Some(m) = meta_of(&ft.schema, row) {
                if referenced.contains(&m.id) || now - m.created < KEEP_US { since.remove(&m.id); }
                else if now - *since.entry(m.id.clone()).or_insert(now) >= UNREFERENCED_US { gone.push(m); }
            }
            true
        });
        let (mut n, mut bytes) = (0, 0u64);
        for m in gone {
            let k = ft.schema.key_from_value(&Value::Text(m.id.clone()))?;
            if ft.delete_by_pk(k).is_ok() {
                let _ = std::fs::remove_file(self.file_path(&m.id)); since.remove(&m.id); n += 1; bytes += m.size as u64;
                if let Some(b) = self.services.lock().unwrap().as_ref().and_then(|s| s.files_backup.as_ref()) { b.delete(&m.id); }
            }
        }
        // staged uploads that never became files
        if let Ok(rd) = std::fs::read_dir(self.files_dir().join("tmp")) {
            for e in rd.flatten() { if e.metadata().and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).is_some_and(|age| age > Duration::from_secs(86_400)) { let _ = std::fs::remove_file(e.path()); } }
        }
        Ok((n, bytes))
    }
}
/// Where file `id`'s bytes are in the database directory `dir`: `files/<first two hex digits>/<id>`.
pub fn file_path_in(dir: &Path, id: &str) -> PathBuf { dir.join("files").join(id.get(..2).unwrap_or("00")).join(id) }
/// Copy a database directory's files to another (not uploads still being staged): hard links when both are on one
/// file system, as a file never changes once written, else copies. Returns their bytes.
pub fn copy_files(src: &Path, dest: &Path) -> Result<u64, String> {
    let err = |e: std::io::Error| format!("files: {e}");
    let Ok(dirs) = std::fs::read_dir(src.join("files")) else { return Ok(0) };
    let mut bytes = 0;
    for d in dirs.flatten() {
        if d.file_name() == "tmp" || !d.path().is_dir() { continue; }
        let to = dest.join("files").join(d.file_name()); std::fs::create_dir_all(&to).map_err(err)?;
        for f in std::fs::read_dir(d.path()).map_err(err)?.flatten() {
            if f.path().extension().is_some() { continue; }   // a download in progress (`.part`)
            let t = to.join(f.file_name()); let _ = std::fs::remove_file(&t);
            bytes += f.metadata().map_err(err)?.len();
            if std::fs::hard_link(f.path(), &t).is_err() { std::fs::copy(f.path(), &t).map_err(err)?; }
        }
    }
    Ok(bytes)
}

// ---- files in the backup bucket

/// The files half of the backup (`[backup]`): a new file is uploaded as it arrives (`cloud::put_file`, 8 at a time),
/// and a file the sweep deletes is deleted from the bucket too; closing finishes what is queued unless the bucket fails. At start the bucket is compared with `_sqz_files`:
/// files it lacks are uploaded, files this directory lacks are fetched back, and objects of files that are gone are
/// deleted. Its failures count in the backup's health.
pub struct FilesBackup { q: Arc<(Mutex<Queue>, Condvar)>, stop: Arc<AtomicBool>, thread: Option<std::thread::JoinHandle<()>>, pub stats: Arc<FilesStats> }
/// Since start: files uploaded (and their bytes in the bucket), deleted there, fetched back from it; files waiting; files
/// that are in neither place.
#[derive(Default)] pub struct FilesStats { pub uploaded: AtomicU64, pub bytes: AtomicU64, pub deleted: AtomicU64, pub fetched: AtomicU64, pub pending: AtomicU64, pub missing: AtomicU64 }
/// Fetch carries the SHA-256 `_sqz_files` recorded, which the download must match.
enum Op { Put(String), Delete(String), Fetch(String, OPath, [u8; 32]), Drop(OPath) }
/// Work waiting for the thread, and who waits for which upload (`durable = "cloud"`). `dead` once it can't run.
#[derive(Default)] struct Queue { ops: VecDeque<Op>, waiting: HashMap<String, Vec<mpsc::Sender<Result<(), String>>>>, dead: Option<String> }
const AT_ONCE: usize = 8;

impl FilesBackup {
    pub fn start(db: Arc<Database>, cfg: CloudConfig, health: Arc<CloudStats>) -> FilesBackup {
        match cfg.try_store(3) {
            Ok(store) => FilesBackup::start_with(db, cfg, store, health),
            Err(e) => { let q = Queue { dead: Some(e), ..Default::default() }; FilesBackup { q: Arc::new((Mutex::new(q), Condvar::new())), stop: Default::default(), thread: None, stats: Default::default() } }
        }
    }
    /// The same, with the bucket client given (tests use an in-memory one).
    pub fn start_with(db: Arc<Database>, cfg: CloudConfig, store: Arc<dyn ObjectStore>, health: Arc<CloudStats>) -> FilesBackup {
        let (q, stop, stats) = (Arc::new((Mutex::new(Queue::default()), Condvar::new())), Arc::new(AtomicBool::new(false)), Arc::new(FilesStats::default()));
        let (q2, stop2, st2) = (q.clone(), stop.clone(), stats.clone());
        let thread = std::thread::Builder::new().name("sqweezdb-files-backup".into()).spawn(move || backup_files(&db, &cfg, &*store, &q2, &stop2, &st2, &health)).expect("a thread");
        FilesBackup { q, stop, thread: Some(thread), stats }
    }
    /// Upload a new file; with `wait`, the receiver hears once it is in the bucket.
    pub fn put(&self, id: &str, wait: bool) -> Option<mpsc::Receiver<Result<(), String>>> {
        let (m, cv) = &*self.q; let mut q = m.lock().unwrap();
        let rx = wait.then(|| { let (tx, rx) = mpsc::channel(); match &q.dead { Some(e) => { let _ = tx.send(Err(format!("files: no backup: {e}"))); } None => q.waiting.entry(id.into()).or_default().push(tx) } rx });
        if q.dead.is_none() { q.ops.push_back(Op::Put(id.into())); self.stats.pending.store(q.ops.len() as u64, Ordering::Relaxed); cv.notify_all(); }
        rx
    }
    /// Delete a file from the bucket.
    pub fn delete(&self, id: &str) { let (m, cv) = &*self.q; let mut q = m.lock().unwrap(); q.ops.push_back(Op::Delete(id.into())); self.stats.pending.store(q.ops.len() as u64, Ordering::Relaxed); cv.notify_all(); }
}
impl Drop for FilesBackup {
    fn drop(&mut self) {
        // under the queue's lock, so the thread is either before its check of `stop` or already waiting
        { let _q = self.q.0.lock().unwrap(); self.stop.store(true, Ordering::Relaxed); } self.q.1.notify_all();
        if let Some(h) = self.thread.take() { h.join().ok(); }
        for (_, ws) in self.q.0.lock().unwrap().waiting.drain() { for w in ws { let _ = w.send(Err("files: the database closed before the file reached the bucket".into())); } }
    }
}

fn backup_files(db: &Database, cfg: &CloudConfig, store: &dyn ObjectStore, q: &(Mutex<Queue>, Condvar), stop: &AtomicBool, st: &FilesStats, health: &CloudStats) {
    let rt = crate::cloud::rt(); let mut failures = 0u32;
    // at start: what the bucket holds against what the database holds (until the bucket answers)
    loop {
        if stop.load(Ordering::Relaxed) { return; }
        match rt.block_on(crate::cloud::list_files(store, cfg)) {
            Ok(listed) => { health.contact(); reconcile(db, cfg, listed, q, st); break; }
            Err(e) => { health.fail(format!("listing the files in the bucket: {e}")); failures += 1; if !pause(stop, failures) { return; } }
        }
    }
    failures = 0;
    loop {
        let batch: Vec<Op> = {
            let mut g = q.0.lock().unwrap();
            while g.ops.is_empty() && !stop.load(Ordering::Relaxed) { g = q.1.wait(g).unwrap(); }
            // closing: finish what is queued, as the log's uploader does (and give up at the first failure, below)
            if g.ops.is_empty() { return; }
            let n = g.ops.len().min(64); g.ops.drain(..n).collect()
        };
        let done: Vec<(Op, Result<Option<u64>, String>)> = rt.block_on(async {
            use futures_util::StreamExt;
            futures_util::stream::iter(batch).map(|op| async move { let r = run(db, cfg, store, &op, st).await; (op, r) }).buffer_unordered(AT_ONCE).collect().await
        });
        let (mut error, mut put) = (None, false); let mut g = q.0.lock().unwrap();
        for (op, r) in done {
            match (r, op) {
                (Ok(Some(n)), Op::Put(id)) => { put = true; st.uploaded.fetch_add(1, Ordering::Relaxed); st.bytes.fetch_add(n, Ordering::Relaxed); for w in g.waiting.remove(&id).unwrap_or_default() { let _ = w.send(Ok(())); } }
                (Ok(None), Op::Put(id)) => { for w in g.waiting.remove(&id).unwrap_or_default() { let _ = w.send(Err(format!("files: {id} is gone"))); } }
                (Ok(Some(_)), Op::Delete(_) | Op::Drop(_)) => { st.deleted.fetch_add(1, Ordering::Relaxed); }
                (Ok(Some(_)), Op::Fetch(..)) => { st.fetched.fetch_add(1, Ordering::Relaxed); }
                (Ok(_), _) => {}   // given up (reported)
                (Err(e), op) => { error = Some(e); g.ops.push_front(op); }   // again, after a pause
            }
        }
        st.pending.store(g.ops.len() as u64, Ordering::Relaxed); drop(g);
        match error {
            None => { if put { health.uploaded(); } else { health.contact(); } failures = 0; }
            Some(e) => { health.fail(e); failures += 1; if !pause(stop, failures) { return; } }   // closing: give up
        }
    }
}
/// One piece of work: Ok with the bytes moved, Ok(None) when there is nothing it could do (reported), Err to try again.
async fn run(db: &Database, cfg: &CloudConfig, store: &dyn ObjectStore, op: &Op, st: &FilesStats) -> Result<Option<u64>, String> {
    match op {
        Op::Put(id) => {
            let path = file_path_in(&db.dir, id);
            // deleted before it got there (the bucket was down for a day): nothing to upload
            if !path.exists() { st.missing.fetch_add(1, Ordering::Relaxed); eprintln!("files: {id} left {} before reaching the bucket", db.dir.display()); return Ok(None); }
            crate::cloud::put_file(store, cfg, id, &path).await.map(Some)
        }
        Op::Delete(id) => crate::cloud::delete_file(store, cfg, id).await.map(|()| Some(0)),
        Op::Fetch(id, key, sha) => match crate::cloud::get_file(store, cfg, key, &file_path_in(&db.dir, id), Some(sha)).await {
            Ok(n) => Ok(Some(n)),
            Err(crate::cloud::FetchError::Retry(e)) => Err(e),
            // damaged or altered in the bucket: fetching it again won't help
            Err(crate::cloud::FetchError::Refused(e)) => { st.missing.fetch_add(1, Ordering::Relaxed); eprintln!("files: {id} was not fetched back: {e}"); Ok(None) }
        },
        Op::Drop(key) => crate::cloud::delete_object(store, key).await.map(|()| Some(0)),
    }
}
/// Queue what makes the bucket and `_sqz_files` agree.
fn reconcile(db: &Database, cfg: &CloudConfig, listed: Vec<(String, OPath)>, q: &(Mutex<Queue>, Condvar), st: &FilesStats) {
    // no file was ever uploaded here: leave the bucket alone (it may not be this database's)
    let Some(t) = db.table(FILES) else { return };
    let mut rows = HashMap::new(); t.scan(|r| { if let Some(m) = meta_of(&t.schema, r) { rows.insert(m.id, m.sha256); } true });
    let (mut ops, mut there) = (vec![], HashSet::new());
    for (id, k) in listed {
        // with a passphrase, an object that isn't encrypted is no copy of ours (it was put there before the passphrase
        // was, or by someone else): replaced by an encrypted one
        let plain = cfg.key.is_some() && !crate::cloud::parse_file_key(k.as_ref()).is_some_and(|(_, _, e)| e);
        match rows.get(&id) {
            Some(sha) if !plain => { if there.insert(id.clone()) && !file_path_in(&db.dir, &id).exists() { ops.push(Op::Fetch(id, k, *sha)); } }
            _ => ops.push(Op::Drop(k)),
        }
    }
    let mut missing = 0;
    for id in rows.into_keys() { if !there.contains(&id) { if file_path_in(&db.dir, &id).exists() { ops.push(Op::Put(id)); } else { missing += 1; } } }
    if missing > 0 { st.missing.fetch_add(missing, Ordering::Relaxed); eprintln!("files: {missing} files are neither in {} nor in the bucket", db.dir.display()); }
    let mut g = q.0.lock().unwrap(); g.ops.extend(ops); st.pending.store(g.ops.len() as u64, Ordering::Relaxed); q.1.notify_all();
}
/// After a failure: 1, 2, 4 … up to 30 s, waking early only to stop. False when stopping.
fn pause(stop: &AtomicBool, failures: u32) -> bool {
    let end = Instant::now() + Duration::from_secs(1 << (failures.clamp(1, 6) - 1)).min(Duration::from_secs(30));
    while Instant::now() < end { if stop.load(Ordering::Relaxed) { return false; } std::thread::sleep(Duration::from_millis(50)); }
    !stop.load(Ordering::Relaxed)
}

fn meta_of(s: &Schema, r: &[u8]) -> Option<FileMeta> {
    let t = |c| match decode_col(s, r, c) { Value::Text(x) => Some(x), _ => None };
    let (Value::Int(size), Value::Bytes(sha), Value::Int(created)) = (decode_col(s, r, 4), decode_col(s, r, 5), decode_col(s, r, 6)) else { return None };
    Some(FileMeta { id: t(0)?, owner: t(1)?, name: t(2)?, ctype: t(3)?, size, sha256: sha.try_into().ok()?, created })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::sql::error_code;
    fn tmp(n: &str) -> PathBuf { let d = std::env::temp_dir().join(format!("sqweezdb-files-{}-{n}", std::process::id())); let _ = std::fs::remove_dir_all(&d); d }
    fn q(s: &Sql, sess: &mut Session, sql: &str, p: &[Value]) -> Result<Vec<Vec<Value>>, String> { s.exec_s(sess, sql, p) }
    fn app(s: &Sql, sql: &str) -> Vec<Vec<Value>> { s.exec_s(&mut Session::default(), sql, &[]).unwrap_or_else(|e| panic!("{sql}: {e}")) }
    fn setup(s: &Sql) {
        for st in ["CREATE TABLE users (id SERIAL PRIMARY KEY, email TEXT UNIQUE, role TEXT DEFAULT 'member')", "CREATE ROLE member",
                   "CREATE TABLE notes (id SERIAL PRIMARY KEY, owner INT, body TEXT, attachment FILE)",
                   "GRANT SELECT, INSERT, UPDATE, DELETE ON notes TO member", "CREATE POLICY own ON notes FOR ALL TO member USING (owner = SESSION.id)",
                   "ALTER TABLE users ENABLE AUTH (ROLE FROM role)"] { app(s, st); }
    }
    fn user(s: &Sql, email: &str) -> (Session, i64) {
        let si = s.sign_up("users", &[("email".into(), Value::Text(email.into()))], "the password 1").unwrap();
        let mut sess = Session::default(); s.session_from_token(&mut sess, &si.token).unwrap();
        let Some((_, Value::Int(id))) = si.user.iter().find(|(k, _)| k == "id").cloned() else { panic!() }; (sess, id)
    }
    fn put(s: &Arc<Sql>, sess: &Session, bytes: &[u8]) -> FileMeta { s.file_put(sess, "../../cat.png", "image/PNG; charset=x", &mut &bytes[..], 1 << 20).unwrap() }
    fn text(v: &str) -> Value { Value::Text(v.into()) }

    #[test] fn a_file_goes_into_rows_of_whoever_uploaded_it() {
        let d = tmp("own"); let s = Sql::open_with(&d, Config::default()).unwrap(); setup(&s);
        let (mut ann, a) = user(&s, "ann@x"); let (mut bob, b) = user(&s, "bob@x");
        let f = put(&s, &ann, b"\x89PNG not really");
        assert_eq!((f.name.as_str(), f.ctype.as_str(), f.size), ("cat.png", "image/png", 15), "a name without its path, a type without parameters");
        assert_eq!(std::fs::read(s.file_path(&f.id)).unwrap(), b"\x89PNG not really");
        let ins = "INSERT INTO notes (owner, body, attachment) VALUES (?, ?, ?)";
        q(&s, &mut ann, ins, &[Value::Int(a), text("mine"), text(&f.id)]).unwrap();
        // someone else's file, even one they can see the id of: refused
        let e = q(&s, &mut bob, ins, &[Value::Int(b), text("taken"), text(&f.id)]).unwrap_err(); assert_eq!(error_code(&e), "DENIED", "{e}");
        q(&s, &mut bob, "INSERT INTO notes (owner, body) VALUES (?, 'his')", &[Value::Int(b)]).unwrap();
        let e = q(&s, &mut bob, "UPDATE notes SET attachment = ? WHERE owner = ?", &[text(&f.id), Value::Int(b)]).unwrap_err(); assert_eq!(error_code(&e), "DENIED", "{e}");
        let e = q(&s, &mut bob, "INSERT INTO notes (owner, body, attachment) VALUES (?, 'up', ?) ON CONFLICT (id) DO NOTHING", &[Value::Int(b), text(&f.id)]).unwrap_err(); assert_eq!(error_code(&e), "DENIED", "{e}");
        let e = q(&s, &mut ann, ins, &[Value::Int(a), text("x"), text("01234567-89ab-4def-8123-456789abcdef")]).unwrap_err(); assert_eq!(error_code(&e), "NOT_FOUND", "{e}");
        // the application may use any file; a user keeps a file the row already has
        let g = put(&s, &bob, b"bob's");
        s.exec_s(&mut Session::default(), "INSERT INTO notes (owner, body, attachment) VALUES (?, ?, ?)", &[Value::Int(a), text("given"), text(&g.id)]).unwrap();
        q(&s, &mut ann, "UPDATE notes SET body = 'edited' WHERE body = 'given'", &[]).unwrap();
        // a file uploaded more than an hour ago can't be attached by a user any more
        let old = put(&s, &ann, b"old");
        let t = s.db.table(FILES).unwrap(); let k = t.schema.key_from_value(&text(&old.id)).unwrap();
        t.update_by_pk(k, |r| { let mut r = r.to_vec(); crate::table::encode_col(&t.schema, &mut r, 6, &Value::Int(old.created - ATTACH_WITHIN_US - 1)).map_err(crate::table::Abort::Type)?; Ok(r) }).unwrap();
        assert_eq!(error_code(&q(&s, &mut ann, ins, &[Value::Int(a), text("late"), text(&old.id)]).unwrap_err()), "DENIED");
        // SQL sees ids, never the file records
        assert_eq!(q(&s, &mut ann, "SELECT attachment FROM notes WHERE body = 'mine'", &[]).unwrap(), vec![vec![text(&f.id)]]);
        assert!(s.exec_s(&mut Session::default(), "SELECT * FROM _sqz_files", &[]).unwrap_err().contains("no such table"));
        assert!(!s.db.table_names().iter().any(|n| n == FILES));
    }
    #[test] fn a_file_column_is_no_key_and_has_no_default() {
        let d = tmp("ddl"); let s = Sql::open_with(&d, Config::default()).unwrap();
        for bad in ["CREATE TABLE a (f FILE PRIMARY KEY)", "CREATE TABLE a (id INT PRIMARY KEY, f FILE UNIQUE)", "CREATE TABLE a (id INT PRIMARY KEY, f FILE, UNIQUE (f))", "CREATE TABLE a (id INT PRIMARY KEY, f FILE DEFAULT uuid())"] {
            assert!(s.exec_s(&mut Session::default(), bad, &[]).is_err(), "{bad}");
        }
        app(&s, "CREATE TABLE a (id INT PRIMARY KEY, f FILE, u UUID)");
        assert!(s.exec_s(&mut Session::default(), "ALTER TABLE a ALTER COLUMN f TYPE UUID", &[]).is_err());
        assert!(s.exec_s(&mut Session::default(), "ALTER TABLE a ALTER COLUMN u TYPE FILE", &[]).is_err());
        app(&s, "ALTER TABLE a ADD COLUMN g FILE");
        let cols = |s: &Sql| s.db.table("a").unwrap().schema.columns.iter().map(|c| c.type_name()).collect::<Vec<_>>();
        assert_eq!(cols(&s), ["INT", "FILE", "UUID", "FILE"]);
        drop(s); let s = Sql::open_with(&d, Config::default()).unwrap();
        assert_eq!(cols(&s), ["INT", "FILE", "UUID", "FILE"], "through a restart");
    }
    #[test] fn unreferenced_files_go_after_a_day_and_an_hour() {
        let d = tmp("gc"); let s = Sql::open_with(&d, Config::default()).unwrap(); setup(&s);
        let (mut ann, a) = user(&s, "ann@x");
        let (kept, loose) = (put(&s, &ann, b"kept"), put(&s, &ann, b"loose"));
        q(&s, &mut ann, "INSERT INTO notes (owner, body, attachment) VALUES (?, 'k', ?)", &[Value::Int(a), text(&kept.id)]).unwrap();
        let mut since = HashMap::new(); let now = now_micros();
        assert_eq!(s.files_sweep(now, &mut since).unwrap(), (0, 0), "a fresh upload waits for its row");
        let day = now + KEEP_US + 1;
        assert_eq!(s.files_sweep(day, &mut since).unwrap(), (0, 0), "first seen unreferenced");
        assert_eq!(s.files_sweep(day + UNREFERENCED_US, &mut since).unwrap(), (1, 5), "an hour later: gone");
        assert!(s.file_meta(&loose.id).is_none() && !s.file_path(&loose.id).exists());
        assert!(s.file_meta(&kept.id).is_some() && s.file_path(&kept.id).exists());
        // the row lets go of it: it goes the same way
        q(&s, &mut ann, "UPDATE notes SET attachment = NULL WHERE body = 'k'", &[]).unwrap();
        s.files_sweep(day + 2 * UNREFERENCED_US, &mut since).unwrap();
        assert_eq!(s.files_sweep(day + 3 * UNREFERENCED_US, &mut since).unwrap(), (1, 4));
    }

    // ---- the backup, against an in-memory bucket
    fn bucket(s: &Arc<Sql>, store: &Arc<object_store::memory::InMemory>) -> Arc<FilesStats> {
        let b = FilesBackup::start_with(s.db.clone(), CloudConfig::local("b", "db").with_passphrase("pw"), store.clone(), Arc::new(CloudStats::default()));
        let st = b.stats.clone(); let mut sv = crate::sql::Services::default(); sv.files_backup = Some(b); *s.services.lock().unwrap() = Some(sv); st
    }
    fn in_bucket(store: &object_store::memory::InMemory) -> Vec<String> { let c = CloudConfig::local("b", "db"); crate::cloud::rt().block_on(crate::cloud::list_files(store, &c)).unwrap().into_iter().map(|(id, _)| id).collect() }
    fn until(what: &str, f: impl Fn() -> bool) { let t = Instant::now(); while !f() { assert!(t.elapsed() < Duration::from_secs(10), "waited for {what}"); std::thread::sleep(Duration::from_millis(5)); } }
    #[test] fn files_follow_the_database_into_the_bucket() {
        let d = tmp("bk"); let s = Arc::new(Sql::open_with(&d, Config::default()).unwrap()); setup(&s);
        let store = Arc::new(object_store::memory::InMemory::new()); let st = bucket(&s, &store);
        let (ann, _) = user(&s, "ann@x");
        let (a, b) = (put(&s, &ann, b"first"), put(&s, &ann, &vec![7u8; 900 << 10]));
        until("two uploads", || st.uploaded.load(Ordering::Relaxed) == 2);
        let mut ids = in_bucket(&store); ids.sort(); let mut want = vec![a.id.clone(), b.id.clone()]; want.sort(); assert_eq!(ids, want);
        // the sweep deletes a file: so does the bucket
        let mut since = HashMap::new(); let later = now_micros() + KEEP_US + 1;
        s.files_sweep(later, &mut since).unwrap(); assert_eq!(s.files_sweep(later + UNREFERENCED_US, &mut since).unwrap().0, 2);
        until("two deletes", || st.deleted.load(Ordering::Relaxed) == 2); assert!(in_bucket(&store).is_empty());
        s.close();
    }
    #[test] fn at_start_the_bucket_and_the_directory_are_made_to_agree() {
        let d = tmp("agree"); let s = Arc::new(Sql::open_with(&d, Config::default()).unwrap()); setup(&s);
        let store = Arc::new(object_store::memory::InMemory::new());
        let (ann, _) = user(&s, "ann@x");
        let (up, lost, before) = (put(&s, &ann, b"backed up"), put(&s, &ann, b"lost here"), put(&s, &ann, b"from before the backup"));
        // `up` and `lost` are in the bucket, `before` is not, and an object of a file that is gone is
        let c = CloudConfig::local("b", "db").with_passphrase("pw"); let rt = crate::cloud::rt();
        for f in [&up, &lost] { rt.block_on(crate::cloud::put_file(&*store, &c, &f.id, &s.file_path(&f.id))).unwrap(); }
        let gone = "0123abcd-89ab-4def-8123-456789abcdef"; rt.block_on(crate::cloud::put_file(&*store, &c, gone, &s.file_path(&up.id))).unwrap();
        std::fs::remove_file(s.file_path(&lost.id)).unwrap();
        let st = bucket(&s, &store);
        until("reconciled", || st.uploaded.load(Ordering::Relaxed) == 1 && st.fetched.load(Ordering::Relaxed) == 1 && st.deleted.load(Ordering::Relaxed) == 1);
        let mut ids = in_bucket(&store); ids.sort(); let mut want = vec![up.id.clone(), lost.id.clone(), before.id.clone()]; want.sort(); assert_eq!(ids, want);
        assert_eq!(std::fs::read(s.file_path(&lost.id)).unwrap(), b"lost here", "fetched back");
        // an object altered in the bucket is not fetched back, and not tried again and again
        let c2 = c.clone(); let key = crate::cloud::file_key(&lost.id, false, &c2);
        let other = rt.block_on(async { object_store::ObjectStoreExt::get(&*store, &crate::cloud::file_key(&up.id, false, &c2)).await.unwrap().bytes().await.unwrap() });
        rt.block_on(object_store::ObjectStoreExt::put(&*store, &key, other.into())).unwrap();
        std::fs::remove_file(s.file_path(&lost.id)).unwrap();
        let st = bucket(&s, &store);
        until("refused", || st.missing.load(Ordering::Relaxed) == 1 && st.pending.load(Ordering::Relaxed) == 0);
        assert!(!s.file_path(&lost.id).exists()); assert_eq!(st.fetched.load(Ordering::Relaxed), 0);
        // a plain object with a passphrase set: replaced by an encrypted one
        rt.block_on(object_store::ObjectStoreExt::put(&*store, &crate::cloud::file_key(&up.id, false, &CloudConfig::local("b", "db")), b"plain".to_vec().into())).unwrap();
        let st = bucket(&s, &store);
        until("replaced", || st.deleted.load(Ordering::Relaxed) == 1);
        let keys: Vec<String> = crate::cloud::rt().block_on(crate::cloud::list_files(&*store, &c)).unwrap().into_iter().filter(|(i, _)| *i == up.id).map(|(_, k)| k.as_ref().to_string()).collect();
        assert_eq!(keys.len(), 1); assert!(keys[0].ends_with(".enc"), "{keys:?}");
        // with durable = "cloud", an upload returns once its file is in the bucket
        let rx = s.services.lock().unwrap().as_ref().unwrap().files_backup.as_ref().unwrap().put(&before.id, true).unwrap();
        assert_eq!(rx.recv().unwrap(), Ok(()));
        s.close();
        assert!(FilesBackup::start(s.db.clone(), { let mut c = c.clone(); c.endpoint = "not a url".into(); c }, Arc::new(CloudStats::default())).put(&up.id, true).unwrap().recv().unwrap().is_err(), "no bucket: an error, not a wait");
    }
}
