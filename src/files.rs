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
use crate::sql::{Session, Sql};
use crate::table::{decode_col, encode_row, now_micros, Schema, Value};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

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
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
fn new_id() -> String { let mut b = [0u8; 16]; getrandom::fill(&mut b).expect("random"); b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80; crate::table::format_uuid(&b) }

impl Sql {
    pub fn files_dir(&self) -> PathBuf { self.db.dir.join("files") }
    /// Where a file's bytes are: `files/<first two hex digits>/<id>`. `id` must be a canonical UUID (a FILE value).
    pub fn file_path(&self, id: &str) -> PathBuf { self.files_dir().join(id.get(..2).unwrap_or("00")).join(id) }
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
        Ok(meta)
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
            if ft.delete_by_pk(k).is_ok() { let _ = std::fs::remove_file(self.file_path(&m.id)); since.remove(&m.id); n += 1; bytes += m.size as u64; }
        }
        // staged uploads that never became files
        if let Ok(rd) = std::fs::read_dir(self.files_dir().join("tmp")) {
            for e in rd.flatten() { if e.metadata().and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).is_some_and(|age| age > Duration::from_secs(86_400)) { let _ = std::fs::remove_file(e.path()); } }
        }
        Ok((n, bytes))
    }
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
}
