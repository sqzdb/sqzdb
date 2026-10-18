//! Continuous backup to any S3-compatible bucket (S3, R2, MinIO, Backblaze, rclone...), restore (optionally to a point
//! in time), and followers that read only the bucket. The on-disk backup format of E26 is uploaded as immutable objects:
//!   snap/{s0:020}                       the snapshot file (self-contained table image + catalog)
//!   log/{segment:020}/{offset:020}      a chunk of a log segment: the bytes [offset, offset+len), complete records
//!   files/{id}                          an uploaded file (a FILE column's bytes), written once (see `put_file`)
//! A chunk is uploaded whenever new records have been written (bounded by `interval`); the active segment grows as a
//! series of chunks; restore concatenates them. Nothing in the bucket is ever rewritten.
use crate::table::{parse_glog, GLog, SNAP_MAGIC};
use object_store::{aws::AmazonS3Builder, path::Path as OPath, ObjectStore, ObjectStoreExt, PutPayload};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct CloudConfig { pub endpoint: String, pub bucket: String, pub prefix: String, pub access_key: String, pub secret_key: String, pub region: String, pub interval: Duration, /// artificial delay before each upload, to mimic a distant cloud on a loopback server
    pub rtt: Duration, /// zstd every object (level 3)
    pub compress: bool, /// merge consecutive chunks older than this into one object (zero disables)
    pub compact_after: Duration, pub compact_every: Duration, /// AES-256-GCM key; every object is encrypted after compression, the bucket provider sees only noise
    pub key: Option<[u8; 32]> }
/// A frame of an encrypted object: [len u32][nonce 12][ciphertext + 16-byte tag]; objects start with "ENC1".
const FRAME: usize = 16 << 20; const ENC_MAGIC: &[u8; 4] = b"ENC1";
fn encrypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    use aes_gcm::{aead::KeyInit, Aes256Gcm};
    let cipher = Aes256Gcm::new(key.into()); let mut out = Vec::with_capacity(data.len() + 64); out.extend_from_slice(ENC_MAGIC);
    for part in data.chunks(FRAME).chain(if data.is_empty() { Some(&data[..]) } else { None }) { seal_frame(&cipher, part, &mut out); }
    out
}
fn decrypt(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    use aes_gcm::{aead::KeyInit, Aes256Gcm};
    if data.len() < 4 || &data[..4] != ENC_MAGIC { return Err("object is not encrypted the way this key expects".into()); }
    let cipher = Aes256Gcm::new(key.into()); let mut out = Vec::with_capacity(data.len()); let mut p = 4;
    while p < data.len() { match open_frame(&cipher, &data[p..])? { Some((pt, n)) => { out.extend(pt); p += n; } None => return Err("truncated encrypted object".into()) } }
    Ok(out)
}
fn seal_frame(cipher: &aes_gcm::Aes256Gcm, part: &[u8], out: &mut Vec<u8>) {
    use aes_gcm::{aead::{Aead, AeadCore, OsRng}, Aes256Gcm};
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); let ct = cipher.encrypt(&nonce, part).unwrap();
    out.extend_from_slice(&(ct.len() as u32).to_le_bytes()); out.extend_from_slice(&nonce); out.extend_from_slice(&ct);
}
/// The frame at the start of `data` decrypted, and the bytes it took; None while `data` holds less than a frame.
fn open_frame(cipher: &aes_gcm::Aes256Gcm, data: &[u8]) -> Result<Option<(Vec<u8>, usize)>, String> {
    use aes_gcm::{aead::Aead, Nonce};
    if data.len() < 16 { return Ok(None); }
    let len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize; if data.len() < 16 + len { return Ok(None); }
    let pt = cipher.decrypt(Nonce::from_slice(&data[4..16]), &data[16..16 + len]).map_err(|_| "object failed authentication: wrong key, or the data was altered in the bucket".to_string())?;
    Ok(Some((pt, 16 + len)))
}
/// Chunk keys: `log/{segment:020}/{offset:020}-{len:020}[.zst]`; they sort like the log, and the uncompressed length is in the name.
pub fn chunk_key(seg: u64, off: u64, len: u64, suffix: &str) -> String { format!("log/{seg:020}/{off:020}-{len:020}{suffix}") }
/// (segment, offset, uncompressed length, compressed?, encrypted?)
pub fn parse_chunk(key: &str) -> Option<(u64, u64, u64, bool, bool)> {
    let mut it = key.rsplit('/'); let name = it.next()?; let seg: u64 = it.next()?.parse().ok()?;
    let e = name.ends_with(".enc"); let name = name.trim_end_matches(".enc"); let z = name.ends_with(".zst"); let name = name.trim_end_matches(".zst");
    match name.split_once('-') { Some((o, l)) => Some((seg, o.parse().ok()?, l.parse().ok()?, z, e)), None => None }
}
fn pack(data: &[u8], cfg: &CloudConfig) -> Vec<u8> { let d = if cfg.compress { zstd::encode_all(data, 3).unwrap() } else { data.to_vec() }; match &cfg.key { Some(k) => encrypt(&d, k), None => d } }
fn unpack(data: &[u8], z: bool, e: bool, cfg: &CloudConfig) -> Result<Vec<u8>, String> {
    let d: Vec<u8> = if e { match &cfg.key { Some(k) => decrypt(data, k)?, None => return Err("object is encrypted and no key was given".into()) } } else { data.to_vec() };
    if z { zstd::decode_all(&d[..]).map_err(|e| format!("object failed to decompress: {e}")) } else { Ok(d) }
}
/// For measurements: the exact bytes an upload would carry, and the reverse.
pub fn pack_bytes(data: &[u8], cfg: &CloudConfig) -> Vec<u8> { pack(data, cfg) }
pub fn unpack_bytes(data: &[u8], cfg: &CloudConfig) -> Result<Vec<u8>, String> { unpack(data, cfg.compress, cfg.key.is_some(), cfg) }
fn flags(key: &str) -> (bool, bool) { let e = key.ends_with(".enc"); let k = key.trim_end_matches(".enc"); (k.ends_with(".zst"), e) }
impl CloudConfig {
    /// Derive the encryption key from a passphrase (SHA-256; a real deployment would use a KDF with a salt).
    pub fn with_passphrase(mut self, pass: &str) -> CloudConfig { use sha2::Digest; let d = sha2::Sha256::digest(pass.as_bytes()); let mut k = [0u8; 32]; k.copy_from_slice(&d); self.key = Some(k); self }
    fn suffix(&self) -> String { format!("{}{}", if self.compress { ".zst" } else { "" }, if self.key.is_some() { ".enc" } else { "" }) }
    /// Local defaults for the lab: an rclone/MinIO server on 127.0.0.1:9000 with minioadmin/minioadmin.
    pub fn local(bucket: &str, prefix: &str) -> CloudConfig { CloudConfig { endpoint: std::env::var("S3_ENDPOINT").unwrap_or("http://127.0.0.1:9000".into()), bucket: bucket.into(), prefix: prefix.into(), access_key: std::env::var("S3_KEY").unwrap_or("minioadmin".into()), secret_key: std::env::var("S3_SECRET").unwrap_or("minioadmin".into()), region: "us-east-1".into(), interval: Duration::from_secs(1), rtt: Duration::ZERO, compress: true, compact_after: Duration::from_secs(60), compact_every: Duration::from_secs(30), key: None } }
    pub fn store(&self) -> Arc<dyn ObjectStore> { self.try_store(3).unwrap() }
    /// The bucket client: 5 s to connect, 2 min per request (8 MB snapshot parts on a slow link), `retries` quick retries
    /// within 30 s. Callers that keep going after an error (the uploader) retry on their own schedule.
    pub fn try_store(&self, retries: usize) -> Result<Arc<dyn ObjectStore>, String> {
        // the client panics while signing a request to an endpoint that is not a URL: refuse it here instead
        check_endpoint(&self.endpoint)?;
        let retry = object_store::RetryConfig { max_retries: retries, retry_timeout: Duration::from_secs(30), ..Default::default() };
        let client = object_store::ClientOptions::new().with_connect_timeout(Duration::from_secs(5)).with_timeout(Duration::from_secs(120)).with_allow_http(true);
        AmazonS3Builder::new().with_endpoint(&self.endpoint).with_bucket_name(&self.bucket).with_access_key_id(&self.access_key).with_secret_access_key(&self.secret_key).with_region(&self.region)
            .with_allow_http(true).with_virtual_hosted_style_request(false).with_retry(retry).with_client_options(client).build().map(|s| Arc::new(s) as Arc<dyn ObjectStore>).map_err(|e| format!("bucket settings: {e}"))
    }
    fn key(&self, rest: &str) -> OPath { OPath::from(format!("{}/{}", self.prefix.trim_matches('/'), rest)) }
}
pub fn rt() -> tokio::runtime::Runtime { tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap() }

/// Counters a running uploader exposes.
#[derive(Default)]
pub struct CloudStats { pub puts: AtomicU64, pub bytes: AtomicU64, pub cloud_seq: AtomicU64, pub snapshots: AtomicU64, pub deletes: AtomicU64, pub last_put_ms: AtomicU64, pub merges: AtomicU64, pub raw_bytes: AtomicU64, pub compress_ms: AtomicU64, pub parts: AtomicU64,
    /// health, in Unix milliseconds: the last call the bucket answered, the last upload, the last failure
    pub ok_at_ms: AtomicU64, pub upload_at_ms: AtomicU64, pub err_at_ms: AtomicU64,
    /// failed calls in a row (0 = working) and in total; `resumed` once the bucket's contents were read at start
    pub failures: AtomicU64, pub failures_total: AtomicU64, pub resumed: AtomicBool, pub last_error: std::sync::Mutex<String> }
impl CloudStats {
    /// The bucket answered: the connection works.
    pub fn contact(&self) { self.ok_at_ms.store(now_ms(), Ordering::Relaxed); self.failures.store(0, Ordering::Relaxed); }
    pub fn uploaded(&self) { self.contact(); self.upload_at_ms.store(now_ms(), Ordering::Relaxed); }
    pub fn fail(&self, e: String) {
        self.failures.fetch_add(1, Ordering::Relaxed); self.failures_total.fetch_add(1, Ordering::Relaxed); self.err_at_ms.store(now_ms(), Ordering::Relaxed);
        let e: String = e.chars().take(600).collect(); *self.last_error.lock().unwrap() = e;
    }
    pub fn last_error(&self) -> String { self.last_error.lock().unwrap().clone() }
    /// "connecting" until the bucket was first read, "healthy", "retrying" after one or two failed calls in a row, then "failing".
    pub fn state(&self) -> &'static str { match self.failures.load(Ordering::Relaxed) { 0 if !self.resumed.load(Ordering::Relaxed) => "connecting", 0 => "healthy", 1 | 2 => "retrying", _ => "failing" } }
}
/// An endpoint must be an http(s) URL with a host: the S3 client panics on anything else.
pub fn check_endpoint(e: &str) -> Result<(), String> {
    let rest = e.strip_prefix("https://").or_else(|| e.strip_prefix("http://")).ok_or_else(|| format!("endpoint {e:?} must start with https:// or http://"))?;
    let host = rest.split('/').next().unwrap_or("");
    if host.is_empty() || host.contains(char::is_whitespace) || host.starts_with(':') { return Err(format!("endpoint {e:?} has no host name")); }
    Ok(())
}
pub fn now_ms() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0) }
/// After a failure: wait 1, 2, 4 … up to 30 s (never less than the upload interval), waking early only to stop. False when stopping.
fn backoff(st: &CloudStats, stop: &AtomicBool, cfg: &CloudConfig) -> bool {
    let n = st.failures.load(Ordering::Relaxed).clamp(1, 6) as u32;
    let end = Instant::now() + cfg.interval.max(Duration::from_secs(1 << (n - 1)).min(Duration::from_secs(30)));
    while Instant::now() < end { if stop.load(Ordering::Relaxed) { return false; } std::thread::sleep(Duration::from_millis(50)); }
    !stop.load(Ordering::Relaxed)
}
/// Check a bucket the way the uploader uses it: list the prefix, write a small object, delete it. Each step with its time
/// in milliseconds and the error, if any; stops at the first failure.
pub fn probe(cfg: &CloudConfig) -> Vec<(&'static str, bool, f64, String)> {
    let mut out = vec![];
    let store = match cfg.try_store(0) { Ok(s) => s, Err(e) => { out.push(("connect", false, 0.0, e)); return out; } };
    let rt = rt(); let ms = |t: Instant| t.elapsed().as_secs_f64() * 1e3;
    let t = Instant::now(); let r = rt.block_on(store.list_with_delimiter(Some(&cfg.key(""))));
    let ok = r.is_ok(); out.push(("list", ok, ms(t), r.err().map(|e| e.to_string()).unwrap_or_default())); if !ok { return out; }
    let key = cfg.key(&format!(".sqweezdb-probe-{}", now_ms()));
    let t = Instant::now(); let r = rt.block_on(store.put(&key, PutPayload::from(b"sqweezdb connection check".to_vec())));
    let ok = r.is_ok(); out.push(("write", ok, ms(t), r.err().map(|e| e.to_string()).unwrap_or_default())); if !ok { return out; }
    let t = Instant::now(); let r = rt.block_on(store.delete(&key));
    out.push(("delete", r.is_ok(), ms(t), r.err().map(|e| e.to_string()).unwrap_or_default()));
    out
}
pub struct Uploader { pub stats: Arc<CloudStats>, stop: Arc<AtomicBool>, thread: Option<std::thread::JoinHandle<()>>, pub kick: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)> }
impl Drop for Uploader { fn drop(&mut self) { self.stop.store(true, Ordering::Relaxed); let (m, cv) = &*self.kick; *m.lock().unwrap() = true; cv.notify_all(); if let Some(h) = self.thread.take() { h.join().ok(); } } }

/// Start continuous backup of a database directory. Every `interval` (or immediately when `kick`ed, which the
/// cloud-durable commit mode does), new bytes of the current segment go up as one chunk and `cloud_seq` advances to
/// the last complete record in the bucket. A new snapshot file is uploaded when it appears; chunks of segments the
/// snapshot made redundant are deleted.
pub fn start_uploader(cfg: CloudConfig, dir: PathBuf, log: Arc<GLog>) -> Uploader {
    let stats = Arc::new(CloudStats::default());
    let stop = Arc::new(AtomicBool::new(false)); let kick = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let (st2, stop2, kick2) = (stats.clone(), stop.clone(), kick.clone());
    let h = std::thread::spawn(move || {
        let rt = rt();
        // bad settings (an endpoint that is not a URL) cannot heal: report them and stay down
        let store = match cfg.try_store(3) { Ok(s) => s, Err(e) => { st2.fail(e); st2.failures.store(u64::MAX / 2, Ordering::Relaxed); return; } };
        let mut cur: Option<(u64, u64)> = None;  // (segment first seq, bytes uploaded so far)
        let mut last_snap: Option<u64> = None;    // s0 of the last uploaded snapshot
        // resume: what the bucket already holds (a fresh uploader must never rewrite a chunk)
        let mut existing: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();
        let (log_keys, snap_keys) = loop {
            let r = rt.block_on(async { Ok::<_, String>((futures_lite_shim::try_list_sized(&*store, &cfg.key("log")).await?, futures_lite_shim::try_list_sized(&*store, &cfg.key("snap")).await?)) });
            match r { Ok(v) => { st2.contact(); st2.resumed.store(true, Ordering::Relaxed); break v; } Err(e) => { st2.fail(format!("reading the bucket: {e}")); if !backoff(&st2, &stop2, &cfg) { return; } } }
        };
        for (k, _) in log_keys { if let Some((seg, off, len, _, _)) = parse_chunk(k.as_ref()) { let e = existing.entry(seg).or_insert(0); *e = (*e).max(off + len); } }
        if let Some((&seg, &done)) = existing.iter().max_by_key(|(s, _)| **s) {
            // the last complete record already in the bucket for the newest segment
            if let Ok(mut f) = File::open(GLog::seg_path_in(&dir, seg)) { let mut buf = vec![0u8; done as usize]; if f.read_exact(&mut buf).is_ok() { let (recs, _) = parse_glog(&buf); if let Some(r) = recs.last() { st2.cloud_seq.store(r.0, Ordering::Relaxed); log.notify_cloud(r.0); } } }
            cur = Some((seg, done));
        }
        for (k, _) in snap_keys { if let Ok(s0) = k.as_ref().rsplit('/').next().unwrap_or("").trim_end_matches(".enc").trim_end_matches(".zst").parse::<u64>() { last_snap = Some(last_snap.unwrap_or(0).max(s0)); } }
        let mut last_compact = Instant::now();
        loop {
            // wait for the interval or a kick
            if st2.failures.load(Ordering::Relaxed) > 0 { if !backoff(&st2, &stop2, &cfg) { return; } }
            else { let (m, cv) = &*kick2; let k = m.lock().unwrap(); let mut k = if !*k { cv.wait_timeout(k, cfg.interval).unwrap().0 } else { k }; *k = false; }
            // stopping: finish what can be finished; while the bucket is failing, give up (the next start resumes from the bucket)
            if stop2.load(Ordering::Relaxed) && (log.st.lock().unwrap().written <= st2.cloud_seq.load(Ordering::Relaxed) || st2.failures.load(Ordering::Relaxed) > 0) { return; }
            let step = (|| -> Result<(), String> {
            // 1. snapshot: upload if a newer one exists
            if let Ok(mut f) = File::open(dir.join("snap")) {
                let mut h = [0u8; 24]; if f.read_exact(&mut h).is_ok() && u64::from_le_bytes(h[..8].try_into().unwrap()) == SNAP_MAGIC {
                    let (low_water, s0) = (u64::from_le_bytes(h[8..16].try_into().unwrap()), u64::from_le_bytes(h[16..24].try_into().unwrap()));
                    if last_snap != Some(s0) {
                        let mut data = Vec::new(); f.seek(SeekFrom::Start(0)).unwrap(); f.read_to_end(&mut data).unwrap();
                        let raw = data.len() as u64; let tc = Instant::now(); let data = pack(&data, &cfg); st2.compress_ms.fetch_add(tc.elapsed().as_millis() as u64, Ordering::Relaxed); let n = data.len() as u64; let t = Instant::now();
                        // multipart upload in 8 MB parts (snapshots can exceed what one PUT may carry)
                        rt.block_on(async { let mut w = object_store::WriteMultipart::new_with_chunk_size(store.put_multipart(&cfg.key(&format!("snap/{s0:020}{}", cfg.suffix()))).await.map_err(|e| format!("uploading the snapshot: {e}"))?, 8 << 20); w.write(&data); w.finish().await.map_err(|e| format!("uploading the snapshot: {e}"))?; Ok::<(), String>(()) })?;
                        st2.uploaded();
                        st2.parts.fetch_add((n as usize).div_ceil(8 << 20) as u64, Ordering::Relaxed);
                        st2.puts.fetch_add(1, Ordering::Relaxed); st2.bytes.fetch_add(n, Ordering::Relaxed); st2.raw_bytes.fetch_add(raw, Ordering::Relaxed); st2.snapshots.fetch_add(1, Ordering::Relaxed); st2.last_put_ms.store(t.elapsed().as_millis() as u64, Ordering::Relaxed); last_snap = Some(s0);
                        // everything below the snapshot's low water is covered by it
                        if low_water > 1 && st2.cloud_seq.load(Ordering::Relaxed) < low_water - 1 { st2.cloud_seq.store(low_water - 1, Ordering::Relaxed); log.notify_cloud(low_water - 1); }
                        // retire chunks of segments entirely below the snapshot's low water (the local side does the same)
                        let segs = GLog::list_segments(&dir);
                        for i in 0..segs.len().saturating_sub(1) { if segs[i + 1] - 1 < low_water { let prefix = cfg.key(&format!("log/{:020}", segs[i])); let keys: Vec<OPath> = rt.block_on(async { use futures_lite_shim::collect_list; collect_list(&*store, &prefix).await }); for k in keys { if rt.block_on(store.delete(&k)).is_ok() { st2.deletes.fetch_add(1, Ordering::Relaxed); } } } }
                        // also retire older snapshots
                        let keys: Vec<OPath> = rt.block_on(async { futures_lite_shim::collect_list(&*store, &cfg.key("snap")).await });
                        for k in keys { if !k.as_ref().trim_end_matches(".enc").trim_end_matches(".zst").ends_with(&format!("{s0:020}")) { if rt.block_on(store.delete(&k)).is_ok() { st2.deletes.fetch_add(1, Ordering::Relaxed); } } }
                    }
                }
            }
            // 2. log: upload new complete records of the segment holding cloud_seq + 1 (after the writer thread has flushed what was appended)
            let written = log.wait_written(Duration::from_millis(200));
            loop {
                let want = st2.cloud_seq.load(Ordering::Relaxed) + 1;
                let segs = GLog::list_segments(&dir);
                let seg = match segs.iter().copied().filter(|&f| f <= want).last() { Some(s) => s, None => match segs.first() { Some(&f) if f > want => { st2.cloud_seq.store(f - 1, Ordering::Relaxed); log.notify_cloud(f - 1); continue; } _ => break } };
                let done = match cur { Some((s, off)) if s == seg => off, _ => existing.get(&seg).copied().unwrap_or(0) };
                let path = GLog::seg_path_in(&dir, seg);
                let mut f = match File::open(&path) { Ok(f) => f, Err(_) => break };
                let mut buf = vec![]; f.seek(SeekFrom::Start(done)).unwrap(); f.read_to_end(&mut buf).unwrap();
                let (recs, rest) = parse_glog(&buf); let complete = buf.len() - rest;
                if complete == 0 { // nothing new in this segment: has the owner moved on?
                    if segs.iter().any(|&x| x > seg) && rest == 0 { cur = Some((segs.iter().copied().filter(|&x| x > seg).min().unwrap(), 0)); let next = cur.unwrap().0; if next > want { st2.cloud_seq.store(next - 1, Ordering::Relaxed); } continue; }
                    break;
                }
                let last = recs.last().map(|r| r.0).unwrap_or(want - 1); let tc = Instant::now(); let body = pack(&buf[..complete], &cfg); st2.compress_ms.fetch_add(tc.elapsed().as_micros() as u64, Ordering::Relaxed); let t = Instant::now(); if !cfg.rtt.is_zero() { std::thread::sleep(cfg.rtt); }
                let n = body.len() as u64; rt.block_on(store.put(&cfg.key(&chunk_key(seg, done, complete as u64, &cfg.suffix())), PutPayload::from(body))).map_err(|e| format!("uploading the log: {e}"))?;
                st2.uploaded();
                st2.puts.fetch_add(1, Ordering::Relaxed); st2.bytes.fetch_add(n, Ordering::Relaxed); st2.raw_bytes.fetch_add(complete as u64, Ordering::Relaxed); st2.last_put_ms.store(t.elapsed().as_millis() as u64, Ordering::Relaxed);
                cur = Some((seg, done + complete as u64)); st2.cloud_seq.store(last, Ordering::Relaxed); log.notify_cloud(last);
                if last >= written { break; }
            }
            // 3. compaction: merge runs of consecutive chunks older than `compact_after` into one object, then delete them.
            // The merged object is written first, so a reader always sees either the small chunks, both, or the merged one;
            // readers tolerate overlap by offset, so no state is ever unreadable.
            if !cfg.compact_after.is_zero() && last_compact.elapsed() >= cfg.compact_every {
                last_compact = Instant::now();
                for seg in GLog::list_segments(&dir) {
                    let keys = rt.block_on(futures_lite_shim::collect_list_meta(&*store, &cfg.key(&format!("log/{seg:020}"))));
                    let mut chunks: Vec<(u64, u64, OPath, bool)> = keys.iter().filter_map(|(k, _, age)| parse_chunk(k.as_ref()).map(|(_, off, len, _, _)| (off, len, k.clone(), *age >= cfg.compact_after))).collect();
                    chunks.sort_by_key(|c| (c.0, std::cmp::Reverse(c.1)));
                    let mut i = 0;
                    while i < chunks.len() {
                        // a run: consecutive, all old enough, more than one chunk, up to 64 MB
                        let (start, mut end, mut j) = (chunks[i].0, chunks[i].0 + chunks[i].1, i + 1);
                        if !chunks[i].3 { i += 1; continue; }
                        while j < chunks.len() && chunks[j].3 && chunks[j].0 == end && end - start + chunks[j].1 <= 64 << 20 { end += chunks[j].1; j += 1; }
                        if j - i >= 2 {
                            if let Ok(mut f) = File::open(GLog::seg_path_in(&dir, seg)) { let mut buf = vec![0u8; (end - start) as usize]; f.seek(SeekFrom::Start(start)).unwrap(); if f.read_exact(&mut buf).is_ok() {
                                let body = pack(&buf, &cfg); let n = body.len() as u64;
                                if rt.block_on(store.put(&cfg.key(&chunk_key(seg, start, end - start, &cfg.suffix())), PutPayload::from(body))).is_ok() {
                                    st2.puts.fetch_add(1, Ordering::Relaxed); st2.bytes.fetch_add(n, Ordering::Relaxed); st2.merges.fetch_add(1, Ordering::Relaxed);
                                    for c in &chunks[i..j] { if rt.block_on(store.delete(&c.2)).is_ok() { st2.deletes.fetch_add(1, Ordering::Relaxed); } }
                                } } }
                        }
                        i = j.max(i + 1);
                    }
                }
            }
            Ok(())
            })();
            if let Err(e) = step { st2.fail(e); }
        }
    });
    Uploader { stats, stop, thread: Some(h), kick }
}

/// Minimal list helper (object_store lists are async streams).
mod futures_lite_shim {
    use object_store::{path::Path, ObjectStore};
    pub async fn collect_list(store: &dyn ObjectStore, prefix: &Path) -> Vec<Path> { collect_list_sized(store, prefix).await.into_iter().map(|(p, _)| p).collect() }
    pub async fn collect_list_sized(store: &dyn ObjectStore, prefix: &Path) -> Vec<(Path, u64)> { collect_list_meta(store, prefix).await.into_iter().map(|(p, s, _)| (p, s)).collect() }
    /// Like `collect_list_sized`, but an error from the bucket is an error, not an empty listing.
    pub async fn try_list_sized(store: &dyn ObjectStore, prefix: &Path) -> Result<Vec<(Path, u64)>, String> {
        use futures_util::StreamExt;
        let mut s = store.list(Some(prefix)); let mut out = vec![];
        while let Some(r) = s.next().await { let m = r.map_err(|e| e.to_string())?; out.push((m.location, m.size)); }
        out.sort_by(|a, b| a.0.as_ref().cmp(b.0.as_ref())); Ok(out)
    }
    /// (key, size, age since last modification)
    pub async fn collect_list_meta(store: &dyn ObjectStore, prefix: &Path) -> Vec<(Path, u64, std::time::Duration)> {
        use futures_util::StreamExt;
        let mut s = store.list(Some(prefix)); let mut out = vec![]; let now = std::time::SystemTime::now();
        while let Some(r) = s.next().await { if let Ok(m) = r { let age = now.duration_since(std::time::SystemTime::from(m.last_modified)).unwrap_or_default(); out.push((m.location, m.size, age)); } }
        out.sort_by(|a, b| a.0.as_ref().cmp(b.0.as_ref())); out
    }
}

/// Delete every object under the configured prefix (through the API, so the server's own view stays consistent).
pub fn clear_prefix(cfg: &CloudConfig) -> usize {
    let rt = rt(); let store = cfg.store(); let keys = rt.block_on(futures_lite_shim::collect_list(&*store, &cfg.key(""))); let mut n = 0;
    for k in keys { if rt.block_on(store.delete(&k)).is_ok() { n += 1; } } n
}
/// Rebuild a database directory from the bucket: the latest snapshot plus every chunk after it, in order, and the
/// uploaded files. Returns (snapshot s0, chunks downloaded, bytes). The caller opens it with `Sql::open` / `recover_upto`.
pub fn download(cfg: &CloudConfig, dest: &Path) -> Result<(u64, usize, u64), String> {
    let (s0, n, bytes) = download_log(cfg, dest)?; let (_, fb) = download_files(cfg, dest)?;
    Ok((s0, n, bytes + fb))
}
/// `download` without the files: the snapshot and the log, into a `dest` emptied first.
pub fn download_log(cfg: &CloudConfig, dest: &Path) -> Result<(u64, usize, u64), String> {
    let rt = rt(); let store = cfg.store();
    let _ = fs::remove_dir_all(dest); fs::create_dir_all(dest).map_err(|e| e.to_string())?;
    let snaps = rt.block_on(futures_lite_shim::collect_list(&*store, &cfg.key("snap")));
    let mut bytes = 0u64; let mut s0 = 0u64;
    if let Some(k) = snaps.last() {
        let data = rt.block_on(async { store.get(k).await.map_err(|e| e.to_string())?.bytes().await.map_err(|e| e.to_string()) })?;
        bytes += data.len() as u64; let (z, e) = flags(k.as_ref()); let data = unpack(&data, z, e, cfg).map_err(|er| format!("snapshot {}: {er}", k.as_ref()))?; fs::write(dest.join("snap"), &data).map_err(|e| e.to_string())?;
        s0 = u64::from_le_bytes(data[16..24].try_into().unwrap());
    }
    let chunks = rt.block_on(futures_lite_shim::collect_list(&*store, &cfg.key("log")));
    let mut n = 0usize; let mut cur_seg: Option<(u64, File, u64)> = None;  // (segment, file, bytes assembled)
    for k in chunks {
        let Some((seg, off, len, z, e)) = parse_chunk(k.as_ref()) else { continue };
        if cur_seg.as_ref().map(|(s, _, _)| *s != seg).unwrap_or(true) { cur_seg = Some((seg, File::create(GLog::seg_path_in(dest, seg)).map_err(|e| e.to_string())?, 0)); }
        let (_, f, have) = cur_seg.as_mut().unwrap();
        if off + len <= *have { continue; }                      // fully covered by what we already have (a merged object was followed by the small chunks it replaced, or vice versa)
        if off > *have { return Err(format!("gap in segment {seg}: have {have} bytes, next chunk starts at {off}")); }
        let data = rt.block_on(async { store.get(&k).await.map_err(|e| e.to_string())?.bytes().await.map_err(|e| e.to_string()) })?;
        bytes += data.len() as u64; let data = unpack(&data, z, e, cfg).map_err(|er| format!("chunk {}: {er}", k.as_ref()))?; let skip = (*have - off) as usize;   // overlap: take only the tail
        f.write_all(&data[skip..]).map_err(|e| e.to_string())?; *have += (data.len() - skip) as u64; n += 1;
    }
    Ok((s0, n, bytes))
}

// ---- uploaded files

/// Uploaded files (the bytes of FILE columns) are objects too: `files/{id}`, `.zst` when compressed, `.enc` when
/// encrypted, written once. Compressed only when it pays (the first megabyte must shrink by a tenth: photos, video and
/// archives are compressed already), encrypted like the rest, and streamed in 8 MB parts, so a large file is never in
/// memory whole.
pub fn file_key(id: &str, z: bool, cfg: &CloudConfig) -> OPath { cfg.key(&format!("files/{id}{}{}", if z { ".zst" } else { "" }, if cfg.key.is_some() { ".enc" } else { "" })) }
/// The file id of a key under `files/`, and whether its object is compressed and encrypted.
pub fn parse_file_key(key: &str) -> Option<(String, bool, bool)> {
    let name = key.rsplit('/').next()?; let (z, e) = flags(name); let id = name.trim_end_matches(".enc").trim_end_matches(".zst");
    (id.len() == 36 && id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')).then(|| (id.to_string(), z, e))
}
/// Parts of a file's upload, and its encryption frames (smaller than other objects', so little is held at once).
const PART: usize = 8 << 20; const FILE_FRAME: usize = 1 << 20;
/// `encrypt` as a stream: bytes in, frames of FILE_FRAME bytes out (the format `decrypt` reads), collected in `out`.
struct Seal { cipher: Option<aes_gcm::Aes256Gcm>, pending: Vec<u8>, out: Vec<u8>, frames: usize }
impl Seal {
    fn new(key: Option<&[u8; 32]>) -> Seal { use aes_gcm::aead::KeyInit; let cipher = key.map(|k| aes_gcm::Aes256Gcm::new(k.into())); Seal { out: if cipher.is_some() { ENC_MAGIC.to_vec() } else { vec![] }, cipher, pending: Vec::with_capacity(FILE_FRAME), frames: 0 } }
    fn seal(&mut self, n: usize) { let Some(c) = &self.cipher else { return }; seal_frame(c, &self.pending[..n], &mut self.out); self.pending.drain(..n); self.frames += 1; }
    /// What is left to send, the last frame included (an empty object still has one).
    fn finish(mut self) -> Vec<u8> { if self.cipher.is_some() && (!self.pending.is_empty() || self.frames == 0) { self.seal(self.pending.len()); } self.out }
}
impl Write for Seal {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if self.cipher.is_none() { self.out.extend_from_slice(b); return Ok(b.len()); }
        let mut rest = b;
        while !rest.is_empty() { let n = (FILE_FRAME - self.pending.len()).min(rest.len()); self.pending.extend_from_slice(&rest[..n]); rest = &rest[n..]; if self.pending.len() == FILE_FRAME { self.seal(FILE_FRAME); } }
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}
enum Pack { Plain(Seal), Z(zstd::stream::write::Encoder<'static, Seal>) }
impl Pack {
    fn sink(&mut self) -> &mut Seal { match self { Pack::Plain(s) => s, Pack::Z(z) => z.get_mut() } }
    fn finish(self) -> std::io::Result<Vec<u8>> { Ok(match self { Pack::Plain(s) => s, Pack::Z(z) => z.finish()? }.finish()) }
}
impl Write for Pack {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> { match self { Pack::Plain(s) => s.write(b), Pack::Z(z) => z.write(b) } }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}
/// `unpack` as a stream: an object's bytes in as they arrive, the file's bytes out.
struct Unseal { cipher: Option<aes_gcm::Aes256Gcm>, buf: Vec<u8>, magic: bool, out: Unpack }
enum Unpack { Plain(File), Z(zstd::stream::zio::Writer<File, zstd::stream::raw::Decoder<'static>>) }
impl Unseal {
    fn push(&mut self, b: &[u8]) -> Result<(), String> {
        let Some(c) = &self.cipher else { return self.out.write_all(b).map_err(|e| e.to_string()) };
        self.buf.extend_from_slice(b);
        if !self.magic { if self.buf.len() < 4 { return Ok(()); } if &self.buf[..4] != ENC_MAGIC { return Err("object is not encrypted the way this key expects".into()); } self.magic = true; self.buf.drain(..4); }
        let mut p = 0; while let Some((pt, n)) = open_frame(c, &self.buf[p..])? { self.out.write_all(&pt).map_err(|e| e.to_string())?; p += n; }
        self.buf.drain(..p); Ok(())
    }
    /// The end of the object: it must not stop inside a frame, encrypted or compressed.
    fn finish(self) -> Result<(), String> {
        if self.cipher.is_some() && (!self.magic || !self.buf.is_empty()) { return Err("truncated encrypted object".into()); }
        if let Unpack::Z(mut z) = self.out { z.finish().map_err(|e| format!("object failed to decompress: {e}"))?; }
        Ok(())
    }
}
impl Write for Unpack {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> { match self { Unpack::Plain(f) => f.write(b), Unpack::Z(z) => z.write(b) } }
    fn flush(&mut self) -> std::io::Result<()> { match self { Unpack::Plain(f) => f.flush(), Unpack::Z(z) => z.flush() } }
}
/// Upload the file at `path` as file `id`, giving up between parts once `stop` is set. Returns the bytes sent.
pub async fn put_file(store: &dyn ObjectStore, cfg: &CloudConfig, id: &str, path: &Path, stop: &AtomicBool) -> Result<u64, String> {
    let mut upload = None;
    let r = put_file_parts(store, cfg, id, path, stop, &mut upload).await;
    if r.is_err() { if let Some(mut u) = upload { let _ = u.abort().await; } }
    r
}
async fn put_file_parts(store: &dyn ObjectStore, cfg: &CloudConfig, id: &str, path: &Path, stop: &AtomicBool, upload: &mut Option<Box<dyn object_store::MultipartUpload>>) -> Result<u64, String> {
    let err = |e: std::io::Error| format!("{}: {e}", path.display()); let up = |e: object_store::Error| format!("uploading a file: {e}");
    let mut f = File::open(path).map_err(err)?; let mut buf = vec![0u8; 1 << 20]; let mut n = f.read(&mut buf).map_err(err)?;
    let z = cfg.compress && n > 0 && zstd::bulk::compress(&buf[..n], 3).is_ok_and(|c| c.len() * 10 < n * 9);
    let key = file_key(id, z, cfg);
    let mut pack = if z { let mut e = zstd::stream::write::Encoder::new(Seal::new(cfg.key.as_ref()), 3).map_err(err)?; e.include_checksum(true).map_err(err)?; Pack::Z(e) } else { Pack::Plain(Seal::new(cfg.key.as_ref())) };
    let mut sent = 0u64;
    while n > 0 {
        pack.write_all(&buf[..n]).map_err(err)?;
        while pack.sink().out.len() >= PART {
            if stop.load(Ordering::Relaxed) { return Err("stopping".into()); }
            let rest = pack.sink().out.split_off(PART); let part = std::mem::replace(&mut pack.sink().out, rest);
            if upload.is_none() { *upload = Some(store.put_multipart(&key).await.map_err(up)?); }
            upload.as_mut().unwrap().put_part(PutPayload::from(part)).await.map_err(up)?; sent += PART as u64;
        }
        n = f.read(&mut buf).map_err(err)?;
    }
    let last = pack.finish().map_err(err)?; sent += last.len() as u64;
    match upload {
        None => { store.put(&key, PutPayload::from(last)).await.map_err(up)?; }
        Some(u) => { if !last.is_empty() { u.put_part(PutPayload::from(last)).await.map_err(up)?; } u.complete().await.map_err(up)?; }
    }
    Ok(sent)
}
/// Download the file object `key` (as listed under `files/`) to `dest`, by way of `dest.part`. Returns the bytes received.
pub async fn get_file(store: &dyn ObjectStore, cfg: &CloudConfig, key: &OPath, dest: &Path) -> Result<u64, String> {
    let part = dest.with_extension("part");
    let r = get_file_to(store, cfg, key, &part).await.map_err(|e| format!("{}: {e}", key.as_ref()))
        .and_then(|n| fs::rename(&part, dest).map(|()| n).map_err(|e| format!("{}: {e}", dest.display())));
    if r.is_err() { let _ = fs::remove_file(&part); }
    r
}
async fn get_file_to(store: &dyn ObjectStore, cfg: &CloudConfig, key: &OPath, path: &Path) -> Result<u64, String> {
    use aes_gcm::aead::KeyInit; use futures_util::StreamExt;
    let (_, z, e) = parse_file_key(key.as_ref()).ok_or("not a file's object")?;
    if e && cfg.key.is_none() { return Err("object is encrypted and no key was given".into()); }
    let err = |e: std::io::Error| format!("{}: {e}", path.display());
    if let Some(d) = path.parent() { fs::create_dir_all(d).map_err(err)?; }
    let f = File::create(path).map_err(err)?;
    let out = if z { Unpack::Z(zstd::stream::zio::Writer::new(f, zstd::stream::raw::Decoder::new().map_err(err)?)) } else { Unpack::Plain(f) };
    let mut un = Unseal { cipher: if e { cfg.key.as_ref().map(|k| aes_gcm::Aes256Gcm::new(k.into())) } else { None }, buf: vec![], magic: false, out };
    let mut s = store.get(key).await.map_err(|e| e.to_string())?.into_stream(); let mut n = 0u64;
    while let Some(b) = s.next().await { let b = b.map_err(|e| e.to_string())?; n += b.len() as u64; un.push(&b)?; }
    un.finish()?;
    Ok(n)
}
/// Delete a file's object, compressed or not; one that is not there is no error.
pub async fn delete_file(store: &dyn ObjectStore, cfg: &CloudConfig, id: &str) -> Result<(), String> {
    for k in [file_key(id, false, cfg), file_key(id, true, cfg)] { delete_object(store, &k).await?; }
    Ok(())
}
pub async fn delete_object(store: &dyn ObjectStore, key: &OPath) -> Result<(), String> {
    match store.delete(key).await { Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()), Err(e) => Err(format!("deleting {}: {e}", key.as_ref())) }
}
/// The files in the bucket: (id, key).
pub async fn list_files(store: &dyn ObjectStore, cfg: &CloudConfig) -> Result<Vec<(String, OPath)>, String> {
    Ok(futures_lite_shim::try_list_sized(store, &cfg.key("files")).await?.into_iter().filter_map(|(k, _)| parse_file_key(k.as_ref()).map(|(id, ..)| (id, k))).collect())
}
/// Download every file in the bucket into `dest`'s `files/`, 16 at a time. Returns (files, bytes).
pub fn download_files(cfg: &CloudConfig, dest: &Path) -> Result<(usize, u64), String> {
    use futures_util::StreamExt;
    let rt = rt(); let store = cfg.store();
    rt.block_on(async {
        let files = list_files(&*store, cfg).await?;
        let got: Vec<Result<u64, String>> = futures_util::stream::iter(&files).map(|(id, k)| { let (store, to) = (&*store, crate::files::file_path_in(dest, id)); async move { get_file(store, cfg, k, &to).await } }).buffer_unordered(16).collect().await;
        let mut bytes = 0; for r in got { bytes += r?; }
        Ok((files.len(), bytes))
    })
}

/// A follower fed only by the bucket: polls for new chunks, appends them to local segment files, and the ordinary
/// file-tailing follower (E26) applies them. Returns the bytes downloaded so far through `pulled`.
pub struct BucketPuller { pub pulled: Arc<AtomicU64>, pub chunks: Arc<AtomicU64>, stop: Arc<AtomicBool>, thread: Option<std::thread::JoinHandle<()>> }
impl Drop for BucketPuller { fn drop(&mut self) { self.stop.store(true, Ordering::Relaxed); if let Some(h) = self.thread.take() { h.join().ok(); } } }
pub fn start_puller(cfg: CloudConfig, dir: PathBuf, poll: Duration) -> BucketPuller {
    let pulled = Arc::new(AtomicU64::new(0)); let chunks = Arc::new(AtomicU64::new(0)); let stop = Arc::new(AtomicBool::new(false));
    let (p2, c2, s2) = (pulled.clone(), chunks.clone(), stop.clone());
    let h = std::thread::spawn(move || {
        let rt = rt(); let store = cfg.store();
        // keys sort like the log itself (zero-padded segment, zero-padded offset), so one start-after listing per poll
        // returns exactly the chunks not seen yet; start after the last chunk already on disk
        let mut after: Option<OPath> = None; let mut idle = 0u32;
        if let Some(seg) = GLog::list_segments(&dir).last().copied() { let len = fs::metadata(GLog::seg_path_in(&dir, seg)).map(|m| m.len()).unwrap_or(0); if len > 0 { let keys = rt.block_on(futures_lite_shim::collect_list(&*store, &cfg.key(&format!("log/{seg:020}")))); after = keys.into_iter().filter(|k| parse_chunk(k.as_ref()).map(|(_, o, l, _, _)| o + l <= len).unwrap_or(false)).last(); } }
        // append whatever of this object we do not have yet (overlap-tolerant)
        let take = |k: &OPath, seg: u64, off: u64, len: u64, z: bool, e: bool| -> Option<u64> {
            let path = GLog::seg_path_in(&dir, seg); let cur = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            if off + len <= cur { return Some(0); } if off > cur { return None; }
            let data = rt.block_on(async { store.get(k).await?.bytes().await }).ok()?; let data = match unpack(&data, z, e, &cfg) { Ok(d) => d, Err(er) => { eprintln!("puller: {}: {er}", k.as_ref()); return None; } }; let skip = (cur - off) as usize;
            let mut f = fs::OpenOptions::new().create(true).append(true).open(&path).unwrap(); f.write_all(&data[skip..]).unwrap(); Some((data.len() - skip) as u64)
        };
        loop {
            if s2.load(Ordering::Relaxed) { return; }
            let keys: Vec<OPath> = rt.block_on(async { use futures_util::StreamExt; let prefix = cfg.key("log"); let mut s = match &after { Some(a) => store.list_with_offset(Some(&prefix), a), None => store.list(Some(&prefix)) }; let mut out = vec![]; while let Some(r) = s.next().await { if let Ok(m) = r { out.push(m.location); } } out.sort_by(|a, b| a.as_ref().cmp(b.as_ref())); out });
            let mut got = false;
            for k in keys {
                let Some((seg, off, len, z, e)) = parse_chunk(k.as_ref()) else { after = Some(k.clone()); continue };
                match take(&k, seg, off, len, z, e) { Some(0) => { after = Some(k.clone()); } Some(n) => { p2.fetch_add(n, Ordering::Relaxed); c2.fetch_add(1, Ordering::Relaxed); after = Some(k.clone()); got = true; } None => break }
            }
            if !got {
                idle += 1;
                // nothing new for a while: the chunk we wait for may have been merged into an object that sorts before our position
                if idle % 20 == 0 { if let Some(seg) = GLog::list_segments(&dir).last().copied() { for k in rt.block_on(futures_lite_shim::collect_list(&*store, &cfg.key(&format!("log/{seg:020}")))) { if let Some((seg, off, len, z, e)) = parse_chunk(k.as_ref()) { if let Some(n) = take(&k, seg, off, len, z, e) { if n > 0 { p2.fetch_add(n, Ordering::Relaxed); c2.fetch_add(1, Ordering::Relaxed); } } } } } }
                std::thread::sleep(poll);
            } else { idle = 0; }
        }
    });
    BucketPuller { pulled, chunks, stop, thread: Some(h) }
}

#[cfg(test)]
mod file_tests {
    use super::*;
    use object_store::memory::InMemory;
    fn cfg(pass: Option<&str>) -> CloudConfig { let c = CloudConfig::local("b", "db"); match pass { Some(p) => c.with_passphrase(p), None => c } }
    fn tmp(n: &str) -> PathBuf { let d = std::env::temp_dir().join(format!("sqweezdb-cloudfiles-{}-{n}", std::process::id())); let _ = fs::remove_dir_all(&d); fs::create_dir_all(&d).unwrap(); d }
    fn noise(n: usize) -> Vec<u8> { let mut v = vec![0u8; n]; getrandom::fill(&mut v).unwrap(); v }
    const ID: &str = "0123abcd-89ab-4def-8123-456789abcdef";

    #[test] fn files_go_up_and_come_back_streamed() {
        let d = tmp("roundtrip"); let rt = rt(); let stop = AtomicBool::new(false);
        let text: Vec<u8> = (0..300_000).flat_map(|i: u32| format!("line {i} of a note that compresses well\n").into_bytes()).take(3 << 20).collect();
        // empty, small text, a photo-like 20 MB (multipart, past an encryption frame), text past a part
        for (name, data) in [("empty", vec![]), ("small", b"hello".to_vec()), ("photo", noise(20 << 20)), ("text", text)] {
            for pass in [None, Some("pw")] {
                let (store, c) = (InMemory::new(), cfg(pass)); let src = d.join(name); fs::write(&src, &data).unwrap();
                let sent = rt.block_on(put_file(&store, &c, ID, &src, &stop)).unwrap();
                let listed = rt.block_on(list_files(&store, &c)).unwrap(); assert_eq!(listed.len(), 1, "{name}");
                let (id, key) = &listed[0]; assert_eq!(id, ID);
                let (z, e) = flags(key.as_ref());
                assert_eq!(z, name == "text", "{name}: compressed only when it pays"); assert_eq!(e, pass.is_some());
                let obj = rt.block_on(async { store.get(key).await.unwrap().bytes().await.unwrap() });
                assert_eq!(obj.len() as u64, sent);
                assert_eq!(unpack(&obj, z, e, &c).unwrap(), data, "{name}: the format `unpack` reads");
                let back = d.join("back").join(name);
                assert_eq!(rt.block_on(get_file(&store, &c, key, &back)).unwrap(), sent);
                assert!(fs::read(&back).unwrap() == data, "{name} {pass:?}"); assert!(!back.with_extension("part").exists());
                rt.block_on(delete_file(&store, &c, ID)).unwrap(); assert!(rt.block_on(list_files(&store, &c)).unwrap().is_empty());
                rt.block_on(delete_file(&store, &c, ID)).unwrap();   // gone already: no error
            }
        }
    }
    #[test] fn a_damaged_file_object_is_refused() {
        let d = tmp("damaged"); let rt = rt(); let stop = AtomicBool::new(false); let src = d.join("f");
        let text: Vec<u8> = (0..100_000).flat_map(|i: u32| format!("row {i}\n").into_bytes()).collect(); fs::write(&src, &text).unwrap();
        for pass in [None, Some("pw")] {
            let (store, c) = (InMemory::new(), cfg(pass)); rt.block_on(put_file(&store, &c, ID, &src, &stop)).unwrap();
            let (_, key) = rt.block_on(list_files(&store, &c)).unwrap().remove(0);
            let obj = rt.block_on(async { store.get(&key).await.unwrap().bytes().await.unwrap() });
            let dest = d.join("out");
            // cut short, or one bit changed
            for bad in [obj[..obj.len() - 7].to_vec(), { let mut b = obj.to_vec(); let i = b.len() / 2; b[i] ^= 1; b }] {
                rt.block_on(store.put(&key, PutPayload::from(bad))).unwrap();
                assert!(rt.block_on(get_file(&store, &c, &key, &dest)).is_err(), "{pass:?}");
                assert!(!dest.exists() && !dest.with_extension("part").exists());
            }
            if pass.is_some() { rt.block_on(store.put(&key, PutPayload::from(obj.clone()))).unwrap(); assert!(rt.block_on(get_file(&store, &cfg(Some("other")), &key, &dest)).unwrap_err().contains("authentication")); }
        }
    }
}

#[cfg(test)]
mod health_tests {
    use super::*;
    #[test] fn backup_health_moves_through_its_states() {
        let st = CloudStats::default();
        assert_eq!(st.state(), "connecting");
        st.fail("reading the bucket: refused".into()); assert_eq!(st.state(), "retrying");
        st.contact(); st.resumed.store(true, Ordering::Relaxed); assert_eq!(st.state(), "healthy");
        for _ in 0..3 { st.fail("uploading the log: timeout".into()); }
        assert_eq!(st.state(), "failing"); assert_eq!(st.failures.load(Ordering::Relaxed), 3); assert_eq!(st.last_error(), "uploading the log: timeout");
        st.uploaded(); assert_eq!(st.state(), "healthy");
        assert_eq!(st.failures_total.load(Ordering::Relaxed), 4, "the total survives recovery");
        assert!(st.upload_at_ms.load(Ordering::Relaxed) >= st.err_at_ms.load(Ordering::Relaxed));
        st.fail("x".repeat(5000)); assert_eq!(st.last_error().len(), 600, "long errors are cut");
    }
    #[test] fn a_bad_endpoint_is_an_error_not_a_panic() {
        // the client accepts any endpoint text and fails on the first request: the probe reports it, nothing panics
        let mut c = CloudConfig::local("b", "p"); c.endpoint = "not a url".into();
        assert!(c.try_store(0).is_err());
        let steps = probe(&c); assert_eq!(steps.len(), 1); assert_eq!(steps[0].0, "connect"); assert!(steps[0].3.contains("https://"), "{steps:?}");
        for good in ["https://s3.eu-central-1.amazonaws.com", "http://127.0.0.1:9000", "https://acct.r2.cloudflarestorage.com/"] { assert!(check_endpoint(good).is_ok(), "{good}"); }
        for bad in ["s3.amazonaws.com", "https://", "http:// spaces", "ftp://x"] { assert!(check_endpoint(bad).is_err(), "{bad}"); }
    }
}
