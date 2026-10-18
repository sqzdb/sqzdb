//! Vectors (`VECTOR(n)`): a column of n f32s, stored as BYTES(4n), searched with `cosine_distance`, `l2_distance`
//! and `inner_product` (exact: a query computes the distance for every row its policies let it see).
//!
//! A column `VECTOR(n) GENERATED ALWAYS AS (embed(<text expression>)) STORED` is the embedding of that text, made by
//! the endpoint in `[embed]` (OpenAI-compatible: OpenAI, Ollama, llama.cpp, vLLM …):
//! - a write leaves it NULL (an INSERT), or sets it back to NULL when the text it embeds changes (an UPDATE); no
//!   statement writes a vector there;
//! - the embedder, a thread per database, finds rows whose vector is NULL and whose text isn't, embeds them in
//!   batches, and writes each vector only if the row still has that text. Live queries see it arrive.
//!
//! `embed('text')` in a query is replaced by that text's embedding when the statement runs (cached), so
//! `ORDER BY cosine_distance(embedding, embed(?))` searches by meaning.
use crate::sql::Sql;
use crate::table::{decode_col, encode_col, is_null, Abort, Key, Schema, Value};
use serde_json::{json, Value as J};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The most text sent for one embedding: longer text is cut (models take a few thousand words at most).
const MAX_TEXT: usize = 8_000;
const QUERY_CACHE: usize = 1_000;
/// How long a text the endpoint refused is left alone before it is tried again.
const SKIP_FOR: Duration = Duration::from_secs(600);

/// Per database: whether the embedder runs, search texts already embedded (by the SHA-256 of what was sent, so the
/// cache is at most QUERY_CACHE vectors whatever the texts), rows whose text the endpoint refused.
#[derive(Default)] pub struct VectorState { started: AtomicBool, cache: Mutex<(HashMap<[u8; 32], Vec<u8>>, VecDeque<[u8; 32]>)>, refused: Mutex<HashMap<(u16, Key), Instant>> }

fn clip(mut s: String) -> String { if s.len() > MAX_TEXT { let mut n = MAX_TEXT; while !s.is_char_boundary(n) { n -= 1; } s.truncate(n); } s }
fn raw<'r>(schema: &Schema, row: &'r [u8], k: usize) -> (bool, &'r [u8]) { (is_null(row, k), &row[schema.offsets[k]..schema.offsets[k] + schema.columns[k].ty.width()]) }
fn generated(c: &crate::table::Column) -> String { format!("permission denied: column {} is generated from embed({}); the database writes it", c.name, c.embed.as_ref().map(|e| e.expr.as_str()).unwrap_or("")) }

/// A new row of a table with generated VECTOR columns: they must be NULL (the embedder fills them).
pub(crate) fn embed_insert_ok(schema: &Schema, row: &[u8]) -> Result<(), String> {
    for (c, col) in schema.columns.iter().enumerate() { if col.embed.is_some() && !is_null(row, c) { return Err(generated(col)); } }
    Ok(())
}
/// An updated row: a generated VECTOR column may only be set to NULL, and becomes NULL when the text it embeds changes.
pub(crate) fn embed_on_update(schema: &Schema, old: &[u8], new: &mut [u8]) -> Result<(), String> {
    for (c, col) in schema.columns.iter().enumerate() {
        let Some(spec) = &col.embed else { continue };
        if raw(schema, old, c) != raw(schema, new, c) && !is_null(new, c) { return Err(generated(col)); }
        if spec.cols.iter().any(|n| schema.col(n).is_none_or(|k| raw(schema, old, k) != raw(schema, new, k))) { encode_col(schema, new, c, &Value::Null)?; }
    }
    Ok(())
}

impl Sql {
    /// The embeddings of `texts` from the `[embed]` endpoint, in order.
    pub fn embed_texts(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
        let p = self.cfg.embed.clone().ok_or("embed: set [embed] in the configuration (an OpenAI-compatible endpoint and a model)")?;
        let mut body = json!({"model": p.model, "input": texts}); if let Some(d) = p.dimensions { body["dimensions"] = json!(d); }
        let v = crate::oauth::http_with(Duration::from_secs(60), move |c| async move {
            let mut r = c.post(format!("{}/embeddings", p.url)).header("content-type", "application/json").body(body.to_string());
            if let Some(k) = &p.api_key { r = r.bearer_auth(k); }
            let resp = r.send().await.map_err(|e| format!("embed: {}: {e}", p.url))?; let status = resp.status(); let text = resp.text().await.map_err(|e| format!("embed: {e}"))?;
            if !status.is_success() { return Err(format!("embed: HTTP {status}: {}", text.chars().take(300).collect::<String>())); }
            serde_json::from_str::<J>(&text).map_err(|e| format!("embed: not JSON ({e})"))
        })?;
        let data = v.get("data").and_then(|d| d.as_array()).ok_or("embed: the answer has no data")?;
        let mut out: Vec<Option<Vec<f32>>> = vec![None; texts.len()];
        for (k, d) in data.iter().enumerate() {
            let i = d.get("index").and_then(|i| i.as_u64()).map(|i| i as usize).unwrap_or(k);
            let e = d.get("embedding").and_then(|e| e.as_array()).ok_or("embed: an item without an embedding")?;
            let e: Vec<f32> = e.iter().map(|x| x.as_f64().map(|f| f as f32)).collect::<Option<_>>().ok_or("embed: an embedding that isn't numbers")?;
            if let Some(slot) = out.get_mut(i) { *slot = Some(e); }
        }
        out.into_iter().enumerate().map(|(i, e)| e.ok_or_else(|| format!("embed: no embedding for input {i}"))).collect()
    }
    /// A search text's embedding, as a VECTOR value: cached, so a query run again (a live one, say) costs nothing.
    pub(crate) fn embed_query(&self, text: &str) -> Result<Vec<u8>, String> {
        use sha2::Digest;
        let sent = clip(text.to_string()); let key: [u8; 32] = sha2::Sha256::digest(sent.as_bytes()).into();
        if let Some(v) = self.vectors.cache.lock().unwrap().0.get(&key) { return Ok(v.clone()); }
        let v: Vec<u8> = self.embed_texts(&[sent])?.remove(0).iter().flat_map(|x| x.to_le_bytes()).collect();
        let mut c = self.vectors.cache.lock().unwrap();
        if c.0.len() >= QUERY_CACHE { if let Some(old) = c.1.pop_front() { c.0.remove(&old); } }
        if c.0.insert(key, v.clone()).is_none() { c.1.push_back(key); }
        Ok(v)
    }

    /// Start the embedder (once per database, when `[embed]` is set): it wakes on writes and fills generated vectors.
    pub fn vectors_start(self: &Arc<Self>) {
        if self.cfg.embed.is_none() || self.vectors.started.swap(true, Ordering::AcqRel) { return; }
        let weak = Arc::downgrade(self);
        std::thread::Builder::new().name("sqweezdb-embed".into()).spawn(move || {
            let mut wait = Duration::from_secs(5);
            loop {
                let Some(sql) = weak.upgrade() else { return };
                match sql.embed_round() {
                    // nothing to do: until something is written (rows that come while a request is out make the next batch)
                    Ok(0) => { let (seq, log, durable) = (sql.current_seq(), sql.db.log.clone(), sql.db.durable); drop(sql); log.wait_feed(seq, durable, Duration::from_secs(1)); }
                    Ok(_) => wait = Duration::from_secs(5),
                    Err(e) => { eprintln!("embed: {e}; trying again in {} s", wait.as_secs()); drop(sql); std::thread::sleep(wait); wait = (wait * 2).min(Duration::from_secs(300)); }
                }
            }
        }).expect("a thread");
    }
    /// One round of the embedder: up to a batch of rows whose generated vector is NULL and whose text isn't, embedded
    /// in one request and written back. Returns how many rows it looked at (0: nothing to do).
    pub fn embed_round(&self) -> Result<usize, String> {
        let batch = self.cfg.embed.as_ref().map(|p| p.batch).unwrap_or(64);
        let mut refused = self.vectors.refused.lock().unwrap(); refused.retain(|_, at| at.elapsed() < SKIP_FOR);
        let mut todo = vec![];   // (table, column, its source planned, key, text)
        'tables: for name in self.db.table_names() {
            let Some(t) = self.db.table(&name) else { continue };
            for (c, col) in t.schema.columns.iter().enumerate() {
                let Some(spec) = &col.embed else { continue };
                let x = Arc::new(self.plan_embed(&t.schema, spec).map_err(|e| format!("{}.{}: {e}", t.schema.name, col.name))?);
                t.scan(|row| {
                    if !is_null(row, c) { return true; }
                    let Ok(Value::Text(s)) = x.eval(&|k| decode_col(&t.schema, row, k)) else { return true };
                    let key = t.schema.key_of(row);
                    if s.trim().is_empty() || refused.contains_key(&(t.id, key)) { return true; }
                    todo.push((t.clone(), c, x.clone(), key, clip(s))); todo.len() < batch
                });
                if todo.len() >= batch { break 'tables; }
            }
        }
        if todo.is_empty() { return Ok(0); }
        let texts: Vec<String> = todo.iter().map(|x| x.4.clone()).collect();
        let vecs: Vec<Result<Vec<f32>, String>> = match self.embed_texts(&texts) {
            Ok(v) => v.into_iter().map(Ok).collect(),
            // the whole batch failed: one text alone tells an endpoint that is down (try again later) from texts it refuses
            Err(e) => match self.embed_texts(&texts[..1]) {
                Err(_) => return Err(e),
                Ok(mut first) => std::iter::once(Ok(first.remove(0))).chain(texts[1..].iter().map(|t| self.embed_texts(std::slice::from_ref(t)).map(|mut v| v.remove(0)))).collect(),
            },
        };
        let n = todo.len();
        for ((t, c, x, key, text), v) in todo.into_iter().zip(vecs) {
            let v = match v { Ok(v) => v, Err(e) => { eprintln!("embed: {}.{}: a text the endpoint refused, skipped for 10 minutes: {e}", t.schema.name, t.schema.columns[c].name); refused.insert((t.id, key), Instant::now()); continue } };
            let dims = t.schema.columns[c].vector.unwrap_or(0);
            if v.len() != dims { return Err(format!("the model makes vectors of {} numbers, and {}.{} is VECTOR({dims}): change the column, or set [embed] dimensions", v.len(), t.schema.name, t.schema.columns[c].name)); }
            let bytes = Value::Bytes(v.iter().flat_map(|f| f.to_le_bytes()).collect());
            // the row may have changed since: write the vector only if it still embeds this text
            let _ = t.update_by_pk(key, |row| {
                if !is_null(row, c) { return Err(Abort::NotFound); }
                match x.eval(&|k| decode_col(&t.schema, row, k)) { Ok(Value::Text(s)) if clip(s.clone()) == text => {}, _ => return Err(Abort::NotFound) }
                let mut new = row.to_vec(); encode_col(&t.schema, &mut new, c, &bytes).map_err(Abort::Type)?; Ok(new)
            });
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::sql::{error_code, Session};
    use std::io::{Read, Write};
    fn tmp(n: &str) -> std::path::PathBuf { let d = std::env::temp_dir().join(format!("sqweezdb-vector-{}-{n}", std::process::id())); let _ = std::fs::remove_dir_all(&d); d }
    fn app(s: &Sql, sql: &str) -> Vec<Vec<Value>> { s.exec_s(&mut Session::default(), sql, &[]).unwrap_or_else(|e| panic!("{sql}: {e}")) }
    fn f(v: &Value) -> f64 { match v { Value::Float(x) => *x, v => panic!("{v:?}") } }
    /// An OpenAI-style embeddings endpoint whose vectors count a text's words in `dims` buckets (so texts sharing
    /// words are near), counting its requests.
    fn fake_endpoint(dims: usize) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap(); let url = format!("http://127.0.0.1:{}/v1", l.local_addr().unwrap().port());
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0)); let c = calls.clone();
        std::thread::spawn(move || for s in l.incoming() { let Ok(mut s) = s else { continue }; let c = c.clone(); std::thread::spawn(move || {
            let mut buf = vec![]; let mut b = [0u8; 4096];
            let head = loop { let n = s.read(&mut b).unwrap_or(0); if n == 0 { return; } buf.extend_from_slice(&b[..n]); if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") { break i + 4; } };
            let h = String::from_utf8_lossy(&buf[..head]).to_lowercase();
            let len: usize = h.lines().find_map(|l| l.strip_prefix("content-length:")).and_then(|v| v.trim().parse().ok()).unwrap_or(0);
            while buf.len() < head + len { let n = s.read(&mut b).unwrap_or(0); if n == 0 { return; } buf.extend_from_slice(&b[..n]); }
            c.fetch_add(1, Ordering::Relaxed);
            let req: J = serde_json::from_slice(&buf[head..head + len]).unwrap();
            let data: Vec<J> = req["input"].as_array().unwrap().iter().enumerate().map(|(i, t)| {
                let mut v = vec![0f64; dims];
                for w in t.as_str().unwrap().to_lowercase().split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()) { v[w.bytes().fold(7u64, |a, x| a.wrapping_mul(31).wrapping_add(x as u64)) as usize % dims] += 1.0; }
                json!({"index": i, "embedding": v})
            }).collect();
            let body = json!({"data": data}).to_string();
            let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
        }); });
        (url, calls)
    }
    fn open(d: &std::path::Path, url: &str) -> Arc<Sql> { Sql::open_with(d, Config::from_json(&format!(r#"{{"embed":{{"url":"{url}","model":"fake","batch":2}}}}"#)).unwrap()).unwrap() }
    fn filled(s: &Sql, table: &str) { let t = std::time::Instant::now(); while app(s, &format!("SELECT count(*) FROM {table} WHERE embedding IS NULL"))[0][0] != Value::Int(0) { assert!(t.elapsed() < Duration::from_secs(10), "the embedder didn't fill {table}"); std::thread::sleep(Duration::from_millis(20)); } }

    #[test] fn distances_and_vector_columns() {
        let d = tmp("dist"); let s = Sql::open_with(&d, Config::default()).unwrap();
        let r = &app(&s, "SELECT cosine_distance('[1,0]', '[0,1]'), l2_distance('[0,0]', '[3,4]'), inner_product('[1,2]', '[3,4]'), vector_dims('[1,2,3]'), cosine_distance('[0,0]', '[1,1]'), cosine_distance(NULL, '[1]')")[0];
        assert_eq!((f(&r[0]), f(&r[1]), f(&r[2]), &r[3], &r[4], &r[5]), (1.0, 5.0, 11.0, &Value::Int(3), &Value::Null, &Value::Null));
        assert!(s.exec_s(&mut Session::default(), "SELECT cosine_distance('[1,0]', '[1,0,0]')", &[]).unwrap_err().contains("vectors of 2 and 3"));
        app(&s, "CREATE TABLE v (id INT PRIMARY KEY, e VECTOR(3))");
        s.exec_s(&mut Session::default(), "INSERT INTO v VALUES (1, ?), (2, '[0, 1, 0]')", &[Value::Text("[1, 0, 0.5]".into())]).unwrap();
        let near = app(&s, "SELECT id, l2_distance(e, '[1, 0, 0.4]') AS d FROM v ORDER BY d LIMIT 1"); assert_eq!(near[0][0], Value::Int(1));
        assert_eq!(app(&s, "SELECT e FROM v WHERE id = 1")[0][0], Value::Bytes([1f32, 0.0, 0.5].iter().flat_map(|x| x.to_le_bytes()).collect()));
        for bad in ["'[1, 2]'", "'[1, 2, \"x\"]'", "'not a vector'"] { assert!(s.exec_s(&mut Session::default(), &format!("INSERT INTO v VALUES (3, {bad})"), &[]).unwrap_err().contains("vector of 3"), "{bad}"); }
        for bad in ["CREATE TABLE w (e VECTOR(3) PRIMARY KEY)", "CREATE TABLE w (id INT PRIMARY KEY, e VECTOR(0))", "CREATE TABLE w (id INT PRIMARY KEY, b TEXT GENERATED ALWAYS AS (embed(id)) STORED)",
                    "CREATE TABLE w (id INT PRIMARY KEY, e VECTOR(3) GENERATED ALWAYS AS (embed(nope)) STORED)", "CREATE TABLE w (id INT PRIMARY KEY, b TEXT, e VECTOR(3) NOT NULL GENERATED ALWAYS AS (embed(b)) STORED)",
                    "CREATE TABLE w (id INT PRIMARY KEY, b TEXT, e VECTOR(3) GENERATED ALWAYS AS (lower(b)) STORED)"] {
            assert!(s.exec_s(&mut Session::default(), bad, &[]).is_err(), "{bad}");
        }
        assert!(app(&s, "SELECT 1").len() == 1 && s.exec_s(&mut Session::default(), "SELECT embed('x')", &[]).unwrap_err().contains("[embed]"));
    }

    #[test] fn a_generated_vector_is_the_embedding_of_its_text() {
        let (url, calls) = fake_endpoint(8); let d = tmp("gen"); let s = open(&d, &url);
        for st in ["CREATE TABLE users (id SERIAL PRIMARY KEY, email TEXT UNIQUE, role TEXT DEFAULT 'member')", "CREATE ROLE member",
                   "CREATE TABLE notes (id SERIAL PRIMARY KEY, owner INT, title TEXT, body TEXT, embedding VECTOR(8) GENERATED ALWAYS AS (embed(title || ' ' || body)) STORED)",
                   "GRANT SELECT, INSERT, UPDATE ON notes TO member", "CREATE POLICY own ON notes FOR ALL TO member USING (owner = SESSION.id)", "ALTER TABLE users ENABLE AUTH (ROLE FROM role)"] { app(&s, st); }
        let ann = s.sign_up("users", &[("email".into(), Value::Text("ann@x".into()))], "the password 1").unwrap();
        let mut a = Session::default(); s.session_from_token(&mut a, &ann.token).unwrap();
        let id = |si: &crate::auth::SignedIn| si.user.iter().find(|(k, _)| k == "id").unwrap().1.clone();
        for (owner, t, b) in [(id(&ann), "cats", "my cat eats fish"), (id(&ann), "trip", "a train to lisbon"), (Value::Int(99), "secret", "the cat recipe of someone else"), (id(&ann), "work", "quarterly report numbers")] {
            s.exec_s(&mut Session::default(), "INSERT INTO notes (owner, title, body) VALUES (?, ?, ?)", &[owner, Value::Text(t.into()), Value::Text(b.into())]).unwrap();
        }
        filled(&s, "notes");
        assert!(calls.load(Ordering::Relaxed) >= 2, "batches of 2");
        // search by meaning, under the policy: Ann's notes only
        let q = "SELECT title, cosine_distance(embedding, embed(?)) AS d FROM notes ORDER BY d LIMIT 2";
        let found = s.exec_s(&mut a, q, &[Value::Text("cat fish".into())]).unwrap();
        assert_eq!(found[0][0], Value::Text("cats".into())); assert_eq!(found.len(), 2); assert!(found.iter().all(|r| r[0] != Value::Text("secret".into())));
        let before = calls.load(Ordering::Relaxed); s.exec_s(&mut a, q, &[Value::Text("cat fish".into())]).unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), before, "a search text is embedded once");
        // only the database writes the vector; a change to its text makes a new one
        let e = s.exec_s(&mut a, "INSERT INTO notes (owner, title, body, embedding) VALUES (?, 'x', 'y', '[1,0,0,0,0,0,0,0]')", &[id(&ann)]).unwrap_err(); assert_eq!(error_code(&e), "DENIED", "{e}");
        let e = s.exec_s(&mut Session::default(), "UPDATE notes SET embedding = '[1,0,0,0,0,0,0,0]' WHERE title = 'work'", &[]).unwrap_err(); assert_eq!(error_code(&e), "DENIED", "{e}");
        let old = app(&s, "SELECT embedding FROM notes WHERE title = 'trip'")[0][0].clone();
        s.exec_s(&mut a, "UPDATE notes SET body = 'my cat sleeps' WHERE title = 'trip'", &[]).unwrap();
        filled(&s, "notes");
        assert_ne!(app(&s, "SELECT embedding FROM notes WHERE title = 'trip'")[0][0], old, "embedded again");
        let unchanged = app(&s, "SELECT embedding FROM notes WHERE title = 'work'")[0][0].clone();
        s.exec_s(&mut a, "UPDATE notes SET owner = owner WHERE title = 'work'", &[]).unwrap();
        assert_eq!(app(&s, "SELECT embedding FROM notes WHERE title = 'work'")[0][0], unchanged, "a change that isn't to the text keeps the vector");
        // through a restart: the source survives, and rows written while it was closed are filled
        drop(a); drop(s); let s = Sql::open_with(&d, Config::default()).unwrap();
        app(&s, "INSERT INTO notes (owner, title, body) VALUES (1, 'later', 'written with no embedder')");
        let spec = s.db.table("notes").unwrap().schema.columns[4].embed.clone().unwrap(); assert_eq!(spec.cols, ["title", "body"]);
        drop(s); let s = open(&d, &url); filled(&s, "notes");
    }

    #[test] fn a_model_of_other_dimensions_is_an_error_to_fix() {
        let (url, _) = fake_endpoint(8); let d = tmp("dims"); let s = Sql::open_with(&d, Config::from_json(&format!(r#"{{"embed":{{"url":"{url}","model":"fake"}}}}"#)).unwrap()).unwrap();
        app(&s, "CREATE TABLE n (id INT PRIMARY KEY, b TEXT, e VECTOR(4) GENERATED ALWAYS AS (embed(b)) STORED)"); app(&s, "INSERT INTO n (id, b) VALUES (1, 'x')");
        let e = s.embed_round().unwrap_err(); assert!(e.contains("vectors of 8 numbers") && e.contains("VECTOR(4)"), "{e}");
    }
}

#[cfg(test)]
mod timing {
    use super::*;
    use crate::config::Config;
    use crate::sql::Session;
    /// Where an exact search's time goes (run with --ignored --nocapture).
    #[test] #[ignore] fn search_costs() {
        let d = std::env::temp_dir().join(format!("sqweezdb-vector-timing-{}", std::process::id())); let _ = std::fs::remove_dir_all(&d);
        let s = Sql::open_with(&d, Config::default()).unwrap(); let mut a = Session::default();
        s.exec_s(&mut a, "CREATE TABLE docs (id SERIAL PRIMARY KEY, e VECTOR(384))", &[]).unwrap();
        let mut r = 1u64; let mut rnd = || { r ^= r << 13; r ^= r >> 7; r ^= r << 17; (r % 1000) as f64 / 1000.0 - 0.5 };
        let vecj = |rnd: &mut dyn FnMut() -> f64| format!("[{}]", (0..384).map(|_| format!("{:.3}", rnd())).collect::<Vec<_>>().join(","));
        s.exec_s(&mut a, "BEGIN", &[]).unwrap();
        for _ in 0..100_000 { s.exec_s(&mut a, "INSERT INTO docs (e) VALUES (?)", &[Value::Text(vecj(&mut rnd))]).unwrap(); }
        s.exec_s(&mut a, "COMMIT", &[]).unwrap();
        let q = Value::Text(vecj(&mut rnd));
        for (label, sql) in [("count(*)", "SELECT count(*) FROM docs"), ("vector_dims(e) of each", "SELECT sum(vector_dims(e)) FROM docs"),
                             ("cosine_distance of each, summed", "SELECT sum(cosine_distance(e, ?)) FROM docs"),
                             ("nearest 10 (ORDER BY alias LIMIT 10)", "SELECT id, cosine_distance(e, ?) AS d FROM docs ORDER BY d LIMIT 10")] {
            let p: Vec<Value> = if sql.contains('?') { vec![q.clone()] } else { vec![] };
            let t = std::time::Instant::now(); for _ in 0..5 { s.exec_s(&mut a, sql, &p).unwrap(); }
            eprintln!("{label:40} {:.1} ms", t.elapsed().as_secs_f64() * 1e3 / 5.0);
        }
        drop(s); let _ = std::fs::remove_dir_all(&d);
    }
}
