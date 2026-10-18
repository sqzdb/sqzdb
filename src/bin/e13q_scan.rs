//! E13's scan queries (Q3, Q4, Q5, Q7) and its UPDATE by id (W1) on the same 1M rows, many repetitions: a quick A/B.
use sqweezdb::sql::Sql;
use sqweezdb::table::Value;
use sqweezdb::util::Rng;
use std::time::Instant;
const N: i64 = 1_000_000;
fn median(iters: usize, mut f: impl FnMut()) -> f64 { let mut ts = vec![]; for _ in 0..iters { let t = Instant::now(); f(); ts.push(t.elapsed().as_secs_f64() * 1e3); } ts.sort_by(|a, b| a.partial_cmp(b).unwrap()); ts[iters / 2] }
fn main() {
    let dir = std::path::PathBuf::from("data/nocow/e13q"); let _ = std::fs::remove_dir_all(&dir);
    let sql = Sql::recreate(&dir, false);
    sql.exec("CREATE TABLE t(id INTEGER PRIMARY KEY, score DOUBLE, country INT, age INT, name VARCHAR(32) UNIQUE, payload BLOB(64))", &[]).unwrap();
    let ins = sql.prepare("INSERT INTO t VALUES (?,?,?,?,?,?)").unwrap(); let mut rng = Rng(7);
    for id in 1..=N { sql.execute(&ins, &[Value::Int(id), Value::Float((rng.next() % 100000) as f64 / 100.0), Value::Int(id % 20), Value::Int(18 + id % 60), Value::Text(format!("u{id}@example.com")), Value::Bytes(vec![7u8; 64])]).unwrap(); }
    for round in 0..3 {
        let q3 = median(31, || { sql.exec("SELECT count(*) FROM t WHERE age > 40", &[]).unwrap(); });
        let q4 = median(31, || { sql.exec("SELECT country, avg(score), count(*) FROM t GROUP BY country", &[]).unwrap(); });
        let q7 = median(31, || { sql.exec("SELECT sum(score) FROM t WHERE country = 7 AND age BETWEEN 30 AND 50", &[]).unwrap(); });
        let q5p = sql.prepare("SELECT sum(score) FROM t WHERE id >= ? AND id < ?").unwrap(); let mut r = Rng(99);
        let t = Instant::now(); for _ in 0..50_000 { let a = (r.next() % (N - 1000) as u64) as i64 + 1; sql.execute(&q5p, &[Value::Int(a), Value::Int(a + 1000)]).unwrap(); } let q5 = t.elapsed().as_secs_f64() * 1e6 / 50_000.0;
        let w1p = sql.prepare("UPDATE t SET score = ? WHERE id = ?").unwrap();
        let t = Instant::now(); for i in 0..300_000 { let id = (r.next() % N as u64) as i64 + 1; sql.execute(&w1p, &[Value::Float(i as f64), Value::Int(id)]).unwrap(); } let w1 = t.elapsed().as_secs_f64() * 1e6 / 300_000.0;
        println!("round {round}: Q3 {q3:.3} ms  Q4 {q4:.3} ms  Q7 {q7:.3} ms  Q5 {q5:.3} us/call  W1 {w1:.3} us/call");
    }
    drop(sql); let _ = std::fs::remove_dir_all(&dir);
}
