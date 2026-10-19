//! Experiment 55: differential test of everyday SQL. The same schema, rows and queries run on sqzdb and on SQLite
//! (system library); every result is compared: in order when the query has ORDER BY, as sorted rows otherwise. Integers
//! and floats compare as numbers, booleans as 0 and 1. A query sqzdb refuses is reported as such, not as a mismatch.
//!
//!     cargo run --release --features lab --bin e55_sql_diff [filter]
use rusqlite::types::ValueRef;
use sqzdb::config::Config;
use sqzdb::sql::{Session, Sql};
use sqzdb::table::Value;

const SETUP: &[&str] = &[
    "CREATE TABLE users (id INTEGER PRIMARY KEY, name VARCHAR(40), age INT, grp INT, city VARCHAR(40), score DOUBLE)",
    "INSERT INTO users VALUES (1, 'alice', 30, 1, 'lisbon', 1.5), (2, 'bob', 25, 1, 'paris', 2.0), (3, 'carol', 35, 2, 'lisbon', 3.25), (4, 'dave', 40, 2, NULL, NULL), (5, 'eve', NULL, 3, 'paris', 0.5), (6, 'frank', 25, 1, 'lisbon', 2.0), (7, 'grace', 35, 2, 'rome', -1.0), (8, 'heidi', NULL, NULL, NULL, NULL)",
    "CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INT, amount INT, note VARCHAR(40))",
    "INSERT INTO orders VALUES (1, 1, 10, 'a'), (2, 1, 20, 'b'), (3, 3, 5, NULL), (4, 2, 20, 'a'), (5, 7, 15, 'c'), (6, 1, 10, 'a'), (7, 5, NULL, 'd')",
    "CREATE TABLE items (id INTEGER PRIMARY KEY, order_id INT, qty INT)",
    "INSERT INTO items VALUES (1, 1, 2), (2, 1, 3), (3, 4, 1), (4, 5, 7)",
    // text join keys: 'lisbonA' and 'lisbonB' have the same length and first six bytes
    "CREATE TABLE cities (id INTEGER PRIMARY KEY, city VARCHAR(40), country VARCHAR(8))",
    "INSERT INTO cities VALUES (1, 'lisbon', 'pt'), (2, 'paris', 'fr'), (3, 'lisbonA', 'aa'), (4, 'porto', 'pt'), (5, 'lisbon-metropolitan-area', 'lm')",
    // and values over 15 bytes, which take the hashed key: 'lisbon-metropolitan-areb' differs in the last byte
    "CREATE TABLE visits (id INTEGER PRIMARY KEY, city VARCHAR(40), days INT)",
    "INSERT INTO visits VALUES (1, 'lisbonB', 3), (2, 'paris', 2), (3, 'lisbon', 5), (4, NULL, 1), (5, 'porto', 4), (6, 'lisbon-metropolitan-areb', 9), (7, 'lisbon-metropolitan-area', 2)",
    // a text primary key, short and hashed (over 15 bytes)
    "CREATE TABLE codes (code VARCHAR(30) PRIMARY KEY, label VARCHAR(20))",
    "INSERT INTO codes VALUES ('pt', 'Portugal'), ('fr', 'France'), ('aa', 'Aland'), ('lm-metropolitan-region', 'LMR')",
];

const QUERIES: &[&str] = &[
    // ORDER BY several keys, positions, aliases, hidden columns; LIMIT and OFFSET
    "SELECT name, grp, age FROM users ORDER BY grp, age, name",
    "SELECT name, grp, age FROM users ORDER BY grp DESC, age ASC, name",
    "SELECT name FROM users ORDER BY age, name",
    "SELECT name FROM users ORDER BY age DESC, name LIMIT 3",
    "SELECT name, age FROM users ORDER BY age, name LIMIT 2 OFFSET 2",
    "SELECT name FROM users ORDER BY id LIMIT 3 OFFSET 6",
    "SELECT name FROM users ORDER BY id LIMIT 3 OFFSET 20",
    "SELECT id, name FROM users ORDER BY 2 DESC",
    "SELECT name AS who, age FROM users ORDER BY who",
    "SELECT name, score FROM users ORDER BY score DESC, name",
    "SELECT name, city FROM users ORDER BY city, name",
    "SELECT * FROM users ORDER BY id LIMIT 2 OFFSET 1",
    "SELECT name FROM users WHERE grp = 1 ORDER BY age DESC, name",
    // DISTINCT
    "SELECT DISTINCT grp FROM users",
    "SELECT DISTINCT grp FROM users ORDER BY grp",
    "SELECT DISTINCT grp, city FROM users ORDER BY grp, city",
    "SELECT DISTINCT city FROM users ORDER BY city LIMIT 2",
    "SELECT DISTINCT age FROM users WHERE grp = 1",
    // aggregates over DISTINCT values
    "SELECT count(DISTINCT grp) FROM users",
    "SELECT count(DISTINCT city) FROM users",
    "SELECT count(DISTINCT city), count(city), count(*) FROM users",
    "SELECT sum(DISTINCT age), avg(DISTINCT age), min(DISTINCT age), max(DISTINCT age) FROM users",
    "SELECT grp, count(DISTINCT city) FROM users GROUP BY grp ORDER BY grp",
    "SELECT count(DISTINCT city) FROM users WHERE id > 1000",
    // several GROUP BY columns
    "SELECT grp, city, count(*) FROM users GROUP BY grp, city ORDER BY grp, city",
    "SELECT grp, city, sum(age), avg(score) FROM users GROUP BY grp, city",
    "SELECT city, grp, max(name) FROM users GROUP BY city, grp ORDER BY city DESC, grp",
    "SELECT grp, city, count(*) FROM users WHERE id > 1000 GROUP BY grp, city",
    // HAVING
    "SELECT grp, avg(age) FROM users GROUP BY grp HAVING avg(age) > 30",
    "SELECT grp FROM users GROUP BY grp HAVING count(*) >= 2 ORDER BY grp",
    "SELECT grp, count(*) FROM users GROUP BY grp HAVING count(*) > 1 AND max(age) < 40",
    "SELECT city, count(*) FROM users GROUP BY city HAVING count(*) = 1",
    "SELECT grp, city, count(*) FROM users GROUP BY grp, city HAVING count(*) > 1",
    "SELECT count(*) FROM users HAVING count(*) > 3",
    "SELECT count(*) FROM users HAVING count(*) > 30",
    "SELECT grp FROM users GROUP BY grp HAVING 2 <= count(*)",
    "SELECT grp, sum(age) FROM users GROUP BY grp HAVING grp > 1",
    // ORDER BY aggregates and aliases with GROUP BY
    "SELECT grp, count(*) AS n FROM users GROUP BY grp ORDER BY n DESC, grp",
    "SELECT grp, count(*) FROM users GROUP BY grp ORDER BY 2 DESC, 1",
    "SELECT grp FROM users GROUP BY grp ORDER BY count(*) DESC, grp LIMIT 1",
    "SELECT grp, sum(age) FROM users GROUP BY grp ORDER BY sum(age) DESC, grp",
    "SELECT city, count(*) FROM users GROUP BY city ORDER BY count(*) DESC, city LIMIT 2 OFFSET 1",
    // joins
    "SELECT u.name, o.amount FROM orders o JOIN users u ON u.id = o.user_id ORDER BY u.name, o.amount DESC",
    "SELECT u.grp, count(*) FROM orders o JOIN users u ON u.id = o.user_id GROUP BY u.grp ORDER BY u.grp",
    "SELECT u.grp, u.city, sum(o.amount) FROM orders o JOIN users u ON u.id = o.user_id GROUP BY u.grp, u.city ORDER BY 1, 2",
    "SELECT DISTINCT u.city FROM orders o JOIN users u ON u.id = o.user_id ORDER BY u.city",
    "SELECT u.name FROM orders o JOIN users u ON u.id = o.user_id GROUP BY u.name HAVING sum(o.amount) > 15 ORDER BY u.name",
    "SELECT count(DISTINCT o.user_id) FROM orders o JOIN users u ON u.id = o.user_id WHERE u.grp = 1",
    // subqueries next to the new clauses
    "SELECT name FROM users WHERE id IN (SELECT DISTINCT user_id FROM orders) ORDER BY name",
    "SELECT name FROM users WHERE id IN (SELECT user_id FROM orders GROUP BY user_id HAVING count(*) > 1)",
    // ---- expressions in the select list
    "SELECT id, age + 1, age * 2 - 3, age / 7, age % 7, -age FROM users ORDER BY id",
    "SELECT id, score * 2, score + age, score / 4 FROM users ORDER BY id",
    "SELECT name || '-' || age, name || score FROM users ORDER BY id",
    "SELECT upper(name), lower('ABC'), length(name), substr(name, 2, 3), substr(name, -2), substr(name, 0, 2), replace(name, 'a', 'A') FROM users ORDER BY id",
    "SELECT trim('  x  '), ltrim('xxabc', 'x'), rtrim('abcyy', 'y'), instr(name, 'a'), hex(name) FROM users ORDER BY id",
    "SELECT abs(-5), abs(score), round(score), round(score, 1), round(2.5), sign(score) FROM users ORDER BY id",
    "SELECT coalesce(age, -1), coalesce(city, name), ifnull(score, 0), nullif(age, 25), iif(age > 30, 'old', 'young') FROM users ORDER BY id",
    "SELECT CASE WHEN age >= 35 THEN 'senior' WHEN age >= 30 THEN 'mid' ELSE 'junior' END FROM users ORDER BY id",
    "SELECT CASE grp WHEN 1 THEN 'one' WHEN 2 THEN 'two' END FROM users ORDER BY id",
    "SELECT CAST(age AS TEXT), CAST('42' AS INTEGER), CAST(score AS INTEGER), CAST(age AS REAL) FROM users ORDER BY id",
    "SELECT age IS NULL, city IS NOT NULL, age > 30, age BETWEEN 25 AND 30, grp IN (1, 3) FROM users ORDER BY id",
    "SELECT min(age, grp), max(age, grp) FROM users ORDER BY id",
    "SELECT concat(name, '/', city), concat_ws('-', name, city, grp) FROM users ORDER BY id",
    "SELECT json_extract('{\"a\":{\"b\":[1,2,3]}}', '$.a.b[1]') FROM users WHERE id = 1",
    "SELECT date('2026-10-17', '+1 day'), date('2026-01-31', '+1 month'), datetime('2026-10-17 13:45:00', 'start of day'), strftime('%Y-%m', '2026-10-17'), time('2026-10-17 13:45:09') FROM users WHERE id = 1",
    "SELECT u.name, o.amount * 2, u.age + o.amount FROM orders o JOIN users u ON u.id = o.user_id ORDER BY o.id",
    // ---- SELECT without FROM
    "SELECT 1 + 2, 'a' || 'b', upper('x'), 7 / 2, 7.0 / 2, abs(-3)",
    "SELECT CASE WHEN 1 > 2 THEN 'no' ELSE 'yes' END, coalesce(NULL, NULL, 3)",
    // ---- WHERE with expressions, OR, NOT, LIKE
    "SELECT name FROM users WHERE age = 25 OR city = 'rome' ORDER BY name",
    "SELECT name FROM users WHERE NOT (grp = 1) ORDER BY name",
    "SELECT name FROM users WHERE name LIKE 'a%' OR name LIKE '%e' ORDER BY name",
    "SELECT name FROM users WHERE name LIKE '_a%' ORDER BY name",
    "SELECT name FROM users WHERE name NOT LIKE '%a%' ORDER BY name",
    "SELECT name FROM users WHERE city LIKE 'l%' AND age > 26 ORDER BY name",
    "SELECT name FROM users WHERE length(name) = 5 ORDER BY name",
    "SELECT name FROM users WHERE age + grp > 30 ORDER BY name",
    "SELECT name FROM users WHERE upper(city) = 'PARIS' ORDER BY name",
    "SELECT name FROM users WHERE coalesce(age, 0) < 26 ORDER BY name",
    "SELECT name FROM users WHERE (age > 30 AND grp = 2) OR (age < 26 AND grp = 1) ORDER BY name",
    "SELECT name FROM users WHERE age IN (25, 35) OR score IS NULL ORDER BY name",
    "SELECT count(*) FROM users WHERE name LIKE '%a%'",
    "SELECT u.name FROM orders o JOIN users u ON u.id = o.user_id WHERE o.amount > 10 OR u.city = 'rome' ORDER BY o.id",
    "SELECT name FROM users WHERE age > (SELECT avg(age) FROM users) ORDER BY name",
    // ---- aggregates over expressions, expressions over aggregates, GROUP BY expressions
    "SELECT sum(age * 2), avg(score + 1), max(length(name)), count(CASE WHEN age > 30 THEN 1 END) FROM users",
    "SELECT grp, sum(CASE WHEN city = 'lisbon' THEN 1 ELSE 0 END) FROM users GROUP BY grp ORDER BY grp",
    "SELECT grp, count(*) * 10, sum(age) + 1, max(age) - min(age), round(avg(age), 2) FROM users GROUP BY grp ORDER BY grp",
    "SELECT grp, sum(age) / count(age) FROM users WHERE age IS NOT NULL GROUP BY grp ORDER BY grp",
    "SELECT upper(city), count(*) FROM users GROUP BY upper(city) ORDER BY 1",
    "SELECT length(name), count(*) FROM users GROUP BY length(name) ORDER BY length(name)",
    "SELECT substr(name, 1, 1) AS initial, count(*) FROM users GROUP BY initial ORDER BY initial",
    "SELECT grp, group_concat(name) FROM users GROUP BY grp ORDER BY grp",
    "SELECT grp, group_concat(name, '|') FROM users WHERE grp IS NOT NULL GROUP BY grp ORDER BY grp",
    "SELECT grp, string_agg(name, ', ') FROM users GROUP BY grp ORDER BY grp",
    "SELECT grp, count(*) FROM users GROUP BY grp HAVING sum(age) > 60 OR count(*) = 1 ORDER BY grp",
    "SELECT grp, avg(score) FROM users GROUP BY grp HAVING avg(score) IS NOT NULL ORDER BY avg(score) DESC",
    "SELECT city, count(*) AS n FROM users GROUP BY city ORDER BY n * -1, city",
    "SELECT count(*) + 1, max(age) * 2 FROM users",
    "SELECT u.city, sum(o.amount * 2) FROM orders o JOIN users u ON u.id = o.user_id GROUP BY u.city ORDER BY u.city",
    // ---- ORDER BY expressions
    "SELECT name FROM users ORDER BY length(name) DESC, name",
    "SELECT name, age FROM users ORDER BY coalesce(age, 0) DESC, name",
    "SELECT name FROM users ORDER BY age * -1, name LIMIT 3",
    // ---- writes with expressions (a separate table; each statement runs on both sides, then the check)
    "!CREATE TABLE stock (id INTEGER PRIMARY KEY, item VARCHAR(20), qty INT, price DOUBLE)",
    "!INSERT INTO stock VALUES (1, 'nail', 100, 0.25), (2, 'screw', 50, 0.4), (3, 'bolt', 0, 1.5), (4, 'washer', 10, 0.05)",
    "!UPDATE stock SET qty = qty - 5, price = price * 2 WHERE id = 1",
    "!UPDATE stock SET item = upper(item) || '!' WHERE id = 2",
    "!UPDATE stock SET qty = CASE WHEN qty = 0 THEN 99 ELSE qty END WHERE id = 3",
    "SELECT id, item, qty, price FROM stock ORDER BY id",
    "!DELETE FROM stock WHERE qty < 20 OR item LIKE 'n%'",
    "SELECT id, item, qty FROM stock ORDER BY id",
    // ---- LEFT JOIN and one-to-many joins (users without orders, an order whose user is gone, NULL keys)
    "!INSERT INTO orders VALUES (8, 99, 40, 'z'), (9, NULL, 1, 'n')",
    "SELECT u.name, o.amount FROM users u LEFT JOIN orders o ON o.user_id = u.id ORDER BY u.id, o.id",
    "SELECT u.name, count(o.id) FROM users u LEFT JOIN orders o ON o.user_id = u.id GROUP BY u.name ORDER BY u.name",
    "SELECT u.name, sum(o.amount), max(o.note) FROM users u LEFT JOIN orders o ON o.user_id = u.id GROUP BY u.name ORDER BY u.name",
    "SELECT u.name FROM users u LEFT JOIN orders o ON o.user_id = u.id WHERE o.id IS NULL ORDER BY u.name",
    "SELECT u.name, o.amount FROM users u LEFT JOIN orders o ON o.user_id = u.id AND o.amount > 10 ORDER BY u.id, o.id",
    "SELECT u.name, o.amount FROM users u LEFT JOIN orders o ON o.user_id = u.id WHERE o.amount > 10 OR u.grp = 3 ORDER BY u.id, o.id",
    "SELECT o.id, u.name FROM orders o LEFT JOIN users u ON u.id = o.user_id ORDER BY o.id",
    "SELECT o.id, coalesce(u.name, '?') FROM orders o LEFT JOIN users u ON u.id = o.user_id WHERE u.id IS NULL ORDER BY o.id",
    "SELECT u.city, count(o.id), count(*) FROM users u LEFT JOIN orders o ON o.user_id = u.id GROUP BY u.city ORDER BY u.city",
    "SELECT u.name, o.amount, i.qty FROM users u LEFT JOIN orders o ON o.user_id = u.id LEFT JOIN items i ON i.order_id = o.id ORDER BY u.id, o.id, i.id",
    "SELECT u.name, o.amount FROM users u JOIN orders o ON o.user_id = u.id ORDER BY u.id, o.id",
    "SELECT DISTINCT u.name FROM users u LEFT JOIN orders o ON o.user_id = u.id WHERE o.amount >= 20 ORDER BY u.name",
    // ---- INSERT … SELECT and upserts
    "!CREATE TABLE tally (k INTEGER PRIMARY KEY, label VARCHAR(40) UNIQUE, n INT)",
    "!INSERT INTO tally (k, label, n) SELECT id, name, coalesce(age, 0) FROM users WHERE grp = 1",
    "SELECT k, label, n FROM tally ORDER BY k",
    "!INSERT INTO tally (k, label, n) VALUES (1, 'alice', 5), (99, 'zed', 1) ON CONFLICT (k) DO UPDATE SET n = tally.n + excluded.n",
    "!INSERT INTO tally (k, label, n) VALUES (50, 'bob', 7) ON CONFLICT (label) DO UPDATE SET n = excluded.n * 2 WHERE tally.n < 100",
    "!INSERT INTO tally (k, label, n) VALUES (6, 'x', 0), (7, 'y', 0) ON CONFLICT DO NOTHING",
    "!INSERT OR IGNORE INTO tally (k, label, n) VALUES (99, 'q', 0)",
    "!INSERT OR REPLACE INTO tally (k, label, n) VALUES (6, 'frank2', 66)",
    "SELECT k, label, n FROM tally ORDER BY k",
    "!INSERT INTO tally (k, label, n) SELECT k + 1000, label || '!', n FROM tally WHERE n > 10",
    "SELECT k, label, n FROM tally ORDER BY k",
    // joins and subqueries on text columns
    "SELECT v.id, c.country FROM visits v JOIN cities c ON c.city = v.city ORDER BY v.id",
    "SELECT v.id, c.country FROM visits v LEFT JOIN cities c ON c.city = v.city ORDER BY v.id",
    "SELECT c.city, count(v.id) FROM cities c LEFT JOIN visits v ON v.city = c.city GROUP BY c.city ORDER BY c.city",
    "SELECT u.name, c.country FROM users u JOIN cities c ON c.city = u.city ORDER BY u.name",
    "SELECT id FROM visits WHERE city IN (SELECT city FROM cities WHERE country = 'pt') ORDER BY id",
    "SELECT id FROM visits WHERE city NOT IN (SELECT city FROM cities WHERE country = 'pt') ORDER BY id",
    "SELECT id, (SELECT country FROM cities c WHERE c.city = visits.city) FROM visits ORDER BY id",
    "SELECT id FROM visits WHERE EXISTS (SELECT 1 FROM cities c WHERE c.city = visits.city) ORDER BY id",
    "SELECT id FROM visits WHERE NOT EXISTS (SELECT 1 FROM cities c WHERE c.city = visits.city) ORDER BY id",
    "SELECT v.id, u.name FROM visits v JOIN users u ON u.age = v.days ORDER BY v.id, u.name",
    // the same through indexes on the text columns, kept up to date by UPDATE and DELETE
    "!CREATE INDEX visits_city ON visits(city)",
    "!CREATE INDEX cities_city ON cities(city)",
    "SELECT id, days FROM visits WHERE city = 'lisbon' ORDER BY id",
    "SELECT id FROM visits WHERE city = 'lisbonB'",
    "SELECT count(*) FROM visits WHERE city = 'lisbon-metropolitan-area'",
    "SELECT count(*) FROM visits WHERE city = 'lisbon-metropolitan-are'",
    "SELECT count(*) FROM visits WHERE city = 'nowhere'",
    "SELECT v.id, c.country FROM visits v JOIN cities c ON c.city = v.city ORDER BY v.id",
    "SELECT v.id, c.country FROM visits v LEFT JOIN cities c ON c.city = v.city ORDER BY v.id",
    "SELECT c.id, v.id FROM cities c JOIN visits v ON v.city = c.city WHERE c.country = 'pt' ORDER BY c.id, v.id",
    "SELECT id FROM visits WHERE city IN ('porto', 'lisbon-metropolitan-area', 'x') ORDER BY id",
    "!UPDATE visits SET city = 'porto' WHERE id = 3",
    "!UPDATE visits SET city = 'lisbon-metropolitan-area' WHERE id = 6",
    "!DELETE FROM visits WHERE id = 5",
    "SELECT id FROM visits WHERE city = 'porto' ORDER BY id",
    "SELECT id FROM visits WHERE city = 'lisbon' ORDER BY id",
    "SELECT id FROM visits WHERE city = 'lisbon-metropolitan-area' ORDER BY id",
    "SELECT c.city, count(v.id) FROM cities c LEFT JOIN visits v ON v.city = c.city GROUP BY c.city ORDER BY c.city",
    // through a text primary key
    "SELECT label FROM codes WHERE code = 'pt'",
    "SELECT label FROM codes WHERE code = 'lm-metropolitan-region'",
    "SELECT label FROM codes WHERE code = 'PT'",
    "SELECT code FROM codes ORDER BY code",
    "SELECT code FROM codes WHERE code > 'b' ORDER BY code DESC",
    "SELECT c.city, k.label FROM cities c JOIN codes k ON k.code = c.country ORDER BY c.city",
    "SELECT c.city, k.label FROM cities c LEFT JOIN codes k ON k.code = c.country ORDER BY c.city",
    "SELECT k.label, count(c.id) FROM codes k LEFT JOIN cities c ON c.country = k.code GROUP BY k.label ORDER BY k.label",
    "SELECT code FROM codes WHERE code IN (SELECT country FROM cities) ORDER BY code",
    "!INSERT INTO codes VALUES ('pt', 'P') ON CONFLICT (code) DO UPDATE SET label = excluded.label || '!'",
    "!INSERT OR REPLACE INTO codes VALUES ('fr', 'F')",
    "!INSERT OR IGNORE INTO codes VALUES ('aa', 'ignored'), ('lm', 'LM')",
    "!DELETE FROM codes WHERE code = 'lm-metropolitan-region'",
    "!UPDATE codes SET label = 'Aaland' WHERE code = 'aa'",
    "SELECT code, label FROM codes ORDER BY code",
    // UPDATE by any condition, then the rows it left
    "!UPDATE users SET score = score * 2 WHERE grp = 1",
    "SELECT name, score FROM users ORDER BY id",
    "!UPDATE users SET city = upper(city), age = age + 1 WHERE name LIKE '%e%' AND city IS NOT NULL",
    "SELECT name, age, city FROM users ORDER BY id",
    "!UPDATE users SET score = CASE WHEN score IS NULL THEN 0 ELSE score + 1 END WHERE age > 30 OR age IS NULL",
    "SELECT name, score FROM users ORDER BY id",
    "!UPDATE orders SET amount = amount + 1 WHERE user_id IN (SELECT id FROM users WHERE grp = 1)",
    "SELECT id, amount FROM orders ORDER BY id",
    "!UPDATE visits SET days = days * 10 WHERE city = 'porto'",
    "SELECT id, days FROM visits ORDER BY id",
    "!UPDATE codes SET label = label || '?' WHERE code > 'b'",
    "SELECT code, label FROM codes ORDER BY code",
    "!UPDATE users SET age = 0 WHERE id = 999 OR id = 998",
    "SELECT count(*) FROM users WHERE age = 0",
];

fn norm(v: &Value) -> String { match v { Value::Null => "NULL".into(), Value::Int(i) => i.to_string(), Value::Float(f) => if f.fract() == 0.0 && f.abs() < 1e15 { format!("{}", *f as i64) } else { format!("{:.6}", f) }, Value::Bool(b) => (*b as i32).to_string(), Value::Text(s) => s.clone(), Value::Bytes(b) => format!("{b:?}") } }
fn lite_norm(v: ValueRef) -> String { match v { ValueRef::Null => "NULL".into(), ValueRef::Integer(i) => i.to_string(), ValueRef::Real(f) => if f.fract() == 0.0 && f.abs() < 1e15 { format!("{}", f as i64) } else { format!("{:.6}", f) }, ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(), ValueRef::Blob(b) => format!("{b:?}") } }

fn main() {
    let filter = std::env::args().nth(1).unwrap_or_default();
    let dir = std::path::PathBuf::from("data/nocow/e55"); let _ = std::fs::remove_dir_all(&dir);
    let ours = Sql::open_with(&dir, Config::default()).unwrap();
    let lite = rusqlite::Connection::open_in_memory().unwrap();
    for q in SETUP { ours.exec_s(&mut Session::default(), q, &[]).unwrap_or_else(|e| panic!("{q}: {e}")); lite.execute_batch(q).unwrap(); }
    let (mut same, mut differ, mut refused) = (0, 0, 0);
    for q in QUERIES.iter().filter(|q| q.starts_with('!') || q.contains(filter.as_str())) {
        if let Some(st) = q.strip_prefix('!') {   // a statement for both sides, compared by its effect on later queries
            lite.execute_batch(st).unwrap_or_else(|e| panic!("sqlite: {st}: {e}"));
            if let Err(e) = ours.exec_s(&mut Session::default(), st, &[]) { refused += 1; println!("REFUSED  {st}\n         {e}"); }
            continue;
        }
        let ordered = q.to_uppercase().contains("ORDER BY");
        let mut l: Vec<Vec<String>> = { let mut st = lite.prepare(q).unwrap(); let n = st.column_count(); let mut rows = st.query([]).unwrap(); let mut out = vec![]; while let Some(r) = rows.next().unwrap() { out.push((0..n).map(|i| lite_norm(r.get_ref(i).unwrap())).collect()); } out };
        let mut o: Vec<Vec<String>> = match ours.exec_s(&mut Session::default(), q, &[]) { Ok(rows) => rows.iter().map(|r| r.iter().map(norm).collect()).collect(), Err(e) => { refused += 1; println!("REFUSED  {q}\n         {e}"); continue; } };
        if !ordered { l.sort(); o.sort(); }
        if l == o { same += 1; } else { differ += 1; println!("DIFFER   {q}\n  sqlite   {l:?}\n  sqzdb {o:?}"); }
    }
    println!("{same} same, {differ} differ, {refused} refused");
    drop(ours); let _ = std::fs::remove_dir_all(&dir);
    if differ > 0 { std::process::exit(1); }
}
