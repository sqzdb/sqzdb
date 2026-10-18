//! Experiment 54: the SQL feature matrix. Each probe is a short script run on a fresh database in sqweezdb, SQLite
//! (system library) and Turso 0.8.3. A probe has one or more variants (the same feature in another dialect, or behind
//! a setting); the first variant that gives the expected answer marks the feature as working, with its label. A probe
//! that runs but answers differently is "wrong"; one where a statement fails is "missing", with the error. Turso is
//! retried with its experimental features switched on when the default build refuses. Output: one tab-separated row
//! per probe (category, feature, then a cell per engine), for the matrix in results/e54_features.md.
use rusqlite::types::ValueRef;
use sqweezdb::config::Config;
use sqweezdb::sql::{Session, Sql};
use sqweezdb::table::Value;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy)]
enum Expect { Eq(&'static str), EqNoSpace(&'static str), Prefix(&'static str), Err, Uuid, Any, Ge1, Rows(usize) }
struct Probe { cat: &'static str, name: &'static str, variants: &'static [(&'static str, &'static [&'static str])], expect: Expect }

const USERS: &str = "CREATE TABLE users (id INTEGER PRIMARY KEY, name VARCHAR(40), age INT, grp INT)";
const USERS_ROWS: &str = "INSERT INTO users VALUES (1, 'alice', 30, 1), (2, 'bob', 25, 1), (3, 'carol', 35, 2), (4, 'dave', 40, 2)";
const ORDERS: &str = "CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INT, amount INT)";
const ORDERS_ROWS: &str = "INSERT INTO orders VALUES (1, 1, 10), (2, 1, 20), (3, 3, 5)";
const DOCS_FTS5: &[&str] = &["CREATE VIRTUAL TABLE docs USING fts5(body)", "INSERT INTO docs(body) VALUES ('the quick brown fox'), ('hello world'), ('lazy dogs sleep')"];

macro_rules! v { ($($s:expr),* $(,)?) => { &[$($s),*] } }
macro_rules! with_users { ($($s:expr),* $(,)?) => { &[USERS, USERS_ROWS, $($s),*] } }
macro_rules! with_uo { ($($s:expr),* $(,)?) => { &[USERS, USERS_ROWS, ORDERS, ORDERS_ROWS, $($s),*] } }

static PROBES: &[Probe] = &[
    // ---- types and values
    Probe { cat: "Types", name: "Text of any length, no declared maximum", expect: Expect::Eq("1"), variants: &[
        ("", v!["CREATE TABLE t (id INTEGER PRIMARY KEY, s TEXT)", "INSERT INTO t VALUES (1, '{LONG}')", "SELECT count(*) FROM t WHERE s = '{LONG}'"]),
        ("only with a declared maximum, stored at full width", v!["CREATE TABLE t (id INTEGER PRIMARY KEY, s VARCHAR(10000))", "INSERT INTO t VALUES (1, '{LONG}')", "SELECT count(*) FROM t WHERE s = '{LONG}'"])] },
    Probe { cat: "Types", name: "Text longer than 64 KB", expect: Expect::Eq("1"), variants: &[
        ("", v!["CREATE TABLE t (id INTEGER PRIMARY KEY, s TEXT)", "INSERT INTO t VALUES (1, '{HUGE}')", "SELECT count(*) FROM t WHERE s = '{HUGE}'"]),
        ("with a declared maximum", v!["CREATE TABLE t (id INTEGER PRIMARY KEY, s VARCHAR(100000))", "INSERT INTO t VALUES (1, '{HUGE}')", "SELECT count(*) FROM t WHERE s = '{HUGE}'"])] },
    Probe { cat: "Types", name: "Binary data (BLOB)", expect: Expect::Eq("00ff10"), variants: &[
        ("", v!["CREATE TABLE b (id INTEGER PRIMARY KEY, data BLOB)", "INSERT INTO b VALUES (1, x'00ff10')", "SELECT data FROM b"]),
        ("with a declared maximum", v!["CREATE TABLE b (id INTEGER PRIMARY KEY, data BLOB(16))", "INSERT INTO b VALUES (1, x'00ff10')", "SELECT data FROM b"])] },
    Probe { cat: "Types", name: "Boolean type", expect: Expect::Eq("1"), variants: &[
        ("", v!["CREATE TABLE f (id INTEGER PRIMARY KEY, ok BOOLEAN)", "INSERT INTO f VALUES (1, true), (2, false)", "SELECT count(*) FROM f WHERE ok"]),
        ("as ok = true, not bare ok", v!["CREATE TABLE f (id INTEGER PRIMARY KEY, ok BOOLEAN)", "INSERT INTO f VALUES (1, true), (2, false)", "SELECT count(*) FROM f WHERE ok = true"])] },
    Probe { cat: "Types", name: "Exact decimals (0.1 + 0.2 = 0.3)", expect: Expect::Eq("1"), variants: &[
        ("", v!["CREATE TABLE m (id INTEGER PRIMARY KEY, v DECIMAL(10,2))", "INSERT INTO m VALUES (1, 0.1), (2, 0.2)", "SELECT CASE WHEN sum(v) = 0.3 THEN 1 ELSE 0 END FROM m"])] },
    Probe { cat: "Types", name: "A value of the wrong type is rejected", expect: Expect::Err, variants: &[
        ("", v!["CREATE TABLE s (id INTEGER PRIMARY KEY, n INT)", "INSERT INTO s VALUES (1, 'abc')"]),
        ("only in STRICT tables", v!["CREATE TABLE s (id INTEGER PRIMARY KEY, n INT) STRICT", "INSERT INTO s VALUES (1, 'abc')"])] },
    Probe { cat: "Types", name: "Generate a UUID", expect: Expect::Uuid, variants: &[
        ("uuid()", v!["SELECT uuid()"]), ("gen_random_uuid()", v!["SELECT gen_random_uuid()"]), ("uuid4_str()", v!["SELECT uuid4_str()"]), ("uuid7_str()", v!["SELECT uuid7_str()"])] },
    Probe { cat: "Types", name: "UUID column that rejects a malformed value", expect: Expect::Err, variants: &[
        ("", v!["CREATE TABLE x (id UUID PRIMARY KEY, v INT)", "INSERT INTO x VALUES ('not-a-uuid', 1)"])] },
    Probe { cat: "Types", name: "Current date and time", expect: Expect::Any, variants: &[
        ("CURRENT_TIMESTAMP", v!["SELECT CURRENT_TIMESTAMP"]), ("now()", v!["SELECT now()"])] },
    Probe { cat: "Types", name: "Date arithmetic", expect: Expect::Prefix("2026-10-18"), variants: &[
        ("date(…, '+1 day')", v!["SELECT date('2026-10-17', '+1 day')"]), ("+ INTERVAL", v!["SELECT CAST(DATE '2026-10-17' + INTERVAL '1 day' AS TEXT)"])] },
    Probe { cat: "Types", name: "Extract a part of a date", expect: Expect::Eq("2026"), variants: &[
        ("strftime", v!["SELECT strftime('%Y', '2026-10-17')"]), ("EXTRACT", v!["SELECT EXTRACT(YEAR FROM DATE '2026-10-17')"])] },
    Probe { cat: "Types", name: "Timestamp column defaulting to now", expect: Expect::Eq("1"), variants: &[
        ("CURRENT_TIMESTAMP", v!["CREATE TABLE e (id INTEGER PRIMARY KEY, at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)", "INSERT INTO e (id) VALUES (1)", "SELECT count(*) FROM e WHERE at IS NOT NULL"]),
        ("now()", v!["CREATE TABLE e (id INTEGER PRIMARY KEY, at TIMESTAMP DEFAULT now())", "INSERT INTO e (id) VALUES (1)", "SELECT count(*) FROM e WHERE at IS NOT NULL"])] },
    // ---- JSON
    Probe { cat: "JSON", name: "Read a field from JSON text", expect: Expect::Eq("2"), variants: &[
        ("json_extract", v!["SELECT json_extract('{\"a\":{\"b\":2}}', '$.a.b')"]), ("->>", v!["SELECT '{\"a\":{\"b\":2}}' ->> '$.a.b'"]),
        ("::json -> ->>", v!["SELECT '{\"a\":{\"b\":2}}'::json -> 'a' ->> 'b'"])] },
    Probe { cat: "JSON", name: "Filter rows by a field inside JSON", expect: Expect::Eq("1"), variants: &[
        ("json_extract", v!["CREATE TABLE d (id INTEGER PRIMARY KEY, doc TEXT)", "INSERT INTO d VALUES (1, '{\"n\":5}'), (2, '{\"n\":1}')", "SELECT count(*) FROM d WHERE json_extract(doc, '$.n') > 3"]),
        ("->>", v!["CREATE TABLE d (id INTEGER PRIMARY KEY, doc VARCHAR(200))", "INSERT INTO d VALUES (1, '{\"n\":5}'), (2, '{\"n\":1}')", "SELECT count(*) FROM d WHERE (doc ->> 'n')::int > 3"])] },
    Probe { cat: "JSON", name: "Aggregate rows into a JSON array", expect: Expect::EqNoSpace("[1,2]"), variants: &[
        ("json_group_array", v!["SELECT json_group_array(x) FROM (SELECT 1 AS x UNION ALL SELECT 2)"]), ("json_agg", v!["SELECT json_agg(x) FROM (SELECT 1 AS x UNION ALL SELECT 2) t"])] },
    Probe { cat: "JSON", name: "A JSON column rejects malformed JSON", expect: Expect::Err, variants: &[
        ("", v!["CREATE TABLE j (id INTEGER PRIMARY KEY, doc JSON)", "INSERT INTO j VALUES (1, 'not json')"]),
        ("with CHECK (json_valid(…))", v!["CREATE TABLE j (id INTEGER PRIMARY KEY, doc TEXT CHECK (json_valid(doc)))", "INSERT INTO j VALUES (1, 'not json')"])] },
    // ---- schema and constraints
    Probe { cat: "Schema", name: "Automatic ids", expect: Expect::Eq("2"), variants: &[
        ("AUTOINCREMENT", v!["CREATE TABLE a (id INTEGER PRIMARY KEY AUTOINCREMENT, v INT)", "INSERT INTO a (v) VALUES (5)", "INSERT INTO a (v) VALUES (6)", "SELECT max(id) FROM a"]),
        ("SERIAL", v!["CREATE TABLE a (id SERIAL PRIMARY KEY, v INT)", "INSERT INTO a (v) VALUES (5)", "INSERT INTO a (v) VALUES (6)", "SELECT max(id) FROM a"])] },
    Probe { cat: "Schema", name: "UNIQUE constraint", expect: Expect::Err, variants: &[
        ("", v!["CREATE TABLE u (id INTEGER PRIMARY KEY, e VARCHAR(40) UNIQUE)", "INSERT INTO u VALUES (1, 'a@x')", "INSERT INTO u VALUES (2, 'a@x')"])] },
    Probe { cat: "Schema", name: "NOT NULL with a DEFAULT", expect: Expect::Eq("7"), variants: &[
        ("", v!["CREATE TABLE n (id INTEGER PRIMARY KEY, v INT NOT NULL DEFAULT 7)", "INSERT INTO n (id) VALUES (1)", "SELECT v FROM n"])] },
    Probe { cat: "Schema", name: "CHECK constraint", expect: Expect::Err, variants: &[
        ("", v!["CREATE TABLE c (id INTEGER PRIMARY KEY, age INT CHECK (age >= 0))", "INSERT INTO c VALUES (1, -5)"])] },
    Probe { cat: "Schema", name: "Foreign keys enforced", expect: Expect::Err, variants: &[
        ("", v!["CREATE TABLE p (id INTEGER PRIMARY KEY)", "CREATE TABLE c (id INTEGER PRIMARY KEY, p_id INT REFERENCES p(id))", "INSERT INTO c VALUES (1, 99)"]),
        ("after PRAGMA foreign_keys = ON (off by default, per connection)", v!["PRAGMA foreign_keys = ON", "CREATE TABLE p (id INTEGER PRIMARY KEY)", "CREATE TABLE c (id INTEGER PRIMARY KEY, p_id INT REFERENCES p(id))", "INSERT INTO c VALUES (1, 99)"])] },
    Probe { cat: "Schema", name: "ON DELETE CASCADE", expect: Expect::Eq("0"), variants: &[
        ("", v!["CREATE TABLE p (id INTEGER PRIMARY KEY)", "CREATE TABLE c (id INTEGER PRIMARY KEY, p_id INT REFERENCES p(id) ON DELETE CASCADE)", "INSERT INTO p VALUES (1)", "INSERT INTO c VALUES (1, 1)", "DELETE FROM p WHERE id = 1", "SELECT count(*) FROM c"]),
        ("after PRAGMA foreign_keys = ON", v!["PRAGMA foreign_keys = ON", "CREATE TABLE p (id INTEGER PRIMARY KEY)", "CREATE TABLE c (id INTEGER PRIMARY KEY, p_id INT REFERENCES p(id) ON DELETE CASCADE)", "INSERT INTO p VALUES (1)", "INSERT INTO c VALUES (1, 1)", "DELETE FROM p WHERE id = 1", "SELECT count(*) FROM c"])] },
    Probe { cat: "Schema", name: "Composite primary key", expect: Expect::Err, variants: &[
        ("", v!["CREATE TABLE cp (a INT, b INT, v INT, PRIMARY KEY (a, b))", "INSERT INTO cp VALUES (1, 1, 1), (1, 2, 2)", "INSERT INTO cp VALUES (1, 1, 3)"])] },
    Probe { cat: "Schema", name: "Text primary key", expect: Expect::Eq("1"), variants: &[
        ("", v!["CREATE TABLE tk (code VARCHAR(10) PRIMARY KEY, v INT)", "INSERT INTO tk VALUES ('a', 1), ('b', 2)", "SELECT v FROM tk WHERE code = 'a'"])] },
    Probe { cat: "Schema", name: "Index on several columns", expect: Expect::Eq("1"), variants: &[
        ("", v!["CREATE TABLE mi (id INTEGER PRIMARY KEY, a INT, b INT)", "CREATE INDEX mi_ab ON mi (a, b)", "INSERT INTO mi VALUES (1, 1, 2), (2, 1, 3)", "SELECT count(*) FROM mi WHERE a = 1 AND b = 2"])] },
    Probe { cat: "Schema", name: "Index on a text column", expect: Expect::Eq("2"), variants: &[
        ("", with_users!["CREATE INDEX users_name ON users (name)", "SELECT id FROM users WHERE name = 'bob'"])] },
    Probe { cat: "Schema", name: "Expression or partial index", expect: Expect::Eq("1"), variants: &[
        ("expression", with_users!["CREATE INDEX users_lname ON users (lower(name))", "SELECT count(*) FROM users WHERE lower(name) = 'bob'"]),
        ("partial", with_users!["CREATE INDEX users_old ON users (age) WHERE age > 30", "SELECT count(*) FROM users WHERE age > 36"])] },
    Probe { cat: "Schema", name: "Generated columns", expect: Expect::Eq("6"), variants: &[
        ("", v!["CREATE TABLE g (id INTEGER PRIMARY KEY, a INT, b INT GENERATED ALWAYS AS (a * 2) VIRTUAL)", "INSERT INTO g (id, a) VALUES (1, 3)", "SELECT b FROM g"]),
        ("STORED", v!["CREATE TABLE g (id INTEGER PRIMARY KEY, a INT, b INT GENERATED ALWAYS AS (a * 2) STORED)", "INSERT INTO g (id, a) VALUES (1, 3)", "SELECT b FROM g"])] },
    Probe { cat: "Schema", name: "Views", expect: Expect::Eq("3"), variants: &[
        ("", with_users!["CREATE VIEW grown AS SELECT id FROM users WHERE age > 28", "SELECT count(*) FROM grown"])] },
    Probe { cat: "Schema", name: "Materialized views", expect: Expect::Eq("2"), variants: &[
        ("", with_users!["CREATE MATERIALIZED VIEW by_grp AS SELECT grp, count(*) AS n FROM users GROUP BY grp", "SELECT count(*) FROM by_grp"])] },
    Probe { cat: "Schema", name: "Triggers", expect: Expect::Eq("1"), variants: &[
        ("", v!["CREATE TABLE t (id INTEGER PRIMARY KEY)", "CREATE TABLE audit (id INTEGER PRIMARY KEY, t_id INT)", "CREATE TRIGGER t_ins AFTER INSERT ON t BEGIN INSERT INTO audit (t_id) VALUES (NEW.id); END", "INSERT INTO t VALUES (5)", "SELECT count(*) FROM audit"])] },
    Probe { cat: "Schema", name: "ALTER TABLE … ADD COLUMN", expect: Expect::Eq("x"), variants: &[
        ("", with_users!["ALTER TABLE users ADD COLUMN email VARCHAR(80) DEFAULT 'x'", "SELECT email FROM users WHERE id = 1"])] },
    Probe { cat: "Schema", name: "ALTER TABLE … DROP COLUMN", expect: Expect::Err, variants: &[
        ("", with_users!["ALTER TABLE users DROP COLUMN age", "SELECT age FROM users"])] },
    Probe { cat: "Schema", name: "ALTER TABLE … RENAME COLUMN", expect: Expect::Eq("bob"), variants: &[
        ("", with_users!["ALTER TABLE users RENAME COLUMN name TO full_name", "SELECT full_name FROM users WHERE id = 2"])] },
    Probe { cat: "Schema", name: "ALTER TABLE … RENAME TO", expect: Expect::Eq("4"), variants: &[
        ("", with_users!["ALTER TABLE users RENAME TO people", "SELECT count(*) FROM people"])] },
    Probe { cat: "Schema", name: "Change a column's type", expect: Expect::Eq("30"), variants: &[
        ("ALTER COLUMN … TYPE", with_users!["ALTER TABLE users ALTER COLUMN age TYPE BIGINT", "SELECT age FROM users WHERE id = 1"])] },
    Probe { cat: "Schema", name: "Case-insensitive comparison", expect: Expect::Eq("1"), variants: &[
        ("COLLATE NOCASE", with_users!["SELECT count(*) FROM users WHERE name = 'ALICE' COLLATE NOCASE"]), ("ILIKE", with_users!["SELECT count(*) FROM users WHERE name ILIKE 'ALICE'"])] },
    Probe { cat: "Schema", name: "List tables from SQL", expect: Expect::Ge1, variants: &[
        ("sqlite_schema", with_users!["SELECT count(*) FROM sqlite_schema WHERE type = 'table'"]), ("information_schema", with_users!["SELECT count(*) FROM information_schema.tables"]),
        ("SHOW TABLES", with_users!["SHOW TABLES"])] },
    Probe { cat: "Schema", name: "Attach a second database file", expect: Expect::Eq("0"), variants: &[
        ("", v!["ATTACH DATABASE '{DIR}/other.db' AS other", "CREATE TABLE other.t (id INTEGER PRIMARY KEY)", "SELECT count(*) FROM other.t"])] },
    // ---- queries
    Probe { cat: "Queries", name: "LEFT JOIN", expect: Expect::Eq("5"), variants: &[
        ("", with_uo!["SELECT count(*) FROM users u LEFT JOIN orders o ON o.user_id = u.id"])] },
    Probe { cat: "Queries", name: "Join three tables", expect: Expect::Eq("2"), variants: &[
        ("", with_uo!["CREATE TABLE items (id INTEGER PRIMARY KEY, order_id INT, qty INT)", "INSERT INTO items VALUES (1, 1, 2), (2, 3, 1)", "SELECT sum(i.qty) FROM users u JOIN orders o ON o.user_id = u.id JOIN items i ON i.order_id = o.id WHERE u.grp = 1"])] },
    Probe { cat: "Queries", name: "RIGHT and FULL OUTER joins", expect: Expect::Eq("5"), variants: &[
        ("", with_uo!["SELECT count(*) FROM orders o FULL OUTER JOIN users u ON o.user_id = u.id"])] },
    Probe { cat: "Queries", name: "IN (subquery)", expect: Expect::Eq("2"), variants: &[
        ("", with_uo!["SELECT count(*) FROM users WHERE id IN (SELECT user_id FROM orders)"])] },
    Probe { cat: "Queries", name: "EXISTS (subquery)", expect: Expect::Eq("2"), variants: &[
        ("uncorrelated", with_uo!["SELECT count(*) FROM users WHERE grp = 1 AND EXISTS (SELECT 1 FROM orders WHERE amount > 15)"]),
        ("correlated only", with_uo!["SELECT count(*) FROM users u WHERE EXISTS (SELECT 1 FROM orders o WHERE o.user_id = u.id)"])] },
    Probe { cat: "Queries", name: "Subquery in FROM (derived table)", expect: Expect::Eq("2"), variants: &[
        ("", with_uo!["SELECT count(*) FROM (SELECT user_id FROM orders WHERE amount >= 10) t"])] },
    Probe { cat: "Queries", name: "Correlated subquery", expect: Expect::Eq("alice"), variants: &[
        ("", with_uo!["SELECT name FROM users u WHERE (SELECT sum(amount) FROM orders o WHERE o.user_id = u.id) > 25"])] },
    Probe { cat: "Queries", name: "WITH (common table expressions)", expect: Expect::Eq("2"), variants: &[
        ("", with_uo!["WITH big AS (SELECT * FROM orders WHERE amount >= 10) SELECT count(*) FROM big"])] },
    Probe { cat: "Queries", name: "Recursive WITH", expect: Expect::Eq("15"), variants: &[
        ("", v!["WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < 5) SELECT sum(x) FROM n"])] },
    Probe { cat: "Queries", name: "Window functions", expect: Expect::Eq("2"), variants: &[
        ("", with_users!["SELECT max(r) FROM (SELECT row_number() OVER (PARTITION BY grp ORDER BY age) AS r FROM users) t"]),
        ("without a derived table", with_users!["SELECT row_number() OVER (PARTITION BY grp ORDER BY age) FROM users WHERE id = 4"])] },
    Probe { cat: "Queries", name: "GROUP BY with HAVING", expect: Expect::Eq("2"), variants: &[
        ("", with_users!["SELECT max(grp) FROM (SELECT grp FROM users GROUP BY grp HAVING avg(age) > 30) t"]),
        ("without a derived table", with_users!["SELECT grp FROM users GROUP BY grp HAVING avg(age) > 30"])] },
    Probe { cat: "Queries", name: "ORDER BY two columns", expect: Expect::Eq("bob"), variants: &[
        ("", with_users!["SELECT name FROM users WHERE grp = 1 ORDER BY grp, age LIMIT 1"]),
        ("sort columns must be selected", with_users!["SELECT name, grp, age FROM users WHERE grp = 1 ORDER BY grp, age LIMIT 1"])] },
    Probe { cat: "Queries", name: "LIMIT with OFFSET", expect: Expect::Eq("carol"), variants: &[
        ("", with_users!["SELECT name FROM users ORDER BY age DESC LIMIT 1 OFFSET 1"]),
        ("sort columns must be selected", with_users!["SELECT name, age FROM users ORDER BY age DESC LIMIT 1 OFFSET 1"])] },
    Probe { cat: "Queries", name: "SELECT DISTINCT", expect: Expect::Rows(2), variants: &[
        ("", with_uo!["SELECT DISTINCT user_id FROM orders"])] },
    Probe { cat: "Queries", name: "UNION and EXCEPT", expect: Expect::Eq("3"), variants: &[
        ("", with_uo!["SELECT count(*) FROM (SELECT id FROM users UNION SELECT user_id FROM orders EXCEPT SELECT 4) t"]),
        ("without a derived table", with_uo!["SELECT count(*) FROM users WHERE id IN (SELECT id FROM users UNION SELECT user_id FROM orders EXCEPT SELECT 4)"])] },
    Probe { cat: "Queries", name: "CASE expressions", expect: Expect::Eq("3"), variants: &[
        ("", with_users!["SELECT sum(CASE WHEN age >= 30 THEN 1 ELSE 0 END) FROM users"]),
        ("not inside an aggregate", with_users!["SELECT CASE WHEN age >= 30 THEN 3 ELSE 0 END FROM users WHERE id = 1"])] },
    Probe { cat: "Queries", name: "COUNT(DISTINCT …)", expect: Expect::Eq("2"), variants: &[
        ("", with_uo!["SELECT count(DISTINCT user_id) FROM orders"])] },
    Probe { cat: "Queries", name: "Aggregates (avg)", expect: Expect::Eq("32.5"), variants: &[
        ("", with_users!["SELECT avg(age) FROM users"])] },
    Probe { cat: "Queries", name: "Arithmetic on aggregates", expect: Expect::Eq("227.5"), variants: &[
        ("", with_users!["SELECT sum(age) + avg(age) + min(age) + max(age) FROM users"])] },
    Probe { cat: "Queries", name: "upper() and lower()", expect: Expect::Eq("ALICE"), variants: &[
        ("", with_users!["SELECT upper(name) FROM users WHERE id = 1"])] },
    Probe { cat: "Queries", name: "substr(), replace(), length()", expect: Expect::Eq("alicA"), variants: &[
        ("", with_users!["SELECT replace(substr(name, 1, length(name)), 'e', 'A') FROM users WHERE id = 1"]), ("replace only", with_users!["SELECT replace(name, 'e', 'A') FROM users WHERE id = 1"])] },
    Probe { cat: "Queries", name: "Concatenate strings", expect: Expect::Eq("alice-30"), variants: &[
        ("||", with_users!["SELECT name || '-' || age FROM users WHERE id = 1"]), ("concat()", with_users!["SELECT concat(name, '-', age) FROM users WHERE id = 1"])] },
    Probe { cat: "Queries", name: "Join strings across rows", expect: Expect::Eq("alice,bob,carol,dave"), variants: &[
        ("group_concat", with_users!["SELECT group_concat(name, ',') FROM (SELECT name FROM users ORDER BY id) t"]), ("string_agg", with_users!["SELECT string_agg(name, ',') FROM (SELECT name FROM users ORDER BY id) t"]),
        ("group_concat, no derived table", with_users!["SELECT group_concat(name, ',') FROM users"]), ("string_agg, no derived table", with_users!["SELECT string_agg(name, ',') FROM users"])] },
    Probe { cat: "Queries", name: "Math functions", expect: Expect::Eq("14"), variants: &[
        ("", v!["SELECT round(sqrt(16) + abs(-2) + power(2, 3), 1)"])] },
    Probe { cat: "Queries", name: "COALESCE, NULLIF, CAST", expect: Expect::Eq("7"), variants: &[
        ("", v!["SELECT coalesce(NULL, nullif(3, 3), CAST('7' AS INTEGER))"])] },
    Probe { cat: "Queries", name: "BETWEEN and IN lists", expect: Expect::Eq("2"), variants: &[
        ("", with_users!["SELECT count(*) FROM users WHERE age BETWEEN 26 AND 36 AND grp IN (1, 2)"])] },
    Probe { cat: "Queries", name: "Query plan (EXPLAIN)", expect: Expect::Any, variants: &[
        ("EXPLAIN QUERY PLAN", with_users!["EXPLAIN QUERY PLAN SELECT * FROM users WHERE id = 1"]), ("EXPLAIN", with_users!["EXPLAIN SELECT * FROM users WHERE id = 1"])] },
    // ---- search
    Probe { cat: "Search", name: "LIKE", expect: Expect::Eq("1"), variants: &[
        ("", with_users!["SELECT count(*) FROM users WHERE name LIKE 'a%'"])] },
    Probe { cat: "Search", name: "Case-insensitive LIKE", expect: Expect::Eq("1"), variants: &[
        ("ILIKE", with_users!["SELECT count(*) FROM users WHERE name ILIKE 'A%'"]), ("LIKE ignores case (ASCII)", with_users!["SELECT count(*) FROM users WHERE name LIKE 'A%'"])] },
    Probe { cat: "Search", name: "Regular expressions", expect: Expect::Eq("2"), variants: &[
        ("REGEXP", with_users!["SELECT count(*) FROM users WHERE name REGEXP '^[ab]'"]), ("~", with_users!["SELECT count(*) FROM users WHERE name ~ '^[ab]'"])] },
    Probe { cat: "Search", name: "Full-text search", expect: Expect::Eq("1"), variants: &[
        ("FTS5", &[DOCS_FTS5[0], DOCS_FTS5[1], "SELECT count(*) FROM docs WHERE docs MATCH 'hello'"]),
        ("fts index", v!["CREATE TABLE docs (id INTEGER PRIMARY KEY, body TEXT)", "CREATE INDEX docs_fts ON docs USING fts (body)", "INSERT INTO docs (body) VALUES ('the quick brown fox'), ('hello world'), ('lazy dogs sleep')", "SELECT count(*) FROM docs WHERE fts_match(body, 'hello')"]),
        ("tsvector", v!["CREATE TABLE docs (id INTEGER PRIMARY KEY, body VARCHAR(100))", "INSERT INTO docs (body) VALUES ('the quick brown fox'), ('hello world'), ('lazy dogs sleep')", "SELECT count(*) FROM docs WHERE to_tsvector(body) @@ to_tsquery('hello')"])] },
    Probe { cat: "Search", name: "Full-text relevance ranking", expect: Expect::Eq("1"), variants: &[
        ("bm25", &[DOCS_FTS5[0], DOCS_FTS5[1], "SELECT count(*) FROM (SELECT rowid FROM docs WHERE docs MATCH 'fox OR hello' ORDER BY bm25(docs) LIMIT 1) t"]),
        ("fts_score", v!["CREATE TABLE docs (id INTEGER PRIMARY KEY, body TEXT)", "CREATE INDEX docs_fts ON docs USING fts (body)", "INSERT INTO docs (body) VALUES ('the quick brown fox'), ('hello world'), ('lazy dogs sleep')", "SELECT count(*) FROM (SELECT id FROM docs WHERE fts_match(body, 'fox OR hello') ORDER BY fts_score(body, 'fox OR hello') DESC LIMIT 1) t"])] },
    Probe { cat: "Search", name: "Vector similarity (nearest embedding)", expect: Expect::Eq("1"), variants: &[
        ("vector32 + vector_distance_cos", v!["CREATE TABLE e (id INTEGER PRIMARY KEY, emb BLOB)", "INSERT INTO e VALUES (1, vector32('[1,0,0]')), (2, vector32('[0,1,0]'))", "SELECT id FROM e ORDER BY vector_distance_cos(emb, vector32('[0.9,0.1,0]')) LIMIT 1"]),
        ("pgvector <=>", v!["CREATE TABLE e (id INTEGER PRIMARY KEY, emb VECTOR(3))", "INSERT INTO e VALUES (1, '[1,0,0]'), (2, '[0,1,0]')", "SELECT id FROM e ORDER BY emb <=> '[0.9,0.1,0]' LIMIT 1"])] },
    Probe { cat: "Search", name: "Vector index", expect: Expect::Eq("1"), variants: &[
        ("toy_vector_sparse_ivf, sparse vectors only", v!["CREATE TABLE e (id INTEGER PRIMARY KEY, emb BLOB)", "CREATE INDEX e_idx ON e USING toy_vector_sparse_ivf (emb)", "INSERT INTO e VALUES (1, vector32_sparse('[1,0,0]')), (2, vector32_sparse('[0,1,0]'))", "SELECT id FROM e ORDER BY vector_distance_jaccard(emb, vector32_sparse('[1,0,0]')) LIMIT 1"])] },
    // ---- writes
    Probe { cat: "Writes", name: "UPSERT (ON CONFLICT DO UPDATE)", expect: Expect::Eq("2"), variants: &[
        ("", v!["CREATE TABLE kv (k INTEGER PRIMARY KEY, v INT)", "INSERT INTO kv VALUES (1, 1)", "INSERT INTO kv VALUES (1, 2) ON CONFLICT (k) DO UPDATE SET v = excluded.v", "SELECT v FROM kv WHERE k = 1"])] },
    Probe { cat: "Writes", name: "Insert, ignoring duplicates", expect: Expect::Eq("1"), variants: &[
        ("ON CONFLICT DO NOTHING", v!["CREATE TABLE kv (k INTEGER PRIMARY KEY, v INT)", "INSERT INTO kv VALUES (1, 1)", "INSERT INTO kv VALUES (1, 2) ON CONFLICT DO NOTHING", "SELECT v FROM kv WHERE k = 1"]),
        ("INSERT OR IGNORE", v!["CREATE TABLE kv (k INTEGER PRIMARY KEY, v INT)", "INSERT INTO kv VALUES (1, 1)", "INSERT OR IGNORE INTO kv VALUES (1, 2)", "SELECT v FROM kv WHERE k = 1"])] },
    Probe { cat: "Writes", name: "INSERT … RETURNING", expect: Expect::Eq("7"), variants: &[
        ("", v!["CREATE TABLE r (id INTEGER PRIMARY KEY, v INT)", "INSERT INTO r (id, v) VALUES (7, 5) RETURNING id"])] },
    Probe { cat: "Writes", name: "UPDATE … RETURNING", expect: Expect::Eq("6"), variants: &[
        ("", v!["CREATE TABLE r (id INTEGER PRIMARY KEY, v INT)", "INSERT INTO r VALUES (7, 5)", "UPDATE r SET v = 6 WHERE id = 7 RETURNING v"])] },
    Probe { cat: "Writes", name: "INSERT … SELECT", expect: Expect::Eq("2"), variants: &[
        ("", with_users!["CREATE TABLE u2 (id INTEGER PRIMARY KEY, name VARCHAR(40))", "INSERT INTO u2 SELECT id, name FROM users WHERE grp = 1", "SELECT count(*) FROM u2"])] },
    Probe { cat: "Writes", name: "CREATE TABLE … AS SELECT", expect: Expect::Eq("2"), variants: &[
        ("", with_users!["CREATE TABLE u2 AS SELECT id, name FROM users WHERE grp = 1", "SELECT count(*) FROM u2"])] },
    Probe { cat: "Writes", name: "UPDATE with a subquery", expect: Expect::Eq("20"), variants: &[
        ("", with_uo!["UPDATE users SET age = (SELECT max(amount) FROM orders) WHERE id = 2", "SELECT age FROM users WHERE id = 2"])] },
    Probe { cat: "Writes", name: "UPDATE … FROM another table", expect: Expect::Eq("5"), variants: &[
        ("", with_uo!["UPDATE users SET age = o.amount FROM orders o WHERE o.user_id = users.id AND o.id = 3", "SELECT age FROM users WHERE id = 3"])] },
    Probe { cat: "Writes", name: "DELETE with a subquery", expect: Expect::Eq("2"), variants: &[
        ("", with_uo!["DELETE FROM users WHERE id NOT IN (SELECT user_id FROM orders)", "SELECT count(*) FROM users"])] },
    // ---- transactions
    Probe { cat: "Transactions", name: "BEGIN, COMMIT, ROLLBACK", expect: Expect::Eq("0"), variants: &[
        ("", v!["CREATE TABLE t (id INTEGER PRIMARY KEY)", "BEGIN", "INSERT INTO t VALUES (1)", "ROLLBACK", "SELECT count(*) FROM t"])] },
    Probe { cat: "Transactions", name: "Savepoints", expect: Expect::Eq("1"), variants: &[
        ("", v!["CREATE TABLE t (id INTEGER PRIMARY KEY)", "BEGIN", "INSERT INTO t VALUES (1)", "SAVEPOINT s", "INSERT INTO t VALUES (2)", "ROLLBACK TO s", "COMMIT", "SELECT count(*) FROM t"])] },
    Probe { cat: "Transactions", name: "A transaction sees its own writes", expect: Expect::Eq("5"), variants: &[
        ("", with_users!["BEGIN", "INSERT INTO users VALUES (5, 'eve', 20, 1)", "SELECT count(*) FROM users"])] },
    Probe { cat: "Transactions", name: "Concurrent writers syntax (BEGIN CONCURRENT)", expect: Expect::Eq("1"), variants: &[
        ("MVCC journal mode", v!["PRAGMA journal_mode = 'experimental_mvcc'", "CREATE TABLE t (id INTEGER PRIMARY KEY)", "BEGIN CONCURRENT", "INSERT INTO t VALUES (1)", "COMMIT", "SELECT count(*) FROM t"])] },
    // ---- operations, from SQL
    Probe { cat: "Operations", name: "Copy a live database (VACUUM INTO)", expect: Expect::Eq("1"), variants: &[
        ("", with_users!["VACUUM INTO '{DIR}/copy.db'", "SELECT 1"])] },
    Probe { cat: "Operations", name: "Change capture readable from SQL", expect: Expect::Ge1, variants: &[
        ("PRAGMA capture_data_changes_conn", v!["PRAGMA capture_data_changes_conn('full')", "CREATE TABLE t (id INTEGER PRIMARY KEY, v INT)", "INSERT INTO t VALUES (1, 1)", "SELECT count(*) FROM turso_cdc"])] },
];

// ---- engines

#[derive(Clone, Copy, PartialEq)] enum Engine { Ours, Sqlite, Turso, TursoExperimental }
static SEQ: AtomicU64 = AtomicU64::new(0);
fn fresh_dir() -> PathBuf { let d = PathBuf::from(format!("data/nocow/e54/{}", SEQ.fetch_add(1, Ordering::Relaxed))); let _ = std::fs::remove_dir_all(&d); std::fs::create_dir_all(&d).unwrap(); d }
fn fmt_f(f: f64) -> String { if f.fract() == 0.0 && f.abs() < 1e15 { format!("{}", f as i64) } else { format!("{f}") } }
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

/// Run the statements on a fresh database; the result is the first column of the last statement's first row.
/// On failure: the index of the failing statement and its message.
fn run(engine: Engine, stmts: &[String], dir: &PathBuf) -> Result<(Option<String>, usize), (usize, String)> {
    match engine {
        Engine::Ours => {
            let sql = Sql::open_with(&dir.join("db"), Config::default()).map_err(|e| (0, e))?;
            let mut se = Session::default(); let mut last = None; let mut n = 0;
            for (i, q) in stmts.iter().enumerate() {
                let rows = sql.exec_s(&mut se, q, &[]).map_err(|e| (i, e))?; n = rows.len();
                last = rows.first().and_then(|r| r.first()).map(|v| match v { Value::Int(i) => i.to_string(), Value::Float(f) => fmt_f(*f), Value::Bool(b) => (*b as i32).to_string(), Value::Text(s) => s.clone(), Value::Bytes(b) => hex(b), Value::Null => "NULL".into() });
            }
            Ok((last, n))
        }
        Engine::Sqlite => {
            let c = rusqlite::Connection::open(dir.join("db.sqlite")).map_err(|e| (0, e.to_string()))?; let mut last = None; let mut n = 0;
            for (i, q) in stmts.iter().enumerate() {
                let mut st = c.prepare(q).map_err(|e| (i, e.to_string()))?; let mut rows = st.query([]).map_err(|e| (i, e.to_string()))?; last = None; n = 0;
                if let Some(r) = rows.next().map_err(|e| (i, e.to_string()))? { last = Some(match r.get_ref(0).map_err(|e| (i, e.to_string()))? { ValueRef::Null => "NULL".into(), ValueRef::Integer(x) => x.to_string(), ValueRef::Real(f) => fmt_f(f), ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(), ValueRef::Blob(b) => hex(b) }); n = 1; }
                while rows.next().map_err(|e| (i, e.to_string()))?.is_some() { n += 1; }
            }
            Ok((last, n))
        }
        Engine::Turso | Engine::TursoExperimental => {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            rt.block_on(async {
                let mut b = turso::Builder::new_local(dir.join("db.turso").to_str().unwrap());
                if engine == Engine::TursoExperimental { b = b.experimental_triggers(true).experimental_attach(true).experimental_strict(true).experimental_custom_types(true).experimental_generated_columns(true).experimental_index_method(true).experimental_materialized_views(true).experimental_vacuum(true).experimental_without_rowid(true); }
                let db = b.build().await.map_err(|e| (0, e.to_string()))?; let c = db.connect().map_err(|e| (0, e.to_string()))?; let mut last = None; let mut n = 0;
                for (i, q) in stmts.iter().enumerate() {
                    let mut rows = c.query(q, ()).await.map_err(|e| (i, e.to_string()))?; last = None; let mut first = true; n = 0;
                    while let Some(r) = rows.next().await.map_err(|e| (i, e.to_string()))? { n += 1;
                        if first { first = false; last = Some(match r.get_value(0).map_err(|e| (i, e.to_string()))? { turso::Value::Null => "NULL".into(), turso::Value::Integer(x) => x.to_string(), turso::Value::Real(f) => fmt_f(f), turso::Value::Text(t) => t, turso::Value::Blob(b) => hex(&b) }); }
                    }
                }
                Ok((last, n))
            })
        }
    }
}

enum Cell { Works(String), Wrong(String), Missing(String) }
fn check(expect: Expect, n: usize, r: &Result<(Option<String>, usize), (usize, String)>) -> Result<(), Cell> {
    let is_uuid = |s: &str| s.len() == 36 && s.chars().enumerate().all(|(i, c)| if [8, 13, 18, 23].contains(&i) { c == '-' } else { c.is_ascii_hexdigit() });
    match (expect, r) {
        (Expect::Err, Err((i, _))) if *i == n - 1 => Ok(()),
        (Expect::Err, Err((_, e))) => Err(Cell::Missing(e.clone())),
        (Expect::Err, Ok(_)) => Err(Cell::Wrong("accepted".into())),
        (_, Err((_, e))) => Err(Cell::Missing(e.clone())),
        (Expect::Rows(want), Ok((_, got))) => if *got == want { Ok(()) } else { Err(Cell::Wrong(format!("{got} rows"))) },
        (_, Ok((None, _))) => Err(Cell::Wrong("no rows".into())),
        (Expect::Eq(x), Ok((Some(v), _))) => if v == x { Ok(()) } else { Err(Cell::Wrong(format!("returned {v}"))) },
        (Expect::EqNoSpace(x), Ok((Some(v), _))) => if v.replace(' ', "") == x { Ok(()) } else { Err(Cell::Wrong(format!("returned {v}"))) },
        (Expect::Prefix(x), Ok((Some(v), _))) => if v.starts_with(x) { Ok(()) } else { Err(Cell::Wrong(format!("returned {v}"))) },
        (Expect::Uuid, Ok((Some(v), _))) => if is_uuid(v) { Ok(()) } else { Err(Cell::Wrong(format!("returned {v}"))) },
        (Expect::Any, Ok((Some(v), _))) => if v != "NULL" { Ok(()) } else { Err(Cell::Wrong("NULL".into())) },
        (Expect::Ge1, Ok((Some(v), _))) => if v.parse::<i64>().map(|n| n >= 1).unwrap_or(false) { Ok(()) } else { Err(Cell::Wrong(format!("returned {v}"))) },
    }
}

fn probe(engine: Engine, p: &Probe) -> Cell {
    let long = "x".repeat(10_000); let huge = "y".repeat(100_000);
    let mut first_missing = None; let mut wrong = None;
    // a probe that is a single SELECT without FROM is retried against a one-row table: some engines need a FROM
    let mut variants: Vec<(String, Vec<&str>)> = p.variants.iter().map(|(l, s)| (l.to_string(), s.to_vec())).collect();
    let extra: Vec<(String, Vec<String>)> = p.variants.iter().filter(|(_, s)| s.len() == 1 && s[0].starts_with("SELECT") && !s[0].contains(" FROM ")).map(|(l, s)| (if l.is_empty() { "needs a FROM clause".to_string() } else { format!("{l}, needs a FROM clause") }, vec!["CREATE TABLE one (id INTEGER PRIMARY KEY)".to_string(), "INSERT INTO one VALUES (1)".to_string(), format!("{} FROM one", s[0])])).collect();
    let extra_refs: Vec<(String, Vec<&str>)> = extra.iter().map(|(l, s)| (l.clone(), s.iter().map(|x| x.as_str()).collect())).collect();
    variants.extend(extra_refs);
    for (label, stmts) in &variants {
        let dir = fresh_dir();
        let stmts: Vec<String> = stmts.iter().map(|s| s.replace("{LONG}", &long).replace("{HUGE}", &huge).replace("{DIR}", dir.to_str().unwrap())).collect();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(engine, &stmts, &dir))).unwrap_or_else(|_| Err((usize::MAX, "panicked".into())));
        let _ = std::fs::remove_dir_all(&dir);
        match check(p.expect, stmts.len(), &r) {
            Ok(()) => return Cell::Works(label.clone()),
            Err(Cell::Wrong(w)) => { if wrong.is_none() { wrong = Some(if label.is_empty() { w } else { format!("{label}: {w}") }); } }
            Err(Cell::Missing(m)) => { if first_missing.is_none() || first_missing.as_deref().map(|f: &str| f.contains("between one and eight tables in FROM")).unwrap_or(false) && !m.contains("between one and eight tables in FROM") { first_missing = Some(m); } }
            Err(Cell::Works(_)) => unreachable!(),
        }
    }
    if let Some(w) = wrong { Cell::Wrong(w) } else { Cell::Missing(first_missing.unwrap_or_default()) }
}

fn cell_text(c: &Cell) -> String {
    let clean = |s: &str| s.replace(['\t', '\n'], " ").chars().take(140).collect::<String>();
    match c { Cell::Works(l) if l.is_empty() => "yes".into(), Cell::Works(l) => format!("yes: {}", clean(l)), Cell::Wrong(w) => format!("wrong: {}", clean(w)), Cell::Missing(m) => format!("no: {}", clean(m)) }
}

/// Features that need the engine's API rather than SQL: encryption of the local files, change notifications in the
/// process, an online copy of a live database. One row per feature, a cell per engine.
fn extras() {
    const MARK: &str = "PLAINTEXT-MARKER-7f3a";
    let has_mark = |dir: &PathBuf| -> bool { std::fs::read_dir(dir).unwrap().flatten().any(|e| e.path().is_file() && std::fs::read(e.path()).map(|b| b.windows(MARK.len()).any(|w| w == MARK.as_bytes())).unwrap_or(false)) };
    println!("category\tfeature\tsqweezdb\tsqlite\tturso");
    // encryption at rest
    let ours = { let d = fresh_dir(); { let s = Sql::open_with(&d.join("db"), Config::default()).unwrap(); let mut se = Session::default(); s.exec_s(&mut se, "CREATE TABLE t (id INTEGER PRIMARY KEY, s VARCHAR(40))", &[]).unwrap(); s.exec_s(&mut se, &format!("INSERT INTO t VALUES (1, '{MARK}')"), &[]).unwrap(); s.snapshot(); }
        if has_mark(&d.join("db")) { "no: the log and snapshot are plaintext; backups are encrypted with AES-256-GCM (E35)".to_string() } else { "yes".into() } };
    let lite = { let d = fresh_dir(); { let c = rusqlite::Connection::open(d.join("db.sqlite")).unwrap(); c.execute_batch(&format!("CREATE TABLE t (id INTEGER PRIMARY KEY, s TEXT); INSERT INTO t VALUES (1, '{MARK}');")).unwrap(); }
        if has_mark(&d) { "no: plaintext file (encryption needs SEE, SQLCipher or a VFS)".to_string() } else { "yes".into() } };
    let turso = { let d = fresh_dir(); let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap(); let path = d.join("db.turso"); let path = path.to_str().unwrap().to_string();
        let key = "b1bbfda4f589dc9daaf004fe21111e00dc00c98237102f5c7002a5669fc76327".to_string();
        let opts = || turso::core::EncryptionOpts { cipher: "aegis256".into(), hexkey: key.clone() };
        let wrote: Result<(), String> = rt.block_on(async { let db = turso::Builder::new_local(&path).experimental_encryption(true).with_encryption(opts()).build().await.map_err(|e| e.to_string())?; let c = db.connect().map_err(|e| e.to_string())?;
            c.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, s TEXT)", ()).await.map_err(|e| e.to_string())?; c.execute(&format!("INSERT INTO t VALUES (1, '{MARK}')"), ()).await.map_err(|e| e.to_string())?; Ok(()) });
        let read_with_key: Result<String, String> = rt.block_on(async { let db = turso::Builder::new_local(&path).experimental_encryption(true).with_encryption(opts()).build().await.map_err(|e| e.to_string())?; let c = db.connect().map_err(|e| e.to_string())?;
            let mut r = c.query("SELECT s FROM t", ()).await.map_err(|e| e.to_string())?; let row = r.next().await.map_err(|e| e.to_string())?.ok_or("no row")?; Ok(format!("{:?}", row.get_value(0).map_err(|e| e.to_string())?)) });
        let read_without: Result<(), String> = rt.block_on(async { let db = turso::Builder::new_local(&path).build().await.map_err(|e| e.to_string())?; let c = db.connect().map_err(|e| e.to_string())?; let mut r = c.query("SELECT s FROM t", ()).await.map_err(|e| e.to_string())?; r.next().await.map_err(|e| e.to_string())?; Ok(()) });
        match wrote { Err(e) => format!("no: {e}"), Ok(()) => if has_mark(&d) { "no: the marker is readable in the file".into() } else if read_with_key.as_ref().map(|v| v.contains(MARK)).unwrap_or(false) && read_without.is_err() { "yes: AEGIS or AES-GCM page encryption (experimental flag); unreadable without the key".into() } else { format!("partial: read with key {read_with_key:?}, without key {read_without:?}") } } };
    println!("Operations\tEncryption of the database files\t{ours}\t{lite}\t{turso}");
    // change notifications inside the process
    let ours = { let d = fresh_dir(); let s = Sql::open_with(&d.join("db"), Config::default()).unwrap(); let mut se = Session::default(); s.exec_s(&mut se, "CREATE TABLE t (id INTEGER PRIMARY KEY, v INT)", &[]).unwrap();
        let sub = s.reactor().subscribe(&Session::default(), "SELECT * FROM t WHERE v > 10", &[]).unwrap(); s.exec_s(&mut se, "INSERT INTO t VALUES (1, 5), (2, 50)", &[]).unwrap();
        let mut n = 0; let t = std::time::Instant::now(); while t.elapsed() < std::time::Duration::from_secs(2) { if sub.recv_timeout(std::time::Duration::from_millis(100)).is_some() { n += 1; } if n >= 1 && sub.pending() == 0 { std::thread::sleep(std::time::Duration::from_millis(50)); if sub.pending() == 0 { break; } } }
        if n == 1 { "yes: filtered subscriptions and live queries, with row policies, also to other processes (E37); a resumable change feed (E32)".to_string() } else { format!("wrong: {n} events for one matching row") } };
    let lite = { let d = fresh_dir(); let c = rusqlite::Connection::open(d.join("db.sqlite")).unwrap(); c.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, v INT)").unwrap();
        let n = std::sync::Arc::new(AtomicU64::new(0)); let n2 = n.clone(); c.update_hook(Some(move |_: rusqlite::hooks::Action, _: &str, _: &str, _: i64| { n2.fetch_add(1, Ordering::Relaxed); })).ok(); c.execute_batch("INSERT INTO t VALUES (1, 5), (2, 50)").unwrap();
        format!("partial: update_hook gives table and rowid for every change ({} for 2 rows), same connection only, no filter", n.load(Ordering::Relaxed)) };
    println!("Realtime\tChange notifications in the process\t{ours}\t{lite}\tpartial: change capture into a table read with SQL (turso_cdc), no push");
    // online copy of a live database
    let ours = "yes: snapshot while writers run, point-in-time restore, followers (E26)".to_string();
    let lite = { let d = fresh_dir(); let c = rusqlite::Connection::open(d.join("db.sqlite")).unwrap(); c.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY); INSERT INTO t VALUES (1), (2), (3);").unwrap();
        let mut dst = rusqlite::Connection::open(d.join("copy.sqlite")).unwrap(); { let b = rusqlite::backup::Backup::new(&c, &mut dst).unwrap(); b.run_to_completion(64, std::time::Duration::from_millis(0), None).unwrap(); }
        let n: i64 = dst.query_row("SELECT count(*) FROM t", [], |r| r.get(0)).unwrap(); if n == 3 { "yes: the backup API and VACUUM INTO".to_string() } else { format!("wrong: {n}") } };
    println!("Operations\tOnline copy of a live database\t{ours}\t{lite}\tyes: VACUUM INTO");
    // can another tool read the file?
    let turso = { let d = fresh_dir(); let path = d.join("db.turso"); let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async { let db = turso::Builder::new_local(path.to_str().unwrap()).build().await.unwrap(); let c = db.connect().unwrap(); c.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, s TEXT)", ()).await.unwrap(); c.execute("INSERT INTO t VALUES (1, 'a'), (2, 'b')", ()).await.unwrap(); });
        let n: Result<i64, String> = rusqlite::Connection::open(&path).map_err(|e| e.to_string()).and_then(|c| c.query_row("SELECT count(*) FROM t", [], |r| r.get(0)).map_err(|e| e.to_string()));
        match n { Ok(2) => "yes: SQLite opens the file Turso wrote".to_string(), other => format!("no: {other:?}") } };
    println!("Operations\tData readable by other tools\tno: its own log and snapshot format; read it through sqweezdb (shell, console, bindings)\tyes: the most widely supported file format\t{turso}");
    let _ = std::fs::remove_dir_all("data/nocow/e54");
}

fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    if std::env::args().nth(1).as_deref() == Some("extras") { let _ = std::fs::remove_dir_all("data/nocow/e54"); return extras(); }
    let _ = std::fs::remove_dir_all("data/nocow/e54");
    println!("category\tfeature\tsqweezdb\tsqlite\tturso");
    for p in PROBES {
        let ours = probe(Engine::Ours, p); let lite = probe(Engine::Sqlite, p);
        let turso = match probe(Engine::Turso, p) { Cell::Works(l) => Cell::Works(l), other => match probe(Engine::TursoExperimental, p) { Cell::Works(l) => Cell::Works(if l.is_empty() { "experimental flag".into() } else { format!("{l} (experimental flag)") }), _ => other } };
        println!("{}\t{}\t{}\t{}\t{}", p.cat, p.name, cell_text(&ours), cell_text(&lite), cell_text(&turso));
    }
    let _ = std::fs::remove_dir_all("data/nocow/e54");
}
