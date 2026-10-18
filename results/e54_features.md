# Feature matrix: sqweezdb, PocketBase 0.40.5, SQLite 3.53.4, Turso 0.8.3

Every cell comes from a probe run on the lab machine (E54), from an earlier experiment it names, or is marked 📄 when
only the product's documentation says so. ✅ works · ⚠️ partial, or only behind a setting · ⛔ runs but gives a wrong
answer · ❌ missing · 📄 documented, not tested here · — not applicable.

Sources: `src/bin/e54_features.rs` (SQL probes, each on a fresh database, and the engine extras), `lab/e54_pocketbase.py`
(PocketBase through its HTTP API, with a local mail server and S3 server), raw output in `results/e54_features_*.tsv`.
Turso is tried with its default build first, then with its experimental features switched on.

## In numbers

| SQL features (88) | ✅ | ⚠️ | ⛔ wrong | ❌ |
|---|---:|---:|---:|---:|
| sqweezdb | 49 | 4 | 0 | 35 |
| SQLite | 73 | 5 | 2 | 8 |
| Turso | 72 | 12 | 2 | 2 |

| Product features (38) | ✅ | ⚠️ | ❌ | 📄 | — |
|---|---:|---:|---:|---:|---:|
| PocketBase | 23 | 4 | 6 | 2 | 3 |
| sqweezdb | 14 | 6 | 16 | 0 | 2 |
| SQLite | 7 | 4 | 19 | 4 | 4 |
| Turso | 8 | 7 | 11 | 8 | 4 |

PocketBase's SQL is SQLite's (it runs on SQLite), reachable through view collections and hooks rather than its REST API.

## Wrong answers without an error (sqweezdb)

None now. The first run (`results/e54_features_sql_before_h63.tsv`) found the cases below. Each now fails with `SYNTAX` ("unsupported: … is not implemented yet") or, for the transaction, `TRANSACTION`, and SQL that is not implemented is refused rather than ignored.

- ~~**Text longer than 64 KB**: `VARCHAR(100000)` is accepted, but a 100,000-byte value comes back different from what was inserted (its length is kept in two bytes).~~ now an error
- ~~**A JSON column rejects malformed JSON**: `CHECK (json_valid(doc))` is accepted and never enforced (the same cause as CHECK).~~ now an error
- ~~**CHECK constraint**: accepted by CREATE TABLE and never enforced: `age = -5` was inserted.~~ now an error
- ~~**Generated columns**: `GENERATED ALWAYS AS (a * 2)` is accepted; the column reads NULL.~~ now an error
- ~~**GROUP BY with HAVING**: HAVING is ignored: every group comes back.~~ now an error
- ~~**ORDER BY two columns**: only the first ORDER BY column sorts; the second is ignored.~~ now an error
- ~~**LIMIT with OFFSET**: OFFSET is ignored: the first rows come back.~~ now an error
- ~~**SELECT DISTINCT**: DISTINCT is ignored: 3 rows instead of 2.~~ now an error
- ~~**COUNT(DISTINCT …)**: duplicates are counted: 3 instead of 2.~~ now an error
- ~~**UPDATE … RETURNING**: RETURNING is ignored on UPDATE: no rows come back.~~ now an error
- ~~**A transaction sees its own writes**: a read inside a transaction does not see the rows the transaction wrote (documented in the README).~~ now an error

## Product features

|  | Feature | PocketBase | sqweezdb | SQLite | Turso |
|---|---|---|---|---|---|
| Backend | Admin UI | ✅ the admin dashboard at /_/ | ✅ web console: SQL editor, tables, change feed, access, backup (E43, E51) | ❌ third-party tools | ❌ locally; 📄 Turso Cloud dashboard |
| Backend | REST API for each table, no code | ✅ create, list, view, update and delete for every collection, no code | ❌ the app writes its endpoints (the console's SQL endpoint is for admins) | ❌ | ❌ locally; 📄 Turso Cloud has an HTTP SQL API |
| Backend | Server-side code (hooks, custom routes) | ✅ JavaScript hooks (custom routes, record events), or Go when used as a library | ⚠️ the app embeds the database; no triggers or hooks inside it | ⚠️ triggers, functions registered by the app | ⚠️ triggers |
| Backend | Scheduled jobs (cron) | ✅ cronAdd() in hooks; listed and runnable from the API | ❌ | ❌ | ❌ |
| Backend | Filter, sort, page and expand relations over HTTP | ✅ filter expressions (=, !=, >, ~ contains, ?= any), JSON paths, multi-column sort, pages; expand=relation returns the related record inline | — SQL through a binding or TCP | — SQL | — SQL |
| Backend | SQL views | ⚠️ a SQL SELECT with joins and JSON functions becomes a read-only collection; its column parser refused a window function | ❌ (E54 SQL) | ✅ | ✅ |
| Backend | Transactions | ✅ /api/batch (off by default), all or nothing | ⚠️ BEGIN/COMMIT; no savepoints; only lookups by primary key see the transaction's own writes, other reads of a table it wrote are refused | ✅ | ✅ |
| Backend | Schema as code (migrations, export/import) | ✅ every schema change made in the UI or API is written as a JS migration file (2 so far); export the collections as JSON and import them into another instance | ⚠️ online ALTER with writers running (E30); no migration files | ❌ external tools | ❌ external tools |
| Auth | Email and password sign-in | ✅ sign-up, sign-in, token refresh, built-in users collection | ❌ the app signs users in and passes their identity per request (E49) | ❌ | ❌ |
| Auth | OAuth2 (Google, GitHub, …) | ✅ providers configured by settings, the sign-in URL and code exchange handled by the server (verified up to the provider's redirect; no real Google account used) | ❌ | ❌ | ❌ |
| Auth | Email verification, password reset, one-time codes | ✅ verification link, reset link and OTP all received and completed through a local mail server | ❌ | ❌ | ❌ |
| Auth | Multi-factor authentication | ✅ with MFA on, a password alone returns an mfaId that a second method (OTP, OAuth2) must complete | ❌ | ❌ | ❌ |
| Auth | Act as a user | ✅ a superuser gets a token acting as any user | ⚠️ the app passes any identity per request (Assume) | — | — |
| Auth | Per-user access rules | ✅ per-collection rules on the request's user and on related records (E52) | ⚠️ roles, grants and row policies enforced in the engine (E16, E49); a policy cannot follow a relation (E52) | ❌ | ❌ |
| Files | File uploads with thumbnails | ✅ file fields, size and type limits, thumbnails generated on request (100x100 verified) | ❌ BLOB columns need a declared maximum (≤ 64 KB); no file API | ⚠️ BLOBs up to 1 GB; no file API | ⚠️ BLOBs; no file API |
| Files | Files in S3-compatible storage | ✅ files stored in an S3-compatible bucket (tested against a local S3 server) | ❌ | ❌ | ❌ |
| Realtime | Push changes to browsers | ✅ SSE subscriptions with rules (E52) | ⚠️ subscriptions in the engine; the app relays them (E39 example, E52 demo) | ❌ | ❌ |
| Realtime | Change notifications in the process | ⚠️ record events in hooks | ✅ filtered subscriptions and live queries, with row policies, also to other processes (E37); a resumable change feed (E32) | ⚠️ update_hook gives table and rowid for every change (2 for 2 rows), same connection only, no filter | ⚠️ change capture into a table read with SQL (turso_cdc), no push |
| Realtime | Resumable change feed | ❌ | ✅ by log sequence (E32) | ❌ | ⚠️ turso_cdc table (E54 SQL) |
| Scale | Many concurrent writers | ❌ one SQLite writer: 8–9k inserts/s (E52) | ✅ 132–166k durable commits/s at 256 writers (E50) | ❌ one writer at a time: 2.3k durable commits/s at any count (E50) | ✅ experimental MVCC: 107–118k at 256 (E50) |
| Scale | A database per tenant or agent | ⚠️ a process per tenant: 35 MB each (E53) | ✅ 100 KB per open database, 0.23 ms to create (E38, E53) | ✅ a file each: 188 KB open (E53) | ✅ a file each: 0.9–1.2 MB open (E53) |
| Scale | Access from other processes | — over HTTP | ✅ through the owner process: Unix socket, shared memory, TCP (E40) | ✅ file locking | 📄 experimental multi-process WAL |
| Scale | Network access | ✅ HTTP | ✅ TCP with a token, and the console (E40) | ❌ | 📄 Turso Cloud, or a server |
| Search | Full-text search | ⚠️ filter ~ is a LIKE '%…%' scan; no index or ranking | ❌ (E54 SQL) | ✅ FTS5 with bm25 | ⚠️ experimental fts index with scores |
| Search | Vector similarity | ❌ | ❌ | ❌ without an extension; 📄 sqlite-vec | ✅ vector functions; ⚠️ only an experimental sparse index |
| Operations | Backups | ✅ a zip of pb_data from the API or UI, scheduled backups, optionally to S3; restore replaces the data and restarts | ✅ continuous to S3, compressed, optionally encrypted (E33, E35) | ⚠️ backup API; continuous only with Litestream (E33) | ⚠️ VACUUM INTO; 📄 continuous in Turso Cloud |
| Operations | Point-in-time restore | ❌ restore a whole backup | ✅ (E26) | ❌; 📄 Litestream | 📄 Turso Cloud |
| Operations | Read replicas | ❌ | ✅ followers from a directory or a bucket (E26, E42) | ❌; 📄 LiteFS | 📄 embedded replicas synced with Turso Cloud |
| Operations | Online copy of a live database | ✅ backup zip | ✅ snapshot while writers run, point-in-time restore, followers (E26) | ✅ the backup API and VACUUM INTO | ✅ VACUUM INTO |
| Operations | Encryption of the database files | ❌ only its settings (--encryptionEnv) | ❌ the log and snapshot are plaintext; backups are encrypted with AES-256-GCM (E35) | ❌ plaintext file (encryption needs SEE, SQLCipher or a VFS) | ⚠️ AEGIS or AES-GCM page encryption (experimental flag); unreadable without the key |
| Operations | Rate limiting | ✅ per-route rules by IP or user (8 quick requests got 5 × 429) | — | — | — |
| Operations | Request logs | ✅ every request logged to a separate SQLite file, searchable in the UI (66 so far) | ❌ | — | — |
| Operations | Data readable by other tools | ✅ the data is a plain SQLite file any SQLite tool can read (8 notes) | ❌ its own log and snapshot format; read it through sqweezdb (shell, console, bindings) | ✅ the most widely supported file format | ✅ SQLite opens the file Turso wrote |
| Platform | Languages | 📄 JS and Dart SDKs; any HTTP client | ✅ Node, Python, Go, C, Rust (E36) | 📄 nearly every language | ✅ Rust (tested); 📄 JS, Python, Go, Java |
| Platform | Browser (WebAssembly) | — | ❌ | 📄 official WASM build | 📄 WASM build |
| Platform | Inside a mobile app | — | ❌ | 📄 built into iOS and Android | 📄 mobile SDKs |
| Platform | Operating systems | 📄 Linux, macOS, Windows, FreeBSD | ✅ Linux and macOS (x64, arm64); ❌ Windows | 📄 all | 📄 Linux, macOS, Windows |
| Platform | One binary to run a server | ✅ | ✅ sqweezdb serve | ❌ | 📄 tursodb |

## SQL features

|  | Feature | sqweezdb | SQLite | Turso |
|---|---|---|---|---|
| Types | Text of any length, no declared maximum | ⚠️ only with a declared maximum, stored at full width | ✅ | ✅ |
| Types | Text longer than 64 KB | ❌ column s: TEXT value of 100000 bytes exceeds TEXT(255) | ✅ | ✅ |
| Types | Binary data (BLOB) | ❌ unsupported literal X'00ff10' | ✅ | ✅ |
| Types | Boolean type | ✅ | ✅ | ✅ |
| Types | Exact decimals (0.1 + 0.2 = 0.3) | ❌ unsupported type DECIMAL(10,2) | ⛔ returned 0 | ⛔ returned 0 |
| Types | A value of the wrong type is rejected | ✅ | ⚠️ only in STRICT tables | ⚠️ only in STRICT tables |
| Types | Generate a UUID | ✅ uuid() | ❌ no such function: uuid | ✅ gen_random_uuid() |
| Types | UUID column that rejects a malformed value | ✅ | ⛔ accepted | ⛔ accepted |
| Types | Current date and time | ✅ CURRENT_TIMESTAMP | ✅ CURRENT_TIMESTAMP | ✅ CURRENT_TIMESTAMP |
| Types | Date arithmetic | ✅ date(…, '+1 day') | ✅ date(…, '+1 day') | ✅ date(…, '+1 day') |
| Types | Extract a part of a date | ✅ strftime | ✅ strftime | ✅ strftime |
| Types | Timestamp column defaulting to now | ✅ CURRENT_TIMESTAMP | ✅ CURRENT_TIMESTAMP | ✅ CURRENT_TIMESTAMP |
| JSON | Read a field from JSON text | ✅ json_extract | ✅ json_extract | ✅ json_extract |
| JSON | Filter rows by a field inside JSON | ✅ json_extract | ✅ json_extract | ✅ json_extract |
| JSON | Aggregate rows into a JSON array | ❌ unsupported FROM (SELECT 1 AS x UNION ALL SELECT 2) | ✅ json_group_array | ✅ json_group_array |
| JSON | A JSON column rejects malformed JSON | ❌ unsupported type JSON | ⚠️ with CHECK (json_valid(…)) | ⚠️ with CHECK (json_valid(…)) |
| Schema | Automatic ids | ✅ AUTOINCREMENT | ✅ AUTOINCREMENT | ✅ AUTOINCREMENT |
| Schema | UNIQUE constraint | ✅ | ✅ | ✅ |
| Schema | NOT NULL with a DEFAULT | ✅ | ✅ | ✅ |
| Schema | CHECK constraint | ❌ unsupported: CHECK constraint on age is not implemented yet | ✅ | ✅ |
| Schema | Foreign keys enforced | ✅ | ⚠️ after PRAGMA foreign_keys = ON (off by default, per connection) | ⚠️ after PRAGMA foreign_keys = ON (off by default, per connection) |
| Schema | ON DELETE CASCADE | ✅ | ⚠️ after PRAGMA foreign_keys = ON | ⚠️ after PRAGMA foreign_keys = ON |
| Schema | Composite primary key | ❌ unsupported: a primary key on more than one column is not implemented yet | ✅ | ✅ |
| Schema | Text primary key | ✅ | ✅ | ✅ |
| Schema | Index on several columns | ❌ expected ( column ) | ✅ | ✅ |
| Schema | Index on a text column | ✅ | ✅ | ✅ |
| Schema | Expression or partial index | ✅ partial | ✅ expression | ✅ expression |
| Schema | Generated columns | ❌ unsupported: generated column b is not implemented yet | ✅ | ⚠️ experimental flag |
| Schema | Views | ❌ unsupported statement CREATE VIEW grown AS SELECT id FROM users WHERE age > 28 | ✅ | ✅ |
| Schema | Materialized views | ❌ unsupported statement CREATE MATERIALIZED VIEW by_grp AS SELECT grp, count(*) AS n FROM us… | ❌ near "MATERIALIZED": syntax error | ⚠️ experimental flag |
| Schema | Triggers | ❌ unsupported statement CREATE TRIGGER t_ins AFTER INSERT ON t BEGIN INSERT INTO audit (t_id… | ✅ | ✅ |
| Schema | ALTER TABLE … ADD COLUMN | ✅ | ✅ | ✅ |
| Schema | ALTER TABLE … DROP COLUMN | ✅ | ✅ | ✅ |
| Schema | ALTER TABLE … RENAME COLUMN | ✅ | ✅ | ✅ |
| Schema | ALTER TABLE … RENAME TO | ❌ unsupported ALTER TABLE operation RENAME TO people | ✅ | ✅ |
| Schema | Change a column's type | ✅ ALTER COLUMN … TYPE | ❌ near "TYPE": syntax error | ❌ near "TYPE": syntax error |
| Schema | Case-insensitive comparison | ✅ ILIKE | ✅ COLLATE NOCASE | ✅ COLLATE NOCASE |
| Schema | List tables from SQL | ❌ no such table sqlite_schema | ✅ sqlite_schema | ✅ sqlite_schema |
| Schema | Attach a second database file | ❌ unsupported statement ATTACH DATABASE 'data/nocow/e54/146/other.db' AS other | ✅ | ⚠️ experimental flag |
| Queries | LEFT JOIN | ✅ | ✅ | ✅ |
| Queries | Join three tables | ✅ | ✅ | ✅ |
| Queries | RIGHT and FULL OUTER joins | ❌ unsupported: FULL OUTER JOIN is not implemented yet | ✅ | ❌ Parse error: FULL OUTER JOIN requires an equality condition in the ON clause |
| Queries | IN (subquery) | ✅ | ✅ | ✅ |
| Queries | EXISTS (subquery) | ⚠️ correlated only | ✅ uncorrelated | ✅ uncorrelated |
| Queries | Subquery in FROM (derived table) | ❌ unsupported FROM (SELECT user_id FROM orders WHERE amount >= 10) t | ✅ | ✅ |
| Queries | Correlated subquery | ❌ unsupported: a correlated subquery inside an expression is not implemented yet | ✅ | ✅ |
| Queries | WITH (common table expressions) | ❌ unsupported: WITH is not implemented yet | ✅ | ✅ |
| Queries | Recursive WITH | ❌ unsupported: WITH is not implemented yet | ✅ | ✅ |
| Queries | Window functions | ❌ unsupported FROM (SELECT row_number() OVER (PARTITION BY grp ORDER BY age) AS r FROM users… | ✅ | ✅ |
| Queries | GROUP BY with HAVING | ⚠️ without a derived table | ✅ | ✅ |
| Queries | ORDER BY two columns | ✅ | ✅ | ✅ |
| Queries | LIMIT with OFFSET | ✅ | ✅ | ✅ |
| Queries | SELECT DISTINCT | ✅ | ✅ | ✅ |
| Queries | UNION and EXCEPT | ❌ unsupported FROM (SELECT id FROM users UNION SELECT user_id FROM orders EXCEPT SELECT 4) t | ✅ | ✅ |
| Queries | CASE expressions | ✅ | ✅ | ✅ |
| Queries | COUNT(DISTINCT …) | ✅ | ✅ | ✅ |
| Queries | Aggregates (avg) | ✅ | ✅ | ✅ |
| Queries | Arithmetic on aggregates | ✅ | ✅ | ✅ |
| Queries | upper() and lower() | ✅ | ✅ | ✅ |
| Queries | substr(), replace(), length() | ✅ | ✅ | ✅ |
| Queries | Concatenate strings | ✅ \|\| | ✅ \|\| | ✅ \|\| |
| Queries | Join strings across rows | ⚠️ group_concat, no derived table | ✅ group_concat | ✅ group_concat |
| Queries | Math functions | ✅ | ✅ | ✅ |
| Queries | COALESCE, NULLIF, CAST | ✅ | ✅ | ✅ |
| Queries | BETWEEN and IN lists | ✅ | ✅ | ✅ |
| Queries | Query plan (EXPLAIN) | ❌ unsupported statement EXPLAIN QUERY PLAN SELECT * FROM users WHERE id = 1 | ✅ EXPLAIN QUERY PLAN | ✅ EXPLAIN QUERY PLAN |
| Search | LIKE | ✅ | ✅ | ✅ |
| Search | Case-insensitive LIKE | ✅ ILIKE | ⚠️ LIKE ignores case (ASCII) | ⚠️ LIKE ignores case (ASCII) |
| Search | Regular expressions | ❌ unsupported: the expression name REGEXP '^[ab]' is not implemented yet | ❌ no such function: REGEXP | ✅ REGEXP |
| Search | Full-text search | ❌ unsupported statement CREATE VIRTUAL TABLE docs USING fts5 (body) | ✅ FTS5 | ⚠️ fts index (experimental flag) |
| Search | Full-text relevance ranking | ❌ unsupported statement CREATE VIRTUAL TABLE docs USING fts5 (body) | ✅ bm25 | ⚠️ fts_score (experimental flag) |
| Search | Vector similarity (nearest embedding) | ❌ unsupported expression vector32('[1,0,0]') | ❌ no such function: vector32 | ✅ vector32 + vector_distance_cos |
| Search | Vector index | ❌ expected ( column ) | ❌ near "USING": syntax error | ⚠️ toy_vector_sparse_ivf, sparse vectors only (experimental flag) |
| Writes | UPSERT (ON CONFLICT DO UPDATE) | ✅ | ✅ | ✅ |
| Writes | Insert, ignoring duplicates | ✅ ON CONFLICT DO NOTHING | ✅ ON CONFLICT DO NOTHING | ✅ ON CONFLICT DO NOTHING |
| Writes | INSERT … RETURNING | ✅ | ✅ | ✅ |
| Writes | UPDATE … RETURNING | ✅ | ✅ | ✅ |
| Writes | INSERT … SELECT | ✅ | ✅ | ✅ |
| Writes | CREATE TABLE … AS SELECT | ❌ unsupported: CREATE TABLE with OR REPLACE, TEMPORARY, AS SELECT, LIKE, CLONE, INHERITS or … | ✅ | ✅ |
| Writes | UPDATE with a subquery | ✅ | ✅ | ✅ |
| Writes | UPDATE … FROM another table | ❌ unsupported: UPDATE … FROM another table is not implemented yet | ✅ | ✅ |
| Writes | DELETE with a subquery | ✅ | ✅ | ✅ |
| Transactions | BEGIN, COMMIT, ROLLBACK | ✅ | ✅ | ✅ |
| Transactions | Savepoints | ❌ unsupported statement SAVEPOINT s | ✅ | ✅ |
| Transactions | A transaction sees its own writes | ❌ unsupported: reading users after writing it in the same transaction is not implemented yet… | ✅ | ✅ |
| Transactions | Concurrent writers syntax (BEGIN CONCURRENT) | ❌ unsupported statement PRAGMA journal_mode = 'experimental_mvcc' | ❌ near "CONCURRENT": syntax error | ⚠️ MVCC journal mode |
| Operations | Copy a live database (VACUUM INTO) | ❌ sql parser error: Expected: end of statement, found: 'data/nocow/e54/316/copy.db' at Line:… | ✅ | ✅ |
| Operations | Change capture readable from SQL | ❌ unsupported statement PRAGMA capture_data_changes_conn('full') | ❌ no such table: turso_cdc | ✅ PRAGMA capture_data_changes_conn |
