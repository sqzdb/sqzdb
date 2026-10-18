# Changelog

## 0.4.1 — 2026-10-17

**Upgrade from 0.4.0 if you use sign-in** (see Fixed).

### Fixed
- **Sign-in attempts sent at the same moment were not limited.** The failure count was checked before
  the password hash and raised after it, so many guesses at once all got through before the slowdown
  began. Each attempt now counts as it starts.
- **A session handle kept the identity it had when it was made.** A handle from `db.session(token)`
  that an application kept open, and subscriptions and live queries made through it, went on acting as
  the user after a sign-out, a password change or the user's deletion, and with an old role or old
  attributes. Such a handle now checks its token again after any sign-in change. It fails with `AUTH`
  once the token no longer holds, and its subscriptions are dropped.
- A session whose `use_token` failed was left acting as the application, without restrictions, if the
  error was ignored. It now has no rights.
- A table whose name contains `:` can't be marked `ENABLE AUTH` (the name would make password records
  ambiguous).

## 0.4.0 — 2026-10-17

### Added
- **Sign-in.** `ALTER TABLE users ENABLE AUTH (ROLE FROM role)` marks a table you define as the one users
  sign in to; its `UNIQUE` text column is the login. `db.auth('users').signUp(fields, password)` and
  `signIn(login, password)` return a session token, and `db.session(token)` acts as that user: their
  role, and their row's columns as `SESSION` attributes for row policies. Also `signOut`,
  `setPassword` and `signOutEverywhere`, in Node, Python (`db.auth("users").sign_in`,
  `session.use_token`), Go (`db.Auth("users").SignIn`, `Session.UseToken`) and C. Passwords are hashed
  with Argon2id into a system table no SQL can read, and only a SHA-256 of each token is stored. Repeated
  failures for one login slow down. Sessions last `auth.sessionTtl` (30 days), and passwords need
  `auth.passwordMin` characters (8).
- The `AUTH` error code.

### Changed
- Table names starting with `_auth_` are reserved for the engine.

## 0.3.2 — 2026-10-17

**Upgrade if you use roles and row policies.** A role could read rows through a write that its grants
and policies hide from it (see Fixed).

### Fixed
- **A role could read rows it has no right to read through a write.** `UPDATE … RETURNING` returned
  rows to a role without `SELECT` on the table, or outside its `SELECT` policies, and the row count of an
  `UPDATE`, `DELETE` or upsert with a condition on other columns told it whether rows with given values
  exist (0.3.1 for `UPDATE`, 0.3.0 for `ON CONFLICT … DO UPDATE`, earlier versions for `DELETE`). A
  write that reads the rows it changes now needs `SELECT` as well and reaches only the rows the role's
  `SELECT` policies show, as in PostgreSQL. A write by primary key with values from the statement still
  needs only `UPDATE` or `DELETE`.

## 0.3.1 — 2026-10-17

**Upgrade from 0.3.0:** any role allowed to run a `SELECT` could crash a 0.3.0 server by exhausting its
memory with one expression (see Fixed).

### Added
- **`UPDATE` by any condition**, with `RETURNING`. An `UPDATE` that changes several rows changes all of
  them or none, and a row is changed only if it still matches when it is written.

### Changed
- `UPDATE` returns how many rows it changed as a `changes` row, like `DELETE`; it returned no rows. In
  Node, `run().changes` is that count. `UPDATE … WHERE <primary key> = ?` still fails with `NOT_FOUND`
  for a missing row, and the message names the table and the key.

### Fixed
- **An expression could build a value big enough to exhaust the server's memory**, for example
  `repeat(repeat('x', 1000000), 1000000)` or `replace()` with a long replacement, so any role allowed to
  run a `SELECT` could crash a 0.3.0 server. A value an expression builds is now at most 1 MB, and a
  `group_concat` result at most 16 MB; anything longer fails with `TYPE`.
- The `demos/agents` server, which has no sign-in, accepted writes from any web page open in the same
  browser. It now refuses writes from other origins and, while it listens on loopback, requests for
  another host name (DNS rebinding).

## 0.3.0 — 2026-10-17

**Upgrade if you delete rows inside transactions.** Versions 0.1.0 and 0.2.0 replayed a transaction's
deletes from a table with an `INT` key against the wrong rows after a restart (see Fixed). This version
replays those logs correctly; a snapshot written after a wrong replay keeps the wrong rows.

### Added
- **Everyday SQL.** `LEFT JOIN`; `OR`, `NOT`, `LIKE` and `ILIKE` in `WHERE`; `DISTINCT`; `GROUP BY` several
  columns or expressions; `HAVING`; `ORDER BY` several columns; `OFFSET`; `COUNT(DISTINCT …)`,
  `group_concat` and `string_agg`; arithmetic, `CASE`, `CAST`, JSON `->` and `->>`, and about 50 functions
  for text, numbers, time and JSON; `SELECT` without `FROM`; `INSERT … SELECT`; upserts (`ON CONFLICT …
  DO NOTHING | DO UPDATE`, `INSERT OR IGNORE | REPLACE`, `REPLACE INTO`); `UPDATE … SET col = expression`;
  `DELETE` by any condition. 148 queries and statements return the same rows as SQLite on the same data
  (`src/bin/e55_sql_diff.rs`). Where SQLite returns NULL or guesses, these return an error: a division by
  zero, an integer overflow, a value of the wrong type.
- **Text primary keys**: `id TEXT PRIMARY KEY` (or `VARCHAR(n)`, `BYTES(n)`), with foreign keys, joins,
  cascades, transactions, the change feed and live queries. A key of up to 15 bytes is kept exactly; a
  longer one by 120 bits of its SHA-256.
- **Indexes on text and bytes columns**, and joins and `IN` on text columns.
- **`log.syncDelay`**: with `durable: false`, hold the background fsync up to this long so one fsync covers
  more writes. Off by default. For hosts with thousands of small databases on one disk, where 1 s gave
  two to three times the write throughput across 10,000 databases. Anything that waits for durability
  still syncs at once. In Go: `Options.Log.SyncDelay`.
- **Two demos with benchmarks**: `demos/boards` (a multi-tenant board app) and `demos/agents` (a database
  per AI agent), each with a load tool that runs the same workload against PocketBase.
- `CREATE TABLE IF NOT EXISTS` leaves an existing table alone.
- `PRIMARY KEY (col)` and `UNIQUE (col)` declared at the end of `CREATE TABLE`.

### Changed
- **SQL that isn't implemented is refused instead of ignored.** These used to run and return a wrong
  answer without an error, and now fail with `SYNTAX` ("unsupported: … is not implemented yet"): window
  functions, `FILTER`, `WITH`, `LIMIT offset, count`, `NULLS FIRST/LAST`, `FOR UPDATE`, `CHECK`
  constraints, generated columns, a second `UNIQUE` column, text or binary columns wider than 65,535
  bytes, `COLLATE`, `UPDATE … RETURNING`, `UPDATE … FROM`, `DELETE … LIMIT` (which deleted every
  matching row), `DELETE … RETURNING`, and `CREATE TEMPORARY TABLE`. (`HAVING`, `DISTINCT`,
  `COUNT(DISTINCT …)`, `OFFSET`, `ORDER BY` a second column and the upserts, which were ignored too,
  now work.)
- A join between columns that hold different kinds of values (`INT` with `TEXT`, or any `DOUBLE` or
  `BOOL` column) is refused. `SUM` and `AVG` over text, bytes, UUID or timestamp columns are refused;
  they returned 0.
- A column named `true`, `false` or `null` must be quoted (`"true"`), as in PostgreSQL, because
  `SELECT true` reads the value.
- A value of the wrong type for an operator or function, a division by zero and an integer overflow
  fail with `TYPE`. `UPDATE` by anything other than the primary key fails with `SYNTAX` (it was `ERROR`).
- Inside a transaction, a read of a table the transaction has written, other than a lookup by primary key,
  fails with `TRANSACTION`. It used to return rows without the transaction's own writes, and a `DELETE`
  by any other condition skipped rows the transaction had inserted.

### Fixed
- **After a restart, a transaction's deletes from a table with an `INT` key were applied to the wrong
  rows.** Each was logged as a 16-byte key and read back as part of a row, so replaying the log removed a
  different row, or none, and kept the deleted one. Delete records now carry 8 bytes, and logs written by
  0.1.0 and 0.2.0 replay correctly. A snapshot written after such a replay already holds the wrong rows;
  restarting with this version can't repair it.
- `MIN` and `MAX` over a text, `UUID` or `BOOL` column returned 0. They compare the values now.
- `MIN` and `MAX` of integers beyond 2^53 were rounded (they went through a double), and `SUM` of
  integers wrapped around on overflow; `SUM` now fails instead. `SUM` over a `BOOL` column returned 0; it
  counts the true values.
- In one transaction, deleting a row (or changing its `UNIQUE` value) and giving that value to another
  row failed with `DUPLICATE`, and so did swapping two rows' values.
- With `log.threadsIdleAfter` set, a write that woke the idle log threads, followed at once by a close,
  could be acknowledged and never written. Closing now waits for those threads.
- Closing a database opened with a snapshot policy (the default) waited up to 200 ms.
- With `log.threadsIdleAfter` set, every restart of the log threads began a new log file, so a database
  written now and then collected one small file per write until its next snapshot.

## 0.2.0 — 2026-10-17

### Added
- **UUID primary keys.** `id UUID PRIMARY KEY DEFAULT uuid()`, with foreign keys, joins, indexes, the change feed
  and live queries on UUID columns. `lastInsertId` is the UUID text for such tables.
- **Automatic ids and generated values.** `SERIAL`, `AUTOINCREMENT` and `GENERATED AS IDENTITY` hand out ids
  that are never reused; `DEFAULT uuid()`, `gen_random_uuid()` and `now()`; `INSERT … RETURNING`;
  `INSERT` with several rows, all or none.
- **Identities supplied by the application** for row-level security: `db.as({ role, ...attributes })` in Node,
  `session.assume(...)` in Python, `Session.Assume(...)` in Go, `sqweezdb_assume` in C. Nothing about the user
  is stored in the database.
- **Database directories are marked** with `sqweezdb.meta`; opening a file or a foreign directory is refused
  with the error code `PATH`. Directories made by 0.1.0 are adopted.
- **A redesigned web console**: a graphite theme, a sign-in screen, SQL highlighting and line numbers,
  query history, typed result columns with click-to-copy cells, live results that highlight changed rows,
  a readable change feed, a table designer, and an Access tab.
- **Backup health** in the console: whether uploads work, how far the bucket is behind, the last error,
  and a connection test; when backup is off, a generator for the settings file and the restart command.
- **The MIT license.**

### Fixed
- The backup uploader stopped for good on the first failed upload, without telling anyone. It now records
  the error, retries with backoff and catches up when the bucket answers.
- At start, an unreachable bucket was read as an empty one. The uploader now retries until it can read it.
- A malformed backup `endpoint` crashed the S3 client; it is now refused when the database opens.
- Durable commits with many concurrent writers were about a third as fast as they should be: 256 writers
  now make 130,000 to 165,000 durable commits per second on the benchmark machine, up from about 65,000.
- `GROUP BY` and `ORDER BY` on text, boolean and UUID columns returned wrong groups and unsorted rows.
- Correlated subqueries on UUID columns returned one value for every parent row; other non-integer
  correlations are refused instead of answered wrongly.
- A failing `ALTER TABLE` reported success; it now returns the error and changes nothing.
- The change feed could end a poll early during an `ALTER`; a live subscription could miss changes
  committed while it started; a failed `CREATE TABLE` could leave a half-registered table.
- A short `VALUES` row now names the columns and shows the corrected statement.

## 0.1.0 — 2026-10-16

First release: the embedded engine with concurrent writers, strict types, row policies, live queries,
online schema changes, foreign keys, S3 backup with compression and encryption, followers, the `sqweezdb`
command with its web console, and bindings for Node, Python, Go and C.
