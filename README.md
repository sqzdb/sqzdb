<div align="center">

# sqzdb

**An embedded SQL database for applications that outgrow SQLite.**<br>
Concurrent writers, strict types, row-level security, live queries and continuous backup,<br>
in a library inside your process, or as the whole backend of a web or mobile app.

[sqzdb.dev](https://sqzdb.dev)

[![CI](https://github.com/sqzdb/sqzdb/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/sqzdb/sqzdb/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/sqzdb/sqzdb?sort=semver)](https://github.com/sqzdb/sqzdb/releases/latest)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange?logo=rust)](#building-from-source)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS-blue)](#installation)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Status: experimental](https://img.shields.io/badge/status-experimental-yellow)](#project-status)

[Features](#features) · [Performance](#performance) · [Installation](#installation) · [Quick start](#quick-start) · [Guides](#guides) · [Configuration](#configuration) · [SQL](#sql-reference) · [Building](#building-from-source)

</div>

---

sqzdb keeps SQLite's deployment model: no server to run, one directory per database, opened by the
library in your process. It is written in Rust and adds what SQLite leaves to the application: many
writers at once, enforced column types, access control inside the engine, subscriptions to changes,
schema changes without downtime, and backup to any S3-compatible bucket.

It can also be the whole backend of a browser or mobile app. Users sign in and send SQL straight from
the client, the row policies decide what each one sees and changes, any query can be live, and HTTPS
with certificates from Let's Encrypt is built in. See [the app API](#the-app-api-sql-from-the-browser).

> [!WARNING]
> **Project status: experimental.** Every feature below exists and is covered by tests and benchmarks,
> but the file format is not frozen, the APIs may change between releases, and the SQL dialect is
> deliberately narrow. Do not use it for data you cannot afford to lose yet.

## Features

| Capability | What you get |
|---|---|
| **Concurrent writers** | Commits share one append-only log with group commit, so concurrent writers share each fsync: 256 writers make 130,000 to 165,000 durable commits per second, where SQLite stays near 2,300. Transactions conflict per row, not per database. |
| **Lock-free reads** | Readers never take a lock. A point read costs about 0.4 µs in-process, and 8 threads make 17.5 million point reads per second. |
| **Strict types** | `INT`, `DOUBLE`, `BOOL`, `TEXT` and `BYTES` of any length (up to 16 MB) or `TEXT(n)`, `TIMESTAMP`, `UUID`, `FILE`, `VECTOR(n)`. A value of the wrong type is rejected, never stored. |
| **Keys and ids** | Automatic integer ids that are never reused, UUID primary keys (time-ordered v7 or random v4), text primary keys, `DEFAULT now()`, and `INSERT … RETURNING`. |
| **Row-level security** | Roles, grants and row policies enforced on every query, write and subscription. Your app passes who is asking on each request. |
| **Sign-in** | Email and password, Google, GitHub or any OpenID Connect provider, for a users table you define, with sessions. A signed-in user's row becomes the identity the row policies read. |
| **SQL from the browser** | Browsers and mobile apps sign in and send SQL straight to the database, with no server code of their own: each statement runs as the signed-in user under the row policies, and any query can be live over one WebSocket. HTTPS is built in, with certificates from Let's Encrypt renewed automatically. A connected user costs the server about 20 KB. |
| **Agents over MCP** | Claude, ChatGPT, Claude Code and other MCP clients connect to `/mcp`, sign their user in on the database's own OAuth page, and query and change data as that user, under the same grants and row policies. |
| **Functions** | Your app's rules as TypeScript or JavaScript that runs inside the database, one transaction per call, as the caller. Each is an API endpoint and an MCP tool. Deploy a folder: on a server, a change to it deploys itself. |
| **In front of your app** | Point sqzdb at a Next.js (or any) server and it serves the site: HTTPS and HTTP/2 to browsers, a streaming, pooled proxy to the app, sign-in pages with the session in a cookie, and middleware and routes in TypeScript that guard pages and answer webhooks, with the database at hand. |
| **Files as a column** | A `FILE` column holds an uploaded file. A browser uploads it with the row, and whoever may read the row gets a signed link that an `<img>` can load, with caching and byte ranges. Files no row refers to are cleaned up. |
| **Vectors and search by meaning** | A `VECTOR(n)` column, searched with `cosine_distance` under the same policies as everything else. A column can be the embedding of other columns, filled in the background by OpenAI, Ollama or any OpenAI-compatible model, and `embed(?)` embeds the search text. |
| **Live queries** | Subscribe to the changes a query would see, or watch a query and receive its new result whenever it changes. |
| **Online schema changes** | `ALTER TABLE` adds, drops, renames or retypes a column while reads and writes continue. |
| **Foreign keys** | Always enforced, with `RESTRICT`, `CASCADE` and `SET NULL`. |
| **Backup and replication** | Continuous backup to S3-compatible storage, compressed and encrypted; point-in-time restore; read-only followers. |
| **Fast restart** | The snapshot is the table image and is memory-mapped, not loaded. After a snapshot, a million-row table reopens in under a millisecond; each secondary index adds about 30 ms per million rows. |
| **Tooling** | A `sqzdb` command with a server, a SQL shell and a web console, plus bindings for Node, Python, Go, C and Rust. |

## Performance

The same statements and the same data on each engine, 1 million rows, each engine in its own process:
SQLite 3.53 (the system library, WAL mode), Turso 0.8.3 (its MVCC mode with `BEGIN CONCURRENT`) and
sqzdb. All three returned identical results, to the cent and to the row.

| Workload | SQLite | Turso | sqzdb |
|---|---:|---:|---:|
| Durable commits per second, 1 writer | 2,197–2,220 | 2,288–2,362 | 2,287–2,351 |
| Durable commits per second, 64 writers | 2,264–2,306 | 53,017–59,845 | 50,823–55,315 |
| Durable commits per second, 256 writers | 2,285–2,326 | 106,866–118,324 | **131,874–165,783** |
| Transactions per second, 12 threads (2 reads + 2 updates each) | 1,532 | 4,985 | **880,868** |
| Bulk load, 1,000-row transactions | 1.09 µs/row | 10.28 µs/row | **0.88 µs/row** |
| Single-row insert, CPU cost | 9.33 µs | 20.16 µs | **1.03 µs** |
| Point read by primary key | 1.11 µs | 2.33 µs | **0.39 µs** |
| Lookup by a unique column | 1.94 µs | 4.56 µs | **0.44 µs** |
| Point reads per second, 8 threads | 5.0M | 1.4M | **17.5M** |
| Filtered count over 1M rows | 26.9 ms | 138.6 ms | **4.3 ms** |
| `GROUP BY` over 1M rows, 20 groups | 132 ms | 287 ms | **6.0 ms** |
| Reopen and first read | **0.19 ms** | 1.30 ms | 0.29 ms |
| Resident memory at the end | **17 MB** | 121 MB | 250 MB |

The durable rows insert single rows into a fresh table and wait for an fsync on every engine, so one
writer is bound by the disk on all three; their ranges come from two runs with the engines in opposite
orders. The transaction row does not wait
for the disk. sqzdb keeps tables in memory, so it uses the most memory
after a large load; after a restart that maps the snapshot, it owns about 2 MB and the operating
system's page cache holds the rest.

Compared with the tools usually paired with SQLite:

| Workload | SQLite with its usual tool | sqzdb |
|---|---:|---:|
| Node: point read returned as an object | 1.38 µs (better-sqlite3) | **0.98 µs** |
| Node: 1,000 rows returned as objects | 111 µs (better-sqlite3) | **66 µs** |
| Node: autocommit insert | 8.7 µs (better-sqlite3) | **1.07 µs** |
| 1M rows in a backup bucket | 43 MB (Litestream) | **6 MB** |
| Insert then delete 3M rows, one at a time | 614 s | **4.1 s** |

As the backend of a browser app, against PocketBase 0.40.5 running the same notes app with the same
rules ([`demos/notes`](demos/notes); PocketBase's range is with and without its request log):

| Workload | PocketBase | sqzdb |
|---|---:|---:|
| Notes created per second, 32 users writing at once | 4,972–5,761 | **47,548** |
| Read one note over HTTP, p50 | 0.105–0.112 ms | **0.026 ms** |
| A note with a 100 KB picture created, p50 | 0.602–0.617 ms | **0.180 ms** |
| Download that picture, p50 | 0.177–0.182 ms | **0.074 ms** |
| A write on one device seen on another, p50 | 0.67–0.70 ms | **0.27 ms** |
| Server memory with 1,000 devices connected | 160–247 MB | **48 MB** |
| Writes per second while they are connected | 205–211 | **22,431** |

Where the others are ahead or even: Turso matches sqzdb on durable commits up to about 64 writers;
SQLite reopens slightly faster, uses far less memory after a load, bulk-loads faster one row
per call through a language binding, and finishes `ALTER TABLE` changes that only touch metadata
instantly, where sqzdb copies the table in the background.

Measured on one machine, an AMD Ryzen 5 9600X with NVMe storage and btrfs; the numbers describe that
machine, not yours. Every benchmark is a program in [`src/bin/`](src/bin/) that you can run, and its
raw output is in [`results/`](results/).

## Installation

### Command-line tool

Prebuilt for Linux and macOS on x86_64 and arm64:

```sh
curl -fsSL https://raw.githubusercontent.com/sqzdb/sqzdb/main/install.sh | sh
```

The installer verifies the download against the release's `SHA256SUMS` and installs to `~/.local/bin`,
or `/usr/local/bin` when run as root. On Linux it uses the glibc build, which needs glibc 2.17 or newer,
and switches to the static musl build on Alpine.

| Variable | Effect |
|---|---|
| `SQZDB_VERSION=v0.11.0` | Install a specific release instead of the latest. |
| `SQZDB_INSTALL_DIR=/opt/bin` | Install somewhere else. |
| `SQZDB_LIBC=musl` | Force the static musl build on Linux. |

To remove it, run `sh install.sh --uninstall`. From a checkout, `make install` and `make uninstall`
do the same with a local build.

### Libraries

The Node package is on npm, with prebuilt engines for Linux (x64 and arm64, glibc and musl) and
macOS (x64 and arm64):

```sh
npm install sqzdb
```

The other bindings are not published to PyPI or crates.io yet. Build them from source, as described in
[Building from source](#building-from-source).

| Language | Binding | Location |
|---|---|---|
| Node.js 20+ | Native addon (N-API), synchronous calls with promises where work waits | `npm install sqzdb` (`bindings/node`) |
| Python 3.11+ | Extension module (PyO3), releases the GIL while the engine works | `bindings/python` |
| Go 1.24+ | cgo package over the C ABI | `bindings/go/sqzdb` |
| C | Shared library `libsqzdb.so` | `src/capi.rs` |
| Rust | The `sqzdb` crate | `src/` |

## Quick start

### Node.js

```js
import { open } from 'sqzdb'

const db = open('./data/shop')   // creates the database, or reopens it

db.exec(`CREATE TABLE orders (
  id         SERIAL PRIMARY KEY,
  public_id  UUID UNIQUE DEFAULT uuid(),
  user_id    INT NOT NULL,
  amount     DOUBLE,
  placed_at  TIMESTAMP DEFAULT now()
)`)

const r = db.run('INSERT INTO orders (user_id, amount) VALUES (?, ?)', [42, 9.5])
r.lastInsertId       // 1
await r.durable      // optional: resolves once the write is on disk

db.get('INSERT INTO orders (user_id, amount) VALUES (?, ?) RETURNING id, public_id', [42, 12])
// { id: 2, public_id: '01a145c7-a2bb-7001-862a-a205073c0824' }

db.get('SELECT * FROM orders WHERE id = ?', [1])
// { id: 1, public_id: '01a145c7-…', user_id: 42, amount: 9.5, placed_at: 2026-10-15T19:30:00.000Z }

// transactions retry automatically on write conflicts
const place = db.transaction((tx, userId, amount) =>
  tx.run('INSERT INTO orders (user_id, amount) VALUES (?, ?)', [userId, amount]).lastInsertId)
place(42, 12)

// a query result that updates itself
db.watch('SELECT user_id, sum(amount) AS total FROM orders GROUP BY user_id', [],
  (rows) => render(rows))
```

Calls are synchronous, like better-sqlite3 and `node:sqlite`, because a read answers in about a
microsecond. Promises appear only where something waits: `run().durable`, subscriptions, and
`stmt.allAsync()` for long scans. Rows are plain objects. `INT` becomes a number, or a `BigInt` beyond
2^53; `BYTES` becomes a `Buffer` and `TIMESTAMP` a `Date`. The full API is typed in
[`bindings/node/index.d.ts`](bindings/node/index.d.ts).

<details>
<summary><b>Python</b></summary>

```python
import sqzdb

db = sqzdb.Database("./data/shop")                 # Database(path, durable=False, **options)
s = db.session()
s.exec("CREATE TABLE t (id INTEGER PRIMARY KEY, name VARCHAR(32), at TIMESTAMP)")
ins = db.prepare("INSERT INTO t VALUES (?, ?, ?)")
s.execute(ins, (1, "alice", 1_700_000_000_000_000))   # TIMESTAMP as microseconds since the epoch
s.exec("SELECT * FROM t WHERE id = ?", (1,))          # [(1, 'alice', 1700000000000000)]

sub = db.session().subscribe("SELECT * FROM t WHERE id > ?", (0,))
ev = sub.next(1000)                                   # [op, table, key, columns...] or None on timeout
```

The interpreter lock is released while the engine works and while a subscription waits, so a consumer
thread can block on `next()` without stalling the rest of the program.

</details>

<details>
<summary><b>Go</b></summary>

```go
import "github.com/sqzdb/sqzdb/bindings/go/sqzdb"

db, err := sqzdb.Open("./data/shop", false)
s := db.Session()
s.ExecText("CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INT, amount DOUBLE)")
ins, _ := db.Prepare("INSERT INTO orders VALUES (?, ?, ?)")
s.Exec(ins, int64(1), int64(42), 9.5)
rows, _ := s.ExecText("SELECT * FROM orders WHERE user_id = ?", int64(42))   // [][]any

sub, _ := s.Subscribe("SELECT * FROM orders WHERE user_id = ?", int64(42))
ev, _ := sub.Next(200)   // []any{op, table, key, columns...}, or nil on timeout
```

[`bindings/go/sse/main.go`](bindings/go/sse/main.go) is a complete example: a Go server that embeds
the database and streams a filtered subscription to browsers as Server-Sent Events.

</details>

<details>
<summary><b>Rust</b></summary>

```rust
use sqzdb::config::Config;
use sqzdb::sql::{Session, Sql};
use sqzdb::table::Value;

let sql = Sql::open_with(std::path::Path::new("./data/shop"), Config::default())?;
let mut s = Session::default();
sql.exec_s(&mut s, "CREATE TABLE t (id INTEGER PRIMARY KEY, name VARCHAR(32))", &[])?;
let ins = sql.prepare("INSERT INTO t VALUES (?, ?)")?;
sql.execute_s(&mut s, &ins, &[Value::Int(1), Value::Text("alice".into())])?;
let rows = sql.exec_s(&mut s, "SELECT * FROM t WHERE id = ?", &[Value::Int(1)])?;
```

Other processes reach the owning process through `sqzdb::net::Client`, over a Unix socket, a
shared-memory ring or TCP. `sqzdb::tenants::TenantHost` runs thousands of databases in one process,
at about 90 µs to create one and about 100 KB each; it is Rust-only for now.

</details>

<details>
<summary><b>C</b></summary>

`libsqzdb.so` exports a small C ABI: `sqzdb_open_with`, `sqzdb_prepare`, `sqzdb_exec`,
`sqzdb_rows_all`, `sqzdb_subscribe`, `sqzdb_assume` and more. The declarations live in the
cgo preamble of [`bindings/go/sqzdb/sqzdb.go`](bindings/go/sqzdb/sqzdb.go), which also
serves as the reference for using them.

</details>

## Guides

### Databases are directories

A database is a directory, and its name is the database's name. `open('./data/orders')` and
`open('./data/users')` are two databases side by side. Copy, move, back up or delete the directory as
a whole.

```
data/orders/
  sqzdb.meta   marks the directory as a database and records its format version
  snap            the table image, memory-mapped at startup
  log.000…        the change log, in segments; old segments are removed after a snapshot
  .lock           held while the database is open
```

Opening a path follows four rules, checked before anything is written:

- A directory with `sqzdb.meta` opens, unless it was written by a newer, incompatible format.
- A missing or empty directory becomes a new database, unless `create: false` is set. Hidden files and
  `.toml` files don't count, so a configuration file can live there.
- A directory with database files but no marker, as written by 0.1.0, is adopted and gets a marker.
- Anything else is refused with the error code `PATH`, such as a regular file or a non-empty directory
  that isn't a database.

One process owns a database at a time. A second process, or a second handle in the same process, is
refused instead of corrupting the log. Other processes connect to the owner; see
[Configuration](#configuration) for `listen`.

### Primary keys: INT, UUID or text

```sql
CREATE TABLE accounts (id UUID PRIMARY KEY DEFAULT uuid(), name VARCHAR(64));
CREATE TABLE orders   (id UUID PRIMARY KEY DEFAULT uuid(),
                       account_id UUID NOT NULL REFERENCES accounts(id), amount DOUBLE);

INSERT INTO accounts (name) VALUES ('alice') RETURNING id;   -- '01a145fe-2334-7000-884d-285c8eaa5c58'
```

An integer key can be automatic with `SERIAL`, `AUTOINCREMENT` or `GENERATED AS IDENTITY`. Ids are never
reused, even after the highest row is deleted and the database restarts. A UUID key is read and written
as text, and `lastInsertId` returns that text. `uuid()` makes version 7 UUIDs, which can't be guessed and
sort by creation time; they do reveal when a row was created. `gen_random_uuid()` makes version 4 UUIDs,
which reveal nothing.

Without a column list, `INSERT` needs a value for every column; write `DEFAULT` for a generated one.
With a column list, the columns left out take their defaults.

A text key (`TEXT`, `VARCHAR(n)` or `BYTES(n)` as the primary key) fits ids that already exist
elsewhere: slugs, codes, ids from another system. It compares exactly, so case and trailing spaces
count. A key of up to 15 bytes is kept as it is; a longer one is keyed by 120 bits of its SHA-256, so
two keys could only be confused through a SHA-256 collision. The application supplies text keys; there
is no automatic one. A range over a text key (`id >= 'm'`) runs as a filter.

Wider keys cost more per operation. With 1 million rows per table:

| Operation | `INT` key | `UUID` key | Text, 15 bytes | Text, 27 bytes |
|---|---|---|---|---|
| Insert | 0.39 µs | 0.58 µs | 0.66 µs | 0.73 µs |
| Insert with a foreign key check | 0.63 µs | 1.01 µs | 1.32 µs | 1.46 µs |
| Point read by key | 0.25 µs | 0.44 µs | 0.43 µs | 0.42 µs |
| Join one row by key | 0.90 µs | 1.09 µs | 1.11 µs | 1.11 µs |
| Join all 1M orders to their users | 16 ms | 62 ms | 109 ms | 182 ms |
| Delete by key | 0.50 µs | 0.71 µs | 1.11 µs | 1.23 µs |
| Restart from snapshot | 75 ms | 66 ms | 83 ms | 119 ms |

Use `INT` when ids stay inside your system and speed matters most. Use `UUID` when ids are shown to
users, appear in URLs, or are created by clients. Use text when the ids come from outside. Either way,
an access check protects a row; an id that is hard to guess does not.

### Transactions and durability

`BEGIN`, `COMMIT` and `ROLLBACK` use optimistic concurrency: transactions run without locks, and a
commit that conflicts with a concurrent one fails with `CONFLICT`. `db.transaction(fn)` in Node retries
those automatically. Reads inside an open transaction see committed data plus the transaction's own
writes: a query on one table (by key, index, range or scan, `count(*)` included) and the rows an `UPDATE`
or `DELETE` picks. A join, a subquery or `INSERT … SELECT` over a table the transaction has written still
reads committed data only, so it fails with `TRANSACTION` instead of returning rows without those writes.
Every read is checked again at `COMMIT`. A row read by its key must be unchanged. A table read any other way
(a scan, an index, a range, a `UNIQUE` value) must have had no other write become visible since, nor have
one on its way. This check is per table, so it's coarse: a transaction that counts a table's rows conflicts
with any concurrent write to that table, and retrying gives it the new count.

| `durable` | A commit returns when | A crash can lose |
|---|---|---|
| `false` (default) | it is visible to readers; the fsync follows within about half a millisecond | the last few hundred microseconds of acknowledged writes |
| `true` | it is fsynced; concurrent writers share one fsync | nothing acknowledged |
| `'cloud'` | its log record is in the backup bucket | nothing acknowledged |

With `durable: false`, Node's `run().durable` promise resolves at the moment a specific write is on disk. With
`log.syncDelay` set, the background fsync may wait up to that long (see [configuration](#configuration)); a commit or
`durable` promise that waits for the disk still gets its sync right away.

### Vectors and search by meaning

A `VECTOR(n)` column holds n numbers. Queries compare vectors with `cosine_distance`, `l2_distance` and
`inner_product`, so the nearest rows are an `ORDER BY` with a `LIMIT`, under the same row policies as any query.

```sql
CREATE TABLE notes (id SERIAL PRIMARY KEY, owner INT, title TEXT, body TEXT,
                    embedding VECTOR(768) GENERATED ALWAYS AS (embed(title || ' ' || body)) STORED);

SELECT id, title, cosine_distance(embedding, embed(?)) AS d
FROM notes WHERE embedding IS NOT NULL ORDER BY d LIMIT 10;     -- ? is the search text
```

```toml
[embed]                           # any OpenAI-compatible embeddings endpoint
url   = "http://localhost:11434/v1"
model = "nomic-embed-text"        # Ollama on this machine: 768 numbers
# url = "https://api.openai.com/v1"; model = "text-embedding-3-small"; apiKey = "${OPENAI_API_KEY}"   (1536)
```

- **Embedding on write.** A column `GENERATED ALWAYS AS (embed(<text expression>)) STORED` is the embedding
  of that text. A write leaves it `NULL`, and an `UPDATE` that changes the text sets it back to `NULL`. A
  background thread embeds those rows in batches and writes each vector only if the row still has the
  text it embedded; live queries see it arrive (about 2 ms after the write, plus the model's time). No
  statement writes that column. Rows written while the database was closed are embedded when it opens.
- **Search text.** `embed(?)` in a query becomes the embedding of the parameter when the statement runs,
  and is cached, so a live search re-run costs no request. With `[embed]` set, the app API runs statements
  on its blocking pool, since any of them may wait for the endpoint. Until a row is embedded its distance is `NULL`,
  which sorts first: search with `WHERE embedding IS NOT NULL`.
- **Values.** A vector is written as a JSON array of numbers (a client's array parameter is one) and
  comes back as an array through the app API, as raw little-endian floats through the libraries.
- **Cost.** The search is exact: it computes the distance for every row the query sees. The nearest 10 of
  10,000 vectors of 384 numbers take 3.3 ms through the app API, of 100,000 take 34 ms (E62).
- **Errors to fix.** A model whose vectors aren't the column's size is reported (set `embed.dimensions`
  for models that can shorten theirs, or change the column). A text the endpoint refuses is skipped for
  10 minutes; an endpoint that is down is tried again after 5 seconds, then less often.
- **Not built yet:** an approximate index (HNSW) for millions of vectors, a model built in, and search
  that mixes meaning with words.

### Live queries and subscriptions

```js
// every change a query would see, as it commits
for await (const ev of db.subscribe('SELECT * FROM orders WHERE user_id = ?', [42])) {
  // { type: 'change', op: 'insert', table: 'orders', key: 7, seq, row: { … } }
}

// the full result again whenever it changes, with what was added and removed
const w = db.watch('SELECT * FROM orders WHERE user_id = ?', [42], (rows, { added, removed }) => update(rows))
w.close()
```

`subscribe` takes a single-table query. `watch` takes any query and re-runs it when a table it reads
changes, debounced by `live.debounce`. Events reach a Node callback about 15 µs after the commit.
Subscriptions respect access control: each one sees only the rows its session may see. A subscriber
that falls behind by more than `live.queue` events receives an overflow notice and is dropped, so a
slow consumer never slows the writers.

### Access control

The rules live in the database: roles, what each role may do to each table, and which rows it may
touch. Who is asking comes from your application, which has already checked the login.

```sql
CREATE ROLE customer;
GRANT SELECT, INSERT ON orders TO customer;
CREATE POLICY own_orders ON orders FOR ALL TO customer USING (tenant_id = SESSION.tenant);
```

```js
app.get('/orders', (req, res) => {
  const tenantDb = db.as({ role: 'customer', tenant: req.user.tenantId })   // after your login check
  res.json(tenantDb.all('SELECT * FROM orders'))                           // only this tenant's rows
})
```

```python
s = db.session(); s.assume("customer", tenant=42)
```

```go
s := db.Session(); s.Assume([]string{"customer"}, map[string]any{"tenant": 42})
```

`role`, or `roles` as a list, names existing roles. Every other key is a session attribute that
policies read as `SESSION.<key>`: a number, a string, a boolean, or in Node a `BigInt` or a `Date`.
Nothing about the user is stored in the database.

- Reads, writes, subscriptions and live queries are all filtered. A write outside the policy fails with
  `DENIED`, and asking for another tenant's row by its id returns nothing.
- Grants from all of a session's roles add up, and every policy of those roles applies together.
- A write that reads the rows it changes needs `SELECT` too, as in PostgreSQL, and reaches only the rows
  the role's `SELECT` policies show: an `UPDATE` or `DELETE` with a condition beyond `id = ?`, an
  `UPDATE` whose `SET` reads a column, `RETURNING`, and `ON CONFLICT … DO UPDATE`. `UPDATE … SET n = 1
  WHERE id = ?` and `DELETE … WHERE id = ?` need only `UPDATE` or `DELETE`.
- A missing attribute is an error, not an empty result. So is an unknown role, or an attribute that is
  `undefined`.
- An identity can never change the schema, roles, grants or policies. Only the application's own handle can.
- Creating an identity costs about 1.4 µs in Node, and a policy adds about 0.1 µs to a point read, so
  one identity per request is fine.

Users can also be stored in the database with `CREATE USER alice IN ROLE customer WITH tenant = 7`, and
used with `db.as('alice')`. A client of the TCP listener selects such a user by name after presenting
the listener's token, and a network client can never supply its own attributes. For end users who sign
in with a password, use the next section instead.

### Sign-in

Mark a table you define as the one users sign in to. Its `UNIQUE` text column is the login, and each
user's role comes from a column or is fixed. A signed-in user acts with their row's columns as
`SESSION` attributes, so policies such as `USING (owner = SESSION.id)` apply per user.

```sql
CREATE TABLE users (id SERIAL PRIMARY KEY, email TEXT UNIQUE, name TEXT, role TEXT DEFAULT 'member', tenant_id INT);
ALTER TABLE users ENABLE AUTH (ROLE FROM role);         -- or (ROLE member) for one role for everyone
CREATE POLICY own ON notes FOR ALL TO member USING (owner = SESSION.id);
```

```js
const auth = db.auth('users')
const { token, user } = await auth.signUp({ email: 'ann@example.com', name: 'Ann' }, password)
const again = await auth.signIn('Ann@Example.com', password)        // rejects with AUTH when wrong

app.use((req, res, next) => {                                       // on every request
  try { req.db = db.session((req.get('authorization') ?? '').replace(/^Bearer /, '')) }
  catch { return res.status(401).end() }                            // unknown, signed out or expired
  next()                                                            // req.db acts as her: role, SESSION.id …
})
app.get('/notes', (req, res) => res.json(req.db.all('SELECT * FROM notes')))   // only her notes
auth.signOut(again.token)
```

```python
auth = db.auth("users"); token, user = auth.sign_in("ann@example.com", password)
s = db.session(); s.use_token(token)
```

```go
in, err := db.Auth("users").SignIn("ann@example.com", password)
s := db.Session(); err = s.UseToken(in.Token)
```

- **Logins** are compared trimmed and lowercased; `signUp` stores them that way. If you insert users
  yourself, store logins lowercased.
- **Passwords** are hashed with Argon2id (19 MiB, 2 passes, OWASP's recommendation), about 9 ms each,
  with as many at once as there are cores, up to 8. The hashes live in a system table no SQL can read, not even the application's.
  In Node, `signUp`, `signIn` and `setPassword` run off the JavaScript thread and return promises.
- **Sessions** are random 256-bit tokens (`sqz_…`). Only their SHA-256 is stored. `db.session(token)`
  costs about 2 µs, so it can run on every request. A session lasts `auth.sessionTtl` (30 days).
  `signOut` ends one session; `setPassword` and `signOutEverywhere` end all of a user's sessions.
- **Open handles follow the user.** A handle from `db.session(token)` that you keep, for a connection
  or a socket, checks its token again before its next statement whenever anything about sign-in
  changes. A role or attribute change in the user's row applies there. A sign-out, a password change
  or the user's deletion makes it fail with `AUTH` from then on. Subscriptions and live queries made
  through such a handle are dropped (resubscribe) when the user changes or the session ends.
- **Wrong passwords**: a wrong password and an unknown login fail the same way, in the same time. After
  5 failures for one login, each further attempt waits 1 s, then 2, 4 and so on, up to 15 minutes.
- **Deleting a user** ends their sessions. A new row that reuses a deleted user's key starts without a
  password.
- **Not built yet:** email verification and password reset, and sign-in over the TCP listener and the
  web console.

#### Google, GitHub and other OAuth providers

Configure each provider with your app's client id and secret. `google` and `github` know their
endpoints; any other name is an OpenID Connect provider with `kind = "oidc"`, `authUrl`, `tokenUrl`,
`jwksUrl` and `issuer`.

```toml
[auth.oauth.google]
clientId = "123.apps.googleusercontent.com"
clientSecret = "${GOOGLE_CLIENT_SECRET}"

[auth.oauth.github]
clientId = "Iv1.abc"
clientSecret = "${GITHUB_CLIENT_SECRET}"
```

Your app sends the browser to the provider and takes the code back:

```js
app.get('/auth/google', (req, res) => {
  const { url, cookie } = db.auth('users').oauthStart('google', 'https://app.example/auth/google/callback')
  res.cookie('oauth', cookie, { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 600_000 })   // this browser
  res.redirect(url)
})
app.get('/auth/google/callback', async (req, res) => {
  const { token, user, created } = await db.auth('users')
    .oauthFinish('google', req.query.code, req.query.state, req.cookies.oauth)    // rejects with AUTH if they don't match
  res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'lax' }).redirect('/')
})
```

- The engine makes a single-use `state` (10 minutes), a PKCE challenge, and for OpenID Connect a
  nonce. It checks a Google ID token's RS256 signature against Google's keys, and its issuer, audience,
  expiry, nonce and verified email. A GitHub sign-in needs a verified primary email.
- `oauthFinish` needs the `cookie` from `oauthStart`, read back from the browser, so only the browser that
  started a sign-in can finish it. That rules out login CSRF, and linking someone's provider account to an
  attacker's.
- A first sign-in makes a user whose login is the verified email (`created: true`). Later sign-ins find
  that user by the provider's account id, even if the email changes.
- A sign-in never takes over an existing account by its email, with or without a password. That account
  may have been made by someone else with this address, or through a provider that checks emails less
  strictly. Its owner links the provider while signed in, with
  `oauthStart('google', redirectUri, { link: token })`.
- A user made through a provider has no password until `setPassword`.
- In Python, `auth.oauth_start(provider, redirect_uri, link=None)` returns `(url, state, cookie)`, and
  `auth.oauth_finish(provider, code, state, cookie)` returns `(token, user, created)`. In Go, use
  `Auth.OAuthStart` and `Auth.OAuthFinish`, configured with `Options.Auth`.

### The app API: SQL from the browser

A browser or mobile app can talk to the database directly: users sign in, and the app sends SQL. Every
statement runs as the signed-in user under the row policies, so the rules live in the database and the
app needs no server code of its own. Any `SELECT` can be live, joins and aggregates included: the client
gets its rows at once and again whenever they change.

```sh
sqzdb serve ./data --app 0.0.0.0:8080 --config app.toml
```

```toml
# app.toml
[app]
origins   = ["https://app.example"]   # web pages that may call the API (its own origin always may)
publicUrl = "https://api.example"     # where browsers reach it; needed for provider sign-in
staticDir = "./dist"                  # optional: serve the app's files too

[app.signUp]
users = ["name"]                      # tables clients may make accounts in, and the columns they may set
```

```js
import { connect } from 'https://api.example/api/client.js'   // the server hands out its client: no build step
const db = connect('https://api.example')

await db.auth.signUp({ email, name }, password)               // or signIn(email, password), or signInWith('google')
await db.sql('INSERT INTO notes (owner, body) VALUES (?, ?)', [db.auth.user.id, text])
db.live('SELECT id, body FROM notes ORDER BY created DESC LIMIT 20', (rows) => render(rows))   // her notes, kept current
```

The client (`clients/js`) runs in browsers, React Native and Node 22+. It keeps the session in
`localStorage`, carries SQL and every live query over one WebSocket, and reconnects. Its calls are
`auth.signUp`, `signIn`, `signInWith`, `signOut`, `onChange` and `methods` (whether sign-up is open, and
which providers are configured), then `sql(text, params)`, `batch([[text, params], …])` for one
transaction, `live(text, params, fn)` and `close()`. [`demos/notes`](demos/notes) is a whole app built this way.
On a page sqzdb serves itself (`app.staticDir`, or an app behind it), `connect(location.origin, { cookies: true })`
keeps the session in an HttpOnly cookie instead, out of any script's reach (see
[in front of your app](#in-front-of-your-app-nextjs-and-others)). The API speaks HTTP/1.1 and HTTP/2.

- **Statements:** `SELECT`, `INSERT`, `UPDATE` and `DELETE`, up to 64 KB of SQL and 1,000 parameters
  each, in a request of at most `app.maxRequest` (8 MB). No DDL, no grants, no `BEGIN`: a transaction is a
  `batch` of up to 100 statements, all or none. A result has at most `app.maxRows` rows.
- **Who is asking:** a request acts as the user its session token belongs to. Without a token it acts as
  `app.anonymousRole`, or is refused with `AUTH`.
- **Sign-up** works only in the tables `app.signUp` lists, and sets only the login column and the columns
  listed there; the role column is never a client's to set. Other tables are sign-in only, by password or
  by provider. Sign-up, sign-in and the code exchange are rate limited per client address: 10 at once,
  then one every 3 seconds.
- **Providers:** `signInWith('google')` sends the browser to the API, which sends it to Google. Google
  sends it back to the API, which returns it to the app's page with a one-time code in the URL fragment. The
  client trades the code for a session (once, within 60 seconds) and removes it from the address bar, so
  a session token never sits in a URL. The code works only in the tab that started the sign-in:
  `signInWith` keeps a random verifier in that tab's `sessionStorage` and sends only its SHA-256, and the
  exchange needs the verifier (as in PKCE). A code someone else got for their own account and planted in
  a link signs no one in. The page must be on `app.origins` or `app.publicUrl`.
- **Origins:** browsers may call from the API's own origin and from `app.origins`. Requests and
  WebSockets from other pages are refused.
- **Live queries:** up to 64 per connection. They end when their session does, or when a change to the
  user's row changes their role or attributes; the client then signs out or makes them again.

| Endpoint | Returns |
|---|---|
| `POST /api/auth/<table>/sign-up` `{fields, password}` and `…/sign-in` `{login, password}` | `{token, user, created}` |
| `GET /api/auth/<table>/oauth/<provider>?return=<url>&challenge=<c>` | the provider's sign-in page; `c` is the base64url SHA-256 of the page's verifier |
| `POST /api/auth/exchange` `{code, verifier}` | `{token, user, created}`, for the code a provider sign-in returned |
| `POST /api/auth/sign-out`, `GET /api/me`, `GET /api/auth/<table>/methods` | |
| `POST /api/sql` `{sql, params}` and `POST /api/batch` `{statements}` | `{columns, rows}`, and `lastInsertId` for an `INSERT` |
| `GET /api/socket` | a WebSocket of JSON messages: `auth`, `sql`, `batch`, `live` and `unlive` |
| `POST /api/files?name=<name>` with the bytes as the body | the new file, `{id, name, type, size, url}` |
| `GET /api/files/<id>?e=…&s=…` | the file, through a link a query handed out |
| `GET /api/client.js` | the JavaScript client |

Requests carry the session as `Authorization: Bearer <token>`. Errors are `{error, code}` with the
[codes below](#error-codes), with HTTP status 401 for `AUTH`, 403 for `DENIED`, 429 for `RATE_LIMITED`
and 400 otherwise.

Connections are tasks on a small runtime, not threads. A connected user with two live queries costs the
server about 20 KB, and a write reaches another device's live query in about 0.1 ms, or within
`live.debounce` when writes come back to back (E58, E59).

#### Files

A `FILE` column holds an uploaded file. The row stores the file's id; the bytes are kept in the database
directory's `files/`, each file written once.

```sql
CREATE TABLE notes (id SERIAL PRIMARY KEY, owner INT, body TEXT, attachment FILE);
```

```js
await db.sql('INSERT INTO notes (owner, body, attachment) VALUES (?, ?, ?)', [db.auth.user.id, text, file])   // a File or Blob: uploaded first
const [note] = await db.sql('SELECT body, attachment FROM notes WHERE id = ?', [id])
img.src = note.attachment.url        // { id, name, type, size, url }
```

- **Uploading.** A `File` or `Blob` passed as a parameter is uploaded, and its id goes in the statement.
  `db.files.upload(blob)` uploads on its own and returns the file. A file from a result can be passed back
  as a parameter. Only signed-in users upload, up to `app.files.maxSize` (25 MB). A sign-up can't set a
  `FILE` column (nothing is uploaded yet); set it once signed in.
- **Who may put a file in a row.** A user may set a `FILE` column only to a file they uploaded within the
  last hour, or leave it as the row has it. So a file id someone has seen, in a link say, can't be copied
  into a row of their own. The application, through the library, may set any file.
- **Who may download it.** Whoever may read the row. A `FILE` value in a query's result (live ones
  included) comes with a signed `url`, valid for `app.files.linkTtl` (an hour), so `<img>` and `<a>` work
  without headers, and SQL never sees anyone else's file. The link stays the same for half its lifetime,
  so browsers cache it. An expression over a `FILE` column, or a `GROUP BY`, gives the plain id.
- **How it is served:** with an `ETag` (`304` when unchanged), byte ranges (seeking in a video), and
  `Content-Security-Policy: sandbox` with `nosniff`. Images, video, audio, PDF and plain text are shown in
  place; anything else, HTML and SVG included, downloads as an attachment, so an upload can't run script
  on the API's origin.
- **Cleanup.** A file no row refers to is deleted once it is a day old and has gone an hour unreferenced.
  A file whose row changed or went is therefore gone within about a day.
- **Backup.** With [`backup`](#backup-restore-and-replication) set, each file is uploaded to the bucket
  as it arrives, encrypted like the rest, and deleted there when it is deleted here. Restoring from the
  bucket brings the files back with the rows.
- **Not built yet:** files stored only in S3 (they are kept on the database's disk, and the bucket holds a
  copy), image thumbnails, upload quotas per user, and files through the Node, Python and Go libraries.

#### HTTPS, with certificates from Let's Encrypt

Give the app API its domain and it serves https and wss with a certificate from Let's Encrypt, renewed
automatically, the way Caddy does. No proxy is needed in front.

```sh
sudo setcap cap_net_bind_service=+ep "$(command -v sqzdb)"   # once: bind port 443 without root
sqzdb serve ./data --app 0.0.0.0:443 --domain api.example.com --email ops@example.com
```

```toml
[app.tls]
domains  = ["api.example.com"]      # their DNS points at this server
email    = "ops@example.com"        # optional: the CA's notices
redirect = "0.0.0.0:80"             # optional: send http:// visitors to https://
# cert = "/etc/ssl/api.pem"         # or your own certificate and key (PEM) instead of domains
# key  = "/etc/ssl/api.key"
# acme = "https://acme-staging-v02.api.letsencrypt.org/directory"   # another CA: staging, ZeroSSL, your own
```

- The CA checks the domains over TLS-ALPN-01 on port 443 itself, so port 80 can stay closed. The domains
  must resolve to this server, and port 443 must reach it.
- The first certificate arrives a second or so after start (1 s against Let's Encrypt's test CA here);
  until then https connections fail. A restart serves the stored certificate at once.
- Renewal starts with a third of the certificate's lifetime left (30 days of Let's Encrypt's 90). A failed
  attempt is retried after a minute, then less often, up to every hour, while the current certificate keeps
  serving. Progress goes to stderr as `tls: …`.
- The account key and the certificate are kept in the database directory's `tls/` (or `app.tls.dir`),
  readable only by the owner. Losing them only means getting a new certificate.
- Setting `domains` agrees to the CA's terms (for Let's Encrypt, its Subscriber Agreement).
- `app.publicUrl` defaults to `https://` and the first domain.
- TLS costs about 10 KB more per connected device (27 KB with two live queries), and requests take as long
  as without it (E60).
- Wildcard and IP-address certificates aren't supported: they need DNS challenges, or a CA profile this
  doesn't ask for.

**Not built yet:** email verification and password reset.

#### Agents over MCP: Claude, ChatGPT, Claude Code

With `[app.mcp]` set, the app API also serves the [Model Context Protocol](https://modelcontextprotocol.io)
at `/mcp`. An agent connects with that URL alone. It finds the database's sign-in through the protocol's
discovery, registers itself, and sends its user to a sign-in page that the database serves. The user signs
in with a password or a provider (`auth.oauth`) and allows the agent. From then on the agent acts as that
user, with that user's grants and row policies, as a browser does.

```toml
[app]
publicUrl = "https://api.example.com"   # or --domain api.example.com

[app.mcp]
users = "users"                          # the ENABLE AUTH table people sign in to (optional when there is one)
```

```sh
claude mcp add --transport http myapp https://api.example.com/mcp   # Claude Code
```

In Claude and ChatGPT, add a custom connector with the same URL.

- **What an agent can do:** the app's [functions](#functions-your-apps-rules-in-the-database) it may call,
  one tool each, and three SQL tools. `describe` lists the tables it may use (columns, types, keys, what it
  may do with each, the policies that apply) and who it is. `query` runs one `SELECT`. `execute` runs
  `INSERT`, `UPDATE` and `DELETE`, one statement or several in a transaction. The statement rules are
  those of `/api/sql`: no DDL and no grants. Rows come back as objects, at most `app.mcp.maxRows` (500) a
  result. With `app.mcp.sql = false`, an agent gets the functions only.
- **Sign-in** follows the MCP authorization spec: protected-resource and authorization-server metadata,
  dynamic client registration (public clients, or ones with a secret), PKCE with S256 only, tokens bound
  to this server's `/mcp`. The page shows which app is asking and where it will send the user back. It
  can't be framed. An address the app didn't register is never redirected to.
- **Tokens:** an access token lasts `app.mcp.tokenTtl` (an hour) and works only at `/mcp`. An app
  session works only at the app API. A refresh token is good once: it's replaced, and the access token
  it came with ends. A refresh token used twice ends the whole sign-in, since someone has a copy. A
  sign-in lapses after `app.mcp.grantTtl` (30 days) unused and after 90 days in any case. A password
  change or a sign-out everywhere ends it. Revocation is at `/oauth/revoke`.
- **Abuse:** a sign-in in progress is bound to the browser that started it, so its link alone is
  useless to anyone else. Sign-ins and registrations are rate-limited per address (an IPv6 /64), with
  at most 20 sign-ins in progress per address. Registrations that never got a token make room after a
  day. A page may call `/mcp` only from the app's own origin or `app.origins`.
- The official TypeScript SDK's client (1.30) connects, signs in, lists the tools and calls them; a tool
  call takes about 0.3 ms over HTTP (E65). Claude, ChatGPT and Claude Code use the same flow but weren't
  tested here: they need the server on a public https address.
- **Not built yet:** Client ID Metadata Documents (clients register dynamically instead), server-to-agent
  notifications, resources and prompts.

### Functions: your app's rules in the database

A function is a piece of your app's server code, in TypeScript or JavaScript, that runs inside the
database. Clients call it by name instead of sending SQL. A rule such as "a finished run can't change" then
holds for the browser, a script and an agent alike, with no backend of your own to enforce it.

```ts
// functions/runs.ts
import { fn } from 'sqzdb/functions'

export const reportRun = fn({
  description: 'Report how a run ended; when every run of its job has ended, the job moves to review',
  args: { runId: 'int', status: ['completed', 'failed'], outcome: 'text?' },
  roles: ['member'],
  run({ db, admin }, { runId, status, outcome }) {
    const run = db.get('SELECT id, job, status FROM runs WHERE id = ?', [runId])   // as the caller, under their policies
    if (!run) throw Object.assign(new Error(`no run ${runId}`), { code: 'NO_RUN' })
    if (run.status !== 'running') throw Object.assign(new Error('a finished run cannot change'), { code: 'ALREADY_FINISHED' })
    if (status === 'completed' && !outcome) throw new Error('a completed run needs an outcome')
    admin.run('UPDATE runs SET status = ?, outcome = ? WHERE id = ?', [status, outcome ?? null, runId])
    const left = admin.get("SELECT count(*) AS n FROM runs WHERE job = ? AND status = 'running'", [run.job]).n
    if (left === 0) admin.run("UPDATE jobs SET status = 'review' WHERE id = ?", [run.job])
    return { status, jobStatus: left === 0 ? 'review' : 'running' }
  },
})
```

**Deploying.** You deploy a folder as a whole. It holds `.ts`, `.mts`, `.js` and `.mjs` files that import
each other by relative path; `.d.ts`, `*.test.*`, `*.spec.*`, `node_modules` and hidden entries are skipped.
The folder deploys when the database opens and, by default, again whenever it changes. On a server, a
`git pull` is a deploy.

```js
const db = open('./data/app', { functions: './functions' })   // Node, embedded
```

```sh
sqzdb serve ./data --app 0.0.0.0:443 --domain api.example.com --functions ./functions
sqzdb deploy ./functions ./data                                 # to a database that isn't open
sqzdb deploy ./functions db.internal:7781 --token "$DB_TOKEN"   # to a running server, over its TCP port
```

- A deploy replaces every function before it. The same files again change nothing.
- A deploy is stored in the catalog, so it is logged, snapshotted, backed up and copied to followers with
  the schema. A database restored from its bucket has its functions.
- A deploy that fails changes nothing and names the file, line and column. It fails on a syntax error, an
  import that isn't there, or two functions with one name.
- Only the application deploys: in code, through the TCP port or socket with its token, or from the
  console. A client of the app API or an agent can't.

**Calling.** A call runs as the caller, under their grants and policies:

- **Node:** `db.call('reportRun', { runId: 7, status: 'failed' })` on any handle: the app itself, `db.as(…)`
  or `db.session(token)`. Python has `session.call(name, args)`, Go `Session.Call` and C `sqzdb_call`.
- **The browser client:** `await client.call('reportRun', { … })`, over its socket. Over plain HTTP it's
  `POST /api/fn/reportRun` with the arguments as the JSON body; the answer is `{"result": …}`.
- **Agents over MCP:** each function is a tool. Its `description` and `args` become the tool's
  description and input schema, and `readOnly` its read-only hint.

**What a function gets.** `run(ctx, args)`, where `ctx` has:

- `ctx.db` acts as the caller. `get(sql, params)` returns the first row or null, `all(sql, params)`
  the rows, and `run(sql, params)` `{ changes, lastInsertId }`.
- `ctx.admin` is the same, in the same transaction, without grants or policies. It does what the
  caller may not. In the example, members have `SELECT` on `runs` but no `UPDATE`, so `reportRun`, with its
  rules, is the only way they can change a run.
- Both work only during the call that received them: a function that keeps one for later gets an error,
  never another caller's identity.
- Who is calling is checked again at each call. A signed-out session, or a user whose role changed, is
  refused at once, even on a socket that stays open.
- `ctx.user` is the caller's row, or the attributes `db.as` vouched for; null when the app calls.
  `ctx.roles` lists the caller's roles.
- Values are as in Node: `INT` is a number (BigInt past 2^53), `TIMESTAMP` a Date, `BYTES` a Uint8Array.
- A function returns any JSON value. A Date becomes its ISO text, bytes 0x-prefixed hex.

**The rules of a call:**

- **Transaction:** a call is one transaction. It commits when `run` returns and rolls back when it throws.
  A call inside an open transaction (`db.transaction` in Node) joins it. If the call fails there, that
  transaction can't commit.
- **Conflicts:** when another writer got there first, the whole call runs again, up to 50 times. Its reads
  count as described under [transactions](#transactions-and-durability). Two calls that each update a run
  and then count the job's running runs can't both see "one left".
- **A failed write ends the call:** a statement that fails while writing may have written some of its rows,
  so it ends the call's transaction even if the function catches the error. Catch it to change the error,
  not to carry on. For a duplicate you expect, use `INSERT … ON CONFLICT DO NOTHING`. A failed read can be
  caught and handled.
- **Errors** reach the caller with a code:
  - `NOT_FOUND`: no such function;
  - `DENIED`: the caller lacks its `roles`;
  - `ARGUMENTS`, or `LIMIT` for time or memory;
  - `FUNCTION`: it threw;
  - the code of a database error it let through;
  - or the `code` of an Error it threw (`ALREADY_FINISHED` above: capitals, digits and `_`).

  A `TypeError` and other bugs say where they happened, in the TypeScript's own lines.
- **`roles`** says who may call. Without it, anyone signed in may; the anonymous role
  (`app.anonymousRole`) only when it's listed.
- **`readOnly: true`** allows `SELECT` only.

**Arguments** are checked before the function runs:

- a type: `'int'`, `'number'`, `'text'`, `'bool'`, `'uuid'` or `'json'` (any value);
- `?` after the type when it may be left out or null;
- a list of the texts it may be (`['completed', 'failed']`);
- or `{ type, description, optional }`.

Arguments the function doesn't take are refused. With `sqzdb/functions` from npm (`npm install -D
sqzdb`), TypeScript infers `run`'s arguments from `args`. Above, `status` is `'completed' | 'failed'` and
`outcome` is `string | null | undefined`.

**The sandbox.** Functions run in QuickJS, inside the database's process:

- no files, network, timers or processes;
- no npm packages: imports are the folder's files and `sqzdb/functions`;
- `functions.timeout` per call (1 s) and `functions.memory` per instance (64 MB). A function past either
  fails with `LIMIT`, and the database carries on. The rows a query hands it and the result it returns
  count toward the memory limit too;
- a call waits for a free instance for at most four time limits (at least 5 s), then fails with `LIMIT`;
- a promise that can't settle fails the call (there are no timers or I/O to wait for);
- up to `functions.instances` calls run at once (the CPU count), each in its own instance. A module's
  top-level variables live per instance, so don't keep state there;
- `console.log` goes to the server's error output.

**Costs (E66):**

- In the process, a function that does nothing costs 3 µs, its transaction included.
- One that returns 10 rows costs 16 µs, against 3 µs for its `SELECT` sent directly.
- Over HTTP, a call costs 10 to 20 µs more than the same `SELECT`: about 70 to 90 µs a round trip.
- QuickJS and the TypeScript stripper add about 4 MB to the binary.

Middleware and routes, the same kind of code for HTTP requests, are under
[in front of your app](#in-front-of-your-app-nextjs-and-others).

**Not built yet:**

- npm packages inside functions;
- functions on a schedule;
- functions that call out over HTTP (for now, a worker of yours does that and calls a function back);
- an output schema for MCP;
- read-only functions on followers.

### In front of your app: Next.js and others

sqzdb can serve the whole site. It answers what is its own and passes everything else on to your app's
server, such as Next.js on 127.0.0.1:3000. One process then gives the site:
- HTTPS, with certificates from Let's Encrypt, and HTTP/2;
- sign-in, the database and live queries;
- MCP for agents;
- your app's rules.

```sh
sqzdb serve ./data --app 0.0.0.0:443 --domain tasks.example.com --proxy http://127.0.0.1:3000 --functions ./functions
next start -H 127.0.0.1 -p 3000
```

Or with the database embedded in Next.js, as in [`demos/nextjs`](demos/nextjs):

```js
open('./data/app', { functions: './functions', listen: { app: '0.0.0.0:443' },
                     app: { proxy: 'http://127.0.0.1:3000', tls: { domains: ['tasks.example.com'] } } })
```

Open it when the server starts (Next.js's `instrumentation.js`), so the front door is listening before
anyone asks.

**What goes where:**
- **sqzdb's own paths** are answered as always:
  - `/api/…`, matched endpoint by endpoint, so your app's own `/api` routes still reach it;
  - `/mcp`, `/oauth/…` and `/.well-known/oauth-…`;
  - its sign-in pages under `/_sqz/`.
- **Everything else goes to the app**, after middleware and routes (below):
  - bodies stream both ways, and a page that renders in pieces arrives in pieces;
  - WebSocket upgrades are passed through, and no other kind: a client can't turn a connection into a
    tunnel to the app that middleware never sees;
  - connections to the app are kept in a pool, with at most `app.proxy.connections` (256) requests in
    flight;
  - if the app is down, visitors get a 502 page and the API carries on.
- **The app learns who asked:**
  - `X-Forwarded-For`, `-Proto` and `-Host`, and `X-Real-IP`;
  - for a signed-in visitor, `X-Sqz-User` (their key), `X-Sqz-Table` (the table it is a key of) and
    `X-Sqz-Roles`. A client's own `X-Sqz-…` headers never get through.

  Let the app listen on 127.0.0.1 only, so nothing reaches it any other way.

**Sessions in a cookie.** A page navigation carries cookies, not an `Authorization` header. So for a site
sqzdb serves, the session lives in a cookie:
- **The cookie:** `__Host-sqz_session` over https (`sqz_session` over http, in development). It is HttpOnly
  (no script reads it), SameSite=Lax (no other site's form or fetch sends it), Secure, and a browser takes it
  only from this very host, so a sibling subdomain can't plant one.
- **Only from the site itself:** it counts when a request comes from the site's own origin or one
  `app.origins` names. `"*"` lets other pages call the API, not act as its visitor.
- **Who reads it:**
  - the API takes it wherever it takes a token;
  - the app can act as the visitor with it, as `db.session(cookies().get(db.sessionCookie)?.value)` in
    Next.js.
- **sqzdb's sign-in page,** `/_sqz/sign-in?return=/somewhere`:
  - it signs in with a password or a provider of `auth.oauth`, and makes accounts where `app.signUp` lists
    the table;
  - it sets the cookie and goes back to `return`: a path on the site, or a page on `app.origins`, never
    another site;
  - `/_sqz/sign-out` ends the session.
- **Or a page of your own:** the client in cookie mode, `connect(location.origin, { cookies: true })`, signs
  in the same way, and `signInWith('google')` comes back signed in. No token ever reaches the page.
- **Forged forms:** the pages' forms are bound to the browser that loaded them and to the site's own
  origin, so another site can't sign a visitor in or out.

**Middleware and routes.** They live in the same folder as
[functions](#functions-your-apps-rules-in-the-database):

```ts
import { middleware, route, signIn } from 'sqzdb/functions'

export const guard = middleware({
  match: ['/dashboard/*', '/admin/*'],
  run({ user, roles }, req) {
    if (!user) return signIn(req)                      // to the sign-in page, and back here after
    if (req.path.startsWith('/admin') && !roles.includes('admin')) return new Response('Forbidden', { status: 403 })
    req.headers.set('x-plan', 'pro')                   // the app sees it
  },
})

export const hooks = route({
  method: 'POST', path: '/hooks/:source',
  async run({ admin }, req) {
    admin.run('INSERT INTO events (source, body) VALUES (?, ?)', [req.params.source, await req.text()])
    return Response.json({ ok: true })
  },
})
```

- **Middleware:**
  - it runs for the paths it `match`es, never sqzdb's own, in `order` and then by file and name;
  - it returns a `Response` to answer, or nothing to let the request go on, with any headers it set or
    removed;
  - it gets the headers, not the body, which streams on untouched.
- **Routes:**
  - a route answers a `method` and `path` itself, with a `Response`, a value (sent as JSON), or nothing
    (204);
  - it gets the body (`req.text()`, `json()` or `bytes()`, up to `app.maxRequest`);
  - of routes that match, the one with the most literal segments wins;
  - `roles` limits who may call it.
- **What both get:**
  - `ctx` as functions do: `db` as the visitor, `admin`, `user` and `roles`;
  - a request: `method`, `path` (decoded, as patterns matched it: check paths with this), `rawPath` and
    `url` (as sent), `query`, `params` (`/jobs/:id` gives `req.params.id`, and a final `*` gives the rest),
    `headers`, `cookies` and `ip`;
  - each request is one transaction, with the functions' limits. At most `functions.instances` run at
    once; the rest wait their turn, and get a 503 if none comes in time.
- **If the deployed functions can't load** (say, after a change of configuration), everything that isn't
  sqzdb's own gets a 503 until they can: the site is never served without its guards.
- **Path matching** follows how the app will resolve the path:
  - each segment is decoded (`/adm%69n` is `/admin`);
  - Next.js's data route for a page (`/_next/data/<build>/admin.json`) counts as that page;
  - dot segments and encoded slashes are refused (400). Browsers never send them, and they could reach the
    app by a path a pattern never saw.
- **`Response` and `Headers`** are global inside the database. In TypeScript, outside a project with DOM
  types, import them from `sqzdb/functions`.

**Behind proxies of yours.** With Caddy, nginx or a load balancer in front, name them in
`app.trustProxy = ["127.0.0.1", "10.0.0.0/8"]`. From those addresses, the client's address is the last one in
`X-Forwarded-For` (over all its headers) that isn't one of them, so the sign-in rate limits count each visitor,
not the proxy. From anyone else, `X-Forwarded-For` is kept for the app but never believed, and `Forwarded` is
dropped.

**Costs (E67, E68):**
- **A small page:** about 10 to 20 µs more through sqzdb than from the app directly (52 against 40 µs);
- **with a middleware:** about 40 µs more again;
- **a route sqzdb answers itself:** about 48 µs in all;
- **a Next.js page that takes 1 ms to render:** 1.05 ms through sqzdb;
- **connections:** 2,000 requests one after another used one connection to the app. 50 at once opened 49,
  and the next 50 reused them;
- **a 64 MB upload** streams through in about 100 ms.

**Not built yet:** HTTP/3, compressing the app's responses (Next.js compresses its own by default), and
caching.

### Backup, restore and replication

Everything is built on the change log, so backups never pause the database.

- **Continuous backup** to any S3-compatible bucket with the `backup` option. Objects are compressed
  with zstd and, with a `passphrase`, encrypted with AES-256-GCM before upload. Small objects are
  compacted in the bucket automatically. 1 million rows take about 6 MB in the bucket.
- **Uploaded files** go to the same bucket, under `files/`, as they arrive: compressed when that helps (not
  photos, video or archives, which already are), encrypted, and streamed, so a large file is never held
  in memory whole. A file deleted here is deleted there. When the database opens, it checks the bucket
  against its files. It uploads what is missing there, fetches back what is missing here, and deletes
  objects of files it no longer has. A file fetched from the bucket must have the SHA-256 recorded when
  it was uploaded, so one altered or swapped in the bucket is refused and reported, not restored. With
  `durable: 'cloud'`, an upload returns once its file is in the bucket. On a local S3 server, a 100 KB
  file was in the bucket 0.8 ms after its upload (E63).
- **Bootstrap.** With `backup.bootstrap: true`, opening an empty directory restores the latest state
  from the bucket first, files included; a 1M-row bucket was restored and answering queries in 0.28 s.
- **Followers.** The `follow` option opens a read-only replica of another directory on the same host,
  or of a bucket. With a 20 ms `poll`, new rows reached the follower about 38 ms after the primary
  committed them.
- **Point-in-time restore** to any log position is available from the Rust API
  (`Sql::backup` and `Sql::restore`). Both take the files along, as hard links when they can.
- **Outages.** If the bucket stops answering, writes continue and the uploader retries with a growing
  pause, up to 30 seconds; when the bucket is back it catches up on its own. With `durable: 'cloud'`,
  commits wait for the bucket instead. A malformed `endpoint` is refused when the database opens.

### Web console and command line

```sh
sqzdb serve ./data/shop --ui 127.0.0.1:7780 --tcp 0.0.0.0:7781   # own a database, serve it
sqzdb serve ./data/shop --app 0.0.0.0:8080 --config app.toml     # … to browsers and mobile apps
sqzdb serve ./data/shop --app 0.0.0.0:443 --domain api.shop.com   # … over https, certificate from Let's Encrypt
sqzdb shell ./data/shop                                          # SQL in the terminal
sqzdb shell db.internal:7781 --token …                           # the same against a running server
sqzdb serve ./data/shop --app 0.0.0.0:8080 --functions ./functions   # with the app's functions, redeployed on change
sqzdb deploy ./functions db.internal:7781 --token …               # deploy them to a running server
sqzdb serve ./data --app 0.0.0.0:443 --domain shop.com --proxy http://127.0.0.1:3000   # in front of your app
```

`serve` owns a directory and starts what you ask for: a Unix socket, TCP, backup, the snapshot policy,
with `--ui` a web console, and with `--app` [the app API](#the-app-api-sql-from-the-browser). Every console request needs the token; without `--token`, one is
generated and printed once. `Ctrl-C` stops cleanly, writing a final snapshot so the next start is
instant.

The console has a table browser, a form to create and alter tables, a SQL editor with a **Live** toggle
that keeps results current, a feed of changes, and the roles, grants and policies. Its **Backup** tab
shows whether uploads are healthy, how far the bucket is behind, the last error and a connection test;
when backup is off, it writes the settings file and the restart command for your bucket. It is one HTML page compiled into the binary, with no build step. Bind it
to loopback unless you intend otherwise: it acts as the application and sees everything.

An embedded database can serve the same console from inside your application:

```js
const db = open('./data/shop', { listen: { http: '127.0.0.1:7780', token: process.env.DB_CONSOLE_TOKEN } })
```

It runs on the database's own threads, not on the event loop, and costs about 0.1 MB when idle.
`db.close()` stops it and frees the port.

## Configuration

Every binding accepts the same options. Values passed in code override a TOML file named by
`configFile`, which overrides the defaults. The data directory itself is never read for configuration,
so a directory others can write to cannot redirect your backups or open a listener. Unknown keys are
errors, so a typo never silently disables anything.

```js
const db = open('./data/orders', {
  configFile: '/etc/sqzdb/orders.toml',
  durable: true,
  backup: {
    endpoint: 'https://s3.eu-central-1.amazonaws.com', bucket: 'acme-prod', prefix: 'orders/',
    region: 'eu-central-1', accessKey: process.env.S3_KEY, secretKey: process.env.S3_SECRET,
    passphrase: process.env.DB_PASSPHRASE,
  },
  listen: { socket: '/run/sqzdb/orders.sock', http: '127.0.0.1:7780', token: process.env.DB_TOKEN },
})
```

Python takes the same keys as keyword arguments, `sqzdb.Database(path, backup={...})`. Go takes
`sqzdb.OpenWith(path, sqzdb.Options{...})`, and C takes a JSON string in `sqzdb_open_with`.

| Key | Default | Description |
|---|---|---|
| `configFile` | none | A TOML file with these same keys. Code only; a file cannot name another. |
| `durable` | `false` | `false`, `true` or `'cloud'`. See [durability](#transactions-and-durability). |
| `create` | `true` | Create the database if the directory holds none. Never wipes one. |
| `recoverThreads` | `4` | Threads used to replay the log at startup. |
| `backup.endpoint`, `bucket`, `accessKey`, `secretKey` | required | The S3-compatible bucket to back up to. |
| `backup.prefix` / `region` | `''` / `us-east-1` | Where in the bucket, and the bucket's region. |
| `backup.passphrase` | none | Encrypt with AES-256-GCM before upload. Without it, data is compressed only. |
| `backup.interval` | `1s` | How often new log records are uploaded. |
| `backup.compress` | `true` | Compress uploads with zstd. |
| `backup.compactAfter` / `compactEvery` | `1m` / `30s` | When small objects are merged in the bucket. |
| `backup.bootstrap` | `false` | Restore from the bucket, files included, when opening an empty directory. |
| `follow.dir` or `follow.bucket` | none | Open as a read-only replica of a directory or a bucket. |
| `follow.poll` | `100ms` | How often a follower checks for new records. |
| `snapshot.logBytes` | `64MB` | Snapshot once the log since the last snapshot exceeds this size, or that snapshot's own size if larger. |
| `snapshot.idleAfter` | `30s` | Snapshot after this long without writes. |
| `listen.socket` / `tcp` / `http` | none | A Unix socket, a TCP listener, and the web console. |
| `listen.token` | none | The shared secret for TCP and the console; required when either is on. The `sqzdb` command generates one if you don't pass `--token`. |
| `listen.app` | none | The app API for browsers and mobile apps (`--app`). Users sign in; no shared token. See [the app API](#the-app-api-sql-from-the-browser). |
| `app.origins` | `[]` | Web origins whose pages may call the app API, besides its own. `"*"` allows any. |
| `app.publicUrl` | none | The URL the app API is reached at. Needed for provider sign-in. |
| `app.signUp.<table>` | none | A table clients may make accounts in, and the columns they may set besides the login. Tables not listed are sign-in only. |
| `app.anonymousRole` | none | The role of a request without a session. Without it, such requests are refused. |
| `app.maxRows` | `10000` | The most rows one result for a client may have. |
| `app.staticDir` | none | Files to serve beside the API (the app itself), with `index.html` for paths without a file. |
| `app.files.maxSize` | `25MB` | The largest file a client may upload. |
| `app.files.linkTtl` | `1h` | How long a link to a file in a query's result works (at least `1m`, at most `7d`). |
| `app.mcp` | off | Serve MCP at `/mcp`, with sign-in through the API's own OAuth server (needs an https `app.publicUrl` or `app.tls.domains`). See [agents over MCP](#agents-over-mcp-claude-chatgpt-claude-code). |
| `app.mcp.users` | the only `ENABLE AUTH` table | The table people sign in to when they connect an agent. |
| `app.mcp.tokenTtl` / `grantTtl` | `1h` / `30d` | How long an agent's access token lasts, and how long its sign-in lasts unused (the agent refreshes on its own). |
| `app.mcp.maxRows` | `500` | The most rows one result for an agent may have. |
| `app.proxy` or `app.proxy.to` | none | The app sqzdb stands in front of (`--proxy`), such as `http://127.0.0.1:3000`: what isn't sqzdb's own goes on to it. See [in front of your app](#in-front-of-your-app-nextjs-and-others). |
| `app.proxy.timeout` / `connections` | `60s` / `256` | How long the app may take to start answering, and how many requests may be in flight to it at once (the rest wait as long, then get a 503). |
| `app.trustProxy` | `[]` | Proxies of yours in front of sqzdb (addresses or networks): from them, the client's address comes from `X-Forwarded-For`. |
| `app.mcp.sql` | `true` | The SQL tools (`describe`, `query`, `execute`) besides the app's functions. `false`: agents get the functions only. |
| `app.maxRequest` | `8MB` | The largest request body or WebSocket message a client may send, between `64KB` and `256MB`. A file upload streams instead (`app.files.maxSize`). |
| `app.tls.domains` | none | Serve https with a certificate for these names from the CA (`--domain`), renewed automatically. See [HTTPS](#https-with-certificates-from-lets-encrypt). |
| `app.tls.email` | none | The contact on the CA account, for its notices (`--email`). |
| `app.tls.cert` / `key` | none | Your own certificate chain and key (PEM files), instead of `domains`. |
| `app.tls.acme` | Let's Encrypt | The directory URL of another ACME CA. |
| `app.tls.acmeRoot` | none | A root certificate (PEM) to trust for the CA's own connection: a private or test CA. |
| `app.tls.dir` | `<database>/tls` | Where the account key and the certificate are kept. |
| `app.tls.redirect` | none | An address, such as `0.0.0.0:80`, where plain HTTP is sent on to https. |
| `functions` or `functions.dir` | none | A folder of the app's functions, deployed at open (`--functions`). See [functions](#functions-your-apps-rules-in-the-database). |
| `functions.watch` | `true` | Deploy the folder again whenever it changes. |
| `functions.timeout` / `memory` | `1s` / `64MB` | How long one call may run, and the memory of the instance it runs in. |
| `functions.instances` | the CPU count | How many calls run at once, each in its own instance. |
| `live.debounce` | `5ms` | The shortest time between two re-runs of a live query. A change re-runs it at once; more changes within this time are batched into one re-run. |
| `live.queue` | `65536` | Events a subscriber may fall behind before it is dropped. |
| `log.threadsIdleAfter` | off | Let log threads exit when idle; for many idle databases in one process. |
| `auth.sessionTtl` | `30d` | How long a session from sign-in lasts. At least `60s`. |
| `auth.passwordMin` | `8` | The shortest password `signUp` and `setPassword` accept, in characters. |
| `auth.oauth.<name>` | none | An OAuth provider: `clientId`, `clientSecret`; for providers other than `google` and `github`, `kind = "oidc"`, `authUrl`, `tokenUrl`, `jwksUrl` and `issuer`. Optional `scopes`. See [sign-in](#sign-in). |
| `embed.url` / `model` | none | An OpenAI-compatible embeddings endpoint (https, or http on this machine) and its model, for generated `VECTOR` columns and `embed()`. |
| `embed.apiKey` | none | Sent as `Authorization: Bearer`. |
| `embed.dimensions` | the model's | Asked of models that can shorten their vectors. |
| `embed.batch` | `64` | Texts embedded in one request. |
| `log.syncDelay` | off | With `durable: false`, hold the background fsync up to this long so one fsync covers more writes. For hosts with thousands of small databases (one per tenant or agent) on one disk. A machine crash can then lose up to this much; a process crash still loses nothing, and anything that waits for durability syncs at once. At most `60s`. |

Durations are written as `'5ms'`, `'1s'`, `'2m'`, `'1h'`, `'7d'` or a number of milliseconds. Sizes are
`'256MB'`, `'1GB'` or a number of bytes. `0` turns a snapshot policy off.

The same settings as a file, for operators. Strings may reference environment variables as `${NAME}`;
an unset variable is an error.

```toml
# /etc/sqzdb/orders.toml
durable = true

[backup]
endpoint   = "https://s3.eu-central-1.amazonaws.com"
bucket     = "acme-prod"
prefix     = "orders/"
accessKey  = "${S3_KEY}"
secretKey  = "${S3_SECRET}"
passphrase = "${DB_PASSPHRASE}"
bootstrap  = true

[listen]
tcp   = "0.0.0.0:7781"
token = "${DB_TOKEN}"
```

## SQL reference

**Tables and constraints**

- `CREATE TABLE [IF NOT EXISTS]` with an `INT`, `UUID`, text or bytes primary key, `NOT NULL`, `DEFAULT`
  (a constant, `uuid()`, `gen_random_uuid()` or `now()`), one `UNIQUE` column, and
  `FOREIGN KEY … REFERENCES … ON DELETE RESTRICT | CASCADE | SET NULL`. The key and the `UNIQUE`
  column can also be declared at the end: `PRIMARY KEY (id)`, `UNIQUE (email)`.
- `CREATE INDEX` on one column of type `INT`, `TIMESTAMP`, `UUID`, `TEXT` or `BYTES`.
- `TEXT` and `BYTES` (also `VARCHAR`, `CLOB`, `BLOB`, `BYTEA`) hold values of any length, up to 16 MB.
  A value of up to 44 bytes is kept in its row and a longer one beside it, so short text costs 64 bytes
  of row and a document costs about its length. `TEXT(n)` and `BYTES(n)` keep up to n bytes (at most
  65,535) in the row itself. Either kind can be a key, `UNIQUE`, indexed, joined on and referenced.
  An update logs the whole row, long values included: changing a status on a row with a 256 KB text
  writes 256 KB of log (E64). In a database made before 0.9, a `TEXT` column made then stays `TEXT(255)`.
- `FILE` columns hold uploaded files (see [files](#files)). A `FILE` column can't be a key, `UNIQUE` or have
  a `DEFAULT`, and its type doesn't change.
- `VECTOR(n)` columns hold n numbers, and `VECTOR(n) GENERATED ALWAYS AS (embed(<expression>)) STORED` the
  embedding of a text (see [vectors](#vectors-and-search-by-meaning)). The same rules as for `FILE` apply.
- `ALTER TABLE … ADD | DROP | RENAME COLUMN`, `ALTER COLUMN … TYPE`, `SET | DROP NOT NULL`, all online.

**Queries**

- `SELECT` with `WHERE` (comparisons, `AND`, `OR`, `NOT`, `IN`, `NOT IN`, `IS NULL`, `BETWEEN`, `LIKE`,
  `ILIKE`), `DISTINCT`, `GROUP BY` any number of columns or expressions, `HAVING`, `ORDER BY` several
  columns, positions or aliases, `LIMIT` and `OFFSET`. `LIKE` is case-sensitive; `ILIKE` is not.
- Aggregates: `COUNT`, `SUM`, `AVG`, `MIN`, `MAX`, `COUNT(DISTINCT …)` and the other `DISTINCT` forms,
  `group_concat` and `string_agg`, over columns or expressions, and expressions over aggregates.
- Expressions wherever a value goes: arithmetic, `||`, `CASE`, `CAST`, JSON `->` and `->>`, and functions
  for text (`lower`, `upper`, `length`, `substr`, `replace`, `trim`, `instr`, `concat`, `concat_ws`, `left`,
  `right`, `reverse`, `repeat`, `hex`), numbers (`abs`, `round`, `ceil`, `floor`, `sqrt`, `power`, `sign`,
  `mod`, `greatest`, `least`), NULL (`coalesce`, `ifnull`, `nullif`, `iif`), time (`now()`,
  `current_date`, `date`, `time`, `datetime`, `strftime`, `unixepoch`, `EXTRACT`), JSON (`json_extract`,
  `json`, `json_valid`, `json_array_length`, `json_object`, `json_array`, `json_type`), vectors
  (`cosine_distance`, `l2_distance`, `inner_product`, `vector_dims`, `embed`), and `uuid()`,
  `gen_random_uuid()` and `typeof`. Unlike SQLite, a division by zero, an integer overflow (in `SUM` too)
  and a value of the wrong type are errors, not NULL or a guess.
- `SELECT` without `FROM`: `SELECT 1 + 1`, `SELECT now()`.
- `JOIN` and `LEFT JOIN` on equalities across up to eight tables, and scalar, `IN`, `EXISTS` and
  correlated subqueries. Joined columns hold the same kind of value: integers (`INT`, `TIMESTAMP`),
  UUIDs, text, or bytes.

**Writes**

- `INSERT … VALUES` with several rows (all or none), `DEFAULT` as a value, `INSERT … SELECT`, and
  `RETURNING`.
- Upserts: `ON CONFLICT (col) DO NOTHING`, `ON CONFLICT (col) DO UPDATE SET … [WHERE …]` with
  `excluded.col`, `INSERT OR IGNORE`, `INSERT OR REPLACE` and `REPLACE INTO`.
- `UPDATE … SET col = expression WHERE` any condition, with `RETURNING`, and `DELETE … WHERE` any
  condition. Both return how many rows changed (`changes`), and a statement that changes several rows
  changes all of them or none. `UPDATE … WHERE <primary key> = ?` fails with `NOT_FOUND` when the row
  doesn't exist.
- `BEGIN`, `COMMIT`, `ROLLBACK`. Inside a transaction, a lookup by primary key sees the transaction's own
  writes. Any other read of a table the transaction has already written is refused with `TRANSACTION`,
  because reads see committed data only: read before writing, or commit first.

**Access control**

- `CREATE ROLE`, `CREATE USER … IN ROLE … [WITH attr = value]`, `GRANT … ON table TO role`, and
  `CREATE POLICY name ON table FOR cmd TO role USING (col = SESSION.attr [AND …])`.
- `ALTER TABLE … ENABLE AUTH [(ROLE FROM column | ROLE name)]` and `DISABLE AUTH`: see
  [sign-in](#sign-in).

**Values**

- `TIMESTAMP` literals as text: `'2026-10-15'`, `'2026-10-15 19:30:00'`, `'2026-10-15T19:30:00.123Z'`.
- `UUID` literals as text, with or without hyphens.

**Not supported yet:** `UPDATE … FROM`, `DELETE … RETURNING`, `RIGHT` and `FULL` joins, `WITH`, `UNION`, window functions, subqueries in `FROM`, correlated subqueries on text
columns, `DISTINCT ON`, `NULLS FIRST` and `NULLS LAST`, `CHECK` constraints, generated columns other than embeddings, a second `UNIQUE` column,
composite primary keys, multi-column indexes, `DELETE … LIMIT`, savepoints, `DROP TABLE`, views and
triggers. A value an expression builds is at most 1 MB (`group_concat`: 16 MB). A correlated `IN (subquery)` can't be keyed on a UUID column; use `EXISTS` or a join. A table
holds at most 16.7 million rows.

Anything not supported is refused with `SYNTAX` ("unsupported: … is not implemented yet"); nothing is
accepted and then ignored.

### Error codes

Every binding reports errors with a stable code. In Node it is `err.code` on a `SqzError`.

| Code | Meaning |
|---|---|
| `SYNTAX` | The statement can't be parsed or uses something unsupported. |
| `SCHEMA` | No such table, column or role. |
| `TYPE` | A value doesn't fit: the wrong type for its column, operator or function, too long, NULL in a `NOT NULL` column, a division by zero, or a number out of range. |
| `DUPLICATE` | A primary key or `UNIQUE` value already exists. |
| `FOREIGN_KEY` | A referenced row is missing, or a delete is blocked by children. |
| `DENIED` | The session lacks a grant, or a row falls outside its policy. |
| `AUTH` | A wrong login or password, too many failed sign-ins, or a session token that is unknown, signed out, ended or expired. |
| `CONFLICT` | A concurrent transaction changed the same rows; retry. |
| `NOT_FOUND` | An `UPDATE` by primary key found no row, or there is no function by that name. |
| `TRANSACTION` | `BEGIN` inside a transaction, `COMMIT` outside one, or a join, subquery or `INSERT … SELECT` over a table the transaction has written. |
| `ARGUMENTS` | Too few parameters for the statement, or a request the app API can't take: bad JSON, too large, or a result over `app.maxRows`. |
| `PATH` | The path is a file, or a directory that isn't a database. |
| `CONFIG` | An invalid or unknown option. |
| `RATE_LIMITED` | The app API: too many sign-ins or sign-ups from one address; wait a few seconds. |
| `LIMIT` | A function ran longer than `functions.timeout`, or used more than `functions.memory`. |
| `FUNCTION` | A function threw (an Error with a `code` of its own gives that code instead). |
| `CLOSED` | The JavaScript client: the connection closed with the request unanswered. |
| `ERROR` | Anything else. |

## How it works

One process owns a database directory. Every commit is appended to a checksummed log by a writer
thread, and a second thread fsyncs, so concurrent writers share one sync. Tables live in memory as
fixed-width typed rows, so readers need no locks and a row access takes tens of nanoseconds. A snapshot
is written in the tables' own in-memory layout and memory-mapped at startup, so a table reopens in under
a millisecond at any size. Secondary indexes are rebuilt when the database opens, and anything written
since the last snapshot is replayed from the log at about 350 MB/s. The snapshot policy keeps that
replay short: by default it snapshots after 64 MB of log, or the last snapshot's size if larger, and
after 30 seconds without writes. Followers, point-in-time restore, cloud backup and subscriptions are
all readers of that same log.

Other processes never open the files. They connect to the owner over a Unix socket, upgrade to a
shared-memory ring for reads of about 0.6 µs, or connect over TCP with a token.

## Demos

Three apps, each benchmarked against the same app on PocketBase 0.40.5:

- [`demos/notes`](demos/notes): notes with no server code at all. The page signs in and runs SQL through
  the app API, the list is a live query, attachments are a `FILE` column, search by meaning is a
  generated `VECTOR` column, and who sees what is a row policy. It made 8 to 10 times
  PocketBase's writes, answered a read in a quarter of the time, and held 1,000 connected devices in
  48 MB, where PocketBase used 160 to 247 MB.
- [`demos/boards`](demos/boards) (Go): a multi-tenant task board. The tenant rule is a row policy, each
  request runs as the signed-in member, and live updates are one subscription per organization. Against
  PocketBase 0.40.5 it handled 11 to 12 times the card inserts, and live updates took 1 ms instead of 33 ms (p50,
  1,000 browsers).
- [`demos/agents`](demos/agents) (Go): a database per AI agent, created in a quarter of a millisecond, closed
  when idle and forgotten by deleting its directory; also compared with SQLite and Turso at 10,000
  agents. Its README lists where it is behind as well: fixed-width text makes long memories expensive,
  and there is no text or vector search yet.

## Building from source

Requirements: Rust 1.85 or newer, and for the bindings Node 20+, Python 3.11+ or Go 1.24+.

```sh
make                 # the sqzdb command, in target/dist/sqzdb
make test            # the test suite
make install         # build and install the command to ~/.local/bin (PREFIX=… to change)
make node            # bindings/node/sqzdb.node
make python          # bindings/python/sqzdb.so
make go              # the C library, then the Go package
make dist            # a release tarball and its checksum
```

`cargo build --release` builds the engine and the C library, `target/release/libsqzdb.so`. The web
console is the default `ui` feature; build with `--no-default-features` for the smallest library.

## Contributing

- `src/table.rs`: storage, log, snapshots and recovery
- `src/sql.rs`: parser, planner, executor, access control and the change feed
- `src/live.rs`: subscriptions and live queries
- `src/auth.rs`, `src/oauth.rs`: sign-in, sessions and OAuth providers
- `src/app.rs`: the app API for browsers and mobile apps
- `src/tls.rs`: HTTPS, and certificates from Let's Encrypt or another ACME CA
- `src/cloud.rs`: S3 backup, compression and encryption
- `src/net.rs`: the socket, shared-memory ring and TCP server
- `src/config.rs`: options, configuration files and validation
- `src/ui.rs`, `src/ui/index.html`: the web console
- `src/main.rs`: the `sqzdb` command
- `src/capi.rs`: the C ABI
- `src/tenants.rs`: many databases in one process
- `bindings/`: Node, Python and Go
- `clients/js`: the JavaScript client for the app API
- `demos/`: example apps, each with a benchmark against PocketBase

Design decisions are made with benchmarks. The programs in `src/bin/` race sqzdb against SQLite and
Turso on the same machine, one question each; their outputs are in `results/`. They need the `lab`
feature and a system `libsqlite3` with headers: `cargo lab e40_tcp` runs one, and `make lab` builds
them all.

Releases are tags that match the version in `Cargo.toml`, such as `v0.11.0`. The release workflow builds
Linux binaries for glibc and musl on x86_64 and arm64 plus macOS binaries, and publishes them with
`SHA256SUMS` and `install.sh`.

## Project status

sqzdb is experimental and pre-1.0. Expect breaking changes to the file format and the APIs before
1.0, and keep backups of anything that matters.

What changed in each release is in [CHANGELOG.md](CHANGELOG.md).

## License

sqzdb is released under the [MIT License](LICENSE).
