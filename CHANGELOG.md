# Changelog

## 0.7.1 — 2026-10-18

**Upgrade from 0.7.0 if you use files, `[embed]` or provider sign-in through the app API.**

### Fixed
- **A sign-up could take someone else's file.** With a `FILE` column listed in `app.signUp`, a client could
  sign up with the id of another user's file (seen in a link, say) and keep it through their own row. A
  sign-up now can't set `FILE` columns; set them once signed in.
- **A request to the embeddings endpoint could stall the app API.** A statement calling `embed()` written so
  the server didn't recognize it (a space before the parenthesis, a comment, a JSON escape) ran on the
  server's async threads while it waited for the model; a few at once could hold up every client. With
  `[embed]` set, every statement now runs on the blocking pool.
- **An API key or client secret could go to another host over plain http.** `embed.url` and OAuth endpoints
  may be http only on this machine, and `http://localhost:80@elsewhere` passed that check. URLs are now
  parsed, and one with a user or password in it is refused.
- The search-text cache kept every text whole, up to a megabyte each; it keeps the hash of the text sent.

## 0.7.0 — 2026-10-18

### Added
- **Files as a column** (`FILE`). A `FILE` column holds an uploaded file; the bytes are kept in the database
  directory's `files/`. Through the app API a browser uploads with `POST /api/files`, and the JS client does
  it for a `File` or `Blob` passed as a SQL parameter (or `db.files.upload`). A query's result gives each
  file as `{ id, name, type, size, url }`, where `url` is a signed link (`app.files.linkTtl`, an hour) with
  ETags and byte ranges. Whoever may read the row may download the file.
- A signed-in user may put a file in a row only if they uploaded it within the hour, or keep the one the row
  has. Files no row refers to are deleted after a day. New settings: `app.files.maxSize`, `app.files.linkTtl`.
- **Vectors** (`VECTOR(n)`), searched with `cosine_distance`, `l2_distance` and `inner_product` (exact, under
  the row policies), plus `vector_dims`. A vector is written as a JSON array, and the app API returns one.
- **Embedding on write.** `VECTOR(n) GENERATED ALWAYS AS (embed(<text expression>)) STORED` is filled in the
  background by an OpenAI-compatible endpoint (`[embed]`: OpenAI, Ollama, llama.cpp …), and filled again when
  the text changes. `embed(?)` in a query embeds the search text, cached.
- `demos/notes` has attachments, pasted or chosen, shown in place when they are images, and search by meaning
  when an embedding column is added.

### Changed
- `ORDER BY … LIMIT k` over many rows finds the first k without sorting them all; the rows are the same.

## 0.6.1 — 2026-10-18

**Upgrade from 0.6.0 if you use provider sign-in through the app API.** Use the client the server serves
(`/api/client.js`), or `clients/js` from this release.

### Fixed
- **A provider sign-in code could be planted in another browser (login CSRF).** Someone could sign in
  with their own provider account, keep the one-time code from their address bar, and send a link to the
  app carrying it. Whoever opened the link was signed in as them, and what they wrote went to that
  account. The code now works only with a verifier the starting tab keeps, as in PKCE.

### Changed
- `auth.signInWith` returns a promise. `GET /api/auth/<table>/oauth/<provider>` requires `challenge` (the
  base64url SHA-256 of the page's verifier), and `POST /api/auth/exchange` requires `verifier`. The client
  does both.

## 0.6.0 — 2026-10-18

### Added
- **The app API: SQL from the browser** (`listen.app`, `sqweezdb serve --app <addr>`). Browsers and mobile
  apps sign up and sign in (password, or a provider through browser redirects) and send SQL that runs as the
  signed-in user, under the row policies. Any `SELECT` can be live over one WebSocket. Clients may send
  `SELECT`, `INSERT`, `UPDATE` and `DELETE`, and transactions as batches. Results are capped by
  `app.maxRows`. Accounts can be made only in the tables `app.signUp` lists, with the columns listed there.
  New settings: `app.origins`, `app.publicUrl`, `app.signUp`, `app.anonymousRole`, `app.maxRows` and
  `app.staticDir`. See the README's "The app API".
- **A JavaScript client** (`clients/js`) for browsers, React Native and Node 22+: `connect(url)`, `auth.signUp`,
  `signIn`, `signInWith`, `signOut`, `onChange`, `methods`, `sql`, `batch`, `live`. The server also serves it
  at `/api/client.js`.
- **`demos/notes`**: a notes app with no server code, and a benchmark of it against PocketBase 0.40.5.
- **HTTPS for the app API, with certificates from Let's Encrypt** (`app.tls`, `sqweezdb serve --domain`). The
  certificate for `app.tls.domains` is requested at start and renewed in the background with a third of its
  lifetime left, as Caddy does. The CA checks the domains over TLS-ALPN-01 on port 443 itself, so port 80 isn't
  needed; `app.tls.redirect` sends plain HTTP on to https. Your own certificate works too (`cert` and `key`),
  and so does another ACME CA (`acme`, `acmeRoot`).
- `sqweezdb serve` raises its open-files limit to the system's hard limit, for many connected users.

### Changed
- `live.debounce` is now the shortest time between two re-runs of a live query, not a wait before each one.
  A change re-runs it at once (about 0.1 ms to another device, was 5 ms), and changes within the next
  `live.debounce` are batched.

### Fixed
- A live query could miss a write that came in just as it re-ran: the write was in the log a moment before
  its row was visible. It was rare with the old 5 ms wait.
- With `durable` on, live queries kept a core partly busy (20% at 100 writes/s) while each commit synced.
- After sign-ins, up to 19 MiB per thread that had hashed a password stayed allocated. Password hashing now
  uses memory of its own and returns it. Stored hashes are unchanged.
- `sqweezdb shell` reading a file: a `--` comment line swallowed the statement after it.

## 0.5.1 — 2026-10-18

**Upgrade from 0.5.0 if you use provider sign-in.** This changes its API (see Changed).

### Fixed
- **A provider sign-in could take over an account with the same email.** In 0.5.0 a first Google or
  GitHub sign-in attached to an existing account with that email if it had no password: an account
  made through another provider, or a row the application inserted itself. A sign-in now never attaches
  to an existing account by email. Its owner signs in and links the provider (`{ link: token }`).
- **A sign-in or a link could be finished in another browser.** The state from `oauthStart` was the
  only check, so an attacker could start a sign-in, or a link to their own account, and get a victim's
  browser to finish it. That logged the victim in as the attacker, or attached the victim's provider
  account to the attacker's account. `oauthStart` now also returns a `cookie` secret, and
  `oauthFinish` requires it back.
- A provider sign-in to one auth table with a provider account linked to a user of another table
  removed that link. It is now refused.

### Changed
- `oauthStart` returns `{ url, state, cookie }`; keep `cookie` in an HttpOnly cookie of that browser.
  `oauthFinish(provider, code, state, cookie)` takes it back. In Python, `oauth_start` returns
  `(url, state, cookie)` and `oauth_finish` takes `cookie`. In Go, `OAuthStart` returns the cookie and
  `OAuthFinish` takes it. In C, `sqweezdb_oauth_finish` takes it as its last argument.

## 0.5.0 — 2026-10-18

### Added
- **Sign-in with Google, GitHub and other OpenID Connect providers.** Configure `auth.oauth.google`,
  `auth.oauth.github`, or any provider by its endpoints. `db.auth('users').oauthStart(provider,
  redirectUri)` gives the URL to send the browser to, and `oauthFinish(provider, code, state)` returns a
  session, like `signIn`. The engine makes a single-use state, a PKCE challenge and a nonce. It checks
  Google's ID tokens (signature, issuer, audience, expiry, nonce, verified email) and needs a verified
  primary email from GitHub. A first sign-in makes a user whose login is that email, and later ones find
  the user by the provider's account id. An account that has a password is linked only by its owner,
  while signed in (`{ link: token }`). In Python, `oauth_start` and `oauth_finish`; in Go,
  `Auth.OAuthStart` and `Auth.OAuthFinish`.
- Sign-in results include `created`: true when this sign-in made the user.
- Go: `Options.Auth` for `sessionTtl`, `passwordMin` and `oauth`.

## 0.4.2 — 2026-10-17

### Fixed
- **A sign-out could fail to end a session that was running a statement at that moment.** The sign-in
  state counter moved when the sign-out was logged, before it was visible. A session that checked its
  token in between could record the new count against the old rows and never check again. The counter
  now moves only once a write is visible. A test signs out 300 times while another thread keeps
  querying through the session. On 0.4.1 it fails in the first round, with the database writing to
  disk on every commit.

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
