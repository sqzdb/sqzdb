# Changelog

## 0.14.0 — 2026-10-20

### Added
- **Set up sign-in, in the console.** The Access tab opens with the state of sign-in, and when nothing is set
  up, a guided step: a new users table (or one of yours, with its login column found), the `member` and `admin`
  roles, who may create an account (open, or invite only), what a member may do with their own row, and
  providers, with the SQL and the setting it generates shown before they run. Once set up, the card shows the
  sign-in page's address, the client snippet to sign up and in, and creates test accounts
  (`POST /api/auth/sign-up` on the console).
- **A function says how it is reached.** `method: 'GET'` lets `fn()` answer `GET /api/fn/<name>?arg=value` as well
  as POST, the arguments read from the query string as `args` says; a GET function is read-only. `mcp: false` keeps
  a function off the agents' tool list. A function given a `path` is refused with a pointer to `route()`.
- **The Functions tab says what each export is.** New offers a function, a REST route or a middleware, each template
  with its fields explained; the Exports list and the bar beside the open file show where each export is reached
  (`POST /api/fn/hello`, `GET /jobs/:id`, the paths a middleware runs before) and whether agents get it.

### Fixed
- **MCP on this machine needed `app.publicUrl`.** When the app server listens on 127.0.0.1, localhost or [::1], the
  public address is now that address, so agents and sign-in links work locally with nothing set. The Settings tab
  shows, under the Agents (MCP) switch, the address agents will connect at as the form stands, or what is missing
  for one, before you save; the app server's listen address is a field there too.

### Changed
- **The Settings tab says what each setting is.** Its sections are named for what they do (the app server, the
  HTTPS certificate) rather than for their flags, each opens with a plain description, and every field has one.
  The form gains the fields that explain the app server: your app behind it (the reverse proxy) and a static
  files folder, and under HTTPS your own certificate and key as the alternative to Let's Encrypt.
- **The npm engines are built like the command** (thin LTO, one codegen unit), from the same compilation: a
  release builds the crate once per target, and runs the unit tests before publishing anything.

## 0.13.1 — 2026-10-20

### Fixed
- **Security: a user could move themselves to another tenant.** Only the role column of a sign-in table was the
  application's alone. A user allowed to edit their own row could set any other column, and a policy that read it
  as `SESSION.tenant_id` then showed them that tenant's rows. Now every column a policy reads as `SESSION.<column>`
  is set only by the application too: an update or upsert that sets one is refused, and an insert may leave it as
  it defaults or give the new row what the user has themselves. The console's Sign-in tables card lists these
  columns.

## 0.13.0 — 2026-10-19

### Added
- **The console's Settings tab.** It covers the server's whole configuration, one section at a time from a
  menu that shows what is on and what isn't saved:
  - forms for the public address, sign-up tables, origins, HTTPS, sign-in and Google/GitHub, agents over MCP,
    backup (and when a commit counts as confirmed) and the functions' limits;
  - the whole file as text, for anything else.

  With backup off, the Backup tab's **Set up backup** opens it there, instead of a file to copy.
- **Taking access back:** `REVOKE … ON table FROM role`, `DROP POLICY name ON table`, `DROP USER name`, and
  `DROP ROLE name`. A role can be dropped once nothing uses it; the error lists what still does.
- **The console's Change access builder,** in the Access tab. Choose an action: create a role, grant, limit a
  role to some rows, let users sign in to a table, create a stored user, or the removals above. Pick from the
  roles, tables and columns that exist. It shows the statement and what it does in plain words, and warns when
  something is missing (a policy on a table its role has no grant on). Run it there or open it in the editor.

  A save is checked as the server would start with it, and keeps the file's comments. Secrets show only as set
  or not, in the form and in the file's text, where saving keeps them as they were. Changing where a secret is
  sent (an endpoint or a URL) needs it typed again as a value, and a save can't add a `${VAR}` reference or move
  one to another key: those are added in the file on the server. Errors name the key and the line, never a value, and a file that doesn't
  parse isn't shown. **Restart now** applies the settings in place (same process, same console token). It is refused while
  the file would keep the server from starting.
- **`sqzdb serve` without `--config` uses `<dir>/sqzdb.toml`,** the file the Settings tab writes, with mode 600.
  It must belong to the user sqzdb runs as and be writable by no one else, or the server won't start. It is read
  through the handle that was checked, and a link is not followed. Backups never carry it.

### Fixed
- **Security: a signed-in user could make themselves admin.** With `ENABLE AUTH (ROLE FROM role)` and a grant
  letting users edit their own row (`GRANT UPDATE ON users` plus a policy on `SESSION.id`), `UPDATE users SET
  role = 'admin'` worked, and their next request ran as admin. Sign-up never let a client set the role column;
  now nothing does but the application. An update or upsert that sets it is refused for a signed-in user or an
  assumed identity, and so is an insert with any role but the column's default. In a function, `ctx.admin` sets
  it.
- **Live queries and subscriptions kept the access rules they started with.** A new policy, or a grant taken
  back, didn't reach a change subscription already open. Now any change to roles, grants, policies, users or
  sign-in tables ends those of identities, and their clients subscribe again under the new rules. One being
  set up while the rules change is compiled again under the new ones.
- A settings file that opens the console (`listen.http`) or a TCP port without `listen.token` stopped the
  server. A token is now generated and printed, as with `--ui`.

## 0.12.0 — 2026-10-19

**A standalone sqzdb is a whole backend.** Write the app's functions in the web console, and agents connected
over MCP see the new tools at once. CLIs and servers sign in as their user with a code.

### Added
- **The console's Functions tab:**
  - write, paste or upload `.ts` and `.js` files, and deploy them (Ctrl+S). A failed deploy names the file,
    line and column, and changes nothing;
  - see each export: functions (as MCP tools), middleware and routes, their arguments and roles;
  - call a function with JSON arguments, as the app or as a role with attributes.

  When the server deploys a folder (`--functions`), the tab shows its files read-only.
- **MCP's event stream:** `GET /mcp` with `Accept: text/event-stream`. When a deploy changes the tools an
  agent may call, or its user's roles change, the agent gets `notifications/tools/list_changed` and lists them
  again. `initialize` now says `listChanged: true`.
- **Device login** (RFC 8628) for programs without a browser of their own:
  - `POST /api/auth/device` gives a code, which the user types at `/_sqz/device` in a browser where they're
    signed in. The page shows the device's name, address and age. The code is never carried in a link, against
    device-code phishing;
  - **Allow** gives the program a session of its own, which it gets by polling `POST /api/auth/device/token`;
  - in the browser client, `auth.signInWithDevice({ name, onCode })` does all of it.

## 0.11.1 — 2026-10-19

### Added
- **`LIMIT ?` and `OFFSET ?`.** Both take parameters, so one prepared statement serves every page. A NULL limit
  means no limit, and a NULL offset none. Before, they took only numbers written in the query.

### Fixed
- **sqzdb's sign-in page signed no one in from a browser.** Its pages sent `Referrer-Policy: no-referrer`, under
  which browsers post forms with `Origin: null`, and the page took that for another site. Its pages now send
  `same-origin`. A session cookie also counts with `Origin: null` when the browser's `Sec-Fetch-Site` says the
  request comes from the same origin (a page of the app's with `no-referrer`). Any other null origin is still
  refused.
- **A live query without the primary key in its result kept rows that stopped matching.** For example,
  `SELECT job_id FROM runs WHERE status = 'working'`, or a count by group, kept a run that had finished. Such a
  query now re-runs on any update to its table.

## 0.11.0 — 2026-10-19

**Functions: an app's rules in the database.** You write them in TypeScript or JavaScript, in a folder of your
app. The database strips the types, keeps the code in its catalog, and runs it in QuickJS, one transaction per
call, as the caller. Clients call a function by name:
- `db.call` in Node, `call` in Python, Go and C;
- `client.call` or `POST /api/fn/<name>` from a browser;
- MCP, where each function is a tool.

### Added
- Functions (see the README's guide):
  - **Deploying:** a folder deploys at open (the `functions` option, `[functions] dir`, `sqzdb serve
    --functions`) and again whenever it changes. `sqzdb deploy <folder> <dir | host:port>` deploys from the
    command line, and the application can send `DEPLOY FUNCTIONS` as a statement. A deploy replaces the one
    before it and travels with the catalog: logs, snapshots, backups, followers.
  - **Who acts:** `ctx.db` acts as the caller, under their grants and row policies. `ctx.admin` acts as the
    app, in the same transaction, for rules a caller must not get around.
  - **Checks:** arguments are checked against `args` before the function runs; `roles` says who may call;
    `readOnly` allows reads only.
  - **Errors** carry codes: the function's own, the database's, `LIMIT` and `FUNCTION`. A bug points at the
    line of the TypeScript.
  - **Limits:** `functions.timeout` (1 s), `functions.memory` (64 MB), `functions.instances`.
  - **Types:** `sqzdb/functions` in the npm package gives `fn()`, with types that work out each function's
    arguments from `args`.
- `app.mcp.sql = false`: agents get the app's functions and no SQL tools.
- **sqzdb in front of your app** (`app.proxy`, `sqzdb serve --proxy`): requests that aren't sqzdb's own go on to
  your app's server, such as Next.js on 127.0.0.1. The proxy:
  - streams bodies both ways;
  - passes WebSocket upgrades through, and no other kind (no `h2c` tunnel around middleware);
  - keeps a pool of connections to the app, with at most `app.proxy.connections` requests in flight;
  - tells the app who asked: `X-Forwarded-*` and `X-Real-IP`, and for a signed-in visitor `X-Sqz-User`,
    `X-Sqz-Table` and `X-Sqz-Roles` (a client's own `X-Sqz-*` headers are dropped);
  - shows a 502 page while the app is down, and a 503 when it's busy.
  `demos/nextjs` is a Next.js app with sqzdb embedded and in front of it.
- **Sessions in a cookie**, for a site sqzdb serves: `__Host-sqz_session` over https (Secure, this host only),
  `sqz_session` over http; HttpOnly and SameSite=Lax either way. Node's `db.sessionCookie` gives the name.
  - the API takes the cookie wherever it takes a token, from the site's own origin or one `app.origins` names
    (`"*"` doesn't count);
  - sign-in, sign-up and the code exchange set it with `"cookie": true`, and a provider sign-in with `?cookie=1`;
  - sqzdb serves its own sign-in and sign-out pages at `/_sqz/sign-in` and `/_sqz/sign-out`;
  - the browser client has a cookie mode, `connect(location.origin, { cookies: true })`.
- **Middleware and routes**, in the functions folder:
  - `middleware({ match, run })` runs before requests to the paths it matches go on, and can answer them or
    set their headers;
  - `route({ method, path, run })` answers requests itself;
  - both get the visitor and the database, one transaction per request, at most `functions.instances` at once;
  - paths are matched decoded, as the app will resolve them, and `req.path` is that path (`req.rawPath` as
    sent); dot segments and encoded slashes are refused;
  - if the deployed functions don't load, everything but sqzdb's own paths gets a 503 until they do, so the
    site is never served without its guards.
- `app.trustProxy`: proxies of yours in front of sqzdb; from them, the client's address is the last one in
  `X-Forwarded-For` that isn't theirs, so the sign-in limits count visitors, not the proxy. From anyone else
  `X-Forwarded-For` isn't believed, and `Forwarded` is dropped.

### Fixed
- **A transaction's reads other than by key were never checked at commit.** Two transactions could each count
  rows, write, and both commit, each acting on a count the other had changed. For example, two runs of a job
  end together, each sees one still running, and the job never moves on. Updates read by a `UNIQUE` value could
  also be lost. Now a table read by a scan, an index, a range or a `UNIQUE` value makes the commit fail with
  `CONFLICT` if any other write to that table became visible since, or is on its way. Retry as for any
  conflict: `db.transaction` in Node and functions do it themselves. The check is per table, so concurrent
  writers to a table that transactions scan conflict more often than before.
- A batch from the app API whose sign-in ended while it ran left its transaction open on a socket session.
- In Python, a session's state is now marked busy, not the unrestricted application session, while a call on
  it runs with the GIL released.

### Changed
- **The app API speaks HTTP/2** (over TLS, as the browser chooses; HTTP/1.1 stays). It now runs on hyper. It
  answers a request body over `app.maxRequest` with 413 instead of closing the connection. A connection that
  sends nothing for 10 s, has nothing in flight for 60 s, or stops reading for 60 s is closed.
- **A transaction reads its own writes.** A query on one table, and the rows an `UPDATE` or `DELETE` picks,
  now see what the transaction wrote. Before, any read of a written table other than by primary key failed with
  `TRANSACTION`. Joins, subqueries and `INSERT … SELECT` over a written table still fail that way.
- The command and the libraries are about 4 MB larger (QuickJS, and oxc to strip TypeScript).

## 0.10.0 — 2026-10-18

**sqweezdb is now sqzdb** (https://sqzdb.dev, https://github.com/sqzdb/sqzdb). What changed:
- the command is `sqzdb`;
- the crate and npm package are `sqzdb`, the engines `@sqzdb/<platform>`, the Python module `sqzdb`, the Go
  package `github.com/sqzdb/sqzdb/bindings/go/sqzdb`;
- the C library is `libsqzdb` with `sqzdb_*` functions;
- the installer's variables are `SQZDB_*`;
- the JavaScript error class is `SqzError`.

Databases open as they are: a directory marked `sqweezdb.meta` keeps that marker, and new ones get `sqzdb.meta`.
The old GitHub URLs redirect. After installing, remove the old command (the installer says where it is). The
installer's `SQWEEZDB_*` variables still work. To install a release from before the rename, use that release's
`install.sh`.

### Fixed
- **A loopback redirect could be sent elsewhere.** An agent registered with `http://localhost/…` could ask
  for `http://localhost:@evil.example/…`, which matched by port but took the browser, and the code, to
  `evil.example`. Loopback redirect URIs are now parsed strictly.
- **A policy could pass a row it should refuse.** A `<`, `<=`, `>` or `>=` policy on a long `TEXT` value
  was let through for a row being written, when the value sat behind another long value in that row. It is
  compared now.
- The limit on sign-ins in progress counts an IPv6 client by its /64.
- The test of large values through the shared-memory ring runs on Linux only (macOS has no /dev/shm).

### Added
- The Node package can be installed from npm (`npm install sqzdb`), with a prebuilt engine for Linux and
  macOS, x64 and arm64, glibc and musl, as `@sqzdb/<platform>` optional dependencies. The release
  workflow builds and smoke-tests them on each tag, and publishes them when the repository has an
  `NPM_TOKEN` secret. The package's types cover the app API, MCP, sign-in and embeddings options.

## 0.9.0 — 2026-10-18

**`TEXT` without a length now means text of any length.** In tables made before this version, `TEXT`
columns stay `TEXT(255)`; a column added or a table made from now on gets the new kind. A database opened
by this version can't be opened by an older one once it runs a `CREATE` or `ALTER`.

### Added
- **Text and bytes of any length.** `TEXT` and `BYTES` (also `VARCHAR`, `CLOB`, `BLOB`, `BYTEA`) hold
  values up to 16 MB. A value of up to 44 bytes stays in its row (64 bytes of row, where `TEXT` took 257);
  a longer one is kept beside it. Such a column can be a key, `UNIQUE`, indexed, joined and referenced,
  like `TEXT(n)`, which keeps its meaning. The log, change feeds, live queries, backups and followers
  carry whole values. A value replaced or deleted is freed once no statement can still be reading it.
  After a restart, values stay in the snapshot's mapping until read.
- **Agents over MCP** (`[app.mcp]`). Claude, ChatGPT, Claude Code and other MCP clients connect to
  `/mcp` and act as a user who signed in, under that user's grants and row policies. They get three tools:
  `describe`, `query` (SELECT) and `execute` (INSERT, UPDATE, DELETE). The app API is their OAuth 2.1
  server, per the MCP authorization spec:
  - discovery metadata and dynamic client registration;
  - a sign-in page (password or `auth.oauth` providers) with a consent step;
  - PKCE (S256), tokens bound to `/mcp`, and refresh tokens that rotate.

  A refresh token used twice ends the sign-in, and a sign-in lasts at most 90 days. A password change
  or sign-out everywhere ends an agent's access. New settings: `app.mcp.users`, `tokenTtl`, `grantTtl`,
  `maxRows`. The official TypeScript SDK's client connects end to end (E65).
- A provider sign-in's `return` may no longer point into `/oauth/`, except at a sign-in in progress.
- The sign-in rate limit counts an IPv6 client by its /64.
- `app.maxRequest` (default `8MB`): the largest request body or WebSocket message a client may send. It
  was a fixed 1 MB.

### Fixed
- A process connected through a Unix socket (the shared-memory ring) got a result over 1 MB cut short,
  and couldn't send a request over 1 MB. Both now go through the ring in pieces.
- Reading text is faster: a 4 MB value takes 0.1 ms instead of 0.8 ms. It was checked for UTF-8 the slow
  way.

## 0.8.1 — 2026-10-18

### Fixed
- **A file altered in the backup bucket could be restored as the real one.** Someone with write access to
  the bucket, without the passphrase, could move one file's object over another's, cut off its end, or put
  up an unencrypted object in its place. A bootstrap would then restore that as the file. Every file fetched
  from the bucket is now checked against the SHA-256 recorded when it was uploaded. One that differs is
  refused and reported, and the other files are restored. With a passphrase set, an unencrypted file object
  is refused, and replaced by an encrypted copy when the database still has the file.
- **Closing the database dropped file uploads still waiting.** Files uploaded just before a shutdown
  reached the bucket only at the next start. Closing now finishes them first, as it does for the log,
  unless the bucket fails.

## 0.8.0 — 2026-10-18

### Added
- **Uploaded files are in the backup.** With `[backup]` set, each file a `FILE` column holds is uploaded to
  the bucket as it arrives (`files/<id>`), encrypted with the backup's passphrase. It is compressed only
  when that helps, and streamed in parts, so a large file is never in memory whole. A file the cleanup
  deletes is deleted from the bucket too. A bootstrap from the bucket brings the files back with the rows.
- When a database with a backup opens, it compares its files with the bucket's. It uploads what the
  bucket lacks (files from before the backup was set up), fetches back files missing from the directory,
  and deletes objects of files it no longer has.
- With `durable = "cloud"`, an upload returns once its file is in the bucket.
- The console's Backup tab shows the files: uploaded, waiting, deleted, fetched back.
- `Sql::backup` and `Sql::restore` copy the files too (as hard links when they can).

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
