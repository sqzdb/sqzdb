# Notes: an app with no server code, on sqweezdb

A notes app whose only server is sqweezdb. The page signs users in, runs SQL as them and keeps its list
current with live queries, all through the [app API](../../README.md#the-app-api-sql-from-the-browser).
Open it in two windows: a note written in one shows up in the other.

The whole backend is [`schema.sql`](schema.sql): two tables, a role and the rule that a note belongs to
its owner.

```sql
CREATE POLICY own ON notes FOR ALL TO member USING (owner = SESSION.id);
```

Every statement from the browser runs under that policy, live queries included. The page's SQL has no
`WHERE owner = ?`, and still sees only the signed-in user's notes:

```js
import { connect } from '/api/client.js'           // the client, served by sqweezdb itself
const db = connect(location.origin)
await db.auth.signIn(email, password)
db.live('SELECT id, body, pinned, created FROM notes WHERE body ILIKE ? ORDER BY pinned DESC, created DESC LIMIT 200', [`%${search}%`], render)
await db.sql('INSERT INTO notes (owner, body) VALUES (?, ?)', [db.auth.user.id, body])
```

## Run it

```sh
cargo build --release                                   # or use an installed sqweezdb
cd demos/notes
../../target/release/sqweezdb shell ./data < schema.sql
../../target/release/sqweezdb serve ./data --config notes.toml   # then open http://127.0.0.1:8075
```

[`notes.toml`](notes.toml) turns on the app API, serves [`static/`](static) beside it, and lets anyone
make an account with their email and name. To add **Continue with Google**, uncomment `publicUrl` and the
`[auth.oauth.google]` block there and fill in an OAuth client of yours; the button appears by itself
(`db.auth.methods()` lists the configured providers).

## Benchmark against PocketBase

[`bench/bench.mjs`](bench/bench.mjs) runs the same workloads against sqweezdb and against PocketBase
0.40.5 set up the same way. Users sign up through the public API, notes are restricted to their owner
(a policy here, `owner = @request.auth.id` collection rules there), and `notes.owner` is indexed in both.
Both servers run on the same machine with data on the same disk, and the same Node client drives them
(keep-alive HTTP, one connection per user). PocketBase runs twice: as it comes, and with its request log off.

```sh
cargo build --release && node demos/notes/bench/bench.mjs [--users 200] [--notes 50] [--devices 1000]
```

It expects the PocketBase 0.40.5 binary from its [releases](https://github.com/pocketbase/pocketbase/releases)
at `tools/pocketbase-0.40.5/pocketbase`, or pass `--pocketbase <path>`.

On a 12-core Linux machine, 200 users with 50 notes each and 1,000 connected devices
([`results/e59_notes_vs_pocketbase.txt`](../../results/e59_notes_vs_pocketbase.txt)):

| | sqweezdb | PocketBase | PocketBase, log off |
|---|---|---|---|
| Notes created, 32 users writing at once | 38,941/s | 5,774/s | 8,364/s |
| Server CPU per note created | 16 µs | 367 µs | 317 µs |
| Read one note, p50 / p99 | 0.029 / 0.137 ms | 0.128 / 0.399 ms | 0.118 / 0.348 ms |
| List the newest 20, p50 / p99 | 0.048 / 0.116 ms | 0.321 / 0.763 ms | 0.286 / 0.675 ms |
| List the newest 20, 32 users at once | 46,453/s on 1 core | 13,155/s on 8 cores | 13,951/s on 8 cores |
| Write on one device, seen on another, p50 | 0.37 ms | 0.79 ms | 0.75 ms |
| Server memory, 1,000 devices connected | 42 MB | 251 MB | 158 MB |
| Writes while they are connected | 24,593/s | 187/s | 180/s |
| Server CPU for the whole run | 6.4 s | 84.0 s | 82.8 s |
| Data on disk | 11.1 MB | 40.1 MB | 12.0 MB |

What the rows measure, and where they are uneven:

- A sqweezdb device holds two live queries: its newest 10 notes and its count, both kept current by the
  server. A PocketBase device holds one subscription to note events, and the app works out the rest.
- In the 32-users-at-once row, sqweezdb's server used one core, so the single Node client was the limit
  there.
- PocketBase checks the collection rule for every subscriber on every event. That is where its writes
  slow down with 1,000 devices connected.
- Sign-up rates are not compared. Both hash passwords on purpose (sqweezdb uses argon2id, 19 MiB, about
  10 ms), and PocketBase also needs a sign-in after sign-up to get a session.
- On both servers, no device saw another user's note.
