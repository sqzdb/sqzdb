# Notes: an app with no server code, on sqzdb

A notes app whose only server is sqzdb. The page signs users in, runs SQL as them and keeps its list
current with live queries, all through the [app API](../../README.md#the-app-api-sql-from-the-browser).
Open it in two windows: a note written in one shows up in the other. Attach a picture (or paste one) and it
shows in both: the attachment is a `FILE` column, and the image loads from a signed link the query returned.

The whole backend is [`schema.sql`](schema.sql): two tables, a role and the rule that a note belongs to
its owner.

```sql
CREATE POLICY own ON notes FOR ALL TO member USING (owner = SESSION.id);
```

Every statement from the browser runs under that policy, live queries included. The page's SQL has no
`WHERE owner = ?`, and still sees only the signed-in user's notes:

```js
import { connect } from '/api/client.js'           // the client, served by sqzdb itself
const db = connect(location.origin)
await db.auth.signIn(email, password)
db.live('SELECT id, body, pinned, created FROM notes WHERE body ILIKE ? ORDER BY pinned DESC, created DESC LIMIT 200', [`%${search}%`], render)
await db.sql('INSERT INTO notes (owner, body) VALUES (?, ?)', [db.auth.user.id, body])
```

## Run it

```sh
cargo build --release                                   # or use an installed sqzdb
cd demos/notes
../../target/release/sqzdb shell ./data < schema.sql
../../target/release/sqzdb serve ./data --config notes.toml   # then open http://127.0.0.1:8075
```

[`notes.toml`](notes.toml) turns on the app API, serves [`static/`](static) beside it, and lets anyone
make an account with their email and name. To add **Continue with Google**, uncomment `publicUrl` and the
`[auth.oauth.google]` block there and fill in an OAuth client of yours; the button appears by itself
(`db.auth.methods()` lists the configured providers).

## Search by meaning

Add an embedding of each note, made by the database when a note is written, and point it at a model. Ollama
on this machine (`ollama pull nomic-embed-text`) or OpenAI both work; the column's size is the model's:

```sh
echo "ALTER TABLE notes ADD COLUMN embedding VECTOR(768) GENERATED ALWAYS AS (embed(body)) STORED;" | ../../target/release/sqzdb shell ./data
```

Then uncomment `[embed]` in `notes.toml` and restart. The page notices the column and shows **≈ meaning**
next to the search box: the list becomes the notes nearest to what you type, still live, still only yours:

```sql
SELECT id, body, cosine_distance(embedding, embed(?)) AS d FROM notes WHERE embedding IS NOT NULL ORDER BY d LIMIT 20
```

## Benchmark against PocketBase

[`bench/bench.mjs`](bench/bench.mjs) runs the same workloads against sqzdb and against PocketBase
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

| | sqzdb | PocketBase | PocketBase, log off |
|---|---|---|---|
| Notes created, 32 users writing at once | 47,548/s | 4,972/s | 5,761/s |
| Server CPU per note created | 12 µs | 352 µs | 305 µs |
| Read one note, p50 / p99 | 0.026 / 0.105 ms | 0.112 / 0.367 ms | 0.105 / 0.337 ms |
| List the newest 20, p50 / p99 | 0.039 / 0.111 ms | 0.278 / 0.649 ms | 0.266 / 0.635 ms |
| A note with a 100 KB picture, p50 / p99 | 0.180 / 0.424 ms | 0.617 / 1.055 ms | 0.602 / 1.044 ms |
| Download that picture, p50 / p99 | 0.074 / 0.845 ms | 0.177 / 0.687 ms | 0.182 / 0.568 ms |
| List the newest 20, 32 users at once | 49,868/s on 1 core | 14,435/s on 8.5 cores | 15,089/s on 8.3 cores |
| Write on one device, seen on another, p50 | 0.27 ms | 0.70 ms | 0.67 ms |
| Server memory, 1,000 devices connected | 48 MB | 247 MB | 160 MB |
| Writes while they are connected | 22,431/s | 205/s | 211/s |
| Server CPU for the whole run | 5.9 s | 83.6 s | 81.3 s |
| Data on disk | 31.1 MB | 68.7 MB | 33.5 MB |

What the rows measure, and where they are uneven:

- A sqzdb device holds two live queries: its newest 10 notes and its count, both kept current by the
  server. A PocketBase device holds one subscription to note events, and the app works out the rest.
- In the 32-users-at-once row, sqzdb's server used one core, so the single Node client was the limit
  there.
- A note with a picture is two requests for sqzdb (the upload, then the INSERT, which the JS client does
  for a `File` parameter) and one multipart request for PocketBase. Its download is a signed link for
  sqzdb, and a file token plus the file's URL for PocketBase (both with protected files).
- PocketBase checks the collection rule for every subscriber on every event. That is where its writes
  slow down with 1,000 devices connected.
- Sign-up rates are not compared. Both hash passwords on purpose (sqzdb uses argon2id, 19 MiB, about
  10 ms), and PocketBase also needs a sign-in after sign-up to get a session.
- On both servers, no device saw another user's note.
