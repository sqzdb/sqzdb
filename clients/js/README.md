# @sqzdb/client

The browser client for a [sqzdb](https://github.com/sqzdb/sqzdb) app API. It signs users in, sends SQL that runs
as the signed-in user under the database's row policies, keeps live queries current over one WebSocket, uploads
files, and calls the app's functions. It runs in browsers, React Native and Node 22+, and has no dependencies.

The same file is served by every sqzdb at `<api>/api/client.js`, for pages with no build step.

```sh
npm install @sqzdb/client
```

```ts
import { connect } from '@sqzdb/client'

const db = connect('https://api.example')                 // the server's app API (--app)

await db.auth.signInWith('google')                        // or signUp({ email, name }, password), signIn(email, password)
await db.sql('INSERT INTO posts (author, title) VALUES (?, ?)', [db.auth.user!.id, 'Hello'])
const live = db.live('SELECT id, title FROM posts ORDER BY created DESC', (rows) => render(rows))   // now, and on every change
await db.call('deleteComment', { id })                    // one of the app's functions, as this user
live.close()
```

- `connect(url, { users, storage, cookies })`: `users` is the sign-in table (`users` by default); `storage` where the
  session is kept (`localStorage` by default, `null` for none); `cookies: true` keeps the session in the API's HttpOnly
  cookie instead, for a page the API serves itself.
- `db.auth`: `signUp`, `signIn`, `signInWith(provider)`, `signInWithDevice`, `signOut`, `onChange(fn)`, `user`, and
  `methods()` (whether sign-up is open, which providers exist, whether a password signs in at all).
- `db.sql(text, params)`, `db.batch([...])` for one transaction, `db.live(text, params, fn)`, `db.call(name, args)`,
  `db.files.upload(blob)`, `db.close()`.
- Errors are `SqzError`s with a `code`: `AUTH`, `DENIED`, `NOT_FOUND`, `ARGUMENTS`, `RATE_LIMITED` and the rest.

The server side, the rules and the full reference are in the
[sqzdb README](https://github.com/sqzdb/sqzdb#the-app-api-sql-from-the-browser).
