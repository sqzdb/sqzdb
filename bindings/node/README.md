# sqzdb for Node

An embedded SQL database that runs inside your Node process, the way SQLite does. It adds concurrent writers, strict
types, row-level security, live queries, files, vectors, sign-in, and MCP for AI agents. There is no separate server
and nothing to compile: npm installs a prebuilt engine for Linux and macOS (x64 and arm64, glibc and musl).

```sh
npm install sqzdb
```

```js
import { open } from 'sqzdb'

const db = open('./data/app')                 // a directory; created if missing
db.exec('CREATE TABLE IF NOT EXISTS notes (id SERIAL PRIMARY KEY, body TEXT)')
db.run('INSERT INTO notes (body) VALUES (?)', ['hello'])
console.log(db.all('SELECT * FROM notes'))
```

Reads and writes are synchronous: a point read takes well under a microsecond. Promises are used only where there is
real waiting: durability, subscriptions and long scans.

## Serve browsers, phones and agents from the same process

```js
const db = open('./data/app', {
  listen: { app: '0.0.0.0:8081' },
  app: { publicUrl: 'https://api.example.com', signUp: { users: [] }, mcp: {} },
  backup: { endpoint: 'https://<account>.r2.cloudflarestorage.com', bucket: 'my-app', accessKey: '…', secretKey: '…', bootstrap: true },
})
```

- `listen.app` serves the app API from your process: SQL from the browser, live queries, sign-in.
- `app.mcp` serves `/mcp`, so Claude, ChatGPT and Claude Code can connect as a signed-in user.
- `backup` keeps a continuous copy in any S3-compatible bucket. With `bootstrap`, a new machine with an empty disk
  restores itself before it opens.

## In Next.js

- Mark the package external, since a native module can't be bundled: in `next.config.js`, set
  `serverExternalPackages: ['sqzdb']`.
- Open the database once per process, when it is first used, and keep the handle. Development reloads modules, and
  only one handle may own a directory:
  ```js
  // lib/db.js
  import { open } from 'sqzdb'
  export const db = () => (globalThis.__db ??= open(process.env.DB_DIR ?? './data/app'))
  ```
- Make pages that read it dynamic (`export const dynamic = 'force-dynamic'`), so `next build` doesn't prerender them
  and open the database in its build workers.
- Run it on a server that keeps a disk and stays up: `next start` on a VPS, Fly.io, Railway, Render or Docker.
  Serverless platforms such as Vercel and Netlify give each request a fresh, short-lived disk, so they can't host an
  embedded database. There, run sqzdb as its own server and connect to it.

## More

The full guide, SQL reference and configuration: https://github.com/sqzdb/sqzdb#readme
