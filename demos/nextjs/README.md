# Next.js with sqzdb inside it, and in front of it

A small ai-tasks: a Next.js app (App Router) whose database is sqzdb, embedded in the same Node process. sqzdb
also serves the site. Its app API listens on the public address, answers what is its own (sign-in, the API,
`/mcp`, the app's routes) and passes everything else on to Next.js, which listens on 127.0.0.1 only.

```
browser ──▶ sqzdb :8099 (HTTPS with --domain, HTTP/2) ──▶ Next.js 127.0.0.1:3000
             │ /_sqz/sign-in, /api/…, /mcp, /healthz           │
             │ middleware: /dashboard needs a sign-in           │ db() in pages and actions:
             └──────────────── the database ◀──────────────────┘ the same database, in-process
```

- [`instrumentation.js`](instrumentation.js) opens the database when the server starts, so the front door is
  listening before anyone asks.
- [`lib/db.js`](lib/db.js) opens it once per process, with the proxy settings and the schema.
- [`functions/app.ts`](functions/app.ts) holds the app's rules:
  - a middleware that sends anyone not signed in to sqzdb's sign-in page;
  - `park`, the function that adds a job, with its check;
  - `/healthz`, a route sqzdb answers itself.
- [`app/dashboard/page.js`](app/dashboard/page.js) reads as the signed-in user: the session cookie is the
  database's own (`db().session(cookie)`). Next.js learns who is asking from `X-Sqz-User` and `X-Sqz-Roles`.
  Its server action calls `park` as that user.

## Run it

```sh
npm install
npm run build
npm start               # Next.js on 127.0.0.1:3000; sqzdb in front of it on 127.0.0.1:8099
```

Open http://127.0.0.1:8099/dashboard: you are sent to sign in (or make an account), and back.

For a public server, set `FRONT=0.0.0.0:443` and add `tls: { domains: ['tasks.example.com'] }` to `app` in
[`lib/db.js`](lib/db.js): sqzdb gets and renews the certificate itself.

`clients/js/e68_nextjs.mjs` runs this app end to end (E68).
