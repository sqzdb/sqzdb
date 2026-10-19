// E67: the app API in front of an app (app.proxy). The app here is a stand-in for Next.js: a Node server with pages,
// a page that streams, its own /api route, an upload, cookies, a WebSocket. Checked: what reaches the app and what the
// API keeps, streaming both ways, the connection pool, WebSockets through, HTTP/2 from the client, the app being down,
// and app.trustProxy. Costs: a page through the API against the app directly. Then the edges: guards that check
// req.path however the path is written, only WebSockets upgraded, cookies that aren't UTF-8 or come split (HTTP/2), a
// silent connection closed, the app's slots full, and the site refused (503) when the deployed functions don't load.
import { spawn, execFileSync } from 'node:child_process';
import fs from 'node:fs'; import http from 'node:http'; import http2 from 'node:http2'; import net from 'node:net'; import crypto from 'node:crypto';
import assert from 'node:assert/strict';

const BIN = new URL('../../target/release/sqzdb', import.meta.url).pathname;
const dir = new URL('../../data/nocow/e67', import.meta.url).pathname; fs.rmSync(dir, { recursive: true, force: true });
const freePort = () => new Promise((r) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
const [port, appPort, hubPort] = [await freePort(), await freePort(), await freePort()];
const base = `http://127.0.0.1:${port}`, direct = `http://127.0.0.1:${appPort}`;
const pr = (label, v) => console.log(label.padEnd(64), v);

// ---- the app's own code in the API: middleware and routes
const fns = `${dir}-functions`; fs.rmSync(fns, { recursive: true, force: true }); fs.mkdirSync(fns, { recursive: true });
fs.writeFileSync(`${fns}/http.ts`, `import { middleware, route, signIn } from 'sqzdb/functions'
export const guard = middleware({ match: ['/dashboard/*'], run({ user }, req) {
  if (!user) return signIn(req)
  req.headers.set('x-plan', 'pro')
} })
export const adminOnly = middleware({ match: '/admin/*', run({ roles }) { if (!roles.includes('admin')) return new Response('Forbidden', { status: 403 }) } })
export const passing = middleware({ match: '/timed/*', run() {} })
// as the README's guard checks it: by req.path, which is the path the patterns matched (decoded)
export const staff = middleware({ match: ['/staff/*', '/team/*'], run({ roles }, req) {
  if (req.path.startsWith('/staff') && !roles.includes('admin')) return new Response('Forbidden', { status: 403 })
} })
export const echo = route({ path: '/echo/*', run: (_, req) => ({ path: req.path, rawPath: req.rawPath, url: req.url, rest: req.params['*'], cookies: req.cookies, cookie: req.headers.get('cookie') }) })
// (fine here; with app.mcp, /oauth/… is the API's own, and these functions no longer load)
export const done = route({ path: '/oauth/done', run: () => 'done' })
export const hook = route({ method: 'POST', path: '/hooks/:source', async run({ admin }, req) {
  const e = await req.json()
  admin.run('INSERT INTO hooks (source, body) VALUES (?, ?)', [req.params.source, JSON.stringify(e)])
  return Response.json({ ok: true, source: req.params.source, stored: admin.get('SELECT count(*) AS n FROM hooks').n }, { status: 201 })
} })
export const hello = route({ path: '/hello', run: ({ user }, req) => ({ hello: user?.email ?? 'stranger', q: req.query.q ?? null }) })
`);
// ---- the app
let sockets = 0, wsUpgrades = 0; const seen = [];
const app = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x'); seen.push(u.pathname);
  // (/timedx: the same page as /timed/x, which no middleware matches)
  if (u.pathname.startsWith('/dashboard') || u.pathname.startsWith('/timed')) { res.setHeader('content-type', 'application/json'); return res.end(JSON.stringify(req.headers)); }
  if (u.pathname === '/') { res.setHeader('content-type', 'text/html'); return res.end('<h1>home</h1>'); }
  if (u.pathname === '/headers') { res.setHeader('content-type', 'application/json'); return res.end(JSON.stringify(req.headers)); }
  if (u.pathname === '/stream') { res.write('first part\n'); await new Promise((r) => setTimeout(r, +(u.searchParams.get('ms') ?? 400))); return res.end('second part\n'); }
  if (u.pathname === '/cookies') { res.setHeader('set-cookie', ['a=1; Path=/', 'b=2; Path=/']); return res.end('ok'); }
  if (u.pathname === '/api/hello') return res.end('the app\'s own /api route');
  if (u.pathname === '/upload') { let n = 0; const h = crypto.createHash('sha256'); for await (const c of req) { n += c.length; h.update(c); } return res.end(JSON.stringify({ n, sha: h.digest('hex') })); }
  res.statusCode = 404; res.end('no such page');
});
app.on('connection', () => sockets++);
// a WebSocket that echoes text frames back (enough of RFC 6455 for short messages)
app.on('upgrade', (req, sock) => {
  wsUpgrades++;
  const accept = crypto.createHash('sha1').update(req.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  sock.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
  sock.on('data', (b) => {
    const len = b[1] & 0x7f, mask = b.subarray(2, 6), data = Buffer.from(b.subarray(6, 6 + len)).map((x, i) => x ^ mask[i % 4]);
    if ((b[0] & 0x0f) === 1) sock.write(Buffer.concat([Buffer.from([0x81, data.length]), Buffer.from(data)]));
  });
});
await new Promise((r) => app.listen(appPort, '127.0.0.1', r));
// a provider shaped like GitHub: its sign-in page approves at once, then a code, a token, the user and their email
const hub = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x'); const send = (v) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(v)); };
  if (u.pathname === '/authorize') { res.writeHead(302, { location: `${u.searchParams.get('redirect_uri')}?code=hub-code&state=${u.searchParams.get('state')}` }); return res.end(); }
  if (u.pathname === '/token') { req.resume(); return req.on('end', () => send({ access_token: 'hub-token', token_type: 'bearer' })); }
  if (u.pathname === '/user') return send({ id: 4242, login: 'octo' });
  if (u.pathname === '/emails') return send([{ email: 'octo@hub.test', primary: true, verified: true }]);
  res.statusCode = 404; res.end();
});
await new Promise((r) => hub.listen(hubPort, '127.0.0.1', r));
const hubUrl = `http://127.0.0.1:${hubPort}`;

const toml0 = `[app]\npublicUrl = "${base}"\norigins = ["*"]\nproxy = "${direct}"\ntrustProxy = ["127.0.0.1"]\n\n[app.signUp]\nusers = []\n\n[auth.oauth.hub]\nkind = "github"\nclientId = "e67"\nclientSecret = "e67-secret"\nauthUrl = "${hubUrl}/authorize"\ntokenUrl = "${hubUrl}/token"\nuserUrl = "${hubUrl}/user"\nemailsUrl = "${hubUrl}/emails"\n\n[functions]\ndir = "${fns}"\n`;
fs.writeFileSync(`${dir}.toml`, toml0);
execFileSync(BIN, ['shell', dir], { input: ["CREATE TABLE users (id SERIAL PRIMARY KEY, email TEXT UNIQUE, role TEXT DEFAULT 'member');", 'CREATE ROLE member;', 'ALTER TABLE users ENABLE AUTH (ROLE FROM role);', 'GRANT SELECT ON users TO member;', 'CREATE POLICY me ON users FOR ALL TO member USING (id = SESSION.id);', 'CREATE TABLE hooks (id SERIAL PRIMARY KEY, source TEXT, body TEXT);', ''].join('\n'), stdio: ['pipe', 'ignore', 'ignore'] });
let server = spawn(BIN, ['serve', dir, '--app', `127.0.0.1:${port}`, '--config', `${dir}.toml`], { stdio: ['ignore', 'pipe', 'inherit'] });
let banner = ''; await new Promise((r) => server.stdout.on('data', (d) => { banner += d; if (banner.includes('proxy:')) r(); }));
pr('banner', banner.match(/proxy: +(.*)/)[1]);

// a request sent as written (fetch would fix the path and refuse some headers), its status and JSON (if it is)
const rawGet = (path, headers = {}) => new Promise((ok, no) => http.get({ host: '127.0.0.1', port, path, headers }, (x) => { const b = []; x.on('data', (d) => b.push(d)); x.on('end', () => { let json; try { json = JSON.parse(Buffer.concat(b)); } catch {} ok({ status: x.statusCode, json }); }); }).on('error', no));
// a connection that never sends a byte: how long the server keeps it
const silent = new Promise((ok) => { const t = Date.now(); net.connect(port, '127.0.0.1').on('close', () => ok(Date.now() - t)).on('error', () => {}); });

try {
  // what reaches the app, and what the API keeps
  assert.equal(await (await fetch(`${base}/`)).text(), '<h1>home</h1>');
  assert.equal(await (await fetch(`${base}/api/hello`)).text(), "the app's own /api route", 'an /api path the API does not have goes to the app');
  assert.equal((await (await fetch(`${base}/api/me`)).json()).code, 'AUTH', 'the API keeps its own');
  assert.match(await (await fetch(`${base}/api/client.js`)).text(), /export function connect/);
  assert.equal((await fetch(`${base}/nope`)).status, 404);
  // headers: who asked, the client's own X-Sqz-… dropped, cookies, two Set-Cookie back
  let h = await (await fetch(`${base}/headers?x=1`, { headers: { 'x-sqz-user': 'admin', cookie: 'k=v', 'x-forwarded-for': '203.0.113.5' } })).json();
  assert.equal(h['x-sqz-user'], undefined); assert.equal(h.cookie, 'k=v'); assert.equal(h.host, `127.0.0.1:${port}`); assert.equal(h['x-forwarded-proto'], 'http');
  assert.equal(h['x-forwarded-for'], '203.0.113.5, 127.0.0.1', 'from a trusted proxy (127.0.0.1 here): its chain, and it');
  const c = await fetch(`${base}/cookies`); assert.deepEqual(c.headers.getSetCookie(), ['a=1; Path=/', 'b=2; Path=/']);
  // streaming: the first part arrives before the app has finished
  let t = Date.now(); let r = await fetch(`${base}/stream`); const rd = r.body.getReader(); const first = new TextDecoder().decode((await rd.read()).value); const firstAt = Date.now() - t;
  let rest = ''; for (let x; !(x = await rd.read()).done;) rest += new TextDecoder().decode(x.value);
  assert.equal(first, 'first part\n'); assert.ok(firstAt < 300, `first part after ${firstAt} ms`); assert.equal(rest, 'second part\n');
  pr('a streamed page: its first part, the whole', `${firstAt} ms, ${Date.now() - t} ms (the app waits 400 ms)`);
  // a large upload streams through
  const big = crypto.randomBytes(64 << 20);
  t = Date.now(); const up = await (await fetch(`${base}/upload`, { method: 'POST', body: big })).json();
  assert.deepEqual(up, { n: big.length, sha: crypto.createHash('sha256').update(big).digest('hex') });
  pr('a 64 MB upload through the API', `${Date.now() - t} ms`);
  // HTTP/2 from the client (cleartext here; browsers negotiate it over TLS), HTTP/1.1 to the app
  const s2 = http2.connect(base); const got = await new Promise((ok, no) => { const q = s2.request({ ':path': '/headers', cookie: ['a=1', 'b=2'] }); let b = ''; q.on('data', (d) => (b += d)); q.on('end', () => ok(JSON.parse(b))); q.on('error', no); }); s2.close();
  assert.equal(got.cookie, 'a=1; b=2', 'HTTP/2 split cookies, joined for the app'); assert.equal(got.host, `127.0.0.1:${port}`);
  // a WebSocket through
  const ws = new WebSocket(`ws://127.0.0.1:${port}/ws`);
  const echo = await new Promise((ok, no) => { ws.onopen = () => ws.send('hello'); ws.onmessage = (m) => ok(m.data); ws.onerror = no; }); ws.close();
  assert.equal(echo, 'hello'); assert.equal(wsUpgrades, 1);
  // the API's own socket still works
  const own = new WebSocket(`ws://127.0.0.1:${port}/api/socket`); await new Promise((ok, no) => { own.onopen = ok; own.onerror = no; }); own.close();
  pr('checks: routing, headers, streaming, upload, HTTP/2, WebSockets', 'ok');

  // the pool: many requests, few connections to the app
  const N = 2000;
  const loop = async (url) => { const t0 = process.hrtime.bigint(); for (let i = 0; i < N; i++) await (await fetch(url)).text(); return Number(process.hrtime.bigint() - t0) / N / 1000; };
  await loop(`${direct}/`); const before = sockets; await loop(`${base}/`); const one = sockets - before;
  let [d, p] = [Infinity, Infinity]; for (let k = 0; k < 3; k++) { d = Math.min(d, await loop(`${direct}/`)); p = Math.min(p, await loop(`${base}/`)); }
  pr(`a page from the app directly (${N} requests, keep-alive)`, `${d.toFixed(1)} us`);
  pr(`the same page through the API`, `${p.toFixed(1)} us`);
  // 50 at once: the pool grows to what is asked of it, and keeps them
  const s0 = sockets; await Promise.all(Array.from({ length: 50 }, () => fetch(`${base}/stream`).then((x) => x.text())));
  const s1 = sockets; await Promise.all(Array.from({ length: 50 }, () => fetch(`${base}/stream`).then((x) => x.text())));
  pr(`new connections to the app: ${N} requests one at a time; 50 at once; 50 again`, `${one}; ${s1 - s0}; ${sockets - s1}`);
  assert.ok(one <= 1 && sockets - s1 <= 5, 'the pool reuses its connections');

  // app.trustProxy: the rate limit sees each client behind the proxy, not the proxy
  const signIn = (ip) => fetch(`${base}/api/auth/users/sign-in`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-forwarded-for': ip }, body: JSON.stringify({ login: 'x@x.test', password: 'wrong password' }) }).then((x) => x.json());
  for (let i = 0; i < 10; i++) await signIn('198.51.100.1');
  assert.equal((await signIn('198.51.100.1')).code, 'RATE_LIMITED'); assert.equal((await signIn('198.51.100.2')).code, 'AUTH', 'another client is not limited');
  pr('app.trustProxy: the sign-in limit per client behind the proxy', 'ok');

  // ---- part 2: sessions in a cookie, and the API's own sign-in page
  const jar = new Map(); const keep = (r) => { for (const c of r.headers.getSetCookie()) { const [kv] = c.split(';'); const i = kv.indexOf('='); const [k, v] = [kv.slice(0, i), kv.slice(i + 1)]; if (v) jar.set(k, v); else jar.delete(k); } return r; };
  const cookies = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
  const get = (path, h = {}) => fetch(base + path, { redirect: 'manual', headers: { cookie: cookies(), ...h } }).then(keep);
  const post = (path, form, h = {}) => fetch(base + path, { method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookies(), ...h }, body: new URLSearchParams(form) }).then(keep);
  const formOf = async (r) => (await r.text()).match(/name="form" value="([0-9a-f]+)"/)[1];
  let page = await get('/_sqz/sign-in?return=/dashboard%3Ftab%3D1&mode=up'); assert.equal(page.status, 200);
  let f = await formOf(page);
  // another site's form, or a form without this browser's value, signs no one in
  r = await post('/_sqz/sign-in', { form: f, action: 'sign-up', login: 'ann@x.test', password: 'the password 1', return: '/dashboard?tab=1' }, { origin: 'https://evil.example' });
  assert.equal(r.status, 400); assert.match(await r.text(), /came from another page/);
  r = await fetch(base + '/_sqz/sign-in', { method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ form: f, action: 'sign-up', login: 'ann@x.test', password: 'the password 1' }) });
  assert.equal(r.status, 400);
  // as a browser posts it: its own Origin (the page's Referrer-Policy is same-origin), or, from a page of the app's
  // with no-referrer, Origin: null with Sec-Fetch-Site: same-origin; a null origin from anywhere else is refused
  page = await get('/_sqz/sign-in'); assert.equal(page.headers.get('referrer-policy'), 'same-origin');
  r = await post('/_sqz/sign-in', { form: await formOf(page), action: 'sign-in', login: 'nobody@x.test', password: 'the password 1' }, { origin: 'null', 'sec-fetch-site': 'cross-site' });
  assert.match(await r.text(), /came from another page/);
  r = await post('/_sqz/sign-in', { form: await formOf(await get('/_sqz/sign-in')), action: 'sign-in', login: 'nobody@x.test', password: 'the password 1' }, { origin: 'null', 'sec-fetch-site': 'same-origin' });
  assert.doesNotMatch(await r.text(), /came from another page/, 'past the form check (to a wrong password)');
  f = await formOf(await get('/_sqz/sign-in?mode=up'));   // (each page has a value of its own)
  r = await post('/_sqz/sign-in', { form: f, action: 'sign-up', login: 'ann@x.test', password: 'the password 1', return: '/dashboard?tab=1' }, { origin: base });
  assert.equal(r.status, 303); assert.equal(r.headers.get('location'), '/dashboard?tab=1');
  const set = r.headers.getSetCookie().find((c) => c.startsWith('sqz_session=')); assert.match(set, /HttpOnly/); assert.match(set, /SameSite=Lax/); assert.match(set, /Path=\//);
  // the cookie is the session: for the API, and (as headers) for the app behind it
  assert.equal((await (await get('/api/me')).json()).user.email, 'ann@x.test');
  h = await (await get('/headers')).json();
  assert.deepEqual([h['x-sqz-user'], h['x-sqz-table'], h['x-sqz-roles'], h['x-real-ip']], ['1', 'users', 'member', '127.0.0.1']); assert.match(h.cookie, /sqz_session=/);
  // a cookie of the app's that isn't UTF-8 (a browser sends what was set, byte for byte): the session still counts,
  // and the app gets the bytes as sent
  const latin = `pref=caf\u00e9; ${cookies()}`;
  let x = await rawGet('/headers', { cookie: latin }); assert.equal(x.status, 200);
  assert.equal(x.json['x-sqz-user'], '1'); assert.equal(x.json.cookie, latin);
  x = await rawGet('/dashboard/x', { cookie: latin }); assert.equal(x.json['x-plan'], 'pro'); assert.equal(x.json.cookie, latin, 'and past middleware that set a header');
  assert.equal((await rawGet('/api/me', { cookie: latin })).json.user.email, 'ann@x.test');
  // from another site's page the cookie is no session (app.origins has "*": that lets pages call the API, not act as
  // the visitor), and the app is told no one
  assert.equal((await (await get('/api/me', { origin: 'https://evil.example' })).json()).code, 'AUTH');
  assert.equal((await (await get('/headers', { origin: 'https://evil.example' })).json())['x-sqz-user'], undefined);
  // never a way to another site
  for (const back of ['https://evil.example/x', '//evil.example/x', '/\\evil.example']) {
    f = await formOf(await get('/_sqz/sign-in'));
    r = await post('/_sqz/sign-in', { form: f, action: 'sign-in', login: 'ann@x.test', password: 'the password 1', return: back });
    assert.equal(r.headers.get('location'), '/', back);
  }
  // sign-out ends the session
  const old = jar.get('sqz_session');
  f = await formOf(await get('/_sqz/sign-out'));
  r = await post('/_sqz/sign-out', { form: f, return: '/' }); assert.equal(r.status, 303); assert.equal(jar.get('sqz_session'), undefined);
  assert.equal((await (await fetch(`${base}/api/me`, { headers: { cookie: `sqz_session=${old}` } })).json()).code, 'AUTH');
  // the challenge goes into a cookie: only ever a challenge, never what a link put there
  r = await get(`/api/auth/users/oauth/hub?cookie=1&return=/x&challenge=${encodeURIComponent('a; Domain=evil.example; Path=/')}`);
  assert.equal(r.status, 302); assert.ok(r.headers.getSetCookie().find((c) => c.startsWith('sqz_challenge=')).startsWith('sqz_challenge=; '));
  assert.ok(!r.headers.getSetCookie().some((c) => c.includes('evil')));
  // a provider, in cookie mode: back on the page it started from, signed in
  r = await get('/api/auth/users/oauth/hub?cookie=1&return=/after-hub'); assert.equal(r.status, 302);
  const at = await fetch(r.headers.get('location'), { redirect: 'manual' });
  r = await fetch(at.headers.get('location'), { redirect: 'manual', headers: { cookie: cookies() } }).then(keep);
  assert.equal(r.headers.get('location'), '/after-hub'); assert.equal((await (await get('/api/me')).json()).user.email, 'octo@hub.test');
  // the client, in cookie mode: no token in reach of the page; the socket takes the cookie as it connects
  jar.clear();
  const jarFetch = (url, init = {}) => fetch(url, { ...init, headers: { ...(init.headers || {}), cookie: cookies() } }).then(keep);
  class JarSocket extends WebSocket { constructor(url) { super(url, { headers: { cookie: cookies() } }); } }
  const { connect } = await import('./index.js');
  const cl = connect(base, { cookies: true, fetch: jarFetch, WebSocket: JarSocket }); await cl.ready;
  assert.equal(cl.auth.user, null);
  const si = await cl.auth.signIn('ann@x.test', 'the password 1');
  assert.equal(si.token, undefined); assert.equal(cl.token, null); assert.ok(jar.get('sqz_session'));
  assert.deepEqual(await cl.sql('SELECT email FROM users'), [{ email: 'ann@x.test' }], 'as Ann, under her policy');
  const cl2 = connect(base, { cookies: true, fetch: jarFetch, WebSocket: JarSocket }); await cl2.ready;
  assert.equal(cl2.auth.user.email, 'ann@x.test', 'a new page knows who is signed in');
  await cl.auth.signOut(); assert.equal(jar.get('sqz_session'), undefined); cl.close(); cl2.close();
  pr('part 2: cookie sessions, the sign-in page, a provider, the client in cookie mode', 'ok');

  // ---- part 3: middleware and routes
  jar.clear(); seen.length = 0;
  r = await get('/dashboard/reports?tab=2'); assert.equal(r.status, 302); assert.equal(r.headers.get('location'), '/_sqz/sign-in?return=%2Fdashboard%2Freports%3Ftab%3D2');
  assert.deepEqual(seen, [], 'the app never saw it');
  f = await formOf(await get('/_sqz/sign-in'));
  r = await post('/_sqz/sign-in', { form: f, action: 'sign-in', login: 'ann@x.test', password: 'the password 1', return: '/dashboard/reports?tab=2' });
  h = await (await get(r.headers.get('location'), { 'x-sqz-user': '999' })).json();
  assert.deepEqual([h['x-plan'], h['x-sqz-user'], h['x-sqz-roles']], ['pro', '1', 'member'], 'the header middleware set, and who: the API\'s, not the client\'s');
  // a guard holds however the path is written
  for (const p of ['/admin/x', '/adm%69n/x', '/ADMIN/x'.toLowerCase(), '/_next/data/b1d/admin/x.json', '//admin//x']) { r = await get(p); assert.equal(r.status, 403, p); }
  // (sent raw: fetch, like a browser, resolves dot segments before sending; a script of someone else's needn't)
  const raw = (path) => new Promise((ok, no) => http.get({ host: '127.0.0.1', port, path, headers: { cookie: cookies() } }, (x) => { x.resume(); ok(x.statusCode); }).on('error', no));
  for (const p of ['/public/../admin/x', '/admin%2fx', '/x/%2e%2e/admin', '/x/./admin/../admin/y']) assert.equal(await raw(p), 400, p);
  assert.ok(!seen.some((p) => p.toLowerCase().includes('adm')), 'none reached the app');
  // a guard that checks req.path itself (as the README's does) holds too: req.path is the path the patterns matched
  seen.length = 0;
  for (const p of ['/staff/x', '/st%61ff/x', '//staff//x', '/_next/data/b1d/staff/x.json', '/st%61ff/x?q=1']) { r = await get(p); assert.equal(r.status, 403, p); }
  assert.equal((await get('/team/x')).status, 404, 'not the guarded part: on to the app');
  assert.deepEqual(seen, ['/team/x']);
  let e = await (await get('/echo/%61b//c?x=1')).json();
  assert.deepEqual([e.path, e.rawPath, e.url, e.rest], ['/echo/ab/c', '/echo/%61b//c', '/echo/%61b//c?x=1', 'ab/c']);
  // HTTP/2 may send each cookie as a field of its own: one Cookie header, and every cookie, for the route and the API
  const s2b = http2.connect(base);
  const h2 = (path, cookie) => new Promise((ok, no) => { const q = s2b.request({ ':path': path, cookie }); let b = ''; q.on('data', (d) => (b += d)); q.on('end', () => ok(JSON.parse(b))); q.on('error', no); });
  e = await h2('/echo/x', ['a=1', cookies(), 'b=2']);
  assert.deepEqual([e.cookies.a, e.cookies.b, !!e.cookies.sqz_session], ['1', '2', true]); assert.equal(e.cookie, `a=1; ${cookies()}; b=2`);
  assert.equal((await h2('/api/me', ['a=1', cookies()])).user.email, 'ann@x.test'); s2b.close();
  // only WebSockets are upgraded: an h2c (or any other) Upgrade goes on as a plain request, never a tunnel
  const ups = wsUpgrades;
  for (const upgrade of ['h2c', 'tls/1.2', 'websocketx']) {
    x = await rawGet('/headers', { connection: 'Upgrade, HTTP2-Settings', upgrade, 'http2-settings': 'AAMAAABkAAQAoAAAAAIAAAAA' });
    assert.equal(x.status, 200, upgrade); assert.equal(x.json.upgrade, undefined); assert.equal(x.json['http2-settings'], undefined);
  }
  assert.equal(wsUpgrades, ups);
  // routes
  r = await fetch(`${base}/hooks/stripe`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id: 'evt_1', amount: 42 }) });
  assert.equal(r.status, 201); assert.deepEqual(await r.json(), { ok: true, source: 'stripe', stored: 1 });
  assert.deepEqual(await (await fetch(`${base}/hello?q=7`)).json(), { hello: 'stranger', q: '7' });
  assert.deepEqual(await (await get('/hello')).json(), { hello: 'ann@x.test', q: null });
  assert.equal((await fetch(`${base}/hooks/stripe`)).status, 404, 'GET /hooks/… is no route: on to the app, which has no such page');
  pr('part 3: middleware guards (by pattern and by req.path), headers, routes, HTTP/2 cookies, upgrades', 'ok');
  const quiet = await silent; assert.ok(quiet > 9000 && quiet < 16000, `${quiet} ms`);
  pr('a connection that never sends a byte: closed after', `${quiet} ms`);
  {
    const N = 2000; const loop = async (url) => { const t0 = process.hrtime.bigint(); for (let i = 0; i < N; i++) await (await fetch(url)).text(); return Number(process.hrtime.bigint() - t0) / N / 1000; };
    // the same page (/timed/x) three ways: from the app, through the API, through the API and a middleware
    const urls = [`${direct}/timed/x`, `${base}/dashboard/x`.replace('/dashboard', '/timedx'), `${base}/timed/x`, `${base}/hello`];
    for (const u of urls) await loop(u);
    const best = urls.map(() => Infinity); for (let k = 0; k < 3; k++) for (let i = 0; i < urls.length; i++) best[i] = Math.min(best[i], await loop(urls[i]));
    const [a0, a, b, c] = best;
    pr('a page from the app directly', `${a0.toFixed(1)} us`);
    pr('the same page through the API, no middleware', `${a.toFixed(1)} us`);
    pr('the same page through the API and one middleware', `${b.toFixed(1)} us`);
    pr('a route the API answers (JSON)', `${c.toFixed(1)} us`);
  }

  // ---- part 4: the app's slots, and functions that no longer load (each a restart with another configuration)
  const restart = async (toml) => {
    server.kill(); await new Promise((r) => server.once('exit', r));
    fs.writeFileSync(`${dir}.toml`, toml);
    server = spawn(BIN, ['serve', dir, '--app', `127.0.0.1:${port}`, '--config', `${dir}.toml`], { stdio: ['ignore', 'pipe', 'inherit'] });
    let out = ''; await new Promise((r, no) => { server.stdout.on('data', (d) => { out += d; if (out.includes('proxy:')) r(); }); server.once('exit', (c) => no(new Error(`the server exited (${c})`))); });
  };
  // one request at a time to the app, waiting at most 1 s for its turn; the first takes 1.5 s
  await restart(`[app]\npublicUrl = "${base}"\n\n[app.proxy]\nto = "${direct}"\nconnections = 1\ntimeout = "1s"\n`);
  const both = await Promise.all([fetch(`${base}/stream?ms=1500`), new Promise((w) => setTimeout(w, 50)).then(() => fetch(`${base}/stream`))]);
  assert.deepEqual(both.map((x) => x.status), [200, 503]); assert.match(await both[1].text(), /busy/); await both[0].text();
  assert.equal((await fetch(`${base}/stream`)).status, 200, 'and the slot is free again once the first is through');
  pr('app.proxy.connections = 1: the second request at once waits its turn, then a 503', 'ok');
  // app.mcp makes /oauth/… the API's own: the deployed route there can't be, so the functions don't load. Nothing of
  // the site is served unguarded: a 503 for all but the API's own
  await restart(`[app]\npublicUrl = "${base}"\nproxy = "${direct}"\n\n[app.mcp]\nusers = "users"\n`);
  for (const p of ['/', '/dashboard/x', '/staff/x', '/hello']) { r = await fetch(base + p, { redirect: 'manual' }); assert.equal(r.status, 503, p); assert.match(await r.text(), /doesn't load/); }
  assert.equal((await (await fetch(`${base}/api/me`)).json()).code, 'AUTH', 'the API carries on');
  assert.equal((await (await fetch(`${base}/api/fn/anything`, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookies() }, body: '{}' })).json()).code, 'FUNCTION', 'as Ann: no function can be called either');
  // the configuration as it was: they load again, and the site is back
  await restart(toml0); assert.equal((await fetch(`${base}/`)).status, 200); assert.equal((await fetch(`${base}/staff/x`)).status, 403);
  pr("functions that don't load: the site a 503, the API answering; back once they do", 'ok');

  // the app down
  app.close(); app.closeAllConnections();
  const down = await fetch(`${base}/`); assert.equal(down.status, 502); assert.match(await down.text(), /isn't answering/);
  assert.equal((await (await fetch(`${base}/api/me`)).json()).code, 'AUTH', 'the API carries on');
  pr('the app down: a 502 page, the API still answering', 'ok');
} finally { server.kill(); app.close(); hub.close(); }
