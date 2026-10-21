// E58: the app API end to end with the JS client against `sqzdb serve --app`: users sign up and query from the
// client under row policies, live queries move between devices, and the API refuses what a client may not do.
// Sign-in with a provider goes through the browser's redirects against a local OpenID Connect provider (as in E57).
// Then: SQL round trips over the socket and over HTTP, a write's way to the other device's live query, and the
// server's memory with 1,000 connected users holding 2 live queries each.
import { connect } from './index.js';
import { spawn, execFileSync } from 'node:child_process';
import fs from 'node:fs'; import assert from 'node:assert/strict'; import net from 'node:net'; import http from 'node:http'; import crypto from 'node:crypto';

// the provider: signs ID tokens for the codes the test approves
const key = crypto.createPrivateKey({ key: fs.readFileSync(new URL('../../src/testdata/oauth_test_rsa.der', import.meta.url)), format: 'der', type: 'pkcs1' });
const jwk = { ...crypto.createPublicKey(key).export({ format: 'jwk' }), kid: 'node-1', alg: 'RS256' };
const b64 = (b) => Buffer.from(b).toString('base64url');
const sign = (claims) => { const h = b64(JSON.stringify({ alg: 'RS256', kid: 'node-1' })), p = b64(JSON.stringify(claims)); return `${h}.${p}.${b64(crypto.sign('sha256', Buffer.from(`${h}.${p}`), key))}`; };
const grants = new Map();
const idp = http.createServer((req, res) => {
  let body = ''; req.on('data', (c) => { body += c; }); req.on('end', () => {
    const send = (code, obj) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); };
    if (req.url === '/jwks') return send(200, { keys: [jwk] });
    if (req.url === '/token' && req.method === 'POST') {
      const f = Object.fromEntries(new URLSearchParams(body)); const g = grants.get(f.code); grants.delete(f.code);
      if (!g || f.client_secret !== 'node-secret') return send(400, { error: 'invalid_grant' });
      if (crypto.createHash('sha256').update(f.code_verifier).digest('base64url') !== g.challenge) return send(400, { error: 'bad verifier' });
      const now = Math.floor(Date.now() / 1000);
      return send(200, { id_token: sign({ iss: 'https://idp.test', aud: 'node-client', sub: g.sub, email: g.email, email_verified: true, iat: now, exp: now + 600, nonce: g.nonce }) });
    }
    send(404, {});
  });
});
await new Promise((r) => idp.listen(0, '127.0.0.1', r)); const idpUrl = `http://127.0.0.1:${idp.address().port}`;
// the user approves at the provider, which sends the browser back with `code`
const approve = (to, code, sub, email) => { const q = new URL(to).searchParams; grants.set(code, { challenge: q.get('code_challenge'), nonce: q.get('nonce'), sub, email }); return q.get('state'); };

const BIN = new URL('../../target/release/sqzdb', import.meta.url).pathname;
const dir = new URL('../../data/nocow/e58', import.meta.url).pathname; fs.rmSync(dir, { recursive: true, force: true });
const port = await new Promise((r) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
const url = `http://127.0.0.1:${port}`;
fs.mkdirSync(dir, { recursive: true });
const cfg = `${dir}.toml`; fs.writeFileSync(cfg, `[app]\norigins = ["http://localhost:5173"]\nmaxRows = 1000\npublicUrl = "${url}"\n\n[app.signUp]\nusers = ["name"]\n\n` +
  `[auth.oauth.idp]\nkind = "oidc"\nclientId = "node-client"\nclientSecret = "node-secret"\nauthUrl = "${idpUrl}/authorize"\ntokenUrl = "${idpUrl}/token"\njwksUrl = "${idpUrl}/jwks"\nissuer = "https://idp.test"\n`);
execFileSync(BIN, ['shell', dir], { input: [
  "CREATE TABLE users (id SERIAL PRIMARY KEY, email TEXT UNIQUE, name TEXT, role TEXT DEFAULT 'member');",
  'CREATE TABLE notes (id SERIAL PRIMARY KEY, owner INT, body TEXT, created TIMESTAMP DEFAULT now());',
  'CREATE ROLE member;', 'GRANT SELECT, INSERT, UPDATE, DELETE ON notes TO member;',
  'CREATE POLICY own ON notes FOR ALL TO member USING (owner = SESSION.id);',
  'ALTER TABLE users ENABLE AUTH (ROLE FROM role);',
  'CREATE TABLE staff (id SERIAL PRIMARY KEY, login TEXT UNIQUE);', 'ALTER TABLE staff ENABLE AUTH (ROLE member);', '.quit', ''].join('\n'), stdio: ['pipe', 'ignore', 'inherit'] });
const server = spawn(BIN, ['serve', dir, '--app', `127.0.0.1:${port}`, '--config', cfg], { stdio: ['ignore', 'pipe', 'inherit'] });
await new Promise((r) => server.stdout.on('data', (d) => { if (String(d).includes('app API')) r(); }));
const rss = () => Number(fs.readFileSync(`/proc/${server.pid}/status`, 'utf8').match(/VmRSS:\s+(\d+)/)[1]) / 1024;
const ms = (t) => Number(process.hrtime.bigint() - t) / 1e6;
const pct = (xs, p) => { const s = [...xs].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.floor(s.length * p))]; };
const pr = (label, v) => console.log(label.padEnd(64), v);

try {
  // ---- behaviour
  const ann = connect(url, { storage: null }); const bob = connect(url, { storage: null });
  const a = await ann.auth.signUp({ email: 'Ann@x.com', name: 'Ann' }, 'ann password'); assert.equal(a.user.email, 'ann@x.com');
  const b = await bob.auth.signUp({ email: 'bob@x.com', name: 'Bob' }, 'bob password');
  // a sign-up sets the login column and what app.signUp lists, in the tables it lists: not its own role or id
  for (const fields of [{ email: 'mal@x.com', role: 'admin' }, { email: 'mal@x.com', id: 999 }]) await assert.rejects(connect(url, { storage: null }).auth.signUp(fields, 'mal password'), (e) => e.code === 'DENIED', JSON.stringify(fields));
  await assert.rejects(connect(url, { storage: null, users: 'staff' }).auth.signUp({ login: 'mal' }, 'mal password'), (e) => e.code === 'DENIED');
  // what a sign-in page needs to know, and the client itself, from the server
  assert.deepEqual(await ann.auth.methods(), { signUp: true, providers: ['idp'], password: true });
  assert.deepEqual(await connect(url, { storage: null, users: 'staff' }).auth.methods(), { signUp: false, providers: ['idp'], password: true });
  const js = await fetch(`${url}/api/client.js`); assert.equal(js.status, 200); assert.match(js.headers.get('content-type'), /javascript/);
  assert.equal(await js.text(), fs.readFileSync(new URL('./index.js', import.meta.url), 'utf8'));
  await ann.sql('INSERT INTO notes (owner, body) VALUES (?, ?)', [a.user.id, 'ann 1']);
  await bob.sql('INSERT INTO notes (owner, body) VALUES (?, ?)', [b.user.id, 'bob 1']);
  await assert.rejects(bob.sql('INSERT INTO notes (owner, body) VALUES (?, ?)', [a.user.id, 'forged']), (e) => e.code === 'DENIED');
  assert.deepEqual((await ann.sql('SELECT body FROM notes')).map((r) => r.body), ['ann 1']);
  // a second device of Ann's sees her writes live
  const annPhone = connect(url, { storage: null }); await annPhone.auth.signIn('ann@x.com', 'ann password');
  const seen = []; const live = annPhone.live('SELECT body FROM notes ORDER BY id', (rows) => seen.push(rows.map((r) => r.body)));
  await new Promise((r) => setTimeout(r, 100));
  await ann.sql('INSERT INTO notes (owner, body) VALUES (?, ?)', [a.user.id, 'ann 2']);
  await new Promise((r) => setTimeout(r, 100));
  assert.deepEqual(seen.at(-1), ['ann 1', 'ann 2']); assert.equal(seen.length, 2);
  // what a client may not do
  for (const bad of ['CREATE TABLE x (id INT PRIMARY KEY)', 'DROP TABLE notes', 'GRANT SELECT ON users TO member', 'BEGIN', 'ALTER TABLE notes ADD COLUMN x INT']) await assert.rejects(ann.sql(bad), (e) => ['DENIED', 'SYNTAX'].includes(e.code), bad);
  await assert.rejects(ann.sql('SELECT * FROM _auth_secrets'), (e) => e.code === 'SCHEMA');
  const res = await fetch(`${url}/api/sql`, { method: 'POST', headers: { origin: 'https://evil.example', 'content-type': 'application/json', authorization: `Bearer ${a.token}` }, body: JSON.stringify({ sql: 'SELECT 1' }) });
  assert.equal(res.status, 403);
  const ok = await fetch(`${url}/api/sql`, { method: 'POST', headers: { origin: 'http://localhost:5173', 'content-type': 'application/json', authorization: `Bearer ${a.token}` }, body: JSON.stringify({ sql: 'SELECT 1 AS one' }) });
  assert.equal(ok.headers.get('access-control-allow-origin'), 'http://localhost:5173');
  await assert.rejects(fetch(`${url}/api/sql`, { method: 'POST', body: '{"sql":"SELECT 1"}', headers: { 'content-type': 'application/json' } }).then(async (r) => { const v = await r.json(); if (v.error) throw Object.assign(new Error(v.error), { code: v.code }); }), (e) => e.code === 'AUTH');
  // a batch is one transaction
  await assert.rejects(ann.batch([['INSERT INTO notes (owner, body) VALUES (?, ?)', [a.user.id, 'in batch']], ['INSERT INTO notes (owner, body) VALUES (?, ?)', [b.user.id, 'not hers']]]));
  assert.equal((await ann.sql("SELECT count(*) AS n FROM notes WHERE body = 'in batch'"))[0].n, 0);
  // more rows than app.maxRows: refused, with the remedy
  const many = Array.from({ length: 1001 }, (_, i) => ['INSERT INTO notes (owner, body) VALUES (?, ?)', [a.user.id, `n${i}`]]);
  for (let i = 0; i < many.length; i += 100) await ann.batch(many.slice(i, i + 100));
  await assert.rejects(ann.sql('SELECT * FROM notes'), (e) => /maxRows/.test(e.message));
  // signing out on the phone ends its live query's session; signed out, it can't query
  await annPhone.auth.signOut(); await assert.rejects(annPhone.sql('SELECT 1'), (e) => e.code === 'AUTH');
  live.close(); annPhone.close();
  // sign-in with a provider: the API sends the browser there, and back to the app with a one-time code
  const get = (path, cookie) => fetch(url + path, { redirect: 'manual', headers: cookie ? { cookie } : {} });
  const cookiesOf = (res) => res.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ');
  const back = 'http://localhost:5173/app', C = 'A'.repeat(43);   // C: a well-formed challenge, for refusals that come first
  assert.equal((await get(`/api/auth/users/oauth/idp?return=${encodeURIComponent('https://evil.example/')}&challenge=${C}`)).status, 400);   // no open redirect
  assert.equal((await get(`/api/auth/users/oauth/idp?return=${encodeURIComponent(`${back}\r\nRefresh: 0`)}&challenge=${C}`)).status, 400);   // nothing to break the Location header
  assert.equal((await get(`/api/auth/users/oauth/idp?return=${encodeURIComponent(back)}`)).status, 400);   // no challenge
  // a browser tab: its address bar, history and sessionStorage (where signInWith keeps the verifier)
  const tab = () => { const m = new Map(); return { getItem: (k) => m.get(k) ?? null, setItem: (k, v) => m.set(k, v), removeItem: (k) => m.delete(k) }; };
  const inTab = async (t, href, fn) => {
    const bar = []; Object.assign(globalThis, { location: { href, hash: new URL(href).hash, assign() {} }, history: { replaceState: (_, __, u) => bar.push(u) }, sessionStorage: t });
    try { return [await fn(), bar]; } finally { delete globalThis.location; delete globalThis.history; delete globalThis.sessionStorage; }
  };
  /** The page in tab `t` starts a provider sign-in: the API's redirect to the provider, and its cookies. */
  const start = async (t) => {
    const [to] = await inTab(t, back, () => connect(url, { storage: null }).auth.signInWith('idp')); const u = new URL(to);
    const r = await get(u.pathname + u.search); assert.equal(r.status, 302); return { to: r.headers.get('location'), cookies: cookiesOf(r) };
  };
  /** …and the provider approves `sub`: where the browser lands back on the app. */
  const signInAt = async (t, code, sub, email) => {
    const st = await start(t);
    const cb = await get(`/api/auth/users/oauth/idp/callback?code=${code}&state=${encodeURIComponent(approve(st.to, code, sub, email))}`, st.cookies);
    assert.equal(cb.status, 302); return new URL(cb.headers.get('location'));
  };
  const carolTab = tab(); const landed = await signInAt(carolTab, 'code-1', 'idp-carol', 'Carol@IdP.test');
  assert.equal(landed.origin + landed.pathname, back); const code = new URLSearchParams(landed.hash.slice(1)).get('sqz_code'); assert.ok(code);
  // back in the same tab, the client trades the code (with the tab's verifier) and takes it out of the address bar
  const [carol, bar] = await inTab(carolTab, landed.href, async () => { const c = connect(url, { storage: null }); await c.ready; return c; });
  assert.equal(carol.auth.user.email, 'carol@idp.test'); assert.deepEqual(bar, [back]);
  assert.deepEqual(await carol.sql('SELECT count(*) AS n FROM notes'), [{ n: 0 }]);   // a new user: no rows of anyone else's
  const exchange = (c, verifier) => fetch(`${url}/api/auth/exchange`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ code: c, verifier }) });
  assert.equal((await exchange(code, 'v'.repeat(43))).status, 401);   // the code works once
  // login CSRF: Mallory signs in with her own provider account and plants the code in a link to the app. A tab that
  // started a sign-in of its own has another verifier, and the API refuses it; a tab that started none refuses itself
  const planted = await signInAt(tab(), 'code-4', 'idp-mallory', 'mallory@idp.test');
  const victim = tab(); await start(victim);
  await assert.rejects(inTab(victim, planted.href, () => connect(url, { storage: null }).ready), (e) => e.code === 'AUTH');
  const planted2 = await signInAt(tab(), 'code-5', 'idp-mallory', 'mallory@idp.test');
  await assert.rejects(inTab(tab(), planted2.href, () => connect(url, { storage: null }).ready), (e) => e.code === 'AUTH' && /did not start/.test(e.message));
  // the provider's answer delivered to another browser (without the cookies from the start): an error back on the page
  const st = await start(tab()); const st2 = approve(st.to, 'code-2', 'idp-carol', 'carol@idp.test');
  const elsewhere = await get(`/api/auth/users/oauth/idp/callback?code=code-2&state=${encodeURIComponent(st2)}`, st.cookies.split('; ').filter((c) => c.startsWith('sqz_return=')).join('; '));
  const h = new URLSearchParams(new URL(elsewhere.headers.get('location')).hash.slice(1)); assert.ok(h.get('sqz_error') && !h.get('sqz_code'), String(h));
  assert.equal((await get(`/api/auth/users/oauth/idp/callback?code=code-2&state=${encodeURIComponent(st2)}`)).status, 400);   // no cookies at all
  // a table not open to sign-up: a provider account not linked to one of its users is refused, not made a user
  const toStaff = await get(`/api/auth/staff/oauth/idp?return=${encodeURIComponent(back)}&challenge=${C}`); const sc = cookiesOf(toStaff);
  const staffBack = await get(`/api/auth/staff/oauth/idp/callback?code=code-3&state=${encodeURIComponent(approve(toStaff.headers.get('location'), 'code-3', 'idp-mal', 'mal@idp.test'))}`, sc);
  assert.match(new URL(staffBack.headers.get('location')).hash, /^#sqz_error=.*not%20made%20here/);
  carol.close();
  console.log('API checks: ok');

  // ---- costs
  const N = 2000; let lat = [];
  for (let i = 0; i < N; i++) { const t = process.hrtime.bigint(); await ann.sql('SELECT body FROM notes WHERE id = ?', [i % 50 + 1]); lat.push(ms(t)); }
  pr('SQL point read over the socket', `p50 ${pct(lat, .5).toFixed(3)} ms, p99 ${pct(lat, .99).toFixed(3)} ms`);
  lat = [];
  for (let i = 0; i < N; i++) { const t = process.hrtime.bigint(); const r = await fetch(`${url}/api/sql`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${a.token}` }, body: JSON.stringify({ sql: 'SELECT body FROM notes WHERE id = ?', params: [i % 50 + 1] }) }); await r.json(); lat.push(ms(t)); }
  pr('SQL point read over HTTP (fetch, keep-alive)', `p50 ${pct(lat, .5).toFixed(3)} ms, p99 ${pct(lat, .99).toFixed(3)} ms`);
  // a write from one device to the other device's live query
  const phone = connect(url, { storage: null }); await phone.auth.signIn('bob@x.com', 'bob password');
  let resolveSeen = null; phone.live('SELECT id, body FROM notes ORDER BY id DESC LIMIT 1', (rows, info) => { if (!info.initial && resolveSeen) resolveSeen(); });
  await new Promise((r) => setTimeout(r, 100));
  // writes apart (a person typing) are seen at once; back to back, each waits for the last re-run's live.debounce
  for (const [label, gap] of [['10 ms apart', 10], ['back to back', 0]]) {
    lat = [];
    for (let i = 0; i < 300; i++) {
      if (gap) await new Promise((r) => setTimeout(r, gap));
      const seenP = new Promise((r) => { resolveSeen = r; }); const t = process.hrtime.bigint();
      await bob.sql('INSERT INTO notes (owner, body) VALUES (?, ?)', [b.user.id, `w${i}`]); await seenP; lat.push(ms(t));
    }
    pr(`write on one device -> live query on another (writes ${label})`, `p50 ${pct(lat, .5).toFixed(2)} ms, p99 ${pct(lat, .99).toFixed(2)} ms`);
  }
  phone.close();
  // 1,000 users connected, 2 live queries each
  // sign-up is rate limited per client address, so the users come from 100 loopback addresses, 10 each
  const signUpFrom = (localAddress, fields, password) => new Promise((resolve, reject) => {
    const body = JSON.stringify({ fields, password });
    http.request(`${url}/api/auth/users/sign-up`, { method: 'POST', localAddress, headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } }, (res) => {
      let s = ''; res.on('data', (d) => { s += d; }); res.on('end', () => { const v = JSON.parse(s); if (v.error) reject(new Error(v.error)); else resolve(v); });
    }).on('error', reject).end(body);
  });
  const before = rss(); const U = 1000; const clients = [];
  const tokens = [];
  for (let i = 0; i < U; i++) {
    const s = await signUpFrom(`127.0.${1 + Math.floor(i / 10)}.1`, { email: `u${i}@x.com` }, 'the password'); tokens.push(s);
    const kept = JSON.stringify({ token: s.token, user: s.user });
    clients.push(connect(url, { storage: { getItem: () => kept, setItem() {}, removeItem() {} } }));
  }
  let ready = 0; await new Promise((done) => {
    for (const [i, c] of clients.entries()) {
      c.live('SELECT count(*) AS n FROM notes', () => { if (++ready === 2 * U) done(); });
      c.live('SELECT id, body FROM notes WHERE owner = ? ORDER BY id DESC LIMIT 10', [tokens[i].user.id], () => { if (++ready === 2 * U) done(); });
    }
  });
  await new Promise((r) => setTimeout(r, 500));
  pr(`server memory: ${U} users signed up and connected, ${2 * U} live queries`, `${rss().toFixed(0)} MB (${before.toFixed(0)} MB before; ${((rss() - before) * 1024 / U).toFixed(0)} KB per user, their rows and session included)`);
  for (const c of clients) c.close();
} finally {
  server.kill('SIGTERM'); await new Promise((r) => server.on('exit', r)); idp.close();
  fs.rmSync(dir, { recursive: true, force: true }); fs.rmSync(cfg, { force: true });
}
