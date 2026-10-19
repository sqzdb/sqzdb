// E68: a real Next.js app (15.5, App Router) with sqzdb embedded and in front of it: the database opens with the
// server (instrumentation.js) and its app API serves the site, passing what isn't its own on to Next.js on 127.0.0.1.
// Pages are guarded by the app's middleware, the dashboard reads as the signed-in user (their cookie is the session),
// a server action calls the app's function, and sqzdb answers a route of its own. The app is demos/nextjs, built and
// installed with the packed packages (NEXTAPP=<its directory>).
import { spawn } from 'node:child_process';
import fs from 'node:fs'; import net from 'node:net'; import http2 from 'node:http2'; import assert from 'node:assert/strict';

const app = process.env.NEXTAPP || new URL('../../demos/nextjs', import.meta.url).pathname;
const dir = new URL('../../data/nocow/e68', import.meta.url).pathname; fs.rmSync(dir, { recursive: true, force: true });
const freePort = () => new Promise((r) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
const [front, next] = [await freePort(), await freePort()];
const base = `http://127.0.0.1:${front}`, direct = `http://127.0.0.1:${next}`;
const pr = (label, v) => console.log(label.padEnd(64), v);

const t0 = Date.now();
const server = spawn(`${app}/node_modules/.bin/next`, ['start', '-H', '127.0.0.1', '-p', String(next)], { cwd: app, env: { ...process.env, FRONT: `127.0.0.1:${front}`, NEXT_URL: direct, DB_DIR: dir }, stdio: ['ignore', 'pipe', 'inherit'] });
let up = false; for (let i = 0; i < 100 && !up; i++) { await new Promise((r) => setTimeout(r, 100)); up = await fetch(`${base}/healthz`).then((r) => r.ok, () => false); }
assert.ok(up, 'the front door is listening once next start is up');
pr('next start, until the API in front of it answers', `${Date.now() - t0} ms`);

const jar = new Map(); const keep = (r) => { for (const c of r.headers.getSetCookie()) { const [kv] = c.split(';'); const i = kv.indexOf('='); const [k, v] = [kv.slice(0, i), kv.slice(i + 1)]; if (v) jar.set(k, v); else jar.delete(k); } return r; };
const cookies = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
const get = (path) => fetch(base + path, { redirect: 'manual', headers: { cookie: cookies() } }).then(keep);
const post = (path, body, h = {}) => fetch(base + path, { method: 'POST', redirect: 'manual', headers: { cookie: cookies(), ...h }, body }).then(keep);
const formOf = async (r) => (await r.text()).match(/name="form" value="([0-9a-f]+)"/)[1];

try {
  let r = await get('/'); assert.equal(r.status, 200); assert.match(await r.text(), /Welcome to ai-tasks/);
  r = await get('/dashboard'); assert.equal(r.status, 302); assert.equal(r.headers.get('location'), '/_sqz/sign-in?return=%2Fdashboard');
  let f = await formOf(await get('/_sqz/sign-in?mode=up&return=/dashboard'));
  r = await post('/_sqz/sign-in', new URLSearchParams({ form: f, action: 'sign-up', login: 'ann@x.test', password: 'the password 1', return: '/dashboard' }));
  assert.equal(r.status, 303); assert.equal(r.headers.get('location'), '/dashboard');
  let html = await (await get('/dashboard')).text();
  assert.match(html, /Jobs of user <!-- -->1<!-- --> \(<!-- -->member<!-- -->\)/, 'Next.js knows who: X-Sqz-User and X-Sqz-Roles');
  // a server action, posted as a form posts it before JavaScript loads: through the API, to Next.js, to the function
  const action = html.match(/name="\$ACTION_ID_([0-9a-f]+)"/)[1];
  const form = (title) => { const fd = new FormData(); fd.append(`$ACTION_ID_${action}`, ''); fd.append('title', title); return fd; };
  // (with the Origin a browser sends: Next.js checks it against the host it was forwarded for)
  r = await post('/dashboard', form('write the docs'), { origin: base }); assert.equal(r.status, 303); assert.equal(r.headers.get('location'), '/dashboard');
  r = await post('/dashboard', form('no'), { origin: base }); assert.equal(r.status, 500, 'the function refused it (TOO_SHORT), so the action failed');
  // another site's post: the cookie is no session from there, so the guard sends it to sign in, and Next.js never sees it
  r = await post('/dashboard', form('from elsewhere'), { origin: 'https://evil.example' }); assert.equal(r.status, 302); assert.match(r.headers.get('location'), /^\/_sqz\/sign-in/);
  html = await (await get('/dashboard')).text();
  assert.match(html, /<li>write the docs<\/li>/); assert.doesNotMatch(html, /<li>no<\/li>/);
  assert.deepEqual(await (await get('/healthz')).json(), { ok: true, jobs: 1 }, 'a route sqzdb answers itself');
  // Next.js's own files, through the API
  const chunk = html.match(/src="(\/_next\/static\/chunks\/[^"]+\.js)"/)[1];
  r = await get(chunk); assert.equal(r.status, 200); assert.match(r.headers.get('content-type'), /javascript/);
  // HTTP/2 to the API (cleartext here; browsers get it over TLS), HTTP/1.1 from it to Next.js
  const s2 = http2.connect(base); const page = await new Promise((ok, no) => { const q = s2.request({ ':path': '/' }); let b = ''; q.on('data', (d) => (b += d)); q.on('end', () => ok(b)); q.on('error', no); }); s2.close();
  assert.match(page, /Welcome to ai-tasks/);
  // sign out: the dashboard is guarded again
  f = await formOf(await get('/_sqz/sign-out?return=/'));
  r = await post('/_sqz/sign-out', new URLSearchParams({ form: f, return: '/' })); assert.equal(r.status, 303);
  assert.equal((await get('/dashboard')).status, 302);
  pr('checks: guard, sign-up, the dashboard as the user, a server action, a route, Next.js files, HTTP/2, sign-out', 'ok');

  // costs: the home page and a script file, from Next.js directly and through the API
  const N = 1000;
  const loop = async (url) => { const t = process.hrtime.bigint(); for (let i = 0; i < N; i++) await (await fetch(url)).text(); return Number(process.hrtime.bigint() - t) / N / 1000; };
  for (const [what, path] of [['the home page (rendered on each request)', '/'], ['a script file of Next.js', chunk]]) {
    await loop(direct + path); await loop(base + path);
    let [a, b] = [Infinity, Infinity]; for (let k = 0; k < 3; k++) { a = Math.min(a, await loop(direct + path)); b = Math.min(b, await loop(base + path)); }
    pr(`${what}: from Next.js, through the API`, `${a.toFixed(0)} us, ${b.toFixed(0)} us`);
  }
} finally { server.kill(); }
