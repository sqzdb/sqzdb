// E70: a standalone sqzdb as a whole backend. The schema goes in through the console's SQL, the app's rules through
// its Functions tab (as a browser would call its API), and an agent connected over MCP (OAuth, its event stream)
// sees new tools as soon as they are deployed. Then a broken deploy, a call as a role from the console, and a server
// whose functions come from a folder (the console shows them read-only).
import { spawn } from 'node:child_process';
import fs from 'node:fs'; import net from 'node:net'; import crypto from 'node:crypto';
import assert from 'node:assert/strict';

const BIN = new URL('../../target/release/sqzdb', import.meta.url).pathname;
const dir = new URL('../../data/nocow/e70', import.meta.url).pathname; fs.rmSync(dir, { recursive: true, force: true });
const freePort = () => new Promise((r) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
const [port, uiPort] = [await freePort(), await freePort()];
const base = `http://127.0.0.1:${port}`, ui = `http://127.0.0.1:${uiPort}`, token = crypto.randomBytes(18).toString('base64url');
const pr = (label, v = 'ok') => console.log(label.padEnd(64), typeof v === 'string' ? v : JSON.stringify(v));

fs.writeFileSync(`${dir}.toml`, `[app]\npublicUrl = "${base}"\n\n[app.signUp]\nusers = []\n\n[app.mcp]\nusers = "users"\nsql = false\n`);
const start = (extra = []) => {
  const p = spawn(BIN, ['serve', dir, '--app', `127.0.0.1:${port}`, '--ui', `127.0.0.1:${uiPort}`, '--token', token, '--config', `${dir}.toml`, ...extra], { stdio: ['ignore', 'pipe', 'inherit'] });
  return new Promise((r) => { let out = ''; p.stdout.on('data', (d) => { out += d; if (out.includes('app API:')) r(p); }); });
};
let server = await start();
// the console's API, as its page calls it
const con = async (path, body) => {
  const r = await fetch(ui + path, { method: body === undefined ? 'GET' : 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  return { status: r.status, ...(await r.json()) };
};
const json = (path, body, headers = {}) => fetch(base + path, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });

try {
  // the schema, from the console's SQL editor
  for (const sql of ["CREATE TABLE users (id SERIAL PRIMARY KEY, email TEXT UNIQUE, role TEXT DEFAULT 'member')", 'CREATE ROLE member', 'ALTER TABLE users ENABLE AUTH (ROLE FROM role)',
    'CREATE TABLE jobs (id SERIAL PRIMARY KEY, owner INT NOT NULL, title TEXT NOT NULL, done BOOL NOT NULL DEFAULT false)']) {
    const r = await con('/api/sql', { sql }); assert.ok(!r.error, `${sql}: ${r.error}`);
  }
  // the app's rules, from the Functions tab
  const v1 = "import { fn } from 'sqzdb/functions'\n\nexport const add_job = fn({ description: 'Park a job', roles: ['member'], args: { title: 'text' },\n  run: ({ admin, user }, { title }) => admin.get('INSERT INTO jobs (owner, title) VALUES (?, ?) RETURNING id, title', [user!.id, title]) })\n\nexport const open_jobs = fn({ description: 'My open jobs', roles: ['member'], readOnly: true,\n  run: ({ admin, user }) => admin.all('SELECT id, title FROM jobs WHERE owner = ? AND NOT done ORDER BY id', [user!.id]) })\n";
  let r = await con('/api/functions', { files: { 'jobs.ts': v1 } });
  assert.equal(r.status, 200); assert.deepEqual(r.functions.sort(), ['add_job', 'open_jobs']); assert.equal(r.changed, true);
  r = await con('/api/functions');
  assert.deepEqual(r.files, { 'jobs.ts': v1 }, 'the file as written, TypeScript and all'); assert.equal(r.folder, null); assert.equal(r.mcp.url, `${base}/mcp`);
  assert.deepEqual(r.exports.map((e) => [e.name, e.kind, e.roles]), [['add_job', 'function', ['member']], ['open_jobs', 'function', ['member']]]);
  pr('schema from the console SQL, functions from its Functions tab');

  // a user, and an agent of theirs over MCP (the OAuth flow agents use)
  await json('/api/auth/users/sign-up', { fields: { email: 'ann@x.test' }, password: 'the password 1' });
  const redirect = 'http://localhost:7777/callback';
  const client = await (await json('/oauth/register', { client_name: 'E70 agent', redirect_uris: [redirect] })).json();
  const verifier = crypto.randomBytes(32).toString('base64url'); const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const jar = new Map(); const keep = (res) => { for (const c of res.headers.getSetCookie?.() ?? []) { const [kv] = c.split(';'); const [k, val] = kv.split('='); if (val) jar.set(k, val); else jar.delete(k); } return res; };
  const cookie = () => [...jar].map(([k, val]) => `${k}=${val}`).join('; ');
  const form = (body) => fetch(`${base}/oauth/authorize`, { method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookie() }, body: new URLSearchParams(body) }).then(keep);
  const q = new URLSearchParams({ response_type: 'code', client_id: client.client_id, redirect_uri: redirect, code_challenge: challenge, code_challenge_method: 'S256', state: 's', resource: `${base}/mcp` });
  const request = (await (await fetch(`${base}/oauth/authorize?${q}`, { redirect: 'manual' }).then(keep)).text()).match(/name="request" value="([0-9a-f]+)"/)[1];
  await form({ request, action: 'sign-in', login: 'ann@x.test', password: 'the password 1' });
  const back = new URL((await form({ request, action: 'allow' })).headers.get('location'));
  const tok = await (await fetch(`${base}/oauth/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', code: back.searchParams.get('code'), redirect_uri: redirect, client_id: client.client_id, code_verifier: verifier, resource: `${base}/mcp` }) })).json();
  const auth = { authorization: `Bearer ${tok.access_token}`, 'mcp-protocol-version': '2025-06-18' };
  let n = 0; const rpc = async (method, params) => (await (await json('/mcp', { jsonrpc: '2.0', id: ++n, method, params }, auth)).json());
  assert.equal((await rpc('initialize', { protocolVersion: '2025-06-18' })).result.capabilities.tools.listChanged, true);
  const tools = async () => (await rpc('tools/list', {})).result.tools.map((t) => t.name).sort();
  assert.deepEqual(await tools(), ['add_job', 'open_jobs']);
  const call = async (name, args = {}) => (await rpc('tools/call', { name, arguments: args })).result;
  assert.equal((await call('add_job', { title: 'tidy the docs' })).isError, false);
  // its event stream
  const events = await fetch(`${base}/mcp`, { headers: { ...auth, accept: 'text/event-stream' } }); assert.equal(events.status, 200);
  const reader = events.body.getReader(); let said = '', heard = 0;
  (async () => { for (;;) { const { value, done } = await reader.read(); if (done) return; said += new TextDecoder().decode(value); heard = said.split('notifications/tools/list_changed').length - 1; } })().catch(() => {});
  const hears = async (k, ms) => { const t = Date.now(); while (heard < k && Date.now() - t < ms) await new Promise((ok) => setTimeout(ok, 20)); return heard >= k ? Date.now() - t : null; };
  pr('an agent over MCP: OAuth, its tools, a call, its event stream');

  // a new tool, deployed from the console: the agent hears of it
  const v2 = v1 + "\nexport const finish_job = fn({ description: 'Mark a job done', roles: ['member'], args: { id: 'int' },\n  run: ({ admin, user }, { id }) => admin.run('UPDATE jobs SET done = true WHERE id = ? AND owner = ?', [id, user!.id]).changes === 1 })\n";
  const t0 = Date.now(); r = await con('/api/functions', { files: { 'jobs.ts': v2 } }); assert.equal(r.status, 200);
  const after = await hears(1, 3000); assert.ok(after !== null, 'tools/list_changed');
  pr('a console deploy, heard by the agent after', `${Date.now() - t0} ms`);
  assert.deepEqual(await tools(), ['add_job', 'finish_job', 'open_jobs']);
  assert.equal((await call('finish_job', { id: 1 })).structuredContent.result, true);
  // the same files again: nothing changes, nothing is said
  r = await con('/api/functions', { files: { 'jobs.ts': v2 } }); assert.equal(r.changed, false);
  // a broken deploy: refused at its line, the deploy in use goes on, nothing is said
  r = await con('/api/functions', { files: { 'jobs.ts': v2 + '\nexport const = oops(\n' } });
  assert.equal(r.status, 400); assert.equal(r.code, 'FUNCTION'); assert.match(r.error, /^jobs\.ts:\d+:\d+/); pr('a broken deploy', r.error);
  assert.equal(await hears(2, 1500), null); assert.deepEqual(await tools(), ['add_job', 'finish_job', 'open_jobs']);
  // try it from the console: as the app (no user: this rule needs one), and as a member
  r = await con('/api/functions/call', { name: 'open_jobs', args: {} }); assert.equal(r.status, 400, 'as the app, user is null');
  r = await con('/api/functions/call', { name: 'add_job', args: { title: 'from the console' }, as: { roles: ['member'], attrs: { id: 1 } } }); assert.equal(r.status, 200); assert.equal(r.result.title, 'from the console');
  assert.deepEqual((await call('open_jobs')).structuredContent.result.map((j) => j.title), ['from the console'], "the agent's user sees it");
  r = await con('/api/functions/call', { name: 'add_job', args: { title: 1 }, as: { roles: ['member'], attrs: { id: 1 } } }); assert.equal(r.code, 'ARGUMENTS');
  pr('called from the console, as the app and as a member');
  reader.cancel();

  // a server whose functions come from a folder: the console shows them, and refuses to deploy over them
  server.kill(); await new Promise((ok) => server.once('exit', ok));
  const fns = `${dir}-functions`; fs.rmSync(fns, { recursive: true, force: true }); fs.mkdirSync(fns); fs.writeFileSync(`${fns}/ping.ts`, "import { fn } from 'sqzdb/functions'\nexport const ping = fn({ roles: ['member'], run: () => 'pong' })\n");
  server = await start(['--functions', fns]);
  r = await con('/api/functions'); assert.equal(r.folder, fns); assert.deepEqual(Object.keys(r.files), ['ping.ts']);
  r = await con('/api/functions', { files: { 'jobs.ts': v2 } }); assert.equal(r.status, 409); assert.match(r.error, /edit the files there/);
  pr('functions from a folder: shown, and not deployed over');
} finally { server.kill(); }
