// E66: the app's functions, over the network. An app shaped like ai-tasks (jobs, and runs that report back) whose
// rules live in TypeScript functions in the database: members may read their own rows but write only through the
// functions. Part 1: the app API (POST /api/fn), and the client over its socket. Part 2: an agent over MCP with
// app.mcp.sql off, so its tools are the functions alone. Part 3: costs, a function against the same statement sent as
// SQL.
import { spawn, execFileSync } from 'node:child_process';
import fs from 'node:fs'; import assert from 'node:assert/strict'; import net from 'node:net'; import crypto from 'node:crypto';
import { connect } from './index.js';

const BIN = new URL('../../target/release/sqzdb', import.meta.url).pathname;
const dir = new URL('../../data/nocow/e66', import.meta.url).pathname; fs.rmSync(dir, { recursive: true, force: true });
const fns = `${dir}-functions`; fs.rmSync(fns, { recursive: true, force: true }); fs.mkdirSync(fns, { recursive: true });
const port = await new Promise((r) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
const base = `http://127.0.0.1:${port}`;

fs.writeFileSync(`${fns}/jobs.ts`, `import { fn } from 'sqzdb/functions'
import { must, mine } from './lib/checks.ts'

export const park = fn({
  description: 'Park a job to run later: a title and a brief (Markdown, any length)',
  args: { title: 'text', brief: 'text' },
  roles: ['member'],
  run({ admin, user }, { title, brief }) {
    return admin.get('INSERT INTO jobs (owner, title, brief) VALUES (?, ?, ?) RETURNING id, status', [mine(user), title, brief])
  },
})

export const startRun = fn({
  description: 'Start a run of one of your jobs',
  args: { jobId: 'int' },
  roles: ['member'],
  run({ db, admin, user }, { jobId }) {
    const job = must(db.get('SELECT id, status FROM jobs WHERE id = ?', [jobId]), 'NO_JOB', \`no job \${jobId}\`)
    if (job.status === 'review') throw Object.assign(new Error(\`job \${jobId} is in review\`), { code: 'IN_REVIEW' })
    admin.run("UPDATE jobs SET status = 'running' WHERE id = ?", [jobId])
    return admin.get('INSERT INTO runs (job, owner) VALUES (?, ?) RETURNING id', [jobId, mine(user)])
  },
})

export const reportRun = fn({
  description: 'Report how a run ended. A finished run cannot change, a completed run needs an outcome, and when every run of its job has ended the job moves to review.',
  args: { runId: 'int', status: ['completed', 'failed'], outcome: { type: 'text?', description: 'what the run produced (Markdown)' } },
  roles: ['member'],
  run({ db, admin }, { runId, status, outcome }) {
    const run = must(db.get('SELECT id, job, status FROM runs WHERE id = ?', [runId]), 'NO_RUN', \`no run \${runId}\`)
    if (run.status !== 'running') throw Object.assign(new Error(\`run \${runId} is \${run.status} already\`), { code: 'ALREADY_FINISHED' })
    if (status === 'completed' && !outcome) throw Object.assign(new Error('a completed run needs an outcome'), { code: 'NEEDS_OUTCOME' })
    admin.run('UPDATE runs SET status = ?, outcome = ? WHERE id = ?', [status, outcome ?? null, runId])
    const left = admin.get("SELECT count(*) AS n FROM runs WHERE job = ? AND status = 'running'", [run.job])!.n as number
    if (left === 0) admin.run("UPDATE jobs SET status = 'review' WHERE id = ?", [run.job])
    return { run: runId, status, jobStatus: left === 0 ? 'review' : 'running' }
  },
})

export const myJobs = fn({
  description: 'Your jobs, newest first',
  readOnly: true,
  roles: ['member'],
  run: ({ db }) => db.all('SELECT id, title, status FROM jobs ORDER BY id DESC LIMIT 50'),
})
`);
fs.mkdirSync(`${fns}/lib`);
fs.writeFileSync(`${fns}/lib/checks.ts`, `export function must<T>(v: T | null, code: string, message: string): T {
  if (v == null) throw Object.assign(new Error(message), { code })
  return v
}
export const mine = (user: Record<string, unknown> | null): number => user!.id as number
`);
fs.writeFileSync(`${dir}.toml`, `[app]\npublicUrl = "${base}"\n\n[app.signUp]\nusers = []\n\n[app.mcp]\nsql = false\n\n[functions]\ndir = "${fns}"\n`);
execFileSync(BIN, ['shell', dir], { input: [
  "CREATE TABLE users (id SERIAL PRIMARY KEY, email TEXT UNIQUE, role TEXT DEFAULT 'member');",
  "CREATE TABLE jobs (id SERIAL PRIMARY KEY, owner INT NOT NULL, title TEXT, brief TEXT, status TEXT DEFAULT 'inbox');",
  "CREATE TABLE runs (id SERIAL PRIMARY KEY, job INT NOT NULL, owner INT NOT NULL, status TEXT DEFAULT 'running', outcome TEXT);",
  'CREATE INDEX runs_job ON runs (job);',
  'CREATE ROLE member;', 'GRANT SELECT ON jobs TO member;', 'GRANT SELECT ON runs TO member;',
  'CREATE POLICY own ON jobs FOR ALL TO member USING (owner = SESSION.id);', 'CREATE POLICY own_runs ON runs FOR ALL TO member USING (owner = SESSION.id);',
  'ALTER TABLE users ENABLE AUTH (ROLE FROM role);', ''].join('\n'), stdio: ['pipe', 'ignore', 'ignore'] });
const server = spawn(BIN, ['serve', dir, '--app', `127.0.0.1:${port}`, '--config', `${dir}.toml`], { stdio: ['ignore', 'pipe', 'inherit'] });
let banner = ''; await new Promise((r) => server.stdout.on('data', (d) => { banner += d; if (banner.includes('app API')) r(); }));
const pr = (label, v) => console.log(label.padEnd(64), v);
const json = (path, v, headers = {}) => fetch(base + path, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(v) });
const call = async (token, name, args) => { const r = await json(`/api/fn/${name}`, args, token ? { authorization: `Bearer ${token}` } : {}); return [r.status, await r.json()]; };

try {
  pr('functions at start', banner.match(/functions: +(.*)/)[1]);
  const users = {};
  for (const email of ['ann@x.test', 'bob@x.test']) users[email] = await (await json('/api/auth/users/sign-up', { fields: { email }, password: 'the password 1' })).json();
  const ann = users['ann@x.test'].token, bob = users['bob@x.test'].token;

  // ---- part 1: the app API, and the client over its socket
  let [st, v] = await call(ann, 'park', { title: 'tidy the docs', brief: '# Brief\n' + 'x'.repeat(100_000) });
  assert.equal(st, 200); assert.deepEqual(v, { result: { id: 1, status: 'inbox' } });
  const runs = [];
  for (let i = 0; i < 2; i++) { [st, v] = await call(ann, 'startRun', { jobId: 1 }); assert.equal(st, 200); runs.push(v.result.id); }
  [st, v] = await call(bob, 'startRun', { jobId: 1 }); assert.deepEqual([st, v.code], [400, 'NO_JOB'], "bob's policy doesn't show ann's job");
  [st, v] = await call(ann, 'reportRun', { runId: runs[0], status: 'completed' }); assert.deepEqual([st, v.code], [400, 'NEEDS_OUTCOME']);
  [st, v] = await call(ann, 'reportRun', { runId: runs[0], status: 'completed', outcome: 'done' }); assert.deepEqual(v.result, { run: runs[0], status: 'completed', jobStatus: 'running' });
  [st, v] = await call(ann, 'reportRun', { runId: runs[0], status: 'failed' }); assert.equal(v.code, 'ALREADY_FINISHED');
  [st, v] = await call(ann, 'reportRun', { runId: runs[1], status: 'kaput' }); assert.deepEqual([st, v.code], [400, 'ARGUMENTS']); pr('a wrong argument', v.error);
  [st, v] = await call(ann, 'nope', {}); assert.deepEqual([st, v.code], [404, 'NOT_FOUND']);
  [st, v] = await call(null, 'myJobs', {}); assert.deepEqual([st, v.code], [401, 'AUTH'], 'no anonymous role: sign in first');
  // the rules can't be skipped: a member writes jobs and runs only through the functions
  v = await (await json('/api/sql', { sql: "UPDATE runs SET status = 'running' WHERE id = ?", params: [runs[0]] }, { authorization: `Bearer ${ann}` })).json();
  assert.equal(v.code, 'DENIED'); pr('ann updating runs herself', v.error);
  // the client: call() over its socket, as the user who signed in
  const db = connect(base, { storage: null }); await db.auth.signIn('ann@x.test', 'the password 1');
  assert.deepEqual(await db.call('reportRun', { runId: runs[1], status: 'failed' }), { run: runs[1], status: 'failed', jobStatus: 'review' });
  assert.deepEqual(await db.call('myJobs'), [{ id: 1, title: 'tidy the docs', status: 'review' }]);
  await assert.rejects(db.call('startRun', { jobId: 1 }), (e) => e.code === 'IN_REVIEW');
  db.close();
  pr('part 1: app API and socket', 'ok');

  // ---- part 2: an agent over MCP, whose tools are the functions alone
  const redirect = 'http://localhost:7777/callback';
  const client = await (await json('/oauth/register', { client_name: 'E66 agent', redirect_uris: [redirect] })).json();
  const verifier = crypto.randomBytes(32).toString('base64url'); const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const jar = new Map(); const keep = (res) => { for (const c of res.headers.getSetCookie?.() ?? []) { const [kv] = c.split(';'); const [k, val] = kv.split('='); if (val) jar.set(k, val); else jar.delete(k); } return res; };
  const cookie = () => [...jar].map(([k, val]) => `${k}=${val}`).join('; ');
  const form = (body) => fetch(`${base}/oauth/authorize`, { method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookie() }, body: new URLSearchParams(body) }).then(keep);
  const q = new URLSearchParams({ response_type: 'code', client_id: client.client_id, redirect_uri: redirect, code_challenge: challenge, code_challenge_method: 'S256', state: 's', resource: `${base}/mcp` });
  const html = await (await fetch(`${base}/oauth/authorize?${q}`, { redirect: 'manual' }).then(keep)).text();
  const request = html.match(/name="request" value="([0-9a-f]+)"/)[1];
  await form({ request, action: 'sign-in', login: 'bob@x.test', password: 'the password 1' });
  const back = new URL((await form({ request, action: 'allow' })).headers.get('location'));
  const tok = await (await fetch(`${base}/oauth/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', code: back.searchParams.get('code'), redirect_uri: redirect, client_id: client.client_id, code_verifier: verifier, resource: `${base}/mcp` }) })).json();
  let n = 0; const rpc = async (method, params) => (await (await json('/mcp', { jsonrpc: '2.0', id: ++n, method, params }, { authorization: `Bearer ${tok.access_token}`, 'mcp-protocol-version': '2025-06-18' })).json());
  const init = await rpc('initialize', { protocolVersion: '2025-06-18' }); pr('MCP instructions', init.result.instructions);
  assert.equal(init.result.capabilities.tools.listChanged, true);
  // the event stream: open for an agent with its token, and only as a stream
  assert.equal((await fetch(`${base}/mcp`, { headers: { accept: 'text/event-stream' } })).status, 401);
  assert.equal((await fetch(`${base}/mcp`, { headers: { authorization: `Bearer ${tok.access_token}` } })).status, 405, 'GET without Accept: text/event-stream');
  const events = await fetch(`${base}/mcp`, { headers: { accept: 'text/event-stream', authorization: `Bearer ${tok.access_token}` } });
  assert.equal(events.status, 200); assert.match(events.headers.get('content-type'), /^text\/event-stream/);
  const reader = events.body.getReader(); let said = '';
  const listChanged = (async () => { while (!said.includes('notifications/tools/list_changed')) { const { value, done } = await reader.read(); if (done) return false; said += new TextDecoder().decode(value); } return true; })();
  const tools = (await rpc('tools/list', {})).result.tools;
  assert.deepEqual(tools.map((t) => t.name), ['myJobs', 'park', 'reportRun', 'startRun'], 'the functions, and no SQL tools');
  const report = tools.find((t) => t.name === 'reportRun');
  assert.deepEqual(report.inputSchema, { type: 'object', properties: { runId: { type: 'integer' }, status: { type: 'string', enum: ['completed', 'failed'] }, outcome: { type: 'string', description: 'what the run produced (Markdown)' } }, required: ['runId', 'status'], additionalProperties: false });
  assert.equal(tools.find((t) => t.name === 'myJobs').annotations.readOnlyHint, true);
  let out = (await rpc('tools/call', { name: 'park', arguments: { title: "bob's job", brief: 'b' } })).result;
  assert.equal(out.isError, false); const bobJob = out.structuredContent.id;
  out = (await rpc('tools/call', { name: 'startRun', arguments: { jobId: bobJob } })).result; const bobRun = out.structuredContent.id;
  out = (await rpc('tools/call', { name: 'reportRun', arguments: { runId: bobRun, status: 'completed' } })).result;
  assert.equal(out.isError, true); pr('a rule, as the agent sees it', out.content[0].text);
  out = (await rpc('tools/call', { name: 'reportRun', arguments: { runId: bobRun, status: 'completed', outcome: 'ok' } })).result;
  assert.deepEqual(out.structuredContent, { run: bobRun, status: 'completed', jobStatus: 'review' });
  out = (await rpc('tools/call', { name: 'myJobs', arguments: {} })).result;
  assert.deepEqual(out.structuredContent, { result: [{ id: bobJob, title: "bob's job", status: 'review' }] }, 'a list comes wrapped: structured content is an object');
  assert.equal((await rpc('tools/call', { name: 'query', arguments: { sql: 'SELECT * FROM jobs' } })).error.code, -32602, 'no SQL tools with app.mcp.sql off');
  pr('part 2: MCP', 'ok');

  // ---- part 3: costs over HTTP (keep-alive), as ann: a function against the same work sent as SQL; each warmed up,
  // measured twice, the better kept (the first loop of any kind also warms Node's HTTP client)
  fs.writeFileSync(`${fns}/ping.ts`, "import { fn } from 'sqzdb/functions'\nexport const ping = fn({ roles: ['member'], run: () => 1 })\n");
  const t0 = Date.now(); while ((await call(ann, 'ping', {}))[0] !== 200) { assert.ok(Date.now() - t0 < 5000); await new Promise((r) => setTimeout(r, 100)); }
  pr('a new file in the folder, callable after', `${Date.now() - t0} ms`);
  // the agent connected over MCP hears of it, and lists its tools again
  assert.equal(await Promise.race([listChanged, new Promise((r) => setTimeout(() => r('timed out'), 5000))]), true, 'tools/list_changed on the event stream');
  pr('the agent told its tools changed, after the file was written', `${Date.now() - t0} ms`);
  assert.ok((await rpc('tools/list', {})).result.tools.some((t) => t.name === 'ping'));
  reader.cancel();
  const N = 2000; const auth = { authorization: `Bearer ${ann}` };
  const loop = async (f) => { const t = process.hrtime.bigint(); for (let i = 0; i < N; i++) await f(); return Number(process.hrtime.bigint() - t) / N / 1000; };
  const best = async (f) => { await loop(f); return Math.min(await loop(f), await loop(f)); };
  const pairs = [
    ['an empty function (ping)', () => json('/api/fn/ping', {}, auth), 'SELECT 1 as /api/sql', () => json('/api/sql', { sql: 'SELECT 1' }, auth)],
    ['read-only function myJobs (1 row)', () => json('/api/fn/myJobs', {}, auth), 'its SELECT as /api/sql', () => json('/api/sql', { sql: 'SELECT id, title, status FROM jobs ORDER BY id DESC LIMIT 50' }, auth)],
  ];
  for (const [a, fa, b, fb] of pairs) {
    const [ga, gb] = [() => fa().then((r) => r.json()), () => fb().then((r) => r.json())]; await loop(ga); await loop(gb);
    let [x, y] = [Infinity, Infinity]; for (let k = 0; k < 3; k++) { x = Math.min(x, await loop(ga)); y = Math.min(y, await loop(gb)); }
    pr(`HTTP round trip, ${a}`, `${x.toFixed(1)} us`); pr(`HTTP round trip, ${b}`, `${y.toFixed(1)} us`);
  }
  const writes = await best(async () => {
    const [, j] = await call(ann, 'park', { title: 't', brief: 'b' }); const [, r] = await call(ann, 'startRun', { jobId: j.result.id });
    const [, x] = await call(ann, 'reportRun', { runId: r.result.id, status: 'failed' }); assert.equal(x.result.jobStatus, 'review');
  });
  pr('HTTP, park + startRun + reportRun (three calls, six writes)', `${writes.toFixed(1)} us`);
} finally { server.kill(); }
