// E59: the notes app's workloads against sqzdb's app API and against PocketBase 0.40.5, set up the same way:
// users sign up through the public API, a note belongs to its owner (a row policy here, collection rules there),
// both index notes.owner. Both servers run on this machine with their data on the same disk, and both are driven by
// the same Node HTTP client (keep-alive, one connection per simulated user). From the repo:
//
//   cargo build --release && node demos/notes/bench/bench.mjs [--users 200] [--notes 50] [--devices 1000] [--pocketbase <binary>]
//
// PocketBase 0.40.5 is expected at tools/pocketbase-0.40.5/pocketbase (from its GitHub releases) unless given.
//
// Each server is started, measured and stopped in turn: sqzdb, PocketBase as it comes, and PocketBase with its
// request log off (it writes every request to a second SQLite database by default).
import http from 'node:http'; import fs from 'node:fs'; import net from 'node:net'; import assert from 'node:assert/strict'; import crypto from 'node:crypto';
import { spawn, execFileSync } from 'node:child_process';
import { connect } from '../../../clients/js/index.js';

const ROOT = new URL('../../../', import.meta.url).pathname;
const arg = (n, d) => { const i = process.argv.indexOf(`--${n}`); return i > 0 ? (typeof d === 'number' ? Number(process.argv[i + 1]) : process.argv[i + 1]) : d; };
const SQZ = ROOT + 'target/release/sqzdb', PB = arg('pocketbase', ROOT + 'tools/pocketbase-0.40.5/pocketbase'), DATA = ROOT + 'data/nocow/e59';
const USERS = arg('users', 200), NOTES = arg('notes', 50), DEVICES = arg('devices', 1000), PASSWORD = 'the password 1';

// ---------- measuring ----------
const rss = (pid) => Number(fs.readFileSync(`/proc/${pid}/status`, 'utf8').match(/VmRSS:\s+(\d+)/)[1]) / 1024;   // MB
const cpu = (pid) => { const f = fs.readFileSync(`/proc/${pid}/stat`, 'utf8').split(') ')[1].split(' '); return (Number(f[11]) + Number(f[12])) * 10; };   // ms
const du = (dir) => Number(execFileSync('du', ['-sk', dir]).toString().split('\t')[0]) / 1024;   // MB
const ms = (t) => Number(process.hrtime.bigint() - t) / 1e6;
const pct = (xs, p) => { const s = [...xs].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.floor(s.length * p))]; };
const lat = (xs) => `p50 ${pct(xs, 0.5).toFixed(3)} ms, p99 ${pct(xs, 0.99).toFixed(3)} ms`;
const sleep = (t) => new Promise((r) => setTimeout(r, t));
const freePort = () => new Promise((r) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
/** `n` workers over `items`, each `fn(item, i)` in turn. */
async function pool(n, items, fn) { let next = 0; await Promise.all(Array.from({ length: n }, async () => { while (next < items.length) { const i = next++; await fn(items[i], i); } })); }

/** One simulated user's HTTP client: keep-alive, one connection, from its own loopback address (sqzdb limits
 *  sign-ups per address; real users come from many). Resolves to { status, body }. */
function httpClient(base, i) {
  const agent = new http.Agent({ keepAlive: true, maxSockets: 1, localAddress: `127.0.${1 + Math.floor(i / 10)}.1` });
  // body: JSON, or { raw: Buffer, type } sent as it is
  return (method, path, body, auth) => new Promise((resolve, reject) => {
    const data = body === undefined ? null : body.raw ? body.raw : JSON.stringify(body);
    const headers = { ...(data ? { 'content-type': body.raw ? body.type : 'application/json', 'content-length': Buffer.byteLength(data) } : {}), ...(auth ? { authorization: auth } : {}) };
    http.request(base + path, { method, agent, headers }, (res) => {
      const parts = []; res.on('data', (c) => parts.push(c));
      res.on('end', () => { const b = Buffer.concat(parts); let v = null; try { v = b.length && b[0] === 0x7b ? JSON.parse(b) : null; } catch {} resolve({ status: res.statusCode, body: v, size: b.length }); });
    }).on('error', reject).end(data);
  });
}
const ok = (r, what) => { if (r.status !== 200 || r.body?.error) throw new Error(`${what}: HTTP ${r.status} ${JSON.stringify(r.body).slice(0, 300)}`); return r.body; };

// ---------- sqzdb: the notes demo's own schema and settings ----------
const sqzdb = {
  name: 'sqzdb',
  async start() {
    const dir = `${DATA}/sqzdb`, port = await freePort();
    execFileSync(SQZ, ['shell', dir], { input: fs.readFileSync(ROOT + 'demos/notes/schema.sql'), stdio: ['pipe', 'ignore', 'inherit'] });
    fs.writeFileSync(`${dir}.toml`, '[app.signUp]\nusers = ["name"]\n');
    const proc = spawn(SQZ, ['serve', dir, '--app', `127.0.0.1:${port}`, '--config', `${dir}.toml`], { stdio: ['ignore', 'pipe', 'inherit'] });
    await new Promise((r) => proc.stdout.on('data', (d) => { if (String(d).includes('app API')) r(); }));
    return { base: `http://127.0.0.1:${port}`, proc, dir };
  },
  async signUp(c, i) { const r = ok(await c('POST', '/api/auth/users/sign-up', { fields: { email: `u${i}@notes.test` }, password: PASSWORD }), 'sign-up'); return { auth: `Bearer ${r.token}`, token: r.token, user: r.user, id: r.user.id }; },
  sql: async (c, u, sql, params) => ok(await c('POST', '/api/sql', { sql, params }, u.auth), sql),
  async insert(c, u, body) { return (await this.sql(c, u, 'INSERT INTO notes (owner, body) VALUES (?, ?)', [u.id, body])).lastInsertId; },
  async read(c, u, id) { const r = await this.sql(c, u, 'SELECT id, owner, body, pinned, created FROM notes WHERE id = ?', [id]); assert.equal(r.rows.length, 1); },
  async list(c, u) { const r = await this.sql(c, u, 'SELECT id, owner, body, pinned, created FROM notes WHERE owner = ? ORDER BY created DESC LIMIT 20', [u.id]); assert.equal(r.rows.length, 20); },
  /** A note with a picture: the upload, then the INSERT that names it (what the JS client does with a File). */
  async insertWithFile(c, u, body, pic) {
    const f = ok(await c('POST', '/api/files?name=pic.jpg', { raw: pic, type: 'image/jpeg' }, u.auth), 'upload');
    return (await this.sql(c, u, 'INSERT INTO notes (owner, body, attachment) VALUES (?, ?, ?)', [u.id, body, f.id])).lastInsertId;
  },
  /** How to download a note's picture: the signed link a query hands out. */
  async picture(c, u, note) { const url = (await this.sql(c, u, 'SELECT attachment FROM notes WHERE id = ?', [note])).rows[0][0].url; return () => c('GET', url); },
  /** A device of `u` with live queries; `onNote(id)` for the newest note of theirs, each time it changes. */
  device(t, u, { onNote, onLeak, full }) {
    const db = connect(t.base, { storage: { getItem: () => JSON.stringify({ token: u.token, user: u.user }), setItem() {}, removeItem() {} } });
    let n = 0; const ready = new Promise((resolve) => {
      const done = () => { if (++n === (full ? 2 : 1)) resolve(); };
      // no WHERE owner: the row policy alone decides what a device sees, as the collection rules do in PocketBase
      db.live('SELECT id, owner FROM notes ORDER BY id DESC LIMIT 10', (rows, info) => { if (info.initial) done(); else { if (rows.some((r) => r.owner !== u.id)) onLeak?.(); if (rows[0]) onNote?.(rows[0].id); } });
      if (full) db.live('SELECT count(*) AS n FROM notes', () => done());
    });
    return { ready, close: () => db.close() };
  },
};

// ---------- PocketBase: the same data model as collections with rules ----------
const pocketbase = (requestLog) => ({
  name: requestLog ? 'PocketBase' : 'PocketBase, request log off',
  async start() {
    const dir = `${DATA}/pocketbase`, port = await freePort(), base = `http://127.0.0.1:${port}`;
    execFileSync(PB, ['superuser', 'upsert', 'admin@bench.test', 'benchpass123', '--dir', dir], { stdio: 'ignore' });
    const proc = spawn(PB, ['serve', '--http', `127.0.0.1:${port}`, '--dir', dir], { stdio: ['ignore', 'ignore', 'inherit'] });
    for (let i = 0; ; i++) { try { if ((await fetch(`${base}/api/health`)).ok) break; } catch {} if (i > 100) throw new Error('PocketBase did not start'); await sleep(100); }
    const c = httpClient(base, 0);
    const admin = ok(await c('POST', '/api/collections/_superusers/auth-with-password', { identity: 'admin@bench.test', password: 'benchpass123' }), 'superuser').token;
    if (!requestLog) ok(await c('PATCH', '/api/settings', { logs: { maxDays: 0 } }, admin), 'settings');
    const users = ok(await c('PATCH', '/api/collections/users', { createRule: '' }, admin), 'users rule');   // anyone may sign up, as in the demo
    const rule = 'owner = @request.auth.id';
    ok(await c('POST', '/api/collections', { name: 'notes', type: 'base',
      fields: [{ name: 'owner', type: 'relation', collectionId: users.id, maxSelect: 1, required: true, cascadeDelete: true }, { name: 'body', type: 'text', max: 1000, required: true },
        { name: 'pinned', type: 'bool' }, { name: 'created', type: 'autodate', onCreate: true }, { name: 'attachment', type: 'file', maxSelect: 1, maxSize: 26214400, protected: true }],
      listRule: rule, viewRule: rule, createRule: `@request.auth.id != "" && ${rule}`, updateRule: rule, deleteRule: rule,
      indexes: ['CREATE INDEX idx_notes_owner ON notes (owner)'] }, admin), 'notes collection');
    return { base, proc, dir };
  },
  async signUp(c, i) {
    const email = `u${i}@notes.test`;
    ok(await c('POST', '/api/collections/users/records', { email, password: PASSWORD, passwordConfirm: PASSWORD }), 'sign-up');
    const r = ok(await c('POST', '/api/collections/users/auth-with-password', { identity: email, password: PASSWORD }), 'sign-in');   // sign-up makes no session
    return { auth: r.token, token: r.token, id: r.record.id };
  },
  async insert(c, u, body) { return ok(await c('POST', '/api/collections/notes/records', { owner: u.id, body }, u.auth), 'insert').id; },
  async read(c, u, id) { ok(await c('GET', `/api/collections/notes/records/${id}`, undefined, u.auth), 'read'); },
  async list(c, u) { const r = ok(await c('GET', '/api/collections/notes/records?sort=-created&perPage=20&skipTotal=1', undefined, u.auth), 'list'); assert.equal(r.items.length, 20); },
  /** A note with a picture: one multipart request with the fields and the file. */
  async insertWithFile(c, u, body, pic) {
    const b = `----e59${crypto.randomBytes(8).toString('hex')}`, part = (name, v) => `--${b}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${v}\r\n`;
    const raw = Buffer.concat([Buffer.from(part('owner', u.id) + part('body', body) + `--${b}\r\nContent-Disposition: form-data; name="attachment"; filename="pic.jpg"\r\nContent-Type: image/jpeg\r\n\r\n`), pic, Buffer.from(`\r\n--${b}--\r\n`)]);
    const r = ok(await c('POST', '/api/collections/notes/records', { raw, type: `multipart/form-data; boundary=${b}` }, u.auth), 'insert with a file'); return { id: r.id, file: r.attachment };
  },
  /** How to download a note's picture: a file token (protected files), then the file's URL. */
  async picture(c, u, note) { const t = ok(await c('POST', '/api/files/token', {}, u.auth), 'file token').token; return () => c('GET', `/api/files/notes/${note.id}/${note.file}?token=${t}`); },
  /** A device of `u` subscribed to notes over server-sent events; `onNote(id)` for each note of theirs created. */
  device(t, u, { onNote, onLeak }) {
    let req; const ready = new Promise((resolve, reject) => {
      req = http.get(`${t.base}/api/realtime`, { agent: false }, (res) => {
        let buf = '', event = '';
        res.on('data', (chunk) => {
          buf += chunk; let i;
          while ((i = buf.indexOf('\n')) >= 0) {
            const line = buf.slice(0, i).replace(/\r$/, ''); buf = buf.slice(i + 1);
            if (line.startsWith('event:')) event = line.slice(6).trim();
            else if (line.startsWith('data:')) {
              const m = JSON.parse(line.slice(5));
              if (event === 'PB_CONNECT') {
                fetch(`${t.base}/api/realtime`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: u.auth }, body: JSON.stringify({ clientId: m.clientId, subscriptions: ['notes'] }) })
                  .then((r) => (r.ok ? resolve() : reject(new Error(`subscribe: HTTP ${r.status}`))), reject);
              } else if (event === 'notes' && m.action === 'create') { if (m.record.owner !== u.id) onLeak?.(); onNote?.(m.record.id); }
            }
          }
        });
      }).on('error', reject);
    });
    return { ready, close: () => req.destroy() };
  },
});

// ---------- the workloads, the same for every server ----------
async function measure(target) {
  fs.rmSync(`${DATA}`, { recursive: true, force: true }); fs.mkdirSync(DATA, { recursive: true });
  const t = await target.start(); const pid = t.proc.pid; const out = {};
  try {
    out['server memory, started and set up'] = `${rss(pid).toFixed(0)} MB`;
    // users sign up, 16 at a time
    const cs = Array.from({ length: USERS }, (_, i) => httpClient(t.base, i)); const users = new Array(USERS);
    let t0 = process.hrtime.bigint();
    await pool(16, cs, async (c, i) => { users[i] = await target.signUp(c, i); });
    out[`${USERS} sign-ups, 16 at a time (until each has a session)`] = `${(ms(t0) / 1000).toFixed(1)} s (${(USERS / (ms(t0) / 1000)).toFixed(0)}/s); server memory then ${rss(pid).toFixed(0)} MB`;
    // every user writes their notes, 32 users at a time
    let c0 = cpu(pid); t0 = process.hrtime.bigint(); const noteIds = users.map(() => []);
    await pool(32, users, async (u, i) => { for (let k = 0; k < NOTES; k++) noteIds[i].push(await target.insert(cs[i], u, `note ${k} of user ${i}: ${'x'.repeat(80)}`)); });
    const el = ms(t0) / 1000;
    out[`${USERS * NOTES} notes created, 32 users writing at once`] = `${(USERS * NOTES / el).toFixed(0)}/s, server CPU ${((cpu(pid) - c0) * 1000 / (USERS * NOTES)).toFixed(0)} µs per note; memory then ${rss(pid).toFixed(0)} MB`;
    // one user at a time: read a note, list the newest 20
    let xs = [];
    for (let k = 0; k < 2000; k++) { const i = k % USERS; const a = process.hrtime.bigint(); await target.read(cs[i], users[i], noteIds[i][k % NOTES]); xs.push(ms(a)); }
    out['read one note by id (HTTP, one request at a time)'] = lat(xs);
    xs = [];
    for (let k = 0; k < 2000; k++) { const i = k % USERS; const a = process.hrtime.bigint(); await target.list(cs[i], users[i]); xs.push(ms(a)); }
    out['list the newest 20 notes (HTTP, one request at a time)'] = lat(xs);
    // a note with a 100 KB picture; then that picture, downloaded
    const pic = crypto.randomBytes(100 << 10); xs = []; let note;
    for (let k = 0; k < 200; k++) { const i = k % USERS; const a = process.hrtime.bigint(); note = await target.insertWithFile(cs[i], users[i], `picture ${k}`, pic); xs.push(ms(a)); }
    out['a note with a 100 KB picture created (the upload included)'] = lat(xs);
    const fetchPic = await target.picture(cs[199 % USERS], users[199 % USERS], note); xs = [];
    for (let k = 0; k < 500; k++) { const a = process.hrtime.bigint(); const r = await fetchPic(); assert.equal(r.status, 200); assert.equal(r.size, pic.length); xs.push(ms(a)); }
    out['download that picture'] = lat(xs);
    // 32 users reading at once for 3 s
    let done = 0; c0 = cpu(pid); t0 = process.hrtime.bigint(); const until = Date.now() + 3000;
    await Promise.all(Array.from({ length: 32 }, async (_, w) => { for (let k = 0; Date.now() < until; k++) { const i = (w * 7 + k) % USERS; await target.list(cs[i], users[i]); done++; } }));
    out['list the newest 20, 32 users at once for 3 s'] = `${(done / (ms(t0) / 1000)).toFixed(0)}/s, server CPU ${((cpu(pid) - c0) / ms(t0) * 100).toFixed(0)}% of a core; memory then ${rss(pid).toFixed(0)} MB`;
    // a write on one device reaching another device of the same user, writes 20 ms apart
    let wake = null, leaks = 0; const u0 = users[0], seen = new Set();   // a note can show up before its insert's response
    const dev = target.device(t, u0, { onNote: (id) => { seen.add(id); wake?.(); }, onLeak: () => leaks++ }); await dev.ready;
    xs = [];
    for (let k = 0; k < 200; k++) {
      await sleep(20); const a = process.hrtime.bigint(); const id = await target.insert(cs[0], u0, `live ${k}`);
      while (!seen.has(id)) await new Promise((r) => { wake = r; if (seen.has(id)) r(); });
      xs.push(ms(a));
    }
    dev.close();
    out['write on one device -> seen on another (the write included)'] = lat(xs);
    // connected devices: realtime connections held open, users cycled
    await sleep(500); const before = rss(pid); const devs = [];
    for (let k = 0; k < DEVICES; k++) devs.push(target.device(t, users[k % USERS], { onLeak: () => leaks++, full: true }));
    await Promise.all(devs.map((d) => d.ready)); await sleep(1000);
    out[`server memory with ${DEVICES} devices connected`] = `${rss(pid).toFixed(0)} MB (${((rss(pid) - before) * 1024 / DEVICES).toFixed(0)} KB per device)`;
    // a burst of writes while they are connected: every device of the writing user must see its notes, no one else's
    c0 = cpu(pid); t0 = process.hrtime.bigint();
    await pool(32, users.slice(0, 64), async (u, i) => { for (let k = 0; k < 10; k++) await target.insert(cs[i], u, `burst ${k}`); });
    const burst = ms(t0) / 1000; await sleep(500);
    out[`640 writes with the ${DEVICES} devices connected`] = `${(640 / burst).toFixed(0)}/s; a device saw another user's note: ${leaks} times`;
    for (const d of devs) d.close();
    out['server CPU, whole run'] = `${(cpu(pid) / 1000).toFixed(1)} s`;
    out['peak memory (VmHWM)'] = `${(Number(fs.readFileSync(`/proc/${pid}/status`, 'utf8').match(/VmHWM:\s+(\d+)/)[1]) / 1024).toFixed(0)} MB`;
    out['data on disk'] = `${du(t.dir).toFixed(1)} MB`;
  } finally {
    t.proc.kill('SIGTERM'); await new Promise((r) => t.proc.on('exit', r));
    fs.rmSync(DATA, { recursive: true, force: true });
  }
  return out;
}

const results = [];
for (const target of [sqzdb, pocketbase(true), pocketbase(false)]) { process.stderr.write(`measuring ${target.name}...\n`); results.push([target.name, await measure(target)]); }
console.log(`E59: the notes app, ${USERS} users x ${NOTES} notes, ${DEVICES} devices; sqzdb ${JSON.parse(fs.readFileSync(ROOT + 'clients/js/package.json')).version} vs PocketBase 0.40.5 on ${(await import('node:os')).cpus().length} cores\n`);
for (const key of Object.keys(results[0][1])) { console.log(key); for (const [name, r] of results) console.log(`  ${name.padEnd(30)} ${r[key]}`); }
process.exit(0);   // the realtime clients' sockets would keep Node waiting
