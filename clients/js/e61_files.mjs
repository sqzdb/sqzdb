// E61: files as a column, through the app API and the JS client. A File passed as a SQL parameter is uploaded and
// its id stored; queries and live queries return { id, name, type, size, url } with a signed link; the link serves
// the bytes with ETags and ranges, inline only for types that can't run script. Refused: someone else's file id,
// a changed link, an upload too large or without a session. Costs: uploads and downloads of 100 KB and 10 MB.
import { connect } from './index.js';
import { spawn, execFileSync } from 'node:child_process';
import fs from 'node:fs'; import assert from 'node:assert/strict'; import net from 'node:net'; import crypto from 'node:crypto';

const BIN = new URL('../../target/release/sqweezdb', import.meta.url).pathname;
const dir = new URL('../../data/nocow/e61', import.meta.url).pathname; fs.rmSync(dir, { recursive: true, force: true });
const port = await new Promise((r) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
const url = `http://127.0.0.1:${port}`;
fs.writeFileSync(`${dir}.toml`, `[app]\norigins = ["http://localhost:5173"]\npublicUrl = "${url}"\n\n[app.signUp]\nusers = ["avatar"]\n\n[app.files]\nmaxSize = "16MB"\n`);
execFileSync(BIN, ['shell', dir], { input: [
  "CREATE TABLE users (id SERIAL PRIMARY KEY, email TEXT UNIQUE, role TEXT DEFAULT 'member', avatar FILE);",
  'CREATE TABLE notes (id SERIAL PRIMARY KEY, owner INT NOT NULL, body TEXT, attachment FILE);',
  'CREATE ROLE member;', 'GRANT SELECT, INSERT, UPDATE, DELETE ON notes TO member;',
  'CREATE POLICY own ON notes FOR ALL TO member USING (owner = SESSION.id);',
  'ALTER TABLE users ENABLE AUTH (ROLE FROM role);', ''].join('\n'), stdio: ['pipe', 'ignore', 'ignore'] });
const server = spawn(BIN, ['serve', dir, '--app', `127.0.0.1:${port}`, '--config', `${dir}.toml`], { stdio: ['ignore', 'pipe', 'inherit'] });
await new Promise((r) => server.stdout.on('data', (d) => { if (String(d).includes('app API')) r(); }));
const ms = (t) => Number(process.hrtime.bigint() - t) / 1e6;
const pct = (xs, p) => { const s = [...xs].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.floor(s.length * p))]; };
const pr = (label, v) => console.log(label.padEnd(64), v);
const bytes = (n) => crypto.randomBytes(n);

try {
  const ann = connect(url, { storage: null }); const a = await ann.auth.signUp({ email: 'ann@x.test' }, 'the password 1');
  const bob = connect(url, { storage: null }); const b = await bob.auth.signUp({ email: 'bob@x.test' }, 'the password 1');
  const png = bytes(5000);
  // a File as a parameter: uploaded, then its id in the row
  const seen = []; const live = ann.live('SELECT id, attachment FROM notes ORDER BY id', (rows) => seen.push(rows));
  await ann.sql('INSERT INTO notes (owner, body, attachment) VALUES (?, ?, ?)', [a.user.id, 'a cat', new File([png], 'path/to/cat.png', { type: 'image/png' })]);
  const [note] = await ann.sql('SELECT id, body, attachment FROM notes');
  const f = note.attachment;
  assert.deepEqual([f.name, f.type, f.size], ['cat.png', 'image/png', 5000]); assert.match(f.id, /^[0-9a-f-]{36}$/); assert.ok(f.url.startsWith(`${url}/api/files/${f.id}?e=`));
  await new Promise((r) => setTimeout(r, 100)); assert.equal(seen.at(-1)[0].attachment.id, f.id, 'live queries carry files too');
  // the link serves the bytes, inline for an image, never as a page that could run script
  let r = await fetch(f.url);
  assert.equal(r.status, 200); assert.deepEqual(Buffer.from(await r.arrayBuffer()), png);
  assert.equal(r.headers.get('content-type'), 'image/png'); assert.match(r.headers.get('content-disposition'), /^inline; filename\*=UTF-8''cat\.png$/);
  assert.equal(r.headers.get('content-security-policy'), "default-src 'none'; sandbox"); assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
  const etag = r.headers.get('etag');
  assert.equal((await fetch(f.url, { headers: { 'if-none-match': etag } })).status, 304);
  r = await fetch(f.url, { headers: { range: 'bytes=100-199' } }); assert.equal(r.status, 206); assert.deepEqual(Buffer.from(await r.arrayBuffer()), png.subarray(100, 200));
  assert.equal(r.headers.get('content-range'), 'bytes 100-199/5000');
  assert.equal((await fetch(f.url, { headers: { range: 'bytes=9000-' } })).status, 416);
  r = await fetch(f.url, { method: 'HEAD' }); assert.equal(r.status, 200); assert.equal(r.headers.get('content-length'), '5000');
  // a page someone uploads is a download, not a page on the API's origin
  const page = await ann.files.upload(new File(['<script>alert(1)</script>'], 'x.html', { type: 'text/html' }));
  assert.match((await fetch(page.url)).headers.get('content-disposition'), /^attachment;/);
  // a link that was changed, or made for another file, or expired: refused
  const u = new URL(f.url);
  for (const [k, v] of [['s', '0'.repeat(32)], ['e', String(Number(u.searchParams.get('e')) + 1)], ['e', '1000']]) { const bad = new URL(u); bad.searchParams.set(k, v); assert.equal((await fetch(bad)).status, 403, `${k}=${v}`); }
  assert.equal((await fetch(f.url.replace(f.id, page.id))).status, 403);
  // someone else's file: Bob knows the id (it was in a link, say), and still can't put it in a row of his
  await assert.rejects(bob.sql('INSERT INTO notes (owner, body, attachment) VALUES (?, ?, ?)', [b.user.id, 'mine now', f.id]), (e) => e.code === 'DENIED');
  await assert.rejects(bob.sql('INSERT INTO notes (owner, body, attachment) VALUES (?, ?, ?)', [b.user.id, 'mine now', f]), (e) => e.code === 'DENIED');
  await assert.rejects(ann.sql('INSERT INTO notes (owner, body, attachment) VALUES (?, ?, ?)', [a.user.id, 'x', '01234567-89ab-4def-8123-456789abcdef']), (e) => e.code === 'NOT_FOUND');
  // nor by signing up with it: someone signing up has uploaded nothing, so a FILE column waits until they are in
  await assert.rejects(connect(url, { storage: null }).auth.signUp({ email: 'mal@x.test', avatar: f.id }, 'the password 1'), (e) => e.code === 'DENIED' && /FILE/.test(e.message));
  // a file from a result goes back as its id: an edit that keeps it, or puts it in another row of hers
  await ann.sql('UPDATE notes SET body = ?, attachment = ? WHERE id = ?', ['still a cat', f, note.id]);
  assert.equal((await ann.sql('SELECT attachment FROM notes WHERE id = ?', [note.id]))[0].attachment.id, f.id);
  // uploads: at most app.files.maxSize, only for someone signed in, only from allowed pages
  await assert.rejects(ann.files.upload(new Blob([bytes(17 << 20)])), (e) => e.code === 'ARGUMENTS' && /larger than/.test(e.message));
  assert.equal((await fetch(`${url}/api/files?name=x`, { method: 'POST', body: 'x' })).status, 401);
  assert.equal((await fetch(`${url}/api/files?name=x`, { method: 'POST', body: 'x', headers: { origin: 'https://evil.example', authorization: `Bearer ${a.token}` } })).status, 403);
  // a GROUP BY or an expression over a file gives its id, not a link
  assert.equal(typeof (await ann.sql('SELECT coalesce(attachment, attachment) AS f FROM notes'))[0].f, 'string');
  live.close();
  console.log('files: ok');

  // ---- costs
  let lat = []; const small = bytes(100 << 10); let last;
  for (let i = 0; i < 200; i++) { const t = process.hrtime.bigint(); last = await ann.files.upload(new Blob([small], { type: 'image/jpeg' })); lat.push(ms(t)); }
  pr('upload 100 KB (one at a time)', `p50 ${pct(lat, 0.5).toFixed(2)} ms, p99 ${pct(lat, 0.99).toFixed(2)} ms`);
  lat = [];
  for (let i = 0; i < 200; i++) { const t = process.hrtime.bigint(); const res = await fetch(last.url); await res.arrayBuffer(); lat.push(ms(t)); }
  pr('download 100 KB', `p50 ${pct(lat, 0.5).toFixed(2)} ms, p99 ${pct(lat, 0.99).toFixed(2)} ms`);
  const big = bytes(10 << 20); let t = process.hrtime.bigint(); const bf = await ann.files.upload(new Blob([big]));
  const up = ms(t); t = process.hrtime.bigint(); const got = Buffer.from(await (await fetch(bf.url)).arrayBuffer()); const down = ms(t);
  assert.ok(got.equals(big));
  pr('10 MB: upload, download', `${up.toFixed(0)} ms (${(10 / up * 1000).toFixed(0)} MB/s), ${down.toFixed(0)} ms (${(10 / down * 1000).toFixed(0)} MB/s)`);
  t = process.hrtime.bigint(); for (let i = 0; i < 200; i++) await ann.sql('SELECT id, attachment FROM notes WHERE id = ?', [note.id]);
  pr('a query returning a file (and signing its link), over the socket', `${(ms(t) / 200 * 1000).toFixed(0)} µs each`);
} finally {
  server.kill('SIGTERM'); await new Promise((r) => server.on('exit', r));
  fs.rmSync(dir, { recursive: true, force: true }); fs.rmSync(`${dir}.toml`, { force: true });
}
process.exit(0);
