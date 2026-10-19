// E62: vectors through the app API. Notes are embedded in the background by an OpenAI-style endpoint (a fake one
// here, counting words in 64 buckets so notes sharing words are near); the client searches by meaning with
// embed(?), keeps a live search, reads vectors as arrays and passes them as parameters; the generated column takes
// no writes from clients. Costs: from a write to the live search showing it, and exact search over 10,000 and
// 100,000 vectors of 384 numbers.
import { connect } from './index.js';
import { spawn, execFileSync } from 'node:child_process';
import fs from 'node:fs'; import assert from 'node:assert/strict'; import net from 'node:net'; import http from 'node:http';

const BIN = new URL('../../target/release/sqzdb', import.meta.url).pathname;
const dir = new URL('../../data/nocow/e62', import.meta.url).pathname; fs.rmSync(dir, { recursive: true, force: true });
const free = () => new Promise((r) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
const ms = (t) => Number(process.hrtime.bigint() - t) / 1e6;
const pct = (xs, p) => { const s = [...xs].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.floor(s.length * p))]; };
const pr = (label, v) => console.log(label.padEnd(64), v);
const sleep = (t) => new Promise((r) => setTimeout(r, t));

// the endpoint: POST /v1/embeddings { model, input: [...] } -> { data: [{ index, embedding }] }
let calls = 0, texts = 0;
const vec = (t) => { const v = new Array(64).fill(0); for (const w of t.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean)) { let h = 7; for (const c of w) h = (h * 31 + c.charCodeAt(0)) >>> 0; v[h % 64] += 1; } return v; };
const endpoint = http.createServer((req, res) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => {
  const { input } = JSON.parse(b); calls++; texts += input.length;
  res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ data: input.map((t, index) => ({ index, embedding: vec(t) })) }));
}); });
await new Promise((r) => endpoint.listen(0, '127.0.0.1', r));
const port = await free(), url = `http://127.0.0.1:${port}`;
fs.writeFileSync(`${dir}.toml`, `[app.signUp]\nusers = []\n\n[embed]\nurl = "http://127.0.0.1:${endpoint.address().port}/v1"\nmodel = "fake"\n`);
execFileSync(BIN, ['shell', dir], { input: [
  "CREATE TABLE users (id SERIAL PRIMARY KEY, email TEXT UNIQUE, role TEXT DEFAULT 'member');",
  'CREATE TABLE notes (id SERIAL PRIMARY KEY, owner INT NOT NULL, body TEXT, embedding VECTOR(64) GENERATED ALWAYS AS (embed(body)) STORED);',
  'CREATE TABLE docs (id SERIAL PRIMARY KEY, owner INT NOT NULL, e VECTOR(384));',
  'CREATE ROLE member;', 'GRANT SELECT, INSERT, UPDATE, DELETE ON notes TO member;', 'GRANT SELECT, INSERT ON docs TO member;',
  'CREATE POLICY own ON notes FOR ALL TO member USING (owner = SESSION.id);', 'CREATE POLICY own_docs ON docs FOR ALL TO member USING (owner = SESSION.id);',
  'ALTER TABLE users ENABLE AUTH (ROLE FROM role);', ''].join('\n'), stdio: ['pipe', 'ignore', 'ignore'] });
const server = spawn(BIN, ['serve', dir, '--app', `127.0.0.1:${port}`, '--config', `${dir}.toml`], { stdio: ['ignore', 'pipe', 'inherit'] });
await new Promise((r) => server.stdout.on('data', (d) => { if (String(d).includes('app API')) r(); }));

try {
  const ann = connect(url, { storage: null }); const a = await ann.auth.signUp({ email: 'ann@x.test' }, 'the password 1');
  const bob = connect(url, { storage: null }); const b = await bob.auth.signUp({ email: 'bob@x.test' }, 'the password 1');
  const notes = ['my cat eats fish every morning', 'a train to lisbon in may', 'the quarterly report numbers', 'fish and chips for dinner', 'my cat sleeps on the sofa'];
  for (const n of notes) await ann.sql('INSERT INTO notes (owner, body) VALUES (?, ?)', [a.user.id, n]);
  await bob.sql('INSERT INTO notes (owner, body) VALUES (?, ?)', [b.user.id, 'bob: my cat and my other cat']);
  const embedded = async (c) => { for (let i = 0; i < 200; i++) { if ((await c.sql('SELECT count(*) AS n FROM notes WHERE embedding IS NULL'))[0].n === 0) return; await sleep(20); } throw new Error('not embedded'); };
  await embedded(ann); await embedded(bob);
  // search by meaning, under the policy
  // (a note not embedded yet has a NULL distance, which sorts first: a search leaves those out)
  const search = 'SELECT body, cosine_distance(embedding, embed(?)) AS d FROM notes WHERE embedding IS NOT NULL ORDER BY d LIMIT 3';
  const found = await ann.sql(search, ['cat']);
  assert.deepEqual(found.slice(0, 2).map((r) => r.body).sort(), ['my cat eats fish every morning', 'my cat sleeps on the sofa']);
  assert.ok(found.every((r) => !r.body.startsWith('bob')), 'Ann never sees Bob\'s notes');
  assert.ok(found[0].d < found[2].d);
  // however it is written (a space, a comment), embed() runs off the server's async threads
  assert.equal((await ann.sql('SELECT body FROM notes WHERE embedding IS NOT NULL ORDER BY cosine_distance(embedding, embed /* x */ (?)) LIMIT 1', ['cat']))[0].body.includes('cat'), true);
  // a vector comes back as numbers, and goes in as an array
  const [one] = await ann.sql('SELECT embedding FROM notes WHERE body = ?', [notes[0]]);
  assert.equal(one.embedding.length, 64); assert.ok(one.embedding.every((x) => typeof x === 'number'));
  assert.equal((await ann.sql('SELECT body, l2_distance(embedding, ?) AS d FROM notes ORDER BY d LIMIT 1', [one.embedding]))[0].body, notes[0]);
  // the generated column is the database's to write
  await assert.rejects(ann.sql('INSERT INTO notes (owner, body, embedding) VALUES (?, ?, ?)', [a.user.id, 'x', one.embedding]), (e) => e.code === 'DENIED');
  await assert.rejects(ann.sql('UPDATE notes SET embedding = ? WHERE body = ?', [one.embedding, notes[1]]), (e) => e.code === 'DENIED');
  // a live search: a new note about cats joins the result once it is embedded
  let wake = null, last = null; const live = ann.live(search, ['cat'], (rows) => { last = rows; wake?.(); });
  await sleep(100);
  const lat = [];
  for (let i = 0; i < 20; i++) {
    const body = `cat note ${i} cat`; const seen = new Promise((r) => { wake = () => { if (last?.some((x) => x.body === body)) r(); }; });
    const t = process.hrtime.bigint(); await ann.sql('INSERT INTO notes (owner, body) VALUES (?, ?)', [a.user.id, body]); await seen; lat.push(ms(t));
    await ann.sql('DELETE FROM notes WHERE body = ?', [body]); await sleep(30);
  }
  live.close();
  console.log('vectors: ok');
  assert.ok(texts >= 7 + 20, `every new note embedded (${texts} texts)`);
  pr('write -> embedded -> in the live search (the fake endpoint takes ~0)', `p50 ${pct(lat, 0.5).toFixed(1)} ms, p99 ${pct(lat, 0.99).toFixed(1)} ms`);
  pr('the endpoint, for all of the above', `${calls} requests, ${texts} texts`);

  // ---- exact search over many vectors of 384 numbers
  const rnd = () => Array.from({ length: 384 }, () => Math.random() - 0.5);
  let have = 0;
  for (const n of [10_000, 100_000]) {
    for (; have < n; have += 100) await ann.batch(Array.from({ length: 100 }, () => ['INSERT INTO docs (owner, e) VALUES (?, ?)', [a.user.id, rnd()]]));
    const xs = [];
    for (let i = 0; i < 30; i++) { const q = rnd(); const t = process.hrtime.bigint(); const r = await ann.sql('SELECT id, cosine_distance(e, ?) AS d FROM docs ORDER BY d LIMIT 10', [q]); xs.push(ms(t)); assert.equal(r.length, 10); }
    pr(`nearest 10 of ${n.toLocaleString('en-US')} vectors (384 numbers), exact`, `p50 ${pct(xs, 0.5).toFixed(1)} ms, p99 ${pct(xs, 0.99).toFixed(1)} ms`);
  }
} finally {
  server.kill('SIGTERM'); await new Promise((r) => server.on('exit', r)); endpoint.close();
  fs.rmSync(dir, { recursive: true, force: true }); fs.rmSync(`${dir}.toml`, { force: true });
}
process.exit(0);
