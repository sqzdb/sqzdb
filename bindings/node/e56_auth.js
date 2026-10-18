// E56: sign-in from Node. Checks the API end to end, then measures: sign-up, sign-in (sequential and 200 at once),
// db.session(token) per request, a per-user query through row policies, and how long the event loop stalls while
// sign-ins run (they hash off the JavaScript thread).
const { open } = require('./index.js');
const fs = require('fs');
const assert = require('assert');

const dir = '../../data/nocow/e56'; fs.rmSync(dir, { recursive: true, force: true });
const db = open(dir);
for (const s of [
  "CREATE TABLE users (id SERIAL PRIMARY KEY, email TEXT UNIQUE, name TEXT, role TEXT DEFAULT 'member', tenant INT)",
  'CREATE TABLE notes (id SERIAL PRIMARY KEY, owner INT, body TEXT)',
  'CREATE ROLE member', 'GRANT SELECT, INSERT ON notes TO member',
  'CREATE POLICY own ON notes FOR ALL TO member USING (owner = SESSION.id)',
  'ALTER TABLE users ENABLE AUTH (ROLE FROM role)',
]) db.exec(s);
const now = () => Number(process.hrtime.bigint()) / 1e6;
const pct = (xs, p) => { const s = [...xs].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.floor(s.length * p))]; };
const pr = (label, v) => console.log(label.padEnd(64), v);

(async () => {
  // the API end to end
  const auth = db.auth('users');
  const ann = await auth.signUp({ email: 'Ann@Example.com', name: 'Ann', tenant: 7 }, 'correct horse');
  assert.match(ann.token, /^sqz_[0-9a-f]{64}$/); assert.strictEqual(ann.user.email, 'ann@example.com'); assert.strictEqual(ann.user.tenant, 7);
  const annDb = db.session(ann.token);
  annDb.run('INSERT INTO notes (owner, body) VALUES (?, ?)', [ann.user.id, 'mine']);
  db.run('INSERT INTO notes (owner, body) VALUES (99, ?)', ['someone else']);
  assert.deepStrictEqual(annDb.all('SELECT body FROM notes'), [{ body: 'mine' }]);
  await assert.rejects(auth.signIn('ann@example.com', 'wrong'), (e) => e.code === 'AUTH');
  await assert.rejects(auth.signIn('nobody@example.com', 'correct horse'), (e) => e.code === 'AUTH');
  await assert.rejects(auth.signUp({ email: 'x@y' }, 'short'), (e) => e.code === 'TYPE');
  const again = await auth.signIn('ANN@example.com', 'correct horse');
  auth.signOut(again.token); assert.throws(() => db.session(again.token), (e) => e.code === 'AUTH');
  await auth.setPassword(ann.user.id, 'new password');
  assert.throws(() => db.session(ann.token), (e) => e.code === 'AUTH');
  assert.throws(() => db.all('SELECT * FROM _auth_secrets'), (e) => e.code === 'SCHEMA');
  console.log('API checks: ok');

  // costs
  const N = 300; let t = now();
  for (let i = 0; i < N; i++) await auth.signUp({ email: `u${i}@example.com`, name: `u${i}` }, 'the password');
  pr(`sign-up, one at a time (${N})`, `${((now() - t) / N).toFixed(2)} ms each`);
  const lat = []; for (let i = 0; i < N; i++) { const a = now(); await auth.signIn(`u${i}@example.com`, 'the password'); lat.push(now() - a); }
  pr('sign-in, one at a time', `p50 ${pct(lat, 0.5).toFixed(2)} ms, p99 ${pct(lat, 0.99).toFixed(2)} ms`);
  const lat2 = []; for (let i = 0; i < 100; i++) { const a = now(); await auth.signIn(`u${i}@example.com`, 'wrong password').catch(() => {}); lat2.push(now() - a); }
  const lat3 = []; for (let i = 0; i < 100; i++) { const a = now(); await auth.signIn(`ghost${i}@example.com`, 'the password').catch(() => {}); lat3.push(now() - a); }
  pr('failed sign-in: wrong password / unknown login', `p50 ${pct(lat2, 0.5).toFixed(2)} ms / ${pct(lat3, 0.5).toFixed(2)} ms`);
  // 200 sign-ins at once, with a timer watching the event loop
  let worst = 0, last = now(); const timer = setInterval(() => { const n = now(); worst = Math.max(worst, n - last - 1); last = n; }, 1);
  t = now(); const many = await Promise.all(Array.from({ length: 200 }, (_, i) => auth.signIn(`u${i}@example.com`, 'the password')));
  const el = now() - t; clearInterval(timer);
  pr('200 sign-ins at once', `${el.toFixed(0)} ms (${(200 / el * 1000).toFixed(0)}/s); event loop stalled at most ${worst.toFixed(1)} ms`);
  // per request: a session from the token, then one query through the policy
  const tokens = many.map((m) => m.token); const R = 100_000;
  t = now(); for (let i = 0; i < R; i++) db.session(tokens[i % tokens.length]); const sessUs = (now() - t) * 1000 / R;
  pr('db.session(token)', `${sessUs.toFixed(2)} µs`);
  t = now(); for (let i = 0; i < R; i++) db.as({ role: 'member', id: i % 200 + 2 }); pr('db.as({ role, id }) for comparison', `${((now() - t) * 1000 / R).toFixed(2)} µs`);
  for (let i = 0; i < 200; i++) db.run('INSERT INTO notes (owner, body) VALUES (?, ?)', [many[i].user.id, `note ${i}`]);
  t = now(); for (let i = 0; i < R; i++) { const u = db.session(tokens[i % tokens.length]); assert.strictEqual(u.all('SELECT body FROM notes WHERE id = ?', [i % 200 + 3]).length <= 1, true); }
  pr('db.session(token) + a point read through the policy', `${((now() - t) * 1000 / R).toFixed(2)} µs`);
  db.close(); fs.rmSync(dir, { recursive: true, force: true });
})().catch((e) => { console.error(e); process.exit(1); });
