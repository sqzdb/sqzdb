// E57: OAuth sign-in from Node against a local OpenID Connect provider written here with Node's own crypto (so the
// engine's ID-token checks meet an independent JWT signer). Checks the flow end to end, then measures oauthFinish:
// the first (signing keys fetched), and later ones (keys cached).
const { open } = require('./index.js');
const http = require('http'); const crypto = require('crypto'); const fs = require('fs'); const assert = require('assert');

const key = crypto.createPrivateKey({ key: fs.readFileSync(__dirname + '/../../src/testdata/oauth_test_rsa.der'), format: 'der', type: 'pkcs1' });
const jwk = { ...crypto.createPublicKey(key).export({ format: 'jwk' }), kid: 'node-1', alg: 'RS256' };
const b64 = (b) => Buffer.from(b).toString('base64url');
const sign = (claims) => { const h = b64(JSON.stringify({ alg: 'RS256', kid: 'node-1' })), p = b64(JSON.stringify(claims)); return `${h}.${p}.${b64(crypto.sign('sha256', Buffer.from(`${h}.${p}`), key))}`; };
const grants = new Map(); let jwksHits = 0;

const server = http.createServer((req, res) => {
  let body = ''; req.on('data', (c) => (body += c)); req.on('end', () => {
    const send = (code, obj) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); };
    if (req.url === '/jwks') { jwksHits++; return send(200, { keys: [jwk] }); }
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

server.listen(0, '127.0.0.1', async () => {
  const port = server.address().port; const base = `http://127.0.0.1:${port}`;
  const dir = '../../data/nocow/e57'; fs.rmSync(dir, { recursive: true, force: true });
  const db = open(dir, { auth: { oauth: { idp: { kind: 'oidc', clientId: 'node-client', clientSecret: 'node-secret', authUrl: `${base}/authorize`, tokenUrl: `${base}/token`, jwksUrl: `${base}/jwks`, issuer: 'https://idp.test' } } } });
  for (const s of ["CREATE TABLE users (id SERIAL PRIMARY KEY, email TEXT UNIQUE, role TEXT DEFAULT 'member')", 'CREATE ROLE member', 'ALTER TABLE users ENABLE AUTH (ROLE FROM role)']) db.exec(s);
  const auth = db.auth('users');
  // the browser's part: the provider page approved and redirects back with a code
  const approve = (url, code, sub, email) => { const q = new URL(url).searchParams; grants.set(code, { challenge: q.get('code_challenge'), nonce: q.get('nonce'), sub, email }); return q.get('state'); };
  try {
    const st = auth.oauthStart('idp', 'http://127.0.0.1:3000/cb');
    assert.ok(st.url.startsWith(`${base}/authorize?`) && new URL(st.url).searchParams.get('state') === st.state);
    await assert.rejects(auth.oauthFinish('idp', 'code-1', approve(st.url, 'code-1', 'user-1', 'Ann@IdP.test'), 'not the cookie'), (e) => e.code === 'AUTH');   // another browser
    const first = await auth.oauthFinish('idp', 'code-1', st.state, st.cookie);
    assert.strictEqual(first.created, true); assert.strictEqual(first.user.email, 'ann@idp.test');
    assert.ok(db.session(first.token).all('SELECT 1 AS one')[0].one === 1);
    await assert.rejects(auth.oauthFinish('idp', 'code-1', st.state, st.cookie), (e) => e.code === 'AUTH');   // the state was used
    console.log('API checks: ok');
    const N = 200; const t0 = process.hrtime.bigint(); const lat = [];
    for (let i = 0; i < N; i++) {
      const s = auth.oauthStart('idp', 'http://127.0.0.1:3000/cb'); const a = process.hrtime.bigint();
      const r = await auth.oauthFinish('idp', `c${i}`, approve(s.url, `c${i}`, `user-${i % 50}`, `u${i % 50}@idp.test`), s.cookie);
      lat.push(Number(process.hrtime.bigint() - a) / 1e6); if (i >= 50) assert.strictEqual(r.created, false);
    }
    lat.sort((a, b) => a - b);
    console.log(`oauthFinish x${N} (50 users, then returning):`.padEnd(64), `p50 ${lat[N >> 1].toFixed(2)} ms, p99 ${lat[Math.floor(N * 0.99)].toFixed(2)} ms; JWKS fetched ${jwksHits}x`);
  } finally { db.close(); server.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});
