// E60: TLS for the app API.
// 1. Your own certificate: the JS client signs in, runs SQL and keeps live queries over https and wss; plain HTTP to
//    the port gets nothing; asking for acme-tls/1 with no challenge pending gets no certificate; the redirect
//    listener sends browsers to https on the configured host only. Costs: point reads, memory per TLS connection.
// 2. A certificate from an ACME CA, as with Let's Encrypt: Pebble, Let's Encrypt's test CA, issues it after checking
//    the domain over TLS-ALPN-01 on the app API's own port; a restart serves the stored one; a certificate valid for
//    90 seconds is renewed before it ends, with no restart. Build Pebble with
//      GOBIN=<dir> go install github.com/letsencrypt/pebble/v2/cmd/pebble@v2.10.1 github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@v2.10.1
//    and run `node e60_tls.mjs <dir>` (part 2 is skipped without it).
import { connect } from './index.js';
import { spawn, execFileSync } from 'node:child_process';
import fs from 'node:fs'; import assert from 'node:assert/strict'; import net from 'node:net'; import http from 'node:http'; import https from 'node:https'; import tls from 'node:tls';

const BIN = new URL('../../target/release/sqzdb', import.meta.url).pathname;
const SCHEMA = new URL('../../demos/notes/schema.sql', import.meta.url).pathname;
const WORK = new URL('../../data/nocow/e60', import.meta.url).pathname;
const freePort = () => new Promise((r) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
const ms = (t) => Number(process.hrtime.bigint() - t) / 1e6;
const pct = (xs, p) => { const s = [...xs].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.floor(s.length * p))]; };
const pr = (label, v) => console.log(label.padEnd(64), v);
const sleep = (t) => new Promise((r) => setTimeout(r, t));

// the JS client's fetch and WebSocket trust the system's roots plus NODE_EXTRA_CA_CERTS, read at start: make the
// certificate, then run the rest in a child that trusts it
if (!process.env.E60_CERT) {
  fs.rmSync(WORK, { recursive: true, force: true }); fs.mkdirSync(WORK, { recursive: true });
  const cert = `${WORK}/cert.pem`, key = `${WORK}/key.pem`;
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', key, '-out', cert, '-days', '30', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'ignore' });
  const child = spawn(process.execPath, [new URL(import.meta.url).pathname, ...process.argv.slice(2)], { stdio: 'inherit', env: { ...process.env, E60_CERT: cert, E60_KEY: key, NODE_EXTRA_CA_CERTS: cert } });
  const code = await new Promise((r) => child.on('exit', r)); fs.rmSync(WORK, { recursive: true, force: true }); process.exit(code);
}

/** Start `sqzdb serve` on a fresh copy of the notes schema; resolves once it prints its app API line. */
async function serve(dir, port, toml, { fresh = true } = {}) {
  if (fresh) { fs.rmSync(dir, { recursive: true, force: true }); execFileSync(BIN, ['shell', dir], { input: fs.readFileSync(SCHEMA), stdio: ['pipe', 'ignore', 'inherit'] }); }
  fs.writeFileSync(`${dir}.toml`, toml);
  const p = spawn(BIN, ['serve', dir, '--app', `127.0.0.1:${port}`, '--config', `${dir}.toml`], { stdio: ['ignore', 'pipe', 'pipe'] });
  p.log = ''; p.stderr.on('data', (d) => { p.log += d; });
  p.banner = await new Promise((r, j) => { let out = ''; p.stdout.on('data', (d) => { out += d; if (out.includes('app API')) r(out); }); p.on('exit', () => j(new Error(`serve exited: ${p.log}`))); });
  p.waitLog = async (re, after, secs) => { const t = Date.now(); while (!re.test(p.log.slice(after))) { if (Date.now() - t > secs * 1000) throw new Error(`no ${re} in ${secs} s: ${p.log}`); await sleep(100); } };
  return p;
}
const stop = async (p) => { p.kill('SIGTERM'); await new Promise((r) => p.on('exit', r)); };
const rss = (pid) => Number(fs.readFileSync(`/proc/${pid}/status`, 'utf8').match(/VmRSS:\s+(\d+)/)[1]) / 1024;
/** The certificate a TLS server at 127.0.0.1:port presents for `servername`, checked against `ca`. */
const peer = (port, servername, ca, alpn) => new Promise((resolve, reject) => {
  const s = tls.connect({ host: '127.0.0.1', port, servername, ca, ...(alpn ? { ALPNProtocols: alpn } : {}) }, () => { const c = s.getPeerCertificate(); s.end(); resolve(c); });
  s.on('error', reject);
});
const getVia = (port, servername, ca, path) => new Promise((resolve, reject) => {
  https.get({ host: '127.0.0.1', port, servername, ca, path, headers: { 'user-agent': 'e60' } }, (res) => { let b = ''; res.on('data', (c) => { b += c; }); res.on('end', () => resolve({ status: res.statusCode, body: b })); }).on('error', reject);
});

// ---------- 1. your own certificate ----------
{
  const port = await freePort(), rport = await freePort(), url = `https://localhost:${port}`, dir = `${WORK}/own`;
  const ca = fs.readFileSync(process.env.E60_CERT);
  const server = await serve(dir, port, `[app]\npublicUrl = "${url}"\n\n[app.signUp]\nusers = ["name"]\n\n[app.tls]\ncert = "${process.env.E60_CERT}"\nkey = "${process.env.E60_KEY}"\nredirect = "127.0.0.1:${rport}"\n`);
  try {
    assert.match(server.banner, new RegExp(`app API: +${url}/api/ +\\(on 127.0.0.1:${port}, your certificate\\)`));
    const a = connect(url, { storage: null }); const me = await a.auth.signUp({ email: 'a@x.test', name: 'A' }, 'the password 1');
    const b = connect(url, { storage: null }); await b.auth.signIn('a@x.test', 'the password 1');
    let seen = null; const live = b.live('SELECT id, body FROM notes ORDER BY id DESC LIMIT 1', (rows, i) => { if (!i.initial && seen) seen(rows[0]); });
    await sleep(100);
    const got = new Promise((r) => { seen = r; }); await a.sql('INSERT INTO notes (owner, body) VALUES (?, ?)', [me.user.id, 'over wss']);
    assert.equal((await got).body, 'over wss');
    assert.deepEqual(await a.sql('SELECT count(*) AS n FROM notes'), [{ n: 1 }]);
    // plain HTTP to the TLS port gets no answer
    await assert.rejects(fetch(`http://127.0.0.1:${port}/api/auth/users/methods`));
    // a client asking for acme-tls/1 when no CA is checking gets no certificate
    await assert.rejects(peer(port, 'localhost', ca, ['acme-tls/1']));
    // http -> https, to the configured host whatever the request names
    const redirect = (host, path) => new Promise((r) => http.get({ host: '127.0.0.1', port: rport, path, headers: { host } }, (res) => { res.resume(); r([res.statusCode, res.headers.location]); }));
    assert.deepEqual(await redirect('localhost', '/notes?x=1'), [308, `${url}/notes?x=1`]);
    assert.deepEqual(await redirect('evil.example', '/'), [308, `${url}/`]);
    live.close(); b.close();
    console.log('own certificate: ok');
    // costs
    let lat = [];
    for (let i = 0; i < 2000; i++) { const t = process.hrtime.bigint(); await a.sql('SELECT body FROM notes WHERE id = ?', [1]); lat.push(ms(t)); }
    pr('SQL point read over wss', `p50 ${pct(lat, 0.5).toFixed(3)} ms, p99 ${pct(lat, 0.99).toFixed(3)} ms`);
    lat = [];
    for (let i = 0; i < 2000; i++) { const t = process.hrtime.bigint(); const r = await fetch(`${url}/api/sql`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${me.token}` }, body: JSON.stringify({ sql: 'SELECT body FROM notes WHERE id = ?', params: [1] }) }); await r.json(); lat.push(ms(t)); }
    pr('SQL point read over https (fetch, keep-alive)', `p50 ${pct(lat, 0.5).toFixed(3)} ms, p99 ${pct(lat, 0.99).toFixed(3)} ms`);
    await sleep(300); const before = rss(server.pid); const N = 500; const devices = [];
    const kept = JSON.stringify({ token: me.token, user: me.user });
    let ready = 0; await new Promise((done) => {
      for (let i = 0; i < N; i++) {
        const d = connect(url, { storage: { getItem: () => kept, setItem() {}, removeItem() {} } }); devices.push(d);
        d.live('SELECT id, body FROM notes ORDER BY id DESC LIMIT 10', () => { if (++ready === 2 * N) done(); });
        d.live('SELECT count(*) AS n FROM notes', () => { if (++ready === 2 * N) done(); });
      }
    });
    await sleep(500);
    pr(`server memory, ${N} devices on wss with 2 live queries each`, `${rss(server.pid).toFixed(0)} MB (${before.toFixed(0)} MB before; ${((rss(server.pid) - before) * 1024 / N).toFixed(0)} KB per device)`);
    for (const d of devices) d.close(); a.close();
  } finally { await stop(server); }
}

// ---------- 2. a certificate from an ACME CA (Pebble) ----------
const PEBBLE = process.argv[2];
if (!PEBBLE) { console.log('ACME: skipped (pass the directory holding pebble and pebble-challtestsrv)'); process.exit(0); }
{
  const certs = execFileSync('go', ['env', 'GOMODCACHE']).toString().trim() + '/github.com/letsencrypt/pebble/v2@v2.10.1/test/certs';
  const minica = fs.readFileSync(`${certs}/pebble.minica.pem`);
  const [acmePort, mgmtPort, dnsPort, dnsMgmt, httpPort, port] = await Promise.all(Array.from({ length: 6 }, freePort));
  const domain = 'api.notes.test', dir = `${WORK}/acme`;
  const dns = spawn(`${PEBBLE}/pebble-challtestsrv`, ['-dnsserver', `127.0.0.1:${dnsPort}`, '-defaultIPv4', '127.0.0.1', '-defaultIPv6', '', '-http01', '', '-https01', '', '-tlsalpn01', '', '-doh', '', '-management', `127.0.0.1:${dnsMgmt}`], { stdio: 'ignore' });
  fs.writeFileSync(`${WORK}/pebble.json`, JSON.stringify({ pebble: { listenAddress: `127.0.0.1:${acmePort}`, managementListenAddress: `127.0.0.1:${mgmtPort}`, certificate: `${certs}/localhost/cert.pem`, privateKey: `${certs}/localhost/key.pem`,
    httpPort, tlsPort: port, ocspResponderURL: '', externalAccountBindingRequired: false, retryAfter: { authz: 1, order: 1 }, keyAlgorithm: 'ecdsa', profiles: { default: { description: '90 seconds', validityPeriod: 90 } } } }));
  const pebbleLog = fs.openSync(`${WORK}/pebble.log`, 'w');
  const pebble = spawn(`${PEBBLE}/pebble`, ['-config', `${WORK}/pebble.json`, '-dnsserver', `127.0.0.1:${dnsPort}`], { stdio: ['ignore', pebbleLog, pebbleLog], env: { ...process.env, PEBBLE_VA_NOSLEEP: '1', PEBBLE_WFE_NONCEREJECT: '0' } });
  let server;
  try {
    for (let i = 0; ; i++) { try { if ((await getVia(acmePort, 'localhost', minica, '/dir')).status === 200) break; } catch {} if (i > 100) throw new Error(`Pebble did not start: ${fs.readFileSync(`${WORK}/pebble.log`, 'utf8')}`); await sleep(100); }
    const toml = `[app.signUp]\nusers = ["name"]\n\n[app.tls]\ndomains = ["${domain}"]\nemail = "ops@notes.test"\nacme = "https://localhost:${acmePort}/dir"\nacmeRoot = "${certs}/pebble.minica.pem"\n`;
    let t = process.hrtime.bigint();
    server = await serve(dir, port, toml);
    assert.match(server.banner, new RegExp(`app API: +https://${domain}:${port}/api/ +\\(on 127.0.0.1:${port}, certificate from localhost:${acmePort}\\)`));
    await server.waitLog(/tls: certificate for api\.notes\.test/, 0, 60);
    pr('a certificate from the CA, from start (account, order, TLS-ALPN-01, issue)', `${(ms(t) / 1000).toFixed(2)} s`);
    const root = (await getVia(mgmtPort, 'localhost', minica, '/roots/0')).body;
    const first = await peer(port, domain, root);
    assert.match(first.issuer.CN, /Pebble/); assert.equal(first.subjectaltname, `DNS:${domain}`);
    const methods = await getVia(port, domain, root, '/api/auth/users/methods'); assert.equal(methods.status, 200); assert.deepEqual(JSON.parse(methods.body), { signUp: true, providers: [] });
    // the key and the certificate are the owner's alone
    for (const f of ['account.json', 'certificate.json']) assert.equal(fs.statSync(`${dir}/tls/${f}`).mode & 0o777, 0o600, f);
    assert.equal(fs.statSync(`${dir}/tls`).mode & 0o777, 0o700);
    // a restart serves the stored certificate, without asking the CA
    await stop(server); t = process.hrtime.bigint();
    server = await serve(dir, port, toml, { fresh: false });
    await server.waitLog(/serving the stored certificate/, 0, 5);
    assert.equal((await peer(port, domain, root)).serialNumber, first.serialNumber);
    pr('restart: the stored certificate served', `${ms(t).toFixed(0)} ms from start to its banner`);
    // renewal, with a third of the 90 s left, while it serves
    const mark = server.log.length; t = process.hrtime.bigint();
    await server.waitLog(/tls: certificate for api\.notes\.test/, mark, 120);
    const second = await peer(port, domain, root);
    assert.notEqual(second.serialNumber, first.serialNumber);
    assert.ok(new Date(second.valid_to) > new Date(first.valid_to));
    pr('renewed with no restart', `${(ms(t) / 1000).toFixed(0)} s after the restart (certificate ${first.valid_from} .. ${first.valid_to})`);
    console.log('ACME: ok');
  } finally { if (server) await stop(server); pebble.kill(); dns.kill(); }
}
