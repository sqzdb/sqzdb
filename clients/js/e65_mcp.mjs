// E65: agents over MCP, signed in through the app API's own OAuth server. Part 1 walks the flow the MCP
// specification describes, with every check along it: discovery, registration, the sign-in and consent pages, PKCE,
// tokens bound to /mcp, rotation, revocation, a password change. Part 2 connects the official TypeScript SDK's client
// (taken from another project's node_modules, given as SDK=...), which runs the same flow on its own. Costs: a tool
// call, and the whole connection.
import { spawn, execFileSync } from 'node:child_process';
import fs from 'node:fs'; import assert from 'node:assert/strict'; import net from 'node:net'; import crypto from 'node:crypto';

const BIN = new URL('../../target/release/sqzdb', import.meta.url).pathname;
const SDK = process.env.SDK || '/home/iluxa/Projects/cyberdom/node_modules/@modelcontextprotocol/sdk/dist/esm';
const dir = new URL('../../data/nocow/e65', import.meta.url).pathname; fs.rmSync(dir, { recursive: true, force: true });
const port = await new Promise((r) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
const base = `http://127.0.0.1:${port}`;
fs.writeFileSync(`${dir}.toml`, `[app]\npublicUrl = "${base}"\n\n[app.signUp]\nusers = []\n\n[app.mcp]\n`);
execFileSync(BIN, ['shell', dir], { input: [
  "CREATE TABLE users (id SERIAL PRIMARY KEY, email TEXT UNIQUE, role TEXT DEFAULT 'member');",
  'CREATE TABLE jobs (id SERIAL PRIMARY KEY, owner INT NOT NULL, title TEXT, brief TEXT, status TEXT DEFAULT \'inbox\');',
  'CREATE ROLE member;', 'GRANT SELECT, INSERT, UPDATE ON jobs TO member;',
  'CREATE POLICY own ON jobs FOR ALL TO member USING (owner = SESSION.id);',
  'ALTER TABLE users ENABLE AUTH (ROLE FROM role);', ''].join('\n'), stdio: ['pipe', 'ignore', 'ignore'] });
const server = spawn(BIN, ['serve', dir, '--app', `127.0.0.1:${port}`, '--config', `${dir}.toml`], { stdio: ['ignore', 'pipe', 'inherit'] });
await new Promise((r) => server.stdout.on('data', (d) => { if (String(d).includes('app API')) r(); }));
const ms = (t) => Number(process.hrtime.bigint() - t) / 1e6;
const pr = (label, v) => console.log(label.padEnd(64), v);
const b64 = (b) => b.toString('base64url');
const post = (path, body, headers = {}) => fetch(base + path, { method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers }, body: typeof body === 'string' ? body : new URLSearchParams(body) });
const json = (path, v, headers = {}) => fetch(base + path, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(v) });
const requestId = (html) => html.match(/name="request" value="([0-9a-f]+)"/)[1];
// the browser: the cookie that binds a sign-in in progress to it, sent back on each step
const jar = new Map();
const keep = (res) => { for (const c of res.headers.getSetCookie?.() ?? []) { const [kv] = c.split(';'); const [k, v] = kv.split('='); if (v) jar.set(k, v); else jar.delete(k); } return res; };
const cookies = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
const page = (url) => fetch(url, { redirect: 'manual', headers: { cookie: cookies() } }).then(keep);
const step = (body) => post('/oauth/authorize', body, { cookie: cookies() }).then(keep);

try {
  // two users with jobs of their own
  for (const [email, title] of [['ann@x.test', "ann's job"], ['bob@x.test', "bob's job"]]) {
    const r = await json('/api/auth/users/sign-up', { fields: { email }, password: 'the password 1' }); const { token, user } = await r.json();
    await json('/api/sql', { sql: 'INSERT INTO jobs (owner, title, brief) VALUES (?, ?, ?)', params: [user.id, title, 'x'.repeat(300_000)] }, { authorization: `Bearer ${token}` });
  }

  // ---- part 1: the flow, step by step
  let r = await json('/mcp', { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
  assert.equal(r.status, 401); const www = r.headers.get('www-authenticate');
  assert.match(www, new RegExp(`^Bearer resource_metadata="${base}/.well-known/oauth-protected-resource/mcp"`));
  const prm = await (await fetch(`${base}/.well-known/oauth-protected-resource/mcp`)).json();
  assert.deepEqual([prm.resource, prm.authorization_servers], [`${base}/mcp`, [base]]);
  const asm = await (await fetch(`${base}/.well-known/oauth-authorization-server`)).json();
  assert.equal(asm.issuer, base); assert.deepEqual(asm.code_challenge_methods_supported, ['S256']);
  // registration: any agent may register; a redirect elsewhere than https or this machine is refused
  assert.equal((await json('/oauth/register', { redirect_uris: ['http://evil.example/cb'] })).status, 400);
  const redirect = 'http://localhost:7777/callback';
  const client = await (await json('/oauth/register', { client_name: 'Test <agent>', redirect_uris: [redirect] })).json();
  assert.match(client.client_id, /^mcpc_/); assert.equal(client.token_endpoint_auth_method, 'none');
  // authorize: PKCE, the page, the consent
  const verifier = b64(crypto.randomBytes(32)); const challenge = b64(crypto.createHash('sha256').update(verifier).digest());
  const q = (o) => '/oauth/authorize?' + new URLSearchParams({ response_type: 'code', client_id: client.client_id, redirect_uri: redirect, code_challenge: challenge, code_challenge_method: 'S256', state: 'st-1', resource: `${base}/mcp`, scope: 'sql', ...o });
  r = await page(base + q({ redirect_uri: 'https://elsewhere.example/cb' }));
  assert.equal(r.status, 400, 'an unregistered redirect gets a page, never a redirect');
  r = await page(base + q({ code_challenge_method: 'plain' }));
  assert.equal(r.status, 302); assert.match(r.headers.get('location'), /^http:\/\/localhost:7777\/callback\?error=invalid_request/);
  r = await page(base + q({})); let html = await r.text();
  assert.equal(r.status, 200); assert.match(html, /Test &lt;agent&gt;/, 'the name it gave itself, escaped');
  assert.match(r.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  const id = requestId(html);
  // the request's id alone is not enough: not to open it, not to sign in to it, not to allow it
  assert.match(await (await fetch(`${base}/oauth/authorize?request=${id}`)).text(), /another browser/);
  assert.match(await (await post('/oauth/authorize', { request: id, action: 'sign-in', login: 'ann@x.test', password: 'the password 1' })).text(), /another browser/);
  html = await (await step({ request: id, action: 'sign-in', login: 'ann@x.test', password: 'wrong password' })).text();
  assert.match(html, /wrong login or password/);
  html = await (await step({ request: id, action: 'sign-in', login: 'ann@x.test', password: 'the password 1' })).text();
  assert.match(html, /Allow Test &lt;agent&gt;\?/); assert.match(html, /Signed in as <b>ann@x.test<\/b>/);
  r = await post('/oauth/authorize', { request: id, action: 'allow' });
  assert.equal(r.status, 400, 'someone else holding the id cannot allow it once Ann signed in');
  r = await step({ request: id, action: 'allow' });
  assert.equal(r.status, 302); assert.ok(r.headers.get('location').endsWith('#'), 'a fragment from before is never carried on'); const back = new URL(r.headers.get('location'));
  assert.equal(back.origin + back.pathname, redirect); assert.equal(back.searchParams.get('state'), 'st-1'); assert.equal(back.searchParams.get('iss'), base);
  const code = back.searchParams.get('code');
  // the code: once, with its verifier, for its client
  const exchange = (o) => post('/oauth/token', { grant_type: 'authorization_code', code, redirect_uri: redirect, client_id: client.client_id, code_verifier: verifier, resource: `${base}/mcp`, ...o });
  assert.equal((await (await exchange({ code_verifier: b64(crypto.randomBytes(32)) })).json()).error, 'invalid_grant', 'a wrong verifier');
  assert.equal((await (await exchange({})).json()).error, 'invalid_grant', 'a code is gone after one attempt, whatever the verifier');
  // a fresh code for the rest
  const authorize = async (login) => {
    const v = b64(crypto.randomBytes(32)); const c = b64(crypto.createHash('sha256').update(v).digest());
    const html = await (await page(base + q({ code_challenge: c }))).text(); const rid = requestId(html);
    await step({ request: rid, action: 'sign-in', login, password: 'the password 1' });
    const loc = new URL((await step({ request: rid, action: 'allow' })).headers.get('location'));
    const t = await (await post('/oauth/token', { grant_type: 'authorization_code', code: loc.searchParams.get('code'), redirect_uri: redirect, client_id: client.client_id, code_verifier: v, resource: `${base}/mcp` })).json();
    assert.ok(t.access_token?.startsWith('sqzm_') && t.refresh_token?.startsWith('sqzr_'), JSON.stringify(t)); return t;
  };
  const t0 = process.hrtime.bigint(); let tokens = await authorize('ann@x.test'); const signInMs = ms(t0);
  assert.equal(tokens.token_type, 'Bearer'); assert.equal(tokens.expires_in, 3600);
  // MCP: initialize, tools, describe, query, execute, as Ann and under her policy
  let rpcId = 0;
  const mcp = async (method, params, token = tokens.access_token) => { const res = await json('/mcp', { jsonrpc: '2.0', id: ++rpcId, method, params }, { authorization: `Bearer ${token}`, 'mcp-protocol-version': '2025-06-18', accept: 'application/json, text/event-stream' }); return { status: res.status, body: res.status === 200 ? await res.json() : await res.text() }; };
  const init = await mcp('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'e65', version: '1' } });
  assert.equal(init.body.result.protocolVersion, '2025-06-18'); assert.ok(init.body.result.capabilities.tools);
  assert.equal((await json('/mcp', { jsonrpc: '2.0', method: 'notifications/initialized' }, { authorization: `Bearer ${tokens.access_token}` })).status, 202);
  const list = await mcp('tools/list', {}); assert.deepEqual(list.body.result.tools.map((t) => t.name), ['describe', 'query', 'execute']);
  const call = async (name, args, token) => (await mcp('tools/call', { name, arguments: args }, token)).body.result;
  const d = (await call('describe', {})).structuredContent;
  assert.equal(d.you.user, 'ann@x.test'); assert.deepEqual(d.tables.map((t) => [t.name, t.may.join(',')]), [['jobs', 'select,insert,update']]);
  assert.deepEqual(d.tables[0].policies, ['own: owner = SESSION.id']);
  const annId = d.you.session.id;
  let res = await call('query', { sql: 'SELECT id, title, length(brief) AS n FROM jobs' });
  assert.equal(res.isError, false); assert.deepEqual(res.structuredContent.rows, [{ id: 1, title: "ann's job", n: 300000 }], 'only her rows, a long brief included');
  res = await call('execute', { sql: 'INSERT INTO jobs (owner, title, brief) VALUES (?, ?, ?) RETURNING id', params: [annId, 'parked by an agent', '# Objective\n' + 'y'.repeat(200_000)] });
  assert.equal(res.isError, false, JSON.stringify(res));
  res = await call('execute', { statements: [{ sql: "UPDATE jobs SET status = 'ready' WHERE title = ?", params: ['parked by an agent'] }, { sql: 'INSERT INTO jobs (owner, title) VALUES (?, ?)', params: [annId, 'second'] }] });
  assert.equal(res.isError, false, JSON.stringify(res));
  assert.equal((await call('query', { sql: "SELECT count(*) AS n FROM jobs WHERE status = 'ready'" })).structuredContent.rows[0].n, 1);
  assert.equal((await call('execute', { sql: 'INSERT INTO jobs (owner, title) VALUES (2, ?)', params: ['into bob'] })).isError, true, "a row of Bob's: the policy refuses");
  assert.match((await call('query', { sql: 'DELETE FROM jobs' })).content[0].text, /SELECT/, 'query runs SELECT only');
  assert.match((await call('execute', { sql: 'DELETE FROM jobs' })).content[0].text, /permission denied/, 'no DELETE grant');
  assert.match((await call('execute', { sql: 'CREATE TABLE x (id INT PRIMARY KEY)' })).content[0].text, /INSERT, UPDATE and DELETE/);
  // tokens: bound to /mcp, refreshed with rotation, revoked, ended by a password change
  assert.equal((await json('/api/sql', { sql: 'SELECT 1' }, { authorization: `Bearer ${tokens.access_token}` })).status, 401, 'an MCP token is not an app session');
  const appToken = (await (await json('/api/auth/users/sign-in', { login: 'bob@x.test', password: 'the password 1' })).json()).token;
  assert.equal((await mcp('tools/list', {}, appToken)).status, 401, 'an app session is not an MCP token');
  const refresh = (rt) => post('/oauth/token', { grant_type: 'refresh_token', refresh_token: rt, client_id: client.client_id, resource: `${base}/mcp` }).then((x) => x.json());
  const next = await refresh(tokens.refresh_token); assert.ok(next.access_token && next.refresh_token !== tokens.refresh_token);
  assert.equal((await mcp('tools/list', {})).status, 401, 'a refresh ends the access token the old one came with');
  assert.equal((await mcp('tools/list', {}, next.access_token)).status, 200);
  const again = await refresh(tokens.refresh_token);
  assert.equal(again.error, 'invalid_grant'); assert.match(again.error_description, /used before/);
  assert.equal((await mcp('tools/list', {}, next.access_token)).status, 401, 'a refresh token used twice ends the whole sign-in');
  assert.equal((await refresh(next.refresh_token)).error, 'invalid_grant');
  // a client that registers with a secret must present it, in the form or with HTTP Basic
  await new Promise((r) => setTimeout(r, 13000));   // four more sign-in attempts from this address (one every 3 s)
  const conf = await (await json('/oauth/register', { client_name: 'confidential', redirect_uris: [redirect], token_endpoint_auth_method: 'client_secret_post' })).json();
  assert.match(conf.client_secret, /^sqzs_/); assert.equal(conf.token_endpoint_auth_method, 'client_secret_post');
  const confCode = async () => {
    const v = b64(crypto.randomBytes(32)); const c = b64(crypto.createHash('sha256').update(v).digest());
    const html = await (await page(base + '/oauth/authorize?' + new URLSearchParams({ response_type: 'code', client_id: conf.client_id, redirect_uri: redirect, code_challenge: c, code_challenge_method: 'S256' }))).text(); const rid = requestId(html);
    await step({ request: rid, action: 'sign-in', login: 'ann@x.test', password: 'the password 1' });
    return [new URL((await step({ request: rid, action: 'allow' })).headers.get('location')).searchParams.get('code'), v];
  };
  let [cc, cv] = await confCode();
  r = await post('/oauth/token', { grant_type: 'authorization_code', code: cc, redirect_uri: redirect, client_id: conf.client_id, code_verifier: cv });
  assert.equal(r.status, 401); assert.equal((await r.json()).error, 'invalid_client', 'no secret');
  [cc, cv] = await confCode();
  assert.ok((await (await post('/oauth/token', { grant_type: 'authorization_code', code: cc, redirect_uri: redirect, client_id: conf.client_id, client_secret: conf.client_secret, code_verifier: cv })).json()).access_token, 'secret in the form');
  [cc, cv] = await confCode();
  assert.ok((await (await post('/oauth/token', { grant_type: 'authorization_code', code: cc, redirect_uri: redirect, code_verifier: cv }, { authorization: 'Basic ' + Buffer.from(`${conf.client_id}:${conf.client_secret}`).toString('base64') })).json()).access_token, 'secret with Basic');
  await new Promise((r) => setTimeout(r, 7000));   // the sign-in allowance again
  const bobs = await authorize('bob@x.test');
  await post('/oauth/revoke', { token: bobs.refresh_token });
  assert.equal((await mcp('tools/list', {}, bobs.access_token)).status, 401, 'revoking the refresh token ends the sign-in');
  const bob2 = await authorize('bob@x.test');
  assert.deepEqual((await call('query', { sql: 'SELECT title FROM jobs' }, bob2.access_token)).structuredContent.rows, [{ title: "bob's job" }], 'Bob sees his own');
  // the transport's rules: an origin that is no page of this app is refused; the scheme is case-insensitive
  assert.equal((await json('/mcp', { jsonrpc: '2.0', id: 9, method: 'ping' }, { authorization: `Bearer ${bob2.access_token}`, origin: 'https://evil.example' })).status, 403);
  assert.equal((await json('/mcp', { jsonrpc: '2.0', id: 9, method: 'ping' }, { authorization: `bearer ${bob2.access_token}` })).status, 200);
  // a provider sign-in may come back only to a sign-in in progress, not to another URL of the OAuth server: those
  // redirect on, and the sign-in's code in the fragment would go along
  const rt = await fetch(`${base}/api/auth/users/oauth/github?return=${encodeURIComponent(`${base}/oauth/authorize?client_id=${client.client_id}`)}&challenge=${'a'.repeat(43)}`, { redirect: 'manual' });
  assert.equal(rt.status, 400); assert.match((await rt.json()).error, /return must be/, 'refused for where it returns to (not for want of a provider)');
  console.log('flow and checks: ok');

  // ---- costs
  const n = 300; let t = process.hrtime.bigint();
  for (let i = 0; i < n; i++) await call('query', { sql: 'SELECT id, title FROM jobs WHERE id = ?', params: [2] }, bob2.access_token);
  pr('a query tool call over HTTP (Node fetch, keep-alive)', `${(ms(t) / n).toFixed(2)} ms`);
  pr('connecting an agent: authorize, sign in, allow, exchange', `${signInMs.toFixed(0)} ms (most of it the password hash)`);

  // ---- part 2: the official SDK client, on its own
  if (!fs.existsSync(`${SDK}/client/index.js`)) { console.log(`SDK not found at ${SDK}: part 2 skipped`); }
  else {
    const { Client } = await import(`${SDK}/client/index.js`); const { StreamableHTTPClientTransport } = await import(`${SDK}/client/streamableHttp.js`);
    let saved = {}; let authUrl = null;
    const provider = {
      get redirectUrl() { return redirect; },
      get clientMetadata() { return { client_name: 'MCP SDK client', redirect_uris: [redirect], grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], token_endpoint_auth_method: 'none' }; },
      clientInformation: () => saved.client, saveClientInformation: (c) => { saved.client = c; },
      tokens: () => saved.tokens, saveTokens: (x) => { saved.tokens = x; },
      redirectToAuthorization: (url) => { authUrl = url; }, saveCodeVerifier: (v) => { saved.verifier = v; }, codeVerifier: () => saved.verifier,
    };
    // part 1 spent this address's sign-in allowance (10, then one every 3 s): let two come back
    await new Promise((r) => setTimeout(r, 7000));
    const t1 = process.hrtime.bigint();
    let transport = new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { authProvider: provider });
    const sdk = new Client({ name: 'sdk-test', version: '1.0.0' });
    await assert.rejects(sdk.connect(transport), /Unauthorized/i, 'first: no token, so the SDK starts the sign-in');
    assert.ok(authUrl && saved.client?.client_id, 'it discovered the server and registered itself');
    // a person signs in and allows, in a browser: here, the same two form posts
    const html = await (await page(authUrl)).text(); const rid = requestId(html);
    await step({ request: rid, action: 'sign-in', login: 'ann@x.test', password: 'the password 1' });
    const loc = new URL((await step({ request: rid, action: 'allow' })).headers.get('location'));
    await transport.finishAuth(loc.searchParams.get('code'));
    transport = new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { authProvider: provider });
    const sdk2 = new Client({ name: 'sdk-test', version: '1.0.0' }); await sdk2.connect(transport);
    const tl = await sdk2.listTools(); assert.deepEqual(tl.tools.map((x) => x.name), ['describe', 'query', 'execute']);
    const out = await sdk2.callTool({ name: 'query', arguments: { sql: 'SELECT title FROM jobs ORDER BY id' } });
    assert.deepEqual(out.structuredContent.rows.map((x) => x.title), ["ann's job", 'parked by an agent', 'second']);
    pr('the SDK client: discover, register, sign in, connect, list, call', `${ms(t1).toFixed(0)} ms, protocol ${sdk2.getServerVersion()?.name} ${transport.protocolVersion ?? ''}`);
    await sdk2.close();
    console.log('official SDK client: ok');
  }
  // last (it fills this address's room): at most 20 sign-ins in progress from one address
  let full = 0; for (let i = 0; i < 25; i++) { if ((await page(base + q({}))).status === 503) full++; }
  assert.ok(full >= 5, `${full} of 25 refused`);
} finally {
  server.kill('SIGTERM'); await new Promise((r) => server.on('exit', r));
  fs.rmSync(dir, { recursive: true, force: true }); fs.rmSync(`${dir}.toml`, { force: true });
}
process.exit(0);
