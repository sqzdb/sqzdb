// sqzdb client: sign in and query a sqzdb app API (`listen.app`) from a browser, React Native or Node (22+).
// Every statement runs as the signed-in user, under the database's row policies; live queries update themselves.
//
//   import { connect } from 'sqzdb-client'
//   const db = connect('https://api.example')
//   await db.auth.signIn('ann@example.com', password)        // or db.auth.signInWith('google')
//   const notes = await db.sql('SELECT * FROM notes ORDER BY created DESC LIMIT 20')
//   const sub = db.live('SELECT count(*) AS n FROM notes', [], (rows) => render(rows[0].n))
//
// On a page the API serves itself (an app behind it with app.proxy, or app.staticDir), `connect(location.origin,
// { cookies: true })` keeps the session in an HttpOnly cookie instead: no script can read it, and page loads carry it,
// so the API's middleware and the app behind it know who is asking.

export class SqzError extends Error {
  constructor(code, message) { super(message); this.name = 'SqzError'; this.code = code; }
}
const err = (e) => new SqzError(e.code || 'ERROR', e.error || String(e));
const b64url = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
// a File or Blob as a parameter is uploaded first; a file a query returned is sent as its id
const isBlob = (p) => typeof Blob !== 'undefined' && p instanceof Blob;
const isFile = (p) => p !== null && typeof p === 'object' && typeof p.id === 'string' && 'url' in p;
// the verifier of a provider sign-in this tab started (sessionStorage: it survives the trip to the provider)
const verifiers = { mem: new Map(),
  put(k, v) { try { globalThis.sessionStorage.setItem(k, v); } catch { this.mem.set(k, v); } },
  take(k) { let v = null; try { v = globalThis.sessionStorage.getItem(k); globalThis.sessionStorage.removeItem(k); } catch {} if (v === null) { v = this.mem.get(k) ?? null; this.mem.delete(k); } return v; } };
const toObjects = (r) => r.rows.map((row) => Object.fromEntries(r.columns.map((c, i) => [c, row[i]])));

class Auth {
  constructor(client, table) { this._c = client; this.table = table; this.user = null; this._listeners = new Set(); }
  /** Make an account (fields include the login column, such as email) and sign in. */
  async signUp(fields, password) { return this._took(await this._c._post(`/api/auth/${this.table}/sign-up`, { fields, password, ...this._c._mode }, false)); }
  /** Sign in with a login and password; rejects with AUTH when they don't match. */
  async signIn(login, password) { return this._took(await this._c._post(`/api/auth/${this.table}/sign-in`, { login, password, ...this._c._mode }, false)); }
  /** How users of this table sign in: `{ signUp, providers }` (whether they may make an account, and the provider
   *  names `signInWith` takes). */
  async methods() { const r = await this._c._fetch(`/api/auth/${this.table}/methods`); const v = await r.json(); if (v.error) throw err(v); return v; }
  /** Sign in with a provider configured on the server (auth.oauth.<provider>): the browser leaves for the provider
   *  and comes back to `returnTo` (this page by default), where `connect` finishes the sign-in. */
  async signInWith(provider, { returnTo } = {}) {
    const back = returnTo || globalThis.location?.href.split('#')[0];
    if (!back) throw new SqzError('ARGUMENTS', 'signInWith needs returnTo outside a browser');
    if (this._c._cookies) {   // the session comes back as the cookie, and the browser to this page
      const here = new URL(back, this._c.url); const to = `${this._c.url}/api/auth/${this.table}/oauth/${encodeURIComponent(provider)}?cookie=1&return=${encodeURIComponent(here.pathname + here.search)}`;
      if (globalThis.location) globalThis.location.assign(to); return to;
    }
    // the code that comes back works only with this verifier, so a code planted in a link signs no one in
    const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
    const challenge = b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
    verifiers.put(`${this._c._key}:verifier`, verifier);
    const to = `${this._c.url}/api/auth/${this.table}/oauth/${encodeURIComponent(provider)}?return=${encodeURIComponent(back)}&challenge=${challenge}`;
    if (globalThis.location) globalThis.location.assign(to); return to;
  }
  /** Sign in a device without a browser of its own (a CLI, a script on a server): `onCode` gets a code and the page
   *  to type it on, which the user opens in a browser where they are signed in; resolves once they allow it, with a
   *  session of this device's own. Rejects with DENIED, or EXPIRED after 10 minutes. */
  async signInWithDevice({ name, onCode, signal } = {}) {
    const d = await this._c._post('/api/auth/device', { name }, false);
    await onCode?.({ code: d.user_code, url: d.verification_uri, expiresIn: d.expires_in });
    let wait = d.interval * 1000;
    for (;;) {
      await new Promise((ok, no) => { const t = setTimeout(ok, wait); signal?.addEventListener('abort', () => { clearTimeout(t); no(new SqzError('ABORTED', 'device sign-in stopped')); }, { once: true }); });
      try { return this._took(await this._c._post('/api/auth/device/token', { device_code: d.device_code }, false)); }
      catch (e) { if (e.code === 'PENDING') continue; if (e.code === 'SLOW_DOWN') { wait += 5000; continue; } throw e; }
    }
  }
  async signOut() {
    const t = this._c.token; this._set(null, null);
    if (t) await this._c._fetch('/api/auth/sign-out', { method: 'POST', headers: { authorization: `Bearer ${t}` } }).catch(() => {});
    else if (this._c._cookies) await this._c._fetch('/api/auth/sign-out', { method: 'POST' }).catch(() => {});
  }
  /** Called with the user (or null) whenever sign-in changes; returns a function that stops it. */
  onChange(fn) { this._listeners.add(fn); return () => this._listeners.delete(fn); }
  _took(r) { this._set(r.token ?? null, r.user); return r; }
  _set(token, user) {
    this._c.token = token; this.user = user;
    try { if (token) this._c._store?.setItem(this._c._key, JSON.stringify({ token, user })); else this._c._store?.removeItem(this._c._key); } catch {}
    this._c._reauth();
    for (const fn of this._listeners) { try { fn(user); } catch {} }
  }
}

class Files {
  constructor(client) { this._c = client; }
  /** Upload a File or Blob (`name` and `type` from it unless given); resolves to the file as a query returns it,
   *  `{ id, name, type, size, url }`. Put its id (or the object) in a FILE column within the hour. */
  async upload(data, { name, type } = {}) {
    await this._c.ready;
    const headers = { 'content-type': type || data.type || 'application/octet-stream' }; if (this._c.token) headers.authorization = `Bearer ${this._c.token}`;
    const res = await this._c._fetch(`/api/files?name=${encodeURIComponent(name || data.name || 'file')}`, { method: 'POST', headers, body: data });
    const v = await res.json().catch(() => ({ error: `HTTP ${res.status}`, code: 'ERROR' }));
    if (v.error) { if (v.code === 'AUTH' && this._c.token) this._c.auth._set(null, null); throw err(v); }
    return v;
  }
}

class Live {
  constructor(client, sql, params, fn, onError) { Object.assign(this, { _c: client, sql, params, fn, onError, rows: null, closed: false }); this.id = 0; }
  close() { if (this.closed) return; this.closed = true; this._c._lives.delete(this.id); this._c._send({ op: 'unlive', id: this.id }, true); }
}

class Client {
  constructor(url, opts = {}) {
    this.url = (url ?? globalThis.location?.origin ?? '').replace(/\/+$/, ''); this.token = null;
    // cookie mode: the session is the API's HttpOnly cookie; nothing of it is kept here
    this._cookies = !!opts.cookies; this._mode = this._cookies ? { cookie: true } : {};
    this._store = this._cookies ? null : opts.storage !== undefined ? opts.storage : globalThis.localStorage;
    this._key = `sqzdb:${this.url}`; this._fetchImpl = opts.fetch || globalThis.fetch.bind(globalThis);   // a browser's fetch must be called on the window
    this._WS = opts.WebSocket || globalThis.WebSocket;
    this._ws = null; this._open = false; this._wait = []; this._pending = new Map(); this._lives = new Map(); this._next = 1; this._backoff = 500;
    this.auth = new Auth(this, opts.users || 'users'); this.files = new Files(this);
    try { const s = this._store && JSON.parse(this._store.getItem(this._key) || 'null'); if (s) { this.token = s.token; this.auth.user = s.user; } } catch {}
    // back from a provider: trade the one-time code for a session, then take it out of the address bar; in cookie
    // mode, ask who the cookie belongs to
    this.ready = this._cookies ? this._whoami() : this._finishRedirect();
  }
  async _whoami() {
    const r = await this._fetch('/api/me').catch(() => null); const v = r && await r.json().catch(() => null);
    this.auth.user = v && !v.error ? v.user : null;
  }
  async _finishRedirect() {
    const loc = globalThis.location; if (!loc?.hash) return;
    const h = new URLSearchParams(loc.hash.slice(1)); const code = h.get('sqz_code'), e = h.get('sqz_error');
    if (!code && !e) return;
    globalThis.history?.replaceState(null, '', loc.href.split('#')[0]);
    if (e) throw new SqzError('AUTH', e);
    const verifier = verifiers.take(`${this._key}:verifier`);
    if (!verifier) throw new SqzError('AUTH', 'sign-in failed: this page did not start this sign-in');
    this.auth._took(await this._post('/api/auth/exchange', { code, verifier }, false));
  }
  _fetch(path, init) { return this._fetchImpl(this.url + path, init); }
  async _post(path, body, signed = true) {
    const headers = { 'content-type': 'application/json' }; if (signed && this.token) headers.authorization = `Bearer ${this.token}`;
    const res = await this._fetch(path, { method: 'POST', headers, body: JSON.stringify(body) });
    const v = await res.json().catch(() => ({ error: `HTTP ${res.status}`, code: 'ERROR' }));
    if (v.error) { if (v.code === 'AUTH' && signed && this.token) this.auth._set(null, null); throw err(v); }
    return v;
  }
  /** Run one statement as the signed-in user; resolves to rows as objects (an INSERT also has `lastInsertId`). */
  async sql(text, params = []) {
    await this.ready; params = await this._bind(params);
    const r = this._WS ? await this._call({ op: 'sql', sql: text, params }) : await this._post('/api/sql', { sql: text, params });
    const rows = toObjects(r); if (r.lastInsertId !== undefined) rows.lastInsertId = r.lastInsertId; return rows;
  }
  /** Several statements as one transaction: [[sql, params], …]; resolves to each one's rows. */
  async batch(statements) {
    await this.ready;
    const body = { statements: await Promise.all(statements.map(async (s) => { const st = Array.isArray(s) ? { sql: s[0], params: s[1] || [] } : s; return { ...st, params: await this._bind(st.params) }; })) };
    const r = this._WS ? await this._call({ op: 'batch', ...body }) : await this._post('/api/batch', body);
    return r.results.map(toObjects);
  }
  /** Call one of the app's functions (see the server's `functions` folder) as the signed-in user; resolves to what
   *  it returned. Its arguments are an object: `await db.call('reportRun', { runId: 7, status: 'completed' })`. */
  async call(name, args = {}) {
    await this.ready;
    const r = this._WS ? await this._call({ op: 'call', name, args }) : await this._post(`/api/fn/${encodeURIComponent(name)}`, args);
    return r.result;
  }
  /** A query that keeps its result current: `fn(rows)` now and on every change. `onError(e)` if it can't run. */
  live(text, params, fn, onError) {
    if (typeof params === 'function') { onError = fn; fn = params; params = []; }
    const l = new Live(this, text, (params || []).map((p) => (isFile(p) ? p.id : p)), fn, onError); l.id = this._next++;
    this._lives.set(l.id, l); this.ready.then(() => this._subscribe(l), (e) => onError?.(e));
    return l;
  }
  async _bind(params) { return Promise.all((params || []).map(async (p) => (isBlob(p) ? (await this.files.upload(p)).id : isFile(p) ? p.id : p))); }
  _subscribe(l) { if (!l.closed) this._send({ op: 'live', id: l.id, sql: l.sql, params: l.params }, true); }
  // ---------- the socket ----------
  _socket() {
    if (this._ws) return;
    const u = this.url.replace(/^http/, 'ws') + '/api/socket';
    const ws = new this._WS(u); this._ws = ws;
    ws.onopen = () => {
      this._open = true; this._backoff = 500;
      if (this.token) ws.send(JSON.stringify({ op: 'auth', id: 0, token: this.token }));
      for (const l of this._lives.values()) this._subscribe(l);
      for (const m of this._wait.splice(0)) ws.send(m);
    };
    ws.onmessage = (ev) => this._receive(JSON.parse(typeof ev.data === 'string' ? ev.data : String(ev.data)));
    ws.onclose = () => {
      this._ws = null; this._open = false;
      for (const [, p] of this._pending) p.reject(new SqzError('CLOSED', 'the connection closed'));
      this._pending.clear();
      if (this._lives.size) { setTimeout(() => this._socket(), this._backoff); this._backoff = Math.min(this._backoff * 2, 30000); }
    };
    ws.onerror = () => {};
  }
  _send(m, isLive) { const s = JSON.stringify(m); if (this._open) this._ws.send(s); else { if (!isLive) this._wait.push(s); this._socket(); } }
  _call(m) {
    return new Promise((resolve, reject) => { const id = this._next++; this._pending.set(id, { resolve, reject }); this._send({ ...m, id }); })
      .then((v) => { if (v.error) { if (v.code === 'AUTH' && this.token) this.auth._set(null, null); throw err(v); } return v; });
  }
  _receive(m) {
    if (m.id === 0) { if (m.error && m.code === 'AUTH') this.auth._set(null, null); return; }   // the socket's own auth message
    const l = this._lives.get(m.id);
    if (l) {
      if (m.live) { l.rows = toObjects(m); try { l.fn(l.rows, { initial: !!m.initial }); } catch (e) { console.error(e); } return; }
      if (m.ended) { if (!l.closed) this._subscribe(l); return; }   // the server dropped it (it fell behind, or the user changed): make it again
      if (m.error) { this._lives.delete(m.id); if (m.code === 'AUTH' && this.token) this.auth._set(null, null); l.onError?.(err(m)); return; }
    }
    const p = this._pending.get(m.id); if (p) { this._pending.delete(m.id); p.resolve(m); }
  }
  // the open socket follows sign-in: a new token, or null when signed out (its live queries end either way); in cookie
  // mode the socket takes the cookie as it connects, so it connects again
  _reauth() {
    if (!this._cookies) { if (this._open) this._ws.send(JSON.stringify({ op: 'auth', id: 0, token: this.token })); return; }
    const ws = this._ws; if (!ws) return;
    ws.onclose = null; ws.close(); this._ws = null; this._open = false;
    for (const [, p] of this._pending) p.reject(new SqzError('CLOSED', 'the connection closed (signed in or out)'));
    this._pending.clear(); if (this._lives.size) this._socket();
  }
  /** Close the socket (live queries stop). */
  close() { for (const l of this._lives.values()) l.closed = true; this._lives.clear(); this._ws?.close(); }
}

/** Connect to a sqzdb app API. Options: `users` (the table users sign in to, default 'users'), `storage` (where
 *  the session is kept: localStorage in a browser, or null), `fetch` and `WebSocket` (for other runtimes). */
export function connect(url, opts) { return new Client(url, opts); }
