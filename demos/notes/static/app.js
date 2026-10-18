// The notes app: no server code of its own. It signs in and runs SQL with the client its server hands out; the
// database's row policy decides what each user sees and may change.
import { connect } from '/api/client.js';

const db = connect(location.origin);
const $ = (id) => document.getElementById(id);
const LIST = 'SELECT id, body, pinned, created, attachment FROM notes WHERE body ILIKE ? ORDER BY pinned DESC, created DESC LIMIT 200';
const COUNT = 'SELECT count(*) AS n, sum(CASE WHEN pinned THEN 1 ELSE 0 END) AS pinned FROM notes';
// with an embedding column (see the README): the notes nearest in meaning to the search text
const NEAREST = 'SELECT id, body, pinned, created, attachment, cosine_distance(embedding, embed(?)) AS d FROM notes WHERE embedding IS NOT NULL ORDER BY d LIMIT 20';
$('sql-list').textContent = `db.live('${LIST}', ['%' + search + '%'], render)`;
$('sql-count').textContent = `db.live('${COUNT}', showCount)`;

// ---------- sign-in ----------
let mode = 'in';
function setMode(m) {
  mode = m;
  $('tab-in').setAttribute('aria-selected', m === 'in'); $('tab-up').setAttribute('aria-selected', m === 'up');
  $('f-name').classList.toggle('hidden', m === 'in'); $('auth-go').textContent = m === 'in' ? 'Sign in' : 'Create account';
  $('f-password').autocomplete = m === 'in' ? 'current-password' : 'new-password'; $('auth-err').textContent = '';
}
$('tab-in').onclick = () => setMode('in'); $('tab-up').onclick = () => setMode('up');
$('auth-form').onsubmit = async (e) => {
  e.preventDefault(); $('auth-err').textContent = ''; $('auth-go').disabled = true;
  try {
    const email = $('f-email').value.trim(), password = $('f-password').value;
    if (mode === 'in') await db.auth.signIn(email, password);
    else await db.auth.signUp({ email, name: $('f-name').value.trim() || null }, password);
  } catch (err) { $('auth-err').textContent = err.message; } finally { $('auth-go').disabled = false; }
};
db.auth.methods().then(({ signUp, providers }) => {
  if (!signUp) { $('tab-up').classList.add('hidden'); }
  if (!providers.length) return;
  $('providers-wrap').classList.remove('hidden');
  for (const p of providers) {
    const b = document.createElement('button'); b.className = 'btn'; b.textContent = `Continue with ${p[0].toUpperCase()}${p.slice(1)}`;
    b.onclick = () => db.auth.signInWith(p); $('providers').append(b);
  }
}).catch(() => {});
$('sign-out').onclick = () => { stopLive(); db.auth.signOut(); };

// ---------- notes ----------
let list = null, count = null, search = '', seen = new Set(), meaning = false;
const live = (on, text) => { $('live').className = `live ${on === true ? 'on' : on === false ? 'off' : ''}`; $('live-text').textContent = text; };
const when = (ts) => { const d = new Date(ts), s = (Date.now() - d) / 1000; return s < 60 ? 'just now' : s < 3600 ? `${Math.floor(s / 60)} min ago` : s < 86400 ? `${Math.floor(s / 3600)} h ago` : d.toLocaleDateString(); };
function render(rows, { initial }) {
  live(true, 'live');
  const el = $('list'); el.replaceChildren();
  if (!rows.length) { const e = document.createElement('div'); e.className = 'empty'; e.textContent = search ? 'No notes match.' : 'No notes yet. Write the first one above.'; el.append(e); }
  for (const r of rows) {
    const n = document.createElement('article'); n.className = `note${r.pinned ? ' pinned' : ''}${!initial && !seen.has(r.id) ? ' flash' : ''}`;
    const t = document.createElement('div'); t.className = 't'; t.textContent = r.body;
    const m = document.createElement('div'); m.className = 'm'; m.textContent = when(r.created); m.title = r.created;
    const parts = [t];
    if (r.attachment?.url) {   // a signed link the query handed out: an <img> can load it straight from the server
      const f = document.createElement('div'); f.className = 'file'; const a = document.createElement('a'); a.href = r.attachment.url; a.target = '_blank'; a.rel = 'noopener';
      if (r.attachment.type.startsWith('image/')) { const img = document.createElement('img'); img.src = r.attachment.url; img.alt = r.attachment.name; img.loading = 'lazy'; a.append(img); }
      else a.textContent = `📎 ${r.attachment.name} (${size(r.attachment.size)})`;
      f.append(a); parts.push(f);
    }
    const acts = document.createElement('div'); acts.className = 'acts';
    const pin = document.createElement('button'); pin.className = 'pin'; pin.textContent = '★'; pin.title = r.pinned ? 'Unpin' : 'Pin'; pin.setAttribute('aria-label', pin.title);
    pin.onclick = () => run('UPDATE notes SET pinned = ? WHERE id = ?', [!r.pinned, r.id]);
    const del = document.createElement('button'); del.textContent = '✕'; del.title = 'Delete'; del.setAttribute('aria-label', 'Delete');
    del.onclick = () => run('DELETE FROM notes WHERE id = ?', [r.id]);
    acts.append(pin, del); n.append(...parts, m, acts); el.append(n);
  }
  seen = new Set(rows.map((r) => r.id));
}
const size = (n) => (n < 1024 ? `${n} B` : n < 1 << 20 ? `${(n / 1024).toFixed(0)} KB` : `${(n / (1 << 20)).toFixed(1)} MB`);
function showCount([c]) { $('count').textContent = c.n === 0 ? '' : `${c.n} note${c.n === 1 ? '' : 's'}${c.pinned ? `, ${c.pinned} pinned` : ''}`; }
const failed = (e) => { live(false, 'offline'); $('compose-err').textContent = e.message; };
const listQuery = () => (meaning && search ? [NEAREST, [search]] : [LIST, [`%${search}%`]]);
function startLive() {
  stopLive(); live(null, 'connecting');
  list = db.live(...listQuery(), render, failed);
  count = db.live(COUNT, showCount, failed);
  // search by meaning, if this database has an embedding for notes
  db.sql('SELECT embedding IS NULL AS x FROM notes LIMIT 1').then(() => $('meaning').classList.remove('hidden'), () => $('meaning').classList.add('hidden'));
}
function stopLive() { list?.close(); count?.close(); list = count = null; }
async function run(sql, params) { $('compose-err').textContent = ''; try { await db.sql(sql, params); return true; } catch (e) { $('compose-err').textContent = e.message; return false; } }

// an attachment: chosen with the paperclip, or pasted; a File as a parameter is uploaded with the note
let pending = null;
const attach = (file) => { pending = file; $('chip').classList.toggle('hidden', !file); $('hint').classList.toggle('hidden', !!file); $('chip-name').textContent = file ? `${file.name} (${size(file.size)})` : ''; };
$('attach').onclick = () => $('file').click();
$('file').onchange = () => { attach($('file').files[0] || null); $('file').value = ''; };
$('chip-x').onclick = () => attach(null);
$('body').onpaste = (e) => { const f = [...(e.clipboardData?.files || [])][0]; if (f) { e.preventDefault(); attach(f.name ? f : new File([f], 'pasted.png', { type: f.type })); } };
$('compose').onsubmit = async (e) => {
  e.preventDefault(); const box = $('body'), body = box.value.trim(), file = pending; if (!body && !file) return;
  box.value = ''; attach(null);   // at once: the next note can be written while this one saves (it comes back if saving fails)
  if (!await run('INSERT INTO notes (owner, body, attachment) VALUES (?, ?, ?)', [db.auth.user.id, body, file]) && !box.value) { box.value = body; attach(file); }
};
$('body').onkeydown = (e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) $('compose').requestSubmit(); };
let typing = null;
const research = () => { list?.close(); list = db.live(...listQuery(), render, failed); };
$('search').oninput = () => { clearTimeout(typing); typing = setTimeout(() => { search = $('search').value.trim(); research(); }, meaning ? 400 : 150); };
$('meaning').onclick = () => { meaning = !meaning; $('meaning').setAttribute('aria-pressed', meaning); research(); };

// ---------- which screen ----------
function show(user) {
  $('gate').classList.toggle('hidden', !!user); $('app').classList.toggle('hidden', !user);
  if (user) { $('me').textContent = user.name || user.email; startLive(); } else { stopLive(); setMode('in'); }
}
db.auth.onChange(show);
db.ready.then(() => show(db.auth.user), (e) => { show(null); $('auth-err').textContent = e.message; });
