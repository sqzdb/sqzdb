import { open } from 'sqzdb';
// once per process (development reloads modules, and one handle owns the directory). The API in front of Next.js
// (listen.app) serves the site: what isn't its own goes on to Next.js, which listens on 127.0.0.1 only.
export function db() {
  if (!globalThis.__db) {
    const front = process.env.FRONT ?? '127.0.0.1:8099';
    const d = open(process.env.DB_DIR ?? './data/app', {
      functions: './functions',
      listen: { app: front },
      app: { publicUrl: `http://${front}`, proxy: process.env.NEXT_URL ?? 'http://127.0.0.1:3000', signUp: { users: [] } },
    });
    for (const s of ["CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, email TEXT UNIQUE, role TEXT DEFAULT 'member')", 'CREATE TABLE IF NOT EXISTS jobs (id SERIAL PRIMARY KEY, owner INT NOT NULL, title TEXT, status TEXT DEFAULT \'inbox\')',
                     'CREATE ROLE member', 'ALTER TABLE users ENABLE AUTH (ROLE FROM role)', 'GRANT SELECT ON jobs TO member', 'CREATE POLICY own ON jobs FOR ALL TO member USING (owner = SESSION.id)']) {
      try { d.exec(s); } catch (e) { if (!/exists/.test(e.message)) throw e; }
    }
    globalThis.__db = d;
  }
  return globalThis.__db;
}
