-- The notes app's whole backend: its tables, who may do what, and sign-in. Load it once:
--   sqweezdb shell ./data < schema.sql
CREATE TABLE users (id SERIAL PRIMARY KEY, email TEXT UNIQUE, name TEXT, role TEXT DEFAULT 'member');
CREATE TABLE notes (id SERIAL PRIMARY KEY, owner INT NOT NULL, body VARCHAR(1000) NOT NULL, pinned BOOL DEFAULT false, created TIMESTAMP DEFAULT now());
CREATE INDEX notes_owner ON notes (owner);

-- every signed-in user is a member (users.role), and a member's notes are the ones they own: every statement from
-- the browser runs under this, live queries included
CREATE ROLE member;
GRANT SELECT, INSERT, UPDATE, DELETE ON notes TO member;
CREATE POLICY own ON notes FOR ALL TO member USING (owner = SESSION.id);

-- users sign in to the users table: email and password, or a provider (see notes.toml)
ALTER TABLE users ENABLE AUTH (ROLE FROM role);
