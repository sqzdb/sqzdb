//! Sign-up, sign-in and sessions for tables marked `ALTER TABLE users ENABLE AUTH (ROLE FROM role)`.
//!
//! A user is a row of that table; its UNIQUE text column is the login. Signing in checks the password and returns a
//! session token; `session` turns a token into the identity the row policies read: the role from the row (or a fixed
//! one), and every non-NULL column as `SESSION.<column>`. Password hashes and sessions live in two hidden system
//! tables that no SQL can name, so no query returns a hash.
//!
//! - Passwords are hashed with Argon2id, 19 MiB and 2 passes (OWASP's first recommendation; 8 ms on the lab machine),
//!   at most a few at once (each takes 19 MiB). The settings are part of each stored hash, so they can be raised later.
//! - A token is 32 random bytes; only its SHA-256 is stored. Each password row has a random generation, and a session
//!   is valid only for the generation it was made with: changing the password, `sign_out_everywhere`, or a new row
//!   taking a deleted user's key ends every earlier session at once.
//! - After 5 failed sign-ins for one login, the next attempt waits 1 s, then 2, 4 … up to 15 minutes. An unknown login
//!   costs the same hash as a known one, and both fail with the same message.
use crate::sql::{Session, Sql};
use crate::table::{decode_col, encode_row, encode_value, now_micros, ColType, Key, Table, Txn, Value};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

pub const SECRETS: &str = "_auth_secrets";
pub const SESSIONS: &str = "_auth_sessions";
/// Longest `<table>:<key>` a password row is filed under.
const ID_MAX: usize = 160;
const TOKEN_PREFIX: &str = "sqz_";
const PASSWORD_MAX: usize = 1024;
const FREE_FAILURES: u32 = 5;
const LOCK_MAX: Duration = Duration::from_secs(15 * 60);
const SWEEP_EVERY_US: i64 = 3_600_000_000;

/// Names under `_auth_` are the engine's own: SQL can't create, read or change them.
pub fn is_system(name: &str) -> bool { name.len() >= 6 && name[..6].eq_ignore_ascii_case("_auth_") }

/// Where a signed-in user's role comes from.
#[derive(Clone, Debug)] pub enum RoleSrc { Column(usize), Fixed(String) }
/// A table users sign in to: its UNIQUE text column is the login.
#[derive(Clone, Debug)] pub struct AuthTable { pub login: usize, pub role: RoleSrc }

/// A successful sign-up or sign-in: the session token, the user's row as (column, value) pairs, and whether this
/// sign-in made the user (sign-up, or a first sign-in with a provider).
#[derive(Debug, Clone)] pub struct SignedIn { pub token: String, pub user: Vec<(String, Value)>, pub created: bool }

/// Per database: failed sign-ins by login, and when expired sessions were last swept.
/// Per database: failed sign-ins by login, when expired sessions were last swept, and the sign-in state counter that
/// the users table and the auth system tables bump on every write (`Table::watch`).
#[derive(Default)] pub struct AuthState { failures: Mutex<HashMap<String, (u32, Instant)>>, last_sweep: std::sync::atomic::AtomicI64, pub(crate) epoch: Arc<std::sync::atomic::AtomicU64>, create_lock: Mutex<()> }

fn hasher() -> Argon2<'static> { Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(19_456, 2, 1, None).expect("argon2 parameters")) }
/// At most this many hashes at once: each holds 19 MiB.
fn gate() -> &'static (Mutex<usize>, Condvar) { static G: OnceLock<(Mutex<usize>, Condvar)> = OnceLock::new(); G.get_or_init(|| (Mutex::new(0), Condvar::new())) }
fn gated<T>(f: impl FnOnce() -> T) -> T {
    let limit = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).clamp(2, 8);
    let (m, cv) = gate();
    { let mut n = m.lock().unwrap(); while *n >= limit { n = cv.wait(n).unwrap(); } *n += 1; }
    let out = f();
    *m.lock().unwrap() -= 1; cv.notify_one();
    out
}
fn random<const N: usize>() -> [u8; N] { let mut b = [0u8; N]; getrandom::fill(&mut b).expect("the operating system's random source"); b }
fn hash_password(pw: &str) -> Result<String, String> {
    let salt = SaltString::encode_b64(&random::<16>()).map_err(|e| e.to_string())?;
    gated(|| hasher().hash_password(pw.as_bytes(), &salt).map(|h| h.to_string()).map_err(|e| e.to_string()))
}
fn verify_password(pw: &str, stored: &str) -> bool {
    let Ok(h) = PasswordHash::new(stored) else { return false };
    gated(|| hasher().verify_password(pw.as_bytes(), &h).is_ok())
}
/// What an unknown login is checked against, so it costs as much as a known one.
fn dummy_hash() -> &'static str { static D: OnceLock<String> = OnceLock::new(); D.get_or_init(|| hash_password(&format!("{:x?}", random::<16>())).unwrap_or_default()) }
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
fn unhex(s: &str) -> Option<Vec<u8>> { if s.len() % 2 != 0 { return None; } (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect() }
fn token_id(token: &str) -> Option<[u8; 32]> {
    use sha2::Digest;
    let raw = unhex(token.strip_prefix(TOKEN_PREFIX)?)?; if raw.len() != 32 { return None; }
    Some(sha2::Sha256::digest(&raw).into())
}
fn normalize(login: &str) -> String { login.trim().to_lowercase() }
const WRONG: &str = "sign-in failed: wrong login or password";
/// The hash stored for a user who signs in only through a provider: no password matches it.
const NO_PASSWORD: &str = "!";

impl Sql {
    fn system(&self, name: &str) -> Result<Arc<Table>, String> { self.db.table(name).ok_or_else(|| format!("no table {name}: ENABLE AUTH on a table first")) }
    pub(crate) fn auth_table_of(&self, table: &str) -> Result<(Arc<Table>, AuthTable), String> { self.auth_table(table) }
    fn auth_table(&self, table: &str) -> Result<(Arc<Table>, AuthTable), String> {
        let cfg = self.acl.read().unwrap().auth.get(&table.to_lowercase()).cloned().ok_or_else(|| format!("{table} is not a table users sign in to (ALTER TABLE {table} ENABLE AUTH)"))?;
        Ok((self.db.table(table).ok_or_else(|| format!("no such table {table}"))?, cfg))
    }
    /// The password row's key: `<table>:<primary key as text>`.
    fn secret_id(table: &Table, row: &[u8]) -> String { format!("{}:{}", table.schema.name.to_lowercase(), key_text(&decode_col(&table.schema, row, table.schema.pk))) }
    fn text_pk(t: &Table, s: &str) -> Result<Key, String> { t.schema.key_from_value(&Value::Text(s.to_string())) }

    /// `ALTER TABLE t ENABLE AUTH [(ROLE FROM column | ROLE name)]`: checks the table can hold users and creates the
    /// system tables on first use (logged like any CREATE, so a restart replays them before this statement).
    pub(crate) fn enable_auth(&self, table: &str, role: Option<(bool, String)>) -> Result<AuthTable, String> {
        if is_system(table) { return Err(format!("{table} is a system table")); }
        if table.contains(':') { return Err(format!("{table}: the name of a table users sign in to can't contain ':'")); }
        let t = self.db.table(table).ok_or_else(|| format!("no such table {table}"))?;
        let s = &t.schema;
        let login = s.unique.filter(|&u| matches!(s.columns[u].ty, ColType::Text(_))).ok_or_else(|| format!("{table} needs a UNIQUE text column to sign in with, such as email TEXT UNIQUE"))?;
        let keylen = match &s.columns[s.pk].ty { ColType::Int => 20, ColType::Uuid => 36, ColType::Text(n) | ColType::Bytes(n) => *n, _ => usize::MAX };
        if matches!(s.columns[s.pk].ty, ColType::Bytes(_)) || s.name.len() + 1 + keylen > ID_MAX { return Err(format!("{table}: the key of a table users sign in to is an INT, a UUID or a short text (at most {} characters here)", ID_MAX.saturating_sub(s.name.len() + 1))); }
        let role = match role {
            Some((true, col)) => { let c = s.col(&col).ok_or_else(|| format!("no such column {col}"))?; if !matches!(s.columns[c].ty, ColType::Text(_)) { return Err(format!("ROLE FROM {col}: the column must be text")); } RoleSrc::Column(c) }
            Some((false, name)) => { if !self.acl.read().unwrap().roles.contains(&name) { return Err(format!("no such role {name}")); } RoleSrc::Fixed(name) }
            None => match s.col("role") { Some(c) if matches!(s.columns[c].ty, ColType::Text(_)) => RoleSrc::Column(c), _ => return Err(format!("say which role a user of {table} gets: ENABLE AUTH (ROLE FROM column) or ENABLE AUTH (ROLE name)")) },
        };
        for (name, ddl) in [(SECRETS, "CREATE TABLE _auth_secrets (id VARCHAR(160) PRIMARY KEY, hash VARCHAR(160) NOT NULL, gen BYTES(16) NOT NULL, changed TIMESTAMP NOT NULL)"),
                            (SESSIONS, "CREATE TABLE _auth_sessions (id BYTES(32) PRIMARY KEY, secret VARCHAR(160) NOT NULL, gen BYTES(16) NOT NULL, created TIMESTAMP NOT NULL, expires TIMESTAMP NOT NULL)")] {
            if self.db.table(name).is_none() { self.create_system_table(ddl)?; }
        }
        for tb in [t.clone(), self.system(SECRETS)?, self.system(SESSIONS)?] { let _ = tb.watch.set(self.auth.epoch.clone()); }
        Ok(AuthTable { login, role })
    }

    /// Insert a user and set the password in one transaction; returns a session for the new user.
    pub fn sign_up(&self, table: &str, fields: &[(String, Value)], password: &str) -> Result<SignedIn, String> {
        let (t, cfg) = self.auth_table(table)?;
        self.check_password(password)?;
        let s = &t.schema; let mut cols = vec![]; let mut vals = vec![];
        for (k, v) in fields {
            let c = s.col(k).ok_or_else(|| format!("no such column {k} in {table}"))?;
            cols.push(format!("\"{}\"", s.columns[c].name)); vals.push(if c == cfg.login { match v { Value::Text(x) => Value::Text(normalize(x)), v => v.clone() } } else { v.clone() });
        }
        if !fields.iter().any(|(k, _)| s.col(k) == Some(cfg.login)) { return Err(format!("sign-up needs the login column {}", s.columns[cfg.login].name)); }
        let hash = hash_password(password)?;
        let sql = format!("INSERT INTO \"{}\" ({}) VALUES ({}) RETURNING *", s.name, cols.join(", "), vec!["?"; cols.len()].join(", "));
        let mut sess = Session::default();
        self.exec_s(&mut sess, "BEGIN", &[])?;
        let run = |sess: &mut Session| -> Result<(Vec<u8>, String), String> {
            let row = self.exec_s(sess, &sql, &vals)?.pop().ok_or("sign-up inserted no row")?;
            let enc = encode_row(s, &row)?;
            let token = self.write_secret_and_session(sess.txn.as_mut().unwrap(), &t, &enc, Some(&hash))?;
            Ok((enc, token))
        };
        match run(&mut sess) {
            Ok((row, token)) => { self.exec_s(&mut sess, "COMMIT", &[])?; Ok(SignedIn { token, user: user_pairs(&t, &row), created: true }) }
            Err(e) => { let _ = self.exec_s(&mut sess, "ROLLBACK", &[]); Err(e) }
        }
    }

    /// Check a login and password; on success, a new session.
    pub fn sign_in(&self, table: &str, login: &str, password: &str) -> Result<SignedIn, String> {
        let (t, cfg) = self.auth_table(table)?;
        let login = normalize(login);
        let fkey = format!("{}:{login}", t.schema.name.to_lowercase());
        {   // the attempt counts as a failure before its hash, so attempts running at once count against each other; a success clears it
            let mut f = self.auth.failures.lock().unwrap();
            if let Some(&(n, at)) = f.get(&fkey) {
                if n >= FREE_FAILURES { let wait = Duration::from_secs(1u64 << (n - FREE_FAILURES).min(10)).min(LOCK_MAX); if at.elapsed() < wait { return Err(format!("sign-in failed: too many failed sign-ins for this login; try again in {} s", (wait - at.elapsed()).as_secs() + 1)); } }
            }
            if f.len() > 100_000 { f.retain(|_, (_, at)| at.elapsed() < LOCK_MAX); }
            let e = f.entry(fkey.clone()).or_insert((0, Instant::now())); e.0 += 1; e.1 = Instant::now();
        }
        let ty = &t.schema.columns[cfg.login].ty;
        let mut key = vec![0u8; ty.width()];
        let user = if password.len() > PASSWORD_MAX || encode_value(ty, &Value::Text(login.clone()), &mut key).is_err() { None } else { t.with_unique(&key, |r| r.to_vec()) };
        let secrets = self.system(SECRETS)?;
        let stored = user.as_ref().and_then(|r| secrets.with_pk(Self::text_pk(&secrets, &Self::secret_id(&t, r)).ok()?, |r| r.to_vec()));
        let ok = match stored.as_ref().map(|sr| decode_col(&secrets.schema, sr, 1)) { Some(Value::Text(h)) if PasswordHash::new(&h).is_ok() => verify_password(password, &h), _ => { let _ = verify_password(password, dummy_hash()); false } };
        if !ok { return Err(WRONG.into()); }
        self.auth.failures.lock().unwrap().remove(&fkey);
        let user = user.unwrap(); let sr = stored.unwrap();
        let token = self.new_session(&secrets, &Self::secret_id(&t, &user), &sr)?;
        self.sweep_sessions();
        Ok(SignedIn { token, user: user_pairs(&t, &user), created: false })
    }

    /// Make `sess` act as the user the token belongs to: the row's role and its columns as session attributes.
    pub fn session_from_token(&self, sess: &mut Session, token: &str) -> Result<(), String> {
        if sess.txn.is_some() { return Err("cannot change identity inside a transaction".into()); }
        self.bind_token(sess, token).inspect_err(|_| deny(sess))
    }
    /// The sign-in state counter (see `AuthState`).
    pub(crate) fn auth_epoch(&self) -> u64 { self.auth.epoch.load(std::sync::atomic::Ordering::Acquire) }
    pub(crate) fn auth_changed(&self) { self.auth.epoch.fetch_add(1, std::sync::atomic::Ordering::Release); }
    /// Before a statement: a session from a token whose sign-in state changed checks the token again and takes the
    /// user's current role and attributes. If the token no longer holds, the session keeps no roles (so nothing passes
    /// a grant) and every statement fails with AUTH until a new token is bound.
    pub(crate) fn check_identity(&self, sess: &mut Session) -> Result<(), String> {
        let Some((token, seen)) = &sess.token else { return Ok(()) };
        if *seen == self.auth_epoch() { return Ok(()); }
        let token = token.clone();
        self.bind_token(sess, &token).inspect_err(|_| deny(sess))
    }
    fn bind_token(&self, sess: &mut Session, token: &str) -> Result<(), String> {
        let epoch = self.auth_epoch();
        let id = token_id(token).ok_or("session: not a session token")?;
        let sessions = self.system(SESSIONS)?; let secrets = self.system(SECRETS)?;
        let sk = sessions.schema.key_from_value(&Value::Bytes(id.to_vec()))?;
        let row = sessions.with_pk(sk, |r| r.to_vec()).ok_or("session: unknown or signed out; sign in again")?;
        let (Value::Text(secret), Value::Bytes(generation), Value::Int(expires)) = (decode_col(&sessions.schema, &row, 1), decode_col(&sessions.schema, &row, 2), decode_col(&sessions.schema, &row, 4)) else { return Err("session: damaged session row".into()) };
        if expires <= now_micros() { let _ = sessions.delete_by_pk(sk); return Err("session: expired; sign in again".into()); }
        let current = secrets.with_pk(Self::text_pk(&secrets, &secret)?, |r| decode_col(&secrets.schema, r, 2));
        if current != Some(Value::Bytes(generation)) { return Err("session: ended by a password change or a sign-out everywhere; sign in again".into()); }
        let (tname, key) = secret.split_once(':').ok_or("session: damaged session row")?;
        let (t, cfg) = self.auth_table(tname).map_err(|_| format!("session: {tname} no longer takes sign-ins"))?;
        let pk = t.schema.key_from_value(&key_value(&t.schema.columns[t.schema.pk].ty, key)?)?;
        let user = t.with_pk(pk, |r| r.to_vec()).ok_or("session: the user no longer exists")?;
        let role = match &cfg.role { RoleSrc::Fixed(r) => r.clone(), RoleSrc::Column(c) => match decode_col(&t.schema, &user, *c) { Value::Text(r) => r, _ => return Err("session: the user has no role".into()) } };
        if !self.acl.read().unwrap().roles.contains(&role) { return Err(format!("session: the user's role {role} is not a role")); }
        let attrs: HashMap<String, Value> = user_pairs(&t, &user).into_iter().filter(|(_, v)| *v != Value::Null).collect();
        sess.user = match decode_col(&t.schema, &user, cfg.login) { Value::Text(l) => Some(l), v => Some(crate::expr::num_text(&v)) };
        sess.roles = vec![role]; sess.attrs = attrs; sess.assumed = false; sess.token = Some((token.to_string(), epoch));
        Ok(())
    }

    /// End one session. An unknown token is not an error.
    pub fn sign_out(&self, token: &str) -> Result<(), String> {
        let Some(id) = token_id(token) else { return Ok(()) };
        let sessions = self.system(SESSIONS)?;
        match sessions.delete_by_pk(sessions.schema.key_from_value(&Value::Bytes(id.to_vec()))?) { Ok(_) | Err(crate::table::Abort::NotFound) => Ok(()), Err(e) => Err(e.to_string()) }
    }
    /// Set a user's password (the application's own decision: no old password is asked for) and end their sessions.
    pub fn set_password(&self, table: &str, key: &Value, password: &str) -> Result<(), String> {
        let (t, _) = self.auth_table(table)?; self.check_password(password)?;
        let row = t.with_pk(t.schema.key_from_value(key)?, |r| r.to_vec()).ok_or_else(|| format!("no user in {table} with that key"))?;
        let hash = hash_password(password)?;
        let mut txn = Txn::new(); self.write_secret(&mut txn, &t, &row, Some(&hash))?;
        self.db.commit(txn).map(|_| ()).map_err(|e| e.to_string())
    }
    /// End every session of a user (a new generation for their password row).
    pub fn sign_out_everywhere(&self, table: &str, key: &Value) -> Result<(), String> {
        let (t, _) = self.auth_table(table)?;
        let row = t.with_pk(t.schema.key_from_value(key)?, |r| r.to_vec()).ok_or_else(|| format!("no user in {table} with that key"))?;
        let mut txn = Txn::new(); self.write_secret(&mut txn, &t, &row, None)?;
        self.db.commit(txn).map(|_| ()).map_err(|e| e.to_string())
    }
    /// Called for every row inserted into an auth table: a password left by a deleted user with the same key is
    /// dropped in the same transaction, so a new row never inherits an old password or session.
    pub(crate) fn forget_secret(&self, txn: &mut Txn, table: &Table, row: &[u8]) -> Result<(), String> {
        if !self.acl.read().unwrap().auth.contains_key(&table.schema.name.to_lowercase()) { return Ok(()); }
        let secrets = self.system(SECRETS)?; let id = Self::secret_id(table, row); let k = Self::text_pk(&secrets, &id)?;
        if secrets.txn_get(txn, k).is_some() { secrets.txn_delete(txn, k).map_err(|e| e.to_string())?; }
        if let Some(ids) = self.db.table(crate::oauth::IDENTITIES) {
            let ix = ids.index_on(1).ok_or("the identities table has no index")?;
            let mut gone = vec![]; ids.index_lookup(&ix, crate::table::text_key(id.as_bytes()), |r| { gone.push(ids.pk_of(r)); true });
            for g in gone { ids.txn_delete(txn, g).map_err(|e| e.to_string())?; }
        }
        Ok(())
    }
    /// The password-row id of the user a valid session token belongs to.
    pub(crate) fn token_secret(&self, token: &str) -> Result<String, String> {
        let mut s = Session::default(); self.session_from_token(&mut s, token)?;
        let id = token_id(token).ok_or("session: not a session token")?;
        let sessions = self.system(SESSIONS)?;
        match sessions.with_pk(sessions.schema.key_from_value(&Value::Bytes(id.to_vec()))?, |r| decode_col(&sessions.schema, r, 1)) { Some(Value::Text(t)) => Ok(t), _ => Err("session: unknown or signed out; sign in again".into()) }
    }
    /// The identities table (provider accounts linked to users), made on first use with an index on the user.
    fn identities(&self) -> Result<Arc<Table>, String> {
        if let Some(t) = self.db.table(crate::oauth::IDENTITIES) { return Ok(t); }
        let _g = self.auth.create_lock.lock().unwrap();
        if let Some(t) = self.db.table(crate::oauth::IDENTITIES) { return Ok(t); }
        self.create_system_table("CREATE TABLE _auth_identities (id VARCHAR(400) PRIMARY KEY, secret VARCHAR(160) NOT NULL, email VARCHAR(255), created TIMESTAMP NOT NULL)")?;
        let ix = "CREATE INDEX _auth_identities_secret ON _auth_identities (secret)";
        self.apply_admin(ix)?; self.log_admin(ix);
        self.system(crate::oauth::IDENTITIES)
    }
    /// The user a password-row id names, if that row and the user still exist.
    fn user_of_secret(&self, secret: &str) -> Option<(Arc<Table>, Vec<u8>)> {
        let (tname, key) = secret.split_once(':')?; let (t, _) = self.auth_table(tname).ok()?;
        let pk = t.schema.key_from_value(&key_value(&t.schema.columns[t.schema.pk].ty, key).ok()?).ok()?;
        let row = t.with_pk(pk, |r| r.to_vec())?; Some((t, row))
    }
    /// Sign in (or up) with a provider identity: an identity already linked signs in its user; a new one links to
    /// `link` (a signed-in user's password-row id), or makes a user; it never attaches to an existing user by email.
    pub(crate) fn oauth_sign_in(&self, table: &str, provider: &str, who: crate::oauth::Identity, link: Option<&str>) -> Result<SignedIn, String> {
        let (t, cfg) = self.auth_table(table)?; let ids = self.identities()?; let secrets = self.system(SECRETS)?;
        let email = normalize(&who.email); let id = format!("{provider}:{}", who.subject);
        if id.len() > 400 { return Err("sign-in failed: the provider's account id is too long".into()); }
        let ik = Self::text_pk(&ids, &id)?;
        let linked = ids.with_pk(ik, |r| decode_col(&ids.schema, r, 1)).and_then(|v| if let Value::Text(s) = v { Some(s) } else { None });
        let linked_user = linked.as_deref().and_then(|s| self.user_of_secret(s).map(|u| (s.to_string(), u)));
        let ident_row = |secret: &str| encode_row(&ids.schema, &[Value::Text(id.clone()), Value::Text(secret.to_string()), Value::Text(email.clone()), Value::Int(now_micros())]);
        // the user to sign in, the identity row to write (None: already linked), whether the user is new
        let mut txn = Txn::new();
        let (user_t, user_row, created) = if let Some(target) = link {
            let (ut, ur) = self.user_of_secret(target).ok_or("session: the user no longer exists")?;
            if let Some((s, _)) = &linked_user { if s != target { return Err(format!("sign-in failed: this {provider} account is linked to another user")); } }
            else { if linked.is_some() { ids.txn_delete(&mut txn, ik).map_err(|e| e.to_string())?; } ids.txn_insert(&mut txn, &ident_row(target)?).map_err(|e| e.to_string())?; }
            (ut, ur, false)
        } else if let Some((_, (ut, ur))) = linked_user {
            // a provider account belongs to one user: a sign-in to another table neither takes it nor unlinks it
            if !ut.schema.name.eq_ignore_ascii_case(&t.schema.name) { return Err(format!("sign-in failed: this {provider} account belongs to a user of another table")); }
            (ut, ur, false)
        } else {
            if linked.is_some() { ids.txn_delete(&mut txn, ik).map_err(|e| e.to_string())?; }   // it pointed at a user who is gone
            let ty = &t.schema.columns[cfg.login].ty; let mut key = vec![0u8; ty.width()];
            let existing = if encode_value(ty, &Value::Text(email.clone()), &mut key).is_ok() { t.with_unique(&key, |r| r.to_vec()) } else { None };
            match existing {
                // never by email: the account may be someone else's (made with their address, or through a provider
                // that checks emails less strictly). Its owner signs in and links the provider.
                Some(_) => return Err(format!("sign-in failed: an account with this email already exists; sign in to it, then link {provider} from that account")),
                None => {
                    // a new user whose login is the verified email: inserted through SQL (defaults, automatic ids, the
                    // insert hook), then the identity, a password row without a password, and the session
                    let mut sess = Session::default(); self.exec_s(&mut sess, "BEGIN", &[])?;
                    let run = |sess: &mut Session| -> Result<(Vec<u8>, String), String> {
                        let sql = format!("INSERT INTO \"{}\" (\"{}\") VALUES (?) RETURNING *", t.schema.name, t.schema.columns[cfg.login].name);
                        let row = self.exec_s(sess, &sql, &[Value::Text(email.clone())])?.pop().ok_or("sign-in inserted no row")?;
                        let enc = encode_row(&t.schema, &row)?; let tx = sess.txn.as_mut().unwrap();
                        ids.txn_insert(tx, &ident_row(&Self::secret_id(&t, &enc))?).map_err(|e| e.to_string())?;
                        let token = self.write_secret_and_session(tx, &t, &enc, Some(NO_PASSWORD))?;
                        Ok((enc, token))
                    };
                    return match run(&mut sess) {
                        Ok((row, token)) => { self.exec_s(&mut sess, "COMMIT", &[])?; Ok(SignedIn { token, user: user_pairs(&t, &row), created: true }) }
                        Err(e) => { let _ = self.exec_s(&mut sess, "ROLLBACK", &[]); Err(e) }
                    };
                }
            }
        };
        // a session for that user (a user without a password row gets one without a password, for its generation)
        let sid = Self::secret_id(&user_t, &user_row);
        let has_row = secrets.txn_get(&mut txn, Self::text_pk(&secrets, &sid)?).is_some();
        let token = if has_row {
            let sr = secrets.txn_get(&mut txn, Self::text_pk(&secrets, &sid)?).unwrap();
            let sessions = self.system(SESSIONS)?;
            let (token, row) = self.session_row(&sessions, &sid, &decode_col(&secrets.schema, &sr, 2))?;
            sessions.txn_insert(&mut txn, &row).map_err(|e| e.to_string())?; token
        } else { self.write_secret_and_session(&mut txn, &user_t, &user_row, Some(NO_PASSWORD))? };
        self.db.commit(txn).map_err(|e| e.to_string())?;
        Ok(SignedIn { token, user: user_pairs(&user_t, &user_row), created })
    }

    fn check_password(&self, pw: &str) -> Result<(), String> {
        let min = self.cfg.auth.password_min;
        if pw.chars().count() < min { return Err(format!("the password is too short: at least {min} characters")); }
        if pw.len() > PASSWORD_MAX { return Err(format!("the password is too long: at most {PASSWORD_MAX} bytes")); }
        Ok(())
    }
    /// Write the password row (a new hash, or keep the hash) with a new generation: every earlier session ends.
    fn write_secret(&self, txn: &mut Txn, t: &Table, user: &[u8], hash: Option<&str>) -> Result<Vec<u8>, String> {
        let secrets = self.system(SECRETS)?; let id = Self::secret_id(t, user); let k = Self::text_pk(&secrets, &id)?;
        let old = secrets.txn_get(txn, k);
        let hash = match (hash, &old) { (Some(h), _) => h.to_string(), (None, Some(o)) => match decode_col(&secrets.schema, o, 1) { Value::Text(h) => h, _ => return Err("damaged password row".into()) }, (None, None) => return Err("the user has no password".into()) };
        let row = encode_row(&secrets.schema, &[Value::Text(id), Value::Text(hash), Value::Bytes(random::<16>().to_vec()), Value::Int(now_micros())])?;
        if old.is_some() { let r2 = row.clone(); secrets.txn_update(txn, k, move |_| Ok(r2)).map_err(|e| e.to_string())?; } else { secrets.txn_insert(txn, &row).map_err(|e| e.to_string())?; }
        Ok(row)
    }
    fn write_secret_and_session(&self, txn: &mut Txn, t: &Table, user: &[u8], hash: Option<&str>) -> Result<String, String> {
        let secret = self.write_secret(txn, t, user, hash)?;
        let sessions = self.system(SESSIONS)?; let secrets = self.system(SECRETS)?;
        let (token, row) = self.session_row(&sessions, &Self::secret_id(t, user), &decode_col(&secrets.schema, &secret, 2))?;
        sessions.txn_insert(txn, &row).map_err(|e| e.to_string())?;
        Ok(token)
    }
    fn new_session(&self, secrets: &Table, secret_id: &str, secret_row: &[u8]) -> Result<String, String> {
        let sessions = self.system(SESSIONS)?;
        let (token, row) = self.session_row(&sessions, secret_id, &decode_col(&secrets.schema, secret_row, 2))?;
        sessions.insert(&row).map_err(|e| e.to_string())?;
        Ok(token)
    }
    fn session_row(&self, sessions: &Table, secret_id: &str, generation: &Value) -> Result<(String, Vec<u8>), String> {
        use sha2::Digest;
        let raw = random::<32>(); let id: [u8; 32] = sha2::Sha256::digest(raw).into();
        let now = now_micros(); let ttl = self.cfg.auth.session_ttl.as_micros() as i64;
        let row = encode_row(&sessions.schema, &[Value::Bytes(id.to_vec()), Value::Text(secret_id.to_string()), generation.clone(), Value::Int(now), Value::Int(now.saturating_add(ttl))])?;
        Ok((format!("{TOKEN_PREFIX}{}", hex(&raw)), row))
    }
    /// Delete expired sessions, at most once an hour (from sign-ins).
    fn sweep_sessions(&self) {
        let now = now_micros(); let last = self.auth.last_sweep.load(std::sync::atomic::Ordering::Relaxed);
        if now - last < SWEEP_EVERY_US || self.auth.last_sweep.compare_exchange(last, now, std::sync::atomic::Ordering::AcqRel, std::sync::atomic::Ordering::Relaxed).is_err() { return; }
        let Ok(sessions) = self.system(SESSIONS) else { return };
        let mut gone = vec![]; sessions.scan(|r: &[u8]| { if let Value::Int(e) = decode_col(&sessions.schema, r, 4) { if e <= now { gone.push(sessions.pk_of(r)); } } true });
        for k in gone { let _ = sessions.delete_by_pk(k); }
    }
}

/// A session whose token failed: no roles (nothing passes a grant), still a user (never the application), and the
/// token kept, so each later statement checks it again and fails.
fn deny(sess: &mut Session) { sess.roles.clear(); sess.attrs.clear(); if sess.user.is_none() { sess.user = Some("(signed out)".into()); } if let Some(t) = sess.token.as_mut() { t.1 = u64::MAX; } }
fn user_pairs(t: &Table, row: &[u8]) -> Vec<(String, Value)> { (0..t.schema.columns.len()).map(|i| (t.schema.columns[i].name.clone(), decode_col(&t.schema, row, i))).collect() }
fn key_text(v: &Value) -> String { match v { Value::Text(s) => s.clone(), v => crate::expr::num_text(v) } }
fn key_value(ty: &ColType, s: &str) -> Result<Value, String> { match ty { ColType::Int => s.parse::<i64>().map(Value::Int).map_err(|_| "session: damaged session row".to_string()), _ => Ok(Value::Text(s.to_string())) } }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::sql::error_code;
    fn tmp(name: &str) -> std::path::PathBuf { let d = std::env::temp_dir().join(format!("sqweezdb-auth-{}-{name}", std::process::id())); let _ = std::fs::remove_dir_all(&d); d }
    fn q(s: &Sql, sql: &str) -> Vec<Vec<Value>> { s.exec_s(&mut Session::default(), sql, &[]).unwrap_or_else(|e| panic!("{sql}: {e}")) }
    fn qs(s: &Sql, sess: &mut Session, sql: &str) -> Result<Vec<Vec<Value>>, String> { s.exec_s(sess, sql, &[]) }
    fn text(v: &str) -> Value { Value::Text(v.into()) }
    fn setup(s: &Sql) {
        for st in ["CREATE TABLE users (id SERIAL PRIMARY KEY, email TEXT UNIQUE, name TEXT, role TEXT DEFAULT 'member', tenant INT)",
                   "CREATE TABLE notes (id SERIAL PRIMARY KEY, owner INT, body TEXT)",
                   "CREATE ROLE member", "CREATE ROLE admin", "GRANT SELECT, INSERT ON notes TO member", "GRANT SELECT, INSERT, UPDATE, DELETE ON notes TO admin",
                   "CREATE POLICY own ON notes FOR ALL TO member USING (owner = SESSION.id)",
                   "ALTER TABLE users ENABLE AUTH (ROLE FROM role)"] { q(s, st); }
    }
    fn as_token(s: &Sql, token: &str) -> Result<Session, String> { let mut x = Session::default(); s.session_from_token(&mut x, token)?; Ok(x) }

    #[test] fn sign_up_sign_in_and_policies_per_user() {
        let d = tmp("flow"); let s = Sql::open_with(&d, Config::default()).unwrap(); setup(&s);
        let ann = s.sign_up("users", &[("email".into(), text("Ann@Example.com ")), ("name".into(), text("Ann")), ("tenant".into(), Value::Int(7))], "correct horse").unwrap();
        assert!(ann.token.starts_with("sqz_") && ann.token.len() == 68);
        assert!(ann.user.contains(&("email".to_string(), text("ann@example.com"))), "the login is stored trimmed and lowercased");
        let bob = s.sign_up("users", &[("email".into(), text("bob@example.com"))], "battery staple").unwrap();
        // each session sees its own rows, with the attributes of its own row
        let mut a = as_token(&s, &ann.token).unwrap(); let mut b = as_token(&s, &bob.token).unwrap();
        assert_eq!(a.attrs.get("tenant"), Some(&Value::Int(7))); assert_eq!(a.roles, vec!["member".to_string()]); assert!(!b.attrs.contains_key("tenant"), "NULL columns are not attributes");
        qs(&s, &mut a, "INSERT INTO notes (owner, body) VALUES (1, 'ann''s')").unwrap();
        qs(&s, &mut b, "INSERT INTO notes (owner, body) VALUES (2, 'bob''s')").unwrap();
        assert!(qs(&s, &mut b, "INSERT INTO notes (owner, body) VALUES (1, 'forged')").unwrap_err().contains("policy"));
        assert_eq!(qs(&s, &mut a, "SELECT body FROM notes").unwrap(), vec![vec![text("ann's")]]);
        assert_eq!(qs(&s, &mut b, "SELECT body FROM notes").unwrap(), vec![vec![text("bob's")]]);
        assert!(qs(&s, &mut a, "CREATE TABLE x (id INT PRIMARY KEY)").unwrap_err().starts_with("permission denied"), "a signed-in user is never the application");
        // signing in: case and spaces in the login don't matter; a wrong password and an unknown login read the same
        let again = s.sign_in("users", " ANN@example.com", "correct horse").unwrap(); assert_ne!(again.token, ann.token);
        let e1 = s.sign_in("users", "ann@example.com", "wrong horse").unwrap_err(); let e2 = s.sign_in("users", "nobody@example.com", "correct horse").unwrap_err();
        assert_eq!(e1, e2); assert_eq!(error_code(&e1), "AUTH");
        // a role change in the row applies to the next session built from a token
        q(&s, "UPDATE users SET role = 'admin' WHERE id = 1");
        assert_eq!(as_token(&s, &ann.token).unwrap().roles, vec!["admin".to_string()]);
        q(&s, "UPDATE users SET role = 'nobody' WHERE id = 1");
        assert!(as_token(&s, &ann.token).err().unwrap().contains("not a role"));
        q(&s, "UPDATE users SET role = 'member' WHERE id = 1");
        // passwords: rules; sign-up needs the login
        assert_eq!(error_code(&s.sign_up("users", &[("email".into(), text("c@x"))], "short").unwrap_err()), "TYPE");
        assert!(s.sign_up("users", &[("name".into(), text("no login"))], "long enough").unwrap_err().contains("login column"));
        assert!(s.sign_up("users", &[("email".into(), text("bob@example.com"))], "long enough").unwrap_err().contains("Duplicate"), "one account per login");
        assert!(s.sign_up("users", &[("nope".into(), text("x"))], "long enough").unwrap_err().contains("no such column"));
        // not inside a transaction; garbage tokens
        let mut t = Session::default(); qs(&s, &mut t, "BEGIN").unwrap(); assert!(s.session_from_token(&mut t, &ann.token).is_err()); qs(&s, &mut t, "ROLLBACK").unwrap();
        for bad in ["", "sqz_", "sqz_zz", &ann.token[..60], &format!("sqz_{}", "00".repeat(32))] { assert_eq!(error_code(&as_token(&s, bad).err().unwrap()), "AUTH", "{bad:?}"); }
        drop(s); let _ = std::fs::remove_dir_all(&d);
    }

    #[test] fn sessions_end_on_sign_out_password_change_and_expiry() {
        let d = tmp("end"); let s = Sql::open_with(&d, Config::default()).unwrap(); setup(&s);
        let a = s.sign_up("users", &[("email".into(), text("a@x"))], "password one").unwrap();
        let t2 = s.sign_in("users", "a@x", "password one").unwrap().token;
        s.sign_out(&a.token).unwrap(); s.sign_out(&a.token).unwrap();
        assert!(as_token(&s, &a.token).err().unwrap().contains("signed out")); assert!(as_token(&s, &t2).is_ok(), "only that session ends");
        s.set_password("users", &Value::Int(1), "password two").unwrap();
        assert!(as_token(&s, &t2).err().unwrap().contains("password change"));
        assert!(s.sign_in("users", "a@x", "password one").is_err());
        let t3 = s.sign_in("users", "a@x", "password two").unwrap().token;
        s.sign_out_everywhere("users", &Value::Int(1)).unwrap();
        assert!(as_token(&s, &t3).is_err()); let t4 = s.sign_in("users", "a@x", "password two").unwrap().token;
        // an expired session fails and its row goes
        let sessions = s.db.table(SESSIONS).unwrap(); let k = sessions.schema.key_from_value(&Value::Bytes(token_id(&t4).unwrap().to_vec())).unwrap();
        let sch = sessions.schema.clone(); sessions.update_by_pk(k, |r| { let mut n = r.to_vec(); crate::table::encode_col(&sch, &mut n, 4, &Value::Int(now_micros() - 1)).unwrap(); Ok(n) }).unwrap();
        assert!(as_token(&s, &t4).err().unwrap().contains("expired")); assert!(sessions.with_pk(k, |_| ()).is_none());
        drop(s); let _ = std::fs::remove_dir_all(&d);
    }

    #[test] fn repeated_failures_slow_down_one_login() {
        let d = tmp("limit"); let s = Sql::open_with(&d, Config::default()).unwrap(); setup(&s);
        s.sign_up("users", &[("email".into(), text("a@x"))], "the password").unwrap();
        s.sign_up("users", &[("email".into(), text("b@x"))], "the password").unwrap();
        for _ in 0..FREE_FAILURES { assert_eq!(s.sign_in("users", "a@x", "guess").unwrap_err(), WRONG); }
        let e = s.sign_in("users", "a@x", "the password").unwrap_err(); assert!(e.contains("too many failed sign-ins"), "{e}"); assert_eq!(error_code(&e), "AUTH");
        assert!(s.sign_in("users", "b@x", "the password").is_ok(), "other logins are not affected");
        drop(s); let _ = std::fs::remove_dir_all(&d);
    }

    #[test] fn system_tables_are_hidden_and_a_reused_key_starts_clean() {
        let d = tmp("hidden"); let s = Sql::open_with(&d, Config::default()).unwrap(); setup(&s);
        let a = s.sign_up("users", &[("id".into(), Value::Int(50)), ("email".into(), text("old@x"))], "old password").unwrap();
        for bad in ["SELECT * FROM _auth_secrets", "SELECT count(*) FROM _AUTH_SESSIONS", "DELETE FROM _auth_sessions", "UPDATE _auth_secrets SET hash = 'x' WHERE id = 'users:50'",
                    "INSERT INTO _auth_sessions (id) VALUES (X'00')", "CREATE TABLE _auth_mine (id INT PRIMARY KEY)", "ALTER TABLE _auth_secrets ADD COLUMN x INT",
                    "GRANT SELECT ON _auth_secrets TO member", "CREATE INDEX i ON _auth_sessions (secret)", "ALTER TABLE _auth_secrets ENABLE AUTH (ROLE member)"] {
            assert!(s.exec_s(&mut Session::default(), bad, &[]).is_err(), "{bad}");
        }
        assert!(!s.db.table_names().iter().any(|n| is_system(n)));
        // the user goes; a new row takes the same key: no old password, no old session
        q(&s, "DELETE FROM users WHERE id = 50"); q(&s, "INSERT INTO users (id, email) VALUES (50, 'new@x')");
        assert!(as_token(&s, &a.token).is_err());
        assert!(s.sign_in("users", "new@x", "old password").is_err());
        // setup errors
        q(&s, "CREATE TABLE plain (id INT PRIMARY KEY, name TEXT)"); q(&s, "CREATE TABLE wide (id VARCHAR(500) PRIMARY KEY, email TEXT UNIQUE, role TEXT)");
        for (st, msg) in [("ALTER TABLE plain ENABLE AUTH (ROLE member)", "UNIQUE text column"), ("ALTER TABLE wide ENABLE AUTH", "short text"), ("ALTER TABLE nope ENABLE AUTH", "no such table"),
                          ("ALTER TABLE notes ENABLE AUTH (ROLE FROM owner)", "UNIQUE text column"), ("ALTER TABLE users ENABLE AUTH (ROLE ghost)", "no such role"), ("ALTER TABLE users ENABLE AUTH (ROLE FROM tenant)", "must be text")] {
            let e = s.exec_s(&mut Session::default(), st, &[]).unwrap_err(); assert!(e.contains(msg), "{st}: {e}");
        }
        drop(s); let _ = std::fs::remove_dir_all(&d);
    }

    #[test] fn guesses_at_once_count_against_each_other() {
        let d = tmp("race"); let s = Arc::new(Sql::open_with(&d, Config::default()).unwrap()); setup(&s);
        s.sign_up("users", &[("email".into(), text("a@x"))], "the password").unwrap();
        let hs: Vec<_> = (0..40).map(|_| { let s = s.clone(); std::thread::spawn(move || s.sign_in("users", "a@x", "guess")) }).collect();
        let errs: Vec<String> = hs.into_iter().map(|h| h.join().unwrap().unwrap_err()).collect();
        let tried = errs.iter().filter(|e| e.as_str() == WRONG).count();
        assert!(tried <= FREE_FAILURES as usize, "{tried} guesses were checked; the rest must wait");
        assert_eq!(errs.len() - tried, 40 - tried); assert!(errs.iter().all(|e| e == WRONG || e.contains("too many")));
        drop(s); let _ = std::fs::remove_dir_all(&d);
    }

    #[test] fn a_held_session_follows_sign_in_state() {
        let d = tmp("held"); let s = Arc::new(Sql::open_with(&d, Config::default()).unwrap()); setup(&s);
        q(&s, "CREATE ROLE boss"); q(&s, "GRANT SELECT ON notes TO boss");   // no policy: sees every note
        q(&s, "INSERT INTO notes (owner, body) VALUES (1, 'a1'), (2, 'b1')");
        let a = s.sign_up("users", &[("email".into(), text("a@x")), ("tenant".into(), Value::Int(1))], "password a").unwrap();
        // one session object kept across requests (a connection, a websocket)
        let mut held = as_token(&s, &a.token).unwrap();
        assert_eq!(qs(&s, &mut held, "SELECT count(*) FROM notes").unwrap()[0][0], Value::Int(1));
        q(&s, "UPDATE users SET role = 'boss' WHERE id = 1");                   // a role change applies to the held session
        assert_eq!(qs(&s, &mut held, "SELECT count(*) FROM notes").unwrap()[0][0], Value::Int(2));
        q(&s, "UPDATE users SET role = 'member', tenant = 9 WHERE id = 1");
        assert_eq!(qs(&s, &mut held, "SELECT count(*) FROM notes").unwrap()[0][0], Value::Int(1)); assert_eq!(held.attrs.get("tenant"), Some(&Value::Int(9)));
        // a sign-out ends it at the next statement, and it stays ended (no roles, never the application)
        s.sign_out(&a.token).unwrap();
        assert_eq!(error_code(&qs(&s, &mut held, "SELECT count(*) FROM notes").unwrap_err()), "AUTH");
        assert!(held.roles.is_empty() && held.user.is_some());
        assert!(qs(&s, &mut held, "SELECT count(*) FROM notes").is_err());
        // so does a password change, and the user's deletion
        let t2 = s.sign_in("users", "a@x", "password a").unwrap().token; let mut h2 = as_token(&s, &t2).unwrap();
        s.set_password("users", &Value::Int(1), "password b").unwrap(); assert!(qs(&s, &mut h2, "SELECT 1").is_err());
        let t3 = s.sign_in("users", "a@x", "password b").unwrap().token; let mut h3 = as_token(&s, &t3).unwrap();
        q(&s, "DELETE FROM users WHERE id = 1"); assert!(qs(&s, &mut h3, "SELECT 1").is_err());
        // a token that fails leaves the session with nothing, not as the application
        let mut bad = Session::default(); assert!(s.session_from_token(&mut bad, "sqz_00").is_err());
        assert!(qs(&s, &mut bad, "SELECT count(*) FROM notes").unwrap_err().starts_with("permission denied"));
        assert!(qs(&s, &mut bad, "CREATE TABLE x (id INT PRIMARY KEY)").is_err());
        drop(s); let _ = std::fs::remove_dir_all(&d);
    }

    #[test] fn a_sign_out_racing_a_statement_still_ends_the_session() {
        // durable, on disk: a delete then waits for its fsync between the log append and the publish, which is where
        // a statement could check the token too early (the counter has to move after the publish)
        let d = std::path::PathBuf::from(format!("data/nocow/auth-revrace-{}", std::process::id())); let _ = std::fs::remove_dir_all(&d);
        let s = Arc::new(Sql::open_with(&d, Config::default().durable(crate::config::Durability::Fsync)).unwrap()); setup(&s);
        s.sign_up("users", &[("email".into(), text("a@x"))], "password a").unwrap();
        for round in 0..300 {
            let t = s.sign_in("users", "a@x", "password a").unwrap().token;
            let mut held = as_token(&s, &t).unwrap();
            let (stop, s2) = (Arc::new(std::sync::atomic::AtomicBool::new(false)), s.clone());
            let st = stop.clone();
            let h = std::thread::spawn(move || { while !st.load(std::sync::atomic::Ordering::Relaxed) { if s2.exec_s(&mut held, "SELECT count(*) FROM notes", &[]).is_err() { return true; } } false });
            s.sign_out(&t).unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            while !h.is_finished() && Instant::now() < deadline { std::thread::sleep(Duration::from_millis(1)); }
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            assert!(h.join().unwrap(), "round {round}: the session went on after its sign-out");
            if round % 50 == 49 { s.auth.failures.lock().unwrap().clear(); }
        }
        drop(s); let _ = std::fs::remove_dir_all(&d);
    }
    #[test] fn subscriptions_from_a_token_end_with_it() {
        let d = tmp("subs"); let s = Arc::new(Sql::open_with(&d, Config::default()).unwrap()); setup(&s);
        let a = s.sign_up("users", &[("email".into(), text("a@x"))], "password a").unwrap();
        let held = as_token(&s, &a.token).unwrap();
        let sub = s.reactor().subscribe(&held, "SELECT * FROM notes", &[]).unwrap();
        let (watch, _) = s.reactor().watch(&held, "SELECT count(*) FROM notes", &[]).unwrap();
        q(&s, "INSERT INTO notes (owner, body) VALUES (1, 'mine')");
        assert!(matches!(sub.recv_timeout(Duration::from_secs(2)), Some(crate::live::Event::Change(_))));
        assert!(matches!(watch.recv_timeout(Duration::from_secs(2)), Some(crate::live::Event::Live { .. })));
        s.sign_out(&a.token).unwrap();
        q(&s, "INSERT INTO notes (owner, body) VALUES (1, 'after')");
        assert!(matches!(sub.recv_timeout(Duration::from_secs(2)), Some(crate::live::Event::Overflow { .. })), "the subscription is dropped");
        assert!(matches!(watch.recv_timeout(Duration::from_secs(2)), Some(crate::live::Event::Overflow { .. })), "the live query is dropped");
        assert!(s.reactor().subscribe(&held, "SELECT * FROM notes", &[]).is_err(), "and can't be made again");
        q(&s, r#"CREATE TABLE "odd:name" (id INT PRIMARY KEY, email TEXT UNIQUE, role TEXT)"#);
        assert!(s.exec_s(&mut Session::default(), r#"ALTER TABLE "odd:name" ENABLE AUTH"#, &[]).is_err());
        drop(sub); drop(watch); drop(s); let _ = std::fs::remove_dir_all(&d);
    }

    #[test] fn sign_ins_survive_restarts_and_snapshots() {
        let d = tmp("restart"); let token;
        { let s = Sql::open_with(&d, Config::default()).unwrap(); setup(&s); q(&s, "CREATE TABLE staff (id UUID PRIMARY KEY DEFAULT uuid(), login VARCHAR(40) UNIQUE)"); q(&s, "ALTER TABLE staff ENABLE AUTH (ROLE admin)");
          token = s.sign_up("users", &[("email".into(), text("a@x"))], "the password").unwrap().token;
          s.sign_up("staff", &[("login".into(), text("root"))], "staff password").unwrap(); }
        for round in ["log", "snapshot"] {
            let s = Sql::open_with(&d, Config::default()).unwrap();
            assert_eq!(as_token(&s, &token).unwrap().roles, vec!["member".to_string()], "{round}");
            assert!(s.sign_in("users", "a@x", "the password").is_ok(), "{round}");
            assert_eq!(as_token(&s, &s.sign_in("staff", "root", "staff password").unwrap().token).unwrap().roles, vec!["admin".to_string()], "{round}: a fixed role, a UUID key");
            assert!(s.exec_s(&mut Session::default(), "SELECT * FROM _auth_secrets", &[]).is_err(), "{round}");
            if round == "log" { s.snapshot(); }
        }
        { let s = Sql::open_with(&d, Config::default()).unwrap(); q(&s, "ALTER TABLE users DISABLE AUTH"); assert!(as_token(&s, &token).err().unwrap().contains("no longer takes sign-ins")); }
        let _ = std::fs::remove_dir_all(&d);
    }
}
