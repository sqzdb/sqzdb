//! OAuth2 sign-in for tables marked ENABLE AUTH: Google and any OpenID Connect provider (an ID token, verified here),
//! and GitHub (its user API). The application owns HTTP: `oauth_start` gives the provider URL to send the browser
//! to, and `oauth_finish` takes the code the browser brings back.
//!
//! - Each start makes a single-use `state` (bound to the provider, the table and the redirect URL, valid 10 minutes),
//!   a PKCE verifier (S256), and for OpenID Connect a nonce the ID token must carry.
//! - An ID token is accepted only with RS256 and a key from the provider's JWKS, the expected issuer, this client as
//!   audience, an unexpired time, the nonce, and a verified email.
//! - A provider identity is filed under `<provider>:<subject>` in `_auth_identities`, pointing at the user's password
//!   row. A first sign-in makes a user whose login is the verified email. If a user with that login already has a
//!   password, the sign-in is refused: without email verification here, that account could belong to someone who
//!   typed another person's email, so linking is done by the signed-in user (`oauth_start` with their token).
use crate::auth::SignedIn;
use crate::config::{OAuthKind, OAuthProvider};
use crate::sql::Sql;
use base64::Engine;
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub const IDENTITIES: &str = "_auth_identities";
const FLOW_TTL: Duration = Duration::from_secs(600);
const JWKS_TTL: Duration = Duration::from_secs(3600);
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Where to send the browser, and the state value the provider sends back with the code.
#[derive(Debug, Clone)] pub struct OAuthStart { pub url: String, pub state: String }
/// A sign-in waiting for the provider's answer.
pub(crate) struct Flow { provider: String, table: String, verifier: String, nonce: String, redirect: String, link: Option<String>, at: Instant }
/// Who the provider says signed in.
pub(crate) struct Identity { pub subject: String, pub email: String }

#[derive(Default)] pub struct OAuthState { pub(crate) flows: std::sync::Mutex<HashMap<String, Flow>>, jwks: std::sync::Mutex<HashMap<String, (Instant, serde_json::Value)>> }

fn hexs(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
fn random<const N: usize>() -> [u8; N] { let mut b = [0u8; N]; getrandom::fill(&mut b).expect("the operating system's random source"); b }
fn enc(s: &str) -> String { s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect() }
fn fail(m: impl std::fmt::Display) -> String { format!("sign-in failed: {m}") }

/// Run an HTTP exchange on its own thread and runtime (callers may themselves be inside one).
fn http<T: Send, F, Fut>(f: F) -> Result<T, String> where F: FnOnce(reqwest::Client) -> Fut + Send, Fut: std::future::Future<Output = Result<T, String>> {
    std::thread::scope(|s| s.spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
        let client = reqwest::Client::builder().timeout(Duration::from_secs(10)).user_agent(concat!("sqweezdb/", env!("CARGO_PKG_VERSION"))).build().map_err(|e| e.to_string())?;
        rt.block_on(f(client))
    }).join().map_err(|_| "the HTTP thread panicked".to_string())?)
}
async fn json_of(r: reqwest::Response, what: &str) -> Result<serde_json::Value, String> {
    let status = r.status(); let body = r.text().await.map_err(|e| fail(format!("{what}: {e}")))?;
    if !status.is_success() { return Err(fail(format!("{what}: HTTP {status}: {}", body.chars().take(200).collect::<String>()))); }
    serde_json::from_str(&body).map_err(|e| fail(format!("{what}: not JSON ({e})")))
}

impl Sql {
    fn provider(&self, name: &str) -> Result<&OAuthProvider, String> { self.cfg.auth.oauth.get(name).ok_or_else(|| fail(format!("no sign-in provider {name} (set auth.oauth.{name})"))) }

    /// Begin a sign-in with `provider` for users of `table`: send the browser to `url`; the provider sends it back to
    /// `redirect_uri` with a code and `state`. With `link_token` (a session of a signed-in user), the provider
    /// account is linked to that user instead.
    pub fn oauth_start(&self, table: &str, provider: &str, redirect_uri: &str, link_token: Option<&str>) -> Result<OAuthStart, String> {
        self.auth_table_of(table)?; let p = self.provider(provider)?;
        if !(redirect_uri.starts_with("https://") || redirect_uri.starts_with("http://")) { return Err(fail("the redirect URL must be an http or https URL")); }
        let link = match link_token { Some(t) => Some(self.token_secret(t)?), None => None };
        let (state, verifier, nonce) = (hexs(&random::<32>()), B64.encode(random::<32>()), hexs(&random::<16>()));
        let challenge = { use sha2::Digest; B64.encode(sha2::Sha256::digest(verifier.as_bytes())) };
        let mut q = vec![("response_type", "code".to_string()), ("client_id", p.client_id.clone()), ("redirect_uri", redirect_uri.to_string()), ("scope", p.scopes.clone()), ("state", state.clone()), ("code_challenge", challenge), ("code_challenge_method", "S256".into())];
        if p.kind == OAuthKind::Oidc { q.push(("nonce", nonce.clone())); }
        let url = format!("{}{}{}", p.auth_url, if p.auth_url.contains('?') { "&" } else { "?" }, q.iter().map(|(k, v)| format!("{k}={}", enc(v))).collect::<Vec<_>>().join("&"));
        let mut flows = self.oauth.flows.lock().unwrap();
        if flows.len() > 10_000 { flows.retain(|_, f| f.at.elapsed() < FLOW_TTL); }
        if flows.len() > 100_000 { return Err(fail("too many sign-ins in progress; try again shortly")); }
        flows.insert(state.clone(), Flow { provider: provider.into(), table: table.to_lowercase(), verifier, nonce, redirect: redirect_uri.into(), link, at: Instant::now() });
        Ok(OAuthStart { url, state })
    }

    /// Finish a sign-in: exchange `code` (with `state` from the same start), find or make the user, start a session.
    pub fn oauth_finish(&self, table: &str, provider: &str, code: &str, state: &str) -> Result<SignedIn, String> {
        let flow = self.oauth.flows.lock().unwrap().remove(state).ok_or_else(|| fail("unknown or already used sign-in state; start again"))?;
        if flow.at.elapsed() > FLOW_TTL { return Err(fail("the sign-in took longer than 10 minutes; start again")); }
        if flow.provider != provider || flow.table != table.to_lowercase() { return Err(fail("this state belongs to another sign-in")); }
        let p = self.provider(provider)?.clone();
        let who = match p.kind { OAuthKind::Oidc => self.oidc_identity(&p, provider, code, &flow)?, OAuthKind::Github => github_identity(&p, code, &flow)? };
        self.oauth_sign_in(table, provider, who, flow.link.as_deref())
    }

    fn oidc_identity(&self, p: &OAuthProvider, name: &str, code: &str, flow: &Flow) -> Result<Identity, String> {
        let form = [("grant_type", "authorization_code"), ("code", code), ("redirect_uri", &flow.redirect), ("client_id", &p.client_id), ("client_secret", &p.client_secret), ("code_verifier", &flow.verifier)];
        let url = p.token_url.clone();
        let tok = http(|c| async move { json_of(c.post(&url).header("Accept", "application/json").form(&form).send().await.map_err(|e| fail(format!("token request: {e}")))?, "token request").await })?;
        let id_token = tok.get("id_token").and_then(|v| v.as_str()).ok_or_else(|| fail(format!("{name} returned no ID token")))?;
        let claims = self.verify_id_token(p, name, id_token, &flow.nonce)?;
        let sub = claims.get("sub").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).ok_or_else(|| fail("the ID token has no subject"))?;
        let email = claims.get("email").and_then(|v| v.as_str()).ok_or_else(|| fail(format!("{name} gave no email (ask for the email scope)")))?;
        let verified = matches!(claims.get("email_verified"), Some(serde_json::Value::Bool(true))) || claims.get("email_verified").and_then(|v| v.as_str()) == Some("true");
        if !verified { return Err(fail(format!("{name} has not verified this account's email"))); }
        Ok(Identity { subject: sub.into(), email: email.into() })
    }

    /// Check an ID token: RS256 with a key from the provider's JWKS, then issuer, audience, time and nonce.
    pub(crate) fn verify_id_token(&self, p: &OAuthProvider, name: &str, token: &str, nonce: &str) -> Result<serde_json::Map<String, serde_json::Value>, String> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 { return Err(fail("the ID token is not a JWT")); }
        let dec = |s: &str| B64.decode(s.trim_end_matches('=')).map_err(|_| fail("the ID token is not base64url"));
        let header: serde_json::Value = serde_json::from_slice(&dec(parts[0])?).map_err(|_| fail("the ID token header is not JSON"))?;
        if header.get("alg").and_then(|v| v.as_str()) != Some("RS256") { return Err(fail("the ID token is not signed with RS256")); }
        let kid = header.get("kid").and_then(|v| v.as_str()).map(str::to_string);
        let sig = dec(parts[2])?; let msg = format!("{}.{}", parts[0], parts[1]);
        let mut checked = false;
        for refresh in [false, true] {
            let keys = self.jwks(p, name, refresh)?;
            let cands: Vec<&serde_json::Value> = keys.get("keys").and_then(|k| k.as_array()).map(|a| a.iter().filter(|k| k.get("kty").and_then(|v| v.as_str()) == Some("RSA") && (kid.is_none() || k.get("kid").and_then(|v| v.as_str()) == kid.as_deref())).collect()).unwrap_or_default();
            if cands.is_empty() { continue; }
            for k in cands {
                let (Some(n), Some(e)) = (k.get("n").and_then(|v| v.as_str()), k.get("e").and_then(|v| v.as_str())) else { continue };
                let (n, e) = (dec(n)?, dec(e)?);
                if (ring::signature::RsaPublicKeyComponents { n: &n[..], e: &e[..] }).verify(&ring::signature::RSA_PKCS1_2048_8192_SHA256, msg.as_bytes(), &sig).is_ok() { checked = true; break; }
            }
            if checked { break; }
        }
        if !checked { return Err(fail("the ID token's signature does not match the provider's keys")); }
        let claims: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(&dec(parts[1])?).map_err(|_| fail("the ID token claims are not JSON"))?;
        let iss = claims.get("iss").and_then(|v| v.as_str()).unwrap_or("");
        if !p.issuers.iter().any(|i| i == iss) { return Err(fail(format!("the ID token is from {iss:?}, not {}", p.issuers.join(" or ")))); }
        let aud_ok = match claims.get("aud") { Some(serde_json::Value::String(a)) => *a == p.client_id, Some(serde_json::Value::Array(a)) => a.iter().any(|x| x.as_str() == Some(&p.client_id)) && (a.len() == 1 || claims.get("azp").and_then(|v| v.as_str()) == Some(&p.client_id)), _ => false };
        if !aud_ok { return Err(fail("the ID token is for another application")); }
        let now = (crate::table::now_micros() / 1_000_000) as i64;
        if claims.get("exp").and_then(|v| v.as_i64()).map(|exp| exp + 60 < now).unwrap_or(true) { return Err(fail("the ID token has expired")); }
        if claims.get("iat").and_then(|v| v.as_i64()).map(|iat| iat > now + 300).unwrap_or(false) { return Err(fail("the ID token is issued in the future")); }
        if claims.get("nonce").and_then(|v| v.as_str()) != Some(nonce) { return Err(fail("the ID token is not for this sign-in (nonce)")); }
        Ok(claims)
    }
    fn jwks(&self, p: &OAuthProvider, name: &str, refresh: bool) -> Result<serde_json::Value, String> {
        if !refresh { if let Some((at, v)) = self.oauth.jwks.lock().unwrap().get(name) { if at.elapsed() < JWKS_TTL { return Ok(v.clone()); } } }
        let url = p.jwks_url.clone();
        let v = http(|c| async move { json_of(c.get(&url).send().await.map_err(|e| fail(format!("signing keys: {e}")))?, "signing keys").await })?;
        self.oauth.jwks.lock().unwrap().insert(name.into(), (Instant::now(), v.clone()));
        Ok(v)
    }
}

fn github_identity(p: &OAuthProvider, code: &str, flow: &Flow) -> Result<Identity, String> {
    let (token_url, user_url, emails_url) = (p.token_url.clone(), p.user_url.clone(), p.emails_url.clone());
    let form = [("client_id", p.client_id.clone()), ("client_secret", p.client_secret.clone()), ("code", code.to_string()), ("redirect_uri", flow.redirect.clone()), ("code_verifier", flow.verifier.clone())];
    http(|c| async move {
        let tok = json_of(c.post(&token_url).header("Accept", "application/json").form(&form).send().await.map_err(|e| fail(format!("token request: {e}")))?, "token request").await?;
        if let Some(e) = tok.get("error").and_then(|v| v.as_str()) { return Err(fail(format!("GitHub refused the code: {e}"))); }
        let access = tok.get("access_token").and_then(|v| v.as_str()).ok_or_else(|| fail("GitHub returned no access token"))?.to_string();
        let get = |u: String| { let c = c.clone(); let a = access.clone(); async move { json_of(c.get(&u).bearer_auth(&a).header("Accept", "application/vnd.github+json").send().await.map_err(|e| fail(format!("GitHub API: {e}")))?, "GitHub API").await } };
        let user = get(user_url).await?;
        let id = user.get("id").and_then(|v| v.as_i64()).ok_or_else(|| fail("GitHub returned no user id"))?;
        let emails = get(emails_url).await?;
        let email = emails.as_array().and_then(|a| a.iter().find(|e| e.get("primary").and_then(|v| v.as_bool()) == Some(true) && e.get("verified").and_then(|v| v.as_bool()) == Some(true)))
            .and_then(|e| e.get("email").and_then(|v| v.as_str())).ok_or_else(|| fail("the GitHub account has no verified primary email"))?;
        Ok(Identity { subject: id.to_string(), email: email.to_string() })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::sql::error_code;
    use crate::table::Value;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::sync::{Arc, Mutex};

    /// What the fake provider answers for one authorization code.
    #[derive(Clone, Default)] struct Grant { challenge: String, nonce: String, sub: String, email: String, verified: bool, tamper: &'static str }
    #[derive(Default)] struct Fake { grants: Mutex<HashMap<String, Grant>>, gh_emails: Mutex<String> }
    fn b64(b: &[u8]) -> String { B64.encode(b) }
    fn key() -> ring::signature::RsaKeyPair { ring::signature::RsaKeyPair::from_der(include_bytes!("testdata/oauth_test_rsa.der")).unwrap() }
    fn jwt(claims: &serde_json::Value, header: &serde_json::Value, resign: bool) -> String {
        let msg = format!("{}.{}", b64(header.to_string().as_bytes()), b64(claims.to_string().as_bytes()));
        let k = key(); let mut sig = vec![0u8; k.public().modulus_len()];
        k.sign(&ring::signature::RSA_PKCS1_SHA256, &ring::rand::SystemRandom::new(), msg.as_bytes(), &mut sig).unwrap();
        if !resign { return format!("{msg}.{}", b64(&sig)); }
        // claims changed after signing: the signature no longer matches
        let forged = serde_json::json!({ "iss": claims["iss"], "aud": claims["aud"], "sub": "someone-else", "email": claims["email"], "email_verified": true, "exp": claims["exp"], "nonce": claims["nonce"] });
        format!("{}.{}.{}", b64(header.to_string().as_bytes()), b64(forged.to_string().as_bytes()), b64(&sig))
    }
    fn form(body: &str) -> HashMap<String, String> {
        body.split('&').filter_map(|kv| kv.split_once('=')).map(|(k, v)| (k.to_string(), urldec(v))).collect()
    }
    fn urldec(s: &str) -> String { let b = s.as_bytes(); let mut out = vec![]; let mut i = 0; while i < b.len() { if b[i] == b'%' && i + 2 < b.len() + 0 && i + 2 <= b.len() - 1 { out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap()); i += 3; } else if b[i] == b'+' { out.push(b' '); i += 1; } else { out.push(b[i]); i += 1; } } String::from_utf8(out).unwrap() }
    fn serve(fake: Arc<Fake>) -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap(); let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let mut r = BufReader::new(c.try_clone().unwrap()); let mut line = String::new(); if r.read_line(&mut line).is_err() { continue; }
            let (method, path) = { let mut it = line.split_whitespace(); (it.next().unwrap_or("").to_string(), it.next().unwrap_or("").to_string()) };
            let (mut len, mut auth) = (0usize, String::new());
            loop { let mut h = String::new(); if r.read_line(&mut h).is_err() || h == "\r\n" || h.is_empty() { break; } let lower = h.to_lowercase(); if let Some(v) = lower.strip_prefix("content-length:") { len = v.trim().parse().unwrap_or(0); } if lower.starts_with("authorization:") { auth = h[14..].trim().to_string(); } }
            let mut body = vec![0u8; len]; let _ = r.read_exact(&mut body); let body = String::from_utf8_lossy(&body).to_string();
            let (status, out) = route(&fake, &method, &path, &body, &auth, port);
            let _ = write!(c, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}", out.len());
        });
        port
    }
    fn route(fake: &Fake, method: &str, path: &str, body: &str, auth: &str, port: u16) -> (&'static str, String) {
        let pkce_ok = |g: &Grant, f: &HashMap<String, String>| { use sha2::Digest; B64.encode(sha2::Sha256::digest(f.get("code_verifier").map(|s| s.as_str()).unwrap_or("").as_bytes())) == g.challenge };
        match (method, path) {
            ("GET", "/oidc/jwks") => { let pk = ring::signature::RsaPublicKeyComponents::<Vec<u8>>::from(key().public()); ("200 OK", serde_json::json!({ "keys": [{ "kty": "RSA", "kid": "k1", "alg": "RS256", "n": b64(&pk.n), "e": b64(&pk.e) }] }).to_string()) }
            ("POST", "/oidc/token") => {
                let f = form(body); let Some(g) = fake.grants.lock().unwrap().remove(f.get("code").map(|s| s.as_str()).unwrap_or("")) else { return ("400 Bad Request", r#"{"error":"invalid_grant"}"#.into()) };
                if f.get("client_secret").map(|s| s.as_str()) != Some("google-secret") || !pkce_ok(&g, &f) { return ("400 Bad Request", r#"{"error":"invalid_client_or_verifier"}"#.into()); }
                let now = (crate::table::now_micros() / 1_000_000) as i64;
                let mut claims = serde_json::json!({ "iss": "https://accounts.google.com", "aud": "google-client", "sub": g.sub, "email": g.email, "email_verified": g.verified, "iat": now, "exp": now + 3600, "nonce": g.nonce });
                let mut header = serde_json::json!({ "alg": "RS256", "kid": "k1", "typ": "JWT" });
                match g.tamper { "nonce" => claims["nonce"] = "other".into(), "aud" => claims["aud"] = "another-app".into(), "iss" => claims["iss"] = format!("http://127.0.0.1:{port}").into(), "expired" => claims["exp"] = (now - 3600).into(), "alg" => header["alg"] = "none".into(), _ => {} }
                ("200 OK", serde_json::json!({ "id_token": jwt(&claims, &header, g.tamper == "forged"), "access_token": "at" }).to_string())
            }
            ("POST", "/gh/token") => {
                let f = form(body); let Some(g) = fake.grants.lock().unwrap().remove(f.get("code").map(|s| s.as_str()).unwrap_or("")) else { return ("200 OK", r#"{"error":"bad_verification_code"}"#.into()) };
                if !pkce_ok(&g, &f) { return ("200 OK", r#"{"error":"bad_verifier"}"#.into()); }
                ("200 OK", r#"{"access_token":"gh-token","token_type":"bearer"}"#.into())
            }
            ("GET", "/gh/user") => if auth == "Bearer gh-token" { ("200 OK", r#"{"id":4242,"login":"octo"}"#.into()) } else { ("401 Unauthorized", "{}".into()) },
            ("GET", "/gh/emails") => if auth == "Bearer gh-token" { ("200 OK", fake.gh_emails.lock().unwrap().clone()) } else { ("401 Unauthorized", "{}".into()) },
            _ => ("404 Not Found", "{}".into()),
        }
    }
    fn cfg(port: u16) -> Config {
        Config::from_json(&serde_json::json!({ "auth": { "oauth": {
            "google": { "clientId": "google-client", "clientSecret": "google-secret", "authUrl": format!("http://127.0.0.1:{port}/auth"), "tokenUrl": format!("http://127.0.0.1:{port}/oidc/token"), "jwksUrl": format!("http://127.0.0.1:{port}/oidc/jwks"), "issuer": "https://accounts.google.com" },
            "github": { "clientId": "gh-client", "clientSecret": "gh-secret", "authUrl": format!("http://127.0.0.1:{port}/gh/authorize"), "tokenUrl": format!("http://127.0.0.1:{port}/gh/token"), "userUrl": format!("http://127.0.0.1:{port}/gh/user"), "emailsUrl": format!("http://127.0.0.1:{port}/gh/emails") } } } }).to_string()).unwrap()
    }
    fn query(url: &str) -> HashMap<String, String> { form(url.split_once('?').unwrap().1) }
    /// The browser's part: the provider's page approved the sign-in and redirects back with a code.
    fn approve(fake: &Fake, url: &str, code: &str, sub: &str, email: &str, verified: bool, tamper: &'static str) -> String {
        let q = query(url);
        fake.grants.lock().unwrap().insert(code.into(), Grant { challenge: q["code_challenge"].clone(), nonce: q.get("nonce").cloned().unwrap_or_default(), sub: sub.into(), email: email.into(), verified, tamper });
        q["state"].clone()
    }
    fn setup(s: &Sql) { for st in ["CREATE TABLE users (id SERIAL PRIMARY KEY, email TEXT UNIQUE, role TEXT DEFAULT 'member')", "CREATE ROLE member", "CREATE TABLE notes (id SERIAL PRIMARY KEY, owner INT, body TEXT)", "GRANT SELECT ON notes TO member", "CREATE POLICY own ON notes FOR ALL TO member USING (owner = SESSION.id)", "ALTER TABLE users ENABLE AUTH (ROLE FROM role)"] { s.exec_s(&mut crate::sql::Session::default(), st, &[]).unwrap(); } }
    fn tmp(n: &str) -> std::path::PathBuf { let d = std::env::temp_dir().join(format!("sqweezdb-oauth-{}-{n}", std::process::id())); let _ = std::fs::remove_dir_all(&d); d }
    const REDIRECT: &str = "http://127.0.0.1:3000/auth/callback";

    #[test] fn google_sign_in_makes_then_finds_the_user() {
        let fake = Arc::new(Fake::default()); let port = serve(fake.clone()); let d = tmp("google");
        let s = Sql::open_with(&d, cfg(port)).unwrap(); setup(&s);
        let st = s.oauth_start("users", "google", REDIRECT, None).unwrap();
        let q = query(&st.url);
        assert!(st.url.starts_with(&format!("http://127.0.0.1:{port}/auth?")) && q["client_id"] == "google-client" && q["redirect_uri"] == REDIRECT && q["code_challenge_method"] == "S256" && q["scope"] == "openid email profile" && q["state"] == st.state && !q["nonce"].is_empty());
        let state = approve(&fake, &st.url, "c1", "g-123", "Ann@Gmail.com", true, "");
        let a = s.oauth_finish("users", "google", "c1", &state).unwrap();
        assert!(a.created && a.user.contains(&("email".to_string(), Value::Text("ann@gmail.com".into()))));
        let mut u = crate::sql::Session::default(); s.session_from_token(&mut u, &a.token).unwrap(); assert_eq!(u.attrs.get("id"), Some(&Value::Int(1)));
        assert_eq!(error_code(&s.oauth_finish("users", "google", "c1", &state).unwrap_err()), "AUTH", "a state is used once");
        let st2 = s.oauth_start("users", "google", REDIRECT, None).unwrap(); let state2 = approve(&fake, &st2.url, "c2", "g-123", "ann@gmail.com", true, "");
        let b = s.oauth_finish("users", "google", "c2", &state2).unwrap(); assert!(!b.created); assert_eq!(b.user, a.user);
        // an account made by a provider has no password
        assert!(s.sign_in("users", "ann@gmail.com", "anything at all").is_err());
        s.set_password("users", &Value::Int(1), "now a password").unwrap(); assert!(s.sign_in("users", "ann@gmail.com", "now a password").is_ok());
        // the identity survives a restart (its table and index are replayed)
        drop(s); let s = Sql::open_with(&d, cfg(port)).unwrap();
        let st3 = s.oauth_start("users", "google", REDIRECT, None).unwrap(); let state3 = approve(&fake, &st3.url, "c3", "g-123", "ann@gmail.com", true, "");
        assert_eq!(s.oauth_finish("users", "google", "c3", &state3).unwrap().user, a.user);
        assert!(s.exec_s(&mut crate::sql::Session::default(), "SELECT * FROM _auth_identities", &[]).is_err());
        drop(s); let _ = std::fs::remove_dir_all(&d);
    }

    #[test] fn id_tokens_that_do_not_check_out_are_refused() {
        let fake = Arc::new(Fake::default()); let port = serve(fake.clone()); let d = tmp("tokens");
        let s = Sql::open_with(&d, cfg(port)).unwrap(); setup(&s);
        for (i, (tamper, verified, want)) in [("nonce", true, "nonce"), ("aud", true, "another application"), ("iss", true, "is from"), ("expired", true, "expired"), ("alg", true, "RS256"), ("forged", true, "signature"), ("", false, "not verified")].into_iter().enumerate() {
            let st = s.oauth_start("users", "google", REDIRECT, None).unwrap(); let code = format!("t{i}"); let state = approve(&fake, &st.url, &code, "g-9", "x@y.com", verified, tamper);
            let e = s.oauth_finish("users", "google", &code, &state).unwrap_err(); assert!(e.contains(want), "{tamper}: {e}"); assert_eq!(error_code(&e), "AUTH");
        }
        // a code the provider never issued, a state from another provider, an unknown provider
        let st = s.oauth_start("users", "google", REDIRECT, None).unwrap(); assert!(s.oauth_finish("users", "google", "never", &st.state).unwrap_err().contains("token request"));
        let st = s.oauth_start("users", "google", REDIRECT, None).unwrap(); assert!(s.oauth_finish("users", "github", "x", &st.state).unwrap_err().contains("another sign-in"));
        assert!(s.oauth_start("users", "facebook", REDIRECT, None).unwrap_err().contains("no sign-in provider"));
        assert_eq!(s.exec_s(&mut crate::sql::Session::default(), "SELECT count(*) FROM users", &[]).unwrap()[0][0], Value::Int(0), "no user was made");
        drop(s); let _ = std::fs::remove_dir_all(&d);
    }

    #[test] fn a_password_account_is_linked_only_by_its_owner() {
        let fake = Arc::new(Fake::default()); let port = serve(fake.clone()); let d = tmp("link");
        let s = Sql::open_with(&d, cfg(port)).unwrap(); setup(&s);
        let ann = s.sign_up("users", &[("email".into(), Value::Text("ann@gmail.com".into()))], "ann's password").unwrap();
        // someone signing in with a Google account for that email does not get the password account
        let st = s.oauth_start("users", "google", REDIRECT, None).unwrap(); let state = approve(&fake, &st.url, "l1", "g-ann", "ann@gmail.com", true, "");
        assert!(s.oauth_finish("users", "google", "l1", &state).unwrap_err().contains("already has a password"));
        // the owner, signed in, links it
        let st = s.oauth_start("users", "google", REDIRECT, Some(&ann.token)).unwrap(); let state = approve(&fake, &st.url, "l2", "g-ann", "ann@gmail.com", true, "");
        let linked = s.oauth_finish("users", "google", "l2", &state).unwrap(); assert_eq!(linked.user, ann.user);
        let st = s.oauth_start("users", "google", REDIRECT, None).unwrap(); let state = approve(&fake, &st.url, "l3", "g-ann", "ann@gmail.com", true, "");
        assert_eq!(s.oauth_finish("users", "google", "l3", &state).unwrap().user, ann.user, "from now on Google signs her in");
        // a provider account linked to one user can't be linked to another
        let bob = s.sign_up("users", &[("email".into(), Value::Text("bob@x.com".into()))], "bob's password").unwrap();
        let st = s.oauth_start("users", "google", REDIRECT, Some(&bob.token)).unwrap(); let state = approve(&fake, &st.url, "l4", "g-ann", "ann@gmail.com", true, "");
        assert!(s.oauth_finish("users", "google", "l4", &state).unwrap_err().contains("linked to another user"));
        assert!(s.oauth_start("users", "google", REDIRECT, Some("sqz_00")).is_err(), "linking needs a valid session");
        // a deleted user's key taken by a new row: the old provider account does not sign into it
        s.exec_s(&mut crate::sql::Session::default(), "DELETE FROM users WHERE id = 1", &[]).unwrap();
        s.exec_s(&mut crate::sql::Session::default(), "INSERT INTO users (id, email) VALUES (1, 'carol@x.com')", &[]).unwrap();
        let st = s.oauth_start("users", "google", REDIRECT, None).unwrap(); let state = approve(&fake, &st.url, "l5", "g-ann", "ann@gmail.com", true, "");
        let again = s.oauth_finish("users", "google", "l5", &state).unwrap();
        assert!(again.created && again.user.contains(&("email".to_string(), Value::Text("ann@gmail.com".into()))) && !again.user.contains(&("id".to_string(), Value::Int(1))));
        drop(s); let _ = std::fs::remove_dir_all(&d);
    }

    #[test] fn github_sign_in_needs_a_verified_primary_email() {
        let fake = Arc::new(Fake::default()); let port = serve(fake.clone()); let d = tmp("github");
        let s = Sql::open_with(&d, cfg(port)).unwrap(); setup(&s);
        *fake.gh_emails.lock().unwrap() = r#"[{"email":"old@x.com","primary":false,"verified":true},{"email":"Octo@X.com","primary":true,"verified":true}]"#.into();
        let st = s.oauth_start("users", "github", REDIRECT, None).unwrap(); let q = query(&st.url);
        assert!(q["scope"] == "read:user user:email" && q.get("nonce").is_none() && q["code_challenge_method"] == "S256");
        let state = approve(&fake, &st.url, "g1", "", "", true, "");
        let o = s.oauth_finish("users", "github", "g1", &state).unwrap(); assert!(o.created && o.user.contains(&("email".to_string(), Value::Text("octo@x.com".into()))));
        *fake.gh_emails.lock().unwrap() = r#"[{"email":"new@x.com","primary":true,"verified":true}]"#.into();
        let st = s.oauth_start("users", "github", REDIRECT, None).unwrap(); let state = approve(&fake, &st.url, "g2", "", "", true, "");
        assert_eq!(s.oauth_finish("users", "github", "g2", &state).unwrap().user, o.user, "the account is found by its GitHub id, not its email");
        *fake.gh_emails.lock().unwrap() = r#"[{"email":"new@x.com","primary":true,"verified":false}]"#.into();
        drop(s); let d2 = tmp("github2"); let s = Sql::open_with(&d2, cfg(port)).unwrap(); setup(&s);
        let st = s.oauth_start("users", "github", REDIRECT, None).unwrap(); let state = approve(&fake, &st.url, "g3", "", "", true, "");
        assert!(s.oauth_finish("users", "github", "g3", &state).unwrap_err().contains("no verified primary email"));
        drop(s); let _ = std::fs::remove_dir_all(&d); let _ = std::fs::remove_dir_all(&d2);
    }

    #[test] fn provider_settings_are_checked() {
        let bad = |j: serde_json::Value| Config::from_json(&serde_json::json!({ "auth": { "oauth": j } }).to_string()).unwrap_err();
        assert!(bad(serde_json::json!({ "google": { "clientId": "x" } })).contains("clientSecret is required"));
        assert!(bad(serde_json::json!({ "google": { "clientId": "x", "clientSecret": "y", "tokenUrl": "http://example.com/token" } })).contains("https"));
        assert!(bad(serde_json::json!({ "okta": { "clientId": "x", "clientSecret": "y" } })).contains("kind"));
        assert!(bad(serde_json::json!({ "okta": { "kind": "oidc", "clientId": "x", "clientSecret": "y", "authUrl": "https://o/a", "tokenUrl": "https://o/t", "jwksUrl": "https://o/k" } })).contains("issuer is required"));
        let ok = Config::from_json(&serde_json::json!({ "auth": { "oauth": { "google": { "clientId": "x", "clientSecret": "y" }, "github": { "clientId": "a", "clientSecret": "b" } } } }).to_string()).unwrap();
        assert_eq!(ok.auth.oauth["google"].token_url, "https://oauth2.googleapis.com/token"); assert_eq!(ok.auth.oauth["github"].user_url, "https://api.github.com/user");
    }
}
