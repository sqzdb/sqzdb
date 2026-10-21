//! Sessions in a cookie, and the API's own sign-in pages (`/_sqz/…`), for a browser on the API's own site (an app it
//! stands in front of, `app.proxy`, or `app.staticDir`). A page navigation carries cookies, not an Authorization header,
//! so a session that guards pages (middleware) lives in a cookie: HttpOnly (no script reads it), SameSite=Lax (no
//! other site's form or fetch sends it), and over https `__Host-sqz_session` (Secure, this host only). The API takes it
//! wherever it takes a bearer token, from its own site (`cookie_origin_ok`).
//!
//! - `GET /_sqz/sign-in?return=/somewhere`: a page to sign in with a password or a provider of `auth.oauth` (and to
//!   make an account, where `app.signUp` lists the table). It sets the cookie and goes back to `return`, a path on
//!   this site or a page of `app.origins`.
//! - `POST /_sqz/sign-out` (and a page at GET): ends the session, clears the cookie.
//! - `/_sqz/device`: device login. A device (a CLI, a server) got a code from `POST /api/auth/device`; its user, signed
//!   in here, types that code, sees which device asks (and from where, how long ago), and lets it in or not. The
//!   code is always typed: a link with it filled in would let anyone who starts a device sign-in send a signed-in
//!   user one click away from handing over their account.
//!
//! A form posts back with a value that only the browser that loaded it holds (a cookie of its own, compared with the
//! form's field), and from the API's own origin: another site can't sign a visitor in or out.
use crate::app::{cookie, respond, Req};
use crate::mcp::{esc, host_of, page, random_hex, title_case, users_table};
use crate::sql::Sql;
use std::net::IpAddr;

const FORM_COOKIE: &str = "sqz_form";

fn https(sql: &Sql) -> bool { sql.cfg().app.public_url.as_deref().is_some_and(|u| u.starts_with("https://")) || sql.cfg().app.tls.is_some() }
fn secure(sql: &Sql) -> &'static str { if https(sql) { "; Secure" } else { "" } }
/// The session cookie's name: over https `__Host-sqz_session`, which a browser takes only from this very host (Secure,
/// Path=/, no Domain), so a sibling subdomain can't plant one; `sqz_session` over http (local development).
pub fn session_name(sql: &Sql) -> &'static str { if https(sql) { "__Host-sqz_session" } else { "sqz_session" } }
/// The session cookie for `token`, lasting as long as sessions do.
pub(crate) fn session_cookie(sql: &Sql, token: &str) -> String { format!("{}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}{}", session_name(sql), sql.cfg().auth.session_ttl.as_secs(), secure(sql)) }
pub(crate) fn clear_session(sql: &Sql) -> String { format!("{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{}", session_name(sql), secure(sql)) }
/// Whether a request's Origin is the API's own site: its host, or `app.publicUrl`. A browser sends `Origin: null`
/// from a page whose Referrer-Policy is no-referrer, and from sandboxed frames and data: pages: then only its
/// Sec-Fetch-Site (which no script can set) can say the request comes from this very origin.
fn own_site(sql: &Sql, origin: &str, host: Option<&str>, fetch_site: Option<&str>) -> bool {
    if origin == "null" { return fetch_site == Some("same-origin"); }
    let o = origin.trim_end_matches('/');
    o.split_once("://").is_some_and(|(_, h)| host.is_some_and(|x| x.eq_ignore_ascii_case(h))) || sql.cfg().app.public_url.as_deref() == Some(o)
}
/// Whether a request may act on the session cookie. Browsers send Origin with what they post, and with fetches and
/// sockets across origins: the cookie counts only without one (a navigation; not a browser) or from the API's own
/// site (`own_site`), or an origin `app.origins` names ("*" lets any page call the API, never act as its visitor).
pub(crate) fn cookie_origin_ok(sql: &Sql, origin: Option<&str>, host: Option<&str>, fetch_site: Option<&str>) -> bool {
    let Some(o) = origin else { return true };
    own_site(sql, o, host, fetch_site) || sql.cfg().app.origins.iter().any(|x| x != "*" && x.eq_ignore_ascii_case(o.trim_end_matches('/')))
}
/// The session a request carries: `Authorization: Bearer …`, or the session cookie (from the API's own site).
pub(crate) fn token_of(sql: &Sql, req: &Req) -> Option<String> {
    let h = |k: &str| req.headers.get(k).map(String::as_str);
    let from_cookie = || cookie(req, session_name(sql)).filter(|_| cookie_origin_ok(sql, h("origin"), h("host"), h("sec-fetch-site")));
    crate::app::bearer(req).or_else(from_cookie).filter(|t| !t.is_empty())
}
/// The address this API is reached at: `app.publicUrl`, or the scheme and host this request came to.
pub(crate) fn site(sql: &Sql, req: &Req) -> String {
    if let Some(u) = &sql.cfg().app.public_url { return u.trim_end_matches('/').to_string(); }
    format!("{}://{}", if https(sql) { "https" } else { "http" }, req.headers.get("host").map(String::as_str).unwrap_or("localhost"))
}
/// The session token of a browser signed in here (a session that still holds).
fn signed_in(sql: &Sql, req: &Req) -> Option<String> {
    let t = token_of(sql, req)?; let mut s = crate::sql::Session::default();
    sql.session_from_token(&mut s, &t).ok().map(|_| t)
}
/// Where to go back to after signing in or out: a path on this site, or a page on one of `app.origins` (never another
/// site's: no open redirect). Anything else goes home.
pub(crate) fn back_to(sql: &Sql, r: &str) -> String {
    let path_here = r.starts_with('/') && !r.starts_with("//") && !r.contains('\\') && r.bytes().all(|b| (0x21..0x7f).contains(&b));
    if path_here || crate::app::return_ok(sql, r) { r.to_string() } else { "/".into() }
}
fn see_other(to: &str, cookies: &[String]) -> Vec<u8> {
    let mut h: Vec<(String, String)> = vec![("Location".into(), to.into()), ("Cache-Control".into(), "no-store".into()), ("Referrer-Policy".into(), "no-referrer".into())];
    for c in cookies { h.push(("Set-Cookie".into(), c.clone())); }
    respond(303, "text/plain", b"", &h)
}
/// A form posted from this API's own pages: the browser's own value back (`form`), and no other origin.
fn same_browser(sql: &Sql, req: &Req, f: &std::collections::HashMap<String, String>) -> bool {
    let held = cookie(req, FORM_COOKIE).unwrap_or_default();
    let h = |k: &str| req.headers.get(k).map(String::as_str);
    let origin_ok = h("origin").is_none_or(|o| own_site(sql, o, h("host"), h("sec-fetch-site")));
    origin_ok && held.len() == 32 && crate::net::same_secret(held.as_bytes(), f.get("form").map(String::as_bytes).unwrap_or(b""))
}
fn form(req: &Req) -> std::collections::HashMap<String, String> {
    String::from_utf8_lossy(&req.body).split('&').filter(|s| !s.is_empty()).map(|kv| { let (k, v) = kv.split_once('=').unwrap_or((kv, "")); (crate::util::url_decode(&k.replace('+', " ")), crate::util::url_decode(&v.replace('+', " "))) }).collect()
}

/// Answer `/_sqz/…`; None for any other path.
pub(crate) fn handle(sql: &Sql, ip: IpAddr, allow: &dyn Fn() -> bool, req: &Req) -> Option<Vec<u8>> {
    let _ = ip;
    if !req.path.starts_with("/_sqz/") { return None; }
    let q = |k: &str| req.query.get(k).cloned().unwrap_or_default();
    Some(match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/_sqz/sign-in") => sign_in_page(sql, &back_to(sql, &q("return")), q("mode") == "up", req.query.get("error").map(String::as_str)),
        ("POST", "/_sqz/sign-in") => {
            let f = form(req); let back = back_to(sql, f.get("return").map(String::as_str).unwrap_or("/"));
            let up = f.get("action").map(String::as_str) == Some("sign-up");
            if !same_browser(sql, req, &f) { return Some(sign_in_page(sql, &back, up, Some("This form expired, or came from another page. Try again."))); }
            if !sql.cfg().auth.password { return Some(sign_in_page(sql, &back, up, Some("Password sign-in is off here: continue with a provider."))); }
            if !allow() { return Some(sign_in_page(sql, &back, up, Some("Too many sign-ins from here; wait a little and try again."))); }
            let (login, password) = (f.get("login").cloned().unwrap_or_default(), f.get("password").cloned().unwrap_or_default());
            let signed = users_table(sql).and_then(|table| if up {
                if !sql.cfg().app.sign_up.contains_key(&table.to_ascii_lowercase()) { return Err(format!("accounts in {table} are made by the app, not here")); }
                let (t, at) = sql.auth_table_of(&table)?;
                sql.sign_up(&table, &[(t.schema.columns[at.login].name.clone(), crate::table::Value::Text(login.trim().to_string()))], &password)
            } else { sql.sign_in(&table, &login, &password) });
            match signed { Ok(si) => see_other(&back, &[session_cookie(sql, &si.token)]), Err(e) => sign_in_page(sql, &back, up, Some(&e)) }
        }
        ("GET", "/_sqz/sign-out") => sign_out_page(sql, &back_to(sql, &q("return"))),
        ("GET", "/_sqz/device") => device_page(sql, req, None, None),
        ("POST", "/_sqz/device") => {
            let f = form(req); let code = f.get("code").cloned().unwrap_or_default();
            if !same_browser(sql, req, &f) { return Some(device_page(sql, req, None, Some("This form expired, or came from another page. Try again."))); }
            let Some(t) = signed_in(sql, req) else { return Some(device_page(sql, req, None, None)) };
            if !allow() { return Some(device_page(sql, req, None, Some("Too many attempts from here; wait a little and try again."))); }
            // the code as typed: the device that asks, to allow or deny
            if f.get("action").map(String::as_str) == Some("look") { return Some(device_page(sql, req, Some(&code), None)); }
            let allowed = f.get("action").map(String::as_str) == Some("allow");
            match sql.device_decide(&code, allowed.then_some(t.as_str())) {
                Ok(name) => page(200, if allowed { "Device signed in" } else { "Device refused" }, &if allowed {
                    format!("<h1>{} is signed in</h1><p>It acts as you now. You can close this page and go back to it.</p>", esc(&name))
                } else { format!("<h1>{} was not let in</h1><p>Nothing changed. You can close this page.</p>", esc(&name)) }, None),
                Err(e) => device_page(sql, req, None, Some(&e)),
            }
        }
        ("POST", "/_sqz/sign-out") => {
            let f = form(req); let back = back_to(sql, f.get("return").map(String::as_str).unwrap_or("/"));
            if !same_browser(sql, req, &f) { return Some(sign_out_page(sql, &back)); }
            if let Some(t) = cookie(req, session_name(sql)) { let _ = sql.sign_out(&t); }
            see_other(&back, &[clear_session(sql)])
        }
        _ => respond(404, "text/plain", b"not found", &[]),
    })
}
/// The device page: to sign in first; to type the code a device shows; or, for a code typed here that waits, which
/// device asks, from where and how long ago, and whether to let it in as the user signed in here.
fn device_page(sql: &Sql, req: &Req, typed: Option<&str>, err: Option<&str>) -> Vec<u8> {
    let code = crate::auth::user_code(typed.unwrap_or(""));
    let Some(t) = signed_in(sql, req) else { return see_other("/_sqz/sign-in?return=%2F_sqz%2Fdevice", &[]) };
    // who is signed in here: their login, as the page shows it
    let who = sql.token_owner(&t).ok().and_then(|o| { let table = o.split_once(':')?.0.to_string(); let (tb, at) = sql.auth_table_of(&table).ok()?; let mut s = crate::sql::Session::default(); sql.session_from_token(&mut s, &t).ok()?; s.attrs.get(&tb.schema.columns[at.login].name).map(|v| match v { crate::table::Value::Text(x) => x.clone(), v => format!("{v:?}") }) }).unwrap_or_default();
    let host = host_of(&site(sql, req));
    let err = err.map(|e| format!(r#"<p class="err">{}</p>"#, esc(e))).unwrap_or_default();
    match (!code.is_empty()).then(|| sql.device_waiting(&code)).flatten() {
        Some((name, ip, ago)) => with_form(sql, "Sign in a device", |v| format!(r#"<h1>Let this device sign in?</h1>{err}<p>A device that calls itself <b>“{n}”</b> asked {a} from <b>{ip}</b>. It will act as <b>{w}</b> on {h}, with everything you may do, until it signs out or you change your password.</p>
<p class="small">Allow it only if you started it yourself, just now, and it shows <b>{c}</b>. If someone sent you this code, deny it.</p>
<form method="post" action="/_sqz/device"><input type="hidden" name="form" value="{v}"><input type="hidden" name="code" value="{c}"><button name="action" value="allow">Allow</button><button class="alt" name="action" value="deny">Deny</button></form>"#,
            n = esc(&name), w = esc(&who), h = esc(&host), c = esc(&code), ip = esc(&ip), a = match ago.as_secs() { s if s < 60 => format!("{s} seconds ago"), s => format!("{} minutes ago", s / 60) }), if err.is_empty() { 200 } else { 400 }),
        None => with_form(sql, "Sign in a device", |v| format!(r#"<h1>Sign in a device</h1>{err}{gone}<p>Type the code your device shows. It will act as <b>{w}</b>.</p>
<form method="post" action="/_sqz/device"><input type="hidden" name="form" value="{v}"><input type="hidden" name="action" value="look"><label>Code<input name="code" autocomplete="off" autocapitalize="characters" spellcheck="false" placeholder="ABCD-EFGH" required autofocus></label><button>Continue</button></form>"#,
            w = esc(&who), gone = if !code.is_empty() && err.is_empty() { r#"<p class="err">That code is unknown or has expired: start again on the device.</p>"# } else { "" }), if code.is_empty() && err.is_empty() { 200 } else { 400 }),
    }
}
/// A page with a form: its value set as this browser's cookie too.
fn with_form(sql: &Sql, title: &str, body: impl Fn(&str) -> String, status: u16) -> Vec<u8> {
    let v = random_hex(16);
    let mut out = page(status, title, &body(&v), None);
    let c = format!("Set-Cookie: {FORM_COOKIE}={v}; Path=/_sqz/; HttpOnly; SameSite=Strict; Max-Age=3600{}", secure(sql));
    if let Some(i) = out.windows(2).position(|w| w == b"\r\n") { out.splice(i..i, format!("\r\n{c}").into_bytes()); }
    out
}
fn sign_in_page(sql: &Sql, back: &str, up: bool, err: Option<&str>) -> Vec<u8> {
    let table = match users_table(sql) { Ok(t) => t, Err(e) => return page(500, "Can't sign in", &format!("<h1>Can't sign in</h1><p>{}</p>", esc(&e)), None) };
    let login = sql.auth_table_of(&table).ok().map(|(t, a)| t.schema.columns[a.login].name.clone()).unwrap_or_else(|| "login".into());
    let can_sign_up = sql.cfg().app.sign_up.contains_key(&table.to_ascii_lowercase());
    let up = up && can_sign_up;
    let host = host_of(sql.cfg().app.public_url.as_deref().unwrap_or(""));
    let cfg = sql.cfg();
    let providers: Vec<&String> = if cfg.app.public_url.is_some() { cfg.auth.oauth.keys().collect() } else { vec![] };
    let (b, t) = (esc(back), esc(&table));
    let buttons: String = providers.iter().map(|p| format!(r#"<form method="get" action="/api/auth/{t}/oauth/{p}"><input type="hidden" name="cookie" value="1"><input type="hidden" name="return" value="{b}"><button class="alt">Continue with {name}</button></form>"#, p = esc(p), name = esc(&title_case(p)))).collect();
    let (title, action, button, pw, other) = if up {
        ("Create an account", "sign-up", "Create account", "new-password", format!(r#"<p class="small">Have an account? <a href="/_sqz/sign-in?return={}">Sign in</a></p>"#, crate::app::enc(back)))
    } else {
        ("Sign in", "sign-in", "Sign in", "current-password", if can_sign_up { format!(r#"<p class="small">No account? <a href="/_sqz/sign-in?mode=up&amp;return={}">Create one</a></p>"#, crate::app::enc(back)) } else { String::new() })
    };
    // auth.password off: the providers are the only way in, so no form and no account links
    let pw_on = sql.cfg().auth.password;
    let other = if pw_on { other } else { String::new() };
    let status = if err.is_some() { 400 } else { 200 };
    with_form(sql, title, |v| format!(r#"<h1>{title}{to}</h1>{err}
{form}{buttons}{other}"#, to = if host.is_empty() { String::new() } else { format!(" to {}", esc(&host)) }, err = err.map(|e| format!(r#"<p class="err">{}</p>"#, esc(e))).unwrap_or_default(),
        form = if pw_on { format!(r#"<form method="post" action="/_sqz/sign-in"><input type="hidden" name="form" value="{v}"><input type="hidden" name="return" value="{b}"><input type="hidden" name="action" value="{action}">
<label>{label}<input name="login" autocomplete="username" required autofocus></label><label>Password<input name="password" type="password" autocomplete="{pw}" required></label><button>{button}</button></form>
{or}"#, label = esc(&title_case(&login)), or = if providers.is_empty() { "" } else { r#"<div class="or">or</div>"# }) }
               else if providers.is_empty() { r#"<p class="err">No way to sign in is set up: password sign-in is off (auth.password) and no provider is configured.</p>"#.to_string() } else { String::new() }), status)
}
fn sign_out_page(sql: &Sql, back: &str) -> Vec<u8> {
    with_form(sql, "Sign out", |v| format!(r#"<h1>Sign out?</h1><form method="post" action="/_sqz/sign-out"><input type="hidden" name="form" value="{v}"><input type="hidden" name="return" value="{b}"><button>Sign out</button></form>"#, b = esc(back)), 200)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sql(public_url: Option<&str>, origins: &[&str]) -> std::sync::Arc<Sql> {
        let d = std::env::temp_dir().join(format!("sqzdb-signin-{}-{}", std::process::id(), random_hex(4))); let _ = std::fs::remove_dir_all(&d);
        let mut cfg = crate::config::Config::default();
        cfg.app.public_url = public_url.map(String::from); cfg.app.origins = origins.iter().map(|s| s.to_string()).collect();
        Sql::open_with(&d, cfg).unwrap()
    }
    fn req(headers: &[(&str, &str)]) -> Req {
        Req { method: "GET".into(), path: "/api/x".into(), query: Default::default(), headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(), body: vec![] }
    }
    #[test] fn the_cookie_is_named_for_the_scheme() {
        assert_eq!(session_name(&sql(None, &[])), "sqz_session");
        assert_eq!(session_name(&sql(Some("http://localhost:3000"), &[])), "sqz_session");
        let s = sql(Some("https://tasks.example"), &[]);
        assert_eq!(session_name(&s), "__Host-sqz_session");
        let c = session_cookie(&s, "tok"); assert!(c.starts_with("__Host-sqz_session=tok; Path=/;") && c.ends_with("; Secure") && !c.contains("Domain"), "{c}");
        assert!(clear_session(&s).starts_with("__Host-sqz_session=; Path=/;"));
    }
    #[test] fn the_cookie_counts_only_from_the_site_itself() {
        let s = sql(Some("https://tasks.example"), &["*", "https://admin.example"]);
        let ok = |o: Option<&str>, h: Option<&str>| cookie_origin_ok(&s, o, h, None);
        assert!(ok(None, Some("tasks.example")), "a navigation, or not a browser");
        assert!(ok(Some("https://tasks.example"), None), "publicUrl");
        assert!(ok(Some("https://tasks.example/"), None));
        assert!(ok(Some("http://127.0.0.1:8080"), Some("127.0.0.1:8080")), "the host it was asked as");
        assert!(ok(Some("https://ADMIN.example"), Some("tasks.example")), "an origin app.origins names");
        assert!(!ok(Some("https://evil.example"), Some("tasks.example")), "\"*\" lets other pages call the API, not act as its visitor");
        assert!(!ok(Some("null"), Some("tasks.example")));
        // Origin: null from this very origin (a page with Referrer-Policy: no-referrer): the browser's Sec-Fetch-Site says so
        assert!(cookie_origin_ok(&s, Some("null"), Some("tasks.example"), Some("same-origin")));
        for site in ["same-site", "cross-site", "none"] { assert!(!cookie_origin_ok(&s, Some("null"), Some("tasks.example"), Some(site)), "{site}"); }
        assert!(!ok(Some("https://tasks.example.evil"), Some("tasks.example")));
        assert!(!ok(Some("https://evil.example"), None));
        // the token: a bearer header always, the cookie only from the site
        let ck = "a=1; __Host-sqz_session=tok1; b=2";
        assert_eq!(token_of(&s, &req(&[("cookie", ck), ("host", "tasks.example")])).as_deref(), Some("tok1"));
        assert_eq!(token_of(&s, &req(&[("cookie", ck), ("origin", "https://evil.example")])), None);
        assert_eq!(token_of(&s, &req(&[("cookie", "sqz_session=tok1")])), None, "over https only the __Host- cookie counts");
        assert_eq!(token_of(&s, &req(&[("authorization", "Bearer tok2"), ("origin", "https://evil.example")])).as_deref(), Some("tok2"));
    }
    #[test] fn back_goes_only_to_this_site_or_its_origins() {
        let s = sql(Some("https://tasks.example"), &["https://admin.example"]);
        for ok in ["/dashboard", "/a/b?c=1"] { assert_eq!(back_to(&s, ok), ok); }
        for bad in ["//evil.example/x", "/\\evil.example", "https://evil.example/", "javascript:alert(1)", "/a b", ""] { assert_eq!(back_to(&s, bad), "/", "{bad}"); }
    }
}
