//! TLS for the app API (`app.tls`): your own certificate, or one for `app.tls.domains` from an ACME CA (Let's
//! Encrypt unless `app.tls.acme` names another), requested at start and renewed in the background, as Caddy does.
//!
//! The CA checks that this server answers for the domains with TLS-ALPN-01 (RFC 8737): it connects to port 443 of
//! each domain asking for the `acme-tls/1` protocol, and gets a certificate made for that challenge. So the check
//! happens on the app API's own port and nothing has to listen on port 80; connections that ask for `acme-tls/1`
//! are closed after the handshake. A certificate is renewed once a third of its lifetime is left, and a failed
//! attempt is retried after a minute, then less often, up to every hour, while the current certificate serves on.
//!
//! The account key and the certificate live in `app.tls.dir` (the database's `tls/` by default), readable by the
//! owner only. A restart serves the stored certificate at once.
use crate::config::TlsPolicy;
use instant_acme::{Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{json, Value as J};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::CertifiedKey;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

pub const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";
const RETRY_FIRST: Duration = Duration::from_secs(60);
const RETRY_MAX: Duration = Duration::from_secs(3600);
/// The longest sleep between checks of the certificate (a renewal date moved by a restart, or a clock that jumped).
const CHECK_EVERY: Duration = Duration::from_secs(12 * 3600);

/// The certificate served, and the challenge certificates a CA is checking right now, by domain.
#[derive(Debug, Default)] struct Certs { current: RwLock<Option<Arc<CertifiedKey>>>, challenges: Mutex<HashMap<String, Arc<CertifiedKey>>> }
impl ResolvesServerCert for Certs {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let acme = hello.alpn().map(|mut protocols| protocols.any(|p| p == ACME_TLS_ALPN)).unwrap_or(false);
        if acme { return hello.server_name().and_then(|n| self.challenges.lock().unwrap().get(&n.to_ascii_lowercase()).cloned()); }
        self.current.read().unwrap().clone()
    }
}

pub struct Tls { pub acceptor: TlsAcceptor, certs: Arc<Certs> }
impl Tls {
    /// TLS for one listener: the certificate from `cert` and `key`, or the stored one for `domains` while the
    /// background task on `rt` gets one when needed. `db_dir` holds `tls/` unless `dir` says otherwise.
    pub fn start(p: &TlsPolicy, db_dir: &Path, rt: &tokio::runtime::Handle) -> Result<Tls, String> {
        let certs = Arc::new(Certs::default());
        let mut config = ServerConfig::builder_with_provider(Arc::new(tokio_rustls::rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions().map_err(|e| format!("app.tls: {e}"))?.with_no_client_auth().with_cert_resolver(certs.clone());
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), ACME_TLS_ALPN.to_vec()];   // HTTP/2 where the browser offers it
        match (&p.cert, &p.key) {
            (Some(c), Some(k)) => {
                let read = |f: &PathBuf| std::fs::read(f).map_err(|e| format!("app.tls: {}: {e}", f.display()));
                *certs.current.write().unwrap() = Some(certified(&read(c)?, &read(k)?).map_err(|e| format!("app.tls: {e}"))?);
            }
            _ => {
                let dir = p.dir.clone().unwrap_or_else(|| db_dir.join("tls"));
                private_dir(&dir).map_err(|e| format!("app.tls.dir {}: {e}", dir.display()))?;
                let held = Stored::load(&dir, p);
                match &held { Some(s) => { *certs.current.write().unwrap() = Some(s.key.clone()); eprintln!("tls: serving the stored certificate for {} (until {})", p.domains.join(", "), date(s.not_after)); }
                              None => eprintln!("tls: asking {} for a certificate for {}", host_of(&p.acme), p.domains.join(", ")) }
                rt.spawn(manage(certs.clone(), p.clone(), dir, held));
            }
        }
        Ok(Tls { acceptor: TlsAcceptor::from(Arc::new(config)), certs })
    }
    /// Whether a certificate is being served yet (one from the CA can take a few seconds after start).
    pub fn ready(&self) -> bool { self.certs.current.read().unwrap().is_some() }
}

/// A chain and key in PEM as what rustls serves.
fn certified(chain_pem: &[u8], key_pem: &[u8]) -> Result<Arc<CertifiedKey>, String> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(chain_pem).collect::<Result<_, _>>().map_err(|e| format!("certificate: {e}"))?;
    if chain.is_empty() { return Err("certificate: no CERTIFICATE block".into()); }
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| format!("key: {e}"))?;
    let signer = tokio_rustls::rustls::crypto::ring::sign::any_supported_type(&key).map_err(|e| format!("key: {e}"))?;
    Ok(Arc::new(CertifiedKey::new(chain, signer)))
}
fn private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?; }
    Ok(())
}
/// Write a file only its owner can read, in one step (a crash leaves the old one or the new one).
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    { use std::io::Write; let mut o = std::fs::OpenOptions::new(); o.write(true).create(true).truncate(true);
      #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; o.mode(0o600); }
      let mut f = o.open(&tmp)?; f.write_all(bytes)?; f.sync_all()?; }
    std::fs::rename(&tmp, path)
}
fn host_of(url: &str) -> &str { url.split('/').nth(2).unwrap_or(url) }
fn now() -> i64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0) }
fn date(unix: i64) -> String { crate::table::format_timestamp(unix * 1_000_000).chars().take(16).collect::<String>().replace('T', " ") }

/// The certificate in `dir/certificate.json`: for which domains and from which CA, its chain and key, its validity.
struct Stored { key: Arc<CertifiedKey>, not_before: i64, not_after: i64 }
impl Stored {
    /// The stored certificate, if it is for these domains from this CA and still valid.
    fn load(dir: &Path, p: &TlsPolicy) -> Option<Stored> {
        let v: J = serde_json::from_slice(&std::fs::read(dir.join("certificate.json")).ok()?).ok()?;
        let domains: Vec<String> = serde_json::from_value(v.get("domains")?.clone()).ok()?;
        if domains != p.domains || v.get("acme")?.as_str()? != p.acme { return None; }
        Stored::from_pem(v.get("chain")?.as_str()?, v.get("key")?.as_str()?).ok().filter(|s| s.not_after > now())
    }
    fn from_pem(chain: &str, key: &str) -> Result<Stored, String> {
        let k = certified(chain.as_bytes(), key.as_bytes())?;
        let (not_before, not_after) = validity(k.cert[0].as_ref()).ok_or("certificate: no validity")?;
        Ok(Stored { key: k, not_before, not_after })
    }
    /// When to get the next one: with a third of this one's lifetime left.
    fn renew_at(&self) -> i64 { self.not_after - (self.not_after - self.not_before) / 3 }
}

/// Keep a certificate for the domains: get one when there is none or it is due, then sleep until the next is due.
async fn manage(certs: Arc<Certs>, p: TlsPolicy, dir: PathBuf, mut held: Option<Stored>) {
    let mut retry = RETRY_FIRST;
    loop {
        if let Some(s) = &held {
            let wait = s.renew_at() - now();
            if wait > 0 { tokio::time::sleep(Duration::from_secs(wait as u64).min(CHECK_EVERY)).await; continue; }
        }
        match obtain(&certs, &p, &dir).await {
            Ok(s) => {
                eprintln!("tls: certificate for {} from {} (until {}; renewing from {})", p.domains.join(", "), host_of(&p.acme), date(s.not_after), date(s.renew_at()));
                *certs.current.write().unwrap() = Some(s.key.clone()); held = Some(s); retry = RETRY_FIRST;
            }
            Err(e) => {
                eprintln!("tls: no certificate for {} from {}: {e}; trying again in {} s", p.domains.join(", "), host_of(&p.acme), retry.as_secs());
                tokio::time::sleep(retry).await; retry = (retry * 2).min(RETRY_MAX);
            }
        }
    }
}

/// The ACME account in `dir/account.json` for this CA, or a new one (agreeing to the CA's terms, as `domains` asks).
async fn account(p: &TlsPolicy, dir: &Path) -> Result<Account, String> {
    let builder = || match &p.acme_root { Some(root) => Account::builder_with_root(root), None => Account::builder() }.map_err(|e| format!("ACME client: {e}"));
    let path = dir.join("account.json");
    if let Ok(v) = std::fs::read(&path).map_err(|_| ()).and_then(|b| serde_json::from_slice::<J>(&b).map_err(|_| ())) {
        if v.get("acme").and_then(|a| a.as_str()) == Some(p.acme.as_str()) {
            if let Some(Ok(c)) = v.get("credentials").map(|c| serde_json::from_value::<AccountCredentials>(c.clone())) { return builder()?.from_credentials(c).await.map_err(|e| format!("account: {e}")); }
        }
    }
    let contact = p.email.as_ref().map(|e| format!("mailto:{e}"));
    let contacts: Vec<&str> = contact.iter().map(String::as_str).collect();
    let (account, credentials) = builder()?.create(&NewAccount { contact: &contacts, terms_of_service_agreed: true, only_return_existing: false }, p.acme.clone(), None).await.map_err(|e| format!("new account: {e}"))?;
    write_private(&path, json!({"acme": p.acme, "credentials": credentials}).to_string().as_bytes()).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(account)
}

/// One order: prove each domain over TLS-ALPN-01, then fetch and store the certificate.
async fn obtain(certs: &Certs, p: &TlsPolicy, dir: &Path) -> Result<Stored, String> {
    let account = account(p, dir).await?;
    let ids: Vec<Identifier> = p.domains.iter().map(|d| Identifier::Dns(d.clone())).collect();
    let mut order = account.new_order(&NewOrder::new(&ids)).await.map_err(|e| format!("new order: {e}"))?;
    // the challenge certificates are served only while the CA checks them, whatever happens
    struct Answering<'a>(&'a Certs, Vec<String>);
    impl Drop for Answering<'_> { fn drop(&mut self) { let mut c = self.0.challenges.lock().unwrap(); for d in &self.1 { c.remove(d); } } }
    let mut answering = Answering(certs, vec![]);
    {
        let mut auths = order.authorizations();
        while let Some(a) = auths.next().await {
            let mut a = a.map_err(|e| format!("authorization: {e}"))?;
            match a.status { AuthorizationStatus::Pending => {}, AuthorizationStatus::Valid => continue, s => return Err(format!("authorization is {s:?}")) }
            let mut ch = a.challenge(ChallengeType::TlsAlpn01).ok_or("the CA offers no tls-alpn-01 challenge")?;
            let domain = ch.identifier().to_string().to_ascii_lowercase();
            let key = challenge_cert(&domain, ch.key_authorization().digest().as_ref())?;
            certs.challenges.lock().unwrap().insert(domain.clone(), key); answering.1.push(domain);
            ch.set_ready().await.map_err(|e| format!("challenge: {e}"))?;
        }
    }
    let status = order.poll_ready(&RetryPolicy::new().timeout(Duration::from_secs(120))).await.map_err(|e| format!("order: {e}"))?;
    drop(answering);
    if status != OrderStatus::Ready { return Err(format!("the order is {status:?}: the CA could not reach this server at port 443 of {} (DNS, a firewall, or another server there?)", p.domains.join(", "))); }
    let key_pem = order.finalize().await.map_err(|e| format!("finalize: {e}"))?;
    let chain_pem = order.poll_certificate(&RetryPolicy::new().timeout(Duration::from_secs(120))).await.map_err(|e| format!("certificate: {e}"))?;
    let stored = Stored::from_pem(&chain_pem, &key_pem)?;
    let path = dir.join("certificate.json");
    write_private(&path, json!({"domains": p.domains, "acme": p.acme, "chain": chain_pem, "key": key_pem}).to_string().as_bytes()).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(stored)
}

/// The self-signed certificate that answers a TLS-ALPN-01 challenge: the domain, and the SHA-256 of the key
/// authorization in the critical acmeIdentifier extension.
fn challenge_cert(domain: &str, digest: &[u8]) -> Result<Arc<CertifiedKey>, String> {
    let mut params = rcgen::CertificateParams::new(vec![domain.to_string()]).map_err(|e| e.to_string())?;
    params.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(digest)];
    let key = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
    let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
    certified(cert.pem().as_bytes(), key.serialize_pem().as_bytes())
}

/// A certificate's validity in Unix seconds (not before, not after), read from its DER:
/// `Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { [0] version, serial, signature, issuer, validity SEQUENCE { notBefore, notAfter }, … }, … }`.
fn validity(der: &[u8]) -> Option<(i64, i64)> {
    fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {   // (tag, contents, what follows)
        let (&tag, b) = b.split_first()?; let (&l, mut b) = b.split_first()?;
        let len = if l < 0x80 { l as usize } else { let n = (l & 0x7f) as usize; if n == 0 || n > 4 || b.len() < n { return None; } let v = b[..n].iter().fold(0usize, |a, &x| a << 8 | x as usize); b = &b[n..]; v };
        if b.len() < len { return None; } Some((tag, &b[..len], &b[len..]))
    }
    let (_, cert, _) = tlv(der).filter(|t| t.0 == 0x30)?;
    let (_, tbs, _) = tlv(cert).filter(|t| t.0 == 0x30)?;
    let (tag, _, after) = tlv(tbs)?; let mut rest = if tag == 0xa0 { after } else { tbs };   // the version is optional
    for _ in 0..3 { rest = tlv(rest)?.2; }   // serial number, signature algorithm, issuer
    let (_, v, _) = tlv(rest).filter(|t| t.0 == 0x30)?;
    let (t1, nb, r) = tlv(v)?; let (t2, na, _) = tlv(r)?;
    Some((asn1_time(t1, nb)?, asn1_time(t2, na)?))
}
/// UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSSZ) as Unix seconds.
fn asn1_time(tag: u8, b: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(b).ok()?;
    let (year, rest) = match tag { 0x17 => { let y: i64 = s.get(..2)?.parse().ok()?; (if y < 50 { 2000 + y } else { 1900 + y }, s.get(2..)?) } 0x18 => (s.get(..4)?.parse().ok()?, s.get(4..)?), _ => return None };
    if rest.len() != 11 || !rest.ends_with('Z') || !rest[..10].bytes().all(|c| c.is_ascii_digit()) { return None; }
    let us = crate::table::parse_timestamp(&format!("{year:04}-{}-{} {}:{}:{}", &rest[0..2], &rest[2..4], &rest[4..6], &rest[6..8], &rest[8..10]))?;
    Some(us.div_euclid(1_000_000))
}

/// Plain HTTP on `addr`, sent on to https on one of `domains` (`port`: the https port when it isn't 443).
pub async fn redirect(listener: tokio::net::TcpListener, domains: Vec<String>, port: Option<u16>) {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
    loop {
        let Ok((stream, _)) = listener.accept().await else { tokio::time::sleep(Duration::from_millis(10)).await; continue };
        let (domains, port) = (domains.clone(), port);
        tokio::spawn(async move {
            let (rd, mut w) = stream.into_split(); let mut r = tokio::io::BufReader::new(rd);
            let (mut first, mut host) = (String::new(), None);
            let read = async {
                if (&mut r).take(16 << 10).read_line(&mut first).await.ok()? == 0 { return None; }
                for _ in 0..64 { let mut h = String::new(); if (&mut r).take(16 << 10).read_line(&mut h).await.ok()? == 0 { break; } let h = h.trim_end(); if h.is_empty() { break; }
                    if let Some((k, v)) = h.split_once(':') { if k.trim().eq_ignore_ascii_case("host") { host = Some(v.trim().split(':').next().unwrap_or("").to_ascii_lowercase()); } } }
                Some(())
            };
            if tokio::time::timeout(Duration::from_secs(10), read).await.ok().flatten().is_none() { return; }
            // only to a configured domain, so this is no redirect anywhere else; the path as sent, if it is one
            let to = host.filter(|h| domains.contains(h)).unwrap_or_else(|| domains[0].clone());
            let path = first.split_whitespace().nth(1).filter(|p| p.starts_with('/') && p.bytes().all(|b| (0x21..0x7f).contains(&b))).unwrap_or("/");
            let location = format!("https://{to}{}{path}", port.map(|p| format!(":{p}")).unwrap_or_default());
            let _ = w.write_all(format!("HTTP/1.1 308 Permanent Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn reads_a_certificates_validity() {
        let key = rcgen::KeyPair::generate().unwrap();
        for (nb, na) in [((2026, 1, 2), (2026, 4, 2)), ((2025, 12, 31), (2051, 6, 30))] {   // 2051: GeneralizedTime
            let mut params = rcgen::CertificateParams::new(vec!["api.example.com".to_string()]).unwrap();
            params.not_before = rcgen::date_time_ymd(nb.0, nb.1, nb.2); params.not_after = rcgen::date_time_ymd(na.0, na.1, na.2);
            let cert = params.self_signed(&key).unwrap();
            let day = |(y, m, d): (i32, u8, u8)| crate::table::parse_timestamp(&format!("{y:04}-{m:02}-{d:02} 00:00:00")).unwrap() / 1_000_000;
            assert_eq!(validity(cert.der()), Some((day(nb), day(na))));
            let s = Stored::from_pem(&cert.pem(), &key.serialize_pem()).unwrap();
            assert_eq!(s.renew_at(), day(na) - (day(na) - day(nb)) / 3);
        }
        assert_eq!(validity(b"\x30\x03\x02\x01"), None);
        assert_eq!(validity(&[]), None);
    }
    #[test] fn a_challenge_certificate_carries_the_key_authorization() {
        let digest = [7u8; 32];
        let k = challenge_cert("api.example.com", &digest).unwrap();
        let der = k.cert[0].as_ref();
        // the acmeIdentifier extension: OID 1.3.6.1.5.5.7.1.31, critical, an OCTET STRING of the digest
        let oid = [0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1f];
        let at = der.windows(oid.len()).position(|w| w == oid).expect("acmeIdentifier extension");
        let ext = &der[at + oid.len()..];
        assert_eq!(&ext[..3], &[0x01, 0x01, 0xff], "critical");
        assert_eq!(&ext[3..7], &[0x04, 0x22, 0x04, 0x20]);
        assert_eq!(&ext[7..39], &digest);
    }
}
