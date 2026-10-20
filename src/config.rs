//! Configuration for `Sql::open_with`. One set of keys, three sources, one precedence: options passed from code
//! (the bindings send them as JSON) win over a TOML file, which wins over the defaults. The file is read only when
//! the application names it (`configFile`): the data directory is data, and a writable one must not be able to
//! redirect backups, open listeners or read the environment. Strings in the file may reference environment
//! variables as `${NAME}`; nothing is read from the environment unless the named file asks for it.
//! Durations are `"5ms"`, `"1s"`, `"30s"`, `"2m"`, `"1h"`, `"7d"` or a number of milliseconds; sizes are
//! `"256MB"`, `"1GB"` or a number of bytes; `0` turns a policy off.
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Durability {
    /// A write returns when it is visible; the fsync follows within a batch (default).
    Visible,
    /// Every commit waits for its fsync; concurrent writers share one (group commit).
    Fsync,
    /// Every commit waits until its record is in the backup bucket.
    Cloud,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub durable: Durability,
    /// Create the directory when it holds no database (default true). Never wipes an existing one.
    pub create: bool,
    pub recover_threads: usize,
    pub backup: Option<Backup>,
    pub follow: Option<Follow>,
    pub snapshot: SnapshotPolicy,
    pub listen: Listen,
    pub live: LivePolicy,
    pub log: LogPolicy,
    pub auth: AuthPolicy,
    pub app: AppPolicy,
    /// Embeddings for generated VECTOR columns and `embed()` (`vector.rs`); none unless configured.
    pub embed: Option<EmbedPolicy>,
    /// The application's functions (`functions.rs`): a folder to deploy at open, and the sandbox's limits.
    pub functions: FunctionsPolicy,
}
/// `functions`: `dir`, a folder deployed at open (and again whenever it changes, with `watch`); how long one call may
/// run, how much memory its instance may use, and how many calls run at once (each in its own instance).
#[derive(Clone, Debug)] pub struct FunctionsPolicy { pub dir: Option<PathBuf>, pub watch: bool, pub timeout: Duration, pub memory: usize, pub instances: usize }
impl Default for FunctionsPolicy { fn default() -> Self { FunctionsPolicy { dir: None, watch: true, timeout: Duration::from_secs(1), memory: 64 << 20, instances: std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2).clamp(2, 64) } } }
/// An OpenAI-compatible embeddings endpoint: `url` (such as https://api.openai.com/v1, or Ollama's
/// http://localhost:11434/v1), its `model`, an `api_key`, the `dimensions` to ask for (for models that can shorten
/// their vectors), and how many texts go in one request.
#[derive(Clone, Debug)] pub struct EmbedPolicy { pub url: String, pub model: String, pub api_key: Option<String>, pub dimensions: Option<usize>, pub batch: usize }
impl Default for Config {
    fn default() -> Config { Config { durable: Durability::Visible, create: true, recover_threads: 4, backup: None, follow: None, snapshot: SnapshotPolicy::default(), listen: Listen::default(), live: LivePolicy::default(), log: LogPolicy::default(), auth: AuthPolicy::default(), app: AppPolicy::default(), embed: None, functions: FunctionsPolicy::default() } }
}
impl Config {
    pub fn durable(mut self, d: Durability) -> Config { self.durable = d; self }
    /// The effective configuration: defaults, then the TOML file the options name as `configFile` (if any), then the
    /// options themselves. `_dir` is the database directory; nothing is read from it.
    pub fn load(_dir: &Path, json: Option<&str>) -> Result<Config, String> {
        let code: ConfigFile = match json { Some(j) if !j.trim().is_empty() && j.trim() != "null" => serde_json::from_str(j).map_err(|e| format!("options: {e}"))?, _ => ConfigFile::default() };
        let mut file = ConfigFile::default();
        if let Some(p) = &code.config_file {
            let path = Path::new(p);
            let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
            file = file_from_text(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        }
        file.overlay(code).resolve()
    }
    /// The configuration a file's text would give, with these options over it (as `sqzdb serve`'s flags are): checked
    /// before the console saves a file, so a server never restarts into one it can't start with.
    pub fn check(text: &str, options: Option<&str>) -> Result<Config, String> {
        let code: ConfigFile = match options { Some(j) if !j.trim().is_empty() && j.trim() != "null" => serde_json::from_str(j).map_err(|e| format!("options: {e}"))?, _ => ConfigFile::default() };
        file_from_text(text)?.overlay(code).resolve()
    }
    /// Options alone (no file), as the bindings send them.
    pub fn from_json(json: &str) -> Result<Config, String> { let code: ConfigFile = serde_json::from_str(json).map_err(|e| format!("options: {e}"))?; code.resolve() }
}

/// A configuration file's text, its `${VAR}`s filled in from the environment.
fn file_from_text(text: &str) -> Result<ConfigFile, String> {
    let file: ConfigFile = toml::from_str(&interpolate(text)?).map_err(|e| e.to_string())?;
    if file.config_file.is_some() { return Err("configFile cannot be set from a file".into()); }
    Ok(file)
}
/// Whether a configuration file is safe to read without being named: a regular file owned by the user this process
/// runs as, that no one else may write (else whoever can write the database directory could redirect its backups or
/// open a listener). Unix only; elsewhere, any file.
pub fn private_file(path: &Path) -> Result<(), String> {
    let m = std::fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !m.file_type().is_file() { return Err(format!("{}: not a regular file", path.display())); }
    #[cfg(unix)] {
        use std::os::unix::fs::MetadataExt;
        if m.uid() != unsafe { libc::geteuid() } { return Err(format!("{}: owned by another user; it must be yours (chown it, or name it with --config)", path.display())); }
        if m.mode() & 0o022 != 0 { return Err(format!("{}: others may write it; make it yours alone (chmod 600)", path.display())); }
    }
    Ok(())
}

/// Continuous backup to an S3-compatible bucket (see `cloud.rs`).
#[derive(Clone, Debug)]
pub struct Backup {
    pub endpoint: String, pub bucket: String, pub prefix: String, pub region: String, pub access_key: String, pub secret_key: String,
    /// AES-256-GCM under a key derived from this passphrase; `None` uploads plaintext (still compressed).
    pub passphrase: Option<String>,
    pub interval: Duration, pub compress: bool, pub compact_after: Duration, pub compact_every: Duration,
    /// When the directory is empty and the bucket is not, restore the latest state before opening.
    pub bootstrap: bool,
}
impl Backup {
    pub fn cloud(&self) -> crate::cloud::CloudConfig {
        let mut c = crate::cloud::CloudConfig::local(&self.bucket, &self.prefix);
        c.endpoint = self.endpoint.clone(); c.access_key = self.access_key.clone(); c.secret_key = self.secret_key.clone(); c.region = self.region.clone();
        c.interval = self.interval; c.compress = self.compress; c.compact_after = self.compact_after; c.compact_every = self.compact_every; c.rtt = Duration::ZERO;
        match &self.passphrase { Some(p) => c.with_passphrase(p), None => c }
    }
}
/// Open as a read-only replica of a primary on this host (its directory) or of a bucket a primary backs up to.
#[derive(Clone, Debug)]
pub enum Follow { Dir { dir: PathBuf, poll: Duration }, Bucket { source: Backup, poll: Duration } }
/// When the engine writes a snapshot on its own. By size: once the log written since the last snapshot exceeds the
/// larger of `log_bytes` and that snapshot's own size, so a big table is not rewritten for every few megabytes of log
/// (write amplification stays under 2x) and a restart never replays more than about one snapshot's worth of log
/// (E42: 350 MB/s on the lab machine, 64 MB in 0.2 s). By time: after `idle_after` without a write, when something
/// was written since the last snapshot, so a quiet database always restarts from a fresh image. `None` disables a trigger.
#[derive(Clone, Debug)]
pub struct SnapshotPolicy { pub log_bytes: Option<u64>, pub idle_after: Option<Duration> }
impl Default for SnapshotPolicy { fn default() -> Self { SnapshotPolicy { log_bytes: Some(64 << 20), idle_after: Some(Duration::from_secs(30)) } } }
/// Doors for other processes: a Unix socket path, a TCP address, the web console's HTTP address; the last two need the shared token.
#[derive(Clone, Debug, Default)]
pub struct Listen { pub socket: Option<PathBuf>, pub tcp: Option<String>, pub http: Option<String>, pub token: Option<String>, /// the app API for browsers and mobile apps (see `app.rs`)
    pub app: Option<String> }
#[derive(Clone, Debug)]
pub struct LivePolicy { pub debounce: Duration, pub queue: usize }
impl Default for LivePolicy { fn default() -> Self { LivePolicy { debounce: Duration::from_millis(5), queue: 65536 } } }
/// The app API (`listen.app`, see `app.rs`): which web origins may call it, the URL it is reached at (for OAuth
/// redirects), the role of a request without a session, the most rows one result may return, a directory of
/// static files to serve beside it (the app itself), and the tables clients may make accounts in, each with the
/// columns a client may set besides the login column (other tables are sign-in only).
#[derive(Clone, Debug)] pub struct AppPolicy { pub origins: Vec<String>, pub public_url: Option<String>, pub anonymous_role: Option<String>, pub max_rows: usize, pub static_dir: Option<PathBuf>, pub sign_up: std::collections::BTreeMap<String, Vec<String>>, pub tls: Option<TlsPolicy>,
    /// FILE columns: the largest upload, and how long a link to a file that a query hands out works
    pub file_max: u64, pub file_link_ttl: Duration, /// the largest request body or WebSocket message (an upload streams instead)
    pub max_request: usize, /// agents over MCP, signed in through the API's own OAuth server (`mcp.rs`); off unless set
    pub mcp: Option<McpPolicy>,
    /// the app the API stands in front of: requests that aren't the API's own go on to it (`proxy.rs`)
    pub proxy: Option<ProxyPolicy>,
    /// proxies of yours in front of the API: from these, the client's address is taken from X-Forwarded-For
    pub trust_proxy: Vec<crate::proxy::Net> }
/// `app.proxy`: the app's address (`to`, http on this machine or a private network), how long it may take to start
/// answering, and how many requests may be in flight to it at once (as many connections to it are kept).
#[derive(Clone, Debug)] pub struct ProxyPolicy { pub to: String, pub timeout: Duration, pub connections: usize }
/// `app.mcp`: which table people sign in to when they connect an agent, how long an access token lasts (refreshed by
/// the agent on its own), how long a sign-in lasts unused, and the most rows a query hands an agent.
#[derive(Clone, Debug)] pub struct McpPolicy { pub users: Option<String>, pub token_ttl: Duration, pub grant_ttl: Duration, pub max_rows: usize, /// the SQL tools (describe, query, execute) besides the functions; off: agents get the functions only
    pub sql: bool }
impl Default for McpPolicy { fn default() -> McpPolicy { McpPolicy { users: None, token_ttl: Duration::from_secs(3600), grant_ttl: Duration::from_secs(30 * 86400), max_rows: 500, sql: true } } }
impl Default for AppPolicy { fn default() -> AppPolicy { AppPolicy { origins: vec![], public_url: None, anonymous_role: None, max_rows: 10_000, static_dir: None, sign_up: Default::default(), tls: None, file_max: 25 << 20, file_link_ttl: Duration::from_secs(3600), max_request: 8 << 20, mcp: None, proxy: None, trust_proxy: vec![] } } }
/// TLS for the app API (`app.tls`, see `tls.rs`): your own certificate (`cert` and `key`, PEM files), or one for
/// `domains` from the ACME CA whose directory is `acme` (Let's Encrypt), kept in `dir` (the database's `tls/` when
/// unset) under an account with `email` as its contact. `acme_root` is a root to trust for the CA itself (a private
/// CA, or a test one); `redirect` is an address where plain HTTP requests are sent on to https.
#[derive(Clone, Debug)] pub struct TlsPolicy { pub domains: Vec<String>, pub email: Option<String>, pub cert: Option<PathBuf>, pub key: Option<PathBuf>, pub acme: String, pub acme_root: Option<PathBuf>, pub dir: Option<PathBuf>, pub redirect: Option<String> }
/// An endpoint the server sends secrets to: https, or http to this machine (tests, a local model), parsed as a URL
/// so `http://localhost:80@elsewhere` is elsewhere (and refused: no user or password in it).
pub fn secure_url(u: &str) -> bool {
    let Ok(p) = reqwest::Url::parse(u) else { return false };
    if !p.username().is_empty() || p.password().is_some() || p.host_str().is_none() { return false; }
    match p.scheme() { "https" => true, "http" => matches!(p.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")), _ => false }
}
pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
/// A name a CA can check over TLS-ALPN-01: letters, digits and hyphens in dot-separated labels, no wildcard, not an IP.
fn is_dns_name(d: &str) -> bool {
    let label = |l: &str| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    d.len() <= 253 && d.split('.').all(label) && !d.rsplit('.').next().unwrap_or("").bytes().all(|b| b.is_ascii_digit())
}
/// Sign-in (see `auth.rs`): how long a session lasts, and the shortest password `signUp` and `setPassword` accept.
#[derive(Clone, Debug)] pub struct AuthPolicy { pub session_ttl: Duration, pub password_min: usize, /// sign-in providers by name (see `oauth.rs`)
    pub oauth: std::collections::BTreeMap<String, OAuthProvider> }
impl Default for AuthPolicy { fn default() -> AuthPolicy { AuthPolicy { session_ttl: Duration::from_secs(30 * 24 * 3600), password_min: 8, oauth: Default::default() } } }
/// How a provider tells who signed in: an OpenID Connect ID token (Google and others), or GitHub's user API.
#[derive(Clone, Debug, PartialEq)] pub enum OAuthKind { Oidc, Github }
/// An OAuth2 provider: the application's client id and secret, the provider's endpoints, and what to ask for.
#[derive(Clone, Debug)] pub struct OAuthProvider { pub kind: OAuthKind, pub client_id: String, pub client_secret: String, pub auth_url: String, pub token_url: String,
    /// OpenID Connect: the signing keys and the accepted issuers. GitHub: the user and email APIs.
    pub jwks_url: String, pub issuers: Vec<String>, pub user_url: String, pub emails_url: String, pub scopes: String }
#[derive(Clone, Debug, Default)]
pub struct LogPolicy { /// Log threads leave after this long without writes and return on the next one (many idle databases per process).
    pub threads_idle_after: Option<Duration>,
    /// With durable off: hold the background fsync up to this long so one sync covers more writes (many small databases
    /// per disk). A crash of the machine can lose up to this much; anything waiting for durability still syncs at once.
    pub sync_delay: Option<Duration> }

// ---------- the file / JSON form: every field optional, overlaid in precedence order ----------

#[derive(Deserialize, Debug, Clone)] #[serde(untagged)] pub enum DurableIn { Flag(bool), Name(String) }
#[derive(Deserialize, Debug, Clone)] #[serde(untagged)] pub enum Dur { Millis(u64), Text(String) }
#[derive(Deserialize, Debug, Clone)] #[serde(untagged)] pub enum Size { Bytes(u64), Text(String) }

#[derive(Deserialize, Default, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ConfigFile {
    /// Path of a TOML file with these same keys, read before the options and overridden by them. Only from code.
    #[serde(alias = "config_file")] pub config_file: Option<String>,
    pub durable: Option<DurableIn>, pub create: Option<bool>,
    #[serde(alias = "recover_threads")] pub recover_threads: Option<usize>,
    pub backup: Option<BackupFile>, pub follow: Option<FollowFile>, pub snapshot: Option<SnapshotFile>, pub listen: Option<ListenFile>, pub live: Option<LiveFile>, pub log: Option<LogFile>, pub auth: Option<AuthFile>, pub app: Option<AppFile>, pub embed: Option<EmbedFile>,
    pub functions: Option<FunctionsIn>,
}
/// `functions`: the folder alone, or the folder and the limits.
#[derive(Deserialize, Debug, Clone)] #[serde(untagged)] pub enum FunctionsIn { Dir(String), Full(FunctionsFile) }
#[derive(Deserialize, Default, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FunctionsFile { pub dir: Option<String>, pub watch: Option<bool>, pub timeout: Option<Dur>, pub memory: Option<Size>, pub instances: Option<usize> }
impl FunctionsIn { fn full(self) -> FunctionsFile { match self { FunctionsIn::Dir(d) => FunctionsFile { dir: Some(d), ..Default::default() }, FunctionsIn::Full(f) => f } } }
#[derive(Deserialize, Default, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EmbedFile { pub url: Option<String>, pub model: Option<String>, #[serde(alias = "api_key")] pub api_key: Option<String>, pub dimensions: Option<usize>, pub batch: Option<usize> }
#[derive(Deserialize, Default, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AppFile { pub origins: Option<Vec<String>>, #[serde(alias = "public_url")] pub public_url: Option<String>, #[serde(alias = "anonymous_role")] pub anonymous_role: Option<String>, #[serde(alias = "max_rows")] pub max_rows: Option<usize>, #[serde(alias = "static_dir")] pub static_dir: Option<String>, #[serde(alias = "sign_up")] pub sign_up: Option<std::collections::BTreeMap<String, Vec<String>>>, pub tls: Option<TlsFile>, pub files: Option<AppFilesFile>, #[serde(alias = "max_request")] pub max_request: Option<Size>, pub mcp: Option<McpFile>, pub proxy: Option<ProxyIn>, #[serde(alias = "trust_proxy")] pub trust_proxy: Option<Vec<String>> }
/// `app.proxy`: the app's address alone, or with its settings.
#[derive(Deserialize, Debug, Clone)] #[serde(untagged)] pub enum ProxyIn { To(String), Full(ProxyFile) }
#[derive(Deserialize, Default, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProxyFile { pub to: Option<String>, pub timeout: Option<Dur>, pub connections: Option<usize> }
impl ProxyIn { fn full(self) -> ProxyFile { match self { ProxyIn::To(t) => ProxyFile { to: Some(t), ..Default::default() }, ProxyIn::Full(f) => f } } }
#[derive(Deserialize, Default, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct McpFile { pub users: Option<String>, #[serde(alias = "token_ttl")] pub token_ttl: Option<Dur>, #[serde(alias = "grant_ttl")] pub grant_ttl: Option<Dur>, #[serde(alias = "max_rows")] pub max_rows: Option<usize>, pub sql: Option<bool> }
#[derive(Deserialize, Default, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AppFilesFile { #[serde(alias = "max_size")] pub max_size: Option<Size>, #[serde(alias = "link_ttl")] pub link_ttl: Option<Dur> }
#[derive(Deserialize, Default, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TlsFile { pub domains: Option<Vec<String>>, pub email: Option<String>, pub cert: Option<String>, pub key: Option<String>, pub acme: Option<String>, #[serde(alias = "acme_root")] pub acme_root: Option<String>, pub dir: Option<String>, pub redirect: Option<String> }
#[derive(Deserialize, Default, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BackupFile {
    pub endpoint: Option<String>, pub bucket: Option<String>, pub prefix: Option<String>, pub region: Option<String>,
    #[serde(alias = "access_key")] pub access_key: Option<String>, #[serde(alias = "secret_key")] pub secret_key: Option<String>,
    pub passphrase: Option<String>, pub interval: Option<Dur>, pub compress: Option<bool>,
    #[serde(alias = "compact_after")] pub compact_after: Option<Dur>, #[serde(alias = "compact_every")] pub compact_every: Option<Dur>,
    pub bootstrap: Option<bool>,
}
#[derive(Deserialize, Default, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FollowFile { pub dir: Option<String>, pub bucket: Option<BackupFile>, pub poll: Option<Dur> }
#[derive(Deserialize, Default, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SnapshotFile { #[serde(alias = "log_bytes")] pub log_bytes: Option<Size>, #[serde(alias = "idle_after")] pub idle_after: Option<Dur> }
#[derive(Deserialize, Default, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ListenFile { pub socket: Option<String>, pub tcp: Option<String>, pub http: Option<String>, pub token: Option<String>, pub app: Option<String> }
#[derive(Deserialize, Default, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LiveFile { pub debounce: Option<Dur>, pub queue: Option<usize> }
#[derive(Deserialize, Default, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuthFile { #[serde(alias = "session_ttl")] pub session_ttl: Option<Dur>, #[serde(alias = "password_min")] pub password_min: Option<usize>, pub oauth: Option<std::collections::BTreeMap<String, OAuthFile>> }
#[derive(Deserialize, Default, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OAuthFile { pub kind: Option<String>, #[serde(alias = "client_id")] pub client_id: Option<String>, #[serde(alias = "client_secret")] pub client_secret: Option<String>,
    #[serde(alias = "auth_url")] pub auth_url: Option<String>, #[serde(alias = "token_url")] pub token_url: Option<String>, #[serde(alias = "jwks_url")] pub jwks_url: Option<String>,
    pub issuer: Option<String>, #[serde(alias = "user_url")] pub user_url: Option<String>, #[serde(alias = "emails_url")] pub emails_url: Option<String>, pub scopes: Option<String> }
impl OAuthFile { fn overlay(self, o: OAuthFile) -> OAuthFile { OAuthFile { kind: pick(self.kind, o.kind), client_id: pick(self.client_id, o.client_id), client_secret: pick(self.client_secret, o.client_secret), auth_url: pick(self.auth_url, o.auth_url), token_url: pick(self.token_url, o.token_url), jwks_url: pick(self.jwks_url, o.jwks_url), issuer: pick(self.issuer, o.issuer), user_url: pick(self.user_url, o.user_url), emails_url: pick(self.emails_url, o.emails_url), scopes: pick(self.scopes, o.scopes) } } }
/// A provider's settings: `google` and `github` come with their endpoints; any other name is an OpenID Connect
/// provider whose endpoints and issuer are given. Endpoints are https (http only on this machine, for tests).
fn resolve_oauth(name: &str, f: OAuthFile) -> Result<OAuthProvider, String> {
    let key = format!("auth.oauth.{name}");
    let need = |v: Option<String>, k: &str| v.filter(|s| !s.is_empty()).ok_or_else(|| format!("{key}.{k} is required"));
    let (client_id, client_secret) = (need(f.client_id.clone(), "clientId")?, need(f.client_secret.clone(), "clientSecret")?);
    let kind = match (name, f.kind.as_deref()) { ("github", None | Some("github")) => OAuthKind::Github, (_, Some("github")) => OAuthKind::Github, ("google", None | Some("oidc")) | (_, Some("oidc")) => OAuthKind::Oidc, (_, None) => return Err(format!("{key}.kind: \"oidc\" or \"github\" (only google and github are known by name)")), (_, Some(k)) => return Err(format!("{key}.kind: \"oidc\" or \"github\", not {k:?}")) };
    let preset = |g: &str, h: &str| -> Option<String> { match (name, &kind) { ("google", OAuthKind::Oidc) => Some(g.to_string()), ("github", OAuthKind::Github) => Some(h.to_string()), _ => None }.filter(|s| !s.is_empty()) };
    let url = |v: Option<String>, p: Option<String>, k: &str| -> Result<String, String> {
        let u = v.filter(|s| !s.is_empty()).or(p).ok_or_else(|| format!("{key}.{k} is required"))?;
        if !secure_url(&u) { return Err(format!("{key}.{k}: an https URL (http only to this machine), with no user or password in it")); }
        Ok(u)
    };
    let p = OAuthProvider {
        auth_url: url(f.auth_url, preset("https://accounts.google.com/o/oauth2/v2/auth", "https://github.com/login/oauth/authorize"), "authUrl")?,
        token_url: url(f.token_url, preset("https://oauth2.googleapis.com/token", "https://github.com/login/oauth/access_token"), "tokenUrl")?,
        jwks_url: if kind == OAuthKind::Oidc { url(f.jwks_url, preset("https://www.googleapis.com/oauth2/v3/certs", ""), "jwksUrl")? } else { String::new() },
        issuers: if kind == OAuthKind::Oidc { match f.issuer.filter(|s| !s.is_empty()) { Some(i) => vec![i], None if name == "google" => vec!["https://accounts.google.com".into(), "accounts.google.com".into()], None => return Err(format!("{key}.issuer is required")) } } else { vec![] },
        user_url: if kind == OAuthKind::Github { url(f.user_url, preset("", "https://api.github.com/user"), "userUrl")? } else { String::new() },
        emails_url: if kind == OAuthKind::Github { url(f.emails_url, preset("", "https://api.github.com/user/emails"), "emailsUrl")? } else { String::new() },
        scopes: f.scopes.filter(|s| !s.is_empty()).unwrap_or_else(|| if kind == OAuthKind::Github { "read:user user:email".into() } else { "openid email profile".into() }),
        kind, client_id, client_secret,
    };
    Ok(p)
}
#[derive(Deserialize, Default, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LogFile { #[serde(alias = "threads_idle_after")] pub threads_idle_after: Option<Dur>, #[serde(alias = "sync_delay")] pub sync_delay: Option<Dur> }

fn pick<T>(base: Option<T>, over: Option<T>) -> Option<T> { over.or(base) }
fn nest<T>(base: Option<T>, over: Option<T>, f: impl Fn(T, T) -> T) -> Option<T> { match (base, over) { (Some(a), Some(b)) => Some(f(a, b)), (a, b) => b.or(a) } }
impl BackupFile { fn overlay(self, o: BackupFile) -> BackupFile { BackupFile { endpoint: pick(self.endpoint, o.endpoint), bucket: pick(self.bucket, o.bucket), prefix: pick(self.prefix, o.prefix), region: pick(self.region, o.region), access_key: pick(self.access_key, o.access_key), secret_key: pick(self.secret_key, o.secret_key), passphrase: pick(self.passphrase, o.passphrase), interval: pick(self.interval, o.interval), compress: pick(self.compress, o.compress), compact_after: pick(self.compact_after, o.compact_after), compact_every: pick(self.compact_every, o.compact_every), bootstrap: pick(self.bootstrap, o.bootstrap) } } }
impl ConfigFile {
    pub fn overlay(self, o: ConfigFile) -> ConfigFile {
        ConfigFile {
            config_file: pick(self.config_file, o.config_file),
            durable: pick(self.durable, o.durable), create: pick(self.create, o.create), recover_threads: pick(self.recover_threads, o.recover_threads),
            backup: nest(self.backup, o.backup, |a, b| a.overlay(b)),
            follow: nest(self.follow, o.follow, |a, b| FollowFile { dir: pick(a.dir, b.dir), bucket: nest(a.bucket, b.bucket, |x, y| x.overlay(y)), poll: pick(a.poll, b.poll) }),
            snapshot: nest(self.snapshot, o.snapshot, |a, b| SnapshotFile { log_bytes: pick(a.log_bytes, b.log_bytes), idle_after: pick(a.idle_after, b.idle_after) }),
            listen: nest(self.listen, o.listen, |a, b| ListenFile { socket: pick(a.socket, b.socket), tcp: pick(a.tcp, b.tcp), http: pick(a.http, b.http), token: pick(a.token, b.token), app: pick(a.app, b.app) }),
            app: nest(self.app, o.app, |a, b| AppFile { origins: pick(a.origins, b.origins), public_url: pick(a.public_url, b.public_url), anonymous_role: pick(a.anonymous_role, b.anonymous_role), max_rows: pick(a.max_rows, b.max_rows), static_dir: pick(a.static_dir, b.static_dir), sign_up: pick(a.sign_up, b.sign_up), max_request: pick(a.max_request, b.max_request), trust_proxy: pick(a.trust_proxy, b.trust_proxy),
                proxy: nest(a.proxy, b.proxy, |x, y| { let (x, y) = (x.full(), y.full()); ProxyIn::Full(ProxyFile { to: pick(x.to, y.to), timeout: pick(x.timeout, y.timeout), connections: pick(x.connections, y.connections) }) }),
                mcp: nest(a.mcp, b.mcp, |x, y| McpFile { users: pick(x.users, y.users), token_ttl: pick(x.token_ttl, y.token_ttl), grant_ttl: pick(x.grant_ttl, y.grant_ttl), max_rows: pick(x.max_rows, y.max_rows), sql: pick(x.sql, y.sql) }),
                files: nest(a.files, b.files, |x, y| AppFilesFile { max_size: pick(x.max_size, y.max_size), link_ttl: pick(x.link_ttl, y.link_ttl) }),
                tls: nest(a.tls, b.tls, |x, y| TlsFile { domains: pick(x.domains, y.domains), email: pick(x.email, y.email), cert: pick(x.cert, y.cert), key: pick(x.key, y.key), acme: pick(x.acme, y.acme), acme_root: pick(x.acme_root, y.acme_root), dir: pick(x.dir, y.dir), redirect: pick(x.redirect, y.redirect) }) }),
            functions: nest(self.functions, o.functions, |a, b| { let (a, b) = (a.full(), b.full()); FunctionsIn::Full(FunctionsFile { dir: pick(a.dir, b.dir), watch: pick(a.watch, b.watch), timeout: pick(a.timeout, b.timeout), memory: pick(a.memory, b.memory), instances: pick(a.instances, b.instances) }) }),
            embed: nest(self.embed, o.embed, |a, b| EmbedFile { url: pick(a.url, b.url), model: pick(a.model, b.model), api_key: pick(a.api_key, b.api_key), dimensions: pick(a.dimensions, b.dimensions), batch: pick(a.batch, b.batch) }),
            live: nest(self.live, o.live, |a, b| LiveFile { debounce: pick(a.debounce, b.debounce), queue: pick(a.queue, b.queue) }),
            log: nest(self.log, o.log, |a, b| LogFile { threads_idle_after: pick(a.threads_idle_after, b.threads_idle_after), sync_delay: pick(a.sync_delay, b.sync_delay) }),
            auth: nest(self.auth, o.auth, |a, b| AuthFile { session_ttl: pick(a.session_ttl, b.session_ttl), password_min: pick(a.password_min, b.password_min), oauth: nest(a.oauth, b.oauth, |mut x, y| { for (k, v) in y { let merged = match x.remove(&k) { Some(old) => old.overlay(v), None => v }; x.insert(k, merged); } x }) }),
        }
    }
    /// Defaults, validation, and typed values. Errors name the key.
    pub fn resolve(self) -> Result<Config, String> {
        let mut c = Config::default();
        c.durable = match self.durable { None | Some(DurableIn::Flag(false)) => Durability::Visible, Some(DurableIn::Flag(true)) => Durability::Fsync,
            Some(DurableIn::Name(s)) => match s.to_ascii_lowercase().as_str() { "false" | "visible" => Durability::Visible, "true" | "fsync" | "disk" => Durability::Fsync, "cloud" => Durability::Cloud, other => return Err(format!("durable: expected false, true or \"cloud\", got {other:?}")) } };
        if let Some(v) = self.create { c.create = v; }
        if let Some(n) = self.recover_threads { c.recover_threads = n.max(1); }
        if let Some(b) = self.backup { c.backup = Some(resolve_backup(b, "backup")?); }
        if let Some(f) = self.follow {
            let poll = dur_or(f.poll, Duration::from_millis(100), "follow.poll")?;
            c.follow = Some(match (f.dir, f.bucket) {
                (Some(d), None) => Follow::Dir { dir: PathBuf::from(d), poll },
                (None, Some(b)) => Follow::Bucket { source: resolve_backup(b, "follow.bucket")?, poll },
                (Some(_), Some(_)) => return Err("follow: give either dir or bucket, not both".into()),
                (None, None) => return Err("follow: needs dir or bucket".into()),
            });
            if c.backup.is_some() { return Err("follow and backup together: a follower does not back up; configure backup on the primary".into()); }
        }
        if c.durable == Durability::Cloud && c.backup.is_none() { return Err("durable = \"cloud\" needs a backup section".into()); }
        if let Some(s) = self.snapshot {
            if let Some(v) = s.log_bytes { let n = size_of(v, "snapshot.logBytes")?; c.snapshot.log_bytes = if n == 0 { None } else { Some(n) }; }
            if let Some(v) = s.idle_after { let d = dur_of(v, "snapshot.idleAfter")?; c.snapshot.idle_after = if d.is_zero() { None } else { Some(d) }; }
        }
        if let Some(l) = self.listen {
            c.listen.socket = l.socket.map(PathBuf::from); c.listen.tcp = l.tcp; c.listen.http = l.http; c.listen.token = l.token.filter(|t| !t.is_empty()); c.listen.app = l.app.filter(|a| !a.is_empty());
            if c.listen.tcp.is_some() && c.listen.token.is_none() { return Err("listen.tcp needs listen.token (a shared secret every connection presents first)".into()); }
            if c.listen.http.is_some() && c.listen.token.is_none() { return Err("listen.http needs listen.token (the web console asks for it)".into()); }
        }
        if let Some(l) = self.live { if let Some(d) = l.debounce { c.live.debounce = dur_of(d, "live.debounce")?; } if let Some(q) = l.queue { c.live.queue = q.max(16); } }
        if let Some(l) = self.log {
            if let Some(d) = l.threads_idle_after { let d = dur_of(d, "log.threadsIdleAfter")?; c.log.threads_idle_after = if d.is_zero() { None } else { Some(d) }; }
            if let Some(d) = l.sync_delay { let d = dur_of(d, "log.syncDelay")?; if d > Duration::from_secs(60) { return Err("log.syncDelay: at most 60s".into()); } c.log.sync_delay = if d.is_zero() { None } else { Some(d) }; }
        }
        if let Some(e) = self.embed {
            let url = e.url.filter(|u| !u.is_empty()).ok_or("embed.url: the endpoint, such as https://api.openai.com/v1 or http://localhost:11434/v1")?.trim_end_matches('/').to_string();
            if !secure_url(&url) { return Err("embed.url: https, or http to this machine, with no user or password in it (an API key goes with each request)".into()); }
            let model = e.model.filter(|m| !m.is_empty()).ok_or("embed.model: the embedding model, such as text-embedding-3-small or nomic-embed-text")?;
            if let Some(d) = e.dimensions { if !(1..=16_000).contains(&d) { return Err("embed.dimensions: between 1 and 16,000".into()); } }
            let batch = e.batch.unwrap_or(64); if !(1..=2048).contains(&batch) { return Err("embed.batch: between 1 and 2048".into()); }
            c.embed = Some(EmbedPolicy { url, model, api_key: e.api_key.filter(|k| !k.is_empty()), dimensions: e.dimensions, batch });
        }
        if let Some(a) = self.app {
            if let Some(o) = a.origins { for x in &o { if x != "*" && !(x.starts_with("https://") || x.starts_with("http://")) { return Err(format!("app.origins: {x:?} is not an origin (https://app.example, or \"*\")")); } } c.app.origins = o.into_iter().map(|x| x.trim_end_matches('/').to_string()).collect(); }
            if let Some(u) = a.public_url.filter(|u| !u.is_empty()) { if !(u.starts_with("https://") || u.starts_with("http://")) { return Err("app.publicUrl: an http(s) URL".into()); } c.app.public_url = Some(u.trim_end_matches('/').to_string()); }
            c.app.anonymous_role = a.anonymous_role.filter(|r| !r.is_empty());
            if let Some(n) = a.max_rows { if n == 0 { return Err("app.maxRows: at least 1".into()); } c.app.max_rows = n; }
            if let Some(m) = a.max_request { let m = size_of(m, "app.maxRequest")?; if !(64 << 10..=256 << 20).contains(&m) { return Err("app.maxRequest: between 64KB and 256MB".into()); } c.app.max_request = m as usize; }
            c.app.static_dir = a.static_dir.filter(|d| !d.is_empty()).map(PathBuf::from);
            if let Some(p) = a.proxy.map(ProxyIn::full) {
                let to = p.to.filter(|t| !t.is_empty()).ok_or("app.proxy: the app's address, such as http://127.0.0.1:3000")?.trim_end_matches('/').to_string();
                let rest = to.strip_prefix("http://").ok_or("app.proxy: an http:// address (the app on this machine or a private network; the API is what speaks https)")?;
                if rest.is_empty() || rest.contains(['/', '?', '#', '@']) { return Err("app.proxy: scheme, host and port only, such as http://127.0.0.1:3000".into()); }
                let timeout = match p.timeout { Some(t) => dur_of(t, "app.proxy.timeout")?, None => Duration::from_secs(60) };
                if timeout < Duration::from_secs(1) { return Err("app.proxy.timeout: at least 1s".into()); }
                let connections = p.connections.unwrap_or(256); if !(1..=100_000).contains(&connections) { return Err("app.proxy.connections: between 1 and 100,000".into()); }
                if c.app.static_dir.is_some() { return Err("app.staticDir and app.proxy: one or the other (the app serves its own files)".into()); }
                c.app.proxy = Some(ProxyPolicy { to, timeout, connections });
            }
            if let Some(t) = a.trust_proxy { c.app.trust_proxy = t.iter().map(|n| crate::proxy::Net::parse(n).map_err(|e| format!("app.trustProxy: {e}"))).collect::<Result<_, _>>()?; }
            if let Some(m) = a.sign_up { c.app.sign_up = m.into_iter().map(|(t, cols)| (t.to_ascii_lowercase(), cols.into_iter().map(|c| c.to_ascii_lowercase()).collect())).collect(); }
            if let Some(f) = a.files {
                if let Some(m) = f.max_size { let m = size_of(m, "app.files.maxSize")?; if m == 0 { return Err("app.files.maxSize: at least 1 byte".into()); } c.app.file_max = m; }
                if let Some(t) = f.link_ttl { let t = dur_of(t, "app.files.linkTtl")?; if t < Duration::from_secs(60) || t > Duration::from_secs(7 * 86400) { return Err("app.files.linkTtl: between 1m and 7d".into()); } c.app.file_link_ttl = t; }
            }
            if let Some(t) = a.tls {
                let some = |v: Option<String>| v.filter(|x| !x.is_empty());
                let domains: Vec<String> = t.domains.unwrap_or_default().into_iter().map(|d| d.trim().trim_end_matches('.').to_ascii_lowercase()).collect();
                if let Some(d) = domains.iter().find(|d| !is_dns_name(d)) { return Err(format!("app.tls.domains: {d:?} is not a domain name a CA can check here (no wildcards, no IP addresses)")); }
                let (cert, key) = (some(t.cert).map(PathBuf::from), some(t.key).map(PathBuf::from));
                if cert.is_some() != key.is_some() { return Err("app.tls: cert and key go together".into()); }
                if cert.is_none() && domains.is_empty() { return Err("app.tls: domains (a certificate from the CA, renewed automatically) or cert and key (your own)".into()); }
                let acme = some(t.acme).unwrap_or_else(|| LETS_ENCRYPT.to_string());
                if !acme.starts_with("https://") { return Err("app.tls.acme: the https URL of the CA's directory".into()); }
                if let Some(e) = t.email.as_deref().filter(|e| !e.is_empty() && !e.contains('@')) { return Err(format!("app.tls.email: {e:?} is not an email address")); }
                let Some(listen) = c.listen.app.clone() else { return Err("app.tls: set listen.app (the address to serve https on, such as 0.0.0.0:443)".into()) };
                if c.app.public_url.is_none() { if let Some(d) = domains.first() {
                    let port = listen.rsplit_once(':').map(|(_, p)| p).filter(|p| *p != "443");
                    c.app.public_url = Some(format!("https://{d}{}", port.map(|p| format!(":{p}")).unwrap_or_default()));
                } }
                c.app.tls = Some(TlsPolicy { domains, email: some(t.email), cert, key, acme, acme_root: some(t.acme_root).map(PathBuf::from), dir: some(t.dir).map(PathBuf::from), redirect: some(t.redirect) });
            }
            if let Some(m) = a.mcp {
                let mut p = McpPolicy { users: m.users.filter(|u| !u.is_empty()).map(|u| u.to_ascii_lowercase()), ..McpPolicy::default() };
                if let Some(d) = m.token_ttl { let d = dur_of(d, "app.mcp.tokenTtl")?; if d < Duration::from_secs(300) || d > Duration::from_secs(86400) { return Err("app.mcp.tokenTtl: between 5m and 1d".into()); } p.token_ttl = d; }
                if let Some(d) = m.grant_ttl { let d = dur_of(d, "app.mcp.grantTtl")?; if d < Duration::from_secs(3600) || d > Duration::from_secs(365 * 86400) { return Err("app.mcp.grantTtl: between 1h and 365d".into()); } p.grant_ttl = d; }
                if let Some(n) = m.max_rows { if n == 0 { return Err("app.mcp.maxRows: at least 1".into()); } p.max_rows = n; }
                if let Some(b) = m.sql { p.sql = b; }
                // the issuer and the resource are absolute URLs agents check
                if c.app.public_url.as_deref().is_none_or(|u| !u.starts_with("https://") && !(u.starts_with("http://localhost") || u.starts_with("http://127.0.0.1") || u.starts_with("http://[::1]"))) {
                    return Err("app.mcp needs app.publicUrl, the https address agents reach this server at (or app.tls.domains); http only on this machine".into());
                }
                if c.app.public_url.as_deref().and_then(|u| u.split_once("://")).is_some_and(|(_, r)| r.contains('/')) { return Err("app.mcp: app.publicUrl is an origin, without a path (agents find the server at its /.well-known)".into()); }
                c.app.mcp = Some(p);
            }
        }
        if let Some(f) = self.functions.map(FunctionsIn::full) {
            c.functions.dir = f.dir.filter(|d| !d.is_empty()).map(PathBuf::from);
            if let Some(w) = f.watch { c.functions.watch = w; }
            if let Some(t) = f.timeout { let t = dur_of(t, "functions.timeout")?; if t < Duration::from_millis(10) || t > Duration::from_secs(300) { return Err("functions.timeout: between 10ms and 5m".into()); } c.functions.timeout = t; }
            if let Some(m) = f.memory { let m = size_of(m, "functions.memory")?; if !(4 << 20..=4 << 30).contains(&m) { return Err("functions.memory: between 4MB and 4GB".into()); } c.functions.memory = m as usize; }
            if let Some(n) = f.instances { if !(1..=1024).contains(&n) { return Err("functions.instances: between 1 and 1024".into()); } c.functions.instances = n; }
        }
        if let Some(a) = self.auth {
            if let Some(d) = a.session_ttl { let d = dur_of(d, "auth.sessionTtl")?; if d < Duration::from_secs(60) { return Err("auth.sessionTtl: at least 60s".into()); } c.auth.session_ttl = d; }
            if let Some(n) = a.password_min { if !(1..=256).contains(&n) { return Err("auth.passwordMin: between 1 and 256".into()); } c.auth.password_min = n; }
            for (name, f) in a.oauth.unwrap_or_default() { if name.is_empty() || !name.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-') { return Err(format!("auth.oauth: provider names are letters, digits, - and _ (got {name:?})")); } c.auth.oauth.insert(name.clone(), resolve_oauth(&name, f)?); }
        }
        Ok(c)
    }
}
fn resolve_backup(b: BackupFile, key: &str) -> Result<Backup, String> {
    let need = |v: Option<String>, k: &str| v.filter(|s| !s.is_empty()).ok_or_else(|| format!("{key}.{k} is required"));
    if let Some(e) = b.endpoint.as_deref().filter(|e| !e.is_empty()) { crate::cloud::check_endpoint(e).map_err(|m| format!("{key}.{m}"))?; }
    let d = crate::cloud::CloudConfig::local("", "");
    Ok(Backup {
        endpoint: need(b.endpoint, "endpoint")?, bucket: need(b.bucket, "bucket")?, prefix: b.prefix.unwrap_or_default(), region: b.region.unwrap_or_else(|| "us-east-1".into()),
        access_key: need(b.access_key, "accessKey")?, secret_key: need(b.secret_key, "secretKey")?, passphrase: b.passphrase.filter(|p| !p.is_empty()),
        interval: dur_or(b.interval, d.interval, &format!("{key}.interval"))?, compress: b.compress.unwrap_or(true),
        compact_after: dur_or(b.compact_after, d.compact_after, &format!("{key}.compactAfter"))?, compact_every: dur_or(b.compact_every, d.compact_every, &format!("{key}.compactEvery"))?,
        bootstrap: b.bootstrap.unwrap_or(false),
    })
}
fn dur_or(v: Option<Dur>, default: Duration, key: &str) -> Result<Duration, String> { match v { Some(d) => dur_of(d, key), None => Ok(default) } }
fn dur_of(v: Dur, key: &str) -> Result<Duration, String> { match v { Dur::Millis(ms) => Ok(Duration::from_millis(ms)), Dur::Text(s) => parse_duration(&s).map_err(|e| format!("{key}: {e}")) } }
fn size_of(v: Size, key: &str) -> Result<u64, String> { match v { Size::Bytes(n) => Ok(n), Size::Text(s) => parse_size(&s).map_err(|e| format!("{key}: {e}")) } }

fn split_unit(s: &str) -> Result<(f64, String), String> {
    let s = s.trim(); let i = s.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(s.len());
    let v: f64 = s[..i].parse().map_err(|_| format!("not a number: {s:?}"))?; Ok((v, s[i..].trim().to_string()))
}
/// `"5ms"`, `"1.5s"`, `"2m"`, `"1h"`, `"7d"`; a bare number is seconds.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let (v, u) = split_unit(s)?;
    let secs = match u.as_str() { "ms" => v / 1000.0, "" | "s" => v, "m" | "min" => v * 60.0, "h" => v * 3600.0, "d" => v * 86400.0, other => return Err(format!("unknown time unit {other:?} in {s:?}")) };
    if secs < 0.0 || !secs.is_finite() { return Err(format!("bad duration {s:?}")); }
    Ok(Duration::from_secs_f64(secs))
}
/// `"256MB"`, `"1GB"`, `"64KB"`, `"4096"` (bytes); KiB/MiB/GiB mean the same as KB/MB/GB here.
pub fn parse_size(s: &str) -> Result<u64, String> {
    let (v, u) = split_unit(s)?;
    let mult = match u.to_ascii_uppercase().as_str() { "" | "B" => 1u64, "K" | "KB" | "KIB" => 1 << 10, "M" | "MB" | "MIB" => 1 << 20, "G" | "GB" | "GIB" => 1 << 30, "T" | "TB" | "TIB" => 1 << 40, other => return Err(format!("unknown size unit {other:?} in {s:?}")) };
    Ok((v * mult as f64) as u64)
}
/// Replace every `${NAME}` with the environment variable; an unset one is an error, never an empty string.
pub fn interpolate(text: &str) -> Result<String, String> {
    let mut out = String::with_capacity(text.len()); let mut rest = text;
    while let Some(i) = rest.find("${") {
        out.push_str(&rest[..i]); let after = &rest[i + 2..];
        let Some(j) = after.find('}') else { return Err("unterminated ${ in configuration".into()) };
        let name = &after[..j];
        let val = std::env::var(name).map_err(|_| format!("environment variable {name} is not set (referenced as ${{{name}}})"))?;
        out.push_str(&val); rest = &after[j + 1..];
    }
    out.push_str(rest); Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn units() {
        assert_eq!(parse_duration("5ms").unwrap(), Duration::from_millis(5)); assert_eq!(parse_duration("1.5s").unwrap(), Duration::from_millis(1500));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120)); assert_eq!(parse_duration("7d").unwrap(), Duration::from_secs(7 * 86400));
        assert_eq!(parse_size("256MB").unwrap(), 256 << 20); assert_eq!(parse_size("1GB").unwrap(), 1 << 30); assert_eq!(parse_size("4096").unwrap(), 4096);
        assert!(parse_duration("3 weeks").is_err()); assert!(parse_size("5 bananas").is_err());
    }
    #[test] fn defaults_and_json() {
        let c = Config::from_json("{}").unwrap();
        assert_eq!(c.durable, Durability::Visible); assert!(c.create); assert_eq!(c.snapshot.log_bytes, Some(64 << 20)); assert_eq!(c.live.debounce, Duration::from_millis(5));
        let c = Config::from_json(r#"{"durable":"cloud","backup":{"endpoint":"http://x","bucket":"b","accessKey":"k","secretKey":"s","interval":"250ms","passphrase":"p"},"snapshot":{"logBytes":"64MB","idleAfter":0},"listen":{"tcp":"0.0.0.0:7781","token":"t"}}"#).unwrap();
        assert_eq!(c.durable, Durability::Cloud); let b = c.backup.unwrap(); assert_eq!(b.interval, Duration::from_millis(250)); assert!(b.passphrase.is_some()); assert!(b.cloud().key.is_some());
        assert_eq!(c.snapshot.log_bytes, Some(64 << 20)); assert_eq!(c.snapshot.idle_after, None); assert_eq!(c.listen.tcp.as_deref(), Some("0.0.0.0:7781"));
        assert!(Config::from_json(r#"{"durable":"cloud"}"#).is_err(), "cloud durability needs a bucket");
        assert!(Config::from_json(r#"{"listen":{"tcp":"0.0.0.0:1"}}"#).is_err(), "tcp needs a token");
        assert!(Config::from_json(r#"{"backup":{"bucket":"b"}}"#).unwrap_err().contains("endpoint"));
        assert!(Config::from_json(r#"{"snapsot":{}}"#).unwrap_err().contains("snapsot"), "typos are errors");
        assert_eq!(c.log.sync_delay, None, "fsync right away unless asked");
        assert_eq!(Config::from_json(r#"{"log":{"syncDelay":"200ms","threadsIdleAfter":"1s"}}"#).unwrap().log.sync_delay, Some(Duration::from_millis(200)));
        assert!(Config::from_json(r#"{"log":{"syncDelay":"5m"}}"#).unwrap_err().contains("syncDelay"));
    }
    #[test] fn app_tls() {
        let tls = |j: &str| Config::from_json(&format!(r#"{{"listen":{{"app":"0.0.0.0:443"}},"app":{{"tls":{j}}}}}"#));
        let c = tls(r#"{"domains":["API.Example.com."],"email":"ops@example.com"}"#).unwrap(); let t = c.app.tls.unwrap();
        assert_eq!(t.domains, ["api.example.com"]); assert_eq!(t.acme, LETS_ENCRYPT); assert!(t.cert.is_none());
        assert_eq!(c.app.public_url.as_deref(), Some("https://api.example.com"), "publicUrl from the first domain");
        let c = Config::from_json(r#"{"listen":{"app":"0.0.0.0:8443"},"app":{"tls":{"domains":["a.example.com"]}}}"#).unwrap();
        assert_eq!(c.app.public_url.as_deref(), Some("https://a.example.com:8443"), "and its port, when not 443");
        let c = Config::from_json(r#"{"listen":{"app":"0.0.0.0:443"},"app":{"publicUrl":"https://app.example","tls":{"domains":["a.example.com"]}}}"#).unwrap();
        assert_eq!(c.app.public_url.as_deref(), Some("https://app.example"), "a publicUrl given stays");
        assert!(tls(r#"{"cert":"/c.pem","key":"/k.pem"}"#).unwrap().app.tls.unwrap().cert.is_some(), "your own certificate, no domains needed");
        for (bad, says) in [(r#"{}"#, "domains"), (r#"{"cert":"/c.pem"}"#, "together"), (r#"{"domains":["*.example.com"]}"#, "wildcards"), (r#"{"domains":["10.0.0.1"]}"#, "IP"),
                            (r#"{"domains":["a.example.com"],"acme":"http://ca.example/dir"}"#, "https"), (r#"{"domains":["a.example.com"],"email":"nope"}"#, "email"), (r#"{"domains":["a.example.com"],"stapling":true}"#, "stapling")] {
            assert!(tls(bad).unwrap_err().contains(says), "{bad}: {}", tls(bad).unwrap_err());
        }
        assert!(Config::from_json(r#"{"app":{"tls":{"domains":["a.example.com"]}}}"#).unwrap_err().contains("listen.app"));
    }
    #[test] fn endpoints_that_get_secrets() {
        for ok in ["https://api.openai.com/v1", "http://localhost:11434/v1", "http://127.0.0.1/v1", "http://[::1]:8080"] { assert!(secure_url(ok), "{ok}"); }
        for bad in ["http://localhost:80@evil.example/v1", "http://127.0.0.1@evil.example", "https://user:pw@api.example", "http://evil.example", "http://localhost.evil.example", "ftp://localhost", "localhost:11434", ""] { assert!(!secure_url(bad), "{bad}"); }
        assert!(Config::from_json(r#"{"embed":{"url":"http://localhost:1@evil.example/v1","model":"m"}}"#).unwrap_err().contains("embed.url"));
    }
    #[test] fn file_then_code_then_env() {
        let dir = std::env::temp_dir().join(format!("sqzdb-config-test-{}", std::process::id())); std::fs::create_dir_all(&dir).unwrap();
        unsafe { std::env::set_var("SQZDB_TEST_SECRET", "s3cr3t"); }
        let file = dir.join("orders.toml");
        std::fs::write(&file, "durable = true\n[backup]\nendpoint = \"http://127.0.0.1:9000\"\nbucket = \"from-file\"\naccessKey = \"k\"\nsecretKey = \"${SQZDB_TEST_SECRET}\"\n[snapshot]\nlogBytes = \"64MB\"\n").unwrap();
        let json = format!(r#"{{"configFile":{:?},"backup":{{"bucket":"from-code"}},"snapshot":{{"idleAfter":"10s"}}}}"#, file.to_str().unwrap());
        let c = Config::load(&dir, Some(&json)).unwrap();
        assert_eq!(c.durable, Durability::Fsync, "from the file");
        let b = c.backup.unwrap(); assert_eq!(b.bucket, "from-code", "code wins over the file"); assert_eq!(b.secret_key, "s3cr3t", "secret from the environment"); assert_eq!(b.endpoint, "http://127.0.0.1:9000", "untouched file values survive the overlay");
        assert_eq!(c.snapshot.log_bytes, Some(64 << 20)); assert_eq!(c.snapshot.idle_after, Some(Duration::from_secs(10)));
        // a file inside the data directory is data, not configuration: it is never read unless named
        std::fs::write(dir.join("sqzdb.toml"), "durable = true\n[listen]\ntcp = \"0.0.0.0:1\"\ntoken = \"x\"\n").unwrap();
        let c = Config::load(&dir, Some("{}")).unwrap(); assert_eq!(c.durable, Durability::Visible); assert!(c.listen.tcp.is_none());
        std::fs::write(&file, "configFile = \"other.toml\"\n").unwrap();
        assert!(Config::load(&dir, Some(&format!(r#"{{"configFile":{:?}}}"#, file.to_str().unwrap()))).unwrap_err().contains("cannot be set from a file"));
        std::fs::write(&file, "[backup]\nsecretKey = \"${SQZDB_TEST_UNSET_VAR}\"\n").unwrap();
        assert!(Config::load(&dir, Some(&format!(r#"{{"configFile":{:?}}}"#, file.to_str().unwrap()))).unwrap_err().contains("SQZDB_TEST_UNSET_VAR"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
