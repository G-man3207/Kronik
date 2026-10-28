//! TLS for the gateway (ADR 0009): rustls with ring. The certificate comes
//! from PEM files, reloaded twice a day, or from an ACME CA by TLS-ALPN-01 on
//! the gateway's own port, renewed 30 days before it expires. ACME state
//! (the account and the certificates) is cached per CA directory. With a
//! preview domain and a [`Dns01`] provider, a second ACME certificate,
//! `*.<preview domain>`, comes by DNS-01 and is served for the names it
//! covers (ADR 0026).
//
// Shell code: like the hyper server, it runs on tokio and reads the wall
// clock directly (ADR 0004 §3).
#![allow(clippy::disallowed_methods)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use kronik_core::env::BoxFuture;

use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// The ALPN protocol of TLS-ALPN-01 (RFC 8737).
pub const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";

/// Renew a certificate this long before it expires.
const RENEW_BEFORE: Duration = Duration::from_secs(30 * 86_400);

/// Where the gateway's certificate comes from.
#[derive(Debug, Clone)]
pub enum Certificates {
    Files { cert: PathBuf, key: PathBuf },
    Acme(Acme),
}

#[derive(Debug, Clone)]
pub struct Acme {
    pub domains: Vec<String>,
    pub email: String,
    /// The CA's directory URL.
    pub directory: String,
    /// Under the data directory; one subdirectory per CA directory.
    pub cache_dir: PathBuf,
    /// A CA certificate (PEM) to trust for the ACME server, besides the
    /// system's roots: a private ACME CA, or Pebble in tests.
    pub ca_file: Option<PathBuf>,
    /// The wildcard certificate for preview forks, by DNS-01.
    pub wildcard: Option<Wildcard>,
}

/// A certificate for `*.<domain>`, ordered from the same CA and account as
/// the main one, with DNS-01 challenges published by `dns01`.
#[derive(Debug, Clone)]
pub struct Wildcard {
    pub domain: String,
    pub dns01: Arc<dyn Dns01>,
    /// How long to wait after publishing a TXT record before the CA checks
    /// it.
    pub propagation: Duration,
}

/// Publishes and removes the TXT records of DNS-01 challenges (RFC 8555
/// §8.4). `fqdn` is `_acme-challenge.<domain>.`, with the final dot, and
/// `value` the record's text.
pub trait Dns01: Send + Sync + std::fmt::Debug {
    fn present<'a>(&'a self, fqdn: &'a str, value: &'a str) -> BoxFuture<'a, Result<(), String>>;
    fn cleanup<'a>(&'a self, fqdn: &'a str, value: &'a str) -> BoxFuture<'a, Result<(), String>>;
}

/// A [`Dns01`] provider that runs an executable, as `<program> present|cleanup
/// <fqdn> <value>`, which talks to the owner's DNS API. A non-zero exit, or
/// no exit within `timeout`, is a failure; its output goes to the log. The
/// hook inherits the daemon's environment, where its DNS credentials live,
/// minus [`HOOK_ENV_REMOVED`].
#[derive(Debug, Clone)]
pub struct ExecHook {
    pub program: PathBuf,
    pub timeout: Duration,
}

/// Daemon secrets a third-party hook must not see: the master key, and the
/// CLI's API token if the daemon happens to have one.
pub const HOOK_ENV_REMOVED: &[&str] = &[kronik_privacy::MASTER_KEY_ENV, "KRONIK_TOKEN"];

impl ExecHook {
    async fn run(&self, action: &str, fqdn: &str, value: &str) -> Result<(), String> {
        self.run_with(&[], action, fqdn, value).await
    }

    /// `run`, with `daemon_env` added to the inherited environment before
    /// the secrets are removed: the seam that lets a test stand in for the
    /// daemon's environment without changing the test process's.
    async fn run_with(
        &self,
        daemon_env: &[(&str, &str)],
        action: &str,
        fqdn: &str,
        value: &str,
    ) -> Result<(), String> {
        let program = self.program.display();
        let mut command = tokio::process::Command::new(&self.program);
        command
            .args([action, fqdn, value])
            .envs(daemon_env.iter().copied());
        for name in HOOK_ENV_REMOVED {
            command.env_remove(name);
        }
        // Its own process group, so that the timeout also kills what the
        // hook started (a hung curl would otherwise publish after cleanup).
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("{program}: {e}"))?;
        let group = child
            .id()
            .and_then(|id| rustix::process::Pid::from_raw(id as i32));
        let output = match tokio::time::timeout(self.timeout, child.wait_with_output()).await {
            Ok(output) => output.map_err(|e| format!("{program}: {e}"))?,
            Err(_) => {
                if let Some(group) = group {
                    let _ =
                        rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
                }
                return Err(format!(
                    "{program} {action} {fqdn}: no exit within {:?}",
                    self.timeout
                ));
            }
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::info!(hook = %program, action, fqdn, status = %output.status,
            stdout = %stdout.trim(), stderr = %stderr.trim(), "DNS-01 hook");
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "{program} {action} {fqdn}: {}: {}",
                output.status,
                stderr.trim()
            ))
        }
    }
}

impl Dns01 for ExecHook {
    fn present<'a>(&'a self, fqdn: &'a str, value: &'a str) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(self.run("present", fqdn, value))
    }

    fn cleanup<'a>(&'a self, fqdn: &'a str, value: &'a str) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(self.run("cleanup", fqdn, value))
    }
}

/// The certificates the gateway presents: the main one, the wildcard one
/// for the names it covers and, while an ACME order is open, the
/// TLS-ALPN-01 challenge certificates.
#[derive(Debug, Default)]
pub struct Resolver {
    current: RwLock<Option<Arc<CertifiedKey>>>,
    /// The preview domain and its `*.` certificate.
    wildcard: RwLock<Option<(String, Arc<CertifiedKey>)>>,
    challenges: RwLock<HashMap<String, Arc<CertifiedKey>>>,
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let acme = hello
            .alpn()
            .is_some_and(|mut protocols| protocols.any(|p| p == ACME_TLS_ALPN));
        if acme {
            let name = hello.server_name()?;
            return self.challenges.read().ok()?.get(name).cloned();
        }
        if let Some(name) = hello.server_name()
            && let Ok(wildcard) = self.wildcard.read()
            && let Some((domain, key)) = wildcard.as_ref()
            && covered(name, domain)
        {
            return Some(key.clone());
        }
        self.current.read().ok()?.clone()
    }
}

/// Whether `*.<domain>` covers `name`: exactly one more label.
fn covered(name: &str, domain: &str) -> bool {
    let Some(split) = name.len().checked_sub(domain.len() + 1) else {
        return false;
    };
    match (name.get(..split), name.get(split..)) {
        (Some(label), Some(rest)) => {
            !label.is_empty()
                && !label.contains('.')
                && rest.starts_with('.')
                && rest[1..].eq_ignore_ascii_case(domain)
        }
        _ => false,
    }
}

impl Resolver {
    fn install(&self, key: Arc<CertifiedKey>) {
        if let Ok(mut current) = self.current.write() {
            *current = Some(key);
        }
    }

    fn install_wildcard(&self, domain: &str, key: Arc<CertifiedKey>) {
        if let Ok(mut wildcard) = self.wildcard.write() {
            *wildcard = Some((domain.to_owned(), key));
        }
    }

    fn set_challenge(&self, domain: &str, key: Option<Arc<CertifiedKey>>) {
        if let Ok(mut challenges) = self.challenges.write() {
            match key {
                Some(key) => challenges.insert(domain.to_owned(), key),
                None => challenges.remove(domain),
            };
        }
    }
}

/// Which certificate an ACME task looks after.
#[derive(Debug, Clone)]
enum Cert {
    Main,
    Wildcard(Wildcard),
}

impl Cert {
    fn names(&self, acme: &Acme) -> Vec<String> {
        match self {
            Cert::Main => acme.domains.clone(),
            Cert::Wildcard(w) => vec![format!("*.{}", w.domain)],
        }
    }

    /// The cached chain and key, in the CA directory's cache; the wildcard's
    /// is named by its domain, so changing `preview_domain` orders anew.
    fn file(&self) -> String {
        match self {
            Cert::Main => "certificate.pem".into(),
            Cert::Wildcard(w) => format!("wildcard.{}.pem", w.domain),
        }
    }

    fn install(&self, resolver: &Resolver, key: Arc<CertifiedKey>) {
        match self {
            Cert::Main => resolver.install(key),
            Cert::Wildcard(w) => resolver.install_wildcard(&w.domain, key),
        }
    }
}

/// The rustls configuration for `certificates`, and the background tasks
/// that keep the certificates current (spawned on the current tokio
/// runtime). Files are loaded before this returns, so a bad file stops the
/// start.
pub fn start(certificates: Certificates) -> Result<Arc<rustls::ServerConfig>, String> {
    let resolver = Arc::new(Resolver::default());
    match certificates {
        Certificates::Files { cert, key } => {
            let (loaded, _) = load_files(&cert, &key)?;
            resolver.install(Arc::new(loaded));
            tokio::spawn(reload_files(resolver.clone(), cert, key));
        }
        Certificates::Acme(acme) => {
            if acme.domains.is_empty() {
                return Err("ACME needs at least one domain".into());
            }
            if let Some(wildcard) = acme.wildcard.clone() {
                tokio::spawn(keep_acme_certificate(
                    resolver.clone(),
                    acme.clone(),
                    Cert::Wildcard(wildcard),
                ));
            }
            tokio::spawn(keep_acme_certificate(resolver.clone(), acme, Cert::Main));
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS configuration: {e}"))?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"http/1.1".to_vec(), ACME_TLS_ALPN.to_vec()];
    Ok(Arc::new(config))
}

/// A certificate chain and its private key, from PEM, with the chain's
/// expiry.
pub fn parse_pem(chain: &[u8], key: &[u8]) -> Result<(CertifiedKey, SystemTime), String> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(chain)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("reading the certificate chain: {e}"))?;
    let leaf = certs.first().ok_or("no certificate in the chain")?;
    let expiry = not_after(leaf)?;
    let key =
        PrivateKeyDer::from_pem_slice(key).map_err(|e| format!("reading the private key: {e}"))?;
    let signing = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| format!("the private key: {e}"))?;
    Ok((CertifiedKey::new(certs, signing), expiry))
}

/// When a certificate expires.
pub fn not_after(cert: &CertificateDer<'_>) -> Result<SystemTime, String> {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref())
        .map_err(|e| format!("parsing the certificate: {e}"))?;
    let seconds = u64::try_from(parsed.validity().not_after.timestamp())
        .map_err(|_| "the certificate expires before 1970".to_owned())?;
    Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(seconds))
}

fn load_files(cert: &Path, key: &Path) -> Result<(CertifiedKey, SystemTime), String> {
    let chain = std::fs::read(cert).map_err(|e| format!("{}: {e}", cert.display()))?;
    let key_pem = std::fs::read(key).map_err(|e| format!("{}: {e}", key.display()))?;
    parse_pem(&chain, &key_pem)
}

/// Reloads the files twice a day, so a certificate renewed by another tool
/// is picked up; a file that can't be read leaves the current one in place.
async fn reload_files(resolver: Arc<Resolver>, cert: PathBuf, key: PathBuf) {
    loop {
        tokio::time::sleep(Duration::from_secs(12 * 3600)).await;
        match load_files(&cert, &key) {
            Ok((loaded, _)) => resolver.install(Arc::new(loaded)),
            Err(e) => tracing::warn!(error = %e, "TLS: keeping the current certificate"),
        }
    }
}

/// Gets a certificate and renews it, forever; failures are retried with a
/// backoff from a minute to an hour.
async fn keep_acme_certificate(resolver: Arc<Resolver>, acme: Acme, cert: Cert) {
    let mut backoff = Duration::from_secs(60);
    loop {
        let wait = match ensure_certificate(&resolver, &acme, &cert).await {
            Ok(expiry) => {
                backoff = Duration::from_secs(60);
                let renew_at = expiry
                    .checked_sub(RENEW_BEFORE)
                    .unwrap_or(SystemTime::UNIX_EPOCH);
                let until = renew_at
                    .duration_since(SystemTime::now())
                    .unwrap_or_default();
                until.clamp(Duration::from_secs(60), Duration::from_secs(12 * 3600))
            }
            Err(e) => {
                tracing::warn!(error = %e, domains = ?cert.names(&acme), retry_in = ?backoff, "ACME: no certificate");
                let wait = backoff;
                backoff = (backoff * 2).min(Duration::from_secs(3600));
                wait
            }
        };
        tokio::time::sleep(wait).await;
    }
}

/// The cache for this CA directory.
fn cache_dir(acme: &Acme) -> PathBuf {
    let hash = blake3::hash(acme.directory.as_bytes()).to_hex();
    acme.cache_dir.join(&hash.as_str()[..16])
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// Installs the cached certificate, or a new one when there is none or it
/// expires within [`RENEW_BEFORE`]; returns its expiry.
async fn ensure_certificate(
    resolver: &Resolver,
    acme: &Acme,
    cert: &Cert,
) -> Result<SystemTime, String> {
    let dir = cache_dir(acme);
    let cert_path = dir.join(cert.file());
    if let Ok(pem) = std::fs::read(&cert_path)
        && let Ok((key, expiry)) = parse_pem(&pem, &pem)
    {
        cert.install(resolver, Arc::new(key));
        let fresh = expiry
            .duration_since(SystemTime::now())
            .is_ok_and(|left| left > RENEW_BEFORE);
        if fresh {
            return Ok(expiry);
        }
    }
    let (key_pem, chain_pem) = order(resolver, acme, cert, &dir).await?;
    let bundle = format!("{chain_pem}{key_pem}");
    let (key, expiry) = parse_pem(bundle.as_bytes(), key_pem.as_bytes())?;
    write_private(&cert_path, bundle.as_bytes())?;
    cert.install(resolver, Arc::new(key));
    tracing::info!(domains = ?cert.names(acme), "ACME: installed a new certificate");
    Ok(expiry)
}

/// The main and the wildcard task may both find no account: one creates it.
static ACCOUNT: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn account(acme: &Acme, dir: &Path) -> Result<Account, String> {
    let _creating = ACCOUNT.lock().await;
    let builder = match &acme.ca_file {
        Some(ca) => Account::builder_with_root(ca),
        None => Account::builder(),
    }
    .map_err(|e| format!("ACME client: {e}"))?;
    let path = dir.join("account.json");
    if let Ok(bytes) = std::fs::read(&path) {
        let credentials: AccountCredentials =
            serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
        return builder
            .from_credentials(credentials)
            .await
            .map_err(|e| format!("ACME account: {e}"));
    }
    let contact = format!("mailto:{}", acme.email);
    let (account, credentials) = builder
        .create(
            &NewAccount {
                contact: &[&contact],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            acme.directory.clone(),
            None,
        )
        .await
        .map_err(|e| format!("creating the ACME account at {}: {e}", acme.directory))?;
    let json = serde_json::to_vec(&credentials).map_err(|e| format!("ACME account: {e}"))?;
    write_private(&path, &json)?;
    Ok(account)
}

/// Orders a certificate, answering each TLS-ALPN-01 challenge on the
/// gateway's port, or each DNS-01 challenge through the [`Dns01`] provider;
/// returns the private key and the chain, as PEM.
async fn order(
    resolver: &Resolver,
    acme: &Acme,
    cert: &Cert,
    dir: &Path,
) -> Result<(String, String), String> {
    let account = account(acme, dir).await?;
    let identifiers: Vec<Identifier> = cert.names(acme).into_iter().map(Identifier::Dns).collect();
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .map_err(|e| format!("ACME order: {e}"))?;
    // Challenge certificates by domain, or TXT records (fqdn, value).
    let mut answered: Vec<(String, Option<String>)> = Vec::new();
    let status = async {
        let mut authorizations = order.authorizations();
        while let Some(authorization) = authorizations.next().await {
            let mut authorization =
                authorization.map_err(|e| format!("ACME authorization: {e}"))?;
            match authorization.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                other => return Err(format!("ACME authorization is {other:?}")),
            }
            let kind = match cert {
                Cert::Main => ChallengeType::TlsAlpn01,
                Cert::Wildcard(_) => ChallengeType::Dns01,
            };
            let mut challenge = authorization
                .challenge(kind.clone())
                .ok_or(format!("the CA offers no {kind:?} challenge"))?;
            let Identifier::Dns(domain) = challenge.identifier().identifier.clone() else {
                return Err("the CA asks to validate something other than a DNS name".into());
            };
            match cert {
                Cert::Main => {
                    let digest = challenge.key_authorization().digest();
                    let key = challenge_certificate(&domain, digest.as_ref())?;
                    resolver.set_challenge(&domain, Some(key));
                    answered.push((domain, None));
                }
                Cert::Wildcard(w) => {
                    let fqdn = format!("_acme-challenge.{domain}.");
                    let value = challenge.key_authorization().dns_value();
                    // Pushed first: a hook that fails half way may have
                    // published the record.
                    answered.push((fqdn.clone(), Some(value.clone())));
                    w.dns01.present(&fqdn, &value).await?;
                    tokio::time::sleep(w.propagation).await;
                }
            }
            challenge
                .set_ready()
                .await
                .map_err(|e| format!("ACME challenge: {e}"))?;
        }
        order
            .poll_ready(&RetryPolicy::default())
            .await
            .map_err(|e| format!("ACME order: {e}"))
    }
    .await;
    for (name, txt) in &answered {
        match (cert, txt) {
            (Cert::Wildcard(w), Some(value)) => {
                if let Err(e) = w.dns01.cleanup(name, value).await {
                    tracing::warn!(error = %e, fqdn = %name, "DNS-01: the TXT record stays");
                }
            }
            _ => resolver.set_challenge(name, None),
        }
    }
    let status = status?;
    if status != OrderStatus::Ready {
        return Err(format!("the ACME order is {status:?}, not ready"));
    }
    let key_pem = order
        .finalize()
        .await
        .map_err(|e| format!("ACME finalize: {e}"))?;
    let chain_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .map_err(|e| format!("ACME certificate: {e}"))?;
    Ok((key_pem, chain_pem))
}

/// The self-signed certificate that answers a TLS-ALPN-01 challenge.
fn challenge_certificate(domain: &str, digest: &[u8]) -> Result<Arc<CertifiedKey>, String> {
    let key = rcgen::KeyPair::generate().map_err(|e| format!("challenge key: {e}"))?;
    let mut params = rcgen::CertificateParams::new(vec![domain.to_owned()])
        .map_err(|e| format!("challenge certificate: {e}"))?;
    params.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(digest)];
    let cert = params
        .self_signed(&key)
        .map_err(|e| format!("challenge certificate: {e}"))?;
    let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let signing = rustls::crypto::ring::sign::any_supported_type(&der)
        .map_err(|e| format!("challenge key: {e}"))?;
    Ok(Arc::new(CertifiedKey::new(
        vec![cert.der().clone()],
        signing,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wildcard_covers_one_more_label() {
        assert!(covered("abc.preview.example.com", "preview.example.com"));
        assert!(covered("ABC.Preview.Example.com", "preview.example.com"));
        for name in [
            "preview.example.com",
            ".preview.example.com",
            "a.b.preview.example.com",
            "abcpreview.example.com",
            "app.example.com",
        ] {
            assert!(!covered(name, "preview.example.com"), "{name}");
        }
    }

    /// Hook tests write a script and then exec it. A fork by another test
    /// thread while the script is open for writing makes the exec fail with
    /// ETXTBSY, so these tests run one at a time.
    static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn hook(dir: &Path, body: &str, timeout: Duration) -> ExecHook {
        use std::os::unix::fs::PermissionsExt as _;
        let program = dir.join("hook");
        std::fs::write(&program, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        ExecHook { program, timeout }
    }

    #[tokio::test]
    async fn the_exec_hook_gets_the_action_the_name_and_the_value() {
        let _serial = SERIAL.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let calls = dir.path().join("calls");
        let hook = hook(
            dir.path(),
            &format!("echo \"$@\" >> {}", calls.display()),
            Duration::from_secs(10),
        );
        hook.present("_acme-challenge.p.example.", "v1")
            .await
            .unwrap();
        hook.cleanup("_acme-challenge.p.example.", "v1")
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&calls).unwrap(),
            "present _acme-challenge.p.example. v1\ncleanup _acme-challenge.p.example. v1\n"
        );
    }

    #[tokio::test]
    async fn a_failing_or_slow_hook_is_an_error() {
        let _serial = SERIAL.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let failing = hook(
            dir.path(),
            "echo no zone >&2; exit 3",
            Duration::from_secs(10),
        );
        let e = failing
            .present("_acme-challenge.p.example.", "v")
            .await
            .unwrap_err();
        assert!(e.contains("exit status: 3") && e.contains("no zone"), "{e}");
        let slow = hook(dir.path(), "exec sleep 5", Duration::from_millis(200));
        let e = slow
            .present("_acme-challenge.p.example.", "v")
            .await
            .unwrap_err();
        assert!(e.contains("no exit within"), "{e}");
        let missing = ExecHook {
            program: dir.path().join("absent"),
            timeout: Duration::from_secs(1),
        };
        assert!(missing.cleanup("f.", "v").await.is_err());
    }

    #[tokio::test]
    async fn the_hook_gets_dns_credentials_but_not_the_master_key() {
        let _serial = SERIAL.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let seen = dir.path().join("env");
        let hook = hook(
            dir.path(),
            &format!("env > {}", seen.display()),
            Duration::from_secs(10),
        );
        hook.run_with(
            &[
                ("KRONIK_MASTER_KEY", "aa"),
                ("KRONIK_TOKEN", "kt"),
                ("DNS_API_TOKEN", "dns"),
            ],
            "present",
            "_acme-challenge.p.example.",
            "v",
        )
        .await
        .unwrap();
        let env = std::fs::read_to_string(&seen).unwrap();
        assert!(env.lines().any(|l| l == "DNS_API_TOKEN=dns"), "{env}");
        assert!(!env.contains("KRONIK_MASTER_KEY="), "{env}");
        assert!(!env.contains("KRONIK_TOKEN="), "{env}");
    }

    #[tokio::test]
    async fn the_timeout_kills_what_the_hook_started() {
        let _serial = SERIAL.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let pid = dir.path().join("pid");
        // The hook waits on a background sleep; only the timeout ends it.
        let hook = hook(
            dir.path(),
            &format!("sleep 30 & echo $! > {}; wait", pid.display()),
            Duration::from_millis(500),
        );
        let e = hook.present("f.", "v").await.unwrap_err();
        assert!(e.contains("no exit within"), "{e}");
        let pid = std::fs::read_to_string(&pid).unwrap();
        let stat = Path::new("/proc").join(pid.trim()).join("stat");
        // SIGKILL is asynchronous: give the kernel a moment. Gone or a
        // zombie both mean killed.
        for _ in 0..50 {
            match std::fs::read_to_string(&stat) {
                Ok(s) if !s.contains(") Z ") => std::thread::sleep(Duration::from_millis(20)),
                _ => return,
            }
        }
        panic!("the hook's child {} outlived the timeout", pid.trim());
    }
}
