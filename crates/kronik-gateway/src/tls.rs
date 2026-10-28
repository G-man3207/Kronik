//! TLS for the gateway (ADR 0009): rustls with ring. The certificate comes
//! from PEM files, reloaded twice a day, or from an ACME CA by TLS-ALPN-01 on
//! the gateway's own port, renewed 30 days before it expires. ACME state
//! (the account and the certificate) is cached per CA directory.
//
// Shell code: like the hyper server, it runs on tokio and reads the wall
// clock directly (ADR 0004 §3).
#![allow(clippy::disallowed_methods)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

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
}

/// The certificate the gateway presents and, while an ACME order is open,
/// the TLS-ALPN-01 challenge certificates.
#[derive(Debug, Default)]
pub struct Resolver {
    current: RwLock<Option<Arc<CertifiedKey>>>,
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
        self.current.read().ok()?.clone()
    }
}

impl Resolver {
    fn install(&self, key: Arc<CertifiedKey>) {
        if let Ok(mut current) = self.current.write() {
            *current = Some(key);
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

/// The rustls configuration for `certificates`, and the background task that
/// keeps the certificate current (spawned on the current tokio runtime).
/// Files are loaded before this returns, so a bad file stops the start.
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
            tokio::spawn(keep_acme_certificate(resolver.clone(), acme));
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
async fn keep_acme_certificate(resolver: Arc<Resolver>, acme: Acme) {
    let mut backoff = Duration::from_secs(60);
    loop {
        let wait = match ensure_certificate(&resolver, &acme).await {
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
                tracing::warn!(error = %e, domains = ?acme.domains, retry_in = ?backoff, "ACME: no certificate");
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
async fn ensure_certificate(resolver: &Resolver, acme: &Acme) -> Result<SystemTime, String> {
    let dir = cache_dir(acme);
    let cert_path = dir.join("certificate.pem");
    if let Ok(pem) = std::fs::read(&cert_path)
        && let Ok((key, expiry)) = parse_pem(&pem, &pem)
    {
        resolver.install(Arc::new(key));
        let fresh = expiry
            .duration_since(SystemTime::now())
            .is_ok_and(|left| left > RENEW_BEFORE);
        if fresh {
            return Ok(expiry);
        }
    }
    let (key_pem, chain_pem) = order(resolver, acme, &dir).await?;
    let bundle = format!("{chain_pem}{key_pem}");
    let (key, expiry) = parse_pem(bundle.as_bytes(), key_pem.as_bytes())?;
    write_private(&cert_path, bundle.as_bytes())?;
    resolver.install(Arc::new(key));
    tracing::info!(domains = ?acme.domains, "ACME: installed a new certificate");
    Ok(expiry)
}

async fn account(acme: &Acme, dir: &Path) -> Result<Account, String> {
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
/// gateway's port; returns the private key and the chain, as PEM.
async fn order(resolver: &Resolver, acme: &Acme, dir: &Path) -> Result<(String, String), String> {
    let account = account(acme, dir).await?;
    let identifiers: Vec<Identifier> = acme.domains.iter().cloned().map(Identifier::Dns).collect();
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .map_err(|e| format!("ACME order: {e}"))?;
    let mut answered = Vec::new();
    let mut authorizations = order.authorizations();
    while let Some(authorization) = authorizations.next().await {
        let mut authorization = authorization.map_err(|e| format!("ACME authorization: {e}"))?;
        match authorization.status {
            AuthorizationStatus::Valid => continue,
            AuthorizationStatus::Pending => {}
            other => return Err(format!("ACME authorization is {other:?}")),
        }
        let mut challenge = authorization
            .challenge(ChallengeType::TlsAlpn01)
            .ok_or("the CA offers no tls-alpn-01 challenge")?;
        let Identifier::Dns(domain) = challenge.identifier().identifier.clone() else {
            return Err("the CA asks to validate something other than a DNS name".into());
        };
        let key = challenge_certificate(&domain, challenge.key_authorization().digest().as_ref())?;
        resolver.set_challenge(&domain, Some(key));
        answered.push(domain);
        challenge
            .set_ready()
            .await
            .map_err(|e| format!("ACME challenge: {e}"))?;
    }
    let status = order.poll_ready(&RetryPolicy::default()).await;
    for domain in &answered {
        resolver.set_challenge(domain, None);
    }
    let status = status.map_err(|e| format!("ACME order: {e}"))?;
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
