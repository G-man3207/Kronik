//! The server's basic settings: `/etc/kronik/kronik.toml` (SPEC.md,
//! "Operator configuration and policy"). Only what the server needs to start
//! lives in the file; everything that affects behavior (grants, limits,
//! policy, privacy mode, foreign actors) is history set through the API (I5).
//!
//! Every section and key of the brief's file is accepted, with the brief's
//! value as the default, except the values that only make sense for one
//! installation: `tls.domains`, `tls.acme_email`, `ship.url`, `ship.endpoint`
//! and `privacy.subject_from` default to empty and `tls.mode` to `off`.
//! `server.http_listen` defaults to `0.0.0.0:443` with TLS and to
//! `127.0.0.1:8080` without, and `keys.master_key_file` to
//! `<data_dir>/keys/master.key`, so that a bare `kronik serve` touches no
//! system port or path; `kronik serve --init` writes the brief's values.
//! Six keys complete `[tls]`: `cert_file` and `key_file` for `mode =
//! "files"`, `acme_directory` (Let's Encrypt by default) and `acme_ca_file`,
//! a CA to trust for a private ACME server; `dns01_hook` and
//! `dns01_propagation` get a wildcard certificate for `[gateway]
//! preview_domain` by DNS-01 (M11). `[gateway] preview_domain` and
//! `[fork] preview_ttl` (M11) set where preview forks answer and how long
//! they live. Unknown keys are errors, reported with the file and line.

use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use serde::de::{self, Deserializer};

use kronik_gateway::subject::SubjectFrom;

/// Where `kronik serve` and the CLI look for the file.
pub const DEFAULT_PATH: &str = "/etc/kronik/kronik.toml";

/// Let's Encrypt's production ACME directory.
pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";

#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub server: Server,
    pub tls: Tls,
    pub gateway: Gateway,
    pub log: Log,
    pub retention: Retention,
    pub sql: Sql,
    pub ship: Ship,
    pub keys: Keys,
    pub privacy: Privacy,
    pub replay: Replay,
    pub fork: Fork,
    pub promote: Promote,
    pub rebase: Rebase,
    pub foreign: Foreign,
    pub simulators: Simulators,
    pub audit: Audit,
    pub otel: Otel,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Server {
    pub data_dir: PathBuf,
    pub api_socket: PathBuf,
    /// The gateway; see [`Config::http_listen`] for the default.
    pub http_listen: Option<SocketAddr>,
    /// `/metrics` and `/healthz`.
    pub admin_listen: SocketAddr,
    /// The JSON API (and MCP) over TCP, where every request needs a bearer
    /// token (M5); off when absent. See [`Config::api_listen`].
    pub api_listen: Option<SocketAddr>,
}

impl Default for Server {
    fn default() -> Self {
        Server {
            data_dir: "/var/lib/kronik".into(),
            api_socket: "/run/kronik/api.sock".into(),
            http_listen: None,
            admin_listen: SocketAddr::from(([127, 0, 0, 1], 9464)),
            api_listen: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    #[default]
    Off,
    Files,
    Acme,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Tls {
    pub mode: TlsMode,
    pub domains: Vec<String>,
    pub acme_email: Option<String>,
    pub acme_directory: String,
    /// A CA certificate (PEM) to trust for the ACME server, besides the
    /// system's roots.
    pub acme_ca_file: Option<PathBuf>,
    /// The certificate chain (PEM) for `mode = "files"`.
    pub cert_file: Option<PathBuf>,
    /// The private key (PEM) for `mode = "files"`.
    pub key_file: Option<PathBuf>,
    /// The executable that publishes DNS-01 TXT records for the wildcard
    /// certificate of `[gateway] preview_domain` (`mode = "acme"`); called
    /// as `<hook> present|cleanup <fqdn> <value>`.
    pub dns01_hook: Option<PathBuf>,
    /// How long to wait after the hook publishes a record before the CA
    /// checks it.
    pub dns01_propagation: Dur,
}

impl Default for Tls {
    fn default() -> Self {
        Tls {
            mode: TlsMode::Off,
            domains: Vec::new(),
            acme_email: None,
            acme_directory: LETS_ENCRYPT.into(),
            acme_ca_file: None,
            cert_file: None,
            key_file: None,
            dns01_hook: None,
            dns01_propagation: Dur::secs(60),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Gateway {
    pub timeout: Dur,
    pub idempotency_header: String,
    pub idempotency_ttl: Dur,
    /// Reverse proxies, as addresses or CIDR blocks: their connections are
    /// exempt from the per-client connection cap.
    pub trusted_proxies: Vec<String>,
    /// The domain whose subdomains serve preview forks (`<id>.<domain>`);
    /// see M11.
    pub preview_domain: Option<String>,
}

impl Default for Gateway {
    fn default() -> Self {
        Gateway {
            timeout: Dur::secs(30),
            idempotency_header: "Idempotency-Key".into(),
            idempotency_ttl: Dur::secs(24 * 3600),
            trusted_proxies: Vec::new(),
            preview_domain: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Log {
    pub group_commit_ms: u64,
    pub segment_max_mb: u64,
    pub segment_max_age_s: u64,
    /// Below this much free space on the log's file system, new root inputs
    /// and changes are refused (UNAVAILABLE) so that the disk never fills
    /// up under a log write, which would stop the daemon. "0B" turns the
    /// check off.
    pub disk_reserve: Size,
}

impl Default for Log {
    fn default() -> Self {
        Log {
            group_commit_ms: 2,
            segment_max_mb: 64,
            segment_max_age_s: 60,
            disk_reserve: Size(512 << 20),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Retention {
    /// How far back the log reaches; forks and replay must start within it.
    pub history: Dur,
    pub snapshot_interval: Dur,
    pub snapshots_kept: u32,
}

impl Default for Retention {
    fn default() -> Self {
        Retention {
            history: Dur::secs(7 * 86_400),
            snapshot_interval: Dur::secs(3600),
            snapshots_kept: 48,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Sql {
    pub max_size_per_actor: Size,
}

impl Default for Sql {
    fn default() -> Self {
        Sql {
            max_size_per_actor: Size(1 << 30),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Ship {
    pub enabled: bool,
    pub url: Option<String>,
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Keys {
    /// The secret store's and the privacy keystore's master key; see
    /// [`Config::master_key_file`] for the default. The
    /// `KRONIK_MASTER_KEY` environment variable, when set, holds the key
    /// material itself (64 hex characters) and no file is read or created;
    /// setting both is refused.
    pub master_key_file: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Privacy {
    pub keystore_backup_retention: Dur,
    /// Where a request's subject comes from, such as `header:x-user-id`.
    pub subject_from: Option<String>,
}

impl Default for Privacy {
    fn default() -> Self {
        Privacy {
            keystore_backup_retention: Dur::secs(30 * 86_400),
            subject_from: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayMode {
    Isolated,
    Continuous,
    #[default]
    Both,
}

impl ReplayMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ReplayMode::Isolated => "isolated",
            ReplayMode::Continuous => "continuous",
            ReplayMode::Both => "both",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Replay {
    pub default_mode: ReplayMode,
    /// The share of root inputs isolated replay runs, stratified per route
    /// and actor type.
    pub sample: Percent,
}

impl Default for Replay {
    fn default() -> Self {
        Replay {
            default_mode: ReplayMode::Both,
            sample: Percent(100.0),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Fork {
    pub live_allowlist: Vec<String>,
    /// How long a preview fork lives unless created with `--ttl` (M11).
    pub preview_ttl: Dur,
}

impl Default for Fork {
    fn default() -> Self {
        Fork {
            live_allowlist: Vec::new(),
            preview_ttl: Dur::secs(24 * 3600),
        }
    }
}

/// `[simulators]` (M12): server-wide simulator settings.
#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Simulators {
    /// `[simulators.model]`: off when absent (ADR 0015).
    pub model: Option<SimulatorModel>,
}

/// An OpenAI-compatible chat completions endpoint for the model simulator.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulatorModel {
    pub endpoint: String,
    pub model: String,
    /// The environment variable holding the API key; the key itself never
    /// appears in the file.
    #[serde(default)]
    pub api_key_env: Option<String>,
    #[serde(default = "SimulatorModel::default_timeout")]
    pub timeout: Dur,
    #[serde(default = "SimulatorModel::default_max_examples")]
    pub max_examples: usize,
    /// Send recorded examples to the model even when privacy mode is or was
    /// on (state reads are not recorded, so personal data in an untagged
    /// request cannot be ruled out). Off by default.
    #[serde(default)]
    pub examples_under_privacy: bool,
}

impl SimulatorModel {
    fn default_timeout() -> Dur {
        Dur::secs(20)
    }

    fn default_max_examples() -> usize {
        5
    }

    /// The fork's model configuration; reads the key from `api_key_env`.
    pub fn resolve(&self) -> Result<kronik_fork::simulators::ModelConfig, String> {
        let api_key = match &self.api_key_env {
            None => None,
            Some(var) => Some(std::env::var(var).map_err(|_| {
                format!("[simulators.model] api_key_env = {var:?}: the variable is not set")
            })?),
        };
        Ok(kronik_fork::simulators::ModelConfig {
            endpoint: self.endpoint.clone(),
            model: self.model.clone(),
            api_key,
            timeout: self.timeout.0,
            max_examples: self.max_examples,
            examples_under_privacy: self.examples_under_privacy,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Promote {
    pub max_gap: Dur,
    pub catch_up_timeout: Dur,
}

impl Default for Promote {
    fn default() -> Self {
        Promote {
            max_gap: Dur::secs(2),
            catch_up_timeout: Dur::secs(300),
        }
    }
}

/// `[rebase]` (M13): the switch of a rollback via replay.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Rebase {
    /// The longest the switch holds new requests and turns.
    pub max_pause: Dur,
}

impl Default for Rebase {
    fn default() -> Self {
        Rebase {
            max_pause: Dur::secs(2),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    #[default]
    Auto,
    Systrap,
    Kvm,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Foreign {
    pub runsc_path: PathBuf,
    pub platform: Platform,
    /// Runtime state of the sandboxes: runsc's root, network namespaces and
    /// bridge sockets (docs/design/m7-foreign.md §3). A tmpfs, so nothing
    /// survives a reboot.
    pub run_dir: PathBuf,
    /// Directories whose local OCI layouts (`oci-layout:<dir>`) a token
    /// with `operate` may add; any other directory needs `admin`, because
    /// the daemon reads it as root (docs/design/m7-foreign.md §4).
    pub layout_dirs: Vec<PathBuf>,
    /// The longest one image pull from a registry may take.
    pub pull_timeout: Dur,
    /// Checkpoints kept per `fork_mode = "sandbox"` actor (M14).
    pub checkpoints_kept: usize,
}

impl Default for Foreign {
    fn default() -> Self {
        Foreign {
            runsc_path: "/usr/local/bin/runsc".into(),
            platform: Platform::Auto,
            run_dir: "/run/kronik".into(),
            layout_dirs: Vec::new(),
            pull_timeout: Dur::secs(600),
            checkpoints_kept: 3,
        }
    }
}

/// `[audit]`: the audit export (docs/design/m28-otel.md §4, §6.1).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Audit {
    /// `file:///dir/`, `https://…` or `s3://bucket/prefix`; none: off.
    /// `KRONIK_AUDIT_SINK` overrides it ([`Audit::sink`]).
    pub sink: Option<String>,
    /// An S3-compatible server, as `[ship] endpoint` (s3:// only).
    pub endpoint: Option<String>,
    pub batch_records: usize,
    pub interval: Dur,
    /// A directory sink starts a new file at this size.
    pub file_max_bytes: Size,
    /// The environment variable holding a webhook's extra headers
    /// (`key=value,…`), so credentials stay out of this file.
    pub headers_env: Option<String>,
    /// Where a new export starts: the first retained record, or the
    /// applied LSN.
    pub from: AuditFrom,
    /// Retention ignores the hold once it is older ("0s": no cap).
    pub max_hold: Dur,
    /// Retention ignores the hold below this much free disk: `"2x"` (of
    /// `[log] disk_reserve`) or a size.
    pub hold_release: HoldRelease,
}

impl Default for Audit {
    fn default() -> Self {
        Audit {
            sink: None,
            endpoint: None,
            batch_records: 500,
            interval: Dur::secs(1),
            file_max_bytes: Size(64 << 20),
            headers_env: None,
            from: AuditFrom::Start,
            max_hold: Dur::secs(0),
            hold_release: HoldRelease::Times(2),
        }
    }
}

/// `[otel] actor_keys`: how actor keys leave the node in spans and audit
/// lines (m28-otel §3.5, ADR 0082).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKeys {
    /// `kh:` + 12 hex of a keyed hash: stable, not reversible.
    #[default]
    Hashed,
    Plain,
    /// Left out.
    #[serde(rename = "none")]
    Omit,
}

/// OpenTelemetry export (m28-otel §3, §6.1): spans of committed turns and
/// the metrics, over OTLP/HTTP protobuf. Off without an endpoint.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Otel {
    /// `http(s)://host:port` of a collector; `KRONIK_OTEL_ENDPOINT` and
    /// `--otel-endpoint` override it.
    pub endpoint: Option<String>,
    pub traces: bool,
    pub metrics: bool,
    pub service_name: String,
    pub actor_keys: ActorKeys,
    /// How long a batch smaller than `batch_spans` waits for more.
    pub interval: Dur,
    pub metrics_interval: Dur,
    /// At most this many log records per OTLP request.
    pub batch_spans: u64,
    /// The environment variable holding extra headers, `key=value,…`.
    pub headers_env: Option<String>,
}

impl Default for Otel {
    fn default() -> Self {
        Otel {
            endpoint: None,
            traces: true,
            metrics: true,
            service_name: "kronik".into(),
            actor_keys: ActorKeys::Hashed,
            interval: Dur::secs(5),
            metrics_interval: Dur::secs(60),
            batch_spans: 512,
            headers_env: None,
        }
    }
}

/// Environment override of `[audit] sink`.
pub const AUDIT_SINK_ENV: &str = "KRONIK_AUDIT_SINK";

impl Audit {
    /// The sink in force: `KRONIK_AUDIT_SINK`, else the file's; None
    /// (off) for an empty value or `"none"`.
    pub fn sink(&self) -> Option<String> {
        std::env::var(AUDIT_SINK_ENV)
            .ok()
            .or_else(|| self.sink.clone())
            .filter(|s| !s.is_empty() && s != "none")
    }

    /// The parsed sink in force, checked (§6.1).
    pub fn parsed_sink(&self) -> Result<Option<kronik_otel::sink::Sink>, String> {
        self.sink()
            .map(|s| kronik_otel::sink::Sink::parse(&s, self.endpoint.as_deref()))
            .transpose()
    }

    /// `hold_release` in bytes.
    pub fn hold_release_bytes(&self, disk_reserve: u64) -> u64 {
        match self.hold_release {
            HoldRelease::Times(n) => disk_reserve.saturating_mul(n),
            HoldRelease::Bytes(b) => b,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditFrom {
    Start,
    Now,
}

/// `[audit] hold_release`: a multiple of `[log] disk_reserve` (`"2x"`) or a
/// size (`"1GiB"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldRelease {
    Times(u64),
    Bytes(u64),
}

impl std::str::FromStr for HoldRelease {
    type Err = String;

    fn from_str(s: &str) -> Result<HoldRelease, String> {
        match s.trim().strip_suffix('x') {
            Some(n) => n.parse().map(HoldRelease::Times).map_err(|_| {
                format!("invalid hold_release {s:?}: use a multiple such as \"2x\" or a size")
            }),
            None => s.parse::<Size>().map(|b| HoldRelease::Bytes(b.0)),
        }
    }
}

impl Otel {
    /// The endpoint without a trailing `/`, when one is set.
    pub fn endpoint(&self) -> Option<&str> {
        self.endpoint
            .as_deref()
            .map(|e| e.trim_end_matches('/'))
            .filter(|e| !e.is_empty())
    }

    /// An `http(s)://` endpoint with a host; plain HTTP leaves the host
    /// only to a loopback collector when headers (usually credentials) are
    /// sent (review L4).
    pub fn check(&self) -> Result<(), String> {
        if self.batch_spans == 0 {
            return Err("[otel] batch_spans must be at least 1".into());
        }
        let Some(endpoint) = self.endpoint() else {
            return Ok(());
        };
        // Errors show the scheme and host only: userinfo, path and query can
        // hold credentials, and the error reaches the log (review M9).
        let shown = kronik_otel::http::scheme_host(endpoint);
        let scheme = endpoint.split_once("://").map(|(s, _)| s);
        if !matches!(scheme, Some("http" | "https"))
            || kronik_otel::http::host(endpoint).is_none_or(str::is_empty)
        {
            return Err(format!(
                "[otel] endpoint {shown:?}: use http://host:port or https://host:port"
            ));
        }
        if scheme == Some("http")
            && self.headers_env.is_some()
            && !kronik_otel::http::is_loopback(endpoint)
        {
            return Err(format!(
                "[otel] endpoint {shown:?} is plain HTTP to a host that is not loopback, \
                 and headers_env sends headers (usually credentials) with every request; \
                 use https:// or a local collector"
            ));
        }
        Ok(())
    }
}

/// A duration written with a unit: `500ms`, `30s`, `60m`, `24h`, `7d`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dur(pub Duration);

impl Dur {
    const fn secs(s: u64) -> Dur {
        Dur(Duration::from_secs(s))
    }
}

impl std::str::FromStr for Dur {
    type Err = String;

    fn from_str(s: &str) -> Result<Dur, String> {
        let (number, unit) = split_unit(s);
        let n: u64 = number.parse().map_err(|_| {
            format!("invalid duration {s:?}: use a whole number and a unit, as in \"30s\"")
        })?;
        let ms_per = match unit {
            "ms" => 1,
            "s" => 1_000,
            "m" => 60_000,
            "h" => 3_600_000,
            "d" => 86_400_000,
            _ => {
                return Err(format!(
                    "invalid duration {s:?}: the unit must be ms, s, m, h or d"
                ));
            }
        };
        n.checked_mul(ms_per)
            .map(|ms| Dur(Duration::from_millis(ms)))
            .ok_or_else(|| format!("duration {s:?} is too long"))
    }
}

/// A size written with a binary unit: `512B`, `64KiB`, `64MiB`, `1GiB`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Size(pub u64);

impl std::str::FromStr for Size {
    type Err = String;

    fn from_str(s: &str) -> Result<Size, String> {
        let (number, unit) = split_unit(s);
        let n: u64 = number.parse().map_err(|_| {
            format!("invalid size {s:?}: use a whole number and a unit, as in \"64MiB\"")
        })?;
        let shift = match unit {
            "B" => 0,
            "KiB" => 10,
            "MiB" => 20,
            "GiB" => 30,
            "TiB" => 40,
            _ => {
                return Err(format!(
                    "invalid size {s:?}: the unit must be B, KiB, MiB, GiB or TiB"
                ));
            }
        };
        n.checked_mul(1u64 << shift)
            .map(Size)
            .ok_or_else(|| format!("size {s:?} is too large"))
    }
}

/// A percentage above 0 and at most 100: `"10%"`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Percent(pub f64);

impl std::str::FromStr for Percent {
    type Err = String;

    fn from_str(s: &str) -> Result<Percent, String> {
        let p: f64 = s
            .strip_suffix('%')
            .and_then(|n| n.trim().parse().ok())
            .ok_or_else(|| format!("invalid percentage {s:?}: write it as \"10%\""))?;
        if p > 0.0 && p <= 100.0 {
            Ok(Percent(p))
        } else {
            Err(format!(
                "percentage {s:?} must be above 0% and at most 100%"
            ))
        }
    }
}

fn split_unit(s: &str) -> (&str, &str) {
    let s = s.trim();
    let at = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    (&s[..at], s[at..].trim_start())
}

/// Deserializes the `FromStr` types above from TOML strings.
macro_rules! from_string {
    ($($ty:ty),*) => {$(
        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let s = String::deserialize(deserializer)?;
                s.parse().map_err(de::Error::custom)
            }
        }
    )*};
}

from_string!(Dur, Size, Percent, HoldRelease);

/// A file that can't be used: where, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub path: PathBuf,
    /// 1-based, when the error has a place in the file.
    pub line: Option<usize>,
    pub message: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(f, "{}:{line}: {}", self.path.display(), self.message),
            None => write!(f, "{}: {}", self.path.display(), self.message),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Parses and checks a file's text; `path` only names it in errors.
    pub fn parse(text: &str, path: &Path) -> Result<Config, ConfigError> {
        let config: Config = toml::from_str(text).map_err(|e| ConfigError {
            path: path.to_owned(),
            line: e.span().map(|span| line_of(text, span.start)),
            message: e.message().to_owned(),
        })?;
        config.check().map_err(|message| ConfigError {
            path: path.to_owned(),
            line: None,
            message,
        })?;
        Ok(config)
    }

    /// Reads `path`, which must exist.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError {
            path: path.to_owned(),
            line: None,
            message: format!("cannot read the configuration: {e}"),
        })?;
        Config::parse(&text, path)
    }

    /// The configuration `kronik serve` starts with: `explicit` (which must
    /// exist), else [`DEFAULT_PATH`] if it exists, else the defaults. Also
    /// returns the file it read.
    pub fn find(explicit: Option<&Path>) -> Result<(Config, Option<PathBuf>), ConfigError> {
        let path = match explicit {
            Some(path) => path.to_owned(),
            None if Path::new(DEFAULT_PATH).exists() => PathBuf::from(DEFAULT_PATH),
            None => return Ok((Config::default(), None)),
        };
        Config::load(&path).map(|config| (config, Some(path)))
    }

    /// Requirements across keys that the types can't express.
    fn check(&self) -> Result<(), String> {
        match self.tls.mode {
            TlsMode::Acme if self.tls.domains.is_empty() => {
                return Err(
                    "[tls] mode = \"acme\" needs domains, the names to get a certificate for"
                        .into(),
                );
            }
            TlsMode::Acme if self.tls.acme_email.as_deref().unwrap_or("").is_empty() => {
                return Err(
                    "[tls] mode = \"acme\" needs acme_email, where the CA sends expiry notices"
                        .into(),
                );
            }
            TlsMode::Files if self.tls.cert_file.is_none() || self.tls.key_file.is_none() => {
                return Err("[tls] mode = \"files\" needs cert_file and key_file (PEM)".into());
            }
            _ => {}
        }
        if let Some(domain) = &self.gateway.preview_domain {
            let label = |l: &str| {
                (1..=63).contains(&l.len())
                    && !l.starts_with('-')
                    && !l.ends_with('-')
                    && l.chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            };
            // An all-digit TLD is an IP address. 237: `_acme-challenge.` (16)
            // plus the domain must fit in DNS's 253.
            let tld_digits = domain
                .rsplit('.')
                .next()
                .is_some_and(|tld| tld.chars().all(|c| c.is_ascii_digit()));
            if !domain.contains('.')
                || domain.len() > 237
                || tld_digits
                || !domain.split('.').all(label)
            {
                return Err(format!(
                    "[gateway] preview_domain = {domain:?}: use a lowercase domain such as \
                     \"preview.example.com\", without a scheme, port or leading dot \
                     (labels of 1-63 letters, digits or inner hyphens, at most 237 characters)"
                ));
            }
        }
        if self.tls.dns01_hook.is_some() {
            if self.tls.mode != TlsMode::Acme {
                return Err(
                    "[tls] dns01_hook needs mode = \"acme\": the wildcard certificate \
                     for preview_domain comes from the ACME CA"
                        .into(),
                );
            }
            let domain = self.gateway.preview_domain.as_deref().unwrap_or("");
            if domain.is_empty() {
                return Err(
                    "[tls] dns01_hook needs [gateway] preview_domain, the domain \
                     whose wildcard certificate (*.<domain>) it publishes challenges for"
                        .into(),
                );
            }
        }
        if let Some(domain) = &self.gateway.preview_domain {
            // Previews answer only at <id>.<domain> then (P-F1), and with
            // ACME only DNS-01 gets the *.<domain> certificate (P-F5).
            if self.tls.mode == TlsMode::Acme && self.tls.dns01_hook.is_none() {
                return Err(format!(
                    "[gateway] preview_domain = {domain:?} with [tls] mode = \"acme\" needs \
                     [tls] dns01_hook: previews answer only at <id>.{domain}, and without the \
                     hook there is no *.{domain} certificate; set dns01_hook, or remove \
                     preview_domain to serve previews under /__preview/<id>/"
                ));
            }
            // The gateway's own names must not fall under it (P-F6).
            let suffix = format!(".{domain}");
            if let Some(name) = self.tls.domains.iter().find(|d| {
                let d = d.to_ascii_lowercase();
                d == *domain || d.ends_with(&suffix)
            }) {
                return Err(format!(
                    "[gateway] preview_domain = {domain:?} covers the gateway's own name \
                     {name:?} ([tls] domains): its requests would go to previews; use a \
                     domain of its own, best a separate registrable domain such as \
                     \"example-preview.com\""
                ));
            }
        }
        if self.ship.enabled && self.ship.url.as_deref().unwrap_or("").is_empty() {
            return Err("[ship] enabled = true needs url, such as \"s3://bucket/kronik\"".into());
        }
        if self.gateway.idempotency_header.trim().is_empty() {
            return Err(
                "BAD_REQUEST: [gateway] idempotency_header is empty; name the header clients send"
                    .into(),
            );
        }
        if let Some(e) = self
            .gateway
            .trusted_proxies
            .iter()
            .find_map(|p| kronik_gateway::IpNet::parse(p).err())
        {
            return Err(format!("[gateway] trusted_proxies: {e}"));
        }
        if let Some(from) = &self.privacy.subject_from
            && SubjectFrom::parse(from).is_none()
        {
            return Err(format!(
                "[privacy] subject_from = {from:?}: use \"header:<name>\" or \"jwt:sub\""
            ));
        }
        if let Some(d) = self.foreign.layout_dirs.iter().find(|d| !d.is_absolute()) {
            return Err(format!(
                "[foreign] layout_dirs: {} is not an absolute directory",
                d.display()
            ));
        }
        if self.fork.preview_ttl.0.is_zero() {
            return Err("[fork] preview_ttl must be more than zero, such as \"24h\"".into());
        }
        if let Some(m) = &self.simulators.model
            && kronik_effects::http::parse_url(&m.endpoint).is_err()
        {
            return Err(format!(
                "[simulators.model] endpoint = {:?} is not an http(s) URL",
                m.endpoint
            ));
        }
        self.audit.parsed_sink()?;
        if self.audit.endpoint.is_some() && self.audit.sink().is_none() {
            return Err("[audit] endpoint is for an s3:// sink only".into());
        }
        if self.audit.batch_records == 0 {
            return Err("[audit] batch_records must be at least 1".into());
        }
        self.check_audit_hold()?;
        self.otel.check()?;
        self.api_listen()?;
        Ok(())
    }

    /// An audit sink's hold must be able to give way (perf review R3): with
    /// `hold_release` at or below `[log] disk_reserve` (`"0B"` with `"2x"`,
    /// `"1x"`) and no `max_hold`, a sink that stays down keeps the log
    /// until the reserve refuses work, or the disk fills. Checked again
    /// after the flags, which can change the reserve.
    pub fn check_audit_hold(&self) -> Result<(), String> {
        let reserve = self.log.disk_reserve.0;
        let release = self.audit.hold_release_bytes(reserve);
        if self.audit.sink().is_some() && self.audit.max_hold.0.is_zero() && release <= reserve {
            return Err(format!(
                "[audit] hold_release ({release} bytes) must be above [log] disk_reserve \
                 ({reserve} bytes), or max_hold set: otherwise a sink that stays down holds \
                 the log until the disk reserve refuses work"
            ));
        }
        Ok(())
    }

    /// `server.api_listen`. Without TLS it must be a loopback address, so
    /// that bearer tokens never cross a network in the clear; with TLS the
    /// API uses the gateway's certificate.
    pub fn api_listen(&self) -> Result<Option<SocketAddr>, String> {
        match self.server.api_listen {
            Some(addr) if !addr.ip().is_loopback() && self.tls.mode == TlsMode::Off => {
                Err(format!(
                    "server.api_listen = \"{addr}\" is not a loopback address and [tls] is off: \
                     bearer tokens would cross the network in the clear; turn TLS on or listen \
                     on 127.0.0.1"
                ))
            }
            other => Ok(other),
        }
    }

    /// The gateway's address: `server.http_listen`, else `0.0.0.0:443` with
    /// TLS and `127.0.0.1:8080` without.
    pub fn http_listen(&self) -> SocketAddr {
        self.server.http_listen.unwrap_or(match self.tls.mode {
            TlsMode::Off => SocketAddr::from(([127, 0, 0, 1], 8080)),
            TlsMode::Files | TlsMode::Acme => SocketAddr::from(([0, 0, 0, 0], 443)),
        })
    }

    /// The gateway's public host and port for preview URLs under the path
    /// prefix (P-F5): the first `[tls] domains` name, else the bound
    /// address with an unspecified IP (`0.0.0.0`, `::`) as loopback; the
    /// port is left out when it is the scheme's default.
    pub fn public_host(&self, bound: SocketAddr) -> String {
        let mut addr = bound;
        if addr.ip().is_unspecified() {
            addr.set_ip(match addr {
                SocketAddr::V4(_) => std::net::Ipv4Addr::LOCALHOST.into(),
                SocketAddr::V6(_) => std::net::Ipv6Addr::LOCALHOST.into(),
            });
        }
        let host = match (self.tls.domains.first(), addr) {
            (Some(name), _) => name.clone(),
            (None, SocketAddr::V6(a)) => format!("[{}]", a.ip()),
            (None, SocketAddr::V4(a)) => a.ip().to_string(),
        };
        let default_port = if self.tls.mode == TlsMode::Off {
            80
        } else {
            443
        };
        if addr.port() == default_port {
            host
        } else {
            format!("{host}:{}", addr.port())
        }
    }

    /// The master key file: `keys.master_key_file`, else
    /// `<data_dir>/keys/master.key`. The `KRONIK_MASTER_KEY` environment
    /// variable, when set, is the key itself and no file is used.
    pub fn master_key_file(&self) -> PathBuf {
        self.keys
            .master_key_file
            .clone()
            .unwrap_or_else(|| self.server.data_dir.join("keys/master.key"))
    }

    /// Where HTTP root inputs get their subject; checked by [`Config::check`].
    pub fn subject_from(&self) -> Option<SubjectFrom> {
        self.privacy
            .subject_from
            .as_deref()
            .and_then(SubjectFrom::parse)
    }

    /// Where the gateway's certificate comes from; `None` without TLS. The
    /// ACME cache is `<data_dir>/tls/acme`. With `dns01_hook`, ACME also
    /// gets `*.<preview_domain>`; the hook gets two minutes per call.
    pub fn certificates(&self) -> Option<kronik_gateway::tls::Certificates> {
        use kronik_gateway::tls::{Acme, Certificates, ExecHook, Wildcard};
        use std::sync::Arc;
        match self.tls.mode {
            TlsMode::Off => None,
            TlsMode::Files => Some(Certificates::Files {
                cert: self.tls.cert_file.clone().unwrap_or_default(),
                key: self.tls.key_file.clone().unwrap_or_default(),
            }),
            TlsMode::Acme => Some(Certificates::Acme(Acme {
                domains: self.tls.domains.clone(),
                email: self.tls.acme_email.clone().unwrap_or_default(),
                directory: self.tls.acme_directory.clone(),
                cache_dir: self.server.data_dir.join("tls/acme"),
                ca_file: self.tls.acme_ca_file.clone(),
                wildcard: self.tls.dns01_hook.clone().and_then(|program| {
                    Some(Wildcard {
                        domain: self.gateway.preview_domain.clone()?,
                        dns01: Arc::new(ExecHook {
                            program,
                            timeout: Duration::from_secs(120),
                        }),
                        propagation: self.tls.dns01_propagation.0,
                    })
                }),
            })),
        }
    }
}

/// `kronik serve` flags (and their environment variables), which override
/// the file.
#[derive(Debug, Default)]
pub struct Overrides {
    pub data_dir: Option<PathBuf>,
    pub api_socket: Option<PathBuf>,
    pub http_listen: Option<SocketAddr>,
    pub admin_listen: Option<SocketAddr>,
    pub api_listen: Option<SocketAddr>,
    pub gateway_timeout: Option<Duration>,
    pub master_key_file: Option<PathBuf>,
    pub disk_reserve: Option<Size>,
    pub otel_endpoint: Option<String>,
}

impl Config {
    /// The file's values with every given override in their place.
    pub fn with(mut self, o: Overrides) -> Config {
        if let Some(v) = o.data_dir {
            self.server.data_dir = v;
        }
        if let Some(v) = o.api_socket {
            self.server.api_socket = v;
        }
        if let Some(v) = o.http_listen {
            self.server.http_listen = Some(v);
        }
        if let Some(v) = o.admin_listen {
            self.server.admin_listen = v;
        }
        if let Some(v) = o.api_listen {
            self.server.api_listen = Some(v);
        }
        if let Some(v) = o.gateway_timeout {
            self.gateway.timeout = Dur(v);
        }
        if let Some(v) = o.master_key_file {
            self.keys.master_key_file = Some(v);
        }
        if let Some(v) = o.disk_reserve {
            self.log.disk_reserve = v;
        }
        if let Some(v) = o.otel_endpoint {
            self.otel.endpoint = Some(v);
        }
        self
    }
}

/// The API socket a client command uses: `given` (`--socket`), else
/// `$KRONIK_API_SOCKET`, else `server.api_socket` from [`DEFAULT_PATH`] if it
/// exists, else `/run/kronik/api.sock`.
pub fn client_api_socket(given: Option<PathBuf>) -> Result<PathBuf, ConfigError> {
    if let Some(socket) = given.or_else(|| std::env::var_os("KRONIK_API_SOCKET").map(PathBuf::from))
    {
        return Ok(socket);
    }
    Config::find(None).map(|(config, _)| config.server.api_socket)
}

/// The file a client command shares with `kronik serve`: `$KRONIK_CONFIG`
/// when set, else [`DEFAULT_PATH`] if it exists, else the defaults.
pub fn client_config() -> Result<Config, ConfigError> {
    if let Some(path) = std::env::var_os("KRONIK_CONFIG") {
        return Config::load(Path::new(&path));
    }
    Config::find(None).map(|(config, _)| config)
}

/// `--data-dir`, else `server.data_dir` from the configuration file, else
/// `/var/lib/kronik`. An explicit `--data-dir` without `--config` does not
/// read the default configuration file, so a broken system file does not
/// block a command that already named its directory.
pub fn resolve_data_dir(
    config: Option<&Path>,
    data_dir: Option<PathBuf>,
) -> Result<PathBuf, ConfigError> {
    match (config, data_dir) {
        (None, Some(dir)) => Ok(dir),
        (config, data_dir) => {
            let (cfg, _) = Config::find(config)?;
            Ok(data_dir.unwrap_or(cfg.server.data_dir))
        }
    }
}

fn line_of(text: &str, offset: usize) -> usize {
    text.get(..offset).unwrap_or(text).matches('\n').count() + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Config, ConfigError> {
        Config::parse(text, Path::new("kronik.toml"))
    }

    /// The file in SPEC.md, "Operator configuration and policy".
    fn brief_file() -> String {
        let spec = include_str!("../../../SPEC.md");
        let start = spec.find("`/etc/kronik/kronik.toml`:").unwrap();
        let block = &spec[start..];
        let block = &block[block.find("```toml\n").unwrap() + 8..];
        block[..block.find("```").unwrap()].to_owned()
    }

    #[test]
    fn the_brief_file_parses_to_its_values() {
        let config = parse(&brief_file()).unwrap();
        assert_eq!(config.server.data_dir, PathBuf::from("/var/lib/kronik"));
        assert_eq!(config.http_listen(), "0.0.0.0:443".parse().unwrap());
        assert_eq!(
            config.server.admin_listen,
            "127.0.0.1:9464".parse().unwrap()
        );
        assert_eq!(config.tls.mode, TlsMode::Acme);
        assert_eq!(config.tls.domains, ["app.example.com"]);
        assert_eq!(config.gateway.timeout, Dur::secs(30));
        assert_eq!(config.gateway.idempotency_ttl, Dur::secs(86_400));
        assert_eq!(config.retention.history, Dur::secs(7 * 86_400));
        assert_eq!(config.sql.max_size_per_actor, Size(1 << 30));
        assert_eq!(
            config.master_key_file(),
            PathBuf::from("/etc/kronik/master.key")
        );
        assert_eq!(
            config.privacy.subject_from.as_deref(),
            Some("header:x-user-id")
        );
        assert_eq!(config.replay.sample, Percent(100.0));
        assert_eq!(config.promote.catch_up_timeout, Dur::secs(300));
        assert_eq!(config.foreign.platform, Platform::Auto);
    }

    #[test]
    fn omitted_keys_take_the_brief_defaults() {
        let brief = parse(&brief_file()).unwrap();
        let empty = parse("").unwrap();
        assert_eq!(empty, Config::default());
        assert_eq!(empty.gateway, brief.gateway);
        assert_eq!(empty.log, brief.log);
        assert_eq!(empty.retention, brief.retention);
        assert_eq!(empty.sql, brief.sql);
        assert_eq!(empty.replay, brief.replay);
        assert_eq!(empty.fork, brief.fork);
        assert_eq!(empty.promote, brief.promote);
        assert_eq!(empty.foreign, brief.foreign);
        assert_eq!(empty.server.admin_listen, brief.server.admin_listen);
        // Values for one installation are empty, and nothing points at a
        // system port or path without TLS.
        assert_eq!(empty.tls.mode, TlsMode::Off);
        assert_eq!(empty.http_listen(), "127.0.0.1:8080".parse().unwrap());
        assert_eq!(
            empty.master_key_file(),
            PathBuf::from("/var/lib/kronik/keys/master.key")
        );
        assert!(!empty.ship.enabled);
    }

    #[test]
    fn an_empty_idempotency_header_is_a_bad_request() {
        let e = parse("[gateway]\nidempotency_header = \"\"\n").unwrap_err();
        let shown = e.to_string();
        assert!(shown.contains("BAD_REQUEST"), "{shown}");
        assert!(shown.contains("idempotency_header"), "{shown}");
        assert!(shown.contains("kronik.toml"), "{shown}");
    }

    #[test]
    fn trusted_proxies_are_addresses_or_cidr_blocks() {
        let c = parse("[gateway]\ntrusted_proxies = [\"127.0.0.1\", \"10.0.0.0/8\", \"::1\"]\n")
            .unwrap();
        assert_eq!(c.gateway.trusted_proxies.len(), 3);
        let e = parse("[gateway]\ntrusted_proxies = [\"10.0.0.0/33\"]\n").unwrap_err();
        assert!(e.to_string().contains("trusted_proxies"), "{e}");
    }

    #[test]
    fn preview_keys_parse_and_bad_values_are_errors() {
        let c = parse(
            "[gateway]\npreview_domain = \"preview.example.com\"\n[fork]\npreview_ttl = \"2h\"\n",
        )
        .unwrap();
        assert_eq!(
            c.gateway.preview_domain.as_deref(),
            Some("preview.example.com")
        );
        assert_eq!(c.fork.preview_ttl, Dur::secs(7200));
        assert_eq!(Config::default().fork.preview_ttl, Dur::secs(86_400));
        let long_label = format!("{}.example.com", "a".repeat(64));
        let long_name = format!("{}example.com", "abcdefghi.".repeat(23));
        for bad in [
            "https://p.example.com",
            ".p.example.com",
            "localhost",
            "P.example.com",
            "-p.example.com",
            "p-.example.com",
            "10.0.0.1",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            let e = parse(&format!("[gateway]\npreview_domain = {bad:?}\n")).unwrap_err();
            assert!(e.to_string().contains("preview_domain"), "{bad}: {e}");
        }
        let max_label = format!("{}.example.com", "a".repeat(63));
        for good in [
            "p-1.example.com",
            "xn--bcher-kva.example",
            max_label.as_str(),
        ] {
            parse(&format!("[gateway]\npreview_domain = {good:?}\n")).unwrap();
        }
        let e = parse("[fork]\npreview_ttl = \"0s\"\n").unwrap_err();
        assert!(e.to_string().contains("preview_ttl"), "{e}");
    }

    #[test]
    fn unknown_keys_are_errors_with_their_line() {
        let e = parse("[server]\ndata_dir = \"/d\"\nhttp_lisen = \"0.0.0.0:80\"\n").unwrap_err();
        assert_eq!(e.line, Some(3), "{e}");
        assert!(e.message.contains("unknown field `http_lisen`"), "{e}");
        assert!(e.to_string().starts_with("kronik.toml:3: "), "{e}");
        let e = parse("\n[telemetry]\nenabled = true\n").unwrap_err();
        assert_eq!(e.line, Some(2), "{e}");
        assert!(e.message.contains("unknown field `telemetry`"), "{e}");
    }

    #[test]
    fn durations_sizes_and_percentages_need_units() {
        assert_eq!("30s".parse(), Ok(Dur::secs(30)));
        assert_eq!("500ms".parse(), Ok(Dur(Duration::from_millis(500))));
        assert_eq!("60m".parse(), Ok(Dur::secs(3600)));
        assert_eq!("7d".parse(), Ok(Dur::secs(604_800)));
        assert_eq!("64MiB".parse(), Ok(Size(64 << 20)));
        assert_eq!("1GiB".parse(), Ok(Size(1 << 30)));
        assert_eq!("10%".parse(), Ok(Percent(10.0)));
        for bad in ["30", "30 sec", "1.5h", "-1s", "s"] {
            assert!(bad.parse::<Dur>().is_err(), "{bad}");
        }
        for bad in ["64", "64MB", "1G", "GiB"] {
            assert!(bad.parse::<Size>().is_err(), "{bad}");
        }
        for bad in ["0%", "101%", "50", "x%"] {
            assert!(bad.parse::<Percent>().is_err(), "{bad}");
        }
        let e = parse("[gateway]\ntimeout = \"30\"\n").unwrap_err();
        assert_eq!(e.line, Some(2), "{e}");
        assert!(e.message.contains("the unit must be"), "{e}");
    }

    #[test]
    fn keys_that_need_each_other_are_checked() {
        let cases = [
            ("[tls]\nmode = \"acme\"\n", "needs domains"),
            (
                "[tls]\nmode = \"acme\"\ndomains = [\"a.example\"]\n",
                "needs acme_email",
            ),
            (
                "[tls]\nmode = \"files\"\ncert_file = \"/c.pem\"\n",
                "needs cert_file and key_file",
            ),
            ("[ship]\nenabled = true\n", "needs url"),
            (
                "[privacy]\nsubject_from = \"cookie:id\"\n",
                "\"header:<name>\" or \"jwt:sub\"",
            ),
            ("[tls]\nmode = \"ftp\"\n", "unknown variant `ftp`"),
            (
                "[gateway]\npreview_domain = \"p.example\"\n[tls]\ndns01_hook = \"/h\"\n",
                "dns01_hook needs mode = \"acme\"",
            ),
            (
                "[tls]\nmode = \"acme\"\ndomains = [\"a.example\"]\nacme_email = \"o@a.example\"\n\
                 dns01_hook = \"/h\"\n",
                "dns01_hook needs [gateway] preview_domain",
            ),
            (
                "[tls]\nmode = \"acme\"\ndomains = [\"a.example\"]\nacme_email = \"o@a.example\"\n\
                 dns01_hook = \"/h\"\n[gateway]\npreview_domain = \"../p\"\n",
                "use a lowercase domain",
            ),
            (
                "[server]\napi_listen = \"0.0.0.0:7443\"\n",
                "not a loopback address and [tls] is off",
            ),
        ];
        for (text, message) in cases {
            let e = parse(text).unwrap_err();
            assert!(e.message.contains(message), "{text}: {e}");
        }
        let local = parse("[server]\napi_listen = \"127.0.0.1:7443\"\n").unwrap();
        assert_eq!(
            local.api_listen(),
            Ok(Some("127.0.0.1:7443".parse().unwrap()))
        );
        let tls = parse(
            "[server]\napi_listen = \"0.0.0.0:7443\"\n[tls]\nmode = \"files\"\n\
             cert_file = \"/c.pem\"\nkey_file = \"/k.pem\"\n",
        )
        .unwrap();
        assert_eq!(tls.api_listen(), Ok(Some("0.0.0.0:7443".parse().unwrap())));
        assert_eq!(parse("").unwrap().api_listen(), Ok(None));
    }

    #[test]
    fn a_dns01_hook_adds_the_preview_wildcard_to_acme() {
        let acme =
            "[tls]\nmode = \"acme\"\ndomains = [\"a.example\"]\nacme_email = \"o@a.example\"\n";
        let wildcard = |text: &str| match parse(text).unwrap().certificates() {
            Some(kronik_gateway::tls::Certificates::Acme(acme)) => acme.wildcard,
            other => panic!("{other:?}"),
        };
        assert!(wildcard(acme).is_none());
        let w = wildcard(&format!(
            "{acme}dns01_hook = \"/usr/local/bin/kronik-dns01\"\ndns01_propagation = \"0s\"\n\
             [gateway]\npreview_domain = \"preview.a.example\"\n"
        ))
        .unwrap();
        assert_eq!(w.domain, "preview.a.example");
        assert_eq!(w.propagation, Duration::ZERO);
        assert!(format!("{:?}", w.dns01).contains("/usr/local/bin/kronik-dns01"));
    }

    /// P-F5, P-F6: previews need a name of their own that can get a
    /// certificate; prefix URLs name the gateway's public host.
    #[test]
    fn previews_get_valid_urls_or_the_configuration_is_refused() {
        let acme = "[tls]\nmode = \"acme\"\ndomains = [\"www.app.example\"]\n\
                    acme_email = \"o@app.example\"\n";
        let e = parse(&format!(
            "{acme}[gateway]\npreview_domain = \"example-preview.net\"\n"
        ))
        .unwrap_err();
        assert!(e.message.contains("needs [tls] dns01_hook"), "{e}");
        for covering in ["app.example", "www.app.example"] {
            let e = parse(&format!(
                "{acme}dns01_hook = \"/h\"\n[gateway]\npreview_domain = {covering:?}\n"
            ))
            .unwrap_err();
            assert!(e.message.contains("covers the gateway's own name"), "{e}");
        }
        // Files mode: the operator's certificate covers *.<domain>; no TLS:
        // plain HTTP.
        let files = "[tls]\nmode = \"files\"\ncert_file = \"/c.pem\"\nkey_file = \"/k.pem\"\n";
        parse(&format!(
            "{files}[gateway]\npreview_domain = \"p.example\"\n"
        ))
        .unwrap();
        parse("[gateway]\npreview_domain = \"p.example\"\n").unwrap();

        let at = |s: &str| s.parse::<SocketAddr>().unwrap();
        let off = parse("").unwrap();
        assert_eq!(off.public_host(at("127.0.0.1:8080")), "127.0.0.1:8080");
        assert_eq!(off.public_host(at("0.0.0.0:80")), "127.0.0.1");
        assert_eq!(off.public_host(at("[::]:8080")), "[::1]:8080");
        let files = parse(files).unwrap();
        assert_eq!(files.public_host(at("0.0.0.0:443")), "127.0.0.1");
        assert_eq!(files.public_host(at("0.0.0.0:8443")), "127.0.0.1:8443");
        let acme = parse(&format!(
            "{acme}dns01_hook = \"/h\"\n[gateway]\npreview_domain = \"p.example\"\n"
        ))
        .unwrap();
        assert_eq!(acme.public_host(at("0.0.0.0:443")), "www.app.example");
        assert_eq!(acme.public_host(at("0.0.0.0:8443")), "www.app.example:8443");
    }

    /// `[audit]` (m28-otel §6.1): the sink's scheme, plain HTTP only to
    /// loopback, a bucket, and `endpoint` only with `s3://`.
    #[test]
    fn audit_sinks_are_checked() {
        let c = parse(
            "[audit]\nsink = \"s3://b/kronik\"\nendpoint = \"http://127.0.0.1:3900\"\n\
             hold_release = \"1GiB\"\nfrom = \"now\"\nmax_hold = \"7d\"\n",
        )
        .unwrap();
        assert_eq!(c.audit.hold_release_bytes(512), 1 << 30);
        assert_eq!(c.audit.from, AuditFrom::Now);
        let d = parse("").unwrap();
        assert_eq!(d.audit.hold_release_bytes(512 << 20), 1 << 30);
        assert_eq!(d.audit.sink(), None);
        parse("[audit]\nsink = \"file:///var/log/kronik/audit/\"\n").unwrap();
        parse("[audit]\nsink = \"http://127.0.0.1:9000/hook\"\n").unwrap();
        for (text, message) in [
            ("[audit]\nsink = \"ftp://x/\"\n", "use file:///dir/"),
            (
                "[audit]\nsink = \"http://hooks.example.com/x\"\n",
                "loopback",
            ),
            ("[audit]\nsink = \"s3:///x\"\n", "no bucket"),
            (
                "[audit]\nsink = \"https://h/\"\nendpoint = \"http://127.0.0.1:3900\"\n",
                "s3:// sink only",
            ),
            ("[audit]\nhold_release = \"2y\"\n", "invalid size"),
            ("[audit]\nfrom = \"later\"\n", "unknown variant"),
        ] {
            let e = parse(text).unwrap_err();
            assert!(e.message.contains(message), "{text}: {e}");
        }
    }

    /// Perf review R3: an audit sink's hold must be able to give way:
    /// `hold_release` above `[log] disk_reserve`, or `max_hold` set; also
    /// when a flag sets the reserve.
    #[test]
    fn an_audit_hold_that_can_never_give_way_is_refused() {
        let sink = "[audit]\nsink = \"file:///var/log/kronik/audit/\"\n";
        for (extra, ok) in [
            ("[log]\ndisk_reserve = \"0B\"\n", false),
            ("hold_release = \"1x\"\n", false),
            ("hold_release = \"512MiB\"\n", false),
            ("hold_release = \"1GiB\"\n", true),
            (
                "hold_release = \"1GiB\"\n[log]\ndisk_reserve = \"0B\"\n",
                true,
            ),
            ("hold_release = \"1x\"\nmax_hold = \"1d\"\n", true),
        ] {
            let r = parse(&format!("{sink}{extra}"));
            match ok {
                true => assert!(r.is_ok(), "{extra}: {r:?}"),
                false => {
                    let e = r.unwrap_err();
                    assert!(e.message.contains("hold_release"), "{extra}: {e}");
                }
            }
        }
        // Without a sink nothing is held.
        parse("[log]\ndisk_reserve = \"0B\"\n").unwrap();
        // `--disk-reserve 0B` (or KRONIK_DISK_RESERVE) with the default 2x.
        let c = parse(sink).unwrap().with(Overrides {
            disk_reserve: Some(Size(0)),
            ..Overrides::default()
        });
        assert!(c.check_audit_hold().unwrap_err().contains("hold_release"));
    }

    #[test]
    fn otel_endpoints_are_checked() {
        let empty = parse("").unwrap();
        assert_eq!(empty.otel.endpoint(), None);
        assert_eq!(empty.otel.actor_keys, ActorKeys::Hashed);
        assert_eq!(empty.otel.batch_spans, 512);
        let c = parse(
            "[otel]\nendpoint = \"http://127.0.0.1:4318/\"\nactor_keys = \"none\"\n\
             headers_env = \"KRONIK_OTEL_HEADERS\"\n",
        )
        .unwrap();
        assert_eq!(c.otel.endpoint(), Some("http://127.0.0.1:4318"));
        assert_eq!(c.otel.actor_keys, ActorKeys::Omit);
        parse("[otel]\nendpoint = \"https://otlp.example.com\"\nheaders_env = \"H\"\n").unwrap();
        parse("[otel]\nendpoint = \"http://collector:4318\"\n").unwrap();
        for (text, message) in [
            (
                "[otel]\nendpoint = \"grpc://c:4317\"\n",
                "use http://host:port",
            ),
            ("[otel]\nendpoint = \"http://\"\n", "use http://host:port"),
            (
                "[otel]\nendpoint = \"http://collector:4318\"\nheaders_env = \"H\"\n",
                "not loopback",
            ),
            ("[otel]\nbatch_spans = 0\n", "at least 1"),
            (
                "[otel]\nactor_keys = \"clear\"\n",
                "unknown variant `clear`",
            ),
        ] {
            let e = parse(text).unwrap_err();
            assert!(e.message.contains(message), "{text}: {e}");
        }
        // A rejected endpoint is shown as scheme and host only (review M9).
        for text in [
            "[otel]\nendpoint = \"grpc://u:NEEDLE@c:4317/NEEDLE?t=NEEDLE\"\n",
            "[otel]\nendpoint = \"http://u:NEEDLE@collector:4318/NEEDLE?t=NEEDLE\"\n\
             headers_env = \"H\"\n",
        ] {
            let e = parse(text).unwrap_err();
            assert!(!e.to_string().contains("NEEDLE"), "{text}: {e}");
            assert!(e.message.contains("://c"), "{e}");
        }
    }
}
