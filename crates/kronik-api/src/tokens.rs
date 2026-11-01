//! API tokens (M5): `kronik token create|list|revoke` and the bearer
//! [`Authenticator`].
//!
//! A token is `kronik_` followed by 43 base64url characters (32 random
//! bytes). It is shown once, when it is created. `keys/tokens.db` keeps its
//! BLAKE3 hash, never the token, with the token's name, its scopes, and who
//! created or revoked it with which reason. A caller holding a token is
//! recorded as `token:<name>` in `Audit.token_id`; names are never reused,
//! so that id stays unambiguous in the log.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::sync::atomic::{AtomicBool, Ordering};

use base64::Engine as _;
use kronik_core::error::{ApiError, ErrorCode};
use rusqlite::{Connection, OptionalExtension as _, params};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::ApiRequest;
use crate::auth::{Authenticator, Caller, Scope};

mod metadata;
mod native_fleet;
pub use metadata::{ExpectedRevision, ForwardedPrincipal, MetadataSource, MetadataToken, OidcSessionProof, PreparedMetadata};
use metadata::MetadataState;

/// What every token starts with, so that secret scanners can find one.
pub const PREFIX: &str = "kronik_";

/// The scopes of a token created without `scopes` (brief: agents get
/// `read`, `fork` and `propose` by default).
pub const DEFAULT_SCOPES: [Scope; 3] = [Scope::Read, Scope::Fork, Scope::Propose];

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS tokens (
  name TEXT PRIMARY KEY,
  hash BLOB NOT NULL UNIQUE,
  scopes TEXT NOT NULL,
  created_wall_ms INTEGER NOT NULL, created_by TEXT NOT NULL, reason TEXT NOT NULL,
  revoked_wall_ms INTEGER, revoked_by TEXT, revoke_reason TEXT,
  fleet_epoch TEXT, fleet_request_id TEXT
) WITHOUT ROWID;
";

/// A token as stored, without its hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenMeta {
    pub name: String,
    pub scopes: BTreeSet<Scope>,
    pub created_wall_ms: u64,
    pub created_by: String,
    pub reason: String,
    pub revoked: Option<Revocation>,
    pub fleet: Option<FleetToken>,
}

/// Immutable service-issued provenance, never inferred from an operator's name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetToken {
    pub epoch: u64,
    pub request_id: String,
}

impl TokenMeta {
    /// The caller id recorded for this token: `token:<name>`.
    pub fn token_id(&self) -> String {
        token_id(&self.name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    pub wall_ms: u64,
    pub by: String,
    pub reason: String,
}

/// Who did something to a token, and why (`Audit` without the clock).
pub struct Change<'a> {
    pub wall_ms: u64,
    pub by: &'a str,
    pub reason: &'a str,
}

/// `keys/tokens.db`, with the live tokens' hashes in memory.
pub struct TokenStore {
    inner: Option<Mutex<Inner>>,
    /// One fence for token, session, fleet and durable metadata publication.
    publication: Arc<Mutex<()>>,
    live: Mutex<Live>,
    managed: Mutex<HashMap<String, Arc<FleetToken>>>,
    changed: Arc<tokio::sync::Notify>,
    metadata: Mutex<MetadataState>,
    issuer_started: AtomicBool,
    domain_bound: bool,
    execution: OnceLock<kronik_core::authority::AuthLease>,
}

struct Inner {
    conn: Connection,
}

type Live = HashMap<[u8; 32], (String, BTreeSet<Scope>)>;


pub(crate) fn token_id(name: &str) -> String {
    format!("token:{name}")
}

fn hash(token: &str) -> [u8; 32] {
    *blake3::hash(token.as_bytes()).as_bytes()
}

fn new_secret(random: [u8; 32]) -> Zeroizing<String> {
    Zeroizing::new(format!("{PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random)))
}

fn metadata_unavailable() -> ApiError {
    ApiError::new(ErrorCode::Unavailable, "committed metadata token projection unavailable")
}



/// Token names: a lowercase letter, then up to 62 lowercase letters, digits
/// and dashes.
pub fn valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && name.len() <= 63
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `read,fork` -> the scopes, in canonical order.
pub fn parse_scopes<S: AsRef<str>>(list: &[S]) -> Result<BTreeSet<Scope>, ApiError> {
    let mut scopes = BTreeSet::new();
    for s in list {
        let s = s.as_ref().trim();
        let scope = Scope::parse(s).ok_or_else(|| {
            let known: Vec<&str> = Scope::ALL.iter().map(|x| x.as_str()).collect();
            ApiError::new(
                ErrorCode::BadRequest,
                format!("unknown scope {s:?}; the scopes are {}", known.join(", ")),
            )
        })?;
        scopes.insert(scope);
    }
    if scopes.is_empty() {
        return Err(ApiError::new(
            ErrorCode::BadRequest,
            "a token needs at least one scope",
        ));
    }
    Ok(scopes)
}

fn scopes_text(scopes: &BTreeSet<Scope>) -> String {
    let names: Vec<&str> = scopes.iter().map(|s| s.as_str()).collect();
    names.join(",")
}

fn scopes_from_text(text: &str) -> Result<BTreeSet<Scope>, rusqlite::Error> {
    text.split(',')
        .map(|s| {
            Scope::parse(s).ok_or_else(|| {
                rusqlite::Error::InvalidColumnType(
                    0,
                    format!("unknown scope {s:?}"),
                    rusqlite::types::Type::Text,
                )
            })
        })
        .collect()
}

const MANAGED_SCOPES_VERSION: u32 = 1;
const MAX_MANAGED_SCOPES_BYTES: usize = 4096;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedScopes {
    version: u32,
    scopes: String,
    fleet: FleetToken,
}

#[derive(Serialize)]
struct ManagedScopesRef<'a> {
    version: u32,
    scopes: &'a str,
    fleet: &'a FleetToken,
}

fn stored_scopes(row: &rusqlite::Row<'_>, index: usize, fleet: Option<&FleetToken>) -> rusqlite::Result<BTreeSet<Scope>> {
    use rusqlite::types::{Type, ValueRef};
    let invalid = || rusqlite::Error::InvalidColumnType(index, "managed token scopes format".into(), Type::Blob);
    match (row.get_ref(index)?, fleet) {
        (ValueRef::Text(_), None) => scopes_from_text(&row.get::<_, String>(index)?),
        (ValueRef::Blob(bytes), Some(fleet)) if bytes.len() <= MAX_MANAGED_SCOPES_BYTES => {
            let payload: ManagedScopes = serde_json::from_slice(bytes).map_err(|_| invalid())?;
            if payload.version != MANAGED_SCOPES_VERSION || &payload.fleet != fleet { return Err(invalid()); }
            let scopes = scopes_from_text(&payload.scopes).map_err(|_| invalid())?;
            if scopes.is_empty() || scopes_text(&scopes) != payload.scopes { return Err(invalid()); }
            Ok(scopes)
        }
        _ => Err(invalid()),
    }
}

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::new(ErrorCode::Internal, format!("token store: {e}"))
}

fn not_found(name: &str) -> ApiError {
    ApiError::new(ErrorCode::TokenNotFound, format!("no token {name:?}"))
}

fn fleet_meta(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Option<FleetToken>> {
    let epoch: Option<String> = row.get(index)?;
    let request: Option<String> = row.get(index + 1)?;
    match (epoch, request) {
        (None, None) => Ok(None),
        (Some(epoch), Some(request_id)) => {
            let parsed = epoch.parse::<u64>().ok().filter(|v| *v > 0);
            if let Some(epoch) = parsed
                && request_id.len() == 64
                && request_id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
                return Ok(Some(FleetToken { epoch, request_id }));
            }
            Err(rusqlite::Error::InvalidColumnType(index, "fleet provenance".into(), rusqlite::types::Type::Text))
        }
        _ => Err(rusqlite::Error::InvalidColumnType(index, "fleet provenance".into(), rusqlite::types::Type::Text)),
    }
}

fn meta(row: &rusqlite::Row<'_>) -> rusqlite::Result<TokenMeta> {
    let revoked_wall_ms: Option<i64> = row.get(5)?;
    let revoked = match revoked_wall_ms {
        Some(ms) => Some(Revocation {
            wall_ms: ms as u64,
            by: row.get::<_, Option<String>>(6)?.unwrap_or_default(),
            reason: row.get::<_, Option<String>>(7)?.unwrap_or_default(),
        }),
        None => None,
    };
    let fleet = fleet_meta(row, 8)?;
    Ok(TokenMeta {
        name: row.get(0)?,
        scopes: stored_scopes(row, 1, fleet.as_ref())?,
        created_wall_ms: row.get::<_, i64>(2)? as u64,
        created_by: row.get(3)?,
        reason: row.get(4)?,
        revoked,
        fleet,
    })
}

const COLUMNS: &str = "name, scopes, created_wall_ms, created_by, reason, \
    revoked_wall_ms, revoked_by, revoke_reason, fleet_epoch, fleet_request_id";

impl TokenStore {
    /// Opens `path`, creating it with mode 0600 (and its directory) when
    /// missing, and giving it, its `-wal` and its `-shm` mode 0600 when not.
    pub fn open_file(path: &Path) -> Result<TokenStore, String> {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
        }
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("creating {}: {e}", path.display()))?;
        for suffix in ["", "-wal", "-shm"] {
            let mut file = path.as_os_str().to_owned();
            file.push(suffix);
            let file = Path::new(&file);
            if file.exists() {
                std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600))
                    .map_err(|e| format!("setting the mode of {}: {e}", file.display()))?;
            }
        }
        let conn =
            Connection::open(path).map_err(|e| format!("opening {}: {e}", path.display()))?;
        TokenStore::open(conn).map_err(|e| format!("reading {}: {e}", path.display()))
    }

    pub fn open(conn: Connection) -> Result<TokenStore, rusqlite::Error> {
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;")?;
        conn.execute_batch(SCHEMA)?;
        for column in ["fleet_epoch", "fleet_request_id"] {
            let present: bool = conn.query_row("SELECT count(*) > 0 FROM pragma_table_info('tokens') WHERE name = ?1", [column], |r| r.get(0))?;
            if !present {
                conn.execute_batch(&format!("ALTER TABLE tokens ADD COLUMN {column} TEXT"))?;
            }
        }
        let (live, managed) = {
            let mut statement = conn.prepare("SELECT hash,name,scopes,fleet_epoch,fleet_request_id,revoked_wall_ms FROM tokens")?;
            let mut rows = statement.query([])?;
            let (mut live, mut managed) = (HashMap::new(), HashMap::new());
            while let Some(row) = rows.next()? {
                let name: String = row.get(1)?;
                let fleet = fleet_meta(row, 3)?;
                let scopes = stored_scopes(row, 2, fleet.as_ref())?;
                if let Some(fleet) = fleet { managed.insert(name.clone(), Arc::new(fleet)); }
                if row.get::<_, Option<i64>>(5)?.is_none() {
                    let hash: Vec<u8> = row.get(0)?;
                    let hash: [u8; 32] = hash.try_into().map_err(|_| rusqlite::Error::InvalidColumnType(0, "hash".into(), rusqlite::types::Type::Blob))?;
                    live.insert(hash, (name, scopes));
                }
            }
            (live, managed)
        };
        Ok(TokenStore {
            inner: Some(Mutex::new(Inner { conn })),
            publication: Arc::new(Mutex::new(())),
            live: Mutex::new(live),
            managed: Mutex::new(managed),
            changed: Arc::new(tokio::sync::Notify::new()),
            metadata: Mutex::new(MetadataState::Native),
            issuer_started: AtomicBool::new(false),
            domain_bound: false,
            execution: OnceLock::new(),
        })
    }

    /// A member authenticates only from its committed metadata projection.
    /// No native database is opened or inspected, including during startup.
    pub fn for_member(domain: Arc<Mutex<()>>) -> TokenStore {
        TokenStore {
            inner: None, publication: domain, live: Mutex::new(HashMap::new()),
            managed: Mutex::new(HashMap::new()), changed: Arc::new(tokio::sync::Notify::new()),
            metadata: Mutex::new(MetadataState::Pending), issuer_started: AtomicBool::new(false),
            domain_bound: true,
            execution: OnceLock::new(),
        }
    }

    /// Install the physical node's domain before constructing any principal lease.
    pub fn bind_before_any_issuer(&mut self, domain: Arc<Mutex<()>>) -> Result<(), ApiError> {
        if self.domain_bound || *self.issuer_started.get_mut() {
            return Err(internal("authentication publication domain is already in use"));
        }
        self.publication = domain;
        self.domain_bound = true;
        Ok(())
    }

    /// Bind the genuine physical lifecycle before issuing any principal capability.
    /// Repeated builders retain the original capability; they never renew it.
    pub fn bind_execution_before_any_issuer(
        &self, domain: &Arc<Mutex<()>>, origin: kronik_core::authority::AuthLease,
    ) -> Result<(), ApiError> {
        if !self.domain_bound {
            return Err(ApiError::new(
                ErrorCode::Unavailable,
                "authentication has no bound physical publication domain",
            ));
        }
        if !Arc::ptr_eq(domain, &self.publication) {
            return Err(internal("authentication and execution require the same physical publication domain"));
        }
        let _publication = self.publication();
        if let Some(original) = self.execution.get() {
            return original.check();
        }
        if self.issuer_started.load(Ordering::Acquire) {
            return Err(internal("physical execution authority must be bound before authentication issuers"));
        }
        origin.check()?;
        self.execution.set(origin).map_err(|_| internal("physical execution authority is already bound"))
    }

    pub(crate) fn execution(&self) -> Result<&kronik_core::authority::AuthLease, ApiError> {
        self.execution.get().ok_or_else(||
            ApiError::new(ErrorCode::Unavailable, "authentication has no bound physical execution authority"))
    }

    /// The caller holds the common publisher; lifecycle checks never acquire it.
    fn capture_execution(&self) -> Result<kronik_core::authority::AuthLease, ApiError> {
        let execution = self.execution()?;
        execution.check()?;
        self.issuer_started.store(true, Ordering::Release);
        Ok(execution.clone())
    }

    fn inner(&self) -> Result<MutexGuard<'_, Inner>, ApiError> {
        let inner = self.inner.as_ref().ok_or_else(metadata_unavailable)?;
        Ok(inner.lock().unwrap_or_else(|e| e.into_inner()))
    }

    fn live(&self) -> MutexGuard<'_, Live> {
        self.live.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn publication(&self) -> MutexGuard<'_, ()> {
        self.publication.lock().unwrap_or_else(|error| error.into_inner())
    }

    /// Publish already-durable revocation/configuration, or a conservative early
    /// denial. All issuers use this fence; the callback must not wait or do I/O.
    /// Lock order: publication, then bounded live/session/fleet data, then enqueue.
    /// Token storage mutations keep their database lock through publication,
    /// but admission never takes that lock: no I/O runs under this fence.
    pub fn publish_auth_change(&self, change: &mut dyn FnMut() -> Result<(), ApiError>) -> Result<(), ApiError> {
        let _publication = self.publication();
        change()?;
        self.notify_auth_change();
        Ok(())
    }

    /// Managed provenance, including revoked names, without SQLite I/O.
    pub fn fleet_token(&self, token_id: &str) -> Option<Arc<FleetToken>> {
        let name = token_id.strip_prefix("token:")?;
        let state = self.metadata();
        match &*state {
            MetadataState::Ready(source) => { source.tokens.get(name)?.meta.fleet.as_ref()?; }
            MetadataState::Native => {}
            _ => return None,
        }
        self.managed.lock().unwrap_or_else(|e| e.into_inner()).get(name).cloned()
    }

    /// Creates the token `name` from 32 bytes of fresh randomness and
    /// returns it with the token itself, which is never stored. A dry run
    /// checks the request and returns no token.
    pub fn create(
        &self,
        name: &str,
        scopes: BTreeSet<Scope>,
        random: [u8; 32],
        change: &Change<'_>,
        dry_run: bool,
    ) -> Result<(TokenMeta, Option<String>), ApiError> {
        self.create_with_fleet(name, scopes, random, change, dry_run, None)
    }


    pub(crate) fn create_with_fleet(
        &self,
        name: &str,
        scopes: BTreeSet<Scope>,
        random: [u8; 32],
        change: &Change<'_>,
        dry_run: bool,
        fleet: Option<FleetToken>,
    ) -> Result<(TokenMeta, Option<String>), ApiError> {
        if self.metadata_revision()?.is_some() { return Err(metadata_unavailable()); }
        let meta = self.preview_create(name, scopes, change, fleet)?;
        if dry_run { return Ok((meta, None)); }
        let secret = new_secret(random);
        let digest = hash(&secret);
        self.insert_prepared(meta, secret, digest)
    }

    fn preview_create(&self, name: &str, scopes: BTreeSet<Scope>, change: &Change<'_>, fleet: Option<FleetToken>) -> Result<TokenMeta, ApiError> {
        if scopes.is_empty() || fleet.as_ref().is_some_and(|fleet| fleet.epoch == 0 || fleet.request_id.len() != 64
            || !fleet.request_id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())) {
            return Err(ApiError::new(ErrorCode::BadRequest, "invalid token scopes or fleet provenance"));
        }
        if !valid_name(name) {
            return Err(ApiError::new(ErrorCode::BadRequest,
                "token names are a lowercase letter, then up to 62 lowercase letters, digits and dashes"));
        }
        if self.lookup(name)?.is_some() {
            return Err(ApiError::new(ErrorCode::BadRequest,
                format!("a token named {name:?} exists or existed; names are never reused"))
                .with_hint("Choose another name. `kronik token list` shows the names in use."));
        }
        Ok(TokenMeta {
            name: name.to_owned(), scopes, created_wall_ms: change.wall_ms,
            created_by: change.by.to_owned(), reason: change.reason.to_owned(),
            revoked: None, fleet,
        })
    }

    fn insert_prepared(&self, meta: TokenMeta, mut secret: Zeroizing<String>, digest: [u8; 32]) -> Result<(TokenMeta, Option<String>), ApiError> {
        if self.metadata_revision()?.is_some() { return Err(metadata_unavailable()); }
        let inner = self.inner()?;
        let name = meta.name.as_str();
        let scopes = scopes_text(&meta.scopes);
        // Old readers require TEXT and fail before loading any managed bearer.
        let stored = if let Some(fleet) = &meta.fleet {
            let payload = serde_json::to_vec(&ManagedScopesRef { version: MANAGED_SCOPES_VERSION, scopes: &scopes, fleet }).map_err(internal)?;
            if payload.len() > MAX_MANAGED_SCOPES_BYTES { return Err(internal("managed scopes payload exceeds its bound")); }
            rusqlite::types::Value::Blob(payload)
        } else {
            rusqlite::types::Value::Text(scopes)
        };
        inner.conn.execute(
            "INSERT INTO tokens (name, hash, scopes, created_wall_ms, created_by, reason, fleet_epoch, fleet_request_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![name, digest.as_slice(), stored, meta.created_wall_ms as i64,
                &meta.created_by, &meta.reason,
                meta.fleet.as_ref().map(|fleet| fleet.epoch.to_string()),
                meta.fleet.as_ref().map(|fleet| fleet.request_id.as_str())],
        ).map_err(internal)?;
        let mut managed = meta.fleet.as_ref().map(|fleet| (name.to_owned(), Arc::new(fleet.clone())));
        self.publish_auth_change(&mut || {
            if let Some((name, fleet)) = managed.take() {
                self.managed.lock().unwrap_or_else(|e| e.into_inner()).insert(name, fleet);
            }
            self.live().insert(digest, (name.to_owned(), meta.scopes.clone()));
            Ok(())
        })?;
        drop(inner);
        Ok((meta, Some(std::mem::take(&mut *secret))))
    }

    /// Every token, live and revoked, by name.
    pub fn list(&self) -> Result<Vec<TokenMeta>, ApiError> {
        match &*self.metadata() {
            MetadataState::Ready(source) => return Ok(source.tokens.values().map(|row| row.meta.clone()).collect()),
            MetadataState::Native => {}
            _ => return Err(metadata::unavailable()),
        }
        let inner = self.inner()?;
        let mut stmt = inner
            .conn
            .prepare(&format!("SELECT {COLUMNS} FROM tokens ORDER BY name"))
            .map_err(internal)?;
        let rows = stmt.query_map([], meta).map_err(internal)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(internal)
    }

    /// Revokes `name`: from now on it authenticates nobody. The record is
    /// kept, so that the name is not reused.
    pub fn revoke(
        &self,
        name: &str,
        change: &Change<'_>,
        dry_run: bool,
    ) -> Result<TokenMeta, ApiError> {
        if self.metadata_revision()?.is_some() {
            return Err(internal("member token revocation requires the metadata producer"));
        }
        let inner = self.inner()?;
        let mut token = inner
            .conn
            .query_row(
                &format!("SELECT {COLUMNS} FROM tokens WHERE name = ?1"),
                [name],
                meta,
            )
            .optional()
            .map_err(internal)?
            .ok_or_else(|| not_found(name))?;
        if token.revoked.is_some() {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                format!("token {name:?} is already revoked"),
            )
            .with_hint("`kronik token list` shows which tokens are live."));
        }
        token.revoked = Some(Revocation {
            wall_ms: change.wall_ms,
            by: change.by.to_owned(),
            reason: change.reason.to_owned(),
        });
        if dry_run {
            return Ok(token);
        }
        inner
            .conn
            .execute(
                "UPDATE tokens SET revoked_wall_ms = ?2, revoked_by = ?3, revoke_reason = ?4 \
                 WHERE name = ?1",
                params![name, change.wall_ms as i64, change.by, change.reason],
            )
            .map_err(internal)?;
        self.publish_auth_change(&mut || {
            self.live().retain(|_, (live, _)| live != name);
            Ok(())
        })?;
        drop(inner);
        Ok(token)
    }

    /// The caller a token stands for, if it is live.
    pub fn caller(&self, token: &str) -> Option<Caller> {
        let state = self.metadata();
        let live = self.live();
        let (name, scopes) = live.get(&hash(token))?;
        match &*state {
            MetadataState::Ready(source) => {
                let row = source.tokens.get(name)?;
                if row.meta.revoked.is_some() || source.require_fleet(row).is_err() { return None; }
            }
            MetadataState::Native => {}
            _ => return None,
        }
        Some(Caller {
            token_id: token_id(name),
            scopes: scopes.clone(),
        })
    }

    /// A trusted OIDC mapping names a live token; it never supplies scopes.
    pub fn caller_for_name(&self, name: &str) -> Option<Caller> {
        let state = self.metadata();
        match &*state {
            MetadataState::Ready(source) => {
                let row = source.tokens.get(name)?;
                if row.meta.revoked.is_some() || source.require_fleet(row).is_err() { return None; }
                return Some(Caller { token_id: row.meta.token_id(), scopes: row.meta.scopes.clone() });
            }
            MetadataState::Native => {}
            _ => return None,
        }
        let live = self.live();
        let (_, scopes) = live.values().find(|(live, _)| live == name)?;
        Some(Caller { token_id: token_id(name), scopes: scopes.clone() })
    }

    /// Read-only admission evidence from the ordinary live-token projection.
    pub(crate) fn fleet_receipt_is_live(&self, epoch: u64, request_id: &str, scopes: &[String], token_name: Option<&str>) -> bool {
        let state = self.metadata();
        match &*state {
            MetadataState::Ready(source) if source.current_fleet_receipt(epoch, request_id).is_ok_and(|state|
                state.phase == kronik_proto::log::v1::fleet_state::Phase::Active as i32) => {}
            MetadataState::Native => {}
            _ => return false,
        }
        let live = self.live();
        let managed = self.managed.lock().unwrap_or_else(|e| e.into_inner());
        live.values().any(|(name, current_scopes)| token_name.is_none_or(|expected| name == expected)
            && current_scopes.len() == scopes.len()
            && current_scopes.iter().zip(scopes).all(|(scope, expected)| scope.as_str() == expected)
            && managed.get(name).is_some_and(|receipt| receipt.epoch == epoch && receipt.request_id == request_id))
    }

    /// Custody validation is not authentication: Requested credentials must
    /// remain recoverable without granting any ordinary API authority.
    pub(crate) fn fleet_credential_matches(&self, secret: &str, epoch: u64, request_id: &str, scopes: &BTreeSet<Scope>) -> bool {
        let state = self.metadata();
        let live = self.live();
        let Some((name, current_scopes)) = live.get(&hash(secret)) else { return false; };
        if current_scopes != scopes { return false; }
        let matches = |fleet: &FleetToken| fleet.epoch == epoch && fleet.request_id == request_id;
        match &*state {
            MetadataState::Ready(source) => source.current_fleet_receipt(epoch, request_id).is_ok_and(|state|
                state.phase != kronik_proto::log::v1::fleet_state::Phase::Revoked as i32)
                && source.tokens.get(name).is_some_and(|row| row.meta.revoked.is_none()
                    && row.meta.scopes == *scopes && row.meta.fleet.as_ref().is_some_and(matches)),
            MetadataState::Native => self.managed.lock().unwrap_or_else(|e| e.into_inner()).get(name).is_some_and(|fleet| matches(fleet)),
            _ => false,
        }
    }

    /// A trusted OIDC binding names an ordinary token; names are never reused.
    pub fn authority_for_name(self: &Arc<Self>, name: &str, required: Scope) -> Result<kronik_core::authority::AuthLease, ApiError> {
        self.authority(TokenIdentity::Name(name.to_owned()), required)
    }

    pub fn authority_for_token(self: &Arc<Self>, token: &str, required: Scope) -> Result<kronik_core::authority::AuthLease, ApiError> {
        self.authority(TokenIdentity::Hash(hash(token)), required)
    }


    fn authority(self: &Arc<Self>, identity: TokenIdentity, required: Scope) -> Result<kronik_core::authority::AuthLease, ApiError> {
        let _publication = self.publication();
        let execution = self.capture_execution()?;
        let expected = match &*self.metadata() {
            MetadataState::Native => None,
            MetadataState::Ready(source) => {
                let live = self.live();
                let name = match &identity {
                    TokenIdentity::Hash(hash) => live.get(hash).map(|row| row.0.as_str()),
                    TokenIdentity::Name(name) => Some(name.as_str()),
                    TokenIdentity::Local => None,
                };
                let row = name.and_then(|name| source.tokens.get(name));
                Some(source.expected(row))
            }
            _ => return Err(metadata::unavailable()),
        };
        let lease = TokenAuthority { store: self.clone(), execution, identity, required, expected, peer: None };
        lease.current()?;
        Ok(Arc::new(lease))
    }

    /// Register a notification before inspecting sticky live authentication state.
    pub fn changes(&self) -> Arc<tokio::sync::Notify> {
        self.changed.clone()
    }

    /// Session logout shares the same live-authentication wakeup.
    pub(crate) fn notify_auth_change(&self) {
        self.changed.notify_waiters();
    }
}

#[derive(Clone)]
enum TokenIdentity {
    Hash([u8; 32]),
    Name(String),
    Local,
}

#[derive(Clone)]
struct TokenAuthority {
    store: Arc<TokenStore>,
    execution: kronik_core::authority::AuthLease,
    identity: TokenIdentity,
    required: Scope,
    expected: Option<ExpectedRevision>,
    peer: Option<kronik_core::authority::AuthLease>,
}

impl TokenAuthority {
    fn current(&self) -> Result<(), ApiError> {
        self.execution.check()?;
        if let Some(peer) = &self.peer { peer.check()?; }
        let metadata = self.store.metadata();
        let live = self.store.live();
        let token = match &self.identity {
            TokenIdentity::Hash(hash) => live.get(hash),
            TokenIdentity::Name(name) => live.values().find(|(live, _)| live == name),
            TokenIdentity::Local => None,
        };
        match (&*metadata, self.expected) {
            (MetadataState::Native, None) => {}
            (MetadataState::Ready(source), Some(expected)) => {
                let row = token.and_then(|(name, _)| source.tokens.get(name));
                if !source.matches(expected, row) {
                    return Err(unauthenticated("the operation's original authority changed"));
                }
                if let Some(row) = row { source.require_fleet(row)?; }
            }
            _ => return Err(metadata::unavailable()),
        }
        if matches!(self.identity, TokenIdentity::Local) { return Ok(()); }
        let token = token.ok_or_else(|| unauthenticated("the operation's token is revoked"))?;
        if token.1.contains(&self.required) || token.1.contains(&Scope::Admin) {
            Ok(())
        } else {
            Err(ApiError::new(ErrorCode::ScopeMissing, "the operation's live token lacks its required scope"))
        }
    }
}

impl kronik_core::authority::Authority for TokenAuthority {
    fn check(&self) -> Result<(), ApiError> {
        self.current()
    }

    fn cancelled(&self) -> kronik_core::env::BoxFuture<'static, ()> {
        let lease = self.clone();
        Box::pin(async move {
            let changed = lease.store.changes();
            loop {
                let notified = changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if kronik_core::authority::Authority::check(&lease).is_err() { return; }
                let execution = lease.execution.cancelled();
                let peer = async {
                    match &lease.peer { Some(peer) => peer.cancelled().await, None => std::future::pending::<()>().await }
                };
                tokio::select! { () = execution => return, () = peer => return, () = notified => {} }
            }
        })
    }

    fn admit(&self, effect: &mut dyn FnMut() -> Result<(), ApiError>) -> Result<(), ApiError> {
        let _publication = self.store.publication();
        self.current()?;
        effect()
    }
}

fn unauthenticated(message: &str) -> ApiError {
    ApiError::new(ErrorCode::Unauthenticated, message).with_hint(
        "Send a live token as `Authorization: Bearer <token>` (KRONIK_TOKEN for the CLI). \
         `kronik token list` shows the tokens and `kronik token create` makes one.",
    )
}

/// Bearer tokens from [`TokenStore`]. A request with a token is that
/// token's caller, on any listener; without one, the Unix socket's caller
/// has every scope (file permissions decide who connects), and any other
/// listener refuses it.
pub struct TokenAuthenticator {
    store: Arc<TokenStore>,
}

impl TokenAuthenticator {
    pub fn new(store: Arc<TokenStore>) -> TokenAuthenticator {
        TokenAuthenticator { store }
    }
}

impl Authenticator for TokenAuthenticator {
    fn caller(&self, req: &ApiRequest) -> Result<Caller, ApiError> {
        self.store.metadata_revision()?;
        match &req.bearer {
            Some(token) => self
                .store
                .caller(token)
                .ok_or_else(|| unauthenticated("the bearer token is unknown or revoked")),
            None => {
                crate::auth::local_uid(req)?;
                let _publication = self.store.publication();
                self.store.execution()?.check()?;
                self.store.metadata_revision()?;
                Ok(Caller::local(req.token_id.clone()))
            }
        }
    }

    fn authority(&self, req: &ApiRequest, required: Scope) -> Result<kronik_core::authority::AuthLease, ApiError> {
        Ok(self.capture(req, required)?.authority)
    }

    fn capture(&self, req: &ApiRequest, required: Scope) -> Result<crate::CapturedRequest, ApiError> {
        match &req.bearer {
            Some(token) => self.store.capture_token(token, required),
            None => self.store.capture_local(req, required),
        }
    }

    fn changes(&self) -> Option<Arc<tokio::sync::Notify>> {
        Some(self.store.changes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn named_capture_retains_actual_hash_and_original_revocation_at_real_wal() {
        let dir = tempfile::tempdir().unwrap();
        let node = kronik_sched::start_local(kronik_core::env::Env::real(tokio::runtime::Handle::current()),
            dir.path(), kronik_sched::NodeConfig::default()).await.unwrap();
        let mut store = TokenStore::open(Connection::open_in_memory().unwrap()).unwrap();
        store.bind_before_any_issuer(node.publication_domain()).unwrap();
        store.bind_execution_before_any_issuer(&node.publication_domain(), node.local_operator_authority().unwrap()).unwrap();
        let store = Arc::new(store);
        store.create("named-profile", [Scope::Operate].into(), [21; 32], &change("create named"), false).unwrap();
        let api = crate::Api::new(node.clone()).with_tokens(store.clone()).unwrap();
        let captured = api.capture_context(store.capture_name("named-profile", Scope::Operate).unwrap(), None).unwrap();
        assert_eq!(captured.caller.token_id, "token:named-profile");
        let audit = || kronik_proto::log::v1::Audit { token_id: captured.caller.token_id.clone(),
            reason: "named operation".into(), wall_time_ms: node.env().clock.wall_ms() };
        let database = store.inner().unwrap();
        let accepted = node.record_audit_event_authorized("test.named", "named-profile", Default::default(),
            audit(), captured.authority.clone()).await.unwrap();
        drop(database);
        store.revoke("named-profile", &change("revoke named"), false).unwrap();
        captured.authority.cancelled().await;
        assert!(node.record_audit_event_authorized("test.named", "must-not-append", Default::default(),
            audit(), captured.authority.clone()).await.is_err());
        assert_eq!(node.applied_lsn(), accepted);
        let mut actions = Vec::new();
        node.reader().read(accepted, accepted, |entry| {
            if let kronik_proto::Record::AuditEvent(event) = &entry.record { actions.push(event.action.clone()); }
            Ok(())
        }).await.unwrap();
        assert_eq!(actions, ["test.named"]);
    }

    #[tokio::test]
    async fn named_profile_without_real_fleet_provider_is_denied_before_private_identity_work() {
        let dir = tempfile::tempdir().unwrap();
        let node = kronik_sched::start_local(kronik_core::env::Env::real(tokio::runtime::Handle::current()),
            dir.path(), kronik_sched::NodeConfig::default()).await.unwrap();
        let mut store = TokenStore::open(Connection::open_in_memory().unwrap()).unwrap();
        store.bind_before_any_issuer(node.publication_domain()).unwrap();
        store.bind_execution_before_any_issuer(&node.publication_domain(), node.local_operator_authority().unwrap()).unwrap();
        let store = Arc::new(store);
        store.create_with_fleet("managed-profile", [Scope::Read].into(), [22; 32], &change("managed fixture"), false,
            Some(FleetToken { epoch: 1, request_id: "ab".repeat(32) })).unwrap();
        let api = crate::Api::new(node.clone()).with_tokens(store.clone()).unwrap();
        let before = node.applied_lsn();
        let captured = store.capture_name("managed-profile", Scope::Read).unwrap();
        assert_eq!(api.capture_context(captured, None).err().unwrap().code, ErrorCode::Unauthenticated);
        assert_eq!(node.applied_lsn(), before);
    }

    /// Frozen pre-fleet consumer: construction fails before any caller can use
    /// the live table if the original TEXT-only scope reader encounters BLOB.
    struct PreFleetTokenStore { _conn: Connection, live: Live }

    impl PreFleetTokenStore {
        fn open(conn: Connection) -> rusqlite::Result<Self> {
            conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;")?;
            let live = {
                let mut statement = conn.prepare("SELECT hash, name, scopes FROM tokens WHERE revoked_wall_ms IS NULL")?;
                let rows = statement.query_map([], |row| {
                    let hash: Vec<u8> = row.get(0)?;
                    let hash: [u8; 32] = hash.try_into().map_err(|_| rusqlite::Error::InvalidColumnType(0, "hash".into(), rusqlite::types::Type::Blob))?;
                    Ok((hash, (row.get::<_, String>(1)?, scopes_from_text(&row.get::<_, String>(2)?)?)))
                })?;
                rows.collect::<rusqlite::Result<Live>>()?
            };
            Ok(Self { _conn: conn, live })
        }

        fn caller(&self, token: &str) -> Option<Caller> {
            let (name, scopes) = self.live.get(&hash(token))?;
            Some(Caller { token_id: token_id(name), scopes: scopes.clone() })
        }
    }

    #[test]
    fn legacy_fleet_named_tokens_remain_ordinary_and_managed_provenance_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.db");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE tokens (
            name TEXT PRIMARY KEY, hash BLOB NOT NULL UNIQUE, scopes TEXT NOT NULL,
            created_wall_ms INTEGER NOT NULL, created_by TEXT NOT NULL, reason TEXT NOT NULL,
            revoked_wall_ms INTEGER, revoked_by TEXT, revoke_reason TEXT
        ) WITHOUT ROWID;").unwrap();
        let mut ordinary = Vec::new();
        for (index, name) in ["fleet-1", "fleet-team"].into_iter().enumerate() {
            let bearer = format!("{PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([index as u8 + 1; 32]));
            conn.execute("INSERT INTO tokens(name,hash,scopes,created_wall_ms,created_by,reason) VALUES (?1,?2,'read',1,'unix:uid=0','legacy')",
                params![name, hash(&bearer).as_slice()]).unwrap();
            ordinary.push((name, bearer));
        }
        drop(conn);
        let store = TokenStore::open_file(&path).unwrap();
        for (name, bearer) in &ordinary {
            assert!(store.caller(bearer).is_some());
            assert!(store.fleet_token(&token_id(name)).is_none());
        }
        let legacy = PreFleetTokenStore::open(Connection::open(&path).unwrap()).unwrap();
        assert_eq!(legacy.caller(&ordinary[0].1).unwrap().token_id, "token:fleet-1");
        let provenance = FleetToken { epoch: u64::MAX, request_id: "ab".repeat(32) };
        let name = format!("fleet-{}-{}", provenance.epoch, &provenance.request_id[..32]);
        let (managed, bearer) = store.create_with_fleet(&name, [Scope::Read].into(), [7; 32], &change("enroll"), false, Some(provenance.clone())).unwrap();
        assert_eq!(managed.fleet, Some(provenance.clone()));
        assert!(matches!(PreFleetTokenStore::open(Connection::open(&path).unwrap()), Err(rusqlite::Error::InvalidColumnType(2, _, rusqlite::types::Type::Blob))));
        let active_restart = TokenStore::open_file(&path).unwrap();
        let active_caller = active_restart.caller(bearer.as_ref().unwrap()).unwrap();
        assert_eq!(active_caller.scopes, BTreeSet::from([Scope::Read]));
        assert_eq!(active_restart.fleet_token(&active_caller.token_id).unwrap().as_ref(), &provenance);
        store.revoke(&name, &change("revoke"), false).unwrap();
        let downgraded = PreFleetTokenStore::open(Connection::open(&path).unwrap()).unwrap();
        assert!(downgraded.caller(bearer.as_ref().unwrap()).is_none());
        assert!(downgraded.caller(&ordinary[0].1).is_some());
        drop(store);
        let reopened = TokenStore::open_file(&path).unwrap();
        assert_eq!(reopened.fleet_token(&token_id(&name)).unwrap().as_ref(), &provenance);
        for (name, bearer) in ordinary {
            assert!(reopened.caller(&bearer).is_some());
            assert!(reopened.fleet_token(&token_id(name)).is_none());
        }
        assert!(reopened.list().unwrap().iter().filter(|meta| meta.fleet.is_none()).all(|meta| meta.revoked.is_none()));
    }

    #[test]
    fn partial_or_malformed_managed_provenance_fails_closed() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        conn.execute("INSERT INTO tokens(name,hash,scopes,created_wall_ms,created_by,reason,fleet_epoch) VALUES ('broken',?1,'read',1,'system','invalid','1')", [hash("invalid").as_slice()]).unwrap();
        assert!(TokenStore::open(conn).is_err());
    }

    #[test]
    fn managed_scope_format_is_bounded_versioned_and_requires_real_provenance() {
        use rusqlite::types::Value;
        let valid: serde_json::Value = serde_json::from_slice(include_bytes!("../tests/fixtures/managed-token-scopes-v1.json")).unwrap();
        let blob = |value: serde_json::Value| Value::Blob(serde_json::to_vec(&value).unwrap());
        let mut future = valid.clone(); future["version"] = 2.into();
        let mut unknown = valid.clone(); unknown["authority"] = "admin".into();
        let mut scope = valid.clone(); scope["scopes"] = "unknown".into();
        let mut duplicate = valid.clone(); duplicate["scopes"] = "read,read".into();
        let mut wrong_epoch = valid.clone(); wrong_epoch["fleet"]["epoch"] = 8.into();
        let mut wrong_request = valid.clone(); wrong_request["fleet"]["request_id"] = "cd".repeat(32).into();
        let mut missing = valid.clone(); missing.as_object_mut().unwrap().remove("fleet");
        let cases = [
            (Value::Text("read".into()), true), (blob(valid), false), (blob(missing), true),
            (blob(future), true), (blob(unknown), true), (blob(scope), true), (blob(duplicate), true),
            (blob(wrong_epoch), true), (blob(wrong_request), true),
            (Value::Blob(b"{".to_vec()), true),
            (Value::Blob(vec![0xff]), true),
            (Value::Blob(vec![b' '; MAX_MANAGED_SCOPES_BYTES + 1]), true),
        ];
        for (scopes, managed) in cases {
            let conn = Connection::open_in_memory().unwrap();
            conn.execute_batch(SCHEMA).unwrap();
            conn.execute("INSERT INTO tokens(name,hash,scopes,created_wall_ms,created_by,reason,fleet_epoch,fleet_request_id) VALUES ('bad-format',?1,?2,1,'system','invalid',?3,?4)",
                params![hash("invalid").as_slice(), scopes, managed.then_some("7"), managed.then(|| "ab".repeat(32))]).unwrap();
            assert!(TokenStore::open(conn).is_err());
        }
    }

    #[test]
    fn managed_scope_storage_matches_the_versioned_required_provenance_fixture() {
        let expected = include_bytes!("../tests/fixtures/managed-token-scopes-v1.json").trim_ascii_end();
        let store = TokenStore::open(Connection::open_in_memory().unwrap()).unwrap();
        let provenance = FleetToken { epoch: 7, request_id: "ab".repeat(32) };
        store.create_with_fleet("managed-fixture", [Scope::Read, Scope::Fork].into(), [7; 32], &change("fixture"), false, Some(provenance)).unwrap();
        let (kind, actual): (String, Vec<u8>) = store.inner().unwrap().conn.query_row("SELECT typeof(scopes),scopes FROM tokens WHERE name='managed-fixture'", [], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
        assert_eq!(kind, "blob");
        assert_eq!(actual, expected);
    }

    fn metadata_source(token: &str) -> MetadataSource {
        let meta = TokenMeta {
            name: "metadata-reader".into(),
            scopes: [Scope::Read].into(),
            created_wall_ms: 1_000,
            created_by: "operator".into(),
            reason: "metadata fixture".into(),
            revoked: None,
            fleet: None,
        };
        MetadataSource {
            revision: 1,
            owner_member: 7,
            auth_config_revision: 0,
            auth_config: None,
            fleet_revision: 0,
            fleet: None,
            tokens: [(meta.name.clone(), MetadataToken {
                meta, hash: hash(token), created_index: 1, revision: 1, revoked_index: None,
            })].into(),
        }
    }

    #[test]
    fn member_authentication_never_falls_back_to_the_native_database() {
        let store = Arc::new(TokenStore::open(Connection::open_in_memory().unwrap()).unwrap());
        let (_, native) = store.create(
            "native-reader", [Scope::Read].into(), [9; 32], &change("native"), false,
        ).unwrap();
        let native = native.unwrap();
        assert!(store.caller(&native).is_some());
        store.require_metadata().unwrap();
        assert!(store.caller(&native).is_none());
        assert_eq!(store.list().unwrap_err().code, ErrorCode::Unavailable);
        assert_eq!(
            store.capture_token(&native, Scope::Read).err().unwrap().code,
            ErrorCode::Unavailable,
        );
        let source = metadata_source("metadata-token");
        store.publish_prepared(TokenStore::prepare_metadata(source).unwrap()).unwrap();
        assert!(store.caller(&native).is_none());
        assert_eq!(store.caller("metadata-token").unwrap().token_id, "token:metadata-reader");
        assert_eq!(store.list().unwrap().len(), 1);
        store.fail_metadata();
        assert!(store.caller("metadata-token").is_none());
        assert!(store.caller(&native).is_none());
        assert_eq!(store.metadata_revision().unwrap_err().code, ErrorCode::Unavailable);
        assert!(store.revoke("native-reader", &change("no native fallback"), false).is_err());
        let member = Arc::new(TokenStore::for_member(Arc::new(Mutex::new(()))));
        assert!(member.inner.is_none());
        assert_eq!(member.list().unwrap_err().code, ErrorCode::Unavailable);
    }

    #[test]
    fn metadata_publication_rejects_stale_or_conflicting_images_without_reviving_tokens() {
        let store = TokenStore::for_member(Arc::new(Mutex::new(())));
        let source = metadata_source("metadata-token");
        store.publish_prepared(TokenStore::prepare_metadata(source.clone()).unwrap()).unwrap();
        store.publish_prepared(TokenStore::prepare_metadata(source.clone()).unwrap()).unwrap();
        let mut conflicting = source.clone();
        conflicting.tokens.get_mut("metadata-reader").unwrap().meta.scopes = [Scope::Admin].into();
        assert!(store.publish_prepared(TokenStore::prepare_metadata(conflicting).unwrap()).is_err());
        assert_eq!(store.caller("metadata-token").unwrap().scopes, [Scope::Read].into());
        let mut revoked = source.clone();
        revoked.revision = 2;
        let token = revoked.tokens.get_mut("metadata-reader").unwrap();
        token.revision = 2;
        token.revoked_index = Some(2);
        token.meta.revoked = Some(Revocation {
            wall_ms: 2_000, by: "operator".into(), reason: "revoke metadata token".into(),
        });
        store.publish_prepared(TokenStore::prepare_metadata(revoked).unwrap()).unwrap();
        assert!(store.caller("metadata-token").is_none());
        assert!(store.publish_prepared(TokenStore::prepare_metadata(source).unwrap()).is_err());
        assert!(store.caller("metadata-token").is_none());
        assert!(store.lookup("metadata-reader").unwrap().unwrap().revoked.is_some());
    }

    #[test]
    fn incomplete_metadata_sources_are_rejected_before_publication() {
        let source = metadata_source("metadata-token");
        let mut wrong_owner = source.clone();
        wrong_owner.owner_member = 0;
        let mut missing_auth_config = source.clone();
        missing_auth_config.auth_config_revision = 1;
        let mut missing_fleet = source.clone();
        missing_fleet.fleet_revision = 1;
        let mut missing_created_index = source.clone();
        missing_created_index.tokens.get_mut("metadata-reader").unwrap().created_index = 0;
        let mut missing_revocation = source;
        missing_revocation.tokens.get_mut("metadata-reader").unwrap().revoked_index = Some(1);
        for source in [
            wrong_owner, missing_auth_config, missing_fleet,
            missing_created_index, missing_revocation,
        ] {
            assert!(TokenStore::prepare_metadata(source).is_err());
        }
    }

    #[test]
    fn metadata_cannot_reuse_a_revoked_bearer_hash_for_another_principal() {
        let mut source = metadata_source("immutable-bearer");
        let mut revoked = source.tokens["metadata-reader"].clone();
        revoked.meta.name = "archived-reader".into();
        revoked.meta.revoked = Some(Revocation {
            wall_ms: 1_000, by: "operator".into(), reason: "old identity".into(),
        });
        revoked.revoked_index = Some(1);
        source.tokens.insert(revoked.meta.name.clone(), revoked);
        assert!(TokenStore::prepare_metadata(source).is_err());
    }


    fn change(reason: &str) -> Change<'_> {
        Change {
            wall_ms: 1_000,
            by: "unix:uid=0",
            reason,
        }
    }

    fn request(token_id: &str, bearer: Option<&str>) -> ApiRequest {
        ApiRequest {
            method: "GET".into(),
            path: "/v1/actors".into(),
            query: String::new(),
            body: Vec::new(),
            token_id: token_id.into(),
            bearer: bearer.map(str::to_owned),
        }
    }

    #[test]
    fn tokens_are_hashed_scoped_and_revocable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys/tokens.db");
        let store = Arc::new(TokenStore::open_file(&path).unwrap());
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        let scopes = parse_scopes(&["read", "fork", "propose"]).unwrap();
        let (dry, none) = store
            .create("agent-1", scopes.clone(), [7; 32], &change("try"), true)
            .unwrap();
        assert_eq!(dry.name, "agent-1");
        assert!(none.is_none());
        assert!(store.list().unwrap().is_empty());

        let (meta, token) = store
            .create(
                "agent-1",
                scopes.clone(),
                [7; 32],
                &change("ci agent"),
                false,
            )
            .unwrap();
        let token = token.unwrap();
        assert!(token.starts_with(PREFIX));
        assert_eq!(token.len(), PREFIX.len() + 43);
        assert_eq!(meta.token_id(), "token:agent-1");
        // The file has the hash, not the token.
        let bytes = std::fs::read(&path).unwrap();
        let secret = &token.as_bytes()[PREFIX.len()..];
        assert!(!bytes.windows(secret.len()).any(|w| w == secret));

        let auth = TokenAuthenticator::new(store.clone());
        let caller = auth
            .caller(&request("tcp:127.0.0.1:1", Some(&token)))
            .unwrap();
        assert_eq!(caller.token_id, "token:agent-1");
        assert!(caller.has(Scope::Propose));
        assert!(!caller.has(Scope::Approve));
        assert!(!caller.has(Scope::PiiRead));
        // A token on the socket is that token, not the socket's user.
        let on_socket = auth.caller(&request("unix:uid=0", Some(&token))).unwrap();
        assert_eq!(on_socket.token_id, "token:agent-1");
        // A UID alone is not a physical execution capability.
        assert_eq!(
            auth.caller(&request("unix:uid=0", None)).unwrap_err().code,
            ErrorCode::Unavailable,
        );
        assert_eq!(
            store.capture_token(&token, Scope::Read).err().unwrap().code,
            ErrorCode::Unavailable,
        );
        assert_eq!(
            store.capture_local(&request("unix:uid=0", None), Scope::Admin)
                .err().unwrap().code,
            ErrorCode::Unavailable,
        );
        let missing = auth.caller(&request("tcp:127.0.0.1:1", None)).unwrap_err();
        assert_eq!(missing.code, ErrorCode::Unauthenticated);
        let wrong = auth
            .caller(&request("unix:uid=0", Some("kronik_nope")))
            .unwrap_err();
        assert_eq!(wrong.code, ErrorCode::Unauthenticated);

        // Names are never reused, even after a revoke.
        let again = store
            .create("agent-1", scopes.clone(), [8; 32], &change("again"), false)
            .unwrap_err();
        assert_eq!(again.code, ErrorCode::BadRequest);

        // A store opened again knows the live tokens.
        let reopened = TokenStore::open_file(&path).unwrap();
        assert_eq!(reopened.caller(&token).unwrap().token_id, "token:agent-1");

        let planned = store.revoke("agent-1", &change("dry"), true).unwrap();
        assert!(planned.revoked.is_some());
        assert!(store.caller(&token).is_some());
        let revoked = store.revoke("agent-1", &change("rotated"), false).unwrap();
        assert_eq!(revoked.revoked.as_ref().unwrap().reason, "rotated");
        assert!(store.caller(&token).is_none());
        let listed = store.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].revoked.as_ref().unwrap().by, "unix:uid=0");
        assert_eq!(
            store
                .revoke("agent-1", &change("twice"), false)
                .unwrap_err()
                .code,
            ErrorCode::BadRequest
        );
        assert_eq!(
            store
                .revoke("nobody", &change("x"), false)
                .unwrap_err()
                .code,
            ErrorCode::TokenNotFound
        );
        assert!(
            TokenStore::open_file(&path)
                .unwrap()
                .caller(&token)
                .is_none()
        );
    }

    #[test]
    fn names_and_scopes_are_checked() {
        assert!(valid_name("agent-1"));
        assert!(!valid_name("1agent"));
        assert!(!valid_name("Agent"));
        assert!(!valid_name("a_b"));
        assert!(!valid_name(""));
        assert!(!valid_name(&"a".repeat(64)));
        assert_eq!(
            parse_scopes(&["pii:read", "read", "read"]).unwrap(),
            BTreeSet::from([Scope::Read, Scope::PiiRead])
        );
        assert_eq!(
            parse_scopes(&["root"]).unwrap_err().code,
            ErrorCode::BadRequest
        );
        assert_eq!(
            parse_scopes::<&str>(&[]).unwrap_err().code,
            ErrorCode::BadRequest
        );
    }
}
