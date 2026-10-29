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
use std::sync::{Arc, Mutex, MutexGuard};

use base64::Engine as _;
use kronik_core::error::{ApiError, ErrorCode};
use rusqlite::{Connection, OptionalExtension as _, params};

use crate::ApiRequest;
use crate::auth::{Authenticator, Caller, Scope};

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
  revoked_wall_ms INTEGER, revoked_by TEXT, revoke_reason TEXT
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
    inner: Mutex<Inner>,
}

struct Inner {
    conn: Connection,
    /// Hash of a live token -> its name and scopes.
    live: HashMap<[u8; 32], (String, BTreeSet<Scope>)>,
}

pub(crate) fn token_id(name: &str) -> String {
    format!("token:{name}")
}

fn hash(token: &str) -> [u8; 32] {
    *blake3::hash(token.as_bytes()).as_bytes()
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

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::new(ErrorCode::Internal, format!("token store: {e}"))
}

fn not_found(name: &str) -> ApiError {
    ApiError::new(ErrorCode::TokenNotFound, format!("no token {name:?}"))
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
    Ok(TokenMeta {
        name: row.get(0)?,
        scopes: scopes_from_text(&row.get::<_, String>(1)?)?,
        created_wall_ms: row.get::<_, i64>(2)? as u64,
        created_by: row.get(3)?,
        reason: row.get(4)?,
        revoked,
    })
}

const COLUMNS: &str = "name, scopes, created_wall_ms, created_by, reason, \
    revoked_wall_ms, revoked_by, revoke_reason";

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
        let live = {
            let mut stmt = conn
                .prepare("SELECT hash, name, scopes FROM tokens WHERE revoked_wall_ms IS NULL")?;
            let rows = stmt.query_map([], |row| {
                let hash: Vec<u8> = row.get(0)?;
                let hash: [u8; 32] = hash.try_into().map_err(|_| {
                    rusqlite::Error::InvalidColumnType(
                        0,
                        "hash".into(),
                        rusqlite::types::Type::Blob,
                    )
                })?;
                Ok((
                    hash,
                    (
                        row.get::<_, String>(1)?,
                        scopes_from_text(&row.get::<_, String>(2)?)?,
                    ),
                ))
            })?;
            rows.collect::<Result<HashMap<_, _>, _>>()?
        };
        Ok(TokenStore {
            inner: Mutex::new(Inner { conn, live }),
        })
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
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
        if !valid_name(name) {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                format!(
                    "token names are a lowercase letter, then up to 62 lowercase letters, \
                     digits and dashes; got {name:?}"
                ),
            ));
        }
        let mut inner = self.inner();
        let exists: Option<String> = inner
            .conn
            .query_row("SELECT name FROM tokens WHERE name = ?1", [name], |r| {
                r.get(0)
            })
            .optional()
            .map_err(internal)?;
        if exists.is_some() {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                format!("a token named {name:?} exists or existed; names are never reused"),
            )
            .with_hint("Choose another name. `kronik token list` shows the names in use."));
        }
        let meta = TokenMeta {
            name: name.to_owned(),
            scopes,
            created_wall_ms: change.wall_ms,
            created_by: change.by.to_owned(),
            reason: change.reason.to_owned(),
            revoked: None,
        };
        if dry_run {
            return Ok((meta, None));
        }
        let token = format!(
            "{PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random)
        );
        let digest = hash(&token);
        inner
            .conn
            .execute(
                "INSERT INTO tokens (name, hash, scopes, created_wall_ms, created_by, reason) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    name,
                    digest.as_slice(),
                    scopes_text(&meta.scopes),
                    change.wall_ms as i64,
                    change.by,
                    change.reason
                ],
            )
            .map_err(internal)?;
        inner
            .live
            .insert(digest, (name.to_owned(), meta.scopes.clone()));
        Ok((meta, Some(token)))
    }

    /// Every token, live and revoked, by name.
    pub fn list(&self) -> Result<Vec<TokenMeta>, ApiError> {
        let inner = self.inner();
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
        let mut inner = self.inner();
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
        inner.live.retain(|_, (live, _)| live != name);
        Ok(token)
    }

    /// The caller a token stands for, if it is live.
    pub fn caller(&self, token: &str) -> Option<Caller> {
        let inner = self.inner();
        let (name, scopes) = inner.live.get(&hash(token))?;
        Some(Caller {
            token_id: token_id(name),
            scopes: scopes.clone(),
        })
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
        match &req.bearer {
            Some(token) => self
                .store
                .caller(token)
                .ok_or_else(|| unauthenticated("the bearer token is unknown or revoked")),
            None if req.token_id.starts_with("unix:") => Ok(Caller::local(req.token_id.clone())),
            None => Err(unauthenticated("the API over TCP needs a bearer token")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(
            auth.caller(&request("unix:uid=0", None))
                .unwrap()
                .has(Scope::Admin)
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
