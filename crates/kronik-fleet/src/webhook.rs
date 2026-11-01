//! Signed delivery from actual actor or metadata sources, using the same durable
//! M28 cursor, replay generations, prepared bodies, immutable secret pin and Net.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use hmac::{KeyInit as _, Mac as _};
use kronik_core::authority::AuthLease;
use kronik_core::env::{BoxFuture, Env};
use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::ids::{SourcePos, hex};
use kronik_log::{Committed, MetadataAuditGap, MetadataAuditSource, MetadataWebhookKeyChange};
use kronik_otel::{
    audit::Mapper,
    cursor::{Control, Cursors, Entry, Generation},
    follow::{self, Delivery, Sink, Stream},
    http,
};
use kronik_proto::log::v1 as pb;
use kronik_sched::{
    Node, ShardReader,
    secrets::{CertifiedSecretSnapshot, SecretSnapshotPublication},
};
use serde::{Deserialize, Serialize};
use tokio::sync::futures::Notified;

use crate::events::{self, Event, Identity, Page, Position, ResumeCursor};

const STATE_SCHEMA: &str = "kronik.webhook-state/v2";
pub const SIGNATURE_VERSION: &str = "v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretVersion {
    pub name: String,
    pub version: u64,
    pub branch: String,
    pub version_hash: [u8; 16],
    pub hash_revision: u32,
    pub backend: String,
    pub binding: String,
    pub reference: String,
    pub canonical_ref: String,
    pub link_generation: u64,
    pub source_version: String,
}

/// M23 resolves and asserts the complete immutable identity, returning only its MAC.
pub type Resolver = dyn Fn(
        SecretVersion,
        Vec<u8>,
        AuthLease,
    ) -> Pin<Box<dyn Future<Output = Result<[u8; 32], String>> + Send>>
    + Send
    + Sync;

/// The fixed host producer must durably commit this exact closed notice, return
/// its actual source position, and deduplicate retries by stream and index range.
/// The receipt's namespace is independent of the described metadata range.
pub type MetadataGapRecorder = dyn Fn(MetadataAuditGap, AuthLease) -> BoxFuture<'static, Result<SourcePos, ApiError>>
    + Send
    + Sync;

/// The sole physical M23 runtime supplies an already-certified retained privacy
/// catalogue. Missing or stale certification is an error, never an empty fallback.
/// The pair is captured before any authoritative metadata read; the same
/// publication is retained through the final owned delivery and durable cursor.
pub type MetadataCatalogue = dyn Fn() -> Result<(Arc<CertifiedSecretSnapshot>, SecretSnapshotPublication), ApiError>
    + Send
    + Sync;

/// Commits the fixed registered-stream configuration notice before pin activation.
pub type MetadataConfigRecorder = dyn Fn(MetadataWebhookKeyChange, AuthLease) -> BoxFuture<'static, Result<SourcePos, ApiError>>
    + Send
    + Sync;

#[derive(Clone)]
pub struct MetadataRuntime {
    pub env: Env,
    /// Original registered physical boot and hosted role capability; metadata
    /// hosts retain their metadata role. Never renew it or promote the catalogue.
    pub execution: AuthLease,
    pub catalogue: Arc<MetadataCatalogue>,
    pub config_recorder: Arc<MetadataConfigRecorder>,
}

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub url: String,
    pub secret: SecretVersion,
}

pub fn validate_url(url: &str) -> Result<(), &'static str> {
    let uri = url.parse::<::http::Uri>().map_err(|_| "webhook_url")?;
    if uri
        .authority()
        .is_none_or(|authority| authority.as_str().contains('@'))
        || url.contains('#')
        || !(uri.scheme_str() == Some("https")
            || (uri.scheme_str() == Some("http") && http::is_loopback(url)))
    {
        return Err("webhook_config");
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedEvent {
    id: String,
    #[serde(with = "wire_body")]
    body: Bytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum BatchSchema {
    #[serde(rename = "kronik.webhook-batch/v1")]
    V1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Batch {
    schema: BatchSchema,
    pin: SecretVersion,
    source: SourcePos,
    through: SourcePos,
    generation: Generation,
    timestamp_ms: u64,
    events: Vec<PreparedEvent>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    schema: String,
    identity: Identity,
    /// Typed acknowledged coordinate. The same tag governs Entry's opaque u64.
    source: SourcePos,
    url: String,
    secret: SecretVersion,
    #[serde(with = "pending")]
    pending: Option<Arc<Batch>>,
}

mod wire_body {
    use super::*;
    pub fn serialize<S: serde::Serializer>(body: &Bytes, serializer: S) -> Result<S::Ok, S::Error> {
        std::str::from_utf8(body)
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Bytes, D::Error> {
        String::deserialize(deserializer).map(Bytes::from)
    }
}

mod pending {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        batch: &Option<Arc<Batch>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        batch.as_deref().serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Arc<Batch>>, D::Error> {
        Option::<Batch>::deserialize(deserializer).map(|batch| batch.map(Arc::new))
    }
}

pub struct Webhook {
    host: Host,
    mapper: Arc<Mapper>,
    stream: Arc<Stream>,
    cursors: Arc<Cursors>,
    resolver: Arc<Resolver>,
    state: State,
}

enum Host {
    Native {
        node: Arc<Node>,
        execution: AuthLease,
    },
    Registered {
        runtime: MetadataRuntime,
        capture: Arc<
            dyn Fn(AuthLease) -> BoxFuture<'static, Result<Arc<ShardReader>, ApiError>>
                + Send
                + Sync,
        >,
        record_gap: Arc<
            dyn Fn(u64, u64, AuthLease) -> BoxFuture<'static, Result<(), ApiError>> + Send + Sync,
        >,
    },
    Metadata(MetadataRuntime),
}

impl Host {
    fn env(&self) -> &Env {
        match self {
            Self::Native { node, .. } => node.env(),
            Self::Registered { runtime, .. } => &runtime.env,
            Self::Metadata(runtime) => &runtime.env,
        }
    }

    fn execution(&self) -> &AuthLease {
        match self {
            Self::Native { execution, .. } => execution,
            Self::Registered { runtime, .. } => &runtime.execution,
            Self::Metadata(runtime) => &runtime.execution,
        }
    }

    fn catalogue(
        &self,
    ) -> Result<(Arc<CertifiedSecretSnapshot>, SecretSnapshotPublication), ApiError> {
        match self {
            Self::Native { node, .. } => node.native_secret_snapshot_with_publication(),
            Self::Registered { runtime, .. } => (runtime.catalogue)(),
            Self::Metadata(runtime) => (runtime.catalogue)(),
        }
    }

    async fn capture_actor(&self, original: &AuthLease) -> Result<Arc<ShardReader>, String> {
        original
            .check()
            .map_err(|error| error.code.as_str().to_owned())?;
        let reader = match self {
            Self::Native { node, .. } => tokio::select! {
                biased;
                () = original.cancelled() => return Err("execution_revoked".into()),
                reader = node.capture_system_export_reader() => reader,
            }
            .map(Arc::new),
            Self::Registered { capture, .. } => tokio::select! {
                biased;
                () = original.cancelled() => return Err("execution_revoked".into()),
                reader = capture(original.clone()) => reader,
            },
            Self::Metadata(_) => return Err("metadata_requires_actual_metadata_source".into()),
        }
        .map_err(|error| error.code.as_str().to_owned())?;
        original
            .check()
            .map_err(|error| error.code.as_str().to_owned())?;
        Ok(reader)
    }

    async fn record_configuration(
        &self,
        change: MetadataWebhookKeyChange,
        binding: SourcePos,
    ) -> Result<(), String> {
        let recorder = match self {
            Self::Native { node, execution } => {
                let details = [
                    ("change".into(), "webhook.signing_key".into()),
                    ("source".into(), events::domain(binding).into_owned()),
                    ("from_version".into(), change.from_version.to_string()),
                    ("to_version".into(), change.to_version.to_string()),
                ]
                .into();
                node.record_audit_event_authorized(
                    "audit.config",
                    &change.stream,
                    details,
                    pb::Audit {
                        token_id: "system".into(),
                        reason: "the configured webhook signing version changed".into(),
                        wall_time_ms: node.env().clock.wall_ms(),
                    },
                    execution.clone(),
                )
                .await
                .map_err(|_| "webhook_config_audit".to_owned())?;
                return Ok(());
            }
            Self::Registered { runtime, .. } => &runtime.config_recorder,
            Self::Metadata(runtime) => &runtime.config_recorder,
        };
        let receipt = recorder(change, self.execution().clone())
            .await
            .map_err(|error| error.code.as_str().to_owned())?;
        let valid = match receipt {
            SourcePos::Actor { shard, lsn } => {
                lsn > 0 && shard.is_none_or(|shard| shard < kronik_proto::MAX_SHARD_COUNT)
            }
            SourcePos::Metadata { index } => index > 0,
        };
        if valid {
            Ok(())
        } else {
            Err("webhook_config_audit".into())
        }
    }
}

fn same_domain(left: SourcePos, right: SourcePos) -> bool {
    match (left, right) {
        (SourcePos::Actor { shard: left, .. }, SourcePos::Actor { shard: right, .. }) => {
            left == right
        }
        (SourcePos::Metadata { .. }, SourcePos::Metadata { .. }) => true,
        _ => false,
    }
}

fn at(source: SourcePos, coordinate: u64) -> SourcePos {
    match source {
        SourcePos::Actor { shard, .. } => SourcePos::Actor {
            shard,
            lsn: coordinate,
        },
        SourcePos::Metadata { .. } => SourcePos::Metadata { index: coordinate },
    }
}

/// Restore/status must inspect this durable tag, never infer a namespace from a name.
/// Untagged historical entries are actor-only, including untagged coordinate zero.
pub fn cursor_source(entry: &Entry) -> Result<SourcePos, ApiError> {
    if entry.state.is_null() || entry.state.get("source").is_none() {
        if entry
            .state
            .get("schema")
            .and_then(serde_json::Value::as_str)
            == Some(STATE_SCHEMA)
        {
            return Err(ApiError::new(
                ErrorCode::StorageCorrupt,
                "webhook cursor source is missing",
            ));
        }
        return Ok(SourcePos::Actor {
            shard: None,
            lsn: entry.lsn,
        });
    }
    let state = State::deserialize(&entry.state)
        .map_err(|_| ApiError::new(ErrorCode::StorageCorrupt, "invalid typed webhook cursor"))?;
    validate_state(&state, entry).map_err(|_| {
        ApiError::new(
            ErrorCode::StorageCorrupt,
            "invalid typed webhook source position",
        )
    })?;
    Ok(state.source)
}

fn validate_state(state: &State, entry: &Entry) -> Result<(), String> {
    state.identity.validate()?;
    if !valid_pin(&state.secret, &state.identity) {
        return Err("webhook_state".into());
    }
    if state.schema != STATE_SCHEMA
        || events::coordinate(state.source) != entry.lsn
        || matches!(state.source, SourcePos::Actor { shard: Some(shard), .. } if shard >= kronik_proto::MAX_SHARD_COUNT)
    {
        return Err("webhook_state".into());
    }
    if let Some(batch) = &state.pending {
        if !same_domain(state.source, batch.source)
            || !same_domain(batch.source, batch.through)
            || !valid_pin(&batch.pin, &state.identity)
            || matches!(batch.source, SourcePos::Metadata { .. }) && batch.events.is_empty()
            || events::coordinate(batch.source) <= entry.lsn
            || events::coordinate(batch.through) < events::coordinate(batch.source)
            || batch.generation != entry.generation()
            || matches!(state.source, SourcePos::Actor { .. })
                && events::coordinate(batch.source) != entry.lsn.saturating_add(1)
        {
            return Err("webhook_state".into());
        }
        for prepared in &batch.events {
            let event: Event =
                serde_json::from_slice(&prepared.body).map_err(|_| "webhook_state".to_owned())?;
            let branch_matches = match event.source {
                SourcePos::Actor { .. } => {
                    event.branch.as_deref() == Some(state.identity.branch.as_str())
                }
                SourcePos::Metadata { .. } => event.branch.is_none(),
            };
            if event.schema != events::SCHEMA
                || event.installation != state.identity.installation
                || !branch_matches
                || event.source != batch.source
                || event.id != prepared.id
                || event.id
                    != events::event_id(
                        &state.identity,
                        event.source,
                        event.branch.as_deref(),
                        event.subindex,
                        &event.data.record_hash,
                    )?
                || event.body()?.as_slice() != prepared.body.as_ref()
            {
                return Err("webhook_state".into());
            }
        }
    }
    Ok(())
}

fn valid_pin(pin: &SecretVersion, identity: &Identity) -> bool {
    !pin.name.is_empty() && pin.version > 0 && pin.branch == identity.branch
}

fn verify_prepared(batch: &Batch, projected: &[Event]) -> Result<(), String> {
    if batch.events.len() != projected.len() {
        return Err("webhook_history_conflict".into());
    }
    for (prepared, event) in batch.events.iter().zip(projected) {
        if prepared.id != event.id || prepared.body.as_ref() != event.body()?.as_slice() {
            return Err("webhook_history_conflict".into());
        }
    }
    Ok(())
}

/// Signed domain/version, decimal timestamp, stable identity, exact body; never URL.
pub fn signing_input(timestamp_ms: u64, event_id: &str, body: &[u8]) -> Result<Vec<u8>, String> {
    if !event_id.starts_with("ke1.")
        || !event_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.')
    {
        return Err("webhook_signature".into());
    }
    let mut input = format!("kronik.webhook/v1\n{timestamp_ms}\n{event_id}\n").into_bytes();
    input.extend_from_slice(body);
    Ok(input)
}

pub fn signature(
    key: &[u8],
    timestamp_ms: u64,
    event_id: &str,
    body: &[u8],
) -> Result<String, String> {
    if key.is_empty() {
        return Err("webhook_signature".into());
    }
    let input = signing_input(timestamp_ms, event_id, body)?;
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key)
        .map_err(|_| "webhook_signature".to_owned())?;
    mac.update(&input);
    Ok(format!(
        "{SIGNATURE_VERSION}={}",
        hex(&mac.finalize().into_bytes())
    ))
}

async fn advance_cursor(
    env: &Env,
    stream: Arc<Stream>,
    cursors: Arc<Cursors>,
    entry: Entry,
    original: &AuthLease,
) -> Result<Entry, String> {
    original
        .check()
        .map_err(|error| error.code.as_str().to_owned())?;
    let retained = original.clone();
    let mut job = Some(async move {
        let _original = retained;
        if stream.is_stopping() {
            return Err("execution_revoked".into());
        }
        cursors
            .advance(stream.name.as_ref(), entry)
            .await
            .map_err(|_| "webhook_checkpoint".to_owned())
    });
    let mut accepted = None;
    original
        .admit(&mut || {
            let job = job.take().ok_or_else(|| ApiError {
                code: ErrorCode::Internal,
                message: String::new(),
                hint: None,
            })?;
            accepted = Some(env.spawn("events-cursor", job));
            Ok(())
        })
        .map_err(|error| error.code.as_str().to_owned())?;
    accepted
        .ok_or("webhook_checkpoint")?
        .await
        .unwrap_or_else(|| Err("webhook_checkpoint".into()))
}

impl Webhook {
    /// Actor delivery uses the existing follower with Options.batch = 1.
    /// The caller supplies its original native/member execution lease once;
    /// delivery retains it rather than reacquiring authority on retries.
    pub async fn open(
        node: Arc<Node>,
        mapper: Arc<Mapper>,
        identity: Identity,
        shard: Option<u32>,
        stream: Arc<Stream>,
        cursors: Arc<Cursors>,
        settings: Settings,
        resolver: Arc<Resolver>,
        execution: AuthLease,
    ) -> Result<Self, String> {
        if node.branch() != identity.branch {
            return Err("webhook_config".into());
        }
        Self::open_at(
            Host::Native { node, execution },
            mapper,
            identity,
            SourcePos::Actor { shard, lsn: 0 },
            stream,
            cursors,
            settings,
            resolver,
        )
        .await
    }

    /// The real Member producer validates the exact registered source, branch,
    /// shard, cursors and stream before constructing these retained callbacks.
    /// Capture returns that producer's ONE actual reader Arc, never a Node fallback.
    pub async fn open_registered(
        runtime: MetadataRuntime,
        capture: Arc<
            dyn Fn(AuthLease) -> BoxFuture<'static, Result<Arc<ShardReader>, ApiError>>
                + Send
                + Sync,
        >,
        record_gap: Arc<
            dyn Fn(u64, u64, AuthLease) -> BoxFuture<'static, Result<(), ApiError>> + Send + Sync,
        >,
        mapper: Arc<Mapper>,
        identity: Identity,
        shard: Option<u32>,
        stream: Arc<Stream>,
        cursors: Arc<Cursors>,
        settings: Settings,
        resolver: Arc<Resolver>,
    ) -> Result<Self, String> {
        Self::open_at(
            Host::Registered {
                runtime,
                capture,
                record_gap,
            },
            mapper,
            identity,
            SourcePos::Actor { shard, lsn: 0 },
            stream,
            cursors,
            settings,
            resolver,
        )
        .await
    }

    pub async fn open_metadata(
        runtime: MetadataRuntime,
        mapper: Arc<Mapper>,
        identity: Identity,
        stream: Arc<Stream>,
        cursors: Arc<Cursors>,
        settings: Settings,
        resolver: Arc<Resolver>,
    ) -> Result<Self, String> {
        let execution = runtime.execution.clone();
        tokio::select! {
            biased;
            () = execution.cancelled() => Err("execution_revoked".into()),
            opened = Self::open_at(Host::Metadata(runtime), mapper, identity, SourcePos::Metadata { index: 0 },
                stream, cursors, settings, resolver) => opened,
        }
    }

    async fn open_at(
        host: Host,
        mapper: Arc<Mapper>,
        identity: Identity,
        binding: SourcePos,
        stream: Arc<Stream>,
        cursors: Arc<Cursors>,
        settings: Settings,
        resolver: Arc<Resolver>,
    ) -> Result<Self, String> {
        host.execution()
            .check()
            .map_err(|error| error.code.as_str().to_owned())?;
        identity.validate()?;
        ResumeCursor::new(identity.clone()).rewind(Position {
            source: at(binding, 1),
            subindex: 0,
        })?;
        validate_url(&settings.url).map_err(str::to_owned)?;
        if mapper.branch != identity.branch
            || settings.secret.branch != identity.branch
            || settings.secret.version == 0
            || settings.secret.name.is_empty()
            || !stream.name.starts_with("events-")
            || stream.name.len() > 128
            || !stream.is_for_cursors(&cursors)
        {
            return Err("webhook_config".into());
        }
        let saved = cursors.get(stream.name.as_ref());
        if matches!(binding, SourcePos::Metadata { .. })
            && saved
                .as_ref()
                .is_some_and(|entry| entry.state.is_null() || entry.state.get("source").is_none())
        {
            return Err("metadata_cursor_source_missing".into());
        }
        let mut entry = saved.unwrap_or_default();
        let expected = State {
            schema: STATE_SCHEMA.into(),
            identity,
            source: at(binding, entry.lsn),
            url: settings.url,
            secret: settings.secret,
            pending: None,
        };
        let seeded = entry
            .state
            .as_object()
            .is_some_and(|state| state.len() == 1 && state.contains_key("source"));
        if seeded
            && cursor_source(&entry).map_err(|error| error.code.as_str().to_owned())?
                != expected.source
        {
            return Err("webhook_source".into());
        }
        let state = if entry.state.is_null() || seeded {
            entry.state =
                serde_json::to_value(&expected).map_err(|_| "webhook_state".to_owned())?;
            advance_cursor(
                host.env(),
                stream.clone(),
                cursors.clone(),
                entry.clone(),
                host.execution(),
            )
            .await?;
            expected
        } else {
            let mut state =
                State::deserialize(&entry.state).map_err(|_| "webhook_state".to_owned())?;
            validate_state(&state, &entry)?;
            if state.schema != expected.schema
                || state.identity != expected.identity
                || state.source != expected.source
                || state.url != expected.url
            {
                return Err("webhook_config_changed".into());
            }
            if state.secret != expected.secret {
                // A logical immutable version cannot acquire different identity fields.
                if state.secret.name == expected.secret.name
                    && state.secret.version == expected.secret.version
                {
                    return Err("webhook_secret_identity_changed".into());
                }
                host.record_configuration(
                    MetadataWebhookKeyChange {
                        stream: stream.name.to_string(),
                        from_version: state.secret.version,
                        to_version: expected.secret.version,
                    },
                    binding,
                )
                .await?;
                state.secret = expected.secret;
                entry.state =
                    serde_json::to_value(&state).map_err(|_| "webhook_state".to_owned())?;
                advance_cursor(
                    host.env(),
                    stream.clone(),
                    cursors.clone(),
                    entry.clone(),
                    host.execution(),
                )
                .await?;
            }
            state
        };
        Ok(Self {
            host,
            mapper,
            stream,
            cursors,
            resolver,
            state,
        })
    }

    async fn prepare_events(
        &mut self,
        projected: Vec<Event>,
        source: SourcePos,
        through: SourcePos,
        generation: Generation,
    ) -> Result<Arc<Batch>, String> {
        if !same_domain(self.state.source, source)
            || !same_domain(source, through)
            || events::coordinate(through) < events::coordinate(source)
            || projected.iter().any(|event| event.source != source)
            || matches!(source, SourcePos::Actor { .. })
                && (events::coordinate(source)
                    != events::coordinate(self.state.source).saturating_add(1)
                    || through != source)
        {
            return Err("webhook_source".into());
        }
        if let Some(batch) = &self.state.pending {
            if batch.source != source || batch.through != through || batch.generation != generation
            {
                return Err("webhook_state".into());
            }
            verify_prepared(batch, &projected)?;
            return Ok(batch.clone());
        }
        let mut prepared = Vec::new();
        let mut bytes = 0;
        for event in projected {
            let body = event.body()?;
            bytes += body.len();
            if bytes > events::MAX_PAGE_BYTES {
                return Err("webhook_limit".into());
            }
            prepared.push(PreparedEvent {
                id: event.id,
                body: Bytes::from(body),
            });
        }
        let batch = Arc::new(Batch {
            schema: BatchSchema::V1,
            pin: self.state.secret.clone(),
            source,
            through,
            generation,
            timestamp_ms: self.host.env().clock.wall_ms(),
            events: prepared,
        });
        Ok(batch)
    }

    async fn persist_pending(
        &mut self,
        batch: &Arc<Batch>,
        original: &AuthLease,
    ) -> Result<(), String> {
        if let Some(pending) = &self.state.pending {
            return if pending == batch {
                original
                    .check()
                    .map_err(|error| error.code.as_str().to_owned())
            } else {
                Err("webhook_history_conflict".into())
            };
        }
        let mut entry = self
            .cursors
            .get(self.stream.name.as_ref())
            .ok_or("webhook_state")?;
        if cursor_source(&entry).map_err(|error| error.code.as_str().to_owned())?
            != self.state.source
            || entry.generation() != batch.generation
            || events::coordinate(batch.source) <= entry.lsn
        {
            return Err("webhook_state".into());
        }
        let mut state = self.state.clone();
        state.pending = Some(batch.clone());
        entry.state = serde_json::to_value(&state).map_err(|_| "webhook_state".to_owned())?;
        let saved = advance_cursor(
            self.host.env(),
            self.stream.clone(),
            self.cursors.clone(),
            entry,
            original,
        )
        .await?;
        self.state = state;
        if saved
            .pending_rewind()
            .is_some_and(|rewind| rewind.generation != batch.generation)
        {
            return Err("webhook_state".into());
        }
        original
            .check()
            .map_err(|error| error.code.as_str().to_owned())
    }

    /// Only a page built from the actual MetadataAuditSource, never actor Committed.
    pub async fn prepare_metadata(
        &mut self,
        page: Page,
        generation: Generation,
    ) -> Result<Arc<Batch>, String> {
        if !matches!(self.state.source, SourcePos::Metadata { .. })
            || !matches!(page.applied, SourcePos::Metadata { .. })
            || page.gap.is_some()
        {
            return Err("webhook_source".into());
        }
        let source = page.events.first().ok_or("metadata_batch_empty")?.source;
        let next = page
            .cursor
            .streams
            .get("metadata")
            .ok_or("metadata_cursor_missing")?;
        if next.subindex != 0 || !matches!(next.source, SourcePos::Metadata { .. }) {
            return Err("metadata_batch_requires_record_boundary".into());
        }
        let through = events::coordinate(next.source)
            .checked_sub(1)
            .ok_or("metadata_cursor_missing")?;
        self.prepare_events(
            page.events,
            source,
            SourcePos::Metadata { index: through },
            generation,
        )
        .await
    }

    fn pending_metadata(
        &self,
        image: kronik_log::MetadataAuditBatch,
        generation: Generation,
        secrets: &[(&str, &[u8])],
    ) -> Result<Arc<Batch>, String> {
        let batch = self.state.pending.as_ref().ok_or("webhook_state")?;
        let SourcePos::Metadata { index } = batch.source else {
            return Err("webhook_source".into());
        };
        if batch.generation != generation {
            return Err("webhook_state".into());
        }
        if !matches!(self.host, Host::Metadata(_)) {
            return Err("metadata_requires_actual_metadata_source".into());
        }
        if index > image.durable_through {
            return Err("webhook_history_conflict".into());
        }
        if let Some(record) = image
            .records
            .into_iter()
            .next()
            .filter(|record| record.index == index)
        {
            let projected =
                events::project_metadata(&self.mapper, &self.state.identity, &record, secrets)
                    .map_err(|error| error.code.as_str().to_owned())?;
            verify_prepared(batch, &projected)?;
        } else if index >= image.covered_from {
            return Err("webhook_history_conflict".into());
        }
        // Only explicit lost coverage may rely on the durable prepared witness.
        Ok(batch.clone())
    }

    fn checkpoint_value(&self, source: SourcePos) -> Result<serde_json::Value, String> {
        if !same_domain(self.state.source, source) {
            return Err("webhook_source".into());
        }
        let mut state = self.state.clone();
        state.source = source;
        state.pending = None;
        serde_json::to_value(state).map_err(|_| "webhook_state".into())
    }

    fn accept_checkpoint(&mut self, source: SourcePos) {
        self.state.source = source;
        self.state.pending = None;
    }
}

impl Sink for Webhook {
    type Batch = Arc<Batch>;

    async fn prepare(
        &mut self,
        records: &[(pb::ActorSource, Committed)],
        generation: Generation,
        reader: &ShardReader,
        snapshot: &CertifiedSecretSnapshot,
        original: AuthLease,
    ) -> Result<Arc<Batch>, String> {
        original
            .check()
            .map_err(|error| error.code.as_str().to_owned())?;
        let SourcePos::Actor { shard, .. } = self.state.source else {
            return Err("metadata_requires_actual_metadata_source".into());
        };
        reader
            .check()
            .map_err(|error| error.code.as_str().to_owned())?;
        if records.len() != 1 {
            return Err("webhook_batch_requires_one_record".into());
        }
        let (source, committed) = &records[0];
        if source.shard != shard || source.lsn != committed.lsn {
            return Err("webhook_source".into());
        }
        let position = SourcePos::Actor {
            shard: source.shard,
            lsn: source.lsn,
        };
        let secrets: Vec<_> = snapshot
            .values
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_slice()))
            .collect();
        let projected = events::project(
            &self.mapper,
            &self.state.identity,
            source,
            &committed.record,
            &secrets,
        )
        .map_err(|error| error.code.as_str().to_owned())?;
        self.prepare_events(projected, position, position, generation)
            .await
    }

    async fn deliver(&mut self, batch: &Arc<Batch>, original: AuthLease) -> Delivery {
        if let Err(code) = self.persist_pending(batch, &original).await {
            return Delivery::Retry { code, after: None };
        }
        let execution = original;
        for event in &batch.events {
            if let Err(error) = execution.check() {
                return Delivery::Retry {
                    code: error.code.as_str().into(),
                    after: None,
                };
            }
            let input = match signing_input(batch.timestamp_ms, &event.id, &event.body) {
                Ok(input) => input,
                Err(code) => return Delivery::Retry { code, after: None },
            };
            let mac = tokio::select! {
                biased;
                () = execution.cancelled() =>
                    return Delivery::Retry { code: "execution_revoked".into(), after: None },
                mac = (self.resolver)(batch.pin.clone(), input, execution.clone()) => mac,
            };
            if let Err(error) = execution.check() {
                return Delivery::Retry {
                    code: error.code.as_str().into(),
                    after: None,
                };
            }
            let signature = match mac {
                Ok(mac) => format!("{SIGNATURE_VERSION}={}", hex(&mac)),
                Err(_) => {
                    return Delivery::Retry {
                        code: "SECRET_UNAVAILABLE".into(),
                        after: None,
                    };
                }
            };
            let headers = vec![
                ("kronik-signature".into(), signature),
                ("kronik-signature-version".into(), SIGNATURE_VERSION.into()),
                ("kronik-timestamp-ms".into(), batch.timestamp_ms.to_string()),
                ("kronik-event-id".into(), event.id.clone()),
                ("idempotency-key".into(), event.id.clone()),
            ];
            let env = self.host.env();
            let job_env = env.clone();
            let retained_execution = execution.clone();
            let (url, body) = (self.state.url.clone(), event.body.clone());
            let accepted = env.spawn("events-http", async move {
                // Final admission is the canonical transport queue, after connection waits.
                http::post_authorized(
                    &job_env,
                    url,
                    headers,
                    "application/json",
                    body,
                    retained_execution,
                )
                .await
            });
            match accepted.await.unwrap_or(Err("http_job")) {
                Ok(response) if (200..300).contains(&response.status) => {}
                Ok(response) => {
                    return Delivery::Retry {
                        code: format!("http_{}", response.status),
                        after: http::retry_after(&response),
                    };
                }
                Err(code) => {
                    return Delivery::Retry {
                        code: code.into(),
                        after: None,
                    };
                }
            }
        }
        Delivery::Delivered
    }

    async fn checkpoint(&mut self, lsn: u64) -> Result<serde_json::Value, String> {
        if !matches!(self.state.source, SourcePos::Actor { .. }) {
            return Err("metadata_requires_typed_checkpoint".into());
        }
        self.checkpoint_value(at(self.state.source, lsn))
    }

    fn committed(&mut self, lsn: u64, _generation: Generation, _rewind_pending: bool) {
        self.accept_checkpoint(at(self.state.source, lsn));
    }

    async fn rewind(
        &mut self,
        _to: u64,
        _generation: Generation,
        _reader: &ShardReader,
    ) -> Result<(), String> {
        self.state.pending = None;
        Ok(())
    }

    async fn gap(&mut self, from: u64, to: u64, original: AuthLease) -> Result<(), String> {
        if !matches!(self.state.source, SourcePos::Actor { .. }) {
            return Err("metadata_requires_typed_gap".into());
        }
        // A retained canonical body is still deliverable when its source prefix
        // compacted during a restart. Never let the gap checkpoint discard it.
        if let Some(batch) = self.state.pending.clone() {
            original
                .check()
                .map_err(|error| error.code.as_str().to_owned())?;
            let (snapshot, publication) = self
                .host
                .catalogue()
                .map_err(|error| error.code.as_str().to_owned())?;
            let retained = self.host.capture_actor(&original).await?;
            let disclosure = follow::RetainedDisclosure::native(
                retained,
                snapshot,
                publication,
                original.clone(),
            );
            match self.deliver(&batch, disclosure).await {
                Delivery::Delivered => {}
                Delivery::Retry { code, .. } | Delivery::Dropped { code } => return Err(code),
            }
        }
        let node = match &self.host {
            Host::Native { node, .. } => node,
            Host::Registered { record_gap, .. } => {
                return record_gap(from, to, original)
                    .await
                    .map_err(|error| error.code.as_str().to_owned());
            }
            Host::Metadata(_) => return Err("metadata_requires_typed_gap".into()),
        };
        let reader = self.host.capture_actor(&original).await?;
        let mut recorded = false;
        let mut after = reader.point().retained_from.saturating_sub(1);
        loop {
            let page = reader
                .local_export_page(
                    after,
                    events::MAX_SCAN_RECORDS as usize,
                    follow::BATCH_BYTES,
                )
                .await
                .map_err(|error| error.code.as_str().to_owned())?;
            for (_, committed) in page.records {
                if let kronik_proto::Record::AuditEvent(event) = &committed.record {
                    recorded |= event.action == "audit.gap"
                        && event.target == self.stream.name.as_ref()
                        && event.details.get("from") == Some(&from.to_string())
                        && event.details.get("to") == Some(&to.to_string());
                }
            }
            let SourcePos::Actor { lsn: head, .. } = reader.point().source else {
                return Err("webhook_source".into());
            };
            if page.scanned_through >= head {
                break;
            }
            if page.scanned_through <= after {
                return Err("webhook_source".into());
            }
            after = page.scanned_through;
        }
        if !recorded {
            node.record_audit_event_authorized(
                "audit.gap",
                self.stream.name.as_ref(),
                [
                    ("from".into(), from.to_string()),
                    ("to".into(), to.to_string()),
                ]
                .into(),
                pb::Audit {
                    token_id: "system".into(),
                    reason: "retention removed webhook source records".into(),
                    wall_time_ms: node.env().clock.wall_ms(),
                },
                original,
            )
            .await
            .map_err(|_| "webhook_gap".to_owned())?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct MetadataProgress {
    pub cursor: SourcePos,
    pub last_error: Option<String>,
    pub gaps: u64,
}

#[derive(Default)]
struct MetadataErrors {
    code: Option<String>,
    gaps: u64,
    last_gap: Option<events::Gap>,
}

/// A thin actual-metadata reader/control adapter, not an actor follower or queue.
pub struct MetadataStream {
    stream: Arc<Stream>,
    runtime: MetadataRuntime,
    cursors: Arc<Cursors>,
    source: Arc<dyn MetadataAuditSource>,
    gap_recorder: Arc<MetadataGapRecorder>,
    errors: Mutex<MetadataErrors>,
}

impl MetadataStream {
    pub fn stream(&self) -> &Arc<Stream> {
        &self.stream
    }
    pub fn enabled(&self) -> bool {
        self.stream.enabled
    }

    pub fn progress(&self) -> Result<MetadataProgress, ApiError> {
        let entry = self.cursors.get(self.stream.name.as_ref()).ok_or_else(|| {
            ApiError::new(ErrorCode::Unavailable, "metadata webhook cursor is missing")
        })?;
        let cursor = cursor_source(&entry)?;
        if !matches!(cursor, SourcePos::Metadata { .. }) {
            return Err(ApiError::new(
                ErrorCode::StorageCorrupt,
                "metadata webhook source changed",
            ));
        }
        let errors = match self.errors.lock() {
            Ok(errors) => errors,
            Err(error) => error.into_inner(),
        };
        Ok(MetadataProgress {
            cursor,
            last_error: errors.code.clone(),
            gaps: errors.gaps,
        })
    }

    /// The original request lease gates the existing owned rewind job's actual enqueue.
    pub async fn rewind(
        self: &Arc<Self>,
        to: Position,
        authority: kronik_core::authority::AuthLease,
    ) -> Result<(), ApiError> {
        let SourcePos::Metadata { index } = to.source else {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "metadata replay requires a metadata position",
            ));
        };
        if index == 0 || to.subindex != 0 {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "metadata replay must start at a record boundary",
            ));
        }
        let coverage = self.source.read_from(index, 1)?;
        let progress = self.progress()?;
        if index < coverage.covered_from || index > coverage.durable_through.saturating_add(1) {
            return Err(ApiError::new(
                ErrorCode::AuditRangeGone,
                "metadata replay is outside retained coverage",
            ));
        }
        if index - 1 > events::coordinate(progress.cursor) {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "metadata replay may only rewind",
            ));
        }
        self.stream
            .rewind_metadata(&self.runtime.env, index - 1, authority)
            .await?;
        Ok(())
    }

    fn failure(&self, code: String, gap: Option<events::Gap>) {
        let mut errors = match self.errors.lock() {
            Ok(errors) => errors,
            Err(error) => error.into_inner(),
        };
        errors.code = Some(code);
        if let Some(gap) = gap {
            if errors.last_gap.as_ref() != Some(&gap) {
                errors.gaps = errors.gaps.saturating_add(1);
                errors.last_gap = Some(gap);
            }
        }
    }

    fn success(&self) {
        let mut errors = match self.errors.lock() {
            Ok(errors) => errors,
            Err(error) => error.into_inner(),
        };
        errors.code = None;
    }
}

pub async fn start_metadata(
    runtime: MetadataRuntime,
    mapper: Arc<Mapper>,
    identity: Identity,
    stream: Arc<Stream>,
    cursors: Arc<Cursors>,
    settings: Settings,
    resolver: Arc<Resolver>,
    source: Arc<dyn MetadataAuditSource>,
    gap_recorder: Arc<MetadataGapRecorder>,
) -> Result<Arc<MetadataStream>, ApiError> {
    runtime.execution.check()?;
    let sink = Webhook::open_metadata(
        runtime.clone(),
        mapper,
        identity,
        stream.clone(),
        cursors.clone(),
        settings,
        resolver,
    )
    .await
    .map_err(|_| {
        ApiError::new(
            ErrorCode::Unavailable,
            "metadata webhook initialization failed",
        )
    })?;
    let shared = Arc::new(MetadataStream {
        stream,
        runtime: runtime.clone(),
        cursors,
        source,
        gap_recorder,
        errors: Mutex::default(),
    });
    shared.stream.own_task(
        runtime
            .env
            .spawn("metadata-webhook", follow_metadata(sink, shared.clone())),
    );
    Ok(shared)
}

async fn pause(
    env: &Env,
    stream: &Stream,
    changed: Pin<&mut Notified<'_>>,
    delay: Duration,
) -> bool {
    tokio::select! {
    biased;
    () = stream.stopped() => true, () = changed => true, () = env.clock.sleep(delay) => false }
}

async fn metadata_checkpoint(
    sink: &mut Webhook,
    shared: &MetadataStream,
    coordinate: u64,
    control: Option<Control>,
    original: &AuthLease,
) -> Result<Entry, String> {
    let source = SourcePos::Metadata { index: coordinate };
    let state = sink.checkpoint_value(source)?;
    let saved = advance_cursor(
        &shared.runtime.env,
        shared.stream.clone(),
        shared.cursors.clone(),
        Entry {
            lsn: coordinate,
            state,
            control,
        },
        original,
    )
    .await?;
    if cursor_source(&saved).map_err(|error| error.code.as_str().to_owned())? != source {
        return Err("webhook_source".into());
    }
    sink.accept_checkpoint(source);
    shared.success();
    Ok(saved)
}

async fn metadata_gap_checkpoint(
    sink: &mut Webhook,
    shared: &MetadataStream,
    position: u64,
    generation: Generation,
) -> Result<(), String> {
    let _control = shared.stream.control_guard().await;
    let current = shared
        .cursors
        .get(shared.stream.name.as_ref())
        .ok_or("webhook_state")?;
    if current.generation() != generation
        || current.lsn != position
        || current
            .pending_rewind()
            .is_some_and(|rewind| rewind.generation != generation)
    {
        return Ok(());
    }
    let source = SourcePos::Metadata { index: position };
    if cursor_source(&current).map_err(|error| error.code.as_str().to_owned())? != source
        || sink.state.source != source
        || sink.state.pending.is_some()
        || current
            .state
            .get("pending")
            .is_none_or(|pending| !pending.is_null())
    {
        return Err("webhook_state".into());
    }
    let from = position
        .checked_add(1)
        .ok_or("metadata_position_exhausted")?;
    // A new durable image, not the stale public page, authorizes the exact range.
    let coverage = events::metadata_batch(shared.source.as_ref(), from, 1)
        .map_err(|error| error.code.as_str().to_owned())?;
    if from >= coverage.covered_from {
        return Ok(());
    }
    let through = coverage.covered_from - 1;
    let receipt = (shared.gap_recorder)(
        MetadataAuditGap {
            stream: shared.stream.name.to_string(),
            from_index: from,
            through_index: through,
        },
        shared.runtime.execution.clone(),
    )
    .await
    .map_err(|error| error.code.as_str().to_owned())?;
    let valid_receipt = match receipt {
        SourcePos::Actor { shard, lsn } => {
            lsn > 0 && shard.is_none_or(|shard| shard < kronik_proto::MAX_SHARD_COUNT)
        }
        SourcePos::Metadata { index } => index > through,
    };
    if !valid_receipt {
        return Err("webhook_gap_receipt".into());
    }
    // A late durable rewind must survive even if it was written by another
    // controller while the producer completed its fsync.
    let latest = shared
        .cursors
        .get(shared.stream.name.as_ref())
        .ok_or("webhook_state")?;
    if latest.generation() != generation
        || latest.lsn != position
        || latest
            .pending_rewind()
            .is_some_and(|rewind| rewind.generation != generation)
    {
        return Ok(());
    }
    if cursor_source(&latest).map_err(|error| error.code.as_str().to_owned())? != source
        || latest
            .state
            .get("pending")
            .is_none_or(|pending| !pending.is_null())
    {
        return Err("webhook_state".into());
    }
    // Forward coverage loss is not a rewind: keep the current generation and
    // let the existing cursor writer merge any still-later control intent.
    metadata_checkpoint(
        sink,
        shared,
        through,
        latest.control,
        &shared.runtime.execution,
    )
    .await?;
    Ok(())
}

async fn follow_metadata(sink: Webhook, shared: Arc<MetadataStream>) {
    let execution = shared.runtime.execution.clone();
    tokio::select! {
        biased;
        () = execution.cancelled() => shared.failure("execution_revoked".into(), None),
        () = follow_metadata_live(sink, shared.clone()) => {},
    }
}

async fn follow_metadata_live(mut sink: Webhook, shared: Arc<MetadataStream>) {
    let env = shared.runtime.env.clone();
    let mut backoff = follow::FIRST_BACKOFF;
    'source: loop {
        if shared.stream.is_stopping() {
            return;
        }
        let changed = shared.stream.control_notification();
        tokio::pin!(changed);
        changed.as_mut().enable();
        let Some(mut entry) = shared.cursors.get(shared.stream.name.as_ref()) else {
            shared.failure("webhook_state".into(), None);
            pause(&env, &shared.stream, changed.as_mut(), backoff).await;
            backoff = backoff.saturating_mul(2).min(follow::MAX_BACKOFF);
            continue;
        };
        if entry
            .pending_rewind()
            .is_some_and(|rewind| rewind.generation != entry.generation())
        {
            let _control = shared.stream.control_guard().await;
            if let Some(latest) = shared.cursors.get(shared.stream.name.as_ref()) {
                entry = latest;
            }
            if let Some(rewind) = entry
                .pending_rewind()
                .filter(|rewind| rewind.generation != entry.generation())
            {
                sink.state.pending = None;
                match metadata_checkpoint(
                    &mut sink,
                    &shared,
                    rewind.to,
                    Some(Control::new(rewind.generation)),
                    &shared.runtime.execution,
                )
                .await
                {
                    Ok(_) => {
                        backoff = follow::FIRST_BACKOFF;
                        continue;
                    }
                    Err(code) => shared.failure(code, None),
                }
                drop(_control);
                pause(&env, &shared.stream, changed.as_mut(), backoff).await;
                backoff = backoff.saturating_mul(2).min(follow::MAX_BACKOFF);
                continue;
            }
        }
        let position = match cursor_source(&entry) {
            Ok(SourcePos::Metadata { index }) => index,
            _ => {
                shared.failure("webhook_source".into(), None);
                pause(&env, &shared.stream, changed.as_mut(), backoff).await;
                continue;
            }
        };
        let generation = entry.generation();
        if let Err(error) = shared.runtime.execution.check() {
            shared.failure(error.code.as_str().into(), None);
            return;
        }
        let Some(next) = position.checked_add(1) else {
            shared.failure("metadata_position_exhausted".into(), None);
            pause(&env, &shared.stream, changed.as_mut(), follow::MAX_BACKOFF).await;
            continue;
        };
        // Capture even a failure before reading: fixed gaps and empty coverage
        // need no values, but records can never acquire a newer certificate.
        let captured = (shared.runtime.catalogue)();
        let from = sink
            .state
            .pending
            .as_ref()
            .map_or(next, |batch| events::coordinate(batch.source));
        let image = match events::metadata_batch(shared.source.as_ref(), from, 1) {
            Ok(image) => image,
            Err(error) => {
                shared.failure(error.code.as_str().into(), None);
                pause(&env, &shared.stream, changed.as_mut(), backoff).await;
                backoff = backoff.saturating_mul(2).min(follow::MAX_BACKOFF);
                continue;
            }
        };
        if sink.state.pending.is_none() && from < image.covered_from {
            shared.failure(
                "AUDIT_RANGE_GONE".into(),
                Some(events::Gap {
                    from: SourcePos::Metadata { index: from },
                    through: SourcePos::Metadata {
                        index: image.covered_from - 1,
                    },
                }),
            );
            match metadata_gap_checkpoint(&mut sink, &shared, position, generation).await {
                Ok(()) => {
                    backoff = follow::FIRST_BACKOFF;
                    continue;
                }
                Err(code) => shared.failure(code, None),
            }
            pause(&env, &shared.stream, changed.as_mut(), backoff).await;
            backoff = backoff.saturating_mul(2).min(follow::MAX_BACKOFF);
            continue;
        }
        if sink.state.pending.is_none() && image.records.is_empty() {
            if from > image.durable_through.saturating_add(1) {
                shared.failure("webhook_source".into(), None);
            } else if image.scanned_through > position {
                if let Err(code) = metadata_checkpoint(
                    &mut sink,
                    &shared,
                    image.scanned_through,
                    entry.control,
                    &shared.runtime.execution,
                )
                .await
                {
                    shared.failure(code, None);
                }
            }
            pause(
                &env,
                &shared.stream,
                changed.as_mut(),
                Duration::from_millis(100),
            )
            .await;
            continue;
        }
        let (snapshot, publication) = match captured {
            Ok(pair) => pair,
            Err(error) => {
                shared.failure(error.code.as_str().into(), None);
                pause(&env, &shared.stream, changed.as_mut(), backoff).await;
                backoff = backoff.saturating_mul(2).min(follow::MAX_BACKOFF);
                continue;
            }
        };
        let authorization = follow::metadata_records(
            &shared.stream,
            snapshot.clone(),
            publication,
            shared.runtime.execution.clone(),
        );
        let secrets: Vec<_> = snapshot
            .values
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_slice()))
            .collect();
        let batch = if sink.state.pending.is_some() {
            sink.pending_metadata(image, generation, &secrets)
        } else {
            let mut cursor = ResumeCursor::new(sink.state.identity.clone());
            if cursor
                .rewind(Position {
                    source: SourcePos::Metadata { index: next },
                    subindex: 0,
                })
                .is_err()
            {
                shared.failure("webhook_source".into(), None);
                pause(&env, &shared.stream, changed.as_mut(), backoff).await;
                continue;
            }
            let page = match events::metadata_page_from_batch(
                image,
                &sink.mapper,
                &sink.state.identity,
                &cursor,
                &secrets,
                1,
            ) {
                Ok(page) => page,
                Err(error) => {
                    shared.failure(error.code.as_str().into(), None);
                    pause(&env, &shared.stream, changed.as_mut(), backoff).await;
                    backoff = backoff.saturating_mul(2).min(follow::MAX_BACKOFF);
                    continue;
                }
            };
            if page.events.is_empty() {
                let Some(position) = page.cursor.streams.get("metadata") else {
                    shared.failure("webhook_source".into(), None);
                    continue;
                };
                let through = events::coordinate(position.source).saturating_sub(1);
                if let Err(code) =
                    metadata_checkpoint(&mut sink, &shared, through, entry.control, &authorization)
                        .await
                {
                    shared.failure(code, None);
                }
                pause(
                    &env,
                    &shared.stream,
                    changed.as_mut(),
                    Duration::from_millis(100),
                )
                .await;
                continue;
            }
            sink.prepare_metadata(page, generation).await
        };
        let batch = match batch {
            Ok(batch) => batch,
            Err(code) => {
                shared.failure(code, None);
                pause(&env, &shared.stream, changed.as_mut(), backoff).await;
                backoff = backoff.saturating_mul(2).min(follow::MAX_BACKOFF);
                continue;
            }
        };
        if shared
            .cursors
            .get(shared.stream.name.as_ref())
            .is_some_and(|latest| {
                latest
                    .pending_rewind()
                    .is_some_and(|rewind| rewind.generation != generation)
            })
        {
            continue;
        }
        // An admitted delivery owns its bounded completion; a rewind must not
        // detach its pending fsync or HTTP body and then reuse this sink.
        let delivery = sink.deliver(&batch, authorization.clone()).await;
        match delivery {
            Delivery::Delivered => {}
            Delivery::Retry { code, after } => {
                shared.failure(code, None);
                let delay = after.map_or(backoff, |delay| delay.min(follow::MAX_RETRY_AFTER));
                pause(&env, &shared.stream, changed.as_mut(), delay).await;
                backoff = backoff.saturating_mul(2).min(follow::MAX_BACKOFF);
                continue;
            }
            Delivery::Dropped { code } => {
                shared.failure(code, None);
                pause(&env, &shared.stream, changed.as_mut(), backoff).await;
                continue;
            }
        }
        // Freeze the remote ACK while local durability retries; never repost it here.
        loop {
            if shared
                .cursors
                .get(shared.stream.name.as_ref())
                .is_some_and(|latest| {
                    latest
                        .pending_rewind()
                        .is_some_and(|rewind| rewind.generation != generation)
                })
            {
                continue 'source;
            }
            match metadata_checkpoint(
                &mut sink,
                &shared,
                events::coordinate(batch.through),
                entry.control,
                &authorization,
            )
            .await
            {
                Ok(_) => {
                    backoff = follow::FIRST_BACKOFF;
                    continue 'source;
                }
                Err(code) => shared.failure(code, None),
            }
            if pause(&env, &shared.stream, changed.as_mut(), backoff).await {
                continue 'source;
            }
            backoff = backoff.saturating_mul(2).min(follow::MAX_BACKOFF);
        }
    }
}
