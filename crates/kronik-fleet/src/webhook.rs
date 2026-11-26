//! Signed delivery from actual actor sources, using the same durable M28
//! cursor, replay generations, prepared bodies, immutable secret pin and Net.

use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use kronik_core::authority::AuthLease;
use kronik_core::env::Env;
use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::ids::{SourcePos, hex};
use kronik_log::{Committed, MetadataWebhookKeyChange};
use kronik_otel::{
    audit::Mapper,
    cursor::{Cursors, Entry, Generation},
    follow::{self, Delivery, Sink, Stream},
    http,
};
use kronik_proto::log::v1 as pb;
use kronik_sched::{
    Node, ShardReader,
    secrets::{CertifiedSecretSnapshot, SecretSnapshotPublication},
};
use serde::{Deserialize, Serialize};

use crate::events::{self, Event, Identity, Position, ResumeCursor};

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

struct Host {
    node: Arc<Node>,
    execution: AuthLease,
}

impl Host {
    fn env(&self) -> &Env {
        self.node.env()
    }

    fn execution(&self) -> &AuthLease {
        &self.execution
    }

    fn catalogue(
        &self,
    ) -> Result<(Arc<CertifiedSecretSnapshot>, SecretSnapshotPublication), ApiError> {
        self.node.native_secret_snapshot_with_publication()
    }

    async fn capture_actor(&self, original: &AuthLease) -> Result<Arc<ShardReader>, String> {
        original
            .check()
            .map_err(|error| error.code.as_str().to_owned())?;
        let reader = tokio::select! {
            biased;
            () = original.cancelled() => return Err("execution_revoked".into()),
            reader = self.node.capture_system_export_reader() => reader,
        }
        .map(Arc::new)
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
        let details = [
            ("change".into(), "webhook.signing_key".into()),
            ("source".into(), events::domain(binding).into_owned()),
            ("from_version".into(), change.from_version.to_string()),
            ("to_version".into(), change.to_version.to_string()),
        ]
        .into();
        self.node
            .record_audit_event_authorized(
                "audit.config",
                &change.stream,
                details,
                pb::Audit {
                    token_id: "system".into(),
                    reason: "the configured webhook signing version changed".into(),
                    wall_time_ms: self.node.env().clock.wall_ms(),
                },
                self.execution.clone(),
            )
            .await
            .map_err(|_| "webhook_config_audit".to_owned())?;
        Ok(())
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
        if events::domain(state.source) != events::domain(batch.source)
            || events::domain(batch.source) != events::domain(batch.through)
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
    // The webhook stream's opening inputs; grouping them would only move
    // the same names into a struct every caller unpacks again.
    #[allow(clippy::too_many_arguments)]
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
            Host { node, execution },
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

    // The webhook stream's opening inputs.
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
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
        let mut entry = cursors.get(stream.name.as_ref()).unwrap_or_default();
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
        if events::domain(self.state.source) != events::domain(source)
            || events::domain(source) != events::domain(through)
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

    fn checkpoint_value(&self, source: SourcePos) -> Result<serde_json::Value, String> {
        if events::domain(self.state.source) != events::domain(source) {
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
        let node = &self.host.node;
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
