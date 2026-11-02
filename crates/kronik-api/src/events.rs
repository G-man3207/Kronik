//! Operational events retain their actual actor or metadata source namespace.

use std::collections::BTreeMap;
use std::sync::Arc;

use kronik_core::authority::AuthLease;
use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::ids::SourcePos;
use kronik_fleet::events::{self, Identity, Page, Position, ResumeCursor};
use kronik_fleet::webhook::{MetadataCatalogue, MetadataStream};
use kronik_log::MetadataAuditSource;
use kronik_otel::audit::{Keys, Mapper};
use kronik_otel::follow::{RetainedDisclosure, Stream};
use kronik_sched::secrets::{CertifiedSecretSnapshot, SecretSnapshotPublication};
use kronik_sched::{Node, ShardReader};
use serde::{Deserialize, Serialize};

use crate::{Api, ApiResponse, Query, Result, internal, json, ok, reason};

/// Canonical HTTP endpoints served by the event streaming transport.
pub const STREAM_PATHS: [&str; 2] = ["/v1/events/stream", "/v1/events/ws"];

/// Ordinary user replay audit; the original lease, never Audit text, authorizes admission.
/// The host's ordinary durable producer scrubs/withholds free audit text before
/// persistence; no actor Node or catalogue is a substitute metadata authority.
pub type MetadataReplayRecorder = dyn Fn(
        kronik_log::MetadataWebhookReplay,
        kronik_proto::log::v1::Audit,
        kronik_core::authority::AuthLease,
    ) -> kronik_core::env::BoxFuture<'static, Result<SourcePos>>
    + Send
    + Sync;

#[derive(Clone)]
pub enum WebhookTarget {
    Native {
        stream: Arc<Stream>,
    },
    Registered {
        source: SourcePos,
        stream: Arc<Stream>,
        rewind: Arc<
            dyn Fn(u64, AuthLease) -> kronik_core::env::BoxFuture<'static, Result<()>>
                + Send
                + Sync,
        >,
    },
    Metadata {
        stream: Arc<MetadataStream>,
        record_replay: Arc<MetadataReplayRecorder>,
    },
}

impl WebhookTarget {
    fn source(&self) -> Result<SourcePos> {
        Ok(match self {
            Self::Native { .. } => SourcePos::Actor {
                shard: None,
                lsn: 1,
            },
            Self::Registered { source, .. } => match source {
                SourcePos::Actor { shard, .. } => SourcePos::Actor {
                    shard: *shard,
                    lsn: 1,
                },
                SourcePos::Metadata { .. } => {
                    return Err(bad("webhook actor source is unavailable"));
                }
            },
            Self::Metadata { .. } => SourcePos::Metadata { index: 1 },
        })
    }
}

struct MetadataFeed {
    source: Arc<dyn MetadataAuditSource>,
    sealer: Arc<kronik_privacy::sealer::Sealer>,
    catalogue: Arc<MetadataCatalogue>,
}

pub enum ActorFeed {
    Native(Arc<Node>),
    Registered {
        shard: Option<u32>,
        sealer: Arc<kronik_privacy::sealer::Sealer>,
        catalogue: Arc<MetadataCatalogue>,
        capture: Arc<
            dyn Fn(AuthLease) -> kronik_core::env::BoxFuture<'static, Result<Arc<ShardReader>>>
                + Send
                + Sync,
        >,
    },
}

impl ActorFeed {
    fn catalogue(&self) -> Result<(Arc<CertifiedSecretSnapshot>, SecretSnapshotPublication)> {
        match self {
            Self::Native(node) => node.native_secret_snapshot_with_publication(),
            Self::Registered { catalogue, .. } => catalogue(),
        }
    }

    async fn capture(&self, original: AuthLease) -> Result<Arc<ShardReader>> {
        original.check()?;
        let reader = match self {
            Self::Native(node) => Arc::new(tokio::select! {
                biased;
                () = original.cancelled() => return Err(ApiError::new(ErrorCode::Unauthenticated,
                    "event source authority was revoked before capture")),
                reader = node.capture_system_export_reader() => reader?,
            }),
            Self::Registered { capture, .. } => capture(original.clone()).await?,
        };
        original.check()?;
        Ok(reader)
    }
}

pub struct Events {
    pub identity: Identity,
    // Keys are derived from trusted typed bindings, never parsed into authority.
    sources: BTreeMap<String, ActorFeed>,
    metadata: Option<MetadataFeed>,
    webhooks: BTreeMap<String, WebhookTarget>,
}

enum PreparedEventSource {
    Actor(Arc<ShardReader>),
    Metadata,
}

/// One request's held source and certified values, captured before its public
/// read publication. Rendering consumes this preparation without recapturing.
pub(crate) struct PreparedEventPage {
    feed: Arc<Events>,
    source: PreparedEventSource,
    snapshot: Arc<CertifiedSecretSnapshot>,
    mapper: Mapper,
    disclosure: AuthLease,
}

impl PreparedEventPage {
    pub(crate) async fn response(
        self,
        q: &Query,
        header_cursor: Option<&str>,
    ) -> Result<ApiResponse> {
        let cursor = self.feed.cursor(header_cursor.or(q.get("cursor")))?;
        let limit = q.num("limit")?.unwrap_or(100);
        if limit == 0 || limit > events::MAX_EVENTS as u64 {
            return Err(bad("event limit must be between 1 and 256"));
        }
        ok(&self.read(&cursor, limit as usize).await?)
    }

    pub(crate) async fn read(self, cursor: &ResumeCursor, limit: usize) -> Result<Page> {
        self.disclosure.check()?;
        let patterns = self
            .snapshot
            .values
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_slice()))
            .collect::<Vec<_>>();
        match &self.source {
            PreparedEventSource::Actor(reader) => tokio::select! {
                biased;
                () = self.disclosure.cancelled() => Err(ApiError::new(ErrorCode::Unauthenticated,
                    "event page authority was revoked while reading")),
                page = events::page(reader, &self.mapper, &self.feed.identity, cursor, &patterns, limit) => page,
            },
            PreparedEventSource::Metadata => {
                let feed = self
                    .feed
                    .metadata
                    .as_ref()
                    .ok_or_else(|| bad("metadata events are unavailable"))?;
                events::metadata_page(
                    feed.source.as_ref(),
                    &self.mapper,
                    &self.feed.identity,
                    cursor,
                    &patterns,
                    limit,
                )
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReplayRequest {
    pub cursor: ResumeCursor,
    pub reason: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct WebhookStatus {
    pub name: String,
    pub enabled: bool,
    pub cursor: SourcePos,
    pub last_error: Option<String>,
    pub gaps: u64,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct WebhooksResponse {
    pub webhooks: Vec<WebhookStatus>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ReplayResponse {
    pub dry_run: bool,
    pub cursor: ResumeCursor,
}

impl Events {
    pub fn native(identity: Identity, node: Arc<Node>) -> Result<Self> {
        identity
            .validate()
            .map_err(|_| bad("invalid event installation identity"))?;
        if node.branch() != identity.branch {
            return Err(bad("event sources must belong to the installation branch"));
        }
        Ok(Self {
            identity,
            sources: [("actor-native".to_owned(), ActorFeed::Native(node))].into(),
            metadata: None,
            webhooks: BTreeMap::new(),
        })
    }

    pub fn registered(identity: Identity, registered: Vec<ActorFeed>) -> Result<Self> {
        identity
            .validate()
            .map_err(|_| bad("invalid event installation identity"))?;
        if registered.is_empty() {
            return Err(bad("registered actor event sources are unavailable"));
        }
        let mut sources = BTreeMap::new();
        for feed in registered {
            let ActorFeed::Registered { shard, .. } = &feed else {
                return Err(bad("registered event source is not an actor source"));
            };
            let name = events::domain(SourcePos::Actor {
                shard: *shard,
                lsn: 1,
            })
            .into_owned();
            if sources.insert(name, feed).is_some() {
                return Err(bad("an actor event source is registered more than once"));
            }
        }
        Ok(Self {
            identity,
            sources,
            metadata: None,
            webhooks: BTreeMap::new(),
        })
    }

    pub fn metadata(
        identity: Identity,
        source: Arc<dyn MetadataAuditSource>,
        sealer: Arc<kronik_privacy::sealer::Sealer>,
        catalogue: Arc<MetadataCatalogue>,
    ) -> Result<Self> {
        identity
            .validate()
            .map_err(|_| bad("invalid event installation identity"))?;
        Ok(Self {
            identity,
            sources: BTreeMap::new(),
            metadata: Some(MetadataFeed {
                source,
                sealer,
                catalogue,
            }),
            webhooks: BTreeMap::new(),
        })
    }

    pub fn with_metadata(
        mut self,
        source: Arc<dyn MetadataAuditSource>,
        sealer: Arc<kronik_privacy::sealer::Sealer>,
        catalogue: Arc<MetadataCatalogue>,
    ) -> Self {
        self.metadata = Some(MetadataFeed {
            source,
            sealer,
            catalogue,
        });
        self
    }

    pub fn with_webhooks(mut self, webhooks: BTreeMap<String, WebhookTarget>) -> Result<Self> {
        for target in webhooks.values() {
            match target {
                WebhookTarget::Native { .. } => {
                    if !matches!(self.sources.get("actor-native"), Some(ActorFeed::Native(_))) {
                        return Err(bad("webhook native source is unavailable"));
                    }
                }
                WebhookTarget::Registered { .. } => {
                    let domain = events::domain(target.source()?);
                    if !matches!(
                        self.sources.get(domain.as_ref()),
                        Some(ActorFeed::Registered { .. })
                    ) {
                        return Err(bad(
                            "webhook stream does not belong to its registered source",
                        ));
                    }
                }
                WebhookTarget::Metadata { .. } if self.metadata.is_none() => {
                    return Err(bad("webhook metadata source is unavailable"));
                }
                WebhookTarget::Metadata { .. } => {}
            }
        }
        self.webhooks = webhooks;
        Ok(self)
    }

    pub fn source_names(&self) -> impl Iterator<Item = &str> {
        self.sources
            .keys()
            .map(String::as_str)
            .chain(self.metadata.as_ref().map(|_| "metadata"))
    }

    pub fn cursor(&self, raw: Option<&str>) -> Result<ResumeCursor> {
        let cursor = match raw {
            Some(raw) if raw.len() <= events::MAX_CURSOR_BYTES => {
                serde_json::from_str(raw).map_err(|_| bad("invalid event resume cursor"))?
            }
            Some(_) => return Err(bad("event resume cursor is too large")),
            None => ResumeCursor::new(self.identity.clone()),
        };
        cursor
            .validate(&self.identity)
            .map_err(|_| bad("event cursor belongs to another installation or branch"))?;
        if cursor.streams.keys().any(|source| {
            !self.sources.contains_key(source) && !(source == "metadata" && self.metadata.is_some())
        }) {
            return Err(bad("event cursor names an unavailable source"));
        }
        Ok(cursor)
    }

    /// The returned existing M28 guard is the request's complete attenuated
    /// original. Bind it before public-read admission; never wrap it again with
    /// the same catalogue publication or take another snapshot while rendering.
    pub(crate) async fn prepare(
        self: &Arc<Self>,
        source: &str,
        original: AuthLease,
    ) -> Result<(PreparedEventPage, AuthLease)> {
        original.check()?;
        let (snapshot, prepared_source, sealer, disclosure) = if source == "metadata" {
            let feed = self
                .metadata
                .as_ref()
                .ok_or_else(|| bad("metadata events are unavailable"))?;
            let (snapshot, publication) = (feed.catalogue)()?;
            let disclosure =
                RetainedDisclosure::metadata_response(snapshot.clone(), publication, original);
            (
                snapshot,
                PreparedEventSource::Metadata,
                feed.sealer.clone(),
                disclosure,
            )
        } else {
            let feed = self
                .sources
                .get(source)
                .ok_or_else(|| bad("unknown event source"))?;
            let (snapshot, publication) = feed.catalogue()?;
            let reader = feed.capture(original.clone()).await?;
            if events::domain(reader.point().source).as_ref() != source {
                return Err(bad("captured event reader belongs to another source"));
            }
            let sealer = match feed {
                ActorFeed::Native(node) => node.sealer().clone(),
                ActorFeed::Registered { sealer, .. } => sealer.clone(),
            };
            let disclosure =
                RetainedDisclosure::native(reader.clone(), snapshot.clone(), publication, original);
            (
                snapshot,
                PreparedEventSource::Actor(reader),
                sealer,
                disclosure,
            )
        };
        disclosure.check()?;
        let mapper = Mapper {
            keys: Keys::Omit,
            sealer,
            branch: self.identity.branch.clone(),
        };
        let prepared = PreparedEventPage {
            feed: self.clone(),
            source: prepared_source,
            snapshot,
            mapper,
            disclosure: disclosure.clone(),
        };
        Ok((prepared, disclosure))
    }

    pub async fn page(
        self: &Arc<Self>,
        cursor: &ResumeCursor,
        source: &str,
        limit: usize,
        original: AuthLease,
    ) -> Result<(Page, AuthLease)> {
        let (prepared, disclosure) = self.prepare(source, original).await?;
        let page = prepared.read(cursor, limit).await?;
        Ok((page, disclosure))
    }

    fn status(&self) -> Result<WebhooksResponse> {
        let mut webhooks = Vec::with_capacity(self.webhooks.len());
        for (name, target) in &self.webhooks {
            let status = match target {
                WebhookTarget::Native { stream } | WebhookTarget::Registered { stream, .. } => {
                    let progress = stream.progress();
                    let SourcePos::Actor { shard, .. } = target.source()? else {
                        return Err(bad("webhook actor source is unavailable"));
                    };
                    WebhookStatus {
                        name: name.clone(),
                        enabled: stream.enabled,
                        cursor: SourcePos::Actor {
                            shard,
                            lsn: progress.cursor,
                        },
                        last_error: progress.last_error,
                        gaps: progress.gaps,
                    }
                }
                WebhookTarget::Metadata { stream, .. } => {
                    let progress = stream.progress()?;
                    WebhookStatus {
                        name: name.clone(),
                        enabled: stream.enabled(),
                        cursor: progress.cursor,
                        last_error: progress.last_error,
                        gaps: progress.gaps,
                    }
                }
            };
            webhooks.push(status);
        }
        Ok(WebhooksResponse { webhooks })
    }

    async fn validate_replay(
        &self,
        target: &WebhookTarget,
        cursor: &ResumeCursor,
        original: AuthLease,
    ) -> Result<Position> {
        original.check()?;
        let source = target.source()?;
        let position = *cursor
            .streams
            .get(events::domain(source).as_ref())
            .ok_or_else(|| bad("replay cursor lacks the webhook source"))?;
        if position.subindex != 0 {
            return Err(bad("webhook replay must begin at a record boundary"));
        }
        match target {
            WebhookTarget::Native { stream } | WebhookTarget::Registered { stream, .. } => {
                let feed = self
                    .sources
                    .get(events::domain(source).as_ref())
                    .ok_or_else(|| bad("webhook actor source is unavailable"))?;
                let reader = feed.capture(original.clone()).await?;
                let SourcePos::Actor {
                    shard,
                    lsn: through,
                } = reader.point().source
                else {
                    return Err(bad("invalid captured actor replay source"));
                };
                let SourcePos::Actor {
                    shard: requested_shard,
                    lsn,
                } = position.source
                else {
                    return Err(bad("invalid actor replay source"));
                };
                if shard != requested_shard
                    || events::domain(reader.point().source) != events::domain(source)
                {
                    return Err(bad("captured replay reader belongs to another source"));
                }
                if lsn < reader.point().retained_from.max(1) || lsn > through.saturating_add(1) {
                    return Err(range_gone());
                }
                if lsn - 1 > stream.progress().cursor {
                    return Err(bad("webhook replay may only rewind"));
                }
            }
            WebhookTarget::Metadata { stream, .. } => {
                let feed = self
                    .metadata
                    .as_ref()
                    .ok_or_else(|| bad("metadata events are unavailable"))?;
                let (snapshot, publication) = (feed.catalogue)()?;
                let disclosure =
                    RetainedDisclosure::metadata_response(snapshot, publication, original.clone());
                disclosure.check()?;
                let SourcePos::Metadata { index } = position.source else {
                    return Err(bad("invalid metadata replay source"));
                };
                let coverage = feed.source.read_from(index, 1)?;
                if index < coverage.covered_from
                    || index > coverage.durable_through.saturating_add(1)
                {
                    return Err(range_gone());
                }
                if index - 1 > events::coordinate(stream.progress()?.cursor) {
                    return Err(bad("webhook replay may only rewind"));
                }
            }
        }
        original.check()?;
        Ok(position)
    }
}
impl Api {
    pub fn with_events(mut self, installation: String) -> Result<Self> {
        let identity = Identity {
            installation,
            branch: self.node.branch().to_owned(),
        };
        self.events = Some(Arc::new(Events::native(identity, self.node.clone())?));
        Ok(self)
    }

    pub fn with_event_feed(mut self, events: Arc<Events>) -> Self {
        self.events = Some(events);
        self
    }

    pub fn with_event_webhooks(mut self, webhooks: BTreeMap<String, Arc<Stream>>) -> Result<Self> {
        let feed = self
            .events
            .as_mut()
            .and_then(Arc::get_mut)
            .ok_or_else(|| bad("configure event webhooks before publishing the event feed"))?;
        if !matches!(feed.sources.get("actor-native"), Some(ActorFeed::Native(_))) {
            return Err(bad("native actor event source is unavailable"));
        }
        feed.webhooks.extend(
            webhooks
                .into_iter()
                .map(|(name, stream)| (name, WebhookTarget::Native { stream })),
        );
        Ok(self)
    }

    pub fn with_metadata_events(
        mut self,
        source: Arc<dyn MetadataAuditSource>,
        sealer: Arc<kronik_privacy::sealer::Sealer>,
        catalogue: Arc<MetadataCatalogue>,
        webhooks: BTreeMap<String, (Arc<MetadataStream>, Arc<MetadataReplayRecorder>)>,
    ) -> Result<Self> {
        let feed = self
            .events
            .as_mut()
            .and_then(Arc::get_mut)
            .ok_or_else(|| bad("configure metadata events before publishing the event feed"))?;
        feed.metadata = Some(MetadataFeed {
            source,
            sealer,
            catalogue,
        });
        feed.webhooks
            .extend(webhooks.into_iter().map(|(name, (stream, record_replay))| {
                (
                    name,
                    WebhookTarget::Metadata {
                        stream,
                        record_replay,
                    },
                )
            }));
        Ok(self)
    }

    pub(crate) fn event_feed(&self) -> Result<Arc<Events>> {
        self.events.clone().ok_or_else(|| {
            ApiError::new(
                ErrorCode::Unavailable,
                "operational events are not configured",
            )
        })
    }

    pub(crate) async fn event_page_response(
        &self,
        query: &Query,
        header_cursor: Option<&str>,
        original: AuthLease,
    ) -> Result<(ApiResponse, AuthLease)> {
        original.check()?;
        let feed = self.event_feed()?;
        let source = query
            .get("source")
            .or_else(|| feed.source_names().next())
            .ok_or_else(|| {
                ApiError::new(ErrorCode::Unavailable, "event sources are unavailable")
            })?;
        let (prepared, original) = feed.prepare(source, original).await?;
        let response = prepared.response(query, header_cursor).await?;
        original.check()?;
        Ok((response, original))
    }

    pub(crate) async fn event_page(
        &self,
        req: &crate::AuthorizedRequest,
        query: &Query,
    ) -> Result<ApiResponse> {
        let (response, original) = self
            .event_page_response(query, None, req.authority.clone())
            .await?;
        self.node
            .authorized_effect(original, move || async move { Ok(response) })
            .await
    }

    pub(crate) fn event_schemas(&self) -> Result<ApiResponse> {
        ok(&events::schemas().map_err(internal)?)
    }
    pub(crate) fn event_webhooks(&self) -> Result<ApiResponse> {
        self.ok_scrubbed(self.event_feed()?.status()?)
    }

    pub(crate) async fn event_replay(
        &self,
        req: &crate::AuthorizedRequest,
        name: &str,
    ) -> Result<ApiResponse> {
        let request: ReplayRequest = json(&req.body)?;
        reason(&request.reason)?;
        let feed = self.event_feed()?;
        let encoded = serde_json::to_string(&request.cursor).map_err(internal)?;
        let cursor = feed.cursor(Some(&encoded))?;
        let target = feed
            .webhooks
            .get(name)
            .ok_or_else(|| bad("unknown event webhook"))?;
        let position = feed
            .validate_replay(target, &cursor, req.authority.clone())
            .await?;
        req.authority.check()?;
        if !request.dry_run {
            match target.clone() {
                WebhookTarget::Native { stream } => {
                    let Some(ActorFeed::Native(node)) = feed.sources.get("actor-native") else {
                        return Err(bad("webhook native source is unavailable"));
                    };
                    let details = [("source", events::domain(position.source).into_owned()),
                        ("position", events::coordinate(position.source).to_string())];
                    self.audit_event(req, "events.webhook.replay", name, &details, request.reason.clone()).await?;
                    if let Err(error) = stream.rewind(node, events::coordinate(position.source) - 1,
                        req.authority.clone()).await {
                        let mut failed = details.to_vec();
                        failed.push(("code", error.code.as_str().to_owned()));
                        let _ = self.audit_event(req, "events.webhook.replay.failed", name, &failed,
                            request.reason.clone()).await;
                        return Err(error);
                    }
                }
                WebhookTarget::Registered { .. } => return Err(ApiError::new(ErrorCode::Unavailable,
                    "registered webhook replay requires its actual metadata-owned member receiver")
                    .with_hint("Use the registered source's ordinary member API; a native node cannot supply its metadata receipt.")),
                WebhookTarget::Metadata { stream, record_replay } => {
                    let audit = self.audit(req, request.reason);
                    let receipt = record_replay(kronik_log::MetadataWebhookReplay {
                        stream: format!("events-{name}"), from_index: events::coordinate(position.source),
                    }, audit, req.authority.clone()).await?;
                    if !matches!(receipt, SourcePos::Metadata { index } if index > 0 && index <= i64::MAX as u64) {
                        return Err(internal("metadata replay audit returned an invalid source receipt"));
                    }
                    stream.rewind(position, req.authority.clone()).await?;
                }
            }
        }
        ok(&ReplayResponse {
            dry_run: request.dry_run,
            cursor,
        })
    }
}

fn bad(message: &str) -> ApiError {
    ApiError::new(ErrorCode::BadRequest, message)
}
fn range_gone() -> ApiError {
    ApiError::new(
        ErrorCode::AuditRangeGone,
        "webhook replay position is outside retained history",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct UnreadMetadata(AtomicUsize);
    impl MetadataAuditSource for UnreadMetadata {
        fn read_from(&self, _: u64, _: usize) -> Result<kronik_log::MetadataAuditBatch> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Err(ApiError::new(
                ErrorCode::StorageCorrupt,
                "metadata must not be inspected before privacy certification",
            ))
        }
    }

    #[tokio::test]
    async fn metadata_without_actors_holds_before_reading_uncertified_records() {
        // The node supplies only the ordinary local request authority. The
        // metadata feed owns no Actor source and has no native-catalogue fallback.
        let data = tempfile::tempdir().unwrap();
        let node = kronik_sched::start_local(
            kronik_core::env::Env::real(tokio::runtime::Handle::current()),
            data.path(),
            kronik_sched::NodeConfig::default(),
        )
        .await
        .unwrap();
        let api = Api::new(node);
        let request = crate::ApiRequest {
            method: "GET".into(),
            path: "/v1/events".into(),
            query: "source=metadata".into(),
            body: Vec::new(),
            token_id: "unix:uid=0".into(),
            bearer: None,
        };
        let captured = api.capture(&request).unwrap();
        let source = Arc::new(UnreadMetadata(AtomicUsize::new(0)));
        let identity = Identity {
            installation: "owned-no-actor".into(),
            branch: "main".into(),
        };
        let feed = Arc::new(
            Events::metadata(
                identity.clone(),
                source.clone(),
                Arc::new(kronik_privacy::sealer::Sealer::plain()),
                Arc::new(|| {
                    Err(ApiError::new(
                        ErrorCode::SecretUnavailable,
                        "physical catalogue is not certified",
                    ))
                }),
            )
            .unwrap(),
        );
        let error = feed
            .page(
                &ResumeCursor::new(identity),
                "metadata",
                1,
                captured.authority().clone(),
            )
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::SecretUnavailable);
        assert_eq!(source.0.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn metadata_preparation_consumes_its_original_certified_native_fixture_without_recapture()
    {
        struct EmptyMetadata(AtomicUsize);
        impl MetadataAuditSource for EmptyMetadata {
            fn read_from(&self, _: u64, _: usize) -> Result<kronik_log::MetadataAuditBatch> {
                self.0.fetch_add(1, Ordering::Relaxed);
                // Empty unit coverage, not a metadata Raft commit proof.
                Ok(kronik_log::MetadataAuditBatch {
                    covered_from: 1,
                    durable_through: 0,
                    scanned_through: 0,
                    records: Vec::new(),
                })
            }
        }
        let data = tempfile::tempdir().unwrap();
        let node = kronik_sched::start_local(
            kronik_core::env::Env::real(tokio::runtime::Handle::current()),
            data.path(),
            kronik_sched::NodeConfig::default(),
        )
        .await
        .unwrap();
        let operator = node.local_operator_authority().unwrap();
        // The startup background cycle races this first refresh for the
        // inventory lock on a current-thread runtime; retry until stable
        // (the documented fail-closed window, as the CLI does).
        let mut refreshed = None;
        for _ in 0..100 {
            match node.refresh_secret_inventory(operator.clone()).await {
                Ok(()) => {
                    refreshed = Some(());
                    break;
                }
                Err(error) if error.code == ErrorCode::SecretUnavailable => {
                    node.env()
                        .clock
                        .sleep(std::time::Duration::from_millis(50))
                        .await;
                }
                Err(error) => panic!("refresh failed: {error}"),
            }
        }
        assert!(refreshed.is_some(), "the catalogue never certified");
        // The certified snapshot may still be mid-rebuild (the background
        // cycle's clear-then-rebuild window is fail-closed); retry the read
        // within the documented window instead of racing it.
        let fingerprint = {
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
            loop {
                match node.native_secret_snapshot() {
                    Ok(snapshot) => break snapshot.fingerprint,
                    Err(error) if error.code == ErrorCode::SecretUnavailable => {
                        assert!(
                            tokio::time::Instant::now() < deadline,
                            "the catalogue never recertified: {error}"
                        );
                        node.env()
                            .clock
                            .sleep(std::time::Duration::from_millis(100))
                            .await;
                    }
                    Err(error) => panic!("snapshot failed: {error}"),
                }
            }
        };
        let api = Api::new(node.clone());
        let request = crate::ApiRequest {
            method: "GET".into(),
            path: "/v1/events".into(),
            query: "source=metadata".into(),
            body: Vec::new(),
            token_id: "unix:uid=0".into(),
            bearer: None,
        };
        let captured = api.capture(&request).unwrap();
        let source = Arc::new(EmptyMetadata(AtomicUsize::new(0)));
        let catalogues = Arc::new(AtomicUsize::new(0));
        let catalogue_count = catalogues.clone();
        let catalogue_node = node.clone();
        let identity = Identity {
            installation: "owned-no-actor".into(),
            branch: "metadata".into(),
        };
        // The catalogue is a real native unit fixture, explicitly not a Member
        // global-source proof. No native Actor is registered on this feed.
        let feed = Arc::new(
            Events::metadata(
                identity.clone(),
                source.clone(),
                node.sealer().clone(),
                Arc::new(move || {
                    catalogue_count.fetch_add(1, Ordering::Relaxed);
                    catalogue_node.native_secret_snapshot_with_publication()
                }),
            )
            .unwrap(),
        );
        assert_eq!(feed.source_names().collect::<Vec<_>>(), ["metadata"]);
        let cursor = ResumeCursor::new(identity);
        let (prepared, disclosure) = feed
            .prepare("metadata", captured.authority().clone())
            .await
            .unwrap();
        assert_eq!(catalogues.load(Ordering::Relaxed), 1);
        node.refresh_secret_inventory(operator).await.unwrap();
        assert_eq!(
            fingerprint,
            node.native_secret_snapshot().unwrap().fingerprint
        );
        assert!(captured.authority().check().is_ok());
        assert!(disclosure.check().is_err());
        assert!(prepared.read(&cursor, 1).await.is_err());
        assert_eq!(
            catalogues.load(Ordering::Relaxed),
            1,
            "rendering must not refresh the saved catalogue"
        );
        assert_eq!(
            source.0.load(Ordering::Relaxed),
            0,
            "an obsolete preparation must not read metadata"
        );

        let next = api.capture(&request).unwrap();
        let (prepared, disclosure) = feed
            .prepare("metadata", next.authority().clone())
            .await
            .unwrap();
        let page = prepared.read(&cursor, 1).await.unwrap();
        assert!(page.events.is_empty());
        assert!(page.cursor.streams.contains_key("metadata"));
        assert!(disclosure.check().is_ok());
        assert_eq!(catalogues.load(Ordering::Relaxed), 2);
        assert_eq!(source.0.load(Ordering::Relaxed), 1);
    }
}
