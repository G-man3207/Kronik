//! Operational events from the native actor source.

use std::collections::BTreeMap;
use std::sync::Arc;

use kronik_core::authority::AuthLease;
use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::ids::SourcePos;
use kronik_fleet::events::{self, Identity, Page, Position, ResumeCursor};
use kronik_otel::audit::{Keys, Mapper};
use kronik_otel::follow::{RetainedDisclosure, Stream};
use kronik_sched::secrets::CertifiedSecretSnapshot;
use kronik_sched::{Node, ShardReader};
use serde::{Deserialize, Serialize};

use crate::{Api, ApiResponse, Query, Result, internal, json, ok, reason};

/// Canonical HTTP endpoints served by the event streaming transport.
pub const STREAM_PATHS: [&str; 2] = ["/v1/events/stream", "/v1/events/ws"];

/// The native actor log's event source; ADR 0162 defers the Member sources.
const NATIVE: &str = "actor-native";

pub struct Events {
    pub identity: Identity,
    node: Arc<Node>,
    webhooks: BTreeMap<String, Arc<Stream>>,
}

/// One request's held source and certified values, captured before its public
/// read publication. Rendering consumes this preparation without recapturing.
pub(crate) struct PreparedEventPage {
    feed: Arc<Events>,
    reader: Arc<ShardReader>,
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
        tokio::select! {
            biased;
            () = self.disclosure.cancelled() => Err(ApiError::new(ErrorCode::Unauthenticated,
                "event page authority was revoked while reading")),
            page = events::page(&self.reader, &self.mapper, &self.feed.identity, cursor, &patterns, limit) => page,
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
            node,
            webhooks: BTreeMap::new(),
        })
    }

    pub fn with_webhooks(mut self, webhooks: BTreeMap<String, Arc<Stream>>) -> Self {
        self.webhooks = webhooks;
        self
    }

    pub fn source_names(&self) -> impl Iterator<Item = &str> {
        std::iter::once(NATIVE)
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
        if cursor.streams.keys().any(|source| source != NATIVE) {
            return Err(bad("event cursor names an unavailable source"));
        }
        Ok(cursor)
    }

    async fn capture(&self, original: AuthLease) -> Result<Arc<ShardReader>> {
        original.check()?;
        let reader = Arc::new(tokio::select! {
            biased;
            () = original.cancelled() => return Err(ApiError::new(ErrorCode::Unauthenticated,
                "event source authority was revoked before capture")),
            reader = self.node.capture_system_export_reader() => reader?,
        });
        original.check()?;
        Ok(reader)
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
        if source != NATIVE {
            return Err(bad("unknown event source"));
        }
        let (snapshot, publication) = self.node.native_secret_snapshot_with_publication()?;
        let reader = self.capture(original.clone()).await?;
        if events::domain(reader.point().source).as_ref() != source {
            return Err(bad("captured event reader belongs to another source"));
        }
        let disclosure =
            RetainedDisclosure::native(reader.clone(), snapshot.clone(), publication, original);
        disclosure.check()?;
        let mapper = Mapper {
            keys: Keys::Omit,
            sealer: self.node.sealer().clone(),
            branch: self.identity.branch.clone(),
        };
        let prepared = PreparedEventPage {
            feed: self.clone(),
            reader,
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

    fn status(&self) -> WebhooksResponse {
        let webhooks = self
            .webhooks
            .iter()
            .map(|(name, stream)| {
                let progress = stream.progress();
                WebhookStatus {
                    name: name.clone(),
                    enabled: stream.enabled,
                    cursor: SourcePos::Actor {
                        shard: None,
                        lsn: progress.cursor,
                    },
                    last_error: progress.last_error,
                    gaps: progress.gaps,
                }
            })
            .collect();
        WebhooksResponse { webhooks }
    }

    async fn validate_replay(
        &self,
        stream: &Stream,
        cursor: &ResumeCursor,
        original: AuthLease,
    ) -> Result<Position> {
        original.check()?;
        let position = *cursor
            .streams
            .get(NATIVE)
            .ok_or_else(|| bad("replay cursor lacks the webhook source"))?;
        if position.subindex != 0 {
            return Err(bad("webhook replay must begin at a record boundary"));
        }
        let reader = self.capture(original.clone()).await?;
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
        if shard != requested_shard || events::domain(reader.point().source) != NATIVE {
            return Err(bad("captured replay reader belongs to another source"));
        }
        if lsn < reader.point().retained_from.max(1) || lsn > through.saturating_add(1) {
            return Err(range_gone());
        }
        if lsn - 1 > stream.progress().cursor {
            return Err(bad("webhook replay may only rewind"));
        }
        original.check()?;
        Ok(position)
    }
}

impl Api {
    pub fn with_event_feed(mut self, events: Arc<Events>) -> Self {
        self.events = Some(events);
        self
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
        self.ok_scrubbed(self.event_feed()?.status())
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
        let stream = feed
            .webhooks
            .get(name)
            .ok_or_else(|| bad("unknown event webhook"))?;
        let position = feed
            .validate_replay(stream, &cursor, req.authority.clone())
            .await?;
        req.authority.check()?;
        if !request.dry_run {
            let details = [
                ("source", events::domain(position.source).into_owned()),
                ("position", events::coordinate(position.source).to_string()),
            ];
            self.audit_event(
                req,
                "events.webhook.replay",
                name,
                &details,
                request.reason.clone(),
            )
            .await?;
            if let Err(error) = stream
                .rewind(
                    &feed.node,
                    events::coordinate(position.source) - 1,
                    req.authority.clone(),
                )
                .await
            {
                let mut failed = details.to_vec();
                failed.push(("code", error.code.as_str().to_owned()));
                let _ = self
                    .audit_event(
                        req,
                        "events.webhook.replay.failed",
                        name,
                        &failed,
                        request.reason.clone(),
                    )
                    .await;
                return Err(error);
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
