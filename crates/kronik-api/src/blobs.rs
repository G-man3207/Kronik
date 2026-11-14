//! The blob endpoints (M25 §15, M26 §12): the store's status, one blob's
//! inspection and content, and the collector's plan and pass.
//!
//! `GET /v1/blobs/{hash}/content` streams (`serve_content`, called by the
//! server before the buffered routes): the bytes go through the secret
//! output matcher of the moment, and a subject's blob needs `pii:read`.

use kronik_core::error::{ApiError, ErrorCode};
use kronik_sched::blob_gc::{BlobRoot, GcOutcome, SweepOptions, Unrooted};
use kronik_store::db::PinDrift;

use crate::auth::{Caller, Scope};
use crate::types::*;
use crate::{Api, ApiResponse, AuthorizedRequest, Query, Result};
use crate::{json, ok, reason};

#[cfg(feature = "server")]
pub(crate) use content::serve_content;

/// `GET /v1/blobs/{hash}/content`: the hash, when `path` is that route.
#[cfg(feature = "server")]
pub(crate) fn content_path(path: &str) -> Option<&str> {
    path.strip_prefix("/v1/blobs/")?
        .strip_suffix("/content")
        .filter(|hash| !hash.is_empty() && !hash.contains('/'))
}

fn entry(u: &Unrooted, pii: bool) -> BlobGcEntry {
    BlobGcEntry {
        hash: u.hash.clone(),
        reason: u.reason.as_str().to_owned(),
        released_by: u.released_by.as_ref().map(|(actor, _)| actor.clone()),
        size: u.size,
        bytes: u.bytes,
        subject: u.subject.clone().filter(|_| pii),
        last_ref_lsn: u.last_ref_lsn,
        candidate: u.candidate,
    }
}

/// A pin's owner as the API shows it: the store separates the fields of a
/// row's key (an ingress key, a timer) with the unit separator; show them as
/// a path.
fn owner_path(owner: &str) -> String {
    owner.replace('\u{1f}', "/")
}

fn drift_entry(d: PinDrift) -> BlobPinDriftEntry {
    BlobPinDriftEntry {
        hash: d.hash,
        source: kronik_store::db::blob_source::name(d.source).to_owned(),
        owner: owner_path(&d.owner),
        problem: if d.missing { "missing" } else { "extra" }.to_owned(),
    }
}

/// `verify=true|false` of a query.
fn verify_flag(q: &Query) -> Result<bool> {
    match q.get("verify") {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(other) => Err(ApiError::new(
            ErrorCode::BadRequest,
            format!("verify is true or false, not {other:?}"),
        )),
    }
}

fn summary(o: &GcOutcome) -> BlobGcSummary {
    BlobGcSummary {
        objects: o.report.objects,
        bytes: o.report.bytes,
        deleted: o.report.deleted,
        deleted_bytes: o.report.deleted_bytes,
        candidates: o.report.candidates,
        floor: o.floor,
    }
}

fn root(r: BlobRoot) -> BlobRootEntry {
    let mut e = BlobRootEntry {
        kind: String::new(),
        actor: None,
        lsn: None,
        floor: None,
        source: None,
        owner: None,
        fork: None,
    };
    match r {
        BlobRoot::Log {
            last_ref_lsn,
            floor,
        } => {
            e.kind = "log".into();
            e.lsn = Some(last_ref_lsn);
            e.floor = Some(floor);
        }
        BlobRoot::Held { actor, lsn } => {
            e.kind = "held".into();
            e.actor = Some(actor);
            e.lsn = Some(lsn);
        }
        BlobRoot::Pin { source, owner, lsn } => {
            e.kind = "pin".into();
            e.source = Some(source.to_owned());
            e.owner = Some(owner_path(&owner));
            e.lsn = Some(lsn);
        }
        BlobRoot::Snapshot { lsn } => {
            e.kind = "snapshot".into();
            e.lsn = Some(lsn);
        }
        BlobRoot::Fork { name } => {
            e.kind = "fork".into();
            e.fork = Some(name);
        }
        BlobRoot::Lease => e.kind = "lease".into(),
    }
    e
}

impl Api {
    pub(crate) async fn route_blobs(
        &self,
        req: &AuthorizedRequest,
        segs: &[&str],
        q: &Query,
        caller: &Caller,
    ) -> Option<Result<ApiResponse>> {
        let pii = caller.has(Scope::PiiRead);
        Some(match (req.method.as_str(), segs) {
            ("GET", ["v1", "blobs"]) => self.blobs_status(),
            ("GET", ["v1", "blobs", "gc"]) => self.blob_gc_plan(q, pii).await,
            ("POST", ["v1", "blobs", "gc"]) => self.blob_gc_run(req).await,
            ("GET", ["v1", "blobs", hash]) => self.blob_inspect(hash, q, pii).await,
            // Streamed by the server; reached only through a path that
            // buffers (the MCP server, tests), which cannot carry a blob.
            ("GET", ["v1", "blobs", _, "content"]) => Err(ApiError::new(
                ErrorCode::BadRequest,
                "blob content is streamed only over the API socket and TCP listener",
            )
            .with_hint("Run: kronik blobs get <hash> -o FILE")),
            _ => return None,
        })
    }

    fn blobs_status(&self) -> Result<ApiResponse> {
        let s = self.node.blob_status()?;
        ok(&BlobsStatusResponse {
            enabled: s.enabled,
            indexed: s.indexed,
            indexed_bytes: s.indexed_bytes,
            floor: s.floor,
            leases: s.leases,
            free_bytes: s.free_bytes,
            reserve_bytes: s.reserve_bytes,
            below_reserve: s.below_reserve,
            last_gc: s.last_gc.as_ref().map(summary),
        })
    }

    async fn blob_plan(&self, pii: bool, verify: bool) -> Result<BlobGcPlanResponse> {
        let Some(o) = self
            .node
            .blob_gc(SweepOptions {
                dry_run: true,
                ..Default::default()
            })
            .await?
        else {
            return Ok(BlobGcPlanResponse::default());
        };
        let blobs: Vec<BlobGcEntry> = o.unrooted.iter().map(|u| entry(u, pii)).collect();
        let bytes = blobs.iter().map(|b| b.bytes).sum();
        let drift = if verify {
            Some(
                self.node
                    .blob_pin_drift()
                    .await?
                    .into_iter()
                    .map(drift_entry)
                    .collect(),
            )
        } else {
            None
        };
        Ok(BlobGcPlanResponse {
            enabled: true,
            count: blobs.len() as u64,
            bytes,
            floor: Some(o.floor),
            kept: o.report.objects.saturating_sub(blobs.len() as u64),
            blobs,
            drift,
        })
    }

    async fn blob_gc_plan(&self, q: &Query, pii: bool) -> Result<ApiResponse> {
        self.ok_scrubbed(self.blob_plan(pii, verify_flag(q)?).await?)
    }

    /// `GET /v1/actors/{kind}/{key}/blobs` (M26 §12): what the actor holds,
    /// by hash, a page at a time.
    pub(crate) fn actor_blobs(
        &self,
        kind: &str,
        key: &str,
        q: &Query,
        pii: bool,
    ) -> Result<ApiResponse> {
        let actor = Self::actor_ref(kind, key)?;
        let limit = q.limit()?;
        let after = q.get("after").unwrap_or("");
        let mut holds = self
            .node
            .store()
            .db()
            .holds(&actor.kind, &actor.key, after, limit + 1)
            .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?;
        let next = (holds.len() > limit).then(|| {
            holds.truncate(limit);
            holds
                .last()
                .map(|(r, _)| r.hash.clone())
                .unwrap_or_default()
        });
        ok(&ActorBlobsResponse {
            blobs: holds
                .into_iter()
                .map(|(r, lsn)| ActorBlobEntry {
                    hash: r.hash,
                    size: r.size,
                    subject: r.subject.filter(|_| pii),
                    lsn,
                })
                .collect(),
            next,
        })
    }

    async fn blob_gc_run(&self, req: &AuthorizedRequest) -> Result<ApiResponse> {
        let r: BlobGcRequest = json(&req.body)?;
        reason(&r.reason)?;
        if r.dry_run {
            // What a pass now would do: with `immediate` it deletes every
            // file without a root, otherwise the candidates of the last one.
            let plan = self.blob_plan(false, false).await?;
            let (now, later): (Vec<&BlobGcEntry>, Vec<&BlobGcEntry>) =
                plan.blobs.iter().partition(|b| r.immediate || b.candidate);
            return ok(&BlobGcResponse {
                dry_run: true,
                enabled: plan.enabled,
                deleted: now.len() as u64,
                bytes: now.iter().map(|b| b.bytes).sum(),
                candidates: later.len() as u64,
                objects: plan.kept + later.len() as u64,
                floor: plan.floor,
            });
        }
        let outcome = self
            .node
            .blob_gc(SweepOptions {
                immediate: r.immediate,
                dry_run: false,
            })
            .await?;
        let answer = match &outcome {
            Some(o) => BlobGcResponse {
                dry_run: false,
                enabled: true,
                deleted: o.report.deleted,
                bytes: o.report.deleted_bytes,
                candidates: o.report.candidates,
                objects: o.report.objects,
                floor: Some(o.floor),
            },
            None => BlobGcResponse::default(),
        };
        let details = [
            ("deleted", answer.deleted.to_string()),
            ("bytes", answer.bytes.to_string()),
            ("candidates", answer.candidates.to_string()),
            ("immediate", r.immediate.to_string()),
        ];
        self.audit_event(req, "blobs.gc", "main", &details, r.reason)
            .await?;
        ok(&answer)
    }

    async fn blob_inspect(&self, hash: &str, q: &Query, pii: bool) -> Result<ApiResponse> {
        let i = self.node.blob_inspect(hash, verify_flag(q)?).await?;
        let row = i.row.as_ref();
        let (verified, verify_error) = match &i.verified {
            None => (None, None),
            Some(Ok(())) => (Some(true), None),
            Some(Err(e)) => (Some(false), Some(e.clone())),
        };
        self.ok_scrubbed(BlobInspectResponse {
            hash: i.hash.clone(),
            state: i.state.as_str().to_owned(),
            size: row.map(|r| r.size),
            subject: row.and_then(|r| r.subject.clone()).filter(|_| pii),
            key_version: row.map(|r| r.key_version),
            first_ref_lsn: row.map(|r| r.first_lsn),
            last_ref_lsn: row.map(|r| r.last_ref_lsn),
            sealed: i.sealed,
            file_bytes: i.file_bytes,
            roots: i.roots.into_iter().map(root).collect(),
            verified,
            verify_error,
        })
    }
}

#[cfg(feature = "server")]
mod content {
    use std::sync::Arc;

    use bytes::Bytes;
    use http_body_util::{BodyExt, StreamBody};
    use hyper::body::Frame;
    use kronik_core::error::{ApiError, ErrorCode};
    use kronik_effects::http::{CompiledScrubber, ScrubLimits, StreamScrubber};
    use kronik_sched::blob_gc::BlobReader;
    use kronik_sched::scrub::MAX_SECRET_PATTERN_BYTES;

    use crate::auth::Scope;
    use crate::{Api, ApiRequest, CapturedRequest, Query};

    type Body = crate::server::Body;
    type Sender = tokio::sync::mpsc::Sender<Frame<Bytes>>;

    /// One push of the scrubber emits at most this much (a frame is 64 KiB
    /// of plaintext; the markers that replace secret values are longer).
    const CHUNK_BYTES: usize = 1 << 20;

    /// The part of `bytes`, which are the output positions `start..`, that
    /// falls in `skip..skip + take`.
    fn window(bytes: &[u8], start: u64, skip: u64, take: u64) -> Option<Bytes> {
        let end = start + bytes.len() as u64;
        let from = skip.max(start);
        let to = end.min(skip.saturating_add(take));
        if from >= to {
            return None;
        }
        let a = usize::try_from(from - start).ok()?;
        let b = usize::try_from(to - start).ok()?;
        Some(Bytes::copy_from_slice(&bytes[a..b]))
    }

    /// The scrubbed bytes of `reader` at output positions `skip..skip +
    /// take`, sent to `out` in chunks; with `out` None it only counts. Returns
    /// how many bytes the scrubbed blob has (up to where it stopped).
    async fn scrubbed(
        reader: &BlobReader,
        matcher: CompiledScrubber<'static>,
        skip: u64,
        take: u64,
        out: Option<&Sender>,
    ) -> Result<u64, ApiError> {
        let limits = ScrubLimits {
            output_bytes: usize::MAX,
            pattern_bytes: MAX_SECRET_PATTERN_BYTES,
        };
        let mut scrubber = StreamScrubber::from_compiled(matcher, limits, CHUNK_BYTES)
            .map_err(crate::output_scrub::scrub_error)?;
        let mut produced = 0u64;
        for index in 0..reader.frames() {
            if out.is_some() && produced >= skip.saturating_add(take) {
                return Ok(produced);
            }
            let plain = reader
                .frame(index)
                .await
                .map_err(|e| ApiError::new(ErrorCode::StorageCorrupt, e.to_string()))?;
            let chunk = scrubber
                .push(&plain)
                .map_err(crate::output_scrub::scrub_error)?;
            let part = window(chunk, produced, skip, take);
            produced += chunk.len() as u64;
            if let (Some(bytes), Some(out)) = (part, out)
                && out.send(Frame::data(bytes)).await.is_err()
            {
                return Ok(produced);
            }
        }
        let rest = scrubber
            .finish()
            .map_err(crate::output_scrub::scrub_error)?;
        let part = window(&rest, produced, skip, take);
        produced += rest.len() as u64;
        if let (Some(bytes), Some(out)) = (part, out) {
            let _ = out.send(Frame::data(bytes)).await;
        }
        Ok(produced)
    }

    /// `GET /v1/blobs/{hash}/content?offset=&len=` (`kronik blobs get`):
    /// the blob's bytes through the secret output matcher of the moment,
    /// streamed. `offset` and `len` are positions in that output (the
    /// blob's own when it holds no secret value). A first pass reads every
    /// frame (each is checked as it is read) and counts the output, so the
    /// response has its exact `Content-Length`, and a failure in the second
    /// pass shows as a cut stream, never as a short success. A subject's
    /// blob needs `pii:read`.
    pub(crate) async fn serve_content(
        api: Arc<Api>,
        request: ApiRequest,
        captured: CapturedRequest,
    ) -> hyper::Response<Body> {
        let prepared = async {
            captured.require_scope(Scope::Read)?;
            let hash = super::content_path(&request.path)
                .and_then(crate::decode_path)
                .ok_or_else(|| ApiError::new(ErrorCode::BadRequest, "no blob hash"))?;
            let query = Query::parse(&request.query)?;
            let offset = query.num("offset")?.unwrap_or(0);
            let len = query.num("len")?.unwrap_or(u64::MAX);
            let (row, reader) = api.node.blob_content(&hash).await?;
            if row.subject.is_some() {
                captured.require_scope(Scope::PiiRead)?;
            }
            let values = api.node.secret_values()?;
            let patterns = kronik_sched::effects::secret_patterns(&values);
            let compile = || {
                CompiledScrubber::new_output(&patterns, MAX_SECRET_PATTERN_BYTES)
                    .map(CompiledScrubber::into_owned)
                    .map_err(crate::output_scrub::scrub_error)
            };
            let total = scrubbed(&reader, compile()?, 0, u64::MAX, None).await?;
            if offset > total {
                return Err(ApiError::new(
                    ErrorCode::BadRequest,
                    format!("offset {offset} is past the blob's {total} bytes"),
                ));
            }
            let length = len.min(total - offset);
            Ok::<_, ApiError>((row.size, reader, compile()?, offset, length))
        };
        let (size, reader, matcher, offset, length) = match prepared.await {
            Ok(p) => p,
            Err(error) => return crate::server::error_response(&error),
        };
        let (send, mut receive) = tokio::sync::mpsc::channel::<Frame<Bytes>>(1);
        let authority = captured.authority().clone();
        api.node.env().spawn("blob-content", async move {
            tokio::select! {
                biased;
                () = authority.cancelled() => {}
                r = scrubbed(&reader, matcher, offset, length, Some(&send)) => {
                    if let Err(e) = r {
                        tracing::warn!(error = %e.message, "a blob download stopped");
                    }
                }
            }
        });
        let frames = futures_util::stream::poll_fn(move |cx| {
            receive
                .poll_recv(cx)
                .map(|frame| frame.map(Ok::<_, std::convert::Infallible>))
        });
        let mut response = hyper::Response::new(BodyExt::boxed(StreamBody::new(frames)));
        let headers = response.headers_mut();
        headers.insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/octet-stream"),
        );
        headers.insert(
            hyper::header::CONTENT_LENGTH,
            hyper::header::HeaderValue::from(length),
        );
        headers.insert("x-kronik-blob-size", hyper::header::HeaderValue::from(size));
        response
    }
}
