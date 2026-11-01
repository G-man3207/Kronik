//! Real SSE/WebSocket streams. One buffered frame retains its original source
//! and privacy publication through bounded disclosure and transport completion.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::{Sink as _, SinkExt as _, StreamExt as _};
use http_body_util::{BodyExt as _, Full, StreamBody};
use hyper::body::Frame;
use kronik_core::authority::AuthLease;
use kronik_core::env::Env;
use kronik_core::error::{ApiError, ErrorCode};
use kronik_fleet::events::{Page, ResumeCursor};
use tokio_tungstenite::tungstenite::{Message, protocol::Role};

use crate::server::Body;
use crate::{Api, ApiRequest, CapturedRequest, Query};

const SEND_TIMEOUT: Duration = Duration::from_secs(30);
const IDLE: Duration = Duration::from_millis(100);

type QueuedFrame = (Bytes, AuthLease);

/// Bytes retain the same readset and catalogue publication after leaving the
/// bounded queue, until the HTTP/WebSocket consumer releases the actual frame.
struct RetainedFrameBytes { bytes: Vec<u8>, _disclosure: AuthLease }
impl AsRef<[u8]> for RetainedFrameBytes {
    fn as_ref(&self) -> &[u8] { &self.bytes }
}

fn body_frame((bytes, disclosure): QueuedFrame) -> Option<Result<Frame<Bytes>, Infallible>> {
    let mut prepared = Some(Frame::data(bytes));
    let mut published = None;
    disclosure.admit(&mut || {
        let frame = prepared.take().ok_or_else(||
            ApiError::new(ErrorCode::Internal, "event body frame was already admitted"))?;
        published = Some(frame);
        Ok(())
    }).ok()?;
    published.map(Ok)
}

type EventSocket = tokio_tungstenite::WebSocketStream<hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>>;

async fn send_websocket(env: &Env, output: &mut futures_util::stream::SplitSink<EventSocket, Message>,
    disclosure: &AuthLease, message: Message) -> bool {
    // Readiness may flush an older frame; all waiting stays outside admission.
    let ready = tokio::select! {
        biased;
        () = disclosure.cancelled() => return false,
        ready = env.timeout(SEND_TIMEOUT, futures_util::future::poll_fn(|cx|
            std::pin::Pin::new(&mut *output).poll_ready(cx))) => ready,
    };
    if !matches!(ready, Ok(Ok(()))) { return false; }
    let mut message = Some(message);
    if disclosure.admit(&mut || {
        let message = message.take().ok_or_else(||
            ApiError::new(ErrorCode::Internal, "event WebSocket frame was already admitted"))?;
        std::pin::Pin::new(&mut *output).start_send(message).map_err(|_|
            ApiError::new(ErrorCode::Unavailable, "event WebSocket output is unavailable"))
    }).is_err() { return false; }
    // The exact frame is in SplitSink's bounded slot. Retain its DATA lease
    // while flushing only completes this already-admitted handoff.
    tokio::select! {
        biased;
        () = disclosure.cancelled() => false,
        sent = env.timeout(SEND_TIMEOUT, output.flush()) => matches!(sent, Ok(Ok(()))),
    }
}

fn response(error: ApiError) -> hyper::Response<Body> {
    let mut response = hyper::Response::new(Full::new(Bytes::from(error.to_json().to_string())).boxed());
    *response.status_mut() = hyper::StatusCode::from_u16(error.code.http_status()).unwrap_or(hyper::StatusCode::INTERNAL_SERVER_ERROR);
    response.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
    response
}


/// Serve an actual event HTTP request, capturing its ordinary authority once
/// before touching the body. A capture for another route is never accepted.
pub async fn serve(api: Arc<Api>, mut request: ApiRequest,
    mut req: hyper::Request<hyper::body::Incoming>) -> hyper::Response<Body> {
    if request.method != req.method().as_str() || request.path != req.uri().path()
        || request.query != req.uri().query().unwrap_or("")
        || !(crate::events::STREAM_PATHS.contains(&request.path.as_str()) || request.path == "/v1/events")
    {
        return response(ApiError::new(ErrorCode::BadRequest, "invalid event stream request"));
    }
    let captured = match api.capture(&request) {
        Ok(captured) => captured,
        Err(error) => return response(error),
    };
    request.bearer = None;
    req.headers_mut().remove(hyper::header::AUTHORIZATION);
    req.headers_mut().remove(hyper::header::PROXY_AUTHORIZATION);
    req.headers_mut().remove(hyper::header::COOKIE);
    if request.path == "/v1/events" {
        return serve_page_captured(api, request, captured, req).await;
    }
    serve_captured(api, request, captured, req).await
}

/// One ordinary page reuses the stream's exact retained bytes and final frame
/// admission; no extra queue or request context outlives the original operation.
pub(crate) async fn serve_page_captured(api: Arc<Api>, request: ApiRequest,
    captured: CapturedRequest, req: hyper::Request<hyper::body::Incoming>) -> hyper::Response<Body> {
    let prepared = async {
        captured.require_scope(crate::auth::Scope::Admin)?;
        if request.method != "GET" || request.path != "/v1/events"
            || req.method() != hyper::Method::GET || req.uri().path() != "/v1/events"
            || req.headers().get(hyper::header::CONTENT_LENGTH).is_some_and(|length| length != "0")
            || req.headers().contains_key(hyper::header::TRANSFER_ENCODING) {
            return Err(ApiError::new(ErrorCode::BadRequest, "event pages require GET without a request body"));
        }
        let query = Query::parse(&request.query)?;
        let cursor = crate::server::event_cursor_header(req.headers())?;
        api.event_page_response(&query, cursor, captured.authority().clone()).await
    }.await;
    let (value, original) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => return response(error),
    };
    let retained = Bytes::from_owner(RetainedFrameBytes {
        bytes: value.body, _disclosure: original.clone() });
    let frames = futures_util::stream::once(async move { body_frame((retained, original)) })
        .filter_map(futures_util::future::ready);
    let mut result = hyper::Response::new(BodyExt::boxed(StreamBody::new(frames)));
    *result.status_mut() = hyper::StatusCode::from_u16(value.status)
        .unwrap_or(hyper::StatusCode::INTERNAL_SERVER_ERROR);
    result.headers_mut().insert(hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static(value.content_type));
    result
}

pub(crate) async fn serve_captured(api: Arc<Api>, request: ApiRequest, captured: CapturedRequest,
    mut req: hyper::Request<hyper::body::Incoming>) -> hyper::Response<Body> {
    let setup = (|| {
        captured.require_scope(crate::auth::Scope::Admin)?;
        if request.method != "GET"
            || req.headers().get(hyper::header::CONTENT_LENGTH).is_some_and(|length| length != "0")
            || req.headers().contains_key(hyper::header::TRANSFER_ENCODING)
        {
            return Err(ApiError::new(ErrorCode::BadRequest, "event streams require GET without a request body"));
        }
        let feed = api.event_feed()?;
        let env = api.node.env().clone();
        let query = Query::parse(&request.query)?;
        let header_cursor = crate::server::event_cursor_header(req.headers())?;
        let cursor = feed.cursor(header_cursor.or(query.get("cursor")))?;
        let source = query.get("source").map(str::to_owned);
        Ok::<_, ApiError>((captured.authority().clone(), feed, cursor, source, env))
    })();
    let (authority, feed, cursor, source, env) = match setup { Ok(value) => value, Err(error) => return response(error) };
    if req.uri().path() == "/v1/events/ws" {
        let upgrade = hyper::upgrade::on(&mut req);
        let (parts, _) = req.into_parts();
        let handshake = hyper::Request::from_parts(parts, ());
        let handshake = match tokio_tungstenite::tungstenite::handshake::server::create_response(&handshake) {
            Ok(response) => response,
            Err(_) => return response(ApiError::new(ErrorCode::BadRequest, "invalid event WebSocket handshake")),
        };
        let first = match first_page(&feed, &cursor, &authority, source.as_deref()).await {
            Ok(page) => page,
            Err(error) => return response(error),
        };
        let (parts, _) = handshake.into_parts();
        let response = hyper::Response::from_parts(parts, Full::new(Bytes::new()).boxed());
        drop(env.clone().spawn("events-websocket", async move {
            let upgraded = tokio::select! {
                biased;
                () = authority.cancelled() => return,
                upgraded = env.timeout(Duration::from_secs(10), upgrade) => match upgraded { Ok(Ok(upgraded)) => upgraded, _ => return },
            };
            let config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
                .max_message_size(Some(1024)).max_frame_size(Some(1024))
                .write_buffer_size(4096).max_write_buffer_size(2 << 20);
            let socket = tokio_tungstenite::WebSocketStream::from_raw_socket(hyper_util::rt::TokioIo::new(upgraded), Role::Server, Some(config)).await;
            let (mut output, mut input) = socket.split();
            let (send, mut receive) = tokio::sync::mpsc::channel::<QueuedFrame>(1);
            let source_env = env.clone();
            let source_authority = authority.clone();
            drop(env.spawn("events-source", async move { pump(source_env, feed, cursor, source_authority, source, send, false, first).await; }));
            loop {
                tokio::select! {
                    biased;
                    () = authority.cancelled() => break,
                    incoming = input.next() => match incoming {
                        Some(Ok(Message::Ping(payload))) => {
                            if !send_websocket(&env, &mut output, &authority, Message::Pong(payload)).await { break; }
                        }
                        Some(Ok(Message::Pong(_))) => {}
                        _ => break,
                    },
                    frame = receive.recv() => {
                        let Some((frame, disclosure)) = frame else { break; };
                        let Ok(text) = tokio_tungstenite::tungstenite::Utf8Bytes::try_from(frame) else { break; };
                        if !send_websocket(&env, &mut output, &disclosure, Message::Text(text)).await { break; }
                    }
                }
            }
            drop(receive);
            // Failure or cancellation must drop buffered frames, not flush them
            // in an unguarded close after their retained DATA lease is released.
            drop(output);
        }));
        return response;
    }
    let first = match first_page(&feed, &cursor, &authority, source.as_deref()).await {
        Ok(page) => page,
        Err(error) => return response(error),
    };
    let (send, mut receive) = tokio::sync::mpsc::channel::<QueuedFrame>(1);
    let stream = futures_util::stream::poll_fn(move |cx| {
        receive.poll_recv(cx).map(|frame| frame.and_then(body_frame))
    });
    let mut result = hyper::Response::new(http_body_util::BodyExt::boxed(StreamBody::new(stream)));
    result.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("text/event-stream"));
    result.headers_mut().insert(hyper::header::CACHE_CONTROL, hyper::header::HeaderValue::from_static("no-store"));
    result.headers_mut().insert("x-accel-buffering", hyper::header::HeaderValue::from_static("no"));
    drop(env.clone().spawn("events-sse", pump(env, feed, cursor, authority, source, send, true, first)));
    result
}

async fn first_page(feed: &Arc<crate::events::Events>, cursor: &ResumeCursor, authority: &AuthLease,
    selected_source: Option<&str>) -> Result<(Page, AuthLease), ApiError> {
    authority.check()?;
    let source = selected_source.or_else(|| feed.source_names().next())
        .ok_or_else(|| ApiError::new(ErrorCode::Unavailable, "event sources are unavailable"))?;
    tokio::select! {
        biased;
        () = authority.cancelled() => Err(authority.check().err().unwrap_or_else(||
            ApiError::new(ErrorCode::Unauthenticated, "event stream authority was cancelled"))),
        page = feed.page(cursor, source, 64, authority.clone()) => page,
    }
}

async fn send(env: &Env, disclosure: &AuthLease, output: &tokio::sync::mpsc::Sender<QueuedFrame>, frame: Vec<u8>) -> bool {
    let permit = tokio::select! {
        biased;
        () = disclosure.cancelled() => return false,
        result = env.timeout(SEND_TIMEOUT, output.reserve()) => match result {
            Ok(Ok(permit)) => permit,
            _ => return false,
        },
    };
    let frame = Bytes::from_owner(RetainedFrameBytes { bytes: frame, _disclosure: disclosure.clone() });
    let mut queued = Some((permit, frame, disclosure.clone()));
    disclosure.admit(&mut || {
        let Some((permit, frame, disclosure)) = queued.take() else {
            return Err(ApiError::new(ErrorCode::Internal, "event frame was already admitted"));
        };
        permit.send((frame, disclosure));
        Ok(())
    }).is_ok()
}

async fn pump(env: Env, feed: Arc<crate::events::Events>, mut cursor: ResumeCursor, authority: AuthLease,
    selected_source: Option<String>, output: tokio::sync::mpsc::Sender<QueuedFrame>, sse: bool, first: (Page, AuthLease)) {
    let mut first = Some(first);
    loop {
        let mut more = false;
        for source in feed.source_names().filter(|source| selected_source.as_deref().is_none_or(|selected| selected == *source)) {
            let page = match first.take() {
                Some(page) => Ok(page),
                None => tokio::select! {
                    biased;
                    () = authority.cancelled() => return,
                    page = feed.page(&cursor, source, 64, authority.clone()) => page,
                },
            };
            let (page, disclosure) = match page {
                Ok(page) => page,
                Err(error) => {
                    // The stable code is sufficient; no failed payload or secret inventory text.
                    let data = serde_json::json!({"error":{"code":error.code.as_str(),"message":"event stream unavailable","hint":"Reconnect with the last acknowledged cursor after resolving the failure."}});
                    let frame = if sse { format!("event: error\ndata: {data}\n\n").into_bytes() } else { data.to_string().into_bytes() };
                    let _ = send(&env, &authority, &output, frame).await;
                    return;
                }
            };
            for event in &page.events {
                let frame = if sse { kronik_fleet::events::sse_event(event, &cursor).map(String::into_bytes) } else { event.body() };
                let Ok(frame) = frame else { return; };
                if !send(&env, &disclosure, &output, frame).await { return; }
                let Ok(next) = kronik_fleet::events::resume_after(event, &cursor) else { return; };
                cursor = next;
            }
            if page.cursor != cursor || page.gap.is_some() {
                let frame = if sse { kronik_fleet::events::sse_cursor(&page).map(String::into_bytes) }
                    else { serde_json::to_vec(&serde_json::json!({"type":if page.gap.is_some(){"gap"}else{"cursor"},"page":page})).map_err(|_| "events_encode".to_owned()) };
                let Ok(frame) = frame else { return; };
                if !send(&env, &disclosure, &output, frame).await { return; }
            }
            cursor = page.cursor;
            more |= page.more;
        }
        if !more {
            tokio::select! {
                biased;
                () = authority.cancelled() => return,
                () = output.closed() => return,
                () = env.clock.sleep(IDLE) => {}
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use kronik_core::ids::SourcePos;
    use kronik_fleet::events::{Identity, Position};

    #[tokio::test]
    async fn invalid_resume_is_rejected_before_successful_stream_headers() {
        let data = tempfile::tempdir().unwrap();
        let node = kronik_sched::start_local(
            kronik_core::env::Env::real(tokio::runtime::Handle::current()),
            data.path(), kronik_sched::NodeConfig::default(),
        ).await.unwrap();
        let identity = Identity { installation: "11".repeat(32), branch: node.branch().to_owned() };
        let feed = std::sync::Arc::new(crate::events::Events::native(identity.clone(), node.clone()).unwrap());
        let api = crate::Api::new(node.clone());
        let request = crate::ApiRequest { method: "GET".into(), path: "/v1/events".into(),
            query: String::new(), body: Vec::new(), token_id: "unix:uid=0".into(), bearer: None };
        let captured = api.capture(&request).unwrap();
        node.refresh_secret_inventory(node.local_operator_authority().unwrap()).await.unwrap();
        let mut cursor = kronik_fleet::events::ResumeCursor::new(identity);
        cursor.rewind(Position { source: SourcePos::Actor { shard: None, lsn: node.applied_lsn() + 2 }, subindex: 0 }).unwrap();
        let error = super::first_page(&feed, &cursor, captured.authority(), None).await.err().unwrap();
        assert_eq!(error.code, kronik_core::error::ErrorCode::BadRequest);
        assert_eq!(super::response(error).status(), hyper::StatusCode::BAD_REQUEST);
        assert!(super::first_page(&feed, &kronik_fleet::events::ResumeCursor::new(feed.identity.clone()),
            captured.authority(), None).await.is_ok());
        let error = super::first_page(&feed, &kronik_fleet::events::ResumeCursor::new(feed.identity.clone()),
            captured.authority(), Some("actor-0")).await.err().unwrap();
        assert_eq!(error.code, kronik_core::error::ErrorCode::BadRequest);
    }

    #[tokio::test]
    async fn selected_metadata_stream_does_not_prefetch_or_advance_native_actor_history() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct EmptyMetadata {
            reads: AtomicUsize,
            changed: tokio::sync::Notify,
        }
        impl kronik_log::MetadataAuditSource for EmptyMetadata {
            fn read_from(&self, _: u64, _: usize) -> Result<kronik_log::MetadataAuditBatch, kronik_core::error::ApiError> {
                self.reads.fetch_add(1, Ordering::AcqRel);
                self.changed.notify_waiters();
                // Explicit empty unit coverage; this is not a Raft commit proof.
                Ok(kronik_log::MetadataAuditBatch {
                    covered_from: 1, durable_through: 0, scanned_through: 0, records: Vec::new(),
                })
            }
        }
        let data = tempfile::tempdir().unwrap();
        let env = kronik_core::env::Env::real(tokio::runtime::Handle::current());
        let node = kronik_sched::start_local(env.clone(), data.path(), kronik_sched::NodeConfig::default()).await.unwrap();
        node.refresh_secret_inventory(node.local_operator_authority().unwrap()).await.unwrap();
        let metadata = std::sync::Arc::new(EmptyMetadata {
            reads: AtomicUsize::new(0), changed: tokio::sync::Notify::new(),
        });
        let catalogue_node = node.clone();
        let identity = Identity { installation: "11".repeat(32), branch: node.branch().to_owned() };
        let feed = std::sync::Arc::new(crate::events::Events::native(identity.clone(), node.clone()).unwrap()
            .with_metadata(metadata.clone(), node.sealer().clone(), std::sync::Arc::new(move || {
                catalogue_node.native_secret_snapshot_with_publication()
            })));
        let api = crate::Api::new(node);
        let request = crate::ApiRequest { method: "GET".into(), path: "/v1/events/stream".into(),
            query: "source=metadata".into(), body: Vec::new(), token_id: "unix:uid=0".into(), bearer: None };
        let authority = api.capture(&request).unwrap().authority().clone();
        let cursor = kronik_fleet::events::ResumeCursor::new(identity);
        let first = super::first_page(&feed, &cursor, &authority, Some("metadata")).await.unwrap();
        let (output, mut input) = tokio::sync::mpsc::channel(1);
        let running = super::pump(env.clone(), feed, cursor, authority, Some("metadata".into()), output, false, first);
        tokio::pin!(running);
        let frame = env.timeout(std::time::Duration::from_secs(2), async {
            tokio::select! {
                frame = input.recv() => frame.unwrap(),
                () = &mut running => panic!("the source stopped before its initial cursor"),
            }
        }).await.unwrap();
        let frame = super::body_frame(frame).unwrap().unwrap().into_data().unwrap();
        let frame: serde_json::Value = serde_json::from_slice(&frame).unwrap();
        let streams = frame["page"]["cursor"]["streams"].as_object().unwrap();
        assert_eq!(streams.len(), 1);
        assert!(streams.contains_key("metadata"));
        let examined = async {
            loop {
                let changed = metadata.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if metadata.reads.load(Ordering::Acquire) >= 3 { return; }
                changed.await;
            }
        };
        env.timeout(std::time::Duration::from_secs(2), async {
            tokio::select! {
                () = examined => {},
                () = &mut running => panic!("the source stopped before examining subsequent pages"),
            }
        }).await.unwrap();
        assert!(input.try_recv().is_err(), "a selected metadata stream must not emit native actor cursors");
        drop(input);
        env.timeout(std::time::Duration::from_secs(2), running).await.unwrap();
    }

    #[tokio::test]
    async fn revoke_while_the_real_stream_buffer_is_full_never_enqueues_the_frame() {
        use crate::auth::{Authenticator as _, Scope};
        use crate::tokens::{Change, TokenAuthenticator, TokenStore};
        let data = tempfile::tempdir().unwrap();
        let node = kronik_sched::start_local(
            kronik_core::env::Env::real(tokio::runtime::Handle::current()),
            data.path(), kronik_sched::NodeConfig::default(),
        ).await.unwrap();
        let mut tokens = TokenStore::open_file(&data.path().join("tokens.db")).unwrap();
        tokens.bind_before_any_issuer(node.publication_domain()).unwrap();
        tokens.bind_execution_before_any_issuer(&node.publication_domain(), node.local_operator_authority().unwrap()).unwrap();
        let tokens = std::sync::Arc::new(tokens);
        let change = Change { wall_ms: 1, by: "fixture", reason: "test stream revocation" };
        let (_, secret) = tokens.create("reader", [Scope::Read].into(), [7; 32], &change, false).unwrap();
        let mut request = crate::ApiRequest { method: "GET".into(), path: "/v1/events".into(),
            query: String::new(), body: Vec::new(), token_id: "tcp:fixture".into(), bearer: secret };
        let authenticator = TokenAuthenticator::new(tokens.clone());
        let captured = authenticator.capture(&request, Scope::Read).unwrap();
        let env = node.env().clone();
        let (output, mut input) = tokio::sync::mpsc::channel(1);
        output.send((bytes::Bytes::from_static(b"existing"), captured.authority().clone())).await.unwrap();
        let denied = super::send(&env, captured.authority(), &output, b"denied".to_vec());
        tokio::pin!(denied);
        assert!(matches!(std::future::Future::poll(denied.as_mut(),
            &mut std::task::Context::from_waker(std::task::Waker::noop())), std::task::Poll::Pending));
        tokens.revoke("reader", &change, false).unwrap();
        assert_eq!(input.recv().await.unwrap().0, b"existing".as_slice());
        assert!(!denied.await);
        assert!(input.try_recv().is_err());
        let (_, following) = tokens.create("following", [Scope::Read].into(), [8; 32], &change, false).unwrap();
        request.bearer = following;
        let following = authenticator.capture(&request, Scope::Read).unwrap();
        assert!(super::send(&env, following.authority(), &output, b"following".to_vec()).await);
        assert_eq!(super::body_frame(input.recv().await.unwrap()).unwrap().unwrap().into_data().unwrap(),
            b"following".as_slice());
        assert!(input.try_recv().is_err());
    }

    #[tokio::test]
    async fn same_fingerprint_refresh_denies_waiting_and_queued_page_disclosures() {
        let data = tempfile::tempdir().unwrap();
        let env = kronik_core::env::Env::real(tokio::runtime::Handle::current());
        let node = kronik_sched::start_local(env.clone(), data.path(), kronik_sched::NodeConfig::default()).await.unwrap();
        let api = crate::Api::new(node.clone());
        let request = crate::ApiRequest { method: "GET".into(), path: "/v1/events/stream".into(),
            query: String::new(), body: Vec::new(), token_id: "unix:uid=0".into(), bearer: None };
        let captured = api.capture(&request).unwrap();
        let operator = node.local_operator_authority().unwrap();
        node.refresh_secret_inventory(operator.clone()).await.unwrap();
        let fingerprint = node.native_secret_snapshot().unwrap().fingerprint;
        let feed = std::sync::Arc::new(crate::events::Events::native(
            Identity { installation: "11".repeat(32), branch: node.branch().to_owned() }, node.clone()).unwrap());
        let cursor = kronik_fleet::events::ResumeCursor::new(feed.identity.clone());
        let (page, disclosure) = super::first_page(&feed, &cursor, captured.authority(), None).await.unwrap();
        let (output, mut input) = tokio::sync::mpsc::channel(1);
        output.send((bytes::Bytes::from_static(b"occupied"), captured.authority().clone())).await.unwrap();
        let denied = super::send(&env, &disclosure, &output, serde_json::to_vec(&page).unwrap());
        tokio::pin!(denied);
        assert!(matches!(std::future::Future::poll(denied.as_mut(),
            &mut std::task::Context::from_waker(std::task::Waker::noop())), std::task::Poll::Pending));
        node.refresh_secret_inventory(operator.clone()).await.unwrap();
        assert_eq!(fingerprint, node.native_secret_snapshot().unwrap().fingerprint);
        assert!(captured.authority().check().is_ok(), "catalogue refresh does not revoke the ordinary caller");
        assert_eq!(input.recv().await.unwrap().0, b"occupied".as_slice());
        assert!(!denied.await, "capacity becoming ready must not publish a page under its old catalogue");
        assert!(input.try_recv().is_err());

        let (page, disclosure) = super::first_page(&feed, &cursor, captured.authority(), None).await.unwrap();
        assert!(super::send(&env, &disclosure, &output, serde_json::to_vec(&page).unwrap()).await);
        node.refresh_secret_inventory(operator).await.unwrap();
        assert_eq!(fingerprint, node.native_secret_snapshot().unwrap().fingerprint);
        assert!(super::body_frame(input.recv().await.unwrap()).is_none(),
            "an already-buffered page still needs the same live DATA publication at the HTTP body boundary");

        let (page, disclosure) = super::first_page(&feed, &cursor, captured.authority(), None).await.unwrap();
        let expected = serde_json::to_vec(&page).unwrap();
        assert!(super::send(&env, &disclosure, &output, expected.clone()).await);
        let delivered = super::body_frame(input.recv().await.unwrap()).unwrap().unwrap().into_data().unwrap();
        assert_eq!(delivered, expected);
    }
    #[tokio::test]
    async fn public_http_entry_captures_the_actual_stream_route_and_denies_read_only_tokens() {
        use std::convert::Infallible;
        use std::sync::Arc;
        use std::time::Duration;
        use crate::auth::Scope;
        use crate::tokens::{Change, TokenStore};
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let data = tempfile::tempdir().unwrap();
        let env = kronik_core::env::Env::real(tokio::runtime::Handle::current());
        let node = kronik_sched::start_local(env.clone(), data.path(), Default::default()).await.unwrap();
        let mut store = TokenStore::open_file(&data.path().join("tokens.db")).unwrap();
        store.bind_before_any_issuer(node.publication_domain()).unwrap();
        let store = Arc::new(store);
        let api = Arc::new(crate::Api::new(node).with_tokens(store.clone()).unwrap());
        let change = Change { wall_ms: 1, by: "fixture", reason: "test ordinary event stream capture" };
        let (_, secret) = store.create("read-only", [Scope::Read].into(), [9; 32], &change, false).unwrap();
        for (normalized, incoming, status, code) in [
            ("/v1/health", "/v1/health", 400, "BAD_REQUEST"),
            ("/v1/events/stream", "/v1/events/ws", 400, "BAD_REQUEST"),
            ("/v1/events/stream", "/v1/events/stream", 403, "SCOPE_MISSING"),
        ] {
            let request = crate::ApiRequest { method: "GET".into(), path: normalized.into(),
                query: String::new(), body: Vec::new(), token_id: "tcp:fixture".into(), bearer: secret.clone() };
            let (mut client, server) = tokio::io::duplex(8192);
            let endpoint = api.clone();
            let service = hyper::service::service_fn(move |raw| {
                let endpoint = endpoint.clone();
                let request = request.clone();
                async move { Ok::<_, Infallible>(super::serve(endpoint, request, raw).await) }
            });
            let worker = env.spawn("events-http-capture-test", async move {
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(server), service).await
            });
            let wire = tokio::time::timeout(Duration::from_secs(3), async {
                client.write_all(format!("GET {incoming} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    .as_bytes()).await.unwrap();
                let mut wire = Vec::new();
                (&mut client).take(8192).read_to_end(&mut wire).await.unwrap();
                worker.await.unwrap().unwrap();
                wire
            }).await.unwrap();
            assert!(wire.starts_with(format!("HTTP/1.1 {status} ").as_bytes()));
            let body = wire.windows(4).position(|bytes| bytes == b"\r\n\r\n").unwrap() + 4;
            let error: serde_json::Value = serde_json::from_slice(&wire[body..]).unwrap();
            assert_eq!(error["error"]["code"], code);
        }
    }

}
