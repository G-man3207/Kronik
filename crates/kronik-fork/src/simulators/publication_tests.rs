use super::*;
use std::io::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::{mpsc, oneshot};

struct Endpoint {
    url: String,
    captures: mpsc::Receiver<Vec<u8>>,
    connections: Arc<AtomicUsize>,
    release: Option<oneshot::Sender<()>>,
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

async fn request_body(socket: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    loop {
        if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&request[..end]).unwrap();
            let length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            assert!(length <= 2 << 20);
            let body = end + 4;
            if request.len() >= body + length {
                return request[body..body + length].to_vec();
            }
        }
        let mut bytes = [0; 4096];
        let count = socket.read(&mut bytes).await.unwrap();
        assert_ne!(count, 0, "the actual model request must be complete");
        request.extend_from_slice(&bytes[..count]);
        assert!(request.len() <= (2 << 20) + 16384);
    }
}

enum InitialReply {
    Disconnect,
    Http { status: u16, body: Vec<u8> },
}

async fn endpoint(pause_first_body: bool, mut first_reply: Option<InitialReply>) -> Endpoint {
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let (captures, receiver) = mpsc::channel(4);
    let connections = Arc::new(AtomicUsize::new(0));
    let counted = connections.clone();
    let (release, released) = oneshot::channel();
    let (stop, mut stopped) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut released = Some(released);
        loop {
            let accepted = tokio::select! {
                biased;
                _ = &mut stopped => return,
                accepted = listener.accept() => accepted,
            };
            let (mut socket, _) = accepted.unwrap();
            let ordinal = counted.fetch_add(1, Ordering::SeqCst);
            let body = request_body(&mut socket).await;
            // A distinct provider answer, never a request-forwarding echo.
            let first = if ordinal == 0 {
                first_reply.take()
            } else {
                None
            };
            let (status, answer) = match first.as_ref() {
                Some(InitialReply::Disconnect) => {
                    captures.send(body).await.unwrap();
                    continue;
                }
                Some(InitialReply::Http { status, body }) => (*status, body.as_slice()),
                None => (200, br#"{"choices":[{"message":{"content":"{\"status\":201,\"headers\":{},\"body\":\"OK\"}"}}]}"#.as_slice()),
            };
            let headers = format!(
                "HTTP/1.1 {status} ModelFixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                answer.len()
            );
            socket.write_all(headers.as_bytes()).await.unwrap();
            captures.send(body).await.unwrap();
            if pause_first_body && ordinal == 0 {
                released.take().unwrap().await.unwrap();
            }
            let _ = socket.write_all(answer).await;
        }
    });
    Endpoint {
        url: format!("http://{address}/v1/chat/completions"),
        captures: receiver,
        connections,
        release: Some(release),
        stop,
        task,
    }
}

impl Endpoint {
    async fn captured(&mut self) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(5), self.captures.recv())
            .await
            .unwrap()
            .unwrap()
    }
    fn release(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
    async fn stop(mut self) {
        self.release();
        let _ = self.stop.send(());
        self.task.await.unwrap();
    }
}

async fn native() -> (tempfile::TempDir, Arc<kronik_sched::Node>, AuthLease) {
    let data = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let node = kronik_sched::start_local(env, data.path(), kronik_sched::NodeConfig::default())
        .await
        .unwrap();
    let original = node.local_operator_authority().unwrap();
    let audit = pb::Audit {
        token_id: "unix:uid=0".into(),
        reason: "model fixture".into(),
        wall_time_ms: 1,
    };
    node.secret_set("older", b"e".to_vec(), &audit, false, original.clone())
        .await
        .unwrap();
    node.refresh_secret_inventory(original.clone())
        .await
        .unwrap();
    (data, node, original)
}

fn access(node: &Arc<kronik_sched::Node>, endpoint: &str, path: &Path) -> ModelAccess {
    let node = Arc::downgrade(node);
    let env = node.upgrade().unwrap().env().clone();
    ModelAccess {
        config: ModelConfig {
            endpoint: endpoint.into(),
            model: "fixture-model".into(),
            api_key: None,
            timeout: Duration::from_secs(3),
            max_examples: 0,
            examples_under_privacy: false,
        },
        env,
        cache: Arc::new(ModelCache::open(path).unwrap()),
        privacy: false,
        offline: false,
        secret_snapshot: Arc::new(move || {
            node.upgrade()
                .ok_or_else(source_scope_error)?
                .native_secret_snapshot_with_publication()
                .map(|(snapshot, publication)| ModelSecretSnapshot::Live {
                    snapshot,
                    publication,
                })
        }),
    }
}

fn prepared(
    access: &ModelAccess,
) -> (pb::HttpEffectRequest, Target, Arc<[pb::SecretRef]>, Vec<u8>) {
    let source = (access.secret_snapshot)().unwrap();
    let snapshot = source.snapshot();
    let patterns = kronik_sched::effects::secret_patterns(&snapshot.values);
    let matcher =
        CompiledScrubber::new(&patterns, kronik_sched::scrub::MAX_SECRET_PATTERN_BYTES).unwrap();
    let original = pb::HttpEffectRequest {
        method: "POST".into(),
        url: "https://h.invalid/p".into(),
        body: b"e".to_vec(),
        ..Default::default()
    };
    let (target, raw_host) = parse_request_url(&original.url).unwrap();
    let mut request = original.clone();
    let target =
        kronik_sched::scrub::http_request(&mut request, &target, raw_host, &matcher, 4096).unwrap();
    let fingerprint = kronik_effects::http::fingerprint_v2(&request, &target).unwrap();
    let Some(references) = snapshot.references.clone() else {
        panic!("actual file inventory must expose its real identities")
    };
    (request, target, references, fingerprint)
}

#[tokio::test]
async fn actual_model_capture_preserves_prepared_markers_and_recorded_cache_mode() {
    let (data, node, original) = native().await;
    let mut provider = endpoint(false, None).await;
    let access = access(&node, &provider.url, &data.path().join("model-cache.json"));
    let (request, target, scope, fingerprint) = prepared(&access);
    let answer = access
        .answer(
            "http:h.invalid",
            &fingerprint,
            &request,
            &target,
            Some(&scope),
            |_, _| vec![],
            &original,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!((answer.status, answer.body.as_str()), (201, "OK"));
    let captured: serde_json::Value = serde_json::from_slice(&provider.captured().await).unwrap();
    let content: serde_json::Value =
        serde_json::from_str(captured["messages"][1]["content"].as_str().unwrap()).unwrap();
    assert_eq!(content["request"]["body"], "[secret:older]");
    access.cache.save().unwrap();
    let before = std::fs::read(data.path().join("model-cache.json")).unwrap();
    let source = (access.secret_snapshot)().unwrap();
    let snapshot = source.snapshot().clone();
    let mut recorded = access.clone();
    recorded.offline = true;
    recorded.secret_snapshot =
        Arc::new(move || Ok(ModelSecretSnapshot::Recorded(snapshot.clone())));
    assert_eq!(
        recorded
            .cached_answer("http:h.invalid", &fingerprint)
            .unwrap()
            .unwrap(),
        Some(answer.clone())
    );
    assert_eq!(
        recorded
            .answer(
                "http:h.invalid",
                &fingerprint,
                &request,
                &target,
                Some(&scope),
                |_, _| vec![],
                &original
            )
            .await
            .unwrap(),
        Some(answer)
    );
    assert!(
        recorded
            .answer(
                "http:h.invalid",
                &[99; 32],
                &request,
                &target,
                Some(&scope),
                |_, _| vec![],
                &original
            )
            .await
            .is_err()
    );
    access.cache.save().unwrap();
    assert_eq!(
        std::fs::read(data.path().join("model-cache.json")).unwrap(),
        before
    );
    assert_eq!(
        provider.connections.load(Ordering::SeqCst),
        1,
        "saved facts must precede every model dispatch"
    );
    provider.stop().await;
}

#[tokio::test]
async fn actual_model_source_retirement_never_caches_refusal_or_poison_new_operation() {
    for same_fingerprint in [false, true] {
        let (data, node, original) = native().await;
        let mut provider = endpoint(true, None).await;
        let access = access(&node, &provider.url, &data.path().join("model-cache.json"));
        access.cache.save().unwrap();
        let before = std::fs::read(data.path().join("model-cache.json")).unwrap();
        let (request, target, scope, fingerprint) = prepared(&access);
        let initial = (access.secret_snapshot)().unwrap().snapshot().fingerprint;
        let pending = {
            let access = access.clone();
            let original = original.clone();
            let fingerprint = fingerprint.clone();
            tokio::spawn(async move {
                access
                    .answer(
                        "http:h.invalid",
                        &fingerprint,
                        &request,
                        &target,
                        Some(&scope),
                        |_, _| vec![],
                        &original,
                    )
                    .await
            })
        };
        provider.captured().await;
        if !same_fingerprint {
            let audit = pb::Audit {
                token_id: "unix:uid=0".into(),
                reason: "new model value".into(),
                wall_time_ms: 2,
            };
            node.secret_set("later", b"OK".to_vec(), &audit, false, original.clone())
                .await
                .unwrap();
        }
        node.refresh_secret_inventory(original.clone())
            .await
            .unwrap();
        let current = (access.secret_snapshot)().unwrap().snapshot().fingerprint;
        if same_fingerprint {
            assert_eq!(
                current, initial,
                "recertification must not invent semantic source changes"
            );
        } else {
            assert_ne!(current, initial);
        }
        provider.release();
        let error = tokio::time::timeout(Duration::from_secs(5), pending)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::SecretUnavailable);
        access.cache.save().unwrap();
        assert_eq!(
            std::fs::read(data.path().join("model-cache.json")).unwrap(),
            before,
            "a data-denied operation publishes neither an answer nor an immutable refusal/error"
        );
        let (request, target, scope, fingerprint) = prepared(&access);
        let next_original = node.local_operator_authority().unwrap();
        let answer = access
            .answer(
                "http:h.invalid",
                &fingerprint,
                &request,
                &target,
                Some(&scope),
                |_, _| vec![],
                &next_original,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            answer.body,
            if same_fingerprint {
                "OK"
            } else {
                "[secret:later]"
            }
        );
        provider.captured().await;
        assert_eq!(
            provider.connections.load(Ordering::SeqCst),
            2,
            "a new genuine operation is not poisoned by the old job"
        );
        provider.stop().await;
    }
}

#[tokio::test]
async fn actual_core_net_connect_mapping_retains_original_native_denial() {
    let (_data, node, original) = native().await;
    let (_, publication) = node.native_secret_snapshot_with_publication().unwrap();
    let job = ModelHttpAdmission::new(original.clone(), publication);
    let authority: AuthLease = job.clone();
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    node.stop_native_execution().unwrap();
    let expected = original.check().unwrap_err();
    let response = node
        .env()
        .net
        .http_authorized(
            kronik_core::env::HttpRequest {
                method: "POST".into(),
                url: format!("http://{}/no-request", listener.local_addr().unwrap()),
                headers: vec![],
                body: Vec::new().into(),
                max_response_bytes: 1024,
            },
            authority,
        )
        .await;
    assert!(matches!(
        response,
        Err(kronik_core::env::NetError::Connect(_))
    ));
    assert_eq!(
        job.check().unwrap_err(),
        expected,
        "the typed original denial survives Net's Connect string"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(25), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn actual_legacy_known_sensitive_refusal_is_private_and_safe_zero_is_not_a_new_writer() {
    let (data, node, original) = native().await;
    let provider = endpoint(false, None).await;
    let access = access(&node, &provider.url, &data.path().join("model-cache.json"));
    access.cache.save().unwrap();
    let before = std::fs::read(data.path().join("model-cache.json")).unwrap();
    let mut request = pb::HttpEffectRequest {
        method: "GET".into(),
        url: "https://h.invalid/p".into(),
        body: b"e".to_vec(),
        ..Default::default()
    };
    let target = parse_url(&request.url).unwrap();
    let fingerprint = kronik_effects::http::fingerprint(&request).unwrap();
    assert_eq!(
        access
            .answer(
                "http:h.invalid",
                &fingerprint,
                &request,
                &target,
                None,
                |_, _| vec![],
                &original
            )
            .await
            .unwrap(),
        None
    );
    request.body = b"OK".to_vec();
    let fingerprint = kronik_effects::http::fingerprint(&request).unwrap();
    assert_eq!(
        access
            .answer(
                "http:h.invalid",
                &fingerprint,
                &request,
                &target,
                None,
                |_, _| vec![],
                &original
            )
            .await
            .unwrap_err()
            .code,
        ErrorCode::SecretUnavailable
    );
    assert_eq!(provider.connections.load(Ordering::SeqCst), 0);
    access.cache.save().unwrap();
    assert_eq!(
        std::fs::read(data.path().join("model-cache.json")).unwrap(),
        before
    );
    provider.stop().await;
}

#[tokio::test]
async fn actual_new_identity_ambiguity_never_reaches_the_model_provider() {
    let (data, node, original) = native().await;
    let provider = endpoint(false, None).await;
    let access = access(&node, &provider.url, &data.path().join("model-cache.json"));
    access.cache.save().unwrap();
    let before = std::fs::read(data.path().join("model-cache.json")).unwrap();
    let (request, target, scope, fingerprint) = prepared(&access);
    let original_request = request.clone();
    let audit = pb::Audit {
        token_id: "unix:uid=0".into(),
        reason: "new prepared ambiguity".into(),
        wall_time_ms: 3,
    };
    node.secret_set(
        "later",
        b"[secret:older]".to_vec(),
        &audit,
        false,
        original.clone(),
    )
    .await
    .unwrap();
    node.refresh_secret_inventory(original.clone())
        .await
        .unwrap();
    let error = access
        .answer(
            "http:h.invalid",
            &fingerprint,
            &request,
            &target,
            Some(&scope),
            |_, _| vec![],
            &original,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::SecretUnavailable);
    assert_eq!(
        request, original_request,
        "ambiguity is a prerequisite, never request rewriting"
    );
    assert_eq!(provider.connections.load(Ordering::SeqCst), 0);
    access.cache.save().unwrap();
    assert_eq!(
        std::fs::read(data.path().join("model-cache.json")).unwrap(),
        before
    );
    provider.stop().await;
}

#[tokio::test]
async fn actual_model_failures_leave_no_fact_and_a_new_operation_can_succeed() {
    let expansion = serde_json::to_vec(&serde_json::json!({
        "choices": [{"message": {"content": serde_json::to_string(&serde_json::json!({
            "status": 201, "headers": {}, "body": "e".repeat(100_000),
        })).unwrap()}}],
    }))
    .unwrap();
    for (failure, expected) in [
        (InitialReply::Disconnect, ErrorCode::Unavailable),
        (
            InitialReply::Http {
                status: 503,
                body: b"service unavailable".to_vec(),
            },
            ErrorCode::Unavailable,
        ),
        (
            InitialReply::Http {
                status: 200,
                body: br#"{"choices":[{"message":{"content":"no"}}]}"#.to_vec(),
            },
            ErrorCode::Internal,
        ),
        (
            InitialReply::Http {
                status: 200,
                body: vec![b'x'; (1 << 20) + 1],
            },
            ErrorCode::Unavailable,
        ),
        (
            InitialReply::Http {
                status: 200,
                body: expansion,
            },
            ErrorCode::SecretUnavailable,
        ),
    ] {
        let (data, node, original) = native().await;
        let mut provider = endpoint(false, Some(failure)).await;
        let access = access(&node, &provider.url, &data.path().join("model-cache.json"));
        let (request, target, scope, fingerprint) = prepared(&access);
        access.cache.save().unwrap();
        let before = std::fs::read(data.path().join("model-cache.json")).unwrap();
        let error = access
            .answer(
                "http:h.invalid",
                &fingerprint,
                &request,
                &target,
                Some(&scope),
                |_, _| vec![],
                &original,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, expected);
        provider.captured().await;
        access.cache.save().unwrap();
        assert_eq!(
            std::fs::read(data.path().join("model-cache.json")).unwrap(),
            before,
            "a failed physical request or invalid model protocol is not an immutable refusal/error"
        );
        let next_original = node.local_operator_authority().unwrap();
        let answer = access
            .answer(
                "http:h.invalid",
                &fingerprint,
                &request,
                &target,
                Some(&scope),
                |_, _| vec![],
                &next_original,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!((answer.status, answer.body.as_str()), (201, "OK"));
        provider.captured().await;
        assert_eq!(provider.connections.load(Ordering::SeqCst), 2);
        provider.stop().await;
    }
}

#[tokio::test]
async fn actual_model_deadline_does_not_become_a_cached_refusal() {
    let (data, node, original) = native().await;
    let mut provider = endpoint(true, None).await;
    let mut access = access(&node, &provider.url, &data.path().join("model-cache.json"));
    access.config.timeout = Duration::from_millis(200);
    let (request, target, scope, fingerprint) = prepared(&access);
    access.cache.save().unwrap();
    let before = std::fs::read(data.path().join("model-cache.json")).unwrap();
    let pending = {
        let access = access.clone();
        let request = request.clone();
        let target = target.clone();
        let scope = scope.clone();
        let fingerprint = fingerprint.clone();
        tokio::spawn(async move {
            access
                .answer(
                    "http:h.invalid",
                    &fingerprint,
                    &request,
                    &target,
                    Some(&scope),
                    |_, _| vec![],
                    &original,
                )
                .await
        })
    };
    provider.captured().await;
    let error = tokio::time::timeout(Duration::from_secs(5), pending)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Unavailable);
    access.cache.save().unwrap();
    assert_eq!(
        std::fs::read(data.path().join("model-cache.json")).unwrap(),
        before
    );
    provider.release();
    access.config.timeout = Duration::from_secs(3);
    let next_original = node.local_operator_authority().unwrap();
    let answer = access
        .answer(
            "http:h.invalid",
            &fingerprint,
            &request,
            &target,
            Some(&scope),
            |_, _| vec![],
            &next_original,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!((answer.status, answer.body.as_str()), (201, "OK"));
    provider.captured().await;
    assert_eq!(provider.connections.load(Ordering::SeqCst), 2);
    provider.stop().await;
}

fn legacy_key(ordinal: u32) -> (String, Vec<u8>) {
    let request = pb::HttpEffectRequest {
        method: "GET".into(),
        url: format!("https://h.invalid/{ordinal}"),
        ..Default::default()
    };
    let fingerprint = kronik_effects::http::fingerprint(&request).unwrap();
    (format!("http:h.invalid {}", hex(&fingerprint)), fingerprint)
}

fn legacy_cache<'a>(
    path: &Path,
    answers: impl IntoIterator<Item = (String, Option<&'a ModelAnswer>)>,
) {
    let mut file = std::io::BufWriter::new(std::fs::File::create(path).unwrap());
    file.write_all(b"{ \"answers\" : {").unwrap();
    let mut first = true;
    for (key, answer) in answers {
        if !first {
            file.write_all(b", ").unwrap();
        }
        first = false;
        serde_json::to_writer(&mut file, &key).unwrap();
        file.write_all(b": ").unwrap();
        serde_json::to_writer(&mut file, &answer).unwrap();
    }
    file.write_all(b"} }\n").unwrap();
    file.flush().unwrap();
}

fn file_digest(path: &Path) -> blake3::Hash {
    let mut source = std::fs::File::open(path).unwrap();
    let mut digest = blake3::Hasher::new();
    std::io::copy(&mut source, &mut digest).unwrap();
    digest.finalize()
}

#[tokio::test]
async fn actual_old_cache_facts_are_read_only_and_unsafe_or_unknown_disclosure_is_not_a_miss() {
    let (data, node, original) = native().await;
    let provider = endpoint(false, None).await;
    let path = data.path().join("model-cache.json");
    let safe = ModelAnswer {
        status: 206,
        headers: vec![],
        body: "OLD".into(),
    };
    let later = ModelAnswer {
        status: 201,
        headers: vec![],
        body: "NEWVALUE".into(),
    };
    let marker = ModelAnswer {
        status: 202,
        headers: vec![],
        body: "[secret:marker]".into(),
    };
    let header_name = ModelAnswer {
        status: 203,
        headers: vec![("x-e".into(), "OK".into())],
        body: "OLD".into(),
    };
    let header_value = ModelAnswer {
        status: 204,
        headers: vec![("x".into(), "NEWVALUE".into())],
        body: "OLD".into(),
    };
    let (safe_key, safe_fp) = legacy_key(1);
    let (later_key, later_fp) = legacy_key(2);
    let (marker_key, marker_fp) = legacy_key(3);
    let (refusal_key, refusal_fp) = legacy_key(4);
    let (header_name_key, header_name_fp) = legacy_key(5);
    let (header_value_key, header_value_fp) = legacy_key(6);
    legacy_cache(
        &path,
        [
            (safe_key, Some(&safe)),
            (later_key, Some(&later)),
            (marker_key, Some(&marker)),
            (refusal_key, None),
            (header_name_key, Some(&header_name)),
            (header_value_key, Some(&header_value)),
        ],
    );
    let before = std::fs::read(&path).unwrap();
    let mut model = access(&node, &provider.url, &path);
    let (snapshot, _) = node.native_secret_snapshot_with_publication().unwrap();
    model.secret_snapshot = Arc::new(move || Ok(ModelSecretSnapshot::Recorded(snapshot.clone())));
    model.offline = true;
    assert_eq!(
        model.cached_answer("http:h.invalid", &safe_fp).unwrap(),
        Some(Some(safe.clone()))
    );
    assert_eq!(
        model.cached_answer("http:h.invalid", &later_fp).unwrap(),
        Some(Some(later))
    );
    assert_eq!(
        model.cached_answer("http:h.invalid", &refusal_fp).unwrap(),
        Some(None)
    );
    model.cache.save().unwrap();
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "a legacy read/save does not rewrite the old container"
    );
    model.cache = Arc::new(ModelCache::read_only(&path).unwrap());
    assert_eq!(
        model.cached_answer("http:h.invalid", &safe_fp).unwrap(),
        Some(Some(safe.clone()))
    );
    let audit = pb::Audit {
        token_id: "unix:uid=0".into(),
        reason: "cache proof".into(),
        wall_time_ms: 2,
    };
    node.secret_set(
        "later",
        b"NEWVALUE".to_vec(),
        &audit,
        false,
        original.clone(),
    )
    .await
    .unwrap();
    node.secret_set(
        "marker",
        b"[secret:marker]".to_vec(),
        &audit,
        false,
        original.clone(),
    )
    .await
    .unwrap();
    node.refresh_secret_inventory(original).await.unwrap();
    let (snapshot, _) = node.native_secret_snapshot_with_publication().unwrap();
    model.secret_snapshot = Arc::new(move || Ok(ModelSecretSnapshot::Recorded(snapshot.clone())));
    assert_eq!(
        model
            .cached_answer("http:h.invalid", &later_fp)
            .unwrap_err()
            .code,
        ErrorCode::SecretUnavailable
    );
    assert_eq!(
        model
            .cached_answer("http:h.invalid", &marker_fp)
            .unwrap_err()
            .code,
        ErrorCode::SecretUnavailable,
        "an identical marker replacement is still a sensitive occurrence without original scope proof"
    );
    assert_eq!(
        model
            .cached_answer("http:h.invalid", &header_name_fp)
            .unwrap_err()
            .code,
        ErrorCode::SecretUnavailable
    );
    assert_eq!(
        model
            .cached_answer("http:h.invalid", &header_value_fp)
            .unwrap_err()
            .code,
        ErrorCode::SecretUnavailable
    );
    assert_eq!(
        model.cached_answer("http:h.invalid", &safe_fp).unwrap(),
        Some(Some(safe))
    );
    assert_eq!(
        model.cached_answer("http:h.invalid", &refusal_fp).unwrap(),
        Some(None)
    );
    let mut missing = model.clone();
    missing.secret_snapshot = Arc::new(|| {
        Err(ApiError::new(
            ErrorCode::SecretUnavailable,
            "fixture source proof is unavailable",
        ))
    });
    assert_eq!(
        missing
            .cached_answer("http:h.invalid", &safe_fp)
            .unwrap_err()
            .code,
        ErrorCode::SecretUnavailable
    );
    model.cache.save().unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(provider.connections.load(Ordering::SeqCst), 0);
    provider.stop().await;
}

#[tokio::test]
async fn a_genuine_new_fact_preserves_old_cache_keys_values_and_unknown_provenance() {
    let (data, node, original) = native().await;
    let mut provider = endpoint(false, None).await;
    let path = data.path().join("model-cache.json");
    let safe = ModelAnswer {
        status: 206,
        headers: vec![],
        body: "OLD".into(),
    };
    let unsafe_old = ModelAnswer {
        status: 202,
        headers: vec![],
        body: "[secret:older]".into(),
    };
    let (safe_key, safe_fp) = legacy_key(1);
    let (unsafe_key, unsafe_fp) = legacy_key(2);
    let (refusal_key, refusal_fp) = legacy_key(3);
    legacy_cache(
        &path,
        [
            (safe_key.clone(), Some(&safe)),
            (unsafe_key.clone(), Some(&unsafe_old)),
            (refusal_key.clone(), None),
        ],
    );
    let model = access(&node, &provider.url, &path);
    let (request, target, scope, fingerprint) = prepared(&model);
    let answer = model
        .answer(
            "http:h.invalid",
            &fingerprint,
            &request,
            &target,
            Some(&scope),
            |_, _| vec![],
            &original,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!((answer.status, answer.body.as_str()), (201, "OK"));
    provider.captured().await;
    model.cache.save().unwrap();
    let saved: serde_json::Value =
        serde_json::from_reader(std::fs::File::open(&path).unwrap()).unwrap();
    assert_eq!(saved["version"], 2);
    for (key, old) in [
        (&safe_key, Some(&safe)),
        (&unsafe_key, Some(&unsafe_old)),
        (&refusal_key, None),
    ] {
        assert!(
            saved["answers"][key]["source_fingerprint"].is_null(),
            "unknown old provenance is never retagged current"
        );
        assert_eq!(
            saved["answers"][key]["answer"]["Ok"],
            serde_json::to_value(old).unwrap()
        );
    }
    drop(model);
    let reopened = access(&node, &provider.url, &path);
    assert_eq!(
        reopened.cached_answer("http:h.invalid", &safe_fp).unwrap(),
        Some(Some(safe))
    );
    assert_eq!(
        reopened
            .cached_answer("http:h.invalid", &unsafe_fp)
            .unwrap_err()
            .code,
        ErrorCode::SecretUnavailable
    );
    assert_eq!(
        reopened
            .cached_answer("http:h.invalid", &refusal_fp)
            .unwrap(),
        Some(None)
    );
    assert_eq!(
        reopened
            .cached_answer("http:h.invalid", &fingerprint)
            .unwrap()
            .unwrap()
            .unwrap()
            .body,
        "OK"
    );
    assert_eq!(provider.connections.load(Ordering::SeqCst), 1);
    provider.stop().await;
}

#[tokio::test]
async fn actual_multi_answer_cache_crosses_the_old_aggregate_bound_without_losing_facts() {
    let (data, node, original) = native().await;
    let mut provider = endpoint(false, None).await;
    let path = data.path().join("model-cache.json");
    // Each answer fits the real 1 MiB provider response limit, including its
    // chat envelope; only the aggregate exceeds the former record-size cap.
    let answer = ModelAnswer {
        status: 206,
        headers: vec![],
        body: "X".repeat((1 << 20) - 512),
    };
    let count = kronik_sched::scrub::MAX_JSON_OUTPUT_BYTES / answer.body.len() + 2;
    legacy_cache(
        &path,
        (0..count).map(|ordinal| (legacy_key(ordinal as u32).0, Some(&answer))),
    );
    assert!(
        std::fs::metadata(&path).unwrap().len() > kronik_sched::scrub::MAX_JSON_OUTPUT_BYTES as u64
    );
    let original_file = file_digest(&path);
    let mut model = access(&node, &provider.url, &path);
    let live = model.secret_snapshot.clone();
    let (snapshot, _) = node.native_secret_snapshot_with_publication().unwrap();
    model.secret_snapshot = Arc::new(move || Ok(ModelSecretSnapshot::Recorded(snapshot.clone())));
    model.offline = true;
    for ordinal in 0..count {
        let fact = model
            .cached_answer("http:h.invalid", &legacy_key(ordinal as u32).1)
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(fact, answer);
    }
    model.cache.save().unwrap();
    assert_eq!(file_digest(&path), original_file);
    assert_eq!(provider.connections.load(Ordering::SeqCst), 0);
    model.offline = false;
    model.secret_snapshot = live;
    let (request, target, scope, fingerprint) = prepared(&model);
    assert!(
        model
            .answer(
                "http:h.invalid",
                &fingerprint,
                &request,
                &target,
                Some(&scope),
                |_, _| vec![],
                &original
            )
            .await
            .unwrap()
            .is_some()
    );
    provider.captured().await;
    model.cache.save().unwrap();
    drop(model);
    let reopened = access(&node, &provider.url, &path);
    for ordinal in 0..count {
        assert_eq!(
            reopened
                .cached_answer("http:h.invalid", &legacy_key(ordinal as u32).1)
                .unwrap()
                .unwrap()
                .unwrap(),
            answer
        );
    }
    assert!(
        reopened
            .cached_answer("http:h.invalid", &fingerprint)
            .unwrap()
            .flatten()
            .is_some()
    );
    assert_eq!(provider.connections.load(Ordering::SeqCst), 1);
    provider.stop().await;
}

#[tokio::test]
async fn failed_cache_persistence_retains_the_new_fact_for_the_next_real_save() {
    let (data, node, original) = native().await;
    let mut provider = endpoint(false, None).await;
    let path = data.path().join("missing-parent").join("model-cache.json");
    let model = access(&node, &provider.url, &path);
    let (request, target, scope, fingerprint) = prepared(&model);
    let answer = model
        .answer(
            "http:h.invalid",
            &fingerprint,
            &request,
            &target,
            Some(&scope),
            |_, _| vec![],
            &original,
        )
        .await
        .unwrap()
        .unwrap();
    provider.captured().await;
    assert!(model.cache.save().is_err());
    std::fs::create_dir(path.parent().unwrap()).unwrap();
    model.cache.save().unwrap();
    drop(model);
    let reopened = access(&node, &provider.url, &path);
    assert_eq!(
        reopened
            .cached_answer("http:h.invalid", &fingerprint)
            .unwrap(),
        Some(Some(answer))
    );
    assert_eq!(provider.connections.load(Ordering::SeqCst), 1);
    provider.stop().await;
}

#[test]
fn malformed_versioned_cache_metadata_never_becomes_legacy_proof_or_rewrites_the_file() {
    let data = tempfile::tempdir().unwrap();
    let path = data.path().join("cache.json");
    for original in [
        b"{\"version\":2,\"answers\":{\"k\":{\"answer\":{\"Ok\":null}}}}".as_slice(),
        b"{\"version\":2,\"answers\":{\"k\":null}}".as_slice(),
        b"{\"version\":7,\"answers\":{}}".as_slice(),
        b"{\"answers\":{\"k\":{\"source_fingerprint\":null,\"answer\":{\"Ok\":null}}}}".as_slice(),
    ] {
        std::fs::write(&path, original).unwrap();
        assert!(ModelCache::open(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }
}

/// The node's detached initial secret refresh retires the certificate a
/// publication fences on. A test that dispatches a model request must wait
/// until that refresh has settled, so a fresh publication stays current
/// across an idle window; otherwise the request is denied mid-flight (as
/// production intends when the source changes under it).
async fn settle_secret_inventory(node: &kronik_sched::Node) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok((_, publication)) = node.native_secret_snapshot_with_publication() {
            tokio::time::sleep(Duration::from_millis(5)).await;
            if publication.check_current().is_ok()
                && publication.data_is_current_under_publication()
            {
                return;
            }
        } else {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the initial secret refresh did not settle"
        );
    }
}

async fn empty_native() -> (tempfile::TempDir, Arc<kronik_sched::Node>, AuthLease) {
    let data = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let node = kronik_sched::start_local(env, data.path(), kronik_sched::NodeConfig::default())
        .await
        .unwrap();
    let original = node.local_operator_authority().unwrap();
    node.refresh_secret_inventory(original.clone())
        .await
        .unwrap();
    settle_secret_inventory(&node).await;
    (data, node, original)
}

#[tokio::test]
async fn unknown_credentials_are_not_disclosed_from_old_cache_with_complete_empty_inventory() {
    let (data, node, original) = empty_native().await;
    drop(original);
    let provider = endpoint(false, None).await;
    let path = data.path().join("model-cache.json");
    let credential = format!("kronik_{}", "x".repeat(43));
    let safe = ModelAnswer {
        status: 200,
        headers: vec![],
        body: "SAFE".into(),
    };
    let body = ModelAnswer {
        status: 201,
        headers: vec![],
        body: credential.clone(),
    };
    let name = ModelAnswer {
        status: 202,
        headers: vec![(credential.clone(), "VALUE".into())],
        body: "SAFE".into(),
    };
    let value = ModelAnswer {
        status: 203,
        headers: vec![("x".into(), credential)],
        body: "SAFE".into(),
    };
    let facts = [safe, body, name, value];
    legacy_cache(
        &path,
        facts
            .iter()
            .enumerate()
            .map(|(index, fact)| (legacy_key(index as u32).0, Some(fact))),
    );
    let before = std::fs::read(&path).unwrap();
    let model = access(&node, &provider.url, &path);
    assert!(
        (model.secret_snapshot)()
            .unwrap()
            .snapshot()
            .values
            .is_empty()
    );
    assert_eq!(
        model
            .cached_answer("http:h.invalid", &legacy_key(0).1)
            .unwrap(),
        Some(Some(facts[0].clone()))
    );
    for index in 1..facts.len() {
        assert_eq!(
            model
                .cached_answer("http:h.invalid", &legacy_key(index as u32).1)
                .unwrap_err()
                .code,
            ErrorCode::SecretUnavailable
        );
    }
    model.cache.save().unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(provider.connections.load(Ordering::SeqCst), 0);
    provider.stop().await;
}

#[tokio::test]
async fn actual_new_model_output_hides_unknown_credentials_without_changing_literal_request() {
    let (data, node, original) = empty_native().await;
    let credential = format!("kronik_{}", "x".repeat(43));
    let reply = serde_json::to_vec(&serde_json::json!({
        "choices": [{"message": {"content": serde_json::to_string(&serde_json::json!({
            "status": 201, "headers": {"x": credential}, "body": format!("left|{credential}|right"),
        })).unwrap()}}],
    }))
    .unwrap();
    let mut provider = endpoint(
        false,
        Some(InitialReply::Http {
            status: 200,
            body: reply,
        }),
    )
    .await;
    let path = data.path().join("model-cache.json");
    let model = access(&node, &provider.url, &path);
    assert!(
        (model.secret_snapshot)()
            .unwrap()
            .snapshot()
            .values
            .is_empty()
    );
    let (request, target, scope, fingerprint) = prepared(&model);
    assert_eq!(request.body, b"e");
    let answer = model
        .answer(
            "http:h.invalid",
            &fingerprint,
            &request,
            &target,
            Some(&scope),
            |_, _| vec![],
            &original,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(answer.status, 201);
    assert_eq!(answer.body, "left|[secret:token]|right");
    assert_eq!(answer.headers, vec![("x".into(), "[secret:token]".into())]);
    let captured: serde_json::Value = serde_json::from_slice(&provider.captured().await).unwrap();
    let content: serde_json::Value =
        serde_json::from_str(captured["messages"][1]["content"].as_str().unwrap()).unwrap();
    assert_eq!(content["request"]["body"], "e");
    model.cache.save().unwrap();
    drop(model);
    let reopened = access(&node, &provider.url, &path);
    assert_eq!(
        reopened
            .cached_answer("http:h.invalid", &fingerprint)
            .unwrap(),
        Some(Some(answer))
    );
    assert_eq!(provider.connections.load(Ordering::SeqCst), 1);
    provider.stop().await;
}

#[tokio::test]
async fn quoted_history_omits_decoded_unknown_credentials_but_preserves_real_prepared_markers() {
    let (data, node, _original) = native().await;
    let provider = endpoint(false, None).await;
    let model = access(&node, &provider.url, &data.path().join("model-cache.json"));
    let source = (model.secret_snapshot)().unwrap();
    let snapshot = source.snapshot();
    let patterns = kronik_sched::effects::secret_patterns(&snapshot.values);
    let matcher =
        CompiledScrubber::new(&patterns, kronik_sched::scrub::MAX_SECRET_PATTERN_BYTES).unwrap();
    let (request, _, scope, fingerprint) = prepared(&model);
    let reference = scope
        .iter()
        .find(|reference| reference.name == "older")
        .unwrap()
        .clone();
    let reveal = pb::EffectRecord {
        ordinal: 1,
        kind: "secret.reveal".into(),
        status: pb::EffectStatus::Ok as i32,
        request: Some(pb::Sealable {
            value: Some(pb::sealable::Value::Plain(
                pb::RevealEffectRequest {
                    secret: Some(reference),
                }
                .encode_to_vec(),
            )),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut exchange = pb::EffectRecord {
        ordinal: 2,
        kind: "http.fetch".into(),
        status: pb::EffectStatus::Ok as i32,
        fingerprint,
        request: Some(pb::Sealable {
            value: Some(pb::sealable::Value::Plain(request.encode_to_vec())),
            ..Default::default()
        }),
        response: Some(pb::Sealable {
            value: Some(pb::sealable::Value::Plain(
                pb::HttpEffectResponse {
                    status: 200,
                    body: b"[secret:older]".to_vec(),
                    ..Default::default()
                }
                .encode_to_vec(),
            )),
            ..Default::default()
        }),
        ..Default::default()
    };
    let input = pb::Input {
        kind: Some(pb::input::Kind::Migrate(pb::MigrateInput {
            from_schema_version: 1,
            to_schema_version: 2,
        })),
    };
    let prefix = original_secret_prefix(&input, &[reveal, exchange.clone()], 2).unwrap();
    let examples = model_examples(
        &[(2, &exchange, Some(prefix.clone()))],
        1,
        &matcher,
        Some(&scope),
    );
    assert_eq!(examples.len(), 1);
    assert_eq!(examples[0]["request"]["body"], "[secret:older]");
    assert_eq!(examples[0]["response"]["body"], "[secret:older]");
    let credential = format!("kronik_{}", "x".repeat(43));
    for body in [
        credential.as_bytes().to_vec(),
        format!("\"{}\"", credential.replace('k', "\\u006b")).into_bytes(),
    ] {
        exchange.response = Some(pb::Sealable {
            value: Some(pb::sealable::Value::Plain(
                pb::HttpEffectResponse {
                    status: 200,
                    body,
                    ..Default::default()
                }
                .encode_to_vec(),
            )),
            ..Default::default()
        });
        let original = exchange.encode_to_vec();
        assert!(
            model_examples(
                &[(2, &exchange, Some(prefix.clone()))],
                1,
                &matcher,
                Some(&scope)
            )
            .is_empty()
        );
        assert_eq!(exchange.encode_to_vec(), original);
    }
    assert_eq!(provider.connections.load(Ordering::SeqCst), 0);
    provider.stop().await;
}
