// The control-channel fixture returns the library's large response type
// from its websocket handler; the shape is the harness's, not the API's.
#![allow(clippy::result_large_err)]

//! Real transport consumer: no Net or Authority substitute, and no Member proof claim.
use super::*;
use crate::auth::Scope;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::DirBuilderExt as _;
use tokio_tungstenite::tungstenite::{self, Message};
use zeroize::Zeroize as _;

type TlsStream = rustls::StreamOwned<rustls::ServerConnection, std::net::TcpStream>;

enum ControllerStep {
    Enroll,
    Probe(tokio::sync::oneshot::Sender<bool>),
    Late(Arc<tokio::sync::Notify>, std::sync::mpsc::Receiver<()>),
    Healthy(
        Arc<tokio::sync::Notify>,
        std::sync::mpsc::Receiver<()>,
        Zeroizing<String>,
    ),
    Finish,
}

fn accept(listener: &std::net::TcpListener) -> std::net::TcpStream {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(15)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(15)))
                    .unwrap();
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "owned WSS controller accept deadline"
                );
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("owned WSS controller accept: {}", error.kind()),
        }
    }
}

fn request(stream: &mut TlsStream) -> (String, Zeroizing<Vec<u8>>) {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        assert!(header.len() < 8192);
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        header.push(byte[0]);
    }
    let header = String::from_utf8(header).unwrap();
    let length = header
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap();
    assert!((1..=enrollment::MAX_ENROLLMENT_BYTES).contains(&length));
    let mut body = Zeroizing::new(vec![0; length]);
    stream.read_exact(&mut body).unwrap();
    (header, body)
}

fn response(socket: &mut tungstenite::WebSocket<TlsStream>) -> Vec<u8> {
    let mut body = Vec::new();
    loop {
        match socket.read().unwrap() {
            Message::Binary(bytes) => body.extend_from_slice(&bytes),
            Message::Ping(_) | Message::Pong(_) => continue,
            _ => panic!("HTTP response must remain on the binary byte tunnel"),
        }
        assert!(body.len() <= 128 << 10);
        let Some(end) = body
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .map(|at| at + 4)
        else {
            continue;
        };
        let head = std::str::from_utf8(&body[..end]).unwrap();
        let length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap();
        if body.len() == end + length {
            return body;
        }
        assert!(body.len() < end + length);
    }
}

fn upgrade(
    stream: TlsStream,
    bearer: &str,
    record: &EnrollmentRecord,
) -> tungstenite::WebSocket<TlsStream> {
    match tungstenite::accept_hdr(
        stream,
        |request: &tungstenite::handshake::server::Request, response| {
            assert_eq!(request.uri().path(), "/v1/control");
            assert!(
                request
                    .headers()
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| value.strip_prefix("Bearer ") == Some(bearer))
            );
            assert!(
                request
                    .headers()
                    .get("x-kronik-enrollment")
                    .and_then(|value| value.to_str().ok())
                    == Some(record.request_id.as_str())
            );
            assert!(
                request
                    .headers()
                    .get("x-kronik-epoch")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok())
                    == Some(record.epoch)
            );
            Ok(response)
        },
    ) {
        Ok(socket) => socket,
        Err(_) => panic!("owned WSS handshake failed"),
    }
}

#[tokio::test]
async fn real_owned_wss_opening_and_each_command_keep_the_original_ordinary_authority() {
    let directory = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("https://{}", listener.local_addr().unwrap());
    let issuer = Network::default();
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let ca_key = kronik_core::identity::ed25519_key(&[41; 32]).unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    *issuer.issuer.lock().unwrap() = Some(rcgen::Issuer::new(ca_params, ca_key));
    let mut protected_ca = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
    protected_ca.write_all(ca.pem().as_bytes()).unwrap();
    let ca_file = directory.path().join("ca.pem");
    protected_ca.persist(&ca_file).unwrap();
    let server_key = kronik_core::identity::ed25519_key(&[42; 32]).unwrap();
    let mut server_params = rcgen::CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
    server_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server_params
        .signed_by(&server_key, issuer.issuer.lock().unwrap().as_ref().unwrap())
        .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .allow_unauthenticated()
    .build()
    .unwrap();
    let tls = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![server_cert.der().clone()],
                rustls_pki_types::PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
            )
            .unwrap(),
    );
    let (step, steps) = std::sync::mpsc::sync_channel(1);
    let tcp_attempts = Arc::new(AtomicUsize::new(0));
    let mtls_handshakes = Arc::new(AtomicUsize::new(0));
    let ws_handshakes = Arc::new(AtomicUsize::new(0));
    let finished = {
        let (tcp_attempts, mtls_handshakes, ws_handshakes) = (
            tcp_attempts.clone(),
            mtls_handshakes.clone(),
            ws_handshakes.clone(),
        );
        env.blocking("api-real-owned-wss-controller", move || {
            let mut number = 0;
            let mut active: Option<(EnrollmentRecord, Zeroizing<String>)> = None;
            loop {
                match steps.recv_timeout(Duration::from_secs(20)).unwrap() {
                    ControllerStep::Enroll => {
                        number += 1;
                        let mut stream = rustls::StreamOwned::new(rustls::ServerConnection::new(tls.clone()).unwrap(), accept(&listener));
                        let (header, body) = request(&mut stream);
                        assert!(header.starts_with("POST /v1/enroll HTTP/1.1\r\n"));
                        let expected = format!("Bearer wss-once-{number}");
                        assert!(header.lines().filter_map(|line| line.split_once(':'))
                            .any(|(name, value)| name.eq_ignore_ascii_case("authorization") && value.trim() == expected));
                        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
                        let plan: EnrollmentPlan = serde_json::from_value(value["plan"].clone()).unwrap();
                        let csr: Vec<u8> = serde_json::from_value(value["csr_der"].clone()).unwrap();
                        let request_id = value["request_id"].as_str().unwrap().to_owned();
                        let epoch = value["epoch"].as_u64().unwrap();
                        let certificate = issuer.certificate(&csr, &plan, &request_id, epoch);
                        let record = EnrollmentRecord { controller_id: Some(plan.ca_sha256.clone()), plan, request_id, epoch,
                            phase: EnrollmentPhase::Active, csr_der: csr,
                            client_key_sha256: value["client_key_sha256"].as_str().unwrap().to_owned(), client_cert_der: Some(certificate) };
                        let reply = serde_json::to_vec(&serde_json::json!({"schema": enrollment::ENROLLMENT_SCHEMA,
                            "request_id": &record.request_id, "epoch": record.epoch, "plan": &record.plan,
                            "controller_id": &record.controller_id, "client_cert_der": &record.client_cert_der})).unwrap();
                        active = Some((record, Zeroizing::new(value["api_bearer"].as_str().unwrap().to_owned())));
                        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", reply.len()).unwrap();
                        stream.write_all(&reply).unwrap();
                        stream.flush().unwrap();
                    }
                    ControllerStep::Probe(done) => {
                        let empty = matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock);
                        done.send(empty).unwrap();
                    }
                    ControllerStep::Late(entered, release) => {
                        let mut stream = accept(&listener);
                        tcp_attempts.fetch_add(1, Ordering::SeqCst);
                        entered.notify_one();
                        release.recv_timeout(Duration::from_secs(15)).unwrap();
                        let mut connection = rustls::ServerConnection::new(tls.clone()).unwrap();
                        let mut complete = true;
                        while connection.is_handshaking() {
                            if connection.complete_io(&mut stream).is_err() { complete = false; break; }
                        }
                        if complete {
                            assert!(connection.peer_certificates().is_some_and(|certificates| !certificates.is_empty()));
                            mtls_handshakes.fetch_add(1, Ordering::SeqCst);
                            let (record, bearer) = active.as_ref().unwrap();
                            let mut socket = upgrade(rustls::StreamOwned::new(connection, stream), bearer, record);
                            ws_handshakes.fetch_add(1, Ordering::SeqCst);
                            loop {
                                match socket.read() {
                                    Ok(Message::Ping(_) | Message::Pong(_)) => {},
                                    Ok(Message::Close(_)) | Err(_) => break,
                                    _ => panic!("a revoked late connection must not publish command bytes"),
                                }
                            }
                        }
                    }
                    ControllerStep::Healthy(ready, release, stronger) => {
                        let mut stream = accept(&listener);
                        tcp_attempts.fetch_add(1, Ordering::SeqCst);
                        let mut connection = rustls::ServerConnection::new(tls.clone()).unwrap();
                        while connection.is_handshaking() { connection.complete_io(&mut stream).unwrap(); }
                        assert!(connection.peer_certificates().is_some_and(|certificates| !certificates.is_empty()));
                        mtls_handshakes.fetch_add(1, Ordering::SeqCst);
                        let (record, bearer) = active.as_ref().unwrap();
                        let mut socket = upgrade(rustls::StreamOwned::new(connection, stream), bearer, record);
                        ws_handshakes.fetch_add(1, Ordering::SeqCst);
                        socket.send(Message::Binary(b"GET /v1/health HTTP/1.1\r\nHost: controller.test\r\nContent-Length: 0\r\n\r\n".as_slice().into())).unwrap();
                        assert!(response(&mut socket).starts_with(b"HTTP/1.1 200"));
                        let command = format!("POST /v1/fleet/revoke HTTP/1.1\r\nHost: controller.test\r\nAuthorization: Bearer {}\r\nContent-Length: 0\r\n\r\n", stronger.as_str());
                        assert!(socket.send(Message::Binary(command.into_bytes().into())).is_ok(), "owned WSS command send failed");
                        assert!(response(&mut socket).starts_with(b"HTTP/1.1 403"));
                        ready.notify_one();
                        release.recv_timeout(Duration::from_secs(15)).unwrap();
                        let _ = socket.send(Message::Binary(b"GET /v1/health HTTP/1.1\r\nHost: controller.test\r\nContent-Length: 0\r\n\r\n".as_slice().into()));
                        loop {
                            match socket.read() {
                                Ok(Message::Ping(_) | Message::Pong(_)) => {},
                                Ok(Message::Close(_)) | Err(_) => break,
                                Ok(Message::Binary(bytes)) => assert!(!bytes.windows(12).any(|part| part == b"HTTP/1.1 200")),
                                _ => panic!("revoked control must close rather than accept another command"),
                            }
                        }
                    }
                    ControllerStep::Finish => break,
                }
            }
            assert_eq!(number, 5);
        })
    };
    let keys = directory.path().join("keys");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&keys)
        .unwrap();
    let node = kronik_sched::start_local(
        env.clone(),
        directory.path(),
        kronik_sched::NodeConfig::default(),
    )
    .await
    .unwrap();
    node.record_installation_identity(pb::InstallationIdentity {
        installation: "installation-real-owned-wss".into(),
    })
    .await
    .unwrap();
    let mut store = TokenStore::open_file(&keys.join("tokens.db")).unwrap();
    store
        .bind_before_any_issuer(node.publication_domain())
        .unwrap();
    let startup_original = node.local_operator_authority().unwrap();
    store
        .bind_execution_before_any_issuer(&node.publication_domain(), startup_original.clone())
        .unwrap();
    let tokens = Arc::new(store);
    let api = crate::Api::new(node.clone())
        .with_tokens(tokens.clone())
        .unwrap();
    let fleet = Fleet::open(
        node.clone(),
        tokens.clone(),
        FleetConfig {
            controller: ControllerConfig {
                url: url.clone(),
                ca_file,
                client_key_file: keys.join("fleet/client.key"),
            },
            identity: FleetIdentity {
                installation: "installation-real-owned-wss".into(),
                node: None,
                cluster: None,
            },
            scopes: vec!["read".into(), "fork".into()],
        },
        keys.join("fleet/bearer"),
        startup_original,
    )
    .await
    .unwrap();
    let api = Arc::new(api.with_fleet(fleet.clone()));
    let (_, stronger) = tokens
        .create(
            "wss-stronger",
            [Scope::Admin].into(),
            [43; 32],
            &Change {
                by: "unix:uid=0",
                reason: "ordinary stronger header fixture",
                wall_ms: env.clock.wall_ms(),
            },
            false,
        )
        .unwrap();
    let stronger = Zeroizing::new(stronger.unwrap());
    let publications = Arc::new(AtomicUsize::new(0));
    for boundary in 0..5 {
        step.send(ControllerStep::Enroll).unwrap();
        let enrolled = api.handle(crate::ApiRequest {
            method: "POST".into(),
            path: "/v1/fleet/enroll".into(),
            query: String::new(),
            token_id: "unix:uid=0".into(),
            bearer: None,
            body: serde_json::to_vec(
                &serde_json::json!({"url":url,"token":format!("wss-once-{}",boundary+1),
                "reason":"admit real owned WSS fixture", "dry_run":false}),
            )
            .unwrap(),
        });
        assert_eq!(
            env.timeout(Duration::from_secs(10), enrolled)
                .await
                .unwrap()
                .status,
            200
        );
        let (client, record, bearer, guard) = fleet.active_connection().await.unwrap().unwrap();
        let mut binding = crate::ApiRequest {
            method: "GET".into(),
            path: "/".into(),
            query: String::new(),
            body: Vec::new(),
            token_id: "fleet".into(),
            bearer: Some(bearer.to_string()),
        };
        let captured = api.capture_fleet_binding(&binding, guard.clone()).unwrap();
        binding.bearer.as_mut().unwrap().zeroize();
        captured.require_scope(Scope::Fork).unwrap();
        let original = captured.authority().clone();
        let opening_caller = captured.caller.token_id.clone();
        let intent_start = node.applied_lsn();
        let opening_audit = fleet.control_opening_audit(&captured);
        let opening_capacity = Arc::new(tokio::sync::Semaphore::new(1));
        let held = if boundary == 0 {
            Some(opening_capacity.clone().acquire_owned().await.unwrap())
        } else {
            None
        };
        let ready = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let (release_peer, released_peer) = std::sync::mpsc::sync_channel(1);
        if boundary == 3 {
            step.send(ControllerStep::Late(ready.clone(), released_peer))
                .unwrap();
        } else if boundary == 4 {
            step.send(ControllerStep::Healthy(
                ready.clone(),
                released_peer,
                stronger.clone(),
            ))
            .unwrap();
        }
        let entered = Arc::new(tokio::sync::Notify::new());
        let work = {
            let (task_env, api, original, capacity, ready, release, entered, publications) = (
                env.clone(),
                api.clone(),
                original.clone(),
                opening_capacity.clone(),
                ready.clone(),
                release.clone(),
                entered.clone(),
                publications.clone(),
            );
            env.spawn("api-real-owned-wss-attempt", async move {
                entered.notify_one();
                let dispatch = move |prepared: kronik_fleet::transport::PreparedControl|
                    -> BoxFuture<'static, Result<Arc<dyn kronik_core::env::WebSocket>, kronik_fleet::enrollment::FleetError>> {
                    Box::pin(async move {
                        match boundary {
                            1 => {
                                ready.notify_one();
                                release.acquire_owned().await.map_err(|_| kronik_fleet::enrollment::FleetError::Revoked)?.forget();
                                prepared.dispatch_with_admission(move || opening_audit).await
                            },
                            2 => prepared.dispatch_with_admission(move || async move {
                                opening_audit.await?;
                                ready.notify_one();
                                release.acquire_owned().await.map_err(|_| kronik_fleet::enrollment::FleetError::Revoked)?.forget();
                                Ok(())
                            }).await,
                            _ => prepared.dispatch_with_admission(move || opening_audit).await,
                        }
                    })
                };
                kronik_fleet::transport::run_control(&task_env, &client, &record, &bearer, guard,
                    original, capacity, dispatch, move |stream, _guard| {
                        publications.fetch_add(1, Ordering::SeqCst);
                        Box::pin(async move { let _ = crate::server::serve_fleet_connection(stream, api, captured, None).await; })
                    }).await
            })
        };
        env.timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        if boundary != 0 {
            env.timeout(Duration::from_secs(10), ready.notified())
                .await
                .unwrap();
        }
        if boundary == 4 {
            let available = env
                .timeout(
                    Duration::from_secs(5),
                    opening_capacity.clone().acquire_owned(),
                )
                .await
                .unwrap()
                .unwrap();
            drop(available); // Opening capacity must not remain held for the long-lived channel.
            assert_eq!(publications.load(Ordering::SeqCst), 1);
        } else {
            assert_eq!(opening_capacity.available_permits(), 0);
        }
        let revoked = api.handle(crate::ApiRequest { method: "POST".into(), path: "/v1/fleet/revoke".into(),
            query: String::new(), token_id: "unix:uid=0".into(), bearer: None,
            body: serde_json::to_vec(&serde_json::json!({"reason":"durably revoke the original WSS operation", "dry_run":false})).unwrap() });
        assert_eq!(
            env.timeout(Duration::from_secs(5), revoked)
                .await
                .unwrap()
                .status,
            200
        );
        let fenced = node.applied_lsn();
        assert!(original.check().is_err());
        assert_eq!(
            fleet.record().unwrap().unwrap().phase,
            EnrollmentPhase::Revoked
        );
        let mut intents = 0;
        node.reader()
            .read(intent_start + 1, fenced, |committed| {
                if let kronik_proto::Record::AuditEvent(event) = committed.record
                    && event.action == "fleet.control.open"
                {
                    intents += 1;
                    assert!(committed.lsn < fenced);
                    assert_eq!(event.audit.as_ref().unwrap().token_id, opening_caller);
                    assert!(event.operation.is_none());
                    assert!(event.details.is_empty());
                }
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(intents, usize::from(boundary >= 2));
        drop(held);
        release.add_permits(1);
        if boundary >= 3 {
            release_peer.send(()).unwrap();
        }
        assert!(
            env.timeout(Duration::from_secs(10), work)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        let completed = env
            .timeout(
                Duration::from_secs(10),
                opening_capacity.clone().acquire_owned(),
            )
            .await
            .unwrap()
            .unwrap();
        drop(completed);
        let (probe, probed) = tokio::sync::oneshot::channel();
        step.send(ControllerStep::Probe(probe)).unwrap();
        assert!(
            env.timeout(Duration::from_secs(10), probed)
                .await
                .unwrap()
                .unwrap(),
            "no denied or extra control TCP/TLS/HTTP attempt may escape"
        );
        assert_eq!(
            publications.load(Ordering::SeqCst),
            usize::from(boundary == 4)
        );
        let denied = node
            .record_audit_event_authorized(
                "test.old-wss-command",
                "must-not-append",
                Default::default(),
                fleet.audit(
                    "controller",
                    "an old connection is not authority for a future command",
                ),
                original,
            )
            .await;
        assert!(denied.is_err());
        let following = node
            .record_audit_event_authorized(
                "test.wss-following",
                "after-owned-WSS-fence",
                Default::default(),
                fleet.audit("unix:uid=0", "observe actual following WAL"),
                authority(&fleet),
            )
            .await
            .unwrap();
        node.reader().read(fenced + 1, following, |committed| {
            if let kronik_proto::Record::AuditEvent(event) = committed.record {
                assert_ne!(event.action, "test.old-wss-command");
                assert!(!matches!(event.operation, Some(pb::audit_event::Operation::FleetState(pb::FleetState { phase, .. }))
                    if phase == pb::fleet_state::Phase::Active as i32));
            }
            Ok(())
        }).await.unwrap();
    }
    step.send(ControllerStep::Finish).unwrap();
    env.timeout(Duration::from_secs(10), finished)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tcp_attempts.load(Ordering::SeqCst), 2);
    assert!((1..=2).contains(&mtls_handshakes.load(Ordering::SeqCst)));
    assert!((1..=2).contains(&ws_handshakes.load(Ordering::SeqCst)));
}
