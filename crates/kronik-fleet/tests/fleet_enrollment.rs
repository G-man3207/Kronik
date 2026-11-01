use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use bytes::Bytes;
use kronik_core::authority::{AuthLease, Authority};
use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::env::{BoxFuture, Env, HttpRequest, HttpResponse, Net, NetError, TlsConfig, WebSocket, WebSocketRequest};
use kronik_fleet::enrollment::{ControllerClient, ControllerConfig, EnrollmentPhase, EnrollmentPlan, EnrollmentRecord, FleetError, FleetIdentity, PreparedEnrollment, ENROLLMENT_SCHEMA, canonical_controller_url, enroll, load_controller};
use kronik_fleet::transport::{EpochAuthority, PreparedControl, TUNNEL_CHUNK_BYTES, run_control};
use zeroize::Zeroizing;
use rcgen::{BasicConstraints, CertificateParams, CertificateSigningRequestParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType};
use rustls_pki_types::CertificateSigningRequestDer;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use sha2::{Digest as _, Sha256};

fn native_dispatch(prepared: PreparedEnrollment) -> BoxFuture<'static, Result<HttpResponse, FleetError>> {
    Box::pin(prepared.dispatch())
}

// Protocol units exercise an actual durable AuditEvent, not a no-op source hook.
// The API's Native consumer supplies its ordinary authorized Node audit instead.
fn native_control_intent(env: &Env, directory: &std::path::Path, prepared: &PreparedControl)
    -> BoxFuture<'static, Result<(), FleetError>>
{
    let env = env.clone();
    let directory = directory.join("control-opening-intent");
    let record = kronik_proto::Record::AuditEvent(kronik_proto::log::v1::AuditEvent {
        action: "fleet.control.open".into(), target: prepared.request_id().to_owned(),
        details: std::collections::BTreeMap::from([("epoch".into(), prepared.epoch().to_string())]),
        audit: Some(kronik_proto::log::v1::Audit {
            token_id: "token:protocol-native".into(), reason: "exercise the configured outbound control opening".into(),
            wall_time_ms: env.clock.wall_ms(),
        }), ..Default::default()
    });
    Box::pin(async move {
        let (committed, _commits) = tokio::sync::mpsc::unbounded_channel();
        let (fatal, _failure) = tokio::sync::oneshot::channel();
        let (log, _) = kronik_log::Log::open(&env, kronik_log::LogConfig::new(directory, "main"), committed, fatal)
            .await.map_err(|_| FleetError::Persistence)?;
        log.append(record).await.map_err(|_| FleetError::Persistence)?;
        Ok(())
    })
}

fn native_control_dispatch(env: &Env, directory: &std::path::Path)
    -> impl FnOnce(PreparedControl) -> BoxFuture<'static, Result<Arc<dyn WebSocket>, FleetError>> + Send + 'static + use<>
{
    let (env, directory) = (env.clone(), directory.to_path_buf());
    move |prepared: PreparedControl| -> BoxFuture<'static, Result<Arc<dyn WebSocket>, FleetError>> {
        let intent = native_control_intent(&env, &directory, &prepared);
        Box::pin(prepared.dispatch_with_admission(move || intent))
    }
}

struct ResourceHold(Arc<AtomicUsize>);
impl Drop for ResourceHold {
    fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); }
}

#[derive(Clone, Default)]
struct RevocableAuthority {
    revoked: Arc<Mutex<bool>>,
    changes: Arc<tokio::sync::Notify>,
    admissions: Arc<AtomicUsize>,
    deny_next_admission: Arc<AtomicBool>,
    attempts: Arc<AtomicUsize>,
}

impl RevocableAuthority {
    fn new() -> Arc<Self> { Arc::new(Self::default()) }
    fn revoke(&self) {
        *self.revoked.lock().unwrap() = true;
        self.changes.notify_waiters();
    }
}

impl Authority for RevocableAuthority {
    fn check(&self) -> Result<(), ApiError> {
        if *self.revoked.lock().unwrap() {
            Err(ApiError::new(ErrorCode::Unauthenticated, "owned request revoked"))
        } else { Ok(()) }
    }
    fn cancelled(&self) -> BoxFuture<'static, ()> {
        let this = self.clone();
        Box::pin(async move {
            loop {
                let changed = this.changes.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if this.check().is_err() { return; }
                changed.await;
            }
        })
    }
    fn admit(&self, effect: &mut dyn FnMut() -> Result<(), ApiError>) -> Result<(), ApiError> {
        let mut revoked = self.revoked.lock().unwrap();
        self.attempts.fetch_add(1, Ordering::SeqCst);
        if self.deny_next_admission.swap(false, Ordering::SeqCst) {
            *revoked = true;
            self.changes.notify_waiters();
        }
        if *revoked { return Err(ApiError::new(ErrorCode::Unauthenticated, "owned request revoked")); }
        self.admissions.fetch_add(1, Ordering::SeqCst);
        effect()
    }
}

#[derive(Default)]
struct Socket {
    incoming: Mutex<VecDeque<Bytes>>,
    outgoing: Mutex<Vec<Bytes>>,
    closed: AtomicUsize,
    pending_recv: AtomicBool,
    recv_waiting: Arc<tokio::sync::Notify>,
}
impl WebSocket for Socket {
    fn recv(&self) -> BoxFuture<'static, Result<Option<Bytes>, NetError>> {
        let frame = self.incoming.lock().unwrap().pop_front();
        if frame.is_none() && self.pending_recv.load(Ordering::SeqCst) {
            let waiting = self.recv_waiting.clone();
            return Box::pin(async move {
                waiting.notify_one();
                std::future::pending().await
            });
        }
        Box::pin(async move { Ok(frame) })
    }
    fn send(&self, frame: Bytes) -> BoxFuture<'static, Result<(), NetError>> {
        self.outgoing.lock().unwrap().push(frame);
        Box::pin(async { Ok(()) })
    }
    fn close(&self) -> BoxFuture<'static, Result<(), NetError>> {
        self.closed.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
}

#[derive(Clone)]
struct Network {
    requests: Arc<Mutex<Vec<HttpRequest>>>,
    request_bodies: Arc<Mutex<Vec<Bytes>>>,
    durable: Arc<Mutex<Vec<EnrollmentRecord>>>,
    mode: Arc<AtomicUsize>,
    http_waiting: Arc<tokio::sync::Notify>,
    scoped: Arc<AtomicUsize>,
    socket: Arc<Socket>,
    issuer: Arc<Mutex<Option<Issuer<'static, KeyPair>>>>,
    http_capacity: Arc<tokio::sync::Semaphore>,
    http_release: Arc<tokio::sync::Notify>,
    http_completed: Arc<AtomicUsize>,
    authorized_requests: Arc<AtomicUsize>,
    opening_capacity: Arc<tokio::sync::Semaphore>,
    control_requests: Arc<Mutex<Vec<WebSocketRequest>>>,
    control_pending: Arc<AtomicBool>,
    control_waiting: Arc<tokio::sync::Notify>,
    control_release: Arc<tokio::sync::Notify>,
    control_finished: Arc<AtomicUsize>,
    control_prepared: Arc<tokio::sync::Notify>,
}

impl Default for Network {
    fn default() -> Self {
        Self {
            requests: Arc::default(), durable: Arc::default(), mode: Arc::default(),
            http_waiting: Arc::default(), scoped: Arc::default(), socket: Arc::default(),
            issuer: Arc::default(), http_capacity: Arc::new(tokio::sync::Semaphore::new(1)),
            http_release: Arc::default(), http_completed: Arc::default(),
            authorized_requests: Arc::default(),
            request_bodies: Arc::default(),
            opening_capacity: Arc::new(tokio::sync::Semaphore::new(1)),
            control_requests: Arc::default(), control_pending: Arc::default(),
            control_waiting: Arc::default(), control_release: Arc::default(), control_finished: Arc::default(),
            control_prepared: Arc::default(),
        }
    }
}

impl Network {
    fn issue(&self, csr: &[u8], plan: &EnrollmentPlan, id: &str, epoch: u64) -> Vec<u8> {
        let csr = CertificateSigningRequestParams::from_der(&CertificateSigningRequestDer::from(csr)).unwrap();
        let mut params = CertificateParams::default();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, &plan.identity.installation);
        if let Some(cluster) = &plan.identity.cluster {
            params.distinguished_name.push(DnType::OrganizationName, cluster);
        }
        if let Some(node) = &plan.identity.node {
            params.distinguished_name.push(DnType::OrganizationalUnitName, node);
        }
        params.subject_alt_names = vec![SanType::URI(format!("urn:kronik:fleet:request:{id}:{epoch}").try_into().unwrap())];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.signed_by(&csr.public_key, self.issuer.lock().unwrap().as_ref().unwrap()).unwrap().der().to_vec()
    }

    fn response(&self, body: &[u8], headers: &[(String, String)]) -> BoxFuture<'static, Result<HttpResponse, NetError>> {
        assert_eq!(self.durable.lock().unwrap().last().unwrap().phase, EnrollmentPhase::Requested);
        let mut value: serde_json::Value = serde_json::from_slice(body).unwrap();
        let credential = headers.iter().find(|(name, _)| name == "authorization")
            .map(|(_, value)| value.strip_prefix("Bearer ").unwrap().to_owned());
        let mode = self.mode.swap(0, Ordering::SeqCst);
        let csr: Vec<u8> = serde_json::from_value(value["csr_der"].clone()).unwrap();
        let plan: EnrollmentPlan = serde_json::from_value(value["plan"].clone()).unwrap();
        let cert = self.issue(&csr, &plan, value["request_id"].as_str().unwrap(), value["epoch"].as_u64().unwrap());
        let waiting = self.http_waiting.clone();
        let release = self.http_release.clone();
        let completed = self.http_completed.clone();
        Box::pin(async move {
            if mode == 6 {
                waiting.notify_one();
                release.notified().await;
            }
            if mode == 1 { return Err(NetError::Io("lost reply".into())); }
            if mode == 3 { return Ok(HttpResponse { status: 307, headers: vec![("location".into(), "https://evil.test".into())], body: Bytes::new() }); }
            let reflected_bearer = value["api_bearer"].clone();
            value.as_object_mut().unwrap().remove("api_bearer");
            value.as_object_mut().unwrap().remove("csr_der");
            value.as_object_mut().unwrap().remove("client_key_sha256");
            value["client_cert_der"] = serde_json::to_value(cert).unwrap();
            value["controller_id"] = value["plan"]["ca_sha256"].clone();
            if mode == 4 { value["controller_id"] = reflected_bearer; }
            if mode == 5 { value["controller_id"] = credential.unwrap().into(); }
            if mode == 2 { value["plan"]["scopes"] = serde_json::json!(["admin"]); }
            completed.fetch_add(1, Ordering::SeqCst);
            Ok(HttpResponse { status: 200, headers: vec![], body: Bytes::from(serde_json::to_vec(&value).unwrap()) })
        })
    }
}
impl Net for Network {
    fn with_pinned_tls(&self, tls: TlsConfig) -> Result<Arc<dyn Net>, NetError> {
        if tls.identity.is_some() { self.control_prepared.notify_one(); }
        assert!(!tls.ca.is_empty());
        self.scoped.fetch_add(1, Ordering::SeqCst);
        Ok(Arc::new(self.clone()))
    }
    fn http(&self, _request: HttpRequest) -> BoxFuture<'static, Result<HttpResponse, NetError>> {
        Box::pin(async { Err(NetError::Io("unscoped enrollment HTTP is forbidden".into())) })
    }
    fn http_authorized(&self, request: HttpRequest, original: AuthLease)
        -> BoxFuture<'static, Result<HttpResponse, NetError>> {
        let network = self.clone();
        Box::pin(async move {
            assert_eq!(request.url, "https://controller.test/v1/enroll");
            assert_eq!(request.max_response_bytes, 65536);
            let HttpRequest { method, url, headers, body, max_response_bytes } = request;
            if body.len() > 65536 { return Err(NetError::TooLarge); }
            let response = network.response(&body, &headers);
            let mut request = Some(HttpRequest { method, url, headers,
                body: body.clone(), max_response_bytes });
            let mut captured_body = Some(body);
            let admitted = original.admit(&mut || {
                network.requests.lock().unwrap().push(request.take().ok_or_else(|| ApiError::new(
                    ErrorCode::Internal, "owned HTTP fixture consumed a request twice"))?);
                network.request_bodies.lock().unwrap().push(captured_body.take().unwrap());
                network.authorized_requests.fetch_add(1, Ordering::SeqCst);
                Ok(())
            });
            let _original = original;
            admitted.map_err(|_| NetError::Io("owned HTTP authority denied".into()))?;
            response.await
        })
    }
    fn websocket(&self, request: WebSocketRequest) -> BoxFuture<'static, Result<Arc<dyn WebSocket>, NetError>> {
        assert_eq!(request.url, "wss://controller.test/v1/control");
        assert_eq!(request.max_message_bytes, TUNNEL_CHUNK_BYTES);
        self.control_requests.lock().unwrap().push(request);
        let pending = self.control_pending.load(Ordering::SeqCst);
        let (waiting, release, finished) = (self.control_waiting.clone(), self.control_release.clone(), self.control_finished.clone());
        let socket = self.socket.clone() as Arc<dyn WebSocket>;
        Box::pin(async move {
            if pending { waiting.notify_one(); release.notified().await; }
            finished.fetch_add(1, Ordering::SeqCst);
            Ok(socket)
        })
    }
}

fn active_authority(record: &EnrollmentRecord) -> Arc<EpochAuthority> {
    assert_eq!(record.phase, EnrollmentPhase::Active);
    let authority = EpochAuthority::new(record.epoch);
    authority.publish(record).unwrap();
    authority
}

fn persistence(network: &Network) -> impl FnMut(EnrollmentRecord) -> BoxFuture<'static, Result<(), FleetError>> {
    let durable = network.durable.clone();
    move |record| {
        durable.lock().unwrap().push(record);
        Box::pin(async { Ok(()) })
    }
}

async fn setup() -> (Env, ControllerClient, Network, EnrollmentRecord, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let write = |name: &str, value: &[u8]| {
        use std::io::Write as _;
        let mut file = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        file.write_all(value).unwrap();
        let path = directory.path().join(name);
        file.persist(&path).unwrap();
        path
    };
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let key = KeyPair::generate().unwrap();
    let root = params.self_signed(&key).unwrap();
    let config = ControllerConfig {
        url: "https://CONTROLLER.test:443/".into(),
        ca_file: write("ca.pem", root.pem().as_bytes()),
        client_key_file: directory.path().join("identity/client.key"),
    };
    let network = Network::default();
    *network.issuer.lock().unwrap() = Some(Issuer::new(params, key));
    let mut env = Env::real(tokio::runtime::Handle::current());
    env.net = Arc::new(network.clone());
    let client = load_controller(&env, &config).await.unwrap();
    let plan = client.plan(FleetIdentity { installation: "installation-1".into(), node: Some("node-1".into()), cluster: None }, vec!["read".into()]).unwrap();
    let record = EnrollmentRecord::prepare(&env, &client, plan, 1).await.unwrap();
    (env, client, network, record, directory)
}

struct HeldHttpSpawner {
    inner: Arc<dyn kronik_core::env::Spawner>,
    queued: Mutex<Option<BoxFuture<'static, ()>>>,
    ready: tokio::sync::Notify,
}

impl kronik_core::env::Spawner for HeldHttpSpawner {
    fn spawn(&self, name: &'static str, job: BoxFuture<'static, ()>) {
        if name == "fleet-enrollment-http" {
            assert!(self.queued.lock().unwrap().replace(job).is_none());
            self.ready.notify_one();
        } else { self.inner.spawn(name, job); }
    }
    fn spawn_blocking(&self, name: &'static str, job: Box<dyn FnOnce() + Send + 'static>) {
        self.inner.spawn_blocking(name, job);
    }
}

struct RealController {
    env: Env,
    client: ControllerClient,
    network: Network,
    record: EnrollmentRecord,
    _directory: tempfile::TempDir,
    received: Arc<tokio::sync::Notify>,
    release: std::sync::mpsc::SyncSender<()>,
    observed: Arc<Mutex<Vec<(String, u64)>>>,
    finished: kronik_core::env::JoinHandle<EnrollmentRecord>,
}

async fn real_controller() -> RealController {
    let (_, _, network, old_record, directory) = setup().await;
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let cert = params.signed_by(&key, network.issuer.lock().unwrap().as_ref().unwrap()).unwrap();
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions().unwrap().with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()],
            rustls_pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into()).unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let client = load_controller(&env, &ControllerConfig {
        url: format!("https://{address}"), ca_file: directory.path().join("ca.pem"),
        client_key_file: directory.path().join("identity/client.key"),
    }).await.unwrap();
    let plan = client.plan(old_record.plan.identity, old_record.plan.scopes).unwrap();
    let record = EnrollmentRecord::prepare(&env, &client, plan, 1).await.unwrap();
    let received = Arc::new(tokio::sync::Notify::new());
    let observed = Arc::new(Mutex::new(Vec::new()));
    let (release, released) = std::sync::mpsc::sync_channel(1);
    let (server_received, server_observed, issuer) = (received.clone(), observed.clone(), network.clone());
    let finished = env.blocking("test-real-fleet-controller", move || {
        use std::io::{Read as _, Write as _};
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let tls = Arc::new(tls);
        let (mut stream, header) = 'connections: loop {
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(std::time::Instant::now() < deadline, "owned controller accept deadline");
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(error) => panic!("owned controller accept: {}", error.kind()),
                }
            };
            stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
            stream.set_write_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
            let mut stream = rustls::StreamOwned::new(rustls::ServerConnection::new(tls.clone()).unwrap(), stream);
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                assert!(header.len() < 8192);
                let mut byte = [0];
                match stream.read_exact(&mut byte) {
                    Ok(()) => header.push(byte[0]),
                    Err(error) if header.is_empty() && error.kind() == std::io::ErrorKind::UnexpectedEof =>
                        continue 'connections,
                    Err(error) => panic!("owned controller HTTP read: {}", error.kind()),
                }
            }
            break (stream, header);
        };
        let header = std::str::from_utf8(&header).unwrap();
        assert!(header.starts_with("POST /v1/enroll HTTP/1.1\r\n"));
        let length: usize = header.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse().unwrap())
        }).unwrap();
        assert!(length > 0 && length <= kronik_fleet::enrollment::MAX_ENROLLMENT_BYTES);
        let mut body = vec![0; length];
        stream.read_exact(&mut body).unwrap();
        let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let request_id = request["request_id"].as_str().unwrap().to_owned();
        let epoch = request["epoch"].as_u64().unwrap();
        let plan: EnrollmentPlan = serde_json::from_value(request["plan"].clone()).unwrap();
        let csr: Vec<u8> = serde_json::from_value(request["csr_der"].clone()).unwrap();
        let certificate = issuer.issue(&csr, &plan, &request_id, epoch);
        server_observed.lock().unwrap().push((request_id.clone(), epoch));
        #[derive(serde::Serialize)]
        struct Response<'a> {
            schema: &'a str, request_id: &'a str, epoch: u64, plan: &'a EnrollmentPlan,
            controller_id: &'a str, client_cert_der: &'a [u8],
        }
        let body = serde_json::to_vec(&Response {
            schema: ENROLLMENT_SCHEMA, request_id: &request_id, epoch, plan: &plan,
            controller_id: &plan.ca_sha256, client_cert_der: &certificate,
        }).unwrap();
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
        stream.flush().unwrap();
        server_received.notify_one();
        released.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        stream.write_all(&body).unwrap();
        stream.flush().unwrap();
        EnrollmentRecord { controller_id: Some(plan.ca_sha256.clone()), plan, request_id, epoch,
            phase: EnrollmentPhase::Active, csr_der: csr,
            client_key_sha256: request["client_key_sha256"].as_str().unwrap().to_owned(),
            client_cert_der: Some(certificate) }
    });
    RealController { env, client, network, record, _directory: directory, received, release, observed, finished }
}

fn guarded_persistence(network: &Network, authority: AuthLease)
    -> impl FnMut(EnrollmentRecord) -> BoxFuture<'static, Result<(), FleetError>> {
    let saved = network.durable.clone();
    move |record| {
        let mut record = Some(record);
        let result = authority.admit(&mut || {
            saved.lock().unwrap().push(record.take().unwrap());
            Ok(())
        }).map_err(|_| FleetError::Revoked);
        Box::pin(async move { result })
    }
}

#[tokio::test]
async fn real_net_revocation_after_requested_sends_nothing_then_distinct_request_succeeds() {
    let RealController { env, client, network, record, _directory, received, release, observed, finished } = real_controller().await;
    let authority = RevocableAuthority::new();
    let (saved, revoke) = (network.durable.clone(), authority.clone());
    let result = enroll(&env, &client, record.clone(), Some(Zeroizing::new("denied-once".into())),
        "denied-api", authority.clone(), network.http_capacity.clone(), native_dispatch, move |record| {
            let requested = record.phase == EnrollmentPhase::Requested;
            saved.lock().unwrap().push(record);
            if requested { revoke.deny_next_admission.store(true, Ordering::SeqCst); }
            Box::pin(async { Ok(()) })
        }).await;
    assert!(matches!(result, Err(FleetError::Revoked)));
    assert!(observed.lock().unwrap().is_empty());
    assert_eq!(authority.admissions.load(Ordering::SeqCst), 0);
    assert_eq!(authority.attempts.load(Ordering::SeqCst), 1, "canonical final Net queue must reject");
    let following = EnrollmentRecord::prepare(&env, &client, record.plan, 2).await.unwrap();
    let following_id = following.request_id.clone();
    assert_ne!(following_id, record.request_id);
    let task_env = env.clone();
    let task_network = network.clone();
    let next_authority = RevocableAuthority::new();
    let active = env.spawn("test-distinct-real-enrollment", async move {
        enroll(&task_env, &client, following, Some(Zeroizing::new("allowed-once".into())),
            "allowed-api", next_authority.clone(), task_network.http_capacity.clone(), native_dispatch,
            guarded_persistence(&task_network, next_authority)).await
    });
    env.timeout(std::time::Duration::from_secs(5), received.notified()).await.unwrap();
    assert_eq!(*observed.lock().unwrap(), vec![(following_id.clone(), 2)]);
    release.send(()).unwrap();
    let active = env.timeout(std::time::Duration::from_secs(5), active).await.unwrap().unwrap().unwrap();
    assert_eq!(active.request_id, following_id);
    assert_eq!(active.phase, EnrollmentPhase::Active);
    assert_eq!(env.timeout(std::time::Duration::from_secs(5), finished).await.unwrap().unwrap(), active);
}

#[tokio::test]
async fn real_net_queued_before_start_is_denied_but_started_http_outlives_its_waiter() {
    let RealController { mut env, client, network, record, _directory, received, release, observed, finished } = real_controller().await;
    let held = Arc::new(HeldHttpSpawner { inner: env.spawner.clone(), queued: Mutex::new(None), ready: tokio::sync::Notify::new() });
    env.spawner = held.clone();
    let authority = RevocableAuthority::new();
    let (task_env, task_network, task_authority, task_client, task_record) =
        (env.clone(), network.clone(), authority.clone(), client.clone(), record.clone());
    let denied = env.spawn("test-held-real-enrollment", async move {
        enroll(&task_env, &task_client, task_record, Some(Zeroizing::new("queued-once".into())),
            "queued-api", task_authority.clone(), task_network.http_capacity.clone(), native_dispatch,
            guarded_persistence(&task_network, task_authority)).await
    });
    env.timeout(std::time::Duration::from_secs(5), held.ready.notified()).await.unwrap();
    assert_eq!(network.http_capacity.available_permits(), 0);
    authority.revoke();
    assert!(matches!(env.timeout(std::time::Duration::from_secs(5), denied).await.unwrap().unwrap(), Err(FleetError::Revoked)));
    let queued = held.queued.lock().unwrap().take().unwrap();
    held.inner.spawn("test-release-denied-http", queued);
    let permit = env.timeout(std::time::Duration::from_secs(5), network.http_capacity.clone().acquire_owned()).await.unwrap().unwrap();
    drop(permit);
    assert!(observed.lock().unwrap().is_empty());
    env.spawner = held.inner.clone();
    let next = EnrollmentRecord::prepare(&env, &client, record.plan, 2).await.unwrap();
    let next_id = next.request_id.clone();
    let next_authority = RevocableAuthority::new();
    let (task_env, task_network, task_authority) = (env.clone(), network.clone(), next_authority.clone());
    let hold_dropped = Arc::new(AtomicUsize::new(0));
    let hold = ResourceHold(hold_dropped.clone());
    let started = env.spawn("test-started-real-enrollment", async move {
        enroll(&task_env, &client, next, Some(Zeroizing::new("started-once".into())),
            "started-api", task_authority.clone(), task_network.http_capacity.clone(),
            move |prepared| Box::pin(prepared.dispatch_with_hold(hold)),
            guarded_persistence(&task_network, task_authority)).await
    });
    env.timeout(std::time::Duration::from_secs(5), received.notified()).await.unwrap();
    assert_eq!(*observed.lock().unwrap(), vec![(next_id, 2)]);
    next_authority.revoke();
    assert!(matches!(env.timeout(std::time::Duration::from_secs(5), started).await.unwrap().unwrap(), Err(FleetError::Revoked)));
    assert_eq!(network.http_capacity.available_permits(), 0);
    assert_eq!(hold_dropped.load(Ordering::SeqCst), 0, "transport hold must survive response head");
    release.send(()).unwrap();
    let active = env.timeout(std::time::Duration::from_secs(5), finished).await.unwrap().unwrap();
    let permit = env.timeout(std::time::Duration::from_secs(5), network.http_capacity.clone().acquire_owned()).await.unwrap().unwrap();
    drop(permit);
    assert_eq!(hold_dropped.load(Ordering::SeqCst), 1, "transport hold releases at actual body EOF");
    let mut persist = guarded_persistence(&network, next_authority);
    assert!(matches!(persist(active).await, Err(FleetError::Revoked)));
    assert_eq!(observed.lock().unwrap().len(), 1);
    assert!(network.durable.lock().unwrap().iter().all(|record| record.phase != EnrollmentPhase::Active));
}

#[test]
fn controller_origin_and_scope_validation_are_local() {
    assert_eq!(canonical_controller_url("https://EXAMPLE.test:443/").unwrap(), "https://example.test");
    for bad in ["http://example.test", "https://user@example.test", "https://example.test/else", "https://example.test/?x=1", "https://example.test/#x"] {
        assert!(canonical_controller_url(bad).is_err());
    }
    let mut plan = EnrollmentPlan { controller_url: "https://controller.test".into(), identity: FleetIdentity { installation: "i".into(), node: None, cluster: None }, scopes: vec!["read".into(), "fork".into()], ca_sha256: "b".repeat(64) };
    assert!(plan.validate().is_ok());
    for invalid in [vec!["status:read".into()], vec!["read".into(), "read".into()], vec!["fork".into(), "read".into()]] {
        plan.scopes = invalid;
        assert!(plan.validate().is_err());
    }
}

#[tokio::test]
async fn lost_reply_resumes_same_identity_without_one_time_credential() {
    let (env, client, network, record, _dir) = setup().await;
    network.mode.store(1, Ordering::SeqCst);
    let descriptors = Arc::new(Mutex::new(Vec::new()));
    let capture = descriptors.clone();
    let first = enroll(&env, &client, record.clone(), Some(Zeroizing::new("dummy-once".into())),
        "dummy-api", RevocableAuthority::new(), network.http_capacity.clone(), move |prepared| {
            capture.lock().unwrap().push((prepared.destination().to_owned(), prepared.body_hash(), prepared.command_hash()));
            native_dispatch(prepared)
        }, persistence(&network)).await;
    assert!(matches!(first, Err(FleetError::Unavailable)));
    let requested = network.durable.lock().unwrap().last().unwrap().clone();
    assert_eq!(requested.request_id, record.request_id);
    let capture = descriptors.clone();
    let active = enroll(&env, &client, requested, Some(Zeroizing::new("must-not-be-reused".into())),
        "dummy-api", RevocableAuthority::new(), network.http_capacity.clone(), move |prepared| {
            capture.lock().unwrap().push((prepared.destination().to_owned(), prepared.body_hash(), prepared.command_hash()));
            native_dispatch(prepared)
        }, persistence(&network)).await.unwrap();
    assert_eq!(active.phase, EnrollmentPhase::Active);
    assert_eq!(active.controller_id.as_deref(), Some(active.plan.ca_sha256.as_str()));
    let requests = network.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(network.authorized_requests.load(Ordering::SeqCst), 2);
    let bodies = network.request_bodies.lock().unwrap();
    assert_eq!(bodies[0], bodies[1]);
    assert!(requests[0].headers.iter().any(|(name, _)| name == "authorization"));
    assert!(!requests[1].headers.iter().any(|(name, _)| name == "authorization"));
    assert_eq!(network.scoped.load(Ordering::SeqCst), 1);
    let descriptors = descriptors.lock().unwrap();
    assert_eq!(descriptors.len(), 2);
    assert_eq!(descriptors[0].0, "https://controller.test/v1/enroll");
    assert_eq!(descriptors[1].0, descriptors[0].0);
    let expected_body_hash: [u8; 32] = Sha256::digest(&bodies[0]).into();
    assert_eq!(descriptors[0].1, expected_body_hash);
    assert_eq!(descriptors[1].1, expected_body_hash);
    assert_ne!(descriptors[0].2, descriptors[1].2, "initial credential header is command-bound");
}

#[tokio::test]
async fn prepared_factory_is_required_after_requested_and_already_owns_capacity() {
    let (env, client, network, record, _dir) = setup().await;
    let observation = network.clone();
    let result = enroll(&env, &client, record, Some(Zeroizing::new("dummy-once".into())),
        "dummy-api", RevocableAuthority::new(), network.http_capacity.clone(), move |prepared| {
            assert_eq!(observation.durable.lock().unwrap().last().unwrap().phase, EnrollmentPhase::Requested);
            assert_eq!(observation.http_capacity.available_permits(), 0);
            assert_eq!(prepared.destination(), "https://controller.test/v1/enroll");
            drop(prepared); // A refused global handoff cannot invoke the producer.
            Box::pin(async { Err(FleetError::Revoked) })
        }, persistence(&network)).await;
    assert!(matches!(result, Err(FleetError::Revoked)));
    assert_eq!(network.http_capacity.available_permits(), 1);
    assert!(network.requests.lock().unwrap().is_empty());
    assert_eq!(network.durable.lock().unwrap().last().unwrap().phase, EnrollmentPhase::Requested);
}

#[tokio::test]
async fn confirmation_starts_inside_owned_http_job_and_denial_never_sends() {
    let (mut env, client, network, record, _dir) = setup().await;
    let held = Arc::new(HeldHttpSpawner {
        inner: env.spawner.clone(), queued: Mutex::new(None), ready: tokio::sync::Notify::new(),
    });
    env.spawner = held.clone();
    let started = Arc::new(AtomicUsize::new(0));
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let (job_started, job_entered, job_release, job_network) =
        (started.clone(), entered.clone(), release.clone(), network.clone());
    let (task_env, task_network) = (env.clone(), network.clone());
    let pending = env.spawn("test-owned-confirmation-order", async move {
        enroll(&task_env, &client, record, Some(Zeroizing::new("dummy-once".into())),
            "dummy-api", RevocableAuthority::new(), task_network.http_capacity.clone(),
            move |prepared| Box::pin(prepared.dispatch_with_admission(move || {
                job_started.fetch_add(1, Ordering::SeqCst);
                assert_eq!(job_network.http_capacity.available_permits(), 0);
                assert!(job_network.requests.lock().unwrap().is_empty());
                async move {
                    job_entered.notify_one();
                    job_release.notified().await;
                    Err::<(), FleetError>(FleetError::Revoked)
                }
            })), persistence(&task_network)).await
    });
    env.timeout(std::time::Duration::from_secs(2), held.ready.notified()).await.unwrap();
    assert_eq!(started.load(Ordering::SeqCst), 0, "confirmation cannot run before owned handoff");
    assert_eq!(network.http_capacity.available_permits(), 0);
    assert!(network.requests.lock().unwrap().is_empty());
    held.inner.spawn("test-release-owned-confirmation", held.queued.lock().unwrap().take().unwrap());
    env.timeout(std::time::Duration::from_secs(2), entered.notified()).await.unwrap();
    assert_eq!(started.load(Ordering::SeqCst), 1);
    assert_eq!(network.http_capacity.available_permits(), 0);
    assert!(network.requests.lock().unwrap().is_empty());
    release.notify_one();
    let result = env.timeout(std::time::Duration::from_secs(2), pending).await.unwrap().unwrap();
    assert!(matches!(result, Err(FleetError::Revoked)));
    assert_eq!(network.http_capacity.available_permits(), 1);
    assert!(network.requests.lock().unwrap().is_empty());
    assert_eq!(network.durable.lock().unwrap().last().unwrap().phase, EnrollmentPhase::Requested);
}

#[tokio::test]
async fn durable_failure_never_transmits_and_changed_authority_never_activates() {
    let (env, client, network, record, _dir) = setup().await;
    let result = enroll(&env, &client, record.clone(), Some(Zeroizing::new("dummy".into())), "dummy-api", RevocableAuthority::new(), network.http_capacity.clone(), native_dispatch, |_| Box::pin(async { Err(FleetError::Persistence) })).await;
    assert!(matches!(result, Err(FleetError::Persistence)));
    assert!(network.requests.lock().unwrap().is_empty());
    network.mode.store(2, Ordering::SeqCst);
    let result = enroll(&env, &client, record, Some(Zeroizing::new("dummy".into())), "dummy-api", RevocableAuthority::new(), network.http_capacity.clone(), native_dispatch, persistence(&network)).await;
    assert!(matches!(result, Err(FleetError::Protocol)));
    assert_eq!(network.durable.lock().unwrap().last().unwrap().phase, EnrollmentPhase::Requested);
}

#[tokio::test]
async fn redirect_never_selects_destination_or_reuses_token() {
    let (env, client, network, record, _dir) = setup().await;
    network.mode.store(3, Ordering::SeqCst);
    assert!(matches!(enroll(&env, &client, record, Some(Zeroizing::new("dummy".into())), "dummy-api", RevocableAuthority::new(), network.http_capacity.clone(), native_dispatch, persistence(&network)).await, Err(FleetError::Rejected)));
    assert_eq!(network.requests.lock().unwrap().len(), 1);
}


#[tokio::test]
async fn epoch_guards_fence_body_queue_and_never_resurrect() {
    let (env, client, network, mut record, _dir) = setup().await;
    record.epoch = 4;
    let authority = EpochAuthority::new(4);
    assert!(authority.guard().check().is_err());
    authority.publish(&record).unwrap();
    let pending_guard = authority.guard();
    authority.publish(&record).unwrap();
    assert!(pending_guard.check().is_err());
    record.phase = EnrollmentPhase::Requested;
    authority.publish(&record).unwrap();
    let requested_guard = authority.guard();
    authority.publish(&record).unwrap();
    assert!(requested_guard.check().is_err());
    record.phase = EnrollmentPhase::Active;
    record.controller_id = Some(record.plan.ca_sha256.clone());
    record.client_cert_der = Some(network.issue(&record.csr_der, &record.plan, &record.request_id, record.epoch));
    authority.publish(&record).unwrap();
    let guard = authority.guard();
    authority.publish(&record).unwrap();
    assert!(guard.check().is_ok());
    assert_eq!(guard.request_id(), Some(record.request_id.as_str()));
    let revoked = record.revoke().unwrap();
    assert_eq!(revoked.epoch, record.epoch);
    assert_eq!(revoked.csr_der, record.csr_der);
    assert_eq!(revoked.client_cert_der, record.client_cert_der);
    authority.publish(&revoked).unwrap();
    guard.cancelled().await;
    assert!(guard.check().is_err());
    assert!(authority.guard().check().is_err());
    assert!(authority.publish(&record).is_err());
    let restored: EnrollmentRecord = serde_json::from_slice(&serde_json::to_vec(&revoked).unwrap()).unwrap();
    let restarted = EpochAuthority::new(restored.epoch);
    restarted.publish(&restored).unwrap();
    assert!(restarted.guard().check().is_err());
    assert!(restarted.publish(&record).is_err());
    let mut renewed = EnrollmentRecord::prepare(&env, &client, record.plan.clone(), 5).await.unwrap();
    authority.publish(&renewed).unwrap();
    assert!(authority.guard().check().is_err());
    renewed.phase = EnrollmentPhase::Requested;
    authority.publish(&renewed).unwrap();
    renewed.phase = EnrollmentPhase::Active;
    renewed.controller_id = Some(renewed.plan.ca_sha256.clone());
    renewed.client_cert_der = Some(network.issue(&renewed.csr_der, &renewed.plan, &renewed.request_id, renewed.epoch));
    authority.publish(&renewed).unwrap();
    assert!(authority.guard().check().is_ok());
    assert!(guard.check().is_err());
    assert!(authority.publish(&record).is_err());
}

#[tokio::test]
async fn raw_tunnel_preserves_native_sse_and_websocket_wire_bytes() {
    let streams = [
        (b"GET /v1/events/stream HTTP/1.1\r\nHost: installation\r\n\r\n".to_vec(),
         b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n9\r\ndata: x\n\n\r\n0\r\n\r\n".to_vec()),
        (b"GET /v1/events/ws HTTP/1.1\r\nHost: installation\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n".to_vec(),
         [b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n".as_slice(), &[0x81, 2, b'o', b'k', 0x88, 2, 3, 232]].concat()),
    ];
    for (request, response) in streams {
        let (env, client, network, mut record, _dir) = setup().await;
        record.phase = EnrollmentPhase::Active;
        record.client_cert_der = Some(network.issue(&record.csr_der, &record.plan, &record.request_id, record.epoch));
        network.socket.pending_recv.store(true, Ordering::SeqCst);
        network.socket.incoming.lock().unwrap().push_back(Bytes::copy_from_slice(&request));
        let expected = response.clone();
        run_control(&env, &client, &record, "dummy-api", active_authority(&record).guard(), RevocableAuthority::new(), network.opening_capacity.clone(), native_control_dispatch(&env, _dir.path()), move |mut stream, guard| Box::pin(async move {
            let mut received = vec![0; request.len()];
            stream.read_exact(&mut received).await.unwrap();
            guard.check().unwrap();
            assert!(received == request);
            stream.write_all(&response).await.unwrap();
            stream.shutdown().await.unwrap();
        })).await.unwrap();
        let sent = network.socket.outgoing.lock().unwrap();
        assert!(sent.iter().all(|chunk| chunk.len() <= TUNNEL_CHUNK_BYTES));
        let bytes = sent.iter().flat_map(|chunk| chunk.iter().copied()).collect::<Vec<_>>();
        assert!(bytes == expected);
        assert_eq!(network.socket.closed.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn revoked_queued_http_bytes_never_reach_the_api_connection() {
    let (env, client, network, mut record, _dir) = setup().await;
    record.phase = EnrollmentPhase::Active;
    record.client_cert_der = Some(network.issue(&record.csr_der, &record.plan, &record.request_id, record.epoch));
    network.socket.incoming.lock().unwrap().push_back(Bytes::from_static(b"GET /v1/health HTTP/1.1\r\nHost: installation\r\n\r\n"));
    let authority = active_authority(&record);
    let guard = authority.guard();
    authority.publish(&record.revoke().unwrap()).unwrap();
    let result = run_control(&env, &client, &record, "dummy-api", guard, RevocableAuthority::new(), network.opening_capacity.clone(), native_control_dispatch(&env, _dir.path()), |_, _| panic!("revoked connection served")).await;
    assert!(matches!(result, Err(FleetError::Revoked)));
}

#[tokio::test]
async fn preview_plan_does_not_network_or_prepare_durable_enrollment() {
    let (env, _client, network, record, directory) = setup().await;
    let config = ControllerConfig {
        url: record.plan.controller_url.clone(), ca_file: directory.path().join("ca.pem"),
        client_key_file: directory.path().join("preview-only.key"),
    };
    let client = load_controller(&env, &config).await.unwrap();
    client.plan(record.plan.identity.clone(), record.plan.scopes.clone()).unwrap();
    assert!(!config.client_key_file.exists());
    assert!(network.requests.lock().unwrap().is_empty());
    assert!(network.durable.lock().unwrap().is_empty());
    assert_eq!(ENROLLMENT_SCHEMA, "kronik.fleet-enrollment/v1");
}

#[tokio::test]
async fn revoke_during_dispatch_stops_reply_without_claiming_rollback() {
    let (env, client, network, mut record, _dir) = setup().await;
    record.phase = EnrollmentPhase::Active;
    network.socket.pending_recv.store(true, Ordering::SeqCst);
    record.client_cert_der = Some(network.issue(&record.csr_der, &record.plan, &record.request_id, record.epoch));
    let authority = active_authority(&record);
    let admitted = Arc::new(AtomicUsize::new(0));
    let seen = admitted.clone();
    let revoke = authority.clone();
    let revoked = record.revoke().unwrap();
    let result = run_control(&env, &client, &record, "dummy-api", authority.guard(), RevocableAuthority::new(), network.opening_capacity.clone(), native_control_dispatch(&env, _dir.path()), move |stream, guard| {
        Box::pin(async move {
            guard.check().unwrap();
            seen.fetch_add(1, Ordering::SeqCst);
            revoke.publish(&revoked).unwrap();
            drop(stream);
        })
    }).await;
    assert!(matches!(result, Err(FleetError::Revoked)));
    assert_eq!(admitted.load(Ordering::SeqCst), 1);
    assert!(network.socket.outgoing.lock().unwrap().is_empty());
    assert_eq!(network.socket.closed.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn protected_private_key_rejects_public_mode_and_symlink() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    let (env, _client, _network, _record, directory) = setup().await;
    let config = ControllerConfig {
        url: "https://controller.test".into(), ca_file: directory.path().join("ca.pem"),
        client_key_file: directory.path().join("identity/client.key"),
    };
    std::fs::set_permissions(&config.client_key_file, std::fs::Permissions::from_mode(0o644)).unwrap();
    let client = load_controller(&env, &config).await.unwrap();
    assert!(EnrollmentRecord::prepare(&env, &client, _record.plan.clone(), 2).await.is_err());
    std::fs::set_permissions(&config.client_key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let linked = directory.path().join("linked-key.pem");
    symlink(&config.client_key_file, &linked).unwrap();
    let mut linked_config = config;
    linked_config.client_key_file = linked;
    let client = load_controller(&env, &linked_config).await.unwrap();
    assert!(EnrollmentRecord::prepare(&env, &client, _record.plan, 2).await.is_err());
}

#[tokio::test]
async fn issued_certificate_must_match_csr_installation_request_and_pinned_issuer() {
    let (env, client, network, mut record, _dir) = setup().await;
    let (_other_env, _other_client, other_network, other_record, _other_dir) = setup().await;
    record.phase = EnrollmentPhase::Active;
    let mut wrong_identity = record.plan.clone();
    wrong_identity.identity.installation = "another-installation".into();
    let certificates = [
        network.issue(&other_record.csr_der, &record.plan, &record.request_id, record.epoch),
        network.issue(&record.csr_der, &wrong_identity, &record.request_id, record.epoch),
        network.issue(&record.csr_der, &record.plan, "different-request", record.epoch),
        other_network.issue(&record.csr_der, &record.plan, &record.request_id, record.epoch),
    ];
    for certificate in certificates {
        record.client_cert_der = Some(certificate);
        let result = run_control(&env, &client, &record, "dummy-api", active_authority(&record).guard(), RevocableAuthority::new(), network.opening_capacity.clone(), native_control_dispatch(&env, _dir.path()), |_, _| panic!("invalid certificate dispatched")).await;
        assert!(matches!(result, Err(FleetError::Protocol)));
    }
    assert!(network.socket.outgoing.lock().unwrap().is_empty());
}

#[tokio::test]
async fn requested_identity_cannot_silently_replace_its_leaf_or_csr() {
    let (env, client, network, mut record, _dir) = setup().await;
    let (_other_env, _other_client, _other_network, other_record, _other_dir) = setup().await;
    record.phase = EnrollmentPhase::Requested;
    record.csr_der = other_record.csr_der;
    let result = enroll(&env, &client, record, None, "dummy-api", RevocableAuthority::new(), network.http_capacity.clone(), native_dispatch, persistence(&network)).await;
    assert!(matches!(result, Err(FleetError::Invalid(_))));
    assert!(network.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn ordinary_component_sized_http_bodies_cross_multiple_bounded_chunks() {
    let (env, client, network, mut record, _dir) = setup().await;
    record.phase = EnrollmentPhase::Active;
    record.client_cert_der = Some(network.issue(&record.csr_der, &record.plan, &record.request_id, record.epoch));
    let body = vec![b'W'; 2 << 20];
    let mut request = format!("POST /v1/deployments HTTP/1.1\r\nHost: installation\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    request.extend_from_slice(&body);
    let mut response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    response.extend_from_slice(&body);
    network.socket.pending_recv.store(true, Ordering::SeqCst);
    for chunk in request.chunks(TUNNEL_CHUNK_BYTES) {
        network.socket.incoming.lock().unwrap().push_back(Bytes::copy_from_slice(chunk));
    }
    let expected = response.clone();
    run_control(&env, &client, &record, "dummy-api", active_authority(&record).guard(), RevocableAuthority::new(), network.opening_capacity.clone(), native_control_dispatch(&env, _dir.path()), move |mut stream, guard| Box::pin(async move {
        let mut received = vec![0; request.len()];
        stream.read_exact(&mut received).await.unwrap();
        guard.check().unwrap();
        assert!(received == request);
        stream.write_all(&response).await.unwrap();
        stream.shutdown().await.unwrap();
    })).await.unwrap();
    let sent = network.socket.outgoing.lock().unwrap();
    assert!(sent.len() > 1);
    assert!(sent.iter().all(|chunk| chunk.len() <= TUNNEL_CHUNK_BYTES));
    assert!(sent.iter().flat_map(|chunk| chunk.iter().copied()).eq(expected));
}

#[tokio::test]
async fn an_oversized_outer_message_is_not_forwarded_as_http() {
    let (env, client, network, mut record, _dir) = setup().await;
    record.phase = EnrollmentPhase::Active;
    record.client_cert_der = Some(network.issue(&record.csr_der, &record.plan, &record.request_id, record.epoch));
    network.socket.incoming.lock().unwrap().push_back(Bytes::from(vec![b'x'; TUNNEL_CHUNK_BYTES + 1]));
    let (finished, completion) = tokio::sync::oneshot::channel();
    let result = run_control(&env, &client, &record, "dummy-api", active_authority(&record).guard(), RevocableAuthority::new(), network.opening_capacity.clone(), native_control_dispatch(&env, _dir.path()), move |mut stream, _| Box::pin(async move {
        let mut byte = [0; 1];
        assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
        finished.send(()).unwrap();
    })).await;
    assert!(matches!(result, Err(FleetError::Protocol)));
    env.timeout(std::time::Duration::from_secs(2), completion).await.unwrap().unwrap();
    assert!(network.socket.outgoing.lock().unwrap().is_empty());
}

#[tokio::test]
async fn revocation_cancels_a_pending_frame_before_any_dispatch() {
    let (env, client, network, mut record, _dir) = setup().await;
    record.phase = EnrollmentPhase::Active;
    record.client_cert_der = Some(network.issue(&record.csr_der, &record.plan, &record.request_id, record.epoch));
    network.socket.pending_recv.store(true, Ordering::SeqCst);
    let authority = active_authority(&record);
    let guard = authority.guard();
    let task_env = env.clone();
    let revoked = record.revoke().unwrap();
    let (finished, completion) = tokio::sync::oneshot::channel();
    let opening_capacity = network.opening_capacity.clone();
    let opening_dispatch = native_control_dispatch(&env, _dir.path());
    let pending = env.spawn("test-fleet-frame-revocation", async move {
        run_control(&task_env, &client, &record, "dummy-api", guard, RevocableAuthority::new(), opening_capacity, opening_dispatch,
            move |mut stream, _| Box::pin(async move {
                let mut byte = [0; 1];
                assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
                finished.send(()).unwrap();
            })).await
    });
    env.timeout(std::time::Duration::from_secs(2), network.socket.recv_waiting.notified()).await.unwrap();
    authority.publish(&revoked).unwrap();
    let result = env.timeout(std::time::Duration::from_secs(2), pending).await.unwrap().unwrap();
    assert!(matches!(result, Err(FleetError::Revoked)));
    env.timeout(std::time::Duration::from_secs(2), completion).await.unwrap().unwrap();
    assert!(network.socket.outgoing.lock().unwrap().is_empty());
    assert_eq!(network.socket.closed.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn reflected_credentials_cannot_become_durable_controller_identity() {
    for mode in [4, 5] {
        let (env, client, network, record, _dir) = setup().await;
        // Both needles look like canonical hashes; only exact local binding is safe.
        let mut bearer = record.plan.ca_sha256.clone();
        bearer.replace_range(0..1, if bearer.starts_with('0') { "1" } else { "0" });
        let mut one_time = record.plan.ca_sha256.clone();
        one_time.replace_range(63..64, if one_time.ends_with('0') { "1" } else { "0" });
        network.mode.store(mode, Ordering::SeqCst);
        let result = enroll(&env, &client, record, Some(Zeroizing::new(one_time.clone())),
            &bearer, RevocableAuthority::new(), network.http_capacity.clone(), native_dispatch, persistence(&network)).await;
        assert!(matches!(result, Err(FleetError::Protocol)));
        let admitted = network.durable.lock().unwrap();
        let requested = admitted.last().unwrap();
        assert_eq!(requested.phase, EnrollmentPhase::Requested);
        assert!(requested.controller_id.is_none());
        assert!(requested.client_cert_der.is_none());
        let durable_text = serde_json::to_string(&*admitted).unwrap();
        assert!(!durable_text.contains(&bearer));
        assert!(!durable_text.contains(&one_time));
    }
}

#[tokio::test]
async fn revocation_after_requested_denies_final_http_enqueue_and_allows_a_distinct_request() {
    let (env, client, network, record, _dir) = setup().await;
    let authority = RevocableAuthority::new();
    let (revocation, saved) = (authority.clone(), network.durable.clone());
    let persist = move |record: EnrollmentRecord| -> BoxFuture<'static, Result<(), FleetError>> {
        let requested = record.phase == EnrollmentPhase::Requested;
        saved.lock().unwrap().push(record);
        if requested { revocation.revoke(); }
        Box::pin(async { Ok(()) })
    };
    let result = enroll(&env, &client, record.clone(), Some(Zeroizing::new("dummy-once".into())),
        "dummy-api", authority.clone(), network.http_capacity.clone(), native_dispatch, persist).await;
    assert!(matches!(result, Err(FleetError::Revoked)));
    assert_eq!(authority.admissions.load(Ordering::SeqCst), 0);
    assert!(network.requests.lock().unwrap().is_empty());
    assert_eq!(network.http_capacity.available_permits(), 1);
    let following = EnrollmentRecord::prepare(&env, &client, record.plan.clone(), 2).await.unwrap();
    assert_ne!(following.request_id, record.request_id);
    let active = enroll(&env, &client, following, Some(Zeroizing::new("different-once".into())),
        "different-api", RevocableAuthority::new(), network.http_capacity.clone(), native_dispatch, persistence(&network)).await.unwrap();
    assert_eq!(active.phase, EnrollmentPhase::Active);
    assert_eq!(network.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn inflight_http_keeps_capacity_after_waiter_revocation_and_cannot_admit_active() {
    let (env, client, network, record, _dir) = setup().await;
    network.mode.store(6, Ordering::SeqCst);
    let (next_client, next_plan) = (client.clone(), record.plan.clone());
    let authority = RevocableAuthority::new();
    let task_authority = authority.clone();
    let task_env = env.clone();
    let task_network = network.clone();
    let hold_dropped = Arc::new(AtomicUsize::new(0));
    let hold = ResourceHold(hold_dropped.clone());
    let pending = env.spawn("test-enrollment-http-cancellation", async move {
        enroll(&task_env, &client, record, Some(Zeroizing::new("dummy-once".into())),
            "dummy-api", task_authority, task_network.http_capacity.clone(),
            move |prepared| Box::pin(prepared.dispatch_with_hold(hold)),
            persistence(&task_network)).await
    });
    env.timeout(std::time::Duration::from_secs(2), network.http_waiting.notified()).await.unwrap();
    assert_eq!(network.http_capacity.available_permits(), 0);
    authority.revoke();
    let result = env.timeout(std::time::Duration::from_secs(2), pending).await.unwrap().unwrap();
    assert!(matches!(result, Err(FleetError::Revoked)));
    assert_eq!(network.requests.lock().unwrap().len(), 1);
    assert_eq!(network.http_capacity.available_permits(), 0);
    assert_eq!(hold_dropped.load(Ordering::SeqCst), 0);
    let next_authority = RevocableAuthority::new();
    let next = EnrollmentRecord::prepare(&env, &next_client, next_plan, 2).await.unwrap();
    let requested = Arc::new(tokio::sync::Notify::new());
    let (task_env, task_network, task_authority, signal) =
        (env.clone(), network.clone(), next_authority.clone(), requested.clone());
    let following = env.spawn("test-enrollment-capacity-cancellation", async move {
        let saved = task_network.durable.clone();
        enroll(&task_env, &next_client, next, Some(Zeroizing::new("next-once".into())),
            "next-api", task_authority, task_network.http_capacity.clone(), native_dispatch, move |record| {
                let requested = record.phase == EnrollmentPhase::Requested;
                saved.lock().unwrap().push(record);
                if requested { signal.notify_one(); }
                Box::pin(async { Ok(()) })
            }).await
    });
    env.timeout(std::time::Duration::from_secs(2), requested.notified()).await.unwrap();
    assert_eq!(next_authority.admissions.load(Ordering::SeqCst), 0);
    next_authority.revoke();
    let result = env.timeout(std::time::Duration::from_secs(2), following).await.unwrap().unwrap();
    assert!(matches!(result, Err(FleetError::Revoked)));
    assert_eq!(network.requests.lock().unwrap().len(), 1);
    network.http_release.notify_one();
    let permit = env.timeout(std::time::Duration::from_secs(2), network.http_capacity.clone().acquire_owned()).await.unwrap().unwrap();
    drop(permit);
    assert_eq!(network.http_completed.load(Ordering::SeqCst), 1);
    assert_eq!(hold_dropped.load(Ordering::SeqCst), 1);
    let mut active = network.durable.lock().unwrap().last().unwrap().clone();
    active.phase = EnrollmentPhase::Active;
    let saved = network.durable.clone();
    assert!(authority.admit(&mut || { saved.lock().unwrap().push(active.clone()); Ok(()) }).is_err());
    assert_eq!(network.durable.lock().unwrap().last().unwrap().phase, EnrollmentPhase::Requested);
}

#[tokio::test]
async fn active_admission_cancellation_does_not_drop_its_durable_callback() {
    let (env, client, network, record, _dir) = setup().await;
    let authority = RevocableAuthority::new();
    let admitted = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let durable = Arc::new(AtomicBool::new(false));
    let saved = network.durable.clone();
    let (callback_admitted, callback_release, callback_durable) = (admitted.clone(), release.clone(), durable.clone());
    let (callback_env, callback_authority) = (env.clone(), authority.clone());
    let persist = move |record: EnrollmentRecord| -> BoxFuture<'static, Result<(), FleetError>> {
        if record.phase != EnrollmentPhase::Active {
            saved.lock().unwrap().push(record);
            return Box::pin(async { Ok(()) });
        }
        let (admitted, release, durable, saved) = (
            callback_admitted.clone(), callback_release.clone(), callback_durable.clone(), saved.clone(),
        );
        let mut job = Some(async move {
            admitted.notify_one();
            release.notified().await;
            durable.store(true, Ordering::SeqCst);
            saved.lock().unwrap().push(record);
        });
        let mut accepted = None;
        let result = callback_authority.admit(&mut || {
            accepted = Some(callback_env.spawn("test-active-durable", job.take().unwrap()));
            Ok(())
        });
        callback_authority.revoke();
        Box::pin(async move {
            result.map_err(|_| FleetError::Revoked)?;
            accepted.unwrap().await.ok_or(FleetError::Persistence)
        })
    };
    let task_env = env.clone();
    let pending = env.spawn("test-enrollment-active-durability", async move {
        enroll(&task_env, &client, record, Some(Zeroizing::new("dummy-once".into())),
            "dummy-api", authority, network.http_capacity.clone(), native_dispatch, persist).await
    });
    env.timeout(std::time::Duration::from_secs(2), admitted.notified()).await.unwrap();
    assert!(!durable.load(Ordering::SeqCst));
    release.notify_one();
    let active = env.timeout(std::time::Duration::from_secs(2), pending).await.unwrap().unwrap().unwrap();
    assert_eq!(active.phase, EnrollmentPhase::Active);
    assert!(durable.load(Ordering::SeqCst));
}

#[tokio::test]
async fn bootstrap_creates_private_parent_and_reloads_the_same_owned_key() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let (env, client, network, record, directory) = setup().await;
    let key_path = directory.path().join("identity/client.key");
    let parent = std::fs::metadata(key_path.parent().unwrap()).unwrap();
    let key = std::fs::metadata(&key_path).unwrap();
    assert_eq!(parent.permissions().mode() & 0o777, 0o700);
    assert_eq!(key.permissions().mode() & 0o777, 0o600);
    assert_eq!(key.nlink(), 1);
    assert_eq!(key.uid(), parent.uid());
    let persisted = Zeroizing::new(env.fs.read_secure(key_path.clone(), 262_144).await.unwrap());
    let loaded = kronik_core::identity::LeafKeys::from_pem(std::str::from_utf8(&persisted).unwrap()).unwrap();
    assert!(loaded.csr_der().unwrap() == record.csr_der);
    let restored = load_controller(&env, &ControllerConfig {
        url: record.plan.controller_url.clone(),
        ca_file: directory.path().join("ca.pem"),
        client_key_file: key_path.clone(),
    }).await.unwrap();
    let renewed = EnrollmentRecord::prepare(&env, &restored, record.plan.clone(), 2).await.unwrap();
    assert_eq!(renewed.client_key_sha256, record.client_key_sha256);
    assert!(renewed.csr_der == record.csr_der);
    assert_ne!(renewed.request_id, record.request_id);
    let after = Zeroizing::new(env.fs.read_secure(key_path, 262_144).await.unwrap());
    assert!(persisted.as_slice() == after.as_slice());
    assert!(network.requests.lock().unwrap().is_empty());
    assert!(network.durable.lock().unwrap().is_empty());
    assert!(client.validate_plan(&record.plan).is_ok());
}

#[tokio::test]
async fn bootstrap_refuses_an_existing_insecure_parent_without_chmod_or_key_write() {
    use std::os::unix::fs::PermissionsExt as _;
    let (env, _client, network, record, directory) = setup().await;
    let insecure = directory.path().join("insecure");
    std::fs::create_dir(&insecure).unwrap();
    std::fs::set_permissions(&insecure, std::fs::Permissions::from_mode(0o755)).unwrap();
    let key_path = insecure.join("client.key");
    let client = load_controller(&env, &ControllerConfig {
        url: record.plan.controller_url.clone(),
        ca_file: directory.path().join("ca.pem"),
        client_key_file: key_path.clone(),
    }).await.unwrap();
    let result = EnrollmentRecord::prepare(&env, &client, record.plan, 2).await;
    assert!(matches!(result, Err(FleetError::Persistence)));
    assert!(!key_path.exists());
    assert_eq!(std::fs::metadata(insecure).unwrap().permissions().mode() & 0o777, 0o755);
    assert!(network.requests.lock().unwrap().is_empty());
}


fn activate_control_record(network: &Network, mut record: EnrollmentRecord) -> EnrollmentRecord {
    record.phase = EnrollmentPhase::Active;
    record.client_cert_der = Some(network.issue(&record.csr_der, &record.plan, &record.request_id, record.epoch));
    record
}

#[tokio::test]
async fn control_capacity_wait_cancels_without_admission_or_handshake() {
    let (env, client, network, record, _dir) = setup().await;
    let record = activate_control_record(&network, record);
    let epoch = active_authority(&record);
    let original = RevocableAuthority::new();
    let held = network.opening_capacity.clone().acquire_owned().await.unwrap();
    let called = Arc::new(AtomicUsize::new(0));
    let (task_env, task_network, task_original, factory_calls) =
        (env.clone(), network.clone(), original.clone(), called.clone());
    let opening_dispatch = native_control_dispatch(&env, _dir.path());
    let pending = env.spawn("test-control-capacity-wait", async move {
        run_control(&task_env, &client, &record, "dummy-api", epoch.guard(), task_original,
            task_network.opening_capacity.clone(), move |prepared| {
                factory_calls.fetch_add(1, Ordering::SeqCst);
                opening_dispatch(prepared)
            }, |_, _| panic!("capacity-cancelled control served")).await
    });
    env.timeout(std::time::Duration::from_secs(2), network.control_prepared.notified()).await.unwrap();
    original.revoke();
    let result = env.timeout(std::time::Duration::from_secs(2), pending).await.unwrap().unwrap();
    assert!(matches!(result, Err(FleetError::Revoked)));
    assert_eq!(called.load(Ordering::SeqCst), 0);
    assert_eq!(original.admissions.load(Ordering::SeqCst), 0);
    assert!(network.control_requests.lock().unwrap().is_empty());
    assert_eq!(network.opening_capacity.available_permits(), 0);
    drop(held);
    assert_eq!(network.opening_capacity.available_permits(), 1);
}

#[tokio::test]
async fn control_factory_released_after_revocation_never_hands_off_or_opens() {
    let (env, client, network, record, _dir) = setup().await;
    let record = activate_control_record(&network, record);
    let epoch = active_authority(&record);
    let original = RevocableAuthority::new();
    let captured = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let (signal, gate) = (captured.clone(), release.clone());
    let (task_env, task_network, task_original) = (env.clone(), network.clone(), original.clone());
    let opening_dispatch = native_control_dispatch(&env, _dir.path());
    let pending = env.spawn("test-control-before-handoff", async move {
        run_control(&task_env, &client, &record, "dummy-api", epoch.guard(), task_original,
            task_network.opening_capacity.clone(), move |prepared| Box::pin(async move {
                signal.notify_one();
                gate.notified().await;
                opening_dispatch(prepared).await
            }), |_, _| panic!("revoked prepared control served")).await
    });
    env.timeout(std::time::Duration::from_secs(2), captured.notified()).await.unwrap();
    original.revoke();
    release.notify_one();
    let result = env.timeout(std::time::Duration::from_secs(2), pending).await.unwrap().unwrap();
    assert!(matches!(result, Err(FleetError::Revoked)));
    let permit = env.timeout(std::time::Duration::from_secs(2), network.opening_capacity.clone().acquire_owned()).await.unwrap().unwrap();
    drop(permit);
    assert_eq!(original.admissions.load(Ordering::SeqCst), 0);
    assert!(network.control_requests.lock().unwrap().is_empty());
}

struct OutsideControlFenceHold {
    original: Arc<RevocableAuthority>,
    dropped: Arc<AtomicUsize>,
}
impl Drop for OutsideControlFenceHold {
    fn drop(&mut self) {
        assert!(self.original.revoked.try_lock().is_ok(), "resource drop cannot run under the publication fence");
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn control_original_final_fence_denies_ready_after_owned_before_io_wait() {
    let (mut env, client, network, record, _dir) = setup().await;
    let held = Arc::new(HeldControlSpawner {
        inner: env.spawner.clone(), queued: Mutex::new(None), ready: tokio::sync::Notify::new(),
    });
    env.spawner = held.clone();
    let record = activate_control_record(&network, record);
    let epoch = active_authority(&record);
    let original = RevocableAuthority::new();
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let dropped = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(AtomicUsize::new(0));
    let callback_started = started.clone();
    let hold = OutsideControlFenceHold { original: original.clone(), dropped: dropped.clone() };
    let (signal, gate) = (entered.clone(), release.clone());
    let (task_env, task_network, task_original) = (env.clone(), network.clone(), original.clone());
    let (intent_env, intent_directory) = (env.clone(), _dir.path().to_path_buf());
    let pending = env.spawn("test-control-owned-before-io", async move {
        run_control(&task_env, &client, &record, "dummy-api", epoch.guard(), task_original,
            task_network.opening_capacity.clone(), move |prepared| {
                let intent = native_control_intent(&intent_env, &intent_directory, &prepared);
                Box::pin(prepared.dispatch_with_admission(move || async move {
                    callback_started.fetch_add(1, Ordering::SeqCst);
                    signal.notify_one();
                    gate.notified().await;
                    intent.await?;
                    Ok(hold)
                }))
            }, |_, _| panic!("unadmitted ready control served")).await
    });
    env.timeout(std::time::Duration::from_secs(2), held.ready.notified()).await.unwrap();
    assert_eq!(started.load(Ordering::SeqCst), 0);
    assert_eq!(network.opening_capacity.available_permits(), 0);
    assert_eq!(original.admissions.load(Ordering::SeqCst), 0);
    assert!(network.control_requests.lock().unwrap().is_empty());
    let owned = held.queued.lock().unwrap().take().unwrap();
    held.inner.spawn("test-release-owned-control-opening", owned);
    env.timeout(std::time::Duration::from_secs(2), entered.notified()).await.unwrap();
    assert_eq!(started.load(Ordering::SeqCst), 1);
    assert_eq!(original.admissions.load(Ordering::SeqCst), 0);
    assert!(network.control_requests.lock().unwrap().is_empty());
    original.revoke();
    let result = env.timeout(std::time::Duration::from_secs(2), pending).await.unwrap().unwrap();
    assert!(matches!(result, Err(FleetError::Revoked)));
    assert_eq!(network.opening_capacity.available_permits(), 0);
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    release.notify_one();
    let permit = env.timeout(std::time::Duration::from_secs(2), network.opening_capacity.clone().acquire_owned()).await.unwrap().unwrap();
    drop(permit);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert_eq!(original.admissions.load(Ordering::SeqCst), 0);
    assert!(network.control_requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn admitted_control_opening_finishes_once_after_revoke_but_late_socket_is_closed() {
    let (env, client, network, record, _dir) = setup().await;
    let record = activate_control_record(&network, record);
    let revoked = record.revoke().unwrap();
    let epoch = active_authority(&record);
    let guard = epoch.guard();
    let original = RevocableAuthority::new();
    let served = Arc::new(AtomicUsize::new(0));
    let seen = served.clone();
    network.control_pending.store(true, Ordering::SeqCst);
    let (task_env, task_network, task_original) = (env.clone(), network.clone(), original.clone());
    let opening_dispatch = native_control_dispatch(&env, _dir.path());
    let pending = env.spawn("test-control-admitted-opening", async move {
        run_control(&task_env, &client, &record, "dummy-api", guard, task_original,
            task_network.opening_capacity.clone(), opening_dispatch, move |_, _| {
                seen.fetch_add(1, Ordering::SeqCst);
                Box::pin(async {})
            }).await
    });
    env.timeout(std::time::Duration::from_secs(2), network.control_waiting.notified()).await.unwrap();
    assert_eq!(original.admissions.load(Ordering::SeqCst), 1);
    assert_eq!(network.control_requests.lock().unwrap().len(), 1);
    original.revoke();
    epoch.publish(&revoked).unwrap();
    let result = env.timeout(std::time::Duration::from_secs(2), pending).await.unwrap().unwrap();
    assert!(matches!(result, Err(FleetError::Revoked)));
    assert_eq!(network.opening_capacity.available_permits(), 0);
    network.control_release.notify_one();
    let permit = env.timeout(std::time::Duration::from_secs(2), network.opening_capacity.clone().acquire_owned()).await.unwrap().unwrap();
    drop(permit);
    assert_eq!(network.control_finished.load(Ordering::SeqCst), 1);
    assert_eq!(network.control_requests.lock().unwrap().len(), 1);
    assert_eq!(network.socket.closed.load(Ordering::SeqCst), 1);
    assert_eq!(served.load(Ordering::SeqCst), 0);
    assert!(epoch.guard().check().is_err());
}

#[tokio::test]
async fn control_opening_resources_release_before_channel_lifetime_and_original_still_cancels() {
    let (env, client, network, record, _dir) = setup().await;
    let record = activate_control_record(&network, record);
    let epoch = active_authority(&record);
    let guard = epoch.guard();
    let original = RevocableAuthority::new();
    let dropped = Arc::new(AtomicUsize::new(0));
    let hold = ResourceHold(dropped.clone());
    let entered = Arc::new(tokio::sync::Notify::new());
    let signal = entered.clone();
    let expected_id = record.request_id.clone();
    let expected_epoch = record.epoch;
    let mut version = Sha256::new();
    for field in [b"kronik.fleet-control-tls/v1".as_slice(), record.plan.ca_sha256.as_bytes(),
        record.client_key_sha256.as_bytes(), record.client_cert_der.as_deref().unwrap()] {
        version.update((field.len() as u64).to_be_bytes());
        version.update(field);
    }
    let expected_version: [u8; 32] = version.finalize().into();
    network.socket.pending_recv.store(true, Ordering::SeqCst);
    let (task_env, task_network, task_original) = (env.clone(), network.clone(), original.clone());
    let (intent_env, intent_directory) = (env.clone(), _dir.path().to_path_buf());
    let pending = env.spawn("test-control-opening-resource-lifetime", async move {
        run_control(&task_env, &client, &record, "dummy-api", guard, task_original,
            task_network.opening_capacity.clone(), move |prepared| {
                assert_eq!(prepared.destination(), "wss://controller.test/v1/control");
                assert_eq!(prepared.epoch(), expected_epoch);
                assert_eq!(prepared.request_id(), expected_id);
                assert_eq!(prepared.key_version(), expected_version);
                let empty: [u8; 32] = Sha256::digest(b"").into();
                assert_eq!(prepared.body_hash(), empty);
                let intent = native_control_intent(&intent_env, &intent_directory, &prepared);
                Box::pin(prepared.dispatch_with_admission(move || async move {
                    intent.await?;
                    Ok(hold)
                }))
            }, move |mut stream, _| Box::pin(async move {
                signal.notify_one();
                let mut byte = [0; 1];
                assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
            })).await
    });
    env.timeout(std::time::Duration::from_secs(2), entered.notified()).await.unwrap();
    assert_eq!(network.opening_capacity.available_permits(), 1);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert_eq!(original.admissions.load(Ordering::SeqCst), 1);
    assert_eq!(network.control_requests.lock().unwrap().len(), 1);
    original.revoke();
    let result = env.timeout(std::time::Duration::from_secs(2), pending).await.unwrap().unwrap();
    assert!(matches!(result, Err(FleetError::Revoked)));
    assert!(epoch.guard().check().is_ok(), "ordinary principal revocation must cancel independently of fleet epoch");
    assert_eq!(network.socket.closed.load(Ordering::SeqCst), 1);
}


struct HeldControlSpawner {
    inner: Arc<dyn kronik_core::env::Spawner>,
    queued: Mutex<Option<BoxFuture<'static, ()>>>,
    ready: tokio::sync::Notify,
}
impl kronik_core::env::Spawner for HeldControlSpawner {
    fn spawn(&self, name: &'static str, job: BoxFuture<'static, ()>) {
        if name == "fleet-control-opening" {
            assert!(self.queued.lock().unwrap().replace(job).is_none());
            self.ready.notify_one();
        } else { self.inner.spawn(name, job); }
    }
    fn spawn_blocking(&self, name: &'static str, job: Box<dyn FnOnce() + Send + 'static>) {
        self.inner.spawn_blocking(name, job);
    }
}
