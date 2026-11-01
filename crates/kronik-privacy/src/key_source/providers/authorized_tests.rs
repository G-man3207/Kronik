use super::*;
use crate::secret_backend::{BackendError, SecretBackend};
use kronik_core::authority::Authority;
use kronik_core::env::{BoxFuture, File, Fs};
use kronik_core::error::{ApiError, ErrorCode};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::{Notify, oneshot};

struct Gate {
    publication: Mutex<()>,
    revoked: Arc<AtomicBool>,
    changed: Arc<Notify>,
    refuse_at_send: bool,
    connected: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
}
impl Gate {
    fn new(refuse_at_send: bool, connected: Option<std::sync::mpsc::Receiver<()>>) -> Arc<Self> {
        Arc::new(Self {
            publication: Mutex::new(()),
            revoked: Arc::new(AtomicBool::new(false)),
            changed: Arc::new(Notify::new()),
            refuse_at_send,
            connected: Mutex::new(connected),
        })
    }
    fn revoke(&self) {
        let _publication = self.publication.lock().unwrap();
        self.revoked.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }
}
impl Authority for Gate {
    fn check(&self) -> Result<(), ApiError> {
        if self.revoked.load(Ordering::Acquire) {
            Err(ApiError::new(
                ErrorCode::Unauthenticated,
                "test provider authority ended",
            ))
        } else {
            Ok(())
        }
    }
    fn cancelled(&self) -> BoxFuture<'static, ()> {
        let revoked = self.revoked.clone();
        let changed = self.changed.clone();
        Box::pin(async move {
            loop {
                let notified = changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if revoked.load(Ordering::Acquire) {
                    return;
                }
                notified.await;
            }
        })
    }
    fn admit(&self, effect: &mut dyn FnMut() -> Result<(), ApiError>) -> Result<(), ApiError> {
        // The observer wait is deliberately outside the publication fence.
        if let Some(connected) = self.connected.lock().unwrap().take() {
            connected
                .recv_timeout(Duration::from_secs(3))
                .expect("admission must follow real connection readiness");
        }
        let _publication = self.publication.lock().unwrap();
        if self.refuse_at_send {
            self.revoked.store(true, Ordering::Release);
            self.changed.notify_waiters();
        }
        self.check()?;
        effect()
    }
}
pub(crate) fn test_authority() -> AuthLease {
    Gate::new(false, None)
}

const AWS_VERSION: &str = "11111111-1111-1111-1111-111111111111";
const AZURE_VERSION: &str = "0123456789abcdef0123456789abcdef";
fn backend(
    env: Env,
    provider: &str,
    base: &str,
    ca: Option<PathBuf>,
    token: PathBuf,
) -> (Arc<dyn SecretBackend>, String, &'static str) {
    match provider {
        "aws" => (
            Arc::new(
                aws::Secrets::new(
                    env,
                    config::Aws {
                        region: "us-east-1".into(),
                        auth: "imds".into(),
                        endpoint: Some(base.into()),
                        imds_endpoint: Some(base.into()),
                        ca_file: ca,
                        ..Default::default()
                    },
                )
                .unwrap(),
            ),
            "team/service".into(),
            AWS_VERSION,
        ),
        "azure" => (
            Arc::new(
                azure::Secrets::new(
                    env,
                    config::Azure {
                        metadata_endpoint: Some(format!("{base}/token")),
                        ca_file: ca,
                        ..Default::default()
                    },
                    vec![base.into()],
                )
                .unwrap(),
            ),
            format!("{base}/secrets/password"),
            AZURE_VERSION,
        ),
        "gcp" => (
            Arc::new(
                gcp::Secrets::new(
                    env,
                    config::Gcp {
                        endpoint: Some(base.into()),
                        metadata_endpoint: Some(format!("{base}/token")),
                        ca_file: ca,
                        ..Default::default()
                    },
                )
                .unwrap(),
            ),
            "projects/123/secrets/password".into(),
            "1",
        ),
        "openbao" => (
            Arc::new(
                openbao::Secrets::new(
                    env,
                    config::OpenBao {
                        address: base.into(),
                        token_file: Some(token),
                        ca_file: ca,
                        ..Default::default()
                    },
                )
                .unwrap(),
            ),
            "secret/password#value".into(),
            "1",
        ),
        _ => unreachable!(),
    }
}
fn operation<'a>(
    backend: &'a dyn SecretBackend,
    path: &'a str,
    version: &'a str,
    kind: usize,
    original: AuthLease,
) -> BoxFuture<'a, Result<(), BackendError>> {
    Box::pin(async move {
        match kind {
            0 => backend.current(path, original).await.map(|_| ()),
            1 => backend.version(path, version, original).await.map(|_| ()),
            2 => backend.versions(path, None, original).await.map(|_| ()),
            _ => unreachable!(),
        }
    })
}
fn auth_path(provider: &str) -> &'static str {
    match provider {
        "aws" => "/latest/api/token",
        "openbao" => "/v1/auth/token/lookup-self",
        _ => "/token",
    }
}
fn request_path(stream: &mut TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut headers = Vec::new();
    let mut byte = [0; 1];
    while !headers.ends_with(b"\r\n\r\n") {
        assert!(headers.len() < CAP);
        assert_eq!(stream.read(&mut byte).unwrap(), 1);
        headers.push(byte[0]);
    }
    let headers = std::str::from_utf8(&headers).unwrap();
    let path = headers
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .split('?')
        .next()
        .unwrap()
        .to_owned();
    let length = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map_or(0, |(_, value)| value.trim().parse::<usize>().unwrap());
    assert!(length <= CAP);
    let mut remaining = length;
    let mut buffer = [0; 1024];
    while remaining > 0 {
        let count = remaining.min(buffer.len());
        stream.read_exact(&mut buffer[..count]).unwrap();
        remaining -= count;
    }
    path
}
fn accept(listener: &TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        match listener.accept() {
            Ok((stream, _)) => return stream,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(1))
            }
            Err(error) => panic!("provider connection did not arrive: {error}"),
        }
    }
}
fn response(stream: &mut TcpStream, body: &[u8]) {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .unwrap();
    stream.write_all(body).unwrap();
}
fn recovery_requests(provider: &str, base: &str, kind: usize) -> Vec<(String, Vec<u8>)> {
    let encode = |value: Value| serde_json::to_vec(&value).unwrap();
    let (mut requests, secret_path, value) = match provider {
        "aws" => {
            let arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:team/service-Ab12Cd";
            let value = if kind == 2 {
                json!({"ARN":arn,"Name":"team/service","Versions":[{"VersionId":AWS_VERSION}]})
            } else {
                json!({"ARN":arn,"Name":"team/service","VersionId":AWS_VERSION,"SecretString":"value"})
            };
            (
                vec![
                    ("/latest/api/token".into(), b"imds-token".to_vec()),
                    (
                        "/latest/meta-data/iam/security-credentials/".into(),
                        b"role".to_vec(),
                    ),
                    (
                        "/latest/meta-data/iam/security-credentials/role".into(),
                        encode(
                            json!({"Code":"Success","AccessKeyId":"AKID","SecretAccessKey":"SECRET","Token":"SESSION"}),
                        ),
                    ),
                ],
                "/".to_owned(),
                value,
            )
        }
        "azure" => {
            let id = format!("{base}/secrets/password/{AZURE_VERSION}");
            let value = if kind == 2 {
                json!({"value":[{"id":id,"attributes":{"enabled":true}}]})
            } else {
                json!({"id":id,"attributes":{"enabled":true},"value":"value"})
            };
            let path = match kind {
                1 => format!("/secrets/password/{AZURE_VERSION}"),
                2 => "/secrets/password/versions".into(),
                _ => "/secrets/password".into(),
            };
            (
                vec![(
                    "/token".into(),
                    encode(json!({"access_token":"token","expires_in":3600})),
                )],
                path,
                value,
            )
        }
        "gcp" => {
            let name = "projects/123/secrets/password/versions/1";
            let value = if kind == 2 {
                json!({"versions":[{"name":name,"state":"ENABLED"}]})
            } else {
                json!({"name":name,"payload":{"data":"dmFsdWU="}})
            };
            let path = match kind {
                0 => "/v1/projects/123/secrets/password/versions/latest:access",
                1 => "/v1/projects/123/secrets/password/versions/1:access",
                _ => "/v1/projects/123/secrets/password/versions",
            };
            (
                vec![(
                    "/token".into(),
                    encode(json!({"access_token":"token","expires_in":3600})),
                )],
                path.into(),
                value,
            )
        }
        "openbao" => {
            let value = if kind == 2 {
                json!({"data":{"current_version":1,"oldest_version":1,"versions":{"1":{"destroyed":false,"deletion_time":""}}}})
            } else {
                json!({"data":{"data":{"value":"value"},"metadata":{"version":1,"destroyed":false,"deletion_time":""}}})
            };
            let path = if kind == 2 {
                "/v1/secret/metadata/password"
            } else {
                "/v1/secret/data/password"
            };
            (
                vec![(
                    auth_path(provider).into(),
                    encode(json!({"data":{"ttl":3600,"renewable":false}})),
                )],
                path.into(),
                value,
            )
        }
        _ => unreachable!(),
    };
    requests.push((secret_path, encode(value)));
    requests
}

#[tokio::test(flavor = "current_thread")]
async fn every_provider_operation_cancels_during_token_body_without_secret_admission() {
    for provider in ["aws", "azure", "gcp", "openbao"] {
        for kind in 0..3 {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let recovery = recovery_requests(provider, &base, kind);
            let (body_sent, body_observed) = oneshot::channel();
            let (release, held) = std::sync::mpsc::channel();
            let (quiet, quiet_observed) = oneshot::channel();
            let server = std::thread::spawn(move || {
                let mut stream = accept(&listener);
                assert_eq!(request_path(&mut stream), auth_path(provider));
                // Root's Bytes response future cannot finish until this real body reaches EOF.
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\nConnection: close\r\n\r\n{",
                    )
                    .unwrap();
                body_sent.send(()).unwrap();
                held.recv_timeout(Duration::from_secs(3)).unwrap();
                listener.set_nonblocking(true).unwrap();
                assert!(
                    matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
                );
                listener.set_nonblocking(false).unwrap();
                drop(stream);
                quiet.send(()).unwrap();
                for (path, body) in recovery {
                    let mut stream = accept(&listener);
                    assert_eq!(
                        request_path(&mut stream),
                        path,
                        "aborted authentication must not populate the client's token/session cache"
                    );
                    response(&mut stream, &body);
                }
            });
            let directory = tempfile::tempdir().unwrap();
            let token = directory.path().join("token");
            std::fs::write(&token, "provider-token").unwrap();
            let env = Env::real(tokio::runtime::Handle::current());
            let observer = env.clone();
            let gate = Gate::new(false, None);
            let (client, path, version) = backend(env, provider, &base, None, token);
            let mut pending = operation(client.as_ref(), &path, version, kind, gate.clone());
            tokio::select! {
                biased;
                result = &mut pending => panic!("{provider}/{kind} finished before its held body: {result:?}"),
                result = body_observed => result.unwrap(),
                () = tokio::time::sleep(Duration::from_secs(3)) => panic!("provider did not emit its partial body"),
            }
            gate.revoke();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(3), pending)
                    .await
                    .unwrap(),
                Err(BackendError::Unauthorized)
            );
            release.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(3), quiet_observed)
                .await
                .unwrap()
                .unwrap();
            // A later, separately authorized operation on the SAME client must authenticate again.
            assert_eq!(
                tokio::time::timeout(
                    Duration::from_secs(3),
                    operation(client.as_ref(), &path, version, kind, test_authority())
                )
                .await
                .unwrap(),
                Ok(())
            );
            observer
                .blocking("provider-held-body-observer", move || {
                    server.join().unwrap()
                })
                .await
                .unwrap();
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn cold_provider_final_refusal_after_real_ready_sends_zero_http_bytes() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let (accepted, connected) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let mut stream = accept(&listener);
        accepted.send(()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut buffer = [0; 1024];
        match stream.read(&mut buffer) {
            Ok(count) => count,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                0
            }
            Err(error) => panic!("unexpected provider socket read: {error}"),
        }
    });
    let env = Env::real(tokio::runtime::Handle::current());
    let observer = env.clone();
    let gate = Gate::new(true, Some(connected));
    let (client, path, version) = backend(env, "gcp", &base, None, PathBuf::new());
    assert_eq!(
        tokio::time::timeout(
            Duration::from_secs(3),
            operation(client.as_ref(), &path, version, 0, gate)
        )
        .await
        .unwrap(),
        Err(BackendError::Unauthorized)
    );
    assert_eq!(
        observer
            .blocking("provider-final-refusal-observer", move || server
                .join()
                .unwrap())
            .await
            .unwrap(),
        0
    );
}

struct HeldFs {
    inner: Arc<dyn Fs>,
    entered: Arc<Notify>,
}
impl Fs for HeldFs {
    fn open(&self, path: PathBuf, mode: OpenMode) -> BoxFuture<'static, io::Result<Arc<dyn File>>> {
        if path == Path::new("/held-provider-ca") {
            self.entered.notify_one();
            Box::pin(std::future::pending())
        } else {
            self.inner.open(path, mode)
        }
    }
    fn create_dir_all(&self, path: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        self.inner.create_dir_all(path)
    }
    fn exists(&self, path: PathBuf) -> BoxFuture<'static, io::Result<bool>> {
        self.inner.exists(path)
    }
    fn read_dir(&self, path: PathBuf) -> BoxFuture<'static, io::Result<Vec<String>>> {
        self.inner.read_dir(path)
    }
    fn rename(&self, from: PathBuf, to: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        self.inner.rename(from, to)
    }
    fn remove_file(&self, path: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        self.inner.remove_file(path)
    }
    fn sync_dir(&self, path: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        self.inner.sync_dir(path)
    }
    fn available(&self, path: PathBuf) -> BoxFuture<'static, io::Result<u64>> {
        self.inner.available(path)
    }
}

#[tokio::test(flavor = "current_thread")]
async fn every_provider_operation_cancels_credential_wait_before_any_socket_admission() {
    for provider in ["aws", "azure", "gcp", "openbao"] {
        for kind in 0..3 {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let mut env = Env::real(tokio::runtime::Handle::current());
            let gate = Gate::new(false, None);
            let entered = Arc::new(Notify::new());
            env.fs = Arc::new(HeldFs {
                inner: env.fs.clone(),
                entered: entered.clone(),
            });
            let (client, path, version) = backend(
                env,
                provider,
                &base,
                Some("/held-provider-ca".into()),
                PathBuf::new(),
            );
            let mut pending = operation(client.as_ref(), &path, version, kind, gate.clone());
            tokio::select! {
                biased;
                result = &mut pending => panic!("{provider}/{kind} skipped its credential wait: {result:?}"),
                () = entered.notified() => (),
                () = tokio::time::sleep(Duration::from_secs(3)) => panic!("credential read was not entered"),
            }
            gate.revoke();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(3), pending)
                    .await
                    .unwrap(),
                Err(BackendError::Unauthorized)
            );
            listener.set_nonblocking(true).unwrap();
            assert!(
                matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
            );
        }
    }
}
