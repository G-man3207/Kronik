use super::*;
use kronik_core::env::{
    BoxFuture, Clock, EntropySource, File, Fs, HttpResponse, Net, NetError, Process, ProcessRunner,
    ProcessSpec, Spawner,
};
use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

struct Step {
    method: &'static str,
    url: String,
    response: HttpResponse,
}
impl Step {
    fn json(method: &'static str, url: impl Into<String>, value: Value) -> Self {
        Self {
            method,
            url: url.into(),
            response: HttpResponse {
                status: 200,
                headers: vec![],
                body: Bytes::from(serde_json::to_vec(&value).unwrap()),
            },
        }
    }
    fn raw(method: &'static str, url: impl Into<String>, body: &'static str) -> Self {
        let mut step = Self::json(method, url, json!({}));
        step.response.body = Bytes::from_static(body.as_bytes());
        step
    }
}
#[derive(Clone, Default)]
struct Harness {
    steps: Arc<Mutex<VecDeque<Step>>>,
    files: BTreeMap<PathBuf, Vec<u8>>,
}
impl Harness {
    fn script(steps: Vec<Step>) -> Self {
        Self {
            steps: Arc::new(Mutex::new(steps.into())),
            ..Self::default()
        }
    }
    fn file(mut self, name: &str, value: impl Into<Vec<u8>>) -> Self {
        self.files.insert(name.into(), value.into());
        self
    }
    fn env(&self) -> Env {
        let h = Arc::new(self.clone());
        Env {
            clock: h.clone(),
            spawner: h.clone(),
            entropy: h.clone(),
            fs: h.clone(),
            net: h.clone(),
            procs: h,
        }
    }
    fn done(&self) {
        assert!(self.steps.lock().unwrap().is_empty());
    }
}
impl Net for Harness {
    fn http(&self, req: HttpRequest) -> BoxFuture<'static, Result<HttpResponse, NetError>> {
        let step = self
            .steps
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected provider request");
        assert_eq!(req.method, step.method);
        assert_eq!(req.url, step.url);
        Box::pin(async move { Ok(step.response) })
    }
}
impl Clock for Harness {
    fn wall_ms(&self) -> u64 {
        1_440_938_160_000
    }
    fn monotonic(&self) -> Duration {
        Duration::ZERO
    }
    fn sleep(&self, _: Duration) -> BoxFuture<'static, ()> {
        Box::pin(std::future::pending())
    }
}
impl EntropySource for Harness {
    fn fill(&self, b: &mut [u8]) {
        b.fill(7);
    }
}
impl Spawner for Harness {
    fn spawn(&self, _: &'static str, _: BoxFuture<'static, ()>) {
        panic!("provider must not spawn");
    }
    fn spawn_blocking(&self, _: &'static str, _: Box<dyn FnOnce() + Send + 'static>) {
        panic!("provider must not spawn");
    }
}
impl ProcessRunner for Harness {
    fn spawn(&self, _: ProcessSpec) -> BoxFuture<'static, io::Result<Arc<dyn Process>>> {
        panic!("provider must not spawn processes");
    }
}
struct MemoryFile(Vec<u8>);
impl File for MemoryFile {
    fn len(&self) -> BoxFuture<'static, io::Result<u64>> {
        let n = self.0.len() as u64;
        Box::pin(async move { Ok(n) })
    }
    fn read_at(&self, offset: u64, len: usize) -> BoxFuture<'static, io::Result<Vec<u8>>> {
        let v = self.0[offset as usize..offset as usize + len].to_vec();
        Box::pin(async move { Ok(v) })
    }
    fn write_at(&self, _: u64, _: Bytes) -> BoxFuture<'static, io::Result<()>> {
        panic!("provider must not write credentials");
    }
    fn set_len(&self, _: u64) -> BoxFuture<'static, io::Result<()>> {
        panic!("provider must not write credentials");
    }
    fn sync_data(&self) -> BoxFuture<'static, io::Result<()>> {
        panic!("provider must not write credentials");
    }
}
impl Fs for Harness {
    fn open(&self, p: PathBuf, mode: OpenMode) -> BoxFuture<'static, io::Result<Arc<dyn File>>> {
        assert_eq!(mode, OpenMode::Read);
        let data = self
            .files
            .get(&p)
            .cloned()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound));
        Box::pin(async move { data.map(|v| Arc::new(MemoryFile(v)) as Arc<dyn File>) })
    }
    fn create_dir_all(&self, _: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        panic!("unexpected write");
    }
    fn exists(&self, _: PathBuf) -> BoxFuture<'static, io::Result<bool>> {
        panic!("unexpected exists");
    }
    fn read_dir(&self, _: PathBuf) -> BoxFuture<'static, io::Result<Vec<String>>> {
        panic!("unexpected read_dir");
    }
    fn rename(&self, _: PathBuf, _: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        panic!("unexpected rename");
    }
    fn remove_file(&self, _: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        panic!("unexpected remove");
    }
    fn sync_dir(&self, _: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        panic!("unexpected sync");
    }
}
fn ready<T>(f: impl Future<Output = T>) -> T {
    let mut f = std::pin::pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("script unexpectedly waited"),
    }
}
fn bao(auth: &str) -> Keys {
    Keys {
        source: Source::Openbao,
        openbao: Some(config::OpenBao {
            address: "http://127.0.0.1:8200".into(),
            key: "kronik".into(),
            auth: auth.into(),
            ..config::OpenBao::default()
        }),
        ..Keys::default()
    }
}
#[test]
fn provider_errors_never_contain_bodies_and_bad_envelopes_never_connect() {
    let h = Harness::script(vec![Step {
        response: HttpResponse {
            status: 403,
            headers: vec![],
            body: Bytes::from_static(b"provider-secret-error"),
        },
        ..Step::json("GET", "https://example.com", json!({}))
    }]);
    let e = ready(request(
        &h.env(),
        "GET",
        "https://example.com".into(),
        vec![],
        vec![],
    ))
    .err()
    .unwrap();
    assert!(!e.contains("provider-secret-error"));
    h.done();
    let mut cfg = bao("token");
    cfg.openbao.as_mut().unwrap().token_file = Some("/token".into());
    let mut w = envelope(&cfg, "1".into(), "vault:v1:YWJj".into(), &h.env()).unwrap();
    for field in ["schema", "source", "key", "version", "aad"] {
        let old = w.clone();
        match field {
            "schema" => w.schema = "bad".into(),
            "source" => w.source = "aws".into(),
            "key" => w.key = "https://evil".into(),
            "version" => w.key_version = "../evil".into(),
            _ => w.aad = "other".into(),
        }
        assert!(ready(decrypt(&h.env(), &cfg, &w)).is_err());
        w = old;
    }
}

#[test]
fn forged_cloud_versions_cannot_choose_a_network_target() {
    let gcp_key = "projects/p/locations/global/keyRings/r/cryptoKeys/k";
    let cases = [
        (
            Keys {
                source: Source::Gcp,
                gcp: Some(config::Gcp {
                    key: gcp_key.into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            "https://evil/cryptoKeyVersions/3",
        ),
        (
            Keys {
                source: Source::Azure,
                azure: Some(config::Azure {
                    key: "https://v.vault.azure.net/keys/k".into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            "https://evil",
        ),
    ];
    for (cfg, version) in cases {
        let h = Harness::default();
        let w = envelope(&cfg, version.into(), "YWJj".into(), &h.env()).unwrap();
        assert!(ready(decrypt(&h.env(), &cfg, &w)).is_err());
        h.done();
    }
}

#[test]
fn aws_rejects_a_different_returned_key() {
    let key = "arn:aws:kms:us-east-1:123456789012:key/abcd";
    let cfg = Keys {
        source: Source::Aws,
        aws: Some(config::Aws {
            region: "us-east-1".into(),
            key_id: key.into(),
            auth: "imds".into(),
            endpoint: Some("http://127.0.0.1:5000".into()),
            imds_endpoint: Some("http://127.0.0.1:9001".into()),
            ..config::Aws::default()
        }),
        ..Keys::default()
    };
    let h = Harness::script(vec![
        Step::raw(
            "PUT",
            "http://127.0.0.1:9001/latest/api/token",
            "imds-token",
        ),
        Step::raw(
            "GET",
            "http://127.0.0.1:9001/latest/meta-data/iam/security-credentials/",
            "role",
        ),
        Step::json(
            "GET",
            "http://127.0.0.1:9001/latest/meta-data/iam/security-credentials/role",
            json!({"Code":"Success","AccessKeyId":"AKID","SecretAccessKey":"SECRET","Token":"SESSION"}),
        ),
        Step::json(
            "POST",
            "http://127.0.0.1:5000/",
            json!({"KeyId":"arn:aws:kms:us-east-1:123456789012:key/evil","Plaintext":STANDARD.encode([7;32])}),
        ),
    ]);
    let w = envelope(&cfg, key.into(), "YWJj".into(), &h.env()).unwrap();
    assert!(ready(decrypt(&h.env(), &cfg, &w)).is_err());
    h.done();
}

#[test]
fn seed_length_and_request_size_are_bounded() {
    let mut cfg = bao("token");
    cfg.openbao.as_mut().unwrap().token_file = Some("/token".into());
    let h = Harness::script(vec![Step::json(
        "POST",
        "http://127.0.0.1:8200/v1/transit/decrypt/kronik",
        json!({"data":{"plaintext":"YWJj"}}),
    )])
    .file("/token", b"token".to_vec());
    let w = envelope(&cfg, "1".into(), "vault:v1:YWJj".into(), &h.env()).unwrap();
    assert!(ready(decrypt(&h.env(), &cfg, &w)).is_err());
    h.done();
    assert!(
        ready(request(
            &h.env(),
            "POST",
            "http://127.0.0.1".into(),
            vec![],
            vec![0; CAP + 1]
        ))
        .is_err()
    );
    assert!(
        pem(
            b"-----BEGIN RSA PRIVATE KEY-----\nYWJj\n-----END RSA PRIVATE KEY-----",
            "PRIVATE KEY"
        )
        .is_err()
    );
}

#[test]
fn timeout_uses_env_clock_and_transport_errors_are_redacted() {
    struct Deadline;
    impl Clock for Deadline {
        fn wall_ms(&self) -> u64 {
            0
        }
        fn monotonic(&self) -> Duration {
            Duration::ZERO
        }
        fn sleep(&self, _: Duration) -> BoxFuture<'static, ()> {
            Box::pin(async {})
        }
    }
    struct Unavailable(bool);
    impl Net for Unavailable {
        fn http(&self, _: HttpRequest) -> BoxFuture<'static, Result<HttpResponse, NetError>> {
            if self.0 {
                Box::pin(std::future::pending())
            } else {
                Box::pin(async { Err(NetError::Io("secret transport diagnostics".into())) })
            }
        }
    }
    let mut env = Harness::default().env();
    env.clock = Arc::new(Deadline);
    env.net = Arc::new(Unavailable(true));
    assert!(
        ready(request(
            &env,
            "GET",
            "http://127.0.0.1".into(),
            vec![],
            vec![]
        ))
        .is_err()
    );
    env.net = Arc::new(Unavailable(false));
    let e = ready(request(
        &env,
        "GET",
        "http://127.0.0.1".into(),
        vec![],
        vec![],
    ))
    .err()
    .unwrap();
    assert!(!e.contains("secret transport diagnostics"));
}
