use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use kronik_core::env::{
    BoxFuture, Clock, File, Fs, HttpRequest, HttpResponse, Net, NetError, OpenMode,
};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::Poll;

struct TestClock {
    now: Arc<AtomicU64>,
    alarms: Arc<Mutex<BTreeMap<u64, usize>>>,
}
impl Clock for TestClock {
    fn wall_ms(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
    fn monotonic(&self) -> Duration {
        Duration::from_millis(self.wall_ms())
    }
    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        let now = self.now.clone();
        let target = now.load(Ordering::SeqCst) + duration.as_millis() as u64;
        *self.alarms.lock().unwrap().entry(target).or_default() += 1;
        let alarm = Alarm {
            target,
            alarms: self.alarms.clone(),
        };
        Box::pin(async move {
            tokio::task::yield_now().await;
            std::future::poll_fn(|cx| {
                let earliest = *alarm.alarms.lock().unwrap().keys().next().unwrap();
                now.fetch_max(earliest, Ordering::SeqCst);
                if now.load(Ordering::SeqCst) >= target {
                    Poll::Ready(())
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            })
            .await;
        })
    }
}

// Cancel dropped deadlines, as the simulator does; a nested request timer
// must not jump ahead of a still-live startup deadline.
struct Alarm {
    target: u64,
    alarms: Arc<Mutex<BTreeMap<u64, usize>>>,
}
impl Drop for Alarm {
    fn drop(&mut self) {
        let mut alarms = self.alarms.lock().unwrap();
        let count = alarms.get_mut(&self.target).unwrap();
        *count -= 1;
        if *count == 0 {
            alarms.remove(&self.target);
        }
    }
}
struct ReadFile(Vec<u8>);
impl File for ReadFile {
    fn len(&self) -> BoxFuture<'static, std::io::Result<u64>> {
        let n = self.0.len() as u64;
        Box::pin(async move { Ok(n) })
    }
    fn read_at(&self, offset: u64, len: usize) -> BoxFuture<'static, std::io::Result<Vec<u8>>> {
        let bytes = self.0[offset as usize..self.0.len().min(offset as usize + len)].to_vec();
        Box::pin(async move { Ok(bytes) })
    }
    fn write_at(&self, _: u64, _: Bytes) -> BoxFuture<'static, std::io::Result<()>> {
        Box::pin(async { Err(std::io::ErrorKind::PermissionDenied.into()) })
    }
    fn set_len(&self, _: u64) -> BoxFuture<'static, std::io::Result<()>> {
        Box::pin(async { Err(std::io::ErrorKind::PermissionDenied.into()) })
    }
    fn sync_data(&self) -> BoxFuture<'static, std::io::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}
struct ReadFs(Vec<u8>);
impl Fs for ReadFs {
    fn create_dir_all(&self, _: PathBuf) -> BoxFuture<'static, std::io::Result<()>> {
        Box::pin(async { Ok(()) })
    }
    fn open(&self, _: PathBuf, _: OpenMode) -> BoxFuture<'static, std::io::Result<Arc<dyn File>>> {
        let file: Arc<dyn File> = Arc::new(ReadFile(self.0.clone()));
        Box::pin(async move { Ok(file) })
    }
    fn exists(&self, _: PathBuf) -> BoxFuture<'static, std::io::Result<bool>> {
        Box::pin(async { Ok(true) })
    }
    fn read_dir(&self, _: PathBuf) -> BoxFuture<'static, std::io::Result<Vec<String>>> {
        Box::pin(async { Ok(vec![]) })
    }
    fn rename(&self, _: PathBuf, _: PathBuf) -> BoxFuture<'static, std::io::Result<()>> {
        Box::pin(async { Err(std::io::ErrorKind::PermissionDenied.into()) })
    }
    fn remove_file(&self, _: PathBuf) -> BoxFuture<'static, std::io::Result<()>> {
        Box::pin(async { Err(std::io::ErrorKind::PermissionDenied.into()) })
    }
    fn sync_dir(&self, _: PathBuf) -> BoxFuture<'static, std::io::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}
struct Transit {
    calls: AtomicUsize,
    seed: std::sync::Mutex<Vec<u8>>,
    clock: Arc<AtomicU64>,
    wrong: bool,
    hang_decrypt: bool,
}
impl Net for Transit {
    fn http_authorized(
        &self,
        _: HttpRequest,
        _: kronik_core::authority::AuthLease,
    ) -> BoxFuture<'static, Result<HttpResponse, NetError>> {
        panic!("fixed-cause B1 master fixture must not receive an ordinary secret operation")
    }
    fn http(&self, r: HttpRequest) -> BoxFuture<'static, Result<HttpResponse, NetError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let body: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        let response = if r.url.contains("/encrypt/") {
            *self.seed.lock().unwrap() = STANDARD
                .decode(body["plaintext"].as_str().unwrap())
                .unwrap();
            if self.hang_decrypt {
                self.clock.store(9, Ordering::SeqCst);
            }
            serde_json::json!({"data":{"ciphertext":"vault:v1:YWJj"}})
        } else {
            if self.hang_decrypt {
                return Box::pin(std::future::pending());
            }
            let seed = if self.wrong {
                vec![255; 32]
            } else {
                self.seed.lock().unwrap().clone()
            };
            serde_json::json!({"data":{"plaintext":STANDARD.encode(seed)}})
        };
        Box::pin(async move {
            Ok(HttpResponse {
                status: 200,
                headers: vec![],
                body: serde_json::to_vec(&response).unwrap().into(),
            })
        })
    }
}
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}
fn setup(runtime: &tokio::runtime::Runtime, wrong: bool, hang: bool) -> (Env, Arc<Transit>, Keys) {
    let now = Arc::new(AtomicU64::new(0));
    let net = Arc::new(Transit {
        calls: AtomicUsize::new(0),
        seed: Default::default(),
        clock: now.clone(),
        wrong,
        hang_decrypt: hang,
    });
    let mut env = Env::real(runtime.handle().clone());
    env.clock = Arc::new(TestClock {
        now,
        alarms: Default::default(),
    });
    env.fs = Arc::new(ReadFs(b"test-token".to_vec()));
    env.net = net.clone();
    let config = Keys {
        source: Source::Openbao,
        start_timeout: "10ms".into(),
        openbao: Some(config::OpenBao {
            address: "http://127.0.0.1:1".into(),
            key: "kronik".into(),
            token_file: Some("/token".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    (env, net, config)
}

#[test]
fn wrapped_key_v1_fixture_preserves_metadata_and_rejects_other_sources() {
    // Ciphertext is opaque here: this is format compatibility, not provider crypto.
    let bytes = include_bytes!("../../tests/fixtures/wrapped-key-v1.json");
    let mut config = Keys {
        source: Source::Openbao,
        openbao: Some(config::OpenBao {
            address: "http://127.0.0.1:8200".into(),
            key: "kronik".into(),
            token_file: Some("/token".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let wrapped = Wrapped::parse(bytes, &config).unwrap();
    assert_eq!(wrapped.schema, "kronik.wrapped-key/v1");
    assert_eq!(wrapped.key_version, "1");
    assert_eq!(wrapped.aad, "kronik master v1");
    assert_eq!(wrapped.created_wall_ms, 1793354046571);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&wrapped.bytes().unwrap()).unwrap(),
        serde_json::from_slice::<serde_json::Value>(bytes).unwrap()
    );
    assert!(matches!(
        Wrapped::parse(bytes, &Keys::default()),
        Err(KeySourceError::InvalidEnvelope)
    ));
    config.openbao.as_mut().unwrap().key = "another".into();
    assert!(matches!(
        Wrapped::parse(bytes, &config),
        Err(KeySourceError::InvalidEnvelope)
    ));
    let mut future: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    future["schema"] = "kronik.wrapped-key/v2".into();
    config.openbao.as_mut().unwrap().key = "kronik".into();
    assert!(matches!(
        Wrapped::parse(&serde_json::to_vec(&future).unwrap(), &config),
        Err(KeySourceError::InvalidEnvelope)
    ));
}
#[test]
fn fresh_key_is_verified_before_persistence() {
    let rt = runtime();
    let dir = tempfile::tempdir().unwrap();
    let (env, _, cfg) = setup(&rt, true, false);
    let result = rt.block_on(KeySource::load(env, cfg, dir.path(), true));
    assert!(matches!(result, Err(KeySourceError::InvalidEnvelope)));
    assert!(!dir.path().join("keys/master.wrapped").exists());
    assert!(!dir.path().join("keys/secrets.db").exists());
}
#[test]
fn startup_verification_shares_encrypts_total_deadline() {
    let rt = runtime();
    let dir = tempfile::tempdir().unwrap();
    let (env, net, cfg) = setup(&rt, false, true);
    let clock = net.clock.clone();
    let result = rt.block_on(KeySource::load(env, cfg, dir.path(), true));
    assert!(matches!(result, Err(KeySourceError::Unavailable)));
    assert_eq!(clock.load(Ordering::SeqCst), 10);
    assert!(!dir.path().join("keys/master.wrapped").exists());
}
#[test]
fn malformed_envelope_is_refused_without_a_provider_request() {
    let rt = runtime();
    let dir = tempfile::tempdir().unwrap();
    let (env, net, cfg) = setup(&rt, false, false);
    let mut wrapped = Wrapped {
        schema: SCHEMA.into(),
        source: "openbao".into(),
        key: cfg.key_ref().unwrap(),
        key_version: "../other".into(),
        ciphertext: "vault:v1:YWJj".into(),
        aad: PURPOSE.into(),
        created_wall_ms: 0,
    };
    std::fs::create_dir(dir.path().join("keys")).unwrap();
    std::fs::write(
        dir.path().join("keys/master.wrapped"),
        wrapped.bytes().unwrap(),
    )
    .unwrap();
    assert!(matches!(
        rt.block_on(KeySource::load(env.clone(), cfg.clone(), dir.path(), false)),
        Err(KeySourceError::InvalidEnvelope)
    ));
    wrapped.key_version = "1".into();
    wrapped.key = "different/keys/kronik".into();
    assert!(Wrapped::parse(&wrapped.bytes().unwrap(), &cfg).is_err());
    assert_eq!(net.calls.load(Ordering::SeqCst), 0);
}
#[test]
fn existing_or_unreadable_store_never_becomes_fresh() {
    let rt = runtime();
    let dir = tempfile::tempdir().unwrap();
    let (env, net, cfg) = setup(&rt, false, false);
    std::fs::create_dir(dir.path().join("keys")).unwrap();
    std::fs::write(
        dir.path().join("keys/secrets.db"),
        b"existing encrypted store",
    )
    .unwrap();
    assert!(matches!(
        rt.block_on(KeySource::load(env, cfg, dir.path(), true)),
        Err(KeySourceError::Key(PrivacyError::KeyMissing(_)))
    ));
    assert_eq!(net.calls.load(Ordering::SeqCst), 0);
    // A non-directory path is a metadata I/O error, not evidence of absent stores.
    assert!(encrypted_stores(&dir.path().join("keys/secrets.db/subdir")).is_err());
}
#[test]
fn directory_ownership_does_not_need_parent_write_permission_or_a_socket() {
    let dir = tempfile::tempdir().unwrap();
    let first = lock_data(dir.path()).unwrap();
    let error = lock_data(dir.path()).unwrap_err();
    assert!(matches!(error, KeySourceError::DataInUse));
    let error = error.api_error();
    assert_eq!(error.code, kronik_core::error::ErrorCode::Unavailable);
    assert!(error.hint.is_some_and(|hint| !hint.is_empty()));
    drop(first);
    assert!(lock_data(dir.path()).is_ok());
}
#[test]
fn offline_validation_preserves_crashed_wal_and_absent_shm() {
    let dir = tempfile::tempdir().unwrap();
    let keys = dir.path().join("keys");
    std::fs::create_dir(&keys).unwrap();
    let master = MasterKey::from_bytes([7; 32]).unwrap();
    let store = crate::SecretStore::open(
        rusqlite::Connection::open(keys.join("secrets.db")).unwrap(),
        &master,
    )
    .unwrap();
    store
        .set_at("signing", 1, b"secret-value", [9; 24], 1, "t", "r")
        .unwrap();
    let db = std::fs::read(keys.join("secrets.db")).unwrap();
    let wal = std::fs::read(keys.join("secrets.db-wal")).unwrap();
    std::fs::remove_file(keys.join("secrets.db-shm")).unwrap();
    validate_staged_stores(&master, &keys).unwrap();
    assert_eq!(std::fs::read(keys.join("secrets.db")).unwrap(), db);
    assert_eq!(std::fs::read(keys.join("secrets.db-wal")).unwrap(), wal);
    assert!(!keys.join("secrets.db-shm").exists());
    drop(store);
}
#[test]
fn wrong_key_and_failed_rewrap_preserve_the_existing_envelope() {
    let rt = runtime();
    let dir = tempfile::tempdir().unwrap();
    let (env, net, cfg) = setup(&rt, false, false);
    let source = rt
        .block_on(KeySource::load(env, cfg, dir.path(), true))
        .unwrap();
    let path = source.config.envelope_path(dir.path()).unwrap();
    let old = std::fs::read(&path).unwrap();
    *net.seed.lock().unwrap() = vec![199; 32];
    let result = rt.block_on(source.rewrap(false));
    assert!(matches!(
        result,
        Err(KeySourceError::Key(PrivacyError::KeyMismatch(_)))
    ));
    assert_eq!(std::fs::read(path).unwrap(), old);
}
