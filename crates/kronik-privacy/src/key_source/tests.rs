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

/// Root working in the tree of the nonroot service. The tests play "another
/// user's tree" by running as a user that is not the tree's owner (`euid`
/// +1), which needs no privilege: what changes is how the files are reached.
mod another_users_tree {
    use super::*;
    use std::os::unix::fs::{MetadataExt as _, symlink};

    struct Tree {
        _dir: tempfile::TempDir,
        data: std::path::PathBuf,
        victim: std::path::PathBuf,
        /// The caller who is not the tree's owner: root, in production.
        stranger: Caller,
        /// The tree's own owner.
        owner: Caller,
    }

    /// A caller with this number. The directories of a test sit under the
    /// test user's own temporary directory, so the rule for the way to the
    /// data directory is "any" unless a test says otherwise.
    fn caller(euid: u32) -> Caller {
        Caller {
            euid,
            ancestors: Ancestors::Any,
        }
    }

    fn tree() -> Tree {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        std::fs::create_dir_all(data.join("keys")).unwrap();
        let victim = dir.path().join("victim");
        std::fs::create_dir(&victim).unwrap();
        std::fs::write(victim.join("secret.conf"), b"root-only").unwrap();
        let owner = std::fs::metadata(&data).unwrap().uid();
        Tree {
            _dir: dir,
            data,
            victim,
            stranger: caller(owner.wrapping_add(1)),
            owner: caller(owner),
        }
    }

    fn ctime(path: &Path) -> (i64, i64) {
        let meta = std::fs::symlink_metadata(path).unwrap();
        (meta.ctime(), meta.ctime_nsec())
    }

    fn tick() {
        std::thread::sleep(Duration::from_millis(40));
    }

    #[test]
    fn an_envelope_is_written_by_name_given_to_the_directorys_owner_and_replaced() {
        let rt = runtime();
        let (env, _, _) = setup(&rt, false, false);
        let t = tree();
        let path = t.data.join("keys/master.wrapped");
        write_envelope_as(&env, &t.data, &path, b"one", false, t.stranger).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600);
        assert_eq!(meta.uid(), std::fs::metadata(&t.data).unwrap().uid());
        assert_eq!(
            read_envelope_as(&t.data, &path, t.stranger).unwrap(),
            b"one"
        );
        // Creation never replaces what is there; replacement does.
        assert!(write_envelope_as(&env, &t.data, &path, b"two", false, t.stranger).is_err());
        write_envelope_as(&env, &t.data, &path, b"two", true, t.stranger).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        assert!(exists_as(&t.data, &path, t.stranger).unwrap());
        // Nothing else is left in the directory.
        let names: Vec<_> = std::fs::read_dir(t.data.join("keys"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["master.wrapped"]);
    }

    #[test]
    fn a_link_planted_as_keys_is_not_followed_for_a_write_a_read_or_the_stores() {
        let rt = runtime();
        let (env, _, _) = setup(&rt, false, false);
        let t = tree();
        std::fs::remove_dir(t.data.join("keys")).unwrap();
        symlink(&t.victim, t.data.join("keys")).unwrap();
        let path = t.data.join("keys/master.wrapped");
        // A file of the victim's own that the stores would be taken from.
        std::fs::write(t.victim.join("secrets.db"), b"not the service's").unwrap();
        let before = (ctime(&t.victim), ctime(&t.victim.join("secret.conf")));
        tick();
        let error = write_envelope_as(&env, &t.data, &path, b"x", false, t.stranger).unwrap_err();
        assert!(error.to_string().contains("symbolic link"), "{error}");
        assert!(read_envelope_as(&t.data, &path, t.stranger).is_err());
        assert!(exists_as(&t.data, &path, t.stranger).is_err());
        // The stores of a planted keys are refused too, and nothing is staged
        // from the victim.
        let error = stage_stores_as(&t.data.join("keys"), t.stranger).unwrap_err();
        assert!(error.to_string().contains("symbolic link"), "{error}");
        assert_eq!(
            (ctime(&t.victim), ctime(&t.victim.join("secret.conf"))),
            before,
        );
        assert_eq!(std::fs::read_dir(&t.victim).unwrap().count(), 2);
        // In the process's own tree the path works as it always did.
        assert_eq!(
            read_envelope_as(&t.data, &t.data.join("keys/secrets.db"), t.owner).unwrap(),
            b"not the service's"
        );
    }

    #[test]
    fn stores_that_are_links_or_special_files_are_not_staged_and_missing_ones_are_skipped() {
        let t = tree();
        let keys = t.data.join("keys");
        // Nothing there: nothing staged, no error, as before.
        let stage = stage_stores_as(&keys, t.stranger).unwrap();
        assert_eq!(std::fs::read_dir(stage.path()).unwrap().count(), 0);
        let missing = t.data.join("absent/keys");
        assert_eq!(
            std::fs::read_dir(stage_stores_as(&missing, t.stranger).unwrap().path())
                .unwrap()
                .count(),
            0
        );
        // A real store is copied, a staging directory is private.
        std::fs::write(keys.join("secrets.db"), b"db").unwrap();
        let stage = stage_stores_as(&keys, t.stranger).unwrap();
        assert_eq!(
            std::fs::read(stage.path().join("secrets.db")).unwrap(),
            b"db"
        );
        assert_eq!(std::fs::metadata(stage.path()).unwrap().mode() & 0o077, 0);
        // A link in place of a store, a hard link and a FIFO are each refused.
        std::fs::remove_file(keys.join("secrets.db")).unwrap();
        symlink(t.victim.join("secret.conf"), keys.join("secrets.db")).unwrap();
        assert!(stage_stores_as(&keys, t.stranger).is_err());
        std::fs::remove_file(keys.join("secrets.db")).unwrap();
        std::fs::hard_link(t.victim.join("secret.conf"), keys.join("secrets.db")).unwrap();
        assert!(stage_stores_as(&keys, t.stranger).is_err());
        std::fs::remove_file(keys.join("secrets.db")).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            keys.join("secrets.db"),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        assert!(stage_stores_as(&keys, t.stranger).is_err());
    }

    #[test]
    fn the_old_key_file_is_removed_by_name_and_a_link_in_its_place_is_only_unlinked() {
        let t = tree();
        let old = t.data.join("keys/master.key");
        std::fs::write(&old, "ab".repeat(32)).unwrap();
        remove_key_file(&t.data, &old, t.stranger).unwrap();
        assert!(!old.exists());
        // A link planted for it: the link goes, the victim stays.
        symlink(t.victim.join("secret.conf"), &old).unwrap();
        remove_key_file(&t.data, &old, t.stranger).unwrap();
        assert!(old.symlink_metadata().is_err());
        assert_eq!(
            std::fs::read(t.victim.join("secret.conf")).unwrap(),
            b"root-only"
        );
        // A key file outside the tree is the operator's: removed by path.
        let outside = t.victim.join("elsewhere.key");
        std::fs::write(&outside, "cd".repeat(32)).unwrap();
        remove_key_file(&t.data, &outside, t.stranger).unwrap();
        assert!(!outside.exists());
    }

    /// A test that needs root: where it cannot run it skips with a message, or
    /// fails under `KRONIK_FOREIGN_TESTS=require`, which the foreign step of CI
    /// sets and runs as root, so that a skip cannot go unnoticed there.
    fn root_or_skip(what: &str) -> bool {
        if rustix::process::geteuid().is_root() {
            return true;
        }
        assert!(
            std::env::var("KRONIK_FOREIGN_TESTS").as_deref() != Ok("require"),
            "KRONIK_FOREIGN_TESTS=require, but {what} needs root"
        );
        eprintln!("skipped: {what} needs root");
        false
    }

    /// A configuration whose envelope is directly under the data directory, so
    /// that a swapped `keys` is met by the old key and not by the envelope.
    fn wrap_config(base: &Keys) -> Keys {
        Keys {
            wrapped_file: "master.wrapped".into(),
            ..base.clone()
        }
    }

    #[test]
    fn the_old_key_is_read_by_name_and_only_a_plain_file_is_a_key() {
        let t = tree();
        let old = t.data.join("keys/master.key");
        let key = "ef".repeat(32);
        std::fs::write(&old, &key).unwrap();
        assert!(read_old_key_as(&t.data, &old, t.stranger).is_ok());
        assert!(read_old_key_as(&t.data, &old, t.owner).is_ok());
        // Not there: the usual message, not an I/O error from the descriptor code.
        std::fs::remove_file(&old).unwrap();
        for who in [t.stranger, t.owner] {
            let error = read_old_key_as(&t.data, &old, who).err().unwrap();
            assert!(error.to_string().contains("no master key"), "{error}");
        }
        // A link, a hard link and a FIFO planted in its place are refused in
        // another user's tree, and the link is the only one the owner's own path read follows.
        symlink(t.victim.join("secret.conf"), &old).unwrap();
        let error = read_old_key_as(&t.data, &old, t.stranger).err().unwrap();
        assert!(error.to_string().contains("symbolic link"), "{error}");
        std::fs::remove_file(&old).unwrap();
        std::fs::write(t.victim.join("linked.key"), &key).unwrap();
        std::fs::hard_link(t.victim.join("linked.key"), &old).unwrap();
        let error = read_old_key_as(&t.data, &old, t.stranger).err().unwrap();
        assert!(error.to_string().contains("hard links"), "{error}");
        // Bad key text names the file and not its contents.
        std::fs::remove_file(&old).unwrap();
        std::fs::remove_file(t.victim.join("linked.key")).unwrap();
        std::fs::write(&old, "not a key at all").unwrap();
        let error = read_old_key_as(&t.data, &old, t.stranger)
            .err()
            .unwrap()
            .to_string();
        assert!(
            error.contains(old.to_str().unwrap()) && !error.contains("not a key at all"),
            "{error}"
        );
        // One outside the data directory is the operator's, read by path.
        let outside = t.victim.join("operator.key");
        std::fs::write(&outside, &key).unwrap();
        assert!(read_old_key_as(&t.data, &outside, t.stranger).is_ok());
    }

    /// With `keys` swapped for a link to a directory that holds a
    /// `master.key`, nothing is deleted, and nothing is read from it: a failure
    /// to reach the old key by name is a failure, not a reason to go on by path.
    #[test]
    fn a_swapped_keys_never_makes_root_delete_or_read_the_key_it_points_at() {
        let t = tree();
        let real = "ab".repeat(32);
        std::fs::write(t.victim.join("master.key"), &real).unwrap();
        std::fs::remove_dir(t.data.join("keys")).unwrap();
        symlink(&t.victim, t.data.join("keys")).unwrap();
        let old = t.data.join("keys/master.key");
        let before = (ctime(&t.victim), ctime(&t.victim.join("master.key")));
        tick();
        // The pieces: the key is not read, and it is not removed.
        let error = read_old_key_as(&t.data, &old, t.stranger).err().unwrap();
        assert!(error.to_string().contains("symbolic link"), "{error}");
        let error = remove_key_file(&t.data, &old, t.stranger).unwrap_err();
        assert!(error.to_string().contains("symbolic link"), "{error}");
        assert_eq!(
            std::fs::read_to_string(t.victim.join("master.key")).unwrap(),
            real
        );
        // The whole command, with `--remove-file`, an envelope that does not
        // need `keys` and a provider that answers: refused, nothing written or removed.
        let rt = runtime();
        let (env, _, cfg) = setup(&rt, false, false);
        let cfg = wrap_config(&cfg);
        let result = rt.block_on(wrap_existing_as(
            t.stranger,
            &env,
            &cfg,
            &t.data,
            &old,
            true,
            |_, _| "test".to_owned(),
            false,
        ));
        assert!(result.is_err(), "the wrap went on through a swapped keys");
        assert_eq!(
            std::fs::read_to_string(t.victim.join("master.key")).unwrap(),
            real
        );
        assert!(!t.data.join("master.wrapped").exists());
        assert_eq!(
            std::fs::read_dir(&t.victim).unwrap().count(),
            2,
            "the victim directory changed"
        );
        assert_eq!(
            (ctime(&t.victim), ctime(&t.victim.join("master.key"))),
            before,
            "the victim directory or its key was touched"
        );
        // Control: the same command in an untouched tree wraps and removes.
        let c = tree();
        let old = c.data.join("keys/master.key");
        let key_text = "cd".repeat(32);
        std::fs::write(&old, &key_text).unwrap();
        let wrapped = rt.block_on(wrap_existing_as(
            c.stranger,
            &env,
            &cfg,
            &c.data,
            &old,
            true,
            |_, _| "test".to_owned(),
            false,
        ));
        assert!(wrapped.is_ok(), "{wrapped:?}");
        assert!(c.data.join("master.wrapped").exists());
        assert!(!old.exists(), "the old key file is removed by name");
    }

    #[test]
    fn a_wrap_that_is_done_says_so_when_the_old_key_cannot_be_removed() {
        let why = std::io::Error::other("Operation not permitted");
        let text = removal_failed(Path::new("/srv/data/keys/master.key"), &why).to_string();
        for needle in [
            "is wrapped",
            "/srv/data/keys/master.key",
            "Operation not permitted",
            "remove the old file by hand",
            "a wrapped key exists",
        ] {
            assert!(text.contains(needle), "{needle}: {text}");
        }
    }

    #[test]
    fn a_path_is_outside_the_data_directory_by_its_spelling_and_a_dotdot_is_not_trusted() {
        let t = tree();
        std::fs::write(t.victim.join("op.key"), "ab".repeat(32)).unwrap();
        // Outside: by path, in every tree.
        assert!(matches!(
            reach(&t.data, &t.victim.join("op.key"), t.stranger).unwrap(),
            Reach::Path
        ));
        // Inside, in another user's tree: by name; in the owner's own: by path.
        assert!(matches!(
            reach(&t.data, &t.data.join("keys/x"), t.stranger).unwrap(),
            Reach::Name(..)
        ));
        assert!(matches!(
            reach(&t.data, &t.data.join("keys/x"), t.owner).unwrap(),
            Reach::Path
        ));
        // A spelling that does not start with the data directory but has a
        // `..` in it could still lead into it: refused in another user's tree,
        // where that matters, and by path in the owner's own.
        let tricky = t
            .data
            .parent()
            .unwrap()
            .join("other/../data/keys/master.key");
        let error = reach(&t.data, &tricky, t.stranger).err().unwrap();
        assert!(error.to_string().contains("`..`"), "{error}");
        assert!(matches!(
            reach(&t.data, &tricky, t.owner).unwrap(),
            Reach::Path
        ));
        // One that starts with it and goes up again is refused by the walk.
        let inside = t.data.join("../data/keys/master.key");
        assert!(reach(&t.data, &inside, t.stranger).is_err());
        // The data directory itself is not a file below it.
        assert!(reach(&t.data, &t.data, t.stranger).is_err());
    }

    /// The way to the data directory: for another user's tree it is opened
    /// again from `/`, with no link on the way and only directories that root
    /// and the caller can change.
    #[test]
    fn the_way_to_another_users_data_directory_must_be_one_that_only_root_and_the_caller_change() {
        let t = tree();
        let strict = Caller {
            euid: t.stranger.euid,
            ancestors: Ancestors::ControlledBy(t.stranger.euid),
        };
        // The test's own temporary directory belongs to the tree's owner, who
        // is neither root nor the caller here (as root, the test gives it away
        // first, because root's directories always count): refused.
        if rustix::process::geteuid().is_root() {
            std::os::unix::fs::chown(t.data.parent().unwrap(), Some(65_534), None).unwrap();
        }
        let error = reach(&t.data, &t.data.join("keys/x"), strict)
            .err()
            .unwrap();
        assert!(error.to_string().contains("not controlled"), "{error}");
        // The refusal says what to do instead.
        assert!(
            error
                .to_string()
                .contains("run the command as the user who owns it"),
            "{error}"
        );
        // A link in the path of the data directory is refused as well.
        let link = t.data.parent().unwrap().join("data-link");
        symlink(&t.data, &link).unwrap();
        let error = reach(&link, &link.join("keys/x"), caller(t.stranger.euid))
            .err()
            .unwrap();
        assert!(error.to_string().contains("symbolic link"), "{error}");
        // In the owner's own tree the path may be spelled any way.
        assert!(matches!(
            reach(&link, &link.join("keys/x"), t.owner).unwrap(),
            Reach::Path
        ));
    }

    /// The same again, as a real root over a tree that a real other user owns:
    /// the numbers are the kernel's, not a played caller's. Where the test does
    /// not run as root there is no way to give a tree to another user.
    #[test]
    fn a_swapped_keys_is_refused_for_the_real_root_over_a_tree_another_user_owns() {
        use std::os::unix::fs::{chown, lchown};
        if !root_or_skip("giving a tree to another user") {
            return;
        }
        let service = 65_534;
        let rt = runtime();
        let (env, _, cfg) = setup(&rt, false, false);
        let cfg = wrap_config(&cfg);
        let who = Caller::this_process();
        let wrap = |data: &Path, old: &Path| {
            rt.block_on(wrap_existing_as(
                who,
                &env,
                &cfg,
                data,
                old,
                true,
                |_, _| "test".to_owned(),
                false,
            ))
        };
        // The service's tree, with `keys` swapped for a link to a directory of
        // root's own that holds a master.key.
        let t = tree();
        let real = "ab".repeat(32);
        std::fs::write(t.victim.join("master.key"), &real).unwrap();
        chown(&t.data, Some(service), Some(service)).unwrap();
        std::fs::remove_dir(t.data.join("keys")).unwrap();
        symlink(&t.victim, t.data.join("keys")).unwrap();
        lchown(t.data.join("keys"), Some(service), Some(service)).unwrap();
        let old = t.data.join("keys/master.key");
        let before = (ctime(&t.victim), ctime(&t.victim.join("master.key")));
        tick();
        assert!(
            wrap(&t.data, &old).is_err(),
            "the wrap went on through a swapped keys"
        );
        // The pieces, each on its own: the key behind the link is neither read
        // nor removed, whatever else would have stopped the command later.
        let error = read_old_key_as(&t.data, &old, who).err().unwrap();
        assert!(error.to_string().contains("symbolic link"), "{error}");
        let error = remove_key_file(&t.data, &old, who).unwrap_err();
        assert!(error.to_string().contains("symbolic link"), "{error}");
        assert_eq!(
            std::fs::read_to_string(t.victim.join("master.key")).unwrap(),
            real
        );
        assert!(!t.data.join("master.wrapped").exists());
        assert_eq!(
            (ctime(&t.victim), ctime(&t.victim.join("master.key"))),
            before,
            "the victim directory or its key was touched"
        );
        // Control: the service's untouched tree is wrapped, the envelope is
        // given to the service user, and the old key is removed by name.
        let c = tree();
        chown(&c.data, Some(service), Some(service)).unwrap();
        chown(c.data.join("keys"), Some(service), Some(service)).unwrap();
        let old = c.data.join("keys/master.key");
        std::fs::write(&old, "cd".repeat(32)).unwrap();
        chown(&old, Some(service), Some(service)).unwrap();
        let wrapped = wrap(&c.data, &old);
        assert!(wrapped.is_ok(), "{wrapped:?}");
        let envelope = std::fs::metadata(c.data.join("master.wrapped")).unwrap();
        assert_eq!((envelope.uid(), envelope.gid()), (service, service));
        assert!(!old.exists(), "the old key file is removed by name");
    }
}
