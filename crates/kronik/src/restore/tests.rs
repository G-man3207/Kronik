//! The order of a restore that gives up root after its root phase, with the
//! drop replaced by a witness. The drop itself, and what the process is after
//! it, is tested with the real binary in `tests/restore_drop.rs`.

use std::cell::RefCell;
use std::path::{Path, PathBuf};

use super::*;

#[path = "../../tests/support/bucket.rs"]
mod bucket;
#[path = "../../tests/support/s3_stub.rs"]
mod s3_stub;

struct Fixture {
    _dir: tempfile::TempDir,
    bucket: PathBuf,
    data: PathBuf,
}

fn fixture() -> Fixture {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let bucket = dir.path().join("bucket");
    let data = dir.path().join("data");
    std::fs::create_dir(&bucket).unwrap();
    std::fs::create_dir_all(data.join("keys")).unwrap();
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
    let key = bucket::ship_into(&bucket);
    std::fs::write(data.join("keys/master.key"), key).unwrap();
    Fixture {
        _dir: dir,
        bucket,
        data,
    }
}

fn listing(root: &Path) -> Vec<String> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            out.push(
                entry
                    .path()
                    .strip_prefix(root)
                    .unwrap()
                    .display()
                    .to_string(),
            );
            if entry.file_type().unwrap().is_dir() {
                walk(root, &entry.path(), out);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

fn owner_of(path: &Path) -> (u32, u32) {
    use std::os::unix::fs::MetadataExt as _;
    let meta = std::fs::metadata(path).unwrap();
    (meta.uid(), meta.gid())
}

/// Every restore of these tests gives its runtime's threads a name of its own,
/// so that the count is not disturbed by the other tests of the process, which
/// start and join threads of their own.
fn unique_name() -> String {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    format!(
        "rt-test-{}",
        NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    )
}

/// How many threads of this process are called `name`.
fn threads_named(name: &str) -> u64 {
    let mut named = 0;
    for task in std::fs::read_dir("/proc/self/task").unwrap().flatten() {
        let comm = std::fs::read_to_string(task.path().join("comm")).unwrap_or_default();
        if comm.trim() == name {
            named += 1;
        }
    }
    named
}

/// The same once it has settled to none: a thread that has been joined is
/// still listed by the kernel for a moment.
fn threads_named_settled(name: &str) -> Result<u64, ApiError> {
    let mut seen = threads_named(name);
    for _ in 0..400 {
        if seen == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
        seen = threads_named(name);
    }
    Ok(seen)
}

/// What a run of `restore_dropping` did.
struct Run {
    result: Result<kronik_ship::RestoreReport, ApiError>,
    steps: Vec<Step>,
    /// What the data directory held at the moment of the drop, if it came to that.
    at_drop: Option<Vec<String>>,
}

/// Runs `restore_dropping` with a drop that is `drop_to` and no credentials.
fn run(
    job: &Job<'_>,
    data: &Path,
    expected: (u32, u32),
    drop_to: &dyn Fn() -> Result<(), ApiError>,
    name: &str,
) -> Run {
    run_with(
        job,
        data,
        expected,
        drop_to,
        &|_, _| Ok(RemoteCredentials::none()),
        name,
    )
}

type Credentials<'a> =
    &'a dyn Fn(&tokio::runtime::Runtime, &Job<'_>) -> Result<RemoteCredentials, ApiError>;

fn run_with(
    job: &Job<'_>,
    data: &Path,
    expected: (u32, u32),
    drop_to: &dyn Fn() -> Result<(), ApiError>,
    credentials: Credentials<'_>,
    name: &str,
) -> Run {
    let steps = RefCell::new(Vec::new());
    let at_drop = RefCell::new(None);
    let dropper = |_: u32, _: u32| {
        *at_drop.borrow_mut() = Some(listing(data));
        drop_to()
    };
    let mut witness = |step| steps.borrow_mut().push(step);
    let count = || threads_named_settled(name);
    let mut hooks = Hooks {
        drop_to: &dropper,
        seen: &mut witness,
        credentials,
        threads: &count,
        single: 0,
        thread_name: name,
    };
    let result = restore_dropping(job, expected, &mut hooks);
    Run {
        result,
        steps: steps.into_inner(),
        at_drop: at_drop.into_inner(),
    }
}

fn file_job<'a>(
    f: &'a Fixture,
    url: &'a str,
    keys: &'a kronik_privacy::key_source::Keys,
) -> Job<'a> {
    Job {
        from: url,
        endpoint: None,
        data: &f.data,
        branch: "main",
        force: false,
        mode: kronik_ship::KeystoreMode::Require,
        keys,
    }
}

#[test]
fn the_steps_happen_in_one_order_and_nothing_is_written_before_the_drop() {
    let f = fixture();
    let name = unique_name();
    let before = listing(&f.data);
    let url = format!("file://{}", f.bucket.display());
    let keys = Default::default();
    let ran = run(
        &file_job(&f, &url, &keys),
        &f.data,
        owner_of(&f.data),
        &|| Ok(()),
        &name,
    );
    let report = ran.result.unwrap();
    assert_eq!(report.keystore, "installed");
    assert_eq!(
        ran.steps,
        [
            Step::Locked,
            Step::CredentialsResolved,
            Step::RootPhase,
            Step::RuntimeJoined,
            Step::Dropped,
            Step::Reopened,
            Step::Installed,
        ]
    );
    assert_eq!(
        ran.at_drop.unwrap(),
        before,
        "something was written before root was given up"
    );
    assert!(!f.data.join(".restore").exists());
    assert!(f.data.join("branches/main/state.db").is_file());
}

#[test]
fn a_failure_of_the_root_phase_never_drops_and_writes_nothing() {
    let f = fixture();
    let name = unique_name();
    // The key is gone, and the bucket has a keystore backup that needs it.
    std::fs::remove_file(f.data.join("keys/master.key")).unwrap();
    let before = listing(&f.data);
    let url = format!("file://{}", f.bucket.display());
    let keys = Default::default();
    let ran = run(
        &file_job(&f, &url, &keys),
        &f.data,
        owner_of(&f.data),
        &|| Ok(()),
        &name,
    );
    let error = ran.result.unwrap_err();
    assert!(error.message.contains("master key"), "{error:?}");
    assert_eq!(ran.steps, [Step::Locked, Step::CredentialsResolved]);
    assert!(
        ran.at_drop.is_none(),
        "root was given up although the root phase failed"
    );
    assert_eq!(listing(&f.data), before);
}

#[test]
fn a_drop_that_fails_stops_the_restore_before_a_byte_is_downloaded() {
    let f = fixture();
    let name = unique_name();
    let before = listing(&f.data);
    let url = format!("file://{}", f.bucket.display());
    let keys = Default::default();
    let refuse = || {
        Err(ApiError::new(
            ErrorCode::Internal,
            "becoming a service user requires valid nonroot IDs and one thread",
        ))
    };
    let ran = run(
        &file_job(&f, &url, &keys),
        &f.data,
        owner_of(&f.data),
        &refuse,
        &name,
    );
    let error = ran.result.unwrap_err();
    assert!(error.message.contains("one thread"), "{error:?}");
    assert_eq!(
        ran.steps,
        [
            Step::Locked,
            Step::CredentialsResolved,
            Step::RootPhase,
            Step::RuntimeJoined
        ]
    );
    assert_eq!(listing(&f.data), before, "the owner's phase began");
}

#[test]
fn a_failure_after_the_drop_leaves_the_directory_as_it_was() {
    let f = fixture();
    let name = unique_name();
    // Nothing for the owner to restore from.
    std::fs::remove_dir_all(f.bucket.join("main/snapshots")).unwrap();
    let before = listing(&f.data);
    let url = format!("file://{}", f.bucket.display());
    let keys = Default::default();
    let ran = run(
        &file_job(&f, &url, &keys),
        &f.data,
        owner_of(&f.data),
        &|| Ok(()),
        &name,
    );
    let error = ran.result.unwrap_err();
    assert!(error.message.contains("no snapshot"), "{error:?}");
    assert!(ran.steps.contains(&Step::Dropped) && ran.steps.contains(&Step::Reopened));
    assert!(!ran.steps.contains(&Step::Installed));
    assert_eq!(
        listing(&f.data),
        before,
        "the failed restore left something"
    );
}

#[test]
fn a_directory_whose_owner_is_not_the_one_expected_is_refused_before_root_is_given_up() {
    let f = fixture();
    let name = unique_name();
    let (uid, gid) = owner_of(&f.data);
    let before = listing(&f.data);
    let url = format!("file://{}", f.bucket.display());
    let keys = Default::default();
    let ran = run(
        &file_job(&f, &url, &keys),
        &f.data,
        (uid.wrapping_add(1), gid),
        &|| Ok(()),
        &name,
    );
    let error = ran.result.unwrap_err();
    assert_eq!(error.code, ErrorCode::RootlessUnavailable, "{error:?}");
    assert!(error.message.contains("changed owner"), "{error:?}");
    assert!(ran.steps.is_empty(), "{:?}", ran.steps);
    assert!(ran.at_drop.is_none());
    assert_eq!(listing(&f.data), before);
}

#[test]
fn a_bucket_directory_the_owner_cannot_read_is_named_with_the_way_out() {
    let error = unreadable_bucket(
        "/srv/ship",
        (64999, 64999),
        &ShipError::Config("denied".into()),
    );
    assert_eq!(error.code, ErrorCode::BadRequest);
    for needle in [
        "/srv/ship",
        "cannot be read by user 64999",
        "the owner of the data directory",
    ] {
        assert!(error.message.contains(needle), "{needle}: {error:?}");
    }
    let hint = error.hint.unwrap();
    assert!(hint.contains("readable by that user"), "{hint}");
    assert!(hint.contains("s3://"), "{hint}");
}

/// Gives a directory to another user, which only root can do; elsewhere the
/// test says so and ends, or fails under `KRONIK_FOREIGN_TESTS=require`.
fn root_only() -> bool {
    if rustix::process::geteuid().is_root() {
        return true;
    }
    assert!(
        std::env::var("KRONIK_FOREIGN_TESTS").as_deref() != Ok("require"),
        "KRONIK_FOREIGN_TESTS=require, but this test needs root to give a directory to another user"
    );
    eprintln!("skipped: needs root");
    false
}

#[test]
fn the_owner_to_drop_to_is_read_from_the_locked_descriptor_and_not_from_the_path() {
    if !root_only() {
        return;
    }
    let base = tempfile::tempdir().unwrap();
    let data = base.path().join("data");
    std::fs::create_dir(&data).unwrap();
    std::os::unix::fs::chown(&data, Some(64_998), Some(64_998)).unwrap();
    let ownership = kronik_privacy::key_source::lock_data(&data).unwrap();
    // The path now names another directory, with another owner.
    std::fs::rename(&data, base.path().join("moved")).unwrap();
    std::fs::create_dir(&data).unwrap();
    std::os::unix::fs::chown(&data, Some(64_997), Some(64_997)).unwrap();
    assert_eq!(owner_of(&data), (64_997, 64_997));
    assert_eq!(locked_owner(&ownership).unwrap(), (64_998, 64_998));
}

/// A bucket served over HTTP, signed requests only, from the files of the
/// fixture; the client is the real one (`object_store` over `reqwest`).
fn s3(f: &Fixture) -> s3_stub::Stub {
    s3_stub::Stub::start(s3_stub::Settings {
        bucket: "proof".into(),
        root: f.bucket.clone(),
        region: "us-east-1".into(),
        access_key: "AKIAUNITTESTKEY1".into(),
        secret_key: "unit/test+secret=0123456789abcdefghijkl".into(),
        session_token: Some("unit-session-token".into()),
        endpoint_token: String::new(),
        anonymous: false,
    })
}

fn temporary_credentials(
    _: &tokio::runtime::Runtime,
    _: &Job<'_>,
) -> Result<RemoteCredentials, ApiError> {
    Ok(RemoteCredentials::new(
        "AKIAUNITTESTKEY1".into(),
        "unit/test+secret=0123456789abcdefghijkl".into(),
        Some("unit-session-token".into()),
    ))
}

fn s3_job<'a>(
    f: &'a Fixture,
    endpoint: &'a str,
    keys: &'a kronik_privacy::key_source::Keys,
) -> Job<'a> {
    Job {
        from: "s3://proof",
        endpoint: Some(endpoint),
        data: &f.data,
        branch: "main",
        force: false,
        mode: kronik_ship::KeystoreMode::Require,
        keys,
    }
}

#[test]
fn over_a_real_s3_client_the_runtime_leaves_no_thread_and_root_asks_only_for_the_keystore() {
    let f = fixture();
    let name = unique_name();
    let stub = s3(&f);
    let endpoint = stub.endpoint();
    let keys = Default::default();
    let job = s3_job(&f, &endpoint, &keys);
    let at_drop = RefCell::new(Vec::new());
    let ran = run_with(
        &job,
        &f.data,
        owner_of(&f.data),
        &|| {
            *at_drop.borrow_mut() = stub.seen();
            Ok(())
        },
        &temporary_credentials,
        &name,
    );
    let report = ran.result.unwrap();
    assert_eq!(report.keystore, "installed");
    assert!(ran.steps.contains(&Step::RuntimeJoined));
    // Before the drop, root asked for the listing of the keystore backups and
    // for the newest of them, and for nothing else: no manifest, no object
    // that names a path.
    let before = at_drop.into_inner();
    assert!(!before.is_empty());
    for seen in &before {
        let listing = seen.path.starts_with("/proof?") && seen.path.contains("prefix=keystore");
        let backup = seen.path.starts_with("/proof/keystore/") && seen.path.ends_with(".bin");
        assert!(listing || backup, "root asked for {}", seen.path);
        assert_eq!(seen.status, 200, "{seen:?}");
    }
    // After it, the owner fetched the snapshot, signing with the same
    // credentials.
    let after = stub.seen();
    assert!(after.len() > before.len());
    assert!(
        after
            .iter()
            .any(|s| s.path.contains("/snapshots/") && s.path.ends_with(".zst")),
        "{after:?}"
    );
    assert!(
        after.iter().all(|s| s.status == 200 || s.status == 404),
        "{after:?}"
    );
    assert!(f.data.join("branches/main/state.db").is_file());
}

#[test]
fn a_thread_left_behind_stops_the_restore_before_the_drop_and_before_any_download() {
    let f = fixture();
    let name = unique_name();
    let stub = s3(&f);
    let endpoint = stub.endpoint();
    let keys = Default::default();
    let job = s3_job(&f, &endpoint, &keys);
    let before = listing(&f.data);
    // A thread of the kind a runtime makes, that outlives it.
    let (release, parked) = std::sync::mpsc::channel::<()>();
    let lingering = std::thread::Builder::new()
        .name(name.clone())
        .spawn(move || {
            let _ = parked.recv();
        })
        .unwrap();
    let ran = run_with(
        &job,
        &f.data,
        owner_of(&f.data),
        &|| Ok(()),
        &temporary_credentials,
        &name,
    );
    let error = ran.result.unwrap_err();
    assert!(
        error.message.contains("still has 1 threads")
            && error.message.contains("nothing was written"),
        "{error:?}"
    );
    assert_eq!(
        ran.steps,
        [Step::Locked, Step::CredentialsResolved, Step::RootPhase],
        "the restore went on although a thread was left"
    );
    assert!(
        ran.at_drop.is_none(),
        "root was given up with a thread left"
    );
    let asked = stub.seen();
    assert!(
        asked.iter().all(|s| !s.path.contains("/snapshots/")),
        "something was downloaded: {asked:?}"
    );
    assert_eq!(listing(&f.data), before);
    let _ = release.send(());
    lingering.join().unwrap();
}

#[test]
fn credentials_that_run_out_before_the_downloads_end_the_restore_clean_with_the_reason() {
    let f = fixture();
    let name = unique_name();
    let stub = s3(&f);
    stub.expire_at_first_download();
    let endpoint = stub.endpoint();
    let keys = Default::default();
    let job = s3_job(&f, &endpoint, &keys);
    let before = listing(&f.data);
    let ran = run_with(
        &job,
        &f.data,
        owner_of(&f.data),
        &|| Ok(()),
        &temporary_credentials,
        &name,
    );
    let error = ran.result.unwrap_err();
    assert_eq!(error.code, ErrorCode::Unavailable, "{error:?}");
    for needle in [
        "ExpiredToken",
        "resolved before the restore dropped its privileges",
        "cannot be refreshed",
    ] {
        assert!(error.message.contains(needle), "{needle}: {error:?}");
    }
    let hint = error.hint.clone().unwrap();
    assert!(hint.contains("reads the credentials once"), "{hint}");
    assert!(hint.contains("as long as the restore takes"), "{hint}");
    assert!(ran.steps.contains(&Step::Reopened));
    assert!(!ran.steps.contains(&Step::Installed));
    assert_eq!(
        listing(&f.data),
        before,
        "the stage or something else was left in the directory"
    );
}
