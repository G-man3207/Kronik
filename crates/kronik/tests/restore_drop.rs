//! `kronik restore` as root against the data directory of the nonroot service:
//! the root phase (the key, the remote's credentials, the keystore backup),
//! the drop, and the owner's phase, observed from outside, with the real
//! binary, a real drop of privileges and a bucket over HTTP that checks the
//! signature of every request.
//!
//! The binary runs in a mount namespace of its own in which `/etc` is a small
//! tree the test writes, with a `kronik` user (uid and gid 64999), so nothing
//! of the host's accounts changes and nothing of the host's `/etc` but two
//! public files (the loader's cache and the CA bundle) is copied. The tests need root and `unshare`; elsewhere they say so
//! and skip, or fail under `KRONIK_FOREIGN_TESTS=require`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

#[path = "support/bucket.rs"]
mod bucket;
#[path = "support/s3_stub.rs"]
mod s3_stub;

use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

/// The uid and the gid of the `kronik` user that the tests add to their `/etc`.
const OWNER: u32 = 64_999;

fn skip(why: &str) -> bool {
    assert!(
        std::env::var("KRONIK_FOREIGN_TESTS").as_deref() != Ok("require"),
        "KRONIK_FOREIGN_TESTS=require, but {why}"
    );
    eprintln!("skipped: {why}");
    true
}

fn can_run() -> Option<String> {
    if !rustix::process::geteuid().is_root() {
        return Some("a restore that drops root needs root".into());
    }
    let namespace = Command::new("unshare")
        .args(["--mount", "--propagation", "private", "sh", "-c"])
        .arg("mount --bind /etc /etc")
        .status();
    match namespace {
        Ok(status) if status.success() => None,
        _ => Some(
            "a private mount namespace with bind mounts (unshare --mount) is not available".into(),
        ),
    }
}

/// Everything a test needs, below one directory that anyone can enter (the
/// owner reads the bucket and writes the data directory after the drop).
struct World {
    dir: tempfile::TempDir,
    /// The `/etc` that the binary sees (`synthetic_etc`).
    etc: PathBuf,
    /// The shipped data: what a restore reads.
    bucket: PathBuf,
    /// The master key, where only root can read it.
    key: PathBuf,
    /// The token of the pod-identity endpoint, where only root can read it.
    token: PathBuf,
    /// The destination, owned by the played `kronik` user.
    data: PathBuf,
    /// The binary's `TMPDIR`: nothing may be left in it.
    tmp: PathBuf,
    /// A directory of root's with a file in it, outside the service's tree.
    outside: PathBuf,
}

fn chown(path: &Path, uid: u32, gid: u32) {
    std::os::unix::fs::chown(path, Some(uid), Some(gid)).unwrap();
}

fn mkdir(path: &Path, mode: u32) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// The CA bundles of the common distributions, relative to `/etc`: the TLS
/// client loads the system's roots when it starts, and finds them at one of
/// these.
const CA_BUNDLES: [&str; 4] = [
    "ssl/certs/ca-certificates.crt",
    "pki/tls/certs/ca-bundle.crt",
    "ssl/ca-bundle.pem",
    "ssl/cert.pem",
];

/// Makes the `/etc` that the binary sees in its mount namespace: the identity
/// files with the played `kronik` user and its ranges, `localhost`, a name
/// service that reads only those files, and two public files of the host's,
/// the dynamic loader's cache and the CA bundle. Root's and the played
/// user's alone (0750): the binary reads it before and after the drop, and
/// nobody else needs it.
fn synthetic_etc(etc: &Path) {
    mkdir(etc, 0o750);
    chown(etc, 0, OWNER);
    let write = |name: &str, bytes: &[u8]| {
        let path = etc.join(name);
        let parent = path.parent().unwrap();
        if !parent.exists() {
            mkdir(parent, 0o755);
        }
        std::fs::write(&path, bytes).unwrap();
        chown(&path, 0, 0);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    };
    write(
        "passwd",
        format!(
            "root:x:0:0:root:/root:/usr/sbin/nologin\n\
             kronik:x:{OWNER}:{OWNER}::/nonexistent:/usr/sbin/nologin\n"
        )
        .as_bytes(),
    );
    write(
        "group",
        format!("root:x:0:\nkronik:x:{OWNER}:\n").as_bytes(),
    );
    write("subuid", b"kronik:300000:65536\n");
    write("subgid", b"kronik:300000:65536\n");
    write("hosts", b"127.0.0.1 localhost\n::1 localhost\n");
    write(
        "nsswitch.conf",
        b"passwd: files\ngroup: files\nhosts: files\n",
    );
    for name in ["ld.so.cache"].into_iter().chain(CA_BUNDLES) {
        if let Ok(bytes) = std::fs::read(Path::new("/etc").join(name)) {
            write(name, &bytes);
        }
    }
    assert!(
        CA_BUNDLES.iter().any(|bundle| etc.join(bundle).is_file()),
        "no CA bundle found under /etc ({CA_BUNDLES:?})"
    );
}

impl World {
    /// With a bucket that a node shipped into, and its key.
    fn new() -> Option<World> {
        World::build(true)
    }

    /// Without a bucket.
    fn bare() -> Option<World> {
        World::build(false)
    }

    fn build(ship: bool) -> Option<World> {
        if let Some(why) = can_run() {
            skip(&why);
            return None;
        }
        let dir = tempfile::Builder::new()
            .prefix("kronik-restore-drop-")
            .tempdir_in("/tmp")
            .unwrap();
        mkdir(dir.path(), 0o755);
        let world = World {
            etc: dir.path().join("etc"),
            bucket: dir.path().join("bucket"),
            key: dir.path().join("keyroot/master.key"),
            token: dir.path().join("tokenroot/token"),
            data: dir.path().join("data"),
            tmp: dir.path().join("tmp"),
            outside: dir.path().join("outside"),
            dir,
        };
        // The /etc the binary sees, made from scratch: nothing of the host's
        // own (no shadow file, no host keys, no private TLS keys) is copied.
        synthetic_etc(&world.etc);
        mkdir(&world.tmp, 0o777);
        // The destination, as the installer leaves it.
        mkdir(&world.data, 0o700);
        chown(&world.data, OWNER, OWNER);
        mkdir(&world.data.join("keys"), 0o700);
        chown(&world.data.join("keys"), OWNER, OWNER);
        // A directory of root with a file in it.
        mkdir(&world.outside, 0o755);
        std::fs::write(world.outside.join("secret.conf"), b"root's own\n").unwrap();
        if ship {
            world.ship();
        }
        Some(world)
    }

    /// Ships a node's data (a snapshot, the log, a keystore backup) into the
    /// bucket and keeps its master key where only root can read it.
    fn ship(&self) {
        mkdir(&self.bucket, 0o755);
        let key = bucket::ship_into(&self.bucket);
        mkdir(self.key.parent().unwrap(), 0o700);
        std::fs::write(&self.key, key).unwrap();
        std::fs::set_permissions(&self.key, std::fs::Permissions::from_mode(0o600)).unwrap();
        // The bucket is for everyone to read; the writes are the shipper's.
        let _ = Command::new("chmod")
            .args(["-R", "a+rX", self.bucket.to_str().unwrap()])
            .status();
    }

    fn file_url(&self) -> String {
        format!("file://{}", self.bucket.display())
    }

    /// `kronik ARGS` in a mount namespace where `/etc` is the synthetic one
    /// with the played user, as root, with nothing of the host's environment
    /// but `env`.
    fn kronik(&self, args: &[&str], env: &[(&str, &str)]) -> Command {
        let mut command = Command::new("unshare");
        command
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("WORLD_ETC", &self.etc)
            .env("TMPDIR", &self.tmp)
            .env("KRONIK_LOG", "warn")
            .args(["--mount", "--propagation", "private", "sh", "-c"])
            .arg(r#"mount --bind "$WORLD_ETC" /etc && exec "$0" "$@""#)
            .arg(env!("CARGO_BIN_EXE_kronik"))
            .args(args)
            .stdin(Stdio::null());
        for (name, value) in env {
            command.env(name, value);
        }
        command
    }

    /// `kronik --json restore ARGS --data-dir <the destination>`.
    fn restore(&self, args: &[&str], env: &[(&str, &str)]) -> Command {
        let mut all = vec!["--json", "restore"];
        all.extend_from_slice(args);
        let data = self.data.display().to_string();
        all.extend_from_slice(&["--data-dir", &data]);
        self.kronik(&all, env)
    }

    fn with_key(&self) -> [String; 2] {
        ["--master-key-file".into(), self.key.display().to_string()]
    }

    /// What is in the data directory, by path and owner, without following a link.
    fn listing(&self) -> BTreeMap<String, (u32, u32, u32)> {
        fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, (u32, u32, u32)>) {
            for entry in std::fs::read_dir(dir).unwrap().flatten() {
                let meta = std::fs::symlink_metadata(entry.path()).unwrap();
                let name = entry
                    .path()
                    .strip_prefix(root)
                    .unwrap()
                    .display()
                    .to_string();
                out.insert(name, (meta.uid(), meta.gid(), meta.mode() & 0o7777));
                if meta.is_dir() {
                    walk(root, &entry.path(), out);
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(&self.data, &self.data, &mut out);
        out
    }

    /// The file outside the service's tree: bytes, identity and times.
    fn outside_state(&self) -> (Vec<u8>, u64, i64, i64) {
        let path = self.outside.join("secret.conf");
        let meta = std::fs::symlink_metadata(&path).unwrap();
        (
            std::fs::read(&path).unwrap(),
            meta.ino(),
            meta.mtime_nsec() + meta.mtime() * 1_000_000_000,
            meta.ctime_nsec() + meta.ctime() * 1_000_000_000,
        )
    }

    fn stub(&self, session_token: Option<&str>) -> s3_stub::Stub {
        mkdir(self.token.parent().unwrap(), 0o700);
        std::fs::write(&self.token, "the-pods-token").unwrap();
        std::fs::set_permissions(&self.token, std::fs::Permissions::from_mode(0o600)).unwrap();
        s3_stub::Stub::start(s3_stub::Settings {
            bucket: "proof".into(),
            root: self.bucket.clone(),
            region: "us-east-1".into(),
            access_key: "AKIAKRONIKSTUBKEY1".into(),
            secret_key: "stub/secret+key=1234567890abcdefghijklmnop".into(),
            session_token: session_token.map(str::to_owned),
            endpoint_token: "the-pods-token".into(),
            anonymous: false,
        })
    }

    /// A bucket that is read without signing, as a public one is.
    fn anonymous_stub(&self) -> s3_stub::Stub {
        s3_stub::Stub::start(s3_stub::Settings {
            bucket: "proof".into(),
            root: self.bucket.clone(),
            region: "us-east-1".into(),
            access_key: String::new(),
            secret_key: String::new(),
            session_token: None,
            endpoint_token: String::new(),
            anonymous: true,
        })
    }

    /// The environment of a pod: the credentials come from an endpoint, with a
    /// token that only root can read.
    fn pod_env(&self, stub: &s3_stub::Stub) -> Vec<(String, String)> {
        vec![
            (
                "AWS_CONTAINER_CREDENTIALS_FULL_URI".into(),
                format!("{}/credentials", stub.endpoint()),
            ),
            (
                "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE".into(),
                self.token.display().to_string(),
            ),
            ("AWS_REGION".into(), "us-east-1".into()),
        ]
    }
}

fn text(output: &Output) -> String {
    format!(
        "status {:?}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn json(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| panic!("{e}: {}", text(output)))
}

fn run(mut command: Command) -> Output {
    command.output().unwrap()
}

fn proc_status(pid: u32) -> BTreeMap<String, String> {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap()
        .lines()
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.to_owned(), v.trim().to_owned()))
        .collect()
}

/// Waits for a file to appear, and for the child to be gone if it never does.
fn wait_for(path: &Path, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !path.exists() {
        assert!(
            child.try_wait().unwrap().is_none(),
            "the restore ended before it reached the point that the test looks at"
        );
        assert!(Instant::now() < deadline, "the restore never got there");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_restore_as_root_into_the_service_users_directory_leaves_nothing_of_roots() {
    let Some(world) = World::new() else { return };
    let before = world.listing();
    assert!(before.values().all(|(u, g, _)| (*u, *g) == (OWNER, OWNER)));
    let output = run(world.restore(
        &[
            "--from",
            &world.file_url(),
            &world.with_key()[0],
            &world.with_key()[1],
        ],
        &[],
    ));
    assert!(output.status.success(), "{}", text(&output));
    let report = json(&output);
    assert_eq!(report["keystore"], "installed", "{report}");
    assert_eq!(report["data_dir"], world.data.display().to_string());
    let after = world.listing();
    assert!(after.contains_key("branches/main/state.db"), "{after:?}");
    let foreign: Vec<_> = after
        .iter()
        .filter(|(_, (u, g, _))| (*u, *g) != (OWNER, OWNER))
        .collect();
    assert!(
        foreign.is_empty(),
        "entries that do not belong to the service user: {foreign:?}"
    );
    assert!(
        !world.data.join(".restore").exists(),
        "the stage was left behind"
    );
    assert_eq!(
        std::fs::read_dir(&world.tmp).unwrap().count(),
        0,
        "something was staged in TMPDIR"
    );
}

#[test]
fn the_credentials_of_a_token_file_only_root_reads_are_read_once_before_the_drop() {
    let Some(world) = World::new() else { return };
    let stub = world.stub(Some("session-token-1"));
    let pod = world.pod_env(&stub);
    let env: Vec<(&str, &str)> = pod.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let key = world.with_key();
    let output = run(world.restore(
        &[
            "--from",
            "s3://proof",
            "--endpoint",
            &stub.endpoint(),
            &key[0],
            &key[1],
        ],
        &env,
    ));
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(json(&output)["keystore"], "installed");
    // The token was read, and the endpoint asked, once; every request to the
    // bucket was signed with what came back, before and after the drop.
    assert_eq!(stub.credential_requests(), 1);
    let seen = stub.seen();
    let bucket: Vec<_> = seen.iter().filter(|s| s.path != "/credentials").collect();
    assert!(bucket.len() > 10, "{seen:?}");
    assert!(
        bucket.iter().all(|s| s.status == 200 || s.status == 404),
        "{seen:?}"
    );
    assert!(
        bucket
            .iter()
            .all(|s| s.code != "SignatureDoesNotMatch" && s.code != "AccessDenied"),
        "{seen:?}"
    );
    assert!(
        seen.iter()
            .any(|s| s.path.contains("/snapshots/") && s.path.ends_with(".zst"))
    );
    let foreign: Vec<_> = world
        .listing()
        .into_iter()
        .filter(|(_, (u, g, _))| (*u, *g) != (OWNER, OWNER))
        .collect();
    assert!(foreign.is_empty(), "{foreign:?}");
}

#[test]
fn a_bucket_read_without_signing_asks_for_no_credentials() {
    let Some(world) = World::new() else { return };
    let stub = world.anonymous_stub();
    let endpoint = stub.endpoint();
    let key = world.with_key();
    let args = [
        "--from",
        "s3://proof",
        "--endpoint",
        &endpoint,
        &key[0],
        &key[1],
    ];
    // The metadata of an instance is looked for at the stub's address, so that
    // a request for it can be seen.
    let region = ("AWS_REGION", "us-east-1");
    let metadata = ("AWS_METADATA_ENDPOINT", endpoint.as_str());

    // The control: nothing says that the bucket is read without signing and
    // there are no credentials, so they are looked for where an instance keeps
    // them, and the restore fails.
    let output = run(world.restore(&args, &[region, metadata]));
    assert!(!output.status.success(), "{}", text(&output));
    assert!(
        stub.seen().iter().any(|s| s.path.starts_with("/latest/")),
        "the control did not look for the metadata of an instance, so it proves nothing: {}",
        text(&output)
    );

    // Not signing: no credentials are asked for anywhere, and the restore
    // goes through, snapshot included, after the drop.
    let before = stub.seen().len();
    let output = run(world.restore(&args, &[region, metadata, ("AWS_SKIP_SIGNATURE", "true")]));
    assert!(output.status.success(), "{}", text(&output));
    let seen = stub.seen();
    let later = &seen[before..];
    assert!(!later.is_empty());
    assert!(later.iter().all(|s| !s.signed), "{later:?}");
    assert!(
        later.iter().all(|s| !s.path.starts_with("/latest/")),
        "the metadata of an instance was asked for: {later:?}"
    );
    assert!(
        later
            .iter()
            .any(|s| s.path.contains("/snapshots/") && s.path.ends_with(".zst")),
        "{later:?}"
    );
    let foreign: Vec<_> = world
        .listing()
        .into_iter()
        .filter(|(_, (u, g, _))| (*u, *g) != (OWNER, OWNER))
        .collect();
    assert!(foreign.is_empty(), "{foreign:?}");
}

#[test]
fn credentials_that_ran_out_after_the_drop_end_the_restore_with_a_clear_message_and_nothing_is_left()
 {
    let Some(world) = World::new() else { return };
    let stub = world.stub(Some("session-token-2"));
    stub.expire_at_first_download();
    let pod = world.pod_env(&stub);
    let env: Vec<(&str, &str)> = pod.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let before = world.listing();
    let key = world.with_key();
    let output = run(world.restore(
        &[
            "--from",
            "s3://proof",
            "--endpoint",
            &stub.endpoint(),
            &key[0],
            &key[1],
        ],
        &env,
    ));
    let shown = text(&output);
    assert!(!output.status.success(), "{shown}");
    for needle in [
        "ExpiredToken",
        "resolved before the restore dropped its privileges",
        "cannot be refreshed",
        "credentials that last as long as the restore takes",
    ] {
        assert!(shown.contains(needle), "{needle}: {shown}");
    }
    assert_eq!(
        world.listing(),
        before,
        "the failed restore changed the data directory"
    );
    assert_eq!(std::fs::read_dir(&world.tmp).unwrap().count(), 0);
}

#[test]
fn after_the_drop_the_restore_is_the_service_user_with_nothing_to_go_back_to_and_nobody_can_read_it()
 {
    let Some(world) = World::new() else { return };
    let stub = world.stub(Some("session-token-3"));
    let marker = world.dir.path().join("held");
    let release = world.dir.path().join("release");
    stub.hold_first_download(&marker, &release);
    let pod = world.pod_env(&stub);
    let env: Vec<(&str, &str)> = pod.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let key = world.with_key();
    let mut child = world
        .restore(
            &[
                "--from",
                "s3://proof",
                "--endpoint",
                &stub.endpoint(),
                &key[0],
                &key[1],
            ],
            &env,
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for(&marker, &mut child);
    // The first download of the snapshot is what a restore makes first once it
    // is the owner of the data directory: it is held, and this looks at it.
    let pid = child.id();
    let status = proc_status(pid);
    let ids = |key: &str| -> Vec<u32> {
        status[key]
            .split_whitespace()
            .map(|n| n.parse().unwrap())
            .collect()
    };
    assert_eq!(ids("Uid"), [OWNER; 4], "{status:?}");
    assert_eq!(ids("Gid"), [OWNER; 4], "{status:?}");
    assert_eq!(status["Groups"], "", "no supplementary group: {status:?}");
    for set in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
        assert_eq!(status[set], "0000000000000000", "{set}: {status:?}");
    }
    assert_eq!(status["NoNewPrivs"], "1", "{status:?}");
    assert!(status["Threads"].parse::<u32>().unwrap() >= 1, "{status:?}");
    // Not dumpable: the files of /proc/<pid> that expose its memory belong to
    // root, so the same user cannot read them, and a process of the same user
    // that is dumpable is the control that it could.
    let as_owner = |args: &[&str]| -> std::process::ExitStatus {
        Command::new("cat")
            .args(args)
            .uid(OWNER)
            .gid(OWNER)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
    };
    let mut control = Command::new("sleep")
        .arg("60")
        .uid(OWNER)
        .gid(OWNER)
        .spawn()
        .unwrap();
    assert!(
        as_owner(&[&format!("/proc/{}/environ", control.id())]).success(),
        "the control: a process of the same user that is dumpable can be read"
    );
    assert!(
        !as_owner(&[&format!("/proc/{pid}/environ")]).success(),
        "the restore can be read by its own user"
    );
    assert!(
        !as_owner(&[&format!("/proc/{pid}/mem")]).success(),
        "the memory of the restore can be opened by its own user"
    );
    let _ = control.kill();
    let _ = control.wait();
    std::fs::write(&release, b"go").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{}", text(&output));
}

#[test]
fn a_link_where_keys_is_is_not_followed_by_root() {
    let Some(world) = World::new() else { return };
    // The key is looked for where the service's own data keeps it by default,
    // and `keys` is a link to a directory outside the tree that holds a
    // `master.key` of its own.
    std::fs::remove_dir_all(world.data.join("keys")).unwrap();
    std::fs::write(
        world.outside.join("master.key"),
        b"not a key of the service\n",
    )
    .unwrap();
    symlink(&world.outside, world.data.join("keys")).unwrap();
    std::os::unix::fs::lchown(world.data.join("keys"), Some(OWNER), Some(OWNER)).unwrap();
    let before = world.outside_state();
    let watch = Watch::on(&world.outside.join("master.key"));
    let output = run(world.restore(&["--from", &world.file_url()], &[]));
    let opened = watch.events();
    let shown = text(&output);
    assert!(!output.status.success(), "{shown}");
    assert!(shown.contains("link"), "{shown}");
    assert!(
        !shown.contains("not a key of the service"),
        "the content of the file outside the tree was shown: {shown}"
    );
    assert_eq!(opened, 0, "the file was opened through the link: {shown}");
    assert_eq!(world.outside_state(), before);
    assert_eq!(
        std::fs::read(world.outside.join("master.key")).unwrap(),
        b"not a key of the service\n"
    );
}

#[test]
fn a_link_where_the_stage_goes_is_replaced_and_not_followed() {
    let Some(world) = World::new() else { return };
    symlink(&world.outside, world.data.join(".restore")).unwrap();
    std::os::unix::fs::lchown(world.data.join(".restore"), Some(OWNER), Some(OWNER)).unwrap();
    let before = world.outside_state();
    let watch = Watch::on(&world.outside.join("secret.conf"));
    let key = world.with_key();
    let output = run(world.restore(&["--from", &world.file_url(), &key[0], &key[1]], &[]));
    // Asked first: reading the file to compare it is an event of its own.
    let opened = watch.events();
    // The link is removed as the leftover of an earlier restore would be, the
    // stage is made again, and nothing is written or read outside the tree.
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(world.outside_state(), before, "{}", text(&output));
    assert_eq!(
        std::fs::read_dir(&world.outside).unwrap().count(),
        1,
        "something was written into the directory the link points at: {}",
        text(&output)
    );
    assert_eq!(opened, 0, "the file was opened or read");
    assert!(!world.data.join(".restore").exists());
    let foreign: Vec<_> = world
        .listing()
        .into_iter()
        .filter(|(_, (u, g, _))| (*u, *g) != (OWNER, OWNER))
        .collect();
    assert!(foreign.is_empty(), "{foreign:?}");
}

#[test]
fn a_tmpdir_that_only_root_can_write_fails_the_restore_before_any_download() {
    let Some(world) = World::new() else { return };
    let stub = world.stub(None);
    let endpoint = stub.endpoint();
    let closed = world.dir.path().join("closed-tmp");
    mkdir(&closed, 0o700);
    let before = world.listing();
    let key = world.with_key();
    let credentials = [
        ("AWS_ACCESS_KEY_ID", "AKIAKRONIKSTUBKEY1"),
        (
            "AWS_SECRET_ACCESS_KEY",
            "stub/secret+key=1234567890abcdefghijklmnop",
        ),
        ("AWS_REGION", "us-east-1"),
        ("TMPDIR", closed.to_str().unwrap()),
    ];
    let args = [
        "--from",
        "s3://proof",
        "--endpoint",
        endpoint.as_str(),
        key[0].as_str(),
        key[1].as_str(),
    ];
    let output = run(world.restore(&args, &credentials));
    let shown = text(&output);
    assert!(!output.status.success(), "{shown}");
    assert!(shown.contains("Permission denied"), "{shown}");
    assert!(
        stub.seen().iter().all(|s| !s.path.contains("/snapshots/")),
        "something was downloaded: {:?}",
        stub.seen()
    );
    assert_eq!(world.listing(), before, "{shown}");

    // The control: the same restore with a TMPDIR the owner can write.
    let writable = [
        credentials[0],
        credentials[1],
        credentials[2],
        ("TMPDIR", world.tmp.to_str().unwrap()),
    ];
    let output = run(world.restore(&args, &writable));
    assert!(output.status.success(), "{}", text(&output));
}

#[test]
fn a_dry_run_as_root_writes_nothing_and_leaves_no_trace() {
    let Some(world) = World::new() else { return };
    let before = world.listing();
    let key = world.with_key();
    let output = run(world.restore(
        &["--from", &world.file_url(), "--dry-run", &key[0], &key[1]],
        &[],
    ));
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(json(&output)["dry_run"], true);
    assert_eq!(world.listing(), before);
    assert_eq!(std::fs::read_dir(&world.tmp).unwrap().count(), 0);
}

#[test]
fn restoring_without_the_keystore_needs_no_key_and_says_so() {
    let Some(world) = World::new() else { return };
    let missing = world.dir.path().join("no-such-key");
    let output = run(world.restore(
        &[
            "--from",
            &world.file_url(),
            "--without-keystore",
            "--master-key-file",
            missing.to_str().unwrap(),
        ],
        &[],
    ));
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(json(&output)["keystore"], "skipped");
}

#[test]
fn a_restore_without_the_key_stops_before_the_drop_and_writes_nothing() {
    let Some(world) = World::new() else { return };
    let missing = world.dir.path().join("no-such-key");
    let before = world.listing();
    let output = run(world.restore(
        &[
            "--from",
            &world.file_url(),
            "--master-key-file",
            missing.to_str().unwrap(),
        ],
        &[],
    ));
    let shown = text(&output);
    assert!(!output.status.success(), "{shown}");
    assert!(
        shown.contains("MASTER_KEY_MISSING") || shown.contains("master key"),
        "{shown}"
    );
    assert_eq!(world.listing(), before);
}

#[test]
fn a_file_bucket_that_only_root_can_read_is_refused_with_the_way_out_and_nothing_is_written() {
    let Some(world) = World::new() else { return };
    // The owner reads a file bucket once root has been given up.
    let closed = world.dir.path().join("closed-bucket");
    std::fs::rename(&world.bucket, &closed).unwrap();
    mkdir(&closed, 0o700);
    let before = world.listing();
    let key = world.with_key();
    let output = run(world.restore(
        &[
            "--from",
            &format!("file://{}", closed.display()),
            &key[0],
            &key[1],
        ],
        &[],
    ));
    let shown = text(&output);
    assert!(!output.status.success(), "{shown}");
    for needle in [
        "cannot be read by user",
        "the owner of the data directory",
        "s3:// bucket",
    ] {
        assert!(shown.contains(needle), "{needle}: {shown}");
    }
    assert_eq!(world.listing(), before, "{shown}");
}

/// An inotify watch on one file: whoever opens or reads it, in whatever mount
/// namespace, leaves an event.
struct Watch {
    fd: rustix::fd::OwnedFd,
}

impl Watch {
    fn on(file: &Path) -> Watch {
        use rustix::fs::inotify;
        let fd =
            inotify::init(inotify::CreateFlags::NONBLOCK | inotify::CreateFlags::CLOEXEC).unwrap();
        inotify::add_watch(
            &fd,
            file,
            inotify::WatchFlags::OPEN | inotify::WatchFlags::ACCESS,
        )
        .unwrap();
        Watch { fd }
    }

    fn events(&self) -> usize {
        use rustix::fs::inotify;
        let mut buffer = [std::mem::MaybeUninit::<u8>::uninit(); 4096];
        let mut reader = inotify::Reader::new(&self.fd, &mut buffer);
        let mut seen = 0;
        while reader.next().is_ok() {
            seen += 1;
        }
        seen
    }
}

/// `data/branches/main` with a link where the database of the branch is,
/// pointing at `target`; everything is owned by `owner`.
fn link_database_to(data: &Path, target: &Path, owner: (u32, u32)) {
    let branch = data.join("branches/main");
    for dir in [data.join("branches"), branch.clone(), branch.join("log")] {
        std::fs::create_dir_all(&dir).unwrap();
        chown(&dir, owner.0, owner.1);
    }
    symlink(target, branch.join("state.db")).unwrap();
    std::os::unix::fs::lchown(branch.join("state.db"), Some(owner.0), Some(owner.1)).unwrap();
}

#[test]
fn upgrade_check_as_root_opens_nothing_in_the_service_users_directory_before_the_drop() {
    let Some(world) = World::bare() else { return };
    // A file of root's, in a directory only root enters: the service user cannot
    // reach it, root can.
    let closed = world.dir.path().join("closed");
    mkdir(&closed, 0o700);
    let target = closed.join("state.db");
    std::fs::write(&target, b"bytes of root's own, which are not a database").unwrap();
    link_database_to(&world.data, &target, (OWNER, OWNER));
    let watch = Watch::on(&target);
    let data = world.data.display().to_string();
    let output = run(world.kronik(&["upgrade", "check", "--data-dir", &data], &[]));
    assert_eq!(
        watch.events(),
        0,
        "the file was opened or read through the service user's link: {}",
        text(&output)
    );
    // The command went on to its own check after the drop (a directory that
    // never served has no log), so it is not an early failure that proves
    // nothing.
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("holds no log"),
        "{}",
        text(&output)
    );

    // The control: the same link in a directory of root's own is followed, by
    // the same binary, so the watch does see an open when there is one.
    let own = world.dir.path().join("rootdata");
    mkdir(&own, 0o700);
    link_database_to(&own, &target, (0, 0));
    let own_arg = own.display().to_string();
    let control = run(world.kronik(&["upgrade", "check", "--data-dir", &own_arg], &[]));
    assert!(
        watch.events() > 0,
        "the control did not open the file either, so the watch proves nothing: {}",
        text(&control)
    );
}

/// Gives `path` and everything below it to the played service user.
fn give_to_the_owner(path: &Path) {
    let status = Command::new("chown")
        .args(["-R", &format!("{OWNER}:{OWNER}")])
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success());
}

/// A key file only root can read, with `key` in it.
fn root_only_key(world: &World, key: &[u8]) -> String {
    mkdir(world.key.parent().unwrap(), 0o700);
    std::fs::write(&world.key, key).unwrap();
    std::fs::set_permissions(&world.key, std::fs::Permissions::from_mode(0o600)).unwrap();
    world.key.display().to_string()
}

#[test]
fn upgrade_check_as_root_opens_the_keystore_of_the_service_user_as_its_owner() {
    let Some(world) = World::bare() else { return };
    let (source, key) = bucket::node_directory();
    let copied = Command::new("cp")
        .args(["-a", &format!("{}/.", source.path().display())])
        .arg(&world.data)
        .status()
        .unwrap();
    assert!(copied.success());
    mkdir(&world.data, 0o700);
    give_to_the_owner(&world.data);
    let data = world.data.display().to_string();
    let key_file = root_only_key(&world, &key);

    // The right key: the replay opens the sealed value with the keystore, and the
    // report is written by the owner.
    let output = run(world.kronik(
        &[
            "upgrade",
            "check",
            "--data-dir",
            &data,
            "--master-key-file",
            &key_file,
        ],
        &[],
    ));
    assert!(output.status.success(), "{}", text(&output));
    let reports: Vec<_> = std::fs::read_dir(&world.data)
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("upgrade"))
        .collect();
    assert!(!reports.is_empty(), "no report in the data directory");
    for report in &reports {
        let meta = std::fs::symlink_metadata(report.path()).unwrap();
        assert_eq!(
            (meta.uid(), meta.gid()),
            (OWNER, OWNER),
            "{:?}",
            report.path()
        );
    }

    // Another key: refused after the drop, by the check of the stores, and
    // nothing is written.
    let before = world.listing();
    let wrong = root_only_key(&world, "7".repeat(64).as_bytes());
    let output = run(world.kronik(
        &[
            "upgrade",
            "check",
            "--data-dir",
            &data,
            "--master-key-file",
            &wrong,
        ],
        &[],
    ));
    assert!(!output.status.success(), "{}", text(&output));
    assert!(
        text(&output).contains("MASTER_KEY_MISMATCH"),
        "{}",
        text(&output)
    );
    assert_eq!(world.listing(), before);
}

#[test]
fn upgrade_check_as_root_opens_no_store_of_the_service_user_before_the_drop() {
    let Some(world) = World::bare() else { return };
    // A file of root's, in a directory only root enters, behind a link where the
    // keystore of the service user is.
    let closed = world.dir.path().join("closed");
    mkdir(&closed, 0o700);
    let target = closed.join("keystore.db");
    std::fs::write(&target, b"bytes of root's own, which are not a database").unwrap();
    let keys = world.data.join("keys");
    symlink(&target, keys.join("keystore.db")).unwrap();
    std::os::unix::fs::lchown(keys.join("keystore.db"), Some(OWNER), Some(OWNER)).unwrap();
    link_database_to(&world.data, &target, (OWNER, OWNER));
    let key_file = root_only_key(&world, "5".repeat(64).as_bytes());
    let watch = Watch::on(&target);
    let data = world.data.display().to_string();
    let output = run(world.kronik(
        &[
            "upgrade",
            "check",
            "--data-dir",
            &data,
            "--master-key-file",
            &key_file,
        ],
        &[],
    ));
    let opened = watch.events();
    assert_eq!(
        opened,
        0,
        "the file was opened through the link: {}",
        text(&output)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("holds no log"),
        "{}",
        text(&output)
    );

    // The control: a root installation's directory with the same link. Root's own
    // key source checks the stores, and so opens the file, so the watch works.
    let own = world.dir.path().join("rootdata");
    mkdir(&own.join("keys"), 0o700);
    symlink(&target, own.join("keys/keystore.db")).unwrap();
    link_database_to(&own, &target, (0, 0));
    let own_arg = own.display().to_string();
    let control = run(world.kronik(
        &[
            "upgrade",
            "check",
            "--data-dir",
            &own_arg,
            "--master-key-file",
            &key_file,
        ],
        &[],
    ));
    assert!(
        watch.events() > 0,
        "the control did not open the file either, so the watch proves nothing: {}",
        text(&control)
    );
}

#[test]
fn upgrade_check_needs_no_key_where_the_service_user_has_no_keystore() {
    let Some(world) = World::bare() else { return };
    // No keystore, and a key file that does not exist: nothing to open, so the
    // key is not asked for, as for a root installation.
    let missing = world.dir.path().join("no-such-key");
    let data = world.data.display().to_string();
    let output = run(world.kronik(
        &[
            "upgrade",
            "check",
            "--data-dir",
            &data,
            "--master-key-file",
            &missing.display().to_string(),
        ],
        &[],
    ));
    let shown = text(&output);
    assert!(!output.status.success(), "{shown}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("holds no log"),
        "{shown}"
    );
    assert!(!shown.contains("MASTER_KEY"), "{shown}");
}
