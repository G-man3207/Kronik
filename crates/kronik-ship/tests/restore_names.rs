//! Names that a restore takes from a bucket. The manifest of a snapshot
//! lists the files to download; a restore refuses one whose paths are not
//! plain relative paths below the snapshot directory, writes nothing, and
//! leaves the destination as it was. The tests edit a `file://` bucket to
//! break each part of that rule.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use kronik_core::env::Env;
use kronik_core::ids::ActorRef;
use kronik_proto::log::v1 as pb;
use kronik_sched::snapshots::{Manifest, SnapshotFile, StorageConfig};
use kronik_sched::{Node, NodeConfig, start_local};
use kronik_ship::{KeystoreMode, Remote, RestoreReport, ShipError, ShipState, restore, ship_once};
use tokio::runtime::Runtime;

fn runtime() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

fn tempdir(prefix: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap()
}

fn guest(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../../tests/guests/{name}.wasm",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn audit() -> pb::Audit {
    pb::Audit {
        token_id: "test".into(),
        reason: "test".into(),
        wall_time_ms: 0,
    }
}

fn message(name: &str, body: &str) -> pb::Message {
    pb::Message {
        name: name.into(),
        content_type: "text/plain".into(),
        body: Some(pb::Sealable {
            subject: None,
            value: Some(pb::sealable::Value::Plain(body.as_bytes().to_vec())),
        }),
        blobs: vec![],
        retained_compensation_source: None,
    }
}

/// A node running on `dir`, with the runtime it runs on.
struct Proc {
    rt: Runtime,
    node: Arc<Node>,
}

fn start(dir: &Path) -> Proc {
    let rt = runtime();
    let node = rt.block_on(async {
        let mut storage = StorageConfig::new(dir.to_path_buf());
        storage.snapshots_kept = 2;
        start_local(
            Env::real(tokio::runtime::Handle::current()),
            dir,
            NodeConfig {
                storage: Some(storage),
                segment_max_bytes: Some(4096),
                ..NodeConfig::default()
            },
        )
        .await
        .unwrap()
    });
    Proc { rt, node }
}

impl Proc {
    fn operator(&self) -> kronik_core::authority::AuthLease {
        self.node.local_operator_authority().unwrap()
    }

    fn deploy(&self, name: &str) {
        self.rt
            .block_on(
                self.node
                    .deploy(&guest(name), audit(), false, self.operator()),
            )
            .unwrap();
    }

    fn send(&self, actor: &str, name: &str, body: &str) {
        let r = self
            .rt
            .block_on(self.node.send(
                ActorRef::parse(actor).unwrap(),
                message(name, body),
                audit(),
                false,
                self.operator(),
            ))
            .unwrap()
            .unwrap();
        assert!(r.committed(), "{r:?}");
    }

    fn snapshot(&self) {
        self.rt
            .block_on(self.node.snapshot("manual", self.operator()))
            .unwrap();
    }

    fn ship(&self, remote: &Remote, dir: &Path) {
        let mut state = ShipState::load(dir).unwrap();
        self.rt
            .block_on(ship_once(remote, dir, "main", &mut state))
            .unwrap();
    }
}

/// What every test starts from: a bucket that holds one snapshot of a node
/// with SQL state, its log and its components, the master key of that node,
/// and the snapshot's manifest.
struct Shipped {
    bucket: tempfile::TempDir,
    key: Vec<u8>,
    /// `main/snapshots/<lsn>` in the bucket.
    base: String,
    manifest: Manifest,
    rt: Runtime,
}

fn shipped() -> Shipped {
    let src = tempdir("names-src-");
    let bucket = tempdir("names-bucket-");
    let remote = Remote::open(&format!("file://{}", bucket.path().display()), None).unwrap();
    let p = start(src.path());
    p.deploy("counter");
    p.deploy("notes");
    for i in 0..6 {
        p.send(&format!("counter/c{}", i % 2), "increment", "");
        p.send(&format!("notes/n{}", i % 2), "add", &format!("note {i}"));
    }
    p.snapshot();
    p.ship(&remote, src.path());
    let key = std::fs::read(src.path().join("keys/master.key")).unwrap();
    drop(p);

    let rt = runtime();
    let (_, snapshots) = rt.block_on(remote.list("main/snapshots")).unwrap();
    assert_eq!(snapshots.len(), 1, "{snapshots:?}");
    let base = format!("main/snapshots/{}", snapshots[0]);
    let bytes = rt
        .block_on(remote.get(&format!("{base}/manifest.json")))
        .unwrap();
    let manifest: Manifest = serde_json::from_slice(&bytes).unwrap();
    // The legitimate paths include a nested one: `sql/<dir>/<file>.db`.
    let nested = |f: &SnapshotFile| f.path.starts_with("sql/") && f.path.matches('/').count() == 2;
    assert!(manifest.files.iter().any(nested), "{:?}", manifest.files);
    Shipped {
        bucket,
        key,
        base,
        manifest,
        rt,
    }
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// Every directory and file below `root`, with a digest of each file.
fn tree(root: &Path) -> BTreeMap<PathBuf, String> {
    fn walk(root: &Path, at: &Path, out: &mut BTreeMap<PathBuf, String>) {
        for entry in std::fs::read_dir(at).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let name = path.strip_prefix(root).unwrap().to_path_buf();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                out.insert(name, "dir".into());
                walk(root, &path, out);
            } else if kind.is_file() {
                let digest = blake3::hash(&std::fs::read(&path).unwrap()).to_hex();
                out.insert(name, digest.to_string());
            } else {
                out.insert(name, "other".into());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// A bucket of its own, a copy of the shipped one.
struct Bucket {
    _dir: tempfile::TempDir,
    remote: Remote,
}

impl Shipped {
    fn copy(&self) -> Bucket {
        let dir = tempdir("names-copy-");
        copy_dir(self.bucket.path(), dir.path());
        let remote = Remote::open(&format!("file://{}", dir.path().display()), None).unwrap();
        Bucket { _dir: dir, remote }
    }

    /// The names of the components in the bucket: `<hash>.wasm`.
    fn components(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(self.bucket.path().join("code"))
            .unwrap()
            .map(|e| {
                let name = e.unwrap().file_name().to_string_lossy().into_owned();
                name.strip_suffix(".zst").unwrap().to_owned()
            })
            .collect();
        names.sort();
        names
    }

    /// The object `code/<object>` in `bucket`, with `content` compressed.
    fn put_code(&self, bucket: &Bucket, object: &str, content: &[u8]) {
        let packed = zstd::stream::encode_all(content, 3).unwrap();
        self.rt
            .block_on(bucket.remote.put(&format!("code/{object}"), packed))
            .unwrap();
    }

    /// An entry for `path` whose object is in the bucket with the right size
    /// and BLAKE3, so that only the path can refuse it.
    fn entry(&self, bucket: &Bucket, path: &str, content: &[u8]) -> SnapshotFile {
        let object = format!("{}/{path}.zst", self.base);
        let packed = zstd::stream::encode_all(content, 3).unwrap();
        self.rt
            .block_on(bucket.remote.put(&object, packed))
            .unwrap();
        SnapshotFile {
            path: path.into(),
            size: content.len() as u64,
            blake3: blake3::hash(content).to_hex().to_string(),
        }
    }

    /// The manifest with its file list edited, in `bucket`.
    fn edit_manifest(&self, bucket: &Bucket, edit: impl FnOnce(&mut Vec<SnapshotFile>)) {
        let mut manifest = self.manifest.clone();
        edit(&mut manifest.files);
        self.rt
            .block_on(bucket.remote.put(
                &format!("{}/manifest.json", self.base),
                serde_json::to_vec_pretty(&manifest).unwrap(),
            ))
            .unwrap();
    }

    /// A data directory in its own area, holding only the master key.
    fn destination(&self) -> (tempfile::TempDir, PathBuf) {
        let area = tempdir("names-area-");
        let data = area.path().join("data");
        std::fs::create_dir_all(data.join("keys")).unwrap();
        std::fs::write(data.join("keys/master.key"), &self.key).unwrap();
        (area, data)
    }

    fn restore(
        &self,
        bucket: &Bucket,
        data: &Path,
        force: bool,
    ) -> Result<RestoreReport, ShipError> {
        self.rt.block_on(restore(
            &bucket.remote,
            data,
            "main",
            force,
            &Env::real(self.rt.handle().clone()),
            &Default::default(),
            KeystoreMode::Require,
        ))
    }
}

fn refusal(result: Result<RestoreReport, ShipError>, what: &str) -> String {
    match result {
        Err(ShipError::Restore(message)) => message,
        other => panic!("{what}: expected a refusal, got {other:?}"),
    }
}

/// The path a manifest names in each case. The snapshot directory is
/// `<data>/.restore/snapshot`, three levels below the area that holds the
/// data directory, so a path that leaves it lands inside the area, where
/// the comparison of the trees sees it.
const UNSOUND: [&str; 13] = [
    "absolute",
    "parent directory",
    "parent directory below a name",
    "empty",
    "dot",
    "dot first",
    "dot inside",
    "empty part",
    "trailing slash",
    "NUL",
    "a file and a directory",
    "the manifest",
    "a path twice",
];

fn unsound_path(what: &str, area: &Path) -> String {
    match what {
        "absolute" => format!("{}/outside/absolute.bin", area.display()),
        "parent directory" => "../../../up.bin".into(),
        "parent directory below a name" => "sql/../../../../up.bin".into(),
        "empty" => String::new(),
        "dot" => ".".into(),
        "dot first" => "./copy.db".into(),
        "dot inside" => "sql/./copy.db".into(),
        "empty part" => "sql//copy.db".into(),
        "trailing slash" => "sql/copy.db/".into(),
        "NUL" => "co\0py.db".into(),
        "a file and a directory" => "sql".into(),
        "the manifest" => "manifest.json".into(),
        "a path twice" => "state.db".into(),
        other => panic!("{other}"),
    }
}

#[test]
fn a_manifest_with_unsound_paths_is_refused_and_nothing_is_written() {
    let shipped = shipped();
    for what in UNSOUND {
        let bucket = shipped.copy();
        let (area, data) = shipped.destination();
        let path = unsound_path(what, area.path());
        shipped.edit_manifest(&bucket, |files| {
            let entry = if what == "a path twice" {
                files.iter().find(|f| f.path == path).unwrap().clone()
            } else {
                shipped.entry(&bucket, &path, b"extra file")
            };
            files.push(entry);
        });

        let before = tree(area.path());
        let error = refusal(shipped.restore(&bucket, &data, false), what);
        assert!(error.contains("snapshot manifest"), "{what}: {error}");
        assert_eq!(tree(area.path()), before, "{what}: the area changed");
    }
}

#[test]
fn a_refused_restore_leaves_existing_state_as_it_was() {
    let shipped = shipped();
    let (area, data) = shipped.destination();
    // A restore that worked: the data directory now holds a node.
    let good = shipped.copy();
    shipped.restore(&good, &data, false).unwrap();
    let before = tree(area.path());
    assert!(
        before
            .keys()
            .any(|p| p.starts_with("data/branches/main/sql") && p.extension().is_some()),
        "no SQL database was restored: {before:?}"
    );

    // The same bucket with a manifest that names a path outside the snapshot.
    let bucket = shipped.copy();
    shipped.edit_manifest(&bucket, |files| {
        let outside = format!("{}/outside.bin", area.path().display());
        let entry = shipped.entry(&bucket, &outside, b"extra file");
        files.push(entry);
    });
    let error = refusal(shipped.restore(&bucket, &data, true), "forced restore");
    assert!(error.contains("snapshot manifest"), "{error}");
    assert_eq!(tree(area.path()), before);
}

#[test]
fn the_files_a_node_writes_are_restored() {
    let shipped = shipped();
    let (_area, data) = shipped.destination();
    let bucket = shipped.copy();
    let report = shipped.restore(&bucket, &data, false).unwrap();
    assert_eq!(report.snapshot_lsn, shipped.manifest.lsn);
    // The nested paths `sql/<dir>/<file>.db` came back as files.
    for file in &shipped.manifest.files {
        let installed = if let Some(rest) = file.path.strip_prefix("sql/") {
            data.join("branches/main/sql").join(rest)
        } else {
            data.join("snapshots/main")
                .join(format!("{:020}", shipped.manifest.lsn))
                .join(&file.path)
        };
        assert!(
            installed.is_file(),
            "{} is not at {}",
            file.path,
            installed.display()
        );
    }
}

#[test]
fn shipping_does_not_read_files_a_manifest_names_outside_its_directory() {
    let src = tempdir("names-ship-src-");
    let bucket = tempdir("names-ship-bucket-");
    let remote = Remote::open(&format!("file://{}", bucket.path().display()), None).unwrap();
    let p = start(src.path());
    p.deploy("counter");
    p.send("counter/a", "increment", "");
    p.snapshot();
    // A local manifest that names a file next to the snapshots.
    let (dir, manifest) = kronik_sched::snapshots::list(src.path(), "main")
        .pop()
        .unwrap();
    let neighbour = src.path().join("neighbour.txt");
    std::fs::write(&neighbour, b"not part of the snapshot").unwrap();
    let mut edited = manifest.clone();
    edited.files.push(SnapshotFile {
        path: neighbour.display().to_string(),
        size: 24,
        blake3: blake3::hash(b"not part of the snapshot")
            .to_hex()
            .to_string(),
    });
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_vec_pretty(&edited).unwrap(),
    )
    .unwrap();

    p.ship(&remote, src.path());
    // That snapshot was not shipped, and nothing of the neighbour was.
    let state = ShipState::load(src.path()).unwrap();
    assert!(!state.snapshots.contains(&manifest.lsn), "{state:?}");
    let shipped_files = walk_names(bucket.path());
    assert!(
        shipped_files.iter().all(|n| !n.contains("neighbour")),
        "{shipped_files:?}"
    );
    assert!(
        shipped_files
            .iter()
            .all(|n| !n.ends_with(&format!("{:020}/manifest.json", manifest.lsn))),
        "{shipped_files:?}"
    );
}

/// The names of the files below `root`, as paths relative to it.
fn walk_names(root: &Path) -> Vec<String> {
    tree(root)
        .into_iter()
        .filter(|(_, kind)| kind != "dir")
        .map(|(path, _)| path.display().to_string())
        .collect()
}

/// Every `*.cwasm` below `root`.
fn precompiled_below(root: &Path) -> Vec<PathBuf> {
    tree(root)
        .into_keys()
        .filter(|p| p.extension().is_some_and(|e| e == "cwasm"))
        .collect()
}

#[test]
fn a_code_object_that_is_not_a_component_named_by_its_hash_is_refused() {
    let shipped = shipped();
    let engine = shipped.manifest.engine_version.clone();
    let real = shipped.components()[0]
        .strip_suffix(".wasm")
        .unwrap()
        .to_owned();
    let content = guest("counter");
    let other = blake3::hash(b"another content").to_hex().to_string();
    // (what, object under code/, content, what the message says)
    let cases: Vec<(&str, String, Vec<u8>, &str)> = vec![
        (
            "a precompiled artifact of a component",
            format!("{real}.{engine}.cwasm.zst"),
            b"precompiled".to_vec(),
            "code/",
        ),
        (
            "a precompiled artifact of another component",
            format!("{other}.{engine}.cwasm.zst"),
            b"precompiled".to_vec(),
            "code/",
        ),
        (
            "a name that is no hash",
            "plain.wasm.zst".into(),
            content.clone(),
            "code/",
        ),
        (
            "an upper-case hash",
            format!("{}.wasm.zst", real.to_uppercase()),
            content.clone(),
            "code/",
        ),
        (
            "a short hash",
            format!("{}.wasm.zst", &real[..63]),
            content.clone(),
            "code/",
        ),
        (
            "no extension",
            format!("{real}.zst"),
            content.clone(),
            "code/",
        ),
        (
            "a hash of other content",
            format!("{other}.wasm.zst"),
            content.clone(),
            "does not match its name",
        ),
        (
            "the name of a component with other content",
            format!("{real}.wasm.zst"),
            b"other content".to_vec(),
            "does not match its name",
        ),
    ];
    for (what, object, content, says) in &cases {
        let bucket = shipped.copy();
        shipped.put_code(&bucket, object, content);
        let (area, data) = shipped.destination();
        // The destination holds an artifact of its own, which a refusal leaves.
        let code = data.join("code");
        std::fs::create_dir_all(&code).unwrap();
        std::fs::write(code.join(format!("{real}.{engine}.cwasm")), b"held").unwrap();

        let before = tree(area.path());
        let error = refusal(shipped.restore(&bucket, &data, false), what);
        assert!(error.contains(says), "{what}: {error}");
        assert_eq!(tree(area.path()), before, "{what}: the area changed");
    }
}

#[test]
fn a_restore_installs_the_components_and_no_precompiled_artifact() {
    let shipped = shipped();
    let engine = shipped.manifest.engine_version.clone();
    let components = shipped.components();
    let (area, data) = shipped.destination();
    // The destination holds artifacts of components, of an engine and of
    // none, a directory named like one, and a file that is not one.
    let code = data.join("code");
    std::fs::create_dir_all(code.join("dir.cwasm")).unwrap();
    std::fs::write(code.join("dir.cwasm/inside"), b"held").unwrap();
    let held = [
        format!("{}.{engine}.cwasm", components[0].trim_end_matches(".wasm")),
        "0000.another-engine.cwasm".to_owned(),
        "stray.cwasm".to_owned(),
    ];
    for name in &held {
        std::fs::write(code.join(name), b"held").unwrap();
    }
    std::fs::write(code.join("notes.txt"), b"kept").unwrap();

    let bucket = shipped.copy();
    shipped.restore(&bucket, &data, false).unwrap();
    assert!(precompiled_below(area.path()).is_empty());
    assert_eq!(std::fs::read(code.join("notes.txt")).unwrap(), b"kept");
    // Every component came back, as the bytes its name is the hash of.
    assert!(components.len() >= 2, "{components:?}");
    for name in &components {
        let bytes = std::fs::read(code.join(name)).unwrap();
        let hash = blake3::hash(&bytes).to_hex().to_string();
        assert_eq!(format!("{hash}.wasm"), *name);
    }
}
