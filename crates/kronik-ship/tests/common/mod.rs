//! Helpers shared by the shipping and restore integration tests.

#![allow(dead_code)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kronik_core::env::Env;
use kronik_core::ids::ActorRef;
use kronik_privacy::key_source::{Keys, lock_data};
use kronik_proto::log::v1 as pb;
use kronik_sched::snapshots::StorageConfig;
use kronik_sched::{Node, NodeConfig, start_local};
use kronik_ship::{
    KeystoreMode, Remote, RestoreReport, ShipError, ShipState, restore, restore_as_owner,
    root_phase, ship_once,
};
use tokio::runtime::Runtime;

pub fn rt() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

pub fn audit() -> pb::Audit {
    pb::Audit {
        token_id: "test".into(),
        reason: "test".into(),
        wall_time_ms: 0,
    }
}

pub fn tempdir(prefix: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap()
}

/// A node running on `dir`, with the runtime it runs on.
pub struct Proc {
    pub rt: Runtime,
    pub node: Arc<Node>,
}

pub fn start(dir: &Path, history: Option<Duration>) -> Proc {
    let rt = rt();
    let node = rt.block_on(async {
        let mut storage = StorageConfig::new(dir.to_path_buf());
        storage.snapshots_kept = 2;
        if let Some(h) = history {
            storage.history = h;
        }
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
    pub fn send(&self, actor: &str, name: &str, body: &str) -> String {
        let r = self
            .rt
            .block_on(self.node.send(
                ActorRef::parse(actor).unwrap(),
                message(name, body),
                audit(),
                false,
                self.node.local_operator_authority().unwrap(),
            ))
            .unwrap()
            .unwrap();
        assert!(r.committed(), "{r:?}");
        match &r.outcome.output {
            Some(pb::outcome::Output::Reply(m)) => {
                match m.body.as_ref().and_then(|b| b.value.as_ref()) {
                    Some(pb::sealable::Value::Plain(b)) => String::from_utf8_lossy(b).into_owned(),
                    _ => String::new(),
                }
            }
            _ => String::new(),
        }
    }

    /// One turn of `counter/tick` in a later millisecond than every turn so
    /// far, then a retention pass. With `history` 0 the window holds the fork
    /// points of the newest millisecond, so a snapshot becomes the window's
    /// base only once a later turn has put it behind the window.
    pub fn age_and_compact(&self) {
        let hwm = self.node.store().db().time_hwm().unwrap();
        while self.node.store().db().time_hwm().unwrap() <= hwm {
            std::thread::sleep(Duration::from_millis(2));
            self.send("counter/tick", "increment", "");
        }
        self.node
            .compact(self.node.storage_config().unwrap())
            .unwrap();
    }

    pub fn ship(&self, remote: &Remote, dir: &Path) -> kronik_ship::ShipReport {
        let mut st = ShipState::load(dir).unwrap();
        self.rt
            .block_on(ship_once(remote, dir, "main", &mut st))
            .unwrap()
    }

    pub fn deploy(&self, name: &str) {
        self.rt
            .block_on(self.node.deploy(
                &guest(name),
                audit(),
                false,
                self.node.local_operator_authority().unwrap(),
            ))
            .unwrap();
    }

    pub fn snapshot(&self) -> kronik_sched::snapshots::Manifest {
        self.rt
            .block_on(
                self.node
                    .snapshot("manual", self.node.local_operator_authority().unwrap()),
            )
            .unwrap()
    }
}

/// A new data directory holding only the master key `key`.
pub fn destination(prefix: &str, key: &[u8]) -> tempfile::TempDir {
    let dir = tempdir(prefix);
    std::fs::create_dir_all(dir.path().join("keys")).unwrap();
    std::fs::write(dir.path().join("keys/master.key"), key).unwrap();
    dir
}

/// Restores branch `main` from `remote` into `data` with the default options
/// (no force, default key sources, the keystore required, no missing blob
/// allowed, no fault), on a runtime of its own.
pub fn restore_main(remote: &Remote, data: &Path) -> Result<RestoreReport, ShipError> {
    let rt = rt();
    rt.block_on(restore(
        remote,
        data,
        "main",
        false,
        &Env::real(rt.handle().clone()),
        &Default::default(),
        KeystoreMode::Require,
        false,
        &|_| Ok(()),
    ))
}

/// Restores branch `main` from `remote` into `data` in the two phases
/// `kronik restore` runs on either side of a drop of privileges: lock the
/// directory, run the root phase, then the owner's phase under the lock.
pub fn restore_two_phases(
    rt: &Runtime,
    remote: &Remote,
    data: &Path,
    force: bool,
    keys: &Keys,
    mode: KeystoreMode,
) -> Result<RestoreReport, ShipError> {
    let env = Env::real(rt.handle().clone());
    rt.block_on(async {
        let ownership = lock_data(data)?;
        let phase = root_phase(remote, data, &env, keys, mode).await?;
        restore_as_owner(remote, data, "main", force, &env, phase, &ownership).await
    })
}

pub fn guest(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../../tests/guests/{name}.wasm",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

pub fn message(name: &str, body: &str) -> pb::Message {
    pb::Message {
        name: name.into(),
        content_type: "text/plain".into(),
        body: Some(pb::Sealable::new_plain(None, body.as_bytes().to_vec())),
        blobs: vec![],
        retained_compensation_source: None,
    }
}

/// The S3 URL of this run (`scripts/s3.sh` exports it), or `None` to skip.
/// With `KRONIK_TEST_S3=require` (the `s3` step of `scripts/ci.sh`) a
/// missing URL fails the test, so that a run never passes by skipping.
pub fn s3_url() -> Option<String> {
    match std::env::var("KRONIK_TEST_S3_URL") {
        Ok(url) => Some(url),
        Err(_) => {
            assert_ne!(
                std::env::var("KRONIK_TEST_S3").as_deref(),
                Ok("require"),
                "KRONIK_TEST_S3=require, but KRONIK_TEST_S3_URL is not set: run this test under scripts/s3.sh"
            );
            eprintln!("KRONIK_TEST_S3_URL is not set; run scripts/s3.sh for this test");
            None
        }
    }
}
