//! A bucket that a node has shipped into, for the restore tests: one snapshot,
//! the log, and a backup of the privacy keystore.

#![allow(
    dead_code,
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::expect_used
)]

use std::path::Path;
use std::time::Duration;

use kronik_core::env::Env;
use kronik_core::ids::ActorRef;
use kronik_proto::log::v1 as pb;
use kronik_sched::snapshots::StorageConfig;
use kronik_sched::{NodeConfig, start_local};
use kronik_ship::{Remote, ShipState, ship_keystore, ship_once};

pub fn guest(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../../tests/guests/{name}.wasm",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

pub fn audit() -> pb::Audit {
    pb::Audit {
        token_id: "test".into(),
        reason: "test".into(),
        wall_time_ms: 0,
    }
}

pub fn message(name: &str, body: &str) -> pb::Message {
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

/// Runs a node on a scratch directory, ships it into `bucket` (which must
/// exist) and returns its master key, which is never in the bucket.
pub fn ship_into(bucket: &Path) -> Vec<u8> {
    let source = tempfile::tempdir().unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let env = Env::real(runtime.handle().clone());
    let node = runtime.block_on(async {
        let mut storage = StorageConfig::new(source.path().to_path_buf());
        storage.snapshots_kept = 2;
        start_local(
            env.clone(),
            source.path(),
            NodeConfig {
                storage: Some(storage),
                segment_max_bytes: Some(4096),
                ..NodeConfig::default()
            },
        )
        .await
        .unwrap()
    });
    runtime
        .block_on(node.deploy(
            &guest("counter"),
            audit(),
            false,
            node.local_operator_authority().unwrap(),
        ))
        .unwrap();
    for i in 0..6 {
        let reply = runtime
            .block_on(node.send(
                ActorRef::parse(&format!("counter/c{}", i % 3)).unwrap(),
                message("increment", ""),
                audit(),
                false,
                node.local_operator_authority().unwrap(),
            ))
            .unwrap()
            .unwrap();
        assert!(reply.committed(), "{reply:?}");
    }
    node.sealer()
        .keystore()
        .unwrap()
        .key_for_sealing("user:1", [9; 32], [3; 24], 1)
        .unwrap();
    runtime
        .block_on(node.snapshot("manual", node.local_operator_authority().unwrap()))
        .unwrap();
    let remote = Remote::open(&format!("file://{}", bucket.display()), None).unwrap();
    let mut state = ShipState::load(source.path()).unwrap();
    runtime
        .block_on(ship_once(&remote, source.path(), "main", &mut state))
        .unwrap();
    runtime
        .block_on(ship_keystore(
            &env,
            &remote,
            source.path(),
            &mut state,
            1_700_000_000_000,
            Duration::from_secs(30 * 86_400),
            [7; 24],
            node.key_source().unwrap(),
            node.sealer().keystore().unwrap(),
        ))
        .unwrap();
    let key = std::fs::read(source.path().join("keys/master.key")).unwrap();
    drop(node);
    drop(runtime);
    key
}

/// A data directory that a node has served: a log, a snapshot, and a keystore
/// that holds the key of a subject whose sealed value is in the log. Returns
/// the directory and the node's master key (hex text, as the node keeps it).
pub fn node_directory() -> (tempfile::TempDir, Vec<u8>) {
    let source = tempfile::tempdir().unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let env = Env::real(runtime.handle().clone());
    let node = runtime.block_on(async {
        start_local(
            env.clone(),
            source.path(),
            NodeConfig {
                storage: Some(StorageConfig::new(source.path().to_path_buf())),
                segment_max_bytes: Some(4096),
                ..NodeConfig::default()
            },
        )
        .await
        .unwrap()
    });
    runtime
        .block_on(node.deploy(
            &guest("counter"),
            audit(),
            false,
            node.local_operator_authority().unwrap(),
        ))
        .unwrap();
    runtime
        .block_on(node.set_privacy_mode(
            pb::PrivacyState::On,
            audit(),
            false,
            node.local_operator_authority().unwrap(),
        ))
        .unwrap();
    for name in ["increment", "subject", "increment"] {
        let reply = runtime
            .block_on(node.send(
                ActorRef::parse("counter/on").unwrap(),
                message(name, ""),
                audit(),
                false,
                node.local_operator_authority().unwrap(),
            ))
            .unwrap()
            .unwrap();
        assert!(reply.committed(), "{reply:?}");
    }
    let key = std::fs::read(source.path().join("keys/master.key")).unwrap();
    drop(node);
    drop(runtime);
    (source, key)
}
