//! Shared harness of the integration tests in this directory: a node on a
//! runtime of its own, the operator's audit record and lease, and waiting
//! for an ingress.
//!
//! The library's unit tests do not compile this file; `src/gate/tests.rs`
//! includes `revocable.rs` directly.

// Each test binary uses only part of this module.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kronik_core::authority::AuthLease;
use kronik_core::env::Env;
use kronik_core::error::ApiError;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_sched::{DeployResult, Ingress, Node, NodeConfig, TurnResult, start_local};
use tokio::runtime::Runtime;

/// A "process" is a node on a runtime of its own; dropping the runtime
/// cancels every task like a crash.
pub struct Proc {
    pub rt: Runtime,
    pub node: Arc<Node>,
}

/// The audit record of the tests' own operations.
pub fn audit() -> pb::Audit {
    pb::Audit {
        token_id: "test".into(),
        reason: "test".into(),
        wall_time_ms: 0,
    }
}

/// Starts a node with `config` in `dir` on a new two-worker runtime.
pub fn start_proc(dir: &Path, config: NodeConfig) -> Proc {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let node = rt.block_on(async {
        let env = Env::real(tokio::runtime::Handle::current());
        start_local(env, dir, config).await.unwrap()
    });
    Proc { rt, node }
}

/// Waits for an ingress to finish.
pub async fn wait_turn(ingress: Ingress) -> Result<TurnResult, ApiError> {
    match ingress {
        Ingress::Started(w) | Ingress::Joined(w) => w.wait().await,
        Ingress::Done(r) => Ok(*r),
    }
}

impl Proc {
    /// A fresh live operator lease.
    pub fn owner(&self) -> AuthLease {
        self.node.local_operator_authority().unwrap()
    }

    /// Deploys the guest at `path`.
    pub fn deploy_file(&self, path: &str) -> DeployResult {
        let bytes = std::fs::read(path).unwrap();
        self.rt
            .block_on(self.node.deploy(&bytes, audit(), false, self.owner()))
            .unwrap()
    }
}

/// Every record in the log, read with a fresh runtime (the daemon is dead).
pub fn log_records(dir: &Path) -> Vec<Record> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let env = Env::real(tokio::runtime::Handle::current());
        let reader = kronik_log::LogReader::new(env, dir.join("branches/main/log"), "main");
        let mut out = Vec::new();
        reader
            .read(1, u64::MAX, |c| {
                out.push(c.record);
                Ok(())
            })
            .await
            .unwrap();
        out
    })
}

pub fn install_component(dir: &Path, bytes: &[u8]) -> Vec<u8> {
    let hash = kronik_core::ids::CodeHash::of(bytes);
    let code = dir.join("code");
    std::fs::create_dir_all(&code).unwrap();
    std::fs::write(code.join(format!("{}.wasm", hash.hex())), bytes).unwrap();
    hash.0.to_vec()
}

/// Points the open turn's `TurnBegin` at `code_hash` and keeps `state.db`'s
/// offsets on the rewritten segment.
pub fn point_open_turn_at(
    dir: &Path,
    execution_id: &str,
    code_hash: &[u8],
    lsn: u64,
    segment: u64,
) {
    let log = dir.join("branches/main/log");
    let mut found = false;
    for start in kronik_log::segment_starts(&log).unwrap() {
        let path = log.join(kronik_log::segment_name(start));
        let rewritten = kronik_log::rewrite_segment(&path, |_lsn, record| {
            let Record::TurnBegin(begin) = record else {
                return Ok(false);
            };
            if begin.execution_id != execution_id {
                return Ok(false);
            }
            begin.code_hash = code_hash.to_vec();
            found = true;
            Ok(true)
        })
        .unwrap_or_else(|e| panic!("rewrite {}: {e}", path.display()));
        if !found {
            continue;
        }
        let db = rusqlite::Connection::open(dir.join("branches/main/state.db")).unwrap();
        for (at, offset) in &rewritten.offsets {
            db.execute(
                "UPDATE turn_index SET offset = ?1 WHERE lsn = ?2 AND segment = ?3",
                rusqlite::params![*offset as i64, *at as i64, start as i64],
            )
            .unwrap();
            db.execute(
                "UPDATE open_turns SET offset = ?1 WHERE lsn = ?2 AND segment = ?3",
                rusqlite::params![*offset as i64, *at as i64, start as i64],
            )
            .unwrap();
        }
        let pointed = db
            .query_row(
                "SELECT offset FROM open_turns WHERE execution_id = ?1 AND segment = ?2",
                rusqlite::params![execution_id, segment as i64],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        let expected = rewritten
            .offsets
            .iter()
            .find(|(at, _)| *at == lsn)
            .map(|(_, offset)| *offset as i64)
            .expect("the rewritten segment lost the TurnBegin");
        assert_eq!(
            pointed, expected,
            "the open turn no longer points at its TurnBegin"
        );
        break;
    }
    assert!(found, "open turn {execution_id} was not in the log");
}

pub fn text_frame(text: &str) -> pb::Frame {
    pb::Frame {
        kind: pb::frame::Kind::Text as i32,
        data: Some(pb::Sealable {
            subject: None,
            value: Some(pb::sealable::Value::Plain(text.as_bytes().to_vec())),
        }),
        ..Default::default()
    }
}

/// The upgrade request of `/room/<key>/ws?<query>`, as the gateway builds
/// it, offering the subprotocol `room.v1`.
pub fn open_request(key: &str, query: &str) -> pb::HttpInput {
    pb::HttpInput {
        method: "GET".into(),
        path: format!("/room/{key}/ws"),
        query: query.into(),
        params: vec![pb::Param {
            name: "key".into(),
            value: key.into(),
            sealed_value: None,
        }],
        headers: vec![pb::Header {
            name: "sec-websocket-protocol".into(),
            value: Some(pb::Sealable {
                subject: None,
                value: Some(pb::sealable::Value::Plain(b"room.v1".to_vec())),
            }),
        }],
        route: "/room/{key}/ws".into(),
        ..Default::default()
    }
}

/// Answers each request `delay` after it read the request.
#[allow(clippy::disallowed_methods)]
pub fn slow_server(delay: Duration) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        use std::io::{Read as _, Write as _};
        for mut stream in listener.incoming().flatten() {
            stream
                .set_read_timeout(Some(Duration::from_millis(300)))
                .unwrap();
            let mut buf = vec![0u8; 64 << 10];
            while let Ok(n) = stream.read(&mut buf) {
                if n == 0 {
                    break;
                }
            }
            std::thread::sleep(delay);
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
    });
    addr
}
