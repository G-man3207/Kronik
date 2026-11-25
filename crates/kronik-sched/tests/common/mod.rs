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
