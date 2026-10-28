//! An in-memory Kronik node for actor tests.
//!
//! The real scheduler, runtime, effect gate, gateway and API run against an
//! [`Env`] made for tests: a [`ManualClock`] that moves only when the test
//! advances it (so timers fire when the test says), seeded entropy (the same
//! seed gives the same ids and guest randomness), a file system in memory,
//! and a [`StubNet`] that answers outgoing HTTP from stubs and records every
//! request with the secrets the host inserted.
//!
//! `kronik test-host` serves a [`TestHost`] over JSON lines (see
//! [`TestHost::handle_line`]); the SDKs' testkits are clients of it.

mod clock;
mod fs;
mod net;
mod protocol;

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use kronik_api::{Api, ApiRequest, ApiResponse};
use kronik_core::env::{
    BoxFuture, Clock, EntropySource, Env, Process, ProcessRunner, ProcessSpec, Spawner,
};
use kronik_gateway::{Gateway, GatewayConfig, HttpRequest, HttpResponse};
use kronik_log::LogConfig;
use kronik_privacy::{MasterKey, SecretStore};
use kronik_runtime::{CodeStore, PoolSize, build_engine};
use kronik_sched::{Node, NodeConfig, NodeParts};
use kronik_store::Store;
use kronik_store::sql::{Limits, MemOpener, SqlPool};

pub use clock::ManualClock;
pub use net::{Recorded, Stub, StubFailure, StubNet};
pub use protocol::Body;

/// 2026-01-01T00:00:00Z, where a test host's clock starts by default.
pub const DEFAULT_START_MS: u64 = 1_767_225_600_000;

/// How long [`TestHost::settle`] waits for the node to become idle.
const SETTLE_LIMIT: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(String);

impl Error {
    fn new(what: &str, e: impl std::fmt::Display) -> Error {
        Error(format!("{what}: {e}"))
    }
}

/// How a test host starts.
#[derive(Debug, Clone)]
pub struct Options {
    /// Seeds ids, execution seeds and guest randomness.
    pub seed: u64,
    /// The wall clock at the start, in ms since the Unix epoch.
    pub start_ms: u64,
    /// Where compiled components are kept between test hosts; compiling a
    /// JavaScript component takes seconds. `None` compiles in memory.
    pub code_cache: Option<PathBuf>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            seed: 0,
            start_ms: DEFAULT_START_MS,
            code_cache: None,
        }
    }
}

/// A node in memory, with its gateway and API.
pub struct TestHost {
    node: Arc<Node>,
    gateway: Gateway,
    api: Api,
    clock: Arc<ManualClock>,
    net: Arc<StubNet>,
}

impl TestHost {
    /// Starts an empty node. `spawner` runs its tasks (the binary passes a
    /// tokio runtime's).
    pub async fn start(spawner: Arc<dyn Spawner>, options: Options) -> Result<TestHost, Error> {
        let clock = ManualClock::new(options.start_ms);
        let net = Arc::new(StubNet::default());
        let env = Env {
            clock: clock.clone(),
            spawner,
            entropy: Arc::new(SeededEntropy {
                key: *blake3::hash(&options.seed.to_le_bytes()).as_bytes(),
                counter: Mutex::new(0),
            }),
            fs: Arc::new(fs::MemFs::default()),
            net: net.clone(),
            procs: Arc::new(NoProcesses),
        };
        let conn = rusqlite::Connection::open_in_memory().map_err(|e| Error::new("state", e))?;
        let pool = SqlPool::new(Arc::new(MemOpener), Limits::default(), usize::MAX);
        let store = Store::open(conn, pool).map_err(|e| Error::new("state", e))?;
        let concurrency = 4;
        let engine = build_engine(PoolSize { concurrency }).map_err(|e| Error::new("engine", e))?;
        let code = Arc::new(
            CodeStore::new(engine, options.code_cache).map_err(|e| Error::new("code store", e))?,
        );
        let mut log = LogConfig::new(PathBuf::from("/log"), "main");
        // The group commit window is a clock sleep, which would wait for the
        // test to advance time.
        log.group_commit_window = Duration::ZERO;
        let secrets_conn =
            rusqlite::Connection::open_in_memory().map_err(|e| Error::new("secrets", e))?;
        let secrets = SecretStore::open(secrets_conn, &MasterKey::from_bytes([7; 32]))
            .map_err(|e| Error::new("secrets", e))?;
        let node = Node::start(NodeParts {
            env,
            config: NodeConfig {
                concurrency: concurrency as usize,
                ..NodeConfig::default()
            },
            log,
            store,
            code,
            secrets: Some(Arc::new(secrets)),
            sealer: None,
        })
        .await
        .map_err(|e| Error::new("starting the node", e))?;
        Ok(TestHost {
            gateway: Gateway::new(node.clone(), GatewayConfig::default()),
            api: Api::new(node.clone()),
            node,
            clock,
            net,
        })
    }

    /// An HTTP request through the gateway, as a client would send it.
    pub async fn http(&self, req: HttpRequest) -> HttpResponse {
        self.gateway.handle(req).await
    }

    /// A request to the API, as `kronik` would send it over the socket.
    pub async fn api(&self, method: &str, path: &str, query: &str, body: Vec<u8>) -> ApiResponse {
        self.api
            .handle(ApiRequest {
                method: method.to_string(),
                path: path.to_string(),
                query: query.to_string(),
                body,
                token_id: "test-host".to_string(),
                bearer: None,
            })
            .await
    }

    /// The wall clock, in ms since the Unix epoch.
    pub fn now_ms(&self) -> u64 {
        self.clock.wall_ms()
    }

    /// Moves the clock forward by `d`, then waits until the timers that came
    /// due have fired and everything they started has finished.
    pub async fn advance(&self, d: Duration) -> Result<(), Error> {
        self.clock.advance(d);
        self.settle().await
    }

    /// Adds a stub for outgoing HTTP.
    pub fn stub(&self, stub: Stub) {
        self.net.stub(stub);
    }

    /// The outgoing requests so far; `clear` forgets them.
    pub fn requests(&self, clear: bool) -> Vec<Recorded> {
        self.net.recorded(clear)
    }

    /// Waits until no message waits for delivery, no turn is open and no
    /// timer is due: until what earlier requests started has finished.
    pub async fn settle(&self) -> Result<(), Error> {
        let mut waited = Duration::ZERO;
        let step = Duration::from_millis(1);
        loop {
            let busy = self.busy()?;
            if busy.is_empty() {
                return Ok(());
            }
            if waited >= SETTLE_LIMIT {
                return Err(Error(format!(
                    "the test host is still busy after {} s: {busy}",
                    SETTLE_LIMIT.as_secs()
                )));
            }
            // Real time passes on a blocking thread: the manual clock stands
            // still.
            let _ = self
                .node
                .env()
                .blocking("test-host-settle", move || std::thread::sleep(step))
                .await;
            waited += step;
        }
    }

    /// What is still going on, or an empty string if nothing is.
    fn busy(&self) -> Result<String, Error> {
        let db = self.node.store().db();
        let mailbox = db.mailbox().map_err(|e| Error::new("mailbox", e))?.len();
        let open = db
            .open_turns()
            .map_err(|e| Error::new("open turns", e))?
            .len();
        let now = self.now_ms();
        let due = db
            .timers(None)
            .map_err(|e| Error::new("timers", e))?
            .iter()
            .filter(|t| t.due_ms <= now)
            .count();
        if mailbox + open + due == 0 {
            return Ok(String::new());
        }
        Ok(format!(
            "{mailbox} messages to deliver, {open} open turns, {due} timers due"
        ))
    }
}

/// Entropy from a seed: blake3 in keyed XOF mode over a counter.
struct SeededEntropy {
    key: [u8; 32],
    counter: Mutex<u64>,
}

impl EntropySource for SeededEntropy {
    fn fill(&self, buf: &mut [u8]) {
        let n = {
            let mut c = self.counter.lock().unwrap_or_else(PoisonError::into_inner);
            *c += 1;
            *c
        };
        let mut hasher = blake3::Hasher::new_keyed(&self.key);
        hasher.update(&n.to_le_bytes());
        hasher.finalize_xof().fill(buf);
    }
}

/// A test host starts no processes.
struct NoProcesses;

impl ProcessRunner for NoProcesses {
    fn spawn(&self, spec: ProcessSpec) -> BoxFuture<'static, std::io::Result<Arc<dyn Process>>> {
        let e = std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "the test host does not start processes ({})",
                spec.program.display()
            ),
        );
        Box::pin(std::future::ready(Err(e)))
    }
}
