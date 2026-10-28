//! Spike A guest: a Rust component for the `kronik:actor` world.
//!
//! It deliberately exercises every source of non-determinism a Rust guest can
//! reach without going through Kronik's own interfaces (std clocks, std
//! randomness via `HashMap`'s `RandomState`, stdout/stderr) next to the Kronik
//! host calls, so the host harness can prove that all of them are
//! deterministic functions of (input, seed, logical time, state).
//!
//! The behaviour is selected by the message name (or the HTTP path):
//! - `probe`  : full exercise, replies with a text report
//! - `noop`   : returns `output::none` immediately (per-turn overhead bench)
//! - `spin`   : loops forever (fuel exhaustion)
//! - `alloc`  : allocates `<body>` MiB and touches it (memory limit)
//! - `trap`   : panics (trap, with a message on stderr)
//! - `denied` : calls the effect interfaces that the harness denies
//! - `call`   : `messaging.call`s `spike-a/callee` with `probe` (nested turn)

use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::fmt::Write as _;
use std::hash::BuildHasher;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

wit_bindgen::generate!({
    world: "actor",
    path: "../../../wit/kronik-actor.wit",
});

use exports::kronik::actor::handler::Guest;
use kronik::actor::types::ActorRef;
use kronik::actor::types::{
    HandlerError, HttpBody, HttpResponse, Input, Manifest, Message, Output, Route,
};
use kronik::actor::{context, crypto, http_client, log, messaging, secrets, sql, state};

/// Lives in linear memory. Kronik promises a fresh instance per turn (I3), so
/// this must read 1 after the increment in every turn.
static TURNS_IN_THIS_INSTANCE: AtomicU32 = AtomicU32::new(0);

struct SpikeGuest;

impl Guest for SpikeGuest {
    fn describe() -> Manifest {
        Manifest {
            kind: "spike-a".to_string(),
            schema_version: 1,
            routes: vec![Route {
                method: "POST".to_string(),
                pattern: "/spike/{key}".to_string(),
            }],
            capabilities: vec!["http:example.com".to_string()],
        }
    }

    fn handle(input: Input) -> Result<Output, HandlerError> {
        let (mode, body, is_http) = match &input {
            Input::Message(incoming) => {
                (incoming.msg.name.clone(), incoming.msg.body.clone(), false)
            }
            Input::Http(req) => {
                let body = match &req.body {
                    HttpBody::Inline(bytes) => bytes.clone(),
                    HttpBody::Blob(_) => Vec::new(),
                };
                let mode = req.path.rsplit('/').next().unwrap_or("probe").to_string();
                (mode, body, true)
            }
            Input::Timer(t) => (t.msg.name.clone(), t.msg.body.clone(), false),
            Input::Migrate(_) => ("noop".to_string(), Vec::new(), false),
        };

        let report = match mode.as_str() {
            "noop" => return Ok(Output::None),
            "spin" => spin(),
            "alloc" => alloc(&body),
            "trap" => panic!("deliberate trap requested by input"),
            "denied" => denied(),
            "call" => call(),
            #[cfg(feature = "fs-probe")]
            "read-file" => format!("{:?}\n", std::fs::read_to_string("/etc/hostname")),
            _ => probe(),
        };

        if is_http {
            Ok(Output::Http(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: HttpBody::Inline(report.into_bytes()),
            }))
        } else {
            Ok(Output::Reply(Message {
                name: "report".to_string(),
                content_type: "text/plain".to_string(),
                body: report.into_bytes(),
                blobs: Vec::new(),
            }))
        }
    }
}

fn probe() -> String {
    let mut out = String::new();
    let turns = TURNS_IN_THIS_INSTANCE.fetch_add(1, Ordering::SeqCst) + 1;
    let _ = writeln!(out, "static_counter={turns}");

    // Kronik state: read-modify-write of a counter.
    let n = state::get("n")
        .and_then(|v| String::from_utf8(v).ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
        + 1;
    state::set("n", n.to_string().as_bytes());
    let _ = writeln!(out, "state.n={n}");
    let _ = writeln!(out, "state.keys={:?}", state::keys(""));

    // Kronik context.
    let me = context::self_ref();
    let _ = writeln!(out, "self={}/{}", me.kind, me.key);
    let _ = writeln!(out, "causal_id={}", context::causal_id());
    let _ = writeln!(out, "now_ms={}", context::now_ms());
    let _ = writeln!(out, "random_bytes={}", hex(&context::random_bytes(16)));

    // std-level WASI clocks: wasi:clocks/wall-clock and monotonic-clock.
    let sys_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let _ = writeln!(out, "std_system_time_ms={sys_ms}");
    let t0 = Instant::now();
    let mut acc = 0u64;
    for i in 0..10_000u64 {
        acc = acc.wrapping_mul(31).wrapping_add(i);
    }
    let _ = writeln!(out, "busy_acc={acc}");
    let _ = writeln!(out, "std_instant_elapsed_ns={}", t0.elapsed().as_nanos());

    // std-level WASI randomness: RandomState keys come from wasi:random.
    let rs = RandomState::new();
    let _ = writeln!(out, "std_random_state_hash={:016x}", rs.hash_one("kronik"));
    let mut map: HashMap<String, u32> = HashMap::new();
    for i in 0..8 {
        map.insert(format!("k{i}"), i);
    }
    let order: Vec<&str> = map.keys().map(String::as_str).collect();
    let _ = writeln!(out, "std_hashmap_order={}", order.join(","));

    // Floats: NaN canonicalization makes NaN bit patterns deterministic.
    let nan = std::hint::black_box(0.0f64) / std::hint::black_box(0.0f64);
    let _ = writeln!(out, "nan_bits={:016x}", (nan * 1.5).to_bits());

    // stdout/stderr become log events in the host trace.
    println!("hello from guest stdout, n={n}");
    eprintln!("hello from guest stderr");
    log::emit(
        log::Level::Info,
        "probe finished",
        &[("n".to_string(), n.to_string())],
    );
    out
}

fn spin() -> String {
    let mut x = 0u64;
    loop {
        x = std::hint::black_box(x.wrapping_add(1));
    }
}

fn alloc(body: &[u8]) -> String {
    let mib: usize = std::str::from_utf8(body)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(1);
    let mut v = vec![0u8; mib << 20];
    for i in (0..v.len()).step_by(4096) {
        v[i] = (i % 251) as u8;
    }
    let sum: u64 = v.iter().step_by(4096).map(|&b| u64::from(b)).sum();
    format!("allocated_mib={mib} checksum={sum}\n")
}

fn call() -> String {
    let turns = TURNS_IN_THIS_INSTANCE.fetch_add(1, Ordering::SeqCst) + 1;
    let to = ActorRef {
        kind: "spike-a".to_string(),
        key: "callee".to_string(),
    };
    let msg = Message {
        name: "probe".to_string(),
        content_type: "text/plain".to_string(),
        body: Vec::new(),
        blobs: Vec::new(),
    };
    let reply = match messaging::call(&to, &msg, None) {
        Ok(Some(m)) => String::from_utf8_lossy(&m.body).into_owned(),
        other => format!("{other:?}"),
    };
    format!(
        "caller_static_counter={turns}\ncaller_now_ms={}\n--- callee reply ---\n{reply}",
        context::now_ms()
    )
}

fn denied() -> String {
    let mut out = String::new();
    let req = http_client::Request {
        method: "GET".to_string(),
        url: "https://example.com/".to_string(),
        headers: Vec::new(),
        body: HttpBody::Inline(Vec::new()),
    };
    let _ = writeln!(out, "http.fetch={:?}", http_client::fetch(&req).err());
    let _ = writeln!(
        out,
        "crypto.hmac={:?}",
        crypto::hmac_sha256("signing-key", b"data").err()
    );
    let _ = writeln!(
        out,
        "secrets.reveal={:?}",
        secrets::reveal("db-password").err()
    );
    let _ = writeln!(out, "sql.query={:?}", sql::query("SELECT 1", &[]).err());
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

export!(SpikeGuest);
