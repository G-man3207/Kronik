//! Measures HTTP request latency through a bridge into the sandbox.
//!
//! Usage:
//!   bridge-bench bench --target TARGET [--mode keepalive|newconn]
//!                      [--requests N] [--warmup N] [--body BYTES] [--label NAME]
//!   bridge-bench ready --target TARGET [--timeout-ms MS] [--since-ns UNIX_NS]
//!   bridge-bench get   --target TARGET --path PATH
//!
//! TARGET is `tcp:HOST:PORT`, `unix:PATH`, or `pfstream:RUNSC_ROOT:ID:PORT`.
//! For `pfstream` every connection is one `runsc port-forward --stream`
//! process: the bench listens on a temporary Unix socket, runsc connects to
//! it and forwards that one connection to PORT in container ID.
//!
//! `bench` sends POST /echo requests sequentially and prints percentiles in
//! microseconds. In `newconn` mode every request opens a new connection and
//! the connect time is included. `ready` polls GET /healthz every millisecond
//! and prints how long it took until the first 200, counted from `--since-ns`
//! (a `date +%s%N` timestamp) or from its own start.

use std::collections::HashMap;
use std::io::{self, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use spike_c_gvisor::http;

enum Conn {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Conn::Tcp(s) => s.read(buf),
            Conn::Unix(s) => s.read(buf),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Conn::Tcp(s) => s.write(buf),
            Conn::Unix(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A request that takes longer than this fails instead of hanging.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

fn connect(target: &str) -> io::Result<BufReader<Conn>> {
    let conn = if let Some(addr) = target.strip_prefix("tcp:") {
        let s = TcpStream::connect(addr)?;
        s.set_nodelay(true)?;
        s.set_read_timeout(Some(IO_TIMEOUT))?;
        s.set_write_timeout(Some(IO_TIMEOUT))?;
        Conn::Tcp(s)
    } else {
        let s = if let Some(path) = target.strip_prefix("unix:") {
            UnixStream::connect(path)?
        } else if let Some(spec) = target.strip_prefix("pfstream:") {
            port_forward_stream(spec)?
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "target must be tcp:ADDR, unix:PATH or pfstream:ROOT:ID:PORT",
            ));
        };
        s.set_read_timeout(Some(IO_TIMEOUT))?;
        s.set_write_timeout(Some(IO_TIMEOUT))?;
        Conn::Unix(s)
    };
    Ok(BufReader::new(conn))
}

/// Opens one connection to PORT in a container through
/// `runsc port-forward --stream`.
fn port_forward_stream(spec: &str) -> io::Result<UnixStream> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut parts = spec.rsplitn(3, ':');
    let (Some(port), Some(id), Some(root)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pfstream:ROOT:ID:PORT",
        ));
    };
    let path = std::env::temp_dir().join(format!(
        "bridge-bench-{}-{}.sock",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    listener.set_nonblocking(true)?;
    let mut child = Command::new("runsc")
        .args(["--root", root, "port-forward", "--stream"])
        .arg(&path)
        .args([id, port])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let accepted = loop {
        match listener.accept() {
            Ok((stream, _)) => break Ok(stream),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() > deadline || child.try_wait()?.is_some() {
                    break Err(io::Error::other(
                        "runsc port-forward --stream did not connect",
                    ));
                }
                thread::sleep(Duration::from_micros(100));
            }
            Err(e) => break Err(e),
        }
    };
    let _ = std::fs::remove_file(&path);
    // The runsc process exits when the forwarded connection closes.
    thread::spawn(move || child.wait());
    let stream = accepted?;
    stream.set_nonblocking(false)?;
    Ok(stream)
}

fn exchange(
    conn: &mut BufReader<Conn>,
    method: &str,
    path: &str,
    body: &[u8],
    keep_alive: bool,
) -> io::Result<http::Response> {
    http::write_request(conn.get_mut(), method, path, body, keep_alive)?;
    http::read_response(conn)
}

fn main() {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_default();
    let mut opts: HashMap<String, String> = HashMap::new();
    while let (Some(k), Some(v)) = (args.next(), args.next()) {
        opts.insert(k.trim_start_matches("--").to_string(), v);
    }
    let opt = |k: &str, d: &str| opts.get(k).cloned().unwrap_or_else(|| d.to_string());
    let target = opt("target", "");
    let result = match command.as_str() {
        "bench" => bench(
            &target,
            &opt("mode", "keepalive"),
            opt("requests", "1000").parse().unwrap_or(1000),
            opt("warmup", "100").parse().unwrap_or(100),
            opt("body", "64").parse().unwrap_or(64),
            &opt("label", "bench"),
        ),
        "ready" => ready(
            &target,
            opt("timeout-ms", "30000").parse().unwrap_or(30000),
            opts.get("since-ns").and_then(|s| s.parse().ok()),
        ),
        "get" => get(&target, &opt("path", "/healthz")),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "command must be bench, ready or get",
        )),
    };
    if let Err(e) = result {
        eprintln!("bridge-bench: {e}");
        std::process::exit(1);
    }
}

fn bench(
    target: &str,
    mode: &str,
    requests: usize,
    warmup: usize,
    body_len: usize,
    label: &str,
) -> io::Result<()> {
    let body = vec![b'k'; body_len];
    let keepalive = match mode {
        "keepalive" => true,
        "newconn" => false,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "mode must be keepalive or newconn",
            ));
        }
    };
    let mut conn = if keepalive {
        Some(connect(target)?)
    } else {
        None
    };
    let mut samples = Vec::with_capacity(requests);
    let mut errors = 0;
    for i in 0..warmup + requests {
        let start = Instant::now();
        let outcome = if keepalive {
            let c = conn
                .as_mut()
                .ok_or_else(|| io::Error::other("no connection"))?;
            exchange(c, "POST", "/echo", &body, true)
        } else {
            connect(target).and_then(|mut c| exchange(&mut c, "POST", "/echo", &body, false))
        };
        let elapsed = start.elapsed();
        match outcome {
            Ok(r) if r.status == 200 && r.body == body => {
                if i >= warmup {
                    samples.push(elapsed);
                }
            }
            _ => {
                errors += 1;
                if keepalive {
                    conn = Some(connect(target)?);
                }
            }
        }
    }
    samples.sort();
    let n = samples.len();
    if n == 0 {
        return Err(io::Error::other(format!("all {errors} requests failed")));
    }
    let pct = |q: f64| samples[((q * n as f64).ceil() as usize).clamp(1, n) - 1].as_micros();
    let mean = samples.iter().map(|d| d.as_micros()).sum::<u128>() / n as u128;
    println!(
        "label={label} target={target} mode={mode} n={n} errors={errors} body={body_len}B min_us={} p50_us={} p90_us={} p99_us={} p999_us={} max_us={} mean_us={mean}",
        samples[0].as_micros(),
        pct(0.50),
        pct(0.90),
        pct(0.99),
        pct(0.999),
        samples[n - 1].as_micros(),
    );
    Ok(())
}

fn ready(target: &str, timeout_ms: u64, since_ns: Option<u128>) -> io::Result<()> {
    let start_ns = since_ns.unwrap_or_else(now_ns);
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let mut attempts = 0;
    loop {
        attempts += 1;
        if let Ok(r) =
            connect(target).and_then(|mut c| exchange(&mut c, "GET", "/healthz", b"", false))
            && r.status == 200
        {
            let ms = (now_ns() - start_ns) as f64 / 1e6;
            println!("ready_ms={ms:.1} attempts={attempts} target={target}");
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(io::Error::other(format!(
                "{target} not ready after {timeout_ms} ms"
            )));
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn get(target: &str, path: &str) -> io::Result<()> {
    let mut conn = connect(target)?;
    let response = exchange(&mut conn, "GET", path, b"", false)?;
    println!("status={}", response.status);
    io::stdout().write_all(&response.body)
}

fn now_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
