//! A small HTTP/1.1 server that plays the foreign actor in spike C.
//!
//! Usage: echo-server [--listen ADDR]... [--listen-unix PATH]...
//!
//! Routes:
//!
//! ```text
//! GET  /healthz                 200 "ok"
//! *    /echo                    echoes the request body
//! GET  /info                    identity, limits and rootfs checks, as text
//! GET  /exit?code=N             answers, then exits with status N
//! GET  /burn?threads=T&ms=M     keeps T threads busy for M milliseconds
//! GET  /alloc?mb=N              allocates and touches N MiB, then frees it
//! ```

use std::fs;
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::thread;
use std::time::{Duration, Instant};

use spike_c_gvisor::http::{self, Request};

fn main() {
    let mut tcp = Vec::new();
    let mut unix = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match (arg.as_str(), args.next()) {
            ("--listen", Some(addr)) => tcp.push(addr),
            ("--listen-unix", Some(path)) => unix.push(path),
            _ => {
                eprintln!("usage: echo-server [--listen ADDR]... [--listen-unix PATH]...");
                std::process::exit(2);
            }
        }
    }
    if tcp.is_empty() && unix.is_empty() {
        tcp.push("0.0.0.0:8080".into());
    }
    let mut handles = Vec::new();
    for addr in tcp {
        let listener =
            TcpListener::bind(&addr).unwrap_or_else(|e| fail(&format!("bind {addr}: {e}")));
        println!("echo-server: listening on tcp {addr}");
        handles.push(thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let _ = stream.set_nodelay(true);
                thread::spawn(move || {
                    if let Ok(read) = stream.try_clone() {
                        serve(read, stream);
                    }
                });
            }
        }));
    }
    for path in unix {
        let _ = fs::remove_file(&path);
        let listener =
            UnixListener::bind(&path).unwrap_or_else(|e| fail(&format!("bind {path}: {e}")));
        println!("echo-server: listening on unix {path}");
        handles.push(thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                thread::spawn(move || {
                    if let Ok(read) = stream.try_clone() {
                        serve(read, stream);
                    }
                });
            }
        }));
    }
    for handle in handles {
        let _ = handle.join();
    }
}

fn fail(msg: &str) -> ! {
    eprintln!("echo-server: {msg}");
    std::process::exit(1);
}

fn serve(read: impl Read, write: impl Write) {
    let mut reader = BufReader::new(read);
    let mut writer = BufWriter::new(write);
    loop {
        let request = match http::read_request(&mut reader) {
            Ok(Some(r)) => r,
            Ok(None) => return,
            Err(e) => {
                let _ =
                    http::write_response(&mut writer, 400, &[], e.to_string().as_bytes(), false);
                return;
            }
        };
        let keep_alive = request.keep_alive;
        let (status, body) = route(&request);
        let written = http::write_response(
            &mut writer,
            status,
            &[("x-method", request.method.clone())],
            &body,
            keep_alive,
        );
        if request.path() == "/exit" {
            let code = request
                .query("code")
                .and_then(|c| c.parse().ok())
                .unwrap_or(0);
            println!("echo-server: exiting with status {code} as requested");
            std::process::exit(code);
        }
        if written.is_err() || !keep_alive {
            return;
        }
    }
}

fn route(request: &Request) -> (u16, Vec<u8>) {
    let num = |key: &str, default: u64| {
        request
            .query(key)
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(default)
    };
    match request.path() {
        "/healthz" => (200, b"ok\n".to_vec()),
        "/echo" => (200, request.body.clone()),
        "/info" => (200, info().into_bytes()),
        "/exit" => (200, b"exiting\n".to_vec()),
        "/burn" => {
            let threads = num("threads", 1);
            let ms = num("ms", 1000);
            let start = Instant::now();
            let workers: Vec<_> = (0..threads)
                .map(|_| {
                    thread::spawn(move || {
                        let deadline = Instant::now() + Duration::from_millis(ms);
                        let mut x: u64 = 0;
                        while Instant::now() < deadline {
                            x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
                        }
                        x
                    })
                })
                .collect();
            for w in workers {
                let _ = w.join();
            }
            let body = format!(
                "burned {threads} threads for {ms} ms in {:?}\n",
                start.elapsed()
            );
            (200, body.into_bytes())
        }
        "/alloc" => {
            let mb = num("mb", 64) as usize;
            let start = Instant::now();
            let mut block = vec![0u8; mb << 20];
            for i in (0..block.len()).step_by(4096) {
                block[i] = 1;
            }
            let touched = block.iter().step_by(4096).filter(|b| **b == 1).count();
            drop(block);
            let body = format!(
                "allocated and touched {mb} MiB ({touched} pages) in {:?}\n",
                start.elapsed()
            );
            (200, body.into_bytes())
        }
        _ => (404, b"not found\n".to_vec()),
    }
}

fn info() -> String {
    let read = |p: &str| fs::read_to_string(p).unwrap_or_else(|e| format!("<{e}>"));
    let status = read("/proc/self/status");
    let field = |name: &str| {
        status
            .lines()
            .find(|l| l.starts_with(name))
            .map(|l| l.split_whitespace().skip(1).collect::<Vec<_>>().join(" "))
            .unwrap_or_default()
    };
    let mut srv_old: Vec<String> = fs::read_dir("/srv/old")
        .map(|d| {
            d.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    srv_old.sort();
    let meminfo = read("/proc/meminfo");
    format!(
        "pid={}\nuid={}\ngid={}\ncwd={}\nhostname={}\ngreeting={}\navailable_parallelism={}\n{}\netc_stale_conf_exists={}\nsrv_old={:?}\n",
        std::process::id(),
        field("Uid:"),
        field("Gid:"),
        std::env::current_dir()
            .map(|d| d.display().to_string())
            .unwrap_or_default(),
        read("/proc/sys/kernel/hostname").trim(),
        std::env::var("GREETING").unwrap_or_default(),
        thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0),
        meminfo.lines().next().unwrap_or_default(),
        fs::symlink_metadata("/etc/stale.conf").is_ok(),
        srv_old,
    )
}
