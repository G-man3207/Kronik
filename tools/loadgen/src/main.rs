//! HTTP/1.1 load generator for Kronik's performance measurements
//! (docs/perf.md). No dependencies: std threads, one keep-alive TCP
//! connection per worker.
//!
//! Closed loop (throughput): `--concurrency C` workers send back to back.
//! Open loop (latency): `--rate R` schedules R requests per second across
//! the workers; latency is measured from the scheduled send time, so a slow
//! server cannot hide queueing (no coordinated omission).
//!
//! loadgen --addr 127.0.0.1:47812 --path '/counter/k{key}/increment' \
//!         --keys 256 --concurrency 64 --seconds 10 [--rate 200] [--warmup 2]
//!
//! `{key}` is replaced by a key in 0..keys: worker `w` uses keys
//! w, w + C, w + 2C, ... in turn, so with keys >= C no two workers share an
//! actor. Prints one JSON line.
//!
//! `--header 'name: value'` adds a header (`{key}` replaced) to every request,
//! or with `--header-half` only to requests for even keys; `--body B` sends
//! B (`{key}` replaced) as the body (privacy-mode overhead, docs/perf.md).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct Args {
    addr: String,
    path: String,
    method: String,
    keys: usize,
    concurrency: usize,
    seconds: f64,
    warmup: f64,
    rate: Option<f64>,
    header: Option<String>,
    header_half: bool,
    body: String,
}

fn parse() -> Result<Args, String> {
    let mut a = Args {
        addr: "127.0.0.1:47812".into(),
        path: "/counter/k{key}/increment".into(),
        method: "POST".into(),
        keys: 1,
        concurrency: 1,
        seconds: 10.0,
        warmup: 1.0,
        rate: None,
        header: None,
        header_half: false,
        body: String::new(),
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--header-half" {
            a.header_half = true;
            i += 1;
            continue;
        }
        let v = args
            .get(i + 1)
            .cloned()
            .ok_or(format!("{} needs a value", args[i]))?;
        let num = |s: &str| s.parse::<f64>().map_err(|_| format!("bad number {s}"));
        match args[i].as_str() {
            "--addr" => a.addr = v,
            "--path" => a.path = v,
            "--method" => a.method = v,
            "--keys" => a.keys = num(&v)? as usize,
            "--concurrency" => a.concurrency = num(&v)? as usize,
            "--seconds" => a.seconds = num(&v)?,
            "--warmup" => a.warmup = num(&v)?,
            "--rate" => a.rate = Some(num(&v)?),
            "--header" => a.header = Some(v),
            "--body" => a.body = v,
            other => return Err(format!("unknown flag {other}")),
        }
        i += 2;
    }
    a.keys = a.keys.max(1);
    a.concurrency = a.concurrency.max(1);
    Ok(a)
}

struct Conn {
    addr: String,
    stream: Option<(TcpStream, BufReader<TcpStream>)>,
}

impl Conn {
    fn request(
        &mut self,
        method: &str,
        path: &str,
        header: Option<&str>,
        body: &str,
    ) -> Result<u16, String> {
        if self.stream.is_none() {
            let s = TcpStream::connect(&self.addr).map_err(|e| e.to_string())?;
            s.set_nodelay(true).map_err(|e| e.to_string())?;
            let r = BufReader::new(s.try_clone().map_err(|e| e.to_string())?);
            self.stream = Some((s, r));
        }
        let res = self.exchange(method, path, header, body);
        if res.is_err() {
            self.stream = None;
        }
        res
    }

    fn exchange(
        &mut self,
        method: &str,
        path: &str,
        header: Option<&str>,
        body: &str,
    ) -> Result<u16, String> {
        let Some((w, r)) = self.stream.as_mut() else {
            return Err("not connected".into());
        };
        let extra = header.map_or(String::new(), |h| format!("{h}\r\n"));
        write!(
            w,
            "{method} {path} HTTP/1.1\r\nhost: kronik\r\n{extra}content-length: {}\r\n\r\n{body}",
            body.len()
        )
        .map_err(|e| e.to_string())?;
        let mut line = String::new();
        r.read_line(&mut line).map_err(|e| e.to_string())?;
        let status: u16 = line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or(format!("bad status line {line:?}"))?;
        let mut len = 0usize;
        loop {
            line.clear();
            r.read_line(&mut line).map_err(|e| e.to_string())?;
            let l = line.trim_end();
            if l.is_empty() {
                break;
            }
            if let Some((k, v)) = l.split_once(':')
                && k.eq_ignore_ascii_case("content-length")
            {
                len = v.trim().parse().map_err(|_| "bad content-length")?;
            }
        }
        let mut body = vec![0; len];
        r.read_exact(&mut body).map_err(|e| e.to_string())?;
        Ok(status)
    }
}

#[derive(Default)]
struct Stats {
    latencies_us: Vec<u64>,
    ok: u64,
    errors: u64,
    first_error: Option<String>,
}

fn pct(sorted: &[u64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let i = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[i] as f64 / 1000.0
}

fn main() {
    let a = match parse() {
        Ok(a) => Arc::new(a),
        Err(e) => {
            eprintln!("loadgen: {e}");
            std::process::exit(2);
        }
    };
    let stats = Arc::new(Mutex::new(Stats::default()));
    let stop = Arc::new(AtomicBool::new(false));
    let start = Instant::now();
    let measure_from = start + Duration::from_secs_f64(a.warmup);
    let end = measure_from + Duration::from_secs_f64(a.seconds);
    let mut handles = Vec::new();
    for w in 0..a.concurrency {
        let (a, stats, stop) = (a.clone(), stats.clone(), stop.clone());
        handles.push(std::thread::spawn(move || {
            let mut conn = Conn {
                addr: a.addr.clone(),
                stream: None,
            };
            let mut local = Stats::default();
            let interval = a
                .rate
                .map(|r| Duration::from_secs_f64(a.concurrency as f64 / r));
            // Spread open-loop workers evenly over one interval.
            let mut next = start
                + interval.map_or(Duration::ZERO, |i| {
                    i.mul_f64(w as f64 / a.concurrency as f64)
                });
            let mut n = 0usize;
            while !stop.load(Ordering::Relaxed) {
                let scheduled = match interval {
                    Some(i) => {
                        let now = Instant::now();
                        if next > now {
                            std::thread::sleep(next - now);
                        }
                        let s = next;
                        next += i;
                        s
                    }
                    None => Instant::now(),
                };
                if scheduled >= end {
                    break;
                }
                let key = (w + n * a.concurrency) % a.keys;
                n += 1;
                let path = a.path.replace("{key}", &key.to_string());
                let header = a
                    .header
                    .as_ref()
                    .filter(|_| !a.header_half || key.is_multiple_of(2))
                    .map(|h| h.replace("{key}", &key.to_string()));
                let body = a.body.replace("{key}", &key.to_string());
                let res = conn.request(&a.method, &path, header.as_deref(), &body);
                let done = Instant::now();
                if scheduled < measure_from {
                    continue;
                }
                match res {
                    Ok(s) if (200..300).contains(&s) => {
                        local.ok += 1;
                        local
                            .latencies_us
                            .push((done - scheduled).as_micros() as u64);
                    }
                    Ok(s) => {
                        local.errors += 1;
                        local.first_error.get_or_insert(format!("HTTP {s}"));
                    }
                    Err(e) => {
                        local.errors += 1;
                        local.first_error.get_or_insert(e);
                    }
                }
            }
            let mut g = stats.lock().unwrap_or_else(|e| e.into_inner());
            g.ok += local.ok;
            g.errors += local.errors;
            g.latencies_us.extend(local.latencies_us);
            if g.first_error.is_none() {
                g.first_error = local.first_error;
            }
        }));
    }
    let now = Instant::now();
    if end > now {
        std::thread::sleep(end - now);
    }
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.join();
    }
    let mut g = stats.lock().unwrap_or_else(|e| e.into_inner());
    g.latencies_us.sort_unstable();
    let l = &g.latencies_us;
    println!(
        "{{\"keys\":{},\"concurrency\":{},\"rate\":{},\"seconds\":{},\"ok\":{},\"errors\":{},\
         \"rps\":{:.0},\"p50_ms\":{:.2},\"p90_ms\":{:.2},\"p99_ms\":{:.2},\"max_ms\":{:.2},\
         \"first_error\":{}}}",
        a.keys,
        a.concurrency,
        a.rate.map_or("null".to_string(), |r| format!("{r}")),
        a.seconds,
        g.ok,
        g.errors,
        g.ok as f64 / a.seconds,
        pct(l, 0.50),
        pct(l, 0.90),
        pct(l, 0.99),
        pct(l, 1.0),
        g.first_error
            .as_ref()
            .map_or("null".to_string(), |e| format!("{e:?}"))
    );
}
