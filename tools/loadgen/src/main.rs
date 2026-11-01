//! HTTP/1.1 load generator for Kronik's performance measurements (docs/perf.md).
//! No dependencies: one keep-alive TCP connection and fixed-size histogram per worker.
//!
//! loadgen --addr 127.0.0.1:47812 --path '/counter/k{key}/increment' \
//!         --keys 256 --concurrency 64 --seconds 10 [--rate 200] [--warmup 2]
//!
//! Closed loop sends back to back. Open loop schedules `--rate` requests/second
//! across workers and measures latency from scheduled time, including queueing.
//! At the wall-clock cutoff no new requests start; unsent measurement slots count
//! as errors, not omitted samples. An in-flight request may finish after cutoff.
//! `seconds` is requested duration; `elapsed_seconds` includes this drain and is
//! the throughput denominator. Warmup successes are excluded; warmup failures
//! still count as errors. Quantiles include only successful measurement requests.
//!
//! Quantiles use nearest rank and round UP to a nanosecond histogram bucket's
//! upper bound: exact below 64 ns, at most 3.125% high thereafter (32 buckets per
//! power of two). Max is exact. Memory does not grow with sample count.
//!
//! `{key}` cycles over worker-strided keys. `--header 'name: value'` adds a header,
//! optionally only to even keys with `--header-half`; `--body B` sends a body.
//! Both support `{key}` substitution. Existing JSON metric keys are preserved.
//! Addresses must be numeric IP:port (no unbounded DNS). Each complete request
//! has a 5 s deadline, response headers a 16 KiB cap, and bodies a 16 MiB cap.
//! Responses require Content-Length unless HEAD/204/304; transfer encodings and
//! interim responses are rejected rather than risking keep-alive desynchronization.
//! Any request, framing, missed schedule, or worker failure makes exit status 1.

use std::fmt::Write as _;
use std::io::{self, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const HEADER_CAP: usize = 16 * 1024;
const BODY_CAP: u64 = 16 * 1024 * 1024;
const HISTOGRAM_BUCKETS: usize = 32 + 59 * 32;

struct Args {
    addr: SocketAddr,
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

fn parse(args: impl IntoIterator<Item = String>) -> Result<Args, String> {
    let mut a = Args {
        addr: SocketAddr::from(([127, 0, 0, 1], 47812)),
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
    let mut args = args.into_iter();
    while let Some(flag) = args.next() {
        if flag == "--header-half" {
            a.header_half = true;
            continue;
        }
        let v = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
        let num = || v.parse::<f64>().map_err(|_| format!("bad number {v}"));
        let count = || {
            v.parse::<usize>()
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| format!("{flag} requires a positive integer"))
        };
        match flag.as_str() {
            "--addr" => {
                a.addr = v.parse().map_err(|_| "addr requires numeric IP:port")?;
            }
            "--path" => a.path = v,
            "--method" => a.method = v,
            "--keys" => a.keys = count()?,
            "--concurrency" => a.concurrency = count()?,
            "--seconds" => a.seconds = num()?,
            "--warmup" => a.warmup = num()?,
            "--rate" => a.rate = Some(num()?),
            "--header" => a.header = Some(v),
            "--body" => a.body = v,
            other => return Err(format!("unknown flag {other}")),
        }
    }
    for (name, value, allow_zero) in [("seconds", a.seconds, false), ("warmup", a.warmup, true)] {
        if !value.is_finite() || value < 0.0 || (!allow_zero && value == 0.0) {
            return Err(format!(
                "{name} requires a finite {}number",
                if allow_zero {
                    "nonnegative "
                } else {
                    "positive "
                }
            ));
        }
        let duration =
            Duration::try_from_secs_f64(value).map_err(|_| format!("{name} is out of range"))?;
        if !allow_zero && duration.is_zero() {
            return Err(format!("{name} is below clock resolution"));
        }
    }
    if let Some(rate) = a.rate {
        if !rate.is_finite() || rate <= 0.0 {
            return Err("rate requires a finite positive number".into());
        }
        if Duration::try_from_secs_f64(a.concurrency as f64 / rate)
            .map_err(|_| "rate interval is out of range")?
            .is_zero()
        {
            return Err("rate interval is below clock resolution".into());
        }
    }
    let now = Instant::now();
    now.checked_add(Duration::from_secs_f64(a.warmup))
        .and_then(|t| t.checked_add(Duration::from_secs_f64(a.seconds)))
        .and_then(|t| t.checked_add(REQUEST_TIMEOUT))
        .ok_or("measurement duration is out of range")?;
    Ok(a)
}

struct DeadlineStream {
    stream: TcpStream,
    deadline: Instant,
}

impl DeadlineStream {
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "request deadline exceeded"))
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(buf)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

struct Conn {
    addr: SocketAddr,
    stream: Option<BufReader<DeadlineStream>>,
}

impl Conn {
    fn request(
        &mut self,
        method: &str,
        path: &str,
        header: Option<&str>,
        body: &str,
    ) -> Result<u16, String> {
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        if self.stream.is_none() {
            let stream = TcpStream::connect_timeout(&self.addr, REQUEST_TIMEOUT)
                .map_err(|e| e.to_string())?;
            stream.set_nodelay(true).map_err(|e| e.to_string())?;
            self.stream = Some(BufReader::new(DeadlineStream { stream, deadline }));
        }
        let res = self.exchange(method, path, header, body, deadline);
        match res {
            Ok((status, close)) => {
                if close {
                    self.stream = None;
                }
                Ok(status)
            }
            Err(e) => {
                self.stream = None;
                Err(e)
            }
        }
    }

    fn exchange(
        &mut self,
        method: &str,
        path: &str,
        header: Option<&str>,
        body: &str,
        deadline: Instant,
    ) -> Result<(u16, bool), String> {
        let r = self.stream.as_mut().ok_or("not connected")?;
        r.get_mut().deadline = deadline;
        let w = r.get_mut();
        write!(w, "{method} {path} HTTP/1.1\r\nhost: kronik\r\n").map_err(|e| e.to_string())?;
        if let Some(header) = header {
            write!(w, "{header}\r\n").map_err(|e| e.to_string())?;
        }
        write!(w, "content-length: {}\r\n\r\n{body}", body.len()).map_err(|e| e.to_string())?;
        let result = response(r, method == "HEAD")?;
        r.get_mut().remaining().map_err(|e| e.to_string())?;
        Ok(result)
    }
}

fn response(r: &mut impl Read, head: bool) -> Result<(u16, bool), String> {
    let mut headers = [0u8; HEADER_CAP];
    let mut used = 0;
    loop {
        if used == headers.len() {
            return Err("response headers exceed 16 KiB".into());
        }
        r.read_exact(&mut headers[used..used + 1])
            .map_err(|e| e.to_string())?;
        used += 1;
        if headers[..used].ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = std::str::from_utf8(&headers[..used]).map_err(|_| "non-UTF8 headers")?;
    let mut lines = text.split("\r\n");
    let mut status_line = lines.next().ok_or("missing status")?.split_whitespace();
    let version = status_line.next().ok_or("missing HTTP version")?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err("unsupported HTTP version".into());
    }
    let code = status_line.next().ok_or("missing status code")?;
    let status: u16 = code.parse().map_err(|_| "bad status code")?;
    if code.len() != 3 || !(200..600).contains(&status) {
        return Err("unsupported status code (interim responses are not supported)".into());
    }
    let mut len = None;
    let mut close = version == "HTTP/1.0";
    for line in lines.take_while(|line| !line.is_empty()) {
        let (key, value) = line.split_once(':').ok_or("malformed header")?;
        if key.eq_ignore_ascii_case("transfer-encoding") {
            return Err("transfer-encoding is not supported".into());
        }
        if key.eq_ignore_ascii_case("content-length") {
            let value = value.trim();
            if len.is_some() || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err("invalid or duplicate content-length".into());
            }
            let size: u64 = value.parse().map_err(|_| "bad content-length")?;
            if size > BODY_CAP {
                return Err("response body exceeds 16 MiB".into());
            }
            len = Some(size);
        }
        if key.eq_ignore_ascii_case("connection")
            && value
                .split(',')
                .any(|v| v.trim().eq_ignore_ascii_case("close"))
        {
            close = true;
        }
    }
    let mut remaining = if head || status == 204 || status == 304 {
        0
    } else {
        len.ok_or("missing content-length")?
    };
    let mut scratch = [0u8; 8192];
    while remaining > 0 {
        let take = remaining.min(scratch.len() as u64) as usize;
        r.read_exact(&mut scratch[..take])
            .map_err(|e| e.to_string())?;
        remaining -= take as u64;
    }
    Ok((status, close))
}

struct Histogram {
    buckets: [u64; HISTOGRAM_BUCKETS],
    count: u64,
    max_ns: u64,
}

impl Default for Histogram {
    fn default() -> Self {
        Self {
            buckets: [0; HISTOGRAM_BUCKETS],
            count: 0,
            max_ns: 0,
        }
    }
}

impl Histogram {
    fn record(&mut self, ns: u64) {
        let index = if ns < 32 {
            ns as usize
        } else {
            let shift = 63 - ns.leading_zeros() - 5;
            32 + shift as usize * 32 + ((ns >> shift) - 32) as usize
        };
        self.buckets[index] += 1;
        self.count += 1;
        self.max_ns = self.max_ns.max(ns);
    }

    fn merge(&mut self, other: &Self) {
        for (a, b) in self.buckets.iter_mut().zip(&other.buckets) {
            *a += b;
        }
        self.count += other.count;
        self.max_ns = self.max_ns.max(other.max_ns);
    }

    fn quantile_ns(&self, percent: u64) -> u64 {
        let rank = (self.count as u128 * percent as u128).div_ceil(100);
        if rank == 0 {
            return 0;
        }
        let mut count = 0u128;
        for (index, n) in self.buckets.iter().enumerate() {
            count += *n as u128;
            if count >= rank {
                if index < 32 {
                    return index as u64;
                }
                let shift = (index - 32) / 32;
                let slot = (index - 32) % 32;
                return (((33 + slot) as u128) << shift)
                    .saturating_sub(1)
                    .min(u64::MAX as u128) as u64;
            }
        }
        self.max_ns
    }
}

#[derive(Default)]
struct Stats {
    latencies: Histogram,
    ok: u64,
    errors: u64,
    first_error: Option<String>,
}

impl Stats {
    fn error(&mut self, count: u64, error: impl FnOnce() -> String) {
        self.errors += count;
        self.first_error.get_or_insert_with(error);
    }

    fn merge(&mut self, other: Self) {
        self.ok += other.ok;
        self.errors += other.errors;
        self.latencies.merge(&other.latencies);
        if self.first_error.is_none() {
            self.first_error = other.first_error;
        }
    }
}

fn missed_slots(next: Instant, from: Instant, end: Instant, interval: Duration) -> u64 {
    if next >= end {
        return 0;
    }
    let step = interval.as_nanos();
    let skip = from
        .saturating_duration_since(next)
        .as_nanos()
        .div_ceil(step);
    let total = end.duration_since(next).as_nanos().div_ceil(step);
    total.saturating_sub(skip).min(u64::MAX as u128) as u64
}

enum KeyTemplate<'a> {
    Static(&'a str),
    Dynamic {
        parts: Vec<&'a str>,
        rendered: String,
    },
}

impl<'a> KeyTemplate<'a> {
    fn new(template: &'a str) -> Self {
        let slots = template.matches("{key}").count();
        if slots == 0 {
            return Self::Static(template);
        }
        let mut parts = Vec::with_capacity(slots + 1);
        parts.extend(template.split("{key}"));
        let max_digits = usize::MAX.ilog10() as usize + 1;
        Self::Dynamic {
            parts,
            rendered: String::with_capacity(template.len() + slots * (max_digits - 5)),
        }
    }

    fn needs_key(&self) -> bool {
        matches!(self, Self::Dynamic { .. })
    }

    fn render(&mut self, key: &str) -> &str {
        match self {
            Self::Static(template) => template,
            Self::Dynamic { parts, rendered } => {
                rendered.clear();
                rendered.push_str(parts[0]);
                for part in &parts[1..] {
                    rendered.push_str(key);
                    rendered.push_str(part);
                }
                rendered
            }
        }
    }
}

fn worker(a: &Args, w: usize, start: Instant, measure_from: Instant, end: Instant) -> Stats {
    let mut conn = Conn {
        addr: a.addr,
        stream: None,
    };
    let mut local = Stats::default();
    let interval = a
        .rate
        .map(|r| Duration::from_secs_f64(a.concurrency as f64 / r));
    let mut next = start
        .checked_add(interval.map_or(Duration::ZERO, |i| {
            i.mul_f64(w as f64 / a.concurrency as f64)
        }))
        .unwrap_or(end);
    let mut key = w % a.keys;
    let key_step = a.concurrency % a.keys;
    let key_wrap = a.keys - key_step;
    let mut path_template = KeyTemplate::new(&a.path);
    let mut body_template = KeyTemplate::new(&a.body);
    let mut header_template = a.header.as_deref().map(KeyTemplate::new);
    let needs_key = path_template.needs_key()
        || body_template.needs_key()
        || header_template.as_ref().is_some_and(KeyTemplate::needs_key);
    let mut key_text = String::with_capacity(if needs_key {
        usize::MAX.ilog10() as usize + 1
    } else {
        0
    });
    loop {
        let now = Instant::now();
        if now >= end {
            if let Some(i) = interval {
                let missed = missed_slots(next, measure_from, end, i);
                if missed > 0 {
                    local.error(missed, || "open-loop requests not sent before cutoff".into());
                }
            }
            break;
        }
        let scheduled = if let Some(i) = interval {
            if next >= end {
                std::thread::sleep(end - now);
                continue;
            }
            if next > now {
                std::thread::sleep(next - now);
                continue;
            }
            let scheduled = next;
            // A next slot beyond Instant's range is necessarily beyond this run.
            next = next.checked_add(i).unwrap_or(end);
            scheduled
        } else {
            now
        };
        if needs_key {
            key_text.clear();
            let _ = write!(key_text, "{key}");
        }
        let path = path_template.render(&key_text);
        let body = body_template.render(&key_text);
        let header = if a.header_half && !key.is_multiple_of(2) {
            None
        } else {
            header_template.as_mut().map(|template| template.render(&key_text))
        };
        if Instant::now() >= end {
            if interval.is_some() && scheduled >= measure_from {
                local.error(1, || "open-loop request not sent before cutoff".into());
            }
            continue;
        }
        let res = conn.request(&a.method, path, header, body);
        let done = Instant::now();
        key = if key >= key_wrap {
            key - key_wrap
        } else {
            key + key_step
        };
        match res {
            Ok(s) if (200..300).contains(&s) => {
                if scheduled >= measure_from {
                    local.ok += 1;
                    local
                        .latencies
                        .record((done - scheduled).as_nanos().min(u64::MAX as u128) as u64);
                }
            }
            Ok(s) => local.error(1, || format!("HTTP {s}")),
            Err(e) => local.error(1, || e),
        }
    }
    local
}

fn json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c <= '\u{1f}' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn main() {
    let a = match parse(std::env::args().skip(1)) {
        Ok(a) => Arc::new(a),
        Err(e) => {
            eprintln!("loadgen: {e}");
            std::process::exit(2);
        }
    };
    let start = Instant::now();
    let measure_from = start + Duration::from_secs_f64(a.warmup);
    let end = measure_from + Duration::from_secs_f64(a.seconds);
    let mut handles = Vec::new();
    let mut g = Stats::default();
    for w in 0..a.concurrency {
        let a = a.clone();
        match std::thread::Builder::new().spawn(move || worker(&a, w, start, measure_from, end)) {
            Ok(handle) => handles.push(handle),
            Err(e) => {
                g.error(1, || format!("worker spawn failed: {e}"));
                break;
            }
        }
    }
    for h in handles {
        match h.join() {
            Ok(local) => g.merge(local),
            Err(_) => g.error(1, || "worker panicked".into()),
        }
    }
    let elapsed = Instant::now()
        .saturating_duration_since(measure_from)
        .as_secs_f64();
    if g.ok == 0 {
        g.error(1, || "no successful measured requests".into());
    }
    let ms = |ns: u64| ns as f64 / 1_000_000.0;
    println!(
        "{{\"keys\":{},\"concurrency\":{},\"rate\":{},\"seconds\":{},\"elapsed_seconds\":{},\
         \"ok\":{},\"errors\":{},\"rps\":{:.3},\"p50_ms\":{:.6},\"p90_ms\":{:.6},\
         \"p99_ms\":{:.6},\"max_ms\":{:.6},\"first_error\":{}}}",
        a.keys,
        a.concurrency,
        a.rate.map_or("null".to_string(), |r| format!("{r}")),
        a.seconds,
        elapsed,
        g.ok,
        g.errors,
        if elapsed > 0.0 {
            g.ok as f64 / elapsed
        } else {
            0.0
        },
        ms(g.latencies.quantile_ns(50)),
        ms(g.latencies.quantile_ns(90)),
        ms(g.latencies.quantile_ns(99)),
        ms(g.latencies.max_ns),
        g.first_error
            .as_ref()
            .map_or("null".to_string(), |e| json_string(e)),
    );
    if g.errors > 0 {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn all_failures_count_and_preserve_the_first_cause() {
        let mut stats = Stats::default();
        stats.error(2, || "first cause".to_owned());
        stats.error(3, || "second cause".to_owned());
        assert_eq!(stats.errors, 5);
        assert_eq!(stats.first_error.as_deref(), Some("first cause"));
    }

    #[test]
    fn key_rendering_replaces_every_slot_and_clears_the_previous_tail() {
        let mut template = KeyTemplate::new("/counter/{key}/increment?echo={key}");
        assert_eq!(template.render("42"), "/counter/42/increment?echo=42");
        let max_key = usize::MAX.to_string();
        assert_eq!(
            template.render(&max_key),
            format!("/counter/{max_key}/increment?echo={max_key}")
        );
        assert_eq!(template.render("0"), "/counter/0/increment?echo=0");
    }

    #[test]
    fn histogram_bounds_and_merge() {
        let mut left = Histogram::default();
        let mut right = Histogram::default();
        let mut samples = vec![0, 1, 31, 32, 63, 64, 65, u64::MAX];
        for shift in 6..63 {
            samples.extend([(1u64 << shift) - 1, 1u64 << shift, (1u64 << shift) + 1]);
        }
        for (i, &ns) in samples.iter().enumerate() {
            let mut single = Histogram::default();
            single.record(ns);
            let upper = single.quantile_ns(99);
            assert!(upper >= ns);
            assert!((upper as u128 - ns as u128) * 32 <= ns as u128);
            if i % 2 == 0 {
                left.record(ns);
            } else {
                right.record(ns);
            }
        }
        left.merge(&right);
        samples.sort_unstable();
        assert_eq!(left.count, samples.len() as u64);
        assert_eq!(left.max_ns, u64::MAX);
        for percent in [50, 90, 99, 100] {
            let exact = samples[(samples.len() * percent as usize).div_ceil(100) - 1];
            let upper = left.quantile_ns(percent);
            assert!(upper >= exact);
            assert!((upper as u128 - exact as u128) * 32 <= exact as u128);
        }
        assert_eq!(Histogram::default().quantile_ns(99), 0);
    }

    #[test]
    fn response_drains_exactly_one_frame() {
        let mut data = Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcHTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
        assert_eq!(response(&mut data, false), Ok((200, false)));
        assert_eq!(response(&mut data, false), Ok((204, true)));
        let mut head = Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 123\r\n\r\n");
        assert_eq!(response(&mut head, true), Ok((200, false)));
        let body = vec![b'x'; 8193];
        let mut large = b"HTTP/1.1 200 OK\r\nContent-Length: 8193\r\n\r\n".to_vec();
        large.extend(body);
        assert_eq!(response(&mut Cursor::new(large), false), Ok((200, false)));
    }

    #[test]
    fn response_refuses_bad_or_unbounded_framing() {
        for raw in [
            "HTTP/1.1 200 OK\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabc",
            "HTTP/1.1 200 OK\r\nContent-Length: 16777217\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551616\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: +1\r\n\r\nx",
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n",
            "HTTP/1.1 100 Continue\r\n\r\n",
        ] {
            assert!(response(&mut Cursor::new(raw), false).is_err(), "{raw:?}");
        }
        let mut oversized = b"HTTP/1.1 200 OK\r\nx: ".to_vec();
        oversized.resize(HEADER_CAP + 1, b'x');
        assert!(response(&mut Cursor::new(oversized), false).is_err());
    }

    #[test]
    fn invalid_settings_are_not_coerced() {
        for (flag, values) in [
            ("--keys", vec!["0", "-1", "1.5", "NaN", "inf"]),
            ("--concurrency", vec!["0", "-1", "2.1", "1e300"]),
            (
                "--seconds",
                vec!["0", "-1", "NaN", "inf", "1e300", "1e-300"],
            ),
            ("--warmup", vec!["-1", "NaN", "inf", "1e300"]),
            ("--rate", vec!["0", "-1", "NaN", "inf", "1e300", "1e-300"]),
        ] {
            for value in values {
                assert!(
                    parse([flag.into(), value.into()]).is_err(),
                    "{flag} {value}"
                );
            }
        }
        let a = parse(
            [
                "--keys",
                "7",
                "--concurrency",
                "3",
                "--seconds",
                "0.125",
                "--warmup",
                "0",
                "--rate",
                "2.5",
            ]
            .map(String::from),
        )
        .unwrap();
        assert_eq!(
            (a.keys, a.concurrency, a.seconds, a.warmup, a.rate),
            (7, 3, 0.125, 0.0, Some(2.5))
        );
    }

    #[test]
    fn cutoff_counts_only_unsent_measurement_slots() {
        let start = Instant::now();
        let from = start + Duration::from_millis(125);
        let end = start + Duration::from_millis(500);
        let interval = Duration::from_millis(100);
        assert_eq!(missed_slots(start, from, end, interval), 3);
        assert_eq!(
            missed_slots(start + Duration::from_millis(300), from, end, interval),
            2
        );
        assert_eq!(missed_slots(end, from, end, interval), 0);
        assert_eq!(json_string("bad\u{1b}\"\\\n"), "\"bad\\u001b\\\"\\\\\\n\"");
    }
}
