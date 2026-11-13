//! `loadgen chat`: WebSocket chat clients against the `chat-ts` example
//! (examples/chat-ts), for M24's acceptance (docs/design/m24-connections.md
//! section 18).
//!
//! loadgen chat --addr 127.0.0.1:47812 --clients 1000 --rooms 50 --ramp 20 \
//!              --interval 10 --seconds 600 [--drain 10] [--reconnect]
//!
//! Client i joins room `<prefix><i mod rooms>` as user `u<i>`. The clients
//! connect evenly spread over `ramp` seconds, and each waits for its
//! `welcome`. After `settle` more seconds the steady phase starts: every
//! client sends a `say` every `interval` seconds (±20 % jitter, a random
//! first offset) for `seconds` seconds, then keeps reading for `drain`
//! seconds and closes with 1000.
//!
//! The protocol (examples/chat-ts): the first frame is `{"type":"welcome",
//! "last":N, ...}`, where N is the room's last message sequence number; a
//! client sends `{"type":"say","text":T,"id":I}`; every member, the sender
//! included, receives `{"type":"message","seq":S,"id":I, ...}`; and
//! `GET /chat/<room>/messages?after=S` returns `{"messages":[...]}`.
//! Other frames (`joined`, `left`, `token`) are ignored.
//!
//! Every client checks that the sequence numbers it receives on one
//! connection are consecutive (a jump is a gap, a repeat a duplicate). Every
//! message id carries the run, the sender and the send time, so a recipient
//! measures the end-to-end latency on one clock, and a sender counts its own
//! messages coming back. At the end, every member of a room must have
//! received every message of its room: without `--reconnect`, all the
//! messages the room's clients sent; with it, everything up to the highest
//! sequence any member saw.
//!
//! `--reconnect`: a connection the server closes, or that breaks, is opened
//! again with jittered backoff (0.5 s doubling to 30 s). The client then
//! fetches what it missed, from its last sequence up to the new welcome's
//! `last`, through `GET .../messages?after=`. Sends that come due while a
//! client is disconnected are skipped. Messages a client sent but never saw
//! come back are reported as `unacknowledged`, not as a failure: the brief
//! says incoming frames that were not committed are not acknowledged.
//! Without `--reconnect`, any close by the server fails the run.
//!
//! Prints one JSON object. Exit status 1 when a client failed to connect,
//! saw a gap, a duplicate or an unexpected close, missed a message of its
//! room, or did not get its own messages back (without `--reconnect`).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::json::Json;
use crate::ws::{Client, Message, Rng};
use crate::{Histogram, json_string};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);
const BACKOFF_FIRST: Duration = Duration::from_millis(500);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
const RESYNC_CAP: u64 = 16 << 20;
/// Per client thread: the stacks of 1,000 clients stay small.
const STACK: usize = 256 * 1024;

#[derive(Clone, Debug)]
pub struct ChatArgs {
    pub addr: SocketAddr,
    /// The `Host` header; the address by default.
    pub host: String,
    /// The `Origin` header; `http://<host>` by default.
    pub origin: Option<String>,
    pub clients: usize,
    pub rooms: usize,
    pub prefix: String,
    pub ramp: Duration,
    pub settle: Duration,
    pub interval: Duration,
    pub seconds: Duration,
    pub drain: Duration,
    /// The size of each message's text.
    pub bytes: usize,
    /// The WebSocket path, with `{room}` and `{user}`.
    pub path: String,
    /// The resync path, with `{room}` and `{after}`.
    pub messages: String,
    pub reconnect: bool,
    pub seed: u64,
}

pub fn parse(args: impl IntoIterator<Item = String>) -> Result<ChatArgs, String> {
    let mut a = ChatArgs {
        addr: SocketAddr::from(([127, 0, 0, 1], 47812)),
        host: String::new(),
        origin: None,
        clients: 10,
        rooms: 1,
        prefix: "r".into(),
        ramp: Duration::from_secs(1),
        settle: Duration::from_secs(2),
        interval: Duration::from_secs(1),
        seconds: Duration::from_secs(10),
        drain: Duration::from_secs(5),
        bytes: 64,
        path: "/chat/{room}/ws?user={user}".into(),
        messages: "/chat/{room}/messages?after={after}&limit=1000".into(),
        reconnect: false,
        seed: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(1, |d| d.as_nanos() as u64),
    };
    let mut origin = None;
    let mut no_origin = false;
    let mut args = args.into_iter();
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--reconnect" => {
                a.reconnect = true;
                continue;
            }
            "--no-origin" => {
                no_origin = true;
                continue;
            }
            _ => {}
        }
        let v = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
        let count = || {
            v.parse::<usize>()
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| format!("{flag} requires a positive integer"))
        };
        let secs = |positive: bool| {
            let n: f64 = v.parse().map_err(|_| format!("bad number {v}"))?;
            if !n.is_finite() || n < 0.0 || (positive && n == 0.0) {
                return Err(format!(
                    "{flag} requires a finite {}number",
                    if positive {
                        "positive "
                    } else {
                        "nonnegative "
                    }
                ));
            }
            let d =
                Duration::try_from_secs_f64(n).map_err(|_| format!("{flag} is out of range"))?;
            if d > Duration::from_secs(7 * 24 * 3600) || (positive && d.is_zero()) {
                return Err(format!("{flag} is out of range"));
            }
            Ok(d)
        };
        match flag.as_str() {
            "--addr" => a.addr = v.parse().map_err(|_| "addr requires numeric IP:port")?,
            "--host" => a.host = v,
            "--origin" => origin = Some(v),
            "--clients" => a.clients = count()?,
            "--rooms" => a.rooms = count()?,
            "--prefix" => a.prefix = v,
            "--ramp" => a.ramp = secs(false)?,
            "--settle" => a.settle = secs(false)?,
            "--interval" => a.interval = secs(true)?,
            "--seconds" => a.seconds = secs(true)?,
            "--drain" => a.drain = secs(false)?,
            "--bytes" => a.bytes = count()?,
            "--path" => a.path = v,
            "--messages" => a.messages = v,
            "--seed" => a.seed = v.parse().map_err(|_| "seed requires an integer")?,
            other => return Err(format!("unknown flag {other}")),
        }
    }
    if a.rooms > a.clients {
        return Err("rooms must not exceed clients".into());
    }
    if a.bytes > 64 * 1024 {
        return Err("bytes must be at most 65536".into());
    }
    if !a.path.contains("{room}") || !a.messages.contains("{after}") {
        return Err("path needs {room}, messages needs {after}".into());
    }
    if a.host.is_empty() {
        a.host = a.addr.to_string();
    }
    a.origin = match (no_origin, origin) {
        (true, _) => None,
        (false, Some(o)) => Some(o),
        (false, None) => Some(format!("http://{}", a.host)),
    };
    Ok(a)
}

/// What one client saw.
#[derive(Default)]
struct ClientReport {
    room: usize,
    /// The first welcome arrived.
    connected: bool,
    /// Connected when the close phase began.
    connected_at_end: bool,
    /// The first welcome's `last`.
    base: u64,
    /// The last room sequence accounted for.
    last: u64,
    sent: u64,
    skipped: u64,
    echoed: u64,
    received: u64,
    resynced: u64,
    gaps: u64,
    duplicates: u64,
    unexpected_closes: u64,
    closes: BTreeMap<u16, u64>,
    reasons: BTreeMap<u16, String>,
    reconnects: u64,
    reconnect_max: Duration,
    connect: Option<Duration>,
    latencies: Histogram,
    errors: u64,
    first_error: Option<String>,
}

impl ClientReport {
    fn error(&mut self, e: impl Into<String>) {
        self.errors += 1;
        if self.first_error.is_none() {
            self.first_error = Some(e.into());
        }
    }
}

/// `<run>.<client>.<n>.<sent µs>`: the run, the sender and when it sent.
fn parse_id(id: &str) -> Option<(u32, usize, u64)> {
    let mut parts = id.split('.');
    let run = u32::from_str_radix(parts.next()?, 16).ok()?;
    let client = parts.next()?.parse().ok()?;
    let _n: u64 = parts.next()?.parse().ok()?;
    let sent_us = parts.next()?.parse().ok()?;
    parts.next().is_none().then_some((run, client, sent_us))
}

struct Session<'a> {
    a: &'a ChatArgs,
    index: usize,
    room_key: String,
    run: u32,
    t0: Instant,
    rng: Rng,
    conn: Option<Client>,
    /// The next room sequence expected.
    next: u64,
    n: u64,
    text: String,
    down_since: Option<Instant>,
    /// When to try to reconnect next, and the backoff before that try.
    retry_at: Option<Instant>,
    backoff: Duration,
    r: ClientReport,
}

impl Session<'_> {
    fn user(&self) -> String {
        format!("u{}", self.index)
    }

    /// Opens a connection and waits for its welcome: its `last`.
    fn connect(&mut self) -> Result<u64, String> {
        let path = self
            .a
            .path
            .replace("{room}", &self.room_key)
            .replace("{user}", &self.user());
        let seed = self.rng.next_u64();
        let mut conn = Client::connect(
            self.a.addr,
            &self.a.host,
            &path,
            self.a.origin.as_deref(),
            CONNECT_TIMEOUT,
            Rng::new(seed),
        )
        .map_err(|e| e.to_string())?;
        let deadline = Instant::now() + CONNECT_TIMEOUT;
        loop {
            match conn.read(deadline)? {
                Some(Message::Text(text)) => {
                    let v = Json::parse(&text).map_err(|e| format!("frame is not JSON: {e}"))?;
                    match v.get("type").and_then(Json::as_str) {
                        Some("welcome") => {
                            let last = v
                                .get("last")
                                .and_then(Json::as_u64)
                                .ok_or("welcome without last")?;
                            self.conn = Some(conn);
                            return Ok(last);
                        }
                        Some("message") => return Err("a message before the welcome".into()),
                        _ => {}
                    }
                }
                Some(Message::Binary(_)) => return Err("binary frame from the chat server".into()),
                Some(Message::Close(code, reason)) => {
                    return Err(format!("closed before the welcome: {code} {reason}"));
                }
                None => return Err("no welcome within 10 s".into()),
            }
        }
    }

    fn send(&mut self) {
        let Some(conn) = self.conn.as_mut() else {
            self.r.skipped += 1;
            return;
        };
        self.n += 1;
        let sent_us = self.t0.elapsed().as_micros() as u64;
        let id = format!("{:08x}.{}.{}.{sent_us}", self.run, self.index, self.n);
        let frame = format!(
            "{{\"type\":\"say\",\"text\":{},\"id\":\"{id}\"}}",
            json_string(&self.text)
        );
        match conn.send_text(&frame) {
            Ok(()) => self.r.sent += 1,
            Err(e) => self.dropped(1006, e),
        }
    }

    fn on_text(&mut self, text: &str) {
        let v = match Json::parse(text) {
            Ok(v) => v,
            Err(e) => return self.r.error(format!("frame is not JSON: {e}")),
        };
        match v.get("type").and_then(Json::as_str) {
            Some("message") => match v.get("seq").and_then(Json::as_u64) {
                Some(seq) => self.account(seq, v.get("id").and_then(Json::as_str), true),
                None => self.r.error("message without seq"),
            },
            Some("welcome") => self.r.error("a second welcome on one connection"),
            _ => {}
        }
    }

    /// One room message, from a live frame or a resync.
    fn account(&mut self, seq: u64, id: Option<&str>, live: bool) {
        if seq < self.next {
            if live {
                self.r.duplicates += 1;
            }
            return;
        }
        self.r.gaps += seq - self.next;
        self.next = seq + 1;
        self.r.last = seq;
        self.r.received += 1;
        if !live {
            self.r.resynced += 1;
        }
        if let Some((run, client, sent_us)) = id.and_then(parse_id)
            && run == self.run
        {
            if client == self.index {
                self.r.echoed += 1;
            }
            if live {
                let now_us = self.t0.elapsed().as_micros() as u64;
                self.r
                    .latencies
                    .record(now_us.saturating_sub(sent_us).saturating_mul(1000));
            }
        }
    }

    /// The connection ended: by a close frame from the server, or broken
    /// (recorded as 1006).
    fn dropped(&mut self, code: u16, reason: String) {
        if let Some(mut conn) = self.conn.take()
            && code != 1006
        {
            // Answer the close, as the protocol asks.
            let _ = conn.send_close(if code == 1005 { 1000 } else { code }, "");
        }
        *self.r.closes.entry(code).or_default() += 1;
        self.r.reasons.entry(code).or_insert(reason.clone());
        let now = Instant::now();
        self.down_since = Some(now);
        self.backoff = BACKOFF_FIRST;
        self.retry_at = Some(now + self.backoff.mul_f64(0.5 + self.rng.unit()));
        if !self.a.reconnect {
            self.r.unexpected_closes += 1;
            self.r
                .error(format!("the server ended the connection: {code} {reason}"));
        }
    }

    /// Fetches the messages after `next - 1` up to `upto`.
    fn resync(&mut self, upto: u64) -> Result<(), String> {
        if upto + 1 < self.next {
            return Err(format!(
                "the room went back from sequence {} to {upto}",
                self.next - 1
            ));
        }
        while self.next <= upto {
            let path = self
                .a
                .messages
                .replace("{room}", &self.room_key)
                .replace("{after}", &(self.next - 1).to_string());
            let (status, body) = http_get(self.a.addr, &self.a.host, &path, CONNECT_TIMEOUT)?;
            if status != 200 {
                return Err(format!("resync answered HTTP {status}"));
            }
            let text = String::from_utf8(body).map_err(|_| "resync body is not UTF-8")?;
            let v = Json::parse(&text).map_err(|e| format!("resync body is not JSON: {e}"))?;
            let messages = v
                .get("messages")
                .and_then(Json::as_array)
                .ok_or("resync body without a messages array")?;
            let before = self.next;
            for m in messages {
                let seq = m
                    .get("seq")
                    .and_then(Json::as_u64)
                    .ok_or("resync message without seq")?;
                if seq > upto {
                    break;
                }
                self.account(seq, m.get("id").and_then(Json::as_str), false);
            }
            if self.next == before {
                break;
            }
        }
        if self.next <= upto {
            self.r.gaps += upto + 1 - self.next;
            self.next = upto + 1;
            self.r.last = upto;
        }
        Ok(())
    }

    fn run(mut self) -> ClientReport {
        let a = self.a;
        let connect_at = self.t0 + a.ramp.mul_f64(self.index as f64 / a.clients as f64);
        sleep_until(connect_at);
        let steady = self.t0 + a.ramp + a.settle;
        let stop = steady + a.seconds;
        let end = stop + a.drain;
        let started = Instant::now();
        match self.connect() {
            Ok(last) => {
                self.r.connected = true;
                self.r.connect = Some(started.elapsed());
                self.r.base = last;
                self.r.last = last;
                self.next = last + 1;
            }
            Err(e) => {
                self.r.error(format!("u{}: {e}", self.index));
                return self.r;
            }
        }
        if Instant::now() > steady {
            self.r
                .error("connected after the steady phase began: raise --ramp or --settle");
        }
        let mut next_send = steady + a.interval.mul_f64(self.rng.unit());
        let mut reconnect_error = None;
        loop {
            let now = Instant::now();
            if now >= end {
                break;
            }
            if next_send < stop && now >= next_send {
                self.send();
                next_send += a.interval.mul_f64(0.8 + 0.4 * self.rng.unit());
                continue;
            }
            let wake = if next_send < stop {
                next_send.min(end)
            } else {
                end
            };
            let Some(conn) = self.conn.as_mut() else {
                if !a.reconnect {
                    break;
                }
                let at = self.retry_at.unwrap_or(now);
                if now < at {
                    sleep_until(at.min(wake));
                    continue;
                }
                match self.connect() {
                    Ok(last) => {
                        if let Some(since) = self.down_since.take() {
                            self.r.reconnect_max = self.r.reconnect_max.max(since.elapsed());
                        }
                        self.r.reconnects += 1;
                        self.retry_at = None;
                        reconnect_error = None;
                        if let Err(e) = self.resync(last) {
                            self.r.error(format!("resync: {e}"));
                        }
                    }
                    Err(e) => {
                        reconnect_error = Some(e);
                        self.backoff = (self.backoff * 2).min(BACKOFF_MAX);
                        self.retry_at =
                            Some(Instant::now() + self.backoff.mul_f64(0.5 + self.rng.unit()));
                    }
                }
                continue;
            };
            match conn.read(wake) {
                Ok(None) => {}
                Ok(Some(Message::Text(text))) => self.on_text(&text),
                Ok(Some(Message::Binary(_))) => self.r.error("binary frame from the chat server"),
                Ok(Some(Message::Close(code, reason))) => self.dropped(code, reason),
                Err(e) => self.dropped(1006, e),
            }
        }
        if let Some(e) = reconnect_error {
            self.r.error(format!("never reconnected: {e}"));
        }
        self.r.connected_at_end = self.conn.is_some();
        if let Some(mut conn) = self.conn.take() {
            match conn.send_close(1000, "done") {
                Ok(()) => {
                    let deadline = Instant::now() + CLOSE_TIMEOUT;
                    loop {
                        match conn.read(deadline) {
                            Ok(Some(Message::Close(..))) => break,
                            Ok(Some(Message::Text(text))) => self.on_text(&text),
                            Ok(Some(Message::Binary(_))) => {}
                            Ok(None) => {
                                self.r.error("no close frame back within 5 s");
                                break;
                            }
                            Err(e) => {
                                self.r.error(format!("closing: {e}"));
                                break;
                            }
                        }
                    }
                }
                Err(e) => self.r.error(format!("closing: {e}")),
            }
        }
        self.r
    }
}

fn sleep_until(t: Instant) {
    let now = Instant::now();
    if t > now {
        std::thread::sleep(t - now);
    }
}

/// One GET with `connection: close`: the status and the body.
fn http_get(
    addr: SocketAddr,
    host: &str,
    path: &str,
    timeout: Duration,
) -> Result<(u16, Vec<u8>), String> {
    let mut s = TcpStream::connect_timeout(&addr, timeout).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(timeout))
        .and_then(|()| s.set_write_timeout(Some(timeout)))
        .map_err(|e| e.to_string())?;
    write!(
        s,
        "GET {path} HTTP/1.1\r\nhost: {host}\r\nconnection: close\r\n\r\n"
    )
    .map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    s.take(RESYNC_CAP)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("no complete response head")?;
    let head = std::str::from_utf8(&raw[..end]).map_err(|_| "non-UTF-8 response head")?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or("malformed status line")?;
    let mut body = raw[end + 4..].to_vec();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("transfer-encoding") {
            return Err("chunked responses are not supported".into());
        }
        if name.trim().eq_ignore_ascii_case("content-length") {
            let len: usize = value.trim().parse().map_err(|_| "bad content-length")?;
            if body.len() < len {
                return Err("response body shorter than its content-length".into());
            }
            body.truncate(len);
        }
    }
    Ok((status, body))
}

/// The whole run: whether it passed, and the JSON line with the details.
pub struct Report {
    pub ok: bool,
    pub json: String,
}

pub fn run(a: &ChatArgs) -> Report {
    let t0 = Instant::now();
    let a = Arc::new(a.clone());
    let mut seeds = Rng::new(a.seed);
    let run = seeds.next_u64() as u32;
    let mut handles = Vec::with_capacity(a.clients);
    let mut failed_spawns = Vec::new();
    for index in 0..a.clients {
        let a = a.clone();
        let seed = seeds.next_u64();
        let spawned = std::thread::Builder::new()
            .name(format!("chat-{index}"))
            .stack_size(STACK)
            .spawn(move || {
                let room = index % a.rooms;
                let text = format!("hello from u{index} ")
                    .chars()
                    .cycle()
                    .take(a.bytes)
                    .collect();
                Session {
                    room_key: format!("{}{room}", a.prefix),
                    a: &a,
                    index,
                    run,
                    t0,
                    rng: Rng::new(seed),
                    conn: None,
                    next: 0,
                    n: 0,
                    text,
                    down_since: None,
                    retry_at: None,
                    backoff: BACKOFF_FIRST,
                    r: ClientReport {
                        room,
                        ..ClientReport::default()
                    },
                }
                .run()
            });
        match spawned {
            Ok(h) => handles.push(h),
            Err(e) => failed_spawns.push(format!("client thread {index}: {e}")),
        }
    }
    let mut reports = Vec::with_capacity(a.clients);
    for h in handles {
        match h.join() {
            Ok(r) => reports.push(r),
            Err(_) => failed_spawns.push("a client thread panicked".into()),
        }
    }
    summarize(&a, &reports, failed_spawns, t0.elapsed())
}

fn summarize(
    a: &ChatArgs,
    reports: &[ClientReport],
    extra: Vec<String>,
    elapsed: Duration,
) -> Report {
    let mut errors = extra.len() as u64;
    let mut first_error = extra.into_iter().next();
    let mut latencies = Histogram::default();
    let mut connect = Histogram::default();
    let mut closes: BTreeMap<u16, u64> = BTreeMap::new();
    let mut reasons: BTreeMap<u16, String> = BTreeMap::new();
    let sum = |f: fn(&ClientReport) -> u64| reports.iter().map(f).sum::<u64>();
    let mut rooms: BTreeMap<usize, (u64, u64, Option<u64>, bool)> = BTreeMap::new();
    for r in reports.iter().filter(|r| r.connected) {
        let room = rooms.entry(r.room).or_insert((0, 0, None, true));
        room.0 += r.sent;
        room.1 = room.1.max(r.last);
        room.3 &= room.2.is_none_or(|b| b == r.base);
        room.2 = Some(r.base);
    }
    let mut expected = 0u64;
    let mut tail_lost = 0u64;
    let mut extra_messages = 0u64;
    for r in reports {
        latencies.merge(&r.latencies);
        if let Some(c) = r.connect {
            connect.record(c.as_nanos().min(u128::from(u64::MAX)) as u64);
        }
        for (code, n) in &r.closes {
            *closes.entry(*code).or_default() += n;
        }
        for (code, reason) in &r.reasons {
            reasons.entry(*code).or_insert_with(|| reason.clone());
        }
        errors += r.errors;
        if first_error.is_none() {
            first_error.clone_from(&r.first_error);
        }
        if !r.connected {
            continue;
        }
        let Some(&(sent, room_last, _, _)) = rooms.get(&r.room) else {
            continue;
        };
        let want = if a.reconnect {
            room_last
        } else {
            r.base + sent
        };
        expected += want.saturating_sub(r.base);
        tail_lost += want.saturating_sub(r.last);
        extra_messages += r.last.saturating_sub(want);
    }
    let unequal_bases = rooms.values().filter(|room| !room.3).count() as u64;
    if unequal_bases > 0 && !a.reconnect {
        errors += unequal_bases;
        first_error.get_or_insert_with(|| {
            "members of one room were welcomed at different sequences: a message arrived during the ramp".into()
        });
    }
    if extra_messages > 0 {
        errors += 1;
        first_error.get_or_insert_with(|| {
            format!("{extra_messages} messages beyond what the room's clients sent")
        });
    }
    let connected = reports.iter().filter(|r| r.connected).count() as u64;
    let connected_at_end = reports.iter().filter(|r| r.connected_at_end).count() as u64;
    let (sent, echoed) = (sum(|r| r.sent), sum(|r| r.echoed));
    let deliveries = sum(|r| r.received);
    let gaps = sum(|r| r.gaps);
    let duplicates = sum(|r| r.duplicates);
    let unexpected = sum(|r| r.unexpected_closes);
    let reconnects = sum(|r| r.reconnects);
    let reconnect_max = reports
        .iter()
        .map(|r| r.reconnect_max)
        .max()
        .unwrap_or_default();
    if latencies.count == 0 && errors == 0 {
        errors += 1;
        first_error = Some("no message was delivered".into());
    }
    let ok = errors == 0
        && gaps == 0
        && duplicates == 0
        && tail_lost == 0
        && unexpected == 0
        && connected == a.clients as u64
        && connected_at_end == a.clients as u64
        && deliveries == expected
        && (a.reconnect || echoed == sent);
    let ms = |ns: u64| ns as f64 / 1_000_000.0;
    let mut codes = String::new();
    for (i, (code, n)) in closes.iter().enumerate() {
        let _ = write!(codes, "{}\"{code}\":{n}", if i > 0 { "," } else { "" });
    }
    let mut why = String::new();
    for (i, (code, reason)) in reasons.iter().enumerate() {
        let _ = write!(
            why,
            "{}\"{code}\":{}",
            if i > 0 { "," } else { "" },
            json_string(reason)
        );
    }
    let json = format!(
        "{{\"mode\":\"chat\",\"clients\":{},\"rooms\":{},\"reconnect\":{},\"interval\":{},\
         \"seconds\":{},\"connected\":{connected},\"connected_at_end\":{connected_at_end},\
         \"connect_p50_ms\":{:.6},\"connect_p99_ms\":{:.6},\"connect_max_ms\":{:.6},\
         \"sent\":{sent},\"skipped\":{},\"echoed\":{echoed},\"unacknowledged\":{},\
         \"deliveries_expected\":{expected},\"deliveries\":{deliveries},\"resynced\":{},\
         \"gaps\":{gaps},\"duplicates\":{duplicates},\"tail_lost\":{tail_lost},\
         \"unexpected_closes\":{unexpected},\"close_codes\":{{{codes}}},\
         \"close_reasons\":{{{why}}},\"reconnects\":{reconnects},\"reconnect_max_ms\":{:.3},\
         \"p50_ms\":{:.6},\"p90_ms\":{:.6},\"p99_ms\":{:.6},\"max_ms\":{:.6},\
         \"elapsed_seconds\":{:.3},\"errors\":{errors},\"first_error\":{},\"ok\":{ok}}}",
        a.clients,
        a.rooms,
        a.reconnect,
        a.interval.as_secs_f64(),
        a.seconds.as_secs_f64(),
        ms(connect.quantile_ns(50)),
        ms(connect.quantile_ns(99)),
        ms(connect.max_ns),
        sum(|r| r.skipped),
        sent.saturating_sub(echoed),
        sum(|r| r.resynced),
        reconnect_max.as_secs_f64() * 1000.0,
        ms(latencies.quantile_ns(50)),
        ms(latencies.quantile_ns(90)),
        ms(latencies.quantile_ns(99)),
        ms(latencies.max_ns),
        elapsed.as_secs_f64(),
        first_error
            .as_deref()
            .map_or("null".to_string(), json_string),
    );
    Report { ok, json }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ws::{accept_key, parse_client_frame, server_frame};
    use std::collections::HashMap;
    use std::net::TcpListener;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Misbehavior the mock server can inject.
    #[derive(Default, Clone, Copy)]
    struct Faults {
        /// Never send this sequence to the room's first member.
        drop: Option<u64>,
        /// Send this sequence twice.
        duplicate: Option<u64>,
    }

    type Writer = Arc<Mutex<TcpStream>>;

    #[derive(Default)]
    struct Room {
        last: u64,
        history: Vec<(u64, String)>,
        members: Vec<(u64, Writer)>,
    }

    type Rooms = Arc<Mutex<HashMap<String, Room>>>;

    /// A chat server with chat-ts's protocol, in threads.
    struct Mock {
        addr: SocketAddr,
        rooms: Rooms,
    }

    /// Ends every connection: with a close frame `code` first, or by
    /// dropping TCP.
    fn kill(rooms: &Rooms, code: Option<u16>) {
        let mut rooms = rooms.lock().unwrap();
        for room in rooms.values_mut() {
            for (_, w) in room.members.drain(..) {
                let mut s = w.lock().unwrap();
                if let Some(code) = code {
                    let mut payload = code.to_be_bytes().to_vec();
                    payload.extend_from_slice(b"kronik: restart");
                    let _ = s.write_all(&server_frame(8, &payload));
                }
                let _ = s.shutdown(std::net::Shutdown::Both);
            }
        }
    }

    impl Mock {
        fn start(faults: Faults) -> Mock {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let rooms: Rooms = Arc::default();
            let ids = Arc::new(AtomicU64::new(1));
            let shared = rooms.clone();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { return };
                    let (rooms, ids) = (shared.clone(), ids.clone());
                    std::thread::spawn(move || serve(stream, &rooms, &ids, faults));
                }
            });
            Mock { addr, rooms }
        }
    }

    fn header<'h>(head: &'h str, name: &str) -> Option<&'h str> {
        head.split("\r\n").find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
        })
    }

    fn broadcast(room: &mut Room, frame: &[u8], skip_first: bool) {
        for (i, (_, w)) in room.members.iter().enumerate() {
            if !(skip_first && i == 0) {
                let _ = w.lock().unwrap().write_all(frame);
            }
        }
    }

    fn serve(mut stream: TcpStream, rooms: &Rooms, ids: &AtomicU64, faults: Faults) {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        };
        let head = String::from_utf8_lossy(&buf[..end]).into_owned();
        buf.drain(..end);
        let target = head.split_whitespace().nth(1).unwrap_or("/").to_owned();
        let (path, query) = target.split_once('?').unwrap_or((&target, ""));
        let parts: Vec<&str> = path.split('/').collect();
        let room_key = parts.get(2).copied().unwrap_or("").to_owned();
        if parts.get(3) == Some(&"messages") {
            let after: u64 = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("after="))
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let rooms = rooms.lock().unwrap();
            let room = rooms.get(&room_key);
            let items: Vec<&str> = room
                .map(|r| {
                    r.history
                        .iter()
                        .filter(|(s, _)| *s > after)
                        .map(|(_, m)| m.as_str())
                        .collect()
                })
                .unwrap_or_default();
            let body = format!(
                "{{\"messages\":[{}],\"last\":{}}}",
                items.join(","),
                room.map_or(0, |r| r.last)
            );
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
                body.len()
            );
            return;
        }
        let Some(key) = header(&head, "sec-websocket-key") else {
            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n");
            return;
        };
        let _ = write!(
            stream,
            "HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\n\
             sec-websocket-accept: {}\r\n\r\n",
            accept_key(key)
        );
        let writer: Writer = Arc::new(Mutex::new(stream.try_clone().unwrap()));
        let me = ids.fetch_add(1, Ordering::Relaxed);
        {
            let mut rooms = rooms.lock().unwrap();
            let room = rooms.entry(room_key.clone()).or_default();
            let welcome = format!(
                "{{\"type\":\"welcome\",\"members\":[],\"last\":{}}}",
                room.last
            );
            let _ = writer
                .lock()
                .unwrap()
                .write_all(&server_frame(1, welcome.as_bytes()));
            room.members.push((me, writer.clone()));
        }
        let leave = |rooms: &Rooms| {
            if let Some(room) = rooms.lock().unwrap().get_mut(&room_key) {
                room.members.retain(|(id, _)| *id != me);
            }
        };
        loop {
            while let Some((opcode, payload, used)) = parse_client_frame(&buf) {
                buf.drain(..used);
                match opcode {
                    1 => {
                        let v = Json::parse(std::str::from_utf8(&payload).unwrap()).unwrap();
                        if v.get("type").and_then(Json::as_str) != Some("say") {
                            continue;
                        }
                        let id = v.get("id").and_then(Json::as_str).unwrap_or("").to_owned();
                        let mut rooms = rooms.lock().unwrap();
                        let room = rooms.entry(room_key.clone()).or_default();
                        room.last += 1;
                        let seq = room.last;
                        let msg = format!(
                            "{{\"type\":\"message\",\"seq\":{seq},\"user\":\"x\",\"text\":\"t\",\"ts\":0,\"id\":{}}}",
                            json_string(&id)
                        );
                        room.history.push((seq, msg.clone()));
                        let frame = server_frame(1, msg.as_bytes());
                        broadcast(room, &frame, faults.drop == Some(seq));
                        if faults.duplicate == Some(seq) {
                            broadcast(room, &frame, false);
                        }
                    }
                    8 => {
                        let _ = writer
                            .lock()
                            .unwrap()
                            .write_all(&server_frame(8, &1000u16.to_be_bytes()));
                        leave(rooms);
                        return;
                    }
                    9 => {
                        let _ = writer
                            .lock()
                            .unwrap()
                            .write_all(&server_frame(10, &payload));
                    }
                    _ => {}
                }
            }
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => {
                    leave(rooms);
                    return;
                }
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    }

    fn args(addr: SocketAddr, extra: &[&str]) -> ChatArgs {
        let mut v: Vec<String> = [
            "--addr",
            &addr.to_string(),
            "--clients",
            "6",
            "--rooms",
            "2",
            "--ramp",
            "0.1",
            "--settle",
            "0.3",
            "--interval",
            "0.05",
            "--seconds",
            "1",
            "--drain",
            "0.5",
            "--seed",
            "7",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        v.extend(extra.iter().map(|s| s.to_string()));
        parse(v).unwrap()
    }

    /// The report's JSON, and a counter from it.
    fn counters(report: &Report) -> (Json, impl Fn(&str) -> u64) {
        let json = Json::parse(&report.json).unwrap();
        let j = json.clone();
        (json, move |name: &str| {
            j.get(name)
                .and_then(Json::as_u64)
                .unwrap_or_else(|| panic!("no counter {name}"))
        })
    }

    #[test]
    fn every_member_gets_every_message_of_its_room_once() {
        let mock = Mock::start(Faults::default());
        let report = run(&args(mock.addr, &[]));
        assert!(report.ok, "{}", report.json);
        let (json, n) = counters(&report);
        assert_eq!(json.get("ok"), Some(&Json::Bool(true)));
        assert_eq!(n("connected"), 6);
        assert!(n("sent") > 0);
        assert_eq!(n("echoed"), n("sent"));
        // Three members per room: each message reaches all three.
        assert_eq!(n("deliveries"), 3 * n("sent"));
        assert_eq!(n("deliveries"), n("deliveries_expected"));
        assert_eq!(n("gaps") + n("duplicates") + n("tail_lost"), 0);
    }

    #[test]
    fn a_frame_the_server_drops_is_a_gap() {
        let mock = Mock::start(Faults {
            drop: Some(3),
            ..Faults::default()
        });
        let report = run(&args(mock.addr, &[]));
        assert!(!report.ok);
        let (_, n) = counters(&report);
        // Seq 3 exists in both rooms and is missed by each room's first member.
        assert_eq!(n("gaps"), 2, "{}", report.json);
        assert_eq!(n("deliveries") + 2, n("deliveries_expected"));
    }

    #[test]
    fn a_frame_the_server_sends_twice_is_a_duplicate() {
        let mock = Mock::start(Faults {
            duplicate: Some(2),
            ..Faults::default()
        });
        let report = run(&args(mock.addr, &[]));
        assert!(!report.ok);
        let (_, n) = counters(&report);
        assert_eq!(n("duplicates"), 6, "{}", report.json);
        assert_eq!(n("gaps"), 0);
    }

    #[test]
    fn without_reconnect_a_server_close_fails_the_run() {
        let mock = Mock::start(Faults::default());
        let rooms = mock.rooms.clone();
        let killer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(800));
            kill(&rooms, Some(1012));
        });
        let report = run(&args(mock.addr, &[]));
        killer.join().unwrap();
        assert!(!report.ok);
        let (json, n) = counters(&report);
        assert_eq!(n("unexpected_closes"), 6, "{}", report.json);
        let codes = json.get("close_codes").unwrap();
        assert_eq!(codes.get("1012").and_then(Json::as_u64), Some(6));
    }

    #[test]
    fn reconnecting_clients_resync_what_they_missed() {
        let mock = Mock::start(Faults::default());
        let rooms = mock.rooms.clone();
        let killer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(900));
            kill(&rooms, Some(1012));
            std::thread::sleep(Duration::from_millis(1500));
            kill(&rooms, None);
        });
        let report = run(&args(mock.addr, &["--reconnect", "--seconds", "3.5"]));
        killer.join().unwrap();
        assert!(report.ok, "{}", report.json);
        let (json, n) = counters(&report);
        assert_eq!(n("reconnects"), 12);
        assert_eq!(n("connected_at_end"), 6);
        assert_eq!(n("gaps") + n("duplicates") + n("tail_lost"), 0);
        assert_eq!(n("deliveries"), n("deliveries_expected"));
        let codes = json.get("close_codes").unwrap();
        assert_eq!(codes.get("1012").and_then(Json::as_u64), Some(6));
        assert_eq!(codes.get("1006").and_then(Json::as_u64), Some(6));
        let reasons = json.get("close_reasons").unwrap();
        assert_eq!(
            reasons.get("1012").and_then(Json::as_str),
            Some("kronik: restart")
        );
        // The first retry waits 0.25 to 0.75 s.
        let max = json.get("reconnect_max_ms").and_then(Json::as_f64).unwrap();
        assert!((200.0..3000.0).contains(&max), "{max}");
    }

    /// The acceptance's shape (50 rooms of 20) for a few seconds against the
    /// mock: loadgen's own threads, sockets and accounting at full scale.
    /// Needs about 2,100 open files (both ends are in this process):
    /// `ulimit -n 4096; cargo test --release -- --ignored thousand`.
    #[test]
    #[ignore]
    fn a_thousand_clients_in_fifty_rooms() {
        let mock = Mock::start(Faults::default());
        let a = args(
            mock.addr,
            &[
                "--clients",
                "1000",
                "--rooms",
                "50",
                "--ramp",
                "2",
                "--settle",
                "1",
                "--interval",
                "1",
                "--seconds",
                "5",
                "--drain",
                "2",
            ],
        );
        let report = run(&a);
        assert!(report.ok, "{}", report.json);
        let (_, n) = counters(&report);
        assert_eq!(n("connected"), 1000);
        assert_eq!(n("deliveries"), 20 * n("sent"));
        println!("{}", report.json);
    }

    #[test]
    fn ids_carry_the_run_the_sender_and_the_time() {
        assert_eq!(
            parse_id("0000abcd.17.3.123456"),
            Some((0xabcd, 17, 123_456))
        );
        for bad in ["", "x.1.1.1", "1.2.3", "1.2.3.4.5", "1.-2.3.4"] {
            assert_eq!(parse_id(bad), None, "{bad}");
        }
    }

    #[test]
    fn invalid_settings_are_refused() {
        for bad in [
            &["--clients", "0"][..],
            &["--rooms", "2", "--clients", "1"],
            &["--interval", "0"],
            &["--seconds", "-1"],
            &["--ramp", "NaN"],
            &["--bytes", "70000"],
            &["--path", "/chat/ws"],
            &["--bogus", "1"],
            &["--clients"],
        ] {
            assert!(parse(bad.iter().map(|s| s.to_string())).is_err(), "{bad:?}");
        }
        let a = parse(["--addr", "127.0.0.1:9", "--no-origin"].map(String::from)).unwrap();
        assert_eq!((a.host.as_str(), a.origin), ("127.0.0.1:9", None));
        let a = parse(["--addr", "127.0.0.1:9"].map(String::from)).unwrap();
        assert_eq!(a.origin.as_deref(), Some("http://127.0.0.1:9"));
    }
}
