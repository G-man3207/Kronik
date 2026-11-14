//! The connection hub (M24, docs/design/m24-connections.md §5.2): the live
//! registry of the WebSocket and SSE connections that the gateway holds on
//! this node.
//!
//! The hub sits between the node and the transports. The node hands it a
//! committed turn's buffered operations ([`Hub::deliver`]), after the turn
//! record is fsynced and applied and before the turn's result goes out. A
//! transport's writer pulls the queued frames in outgoing `seq` order
//! ([`Hub::next`]) and reports what it wrote ([`Hub::written`]); its reader
//! admits incoming messages as frame inputs of the connection's owner
//! ([`Hub::incoming`]), at most `inflight_frames` at once and paced to
//! `inbound_rate`, so a slow actor or a fast client stops the reading. A
//! transport that ends reports it ([`Hub::finished`]), and the hub admits
//! the connection's close input, exactly once, with the first cause
//! decided: the actor's close, a host close ([`Hub::close_host`]) or the
//! client's.
//!
//! The hub uses only [`Env`] and `tokio::sync` (ADR 0004), so the simulator
//! drives it as production does. Nothing in it is state: a connection is
//! not guest memory (I3), and after a restart every connection that
//! `state.db` holds open gets a close input from the node's start, not from
//! here (§4.8).

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use kronik_core::env::Env;
use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::ids::ActorRef;
use kronik_proto::connection as conn;
use kronik_proto::log::v1 as pb;
use tokio::sync::{Notify, Semaphore};

use crate::node::Node;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The close code and reason of a graceful stop (§5.9).
pub const RESTART_CODE: u16 = 1012;
pub const RESTART_REASON: &str = "kronik: restart";

/// `[connections]` (§5.11): admission and transport settings. Replay never
/// reads them: it reads the recorded inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionsConfig {
    /// Live connections in total, besides the HTTP connections.
    pub max_open: usize,
    /// Live connections per owner.
    pub max_per_actor: usize,
    /// Live connections per client address; trusted proxies are exempt.
    pub max_per_client: usize,
    /// The largest incoming message (never above the kind's message limit).
    pub max_frame_bytes: usize,
    /// Incoming frames per connection admitted and not yet finished.
    pub inflight_frames: usize,
    /// Incoming frames per second per connection; 0: unpaced.
    pub inbound_rate: u32,
    /// Queued outgoing bytes per connection before a slow-consumer close.
    pub outbound_queue_bytes: usize,
    pub ping_interval: Duration,
    pub ping_timeout: Duration,
    pub sse_heartbeat: Duration,
    /// How long an actor's or the host's close waits for the client's.
    pub close_timeout: Duration,
    /// How long a graceful stop waits for the writers.
    pub shutdown_grace: Duration,
    /// How long an accepted connection waits for its transport (the
    /// WebSocket upgrade, the SSE body) before it closes as `abandoned`
    /// (§5.3). Not a kronik.toml key.
    pub attach_timeout: Duration,
    /// Outgoing bytes all connections' queues may hold together: a frame
    /// that would pass it closes its connection as a slow consumer.
    pub total_queue_bytes: usize,
    /// Incoming frame bytes admitted and not yet finished, on all
    /// connections together: past it, readers wait.
    pub total_inflight_bytes: usize,
}

impl Default for ConnectionsConfig {
    fn default() -> Self {
        ConnectionsConfig {
            max_open: 4096,
            max_per_actor: 2048,
            max_per_client: 256,
            max_frame_bytes: 64 << 10,
            inflight_frames: 16,
            inbound_rate: 50,
            outbound_queue_bytes: 1 << 20,
            ping_interval: Duration::from_secs(30),
            ping_timeout: Duration::from_secs(30),
            sse_heartbeat: Duration::from_secs(15),
            close_timeout: Duration::from_secs(5),
            shutdown_grace: Duration::from_secs(2),
            attach_timeout: Duration::from_secs(10),
            total_queue_bytes: 256 << 20,
            total_inflight_bytes: 64 << 20,
        }
    }
}

/// What a connection's transport implements: the gateway's for WebSocket
/// and SSE, the simulator's, and [`RecordingTransport`]. Neither method may
/// block, and either may be called with no hub lock held.
pub trait Transport: Send + Sync {
    /// Frames, or the actor's close, are queued: pull them with
    /// [`Hub::next`].
    fn wake(&self);
    /// The host closes the connection: send `code` and `reason` if the
    /// protocol can (a WebSocket close frame), drop what is still queued,
    /// end, and report [`Hub::finished`].
    fn close(&self, code: u16, reason: &str);
}

/// Reports the end of a connection's transport to the hub when dropped
/// ([`Hub::finished`], which ignores a connection that is gone already).
/// A transport's task holds one, so that the end is reported however the
/// task ends: a write that timed out, an error, or the task being dropped.
pub struct FinishGuard {
    hub: Arc<Hub>,
    conn: String,
    client: Option<(u16, String)>,
}

impl FinishGuard {
    pub fn new(hub: Arc<Hub>, conn: String) -> FinishGuard {
        FinishGuard {
            hub,
            conn,
            client: None,
        }
    }

    /// The client's close (its code and reason), reported with the end.
    pub fn client_closed(&mut self, close: Option<(u16, String)>) {
        self.client = close;
    }
}

impl Drop for FinishGuard {
    fn drop(&mut self) {
        self.hub.finished(&self.conn, self.client.take());
    }
}

/// What a connection's writer sends next.
#[derive(Debug, Clone, PartialEq)]
pub enum Outgoing {
    /// A frame, with its outgoing seq; a broadcast's targets share it.
    Frame { seq: u64, frame: Arc<pb::Frame> },
    /// The actor's close, after the frames before it: send it, wait at most
    /// `close_timeout` for the client's, end, and report [`Hub::finished`].
    Close { code: u16, reason: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// The open turn has not committed.
    Opening,
    Open,
    /// Closed by the actor or the host: nothing more is queued or admitted.
    Closing,
}

#[derive(Debug, Clone)]
struct CloseFacts {
    cause: pb::CloseCause,
    code: u16,
    /// The actor's reason; empty for the host (its cause is the reason).
    reason: String,
}

/// A paced reader: tokens refill at `rate` per second, up to `rate`.
struct Bucket {
    tokens: f64,
    at: Duration,
}

struct Live {
    owner: ActorRef,
    protocol: pb::ConnectionProtocol,
    route: String,
    /// The connection's subject: the accept's, else the request's.
    subject: Option<String>,
    state: State,
    /// Nobody waits for the open any more (the gateway's timeout, or the
    /// client left before the handshake): an accept closes at once.
    abandoned: bool,
    queue: VecDeque<Outgoing>,
    queued_bytes: usize,
    frames_written: u64,
    frames_received: u64,
    /// The next incoming seq.
    next_in: u64,
    inflight: Arc<Semaphore>,
    bucket: Bucket,
    transport: Option<Arc<dyn Transport>>,
    /// Why it closes, once decided: the first cause wins.
    close: Option<CloseFacts>,
    client: Option<IpAddr>,
    /// Counted against `max_per_client`.
    counted_client: bool,
}

#[derive(Default)]
struct Inner {
    live: HashMap<String, Live>,
    per_actor: HashMap<ActorRef, usize>,
    per_client: HashMap<IpAddr, usize>,
    stopping: bool,
    /// The log's last LSN when the node started: a restart close's
    /// `restart_after_lsn`.
    restart_after_lsn: u64,
    /// Connections past their open turn, by kind and protocol: the gauge
    /// `kronik_connections_open`, kept as counters (review M8).
    open: HashMap<(String, &'static str), usize>,
    /// The counters that changed since they were last published.
    changed: Vec<(String, &'static str)>,
}

impl Inner {
    /// A connection past its open turn starts (`delta` 1) or stops (-1)
    /// counting in `kronik_connections_open`.
    fn count_open(&mut self, kind: &str, protocol: pb::ConnectionProtocol, up: bool) {
        let key = (kind.to_owned(), conn::protocol_name(protocol as i32));
        let n = self.open.entry(key.clone()).or_default();
        *n = if up { *n + 1 } else { n.saturating_sub(1) };
        if !self.changed.contains(&key) {
            self.changed.push(key);
        }
    }

    /// The changed counters, to publish once the lock is released.
    fn take_gauges(&mut self) -> Vec<(String, &'static str, usize)> {
        let changed = std::mem::take(&mut self.changed);
        changed
            .into_iter()
            .map(|key| {
                let n = self.open.get(&key).copied().unwrap_or(0);
                if n == 0 {
                    self.open.remove(&key);
                }
                (key.0, key.1, n)
            })
            .collect()
    }
}

/// The key a client address counts under for `max_per_client` (review
/// M1): an IPv4 address, or an IPv6 address's /64, since one client
/// usually holds a whole /64; an IPv4-mapped IPv6 address is its IPv4.
pub fn client_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let prefix = u128::from(v6) & !((1u128 << 64) - 1);
                IpAddr::V6(std::net::Ipv6Addr::from(prefix))
            }
        },
    }
}

/// A close the host decided while delivering: the connection, its
/// transport (none: finish at once), the code and the reason.
type HostClose = (String, Option<Arc<dyn Transport>>, u16, &'static str);

/// The live connections of a node.
pub struct Hub {
    /// For the tasks the hub starts (the attach watchdog).
    me: Weak<Hub>,
    env: Env,
    cfg: ConnectionsConfig,
    node: Mutex<Weak<Node>>,
    inner: Mutex<Inner>,
    /// Signals a finished connection (for [`Hub::shutdown`]).
    gone: Notify,
    /// The bytes all outgoing queues hold (`total_queue_bytes`).
    queued: AtomicUsize,
    /// Incoming frame bytes admitted and not finished
    /// (`total_inflight_bytes`), one permit per byte.
    inflight_bytes: Arc<Semaphore>,
}

/// A host cause's close code (§5.8).
pub fn host_code(cause: pb::CloseCause) -> u16 {
    match cause {
        pb::CloseCause::Restart | pb::CloseCause::Rebase => RESTART_CODE,
        pb::CloseCause::PingTimeout | pb::CloseCause::Abandoned => 1001,
        pb::CloseCause::TooLarge => 1009,
        pb::CloseCause::SlowConsumer | pb::CloseCause::Operator => 1008,
        pb::CloseCause::Protocol => 1002,
        pb::CloseCause::Unavailable => 1013,
        _ => 1011,
    }
}

impl Hub {
    pub fn new(env: Env, cfg: ConnectionsConfig) -> Arc<Hub> {
        let inflight_bytes = Arc::new(Semaphore::new(
            cfg.total_inflight_bytes.clamp(1, Semaphore::MAX_PERMITS),
        ));
        Arc::new_cyclic(|me| Hub {
            me: me.clone(),
            env,
            cfg,
            node: Mutex::new(Weak::new()),
            inner: Mutex::new(Inner::default()),
            gone: Notify::new(),
            queued: AtomicUsize::new(0),
            inflight_bytes,
        })
    }

    pub fn config(&self) -> &ConnectionsConfig {
        &self.cfg
    }

    pub(crate) fn bind(&self, node: Weak<Node>, restart_after_lsn: u64) {
        *lock(&self.node) = node;
        lock(&self.inner).restart_after_lsn = restart_after_lsn;
    }

    fn node(&self) -> Option<Arc<Node>> {
        lock(&self.node).upgrade()
    }

    /// Live connections on this node.
    pub fn live(&self) -> usize {
        lock(&self.inner).live.len()
    }

    /// Whether `conn` is live on this node, and how many bytes it queues.
    pub fn queued_bytes(&self, conn: &str) -> Option<usize> {
        lock(&self.inner).live.get(conn).map(|l| l.queued_bytes)
    }

    /// Whether a graceful stop began: no open or frame is admitted.
    pub fn stopping(&self) -> bool {
        lock(&self.inner).stopping
    }

    /// Registers a connection whose open the node is about to admit,
    /// within the caps: `CONNECTION_LIMIT` when the node, the owner or the
    /// client address (unless `exempt`, a trusted proxy) is full.
    // One admission's facts; a struct would only repack the caller's names.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn register(
        &self,
        id: &str,
        owner: &ActorRef,
        protocol: pb::ConnectionProtocol,
        route: &str,
        subject: Option<String>,
        client: Option<IpAddr>,
        exempt: bool,
    ) -> Result<(), ApiError> {
        let mut inner = lock(&self.inner);
        if inner.stopping {
            return Err(ApiError::new(
                ErrorCode::Unavailable,
                "the node is stopping",
            ));
        }
        let labels = [
            ("kind", owner.kind.as_str()),
            ("protocol", conn::protocol_name(protocol as i32)),
            ("result", "limit"),
        ];
        let full = |what: String| {
            kronik_metrics::inc("kronik_connections_opened_total", &labels);
            tracing::info!(owner = %owner, "refusing a connection over a cap: {what}");
            Err(ApiError::new(ErrorCode::ConnectionLimit, what).with_hint(
                "Try again later; operators raise [connections] max_open, max_per_actor or \
                 max_per_client.",
            ))
        };
        if inner.live.len() >= self.cfg.max_open {
            return full(format!(
                "the gateway holds {} connections, [connections] max_open",
                self.cfg.max_open
            ));
        }
        if inner.per_actor.get(owner).copied().unwrap_or(0) >= self.cfg.max_per_actor {
            return full(format!(
                "{owner} holds {} connections, [connections] max_per_actor",
                self.cfg.max_per_actor
            ));
        }
        let client = client.map(client_key);
        let counted_client = client.is_some() && !exempt;
        if let Some(ip) = client.filter(|_| counted_client)
            && inner.per_client.get(&ip).copied().unwrap_or(0) >= self.cfg.max_per_client
        {
            return full(format!(
                "this client holds {} connections, [connections] max_per_client",
                self.cfg.max_per_client
            ));
        }
        *inner.per_actor.entry(owner.clone()).or_default() += 1;
        if let Some(ip) = client.filter(|_| counted_client) {
            *inner.per_client.entry(ip).or_default() += 1;
        }
        let now = self.env.clock.monotonic();
        inner.live.insert(
            id.to_owned(),
            Live {
                owner: owner.clone(),
                protocol,
                route: route.to_owned(),
                subject,
                state: State::Opening,
                abandoned: false,
                queue: VecDeque::new(),
                queued_bytes: 0,
                frames_written: 0,
                frames_received: 0,
                next_in: 0,
                inflight: Arc::new(Semaphore::new(self.cfg.inflight_frames.max(1))),
                bucket: Bucket {
                    tokens: f64::from(self.cfg.inbound_rate),
                    at: now,
                },
                transport: None,
                close: None,
                client,
                counted_client,
            },
        );
        Ok(())
    }

    /// Removes `id` and gives its cap slots back.
    fn remove(&self, inner: &mut Inner, id: &str) -> Option<Live> {
        let live = inner.live.remove(id)?;
        if live.state != State::Opening {
            inner.count_open(&live.owner.kind, live.protocol, false);
        }
        self.queued.fetch_sub(live.queued_bytes, Ordering::Relaxed);
        if let Some(n) = inner.per_actor.get_mut(&live.owner) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                inner.per_actor.remove(&live.owner);
            }
        }
        if let Some(ip) = live.client.filter(|_| live.counted_client)
            && let Some(n) = inner.per_client.get_mut(&ip)
        {
            *n = n.saturating_sub(1);
            if *n == 0 {
                inner.per_client.remove(&ip);
            }
        }
        Some(live)
    }

    /// Publishes the changed `kronik_connections_open` counters and the
    /// bytes all outgoing queues hold; called with no hub lock held.
    fn publish(&self, gauges: Vec<(String, &'static str, usize)>) {
        for (kind, protocol, n) in gauges {
            kronik_metrics::set(
                "kronik_connections_open",
                &[("kind", &kind), ("protocol", protocol)],
                n as f64,
            );
        }
        kronik_metrics::set(
            "kronik_connection_queued_bytes",
            &[],
            self.queued.load(Ordering::Relaxed) as f64,
        );
    }

    /// The open turn of `input` committed (§4.2): an accept opens the
    /// connection, which the gateway now attaches; anything else forgets
    /// it. An accept for a connection this process did not open is one a
    /// re-run accepted after a restart: no client waits for it, so it
    /// closes at once with the reason `restart` (§4.8).
    pub(crate) fn settle_open(
        &self,
        owner: &ActorRef,
        input: &pb::ConnectionInput,
        outcome: &pb::Outcome,
    ) {
        let accept = match (
            &outcome.output,
            outcome.kind == pb::OutcomeKind::Committed as i32,
        ) {
            (Some(pb::outcome::Output::Accept(a)), true) => Some(a),
            _ => None,
        };
        let request_subject = conn::input_subject(input);
        let subject = accept.and_then(|a| a.subject.clone()).or(request_subject);
        let kind = &owner.kind;
        let protocol = conn::protocol_name(input.protocol);
        let result = if accept.is_some() {
            "accepted"
        } else if outcome.kind == pb::OutcomeKind::Committed as i32 {
            "refused"
        } else {
            "failed"
        };
        kronik_metrics::inc(
            "kronik_connections_opened_total",
            &[("kind", kind), ("protocol", protocol), ("result", result)],
        );
        let mut abandoned = false;
        let mut unattached = false;
        let (restart, gauges) = {
            let mut inner = lock(&self.inner);
            let mut opened = None;
            let restart = match inner.live.get_mut(&input.connection) {
                Some(live) if live.state == State::Opening => {
                    if accept.is_some() {
                        live.state = State::Open;
                        live.subject = subject.clone();
                        abandoned = live.abandoned;
                        unattached = live.transport.is_none();
                        opened = Some(live.protocol);
                        tracing::debug!(connection = %input.connection, owner = %owner, "connection open");
                    } else {
                        self.remove(&mut inner, &input.connection);
                    }
                    None
                }
                Some(_) => None,
                None => accept.map(|_| inner.restart_after_lsn),
            };
            if let Some(protocol) = opened {
                inner.count_open(&owner.kind, protocol, true);
            }
            (restart, inner.take_gauges())
        };
        self.publish(gauges);
        if abandoned {
            self.close_host(&input.connection, pb::CloseCause::Abandoned);
        } else if unattached {
            self.watch_attach(&input.connection);
        }
        if let Some(restart_after_lsn) = restart {
            tracing::debug!(connection = %input.connection, owner = %owner, "a re-run accepted a connection after a restart: closing it");
            let close = pb::ConnectionClose {
                cause: pb::CloseCause::Restart as i32,
                code: u32::from(RESTART_CODE),
                reason: Some(tagged(subject.clone(), Vec::new())),
                frames_written: 0,
                frames_written_known: false,
                frames_received: 0,
                restart_after_lsn,
            };
            self.admit_close(
                owner,
                input.connection.clone(),
                input.protocol,
                &input.route,
                subject,
                close,
            );
        }
    }

    /// An accepted connection that gets no transport within
    /// `attach_timeout` is abandoned, whoever forgot it: the client left
    /// before the upgrade, or its handshake never completed. Until then a
    /// close the actor buffers waits in its queue for the transport; after
    /// it, the connection is freed with the close decided first (review
    /// S3).
    fn watch_attach(&self, conn: &str) {
        let Some(hub) = self.me.upgrade() else {
            return;
        };
        let conn = conn.to_owned();
        let wait = self.cfg.attach_timeout;
        drop(self.env.spawn("connection-attach", async move {
            hub.env.clock.sleep(wait).await;
            let unattached = lock(&hub.inner)
                .live
                .get(&conn)
                .is_some_and(|l| l.state != State::Opening && l.transport.is_none());
            if unattached {
                tracing::info!(connection = %conn, "no transport attached in time: abandoned");
                hub.abandon(&conn);
            }
        }));
    }

    /// The open turn of `conn` finished. One that did not settle the open
    /// (its turn recorded nothing, or failed without running) frees the
    /// connection's slot.
    pub(crate) fn open_finished(&self, conn: &str) {
        let mut inner = lock(&self.inner);
        if inner
            .live
            .get(conn)
            .is_some_and(|l| l.state == State::Opening)
        {
            self.remove(&mut inner, conn);
        }
    }

    /// A committed turn's buffered operations (§4.3), in order: frames are
    /// queued for their connection's writer in seq order, a close after
    /// the frames before it. A connection that is not live here, or is
    /// closing, drops them: they are recorded and never written (§4.7), as
    /// are the targets that no live connection had (`dropped`, ADR 0114,
    /// amended). A queue past `outbound_queue_bytes` closes as a slow
    /// consumer (§5.6). `owner` is the turn's actor.
    pub(crate) fn deliver(&self, owner: &ActorRef, ops: &[pb::ConnectionOp]) {
        let dropped: usize = ops
            .iter()
            .filter(|op| matches!(op.op, Some(pb::connection_op::Op::Send(_))))
            .map(|op| op.dropped.len())
            .sum();
        if dropped > 0 {
            kronik_metrics::add(
                "kronik_connection_frames_dropped_total",
                &[("kind", owner.kind.as_str()), ("protocol", "none")],
                dropped as u64,
            );
        }
        let mut wake: Vec<Arc<dyn Transport>> = Vec::new();
        let mut close: Vec<HostClose> = Vec::new();
        // Counted under the lock, reported after it (review M8).
        let mut out: HashMap<(String, &'static str), (u64, u64)> = HashMap::new();
        let mut dropped_live: HashMap<(String, &'static str), u64> = HashMap::new();
        let gauges = {
            let mut inner = lock(&self.inner);
            for op in ops {
                match &op.op {
                    Some(pb::connection_op::Op::Send(frame)) => {
                        let bytes = conn::frame_bytes(frame);
                        // One copy for every target (review M6).
                        let frame = Arc::new(frame.clone());
                        for (id, seq) in op.connections.iter().zip(&op.seqs) {
                            let Some(live) = inner.live.get_mut(id) else {
                                continue;
                            };
                            let key = (
                                live.owner.kind.clone(),
                                conn::protocol_name(live.protocol as i32),
                            );
                            if live.state == State::Closing {
                                *dropped_live.entry(key).or_default() += 1;
                                continue;
                            }
                            let counts = out.entry(key).or_default();
                            counts.0 += 1;
                            counts.1 += bytes as u64;
                            live.queue.push_back(Outgoing::Frame {
                                seq: *seq,
                                frame: frame.clone(),
                            });
                            live.queued_bytes += bytes;
                            let total = self.queued.fetch_add(bytes, Ordering::Relaxed) + bytes;
                            if live.queued_bytes > self.cfg.outbound_queue_bytes
                                || total > self.cfg.total_queue_bytes
                            {
                                // A committed frame never waits: the client
                                // that cannot keep up is closed (§5.6), also
                                // when all queues together are full.
                                live.state = State::Closing;
                                live.close.get_or_insert(CloseFacts {
                                    cause: pb::CloseCause::SlowConsumer,
                                    code: host_code(pb::CloseCause::SlowConsumer),
                                    reason: String::new(),
                                });
                                live.queue.clear();
                                self.queued.fetch_sub(live.queued_bytes, Ordering::Relaxed);
                                live.queued_bytes = 0;
                                tracing::info!(connection = %id, owner = %live.owner, "closing a slow consumer");
                                close.push((
                                    id.clone(),
                                    live.transport.clone(),
                                    host_code(pb::CloseCause::SlowConsumer),
                                    "slow-consumer",
                                ));
                            } else if let Some(t) = &live.transport
                                && !wake.iter().any(|w| Arc::ptr_eq(w, t))
                            {
                                wake.push(t.clone());
                            }
                        }
                    }
                    Some(pb::connection_op::Op::Close(c)) => {
                        let Some(id) = op.connections.first() else {
                            continue;
                        };
                        let Some(live) = inner.live.get_mut(id) else {
                            continue;
                        };
                        if live.state == State::Closing {
                            continue;
                        }
                        live.state = State::Closing;
                        let code = u16::try_from(c.code).unwrap_or(1000);
                        let reason = match c.reason.as_ref().and_then(|r| r.value.as_ref()) {
                            Some(pb::sealable::Value::Plain(b)) => {
                                String::from_utf8_lossy(b).into_owned()
                            }
                            _ => String::new(),
                        };
                        live.close.get_or_insert(CloseFacts {
                            cause: pb::CloseCause::Actor,
                            code,
                            reason: reason.clone(),
                        });
                        live.queue.push_back(Outgoing::Close { code, reason });
                        match &live.transport {
                            Some(t) => {
                                if !wake.iter().any(|w| Arc::ptr_eq(w, t)) {
                                    wake.push(t.clone());
                                }
                            }
                            // Accepted, but never attached: nobody to write
                            // to. One still waiting for its transport keeps
                            // the close queued; the attach watchdog frees it.
                            None if live.abandoned => close.push((id.clone(), None, code, "")),
                            None => {}
                        }
                    }
                    None => {}
                }
            }
            inner.take_gauges()
        };
        for ((kind, protocol), (frames, bytes)) in out {
            let labels = [
                ("kind", kind.as_str()),
                ("protocol", protocol),
                ("direction", "out"),
            ];
            kronik_metrics::add("kronik_connection_frames_total", &labels, frames);
            kronik_metrics::add("kronik_connection_frame_bytes_total", &labels, bytes);
        }
        for ((kind, protocol), n) in dropped_live {
            kronik_metrics::add(
                "kronik_connection_frames_dropped_total",
                &[("kind", kind.as_str()), ("protocol", protocol)],
                n,
            );
        }
        self.publish(gauges);
        for t in wake {
            t.wake();
        }
        for (id, transport, code, reason) in close {
            match transport {
                Some(t) => t.close(code, reason),
                None => self.finished(&id, None),
            }
        }
    }

    /// Attaches the transport of an accepted connection; its writer starts
    /// with the frames the open turn queued. `UNAVAILABLE` when the
    /// connection is not open here any more (closed meanwhile): the caller
    /// closes its socket.
    pub fn attach(&self, conn: &str, transport: Arc<dyn Transport>) -> Result<(), ApiError> {
        let wake = {
            let mut inner = lock(&self.inner);
            let Some(live) = inner.live.get_mut(conn) else {
                return Err(ApiError::new(
                    ErrorCode::Unavailable,
                    format!("connection {conn} is not live on this node"),
                ));
            };
            if live.state == State::Opening || live.abandoned {
                return Err(ApiError::new(
                    ErrorCode::Unavailable,
                    format!("connection {conn} is not open"),
                ));
            }
            live.transport = Some(transport.clone());
            !live.queue.is_empty()
        };
        if wake {
            transport.wake();
        }
        Ok(())
    }

    /// Nobody will attach a transport to `conn` (the gateway stopped
    /// waiting for its open turn, the client left before the handshake, or
    /// the upgrade failed): an accepted one closes with the reason
    /// `abandoned`, one still opening when its turn commits (§4.2).
    pub fn abandon(&self, conn: &str) {
        let close = {
            let mut inner = lock(&self.inner);
            let Some(live) = inner.live.get_mut(conn) else {
                return;
            };
            live.abandoned = true;
            live.state != State::Opening
        };
        if close {
            self.close_host(conn, pb::CloseCause::Abandoned);
        }
    }

    /// The host closes `conn` (§5.8): it is closing at once, its queue is
    /// dropped, and its transport is told to send the cause's code. The
    /// first cause decided wins.
    pub fn close_host(&self, conn: &str, cause: pb::CloseCause) {
        self.close_host_with(conn, cause, host_code(cause));
    }

    /// [`Hub::close_host`] with a code other than the cause's own: invalid
    /// UTF-8 is a `protocol` close with 1007 (§5.5).
    pub fn close_host_with(&self, conn: &str, cause: pb::CloseCause, code: u16) {
        let (transport, finish) = {
            let mut inner = lock(&self.inner);
            let Some(live) = inner.live.get_mut(conn) else {
                return;
            };
            if live.state == State::Opening {
                live.abandoned |= cause == pb::CloseCause::Abandoned;
                return;
            }
            live.close.get_or_insert(CloseFacts {
                cause,
                code,
                reason: String::new(),
            });
            live.state = State::Closing;
            live.queue.clear();
            self.queued.fetch_sub(live.queued_bytes, Ordering::Relaxed);
            live.queued_bytes = 0;
            (live.transport.clone(), live.transport.is_none())
        };
        if matches!(
            cause,
            pb::CloseCause::SlowConsumer | pb::CloseCause::PingTimeout | pb::CloseCause::TooLarge
        ) {
            tracing::info!(connection = %conn, cause = conn::cause_name(cause as i32), "host closes a connection");
        }
        if let Some(t) = transport {
            t.close(code, conn::cause_name(cause as i32));
        } else if finish {
            self.finished(conn, None);
        }
    }

    /// The next thing `conn`'s writer sends, in seq order; `None` when
    /// nothing is queued (wait for [`Transport::wake`]).
    pub fn next(&self, conn: &str) -> Option<Outgoing> {
        let mut inner = lock(&self.inner);
        let live = inner.live.get_mut(conn)?;
        let item = live.queue.pop_front()?;
        if let Outgoing::Frame { frame, .. } = &item {
            let bytes = conn::frame_bytes(frame).min(live.queued_bytes);
            live.queued_bytes -= bytes;
            self.queued.fetch_sub(bytes, Ordering::Relaxed);
        }
        Some(item)
    }

    /// `conn`'s writer wrote and flushed the frame `seq`.
    pub fn written(&self, conn: &str, seq: u64) {
        let mut inner = lock(&self.inner);
        if let Some(live) = inner.live.get_mut(conn) {
            debug_assert!(
                seq >= live.frames_written,
                "frames are written in seq order"
            );
            live.frames_written = live.frames_written.max(seq.saturating_add(1));
        }
    }

    /// An incoming message on `conn` (WebSocket): admitted as a frame input
    /// of the connection's owner, with the next incoming seq, once one of
    /// its `inflight_frames` permits is free and the inbound rate allows
    /// it. The reader awaits this before it reads on. A message of a
    /// closing connection is counted and discarded; one the node cannot
    /// admit closes the connection with the reason `unavailable` (§5.5).
    pub async fn incoming(&self, conn: &str, frame: pb::Frame) {
        let (inflight, owner, protocol) = {
            let mut inner = lock(&self.inner);
            if inner.stopping {
                return;
            }
            let Some(live) = inner.live.get_mut(conn) else {
                return;
            };
            live.frames_received += 1;
            if live.state != State::Open {
                return;
            }
            (
                live.inflight.clone(),
                live.owner.clone(),
                conn::protocol_name(live.protocol as i32),
            )
        };
        let bytes = conn::frame_bytes(&frame);
        let labels = [
            ("kind", owner.kind.as_str()),
            ("protocol", protocol),
            ("direction", "in"),
        ];
        kronik_metrics::inc("kronik_connection_frames_total", &labels);
        kronik_metrics::add("kronik_connection_frame_bytes_total", &labels, bytes as u64);
        let Ok(permit) = inflight.acquire_owned().await else {
            return;
        };
        // The node-wide budget of incoming bytes in flight (review M6).
        let total = self.cfg.total_inflight_bytes.max(1);
        let share = u32::try_from(bytes.max(1).min(total)).unwrap_or(u32::MAX);
        let Ok(bytes_permit) = self.inflight_bytes.clone().acquire_many_owned(share).await else {
            return;
        };
        self.pace(conn).await;
        let admitted = {
            let mut inner = lock(&self.inner);
            if inner.stopping {
                return;
            }
            let Some(live) = inner.live.get_mut(conn) else {
                return;
            };
            if live.state != State::Open {
                return;
            }
            let seq = live.next_in;
            live.next_in += 1;
            let mut frame = frame;
            if let Some(data) = frame.data.as_mut() {
                data.subject = live.subject.clone();
            }
            let input = pb::ConnectionInput {
                connection: conn.to_owned(),
                protocol: live.protocol as i32,
                route: live.route.clone(),
                event: Some(pb::connection_input::Event::Frame(pb::ConnectionFrame {
                    seq,
                    frame: Some(frame),
                })),
                ..Default::default()
            };
            (input, live.subject.clone())
        };
        let (input, subject) = admitted;
        let admission = match self.node() {
            Some(node) => node.admit_connection(owner, input, subject, false),
            None => Err(ApiError::new(
                ErrorCode::Unavailable,
                "the node is stopping",
            )),
        };
        match admission {
            Ok(rx) => {
                // The permits come back when the frame's turn finished.
                self.env.spawn("connection-frame", async move {
                    let _ = rx.await;
                    drop(permit);
                    drop(bytes_permit);
                });
            }
            Err(e) => {
                tracing::info!(connection = %conn, error = %e, "cannot admit a frame: closing the connection");
                self.close_host(conn, pb::CloseCause::Unavailable);
            }
        }
    }

    /// Waits for a token of `conn`'s inbound rate.
    async fn pace(&self, conn: &str) {
        let rate = f64::from(self.cfg.inbound_rate);
        if rate <= 0.0 {
            return;
        }
        loop {
            let wait = {
                let now = self.env.clock.monotonic();
                let mut inner = lock(&self.inner);
                let Some(live) = inner.live.get_mut(conn) else {
                    return;
                };
                let b = &mut live.bucket;
                let elapsed = now.saturating_sub(b.at).as_secs_f64();
                b.tokens = (b.tokens + elapsed * rate).min(rate);
                b.at = now;
                if b.tokens >= 1.0 {
                    b.tokens -= 1.0;
                    return;
                }
                Duration::from_secs_f64((1.0 - b.tokens) / rate)
            };
            self.env.clock.sleep(wait).await;
        }
    }

    /// `conn`'s transport ended. `client` is the client's close (code and
    /// reason; `None`: gone without one, or the end of a close the actor or
    /// the host asked for). The connection's close input is admitted,
    /// exactly once (§4.8), with the first cause decided and how many
    /// frames were written; during a graceful stop the node's next start
    /// admits it instead (§5.9).
    pub fn finished(&self, conn: &str, client: Option<(u16, String)>) {
        let (live, stopping, gauges) = {
            let mut inner = lock(&self.inner);
            let Some(live) = self.remove(&mut inner, conn) else {
                return;
            };
            (live, inner.stopping, inner.take_gauges())
        };
        self.publish(gauges);
        self.gone.notify_waiters();
        if stopping || live.state == State::Opening {
            return;
        }
        let facts = live.close.clone().unwrap_or_else(|| {
            let (code, reason) = client.unwrap_or((1006, String::new()));
            CloseFacts {
                cause: pb::CloseCause::Client,
                code,
                reason,
            }
        });
        kronik_metrics::inc(
            "kronik_connections_closed_total",
            &[
                ("kind", live.owner.kind.as_str()),
                ("protocol", conn::protocol_name(live.protocol as i32)),
                ("cause", conn::cause_name(facts.cause as i32)),
            ],
        );
        tracing::debug!(connection = %conn, owner = %live.owner, cause = conn::cause_name(facts.cause as i32), "connection closed");
        let close = pb::ConnectionClose {
            cause: facts.cause as i32,
            code: u32::from(facts.code),
            reason: Some(tagged(live.subject.clone(), facts.reason.into_bytes())),
            frames_written: live.frames_written,
            frames_written_known: true,
            frames_received: live.frames_received,
            restart_after_lsn: 0,
        };
        self.admit_close(
            &live.owner,
            conn.to_owned(),
            live.protocol as i32,
            &live.route,
            live.subject,
            close,
        );
    }

    fn admit_close(
        &self,
        owner: &ActorRef,
        connection: String,
        protocol: i32,
        route: &str,
        subject: Option<String>,
        close: pb::ConnectionClose,
    ) {
        let input = pb::ConnectionInput {
            connection,
            protocol,
            route: route.to_owned(),
            event: Some(pb::connection_input::Event::Close(close)),
            ..Default::default()
        };
        let id = input.connection.clone();
        let result = match self.node() {
            Some(node) => node.admit_connection(owner.clone(), input, subject, true),
            None => Err(ApiError::new(
                ErrorCode::Unavailable,
                "the node is stopping",
            )),
        };
        if let Err(e) = result {
            // The row stays open in state.db: the next start closes it.
            tracing::warn!(connection = %id, error = %e, "cannot admit a connection's close input now; the next start closes it");
        }
    }

    /// A graceful stop (§5.9): no more opens or frames are admitted, every
    /// WebSocket gets a close frame with 1012 and `kronik: restart`, every
    /// SSE stream a `retry:` hint and its end, and the writers get at most
    /// `grace` to finish. The close inputs come from the next start.
    pub async fn shutdown(&self, grace: Duration) {
        let transports: Vec<Arc<dyn Transport>> = {
            let mut inner = lock(&self.inner);
            inner.stopping = true;
            inner
                .live
                .values_mut()
                .filter_map(|l| {
                    l.state = State::Closing;
                    l.queue.clear();
                    self.queued.fetch_sub(l.queued_bytes, Ordering::Relaxed);
                    l.queued_bytes = 0;
                    l.transport.clone()
                })
                .collect()
        };
        for t in &transports {
            t.close(RESTART_CODE, RESTART_REASON);
        }
        let all_gone = async {
            loop {
                let gone = self.gone.notified();
                if lock(&self.inner)
                    .live
                    .values()
                    .all(|l| l.transport.is_none())
                {
                    return;
                }
                gone.await;
            }
        };
        if self.env.timeout(grace, all_gone).await.is_err() {
            tracing::warn!(
                left = lock(&self.inner).live.len(),
                "the shutdown grace ran out with connections still writing"
            );
        }
    }
}

fn tagged(subject: Option<String>, bytes: Vec<u8>) -> pb::Sealable {
    pb::Sealable {
        subject,
        value: Some(pb::sealable::Value::Plain(bytes)),
    }
}

/// A transport that writes into memory: it takes every queued frame as
/// soon as it is woken, records the frames in seq order and the close,
/// and reports them written. The test host and tests attach it; `stall`
/// stops the taking, like a client that does not read.
#[derive(Default)]
pub struct RecordingTransport {
    hub: Mutex<Option<(Weak<Hub>, String)>>,
    record: Mutex<Recording>,
}

/// What a [`RecordingTransport`] saw.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Recording {
    /// The frames written, with their seqs.
    pub frames: Vec<(u64, pb::Frame)>,
    /// The close it sent: the actor's or the host's code and reason.
    pub closed: Option<(u16, String)>,
    /// It stopped taking frames.
    pub stalled: bool,
}

impl RecordingTransport {
    /// Attaches a new recording transport to `conn` of `hub`.
    pub fn attach(hub: &Arc<Hub>, conn: &str) -> Result<Arc<RecordingTransport>, ApiError> {
        let t = Arc::new(RecordingTransport::default());
        *lock(&t.hub) = Some((Arc::downgrade(hub), conn.to_owned()));
        hub.attach(conn, t.clone())?;
        Ok(t)
    }

    pub fn recording(&self) -> Recording {
        lock(&self.record).clone()
    }

    /// Stops (or resumes) taking frames: a client that does not read.
    pub fn stall(&self, stalled: bool) {
        lock(&self.record).stalled = stalled;
        if !stalled {
            self.wake();
        }
    }

    /// The client closes: `code` and `reason`, or gone without a close
    /// frame (`None`).
    pub fn client_close(&self, close: Option<(u16, String)>) {
        if let Some((hub, conn)) = self.hub() {
            hub.finished(&conn, close);
        }
    }

    fn hub(&self) -> Option<(Arc<Hub>, String)> {
        let g = lock(&self.hub);
        let (hub, conn) = g.as_ref()?;
        Some((hub.upgrade()?, conn.clone()))
    }
}

impl Transport for RecordingTransport {
    fn wake(&self) {
        let Some((hub, conn)) = self.hub() else {
            return;
        };
        loop {
            if lock(&self.record).stalled {
                return;
            }
            match hub.next(&conn) {
                Some(Outgoing::Frame { seq, frame }) => {
                    lock(&self.record).frames.push((seq, (*frame).clone()));
                    hub.written(&conn, seq);
                }
                Some(Outgoing::Close { code, reason }) => {
                    lock(&self.record).closed = Some((code, reason));
                    hub.finished(&conn, None);
                    return;
                }
                None => return,
            }
        }
    }

    fn close(&self, code: u16, reason: &str) {
        lock(&self.record).closed = Some((code, reason.to_owned()));
        if let Some((hub, conn)) = self.hub() {
            hub.finished(&conn, None);
        }
    }
}
