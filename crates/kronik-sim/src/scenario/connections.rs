//! The M24 connections workload (docs/design/m24-connections.md §14).
//!
//! K clients open WebSocket and SSE connections to the rooms of the room
//! guest (`tests/guests/room.wasm`) through the gateway's connection path
//! and the hub, with [`SimTransport`] in place of tungstenite: a node task
//! (the writer) moves the hub's frames into a bounded simulated socket
//! buffer that the client reads at its own pace, or stops reading, and
//! another (the reader) hands the client's frames to the hub one at a time.
//! Clients broadcast, echo, send to and kick other connections (also those
//! of other rooms, which the host refuses), make turns fail and trap, say
//! bye, then close, vanish, stop reading or linger, and reconnect. A client
//! that gives up during an open makes the server drop the open, as hyper
//! drops the service future of a client that left. The node crashes
//! (unsynced writes lost or torn, `state.db` kept or lost) and stops
//! gracefully (§5.9).
//!
//! The properties (§14), checked as frames reach the clients and at the end:
//!
//! - C1: every accepted connection gets exactly one close input, its last
//!   input; once every client has left the hub holds no connection, and
//!   after the final restart none is open in `state.db`.
//! - C2: a connection's frame inputs have the seqs 0..n-1 in log order, and
//!   n is at most what its client sent.
//! - C3: a client gets a buffered frame only once a committed record that
//!   holds it is durable on the simulated disk.
//! - C4: a client gets its connection's frames in strictly increasing seq;
//!   when a close knows `frames_written`, the client got exactly the seqs
//!   below it.
//! - C5: `send-now`: no frame before its turn's `TurnBegin` is durable (I14),
//!   none performed twice, none performed by a re-run without a recorded
//!   result (I17). Checked from the log and the frames the clients got: one
//!   that no durable buffered record held must be a `send-now` with its
//!   seq, or the one of an outcome-unknown send on its connection.
//! - C6: a client gets frames only from its connection's owner.
//! - C7: the recovered `connections` and `connection_history` tables equal a
//!   rebuild from the log (every start's recovery check).
//! - C8: identity replay of the run's log is empty in both modes.
//! - C9: the run is a deterministic function of the seed (`--twice`).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use kronik_core::env::Env;
use kronik_core::ids::Lsn;
use kronik_gateway::{Gateway, HttpRequest, HttpResponse};
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_sched::Node;
use kronik_sched::connections::{Outgoing, Transport};
use prost::Message as _;
use tokio::sync::{Notify, mpsc, oneshot};

use super::{World, log_dir};
use crate::SimRng;
use crate::fs::Disk;

/// The room guest (tests/guests/room.wasm), built for the world
/// `actor-connections`.
pub const ROOM: &[u8] = include_bytes!("../../../../tests/guests/room.wasm");

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The connections workload's knobs, from the seed.
#[derive(Debug, Clone, Copy)]
pub struct ConnWorkload {
    /// Rooms, `room/r0` to `room/r2`: R = 1 to 3.
    pub rooms: u64,
    /// Connections each client opens, one after the other.
    pub sessions: u64,
    /// Frames a WebSocket client sends on one connection, at most.
    pub frames: u64,
    /// Share of the connections that are SSE streams.
    pub sse_p: f64,
    /// The simulated socket's buffer: written frames the client has not
    /// read, in bytes (the kernel's buffers on both ends).
    pub socket_bytes: usize,
    /// `[connections] outbound_queue_bytes`.
    pub queue_bytes: usize,
    /// `total_queue_bytes` and `total_inflight_bytes`, the node-wide
    /// budgets; `None`: the defaults.
    pub total_queue_bytes: Option<usize>,
    pub total_inflight_bytes: Option<usize>,
    /// The chance that a fault is a graceful stop instead of a crash.
    pub graceful_p: f64,
    /// C8: replay the log at the end (every 10th seed; every seed with
    /// `--identity-replay`).
    pub identity_replay: bool,
    /// The first client that opens connections; the ones before it run
    /// the counter workload (the long run mixes both).
    pub first_client: usize,
}

impl ConnWorkload {
    pub fn for_seed(seed: u64) -> ConnWorkload {
        let r = SimRng::new(seed, b"connections-config");
        ConnWorkload {
            rooms: 1 + r.below(3),
            sessions: 1 + r.below(3),
            frames: 2 + r.below(12),
            sse_p: [0.0, 0.2, 0.4][r.below(3) as usize],
            socket_bytes: [256, 2 << 10, 64 << 10][r.below(3) as usize],
            queue_bytes: [512, 1 << 10, 8 << 10, 1 << 20][r.below(4) as usize],
            graceful_p: [0.0, 0.3, 0.6][r.below(3) as usize],
            total_queue_bytes: [Some(2 << 10), Some(16 << 10), None][r.below(3) as usize],
            total_inflight_bytes: [Some(64), Some(1 << 10), None][r.below(3) as usize],
            identity_replay: seed.is_multiple_of(10),
            first_client: 0,
        }
    }
}

/// The workload's part of the run's state.
#[derive(Default)]
pub(super) struct ConnState {
    /// The current node's listener for opens: the connection path's "TCP
    /// listener"; none while the node is down.
    pub(super) listener: Option<mpsc::UnboundedSender<OpenRequest>>,
    /// Every connection a client was told is open, by id.
    sockets: BTreeMap<String, Arc<Socket>>,
    /// The durable log as of the last look (C3, C5, C6).
    durable: DurableIndex,
    /// The applied LSN at every node start: a re-run crosses one (C5).
    pub(super) starts: Vec<Lsn>,
    /// Frames a client got before any durable record held them. With
    /// `send-now` they are resolved against its effects at the end (C5).
    unresolved: Vec<Unresolved>,
    stats: ConnStats,
}

#[derive(Default)]
struct ConnStats {
    opens: u64,
    accepted: u64,
    refused: u64,
    frames_sent: u64,
    frames_out: u64,
    stops: u64,
    /// C5's evidence: frames resolved as send-now with their seq or as
    /// outcome-unknown sends, and re-run send-now effects checked.
    now_ok: u64,
    now_unknown: u64,
    now_reruns: u64,
}

/// A frame a client got that no durable record held at that moment, with
/// the durable `TurnBegin`s of its owner then (I14).
struct Unresolved {
    conn: String,
    seq: u64,
    frame: pb::Frame,
    begins: BTreeSet<String>,
}

/// An open, from a client to the node's listener.
pub(super) struct OpenRequest {
    req: HttpRequest,
    owner: String,
    sse: bool,
    reply: oneshot::Sender<OpenReply>,
}

/// The server's answer to an open.
pub(super) enum OpenReply {
    /// Accepted: `101 Switching Protocols` or the `200` event stream.
    Open(Arc<Socket>),
    /// Refused, failed, or not admitted.
    Answer(HttpResponse),
}

/// One connection's socket, shared by its client and the node's tasks.
pub(super) struct Socket {
    id: String,
    /// The connection's owner, `room/<key>`.
    owner: String,
    sse: bool,
    /// The buffer's capacity in bytes.
    capacity: usize,
    s: Mutex<SocketState>,
    /// The client sent or closed.
    to_reader: Notify,
    /// The client read (room in the buffer) or closed.
    to_writer: Notify,
    /// The server wrote, closed or died.
    to_client: Notify,
}

#[derive(Default)]
struct SocketState {
    /// Written frames the client has not read.
    buffer: VecDeque<(u64, Arc<pb::Frame>)>,
    buffered: usize,
    /// Every seq written, in order (C4).
    written: Vec<u64>,
    /// Frames the client read.
    read: u64,
    /// The server's close: a WebSocket close frame, or an SSE stream's end.
    server_close: Option<(u16, String)>,
    /// Frames the client sent that the server has not read.
    outgoing: VecDeque<pb::Frame>,
    /// Frames the client sent (C2).
    sent: u64,
    /// The client closed (`Some(code and reason)`) or vanished (`None`).
    client_close: Option<Option<(u16, String)>>,
    /// The server is done with the connection: it reported the close to
    /// the hub, or its node died.
    ended: bool,
    /// The node died under the connection.
    broken: bool,
    /// The client stopped reading.
    stalled: bool,
}

impl Socket {
    fn new(id: String, owner: String, sse: bool, capacity: usize) -> Socket {
        Socket {
            id,
            owner,
            sse,
            capacity,
            s: Mutex::new(SocketState::default()),
            to_reader: Notify::new(),
            to_writer: Notify::new(),
            to_client: Notify::new(),
        }
    }

    fn state(&self) -> MutexGuard<'_, SocketState> {
        lock(&self.s)
    }

    fn wake_all(&self) {
        self.to_reader.notify_one();
        self.to_writer.notify_one();
        self.to_client.notify_one();
    }

    fn ended(&self) -> bool {
        self.state().ended
    }
}

/// Held by each node task of a socket: a task dropped before it ends (its
/// node died) leaves the client a broken connection; one that ends
/// disarms it. It touches only the socket: a dead node's destructors must
/// not reach the hub or the log.
struct ServerEnd {
    socket: Arc<Socket>,
    armed: bool,
}

impl ServerEnd {
    fn new(socket: Arc<Socket>) -> ServerEnd {
        ServerEnd {
            socket,
            armed: true,
        }
    }

    /// The task ended on its own.
    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for ServerEnd {
    fn drop(&mut self) {
        if self.armed {
            let mut s = self.socket.state();
            if !s.ended {
                s.ended = true;
                s.broken = true;
            }
        }
        self.socket.wake_all();
    }
}

/// The simulator's transport: the hub wakes the writer, or closes.
#[derive(Default)]
struct SimTransport {
    /// The host's close, for the writer.
    host_close: Mutex<Option<(u16, String)>>,
    wake: Notify,
}

impl Transport for SimTransport {
    fn wake(&self) {
        self.wake.notify_one();
    }

    fn close(&self, code: u16, reason: &str) {
        lock(&self.host_close).get_or_insert_with(|| (code, reason.to_owned()));
        self.wake.notify_one();
    }
}

/// A frame a durable record sends.
#[derive(Clone)]
struct DurableFrame {
    actor: String,
    committed: bool,
    frame: pb::Frame,
}

/// What the simulated disk holds durably of the log, read incrementally.
#[derive(Default)]
struct DurableIndex {
    /// Per segment file: the durable bytes read and the next LSN to decode.
    scanned: BTreeMap<PathBuf, (usize, Lsn)>,
    /// The records whose buffered operations send `(connection, seq)`.
    frames: BTreeMap<(String, u64), Vec<DurableFrame>>,
    /// Durable `TurnBegin`s: execution id to actor.
    begins: BTreeMap<String, String>,
}

impl DurableIndex {
    /// Reads what became durable since the last look.
    fn refresh(&mut self, disk: &Disk) {
        for path in disk.durable_files_in(&log_dir()) {
            let Some(start) = path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_suffix(".seg"))
                .and_then(|d| d.parse::<Lsn>().ok())
            else {
                continue;
            };
            let Some((len, _)) = disk.durable_suffix(&path, usize::MAX) else {
                continue;
            };
            let (seen, next) = self.scanned.get(&path).copied().unwrap_or((0, start));
            if seen == len {
                continue;
            }
            let Some(image) = disk.durable_contents(&path) else {
                continue;
            };
            let mut last = None;
            let (frames, begins) = (&mut self.frames, &mut self.begins);
            let scanned = kronik_log::scan_segment_image::<kronik_log::LogError>(
                &image,
                "main",
                start,
                next,
                Lsn::MAX,
                true,
                |c| {
                    last = Some(c.lsn);
                    index_record(frames, begins, &c.record);
                    Ok(())
                },
            );
            let next = last.map_or(next, |l| l + 1);
            // A segment that does not scan (yet) is read again next time,
            // from where it stopped.
            let seen = if scanned.is_ok() { len } else { 0 };
            self.scanned.insert(path, (seen, next));
        }
    }

    fn lookup(&mut self, disk: &Mutex<Disk>, conn: &str, seq: u64) -> Option<Vec<DurableFrame>> {
        let key = (conn.to_owned(), seq);
        if !self.frames.contains_key(&key) {
            self.refresh(&lock(disk));
        }
        self.frames.get(&key).cloned()
    }
}

fn actor_name(a: Option<&pb::ActorRef>) -> String {
    a.map(|a| format!("{}/{}", a.kind, a.key))
        .unwrap_or_default()
}

fn committed(t: &pb::TurnRecord) -> bool {
    t.outcome
        .as_ref()
        .is_some_and(|o| o.kind == pb::OutcomeKind::Committed as i32)
}

fn index_record(
    frames: &mut BTreeMap<(String, u64), Vec<DurableFrame>>,
    begins: &mut BTreeMap<String, String>,
    record: &Record,
) {
    match record {
        Record::TurnBegin(b) => {
            begins.insert(b.execution_id.clone(), actor_name(b.actor.as_ref()));
        }
        Record::TurnRecord(t) => {
            let actor = actor_name(t.actor.as_ref());
            let committed = committed(t);
            for op in &t.connection_ops {
                if let Some(pb::connection_op::Op::Send(frame)) = &op.op {
                    for (id, seq) in op.connections.iter().zip(&op.seqs) {
                        frames
                            .entry((id.clone(), *seq))
                            .or_default()
                            .push(DurableFrame {
                                actor: actor.clone(),
                                committed,
                                frame: frame.clone(),
                            });
                    }
                }
            }
        }
        _ => {}
    }
}

fn text_frame(text: &str) -> pb::Frame {
    pb::Frame {
        kind: pb::frame::Kind::Text as i32,
        data: Some(pb::Sealable {
            subject: None,
            value: Some(pb::sealable::Value::Plain(text.as_bytes().to_vec())),
        }),
        event: String::new(),
        id: String::new(),
    }
}

fn frame_bytes(f: &pb::Frame) -> usize {
    let data = match f.data.as_ref().and_then(|d| d.value.as_ref()) {
        Some(pb::sealable::Value::Plain(b)) => b.len(),
        _ => 0,
    };
    data + f.event.len() + f.id.len()
}

/// Whether a frame sent is the one its record holds. A record keeps a
/// subject's data sealed when privacy mode is on, and the client gets it
/// plain: then the frame's kind, SSE fields and subject must match. A
/// tombstone (an erasure that began during the turn) is sealed in both.
fn same_frame(recorded: &pb::Frame, sent: &pb::Frame) -> bool {
    let sealed = matches!(
        recorded.data.as_ref().and_then(|d| d.value.as_ref()),
        Some(pb::sealable::Value::Sealed(_))
    );
    if !sealed {
        return recorded == sent;
    }
    recorded.kind == sent.kind
        && recorded.event == sent.event
        && recorded.id == sent.id
        && recorded.data.as_ref().map(|d| &d.subject) == sent.data.as_ref().map(|d| &d.subject)
}

fn describe(f: &pb::Frame) -> String {
    let (kind, data, event, id) = content(f);
    format!(
        "kind {kind} {:?} {event} {id}",
        String::from_utf8_lossy(&data)
    )
}

/// Where the log has `conn`'s frame `seq`: the records whose buffered
/// operations send it, and the connection's `send-now` effects.
fn frame_history(records: &[(Lsn, Record)], conn: &str, seq: u64) -> String {
    let mut out = Vec::new();
    for (lsn, record) in records {
        let (exec, effects, ops, outcome) = match record {
            Record::TurnRecord(t) => (
                &t.execution_id,
                t.effects.as_slice(),
                t.connection_ops.as_slice(),
                t.outcome.as_ref().map(|o| o.kind),
            ),
            Record::EffectResult(r) => (
                &r.execution_id,
                r.effect.as_slice(),
                &[][..],
                None,
            ),
            Record::TurnBegin(b) if b.input.as_ref().is_some_and(|i| {
                matches!(&i.kind, Some(pb::input::Kind::Connection(c)) if c.connection == conn)
            }) => {
                out.push(format!("lsn {lsn} begin {}", b.execution_id));
                continue;
            }
            _ => continue,
        };
        for op in ops {
            if let Some(pb::connection_op::Op::Send(frame)) = &op.op {
                for (id, s) in op.connections.iter().zip(&op.seqs) {
                    if id == conn && *s == seq {
                        out.push(format!(
                            "lsn {lsn} {exec} outcome {outcome:?} sends it: {}",
                            describe(frame)
                        ));
                    }
                }
            }
        }
        for e in effects.iter().filter(|e| e.kind == "connection.send-now") {
            if let Some(pb::sealable::Value::Plain(b)) =
                e.request.as_ref().and_then(|r| r.value.as_ref())
                && let Ok(req) = pb::ConnectionSendRequest::decode(b.as_slice())
                && req.connection == conn
            {
                out.push(format!(
                    "lsn {lsn} {exec} send-now {} status {} seq {} {:?}",
                    e.ordinal,
                    e.status,
                    req.seq,
                    String::from_utf8_lossy(&req.data)
                ));
            }
        }
    }
    out.join("; ")
}

/// A frame's content as a `send-now` request records it: kind, data, SSE
/// fields (the subject aside).
type Content = (i32, Vec<u8>, String, String);

fn content(f: &pb::Frame) -> Content {
    let data = match f.data.as_ref().and_then(|d| d.value.as_ref()) {
        Some(pb::sealable::Value::Plain(b)) => b.clone(),
        _ => Vec::new(),
    };
    (f.kind, data, f.event.clone(), f.id.clone())
}

/// Standard base64 with padding: a WebSocket key.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let at = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
        let n = (at(0) << 16) | (at(1) << 8) | at(2);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// What the log says about the connections (C1, C2, C4).
#[derive(Default)]
struct LogFacts {
    /// Accepted opens: connection to (owner, LSN).
    accepted: BTreeMap<String, (String, Lsn)>,
    /// Close inputs, without resends: connection to (LSN, close).
    closes: BTreeMap<String, Vec<(Lsn, pb::ConnectionClose)>>,
    /// Frame inputs, without resends: connection to (LSN, incoming seq).
    frames: BTreeMap<String, Vec<(Lsn, u64)>>,
    /// Frames the committed records send: (connection, seq) to their count.
    sent: BTreeMap<(String, u64), u32>,
}

impl LogFacts {
    fn read(records: &[(Lsn, Record)]) -> (LogFacts, Vec<String>) {
        use pb::connection_input::Event;
        let mut f = LogFacts::default();
        let mut problems = Vec::new();
        for (lsn, record) in records {
            let Record::TurnRecord(t) = record else {
                continue;
            };
            if committed(t) {
                for op in &t.connection_ops {
                    if let Some(pb::connection_op::Op::Send(_)) = &op.op {
                        for (id, seq) in op.connections.iter().zip(&op.seqs) {
                            *f.sent.entry((id.clone(), *seq)).or_default() += 1;
                        }
                    }
                }
            }
            let Some(pb::input::Kind::Connection(c)) =
                t.input.as_ref().and_then(|i| i.kind.as_ref())
            else {
                continue;
            };
            match &c.event {
                Some(Event::Open(_)) => {
                    let accepted = committed(t)
                        && matches!(
                            t.outcome.as_ref().and_then(|o| o.output.as_ref()),
                            Some(pb::outcome::Output::Accept(_))
                        );
                    if accepted
                        && let Some((_, first)) = f
                            .accepted
                            .insert(c.connection.clone(), (actor_name(t.actor.as_ref()), *lsn))
                    {
                        problems.push(format!(
                            "C1: {} accepted at lsn {first} and again at lsn {lsn}",
                            c.connection
                        ));
                    }
                }
                Some(Event::Frame(frame)) if c.resend_of.is_empty() => {
                    f.frames
                        .entry(c.connection.clone())
                        .or_default()
                        .push((*lsn, frame.seq));
                }
                Some(Event::Close(close)) if c.resend_of.is_empty() => {
                    f.closes
                        .entry(c.connection.clone())
                        .or_default()
                        .push((*lsn, close.clone()));
                }
                _ => {}
            }
        }
        (f, problems)
    }
}

impl World {
    /// Remembers where a node start recovered to (C5's re-runs).
    pub(super) fn conn_note_start(&self, applied: Lsn) {
        if self.cfg.connections.is_some() {
            self.st().conns.starts.push(applied);
        }
    }

    /// Starts the node's listener for opens; every open is served by a
    /// task of the node, so a crash drops it.
    pub(super) fn listen_for_opens(
        self: &Arc<Self>,
        env: &Env,
        node: &Arc<Node>,
        gateway: &Arc<Gateway>,
    ) {
        let (tx, mut rx) = mpsc::unbounded_channel::<OpenRequest>();
        self.st().conns.listener = Some(tx);
        let me = self.clone();
        let spawner = env.clone();
        let node = node.clone();
        let gateway = gateway.clone();
        env.spawn("conn-listener", async move {
            while let Some(open) = rx.recv().await {
                let me = me.clone();
                let env = spawner.clone();
                let node = node.clone();
                let gateway = gateway.clone();
                spawner.spawn("conn-open", async move {
                    me.serve_open(env, node, gateway, open).await;
                });
            }
        });
    }

    /// The server's side of an open: the gateway's handshake and the open
    /// turn, then the socket's writer, with its reader in another task.
    async fn serve_open(
        self: Arc<Self>,
        env: Env,
        node: Arc<Node>,
        gateway: Arc<Gateway>,
        open: OpenRequest,
    ) {
        let OpenRequest {
            req,
            owner,
            sse,
            mut reply,
        } = open;
        let answer = tokio::select! {
            biased;
            answer = gateway.open_connection(req) => answer,
            () = reply.closed() => {
                // The client left during the open: the server drops it, as
                // hyper drops the service future of a client that left.
                self.event(format!("an open of {owner} lost its client"));
                return;
            }
        };
        let Some(id) = answer.connection else {
            let _ = reply.send(OpenReply::Answer(answer.response));
            return;
        };
        let capacity = self.cfg.connections.map_or(4096, |w| w.socket_bytes);
        let socket = Arc::new(Socket::new(id.clone(), owner, sse, capacity));
        let writer_end = ServerEnd::new(socket.clone());
        if reply.send(OpenReply::Open(socket.clone())).is_err() {
            // The client left before the answer: nobody attaches.
            self.event(format!("{id} abandoned: its client left"));
            socket.state().ended = true;
            node.hub().abandon(&id);
            return;
        }
        let transport = Arc::new(SimTransport::default());
        if let Err(e) = node.hub().attach(&id, transport.clone()) {
            // Closed meanwhile: the server closes the socket.
            self.event(format!("{id} not attached: {:?}", e.code));
            {
                let mut s = socket.state();
                s.server_close = Some((1011, "not open".into()));
                s.ended = true;
            }
            socket.wake_all();
            return;
        }
        let me = self.clone();
        let reader_end = ServerEnd::new(socket.clone());
        let (n, s) = (node.clone(), socket.clone());
        env.spawn("conn-reader", async move {
            me.conn_reader(n, s, reader_end).await;
        });
        self.conn_writer(node, socket, transport, writer_end).await;
    }

    /// Moves the hub's frames into the socket while it has room, and ends
    /// the connection on the actor's or the host's close.
    async fn conn_writer(
        &self,
        node: Arc<Node>,
        socket: Arc<Socket>,
        transport: Arc<SimTransport>,
        end: ServerEnd,
    ) {
        self.write_loop(&node, &socket, &transport).await;
        end.disarm();
    }

    async fn write_loop(&self, node: &Arc<Node>, socket: &Arc<Socket>, transport: &SimTransport) {
        loop {
            let host_close = lock(&transport.host_close).take();
            if let Some((code, reason)) = host_close {
                return self.server_closes(node, socket, code, reason);
            }
            if socket.ended() {
                return;
            }
            loop {
                if socket.state().buffered >= socket.capacity {
                    break;
                }
                match node.hub().next(&socket.id) {
                    Some(Outgoing::Frame { seq, frame }) => {
                        self.check_frame(socket, seq, &frame);
                        {
                            let mut s = socket.state();
                            s.buffered += frame_bytes(&frame).max(1);
                            s.written.push(seq);
                            s.buffer.push_back((seq, frame));
                        }
                        socket.to_client.notify_one();
                        node.hub().written(&socket.id, seq);
                    }
                    Some(Outgoing::Close { code, reason }) => {
                        return self.server_closes(node, socket, code, reason);
                    }
                    None => break,
                }
            }
            tokio::select! {
                biased;
                () = transport.wake.notified() => {}
                () = socket.to_writer.notified() => {}
            }
        }
    }

    /// Hands the client's frames to the hub one at a time, and reports the
    /// client's close, or notices that it vanished.
    async fn conn_reader(&self, node: Arc<Node>, socket: Arc<Socket>, end: ServerEnd) {
        self.read_loop(&node, &socket).await;
        end.disarm();
    }

    async fn read_loop(&self, node: &Arc<Node>, socket: &Arc<Socket>) {
        enum Next {
            Ended,
            Frame(pb::Frame),
            Closed(Option<(u16, String)>),
            Vanished,
            Wait,
        }
        loop {
            let next = {
                let mut s = socket.state();
                if s.ended {
                    Next::Ended
                } else if let Some(frame) = s.outgoing.pop_front() {
                    Next::Frame(frame)
                } else {
                    match &s.client_close {
                        Some(Some(close)) => Next::Closed(Some(close.clone())),
                        Some(None) => Next::Vanished,
                        None => Next::Wait,
                    }
                }
            };
            match next {
                Next::Ended => return,
                Next::Frame(frame) => node.hub().incoming(&socket.id, frame).await,
                Next::Closed(close) => {
                    // An SSE stream has no close frame: its end is all.
                    let close = if socket.sse { None } else { close };
                    return self.client_closed(node, socket, close);
                }
                Next::Vanished => {
                    // Nothing tells the server at once: a reset, a failed
                    // write or the ping timeout, after a while.
                    let after = self
                        .work
                        .duration(Duration::from_millis(50), Duration::from_secs(3));
                    self.sleep(after).await;
                    if socket.sse || self.work.chance(0.5) {
                        self.client_closed(node, socket, None);
                    } else {
                        node.hub()
                            .close_host(&socket.id, pb::CloseCause::PingTimeout);
                    }
                    return;
                }
                Next::Wait => socket.to_reader.notified().await,
            }
        }
    }

    /// The server's close goes to the client, and the hub hears the end.
    fn server_closes(&self, node: &Node, socket: &Socket, code: u16, reason: String) {
        {
            let mut s = socket.state();
            if s.ended {
                return;
            }
            s.server_close = Some((code, reason.clone()));
            s.ended = true;
        }
        self.event(format!(
            "{} closed by the server: {code} {reason}",
            socket.id
        ));
        node.hub().finished(&socket.id, None);
        socket.wake_all();
    }

    /// The client closed or left: the hub hears the end.
    fn client_closed(&self, node: &Node, socket: &Socket, close: Option<(u16, String)>) {
        {
            let mut s = socket.state();
            if s.ended {
                return;
            }
            s.ended = true;
        }
        self.event(format!("{} closed by the client: {close:?}", socket.id));
        node.hub().finished(&socket.id, close);
        socket.wake_all();
    }

    /// C3, C4 and C6 for a frame the writer is about to put in the socket.
    fn check_frame(&self, socket: &Socket, seq: u64, frame: &pb::Frame) {
        let last = socket.state().written.last().copied();
        if let Some(last) = last
            && seq <= last
        {
            self.violation(format!("C4: {} got seq {seq} after seq {last}", socket.id));
        }
        let found = {
            let mut st = self.st();
            st.conns.stats.frames_out += 1;
            let found = st.conns.durable.lookup(&self.disk, &socket.id, seq);
            if found.is_none() {
                let begins = st
                    .conns
                    .durable
                    .begins
                    .iter()
                    .filter(|(_, actor)| **actor == socket.owner)
                    .map(|(id, _)| id.clone())
                    .collect();
                st.conns.unresolved.push(Unresolved {
                    conn: socket.id.clone(),
                    seq,
                    frame: frame.clone(),
                    begins,
                });
                return;
            }
            found
        };
        // A frame no durable record holds (yet) is resolved at the end: a
        // send-now, or a buffered frame given out early (C3).
        let Some(found) = found else {
            return;
        };
        let held: Vec<&DurableFrame> = found.iter().filter(|f| f.committed).collect();
        let Some(first) = held.first() else {
            return self.violation(format!(
                "C3: {} got seq {seq}, which only a failed turn's record holds",
                socket.id
            ));
        };
        if held.len() > 1 {
            self.violation(format!(
                "{} seq {seq} is sent by {} durable records",
                socket.id,
                held.len()
            ));
        }
        if first.actor != socket.owner {
            self.violation(format!(
                "C6: {} (owner {}) got seq {seq} from {}",
                socket.id, socket.owner, first.actor
            ));
        }
        if !same_frame(&first.frame, frame) {
            self.violation(format!(
                "C3: {} seq {seq} is not the frame its record holds",
                socket.id
            ));
        }
    }

    /// A client of the connections workload: `sessions` connections, one
    /// after the other.
    /// In a long run, sessions go on until the run has taken its steps.
    pub(super) async fn conn_client(self: Arc<Self>, client: usize) {
        if let Some(w) = self.cfg.connections {
            for session in 0.. {
                let done = match self.cfg.long {
                    Some(steps) => self.exec.polls() >= steps,
                    None => session >= w.sessions,
                };
                if done {
                    break;
                }
                self.conn_session(w, client, session).await;
                let pause = self
                    .work
                    .duration(Duration::from_millis(1), Duration::from_millis(200));
                self.sleep(pause).await;
            }
        }
        self.st().clients_done += 1;
    }

    async fn conn_session(&self, w: ConnWorkload, client: usize, session: u64) {
        let tag = format!("c{client}s{session}");
        let room = format!("r{}", self.work.below(w.rooms));
        let owner = format!("room/{room}");
        let sse = self.work.chance(w.sse_p);
        let mut query = format!("user={tag}");
        match self.work.below(100) {
            0..=4 => query.push_str("&deny=1"),
            5..=8 => query.push_str("&fail=1"),
            9..=23 => query.push_str("&call=1"),
            _ => {}
        }
        let mut headers: Vec<(String, String)> = Vec::new();
        let path = if sse {
            headers.push(("accept".into(), "text/event-stream".into()));
            format!("/room/{room}/events")
        } else {
            let mut key = [0u8; 16];
            self.work.fill(&mut key);
            headers.extend([
                ("upgrade".into(), "websocket".into()),
                ("connection".into(), "Upgrade".into()),
                ("sec-websocket-version".into(), "13".into()),
                ("sec-websocket-key".into(), base64(&key)),
            ]);
            if self.work.chance(0.5) {
                headers.push(("sec-websocket-protocol".into(), "room.v1".into()));
            }
            format!("/room/{room}/ws")
        };
        // TEST-NET-1 addresses: one per client.
        let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, (client % 250) as u8 + 1));
        let req = HttpRequest {
            method: "GET".into(),
            path,
            query,
            headers,
            body: Vec::new(),
            peer: Some(peer),
        };
        let Some(socket) = self.conn_open(&tag, req, &owner, sse).await else {
            return;
        };
        if !sse {
            let frames = 1 + self.work.below(w.frames);
            // Some clients stop reading halfway and go on sending: their
            // room's broadcasts pile up (a slow consumer, §5.6).
            let stall_at = self.work.chance(0.2).then(|| self.work.below(frames));
            for i in 0..frames {
                if socket.ended() {
                    break;
                }
                if stall_at == Some(i) {
                    socket.state().stalled = true;
                }
                let cmd = self.pick_command(&socket, &format!("{tag}f{i}"));
                self.client_send(&socket, &cmd);
                self.client_read(&socket);
                let gap = self
                    .work
                    .duration(Duration::from_micros(100), Duration::from_millis(20));
                self.sleep(gap).await;
                self.client_read(&socket);
                if cmd == "bye" {
                    break;
                }
            }
        }
        match self.work.below(100) {
            // A clean close (an SSE client just goes).
            0..=39 => {
                self.client_close(&socket, Some((1000, "done".into())));
                self.client_wait(&socket, Duration::from_secs(5), true)
                    .await;
            }
            // Gone without a close.
            40..=59 => self.client_close(&socket, None),
            // It stops reading and waits for the server to give up on it.
            60..=79 => {
                socket.state().stalled = true;
                let wait = self
                    .work
                    .duration(Duration::from_millis(100), Duration::from_secs(10));
                if !self.client_wait(&socket, wait, false).await {
                    self.client_close(&socket, None);
                }
            }
            // It stays a while, reading, then closes.
            _ => {
                let linger = self
                    .work
                    .duration(Duration::from_millis(10), Duration::from_secs(3));
                if !self.client_wait(&socket, linger, true).await {
                    self.client_close(&socket, Some((1000, "done".into())));
                    self.client_wait(&socket, Duration::from_secs(5), true)
                        .await;
                }
            }
        }
    }

    /// Opens a connection, trying again while the node is down, starting or
    /// stopping. `None`: refused, failed, or given up.
    async fn conn_open(
        &self,
        tag: &str,
        req: HttpRequest,
        owner: &str,
        sse: bool,
    ) -> Option<Arc<Socket>> {
        for attempt in 1..=50u32 {
            let listener = self.st().conns.listener.clone();
            let Some(listener) = listener else {
                self.sleep(Duration::from_millis(10)).await;
                continue;
            };
            let (tx, rx) = oneshot::channel();
            self.st().conns.stats.opens += 1;
            let open = OpenRequest {
                req: req.clone(),
                owner: owner.to_owned(),
                sse,
                reply: tx,
            };
            if listener.send(open).is_err() {
                self.sleep(Duration::from_millis(10)).await;
                continue;
            }
            // Mostly patient, sometimes a client that gives up during the
            // open (the server must abandon it, M24 §4.2).
            let patience = if self.work.chance(0.1) {
                self.work
                    .duration(Duration::from_millis(1), Duration::from_millis(50))
            } else {
                Duration::from_secs(60)
            };
            match self.clock_timeout(patience, rx).await {
                Some(Ok(OpenReply::Open(socket))) => {
                    self.event(format!(
                        "{tag} open {owner} -> {} (attempt {attempt})",
                        socket.id
                    ));
                    let mut st = self.st();
                    st.conns.stats.accepted += 1;
                    st.conns.sockets.insert(socket.id.clone(), socket.clone());
                    return Some(socket);
                }
                Some(Ok(OpenReply::Answer(resp))) => {
                    let body = String::from_utf8_lossy(&resp.body).into_owned();
                    self.event(format!("{tag} open {owner} -> {} {body}", resp.status));
                    if !matches!(resp.status, 429 | 503 | 504) {
                        self.st().conns.stats.refused += 1;
                        return None;
                    }
                }
                Some(Err(_)) => self.event(format!("{tag} open {owner} -> connection lost")),
                None => {
                    self.event(format!("{tag} open {owner} -> the client gave up"));
                    return None;
                }
            }
            let backoff = self
                .work
                .duration(Duration::from_millis(5), Duration::from_millis(60));
            self.sleep(backoff).await;
        }
        None
    }

    /// A random connection a client knows of, besides its own (of any
    /// room, open or not).
    fn random_peer(&self, me: &Socket) -> Option<String> {
        let st = self.st();
        let peers: Vec<&String> = st.conns.sockets.keys().filter(|id| **id != me.id).collect();
        if peers.is_empty() {
            return None;
        }
        let i = self.work.below(peers.len() as u64) as usize;
        peers.get(i).map(|id| (*id).clone())
    }

    fn pick_command(&self, socket: &Socket, tag: &str) -> String {
        match self.work.below(100) {
            0..=34 => format!("say {tag}"),
            35..=54 => format!("echo {tag}"),
            55..=59 => format!("binary {tag}"),
            60..=65 => match self.random_peer(socket) {
                Some(peer) => format!("send-to {peer} {tag}"),
                None => format!("say {tag}"),
            },
            66..=69 => match self.random_peer(socket) {
                Some(peer) => format!("kick {peer}"),
                None => format!("echo {tag}"),
            },
            70..=71 => "fail".into(),
            72..=73 => "trap".into(),
            74..=77 => "bye".into(),
            78..=81 => format!("stream {}", 1 + self.work.below(4)),
            82..=85 => format!("stream-safe {}", 1 + self.work.below(4)),
            86..=88 => match self.random_peer(socket) {
                Some(peer) => format!("now-to {peer} {tag}"),
                None => "stream 1".into(),
            },
            _ => format!("say {tag}"),
        }
    }

    fn client_send(&self, socket: &Socket, text: &str) {
        {
            let mut s = socket.state();
            if s.ended || s.client_close.is_some() {
                return;
            }
            s.outgoing.push_back(text_frame(text));
            s.sent += 1;
        }
        self.st().conns.stats.frames_sent += 1;
        socket.to_reader.notify_one();
    }

    /// Reads what the socket holds, unless the client stopped reading.
    fn client_read(&self, socket: &Socket) {
        {
            let mut s = socket.state();
            if s.stalled || s.buffer.is_empty() {
                return;
            }
            s.read += s.buffer.len() as u64;
            s.buffer.clear();
            s.buffered = 0;
        }
        socket.to_writer.notify_one();
    }

    fn client_close(&self, socket: &Socket, close: Option<(u16, String)>) {
        {
            let mut s = socket.state();
            if s.client_close.is_some() {
                return;
            }
            if close.is_none() {
                s.stalled = true;
            }
            s.client_close = Some(close);
        }
        socket.to_reader.notify_one();
        socket.to_writer.notify_one();
    }

    /// Waits at most `d` for the connection to end, reading meanwhile if
    /// `reading`; whether it ended.
    async fn client_wait(&self, socket: &Socket, d: Duration, reading: bool) -> bool {
        let deadline = self.exec.now() + d;
        loop {
            if reading {
                self.client_read(socket);
            }
            if socket.ended() {
                return true;
            }
            let now = self.exec.now();
            if now >= deadline {
                return false;
            }
            let sleep = self.sleep(deadline - now);
            tokio::select! {
                biased;
                () = socket.to_client.notified() => {}
                () = sleep => {}
            }
        }
    }

    /// A graceful stop (§5.9): every connection closes with 1012, then the
    /// process exits; nothing unsynced is lost and `state.db` stays.
    pub(super) async fn stop_gracefully(self: &Arc<Self>) {
        let node = self.st().node.clone();
        if let Some(node) = &node {
            self.event("graceful stop: the hub closes every connection");
            node.hub()
                .shutdown(node.hub().config().shutdown_grace)
                .await;
        }
        let (node_id, store) = {
            let mut st = self.st();
            st.crashes += 1;
            st.conns.stats.stops += 1;
            st.conn = None;
            st.conns.listener = None;
            if let Some(n) = st.node.take() {
                st.turns += n.probe.turns_run.load(std::sync::atomic::Ordering::Relaxed);
            }
            (st.node_id, st.store.take())
        };
        drop(node);
        let killed = self.exec.kill_node(node_id);
        if let Some(s) = store {
            s.sql.abort_turns();
            self.st().store = Some(s);
        }
        self.event(format!("stop node {node_id} ({killed} tasks)"));
    }

    /// C1, part one: once every client has left, the hub of the running
    /// node holds no connection (nothing leaks a slot).
    pub(super) async fn conn_settle(&self) {
        for _ in 0..300 {
            let live = self.st().node.as_ref().map(|n| n.hub().live());
            if live.is_none_or(|n| n == 0) {
                return;
            }
            self.sleep(Duration::from_millis(100)).await;
        }
        let (live, known) = {
            let st = self.st();
            let Some(node) = st.node.as_ref() else {
                return;
            };
            let known: Vec<String> = st
                .conns
                .sockets
                .values()
                .filter(|s| node.hub().queued_bytes(&s.id).is_some())
                .map(|s| {
                    let ss = s.state();
                    format!(
                        "{} (ended {}, broken {}, client close {:?}, stalled {}, server close {:?}, sent {}, written {})",
                        s.id, ss.ended, ss.broken, ss.client_close, ss.stalled, ss.server_close, ss.sent, ss.written.len()
                    )
                })
                .collect();
            (node.hub().live(), known)
        };
        if live > 0 {
            self.violation(format!(
                "C1: the hub holds {live} connections 30 s after every client left; of them its clients know {known:?}"
            ));
        }
    }

    /// A failed turn the workload asks for: an open with `fail=1` fails, a
    /// frame `fail` fails, a frame `trap` traps, and `send-to` or `kick` of
    /// a live connection of another room traps with `CONNECTION_NOT_HELD`.
    pub(super) fn expected_connection_failure(&self, t: &pb::TurnRecord) -> bool {
        use pb::connection_input::Event;
        if self.cfg.connections.is_none() {
            return false;
        }
        let Some(pb::input::Kind::Connection(c)) = t.input.as_ref().and_then(|i| i.kind.as_ref())
        else {
            return false;
        };
        let Some(o) = t.outcome.as_ref() else {
            return false;
        };
        let failed = o.kind == pb::OutcomeKind::Failed as i32;
        let trapped = o.kind == pb::OutcomeKind::Trap as i32;
        match &c.event {
            Some(Event::Open(open)) => {
                failed
                    && open
                        .request
                        .as_ref()
                        .is_some_and(|h| h.query_text().contains("fail=1"))
            }
            Some(Event::Frame(f)) => {
                let text = match f
                    .frame
                    .as_ref()
                    .and_then(|f| f.data.as_ref())
                    .and_then(|d| d.value.as_ref())
                {
                    Some(pb::sealable::Value::Plain(b)) => String::from_utf8_lossy(b).into_owned(),
                    _ => String::new(),
                };
                match text.split(' ').next().unwrap_or_default() {
                    "fail" => failed,
                    "trap" => trapped,
                    // A re-run's send-now without a recorded result.
                    "stream" => failed && o.message.contains("outcome is unknown"),
                    "send-to" | "kick" | "now-to" => {
                        trapped
                            && (o.error_code == "CONNECTION_NOT_HELD"
                                || o.message.contains("CONNECTION_NOT_HELD"))
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    }

    /// The end of a run (after the final restart): C1, C2, C4, C5 from the
    /// log, and C8.
    pub(super) async fn check_connections(&self, node: &Arc<Node>) {
        let Some(w) = self.cfg.connections else {
            return;
        };
        // The final start closes what was still open: wait for those turns.
        let mut open = Vec::new();
        for _ in 0..300 {
            open = match node.store().db().open_connections() {
                Ok(rows) => rows.into_iter().map(|r| r.id).collect(),
                Err(e) => return self.violation(format!("reading the open connections: {e}")),
            };
            if open.is_empty() {
                break;
            }
            self.sleep(Duration::from_millis(100)).await;
        }
        if !open.is_empty() {
            self.violation(format!(
                "C1: connections still open in state.db at the end: {open:?}"
            ));
        }
        let mut records = Vec::new();
        if let Err(e) = node
            .reader()
            .read(1, node.applied_lsn(), |c| {
                records.push((c.lsn, c.record));
                Ok(())
            })
            .await
        {
            return self.violation(format!("reading the log: {e}"));
        }
        let (facts, problems) = LogFacts::read(&records);
        for p in problems {
            self.violation(p);
        }
        self.check_dead_letters(node, &records);
        let sockets = self.st().conns.sockets.clone();
        self.check_closes(&facts);
        self.check_incoming(&facts, &sockets);
        self.check_written(&facts, &sockets);
        self.check_send_now(&records, &facts);
        if w.identity_replay {
            self.check_identity_replay(node, &records).await;
        }
        // What closed the connections, for the report line.
        let mut causes: BTreeMap<&str, usize> = BTreeMap::new();
        for (_, close) in facts.closes.values().flatten() {
            *causes
                .entry(kronik_proto::connection::cause_name(close.cause))
                .or_default() += 1;
        }
        let causes: Vec<String> = causes.iter().map(|(c, n)| format!("{c}:{n}")).collect();
        let mut st = self.st();
        let s = &st.conns.stats;
        let note = format!(
            " conns={}/{} refused={} frames-in={} frames-out={} stops={} closes={} now={}/{}/{}",
            s.accepted,
            s.opens,
            s.refused,
            s.frames_sent,
            s.frames_out,
            s.stops,
            causes.join(","),
            s.now_ok,
            s.now_unknown,
            s.now_reruns
        );
        st.notes.push_str(&note);
    }

    /// Every dead letter is a failure the workload asked for, and every
    /// failed frame or close turn is a dead letter (§6.5).
    fn check_dead_letters(&self, node: &Node, records: &[(Lsn, Record)]) {
        let letters = match node.store().db().dead_letters(0, usize::MAX) {
            Ok(d) => d,
            Err(e) => return self.violation(format!("reading the dead letters: {e}")),
        };
        let lsns: BTreeSet<Lsn> = letters.iter().map(|d| d.lsn).collect();
        for (lsn, record) in records {
            let Record::TurnRecord(t) = record else {
                continue;
            };
            let Some(pb::input::Kind::Connection(c)) =
                t.input.as_ref().and_then(|i| i.kind.as_ref())
            else {
                continue;
            };
            let frame_or_close = matches!(
                c.event,
                Some(pb::connection_input::Event::Frame(_) | pb::connection_input::Event::Close(_))
            );
            let dead = lsns.contains(lsn);
            if frame_or_close && !committed(t) && !dead {
                self.violation(format!("the failed turn at lsn {lsn} is not a dead letter"));
            }
            if dead && !self.expected_connection_failure(t) {
                self.violation(format!(
                    "unexpected dead letter at lsn {lsn}: {:?}",
                    t.outcome.as_ref().map(|o| &o.message)
                ));
            }
        }
        let connection_turns: BTreeSet<Lsn> = records
            .iter()
            .filter(|(_, r)| {
                matches!(r, Record::TurnRecord(t) if matches!(
                    t.input.as_ref().and_then(|i| i.kind.as_ref()),
                    Some(pb::input::Kind::Connection(_))
                ))
            })
            .map(|(lsn, _)| *lsn)
            .collect();
        for d in &letters {
            if !connection_turns.contains(&d.lsn) {
                self.violation(format!(
                    "unexpected dead letter at lsn {}, not a connection turn: {}",
                    d.lsn, d.message
                ));
            }
        }
    }

    /// C1: exactly one close per accepted connection, its last input, and
    /// nothing for a connection that was never accepted.
    fn check_closes(&self, f: &LogFacts) {
        for (id, (owner, opened)) in &f.accepted {
            let closes = f.closes.get(id).map_or(&[][..], Vec::as_slice);
            match closes {
                [] => self.violation(format!("C1: {id} of {owner} was never closed")),
                [(closed, _)] => {
                    if closed < opened {
                        self.violation(format!(
                            "C1: {id} closed at lsn {closed} before its accept at lsn {opened}"
                        ));
                    }
                    if let Some((lsn, seq)) = f
                        .frames
                        .get(id)
                        .and_then(|v| v.iter().find(|(lsn, _)| lsn > closed))
                    {
                        self.violation(format!(
                            "C1: {id} has frame {seq} at lsn {lsn} after its close at lsn {closed}"
                        ));
                    }
                }
                more => self.violation(format!(
                    "C1: {id} has {} close inputs, at lsn {:?}",
                    more.len(),
                    more.iter().map(|(lsn, _)| *lsn).collect::<Vec<_>>()
                )),
            }
        }
        for id in f.closes.keys().chain(f.frames.keys()) {
            if !f.accepted.contains_key(id) {
                self.violation(format!("C1: {id} has inputs but was never accepted"));
            }
        }
    }

    /// C2: incoming seqs 0..n-1 in log order, n at most what was sent.
    fn check_incoming(&self, f: &LogFacts, sockets: &BTreeMap<String, Arc<Socket>>) {
        for (id, frames) in &f.frames {
            for (i, (lsn, seq)) in frames.iter().enumerate() {
                if *seq != i as u64 {
                    self.violation(format!(
                        "C2: {id}'s frame input {i} (lsn {lsn}) has seq {seq}"
                    ));
                    break;
                }
            }
            let sent = sockets.get(id).map_or(0, |s| s.state().sent);
            if frames.len() as u64 > sent {
                self.violation(format!(
                    "C2: {id} has {} frame inputs, its client sent {sent}",
                    frames.len()
                ));
            }
        }
    }

    /// C4: a close that knows `frames_written` matches what the client got.
    fn check_written(&self, f: &LogFacts, sockets: &BTreeMap<String, Arc<Socket>>) {
        for (id, closes) in &f.closes {
            for (lsn, close) in closes {
                if !close.frames_written_known {
                    continue;
                }
                let got = sockets
                    .get(id)
                    .map(|s| s.state().written.clone())
                    .unwrap_or_default();
                let want: Vec<u64> = (0..close.frames_written).collect();
                if got != want {
                    self.violation(format!(
                        "C4: {id}'s close at lsn {lsn} says {} frames written, the client got seqs {got:?}",
                        close.frames_written
                    ));
                }
            }
        }
    }

    /// C5 (`send-now`), from the log and the frames the clients got: no
    /// re-run makes the call without a result recorded before its restart
    /// (I17), no execution sends one twice, and every frame a client got
    /// that no durable buffered record held is a `send-now`, with its seq or
    /// as an outcome-unknown send on its connection, whose `TurnBegin` was
    /// durable then (I14). A buffered frame given out early breaks C3.
    fn check_send_now(&self, records: &[(Lsn, Record)], f: &LogFacts) {
        const KIND: &str = "connection.send-now";
        let ok = pb::EffectStatus::Ok as i32;
        let unknown = pb::EffectStatus::OutcomeUnknown as i32;
        let timeout = pb::EffectStatus::Timeout as i32;
        let decode = |e: &pb::EffectRecord| -> Option<pb::ConnectionSendRequest> {
            let bytes = match e.request.as_ref().and_then(|r| r.value.as_ref()) {
                Some(pb::sealable::Value::Plain(b)) => b.as_slice(),
                _ => return None,
            };
            pb::ConnectionSendRequest::decode(bytes).ok()
        };
        let starts = self.st().conns.starts.clone();
        let mut begun: BTreeMap<String, Lsn> = BTreeMap::new();
        // (execution, ordinal) to the LSNs of their recorded results.
        let mut results: BTreeMap<(String, u32), Vec<Lsn>> = BTreeMap::new();
        // OK sends, both ways, and outcome-unknown ones.
        let mut performed: BTreeMap<(String, u32), BTreeSet<(String, u64)>> = BTreeMap::new();
        let mut sent_now: BTreeMap<(String, u64), BTreeMap<String, Content>> = BTreeMap::new();
        // Outcome-unknown sends: the seq each may have been sent with.
        let mut unknowns: BTreeMap<(String, u32), (String, u64, Content)> = BTreeMap::new();
        let mut note = |exec: &str, e: &pb::EffectRecord| {
            let Some(req) = decode(e) else {
                return;
            };
            let content = (
                req.kind,
                req.data.clone(),
                req.event.clone(),
                req.id.clone(),
            );
            if e.status == ok {
                performed
                    .entry((exec.to_owned(), e.ordinal))
                    .or_default()
                    .insert((req.connection.clone(), req.seq));
                sent_now
                    .entry((req.connection, req.seq))
                    .or_default()
                    .insert(exec.to_owned(), content);
            } else if e.status == unknown {
                unknowns.insert(
                    (exec.to_owned(), e.ordinal),
                    (req.connection, req.seq, content),
                );
            }
        };
        for (lsn, record) in records {
            match record {
                Record::TurnBegin(b) => {
                    begun.insert(b.execution_id.clone(), *lsn);
                }
                Record::EffectResult(r) => {
                    if let Some(e) = &r.effect
                        && e.kind == KIND
                    {
                        results
                            .entry((r.execution_id.clone(), e.ordinal))
                            .or_default()
                            .push(*lsn);
                        note(&r.execution_id, e);
                    }
                }
                Record::TurnRecord(t) => {
                    for e in t.effects.iter().filter(|e| e.kind == KIND) {
                        note(&t.execution_id, e);
                        // A re-run: its TurnBegin is from before a restart.
                        let Some(begin) = begun.get(&t.execution_id) else {
                            continue;
                        };
                        let Some(restart) = starts.iter().find(|s| **s >= *begin && **s < *lsn)
                        else {
                            continue;
                        };
                        self.st().conns.stats.now_reruns += 1;
                        let recorded = results
                            .get(&(t.execution_id.clone(), e.ordinal))
                            .is_some_and(|at| at.iter().any(|l| l <= restart));
                        // Without a result, a re-run must not call the hub.
                        if !recorded && (e.status == ok || e.status == timeout) {
                            self.violation(format!(
                                "C5: the re-run at lsn {lsn} of {} has send-now {} with status {} and no result recorded before the restart at lsn {restart}",
                                t.execution_id, e.ordinal, e.status
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
        for ((exec, ordinal), frames) in &performed {
            if frames.len() > 1 {
                self.violation(format!(
                    "C5: send-now {ordinal} of {exec} was performed {} times: {frames:?}",
                    frames.len()
                ));
            }
        }
        for ((conn, seq), execs) in &sent_now {
            if execs.len() > 1 || f.sent.contains_key(&(conn.clone(), *seq)) {
                self.violation(format!(
                    "C5: {conn} seq {seq} is a send-now of {:?} and also another frame",
                    execs.keys().collect::<Vec<_>>()
                ));
            }
        }
        // An outcome-unknown send keeps the seq it may have used: no later
        // frame of its connection takes it.
        for ((exec, ordinal), (conn, seq, _)) in &unknowns {
            if f.sent.contains_key(&(conn.clone(), *seq))
                || sent_now.contains_key(&(conn.clone(), *seq))
            {
                self.violation(format!(
                    "C5: {conn} seq {seq} of the outcome-unknown send-now {ordinal} of {exec} is also another frame"
                ));
            }
        }
        let unresolved = std::mem::take(&mut self.st().conns.unresolved);
        let mut claimed: BTreeSet<(String, u32)> = BTreeSet::new();
        for u in unresolved {
            let key = (u.conn.clone(), u.seq);
            let got = content(&u.frame);
            // A send-now with this seq.
            if let Some(execs) = sent_now.get(&key) {
                self.st().conns.stats.now_ok += 1;
                for (exec, sent) in execs {
                    if !u.begins.contains(exec) {
                        self.violation(format!(
                            "C5: {} got send-now seq {} of {exec} before its TurnBegin was durable",
                            u.conn, u.seq
                        ));
                    }
                    if *sent != got {
                        self.violation(format!(
                            "C5: {} seq {} is not the frame its send-now recorded",
                            u.conn, u.seq
                        ));
                    }
                }
                continue;
            }
            // A send whose turn crashed before its result was durable: the
            // re-run recorded it outcome-unknown, with the seq it may have
            // been sent with (I17).
            let explained = unknowns
                .iter()
                .find(|(k, (conn, seq, sent))| {
                    *conn == u.conn
                        && *seq == u.seq
                        && u.begins.contains(&k.0)
                        && !claimed.contains(*k)
                        && *sent == got
                })
                .map(|(k, _)| k.clone());
            if let Some(k) = explained {
                claimed.insert(k);
                self.st().conns.stats.now_unknown += 1;
                continue;
            }
            if f.sent.contains_key(&key) {
                self.violation(format!(
                    "C3: {} got seq {} ({}), a buffered frame, before its record was durable; {}; starts at lsn {starts:?}",
                    u.conn,
                    u.seq,
                    describe(&u.frame),
                    frame_history(records, &u.conn, u.seq)
                ));
            } else {
                self.violation(format!(
                    "C3: {} got seq {} ({}), which no durable record held then and no send-now sent; {}",
                    u.conn,
                    u.seq,
                    describe(&u.frame),
                    frame_history(records, &u.conn, u.seq)
                ));
            }
        }
    }

    /// C8: identity replay of the log, from before the first turn, is empty
    /// in both modes.
    async fn check_identity_replay(&self, node: &Arc<Node>, records: &[(Lsn, Record)]) {
        use kronik_fork::diff::{DiffOptions, Mode};
        let Some(first) = records
            .iter()
            .find(|(_, r)| matches!(r, Record::TurnBegin(_) | Record::TurnRecord(_)))
            .map(|(lsn, _)| *lsn)
        else {
            return;
        };
        let fork_lsn = first.saturating_sub(1);
        let to = node.applied_lsn();
        let original = match node.local_operator_authority() {
            Ok(a) => a,
            Err(e) => return self.violation(format!("C8: operator authority: {}", e.code)),
        };
        let index = match kronik_fork::ProductionIndex::load_from(node.reader(), None, fork_lsn, to)
            .await
        {
            Ok(index) => Arc::new(index),
            Err(e) => return self.violation(format!("C8: loading the production index: {e}")),
        };
        let code = node.code().clone();
        let fc = match kronik_fork::fork_kinds(
            &index,
            fork_lsn,
            |h| code.get(h).map_err(|e| e.to_string()),
            &[],
        ) {
            Ok(fc) => fc,
            Err(e) => return self.violation(format!("C8: the fork's kinds: {e}")),
        };
        let config = kronik_fork::config_at(&index, fork_lsn);
        let mut setup = kronik_fork::ReplaySetup::new(
            "f-dst".into(),
            index,
            fc.kinds,
            config,
            node.secrets().cloned(),
            original,
        );
        setup.record_limit = node.turn_record_limit();
        let options = DiffOptions {
            mode: Mode::Both,
            ..DiffOptions::default()
        };
        match kronik_fork::run(
            node.env(),
            Arc::new(setup),
            &options,
            2,
            None,
            fc.before,
            fc.after,
            &[],
        )
        .await
        {
            Ok(out) => {
                let s = &out.diff.summary;
                if s.changed || s.divergent_turns > 0 {
                    // The whole diff goes to a file; the violation names it.
                    let path =
                        std::env::temp_dir().join(format!("kronik-dst-c8-seed{}.json", self.seed));
                    let kept = match std::fs::write(&path, &out.bytes) {
                        Ok(()) => path.display().to_string(),
                        Err(e) => format!("(not kept: {e})"),
                    };
                    self.violation(format!(
                        "C8: identity replay from lsn {fork_lsn} to {to} is not empty: {} of {} turns diverge; the diff: {kept}",
                        s.divergent_turns, s.turns_prod
                    ));
                } else {
                    self.event(format!(
                        "C8: identity replay of {} root inputs is empty",
                        s.root_inputs
                    ));
                }
            }
            Err(e) => self.violation(format!("C8: identity replay failed: {e}")),
        }
    }
}
