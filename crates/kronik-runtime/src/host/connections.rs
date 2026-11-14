//! The host side of `kronik:actor/connections` (M24,
//! docs/design/m24-connections.md §2.4 and §4). The interface is complete
//! from its first version (ADR 0113).
//!
//! `send`, `broadcast` and `close` are buffered in call order, like
//! `messaging.send`, and leave the turn through
//! [`crate::turn::TurnOutput::connection_ops`] only when it commits. A
//! turn may use the connection its open input names and the live
//! connections its actor accepted (ADR 0114, amended 2026-11-13). Another
//! actor's live connection traps with `CONNECTION_NOT_HELD`, and so does a
//! malformed id; an id that no live connection has (it closed, or none was
//! ever accepted) is recorded as dropped and never delivered. At the end of
//! the turn the buffered frames to live connections take their outgoing
//! seqs (§4.5): after the connection's `next_seq` as of the turn's start (0
//! for the connection the turn opens) and after the frames the turn sent
//! with `send-now`.

use std::collections::{BTreeMap, HashMap, HashSet};

use kronik_proto::log::v1 as pb;
use wasmtime::bail;

use super::connection_bindings::kronik::actor::connections as wit;
use super::{ConnectionView, TurnHost};

/// `send`, `broadcast` and `close` calls per turn (§4.11).
pub const MAX_OPERATIONS: usize = 10_000;
/// Frame targets per turn: every send's and broadcast's connections.
pub const MAX_TARGETS: usize = 100_000;
/// Buffered frame payload bytes per turn, counted once per operation.
pub const MAX_PAYLOAD_BYTES: usize = 16 << 20;
/// The longest close reason, in bytes (RFC 6455: 123 in a close frame).
pub const MAX_REASON_BYTES: usize = 123;

/// The trap message prefix of an id the turn does not hold; the turn's
/// error code is then `CONNECTION_NOT_HELD`.
pub const NOT_HELD: &str = "CONNECTION_NOT_HELD";

/// What a turn may do with a connection id (ADR 0114, amended).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Target {
    /// The connection this turn opens, or a live connection of its actor.
    Held(pb::ConnectionProtocol),
    /// No live connection has the id: recorded as dropped, never delivered.
    Dropped,
}

/// The connection state of one turn.
#[derive(Default)]
pub(crate) struct TurnConnections {
    /// The connection this turn's open input names: it is held, and it
    /// opens when the turn commits.
    pub(crate) opening: Option<(String, pb::ConnectionProtocol)>,
    /// The buffered operations, in call order; seqs come at the end.
    pub(crate) ops: Vec<pb::ConnectionOp>,
    /// The `connections` rows the turn looked at, as of its start.
    views: HashMap<String, Option<ConnectionView>>,
    /// Frames each connection got with `send-now` in this turn (`OK`).
    pub(crate) sent_now: HashMap<String, u64>,
    calls: usize,
    targets: usize,
    bytes: usize,
}

impl TurnConnections {
    /// The first outgoing seq of a frame to `conn` that this turn buffers.
    fn first_seq(&self, conn: &str) -> u64 {
        let base = match &self.opening {
            Some((id, _)) if id == conn => 0,
            _ => self
                .views
                .get(conn)
                .and_then(|v| v.as_ref())
                .map_or(0, |v| v.next_seq),
        };
        base + self.sent_now.get(conn).copied().unwrap_or(0)
    }

    /// The buffered operations with their seqs: target by target, in
    /// operation order (§4.5). A close takes none.
    pub(crate) fn take_ops(&mut self) -> Vec<pb::ConnectionOp> {
        let mut next: BTreeMap<String, u64> = BTreeMap::new();
        let mut ops = std::mem::take(&mut self.ops);
        for op in &mut ops {
            if !matches!(op.op, Some(pb::connection_op::Op::Send(_))) {
                continue;
            }
            op.seqs = op
                .connections
                .iter()
                .map(|c| {
                    let n = next.entry(c.clone()).or_insert_with(|| self.first_seq(c));
                    let seq = *n;
                    *n += 1;
                    seq
                })
                .collect();
        }
        ops
    }
}

/// Whether `code` may close a connection: 1000, 1001, 1003, 1007, 1008,
/// 1009, 1011, or an application code from 3000 to 4999.
pub fn valid_close_code(code: u16) -> bool {
    matches!(code, 1000 | 1001 | 1003 | 1007 | 1008 | 1009 | 1011) || (3000..=4999).contains(&code)
}

impl TurnHost {
    /// What this turn may do with `conn` (ADR 0114, amended): a held
    /// connection, or a dropped target. Another actor's live connection
    /// traps with `CONNECTION_NOT_HELD`, and a malformed id traps.
    pub(crate) fn target(&mut self, conn: &str) -> wasmtime::Result<Target> {
        if let Some((id, protocol)) = &self.conns.opening
            && id == conn
        {
            return Ok(Target::Held(*protocol));
        }
        if !kronik_proto::connection::valid_id(conn) {
            bail!(
                "connections: {conn:?} is not a connection id: c- and 32 lowercase hex \
                 characters"
            );
        }
        let view = match self.conns.views.get(conn) {
            Some(view) => *view,
            None => {
                let state = self.state_view()?.clone();
                let view = match state.connection(conn) {
                    Ok(view) => view,
                    Err(e) => return Err(self.host_failure(e)),
                };
                self.conns.views.insert(conn.to_owned(), view);
                view
            }
        };
        match view {
            Some(v) if v.owner_is_self => Ok(Target::Held(v.protocol)),
            Some(_) => bail!(
                "{NOT_HELD}: connection {conn:?} is another actor's; only the actor that \
                 accepted a connection sends on it or closes it ({} did not)",
                self.actor
            ),
            None => Ok(Target::Dropped),
        }
    }

    /// Counts an operation against the turn's limits (§4.11).
    fn charge_operation(&mut self, targets: usize, bytes: usize) -> wasmtime::Result<()> {
        let c = &mut self.conns;
        c.calls += 1;
        c.targets += targets;
        c.bytes += bytes;
        if c.calls > MAX_OPERATIONS {
            bail!(
                "connections: more than {MAX_OPERATIONS} send, broadcast and close calls in one turn"
            );
        }
        if c.targets > MAX_TARGETS {
            bail!("connections: more than {MAX_TARGETS} frame targets in one turn");
        }
        if c.bytes > MAX_PAYLOAD_BYTES {
            bail!("connections: more than {MAX_PAYLOAD_BYTES} bytes of frames in one turn");
        }
        Ok(())
    }

    /// The log form of a guest frame for connections of `protocols`, tagged
    /// with the turn's default subject, and its payload size.
    pub(crate) fn frame_to_pb(
        &self,
        frame: wit::Frame,
        protocols: &[pb::ConnectionProtocol],
    ) -> wasmtime::Result<(pb::Frame, usize)> {
        let (kind, data, event, id) = match frame {
            wit::Frame::Text(t) => (
                pb::frame::Kind::Text,
                t.into_bytes(),
                String::new(),
                String::new(),
            ),
            wit::Frame::Binary(b) => {
                if protocols.contains(&pb::ConnectionProtocol::Sse) {
                    bail!("connections: a binary frame cannot go to an SSE connection");
                }
                (pb::frame::Kind::Binary, b, String::new(), String::new())
            }
            wit::Frame::Event(e) => {
                for (name, value) in [("event", &e.event), ("id", &e.id)] {
                    if value.contains(['\r', '\n', '\0']) {
                        bail!("connections: an event's {name} must not contain CR, LF or NUL");
                    }
                }
                (pb::frame::Kind::Event, e.data.into_bytes(), e.event, e.id)
            }
        };
        let bytes = data.len() + event.len() + id.len();
        if bytes > self.limits.message_bytes {
            bail!(
                "connections: a frame of {bytes} bytes is over the kind's message limit of {}",
                self.limits.message_bytes
            );
        }
        Ok((
            pb::Frame {
                kind: kind as i32,
                data: Some(pb::Sealable {
                    subject: self.subject.clone(),
                    value: Some(pb::sealable::Value::Plain(data)),
                }),
                event,
                id,
            },
            bytes,
        ))
    }
}

impl wit::Host for TurnHost {
    async fn send(&mut self, conn: String, frame: wit::Frame) -> wasmtime::Result<()> {
        self.deny_in_describe("connections")?;
        let target = self.target(&conn)?;
        let protocols: &[pb::ConnectionProtocol] = match &target {
            Target::Held(p) => std::slice::from_ref(p),
            Target::Dropped => &[],
        };
        let (frame, bytes) = self.frame_to_pb(frame, protocols)?;
        self.charge_operation(1, bytes)?;
        let (connections, dropped) = match target {
            Target::Held(_) => (vec![conn], Vec::new()),
            Target::Dropped => (Vec::new(), vec![conn]),
        };
        self.conns.ops.push(pb::ConnectionOp {
            connections,
            seqs: Vec::new(),
            op: Some(pb::connection_op::Op::Send(frame)),
            dropped,
        });
        Ok(())
    }

    async fn broadcast(&mut self, conns: Vec<String>, frame: wit::Frame) -> wasmtime::Result<()> {
        self.deny_in_describe("connections")?;
        // The target limit before any id is looked up, counting the list as
        // given: a list past it costs no lookups (review M7).
        if self.conns.targets.saturating_add(conns.len()) > MAX_TARGETS {
            bail!("connections: more than {MAX_TARGETS} frame targets in one turn");
        }
        // The first occurrence of an id keeps its place.
        let mut seen = HashSet::new();
        let mut live = Vec::new();
        let mut dropped = Vec::new();
        let mut protocols = Vec::new();
        for conn in conns {
            if seen.contains(&conn) {
                continue;
            }
            match self.target(&conn)? {
                Target::Held(p) => {
                    protocols.push(p);
                    live.push(conn.clone());
                }
                Target::Dropped => dropped.push(conn.clone()),
            }
            seen.insert(conn);
        }
        let (frame, bytes) = self.frame_to_pb(frame, &protocols)?;
        let targets = live.len() + dropped.len();
        if targets == 0 {
            self.charge_operation(0, 0)?;
            return Ok(());
        }
        self.charge_operation(targets, bytes)?;
        self.conns.ops.push(pb::ConnectionOp {
            connections: live,
            seqs: Vec::new(),
            op: Some(pb::connection_op::Op::Send(frame)),
            dropped,
        });
        Ok(())
    }

    async fn close(&mut self, conn: String, code: u16, reason: String) -> wasmtime::Result<()> {
        self.deny_in_describe("connections")?;
        let target = self.target(&conn)?;
        if !valid_close_code(code) {
            bail!(
                "connections: close code {code} is not allowed; use 1000, 1001, 1003, 1007, \
                 1008, 1009, 1011 or 3000 to 4999"
            );
        }
        if reason.len() > MAX_REASON_BYTES {
            bail!(
                "connections: a close reason is at most {MAX_REASON_BYTES} bytes, this one {}",
                reason.len()
            );
        }
        self.charge_operation(1, reason.len())?;
        let (connections, dropped) = match target {
            Target::Held(_) => (vec![conn], Vec::new()),
            Target::Dropped => (Vec::new(), vec![conn]),
        };
        self.conns.ops.push(pb::ConnectionOp {
            connections,
            seqs: Vec::new(),
            op: Some(pb::connection_op::Op::Close(pb::ConnectionCloseRequest {
                code: u32::from(code),
                reason: Some(pb::Sealable {
                    subject: self.subject.clone(),
                    value: Some(pb::sealable::Value::Plain(reason.into_bytes())),
                }),
            })),
            dropped,
        });
        Ok(())
    }

    async fn send_now(
        &mut self,
        _conn: String,
        _frame: wit::Frame,
    ) -> wasmtime::Result<Result<(), wit::SendError>> {
        self.deny_in_describe("connections")?;
        bail!("NOT_IMPLEMENTED: connections.send-now is not available yet")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_codes() {
        for ok in [1000, 1001, 1003, 1007, 1008, 1009, 1011, 3000, 4000, 4999] {
            assert!(valid_close_code(ok), "{ok}");
        }
        for bad in [0, 999, 1002, 1004, 1005, 1006, 1010, 1012, 1015, 2999, 5000] {
            assert!(!valid_close_code(bad), "{bad}");
        }
    }

    #[test]
    fn seqs_follow_the_start_and_send_now_target_by_target() {
        let mut c = TurnConnections {
            opening: Some(("c-new".into(), pb::ConnectionProtocol::Websocket)),
            ..TurnConnections::default()
        };
        c.views.insert(
            "c-old".into(),
            Some(ConnectionView {
                owner_is_self: true,
                protocol: pb::ConnectionProtocol::Websocket,
                next_seq: 7,
                closing: false,
            }),
        );
        c.sent_now.insert("c-old".into(), 2);
        let send = |conns: &[&str]| pb::ConnectionOp {
            connections: conns.iter().map(|s| (*s).into()).collect(),
            seqs: vec![],
            op: Some(pb::connection_op::Op::Send(pb::Frame::default())),
            dropped: Vec::new(),
        };
        c.ops = vec![
            send(&["c-new"]),
            send(&["c-old", "c-new"]),
            pb::ConnectionOp {
                connections: vec!["c-old".into()],
                seqs: vec![],
                op: Some(pb::connection_op::Op::Close(
                    pb::ConnectionCloseRequest::default(),
                )),
                dropped: Vec::new(),
            },
            send(&["c-old"]),
        ];
        let ops = c.take_ops();
        let seqs: Vec<Vec<u64>> = ops.iter().map(|o| o.seqs.clone()).collect();
        assert_eq!(seqs, [vec![0], vec![9, 1], vec![], vec![10]]);
    }
}
