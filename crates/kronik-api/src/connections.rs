//! The M24 connection endpoints (docs/design/m24-connections.md §12): list
//! and inspect long-lived WebSocket and SSE connections, and close one as
//! the operator.
//!
//! A view joins the connection's row in state.db (live, or closed until
//! retention's base passes its close) with what the hub knows of the ones
//! this node holds. Its only personal data is the subject, which needs
//! `pii:read` (§8); routes and counts are not personal data.

use std::collections::HashMap;

use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::ids::{ActorRef, TurnId};
use kronik_proto::connection as conn;
use kronik_proto::log::v1 as pb;
use kronik_sched::connections::LiveStats;
use kronik_store::db::{ConnectionRow, ConnectionState};

use crate::types::{
    Connection, ConnectionCloseRequest, ConnectionCloseResponse, ConnectionClosed, ConnectionFates,
    ConnectionFrames, ConnectionLive, ConnectionOpSummary, ConnectionOpened, ConnectionsResponse,
    TurnSummary,
};
use crate::{Api, ApiResponse, AuthorizedRequest, Query, Result, bad, internal, json, ok, reason};

/// The longest close frame reason (RFC 6455 §5.5: a control frame carries
/// at most 125 bytes, two of them the code).
const MAX_CLOSE_MESSAGE_BYTES: usize = 123;

/// The codes an operator may close with: the ones an actor may (§2.4).
fn valid_close_code(code: u16) -> bool {
    matches!(
        code,
        1000 | 1001 | 1003 | 1007 | 1008 | 1009 | 1011 | 3000..=4999
    )
}

/// How many target ids an operation's summary lists.
const OP_TARGETS_SHOWN: usize = 20;

/// History filtered to one connection reads its owner's turns in pages of
/// this many records ...
pub(crate) const HISTORY_SCAN_PAGE: usize = 200;
/// ... and at most this many records per request.
pub(crate) const HISTORY_SCAN: usize = 5000;

pub(crate) fn connection_id(id: &str) -> Result<&str> {
    if conn::valid_id(id) {
        Ok(id)
    } else {
        Err(bad(format!(
            "invalid connection id {id:?}: `c-` and 32 lowercase hex characters"
        )))
    }
}

fn not_found(id: &str, what: &str) -> ApiError {
    ApiError::new(
        ErrorCode::ConnectionNotFound,
        format!("connection {id} {what}"),
    )
}

/// A turn's connection operations as history shows them, without their
/// fates, which need the node.
pub(crate) fn op_summaries(t: &pb::TurnRecord) -> Vec<ConnectionOpSummary> {
    t.connection_ops
        .iter()
        .map(|op| {
            let targets: Vec<&String> = op.connections.iter().chain(&op.dropped).collect();
            let (name, kind, bytes, code) = match &op.op {
                Some(pb::connection_op::Op::Send(f)) => (
                    "send",
                    Some(conn::frame_kind_name(f.kind).to_owned()),
                    Some(conn::frame_bytes(f) as u64),
                    None,
                ),
                Some(pb::connection_op::Op::Close(c)) => ("close", None, None, Some(c.code)),
                None => ("unspecified", None, None, None),
            };
            ConnectionOpSummary {
                op: name.to_owned(),
                targets: targets.len() as u64,
                connections: targets
                    .into_iter()
                    .take(OP_TARGETS_SHOWN)
                    .cloned()
                    .collect(),
                kind,
                bytes,
                code,
                fates: None,
            }
        })
        .collect()
}

/// Whether a turn is one of connection `id`'s: its input is one of the
/// connection's, or it sent to it or closed it, now or buffered.
pub(crate) fn touches(t: &pb::TurnRecord, id: &str) -> bool {
    conn::input(t.input.as_ref()).is_some_and(|c| c.connection == id)
        || t.connection_ops
            .iter()
            .any(|op| op.connections.iter().chain(&op.dropped).any(|c| c == id))
        || t.effects.iter().any(|e| {
            e.kind == "connection.send-now" && e.target.strip_prefix("connection:") == Some(id)
        })
}

/// The connections that one history request looked up: a row (none when
/// retention removed it) and the hub's counts while this node holds it.
pub(crate) type FateCache = HashMap<String, Option<(ConnectionRow, Option<LiveStats>)>>;

impl Api {
    /// Adds the fates of a turn's sends to its summary (§4.7): the frame
    /// with seq `s` of a connection was written if `s` is below its count
    /// of frames written; queued after it while the writer has it; dropped
    /// otherwise, or when no live connection had the id. After a restart,
    /// the frames of turns up to the restart's LSN have an unknown fate,
    /// and later ones were dropped.
    pub(crate) fn fill_fates(
        &self,
        summary: &mut TurnSummary,
        t: &pb::TurnRecord,
        lsn: u64,
        cache: &mut FateCache,
    ) {
        for (s, op) in summary.connection_ops.iter_mut().zip(&t.connection_ops) {
            if !matches!(op.op, Some(pb::connection_op::Op::Send(_))) {
                continue;
            }
            let mut fates = ConnectionFates {
                dropped: op.dropped.len() as u64,
                ..ConnectionFates::default()
            };
            for (id, &seq) in op.connections.iter().zip(&op.seqs) {
                let entry = cache.entry(id.clone()).or_insert_with(|| {
                    let row = self.node.store().db().connection_any(id).ok().flatten()?;
                    let stats = self.node.hub().live_stats(id);
                    Some((row, stats))
                });
                let fate = match entry {
                    None => &mut fates.unknown,
                    Some((row, stats)) => match (row.closed_lsn, stats, row.frames_written) {
                        (None, Some(s), _) if seq < s.frames_written => &mut fates.written,
                        (None, Some(s), _) if seq < s.frames_written + s.queued_frames => {
                            &mut fates.queued
                        }
                        (None, Some(_), _) => &mut fates.dropped,
                        (None, None, _) => &mut fates.unknown,
                        (Some(_), _, Some(w)) if seq < w => &mut fates.written,
                        (Some(_), _, Some(_)) => &mut fates.dropped,
                        (Some(_), _, None) if row.restart_after_lsn.is_some_and(|r| lsn > r) => {
                            &mut fates.dropped
                        }
                        (Some(_), _, None) => &mut fates.unknown,
                    },
                };
                *fate += 1;
            }
            s.fates = Some(fates);
        }
    }

    fn turn_ref(&self, lsn: u64) -> String {
        TurnId {
            branch: self.node.branch().into(),
            lsn,
        }
        .to_string()
    }

    /// `GET /v1/connections`: open connections by default, in id order.
    pub(crate) async fn connections(&self, q: &Query, pii: bool) -> Result<ApiResponse> {
        let state = match q.get("state") {
            None | Some("open") => ConnectionState::Open,
            Some("closed") => ConnectionState::Closed,
            Some("all") => ConnectionState::All,
            Some(other) => {
                return Err(bad(format!(
                    "state must be open, closed or all, not {other:?}"
                )));
            }
        };
        let actor = match (q.get("actor"), q.get("kind")) {
            (Some(_), Some(_)) => return Err(bad("give actor or kind, not both")),
            (Some(a), None) => Some(ActorRef::parse(a).map_err(|e| bad(e.to_string()))?),
            (None, _) => None,
        };
        let owner = match (&actor, q.get("kind")) {
            (Some(a), _) => Some((a.kind.as_str(), Some(a.key.as_str()))),
            (None, Some(kind)) => Some((kind, None)),
            (None, None) => None,
        };
        let after = match q.get("after") {
            Some(a) => connection_id(a)?,
            None => "",
        };
        let limit = q.limit()?;
        let rows = self
            .node
            .store()
            .db()
            .connections(owner, state, after, limit)
            .map_err(internal)?;
        let mut connections = Vec::with_capacity(rows.len());
        for row in &rows {
            connections.push(self.connection_view(row, pii).await);
        }
        let next = (rows.len() == limit)
            .then(|| rows.last().map(|r| r.id.clone()))
            .flatten();
        ok(&ConnectionsResponse { connections, next })
    }

    /// `GET /v1/connections/{id}`.
    pub(crate) async fn connection(&self, id: &str, pii: bool) -> Result<ApiResponse> {
        let id = connection_id(id)?;
        let row = self
            .node
            .store()
            .db()
            .connection_any(id)
            .map_err(internal)?
            .ok_or_else(|| not_found(id, "does not exist"))?;
        ok(&self.connection_view(&row, pii).await)
    }

    /// `POST /v1/connections/{id}/close`: the operator closes an open
    /// connection held by this node, with a code and a message for the
    /// client; the reason goes into the close input's audit (I12).
    pub(crate) async fn close_connection(
        &self,
        req: &AuthorizedRequest,
        id: &str,
        pii: bool,
    ) -> Result<ApiResponse> {
        // The reason first, as for every mutation (I12).
        let r: ConnectionCloseRequest = json(&req.body)?;
        reason(&r.reason)?;
        let id = connection_id(id)?;
        let code = r.code.unwrap_or(1008);
        if !valid_close_code(code) {
            return Err(bad(format!(
                "code {code} is not a close code an operator can send: use 1000, 1001, 1003, \
                 1007, 1008, 1009, 1011, or 3000 to 4999"
            )));
        }
        if r.message.len() > MAX_CLOSE_MESSAGE_BYTES {
            return Err(bad(format!(
                "message must be at most {MAX_CLOSE_MESSAGE_BYTES} bytes, not {}",
                r.message.len()
            )));
        }
        let row = self
            .node
            .store()
            .db()
            .connection(id)
            .map_err(internal)?
            .ok_or_else(|| not_found(id, "is not open"))?;
        if !self.node.hub().live_stats(id).is_some_and(|s| s.open) {
            return Err(not_found(id, "is not open on this node"));
        }
        if !r.dry_run {
            // The mutation's record is an AuditEvent written before the
            // close, so that its reason is durable whatever happens to the
            // connection next (a stop before its close input, say); a close
            // that then fails adds `connection.close.failed`. The close
            // input also carries the audit, for history and replay.
            let audit = self.audit(req, r.reason.clone()).await;
            let hub = self.node.hub().clone();
            let (conn, message) = (id.to_owned(), r.message.clone());
            self.intent(
                req,
                "connection.close",
                id,
                &[("actor", row.actor.to_string()), ("code", code.to_string())],
                &r.reason,
                move || hub.close_operator(&conn, code, &message, audit),
            )
            .await?;
        }
        let connection = self.connection_view(&row, pii).await;
        ok(&ConnectionCloseResponse {
            dry_run: r.dry_run,
            connection,
        })
    }

    /// A connection as the API shows it: its row, the open turn's logical
    /// time, and the hub's counts while this node holds it.
    async fn connection_view(&self, row: &ConnectionRow, pii: bool) -> Connection {
        let stats = self.node.hub().live_stats(&row.id);
        // The open turn's record; gone once retention removed it.
        let logical_time_ms = match self.node.read_record(row.opened_lsn).await {
            Ok(Some(c)) => c.record.turn().map(|t| t.logical_time_ms),
            _ => None,
        };
        let out = row.next_seq;
        let (written, queued, dropped, unknown) = match (row.closed_lsn, stats, row.frames_written)
        {
            // Held here: written by its writer, waiting in its queue, or
            // dropped by a close.
            (None, Some(s), _) => {
                let written = s.frames_written.min(out);
                let queued = s.queued_frames.min(out - written);
                (written, queued, out - written - queued, 0)
            }
            // Closed with the count of frames written.
            (Some(_), _, Some(w)) => (w.min(out), 0, out - w.min(out), 0),
            // A restart ended it: whether its frames were written died with
            // the process. A live row that this node does not hold is one
            // whose restart close is not recorded yet.
            _ => (0, 0, 0, out),
        };
        let state = if row.closed_lsn.is_some() {
            "closed"
        } else if row.closing_lsn.is_some() || !stats.is_some_and(|s| s.open) {
            "closing"
        } else {
            "open"
        };
        Connection {
            id: row.id.clone(),
            actor: row.actor.to_string(),
            protocol: conn::protocol_name(row.protocol).to_owned(),
            route: row.route.clone(),
            state: state.to_owned(),
            opened: ConnectionOpened {
                turn_id: self.turn_ref(row.opened_lsn),
                logical_time_ms,
            },
            closed: row.closed_lsn.map(|lsn| {
                let cause = row.cause.unwrap_or(0);
                ConnectionClosed {
                    turn_id: self.turn_ref(lsn),
                    initiator: conn::initiator(cause).to_owned(),
                    cause: conn::cause_name(cause).to_owned(),
                    code: row.code.unwrap_or(0),
                }
            }),
            frames: ConnectionFrames {
                incoming: row.frames_in,
                out,
                written,
                queued,
                dropped,
                unknown,
            },
            live: stats.map(|s| ConnectionLive {
                queued_bytes: s.queued_bytes as u64,
            }),
            subject: if pii { row.subject.clone() } else { None },
        }
    }
}
