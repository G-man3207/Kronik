//! Test guest (kind `room`, M24): a chat room that holds WebSocket and SSE
//! connections, written directly against the WIT world `actor-connections`
//! (docs/design/m24-connections.md §14). Its state is key-value only:
//! `member/<conn>` = `<user> <ws|sse>`, `seq` = the room sequence,
//! `msg/<seq, 20 digits>` = `<user> <text>`, `close/<conn>` = the close
//! input's `<initiator> <code> <reason>`, `unknown` = how many `send-now`
//! outcomes `stream-safe` found unknown.
//!
//! Opening (`WEBSOCKET /room/{key}/ws`, `SSE /room/{key}/events`), with the
//! query `user=<id>` (the accept sets the subject `user:<id>`; default
//! `anon`, no subject):
//! - `deny=1` refuses with 403, `fail=1` fails the open turn, `call=1` first
//!   calls `room/callee` (`ping`), so the open turn has a `TurnBegin`;
//!   `now=1` calls `send-now` on the connection being opened, which traps;
//!   `headers=<n>` adds `n` headers to the accept;
//! - a WebSocket gets a `welcome` frame; an SSE stream gets the messages
//!   after its `Last-Event-ID` (at most 100);
//! - the other members get `joined`; the subprotocol `room.v1` is selected
//!   when offered (`pick=last`: the last offered one, whatever it is).
//!
//! Incoming frames are text commands:
//! - `say <text>`: the next room seq, stored and broadcast to every member as
//!   a `message` event (JSON data, `id` = seq), the sender included;
//! - `echo <text>`, `binary <text>`: back to the sender (a binary frame);
//! - `stream <n>`: `tok 0` .. `tok <n-1>` with `send-now`, then a buffered
//!   `done <n>`; an `outcome-unknown` fails the turn. `stream-safe <n>`
//!   handles it instead: it counts it in `unknown` and stops;
//! - `kick <conn>`: closes that connection (4000 `kicked`), `bye`: closes
//!   the sender's (1000 `bye`), `send-to <conn> <text>`: a frame to any id
//!   (ownership tests), `now-to <conn> <text>`: the same with `send-now`,
//!   answering the sender `now ok`, `now closed`, `now unknown` or
//!   `now denied <error>`;
//! - `burst <n> <size>`: `n` buffered frames of `size` characters to the
//!   sender, in one turn;
//! - `fail`: the turn fails; `trap`: the guest panics.
//!
//! The close handler records the close and broadcasts `left`. HTTP
//! `GET /room/{key}/{op}` and operator messages of the same names answer
//! `members`, `closes`, `unknown`, `seq` and `messages` (`after=<seq>`);
//! `POST /room/{key}/say` and the message `say` post as `http` and `op`; the
//! message `kick` closes the connection in its body, `spray <n>` broadcasts
//! to `n` well-formed ids that nobody holds; `ping` answers `pong`.
//!
//! Feature `fmt2` (room-fmt2.wasm) changes only the message format: `body`
//! instead of `text`.
//!
//! Feature `bare` (room-bare.wasm) builds the same manifest for the world
//! `actor`, without the `connection-handler` export: deploy must refuse it
//! (ADR 0113).

#[cfg(not(feature = "bare"))]
include!("room.rs");
#[cfg(feature = "bare")]
include!("bare.rs");
