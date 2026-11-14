# M24 connections fixture

The log of a short session of the room test guest (`tests/guests/room`),
written by the version that introduced long-lived connections
(docs/design/m24-connections.md §6.7): two WebSocket opens with their
accepts, frames, a broadcast, a `send-now` stream, an actor's close, and a
crash followed by the restart close of the connection left open.

`crates/kronik-sched/tests/connections_fixture.rs` reads it, applies it and
rebuilds it, and checks the `connections` table. Every later version must
pass that test unchanged. Regenerate it only for a format change, with
`KRONIK_WRITE_FIXTURES=1 cargo test -p kronik-sched --test
connections_fixture`.
