#!/usr/bin/env bash
# Rebuilds the test guest components committed under tests/guests/*.wasm
# (test-actor builds, the leaky and room guests, plus webhook-relay-rs copied
# from the examples build).
# They are checked in so `cargo test` needs no wasm toolchain; rerun this after
# changing tests/guests/test-actor or wit/kronik-actor.wit.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../tests/guests/test-actor"
target=wasm32-wasip2/release/kronik_test_actor.wasm
cargo build --locked --release --target wasm32-wasip2 --target-dir target/counter
cargo build --locked --release --target wasm32-wasip2 --target-dir target/notes --features notes
cargo build --locked --release --target wasm32-wasip2 --target-dir target/fs-probe --features fs-probe
for v in step2 body-v2 fail-get fetch-extra schema1 calls-tally route-tally respond fail-line wasi-http; do
  cargo build --locked --release --target wasm32-wasip2 --target-dir "target/$v" --features "$v"
  cp "target/$v/$target" "../counter-$v.wasm"
done
for v in tally route-tally sql-call untagged; do
  cargo build --locked --release --target wasm32-wasip2 --target-dir "target/notes-$v" --features "notes,$v"
  cp "target/notes-$v/$target" "../notes-$v.wasm"
done
# leaky (I8 scrubbing tests): its own crate, kind `leaky`.
(cd ../leaky && cargo build --locked --release --target wasm32-wasip2 --target-dir target &&
    cp target/wasm32-wasip2/release/kronik_test_leaky.wasm ../leaky.wasm)
# room (M24 connections): its own crate, kind `room`, the world
# actor-connections; fmt2 changes only the message format and refuse refuses
# every open (replay tests), bare declares the same routes without the
# connection export (deploy check).
(cd ../room &&
    cargo build --locked --release --target wasm32-wasip2 --target-dir target/room &&
    cargo build --locked --release --target wasm32-wasip2 --target-dir target/fmt2 --features fmt2 &&
    cargo build --locked --release --target wasm32-wasip2 --target-dir target/refuse --features refuse &&
    cargo build --locked --release --target wasm32-wasip2 --target-dir target/bare --features bare &&
    cp target/room/wasm32-wasip2/release/kronik_test_room.wasm ../room.wasm &&
    cp target/fmt2/wasm32-wasip2/release/kronik_test_room.wasm ../room-fmt2.wasm &&
    cp target/refuse/wasm32-wasip2/release/kronik_test_room.wasm ../room-refuse.wasm &&
    cp target/bare/wasm32-wasip2/release/kronik_test_room.wasm ../room-bare.wasm)
# Rollback via replay (M13): a schema-1 build that migrates and also makes
# the extra GET, so the rolled-back code had a migration and effects the old
# code would not make.
cargo build --locked --release --target wasm32-wasip2 --target-dir target/schema1-extra --features "schema1,fetch-extra"
cp "target/schema1-extra/$target" ../counter-schema1-extra.wasm
# Standard fetch (M22): the wasi:http build that also GETs <url>/extra.
cargo build --locked --release --target wasm32-wasip2 --target-dir target/wasi-http-extra --features "wasi-http,fetch-extra"
cp "target/wasi-http-extra/$target" ../counter-wasi-http-extra.wasm
cp "target/counter/$target" ../counter.wasm
cp "target/notes/$target" ../notes.wasm
cp "target/fs-probe/$target" ../fs-probe.wasm
ls -l ../*.wasm
# webhook-relay-rs (DST webhook workload) and its body-v2 build (replay
# tests), from the examples build.
cd ../../..
scripts/build-examples.sh
cp examples/dist/webhook-relay.wasm examples/dist/webhook-relay-body-v2.wasm tests/guests/
ls -l tests/guests/webhook-relay*.wasm
