//! M25 slice B9 (docs/design/m25-streaming-bodies.md §7.6) through the
//! node: standard `fetch` with blob bodies, with the test guest
//! `counter-wasi-http-blobs`, which uses `wasi:http` and imports
//! `kronik:actor/blobs`. A 3 MiB request body goes to the store as the
//! guest writes it, is recorded as its reference and streamed to the peer;
//! the peer's echo, above the threshold, is a blob the guest reads back
//! through the body's stream.

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::io::Write as _;
use std::path::Path;
use std::sync::{Arc, Mutex};

use common::{Proc, audit, http, start_proc};
use kronik_core::ids::ActorRef;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_sched::{BlobsConfig, NodeConfig, TurnResult};

const GUEST: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter-wasi-http-blobs.wasm"
);

/// A node with a blob store, the guest deployed as kind `counter` with a
/// 64 KiB threshold, and `http:127.0.0.1` granted.
fn start(dir: &Path) -> Proc {
    let p = start_proc(
        dir,
        NodeConfig {
            concurrency: 8,
            blobs: Some(BlobsConfig::default()),
            ..NodeConfig::default()
        },
    );
    let owner = p.node.local_operator_authority().unwrap();
    let code = std::fs::read(GUEST).unwrap();
    p.rt.block_on(async {
        p.node
            .deploy(&code, audit(), false, owner.clone())
            .await
            .unwrap();
        p.node
            .set_limits(
                pb::Limits {
                    kind: "counter".into(),
                    blob_threshold_bytes: Some(65_536),
                    fuel: Some(2_000_000_000),
                    ..Default::default()
                },
                audit(),
                false,
                owner.clone(),
            )
            .await
            .unwrap();
        p.node
            .grant(
                "counter",
                "http:127.0.0.1",
                None,
                None,
                kronik_effects::InForks::Recorded,
                audit(),
                false,
                owner,
            )
            .await
            .unwrap();
    });
    p
}

/// The requests a peer got: head and body.
type Got = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

/// An HTTP peer that answers every request with its body; keeps what it
/// got.
fn echo() -> (String, Got) {
    let got = Arc::new(Mutex::new(Vec::new()));
    let seen = got.clone();
    let addr = http::serve(move |req, stream| {
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            req.body.len()
        );
        let _ = stream.write_all(&req.body);
        seen.lock().unwrap().push((req.head, req.body));
    });
    (addr, got)
}

impl Proc {
    fn send(&self, op: &str, text: &str) -> TurnResult {
        let msg = pb::Message {
            name: op.into(),
            content_type: "text/plain".into(),
            body: Some(pb::Sealable::new_plain(None, text.as_bytes().to_vec())),
            blobs: vec![],
            retained_compensation_source: None,
        };
        let owner = self.node.local_operator_authority().unwrap();
        self.rt
            .block_on(self.node.send(
                ActorRef::parse("counter/a").unwrap(),
                msg,
                audit(),
                false,
                owner,
            ))
            .unwrap()
            .unwrap()
    }

    fn record(&self, r: &TurnResult) -> pb::TurnRecord {
        match self
            .rt
            .block_on(self.node.read_record(r.turn_id.lsn))
            .unwrap()
            .unwrap()
            .record
        {
            Record::TurnRecord(t) => t,
            other => panic!("{other:?}"),
        }
    }
}

fn reply(r: &TurnResult) -> String {
    match &r.outcome.output {
        Some(pb::outcome::Output::Reply(m)) => match m.body.as_ref().and_then(|b| b.value.as_ref())
        {
            Some(pb::sealable::Value::Plain(b)) => String::from_utf8_lossy(b).into_owned(),
            other => panic!("{other:?}"),
        },
        other => panic!("{:?}: {other:?}", r.outcome),
    }
}

/// The value of `key=` in a `wbig` reply.
fn field<'a>(reply: &'a str, key: &str) -> &'a str {
    reply
        .split(' ')
        .find_map(|word| word.strip_prefix(key))
        .unwrap_or_else(|| panic!("no {key} in {reply}"))
}

/// The guest's request body pattern (`wbig`).
fn pattern(i: u64) -> u8 {
    ((i % 251) as u8) ^ ((i / 251) as u8)
}

/// A 3 MiB request body through `wasi:http`: recorded as its blob's
/// reference, which the store holds, streamed to the peer with its length;
/// the echo, above the threshold, is recorded as a blob and read back whole
/// by the guest.
#[test]
fn a_wasi_http_exchange_above_the_threshold_goes_through_the_blob_store() {
    const SIZE: u64 = 3 << 20;
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    let (addr, got) = echo();
    let r = p.send("wbig", &format!("POST http://{addr}/echo\nsize={SIZE}"));
    let text = reply(&r);
    assert!(text.starts_with("200 "), "{text}");
    assert_eq!(field(&text, "sent="), field(&text, "got="), "{text}");
    assert_eq!(field(&text, "end="), "eof", "{text}");
    let expected: Vec<u8> = (0..SIZE).map(pattern).collect();
    // The peer got the whole body, with its length.
    let (head, body) = got.lock().unwrap().pop().unwrap();
    assert!(
        head.to_ascii_lowercase()
            .contains(&format!("content-length: {SIZE}")),
        "{head}"
    );
    assert!(body == expected, "the peer got {} other bytes", body.len());
    // The record holds the references, the store their bytes.
    let record = p.record(&r);
    assert_eq!(record.effects.len(), 1);
    let effect = &record.effects[0];
    assert_eq!(effect.status, pb::EffectStatus::Ok as i32);
    let Some(pb::sealable::Value::Plain(payload)) =
        effect.request.as_ref().and_then(|r| r.value.as_ref())
    else {
        panic!("{effect:?}")
    };
    let request: pb::HttpEffectRequest = prost::Message::decode(payload.as_slice()).unwrap();
    assert!(request.body.is_empty());
    let sent = request.body_blob.expect("the request body's blob");
    assert_eq!(sent.size, SIZE);
    assert_eq!(
        sent.hash,
        format!("b3:{}", blake3::hash(&expected).to_hex())
    );
    let Some(pb::sealable::Value::Plain(payload)) =
        effect.response.as_ref().and_then(|r| r.value.as_ref())
    else {
        panic!("{effect:?}")
    };
    let response: pb::HttpEffectResponse = prost::Message::decode(payload.as_slice()).unwrap();
    assert!(response.body.is_empty());
    let echoed = response.body_blob.expect("the response body's blob");
    assert_eq!(echoed, sent, "the same bytes are the same blob");
    assert!(effect.blobs.contains(&sent), "{:?}", effect.blobs);
    assert!(p.stored(dir.path(), &sent) == expected);
}
