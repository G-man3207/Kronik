//! A grant's in-forks mode (ADR 0112): recorded denies an unmatched crypto
//! call, compute returns a signature, and the key is not in the guest
//! result, the log record, or the diff.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::sync::Arc;

use common::*;
use kronik_core::ids::ActorRef;
use kronik_effects::InForks;
use kronik_fork::diff::DiffOptions;
use kronik_fork::proposal::Proposals;
use kronik_metrics::SampleValue;
use kronik_proto::log::v1 as pb;
use prost::Message as _;

const KEY: &str = "fork-key-VALUE-91c4e2";

fn hmac_hex(data: &[u8]) -> String {
    kronik_effects::crypto::hmac_sha256(KEY.as_bytes(), data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn computations() -> u64 {
    kronik_metrics::snapshot()
        .into_iter()
        .find(|sample| {
            sample.def.name == "kronik_fork_crypto_computations_total"
                && sample
                    .labels
                    .iter()
                    .any(|(name, value)| *name == "algorithm" && value == "hmac-sha256")
        })
        .map(|sample| match sample.value {
            SampleValue::Counter(n) => n,
            _ => 0,
        })
        .unwrap_or(0)
}

fn reply_text(turn: &kronik_fork::ForkTurn) -> String {
    let Some(outcome) = turn.record.outcome.as_ref() else {
        return String::new();
    };
    let reply = match outcome.output.as_ref() {
        Some(pb::outcome::Output::Reply(message)) => message
            .body
            .as_ref()
            .and_then(|body| body.value.as_ref())
            .and_then(|value| match value {
                pb::sealable::Value::Plain(bytes) => {
                    Some(String::from_utf8_lossy(bytes).into_owned())
                }
                _ => None,
            })
            .unwrap_or_default(),
        _ => String::new(),
    };
    format!("{reply} {}", outcome.message)
}

fn assert_key_absent(label: &str, bytes: &[u8], text: &str) {
    assert!(
        !bytes
            .windows(KEY.len())
            .any(|window| window == KEY.as_bytes()),
        "{label}: the key is in the bytes"
    );
    assert!(!text.contains(KEY), "{label}: the key is in {text}");
}

fn grant(p: &Proc, mode: InForks) {
    p.rt.block_on(p.node.grant(
        "counter",
        "secret:signing",
        None,
        None,
        mode,
        audit(),
        false,
        p.owner(),
    ))
    .unwrap();
}

fn fork_hmac(p: &Proc, props: &Arc<Proposals>, fork: &str, data: &str) -> kronik_fork::ForkTurn {
    let message = pb::Message {
        name: "hmac".into(),
        content_type: "text/plain".into(),
        body: plain(&format!("signing\n{data}")),
        blobs: vec![],
        retained_compensation_source: None,
    };
    p.rt.block_on(props.fork_send(
        fork,
        ActorRef::parse("counter/a").unwrap(),
        message,
        p.owner(),
    ))
    .unwrap()
}

/// Recorded denies an unmatched call. Compute returns the signature. Neither
/// puts the production key in the guest result, the log record, or the diff.
#[test]
fn recorded_denies_an_unmatched_call_and_compute_does_not_leak_the_key() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    p.rt.block_on(p.node.secret_set(
        "signing",
        KEY.as_bytes().to_vec(),
        &audit(),
        false,
        p.owner(),
    ))
    .unwrap();
    grant(&p, InForks::Recorded);
    let before = computations();
    let fork_lsn = p.settle();
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    p.rt.block_on(props.create_fork(
        Some("recorded".into()),
        fork_lsn,
        false,
        audit(),
        false,
        p.owner(),
    ))
    .unwrap();

    let denied = fork_hmac(&p, &props, "recorded", "payload");
    let denied_text = reply_text(&denied);
    assert!(
        denied_text.contains("replay: no recording"),
        "{denied_text}"
    );
    assert!(
        !denied_text.contains(&hmac_hex(b"payload")),
        "{denied_text}"
    );
    assert_key_absent("recorded guest", denied_text.as_bytes(), &denied_text);
    let denied_record = denied.record.encode_to_vec();
    assert_key_absent(
        "recorded log record",
        &denied_record,
        &format!("{denied:?}"),
    );
    assert_eq!(computations(), before, "recorded must not compute");
    let crypto = denied
        .record
        .effects
        .iter()
        .find(|effect| effect.kind == "crypto.hmac-sha256")
        .unwrap();
    assert_eq!(crypto.status, pb::EffectStatus::Denied as i32, "{crypto:?}");
    assert!(crypto.response.is_none(), "{crypto:?}");

    // A matching recording is still returned under recorded, without a new
    // computation.
    let main = p.send("counter/b", "hmac", "signing\nsame");
    assert!(main.committed(), "{main:?}");
    let matched_at = p.settle();
    p.rt.block_on(props.create_fork(
        Some("matched".into()),
        matched_at,
        false,
        audit(),
        false,
        p.owner(),
    ))
    .unwrap();
    p.rt.block_on(props.fork_replay("matched", None, DiffOptions::default(), None, p.owner()))
        .unwrap();
    assert_eq!(computations(), before, "a recording is not a computation");
    let diff_bytes = p.rt.block_on(props.diff("matched", false, false)).unwrap();
    let diff_text = String::from_utf8_lossy(&diff_bytes);
    assert_key_absent("matched diff", &diff_bytes, &diff_text);
    let markdown =
        String::from_utf8(p.rt.block_on(props.diff("matched", true, false)).unwrap()).unwrap();
    assert_key_absent("matched markdown", markdown.as_bytes(), &markdown);

    grant(&p, InForks::Compute);
    let compute_at = p.settle();
    p.rt.block_on(props.create_fork(
        Some("compute".into()),
        compute_at,
        false,
        audit(),
        false,
        p.owner(),
    ))
    .unwrap();
    let signed = fork_hmac(&p, &props, "compute", "other");
    let signed_text = reply_text(&signed);
    let want = hmac_hex(b"other");
    assert!(signed_text.contains(&want), "{signed_text}");
    assert_key_absent("compute guest", signed_text.as_bytes(), &signed_text);
    let signed_record = signed.record.encode_to_vec();
    assert_key_absent("compute log record", &signed_record, &format!("{signed:?}"));
    assert!(
        computations() > before,
        "compute must count a fork computation"
    );
    let effect = signed
        .record
        .effects
        .iter()
        .find(|effect| effect.kind == "crypto.hmac-sha256")
        .unwrap();
    let response = effect
        .response
        .as_ref()
        .and_then(|seal| seal.value.as_ref())
        .and_then(|value| match value {
            pb::sealable::Value::Plain(bytes) => Some(bytes.as_slice()),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        response,
        kronik_effects::crypto::hmac_sha256(KEY.as_bytes(), b"other").as_slice()
    );
    assert_key_absent("compute effect response", response, &hex_of(response));

    p.rt.block_on(props.fork_replay("compute", None, DiffOptions::default(), None, p.owner()))
        .unwrap();
    let compute_diff = p.rt.block_on(props.diff("compute", false, false)).unwrap();
    let compute_diff_text = String::from_utf8_lossy(&compute_diff);
    assert_key_absent("compute diff", &compute_diff, &compute_diff_text);
    let compute_md =
        String::from_utf8(p.rt.block_on(props.diff("compute", true, false)).unwrap()).unwrap();
    assert_key_absent("compute markdown", compute_md.as_bytes(), &compute_md);
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
