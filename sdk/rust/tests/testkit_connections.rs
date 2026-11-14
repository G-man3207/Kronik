//! The testkit's connections against a real test host (`kronik test-host`)
//! and the room guest (tests/guests/room). They need a kronik binary in
//! `KRONIK_BIN`, so they are ignored by default: scripts/ci.sh sdks runs
//! them with `--ignored` after it builds one.

use kronik_sdk::testkit::{Close, TestHost};

#[test]
#[ignore = "needs a kronik binary in KRONIK_BIN"]
fn a_test_plays_the_client() {
    let wasm = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/room.wasm");
    let mut host = TestHost::with_components(&[wasm]).unwrap();
    let ada = host.open_connection("/room/lobby/ws?user=ada").unwrap();
    assert!(ada.accepted());
    assert_eq!(ada.response.status, 101);
    let welcome = host.frames_sent(&ada, true).unwrap();
    assert_eq!(welcome.frames.len(), 1);
    assert_eq!(
        welcome.frames[0].json::<serde_json::Value>().unwrap()["type"],
        "welcome"
    );

    host.send_frame(&ada, "echo hi").unwrap();
    host.send_frame(&ada, b"binary raw".as_slice()).unwrap();
    let sent = host.frames_sent(&ada, true).unwrap();
    let got: Vec<(&str, &[u8])> = sent
        .frames
        .iter()
        .map(|f| (f.kind.as_str(), f.body.as_slice()))
        .collect();
    assert_eq!(got, [("text", b"hi".as_slice()), ("binary", b"raw")]);

    host.send_frame(&ada, "say hello").unwrap();
    let message = &host.frames_sent(&ada, true).unwrap().frames[0];
    assert_eq!(
        (
            message.kind.as_str(),
            message.event.as_deref(),
            message.id.as_deref()
        ),
        ("event", Some("message"), Some("1"))
    );

    host.close_connection(&ada, Close::Host("restart".into()))
        .unwrap();
    assert_eq!(
        host.frames_sent(&ada, false).unwrap().closed,
        Some((1012, "restart".to_string()))
    );
    assert!(host.send_frame(&ada, "say late").is_err());

    let bob = host.open_connection("/room/lobby/ws?user=bob").unwrap();
    host.close_connection(&bob, Close::Client(4001, "done".into()))
        .unwrap();
    let cy = host.open_connection("/room/lobby/ws?user=cy").unwrap();
    host.close_connection(&cy, Close::Gone).unwrap();
    let closes = host.http("GET", "/room/lobby/closes", "").unwrap();
    let closes = closes.text().unwrap();
    for line in [
        format!("{} host 1012 restart", ada.id.as_deref().unwrap()),
        format!("{} client 4001 done", bob.id.as_deref().unwrap()),
        format!("{} client 1006 ", cy.id.as_deref().unwrap()),
    ] {
        assert!(closes.lines().any(|l| l == line), "{line:?} in {closes:?}");
    }

    let refused = host
        .open_connection("/room/lobby/ws?user=dee&deny=1")
        .unwrap();
    assert!(!refused.accepted());
    assert_eq!(refused.response.status, 403);
    assert!(host.send_frame(&refused, "say hi").is_err());
    let stream = host
        .open_connection_with("/room/lobby/events", "sse", &[("last-event-id", "0")])
        .unwrap();
    let ids: Vec<_> = host
        .frames_sent(&stream, false)
        .unwrap()
        .frames
        .into_iter()
        .map(|f| f.id)
        .collect();
    assert_eq!(ids, [Some("1".to_string())]);
}
