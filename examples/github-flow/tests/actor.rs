//! The actor in an in-memory Kronik node: `cargo test` builds it and runs
//! these tests (with kronik on PATH, or KRONIK_BIN).

use kronik_sdk::testkit::TestHost;
use serde_json::{Value, json};

#[test]
fn every_key_counts_on_its_own() {
    let mut host = TestHost::start(env!("CARGO_MANIFEST_DIR")).unwrap();
    for n in 1..=3 {
        let res = host.http("POST", "/counter/alice/increment", "").unwrap();
        assert_eq!(res.status, 200);
        assert_eq!(res.json::<Value>().unwrap(), json!({ "n": n }));
    }
    let res = host.http("POST", "/counter/bob/increment", "").unwrap();
    assert_eq!(res.json::<Value>().unwrap(), json!({ "n": 1 }));
    assert_eq!(host.state_json::<u64>("counter/alice", "n").unwrap(), Some(3));
}
