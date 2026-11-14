//! M25 in the test host (`kronik test-host`, which the SDKs' test kits
//! run): a body above the threshold of an actor that imports `blobs` is a
//! blob, and a blob answer comes back whole with its reference.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use base64::Engine as _;
use kronik_gateway::HttpRequest;
use kronik_testhost::{Options, TestHost};

const MEDIA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/media.wasm");

fn post(path: &str, query: &str, body: Vec<u8>) -> HttpRequest {
    HttpRequest {
        method: "POST".into(),
        path: path.into(),
        query: query.into(),
        headers: Vec::new(),
        body,
        peer: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blob_bodies_and_answers_in_the_test_host() {
    let env = kronik_core::env::Env::real(tokio::runtime::Handle::current());
    let host = TestHost::start(env.spawner.clone(), Options::default())
        .await
        .unwrap();
    let wasm = base64::engine::general_purpose::STANDARD.encode(std::fs::read(MEDIA).unwrap());
    let body = format!(r#"{{"wasm_base64": "{wasm}", "reason": "test"}}"#);
    let res = host
        .api("POST", "/v1/deployments", "", body.into_bytes())
        .await;
    assert_eq!(res.status, 200, "{}", String::from_utf8_lossy(&res.body));
    let res = host
        .api(
            "POST",
            "/v1/limits",
            "",
            br#"{"kind": "media", "fuel": 2000000000, "reason": "test"}"#.to_vec(),
        )
        .await;
    assert_eq!(res.status, 200, "{}", String::from_utf8_lossy(&res.body));

    let upload: Vec<u8> = (0..3_000_000u32).map(|i| (i % 241) as u8).collect();
    let (res, blob) = host
        .http_with_blob(post("/media/a/info", "", upload.clone()))
        .await;
    assert_eq!(
        String::from_utf8_lossy(&res.body),
        format!(
            "blob b3:{} {}",
            blake3::hash(&upload).to_hex(),
            upload.len()
        )
    );
    assert!(blob.is_none(), "an inline answer");
    let (res, small) = host
        .http_with_blob(post("/media/a/info", "", b"tiny".to_vec()))
        .await;
    assert_eq!(
        (String::from_utf8_lossy(&res.body).as_ref(), small),
        ("inline 4", None)
    );

    let size = 2_000_000u64;
    let (res, blob) = host
        .http_with_blob(post("/media/a/write", &format!("size={size}"), Vec::new()))
        .await;
    assert_eq!(res.status, 200);
    let expected: Vec<u8> = (0..size).map(|i| ((i * 31 + 7) % 251) as u8).collect();
    assert!(res.body == expected, "the answer's bytes");
    let blob = blob.expect("a blob answer");
    assert_eq!(
        (blob.hash, blob.size),
        (format!("b3:{}", blake3::hash(&expected).to_hex()), size)
    );
}
