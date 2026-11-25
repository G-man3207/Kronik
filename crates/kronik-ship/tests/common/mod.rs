//! Helpers shared by the shipping and restore integration tests.

#![allow(dead_code)]

use kronik_proto::log::v1 as pb;
use tokio::runtime::Runtime;

pub fn rt() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

pub fn audit() -> pb::Audit {
    pb::Audit {
        token_id: "test".into(),
        reason: "test".into(),
        wall_time_ms: 0,
    }
}

pub fn tempdir(prefix: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap()
}

pub fn guest(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../../tests/guests/{name}.wasm",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

pub fn message(name: &str, body: &str) -> pb::Message {
    pb::Message {
        name: name.into(),
        content_type: "text/plain".into(),
        body: Some(pb::Sealable {
            subject: None,
            value: Some(pb::sealable::Value::Plain(body.as_bytes().to_vec())),
        }),
        blobs: vec![],
        retained_compensation_source: None,
    }
}

/// The S3 URL of this run (`scripts/s3.sh` exports it), or `None` to skip.
/// With `KRONIK_TEST_S3=require` (the `s3` step of `scripts/ci.sh`) a
/// missing URL fails the test, so that a run never passes by skipping.
pub fn s3_url() -> Option<String> {
    match std::env::var("KRONIK_TEST_S3_URL") {
        Ok(url) => Some(url),
        Err(_) => {
            assert_ne!(
                std::env::var("KRONIK_TEST_S3").as_deref(),
                Ok("require"),
                "KRONIK_TEST_S3=require, but KRONIK_TEST_S3_URL is not set: run this test under scripts/s3.sh"
            );
            eprintln!("KRONIK_TEST_S3_URL is not set; run scripts/s3.sh for this test");
            None
        }
    }
}
