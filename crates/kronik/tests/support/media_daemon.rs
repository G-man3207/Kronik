//! The `media` test guest on a `common::Daemon`, for blobs.rs and
//! blobs_kill.rs (both run on the test machine of
//! scripts/acceptance-m26.sh).

#![allow(dead_code)]

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

use base64::Engine as _;
use serde_json::{Value, json};

use crate::common::Daemon;

const MEDIA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/media.wasm");

/// The daemon: this build's, or `KRONIK_M26_KRONIK` (the test machine runs
/// the test binary and a static `kronik` away from the checkout,
/// scripts/acceptance-m26.sh).
pub fn kronik_bin() -> PathBuf {
    std::env::var_os("KRONIK_M26_KRONIK").map_or_else(
        || PathBuf::from(env!("CARGO_BIN_EXE_kronik")),
        PathBuf::from,
    )
}

/// The test guest: the checkout's, or `KRONIK_M26_MEDIA`.
pub fn media_wasm() -> Vec<u8> {
    let path =
        std::env::var_os("KRONIK_M26_MEDIA").map_or_else(|| PathBuf::from(MEDIA), PathBuf::from);
    std::fs::read(path).unwrap()
}

impl Daemon {
    pub fn media(&self) {
        let wasm = base64::engine::general_purpose::STANDARD.encode(media_wasm());
        self.api(
            "POST",
            "/v1/deployments",
            json!({"wasm_base64": wasm, "reason": "blob crash test"}),
        );
    }

    /// The text answer of `POST /media/a/<op>?<query>`, which must be 200.
    pub fn ok(&self, op: &str, query: &str) -> String {
        let (status, body) = call(&self.http, &request(op, query));
        let text = String::from_utf8_lossy(&body).into_owned();
        assert_eq!(status, 200, "{op}?{query}: {text}");
        text
    }

    /// The hashes `media/a` holds (M26 §12).
    pub fn holds(&self) -> Vec<String> {
        let (status, v) = self
            .try_api("GET", "/v1/actors/media/a/blobs", Value::Null)
            .unwrap_or_else(|| panic!("holds failed: {}", self.log()));
        assert_eq!(status, 200, "{v}");
        let mut out: Vec<String> = v["blobs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b["hash"].as_str().unwrap().to_owned())
            .collect();
        out.sort();
        out
    }

    /// The collector's dry run: each file without a root and its reason.
    pub fn plan(&self) -> Vec<(String, String)> {
        let v = self.api("GET", "/v1/blobs/gc", Value::Null);
        let mut out: Vec<(String, String)> = v["blobs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| {
                (
                    b["hash"].as_str().unwrap().to_owned(),
                    b["reason"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        out.sort();
        out
    }

    /// A pass of the collector now.
    pub fn gc(&self, immediate: bool) -> Value {
        self.api(
            "POST",
            "/v1/blobs/gc",
            json!({"reason": "blob crash test", "immediate": immediate}),
        )
    }
}

/// The status and body of a request.
pub fn call(http: &str, request: &str) -> (u16, Vec<u8>) {
    let mut s = TcpStream::connect(http).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    s.write_all(request.as_bytes()).unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).unwrap();
    let split = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&out[..split]).to_string();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, out[split + 4..].to_vec())
}

/// `POST /media/a/<op>?<query>` without a body.
pub fn request(op: &str, query: &str) -> String {
    format!(
        "POST /media/a/{op}?{query} HTTP/1.1\r\nhost: x\r\ncontent-length: 0\r\n\
         connection: close\r\n\r\n"
    )
}
