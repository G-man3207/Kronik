//! M25 slice B8: the gateway's body phase and blob responses
//! (docs/design/m25-streaming-bodies.md §6), with the test guest `media`
//! on a node with a blob store. Uploads above the kind's threshold become
//! blobs as they arrive; larger than `upload_bytes`, slow or interrupted
//! ones are refused and leave no part file; a retry of an answered request
//! is only hashed; a blob response streams with its length. The last test
//! runs through the hyper server (the `server` feature).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use kronik_core::env::{BodySource, BoxFuture, Env};
use kronik_gateway::{
    Gateway, GatewayConfig, HttpRequest, HttpResponse, RequestBody, ResponseBody,
};
use kronik_proto::log::v1 as pb;
use kronik_sched::{BlobsConfig, Node, NodeConfig, start_local};

const MEDIA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/media.wasm");
const MIB: usize = 1 << 20;

fn audit() -> pb::Audit {
    pb::Audit {
        token_id: "t".into(),
        reason: "test".into(),
        wall_time_ms: 0,
    }
}

async fn media_node(dir: &Path) -> Arc<Node> {
    let env = Env::real(tokio::runtime::Handle::current());
    let config = NodeConfig {
        blobs: Some(BlobsConfig::default()),
        ..NodeConfig::default()
    };
    let node = start_local(env, dir, config).await.unwrap();
    node.deploy(
        &std::fs::read(MEDIA).unwrap(),
        audit(),
        false,
        node.local_operator_authority().unwrap(),
    )
    .await
    .unwrap();
    // The guest checksums and writes megabytes a byte at a time.
    set_limits(
        &node,
        pb::Limits {
            fuel: Some(2_000_000_000),
            ..Default::default()
        },
    )
    .await;
    node
}

async fn set_limits(node: &Node, limits: pb::Limits) {
    node.set_limits(
        pb::Limits {
            kind: "media".into(),
            ..limits
        },
        audit(),
        false,
        node.local_operator_authority().unwrap(),
    )
    .await
    .unwrap();
}

fn request(op: &str, headers: &[(&str, &str)]) -> HttpRequest {
    HttpRequest {
        method: "POST".into(),
        path: format!("/media/a/{op}"),
        query: String::new(),
        headers: headers
            .iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect(),
        body: Vec::new(),
        peer: None,
    }
}

/// `n` bytes of a pattern the test can check.
fn data(n: usize) -> Vec<u8> {
    (0..n as u64)
        .map(|i| (i.wrapping_mul(131) % 253) as u8)
        .collect()
}

/// The `media` guest's `write` pattern.
fn pattern(n: u64) -> Vec<u8> {
    (0..n)
        .map(|i| ((i.wrapping_mul(31) + 7) % 251) as u8)
        .collect()
}

/// The `media` guest's checksum (FNV-1a 64).
fn fnv(bytes: &[u8]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{h:016x}")
}

/// A body sent in `chunk`-byte pieces; with `stall_after`, it stops sending
/// (without ending) once that many bytes went out.
struct Chunks {
    data: Vec<u8>,
    at: usize,
    chunk: usize,
    stall_after: Option<usize>,
}

fn chunks(data: Vec<u8>, chunk: usize) -> RequestBody {
    RequestBody::Stream(Box::new(Chunks {
        data,
        at: 0,
        chunk,
        stall_after: None,
    }))
}

impl BodySource for Chunks {
    fn next(&mut self) -> BoxFuture<'_, std::io::Result<Option<Bytes>>> {
        Box::pin(async move {
            if self.stall_after.is_some_and(|n| self.at >= n) {
                std::future::pending::<()>().await;
            }
            if self.at >= self.data.len() {
                return Ok(None);
            }
            let end = (self.at + self.chunk).min(self.data.len());
            let out = Bytes::copy_from_slice(&self.data[self.at..end]);
            self.at = end;
            Ok(Some(out))
        })
    }
}

fn text(r: &HttpResponse) -> String {
    String::from_utf8_lossy(&r.body).into_owned()
}

fn code(r: &HttpResponse) -> String {
    let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    v["error"]["code"].as_str().unwrap_or_default().to_owned()
}

fn files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in entries.flatten() {
        let path = e.path();
        if path.is_dir() {
            out.extend(files(&path));
        } else {
            out.push(path);
        }
    }
    out
}

/// Waits until `blobs/tmp` is empty: part files of refused uploads are
/// deleted in the background.
async fn no_part_files(dir: &Path) {
    let tmp = dir.join("blobs/tmp");
    for _ in 0..200 {
        if files(&tmp).is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("part files left: {:?}", files(&tmp));
}

async fn send(gw: &Gateway, req: HttpRequest, body: RequestBody) -> HttpResponse {
    gw.respond(req, body).await.into_response().await
}

/// M25 §6.2: a body up to the threshold is held, a larger one becomes a
/// blob written as it arrives; the turn reads it whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_upload_above_the_threshold_becomes_a_blob() {
    let dir = tempfile::tempdir().unwrap();
    let node = media_node(dir.path()).await;
    let gw = Gateway::new(node.clone(), GatewayConfig::default());
    let at = data(MIB);
    let r = send(&gw, request("info", &[]), chunks(at.clone(), 16 << 10)).await;
    assert_eq!(text(&r), format!("inline {MIB}"));
    let over = data(MIB + 1);
    let r = send(&gw, request("info", &[]), chunks(over.clone(), 16 << 10)).await;
    assert_eq!(
        text(&r),
        format!("blob b3:{} {}", blake3::hash(&over).to_hex(), MIB + 1)
    );
    let big = data(3 * MIB + 5);
    let r = send(&gw, request("sum", &[]), chunks(big.clone(), 16 << 10)).await;
    assert_eq!(text(&r), format!("{} {}", big.len(), fnv(&big)));
    // The simulator's inline bodies take the same path.
    let r = gw
        .handle(HttpRequest {
            body: big.clone(),
            ..request("info", &[])
        })
        .await;
    assert_eq!(
        text(&r),
        format!("blob b3:{} {}", blake3::hash(&big).to_hex(), big.len())
    );
    no_part_files(dir.path()).await;
}

/// M25 §6.2: above `upload_bytes` the request is 413 with the hint, at once
/// for a `Content-Length` and when the bytes pass it otherwise; a body that
/// stops arriving is 400. Neither leaves a part file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn uploads_too_large_or_stalled_are_refused_and_leave_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let node = media_node(dir.path()).await;
    set_limits(
        &node,
        pb::Limits {
            upload_bytes: Some(2 * MIB as u64),
            ..Default::default()
        },
    )
    .await;
    let gw = Gateway::new(
        node.clone(),
        GatewayConfig {
            body_idle_timeout: Duration::from_millis(300),
            ..GatewayConfig::default()
        },
    );
    let declared = (3 * MIB).to_string();
    let r = send(
        &gw,
        request("info", &[("content-length", declared.as_str())]),
        chunks(data(3 * MIB), 64 << 10),
    )
    .await;
    assert_eq!((r.status, code(&r)), (413, "PAYLOAD_TOO_LARGE".into()));
    assert!(text(&r).contains("--upload-size"), "{}", text(&r));
    let r = send(&gw, request("info", &[]), chunks(data(3 * MIB), 64 << 10)).await;
    assert_eq!((r.status, code(&r)), (413, "PAYLOAD_TOO_LARGE".into()));
    let stalled = RequestBody::Stream(Box::new(Chunks {
        data: data(3 * MIB),
        at: 0,
        chunk: 64 << 10,
        stall_after: Some(MIB + (256 << 10)),
    }));
    let started = std::time::Instant::now();
    let r = send(&gw, request("info", &[]), stalled).await;
    assert_eq!((r.status, code(&r)), (400, "BAD_REQUEST".into()));
    assert!(text(&r).contains("stopped arriving"), "{}", text(&r));
    assert!(started.elapsed() < Duration::from_secs(10));
    no_part_files(dir.path()).await;
    // Nothing was named either.
    assert!(files(&dir.path().join("blobs/objects")).is_empty());
}

/// M25 §6.2: a retry of an answered request is only hashed: no new blob,
/// the saved answer; another body under the same key is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_retry_of_an_answered_upload_is_only_hashed() {
    let dir = tempfile::tempdir().unwrap();
    let node = media_node(dir.path()).await;
    let gw = Gateway::new(node.clone(), GatewayConfig::default());
    let body = data(2 * MIB);
    let key = [("Idempotency-Key", "upload-1")];
    let first = send(&gw, request("info", &key), chunks(body.clone(), 32 << 10)).await;
    assert!(text(&first).starts_with("blob "), "{}", text(&first));
    let objects = files(&dir.path().join("blobs/objects"));
    let lsn = |r: &HttpResponse| {
        r.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("kronik-turn-id"))
            .map(|(_, v)| v.clone())
    };
    let retry = send(&gw, request("info", &key), chunks(body.clone(), 32 << 10)).await;
    assert_eq!(text(&retry), text(&first));
    assert_eq!(lsn(&retry), lsn(&first));
    assert_eq!(files(&dir.path().join("blobs/objects")), objects);
    let mut other = body;
    other[MIB] ^= 1;
    let r = send(&gw, request("info", &key), chunks(other, 32 << 10)).await;
    assert_eq!((r.status, code(&r)), (422, "IDEMPOTENCY_KEY_REUSED".into()));
    assert_eq!(files(&dir.path().join("blobs/objects")), objects);
    no_part_files(dir.path()).await;
}

/// M25 §6.5: a blob response streams from the store with its length, a
/// frame at a time; an echoed upload comes back byte for byte.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blob_response_streams_with_its_length() {
    let dir = tempfile::tempdir().unwrap();
    let node = media_node(dir.path()).await;
    let gw = Gateway::new(node.clone(), GatewayConfig::default());
    let size = 3_000_000u64;
    let mut req = request("write", &[]);
    req.query = format!("size={size}");
    let answer = gw.respond(req, RequestBody::Inline(Vec::new())).await;
    assert_eq!(answer.status, 200);
    let ResponseBody::Blob(blob) = answer.body else {
        panic!("not a blob: {:?}", answer.body)
    };
    assert_eq!(blob.size(), size);
    assert_eq!(blob.collect().await.unwrap(), pattern(size));
    let upload = data(2 * MIB + 3);
    let r = send(&gw, request("echo", &[]), chunks(upload.clone(), 8 << 10)).await;
    assert_eq!(r.status, 200);
    assert!(r.body == upload, "the echo differs");
}

/// M25 §6.2: below the blob reserve an upload that would become a blob is
/// 503 BLOB_STORE_FULL; a small body still works.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn below_the_blob_reserve_uploads_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let node = media_node(dir.path()).await;
    let gw = Gateway::new(node.clone(), GatewayConfig::default());
    let store = node.blob_store().unwrap().clone();
    store.set_reserve(1 << 40);
    store.set_free(1 << 30);
    let r = send(&gw, request("info", &[]), chunks(data(2 * MIB), 64 << 10)).await;
    assert_eq!((r.status, code(&r)), (503, "BLOB_STORE_FULL".into()));
    let r = send(&gw, request("info", &[]), chunks(data(10), 64 << 10)).await;
    assert_eq!(text(&r), "inline 10");
}

/// Through the hyper server: a chunked 3 MiB upload is echoed back as a
/// blob response with its `content-length`.
#[cfg(feature = "server")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_server_streams_uploads_and_blob_responses() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let dir = tempfile::tempdir().unwrap();
    let node = media_node(dir.path()).await;
    let gw = Arc::new(Gateway::new(node.clone(), GatewayConfig::default()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(kronik_gateway::server::serve(listener, gw, 16));
    let upload = data(3 * MIB);
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(
        b"POST /media/a/echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\
          Connection: close\r\n\r\n",
    )
    .await
    .unwrap();
    for part in upload.chunks(100_000) {
        s.write_all(format!("{:x}\r\n", part.len()).as_bytes())
            .await
            .unwrap();
        s.write_all(part).await.unwrap();
        s.write_all(b"\r\n").await.unwrap();
    }
    s.write_all(b"0\r\n\r\n").await.unwrap();
    let mut response = Vec::new();
    s.read_to_end(&mut response).await.unwrap();
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a head");
    let head = String::from_utf8_lossy(&response[..split]).to_ascii_lowercase();
    assert!(head.starts_with("http/1.1 200"), "{head}");
    assert!(
        head.contains(&format!("content-length: {}", upload.len())),
        "{head}"
    );
    assert!(response[split + 4..] == upload[..], "the echo differs");
}
