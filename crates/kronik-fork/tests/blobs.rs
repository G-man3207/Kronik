//! M25 slice B10: blobs in forks (docs/design/m25-streaming-bodies.md §9,
//! §17 criteria 2 and 5). A fork replays turns that fetched a blob response
//! and that used a reference they did not hold, with the test guest `media`,
//! in both replay modes: the replay serves the recordings, the fork's guest
//! reads production's blobs, and nothing diverges.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::*;
use kronik_core::ids::ActorRef;
use kronik_fork::diff::{DiffOptions, Mode};
use kronik_fork::proposal::Proposals;
use kronik_proto::log::v1 as pb;
use kronik_sched::{BlobsConfig, Ingress, NodeConfig, TurnResult};

fn pattern(i: u64) -> u8 {
    ((i.wrapping_mul(31) + 7) % 251) as u8
}

/// A "PDF" of `n` bytes: a header, then the `write` pattern.
fn document(n: u64) -> Vec<u8> {
    let mut out = b"%PDF-1.7\n".to_vec();
    out.extend((out.len() as u64..n).map(pattern));
    out.truncate(n as usize);
    out
}

/// Serves `GET /doc/<n>` and counts the requests.
fn document_server() -> (String, Arc<AtomicUsize>) {
    use std::io::{BufRead as _, BufReader, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut head = String::new();
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap_or(0) > 0 && line != "\r\n" {
                head.push_str(&line);
                line.clear();
            }
            seen.fetch_add(1, Ordering::SeqCst);
            let path = head.split_whitespace().nth(1).unwrap_or("").to_owned();
            let n: u64 = path
                .strip_prefix("/doc/")
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
            let mut stream = stream;
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\nContent-Length: {n}\r\n\
                 Connection: close\r\n\r\n"
            );
            let _ = stream.write_all(&document(n));
        }
    });
    (addr, count)
}

fn http(op: &str, query: &str, body: pb::body::Value) -> pb::HttpInput {
    pb::HttpInput {
        method: "POST".into(),
        path: format!("/media/a/{op}"),
        query: query.into(),
        body: Some(pb::Body { value: Some(body) }),
        route: "/media/{key}/{op}".into(),
        ..Default::default()
    }
}

fn inline(bytes: &[u8]) -> pb::body::Value {
    pb::body::Value::Inline(pb::Sealable {
        subject: None,
        value: Some(pb::sealable::Value::Plain(bytes.to_vec())),
    })
}

fn ingress(p: &Proc, input: pb::HttpInput) -> TurnResult {
    p.rt.block_on(async {
        match p
            .node
            .ingress(ActorRef::parse("media/a").unwrap(), input, None)
            .unwrap()
        {
            Ingress::Started(w) | Ingress::Joined(w) => w.wait().await.unwrap(),
            Ingress::Done(r) => *r,
        }
    })
}

fn answer(r: &TurnResult) -> String {
    match &r.outcome.output {
        Some(pb::outcome::Output::Http(h)) => {
            match h.body.as_ref().and_then(|b| b.value.as_ref()) {
                Some(pb::body::Value::Inline(s)) => match &s.value {
                    Some(pb::sealable::Value::Plain(b)) => String::from_utf8_lossy(b).into_owned(),
                    other => panic!("{other:?}"),
                },
                other => panic!("not inline: {other:?}"),
            }
        }
        other => panic!("{other:?}: {r:?}"),
    }
}

/// A blob written into the node's store from outside, as the gateway
/// writes an upload (slice B8).
fn upload(p: &Proc, dir: &std::path::Path, bytes: &[u8]) -> pb::BlobRef {
    p.rt.block_on(async {
        let store = kronik_blob::BlobStore::open(
            kronik_core::env::Env::real(tokio::runtime::Handle::current()),
            dir,
            kronik_blob::StoreConfig::default(),
        )
        .await
        .unwrap();
        let mut w = store
            .writer(
                kronik_blob::Space::Main,
                None,
                u64::MAX,
                store.leases().take("upload"),
            )
            .await
            .unwrap();
        w.write(bytes).await.unwrap();
        let meta = w.finish().await.unwrap();
        store
            .ensure_durable(&kronik_blob::Space::Main, &[meta.id])
            .await
            .unwrap();
        meta.to_pb()
    })
}

/// Criteria 2 and 5 with a fork: the fetched document is a blob in
/// production and the fork's replay gives the guest the same reference from
/// the recording (the server sees one request); a hash stored in state is
/// not-held in the replay as in production. Both modes, no divergence.
#[test]
fn a_fork_replays_blob_turns_without_divergence() {
    let dir = tempdir();
    let p = Proc::start_with(
        dir.path(),
        NodeConfig {
            concurrency: 8,
            blobs: Some(BlobsConfig::default()),
            ..NodeConfig::default()
        },
    );
    p.deploy("media");
    let owner = p.owner();
    p.rt.block_on(p.node.set_limits(
        pb::Limits {
            kind: "media".into(),
            blob_threshold_bytes: Some(65_536),
            ..Default::default()
        },
        audit(),
        false,
        owner.clone(),
    ))
    .unwrap();
    p.rt.block_on(p.node.grant(
        "media",
        "http:127.0.0.1",
        None,
        None,
        kronik_effects::InForks::Recorded,
        audit(),
        false,
        owner.clone(),
    ))
    .unwrap();
    let (addr, requests) = document_server();
    let fork_at = p.settle();

    let size = 2_000_000u64;
    let fetched = ingress(
        &p,
        http(
            "fetch",
            "",
            inline(format!("http://{addr}/doc/{size}").as_bytes()),
        ),
    );
    let expected = document(size);
    let hash = format!("b3:{}", blake3::hash(&expected).to_hex());
    assert_eq!(answer(&fetched), format!("status 200 blob {hash} {size}"));
    let summed = ingress(
        &p,
        http(
            "fetch-sum",
            "",
            inline(format!("http://{addr}/doc/{size}").as_bytes()),
        ),
    );
    assert!(answer(&summed).starts_with(&format!("blob {hash} {size} {size} ")));
    let upload = upload(&p, dir.path(), &b"an upload ".repeat(20_000));
    assert_eq!(
        answer(&ingress(
            &p,
            http("remember", "", pb::body::Value::Blob(upload))
        )),
        "remembered"
    );
    assert_eq!(
        answer(&ingress(&p, http("forged-get", "", inline(b"")))),
        "not-held"
    );
    let echo = ingress(&p, http("forged-echo", "", inline(b"")));
    assert_eq!(echo.outcome.error_code, "BLOB_NOT_HELD");
    let post = ingress(
        &p,
        http(
            "forged-post",
            &format!("url=http://{addr}/sink"),
            inline(b""),
        ),
    );
    assert!(
        answer(&post).starts_with("denied(BLOB_NOT_HELD"),
        "{}",
        answer(&post)
    );
    p.settle();
    let served = requests.load(Ordering::SeqCst);
    assert_eq!(served, 2, "production fetched twice");

    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    p.rt.block_on(props.create_fork(
        Some("blobs".into()),
        fork_at,
        false,
        audit(),
        false,
        p.owner(),
    ))
    .unwrap();
    p.rt.block_on(props.fork_replay(
        "blobs",
        None,
        DiffOptions {
            mode: Mode::Both,
            ..DiffOptions::default()
        },
        None,
        p.owner(),
    ))
    .unwrap();
    assert_eq!(
        requests.load(Ordering::SeqCst),
        served,
        "the replay served the recordings"
    );
    let diff: serde_json::Value =
        serde_json::from_slice(&p.rt.block_on(props.diff("blobs", false, false)).unwrap()).unwrap();
    let summary = &diff["summary"];
    assert_eq!(summary["divergent_turns"], 0, "{diff:#}");
    assert_eq!(summary["unverifiable"], 0, "{diff:#}");
    assert!(summary["replayed"].as_u64().unwrap() >= 6, "{diff:#}");
}
