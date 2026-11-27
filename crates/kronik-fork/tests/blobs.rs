//! M25 slice B10: blobs in forks (docs/design/m25-streaming-bodies.md §9,
//! §17 criteria 2 and 5). A fork replays turns that fetched a blob response
//! and that used a reference they did not hold, with the test guest `media`,
//! in both replay modes: the replay serves the recordings, the fork's guest
//! reads production's blobs, and nothing diverges.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use common::*;
use kronik_blob::{BlobId, Space, SweepOptions};
use kronik_core::ids::ActorRef;
use kronik_fork::diff::{DiffOptions, Mode};
use kronik_fork::proposal::{Proposals, ProposeRequest};
use kronik_proto::log::v1 as pb;
use kronik_sched::snapshots::StorageConfig;
use kronik_sched::{BlobsConfig, NodeConfig, TurnResult};

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
    use std::io::Write as _;
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    let addr = common::http::serve(move |req, stream| {
        seen.fetch_add(1, Ordering::SeqCst);
        let n: u64 = req
            .path
            .strip_prefix("/doc/")
            .and_then(|n| n.parse().ok())
            .unwrap_or(0);
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\nContent-Length: {n}\r\n\
             Connection: close\r\n\r\n"
        );
        let _ = stream.write_all(&document(n));
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
    p.ingress(ActorRef::parse("media/a").unwrap(), input, None)
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

/// The text answer of `op` on media/a, which must commit.
fn ok(p: &Proc, op: &str, query: &str) -> String {
    let r = ingress(p, http(op, query, inline(b"")));
    assert!(r.committed(), "{op}: {r:?}");
    answer(&r)
}

/// Raises the media kind's fuel for the blob-heavy operations.
fn media_fuel(p: &Proc) {
    p.rt.block_on(p.node.set_limits(
        pb::Limits {
            kind: "media".into(),
            fuel: Some(2_000_000_000),
            ..Default::default()
        },
        audit(),
        false,
        p.owner(),
    ))
    .unwrap();
}

/// The media code with a custom section added: another component, as
/// a proposal needs, that runs the same.
fn media_v2() -> Vec<u8> {
    let mut v2 = std::fs::read(guest("media")).unwrap();
    v2.extend_from_slice(&[0x00, 0x07, 0x04, b't', b'e', b's', b't', b'v', b'2']);
    v2
}

/// A proposal of [`media_v2`].
fn propose_media_v2(p: &Proc, props: &Arc<Proposals>) -> kronik_fork::proposal::Proposal {
    p.rt.block_on(props.propose(propose_request(vec![media_v2()]), p.owner()))
        .unwrap()
        .0
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
    let p = blob_node(dir.path());
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
    let diff = replay(&p, &props, "blobs", fork_at, false);
    assert_eq!(
        requests.load(Ordering::SeqCst),
        served,
        "the replay served the recordings"
    );
    let summary = &diff["summary"];
    assert_eq!(summary["divergent_turns"], 0, "{diff:#}");
    assert_eq!(summary["unverifiable"], 0, "{diff:#}");
    assert!(summary["replayed"].as_u64().unwrap() >= 6, "{diff:#}");
}

/// A subject's blob written into the node's store, as the gateway writes
/// a subject's upload: keyed with the subject's key.
fn subject_upload(p: &Proc, dir: &std::path::Path, subject: &str, bytes: &[u8]) -> pb::BlobRef {
    let keys = p
        .node
        .sealer()
        .blob_keys(subject, &|b: &mut [u8]| b.fill(9), 1)
        .unwrap();
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
                Some(keys),
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

fn blob_node(dir: &std::path::Path) -> Proc {
    let p = Proc::start_with(
        dir,
        NodeConfig {
            concurrency: 8,
            blobs: Some(BlobsConfig::default()),
            ..NodeConfig::default()
        },
    );
    p.deploy("media");
    p
}

fn replay(
    p: &Proc,
    props: &Arc<Proposals>,
    name: &str,
    fork_at: u64,
    no_pii: bool,
) -> serde_json::Value {
    new_fork(p, props, name, fork_at, no_pii, None);
    serde_json::from_slice(&replay_fork(
        p,
        props,
        name,
        DiffOptions {
            mode: Mode::Both,
            no_pii,
            ..DiffOptions::default()
        },
        None,
    ))
    .unwrap()
}

/// M25 §9: a `--no-pii` fork reads a subject's blob as its pseudonym, never
/// its bytes; the turn is pii-masked, not divergent. The fork also holds a
/// floor lease at its fork point.
#[test]
fn a_no_pii_fork_reads_a_subjects_blob_as_its_pseudonym() {
    let dir = tempdir();
    let p = blob_node(dir.path());
    let fork_at = p.settle();
    let secret = b"SUBJECT-PLAINTEXT-".repeat(4000);
    let upload = subject_upload(&p, dir.path(), "user:1", &secret);
    let read = ingress(&p, http("ranges", "at=0:16", pb::body::Value::Blob(upload)));
    assert!(answer(&read).starts_with("0:16=16 "), "{}", answer(&read));
    p.settle();
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    let diff = replay(&p, &props, "nopii", fork_at, true);
    let summary = &diff["summary"];
    assert_eq!(summary["divergent_turns"], 0, "{diff:#}");
    assert!(summary["pii_masked"].as_u64().unwrap() >= 1, "{diff:#}");
    assert!(!diff.to_string().contains("SUBJECT-PLAINTEXT"));
    let store = p.node.blob_store().unwrap();
    assert_eq!(store.leases().lowest_floor(), Some(fork_at));
}

/// M25 §9 and ADR 0109: a fork's read of an erased subject's blob gives
/// the guest `erased` and makes the turn unverifiable, not divergent.
#[test]
fn a_forks_read_of_an_erased_blob_is_unverifiable() {
    let dir = tempdir();
    let p = blob_node(dir.path());
    let fork_at = p.settle();
    let upload = subject_upload(&p, dir.path(), "user:2", &b"to be erased ".repeat(3000));
    let read = ingress(&p, http("ranges", "at=0:12", pb::body::Value::Blob(upload)));
    assert!(answer(&read).starts_with("0:12=12 "), "{}", answer(&read));
    p.rt.block_on(p.node.erase_subject("user:2", audit(), false, p.owner()))
        .unwrap();
    p.settle();
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    let diff = replay(&p, &props, "erased", fork_at, false);
    let summary = &diff["summary"];
    assert_eq!(summary["divergent_turns"], 0, "{diff:#}");
    assert!(summary["unverifiable"].as_u64().unwrap() >= 1, "{diff:#}");
}

/// M25 §6.4: a preview of code that reads blobs takes uploads into its
/// fork's blob space and streams its blob answers from there, through the
/// gateway's prefix path (sandboxed).
#[test]
fn a_preview_takes_uploads_and_streams_blob_answers_in_its_space() {
    use kronik_gateway::{Gateway, GatewayConfig, HttpRequest, PREVIEW_PREFIX};
    let dir = tempdir();
    let p = blob_node(dir.path());
    media_fuel(&p);
    ingress(&p, http("info", "", inline(b"x")));
    p.settle();
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    let proposal = propose_media_v2(&p, &props);
    let (preview, _) =
        p.rt.block_on(props.create_preview(&proposal.id, None, false, audit(), false, p.owner()))
            .unwrap();
    // A proposal and a preview keep their base state's blobs in main's
    // store as a plain fork does (review L-5): each has its blobs.roots.
    for (id, fork_lsn) in [
        (&proposal.id, proposal.fork_lsn),
        (&preview.id, preview.fork_lsn),
    ] {
        let roots =
            std::fs::read_to_string(dir.path().join("branches").join(id).join("blobs.roots"))
                .unwrap();
        assert_eq!(
            roots.lines().next(),
            Some(format!("fork_lsn {fork_lsn}").as_str())
        );
    }
    let gw = Gateway::new(p.node.clone(), GatewayConfig::default()).with_preview(props.clone());
    let request = |op: &str, query: &str, body: Vec<u8>| HttpRequest {
        method: "POST".into(),
        path: format!("{PREVIEW_PREFIX}{}/media/a/{op}", preview.id),
        query: query.into(),
        headers: Vec::new(),
        body,
        peer: None,
    };
    let objects = |root: std::path::PathBuf| -> usize {
        fn walk(dir: &std::path::Path) -> usize {
            std::fs::read_dir(dir).map_or(0, |entries| {
                entries
                    .flatten()
                    .map(|e| {
                        if e.path().is_dir() {
                            walk(&e.path())
                        } else {
                            1
                        }
                    })
                    .sum()
            })
        }
        walk(&root.join("objects"))
    };
    let main_before = objects(dir.path().join("blobs"));
    let upload: Vec<u8> = (0..2_000_000u64).map(|i| (i % 249) as u8).collect();
    let r =
        p.rt.block_on(gw.handle(request("info", "", upload.clone())));
    assert_eq!(
        String::from_utf8_lossy(&r.body),
        format!(
            "blob b3:{} {}",
            blake3::hash(&upload).to_hex(),
            upload.len()
        ),
    );
    let space = dir.path().join("branches").join(&preview.id).join("blobs");
    assert_eq!(
        objects(space.clone()),
        1,
        "the upload is in the preview's space"
    );
    assert_eq!(
        objects(dir.path().join("blobs")),
        main_before,
        "not in main's"
    );
    let size = 1_500_000u64;
    let r =
        p.rt.block_on(gw.handle(request("write", &format!("size={size}"), Vec::new())));
    assert_eq!(r.status, 200);
    assert_eq!(r.body, (0..size).map(pattern).collect::<Vec<u8>>());
    assert!(
        r.headers
            .iter()
            .any(|(n, v)| n == "content-security-policy" && v == "sandbox"),
        "{:?}",
        r.headers
    );
}

/// Review L-1 (erasure), with privacy off: a subject's upload to a preview
/// creates no key (nothing is sealed), main's upload creates it. With
/// privacy on a preview's upload takes its key as the preview's record does
/// (review P-1, below).
#[test]
fn a_preview_upload_creates_no_subject_key() {
    use kronik_gateway::subject::SubjectFrom;
    use kronik_gateway::{Gateway, GatewayConfig, HttpRequest, PREVIEW_PREFIX};
    let dir = tempdir();
    let p = blob_node(dir.path());
    ingress(&p, http("info", "", inline(b"x")));
    p.settle();
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    let proposal = propose_media_v2(&p, &props);
    let (preview, _) =
        p.rt.block_on(props.create_preview(&proposal.id, None, false, audit(), false, p.owner()))
            .unwrap();
    let gw = Gateway::new(
        p.node.clone(),
        GatewayConfig {
            subject_from: SubjectFrom::parse("header:x-user-id"),
            trusted_proxies: vec![kronik_gateway::IpNet::parse("127.0.0.1").unwrap()],
            ..GatewayConfig::default()
        },
    )
    .with_preview(props.clone());
    let request = |path: String, user: &str| HttpRequest {
        method: "POST".into(),
        path,
        query: String::new(),
        headers: vec![("x-user-id".into(), user.into())],
        body: vec![3u8; 2_000_000],
        peer: Some("127.0.0.1".parse().unwrap()),
    };
    let keys = || {
        p.node
            .sealer()
            .keystore()
            .map_or(0, |k| k.stats().unwrap().keys)
    };
    let before = keys();
    let r = p.rt.block_on(gw.handle(request(
        format!("{PREVIEW_PREFIX}{}/media/a/info", preview.id),
        "user:9",
    )));
    assert!(
        String::from_utf8_lossy(&r.body).starts_with("blob b3s:"),
        "{}",
        String::from_utf8_lossy(&r.body)
    );
    assert_eq!(keys(), before, "the preview created no key");
    let r =
        p.rt.block_on(gw.handle(request("/media/a/info".into(), "user:9")));
    assert!(String::from_utf8_lossy(&r.body).starts_with("blob b3s:"));
    if p.node.sealer().keystore().is_some() {
        assert_eq!(
            keys(),
            before + 1,
            "main's upload created the subject's key"
        );
    }
}

/// Review R-4 (erasure): a rollback by replay re-runs turns with the old
/// code, whose blobs differ from production's and are written to the
/// rebase's fork space. Staging copies them into main's store before the
/// records that reference them are appended: after the switch the rebased
/// turn's blob reads from main, also once the fork's space is gone.
#[test]
fn a_rollback_by_replay_brings_its_blobs_into_main() {
    use kronik_fork::proposal::RebaseRequest;
    let dir = tempdir();
    let p = blob_node(dir.path());
    media_fuel(&p);
    ingress(&p, http("info", "", inline(b"x")));
    p.settle();
    p.rt.block_on(p.node.snapshot("before the deployment", p.owner()))
        .unwrap();
    let props = Arc::new(
        Proposals::open(p.node.clone(), dir.path().to_path_buf())
            .unwrap()
            .with_rebase(std::time::Duration::from_secs(5)),
    );
    let alt = std::fs::read(guest("media-alt")).unwrap();
    let (prop, _) =
        p.rt.block_on(props.propose(propose_request(vec![alt]), p.owner()))
            .unwrap();
    let promoted =
        p.rt.block_on(props.promote(&prop.id, audit(), false, p.owner()))
            .unwrap();
    // Under the new code: the alternate pattern.
    let size = 200_000u64;
    let production = blob_answer_of(&ingress(
        &p,
        http("write", &format!("size={size}"), inline(b"")),
    ));
    p.settle();
    // Roll the code back by replaying with the old code.
    let (rebase, _) =
        p.rt.block_on(props.rebase(
            RebaseRequest {
                epoch: promoted.epoch,
                options: DiffOptions {
                    mode: Mode::Continuous,
                    ..DiffOptions::default()
                },
                workers: Some(2),
                audit: audit(),
                dry_run: false,
            },
            p.owner(),
        ))
        .unwrap();
    p.rt.block_on(props.approve(&rebase.id, audit(), false, None, p.owner()))
        .unwrap();
    p.rt.block_on(props.promote(&rebase.id, audit(), false, p.owner()))
        .unwrap();
    // The rebased turn wrote the old pattern: a blob production never had.
    let old: Vec<u8> = (0..size).map(pattern).collect();
    let rebased = format!("b3:{}", blake3::hash(&old).to_hex());
    assert_ne!(rebased, production.hash);
    let store = p.node.blob_store().unwrap().clone();
    let meta = kronik_blob::BlobMeta {
        id: kronik_blob::BlobId::parse(&rebased).unwrap(),
        size,
        subject: None,
        key_version: 0,
    };
    let fork_space = dir.path().join("branches").join(&rebase.id).join("blobs");
    let read_main = || {
        p.rt.block_on(async {
            let r = store
                .reader(&kronik_blob::Space::Main, &meta, &kronik_blob::NoKeys)
                .await?;
            r.read_at(0, size as usize).await
        })
    };
    assert!(read_main().unwrap() == old, "main has the rebased blob");
    if fork_space.exists() {
        std::fs::remove_dir_all(&fork_space).unwrap();
    }
    assert!(read_main().unwrap() == old, "without the fork's space too");
}

fn blob_answer_of(r: &TurnResult) -> pb::BlobRef {
    match &r.outcome.output {
        Some(pb::outcome::Output::Http(h)) => {
            match h.body.as_ref().and_then(|b| b.value.as_ref()) {
                Some(pb::body::Value::Blob(b)) => b.clone(),
                other => panic!("not a blob: {other:?}"),
            }
        }
        other => panic!("{other:?}"),
    }
}

/// Review M-1: anyone with a preview's URL uploads into its blob space,
/// which no collector sweeps while the preview lives. The space holds at
/// most `[fork] preview_blob_bytes`:
/// - an upload past it is 409 PREVIEW_FULL and gives its bytes back;
/// - a smaller one still fits;
/// - a turn's write past it answers the guest `quota-exceeded`.
///
/// The space goes with the preview, when it is deleted or expires.
#[test]
fn a_previews_blob_space_is_capped_and_goes_with_the_preview() {
    use kronik_gateway::{Gateway, GatewayConfig, HttpRequest, PREVIEW_PREFIX};
    let dir = tempdir();
    let p = blob_node(dir.path());
    media_fuel(&p);
    ingress(&p, http("info", "", inline(b"x")));
    p.settle();
    let props = Arc::new(
        Proposals::open(p.node.clone(), dir.path().to_path_buf())
            .unwrap()
            .with_preview_blob_bytes(3_500_000),
    );
    let proposal = propose_media_v2(&p, &props);
    let create = |ttl: Option<Duration>| {
        p.rt.block_on(props.create_preview(&proposal.id, ttl, false, audit(), false, p.owner()))
            .unwrap()
            .0
    };
    let preview = create(None);
    let gw = Gateway::new(p.node.clone(), GatewayConfig::default()).with_preview(props.clone());
    let request = |id: &str, op: &str, query: &str, body: Vec<u8>| HttpRequest {
        method: "POST".into(),
        path: format!("{PREVIEW_PREFIX}{id}/media/a/{op}"),
        query: query.into(),
        headers: Vec::new(),
        body,
        peer: None,
    };
    let code = |r: &kronik_gateway::HttpResponse| -> String {
        serde_json::from_slice::<serde_json::Value>(&r.body)
            .ok()
            .and_then(|v| v["error"]["code"].as_str().map(str::to_owned))
            .unwrap_or_default()
    };
    let bytes =
        |seed: u64, n: u64| -> Vec<u8> { (0..n).map(|i| ((i * 7 + seed) % 251) as u8).collect() };
    let space = dir.path().join("branches").join(&preview.id).join("blobs");

    let r =
        p.rt.block_on(gw.handle(request(&preview.id, "info", "", bytes(1, 2_000_000))));
    assert!(
        String::from_utf8_lossy(&r.body).starts_with("blob "),
        "{r:?}"
    );
    // Past the cap.
    let r =
        p.rt.block_on(gw.handle(request(&preview.id, "info", "", bytes(2, 2_000_000))));
    assert_eq!((r.status, code(&r)), (409, "PREVIEW_FULL".into()), "{r:?}");
    // What it took is back: a smaller one (still above the 1 MiB threshold)
    // fits.
    let r =
        p.rt.block_on(gw.handle(request(&preview.id, "info", "", bytes(3, 1_200_000))));
    assert!(
        String::from_utf8_lossy(&r.body).starts_with("blob "),
        "{r:?}"
    );
    // A turn that writes past it.
    let r =
        p.rt.block_on(gw.handle(request(&preview.id, "write", "size=500000", Vec::new())));
    assert_ne!(r.status, 200, "{r:?}");
    assert!(
        String::from_utf8_lossy(&r.body).contains("quota"),
        "{}",
        String::from_utf8_lossy(&r.body)
    );
    assert!(space.exists());

    // Deleted: its space too.
    p.rt.block_on(props.delete_preview(&preview.id, audit(), false, p.owner()))
        .unwrap();
    assert!(!space.exists(), "the deleted preview's blob space is gone");

    // Expired: its space too.
    let short = create(Some(Duration::from_secs(2)));
    let r =
        p.rt.block_on(gw.handle(request(&short.id, "info", "", bytes(4, 2_000_000))));
    assert!(
        String::from_utf8_lossy(&r.body).starts_with("blob "),
        "{r:?}"
    );
    let short_space = dir.path().join("branches").join(&short.id).join("blobs");
    assert!(short_space.exists());
    std::thread::sleep(Duration::from_millis(2100));
    assert_eq!(p.rt.block_on(props.expire_previews()), 1);
    assert!(
        !short_space.exists(),
        "the expired preview's blob space is gone"
    );
}

/// Review (ci-green, erasure): a preview reopened after a restart read
/// every request body inline until it was created again, as its body
/// policies were computed only by create_preview. They are computed again
/// at open, and made exact by the first request's rebuild.
#[test]
fn a_preview_takes_uploads_as_blobs_after_a_restart() {
    use kronik_gateway::{Gateway, GatewayConfig, HttpRequest, PREVIEW_PREFIX};
    let dir = tempdir();
    let preview = {
        let p = blob_node(dir.path());
        media_fuel(&p);
        ingress(&p, http("info", "", inline(b"x")));
        p.settle();
        let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
        let proposal = propose_media_v2(&p, &props);
        let (preview, _) = p
            .rt
            .block_on(props.create_preview(&proposal.id, None, false, audit(), false, p.owner()))
            .unwrap();
        p.settle();
        preview
    };
    // The daemon restarts: the node and the proposals open from disk.
    let p = Proc::start_with(
        dir.path(),
        NodeConfig {
            concurrency: 8,
            blobs: Some(BlobsConfig::default()),
            ..NodeConfig::default()
        },
    );
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    let gw = Gateway::new(p.node.clone(), GatewayConfig::default()).with_preview(props.clone());
    let upload: Vec<u8> = (0..2_000_000u64).map(|i| (i % 247) as u8).collect();
    let digest = blake3::hash(&upload).to_hex().to_string();
    for _ in 0..2 {
        let r = p.rt.block_on(gw.handle(HttpRequest {
            method: "POST".into(),
            path: format!("{PREVIEW_PREFIX}{}/media/a/info", preview.id),
            query: String::new(),
            headers: Vec::new(),
            body: upload.clone(),
            peer: None,
        }));
        assert_eq!(
            String::from_utf8_lossy(&r.body),
            format!("blob b3:{digest} {}", upload.len()),
            "status {}",
            r.status
        );
    }
}

/// Review P-1 (erasure): with privacy on, a preview's upload of a subject
/// without a key, and a preview turn's own blob of one, were stored plain
/// (a fork-local test key) although the preview's record sealing created
/// the subject's key for the same request: the bytes survived the
/// subject's erasure. A fork's blob now takes its key as the fork's record
/// does: created for a subject never erased (and sealed), refused for an
/// erased one.
#[test]
fn a_preview_seals_a_new_subjects_blobs_and_refuses_an_erased_ones() {
    use kronik_gateway::subject::SubjectFrom;
    use kronik_gateway::{Gateway, GatewayConfig, HttpRequest, PREVIEW_PREFIX};
    const MARK: &[u8] = b"P1-PREVIEW-MARK-7f3a";
    let dir = tempdir();
    let p = blob_node(dir.path());
    media_fuel(&p);
    p.rt.block_on(
        p.node
            .set_privacy_mode(pb::PrivacyState::On, audit(), false, p.owner()),
    )
    .unwrap();
    ingress(&p, http("info", "", inline(b"x")));
    p.settle();
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    let proposal = propose_media_v2(&p, &props);
    let (preview, _) =
        p.rt.block_on(props.create_preview(&proposal.id, None, false, audit(), false, p.owner()))
            .unwrap();
    let gw = Gateway::new(
        p.node.clone(),
        GatewayConfig {
            subject_from: SubjectFrom::parse("header:x-user-id"),
            trusted_proxies: vec![kronik_gateway::IpNet::parse("127.0.0.1").unwrap()],
            ..GatewayConfig::default()
        },
    )
    .with_preview(props.clone());
    let request = |op: &str, query: &str, user: &str, body: Vec<u8>| HttpRequest {
        method: "POST".into(),
        path: format!("{PREVIEW_PREFIX}{}/media/a/{op}", preview.id),
        query: query.into(),
        headers: vec![("x-user-id".into(), user.into())],
        body,
        peer: Some("127.0.0.1".parse().unwrap()),
    };
    // An upload of a subject that has no key yet: sealed under its new key.
    let mut body = Vec::new();
    while body.len() < 1_500_000 {
        body.extend_from_slice(MARK);
        body.extend_from_slice(&(body.len() as u64).to_le_bytes());
    }
    let r =
        p.rt.block_on(gw.handle(request("info", "", "user:9", body.clone())));
    let answer = String::from_utf8_lossy(&r.body).to_string();
    assert!(answer.starts_with("blob b3s:"), "{} {answer}", r.status);
    assert!(
        files_with(dir.path(), MARK).is_empty(),
        "the upload is plain on disk"
    );
    let sealer = p.node.sealer();
    let keystore = sealer.keystore().expect("privacy on has a keystore");
    assert_eq!(keystore.newest_version("user:9").unwrap(), Some(1));
    // A preview turn's own blob of another new subject: sealed too.
    let r =
        p.rt.block_on(gw.handle(request("write", "size=300000", "user:10", Vec::new())));
    assert_eq!(r.status, 200);
    let written: Vec<u8> = (0..4096u64).map(pattern).collect();
    assert!(r.body.starts_with(&written));
    assert!(
        files_with(dir.path(), &written).is_empty(),
        "the preview turn's blob is plain on disk"
    );
    assert_eq!(keystore.newest_version("user:10").unwrap(), Some(1));
    // The erasure makes the upload unreadable, and the preview refuses a
    // new body of the erased subject.
    p.rt.block_on(p.node.erase_subject("user:9", audit(), false, p.owner()))
        .unwrap();
    let hash = answer.split_whitespace().nth(1).unwrap().to_owned();
    let meta = kronik_blob::BlobMeta {
        id: kronik_blob::BlobId::parse(&hash).unwrap(),
        size: body.len() as u64,
        subject: Some("user:9".into()),
        key_version: 1,
    };
    let store = p.node.blob_store().unwrap().clone();
    let read = p.rt.block_on(store.reader(
        &kronik_blob::Space::Fork(preview.id.clone()),
        &meta,
        &sealer.blob_key_access(),
    ));
    assert!(
        matches!(read, Err(kronik_blob::BlobError::Erased)),
        "{:?}",
        read.err()
    );
    let r =
        p.rt.block_on(gw.handle(request("info", "", "user:9", body)));
    assert_eq!(r.status, 410, "{}", String::from_utf8_lossy(&r.body));
    assert!(String::from_utf8_lossy(&r.body).contains("SUBJECT_ERASED"));
    assert!(files_with(dir.path(), MARK).is_empty());
}

/// `kronik upgrade check` (and the start of a daemon whose engine changed)
/// replays the window offline. It replayed blob turns without the blob
/// store, so a recorded blob response failed the check ("a blob response in
/// a turn without blobs"; found by the v0.5.0 compatibility corpus). It
/// reads production's blobs, writes the replayed turns' own to a space of
/// its own, and removes that space after.
#[test]
fn the_upgrade_check_replays_blob_turns_and_leaves_no_space_behind() {
    let dir = tempdir();
    {
        let p = blob_node(dir.path());
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
            owner,
        ))
        .unwrap();
        let (addr, _) = document_server();
        let fetched = ingress(
            &p,
            http(
                "fetch",
                "",
                inline(format!("http://{addr}/doc/300000").as_bytes()),
            ),
        );
        assert!(
            answer(&fetched).starts_with("status 200 blob b3:"),
            "{}",
            answer(&fetched)
        );
        let upload = upload(&p, dir.path(), &document(200_000));
        assert_eq!(
            answer(&ingress(&p, http("sum", "", pb::body::Value::Blob(upload))))
                .split(' ')
                .next(),
            Some("200000")
        );
        let written = ingress(&p, http("write", "size=150000", inline(b"")));
        assert!(written.committed());
        p.settle();
    }
    let rt = tokio::runtime::Runtime::new().unwrap();
    let checked = rt
        .block_on(async {
            let env = kronik_core::env::Env::real(tokio::runtime::Handle::current());
            kronik_fork::upgrade::check(
                &env,
                dir.path(),
                std::time::Duration::from_secs(6 * 3600),
                2,
                None,
            )
            .await
        })
        .unwrap();
    assert!(checked.report.passed, "{:?}", checked.report);
    assert!(checked.report.root_inputs >= 3, "{:?}", checked.report);
    let spaces: Vec<String> = branch_names(dir.path())
        .into_iter()
        .filter(|name| name.starts_with("upgrade-"))
        .collect();
    assert!(spaces.is_empty(), "the check left {spaces:?}");
}

/// B14's quota across an erasure (ADR 0119 as amended 2026-11-14, second
/// note): an erased subject's blobs stop counting against their holder from
/// the holder's next turn after the erasure on. A fork that replays across
/// the `Erasure` record, in both modes, decides each quota as production did:
/// refused before the erasure and in the holder's first turn after it,
/// granted in the next.
#[test]
fn a_replay_across_an_erasure_decides_the_quota_as_production_did() {
    let dir = tempdir();
    let p = blob_node(dir.path());
    p.rt.block_on(
        p.node
            .set_privacy_mode(pb::PrivacyState::On, audit(), false, p.owner()),
    )
    .unwrap();
    p.rt.block_on(p.node.set_limits(
        pb::Limits {
            kind: "media".into(),
            blob_bytes_per_actor: Some(5 << 19),
            ..Default::default()
        },
        audit(),
        false,
        p.owner(),
    ))
    .unwrap();
    let put = |size: u64, subject: &str| {
        let input = pb::HttpInput {
            body: Some(pb::Body {
                value: Some(pb::body::Value::Inline(pb::Sealable {
                    subject: Some(subject.into()),
                    value: Some(pb::sealable::Value::Plain(Vec::new())),
                })),
            }),
            ..http("put", &format!("size={size}"), inline(b""))
        };
        let r = p.ingress(ActorRef::parse("media/a").unwrap(), input, Some(subject));
        assert!(r.committed(), "{r:?}");
        answer(&r)
    };
    assert!(put(1 << 20, "user:1").starts_with("blob b3s:"));
    assert!(put(1_000_000, "user:1").starts_with("blob b3s:"));
    let fork_at = p.settle();
    assert_eq!(put(1 << 20, "user:2"), "quota-exceeded");
    p.rt.block_on(p.node.erase_subject("user:1", audit(), false, p.owner()))
        .unwrap();
    assert_eq!(put(1 << 20, "user:2"), "quota-exceeded");
    assert!(put(1 << 20, "user:2").starts_with("blob b3s:"));
    p.settle();
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    let diff = replay(&p, &props, "quota", fork_at, false);
    assert_eq!(diff["summary"]["root_inputs"], 3, "{diff:#}");
    assert_eq!(diff["summary"]["divergent_turns"], 0, "{diff:#}");
    assert_eq!(diff["responses"]["changed"], 0, "{diff:#}");
    assert_eq!(diff["summary"]["changed"], false, "{diff:#}");
}

/// The first LSN the main log still holds: its first segment's name.
fn log_start(dir: &std::path::Path) -> u64 {
    std::fs::read_dir(dir.join("branches/main/log"))
        .unwrap()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            name.strip_suffix(".seg")?.parse::<u64>().ok()
        })
        .min()
        .unwrap()
}

/// M26 criterion 7 (slice B16, docs/design/m26-blobs.md §6.1, §6.3): a blob
/// that a replay in progress is reading is not cleaned away during the
/// replay. A proposal's isolated replay is parked
/// (`Proposals::with_test_gate`) before the root input that reads a blob
/// its actor held at the fork point and has released since; retention then
/// moves the log's start past every record that references the blob, and
/// two immediate passes of the collector run. The blob stays: the replay's
/// floor lease and its fork's roots keep it. Let go, the parked turn reads
/// it, and nothing diverges.
#[test]
fn a_replay_in_progress_keeps_the_blobs_it_reads() {
    let dir = tempdir();
    // The proposal needs its fork point within retention (7 days);
    // retention then runs with no history at all.
    let storage = StorageConfig::new(dir.path().to_path_buf());
    let p = Proc::start_with(
        dir.path(),
        NodeConfig {
            concurrency: 8,
            storage: Some(storage.clone()),
            segment_max_bytes: Some(4096),
            blobs: Some(BlobsConfig {
                gc_interval: Duration::ZERO,
                ..BlobsConfig::default()
            }),
            ..NodeConfig::default()
        },
    );
    p.deploy("media");
    // media/a holds a blob at the fork point.
    let put = ok(&p, "put", "size=5000");
    let hash = put.split(' ').nth(1).unwrap().to_owned();
    let fork_at = p.settle();
    // After it, a turn reads the blob, and then the actor releases it.
    let sum = ok(&p, "held-sum", "");
    assert!(sum.starts_with("5000 "), "{sum}");
    assert_eq!(ok(&p, "release", ""), "released");
    let released_at = p.settle();

    // A proposal of the same code (a custom section makes it another
    // component), replayed in isolation from the fork point; parked before
    // its first root input, the read.
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let props = Arc::new(
        Proposals::open(p.node.clone(), dir.path().to_path_buf())
            .unwrap()
            .with_test_gate(gate.clone()),
    );
    let v2 = media_v2();
    let task = {
        let props = props.clone();
        let owner = p.owner();
        p.rt.spawn(async move {
            props
                .propose(
                    ProposeRequest {
                        at: Some(fork_at),
                        options: DiffOptions {
                            mode: Mode::Isolated,
                            ..DiffOptions::default()
                        },
                        workers: Some(1),
                        ..propose_request(vec![v2])
                    },
                    owner,
                )
                .await
        })
    };
    let store = p.node.blob_store().unwrap().clone();
    for _ in 0..3000 {
        if store.leases().lowest_floor().is_some() {
            break;
        }
        assert!(
            !task.is_finished(),
            "{:?}",
            p.rt.block_on(task).unwrap().map(|_| ())
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        store.leases().lowest_floor(),
        Some(fork_at),
        "the replay's floor lease"
    );

    // Retention moves the log's start past every record that references
    // the blob: turns that roll segments, a snapshot, a later turn, a pass.
    for i in 0..60 {
        ok(&p, "info", &format!("n={i}"));
    }
    let owner = p.owner();
    p.rt.block_on(p.node.snapshot("manual", owner)).unwrap();
    let hwm = p.node.store().db().time_hwm().unwrap();
    while p.node.store().db().time_hwm().unwrap() <= hwm {
        std::thread::sleep(Duration::from_millis(2));
        ok(&p, "info", "");
    }
    p.node
        .compact(&StorageConfig {
            history: Duration::ZERO,
            ..storage
        })
        .unwrap();
    assert!(
        log_start(dir.path()) > released_at,
        "the log still holds the records that reference the blob"
    );

    // Two immediate passes: the blob stays.
    for _ in 0..2 {
        p.rt.block_on(p.node.blob_gc(SweepOptions {
            immediate: true,
            ..Default::default()
        }))
        .unwrap();
    }
    let id = BlobId::parse(&hash).unwrap();
    assert!(
        store.object_path(&Space::Main, &id).exists(),
        "the collector deleted a blob a replay in progress reads"
    );

    // Let go: the parked turn reads it, and nothing diverges.
    gate.add_permits(1 << 20);
    let (proposal, _) = p.rt.block_on(task).unwrap().unwrap();
    let diff: serde_json::Value = serde_json::from_slice(
        &p.rt
            .block_on(props.diff(&proposal.id, false, false))
            .unwrap(),
    )
    .unwrap();
    let summary = &diff["summary"];
    assert_eq!(summary["divergent_turns"], 0, "{diff:#}");
    assert!(summary["replayed"].as_u64().unwrap() >= 2, "{diff:#}");
}
