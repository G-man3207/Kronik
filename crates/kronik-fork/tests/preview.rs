//! Preview forks against a real node (docs/design/m11-preview.md): bounded
//! memory and count (P-F3), a lock of their own (P-F4), fork commands
//! refused (P-F9), no production key (P-F10), and state started again after
//! an erasure (P-F11).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use kronik_core::error::ErrorCode;
use kronik_core::ids::ActorRef;
use kronik_fork::diff::{DiffOptions, MAX_SAMPLES};
use kronik_fork::proposal::preview::MAX_PREVIEWS;
use kronik_fork::proposal::{Proposal, Proposals, ProposeRequest};
use kronik_gateway::PreviewRouter;
use kronik_proto::log::v1 as pb;
use kronik_sched::{NodeConfig, TurnResult};

/// counter/x is 1 on main; returns a proposal of counter-step2 (increment
/// adds 2).
fn propose_step2(p: &Proc, props: &Arc<Proposals>) -> String {
    p.http("x", "increment", "");
    p.settle();
    let bytes = std::fs::read(guest("counter-step2")).unwrap();
    let (prop, _) =
        p.rt.block_on(props.propose(
            ProposeRequest {
                wasm: vec![bytes],
                names: Vec::new(),
                window_ms: None,
                at: None,
                options: DiffOptions::default(),
                workers: Some(2),
                audit: audit(),
                dry_run: false,
            },
            p.owner(),
        ))
        .unwrap();
    prop.id
}

fn create(p: &Proc, props: &Proposals, proposal: &str) -> String {
    p.rt.block_on(props.create_preview(proposal, None, false, audit(), false, p.owner()))
        .unwrap()
        .0
        .id
}

/// `POST /counter/x/<op>` as the gateway builds it.
fn request(op: &str, body: &str) -> (ActorRef, pb::HttpInput) {
    let input = pb::HttpInput {
        method: "POST".into(),
        path: format!("/counter/x/{op}"),
        params: vec![
            pb::Param {
                name: "key".into(),
                value: "x".into(),
                sealed_value: None,
            },
            pb::Param {
                name: "op".into(),
                value: op.into(),
                sealed_value: None,
            },
        ],
        body: Some(pb::Body {
            value: Some(pb::body::Value::Inline(plain(body).unwrap())),
        }),
        route: "/counter/{key}/{op}".into(),
        ..Default::default()
    };
    (ActorRef::parse("counter/x").unwrap(), input)
}

fn send(p: &Proc, props: &Arc<Proposals>, id: &str, op: &str, body: &str) -> TurnResult {
    let (actor, http) = request(op, body);
    let original = p.node.local_operator_authority().unwrap();
    p.rt.block_on(PreviewRouter::send(
        props.clone(),
        id.to_owned(),
        actor,
        http,
        None,
        original,
    ))
    .unwrap()
}

/// P-F3: a preview keeps at most MAX_SAMPLES slimmed turns in memory, the
/// diff still counts every request, and at most MAX_PREVIEWS live at once.
#[test]
fn previews_keep_bounded_state_and_are_capped() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    let proposal = propose_step2(&p, &props);
    let id = create(&p, &props, &proposal);
    for n in 1..=30u32 {
        let r = send(&p, &props, &id, "increment", "");
        assert_eq!(http_body(&r), (1 + 2 * n).to_string());
        let held = p.rt.block_on(props.preview_turns_held(&id)).unwrap();
        assert!(held <= MAX_SAMPLES, "{held} turns held after {n} requests");
    }
    let d: serde_json::Value =
        serde_json::from_slice(&p.rt.block_on(props.diff(&id, false, false)).unwrap()).unwrap();
    assert_eq!(d["summary"]["preview_inputs"], 30, "{d}");
    let samples = d["samples"]["preview"].as_array().unwrap();
    assert_eq!(samples.len(), MAX_SAMPLES, "{d}");
    assert_eq!(samples[0]["route"], "/counter/{key}/{op}", "{d}");
    assert_eq!(samples[0]["outcome"], "committed", "{d}");

    for _ in 1..MAX_PREVIEWS {
        create(&p, &props, &proposal);
    }
    for dry_run in [true, false] {
        let e = p
            .rt
            .block_on(props.create_preview(&proposal, None, false, audit(), dry_run, p.owner()))
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::PreviewLimit, "{e}");
    }
    p.rt.block_on(props.delete_preview(&id, audit(), false, p.owner()))
        .unwrap();
    create(&p, &props, &proposal);
}

#[test]
fn preview_persistence_failures_keep_intent_failure_and_caller_context() {
    let dir = tempdir();
    let mut fault = None;
    let p = Proc::start_env(
        dir.path(),
        NodeConfig {
            concurrency: 8,
            ..Default::default()
        },
        |env| fault = Some(ProposalSaveFault::install(env)),
    );
    let fault = fault.unwrap();
    let data = dir.path().join("preview-manager");
    let props = Arc::new(Proposals::open(p.node.clone(), data.clone()).unwrap());
    let proposal = propose_step2(&p, &props);
    let branches = data.join("branches");
    let audit = pb::Audit {
        token_id: "operator".into(),
        reason: "preview persistence fault".into(),
        wall_time_ms: 1234,
    };
    let before = p.node.applied_lsn();
    fault.arm(&data, "v-");
    let (preview, dry_run) =
        p.rt.block_on(props.create_preview(&proposal, None, true, audit.clone(), true, p.owner()))
            .unwrap();
    assert!(dry_run);
    assert_eq!(p.node.applied_lsn(), before);
    assert!(p.rt.block_on(props.previews()).is_empty());
    let branch = branches.join(&preview.id);
    assert!(branch.join("proposal.json").is_dir());
    assert!(!branch.join("proposal.tmp").exists());
    std::fs::remove_dir_all(&branch).unwrap();
    fault.arm(&data, "v-");
    let e =
        p.rt.block_on(props.create_preview(&proposal, None, true, audit.clone(), false, p.owner()))
            .unwrap_err();
    assert_eq!(e.code, ErrorCode::Internal, "{e}");
    assert!(p.rt.block_on(props.previews()).is_empty());
    let mut events = Vec::new();
    p.rt.block_on(p.node.reader().read(before + 1, p.node.applied_lsn(), |c| {
        if let kronik_proto::Record::AuditEvent(event) = c.record {
            events.push(event);
        }
        Ok(())
    }))
    .unwrap();
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(events[0].action, "preview.create");
    assert_eq!(events[1].action, "preview.create.failed");
    assert_eq!(events[0].target, events[1].target);
    for event in &events {
        assert_eq!(event.audit.as_ref(), Some(&audit));
        assert_eq!(event.details["proposal"], proposal);
        assert_eq!(event.details["no_pii"], "true");
    }
    assert_eq!(events[1].details["code"], e.code.as_str());
    let branch = branches.join(&events[0].target);
    assert!(branch.join("proposal.json").is_dir());
    let pending: Proposal =
        serde_json::from_slice(&std::fs::read(branch.join("proposal.tmp")).unwrap()).unwrap();
    assert_eq!(pending.id, events[0].target);
    assert_eq!(pending.status, "preview");
    assert_eq!(pending.preview.unwrap().proposal, proposal);

    std::fs::remove_dir_all(&branch).unwrap();
    let id = create(&p, &props, &proposal);
    let branch = branches.join(&id);
    std::fs::remove_dir_all(&branch).unwrap();
    std::fs::write(&branch, b"not a directory").unwrap();
    let before = p.node.applied_lsn();
    p.rt.block_on(props.delete_preview(&id, audit.clone(), true, p.owner()))
        .unwrap();
    assert_eq!(p.node.applied_lsn(), before);
    let e =
        p.rt.block_on(props.delete_preview(&id, audit.clone(), false, p.owner()))
            .unwrap_err();
    assert_eq!(e.code, ErrorCode::Internal, "{e}");
    let mut events = Vec::new();
    p.rt.block_on(p.node.reader().read(before + 1, p.node.applied_lsn(), |c| {
        if let kronik_proto::Record::AuditEvent(event) = c.record {
            events.push(event);
        }
        Ok(())
    }))
    .unwrap();
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(events[0].action, "preview.delete");
    assert_eq!(events[1].action, "preview.delete.failed");
    for event in &events {
        assert_eq!(event.target, id);
        assert_eq!(event.audit.as_ref(), Some(&audit));
    }
    assert_eq!(events[1].details["code"], e.code.as_str());
}

// The preview scrub reads the node's certified inventory
// (`Node::secret_values`). Warm certified bytes survive ciphertext damage,
// so the injection must also destroy the retained row's physical identity
// (version_hash) and force a recertification, which then fails closed and
// makes the inventory — and with it the preview — answer
// SECRET_UNAVAILABLE (the fleet unit test in crates/kronik-api/src/fleet.rs
// uses the same recipe).
#[test]
fn preview_output_is_unavailable_when_retained_secret_loading_fails() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    let proposal = propose_step2(&p, &props);
    let id = create(&p, &props, &proposal);
    p.rt.block_on(p.node.secret_set(
        "scrub",
        b"retained-preview-secret".to_vec(),
        &audit(),
        false,
        p.owner(),
    ))
    .unwrap();
    rusqlite::Connection::open(dir.path().join("keys/secrets.db"))
        .unwrap()
        .execute(
            "UPDATE secrets SET ciphertext = x'00', version_hash = x'00'",
            [],
        )
        .unwrap();
    p.rt.block_on(p.node.refresh_secret_inventory(p.owner()))
        .unwrap_err();
    let (actor, http) = request("get", "");
    let original = p.node.local_operator_authority().unwrap();
    let e =
        p.rt.block_on(PreviewRouter::send(props, id, actor, http, None, original))
            .unwrap_err();
    assert_eq!(e.code.as_str(), "SECRET_UNAVAILABLE", "{e}");
}

/// P-F4: a preview request waiting for an allowlisted live GET holds only
/// its preview: the proposals list, approve's dry run and route lookup
/// answer meanwhile.
#[test]
fn a_held_preview_request_blocks_no_operator_command() {
    // An allowlisted host that answers when the test says so.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (got, got_rx) = std::sync::mpsc::channel();
    let (release, release_rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let _ = s.read(&mut buf);
        got.send(()).unwrap();
        let _ = release_rx.recv();
        let _ =
            s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\nconnection: close\r\n\r\npong");
    });
    let dir = tempdir();
    let p = Proc::start(dir.path());
    p.grant("http:127.0.0.1");
    let props = Arc::new(
        Proposals::open(p.node.clone(), dir.path().to_path_buf())
            .unwrap()
            .with_live_allowlist(vec!["127.0.0.1".into()]),
    );
    let proposal = propose_step2(&p, &props);
    let id = create(&p, &props, &proposal);

    let (actor, http) = request("fetch-ok", &format!("GET http://{addr}/ping"));
    let original = p.node.local_operator_authority().unwrap();
    let held = p.rt.spawn(PreviewRouter::send(
        props.clone(),
        id.clone(),
        actor,
        http,
        None,
        original,
    ));
    got_rx.recv_timeout(Duration::from_secs(60)).unwrap();
    let env = p.node.env().clone();
    let quick = Duration::from_secs(5);
    p.rt.block_on(async {
        let list = env.timeout(quick, props.list()).await;
        assert!(
            list.is_ok(),
            "proposals list waited for the preview request"
        );
        let approve = env
            .timeout(
                quick,
                props.approve(&proposal, audit(), true, None, p.owner()),
            )
            .await;
        assert!(
            approve.is_ok(),
            "approve --dry-run waited for the preview request"
        );
        let routes = env
            .timeout(quick, PreviewRouter::routes(&*props, &id))
            .await;
        assert!(
            routes.is_ok_and(|r| r.is_ok()),
            "route lookup waited for the preview request"
        );
    });
    release.send(()).unwrap();
    let r = p.rt.block_on(held).unwrap().unwrap();
    assert_eq!(http_body(&r), "200 pong");
}

/// P-F9: deploy, replay, send and fork delete refuse a preview; it keeps
/// answering on its proposal's code.
#[test]
fn fork_commands_refuse_a_preview() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    let proposal = propose_step2(&p, &props);
    let id = create(&p, &props, &proposal);
    let wasm = std::fs::read(guest("counter")).unwrap();
    let msg = pb::Message {
        name: "increment".into(),
        content_type: "text/plain".into(),
        body: plain(""),
        blobs: vec![],
        retained_compensation_source: None,
    };
    let errors = [
        p.rt.block_on(props.fork_deploy(&id, &wasm, false, p.owner()))
            .map(|_| ())
            .unwrap_err(),
        p.rt.block_on(props.fork_replay(&id, None, DiffOptions::default(), None, p.owner()))
            .map(|_| ())
            .unwrap_err(),
        p.rt.block_on(props.fork_send(&id, ActorRef::parse("counter/x").unwrap(), msg, p.owner()))
            .map(|_| ())
            .unwrap_err(),
        p.rt.block_on(props.delete_fork(&id, false, p.owner()))
            .unwrap_err(),
    ];
    for e in errors {
        assert!(e.message.contains("is a preview"), "{e}");
    }
    assert_eq!(http_body(&send(&p, &props, &id, "increment", "")), "3");
}

/// P-F10: a preview computes no HMAC with the production key (no
/// recording) and reveals only the placeholder.
#[test]
fn a_preview_uses_no_production_key() {
    const SECRET: &str = "VALUE-preview-41c7aa";
    let dir = tempdir();
    let p = Proc::start(dir.path());
    p.rt.block_on(
        p.node
            .secret_set("k1", SECRET.as_bytes().to_vec(), &audit(), false, p.owner()),
    )
    .unwrap();
    p.grant("secret:k1");
    p.grant("secret-reveal:k1");
    let main = p.http("y", "hmac", "k1\ndata");
    assert!(main.committed(), "{main:?}");
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    let proposal = propose_step2(&p, &props);
    let id = create(&p, &props, &proposal);

    let r = send(&p, &props, &id, "hmac", "k1\ndata");
    assert!(!r.committed(), "{r:?}");
    assert!(r.outcome.message.contains("no recording"), "{r:?}");
    assert_ne!(http_body(&r), http_body(&main));
    let r = send(&p, &props, &id, "reveal", "k1");
    assert_eq!(http_body(&r), "[secret:k1]");
}

/// P-F11: an erasure makes previews drop their state; the next request
/// starts again from the fork point.
#[test]
fn forgotten_preview_states_start_again_from_the_fork_point() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    let proposal = propose_step2(&p, &props);
    let id = create(&p, &props, &proposal);
    assert_eq!(http_body(&send(&p, &props, &id, "increment", "")), "3");
    assert_eq!(http_body(&send(&p, &props, &id, "increment", "")), "5");
    props.forget_preview_states();
    assert_eq!(http_body(&send(&p, &props, &id, "increment", "")), "3");
}

/// N1: a preview's state takes at most `max_preview_requests` requests,
/// then answers PREVIEW_FULL; a rebuilt state (after an erasure) counts
/// again.
#[test]
fn a_preview_takes_a_bounded_number_of_requests() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let props = Arc::new(
        Proposals::open(p.node.clone(), dir.path().to_path_buf())
            .unwrap()
            .with_max_preview_requests(2),
    );
    let proposal = propose_step2(&p, &props);
    let id = create(&p, &props, &proposal);
    send(&p, &props, &id, "increment", "");
    assert_eq!(http_body(&send(&p, &props, &id, "increment", "")), "5");
    let (actor, http) = request("increment", "");
    let original = p.node.local_operator_authority().unwrap();
    let e =
        p.rt.block_on(PreviewRouter::send(
            props.clone(),
            id.clone(),
            actor,
            http,
            None,
            original,
        ))
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::PreviewFull, "{e}");
    props.forget_preview_states();
    assert_eq!(http_body(&send(&p, &props, &id, "increment", "")), "3");
}
