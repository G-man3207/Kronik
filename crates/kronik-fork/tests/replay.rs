//! Replay and diff tests against a real node's recorded history
//! (docs/design/m3-fork.md §10).

// Test helpers may unwrap; the test HTTP server uses plain std threads.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use common::*;
use kronik_core::ids::Lsn;
use kronik_fork::diff::{DiffOptions, Mode};
use kronik_fork::{ForkKind, ProductionIndex, ReplayOutput, ReplaySetup, config_at, fork_kinds};
use kronik_runtime::TurnLimits;
use serde_json::Value;

fn replay(
    p: &Proc,
    wasm: Option<&str>,
    fork_lsn: Lsn,
    options: &DiffOptions,
    workers: usize,
) -> ReplayOutput {
    replay_with(p, wasm, fork_lsn, options, workers, None)
}

/// `replay`, reading production from a base snapshot when given.
fn replay_with(
    p: &Proc,
    wasm: Option<&str>,
    fork_lsn: Lsn,
    options: &DiffOptions,
    workers: usize,
    base: Option<kronik_fork::index::Base>,
) -> ReplayOutput {
    let to = p.settle();
    let node = p.node.clone();
    p.rt.block_on(async move {
        let index = Arc::new(
            ProductionIndex::load_from(node.reader(), base, fork_lsn, to)
                .await
                .unwrap(),
        );
        let mut new = Vec::new();
        if let Some(w) = wasm {
            let bytes = std::fs::read(guest(w)).unwrap();
            let (hash, program) = node.code().add(&bytes).unwrap();
            let m = program.describe(TurnLimits::default()).await.unwrap();
            new.push((
                m.kind.clone(),
                ForkKind {
                    hash,
                    program,
                    schema_version: m.schema_version,
                },
            ));
        }
        let code = node.code().clone();
        let fc = fork_kinds(
            &index,
            fork_lsn,
            |h| code.get(h).map_err(|e| e.to_string()),
            &new,
        )
        .unwrap();
        let config = config_at(&index, fork_lsn);
        let mut setup = ReplaySetup::new(
            "f-test".into(),
            index.clone(),
            fc.kinds,
            config,
            node.secrets().cloned(),
        );
        setup.stubs = options.stubs.clone();
        setup.live = (!options.live_allowlist.is_empty()).then(|| kronik_fork::LiveAccess {
            hosts: options.live_allowlist.clone(),
            env: node.env().clone(),
        });
        let setup = Arc::new(setup);
        kronik_fork::run(
            node.env(),
            setup,
            options,
            workers,
            None,
            fc.before,
            fc.after,
            &[],
        )
        .await
        .unwrap()
    })
}

fn json(out: &ReplayOutput) -> Value {
    serde_json::from_slice(&out.bytes).unwrap()
}

fn opts(mode: Mode) -> DiffOptions {
    DiffOptions {
        mode,
        ..DiffOptions::default()
    }
}

#[test]
fn identity_step2_isolation_drift_workers_and_sampling() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let fork_lsn = p.settle();
    let keys = ["a", "b", "c"];
    for i in 0..10 {
        for k in keys {
            p.http(k, "increment", "");
        }
        p.send(&format!("counter/m{}", i % 2), "increment", "");
    }
    // HTTP turns reply n.
    assert_eq!(http_body(&p.http("a", "increment", "")), "11");
    let http_inputs = 31;

    // Identity: the same code gives an empty diff in both modes.
    let same = replay(&p, None, fork_lsn, &opts(Mode::Both), 2);
    let s = &same.diff.summary;
    assert!(!s.changed, "{}", String::from_utf8_lossy(&same.bytes));
    assert_eq!((s.root_inputs, s.replayed, s.divergent_turns), (41, 41, 0));
    assert_eq!(s.turns_prod, s.turns_fork);
    assert_eq!(same.diff.responses.unchanged, http_inputs);
    assert_eq!(s.confidence, 1.0);

    // Counter +2.
    let both = replay(&p, Some("counter-step2"), fork_lsn, &opts(Mode::Both), 2);
    let d = &both.diff;
    assert!(d.summary.changed);
    assert_eq!(d.responses.changed, http_inputs);
    assert_eq!(d.summary.synthetic, 0);
    assert_eq!(d.summary.origins, 41);
    assert_eq!(d.state.isolated.len(), 41);
    // Isolation: the last request on counter/a ran on production's state
    // (n = 10), so the fork answers 12, not 22.
    let last = d.responses.items.last().unwrap();
    assert_eq!(last.route, "POST /counter/{key}/{op}");
    let v = serde_json::to_value(&last.body).unwrap();
    // The bodies parse as JSON numbers: one replace at the root.
    assert_eq!(v[0]["op"], "replace");
    assert_eq!(v[0]["path"], "");
    assert_eq!(v[0]["prod"], 11);
    assert_eq!(v[0]["fork"], 12);
    // Continuous: counter/a drifts to 22 (production 11).
    let a = d
        .state
        .continuous
        .iter()
        .find(|s| s.actor == "counter/a")
        .unwrap();
    assert_eq!(
        (a.keys[0].prod.as_str(), a.keys[0].fork.as_str()),
        (Some("11"), Some("22"))
    );
    assert_eq!(d.cumulative.actors_changed, 5);
    let j = json(&both);
    assert_eq!(j["schema"], "kronik.diff/v1");
    assert_eq!(j["causes"][0]["input"], "POST /counter/{key}/{op}");
    assert_eq!(j["causes"][0]["origins"], 31);
    assert_eq!(j["causes"][1]["input"], "message increment");
    assert_eq!(j["causes"][1]["origins"], 10);

    // Same fork and code twice: identical bytes; 1, 4 and 16 workers too.
    let iso = |w| {
        replay(
            &p,
            Some("counter-step2"),
            fork_lsn,
            &opts(Mode::Isolated),
            w,
        )
    };
    let one = iso(1);
    assert_eq!(one.bytes, iso(1).bytes);
    assert_eq!(one.bytes, iso(4).bytes);
    assert_eq!(one.bytes, iso(16).bytes);
    assert_eq!(one.hash, kronik_fork::diff::diff_hash(&one.bytes));

    // Sampling: deterministic, stratified, coverage in the summary.
    let sampled = DiffOptions {
        mode: Mode::Isolated,
        sample: 0.25,
        ..DiffOptions::default()
    };
    let s1 = replay(&p, Some("counter-step2"), fork_lsn, &sampled, 2);
    let s2 = replay(&p, Some("counter-step2"), fork_lsn, &sampled, 3);
    assert_eq!(s1.bytes, s2.bytes);
    // Strata: POST /counter/{key}/{op} (31 -> 8), message increment (10 -> 3).
    assert_eq!(s1.diff.summary.replayed, 11);
    assert_eq!(s1.diff.summary.sample, kronik_fork::diff::r6(11.0 / 41.0));

    // Markdown renders deterministically.
    let md = kronik_fork::markdown::render(&both.diff, None);
    assert!(md.contains("41 origins"), "{md}");
    assert_eq!(md, kronik_fork::markdown::render(&both.diff, None));
}

/// Isolated replay where a second worker splits the first worker's range
/// mid-chunk (as the continuous replay's task does in both modes once it is
/// done) gives the same diff bytes as one worker without a split.
#[test]
fn isolated_split_mid_chunk_gives_the_same_diff() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let fork_lsn = p.settle();
    for i in 0..60 {
        p.http(["a", "b", "c"][i % 3], "increment", "");
        if i % 4 == 0 {
            p.send(&format!("counter/m{}", i % 2), "increment", "");
        }
    }
    let to = p.settle();
    let node = p.node.clone();
    let (split, whole) = p.rt.block_on(async move {
        let index = Arc::new(
            ProductionIndex::load_from(node.reader(), None, fork_lsn, to)
                .await
                .unwrap(),
        );
        let bytes = std::fs::read(guest("counter-step2")).unwrap();
        let (hash, program) = node.code().add(&bytes).unwrap();
        let m = program.describe(TurnLimits::default()).await.unwrap();
        let new = [(
            m.kind.clone(),
            ForkKind {
                hash,
                program,
                schema_version: m.schema_version,
            },
        )];
        let code = node.code().clone();
        let fc = fork_kinds(
            &index,
            fork_lsn,
            |h| code.get(h).map_err(|e| e.to_string()),
            &new,
        )
        .unwrap();
        let setup = Arc::new(ReplaySetup::new(
            "f-test".into(),
            index.clone(),
            fc.kinds,
            config_at(&index, fork_lsn),
            node.secrets().cloned(),
        ));
        let env = node.env();
        let roots = index.roots.clone();
        let options = opts(Mode::Isolated);
        let diff = |trees: &[kronik_fork::replay::TreeResult]| {
            kronik_fork::diff::build(kronik_fork::diff::DiffInput {
                fork: "f-test",
                proposal_id: None,
                index: &index,
                before: fc.before.clone(),
                after: fc.after.clone(),
                options: &options,
                isolated: Some(trees),
                continuous: None,
            })
            .unwrap()
            .to_bytes()
        };
        let whole = kronik_fork::replay::isolated(env, setup.clone(), roots.clone(), 1)
            .await
            .unwrap();
        // One range of every root; a second worker splits it at once.
        let split = kronik_fork::replay::isolated_split(env, setup, roots, 1, 1, 2)
            .await
            .unwrap();
        (diff(&split), diff(&whole))
    });
    assert!(serde_json::from_slice::<Value>(&whole).unwrap()["summary"]["changed"] == true);
    assert_eq!(split, whole);
}

#[test]
fn one_origin_with_1000_consequences() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let fork_lsn = p.settle();
    assert_eq!(http_body(&p.http("src", "fanout", "1000")), "1");
    p.wait_kv("counter/f999", "last");
    let out = replay(
        &p,
        Some("counter-step2"),
        fork_lsn,
        &opts(Mode::Isolated),
        2,
    );
    let d = &out.diff;
    assert_eq!((d.summary.origins, d.summary.consequences), (1, 1000));
    assert_eq!(d.summary.turns_prod, 1001);
    assert_eq!(d.causes.len(), 1);
    let c = &d.causes[0];
    assert_eq!(
        (c.kind.as_str(), c.input.as_str()),
        ("counter", "POST /counter/{key}/{op}")
    );
    assert_eq!((c.origins, c.consequences, c.root_inputs), (1, 1000, 1));
    assert!(c.samples[0].starts_with("f-test:r") && c.samples[0].ends_with(".0"));
}

#[test]
fn approximate_effects_and_no_live_requests() {
    let (addr, hits) = server();
    let dir = tempdir();
    let p = Proc::start(dir.path());
    p.grant("http:127.0.0.1");
    let fork_lsn = p.settle();
    for i in 0..5 {
        let spec = format!("POST http://{addr}/v1/charges/{}\n\namount=10", 1000 + i);
        assert_eq!(
            http_body(&p.http("pay", "fetch-ok", &spec)),
            format!("200 charged {}", i + 1)
        );
    }
    assert_eq!(hits.load(Ordering::SeqCst), 5);

    let same = replay(&p, None, fork_lsn, &opts(Mode::Both), 2);
    let s = &same.diff.summary;
    assert!(!s.changed);
    // Both modes ran, the isolated part counts groundings.
    assert_eq!(
        (s.exact, s.approximate, s.synthetic, s.confidence),
        (5, 0, 0, 1.0)
    );

    let v2 = replay(&p, Some("counter-body-v2"), fork_lsn, &opts(Mode::Both), 2);
    let d = &v2.diff;
    assert_eq!(
        (d.summary.exact, d.summary.approximate, d.summary.synthetic),
        (0, 5, 0)
    );
    assert!(d.summary.confidence < 1.0);
    assert_eq!(d.grounding.len(), 1);
    let g = &d.grounding[0];
    assert_eq!(
        (
            g.kind.as_str(),
            g.method.as_str(),
            g.host.as_str(),
            g.route.as_str(),
            g.approximate
        ),
        ("http.fetch", "POST", "127.0.0.1", "/v1/charges/{}", 5)
    );
    assert_eq!(d.effects.changed, 5);
    let f = &d.effects.items[0].fields;
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].field, "body");
    assert_eq!(f[0].fork, "amount=10 v2");
    // The recorded responses were reused: the replies did not change.
    assert_eq!(d.responses.changed, 0);
    // Replay never reached the server.
    assert_eq!(hits.load(Ordering::SeqCst), 5);
}

#[test]
fn introduced_errors() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let fork_lsn = p.settle();
    p.http("a", "increment", "");
    for _ in 0..3 {
        p.send("counter/a", "get", "");
    }
    let out = replay(&p, Some("counter-fail-get"), fork_lsn, &opts(Mode::Both), 2);
    let e = &out.diff.errors;
    assert_eq!((e.introduced, e.fixed), (3, 0));
    assert_eq!(e.items[0].error_code, "TURN_FAILED");
    assert_eq!(e.items[0].message, "get is broken in this build");
    assert_eq!(e.items[0].input, "message get");
    assert_eq!(out.diff.samples.errors_introduced.len(), 3);
    // The reverse direction counts as fixed.
    let back = replay(&p, None, fork_lsn, &opts(Mode::Isolated), 1);
    assert_eq!(back.diff.errors.fixed, 0);
}

/// Identity replay of 10 000 recorded requests (slow in debug builds; run
/// with `cargo test --release -p kronik-fork -- --ignored`).
#[test]
#[ignore]
fn identity_replay_of_10k_requests() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let fork_lsn = p.settle();
    for i in 0..10_000 {
        p.http(&format!("k{}", i % 100), "increment", "");
    }
    for mode in [Mode::Isolated, Mode::Continuous] {
        let out = replay(&p, None, fork_lsn, &opts(mode), 4);
        let s = &out.diff.summary;
        assert!(!s.changed, "{mode:?}");
        assert_eq!((s.root_inputs, s.divergent_turns), (10_000, 0));
    }
}

/// webhook-relay-rs with a changed request body: changed effects,
/// approximate grounding, confidence below 1, grounding per target; the
/// signature is recomputed on the host (exact).
#[test]
fn webhook_relay_with_a_changed_body() {
    let (addr, hits) = server();
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let a = audit();
    let wasm = std::fs::read(guest("webhook-relay")).unwrap();
    p.rt.block_on(p.node.deploy(&wasm, a.clone(), false))
        .unwrap();
    p.node
        .secret_set("relay-signing-key", b"test-signing-key", &a, false)
        .unwrap();
    for cap in ["http:127.0.0.1", "secret:relay-signing-key"] {
        p.rt.block_on(
            p.node
                .grant("webhook-relay", cap, None, None, a.clone(), false),
        )
        .unwrap();
    }
    let target = format!("{{\"target\":\"http://{addr}/relay\"}}");
    let m = kronik_proto::log::v1::Message {
        name: "configure".into(),
        content_type: "application/json".into(),
        body: plain(&target),
        blobs: vec![],
    };
    let r = p.rt.block_on(p.node.send(
        kronik_core::ids::ActorRef::parse("webhook-relay/shop").unwrap(),
        m,
        a,
        false,
    ));
    assert!(r.unwrap().unwrap().committed());
    let fork_lsn = p.settle();
    for i in 0..4 {
        let http = kronik_proto::log::v1::HttpInput {
            method: "POST".into(),
            path: "/hooks/shop".into(),
            params: vec![kronik_proto::log::v1::Param {
                name: "key".into(),
                value: "shop".into(),
                sealed_value: None,
            }],
            body: Some(kronik_proto::log::v1::Body {
                value: Some(kronik_proto::log::v1::body::Value::Inline(
                    plain(&format!("{{\"order\":{i}}}")).unwrap(),
                )),
            }),
            route: "/hooks/{key}".into(),
            ..Default::default()
        };
        let actor = kronik_core::ids::ActorRef::parse("webhook-relay/shop").unwrap();
        let w = match p.node.ingress(actor, http, None).unwrap() {
            kronik_sched::Ingress::Started(w) => w,
            _ => panic!("expected a new root input"),
        };
        let t = p.rt.block_on(w.wait()).unwrap();
        assert!(t.committed());
    }
    assert_eq!(hits.load(Ordering::SeqCst), 4);
    let same = replay(&p, None, fork_lsn, &opts(Mode::Both), 2);
    assert!(
        !same.diff.summary.changed,
        "{}",
        String::from_utf8_lossy(&same.bytes)
    );
    let v2 = replay(
        &p,
        Some("webhook-relay-body-v2"),
        fork_lsn,
        &opts(Mode::Both),
        2,
    );
    let d = &v2.diff;
    assert!(d.summary.confidence < 1.0, "{:?}", d.summary);
    assert_eq!(d.summary.synthetic, 0);
    let fetch = d.grounding.iter().find(|g| g.kind == "http.fetch").unwrap();
    assert_eq!(
        (
            fetch.method.as_str(),
            fetch.host.as_str(),
            fetch.route.as_str(),
            fetch.approximate
        ),
        ("POST", "127.0.0.1", "/relay", 4)
    );
    let hmac = d
        .grounding
        .iter()
        .find(|g| g.kind == "crypto.hmac-sha256")
        .unwrap();
    assert_eq!(
        (hmac.host.as_str(), hmac.exact, hmac.approximate),
        ("relay-signing-key", 4, 0)
    );
    let fetches: Vec<_> = d
        .effects
        .items
        .iter()
        .filter(|e| e.kind == "http.fetch")
        .collect();
    assert_eq!(fetches.len(), 4);
    let fields: Vec<&str> = fetches[0].fields.iter().map(|f| f.field.as_str()).collect();
    assert!(
        fields.contains(&"body") && fields.contains(&"header:x-signature"),
        "{fields:?}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 4);
}

/// Effects without a recording: FailClosed by default, a stub rule's
/// canned answer (synthetic), or a live GET to an allowlisted host; nothing
/// else reaches the network (I7).
#[test]
fn stub_rules_and_the_live_allowlist() {
    let (addr, hits) = server();
    let dir = tempdir();
    let p = Proc::start(dir.path());
    p.grant("http:127.0.0.1");
    let fork_lsn = p.settle();
    for i in 0..3 {
        let spec = format!("POST http://{addr}/v1/charges/{i}\n\namount=10");
        p.http("pay", "fetch-ok", &spec);
    }
    assert_eq!(hits.load(Ordering::SeqCst), 3);
    let hits_now = || hits.load(Ordering::SeqCst);

    // The fetch-extra build also GETs <url>/extra, never recorded:
    // FailClosed, the guest sees denied.
    let closed = replay(
        &p,
        Some("counter-fetch-extra"),
        fork_lsn,
        &opts(Mode::Both),
        2,
    );
    let s = &closed.diff.summary;
    assert_eq!((s.exact, s.synthetic, s.live), (3, 3, 0));
    assert_eq!(closed.diff.responses.changed, 3);
    assert!(
        serde_json::to_string(&closed.diff.responses.items[0].body)
            .unwrap()
            .contains("replay: no recording"),
        "{:?}",
        closed.diff.responses.items[0].body
    );
    assert_eq!(hits_now(), 3);

    // A stub rule answers it; still synthetic, and recorded in the options.
    let stubbed = DiffOptions {
        mode: Mode::Both,
        stubs: vec![kronik_fork::stubs::StubRule {
            method: Some("GET".into()),
            url_prefix: format!("http://{addr}/v1/charges/"),
            status: 200,
            headers: vec![],
            body: "stubbed".into(),
            error: None,
        }],
        ..DiffOptions::default()
    };
    let out = replay(&p, Some("counter-fetch-extra"), fork_lsn, &stubbed, 2);
    assert_eq!((out.diff.summary.synthetic, out.diff.summary.live), (3, 0));
    assert!(
        serde_json::to_string(&out.diff.responses.items[0].body)
            .unwrap()
            .contains("200 stubbed"),
        "{:?}",
        out.diff.responses.items[0].body
    );
    assert_eq!(json(&out)["options"]["stubs"][0]["body"], "stubbed");
    assert_eq!(hits_now(), 3);

    // An allowlist for another host lets nothing out.
    let elsewhere = DiffOptions {
        mode: Mode::Isolated,
        live_allowlist: vec!["example.com".into()],
        ..DiffOptions::default()
    };
    let out = replay(&p, Some("counter-fetch-extra"), fork_lsn, &elsewhere, 2);
    assert_eq!((out.diff.summary.synthetic, out.diff.summary.live), (3, 0));
    assert_eq!(hits_now(), 3);

    // Allowlisted: the three GETs go out live (grounding live, below 1).
    let live = DiffOptions {
        mode: Mode::Isolated,
        live_allowlist: vec!["127.0.0.1".into()],
        ..DiffOptions::default()
    };
    let out = replay(&p, Some("counter-fetch-extra"), fork_lsn, &live, 2);
    let s = &out.diff.summary;
    assert_eq!((s.exact, s.synthetic, s.live), (3, 0, 3));
    assert!(s.confidence < 1.0);
    assert_eq!(hits_now(), 6);
    let row = out
        .diff
        .grounding
        .iter()
        .find(|g| g.route == "/v1/charges/{}/extra")
        .unwrap();
    assert_eq!((row.method.as_str(), row.live), ("GET", 3));
}

/// A new schema version: `migrate(from)` runs in each isolated overlay
/// before the root input's turn, once per actor in continuous replay, and
/// the migration turns show in the diff.
#[test]
fn migrations_run_in_replay_and_show_in_the_diff() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let fork_lsn = p.settle();
    for _ in 0..3 {
        p.http("a", "increment", "");
        p.http("b", "increment", "");
    }
    let iso = replay(
        &p,
        Some("counter-schema1"),
        fork_lsn,
        &opts(Mode::Isolated),
        2,
    );
    let d = &iso.diff;
    assert_eq!((d.summary.turns_prod, d.summary.turns_fork), (6, 12));
    assert_eq!((d.summary.origins, d.summary.consequences), (0, 6));
    assert_eq!(d.errors.introduced, 0);
    // Every tree's overlay got the migration's write.
    let migrated = d
        .state
        .isolated
        .iter()
        .filter(|s| {
            s.keys
                .iter()
                .any(|k| k.key == "schema" && k.fork == "1" && k.prod.is_null())
        })
        .count();
    assert_eq!(migrated, 6);
    assert_eq!(d.code.after[0].schema_version, 1);

    let cont = replay(
        &p,
        Some("counter-schema1"),
        fork_lsn,
        &opts(Mode::Continuous),
        1,
    );
    let d = &cont.diff;
    assert_eq!((d.summary.turns_prod, d.summary.turns_fork), (6, 8));
    assert_eq!(d.summary.consequences, 2);
    for actor in ["counter/a", "counter/b"] {
        let s = d
            .state
            .continuous
            .iter()
            .find(|s| s.actor == actor)
            .unwrap();
        let k = s.keys.iter().find(|k| k.key == "schema").unwrap();
        assert_eq!((k.op.as_ref(), &k.fork), ("set", &serde_json::json!("1")));
    }
}

/// Replay that starts from a snapshot gives the same diff as replay from
/// LSN 1 (m6-storage §3), with SQL actors in the snapshot.
#[test]
fn replay_from_a_snapshot_equals_replay_from_the_start() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let notes = std::fs::read(guest("notes")).unwrap();
    p.rt.block_on(p.node.deploy(&notes, audit(), false))
        .unwrap();
    let note = |key: &str, text: &str| {
        let m = kronik_proto::log::v1::Message {
            name: "add".into(),
            content_type: "text/plain".into(),
            body: plain(text),
            blobs: vec![],
        };
        let actor = kronik_core::ids::ActorRef::parse(&format!("notes/{key}")).unwrap();
        p.rt.block_on(p.node.send(actor, m, audit(), false))
            .unwrap()
            .unwrap();
    };
    for i in 0..6 {
        p.http(&format!("k{}", i % 3), "increment", "");
        note(&format!("n{}", i % 2), &format!("before {i}"));
    }
    p.settle();
    let snap = p.rt.block_on(p.node.snapshot("manual")).unwrap();
    for i in 0..4 {
        p.http(&format!("k{}", i % 3), "increment", "");
        note("n0", &format!("between {i}"));
    }
    let fork_lsn = p.settle();
    for i in 0..6 {
        p.http(&format!("k{}", i % 4), "increment", "");
        note(&format!("n{}", i % 3), &format!("window {i}"));
    }
    let base = kronik_fork::pick_base(dir.path(), "main", fork_lsn, false)
        .unwrap()
        .unwrap();
    assert_eq!(base.lsn, snap.lsn);
    let full = replay(&p, Some("counter-step2"), fork_lsn, &opts(Mode::Both), 2);
    let based = replay_with(
        &p,
        Some("counter-step2"),
        fork_lsn,
        &opts(Mode::Both),
        2,
        Some(base),
    );
    assert!(full.diff.summary.changed);
    assert_eq!(
        String::from_utf8_lossy(&full.bytes),
        String::from_utf8_lossy(&based.bytes)
    );
}

/// Identity replay is empty when production holds turns that failed with
/// EFFECT_OUTCOME_UNKNOWN (an unsafe request cut off by a crash): the fork
/// reuses the unknown outcome and fails the same way (reported by
/// fast-foundation's crash test).
#[test]
fn identity_replay_over_outcome_unknown_turns_is_empty() {
    use std::io::{BufRead, BufReader};
    // A server that reads requests and never answers.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let s2 = seen.clone();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming().flatten() {
            let mut r = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            let _ = r.read_line(&mut line);
            s2.fetch_add(1, Ordering::SeqCst);
            held.push(stream);
        }
    });
    let dir = tempdir();
    let p = Proc::start(dir.path());
    p.grant("http:127.0.0.1");
    let fork_lsn = p.settle();
    let node = p.node.clone();
    let spec = format!("POST http://{addr}/charge\n\nx");
    p.rt.spawn(async move {
        let m = kronik_proto::log::v1::Message {
            name: "fetch".into(),
            content_type: "text/plain".into(),
            body: plain(&spec),
            blobs: vec![],
        };
        let _ = node
            .send(
                kronik_core::ids::ActorRef::parse("counter/u").unwrap(),
                m,
                audit(),
                false,
            )
            .await;
    });
    while seen.load(Ordering::SeqCst) == 0 {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    std::thread::sleep(std::time::Duration::from_millis(50));
    drop(p); // the crash: the unsafe request's outcome is unknown
    let p = Proc::start(dir.path());
    p.http("a", "increment", "");
    let to = p.settle();
    let unknown = (fork_lsn..=to).any(|l| {
        let r = p.rt.block_on(p.node.read_record(l)).unwrap();
        matches!(r.map(|c| c.record), Some(kronik_proto::Record::TurnRecord(t))
            if t.outcome.as_ref().is_some_and(|o| o.error_code == "EFFECT_OUTCOME_UNKNOWN"))
    });
    assert!(unknown, "production should hold an outcome-unknown turn");
    let out = replay(&p, None, fork_lsn, &opts(Mode::Both), 2);
    let s = &out.diff.summary;
    assert!(!s.changed, "{}", String::from_utf8_lossy(&out.bytes));
    assert_eq!(s.divergent_turns, 0);
    assert!(out.diff.errors.outcome_unknown >= 1);
}

#[test]
fn isolated_identity_over_timers_and_calls_is_empty() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let fork_lsn = p.settle();
    // A timer set by a root input fires inside the window: the isolated
    // tree fires it where production did.
    p.send("counter/t", "schedule", "1 increment");
    p.wait_kv("counter/t", "n");
    // Calls: a callee commits before its caller's record, so the tree
    // starts at the caller's TurnBegin.
    for i in 0..3 {
        p.send(&format!("counter/c{i}"), "call", "counter/ledger increment");
    }
    let to = p.settle();
    let records: Vec<_> = (fork_lsn + 1..=to)
        .filter_map(|l| p.rt.block_on(p.node.read_record(l)).unwrap())
        .collect();
    let lsn_of = |actor: &str| {
        records.iter().find_map(|c| match &c.record {
            kronik_proto::Record::TurnRecord(t)
                if t.actor
                    .as_ref()
                    .is_some_and(|a| format!("{}/{}", a.kind, a.key) == actor) =>
            {
                Some(c.lsn)
            }
            _ => None,
        })
    };
    assert!(lsn_of("counter/ledger").unwrap() < lsn_of("counter/c0").unwrap());
    for mode in [Mode::Isolated, Mode::Both] {
        let out = replay(&p, None, fork_lsn, &opts(mode), 2);
        let s = &out.diff.summary;
        assert!(
            !s.changed,
            "{mode:?}: {}",
            String::from_utf8_lossy(&out.bytes)
        );
        assert_eq!(
            (s.turns_prod, s.divergent_turns),
            (s.turns_fork, 0),
            "{mode:?}"
        );
    }
    // One worker: the trees share a cursor, in order of their first record.
    let out = replay(&p, None, fork_lsn, &opts(Mode::Isolated), 1);
    assert!(
        !out.diff.summary.changed,
        "{}",
        String::from_utf8_lossy(&out.bytes)
    );
}

/// A root input whose turn fails after a successful call must run the
/// call's compensation message as a consequence turn in the fork exactly
/// as in production, and the compensation must read the state the callee
/// wrote (billing-ts's declined charge: the ledger `reverse` turn saw no
/// posting to reverse and committed without a write).
#[test]
fn isolated_identity_over_a_failed_call_compensation_is_empty() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let fork_lsn = p.settle();
    // The compensation is `increment`, which reads the counter state the
    // called turn wrote: production books 2 per ledger, once for the call
    // and once for the compensation.
    for i in 0..3 {
        p.send(
            &format!("counter/c{i}"),
            "call-fail",
            &format!("counter/l{i} increment increment"),
        );
    }
    let to = p.settle();
    for i in 0..3 {
        let n = p
            .node
            .store()
            .db()
            .kv_get("counter", &format!("l{i}"), "n")
            .unwrap();
        assert_eq!(n.as_deref(), Some(b"2".as_slice()), "counter/l{i}");
    }
    // Production holds one compensation turn per failed call.
    let records: Vec<_> = (fork_lsn + 1..=to)
        .filter_map(|l| p.rt.block_on(p.node.read_record(l)).unwrap())
        .collect();
    let comps = records
        .iter()
        .filter(|c| {
            matches!(
                &c.record,
                kronik_proto::Record::TurnRecord(t)
                    if t.input.as_ref().and_then(|i| i.kind.as_ref()).is_some_and(
                        |k| matches!(k, kronik_proto::log::v1::input::Kind::Message(m)
                            if m.source == kronik_proto::log::v1::MessageSource::Compensation as i32)
                    )
            )
        })
        .count();
    assert_eq!(comps, 3, "production should hold three compensation turns");
    for mode in [Mode::Isolated, Mode::Both] {
        let out = replay(&p, None, fork_lsn, &opts(mode), 2);
        let s = &out.diff.summary;
        assert!(
            !s.changed,
            "{mode:?}: {}",
            String::from_utf8_lossy(&out.bytes)
        );
        assert_eq!(
            (s.turns_prod, s.divergent_turns),
            (s.turns_fork, 0),
            "{mode:?}"
        );
    }
    // One worker: the trees share a cursor, in order of their first record.
    let out = replay(&p, None, fork_lsn, &opts(Mode::Isolated), 1);
    assert!(
        !out.diff.summary.changed,
        "{}",
        String::from_utf8_lossy(&out.bytes)
    );
}

/// A timer consequence must see root inputs that committed after the turn
/// that scheduled it. Without that, identity replay reports the later root's
/// write as a difference of the scheduling turn.
#[test]
fn isolated_timer_sees_state_from_later_roots() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let fork_lsn = p.settle();
    // Long enough that the increment commits before the timer is due.
    p.send("counter/t", "schedule", "1500 increment");
    p.send("counter/t", "increment", "");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let n = p.node.store().db().kv_get("counter", "t", "n").unwrap();
        if n.as_deref() == Some(b"2".as_slice()) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timer never incremented past the intervening write: {n:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let to = p.settle();
    let records: Vec<_> = (fork_lsn + 1..=to)
        .filter_map(|l| p.rt.block_on(p.node.read_record(l)).unwrap())
        .collect();
    let lsn_of = |want: fn(&kronik_proto::log::v1::input::Kind) -> bool| {
        records.iter().find_map(|c| match &c.record {
            kronik_proto::Record::TurnRecord(t)
                if t.input
                    .as_ref()
                    .and_then(|i| i.kind.as_ref())
                    .is_some_and(want) =>
            {
                Some(c.lsn)
            }
            _ => None,
        })
    };
    let message = |name: &str| {
        records.iter().find_map(|c| match &c.record {
            kronik_proto::Record::TurnRecord(t)
                if t.input.as_ref().is_some_and(|i| {
                    matches!(&i.kind, Some(kronik_proto::log::v1::input::Kind::Message(m)) if m.msg.as_ref().is_some_and(|msg| msg.name == name))
                }) =>
            {
                Some(c.lsn)
            }
            _ => None,
        })
    };
    let scheduled = message("schedule").unwrap();
    let incremented = message("increment").unwrap();
    let fired = lsn_of(|k| matches!(k, kronik_proto::log::v1::input::Kind::Timer(_))).unwrap();
    assert!(
        scheduled < incremented && incremented < fired,
        "the timer must fire after the intervening increment (schedule {scheduled}, increment {incremented}, timer {fired})"
    );
    let out = replay(&p, None, fork_lsn, &opts(Mode::Isolated), 1);
    assert!(
        !out.diff.summary.changed,
        "{}",
        String::from_utf8_lossy(&out.bytes)
    );
    assert_eq!(out.diff.summary.divergent_turns, 0);
}
