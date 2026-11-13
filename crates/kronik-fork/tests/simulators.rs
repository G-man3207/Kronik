//! Effect simulators end to end against a real node
//! (docs/design/m12-simulators.md §7): labels, contract fakes, the model
//! simulator's cache and privacy, and policy per target.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::sync::Arc;

use common::*;
use kronik_core::error::ErrorCode;
use kronik_effects::InForks;
use kronik_fork::diff::DiffOptions;
use kronik_fork::proposal::Proposals;
use kronik_fork::simulators::{ModelAccess, ModelCache, ModelSecretSnapshot, SimulatorOverride};
use kronik_fork::stubs::StubRule;
use kronik_policy::{Action, RuleSet};
use kronik_proto::log::v1 as pb;
use serde_json::{Value, json};

/// Three recorded charges to `addr`; returns the LSN before them.
fn three_charges(p: &Proc, addr: &str) -> u64 {
    p.grant("http:127.0.0.1");
    let fork_lsn = p.settle();
    for i in 0..3 {
        p.http(
            "pay",
            "fetch-ok",
            &format!("POST http://{addr}/v1/charges/{i}\n\namount=10"),
        );
    }
    fork_lsn
}

fn set(p: &Proc, m: pb::SimulatorConfig) {
    p.rt.block_on(p.node.set_simulators(m, audit(), false, p.owner()))
        .unwrap();
}

fn target(
    stubs: Vec<pb::StubRuleSpec>,
    contract: &[u8],
    neighbor: bool,
    model: bool,
) -> pb::SimulatorConfig {
    pb::SimulatorConfig {
        target: "http:127.0.0.1".into(),
        stubs,
        contract: contract.to_vec(),
        neighbor,
        model,
        ..Default::default()
    }
}

/// The same configuration carried by a replay request (I5: main's
/// configuration after the fork point does not apply to the fork).
fn overrides(
    stubs: Vec<StubRule>,
    contract: Option<&str>,
    neighbor: bool,
    model: bool,
) -> DiffOptions {
    DiffOptions {
        simulator_overrides: vec![SimulatorOverride {
            target: "http:127.0.0.1".into(),
            stubs,
            contract: contract.map(|c| serde_json::from_str(c).unwrap()),
            neighbor,
            model,
        }],
        ..DiffOptions::default()
    }
}

/// A fork of the fetch-extra build (it also GETs `<url>/extra`, never
/// recorded) at `fork_lsn`.
fn fork(p: &Proc, props: &Arc<Proposals>, name: &str, fork_lsn: u64) {
    p.rt.block_on(props.create_fork(
        Some(name.into()),
        fork_lsn,
        false,
        audit(),
        false,
        p.owner(),
    ))
    .unwrap();
    let bytes = std::fs::read(guest("counter-fetch-extra")).unwrap();
    p.rt.block_on(props.fork_deploy(name, &bytes, false, p.owner()))
        .unwrap();
}

/// Replays the fork over everything so far; the diff's bytes.
fn replay(p: &Proc, props: &Arc<Proposals>, name: &str) -> Vec<u8> {
    replay_with(p, props, name, DiffOptions::default())
}

fn replay_with(p: &Proc, props: &Arc<Proposals>, name: &str, options: DiffOptions) -> Vec<u8> {
    p.settle();
    // A replay verifies the recorded operation against the certified source;
    // the daemon answers the documented fail-closed 503 SECRET_UNAVAILABLE
    // while its certificate is retired (ADR 0108), so await that window
    // (bounded) instead of racing it.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        match p
            .rt
            .block_on(props.fork_replay(name, None, options.clone(), Some(2), p.owner()))
        {
            Ok(_) => break,
            Err(error)
                if error.code == ErrorCode::SecretUnavailable
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(error) => panic!("fork replay of {name}: {error}"),
        }
    }
    p.rt.block_on(props.diff(name, false, false)).unwrap()
}

fn extra_items(d: &Value) -> Vec<&Value> {
    d["effects"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["route"] == "/v1/charges/{}/extra")
        .collect()
}

/// Every extra item is `synthetic` (the v0.1 value) answered by `sim`.
fn all_synthetic_by(d: &Value, sim: &str) -> bool {
    let items = extra_items(d);
    !items.is_empty()
        && items
            .iter()
            .all(|e| e["grounding"] == "synthetic" && e["simulator"] == sim)
}

const CONTRACT: &str = r#"{
  "openapi": "3.0.3",
  "info": {"title": "Charges", "version": "1"},
  "paths": {
    "/v1/charges/{id}/extra": {
      "get": {
        "responses": {
          "200": {
            "description": "extra",
            "content": {"application/json": {"schema": {
              "type": "object",
              "required": ["id", "amount", "currency"],
              "properties": {
                "id": {"type": "string"},
                "amount": {"type": "integer", "minimum": 0},
                "currency": {"type": "string", "enum": ["SEK", "EUR"]}
              }
            }}}
          }
        }
      }
    }
  }
}"#;

/// M12 (1) and (2): every synthetic answer is labeled with its simulator in
/// the diff (items, grounding rows, summary, options) and in the fork's
/// turns, while `grounding` keeps its v0.1 value `synthetic` (review M1); a
/// contract fake answers schema-valid and the same every time.
#[test]
fn simulators_label_every_synthetic_answer() {
    let (addr, hits) = server();
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let fork_lsn = three_charges(&p, &addr);
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    fork(&p, &props, "try", fork_lsn);

    // Nothing configured: the extra GETs fail closed, labeled so.
    let d: Value = serde_json::from_slice(&replay(&p, &props, "try")).unwrap();
    assert_eq!(
        d["summary"]["synthetic_by"],
        json!({"fail-closed": 3}),
        "{d}"
    );
    assert!(d["options"].get("simulators").is_none(), "{}", d["options"]);
    assert!(all_synthetic_by(&d, "fail-closed"), "{d}");

    // A contract: schema-valid answers, labeled contract.
    let first = replay_with(
        &p,
        &props,
        "try",
        overrides(vec![], Some(CONTRACT), true, false),
    );
    let d: Value = serde_json::from_slice(&first).unwrap();
    assert_eq!(d["summary"]["synthetic_by"], json!({"contract": 3}), "{d}");
    let row = d["grounding"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["route"] == "/v1/charges/{}/extra")
        .unwrap();
    assert_eq!(row["synthetic_by"], json!({"contract": 3}), "{row}");
    let opt = &d["options"]["simulators"][0];
    assert_eq!(
        (
            &opt["target"],
            &opt["stubs"],
            &opt["neighbor"],
            &opt["model"],
            &opt["request"]
        ),
        (
            &json!("http:127.0.0.1"),
            &json!(0),
            &json!(true),
            &json!(false),
            &json!(true)
        ),
        "{opt}"
    );
    assert!(
        opt["contract"].as_str().unwrap().starts_with("b3:"),
        "{opt}"
    );
    assert_eq!(
        d["options"]["simulator_overrides"][0]["target"],
        "http:127.0.0.1"
    );
    assert!(all_synthetic_by(&d, "contract"), "{d}");
    // The fork's turns say so too (what `kronik trace --fork` shows).
    let turn =
        p.rt.block_on(props.fork_turn("try", fork_lsn + 3))
            .unwrap()
            .unwrap();
    let extra = turn
        .effects
        .iter()
        .find(|e| e.grounding == pb::Grounding::Synthetic as i32)
        .unwrap();
    assert_eq!(extra.simulator, "contract");
    let resp = match extra.response.as_ref().and_then(|s| s.value.as_ref()) {
        Some(pb::sealable::Value::Plain(b)) => {
            <pb::HttpEffectResponse as prost::Message>::decode(b.as_slice()).unwrap()
        }
        other => panic!("{other:?}"),
    };
    assert_eq!(resp.status, 200);
    let body: Value = serde_json::from_slice(&resp.body).unwrap();
    assert!(body["id"].is_string(), "{body}");
    assert!(body["amount"].as_i64().is_some_and(|a| a >= 0), "{body}");
    assert!(
        ["SEK", "EUR"].contains(&body["currency"].as_str().unwrap()),
        "{body}"
    );
    // The same requests get the same answers.
    assert_eq!(
        replay_with(
            &p,
            &props,
            "try",
            overrides(vec![], Some(CONTRACT), true, false)
        ),
        first
    );

    // A target stub comes before the contract.
    let stub = StubRule {
        method: Some("GET".into()),
        url_prefix: format!("http://{addr}/v1/charges/"),
        status: 200,
        headers: vec![],
        body: "stubbed".into(),
        error: None,
    };
    let d: Value = serde_json::from_slice(&replay_with(
        &p,
        &props,
        "try",
        overrides(vec![stub], Some(CONTRACT), false, false),
    ))
    .unwrap();
    assert_eq!(d["summary"]["synthetic_by"], json!({"stub": 3}), "{d}");
    assert!(all_synthetic_by(&d, "stub"), "{d}");

    // A request stub (replay options) also says stub.
    let options = DiffOptions {
        stubs: vec![StubRule {
            method: None,
            url_prefix: format!("http://{addr}/"),
            status: 503,
            headers: vec![],
            body: String::new(),
            error: None,
        }],
        ..DiffOptions::default()
    };
    let d: Value = serde_json::from_slice(&replay_with(&p, &props, "try", options)).unwrap();
    assert_eq!(d["summary"]["synthetic_by"], json!({"stub": 3}), "{d}");
    // Nothing went out.
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 3);
}

/// Review M16 and M2 (I5): a fork uses main's simulator configuration as
/// of its fork point. Configuration set later never applies to it, also
/// when the window grows (catch-up) and after a restart; a configuration
/// set before the fork point does.
#[test]
fn simulator_configuration_is_taken_at_the_fork_point() {
    let (addr, _hits) = server();
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let fork_lsn = three_charges(&p, &addr);
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    fork(&p, &props, "try", fork_lsn);
    let first = replay(&p, &props, "try");

    // Main sets a contract after the fork point: the same window gives the
    // same bytes.
    set(&p, target(vec![], CONTRACT.as_bytes(), false, false));
    p.settle();
    let to = p.node.applied_lsn();
    p.rt.block_on(props.fork_replay("try", Some(to), DiffOptions::default(), Some(2), p.owner()))
        .unwrap();
    let d: Value =
        serde_json::from_slice(&p.rt.block_on(props.diff("try", false, false)).unwrap()).unwrap();
    assert_eq!(
        d["summary"]["synthetic_by"],
        json!({"fail-closed": 3}),
        "{d}"
    );
    assert!(d["options"].get("simulators").is_none(), "{}", d["options"]);

    // More traffic: the longer window still uses the fork point's
    // configuration, before and after a restart.
    p.http(
        "pay",
        "fetch-ok",
        &format!("POST http://{addr}/v1/charges/9\n\namount=10"),
    );
    let longer = replay(&p, &props, "try");
    let d: Value = serde_json::from_slice(&longer).unwrap();
    assert_eq!(
        d["summary"]["synthetic_by"],
        json!({"fail-closed": 4}),
        "{d}"
    );
    drop(props);
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    assert_eq!(replay(&p, &props, "try"), longer);
    assert_ne!(longer, first);

    // A fork after the record sees it.
    let later = p.settle();
    p.http(
        "pay",
        "fetch-ok",
        &format!("POST http://{addr}/v1/charges/10\n\namount=10"),
    );
    fork(&p, &props, "later", later);
    let d: Value = serde_json::from_slice(&replay(&p, &props, "later")).unwrap();
    assert_eq!(d["summary"]["synthetic_by"], json!({"contract": 1}), "{d}");
    let opt = &d["options"]["simulators"][0];
    assert!(opt.get("request").is_none(), "{opt}");
    assert!(opt["lsn"].as_u64().unwrap() > 0, "{opt}");
}

/// M12 (3): the same proposal replayed twice with the model simulator gives
/// a byte-identical diff: answers are cached per proposal, also across a
/// restart, while the fake model answers differently on every call.
#[test]
fn model_answers_are_cached_per_proposal() {
    let (addr, _hits) = server();
    let (model_addr, seen) = model_server();
    let dir = tempdir();
    let p = Proc::start(dir.path());
    set(&p, target(vec![], b"", false, true));
    let fork_lsn = three_charges(&p, &addr);
    let open = || {
        Arc::new(
            Proposals::open(p.node.clone(), dir.path().to_path_buf())
                .unwrap()
                .with_model(Some(model(&model_addr))),
        )
    };
    let props = open();
    fork(&p, &props, "try", fork_lsn);

    let first = replay(&p, &props, "try");
    let d: Value = serde_json::from_slice(&first).unwrap();
    assert_eq!(d["summary"]["synthetic_by"], json!({"model": 3}), "{d}");
    assert!(all_synthetic_by(&d, "model"), "{d}");
    let calls = seen.lock().unwrap().len();
    assert_eq!(
        calls, 3,
        "one call per distinct request, shared by both modes"
    );
    assert!(
        dir.path()
            .join("branches/try/simulator-cache.json")
            .exists()
    );

    assert_eq!(replay(&p, &props, "try"), first);
    drop(props);
    let props = open();
    assert_eq!(replay(&p, &props, "try"), first);
    assert_eq!(seen.lock().unwrap().len(), calls, "no second call");

    // Without `model = true` on the target the model is never asked.
    let d: Value = serde_json::from_slice(&replay_with(
        &p,
        &props,
        "try",
        overrides(vec![], None, true, false),
    ))
    .unwrap();
    assert_eq!(
        d["summary"]["synthetic_by"],
        json!({"fail-closed": 3}),
        "{d}"
    );
    assert_eq!(seen.lock().unwrap().len(), calls);

    // Review M3: a cache that no longer parses fails the replay instead of
    // silently asking the model again.
    std::fs::write(dir.path().join("branches/try/simulator-cache.json"), b"{").unwrap();
    p.settle();
    let e =
        p.rt.block_on(props.fork_replay("try", None, DiffOptions::default(), Some(2), p.owner()))
            .unwrap_err();
    assert!(e.message.contains("simulator-cache.json"), "{e:?}");
    assert_eq!(seen.lock().unwrap().len(), calls);
}

/// Review L1 (I12): a dry-run proposal never calls the model and writes
/// nothing under `branches/`. ADR 0015: a dry run is `RecordedOnly`, so a
/// model cache miss is a typed host prerequisite before any credentials or
/// network I/O, not a fail-closed synthetic answer.
#[test]
fn a_dry_run_proposal_calls_no_model_and_writes_nothing() {
    let (addr, _hits) = server();
    let (model_addr, seen) = model_server();
    let dir = tempdir();
    let p = Proc::start(dir.path());
    set(&p, target(vec![], b"", false, true));
    let fork_lsn = three_charges(&p, &addr);
    p.settle();
    let props = Arc::new(
        Proposals::open(p.node.clone(), dir.path().to_path_buf())
            .unwrap()
            .with_model(Some(model(&model_addr))),
    );
    let branches = |p: &std::path::Path| {
        std::fs::read_dir(p.join("branches"))
            .map(|d| d.count())
            .unwrap_or(0)
    };
    let before = branches(dir.path());
    let err =
        p.rt.block_on(props.propose(
            kronik_fork::proposal::ProposeRequest {
                wasm: vec![std::fs::read(guest("counter-fetch-extra")).unwrap()],
                names: vec![],
                window_ms: None,
                at: Some(fork_lsn),
                options: DiffOptions::default(),
                workers: Some(2),
                audit: audit(),
                dry_run: true,
            },
            p.owner(),
        ))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Unavailable, "{err}");
    assert_eq!(seen.lock().unwrap().len(), 0, "no model call");
    assert_eq!(branches(dir.path()), before, "nothing under branches/");
}

/// Every file under `dir` with its bytes.
fn files(dir: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let path = e.path();
            if path.is_dir() {
                todo.push(path);
            } else {
                out.push((path.clone(), std::fs::read(&path).unwrap()));
            }
        }
    }
    out.sort();
    out
}

/// Review L1 (I12): `promote --dry-run` replays and catches up without
/// calling the model, writes nothing under `branches/`, and leaves the
/// proposal as it was.
#[test]
fn a_dry_run_promote_calls_no_model_and_writes_nothing() {
    let (addr, _hits) = server();
    let (model_addr, seen) = model_server();
    let dir = tempdir();
    let p = Proc::start(dir.path());
    set(&p, target(vec![], b"", false, true));
    let fork_lsn = three_charges(&p, &addr);
    p.settle();
    let props = Arc::new(
        Proposals::open(p.node.clone(), dir.path().to_path_buf())
            .unwrap()
            .with_model(Some(model(&model_addr))),
    );
    let (meta, _) =
        p.rt.block_on(props.propose(
            kronik_fork::proposal::ProposeRequest {
                wasm: vec![std::fs::read(guest("counter-fetch-extra")).unwrap()],
                names: vec![],
                window_ms: None,
                at: Some(fork_lsn),
                options: DiffOptions::default(),
                workers: Some(2),
                audit: audit(),
                dry_run: false,
            },
            p.owner(),
        ))
        .unwrap();
    let calls = seen.lock().unwrap().len();
    assert_eq!(calls, 3);
    // New traffic for catch-up: two requests the model has not answered.
    for i in 3..5 {
        p.http(
            "pay",
            "fetch-ok",
            &format!("POST http://{addr}/v1/charges/{i}\n\namount=10"),
        );
    }
    p.settle();
    // Main's own state lives in branches/main; everything else is forks'.
    let forks = |d: &std::path::Path| -> Vec<_> {
        files(&d.join("branches"))
            .into_iter()
            .filter(|(p, _)| !p.starts_with(d.join("branches/main")))
            .collect()
    };
    let before = forks(dir.path());
    let _ =
        p.rt.block_on(props.promote(&meta.id, audit(), true, p.owner()));
    assert_eq!(seen.lock().unwrap().len(), calls, "no model call");
    let after = forks(dir.path());
    let changed: Vec<_> = after
        .iter()
        .filter(|f| !before.contains(f))
        .map(|f| f.0.clone())
        .chain(
            before
                .iter()
                .filter(|f| !after.contains(f))
                .map(|f| f.0.clone()),
        )
        .collect();
    assert!(changed.is_empty(), "written: {changed:?}");
    assert_eq!(p.rt.block_on(props.get(&meta.id)).unwrap(), meta);
}

/// M12 (4): the model simulator never sees personal data. A turn on behalf
/// of a subject is never simulated by the model, and recorded exchanges
/// with personal data are never examples. Under privacy mode no recorded
/// exchange is an example at all (review H9: a turn without a subject may
/// have copied personal data it read), unless the server opts in.
#[test]
fn model_never_sees_personal_data() {
    let (addr, _hits) = server();
    let dir = tempdir();
    let p = Proc::start(dir.path());
    p.grant("http:127.0.0.1");
    p.rt.block_on(
        p.node
            .set_privacy_mode(pb::PrivacyState::On, audit(), false, p.owner()),
    )
    .unwrap();
    set(&p, target(vec![], b"", false, true));
    let fork_lsn = p.settle();
    let secret = "pnr-19121212-1212";
    for i in 0..2 {
        p.http_as(
            "alice",
            "fetch-ok",
            &format!("POST http://{addr}/v1/charges/a{i}\n\ncustomer={secret}"),
            Some("user:alice"),
        );
    }
    // No subject, yet personal data (as if read from alice's state).
    p.http(
        "plain",
        "fetch-ok",
        &format!("POST http://{addr}/v1/charges/p0\n\ncopied=pnr-19850101-0101"),
    );
    p.settle();
    for (name, opt_in) in [("try", false), ("opted", true)] {
        let (model_addr, seen) = model_server();
        let mut config = model(&model_addr);
        config.examples_under_privacy = opt_in;
        let props = Arc::new(
            Proposals::open(p.node.clone(), dir.path().to_path_buf())
                .unwrap()
                .with_model(Some(config)),
        );
        fork(&p, &props, name, fork_lsn);
        let d: Value = serde_json::from_slice(&replay(&p, &props, name)).unwrap();

        // The subject's turns fail closed; only the plain one was simulated.
        assert_eq!(
            d["summary"]["synthetic_by"],
            json!({"fail-closed": 2, "model": 1}),
            "{d}"
        );
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        let all: Vec<u8> = seen.concat();
        let text = String::from_utf8_lossy(&all);
        assert!(!text.contains(secret), "{text}");
        assert!(!text.contains("alice"), "{text}");
        assert!(!text.contains("/charges/a"), "{text}");
        // The untagged exchange is an example only when the server opts in.
        assert_eq!(text.contains("pnr-19850101-0101"), opt_in, "{text}");
    }
}

/// Review H10 (I8): a request holding a secret's value is never sent to
/// the model, and a secret value in the model's answer is scrubbed before
/// it is cached.
#[test]
fn the_model_never_sees_or_caches_secret_values() {
    let (model_addr, seen) = model_server();
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let original = p.node.local_operator_authority().unwrap();
    p.rt.block_on(p.node.secret_set(
        "api-key",
        b"sk-live-0123456789".to_vec(),
        &audit(),
        false,
        original.clone(),
    ))
    .unwrap();
    // Use actual committed source rows and the certified inventory producer.
    p.rt.block_on(p.node.secret_set(
        "echo",
        b"answer 1".to_vec(),
        &audit(),
        false,
        original.clone(),
    ))
    .unwrap();
    p.rt.block_on(p.node.refresh_secret_inventory(original.clone()))
        .unwrap();
    let original_node = Arc::downgrade(&p.node);
    let access = ModelAccess {
        config: model(&model_addr),
        env: p.node.env().clone(),
        cache: Arc::new(ModelCache::memory()),
        privacy: false,
        secret_snapshot: Arc::new(move || {
            let node = original_node.upgrade().ok_or_else(|| {
                kronik_core::error::ApiError::new(
                    kronik_core::error::ErrorCode::SecretUnavailable,
                    "the original model node ended",
                )
            })?;
            // The certified catalogue briefly uncertifies across a
            // deployment-epoch publication (known product gap): a
            // scrubbed read answers SECRET_UNAVAILABLE while it
            // recertifies, and clients must retry that window, as the CLI
            // does. Await exactly that window here; any other error, or a
            // wait that runs out, still fails the test.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            loop {
                match node.native_secret_snapshot_with_publication() {
                    Ok((snapshot, publication)) => {
                        return Ok(ModelSecretSnapshot::Live {
                            snapshot,
                            publication,
                        });
                    }
                    Err(error)
                        if error.code == kronik_core::error::ErrorCode::SecretUnavailable =>
                    {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "the secret catalogue never recertified: {error}"
                        );
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    Err(error) => return Err(error),
                }
            }
        }),
        offline: false,
    };
    let req = |body: &str| pb::HttpEffectRequest {
        method: "POST".into(),
        url: "http://127.0.0.1/v1/charges".into(),
        headers: vec![],
        body: body.as_bytes().to_vec(),
        fingerprint_version: 0,
    };
    // Preserve the existing known-literal legacy refusal/no-wire contract.
    let unprepared = req("key=sk-live-0123456789");
    let target = kronik_effects::http::parse_url(&unprepared.url).unwrap();
    let fingerprint = kronik_effects::http::fingerprint(&unprepared).unwrap();
    let answer =
        p.rt.block_on(access.answer(
            "http:127.0.0.1",
            &fingerprint,
            &unprepared,
            &target,
            None,
            |_, _| Vec::new(),
            &original,
        ))
        .unwrap();
    assert_eq!(answer, None);
    assert_eq!(seen.lock().unwrap().len(), 0, "nothing was sent");
    let source = (access.secret_snapshot)().unwrap();
    let snapshot = match &source {
        ModelSecretSnapshot::Recorded(snapshot) | ModelSecretSnapshot::Live { snapshot, .. } => {
            snapshot
        }
    };
    let patterns = kronik_sched::effects::secret_patterns(&snapshot.values);
    let matcher = kronik_effects::http::CompiledScrubber::new(
        &patterns,
        kronik_sched::scrub::MAX_SECRET_PATTERN_BYTES,
    )
    .unwrap();
    let raw = req("amount=1");
    let (target, raw_host) = kronik_effects::http::parse_request_url(&raw.url).unwrap();
    let mut prepared = raw.clone();
    let target = kronik_sched::scrub::http_request(
        &mut prepared,
        &target,
        raw_host,
        &matcher,
        kronik_sched::scrub::MAX_JSON_OUTPUT_BYTES,
    )
    .unwrap();
    let fingerprint = kronik_effects::http::fingerprint_v2(&prepared, &target).unwrap();
    let answer =
        p.rt.block_on(access.answer(
            "http:127.0.0.1",
            &fingerprint,
            &prepared,
            &target,
            snapshot.references.as_deref(),
            |_, _| Vec::new(),
            &original,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(answer.body, "model [secret:echo]");
}

/// Review M5: a fork records an `actor.call` reply with the reply's subject,
/// as production does, so the model simulator's taint check sees it.
#[test]
fn fork_call_replies_keep_their_subject() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let fork_lsn = p.settle();
    p.http("caller", "call", "counter/callee subject");
    p.settle();
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    p.rt.block_on(props.create_fork(Some("f".into()), fork_lsn, false, audit(), false, p.owner()))
        .unwrap();
    let options = DiffOptions {
        mode: kronik_fork::diff::Mode::Continuous,
        ..DiffOptions::default()
    };
    replay_with(&p, &props, "f", options);
    let reply_subject = |t: &pb::TurnRecord| {
        t.effects
            .iter()
            .find(|e| e.kind == "actor.call")
            .map(|e| e.response.as_ref().and_then(|r| r.subject.clone()))
    };
    // Production's record says user:2 (the callee's subject).
    let mut prod = None;
    let head = p.node.applied_lsn();
    p.rt.block_on(p.node.reader().read(fork_lsn + 1, head, |c| {
        if let kronik_proto::Record::TurnRecord(t) = &c.record
            && let Some(s) = reply_subject(t)
        {
            prod = Some(s);
        }
        Ok(())
    }))
    .unwrap();
    let mut fork = None;
    for lsn in fork_lsn + 1..=head + 4 {
        if let Some(t) = p.rt.block_on(props.fork_turn("f", lsn)).unwrap()
            && let Some(s) = reply_subject(&t)
        {
            fork = Some(s);
        }
    }
    assert_eq!(prod, Some(Some("user:2".to_owned())), "production's record");
    assert_eq!(fork, prod);
}

/// M12 (5): policy can forbid synthetic answers per target, with the
/// per-simulator counts of each grounding row.
#[test]
fn policy_forbids_synthetic_answers_per_target() {
    let (addr, _hits) = server();
    let dir = tempdir();
    let p = Proc::start(dir.path());
    set(&p, target(vec![], CONTRACT.as_bytes(), false, false));
    let fork_lsn = three_charges(&p, &addr);
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    fork(&p, &props, "try", fork_lsn);
    let d: Value = serde_json::from_slice(&replay(&p, &props, "try")).unwrap();

    let rules = |host: &str, sim: &str| {
        RuleSet::parse_toml(&format!(
            r#"
[[rule]]
name = "no-synthetic"
when = "diff.grounding.exists(t, t.host.startsWith('{host}') && has(t.synthetic_by) && has(t.synthetic_by.{sim}))"
action = "deny"
"#
        ))
        .unwrap()
    };
    let e = rules("127.0.0.1", "contract").evaluate(&d);
    assert_eq!(e.outcome, Action::Deny, "{e:?}");
    assert_eq!(e.errors, []);
    // Another target, or another simulator: allowed.
    assert_eq!(
        rules("payments.internal", "contract").evaluate(&d).outcome,
        Action::Allow
    );
    assert_eq!(
        rules("127.0.0.1", "model").evaluate(&d).outcome,
        Action::Allow
    );
    // Any synthetic answer to the target, with the plain count.
    let any = RuleSet::parse_toml(
        r#"
[[rule]]
name = "exact-only"
when = "diff.grounding.exists(t, t.host.startsWith('127.0.0.1') && t.synthetic > 0)"
action = "deny"
"#,
    )
    .unwrap();
    assert_eq!(any.evaluate(&d).outcome, Action::Deny);
}

/// Review N12-2 (ADR 0015): a request override may turn the model off,
/// never on. Main's configuration at the fork point has no model for the
/// target; an override with `model: true` from a fork caller does not send
/// its recorded exchanges to the model endpoint.
#[test]
fn an_override_cannot_turn_the_model_on() {
    let (addr, _hits) = server();
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let fork_lsn = three_charges(&p, &addr);
    let (model_addr, seen) = model_server();
    let props = Arc::new(
        Proposals::open(p.node.clone(), dir.path().to_path_buf())
            .unwrap()
            .with_model(Some(model(&model_addr))),
    );
    fork(&p, &props, "try", fork_lsn);
    let d: Value = serde_json::from_slice(&replay_with(
        &p,
        &props,
        "try",
        overrides(vec![], None, false, true),
    ))
    .unwrap();
    assert_eq!(seen.lock().unwrap().len(), 0, "the model was called");
    assert!(all_synthetic_by(&d, "fail-closed"), "{d}");
}

/// The model simulator's taint paths: production turns `fetch-ok` each
/// `(key, head lines)` of `charges` with the plain build, which ignores the
/// `T` lines; the fork's fetch-extra build does them before an extra GET of
/// its own, which only a simulator can answer. `signing` is the in-forks
/// mode of the `secret:api-key` grant (ADR 0112). Returns each extra GET's
/// route and simulator in route order, the summary's `synthetic_by`, and
/// the number of requests the model got.
fn model_taint(
    signing: InForks,
    charges: &[(&str, &str)],
) -> (Vec<(String, String)>, Value, usize) {
    let (addr, _hits) = server();
    let dir = tempdir();
    let p = Proc::start(dir.path());
    p.deploy("notes");
    p.grant("http:127.0.0.1");
    p.grant("secret-reveal:api-key");
    p.rt.block_on(p.node.grant(
        "counter",
        "secret:api-key",
        None,
        None,
        signing,
        audit(),
        false,
        p.owner(),
    ))
    .unwrap();
    // The production secret path: the certified inventory a replay's gate
    // uses must hold the committed value.
    let original = p.node.local_operator_authority().unwrap();
    p.rt.block_on(p.node.secret_set(
        "api-key",
        b"sk-1".to_vec(),
        &audit(),
        false,
        original.clone(),
    ))
    .unwrap();
    p.rt.block_on(p.node.refresh_secret_inventory(original))
        .unwrap();
    set(&p, target(vec![], b"", false, true));
    // Tagged state for the state-read cases, and a notes row for SQL.
    for key in ["st", "b"] {
        p.http(key, "subject", "");
    }
    p.send("notes/n", "add", "a row");
    let fork_lsn = p.settle();
    for (key, taint) in charges {
        p.http(
            key,
            "fetch-ok",
            &format!("POST http://{addr}/v1/charges/{key}{taint}\n\namount=1"),
        );
    }
    p.settle();
    let (model_addr, seen) = model_server();
    let props = Arc::new(
        Proposals::open(p.node.clone(), dir.path().to_path_buf())
            .unwrap()
            .with_model(Some(model(&model_addr))),
    );
    fork(&p, &props, "try", fork_lsn);
    let d: Value = serde_json::from_slice(&replay(&p, &props, "try")).unwrap();
    let mut by_route: Vec<(String, String)> = d["effects"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["route"].as_str().is_some_and(|r| r.ends_with("/extra")))
        .map(|e| {
            (
                e["route"].as_str().unwrap_or_default().to_owned(),
                e["simulator"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    by_route.sort();
    let requests = seen.lock().unwrap().len();
    (by_route, d["summary"]["synthetic_by"].clone(), requests)
}

/// `(route, simulator)` pairs as [`model_taint`] returns them.
fn routes(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(key, sim)| (format!("/v1/charges/{key}/extra"), (*sim).to_owned()))
        .collect()
}

/// Review M5 and N12-3: the model declines for a turn that read tagged
/// state, used a secret, or called a turn that used SQL or read tagged
/// state (personal data from another turn); a turn that saw none of that
/// is simulated. The fetch-extra build does the `T` lines before its extra
/// GET. The `sec` turn's HMAC has no recording, and its grant is `compute`,
/// so the fork signs it on the host (an exact answer, not synthetic).
#[test]
fn the_model_declines_after_personal_data_from_any_path() {
    let (by_route, synthetic_by, seen) = model_taint(
        InForks::Compute,
        &[
            ("plain", ""),
            ("st", "\nT read s"),
            ("sec", "\nT hmac api-key"),
            ("sq", "\nT call notes/n count"),
            ("cr", "\nT call counter/b read"),
        ],
    );
    assert_eq!(
        by_route,
        routes(&[
            ("cr", "fail-closed"),
            ("plain", "model"),
            ("sec", "fail-closed"),
            ("sq", "fail-closed"),
            ("st", "fail-closed"),
        ])
    );
    assert_eq!(
        synthetic_by,
        json!({"fail-closed": 4, "model": 1}),
        "{by_route:?}"
    );
    assert_eq!(seen, 1);
}

/// ADR 0015: any use of a secret keeps the model away from the rest of the
/// turn, not only a signature the fork computed. With a `recorded` grant,
/// the default of a new grant (ADR 0112), the unmatched HMAC is denied and
/// graded `fail-closed` itself; a reveal answers its placeholder. Neither
/// turn's extra GET is sent to the model; the plain turn's is.
#[test]
fn the_model_declines_after_a_denied_signature_or_a_reveal() {
    let (by_route, synthetic_by, seen) = model_taint(
        InForks::Recorded,
        &[
            ("plain", ""),
            ("sec", "\nT hmac api-key"),
            ("rv", "\nT reveal api-key"),
        ],
    );
    assert_eq!(
        by_route,
        routes(&[
            ("plain", "model"),
            ("rv", "fail-closed"),
            ("sec", "fail-closed"),
        ])
    );
    // The two extra GETs and the denied HMAC fail closed.
    assert_eq!(
        synthetic_by,
        json!({"fail-closed": 3, "model": 1, "placeholder": 1}),
        "{by_route:?}"
    );
    assert_eq!(seen, 1);
}

/// Review N12-6: a fork's reveal where production revealed nothing is
/// labeled `placeholder`, so every synthetic answer has a simulator and
/// summary.synthetic is the sum of synthetic_by.
#[test]
fn an_unmatched_fork_reveal_is_labeled() {
    let (addr, _hits) = server();
    let dir = tempdir();
    let p = Proc::start(dir.path());
    p.grant("http:127.0.0.1");
    p.grant("secret-reveal:k");
    p.node
        .secrets()
        .unwrap()
        .set_at("k", 1, b"v-1", [7; 24], 0, "t", "r")
        .unwrap();
    let fork_lsn = p.settle();
    p.http(
        "a",
        "fetch-ok",
        &format!("POST http://{addr}/v1/charges/a\nT reveal k\n\namount=1"),
    );
    p.settle();
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    fork(&p, &props, "try", fork_lsn);
    let d: Value = serde_json::from_slice(&replay(&p, &props, "try")).unwrap();
    assert_eq!(
        d["summary"]["synthetic_by"],
        json!({"fail-closed": 1, "placeholder": 1}),
        "{d}"
    );
    assert_eq!(d["summary"]["synthetic"], 2, "{d}");
}

/// Review N12-7: privacy mode in force at the fork point counts, also when
/// the base snapshot's configuration predates the window: no recorded
/// exchange is an example for a replay up to a point before privacy was
/// turned off again.
#[test]
fn privacy_at_the_fork_point_keeps_examples_out() {
    let (addr, _hits) = server();
    let dir = tempdir();
    let p = Proc::start_with(
        dir.path(),
        kronik_sched::NodeConfig {
            concurrency: 8,
            storage: Some(kronik_sched::snapshots::StorageConfig::new(
                dir.path().to_path_buf(),
            )),
            ..kronik_sched::NodeConfig::default()
        },
    );
    p.grant("http:127.0.0.1");
    set(&p, target(vec![], b"", false, true));
    p.rt.block_on(
        p.node
            .set_privacy_mode(pb::PrivacyState::On, audit(), false, p.owner()),
    )
    .unwrap();
    p.settle();
    p.rt.block_on(p.node.snapshot("manual", p.owner())).unwrap();
    let fork_lsn = p.settle();
    for i in 0..2 {
        p.http(
            "pay",
            "fetch-ok",
            &format!("POST http://{addr}/v1/charges/{i}\n\namount=10"),
        );
    }
    let to = p.settle();
    p.rt.block_on(
        p.node
            .set_privacy_mode(pb::PrivacyState::Off, audit(), false, p.owner()),
    )
    .unwrap();
    p.settle();
    let (model_addr, seen) = model_server();
    let props = Arc::new(
        Proposals::open(p.node.clone(), dir.path().to_path_buf())
            .unwrap()
            .with_model(Some(model(&model_addr))),
    );
    fork(&p, &props, "try", fork_lsn);
    p.rt.block_on(props.fork_replay("try", Some(to), DiffOptions::default(), Some(2), p.owner()))
        .unwrap();
    let seen = seen.lock().unwrap();
    assert!(!seen.is_empty(), "the model was not asked");
    let text = String::from_utf8_lossy(&seen.concat()).into_owned();
    assert!(!text.contains("amount=10"), "{text}");
}

/// Review N12-3 (round 3): a production timer pending at the fork point
/// fires in the fork as if its scheduling turn saw personal data (what that
/// turn read is unknown), so the model declines for its effects.
#[test]
fn the_model_declines_for_timers_pending_at_the_fork_point() {
    let (addr, _hits) = server();
    let dir = tempdir();
    let p = Proc::start(dir.path());
    p.grant("http:127.0.0.1");
    set(&p, target(vec![], b"", false, true));
    // A timer whose message charges through `fetch-ok`.
    p.http(
        "t",
        "schedule",
        &format!("2000 fetch-ok\nPOST http://{addr}/v1/charges/t\n\namount=1"),
    );
    let fork_lsn = p.settle();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while p.settle() == fork_lsn {
        assert!(
            std::time::Instant::now() < deadline,
            "the timer did not fire"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let (model_addr, seen) = model_server();
    let props = Arc::new(
        Proposals::open(p.node.clone(), dir.path().to_path_buf())
            .unwrap()
            .with_model(Some(model(&model_addr))),
    );
    // The fetch-extra build also GETs <url>/extra: a simulator answers.
    fork(&p, &props, "try", fork_lsn);
    replay(&p, &props, "try");
    // The timer's fork turn (it has no root input in the window, so the
    // diff's effect items leave it out): its recorded charge matched, and
    // the extra GET was answered by fail-closed, not by the model.
    let turn = (1..=p.settle())
        .filter_map(|lsn| p.rt.block_on(props.fork_turn("try", lsn)).unwrap())
        .find(|t| {
            matches!(
                t.input.as_ref().and_then(|i| i.kind.as_ref()),
                Some(pb::input::Kind::Timer(_))
            )
        })
        .expect("the timer's fork turn");
    let sims: Vec<&str> = turn.effects.iter().map(|e| e.simulator.as_str()).collect();
    assert_eq!(sims, ["", "fail-closed"], "{:?}", turn.effects);
    assert!(seen.lock().unwrap().is_empty());
}

/// M22 (ADR 0070): standard fetch through `wasi:http` in forks. The same
/// code replays with every recorded request matched; a build that also GETs
/// `<url>/extra` gets those answers from the simulators, labeled, and nothing
/// goes out.
#[test]
fn standard_fetch_is_matched_in_replay_and_meets_the_simulators() {
    let (addr, hits) = server();
    let dir = tempdir();
    let p = Proc::start(dir.path());
    p.deploy("counter-wasi-http");
    p.grant("http:127.0.0.1");
    let fork_lsn = p.settle();
    for i in 0..3 {
        let r = p.http(
            "pay",
            "wfetch",
            &format!("POST http://{addr}/v1/charges/{i}\n\namount=10"),
        );
        assert!(http_body(&r).starts_with("200 "), "{r:?}");
    }
    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());

    // The same code: every request matches its recording.
    p.rt.block_on(props.create_fork(
        Some("same".into()),
        fork_lsn,
        false,
        audit(),
        false,
        p.owner(),
    ))
    .unwrap();
    let bytes = std::fs::read(guest("counter-wasi-http")).unwrap();
    p.rt.block_on(props.fork_deploy("same", &bytes, false, p.owner()))
        .unwrap();
    let d: Value = serde_json::from_slice(&replay(&p, &props, "same")).unwrap();
    assert_eq!(d["summary"]["changed"], false, "{d}");
    assert_eq!(d["summary"]["exact"], 3, "{d}");

    // A build that also GETs <url>/extra: a target stub answers those.
    p.rt.block_on(props.create_fork(
        Some("extra".into()),
        fork_lsn,
        false,
        audit(),
        false,
        p.owner(),
    ))
    .unwrap();
    let bytes = std::fs::read(guest("counter-wasi-http-extra")).unwrap();
    p.rt.block_on(props.fork_deploy("extra", &bytes, false, p.owner()))
        .unwrap();
    let stub = StubRule {
        method: Some("GET".into()),
        url_prefix: format!("http://{addr}/v1/charges/"),
        status: 200,
        headers: vec![],
        body: "stubbed".into(),
        error: None,
    };
    let d: Value = serde_json::from_slice(&replay_with(
        &p,
        &props,
        "extra",
        overrides(vec![stub], None, false, false),
    ))
    .unwrap();
    assert_eq!(d["summary"]["synthetic_by"], json!({"stub": 3}), "{d}");
    assert!(all_synthetic_by(&d, "stub"), "{d}");
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 3);
}
