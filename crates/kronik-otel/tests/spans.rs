//! The span mapping (docs/design/m28-otel.md §3): ids, parents and links,
//! times, attributes, what never leaves (ADR 0082), and a call through
//! three actors as one connected trace.

// Test helpers outside #[test] functions may unwrap.
#![allow(clippy::unwrap_used)]

use kronik_core::causal;
use kronik_core::ids::{ActorRef, hex};
use kronik_otel::otlp::common::v1::any_value::Value;
use kronik_otel::otlp::trace::v1::{Span, span, status};
use kronik_otel::spans::{
    ActorKeys, IdKey, OpenTurns, Resource, SpanRef, Turn, clamp, effect_span_id, key_label,
    new_trace_id, own_span_id, parse_traceparent, request, spans, started_trace_id, trace_id,
    traceparent_of, turn_ref, turn_span_id,
};
use kronik_proto::log::v1 as pb;
use prost::Message as _;

const ROOT: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const T0: u64 = 1_761_500_000_123;

fn actor(s: &str) -> ActorRef {
    let (kind, key) = s.split_once('/').unwrap();
    ActorRef {
        kind: kind.into(),
        key: key.into(),
    }
}

fn plain(b: &str) -> Option<pb::Sealable> {
    Some(pb::Sealable {
        subject: None,
        value: Some(pb::sealable::Value::Plain(b.as_bytes().to_vec())),
    })
}

fn message(name: &str) -> Option<pb::Message> {
    Some(pb::Message {
        name: name.into(),
        ..Default::default()
    })
}

fn http(route: &str, headers: &[(&str, &str)]) -> pb::Input {
    pb::Input {
        kind: Some(pb::input::Kind::Http(pb::HttpInput {
            method: "POST".into(),
            route: route.into(),
            headers: headers
                .iter()
                .map(|(n, v)| pb::Header {
                    name: (*n).into(),
                    value: plain(v),
                })
                .collect(),
            ..Default::default()
        })),
    }
}

fn msg_input(source: pb::MessageSource, name: &str) -> pb::Input {
    pb::Input {
        kind: Some(pb::input::Kind::Message(pb::MessageInput {
            source: source as i32,
            msg: message(name),
            ..Default::default()
        })),
    }
}

fn call_effect(ordinal: u32, to: &str, offset_us: u64, duration_us: u64) -> pb::EffectRecord {
    pb::EffectRecord {
        ordinal,
        kind: "actor.call".into(),
        target: format!("actor:{to}"),
        status: pb::EffectStatus::Ok as i32,
        grounding: pb::Grounding::Live as i32,
        offset_us,
        duration_us,
        ..Default::default()
    }
}

fn record(
    actor: &str,
    key: pb::CausalKey,
    input: pb::Input,
    effects: Vec<pb::EffectRecord>,
) -> pb::TurnRecord {
    pb::TurnRecord {
        actor: Some(self::actor(actor).to_pb()),
        code_hash: vec![0xab; 32],
        causal_key: Some(key),
        logical_time_ms: T0,
        input: Some(input),
        effects,
        outcome: Some(pb::Outcome {
            kind: pb::OutcomeKind::Committed as i32,
            ..Default::default()
        }),
        fuel_used: 42,
        config_epoch: 3,
        ..Default::default()
    }
}

/// The node's id key in these tests.
const IDS: IdKey = IdKey([7; 32]);

static NONE_OPEN: std::sync::LazyLock<OpenTurns> = std::sync::LazyLock::new(|| OpenTurns::new(IDS));

/// A turn mapped while no other turn is open.
fn turn(r: &pb::TurnRecord) -> Turn<'_> {
    Turn {
        record: r,
        lsn: 7,
        branch: "main",
        open: &NONE_OPEN,
        resend_of: None,
    }
}

/// The open turns after the `TurnBegin`s of `begun`, in log order.
fn open(begun: &[&pb::TurnRecord]) -> OpenTurns {
    let mut open = OpenTurns::new(IDS);
    for r in begun {
        assert!(open.begin(r.causal_key.as_ref().unwrap(), r.input.as_ref()));
    }
    open
}

/// What the exporter sends for `records` (in commit order) after the
/// `TurnBegin`s of `begun`: each turn closes once its record is mapped.
fn export(begun: &[&pb::TurnRecord], records: &[&pb::TurnRecord], keys: &ActorKeys) -> Vec<Span> {
    let mut open = open(begun);
    let mut out = Vec::new();
    for r in records {
        out.extend(spans(
            &Turn {
                open: &open,
                ..turn(r)
            },
            keys,
        ));
        open.commit(r);
    }
    assert!(open.is_empty(), "every begun turn committed");
    clamp(&mut out);
    out
}

fn root_key() -> pb::CausalKey {
    causal::root(ROOT.into())
}

fn attr<'a>(s: &'a Span, key: &str) -> Option<&'a Value> {
    s.attributes
        .iter()
        .find(|a| a.key == key)
        .and_then(|a| a.value.as_ref())
        .and_then(|v| v.value.as_ref())
}

fn str_attr<'a>(s: &'a Span, key: &str) -> Option<&'a str> {
    match attr(s, key) {
        Some(Value::StringValue(v)) => Some(v),
        _ => None,
    }
}

fn link(s: &Span) -> Option<(SpanRef, String)> {
    let l = s.links.first()?;
    let name = match l.attributes[0].value.as_ref()?.value.as_ref()? {
        Value::StringValue(v) => v.clone(),
        _ => return None,
    };
    Some((
        SpanRef {
            trace_id: l.trace_id.as_slice().try_into().ok()?,
            span_id: l.span_id.as_slice().try_into().ok()?,
        },
        name,
    ))
}

/// The link's `opentracing.ref_type`, which Jaeger reads when the link is
/// also the parent.
fn ref_type(s: &Span) -> Option<&str> {
    let a = s
        .links
        .first()?
        .attributes
        .iter()
        .find(|a| a.key == "opentracing.ref_type")?;
    match a.value.as_ref()?.value.as_ref()? {
        Value::StringValue(v) => Some(v),
        _ => None,
    }
}

fn hasher(kind: &str, key: &str) -> String {
    format!("kh:{kind}-{}", key.len())
}

// ---- ids ----

#[test]
fn trace_id_is_the_root_or_a_hash_of_it() {
    assert_eq!(hex(&trace_id(ROOT)), ROOT);
    // Not 32 lowercase hex characters: a hash, deterministic and distinct.
    for odd in ["root1", &ROOT.to_ascii_uppercase(), &ROOT[..30]] {
        assert_eq!(trace_id(odd), trace_id(odd));
        assert_ne!(hex(&trace_id(odd)), odd.to_ascii_lowercase());
    }
    assert_ne!(trace_id("root1"), trace_id("root2"));
}

#[test]
fn span_ids_are_deterministic_per_key_and_ordinal() {
    let a = root_key();
    let b = causal::child(&a, &actor("counter/a"), 0);
    assert_eq!(turn_span_id(&IDS, &b), turn_span_id(&IDS, &b.clone()));
    assert_ne!(turn_span_id(&IDS, &a), turn_span_id(&IDS, &b));
    assert_ne!(effect_span_id(&IDS, &a, 0), effect_span_id(&IDS, &a, 1));
    assert_ne!(effect_span_id(&IDS, &a, 0), turn_span_id(&IDS, &a));
    // The spec's preimages: "kronik span v1" ‖ encode(key), keyed (P1).
    let mut pre = b"kronik span v1".to_vec();
    pre.extend(causal::encode(&a));
    assert_eq!(
        turn_span_id(&IDS, &a),
        blake3::keyed_hash(&IDS.0, &pre).as_bytes()[..8]
    );
    assert_ne!(turn_span_id(&IdKey([8; 32]), &a), turn_span_id(&IDS, &a));
}

#[test]
fn traceparent_parsing_is_strict() {
    let ok = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    let r = parse_traceparent(ok).unwrap();
    assert_eq!(hex(&r.trace_id), ROOT);
    assert_eq!(hex(&r.span_id), "00f067aa0ba902b7");
    for bad in [
        "",
        "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
        "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
        "00-4bf92f3577b34da6a3ce929d0e0e473-00f067aa0ba902b7-01",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-1",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-x",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
        " 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902bg-01",
    ] {
        assert_eq!(parse_traceparent(bad), None, "{bad:?}");
    }
    let input = http("/x", &[("TraceParent", ok)]);
    assert_eq!(traceparent_of(&input), Some(r));
    let two = http("/x", &[("traceparent", ok), ("traceparent", ok)]);
    assert_eq!(traceparent_of(&two), None);
    let msg = msg_input(pb::MessageSource::Operator, "m");
    assert_eq!(traceparent_of(&msg), None);
    // A sealed header counts only once the caller unsealed the input.
    let mut sealed = input.clone();
    if let Some(pb::input::Kind::Http(h)) = sealed.kind.as_mut() {
        h.headers[0].value = Some(pb::Sealable {
            subject: Some("user:1".into()),
            value: Some(pb::sealable::Value::Sealed(pb::Sealed::default())),
        });
    }
    assert_eq!(traceparent_of(&sealed), None);
}

// ---- parents and links (§3.2) ----

fn turn_span(r: &pb::TurnRecord) -> Span {
    turn_span_of(turn(r))
}

fn turn_span_of(t: Turn) -> Span {
    spans(&t, &ActorKeys::Omit).remove(0)
}

#[test]
fn an_http_root_has_no_parent_and_links_an_incoming_traceparent() {
    let r = record("counter/a", root_key(), http("/counter/{key}", &[]), vec![]);
    let s = turn_span(&r);
    assert!(s.parent_span_id.is_empty() && s.links.is_empty());
    assert_eq!(s.kind, span::SpanKind::Server as i32);
    assert_eq!(hex(&s.trace_id), ROOT);
    let tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
    let r = record(
        "counter/a",
        root_key(),
        http("/counter/{key}", &[("traceparent", tp)]),
        vec![],
    );
    let s = turn_span(&r);
    // The trace stays the causal root's; the caller's span is a link.
    assert_eq!(hex(&s.trace_id), ROOT);
    assert!(s.parent_span_id.is_empty());
    assert_eq!(
        link(&s),
        Some((parse_traceparent(tp).unwrap(), "traceparent".into()))
    );
}

/// Each caused turn, with the turn its key names open and without: a
/// call, compensation or migrate joins that turn's trace while it is open,
/// with a parent for the first two; else it starts a trace of its own. A
/// send always starts one (review M1). The link always names the cause.
#[test]
fn every_caused_turn_has_a_typed_link_and_a_parent_while_its_cause_is_open() {
    use span::SpanKind;
    let a = actor("counter/a");
    let b = actor("counter/b");
    let root = root_key();
    let root_rec = record("counter/a", root.clone(), http("/r", &[]), vec![]);
    let call_turn = causal::child(&root, &a, 6);
    let call_rec = record(
        "counter/b",
        call_turn.clone(),
        msg_input(pb::MessageSource::Call, "get"),
        vec![],
    );
    let in_root = |span_id| SpanRef {
        trace_id: trace_id(ROOT),
        span_id,
    };
    let migrate = pb::Input {
        kind: Some(pb::input::Kind::Migrate(pb::MigrateInput::default())),
    };
    // (key, input, the open cause, parent while open, link while open, link
    // when gone, name, kind)
    let cases = [
        (
            causal::child(&root, &a, 3),
            msg_input(pb::MessageSource::Call, "get"),
            vec![&root_rec],
            Some(effect_span_id(&IDS, &root, 3)),
            in_root(effect_span_id(&IDS, &root, 3)),
            in_root(effect_span_id(&IDS, &root, 3)),
            "call",
            SpanKind::Server,
        ),
        (
            causal::child(&root, &a, 4),
            msg_input(pb::MessageSource::Actor, "increment"),
            vec![&root_rec],
            None,
            in_root(turn_span_id(&IDS, &root)),
            in_root(turn_span_id(&IDS, &root)),
            "message",
            SpanKind::Consumer,
        ),
        // The compensation's key is the callee's call turn key plus a step.
        (
            causal::compensation(&root, &a, 6, &b),
            msg_input(pb::MessageSource::Compensation, "undo"),
            vec![&root_rec, &call_rec],
            Some(turn_span_id(&IDS, &call_turn)),
            in_root(turn_span_id(&IDS, &call_turn)),
            SpanRef {
                trace_id: new_trace_id(&IDS, &call_turn),
                span_id: turn_span_id(&IDS, &call_turn),
            },
            "compensation",
            SpanKind::Internal,
        ),
        // The input turn runs after its migrate turn: a link only.
        (
            causal::migrate(&root, &b),
            migrate,
            vec![&root_rec],
            None,
            in_root(turn_span_id(&IDS, &root)),
            in_root(turn_span_id(&IDS, &root)),
            "migrate",
            SpanKind::Internal,
        ),
    ];
    for (key, input, cause, parent, open_link, gone_link, name, kind) in cases {
        let r = record("counter/b", key.clone(), input, vec![]);
        let joins = name != "message";
        let open = open(&cause);
        let s = turn_span_of(Turn {
            open: &open,
            ..turn(&r)
        });
        assert_eq!(
            s.parent_span_id,
            parent.map_or_else(Vec::new, |p| p.to_vec()),
            "{name}"
        );
        let joined = if joins {
            trace_id(ROOT)
        } else {
            started_trace_id(&IDS, &key, r.input.as_ref())
        };
        assert_eq!(s.trace_id, joined, "{name}");
        assert_eq!(s.kind, kind as i32, "{name}");
        assert_eq!(link(&s), Some((open_link, name.into())), "{name}");
        // A link that is also the parent says child_of, or Jaeger shows the
        // synchronous call as FOLLOWS_FROM (it merges the two references).
        let child_of = parent == Some(open_link.span_id);
        assert_eq!(ref_type(&s), child_of.then_some("child_of"), "{name}");
        let s = turn_span(&r);
        assert!(s.parent_span_id.is_empty(), "{name}");
        assert_eq!(
            s.trace_id,
            started_trace_id(&IDS, &key, r.input.as_ref()),
            "{name}"
        );
        assert_eq!(link(&s), Some((gone_link, name.into())), "{name}");
        assert_eq!(ref_type(&s), None, "{name}");
    }
}

fn timer(key: pb::CausalKey) -> pb::TurnRecord {
    let input = pb::Input {
        kind: Some(pb::input::Kind::Timer(pb::TimerInput {
            msg: message("tick"),
            ..Default::default()
        })),
    };
    record("counter/a", key, input, vec![])
}

/// A timer that reschedules itself gives one small trace per firing, each
/// linked to the turn that scheduled it, not one trace for its lifetime.
#[test]
fn each_timer_turn_starts_a_trace_linked_to_its_scheduler() {
    const N: usize = 50;
    let a = actor("counter/a");
    let mut keys = vec![root_key()];
    for _ in 0..N {
        let next = causal::child(keys.last().unwrap(), &a, 0);
        keys.push(next);
    }
    let mut traces = std::collections::BTreeMap::<Vec<u8>, usize>::new();
    for (i, key) in keys[1..].iter().enumerate() {
        // The timer turn calls counter/b: it begins, its callee commits in
        // its trace, then it commits.
        let r = timer(key.clone());
        let callee = record(
            "counter/b",
            causal::child(key, &a, 1),
            msg_input(pb::MessageSource::Call, "get"),
            vec![],
        );
        let all = export(&[&r], &[&callee, &r], &ActorKeys::Omit);
        let (c, s) = (&all[0], &all[1]);
        assert_eq!(s.trace_id, new_trace_id(&IDS, key));
        assert!(s.parent_span_id.is_empty());
        let scheduler = &keys[i];
        let scheduler_trace = if i == 0 {
            trace_id(ROOT)
        } else {
            new_trace_id(&IDS, scheduler)
        };
        assert_eq!(
            link(s),
            Some((
                SpanRef {
                    trace_id: scheduler_trace,
                    span_id: turn_span_id(&IDS, scheduler),
                },
                "timer".into()
            ))
        );
        assert_eq!(c.trace_id, s.trace_id);
        assert_eq!(c.parent_span_id, effect_span_id(&IDS, key, 1));
        *traces.entry(s.trace_id.clone()).or_default() += 1;
        *traces.entry(c.trace_id.clone()).or_default() += 1;
    }
    assert_eq!(traces.len(), N);
    assert!(traces.values().all(|&n| n == 2));
}

/// Two actors messaging each other 100 times give 100 traces of one span
/// each, every one linked to the turn that sent its message (review M1),
/// not one trace for their whole exchange.
#[test]
fn a_ping_pong_of_two_actors_gives_one_bounded_trace_per_message() {
    const N: usize = 100;
    let (a, b) = (actor("counter/a"), actor("counter/b"));
    let mut records = vec![record(
        "counter/a",
        root_key(),
        http("/counter/{key}/{op}", &[]),
        vec![],
    )];
    for i in 1..N {
        let (to, from) = if i % 2 == 1 {
            ("counter/b", &a)
        } else {
            ("counter/a", &b)
        };
        let key = causal::child(records[i - 1].causal_key.as_ref().unwrap(), from, 0);
        records.push(record(
            to,
            key,
            msg_input(pb::MessageSource::Actor, "ping"),
            vec![],
        ));
    }
    let all = export(&[], &records.iter().collect::<Vec<_>>(), &ActorKeys::Omit);
    let traces: std::collections::BTreeSet<&[u8]> =
        all.iter().map(|s| s.trace_id.as_slice()).collect();
    assert_eq!(traces.len(), N);
    assert!(all.iter().all(|s| s.parent_span_id.is_empty()));
    for pair in all.windows(2) {
        let (sender, receiver) = (&pair[0], &pair[1]);
        let (to, name) = link(receiver).unwrap();
        assert_eq!(name, "message");
        assert_eq!(to.trace_id.as_slice(), sender.trace_id);
        assert_eq!(to.span_id.as_slice(), sender.span_id);
    }
}

/// Maps `r` with `open` and commits it: its turn span.
fn map_commit(open: &mut OpenTurns, r: &pb::TurnRecord) -> Span {
    let s = turn_span_of(Turn { open, ..turn(r) });
    open.commit(r);
    s
}

fn outbound(to: &str, ordinal: u32) -> pb::OutboundMessage {
    pb::OutboundMessage {
        to: Some(actor(to).to_pb()),
        msg: message("note"),
        ordinal,
        ..Default::default()
    }
}

/// A calls B; B sends to C and schedules a timer; A fails, so B gets a
/// compensation. B ran in A's trace, so each of the three links names B's
/// span there, not in the trace B's key would start (review M7). The set
/// keeps B (through the cursor file) until all three came.
#[test]
fn a_callees_messages_timers_and_compensation_link_into_its_callers_trace() {
    let (a, b) = (actor("counter/a"), actor("counter/b"));
    let root = root_key();
    let mut caller = record(
        "counter/a",
        root.clone(),
        http("/r", &[]),
        vec![call_effect(3, "counter/b", 10, 10)],
    );
    caller.compensations = vec![outbound("counter/b", 3)];
    let b_key = causal::child(&root, &a, 3);
    let mut callee = record(
        "counter/b",
        b_key.clone(),
        msg_input(pb::MessageSource::Call, "go"),
        vec![],
    );
    callee.messages = vec![outbound("counter/c", 1)];
    callee.timers = vec![pb::TimerOp {
        kind: pb::TimerOpKind::Schedule as i32,
        timer_id: 1,
        msg: message("tick"),
        ordinal: 2,
        ..Default::default()
    }];
    let sent = record(
        "counter/c",
        causal::child(&b_key, &b, 1),
        msg_input(pb::MessageSource::Actor, "note"),
        vec![],
    );
    let fired = timer(causal::child(&b_key, &b, 2));
    let undo = record(
        "counter/b",
        causal::compensation(&root, &a, 3, &b),
        msg_input(pb::MessageSource::Compensation, "undo"),
        vec![],
    );
    let mut open = open(&[&caller]);
    let callee_span = map_commit(&mut open, &callee);
    assert_eq!(callee_span.trace_id, trace_id(ROOT));
    map_commit(&mut open, &caller);
    let mut open = OpenTurns::from_json(&open.to_json(), IDS);
    assert_eq!((open.len(), open.kept()), (0, 1));
    let b_span = SpanRef {
        trace_id: trace_id(ROOT),
        span_id: turn_span_id(&IDS, &b_key),
    };
    for (r, name) in [
        (&sent, "message"),
        (&fired, "timer"),
        (&undo, "compensation"),
    ] {
        let s = map_commit(&mut open, r);
        assert_eq!(link(&s), Some((b_span, name.into())), "{name}");
        assert_eq!(
            s.trace_id,
            new_trace_id(&IDS, r.causal_key.as_ref().unwrap())
        );
        assert!(s.parent_span_id.is_empty(), "{name}");
    }
    assert_eq!(open.kept(), 0, "B leaves once nothing names it");
}

/// A call that timed out lets its caller commit before the callee runs:
/// the callee still joins the caller's trace, under its call effect.
#[test]
fn a_callee_whose_call_timed_out_joins_its_callers_trace() {
    let a = actor("counter/a");
    let root = root_key();
    let mut timed_out = call_effect(3, "counter/b", 10, 10);
    timed_out.status = pb::EffectStatus::Timeout as i32;
    let caller = record("counter/a", root.clone(), http("/r", &[]), vec![timed_out]);
    let late = record(
        "counter/b",
        causal::child(&root, &a, 3),
        msg_input(pb::MessageSource::Call, "go"),
        vec![],
    );
    let mut open = open(&[&caller]);
    map_commit(&mut open, &caller);
    let s = map_commit(&mut open, &late);
    assert_eq!(s.trace_id, trace_id(ROOT));
    assert_eq!(s.parent_span_id, effect_span_id(&IDS, &root, 3));
    assert_eq!((open.len(), open.kept()), (0, 0));
}

/// A callee that migrates twice (a code switch during its first
/// migration): two migrate turns under one key get distinct ids, stable
/// on re-export, and each links to the input's span in the trace that
/// input joins, its open caller's.
#[test]
fn two_migrations_of_one_input_get_distinct_ids_and_link_into_the_inputs_trace() {
    let (a, b) = (actor("counter/a"), actor("counter/b"));
    let root = root_key();
    let caller = record("counter/a", root.clone(), http("/r", &[]), vec![]);
    let input = causal::child(&root, &a, 3);
    let migrate = |from, to| {
        let m = pb::Input {
            kind: Some(pb::input::Kind::Migrate(pb::MigrateInput {
                from_schema_version: from,
                to_schema_version: to,
            })),
        };
        record("counter/b", causal::migrate(&input, &b), m, vec![])
    };
    let (first, second) = (migrate(1, 2), migrate(2, 3));
    let open = open(&[&caller]);
    let s1 = turn_span_of(Turn {
        open: &open,
        ..turn(&first)
    });
    let s2 = turn_span_of(Turn {
        open: &open,
        ..turn(&second)
    });
    assert_ne!(s1.span_id, s2.span_id);
    assert_ne!(s1.trace_id, s2.trace_id);
    let key = first.causal_key.as_ref().unwrap();
    assert_eq!(s1.span_id, own_span_id(&IDS, key, first.input.as_ref()));
    assert_eq!(
        s1,
        turn_span_of(Turn {
            open: &open,
            ..turn(&first)
        })
    );
    let input_span = SpanRef {
        trace_id: trace_id(ROOT),
        span_id: turn_span_id(&IDS, &input),
    };
    for s in [&s1, &s2] {
        assert_eq!(link(s), Some((input_span, "migrate".into())));
    }
}

/// Review P1: the causal key holds every step's actor key in plain, so a
/// backend that sees an unkeyed id could test guessed keys against it. A
/// call chain, a self-timer and a migrate under `counter/carol@example.com`
/// export no trace, span, parent or link id that the unkeyed derivation
/// from `causal::encode` gives; only the root's trace id is plain.
#[test]
fn no_exported_id_is_the_unkeyed_derivation_of_its_causal_key() {
    let carol = actor("counter/carol@example.com");
    let root = root_key();
    let root_rec = record(
        "counter/carol@example.com",
        root.clone(),
        http("/r", &[]),
        vec![call_effect(0, "billing/x", 10, 100)],
    );
    let callee_key = causal::child(&root, &carol, 0);
    let callee = record(
        "billing/x",
        callee_key.clone(),
        msg_input(pb::MessageSource::Call, "charge"),
        vec![call_effect(0, "counter/carol@example.com", 10, 50)],
    );
    let chain_key = causal::child(&callee_key, &actor("billing/x"), 0);
    let chain = record(
        "counter/carol@example.com",
        chain_key.clone(),
        msg_input(pb::MessageSource::Call, "get"),
        vec![],
    );
    let timer_key = causal::child(&root, &carol, 1);
    let mut timer_rec = timer(timer_key.clone());
    timer_rec.actor = Some(carol.to_pb());
    timer_rec.effects = vec![call_effect(0, "billing/x", 10, 100)];
    let timer_callee_key = causal::child(&timer_key, &carol, 0);
    let timer_callee = record(
        "billing/x",
        timer_callee_key.clone(),
        msg_input(pb::MessageSource::Call, "charge"),
        vec![],
    );
    let migrate_key = causal::migrate(&timer_key, &carol);
    let migrate_input = pb::Input {
        kind: Some(pb::input::Kind::Migrate(pb::MigrateInput {
            from_schema_version: 1,
            to_schema_version: 2,
        })),
    };
    let migrate = record(
        "counter/carol@example.com",
        migrate_key.clone(),
        migrate_input,
        vec![],
    );
    let mut all = export(
        &[&root_rec, &callee],
        &[&chain, &callee, &root_rec],
        &ActorKeys::Omit,
    );
    all.extend(export(
        &[&timer_rec],
        &[&migrate, &timer_callee, &timer_rec],
        &ActorKeys::Omit,
    ));
    // Every unkeyed id these keys give, migrate's schema version included.
    let b3 = |parts: &[&[u8]]| blake3::hash(&parts.concat()).as_bytes().to_vec();
    let mut unkeyed = std::collections::BTreeSet::new();
    for key in [
        &root,
        &callee_key,
        &chain_key,
        &timer_key,
        &timer_callee_key,
        &migrate_key,
    ] {
        let enc = causal::encode(key);
        let migrated = [&enc[..], &2u32.to_le_bytes()].concat();
        for base in [&enc, &migrated] {
            unkeyed.insert(b3(&[b"kronik trace v1", base])[..16].to_vec());
            unkeyed.insert(b3(&[b"kronik span v1", base])[..8].to_vec());
            for o in 0..4u32 {
                unkeyed
                    .insert(b3(&[b"kronik effect span v1", base, &o.to_le_bytes()])[..8].to_vec());
            }
        }
    }
    assert!(all.len() >= 9, "{} spans", all.len());
    let mut seen = 0;
    for s in &all {
        let mut ids = vec![&s.span_id, &s.parent_span_id];
        if s.trace_id != trace_id(ROOT) {
            ids.push(&s.trace_id);
        }
        for l in &s.links {
            ids.push(&l.span_id);
            if l.trace_id != trace_id(ROOT) {
                ids.push(&l.trace_id);
            }
        }
        for id in ids.into_iter().filter(|id| !id.is_empty()) {
            seen += 1;
            assert!(
                !unkeyed.contains(id),
                "{} is unkeyed in {}",
                hex(id),
                s.name
            );
        }
    }
    assert!(seen >= 20, "{seen} ids checked");
}

/// The set survives the cursor file: a callee whose caller began before a
/// restart still joins the caller's trace after it.
#[test]
fn open_turns_round_trip_through_the_cursor_state() {
    let a = actor("counter/a");
    let t = timer(causal::child(&root_key(), &a, 0));
    let open = open(&[&t]);
    let back = OpenTurns::from_json(&open.to_json(), IDS);
    assert_eq!(back.len(), 1);
    let key = causal::child(t.causal_key.as_ref().unwrap(), &a, 2);
    let call = Some(msg_input(pb::MessageSource::Call, "get"));
    assert_eq!(
        back.trace(&key, call.as_ref()),
        new_trace_id(&IDS, t.causal_key.as_ref().unwrap())
    );
    assert_eq!(
        OpenTurns::from_json(&serde_json::json!("junk"), IDS).len(),
        0
    );
}

#[test]
fn operator_sends_are_roots_and_resends_link_to_the_dead_letter() {
    let r = record(
        "counter/a",
        root_key(),
        msg_input(pb::MessageSource::Operator, "increment"),
        vec![],
    );
    let s = turn_span(&r);
    assert!(s.parent_span_id.is_empty() && s.links.is_empty());
    assert_eq!(s.kind, span::SpanKind::Internal as i32);

    let failed_key = causal::child(&causal::root("aa".repeat(16)), &actor("counter/z"), 1);
    let failed = record(
        "counter/a",
        failed_key.clone(),
        msg_input(pb::MessageSource::Actor, "increment"),
        vec![],
    );
    let dead = turn_ref(&failed, &OpenTurns::new(IDS));
    let mut input = msg_input(pb::MessageSource::DeadLetterResend, "increment");
    if let Some(pb::input::Kind::Message(m)) = input.kind.as_mut() {
        m.resend_of = "main:3".into();
    }
    let r = record("counter/a", root_key(), input, vec![]);
    let s = turn_span_of(Turn {
        resend_of: Some(dead),
        ..turn(&r)
    });
    assert!(s.parent_span_id.is_empty());
    assert_eq!(s.trace_id, trace_id(ROOT));
    assert_eq!(link(&s), Some((dead, "resend".into())));
    // The dead-lettered send started its own trace.
    assert_eq!(dead.trace_id, new_trace_id(&IDS, &failed_key));
}

// ---- times (§3.3) ----

#[test]
fn times_come_from_the_record() {
    let r = record(
        "counter/a",
        root_key(),
        http("/r", &[]),
        vec![
            call_effect(0, "counter/b", 250, 1_000),
            call_effect(1, "counter/c", 2_000, 500),
        ],
    );
    let all = spans(&turn(&r), &ActorKeys::Omit);
    let start = T0 * 1_000_000;
    assert_eq!(all[0].start_time_unix_nano, start);
    assert_eq!(all[1].start_time_unix_nano, start + 250_000);
    assert_eq!(all[1].end_time_unix_nano, start + 1_250_000);
    assert_eq!(all[2].start_time_unix_nano, start + 2_000_000);
    // A record without the turn's duration (from before M11) ends with its
    // last effect.
    assert_eq!(all[0].end_time_unix_nano, start + 2_500_000);
    for e in &all[1..] {
        assert_eq!(e.parent_span_id, all[0].span_id);
        assert_eq!(e.kind, span::SpanKind::Client as i32);
    }
    // With TurnRecord.duration_us (M11): the turn lasts that long.
    let mut timed = r.clone();
    timed.duration_us = 4_000;
    assert_eq!(turn_span(&timed).end_time_unix_nano, start + 4_000_000);
    // Without effects: 1 µs.
    let r = record("counter/a", root_key(), http("/r", &[]), vec![]);
    let s = turn_span(&r);
    assert_eq!(s.end_time_unix_nano, start + 1_000);
}

/// A callee's turn (millisecond logical time, possibly ahead) is clamped
/// into its caller's call effect when both are in one batch, and its own
/// effects follow it.
#[test]
fn clamp_puts_children_inside_their_parents() {
    let a = actor("counter/a");
    let root = root_key();
    let caller = record(
        "counter/a",
        root.clone(),
        http("/r", &[]),
        vec![call_effect(0, "counter/b", 100, 400)],
    );
    let mut callee = record(
        "counter/b",
        causal::child(&root, &a, 0),
        msg_input(pb::MessageSource::Call, "get"),
        vec![call_effect(0, "counter/x", 0, 5_000)],
    );
    callee.logical_time_ms = T0 + 2;
    let caller_open = open(&[&caller]);
    let mut all = spans(
        &Turn {
            open: &caller_open,
            ..turn(&callee)
        },
        &ActorKeys::Omit,
    );
    // Within its own record, the effect lies inside the turn.
    assert!(all[1].start_time_unix_nano >= all[0].start_time_unix_nano);
    assert!(all[1].end_time_unix_nano <= all[0].end_time_unix_nano);
    all.extend(spans(&turn(&caller), &ActorKeys::Omit));
    clamp(&mut all);
    let by_id = |id: &[u8]| all.iter().find(|s| s.span_id == id).unwrap();
    for s in &all {
        if !s.parent_span_id.is_empty() {
            let p = by_id(&s.parent_span_id);
            assert!(
                p.start_time_unix_nano <= s.start_time_unix_nano
                    && s.end_time_unix_nano <= p.end_time_unix_nano,
                "{} outside {}",
                s.name,
                p.name
            );
        }
    }
    let call = by_id(&effect_span_id(&IDS, &root, 0));
    assert_eq!(all[0].start_time_unix_nano, call.end_time_unix_nano);
}

/// An `EffectRecord` written before `offset_us` (field 80) existed: it
/// decodes, and its span starts at the turn's start (I16).
#[test]
fn effect_records_from_before_offset_us_start_at_the_turn() {
    let fixture = include_str!("../../kronik-proto/tests/fixtures/effect-record-v1.hex").trim();
    let bytes: Vec<u8> = (0..fixture.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&fixture[i..i + 2], 16).unwrap())
        .collect();
    let e = pb::EffectRecord::decode(bytes.as_slice()).unwrap();
    assert_eq!(
        (e.kind.as_str(), e.duration_us, e.offset_us),
        ("http.fetch", 1_500, 0)
    );
    let r = record("counter/a", root_key(), http("/r", &[]), vec![e]);
    let all = spans(&turn(&r), &ActorKeys::Omit);
    assert_eq!(all[1].start_time_unix_nano, T0 * 1_000_000);
    assert_eq!(all[1].end_time_unix_nano, T0 * 1_000_000 + 1_500_000);
    assert_eq!(str_attr(&all[1], "server.address"), Some("api.example.com"));
}

// ---- attributes (§3.4, §3.5) ----

#[test]
fn actor_keys_are_hashed_plain_or_left_out() {
    let r = record(
        "counter/carol@example.com",
        root_key(),
        http("/counter/{key}", &[]),
        vec![call_effect(0, "notes/carol@example.com", 0, 1)],
    );
    let t = turn(&r);
    let hashed = spans(&t, &ActorKeys::Hashed(&hasher));
    assert_eq!(key_label(&[0xab; 32]), "kh:abababababab");
    assert_eq!(
        str_attr(&hashed[0], "kronik.actor.key"),
        Some("kh:counter-17")
    );
    assert_eq!(
        str_attr(&hashed[1], "kronik.target.actor.key"),
        Some("kh:notes-17")
    );
    assert_eq!(
        str_attr(&hashed[1], "kronik.target.actor.kind"),
        Some("notes")
    );
    let plain = spans(&t, &ActorKeys::Plain);
    assert_eq!(
        str_attr(&plain[0], "kronik.actor.key"),
        Some("carol@example.com")
    );
    assert_eq!(
        str_attr(&plain[1], "kronik.target.actor.key"),
        Some("carol@example.com")
    );
    let omit = spans(&t, &ActorKeys::Omit);
    assert_eq!(attr(&omit[0], "kronik.actor.key"), None);
    assert_eq!(attr(&omit[1], "kronik.target.actor.key"), None);
    assert_eq!(str_attr(&omit[0], "kronik.actor.kind"), Some("counter"));
}

#[test]
fn turn_and_effect_attributes() {
    let mut r = record(
        "counter/a",
        root_key(),
        http("/counter/{key}/{op}", &[]),
        vec![
            pb::EffectRecord {
                ordinal: 0,
                kind: "http.fetch".into(),
                target: "http:api.example.com".into(),
                status: pb::EffectStatus::Timeout as i32,
                grounding: pb::Grounding::Live as i32,
                delivery: "unsafe".into(),
                ..Default::default()
            },
            pb::EffectRecord {
                ordinal: 1,
                kind: "secret.reveal".into(),
                target: "secret-reveal:stripe".into(),
                status: pb::EffectStatus::Denied as i32,
                grounding: pb::Grounding::Live as i32,
                ..Default::default()
            },
        ],
    );
    r.outcome = Some(pb::Outcome {
        kind: pb::OutcomeKind::Failed as i32,
        error_code: "TURN_FAILED".into(),
        output: Some(pb::outcome::Output::Http(pb::HttpResponse {
            status: 503,
            ..Default::default()
        })),
        ..Default::default()
    });
    let all = spans(&turn(&r), &ActorKeys::Omit);
    let s = &all[0];
    assert_eq!(s.name, "counter POST /counter/{key}/{op}");
    assert_eq!(str_attr(s, "kronik.turn_id"), Some("main:7"));
    assert_eq!(str_attr(s, "kronik.input"), Some("http"));
    assert_eq!(str_attr(s, "http.route"), Some("/counter/{key}/{op}"));
    assert_eq!(
        attr(s, "http.response.status_code"),
        Some(&Value::IntValue(503))
    );
    assert_eq!(str_attr(s, "kronik.outcome"), Some("failed"));
    assert_eq!(str_attr(s, "kronik.error_code"), Some("TURN_FAILED"));
    assert_eq!(
        str_attr(s, "kronik.code_hash"),
        Some(&*format!("b3:{}", "ab".repeat(32)))
    );
    assert_eq!(attr(s, "kronik.config_epoch"), Some(&Value::IntValue(3)));
    assert_eq!(attr(s, "kronik.fuel_used"), Some(&Value::IntValue(42)));
    let st = s.status.as_ref().unwrap();
    assert_eq!(
        (st.code, st.message.as_str()),
        (status::StatusCode::Error as i32, "TURN_FAILED")
    );

    let fetch = &all[1];
    assert_eq!(fetch.name, "http.fetch");
    assert_eq!(str_attr(fetch, "kronik.effect.status"), Some("timeout"));
    assert_eq!(str_attr(fetch, "kronik.effect.grounding"), Some("live"));
    assert_eq!(str_attr(fetch, "kronik.effect.delivery"), Some("unsafe"));
    assert_eq!(str_attr(fetch, "kronik.effect.target"), Some("http"));
    assert_eq!(str_attr(fetch, "server.address"), Some("api.example.com"));
    assert_eq!(
        fetch.status.as_ref().unwrap().code,
        status::StatusCode::Error as i32
    );
    let reveal = &all[2];
    assert_eq!(str_attr(reveal, "kronik.secret.name"), Some("stripe"));
    assert_eq!(str_attr(reveal, "kronik.effect.status"), Some("denied"));
    assert!(reveal.status.is_none());

    let timer = record(
        "counter/a",
        causal::child(&root_key(), &actor("counter/a"), 1),
        pb::Input {
            kind: Some(pb::input::Kind::Timer(pb::TimerInput {
                msg: message("tick"),
                ..Default::default()
            })),
        },
        vec![],
    );
    let s = turn_span(&timer);
    assert_eq!(s.name, "counter timer tick");
    assert!(s.status.is_none());
    let m = record(
        "counter/a",
        causal::child(&root_key(), &actor("counter/z"), 1),
        msg_input(pb::MessageSource::Actor, "increment"),
        vec![],
    );
    let s = turn_span(&m);
    assert_eq!(s.name, "counter message increment");
    assert_eq!(str_attr(&s, "kronik.message.source"), Some("actor"));
}

// ---- what never leaves (ADR 0082) ----

#[test]
fn no_needle_leaves_in_an_export_request() {
    const N: &str = "NEEDLE";
    let sealed = |v: &str| {
        Some(pb::Sealable {
            subject: Some(format!("user-{N}-subject")),
            value: Some(pb::sealable::Value::Plain(v.as_bytes().to_vec())),
        })
    };
    let body = |v: &str| {
        Some(pb::Body {
            value: Some(pb::body::Value::Inline(sealed(v).unwrap())),
        })
    };
    let needle_msg = || {
        Some(pb::Message {
            name: "increment".into(),
            content_type: "text/plain".into(),
            body: sealed(&format!("body-{N}")),
            blobs: vec![],
        })
    };
    let effect = pb::EffectRecord {
        ordinal: 0,
        kind: "http.fetch".into(),
        target: "http:api.example.com".into(),
        request: sealed(&format!("request-{N}")),
        response: sealed(&format!("response-{N}")),
        error: format!("error-{N}"),
        status: pb::EffectStatus::Network as i32,
        grounding: pb::Grounding::Live as i32,
        idempotency_key: format!("idem-{N}"),
        fingerprint: N.as_bytes().to_vec(),
        ..Default::default()
    };
    let mut http_root = record(
        "counter/a",
        root_key(),
        pb::Input {
            kind: Some(pb::input::Kind::Http(pb::HttpInput {
                method: "POST".into(),
                path: format!("/counter/{N}"),
                query: format!("q={N}"),
                params: vec![pb::Param {
                    name: "key".into(),
                    value: N.into(),
                    sealed_value: sealed(N),
                }],
                headers: vec![
                    pb::Header {
                        name: "authorization".into(),
                        value: sealed(&format!("Bearer {N}")),
                    },
                    pb::Header {
                        name: "traceparent".into(),
                        value: sealed("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
                    },
                ],
                body: body(&format!("body-{N}")),
                route: "/counter/{key}".into(),
                idempotency_key: format!("idem-{N}"),
                request_hash: N.as_bytes().to_vec(),
                sealed_path: sealed(&format!("/counter/{N}")),
                sealed_query: sealed(&format!("q={N}")),
            })),
        },
        vec![effect],
    );
    http_root.outcome = Some(pb::Outcome {
        kind: pb::OutcomeKind::Failed as i32,
        error_code: "TURN_FAILED".into(),
        message: format!("guest text {N}"),
        output: Some(pb::outcome::Output::Http(pb::HttpResponse {
            status: 500,
            headers: vec![pb::Header {
                name: "x".into(),
                value: sealed(N),
            }],
            body: body(N),
        })),
    });
    http_root.writes = vec![pb::StateWrite {
        op: pb::StateOp::Set as i32,
        key: "n".into(),
        value: sealed(N),
    }];
    http_root.messages = vec![pb::OutboundMessage {
        to: Some(actor("counter/b").to_pb()),
        msg: needle_msg(),
        ordinal: 1,
        message_id: String::new(),
    }];
    http_root.sql_changes = vec![pb::SqlChangeset {
        changeset: sealed(N),
    }];
    let mut msg_turn = record(
        "counter/b",
        causal::child(&root_key(), &actor("counter/a"), 1),
        pb::Input {
            kind: Some(pb::input::Kind::Message(pb::MessageInput {
                source: pb::MessageSource::Actor as i32,
                sender: Some(actor("counter/a").to_pb()),
                msg: needle_msg(),
                ..Default::default()
            })),
        },
        vec![],
    );
    msg_turn.outcome = Some(pb::Outcome {
        kind: pb::OutcomeKind::Committed as i32,
        output: Some(pb::outcome::Output::Reply(needle_msg().unwrap())),
        ..Default::default()
    });
    let mut all = spans(&turn(&http_root), &ActorKeys::Hashed(&hasher));
    assert_eq!(link(&all[0]).unwrap().1, "traceparent");
    all.extend(spans(&turn(&msg_turn), &ActorKeys::Hashed(&hasher)));
    let bytes = request(&resource(), all).encode_to_vec();
    assert!(
        !bytes.windows(N.len()).any(|w| w == N.as_bytes()),
        "a needle left the node"
    );
}

// ---- the acceptance: three actors, one trace ----

/// Also when the outside caller sent a `traceparent`: it is a link on the
/// root span, and the trace stays the causal root's (review H1).
#[test]
fn a_call_through_three_actors_is_one_connected_trace() {
    let tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
    for headers in [&[][..], &[("traceparent", tp)][..]] {
        three_actors(headers);
    }
}

fn three_actors(headers: &[(&str, &str)]) {
    let a = actor("counter/a");
    let b = actor("counter/b");
    let root = root_key();
    let b_key = causal::child(&root, &a, 0);
    let x_key = causal::child(&b_key, &b, 1);
    // In commit order: callees first.
    let records = [
        record(
            "counter/x",
            x_key,
            msg_input(pb::MessageSource::Call, "increment"),
            vec![],
        ),
        record(
            "counter/b",
            b_key,
            msg_input(pb::MessageSource::Call, "call"),
            vec![call_effect(1, "counter/x", 10, 100)],
        ),
        record(
            "counter/a",
            root,
            http("/counter/{key}/{op}", headers),
            vec![call_effect(0, "counter/b", 10, 1_000)],
        ),
    ];
    // In log order: a and b begin (each before its call), x commits
    // without one (no live effect), then b and a.
    let all = export(
        &[&records[2], &records[1]],
        &records.iter().collect::<Vec<_>>(),
        &ActorKeys::Plain,
    );
    assert_eq!(all.len(), 5);
    assert!(all.iter().all(|s| s.trace_id == trace_id(ROOT)));
    let ids: Vec<&[u8]> = all.iter().map(|s| s.span_id.as_slice()).collect();
    let roots: Vec<&Span> = all.iter().filter(|s| s.parent_span_id.is_empty()).collect();
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0].name, "counter POST /counter/{key}/{op}");
    assert_eq!(
        link(roots[0]),
        headers
            .first()
            .map(|(_, v)| (parse_traceparent(v).unwrap(), "traceparent".into()))
    );
    for s in &all {
        if !s.parent_span_id.is_empty() {
            assert!(
                ids.contains(&s.parent_span_id.as_slice()),
                "{} has no parent",
                s.name
            );
        }
    }
    // Each callee's parent and `call` link is its caller's call effect span.
    for callee in all
        .iter()
        .filter(|s| str_attr(s, "kronik.message.source") == Some("call"))
    {
        let parent = all
            .iter()
            .find(|p| p.span_id == callee.parent_span_id)
            .unwrap();
        assert_eq!(parent.name, "actor.call");
        let (to, name) = link(callee).unwrap();
        assert_eq!(
            (to.span_id.as_slice(), name.as_str()),
            (parent.span_id.as_slice(), "call")
        );
    }
}

// ---- golden ----

fn resource() -> Resource<'static> {
    Resource {
        service_name: "kronik",
        service_version: "0.1.0-dev",
        node: "main",
        engine: "kronik-0.1.0+wasmtime-50.0.0",
    }
}

/// A readable rendering of a request, one span per line.
fn render(req: &kronik_otel::otlp::collector::trace::v1::ExportTraceServiceRequest) -> String {
    let kv = |a: &[kronik_otel::otlp::common::v1::KeyValue]| {
        a.iter()
            .map(|a| {
                let v = match a.value.as_ref().and_then(|v| v.value.as_ref()) {
                    Some(Value::StringValue(s)) => format!("{s:?}"),
                    Some(Value::IntValue(i)) => i.to_string(),
                    other => format!("{other:?}"),
                };
                format!("{}={v}", a.key)
            })
            .collect::<Vec<_>>()
            .join(" ")
    };
    let mut out = String::new();
    for rs in &req.resource_spans {
        out += &format!(
            "resource {}\n",
            kv(&rs.resource.as_ref().unwrap().attributes)
        );
        for ss in &rs.scope_spans {
            let scope = ss.scope.as_ref().unwrap();
            out += &format!("scope {} {}\n", scope.name, scope.version);
            for s in &ss.spans {
                out += &format!(
                    "span {:?} trace={} id={} parent={} kind={} {}..{} status={:?}\n  {}\n",
                    s.name,
                    hex(&s.trace_id),
                    hex(&s.span_id),
                    hex(&s.parent_span_id),
                    s.kind,
                    s.start_time_unix_nano,
                    s.end_time_unix_nano,
                    s.status.as_ref().map(|s| (s.code, &s.message)),
                    kv(&s.attributes),
                );
                for l in &s.links {
                    out += &format!(
                        "  link trace={} id={} {}\n",
                        hex(&l.trace_id),
                        hex(&l.span_id),
                        kv(&l.attributes)
                    );
                }
            }
        }
    }
    out
}

/// The whole mapping of a call A → B, pinned. Update with
/// `KRONIK_UPDATE_DOCS=1 cargo test -p kronik-otel --test spans golden`.
#[test]
fn golden_export_request() {
    let a = actor("counter/a");
    let root = root_key();
    let b_key = causal::child(&root, &a, 0);
    let a_rec = record(
        "counter/a",
        root,
        http("/counter/{key}/{op}", &[]),
        vec![call_effect(0, "counter/b", 120, 3_400)],
    );
    let b_rec = record(
        "counter/b",
        b_key,
        msg_input(pb::MessageSource::Call, "increment"),
        vec![],
    );
    let a_open = open(&[&a_rec]);
    let mut all = spans(
        &Turn {
            open: &a_open,
            ..turn(&b_rec)
        },
        &ActorKeys::Hashed(&hasher),
    );
    all.extend(spans(&turn(&a_rec), &ActorKeys::Hashed(&hasher)));
    let got = render(&request(&resource(), all));
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/spans.txt");
    if std::env::var_os("KRONIK_UPDATE_DOCS").is_some() {
        std::fs::write(path, &got).unwrap();
    }
    assert_eq!(got, std::fs::read_to_string(path).unwrap());
}

// ---- the wire format, independently of prost-build ----

fn varint(mut v: u64, out: &mut Vec<u8>) {
    while v >= 0x80 {
        out.push(v as u8 | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn len_field(n: u64, bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    varint(n << 3 | 2, &mut out);
    varint(bytes.len() as u64, &mut out);
    out.extend_from_slice(bytes);
    out
}

fn varint_field(n: u64, v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    varint(n << 3, &mut out);
    varint(v, &mut out);
    out
}

fn fixed64_field(n: u64, v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    varint(n << 3 | 1, &mut out);
    out.extend_from_slice(&v.to_le_bytes());
    out
}

fn string_kv(key: &str, value: &str) -> Vec<u8> {
    [
        len_field(1, key.as_bytes()),
        len_field(2, &len_field(1, value.as_bytes())),
    ]
    .concat()
}

/// An `ExportTraceServiceRequest` encoded by hand from the field numbers
/// and wire types of the OTLP 1.x spec (no reference sample is in the
/// offline crate cache, and no Collector runs here). Our generated types
/// decode it to the expected values and encode it back byte for byte.
#[test]
fn generated_types_match_the_otlp_wire_format() {
    let trace = [0x4b; 16];
    let span_id = [0x01; 8];
    let parent = [0x02; 8];
    let link_bytes = [
        len_field(1, &trace),
        len_field(2, &[0x03; 8]),
        len_field(4, &string_kv("kronik.link", "call")),
    ]
    .concat();
    let status_bytes = [len_field(2, b"TURN_FAILED"), varint_field(3, 2)].concat();
    let int_kv = [
        len_field(1, b"kronik.fuel_used"),
        len_field(2, &varint_field(3, 42)),
    ]
    .concat();
    let span = [
        len_field(1, &trace),
        len_field(2, &span_id),
        len_field(4, &parent),
        len_field(5, b"counter message get"),
        varint_field(6, 2),
        fixed64_field(7, 1_761_500_000_123_000_000),
        fixed64_field(8, 1_761_500_000_124_000_000),
        len_field(9, &string_kv("kronik.actor.kind", "counter")),
        len_field(9, &int_kv),
        len_field(13, &link_bytes),
        len_field(15, &status_bytes),
    ]
    .concat();
    let scope = [len_field(1, b"kronik"), len_field(2, b"0.1.0-dev")].concat();
    let scope_spans = [len_field(1, &scope), len_field(2, &span)].concat();
    let resource = len_field(1, &string_kv("service.name", "kronik"));
    let resource_spans = [len_field(1, &resource), len_field(2, &scope_spans)].concat();
    let bytes = len_field(1, &resource_spans);

    let req = kronik_otel::otlp::collector::trace::v1::ExportTraceServiceRequest::decode(
        bytes.as_slice(),
    )
    .unwrap();
    let rs = &req.resource_spans[0];
    assert_eq!(
        rs.resource.as_ref().unwrap().attributes[0].key,
        "service.name"
    );
    let ss = &rs.scope_spans[0];
    assert_eq!(ss.scope.as_ref().unwrap().version, "0.1.0-dev");
    let s = &ss.spans[0];
    assert_eq!(
        (s.trace_id.as_slice(), s.span_id.as_slice()),
        (&trace[..], &span_id[..])
    );
    assert_eq!(s.parent_span_id, parent);
    assert_eq!(s.name, "counter message get");
    assert_eq!(s.kind, span::SpanKind::Server as i32);
    assert_eq!(s.start_time_unix_nano, 1_761_500_000_123_000_000);
    assert_eq!(s.end_time_unix_nano, 1_761_500_000_124_000_000);
    assert_eq!(str_attr(s, "kronik.actor.kind"), Some("counter"));
    assert_eq!(attr(s, "kronik.fuel_used"), Some(&Value::IntValue(42)));
    assert_eq!(link(s).unwrap().1, "call");
    assert_eq!(s.links[0].span_id, [0x03; 8]);
    let st = s.status.as_ref().unwrap();
    assert_eq!(
        (st.code, st.message.as_str()),
        (status::StatusCode::Error as i32, "TURN_FAILED")
    );
    assert_eq!(req.encode_to_vec(), bytes);
}
