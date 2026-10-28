//! The CEL a rule's `when` can use: docs/design/m3-fork.md §7's "CEL subset
//! that must work", how the diff's JSON maps to CEL values, determinism, and
//! the limits of ADR 0007.

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use kronik_policy::{Action, MAX_WHEN_BYTES, MAX_WHEN_DEPTH, MAX_WHEN_NESTING, RuleSet};
use serde_json::{Value, json};
use std::path::Path;

/// The approximate-payments fixture, plus values the fixtures lack under
/// `diff.test`.
fn diff() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/design/fixtures/diff-approximate-payments.json");
    let mut diff: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    diff.as_object_mut().unwrap().remove("expected_policy");
    diff["test"] = json!({
        "text": "héllo wörld",
        "max_u64": u64::MAX,
        "negative": -3,
        "quarter": 0.25,
        "whole_double": 2.0,
        "flags": [true, false],
        "nested": [[1, 2], [3]],
        "empty_list": [],
        "empty_map": {},
        "nothing": null,
        "unordered": {"b": 2, "a": 1, "c": 3},
        "deep": {"a": {"a": {"a": 1}}},
    });
    diff
}

fn single_rule(when: &str) -> Result<RuleSet, String> {
    let when = serde_json::to_string(when).unwrap();
    RuleSet::parse_toml(&format!(
        "[[rule]]\nname = \"r\"\nwhen = {when}\naction = \"deny\"\n"
    ))
    .map_err(|e| e.message)
}

/// `Ok` with the value of `when` against `diff`, or `Err` with the message
/// of the evaluation error.
fn eval_on(when: &str, diff: &Value) -> Result<bool, String> {
    let set = single_rule(when).unwrap_or_else(|e| panic!("{when}: {e}"));
    let evaluation = set.evaluate(diff);
    match (evaluation.fired.as_slice(), evaluation.errors.as_slice()) {
        ([], []) => Ok(false),
        ([fired], []) => {
            assert_eq!(fired.action, Action::Deny);
            Ok(true)
        }
        ([fired], [error]) => {
            assert_eq!(fired.action, Action::Deny);
            Err(error.message.clone())
        }
        _ => panic!("{when}: {evaluation:?}"),
    }
}

fn eval(when: &str) -> Result<bool, String> {
    eval_on(when, &diff())
}

fn assert_true(cases: &[&str]) {
    let diff = diff();
    for when in cases {
        assert_eq!(eval_on(when, &diff), Ok(true), "{when}");
    }
}

fn assert_false(cases: &[&str]) {
    let diff = diff();
    for when in cases {
        assert_eq!(eval_on(when, &diff), Ok(false), "{when}");
    }
}

fn assert_error(cases: &[&str]) {
    let diff = diff();
    for when in cases {
        assert!(eval_on(when, &diff).is_err(), "{when}: expected an error");
    }
}

/// The message `parse_toml` gives for a rule with this `when`.
fn compile_error(when: &str) -> String {
    match single_rule(when) {
        Ok(_) => panic!("{when}: expected a parse error"),
        Err(message) => message,
    }
}

#[test]
fn literals() {
    assert_true(&[
        "1 == 1",
        "-1 < 0",
        "1u == 1u",
        "1.5 == 1.5",
        "1e3 == 1000.0",
        "0x10 == 16",
        "'a' == \"a\"",
        "'''multi\nline''' == 'multi\\nline'",
        "r'\\d' == '\\\\d'",
        "'\\u00e9' == 'é'",
        "b'abc' == b'abc'",
        "null == null",
        "true != false",
        "[1, 'two', 3.0] == [1, 'two', 3.0]",
        "[] == []",
    ]);
}

#[test]
fn json_values_map_to_cel_types() {
    assert_true(&[
        "type(diff.summary.root_inputs) == int",
        "type(diff.summary.confidence) == double",
        "type(diff.test.whole_double) == double",
        "type(diff.test.negative) == int",
        "type(diff.test.max_u64) == uint",
        "diff.test.max_u64 == 18446744073709551615u",
        "type(diff.base.branch) == string",
        "type(diff.summary.changed) == bool",
        "type(diff.grounding) == list",
        "type(diff.summary) == map",
        "diff.test.nothing == null",
        "diff.test.nested == [[1, 2], [3]]",
        "diff.test.empty_list == []",
        "diff.test.deep.a == diff.test.deep.a",
        "diff.test.deep != diff.test.deep.a",
        "[diff.test.deep] == [diff.test.deep]",
        "diff.test.deep in [diff.test.unordered, diff.test.deep]",
    ]);
}

#[test]
fn field_selection_and_indexing() {
    assert_true(&[
        "diff.summary.root_inputs == 100",
        "diff.base.branch == 'main'",
        "diff.grounding[0].host == 'payments.internal'",
        "diff.grounding[0]['route'] == '/v1/charges/{}'",
        "diff['summary']['exact'] == 120",
        "diff.test.nested[0][1] == 2",
        "diff.test.nested[1u][0] == 3",
        "diff.test.deep.a.a.a == 1",
        "[10, 20, 30][2] == 30",
    ]);
    assert_eq!(
        eval("diff.summary.no_such_field == 1"),
        Err("No such key: no_such_field".into())
    );
    assert_error(&[
        "diff.grounding[1].host == ''",
        "diff.grounding[-1].host == ''",
        "diff.summary[0] == 1",
        "diff.base.branch.length == 4",
        "diff.test.nothing.field == 1",
    ]);
}

#[test]
fn comparisons_mix_ints_and_doubles_numerically() {
    // The two forms §7 names.
    assert_eq!(eval("diff.summary.sample < 1"), Ok(false));
    assert_eq!(eval("diff.errors.introduced > 0.0"), Ok(false));
    assert_true(&[
        "diff.summary.sample == 1",
        "diff.summary.sample <= 1",
        "diff.summary.sample >= 1",
        "diff.summary.sample > 0",
        "diff.summary.sample < 2",
        "diff.errors.introduced == 0.0",
        "diff.errors.introduced < 0.5",
        "diff.errors.introduced >= -0.5",
        "diff.summary.root_inputs > 99.5",
        "diff.summary.root_inputs != 100.5",
        "diff.summary.confidence < 1",
        "diff.summary.confidence > 0",
        "diff.test.max_u64 > 1",
        "diff.test.negative < 0u",
        "1 == 1u",
        "1 == 1.0",
        "'a' < 'b'",
        "'payments' >= 'pay'",
        "b'a' < b'b'",
        "false < true",
        "1 != 'a'",
    ]);
    assert_false(&[
        "diff.summary.confidence < 0.9",
        "diff.summary.root_inputs < 100.0",
        "diff.summary.sample != 1",
        "1 == 'a'",
    ]);
    assert_eq!(
        eval("diff.base.branch > 1"),
        Err("found no matching overload for '_>_' applied to '(string, int)'".into())
    );
    assert_error(&["diff.test.flags < 1", "null < 1"]);
}

#[test]
fn logical_operators_absorb_errors_the_other_side_decides() {
    assert_true(&[
        "true && true",
        "true || false",
        "!false",
        "!(diff.summary.root_inputs < 1)",
        "true || diff.no_such_field",
        "diff.no_such_field || true",
        "1 / 0 == 1 || true",
        "true ? true : diff.no_such_field",
    ]);
    assert_false(&[
        "true && false",
        "false || false",
        "!true",
        "false && diff.no_such_field",
        "diff.no_such_field && false",
    ]);
    assert_error(&[
        "diff.no_such_field || false",
        "true && diff.no_such_field",
        "!1",
        "1 && true",
        "diff.base.branch || true && false",
    ]);
}

#[test]
fn arithmetic() {
    assert_true(&[
        "1 + 2 == 3",
        "5 - 7 == -2",
        "3 * 4 == 12",
        "7 / 2 == 3",
        "7 % 3 == 1",
        "7.0 / 2.0 == 3.5",
        "0.1 + 0.2 > 0.3",
        "2u * 3u == 6u",
        "1.0 / 0.0 > 1e308",
        "'pay' + 'ments' == 'payments'",
        "[1] + [2] == [1, 2]",
        "diff.grounding[0].approximate + diff.grounding[0].synthetic == 4",
        "diff.summary.exact - diff.summary.approximate == 116",
        "diff.resources.fuel.fork.p99 * 2 == 122000",
        "diff.summary.exact / (diff.summary.exact + diff.summary.approximate) == 0",
        "double(diff.summary.exact) / double(diff.summary.exact + diff.summary.approximate) > 0.96",
    ]);
    assert_eq!(eval("1 / 0 == 0"), Err("Division by zero of Int(1)".into()));
    assert_error(&[
        // CEL arithmetic does not mix int and double, unlike comparison.
        "1 + 1.0 == 2.0",
        "diff.summary.sample * 100 == 100",
        "9223372036854775807 + 1 > 0",
        "-9223372036854775807 - 2 < 0",
        "'a' - 'b' == ''",
        "diff.summary + 1 == 1",
    ]);
}

#[test]
fn membership() {
    assert_true(&[
        "2 in [1, 2, 3]",
        "2.0 in [1, 2, 3]",
        "'summary' in diff",
        "'payments.internal' in diff.grounding.map(t, t.host)",
        "'p99' in diff.resources.fuel.prod",
        "[3] in diff.test.nested",
        "!('nope' in diff.summary)",
    ]);
    assert_false(&["4 in [1, 2, 3]", "'nope' in diff", "1 in diff.summary"]);
    assert_error(&["[1] in diff.summary", "1 in 2"]);
}

#[test]
fn size() {
    assert_true(&[
        "size(diff.grounding) == 1",
        "diff.grounding.size() == 1",
        "size(diff.summary) == 15",
        "diff.summary.size() == 15",
        "size(diff.test.empty_map) == 0",
        "size(diff.test.text) == 11",
        "size(b'ab') == 2",
        "size([]) == 0",
        "size(diff.grounding.filter(t, t.exact > 0)) == 1",
    ]);
    assert_error(&["size(1) == 1", "size(diff.test.nothing) == 0"]);
}

#[test]
fn comprehension_macros() {
    assert_true(&[
        "diff.grounding.exists(t, t.host.endsWith('payments.internal'))",
        "diff.grounding.all(t, t.exact > 100)",
        "diff.grounding.exists_one(t, t.approximate == 4)",
        "diff.grounding.existsOne(t, t.approximate == 4)",
        "diff.grounding.filter(t, t.approximate > 0).size() == 1",
        "diff.grounding.map(t, t.approximate + t.synthetic) == [4]",
        "diff.grounding.map(t, t.approximate > 0, t.route) == ['/v1/charges/{}']",
        "[].all(x, x > 1)",
        "!([].exists(x, x > 1))",
        "[1, 2, 3].exists_one(x, x > 2)",
        "!([1, 2, 3].exists_one(x, x > 1))",
        "[1, 2, 3].filter(x, x > 1) == [2, 3]",
        "[1, 2, 3].map(x, x * 2) == [2, 4, 6]",
        "diff.test.nested.all(l, l.all(x, x > 0))",
        "diff.test.nested.map(l, size(l)) == [2, 1]",
        // Over a map, the macros range over its keys.
        "diff.summary.exists(k, k == 'confidence')",
        "diff.summary.all(k, k != '')",
        "size(diff.summary.filter(k, k.startsWith('turns'))) == 2",
        "diff.resources.fuel.prod.all(k, diff.resources.fuel.prod[k] == diff.resources.fuel.fork[k])",
        // As && and ||: an error on one element is absorbed when another decides.
        "[1, 'a'].exists(x, x > 0)",
        "['a', 1].exists(x, x > 0)",
        "!(['a', 0].all(x, x > 0))",
    ]);
    assert_error(&[
        "[1, 'a'].all(x, x > 0)",
        "[2, 'a', 3].exists_one(x, x > 2)",
        "[1, 2].map(x, x / 0) == []",
        "diff.grounding.exists(t, t.no_such_field > 0)",
        "1.exists(x, true)",
        // Not a macro with one argument: a call of an undeclared function.
        "diff.grounding.exists(t)",
        // The variable is only in scope inside the macro.
        "[1].exists(x, x == 1) && x == 1",
    ]);
    assert!(compile_error("[1, 2].exists(1, true)").starts_with("invalid `when`: "));
}

#[test]
fn string_functions() {
    assert_true(&[
        "diff.grounding[0].host.startsWith('payments')",
        "diff.grounding[0].host.endsWith('.internal')",
        "diff.grounding[0].host.contains('ments.int')",
        "diff.grounding[0].route.matches('^/v1/charges/')",
        "diff.grounding[0].host.matches('^[a-z]+\\\\.internal$')",
        "matches(diff.base.branch, 'ai')",
        "diff.test.text.startsWith('hé')",
        "diff.test.text.contains('wö')",
        "!diff.grounding[0].host.startsWith('internal')",
        "!diff.base.branch.matches('^x')",
    ]);
    assert_error(&[
        "diff.base.branch.matches('(')",
        "diff.summary.exact.startsWith('1')",
        "diff.base.branch.contains(1)",
        "diff.test.nothing.endsWith('')",
    ]);
}

#[test]
fn has_tests_field_presence() {
    assert_true(&[
        "has(diff.summary)",
        "has(diff.summary.confidence)",
        "!has(diff.summary.no_such_field)",
        "!has(diff.no_such_field)",
        "has(diff.grounding[0].host)",
        "diff.grounding.all(t, has(t.confidence))",
        "!has(diff.test.empty_map.anything)",
        "has(diff.test.nothing)",
    ]);
    assert_error(&[
        "has(diff.no_such_field.deeper)",
        "has(diff.test.negative.x)",
    ]);
    for when in ["has(diff)", "has(1)", "has(diff.grounding[0])"] {
        assert!(
            compile_error(when).starts_with("invalid `when`: "),
            "{when}"
        );
    }
}

#[test]
fn a_rule_must_evaluate_to_a_bool() {
    for (when, kind) in [
        ("diff.summary.root_inputs", "int"),
        ("diff.summary.confidence", "double"),
        ("diff.base.branch", "string"),
        ("diff.grounding", "list"),
        ("diff.summary", "map"),
        ("diff.test.nothing", "null_type"),
    ] {
        assert_eq!(
            eval(when),
            Err(format!("the expression evaluated to a {kind}, not a bool")),
            "{when}"
        );
    }
}

#[test]
fn maps_iterate_in_the_json_objects_order_on_every_evaluation() {
    let diff = diff();
    let keys = |path: &str| -> Vec<String> {
        diff.pointer(path)
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
            .map(|k| format!("'{k}'"))
            .collect()
    };
    let summary = format!(
        "diff.summary.map(k, k) == [{}]",
        keys("/summary").join(", ")
    );
    let unordered = format!(
        "diff.test.unordered.map(k, k) == [{}]",
        keys("/test/unordered").join(", ")
    );
    let first_plural = keys("/summary")
        .into_iter()
        .find(|k| k.ends_with("s'"))
        .unwrap();
    let first_key = format!("diff.summary.filter(k, k.endsWith('s'))[0] == {first_plural}");
    let set = RuleSet::parse_toml(&format!(
        "[[rule]]\nname = \"summary\"\nwhen = {}\naction = \"deny\"\n\n\
         [[rule]]\nname = \"unordered\"\nwhen = {}\naction = \"deny\"\n\n\
         [[rule]]\nname = \"first-key\"\nwhen = {}\naction = \"deny\"\n\n\
         [[rule]]\nname = \"first-error\"\nwhen = \"diff.all(k, diff[k] > 0)\"\naction = \"deny\"\n",
        serde_json::to_string(&summary).unwrap(),
        serde_json::to_string(&unordered).unwrap(),
        serde_json::to_string(&first_key).unwrap(),
    ))
    .unwrap();
    let first = set.evaluate(&diff);
    let fired: Vec<&str> = first.fired.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(fired, ["summary", "unordered", "first-key", "first-error"]);
    assert_eq!(first.errors.len(), 1, "{first:?}");
    // CEL's own maps iterate in hash order, which varies between
    // evaluations; the diff's maps don't.
    for _ in 0..200 {
        assert_eq!(set.evaluate(&diff), first);
    }
}

#[test]
fn nothing_reaches_a_clock_or_the_environment() {
    for when in [
        "now() > 0",
        "timestamp('2026-01-01T00:00:00Z') < timestamp('2027-01-01T00:00:00Z')",
        "duration('1h') > duration('1m')",
        "getenv('HOME') != ''",
        "env('HOME') != ''",
        "os.getenv('HOME') != ''",
        "time.now() > 0",
        "base64.encode(b'x') != ''",
        "math.greatest(1, 2) == 2",
        "diff.base.branch.lowerAscii() == 'main'",
    ] {
        let message = eval(when).unwrap_err();
        assert!(
            message.starts_with("Undeclared reference to '"),
            "{when}: {message}"
        );
    }
}

#[test]
fn map_literals_message_construction_and_optional_syntax_are_rejected() {
    for when in [
        "{'a': 1}.size() == 1",
        "diff.grounding[0].host in {'payments.internal': true}",
        "[{'a': 1}].size() == 1",
        "{}.size() == 0",
    ] {
        assert_eq!(
            compile_error(when),
            "invalid `when`: map literals are not supported: CEL leaves the order in which a \
             map is iterated unspecified, and a policy must evaluate deterministically",
            "{when}"
        );
    }
    assert_eq!(
        compile_error("Point{x: 1}.x == 1"),
        "invalid `when`: message construction (`Point{…}`) is not supported"
    );
    for when in [
        "diff.?summary.hasValue()",
        "diff[?'summary'].hasValue()",
        "[?diff.summary] == []",
    ] {
        let error = compile_error(when);
        assert!(
            error.starts_with("invalid `when`: unsupported syntax '"),
            "{when}: {error}"
        );
    }
}

/// Runs `test` on a thread with the stack a tokio worker or test thread has:
/// 2 MiB, enough for any rule in debug builds. Release builds need a fraction
/// of that; this checks 512 KiB under `cargo test --release`.
fn within_worker_stack(test: impl FnOnce() + Send + 'static) {
    let stack = if cfg!(debug_assertions) {
        2 << 20
    } else {
        512 << 10
    };
    std::thread::Builder::new()
        .stack_size(stack)
        .spawn(test)
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn a_when_longer_than_the_limit_is_rejected() {
    let longest = format!("{}true", " ".repeat(MAX_WHEN_BYTES - 4));
    assert_eq!(eval(&longest), Ok(true));
    let too_long = format!(" {longest}");
    assert_eq!(
        compile_error(&too_long),
        format!(
            "invalid `when`: the expression is {} bytes long; at most {MAX_WHEN_BYTES} are allowed",
            MAX_WHEN_BYTES + 1
        )
    );
}

#[test]
fn nesting_beyond_the_limit_is_rejected_before_it_costs_stack() {
    within_worker_stack(|| {
        let nested = |open: &str, close: &str, levels: usize| {
            format!("{}true{}", open.repeat(levels), close.repeat(levels))
        };
        let pairs = MAX_WHEN_NESTING / 2;
        let deepest = [
            nested("(", ")", MAX_WHEN_NESTING),
            format!("size({}) == 1", nested("[", "]", MAX_WHEN_NESTING - 1)),
            format!(
                "{}1{} == 1",
                "size(string(".repeat(pairs),
                "))".repeat(pairs)
            ),
            format!("{}true", "true ? true : ".repeat(MAX_WHEN_NESTING)),
            format!(
                "{}true{}",
                "[1].exists(a, ".repeat(MAX_WHEN_NESTING),
                ")".repeat(MAX_WHEN_NESTING)
            ),
        ];
        for when in &deepest {
            assert_eq!(eval(when), Ok(true), "{when}");
        }
        let message = format!(
            "invalid `when`: the expression nests parentheses, brackets, braces, calls or \
             conditionals more than {MAX_WHEN_NESTING} levels deep"
        );
        let deeper = MAX_WHEN_NESTING + 1;
        assert_eq!(
            compile_error(&format!("{}true", "true ? true : ".repeat(deeper))),
            message
        );
        for levels in [deeper, 100, MAX_WHEN_BYTES / 2 - 2] {
            for (open, close) in [
                ("(", ")"),
                ("[", "]"),
                ("{", "}"),
                ("f(", ")"),
                ("[1].all(a, ", ")"),
            ] {
                let when = nested(open, close, levels);
                let when = &when[..when.len().min(MAX_WHEN_BYTES)];
                assert_eq!(compile_error(when), message, "{levels} levels of {open}");
            }
        }
    });
}

#[test]
fn the_deepest_accepted_rules_evaluate_and_deeper_ones_are_rejected() {
    within_worker_stack(|| {
        let mut diff = diff();
        let mut deep = json!(1);
        let mut list = json!(1);
        for _ in 0..MAX_WHEN_DEPTH - 3 {
            deep = json!({"a": deep});
            list = json!([list]);
        }
        diff["deep"] = deep;
        diff["list"] = list;
        // Each shape as deep as accepted, `MAX_WHEN_DEPTH` levels with what
        // surrounds it, and one link longer.
        type Shape = (&'static str, fn(usize) -> String, usize);
        let shapes: [Shape; 5] = [
            (
                "+ chain",
                |n| format!("{} > 0", vec!["1"; n + 1].join(" + ")),
                MAX_WHEN_DEPTH - 2,
            ),
            (
                "field chain",
                |n| format!("diff.deep{} == 1", ".a".repeat(n)),
                MAX_WHEN_DEPTH - 3,
            ),
            (
                "index chain",
                |n| format!("diff.list{} == 1", "[0]".repeat(n)),
                MAX_WHEN_DEPTH - 3,
            ),
            (
                "map chain",
                |n| format!("size([1]{}) == 1", ".map(a, a)".repeat(n)),
                (MAX_WHEN_DEPTH - 5) / 2,
            ),
            (
                "filter chain",
                |n| format!("size([1]{}) == 1", ".filter(a, true)".repeat(n)),
                (MAX_WHEN_DEPTH - 5) / 2,
            ),
        ];
        let message =
            format!("invalid `when`: the expression nests deeper than {MAX_WHEN_DEPTH} levels");
        for (shape, when, deepest) in shapes {
            assert_eq!(eval_on(&when(deepest), &diff), Ok(true), "{shape}");
            assert_eq!(compile_error(&when(deepest + 1)), message, "{shape}");
        }
        // Chains as long as the length limit allows parse, then fail the check.
        for (start, link) in [
            ("1", " + 1"),
            ("1", "<1"),
            ("diff", ".a"),
            ("diff", "[0]"),
            ("[1]", ".map(a,a)"),
        ] {
            let mut when = start.to_owned() + &link.repeat(MAX_WHEN_BYTES / link.len());
            when.truncate(MAX_WHEN_BYTES);
            let error = compile_error(&when);
            assert!(error.starts_with("invalid `when`: "), "{link}: {error}");
        }
    });
}
