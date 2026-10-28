//! Rule sets: parsing, the default rules, outcomes and their JSON form
//! (docs/design/m3-fork.md §7).

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use kronik_policy::{
    Action, DEFAULT_RULES_TOML, Evaluation, Fired, PII_MASKED_RULE, PolicyError, Rule, RuleSet,
};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

/// The Swedish brief's file name at the repo root (it holds an em dash and
/// spaces), located by pattern rather than by a literal that encoding
/// trouble could silently misspell.
fn brief_path() -> PathBuf {
    let root = repo_path(".");
    let name = std::fs::read_dir(&root)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .find(|n| n.starts_with("Kronik") && n.ends_with("Agent Build Brief.md"))
        .expect("the brief (Kronik — Agent Build Brief.md) is in the repo root");
    root.join(name)
}

/// A fixture diff, and its `expected_policy` removed from it.
fn fixture(path: &Path) -> (Value, Value) {
    let text = std::fs::read_to_string(path).unwrap();
    let mut diff: Value = serde_json::from_str(&text).unwrap();
    let expected = diff
        .as_object_mut()
        .unwrap()
        .remove("expected_policy")
        .unwrap();
    (diff, expected)
}

fn fixture_named(name: &str) -> Value {
    fixture(&repo_path("docs/design/fixtures").join(name)).0
}

/// A rules file with one `[[rule]]` per `(name, when, action)`.
fn rules_toml(rules: &[(&str, &str, &str)]) -> String {
    rules
        .iter()
        .map(|(name, when, action)| {
            // A JSON string is a valid TOML basic string.
            let when = serde_json::to_string(when).unwrap();
            format!("[[rule]]\nname = \"{name}\"\nwhen = {when}\naction = \"{action}\"\n\n")
        })
        .collect()
}

fn rule_set(rules: &[(&str, &str, &str)]) -> RuleSet {
    RuleSet::parse_toml(&rules_toml(rules)).unwrap()
}

fn parse_error(text: &str) -> PolicyError {
    RuleSet::parse_toml(text).unwrap_err()
}

fn fired(evaluation: &Evaluation) -> Vec<(&str, Action)> {
    evaluation
        .fired
        .iter()
        .map(|f| (f.name.as_str(), f.action))
        .collect()
}

#[test]
fn every_fixture_gives_its_expected_policy_under_the_default_rules() {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(repo_path("docs/design/fixtures")).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        if !(name.starts_with("diff-") && name.ends_with(".json")) {
            continue;
        }
        let (diff, expected) = fixture(&path);
        let evaluation = RuleSet::defaults().evaluate(&diff);
        let got = serde_json::to_value(&evaluation).unwrap();
        assert_eq!(
            got["outcome"], expected["outcome"],
            "{name}: {evaluation:?}"
        );
        assert_eq!(got["fired"], expected["fired"], "{name}: {evaluation:?}");
        assert_eq!(evaluation.errors, [], "{name}");
        names.push(name);
    }
    names.sort();
    assert_eq!(
        names,
        [
            "diff-approximate-payments.json",
            "diff-counter-plus-2.json",
            "diff-identity.json",
            "diff-introduced-error.json",
            "diff-sampled-payments.json",
            "diff-system-caller-alone.json",
        ]
    );
}

#[test]
fn the_default_rules_are_the_brief_rules_verbatim() {
    // The Swedish brief is authoritative; its `Standardregler` block is
    // the default rules, byte for byte. (SPEC.md carries a translation.)
    let brief = std::fs::read_to_string(brief_path()).unwrap();
    let start = brief.find("Standardregler som följer med:").unwrap();
    let block = &brief[start..];
    let block = &block[block.find("```toml\n").unwrap() + "```toml\n".len()..];
    let block = &block[..block.find("```").unwrap()];
    assert_eq!(DEFAULT_RULES_TOML, block);

    let defaults = RuleSet::defaults();
    assert_eq!(RuleSet::parse_toml(DEFAULT_RULES_TOML).unwrap(), defaults);
    let names: Vec<(&str, Action)> = defaults
        .rules
        .iter()
        .map(|rule| (rule.name.as_str(), rule.action))
        .collect();
    assert_eq!(
        names,
        [
            ("no-new-errors", Action::Deny),
            ("no-new-orphans", Action::RequireApproval),
            ("low-grounding-needs-approval", Action::RequireApproval),
            ("payments-must-be-exact", Action::RequireApproval),
            ("payments-full-coverage", Action::Deny),
            ("fuel-regression", Action::Deny),
        ]
    );
}

/// M5: "The rule `payments-must-be-exact` triggers on grounding per target
/// even when the total confidence is above 0.99."
#[test]
fn payments_must_be_exact_fires_on_one_target_when_total_confidence_is_above_99_percent() {
    let mut diff = fixture_named("diff-approximate-payments.json");
    // Thousands of exact calls to another target hide 4 approximate payments
    // in the totals.
    diff["grounding"].as_array_mut().unwrap().insert(
        0,
        json!({"kind": "http.fetch", "method": "GET", "host": "api.example.com",
               "route": "/items/{}", "exact": 20000, "approximate": 0, "synthetic": 0,
               "confidence": 1.0}),
    );
    let summary = &mut diff["summary"];
    summary["exact"] = json!(20120);
    summary["approximate"] = json!(4);
    summary["confidence"] = json!(0.999801);
    assert!(diff["summary"]["confidence"].as_f64().unwrap() > 0.99);

    let evaluation = RuleSet::defaults().evaluate(&diff);
    assert_eq!(evaluation.outcome, Action::RequireApproval);
    assert_eq!(
        fired(&evaluation),
        [("payments-must-be-exact", Action::RequireApproval)]
    );
    assert_eq!(evaluation.errors, []);

    // The same diff with exact payments passes.
    diff["grounding"][1]["exact"] = json!(124);
    diff["grounding"][1]["approximate"] = json!(0);
    assert_eq!(RuleSet::defaults().evaluate(&diff).outcome, Action::Allow);
}

/// M9: a rule can single out one actor kind of a system proposal through
/// the diff's per-kind `kinds` entries.
#[test]
fn a_rule_can_judge_one_kind_of_a_system_diff() {
    let diff = fixture_named("diff-system-caller-alone.json");
    let rules = rule_set(&[(
        "notes-untouched",
        "diff.kinds.exists(k, k.kind == 'notes' && k.code == 'unchanged' && k.errors.introduced > 0)",
        "require_approval",
    )]);
    let evaluation = rules.evaluate(&diff);
    assert_eq!(evaluation.errors, []);
    assert_eq!(
        fired(&evaluation),
        [("notes-untouched", Action::RequireApproval)]
    );
    // A diff from before M9 has no `kinds`: the rule errs, which counts as
    // firing with at least require_approval.
    let old = fixture_named("diff-identity.json");
    let evaluation = rules.evaluate(&old);
    assert_eq!(evaluation.outcome, Action::RequireApproval);
    assert_eq!(evaluation.errors.len(), 1);
}

#[test]
fn actions_order_from_allow_to_deny() {
    assert!(Action::Allow < Action::RequireApproval);
    assert!(Action::RequireApproval < Action::Deny);
    assert_eq!(
        [Action::Deny, Action::Allow, Action::RequireApproval]
            .into_iter()
            .max(),
        Some(Action::Deny)
    );
}

#[test]
fn the_strictest_action_among_fired_rules_wins() {
    let diff = fixture_named("diff-identity.json");
    let cases: &[(&[&str], Action)] = &[
        (&["allow"], Action::Allow),
        (&["require_approval"], Action::RequireApproval),
        (&["deny"], Action::Deny),
        (&["allow", "require_approval"], Action::RequireApproval),
        (&["require_approval", "allow"], Action::RequireApproval),
        (&["deny", "require_approval", "allow"], Action::Deny),
        (&["allow", "allow", "deny"], Action::Deny),
    ];
    for (actions, outcome) in cases {
        let names: Vec<String> = (0..actions.len()).map(|i| format!("rule-{i}")).collect();
        let rules: Vec<(&str, &str, &str)> = actions
            .iter()
            .zip(&names)
            .map(|(action, name)| (name.as_str(), "true", *action))
            .collect();
        let evaluation = rule_set(&rules).evaluate(&diff);
        assert_eq!(evaluation.outcome, *outcome, "{actions:?}");
        assert_eq!(evaluation.fired.len(), actions.len(), "{actions:?}");
    }
    // Rules that don't fire count for nothing.
    let evaluation =
        rule_set(&[("off", "false", "deny"), ("on", "true", "require_approval")]).evaluate(&diff);
    assert_eq!(evaluation.outcome, Action::RequireApproval);
    assert_eq!(fired(&evaluation), [("on", Action::RequireApproval)]);
}

#[test]
fn no_rule_firing_and_no_rules_both_allow() {
    let diff = fixture_named("diff-counter-plus-2.json");
    let quiet = rule_set(&[("never", "diff.summary.changed && false", "deny")]);
    let evaluation = quiet.evaluate(&diff);
    assert_eq!(evaluation.outcome, Action::Allow);
    assert_eq!(evaluation.fired, []);

    let empty = RuleSet::parse_toml("").unwrap();
    assert_eq!(empty.rules, []);
    assert_eq!(
        empty.evaluate(&diff),
        Evaluation {
            outcome: Action::Allow,
            fired: vec![],
            errors: vec![],
        }
    );
}

#[test]
fn fired_rules_are_listed_in_rule_order() {
    let diff = fixture_named("diff-introduced-error.json");
    let set = rule_set(&[
        ("c", "true", "allow"),
        ("a", "diff.errors.introduced == 1", "deny"),
        ("skipped", "false", "deny"),
        ("b", "diff.errors.new_orphans == 1", "require_approval"),
    ]);
    assert_eq!(
        fired(&set.evaluate(&diff)),
        [
            ("c", Action::Allow),
            ("a", Action::Deny),
            ("b", Action::RequireApproval),
        ]
    );
}

#[test]
fn a_rule_that_fails_to_evaluate_fires_with_at_least_require_approval() {
    let diff = fixture_named("diff-identity.json");
    let set = rule_set(&[
        ("missing-field", "diff.summary.no_such_field > 0", "allow"),
        ("type-error", "diff.base.branch > 1", "require_approval"),
        ("not-a-bool", "diff.summary.root_inputs", "deny"),
        ("fine", "diff.summary.root_inputs == 100", "allow"),
        ("quiet", "diff.summary.changed", "deny"),
    ]);
    let evaluation = set.evaluate(&diff);
    assert_eq!(
        fired(&evaluation),
        [
            ("missing-field", Action::RequireApproval),
            ("type-error", Action::RequireApproval),
            ("not-a-bool", Action::Deny),
            ("fine", Action::Allow),
        ]
    );
    assert_eq!(evaluation.outcome, Action::Deny);
    let errors: Vec<(&str, &str)> = evaluation
        .errors
        .iter()
        .map(|e| (e.name.as_str(), e.message.as_str()))
        .collect();
    assert_eq!(
        errors,
        [
            ("missing-field", "No such key: no_such_field"),
            (
                "type-error",
                "found no matching overload for '_>_' applied to '(string, int)'"
            ),
            (
                "not-a-bool",
                "the expression evaluated to a int, not a bool"
            ),
        ]
    );

    // An erroring `allow` rule alone requires approval.
    let evaluation = rule_set(&[("broken", "diff.nope", "allow")]).evaluate(&diff);
    assert_eq!(evaluation.outcome, Action::RequireApproval);

    // A diff that is not an object fails every rule that reads it.
    let evaluation = RuleSet::defaults().evaluate(&Value::Null);
    assert_eq!(evaluation.outcome, Action::Deny);
    assert_eq!(evaluation.errors.len(), 6);
}

#[test]
fn an_evaluation_renders_as_the_specified_json() {
    let diff = fixture_named("diff-identity.json");
    let set = rule_set(&[
        ("needs-ok", "true", "require_approval"),
        ("broken", "diff.nope", "allow"),
    ]);
    let evaluation = set.evaluate(&diff);
    assert_eq!(
        serde_json::to_string(&evaluation).unwrap(),
        r#"{"outcome":"require_approval","fired":[{"name":"needs-ok","action":"require_approval"},{"name":"broken","action":"require_approval"}],"errors":[{"name":"broken","message":"No such key: nope"}]}"#
    );
    let back: Evaluation =
        serde_json::from_value(serde_json::to_value(&evaluation).unwrap()).unwrap();
    assert_eq!(back, evaluation);

    for (action, name) in [
        (Action::Allow, "allow"),
        (Action::RequireApproval, "require_approval"),
        (Action::Deny, "deny"),
    ] {
        assert_eq!(serde_json::to_value(action).unwrap(), json!(name));
        assert_eq!(action.as_str(), name);
        assert_eq!(action.to_string(), name);
    }
    assert_eq!(
        serde_json::to_value(Fired {
            name: "x".into(),
            action: Action::Deny,
            reason: None,
        })
        .unwrap(),
        json!({"name": "x", "action": "deny"})
    );
}

/// ADR 0031: a diff with pii-masked turns is never `allow`, whatever the
/// rules: not with the defaults, not with no rules at all; a `deny` stays.
#[test]
fn pii_masked_turns_need_at_least_an_approval() {
    // The identity fixture is `allow` under the defaults; masked, it is not.
    let (mut diff, _) = fixture(&repo_path("docs/design/fixtures/diff-identity.json"));
    assert_eq!(RuleSet::defaults().evaluate(&diff).outcome, Action::Allow);
    diff["summary"]["pii_masked"] = json!(8);
    for rules in [RuleSet::defaults(), rule_set(&[])] {
        let e = rules.evaluate(&diff);
        assert_eq!(e.outcome, Action::RequireApproval, "{e:?}");
        let floor = e.fired.last().unwrap();
        assert_eq!(
            (floor.name.as_str(), floor.action),
            (PII_MASKED_RULE, Action::RequireApproval)
        );
        let reason = floor.reason.as_deref().unwrap();
        assert!(
            reason.starts_with("8 turns could not be verified"),
            "{reason}"
        );
        assert!(reason.contains("pii:read"), "{reason}");
    }
    let denied = rule_set(&[("no", "true", "deny")]).evaluate(&diff);
    assert_eq!(denied.outcome, Action::Deny);
    diff["summary"]["pii_masked"] = json!(0);
    assert_eq!(rule_set(&[]).evaluate(&diff).fired, []);
    // Identical turns of changed code that read pseudonyms count too.
    diff["summary"]["pii_masked"] = json!(1);
    diff["summary"]["pii_unverified"] = json!(2);
    let e = rule_set(&[]).evaluate(&diff);
    assert_eq!(e.outcome, Action::RequireApproval);
    let reason = e.fired[0].reason.as_deref().unwrap();
    assert!(
        reason.starts_with("3 turns could not be verified"),
        "{reason}"
    );
}

#[test]
fn parsing_keeps_names_expressions_and_actions() {
    let text = r#"
# Comments and multi-line strings are TOML as usual.
[[rule]]
name = "big-fuel-regression-2"
when = """
diff.resources.fuel_p99_change > 2.0
"""
action = "deny"

[[rule]]
action = "allow"
when = 'diff.summary.changed'
name = "changed"
"#;
    let set = RuleSet::parse_toml(text).unwrap();
    assert_eq!(
        set.rules,
        [
            Rule {
                name: "big-fuel-regression-2".into(),
                when: "diff.resources.fuel_p99_change > 2.0\n".into(),
                action: Action::Deny,
            },
            Rule {
                name: "changed".into(),
                when: "diff.summary.changed".into(),
                action: Action::Allow,
            },
        ]
    );
    let diff = fixture_named("diff-introduced-error.json");
    assert_eq!(fired(&set.evaluate(&diff)), [("changed", Action::Allow)]);
}

#[test]
fn unknown_keys_are_errors() {
    let error = parse_error(
        "[[rule]]\nname = \"a\"\nwhen = \"true\"\naction = \"deny\"\nreason = \"why\"\n",
    );
    assert_eq!(error.name.as_deref(), Some("a"));
    assert_eq!(
        error.message,
        "unknown key `reason`: a rule has only `name`, `when` and `action`"
    );
    assert_eq!(
        error.to_string(),
        "rule `a`: unknown key `reason`: a rule has only `name`, `when` and `action`"
    );

    let error = parse_error("[[rules]]\nname = \"a\"\nwhen = \"true\"\naction = \"deny\"\n");
    assert_eq!(error.name, None);
    assert_eq!(
        error.message,
        "unknown key `rules`: a rules file has only [[rule]] tables"
    );

    let error = parse_error("version = 1\n");
    assert_eq!(error.name, None);
    assert!(
        error.message.starts_with("unknown key `version`"),
        "{error}"
    );
}

#[test]
fn duplicate_names_are_errors() {
    let error = parse_error(&rules_toml(&[
        ("same", "true", "allow"),
        ("other", "true", "allow"),
        ("same", "false", "deny"),
    ]));
    assert_eq!(error.name.as_deref(), Some("same"));
    assert_eq!(
        error.message,
        "duplicate name: an earlier rule has the same name"
    );
}

#[test]
fn names_must_match_lowercase_digits_and_dashes() {
    for name in [
        "Payments",
        "no_new_errors",
        "with space",
        "",
        "ümlaut",
        "a.b",
    ] {
        let error = parse_error(&rules_toml(&[(name, "true", "deny")]));
        assert_eq!(error.name.as_deref(), Some(name));
        assert_eq!(
            error.message,
            "invalid name: use lowercase letters, digits and `-` ([a-z0-9-]+)"
        );
    }
    for name in ["a", "0", "-", "payments-2-must-be-exact"] {
        assert!(RuleSet::parse_toml(&rules_toml(&[(name, "true", "deny")])).is_ok());
    }
}

#[test]
fn actions_must_be_allow_require_approval_or_deny() {
    for action in ["block", "Deny", "require-approval", "requireApproval", ""] {
        let error = parse_error(&rules_toml(&[("r", "true", action)]));
        assert_eq!(error.name.as_deref(), Some("r"));
        assert_eq!(
            error.message,
            format!("unknown action `{action}`: use allow, require_approval or deny")
        );
    }
}

#[test]
fn missing_and_mistyped_fields_are_errors() {
    let cases = [
        (
            "[[rule]]\nwhen = \"true\"\naction = \"deny\"\n",
            None,
            "rule 1 has no `name`",
        ),
        (
            "[[rule]]\nname = 7\nwhen = \"true\"\naction = \"deny\"\n",
            None,
            "rule 1: `name` must be a string",
        ),
        (
            "[[rule]]\nname = \"r\"\naction = \"deny\"\n",
            Some("r"),
            "missing `when`",
        ),
        (
            "[[rule]]\nname = \"r\"\nwhen = true\naction = \"deny\"\n",
            Some("r"),
            "`when` must be a string",
        ),
        (
            "[[rule]]\nname = \"r\"\nwhen = \"true\"\n",
            Some("r"),
            "missing `action`",
        ),
        (
            "[[rule]]\nname = \"r\"\nwhen = \"true\"\naction = [\"deny\"]\n",
            Some("r"),
            "`action` must be a string",
        ),
        (
            "rule = \"x\"\n",
            None,
            "`rule` must be an array of tables ([[rule]])",
        ),
        ("rule = [1]\n", None, "rule 1 is not a table"),
    ];
    for (text, name, message) in cases {
        let error = parse_error(text);
        assert_eq!(error.name.as_deref(), name, "{text}");
        assert_eq!(error.message, message, "{text}");
    }
}

#[test]
fn cel_syntax_errors_surface_when_parsing() {
    let error = parse_error(&rules_toml(&[
        ("fine", "true", "allow"),
        ("broken", "diff.errors.introduced >", "deny"),
    ]));
    assert_eq!(error.name.as_deref(), Some("broken"));
    assert!(
        error.message.starts_with("invalid `when`: Syntax error: "),
        "{error}"
    );
    assert!(error.message.ends_with("at line 1, column 25"), "{error}");

    for when in [
        "diff.grounding.exists(t, )",
        "diff..errors",
        "'unterminated",
        "diff.errors introduced",
        "has(diff)",
        "[1].exists(1, true)",
        "",
    ] {
        let error = parse_error(&rules_toml(&[("r", when, "deny")]));
        assert_eq!(error.name.as_deref(), Some("r"), "{when}");
        assert!(
            error.message.starts_with("invalid `when`: "),
            "{when}: {error}"
        );
    }
}

#[test]
fn toml_syntax_errors_carry_their_position() {
    let error = parse_error("[[rule]]\nname = \"a\"\nwhen = \"true\"\naction = deny\n");
    assert_eq!(error.name, None);
    assert!(
        error
            .message
            .starts_with("invalid TOML at line 4, column 10: "),
        "{error}"
    );

    let error = parse_error("[[rule]]\nname = \"a\"\nname = \"b\"\n");
    assert!(
        error.message.starts_with("invalid TOML at line 3"),
        "{error}"
    );
}

#[test]
fn rules_changed_after_parsing_are_evaluated_as_changed() {
    let diff = fixture_named("diff-identity.json");
    let mut set = rule_set(&[("r", "false", "deny")]);
    assert_eq!(set.evaluate(&diff).outcome, Action::Allow);

    set.rules[0].when = "diff.summary.root_inputs == 100".into();
    assert_eq!(fired(&set.evaluate(&diff)), [("r", Action::Deny)]);

    set.rules[0].when = "diff.summary.root_inputs ==".into();
    let evaluation = set.evaluate(&diff);
    assert_eq!(fired(&evaluation), [("r", Action::Deny)]);
    assert!(
        evaluation.errors[0]
            .message
            .starts_with("invalid `when`: Syntax error"),
        "{evaluation:?}"
    );

    set.rules.push(Rule {
        name: "added".into(),
        when: "true".into(),
        action: Action::RequireApproval,
    });
    set.rules.remove(0);
    assert_eq!(
        fired(&set.evaluate(&diff)),
        [("added", Action::RequireApproval)]
    );
}

#[test]
fn evaluation_is_pure_and_rule_sets_are_shareable() {
    fn shareable<T: Send + Sync + Clone + 'static>() {}
    shareable::<RuleSet>();
    shareable::<Evaluation>();
    shareable::<PolicyError>();

    let diff = fixture_named("diff-introduced-error.json");
    let before = diff.clone();
    let set = RuleSet::defaults();
    let first = set.evaluate(&diff);
    let copy = set.clone();
    for _ in 0..100 {
        assert_eq!(set.evaluate(&diff), first);
        assert_eq!(copy.evaluate(&diff), first);
    }
    assert_eq!(diff, before);

    let shared = std::sync::Arc::new(set);
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let shared = std::sync::Arc::clone(&shared);
            let diff = diff.clone();
            std::thread::Builder::new()
                .spawn(move || shared.evaluate(&diff))
                .unwrap()
        })
        .collect();
    for thread in threads {
        assert_eq!(thread.join().unwrap(), first);
    }
}
