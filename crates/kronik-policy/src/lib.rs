//! Policy: rules in CEL evaluated against behavior diffs (`kronik.diff/v1`).
//!
//! A rule set is a TOML file, set with `kronik policy set rules.toml`:
//!
//! ```toml
//! [[rule]]
//! name = "payments-must-be-exact"      # unique, [a-z0-9-]+
//! when = "diff.grounding.exists(t, t.host.endsWith('payments.internal') && t.approximate + t.synthetic > 0)"
//! action = "require_approval"         # allow | require_approval | deny
//! ```
//!
//! [`RuleSet::evaluate`] binds a diff to the variable `diff` and evaluates
//! every rule; the outcome is the strictest action among the rules that fire.
//! The contract is `docs/design/m3-fork.md` §7. ADR 0007 records the CEL
//! engine, the limits on a `when` ([`MAX_WHEN_BYTES`], [`MAX_WHEN_NESTING`],
//! [`MAX_WHEN_DEPTH`], no map literals) and how evaluation is kept
//! deterministic.

mod expr;
mod json;

pub use expr::{MAX_WHEN_BYTES, MAX_WHEN_DEPTH, MAX_WHEN_NESTING};

use expr::Expr;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::sync::{Arc, LazyLock};

/// What a rule asks for when it fires. Ordered from the most lenient to the
/// strictest: `Allow < RequireApproval < Deny`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    RequireApproval,
    Deny,
}

impl Action {
    /// The name in rules files and JSON: `allow`, `require_approval`, `deny`.
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::RequireApproval => "require_approval",
            Action::Deny => "deny",
        }
    }

    fn from_name(name: &str) -> Option<Action> {
        [Action::Allow, Action::RequireApproval, Action::Deny]
            .into_iter()
            .find(|action| action.as_str() == name)
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A rule: when the CEL expression `when` is true for a diff, the rule fires
/// with `action`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub when: String,
    pub action: Action,
}

/// Rules, evaluated in order. Made by [`RuleSet::parse_toml`] or
/// [`RuleSet::defaults`], which compile every `when` once.
#[derive(Clone)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
    /// The `when` of each rule compiled, with the text it was compiled from:
    /// a rule changed after parsing is compiled again when evaluated.
    compiled: Vec<(String, Arc<Expr>)>,
}

/// A rule that fired, with the action it counts with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fired {
    pub name: String,
    pub action: Action,
    /// Why, for a rule of the code rather than of the rule set
    /// ([`PII_MASKED_RULE`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The floor under every rule set (ADR 0031): a diff with turns that ran on
/// pseudonyms (`summary.pii_masked + summary.pii_unverified > 0`) needs at
/// least an approval, since a run on pseudonyms cannot tell broken code
/// from correct code. It is code, not a rule, so no `policy set` drops it.
pub const PII_MASKED_RULE: &str = "pii-masked-needs-approval";

/// A rule whose expression could not be evaluated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleError {
    pub name: String,
    pub message: String,
}

/// The result of evaluating a rule set against a diff. Serializes as
/// `{"outcome", "fired": [{"name", "action", "reason"?}], "errors": [{"name", "message"}]}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evaluation {
    /// The strictest action in `fired`; `allow` when nothing fired.
    pub outcome: Action,
    /// The rules that fired, in rule order, then [`PII_MASKED_RULE`] when
    /// it applies.
    pub fired: Vec<Fired>,
    /// The rules that could not be evaluated, in rule order. Each also counts
    /// as fired, with at least `require_approval`.
    pub errors: Vec<RuleError>,
}

/// A rules file that can't be used. The API reports it as `BAD_REQUEST`.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{}{}", rule_prefix(.name), .message)]
pub struct PolicyError {
    /// The rule the error is about, as named in the file, when it has a name.
    pub name: Option<String>,
    pub message: String,
}

fn rule_prefix(name: &Option<String>) -> String {
    name.as_ref()
        .map(|name| format!("rule `{name}`: "))
        .unwrap_or_default()
}

impl PolicyError {
    fn file(message: impl Into<String>) -> Self {
        Self {
            name: None,
            message: message.into(),
        }
    }

    fn rule(name: &str, message: impl Into<String>) -> Self {
        Self {
            name: Some(name.to_owned()),
            message: message.into(),
        }
    }
}

/// The default rules, which apply while no `Policy` record exists: the
/// brief's six rules, verbatim. [`RuleSet::defaults`] is this file parsed.
pub const DEFAULT_RULES_TOML: &str = r#"[[rule]]
name = "no-new-errors"
when = "diff.errors.introduced > 0"
action = "deny"

[[rule]]
name = "no-new-orphans"
when = "diff.errors.new_orphans > 0"
action = "require_approval"

[[rule]]
name = "low-grounding-needs-approval"
when = "diff.summary.confidence < 0.9"
action = "require_approval"

[[rule]]
name = "payments-must-be-exact"
when = "diff.grounding.exists(t, t.host.endsWith('payments.internal') && t.approximate + t.synthetic > 0)"
action = "require_approval"

[[rule]]
name = "payments-full-coverage"
when = "diff.summary.sample < 1.0 && diff.grounding.exists(t, t.host.endsWith('payments.internal'))"
action = "deny"

[[rule]]
name = "fuel-regression"
when = "diff.resources.fuel_p99_change > 0.5"
action = "deny"
"#;

/// [`DEFAULT_RULES_TOML`] as data; a test checks that the two agree.
const DEFAULT_RULES: [(&str, &str, Action); 6] = [
    ("no-new-errors", "diff.errors.introduced > 0", Action::Deny),
    (
        "no-new-orphans",
        "diff.errors.new_orphans > 0",
        Action::RequireApproval,
    ),
    (
        "low-grounding-needs-approval",
        "diff.summary.confidence < 0.9",
        Action::RequireApproval,
    ),
    (
        "payments-must-be-exact",
        "diff.grounding.exists(t, t.host.endsWith('payments.internal') && t.approximate + t.synthetic > 0)",
        Action::RequireApproval,
    ),
    (
        "payments-full-coverage",
        "diff.summary.sample < 1.0 && diff.grounding.exists(t, t.host.endsWith('payments.internal'))",
        Action::Deny,
    ),
    (
        "fuel-regression",
        "diff.resources.fuel_p99_change > 0.5",
        Action::Deny,
    ),
];

static DEFAULTS: LazyLock<RuleSet> = LazyLock::new(|| {
    let rules: Vec<Rule> = DEFAULT_RULES
        .iter()
        .map(|&(name, when, action)| Rule {
            name: name.to_owned(),
            when: when.to_owned(),
            action,
        })
        .collect();
    // Tested to compile. A rule that did not would be compiled again, and
    // fail, at every evaluation: it would fire, never be skipped.
    let compiled = rules
        .iter()
        .filter_map(|rule| Some((rule.when.clone(), Arc::new(Expr::compile(&rule.when).ok()?))))
        .collect();
    RuleSet { rules, compiled }
});

impl RuleSet {
    /// Parses a rules file: `[[rule]]` tables with exactly `name`, `when` and
    /// `action`. Names are unique and match `[a-z0-9-]+`; every `when` is
    /// compiled, so a CEL syntax error is an error here.
    pub fn parse_toml(text: &str) -> Result<RuleSet, PolicyError> {
        let file: toml::Table =
            toml::from_str(text).map_err(|e| PolicyError::file(toml_error(text, &e)))?;
        if let Some(key) = file.keys().find(|key| *key != "rule") {
            return Err(PolicyError::file(format!(
                "unknown key `{key}`: a rules file has only [[rule]] tables"
            )));
        }
        let entries = match file.get("rule") {
            None => &[][..],
            Some(toml::Value::Array(entries)) => entries.as_slice(),
            Some(_) => {
                return Err(PolicyError::file(
                    "`rule` must be an array of tables ([[rule]])",
                ));
            }
        };
        let mut rules = Vec::with_capacity(entries.len());
        let mut compiled = Vec::with_capacity(entries.len());
        let mut names = BTreeSet::new();
        for (index, entry) in entries.iter().enumerate() {
            let number = index + 1;
            let toml::Value::Table(table) = entry else {
                return Err(PolicyError::file(format!("rule {number} is not a table")));
            };
            let name = match table.get("name") {
                Some(toml::Value::String(name)) => name.as_str(),
                Some(_) => {
                    return Err(PolicyError::file(format!(
                        "rule {number}: `name` must be a string"
                    )));
                }
                None => return Err(PolicyError::file(format!("rule {number} has no `name`"))),
            };
            if let Some(key) = table
                .keys()
                .find(|key| !matches!(key.as_str(), "name" | "when" | "action"))
            {
                return Err(PolicyError::rule(
                    name,
                    format!("unknown key `{key}`: a rule has only `name`, `when` and `action`"),
                ));
            }
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return Err(PolicyError::rule(
                    name,
                    "invalid name: use lowercase letters, digits and `-` ([a-z0-9-]+)",
                ));
            }
            if !names.insert(name) {
                return Err(PolicyError::rule(
                    name,
                    "duplicate name: an earlier rule has the same name",
                ));
            }
            let when = string_field(table, name, "when")?;
            let action = string_field(table, name, "action")?;
            let action = Action::from_name(action).ok_or_else(|| {
                PolicyError::rule(
                    name,
                    format!("unknown action `{action}`: use allow, require_approval or deny"),
                )
            })?;
            let expr = Expr::compile(when)
                .map_err(|message| PolicyError::rule(name, format!("invalid `when`: {message}")))?;
            compiled.push((when.to_owned(), Arc::new(expr)));
            rules.push(Rule {
                name: name.to_owned(),
                when: when.to_owned(),
                action,
            });
        }
        Ok(RuleSet { rules, compiled })
    }

    /// The default rules ([`DEFAULT_RULES_TOML`]), which apply while no
    /// `Policy` record exists.
    pub fn defaults() -> RuleSet {
        DEFAULTS.clone()
    }

    /// Evaluates every rule against `diff`, in order. A rule fires when its
    /// expression is true; a rule whose expression can't be evaluated fires
    /// with at least `require_approval` and is listed in `errors`. Then the
    /// floor: [`PII_MASKED_RULE`] fires with `require_approval` when
    /// `summary.pii_masked + summary.pii_unverified > 0`, whatever the rules.
    /// Pure: the same rules and diff always give the same evaluation.
    pub fn evaluate(&self, diff: &serde_json::Value) -> Evaluation {
        let mut fired = Vec::new();
        let mut errors = Vec::new();
        for (index, rule) in self.rules.iter().enumerate() {
            let result = match self.compiled.get(index) {
                Some((when, expr)) if *when == rule.when => expr.eval(diff),
                _ => Expr::compile(&rule.when)
                    .map_err(|message| format!("invalid `when`: {message}"))
                    .and_then(|expr| expr.eval(diff)),
            };
            match result {
                Ok(false) => {}
                Ok(true) => fired.push(Fired {
                    name: rule.name.clone(),
                    action: rule.action,
                    reason: None,
                }),
                Err(message) => {
                    fired.push(Fired {
                        name: rule.name.clone(),
                        action: rule.action.max(Action::RequireApproval),
                        reason: None,
                    });
                    errors.push(RuleError {
                        name: rule.name.clone(),
                        message,
                    });
                }
            }
        }
        let count = |key: &str| {
            diff.pointer(&format!("/summary/{key}"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
        };
        // Differing and identical turns on pseudonyms: neither ran on the
        // real values.
        let masked = count("pii_masked").saturating_add(count("pii_unverified"));
        if masked > 0 {
            fired.push(Fired {
                name: PII_MASKED_RULE.to_owned(),
                action: Action::RequireApproval,
                reason: Some(format!(
                    "{masked} {} could not be verified without personal data; re-run the \
                     proposal with a pii:read token to see their real behaviour",
                    if masked == 1 { "turn" } else { "turns" }
                )),
            });
        }
        let outcome = fired
            .iter()
            .map(|f| f.action)
            .max()
            .unwrap_or(Action::Allow);
        Evaluation {
            outcome,
            fired,
            errors,
        }
    }
}

impl PartialEq for RuleSet {
    fn eq(&self, other: &Self) -> bool {
        self.rules == other.rules
    }
}

impl Eq for RuleSet {}

impl fmt::Debug for RuleSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleSet")
            .field("rules", &self.rules)
            .finish_non_exhaustive()
    }
}

/// The string at `key` of the rule `name`.
fn string_field<'t>(table: &'t toml::Table, name: &str, key: &str) -> Result<&'t str, PolicyError> {
    match table.get(key) {
        Some(toml::Value::String(value)) => Ok(value),
        Some(_) => Err(PolicyError::rule(name, format!("`{key}` must be a string"))),
        None => Err(PolicyError::rule(name, format!("missing `{key}`"))),
    }
}

/// A TOML syntax error on one line, with its position.
fn toml_error(text: &str, error: &toml::de::Error) -> String {
    let Some(span) = error.span() else {
        return format!("invalid TOML: {}", error.message());
    };
    let before = text.get(..span.start).unwrap_or(text);
    let line_start = before.rfind('\n').map_or(0, |i| i + 1);
    format!(
        "invalid TOML at line {}, column {}: {}",
        before.matches('\n').count() + 1,
        before[line_start..].chars().count() + 1,
        error.message()
    )
}
