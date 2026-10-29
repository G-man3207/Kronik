//! The published JSON Schema of every command's `--json` output (M5):
//! `docs/reference/json.md`. A client command prints the API's response
//! body unchanged, so its schema is the response schema of the operation it
//! calls (`kronik_api::openapi`); `explain`, `doctor`, `init` and `build`
//! answer locally. Errors are always the stable error JSON.
//!
//! The tests check that every command is listed here and that the page is
//! current. To write it again:
//!
//! ```sh
//! KRONIK_UPDATE_DOCS=1 cargo test -p kronik --bin kronik json_output
//! ```

use std::collections::BTreeMap;
use std::fmt::Write as _;

use kronik_api::openapi::{self, Answer};
use schemars::{Schema, SchemaGenerator};
use serde_json::{Value, json};

/// Where a command's `--json` output comes from.
enum Output {
    /// The response body of API operations: `(when, method, path)`, `when`
    /// empty for the default.
    Api(&'static [(&'static str, &'static str, &'static str)]),
    /// Answered by the CLI itself.
    Local(fn(&mut SchemaGenerator) -> Schema),
    /// No `--json`: why.
    None(&'static str),
}

/// Every command, as `kronik <command>`, in the order of the CLI reference.
const COMMANDS: &[(&str, Output)] = &[
    ("serve", Output::None("the daemon; it refuses --json")),
    ("doctor", Output::Local(crate::doctor::json_schema)),
    ("restore", Output::Local(crate::restore::json_schema)),
    ("upgrade check", Output::Local(crate::upgrade::json_schema)),
    ("init", Output::Local(crate::project::init_schema)),
    ("build", Output::Local(crate::project::build_schema)),
    ("deploy", Output::Api(&[("", "POST", "/v1/deployments")])),
    (
        "deployments list",
        Output::Api(&[("", "GET", "/v1/deployments")]),
    ),
    (
        "send",
        Output::Api(&[
            ("", "POST", "/v1/actors/{kind}/{key}/messages"),
            (
                "--fork",
                "POST",
                "/v1/forks/{name}/actors/{kind}/{key}/messages",
            ),
        ]),
    ),
    ("actors list", Output::Api(&[("", "GET", "/v1/actors")])),
    (
        "actors inspect",
        Output::Api(&[("", "GET", "/v1/actors/{kind}/{key}")]),
    ),
    (
        "actors timers",
        Output::Api(&[("", "GET", "/v1/actors/{kind}/{key}/timers")]),
    ),
    (
        "history",
        Output::Api(&[
            ("", "GET", "/v1/actors/{kind}/{key}/history"),
            ("--orphans", "GET", "/v1/orphans"),
        ]),
    ),
    ("trace", Output::Api(&[("", "GET", "/v1/turns/{id}/trace")])),
    (
        "dead-letters list",
        Output::Api(&[("", "GET", "/v1/dead-letters")]),
    ),
    (
        "dead-letters resend",
        Output::Api(&[("", "POST", "/v1/dead-letters/{id}/resend")]),
    ),
    ("grant", Output::Api(&[("", "POST", "/v1/grants")])),
    ("revoke", Output::Api(&[("", "POST", "/v1/grants/revoke")])),
    ("grants list", Output::Api(&[("", "GET", "/v1/grants")])),
    ("limits set", Output::Api(&[("", "POST", "/v1/limits")])),
    ("limits show", Output::Api(&[("", "GET", "/v1/limits")])),
    (
        "secret set",
        Output::Api(&[("", "PUT", "/v1/secrets/{name}")]),
    ),
    ("secret list", Output::Api(&[("", "GET", "/v1/secrets")])),
    (
        "secret delete",
        Output::Api(&[("", "DELETE", "/v1/secrets/{name}")]),
    ),
    ("fork create", Output::Api(&[("", "POST", "/v1/forks")])),
    ("fork list", Output::Api(&[("", "GET", "/v1/forks")])),
    (
        "fork deploy",
        Output::Api(&[("", "POST", "/v1/forks/{name}/deployments")]),
    ),
    (
        "fork delete",
        Output::Api(&[("", "DELETE", "/v1/forks/{name}")]),
    ),
    (
        "replay",
        Output::Api(&[("", "POST", "/v1/forks/{name}/replay")]),
    ),
    (
        "diff show",
        Output::Api(&[
            ("a proposal", "GET", "/v1/proposals/{id}/diff"),
            ("a fork", "GET", "/v1/forks/{name}/diff"),
        ]),
    ),
    ("propose", Output::Api(&[("", "POST", "/v1/proposals")])),
    (
        "proposals list",
        Output::Api(&[("", "GET", "/v1/proposals")]),
    ),
    (
        "proposals show",
        Output::Api(&[("", "GET", "/v1/proposals/{id}")]),
    ),
    (
        "proposal status",
        Output::Api(&[("", "GET", "/v1/proposals/{id}")]),
    ),
    (
        "proposal wait",
        Output::Api(&[("", "GET", "/v1/proposals/{id}")]),
    ),
    (
        "approve",
        Output::Api(&[("", "POST", "/v1/proposals/{id}/approve")]),
    ),
    (
        "promote",
        Output::Api(&[("", "POST", "/v1/proposals/{id}/promote")]),
    ),
    (
        "rollback",
        Output::Api(&[
            ("", "POST", "/v1/deployments/{epoch}/rollback"),
            ("--by-replay", "POST", "/v1/deployments/{epoch}/rebase"),
        ]),
    ),
    (
        "watch",
        Output::Api(&[
            ("", "GET", "/v1/watches/{id}"),
            (
                "with --async or --dry-run",
                "POST",
                "/v1/deployments/{epoch}/watch",
            ),
        ]),
    ),
    ("watches list", Output::Api(&[("", "GET", "/v1/watches")])),
    (
        "watches show",
        Output::Api(&[("", "GET", "/v1/watches/{id}")]),
    ),
    (
        "watches stop",
        Output::Api(&[("", "POST", "/v1/watches/{id}/stop")]),
    ),
    ("policy show", Output::Api(&[("", "GET", "/v1/policy")])),
    ("policy set", Output::Api(&[("", "PUT", "/v1/policy")])),
    (
        "policy test",
        Output::Api(&[("", "POST", "/v1/policy/test")]),
    ),
    (
        "preview create",
        Output::Api(&[("", "POST", "/v1/previews")]),
    ),
    ("preview list", Output::Api(&[("", "GET", "/v1/previews")])),
    (
        "preview delete",
        Output::Api(&[("", "DELETE", "/v1/previews/{id}")]),
    ),
    ("token create", Output::Api(&[("", "POST", "/v1/tokens")])),
    ("token list", Output::Api(&[("", "GET", "/v1/tokens")])),
    (
        "token revoke",
        Output::Api(&[("", "POST", "/v1/tokens/{name}/revoke")]),
    ),
    ("foreign add", Output::Api(&[("", "POST", "/v1/foreign")])),
    ("foreign list", Output::Api(&[("", "GET", "/v1/foreign")])),
    (
        "foreign logs",
        Output::Api(&[("", "GET", "/v1/foreign/{name}/logs")]),
    ),
    (
        "foreign remove",
        Output::Api(&[("", "DELETE", "/v1/foreign/{name}")]),
    ),
    (
        "foreign cleanup",
        Output::Local(super::foreign::cleanup_schema),
    ),
    (
        "stubs set",
        Output::Api(&[("", "PUT", "/v1/simulators/{target}")]),
    ),
    (
        "simulators list",
        Output::Api(&[("", "GET", "/v1/simulators")]),
    ),
    (
        "privacy mode",
        Output::Api(&[("", "POST", "/v1/privacy/mode")]),
    ),
    ("privacy status", Output::Api(&[("", "GET", "/v1/privacy")])),
    (
        "privacy erase",
        Output::Api(&[("", "POST", "/v1/privacy/erase")]),
    ),
    (
        "privacy reseal",
        Output::Api(&[("", "POST", "/v1/privacy/reseal")]),
    ),
    (
        "snapshot list",
        Output::Api(&[("", "GET", "/v1/snapshots")]),
    ),
    (
        "snapshot create",
        Output::Api(&[("", "POST", "/v1/snapshots")]),
    ),
    ("integrity", Output::Api(&[("", "GET", "/v1/integrity")])),
    ("export status", Output::Api(&[("", "GET", "/v1/export")])),
    (
        "export rewind",
        Output::Api(&[("", "POST", "/v1/export/{stream}/rewind")]),
    ),
    ("audit show", Output::Api(&[("", "GET", "/v1/audit")])),
    ("audit verify", Output::Local(super::audit::verify_schema)),
    ("mcp", Output::None("MCP's JSON-RPC on stdout instead")),
    ("explain", Output::Local(explain_schema)),
];

const REF: &str = "#/components/schemas/";

/// `kronik explain --json`: a topic, or `{"topics": [...]}` with `--list`.
fn explain_schema(g: &mut SchemaGenerator) -> Schema {
    let topic = json!({
        "description": "A `kronik explain` topic.",
        "type": "object",
        "required": ["name", "kind", "title", "milestone", "text"],
        "properties": {
            "name": {"type": "string", "description": "A concept, a guide or an error code."},
            "kind": {"type": "string", "enum": ["concept", "guide", "error_code"]},
            "title": {"type": "string"},
            "http_status": {"type": "integer", "description": "Error codes only."},
            "milestone": {"type": "string"},
            "text": {"type": "string", "description": "Markdown."}
        }
    });
    let list = json!({
        "description": "`kronik explain --list`.",
        "type": "object",
        "required": ["topics"],
        "properties": {"topics": {"type": "array", "items": {"$ref": format!("{REF}Topic")}}}
    });
    g.definitions_mut().insert("Topic".into(), topic);
    g.definitions_mut().insert("TopicList".into(), list);
    to_schema(json!({"oneOf": [
        {"$ref": format!("{REF}Topic")},
        {"$ref": format!("{REF}TopicList")}
    ]}))
}

fn to_schema(v: Value) -> Schema {
    match v {
        Value::Object(map) => Schema::from(map),
        _ => Schema::default(),
    }
}

/// The schema an API operation answers with, or `None` for one that is not
/// in the API's table.
fn api_schema(g: &mut SchemaGenerator, method: &str, path: &str) -> Option<Schema> {
    let op = openapi::OPERATIONS
        .iter()
        .find(|op| op.method == method && op.path == path)?;
    Some(match &op.answer {
        Answer::Json(body) => body(g),
        Answer::Diff => openapi::diff(g),
    })
}

/// A link to a schema, by its name when it has one.
fn describe(schema: &Schema, anonymous: &mut Vec<(String, Value)>, label: &str) -> String {
    match schema.get("$ref").and_then(Value::as_str) {
        Some(r) => {
            let name = r.trim_start_matches(REF);
            format!("[`{name}`](#{})", name.to_ascii_lowercase())
        }
        None => {
            let name = format!("{label} output");
            anonymous.push((name.clone(), schema.clone().to_value()));
            format!("[{name}](#{})", anchor(&name))
        }
    }
}

/// mdBook's heading id for `text`.
fn anchor(text: &str) -> String {
    text.to_ascii_lowercase()
        .chars()
        .filter_map(|c| match c {
            'a'..='z' | '0'..='9' | '-' | '_' => Some(c),
            ' ' => Some('-'),
            _ => None,
        })
        .collect()
}

/// The names `schema` refers to, directly or through other definitions.
fn reachable(
    schema: &Value,
    defs: &serde_json::Map<String, Value>,
    out: &mut BTreeMap<String, Value>,
) {
    match schema {
        Value::Object(map) => {
            if let Some(r) = map.get("$ref").and_then(Value::as_str)
                && let Some(name) = r.strip_prefix(REF)
                && !out.contains_key(name)
                && let Some(def) = defs.get(name)
            {
                out.insert(name.to_owned(), def.clone());
                reachable(def, defs, out);
            }
            for v in map.values() {
                reachable(v, defs, out);
            }
        }
        Value::Array(items) => {
            for v in items {
                reachable(v, defs, out);
            }
        }
        _ => {}
    }
}

/// `docs/reference/json.md`.
pub(crate) fn page() -> String {
    let mut g = openapi::generator();
    let mut rows = Vec::new();
    let mut roots = Vec::new();
    let mut anonymous = Vec::new();
    for (command, output) in COMMANDS {
        let text = match output {
            Output::None(why) => format!("no JSON: {why}"),
            Output::Local(schema) => {
                let s = schema(&mut g);
                roots.push(s.clone().to_value());
                format!(
                    "{}, from the CLI itself",
                    describe(&s, &mut anonymous, command)
                )
            }
            Output::Api(ops) => {
                let mut parts = Vec::new();
                for (when, method, path) in *ops {
                    let s = api_schema(&mut g, method, path).unwrap_or_default();
                    roots.push(s.clone().to_value());
                    let link = describe(&s, &mut anonymous, &format!("kronik {command}"));
                    parts.push(if when.is_empty() {
                        format!("{link} (`{method} {path}`)")
                    } else {
                        format!("with {when}: {link} (`{method} {path}`)")
                    });
                }
                parts.join("; ")
            }
        };
        rows.push(format!("| `kronik {command}` | {text} |"));
    }
    let error = g
        .definitions()
        .get("Error")
        .cloned()
        .unwrap_or_else(|| openapi::document()["components"]["schemas"]["Error"].clone());
    let defs = g.take_definitions(true);
    let mut shown = BTreeMap::new();
    shown.insert("Error".to_owned(), error);
    for root in &roots {
        reachable(root, &defs, &mut shown);
    }
    for (_, schema) in &anonymous {
        reachable(schema, &defs, &mut shown);
    }

    let mut out = String::from(
        "# JSON output\n\n\
         <!-- Generated from crates/kronik/src/cli/schemas.rs and the API's types by\n\
         `KRONIK_UPDATE_DOCS=1 cargo test -p kronik --bin kronik json_output`.\n\
         Edit those, not this file; the test fails when it is out of date. -->\n\n\
         With `--json`, every command prints one JSON object on stdout, so a script\n\
         never parses the human output. A client command prints the JSON API's\n\
         response body unchanged, so its schema is that of the operation it calls,\n\
         as in [openapi.json](openapi.json), the OpenAPI 3.1 description that\n\
         `GET /v1/openapi.json` serves. `explain`, `doctor`, `init`, `build`,\n\
         `restore`, `upgrade check` and `audit verify` answer themselves. A\n\
         failure prints the [`Error`](#error) object instead, with exit code 1,\n\
         except `upgrade check`, which prints its report either way and exits 1\n\
         when the replay is not empty (`code` is `ENGINE_UPGRADE_DIVERGED`), and\n\
         `audit verify`, which prints its report either way and exits 1 when it\n\
         is not `complete`. The\n\
         schemas are JSON Schema 2020-12; `$ref`s name the definitions below.\n\n\
         Two bodies are not generated from types but written by hand, and also\n\
         stand alone for validators: the behavior diff,\n\
         [diff-v1.schema.json](diff-v1.schema.json) (`kronik diff show --json`,\n\
         [`Diff`](#diff) below), and the turn JSON of `GET /v1/turns/{id}`,\n\
         [turn.schema.json](turn.schema.json). Tests validate real diffs and turns\n\
         against both.\n\n\
         | Command | `--json` prints |\n| --- | --- |\n",
    );
    for row in rows {
        out.push_str(&row);
        out.push('\n');
    }
    out.push_str("\n## Schemas\n");
    for (name, schema) in anonymous
        .iter()
        .map(|(n, s)| (n.clone(), s.clone()))
        .chain(shown)
    {
        let pretty = serde_json::to_string_pretty(&schema).unwrap_or_default();
        let _ = write!(out, "\n### {name}\n\n```json\n{pretty}\n```\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use clap::CommandFactory as _;

    use super::*;

    /// Every leaf command of the binary, as `actors list`.
    fn leaves(cmd: &clap::Command, prefix: &str, out: &mut BTreeSet<String>) {
        for sub in cmd.get_subcommands() {
            if sub.is_hide_set() || sub.get_name() == "help" {
                continue;
            }
            let name = if prefix.is_empty() {
                sub.get_name().to_owned()
            } else {
                format!("{prefix} {}", sub.get_name())
            };
            if sub.has_subcommands() {
                leaves(sub, &name, out);
            } else {
                out.insert(name);
            }
        }
    }

    #[test]
    fn every_command_has_its_json_output_listed() {
        let mut commands = BTreeSet::new();
        leaves(&crate::Cli::command(), "", &mut commands);
        let listed: BTreeSet<String> = COMMANDS.iter().map(|(c, _)| (*c).to_owned()).collect();
        assert_eq!(
            commands, listed,
            "crates/kronik/src/cli/schemas.rs COMMANDS must list every command"
        );
        for (command, output) in COMMANDS {
            if let Output::Api(ops) = output {
                for (_, method, path) in *ops {
                    assert!(
                        api_schema(&mut openapi::generator(), method, path).is_some(),
                        "kronik {command}: no API operation {method} {path}"
                    );
                }
            }
        }
    }

    #[test]
    fn json_output_page_is_current() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/reference/json.md");
        let current = page();
        if std::env::var_os("KRONIK_UPDATE_DOCS").is_some() {
            std::fs::write(path, &current).unwrap();
        }
        let committed = std::fs::read_to_string(path).unwrap_or_default();
        assert!(
            committed == current,
            "docs/reference/json.md is out of date: run \
             `KRONIK_UPDATE_DOCS=1 cargo test -p kronik --bin kronik json_output`"
        );
    }
}
