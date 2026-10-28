//! The tools of the brief's MCP table. Each is an API request made as the
//! caller: the same result, or the same stable error JSON, as the CLI gets,
//! and the API checks the caller's scope. `explain` is answered here, after
//! the same check.

use std::sync::Arc;

use rmcp::ErrorData;
use rmcp::RoleServer;
use rmcp::model::{CallToolResult, JsonObject, MetaObject, Tool, ToolAnnotations};
use rmcp::service::RequestContext;
use serde_json::{Map, Value, json};

use crate::{KronikMcp, bad_request};

/// A tool, with the scope it needs.
struct Spec {
    name: &'static str,
    title: &'static str,
    scope: &'static str,
    description: &'static str,
    /// Changes something: requires `reason` (I12).
    mutates: bool,
    /// Accepts `dry_run`: check the call and change nothing.
    dry_run: bool,
    /// Switches what production runs.
    destructive: bool,
    input: fn() -> Value,
    output: fn() -> Value,
}

const TOOLS: &[Spec] = &[
    Spec {
        name: "list_actors",
        title: "List actors",
        scope: "read",
        description: "List actors in kind/key order, with their schema version, number of \
            turns, last turn id and whether they have SQL tables. To page, pass the previous \
            result's `next` as `after`.",
        mutates: false,
        dry_run: false,
        destructive: false,
        input: || {
            object(
                json!({
                    "kind": {"type": "string", "description": "Only actors of this kind."},
                    "after": {"type": "string", "description": "Start after this actor (`kind/key`): the previous result's `next`."},
                    "limit": {"type": "integer", "minimum": 1, "description": "At most this many actors."}
                }),
                &[],
            )
        },
        output: || {
            result(json!({
                "actors": {"type": "array", "items": {"type": "object", "description": "{kind, key, schema_version, turns, last_turn_id, sql}"}},
                "next": {"type": ["string", "null"], "description": "Pass as `after` for the next page; null at the end."}
            }))
        },
    },
    Spec {
        name: "inspect_actor",
        title: "Inspect an actor",
        scope: "read",
        description: "An actor's metadata, its key-value state (values as text and base64, \
            with their subject and LSN; without pii:read a sealed value reads [sealed] and the \
            subject is null) and its SQL tables with row counts.",
        mutates: false,
        dry_run: false,
        destructive: false,
        input: || object(json!({"actor": actor_property()}), &["actor"]),
        output: || {
            result(json!({
                "actor": {"type": "object"},
                "state": {"type": "array", "items": {"type": "object", "description": "{key, text, base64, subject, lsn}"}},
                "sql": {"type": "object", "description": "{tables: [{name, rows}]}"}
            }))
        },
    },
    Spec {
        name: "query_history",
        title: "Query an actor's history",
        scope: "read",
        description: "An actor's turns: turn id, LSN, logical time, code hash, input, outcome \
            with its error code, state writes, messages sent, SQL changes, effects and fuel. \
            To page, pass the previous result's `next` as `before`.",
        mutates: false,
        dry_run: false,
        destructive: false,
        input: || {
            object(
                json!({
                    "actor": actor_property(),
                    "before": {"type": "integer", "minimum": 0, "description": "Only turns before this LSN: the previous result's `next`."},
                    "limit": {"type": "integer", "minimum": 1, "description": "At most this many turns."}
                }),
                &["actor"],
            )
        },
        output: || {
            result(json!({
                "turns": {"type": "array", "items": {"type": "object"}},
                "next": {"type": ["integer", "null"], "description": "Pass as `before` for the next page; null at the end."}
            }))
        },
    },
    Spec {
        name: "trace_turn",
        title: "Trace a turn's causal tree",
        scope: "read",
        description: "A turn's causal tree: the root input that started it, the turns from \
            the root down to it (`ancestors`), and every turn it caused (`descendants`, a tree, \
            at most 1000 turns). Turn ids come from query_history, trace results and a diff's \
            `samples`; fork turns have ids such as `try:7` or `p-7h3k2a9c1d0e:r12.0`.",
        mutates: false,
        dry_run: false,
        destructive: false,
        input: || {
            object(
                json!({"turn_id": {"type": "string", "description": "The turn id, `<branch>:<lsn>`, e.g. main:42."}}),
                &["turn_id"],
            )
        },
        output: || {
            result(json!({
                "turn": {"type": "object", "description": "{turn_id, lsn, logical_time_ms, code_hash, input, outcome, ...}"},
                "actor": {"type": "string", "description": "kind/key"},
                "root": {"type": ["object", "null"], "description": "{lsn, root_id, input}; null when outside the log"},
                "ancestors": {"type": "array", "items": {"type": "object"}, "description": "From the root input down to the turn's parent."},
                "descendants": {"type": "array", "items": {"type": "object"}, "description": "{turn_id, actor, input, outcome, children}"},
                "truncated": {"type": "boolean"}
            }))
        },
    },
    Spec {
        name: "list_dead_letters",
        title: "List dead letters",
        scope: "read",
        description: "Inputs that failed and effects whose outcome is uncertain: id, actor, \
            input, error code and message, and the id of the resend if there was one.",
        mutates: false,
        dry_run: false,
        destructive: false,
        input: || {
            object(
                json!({
                    "after": {"type": "string", "description": "Start after this dead letter id."},
                    "limit": {"type": "integer", "minimum": 1, "description": "At most this many."}
                }),
                &[],
            )
        },
        output: || {
            result(json!({
                "dead_letters": {"type": "array", "items": {"type": "object", "description": "{id, actor, input, error_code, message, resent_as}"}}
            }))
        },
    },
    Spec {
        name: "create_fork",
        title: "Create a fork",
        scope: "fork",
        description: "Fork main at a point in its history. A fork makes no live effects. \
            A token without the pii:read scope always gets a fork without personal data.",
        mutates: true,
        dry_run: true,
        destructive: false,
        input: || {
            object(
                json!({
                    "at": {"type": ["integer", "string"], "description": "The fork point: an LSN, \"now\", or an RFC 3339 time."},
                    "name": {"type": "string", "description": "The fork's name; generated when omitted."},
                    "no_pii": {"type": "boolean", "description": "Fork without personal data."}
                }),
                &["at"],
            )
        },
        output: || {
            result(json!({
                "dry_run": {"type": "boolean"},
                "fork": {"type": "object", "description": "{name, fork_lsn, no_pii, proposal_id}"}
            }))
        },
    },
    Spec {
        name: "send_to_fork",
        title: "Send a message into a fork",
        scope: "fork",
        description: "Run one message against a fork's code and state, and get its outcome, \
            reply and effects. Effects are answered from recordings or denied (only a GET without \
            secrets to a host the operator allowlisted goes out), and main is untouched. \
            Messages into a fork have no dry run. A fork made without no_pii needs the pii:read \
            scope; in a no_pii fork, the values of a turn that used SQL read [sql].",
        mutates: true,
        dry_run: false,
        destructive: false,
        input: || {
            object(
                json!({
                    "fork": {"type": "string", "description": "The fork's name, from create_fork or a proposal's `fork`."},
                    "actor": actor_property(),
                    "name": {"type": "string", "minLength": 1, "description": "The message name the actor handles, e.g. increment."},
                    "text": {"type": "string", "description": "The body as text."},
                    "base64": {"type": "string", "description": "The body as base64, instead of text."},
                    "content_type": {"type": "string", "description": "application/octet-stream when omitted."},
                    "subject": {"type": "string", "description": "Whose data the body is, e.g. user:123."}
                }),
                &["fork", "actor", "name"],
            )
        },
        output: || {
            result(json!({
                "fork": {"type": "string"},
                "turn_id": {"type": "string"},
                "outcome": {"type": "object", "description": "{kind: committed | failed, error_code, message}"},
                "reply": {"type": ["object", "null"], "description": "{content_type, text, base64}"},
                "effects": {"type": "array", "items": {"type": "object", "description": "{kind, target, delivery, status, error_code}"}}
            }))
        },
    },
    Spec {
        name: "propose_change",
        title: "Propose a change",
        scope: "propose",
        description: "Propose new code: Kronik forks, replays the window's real root inputs \
            through the component and evaluates the policy against the behavior diff. Pass the \
            components of every actor kind the change touches in one list: they are replayed \
            together in one fork, the diff reports each kind under `kinds`, and promote and \
            rollback switch them as one. A component whose code already runs is skipped and \
            listed in `proposal.unchanged`. Returns the proposal with its diff summary and policy \
            outcome, and in `next` the exact commands that follow: a human runs `kronik approve` \
            when the policy requires approval. Without pii:read, turns that ran on pseudonyms are \
            counted in `summary.pii_masked` (differing) and `summary.pii_unverified` (identical, of \
            changed code): they are not verified, so the policy then requires approval (rule \
            pii-masked-needs-approval).",
        mutates: true,
        dry_run: true,
        destructive: false,
        input: || {
            object(
                json!({
                    "wasm_base64": {
                        "description": "The component (.wasm), base64: one, or a list with one per actor kind of the change.",
                        "oneOf": [
                            {"type": "string", "minLength": 1},
                            {"type": "array", "minItems": 1, "items": {"type": "string", "minLength": 1}}
                        ]
                    },
                    "window_ms": {"type": "integer", "minimum": 1, "description": "How much logical time back from HEAD to replay; one hour when omitted."},
                    "at": {"type": ["integer", "null"], "description": "Replay from this LSN instead of a window."},
                    "mode": {"type": "string", "enum": ["isolated", "continuous", "both"], "description": "Replay mode; both when omitted."},
                    "sample": {"type": "number", "exclusiveMinimum": 0, "maximum": 1, "description": "The share of root inputs replayed in isolation; 1.0 when omitted."},
                    "ignore_headers": {"type": "array", "items": {"type": "string"}, "description": "Response headers the diff ignores."},
                    "ignore_json_paths": {"type": "array", "items": {"type": "string"}, "description": "JSON paths in bodies the diff ignores, such as $.requestId."}
                }),
                &["wasm_base64"],
            )
        },
        output: || {
            result(json!({
                "dry_run": {"type": "boolean"},
                "proposal": {"type": "object", "description": "{id, fork, status, verified_through_lsn, diff_hash, policy: {outcome, fired, errors}, summary, kinds, unchanged}"},
                "next": {"type": "array", "items": {"type": "string"}, "description": "The exact commands that follow, in order."}
            }))
        },
    },
    Spec {
        name: "get_diff",
        title: "Get a behavior diff",
        scope: "read",
        description: "The whole behavior diff (kronik.diff/v1) of a proposal or a fork: \
            summary, each actor kind on its own, causes, grounding per target, responses, \
            effects, state, errors, resources and sample turn ids.",
        mutates: false,
        dry_run: false,
        destructive: false,
        input: || {
            let mut schema = object(
                json!({
                    "proposal": {"type": "string", "description": "A proposal id."},
                    "fork": {"type": "string", "description": "A fork name."}
                }),
                &[],
            );
            schema["oneOf"] = json!([{"required": ["proposal"]}, {"required": ["fork"]}]);
            schema
        },
        output: || {
            result(json!({
                "schema": {"type": "string", "const": "kronik.diff/v1"},
                "summary": {"type": "object"},
                "grounding": {"type": "array", "items": {"type": "object"}}
            }))
        },
    },
    Spec {
        name: "request_approval",
        title: "Ask a human to approve a proposal",
        scope: "propose",
        description: "Record a pending request for a human's approval of a proposal, with your \
            reason as the evidence. Returns `request.command`, the exact command the human runs \
            to approve; give it to them with the proposal id and a summary of the diff.",
        mutates: true,
        dry_run: true,
        destructive: false,
        input: || {
            object(
                json!({"proposal": {"type": "string", "description": "The proposal id, e.g. p-7h3k2a9c1d0e."}}),
                &["proposal"],
            )
        },
        output: || {
            result(json!({
                "dry_run": {"type": "boolean"},
                "request": {"type": "object", "description": "{proposal_id, diff_hash, verified_through_lsn, lsn, command}"}
            }))
        },
    },
    Spec {
        name: "promote",
        title: "Promote a proposal",
        scope: "promote",
        description: "Switch production to a proposal's code. Catch-up runs first: traffic \
            since the proposal goes through the new code and the policy is evaluated again.",
        mutates: true,
        dry_run: true,
        destructive: true,
        input: || {
            object(
                json!({"proposal": {"type": "string", "description": "The proposal id."}}),
                &["proposal"],
            )
        },
        output: || {
            result(json!({
                "dry_run": {"type": "boolean"},
                "deployment": {"type": "object", "description": "{epoch, lsn, effective_lsn, verified_through_lsn, unverified_inputs, kinds}"},
                "policy": {"type": "object", "description": "{outcome, fired, errors}"}
            }))
        },
    },
    Spec {
        name: "rollback",
        title: "Roll back a deployment",
        scope: "promote",
        description: "Switch back to the code that ran before a deployment. With `by_replay` \
            (a deployment that migrated state), instead create a rollback via replay: a rebase \
            proposal `r-...` whose diff shows the old code's state and the irreversible effects \
            (needs the `propose` and `pii:read` scopes: it replays on full data); a human \
            approves it, then `promote` switches main.",
        mutates: true,
        dry_run: true,
        destructive: true,
        input: || {
            object(
                json!({
                    "deployment": {"type": "integer", "minimum": 0, "description": "The deployment's epoch."},
                    "by_replay": {"type": "boolean", "description": "Roll back via replay (kronik rollback --by-replay)."},
                    "mode": {"type": "string", "enum": ["continuous", "both"], "description": "With by_replay: the replay mode (default continuous)."},
                    "threads": {"type": "integer", "minimum": 1, "description": "With by_replay: replay workers."}
                }),
                &["deployment"],
            )
        },
        output: || {
            result(json!({
                "dry_run": {"type": "boolean"},
                "deployment": {"type": "object"},
                "proposal": {"type": "object", "description": "With by_replay: the rebase proposal, with `rebase` {rolled_back_epoch, base_lsn, irreversible_effects}."}
            }))
        },
    },
    Spec {
        name: "explain",
        title: "Explain a concept or an error code",
        scope: "read",
        description: "Kronik's built-in documentation, as `kronik explain`: a concept such as \
            `fork` or `causal-key`, an error code such as `POLICY_DENIED`, or `agent`, the \
            agent guide (also the resource kronik://agent-guide). Without a topic, lists every \
            topic.",
        mutates: false,
        dry_run: false,
        destructive: false,
        input: || {
            object(
                json!({
                    "topic": {"type": "string", "description": "A concept or an error code; omit to list the topics."}
                }),
                &[],
            )
        },
        output: || {
            result(json!({
                "topics": {"type": "array", "items": {"type": "object"}, "description": "Every topic, when no topic was given."},
                "name": {"type": "string"},
                "kind": {"type": "string", "enum": ["concept", "guide", "error_code"]},
                "title": {"type": "string"},
                "http_status": {"type": "integer"},
                "milestone": {"type": "string"},
                "text": {"type": "string", "description": "The explanation, in Markdown."}
            }))
        },
    },
];

/// The `actor` argument.
fn actor_property() -> Value {
    json!({"type": "string", "pattern": "^[^/]+/.+$", "description": "The actor as `kind/key`."})
}

/// An input schema: an object with these properties.
fn object(properties: Value, required: &[&str]) -> Value {
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false
    })
}

/// An output schema: the API's response, or the stable error JSON.
fn result(mut properties: Value) -> Value {
    properties["error"] = json!({
        "type": "object",
        "description": "Instead of the result when the call failed: the stable error, as from the API and the CLI.",
        "properties": {
            "code": {"type": "string", "description": "Stable; see the error catalog resource or explain."},
            "message": {"type": "string"},
            "hint": {"type": "string", "description": "What to do next, often the exact command."},
            "docs": {"type": "string"}
        },
        "required": ["code", "message"]
    });
    json!({"type": "object", "properties": properties})
}

fn json_object(value: Value) -> Arc<JsonObject> {
    match value {
        Value::Object(map) => Arc::new(map),
        _ => Arc::new(JsonObject::new()),
    }
}

/// Every tool, with its schemas and its scope in `_meta`.
pub(crate) fn list() -> Vec<Tool> {
    TOOLS
        .iter()
        .map(|spec| {
            let mut input = (spec.input)();
            if spec.mutates {
                input["properties"]["reason"] = json!({
                    "type": "string",
                    "minLength": 1,
                    "description": "Why: recorded with the change, with your token id."
                });
                if let Some(required) = input["required"].as_array_mut() {
                    required.push(json!("reason"));
                }
            }
            if spec.dry_run {
                input["properties"]["dry_run"] = json!({
                    "type": "boolean",
                    "description": "Return what would be done, and write nothing."
                });
            }
            let mut meta = JsonObject::new();
            meta.insert("kronik/scope".into(), json!(spec.scope));
            let annotations = ToolAnnotations::with_title(spec.title)
                .read_only(!spec.mutates)
                .destructive(spec.destructive)
                .idempotent(!spec.mutates)
                .open_world(false);
            Tool::new(
                spec.name,
                format!("{} Requires the `{}` scope.", spec.description, spec.scope),
                json_object(input),
            )
            .with_title(spec.title)
            .with_raw_output_schema(json_object((spec.output)()))
            .with_annotations(annotations)
            .with_meta(MetaObject(meta))
        })
        .collect()
}

/// Runs a tool. An unknown tool is a protocol error; anything the call
/// itself rejects is a tool result with `isError` and the stable error JSON.
pub(crate) async fn call(
    mcp: &KronikMcp,
    context: &RequestContext<RoleServer>,
    name: &str,
    args: Map<String, Value>,
) -> Result<CallToolResult, ErrorData> {
    let Some(spec) = TOOLS.iter().find(|spec| spec.name == name) else {
        return Err(ErrorData::invalid_params(format!("no tool {name:?}"), None));
    };
    let args = Args(args);
    let request = match spec.name {
        "list_actors" => args
            .query(&["kind", "after", "limit"])
            .map(|q| Request::get("/v1/actors".into(), q)),
        "inspect_actor" => args
            .actor()
            .map(|(kind, key)| Request::get(format!("/v1/actors/{kind}/{key}"), String::new())),
        "query_history" => args.actor().and_then(|(kind, key)| {
            let q = args.query(&["before", "limit"])?;
            Ok(Request::get(format!("/v1/actors/{kind}/{key}/history"), q))
        }),
        "trace_turn" => args
            .segment("turn_id")
            .map(|id| Request::get(format!("/v1/turns/{id}/trace"), String::new())),
        "list_dead_letters" => args
            .query(&["after", "limit"])
            .map(|q| Request::get("/v1/dead-letters".into(), q)),
        "create_fork" => Ok(args.post("/v1/forks".into(), &["at", "name", "no_pii"])),
        "send_to_fork" => args.segment("fork").and_then(|fork| {
            let (kind, key) = args.actor()?;
            Ok(args.post(
                format!("/v1/forks/{fork}/actors/{kind}/{key}/messages"),
                &["name", "text", "base64", "content_type", "subject"],
            ))
        }),
        "propose_change" => args.propose(),
        "get_diff" => args.diff(),
        "request_approval" => args
            .segment("proposal")
            .map(|id| args.post(format!("/v1/proposals/{id}/request-approval"), &[])),
        "promote" => args
            .segment("proposal")
            .map(|id| args.post(format!("/v1/proposals/{id}/promote"), &[])),
        "rollback" => match args.0.get("deployment").and_then(Value::as_u64) {
            Some(epoch) if args.0.get("by_replay").and_then(Value::as_bool) == Some(true) => {
                Ok(args.post(
                    format!("/v1/deployments/{epoch}/rebase"),
                    &["mode", "threads"],
                ))
            }
            Some(epoch) => Ok(args.post(format!("/v1/deployments/{epoch}/rollback"), &[])),
            None => Err(bad_request(
                "`deployment` must be a deployment epoch (an integer)",
                "List the deployments with `kronik deployments list` or the kronik://config resource.",
            )),
        },
        "explain" => {
            return Ok(match mcp.refused(context, spec.scope)? {
                Some(error) => CallToolResult::structured_error(error),
                None => explain(&args),
            });
        }
        _ => {
            return Err(ErrorData::internal_error(
                format!("tool {name:?} has no handler"),
                None,
            ));
        }
    };
    let request = match request {
        Ok(request) => request,
        Err(error) => return Ok(CallToolResult::structured_error(error)),
    };
    let response = mcp
        .api(
            context,
            request.method,
            &request.path,
            request.query,
            request.body,
        )
        .await?;
    let value = serde_json::from_slice(&response.body)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&response.body).into_owned()));
    if response.status >= 400 {
        return Ok(CallToolResult::structured_error(value));
    }
    Ok(CallToolResult::structured(match spec.name {
        "propose_change" => with_next_commands(value),
        _ => value,
    }))
}

/// An API request a tool makes.
struct Request {
    method: &'static str,
    path: String,
    query: String,
    body: Vec<u8>,
}

impl Request {
    fn get(path: String, query: String) -> Request {
        Request {
            method: "GET",
            path,
            query,
            body: Vec::new(),
        }
    }
}

/// A tool's arguments.
struct Args(Map<String, Value>);

impl Args {
    /// A query string of the given arguments that are present.
    fn query(&self, keys: &[&str]) -> Result<String, Value> {
        let mut pairs = Vec::new();
        for key in keys {
            match self.0.get(*key) {
                None | Some(Value::Null) => {}
                Some(Value::String(s)) => pairs.push(format!("{key}={}", encode(s))),
                Some(Value::Number(n)) => pairs.push(format!("{key}={n}")),
                Some(_) => {
                    return Err(bad_request(
                        format!("`{key}` must be a string or a number"),
                        "See the tool's input schema.",
                    ));
                }
            }
        }
        Ok(pairs.join("&"))
    }

    /// A required string argument, encoded as a path segment.
    fn segment(&self, key: &str) -> Result<String, Value> {
        match self.0.get(key) {
            Some(Value::String(s)) if !s.is_empty() => Ok(encode(s)),
            _ => Err(bad_request(
                format!("`{key}` is required and must be a non-empty string"),
                "See the tool's input schema.",
            )),
        }
    }

    /// The `actor` argument, `kind/key`, as two path segments.
    fn actor(&self) -> Result<(String, String), Value> {
        let actor = self
            .0
            .get("actor")
            .and_then(Value::as_str)
            .unwrap_or_default();
        match actor.split_once('/') {
            Some((kind, key)) if !kind.is_empty() && !key.is_empty() => {
                Ok((encode(kind), encode(key)))
            }
            _ => Err(bad_request(
                format!("`actor` must be `kind/key`, got {actor:?}"),
                "List the actors with the list_actors tool.",
            )),
        }
    }

    /// A mutation: the given arguments plus `reason` and `dry_run`, as JSON.
    /// An absent reason is sent empty, so that the API answers with its
    /// `REASON_REQUIRED` rather than a generic malformed-body error.
    fn post(&self, path: String, keys: &[&str]) -> Request {
        let mut body: Map<String, Value> = keys
            .iter()
            .chain(&["reason", "dry_run"])
            .filter_map(|key| Some((key.to_string(), self.0.get(*key)?.clone())))
            .collect();
        body.entry("reason").or_insert_with(|| json!(""));
        Request {
            method: "POST",
            path,
            query: String::new(),
            body: Value::Object(body).to_string().into_bytes(),
        }
    }

    fn propose(&self) -> Result<Request, Value> {
        let mut request = self.post(
            "/v1/proposals".into(),
            &[
                "window_ms",
                "at",
                "mode",
                "sample",
                "ignore_headers",
                "ignore_json_paths",
            ],
        );
        let wasm = match self.0.get("wasm_base64") {
            Some(Value::String(one)) => json!([one]),
            Some(Value::Array(list)) => Value::Array(list.clone()),
            _ => {
                return Err(bad_request(
                    "`wasm_base64` is required: the component as base64, or a list of them",
                    "Build the component with `kronik build` and pass dist/<name>.wasm as base64.",
                ));
            }
        };
        let mut body: Map<String, Value> =
            serde_json::from_slice(&request.body).unwrap_or_default();
        body.insert("wasm_base64".into(), wasm);
        request.body = Value::Object(body).to_string().into_bytes();
        Ok(request)
    }

    fn diff(&self) -> Result<Request, Value> {
        let (kind, key) = match (self.0.get("proposal"), self.0.get("fork")) {
            (Some(_), None) => ("proposals", "proposal"),
            (None, Some(_)) => ("forks", "fork"),
            _ => {
                return Err(bad_request(
                    "give exactly one of `proposal` and `fork`",
                    "See the tool's input schema.",
                ));
            }
        };
        let id = self.segment(key)?;
        Ok(Request::get(
            format!("/v1/{kind}/{id}/diff"),
            "format=json".into(),
        ))
    }
}

/// Percent-encodes everything but unreserved characters, for a path segment
/// or a query value.
fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A proposal with `next`: the exact commands that follow its policy outcome.
fn with_next_commands(mut value: Value) -> Value {
    let id = value["proposal"]["id"].as_str().map(str::to_owned);
    let outcome = value["proposal"]["policy"]["outcome"]
        .as_str()
        .map(str::to_owned);
    let next = match (id, outcome) {
        (Some(id), Some(outcome)) => {
            let mut next = vec![format!("kronik diff show {id} --md")];
            match outcome.as_str() {
                "allow" => next.push(format!("kronik promote {id} --reason '...'")),
                "require_approval" => {
                    let summary = &value["proposal"]["summary"];
                    let masked = ["pii_masked", "pii_unverified"]
                        .iter()
                        .map(|k| summary[*k].as_u64().unwrap_or(0))
                        .sum::<u64>();
                    next.push(if masked > 0 {
                        // A shell comment: the command still runs as given.
                        format!(
                            "kronik approve {id} --reason '...'  # {masked} pii-masked turns were not verified: re-run the proposal with a pii:read token first"
                        )
                    } else {
                        format!("kronik approve {id} --reason '...'")
                    });
                    next.push(format!("kronik promote {id} --reason '...'"));
                }
                _ => {}
            }
            next
        }
        _ => Vec::new(),
    };
    if let Value::Object(map) = &mut value {
        map.insert("next".into(), json!(next));
    }
    value
}

/// The `explain` tool: `kronik explain`, in-process.
fn explain(args: &Args) -> CallToolResult {
    let Some(topic) = args.0.get("topic").and_then(Value::as_str) else {
        let topics: Vec<_> = kronik_core::explain::list().collect();
        return CallToolResult::structured(json!({ "topics": topics }));
    };
    match kronik_core::explain::lookup(topic) {
        Some(found) => CallToolResult::structured(json!(found)),
        None => CallToolResult::structured_error(bad_request(
            format!("no topic {topic:?}"),
            "Call explain without a topic to list them, or run `kronik explain --list`.",
        )),
    }
}
