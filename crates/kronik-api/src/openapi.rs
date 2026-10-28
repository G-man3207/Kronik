//! The OpenAPI 3.1 description of `/v1`: every operation with its scope,
//! parameters, request body and response, and the JSON Schema (2020-12) of
//! every type, generated with schemars from the types the handlers use.
//! `GET /v1/openapi.json` serves it, and `docs/reference/openapi.json` is the
//! committed copy:
//!
//! ```sh
//! cargo run -p kronik-api --example openapi > docs/reference/openapi.json
//! ```
//!
//! Tests keep both honest: the committed file must equal [`document`], and
//! every route the router dispatches must be in [`OPERATIONS`] and the
//! other way round.

use kronik_core::error::ErrorCode;
use schemars::generate::SchemaSettings;
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde_json::{Map, Value, json};

use crate::m7::*;
use crate::privacy::*;
use crate::types::*;

/// A body's schema, from the shared generator: a `$ref` for a named type.
pub type Body = fn(&mut SchemaGenerator) -> Schema;

/// A query parameter.
pub struct Param {
    pub name: &'static str,
    /// `string`, `integer` or `boolean`.
    pub kind: &'static str,
    pub description: &'static str,
}

/// What an operation answers with.
pub enum Answer {
    /// JSON of this schema.
    Json(Body),
    /// A behavior diff: `kronik.diff/v1` JSON, or Markdown with
    /// `format=md`.
    Diff,
}

/// One `/v1` operation.
pub struct Operation {
    pub method: &'static str,
    /// The path, with `{name}` for a path parameter.
    pub path: &'static str,
    pub summary: &'static str,
    pub query: &'static [Param],
    pub request: Option<Body>,
    pub answer: Answer,
}

fn schema<T: JsonSchema>(g: &mut SchemaGenerator) -> Schema {
    g.subschema_for::<T>()
}

/// JSON with no fixed type: this document.
fn any_object(_: &mut SchemaGenerator) -> Schema {
    object(json!({"type": "object"}))
}

fn object(v: Value) -> Schema {
    match v {
        Value::Object(map) => Schema::from(map),
        _ => Schema::default(),
    }
}

/// Registers `schema` as the component `name` and refers to it.
fn define(g: &mut SchemaGenerator, name: &str, schema: Value) -> Schema {
    g.definitions_mut().insert(name.to_owned(), schema);
    Schema::new_ref(format!("#/components/schemas/{name}"))
}

/// A policy evaluation (docs/design/m3-fork.md §7), as
/// `kronik_policy::Evaluation` serializes it.
pub fn policy_evaluation(g: &mut SchemaGenerator) -> Schema {
    let action = json!({"type": "string", "enum": ["allow", "require_approval", "deny"]});
    define(
        g,
        "PolicyEvaluation",
        json!({
            "description": "The policy's verdict on a behavior diff.",
            "type": "object",
            "required": ["outcome", "fired", "errors"],
            "properties": {
                "outcome": {
                    "description": "The strictest action among the rules that fired; allow when none did.",
                    "allOf": [action]
                },
                "fired": {
                    "description": "The rules that fired, in rule order, then pii-masked-needs-approval (a floor in code, ADR 0031) when the diff has pii-masked turns.",
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["name", "action"],
                        "properties": {
                            "name": {"type": "string"},
                            "action": action,
                            "reason": {"type": "string", "description": "Why, for the floor in code; absent for rules."}
                        }
                    }
                },
                "errors": {
                    "description": "Rules that could not be evaluated; each also counts as fired, with at least require_approval.",
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["name", "message"],
                        "properties": {"name": {"type": "string"}, "message": {"type": "string"}}
                    }
                }
            }
        }),
    )
}

/// The JSON Schema of `kronik.diff/v1` (docs/design/m3-fork.md §5), written
/// by hand: the diff is built by `kronik_fork::diff`, not from API types.
pub const DIFF_SCHEMA: &str = include_str!("../../../docs/reference/diff-v1.schema.json");

/// The JSON Schema of the turn JSON of `GET /v1/turns/{id}`, written by hand:
/// the handler renders the log's turn record.
pub const TURN_SCHEMA: &str = include_str!("../../../docs/reference/turn.schema.json");

/// Registers a schema file as the component `name`, and each of its
/// `$defs` as a component of its own (the files name them uniquely), with
/// `#/$defs/` references pointed at the components; refers to it.
fn schema_file(g: &mut SchemaGenerator, name: &str, text: &str) -> Schema {
    let text = text.replace("\"#/$defs/", "\"#/components/schemas/");
    let Ok(Value::Object(mut root)) = serde_json::from_str::<Value>(&text) else {
        // The tests parse both files; an unreadable one leaves a dangling
        // reference, which they also catch.
        return Schema::new_ref(format!("#/components/schemas/{name}"));
    };
    root.remove("$schema");
    if let Some(Value::Object(defs)) = root.remove("$defs") {
        g.definitions_mut().extend(defs);
    }
    define(g, name, Value::Object(root))
}

/// A behavior diff, `kronik.diff/v1` (docs/reference/diff-v1.schema.json).
pub fn diff(g: &mut SchemaGenerator) -> Schema {
    schema_file(g, "Diff", DIFF_SCHEMA)
}

/// A turn record as JSON (docs/reference/turn.schema.json).
pub fn turn(g: &mut SchemaGenerator) -> Schema {
    schema_file(g, "Turn", TURN_SCHEMA)
}

/// A behavior diff's `summary` (docs/design/m3-fork.md §5.1), from the diff's
/// schema.
pub fn diff_summary(g: &mut SchemaGenerator) -> Schema {
    diff(g);
    Schema::new_ref("#/components/schemas/DiffSummary".into())
}

/// `schema`, or null.
fn or_null(schema: Schema) -> Schema {
    let mut map = serde_json::Map::new();
    map.insert("anyOf".into(), json!([schema.to_value(), {"type": "null"}]));
    Schema::from(map)
}

/// [`policy_evaluation`], or null while a proposal is running (M10).
pub fn policy_evaluation_or_null(g: &mut SchemaGenerator) -> Schema {
    or_null(policy_evaluation(g))
}

/// [`diff_summary`], or null while a proposal is running (M10).
pub fn diff_summary_or_null(g: &mut SchemaGenerator) -> Schema {
    or_null(diff_summary(g))
}

const LIMIT: Param = Param {
    name: "limit",
    kind: "integer",
    description: "At most this many; 1 to 1000, 100 when absent.",
};
const KIND: Param = Param {
    name: "kind",
    kind: "string",
    description: "Only this actor kind.",
};
const FORMAT: Param = Param {
    name: "format",
    kind: "string",
    description: "`json` (the default), `md` for Markdown, or `summary` for the short Markdown summary without bodies or state values (M10).",
};

/// Every `/v1` operation, in the order of the API reference.
pub const OPERATIONS: &[Operation] = &[
    Operation {
        method: "GET",
        path: "/v1/health",
        summary: "The daemon's version, engine, applied LSN and gateway address",
        query: &[],
        request: None,
        answer: Answer::Json(schema::<HealthResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/openapi.json",
        summary: "This document",
        query: &[],
        request: None,
        answer: Answer::Json(any_object),
    },
    Operation {
        method: "POST",
        path: "/v1/deployments",
        summary: "Deploy a component as a new actor type (a kind without history)",
        query: &[],
        request: Some(schema::<DeployRequest>),
        answer: Answer::Json(schema::<DeployResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/deployments",
        summary: "Every deployment, oldest first, with its epoch, cause, code and caller",
        query: &[],
        request: None,
        answer: Answer::Json(schema::<DeploymentsResponse>),
    },
    Operation {
        method: "POST",
        path: "/v1/deployments/{epoch}/rollback",
        summary: "Switch back to the code in force before a deployment",
        query: &[],
        request: Some(schema::<ResendRequest>),
        answer: Answer::Json(schema::<RollbackResponse>),
    },
    Operation {
        method: "POST",
        path: "/v1/deployments/{epoch}/watch",
        summary: "Watch a deployment's error rate and latency; alert or roll back on a guard",
        query: &[],
        request: Some(schema::<WatchRequest>),
        answer: Answer::Json(schema::<WatchResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/watches",
        summary: "List the watches",
        query: &[],
        request: None,
        answer: Answer::Json(schema::<WatchesResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/watches/{id}",
        summary: "A watch: its status, the guards that fired and the last metrics",
        query: &[],
        request: None,
        answer: Answer::Json(schema::<WatchInfo>),
    },
    Operation {
        method: "POST",
        path: "/v1/watches/{id}/stop",
        summary: "Stop a watch: it alerts and rolls back no more",
        query: &[],
        request: Some(schema::<ResendRequest>),
        answer: Answer::Json(schema::<WatchResponse>),
    },
    Operation {
        method: "POST",
        path: "/v1/actors/{kind}/{key}/messages",
        summary: "Send an operator message and wait for its turn",
        query: &[],
        request: Some(schema::<SendRequest>),
        answer: Answer::Json(schema::<TurnResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/actors",
        summary: "Actors in kind/key order",
        query: &[
            KIND,
            Param {
                name: "after",
                kind: "string",
                description: "Start after this actor, `kind/key`: the previous page's `next`.",
            },
            LIMIT,
        ],
        request: None,
        answer: Answer::Json(schema::<ActorsResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/actors/{kind}/{key}",
        summary: "An actor's metadata, key-value state and SQL tables",
        query: &[],
        request: None,
        answer: Answer::Json(schema::<InspectResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/actors/{kind}/{key}/history",
        summary: "An actor's turns, newest first",
        query: &[
            Param {
                name: "before",
                kind: "integer",
                description: "Only turns before this LSN: the previous page's `next`.",
            },
            LIMIT,
        ],
        request: None,
        answer: Answer::Json(schema::<HistoryResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/actors/{kind}/{key}/timers",
        summary: "An actor's pending timers",
        query: &[],
        request: None,
        answer: Answer::Json(schema::<TimersResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/turns/{id}",
        summary: "A turn record as JSON, on main or in a fork",
        query: &[],
        request: None,
        answer: Answer::Json(turn),
    },
    Operation {
        method: "GET",
        path: "/v1/turns/{id}/trace",
        summary: "A turn's causal tree: its root input, ancestors and descendants",
        query: &[],
        request: None,
        answer: Answer::Json(schema::<TraceResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/dead-letters",
        summary: "Failed inputs and uncertain effect outcomes",
        query: &[
            Param {
                name: "after",
                kind: "string",
                description: "Start after this dead letter id.",
            },
            LIMIT,
        ],
        request: None,
        answer: Answer::Json(schema::<DeadLettersResponse>),
    },
    Operation {
        method: "POST",
        path: "/v1/dead-letters/{id}/resend",
        summary: "Resend a dead letter as a new root input",
        query: &[],
        request: Some(schema::<ResendRequest>),
        answer: Answer::Json(schema::<TurnResponse>),
    },
    Operation {
        method: "POST",
        path: "/v1/grants",
        summary: "Grant an actor type a capability",
        query: &[],
        request: Some(schema::<GrantRequest>),
        answer: Answer::Json(schema::<GrantResponse>),
    },
    Operation {
        method: "POST",
        path: "/v1/grants/revoke",
        summary: "Revoke a capability",
        query: &[],
        request: Some(schema::<RevokeRequest>),
        answer: Answer::Json(schema::<RevokeResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/grants",
        summary: "The capabilities granted to actor types",
        query: &[KIND],
        request: None,
        answer: Answer::Json(schema::<GrantsResponse>),
    },
    Operation {
        method: "POST",
        path: "/v1/limits",
        summary: "Set an actor type's limits",
        query: &[],
        request: Some(schema::<LimitsRequest>),
        answer: Answer::Json(schema::<LimitsResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/limits",
        summary: "The limits of actor types",
        query: &[KIND],
        request: None,
        answer: Answer::Json(schema::<LimitsListResponse>),
    },
    Operation {
        method: "PUT",
        path: "/v1/secrets/{name}",
        summary: "Store a secret, or a new version of it",
        query: &[],
        request: Some(schema::<SecretSetRequest>),
        answer: Answer::Json(schema::<SecretResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/secrets",
        summary: "Secrets: names, versions and version hashes, never values",
        query: &[],
        request: None,
        answer: Answer::Json(schema::<SecretsResponse>),
    },
    Operation {
        method: "DELETE",
        path: "/v1/secrets/{name}",
        summary: "Delete every version of a secret",
        query: &[],
        request: Some(schema::<SecretDeleteRequest>),
        answer: Answer::Json(schema::<SecretDeleteResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/orphans",
        summary: "Orphaned changes: a callee's committed change whose caller failed",
        query: &[Param {
            name: "all",
            kind: "boolean",
            description: "Also the resolved ones.",
        }],
        request: None,
        answer: Answer::Json(schema::<OrphansResponse>),
    },
    Operation {
        method: "POST",
        path: "/v1/tokens",
        summary: "Create an API token; the token is in the answer, once",
        query: &[],
        request: Some(schema::<TokenCreateRequest>),
        answer: Answer::Json(schema::<TokenCreateResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/tokens",
        summary: "The tokens, live and revoked, without the tokens themselves",
        query: &[],
        request: None,
        answer: Answer::Json(schema::<TokensResponse>),
    },
    Operation {
        method: "POST",
        path: "/v1/tokens/{name}/revoke",
        summary: "Revoke a token",
        query: &[],
        request: Some(schema::<TokenRevokeRequest>),
        answer: Answer::Json(schema::<TokenRevokeResponse>),
    },
    Operation {
        method: "POST",
        path: "/v1/forks",
        summary: "Fork main at an LSN, a logical time or now",
        query: &[],
        request: Some(schema::<ForkCreateRequest>),
        answer: Answer::Json(schema::<ForkCreateResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/forks",
        summary: "The forks, those of proposals included",
        query: &[],
        request: None,
        answer: Answer::Json(schema::<ForksResponse>),
    },
    Operation {
        method: "DELETE",
        path: "/v1/forks/{name}",
        summary: "Delete a fork and its state",
        query: &[],
        request: Some(schema::<ResendRequest>),
        answer: Answer::Json(schema::<ForkDeleteResponse>),
    },
    Operation {
        method: "POST",
        path: "/v1/forks/{name}/deployments",
        summary: "Deploy a component in a fork",
        query: &[],
        request: Some(schema::<DeployRequest>),
        answer: Answer::Json(schema::<ForkDeployResponse>),
    },
    Operation {
        method: "POST",
        path: "/v1/forks/{name}/replay",
        summary: "Replay root inputs through a fork's code and write its diff",
        query: &[],
        request: Some(schema::<ReplayRequest>),
        answer: Answer::Json(schema::<ReplayResponse>),
    },
    Operation {
        method: "POST",
        path: "/v1/forks/{name}/actors/{kind}/{key}/messages",
        summary: "Run one message in a fork",
        query: &[],
        request: Some(schema::<SendRequest>),
        answer: Answer::Json(schema::<ForkTurnResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/forks/{name}/diff",
        summary: "A fork's behavior diff",
        query: &[FORMAT],
        request: None,
        answer: Answer::Diff,
    },
    Operation {
        method: "POST",
        path: "/v1/previews",
        summary: "Create a preview: a fork of HEAD with a proposal's code that takes new requests",
        query: &[],
        request: Some(schema::<PreviewCreateRequest>),
        answer: Answer::Json(schema::<PreviewCreateResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/previews",
        summary: "The previews that have not expired",
        query: &[],
        request: None,
        answer: Answer::Json(schema::<PreviewsResponse>),
    },
    Operation {
        method: "DELETE",
        path: "/v1/previews/{id}",
        summary: "Delete a preview and its state",
        query: &[],
        request: Some(schema::<ResendRequest>),
        answer: Answer::Json(schema::<PreviewDeleteResponse>),
    },
    Operation {
        method: "POST",
        path: "/v1/proposals",
        summary: "Propose new code: fork, replay recent traffic, diff and evaluate the policy",
        query: &[],
        request: Some(schema::<ProposeRequest>),
        answer: Answer::Json(schema::<ProposeResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/proposals",
        summary: "The proposals",
        query: &[],
        request: None,
        answer: Answer::Json(schema::<ProposalsResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/proposals/{id}",
        summary: "A proposal with its policy outcome, summary and approval requests",
        query: &[],
        request: None,
        answer: Answer::Json(schema::<ProposalInfo>),
    },
    Operation {
        method: "GET",
        path: "/v1/proposals/{id}/diff",
        summary: "A proposal's behavior diff",
        query: &[FORMAT],
        request: None,
        answer: Answer::Diff,
    },
    Operation {
        method: "POST",
        path: "/v1/proposals/{id}/request-approval",
        summary: "Record a pending request for a human's approval",
        query: &[],
        request: Some(schema::<ResendRequest>),
        answer: Answer::Json(schema::<RequestApprovalResponse>),
    },
    Operation {
        method: "POST",
        path: "/v1/proposals/{id}/approve",
        summary: "Approve a proposal's diff",
        query: &[],
        request: Some(schema::<ResendRequest>),
        answer: Answer::Json(schema::<ApproveResponse>),
    },
    Operation {
        method: "POST",
        path: "/v1/proposals/{id}/promote",
        summary: "Switch to a proposal's code, after catch-up",
        query: &[],
        request: Some(schema::<ResendRequest>),
        answer: Answer::Json(schema::<PromoteResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/policy",
        summary: "The policy rules in force",
        query: &[],
        request: None,
        answer: Answer::Json(schema::<PolicyResponse>),
    },
    Operation {
        method: "PUT",
        path: "/v1/policy",
        summary: "Replace the policy rules",
        query: &[],
        request: Some(schema::<PolicySetRequest>),
        answer: Answer::Json(schema::<PolicySetResponse>),
    },
    Operation {
        method: "POST",
        path: "/v1/policy/test",
        summary: "Evaluate rules against a proposal's or a fork's diff",
        query: &[],
        request: Some(schema::<PolicyTestRequest>),
        answer: Answer::Json(policy_evaluation),
    },
    Operation {
        method: "POST",
        path: "/v1/foreign",
        summary: "Add a foreign actor: a Linux program from an OCI image in gVisor",
        query: &[],
        request: Some(schema::<ForeignAddRequest>),
        answer: Answer::Json(schema::<ForeignAddResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/foreign",
        summary: "The foreign actors and their status",
        query: &[],
        request: None,
        answer: Answer::Json(schema::<ForeignListResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/foreign/{name}",
        summary: "A foreign actor and its status",
        query: &[],
        request: None,
        answer: Answer::Json(schema::<ForeignShowResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/foreign/{name}/logs",
        summary: "A foreign actor's recent log lines",
        query: &[Param {
            name: "tail",
            kind: "integer",
            description: "At most this many lines; 1 to 10000, 200 when absent.",
        }],
        request: None,
        answer: Answer::Json(schema::<ForeignLogsResponse>),
    },
    Operation {
        method: "DELETE",
        path: "/v1/foreign/{name}",
        summary: "Remove a foreign actor",
        query: &[],
        request: Some(schema::<ForeignRemoveRequest>),
        answer: Answer::Json(schema::<ForeignRemoveResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/privacy",
        summary: "Privacy mode, its epoch and the keystore's counts",
        query: &[],
        request: None,
        answer: Answer::Json(schema::<PrivacyStatus>),
    },
    Operation {
        method: "POST",
        path: "/v1/privacy/mode",
        summary: "Turn privacy mode on or off",
        query: &[],
        request: Some(schema::<PrivacyModeRequest>),
        answer: Answer::Json(schema::<PrivacyModeResponse>),
    },
    Operation {
        method: "POST",
        path: "/v1/privacy/erase",
        summary: "Erase a subject: its keys, then its state values and SQL rows",
        query: &[],
        request: Some(schema::<ErasureRequest>),
        answer: Answer::Json(schema::<ErasureResponse>),
    },
    Operation {
        method: "POST",
        path: "/v1/privacy/reseal",
        summary: "Seal history written while privacy mode was off, and tombstone erased subjects",
        query: &[],
        request: Some(schema::<ResealRequest>),
        answer: Answer::Json(schema::<ResealResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/snapshots",
        summary: "Snapshots of main, newest first",
        query: &[],
        request: None,
        answer: Answer::Json(schema::<SnapshotsResponse>),
    },
    Operation {
        method: "POST",
        path: "/v1/snapshots",
        summary: "Take a snapshot now (state, actor databases, secrets at one LSN)",
        query: &[],
        request: Some(schema::<SnapshotCreateRequest>),
        answer: Answer::Json(schema::<SnapshotCreateResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/integrity",
        summary: "The applied LSN, the state hash and a hash of the log, to compare after a restore",
        query: &[],
        request: None,
        answer: Answer::Json(schema::<IntegrityResponse>),
    },
];

/// The stable error JSON (docs/errors.md), registered as the component
/// `Error`.
pub fn error_schema(g: &mut SchemaGenerator) -> Schema {
    let codes: Vec<&str> = ErrorCode::ALL.iter().map(|c| c.as_str()).collect();
    let error = json!({
        "description": "The stable error JSON, the same from the API, the CLI's --json and MCP.",
        "type": "object",
        "required": ["error"],
        "properties": {
            "error": {
                "type": "object",
                "required": ["code", "message"],
                "properties": {
                    "code": {
                        "description": "Stable; `kronik explain <code>` documents it.",
                        "type": "string",
                        "enum": codes
                    },
                    "message": {"type": "string"},
                    "hint": {"type": "string", "description": "What to do next, often the exact command."},
                    "docs": {"type": "string", "description": "`kronik explain <code>`."}
                }
            }
        }
    });
    g.definitions_mut().insert("Error".into(), error);
    Schema::new_ref("#/components/schemas/Error".into())
}

/// `{"$ref": …}` of a schema, or the schema itself.
fn json_content(schema: Schema) -> Value {
    json!({"application/json": {"schema": schema.to_value()}})
}

/// The name of an operation: its method and path, e.g.
/// `get_v1_actors_kind_key_history`.
pub fn operation_id(op: &Operation) -> String {
    let mut id = op.method.to_ascii_lowercase();
    for seg in op.path.split('/').filter(|s| !s.is_empty()) {
        id.push('_');
        id.extend(
            seg.chars()
                .filter(|c| !matches!(c, '{' | '}'))
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }),
        );
    }
    id
}

/// The scope an operation needs, from the router's table.
pub fn scope(op: &Operation) -> &'static str {
    let segs: Vec<&str> = op.path.split('/').skip(1).collect();
    crate::auth::required_scope(op.method, &segs).as_str()
}

/// The schema settings the document is generated with: JSON Schema 2020-12,
/// definitions under `components/schemas`.
pub fn generator() -> SchemaGenerator {
    SchemaSettings::draft2020_12()
        .with(|s| {
            s.definitions_path = "/components/schemas".into();
            s.meta_schema = None;
        })
        .into_generator()
}

fn operation(op: &Operation, g: &mut SchemaGenerator, error: &Schema) -> Value {
    let mut parameters = Vec::new();
    for seg in op.path.split('/') {
        if let Some(name) = seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            parameters.push(json!({
                "name": name, "in": "path", "required": true, "schema": {"type": "string"}
            }));
        }
    }
    for p in op.query {
        parameters.push(json!({
            "name": p.name, "in": "query", "required": false,
            "description": p.description, "schema": {"type": p.kind}
        }));
    }
    let ok = match &op.answer {
        Answer::Json(body) => json!({"description": "Success.", "content": json_content(body(g))}),
        Answer::Diff => json!({
            "description": "The behavior diff: `kronik.diff/v1` JSON, or Markdown with `format=md` or `format=summary`.",
            "content": {
                "application/json": {"schema": diff(g).to_value()},
                "text/markdown": {"schema": {"type": "string"}}
            }
        }),
    };
    let mut out = Map::new();
    out.insert("operationId".into(), json!(operation_id(op)));
    out.insert("summary".into(), json!(op.summary));
    out.insert("x-kronik-scope".into(), json!(scope(op)));
    if !parameters.is_empty() {
        out.insert("parameters".into(), Value::Array(parameters));
    }
    if let Some(body) = op.request {
        out.insert(
            "requestBody".into(),
            json!({"required": true, "content": json_content(body(g))}),
        );
    }
    out.insert(
        "responses".into(),
        json!({
            "200": ok,
            "default": {
                "description": "An error: the stable error JSON.",
                "content": json_content(error.clone())
            }
        }),
    );
    Value::Object(out)
}

/// The OpenAPI 3.1 document of `/v1`.
pub fn document() -> Value {
    let mut g = generator();
    let error = error_schema(&mut g);
    let mut paths = Map::new();
    for op in OPERATIONS {
        let item = operation(op, &mut g, &error);
        let entry = paths
            .entry(op.path)
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(methods) = entry {
            methods.insert(op.method.to_ascii_lowercase(), item);
        }
    }
    let schemas = g.take_definitions(true);
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Kronik JSON API",
            "version": kronik_runtime::KRONIK_VERSION,
            "description": "The daemon's API, versioned under /v1, on the Unix socket and, with a \
                bearer token, over TCP (`--api-listen`). Every mutation requires `reason` and \
                takes `dry_run`; every error is the stable error JSON. `x-kronik-scope` is the \
                scope an operation needs; without a token, the socket's caller has every scope."
        },
        "paths": paths,
        "components": {
            "schemas": schemas,
            "securitySchemes": {
                "bearer": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": "A token from `kronik token create`; required over TCP, \
                        optional on the Unix socket."
                }
            }
        },
        "security": [{}, {"bearer": []}]
    })
}

/// [`document`] as the bytes `GET /v1/openapi.json` serves and
/// `docs/reference/openapi.json` holds: pretty, with a final newline.
pub fn document_bytes() -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(&document()).unwrap_or_default();
    bytes.push(b'\n');
    bytes
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    /// `("GET", ["v1", "actors", kind, key])` arms that dispatch to a handler,
    /// as `GET /v1/actors/{}/{}`, in every source file of the crate.
    fn routed() -> BTreeSet<String> {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
        let mut out = BTreeSet::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            let mut rest = text.as_str();
            while let Some(i) = rest.find("(\"") {
                rest = &rest[i + 2..];
                let Some((method, after)) = rest.split_once("\", [") else {
                    continue;
                };
                if !matches!(method, "GET" | "POST" | "PUT" | "DELETE") {
                    continue;
                }
                let Some((segs, tail)) = after.split_once("])") else {
                    continue;
                };
                let arm = tail.trim_start().strip_prefix("=>").map(str::trim_start);
                let dispatches = arm
                    .is_some_and(|a| a.trim_start_matches('{').trim_start().starts_with("self."));
                if !dispatches || !segs.starts_with("\"v1\"") {
                    continue;
                }
                let path: Vec<String> = segs
                    .split(',')
                    .map(|s| {
                        let s = s.trim();
                        match s.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
                            Some(literal) => literal.to_owned(),
                            None => "{}".to_owned(),
                        }
                    })
                    .collect();
                out.insert(format!("{method} /{}", path.join("/")));
            }
        }
        out
    }

    fn described() -> BTreeSet<String> {
        OPERATIONS
            .iter()
            .map(|op| {
                let path: Vec<&str> = op
                    .path
                    .split('/')
                    .map(|s| if s.starts_with('{') { "{}" } else { s })
                    .collect();
                format!("{} {}", op.method, path.join("/"))
            })
            .collect()
    }

    #[test]
    fn every_route_is_described_and_every_operation_routes() {
        let routed = routed();
        let described = described();
        assert!(routed.len() > 40, "{routed:?}");
        let undocumented: Vec<_> = routed.difference(&described).collect();
        let unrouted: Vec<_> = described.difference(&routed).collect();
        assert!(
            undocumented.is_empty() && unrouted.is_empty(),
            "routes missing from openapi::OPERATIONS: {undocumented:?}; \
             operations without a route: {unrouted:?}"
        );
        assert_eq!(described.len(), OPERATIONS.len(), "an operation twice");
    }

    #[test]
    fn the_committed_document_is_current() {
        let committed = include_str!("../../../docs/reference/openapi.json");
        let current = String::from_utf8(document_bytes()).unwrap();
        assert!(
            committed == current,
            "docs/reference/openapi.json is out of date: run \
             `cargo run -p kronik-api --example openapi > docs/reference/openapi.json`"
        );
    }

    #[test]
    fn every_operation_has_its_scope_and_schemas() {
        let doc = document();
        assert_eq!(doc["openapi"], "3.1.0");
        let schemas = doc["components"]["schemas"].as_object().unwrap();
        for name in [
            "Error",
            "ActorsResponse",
            "TokenCreateResponse",
            "ProposeResponse",
        ] {
            assert!(schemas.contains_key(name), "{name}");
        }
        let get = &doc["paths"]["/v1/actors/{kind}/{key}/history"]["get"];
        assert_eq!(get["x-kronik-scope"], "read");
        assert_eq!(
            get["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/HistoryResponse"
        );
        let approve = &doc["paths"]["/v1/proposals/{id}/approve"]["post"];
        assert_eq!(approve["x-kronik-scope"], "approve");
        assert_eq!(doc["paths"]["/v1/tokens"]["get"]["x-kronik-scope"], "admin");
        // Every reference resolves.
        let text = doc.to_string();
        for (i, _) in text.match_indices("#/components/schemas/") {
            let name: String = text[i + "#/components/schemas/".len()..]
                .chars()
                .take_while(|c| *c != '"')
                .collect();
            assert!(schemas.contains_key(&name), "dangling $ref {name}");
        }
        // The hand-written schemas: the turn and the diff are typed, and
        // every definition of the files is a component.
        let ok = |path: &str| {
            doc["paths"][path]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
                ["$ref"]
                .clone()
        };
        assert_eq!(ok("/v1/turns/{id}"), "#/components/schemas/Turn");
        assert_eq!(ok("/v1/proposals/{id}/diff"), "#/components/schemas/Diff");
        assert_eq!(ok("/v1/forks/{name}/diff"), "#/components/schemas/Diff");
        for file in [DIFF_SCHEMA, TURN_SCHEMA] {
            let file: Value = serde_json::from_str(file).unwrap();
            assert_eq!(
                file["$schema"],
                "https://json-schema.org/draft/2020-12/schema"
            );
            for name in file["$defs"].as_object().unwrap().keys() {
                assert!(schemas.contains_key(name), "{name} is not a component");
            }
        }
        assert!(!text.contains("#/$defs/"), "a reference into a schema file");
    }
}
