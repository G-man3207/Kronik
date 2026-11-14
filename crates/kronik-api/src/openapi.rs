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
use crate::m12::*;
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
    /// A bounded SSE stream of versioned operational events and cursor frames.
    EventsSse,
    /// HTTP upgrade to a bounded JSON event WebSocket.
    EventsWebSocket,
    /// Browser login/callback redirects.
    Redirect,
    /// Embedded static asset, on the admin listener only.
    Asset(&'static str),
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

pub fn cluster_status(g: &mut SchemaGenerator) -> Schema {
    schema_file(
        g,
        "ClusterStatusResponse",
        include_str!("../../../docs/reference/cluster-status.schema.json"),
    )
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

/// Every public operation, including the admin listener's embedded assets.
pub const OPERATIONS: &[Operation] = &[
    Operation {
        method: "GET",
        path: "/ui",
        summary: "Embedded admin UI",
        query: &[],
        request: None,
        answer: Answer::Asset("text/html; charset=utf-8"),
    },
    Operation {
        method: "GET",
        path: "/ui/",
        summary: "Embedded admin UI",
        query: &[],
        request: None,
        answer: Answer::Asset("text/html; charset=utf-8"),
    },
    Operation {
        method: "GET",
        path: "/ui/app.js",
        summary: "Embedded admin UI script",
        query: &[],
        request: None,
        answer: Answer::Asset("text/javascript; charset=utf-8"),
    },
    Operation {
        method: "GET",
        path: "/ui/app.css",
        summary: "Embedded admin UI stylesheet",
        query: &[],
        request: None,
        answer: Answer::Asset("text/css; charset=utf-8"),
    },
    Operation {
        method: "HEAD",
        path: "/ui",
        summary: "Embedded admin UI headers",
        query: &[],
        request: None,
        answer: Answer::Asset("text/html; charset=utf-8"),
    },
    Operation {
        method: "HEAD",
        path: "/ui/",
        summary: "Embedded admin UI headers",
        query: &[],
        request: None,
        answer: Answer::Asset("text/html; charset=utf-8"),
    },
    Operation {
        method: "HEAD",
        path: "/ui/app.js",
        summary: "Embedded admin UI script headers",
        query: &[],
        request: None,
        answer: Answer::Asset("text/javascript; charset=utf-8"),
    },
    Operation {
        method: "HEAD",
        path: "/ui/app.css",
        summary: "Embedded admin UI stylesheet headers",
        query: &[],
        request: None,
        answer: Answer::Asset("text/css; charset=utf-8"),
    },
    Operation {
        method: "GET",
        path: "/ui/icon.svg",
        summary: "Embedded admin UI icon",
        query: &[],
        request: None,
        answer: Answer::Asset("image/svg+xml"),
    },
    Operation {
        method: "HEAD",
        path: "/ui/icon.svg",
        summary: "Embedded admin UI icon headers",
        query: &[],
        request: None,
        answer: Answer::Asset("image/svg+xml"),
    },
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
        method: "GET",
        path: "/v1/cluster/status",
        summary: "Ordinary cluster observations, or the actual native non-member response",
        query: &[],
        request: None,
        answer: Answer::Json(cluster_status),
    },
    Operation {
        method: "GET",
        path: "/v1/auth/session",
        summary: "Current browser session or bearer identity and live scopes (admin listener)",
        query: &[],
        request: None,
        answer: Answer::Json(schema::<crate::oidc::SessionInfo>),
    },
    Operation {
        method: "GET",
        path: "/v1/auth/login",
        summary: "Begin browser-bound OIDC authorization code with PKCE, state and nonce (admin listener)",
        query: &[],
        request: None,
        answer: Answer::Redirect,
    },
    Operation {
        method: "GET",
        path: "/v1/auth/callback",
        summary: "Consume the single-use OIDC code and browser-bound state (admin listener)",
        query: &[
            Param {
                name: "code",
                kind: "string",
                description: "The provider's single-use authorization code.",
            },
            Param {
                name: "state",
                kind: "string",
                description: "The exact browser-bound state issued by login.",
            },
            Param {
                name: "iss",
                kind: "string",
                description: "When present, must exactly equal the configured issuer.",
            },
            Param {
                name: "error",
                kind: "string",
                description: "Provider denial; no session is created.",
            },
        ],
        request: None,
        answer: Answer::Redirect,
    },
    Operation {
        method: "POST",
        path: "/v1/auth/logout",
        summary: "Revoke this browser session; cookie authentication requires Origin and X-Kronik-CSRF",
        query: &[],
        request: Some(schema::<ResendRequest>),
        answer: Answer::Json(any_object),
    },
    Operation {
        method: "GET",
        path: "/v1/auth/config",
        summary: "Durably admitted authentication profile source and activation status",
        query: &[],
        request: None,
        answer: Answer::Json(schema::<crate::auth_config::Status>),
    },
    Operation {
        method: "PUT",
        path: "/v1/auth/config",
        summary: "Admit a typed authentication profile; null explicitly disables it",
        query: &[],
        request: Some(schema::<crate::auth_config::Change>),
        answer: Answer::Json(schema::<crate::auth_config::Changed>),
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
        path: "/v1/deployments/{epoch}/rebase",
        summary: "Roll back a deployment by replay: a proposal with the old code's state and the irreversible effects (needs pii:read besides x-kronik-scope)",
        query: &[],
        request: Some(schema::<RebaseRequest>),
        answer: Answer::Json(schema::<ProposeResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/keys",
        summary: "The master key source and provider version, never key material",
        query: &[],
        request: None,
        answer: Answer::Json(schema::<kronik_privacy::key_source::KeyStatus>),
    },
    Operation {
        method: "POST",
        path: "/v1/keys/rewrap",
        summary: "Wrap the current master seed under the provider's current key version",
        query: &[],
        request: Some(schema::<KeysRewrapRequest>),
        answer: Answer::Json(schema::<KeysChangeResponse>),
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
        method: "GET",
        path: "/v1/connections",
        summary: "Long-lived WebSocket and SSE connections, in id order",
        query: &[
            Param {
                name: "actor",
                kind: "string",
                description: "Only the connections this actor (`kind/key`) accepted.",
            },
            Param {
                name: "kind",
                kind: "string",
                description: "Only the connections of actors of this kind.",
            },
            Param {
                name: "state",
                kind: "string",
                description: "`open` (the default: open or closing), `closed` or `all`.",
            },
            Param {
                name: "after",
                kind: "string",
                description: "Start after this connection id: the previous page's `next`.",
            },
            LIMIT,
        ],
        request: None,
        answer: Answer::Json(schema::<ConnectionsResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/connections/{id}",
        summary: "One connection, open or closed",
        query: &[],
        request: None,
        answer: Answer::Json(schema::<Connection>),
    },
    Operation {
        method: "POST",
        path: "/v1/connections/{id}/close",
        summary: "Close an open connection as the operator",
        query: &[],
        request: Some(schema::<ConnectionCloseRequest>),
        answer: Answer::Json(schema::<ConnectionCloseResponse>),
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
        method: "PUT",
        path: "/v1/secrets/{name}/link",
        summary: "Bind a name to a trusted external secret reference",
        query: &[],
        request: Some(schema::<SecretLinkRequest>),
        answer: Answer::Json(schema::<SecretLinkResponse>),
    },
    Operation {
        method: "DELETE",
        path: "/v1/secrets/{name}/link",
        summary: "Return a name to the built-in source",
        query: &[],
        request: Some(schema::<SecretDeleteRequest>),
        answer: Answer::Json(schema::<SecretLinkResponse>),
    },
    Operation {
        method: "POST",
        path: "/v1/secrets/{name}/refresh",
        summary: "Observe the current immutable source version",
        query: &[],
        request: Some(schema::<SecretRefreshRequest>),
        answer: Answer::Json(schema::<SecretResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/secrets/{name}/history",
        summary: "Committed secret identities and publication outcomes, never values",
        query: &[],
        request: None,
        answer: Answer::Json(schema::<SecretHistoryResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/secrets/backends",
        summary: "Trusted backend bindings and retained-inventory readiness",
        query: &[],
        request: None,
        answer: Answer::Json(schema::<SecretBackendsResponse>),
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
        request: Some(schema::<ApproveRequest>),
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
        path: "/v1/simulators",
        summary: "The effect simulators and each target's simulator configuration",
        query: &[],
        request: None,
        answer: Answer::Json(schema::<SimulatorsResponse>),
    },
    Operation {
        method: "PUT",
        path: "/v1/simulators/{target}",
        summary: "Set a target's stub rules, contract, neighbor and model simulators",
        query: &[],
        request: Some(schema::<SimulatorsSetRequest>),
        answer: Answer::Json(schema::<SimulatorsSetResponse>),
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
        query: &[Param {
            name: "through",
            kind: "integer",
            description: "Hash the log only through this LSN (1 to the applied LSN): a restored node's first start adds a `restore` event after the source's last record.",
        }],
        request: None,
        answer: Answer::Json(schema::<IntegrityResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/audit",
        summary: "The audit lines of main's log (kronik.audit/v3), as an audit sink receives them",
        query: &[
            Param {
                name: "from",
                kind: "integer",
                description: "Lines of records at this LSN and after; the first retained record when absent.",
            },
            LIMIT,
        ],
        request: None,
        answer: Answer::Json(schema::<AuditResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/export",
        summary: "The export streams (traces, audit): sink scheme and host, cursor, lag, last success and error code, gaps",
        query: &[],
        request: None,
        answer: Answer::Json(schema::<ExportStatusResponse>),
    },
    Operation {
        method: "POST",
        path: "/v1/export/{stream}/rewind",
        summary: "Move an export stream's cursor back to resend from after `to` (writes an AuditEvent export.rewind)",
        query: &[],
        request: Some(schema::<ExportRewindRequest>),
        answer: Answer::Json(schema::<ExportRewindResponse>),
    },
    Operation {
        method: "GET",
        path: "/v1/fleet",
        summary: "Show durable fleet enrollment and current local admission",
        query: &[],
        request: None,
        answer: Answer::Json(schema::<crate::fleet::FleetStatus>),
    },
    Operation {
        method: "POST",
        path: "/v1/fleet/enroll",
        summary: "Enroll through pinned TLS; dry-run is local only",
        query: &[],
        request: Some(schema::<crate::fleet::FleetEnrollRequest>),
        answer: Answer::Json(schema::<crate::fleet::FleetStatus>),
    },
    Operation {
        method: "POST",
        path: "/v1/fleet/revoke",
        summary: "Durably revoke fleet admission and cancel old channels",
        query: &[],
        request: Some(schema::<crate::fleet::FleetRevokeRequest>),
        answer: Answer::Json(schema::<crate::fleet::FleetStatus>),
    },
    Operation {
        method: "GET",
        path: "/v1/events",
        summary: "Read safe operational events at typed source positions",
        query: &[
            Param {
                name: "cursor",
                kind: "string",
                description: "Compact kronik.events-cursor/v1 JSON, or the Last-Event-ID header.",
            },
            Param {
                name: "source",
                kind: "string",
                description: "One actual configured actor-native, actor-N or metadata source; defaults to the first configured source.",
            },
            Param {
                name: "limit",
                kind: "integer",
                description: "Events per page, 1 to 256; default 100.",
            },
        ],
        request: None,
        answer: Answer::Json(schema::<kronik_fleet::events::Page>),
    },
    Operation {
        method: "GET",
        path: "/v1/events/stream",
        summary: "SSE events and typed resume cursors; no cross-source total order",
        query: &[
            Param {
                name: "cursor",
                kind: "string",
                description: "Resume cursor, or the Last-Event-ID header; gaps are explicit.",
            },
            Param {
                name: "source",
                kind: "string",
                description: "One actual configured source; omission follows all configured sources.",
            },
        ],
        request: None,
        answer: Answer::EventsSse,
    },
    Operation {
        method: "GET",
        path: "/v1/events/ws",
        summary: "Bounded WebSocket operational events with live revocation",
        query: &[
            Param {
                name: "cursor",
                kind: "string",
                description: "Typed per-source resume cursor; gaps are explicit.",
            },
            Param {
                name: "source",
                kind: "string",
                description: "One actual configured source; omission follows all configured sources.",
            },
        ],
        request: None,
        answer: Answer::EventsWebSocket,
    },
    Operation {
        method: "GET",
        path: "/v1/events/schemas",
        summary: "Published versioned operational event schema registry",
        query: &[],
        request: None,
        answer: Answer::Json(any_object),
    },
    Operation {
        method: "GET",
        path: "/v1/events/webhooks",
        summary: "Durable configured webhook delivery progress",
        query: &[],
        request: None,
        answer: Answer::Json(schema::<crate::events::WebhooksResponse>),
    },
    Operation {
        method: "POST",
        path: "/v1/events/webhooks/{name}/replay",
        summary: "Authorized audited replay without changing event identity",
        query: &[],
        request: Some(schema::<crate::events::ReplayRequest>),
        answer: Answer::Json(schema::<crate::events::ReplayResponse>),
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
    if op.path.ends_with('/') {
        id.push_str("_index");
    }
    id
}

/// The scope an operation needs, from the router's table.
pub fn scope(op: &Operation) -> &'static str {
    if matches!(op.answer, Answer::Asset(_)) {
        return "public";
    }
    let segs: Vec<&str> = op.path.split('/').skip(1).collect();
    if matches!(
        op.path,
        "/v1/auth/session" | "/v1/auth/login" | "/v1/auth/callback"
    ) {
        return "public";
    }
    if op.path == "/v1/auth/logout" {
        return "authenticated";
    }
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
    if matches!(
        op.path,
        "/v1/events" | "/v1/events/stream" | "/v1/events/ws"
    ) {
        parameters.push(json!({
            "name": "Last-Event-ID", "in": "header", "required": false,
            "description": "Bounded typed resume cursor; never a cross-source global LSN.",
            "schema": {"type": "string"}
        }));
    }
    if !matches!(op.method, "GET" | "HEAD") {
        for (name, description) in [
            (
                "Origin",
                "Required only for browser-session authentication: exact configured admin origin.",
            ),
            (
                "X-Kronik-CSRF",
                "Required only for browser-session authentication: the current CSRF token from /v1/auth/session.",
            ),
        ] {
            parameters.push(json!({
                "name": name, "in": "header", "required": false,
                "description": description, "schema": {"type": "string"},
                "x-kronik-required-for": "browserSession"
            }));
        }
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
        Answer::EventsSse => json!({
            "description": "Long-lived SSE; event, typed cursor and explicit gap frames with backpressure and live revocation.",
            "content": {"text/event-stream": {"schema": {"type": "string"},
                "x-kronik-event-schema": schema::<kronik_fleet::events::Event>(g).to_value()}}
        }),
        Answer::EventsWebSocket => json!({
            "description": "WebSocket upgrade; bounded operational event, typed cursor and gap frames.",
            "x-kronik-event-schema": schema::<kronik_fleet::events::Event>(g).to_value()
        }),
        Answer::Redirect => json!({
            "description": "See Other. Login binds the browser transaction; callback installs the opaque cookie.",
            "headers": {
                "Location": {"schema": {"type": "string"}},
                "Set-Cookie": {"description": "Host-only HttpOnly Secure SameSite=Lax login/session cookie.", "schema": {"type": "string"}}
            }
        }),
        Answer::Asset(content_type) => json!({
            "description": "Embedded static admin asset. Never mounted on application routes.",
            "content": {(*content_type): {"schema": {"type": "string"}}}
        }),
    };
    let mut out = Map::new();
    out.insert("operationId".into(), json!(operation_id(op)));
    out.insert("summary".into(), json!(op.summary));
    out.insert("x-kronik-scope".into(), json!(scope(op)));
    if op.path.starts_with("/v1/auth/") || matches!(op.answer, Answer::Asset(_)) {
        out.insert("x-kronik-listener".into(), json!("admin"));
    }
    if matches!(
        op.path,
        "/v1/auth/session" | "/v1/auth/login" | "/v1/auth/callback"
    ) || matches!(op.answer, Answer::Asset(_))
    {
        out.insert("security".into(), json!([{}]));
    } else if op.path == "/v1/auth/logout" {
        out.insert("security".into(), json!([{"browserSession": []}]));
    } else {
        out.insert(
            "security".into(),
            json!([{}, {"bearer": []}, {"browserSession": []}]),
        );
    }
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
            (if matches!(op.answer, Answer::Redirect) { "303" } else if matches!(op.answer, Answer::EventsWebSocket) { "101" } else { "200" }): ok,
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
                bearer token, over TCP (`--api-listen`). The admin listener serves the same \
                operations to bearer callers or OIDC sessions and the admin-only /v1/auth \
                transport operations. Product mutations require reason and take dry_run; \
                errors use the stable error JSON. x-kronik-scope declares the required scope."
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
                },
                "browserSession": {
                    "type": "apiKey",
                    "in": "cookie",
                    "name": "__Host-kronik-session",
                    "description": "Opaque admin-listener session; live mapped-token scopes/revocation and expiry are checked on every request. Cookie-authenticated writes require exact configured Origin and X-Kronik-CSRF from /v1/auth/session."
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

    #[test]
    fn browser_auth_and_historical_identity_contract() {
        let doc = document();
        let paths = &doc["paths"];
        let mut asset_ids = BTreeSet::new();
        for op in OPERATIONS
            .iter()
            .filter(|op| matches!(op.answer, Answer::Asset(_)))
        {
            let asset = kronik_ui::asset(op.path).unwrap();
            let operation = &paths[op.path][op.method.to_ascii_lowercase()];
            assert!(!asset.bytes.is_empty());
            assert_eq!(operation["x-kronik-listener"], "admin");
            assert_eq!(operation["x-kronik-scope"], "public");
            assert_eq!(operation["security"], json!([{}]));
            assert_eq!(
                operation["responses"]["200"]["content"][asset.content_type]["schema"]["type"],
                "string"
            );
            assert!(asset_ids.insert(operation["operationId"].as_str().unwrap()));
        }
        for path in [
            "/v1/auth/session",
            "/v1/auth/login",
            "/v1/auth/callback",
            "/v1/auth/logout",
            "/v1/auth/config",
        ] {
            for (_, operation) in paths[path].as_object().unwrap() {
                assert_eq!(operation["x-kronik-listener"], "admin");
            }
        }
        for path in ["/v1/auth/login", "/v1/auth/callback"] {
            assert!(paths[path]["get"]["responses"].get("303").is_some());
            assert_eq!(paths[path]["get"]["security"], json!([{}]));
        }
        assert_eq!(
            paths["/v1/auth/logout"]["post"]["security"],
            json!([{"browserSession": []}])
        );
        for operation in [
            &paths["/v1/auth/config"]["put"],
            &paths["/v1/proposals/{id}/approve"]["post"],
        ] {
            let parameters = operation["parameters"].as_array().unwrap();
            for name in ["Origin", "X-Kronik-CSRF"] {
                assert!(
                    parameters.iter().any(
                        |p| p["name"] == name && p["x-kronik-required-for"] == "browserSession"
                    )
                );
            }
        }
        let schemas = &doc["components"]["schemas"];
        assert_eq!(schemas["ApproveRequest"]["additionalProperties"], false);
        assert_eq!(
            paths["/v1/proposals/{id}/approve"]["post"]["requestBody"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/ApproveRequest"
        );
        assert!(
            schemas["ReviewedApproval"]["properties"]
                .get("verified_identity")
                .is_some()
        );
        assert!(
            !schemas["ReviewedApproval"]["required"]
                .as_array()
                .unwrap()
                .contains(&json!("verified_identity"))
        );
        assert_eq!(
            doc["components"]["securitySchemes"]["browserSession"]["name"],
            "__Host-kronik-session"
        );
        assert_eq!(paths["/v1/auth/config"]["get"]["x-kronik-scope"], "admin");
        assert_eq!(paths["/v1/auth/config"]["put"]["x-kronik-scope"], "admin");
        assert_eq!(
            paths["/v1/cluster/status"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
                ["$ref"],
            "#/components/schemas/ClusterStatusResponse"
        );
        let native = &schemas["ClusterStatusResponse"]["oneOf"][0];
        assert_eq!(native["required"], json!(["member"]));
        assert_eq!(native["properties"], json!({"member": {"const": false}}));
        assert_eq!(native["additionalProperties"], false);
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
