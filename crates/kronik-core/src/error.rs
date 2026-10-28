//! Stable error codes and the error shape of the API, the gateway and the
//! CLI:
//!
//! ```json
//! {"error":{"code":"ACTOR_NOT_FOUND","message":"…","hint":"…","docs":"kronik explain ACTOR_NOT_FOUND"}}
//! ```
//!
//! Codes are part of the public contract: never rename or reuse one. Every
//! code has an HTTP status, a one-line title, a default hint and a long
//! explanation in `explain/codes/<CODE>.md`. `kronik explain <CODE>` prints
//! the explanation (see [`crate::explain`]), and `docs/errors.md` is
//! generated from this catalog with
//! `cargo run -p kronik-core --example errors_md > docs/errors.md`.

use std::fmt;

use serde::de::{self, Deserializer, Visitor};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

macro_rules! codes {
    ($($variant:ident = $name:literal, $status:literal, $milestone:literal, $title:literal, $hint:literal;)*) => {
        /// A stable error code.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum ErrorCode {
            $(
                #[doc = $title]
                $variant,
            )*
        }

        impl ErrorCode {
            /// Every code, in catalog order.
            pub const ALL: &'static [ErrorCode] = &[$(ErrorCode::$variant,)*];

            /// Every code as written in JSON, in catalog order.
            const NAMES: &'static [&'static str] = &[$($name,)*];

            /// The code as written in JSON, e.g. `STORAGE_CORRUPT`.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(ErrorCode::$variant => $name,)*
                }
            }

            /// HTTP status used by the API and the gateway.
            pub const fn http_status(self) -> u16 {
                match self {
                    $(ErrorCode::$variant => $status,)*
                }
            }

            /// The roadmap milestone that introduces the code, `M1` to `M8`
            /// for v0.1 (SPEC.md, "Roadmap").
            pub const fn milestone(self) -> &'static str {
                match self {
                    $(ErrorCode::$variant => $milestone,)*
                }
            }

            /// What the code means, in one line.
            pub const fn title(self) -> &'static str {
                match self {
                    $(ErrorCode::$variant => $title,)*
                }
            }

            /// One-line advice on what to do next. [`ApiError::new`] uses it
            /// as the error's hint.
            pub const fn hint(self) -> &'static str {
                match self {
                    $(ErrorCode::$variant => $hint,)*
                }
            }

            /// The long explanation in Markdown: what the code means, typical
            /// causes, how to fix it and the next command where one applies.
            pub const fn explain(self) -> &'static str {
                match self {
                    $(ErrorCode::$variant => {
                        include_str!(concat!("../explain/codes/", $name, ".md")).trim_ascii()
                    })*
                }
            }

            /// Parses a code as written in JSON. Matching is exact: codes are
            /// upper case.
            pub fn parse(s: &str) -> Option<ErrorCode> {
                match s {
                    $($name => Some(ErrorCode::$variant),)*
                    _ => None,
                }
            }
        }
    };
}

// Catalog order is alphabetical. Generic codes (not named in the brief) are
// justified in their explanation.
codes! {
    ActorNotFound = "ACTOR_NOT_FOUND", 404, "M1",
        "No such actor or actor type",
        "Check the kind and key with `kronik actors list`.";
    ApprovalRequired = "APPROVAL_REQUIRED", 403, "M3",
        "The policy requires an approval first",
        "Read the diff, then run `kronik approve <proposal> --reason '...'`.";
    BadRequest = "BAD_REQUEST", 400, "M1",
        "The request is malformed",
        "Fix the field or value named in the message and send the request again.";
    CapabilityNotGranted = "CAPABILITY_NOT_GRANTED", 403, "M2",
        "The actor type lacks a capability for this effect",
        "Grant it with `kronik grant <kind> <capability> --reason '...'`.";
    DeadLetterAlreadyResent = "DEAD_LETTER_ALREADY_RESENT", 409, "M1",
        "The dead letter was already resent",
        "See its `resent_as` turn in `kronik dead-letters list`.";
    DeadLetterNotFound = "DEAD_LETTER_NOT_FOUND", 404, "M1",
        "No such dead letter",
        "List dead letters with `kronik dead-letters list`.";
    DeploymentNotFound = "DEPLOYMENT_NOT_FOUND", 404, "M3",
        "No such deployment",
        "List the deployments and their epochs with `kronik deployments list`.";
    EffectOutcomeUnknown = "EFFECT_OUTCOME_UNKNOWN", 500, "M2",
        "An unsafe effect may or may not have happened",
        "Check the target system; resend the dead letter only if the effect did not happen.";
    EngineUpgradeDiverged = "ENGINE_UPGRADE_DIVERGED", 409, "M6",
        "The new engine version changes behavior",
        "Keep the current binary and report the diff from `kronik upgrade check`.";
    EngineVersionMismatch = "ENGINE_VERSION_MISMATCH", 409, "M6",
        "The engine version differs from the recorded one",
        "Run the recorded engine version, or verify the new one with `kronik upgrade check`.";
    ForeignExists = "FOREIGN_EXISTS", 409, "M7",
        "A foreign actor with this name is already declared",
        "Remove it first with `kronik foreign remove <name> --reason '...'`, then add it again.";
    ForeignNotFound = "FOREIGN_NOT_FOUND", 404, "M7",
        "No foreign actor with this name is declared",
        "List the foreign actors with `kronik foreign list`.";
    ForeignUnavailable = "FOREIGN_UNAVAILABLE", 503, "M7",
        "The foreign actor is not reachable",
        "Check it with `kronik foreign list` and `kronik foreign logs <name>`.";
    ForkNotFound = "FORK_NOT_FOUND", 404, "M3",
        "No such fork",
        "List forks with `kronik fork list`.";
    FuelExhausted = "FUEL_EXHAUSTED", 500, "M1",
        "The turn ran out of fuel",
        "Make the handler cheaper, or raise the fuel with `kronik limits set <kind> --fuel <n> --reason '...'`.";
    GatewayTimeout = "GATEWAY_TIMEOUT", 504, "M1",
        "The turn outlived the gateway timeout",
        "The turn still completes; repeat the request with the same Idempotency-Key to get its response.";
    IdempotencyInFlight = "IDEMPOTENCY_IN_FLIGHT", 409, "M1",
        "The original request with this key is still running",
        "Retry later with the same Idempotency-Key and the same request.";
    IdempotencyKeyReused = "IDEMPOTENCY_KEY_REUSED", 422, "M1",
        "The key was already used for a different request",
        "Use a new Idempotency-Key for a different request.";
    ImageInvalid = "IMAGE_INVALID", 400, "M7",
        "The image cannot be used",
        "Pin the image by digest (`<ref>@sha256:<digest>` or `oci-layout:<dir>`) and check that it is a linux image for this host.";
    ImportNotAllowed = "IMPORT_NOT_ALLOWED", 400, "M1",
        "The component imports an interface outside the allowlist",
        "Remove the listed imports; only kronik:actor and deterministic WASI are allowed.";
    Internal = "INTERNAL", 500, "M1",
        "An internal error in Kronik",
        "This is a bug in Kronik; please report it with the daemon log.";
    KeystoreIncomplete = "KEYSTORE_INCOMPLETE", 409, "M8",
        "A sealed value's subject key is not in the keystore",
        "Let the source ship its keystore again and restore again; if it is gone, `kronik restore --allow-missing-keys` keeps every other subject readable.";
    KvmUnavailable = "KVM_UNAVAILABLE", 503, "M7",
        "KVM is not available on this host",
        "Set `platform = \"auto\"` or `\"systrap\"` under `[foreign]`, or enable `/dev/kvm`.";
    MasterKeyMismatch = "MASTER_KEY_MISMATCH", 409, "M2",
        "The master key is not the key the stores were encrypted under",
        "Start with the data directory's own master key: the file it was created with, or its KRONIK_MASTER_KEY.";
    MasterKeyMissing = "MASTER_KEY_MISSING", 409, "M2",
        "The master key is missing, and the data directory holds encrypted stores",
        "Put the key back where [keys] master_key_file points, or set KRONIK_MASTER_KEY; Kronik does not make a new key over existing stores.";
    NothingToPropose = "NOTHING_TO_PROPOSE", 409, "M10",
        "Main already runs every component of the proposal",
        "Nothing changed: main already runs this code. Change a component and build it again.";
    NotImplemented = "NOT_IMPLEMENTED", 501, "M1",
        "Not available in this version",
        "Use what this version supports; `kronik --version` shows the version.";
    PayloadTooLarge = "PAYLOAD_TOO_LARGE", 413, "M1",
        "The body or message is over the limit",
        "Send less data; messages are limited to 1 MiB by default.";
    PolicyDenied = "POLICY_DENIED", 403, "M3",
        "A policy rule denies the change",
        "Read the diff with `kronik diff show <proposal>`, change the code and propose again.";
    PreviewFull = "PREVIEW_FULL", 409, "M11",
        "The preview took as many requests as it can hold",
        "Delete it with `kronik preview delete <id>` and create a new one with `kronik preview create <proposal>`.";
    PreviewLimit = "PREVIEW_LIMIT", 409, "M11",
        "As many previews are live as there can be",
        "Delete one with `kronik preview delete <id>` (see `kronik preview list`), or wait until one expires.";
    PreviewNotFound = "PREVIEW_NOT_FOUND", 404, "M11",
        "No such preview, or it expired",
        "List the previews with `kronik preview list`; create one with `kronik preview create <proposal>`.";
    ProposalNotFound = "PROPOSAL_NOT_FOUND", 404, "M3",
        "No such proposal",
        "List the proposals with `kronik proposals list`.";
    ProposalRunning = "PROPOSAL_RUNNING", 409, "M10",
        "The proposal is still running its replay",
        "Follow it with `kronik proposal wait <proposal>`, then try again.";
    ProposalStale = "PROPOSAL_STALE", 409, "M3",
        "The proposal can no longer be promoted",
        "Propose again with `kronik propose <wasm> --reason '...'`.";
    ReasonRequired = "REASON_REQUIRED", 400, "M1",
        "The mutation has no reason",
        "Add --reason with a short explanation.";
    ReplayDiverged = "REPLAY_DIVERGED", 500, "M2",
        "Replay did not reproduce the recorded history",
        "This is a determinism bug; report it with the turn id and the daemon log.";
    RollbackSchemaChanged = "ROLLBACK_SCHEMA_CHANGED", 409, "M3",
        "The schema version changed since that deployment",
        "Fix forward: propose a corrected version that keeps the current schema version.";
    RouteConflict = "ROUTE_CONFLICT", 409, "M1",
        "Another actor type already serves this route",
        "Change the method or pattern in the kind's describe, rebuild and deploy again.";
    RouteNotFound = "ROUTE_NOT_FOUND", 404, "M1",
        "No deployed route matches the request",
        "Check the method and path against the routes that `kronik deploy` printed.";
    RuncMissing = "RUNC_MISSING", 503, "M7",
        "runc is not installed",
        "Install runc for `--isolation trusted`, or use the default `gvisor`.";
    RunscMissing = "RUNSC_MISSING", 503, "M7",
        "gVisor's runsc is not installed",
        "Install gVisor's runsc, then check the host with `kronik doctor`.";
    ScopeMissing = "SCOPE_MISSING", 403, "M5",
        "The token lacks the scope for this operation",
        "Use a token with the required scope.";
    SecretNotFound = "SECRET_NOT_FOUND", 404, "M2",
        "No such secret",
        "List secrets with `kronik secret list`.";
    StorageCorrupt = "STORAGE_CORRUPT", 500, "M1",
        "The log or state on disk is corrupt",
        "Stop the daemon and keep the data directory; do not delete log segments.";
    SubjectErased = "SUBJECT_ERASED", 410, "M8",
        "The subject's data was erased",
        "The subject was erased; its data cannot be read.";
    TokenNotFound = "TOKEN_NOT_FOUND", 404, "M5",
        "No API token with that name",
        "List the tokens with `kronik token list`.";
    TurnFailed = "TURN_FAILED", 500, "M1",
        "The turn failed",
        "Inspect the turn with `kronik history <kind/key>`; resend failed messages with `kronik dead-letters resend`.";
    TurnNotFound = "TURN_NOT_FOUND", 404, "M1",
        "No turn with that id",
        "Check the turn id (`<branch>:<lsn>`) with `kronik history <kind/key>`.";
    Unauthenticated = "UNAUTHENTICATED", 401, "M5",
        "No valid token",
        "Send a valid token as `Authorization: Bearer <token>`.";
    Unavailable = "UNAVAILABLE", 503, "M1",
        "The daemon is not accepting requests",
        "Retry shortly; if it persists, check the daemon log.";
    VerifyRequired = "VERIFY_REQUIRED", 409, "M1",
        "The actor type has history; verify the change first",
        "A kind with history changes through `kronik propose` and `kronik promote`.";
    WatchNotFound = "WATCH_NOT_FOUND", 404, "M11",
        "No such watch",
        "List the watches with `kronik watches list`.";
}

impl ErrorCode {
    /// The `docs` field of an error: `kronik explain <CODE>`.
    pub fn docs(self) -> String {
        format!("kronik explain {}", self.as_str())
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ErrorCode {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ErrorCode {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<ErrorCode, D::Error> {
        struct CodeVisitor;

        impl Visitor<'_> for CodeVisitor {
            type Value = ErrorCode;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a Kronik error code such as ACTOR_NOT_FOUND")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<ErrorCode, E> {
                ErrorCode::parse(v).ok_or_else(|| E::unknown_variant(v, ErrorCode::NAMES))
            }
        }

        d.deserialize_str(CodeVisitor)
    }
}

/// An error as returned by the API, the gateway and the CLI. It serializes
/// as `{"error":{"code","message","hint","docs"}}`, where `docs` is derived
/// from the code and `hint` is omitted when it is `None`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {message}")]
pub struct ApiError {
    pub code: ErrorCode,
    /// What happened, for this request.
    pub message: String,
    /// What to do next, ideally the exact next command (I12).
    pub hint: Option<String>,
}

impl ApiError {
    /// An error whose hint is the code's default hint ([`ErrorCode::hint`]).
    pub fn new(code: ErrorCode, message: impl Into<String>) -> ApiError {
        ApiError {
            code,
            message: message.into(),
            hint: Some(code.hint().to_owned()),
        }
    }

    /// Replaces the hint, typically with the exact next command, e.g.
    /// `kronik grant billing http:payments.internal --reason '...'`.
    #[must_use]
    pub fn with_hint(mut self, hint: impl Into<String>) -> ApiError {
        self.hint = Some(hint.into());
        self
    }

    /// The serialized form as a JSON value.
    pub fn to_json(&self) -> serde_json::Value {
        let mut body = serde_json::Map::new();
        body.insert("code".into(), self.code.as_str().into());
        body.insert("message".into(), self.message.as_str().into());
        if let Some(hint) = &self.hint {
            body.insert("hint".into(), hint.as_str().into());
        }
        body.insert("docs".into(), self.code.docs().into());
        serde_json::json!({ "error": body })
    }
}

/// An error with the code's title as its message.
impl From<ErrorCode> for ApiError {
    fn from(code: ErrorCode) -> ApiError {
        ApiError::new(code, code.title())
    }
}

/// The derived `docs` field, written without allocating.
struct Docs(ErrorCode);

impl Serialize for Docs {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(&format_args!("kronik explain {}", self.0.as_str()))
    }
}

impl Serialize for ApiError {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Wire<'a> {
            error: Body<'a>,
        }

        #[derive(Serialize)]
        struct Body<'a> {
            code: ErrorCode,
            message: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            hint: Option<&'a str>,
            docs: Docs,
        }

        Wire {
            error: Body {
                code: self.code,
                message: &self.message,
                hint: self.hint.as_deref(),
                docs: Docs(self.code),
            },
        }
        .serialize(s)
    }
}

/// Reads the shape that [`Serialize`] writes. `docs` is ignored, because it
/// follows from the code, and so are fields added in later versions.
impl<'de> Deserialize<'de> for ApiError {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<ApiError, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            error: Body,
        }

        #[derive(Deserialize)]
        struct Body {
            code: ErrorCode,
            message: String,
            hint: Option<String>,
        }

        let Wire {
            error:
                Body {
                    code,
                    message,
                    hint,
                },
        } = Wire::deserialize(d)?;
        Ok(ApiError {
            code,
            message,
            hint,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use serde_json::{Value, json};

    use super::*;

    /// The codes that the brief requires in v0.1 (SPEC.md, "Agent
    /// interface: API, CLI and MCP").
    const BRIEF_CODES: [&str; 26] = [
        "IMPORT_NOT_ALLOWED",
        "CAPABILITY_NOT_GRANTED",
        "ACTOR_NOT_FOUND",
        "ROUTE_CONFLICT",
        "VERIFY_REQUIRED",
        "PROPOSAL_STALE",
        "POLICY_DENIED",
        "APPROVAL_REQUIRED",
        "ROLLBACK_SCHEMA_CHANGED",
        "REPLAY_DIVERGED",
        "TURN_FAILED",
        "EFFECT_OUTCOME_UNKNOWN",
        "FUEL_EXHAUSTED",
        "IDEMPOTENCY_KEY_REUSED",
        "IDEMPOTENCY_IN_FLIGHT",
        "FORK_NOT_FOUND",
        "SUBJECT_ERASED",
        "FOREIGN_UNAVAILABLE",
        "RUNSC_MISSING",
        "KVM_UNAVAILABLE",
        "NOT_IMPLEMENTED",
        "STORAGE_CORRUPT",
        "ENGINE_VERSION_MISMATCH",
        "ENGINE_UPGRADE_DIVERGED",
        "SCOPE_MISSING",
        "REASON_REQUIRED",
    ];

    /// Statuses fixed by docs/design/m1-core.md §4, plus UNAUTHENTICATED.
    const FIXED_STATUSES: [(&str, u16); 13] = [
        ("ROUTE_NOT_FOUND", 404),
        ("GATEWAY_TIMEOUT", 504),
        ("BAD_REQUEST", 400),
        ("PAYLOAD_TOO_LARGE", 413),
        ("DEAD_LETTER_NOT_FOUND", 404),
        ("DEAD_LETTER_ALREADY_RESENT", 409),
        ("TURN_NOT_FOUND", 404),
        ("UNAVAILABLE", 503),
        ("INTERNAL", 500),
        ("IDEMPOTENCY_IN_FLIGHT", 409),
        ("IDEMPOTENCY_KEY_REUSED", 422),
        ("TURN_FAILED", 500),
        ("UNAUTHENTICATED", 401),
    ];

    #[test]
    fn catalog_has_the_required_codes_and_statuses() {
        for name in BRIEF_CODES {
            assert!(ErrorCode::parse(name).is_some(), "{name} is missing");
        }
        for (name, status) in FIXED_STATUSES {
            assert_eq!(
                ErrorCode::parse(name).map(ErrorCode::http_status),
                Some(status),
                "{name}"
            );
        }
    }

    #[test]
    fn every_code_round_trips_through_its_string() {
        let mut seen = HashSet::new();
        for &code in ErrorCode::ALL {
            let name = code.as_str();
            assert!(seen.insert(name), "{name} appears twice");
            assert!(
                name.bytes().all(|b| b.is_ascii_uppercase() || b == b'_'),
                "{name}"
            );
            assert_eq!(ErrorCode::parse(name), Some(code));
            assert_eq!(code.to_string(), name);
            let v = serde_json::to_value(code).unwrap();
            assert_eq!(v, Value::String(name.to_owned()));
            assert_eq!(serde_json::from_value::<ErrorCode>(v).unwrap(), code);
        }
    }

    #[test]
    fn parsing_is_exact() {
        assert_eq!(ErrorCode::parse("actor_not_found"), None);
        assert_eq!(ErrorCode::parse(" ACTOR_NOT_FOUND"), None);
        assert_eq!(ErrorCode::parse("NO_SUCH_CODE"), None);
        assert!(serde_json::from_value::<ErrorCode>(json!("NO_SUCH_CODE")).is_err());
        assert!(serde_json::from_value::<ErrorCode>(json!(404)).is_err());
    }

    #[test]
    fn every_code_has_a_status_milestone_title_hint_and_explanation() {
        const MILESTONES: [&str; 11] = [
            "M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8", "M9", "M10", "M11",
        ];
        for &code in ErrorCode::ALL {
            assert!((400..600).contains(&code.http_status()), "{code}");
            assert!(MILESTONES.contains(&code.milestone()), "{code}");
            for line in [code.title(), code.hint()] {
                assert!(!line.is_empty() && !line.contains('\n'), "{code}");
            }
            assert!(!code.explain().is_empty(), "{code}");
        }
    }

    #[test]
    fn serializes_to_the_documented_shape() {
        let e = ApiError::new(
            ErrorCode::CapabilityNotGranted,
            "billing is not allowed to call payments.internal",
        )
        .with_hint("kronik grant billing http:payments.internal --reason '...'");
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(
            v,
            json!({"error": {
                "code": "CAPABILITY_NOT_GRANTED",
                "message": "billing is not allowed to call payments.internal",
                "hint": "kronik grant billing http:payments.internal --reason '...'",
                "docs": "kronik explain CAPABILITY_NOT_GRANTED",
            }})
        );
        assert_eq!(e.to_json(), v);
    }

    #[test]
    fn new_uses_the_default_hint_and_none_omits_it() {
        let e = ApiError::new(ErrorCode::StorageCorrupt, "bad crc");
        assert_eq!(e.hint.as_deref(), Some(ErrorCode::StorageCorrupt.hint()));
        assert_eq!(
            e.to_json()["error"]["hint"],
            ErrorCode::StorageCorrupt.hint()
        );

        let bare = ApiError { hint: None, ..e };
        let v = serde_json::to_value(&bare).unwrap();
        assert_eq!(v["error"].get("hint"), None);
        assert_eq!(v["error"]["docs"], "kronik explain STORAGE_CORRUPT");
        assert_eq!(bare.to_json(), v);
        assert_eq!(serde_json::from_value::<ApiError>(v).unwrap(), bare);
    }

    #[test]
    fn every_code_round_trips_as_an_api_error() {
        for &code in ErrorCode::ALL {
            let errors = [
                ApiError::new(code, "what happened"),
                ApiError::new(code, "what happened").with_hint("kronik doctor"),
                ApiError {
                    hint: None,
                    ..ApiError::from(code)
                },
            ];
            for e in errors {
                let text = serde_json::to_string(&e).unwrap();
                assert_eq!(
                    serde_json::from_str::<ApiError>(&text).unwrap(),
                    e,
                    "{text}"
                );
                assert_eq!(serde_json::from_value::<ApiError>(e.to_json()).unwrap(), e);
            }
        }
    }

    #[test]
    fn deserializing_ignores_docs_and_rejects_other_shapes() {
        let e: ApiError = serde_json::from_value(json!({"error": {
            "code": "TURN_FAILED",
            "message": "boom",
            "docs": "anything",
            "added_later": 1,
        }}))
        .unwrap();
        assert_eq!(e.code, ErrorCode::TurnFailed);
        assert_eq!((e.message.as_str(), e.hint.as_deref()), ("boom", None));
        assert_eq!(e.to_json()["error"]["docs"], "kronik explain TURN_FAILED");

        for bad in [
            json!({"error": {"code": "NO_SUCH_CODE", "message": "x"}}),
            json!({"error": {"code": "TURN_FAILED"}}),
            json!({"code": "TURN_FAILED", "message": "x"}),
        ] {
            assert!(
                serde_json::from_value::<ApiError>(bad.clone()).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn display_is_code_and_message() {
        let e = ApiError::new(ErrorCode::TurnFailed, "boom");
        assert_eq!(e.to_string(), "TURN_FAILED: boom");
    }
}
