use std::fmt;

use crate::bindings::kronik::actor::crypto::CryptoError;
use crate::bindings::kronik::actor::http_client::FetchError;
use crate::{CallError, HandlerError, SqlError};

/// An error from a host call or from the SDK.
///
/// `?` turns it into [`HandlerError::Failed`], which fails the turn. Every
/// message names a `kronik explain` topic.
#[derive(Debug)]
pub enum Error {
    /// A SQL statement failed.
    Sql(SqlError),
    /// An outgoing HTTP request failed or was denied.
    Fetch(FetchError),
    /// A call to another actor failed.
    Call(CallError),
    /// A crypto operation failed or was denied.
    Crypto(CryptoError),
    /// Revealing a secret failed or was denied.
    Reveal(String),
    /// A value could not be converted to or from JSON.
    Json {
        /// What was being converted, such as `state value "n"`.
        what: String,
        /// The `kronik explain` topic for it.
        topic: &'static str,
        /// The JSON error.
        source: serde_json::Error,
    },
    /// Bytes that should be UTF-8 text are not.
    Utf8 {
        /// What was being read, such as `the request body`.
        what: String,
        /// The `kronik explain` topic for it.
        topic: &'static str,
    },
    /// A SQL value is missing or has another type than the one asked for.
    Value(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Sql(e) => {
                let (what, message) = match e {
                    SqlError::Syntax(m) => ("SQL syntax error", m.as_str()),
                    SqlError::Constraint(m) => ("SQL constraint failed", m.as_str()),
                    SqlError::Denied(m) => ("SQL statement denied", m.as_str()),
                    SqlError::TooLarge => ("SQL value or database over its size limit", ""),
                };
                write_error(f, what, message, explain_topic(message, "sql-state"))
            }
            Error::Fetch(e) => match e {
                FetchError::Denied(m) => {
                    write_error(f, "HTTP request denied", m, explain_topic(m, "capability"))
                }
                FetchError::Network(m) => write_error(f, "HTTP request failed", m, "effect"),
                FetchError::Timeout => write_error(f, "HTTP request timed out", "", "effect"),
                FetchError::TooLarge => {
                    write_error(f, "HTTP response over its size limit", "", "effect")
                }
                FetchError::OutcomeUnknown => write_error(
                    f,
                    "the HTTP request may or may not have reached its target",
                    "",
                    "EFFECT_OUTCOME_UNKNOWN",
                ),
            },
            Error::Call(e) => match e {
                CallError::NotFound => write_error(
                    f,
                    "call failed: no actor type is deployed for the callee",
                    "",
                    "ACTOR_NOT_FOUND",
                ),
                CallError::Rejected(m) => {
                    write_error(f, "call rejected by the callee", m, "TURN_FAILED")
                }
                CallError::Failed(m) => {
                    write_error(f, "call failed in the callee", m, "TURN_FAILED")
                }
                CallError::Reentrant => write_error(
                    f,
                    "call refused: the callee is already waiting in this chain of calls",
                    "",
                    "effect",
                ),
                CallError::Timeout => write_error(f, "call timed out", "", "effect"),
            },
            Error::Crypto(e) => match e {
                CryptoError::Denied(m) => {
                    write_error(f, "crypto denied", m, explain_topic(m, "secret-handle"))
                }
                CryptoError::Unsupported(m) => {
                    write_error(f, "crypto not supported", m, "NOT_IMPLEMENTED")
                }
            },
            Error::Reveal(m) => write_error(
                f,
                "revealing the secret failed",
                m,
                explain_topic(m, "secret-handle"),
            ),
            Error::Json {
                what,
                topic,
                source,
            } => write_error(
                f,
                &format!("{what} is not the expected JSON"),
                &source.to_string(),
                topic,
            ),
            Error::Utf8 { what, topic } => {
                write_error(f, &format!("{what} is not UTF-8"), "", topic)
            }
            Error::Value(m) => write_error(f, m, "", "sql-state"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Json { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<Error> for HandlerError {
    fn from(error: Error) -> Self {
        HandlerError::Failed(error.to_string())
    }
}

fn write_error(f: &mut fmt::Formatter<'_>, what: &str, detail: &str, topic: &str) -> fmt::Result {
    if detail.is_empty() {
        write!(f, "{what} (see `kronik explain {topic}`)")
    } else {
        write!(f, "{what}: {detail} (see `kronik explain {topic}`)")
    }
}

/// The error code that starts a host message such as
/// `CAPABILITY_NOT_GRANTED: http:api.example.com`, else `fallback`.
pub(crate) fn explain_topic<'a>(message: &'a str, fallback: &'a str) -> &'a str {
    match message.split_once(':') {
        Some((code, _))
            if code.len() > 1
                && code.starts_with(|c: char| c.is_ascii_uppercase())
                && code
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_') =>
        {
            code
        }
        _ => fallback,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_error_codes_become_the_topic() {
        assert_eq!(
            explain_topic("CAPABILITY_NOT_GRANTED: http:api.example.com", "capability"),
            "CAPABILITY_NOT_GRANTED"
        );
        assert_eq!(
            explain_topic("NOT_IMPLEMENTED: timers come in M2", "x"),
            "NOT_IMPLEMENTED"
        );
        assert_eq!(
            explain_topic("DDL is only allowed in migrate", "sql-state"),
            "sql-state"
        );
        assert_eq!(explain_topic("http: bad url", "effect"), "effect");
        assert_eq!(explain_topic("", "effect"), "effect");
    }

    #[test]
    fn every_message_names_an_explain_topic() {
        let errors = [
            Error::Sql(SqlError::Denied("DDL is only allowed in migrate".into())),
            Error::Sql(SqlError::TooLarge),
            Error::Fetch(FetchError::Denied(
                "CAPABILITY_NOT_GRANTED: http:x.example".into(),
            )),
            Error::Fetch(FetchError::OutcomeUnknown),
            Error::Call(CallError::NotFound),
            Error::Call(CallError::Reentrant),
            Error::Crypto(CryptoError::Unsupported("ed25519".into())),
            Error::Reveal("CAPABILITY_NOT_GRANTED: secret-reveal:stripe".into()),
            Error::Value("column 2: expected an integer, got text".into()),
        ];
        let messages: Vec<String> = errors.iter().map(ToString::to_string).collect();
        for m in &messages {
            assert!(m.contains("(see `kronik explain "), "{m}");
        }
        assert_eq!(
            messages[0],
            "SQL statement denied: DDL is only allowed in migrate (see `kronik explain sql-state`)"
        );
        assert_eq!(
            messages[2],
            "HTTP request denied: CAPABILITY_NOT_GRANTED: http:x.example (see `kronik explain CAPABILITY_NOT_GRANTED`)"
        );
    }

    #[test]
    fn errors_become_failed_handler_errors() {
        let e: HandlerError = Error::Call(CallError::Timeout).into();
        match e {
            HandlerError::Failed(m) => {
                assert_eq!(m, "call timed out (see `kronik explain effect`)")
            }
            HandlerError::Rejected(m) => panic!("rejected: {m}"),
        }
    }
}
