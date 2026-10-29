//! Built-in documentation for `kronik explain <topic>`: Kronik's concepts
//! and every error code.
//!
//! The texts are Markdown files in this crate's `explain/` directory:
//! `explain/concepts/<name>.md` for concepts and `explain/codes/<CODE>.md`
//! for error codes (see [`ErrorCode::explain`]). Code, docs and the CLI use
//! the concept names exactly as listed here.

use std::fmt;

use serde::Serialize;

use crate::error::ErrorCode;

/// What a topic documents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TopicKind {
    /// A Kronik concept or internal term, such as `fork`.
    Concept,
    /// A guide: `agent`, the repository's `AGENT_GUIDE.md`.
    Guide,
    /// A stable error code, such as `ACTOR_NOT_FOUND`.
    ErrorCode,
}

/// `AGENT_GUIDE.md`, the single page an agent needs for the golden path.
/// `kronik explain agent` and the MCP resource `kronik://agent-guide` both
/// give this text.
pub const AGENT_GUIDE: &str = include_str!("../../../AGENT_GUIDE.md");

/// The guide topics.
const GUIDES: &[Topic] = &[Topic {
    name: "agent",
    kind: TopicKind::Guide,
    title: "AGENT_GUIDE.md: the golden path for an agent, from zero",
    http_status: None,
    milestone: "M5",
    text: AGENT_GUIDE.trim_ascii(),
}];

/// One `kronik explain` topic. `Display` renders it for a terminal, and
/// `Serialize` gives the `--json` form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Topic {
    /// The name to look the topic up by: a concept such as `turn-id`, or an
    /// error code such as `TURN_NOT_FOUND`.
    pub name: &'static str,
    pub kind: TopicKind,
    /// One line.
    pub title: &'static str,
    /// The error code's HTTP status; `None` for concepts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    /// The roadmap milestone that introduces the topic, `M1` to `M8` for
    /// v0.1 (SPEC.md, "Roadmap"). A text marks later parts with their own
    /// milestone.
    pub milestone: &'static str,
    /// The explanation, in Markdown.
    pub text: &'static str,
}

impl From<ErrorCode> for Topic {
    fn from(code: ErrorCode) -> Topic {
        Topic {
            name: code.as_str(),
            kind: TopicKind::ErrorCode,
            title: code.title(),
            http_status: Some(code.http_status()),
            milestone: code.milestone(),
            text: code.explain(),
        }
    }
}

impl fmt::Display for Topic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.http_status {
            Some(status) => writeln!(f, "{} (HTTP {status}): {}", self.name, self.title)?,
            None => writeln!(f, "{}: {}", self.name, self.title)?,
        }
        write!(f, "\n{}\n\nMilestone: {}", self.text, self.milestone)
    }
}

macro_rules! concepts {
    ($($name:literal => $milestone:literal, $title:literal;)*) => {
        /// The concept topics, in the order of the brief's glossary.
        const CONCEPTS: &[Topic] = &[$(
            Topic {
                name: $name,
                kind: TopicKind::Concept,
                title: $title,
                http_status: None,
                milestone: $milestone,
                text: include_str!(concat!("../explain/concepts/", $name, ".md")).trim_ascii(),
            },
        )*];
    };
}

concepts! {
    "actor" => "M1", "An instance with its own state, identified by kind/key";
    "kind" => "M1", "An actor type: the code for one sort of actor";
    "message" => "M1", "Data sent to an actor: name, content type and body";
    "effect" => "M2", "A call from guest code to the outside world, via the host";
    "hash" => "M1", "The BLAKE3 hash of a component: the identity of its code";
    "fork" => "M3", "A branch of the system's history from an LSN";
    "turn" => "M1", "One execution of an actor's handle for one input";
    "turn-id" => "M1", "The branch and LSN of a turn's turn record";
    "lsn" => "M1", "The log sequence number of a log record";
    "branch" => "M1", "main or a fork, each with its own log and state";
    "root-input" => "M1", "An input from outside: HTTP, an operator message or a timer";
    "causal-key" => "M1", "The root input's id plus the path to a turn";
    "causal-id" => "M1", "A correlation id that is the same in production and replay";
    "execution-id" => "M1", "The host's internal id for one execution of a turn";
    "logical-time" => "M1", "The turn's time: constant, monotonic and recorded";
    "deployment" => "M1", "A log record that points actor types at code hashes";
    "configuration-epoch" => "M1", "A sequence number for system-wide configuration changes";
    "proposal" => "M3", "A fork with a diff: the result of kronik propose";
    "behavior-diff" => "M3", "What changes in responses, effects, state, errors and resources";
    "grounding" => "M3", "How well a fork's effects rest on recordings";
    "isolated-replay" => "M3", "Each root input replayed on production's state at its own LSN";
    "continuous-replay" => "M3", "The fork evolves its own state under the new code";
    "capability" => "M2", "Permission for an actor type to use an effect against a target";
    "delivery-class" => "M2", "How a target tolerates retries";
    "secret-handle" => "M2", "A secret referred to by name; the value never reaches the guest";
    "sql-state" => "M1", "A SQLite database per actor, owned by the host";
    "dead-letters" => "M1", "Inputs whose turn failed, kept for inspection and resend";
    "orphaned-change" => "M2", "A callee's committed change whose caller then failed";
    "privacy-mode" => "M8", "The operator's GDPR switch for sealing personal data";
    "subject" => "M1", "The person a value belongs to, such as user:123";
    "sealed-value" => "M8", "A value encrypted with its subject's key";
    "foreign-actor" => "M7", "A Linux binary in gVisor behind a recorded boundary";
    "isolation-level" => "M7", "How code is sandboxed: wasm, gvisor, trusted or microvm";
    "snapshot" => "M6", "A consistent copy of materialized state at an LSN";
    "segment" => "M1", "A log file; closed segments are immutable";
}

/// Every topic: the concepts, the guides, then the error codes in catalog
/// order.
pub fn list() -> impl Iterator<Item = Topic> {
    CONCEPTS
        .iter()
        .chain(GUIDES)
        .copied()
        .chain(ErrorCode::ALL.iter().map(|&code| Topic::from(code)))
}

/// Finds a topic by name, ignoring ASCII case, so `actor_not_found` finds
/// `ACTOR_NOT_FOUND`.
pub fn lookup(topic: &str) -> Option<Topic> {
    list().find(|t| t.name.eq_ignore_ascii_case(topic))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    /// The concepts that `kronik explain` must cover.
    const REQUIRED_CONCEPTS: [&str; 35] = [
        "actor",
        "kind",
        "message",
        "effect",
        "hash",
        "fork",
        "turn",
        "turn-id",
        "lsn",
        "branch",
        "root-input",
        "causal-key",
        "causal-id",
        "execution-id",
        "logical-time",
        "deployment",
        "configuration-epoch",
        "proposal",
        "behavior-diff",
        "grounding",
        "isolated-replay",
        "continuous-replay",
        "capability",
        "delivery-class",
        "secret-handle",
        "sql-state",
        "dead-letters",
        "orphaned-change",
        "privacy-mode",
        "subject",
        "sealed-value",
        "foreign-actor",
        "isolation-level",
        "snapshot",
        "segment",
    ];

    #[test]
    fn every_error_code_is_a_topic() {
        for &code in ErrorCode::ALL {
            let t = lookup(code.as_str()).unwrap();
            assert_eq!(t, Topic::from(code));
            assert_eq!(t.kind, TopicKind::ErrorCode);
            assert_eq!(t.http_status, Some(code.http_status()));
            assert_eq!(t.text, code.explain());
        }
    }

    #[test]
    fn codes_are_found_in_any_case() {
        for &code in ErrorCode::ALL {
            let lower = code.as_str().to_ascii_lowercase();
            let mut mixed = lower.clone();
            mixed[..1].make_ascii_uppercase();
            for name in [lower.as_str(), mixed.as_str()] {
                assert_eq!(lookup(name).map(|t| t.name), Some(code.as_str()), "{name}");
            }
        }
        assert_eq!(lookup("Turn-Id").map(|t| t.name), Some("turn-id"));
    }

    #[test]
    fn every_required_concept_is_a_topic() {
        for name in REQUIRED_CONCEPTS {
            let t = lookup(name).unwrap_or_else(|| panic!("{name} is missing"));
            assert_eq!(
                (t.name, t.kind, t.http_status),
                (name, TopicKind::Concept, None)
            );
        }
        assert_eq!(CONCEPTS.len(), REQUIRED_CONCEPTS.len());
    }

    #[test]
    fn the_agent_guide_is_a_topic() {
        let t = lookup("agent").unwrap();
        assert_eq!((t.kind, t.http_status), (TopicKind::Guide, None));
        assert!(t.text.starts_with("# Kronik for agents"), "{}", t.text);
        assert_eq!(t.text, AGENT_GUIDE.trim_ascii());
    }

    #[test]
    fn unknown_topics_are_not_found() {
        for name in ["", "actors", "NO_SUCH_CODE", "turn_id", " actor"] {
            assert_eq!(lookup(name), None, "{name:?}");
        }
    }

    #[test]
    fn names_are_unique_and_texts_are_complete() {
        const MILESTONES: [&str; 12] = [
            "M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8", "M9", "M10", "M11", "M28",
        ];
        let mut seen = HashSet::new();
        for t in list() {
            assert!(seen.insert(t.name.to_ascii_lowercase()), "{} twice", t.name);
            assert!(!t.title.is_empty() && !t.title.contains('\n'), "{}", t.name);
            assert!(MILESTONES.contains(&t.milestone), "{}", t.name);
            assert!(!t.text.is_empty(), "{}", t.name);
            assert_eq!(t.text, t.text.trim(), "{}", t.name);
        }
        assert_eq!(
            seen.len(),
            CONCEPTS.len() + GUIDES.len() + ErrorCode::ALL.len()
        );
    }

    /// `See also:` lines and `kronik explain <topic>` commands in the texts
    /// name existing topics.
    #[test]
    fn cross_references_resolve() {
        for t in list() {
            for line in t.text.lines() {
                if let Some(refs) = line.strip_prefix("See also: ") {
                    let refs = refs.strip_suffix('.').unwrap_or(refs);
                    for r in refs.split(", ") {
                        let name = r.trim_matches('`');
                        assert!(lookup(name).is_some(), "{}: unknown topic {r}", t.name);
                        assert_ne!(name, t.name, "{} refers to itself", t.name);
                    }
                }
                for (i, _) in line.match_indices("kronik explain ") {
                    let name: String = line[i + "kronik explain ".len()..]
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                        .collect();
                    assert!(lookup(&name).is_some(), "{}: kronik explain {name}", t.name);
                }
            }
        }
    }

    #[test]
    fn renders_and_serializes() {
        let code = lookup("TURN_FAILED").unwrap();
        let shown = code.to_string();
        assert!(shown.starts_with("TURN_FAILED (HTTP 500): "), "{shown}");
        assert!(
            shown.ends_with(&format!("\n\n{}\n\nMilestone: M1", code.text)),
            "{shown}"
        );
        let v = serde_json::to_value(code).unwrap();
        assert_eq!(v["kind"], "error_code");
        assert_eq!(v["http_status"], 500);
        assert_eq!(v["milestone"], "M1");

        let concept = lookup("fork").unwrap();
        let shown = concept.to_string();
        assert!(shown.starts_with("fork: "), "{shown}");
        assert!(shown.ends_with(&format!("\n\n{}\n\nMilestone: M3", concept.text)));
        let v = serde_json::to_value(concept).unwrap();
        assert_eq!(v["kind"], "concept");
        assert_eq!(v.get("http_status"), None);
        assert_eq!(v["milestone"], "M3");
    }
}
