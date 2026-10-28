//! Stub rules (the brief's `StubRules` simulator, docs/design/m3-fork.md
//! §3.5): canned answers for external effects that have no recording,
//! supplied with a replay or proposal and recorded in the diff's options.
//! A stubbed effect counts as synthetic grounding.

use serde::{Deserialize, Serialize};

fn ok_status() -> u16 {
    200
}

/// One rule: requests whose method (when given) and URL prefix match get
/// the canned response or error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StubRule {
    /// `GET`, `POST`, ...; any method when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Matched against the start of the request URL.
    pub url_prefix: String,
    #[serde(default = "ok_status")]
    pub status: u16,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    /// The response body as text.
    #[serde(default)]
    pub body: String,
    /// Instead of a response: `network`, `timeout`, `too-large` or
    /// `denied`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl StubRule {
    pub fn matches(&self, method: &str, url: &str) -> bool {
        self.method
            .as_deref()
            .is_none_or(|m| m.eq_ignore_ascii_case(method))
            && url.starts_with(&self.url_prefix)
    }
}

/// Rejects rules that cannot apply.
pub fn check(rules: &[StubRule]) -> Result<(), String> {
    for r in rules {
        if r.url_prefix.is_empty() {
            return Err("a stub rule needs a url_prefix".into());
        }
        if let Some(e) = &r.error
            && !matches!(e.as_str(), "network" | "timeout" | "too-large" | "denied")
        {
            return Err(format!(
                "stub error must be network, timeout, too-large or denied, not {e:?}"
            ));
        }
        if !(100..=599).contains(&r.status) {
            return Err(format!("stub status {} is not an HTTP status", r.status));
        }
    }
    Ok(())
}

/// The first rule matching a request.
pub fn find<'a>(rules: &'a [StubRule], method: &str, url: &str) -> Option<&'a StubRule> {
    rules.iter().find(|r| r.matches(method, url))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_and_checks() {
        let r: StubRule =
            serde_json::from_str(r#"{"method": "get", "url_prefix": "http://a/x"}"#).unwrap();
        assert_eq!(r.status, 200);
        assert!(r.matches("GET", "http://a/x/1"));
        assert!(!r.matches("POST", "http://a/x/1"));
        assert!(!r.matches("GET", "http://b/x"));
        assert!(check(&[r]).is_ok());
        let bad: StubRule =
            serde_json::from_str(r#"{"url_prefix": "http://a", "error": "boom"}"#).unwrap();
        assert!(check(&[bad]).is_err());
    }
}
