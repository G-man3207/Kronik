//! The resources: the agent guide, the concepts and the error catalog
//! (`kronik explain`), the actor WIT, and the current configuration from the
//! API. Each needs the `read` scope.

use kronik_core::explain::{self, TopicKind};
use rmcp::ErrorData;
use rmcp::RoleServer;
use rmcp::model::{ReadResourceResult, Resource, ResourceContents};
use rmcp::service::RequestContext;
use serde_json::{Map, Value};

use crate::KronikMcp;

/// The WIT world every actor component implements.
const WIT: &str = include_str!("../../../wit/kronik-actor.wit");

const JSON: &str = "application/json";

struct Spec {
    uri: &'static str,
    name: &'static str,
    title: &'static str,
    description: &'static str,
    mime_type: &'static str,
}

const RESOURCES: &[Spec] = &[
    Spec {
        uri: "kronik://agent-guide",
        name: "agent-guide",
        title: "AGENT_GUIDE.md",
        description: "Start here: the golden path for an agent, from zero. Reading history, \
            proposing a change, reading the diff and asking for approval, with the tools to \
            use. The same text as `kronik explain agent`.",
        mime_type: "text/markdown",
    },
    Spec {
        uri: "kronik://concepts",
        name: "concepts",
        title: "Concepts",
        description: "Every Kronik concept, as `kronik explain <concept>` gives it: name, \
            title, milestone and the explanation in Markdown.",
        mime_type: JSON,
    },
    Spec {
        uri: "kronik://errors",
        name: "errors",
        title: "Error catalog",
        description: "Every stable error code, as `kronik explain <CODE>` gives it: HTTP \
            status, title, milestone and what to do about it.",
        mime_type: JSON,
    },
    Spec {
        uri: "kronik://wit/kronik-actor.wit",
        name: "wit",
        title: "Actor WIT",
        description: "The WIT that every actor component implements: the handler export and \
            the host interfaces it may import.",
        mime_type: "text/plain",
    },
    Spec {
        uri: "kronik://config",
        name: "config",
        title: "Current configuration",
        description: "Deployments, grants, limits and the policy as they are now, from the API.",
        mime_type: JSON,
    },
];

pub(crate) fn list() -> Vec<Resource> {
    RESOURCES
        .iter()
        .map(|spec| {
            Resource::new(spec.uri, spec.name)
                .with_title(spec.title)
                .with_description(spec.description)
                .with_mime_type(spec.mime_type)
        })
        .collect()
}

pub(crate) async fn read(
    mcp: &KronikMcp,
    context: &RequestContext<RoleServer>,
    uri: &str,
) -> Result<ReadResourceResult, ErrorData> {
    let Some(spec) = RESOURCES.iter().find(|spec| spec.uri == uri) else {
        return Err(ErrorData::resource_not_found(
            format!("no resource {uri:?}"),
            None,
        ));
    };
    if let Some(error) = mcp.refused(context, "read")? {
        let message = error["error"]["message"]
            .as_str()
            .unwrap_or("refused")
            .to_owned();
        return Err(ErrorData::invalid_request(message, Some(error)));
    }
    let text = match spec.name {
        "agent-guide" => explain::AGENT_GUIDE.to_owned(),
        "concepts" => topics(TopicKind::Concept),
        "errors" => topics(TopicKind::ErrorCode),
        "wit" => WIT.to_owned(),
        _ => config(mcp, context).await?,
    };
    Ok(ReadResourceResult::new(vec![
        ResourceContents::text(text, uri).with_mime_type(spec.mime_type),
    ]))
}

fn topics(kind: TopicKind) -> String {
    let topics: Vec<_> = explain::list().filter(|topic| topic.kind == kind).collect();
    serde_json::json!(topics).to_string()
}

/// The configuration endpoints' answers, each the API's error JSON when it
/// refused.
async fn config(
    mcp: &KronikMcp,
    context: &RequestContext<RoleServer>,
) -> Result<String, ErrorData> {
    let mut config = Map::new();
    for (key, path) in [
        ("deployments", "/v1/deployments"),
        ("grants", "/v1/grants"),
        ("limits", "/v1/limits"),
        ("policy", "/v1/policy"),
    ] {
        let response = mcp
            .api(context, "GET", path, String::new(), Vec::new())
            .await?;
        let value: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
        let value = match value.get(key) {
            Some(inner) if response.status < 400 => inner.clone(),
            _ => value,
        };
        config.insert(key.into(), value);
    }
    Ok(Value::Object(config).to_string())
}
