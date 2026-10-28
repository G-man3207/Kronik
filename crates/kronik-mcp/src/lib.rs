//! The MCP server: tools and resources over the in-process JSON API.
//!
//! [`mount`] serves it as Streamable HTTP at [`PATH`] on the API listener,
//! and `kronik mcp` bridges stdio to that endpoint (ADR 0008). A tool call is
//! an API request made with the caller's token id, so an agent gets the same
//! results, errors and stable codes as the CLI.

mod resources;
mod tools;

use std::sync::Arc;

use kronik_api::auth::Scope;
use kronik_api::server::{MAX_REQUEST, Mount};
use kronik_api::{Api, ApiRequest, ApiResponse};
use kronik_core::error::{ApiError, ErrorCode};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, Implementation, ListResourcesResult, ListToolsResult,
    PaginatedRequestParams, ReadResourceRequestParams, ReadResourceResponse, ServerCapabilities,
    ServerConfig,
};
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::session::never::NeverSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData, RoleServer, ServerHandler};
use tower_service::Service as _;

/// Where the API listener serves MCP.
pub const PATH: &str = "/mcp";

/// What an agent is told when it connects.
const INSTRUCTIONS: &str = "Kronik runs actors whose every change is verified against \
recorded production traffic before it goes live. Read the resource kronik://agent-guide first: \
it is the whole golden path. In short: read with list_actors, inspect_actor, query_history and \
trace_turn; propose a new component with propose_change, which replays recent traffic through \
it and returns a diff summary, the policy outcome and the exact next commands; read the whole \
diff with get_diff; when the policy requires approval, ask a human with request_approval. \
Every tool that changes something requires a `reason`. Errors carry a stable `code` and a \
`hint` with the next step; explain documents concepts and codes.";

/// The caller, as the API listener tells the mount: the connection's
/// identity and the request's bearer token, which every API request of the
/// MCP call carries again (so a revoked token stops at once).
#[derive(Clone)]
struct Credentials {
    token_id: String,
    bearer: Option<String>,
}

/// The MCP service for one request: Streamable HTTP is served statelessly.
#[derive(Clone)]
pub struct KronikMcp {
    api: Arc<Api>,
}

impl KronikMcp {
    pub fn new(api: Arc<Api>) -> Self {
        Self { api }
    }

    /// Makes an API request as the caller of `context`.
    async fn api(
        &self,
        context: &RequestContext<RoleServer>,
        method: &str,
        path: &str,
        query: String,
        body: Vec<u8>,
    ) -> Result<ApiResponse, ErrorData> {
        let credentials = credentials(context)?;
        Ok(self
            .api
            .handle(ApiRequest {
                method: method.to_owned(),
                path: path.to_owned(),
                query,
                body,
                token_id: credentials.token_id,
                bearer: credentials.bearer,
            })
            .await)
    }

    /// The stable error JSON when the caller of `context` lacks `scope`, for
    /// what the server answers itself (`explain` and the built-in
    /// resources); the API checks everything else.
    fn refused(
        &self,
        context: &RequestContext<RoleServer>,
        scope: &str,
    ) -> Result<Option<serde_json::Value>, ErrorData> {
        let credentials = credentials(context)?;
        let scope = Scope::parse(scope)
            .ok_or_else(|| ErrorData::internal_error(format!("unknown scope {scope:?}"), None))?;
        let probe = ApiRequest {
            method: "GET".into(),
            path: PATH.into(),
            query: String::new(),
            body: Vec::new(),
            token_id: credentials.token_id,
            bearer: credentials.bearer,
        };
        Ok(self
            .api
            .caller(&probe)
            .and_then(|caller| caller.require(scope))
            .err()
            .map(|e| e.to_json()))
    }
}

/// The caller the API listener resolved for the HTTP request.
fn credentials(context: &RequestContext<RoleServer>) -> Result<Credentials, ErrorData> {
    context
        .extensions
        .get::<http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<Credentials>())
        .cloned()
        .ok_or_else(|| ErrorData::internal_error("the request has no caller identity", None))
}

/// The stable error JSON for a request the tool itself rejects.
fn bad_request(message: impl Into<String>, hint: &str) -> serde_json::Value {
    ApiError::new(ErrorCode::BadRequest, message)
        .with_hint(hint)
        .to_json()
}

impl ServerHandler for KronikMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        )
        .with_server_info(Implementation::new("kronik", env!("CARGO_PKG_VERSION")))
        .with_instructions(INSTRUCTIONS)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(tools::list()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let arguments = request.arguments.unwrap_or_default();
        tools::call(self, &context, &request.name, arguments)
            .await
            .map(CallToolResponse::from)
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        Ok(ListResourcesResult::with_all_items(resources::list()))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        resources::read(self, &context, &request.uri)
            .await
            .map(ReadResourceResponse::from)
    }
}

/// The MCP endpoint for [`kronik_api::server::serve_with`]: Streamable HTTP,
/// stateless, answering with JSON. Each request gets a [`KronikMcp`] that
/// calls `api` as the request's caller. Only loopback `Host` names are
/// accepted, which is what clients on the Unix socket send.
pub fn mount(api: Arc<Api>) -> (&'static str, Mount) {
    serve(api, config())
}

/// [`mount`] for [`kronik_api::server::serve_tcp`]: any `Host` is accepted.
/// rmcp checks `Host` against DNS rebinding, where a browser lends a page
/// its ambient credentials; on TCP every request needs a bearer token,
/// which a browser never attaches by itself, and the names the API is
/// reached by (a TLS domain, an address) are the operator's.
pub fn mount_for_tcp(api: Arc<Api>) -> (&'static str, Mount) {
    serve(api, config().disable_allowed_hosts())
}

fn config() -> StreamableHttpServerConfig {
    StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_sse_keep_alive(None)
        .with_max_request_body_bytes(MAX_REQUEST)
}

fn serve(api: Arc<Api>, config: StreamableHttpServerConfig) -> (&'static str, Mount) {
    let service = StreamableHttpService::new(
        move || Ok(KronikMcp::new(api.clone())),
        Arc::new(NeverSessionManager::default()),
        config,
    );
    let mount: Mount = Arc::new(move |token_id, mut request| {
        // The listener has checked the token already.
        let bearer = kronik_api::server::bearer(request.headers()).ok().flatten();
        request
            .extensions_mut()
            .insert(Credentials { token_id, bearer });
        let mut service = service.clone();
        Box::pin(async move {
            match service.call(request).await {
                Ok(response) => response,
                Err(never) => match never {},
            }
        })
    });
    (PATH, mount)
}
