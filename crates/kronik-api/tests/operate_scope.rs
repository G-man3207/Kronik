//! An `operate` token is not `admin`. `POST /v1/keys/rewrap` and
//! `PUT /v1/secrets/{name}/link` are admin because their match arms say so;
//! the same match's default is `operate`. This test is the one that fails
//! if either arm is deleted.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use kronik_api::auth::Scope;
use kronik_api::tokens::{Change, TokenStore};
use kronik_api::{Api, ApiRequest};
use kronik_core::env::Env;
use kronik_proto::Record;
use kronik_sched::{NodeConfig, start_local};
use serde_json::{Value, json};

async fn call(api: &Api, method: &str, path: &str, bearer: &str, body: Value) -> (u16, Value) {
    let response = api
        .handle(ApiRequest {
            method: method.into(),
            path: path.into(),
            query: String::new(),
            body: body.to_string().into_bytes(),
            // Not a local uid: a missing bearer must not become the all-scopes caller.
            token_id: "tcp:test".into(),
            bearer: Some(bearer.into()),
        })
        .await;
    (
        response.status,
        serde_json::from_slice(&response.body).unwrap(),
    )
}

fn assert_admin_missing(status: u16, body: &Value, what: &str) {
    assert_eq!(status, 403, "{what}: {body}");
    assert_eq!(body["error"]["code"], "SCOPE_MISSING", "{what}: {body}");
    let message = body["error"]["message"].as_str().unwrap_or("");
    assert!(
        message.contains("lacks scope admin"),
        "{what} message does not name admin: {body}"
    );
}

/// `keys.rewrap` audit actions and `SecretLink` records in main's log.
async fn key_write_records(node: &kronik_sched::Node) -> Vec<String> {
    let upto = node.applied_lsn();
    if upto == 0 {
        return Vec::new();
    }
    let mut found = Vec::new();
    node.reader()
        .read(1, upto, |committed| {
            match &committed.record {
                Record::AuditEvent(event)
                    if event.action == "keys.rewrap" || event.action == "keys.rewrap.failed" =>
                {
                    found.push(event.action.clone());
                }
                Record::SecretLink(_) => found.push("secret.link".into()),
                _ => {}
            }
            Ok(())
        })
        .await
        .unwrap();
    found
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_operate_token_cannot_rewrap_keys_or_link_a_secret() {
    let dir = tempfile::tempdir().unwrap();
    let node = start_local(
        Env::real(tokio::runtime::Handle::current()),
        dir.path(),
        NodeConfig::default(),
    )
    .await
    .unwrap();
    let mut tokens = TokenStore::open_file(&dir.path().join("tokens.db")).unwrap();
    tokens
        .bind_before_any_issuer(node.publication_domain())
        .unwrap();
    let tokens = std::sync::Arc::new(tokens);
    let api = Api::new(node.clone()).with_tokens(tokens.clone()).unwrap();
    let (_, secret) = tokens
        .create(
            "ops",
            [Scope::Operate].into(),
            [9; 32],
            &Change {
                wall_ms: node.env().clock.wall_ms(),
                by: "unix:uid=0",
                reason: "operate token",
            },
            false,
        )
        .unwrap();
    let secret = secret.unwrap();

    let (status, body) = call(
        &api,
        "POST",
        "/v1/keys/rewrap",
        &secret,
        json!({"reason": "rotate"}),
    )
    .await;
    assert_admin_missing(status, &body, "POST /v1/keys/rewrap");

    let (status, body) = call(
        &api,
        "PUT",
        "/v1/secrets/stripe/link",
        &secret,
        json!({"backend": "vault", "ref": "secret/stripe#api_key", "reason": "point stripe at vault"}),
    )
    .await;
    assert_admin_missing(status, &body, "PUT /v1/secrets/stripe/link");

    assert_eq!(
        key_write_records(&node).await,
        Vec::<String>::new(),
        "a refused key write recorded keys.rewrap or a secret link"
    );
}
