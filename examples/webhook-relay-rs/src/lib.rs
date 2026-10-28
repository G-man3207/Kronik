//! webhook-relay-rs: relays webhooks to a target, signed, with retries.
//!
//! An actor `webhook-relay/<key>` accepts webhooks for one source and
//! forwards each one to its target with `http.fetch`, signed with
//! `crypto.hmac-sha256`. It records every delivery in its state and retries
//! failures that may go away with a timer.
//!
//! - `POST /hooks/{key}` accepts a webhook (any body of at most 512 KiB) and
//!   forwards it at once. The answer is the delivery record: `200` when the
//!   target accepted it, else `502`.
//! - `GET /hooks/{key}/{id}` returns the delivery record of one webhook.
//! - The message `configure` with `{"target": "...", "auth_secret": "..."}`
//!   (both optional) sets the target URL and the secret for an
//!   `authorization: Bearer <secret>` header. The default target is
//!   `https://webhooks.example.com/relay`.
//!
//! The forwarded request is `POST <target>` with
//!
//! - `content-type: application/json`;
//! - `x-webhook-id: <id>`, the same in every attempt, so the target can drop
//!   duplicates; `<id>` is the causal id of the turn that accepted it;
//! - `x-signature: sha256=<hex>`, the HMAC-SHA256 of the body with the
//!   secret `relay-signing-key`, computed by the host;
//! - `authorization: Bearer <secret>` if `auth_secret` is set, inserted by
//!   the host, so the value never reaches the actor;
//! - the body `{"webhook": "<id>", "source": "<key>", "payload": <the webhook
//!   body as JSON, or as a string if it is not JSON>}`. The `body-v2` build
//!   adds `"relay": "kronik-webhook-relay/2"`.
//!
//! The host adds an `Idempotency-Key` and records the request and its
//! response. Outcomes: a 2xx answer is `delivered`. A network error, a
//! timeout, an unknown outcome (after a crash, for a target granted as
//! `unsafe`), a 5xx or a 429 is `retrying`: a timer tries again after 1, 2,
//! 4 and 8 seconds, and after 5 attempts the webhook is `failed`. Anything
//! else, such as a 4xx, a missing grant or a missing secret, is `failed` at
//! once. The actor answers with the record either way, so its turn commits
//! and the record and the retry timer are kept.
//!
//! The operator grants what the manifest asks for, plus `http:<host>` for a
//! configured target and `secret:<name>` for an `auth_secret`:
//!
//! ```text
//! kronik secret set relay-signing-key
//! kronik grant webhook-relay http:webhooks.example.com --delivery idempotency-keyed --reason '...'
//! kronik grant webhook-relay secret:relay-signing-key --reason '...'
//! ```

use std::time::Duration;

use kronik_sdk::http::{FetchError, Request};
use kronik_sdk::prelude::*;
use serde::{Deserialize, Serialize};

struct WebhookRelay;

const DEFAULT_TARGET: &str = "https://webhooks.example.com/relay";
const SIGNING_KEY: &str = "relay-signing-key";
const MAX_PAYLOAD_BYTES: usize = 512 * 1024;
const MAX_ATTEMPTS: u32 = 5;
const FIRST_RETRY_MS: u64 = 1000;

#[derive(Serialize, Deserialize)]
struct Config {
    target: String,
    auth_secret: Option<String>,
}

#[derive(Deserialize)]
struct ConfigUpdate {
    target: Option<String>,
    auth_secret: Option<String>,
}

/// What happened to one webhook. Kept in state under `hook/<id>`.
#[derive(Serialize, Deserialize)]
struct Delivery {
    id: String,
    /// `delivered`, `retrying` or `failed`.
    status: String,
    attempts: u32,
    target: String,
    target_status: Option<u16>,
    error: Option<String>,
    received_ms: u64,
    updated_ms: u64,
    next_retry_ms: Option<u64>,
}

#[derive(Serialize)]
struct Forwarded<'a> {
    webhook: &'a str,
    source: &'a str,
    payload: serde_json::Value,
    #[cfg(feature = "body-v2")]
    relay: &'static str,
}

#[derive(Serialize, Deserialize)]
struct Retry {
    id: String,
}

enum Attempt {
    Delivered(u16),
    Retry(String, Option<u16>),
    Fail(String, Option<u16>),
}

impl Actor for WebhookRelay {
    fn describe() -> Manifest {
        Manifest::new("webhook-relay", 0)
            .route(Route::post("/hooks/{key}"))
            .route(Route::get("/hooks/{key}/{id}"))
            .capability("http:webhooks.example.com")
            .capability(format!("secret:{SIGNING_KEY}"))
    }

    fn http(ctx: &mut Ctx, request: HttpRequest) -> Result<Output, HandlerError> {
        match (request.method.as_str(), request.param("id")) {
            ("POST", None) => accept(ctx, &request),
            ("GET", Some(id)) => match ctx.state().get_json::<Delivery>(&record_key(id))? {
                Some(delivery) => Ok(Output::json(200, &delivery)),
                None => Ok(Output::status(404)),
            },
            _ => Ok(Output::status(405)),
        }
    }

    fn message(ctx: &mut Ctx, incoming: Incoming) -> Result<Output, HandlerError> {
        if incoming.msg.name != "configure" {
            return Err(HandlerError::rejected(format!(
                "unknown message {:?}: webhook-relay takes `configure`",
                incoming.msg.name
            )));
        }
        let update: ConfigUpdate = incoming.msg.body_json()?;
        let mut config = config(ctx)?;
        if let Some(target) = update.target {
            if !["https://", "http://", "foreign://"]
                .iter()
                .any(|scheme| target.starts_with(scheme))
            {
                return Err(HandlerError::rejected(format!(
                    "target {target:?} is not an https://, http:// or foreign:// URL"
                )));
            }
            config.target = target;
        }
        if update.auth_secret.is_some() {
            config.auth_secret = update.auth_secret;
        }
        ctx.state().set_json("config", &config)?;
        Ok(Output::reply(Message::json("config", &config)?))
    }

    fn timer(ctx: &mut Ctx, timer: TimerFired) -> Result<Output, HandlerError> {
        let retry: Retry = timer.msg.body_json()?;
        let Some(mut delivery) = ctx.state().get_json::<Delivery>(&record_key(&retry.id))? else {
            return Ok(Output::none());
        };
        let body = ctx.state().get(&body_key(&retry.id));
        match body {
            Some(body) if delivery.status == "retrying" => {
                deliver(ctx, &mut delivery, &body)?;
                Ok(Output::none())
            }
            _ => Ok(Output::none()),
        }
    }
}

/// Accepts a webhook and makes the first delivery attempt.
fn accept(ctx: &Ctx, request: &HttpRequest) -> Result<Output, HandlerError> {
    let raw = request.body_bytes();
    if raw.len() > MAX_PAYLOAD_BYTES {
        return Ok(Output::json(
            413,
            &serde_json::json!({ "error": format!("the webhook body is over {MAX_PAYLOAD_BYTES} bytes") }),
        ));
    }
    let payload = match serde_json::from_slice::<serde_json::Value>(raw) {
        Ok(json) => json,
        Err(_) => match std::str::from_utf8(raw) {
            Ok(text) => serde_json::Value::String(text.to_string()),
            Err(_) => {
                return Ok(Output::json(
                    400,
                    &serde_json::json!({ "error": "the webhook body is neither JSON nor UTF-8 text" }),
                ));
            }
        },
    };
    let id = ctx.causal_id();
    let key = ctx.self_ref().key;
    let body = serde_json::to_vec(&Forwarded {
        webhook: &id,
        source: &key,
        payload,
        #[cfg(feature = "body-v2")]
        relay: "kronik-webhook-relay/2",
    })?;
    let now = ctx.now();
    let mut delivery = Delivery {
        id: id.clone(),
        status: "retrying".to_string(),
        attempts: 0,
        target: config(ctx)?.target,
        target_status: None,
        error: None,
        received_ms: now,
        updated_ms: now,
        next_retry_ms: None,
    };
    ctx.state().set(&body_key(&id), &body);
    deliver(ctx, &mut delivery, &body)?;
    let status = if delivery.status == "delivered" {
        200
    } else {
        502
    };
    Ok(Output::json(status, &delivery))
}

/// Makes one delivery attempt and records its outcome, scheduling the next
/// attempt when the failure may go away.
fn deliver(ctx: &Ctx, delivery: &mut Delivery, body: &[u8]) -> Result<(), Error> {
    let config = config(ctx)?;
    delivery.attempts += 1;
    delivery.updated_ms = ctx.now();
    delivery.target = config.target.clone();
    delivery.next_retry_ms = None;
    let (status, error, target_status) = match attempt(ctx, &delivery.id, body, &config) {
        Attempt::Delivered(code) => ("delivered", None, Some(code)),
        Attempt::Retry(e, code) if delivery.attempts < MAX_ATTEMPTS => {
            let delay = FIRST_RETRY_MS << (delivery.attempts - 1);
            let retry = Message::json(
                "retry",
                &Retry {
                    id: delivery.id.clone(),
                },
            )?;
            ctx.timers().schedule(Duration::from_millis(delay), &retry);
            delivery.next_retry_ms = Some(ctx.now() + delay);
            ("retrying", Some(e), code)
        }
        Attempt::Retry(e, code) | Attempt::Fail(e, code) => ("failed", Some(e), code),
    };
    delivery.status = status.to_string();
    delivery.error = error;
    delivery.target_status = target_status;
    ctx.state().set_json(&record_key(&delivery.id), delivery)?;
    if status != "retrying" {
        ctx.state().delete(&body_key(&delivery.id));
    }
    Ok(())
}

/// Signs and sends the forwarded body once.
fn attempt(ctx: &Ctx, id: &str, body: &[u8], config: &Config) -> Attempt {
    let signature = match ctx.crypto().hmac_sha256(&ctx.secret(SIGNING_KEY), body) {
        Ok(mac) => hex(&mac),
        Err(e) => return Attempt::Fail(e.to_string(), None),
    };
    let mut request = Request::post(config.target.as_str())
        .header("content-type", "application/json")
        .header("x-webhook-id", id)
        .header("x-signature", format!("sha256={signature}"))
        .body(body.to_vec());
    if let Some(name) = &config.auth_secret {
        request = request.secret_header("authorization", &ctx.secret(name.as_str()), "Bearer {}");
    }
    match ctx.http().fetch(&request) {
        Ok(response) if response.is_success() => Attempt::Delivered(response.status),
        Ok(response) if response.status == 429 || response.status >= 500 => Attempt::Retry(
            format!("the target answered {}", response.status),
            Some(response.status),
        ),
        Ok(response) => Attempt::Fail(
            format!("the target answered {}", response.status),
            Some(response.status),
        ),
        Err(
            e @ Error::Fetch(
                FetchError::Network(_) | FetchError::Timeout | FetchError::OutcomeUnknown,
            ),
        ) => Attempt::Retry(e.to_string(), None),
        Err(e) => Attempt::Fail(e.to_string(), None),
    }
}

fn config(ctx: &Ctx) -> Result<Config, Error> {
    Ok(ctx.state().get_json("config")?.unwrap_or_else(|| Config {
        target: DEFAULT_TARGET.to_string(),
        auth_secret: None,
    }))
}

fn record_key(id: &str) -> String {
    format!("hook/{id}")
}

fn body_key(id: &str) -> String {
    format!("hook/{id}/body")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

kronik_sdk::export!(WebhookRelay);
