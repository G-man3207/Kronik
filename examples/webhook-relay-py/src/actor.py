# webhook-relay-py: relays webhooks to a target, signed, with retries. The
# Python twin of webhook-relay-ts, with the same routes, messages, records
# and forwarded requests.
#
# An actor `webhook-relay/<key>` accepts webhooks for one source and
# forwards each one to its target with `ctx.http.fetch`, signed with
# `ctx.crypto.hmac_sha256`. It records every delivery in its state and
# retries failures that may go away with a timer.
#
# - `POST /hooks/{key}` accepts a webhook (any body of at most 512 KiB) and
#   forwards it at once. The answer is the delivery record: `200` when the
#   target accepted it, else `502`.
# - `GET /hooks/{key}/{id}` returns the delivery record of one webhook.
# - The message `configure` with `{"target": "...", "auth_secret": "..."}`
#   (both optional) sets the target URL and the secret for an
#   `authorization: Bearer <secret>` header. The default target is
#   `https://webhooks.example.com/relay`.
#
# The forwarded request is `POST <target>` with
#
# - `content-type: application/json`;
# - `x-webhook-id: <id>`, the same in every attempt, so the target can drop
#   duplicates; `<id>` is the causal id of the turn that accepted it;
# - `x-signature: sha256=<hex>`, the HMAC-SHA256 of the body with the secret
#   `relay-signing-key`, computed by the host;
# - `authorization: Bearer <secret>` if `auth_secret` is set, inserted by the
#   host, so the value never reaches the actor;
# - the body `{"webhook": "<id>", "source": "<key>", "payload": <the webhook
#   body as JSON, or as a string if it is not JSON>}`.
#
# The host adds an `Idempotency-Key` and records the request and its
# response. Outcomes: a 2xx answer is `delivered`. A network error, a
# timeout, an unknown outcome (after a crash, for a target granted as
# `unsafe`), a 5xx or a 429 is `retrying`: a timer tries again after 1, 2, 4
# and 8 seconds, and after 5 attempts the webhook is `failed`. Anything else,
# such as a 4xx, a missing grant or a missing secret, is `failed` at once.
# The actor answers with the record either way, so its turn commits and the
# record and the retry timer are kept.
#
# The operator grants what the manifest asks for, plus `http:<host>` for a
# configured target and `secret:<name>` for an `auth_secret`:
#
#     kronik secret set relay-signing-key
#     kronik grant webhook-relay http:webhooks.example.com --delivery idempotency-keyed --reason '...'
#     kronik grant webhook-relay secret:relay-signing-key --reason '...'

import json

from kronik import KronikError, Rejected, actor

DEFAULT_TARGET = "https://webhooks.example.com/relay"
SIGNING_KEY = "relay-signing-key"
MAX_PAYLOAD_BYTES = 512 * 1024
MAX_ATTEMPTS = 5
FIRST_RETRY_MS = 1000
# Fetch errors that may go away on a later attempt.
RETRYABLE = ("fetch.network", "fetch.timeout", "fetch.outcome-unknown")


def config(ctx):
    cfg = ctx.state.get_json("config")
    return {"target": DEFAULT_TARGET, "auth_secret": None} if cfg is None else cfg


def accept(req, ctx):
    """Accepts a webhook and makes the first delivery attempt."""
    if len(req.body) > MAX_PAYLOAD_BYTES:
        return ctx.json(413, {"error": f"the webhook body is over {MAX_PAYLOAD_BYTES} bytes"})
    try:
        payload = req.json()
    except KronikError:
        try:
            payload = req.text()
        except KronikError:
            return ctx.json(400, {"error": "the webhook body is neither JSON nor UTF-8 text"})
    webhook_id = ctx.causal_id()
    body = json.dumps(
        {"webhook": webhook_id, "source": ctx.self().key, "payload": payload},
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    now = ctx.now()
    # What happened to one webhook. Kept in state under `hook/<id>`.
    delivery = {
        "id": webhook_id,
        "status": "retrying",
        "attempts": 0,
        "target": config(ctx)["target"],
        "target_status": None,
        "error": None,
        "received_ms": now,
        "updated_ms": now,
        "next_retry_ms": None,
    }
    ctx.state.set(f"hook/{webhook_id}/body", body)
    deliver(ctx, delivery, body)
    return ctx.json(200 if delivery["status"] == "delivered" else 502, delivery)


def deliver(ctx, delivery, body):
    """Makes one delivery attempt and records its outcome, scheduling the
    next attempt when the failure may go away."""
    cfg = config(ctx)
    delivery["attempts"] += 1
    delivery["updated_ms"] = ctx.now()
    delivery["target"] = cfg["target"]
    delivery["next_retry_ms"] = None
    outcome, error, code = attempt(ctx, delivery["id"], body, cfg)
    if outcome == "delivered":
        delivery["status"] = "delivered"
        delivery["error"] = None
    elif outcome == "retry" and delivery["attempts"] < MAX_ATTEMPTS:
        delay = FIRST_RETRY_MS * 2 ** (delivery["attempts"] - 1)
        ctx.timers.schedule(delay, {"name": "retry", "body": {"id": delivery["id"]}})
        delivery["next_retry_ms"] = ctx.now() + delay
        delivery["status"] = "retrying"
        delivery["error"] = error
    else:
        delivery["status"] = "failed"
        delivery["error"] = error
    delivery["target_status"] = code
    ctx.state.set_json(f"hook/{delivery['id']}", delivery)
    if delivery["status"] != "retrying":
        ctx.state.delete(f"hook/{delivery['id']}/body")


def attempt(ctx, webhook_id, body, cfg):
    """Signs and sends the forwarded body once: (outcome, error, target status)."""
    try:
        signature = ctx.crypto.hmac_sha256(ctx.secret(SIGNING_KEY), body).hex()
        headers = {
            "content-type": "application/json",
            "x-webhook-id": webhook_id,
            "x-signature": f"sha256={signature}",
        }
        if cfg["auth_secret"] is not None:
            headers["authorization"] = ctx.secret(cfg["auth_secret"]).header("Bearer {}")
        response = ctx.http.fetch({"method": "POST", "url": cfg["target"], "headers": headers, "body": body})
    except KronikError as e:
        return ("retry" if e.kind in RETRYABLE else "fail"), str(e), None
    if response.ok:
        return "delivered", None, response.status
    retry = response.status == 429 or response.status >= 500
    return ("retry" if retry else "fail"), f"the target answered {response.status}", response.status


def http(req, ctx):
    hook_id = req.param("id")
    if req.method == "POST" and hook_id is None:
        return accept(req, ctx)
    if req.method == "GET" and hook_id is not None:
        delivery = ctx.state.get_json(f"hook/{hook_id}")
        return ctx.status(404) if delivery is None else ctx.json(200, delivery)
    return ctx.status(405)


def message(msg, ctx):
    if msg.name != "configure":
        raise Rejected(f"unknown message {json.dumps(msg.name, ensure_ascii=False)}: webhook-relay takes `configure`")
    update = msg.json()
    if not isinstance(update, dict):
        update = {}  # as in webhook-relay-ts, where a non-object has no fields
    cfg = config(ctx)
    target = update.get("target")
    if isinstance(target, str):
        if not target.startswith(("https://", "http://", "foreign://")):
            raise Rejected(f"target {json.dumps(target, ensure_ascii=False)} is not an https://, http:// or foreign:// URL")
        cfg["target"] = target
    if isinstance(update.get("auth_secret"), str):
        cfg["auth_secret"] = update["auth_secret"]
    ctx.state.set_json("config", cfg)
    return ctx.reply({"name": "config", "body": cfg})


def timer(timer, ctx):
    hook_id = timer.message.json()["id"]
    delivery = ctx.state.get_json(f"hook/{hook_id}")
    body = ctx.state.get(f"hook/{hook_id}/body")
    if delivery is not None and body is not None and delivery["status"] == "retrying":
        deliver(ctx, delivery, body)
    return ctx.none()


handler = actor(
    kind="webhook-relay",
    schema_version=0,
    routes=[
        {"method": "POST", "pattern": "/hooks/{key}"},
        {"method": "GET", "pattern": "/hooks/{key}/{id}"},
    ],
    capabilities=["http:webhooks.example.com", f"secret:{SIGNING_KEY}"],
    http=http,
    message=message,
    timer=timer,
)
