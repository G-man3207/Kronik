# Errors from host calls and from the SDK. Every message names a
# `kronik explain` topic, taken from the host's error code when the host's
# message starts with one (`CAPABILITY_NOT_GRANTED: http:api.example.com`).

import re

_CODE = re.compile(r"[A-Z][A-Z0-9_]+")


class KronikError(Exception):
    """An error from a host call or from the SDK. Raised out of a handler, it fails the turn.

    `kind` says what failed and how (such as `fetch.denied` or `sql.syntax`),
    `topic` is its `kronik explain` topic and `payload` the host's error value.
    """

    def __init__(self, kind, what, detail, topic, payload=None):
        super().__init__(f"{what}: {detail} (see `kronik explain {topic}`)" if detail else f"{what} (see `kronik explain {topic}`)")
        self.kind = kind
        self.topic = topic
        self.payload = payload


class Rejected(Exception):
    """Raised out of a handler, refuses the input: the turn fails with
    `handler-error::rejected` and its writes are discarded. Any other
    exception fails it with `handler-error::failed`."""


def explain_topic(message, fallback):
    """The error code that starts a host message such as `CAPABILITY_NOT_GRANTED: ...`, else `fallback`."""
    code = message.split(":", 1)[0]
    return code if ":" in message and _CODE.fullmatch(code) else fallback


_MESSAGES = {
    "sql": {
        "syntax": ("SQL syntax error", "sql-state"),
        "constraint": ("SQL constraint failed", "sql-state"),
        "denied": ("SQL statement denied", "sql-state"),
        "too-large": ("SQL value or database over its size limit", "sql-state"),
    },
    "fetch": {
        "denied": ("HTTP request denied", "capability"),
        "network": ("HTTP request failed", "effect"),
        "timeout": ("HTTP request timed out", "effect"),
        "too-large": ("HTTP response over its size limit", "effect"),
        "outcome-unknown": ("the HTTP request may or may not have reached its target", "EFFECT_OUTCOME_UNKNOWN"),
    },
    "call": {
        "not-found": ("call failed: no actor type is deployed for the callee", "ACTOR_NOT_FOUND"),
        "rejected": ("call rejected by the callee", "TURN_FAILED"),
        "failed": ("call failed in the callee", "TURN_FAILED"),
        "reentrant": ("call refused: the callee is already waiting in this chain of calls", "effect"),
        "timeout": ("call timed out", "effect"),
    },
    "crypto": {
        "denied": ("crypto denied", "secret-handle"),
        "unsupported": ("crypto not supported", "NOT_IMPLEMENTED"),
    },
}


def variant_tag(value):
    """The WIT case of a componentize-py variant value: `FetchError_OutcomeUnknown` is `outcome-unknown`."""
    name = type(value).__name__
    case = name.split("_", 1)[1] if "_" in name else name
    return re.sub(r"(?<!^)(?=[A-Z])", "-", case).lower()


def host_error(area, payload):
    """Turns the error value of a failing host call (`Err.value`) into a KronikError.

    `payload` is a WIT variant for `sql`, `fetch`, `call` and `crypto`, a string for `reveal`.
    """
    if area == "reveal":
        detail = str(payload)
        return KronikError("reveal", "revealing the secret failed", detail, explain_topic(detail, "secret-handle"), payload)
    tag = variant_tag(payload)
    known = _MESSAGES[area].get(tag)
    if known is None:
        return KronikError(f"{area}.unknown", f"{area} failed", repr(payload), "effect", payload)
    detail = getattr(payload, "value", "")
    detail = detail if isinstance(detail, str) else ""
    what, topic = known
    return KronikError(f"{area}.{tag}", what, detail, explain_topic(detail, topic), payload)
