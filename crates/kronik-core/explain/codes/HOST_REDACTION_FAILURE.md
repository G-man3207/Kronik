Kronik refused to disclose an effect result because it could not safely redact the free data. This is a host-raised trap, not a guest error or a network error. The turn discards its buffered state changes, sends, timers and SQL work; unrelated actors remain usable.

An external request may already have completed. For a new response, Kronik durably records `EFFECT_STATUS_HOST_REDACTION_FAILURE` before terminating the caller. Its HTTP response retains the actual status, but its free headers and body are explicitly withheld. Recovery consumes that recorded failure rather than sending the request again.

A proven unsafe legacy response can also terminate the caller. Its original stored receipt and fingerprint remain unchanged. The new terminal record contains an explicit host-disclosure-failure projection, not another copy of the unsafe plain payload or a claim that the original network request failed. An unavailable key or an incomplete inventory is not proof that a legacy response is unsafe; the existing prerequisite handling still applies.

Inspect the turn and its effects, then resolve the reported redaction resource or data boundary. Do not disable secret matching, discard retained secret versions, or treat a withheld response as an empty successful response. Before resending a dead letter, check whether its external effect already happened; resending is a new attempt and can duplicate that effect.

    kronik dead-letters list

See also: `EFFECT_OUTCOME_UNKNOWN`, `SECRET_UNAVAILABLE`, `dead-letters`.
