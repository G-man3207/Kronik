// Errors from host calls and from the SDK. Every message names a
// `kronik explain` topic, taken from the host's error code when the host's
// message starts with one (`CAPABILITY_NOT_GRANTED: http:api.example.com`).

package kronik

import (
	"errors"
	"fmt"
	"strings"
)

// Error is an error from a host call or from the SDK. Returned from a
// handler, it fails the turn.
type Error struct {
	// Kind says what failed and how, such as "fetch.denied" or "sql.syntax".
	Kind string
	// Topic is the `kronik explain` topic for it.
	Topic string
	// Payload is the host's error value, if the error came from a host call.
	Payload any
	message string
}

func (e *Error) Error() string { return e.message }

func newError(kind, what, detail, topic string, payload any) *Error {
	msg := what
	if detail != "" {
		msg = what + ": " + detail
	}
	return &Error{Kind: kind, Topic: topic, Payload: payload, message: fmt.Sprintf("%s (see `kronik explain %s`)", msg, topic)}
}

// RejectedError refuses an input; see [Rejected].
type RejectedError struct{ Message string }

func (e *RejectedError) Error() string { return e.Message }

// Rejected returns an error that, returned from a handler, refuses the
// input: the turn fails with handler-error::rejected and its writes are
// discarded. Any other error fails it with handler-error::failed.
func Rejected(message string) error { return &RejectedError{Message: message} }

// IsRejected reports whether err is or wraps a [Rejected] error.
func IsRejected(err error) bool {
	var r *RejectedError
	return errors.As(err, &r)
}

// explainTopic is the error code that starts a host message such as
// `CAPABILITY_NOT_GRANTED: ...`, else fallback.
func explainTopic(message, fallback string) string {
	code, _, found := strings.Cut(message, ":")
	if !found || len(code) < 2 || code[0] < 'A' || code[0] > 'Z' {
		return fallback
	}
	for i := 1; i < len(code); i++ {
		c := code[i]
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return fallback
		}
	}
	return code
}

var hostMessages = map[string]map[string][2]string{
	"sql": {
		"syntax":     {"SQL syntax error", "sql-state"},
		"constraint": {"SQL constraint failed", "sql-state"},
		"denied":     {"SQL statement denied", "sql-state"},
		"too-large":  {"SQL value or database over its size limit", "sql-state"},
	},
	"fetch": {
		"denied":          {"HTTP request denied", "capability"},
		"network":         {"HTTP request failed", "effect"},
		"timeout":         {"HTTP request timed out", "effect"},
		"too-large":       {"HTTP response over its size limit", "effect"},
		"outcome-unknown": {"the HTTP request may or may not have reached its target", "EFFECT_OUTCOME_UNKNOWN"},
	},
	"call": {
		"not-found": {"call failed: no actor type is deployed for the callee", "ACTOR_NOT_FOUND"},
		"rejected":  {"call rejected by the callee", "TURN_FAILED"},
		"failed":    {"call failed in the callee", "TURN_FAILED"},
		"reentrant": {"call refused: the callee is already waiting in this chain of calls", "effect"},
		"timeout":   {"call timed out", "effect"},
	},
	"crypto": {
		"denied":      {"crypto denied", "secret-handle"},
		"unsupported": {"crypto not supported", "NOT_IMPLEMENTED"},
	},
}

// hostError turns a WIT error variant of area (its case name tag and its
// string value, if any) into an [*Error].
func hostError(area, tag, detail string, payload any) *Error {
	known, ok := hostMessages[area][tag]
	if !ok {
		return newError(area+".unknown", area+" failed", tag, "effect", payload)
	}
	return newError(area+"."+tag, known[0], detail, explainTopic(detail, known[1]), payload)
}

func revealError(detail string) *Error {
	return newError("reveal", "revealing the secret failed", detail, explainTopic(detail, "secret-handle"), detail)
}
