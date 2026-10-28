// webhook-relay-go: relays webhooks to a target, signed, with retries. The
// Go twin of webhook-relay-ts, with the same routes, messages, records and
// forwarded requests.
//
// An actor webhook-relay/<key> accepts webhooks for one source and forwards
// each one to its target with ctx.HTTP.Fetch, signed with
// ctx.Crypto.HMACSHA256. It records every delivery in its state and retries
// failures that may go away with a timer.
//
//   - POST /hooks/{key} accepts a webhook (any body of at most 512 KiB) and
//     forwards it at once. The answer is the delivery record: 200 when the
//     target accepted it, else 502.
//   - GET /hooks/{key}/{id} returns the delivery record of one webhook.
//   - The message configure with {"target": "...", "auth_secret": "..."}
//     (both optional) sets the target URL and the secret for an
//     "authorization: Bearer <secret>" header. The default target is
//     https://webhooks.example.com/relay.
//
// The forwarded request is POST <target> with
//
//   - content-type: application/json;
//   - x-webhook-id: <id>, the same in every attempt, so the target can drop
//     duplicates; <id> is the causal id of the turn that accepted it;
//   - x-signature: sha256=<hex>, the HMAC-SHA256 of the body with the
//     secret relay-signing-key, computed by the host;
//   - authorization: Bearer <secret> if auth_secret is set, inserted by the
//     host, so the value never reaches the actor;
//   - the body {"webhook": "<id>", "source": "<key>", "payload": <the
//     webhook body as JSON, or as a string if it is not JSON>}.
//
// The host adds an Idempotency-Key and records the request and its
// response. Outcomes: a 2xx answer is delivered. A network error, a
// timeout, an unknown outcome (after a crash, for a target granted as
// unsafe), a 5xx or a 429 is retrying: a timer tries again after 1, 2, 4
// and 8 seconds, and after 5 attempts the webhook is failed. Anything else,
// such as a 4xx, a missing grant or a missing secret, is failed at once.
// The actor answers with the record either way, so its turn commits and the
// record and the retry timer are kept.
//
// The operator grants what the manifest asks for, plus http:<host> for a
// configured target and secret:<name> for an auth_secret:
//
//	kronik secret set relay-signing-key
//	kronik grant webhook-relay http:webhooks.example.com --delivery idempotency-keyed --reason '...'
//	kronik grant webhook-relay secret:relay-signing-key --reason '...'
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"kronik.dev/sdk"
)

const (
	defaultTarget   = "https://webhooks.example.com/relay"
	signingKey      = "relay-signing-key"
	maxPayloadBytes = 512 * 1024
	maxAttempts     = 5
	firstRetryMs    = 1000
)

// config is the relay's configuration, kept in state under "config".
type config struct {
	Target     string  `json:"target"`
	AuthSecret *string `json:"auth_secret"`
}

// delivery is what happened to one webhook, kept in state under hook/<id>.
type delivery struct {
	ID           string  `json:"id"`
	Status       string  `json:"status"`
	Attempts     int     `json:"attempts"`
	Target       string  `json:"target"`
	TargetStatus *int    `json:"target_status"`
	Error        *string `json:"error"`
	ReceivedMs   int64   `json:"received_ms"`
	UpdatedMs    int64   `json:"updated_ms"`
	NextRetryMs  *int64  `json:"next_retry_ms"`
}

// toJSON writes v as JSON.stringify does: compact, without HTML escaping.
func toJSON(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'}), nil
}

func loadConfig(ctx *kronik.Ctx) (config, error) {
	cfg := config{Target: defaultTarget}
	_, err := ctx.State.GetJSON("config", &cfg)
	return cfg, err
}

func accept(req *kronik.Request, ctx *kronik.Ctx) (kronik.Output, error) {
	if len(req.Body) > maxPayloadBytes {
		return ctx.JSON(413, map[string]string{"error": fmt.Sprintf("the webhook body is over %d bytes", maxPayloadBytes)})
	}
	// The payload as JSON (compacted, keys in their order), else as text.
	var payload json.RawMessage
	var compact bytes.Buffer
	if json.Valid(req.Body) && json.Compact(&compact, req.Body) == nil {
		payload = compact.Bytes()
	} else if utf8.Valid(req.Body) {
		text, err := toJSON(string(req.Body))
		if err != nil {
			return kronik.Output{}, err
		}
		payload = text
	} else {
		return ctx.JSON(400, map[string]string{"error": "the webhook body is neither JSON nor UTF-8 text"})
	}
	id := ctx.CausalID()
	body, err := toJSON(struct {
		Webhook string          `json:"webhook"`
		Source  string          `json:"source"`
		Payload json.RawMessage `json:"payload"`
	}{id, ctx.Self().Key, payload})
	if err != nil {
		return kronik.Output{}, err
	}
	cfg, err := loadConfig(ctx)
	if err != nil {
		return kronik.Output{}, err
	}
	now := ctx.Now().UnixMilli()
	d := delivery{ID: id, Status: "retrying", Target: cfg.Target, ReceivedMs: now, UpdatedMs: now}
	ctx.State.Set("hook/"+id+"/body", body)
	if err := deliver(ctx, &d, body); err != nil {
		return kronik.Output{}, err
	}
	status := 502
	if d.Status == "delivered" {
		status = 200
	}
	return ctx.JSON(status, d)
}

// deliver makes one delivery attempt and records its outcome, scheduling
// the next attempt when the failure may go away.
func deliver(ctx *kronik.Ctx, d *delivery, body []byte) error {
	cfg, err := loadConfig(ctx)
	if err != nil {
		return err
	}
	d.Attempts++
	d.UpdatedMs = ctx.Now().UnixMilli()
	d.Target = cfg.Target
	d.NextRetryMs = nil
	outcome, why, code := attempt(ctx, d.ID, body, cfg)
	switch {
	case outcome == "delivered":
		d.Status, d.Error = "delivered", nil
	case outcome == "retry" && d.Attempts < maxAttempts:
		delay := int64(firstRetryMs) << (d.Attempts - 1)
		if _, err := ctx.Timers.Schedule(time.Duration(delay)*time.Millisecond, kronik.OutgoingMessage{
			Name: "retry",
			Body: map[string]string{"id": d.ID},
		}); err != nil {
			return err
		}
		next := ctx.Now().UnixMilli() + delay
		d.NextRetryMs, d.Status, d.Error = &next, "retrying", &why
	default:
		d.Status, d.Error = "failed", &why
	}
	d.TargetStatus = code
	if err := ctx.State.SetJSON("hook/"+d.ID, d); err != nil {
		return err
	}
	if d.Status != "retrying" {
		ctx.State.Delete("hook/" + d.ID + "/body")
	}
	return nil
}

// attempt signs and sends the forwarded body once: the outcome ("delivered",
// "retry" or "fail"), the error and the target's status.
func attempt(ctx *kronik.Ctx, id string, body []byte, cfg config) (string, string, *int) {
	failure := func(err error) (string, string, *int) {
		var e *kronik.Error
		if errors.As(err, &e) && (e.Kind == "fetch.network" || e.Kind == "fetch.timeout" || e.Kind == "fetch.outcome-unknown") {
			return "retry", err.Error(), nil
		}
		return "fail", err.Error(), nil
	}
	signature, err := ctx.Crypto.HMACSHA256(ctx.Secret(signingKey), body)
	if err != nil {
		return failure(err)
	}
	headers := []kronik.FetchHeader{
		{Name: "content-type", Value: "application/json"},
		{Name: "x-webhook-id", Value: id},
		{Name: "x-signature", Value: "sha256=" + hex.EncodeToString(signature)},
	}
	if cfg.AuthSecret != nil {
		headers = append(headers, kronik.FetchHeader{Name: "authorization", Secret: ctx.Secret(*cfg.AuthSecret).Header("Bearer {}")})
	}
	res, err := ctx.HTTP.Fetch(kronik.FetchRequest{Method: "POST", URL: cfg.Target, Headers: headers, Body: body})
	if err != nil {
		return failure(err)
	}
	status := res.Status
	if res.OK() {
		return "delivered", "", &status
	}
	outcome := "fail"
	if status == 429 || status >= 500 {
		outcome = "retry"
	}
	return outcome, fmt.Sprintf("the target answered %d", status), &status
}

func handleHTTP(req *kronik.Request, ctx *kronik.Ctx) (kronik.Output, error) {
	id, hasID := req.Param("id")
	switch {
	case req.Method == "POST" && !hasID:
		return accept(req, ctx)
	case req.Method == "GET" && hasID:
		var d delivery
		found, err := ctx.State.GetJSON("hook/"+id, &d)
		if err != nil {
			return kronik.Output{}, err
		}
		if !found {
			return ctx.Status(404)
		}
		return ctx.JSON(200, d)
	}
	return ctx.Status(405)
}

func quote(s string) string {
	q, _ := toJSON(s)
	return string(q)
}

func handleMessage(msg *kronik.Message, ctx *kronik.Ctx) (kronik.Output, error) {
	if msg.Name != "configure" {
		return kronik.Output{}, kronik.Rejected(fmt.Sprintf("unknown message %s: webhook-relay takes `configure`", quote(msg.Name)))
	}
	var body any
	if err := msg.JSON(&body); err != nil {
		return kronik.Output{}, err
	}
	// As in webhook-relay-ts, a body that is not an object has no fields.
	update, _ := body.(map[string]any)
	cfg, err := loadConfig(ctx)
	if err != nil {
		return kronik.Output{}, err
	}
	if target, ok := update["target"].(string); ok {
		if !strings.HasPrefix(target, "https://") && !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "foreign://") {
			return kronik.Output{}, kronik.Rejected(fmt.Sprintf("target %s is not an https://, http:// or foreign:// URL", quote(target)))
		}
		cfg.Target = target
	}
	if secret, ok := update["auth_secret"].(string); ok {
		cfg.AuthSecret = &secret
	}
	if err := ctx.State.SetJSON("config", cfg); err != nil {
		return kronik.Output{}, err
	}
	return ctx.Reply(kronik.OutgoingMessage{Name: "config", Body: cfg})
}

func handleTimer(timer kronik.Timer, ctx *kronik.Ctx) (kronik.Output, error) {
	var ref struct {
		ID string `json:"id"`
	}
	if err := timer.Message.JSON(&ref); err != nil {
		return kronik.Output{}, err
	}
	var d delivery
	found, err := ctx.State.GetJSON("hook/"+ref.ID, &d)
	if err != nil {
		return kronik.Output{}, err
	}
	body, hasBody := ctx.State.Get("hook/" + ref.ID + "/body")
	if found && hasBody && d.Status == "retrying" {
		if err := deliver(ctx, &d, body); err != nil {
			return kronik.Output{}, err
		}
	}
	return ctx.None()
}

func init() {
	kronik.Export(kronik.Actor{
		Kind:          "webhook-relay",
		SchemaVersion: 0,
		Routes: []kronik.Route{
			{Method: "POST", Pattern: "/hooks/{key}"},
			{Method: "GET", Pattern: "/hooks/{key}/{id}"},
		},
		Capabilities: []string{"http:webhooks.example.com", "secret:" + signingKey},
		HTTP:         handleHTTP,
		Message:      handleMessage,
		Timer:        handleTimer,
	})
}

func main() {}
