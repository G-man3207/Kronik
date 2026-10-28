package test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"kronik.dev/sdk/testkit"
)

const (
	target     = "https://webhooks.example.com/relay"
	signingKey = "test-signing-key"
)

type delivery struct {
	ID           string  `json:"id"`
	Status       string  `json:"status"`
	Attempts     int     `json:"attempts"`
	TargetStatus *int    `json:"target_status"`
	Error        *string `json:"error"`
	NextRetryMs  *int64  `json:"next_retry_ms"`
}

// relayHost is a host with the relay's grants and secrets, as an operator
// sets them up.
func relayHost(t *testing.T) *testkit.TestHost {
	host := testkit.Start(t, testkit.Options{Dir: ".."})
	host.Secret("relay-signing-key", signingKey)
	host.Secret("relay-auth", "tok-123")
	host.Grant("webhook-relay", "secret:relay-signing-key", "")
	host.Grant("webhook-relay", "secret:relay-auth", "")
	host.Grant("webhook-relay", "http:webhooks.example.com", "idempotency-keyed")
	return host
}

func TestAWebhookIsForwardedSignedWithTheSecretInsertedByTheHost(t *testing.T) {
	host := relayHost(t)
	host.Send("webhook-relay/acme", "configure", `{"auth_secret":"relay-auth"}`)
	host.Stub(testkit.Stub{URL: target, Status: 202})

	res := host.HTTP("POST", "/hooks/acme", map[string]any{"event": "paid", "amount": 42})
	if res.Status != 200 {
		t.Fatalf("status %d: %s", res.Status, res.Text())
	}
	var d delivery
	res.JSON(&d)
	if d.Status != "delivered" || d.TargetStatus == nil || *d.TargetStatus != 202 {
		t.Fatalf("delivery %+v", d)
	}

	sent := host.Requests(false)
	if len(sent) != 1 {
		t.Fatalf("%d requests sent", len(sent))
	}
	req := sent[0]
	if req.URL != target {
		t.Fatalf("url %s", req.URL)
	}
	var body any
	if err := json.Unmarshal(req.Body, &body); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"webhook": d.ID, "source": "acme", "payload": map[string]any{"event": "paid", "amount": 42.0}}
	if !reflect.DeepEqual(body, want) {
		t.Fatalf("body %s", req.Body)
	}
	mac := hmac.New(sha256.New, []byte(signingKey))
	mac.Write(req.Body)
	for name, want := range map[string]string{
		"x-webhook-id":  d.ID,
		"x-signature":   "sha256=" + hex.EncodeToString(mac.Sum(nil)),
		"authorization": "Bearer tok-123",
	} {
		if got, _ := req.Header(name); got != want {
			t.Fatalf("%s: %q, want %q", name, got, want)
		}
	}
	if key, _ := req.Header("idempotency-key"); len(key) != 64 {
		t.Fatalf("idempotency-key %q", key)
	}

	// The record stays readable.
	var again delivery
	host.HTTP("GET", "/hooks/acme/"+d.ID, nil).JSON(&again)
	if again.Status != "delivered" {
		t.Fatalf("record %+v", again)
	}
	if res := host.HTTP("GET", "/hooks/acme/nope", nil); res.Status != 404 {
		t.Fatalf("unknown webhook: %d", res.Status)
	}
}

func TestAFailureThatMayGoAwayIsRetriedByATimer(t *testing.T) {
	host := relayHost(t)
	host.Stub(testkit.Stub{URL: target, Status: 200})
	host.Stub(testkit.Stub{URL: target, Status: 503, Times: 1})

	first := host.HTTP("POST", "/hooks/acme", "plain text")
	if first.Status != 502 {
		t.Fatalf("status %d", first.Status)
	}
	var d delivery
	first.JSON(&d)
	if d.Status != "retrying" || d.Attempts != 1 || d.TargetStatus == nil || *d.TargetStatus != 503 {
		t.Fatalf("delivery %+v", d)
	}
	now := host.Advance(0)
	if d.NextRetryMs == nil || *d.NextRetryMs != now+1000 {
		t.Fatalf("next retry %v, now %d", d.NextRetryMs, now)
	}

	host.Advance(999)
	if n := len(host.Requests(false)); n != 1 {
		t.Fatalf("%d requests before the retry is due", n)
	}
	host.Advance(1)
	var retried delivery
	host.HTTP("GET", "/hooks/acme/"+d.ID, nil).JSON(&retried)
	if retried.Status != "delivered" || retried.Attempts != 2 {
		t.Fatalf("after the retry %+v", retried)
	}
	sent := host.Requests(false)
	if len(sent) != 2 || string(sent[0].Body) != string(sent[1].Body) {
		t.Fatalf("not the same request twice: %d requests", len(sent))
	}
	var body struct {
		Payload any `json:"payload"`
	}
	if err := json.Unmarshal(sent[0].Body, &body); err != nil || body.Payload != "plain text" {
		t.Fatalf("payload %s", sent[0].Body)
	}
}

func TestATargetOutsideTheGrantsFailsAtOnce(t *testing.T) {
	host := relayHost(t)
	host.Send("webhook-relay/acme", "configure", `{"target":"https://elsewhere.example.com/x"}`)
	res := host.HTTP("POST", "/hooks/acme", map[string]any{})
	if res.Status != 502 {
		t.Fatalf("status %d", res.Status)
	}
	var d delivery
	res.JSON(&d)
	if d.Status != "failed" || d.Error == nil || !strings.Contains(*d.Error, "CAPABILITY_NOT_GRANTED") {
		t.Fatalf("delivery %+v", d)
	}
	if n := len(host.Requests(false)); n != 0 {
		t.Fatalf("%d requests sent", n)
	}
}

func TestAnUnknownMessageIsRejected(t *testing.T) {
	host := relayHost(t)
	res := host.API("POST", "/v1/actors/webhook-relay/acme/messages", map[string]any{"name": "nope", "text": "", "reason": "test"})
	var answer struct {
		Outcome struct {
			Kind    string `json:"kind"`
			Message string `json:"message"`
		} `json:"outcome"`
	}
	_ = json.Unmarshal(res.Body, &answer)
	if answer.Outcome.Kind != "rejected" || !strings.Contains(string(res.Body), "webhook-relay takes `configure`") {
		t.Fatalf("answer %d %s", res.Status, res.Body)
	}
}
