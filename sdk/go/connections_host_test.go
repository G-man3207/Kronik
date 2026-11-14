//go:build kronikhost

// The testkit's connections against a real test host (`kronik test-host`)
// and the room guest (tests/guests/room). They need a kronik binary in
// KRONIK_BIN: scripts/ci.sh sdks runs them with -tags kronikhost after it
// builds one.
package kronik_test

import (
	"path/filepath"
	"strings"
	"testing"

	"kronik.dev/sdk/testkit"
)

func room(t *testing.T) *testkit.TestHost {
	t.Helper()
	wasm, err := filepath.Abs("../../tests/guests/room.wasm")
	if err != nil {
		t.Fatal(err)
	}
	return testkit.Start(t, testkit.Options{NoDir: true, Wasm: []string{wasm}})
}

func TestATestPlaysTheClient(t *testing.T) {
	host := room(t)
	ada := host.OpenConnection("/room/lobby/ws?user=ada")
	if !ada.Accepted() || ada.Response.Status != 101 {
		t.Fatalf("open: %d %s", ada.Response.Status, ada.Response.Text())
	}
	var welcome struct{ Type string }
	sent := host.FramesSent(ada, true)
	if len(sent.Frames) != 1 {
		t.Fatalf("welcome: %+v", sent)
	}
	sent.Frames[0].JSON(&welcome)
	if welcome.Type != "welcome" {
		t.Fatalf("welcome: %+v", welcome)
	}

	host.SendFrame(ada, "echo hi")
	host.SendFrame(ada, []byte("binary raw"))
	sent = host.FramesSent(ada, true)
	if len(sent.Frames) != 2 || sent.Frames[0].Kind != "text" || sent.Frames[0].Text() != "hi" ||
		sent.Frames[1].Kind != "binary" || sent.Frames[1].Text() != "raw" || sent.Closed != nil {
		t.Fatalf("echoes: %+v", sent)
	}

	host.SendFrame(ada, "say hello")
	sent = host.FramesSent(ada, true)
	if len(sent.Frames) != 1 || sent.Frames[0].Kind != "event" || sent.Frames[0].Event != "message" || sent.Frames[0].ID != "1" {
		t.Fatalf("message: %+v", sent)
	}

	host.CloseConnection(ada, testkit.Close{Initiator: "host", Cause: "restart"})
	if closed := host.FramesSent(ada, false).Closed; closed == nil || *closed != (testkit.Closed{Code: 1012, Reason: "restart"}) {
		t.Fatalf("closed: %+v", closed)
	}

	bob := host.OpenConnection("/room/lobby/ws?user=bob")
	host.CloseConnection(bob, testkit.Close{Code: 4001, Reason: "done"})
	closes := host.HTTP("GET", "/room/lobby/closes", nil).Text()
	for _, want := range []string{ada.ID + " host 1012 restart", bob.ID + " client 4001 done"} {
		if !strings.Contains(closes, want) {
			t.Errorf("%q not in %q", want, closes)
		}
	}

	refused := host.OpenConnection("/room/lobby/ws?user=cy&deny=1")
	if refused.Accepted() || refused.Response.Status != 403 {
		t.Fatalf("refused: %d", refused.Response.Status)
	}
	stream := host.OpenConnection("/room/lobby/events", testkit.ConnectionOptions{Protocol: "sse", Headers: []testkit.Header{{"last-event-id", "0"}}})
	if got := host.FramesSent(stream, false).Frames; len(got) != 1 || got[0].ID != "1" {
		t.Fatalf("stream: %+v", got)
	}
}
