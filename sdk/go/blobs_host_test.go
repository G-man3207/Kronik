//go:build kronikhost

// The SDK's blobs (M25) in an actor that `kronik build` makes from
// testdata/files, run by a test host (`kronik test-host`). They need a
// kronik binary in KRONIK_BIN: scripts/ci.sh sdks runs them with
// -tags kronikhost after it builds one.
package kronik_test

import (
	"bytes"
	"net/url"
	"testing"

	"kronik.dev/sdk/testkit"
)

const mib = 1 << 20

func pattern(from, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(((from+i)*31 + 7) % 251)
	}
	return out
}

// checksum is the fixture's probe: every 4093th byte, weighted by its place.
func checksum(b []byte) uint64 {
	var s uint64
	for i := 0; i < len(b); i += 4093 {
		s = (s + uint64(b[i])*uint64((i/4093)%7+1)) % 1_000_000_007
	}
	return s
}

type info struct {
	Blob     bool   `json:"blob"`
	Size     int    `json:"size"`
	Range    []int  `json:"range"`
	Streamed uint64 `json:"streamed"`
	Whole    uint64 `json:"whole"`
}

func want(b []byte, blob bool) info {
	return info{Blob: blob, Size: len(b), Range: []int{int(b[2]), int(b[3]), int(b[4]), int(b[5])}, Streamed: checksum(b), Whole: checksum(b)}
}

func TestBlobsInAnActor(t *testing.T) {
	host := testkit.Start(t, testkit.Options{Dir: "testdata/files"})
	host.Grant("files", "http:store.test", "")

	// A small body stays inline; one above the blob threshold (1 MiB) is a
	// blob: read in a range, with a reader and whole.
	for _, c := range []struct {
		body []byte
		blob bool
	}{{pattern(0, 100), false}, {pattern(0, mib+mib/2), true}} {
		var got info
		res := host.HTTP("POST", "/files/a/info", c.body)
		if res.Status != 200 {
			t.Fatalf("info of %d bytes: %d %s", len(c.body), res.Status, res.Text())
		}
		res.JSON(&got)
		if w := want(c.body, c.blob); got.Blob != w.Blob || got.Size != w.Size || got.Streamed != w.Streamed || got.Whole != w.Whole ||
			len(got.Range) != 4 || got.Range[0] != w.Range[0] || got.Range[3] != w.Range[3] {
			t.Fatalf("info of %d bytes: %+v, want %+v", len(c.body), got, w)
		}
	}

	// Answering with the blob it got.
	big := pattern(0, mib+mib/2)
	echo := host.HTTP("POST", "/files/a/echo", big, testkit.Header{"content-type", "application/x-test"})
	if ct, _ := echo.Header("content-type"); echo.Status != 200 || echo.Blob == nil || echo.Blob.Size != uint64(len(big)) ||
		ct != "application/x-test" || !bytes.Equal(echo.Body, big) {
		t.Fatalf("echo: %d %+v %q", echo.Status, echo.Blob, ct)
	}

	// A blob written in parts that are not whole frames.
	written := host.HTTP("POST", "/files/a/write?size=1310720", nil)
	if written.Blob == nil || written.Blob.Size != 1310720 || !bytes.Equal(written.Body, pattern(0, 1310720)) {
		t.Fatalf("write: %d %+v", written.Status, written.Blob)
	}

	// The blob it got as a fetch's body; the fetch's large answer is a blob.
	answer := pattern(7, mib+mib/4)
	host.Stub(testkit.Stub{URL: "http://store.test/up", Body: answer})
	var relayed struct {
		Status int    `json:"status"`
		Blob   bool   `json:"blob"`
		Size   int    `json:"size"`
		Sum    uint64 `json:"sum"`
	}
	host.HTTP("POST", "/files/a/relay?url="+url.QueryEscape("http://store.test/up"), big).JSON(&relayed)
	if relayed.Status != 200 || !relayed.Blob || relayed.Size != len(answer) || relayed.Sum != checksum(answer) {
		t.Fatalf("relay: %+v", relayed)
	}
	sent := host.Requests(false)
	if len(sent) != 1 || sent[0].Method != "POST" || !bytes.Equal(sent[0].Body, big) {
		t.Fatalf("sent %d requests", len(sent))
	}

	// A reference the turn never got.
	var forged struct{ Error string }
	host.HTTP("GET", "/files/a/forged", nil).JSON(&forged)
	if forged.Error != "BLOB_NOT_HELD" {
		t.Fatalf("forged: %+v", forged)
	}
}
