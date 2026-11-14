// The SDK's blobs (M25) in an actor, for blobs_host_test.go: it reads a
// body inline or as a blob (whole, in a range and with a reader), answers
// with a blob, writes one, sends one in a fetch whose answer is a blob, and
// tries a reference it never got.
package main

import (
	"errors"
	"io"
	"strconv"
	"strings"

	"kronik.dev/sdk"
)

const (
	p    = 1_000_000_007
	step = 4093
)

// probe is every step-th byte of a body weighted by its place, b being the
// body's bytes from start: a few hundred steps for a megabyte (a turn's
// fuel would not cover a loop over every byte).
func probe(b []byte, start int, s uint64) uint64 {
	for i := (start + step - 1) / step * step; i < start+len(b); i += step {
		s = (s + uint64(b[i-start])*uint64((i/step)%7+1)) % p
	}
	return s
}

// period is the test's bytes: byte i is (i * 31 + 7) % 251.
var period = func() []byte {
	b := make([]byte, 251)
	for i := range b {
		b[i] = byte((i*31 + 7) % 251)
	}
	return b
}()

func pattern(from, n int) []byte {
	out := make([]byte, n)
	for at, k := 0, from%251; at < n; k = 0 {
		at += copy(out[at:], period[k:])
	}
	return out
}

// ints is b as numbers: encoding/json writes []byte as base64.
func ints(b []byte) []int {
	out := make([]int, len(b))
	for i, x := range b {
		out[i] = int(x)
	}
	return out
}

func info(req *kronik.Request, ctx *kronik.Ctx) (kronik.Output, error) {
	body, err := req.Body()
	if err != nil {
		return kronik.Output{}, err
	}
	blob, ok := req.Blob()
	if !ok {
		return ctx.JSON(200, map[string]any{"blob": false, "size": len(body), "range": ints(body[2:6]),
			"streamed": probe(body, 0, 0), "whole": probe(body, 0, 0)})
	}
	rng, err := ctx.Blobs.Get(blob, 2, 4)
	if err != nil {
		return kronik.Output{}, err
	}
	reader := ctx.Blobs.Reader(blob)
	buf := make([]byte, 200_000)
	var streamed uint64
	for at := 0; ; {
		n, err := reader.Read(buf)
		streamed = probe(buf[:n], at, streamed)
		at += n
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return kronik.Output{}, err
		}
	}
	return ctx.JSON(200, map[string]any{"blob": true, "size": blob.Size, "range": ints(rng),
		"streamed": streamed, "whole": probe(body, 0, 0)})
}

func http(req *kronik.Request, ctx *kronik.Ctx) (kronik.Output, error) {
	op, _ := req.Param("op")
	switch op {
	case "info":
		return info(req, ctx)
	case "echo":
		if blob, ok := req.Blob(); ok {
			contentType, _ := req.Header("content-type")
			return kronik.BlobResponse(200, blob, contentType), nil
		}
		text, err := req.Text()
		if err != nil {
			return kronik.Output{}, err
		}
		return ctx.Text(200, text)
	case "write":
		q, _ := req.QueryParam("size")
		size, _ := strconv.Atoi(q)
		writer := ctx.Blobs.Writer()
		for at := 0; at < size; at += 300_000 {
			if _, err := writer.Write(pattern(at, min(300_000, size-at))); err != nil {
				return kronik.Output{}, err
			}
		}
		blob, err := writer.Finish()
		if err != nil {
			return kronik.Output{}, err
		}
		return kronik.BlobResponse(200, blob, ""), nil
	case "relay":
		url, _ := req.QueryParam("url")
		fetch := kronik.FetchRequest{Method: "POST", URL: url}
		if blob, ok := req.Blob(); ok {
			fetch.BodyBlob = &blob
		} else {
			body, err := req.Body()
			if err != nil {
				return kronik.Output{}, err
			}
			fetch.Body = body
		}
		res, err := ctx.HTTP.Fetch(fetch)
		if err != nil {
			return kronik.Output{}, err
		}
		body, err := res.Body()
		if err != nil {
			return kronik.Output{}, err
		}
		_, isBlob := res.Blob()
		return ctx.JSON(200, map[string]any{"status": res.Status, "blob": isBlob, "size": len(body), "sum": probe(body, 0, 0)})
	case "forged":
		_, err := ctx.Blobs.Get(kronik.BlobRef{Hash: "b3:" + strings.Repeat("0", 64), Size: 10}, 0, 10)
		var e *kronik.Error
		if errors.As(err, &e) {
			return ctx.JSON(200, map[string]any{"error": e.Topic})
		}
		return ctx.JSON(200, map[string]any{"error": nil})
	}
	return ctx.Status(404)
}

func init() {
	kronik.Export(kronik.Actor{
		Kind:          "files",
		SchemaVersion: 0,
		Routes: []kronik.Route{
			{Method: "POST", Pattern: "/files/{key}/{op}"},
			{Method: "GET", Pattern: "/files/{key}/{op}"},
		},
		Capabilities: []string{"http:store.test"},
		HTTP:         http,
	})
}

func main() {}
