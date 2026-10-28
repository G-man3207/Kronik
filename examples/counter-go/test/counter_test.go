package test

import (
	"testing"

	"kronik.dev/sdk/testkit"
)

type count struct {
	N int `json:"n"`
}

func TestEachCounterCountsItsIncrements(t *testing.T) {
	host := testkit.Start(t, testkit.Options{Dir: ".."})
	for _, want := range []int{1, 2, 3} {
		var got count
		host.HTTP("POST", "/counter/alice/increment", nil).JSON(&got)
		if got.N != want {
			t.Fatalf("increment: n = %d, want %d", got.N, want)
		}
	}
	for actor, want := range map[string]int{"alice": 3, "bob": 0} {
		var got count
		host.HTTP("GET", "/counter/"+actor, nil).JSON(&got)
		if got.N != want {
			t.Fatalf("GET %s: n = %d, want %d", actor, got.N, want)
		}
	}

	// A message increments too and replies with the count.
	if reply := host.SendReply("counter/alice", "increment", ""); reply != `{"n":4}` {
		t.Fatalf("reply %s", reply)
	}
	var n int
	if !host.StateJSON("counter/alice", "n", &n) || n != 4 {
		t.Fatalf("state n = %d", n)
	}
}
