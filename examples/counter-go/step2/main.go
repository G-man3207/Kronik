// counter-go-step2: increments by 2, a changed behavior for the M3 tests
// (see counter/counter.go). Built with `kronik build --entry ./step2`.
package main

import (
	"counter-go/counter"

	"kronik.dev/sdk"
)

func init() { kronik.Export(counter.Actor(2)) }

func main() {}
