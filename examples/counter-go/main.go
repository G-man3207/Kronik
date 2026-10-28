// counter-go as deployed: increments by 1 (see counter/counter.go).
package main

import (
	"counter-go/counter"

	"kronik.dev/sdk"
)

func init() { kronik.Export(counter.Actor(1)) }

func main() {}
