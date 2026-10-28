package kronik

import (
	_ "unsafe" // go:linkname

	"kronik.dev/sdk/internal/wit/kronik/actor/types"
)

// The host import that handle can reach, defined for host tests: the
// generated bindings only declare it.
//
//go:linkname hostSelfRef kronik.dev/sdk/internal/wit/kronik/actor/context.wasmimport_SelfRef
func hostSelfRef(result *types.ActorRef) { *result = types.ActorRef{Kind: "x", Key: "k"} }
