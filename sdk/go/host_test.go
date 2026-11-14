package kronik

import (
	_ "unsafe" // go:linkname

	"go.bytecodealliance.org/cm"
	"kronik.dev/sdk/internal/wit/kronik/actor/blobs"
	"kronik.dev/sdk/internal/wit/kronik/actor/types"
)

// The host imports that handle can reach, defined for host tests: the
// generated bindings only declare them.
//
//go:linkname hostSelfRef kronik.dev/sdk/internal/wit/kronik/actor/context.wasmimport_SelfRef
func hostSelfRef(result *types.ActorRef) { *result = types.ActorRef{Kind: "x", Key: "k"} }

// A blob body's lazy read: no blob is held in host tests.
//
//go:linkname hostBlobGet kronik.dev/sdk/internal/wit/kronik/actor/blobs.wasmimport_Get
func hostBlobGet(blob0 *uint8, blob1 uint32, blob2 uint64, offset0 uint64, len0 uint32, result *cm.Result[blobs.BlobErrorShape, cm.List[uint8], blobs.BlobError]) {
	*result = cm.Err[cm.Result[blobs.BlobErrorShape, cm.List[uint8], blobs.BlobError]](blobs.BlobErrorNotHeld())
}
