//! The host side of `kronik:actor/blobs` (M25/M26, ADR 0121,
//! docs/design/m25-streaming-bodies.md §5). The interface is complete from
//! its first version (ADR 0113); a function whose slice has not landed traps
//! with `NOT_IMPLEMENTED`.

use wasmtime::bail;
use wasmtime::component::Resource;

use super::TurnHost;
use super::bindings::kronik::actor::blobs as wit;
use super::bindings::kronik::actor::types::BlobRef;

/// The host's state of a guest's `writer` resource.
pub struct GuestWriter;

impl wit::Host for TurnHost {
    async fn get(
        &mut self,
        _blob: BlobRef,
        _offset: u64,
        _len: u32,
    ) -> wasmtime::Result<Result<Vec<u8>, wit::BlobError>> {
        self.deny_in_describe("blobs")?;
        bail!("NOT_IMPLEMENTED: blobs.get is not available yet")
    }

    async fn put(&mut self, _bytes: Vec<u8>) -> wasmtime::Result<Result<BlobRef, wit::BlobError>> {
        self.deny_in_describe("blobs")?;
        bail!("NOT_IMPLEMENTED: blobs.put is not available yet")
    }

    async fn retain(&mut self, _blob: BlobRef) -> wasmtime::Result<Result<(), wit::BlobError>> {
        self.deny_in_describe("blobs")?;
        bail!("NOT_IMPLEMENTED: blobs.retain is not available yet")
    }

    async fn release(&mut self, _blob: BlobRef) -> wasmtime::Result<Result<(), wit::BlobError>> {
        self.deny_in_describe("blobs")?;
        bail!("NOT_IMPLEMENTED: blobs.release is not available yet")
    }
}

impl wit::HostWriter for TurnHost {
    async fn new(&mut self) -> wasmtime::Result<Resource<GuestWriter>> {
        self.deny_in_describe("blobs")?;
        bail!("NOT_IMPLEMENTED: blobs.writer is not available yet")
    }

    async fn write(
        &mut self,
        _writer: Resource<GuestWriter>,
        _chunk: Vec<u8>,
    ) -> wasmtime::Result<Result<(), wit::BlobError>> {
        self.deny_in_describe("blobs")?;
        bail!("NOT_IMPLEMENTED: blobs.writer.write is not available yet")
    }

    async fn finish(
        &mut self,
        _writer: Resource<GuestWriter>,
    ) -> wasmtime::Result<Result<BlobRef, wit::BlobError>> {
        self.deny_in_describe("blobs")?;
        bail!("NOT_IMPLEMENTED: blobs.writer.finish is not available yet")
    }

    async fn drop(&mut self, writer: Resource<GuestWriter>) -> wasmtime::Result<()> {
        self.table.delete(writer)?;
        Ok(())
    }
}
