//! The host side of `kronik:actor/connections` (M24,
//! docs/design/m24-connections.md §2.4). The interface is complete from its
//! first version (ADR 0113); a function whose slice has not landed traps
//! with `NOT_IMPLEMENTED`.

use wasmtime::bail;

use super::TurnHost;
use super::connection_bindings::kronik::actor::connections as wit;

impl wit::Host for TurnHost {
    async fn send(&mut self, _conn: String, _frame: wit::Frame) -> wasmtime::Result<()> {
        self.deny_in_describe("connections")?;
        bail!("NOT_IMPLEMENTED: connections.send is not available yet")
    }

    async fn broadcast(&mut self, _conns: Vec<String>, _frame: wit::Frame) -> wasmtime::Result<()> {
        self.deny_in_describe("connections")?;
        bail!("NOT_IMPLEMENTED: connections.broadcast is not available yet")
    }

    async fn close(&mut self, _conn: String, _code: u16, _reason: String) -> wasmtime::Result<()> {
        self.deny_in_describe("connections")?;
        bail!("NOT_IMPLEMENTED: connections.close is not available yet")
    }

    async fn send_now(
        &mut self,
        _conn: String,
        _frame: wit::Frame,
    ) -> wasmtime::Result<Result<(), wit::SendError>> {
        self.deny_in_describe("connections")?;
        bail!("NOT_IMPLEMENTED: connections.send-now is not available yet")
    }
}
