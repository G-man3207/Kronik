//! Response bodies of the gateway's server. M25 owns this file (streaming
//! bodies, docs/design/m25-streaming-bodies.md §6.1); M24 adds the SSE
//! variant (docs/design/m24-connections.md §5.4). The server turns every
//! response into one `hyper::body::Body` implementation over this enum
//! (`server.rs`).

/// A response body.
#[derive(Debug)]
pub enum ResponseBody {
    /// The whole body at once.
    Inline(Vec<u8>),
    /// An SSE event stream (M24): the encoded chunks a connection's driver
    /// sends, until it ends the stream. Dropping the receiver, which hyper
    /// does when the client goes away, tells the driver.
    Events(tokio::sync::mpsc::Receiver<Vec<u8>>),
}
