//! Request and response bodies of the gateway. M25 owns this file
//! (streaming bodies, docs/design/m25-streaming-bodies.md §6.1); M24 adds
//! the SSE variant (docs/design/m24-connections.md §5.4). The server hands
//! every request body over as a [`RequestBody`] and turns every response
//! into one `hyper::body::Body` implementation over [`ResponseBody`]
//! (`server.rs`).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use kronik_blob::{BlobError, BlobReader, Lease};
use kronik_core::env::BodySource;

/// A request body as the server hands it over (M25 §6.1).
pub enum RequestBody {
    /// The whole body at once: the simulator, tests, the connection path.
    Inline(Vec<u8>),
    /// A body still arriving, read as the body phase decides (§6.2): into
    /// memory, into a blob, or only hashed.
    Stream(Box<dyn BodySource>),
}

impl std::fmt::Debug for RequestBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestBody::Inline(b) => write!(f, "Inline({} bytes)", b.len()),
            RequestBody::Stream(_) => f.write_str("Stream"),
        }
    }
}

/// A response body.
#[derive(Debug)]
pub enum ResponseBody {
    /// The whole body at once.
    Inline(Vec<u8>),
    /// A blob, streamed from the store after its turn committed (M25 §6.5).
    Blob(BlobBody),
    /// An SSE event stream (M24): the encoded chunks a connection's driver
    /// sends, until it ends the stream. Dropping the receiver, which hyper
    /// does when the client goes away, tells the driver.
    Events(tokio::sync::mpsc::Receiver<Vec<u8>>),
}

type FrameRead = Pin<Box<dyn Future<Output = Result<Bytes, BlobError>> + Send>>;

/// A blob response body: one 64 KiB frame in memory at a time, checked (and
/// opened, when sealed) as it is read. Its streaming lease keeps the blob
/// until the body is dropped. A frame that fails its check after the
/// headers went out ends the response early: the client sees a short body.
pub struct BlobBody {
    reader: Arc<BlobReader>,
    next: u64,
    size: u64,
    reading: Option<FrameRead>,
    _lease: Lease,
}

impl std::fmt::Debug for BlobBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Blob({} of {} bytes)", self.next, self.size)
    }
}

impl BlobBody {
    pub(crate) fn new(reader: BlobReader, lease: Lease) -> BlobBody {
        let size = reader.meta().size;
        BlobBody {
            reader: Arc::new(reader),
            next: 0,
            size,
            reading: None,
            _lease: lease,
        }
    }

    /// The blob's size: the response's length.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The bytes not sent yet.
    pub fn remaining(&self) -> u64 {
        self.size - self.next
    }

    /// The next frame of the blob; `None` at its end.
    pub fn poll_frame(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<Bytes, BlobError>>> {
        if self.next >= self.size {
            return Poll::Ready(None);
        }
        let reading = self.reading.get_or_insert_with(|| {
            let reader = self.reader.clone();
            let at = self.next;
            let len = (kronik_blob::format::FRAME_SIZE as u64).min(self.size - at) as usize;
            Box::pin(async move { reader.read_at(at, len).await })
        });
        let read = match reading.as_mut().poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(read) => read,
        };
        self.reading = None;
        Poll::Ready(Some(match read {
            Ok(frame) if frame.is_empty() => Err(BlobError::Corrupt {
                id: self.reader.meta().id,
                why: format!("the blob ends at {} of {} bytes", self.next, self.size),
            }),
            Ok(frame) => {
                self.next += frame.len() as u64;
                kronik_metrics::add(
                    "kronik_blob_read_bytes_total",
                    &[("reader", "gateway")],
                    frame.len() as u64,
                );
                Ok(frame)
            }
            Err(e) => Err(e),
        }))
    }

    /// The whole blob, for tests and the simulator.
    pub async fn collect(mut self) -> Result<Vec<u8>, BlobError> {
        let mut out = Vec::new();
        while let Some(frame) = std::future::poll_fn(|cx| self.poll_frame(cx)).await {
            out.extend_from_slice(&frame?);
        }
        Ok(out)
    }
}
