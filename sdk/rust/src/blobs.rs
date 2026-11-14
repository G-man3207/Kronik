//! `ctx.blobs()`: bodies too large to hold inline, as blobs (M25; see
//! `kronik explain blob`).
//!
//! A body above the actor type's blob threshold reaches the actor as a blob
//! reference instead of bytes: [`HttpRequest::body_blob`](crate::HttpRequest::body_blob)
//! and [`Response::blob`](crate::http::Response::blob) say so, and
//! [`Blobs::reader`] reads it a frame at a time. A turn may read the blobs it
//! received (its request's body, a fetch's response, a message's blobs), the
//! ones it wrote and the ones its actor holds; any other reference fails with
//! `not-held`. [`Blobs::put`], [`Blobs::retain`] and [`Blobs::release`] hold
//! blobs across turns (M26), and [`Message::blob`](crate::Message::blob)
//! sends one with a message.

use std::io;

use crate::bindings::kronik::actor::{blobs, privacy};
use crate::{BlobRef, Error};

pub use crate::bindings::kronik::actor::blobs::BlobError;

/// The most one [`Blobs::get`] returns, and one write sends.
pub const MAX_CHUNK: usize = 1 << 20;

/// Blobs are stored in frames of 64 KiB; a read is charged for every frame
/// it touches, so the reader reads whole frames.
const FRAME: u64 = 64 << 10;

/// The turn's blobs (see `kronik explain blob`).
pub struct Blobs {
    _private: (),
}

impl Blobs {
    pub(crate) fn new() -> Self {
        Blobs { _private: () }
    }

    /// Up to `len` bytes of `blob` from `offset` (at most 1 MiB), fewer only
    /// at its end and none past it.
    pub fn get(&self, blob: &BlobRef, offset: u64, len: u32) -> Result<Vec<u8>, Error> {
        let len = len.min(MAX_CHUNK as u32);
        blobs::get(blob, offset, len).map_err(Error::Blob)
    }

    /// The whole blob in memory, read a megabyte at a time. The guest's
    /// memory bounds it (64 MiB by default): read a large blob with
    /// [`Blobs::reader`] instead.
    pub fn read_all(&self, blob: &BlobRef) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(blob.size.min(MAX_CHUNK as u64) as usize);
        while (out.len() as u64) < blob.size {
            let chunk = self.get(blob, out.len() as u64, MAX_CHUNK as u32)?;
            if chunk.is_empty() {
                break;
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }

    /// A reader over `blob`: [`io::Read`] and [`io::Seek`], reading 64 KiB
    /// frames as they are needed.
    pub fn reader(&self, blob: &BlobRef) -> BlobReader {
        BlobReader {
            blob: blob.clone(),
            pos: 0,
            frame: Vec::new(),
            frame_at: 0,
        }
    }

    /// A writer for a new blob of the turn's subject: [`io::Write`], then
    /// [`BlobWriter::finish`] for its reference. Dropping a writer, or
    /// leaving it open when the turn ends, discards the blob. A turn holds at
    /// most 64 writers open at once.
    pub fn writer(&self) -> BlobWriter {
        BlobWriter {
            inner: blobs::Writer::new(),
            pending: Vec::new(),
        }
    }

    /// Stores `bytes` as a blob tagged with the turn's default subject; the
    /// actor holds it once the turn commits (M26). One host call takes at
    /// most 1 MiB: a larger value is written in parts and then retained,
    /// which is the same.
    pub fn put(&self, bytes: &[u8]) -> Result<BlobRef, Error> {
        if bytes.len() <= MAX_CHUNK {
            return blobs::put(bytes).map_err(Error::Blob);
        }
        let writer = blobs::Writer::new();
        for chunk in bytes.chunks(MAX_CHUNK) {
            writer.write(chunk).map_err(Error::Blob)?;
        }
        let blob = writer.finish().map_err(Error::Blob)?;
        self.retain(&blob)?;
        Ok(blob)
    }

    /// [`Blobs::put`] tagged with `subject` (`None`: none), whatever the
    /// turn's default subject is; the default is restored afterwards, also
    /// when the put fails.
    pub fn put_for<'a>(
        &self,
        subject: impl Into<Option<&'a str>>,
        bytes: &[u8],
    ) -> Result<BlobRef, Error> {
        let before = privacy::current_subject();
        privacy::set_subject(subject.into());
        let put = self.put(bytes);
        privacy::set_subject(before.as_deref());
        put
    }

    /// Holds `blob` from the turn's commit on: one the turn may use, such as
    /// a request body, a fetch response or one that a message brought. A
    /// blob the actor already holds stays held.
    pub fn retain(&self, blob: &BlobRef) -> Result<(), Error> {
        blobs::retain(blob).map_err(Error::Blob)
    }

    /// Ends the actor's hold on `blob` at the turn's commit; the turn can
    /// still read it. Only a hold of this actor's own ends; a blob nothing
    /// holds any more is deleted later by collection.
    pub fn release(&self, blob: &BlobRef) -> Result<(), Error> {
        blobs::release(blob).map_err(Error::Blob)
    }
}

/// Reads a blob a frame at a time (see [`Blobs::reader`]).
pub struct BlobReader {
    blob: BlobRef,
    pos: u64,
    /// The frame read last, starting at `frame_at`.
    frame: Vec<u8>,
    frame_at: u64,
}

impl BlobReader {
    /// The blob it reads.
    pub fn blob(&self) -> &BlobRef {
        &self.blob
    }
}

impl io::Read for BlobReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.pos >= self.blob.size {
            return Ok(0);
        }
        let held = self.frame_at <= self.pos && self.pos < self.frame_at + self.frame.len() as u64;
        if !held {
            let start = self.pos - self.pos % FRAME;
            let len = FRAME.min(self.blob.size - start) as u32;
            self.frame =
                blobs::get(&self.blob, start, len).map_err(|e| io::Error::other(Error::Blob(e)))?;
            self.frame_at = start;
            if self.frame.is_empty() {
                return Ok(0);
            }
        }
        let at = (self.pos - self.frame_at) as usize;
        let n = buf.len().min(self.frame.len() - at);
        buf[..n].copy_from_slice(&self.frame[at..at + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl io::Seek for BlobReader {
    fn seek(&mut self, to: io::SeekFrom) -> io::Result<u64> {
        let pos = match to {
            io::SeekFrom::Start(n) => Some(n),
            io::SeekFrom::End(d) => self.blob.size.checked_add_signed(d),
            io::SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        };
        match pos {
            Some(pos) => {
                self.pos = pos;
                Ok(pos)
            }
            None => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before the start of the blob",
            )),
        }
    }
}

/// Writes a new blob (see [`Blobs::writer`]): bytes are sent to the host
/// 64 KiB at a time.
pub struct BlobWriter {
    inner: blobs::Writer,
    pending: Vec<u8>,
}

impl BlobWriter {
    /// Sends what is buffered.
    fn send(&mut self) -> Result<(), Error> {
        if !self.pending.is_empty() {
            self.inner.write(&self.pending).map_err(Error::Blob)?;
            self.pending.clear();
        }
        Ok(())
    }

    /// Ends the blob and gives its reference, which the turn may answer
    /// with, fetch with, or read.
    pub fn finish(mut self) -> Result<BlobRef, Error> {
        self.send()?;
        self.inner.finish().map_err(Error::Blob)
    }
}

impl io::Write for BlobWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let room = FRAME as usize - self.pending.len();
        let n = buf.len().min(room);
        self.pending.extend_from_slice(&buf[..n]);
        if self.pending.len() == FRAME as usize {
            self.send().map_err(io::Error::other)?;
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.send().map_err(io::Error::other)
    }
}
