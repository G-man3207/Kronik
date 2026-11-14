// Blobs (M25, M26): reading and writing large bodies with the turn's host
// calls, and holding blobs. A turn may use the blobs its actor holds, the
// ones its input carries, and the ones it got or wrote; the host checks every
// call (`BLOB_NOT_HELD`).

import { get as blobsGet, put as blobsPut, release as blobsRelease, retain as blobsRetain, Writer } from 'kronik:actor/blobs@0.1.1';
import { currentSubject, setSubject } from 'kronik:actor/privacy@0.1.1';
import { hostError, KronikError } from './errors.ts';
import { BLOB_CALL_BYTES, BLOB_FRAME_BYTES, BlobRef, own } from './http.ts';

const encoder = new TextEncoder();

/** Up to `length` (at most 1 MiB) bytes of `blob` from `offset`: one host call. */
function getOnce(blob: BlobRef, offset: bigint, length: number): Uint8Array {
  try {
    return own(blobsGet(blob.toWit(), offset, length));
  } catch (e) {
    throw hostError('blob', e);
  }
}

/** Up to `length` bytes of `blob` from `offset`, fewer only at its end. */
function read(blob: BlobRef, offset: bigint, length: number): Uint8Array {
  if (offset < 0n || !Number.isSafeInteger(length) || length < 0) {
    throw new KronikError('blob.range', `no such range of a blob: offset ${offset}, length ${length}`, '', 'blob');
  }
  const end = offset + BigInt(length) < blob.size ? offset + BigInt(length) : blob.size;
  if (end <= offset) return new Uint8Array();
  const out = new Uint8Array(Number(end - offset));
  let at = 0;
  while (at < out.length) {
    const chunk = getOnce(blob, offset + BigInt(at), Math.min(BLOB_CALL_BYTES, out.length - at));
    if (chunk.length === 0) break;
    out.set(chunk, at);
    at += chunk.length;
  }
  return at === out.length ? out : out.subarray(0, at);
}

/**
 * Reads a whole blob: a lazy body (`req.body`, `res.body`). It must fit in
 * the guest's memory (64 MiB by default).
 */
export function readBlob(blob: BlobRef): Uint8Array {
  if (blob.size > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new KronikError('blob.too-large', `a blob of ${blob.size} bytes does not fit in memory; read it with ctx.blobs.stream()`, '', 'blob');
  }
  return read(blob, 0n, Number(blob.size));
}

/**
 * The turn's blobs (see `kronik explain blob`): read the ones the turn may
 * use, in ranges or as a stream, write new ones, and hold them across turns
 * (`put`, `retain`, `release`).
 */
export class Blobs {
  /**
   * Up to `length` bytes of `blob` from `offset`: fewer only at its end, none
   * at or past it. One host call moves at most 1 MiB; this makes as many as
   * `length` needs.
   */
  get(blob: BlobRef, offset: number | bigint, length: number): Uint8Array {
    return read(blob, BigInt(offset), length);
  }

  /**
   * `blob` as a stream of chunks of `chunkBytes` (rounded up to whole 64 KiB
   * frames, at most 1 MiB: what one host call moves), the last one shorter.
   * Read it with `getReader()` in an `async` handler.
   */
  stream(blob: BlobRef, chunkBytes = BLOB_CALL_BYTES): ReadableStream<Uint8Array> {
    const frames = Math.ceil(Math.max(1, Math.floor(chunkBytes)) / BLOB_FRAME_BYTES);
    const size = Math.min(frames * BLOB_FRAME_BYTES, BLOB_CALL_BYTES);
    let offset = 0n;
    return new ReadableStream<Uint8Array>({
      pull(controller) {
        if (offset >= blob.size) {
          controller.close();
          return;
        }
        const chunk = getOnce(blob, offset, size);
        if (chunk.length === 0) {
          controller.close();
          return;
        }
        offset += BigInt(chunk.length);
        controller.enqueue(chunk);
      },
    });
  }

  /**
   * A writer of a new blob, tagged with the turn's default subject: `write()`
   * its bytes, then `finish()` to get the blob, which the turn may use as a
   * response or fetch body.
   */
  writer(): BlobWriter {
    return new BlobWriter();
  }

  /**
   * Stores `bytes` (or text as UTF-8) as a blob tagged with the turn's default
   * subject, and holds it once the turn commits (M26). One host call takes
   * at most 1 MiB; a larger value is written in parts and then retained,
   * which is the same.
   */
  put(bytes: Uint8Array | string): BlobRef {
    const data = typeof bytes === 'string' ? encoder.encode(bytes) : own(bytes);
    if (data.length > BLOB_CALL_BYTES) {
      const writer = this.writer();
      writer.write(data);
      const blob = writer.finish();
      this.retain(blob);
      return blob;
    }
    try {
      const blob = blobsPut(data);
      return new BlobRef(blob.hash, blob.size);
    } catch (e) {
      throw hostError('blob', e);
    }
  }

  /**
   * {@link Blobs.put} tagged with `subject` (`null`: none), whatever the
   * turn's default subject is; the default is restored afterwards, also when
   * the put fails.
   */
  putFor(subject: string | null, bytes: Uint8Array | string): BlobRef {
    const before = currentSubject();
    setSubject(subject ?? undefined);
    try {
      return this.put(bytes);
    } finally {
      setSubject(before);
    }
  }

  /**
   * Holds `blob` from the turn's commit on: one the turn may use, such as a
   * request body, a fetch response or one that a message brought. A blob
   * the actor already holds stays held.
   */
  retain(blob: BlobRef): void {
    try {
      blobsRetain(blob.toWit());
    } catch (e) {
      throw hostError('blob', e);
    }
  }

  /**
   * Ends the actor's hold on `blob` at the turn's commit; the turn can still
   * read it. Only a hold of this actor's own ends; a blob nothing holds any
   * more is deleted later by collection.
   */
  release(blob: BlobRef): void {
    try {
      blobsRelease(blob.toWit());
    } catch (e) {
      throw hostError('blob', e);
    }
  }
}

/**
 * Writes one blob in parts; {@link BlobWriter.finish} ends it. Bytes go to
 * the host as whole 64 KiB frames (calls of at most 1 MiB); what is short of
 * a frame waits for the next write or `finish`.
 */
export class BlobWriter {
  readonly #writer = new Writer();
  #pending = new Uint8Array();

  /** Appends bytes, or text as UTF-8, of any length. */
  write(chunk: Uint8Array | string): void {
    let bytes = typeof chunk === 'string' ? encoder.encode(chunk) : own(chunk);
    if (this.#pending.length > 0) {
      const all = new Uint8Array(this.#pending.length + bytes.length);
      all.set(this.#pending);
      all.set(bytes, this.#pending.length);
      bytes = all;
    }
    const whole = bytes.length - (bytes.length % BLOB_FRAME_BYTES);
    this.#send(bytes.subarray(0, whole));
    // A copy: the caller may reuse its buffer.
    this.#pending = bytes.slice(whole);
  }

  #send(bytes: Uint8Array): void {
    for (let at = 0; at < bytes.length; at += BLOB_CALL_BYTES) {
      try {
        this.#writer.write(bytes.subarray(at, at + BLOB_CALL_BYTES));
      } catch (e) {
        throw hostError('blob', e);
      }
    }
  }

  /** Ends the blob and gives it; the writer takes no more bytes. */
  finish(): BlobRef {
    this.#send(this.#pending);
    this.#pending = new Uint8Array();
    try {
      const blob = this.#writer.finish();
      return new BlobRef(blob.hash, blob.size);
    } catch (e) {
      throw hostError('blob', e);
    }
  }
}
