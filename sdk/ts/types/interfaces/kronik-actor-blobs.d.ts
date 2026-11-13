/// <reference path="./kronik-actor-types.d.ts" />
declare module 'kronik:actor/blobs@0.1.1' {
  /**
   * Up to `len` bytes (at most 1 MiB) from `offset`. Fewer only at the end
   * of the blob; empty at or past the end.
   */
  export function get(blob: BlobRef, offset: bigint, len: number): Uint8Array;
  /**
   * Stores `bytes` (at most 1 MiB) with the turn's default subject; the
   * actor holds the result once the turn commits.
   */
  export function put(bytes: Uint8Array): BlobRef;
  /**
   * Holds a reference the turn may use, from commit on.
   */
  export function retain(blob: BlobRef): void;
  /**
   * Ends the actor's own hold at commit.
   */
  export function release(blob: BlobRef): void;
  export type BlobRef = import('kronik:actor/types@0.1.1').BlobRef;
  export type BlobError = BlobErrorNotHeld | BlobErrorQuotaExceeded | BlobErrorErased | BlobErrorInvalid;
  /**
   * the turn neither holds nor borrows this reference (BLOB_NOT_HELD)
   */
  export interface BlobErrorNotHeld {
    tag: 'not-held',
  }
  /**
   * over the actor's blob quota (BLOB_QUOTA_EXCEEDED)
   */
  export interface BlobErrorQuotaExceeded {
    tag: 'quota-exceeded',
  }
  /**
   * the blob belonged to an erased subject (SUBJECT_ERASED)
   */
  export interface BlobErrorErased {
    tag: 'erased',
  }
  /**
   * a call outside the limits, such as more than 1 MiB in one call
   */
  export interface BlobErrorInvalid {
    tag: 'invalid',
    val: string,
  }
  
  export class Writer implements Disposable {
    constructor()
    /**
    * At most 1 MiB per call.
    */
    write(chunk: Uint8Array): void;
    /**
    * Ends the blob; the writer takes no more data.
    */
    finish(): BlobRef;
    [Symbol.dispose](): void;
  }
}
