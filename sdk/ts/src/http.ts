// HTTP for actors: the incoming request, outgoing requests and their
// responses, and secret handles. No host calls here.

import type { BlobRef as WitBlobRef, HttpBody, HttpRequest, Message as WitMessage } from 'kronik:actor/types@0.1.1';
import type { HeaderValue, Request as WitRequest, Response as WitResponse } from 'kronik:actor/http-client@0.1.1';
import { KronikError } from './errors.ts';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

/**
 * `bytes` from the host as a `Uint8Array` of the actor's own realm, without
 * copying. ComponentizeJS hands over `list<u8>` values whose prototype is
 * another realm's, so `instanceof Uint8Array` is false for them.
 */
export function own(bytes: ArrayBufferView): Uint8Array {
  return bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

/** Whether `value` is a `Uint8Array`, of this realm or another. */
export function isBytes(value: unknown): value is Uint8Array {
  return value instanceof Uint8Array || Object.prototype.toString.call(value) === '[object Uint8Array]';
}

/** The most bytes one blob call moves: 1 MiB. */
export const BLOB_CALL_BYTES = 1 << 20;

/**
 * A blob's frame: the store reads and checks whole frames, and a read is
 * charged for every frame it touches, so readers fetch whole frames.
 */
export const BLOB_FRAME_BYTES = 1 << 16;

/**
 * A blob: a large body kept outside the log and named by its hash (see
 * `kronik explain blob`). A handler gets one as `req.blob` or `res.blob`, in
 * a message's `blobs`, from `ctx.blobs.writer().finish()` or `ctx.blobs.put`,
 * and may use it in the turn that got it: read it (`ctx.blobs`), answer with
 * it (`ctx.blob`), send it (`ctx.http.fetch({ body: blob })`, a message's
 * `blobs`), or hold it for later turns (`ctx.blobs.retain`).
 */
export class BlobRef {
  /** `b3:<hex>`, or `b3s:<hex>` for a data subject's blob. */
  readonly hash: string;
  /** The blob's size in bytes. */
  readonly size: bigint;

  constructor(hash: string, size: bigint) {
    this.hash = hash;
    this.size = size;
  }

  /** The WIT value. */
  toWit(): WitBlobRef {
    return { hash: this.hash, size: this.size };
  }
}

/** Reads a whole blob into memory; the turn's host calls (`ctx.blobs`). */
export type BlobReader = (blob: BlobRef) => Uint8Array;

/** An inline body's bytes, or its blob. */
function splitBody(body: HttpBody): { inline?: Uint8Array; blob?: BlobRef } {
  return body.tag === 'inline' ? { inline: own(body.val) } : { blob: new BlobRef(body.val.hash, body.val.size) };
}

/** The bytes of a body that is `inline` or a `blob` read with `read`. */
function wholeBody(inline: Uint8Array | undefined, blob: BlobRef | undefined, read: BlobReader | undefined, what: string): Uint8Array {
  if (inline !== undefined) return inline;
  if (!blob || !read) throw new KronikError('blob', `${what} is a blob that this value cannot read`, '', 'blob');
  return read(blob);
}

/** A body: bytes, text (UTF-8), or any other value as JSON. */
export type Body = Uint8Array | string | unknown;

/** Encodes a body: bytes as they are, a string as UTF-8, anything else as JSON. */
export function encodeBody(body: Body): { bytes: Uint8Array; contentType: string } {
  if (isBytes(body)) return { bytes: own(body), contentType: 'application/octet-stream' };
  if (typeof body === 'string') return { bytes: encoder.encode(body), contentType: 'text/plain; charset=utf-8' };
  return { bytes: encoder.encode(toJson(body)), contentType: 'application/json' };
}

/**
 * A message to send, schedule or reply with: a name and a body (bytes, text,
 * or a value as JSON), and the blobs it carries (M26).
 */
export interface OutgoingMessage {
  name: string;
  body?: Body;
  /** Overrides the content type that follows from the body. */
  contentType?: string;
  /**
   * Blobs that travel with the message, at most 256: each must be one the
   * turn may use (`kronik explain blob`). The receiving turn may read them,
   * and holds them only if it `retain`s them.
   */
  blobs?: readonly BlobRef[];
}

/** The WIT message for `msg`. */
export function toWitMessage(msg: OutgoingMessage): WitMessage {
  const { bytes, contentType } = msg.body === undefined ? { bytes: new Uint8Array(), contentType: '' } : encodeBody(msg.body);
  return {
    name: msg.name,
    contentType: msg.contentType ?? contentType,
    body: bytes,
    blobs: (msg.blobs ?? []).map((blob) => blob.toWit()),
  };
}

/** The safe integer range as bigints: such a bigint converts to a number exactly. */
export const MIN_SAFE_BIGINT = BigInt(Number.MIN_SAFE_INTEGER);
export const MAX_SAFE_BIGINT = BigInt(Number.MAX_SAFE_INTEGER);

/**
 * JSON text for `value`; a `bigint` becomes a number if it is a safe integer,
 * else a string. Plain `JSON.stringify` runs first: a replacer is a call into
 * JavaScript per value, which costs a large response much fuel, and only a
 * bigint needs it.
 */
export function toJson(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch (e) {
    if (!(e instanceof TypeError)) throw e;
    return JSON.stringify(value, (_key, v) =>
      typeof v === 'bigint' ? (v >= MIN_SAFE_BIGINT && v <= MAX_SAFE_BIGINT ? Number(v) : v.toString()) : v,
    );
  }
}

/** `bytes` as UTF-8 text; throws a {@link KronikError} naming `what` if they are not. */
export function text(bytes: Uint8Array, what: string, topic: string): string {
  try {
    return decoder.decode(bytes);
  } catch {
    throw new KronikError('utf8', `${what} is not UTF-8`, '', topic);
  }
}

/** `bytes` parsed as JSON; throws a {@link KronikError} naming `what` if they are not JSON. */
export function json<T>(bytes: Uint8Array, what: string, topic: string): T {
  const source = text(bytes, what, topic);
  try {
    return JSON.parse(source) as T;
  } catch (e) {
    throw new KronikError('json', `${what} is not the expected JSON`, (e as Error).message, topic);
  }
}

/** An HTTP request routed to the actor by one of its manifest's routes. */
export class Request {
  readonly method: string;
  readonly path: string;
  /** The raw query string, without `?`. */
  readonly query: string;
  /** The route parameters, such as `key` for `/notes/{key}`. */
  readonly params: Record<string, string>;
  readonly headers: Array<{ name: string; value: string }>;
  /** The body's blob, when the gateway stored a large body as one; else `undefined`. */
  readonly blob: BlobRef | undefined;
  #inline: Uint8Array | undefined;
  readonly #read: BlobReader | undefined;

  constructor(req: HttpRequest, read?: BlobReader) {
    this.method = req.method;
    this.path = req.path;
    this.query = req.query;
    this.params = Object.fromEntries(req.params);
    this.headers = req.headers;
    const { inline, blob } = splitBody(req.body);
    this.#inline = inline;
    this.blob = blob;
    this.#read = read;
  }

  /**
   * The body's bytes. A blob body is read on first use, whole, within the
   * guest's memory limit (64 MiB by default); read a larger one in parts
   * with `ctx.blobs.stream(req.blob)`.
   */
  get body(): Uint8Array {
    this.#inline ??= wholeBody(this.#inline, this.blob, this.#read, 'the request body');
    return this.#inline;
  }

  /** The route parameter `name`. */
  param(name: string): string | undefined {
    return this.params[name];
  }

  /** The first query parameter called `name`, decoded. */
  queryParam(name: string): string | undefined {
    return new URLSearchParams(this.query).get(name) ?? undefined;
  }

  /** The first header called `name`, ignoring case. */
  header(name: string): string | undefined {
    const lower = name.toLowerCase();
    return this.headers.find((h) => h.name.toLowerCase() === lower)?.value;
  }

  /** The body as UTF-8 text. */
  text(): string {
    return text(this.body, 'the request body', 'message');
  }

  /** The body parsed as JSON. */
  json<T = unknown>(): T {
    return json<T>(this.body, 'the request body', 'message');
  }
}

/** A message from another actor or the operator. */
export class Message {
  readonly name: string;
  readonly contentType: string;
  readonly body: Uint8Array;
  /** The sending actor, if an actor sent it. */
  readonly sender?: { kind: string; key: string };
  /**
   * The blobs the message carries (M26): the turn may read them, and holds
   * one only if it `ctx.blobs.retain`s it.
   */
  readonly blobs: BlobRef[];

  constructor(msg: WitMessage, sender?: { kind: string; key: string }) {
    this.name = msg.name;
    this.contentType = msg.contentType;
    this.body = own(msg.body);
    this.sender = sender;
    this.blobs = (msg.blobs ?? []).map((blob) => new BlobRef(blob.hash, blob.size));
  }

  /** The body as UTF-8 text. */
  text(): string {
    return text(this.body, 'the message body', 'message');
  }

  /** The body parsed as JSON. */
  json<T = unknown>(): T {
    return json<T>(this.body, 'the message body', 'message');
  }
}

/**
 * A handle to a secret: its name, never its value (see `kronik explain
 * secret-handle`). The host inserts the value at the effect boundary.
 */
export class Secret {
  readonly name: string;

  constructor(name: string) {
    this.name = name;
  }

  /** A header value the host makes from this secret: `{}` in `template` is replaced by the value. */
  header(template = 'Bearer {}'): SecretHeader {
    return new SecretHeader(this.name, template);
  }
}

/** A header value made from a secret by the host; see {@link Secret.header}. */
export class SecretHeader {
  readonly secret: string;
  readonly template: string;

  constructor(secret: string, template: string) {
    this.secret = secret;
    this.template = template;
  }
}

/** An outgoing request for `ctx.http.fetch`. */
export interface FetchRequest {
  method?: string;
  url: string;
  /** Header values are text, or a secret's value inserted by the host (`ctx.secret(name).header()`). */
  headers?: Record<string, string | SecretHeader>;
  /**
   * Bytes, text, a value sent as JSON (which also sets `content-type`), or a
   * blob, streamed from the blob store (`application/octet-stream` unless
   * `headers` say otherwise).
   */
  body?: Body | BlobRef;
}

export function toWitRequest(req: FetchRequest): WitRequest {
  const headers: Array<{ name: string; value: HeaderValue }> = [];
  let hasContentType = false;
  for (const [name, value] of Object.entries(req.headers ?? {})) {
    hasContentType ||= name.toLowerCase() === 'content-type';
    headers.push({
      name,
      value: value instanceof SecretHeader ? { tag: 'secret', val: { name: value.secret, template: value.template } } : { tag: 'text', val: value },
    });
  }
  if (req.body instanceof BlobRef) {
    if (!hasContentType) headers.push({ name: 'content-type', value: { tag: 'text', val: 'application/octet-stream' } });
    return { method: req.method ?? 'GET', url: req.url, headers, body: { tag: 'blob', val: req.body.toWit() } };
  }
  let bytes: Uint8Array = new Uint8Array();
  if (req.body !== undefined) {
    const encoded = encodeBody(req.body);
    bytes = encoded.bytes;
    if (!hasContentType) headers.push({ name: 'content-type', value: { tag: 'text', val: encoded.contentType } });
  }
  return { method: req.method ?? 'GET', url: req.url, headers, body: { tag: 'inline', val: bytes } };
}

/** The response to `ctx.http.fetch`. */
export class FetchResponse {
  readonly status: number;
  readonly headers: Array<[string, string]>;
  /** The body's blob, when the host stored a large response as one; else `undefined`. */
  readonly blob: BlobRef | undefined;
  #inline: Uint8Array | undefined;
  readonly #read: BlobReader | undefined;

  constructor(res: WitResponse, read?: BlobReader) {
    this.status = res.status;
    this.headers = res.headers;
    const { inline, blob } = splitBody(res.body);
    this.#inline = inline;
    this.blob = blob;
    this.#read = read;
  }

  /**
   * The body's bytes. A blob body is read on first use, whole, within the
   * guest's memory limit; read a larger one with `ctx.blobs.stream(res.blob)`.
   */
  get body(): Uint8Array {
    this.#inline ??= wholeBody(this.#inline, this.blob, this.#read, 'the response body');
    return this.#inline;
  }

  /** Whether the status is 2xx. */
  get ok(): boolean {
    return this.status >= 200 && this.status < 300;
  }

  /** The first header called `name`, ignoring case. */
  header(name: string): string | undefined {
    const lower = name.toLowerCase();
    return this.headers.find(([n]) => n.toLowerCase() === lower)?.[1];
  }

  /** The body as UTF-8 text. */
  text(): string {
    return text(this.body, 'the response body', 'effect');
  }

  /** The body parsed as JSON. */
  json<T = unknown>(): T {
    return json<T>(this.body, 'the response body', 'effect');
  }
}
