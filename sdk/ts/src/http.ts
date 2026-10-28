// HTTP for actors: the incoming request, outgoing requests and their
// responses, and secret handles. No host calls here.

import type { HttpRequest, Message as WitMessage } from 'kronik:actor/types@0.1.0';
import type { HeaderValue, Request as WitRequest, Response as WitResponse } from 'kronik:actor/http-client@0.1.0';
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

/** A body: bytes, text (UTF-8), or any other value as JSON. */
export type Body = Uint8Array | string | unknown;

/** Encodes a body: bytes as they are, a string as UTF-8, anything else as JSON. */
export function encodeBody(body: Body): { bytes: Uint8Array; contentType: string } {
  if (isBytes(body)) return { bytes: own(body), contentType: 'application/octet-stream' };
  if (typeof body === 'string') return { bytes: encoder.encode(body), contentType: 'text/plain; charset=utf-8' };
  return { bytes: encoder.encode(toJson(body)), contentType: 'application/json' };
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
  /** The body's bytes (inline; a blob body, from M25, is empty here). */
  readonly body: Uint8Array;

  constructor(req: HttpRequest) {
    this.method = req.method;
    this.path = req.path;
    this.query = req.query;
    this.params = Object.fromEntries(req.params);
    this.headers = req.headers;
    this.body = req.body.tag === 'inline' ? own(req.body.val) : new Uint8Array();
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

  constructor(msg: WitMessage, sender?: { kind: string; key: string }) {
    this.name = msg.name;
    this.contentType = msg.contentType;
    this.body = own(msg.body);
    this.sender = sender;
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
  /** Bytes, text, or a value sent as JSON (which also sets `content-type`). */
  body?: Body;
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
  readonly body: Uint8Array;

  constructor(res: WitResponse) {
    this.status = res.status;
    this.headers = res.headers;
    this.body = res.body.tag === 'inline' ? own(res.body.val) : new Uint8Array();
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
