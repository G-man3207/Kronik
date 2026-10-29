// The globals an actor can use: what StarlingMonkey, the engine inside a
// ComponentizeJS component, provides with Kronik's build flags (ADR 0002).
// console goes to the turn's log; Date, performance.now(), Math.random() and
// crypto are deterministic and recorded. Standard `fetch` is an `http.fetch`
// effect (ADR 0070): a header value `Bearer {{secret:NAME}}` gets the secret
// inserted by the host, and every failure is a TypeError (use ctx.http.fetch
// when the kind of error matters, or for foreign:// URLs).

declare interface Console {
  debug(...data: unknown[]): void;
  error(...data: unknown[]): void;
  info(...data: unknown[]): void;
  log(...data: unknown[]): void;
  trace(...data: unknown[]): void;
  warn(...data: unknown[]): void;
}
declare var console: Console;

declare class TextEncoder {
  readonly encoding: string;
  encode(input?: string): Uint8Array;
}

declare class TextDecoder {
  constructor(label?: string, options?: { fatal?: boolean; ignoreBOM?: boolean });
  readonly encoding: string;
  decode(input?: ArrayBufferView | ArrayBuffer, options?: { stream?: boolean }): string;
}

declare class URLSearchParams {
  constructor(init?: string | Record<string, string> | Array<[string, string]>);
  append(name: string, value: string): void;
  delete(name: string): void;
  get(name: string): string | null;
  getAll(name: string): string[];
  has(name: string): boolean;
  set(name: string, value: string): void;
  toString(): string;
  entries(): IterableIterator<[string, string]>;
  [Symbol.iterator](): IterableIterator<[string, string]>;
}

declare class URL {
  constructor(url: string, base?: string | URL);
  hash: string;
  host: string;
  hostname: string;
  href: string;
  readonly origin: string;
  pathname: string;
  port: string;
  protocol: string;
  search: string;
  readonly searchParams: URLSearchParams;
  toString(): string;
}

declare var crypto: {
  getRandomValues<T extends ArrayBufferView>(array: T): T;
  randomUUID(): string;
};

declare var performance: {
  now(): number;
};

type HeadersInit = Headers | Record<string, string> | Array<[string, string]>;
type BodyInit = string | Uint8Array | ArrayBuffer | URLSearchParams | ReadableStream<Uint8Array>;

declare class Headers {
  constructor(init?: HeadersInit);
  append(name: string, value: string): void;
  delete(name: string): void;
  get(name: string): string | null;
  has(name: string): boolean;
  set(name: string, value: string): void;
  forEach(callback: (value: string, name: string) => void): void;
  entries(): IterableIterator<[string, string]>;
  [Symbol.iterator](): IterableIterator<[string, string]>;
}

interface ReadableStreamDefaultController<R> {
  enqueue(chunk: R): void;
  close(): void;
  error(reason?: unknown): void;
}

declare class ReadableStream<R = unknown> {
  constructor(source?: {
    start?(controller: ReadableStreamDefaultController<R>): void | Promise<void>;
    pull?(controller: ReadableStreamDefaultController<R>): void | Promise<void>;
    cancel?(reason?: unknown): void | Promise<void>;
  });
}

interface RequestInit {
  method?: string;
  headers?: HeadersInit;
  body?: BodyInit | null;
  /** Needed with a ReadableStream body. */
  duplex?: 'half';
}

declare class Response {
  readonly status: number;
  readonly statusText: string;
  readonly ok: boolean;
  readonly headers: Headers;
  readonly url: string;
  text(): Promise<string>;
  json(): Promise<unknown>;
  arrayBuffer(): Promise<ArrayBuffer>;
}

declare function fetch(input: string | URL, init?: RequestInit): Promise<Response>;
