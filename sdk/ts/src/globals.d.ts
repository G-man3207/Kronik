// The globals an actor can use: what StarlingMonkey, the engine inside a
// ComponentizeJS component, provides with Kronik's build flags (ADR 0002).
// `fetch` is not among them: use ctx.http.fetch. console goes to the turn's
// log; Date, performance.now(), Math.random() and crypto are deterministic
// and recorded.

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
