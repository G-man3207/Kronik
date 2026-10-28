// @kronik/sdk/testkit: tests for actors, in Node.js. TestHost runs the
// project's component in an in-memory Kronik node (`kronik test-host`): the
// real scheduler, runtime and effect gate, with a clock that moves only when
// the test advances it and outgoing HTTP answered by stubs and recorded.
//
//   import { test } from "node:test";
//   import assert from "node:assert/strict";
//   import { TestHost } from "@kronik/sdk/testkit";
//
//   test("counts", async (t) => {
//     const host = await TestHost.start();
//     t.after(() => host.close());
//     const res = await host.http("POST", "/counter/alice/increment");
//     assert.deepEqual(res.json(), { n: 1 });
//   });
//
// TestHost.start() builds the project as `kronik build` does, so tests run
// the code they see. The `kronik` binary comes from the KRONIK_BIN
// environment variable or PATH. Every request waits until what it started
// has finished (messages delivered, timers that came due fired), so a test
// can check the outcome right after it.

import { spawn, type ChildProcessByStdio } from 'node:child_process';
import { createInterface } from 'node:readline';
import type { Readable, Writable } from 'node:stream';

/** How to start a test host. */
export interface StartOptions {
  /** The project to build and deploy; default the current directory, `null` for none. */
  dir?: string | null;
  /** The project's entries to build and deploy instead of package.json's `kronik.entry`: a second actor type, a variant. */
  entries?: string[];
  /** Components that are already built, deployed as well. */
  wasm?: string[];
  /** The kronik binary; default KRONIK_BIN, else `kronik` on PATH. */
  bin?: string;
  /** Seeds the host's ids and guest randomness; default KRONIK_TEST_SEED, else 0. */
  seed?: number;
}

/** A body: bytes, text, or any other value as JSON. */
export type TestBody = Uint8Array | string | unknown;

/** A response through the gateway. */
export class TestResponse {
  readonly status: number;
  readonly headers: Array<[string, string]>;
  readonly body: Uint8Array;
  /** The id of the turn that answered, such as `main:5`. */
  readonly turn: string | undefined;

  constructor(status: number, headers: Array<[string, string]>, body: Uint8Array, turn: string | undefined) {
    this.status = status;
    this.headers = headers;
    this.body = body;
    this.turn = turn;
  }

  /** The first header called `name`, ignoring case. */
  header(name: string): string | undefined {
    const lower = name.toLowerCase();
    return this.headers.find(([n]) => n.toLowerCase() === lower)?.[1];
  }

  text(): string {
    return new TextDecoder().decode(this.body);
  }

  json<T = unknown>(): T {
    return JSON.parse(this.text()) as T;
  }
}

/** An outgoing request an actor made, as the target got it (with the secrets the host inserted). */
export interface RecordedRequest {
  method: string;
  url: string;
  headers: Array<[string, string]>;
  body: Uint8Array;
}

/**
 * An answer for the outgoing requests whose URL starts with `url`. The newest
 * stub that matches answers; a request no stub matches fails as if the
 * connection were refused.
 */
export interface Stub {
  url: string;
  /** Only requests with this method. */
  method?: string;
  /** Default 200. */
  status?: number;
  headers?: Array<[string, string]>;
  body?: TestBody;
  /** Fail instead: `connect` (not sent) or `io` (may have arrived; outcome unknown). */
  error?: 'connect' | 'io';
  /** Answer only this many requests. */
  times?: number;
}

// The answers of `kronik test-host`, as its protocol defines them
// (crates/kronik-testhost/src/protocol.rs).
interface WireBody {
  body?: string;
  body_base64?: string;
}
interface HttpAnswer extends WireBody {
  status: number;
  headers: Array<[string, string]>;
  turn: string | null;
}
interface ApiAnswer {
  status: number;
  body: unknown;
}
interface RecordedAnswer extends WireBody {
  method: string;
  url: string;
  headers: Array<[string, string]>;
}

/** The wire fields for a body: text if it is a string, base64 for bytes, else JSON. */
function wireBody(body: TestBody): WireBody & { json: boolean } {
  if (body === undefined) return { json: false };
  if (typeof body === 'string') return { body, json: false };
  if (body instanceof Uint8Array) return { body_base64: Buffer.from(body).toString('base64'), json: false };
  return { body: JSON.stringify(body), json: true };
}

function bytesOf(wire: WireBody): Uint8Array {
  if (wire.body_base64 !== undefined) return new Uint8Array(Buffer.from(wire.body_base64, 'base64'));
  if (wire.body !== undefined) return new TextEncoder().encode(wire.body);
  return new Uint8Array();
}

/** The `error` of an API answer, read without trusting its shape. */
function apiError(status: number, body: unknown): Error {
  const error = typeof body === 'object' && body !== null && 'error' in body ? body.error : undefined;
  const field = (name: string) => (typeof error === 'object' && error !== null && name in error ? String(Reflect.get(error, name)) : undefined);
  return new Error(`${field('code') ?? `HTTP ${status}`}: ${field('message') ?? 'the request failed'}`);
}

/** An in-memory node running the components under test. */
export class TestHost {
  #child: ChildProcessByStdio<Writable, Readable, null>;
  #waiting: Array<PromiseWithResolvers<unknown>> = [];
  #exited: Error | undefined;

  private constructor(child: ChildProcessByStdio<Writable, Readable, null>) {
    this.#child = child;
    createInterface({ input: child.stdout }).on('line', (line) => {
      const next = this.#waiting.shift();
      if (next === undefined) return;
      let answer: unknown;
      try {
        answer = JSON.parse(line);
      } catch (e) {
        next.reject(new Error(`the test host's answer is not JSON: ${line}`, { cause: e }));
        return;
      }
      const ok = typeof answer === 'object' && answer !== null && 'ok' in answer && answer.ok === true;
      if (ok) {
        next.resolve(answer);
      } else {
        const error = typeof answer === 'object' && answer !== null && 'error' in answer ? String(answer.error) : line;
        next.reject(new Error(error));
      }
    });
    child.on('exit', (code, signal) => {
      this.#fail(new Error(`the test host exited (${signal ?? `code ${code}`}); its errors are above, on stderr`));
    });
    child.on('error', (e) => this.#fail(e));
  }

  #fail(error: Error): void {
    this.#exited ??= error;
    for (const w of this.#waiting.splice(0)) w.reject(this.#exited);
  }

  /** Builds the project (or takes built components) and starts a test host with them deployed. */
  static async start(options: StartOptions = {}): Promise<TestHost> {
    const bin = options.bin ?? process.env.KRONIK_BIN ?? 'kronik';
    const args = ['test-host'];
    const dir = options.dir === undefined ? '.' : options.dir;
    if (dir !== null) {
      args.push('--dir', dir);
      for (const entry of options.entries ?? []) args.push('--entry', entry);
    }
    for (const wasm of options.wasm ?? []) args.push('--wasm', wasm);
    const seed = options.seed ?? process.env.KRONIK_TEST_SEED;
    if (seed !== undefined) args.push('--seed', String(seed));
    const host = new TestHost(spawn(bin, args, { stdio: ['pipe', 'pipe', 'inherit'] }));
    await host.#next();
    return host;
  }

  /** The next answer. `T` is the answer's shape in the protocol. */
  #next<T>(): Promise<T> {
    const waiter = Promise.withResolvers<unknown>();
    if (this.#exited) waiter.reject(this.#exited);
    else this.#waiting.push(waiter);
    // The protocol defines the shape of each answer; ok was checked above.
    const answer = waiter.promise as Promise<T>;
    return answer;
  }

  #call<T>(request: Record<string, unknown>): Promise<T> {
    const answer = this.#next<T>();
    this.#child.stdin.write(`${JSON.stringify(request)}\n`);
    return answer;
  }

  /** Sends an HTTP request through the gateway, as a client would. */
  async http(method: string, path: string, init: { body?: TestBody; headers?: Record<string, string> } = {}): Promise<TestResponse> {
    const { json, ...body } = wireBody(init.body);
    const headers = Object.entries(init.headers ?? {});
    if (json && !headers.some(([n]) => n.toLowerCase() === 'content-type')) headers.push(['content-type', 'application/json']);
    const answer = await this.#call<HttpAnswer>({ op: 'http', method, path, headers, ...body });
    return new TestResponse(answer.status, answer.headers, bytesOf(answer), answer.turn ?? undefined);
  }

  /** Sends the message `name` to `actor` (`"kind/key"`) as the operator; returns the API's answer (`outcome`, `reply`, `turn_id`). */
  async send(actor: string, name: string, body = ''): Promise<unknown> {
    return this.#api('POST', `/v1/actors/${actor}/messages`, { name, text: body, reason: 'test' });
  }

  /** Moves the clock forward and runs the timers that came due; returns the new time in ms since the Unix epoch. */
  async advance(ms: number): Promise<number> {
    const answer = await this.#call<{ now_ms: number }>({ op: 'advance', ms });
    return answer.now_ms;
  }

  /** Adds a stub for outgoing HTTP. */
  async stub(stub: Stub): Promise<void> {
    const { json, ...body } = wireBody(stub.body);
    const headers = [...(stub.headers ?? [])];
    if (json && !headers.some(([n]) => n.toLowerCase() === 'content-type')) headers.push(['content-type', 'application/json']);
    await this.#call({ op: 'stub', url: stub.url, method: stub.method, status: stub.status ?? 200, headers, error: stub.error, times: stub.times, ...body });
  }

  /** The outgoing requests the actors made so far, oldest first; `clear` forgets them. */
  async requests(options: { clear?: boolean } = {}): Promise<RecordedRequest[]> {
    const answer = await this.#call<{ requests: RecordedAnswer[] }>({ op: 'requests', clear: options.clear ?? false });
    return answer.requests.map((r) => ({ method: r.method, url: r.url, headers: r.headers, body: bytesOf(r) }));
  }

  /**
   * Grants the actor type `kind` a capability, such as `http:api.example.com`
   * or `secret:stripe`. `http:` grants need a delivery: `idempotency-keyed`,
   * `at-most-once` or `unsafe`.
   */
  async grant(kind: string, capability: string, delivery?: string): Promise<void> {
    await this.#api('POST', '/v1/grants', { kind, capability, delivery, reason: 'test' });
  }

  /** Sets the secret `name`. */
  async secret(name: string, value: string): Promise<void> {
    await this.#api('PUT', `/v1/secrets/${name}`, { text: value, reason: 'test' });
  }

  /** The key-value state of `actor` (`"kind/key"`). */
  async state(actor: string): Promise<Map<string, Uint8Array>> {
    // GET /v1/actors/<kind>/<key> lists the state as { key, base64 } entries.
    const answer = (await this.#api('GET', `/v1/actors/${actor}`)) as { state: Array<{ key: string; base64: string }> };
    return new Map(answer.state.map((e) => [e.key, new Uint8Array(Buffer.from(e.base64, 'base64'))]));
  }

  /** The state value `key` of `actor` parsed as JSON, if there is one. */
  async stateJson<T = unknown>(actor: string, key: string): Promise<T | undefined> {
    const value = (await this.state(actor)).get(key);
    return value === undefined ? undefined : (JSON.parse(new TextDecoder().decode(value)) as T);
  }

  /** Any request to the daemon's API, as `kronik` sends it over its socket (`/v1/...`): the status and the JSON body. */
  async api(method: string, path: string, body?: unknown): Promise<ApiAnswer> {
    const answer = await this.#call<ApiAnswer>({ op: 'api', method, path, body });
    return { status: answer.status, body: answer.body };
  }

  async #api(method: string, path: string, body?: unknown): Promise<unknown> {
    const answer = await this.api(method, path, body);
    if (answer.status !== 200) throw apiError(answer.status, answer.body);
    return answer.body;
  }

  /** Stops the test host. */
  async close(): Promise<void> {
    if (this.#exited) return;
    const exited = Promise.withResolvers<void>();
    this.#child.once('exit', () => exited.resolve());
    this.#child.stdin.end();
    await exited.promise;
  }
}
