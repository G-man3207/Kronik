// actor(): the handler export, built from an actor's spec.

import { emit, type Level } from 'kronik:actor/log@0.1.0';
import type { HandlerError, Input, Manifest, Output, Route } from 'kronik:actor/types@0.1.0';
import { Ctx } from './ctx.ts';
import { Rejected } from './errors.ts';
import { Message, Request, toJson } from './http.ts';

/** A timer this actor scheduled, arriving as an input. */
export interface Timer {
  id: bigint;
  message: Message;
}

/** An actor type: its manifest and the handlers for the inputs it takes. */
export interface ActorSpec {
  /** The actor type's name, such as `"counter"`. */
  kind: string;
  /** Raise it when `migrate` gains a step; above 0, a new actor runs `migrate(0)` first. */
  schemaVersion: number;
  /** HTTP routes the gateway sends to this actor type. `{key}` in a pattern names the actor's key. */
  routes?: Route[];
  /** Capabilities the actor type asks for, such as `http:api.example.com`. */
  capabilities?: string[];
  /** Handles an HTTP request. A handler may be `async` (to `await fetch(...)`). */
  http?(req: Request, ctx: Ctx): Output | Promise<Output>;
  /** Handles a message from another actor or the operator. */
  message?(msg: Message, ctx: Ctx): Output | Promise<Output>;
  /** Handles a timer this actor scheduled. */
  timer?(timer: Timer, ctx: Ctx): Output | Promise<Output>;
  /** Migrates the actor's state from schema version `from`; SQL DDL is allowed only here. */
  migrate?(from: number, ctx: Ctx): void | Promise<void>;
}

/** The `kronik:actor/handler` export: what `kronik build` exports from the module's default export. */
export interface Handler {
  describe(): Manifest;
  handle(input: Input): Output;
}

// With the stdio feature disabled (ADR 0002), console output would be dropped;
// it goes to the turn's log instead. This runs at build time, while the
// component is pre-initialized, and only installs the functions.
const consoleLevels: Array<[string, Level]> = [
  ['debug', 'debug'],
  ['error', 'error'],
  ['info', 'info'],
  ['log', 'info'],
  ['trace', 'trace'],
  ['warn', 'warn'],
];
for (const [method, level] of consoleLevels) {
  (console as unknown as Record<string, unknown>)[method] = (...args: unknown[]) => {
    emit(level, args.map((a) => (typeof a === 'string' ? a : (toJson(a) ?? String(a)))).join(' '), []);
  };
}

/**
 * Builds an actor type's handler from its spec:
 *
 * ```ts
 * export default actor({
 *   kind: "counter",
 *   schemaVersion: 1,
 *   routes: [{ method: "POST", pattern: "/counter/{key}/increment" }],
 *   http(req, ctx) {
 *     const n = (ctx.state.getJson<number>("n") ?? 0) + 1;
 *     ctx.state.setJson("n", n);
 *     return ctx.json(200, { n });
 *   },
 * });
 * ```
 *
 * Every input runs as one turn on a fresh instance: module-level variables
 * do not survive it, and module scope itself runs at build time. A handler
 * that throws (or whose promise rejects) fails the turn and its writes are
 * discarded: {@link Rejected} gives `handler-error::rejected`, anything else
 * `handler-error::failed` with the error's message. An `async` handler's
 * turn ends when its promise settles; standard `fetch` calls run while it
 * waits (each is an `http.fetch` effect, as `ctx.http.fetch`).
 */
export function actor(spec: ActorSpec): Handler {
  return {
    describe(): Manifest {
      return {
        kind: spec.kind,
        schemaVersion: spec.schemaVersion,
        routes: spec.routes ?? [],
        capabilities: spec.capabilities ?? [],
      };
    },

    handle(input: Input): Output {
      const ctx = new Ctx();
      try {
        const out = dispatch(spec, input, ctx);
        // ComponentizeJS runs the event loop until a returned promise
        // settles and uses its value, or its rejection as a throw.
        return out instanceof Promise ? (out.then(undefined, (e) => fail(e)) as unknown as Output) : out;
      } catch (e) {
        fail(e);
      }
    },
  };
}

function dispatch(spec: ActorSpec, input: Input, ctx: Ctx): Output | Promise<Output> {
  switch (input.tag) {
    case 'http':
      if (!spec.http) throw new Rejected(unhandled(ctx, 'HTTP requests', 'http', 'actor'));
      return spec.http(new Request(input.val), ctx);
    case 'message':
      if (!spec.message) throw new Rejected(unhandled(ctx, 'messages', 'message', 'message'));
      return spec.message(new Message(input.val.msg, input.val.sender), ctx);
    case 'timer':
      if (!spec.timer) throw new Rejected(unhandled(ctx, 'timers', 'timer', 'dead-letters'));
      return spec.timer({ id: input.val.id, message: new Message(input.val.msg) }, ctx);
    case 'migrate': {
      const done = spec.migrate?.(input.val, ctx);
      return done instanceof Promise ? done.then(() => ({ tag: 'none' })) : { tag: 'none' };
    }
  }
}

/** Throws `e` as the WIT `handler-error`: ComponentizeJS turns a thrown
 * handler-error value into the export's error result; anything else would
 * trap and lose its message. */
function fail(e: unknown): never {
  const error: HandlerError =
    e instanceof Rejected
      ? { tag: 'rejected', val: e.message }
      : { tag: 'failed', val: e instanceof Error ? `${e.name}: ${e.message}` : String(e) };
  throw error;
}

function unhandled(ctx: Ctx, what: string, method: string, topic: string): string {
  return `actor type ${ctx.self().kind} does not handle ${what}: give the actor spec a ${method}() (see \`kronik explain ${topic}\`)`;
}
