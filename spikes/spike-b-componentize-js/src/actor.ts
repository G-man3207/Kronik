// Spike B actor: a TypeScript component for the kronik:actor world.
//
// It exercises Kronik's imports (state, context, log) and the JavaScript
// sources of non-determinism (Math.random, Date, performance, crypto) so the
// harness trace shows where each value comes from. The message name, or the
// last path segment of an HTTP request, selects the mode:
//
//   noop     returns immediately (benchmarks the fresh-instance turn)
//   counter  the brief's TypeScript counter: state n += 1, JSON reply
//   probe    reads and writes state and reports every value as JSON
//   math     calls Math.random() <body> times (how often does it hit the host?)
//   json     builds <body> small objects, then JSON.stringify and JSON.parse
//   spin     loops forever (fuel limit)
//   alloc    allocates and touches <body> MiB (memory limit)
//   throw    throws an Error (a trap or a handler error?)
//   reject   throws { tag: 'rejected', val } (handler-error::rejected)

import { get, set } from 'kronik:actor/state@0.1.0';
import { causalId, nowMs, randomBytes, selfRef } from 'kronik:actor/context@0.1.0';
import { emit } from 'kronik:actor/log@0.1.0';
import type { Input, Manifest, Output } from 'kronik:actor/types@0.1.0';

// Module scope runs once, when ComponentizeJS pre-initializes the component
// with Wizer at build time. Its results are part of the snapshot: this Date.now()
// is the build time. (Math.random() here fails the build, see
// src/build-time-random.ts.)
let turns = 0;
const buildTime = { dateNow: Date.now() };

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function probe(): Record<string, unknown> {
  const before = get('n');
  const n = (before === undefined ? 0 : Number(decoder.decode(before))) + 1;
  set('n', encoder.encode(String(n)));

  const cryptoBytes = new Uint8Array(8);
  globalThis.crypto.getRandomValues(cryptoBytes);
  const report = {
    turnsSeenByThisInstance: turns,
    n,
    self: selfRef(),
    causalId: causalId(),
    nowMs: nowMs(),
    dateNow: Date.now(),
    dateIso: new Date().toISOString(),
    performanceNow: globalThis.performance?.now(),
    mathRandom: [Math.random(), Math.random(), Math.random()],
    cryptoGetRandomValues: Array.from(cryptoBytes),
    randomUUID: globalThis.crypto.randomUUID?.(),
    randomBytes: Array.from(randomBytes(8)),
    buildTime,
  };
  console.log(`probe n=${n} turns=${turns}`);
  emit('info', 'probe', [
    ['n', String(n)],
    ['turns', String(turns)],
  ]);
  return report;
}

/** A JSON reply in the shape that fits the input: an HTTP response or a message. */
function reply(input: Input, value: unknown): Output {
  const body = encoder.encode(
    JSON.stringify(value, (_key, v) => (typeof v === 'bigint' ? v.toString() : v)),
  );
  if (input.tag === 'http') {
    return {
      tag: 'http',
      val: {
        status: 200,
        headers: [{ name: 'content-type', value: 'application/json' }],
        body: { tag: 'inline', val: body },
      },
    };
  }
  return {
    tag: 'reply',
    val: { name: 'probe-result', contentType: 'application/json', body, blobs: [] },
  };
}

/** The mode name and body of any input. */
function mode(input: Input): [string, Uint8Array] {
  switch (input.tag) {
    case 'http': {
      const body = input.val.body.tag === 'inline' ? input.val.body.val : new Uint8Array();
      return [input.val.path.split('/').pop() ?? '', body];
    }
    case 'message':
      return [input.val.msg.name, input.val.msg.body];
    case 'timer':
      return [input.val.msg.name, input.val.msg.body];
    case 'migrate':
      return ['migrate', new Uint8Array()];
  }
}

export const handler = {
  describe(): Manifest {
    return {
      kind: 'spike-b',
      schemaVersion: 1,
      routes: [{ method: 'POST', pattern: '/spike-b/{key}/{mode}' }],
      capabilities: [],
    };
  },

  handle(input: Input): Output {
    turns += 1;
    const [name, body] = mode(input);
    switch (name) {
      case 'noop':
        return { tag: 'none' };
      case 'counter': {
        const stored = get('n');
        const n = (stored === undefined ? 0 : JSON.parse(decoder.decode(stored)) as number) + 1;
        set('n', encoder.encode(JSON.stringify(n)));
        return reply(input, { n });
      }
      case 'probe':
        return reply(input, probe());
      case 'math': {
        const count = Number(decoder.decode(body)) || 10;
        let sum = 0;
        for (let i = 0; i < count; i++) sum += Math.random();
        return reply(input, { count, sum });
      }
      case 'json': {
        const count = Number(decoder.decode(body)) || 1000;
        const items = Array.from({ length: count }, (_, i) => ({
          id: i,
          name: `item-${i}`,
          tags: ['a', 'b', 'c'],
          price: i * 1.25,
        }));
        const text = JSON.stringify(items);
        const parsed = JSON.parse(text) as Array<{ price: number }>;
        const total = parsed.reduce((sum, item) => sum + item.price, 0);
        return reply(input, { count, bytes: text.length, total });
      }
      case 'spin': {
        let x = 0;
        for (;;) x = (x * 31 + 7) | 0;
      }
      case 'alloc': {
        const mib = Number(decoder.decode(body)) || 16;
        const block = new Uint8Array(mib << 20);
        for (let i = 0; i < block.length; i += 4096) block[i] = 1;
        return reply(input, { allocatedMiB: mib, touched: block.length });
      }
      case 'throw':
        throw new Error('boom');
      case 'reject':
        throw { tag: 'rejected', val: 'not today' };
      default:
        throw { tag: 'rejected', val: `unknown mode ${name}` };
    }
  },
};
