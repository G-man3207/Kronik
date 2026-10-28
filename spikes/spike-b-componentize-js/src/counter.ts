// The brief's TypeScript counter, written against the raw kronik:actor
// bindings (the M4 SDK wraps exactly this). Used to measure a realistic small
// turn and to check whether builds are reproducible: unlike src/actor.ts, it
// reads no clock or randomness in module scope.

import { get, set } from 'kronik:actor/state@0.1.0';
import type { Input, Manifest, Output } from 'kronik:actor/types@0.1.0';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const handler = {
  describe(): Manifest {
    return {
      kind: 'counter',
      schemaVersion: 1,
      routes: [{ method: 'POST', pattern: '/counter/{key}/increment' }],
      capabilities: [],
    };
  },

  handle(input: Input): Output {
    const stored = get('n');
    const n = (stored === undefined ? 0 : (JSON.parse(decoder.decode(stored)) as number)) + 1;
    set('n', encoder.encode(JSON.stringify(n)));
    const body = encoder.encode(JSON.stringify({ n }));
    if (input.tag !== 'http') {
      return { tag: 'reply', val: { name: 'n', contentType: 'application/json', body, blobs: [] } };
    }
    return {
      tag: 'http',
      val: {
        status: 200,
        headers: [{ name: 'content-type', value: 'application/json' }],
        body: { tag: 'inline', val: body },
      },
    };
  },
};
