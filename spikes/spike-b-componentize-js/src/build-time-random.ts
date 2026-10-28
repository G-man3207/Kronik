// Expected to fail at build time: Math.random() in module scope runs during
// Wizer pre-initialization. StarlingMonkey draws every Math.random() value
// from wasi:random/random, and Wizer refuses imported calls.

import type { Input, Manifest, Output } from 'kronik:actor/types@0.1.0';

const seededAtBuildTime = Math.random();

export const handler = {
  describe(): Manifest {
    return { kind: 'spike-b-build-time-random', schemaVersion: 1, routes: [], capabilities: [] };
  },
  handle(_input: Input): Output {
    return { tag: 'reply', val: { name: String(seededAtBuildTime), contentType: '', body: new Uint8Array(), blobs: [] } };
  },
};
