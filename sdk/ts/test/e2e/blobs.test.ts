// The SDK's blobs (M25) in an actor that `kronik build` makes from
// test/e2e/files, run by a test host (`kronik test-host`). They need a kronik
// binary in KRONIK_BIN: scripts/ci.sh ts runs them after it builds one.
//
//   KRONIK_BIN=... node --test test/e2e/*.test.ts

import assert from 'node:assert/strict';
import { existsSync, mkdirSync, symlinkSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { TestHost } from '../../testkit/index.ts';

// `kronik build` finds @kronik/sdk in a node_modules above the project: the
// fixture gets this SDK there.
const fixture = join(dirname(fileURLToPath(import.meta.url)), 'files');
const link = join(fixture, 'node_modules', '@kronik', 'sdk');
if (!existsSync(link)) {
  mkdirSync(dirname(link), { recursive: true });
  symlinkSync(join(fixture, '..', '..', '..'), link, 'dir');
}

const MIB = 1 << 20;
const P = 1_000_000_007;
const STEP = 4093;
const pattern = (from: number, n: number) => Uint8Array.from({ length: n }, (_, i) => ((from + i) * 31 + 7) % 251);
/** The fixture's probe: every STEP-th byte, weighted by its place. */
const sum = (b: Uint8Array) => {
  let s = 0;
  for (let i = 0; i < b.length; i += STEP) s = (s + b[i] * (((i / STEP) % 7) + 1)) % P;
  return s;
};
const bytes = (b: Uint8Array) => new Uint8Array(b);

test('an actor reads, answers, writes and sends blobs', async (t) => {
  const host = await TestHost.start({ dir: fixture });
  t.after(() => host.close());
  await host.grant('files', 'http:store.test');

  // A small body stays inline.
  const small = pattern(0, 100);
  assert.deepEqual((await host.http('POST', '/files/a/info', { body: small })).json(), {
    blob: false,
    size: 100,
    range: Array.from(small.subarray(2, 6)),
    streamed: sum(small),
    whole: sum(small),
  });

  // One above the blob threshold (1 MiB) is a blob: read in a range, as a
  // stream and whole.
  const big = pattern(0, 1.5 * MIB);
  assert.deepEqual((await host.http('POST', '/files/a/info', { body: big })).json(), {
    blob: true,
    size: big.length,
    range: Array.from(big.subarray(2, 6)),
    streamed: sum(big),
    whole: sum(big),
  });

  // Answering with the blob it got.
  const echo = await host.http('POST', '/files/a/echo', { body: big, headers: { 'content-type': 'application/x-test' } });
  assert.equal(echo.status, 200);
  assert.equal(echo.blob?.size, big.length);
  assert.equal(echo.header('content-type'), 'application/x-test');
  assert.deepEqual(bytes(echo.body), big);

  // A blob written in parts that are not whole frames.
  const written = await host.http('POST', '/files/a/write?size=1310720');
  assert.equal(written.blob?.size, 1310720);
  assert.deepEqual(bytes(written.body), pattern(0, 1310720));

  // The blob it got as a fetch's body; the fetch's large answer is a blob.
  const answer = pattern(7, 1.25 * MIB);
  await host.stub({ url: 'http://store.test/up', body: answer });
  const relayed = await host.http('POST', `/files/a/relay?url=${encodeURIComponent('http://store.test/up')}`, { body: big });
  assert.deepEqual(relayed.json(), { status: 200, blob: true, size: answer.length, sum: sum(answer) });
  const [sent] = await host.requests();
  assert.equal(sent.method, 'POST');
  assert.deepEqual(bytes(sent.body), big);

  // A reference the turn never got.
  assert.deepEqual((await host.http('GET', '/files/a/forged')).json(), { error: 'BLOB_NOT_HELD' });
});
