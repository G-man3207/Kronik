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

test('an actor holds blobs across turns and sends them in messages (M26)', async (t) => {
  const host = await TestHost.start({ dir: fixture });
  t.after(() => host.close());
  const kept = async (key: string) => {
    const r = await host.http('GET', `/files/${key}/kept`);
    return r.status === 200 ? bytes(r.body) : r.json();
  };

  // An inline body, stored with put and held: a later turn reads it.
  const small = pattern(3, 5000);
  const a = (await host.http('POST', '/files/a/keep', { body: small })).json() as { hash: string; size: number };
  assert.match(a.hash, /^b3:[0-9a-f]{64}$/);
  assert.equal(a.size, small.length);
  assert.deepEqual(await kept('a'), small);

  // A blob sent in a message: the receiving key retains it and reads it in
  // its own later turns.
  assert.equal((await host.http('POST', '/files/a/share?to=b')).status, 202);
  assert.deepEqual(await kept('b'), small);

  // A release ends a's hold only: b's own hold keeps the blob readable, and
  // a second release is BLOB_NOT_HELD.
  assert.deepEqual((await host.http('POST', '/files/a/release')).json(), { ok: true });
  assert.deepEqual(await kept('a'), { error: 'BLOB_NOT_HELD' });
  assert.deepEqual(await kept('b'), small);
  assert.deepEqual((await host.http('POST', '/files/a/release')).json(), { error: 'BLOB_NOT_HELD' });

  // A body above the threshold arrives as a blob and is retained as it is.
  const big = pattern(0, 1.5 * MIB);
  const c = (await host.http('POST', '/files/c/keep', { body: big })).json() as { size: number };
  assert.equal(c.size, big.length);
  assert.deepEqual(await kept('c'), big);

  // put takes more than one host call's 1 MiB: written in parts, retained.
  const d = (await host.http('POST', '/files/d/put-big?size=1300000')).json() as { size: number };
  assert.equal(d.size, 1300000);
  assert.deepEqual(await kept('d'), pattern(0, 1300000));

  // putFor tags the blob with a subject: a subject's blob has a b3s: hash.
  const e = (await host.http('POST', '/files/e/put-for?subject=user:1', { body: small })).json() as { hash: string };
  assert.match(e.hash, /^b3s:[0-9a-f]{64}$/);
  assert.deepEqual(await kept('e'), small);
});
