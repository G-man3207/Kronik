// The SDK's blobs (M25) in an actor, for test/e2e/blobs.test.ts: it reads
// a body inline or as a blob (whole, in ranges and as a stream), answers
// with a blob, writes one, sends one in a fetch whose answer is a blob, and
// tries a reference it never got.

import { actor, BlobRef, type Ctx, KronikError } from '@kronik/sdk';

const P = 1_000_000_007;
const STEP = 4093;

/**
 * Every STEP-th byte of a body weighted by its place, `bytes` being the
 * body's bytes from `start`: a few hundred steps for a megabyte, which
 * interpreted JavaScript pays in fuel.
 */
function probe(bytes: Uint8Array, start = 0, s = 0): number {
  for (let i = Math.ceil(start / STEP) * STEP; i < start + bytes.length; i += STEP) {
    s = (s + bytes[i - start] * (((i / STEP) % 7) + 1)) % P;
  }
  return s;
}

/** The test's bytes: byte i is (i * 31 + 7) % 251, a period of 251. */
const PERIOD = Uint8Array.from({ length: 251 }, (_, i) => (i * 31 + 7) % 251);

function pattern(from: number, n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let at = 0, k = from % 251; at < n; k = 0) {
    const take = Math.min(251 - k, n - at);
    out.set(PERIOD.subarray(k, k + take), at);
    at += take;
  }
  return out;
}

async function streamed(ctx: Ctx, blob: BlobRef): Promise<number> {
  // 200 000 bytes become chunks of four whole frames.
  const chunks = ctx.blobs.stream(blob, 200_000).getReader();
  let s = 0;
  let at = 0;
  for (let next = await chunks.read(); !next.done; next = await chunks.read()) {
    s = probe(next.value, at, s);
    at += next.value.length;
  }
  return s;
}

export default actor({
  kind: 'files',
  schemaVersion: 0,
  routes: [
    { method: 'POST', pattern: '/files/{key}/{op}' },
    { method: 'GET', pattern: '/files/{key}/{op}' },
  ],
  capabilities: ['http:store.test'],
  async http(req, ctx) {
    switch (req.param('op')) {
      case 'info': {
        const blob = req.blob;
        return ctx.json(200, {
          blob: blob !== undefined,
          size: blob ? Number(blob.size) : req.body.length,
          range: Array.from(blob ? ctx.blobs.get(blob, 2, 4) : req.body.subarray(2, 6)),
          streamed: blob ? await streamed(ctx, blob) : probe(req.body),
          whole: probe(req.body),
        });
      }
      case 'echo':
        return req.blob ? ctx.blob(200, req.blob, req.header('content-type') ?? 'application/octet-stream') : ctx.text(200, req.text());
      case 'write': {
        const size = Number(req.queryParam('size') ?? '0');
        const writer = ctx.blobs.writer();
        for (let at = 0; at < size; at += 300_000) writer.write(pattern(at, Math.min(300_000, size - at)));
        return ctx.blob(200, writer.finish());
      }
      case 'relay': {
        const res = ctx.http.fetch({ method: 'POST', url: req.queryParam('url') ?? '', body: req.blob ?? req.body });
        return ctx.json(200, { status: res.status, blob: res.blob !== undefined, size: res.body.length, sum: probe(res.body) });
      }
      case 'forged':
        try {
          ctx.blobs.get(new BlobRef(`b3:${'0'.repeat(64)}`, 10n), 0, 10);
          return ctx.json(200, { error: null });
        } catch (e) {
          return ctx.json(200, { error: e instanceof KronikError ? e.topic : String(e) });
        }
      default:
        return ctx.status(404);
    }
  },
});
