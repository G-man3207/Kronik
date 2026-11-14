import assert from "node:assert/strict";
import { test } from "node:test";
import { TestHost } from "@kronik/sdk/testkit";

interface Image {
  id: string;
  hash: string;
  size: number;
  content_type: string;
  created_ms: number;
}

const MIB = 1 << 20;
const DAY_MS = 86_400_000;
/** Bytes that stand in for an image: byte i is (i * 31 + seed) % 251. */
const picture = (n: number, seed = 7) => Uint8Array.from({ length: n }, (_, i) => (i * 31 + seed) % 251);
const png = { "content-type": "image/png" };

async function start(t: { after(f: () => Promise<void>): void }) {
  const host = await TestHost.start();
  t.after(() => host.close());
  const upload = async (album: string, bytes: Uint8Array, headers: Record<string, string> = png) =>
    host.http("POST", `/media/${album}/images`, { body: bytes, headers });
  const list = async (album: string) => (await host.http("GET", `/media/${album}/images`)).json<{ images: Image[] }>().images;
  const read = async (album: string, id: string) => host.http("GET", `/media/${album}/images/${id}`);
  return { host, upload, list, read };
}

test("images are uploaded, listed, read and deleted; a blob goes with its last row", async (t) => {
  const { host, upload, list, read } = await start(t);

  // A small image is stored with put and held; it reads back as it was.
  const small = picture(20_000);
  const first = await upload("trip", small);
  assert.equal(first.status, 201);
  const one = first.json<{ id: string; hash: string; size: number }>();
  assert.equal(one.id, "img-1");
  assert.match(one.hash, /^b3:[0-9a-f]{64}$/);
  assert.equal(one.size, small.length);
  const got = await read("trip", "img-1");
  assert.equal(got.header("content-type"), "image/png");
  assert.deepEqual(new Uint8Array(got.body), small);

  // The same bytes again are the same blob in a second row.
  const again = (await upload("trip", small)).json<{ id: string; hash: string }>();
  assert.deepEqual([again.id, again.hash], ["img-2", one.hash]);

  // An image above the blob threshold (1 MiB) arrives as a blob and is held as it is.
  const big = picture(1.5 * MIB, 11);
  assert.equal((await upload("trip", big, { "content-type": "image/jpeg" })).status, 201);
  assert.deepEqual(new Uint8Array((await read("trip", "img-3")).body), big);
  assert.deepEqual(
    (await list("trip")).map((i) => [i.id, i.size, i.content_type]),
    [
      ["img-1", small.length, "image/png"],
      ["img-2", small.length, "image/png"],
      ["img-3", big.length, "image/jpeg"],
    ],
  );

  // Deleting one of two rows of a blob keeps the album's hold for the other.
  assert.equal((await host.http("DELETE", "/media/trip/images/img-1")).status, 204);
  assert.equal((await read("trip", "img-1")).status, 404);
  assert.deepEqual(new Uint8Array((await read("trip", "img-2")).body), small);
  assert.equal((await host.http("DELETE", "/media/trip/images/img-2")).status, 204);
  assert.deepEqual((await list("trip")).map((i) => i.id), ["img-3"]);

  // What is not an image, or empty, is refused.
  assert.equal((await upload("trip", small, { "content-type": "text/plain" })).status, 415);
  assert.equal((await upload("trip", new Uint8Array())).status, 400);
  assert.equal((await host.http("DELETE", "/media/trip/images/img-9")).status, 404);
});

test("an album shares an image by message, and the receiver holds its own", async (t) => {
  const { host, upload, list, read } = await start(t);
  const bytes = picture(30_000);
  const { hash } = (await upload("alice", bytes)).json<{ hash: string }>();

  const shared = await host.http("POST", "/media/alice/images/img-1/share/bob");
  assert.equal(shared.status, 202);
  assert.deepEqual(shared.json(), { to: "media/bob" });
  assert.deepEqual((await list("bob")).map((i) => [i.id, i.hash]), [["img-1", hash]]);
  assert.deepEqual(new Uint8Array((await read("bob", "img-1")).body), bytes);

  // alice's delete ends alice's hold only.
  assert.equal((await host.http("DELETE", "/media/alice/images/img-1")).status, 204);
  assert.deepEqual(new Uint8Array((await read("bob", "img-1")).body), bytes);

  assert.equal((await host.http("POST", "/media/bob/images/img-1/share/bob")).status, 400);
  assert.equal((await host.http("POST", "/media/bob/images/img-7/share/carol")).status, 404);
});

test("an image is imported from a granted host", async (t) => {
  const { host, read } = await start(t);
  const cat = picture(1.25 * MIB, 3);
  await host.stub({ url: "http://img.test/cat.png", headers: [["content-type", "image/png"]], body: cat });
  await host.stub({ url: "http://img.test/page", headers: [["content-type", "text/html"]], body: "<html>" });

  // Without a grant the fetch is denied.
  const denied = await host.http("POST", "/media/zoo/import", { body: { url: "http://img.test/cat.png" } });
  assert.equal(denied.status, 502);
  assert.match(denied.json<{ error: string }>().error, /CAPABILITY_NOT_GRANTED/);

  await host.grant("media", "http:img.test");
  const imported = await host.http("POST", "/media/zoo/import", { body: { url: "http://img.test/cat.png" } });
  assert.equal(imported.status, 201);
  assert.equal(imported.json<{ size: number }>().size, cat.length);
  assert.deepEqual(new Uint8Array((await read("zoo", "img-1")).body), cat);

  assert.equal((await host.http("POST", "/media/zoo/import", { body: { url: "http://img.test/page" } })).status, 502);
  assert.equal((await host.http("POST", "/media/zoo/import", { body: { url: "ftp://img.test/x" } })).status, 400);
});

test("an image expires when its timer fires", async (t) => {
  const { host, upload, list, read } = await start(t);
  await upload("old", picture(10_000));
  await upload("old", picture(10_000, 9));

  for (const days of ["0", "-1", "3651", "soon"]) {
    assert.equal((await host.http("POST", `/media/old/images/img-1/expire?days=${days}`)).status, 400, days);
  }
  const expiring = await host.http("POST", "/media/old/images/img-1/expire?days=1.5");
  assert.equal(expiring.status, 202);
  // img-2's expiry finds no row: it was deleted before its timer fired.
  assert.equal((await host.http("POST", "/media/old/images/img-2/expire?days=1")).status, 202);
  assert.equal((await host.http("DELETE", "/media/old/images/img-2")).status, 204);

  await host.advance(DAY_MS);
  assert.deepEqual((await list("old")).map((i) => i.id), ["img-1"]);
  await host.advance(DAY_MS);
  assert.deepEqual(await list("old"), []);
  assert.equal((await read("old", "img-1")).status, 404);

  // Every turn committed: nothing became a dead letter.
  const dead = await host.api("GET", "/v1/dead-letters");
  assert.deepEqual((dead.body as { dead_letters: unknown[] }).dead_letters, []);
});
