// media-ts: an image album per actor (kind `media`, key = the album), the
// example of M26's blob storage (docs/design/m26-blobs.md §15).
//
// An image's bytes are a blob that the album holds; SQL keeps its hash and
// size, which keep nothing alive by themselves: the hold does. The album
// holds a blob once, however many of its rows name it, so a delete releases
// the blob only with its last row. An album shares an image by sending the
// blob in a message (the receiving album retains it), imports one from a
// URL (the operator grants the host), and lets one expire with a timer
// whose message carries the blob.

import { actor, BlobRef, type Ctx, KronikError, type Request } from '@kronik/sdk';

/** The longest expiry: ten years. */
const MAX_DAYS = 3650;
const DAY_MS = 86_400_000;
const COLUMNS = 'id, hash, size, content_type, created_ms';

interface Image {
  id: string;
  hash: string;
  size: number;
  content_type: string;
  created_ms: number;
}

const isImage = (contentType: string | undefined): contentType is string =>
  (contentType ?? '').toLowerCase().startsWith('image/');

/** This album's image `id`, if it has one. */
function image(ctx: Ctx, id: string): Image | undefined {
  return ctx.sql.query(`SELECT ${COLUMNS} FROM images WHERE id = ?1`, [id]).first() as Image | undefined;
}

/**
 * A row's blob. A reference is only a hash and a size; what lets the album
 * use it is that it holds the blob.
 */
function blobOf(row: Image): BlobRef {
  return new BlobRef(row.hash, BigInt(row.size));
}

/** Holds a body: a blob as it came, inline bytes stored with `put`. */
function hold(ctx: Ctx, blob: BlobRef | undefined, bytes: () => Uint8Array): BlobRef {
  if (blob === undefined) return ctx.blobs.put(bytes());
  ctx.blobs.retain(blob);
  return blob;
}

/** A row for `blob`, which the album holds, with the next id; ids are never reused. */
function add(ctx: Ctx, blob: BlobRef, contentType: string): Image {
  const n = (ctx.state.getJson<number>('next_id') ?? 0) + 1;
  ctx.state.setJson('next_id', n);
  const row: Image = { id: `img-${n}`, hash: blob.hash, size: Number(blob.size), content_type: contentType, created_ms: ctx.now() };
  ctx.sql.execute('INSERT INTO images (id, hash, size, content_type, created_ms) VALUES (?1, ?2, ?3, ?4, ?5)', [
    row.id,
    row.hash,
    row.size,
    row.content_type,
    row.created_ms,
  ]);
  return row;
}

/** Deletes a row, and releases its blob unless another row of the album has it. */
function remove(ctx: Ctx, row: Image): void {
  ctx.sql.execute('DELETE FROM images WHERE id = ?1', [row.id]);
  const others = ctx.sql.query('SELECT count(*) AS n FROM images WHERE hash = ?1', [row.hash]).first();
  if (others?.n === 0) ctx.blobs.release(blobOf(row));
}

const created = (ctx: Ctx, row: Image) => ctx.json(201, { id: row.id, hash: row.hash, size: row.size });

function upload(req: Request, ctx: Ctx) {
  const contentType = req.header('content-type');
  if (!isImage(contentType)) return ctx.json(415, { error: 'an image needs a content-type of image/*' });
  if (req.blob === undefined && req.body.length === 0) return ctx.json(400, { error: 'the image is empty' });
  return created(ctx, add(ctx, hold(ctx, req.blob, () => req.body), contentType));
}

function importImage(req: Request, ctx: Ctx) {
  let url: unknown;
  try {
    url = req.json<{ url?: unknown }>().url;
  } catch {
    url = undefined;
  }
  if (typeof url !== 'string' || !/^https?:\/\//.test(url)) {
    return ctx.json(400, { error: 'give the image as {"url": "http(s)://..."}' });
  }
  let res;
  try {
    res = ctx.http.fetch({ url });
  } catch (e) {
    // Without a grant for the host: CAPABILITY_NOT_GRANTED.
    if (e instanceof KronikError) return ctx.json(502, { error: e.message });
    throw e;
  }
  if (!res.ok) return ctx.json(502, { error: `the image's URL answered ${res.status}` });
  const contentType = res.headers.find(([name]) => name.toLowerCase() === 'content-type')?.[1];
  if (!isImage(contentType)) return ctx.json(502, { error: `the URL answered ${contentType ?? 'no content type'}, not an image` });
  const answer = res;
  return created(ctx, add(ctx, hold(ctx, res.blob, () => answer.body), contentType));
}

function share(req: Request, ctx: Ctx, row: Image) {
  const album = req.param('album') ?? '';
  if (album === req.param('key')) return ctx.json(400, { error: 'share the image with another album' });
  ctx.send(`media/${album}`, { name: 'shared', body: { content_type: row.content_type }, blobs: [blobOf(row)] });
  return ctx.json(202, { to: `media/${album}` });
}

function expire(req: Request, ctx: Ctx, row: Image) {
  const days = Number(req.queryParam('days'));
  if (!(days > 0 && days <= MAX_DAYS)) return ctx.json(400, { error: `days must be more than 0 and at most ${MAX_DAYS}` });
  const delay = Math.round(days * DAY_MS);
  // The timer's message carries the blob: it keeps the bytes until it fires.
  ctx.timers.schedule(delay, { name: 'expire', body: { id: row.id }, blobs: [blobOf(row)] });
  return ctx.json(202, { id: row.id, expires_ms: ctx.now() + delay });
}

export default actor({
  kind: 'media',
  schemaVersion: 1,
  routes: [
    { method: 'POST', pattern: '/media/{key}/images' },
    { method: 'GET', pattern: '/media/{key}/images' },
    { method: 'GET', pattern: '/media/{key}/images/{id}' },
    { method: 'DELETE', pattern: '/media/{key}/images/{id}' },
    { method: 'POST', pattern: '/media/{key}/images/{id}/share/{album}' },
    { method: 'POST', pattern: '/media/{key}/images/{id}/expire' },
    { method: 'POST', pattern: '/media/{key}/import' },
  ],

  migrate(from, ctx) {
    if (from < 1) {
      ctx.sql.execute(`CREATE TABLE images (
        id TEXT PRIMARY KEY,
        hash TEXT NOT NULL,
        size INTEGER NOT NULL,
        content_type TEXT NOT NULL,
        created_ms INTEGER NOT NULL,
        _subject TEXT DEFAULT (kronik_subject())
      )`);
    }
  },

  http(req, ctx) {
    // The routes differ in their number of path segments:
    // /media/{key}/images, /media/{key}/import (4), .../images/{id} (5),
    // .../{id}/expire (6) and .../{id}/share/{album} (7).
    const parts = req.path.split('/');
    try {
      if (parts.length === 4) {
        if (parts[3] === 'import') return importImage(req, ctx);
        if (req.method === 'POST') return upload(req, ctx);
        const images = ctx.sql.query(`SELECT ${COLUMNS} FROM images ORDER BY CAST(substr(id, 5) AS INTEGER)`).rows();
        return ctx.json(200, { images });
      }
      const row = image(ctx, req.param('id') ?? '');
      if (row === undefined) return ctx.json(404, { error: 'no such image' });
      if (parts.length === 7) return share(req, ctx, row);
      if (parts.length === 6) return expire(req, ctx, row);
      if (req.method === 'DELETE') {
        remove(ctx, row);
        return ctx.status(204);
      }
      return ctx.blob(200, blobOf(row), row.content_type);
    } catch (e) {
      // Over the actor type's quota (`kronik limits set media --blob-size-per-actor`).
      if (e instanceof KronikError && e.topic === 'BLOB_QUOTA_EXCEEDED') return ctx.json(409, { error: e.message });
      throw e;
    }
  },

  // A shared image: this album retains the blob and adds a row of its own.
  message(msg, ctx) {
    if (msg.name !== 'shared' || msg.blobs.length !== 1) return ctx.none();
    const { content_type } = msg.json<{ content_type: string }>();
    ctx.blobs.retain(msg.blobs[0]);
    add(ctx, msg.blobs[0], content_type);
    return ctx.none();
  },

  // An expiry: the image goes as with DELETE, if it is still there.
  timer(timer, ctx) {
    if (timer.message.name !== 'expire') return ctx.none();
    const row = image(ctx, timer.message.json<{ id: string }>().id);
    if (row !== undefined) remove(ctx, row);
    return ctx.none();
  },
});
