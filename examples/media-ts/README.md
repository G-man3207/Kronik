# media-ts

An image album per actor (kind `media`, key = the album): the example of
blob storage (M26, [the design](../../docs/design/m26-blobs.md) §15). An
image's bytes are a blob that the album holds; SQL keeps each image's hash,
size and content type.

| Route | Does |
| --- | --- |
| `POST /media/{key}/images` | an upload with a `content-type` of `image/*`: the album holds its blob and adds a row; `201 {"id","hash","size"}` |
| `GET /media/{key}/images` | `{"images": [{"id","hash","size","content_type","created_ms"}]}`, in upload order |
| `GET /media/{key}/images/{id}` | the image, with its content type |
| `DELETE /media/{key}/images/{id}` | deletes the row; the album lets the blob go with its last row |
| `POST /media/{key}/images/{id}/share/{album}` | sends the blob in a message to another album, which holds it and adds a row of its own; `202 {"to"}` |
| `POST /media/{key}/import` | `{"url": "https://..."}`: fetches an image (the host needs a grant) and holds it; `201` |
| `POST /media/{key}/images/{id}/expire?days=N` | a timer whose message carries the blob; when it fires, the image goes as with `DELETE` |

How it uses blobs:

- An upload above the blob threshold (1 MiB by default) arrives as a blob,
  which the album retains; a smaller one arrives inline and is stored with
  `ctx.blobs.put`. Either way the album holds the blob from the turn's
  commit on, and later turns read it.
- The hash in SQL keeps nothing alive and grants nothing: a reference is only
  a hash and a size, and the host lets the album use it because the album
  holds the blob. The same bytes uploaded twice are one blob in two rows, so
  a delete releases the blob only with its last row.
- A share sends the blob with a message (`blobs`); the receiving album may
  read it in that turn and keeps it because it retains it. Each album's hold
  is its own: the sender's delete leaves the receiver's image.
- An expiry's timer carries the blob, which keeps the bytes until it fires,
  even if the image was deleted meanwhile.
- An image is its uploader's data. With `[privacy] subject_from`, its row
  and its blob get the subject of the upload request, and a share and an
  expiry run under that subject, whoever asks: the copy in the receiving
  album and the timer are the owner's too, and erasing the owner takes
  them all.
- A blob that nothing holds, carries or keeps any more is deleted by
  collection once retention passes its last record.

## Try it

With `kronik serve` running (see the [quickstart](../../docs/guides/quickstart.md)),
from the repository root:

```sh
(cd examples && npm install)
kronik build --dir examples/media-ts
kronik deploy examples/media-ts/dist/media-ts.wasm --reason "the media example"

curl -s -X POST --data-binary @photo.png -H 'content-type: image/png' \
  http://127.0.0.1:8080/media/trip/images
curl -s http://127.0.0.1:8080/media/trip/images
curl -s -o copy.png http://127.0.0.1:8080/media/trip/images/img-1
curl -s -X POST http://127.0.0.1:8080/media/trip/images/img-1/share/family
curl -s -X POST 'http://127.0.0.1:8080/media/trip/images/img-1/expire?days=30'
```

An import needs a grant for the image's host, like any outgoing request:

```sh
kronik grant media http:upload.wikimedia.org --reason "media imports"
curl -s -X POST -H 'content-type: application/json' \
  -d '{"url": "https://upload.wikimedia.org/wikipedia/commons/a/a9/Example.jpg"}' \
  http://127.0.0.1:8080/media/trip/import
```

What the albums hold, and what keeps a blob:

```sh
kronik blobs list --actor media/trip
kronik blobs inspect <hash>
kronik blobs gc --dry-run
```

`npm test` runs the tests against a test host (`KRONIK_BIN` names the
`kronik` binary); `scripts/identity-examples.py` replays a workload of
uploads, reads, shares, imports and expiries through the same code and
expects an empty diff. Its `media-ts-private` variant does the same with
privacy mode on and two users, then checks that erasing a user who shared
another's image leaves that image, and that erasing its owner removes it
from both albums.
