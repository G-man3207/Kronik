# The SDK's blobs (M25) in an actor, for host_tests/test_blobs.py: it reads
# a body inline or as a blob (whole, in a range and with a reader), answers
# with a blob, writes one, sends one in a fetch whose answer is a blob, and
# tries a reference it never got.

from kronik import BlobRef, KronikError, actor

P = 1_000_000_007
# The test's bytes: byte i is (i * 31 + 7) % 251, which repeats every 251.
PERIOD = bytes((i * 31 + 7) % 251 for i in range(251))


def pattern(start, n):
    k = start % 251
    return (PERIOD * ((k + n) // 251 + 1))[k : k + n]


STEP = 4093


def probe(data, start=0, s=0):
    """Every STEP-th byte of a body weighted by its place, `data` being the
    body's bytes from `start`: a few hundred steps for a megabyte (a turn's
    fuel would not cover a loop over every byte)."""
    i = -(-start // STEP) * STEP
    while i < start + len(data):
        s = (s + data[i - start] * ((i // STEP) % 7 + 1)) % P
        i += STEP
    return s


def info(req, ctx):
    blob = req.blob
    if blob is None:
        return ctx.json(200, {"blob": False, "size": len(req.body), "range": list(req.body[2:6]),
                              "streamed": probe(req.body), "whole": probe(req.body)})
    reader = ctx.blobs.reader(blob)
    streamed, at = 0, 0
    while chunk := reader.read(200_000):
        streamed = probe(chunk, at, streamed)
        at += len(chunk)
    return ctx.json(200, {"blob": True, "size": blob.size, "range": list(ctx.blobs.get(blob, 2, 4)),
                          "streamed": streamed, "whole": probe(req.body)})


def http(req, ctx):
    op = req.param("op")
    if op == "info":
        return info(req, ctx)
    if op == "echo":
        if req.blob is not None:
            return ctx.blob(200, req.blob, req.header("content-type") or "application/octet-stream")
        return ctx.text(200, req.text())
    if op == "write":
        size = int(req.query_param("size") or 0)
        writer = ctx.blobs.writer()
        for at in range(0, size, 300_000):
            writer.write(pattern(at, min(300_000, size - at)))
        return ctx.blob(200, writer.finish())
    if op == "relay":
        body = req.blob if req.blob is not None else req.body
        res = ctx.http.fetch(req.query_param("url"), method="POST", body=body)
        return ctx.json(200, {"status": res.status, "blob": res.blob is not None, "size": len(res.body),
                              "sum": probe(res.body)})
    if op == "forged":
        try:
            ctx.blobs.get(BlobRef("b3:" + "0" * 64, 10), 0, 10)
        except KronikError as e:
            return ctx.json(200, {"error": e.topic})
        return ctx.json(200, {"error": None})
    return ctx.status(404)


handler = actor(
    kind="files",
    schema_version=0,
    routes=[{"method": "POST", "pattern": "/files/{key}/{op}"}, {"method": "GET", "pattern": "/files/{key}/{op}"}],
    capabilities=["http:store.test"],
    http=http,
)
