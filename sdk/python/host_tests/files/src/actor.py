# The SDK's blobs (M25) in an actor, for host_tests/test_blobs.py: it reads
# a body inline or as a blob (whole, in a range and with a reader), answers
# with a blob, writes one, sends one in a fetch whose answer is a blob, and
# tries a reference it never got. M26: it holds blobs across turns (`put`,
# `retain`, `release`, `put_for`) and sends one in a message to another key,
# which retains it.

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


def kept(ctx):
    """The blob this key keeps, rebuilt from its hash and size in state."""
    k = ctx.state.get_json("kept")
    return BlobRef(k["hash"], k["size"]) if k else None


def keep(ctx, blob):
    ctx.state.set_json("kept", {"hash": blob.hash, "size": blob.size})
    return ctx.json(200, {"hash": blob.hash, "size": blob.size})


def holds(op, req, ctx):
    """M26: the hold operations; None for any other op."""
    if op == "keep":
        blob = req.blob if req.blob is not None else ctx.blobs.put(req.body)
        if req.blob is not None:
            ctx.blobs.retain(blob)
        return keep(ctx, blob)
    if op == "put-big":
        return keep(ctx, ctx.blobs.put(pattern(0, int(req.query_param("size") or 0))))
    if op == "put-for":
        return keep(ctx, ctx.blobs.put_for(req.query_param("subject"), req.body))
    blob = kept(ctx)
    if op in ("kept", "release", "share") and blob is None:
        return ctx.status(404)
    if op == "kept":
        # A read first: a blob the actor no longer holds gives its error here.
        try:
            ctx.blobs.get(blob, 0, 1)
        except KronikError as e:
            return ctx.json(409, {"error": e.topic})
        return ctx.blob(200, blob)
    if op == "release":
        try:
            ctx.blobs.release(blob)
        except KronikError as e:
            return ctx.json(200, {"error": e.topic})
        return ctx.json(200, {"ok": True})
    if op == "share":
        ctx.send(f"files/{req.query_param('to')}", {"name": "shared", "body": "from " + req.param("key"), "blobs": [blob]})
        return ctx.status(202)
    return None


def message(msg, ctx):
    """M26: a shared blob arrives with the message; this key retains it."""
    if msg.name == "shared" and len(msg.blobs) == 1:
        ctx.blobs.retain(msg.blobs[0])
        ctx.state.set_json("kept", {"hash": msg.blobs[0].hash, "size": msg.blobs[0].size})
    return ctx.none()


def http(req, ctx):
    op = req.param("op")
    answer = holds(op, req, ctx)
    if answer is not None:
        return answer
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
    message=message,
)
