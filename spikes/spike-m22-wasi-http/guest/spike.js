// Spike M22 guest: standard `fetch` (StarlingMonkey's, via wasi:http).
// `run(mode)` resolves to a JSON string; ComponentizeJS runs the event loop
// until the promise settles.
const order = [];

async function call(tag, url, init) {
  const r = await fetch(url, init);
  order.push(tag);
  return { status: r.status, text: await r.text() };
}

function chunks(n) {
  let i = 0;
  return new ReadableStream({
    pull(c) {
      if (i < n) {
        c.enqueue(new Uint8Array([97 + (i % 26)]));
        i += 1;
      } else {
        c.close();
      }
    },
  });
}

export async function run(mode) {
  order.length = 0;
  let out;
  if (mode === 'two') {
    // Two fetches in flight at once; whichever settles first is pushed first.
    const [a, b] = await Promise.all([
      call('a', 'http://a.example/slow', { method: 'POST', body: 'hello a' }),
      call('b', 'http://b.example/fast?q=1', {
        headers: { authorization: 'Bearer {{secret:api}}', 'x-n': '2' },
      }),
    ]);
    out = { a, b };
  } else if (mode === 'stream') {
    // A body of 64 one-byte chunks: more than the outgoing body's buffer.
    out = {
      s: await call('s', 'http://s.example/upload', {
        method: 'POST',
        body: chunks(64),
        duplex: 'half',
      }),
    };
  } else if (mode === 'error') {
    try {
      await fetch('http://denied.example/');
      out = { error: null };
    } catch (e) {
      out = { error: String(e) };
    }
  } else {
    throw new Error(`unknown mode ${mode}`);
  }
  return JSON.stringify({ order, ...out });
}
