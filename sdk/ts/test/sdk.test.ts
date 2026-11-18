// Unit tests for the parts of the SDK that make no host calls:
// node --test test/*.test.ts

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';
import { explainTopic, hostError, KronikError } from '../src/errors.ts';
import { BlobRef, encodeBody, FetchResponse, json, Message, own, Request, Secret, toJson, toWitMessage, toWitRequest } from '../src/http.ts';
import { fromSql, hasOrderBy, SqlRows, toSql } from '../src/sql.ts';
import { accept, closedOf, Frame, IncomingFrame, OpenRequest, OutcomeUnknown, refusal, sendNowFailure, toOpenReply, toWitFrame } from '../src/connections.ts';

test('host error codes become the explain topic', () => {
  assert.equal(explainTopic('CAPABILITY_NOT_GRANTED: http:api.example.com', 'capability'), 'CAPABILITY_NOT_GRANTED');
  assert.equal(explainTopic('DDL is only allowed in migrate', 'sql-state'), 'sql-state');
  assert.equal(explainTopic('http: bad url', 'effect'), 'effect');
  assert.equal(explainTopic('', 'effect'), 'effect');
});

test('host errors name what failed and a kronik explain topic', () => {
  const denied = hostError('fetch', { payload: { tag: 'denied', val: 'CAPABILITY_NOT_GRANTED: http:x.example' } });
  assert.ok(denied instanceof KronikError);
  assert.equal(denied.kind, 'fetch.denied');
  assert.equal(denied.message, 'HTTP request denied: CAPABILITY_NOT_GRANTED: http:x.example (see `kronik explain CAPABILITY_NOT_GRANTED`)');
  assert.equal(hostError('sql', { payload: { tag: 'too-large' } }).message, 'SQL value or database over its size limit (see `kronik explain sql-state`)');
  assert.equal(hostError('call', { payload: { tag: 'not-found' } }).topic, 'ACTOR_NOT_FOUND');
  assert.equal(
    hostError('reveal', { payload: 'CAPABILITY_NOT_GRANTED: secret-reveal:stripe' }).message,
    'revealing the secret failed: CAPABILITY_NOT_GRANTED: secret-reveal:stripe (see `kronik explain CAPABILITY_NOT_GRANTED`)',
  );
  assert.match(hostError('crypto', new Error('boom')).message, /crypto failed: boom \(see `kronik explain effect`\)/);
});

test('SQL parameters and results convert', () => {
  assert.deepEqual([null, undefined, true, 7, 2.5, 9007199254740993n, 't', new Uint8Array([1])].map(toSql), [
    { tag: 'null' },
    { tag: 'null' },
    { tag: 'integer', val: 1n },
    { tag: 'integer', val: 7n },
    { tag: 'real', val: 2.5 },
    { tag: 'integer', val: 9007199254740993n },
    { tag: 'text', val: 't' },
    { tag: 'blob', val: new Uint8Array([1]) },
  ]);
  assert.throws(() => toSql({} as never), /not a SQL parameter.*kronik explain sql-state/);
  assert.equal(fromSql({ tag: 'integer', val: 42n }), 42);
  assert.equal(fromSql({ tag: 'integer', val: 9007199254740993n }), 9007199254740993n);
  const rows = new SqlRows({
    columns: ['id', 'title', 'done'],
    values: [
      [{ tag: 'integer', val: 1n }, { tag: 'text', val: 'milk' }, { tag: 'null' }],
      [{ tag: 'integer', val: 2n }, { tag: 'text', val: 'eggs' }, { tag: 'integer', val: 1n }],
    ],
  });
  assert.equal(rows.length, 2);
  assert.deepEqual(rows.rows(), [
    { id: 1, title: 'milk', done: null },
    { id: 2, title: 'eggs', done: 1 },
  ]);
  assert.deepEqual(rows.first(), { id: 1, title: 'milk', done: null });
});

test('ORDER BY detection skips literals, identifiers and comments', () => {
  assert.ok(hasOrderBy('SELECT * FROM notes ORDER BY id'));
  assert.ok(hasOrderBy('select id from notes order\n by created desc'));
  assert.ok(hasOrderBy('SELECT id FROM t ORDER /* c */ BY id'));
  assert.ok(!hasOrderBy('SELECT * FROM notes'));
  assert.ok(!hasOrderBy("SELECT * FROM notes WHERE title = 'order by'"));
  assert.ok(!hasOrderBy('SELECT "order", by FROM t'));
  assert.ok(!hasOrderBy('SELECT x FROM t -- ORDER BY x'));
  assert.ok(!hasOrderBy('SELECT x FROM t /* ORDER BY x */'));
  assert.ok(!hasOrderBy('SELECT recorder, bypass FROM t'));
});

test('bodies, JSON and requests', () => {
  assert.equal(encodeBody('hi').contentType, 'text/plain; charset=utf-8');
  assert.equal(encodeBody({ a: 1n }).contentType, 'application/json');
  assert.equal(toJson({ small: 5n, big: 2n ** 60n }), '{"small":5,"big":"1152921504606846976"}');
  assert.throws(() => json(new TextEncoder().encode('{'), 'the body', 'message'), /the body is not the expected JSON.*kronik explain message/);
  const req = new Request({
    method: 'GET',
    path: '/notes/alice',
    query: 'after=7&q=a+b%2Fc',
    params: [['key', 'alice']],
    headers: [{ name: 'Content-Type', value: 'application/json' }],
    body: { tag: 'inline', val: new TextEncoder().encode('{"x":1}') },
  });
  assert.equal(req.param('key'), 'alice');
  assert.equal(req.queryParam('after'), '7');
  assert.equal(req.queryParam('q'), 'a b/c');
  assert.equal(req.queryParam('nope'), undefined);
  assert.equal(req.header('content-type'), 'application/json');
  assert.deepEqual(req.json(), { x: 1 });
  const out = toWitRequest({
    method: 'POST',
    url: 'https://api.example.com/charges',
    headers: { authorization: new Secret('stripe').header() },
    body: { amount: 100 },
  });
  assert.deepEqual(out.headers, [
    { name: 'authorization', value: { tag: 'secret', val: { name: 'stripe', template: 'Bearer {}' } } },
    { name: 'content-type', value: { tag: 'text', val: 'application/json' } },
  ]);
  assert.deepEqual(out.body, { tag: 'inline', val: new TextEncoder().encode('{"amount":100}') });
});

test('query parameters match the SDK contract', () => {
  const q = (query: string, name: string) =>
    new Request({
      method: 'GET',
      path: '/',
      query,
      params: [],
      headers: [],
      body: { tag: 'inline', val: new Uint8Array() },
    }).queryParam(name);
  assert.equal(q('q=a+b%2Fc', 'q'), 'a b/c');
  assert.equal(q('x=%zz%4', 'x'), '%zz%4');
  assert.equal(q('q=%ff', 'q'), undefined);
  assert.equal(q('flag', 'flag'), '');
  assert.equal(q('redir=http://x.com/p;jsessionid=1', 'redir'), 'http://x.com/p;jsessionid=1');
  assert.equal(q('ok=1&q=%ff', 'ok'), '1');
  assert.equal(q('ok=1&q=%ff', 'q'), undefined);
});

// ComponentizeJS hands over list<u8> values from another realm.
test('bytes from another realm are bytes', () => {
  const foreign = runInNewContext('new Uint8Array([0, 1, 2, 3, 4]).subarray(1, 4)') as Uint8Array;
  assert.equal(foreign instanceof Uint8Array, false);
  const mine = own(foreign);
  assert.ok(mine instanceof Uint8Array);
  assert.deepEqual([...mine], [1, 2, 3]);
  assert.equal(mine.buffer, foreign.buffer, 'a view, not a copy');
  assert.deepEqual(encodeBody(foreign), { bytes: mine, contentType: 'application/octet-stream' });
  assert.deepEqual(toSql(foreign), { tag: 'blob', val: foreign });
  assert.ok(fromSql({ tag: 'blob', val: foreign }) instanceof Uint8Array);
  const req = new Request({ method: 'POST', path: '/', query: '', params: [], headers: [], body: { tag: 'inline', val: foreign } });
  assert.ok(req.body instanceof Uint8Array);
});

test('frames for ctx.connections', () => {
  assert.deepEqual(Frame.text('hi'), { tag: 'text', val: 'hi' });
  assert.deepEqual(Frame.json({ n: 2n ** 60n }), { tag: 'text', val: '{"n":"1152921504606846976"}' });
  assert.deepEqual(Frame.binary(new Uint8Array([1, 2])), { tag: 'binary', val: new Uint8Array([1, 2]) });
  assert.deepEqual(Frame.event({ data: { seq: 7 }, id: 7 }), { tag: 'event', val: { event: '', id: '7', data: '{"seq":7}' } });
  assert.deepEqual(Frame.event({ event: 'message', data: 'x' }), { tag: 'event', val: { event: 'message', id: '', data: 'x' } });
  assert.deepEqual(toWitFrame('hi'), Frame.text('hi'));
  assert.deepEqual(toWitFrame(new Uint8Array([3])), Frame.binary(new Uint8Array([3])));
  const foreign = runInNewContext('new Uint8Array([4])') as Uint8Array;
  assert.deepEqual(toWitFrame(foreign).tag, 'binary');
  assert.equal(toWitFrame(Frame.json(1)).tag, 'text');
  assert.throws(() => toWitFrame({ type: 'say' } as never), /not a frame.*kronik explain connections/);
});

test('the open request, incoming frames and the close', () => {
  const req = new OpenRequest({
    connection: 'c-0123',
    protocol: 'websocket',
    subprotocols: ['chat.v1'],
    request: {
      method: 'GET',
      path: '/chat/lobby/ws',
      query: 'user=ada',
      params: [['key', 'lobby']],
      headers: [
        { name: 'Origin', value: 'https://chat.example' },
        { name: 'Last-Event-ID', value: '41' },
      ],
      body: { tag: 'inline', val: new Uint8Array() },
    },
  });
  assert.equal(req.connection, 'c-0123');
  assert.equal(req.protocol, 'websocket');
  assert.deepEqual(req.subprotocols, ['chat.v1']);
  assert.equal(req.param('key'), 'lobby');
  assert.equal(req.queryParam('user'), 'ada');
  assert.equal(req.origin(), 'https://chat.example');
  assert.equal(req.lastEventId(), '41');
  const text = new IncomingFrame({ connection: 'c-0123', seq: 3n, frame: { tag: 'text', val: '{"type":"say"}' } });
  assert.equal(text.seq, 3);
  assert.equal(text.kind, 'text');
  assert.deepEqual(text.json(), { type: 'say' });
  assert.deepEqual([...text.bytes()], [...new TextEncoder().encode('{"type":"say"}')]);
  const binary = new IncomingFrame({ connection: 'c-0123', seq: 4n, frame: { tag: 'binary', val: new TextEncoder().encode('hé') } });
  assert.equal(binary.text(), 'hé');
  const bad = new IncomingFrame({ connection: 'c-0123', seq: 5n, frame: { tag: 'binary', val: new Uint8Array([0xff]) } });
  assert.throws(() => bad.text(), /the frame is not UTF-8.*kronik explain connections/);
  assert.throws(() => new IncomingFrame({ connection: 'c', seq: 0n, frame: { tag: 'text', val: '{' } }).json(), /not the expected JSON/);
  assert.deepEqual(closedOf({ connection: 'c-0123', info: { initiator: 'host', code: 1012, reason: 'restart' } }), {
    connection: 'c-0123',
    initiator: 'host',
    code: 1012,
    reason: 'restart',
  });
});

test('an open handler accepts, or refuses with an HTTP response', () => {
  assert.deepEqual(accept(), { tag: 'accept', val: { subprotocol: undefined, headers: [], subject: undefined } });
  assert.deepEqual(accept({ subprotocol: 'chat.v1', headers: { 'x-room': 'lobby' }, subject: 'user:ada' }), {
    tag: 'accept',
    val: { subprotocol: 'chat.v1', headers: [{ name: 'x-room', value: 'lobby' }], subject: 'user:ada' },
  });
  const forbidden = { status: 403, headers: [], body: { tag: 'inline' as const, val: new Uint8Array() } };
  assert.deepEqual(toOpenReply({ tag: 'http', val: forbidden }), { tag: 'refuse', val: forbidden });
  assert.deepEqual(toOpenReply(accept()), accept());
  assert.throws(() => toOpenReply({ tag: 'none' }), /must return ctx.accept\(\) or an HTTP response.*it returned none/);
  const refused = refusal(404, 'no connections here');
  assert.equal(refused.tag, 'refuse');
  assert.equal(refused.tag === 'refuse' && refused.val.status, 404);
});

test('send-now failures: closed is false, the rest throw', () => {
  assert.equal(sendNowFailure({ payload: { tag: 'closed' } }), false);
  const unknown = sendNowFailure({ payload: { tag: 'outcome-unknown' } });
  assert.ok(unknown instanceof OutcomeUnknown);
  assert.equal((unknown as OutcomeUnknown).topic, 'EFFECT_OUTCOME_UNKNOWN');
  assert.match((unknown as Error).message, /may or may not have reached the client \(see `kronik explain EFFECT_OUTCOME_UNKNOWN`\)/);
  const denied = sendNowFailure({ payload: { tag: 'denied', val: 'CAPABILITY_NOT_GRANTED: connection:send-now' } }) as KronikError;
  assert.equal(denied.kind, 'send-now.denied');
  assert.equal(denied.topic, 'CAPABILITY_NOT_GRANTED');
  assert.equal((sendNowFailure(new Error('boom')) as KronikError).kind, 'send-now.unknown');
});

test('a blob body is read once, when first used', () => {
  let reads = 0;
  const read = (b: BlobRef) => {
    reads++;
    assert.equal(b.hash, 'b3:' + 'ab'.repeat(32));
    return new TextEncoder().encode('{"big":true}');
  };
  const blob = { hash: 'b3:' + 'ab'.repeat(32), size: 12n };
  const req = new Request({ method: 'POST', path: '/p', query: '', params: [], headers: [], body: { tag: 'blob', val: blob } }, read);
  assert.ok(req.blob instanceof BlobRef);
  assert.equal(req.blob?.size, 12n);
  assert.equal(reads, 0);
  assert.deepEqual(req.json(), { big: true });
  assert.equal(req.text(), '{"big":true}');
  assert.equal(reads, 1);
  const inline = new Request({ method: 'POST', path: '/p', query: '', params: [], headers: [], body: { tag: 'inline', val: new Uint8Array([1]) } }, read);
  assert.equal(inline.blob, undefined);
  assert.deepEqual(inline.body, new Uint8Array([1]));
  assert.equal(reads, 1);
  // Without a reader (a value built outside a turn) a blob body cannot be read.
  const unread = new Request({ method: 'GET', path: '/p', query: '', params: [], headers: [], body: { tag: 'blob', val: blob } });
  assert.throws(() => unread.body, /the request body is a blob that this value cannot read/);
});

test('a fetch response may be a blob, read lazily', () => {
  const blob = { hash: 'b3:' + 'cd'.repeat(32), size: 3n };
  const res = new FetchResponse({ status: 200, headers: [], body: { tag: 'blob', val: blob } }, () => new Uint8Array([7, 8, 9]));
  assert.equal(res.blob?.hash, blob.hash);
  assert.deepEqual(res.body, new Uint8Array([7, 8, 9]));
});

test('a blob is sent as a fetch body as it is', () => {
  const blob = new BlobRef('b3:' + 'ef'.repeat(32), 5n);
  const req = toWitRequest({ method: 'PUT', url: 'https://x.example/up', body: blob });
  assert.deepEqual(req.body, { tag: 'blob', val: { hash: blob.hash, size: 5n } });
  assert.deepEqual(req.headers, [{ name: 'content-type', value: { tag: 'text', val: 'application/octet-stream' } }]);
  const typed = toWitRequest({ method: 'PUT', url: 'https://x.example/up', headers: { 'Content-Type': 'application/pdf' }, body: blob });
  assert.deepEqual(typed.headers, [{ name: 'Content-Type', value: { tag: 'text', val: 'application/pdf' } }]);
  // A plain object with the same fields is a JSON body, not a blob.
  const json = toWitRequest({ method: 'POST', url: 'https://x.example/', body: { hash: blob.hash, size: 5 } });
  assert.equal(json.body.tag, 'inline');
});

test('blob errors name their code', () => {
  assert.equal(hostError('blob', { payload: { tag: 'not-held' } }).topic, 'BLOB_NOT_HELD');
  assert.equal(hostError('blob', { payload: { tag: 'quota-exceeded' } }).topic, 'BLOB_QUOTA_EXCEEDED');
  assert.equal(hostError('blob', { payload: { tag: 'erased' } }).message, 'the blob belonged to an erased subject (see `kronik explain SUBJECT_ERASED`)');
  assert.equal(hostError('blob', { payload: { tag: 'invalid', val: 'more than 1 MiB in one call' } }).kind, 'blob.invalid');
});

test('messages carry blobs both ways (M26)', () => {
  const a = new BlobRef('b3:' + 'aa'.repeat(32), 5n);
  const b = new BlobRef('b3s:' + 'bb'.repeat(32), 1048577n);
  assert.deepEqual(toWitMessage({ name: 'shared', body: { id: 'img-1' }, blobs: [a, b] }), {
    name: 'shared',
    contentType: 'application/json',
    body: new TextEncoder().encode('{"id":"img-1"}'),
    blobs: [
      { hash: a.hash, size: 5n },
      { hash: b.hash, size: 1048577n },
    ],
  });
  assert.deepEqual(toWitMessage({ name: 'tick' }).blobs, []);
  const incoming = new Message({ name: 'shared', contentType: 'text/plain', body: new Uint8Array(), blobs: [{ hash: a.hash, size: 5n }] });
  assert.equal(incoming.blobs.length, 1);
  assert.ok(incoming.blobs[0] instanceof BlobRef);
  assert.deepEqual([incoming.blobs[0].hash, incoming.blobs[0].size], [a.hash, 5n]);
  assert.deepEqual(new Message({ name: 'tick', contentType: '', body: new Uint8Array(), blobs: [] }).blobs, []);
});
