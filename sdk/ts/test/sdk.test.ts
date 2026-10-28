// Unit tests for the parts of the SDK that make no host calls:
// node --test test/*.test.ts

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';
import { explainTopic, hostError, KronikError } from '../src/errors.ts';
import { encodeBody, json, own, Request, Secret, toJson, toWitRequest } from '../src/http.ts';
import { fromSql, hasOrderBy, SqlRows, toSql } from '../src/sql.ts';

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
