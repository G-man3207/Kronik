// The turn's access to the host. Every method is a synchronous host call.

import { get as stateGet, set as stateSet, setFor as stateSetFor, delete as stateDelete, keys as stateKeys } from 'kronik:actor/state@0.1.0';
import { query as sqlQuery, execute as sqlExecute } from 'kronik:actor/sql@0.1.0';
import { selfRef, causalId, nowMs, randomBytes } from 'kronik:actor/context@0.1.0';
import { send as messagingSend, call as messagingCall } from 'kronik:actor/messaging@0.1.0';
import { schedule as timersSchedule, cancel as timersCancel } from 'kronik:actor/timers@0.1.0';
import { fetch as httpFetch } from 'kronik:actor/http-client@0.1.0';
import { hmacSha256, signEd25519 } from 'kronik:actor/crypto@0.1.0';
import { reveal } from 'kronik:actor/secrets@0.1.0';
import { emit, type Level } from 'kronik:actor/log@0.1.0';
import { setSubject, currentSubject } from 'kronik:actor/privacy@0.1.0';
import type { ActorRef, Message as WitMessage, Output } from 'kronik:actor/types@0.1.0';
import { hostError } from './errors.ts';
import { type Body, encodeBody, FetchResponse, type FetchRequest, json, Message, own, Secret, text, toJson, toWitRequest } from './http.ts';
import { hasOrderBy, SqlRows, toSql, type SqlParam } from './sql.ts';

const encoder = new TextEncoder();

/** An actor, as `"kind/key"` or `{ kind, key }`. */
export type ActorLike = string | ActorRef;

/** A message to send: a name and a body (bytes, text, or a value as JSON). */
export interface OutgoingMessage {
  name: string;
  body?: Body;
  /** Overrides the content type that follows from the body. */
  contentType?: string;
}

function actorRef(actor: ActorLike): ActorRef {
  if (typeof actor !== 'string') return actor;
  const slash = actor.indexOf('/');
  if (slash <= 0 || slash === actor.length - 1) {
    throw new TypeError(`${JSON.stringify(actor)} is not an actor: expected kind/key (see \`kronik explain actor\`)`);
  }
  return { kind: actor.slice(0, slash), key: actor.slice(slash + 1) };
}

function witMessage(msg: OutgoingMessage): WitMessage {
  const { bytes, contentType } = msg.body === undefined ? { bytes: new Uint8Array(), contentType: '' } : encodeBody(msg.body);
  return { name: msg.name, contentType: msg.contentType ?? contentType, body: bytes, blobs: [] };
}

/** The actor's key-value state. Writes apply only if the turn commits. */
export class State {
  /** The value of `key`. */
  get(key: string): Uint8Array | undefined {
    const value = stateGet(key);
    return value === undefined ? undefined : own(value);
  }

  /** The value of `key` as UTF-8 text. */
  getText(key: string): string | undefined {
    const value = stateGet(key);
    return value === undefined ? undefined : text(value, `state value ${JSON.stringify(key)}`, 'actor');
  }

  /** The value of `key` parsed as JSON. */
  getJson<T = unknown>(key: string): T | undefined {
    const value = stateGet(key);
    return value === undefined ? undefined : json<T>(value, `state value ${JSON.stringify(key)}`, 'actor');
  }

  /** Sets `key` (bytes, or text as UTF-8), tagged with the turn's default subject. */
  set(key: string, value: Uint8Array | string): void {
    stateSet(key, typeof value === 'string' ? encoder.encode(value) : value);
  }

  /** Sets `key` to `value` as JSON, tagged with the turn's default subject. */
  setJson(key: string, value: unknown): void {
    stateSet(key, encoder.encode(toJson(value)));
  }

  /** Sets `key` tagged with `subject` (`null`: no subject), whatever the turn's default subject is. */
  setFor(subject: string | null, key: string, value: Uint8Array | string): void {
    stateSetFor(subject ?? undefined, key, typeof value === 'string' ? encoder.encode(value) : value);
  }

  /** Deletes `key`. */
  delete(key: string): void {
    stateDelete(key);
  }

  /** The keys that start with `prefix`. */
  keys(prefix = ''): string[] {
    return stateKeys(prefix);
  }
}

/**
 * The actor's own SQLite database (see `kronik explain sql-state`). DDL is
 * allowed only in `migrate`, before the first statement that changes data;
 * `datetime('now')`, `random()` and `randomblob()` are deterministic, and
 * `kronik_subject()` gives the turn's default subject.
 */
export class Sql {
  private readonly log: Log;

  constructor(log: Log) {
    this.log = log;
  }

  /**
   * Runs a query. A query without ORDER BY that returns several rows logs a
   * warning: their order then depends on SQLite's plan.
   */
  query(statement: string, params: SqlParam[] = []): SqlRows {
    let rows;
    try {
      rows = sqlQuery(statement, params.map(toSql));
    } catch (e) {
      throw hostError('sql', e);
    }
    if (rows.values.length > 1 && !hasOrderBy(statement)) {
      this.log.warn('a query returned several rows without ORDER BY, so their order is not guaranteed (see `kronik explain sql-state`)', {
        rows: rows.values.length,
        statement,
      });
    }
    return new SqlRows(rows);
  }

  /** Runs a statement that returns no rows and returns how many rows it changed. */
  execute(statement: string, params: SqlParam[] = []): number {
    try {
      return Number(sqlExecute(statement, params.map(toSql)));
    } catch (e) {
      throw hostError('sql', e);
    }
  }
}

/** Outgoing HTTP, recorded as effects (see `kronik explain effect`). Needs the capability `http:<host>`. */
export class Http {
  /** Sends `request` and waits for the response. */
  fetch(request: FetchRequest): FetchResponse {
    try {
      return new FetchResponse(httpFetch(toWitRequest(request)));
    } catch (e) {
      throw hostError('fetch', e);
    }
  }
}

/** Crypto computed by the host with a secret's value; needs the capability `secret:<name>`. */
export class Crypto {
  /** HMAC-SHA256 of `data` keyed with `secret`. */
  hmacSha256(secret: Secret | string, data: Uint8Array | string): Uint8Array {
    try {
      return own(hmacSha256(typeof secret === 'string' ? secret : secret.name, typeof data === 'string' ? encoder.encode(data) : data));
    } catch (e) {
      throw hostError('crypto', e);
    }
  }

  /** An Ed25519 signature of `data` with the private key `secret`. */
  signEd25519(secret: Secret | string, data: Uint8Array | string): Uint8Array {
    try {
      return own(signEd25519(typeof secret === 'string' ? secret : secret.name, typeof data === 'string' ? encoder.encode(data) : data));
    } catch (e) {
      throw hostError('crypto', e);
    }
  }
}

/** Revealing secrets: the exception path, behind the capability `secret-reveal:<name>`. */
export class Secrets {
  /** The value of `secret` inside the guest. Prefer secret headers and `ctx.crypto`. */
  reveal(secret: Secret | string): string {
    try {
      return reveal(typeof secret === 'string' ? secret : secret.name);
    } catch (e) {
      throw hostError('reveal', e);
    }
  }
}

/** Timers that deliver a message to this actor later. Registered only if the turn commits. */
export class Timers {
  /** Schedules `msg` to arrive as a timer input after `delayMs`; returns the timer's id. */
  schedule(delayMs: number, msg: OutgoingMessage): bigint {
    return timersSchedule(BigInt(Math.max(0, Math.floor(delayMs))), witMessage(msg));
  }

  /** Cancels the timer `id`; returns whether it was pending. */
  cancel(id: bigint): boolean {
    return timersCancel(id);
  }
}

/** Randomness from the turn's recorded seed: a replay gets the same values. */
export class Random {
  /** `length` random bytes (at most 1 MiB). */
  bytes(length: number): Uint8Array {
    return own(randomBytes(length));
  }

  /** A random unsigned 64-bit integer. */
  u64(): bigint {
    const bytes = randomBytes(8);
    return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(0, true);
  }
}

/** The actor's log. The host adds the turn's ids to every event. */
export class Log {
  /** Logs `message` at `level` with `fields`. */
  emit(level: Level, message: string, fields: Record<string, unknown> = {}): void {
    emit(
      level,
      message,
      Object.entries(fields).map(([k, v]) => [k, typeof v === 'string' ? v : toJson(v)]),
    );
  }

  trace(message: string, fields?: Record<string, unknown>): void {
    this.emit('trace', message, fields);
  }

  debug(message: string, fields?: Record<string, unknown>): void {
    this.emit('debug', message, fields);
  }

  info(message: string, fields?: Record<string, unknown>): void {
    this.emit('info', message, fields);
  }

  warn(message: string, fields?: Record<string, unknown>): void {
    this.emit('warn', message, fields);
  }

  error(message: string, fields?: Record<string, unknown>): void {
    this.emit('error', message, fields);
  }
}

/**
 * A turn's access to the host: the names Kronik's SDKs share (`state`,
 * `sql`, `send`, `call`, `http.fetch`, `crypto`, `timers`, `now`, `random`,
 * `causalId`, `secret`, `subject`, `log`) and helpers for outputs.
 */
export class Ctx {
  readonly state = new State();
  readonly log = new Log();
  readonly sql = new Sql(this.log);
  readonly http = new Http();
  readonly crypto = new Crypto();
  readonly secrets = new Secrets();
  readonly timers = new Timers();
  readonly random = new Random();

  /** Sends a message to `to`: buffered, delivered exactly once, only if this turn commits. */
  send(to: ActorLike, msg: OutgoingMessage): void {
    messagingSend(actorRef(to), witMessage(msg));
  }

  /**
   * Calls `to` and waits for its reply. The callee commits its own turn now;
   * if this turn fails afterwards, `compensate` is delivered to it once.
   */
  call(to: ActorLike, msg: OutgoingMessage, compensate?: OutgoingMessage): Message | undefined {
    let reply;
    try {
      reply = messagingCall(actorRef(to), witMessage(msg), compensate && witMessage(compensate));
    } catch (e) {
      throw hostError('call', e);
    }
    return reply && new Message(reply);
  }

  /** The turn's logical time in milliseconds since the Unix epoch: constant within the turn and recorded. */
  now(): number {
    return Number(nowMs());
  }

  /** The turn's correlation id, the same in production and in replay. */
  causalId(): string {
    return causalId();
  }

  /** This actor. */
  self(): ActorRef {
    return selfRef();
  }

  /** A handle to the secret `name`; its value never enters the guest. */
  secret(name: string): Secret {
    return new Secret(name);
  }

  /** Sets the default subject (such as `"user:123"`) for values written from now on; `null`: none. */
  subject(subject: string | null): void {
    setSubject(subject ?? undefined);
  }

  /** The current default subject. */
  currentSubject(): string | undefined {
    return currentSubject();
  }

  /** An HTTP response with `value` as a JSON body. */
  json(status: number, value: unknown): Output {
    const body = encoder.encode(toJson(value));
    return { tag: 'http', val: { status, headers: [{ name: 'content-type', value: 'application/json' }], body: { tag: 'inline', val: body } } };
  }

  /** An HTTP response with a text body. */
  text(status: number, body: string): Output {
    const bytes = encoder.encode(body);
    return { tag: 'http', val: { status, headers: [{ name: 'content-type', value: 'text/plain; charset=utf-8' }], body: { tag: 'inline', val: bytes } } };
  }

  /** An HTTP response with no body, such as 404. */
  status(status: number): Output {
    return { tag: 'http', val: { status, headers: [], body: { tag: 'inline', val: new Uint8Array() } } };
  }

  /** A reply message (an HTTP request gets 200 with its body). */
  reply(msg: OutgoingMessage): Output {
    return { tag: 'reply', val: witMessage(msg) };
  }

  /** No output (an HTTP request gets 204). */
  none(): Output {
    return { tag: 'none' };
  }
}
