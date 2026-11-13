// Long-lived connections (M24): frames, the open request, incoming frames,
// the close, and the open handler's answer. No host calls here: those are
// `ctx.connections` in ctx.ts.

import type {
  CloseInitiator,
  Closed as WitClosed,
  Frame as WitFrame,
  IncomingFrame as WitIncomingFrame,
  OpenReply,
  OpenRequest as WitOpenRequest,
  Protocol,
} from 'kronik:actor/connections@0.1.1';
import type { HttpResponse, Output } from 'kronik:actor/types@0.1.1';
import { explainTopic, KronikError } from './errors.ts';
import { isBytes, json, own, Request, text, toJson } from './http.ts';

const encoder = new TextEncoder();

/** A frame to send: one WebSocket message or one SSE event. */
export type OutgoingFrame = WitFrame;

/** What `send`, `broadcast` and `sendNow` take: a frame, or a string (a text frame) or bytes (a binary frame). */
export type FrameLike = OutgoingFrame | string | Uint8Array;

/** Builds frames for `ctx.connections`. */
export const Frame = {
  /** A text frame; on an SSE stream, an event with only data. */
  text(text: string): OutgoingFrame {
    return { tag: 'text', val: text };
  },

  /** `value` as JSON in a text frame. */
  json(value: unknown): OutgoingFrame {
    return { tag: 'text', val: toJson(value) };
  },

  /** A binary frame (WebSocket only: sending one on an SSE stream traps). */
  binary(bytes: Uint8Array): OutgoingFrame {
    return { tag: 'binary', val: own(bytes) };
  },

  /**
   * An SSE event: `data` as text, or any other value as JSON, with an
   * optional `event` name and `id`. A reconnecting EventSource sends the
   * last id back (`req.lastEventId()`). On a WebSocket, a text frame with
   * the data.
   */
  event(event: { event?: string; id?: string | number | bigint; data: unknown }): OutgoingFrame {
    return {
      tag: 'event',
      val: {
        event: event.event ?? '',
        id: event.id === undefined ? '' : String(event.id),
        data: typeof event.data === 'string' ? event.data : toJson(event.data),
      },
    };
  },
};

/** `frame` as the WIT frame the host takes. */
export function toWitFrame(frame: FrameLike): OutgoingFrame {
  if (typeof frame === 'string') return Frame.text(frame);
  if (isBytes(frame)) return Frame.binary(frame);
  const tag = (frame as { tag?: unknown } | null)?.tag;
  if (tag === 'text' || tag === 'binary' || tag === 'event') return frame as OutgoingFrame;
  throw new KronikError(
    'frame',
    'not a frame',
    'send a string, bytes, or Frame.text/json/binary/event(...)',
    'connections',
  );
}

/**
 * A client asks to open a connection: a WebSocket upgrade or an SSE GET,
 * routed by one of the kind's `WEBSOCKET` or `SSE` routes. The body is
 * empty.
 */
export class OpenRequest extends Request {
  /** The new connection's id (`c-...`). Keep it to send to the connection in later turns. */
  readonly connection: string;
  readonly protocol: Protocol;
  /** The WebSocket subprotocols the client offered (`Sec-WebSocket-Protocol`), in order. */
  readonly subprotocols: string[];

  constructor(req: WitOpenRequest) {
    super(req.request);
    this.connection = req.connection;
    this.protocol = req.protocol;
    this.subprotocols = req.subprotocols;
  }

  /**
   * The `Origin` header. A browser sends it, with its cookies, on a
   * WebSocket handshake: an actor that authenticates by cookie checks it
   * (see `kronik explain connections`).
   */
  origin(): string | undefined {
    return this.header('origin');
  }

  /** The last SSE event id a reconnecting EventSource saw (`Last-Event-ID`). */
  lastEventId(): string | undefined {
    return this.header('last-event-id');
  }
}

/** One frame from a client (WebSocket only). */
export class IncomingFrame {
  /** The connection it came on. */
  readonly connection: string;
  /** 0, 1, 2, ... per connection, in the order the client sent them. */
  readonly seq: number;
  readonly kind: 'text' | 'binary' | 'event';
  readonly #frame: WitFrame;

  constructor(event: WitIncomingFrame) {
    this.connection = event.connection;
    this.seq = Number(event.seq);
    this.kind = event.frame.tag;
    this.#frame = event.frame;
  }

  /** The frame's bytes: a text frame's text as UTF-8. */
  bytes(): Uint8Array {
    const f = this.#frame;
    if (f.tag === 'binary') return own(f.val);
    return encoder.encode(f.tag === 'text' ? f.val : f.val.data);
  }

  /** The frame's text: a binary frame's bytes decoded as UTF-8. */
  text(): string {
    const f = this.#frame;
    if (f.tag === 'text') return f.val;
    if (f.tag === 'event') return f.val.data;
    return text(own(f.val), 'the frame', 'connections');
  }

  /** The frame parsed as JSON. */
  json<T = unknown>(): T {
    return json<T>(this.bytes(), 'the frame', 'connections');
  }
}

/** A connection ended. Always the connection's last input, exactly once. */
export interface Closed {
  readonly connection: string;
  /** Who ended it: the client, this actor (`ctx.connections.close`), or the host (a restart, a limit, an operator). */
  readonly initiator: CloseInitiator;
  /** The WebSocket close code: 1000 normal, 1006 gone without a close frame, 1012 a restart. */
  readonly code: number;
  /** The client's or the actor's reason; for the host one of `restart`, `ping-timeout`, `too-large`, `slow-consumer`, `protocol`, `operator`, `rebase`, `abandoned`, `unavailable`. */
  readonly reason: string;
}

export function closedOf(event: WitClosed): Closed {
  return {
    connection: event.connection,
    initiator: event.info.initiator,
    code: event.info.code,
    reason: event.info.reason,
  };
}

/** How `ctx.accept` accepts a connection. */
export interface AcceptOptions {
  /** One of the subprotocols the client offered (WebSocket only). */
  subprotocol?: string;
  /** Extra response headers. */
  headers?: Record<string, string>;
  /** The subject of the connection's later inputs (its frames and its close); by default the request's. */
  subject?: string;
}

export function accept(options: AcceptOptions = {}): OpenReply {
  return {
    tag: 'accept',
    val: {
      subprotocol: options.subprotocol,
      headers: Object.entries(options.headers ?? {}).map(([name, value]) => ({ name, value })),
      subject: options.subject,
    },
  };
}

/** The refusal of an open for an actor type that does not handle connections. */
export function refusal(status: number, message: string): OpenReply {
  const response: HttpResponse = {
    status,
    headers: [{ name: 'content-type', value: 'text/plain; charset=utf-8' }],
    body: { tag: 'inline', val: encoder.encode(message) },
  };
  return { tag: 'refuse', val: response };
}

/**
 * What an open handler returned, as the export's answer: an accept stays
 * one, and an HTTP output (`ctx.status(403)`, `ctx.json(...)`) refuses the
 * connection with that response.
 */
export function toOpenReply(out: OpenReply | Output): OpenReply {
  switch (out?.tag) {
    case 'accept':
    case 'refuse':
      return out;
    case 'http':
      return { tag: 'refuse', val: out.val };
    default:
      throw new KronikError(
        'open',
        'an open handler must return ctx.accept() or an HTTP response such as ctx.status(403)',
        `it returned ${out?.tag ?? String(out)}`,
        'connections',
      );
  }
}

/**
 * Thrown by `sendNow` when the frame's outcome is unknown: the node stopped
 * after it sent the frame and before it recorded that, and a frame is never
 * sent twice. The turn may catch it; uncaught, the turn fails with
 * `EFFECT_OUTCOME_UNKNOWN`.
 */
export class OutcomeUnknown extends KronikError {
  constructor(payload?: unknown) {
    super('send-now.outcome-unknown', 'the frame may or may not have reached the client', '', 'EFFECT_OUTCOME_UNKNOWN', payload);
    this.name = 'OutcomeUnknown';
  }
}

/**
 * What a failing `send-now` host call threw: `false` when the connection is
 * closed (or the client did not keep up), else the error to throw.
 * ComponentizeJS throws a `ComponentError` whose `payload` is the WIT
 * `send-error`.
 */
export function sendNowFailure(thrown: unknown): false | KronikError {
  const payload = (thrown as { payload?: unknown } | null)?.payload as { tag?: string; val?: unknown } | undefined;
  switch (payload?.tag) {
    case 'closed':
      return false;
    case 'outcome-unknown':
      return new OutcomeUnknown(payload);
    case 'denied': {
      const detail = typeof payload.val === 'string' ? payload.val : '';
      return new KronikError('send-now.denied', 'sending now denied', detail, explainTopic(detail, 'capability'), payload);
    }
    default:
      return new KronikError('send-now.unknown', 'sending now failed', String((thrown as Error)?.message ?? thrown), 'connections', payload);
  }
}
