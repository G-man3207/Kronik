// Errors from host calls and from the SDK. Every message names a
// `kronik explain` topic, taken from the host's error code when the host's
// message starts with one (`CAPABILITY_NOT_GRANTED: http:api.example.com`).

/** An error from a host call or from the SDK. Thrown out of a handler, it fails the turn. */
export class KronikError extends Error {
  /** What failed and how, such as `fetch.denied` or `sql.syntax`. */
  readonly kind: string;
  /** The `kronik explain` topic for it. */
  readonly topic: string;
  /** The host's error value, if the error came from a host call. */
  readonly payload: unknown;

  constructor(kind: string, what: string, detail: string, topic: string, payload?: unknown) {
    super(`${detail ? `${what}: ${detail}` : what} (see \`kronik explain ${topic}\`)`);
    this.name = 'KronikError';
    this.kind = kind;
    this.topic = topic;
    this.payload = payload;
  }
}

/**
 * Thrown out of a handler, refuses the input: the turn fails with
 * `handler-error::rejected` and its writes are discarded. Any other error
 * fails it with `handler-error::failed`.
 */
export class Rejected extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'Rejected';
  }
}

/** The error code that starts a host message such as `CAPABILITY_NOT_GRANTED: ...`, else `fallback`. */
export function explainTopic(message: string, fallback: string): string {
  const code = message.split(':', 1)[0];
  return message.includes(':') && /^[A-Z][A-Z0-9_]+$/.test(code) ? code : fallback;
}

type Variant = { tag: string; val?: unknown };

const messages: Record<string, Record<string, [string, string]>> = {
  sql: {
    syntax: ['SQL syntax error', 'sql-state'],
    constraint: ['SQL constraint failed', 'sql-state'],
    denied: ['SQL statement denied', 'sql-state'],
    'too-large': ['SQL value or database over its size limit', 'sql-state'],
  },
  fetch: {
    denied: ['HTTP request denied', 'capability'],
    network: ['HTTP request failed', 'effect'],
    timeout: ['HTTP request timed out', 'effect'],
    'too-large': ['HTTP response over its size limit', 'effect'],
    'outcome-unknown': ['the HTTP request may or may not have reached its target', 'EFFECT_OUTCOME_UNKNOWN'],
  },
  call: {
    'not-found': ['call failed: no actor type is deployed for the callee', 'ACTOR_NOT_FOUND'],
    rejected: ['call rejected by the callee', 'TURN_FAILED'],
    failed: ['call failed in the callee', 'TURN_FAILED'],
    reentrant: ['call refused: the callee is already waiting in this chain of calls', 'effect'],
    timeout: ['call timed out', 'effect'],
  },
  crypto: {
    denied: ['crypto denied', 'secret-handle'],
    unsupported: ['crypto not supported', 'NOT_IMPLEMENTED'],
  },
};

/**
 * Turns what a failing host call threw into a {@link KronikError}.
 * ComponentizeJS throws a `ComponentError` whose `payload` is the WIT error
 * value: a variant for `area`, or a string for `reveal`.
 */
export function hostError(area: 'sql' | 'fetch' | 'call' | 'crypto' | 'reveal', thrown: unknown): KronikError {
  const payload = (thrown as { payload?: unknown } | null)?.payload;
  if (area === 'reveal') {
    const detail = typeof payload === 'string' ? payload : String(thrown);
    return new KronikError('reveal', 'revealing the secret failed', detail, explainTopic(detail, 'secret-handle'), payload);
  }
  const variant = payload as Variant | undefined;
  const known = variant && typeof variant.tag === 'string' ? messages[area][variant.tag] : undefined;
  if (!variant || !known) {
    return new KronikError(`${area}.unknown`, `${area} failed`, String((thrown as Error)?.message ?? thrown), 'effect', payload);
  }
  const detail = typeof variant.val === 'string' ? variant.val : '';
  const [what, topic] = known;
  return new KronikError(`${area}.${variant.tag}`, what, detail, explainTopic(detail, topic), payload);
}
