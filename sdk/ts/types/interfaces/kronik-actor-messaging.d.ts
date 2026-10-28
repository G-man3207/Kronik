/// <reference path="./kronik-actor-types.d.ts" />
declare module 'kronik:actor/messaging@0.1.0' {
  /**
   * buffered; delivered exactly once, and only if this turn commits
   */
  export function send(to: ActorRef, msg: Message): void;
  /**
   * happens now; the callee commits its own turn; not atomic with this turn.
   * compensate is delivered exactly once to the callee if this turn fails afterwards
   */
  export function call(to: ActorRef, msg: Message, compensate: Message | undefined): Message | undefined;
  export type ActorRef = import('kronik:actor/types@0.1.0').ActorRef;
  export type Message = import('kronik:actor/types@0.1.0').Message;
  export type CallError = CallErrorNotFound | CallErrorRejected | CallErrorFailed | CallErrorReentrant | CallErrorTimeout;
  export interface CallErrorNotFound {
    tag: 'not-found',
  }
  export interface CallErrorRejected {
    tag: 'rejected',
    val: string,
  }
  export interface CallErrorFailed {
    tag: 'failed',
    val: string,
  }
  export interface CallErrorReentrant {
    tag: 'reentrant',
  }
  export interface CallErrorTimeout {
    tag: 'timeout',
  }
}
