/// <reference path="./kronik-actor-connections.d.ts" />
/// <reference path="./kronik-actor-types.d.ts" />
declare module 'kronik:actor/connection-handler@0.1.1' {
  /**
   * A client asks to open a connection: accept or refuse it.
   */
  export function open(request: OpenRequest): OpenReply;
  /**
   * One incoming frame (WebSocket only).
   */
  export function frame(event: IncomingFrame): void;
  /**
   * The connection closed; always its last input.
   */
  export function close(event: Closed): void;
  export type HandlerError = import('kronik:actor/types@0.1.1').HandlerError;
  export type OpenRequest = import('kronik:actor/connections@0.1.1').OpenRequest;
  export type OpenReply = import('kronik:actor/connections@0.1.1').OpenReply;
  export type IncomingFrame = import('kronik:actor/connections@0.1.1').IncomingFrame;
  export type Closed = import('kronik:actor/connections@0.1.1').Closed;
}
