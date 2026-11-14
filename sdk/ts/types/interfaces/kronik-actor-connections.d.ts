/// <reference path="./kronik-actor-types.d.ts" />
declare module 'kronik:actor/connections@0.1.1' {
  /**
   * Buffered: sent after this turn commits, in call order; nothing if the
   * turn fails. To an id that is not a live connection of this actor (it
   * closed, was never accepted, or another actor holds it) the frame is
   * recorded as dropped and never delivered. Traps on a malformed id.
   */
  export function send(conn: ConnectionId, frame: Frame): void;
  /**
   * `send` to each of `conns`, recorded once; ids that are not this
   * actor's live connections are recorded as dropped.
   */
  export function broadcast(conns: Array<ConnectionId>, frame: Frame): void;
  /**
   * Buffered like `send`: after the frames before it, the connection
   * closes with `code` and `reason` (WebSocket) or its stream ends (SSE).
   * On an id that is not a live connection of this actor the close is
   * recorded as dropped and does nothing.
   */
  export function close(conn: ConnectionId, code: number, reason: string): void;
  /**
   * Sends now, before the turn commits: an effect with delivery class
   * unsafe that needs the capability connection:send-now. `ok` means
   * handed to the connection in order, not received. Never sent again
   * after a crash: the re-run gets `outcome-unknown`. An id that is not a
   * live connection of this actor answers `closed` (recorded, no frame
   * sent).
   */
  export function sendNow(conn: ConnectionId, frame: Frame): void;
  export type Header = import('kronik:actor/types@0.1.1').Header;
  export type HttpRequest = import('kronik:actor/types@0.1.1').HttpRequest;
  export type HttpResponse = import('kronik:actor/types@0.1.1').HttpResponse;
  /**
   * "c-" and 32 lowercase hex characters: assigned when the connection
   * opens, recorded, and the same in replay. Data, not a capability.
   */
  export type ConnectionId = string;
  /**
   * # Variants
   * 
   * ## `"websocket"`
   * 
   * ## `"sse"`
   */
  export type Protocol = 'websocket' | 'sse';
  /**
   * An SSE event. `event` and `id` must not contain CR, LF or NUL.
   */
  export interface SseEvent {
    /**
     * the `event:` field; empty: none (the browser's default, "message")
     */
    event: string,
    /**
     * the `id:` field; empty: none. A reconnecting EventSource sends the
     * last one back as the `Last-Event-ID` header.
     */
    id: string,
    data: string,
  }
  /**
   * One frame. On a WebSocket, `text` and `event` (its data) are text
   * frames and `binary` is a binary frame. On SSE, `event` is an event,
   * `text` is an event with only data, and `binary` traps.
   */
  export type Frame = FrameText | FrameBinary | FrameEvent;
  export interface FrameText {
    tag: 'text',
    val: string,
  }
  export interface FrameBinary {
    tag: 'binary',
    val: Uint8Array,
  }
  export interface FrameEvent {
    tag: 'event',
    val: SseEvent,
  }
  export interface OpenRequest {
    connection: ConnectionId,
    protocol: Protocol,
    /**
     * the upgrade request (WebSocket) or the GET (SSE); the body is empty
     */
    request: HttpRequest,
    /**
     * the subprotocols the client offered (Sec-WebSocket-Protocol), in order
     */
    subprotocols: Array<string>,
  }
  export interface IncomingFrame {
    connection: ConnectionId,
    /**
     * 0, 1, 2, ... per connection, in the order the client sent them
     */
    seq: bigint,
    frame: Frame,
  }
  /**
   * # Variants
   * 
   * ## `"client"`
   * 
   * ## `"actor"`
   * 
   * ## `"host"`
   */
  export type CloseInitiator = 'client' | 'actor' | 'host';
  export interface CloseInfo {
    initiator: CloseInitiator,
    /**
     * the WebSocket close code (1000 normal, 1006 gone without a close
     * frame, 1012 a restart, ...)
     */
    code: number,
    /**
     * the client's or the actor's reason; for the host one of "restart",
     * "ping-timeout", "too-large", "slow-consumer", "protocol",
     * "operator", "rebase", "abandoned", "unavailable"
     */
    reason: string,
  }
  export interface Closed {
    connection: ConnectionId,
    info: CloseInfo,
  }
  export interface Accept {
    /**
     * one of the offered subprotocols (WebSocket only)
     */
    subprotocol?: string,
    /**
     * extra response headers
     */
    headers: Array<Header>,
    /**
     * the subject of the connection's later inputs; none: the request's
     */
    subject?: string,
  }
  export type OpenReply = OpenReplyAccept | OpenReplyRefuse;
  export interface OpenReplyAccept {
    tag: 'accept',
    val: Accept,
  }
  export interface OpenReplyRefuse {
    tag: 'refuse',
    val: HttpResponse,
  }
  export type SendError = SendErrorClosed | SendErrorOutcomeUnknown | SendErrorDenied;
  /**
   * not a live connection of this actor (closed or closing, never
   * accepted, or another actor's), or the client could not keep up: the
   * frame was not sent
   */
  export interface SendErrorClosed {
    tag: 'closed',
  }
  /**
   * after a crash: the frame may or may not have been sent (I17)
   */
  export interface SendErrorOutcomeUnknown {
    tag: 'outcome-unknown',
  }
  /**
   * no grant of connection:send-now
   */
  export interface SendErrorDenied {
    tag: 'denied',
    val: string,
  }
}
