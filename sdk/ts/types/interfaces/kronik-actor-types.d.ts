declare module 'kronik:actor/types@0.1.0' {
  /**
   * "kind/key", e.g. billing/acme
   */
  export interface ActorRef {
    kind: string,
    key: string,
  }
  /**
   * identifies a blob; it does not grant access, the host's reference graph does; used from M25
   */
  export interface BlobRef {
    hash: string,
    size: bigint,
  }
  /**
   * blobs travel next to the body, never hidden inside it; always empty before M26
   */
  export interface Message {
    name: string,
    contentType: string,
    body: Uint8Array,
    blobs: Array<BlobRef>,
  }
  /**
   * an HTTP body: inline bytes, or a blob from M25; only inline before M25
   */
  export type HttpBody = HttpBodyInline | HttpBodyBlob;
  export interface HttpBodyInline {
    tag: 'inline',
    val: Uint8Array,
  }
  export interface HttpBodyBlob {
    tag: 'blob',
    val: BlobRef,
  }
  export interface Header {
    name: string,
    value: string,
  }
  export interface Incoming {
    sender?: ActorRef,
    msg: Message,
  }
  export interface HttpRequest {
    method: string,
    path: string,
    query: string,
    params: Array<[string, string]>,
    headers: Array<Header>,
    body: HttpBody,
  }
  export interface HttpResponse {
    status: number,
    headers: Array<Header>,
    body: HttpBody,
  }
  export interface TimerFired {
    id: bigint,
    msg: Message,
  }
  export type Input = InputHttp | InputMessage | InputTimer | InputMigrate;
  export interface InputHttp {
    tag: 'http',
    val: HttpRequest,
  }
  export interface InputMessage {
    tag: 'message',
    val: Incoming,
  }
  export interface InputTimer {
    tag: 'timer',
    val: TimerFired,
  }
  export interface InputMigrate {
    tag: 'migrate',
    val: number,
  }
  export type Output = OutputNone | OutputReply | OutputHttp;
  export interface OutputNone {
    tag: 'none',
  }
  export interface OutputReply {
    tag: 'reply',
    val: Message,
  }
  export interface OutputHttp {
    tag: 'http',
    val: HttpResponse,
  }
  export type HandlerError = HandlerErrorRejected | HandlerErrorFailed;
  export interface HandlerErrorRejected {
    tag: 'rejected',
    val: string,
  }
  export interface HandlerErrorFailed {
    tag: 'failed',
    val: string,
  }
  export interface Route {
    method: string,
    pattern: string,
  }
  export interface Manifest {
    kind: string,
    schemaVersion: number,
    routes: Array<Route>,
    capabilities: Array<string>,
  }
}
