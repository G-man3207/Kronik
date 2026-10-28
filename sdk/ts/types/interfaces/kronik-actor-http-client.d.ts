/// <reference path="./kronik-actor-types.d.ts" />
declare module 'kronik:actor/http-client@0.1.0' {
  /**
   * url may be https://... or foreign://<name>/...
   */
  export function fetch(req: Request): Response;
  export type HttpBody = import('kronik:actor/types@0.1.0').HttpBody;
  /**
   * the host inserts the secret at the effect boundary, e.g. template "Bearer {}"
   */
  export interface SecretTemplate {
    name: string,
    template: string,
  }
  export type HeaderValue = HeaderValueText | HeaderValueSecret;
  export interface HeaderValueText {
    tag: 'text',
    val: string,
  }
  export interface HeaderValueSecret {
    tag: 'secret',
    val: SecretTemplate,
  }
  export interface RequestHeader {
    name: string,
    value: HeaderValue,
  }
  export interface Request {
    method: string,
    url: string,
    headers: Array<RequestHeader>,
    body: HttpBody,
  }
  export interface Response {
    status: number,
    headers: Array<[string, string]>,
    body: HttpBody,
  }
  export type FetchError = FetchErrorDenied | FetchErrorNetwork | FetchErrorTimeout | FetchErrorTooLarge | FetchErrorOutcomeUnknown;
  export interface FetchErrorDenied {
    tag: 'denied',
    val: string,
  }
  export interface FetchErrorNetwork {
    tag: 'network',
    val: string,
  }
  export interface FetchErrorTimeout {
    tag: 'timeout',
  }
  export interface FetchErrorTooLarge {
    tag: 'too-large',
  }
  export interface FetchErrorOutcomeUnknown {
    tag: 'outcome-unknown',
  }
}
