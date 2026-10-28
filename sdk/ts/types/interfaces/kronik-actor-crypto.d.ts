declare module 'kronik:actor/crypto@0.1.0' {
  /**
   * secret is a name; the value never enters guest memory
   */
  export function hmacSha256(secret: string, data: Uint8Array): Uint8Array;
  export function signEd25519(secret: string, data: Uint8Array): Uint8Array;
  export type CryptoError = CryptoErrorDenied | CryptoErrorUnsupported;
  export interface CryptoErrorDenied {
    tag: 'denied',
    val: string,
  }
  export interface CryptoErrorUnsupported {
    tag: 'unsupported',
    val: string,
  }
}
