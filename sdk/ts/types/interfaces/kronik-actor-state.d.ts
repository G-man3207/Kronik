declare module 'kronik:actor/state@0.1.0' {
  /**
   * values and messages are at most 1 MiB by default (per-kind limits)
   */
  export function get(key: string): Uint8Array | undefined;
  /**
   * tagged with the current default subject, see privacy
   */
  export function set(key: string, value: Uint8Array): void;
  /**
   * tagged with an explicit subject (none = no subject), whatever the default
   */
  export function setFor(subject: string | undefined, key: string, value: Uint8Array): void;
  export { _delete as delete };
  function _delete(key: string): void;
  export function keys(prefix: string): Array<string>;
}
