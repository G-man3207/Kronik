declare module 'kronik:actor/log@0.1.0' {
  /**
   * the host adds execution id and causal id to every event
   */
  export function emit(lvl: Level, message: string, fields: Array<[string, string]>): void;
  /**
   * # Variants
   * 
   * ## `"trace"`
   * 
   * ## `"debug"`
   * 
   * ## `"info"`
   * 
   * ## `"warn"`
   * 
   * ## `"error"`
   */
  export type Level = 'trace' | 'debug' | 'info' | 'warn' | 'error';
}
