/// <reference path="./kronik-actor-types.d.ts" />
declare module 'kronik:actor/timers@0.1.0' {
  /**
   * registered when this turn commits
   */
  export function schedule(delayMs: bigint, msg: Message): bigint;
  export function cancel(id: bigint): boolean;
  export type Message = import('kronik:actor/types@0.1.0').Message;
}
