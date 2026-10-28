/// <reference path="./kronik-actor-types.d.ts" />
declare module 'kronik:actor/context@0.1.0' {
  export function selfRef(): ActorRef;
  /**
   * derived from the causal key: identical in production and replay
   */
  export function causalId(): string;
  /**
   * logical time of this turn: constant within the turn,
   * monotonic per branch and shard, never below the parent's
   */
  export function nowMs(): bigint;
  /**
   * deterministic per turn, seeded from the recorded seed
   */
  export function randomBytes(len: number): Uint8Array;
  export type ActorRef = import('kronik:actor/types@0.1.0').ActorRef;
}
