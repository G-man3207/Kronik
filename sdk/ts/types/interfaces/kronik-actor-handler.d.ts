/// <reference path="./kronik-actor-types.d.ts" />
declare module 'kronik:actor/handler@0.1.1' {
  export function describe(): Manifest;
  export function handle(input: Input): Output;
  export type Input = import('kronik:actor/types@0.1.1').Input;
  export type Output = import('kronik:actor/types@0.1.1').Output;
  export type HandlerError = import('kronik:actor/types@0.1.1').HandlerError;
  export type Manifest = import('kronik:actor/types@0.1.1').Manifest;
}
