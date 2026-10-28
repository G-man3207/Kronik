/// <reference path="./kronik-actor-types.d.ts" />
declare module 'kronik:actor/handler@0.1.0' {
  export function describe(): Manifest;
  export function handle(input: Input): Output;
  export type Input = import('kronik:actor/types@0.1.0').Input;
  export type Output = import('kronik:actor/types@0.1.0').Output;
  export type HandlerError = import('kronik:actor/types@0.1.0').HandlerError;
  export type Manifest = import('kronik:actor/types@0.1.0').Manifest;
}
