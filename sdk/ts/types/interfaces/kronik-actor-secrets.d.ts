declare module 'kronik:actor/secrets@0.1.1' {
  /**
   * exception only: requires capability secret-reveal:<name>
   */
  export function reveal(name: string): string;
}
