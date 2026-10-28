declare module 'kronik:actor/privacy@0.1.0' {
  /**
   * default subject for values written from now on in this turn
   */
  export function setSubject(subject: string | undefined): void;
  /**
   * the current default subject (initially set by the gateway or the sender)
   */
  export function currentSubject(): string | undefined;
}
