declare module 'kronik:actor/sql@0.1.0' {
  /**
   * per-actor SQLite owned by the host; changes are recorded as changesets.
   * DDL is allowed only in a migrate turn, before its first DML statement.
   * A row's subject is its `_subject` column; tables without one use the
   * turn's default subject. The SQL function kronik_subject() returns the
   * current default subject (e.g. `_subject TEXT DEFAULT (kronik_subject())`).
   */
  export function query(statement: string, params: Array<SqlValue>): Rows;
  export function execute(statement: string, params: Array<SqlValue>): bigint;
  export type SqlValue = SqlValueNull | SqlValueInteger | SqlValueReal | SqlValueText | SqlValueBlob;
  export interface SqlValueNull {
    tag: 'null',
  }
  export interface SqlValueInteger {
    tag: 'integer',
    val: bigint,
  }
  export interface SqlValueReal {
    tag: 'real',
    val: number,
  }
  export interface SqlValueText {
    tag: 'text',
    val: string,
  }
  export interface SqlValueBlob {
    tag: 'blob',
    val: Uint8Array,
  }
  export interface Rows {
    columns: Array<string>,
    values: Array<Array<SqlValue>>,
  }
  export type SqlError = SqlErrorSyntax | SqlErrorConstraint | SqlErrorDenied | SqlErrorTooLarge;
  export interface SqlErrorSyntax {
    tag: 'syntax',
    val: string,
  }
  export interface SqlErrorConstraint {
    tag: 'constraint',
    val: string,
  }
  export interface SqlErrorDenied {
    tag: 'denied',
    val: string,
  }
  export interface SqlErrorTooLarge {
    tag: 'too-large',
  }
}
