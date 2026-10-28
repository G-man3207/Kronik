// Values and rows for ctx.sql. No host calls here, so the conversions can be
// tested without a host.

import type { Rows, SqlValue } from 'kronik:actor/sql@0.1.0';
import { KronikError } from './errors.ts';
import { isBytes, MAX_SAFE_BIGINT, MIN_SAFE_BIGINT, own } from './http.ts';

/**
 * A SQL parameter. `null` and `undefined` are NULL, a `boolean` is 0 or 1,
 * an integral `number` or a `bigint` is an INTEGER, any other `number` is a
 * REAL, a `string` is TEXT and a `Uint8Array` is a BLOB.
 */
export type SqlParam = null | undefined | boolean | number | bigint | string | Uint8Array;

/**
 * A SQL value in JavaScript: INTEGER is a `number` when it is a safe
 * integer and a `bigint` otherwise, REAL a `number`, TEXT a `string`, BLOB a
 * `Uint8Array` and NULL `null`.
 */
export type SqlResult = null | number | bigint | string | Uint8Array;

/** One row: column name to value. */
export type Row = Record<string, SqlResult>;

/** The rows of a query. */
export class SqlRows {
  /** The column names. */
  readonly columns: string[];
  /** The values as the host returned them. */
  readonly raw: SqlValue[][];

  constructor(rows: Rows) {
    this.columns = rows.columns;
    this.raw = rows.values;
  }

  /** The number of rows. */
  get length(): number {
    return this.raw.length;
  }

  /** The rows as objects, in the order the query returned them. */
  rows(): Row[] {
    const rows: Row[] = new Array(this.raw.length);
    for (let i = 0; i < this.raw.length; i++) rows[i] = toRow(this.columns, this.raw[i]);
    return rows;
  }

  /** The first row, if any. */
  first(): Row | undefined {
    return this.raw.length > 0 ? toRow(this.columns, this.raw[0]) : undefined;
  }
}

function toRow(columns: string[], values: SqlValue[]): Row {
  const row: Row = {};
  for (let i = 0; i < columns.length; i++) row[columns[i]] = fromSql(values[i]);
  return row;
}

export function toSql(param: SqlParam): SqlValue {
  switch (typeof param) {
    case 'undefined':
      return { tag: 'null' };
    case 'boolean':
      return { tag: 'integer', val: param ? 1n : 0n };
    case 'bigint':
      return { tag: 'integer', val: param };
    case 'number':
      return Number.isInteger(param) ? { tag: 'integer', val: BigInt(param) } : { tag: 'real', val: param };
    case 'string':
      return { tag: 'text', val: param };
    default:
      if (param === null) return { tag: 'null' };
      if (isBytes(param)) return { tag: 'blob', val: param };
      throw new KronikError(
        'sql.param',
        'not a SQL parameter',
        `${Object.prototype.toString.call(param)}; use null, a boolean, number, bigint, string or Uint8Array`,
        'sql-state',
      );
  }
}

export function fromSql(value: SqlValue): SqlResult {
  switch (value.tag) {
    case 'null':
      return null;
    case 'integer':
      return value.val >= MIN_SAFE_BIGINT && value.val <= MAX_SAFE_BIGINT ? Number(value.val) : value.val;
    case 'real':
    case 'text':
      return value.val;
    case 'blob':
      return own(value.val);
  }
}

/**
 * Whether `statement` contains the keywords ORDER BY outside string
 * literals, quoted identifiers and comments.
 */
export function hasOrderBy(statement: string): boolean {
  const words: string[] = [];
  let word = '';
  const endWord = () => {
    if (word) words.push(word.toUpperCase());
    word = '';
  };
  for (let i = 0; i < statement.length; i++) {
    const c = statement[i];
    if (c === "'" || c === '"' || c === '`' || c === '[') {
      endWord();
      const close = c === '[' ? ']' : c;
      const end = statement.indexOf(close, i + 1);
      i = end < 0 ? statement.length : end;
      words.push('');
    } else if (c === '-' && statement[i + 1] === '-') {
      endWord();
      const end = statement.indexOf('\n', i);
      i = end < 0 ? statement.length : end;
    } else if (c === '/' && statement[i + 1] === '*') {
      endWord();
      const end = statement.indexOf('*/', i + 2);
      i = end < 0 ? statement.length : end + 1;
    } else if (/[\p{L}\p{N}_]/u.test(c)) {
      word += c;
    } else {
      endWord();
    }
  }
  endWord();
  return words.some((w, i) => w === 'ORDER' && words[i + 1] === 'BY');
}
