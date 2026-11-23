# Values and rows for ctx.sql. No host calls here, so the conversions can be
# tested without a host.

import re

from .errors import KronikError

# A string literal, a quoted identifier or a comment, also one that is never
# closed. Each is replaced by a space, so that `or''der` stays two words.
_LITERAL_OR_COMMENT = re.compile(r"'[^']*'?|\"[^\"]*\"?|`[^`]*`?|\[[^\]]*\]?|--[^\n]*|/\*[\s\S]*?(?:\*/|\Z)")
_ORDER_BY = re.compile(r"\bORDER\s+BY\b", re.I)


def from_sql(value):
    """A SQL value in Python: INTEGER int, REAL float, TEXT str, BLOB bytes, NULL None."""
    return getattr(value, "value", None)


class SqlRows:
    """The rows of a query: `columns` and `raw`, the values as the host returned them."""

    def __init__(self, rows):
        self.columns = rows.columns
        self.raw = rows.values

    def __len__(self):
        return len(self.raw)

    def rows(self):
        """The rows as dicts (column name to value), in the order the query returned them."""
        return [dict(zip(self.columns, map(from_sql, values))) for values in self.raw]

    def first(self):
        """The first row as a dict, or None."""
        return dict(zip(self.columns, map(from_sql, self.raw[0]))) if self.raw else None


def to_sql(param, sql):
    """A SQL parameter as a value of `sql` (the WIT interface's module): None is NULL, a bool 0 or 1,
    an int INTEGER, a float REAL, a str TEXT and bytes a BLOB."""
    if param is None:
        return sql.SqlValue_Null()
    if isinstance(param, (bool, int)):
        return sql.SqlValue_Integer(int(param))
    if isinstance(param, float):
        return sql.SqlValue_Real(param)
    if isinstance(param, str):
        return sql.SqlValue_Text(param)
    if isinstance(param, (bytes, bytearray, memoryview)):
        return sql.SqlValue_Blob(bytes(param))
    raise KronikError(
        "sql.param",
        "not a SQL parameter",
        f"{type(param).__name__}; use None, a bool, int, float, str or bytes",
        "sql-state",
    )


def has_order_by(statement):
    """Whether `statement` contains the keywords ORDER BY outside string
    literals, quoted identifiers and comments."""
    return _ORDER_BY.search(_LITERAL_OR_COMMENT.sub(" ", statement)) is not None
