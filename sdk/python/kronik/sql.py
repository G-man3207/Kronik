# Values and rows for ctx.sql. No host calls here, so the conversions can be
# tested without a host.

from .errors import KronikError


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
    words = []
    word = []
    i, n = 0, len(statement)
    while i < n:
        c = statement[i]
        if c in "'\"`[":
            if word:
                words.append("".join(word).upper())
                word = []
            end = statement.find("]" if c == "[" else c, i + 1)
            i = n if end < 0 else end
            words.append("")
        elif c == "-" and statement.startswith("-", i + 1):
            if word:
                words.append("".join(word).upper())
                word = []
            end = statement.find("\n", i)
            i = n if end < 0 else end
        elif c == "/" and statement.startswith("*", i + 1):
            if word:
                words.append("".join(word).upper())
                word = []
            end = statement.find("*/", i + 2)
            i = n if end < 0 else end + 1
        elif c.isalnum() or c == "_":
            word.append(c)
        elif word:
            words.append("".join(word).upper())
            word = []
        i += 1
    if word:
        words.append("".join(word).upper())
    return any(w == "ORDER" and words[k + 1 : k + 2] == ["BY"] for k, w in enumerate(words))
