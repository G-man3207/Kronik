// Values and rows for ctx.SQL. No host calls here, so the conversions can be
// tested without a host.

package kronik

import (
	"bytes"
	"fmt"
	"math"
	"strings"
	"unicode"

	"go.bytecodealliance.org/cm"
	"kronik.dev/sdk/internal/wit/kronik/actor/sql"
)

// SQLRows are the rows of a query.
type SQLRows struct {
	// Columns are the column names.
	Columns []string
	raw     []cm.List[sql.SQLValue]
}

// Len is the number of rows.
func (r *SQLRows) Len() int { return len(r.raw) }

// Rows returns the rows in the order the query returned them.
func (r *SQLRows) Rows() []Row {
	rows := make([]Row, len(r.raw))
	for i, values := range r.raw {
		rows[i] = toRow(r.Columns, values.Slice())
	}
	return rows
}

// First returns the first row, if any.
func (r *SQLRows) First() (Row, bool) {
	if len(r.raw) == 0 {
		return Row{}, false
	}
	return toRow(r.Columns, r.raw[0].Slice()), true
}

// Row is one row of a query. A value is nil (NULL), an int64 (INTEGER), a
// float64 (REAL), a string (TEXT) or a []byte (BLOB). As JSON it is an
// object with the columns in the query's order.
type Row struct {
	Columns []string
	Values  []any
}

// Get returns the value of the column name, and whether there is one.
func (r Row) Get(name string) (any, bool) {
	for i, c := range r.Columns {
		if c == name {
			return r.Values[i], true
		}
	}
	return nil, false
}

// MarshalJSON writes the row as an object in column order.
func (r Row) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, c := range r.Columns {
		if i > 0 {
			b.WriteByte(',')
		}
		name, err := toJSON(c)
		if err != nil {
			return nil, err
		}
		value, err := toJSON(r.Values[i])
		if err != nil {
			return nil, err
		}
		b.Write(name)
		b.WriteByte(':')
		b.Write(value)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

func toRow(columns []string, values []sql.SQLValue) Row {
	row := Row{Columns: columns, Values: make([]any, len(columns))}
	for i := range columns {
		row.Values[i] = fromSQL(values[i])
	}
	return row
}

// toSQL converts a SQL parameter: nil is NULL, a bool 0 or 1, an integer
// INTEGER, a float REAL, a string TEXT and a []byte a BLOB.
func toSQL(param any) (sql.SQLValue, error) {
	switch p := param.(type) {
	case nil:
		return sql.SQLValueNull(), nil
	case bool:
		if p {
			return sql.SQLValueInteger(1), nil
		}
		return sql.SQLValueInteger(0), nil
	case int:
		return sql.SQLValueInteger(int64(p)), nil
	case int8:
		return sql.SQLValueInteger(int64(p)), nil
	case int16:
		return sql.SQLValueInteger(int64(p)), nil
	case int32:
		return sql.SQLValueInteger(int64(p)), nil
	case int64:
		return sql.SQLValueInteger(p), nil
	case uint:
		return uintToSQL(uint64(p))
	case uint8:
		return sql.SQLValueInteger(int64(p)), nil
	case uint16:
		return sql.SQLValueInteger(int64(p)), nil
	case uint32:
		return sql.SQLValueInteger(int64(p)), nil
	case uint64:
		return uintToSQL(p)
	case float32:
		return sql.SQLValueReal(float64(p)), nil
	case float64:
		return sql.SQLValueReal(p), nil
	case string:
		return sql.SQLValueText(p), nil
	case []byte:
		return sql.SQLValueBlob(cm.ToList(p)), nil
	}
	return sql.SQLValue{}, newError("sql.param", "not a SQL parameter",
		fmt.Sprintf("%T; use nil, a bool, an integer, a float, a string or []byte", param), "sql-state", nil)
}

func uintToSQL(v uint64) (sql.SQLValue, error) {
	if v > math.MaxInt64 {
		return sql.SQLValue{}, newError("sql.param", "not a SQL parameter", fmt.Sprintf("%d is over SQLite's INTEGER range", v), "sql-state", nil)
	}
	return sql.SQLValueInteger(int64(v)), nil
}

func fromSQL(v sql.SQLValue) any {
	switch {
	case v.Integer() != nil:
		return *v.Integer()
	case v.Real() != nil:
		return *v.Real()
	case v.Text() != nil:
		return *v.Text()
	case v.Blob() != nil:
		return v.Blob().Slice()
	}
	return nil
}

// hasOrderBy reports whether statement contains the keywords ORDER BY
// outside string literals, quoted identifiers and comments.
func hasOrderBy(statement string) bool {
	var words []string
	var word strings.Builder
	endWord := func() {
		if word.Len() > 0 {
			words = append(words, strings.ToUpper(word.String()))
		}
		word.Reset()
	}
	s := statement
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'' || c == '"' || c == '`' || c == '[':
			endWord()
			closer := c
			if c == '[' {
				closer = ']'
			}
			end := strings.IndexByte(s[i+1:], closer)
			if end < 0 {
				i = len(s)
			} else {
				i += 1 + end
			}
			words = append(words, "")
		case c == '-' && i+1 < len(s) && s[i+1] == '-':
			endWord()
			end := strings.IndexByte(s[i:], '\n')
			if end < 0 {
				i = len(s)
			} else {
				i += end
			}
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			endWord()
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				i = len(s)
			} else {
				i += 2 + end + 1
			}
		case c == '_' || c >= 0x80 || unicode.IsLetter(rune(c)) || unicode.IsDigit(rune(c)):
			// Bytes of multi-byte characters are letters here, as in the
			// other SDKs' \p{L}: no SQL keyword contains one.
			word.WriteByte(c)
		default:
			endWord()
		}
	}
	endWord()
	for i := range len(words) - 1 {
		if words[i] == "ORDER" && words[i+1] == "BY" {
			return true
		}
	}
	return false
}
