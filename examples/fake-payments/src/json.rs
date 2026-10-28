//! A small JSON parser and string quoting, std only. Enough for request
//! bodies (flat objects) and the service's own state file (objects and
//! arrays of flat objects). Numbers are kept as their source text so integers
//! are never rounded through `f64`.

/// A parsed JSON value. Object members keep their order.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// The number as written, e.g. `12500` or `1.5e3`.
    Number(String),
    String(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

impl Value {
    /// The member `key` of an object.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The string, if this is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// The number, if this is an integer without fraction or exponent that
    /// fits an `i64`.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Number(n) if !n.contains(['.', 'e', 'E']) => n.parse().ok(),
            _ => None,
        }
    }

    /// The elements, if this is an array.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }
}

/// How deeply arrays and objects may nest.
const MAX_DEPTH: usize = 32;

/// Parses a complete JSON document. Duplicate object keys are rejected.
pub fn parse(text: &str) -> Result<Value, String> {
    let mut p = Parser {
        bytes: text.as_bytes(),
        pos: 0,
    };
    let value = p.value(0)?;
    p.skip_ws();
    if p.pos != p.bytes.len() {
        return Err(p.error("trailing characters"));
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn error(&self, msg: &str) -> String {
        format!("{msg} at byte {}", self.pos)
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, b: u8) -> Result<(), String> {
        if self.peek() == Some(b) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.error(&format!("expected '{}'", b as char)))
        }
    }

    fn literal(&mut self, word: &str, value: Value) -> Result<Value, String> {
        if self.bytes[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Ok(value)
        } else {
            Err(self.error("unexpected character"))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, String> {
        if depth > MAX_DEPTH {
            return Err(self.error("nested too deeply"));
        }
        self.skip_ws();
        match self.peek() {
            None => Err(self.error("unexpected end")),
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(Value::String),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'n') => self.literal("null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => Err(self.error("unexpected character")),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, String> {
        self.expect(b'{')?;
        let mut members: Vec<(String, Value)> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(members));
        }
        loop {
            self.skip_ws();
            let key = self.string()?;
            if members.iter().any(|(k, _)| *k == key) {
                return Err(self.error(&format!("duplicate key {key:?}")));
            }
            self.skip_ws();
            self.expect(b':')?;
            let value = self.value(depth + 1)?;
            members.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Object(members));
                }
                _ => return Err(self.error("expected ',' or '}'")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, String> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(self.error("expected ',' or ']'")),
            }
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        self.pos - start
    }

    fn number(&mut self) -> Result<Value, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(self.error("bad number")),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if self.digits() == 0 {
                return Err(self.error("bad number"));
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if self.digits() == 0 {
                return Err(self.error("bad number"));
            }
        }
        // The slice is ASCII digits and signs, so always valid UTF-8.
        let text = String::from_utf8_lossy(&self.bytes[start..self.pos]).into_owned();
        Ok(Value::Number(text))
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let digits = self
            .bytes
            .get(self.pos..self.pos + 4)
            .and_then(|h| std::str::from_utf8(h).ok())
            .filter(|h| h.bytes().all(|b| b.is_ascii_hexdigit()))
            .and_then(|h| u32::from_str_radix(h, 16).ok())
            .ok_or_else(|| self.error("bad \\u escape"))?;
        self.pos += 4;
        Ok(digits)
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let Some(b) = self.peek() else {
                return Err(self.error("unterminated string"));
            };
            self.pos += 1;
            match b {
                b'"' => break,
                b'\\' => {
                    let Some(e) = self.peek() else {
                        return Err(self.error("unterminated string"));
                    };
                    self.pos += 1;
                    let c = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            let code = if (0xD800..0xDC00).contains(&hi) {
                                // A surrogate pair: \uD83D\uDE00.
                                if !self.bytes[self.pos..].starts_with(b"\\u") {
                                    return Err(self.error("lone surrogate"));
                                }
                                self.pos += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(self.error("lone surrogate"));
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else {
                                hi
                            };
                            char::from_u32(code).ok_or_else(|| self.error("lone surrogate"))?
                        }
                        _ => return Err(self.error("bad escape")),
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                }
                0..=0x1f => return Err(self.error("control character in string")),
                b => out.push(b),
            }
        }
        // The input is a &str, and escapes add whole characters.
        String::from_utf8(out).map_err(|_| self.error("invalid UTF-8"))
    }
}

/// `s` as a JSON string literal.
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_flat_object() {
        let v = parse(
            r#" {"customer":"acme","invoice":"inv-1","amount":12500,"currency":"EUR","ok":true,"n":null} "#,
        )
        .unwrap();
        assert_eq!(v.get("customer").and_then(Value::as_str), Some("acme"));
        assert_eq!(v.get("amount").and_then(Value::as_i64), Some(12500));
        assert_eq!(v.get("ok"), Some(&Value::Bool(true)));
        assert_eq!(v.get("n"), Some(&Value::Null));
        assert_eq!(v.get("missing"), None);
    }

    #[test]
    fn numbers() {
        let n = |s: &str| parse(s).unwrap();
        assert_eq!(n("-0").as_i64(), Some(0));
        assert_eq!(n("12.5").as_i64(), None);
        assert_eq!(n("1e3").as_i64(), None);
        assert_eq!(n("99999999999999999999").as_i64(), None);
        assert_eq!(n("1.5E-3"), Value::Number("1.5E-3".into()));
        for bad in ["01", "-", "1.", ".5", "1e", "+1"] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn strings_and_escapes() {
        let v = parse(r#""a\"b\\c\/\n\u00e9\ud83d\ude00é""#).unwrap();
        assert_eq!(v.as_str(), Some("a\"b\\c/\né😀é"));
        for bad in [
            r#""\x""#,
            r#""\ud83d""#,
            r#""\udc00""#,
            "\"a\u{1}\"",
            "\"open",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn nesting_and_structure_errors() {
        let v = parse(r#"{"a":[1,{"b":[]},"c"],"d":{}}"#).unwrap();
        assert_eq!(
            v.get("a").and_then(Value::as_array).map(<[_]>::len),
            Some(3)
        );
        for bad in [
            "",
            "{",
            "{\"a\"}",
            "{\"a\":1,}",
            "[1,]",
            "{\"a\":1 \"b\":2}",
            "{} x",
            "{a:1}",
            "{\"a\":1,\"a\":2}",
            "tru",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        let deep = "[".repeat(MAX_DEPTH + 2) + &"]".repeat(MAX_DEPTH + 2);
        assert!(parse(&deep).is_err());
    }

    #[test]
    fn quote_round_trips() {
        let s = "q\"b\\s\n\t\u{1}é";
        assert_eq!(parse(&quote(s)).unwrap().as_str(), Some(s));
    }
}
