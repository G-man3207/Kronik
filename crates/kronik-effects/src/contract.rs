//! `ContractFake` (M12, docs/design/m12-simulators.md §3.1, ADR 0016):
//! schema-valid JSON answers from an OpenAPI 3 document for one target,
//! the same bytes for the same request fingerprint.

use serde_json::{Map, Value};

use crate::http::parse_url;

/// How deep `$ref`s and nested schemas are followed.
const MAX_DEPTH: usize = 16;

/// The most JSON values one answer may have; past it there is no answer.
const MAX_NODES: usize = 10_000;

/// The longest string an answer may have; a longer `minLength` gives no
/// answer.
const MAX_STRING: usize = 4096;

/// The most bytes one answer may have (strings, `const` and `enum` values
/// at their serialized size, keys and scalars); past it there is no answer.
/// Values are counted, not nodes alone: one `const` can be a megabyte.
const MAX_BYTES: usize = 1 << 20;

/// A parsed OpenAPI document for one target.
#[derive(Debug, Clone)]
pub struct Contract {
    doc: Value,
    /// The path prefix of `servers[0].url`, stripped from request paths.
    base: String,
}

/// A generated answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractAnswer {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Choices drawn from BLAKE3's output stream: deterministic per seed. Also
/// the budget of one answer and the `$ref`s on the current path.
struct Draw {
    xof: blake3::OutputReader,
    nodes: usize,
    /// The bytes left of [`MAX_BYTES`].
    bytes: usize,
    /// The schema cannot be satisfied within the bounds: no answer.
    over: bool,
    path: Vec<String>,
}

impl Draw {
    fn next(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.xof.fill(&mut b);
        u64::from_le_bytes(b)
    }

    /// A number in `0..n` (`n` > 0).
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }

    /// Charges `n` bytes to the answer; past the budget there is no answer.
    fn charge(&mut self, n: usize) {
        match self.bytes.checked_sub(n) {
            Some(left) => self.bytes = left,
            None => self.over = true,
        }
    }

    /// Charges a literal value at its serialized size, then gives a copy,
    /// or Null past the budget (the copy is never made then).
    fn literal(&mut self, v: &Value) -> Value {
        // Serialized at most until the budget runs out: a contract is at
        // most 1 MiB, so this is bounded too.
        let n = match v {
            Value::String(s) => s.len() + 2,
            _ => serde_json::to_vec(v).map_or(usize::MAX, |b| b.len()),
        };
        self.charge(n);
        if self.over { Value::Null } else { v.clone() }
    }

    /// Whether `schema` is a `$ref` already being generated (recursion).
    fn on_path(&self, schema: &Value) -> bool {
        schema
            .get("$ref")
            .and_then(Value::as_str)
            .is_some_and(|r| self.path.iter().any(|p| p == r))
    }
}

/// An integer in `lo..=hi` (`lo <= hi`), without overflow.
fn int_between(draw: &mut Draw, lo: i64, hi: i64) -> i64 {
    let span = (i128::from(hi) - i128::from(lo) + 1) as u128;
    let off = u128::from(draw.next()) % span;
    i64::try_from(i128::from(lo) + off as i128).unwrap_or(lo)
}

impl Contract {
    /// Parses an OpenAPI 3.0 or 3.1 document in JSON.
    pub fn parse(bytes: &[u8]) -> Result<Contract, String> {
        let doc: Value =
            serde_json::from_slice(bytes).map_err(|e| format!("contract is not JSON: {e}"))?;
        let version = doc.get("openapi").and_then(Value::as_str).unwrap_or("");
        if !version.starts_with("3.") {
            return Err("contract must be an OpenAPI 3 document (\"openapi\": \"3.x\")".into());
        }
        if !doc.get("paths").is_some_and(Value::is_object) {
            return Err("contract has no paths".into());
        }
        let base = doc
            .pointer("/servers/0/url")
            .and_then(Value::as_str)
            .map(|u| match u.split_once("://") {
                Some((_, rest)) => rest.find('/').map_or("", |i| &rest[i..]).to_owned(),
                None => u.to_owned(),
            })
            .unwrap_or_default()
            .trim_end_matches('/')
            .to_owned();
        Ok(Contract { doc, base })
    }

    /// The document's `info.title`, if any.
    pub fn title(&self) -> Option<&str> {
        self.doc.pointer("/info/title").and_then(Value::as_str)
    }

    /// The answer for a request, or `None` when the document has no
    /// matching operation with a JSON response. `seed` identifies the
    /// request (target and fingerprint).
    pub fn answer(&self, method: &str, url: &str, seed: &[u8]) -> Option<ContractAnswer> {
        let t = parse_url(url).ok()?;
        let path = t.path.strip_prefix(&self.base).unwrap_or(&t.path);
        let path = if path.is_empty() { "/" } else { path };
        let item = self.path_item(path)?;
        let op = item.get(method.to_ascii_lowercase())?;
        let (status, schema) = response_schema(op)?;
        let mut h = blake3::Hasher::new();
        h.update(b"kronik.contract.v1\0");
        h.update(seed);
        let mut draw = Draw {
            xof: h.finalize_xof(),
            nodes: MAX_NODES,
            bytes: MAX_BYTES,
            over: false,
            path: Vec::new(),
        };
        let value = self.generate(schema, &mut draw, 0);
        if draw.over {
            return None;
        }
        Some(ContractAnswer {
            status,
            body: serde_json::to_vec(&value).ok()?,
        })
    }

    /// The path item whose template matches `path`: most literal segments
    /// first, then the smallest template.
    fn path_item(&self, path: &str) -> Option<&Value> {
        let segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        let paths = self.doc.get("paths")?.as_object()?;
        let mut best: Option<(usize, &str, &Value)> = None;
        for (template, item) in paths {
            let tsegs: Vec<&str> = template.trim_start_matches('/').split('/').collect();
            if tsegs.len() != segs.len() {
                continue;
            }
            let mut literals = 0;
            let fits = tsegs.iter().zip(&segs).all(|(t, s)| {
                if t.starts_with('{') && t.ends_with('}') {
                    !s.is_empty()
                } else {
                    literals += 1;
                    t == s
                }
            });
            if !fits {
                continue;
            }
            let better = match best {
                None => true,
                Some((l, tmpl, _)) => literals > l || (literals == l && template.as_str() < tmpl),
            };
            if better {
                best = Some((literals, template, item));
            }
        }
        best.map(|(_, _, item)| item)
    }

    fn resolve<'a>(&'a self, schema: &'a Value, depth: usize) -> &'a Value {
        let mut s = schema;
        for _ in depth..MAX_DEPTH {
            let Some(r) = s.get("$ref").and_then(Value::as_str) else {
                return s;
            };
            match r.strip_prefix('#').and_then(|p| self.doc.pointer(p)) {
                Some(next) => s = next,
                None => return &Value::Null,
            }
        }
        &Value::Null
    }

    fn generate(&self, schema: &Value, draw: &mut Draw, depth: usize) -> Value {
        // Past a bound the schema gets no answer rather than an invalid one.
        if depth >= MAX_DEPTH || draw.nodes == 0 {
            draw.over = true;
        }
        if draw.over {
            return Value::Null;
        }
        draw.nodes -= 1;
        if let Some(r) = schema.get("$ref").and_then(Value::as_str) {
            draw.path.push(r.to_owned());
            let v = self.generate_resolved(self.resolve(schema, depth), draw, depth);
            draw.path.pop();
            return v;
        }
        self.generate_resolved(schema, draw, depth)
    }

    fn generate_resolved(&self, schema: &Value, draw: &mut Draw, depth: usize) -> Value {
        if let Some(c) = schema.get("const") {
            return draw.literal(c);
        }
        if let Some(e) = schema.get("enum").and_then(Value::as_array)
            && !e.is_empty()
        {
            let pick = &e[draw.below(e.len() as u64) as usize];
            return draw.literal(pick);
        }
        for key in ["oneOf", "anyOf"] {
            if let Some(first) = schema
                .get(key)
                .and_then(Value::as_array)
                .and_then(|a| a.first())
            {
                return self.generate(first, draw, depth + 1);
            }
        }
        if let Some(all) = schema.get("allOf").and_then(Value::as_array) {
            let mut out = Map::new();
            for part in all {
                match self.generate(part, draw, depth + 1) {
                    Value::Object(m) => out.extend(m),
                    other if out.is_empty() => return other,
                    _ => {}
                }
            }
            return Value::Object(out);
        }
        let ty = match schema.get("type") {
            Some(Value::String(t)) => t.as_str(),
            // 3.1 type lists: the first non-null type.
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(Value::as_str)
                .find(|t| *t != "null")
                .unwrap_or("null"),
            _ if schema.get("properties").is_some() => "object",
            _ if schema.get("items").is_some() => "array",
            _ => "object",
        };
        match ty {
            "object" => {
                let mut out = Map::new();
                let required: Vec<&str> = schema
                    .get("required")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .collect();
                if let Some(props) = schema.get("properties").and_then(Value::as_object) {
                    // serde_json's map is ordered by key: name order.
                    for (name, sub) in props {
                        // An optional property that recurses is left out.
                        if draw.on_path(sub) && !required.contains(&name.as_str()) {
                            continue;
                        }
                        draw.charge(name.len() + 4);
                        out.insert(name.clone(), self.generate(sub, draw, depth + 1));
                    }
                }
                // Required names without a property schema: any value.
                for name in required {
                    if !out.contains_key(name) {
                        out.insert(name.to_owned(), Value::Object(Map::new()));
                    }
                }
                Value::Object(out)
            }
            "array" => {
                let min = schema.get("minItems").and_then(Value::as_u64).unwrap_or(0);
                let max = schema
                    .get("maxItems")
                    .and_then(Value::as_u64)
                    .unwrap_or(u64::MAX);
                let items = schema.get("items").unwrap_or(&Value::Null);
                if min > max {
                    draw.over = true;
                    return Value::Null;
                }
                // One item when the schema allows it, unless it recurses.
                let n = if min > 0 || draw.on_path(items) {
                    min
                } else {
                    max.min(1)
                };
                let mut out = Vec::new();
                for _ in 0..n {
                    if draw.over {
                        break;
                    }
                    out.push(self.generate(items, draw, depth + 1));
                }
                Value::Array(out)
            }
            "string" => {
                let s = string(schema, draw);
                draw.charge(s.len() + 2);
                Value::String(s)
            }
            "integer" => {
                let min = schema.get("minimum").and_then(Value::as_i64);
                let max = schema.get("maximum").and_then(Value::as_i64);
                let (lo, hi) = match (min, max) {
                    (Some(lo), Some(hi)) => (lo, hi),
                    (Some(lo), None) => (lo, lo.saturating_add(1000)),
                    (None, Some(hi)) if hi >= 0 => (0, hi),
                    (None, Some(hi)) => (hi.saturating_sub(1000), hi),
                    (None, None) => (0, 1000),
                };
                if lo > hi {
                    draw.over = true;
                    return Value::Null;
                }
                draw.charge(20);
                Value::from(int_between(draw, lo, hi))
            }
            "number" => {
                let min = schema.get("minimum").and_then(Value::as_f64);
                let max = schema.get("maximum").and_then(Value::as_f64);
                let (lo, hi) = match (min, max) {
                    (Some(lo), Some(hi)) => (lo, hi),
                    (Some(lo), None) => (lo, lo + 1000.0),
                    (None, Some(hi)) if hi >= 0.0 => (0.0, hi),
                    (None, Some(hi)) => (hi - 1000.0, hi),
                    (None, None) => (0.0, 1000.0),
                };
                if !lo.is_finite() || !hi.is_finite() || lo > hi {
                    draw.over = true;
                    return Value::Null;
                }
                draw.charge(24);
                let frac = draw.below(1_000_001) as f64 / 1_000_000.0;
                serde_json::Number::from_f64(lo + (hi - lo) * frac)
                    .map_or(Value::Null, Value::Number)
            }
            "boolean" => Value::Bool(draw.below(2) == 1),
            _ => Value::Null,
        }
    }
}

/// The lowest 2xx response with a JSON schema, else `default` / `2XX`.
fn response_schema(op: &Value) -> Option<(u16, &Value)> {
    let responses = op.get("responses")?.as_object()?;
    fn schema(r: &Value) -> Option<&Value> {
        let content = r.get("content")?.as_object()?;
        content
            .iter()
            .find(|(t, _)| t.starts_with("application/json") || t.ends_with("+json"))
            .and_then(|(_, m)| m.get("schema"))
    }
    let mut codes: Vec<(u16, &Value)> = responses
        .iter()
        .filter_map(|(code, r)| {
            let n: u16 = code.parse().ok()?;
            (200..300).contains(&n).then_some((n, r))
        })
        .collect();
    codes.sort_by_key(|(n, _)| *n);
    for (n, r) in codes {
        if let Some(s) = schema(r) {
            return Some((n, s));
        }
    }
    ["2XX", "default"]
        .iter()
        .find_map(|k| responses.get(*k).and_then(schema))
        .map(|s| (200, s))
}

fn string(schema: &Value, draw: &mut Draw) -> String {
    let hex = |draw: &mut Draw, n: usize| -> String {
        (0..n)
            .map(|_| char::from_digit(draw.below(16) as u32, 16).unwrap_or('0'))
            .collect()
    };
    let format = schema.get("format").and_then(Value::as_str);
    let s = match format {
        Some("date-time") => format!(
            "2026-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            1 + draw.below(12),
            1 + draw.below(28),
            draw.below(24),
            draw.below(60),
            draw.below(60)
        ),
        Some("date") => format!("2026-{:02}-{:02}", 1 + draw.below(12), 1 + draw.below(28)),
        Some("uuid") => {
            let h = hex(draw, 32);
            format!(
                "{}-{}-4{}-a{}-{}",
                &h[..8],
                &h[8..12],
                &h[13..16],
                &h[17..20],
                &h[20..]
            )
        }
        Some("email") => format!("user{}@example.com", draw.below(10_000)),
        Some("uri" | "url") => format!("https://example.com/{}", hex(draw, 8)),
        _ => format!("s{}", hex(draw, 8)),
    };
    let formatted = matches!(
        format,
        Some("date-time" | "date" | "uuid" | "email" | "uri" | "url")
    );
    let min = schema.get("minLength").and_then(Value::as_u64).unwrap_or(0);
    let max = schema
        .get("maxLength")
        .and_then(Value::as_u64)
        .unwrap_or(u64::MAX);
    let len = s.len() as u64; // ASCII
    // Padding or cutting would break the format; past MAX_STRING is too big.
    if min > max || min > MAX_STRING as u64 || (formatted && (len < min || len > max)) {
        draw.over = true;
        return String::new();
    }
    let mut s = s;
    if len < min {
        s.extend(std::iter::repeat_n('x', (min - len) as usize));
    }
    if len > max {
        s.truncate(max as usize);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = r##"{
      "openapi": "3.0.3",
      "info": {"title": "Payments", "version": "1"},
      "servers": [{"url": "https://payments.internal/v1"}],
      "paths": {
        "/charges/{id}": {"get": {"responses": {
          "404": {"description": "missing"},
          "200": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Charge"}}}}
        }}},
        "/charges/search": {"get": {"responses": {
          "200": {"content": {"application/json": {"schema": {
            "type": "array", "minItems": 2, "maxItems": 3,
            "items": {"$ref": "#/components/schemas/Charge"}}}}}
        }}},
        "/refunds": {"post": {"responses": {
          "201": {"content": {"application/json": {"schema": {"allOf": [
            {"type": "object", "required": ["id"], "properties": {"id": {"type": "string", "format": "uuid"}}},
            {"type": "object", "properties": {"ok": {"type": "boolean"}}}
          ]}}}}
        }}}
      },
      "components": {"schemas": {
        "Charge": {"type": "object", "required": ["id", "amount", "status"], "properties": {
          "id": {"type": "string", "minLength": 4, "maxLength": 12},
          "amount": {"type": "integer", "minimum": 1, "maximum": 100000},
          "fee": {"type": "number", "minimum": 0, "maximum": 3.5},
          "status": {"type": "string", "enum": ["pending", "succeeded", "failed"]},
          "created": {"type": "string", "format": "date-time"},
          "email": {"type": "string", "format": "email"},
          "tags": {"type": "array", "items": {"type": "string"}},
          "meta": {"oneOf": [{"type": "object", "properties": {"k": {"type": "string"}}}, {"type": "string"}]}
        }}
      }}
    }"##;

    /// An independent validator for the keywords the generator covers.
    fn valid(doc: &Value, schema: &Value, v: &Value) -> Result<(), String> {
        let schema = match schema.get("$ref").and_then(Value::as_str) {
            Some(r) => doc.pointer(&r[1..]).ok_or("dangling ref")?,
            None => schema,
        };
        if let Some(e) = schema.get("enum").and_then(Value::as_array) {
            return e
                .contains(v)
                .then_some(())
                .ok_or(format!("{v} not in enum"));
        }
        if let Some(one) = schema.get("oneOf").and_then(Value::as_array) {
            return one
                .iter()
                .any(|s| valid(doc, s, v).is_ok())
                .then_some(())
                .ok_or(format!("{v} matches no oneOf branch"));
        }
        if let Some(all) = schema.get("allOf").and_then(Value::as_array) {
            return all.iter().try_for_each(|s| valid(doc, s, v));
        }
        match schema.get("type").and_then(Value::as_str) {
            Some("object") => {
                let o = v.as_object().ok_or(format!("{v} is not an object"))?;
                for r in schema
                    .get("required")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let r = r.as_str().unwrap_or("");
                    o.get(r).ok_or(format!("missing {r}"))?;
                }
                if let Some(props) = schema.get("properties").and_then(Value::as_object) {
                    for (k, sub) in props {
                        if let Some(x) = o.get(k) {
                            valid(doc, sub, x)?;
                        }
                    }
                }
                Ok(())
            }
            Some("array") => {
                let a = v.as_array().ok_or(format!("{v} is not an array"))?;
                let min = schema.get("minItems").and_then(Value::as_u64).unwrap_or(0) as usize;
                let max = schema
                    .get("maxItems")
                    .and_then(Value::as_u64)
                    .map_or(usize::MAX, |m| m as usize);
                if a.len() < min || a.len() > max {
                    return Err(format!("{} items", a.len()));
                }
                let items = schema.get("items").cloned().unwrap_or(Value::Null);
                a.iter().try_for_each(|x| valid(doc, &items, x))
            }
            Some("string") => {
                let s = v.as_str().ok_or(format!("{v} is not a string"))?;
                let n = s.chars().count() as u64;
                if schema
                    .get("minLength")
                    .and_then(Value::as_u64)
                    .is_some_and(|m| n < m)
                    || schema
                        .get("maxLength")
                        .and_then(Value::as_u64)
                        .is_some_and(|m| n > m)
                {
                    return Err(format!("{s:?} has the wrong length"));
                }
                match schema.get("format").and_then(Value::as_str) {
                    Some("uuid") if s.len() != 36 || s.matches('-').count() != 4 => {
                        Err(format!("{s} is not a uuid"))
                    }
                    Some("date-time")
                        if !(s.len() == 20 && s.ends_with('Z') && s.contains('T')) =>
                    {
                        Err(format!("{s} is not a date-time"))
                    }
                    Some("email") if !s.contains('@') => Err(format!("{s} is not an email")),
                    _ => Ok(()),
                }
            }
            Some("integer") => {
                let n = v.as_i64().ok_or(format!("{v} is not an integer"))?;
                let lo = schema
                    .get("minimum")
                    .and_then(Value::as_i64)
                    .unwrap_or(i64::MIN);
                let hi = schema
                    .get("maximum")
                    .and_then(Value::as_i64)
                    .unwrap_or(i64::MAX);
                (lo..=hi)
                    .contains(&n)
                    .then_some(())
                    .ok_or(format!("{n} out of range"))
            }
            Some("number") => {
                let n = v.as_f64().ok_or(format!("{v} is not a number"))?;
                let lo = schema
                    .get("minimum")
                    .and_then(Value::as_f64)
                    .unwrap_or(f64::MIN);
                let hi = schema
                    .get("maximum")
                    .and_then(Value::as_f64)
                    .unwrap_or(f64::MAX);
                (lo <= n && n <= hi)
                    .then_some(())
                    .ok_or(format!("{n} out of range"))
            }
            Some("boolean") => v
                .is_boolean()
                .then_some(())
                .ok_or(format!("{v} is not a bool")),
            _ => Ok(()),
        }
    }

    #[test]
    fn answers_are_schema_valid_and_deterministic() {
        let c = Contract::parse(DOC.as_bytes()).unwrap();
        let doc: Value = serde_json::from_str(DOC).unwrap();
        assert_eq!(c.title(), Some("Payments"));
        let charge = doc.pointer("/components/schemas/Charge").unwrap();
        let search = doc
            .pointer("/paths/~1charges~1search/get/responses/200/content/application~1json/schema")
            .unwrap();
        let refund = doc
            .pointer("/paths/~1refunds/post/responses/201/content/application~1json/schema")
            .unwrap();
        for i in 0..300u32 {
            let seed = i.to_le_bytes();
            let a = c
                .answer(
                    "GET",
                    &format!("https://payments.internal/v1/charges/ch_{i}"),
                    &seed,
                )
                .unwrap();
            assert_eq!(a.status, 200);
            let v: Value = serde_json::from_slice(&a.body).unwrap();
            valid(&doc, charge, &v).unwrap_or_else(|e| panic!("{e}: {v}"));
            // The same request (seed) gives the same bytes.
            let again = c
                .answer(
                    "GET",
                    &format!("https://payments.internal/v1/charges/ch_{i}"),
                    &seed,
                )
                .unwrap();
            assert_eq!(a, again);
            let s = c
                .answer("GET", "https://payments.internal/v1/charges/search", &seed)
                .unwrap();
            let v: Value = serde_json::from_slice(&s.body).unwrap();
            valid(&doc, search, &v).unwrap_or_else(|e| panic!("{e}: {v}"));
            let r = c
                .answer("POST", "https://payments.internal/v1/refunds", &seed)
                .unwrap();
            assert_eq!(r.status, 201);
            let v: Value = serde_json::from_slice(&r.body).unwrap();
            valid(&doc, refund, &v).unwrap_or_else(|e| panic!("{e}: {v}"));
        }
        // Different requests differ.
        let a = c
            .answer("GET", "https://payments.internal/v1/charges/a", b"1")
            .unwrap();
        let b = c
            .answer("GET", "https://payments.internal/v1/charges/a", b"2")
            .unwrap();
        assert_ne!(a.body, b.body);
    }

    #[test]
    fn matching_and_parse_errors() {
        let c = Contract::parse(DOC.as_bytes()).unwrap();
        // The literal template wins over {id}.
        let s = c
            .answer("GET", "https://payments.internal/v1/charges/search", b"x")
            .unwrap();
        assert!(serde_json::from_slice::<Value>(&s.body).unwrap().is_array());
        assert!(
            c.answer("DELETE", "https://payments.internal/v1/charges/a", b"x")
                .is_none()
        );
        assert!(
            c.answer("GET", "https://payments.internal/v1/other", b"x")
                .is_none()
        );
        assert!(Contract::parse(b"{}").is_err());
        assert!(Contract::parse(br#"{"openapi": "2.0", "paths": {}}"#).is_err());
        assert!(Contract::parse(b"not json").is_err());
    }

    /// The answer for `GET /x` whose schema is `components.schemas.N`.
    fn fake(n: Value) -> Option<Value> {
        let doc = serde_json::json!({
            "openapi": "3.0.3",
            "paths": {"/x": {"get": {"responses": {"200": {"content": {
                "application/json": {"schema": {"$ref": "#/components/schemas/N"}}}}}}}},
            "components": {"schemas": {"N": n}},
        });
        let c = Contract::parse(&serde_json::to_vec(&doc).unwrap()).unwrap();
        c.answer("GET", "https://h/x", b"seed")
            .map(|a| serde_json::from_slice(&a.body).unwrap())
    }

    /// M4: recursion and breadth are bounded; an unsatisfiable schema gets
    /// no answer, never an invalid one or a panic.
    #[test]
    fn generation_is_bounded() {
        let me = serde_json::json!({"$ref": "#/components/schemas/N"});
        // Required self-references cannot end: no answer.
        let required = serde_json::json!({"type": "object", "required": ["a", "b"],
            "properties": {"a": me, "b": me}});
        assert_eq!(fake(required), None);
        // Optional ones are left out.
        let optional = fake(serde_json::json!({"type": "object", "properties": {
            "child": me, "kids": {"type": "array", "items": me}, "v": {"type": "integer"}}}))
        .unwrap();
        let keys: Vec<&String> = optional.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["kids", "v"], "{optional}");
        assert_eq!(optional["kids"], serde_json::json!([]));
        // Too many values, a too long string: no answer.
        assert_eq!(
            fake(serde_json::json!({"type": "array", "minItems": 1_000_000})),
            None
        );
        assert_eq!(
            fake(serde_json::json!({"type": "string", "minLength": 5000})),
            None
        );
        // N12-1: values are counted in bytes, not only nodes: a 10 KiB const
        // a thousand times (10 MB) gets no answer, and so do strings that
        // add up past the budget; within it the answer stays.
        let big = "x".repeat(10 << 10);
        assert_eq!(
            fake(serde_json::json!({"type": "array", "minItems": 1000,
                "items": {"const": big}})),
            None
        );
        assert_eq!(
            fake(serde_json::json!({"type": "array", "minItems": 1000,
                "items": {"enum": [{"a": big}]}})),
            None
        );
        assert_eq!(
            fake(serde_json::json!({"type": "array", "minItems": 1000,
                "items": {"type": "string", "minLength": 2000}})),
            None
        );
        let ok = fake(serde_json::json!({"type": "array", "minItems": 50,
            "items": {"const": big}}))
        .unwrap();
        assert_eq!(ok.as_array().unwrap().len(), 50);
        // The full i64 range does not overflow.
        let v = fake(serde_json::json!({"type": "integer",
            "minimum": i64::MIN, "maximum": i64::MAX}))
        .unwrap();
        assert!(v.is_i64(), "{v}");
    }

    /// L2: keywords the first generator got wrong.
    #[test]
    fn keyword_edges() {
        let v = fake(serde_json::json!({"type": "integer", "maximum": -1})).unwrap();
        assert!(v.as_i64().unwrap() <= -1, "{v}");
        let v = fake(serde_json::json!({"type": "number", "maximum": -1.5})).unwrap();
        assert!(v.as_f64().unwrap() <= -1.5, "{v}");
        let v = fake(serde_json::json!({"type": "array", "minItems": 20,
            "items": {"type": "integer"}}))
        .unwrap();
        assert_eq!(v.as_array().unwrap().len(), 20);
        let v = fake(
            serde_json::json!({"type": "object", "required": ["id", "extra"],
            "properties": {"id": {"type": "string"}}}),
        )
        .unwrap();
        assert!(v.get("extra").is_some() && v["id"].is_string(), "{v}");
        // A format that does not fit the length: no answer rather than a cut.
        assert_eq!(
            fake(serde_json::json!({"type": "string", "format": "date-time", "maxLength": 10})),
            None
        );
        assert_eq!(
            fake(serde_json::json!({"type": "integer", "minimum": 5, "maximum": 1})),
            None
        );
    }
}
