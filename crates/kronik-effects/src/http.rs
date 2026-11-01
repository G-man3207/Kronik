//! HTTP effect requests: URL parsing, fingerprints and secret scrubbing.

use kronik_proto::log::v1 as pb;

mod credential_output;

/// Headers left out of the fingerprint by default.
pub const FINGERPRINT_EXCLUDED: &[&str] = &[
    "authorization",
    "cookie",
    "date",
    "idempotency-key",
    "user-agent",
    "x-request-id",
];

/// The parts of an effect URL Kronik needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub scheme: String,
    /// Lowercase for live/legacy URLs; already encoded and case-preserved for prepared v2 data.
    pub host: String,
    /// Only when it differs from the scheme's default.
    pub port: Option<u16>,
    pub path: String,
    pub query: String,
}

/// Parses `http://`, `https://` and `foreign://` URLs.
pub fn parse_url(url: &str) -> Result<Target, String> {
    Ok(parsed_url(url)?.1)
}

/// Parse the live URL once and retain its original host bytes for exact redaction.
pub fn parse_request_url(url: &str) -> Result<(Target, &str), String> {
    let (uri, target) = parsed_url(url)?;
    let host = uri.authority().ok_or("validated URL has no authority")?.host();
    // The validated authority has no userinfo, so its host starts after "://".
    let start = target.scheme.len() + 3;
    let end = start.checked_add(host.len()).ok_or("validated URL host span overflow")?;
    let raw_host = url.get(start..end).ok_or("validated URL host span is invalid")?;
    Ok((target, raw_host))
}

fn parsed_url(url: &str) -> Result<(http::Uri, Target), String> {
    let uri: http::Uri = url
        .parse()
        .map_err(|e| format!("invalid URL {url:?}: {e}"))?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| format!("URL {url:?} has no scheme"))?
        .to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https" | "foreign") {
        return Err(format!("URL scheme {scheme:?} is not supported"));
    }
    let auth = uri
        .authority()
        .ok_or_else(|| format!("URL {url:?} has no host"))?;
    if auth.as_str().contains('@') {
        return Err("credentials in URLs are not allowed; use a secret header".into());
    }
    let default = match scheme.as_str() {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    };
    let target = Target {
        host: auth.host().to_ascii_lowercase(),
        port: uri.port_u16().filter(|p| Some(*p) != default),
        path: if uri.path().is_empty() {
            "/".into()
        } else {
            uri.path().to_owned()
        },
        query: uri.query().unwrap_or("").to_owned(),
        scheme,
    };
    Ok((uri, target))
}

/// Read the internal v2 component encoding, not a live URI or a new redaction input.
pub fn prepared_target(req: &pb::HttpEffectRequest) -> Result<Target, String> {
    if req.fingerprint_version != 2 {
        return Err("prepared HTTP target requires policy version 2".into());
    }
    let invalid = || "invalid prepared HTTP target".to_owned();
    let (scheme, rest) = req.url.split_once("://").ok_or_else(invalid)?;
    let default = match scheme {
        "http" => Some(80),
        "https" => Some(443),
        "foreign" => None,
        _ => return Err(invalid()),
    };
    let authority_end = rest.find('/').ok_or_else(invalid)?;
    let authority = &rest[..authority_end];
    let (host, port) = if authority.starts_with('[') {
        let parsed: http::uri::Authority = authority.parse().map_err(|_| invalid())?;
        if parsed.as_str().contains('@') { return Err(invalid()); }
        let host = &authority[..parsed.host().len()];
        let port = match authority.get(host.len()..).and_then(|suffix| suffix.strip_prefix(':')) {
            Some(port) => Some(port.parse::<u16>().map_err(|_| invalid())?),
            None => None,
        };
        (host, port)
    } else {
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port.parse::<u16>().map_err(|_| invalid())?)),
            None => (authority, None),
        };
        let mut bytes = host.as_bytes().iter().copied();
        if host.is_empty() { return Err(invalid()); }
        while let Some(byte) = bytes.next() {
            if byte == b'%' {
                if !bytes.next().is_some_and(|byte| byte.is_ascii_hexdigit())
                    || !bytes.next().is_some_and(|byte| byte.is_ascii_hexdigit()) {
                    return Err(invalid());
                }
            } else if !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'~' | b'.')) {
                return Err(invalid());
            }
        }
        (host, port)
    };
    let suffix = &rest[authority_end..];
    let path: http::uri::PathAndQuery = suffix.parse().map_err(|_| invalid())?;
    if path.as_str() != suffix { return Err(invalid()); }
    Ok(Target { scheme: scheme.into(), host: host.into(), port: port.filter(|port| Some(*port) != default),
        path: path.path().into(), query: path.query().unwrap_or("").into() })
}

/// The route pattern of a URL path (docs/design/m3-fork.md §3.5): each
/// segment that is a decimal number, a UUID, 8 or more hex characters, or a
/// mix of letters and 6 or more digits becomes `{}`.
pub fn route_pattern(path: &str) -> String {
    fn variable(seg: &str) -> bool {
        if seg.is_empty() {
            return false;
        }
        let digits = seg.bytes().filter(u8::is_ascii_digit).count();
        let all_digits = digits == seg.len();
        let hex = seg.len() >= 8 && seg.bytes().all(|b| b.is_ascii_hexdigit());
        let uuid = seg.len() == 36
            && seg.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            });
        let mixed = digits >= 6 && seg.bytes().any(|b| b.is_ascii_alphabetic());
        all_digits || hex || uuid || mixed
    }
    path.split('/')
        .map(|s| if variable(s) { "{}" } else { s })
        .collect::<Vec<_>>()
        .join("/")
}

/// The target of an HTTP effect for approximate matching: method, host and
/// route pattern.
pub fn target_of(req: &pb::HttpEffectRequest) -> Option<(String, String, String)> {
    let t = match req.fingerprint_version {
        0 => parse_url(&req.url),
        2 => prepared_target(req),
        _ => return None,
    }.ok()?;
    Some((
        req.method.to_ascii_uppercase(),
        t.host,
        route_pattern(&t.path),
    ))
}

/// The fingerprint of an HTTP effect (docs/design/m2-effects.md §3): method,
/// scheme, host, port, path, sorted query parameters, body hash and the
/// non-excluded headers; secrets contribute name and version hash only.
pub fn fingerprint(req: &pb::HttpEffectRequest) -> Result<Vec<u8>, String> {
    if req.fingerprint_version != 0 {
        return Err("legacy HTTP fingerprint requires policy version 0".into());
    }
    Ok(fingerprint_fields(req, &parse_url(&req.url)?, false))
}

/// Current policy hashes already-scrubbed typed URL components, not a reparsed
/// marker-bearing URI. The caller retains the original request for the wire.
pub fn fingerprint_v2(req: &pb::HttpEffectRequest, target: &Target) -> Result<Vec<u8>, String> {
    if req.fingerprint_version != 2 {
        return Err("strict HTTP fingerprint requires policy version 2".into());
    }
    Ok(fingerprint_fields(req, target, true))
}

fn fingerprint_fields(req: &pb::HttpEffectRequest, t: &Target, strict: bool) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    let mut field = |b: &[u8]| {
        h.update(&(b.len() as u64).to_le_bytes());
        h.update(b);
    };
    field(if strict { b"kronik.fingerprint.http.v2" } else { b"kronik.fingerprint.http.v1" });
    field(req.method.to_ascii_uppercase().as_bytes());
    field(t.scheme.as_bytes());
    field(t.host.as_bytes());
    field(&t.port.unwrap_or(0).to_le_bytes());
    field(t.path.as_bytes());
    let mut query: Vec<&str> = t.query.split('&').filter(|p| !p.is_empty()).collect();
    query.sort_by_key(|p| (p.split_once('=').map_or(*p, |(k, _)| k), *p));
    for q in query {
        field(q.as_bytes());
    }
    field(blake3::hash(&req.body).as_bytes());
    let mut headers: Vec<(String, Vec<u8>)> = req
        .headers
        .iter()
        .filter(|hd| !FINGERPRINT_EXCLUDED.contains(&hd.name.to_ascii_lowercase().as_str()))
        .map(|hd| {
            let v = match &hd.value {
                Some(pb::http_effect_header::Value::Text(t)) => t.as_bytes().to_vec(),
                Some(pb::http_effect_header::Value::Secret(s)) => {
                    let mut v = b"secret:".to_vec();
                    v.extend_from_slice(s.name.as_bytes());
                    v.push(b'@');
                    v.extend_from_slice(&s.version_hash);
                    if strict {
                        v.extend_from_slice(&(s.template.len() as u64).to_le_bytes());
                        v.extend_from_slice(s.template.as_bytes());
                    }
                    v
                }
                None => Vec::new(),
            };
            (hd.name.to_ascii_lowercase(), v)
        })
        .collect();
    headers.sort();
    for (n, v) in headers {
        field(n.as_bytes());
        field(&v);
    }
    h.finalize().as_bytes().to_vec()
}

/// Existing caller resource limits for one free-data redaction operation.
#[derive(Clone, Copy, Debug)]
pub struct ScrubLimits {
    pub output_bytes: usize,
    pub pattern_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScrubError {
    OutputLimit,
    PatternLimit,
    MatcherUnavailable,
    InvalidText,
    SourceScopeUnavailable,
}

impl std::fmt::Display for ScrubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::OutputLimit => "REDACTION_OUTPUT_LIMIT",
            Self::PatternLimit => "REDACTION_PATTERN_LIMIT",
            Self::MatcherUnavailable => "REDACTION_UNAVAILABLE",
            Self::InvalidText => "REDACTION_INVALID_TEXT",
            Self::SourceScopeUnavailable => "REDACTION_SOURCE_SCOPE_UNAVAILABLE",
        })
    }
}

impl std::error::Error for ScrubError {}

#[derive(Clone, Copy)]
struct ScrubMatch {
    start: usize,
    end: usize,
    pattern: Option<usize>,
}

impl From<aho_corasick::Match> for ScrubMatch {
    fn from(matched: aho_corasick::Match) -> Self {
        Self { start: matched.start(), end: matched.end(), pattern: Some(matched.pattern().as_usize()) }
    }
}

enum CompiledMatcher {
    Literals(aho_corasick::AhoCorasick),
    Output(credential_output::CredentialMatcher),
}

/// One ordered matcher. Secret values are compiled once; only names remain borrowed.
pub struct CompiledScrubber<'a> {
    names: Vec<std::borrow::Cow<'a, [u8]>>,
    matcher: Option<CompiledMatcher>,
    max_len: usize,
    pattern_bytes: usize,
}

impl<'a> CompiledScrubber<'a> {
    pub fn new<N: AsRef<str>, V: AsRef<[u8]>>(
        secrets: &'a [(N, V)],
        pattern_bytes: usize,
    ) -> Result<Self, ScrubError> {
        Self::build(secrets, pattern_bytes, usize::MAX, false)
    }

    /// Output-only plan: also hides syntactically valid Kronik credentials on the original bytes.
    /// Request normalization must keep using `new`, which matches only supplied literal values.
    pub fn new_output<N: AsRef<str>, V: AsRef<[u8]>>(
        secrets: &'a [(N, V)],
        pattern_bytes: usize,
    ) -> Result<Self, ScrubError> {
        Self::build(secrets, pattern_bytes, usize::MAX, true)
    }

    /// Own only marker names, not another copy of secret values or the automaton.
    pub fn into_owned(self) -> CompiledScrubber<'static> {
        CompiledScrubber {
            names: self.names.into_iter()
                .map(|name| std::borrow::Cow::Owned(name.into_owned())).collect(),
            matcher: self.matcher,
            max_len: self.max_len,
            pattern_bytes: self.pattern_bytes,
        }
    }

    fn build<N: AsRef<str>, V: AsRef<[u8]>>(
        secrets: &'a [(N, V)],
        pattern_limit: usize,
        max_match_bytes: usize,
        credentials: bool,
    ) -> Result<Self, ScrubError> {
        let mut seen = std::collections::HashSet::new();
        let mut patterns = Vec::new();
        let mut pattern_bytes = 0usize;
        let mut max_len = 0;
        for (name, value) in secrets {
            let name = name.as_ref();
            let value = value.as_ref();
            if value.is_empty() || !seen.insert(value) {
                continue;
            }
            pattern_bytes = pattern_bytes.checked_add(value.len())
                .and_then(|bytes| bytes.checked_add(name.len()))
                .filter(|bytes| *bytes <= pattern_limit)
                .ok_or(ScrubError::PatternLimit)?;
            if value.len() <= max_match_bytes {
                max_len = max_len.max(value.len());
                patterns.push((value, name.as_bytes()));
            }
        }
        let matcher = if credentials {
            max_len = max_len.max(50);
            Some(CompiledMatcher::Output(credential_output::CredentialMatcher::build(
                patterns.iter().map(|(value, _)| *value),
            )?))
        } else if patterns.is_empty() {
            None
        } else {
            Some(CompiledMatcher::Literals(aho_corasick::AhoCorasick::builder()
                .kind(Some(aho_corasick::AhoCorasickKind::NoncontiguousNFA))
                .match_kind(aho_corasick::MatchKind::LeftmostLongest)
                .build(patterns.iter().map(|(value, _)| *value))
                .map_err(|_| ScrubError::MatcherUnavailable)?))
        };
        let names = patterns.into_iter()
            .map(|(_, name)| std::borrow::Cow::Borrowed(name)).collect();
        Ok(Self { names, matcher, max_len, pattern_bytes })
    }

    /// Test original bytes without allocating replacement output.
    pub fn is_match(&self, bytes: &[u8]) -> bool {
        self.matcher.as_ref().is_some_and(|matcher| match matcher {
            CompiledMatcher::Literals(matcher) => matcher.is_match(bytes),
            CompiledMatcher::Output(matcher) => matcher.is_match(bytes),
        })
    }

    /// None means no original match, not merely byte-identical replacement output.
    pub fn scrub_if_matched(
        &self,
        bytes: &[u8],
        output_limit: usize,
    ) -> Result<Option<Vec<u8>>, ScrubError> {
        match &self.matcher {
            Some(CompiledMatcher::Literals(matcher)) => self.collect_matches(
                bytes, matcher.find_iter(bytes).map(ScrubMatch::from), output_limit,
            ),
            Some(CompiledMatcher::Output(matcher)) => self.collect_matches(
                bytes, matcher.matches(bytes, &mut credential_output::Scratch::default())?, output_limit,
            ),
            None => self.collect_matches(bytes, std::iter::empty(), output_limit),
        }
    }

    fn collect_matches(
        &self,
        bytes: &[u8],
        mut matches: impl Iterator<Item = ScrubMatch>,
        output_limit: usize,
    ) -> Result<Option<Vec<u8>>, ScrubError> {
        if let Some(first) = matches.next() {
            let mut out = Vec::new();
            out.try_reserve_exact(bytes.len().min(output_limit))
                .map_err(|_| ScrubError::MatcherUnavailable)?;
            self.emit_matches(
                bytes, bytes.len(), std::iter::once(first).chain(matches), &mut out, output_limit,
            )?;
            return Ok(Some(out));
        }
        if bytes.len() > output_limit {
            return Err(ScrubError::OutputLimit);
        }
        Ok(None)
    }

    /// Starts before `stable_through` have enough lookahead for the longest match.
    fn emit(
        &self,
        bytes: &[u8],
        stable_through: usize,
        out: &mut Vec<u8>,
        output_limit: usize,
        scratch: &mut credential_output::Scratch,
    ) -> Result<usize, ScrubError> {
        match &self.matcher {
            Some(CompiledMatcher::Literals(matcher)) => self.emit_matches(
                bytes, stable_through, matcher.find_iter(bytes).map(ScrubMatch::from), out, output_limit,
            ),
            Some(CompiledMatcher::Output(matcher)) => self.emit_matches(
                bytes, stable_through, matcher.matches(bytes, scratch)?, out, output_limit,
            ),
            None => self.emit_matches(
                bytes, stable_through, std::iter::empty(), out, output_limit,
            ),
        }
    }

    fn emit_matches(
        &self,
        bytes: &[u8],
        stable_through: usize,
        matches: impl Iterator<Item = ScrubMatch>,
        out: &mut Vec<u8>,
        output_limit: usize,
    ) -> Result<usize, ScrubError> {
        let mut end = 0;
        for matched in matches {
            if matched.start >= stable_through {
                break;
            }
            let (prefix, name) = match matched.pattern {
                Some(pattern) => (b"[secret:".as_slice(), self.names[pattern].as_ref()),
                None => (b"[secret:".as_slice(), b"token".as_slice()),
            };
            let required = (matched.start - end).checked_add(prefix.len())
                .and_then(|bytes| bytes.checked_add(name.len()))
                .and_then(|bytes| bytes.checked_add(1))
                .and_then(|bytes| out.len().checked_add(bytes))
                .filter(|bytes| *bytes <= output_limit)
                .ok_or(ScrubError::OutputLimit)?;
            reserve_scrub_output(out, required, output_limit)?;
            out.extend_from_slice(&bytes[end..matched.start]);
            out.extend_from_slice(prefix);
            out.extend_from_slice(name);
            out.push(b']');
            end = matched.end;
        }
        let consumed = stable_through.max(end);
        let required = out.len().checked_add(consumed - end)
            .filter(|bytes| *bytes <= output_limit)
            .ok_or(ScrubError::OutputLimit)?;
        reserve_scrub_output(out, required, output_limit)?;
        out.extend_from_slice(&bytes[end..consumed]);
        Ok(consumed)
    }
}

fn reserve_scrub_output(
    out: &mut Vec<u8>,
    required: usize,
    output_limit: usize,
) -> Result<(), ScrubError> {
    if required > out.capacity() {
        let capacity = out.capacity().saturating_mul(2).max(required).min(output_limit);
        out.try_reserve_exact(capacity - out.len())
            .map_err(|_| ScrubError::MatcherUnavailable)?;
    }
    Ok(())
}

/// Replaces all nonempty secret values in original free bytes, never encoded protocols.
/// Equal values use the first name; overlaps use the leftmost longest match.
pub fn scrub<N: AsRef<str>, V: AsRef<[u8]>>(
    bytes: &[u8],
    secrets: &[(N, V)],
    limits: ScrubLimits,
) -> Result<Vec<u8>, ScrubError> {
    let matcher = CompiledScrubber::build(secrets, limits.pattern_bytes, bytes.len(), false)?;
    if matcher.matcher.is_none() && bytes.len() > limits.output_bytes {
        return Err(ScrubError::OutputLimit);
    }
    let mut out = Vec::new();
    out.try_reserve_exact(bytes.len().min(limits.output_bytes))
        .map_err(|_| ScrubError::MatcherUnavailable)?;
    matcher.emit(bytes, bytes.len(), &mut out, limits.output_bytes, &mut credential_output::Scratch::default())?;
    Ok(out)
}

/// The same redactor for an owned body stream; raw lookahead is never emitted.
/// Raw scratch is at most `(M - 1) + max(M, 64 KiB)` for longest secret M.
/// Each emission is separately bounded by the caller's existing memory budget.
/// Returned bytes borrow a reused buffer; finish before committing the output.
pub struct StreamScrubber<'a> {
    matcher: CompiledScrubber<'a>,
    limits: ScrubLimits,
    buffer_bytes: usize,
    pending_limit: usize,
    pending: zeroize::Zeroizing<Vec<u8>>,
    output: Vec<u8>,
    produced: usize,
    failed: Option<ScrubError>,
    scratch: credential_output::Scratch,
}

impl<'a> StreamScrubber<'a> {
    pub fn new<N: AsRef<str>, V: AsRef<[u8]>>(
        secrets: &'a [(N, V)],
        limits: ScrubLimits,
        buffer_bytes: usize,
    ) -> Result<Self, ScrubError> {
        let matcher = CompiledScrubber::new(secrets, limits.pattern_bytes)?;
        Self::from_compiled(matcher, limits, buffer_bytes)
    }

    /// Move the same matcher after independent fields, with their output already
    /// subtracted from the body budget. Field boundaries never share raw lookahead.
    pub fn from_compiled(
        matcher: CompiledScrubber<'a>,
        limits: ScrubLimits,
        buffer_bytes: usize,
    ) -> Result<Self, ScrubError> {
        if matcher.pattern_bytes > limits.pattern_bytes {
            return Err(ScrubError::PatternLimit);
        }
        let pending_limit = matcher.max_len.saturating_sub(1)
            .checked_add(matcher.max_len.max(64 * 1024))
            .ok_or(ScrubError::PatternLimit)?;
        let pending = zeroize::Zeroizing::new(Vec::new());
        Ok(Self {
            matcher, limits, buffer_bytes, pending_limit, pending, output: Vec::new(),
            produced: 0, failed: None,
            scratch: credential_output::Scratch::default(),
        })
    }

    /// Append original bytes. On failure discard this stream and any staged output.
    pub fn push(&mut self, bytes: &[u8]) -> Result<&[u8], ScrubError> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        self.output.clear();
        if let Err(error) = self.push_inner(bytes) {
            self.failed = Some(error);
            zeroize::Zeroize::zeroize(&mut self.pending);
            return Err(error);
        }
        self.produced += self.output.len();
        Ok(&self.output)
    }

    fn push_inner(&mut self, mut bytes: &[u8]) -> Result<(), ScrubError> {
        let output_limit = (self.limits.output_bytes - self.produced).min(self.buffer_bytes);
        if self.matcher.matcher.is_none() {
            self.matcher.emit(bytes, bytes.len(), &mut self.output, output_limit, &mut self.scratch)?;
            return Ok(());
        }
        if !bytes.is_empty() && self.pending.capacity() == 0 {
            // Allocate raw scratch before input so growth cannot leave old raw bytes behind.
            self.pending.try_reserve_exact(self.pending_limit)
                .map_err(|_| ScrubError::MatcherUnavailable)?;
        }
        while !bytes.is_empty() {
            let count = bytes.len().min(self.pending_limit - self.pending.len());
            self.pending.extend_from_slice(&bytes[..count]);
            bytes = &bytes[count..];
            if self.pending.len() == self.pending_limit {
                let stable_through = self.pending.len() - self.matcher.max_len.saturating_sub(1);
                let consumed = self.matcher.emit(
                    &self.pending, stable_through, &mut self.output, output_limit, &mut self.scratch,
                )?;
                let retained = self.pending.len() - consumed;
                self.pending.copy_within(consumed.., 0);
                zeroize::Zeroize::zeroize(&mut self.pending[retained..]);
                self.pending.truncate(retained);
            }
        }
        Ok(())
    }

    /// Flush final lookahead. An earlier error remains a failure, never a partial success.
    pub fn finish(mut self) -> Result<Vec<u8>, ScrubError> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        self.output.clear();
        self.matcher.emit(
            &self.pending, self.pending.len(), &mut self.output,
            (self.limits.output_bytes - self.produced).min(self.buffer_bytes), &mut self.scratch,
        )?;
        Ok(self.output)
    }
}

/// Redacts free text without silently expanding invalid UTF-8 beyond its byte budget.
pub fn scrub_str<N: AsRef<str>, V: AsRef<[u8]>>(
    text: &str,
    secrets: &[(N, V)],
    limits: ScrubLimits,
) -> Result<String, ScrubError> {
    String::from_utf8(scrub(text.as_bytes(), secrets, limits)?)
        .map_err(|_| ScrubError::InvalidText)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_matches_original_leftmost_longest_across_all_chunk_boundaries() {
        let patterns = [("short", b"ab".as_slice()), ("long", b"abc".as_slice()),
            ("duplicate", b"abc".as_slice()), ("one", b"1".as_slice()),
            ("marker-word", b"secret".as_slice()), ("binary", &[0xff])];
        let input = b"abc ab 1 secret \xff abc";
        let expected = b"[secret:long] [secret:short] [secret:one] [secret:marker-word] [secret:binary] [secret:long]";
        assert_eq!(scrub(input, &patterns, limits(512)).unwrap(), expected);
        for chunk_bytes in 1..=input.len() {
            let mut stream = StreamScrubber::new(&patterns, limits(512), 512).unwrap();
            let mut result = Vec::new();
            for chunk in input.chunks(chunk_bytes) {
                result.extend_from_slice(stream.push(chunk).unwrap());
            }
            result.extend_from_slice(&stream.finish().unwrap());
            assert_eq!(result, expected, "chunk size {chunk_bytes}");
        }
    }

    #[test]
    fn stream_withholds_cross_window_matches_and_flushes_only_safe_tail() {
        let patterns = [("boundary", b"ABCD".as_slice()), ("tiny", b"x".as_slice())];
        let mut input = vec![b'q'; 65_535];
        input.extend_from_slice(b"ABCD-x-tail-ABC");
        let mut expected = vec![b'q'; 65_535];
        expected.extend_from_slice(b"[secret:boundary]-[secret:tiny]-tail-ABC");
        let mut stream = StreamScrubber::new(&patterns, limits(128 * 1024), 128 * 1024).unwrap();
        let mut result = Vec::new();
        for chunk in input.chunks(64 * 1024) {
            result.extend_from_slice(stream.push(chunk).unwrap());
        }
        result.extend_from_slice(&stream.finish().unwrap());
        assert_eq!(result, expected);
    }

    #[test]
    fn stream_handles_a_secret_longer_than_body_read_chunks() {
        let long = vec![b'a'; 3 * 64 * 1024 + 1];
        let mut input = long.clone();
        input.push(b'|');
        input.extend_from_slice(&long);
        input.push(b'|');
        input.extend_from_slice(&long);
        let patterns = [("short", b"a".as_slice()), ("long", long.as_slice())];
        let limits = ScrubLimits { output_bytes: 64, pattern_bytes: long.len() + 32 };
        let mut stream = StreamScrubber::new(&patterns, limits, 64).unwrap();
        let mut result = Vec::new();
        for chunk in input.chunks(64 * 1024) {
            result.extend_from_slice(stream.push(chunk).unwrap());
        }
        result.extend_from_slice(&stream.finish().unwrap());
        assert_eq!(result, b"[secret:long]|[secret:long]|[secret:long]");
    }

    #[test]
    fn stream_output_budget_is_cumulative_and_errors_stay_closed() {
        let patterns = [("one", b"x".as_slice())];
        let marker = b"[secret:one]";
        let count = 64 * 1024;
        let mut stream = StreamScrubber::new(&patterns, limits(count * marker.len()), count * marker.len()).unwrap();
        let output = stream.push(&vec![b'x'; count]).unwrap();
        assert!(output.chunks_exact(marker.len()).all(|part| part == marker));
        assert_eq!(output.len(), count * marker.len());
        assert!(stream.push(b"").unwrap().is_empty());
        stream.push(b"x").unwrap();
        assert_eq!(stream.finish(), Err(ScrubError::OutputLimit));

        let mut failed = StreamScrubber::new(&patterns, limits(1), 1).unwrap();
        assert_eq!(failed.push(&vec![b'x'; count]), Err(ScrubError::OutputLimit));
        assert_eq!(failed.push(b""), Err(ScrubError::OutputLimit));
        assert_eq!(failed.finish(), Err(ScrubError::OutputLimit));
        let empty = &[] as &[(&str, &[u8])];
        let mut plain = StreamScrubber::new(empty, limits(3), 3).unwrap();
        assert_eq!(plain.push(b"ab").unwrap(), b"ab");
        assert_eq!(plain.push(b"cd"), Err(ScrubError::OutputLimit));
        assert_eq!(plain.finish(), Err(ScrubError::OutputLimit));
    }

    #[test]
    fn compiled_matching_reports_literal_marker_matches_and_outlives_the_inventory() {
        let matcher = {
            let patterns = vec![(String::from("marker"), b"[secret:marker]".to_vec()),
                (String::from("one"), b"1".to_vec())];
            CompiledScrubber::new(&patterns, 128).unwrap().into_owned()
        };
        let matcher = std::sync::Arc::new(matcher);
        assert!(matcher.is_match(b"[secret:marker]"));
        assert!(!matcher.is_match(b"unchanged"));
        let callback: Box<dyn Fn(&[u8]) -> Result<Option<Vec<u8>>, ScrubError> + Send + Sync> =
            Box::new(move |bytes| matcher.scrub_if_matched(bytes, 128));
        assert_eq!(callback(b"unchanged").unwrap(), None);
        assert_eq!(callback(b"[secret:marker]").unwrap(), Some(b"[secret:marker]".to_vec()));
        assert_eq!(callback(b"1").unwrap(), Some(b"[secret:one]".to_vec()));
        assert_eq!(callback(b"1 [secret:marker]").unwrap(),
            Some(b"[secret:one] [secret:marker]".to_vec()));
        assert_eq!(callback(&[b'x'; 129]), Err(ScrubError::OutputLimit));
    }

    #[test]
    fn independent_fields_share_the_compiler_and_budget_not_raw_lookahead() {
        let patterns = [("cross", b"headerbody".as_slice()), ("one", b"x".as_slice())];
        let plan = CompiledScrubber::new(&patterns, 128).unwrap().into_owned();
        let total_budget = b"headerbody".len();
        assert_eq!(plan.scrub_if_matched(b"header", total_budget).unwrap(), None);
        let mut stream = StreamScrubber::from_compiled(plan,
            ScrubLimits { output_bytes: total_budget - b"header".len(), pattern_bytes: 128 }, total_budget).unwrap();
        assert!(stream.push(b"body").unwrap().is_empty());
        assert_eq!(stream.finish().unwrap(), b"body");

        let plan = CompiledScrubber::new(&patterns, 128).unwrap().into_owned();
        let total_budget = b"[secret:one]".len() + 1;
        let header = plan.scrub_if_matched(b"x", total_budget).unwrap().unwrap();
        let mut stream = StreamScrubber::from_compiled(plan,
            ScrubLimits { output_bytes: total_budget - header.len(), pattern_bytes: 128 }, total_budget).unwrap();
        stream.push(b"x").unwrap();
        assert_eq!(stream.finish(), Err(ScrubError::OutputLimit));

        let plan = CompiledScrubber::new(&patterns, 128).unwrap();
        assert_eq!(StreamScrubber::from_compiled(plan,
            ScrubLimits { output_bytes: 64, pattern_bytes: 1 }, 64).err(), Some(ScrubError::PatternLimit));
    }

    #[test]
    fn stream_memory_bound_rejects_expanded_windows_and_final_lookahead() {
        let long = vec![b'y'; 4096];
        let patterns = [("unused", long.as_slice()), ("short", b"x".as_slice())];
        let limits = ScrubLimits { output_bytes: usize::MAX, pattern_bytes: long.len() + 32 };
        let mut stream = StreamScrubber::new(&patterns, limits, 128).unwrap();
        assert!(stream.push(&vec![b'x'; 64 * 1024]).unwrap().is_empty());
        assert_eq!(stream.push(&vec![b'x'; 64 * 1024]), Err(ScrubError::OutputLimit));
        assert_eq!(stream.push(b""), Err(ScrubError::OutputLimit));
        assert_eq!(stream.finish(), Err(ScrubError::OutputLimit));
        let plan = CompiledScrubber::new(&patterns, limits.pattern_bytes).unwrap();
        let mut tail = StreamScrubber::from_compiled(plan, limits, 32).unwrap();
        assert!(tail.push(b"xxxxxxxx").unwrap().is_empty());
        assert_eq!(tail.finish(), Err(ScrubError::OutputLimit));
    }

    #[test]
    fn stream_total_body_can_exceed_its_reused_emission_buffer() {
        let patterns = &[] as &[(&str, &[u8])];
        let mut stream = StreamScrubber::new(patterns,
            ScrubLimits { output_bytes: usize::MAX, pattern_bytes: 0 }, 64 * 1024).unwrap();
        let input = vec![b'q'; 64 * 1024];
        let mut emitted = 0;
        for _ in 0..17 {
            assert_eq!(stream.push(&input).unwrap(), input);
            emitted += input.len();
        }
        assert!(emitted > 64 * 1024);
        assert!(stream.finish().unwrap().is_empty());
    }

    fn req(url: &str, headers: Vec<(&str, &str)>, body: &[u8]) -> pb::HttpEffectRequest {
        pb::HttpEffectRequest {
            method: "POST".into(),
            url: url.into(),
            headers: headers
                .into_iter()
                .map(|(n, v)| pb::HttpEffectHeader {
                    name: n.into(),
                    value: Some(pb::http_effect_header::Value::Text(v.into())),
                })
                .collect(),
            body: body.to_vec(),
            ..Default::default()
        }
    }

    #[test]
    fn fingerprint_normalizes_and_excludes() {
        let a = fingerprint(&req(
            "https://API.example.com:443/p?b=2&a=1",
            vec![("Date", "x"), ("X-A", "1")],
            b"{}",
        ))
        .unwrap();
        let b = fingerprint(&req(
            "https://api.example.com/p?a=1&b=2",
            vec![("x-a", "1"), ("user-agent", "y")],
            b"{}",
        ))
        .unwrap();
        assert_eq!(a, b);
        let c = fingerprint(&req(
            "https://api.example.com/p?a=1&b=2",
            vec![("x-a", "2")],
            b"{}",
        ))
        .unwrap();
        assert_ne!(a, c);
        let d = fingerprint(&req(
            "https://api.example.com/p?a=1&b=2",
            vec![("x-a", "1")],
            b"{ }",
        ))
        .unwrap();
        assert_ne!(a, d);
        assert!(parse_url("ftp://x").is_err());
        assert!(parse_url("https://user:pw@x.com/").is_err());
        assert_eq!(parse_url("http://h:8080").unwrap().port, Some(8080));
        assert_eq!(parse_url("http://h:80/a").unwrap().port, None);
    }

    #[test]
    fn secret_width_preserves_historical_fingerprint_inputs() {
        let request = |header: &str, version, hash: u8| {
            let mut secret = pb::SecretRef {
                name: "token".into(),
                template: "Bearer {}".into(),
                version_hash: vec![hash; 16],
                ..Default::default()
            };
            secret.set_resolved_version(version).unwrap();
            pb::HttpEffectRequest {
                method: "GET".into(),
                url: "https://example.com/".into(),
                headers: vec![pb::HttpEffectHeader {
                    name: header.into(),
                    value: Some(pb::http_effect_header::Value::Secret(secret)),
                }],
                body: Vec::new(),
                ..Default::default()
            }
        };
        let old = u64::from(u32::MAX);
        let wide = old + 1;
        // Authorization remains excluded even across a rotation and format boundary.
        assert_eq!(
            fingerprint(&request("Authorization", old, 1)).unwrap(),
            fingerprint(&request("Authorization", wide, 2)).unwrap(),
        );
        // Non-excluded secret headers keep the existing name/hash fingerprint;
        // neither wire-version field becomes a new fingerprint input.
        assert_eq!(
            fingerprint(&request("x-api-key", old, 1)).unwrap(),
            fingerprint(&request("x-api-key", wide, 1)).unwrap(),
        );
        assert_ne!(
            fingerprint(&request("x-api-key", old, 1)).unwrap(),
            fingerprint(&request("x-api-key", wide, 2)).unwrap(),
        );
    }

    #[test]
    fn route_patterns() {
        assert_eq!(route_pattern("/v1/charges/123"), "/v1/charges/{}");
        assert_eq!(
            route_pattern("/u/550e8400-e29b-41d4-a716-446655440000/x"),
            "/u/{}/x"
        );
        assert_eq!(route_pattern("/obj/deadbeefcafe"), "/obj/{}");
        assert_eq!(route_pattern("/ord/ab123456"), "/ord/{}");
        assert_eq!(route_pattern("/v2/users/me"), "/v2/users/me");
        assert_eq!(route_pattern("/"), "/");
    }

    fn limits(output_bytes: usize) -> ScrubLimits {
        ScrubLimits { output_bytes, pattern_bytes: 4096 }
    }

    #[test]
    fn scrubbing_preserves_inventory_order_and_never_rescans_markers() {
        let secrets = vec![
            ("current", b"sk_live_123".to_vec()),
            ("duplicate", b"sk_live_123".to_vec()),
            ("deleted", b"sk_live".to_vec()),
            ("word", b"secret".to_vec()),
            ("tiny", b"ab".to_vec()),
            ("flag", b"true".to_vec()),
        ];
        assert_eq!(
            scrub(b"sk_live_123 sk_live_9 secret ab true", &secrets, limits(4096)).unwrap(),
            b"[secret:current] [secret:deleted]_9 [secret:word] [secret:tiny] [secret:flag]"
        );
        assert_eq!(scrub(b"nothing", &secrets, limits(7)).unwrap(), b"nothing");
        let names = vec![("secret", b"secret".to_vec()), ("k", b"k".to_vec())];
        assert_eq!(scrub(b"secret k", &names, limits(64)).unwrap(), b"[secret:secret] [secret:k]");
    }

    #[test]
    fn every_nonempty_free_value_including_literals_utf8_and_binary_is_redacted() {
        for value in ["1", "ab", "true", "false", "null", "é"] {
            let secrets = vec![("value", value.as_bytes().to_vec())];
            assert_eq!(scrub_str(&format!("before {value} after"), &secrets, limits(64)).unwrap(),
                "before [secret:value] after");
        }
        let secrets = vec![("zero", vec![0]), ("binary", vec![255]),
            ("empty", Vec::new())];
        assert_eq!(scrub(&[0, 1, 255], &secrets, limits(64)).unwrap(),
            b"[secret:zero]\x01[secret:binary]");
        assert_eq!(scrub(b"", &secrets, limits(0)).unwrap(), b"");
        assert_eq!(scrub(b"abc", &[("empty", b"".as_slice())], limits(3)).unwrap(), b"abc");
    }

    #[test]
    fn overlaps_choose_leftmost_longest_original_value() {
        let secrets = vec![("short", b"ab".to_vec()), ("long", b"abc".to_vec()),
            ("later", b"bc".to_vec())];
        assert_eq!(scrub(b"abc ab bc", &secrets, limits(64)).unwrap(),
            b"[secret:long] [secret:short] [secret:later]");
    }

    #[test]
    fn output_limits_reject_expansion_without_partial_success() {
        let secrets = vec![("k", b"1".to_vec())];
        let marker = b"[secret:k]";
        assert_eq!(scrub(b"1", &secrets, limits(marker.len())).unwrap(), marker);
        assert_eq!(scrub(b"1", &secrets, limits(marker.len() - 1)), Err(ScrubError::OutputLimit));
        assert_eq!(scrub(b"1111111111111111", &secrets, limits(16)), Err(ScrubError::OutputLimit));
        assert_eq!(scrub(b"prefix 1 tail", &secrets, limits(17)), Err(ScrubError::OutputLimit));
        assert_eq!(scrub(b"abc", &[] as &[(&str, &[u8])], limits(2)), Err(ScrubError::OutputLimit));
        assert_eq!(scrub(&vec![b'1'; 65_536], &secrets, limits(1024)), Err(ScrubError::OutputLimit));
    }

    #[test]
    fn pattern_budget_and_diagnostics_never_expose_input_or_names() {
        let needle = "private-name-NEEDLE";
        let secrets = vec![(needle, b"1".to_vec())];
        let error = scrub(b"1", &secrets, ScrubLimits { output_bytes: 64, pattern_bytes: 1 }).unwrap_err();
        assert_eq!(error, ScrubError::PatternLimit);
        assert!(!error.to_string().contains(needle));
        let secrets = vec![(needle.repeat(100), b"1".to_vec())];
        assert_eq!(scrub(b"1", &secrets, limits(1)), Err(ScrubError::OutputLimit));
        let duplicate = vec![("first".into(), b"1".to_vec()), ("ignored-long-name".repeat(100), b"1".to_vec())];
        assert_eq!(scrub(b"1", &duplicate, ScrubLimits { output_bytes: 32, pattern_bytes: 6 }).unwrap(),
            b"[secret:first]");
    }

    #[test]
    fn text_does_not_expand_invalid_utf8_after_a_partial_binary_match() {
        let secret = vec![("byte", vec![0xa9])];
        assert_eq!(scrub_str("é", &secret, limits(64)), Err(ScrubError::InvalidText));
    }
}
