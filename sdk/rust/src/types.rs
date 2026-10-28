//! Constructors and accessors for the WIT types.

use std::fmt;
use std::str::FromStr;

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::{
    ActorRef, Error, HandlerError, Header, HttpBody, HttpRequest, HttpResponse, Manifest, Message,
    Output, Route,
};

impl Manifest {
    /// A manifest for actor type `kind` at `schema_version`, without routes
    /// or capabilities. Raise the schema version when [`Actor::migrate`]
    /// gains a step.
    ///
    /// [`Actor::migrate`]: crate::Actor::migrate
    pub fn new(kind: impl Into<String>, schema_version: u32) -> Self {
        Manifest {
            kind: kind.into(),
            schema_version,
            routes: Vec::new(),
            capabilities: Vec::new(),
        }
    }

    /// Adds an HTTP route that the gateway sends to this actor type.
    pub fn route(mut self, route: Route) -> Self {
        self.routes.push(route);
        self
    }

    /// Adds a capability the actor type asks for, such as
    /// `http:api.example.com` (see `kronik explain capability`). Deploy
    /// warns about capabilities that are not granted yet.
    pub fn capability(mut self, capability: impl Into<String>) -> Self {
        self.capabilities.push(capability.into());
        self
    }
}

impl Route {
    /// A route for `method` and `pattern`. A pattern segment `{name}`
    /// matches one path segment and becomes a parameter; `{key}` names the
    /// actor's key, and a route without it targets the actor `kind/_`.
    pub fn new(method: impl Into<String>, pattern: impl Into<String>) -> Self {
        Route {
            method: method.into(),
            pattern: pattern.into(),
        }
    }

    /// A `GET` route.
    pub fn get(pattern: impl Into<String>) -> Self {
        Route::new("GET", pattern)
    }

    /// A `POST` route.
    pub fn post(pattern: impl Into<String>) -> Self {
        Route::new("POST", pattern)
    }

    /// A `PUT` route.
    pub fn put(pattern: impl Into<String>) -> Self {
        Route::new("PUT", pattern)
    }

    /// A `PATCH` route.
    pub fn patch(pattern: impl Into<String>) -> Self {
        Route::new("PATCH", pattern)
    }

    /// A `DELETE` route.
    pub fn delete(pattern: impl Into<String>) -> Self {
        Route::new("DELETE", pattern)
    }
}

impl Output {
    /// No output. An HTTP request gets `204 No Content`.
    pub fn none() -> Self {
        Output::None
    }

    /// A reply message. An HTTP request gets `200` with the message's body
    /// and content type.
    pub fn reply(message: Message) -> Self {
        Output::Reply(message)
    }

    /// An HTTP response.
    pub fn http(response: HttpResponse) -> Self {
        Output::Http(response)
    }

    /// An HTTP response with status `status` and `value` as a JSON body.
    ///
    /// # Panics
    ///
    /// If `value` cannot be serialized, which fails the turn: for example a
    /// map with keys that are not strings. [`Output::try_json`] returns the
    /// error instead.
    pub fn json<T: Serialize + ?Sized>(status: u16, value: &T) -> Self {
        match Output::try_json(status, value) {
            Ok(output) => output,
            Err(e) => panic!("Output::json: {e}"),
        }
    }

    /// Like [`Output::json`], but returns the serialization error.
    pub fn try_json<T: Serialize + ?Sized>(status: u16, value: &T) -> Result<Self, Error> {
        let body = to_json(value, "the response body", "message")?;
        Ok(Output::Http(
            HttpResponse::new(status)
                .header("content-type", "application/json")
                .body(body),
        ))
    }

    /// An HTTP response with status `status` and a plain text body.
    pub fn text(status: u16, body: impl Into<String>) -> Self {
        Output::Http(
            HttpResponse::new(status)
                .header("content-type", "text/plain; charset=utf-8")
                .body(body.into()),
        )
    }

    /// An HTTP response with status `status` and no body, such as `404`.
    pub fn status(status: u16) -> Self {
        Output::Http(HttpResponse::new(status))
    }
}

impl HttpResponse {
    /// A response with status `status`, no headers and an empty body.
    pub fn new(status: u16) -> Self {
        HttpResponse {
            status,
            headers: Vec::new(),
            body: HttpBody::Inline(Vec::new()),
        }
    }

    /// Adds a header.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push(Header {
            name: name.into(),
            value: value.into(),
        });
        self
    }

    /// Sets the body.
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = HttpBody::Inline(body.into());
        self
    }
}

impl HttpRequest {
    /// The value of the route parameter `name`, such as `key` for a route
    /// `/notes/{key}`.
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// The first query parameter called `name`, percent-decoded (`+` is a
    /// space): `query_param("after")` is `Some("7")` for `?after=7&limit=10`.
    /// `None` if it is missing or not UTF-8 after decoding.
    pub fn query_param(&self, name: &str) -> Option<String> {
        self.query
            .split('&')
            .map(|pair| pair.split_once('=').unwrap_or((pair, "")))
            .find(|(n, _)| percent_decode(n).as_deref() == Some(name))
            .and_then(|(_, v)| percent_decode(v))
    }

    /// The first header called `name`, ignoring ASCII case.
    pub fn header(&self, name: &str) -> Option<&str> {
        find_header(self.headers.iter().map(|h| (&h.name, &h.value)), name)
    }

    /// The body's bytes. Bodies are inline up to M25; a blob body gives an
    /// empty slice.
    pub fn body_bytes(&self) -> &[u8] {
        inline_bytes(&self.body)
    }

    /// The body as UTF-8 text.
    pub fn text(&self) -> Result<&str, Error> {
        utf8(self.body_bytes(), "the request body", "message")
    }

    /// The body parsed as JSON.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T, Error> {
        from_json(self.body_bytes(), "the request body", "message")
    }
}

impl Message {
    /// A message called `name` with any content type and body.
    pub fn new(
        name: impl Into<String>,
        content_type: impl Into<String>,
        body: impl Into<Vec<u8>>,
    ) -> Self {
        Message {
            name: name.into(),
            content_type: content_type.into(),
            body: body.into(),
            blobs: Vec::new(),
        }
    }

    /// A message with a plain text body.
    pub fn text(name: impl Into<String>, text: impl Into<String>) -> Self {
        Message::new(name, "text/plain; charset=utf-8", text.into())
    }

    /// A message with `value` as a JSON body.
    pub fn json<T: Serialize + ?Sized>(name: impl Into<String>, value: &T) -> Result<Self, Error> {
        Ok(Message::new(
            name,
            "application/json",
            to_json(value, "the message body", "message")?,
        ))
    }

    /// The body as UTF-8 text.
    pub fn body_text(&self) -> Result<&str, Error> {
        utf8(&self.body, "the message body", "message")
    }

    /// The body parsed as JSON.
    pub fn body_json<T: DeserializeOwned>(&self) -> Result<T, Error> {
        from_json(&self.body, "the message body", "message")
    }
}

impl ActorRef {
    /// The actor `kind/key`.
    pub fn new(kind: impl Into<String>, key: impl Into<String>) -> Self {
        ActorRef {
            kind: kind.into(),
            key: key.into(),
        }
    }
}

impl fmt::Display for ActorRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.kind, self.key)
    }
}

impl FromStr for ActorRef {
    type Err = String;

    /// Parses `kind/key`. The key may contain further slashes.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once('/') {
            Some((kind, key)) if !kind.is_empty() && !key.is_empty() => {
                Ok(ActorRef::new(kind, key))
            }
            _ => Err(format!(
                "{s:?} is not an actor: expected kind/key (see `kronik explain actor`)"
            )),
        }
    }
}

impl HandlerError {
    /// The actor refuses the input, for example because it is invalid. The
    /// turn fails and its writes are discarded.
    pub fn rejected(message: impl Into<String>) -> Self {
        HandlerError::Rejected(message.into())
    }

    /// The actor could not handle the input. The turn fails and its writes
    /// are discarded.
    pub fn failed(message: impl Into<String>) -> Self {
        HandlerError::Failed(message.into())
    }
}

impl From<serde_json::Error> for HandlerError {
    fn from(error: serde_json::Error) -> Self {
        HandlerError::Failed(format!(
            "JSON error: {error} (see `kronik explain message`)"
        ))
    }
}

/// Decodes `%XX` escapes and `+` (a space) in a query string component.
/// Malformed escapes stay as they are; `None` if the result is not UTF-8.
fn percent_decode(s: &str) -> Option<String> {
    let hex = |b: Option<&u8>| b.and_then(|&b| char::from(b).to_digit(16));
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        i += 1;
        match b {
            b'+' => out.push(b' '),
            b'%' => match (hex(bytes.get(i)), hex(bytes.get(i + 1))) {
                (Some(high), Some(low)) => {
                    // Two hex digits make at most 0xff.
                    out.push((high * 16 + low) as u8);
                    i += 2;
                }
                _ => out.push(b'%'),
            },
            b => out.push(b),
        }
    }
    String::from_utf8(out).ok()
}

pub(crate) fn inline_bytes(body: &HttpBody) -> &[u8] {
    match body {
        HttpBody::Inline(bytes) => bytes,
        HttpBody::Blob(_) => &[],
    }
}

pub(crate) fn find_header<'a>(
    mut headers: impl Iterator<Item = (&'a String, &'a String)>,
    name: &str,
) -> Option<&'a str> {
    headers
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

pub(crate) fn utf8<'a>(bytes: &'a [u8], what: &str, topic: &'static str) -> Result<&'a str, Error> {
    std::str::from_utf8(bytes).map_err(|_| Error::Utf8 {
        what: what.to_string(),
        topic,
    })
}

pub(crate) fn from_json<T: DeserializeOwned>(
    bytes: &[u8],
    what: &str,
    topic: &'static str,
) -> Result<T, Error> {
    serde_json::from_slice(bytes).map_err(|source| Error::Json {
        what: what.to_string(),
        topic,
        source,
    })
}

pub(crate) fn to_json<T: Serialize + ?Sized>(
    value: &T,
    what: &str,
    topic: &'static str,
) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(value).map_err(|source| Error::Json {
        what: what.to_string(),
        topic,
        source,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn manifest_builder() {
        let m = Manifest::new("notes", 2)
            .route(Route::post("/notes/{key}"))
            .route(Route::get("/notes/{key}/{id}"))
            .capability("http:api.example.com");
        assert_eq!(m.kind, "notes");
        assert_eq!(m.schema_version, 2);
        let routes: Vec<_> = m
            .routes
            .iter()
            .map(|r| (r.method.as_str(), r.pattern.as_str()))
            .collect();
        assert_eq!(
            routes,
            [("POST", "/notes/{key}"), ("GET", "/notes/{key}/{id}")]
        );
        assert_eq!(m.capabilities, ["http:api.example.com"]);
    }

    #[test]
    fn json_output_is_an_http_response() {
        let Output::Http(r) = Output::json(201, &serde_json::json!({ "n": 1 })) else {
            panic!("not an HTTP response");
        };
        assert_eq!(r.status, 201);
        assert_eq!(r.headers[0].name, "content-type");
        assert_eq!(r.headers[0].value, "application/json");
        assert_eq!(inline_bytes(&r.body), br#"{"n":1}"#);
    }

    #[test]
    fn json_output_reports_unserializable_values() {
        let map: BTreeMap<Vec<u8>, u8> = BTreeMap::from([(vec![1], 1)]);
        let e = Output::try_json(200, &map).err().map(|e| e.to_string());
        assert_eq!(
            e.as_deref(),
            Some(
                "the response body is not the expected JSON: key must be a string (see `kronik explain message`)"
            )
        );
    }

    #[test]
    fn request_accessors() {
        let req = HttpRequest {
            method: "POST".into(),
            path: "/notes/alice/7".into(),
            query: String::new(),
            params: vec![("key".into(), "alice".into()), ("id".into(), "7".into())],
            headers: vec![Header {
                name: "Content-Type".into(),
                value: "application/json".into(),
            }],
            body: HttpBody::Inline(br#"{"title":"t"}"#.to_vec()),
        };
        assert_eq!(req.param("id"), Some("7"));
        assert_eq!(req.param("nope"), None);
        assert_eq!(req.header("content-type"), Some("application/json"));
        let v: serde_json::Value = req.json().ok().unwrap_or_default();
        assert_eq!(v["title"], "t");
        assert_eq!(req.text().ok(), Some(r#"{"title":"t"}"#));

        let q = |query: &str, name: &str| {
            HttpRequest {
                query: query.into(),
                ..req.clone()
            }
            .query_param(name)
        };
        assert_eq!(q("after=7&limit=10", "limit").as_deref(), Some("10"));
        assert_eq!(q("after=7&limit=10", "before"), None);
        assert_eq!(q("q=a+b%2Fc&flag", "q").as_deref(), Some("a b/c"));
        assert_eq!(q("q=a+b%2Fc&flag", "flag").as_deref(), Some(""));
        assert_eq!(q("q=100%25&x=%zz%4", "q").as_deref(), Some("100%"));
        assert_eq!(q("q=100%25&x=%zz%4", "x").as_deref(), Some("%zz%4"));
        assert_eq!(q("q=%ff", "q"), None);
        assert_eq!(q("", "q"), None);
    }

    #[test]
    fn messages_and_actor_refs() {
        let m = Message::text("hello", "world");
        assert_eq!(m.content_type, "text/plain; charset=utf-8");
        assert_eq!(m.body_text().ok(), Some("world"));
        let bad = Message::new("x", "application/octet-stream", vec![0xff]);
        assert_eq!(
            bad.body_text().err().map(|e| e.to_string()).as_deref(),
            Some("the message body is not UTF-8 (see `kronik explain message`)")
        );
        let a: ActorRef = "notes/user/1".parse().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!((a.kind.as_str(), a.key.as_str()), ("notes", "user/1"));
        assert_eq!(a.to_string(), "notes/user/1");
        assert!("notes".parse::<ActorRef>().is_err());
    }
}
