//! `ctx.http()`: outgoing HTTP requests, recorded as effects.

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::BlobRef;
use crate::Error;
use crate::HttpBody;
use crate::bindings::kronik::actor::http_client::{
    self, HeaderValue, RequestHeader, SecretTemplate,
};
use crate::types::{blob_of, find_header, from_json, inline_bytes, inline_only, to_json, utf8};

pub use crate::bindings::kronik::actor::http_client::{FetchError, Request, Response};

/// Outgoing HTTP (see `kronik explain effect`).
///
/// A request needs the capability `http:<host>` for the actor type (see
/// `kronik explain capability`); without it the request is denied. Every
/// request is recorded with its response, so a replay gets the same answer,
/// and carries an `Idempotency-Key` derived from the turn.
pub struct Http {
    _private: (),
}

impl Http {
    pub(crate) fn new() -> Self {
        Http { _private: () }
    }

    /// Sends `request` and waits for the response. The URL may be
    /// `https://...` or, for a foreign actor, `foreign://<name>/...`.
    pub fn fetch(&self, request: &Request) -> Result<Response, Error> {
        http_client::fetch(request).map_err(Error::Fetch)
    }
}

/// A handle to a secret: its name, never its value (see
/// `kronik explain secret-handle`).
///
/// The host inserts the value at the effect boundary, in a request header
/// ([`Request::secret_header`]) or in a crypto operation
/// ([`Ctx::crypto`](crate::Ctx::crypto)); it never enters the guest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Secret {
    name: String,
}

impl Secret {
    pub(crate) fn new(name: String) -> Self {
        Secret { name }
    }

    /// The secret's name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Request {
    /// A request with `method` to `url`, without headers or body.
    pub fn new(method: impl Into<String>, url: impl Into<String>) -> Self {
        Request {
            method: method.into(),
            url: url.into(),
            headers: Vec::new(),
            body: HttpBody::Inline(Vec::new()),
        }
    }

    /// A `GET` request.
    pub fn get(url: impl Into<String>) -> Self {
        Request::new("GET", url)
    }

    /// A `POST` request.
    pub fn post(url: impl Into<String>) -> Self {
        Request::new("POST", url)
    }

    /// A `PUT` request.
    pub fn put(url: impl Into<String>) -> Self {
        Request::new("PUT", url)
    }

    /// A `PATCH` request.
    pub fn patch(url: impl Into<String>) -> Self {
        Request::new("PATCH", url)
    }

    /// A `DELETE` request.
    pub fn delete(url: impl Into<String>) -> Self {
        Request::new("DELETE", url)
    }

    /// Adds a header.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push(RequestHeader {
            name: name.into(),
            value: HeaderValue::Text(value.into()),
        });
        self
    }

    /// Adds a header whose value the host makes from a secret: `{}` in
    /// `template` is replaced by the secret's value, as in
    /// `.secret_header("authorization", &ctx.secret("stripe"), "Bearer {}")`.
    /// Needs the capability `secret:<name>`.
    pub fn secret_header(
        mut self,
        name: impl Into<String>,
        secret: &Secret,
        template: impl Into<String>,
    ) -> Self {
        self.headers.push(RequestHeader {
            name: name.into(),
            value: HeaderValue::Secret(SecretTemplate {
                name: secret.name.clone(),
                template: template.into(),
            }),
        });
        self
    }

    /// Sets the body.
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = HttpBody::Inline(body.into());
        self
    }

    /// Sets a blob the turn holds as the body (M25): the host streams it to
    /// the target from the blob store.
    pub fn body_blob(mut self, blob: &BlobRef) -> Self {
        self.body = HttpBody::Blob(blob.clone());
        self
    }

    /// Sets `value` as a JSON body and the `content-type` header.
    pub fn json<T: Serialize + ?Sized>(self, value: &T) -> Result<Self, Error> {
        let body = to_json(value, "the request body", "effect")?;
        Ok(self.header("content-type", "application/json").body(body))
    }
}

impl Response {
    /// Whether the status is 2xx.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// The first header called `name`, ignoring ASCII case.
    pub fn header(&self, name: &str) -> Option<&str> {
        find_header(self.headers.iter().map(|(n, v)| (n, v)), name)
    }

    /// The body's bytes when it is inline; a blob body (above the actor
    /// type's blob threshold, M25) gives an empty slice: see
    /// [`Response::blob`] and [`Response::read_body`].
    pub fn body_bytes(&self) -> &[u8] {
        inline_bytes(&self.body)
    }

    /// The body's blob, when the response is one (M25).
    pub fn blob(&self) -> Option<&BlobRef> {
        blob_of(&self.body)
    }

    /// The whole body, inline or blob; a blob is read into memory.
    pub fn read_body(&self) -> Result<Vec<u8>, Error> {
        crate::types::read_body(&self.body)
    }

    /// The body as UTF-8 text; `Error::BlobBody` for a blob body.
    pub fn text(&self) -> Result<&str, Error> {
        utf8(
            inline_only(&self.body, "the response body")?,
            "the response body",
            "effect",
        )
    }

    /// The body parsed as JSON; `Error::BlobBody` for a blob body.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T, Error> {
        from_json(
            inline_only(&self.body, "the response body")?,
            "the response body",
            "effect",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_builder() {
        let secret = Secret::new("stripe".into());
        let req = Request::post("https://api.example.com/v1/charges")
            .header("accept", "application/json")
            .secret_header("authorization", &secret, "Bearer {}")
            .json(&serde_json::json!({ "amount": 100 }))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(req.method, "POST");
        let headers: Vec<String> = req
            .headers
            .iter()
            .map(|h| match &h.value {
                HeaderValue::Text(v) => format!("{}: {v}", h.name),
                HeaderValue::Secret(s) => format!("{}: <{} as {}>", h.name, s.name, s.template),
            })
            .collect();
        assert_eq!(
            headers,
            [
                "accept: application/json",
                "authorization: <stripe as Bearer {}>",
                "content-type: application/json",
            ]
        );
        assert_eq!(inline_bytes(&req.body), br#"{"amount":100}"#);
    }

    /// M25: a blob body is never read as text by accident; `read_body`
    /// and the blob API read it.
    #[test]
    fn blob_bodies() {
        let blob = BlobRef {
            hash: format!("b3:{}", "ab".repeat(32)),
            size: 3_000_000,
        };
        let req = Request::post("https://api.example.com/files").body_blob(&blob);
        assert!(
            matches!(&req.body, HttpBody::Blob(b) if b.hash == blob.hash && b.size == blob.size)
        );
        let res = Response {
            status: 200,
            headers: Vec::new(),
            body: HttpBody::Blob(blob.clone()),
        };
        assert_eq!(
            res.blob().map(|b| (b.hash.as_str(), b.size)),
            Some((blob.hash.as_str(), blob.size))
        );
        assert!(res.body_bytes().is_empty());
        let e = res.text().err().map(|e| e.to_string()).unwrap_or_default();
        assert!(e.contains("is a blob of 3000000 bytes"), "{e}");
        assert!(e.contains("kronik explain blob"), "{e}");
        assert!(matches!(
            res.json::<serde_json::Value>(),
            Err(Error::BlobBody {
                size: 3_000_000,
                ..
            })
        ));
        let out = crate::HttpResponse::blob(200, &blob, "application/pdf");
        assert!(matches!(&out.body, HttpBody::Blob(b) if b.hash == blob.hash));
        assert_eq!(out.headers[0].value, "application/pdf");
    }

    #[test]
    fn response_accessors() {
        let res = Response {
            status: 201,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: HttpBody::Inline(br#"{"id":"ch_1"}"#.to_vec()),
        };
        assert!(res.is_success());
        assert_eq!(res.header("content-type"), Some("application/json"));
        let v: serde_json::Value = res.json().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(v["id"], "ch_1");
    }
}
