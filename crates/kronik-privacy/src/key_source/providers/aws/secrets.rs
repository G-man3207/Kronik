use super::*;
use crate::secret_backend::{Fetched, SecretBackend, VersionPage};
use kronik_core::env::BoxFuture;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

pub(crate) struct Secrets {
    env: Env,
    config: Aws,
    bindings: Mutex<BTreeMap<String, String>>,
}

struct Reference<'a> {
    resource: &'a str,
    field: Option<&'a str>,
}
fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'+' | b'=' | b'.' | b'@' | b'-')
        })
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}
fn arn<'a>(value: &'a str, region: &str) -> Result<&'a str, BackendError> {
    let parts: Vec<_> = value.splitn(7, ':').collect();
    let partition = if region.starts_with("cn-") {
        "aws-cn"
    } else if region.starts_with("us-gov-") {
        "aws-us-gov"
    } else {
        "aws"
    };
    if parts.len() != 7
        || parts[0] != "arn"
        || parts[1] != partition
        || parts[2] != "secretsmanager"
        || parts[3] != region
        || parts[4].len() != 12
        || !parts[4].bytes().all(|b| b.is_ascii_digit())
        || parts[5] != "secret"
    {
        return Err(BackendError::Invalid);
    }
    let (resource, suffix) = parts[6].rsplit_once('-').ok_or(BackendError::Invalid)?;
    if !name(resource) || suffix.len() != 6 || !suffix.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(BackendError::Invalid);
    }
    Ok(resource)
}
impl<'a> Reference<'a> {
    fn parse(path: &'a str, region: &str) -> Result<Self, BackendError> {
        let (resource, field) = match path.split_once('#') {
            Some((resource, field)) => {
                if field.is_empty()
                    || field.len() > 256
                    || !field
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
                {
                    return Err(BackendError::Invalid);
                }
                (resource, Some(field))
            }
            None => (path, None),
        };
        if resource.starts_with("arn:") {
            arn(resource, region)?;
        } else if !name(resource) {
            return Err(BackendError::Invalid);
        }
        Ok(Self { resource, field })
    }
    fn canonical(&self, resource: &str) -> String {
        match self.field {
            Some(field) => format!("{resource}#{field}"),
            None => resource.to_owned(),
        }
    }
    fn identity(&self, region: &str, response: &Value) -> Result<String, BackendError> {
        let returned_arn = field(response, "ARN").map_err(|_| BackendError::Invalid)?;
        let returned_name = field(response, "Name").map_err(|_| BackendError::Invalid)?;
        if arn(returned_arn, region)? != returned_name
            || (self.resource.starts_with("arn:") && self.resource != returned_arn)
            || (!self.resource.starts_with("arn:") && self.resource != returned_name)
        {
            return Err(BackendError::Invalid);
        }
        Ok(self.canonical(returned_arn))
    }
}

fn version_id(id: &str) -> bool {
    (32..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
fn page_token(token: &str) -> bool {
    !token.is_empty() && token.len() <= 4096 && token.bytes().all(|b| (0x21..=0x7e).contains(&b))
}
fn cursor(resource: &str, token: &str) -> Result<String, BackendError> {
    if !page_token(token) {
        return Err(BackendError::Invalid);
    }
    let json = serde_json::to_vec(&(resource, token)).map_err(|_| BackendError::Invalid)?;
    Ok(URL_SAFE_NO_PAD.encode(json))
}
fn continuation(cursor: &str, expected: &str) -> Result<String, BackendError> {
    if cursor.len() > 16384 {
        return Err(BackendError::Invalid);
    }
    let bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(cursor)
            .map_err(|_| BackendError::Invalid)?,
    );
    if URL_SAFE_NO_PAD.encode(&bytes) != cursor {
        return Err(BackendError::Invalid);
    }
    let value = SecretJson(serde_json::from_slice(&bytes).map_err(|_| BackendError::Invalid)?);
    let fields = value
        .as_array()
        .filter(|v| v.len() == 2)
        .ok_or(BackendError::Invalid)?;
    let resource = fields[0].as_str().ok_or(BackendError::Invalid)?;
    let token = fields[1]
        .as_str()
        .filter(|s| page_token(s))
        .ok_or(BackendError::Invalid)?;
    if resource != expected {
        return Err(BackendError::Invalid);
    }
    Ok(token.to_owned())
}

fn response(status: u16, bytes: &[u8]) -> Result<SecretJson, BackendError> {
    if (200..=299).contains(&status) {
        return serde_json::from_slice(bytes)
            .map(SecretJson)
            .map_err(|_| BackendError::Invalid);
    }
    // AWS JSON APIs use HTTP 400 even for denied or missing immutable versions.
    if status == 400 {
        let value = SecretJson(serde_json::from_slice(bytes).map_err(|_| BackendError::Invalid)?);
        let code = value
            .get("__type")
            .or_else(|| value.get("code"))
            .and_then(Value::as_str)
            .ok_or(BackendError::Invalid)?;
        return Err(match code.rsplit(['#', ':']).next().unwrap_or("") {
            "AccessDeniedException"
            | "NotAuthorizedException"
            | "UnrecognizedClientException"
            | "InvalidClientTokenId"
            | "ExpiredTokenException"
            | "InvalidSignatureException"
            | "SignatureDoesNotMatch"
            | "DecryptionFailure" => BackendError::Denied,
            "ResourceNotFoundException" => BackendError::NotFound,
            "ThrottlingException"
            | "TooManyRequestsException"
            | "InternalServiceError"
            | "InternalServiceErrorException"
            | "ServiceUnavailableException" => BackendError::Unavailable,
            _ => BackendError::Invalid,
        });
    }
    http_status(status)?;
    Err(BackendError::Invalid)
}

impl Secrets {
    pub(crate) fn new(env: Env, config: Aws) -> Result<Self, BackendError> {
        if !config::segment(&config.region)
            || !matches!(config.auth.as_str(), "auto" | "env" | "imds")
            || unsupported_source().is_some()
        {
            return Err(BackendError::Invalid);
        }
        if let Some(endpoint) = &config.endpoint {
            config::endpoint(endpoint).map_err(|_| BackendError::Invalid)?;
        }
        if let Some(endpoint) = &config.imds_endpoint {
            config::local_auth_endpoint(endpoint, true).map_err(|_| BackendError::Invalid)?;
        }
        Ok(Self {
            env,
            config,
            bindings: Mutex::new(BTreeMap::new()),
        })
    }

    fn bound(&self, path: &str, reference: &Reference<'_>) -> Result<String, BackendError> {
        let bindings = self.bindings.lock().map_err(|_| BackendError::Invalid)?;
        Ok(bindings
            .get(path)
            .cloned()
            .unwrap_or_else(|| reference.canonical(reference.resource)))
    }

    fn bind(&self, path: &str, canonical: &str) -> Result<(), BackendError> {
        let mut bindings = self.bindings.lock().map_err(|_| BackendError::Invalid)?;
        if let Some(previous) = bindings.get(path) {
            if previous != canonical {
                return Err(BackendError::Invalid);
            }
        } else {
            bindings.insert(path.to_owned(), canonical.to_owned());
        }
        Ok(())
    }

    async fn request(
        &self,
        operation: &str,
        value: SecretJson,
        original: &AuthLease,
    ) -> Result<SecretJson, BackendError> {
        let dispatch = Dispatch::Authorized(original);
        let env = dispatch
            .wait(tls_env(
                &self.env,
                self.config.ca_file.as_deref(),
                None,
                dispatch,
            ))
            .await?
            .map_err(|_| BackendError::Invalid)?;
        let credentials = credentials(&env, &self.config, dispatch).await?;
        let domain = if self.config.region.starts_with("cn-") {
            "amazonaws.com.cn"
        } else {
            "amazonaws.com"
        };
        let default = format!("https://secretsmanager.{}.{domain}", self.config.region);
        let url = config::endpoint(self.config.endpoint.as_deref().unwrap_or(&default))
            .map_err(|_| BackendError::Invalid)?;
        let host = url.host_str().ok_or(BackendError::Invalid)?;
        let host = match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_owned(),
        };
        let date = sigv4::timestamp(env.clock.wall_ms()).map_err(|_| BackendError::Invalid)?;
        let mut headers = vec![
            ("host".into(), host),
            ("x-amz-date".into(), date.clone()),
            ("x-amz-target".into(), format!("secretsmanager.{operation}")),
            ("content-type".into(), "application/x-amz-json-1.1".into()),
        ];
        if let Some(token) = &credentials.token {
            headers.push(("x-amz-security-token".into(), token.to_string()));
        }
        let mut body =
            Zeroizing::new(serde_json::to_vec(&value.0).map_err(|_| BackendError::Invalid)?);
        let authorization = sigv4::authorization(
            "POST",
            "/",
            "",
            &headers,
            &body,
            &credentials.access,
            &credentials.secret,
            &self.config.region,
            "secretsmanager",
            &date,
        )
        .map_err(|_| BackendError::Invalid)?;
        headers.push(("authorization".into(), authorization));
        let (status, bytes) = request_raw(
            &env,
            "POST",
            url.to_string(),
            headers,
            std::mem::take(&mut *body),
            SECRET_RESPONSE_CAP,
            dispatch,
        )
        .await?;
        response(status, &bytes)
    }

    async fn get(
        &self,
        path: &str,
        id: Option<&str>,
        original: &AuthLease,
    ) -> Result<Fetched, BackendError> {
        let reference = Reference::parse(path, &self.config.region)?;
        if id.is_some_and(|id| !version_id(id)) {
            return Err(BackendError::Invalid);
        }
        let bound = self.bound(path, &reference)?;
        let pinned = Reference::parse(&bound, &self.config.region)?;
        let mut body = SecretJson(json!({"SecretId":pinned.resource}));
        if let Some(id) = id {
            body.0["VersionId"] = json!(id);
        }
        let result = self.request("GetSecretValue", body, original).await;
        let r = match result {
            Err(BackendError::NotFound) if id.is_some() => return Err(BackendError::VersionGone),
            result => result?,
        };
        let fetched = fetched(&pinned, &self.config.region, id, &r)?;
        self.bind(path, &fetched.canonical_ref)?;
        Ok(fetched)
    }
}

fn fetched(
    reference: &Reference<'_>,
    region: &str,
    id: Option<&str>,
    response: &Value,
) -> Result<Fetched, BackendError> {
    let canonical_ref = reference.identity(region, response)?;
    let source_version = field(response, "VersionId").map_err(|_| BackendError::Invalid)?;
    if !version_id(source_version) || id.is_some_and(|id| id != source_version) {
        return Err(BackendError::Invalid);
    }
    let mut value = match (response.get("SecretString"), response.get("SecretBinary")) {
        (Some(Value::String(s)), None) => Zeroizing::new(s.as_bytes().to_vec()),
        (None, Some(Value::String(s))) => {
            // Secrets Manager limits decoded binary values to 64 KiB; failures wipe partial output.
            if s.len() % 4 != 0 || s.len() > 87_384 {
                return Err(BackendError::Invalid);
            }
            let padding = if s.ends_with("==") {
                2
            } else if s.ends_with('=') {
                1
            } else {
                0
            };
            let size = s.len() / 4 * 3 - padding;
            if size > 65_536 {
                return Err(BackendError::Invalid);
            }
            let mut value = Zeroizing::new(vec![0; size]);
            let decoded = STANDARD
                .decode_slice(s, &mut value)
                .map_err(|_| BackendError::Invalid)?;
            if decoded != size {
                return Err(BackendError::Invalid);
            }
            let encoded = Zeroizing::new(STANDARD.encode(&value));
            if encoded.as_str() != s {
                return Err(BackendError::Invalid);
            }
            value
        }
        _ => return Err(BackendError::Invalid),
    };
    if let Some(key) = reference.field {
        // JSON field selection is defined only for SecretString, never binary or objects.
        if response.get("SecretString").is_none() {
            return Err(BackendError::Invalid);
        }
        let json = SecretJson(serde_json::from_slice(&value).map_err(|_| BackendError::Invalid)?);
        let selected = json
            .get(key)
            .ok_or(BackendError::NotFound)?
            .as_str()
            .ok_or(BackendError::Invalid)?;
        value = Zeroizing::new(selected.as_bytes().to_vec());
    }
    Ok(Fetched {
        value,
        source_version: source_version.to_owned(),
        canonical_ref,
    })
}

fn catalogue(
    reference: &Reference<'_>,
    region: &str,
    r: &Value,
    prior: Option<&str>,
) -> Result<VersionPage, BackendError> {
    let canonical_ref = reference.identity(region, r)?;
    let entries = r["Versions"]
        .as_array()
        .filter(|v| v.len() <= 100)
        .ok_or(BackendError::Invalid)?;
    let mut seen = BTreeSet::new();
    let mut ids = Vec::with_capacity(entries.len());
    for entry in entries {
        let id = field(entry, "VersionId").map_err(|_| BackendError::Invalid)?;
        if !version_id(id) || !seen.insert(id) {
            return Err(BackendError::Invalid);
        }
        ids.push(id.to_owned());
    }
    let next = match r.get("NextToken") {
        None => None,
        Some(Value::String(token)) if prior != Some(token.as_str()) => {
            Some(cursor(&canonical_ref, token)?)
        }
        _ => return Err(BackendError::Invalid),
    };
    Ok(VersionPage {
        canonical_ref,
        ids,
        next,
    })
}

impl SecretBackend for Secrets {
    fn current<'a>(
        &'a self,
        path: &'a str,
        original: AuthLease,
    ) -> BoxFuture<'a, Result<Fetched, BackendError>> {
        Box::pin(async move { self.get(path, None, &original).await })
    }
    fn version<'a>(
        &'a self,
        path: &'a str,
        id: &'a str,
        original: AuthLease,
    ) -> BoxFuture<'a, Result<Fetched, BackendError>> {
        Box::pin(async move { self.get(path, Some(id), &original).await })
    }
    fn versions<'a>(
        &'a self,
        path: &'a str,
        cursor: Option<&'a str>,
        original: AuthLease,
    ) -> BoxFuture<'a, Result<VersionPage, BackendError>> {
        Box::pin(async move {
            let reference = Reference::parse(path, &self.config.region)?;
            let bound = self.bound(path, &reference)?;
            let pinned = Reference::parse(&bound, &self.config.region)?;
            let token = cursor
                .map(|cursor| continuation(cursor, &bound))
                .transpose()?;
            let mut body = SecretJson(
                json!({"SecretId":pinned.resource,"IncludeDeprecated":true,"MaxResults":100}),
            );
            if let Some(token) = &token {
                body.0["NextToken"] = json!(token);
            }
            let r = self
                .request("ListSecretVersionIds", body, &original)
                .await?;
            let page = catalogue(&pinned, &self.config.region, &r, token.as_deref())?;
            self.bind(path, &page.canonical_ref)?;
            Ok(page)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoNetwork;
    impl kronik_core::env::Net for NoNetwork {
        fn http_authorized(
            &self,
            _: HttpRequest,
            _: kronik_core::authority::AuthLease,
        ) -> BoxFuture<'static, Result<kronik_core::env::HttpResponse, kronik_core::env::NetError>>
        {
            panic!("malformed local identity must not initiate authorized provider I/O")
        }
        fn http(
            &self,
            _: HttpRequest,
        ) -> BoxFuture<'static, Result<kronik_core::env::HttpResponse, kronik_core::env::NetError>>
        {
            panic!("malformed local identity must not initiate provider I/O");
        }
    }

    #[tokio::test]
    async fn malformed_references_versions_and_cursors_never_authenticate() {
        let mut env = Env::real(tokio::runtime::Handle::current());
        env.net = std::sync::Arc::new(NoNetwork);
        let backend = Secrets {
            env,
            config: Aws {
                region: "us-east-1".into(),
                ..Aws::default()
            },
            bindings: Mutex::new(BTreeMap::new()),
        };
        assert!(matches!(
            backend
                .current("https://evil/secret", test_authority())
                .await,
            Err(BackendError::Invalid)
        ));
        assert!(matches!(
            backend.version(ARN, "../version", test_authority()).await,
            Err(BackendError::Invalid)
        ));
        let wrong_resource = cursor(&format!("{ARN}#other"), "opaque").unwrap();
        assert!(matches!(
            backend
                .versions(ARN, Some(&wrong_resource), test_authority())
                .await,
            Err(BackendError::Invalid)
        ));
        assert!(matches!(
            backend
                .versions(ARN, Some("https://evil"), test_authority())
                .await,
            Err(BackendError::Invalid)
        ));
    }
    const ARN: &str = "arn:aws:secretsmanager:us-east-1:123456789012:secret:team/service-Ab12Cd";
    const VERSION: &str = "11111111-1111-1111-1111-111111111111";

    #[test]
    fn canonical_identity_rejects_other_names_accounts_regions_and_versions() {
        let reference = Reference::parse(ARN, "us-east-1").unwrap();
        let mut response =
            json!({"ARN":ARN,"Name":"team/service","VersionId":VERSION,"SecretString":"value"});
        response["ARN"] = json!(ARN.replace("123456789012", "999999999999"));
        assert!(matches!(
            fetched(&reference, "us-east-1", Some(VERSION), &response),
            Err(BackendError::Invalid)
        ));
        response["ARN"] = json!(ARN);
        response["VersionId"] = json!("22222222-2222-2222-2222-222222222222");
        assert!(matches!(
            fetched(&reference, "us-east-1", Some(VERSION), &response),
            Err(BackendError::Invalid)
        ));
        assert!(Reference::parse(&ARN.replace("us-east-1", "eu-west-1"), "us-east-1").is_err());
        let short = Reference::parse("team/other", "us-east-1").unwrap();
        assert!(short.identity("us-east-1", &response).is_err());
    }

    #[test]
    fn values_require_an_unambiguous_representation_and_string_selection() {
        let reference = Reference::parse(ARN, "us-east-1").unwrap();
        let mut r =
            json!({"ARN":ARN,"Name":"team/service","VersionId":VERSION,"SecretBinary":"Zg=="});
        assert_eq!(
            &*fetched(&reference, "us-east-1", None, &r).unwrap().value,
            b"f"
        );
        r["SecretBinary"] = json!("Zh==");
        assert!(fetched(&reference, "us-east-1", None, &r).is_err());
        r["SecretString"] = json!("{}");
        assert!(fetched(&reference, "us-east-1", None, &r).is_err());
        r.as_object_mut().unwrap().remove("SecretBinary");
        r["SecretString"] = json!(r#"{"password":{"nested":"secret"}}"#);
        let selected_path = format!("{ARN}#password");
        let selected = Reference::parse(&selected_path, "us-east-1").unwrap();
        assert!(fetched(&selected, "us-east-1", None, &r).is_err());
    }

    #[test]
    fn binary_decode_rejects_oversized_output_and_a_malformed_final_quantum() {
        let reference = Reference::parse(ARN, "us-east-1").unwrap();
        let mut r = json!({"ARN":ARN,"Name":"team/service","VersionId":VERSION,
            "SecretBinary":STANDARD.encode(vec![7; 65_537])});
        assert!(matches!(
            fetched(&reference, "us-east-1", None, &r),
            Err(BackendError::Invalid)
        ));
        r["SecretBinary"] = json!("c2VjcmV0LXByZWZpeC1wYXJ0aWFsLW91dHB1dA=?");
        assert!(matches!(
            fetched(&reference, "us-east-1", None, &r),
            Err(BackendError::Invalid)
        ));
    }

    #[test]
    fn pagination_cannot_change_identity_hide_duplicates_or_repeat_a_cursor() {
        let reference = Reference::parse(ARN, "us-east-1").unwrap();
        let mut r = json!({"ARN":ARN,"Name":"team/service","Versions":[{"VersionId":VERSION}],"NextToken":"opaque"});
        let page = catalogue(&reference, "us-east-1", &r, None).unwrap();
        assert!(continuation(page.next.as_deref().unwrap(), &format!("{ARN}#other")).is_err());
        assert!(catalogue(&reference, "us-east-1", &r, Some("opaque")).is_err());
        r["Versions"]
            .as_array_mut()
            .unwrap()
            .push(json!({"VersionId":VERSION}));
        assert!(catalogue(&reference, "us-east-1", &r, None).is_err());
        for malformed in ["https://evil/?secret=value", "../token", ""] {
            assert!(continuation(malformed, ARN).is_err());
        }
    }

    #[test]
    fn authorization_is_never_stale_eligible_and_errors_do_not_disclose_bodies() {
        for (status, code, expected) in [
            (400, "AccessDeniedException", BackendError::Denied),
            (400, "ExpiredTokenException", BackendError::Denied),
            (400, "ResourceNotFoundException", BackendError::NotFound),
            (400, "ThrottlingException", BackendError::Unavailable),
            (403, "secret-error", BackendError::Denied),
            (503, "secret-error", BackendError::Unavailable),
        ] {
            let body =
                serde_json::to_vec(&json!({"__type":code,"Message":"private-provider-body"}))
                    .unwrap();
            let error = response(status, &body).err().unwrap();
            assert_eq!(error, expected);
            assert!(!error.to_string().contains("private-provider-body"));
        }
    }
}
