use super::*;
use crate::secret_backend::{Fetched, SecretBackend, VersionPage};
use kronik_core::env::BoxFuture;

pub(crate) struct Secrets {
    env: Env,
    config: OpenBao,
    session: tokio::sync::Mutex<Option<Session>>,
}

struct Reference<'a> {
    mount: &'a str,
    path: &'a str,
    field: &'a str,
}
impl<'a> Reference<'a> {
    fn parse(path: &'a str) -> Result<Self, BackendError> {
        let (resource, field) = path.split_once('#').ok_or(BackendError::Invalid)?;
        let (mount, path) = resource.split_once('/').ok_or(BackendError::Invalid)?;
        if resource.len() > 4096
            || !config::segment(mount)
            || !path.split('/').all(config::segment)
            || field.is_empty()
            || field.len() > 256
            || !field
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        {
            return Err(BackendError::Invalid);
        }
        Ok(Self { mount, path, field })
    }

    fn url(&self, config: &OpenBao, operation: &str) -> String {
        format!(
            "{}/v1/{}/{operation}/{}",
            config.address.trim_end_matches('/'),
            self.mount,
            self.path
        )
    }
}

impl Secrets {
    pub(crate) fn new(env: Env, config: OpenBao) -> Result<Self, BackendError> {
        config::endpoint(&config.address).map_err(|_| BackendError::Invalid)?;
        if config
            .auth_mount
            .as_ref()
            .is_some_and(|s| !config::segment(s))
            || config.role.as_ref().is_some_and(|s| !config::segment(s))
        {
            return Err(BackendError::Invalid);
        }
        let valid = match config.auth.as_str() {
            "token" => {
                config.token_file.is_some()
                    && config.role_id_file.is_none()
                    && config.secret_id_file.is_none()
                    && config.cert_file.is_none()
                    && config.key_file.is_none()
                    && config.role.is_none()
                    && config.auth_mount.is_none()
            }
            "approle" => {
                config.role_id_file.is_some()
                    && config.secret_id_file.is_some()
                    && config.token_file.is_none()
                    && config.cert_file.is_none()
                    && config.key_file.is_none()
                    && config.role.is_none()
            }
            "cert" => {
                config.cert_file.is_some()
                    && config.key_file.is_some()
                    && config.token_file.is_none()
                    && config.role_id_file.is_none()
                    && config.secret_id_file.is_none()
            }
            _ => false,
        };
        if !valid {
            return Err(BackendError::Invalid);
        }
        Ok(Self {
            env,
            config,
            session: tokio::sync::Mutex::new(None),
        })
    }

    async fn session(
        &self,
        original: &AuthLease,
    ) -> Result<(Env, Zeroizing<String>), BackendError> {
        let dispatch = Dispatch::Authorized(original);
        let mut cached = dispatch.wait(self.session.lock()).await?;
        let mut renewal_error = None;
        if let Some(session) = cached.as_mut() {
            if self.env.clock.monotonic() < session.renew_at {
                return Ok((session.env.clone(), session.token.clone()));
            }
            if session.renewable && self.env.clock.monotonic() < session.expires_at {
                let renewal = secret_request(
                    &session.env,
                    "POST",
                    format!(
                        "{}/v1/auth/token/renew-self",
                        self.config.address.trim_end_matches('/')
                    ),
                    vec![
                        ("X-Vault-Token".into(), session.token.to_string()),
                        ("content-type".into(), "application/json".into()),
                    ],
                    b"{}".to_vec(),
                    dispatch,
                )
                .await;
                match renewal {
                    Ok(r) => {
                        let (renew_at, expires_at, renewable) = lease(&self.env, &r["auth"])?;
                        let token = match r["auth"].get("client_token") {
                            Some(token) => {
                                let token = token.as_str().ok_or(BackendError::Invalid)?;
                                header_secret(token).map_err(|_| BackendError::Invalid)?;
                                Zeroizing::new(token.to_owned())
                            }
                            None => session.token.clone(),
                        };
                        original
                            .admit(&mut || {
                                session.token = token.clone();
                                session.renew_at = renew_at;
                                session.expires_at = expires_at;
                                session.renewable = renewable;
                                Ok(())
                            })
                            .map_err(|_| BackendError::Unauthorized)?;
                        return Ok((session.env.clone(), session.token.clone()));
                    }
                    Err(error) if self.config.auth == "token" => {
                        *cached = None;
                        return Err(error);
                    }
                    Err(error) => renewal_error = Some(error),
                }
            }
        }
        *cached = None;
        let mut session = login(&self.env, &self.config, dispatch)
            .await
            .map_err(|error| {
                if error == BackendError::Unavailable {
                    renewal_error.unwrap_or(error)
                } else {
                    error
                }
            })?;
        if self.config.auth == "token" {
            let r = secret_request(
                &session.env,
                "GET",
                format!(
                    "{}/v1/auth/token/lookup-self",
                    self.config.address.trim_end_matches('/')
                ),
                vec![("X-Vault-Token".into(), session.token.to_string())],
                vec![],
                dispatch,
            )
            .await?;
            (session.renew_at, session.expires_at, session.renewable) =
                lease(&self.env, &r["data"])?;
        } else if session.expires_at == Duration::ZERO {
            return Err(BackendError::Invalid);
        }
        let result = (session.env.clone(), session.token.clone());
        let mut session = Some(session);
        original
            .admit(&mut || {
                *cached = session.take();
                Ok(())
            })
            .map_err(|_| BackendError::Unauthorized)?;
        Ok(result)
    }

    async fn invalidate(&self, token: &str) {
        let mut cached = self.session.lock().await;
        if cached
            .as_ref()
            .is_some_and(|session| session.token.as_str() == token)
        {
            *cached = None;
        }
    }

    async fn read(&self, url: String, original: &AuthLease) -> Result<SecretJson, BackendError> {
        let (env, token) = self.session(original).await?;
        let result = secret_request(
            &env,
            "GET",
            url,
            vec![("X-Vault-Token".into(), token.to_string())],
            vec![],
            Dispatch::Authorized(original),
        )
        .await;
        if matches!(&result, Err(BackendError::Denied)) {
            self.invalidate(&token).await;
        }
        result
    }

    async fn get(
        &self,
        path: &str,
        id: Option<&str>,
        original: &AuthLease,
    ) -> Result<Fetched, BackendError> {
        let reference = Reference::parse(path)?;
        if id.is_some_and(|id| !config::positive_version(id)) {
            return Err(BackendError::Invalid);
        }
        let mut url = reference.url(&self.config, "data");
        if let Some(id) = id {
            url.push_str(&format!("?version={id}"));
        }
        let r = match self.read(url, original).await {
            Err(BackendError::NotFound) if id.is_some() => return Err(BackendError::VersionGone),
            result => result?,
        };
        fetched(path, &reference, id, &r)
    }
}

fn fetched(
    path: &str,
    reference: &Reference<'_>,
    id: Option<&str>,
    r: &Value,
) -> Result<Fetched, BackendError> {
    let metadata = &r["data"]["metadata"];
    let version = metadata["version"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or(BackendError::Invalid)?
        .to_string();
    if id.is_some_and(|id| id != version) {
        return Err(BackendError::Invalid);
    }
    let destroyed = metadata["destroyed"]
        .as_bool()
        .ok_or(BackendError::Invalid)?;
    metadata["deletion_time"]
        .as_str()
        .ok_or(BackendError::Invalid)?;
    // A future delete_version_after timestamp is still readable; HTTP 404 marks actual deletion.
    if destroyed {
        return Err(BackendError::VersionGone);
    }
    let value = r["data"]["data"]
        .get(reference.field)
        .ok_or(BackendError::NotFound)?
        .as_str()
        .ok_or(BackendError::Invalid)?;
    Ok(Fetched {
        value: Zeroizing::new(value.as_bytes().to_vec()),
        source_version: version,
        canonical_ref: path.to_owned(),
    })
}

fn catalogue(path: &str, r: &Value) -> Result<VersionPage, BackendError> {
    let data = &r["data"];
    let current = data["current_version"]
        .as_u64()
        .ok_or(BackendError::Invalid)?;
    let oldest = data["oldest_version"]
        .as_u64()
        .ok_or(BackendError::Invalid)?;
    let versions = data["versions"].as_object().ok_or(BackendError::Invalid)?;
    if (current == 0 && (!versions.is_empty() || oldest != 0))
        || (current > 0
            && (oldest > current || current - oldest.max(1) + 1 != versions.len() as u64))
    {
        return Err(BackendError::Invalid);
    }
    let mut ids = Vec::with_capacity(versions.len());
    for (id, version) in versions {
        if !config::positive_version(id) {
            return Err(BackendError::Invalid);
        }
        let number = id.parse::<u64>().map_err(|_| BackendError::Invalid)?;
        if number < oldest || number > current {
            return Err(BackendError::Invalid);
        }
        let destroyed = version["destroyed"]
            .as_bool()
            .ok_or(BackendError::Invalid)?;
        version["deletion_time"]
            .as_str()
            .ok_or(BackendError::Invalid)?;
        // Soft deletion is reversible: its retained value must not disappear from coverage.
        if !destroyed {
            ids.push(id.clone());
        }
    }
    Ok(VersionPage {
        canonical_ref: path.to_owned(),
        ids,
        next: None,
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
            let reference = Reference::parse(path)?;
            if cursor.is_some() {
                return Err(BackendError::Invalid);
            }
            let r = self
                .read(reference.url(&self.config, "metadata"), &original)
                .await?;
            catalogue(path, &r)
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
    async fn malformed_inputs_fail_before_authentication_or_network() {
        let mut env = Env::real(tokio::runtime::Handle::current());
        env.net = std::sync::Arc::new(NoNetwork);
        let backend = Secrets::new(
            env,
            OpenBao {
                address: "http://127.0.0.1:8200".into(),
                token_file: Some("/unread".into()),
                ..OpenBao::default()
            },
        )
        .unwrap();
        assert!(matches!(
            backend
                .current("secret/../escape#k", test_authority())
                .await,
            Err(BackendError::Invalid)
        ));
        assert!(matches!(
            backend.version("secret/a#k", "01", test_authority()).await,
            Err(BackendError::Invalid)
        ));
        assert!(matches!(
            backend
                .versions("secret/a#k", Some("https://evil"), test_authority())
                .await,
            Err(BackendError::Invalid)
        ));
    }

    struct ReadDenied;
    impl kronik_core::env::Net for ReadDenied {
        fn http_authorized(
            &self,
            request: HttpRequest,
            original: kronik_core::authority::AuthLease,
        ) -> BoxFuture<'static, Result<kronik_core::env::HttpResponse, kronik_core::env::NetError>>
        {
            assert_eq!(request.method, "GET");
            assert!(request.url.contains("/data/") || request.url.contains("/metadata/"));
            let mut response = None;
            let admitted = original.admit(&mut || {
                response = Some(kronik_core::env::HttpResponse {
                    status: 403,
                    headers: vec![],
                    body: Bytes::from_static(b"private-denial-body"),
                });
                Ok(())
            });
            Box::pin(std::future::ready(
                admitted
                    .map(|()| response.expect("denial response was not admitted"))
                    .map_err(|_| {
                        kronik_core::env::NetError::Connect("test provider authority ended".into())
                    }),
            ))
        }
        fn http(
            &self,
            request: HttpRequest,
        ) -> BoxFuture<'static, Result<kronik_core::env::HttpResponse, kronik_core::env::NetError>>
        {
            assert_eq!(request.method, "GET");
            assert!(request.url.contains("/data/") || request.url.contains("/metadata/"));
            Box::pin(async {
                Ok(kronik_core::env::HttpResponse {
                    status: 403,
                    headers: vec![],
                    body: Bytes::from_static(b"private-denial-body"),
                })
            })
        }
    }

    #[tokio::test]
    async fn read_denial_clears_only_the_session_that_authorized_the_request() {
        for metadata in [false, true] {
            let mut env = Env::real(tokio::runtime::Handle::current());
            env.net = std::sync::Arc::new(ReadDenied);
            let session = |token: &str| Session {
                env: env.clone(),
                token: Zeroizing::new(token.to_owned()),
                renew_at: Duration::MAX,
                expires_at: Duration::MAX,
                renewable: false,
            };
            let backend = Secrets {
                env: env.clone(),
                config: OpenBao {
                    address: "http://127.0.0.1:8200".into(),
                    ..OpenBao::default()
                },
                session: tokio::sync::Mutex::new(Some(session("old-token"))),
            };
            let error = if metadata {
                backend
                    .versions("secret/a#k", None, test_authority())
                    .await
                    .err()
            } else {
                backend.current("secret/a#k", test_authority()).await.err()
            };
            assert_eq!(error, Some(BackendError::Denied));
            assert!(backend.session.lock().await.is_none());
            *backend.session.lock().await = Some(session("replacement-token"));
            backend.invalidate("old-token").await;
            assert_eq!(
                backend
                    .session
                    .lock()
                    .await
                    .as_ref()
                    .unwrap()
                    .token
                    .as_str(),
                "replacement-token"
            );
            backend.invalidate("replacement-token").await;
            assert!(backend.session.lock().await.is_none());
        }
    }

    struct RenewalFailure(u16);
    impl kronik_core::env::Net for RenewalFailure {
        fn http_authorized(
            &self,
            request: HttpRequest,
            original: kronik_core::authority::AuthLease,
        ) -> BoxFuture<'static, Result<kronik_core::env::HttpResponse, kronik_core::env::NetError>>
        {
            assert!(request.url.ends_with("/v1/auth/token/renew-self"));
            let mut response = None;
            let admitted = original.admit(&mut || {
                response = Some(kronik_core::env::HttpResponse {
                    status: self.0,
                    headers: vec![],
                    body: Bytes::from_static(b"private-auth-body"),
                });
                Ok(())
            });
            Box::pin(std::future::ready(
                admitted
                    .map(|()| response.expect("renewal response was not admitted"))
                    .map_err(|_| {
                        kronik_core::env::NetError::Connect("test provider authority ended".into())
                    }),
            ))
        }
        fn http(
            &self,
            request: HttpRequest,
        ) -> BoxFuture<'static, Result<kronik_core::env::HttpResponse, kronik_core::env::NetError>>
        {
            assert!(request.url.ends_with("/v1/auth/token/renew-self"));
            let status = self.0;
            Box::pin(async move {
                Ok(kronik_core::env::HttpResponse {
                    status,
                    headers: vec![],
                    body: Bytes::from_static(b"private-auth-body"),
                })
            })
        }
    }

    #[tokio::test]
    async fn token_renewal_denial_is_not_an_availability_failure() {
        for (status, expected) in [
            (403, BackendError::Denied),
            (503, BackendError::Unavailable),
        ] {
            let mut env = Env::real(tokio::runtime::Handle::current());
            env.net = std::sync::Arc::new(RenewalFailure(status));
            let backend = Secrets {
                env: env.clone(),
                config: OpenBao {
                    address: "http://127.0.0.1:8200".into(),
                    ..OpenBao::default()
                },
                session: tokio::sync::Mutex::new(Some(Session {
                    env,
                    token: Zeroizing::new("memory-only-token".into()),
                    renew_at: Duration::ZERO,
                    expires_at: Duration::MAX,
                    renewable: true,
                })),
            };
            let error = backend
                .current("secret/a#k", test_authority())
                .await
                .err()
                .unwrap();
            assert_eq!(error, expected);
            assert!(!error.to_string().contains("private-auth-body"));
            assert!(backend.session.lock().await.is_none());
        }
    }

    #[tokio::test]
    async fn leases_use_env_time_and_never_turn_malformed_metadata_into_unlimited_auth() {
        let env = Env::real(tokio::runtime::Handle::current());
        let before = env.clock.monotonic();
        let (renew, expires, renewable) =
            lease(&env, &json!({"lease_duration":60,"renewable":true})).unwrap();
        assert!(renew >= before + Duration::from_secs(30));
        assert_eq!(expires - renew, Duration::from_secs(30));
        assert!(renewable);
        assert!(lease(&env, &json!({"renewable":true})).is_err());
        assert!(lease(&env, &json!({"lease_duration":60})).is_err());
        assert_eq!(
            lease(&env, &json!({"ttl":0,"renewable":false})).unwrap(),
            (Duration::MAX, Duration::MAX, false)
        );
    }

    #[test]
    fn references_cannot_reinterpret_the_configured_authority_or_api_path() {
        for path in [
            "secret/a%2fb#k",
            "secret/../a#k",
            "secret//a#k",
            "secret/a?version=3#k",
            "https://evil/a#k",
            "secret/a#k#other",
            "secret/a%252fb#k",
            "secret/a#",
        ] {
            assert!(Reference::parse(path).is_err());
        }
        assert!(Reference::parse("secret/team/service#password").is_ok());
    }

    #[test]
    fn immutable_versions_and_nonstring_values_are_not_substituted() {
        let path = "secret/service#password";
        let reference = Reference::parse(path).unwrap();
        let mut r = json!({"data":{"data":{"password":"retained"},
            "metadata":{"version":2,"destroyed":false,"deletion_time":""}}});
        assert!(matches!(
            fetched(path, &reference, Some("1"), &r),
            Err(BackendError::Invalid)
        ));
        r["data"]["metadata"]["deletion_time"] = json!("9999-01-01T00:00:00Z");
        assert_eq!(
            &*fetched(path, &reference, Some("2"), &r).unwrap().value,
            b"retained"
        );
        r["data"]["data"]["password"] = json!({"nested":"never stringify"});
        assert!(matches!(
            fetched(path, &reference, Some("2"), &r),
            Err(BackendError::Invalid)
        ));
        r["data"]["metadata"]["destroyed"] = json!(true);
        assert!(matches!(
            fetched(path, &reference, Some("2"), &r),
            Err(BackendError::VersionGone)
        ));
    }

    #[test]
    fn catalogue_keeps_soft_deleted_versions_and_rejects_holes() {
        let mut r = json!({"data":{"current_version":3,"oldest_version":0,"versions":{
            "1":{"destroyed":false,"deletion_time":"2026-01-01T00:00:00Z"},
            "2":{"destroyed":true,"deletion_time":""},
            "3":{"destroyed":false,"deletion_time":""}}}});
        let page = catalogue("secret/a#k", &r).unwrap();
        assert_eq!(page.ids, ["1", "3"]);
        r["data"]["versions"].as_object_mut().unwrap().remove("2");
        assert!(matches!(
            catalogue("secret/a#k", &r),
            Err(BackendError::Invalid)
        ));
    }
}
