use super::*;
use crate::secret_backend::{BackendError, Fetched, SecretBackend, VersionPage};
use kronik_core::env::BoxFuture;
use std::sync::Mutex;

const API_VERSION: &str = "7.4";

pub(crate) struct Secrets {
    env: Env,
    config: Azure,
    origins: Vec<String>,
    token: Mutex<Option<(Zeroizing<String>, Duration)>>,
}

fn vault_origin(url: &url::Url) -> Result<(), BackendError> {
    config::endpoint(&url.origin().ascii_serialization()).map_err(|_| BackendError::Invalid)?;
    let host = url.host_str().ok_or(BackendError::Invalid)?;
    let loopback = host == "localhost"
        || host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    let vault = host.strip_suffix(".vault.azure.net").is_some_and(|vault| {
        (3..=24).contains(&vault.len())
            && vault
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    });
    if !loopback && (!vault || url.port().is_some()) {
        return Err(BackendError::Invalid);
    }
    Ok(())
}

fn resource(path: &str) -> Result<url::Url, BackendError> {
    let url = url::Url::parse(path).map_err(|_| BackendError::Invalid)?;
    vault_origin(&url)?;
    let name = url
        .path()
        .strip_prefix("/secrets/")
        .ok_or(BackendError::Invalid)?;
    if url.as_str() != path
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || name.is_empty()
        || name.len() > 127
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(BackendError::Invalid);
    }
    Ok(url)
}

fn bound_resource(path: &str, origins: &[String]) -> Result<String, BackendError> {
    if origins.is_empty() {
        return Err(BackendError::Denied);
    }
    let parsed = resource(path)?;
    let origin = parsed.origin().ascii_serialization();
    let configured = origins
        .iter()
        .find(|configured| **configured == origin)
        .ok_or(BackendError::Invalid)?;
    Ok(format!("{configured}{}", parsed.path()))
}

fn immutable(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn source_version<'a>(path: &str, returned: &'a str) -> Result<&'a str, BackendError> {
    returned
        .strip_prefix(path)
        .and_then(|s| s.strip_prefix('/'))
        .filter(|id| immutable(id))
        .ok_or(BackendError::Invalid)
}

fn enabled(response: &Value) -> Result<(), BackendError> {
    if response.get("recoveryId").is_some() || response.get("deletedDate").is_some() {
        return Err(BackendError::VersionGone);
    }
    match response
        .get("attributes")
        .and_then(|a| a.get("enabled"))
        .and_then(Value::as_bool)
    {
        Some(true) => Ok(()),
        Some(false) => Err(BackendError::Denied),
        None => Err(BackendError::Invalid),
    }
}

fn page_token(token: &str) -> Result<(), BackendError> {
    if token.is_empty() || token.len() > CAP || token.bytes().any(|b| b.is_ascii_control()) {
        return Err(BackendError::Invalid);
    }
    Ok(())
}

fn list_url(path: &str, cursor: Option<&str>) -> Result<String, BackendError> {
    resource(path)?;
    let mut url =
        url::Url::parse(&format!("{path}/versions")).map_err(|_| BackendError::Invalid)?;
    url.query_pairs_mut()
        .append_pair("api-version", API_VERSION)
        .append_pair("maxresults", "25");
    if let Some(cursor) = cursor {
        page_token(cursor)?;
        url.query_pairs_mut().append_pair("$skiptoken", cursor);
    }
    Ok(url.into())
}

fn next_token(path: &str, link: &str) -> Result<String, BackendError> {
    if link.len() > CAP {
        return Err(BackendError::Invalid);
    }
    let trusted = resource(path)?;
    let url = url::Url::parse(link).map_err(|_| BackendError::Invalid)?;
    if url.as_str() != link
        || url.origin() != trusted.origin()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.path() != format!("{}/versions", trusted.path())
    {
        return Err(BackendError::Invalid);
    }
    let mut api = false;
    let mut limit = false;
    let mut token = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "api-version" if !api && value == API_VERSION => api = true,
            "maxresults" if !limit && value == "25" => limit = true,
            "$skiptoken" if token.is_none() => {
                page_token(&value)?;
                token = Some(value.into_owned());
            }
            _ => return Err(BackendError::Invalid),
        }
    }
    if !api {
        return Err(BackendError::Invalid);
    }
    token.ok_or(BackendError::Invalid)
}

fn fetched(path: &str, expected: Option<&str>, response: &Value) -> Result<Fetched, BackendError> {
    let returned = field(response, "id").map_err(|_| BackendError::Invalid)?;
    let id = source_version(path, returned)?;
    if expected.is_some_and(|expected| id != expected) {
        return Err(BackendError::Invalid);
    }
    enabled(response)?;
    let value = response
        .get("value")
        .and_then(Value::as_str)
        .ok_or(BackendError::Invalid)?;
    if value.len() > SECRET_RESPONSE_CAP {
        return Err(BackendError::Invalid);
    }
    Ok(Fetched {
        value: Zeroizing::new(value.as_bytes().to_vec()),
        source_version: id.into(),
        canonical_ref: path.into(),
    })
}

fn version_page(
    path: &str,
    cursor: Option<&str>,
    response: &Value,
) -> Result<VersionPage, BackendError> {
    let versions = response
        .get("value")
        .and_then(Value::as_array)
        .ok_or(BackendError::Invalid)?;
    let mut ids = Vec::with_capacity(versions.len());
    let mut seen = std::collections::BTreeSet::new();
    for version in versions {
        let id = source_version(
            path,
            field(version, "id").map_err(|_| BackendError::Invalid)?,
        )?;
        enabled(version)?;
        if !seen.insert(id) {
            return Err(BackendError::Invalid);
        }
        ids.push(id.into());
    }
    let next = match response.get("nextLink") {
        None | Some(Value::Null) => None,
        Some(Value::String(link)) if link.is_empty() => None,
        Some(Value::String(link)) => {
            let token = next_token(path, link)?;
            if Some(token.as_str()) == cursor {
                return Err(BackendError::Invalid);
            }
            Some(token)
        }
        _ => return Err(BackendError::Invalid),
    };
    Ok(VersionPage {
        canonical_ref: path.into(),
        ids,
        next,
    })
}

impl Secrets {
    pub(crate) fn new(
        env: Env,
        config: Azure,
        trusted_origins: Vec<String>,
    ) -> Result<Self, BackendError> {
        for origin in &trusted_origins {
            let parsed = config::endpoint(origin).map_err(|_| BackendError::Invalid)?;
            vault_origin(&parsed)?;
            if parsed.origin().ascii_serialization() != *origin {
                return Err(BackendError::Invalid);
            }
        }
        if config.client_secret_file.is_some() {
            if !config.tenant_id.as_deref().is_some_and(config::segment)
                || !config.client_id.as_deref().is_some_and(config::segment)
            {
                return Err(BackendError::Invalid);
            }
        } else if config.tenant_id.is_some()
            || config
                .client_id
                .as_deref()
                .is_some_and(|id| !config::segment(id))
        {
            return Err(BackendError::Invalid);
        }
        if let Some(endpoint) = &config.authority_endpoint {
            config::local_auth_endpoint(endpoint, true).map_err(|_| BackendError::Invalid)?;
        }
        if let Some(endpoint) = &config.metadata_endpoint {
            config::local_auth_endpoint(endpoint, false).map_err(|_| BackendError::Invalid)?;
        }
        Ok(Self {
            env,
            config,
            origins: trusted_origins,
            token: Mutex::new(None),
        })
    }

    async fn token(
        &self,
        net: &Env,
        original: &AuthLease,
    ) -> Result<Zeroizing<String>, BackendError> {
        original.check().map_err(|_| BackendError::Unauthorized)?;
        let now = self.env.clock.monotonic();
        {
            let cache = self.token.lock().map_err(|_| BackendError::Invalid)?;
            if let Some((token, expires)) = &*cache
                && now < *expires
            {
                return Ok(Zeroizing::new(token.to_string()));
            }
        }
        let response = auth_response(net, &self.config, Dispatch::Authorized(original)).await?;
        let token = field(&response, "access_token").map_err(|_| BackendError::Invalid)?;
        header_secret(token).map_err(|_| BackendError::Invalid)?;
        let lifetime = response.get("expires_in").ok_or(BackendError::Invalid)?;
        let seconds = lifetime
            .as_u64()
            .or_else(|| lifetime.as_str().and_then(|s| s.parse::<u64>().ok()))
            .filter(|seconds| *seconds > 0)
            .ok_or(BackendError::Invalid)?;
        let expires = now
            .checked_add(Duration::from_secs(seconds.saturating_sub(30)))
            .ok_or(BackendError::Invalid)?;
        let mut cache = self.token.lock().map_err(|_| BackendError::Invalid)?;
        original
            .admit(&mut || {
                *cache = Some((Zeroizing::new(token.to_owned()), expires));
                Ok(())
            })
            .map_err(|_| BackendError::Denied)?;
        Ok(Zeroizing::new(token.to_owned()))
    }

    async fn get(&self, url: String, original: &AuthLease) -> Result<SecretJson, BackendError> {
        let dispatch = Dispatch::Authorized(original);
        let net = dispatch
            .wait(tls_env(
                &self.env,
                self.config.ca_file.as_deref(),
                None,
                dispatch,
            ))
            .await?
            .map_err(|_| BackendError::Invalid)?;
        let token = self.token(&net, original).await?;
        let result = secret_request(
            &net,
            "GET",
            url,
            bearer(&token).map_err(|_| BackendError::Invalid)?,
            vec![],
            dispatch,
        )
        .await;
        if matches!(result, Err(BackendError::Denied)) {
            *self.token.lock().map_err(|_| BackendError::Invalid)? = None;
        }
        result
    }

    async fn access(
        &self,
        path: &str,
        id: Option<&str>,
        original: &AuthLease,
    ) -> Result<Fetched, BackendError> {
        let path = bound_resource(path, &self.origins)?;
        if id.is_some_and(|id| !immutable(id)) {
            return Err(BackendError::Invalid);
        }
        let target = match id {
            Some(id) => format!("{path}/{id}?api-version={API_VERSION}"),
            None => format!("{path}?api-version={API_VERSION}"),
        };
        let response = match self.get(target, original).await {
            Err(BackendError::NotFound) if id.is_some() => return Err(BackendError::VersionGone),
            other => other?,
        };
        fetched(&path, id, &response)
    }
}

impl SecretBackend for Secrets {
    fn current<'a>(
        &'a self,
        path: &'a str,
        original: AuthLease,
    ) -> BoxFuture<'a, Result<Fetched, BackendError>> {
        Box::pin(async move { self.access(path, None, &original).await })
    }
    fn version<'a>(
        &'a self,
        path: &'a str,
        id: &'a str,
        original: AuthLease,
    ) -> BoxFuture<'a, Result<Fetched, BackendError>> {
        Box::pin(async move { self.access(path, Some(id), &original).await })
    }
    fn versions<'a>(
        &'a self,
        path: &'a str,
        cursor: Option<&'a str>,
        original: AuthLease,
    ) -> BoxFuture<'a, Result<VersionPage, BackendError>> {
        Box::pin(async move {
            let path = bound_resource(path, &self.origins)?;
            let url = list_url(&path, cursor)?;
            let response = self.get(url, &original).await?;
            version_page(&path, cursor, &response)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PATH: &str = "https://vault.vault.azure.net/secrets/password";
    const ID: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn references_cannot_select_an_unconfigured_vault() {
        let origins = vec!["https://vault.vault.azure.net".to_owned()];
        assert_eq!(bound_resource(PATH, &origins).unwrap(), PATH);
        assert!(bound_resource("https://evil.vault.azure.net/secrets/password", &origins).is_err());
        assert!(bound_resource("http://127.0.0.1:1234/secrets/password", &origins).is_err());
        assert_eq!(bound_resource(PATH, &[]).unwrap_err(), BackendError::Denied);
        let emulator = vec!["http://127.0.0.1:1234".to_owned()];
        assert!(bound_resource("http://127.0.0.1:1234/secrets/password", &emulator).is_ok());
        assert!(bound_resource("http://127.0.0.1:1235/secrets/password", &emulator).is_err());
    }

    #[tokio::test]
    async fn empty_origins_deny_all_operations_before_network() {
        struct NoNetwork;
        impl kronik_core::env::Net for NoNetwork {
            fn http_authorized(
                &self,
                _: HttpRequest,
                _: kronik_core::authority::AuthLease,
            ) -> BoxFuture<
                'static,
                Result<kronik_core::env::HttpResponse, kronik_core::env::NetError>,
            > {
                panic!("deny-all backend attempted authorized network access")
            }
            fn http(
                &self,
                _: HttpRequest,
            ) -> BoxFuture<
                'static,
                Result<kronik_core::env::HttpResponse, kronik_core::env::NetError>,
            > {
                panic!("deny-all backend attempted network access");
            }
        }
        let mut env = Env::real(tokio::runtime::Handle::current());
        env.net = std::sync::Arc::new(NoNetwork);
        let backend = Secrets::new(env, Azure::default(), vec![]).unwrap();
        assert!(matches!(
            backend.current(PATH, test_authority()).await,
            Err(BackendError::Denied)
        ));
        assert!(matches!(
            backend.current("invalid reference", test_authority()).await,
            Err(BackendError::Denied)
        ));
        assert!(matches!(
            backend.version(PATH, ID, test_authority()).await,
            Err(BackendError::Denied)
        ));
        assert!(matches!(
            backend
                .versions(PATH, Some("cursor"), test_authority())
                .await,
            Err(BackendError::Denied)
        ));
    }

    #[test]
    fn forged_resource_version_and_disabled_values_fail_closed() {
        for returned in [
            format!("https://evil.vault.azure.net/secrets/password/{ID}"),
            format!("{PATH}2/{ID}"),
            format!("{PATH}/{ID}?api-version=7.4"),
            format!("{PATH}/latest"),
        ] {
            assert!(matches!(
                fetched(
                    PATH,
                    None,
                    &json!({"id":returned,"value":"x","attributes":{"enabled":true}})
                ),
                Err(BackendError::Invalid)
            ));
        }
        let mut response =
            json!({"id":format!("{PATH}/{ID}"),"value":"x","attributes":{"enabled":true}});
        assert!(matches!(
            fetched(PATH, Some("ffffffffffffffffffffffffffffffff"), &response),
            Err(BackendError::Invalid)
        ));
        assert_eq!(
            fetched(PATH, Some(ID), &response).unwrap().value.as_slice(),
            b"x"
        );
        response["attributes"]["enabled"] = json!(false);
        assert!(matches!(
            fetched(PATH, None, &response),
            Err(BackendError::Denied)
        ));
        for bad in [
            "https://evil/secrets/password",
            "http://vault.vault.azure.net/secrets/password",
            "https://vault.vault.azure.net/secrets/a/../password",
            "https://vault.vault.azure.net/secrets/a%2fb",
        ] {
            assert!(resource(bad).is_err());
        }
        assert!(resource("http://127.0.0.1:1234/secrets/password").is_ok());
    }

    #[test]
    fn next_links_cannot_choose_authority_path_or_api() {
        for link in [
            "https://evil.vault.azure.net/secrets/password/versions?api-version=7.4&$skiptoken=x",
            "http://vault.vault.azure.net/secrets/password/versions?api-version=7.4&$skiptoken=x",
            "https://vault.vault.azure.net/secrets/other/versions?api-version=7.4&$skiptoken=x",
            "https://vault.vault.azure.net/secrets/password/x/../versions?api-version=7.4&$skiptoken=x",
            "https://vault.vault.azure.net/secrets/password/versions?api-version=7.5&$skiptoken=x",
            "https://vault.vault.azure.net/secrets/password/versions?api-version=7.4&api-version=7.4&$skiptoken=x",
            "https://vault.vault.azure.net/secrets/password/versions?api-version=7.4&$skiptoken=x&$skiptoken=y",
            "https://vault.vault.azure.net/secrets/password/versions?api-version=7.4&$skiptoken=x#fragment",
            "https://vault.vault.azure.net/secrets/password/versions?api-version=7.4&$skiptoken=",
        ] {
            assert!(next_token(PATH, link).is_err());
        }
        let link = format!("{PATH}/versions?api-version=7.4&$skiptoken=a%2Fb%2B%3D&maxresults=25");
        let token = next_token(PATH, &link).unwrap();
        assert_eq!(token, "a/b+=");
        let rebuilt = list_url(PATH, Some(&token)).unwrap();
        assert_eq!(next_token(PATH, &rebuilt).unwrap(), token);
        assert!(page_token(&"x".repeat(CAP + 1)).is_err());
    }

    #[test]
    fn catalogue_cannot_hide_unreadable_versions_or_repeat_cursor() {
        let mut response =
            json!({"value":[{"id":format!("{PATH}/{ID}"),"attributes":{"enabled":false}}]});
        assert_eq!(
            version_page(PATH, None, &response).unwrap_err(),
            BackendError::Denied
        );
        response["value"][0]["attributes"]["enabled"] = json!(true);
        response["value"][0]["deletedDate"] = json!(1);
        assert_eq!(
            version_page(PATH, None, &response).unwrap_err(),
            BackendError::VersionGone
        );
        assert!(version_page(PATH, None, &json!({})).is_err());
        assert!(version_page(PATH, Some("x"), &json!({"value":[],"nextLink":format!("{PATH}/versions?api-version=7.4&$skiptoken=x")})).is_err());
        assert!(
            version_page(PATH, None, &json!({"value":[]}))
                .unwrap()
                .ids
                .is_empty()
        );
    }
}
