use super::*;
use crate::secret_backend::{BackendError, Fetched, SecretBackend, VersionPage};
use kronik_core::env::BoxFuture;
use std::sync::Mutex;

pub(crate) struct Secrets {
    env: Env,
    config: Gcp,
    base: String,
    token: Mutex<Option<(Zeroizing<String>, Duration)>>,
}

fn resource(path: &str) -> Result<(), BackendError> {
    let mut parts = path.split('/');
    let project = parts.next() == Some("projects");
    let valid = |s: &str| {
        !s.is_empty()
            && s.len() <= 255
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    };
    if !project
        || !parts.next().is_some_and(valid)
        || parts.next() != Some("secrets")
        || !parts.next().is_some_and(valid)
        || parts.next().is_some()
    {
        return Err(BackendError::Invalid);
    }
    Ok(())
}

fn source_version<'a>(path: &str, name: &'a str) -> Result<&'a str, BackendError> {
    let id = name
        .strip_prefix(path)
        .and_then(|s| s.strip_prefix("/versions/"))
        .filter(|s| config::positive_version(s))
        .ok_or(BackendError::Invalid)?;
    Ok(id)
}

fn page_token(value: &str) -> Result<(), BackendError> {
    if value.is_empty() || value.len() > CAP || value.bytes().any(|b| b.is_ascii_control()) {
        return Err(BackendError::Invalid);
    }
    Ok(())
}

fn fetched(path: &str, expected: Option<&str>, response: &Value) -> Result<Fetched, BackendError> {
    let name = field(response, "name").map_err(|_| BackendError::Invalid)?;
    let id = source_version(path, name)?;
    if expected.is_some_and(|expected| expected != id) {
        return Err(BackendError::Invalid);
    }
    let encoded = response
        .get("payload")
        .and_then(|p| p.get("data"))
        .and_then(Value::as_str)
        .ok_or(BackendError::Invalid)?;
    // Secret Manager limits an individual value to 64 KiB; cap before decoding too.
    if encoded.len() > 65_536_usize.div_ceil(3) * 4 {
        return Err(BackendError::Invalid);
    }
    let mut value = Zeroizing::new(vec![0; encoded.len() / 4 * 3 + 3]);
    let len = STANDARD
        .decode_slice(encoded, &mut value)
        .map_err(|_| BackendError::Invalid)?;
    if len > 65_536 {
        return Err(BackendError::Invalid);
    }
    value.truncate(len);
    Ok(Fetched {
        value,
        source_version: id.into(),
        canonical_ref: path.into(),
    })
}

fn version_page(
    path: &str,
    cursor: Option<&str>,
    response: &Value,
) -> Result<VersionPage, BackendError> {
    let mut ids = Vec::new();
    if let Some(versions) = response.get("versions") {
        let versions = versions.as_array().ok_or(BackendError::Invalid)?;
        let mut seen = std::collections::BTreeSet::new();
        for version in versions {
            let name = field(version, "name").map_err(|_| BackendError::Invalid)?;
            let id = source_version(path, name)?;
            match version.get("state").and_then(Value::as_str) {
                Some("ENABLED") => {}
                Some("DISABLED") => return Err(BackendError::Denied),
                // Destroyed metadata is a tombstone; required observed IDs remain in the resolver registry.
                Some("DESTROYED") => continue,
                _ => return Err(BackendError::Invalid),
            }
            if !seen.insert(id) {
                return Err(BackendError::Invalid);
            }
            ids.push(id.into());
        }
    }
    let next = match response.get("nextPageToken") {
        None => None,
        Some(Value::String(s)) if s.is_empty() => None,
        Some(Value::String(s)) => {
            page_token(s)?;
            if Some(s.as_str()) == cursor {
                return Err(BackendError::Invalid);
            }
            Some(s.clone())
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
    pub(crate) fn new(env: Env, config: Gcp) -> Result<Self, BackendError> {
        let base = config
            .endpoint
            .as_deref()
            .unwrap_or("https://secretmanager.googleapis.com");
        config::endpoint(base).map_err(|_| BackendError::Invalid)?;
        for endpoint in [&config.token_endpoint, &config.metadata_endpoint]
            .into_iter()
            .flatten()
        {
            config::local_auth_endpoint(endpoint, false).map_err(|_| BackendError::Invalid)?;
        }
        let base = base.trim_end_matches('/').to_owned();
        Ok(Self {
            env,
            config,
            base,
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
        let response = auth_response(
            net,
            &self.config,
            "https://www.googleapis.com/auth/cloud-platform",
            Dispatch::Authorized(original),
        )
        .await?;
        let token = field(&response, "access_token").map_err(|_| BackendError::Invalid)?;
        header_secret(token).map_err(|_| BackendError::Invalid)?;
        let seconds = response
            .get("expires_in")
            .and_then(Value::as_u64)
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
            .map_err(|_| BackendError::Unauthorized)?;
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
        resource(path)?;
        if id.is_some_and(|id| !config::positive_version(id)) {
            return Err(BackendError::Invalid);
        }
        let result = self
            .get(
                format!(
                    "{}/v1/{path}/versions/{}:access",
                    self.base,
                    id.unwrap_or("latest")
                ),
                original,
            )
            .await;
        let response = match result {
            Err(BackendError::NotFound) if id.is_some() => return Err(BackendError::VersionGone),
            other => other?,
        };
        fetched(path, id, &response)
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
            resource(path)?;
            let mut url = url::Url::parse(&format!("{}/v1/{path}/versions", self.base))
                .map_err(|_| BackendError::Invalid)?;
            url.query_pairs_mut().append_pair("pageSize", "1000");
            if let Some(cursor) = cursor {
                page_token(cursor)?;
                url.query_pairs_mut().append_pair("pageToken", cursor);
            }
            let response = self.get(url.into(), &original).await?;
            version_page(path, cursor, &response)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PATH: &str = "projects/123/secrets/password";

    #[test]
    fn forged_resources_and_aliases_cannot_rebind_access() {
        for name in [
            "projects/999/secrets/password/versions/2",
            "projects/123/secrets/password2/versions/2",
            "projects/project-alias/secrets/password/versions/2",
            "projects/123/secrets/password/versions/latest",
            "projects/123/secrets/password/versions/02",
            "projects/123/secrets/password/versions/2:access",
        ] {
            assert!(matches!(
                fetched(PATH, None, &json!({"name":name,"payload":{"data":"eA=="}})),
                Err(BackendError::Invalid)
            ));
        }
        let response = json!({"name":format!("{PATH}/versions/2"),"payload":{"data":"eA=="}});
        assert!(matches!(
            fetched(PATH, Some("3"), &response),
            Err(BackendError::Invalid)
        ));
        let result = fetched(PATH, Some("2"), &response).unwrap();
        assert_eq!(result.value.as_slice(), b"x");
        assert_eq!(result.canonical_ref, PATH);
        for bad in [
            "projects/123/secrets/../x",
            "projects/123/secrets/x?alt=json",
            "https://evil",
        ] {
            assert!(resource(bad).is_err());
        }
    }

    #[test]
    fn catalogue_rejects_unreadable_retained_versions_and_cycles() {
        for (state, expected) in [
            ("DISABLED", BackendError::Denied),
            ("UNKNOWN", BackendError::Invalid),
        ] {
            let response =
                json!({"versions":[{"name":format!("{PATH}/versions/1"),"state":state}]});
            assert_eq!(version_page(PATH, None, &response).unwrap_err(), expected);
        }
        assert!(version_page(PATH, Some("same"), &json!({"nextPageToken":"same"})).is_err());
        assert!(version_page(PATH, None, &json!({"versions":{}})).is_err());
        assert!(version_page(PATH, None, &json!({"versions":[{"name":"projects/evil/secrets/x/versions/1","state":"ENABLED"}]})).is_err());
        assert!(version_page(PATH, None, &json!({})).unwrap().ids.is_empty());
    }

    #[test]
    fn destroyed_tombstones_are_not_retained_values() {
        let response = json!({
            "versions": [
                {"name":format!("{PATH}/versions/1"),"state":"DESTROYED"},
                {"name":format!("{PATH}/versions/2"),"state":"ENABLED"}
            ],
            "nextPageToken":"next-page"
        });
        let page = version_page(PATH, None, &response).unwrap();
        assert_eq!(page.ids, ["2"]);
        assert_eq!(page.next.as_deref(), Some("next-page"));
        assert!(
            version_page(
                PATH,
                None,
                &json!({
                    "versions":[{"name":"projects/evil/secrets/x/versions/1","state":"DESTROYED"}]
                })
            )
            .is_err()
        );
        assert!(
            version_page(
                PATH,
                None,
                &json!({
                    "versions":[{"name":format!("{PATH}/versions/1"),"state":"DESTROYED"}]
                })
            )
            .unwrap()
            .ids
            .is_empty()
        );
    }

    #[test]
    fn value_and_cursor_bounds_fail_closed() {
        assert!(page_token(&"x".repeat(CAP + 1)).is_err());
        assert!(page_token("x\n").is_err());
        let response = json!({"name":format!("{PATH}/versions/1"),"payload":{"data":STANDARD.encode(vec![0; 65_537])}});
        assert!(matches!(
            fetched(PATH, None, &response),
            Err(BackendError::Invalid)
        ));
    }
}
