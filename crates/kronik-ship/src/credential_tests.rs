//! Credentials that are read once, before a restore gives up the privileges it
//! needed to read them, and used for every request after that.

use super::*;

fn resolved(token: Option<&str>) -> RemoteCredentials {
    RemoteCredentials(Some(Resolved {
        key_id: "AKIATESTKEYID".into(),
        secret_key: Zeroizing::new("test-secret-key".into()),
        token: token.map(|t| Zeroizing::new(t.into())),
    }))
}

fn s3(credentials: &RemoteCredentials) -> Remote {
    Remote::open_with(
        "s3://bucket/prefix",
        Some("http://127.0.0.1:9"),
        credentials,
    )
    .unwrap()
}

fn generic(text: &str) -> object_store::Error {
    object_store::Error::Generic {
        store: "S3",
        source: text.into(),
    }
}

#[tokio::test]
async fn a_remote_signs_with_the_credentials_it_was_given_and_reads_no_other_source() {
    let remote = s3(&resolved(Some("session-token")));
    let provider = remote.credentials.as_ref().unwrap();
    let credential = provider.get_credential().await.unwrap();
    assert_eq!(credential.key_id, "AKIATESTKEYID");
    assert_eq!(credential.secret_key, "test-secret-key");
    assert_eq!(credential.token.as_deref(), Some("session-token"));
}

#[tokio::test]
async fn what_a_remote_resolves_is_what_it_signs_with() {
    let first = s3(&resolved(Some("session-token")));
    let again = first.resolve_credentials().await.unwrap();
    let second = s3(&again);
    let credential = second
        .credentials
        .as_ref()
        .unwrap()
        .get_credential()
        .await
        .unwrap();
    assert_eq!(credential.key_id, "AKIATESTKEYID");
    assert_eq!(credential.secret_key, "test-secret-key");
    assert_eq!(credential.token.as_deref(), Some("session-token"));
}

#[tokio::test]
async fn a_file_remote_has_no_credentials_to_resolve() {
    let directory = tempfile::tempdir().unwrap();
    let remote = Remote::open(&format!("file://{}", directory.path().display()), None).unwrap();
    let resolved = remote.resolve_credentials().await.unwrap();
    assert_eq!(format!("{resolved:?}"), "RemoteCredentials(none)");
    // And opening it with them is opening it.
    Remote::open_with(
        &format!("file://{}", directory.path().display()),
        None,
        &resolved,
    )
    .unwrap();
}

#[test]
fn only_the_providers_own_answer_that_a_token_ran_out_is_blamed_on_the_credentials() {
    let temporary = s3(&resolved(Some("session-token")));
    for text in [
        "ExpiredToken: The provided token has expired.",
        "<Code>ExpiredTokenException</Code>",
        "RequestExpired",
        "TokenRefreshRequired",
        "InvalidToken",
    ] {
        assert!(
            matches!(
                temporary.store_error(generic(text)),
                ShipError::CredentialsExpired(_)
            ),
            "{text}"
        );
    }
    // A refusal for another reason is not blamed on them.
    for text in [
        "AccessDenied: not allowed to perform s3:ListBucket",
        "NoSuchBucket",
        "SignatureDoesNotMatch",
    ] {
        assert!(
            matches!(temporary.store_error(generic(text)), ShipError::Store(_)),
            "{text}"
        );
    }
    // Long-lived credentials (no session token) cannot "run out" in this sense.
    let permanent = s3(&resolved(None));
    assert!(matches!(
        permanent.store_error(generic("ExpiredToken")),
        ShipError::Store(_)
    ));
    // Neither can a remote that read its credentials itself.
    let own = Remote::open("s3://bucket", Some("http://127.0.0.1:9")).unwrap();
    assert!(matches!(
        own.store_error(generic("ExpiredToken")),
        ShipError::Store(_)
    ));
}

#[test]
fn the_message_names_the_expiry_and_what_to_do_and_no_secret() {
    let remote = s3(&resolved(Some("session-token")));
    let error = remote.store_error(generic("ExpiredToken: The provided token has expired."));
    let text = error.to_string();
    for needle in [
        "ExpiredToken",
        "resolved before the restore dropped its privileges",
        "cannot be refreshed",
        "credentials that last as long as the restore takes",
    ] {
        assert!(text.contains(needle), "{needle}: {text}");
    }
    for secret in ["test-secret-key", "session-token", "AKIATESTKEYID"] {
        assert!(!text.contains(secret), "{secret}: {text}");
    }
    assert_eq!(error.code(), "s3");
}

#[test]
fn the_credentials_are_never_printed() {
    let shown = format!("{:?}", resolved(Some("session-token")));
    assert_eq!(shown, "RemoteCredentials(resolved)");
    for secret in ["test-secret-key", "session-token", "AKIATESTKEYID"] {
        assert!(!shown.contains(secret));
    }
}
