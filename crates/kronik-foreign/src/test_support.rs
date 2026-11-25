//! Helpers shared by the crate's unit tests.

use std::path::Path;
use std::sync::Mutex;

use kronik_core::sync::lock;
use kronik_effects::foreign::ForeignSecrets;

/// A temporary directory under `/var/tmp`, where the image tests keep their
/// layouts and blob stores.
pub(crate) fn temp_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("km7-test-")
        .tempdir_in("/var/tmp")
        .unwrap()
}

/// The sorted names of the entries in `dir`; empty when it cannot be read.
pub(crate) fn names(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// A child process's stdout and stderr as one text.
pub(crate) fn child_text(out: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// A resolver that counts what a start asks of it: `stripe` is linked
/// and served from the cache (or the backend), `plain` from the built-in
/// store, `down` is linked to a backend that does not answer.
pub(crate) struct Resolver {
    pub(crate) asked: Mutex<Vec<String>>,
}

impl ForeignSecrets for Resolver {
    fn current(
        &self,
        name: &str,
    ) -> kronik_core::env::BoxFuture<
        'static,
        Result<Option<zeroize::Zeroizing<Vec<u8>>>, kronik_core::error::ApiError>,
    > {
        lock(&self.asked).push(name.to_owned());
        let answer = match name {
            "stripe" => Ok(Some(zeroize::Zeroizing::new(b"backend-value".to_vec()))),
            "plain" => Ok(Some(zeroize::Zeroizing::new(b"plain-value".to_vec()))),
            "down" => Err(kronik_core::error::ApiError::new(
                kronik_core::error::ErrorCode::SecretUnavailable,
                "The retained secret identity or value is unavailable",
            )),
            _ => Ok(None),
        };
        Box::pin(async move { answer })
    }
}

/// A [`Resolver`] that has not been asked anything yet.
pub(crate) fn resolver() -> Resolver {
    Resolver {
        asked: Mutex::new(Vec::new()),
    }
}
