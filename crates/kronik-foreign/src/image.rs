//! Image references (m7-foreign §2): what an operator may write after
//! `--image`, and the canonical, digest-pinned form Kronik records.
//!
//! Two kinds exist:
//!
//! - registry references in Docker's syntax, `[registry/]repo[:tag]@sha256:<hex>`.
//!   They must carry a digest; a tag alone is rejected because it can move.
//!   The tag is accepted for readability and ignored for pulling.
//! - local OCI image layouts, `oci-layout:<absolute dir>` or
//!   `oci-layout:<absolute dir>@sha256:<hex>`. Without a digest the layout must
//!   hold exactly one image (checked when it is imported).

use std::path::PathBuf;

/// Everything that can go wrong between an image reference and a rootfs.
#[derive(Debug, thiserror::Error)]
pub enum ImageError {
    /// The image or its reference is unusable: a bad or unpinned reference,
    /// a digest or size mismatch, an unsupported media type or platform, a
    /// hostile layer, an exceeded limit, or an unreachable registry.
    #[error("{0}")]
    Invalid(String),
    /// A local disk problem (blob store, layout directory, rootfs).
    #[error("{0}")]
    Io(String),
    /// The image's new layers do not fit in the free space above
    /// `[log] disk_reserve`.
    #[error("{0}")]
    NoSpace(String),
    /// A registry or layout directory did not answer within
    /// `[foreign] pull_timeout`.
    #[error("{0}")]
    TimedOut(String),
}

/// The default registry of references without a registry part, like Docker.
pub const DOCKER_HUB: &str = "docker.io";

/// The prefix of local OCI layout references.
pub const LAYOUT_PREFIX: &str = "oci-layout:";

/// A parsed image reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImageRef {
    /// An image in a registry, pinned by its (manifest or index) digest.
    Registry {
        /// Registry host, optionally with a port (`docker.io`, `ghcr.io`,
        /// `127.0.0.1:5000`).
        registry: String,
        /// Repository path (`library/busybox`).
        repository: String,
        /// `sha256:<64 lowercase hex>`.
        digest: String,
    },
    /// An image in a local OCI image layout directory.
    Layout {
        /// Absolute path of the layout directory.
        dir: PathBuf,
        /// `sha256:<64 lowercase hex>` of an image listed in `index.json`;
        /// `None` when the layout holds exactly one image or `reference`
        /// names it.
        digest: Option<String>,
        /// `oci-layout:<dir>:<ref name>`: the image whose
        /// `org.opencontainers.image.ref.name` annotation is `<ref name>`
        /// (as skopeo's `oci:<dir>:<ref>`). The record still stores the
        /// digest it resolved to.
        reference: Option<String>,
    },
}

impl ImageRef {
    /// Parses an image reference. See the module documentation for the
    /// accepted forms.
    pub fn parse(s: &str) -> Result<ImageRef, ImageError> {
        if let Some(rest) = s.strip_prefix(LAYOUT_PREFIX) {
            return parse_layout(rest);
        }
        parse_registry(s)
    }

    /// The canonical record string of this image once it resolved to
    /// `manifest_digest` (the digest of the top-level manifest or index):
    /// `<registry>/<repository>@sha256:<hex>` or
    /// `oci-layout:<dir>@sha256:<hex>`.
    pub fn pinned(&self, manifest_digest: &str) -> String {
        match self {
            ImageRef::Registry {
                registry,
                repository,
                ..
            } => format!("{registry}/{repository}@{manifest_digest}"),
            ImageRef::Layout { dir, .. } => {
                format!("{LAYOUT_PREFIX}{}@{manifest_digest}", dir.display())
            }
        }
    }
}

/// Checks `sha256:` followed by 64 lowercase hex digits.
pub fn validate_digest(digest: &str) -> Result<(), ImageError> {
    let ok = digest
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(is_lower_hex));
    if ok {
        Ok(())
    } else {
        Err(ImageError::Invalid(format!(
            "malformed digest {digest:?}: expected sha256:<64 lowercase hex digits>"
        )))
    }
}

fn is_lower_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

fn parse_layout(rest: &str) -> Result<ImageRef, ImageError> {
    // A digest suffix is only split off when it looks like one, so a
    // directory name containing `@` still works without a digest.
    let (path, digest) = match rest.rsplit_once('@') {
        Some((dir, digest)) if digest.starts_with("sha256:") => {
            validate_digest(digest)?;
            (dir, Some(digest.to_string()))
        }
        _ => (rest, None),
    };
    // `<dir>:<ref name>`: the first `:` starts the ref name (which may
    // contain `:` and `/`, as in `echo:dev`), as skopeo's `oci:` transport
    // splits it. A directory whose path has a `:` needs the digest form.
    let (dir, reference) = match path.split_once(':') {
        Some((_, "")) => {
            return Err(ImageError::Invalid(format!(
                "{LAYOUT_PREFIX}{rest}: empty ref name after `:`"
            )));
        }
        Some((d, r)) => (d, Some(r.to_string())),
        None => (path, None),
    };
    if digest.is_some() && reference.is_some() {
        return Err(ImageError::Invalid(format!(
            "{LAYOUT_PREFIX}{rest}: give a ref name or a digest, not both"
        )));
    }
    if dir.is_empty() {
        return Err(ImageError::Invalid(format!(
            "{LAYOUT_PREFIX}{rest}: missing layout directory"
        )));
    }
    let dir = PathBuf::from(dir);
    if !dir.is_absolute() {
        return Err(ImageError::Invalid(format!(
            "{LAYOUT_PREFIX}{rest}: the layout directory must be an absolute path"
        )));
    }
    Ok(ImageRef::Layout {
        dir,
        digest,
        reference,
    })
}

fn parse_registry(s: &str) -> Result<ImageRef, ImageError> {
    let invalid = |why: &str| ImageError::Invalid(format!("bad image reference {s:?}: {why}"));
    let (name, digest) = match s.split_once('@') {
        Some((name, digest)) => (name, Some(digest)),
        None => (s, None),
    };
    // A tag is the part after the last ':' that follows the last '/', so a
    // registry port (`localhost:5000/repo`) is not mistaken for one.
    let last_slash = name.rfind('/').map_or(0, |i| i + 1);
    let (name, tag) = match name[last_slash..].rfind(':') {
        Some(i) => (&name[..last_slash + i], Some(&name[last_slash + i + 1..])),
        None => (name, None),
    };
    if let Some(tag) = tag {
        let valid = !tag.is_empty()
            && tag.len() <= 128
            && !tag.starts_with(['.', '-'])
            && tag
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
        if !valid {
            return Err(invalid("malformed tag"));
        }
    }
    // Like Docker: the first component is a registry when it contains a dot
    // or a port, or is `localhost`.
    let (registry, repository) = match name.split_once('/') {
        Some((first, rest)) if first.contains(['.', ':']) || first == "localhost" => {
            (first.to_string(), rest.to_string())
        }
        _ => (DOCKER_HUB.to_string(), name.to_string()),
    };
    let registry = if registry == "index.docker.io" || registry == "registry-1.docker.io" {
        DOCKER_HUB.to_string()
    } else {
        registry
    };
    let valid_registry = !registry.is_empty()
        && registry
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'));
    if !valid_registry {
        return Err(invalid("malformed registry"));
    }
    let valid_repository = !repository.is_empty()
        && repository.split('/').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
                && part.as_bytes()[0].is_ascii_alphanumeric()
                && part.as_bytes()[part.len() - 1].is_ascii_alphanumeric()
        });
    if !valid_repository {
        return Err(invalid(
            "malformed repository (lowercase letters, digits and . _ - separated by /)",
        ));
    }
    let repository = if registry == DOCKER_HUB && !repository.contains('/') {
        format!("library/{repository}")
    } else {
        repository
    };
    let Some(digest) = digest else {
        return Err(ImageError::Invalid(format!(
            "{s} is not pinned by digest: use {s}@sha256:<digest>"
        )));
    };
    validate_digest(digest)?;
    Ok(ImageRef::Registry {
        registry,
        repository,
        digest: digest.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn registry(r: &str, repo: &str) -> ImageRef {
        ImageRef::Registry {
            registry: r.into(),
            repository: repo.into(),
            digest: D.into(),
        }
    }

    #[test]
    fn registry_references_need_a_digest() {
        assert_eq!(
            ImageRef::parse(&format!("ghcr.io/acme/echo@{D}")).unwrap(),
            registry("ghcr.io", "acme/echo")
        );
        let err = ImageRef::parse("ghcr.io/acme/echo:1.2").unwrap_err();
        assert_eq!(
            err.to_string(),
            "ghcr.io/acme/echo:1.2 is not pinned by digest: use ghcr.io/acme/echo:1.2@sha256:<digest>"
        );
        assert!(ImageRef::parse("busybox").is_err());
    }

    #[test]
    fn docker_hub_defaults_apply() {
        assert_eq!(
            ImageRef::parse(&format!("busybox@{D}")).unwrap(),
            registry("docker.io", "library/busybox")
        );
        assert_eq!(
            ImageRef::parse(&format!("busybox:1.37@{D}")).unwrap(),
            registry("docker.io", "library/busybox")
        );
        assert_eq!(
            ImageRef::parse(&format!("docker.io/busybox@{D}")).unwrap(),
            registry("docker.io", "library/busybox")
        );
        assert_eq!(
            ImageRef::parse(&format!("index.docker.io/library/busybox@{D}")).unwrap(),
            registry("docker.io", "library/busybox")
        );
        assert_eq!(
            ImageRef::parse(&format!("acme/echo@{D}")).unwrap(),
            registry("docker.io", "acme/echo")
        );
    }

    #[test]
    fn registry_ports_and_localhost_are_registries() {
        assert_eq!(
            ImageRef::parse(&format!("127.0.0.1:5000/echo:t@{D}")).unwrap(),
            registry("127.0.0.1:5000", "echo")
        );
        assert_eq!(
            ImageRef::parse(&format!("localhost/echo@{D}")).unwrap(),
            registry("localhost", "echo")
        );
    }

    #[test]
    fn malformed_references_are_rejected() {
        for bad in [
            format!("Busybox@{D}"),
            format!("busybox@{}", D.to_uppercase()),
            "busybox@sha256:abc".to_string(),
            format!("busybox@sha512:{}", &D[7..]),
            format!("busybox:@{D}"),
            format!("/busybox@{D}"),
            format!("ghcr.io//x@{D}"),
        ] {
            assert!(
                matches!(ImageRef::parse(&bad), Err(ImageError::Invalid(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn layout_references() {
        assert_eq!(
            ImageRef::parse("oci-layout:/srv/images/echo").unwrap(),
            ImageRef::Layout {
                dir: "/srv/images/echo".into(),
                digest: None,
                reference: None
            }
        );
        assert_eq!(
            ImageRef::parse(&format!("oci-layout:/srv/images/echo@{D}")).unwrap(),
            ImageRef::Layout {
                dir: "/srv/images/echo".into(),
                digest: Some(D.into()),
                reference: None
            }
        );
        assert_eq!(
            ImageRef::parse("oci-layout:/srv/images/all:ghcr.io/org/echo:dev").unwrap(),
            ImageRef::Layout {
                dir: "/srv/images/all".into(),
                digest: None,
                reference: Some("ghcr.io/org/echo:dev".into())
            }
        );
        assert!(ImageRef::parse("oci-layout:/srv/images/all:").is_err());
        assert!(ImageRef::parse(&format!("oci-layout:/srv/x:echo:dev@{D}")).is_err());
        assert!(ImageRef::parse("oci-layout:relative/dir").is_err());
        assert!(ImageRef::parse("oci-layout:").is_err());
        assert!(ImageRef::parse("oci-layout:/x@sha256:short").is_err());
    }

    #[test]
    fn pinned_renders_the_record_form() {
        let r = ImageRef::parse(&format!("busybox:latest@{D}")).unwrap();
        assert_eq!(r.pinned(D), format!("docker.io/library/busybox@{D}"));
        let l = ImageRef::parse("oci-layout:/srv/echo").unwrap();
        assert_eq!(l.pinned(D), format!("oci-layout:/srv/echo@{D}"));
    }
}
