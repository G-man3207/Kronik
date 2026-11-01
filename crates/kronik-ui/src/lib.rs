//! The dependency-free admin UI. The admin listener owns authentication,
//! security headers and cache policy; this crate only maps explicit assets.

/// An immutable asset compiled into the daemon.
#[derive(Clone, Copy, Debug)]
pub struct Asset {
    pub content_type: &'static str,
    pub bytes: &'static [u8],
}

/// Resolve an exact URL path, without query parameters or SPA fallbacks.
pub fn asset(path: &str) -> Option<Asset> {
    let (content_type, bytes): (&str, &[u8]) = match path {
        "/ui" | "/ui/" => (
            "text/html; charset=utf-8",
            include_bytes!("../../../ui/index.html"),
        ),
        "/ui/app.js" => (
            "text/javascript; charset=utf-8",
            include_bytes!("../../../ui/app.js"),
        ),
        "/ui/app.css" => (
            "text/css; charset=utf-8",
            include_bytes!("../../../ui/app.css"),
        ),
        "/ui/icon.svg" => ("image/svg+xml", include_bytes!("../../../ui/icon.svg")),
        _ => return None,
    };
    Some(Asset {
        content_type,
        bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::asset;

    #[test]
    fn only_explicit_assets_are_embedded() {
        for (path, content_type) in [
            ("/ui", "text/html; charset=utf-8"),
            ("/ui/", "text/html; charset=utf-8"),
            ("/ui/app.js", "text/javascript; charset=utf-8"),
            ("/ui/app.css", "text/css; charset=utf-8"),
            ("/ui/icon.svg", "image/svg+xml"),
        ] {
            let Some(asset) = asset(path) else {
                panic!("missing embedded asset {path}");
            };
            assert_eq!(asset.content_type, content_type);
            assert!(!asset.bytes.is_empty());
        }
        for path in [
            "/",
            "/ui/index.html",
            "/ui/missing",
            "/ui/../app.js",
            "/ui/?x=1",
        ] {
            assert!(asset(path).is_none(), "unexpected asset {path}");
        }
    }
}
