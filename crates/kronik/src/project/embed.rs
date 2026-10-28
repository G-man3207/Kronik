//! The SDKs and the WIT, embedded so that `kronik init` can vendor them into
//! a new project without a package registry.

/// One file of a vendored SDK: its path inside the SDK and its contents.
pub struct File {
    pub path: &'static str,
    pub contents: &'static str,
}

macro_rules! sdk_files {
    ($base:literal: $($path:literal),* $(,)?) => {
        &[$(File { path: $path, contents: include_str!(concat!($base, $path)) }),*]
    };
}

/// `wit/kronik-actor.wit`, which both SDKs carry in `wit/`.
pub const WIT: &str = include_str!("../../../../wit/kronik-actor.wit");

/// `@kronik/sdk` (sdk/ts), without its `wit` symlink.
pub const TS_SDK: &[File] = sdk_files!("../../../../sdk/ts/":
    "package.json",
    "src/actor.ts",
    "src/ctx.ts",
    "src/errors.ts",
    "src/globals.d.ts",
    "src/http.ts",
    "src/index.ts",
    "src/sql.ts",
    "testkit/index.ts",
    "testkit/tsconfig.json",
    "types/actor.d.ts",
    "types/interfaces/kronik-actor-context.d.ts",
    "types/interfaces/kronik-actor-crypto.d.ts",
    "types/interfaces/kronik-actor-handler.d.ts",
    "types/interfaces/kronik-actor-http-client.d.ts",
    "types/interfaces/kronik-actor-log.d.ts",
    "types/interfaces/kronik-actor-messaging.d.ts",
    "types/interfaces/kronik-actor-privacy.d.ts",
    "types/interfaces/kronik-actor-secrets.d.ts",
    "types/interfaces/kronik-actor-sql.d.ts",
    "types/interfaces/kronik-actor-state.d.ts",
    "types/interfaces/kronik-actor-timers.d.ts",
    "types/interfaces/kronik-actor-types.d.ts",
);

/// `kronik-sdk` (sdk/rust), without its `wit` symlink.
pub const RUST_SDK: &[File] = sdk_files!("../../../../sdk/rust/":
    "Cargo.toml",
    "src/actor.rs",
    "src/ctx.rs",
    "src/error.rs",
    "src/http.rs",
    "src/lib.rs",
    "src/sql.rs",
    "src/testkit.rs",
    "src/types.rs",
);

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;

    fn files_under(root: &Path, dir: &str, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(root.join(dir)) else {
            return;
        };
        for entry in entries.flatten() {
            let rel = format!("{dir}/{}", entry.file_name().to_string_lossy());
            if entry.path().is_dir() {
                files_under(root, &rel, out);
            } else {
                out.push(rel);
            }
        }
    }

    fn embedded_and_on_disk(
        sdk: &str,
        files: &[File],
        dirs: &[&str],
    ) -> (Vec<String>, Vec<String>) {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(sdk);
        let mut on_disk = Vec::new();
        for dir in dirs {
            files_under(&root, dir, &mut on_disk);
        }
        on_disk.push(files[0].path.to_string());
        on_disk.sort();
        let mut embedded: Vec<String> = files.iter().map(|f| f.path.to_string()).collect();
        embedded.sort();
        (embedded, on_disk)
    }

    #[test]
    fn every_sdk_source_file_is_embedded() {
        let (embedded, on_disk) =
            embedded_and_on_disk("sdk/ts", TS_SDK, &["src", "testkit", "types"]);
        assert_eq!(embedded, on_disk, "update TS_SDK in embed.rs");
        let (embedded, on_disk) = embedded_and_on_disk("sdk/rust", RUST_SDK, &["src"]);
        assert_eq!(embedded, on_disk, "update RUST_SDK in embed.rs");
        assert!(WIT.starts_with("package kronik:actor@0.1.0;"));
    }
}
