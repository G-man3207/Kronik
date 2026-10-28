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

/// The Python `kronik` package (sdk/python), without its tests; its WIT is [`WIT`].
pub const PY_SDK: &[File] = sdk_files!("../../../../sdk/python/":
    "kronik/__init__.py",
    "kronik/_export.py",
    "kronik/_host.py",
    "kronik/actor.py",
    "kronik/ctx.py",
    "kronik/errors.py",
    "kronik/http.py",
    "kronik/sql.py",
    "kronik/testkit.py",
);

/// The Go module `kronik.dev/sdk` (sdk/go) with its generated bindings and its world, without its tests.
pub const GO_SDK: &[File] = sdk_files!("../../../../sdk/go/":
    "go.mod",
    "actor.go",
    "ctx.go",
    "errors.go",
    "go.sum",
    "http.go",
    "internal/wit/kronik/actor/context/context.wasm.go",
    "internal/wit/kronik/actor/context/context.wit.go",
    "internal/wit/kronik/actor/context/empty.s",
    "internal/wit/kronik/actor/crypto/abi.go",
    "internal/wit/kronik/actor/crypto/crypto.wasm.go",
    "internal/wit/kronik/actor/crypto/crypto.wit.go",
    "internal/wit/kronik/actor/crypto/empty.s",
    "internal/wit/kronik/actor/handler/abi.go",
    "internal/wit/kronik/actor/handler/empty.s",
    "internal/wit/kronik/actor/handler/handler.exports.go",
    "internal/wit/kronik/actor/handler/handler.wasm.go",
    "internal/wit/kronik/actor/handler/handler.wit.go",
    "internal/wit/kronik/actor/http-client/abi.go",
    "internal/wit/kronik/actor/http-client/empty.s",
    "internal/wit/kronik/actor/http-client/http-client.wasm.go",
    "internal/wit/kronik/actor/http-client/http-client.wit.go",
    "internal/wit/kronik/actor/log/empty.s",
    "internal/wit/kronik/actor/log/log.wasm.go",
    "internal/wit/kronik/actor/log/log.wit.go",
    "internal/wit/kronik/actor/messaging/abi.go",
    "internal/wit/kronik/actor/messaging/empty.s",
    "internal/wit/kronik/actor/messaging/messaging.wasm.go",
    "internal/wit/kronik/actor/messaging/messaging.wit.go",
    "internal/wit/kronik/actor/privacy/abi.go",
    "internal/wit/kronik/actor/privacy/empty.s",
    "internal/wit/kronik/actor/privacy/privacy.wasm.go",
    "internal/wit/kronik/actor/privacy/privacy.wit.go",
    "internal/wit/kronik/actor/secrets/empty.s",
    "internal/wit/kronik/actor/secrets/secrets.wasm.go",
    "internal/wit/kronik/actor/secrets/secrets.wit.go",
    "internal/wit/kronik/actor/sql/abi.go",
    "internal/wit/kronik/actor/sql/empty.s",
    "internal/wit/kronik/actor/sql/sql.wasm.go",
    "internal/wit/kronik/actor/sql/sql.wit.go",
    "internal/wit/kronik/actor/state/abi.go",
    "internal/wit/kronik/actor/state/empty.s",
    "internal/wit/kronik/actor/state/state.wasm.go",
    "internal/wit/kronik/actor/state/state.wit.go",
    "internal/wit/kronik/actor/timers/abi.go",
    "internal/wit/kronik/actor/timers/empty.s",
    "internal/wit/kronik/actor/timers/timers.wasm.go",
    "internal/wit/kronik/actor/timers/timers.wit.go",
    "internal/wit/kronik/actor/types/abi.go",
    "internal/wit/kronik/actor/types/types.wit.go",
    "internal/wit/kronik/go/actor-go/actor-go.wit.go",
    "internal/wit/wasi/cli/environment/empty.s",
    "internal/wit/wasi/cli/environment/environment.wasm.go",
    "internal/wit/wasi/cli/environment/environment.wit.go",
    "internal/wit/wasi/cli/exit/empty.s",
    "internal/wit/wasi/cli/exit/exit.wasm.go",
    "internal/wit/wasi/cli/exit/exit.wit.go",
    "internal/wit/wasi/cli/stderr/empty.s",
    "internal/wit/wasi/cli/stderr/stderr.wasm.go",
    "internal/wit/wasi/cli/stderr/stderr.wit.go",
    "internal/wit/wasi/cli/stdin/empty.s",
    "internal/wit/wasi/cli/stdin/stdin.wasm.go",
    "internal/wit/wasi/cli/stdin/stdin.wit.go",
    "internal/wit/wasi/cli/stdout/empty.s",
    "internal/wit/wasi/cli/stdout/stdout.wasm.go",
    "internal/wit/wasi/cli/stdout/stdout.wit.go",
    "internal/wit/wasi/cli/terminal-input/empty.s",
    "internal/wit/wasi/cli/terminal-input/terminal-input.wasm.go",
    "internal/wit/wasi/cli/terminal-input/terminal-input.wit.go",
    "internal/wit/wasi/cli/terminal-output/empty.s",
    "internal/wit/wasi/cli/terminal-output/terminal-output.wasm.go",
    "internal/wit/wasi/cli/terminal-output/terminal-output.wit.go",
    "internal/wit/wasi/cli/terminal-stderr/empty.s",
    "internal/wit/wasi/cli/terminal-stderr/terminal-stderr.wasm.go",
    "internal/wit/wasi/cli/terminal-stderr/terminal-stderr.wit.go",
    "internal/wit/wasi/cli/terminal-stdin/empty.s",
    "internal/wit/wasi/cli/terminal-stdin/terminal-stdin.wasm.go",
    "internal/wit/wasi/cli/terminal-stdin/terminal-stdin.wit.go",
    "internal/wit/wasi/cli/terminal-stdout/empty.s",
    "internal/wit/wasi/cli/terminal-stdout/terminal-stdout.wasm.go",
    "internal/wit/wasi/cli/terminal-stdout/terminal-stdout.wit.go",
    "internal/wit/wasi/clocks/monotonic-clock/empty.s",
    "internal/wit/wasi/clocks/monotonic-clock/monotonic-clock.wasm.go",
    "internal/wit/wasi/clocks/monotonic-clock/monotonic-clock.wit.go",
    "internal/wit/wasi/clocks/wall-clock/empty.s",
    "internal/wit/wasi/clocks/wall-clock/wall-clock.wasm.go",
    "internal/wit/wasi/clocks/wall-clock/wall-clock.wit.go",
    "internal/wit/wasi/filesystem/preopens/empty.s",
    "internal/wit/wasi/filesystem/preopens/preopens.wasm.go",
    "internal/wit/wasi/filesystem/preopens/preopens.wit.go",
    "internal/wit/wasi/filesystem/types/abi.go",
    "internal/wit/wasi/filesystem/types/empty.s",
    "internal/wit/wasi/filesystem/types/types.wasm.go",
    "internal/wit/wasi/filesystem/types/types.wit.go",
    "internal/wit/wasi/io/error/empty.s",
    "internal/wit/wasi/io/error/error.wasm.go",
    "internal/wit/wasi/io/error/error.wit.go",
    "internal/wit/wasi/io/poll/empty.s",
    "internal/wit/wasi/io/poll/poll.wasm.go",
    "internal/wit/wasi/io/poll/poll.wit.go",
    "internal/wit/wasi/io/streams/empty.s",
    "internal/wit/wasi/io/streams/streams.wasm.go",
    "internal/wit/wasi/io/streams/streams.wit.go",
    "internal/wit/wasi/random/insecure-seed/empty.s",
    "internal/wit/wasi/random/insecure-seed/insecure-seed.wasm.go",
    "internal/wit/wasi/random/insecure-seed/insecure-seed.wit.go",
    "internal/wit/wasi/random/insecure/empty.s",
    "internal/wit/wasi/random/insecure/insecure.wasm.go",
    "internal/wit/wasi/random/insecure/insecure.wit.go",
    "internal/wit/wasi/random/random/empty.s",
    "internal/wit/wasi/random/random/random.wasm.go",
    "internal/wit/wasi/random/random/random.wit.go",
    "internal/wit/wasi/sockets/instance-network/empty.s",
    "internal/wit/wasi/sockets/instance-network/instance-network.wasm.go",
    "internal/wit/wasi/sockets/instance-network/instance-network.wit.go",
    "internal/wit/wasi/sockets/ip-name-lookup/abi.go",
    "internal/wit/wasi/sockets/ip-name-lookup/empty.s",
    "internal/wit/wasi/sockets/ip-name-lookup/ip-name-lookup.wasm.go",
    "internal/wit/wasi/sockets/ip-name-lookup/ip-name-lookup.wit.go",
    "internal/wit/wasi/sockets/network/abi.go",
    "internal/wit/wasi/sockets/network/empty.s",
    "internal/wit/wasi/sockets/network/network.wasm.go",
    "internal/wit/wasi/sockets/network/network.wit.go",
    "internal/wit/wasi/sockets/tcp-create-socket/empty.s",
    "internal/wit/wasi/sockets/tcp-create-socket/tcp-create-socket.wasm.go",
    "internal/wit/wasi/sockets/tcp-create-socket/tcp-create-socket.wit.go",
    "internal/wit/wasi/sockets/tcp/abi.go",
    "internal/wit/wasi/sockets/tcp/empty.s",
    "internal/wit/wasi/sockets/tcp/tcp.wasm.go",
    "internal/wit/wasi/sockets/tcp/tcp.wit.go",
    "internal/wit/wasi/sockets/udp-create-socket/empty.s",
    "internal/wit/wasi/sockets/udp-create-socket/udp-create-socket.wasm.go",
    "internal/wit/wasi/sockets/udp-create-socket/udp-create-socket.wit.go",
    "internal/wit/wasi/sockets/udp/abi.go",
    "internal/wit/wasi/sockets/udp/empty.s",
    "internal/wit/wasi/sockets/udp/udp.wasm.go",
    "internal/wit/wasi/sockets/udp/udp.wit.go",
    "sql.go",
    "testkit/testkit.go",
    "wit/deps/cli/command.wit",
    "wit/deps/cli/environment.wit",
    "wit/deps/cli/exit.wit",
    "wit/deps/cli/imports.wit",
    "wit/deps/cli/run.wit",
    "wit/deps/cli/stdio.wit",
    "wit/deps/cli/terminal.wit",
    "wit/deps/clocks/monotonic-clock.wit",
    "wit/deps/clocks/wall-clock.wit",
    "wit/deps/clocks/world.wit",
    "wit/deps/filesystem/preopens.wit",
    "wit/deps/filesystem/types.wit",
    "wit/deps/filesystem/world.wit",
    "wit/deps/io/error.wit",
    "wit/deps/io/poll.wit",
    "wit/deps/io/streams.wit",
    "wit/deps/io/world.wit",
    "wit/deps/kronik-actor/kronik-actor.wit",
    "wit/deps/random/insecure-seed.wit",
    "wit/deps/random/insecure.wit",
    "wit/deps/random/random.wit",
    "wit/deps/random/world.wit",
    "wit/deps/sockets/instance-network.wit",
    "wit/deps/sockets/ip-name-lookup.wit",
    "wit/deps/sockets/network.wit",
    "wit/deps/sockets/tcp-create-socket.wit",
    "wit/deps/sockets/tcp.wit",
    "wit/deps/sockets/udp-create-socket.wit",
    "wit/deps/sockets/udp.wit",
    "wit/deps/sockets/world.wit",
    "wit/world.wit",
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
        let (embedded, mut on_disk) = embedded_and_on_disk("sdk/python", PY_SDK, &["kronik"]);
        // Python's bytecode caches, written when the SDK's tests run.
        on_disk.retain(|f| !f.contains("__pycache__/"));
        on_disk.dedup();
        assert_eq!(embedded, on_disk, "update PY_SDK in embed.rs");
        let (embedded, mut on_disk) =
            embedded_and_on_disk("sdk/go", GO_SDK, &["internal", "testkit", "wit"]);
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../sdk/go");
        for entry in std::fs::read_dir(&root).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let source = name.ends_with(".go") && !name.ends_with("_test.go");
            if source || name == "go.sum" {
                on_disk.push(name);
            }
        }
        on_disk.sort();
        assert_eq!(embedded, on_disk, "update GO_SDK in embed.rs");
        assert!(WIT.starts_with("package kronik:actor@0.1.0;"));
    }
}
