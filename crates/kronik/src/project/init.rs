//! `kronik init --lang ts|rust <name>`: a new project with one actor, one
//! route and the SDK vendored under `vendor/kronik-sdk`.

use std::path::Path;

use schemars::JsonSchema;
use serde::Serialize;

use super::embed::{RUST_SDK, TS_SDK, WIT};
use super::{Failure, Lang};

/// The TypeScript toolchain the SDK is built and tested with (ADR 0002).
pub const JCO: &str = "1.39.0";
pub const COMPONENTIZE_JS: &str = "0.23.0";
pub const TYPESCRIPT: &str = "7.0.2";
/// The Rust toolchain the SDK is built and tested with.
pub const RUST: &str = "1.99.1";

const TS_PACKAGE: &str = r#"{
  "name": "{name}",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "kronik": {
    "entry": "src/actor.ts"
  },
  "scripts": {
    "build": "kronik build",
    "test": "node --test test/actor.test.ts"
  },
  "dependencies": {
    "@kronik/sdk": "file:vendor/kronik-sdk"
  },
  "devDependencies": {
    "@bytecodealliance/componentize-js": "{componentize_js}",
    "@bytecodealliance/jco": "{jco}",
    "typescript": "{typescript}"
  }
}
"#;

const TS_CONFIG: &str = r#"{
  "compilerOptions": {
    "target": "es2022",
    "module": "esnext",
    "moduleResolution": "bundler",
    "lib": ["es2022"],
    "types": [],
    "strict": true,
    "noEmit": true,
    "allowImportingTsExtensions": true,
    "verbatimModuleSyntax": true,
    "erasableSyntaxOnly": true
  },
  "include": ["src/**/*.ts"]
}
"#;

const TS_ACTOR: &str = r#"import { actor } from "@kronik/sdk";

// One actor per key: POST /{name}/<key>/increment counts the requests for
// <key>. Every request runs as one turn; the state is recorded in the log.
export default actor({
  kind: "{name}",
  schemaVersion: 1,
  routes: [{ method: "POST", pattern: "/{name}/{key}/increment" }],
  http(req, ctx) {
    const n = (ctx.state.getJson<number>("n") ?? 0) + 1;
    ctx.state.setJson("n", n);
    return ctx.json(200, { n });
  },
});
"#;

const TS_TEST: &str = r#"// The actor in an in-memory Kronik node: `npm test` builds it and runs these
// tests (with kronik on PATH, or KRONIK_BIN).
import assert from "node:assert/strict";
import { test } from "node:test";
import { TestHost } from "@kronik/sdk/testkit";

test("every key counts on its own", async (t) => {
  const host = await TestHost.start();
  t.after(() => host.close());
  for (const n of [1, 2, 3]) {
    const res = await host.http("POST", "/{name}/alice/increment");
    assert.equal(res.status, 200);
    assert.deepEqual(res.json(), { n });
  }
  assert.deepEqual((await host.http("POST", "/{name}/bob/increment")).json(), { n: 1 });
  assert.equal(await host.stateJson("{name}/alice", "n"), 3);
});
"#;

const TS_GITIGNORE: &str = "node_modules/\ndist/\n.kronik/\n";

const RUST_CARGO: &str = r#"[package]
name = "{name}"
version = "0.1.0"
edition = "2024"
publish = false

[lib]
crate-type = ["cdylib"]

[dependencies]
kronik-sdk = { path = "vendor/kronik-sdk" }
serde_json = "1"

# The project is a workspace of its own; the vendored SDK is a member.
[workspace]

# Small components: every byte is compiled and stored per code hash.
[profile.release]
opt-level = "s"
lto = true
codegen-units = 1
debug = false
strip = true
panic = "abort"
"#;

const RUST_TOOLCHAIN: &str = r#"[toolchain]
channel = "{rust}"
targets = ["wasm32-wasip2"]
profile = "minimal"
"#;

const RUST_ACTOR: &str = r#"//! One actor per key: POST /{name}/<key>/increment counts the requests for
//! <key>. Every request runs as one turn; the state is recorded in the log.

use kronik_sdk::prelude::*;

struct {type};

impl Actor for {type} {
    fn describe() -> Manifest {
        Manifest::new("{name}", 1).route(Route::post("/{name}/{key}/increment"))
    }

    fn http(ctx: &mut Ctx, _request: HttpRequest) -> Result<Output, HandlerError> {
        let n: u64 = ctx.state().get_json("n")?.unwrap_or(0) + 1;
        ctx.state().set_json("n", &n)?;
        Ok(Output::json(200, &serde_json::json!({ "n": n })))
    }
}

kronik_sdk::export!({type});
"#;

const RUST_TEST: &str = r#"//! The actor in an in-memory Kronik node: `cargo test` builds it and runs
//! these tests (with kronik on PATH, or KRONIK_BIN).

use kronik_sdk::testkit::TestHost;
use serde_json::{Value, json};

#[test]
fn every_key_counts_on_its_own() {
    let mut host = TestHost::start(env!("CARGO_MANIFEST_DIR")).unwrap();
    for n in 1..=3 {
        let res = host.http("POST", "/{name}/alice/increment", "").unwrap();
        assert_eq!(res.status, 200);
        assert_eq!(res.json::<Value>().unwrap(), json!({ "n": n }));
    }
    let res = host.http("POST", "/{name}/bob/increment", "").unwrap();
    assert_eq!(res.json::<Value>().unwrap(), json!({ "n": 1 }));
    assert_eq!(host.state_json::<u64>("{name}/alice", "n").unwrap(), Some(3));
}
"#;

const RUST_GITIGNORE: &str = "target/\ndist/\n.kronik/\n";

/// What `kronik init` made: its `--json` output.
#[derive(Debug, Serialize, JsonSchema)]
pub struct Created {
    /// The project's directory, relative to the current directory.
    pub project: String,
    /// `ts` or `rust`.
    pub lang: &'static str,
    /// The project's actor type: the project's name.
    pub kind: String,
    /// The files written, relative to the project; the SDK and the WIT in
    /// `vendor/kronik-sdk` are not listed.
    pub files: Vec<String>,
    /// The commands that follow, in order.
    pub next: Vec<String>,
}

/// `created …`, then the next commands.
pub fn print(c: &Created) {
    println!(
        "created {}/ with the actor type {} and the SDK in vendor/kronik-sdk",
        c.project, c.kind
    );
    println!("next:");
    for cmd in &c.next {
        println!("  {cmd}");
    }
}

pub fn run(name: &str, lang: Lang) -> Result<Created, Failure> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !name.ends_with('-');
    if !valid {
        return Err(Failure::new(format!(
            "{name:?} is not a project name: use lowercase letters, digits and dashes, starting with a letter"
        )));
    }
    let dir = Path::new(name);
    if dir.exists()
        && std::fs::read_dir(dir)
            .map(|mut d| d.next().is_some())
            .unwrap_or(true)
    {
        return Err(Failure::new(format!(
            "{name}/ already exists and is not empty"
        )));
    }
    // The Rust type for the actor: the name in CamelCase, `my-app` -> `MyApp`.
    let type_name: String = name
        .split('-')
        .map(|part| {
            let mut chars = part.chars();
            chars
                .next()
                .map(|c| c.to_ascii_uppercase().to_string() + chars.as_str())
                .unwrap_or_default()
        })
        .collect();
    let fill = |template: &str| {
        template
            .replace("{name}", name)
            .replace("{type}", &type_name)
            .replace("{jco}", JCO)
            .replace("{componentize_js}", COMPONENTIZE_JS)
            .replace("{typescript}", TYPESCRIPT)
            .replace("{rust}", RUST)
    };
    let (files, sdk): (Vec<(&str, String)>, _) = match lang {
        Lang::Ts => (
            vec![
                ("package.json", fill(TS_PACKAGE)),
                ("tsconfig.json", TS_CONFIG.to_string()),
                ("src/actor.ts", fill(TS_ACTOR)),
                ("test/actor.test.ts", fill(TS_TEST)),
                (".gitignore", TS_GITIGNORE.to_string()),
            ],
            TS_SDK,
        ),
        Lang::Rust => (
            vec![
                ("Cargo.toml", fill(RUST_CARGO)),
                ("rust-toolchain.toml", fill(RUST_TOOLCHAIN)),
                ("src/lib.rs", fill(RUST_ACTOR)),
                ("tests/actor.rs", fill(RUST_TEST)),
                (".gitignore", RUST_GITIGNORE.to_string()),
            ],
            RUST_SDK,
        ),
    };
    for (path, contents) in &files {
        write(&dir.join(path), contents)?;
    }
    let vendor = dir.join("vendor/kronik-sdk");
    for file in sdk {
        write(&vendor.join(file.path), file.contents)?;
    }
    write(&vendor.join("wit/kronik-actor.wit"), WIT)?;

    let mut next = vec![format!("cd {name}")];
    match lang {
        Lang::Ts => {
            next.push("npm install".to_owned());
            next.push("npm test".to_owned());
        }
        Lang::Rust => next.push("cargo test".to_owned()),
    }
    next.push("kronik build".to_owned());
    next.push(format!(
        "kronik deploy dist/{name}.wasm --reason 'first deploy'"
    ));
    Ok(Created {
        project: name.to_owned(),
        lang: match lang {
            Lang::Ts => "ts",
            Lang::Rust => "rust",
        },
        kind: name.to_owned(),
        files: files.iter().map(|(path, _)| (*path).to_owned()).collect(),
        next,
    })
}

fn write(path: &Path, contents: &str) -> Result<(), Failure> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, contents).map_err(|e| Failure::new(format!("{}: {e}", path.display())))
}
