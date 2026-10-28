//! `kronik init --lang ts|rust|python|go <name>`: a new project with one
//! actor, one route, a test and the SDK vendored: under `vendor/kronik-sdk`,
//! or `kronik-sdk` for Go, whose tools reserve `vendor/`.

use std::path::Path;

use schemars::JsonSchema;
use serde::Serialize;

use super::embed::{GO_SDK, PY_SDK, RUST_SDK, TS_SDK, WIT};
use super::{Failure, Lang};

/// The TypeScript toolchain the SDK is built and tested with (ADR 0002).
pub const JCO: &str = "1.39.0";
pub const COMPONENTIZE_JS: &str = "0.23.0";
pub const TYPESCRIPT: &str = "7.0.2";
/// The Rust toolchain the SDK is built and tested with.
pub const RUST: &str = "1.99.1";
/// The checksums of the Go SDK's one dependency, for a new project's go.sum.
const GO_SUM: &str = include_str!("../../../../sdk/go/go.sum");

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

const PY_PROJECT: &str = r#"[project]
name = "{name}"
version = "0.1.0"
requires-python = ">=3.11"

[tool.kronik]
entry = "actor"
sdk = "vendor/kronik-sdk"
"#;

const PY_ACTOR: &str = r#"# One actor per key: POST /{name}/<key>/increment counts the requests for
# <key>. Every request runs as one turn; the state is recorded in the log.

from kronik import actor


def http(req, ctx):
    n = (ctx.state.get_json("n") or 0) + 1
    ctx.state.set_json("n", n)
    return ctx.json(200, {"n": n})


handler = actor(
    kind="{name}",
    schema_version=1,
    routes=[{"method": "POST", "pattern": "/{name}/{key}/increment"}],
    http=http,
)
"#;

const PY_TEST: &str = r#"# The actor in an in-memory Kronik node: `python3 -m unittest discover -s
# tests` builds it and runs these tests (with kronik on PATH, or KRONIK_BIN).
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "vendor/kronik-sdk"))

from kronik.testkit import TestHost  # noqa: E402


class ActorTest(unittest.TestCase):
    def test_every_key_counts_on_its_own(self):
        host = TestHost.start(ROOT)
        self.addCleanup(host.close)
        for n in [1, 2, 3]:
            res = host.http("POST", "/{name}/alice/increment")
            self.assertEqual(res.status, 200)
            self.assertEqual(res.json(), {"n": n})
        self.assertEqual(host.http("POST", "/{name}/bob/increment").json(), {"n": 1})
        self.assertEqual(host.state_json("{name}/alice", "n"), 3)


if __name__ == "__main__":
    unittest.main()
"#;

const PY_GITIGNORE: &str = "dist/\n.kronik/\n__pycache__/\n";

const GO_MOD: &str = r#"module {name}

go 1.27

require kronik.dev/sdk v0.0.0

require go.bytecodealliance.org/cm v0.3.0 // indirect

replace kronik.dev/sdk => ./kronik-sdk
"#;

const GO_ACTOR: &str = r#"// One actor per key: POST /{name}/<key>/increment counts the requests for
// <key>. Every request runs as one turn; the state is recorded in the log.
package main

import "kronik.dev/sdk"

func init() {
	kronik.Export(kronik.Actor{
		Kind:          "{name}",
		SchemaVersion: 1,
		Routes:        []kronik.Route{{Method: "POST", Pattern: "/{name}/{key}/increment"}},
		HTTP: func(_ *kronik.Request, ctx *kronik.Ctx) (kronik.Output, error) {
			var n int64
			if _, err := ctx.State.GetJSON("n", &n); err != nil {
				return kronik.Output{}, err
			}
			n++
			if err := ctx.State.SetJSON("n", n); err != nil {
				return kronik.Output{}, err
			}
			return ctx.JSON(200, map[string]int64{"n": n})
		},
	})
}

func main() {}
"#;

const GO_TEST: &str = r#"// The actor in an in-memory Kronik node: `go test ./test` builds it and runs
// these tests (with kronik on PATH, or KRONIK_BIN). The actor package only
// compiles for TinyGo's wasip2 target, so its tests are a package of their
// own.
package test

import (
	"testing"

	"kronik.dev/sdk/testkit"
)

func TestEveryKeyCountsOnItsOwn(t *testing.T) {
	host := testkit.Start(t, testkit.Options{Dir: ".."})
	for _, want := range []int64{1, 2, 3} {
		var got struct{ N int64 }
		res := host.HTTP("POST", "/{name}/alice/increment", nil)
		if res.Status != 200 {
			t.Fatalf("status %d: %s", res.Status, res.Text())
		}
		res.JSON(&got)
		if got.N != want {
			t.Fatalf("n = %d, want %d", got.N, want)
		}
	}
	var bob struct{ N int64 }
	host.HTTP("POST", "/{name}/bob/increment", nil).JSON(&bob)
	var alice int64
	if bob.N != 1 || !host.StateJSON("{name}/alice", "n", &alice) || alice != 3 {
		t.Fatalf("bob %d, alice %d", bob.N, alice)
	}
}
"#;

const GO_GITIGNORE: &str = "dist/\n.kronik/\n";

/// What `kronik init` made: its `--json` output.
#[derive(Debug, Serialize, JsonSchema)]
pub struct Created {
    /// The project's directory, relative to the current directory.
    pub project: String,
    /// `ts`, `rust`, `python` or `go`.
    pub lang: &'static str,
    /// The project's actor type: the project's name.
    pub kind: String,
    /// The files written, relative to the project; the vendored SDK and its
    /// WIT (`vendor/kronik-sdk`, for Go `kronik-sdk`) are not listed.
    pub files: Vec<String>,
    /// The commands that follow, in order.
    pub next: Vec<String>,
}

/// `created …`, then the next commands.
pub fn print(c: &Created) {
    println!(
        "created {}/ with the actor type {} and the SDK in {}",
        c.project,
        c.kind,
        if c.lang == "go" {
            "kronik-sdk"
        } else {
            "vendor/kronik-sdk"
        }
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
    let (files, sdk) = templates(name, lang);
    for (path, contents) in &files {
        write(&dir.join(path), contents)?;
    }
    let vendor = dir.join(match lang {
        Lang::Go => "kronik-sdk",
        _ => "vendor/kronik-sdk",
    });
    for file in sdk {
        write(&vendor.join(file.path), file.contents)?;
    }
    // Go's world carries the WIT in wit/deps/kronik-actor (part of GO_SDK).
    if !matches!(lang, Lang::Go) {
        write(&vendor.join("wit/kronik-actor.wit"), WIT)?;
    }

    let mut next = vec![format!("cd {name}")];
    match lang {
        Lang::Ts => {
            next.push("npm install".to_owned());
            next.push("npm test".to_owned());
        }
        Lang::Rust => next.push("cargo test".to_owned()),
        Lang::Python | Lang::Go => {
            // The pinned toolchains (ADR 0030) come from a Kronik checkout.
            next.push(
                "<kronik checkout>/scripts/install-sdk-tools.sh  # once: the pinned toolchains"
                    .to_owned(),
            );
            next.push(if matches!(lang, Lang::Python) {
                "python3 -m unittest discover -s tests".to_owned()
            } else {
                "go test ./test".to_owned()
            });
        }
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
            Lang::Python => "python",
            Lang::Go => "go",
        },
        kind: name.to_owned(),
        files: files.iter().map(|(path, _)| (*path).to_owned()).collect(),
        next,
    })
}

/// The project's files for `name` (path, contents), and the SDK's files.
fn templates(
    name: &str,
    lang: Lang,
) -> (Vec<(&'static str, String)>, &'static [super::embed::File]) {
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
    match lang {
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
        Lang::Python => (
            vec![
                ("pyproject.toml", fill(PY_PROJECT)),
                ("src/actor.py", fill(PY_ACTOR)),
                ("tests/test_actor.py", fill(PY_TEST)),
                (".gitignore", PY_GITIGNORE.to_string()),
            ],
            PY_SDK,
        ),
        Lang::Go => (
            vec![
                ("go.mod", fill(GO_MOD)),
                ("go.sum", GO_SUM.to_string()),
                ("main.go", fill(GO_ACTOR)),
                ("test/actor_test.go", fill(GO_TEST)),
                (".gitignore", GO_GITIGNORE.to_string()),
            ],
            GO_SDK,
        ),
    }
}

fn write(path: &Path, contents: &str) -> Result<(), Failure> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, contents).map_err(|e| Failure::new(format!("{}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    /// examples/github-flow holds `kronik init --lang rust counter`'s files
    /// (without vendor/), for a repository that runs the GitHub Action.
    #[test]
    fn the_github_flow_example_is_the_rust_template() {
        let example =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/github-flow");
        let (files, _) = super::templates("counter", super::Lang::Rust);
        for (path, contents) in files {
            let on_disk = std::fs::read_to_string(example.join(path))
                .unwrap_or_else(|e| panic!("examples/github-flow/{path}: {e}"));
            assert_eq!(
                on_disk, contents,
                "examples/github-flow/{path}: rerun the template"
            );
        }
    }
}
