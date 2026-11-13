# Agents

Kronik accepts contributions from people and from automated agents. Before you
change anything, read:

1. [The build brief](https://github.com/G-man3207/Kronik/wiki/Build-Brief): the
   English translation of the project's build brief, and the source of truth
   for scope, invariants and milestones.
2. The original build brief, in Swedish:
   [Build-Brief-Original-Swedish](https://github.com/G-man3207/Kronik/wiki/Build-Brief-Original-Swedish).
   It is authoritative if the two disagree, and the two pages are kept in sync.
3. [The project status](https://github.com/G-man3207/Kronik/wiki/Project-status):
   the current state of each milestone, the open questions and the known gaps.
4. `docs/adr/`: the decisions so far. Record new non-trivial decisions as ADRs
   based on `docs/adr/0000-template.md`.

The build brief also sets out the project's conventions: follow the milestone
order, verify changes against the tests and the demo scripts, and never change
an invariant without a maintainer decision. If a change would alter an
invariant or the scope of v0.1, open an issue for a maintainer decision before
proceeding.

## Public repository

Kronik's repository is public. Everything that is committed
stays in the project history and is visible to everyone, so the project never
commits personal or environment-specific information: no names, email
addresses, usernames, hostnames, private network addresses, home-directory or
absolute local paths, private repository or branch references, internal
receipts, credentials, or other details about a development environment.

Use the project identity (`Kronik Maintainers
<maintainers@users.noreply.github.com>`) for commits, keep project-management
documents on the [wiki](https://github.com/G-man3207/Kronik/wiki), and report
anything sensitive to the maintainers privately instead of committing it. The
rule covers code, comments, documentation, tests, fixtures, scripts, workflow
files and commit messages. If personal information does reach a commit, rewrite
the history before publishing it.

### Commit identity and history

Every commit is authored and committed as the project, never as an individual:
`Kronik Maintainers <maintainers@users.noreply.github.com>`. The repository sets
this identity locally (`git config user.name` / `user.email`), so ordinary
commits inherit it; never override it, even temporarily, because the author and
committer fields are permanent parts of every commit object.

If a personal identity or other personal information has already been committed,
rewrite the history before it is published. A `.mailmap` only changes how an
identity is displayed; it does not change the stored commit data or the commit
SHA. Set both the author and committer identity on every commit, then force-push
and re-point every release tag:

```sh
# Recommended: git filter-repo
git filter-repo --force --commit-callback '
    commit.author_name = b"Kronik Maintainers"
    commit.author_email = b"maintainers@users.noreply.github.com"
    commit.committer_name = b"Kronik Maintainers"
    commit.committer_email = b"maintainers@users.noreply.github.com"
'

# Equivalent with git filter-branch
git filter-branch --env-filter '
    export GIT_AUTHOR_NAME="Kronik Maintainers"
    export GIT_AUTHOR_EMAIL="maintainers@users.noreply.github.com"
    export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME"
    export GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
' --tag-name-filter cat -- --all
```

Rewriting gives every commit a new SHA: update commit references in docs,
workflow pins and release notes, recreate annotated tags with the neutral
tagger, force-push `main` and the tags, and tell collaborators to re-clone (or
hard-reset) because their old objects are unchanged. Keep a backup bundle
before rewriting.

## Conventions

The full list is in `CONTRIBUTING.md`. In short:

- Everything in the repository is in English.
- Small commits with descriptive messages; justify new dependencies in the
  commit message; update docs and the error catalog in the same commit as the
  behavior.
- No `unwrap` or `expect` in daemon code paths; `unsafe` only in allowlisted
  modules with a justification; `tracing`, not `println!`, in the daemon.
- `thiserror` in libraries, `anyhow` only in the `kronik` binary.
- Avoid C dependencies beyond bundled SQLite.
- Format changes need a version bump and a compatibility fixture.

## Running CI locally

```sh
scripts/ci.sh                # fmt, clippy, hygiene, test, docs, book, examples, ts, sdks, dst, deny, foreign, identity and action, as in CI
scripts/ci.sh clippy test    # selected steps
```

It needs rustup, which installs the toolchain pinned in `rust-toolchain.toml`,
and `cargo-deny`. Some steps need more:

- `test` needs the pinned Python runtime of the OIDC tests, prepared as
  `CONTRIBUTING.md` describes, in `KRONIK_TEST_PYTHON`. The step checks it
  first; the tests that need it fail without it, they do not skip.
- `ts` needs Node.js 22.20 or later with npm and network access.
- `sdks` installs the pinned Python and Go toolchains with
  `scripts/install-sdk-tools.sh` on first use (Linux x86_64, `python3` with
  pip, network access).
- `book` downloads the pinned mdBook and `action` the pinned actionlint, both
  checksum-verified; a failed download or check fails the step. `action` also
  needs PyYAML and HTTPS access.
- `foreign` needs root and gVisor's `runsc` (`scripts/install-runsc.sh`) and
  is skipped with a message without them, unless
  `KRONIK_FOREIGN_TESTS=require`. When it runs, it also needs Docker for the
  pinned Postgres image, and skopeo for the registry test.
- `identity` needs libfaketime for `todo-ts`, which it skips with a message
  otherwise.

`ts` uses the local port 47831, and `ts`, `sdks` and `identity` work in fixed
directories under `/var/tmp`, so two runs of them on one machine collide.
