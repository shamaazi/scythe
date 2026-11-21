# Contributing

## Branches

- `main` mirrors upstream ([Goldziher/scythe](https://github.com/Goldziher/scythe)) and is never
  committed to here.
- `shamaazi` carries all of this fork's work. Commit to it directly, one logical change per commit.

To pick up upstream changes, fetch `upstream/main`, fast-forward `main` to it and merge `main` into
`shamaazi`. Upstream still has every engine and language; the merge keeps this fork's deletions.

The crates keep upstream's names (`scythe-*`) and the layout of `crates/scythe-core` (parser,
analyzer, catalog), including the branches for dialects this fork no longer configures, so a
PostgreSQL fix made here can be cherry-picked onto upstream's `main` and offered upstream.

## Setup

Install [Nix](https://nixos.org/download) and [devenv](https://devenv.sh/getting-started/), then:

```bash
devenv shell
devenv tasks run sqlkit:test
```

`devenv.nix` pins the Rust toolchain from `rust-toolchain.toml` and provides Bun and a PostgreSQL
service for the integration projects. Build in debug only; nothing here needs `--release`.

## Tasks

| Task | What it runs |
|---|---|
| `sqlkit:build` | Debug build of the CLI |
| `sqlkit:test` | `cargo test --workspace`, then the core and codegen tests on mygiving's `postgres,lang-typescript` build |
| `sqlkit:lint` | `cargo fmt --all --check` and `cargo clippy -- -D warnings` on the full and the minimal build |
| `sqlkit:generate` | Regenerate the fixture tests and the integration projects' generated code |
| `sqlkit:generated-fresh` | `sqlkit:generate`, then fail if anything changed |
| `sqlkit:integration` | Run the integration projects (starts devenv's PostgreSQL on port 5433) |
| `sqlkit:cluster-scope` | Build the libpg_query helpers and run the `audit --cluster-scope` acceptance controls |

The GitHub workflow in `.github/workflows/ci.yml` runs the same tasks. Linking every test binary at
once can exhaust memory on a small machine; `cargo test --workspace -j1` avoids it.

## Architecture

```text
scythe-cli
  |-- scythe-codegen
  |     |-- scythe-backend  (manifests, type resolution, naming)
  |     +-- scythe-core     (SQL parsing, catalog, type analysis)
  |-- scythe-inspect        (live PostgreSQL checks, schema drift, SQLite schema execution)
  +-- scythe-lint           (lint and audit rules, sqruff integration)
```

| Directory | Purpose |
|---|---|
| `crates/scythe-codegen/manifests/` | Backend manifests: type mappings per backend and engine |
| `crates/scythe-codegen/src/backends/` | `sqlx.rs`, `tokio_postgres.rs`, and `typescript_postgres.rs` (postgres.js and Bun) on `typescript_common.rs` |
| `crates/scythe-lint/src/rules/` | Lint and audit rules |
| `crates/scythe-conformance/` | Live nullability conformance suite (PostgreSQL and SQLite) |
| `testing_data/` | JSON fixtures the test generator turns into tests |
| `integration_tests/` | Projects that run generated code against real databases |
| `tools/test-generator/` | Generates `crates/scythe-codegen/tests/generated` from `testing_data/` |
| `tools/integration-test-generator/` | Renders the Rust integration projects from templates |

## Fixtures

Fixtures live under `testing_data/{category}/`; their IDs must be unique and `snake_case`, since they
become test names. The loader in `tools/test-generator/src/fixture.rs` is the schema, and it rejects
unknown keys. After changing a fixture, a backend or a template, run `sqlkit:generate` and commit the
regenerated files; `sqlkit:generated-fresh` fails otherwise.

## Integration projects

`rust-sqlx`, `rust-tokio-postgres` and `rust-sqlx-sqlite` are rendered by
`tools/integration-test-generator`; `rust-sqlx-nested-json` and `typescript-bun` are kept by hand.
Every project must be run by the `sqlkit:integration` task:
`tools/integration-test-generator/tests/coverage_completeness.rs` fails otherwise.

## Adding a lint rule

1. Implement `LintRule` in the right file under `crates/scythe-lint/src/rules/`.
2. Register it in `crates/scythe-lint/src/registry.rs`.
3. Add fixtures under `testing_data/lint/` that trigger and do not trigger it, and unit tests in the rule file.

## Commits

[Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`,
`refactor:`, `test:`, `chore:`, with a scope where useful (`fix(analyzer): ...`) and `!` for a
breaking change. The body says why. Add an entry under `## [Unreleased]` in `CHANGELOG.md` for
anything a user of the CLI would notice.

## License

Contributions are licensed under the MIT License.
