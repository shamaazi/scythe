# sqlkit

Shamaazi's internal SQL toolkit, a fork of [Scythe](https://github.com/Goldziher/scythe) trimmed to
PostgreSQL. It compiles annotated `.sql` files into typed database access code for
[Bun's SQL client](https://bun.com/docs/runtime/sql), [sqlx](https://github.com/launchbadge/sqlx) or
[tokio-postgres](https://github.com/sfackler/rust-postgres), and lints, audits, formats and checks
that SQL. It reads SQL statically, so generation needs no database. mygiving is its only user.

## Installation

mygiving builds it through Nix with only the features it needs:

```nix
sqlkit = pkgs.rustPlatform.buildRustPackage (final: {
  pname = "sqlkit";
  version = "0.20.3";
  src = pkgs.fetchFromGitHub {
    owner = "shamaazi";
    repo = "scythe";
    rev = "<commit on main>";
    hash = "<nix flake prefetch --json github:shamaazi/scythe/<commit>>";
  };
  cargoLock.lockFile = "${final.src}/Cargo.lock";
  cargoBuildFlags = [ "--package" "sqlkit-cli" ];
  buildNoDefaultFeatures = true;
  buildFeatures = [ "postgres" "lang-typescript" ];
  doCheck = false;
  meta.mainProgram = "sqlkit";
});
```

Cargo features: `postgres` enables the live PostgreSQL client (for `inspect` and
`check --database-url`); `lang-typescript` and `lang-rust` select the backends. The default build
has all three. PostgreSQL is the only engine, so `[[sql]] engine` is optional; when set it must be
`postgresql`, `postgres` or `pg`.

## Annotations

`@name` and `@returns` (`:one`, `:opt`, `:many`, `:exec`, `:batch`, `:grouped` with `@group_by`),
`@param` names and nullability, `@optional` filters. Plain `--` comment lines above the annotations
become the generated function's doc comment.

## Backends

| Backend | Language | Driver |
|---------|----------|--------|
| `typescript-bun` (alias `typescript`, `ts`) | TypeScript | Bun's built-in `SQL` |
| `rust-sqlx` | Rust | sqlx |
| `rust-tokio-postgres` | Rust | tokio-postgres |

`typescript-bun` options, set as keys of a `[[sql.gen]]` table:

| Option | Values | Effect |
|--------|--------|--------|
| `output` | path, or a path containing `{dir}` | Output directory; with `{dir}`, one module per query file, written beside it |
| `field_case` | `snake_case` (default), `camelCase` | Property names of rows and parameters |
| `row_keys` | `remap` (default), `driver` | With `camelCase`, `driver` trusts the client to return camel-cased keys (e.g. Bun's `SQL.camel` transform) instead of remapping rows |
| `params` | `positional` (default), `object` | Query functions take positional arguments or one parameter object |
| `row_type` | `interface` (default), `zod` | Plain interfaces or Zod schemas |
| `validation` | `none` (default), `jsdoc` | Document translated `CHECK` constraints on parameters |
| `constraints` | `ignore`, `warn`, `error` | What to do with a constraint that cannot be translated |
| `column_types` | module specifier | Declare row and parameter properties through a `Column<...>` type from that module |
| `schema_types`, `schema_types_import` | path, specifier | Write the schema's enums and domains once, to one module, and import them |
| `structs_only` | `true`/`false` | Emit types only, no query functions |
| `outer_join_unions` | `true`/`false` | Model outer-joined columns as unions of present and absent shapes |

`rust-sqlx` takes `structs_only`, `serde` and `derive`; `rust-tokio-postgres` takes `serde` and
`derive`.

## Commands

```bash
sqlkit generate                       # compile SQL to code
sqlkit check                          # is the committed code still in sync?
sqlkit lint sql/                      # lint rules
sqlkit audit sql/ --format sarif      # security and migration-safety rules
sqlkit fmt sql/                       # format via sqruff (PostgreSQL dialect)
sqlkit inspect $DATABASE_URL          # live PostgreSQL health checks
```

`check`, `lint` and `audit` exit `2` on error-severity findings and `1` on operational failure, so
CI can tell the two apart. `sqlkit <command> --help` lists every flag.

## Development

The development environment and every task live in [devenv.nix](devenv.nix): run `devenv shell`,
then `devenv tasks run <task>`. Build in debug only; nothing here needs `--release`.

| Task | What it runs |
|------|--------------|
| `sqlkit:build` | Debug build of the CLI |
| `sqlkit:test` | Workspace tests, then the core and codegen tests on the `postgres,lang-typescript` build |
| `sqlkit:lint` | `cargo fmt --check` and clippy on the full and minimal builds |
| `sqlkit:generate` | Regenerate the fixture tests and the integration projects' generated code |
| `sqlkit:generated-fresh` | Fail if regeneration changes anything |
| `sqlkit:integration` | The integration projects against devenv's PostgreSQL (port 5433, database `sqlkit_test`, user and password `sqlkit`) |
| `sqlkit:conformance` | The live nullability conformance suite against the same PostgreSQL |
| `sqlkit:cluster-scope` | Build the libpg_query helpers and run the `audit --cluster-scope` controls |

There is no CI. `devenv shell` installs git hooks: `sqlkit:lint` runs before each commit that
touches Rust or Cargo files, `sqlkit:test` and `sqlkit:generated-fresh` before each push.
`sqlkit:integration` and `sqlkit:conformance` need PostgreSQL and stay manual: run them after
changing a backend's runtime code or nullability inference. If linking every test binary at once
exhausts memory, use `cargo test --workspace -j2`.

Commits go straight to `main` as [Conventional Commits](https://www.conventionalcommits.org/) with a
body that says why.

### Layout

```text
sqlkit-cli
  |-- sqlkit-codegen
  |     |-- sqlkit-backend  (manifests, type resolution, naming)
  |     +-- sqlkit-core     (SQL parsing, catalog, type analysis)
  |-- sqlkit-inspect        (live PostgreSQL checks, schema drift)
  +-- sqlkit-lint           (lint and audit rules, sqruff integration)
```

| Directory | Purpose |
|---|---|
| `crates/sqlkit-codegen/manifests/` | Backend manifests: type mappings per backend |
| `crates/sqlkit-codegen/src/backends/` | `sqlx.rs`, `tokio_postgres.rs`, and `typescript_bun.rs` on `typescript_common.rs` |
| `crates/sqlkit-lint/src/rules/` | Lint and audit rules; register new ones in `crates/sqlkit-lint/src/registry.rs` |
| `crates/sqlkit-conformance/` | Live nullability conformance suite against PostgreSQL |
| `testing_data/` | JSON fixtures the test generator turns into tests |
| `integration_tests/` | Projects that run generated code against PostgreSQL |
| `tools/test-generator/` | Generates `crates/sqlkit-codegen/tests/generated` from `testing_data/` |
| `tools/integration-test-generator/` | Renders the Rust integration projects from templates |

### Generated code

Never hand-edit generated files: change the fixture, backend or template, run `sqlkit:generate` and
commit the result (the pre-push hook fails otherwise). Fixture IDs under `testing_data/{category}/`
must be unique `snake_case`, since they become test names; `tools/test-generator/src/fixture.rs` is
the schema and rejects unknown keys.

`rust-sqlx` and `rust-tokio-postgres` under `integration_tests/` are rendered from
`tools/integration-test-generator/templates/`; `rust-sqlx-nested-json` and `typescript-bun` are kept
by hand. `tools/integration-test-generator/tests/coverage_completeness.rs` checks that every backend
manifest has a project and every project runs in `sqlkit:integration`; known gaps go in
`tools/integration-test-generator/coverage-exemptions.txt` with a reason.

## License

[MIT](LICENSE). sqlkit derives from Scythe, by Na'aman Hirschfeld and contributors; see [ATTRIBUTIONS.md](ATTRIBUTIONS.md).
