# integration_tests

Projects that run sqlkit-generated code against real databases, one directory per backend and
engine combination:

| Project | Backend | Engine |
|---------|---------|--------|
| `rust-sqlx` | `rust-sqlx` | PostgreSQL |
| `rust-sqlx-nested-json` | `rust-sqlx` with nested aggregates | PostgreSQL |
| `rust-sqlx-sqlite` | `rust-sqlx` | SQLite |
| `rust-tokio-postgres` | `rust-tokio-postgres` | PostgreSQL |
| `typescript-bun` | `typescript-bun` | PostgreSQL |

Each harness applies its own schema from `sql/pg/schema.sql` or `sql/sqlite/schema.sql`.
`sql/torture/` is a wider PostgreSQL schema for stress-testing the generators.

## Running them

```bash
devenv tasks run sqlkit:integration
```

The task starts devenv's PostgreSQL (port 5433, database `scythe_test`, user and password `scythe`)
and runs every project; the SQLite project uses a temporary database file.

## How these directories are produced

`tools/integration-test-generator` renders the `rust-sqlx`, `rust-sqlx-sqlite` and
`rust-tokio-postgres` scaffolding (`sqlkit.toml`, the harness and `Cargo.toml`) from
`tools/integration-test-generator/templates/`; `rust-sqlx-nested-json` and `typescript-bun` are kept
by hand. `sqlkit generate` then writes each project's query code. Never hand-edit generated files:
change the generator or the templates, run `devenv tasks run sqlkit:generate` and commit the result.

## Coverage is enforced

`tools/integration-test-generator/tests/coverage_completeness.rs` (part of `cargo test --workspace`)
checks that every backend manifest is exercised by a project here and that every project is run by
the `sqlkit:integration` task. Gaps go in `tools/integration-test-generator/coverage-exemptions.txt`,
one line per gap with a reason; the list fails both on an unlisted gap and on a stale entry.
