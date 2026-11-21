# sqlkit

**Write SQL. Get type-safe TypeScript for Bun, or Rust.**

sqlkit is Shamaazi's fork of [Scythe](https://github.com/Goldziher/scythe), trimmed to what we use:
PostgreSQL (and SQLite), generating TypeScript for [Bun's built-in SQL client](https://bun.com/docs/runtime/sql)
and Rust for [sqlx](https://github.com/launchbadge/sqlx) or
[tokio-postgres](https://github.com/sfackler/rust-postgres). It compiles annotated `.sql` files into
database access code (row types, query functions and type mappings) that stays in sync with the
schema. It reads SQL statically, so generation needs no database connection.

Upstream supports ten languages and ten databases; this fork keeps three backends and two engines,
and adds Bun support, per-file output, schema type modules and other PostgreSQL work. The internal
crates keep upstream's names (`scythe-*`) and layout so PostgreSQL fixes can still be sent
upstream; the binary, config file (`sqlkit.toml`, with a `[sqlkit]` table), provenance header
(`sqlkit:provenance`) and audit suppression comments (`-- sqlkit-audit: ignore[...]`) are named
`sqlkit`. Rule ids keep their `SC-` prefix.

## What you get

| | What it does |
|---|---|
| **Type inference that reads the query** | Nullability propagated through `LEFT`/`RIGHT`/`FULL` joins, `COALESCE`, `CASE WHEN`, aggregates, window functions and SQL functions, not just column constraints. CTEs (including recursive), `RETURNING`, enums, domains, composites, arrays and JSON map to native types. |
| **`sqlkit check`** | Verifies committed code still matches the SQL it was generated from, through the provenance header every generated file carries. Given `--database-url`, it also compares the schema with a live PostgreSQL catalog. |
| **`sqlkit lint`** | Correctness and performance rules (`UPDATE` without `WHERE`, `NULL` compared with `=`, leading-wildcard `LIKE`, query naming), plus sqruff's style rules. |
| **`sqlkit audit`** | Security and migration-safety rules: dangerous functions, `GRANT` to `PUBLIC`, literal passwords, `SECURITY DEFINER` misuse, locking `ALTER`s and destructive DDL. Human, SARIF or JSON output. |
| **`sqlkit fmt`** | SQL formatting through sqruff. |
| **`sqlkit inspect`** | Live PostgreSQL health checks: foreign keys without covering indexes, tables with policies but RLS disabled, duplicate indexes. |
| **Annotations** | `@name` and `@returns` (`:one`, `:opt`, `:many`, `:exec`, `:batch`, `:grouped` with `@group_by`), `@param` names and nullability, `@optional` filters. |

## Installation

Through Nix, building the `scythe-cli` package (which installs the `sqlkit` binary) with only the
features a project needs
(PostgreSQL and TypeScript here):

```nix
sqlkit = pkgs.rustPlatform.buildRustPackage (final: {
  pname = "sqlkit";
  version = "0.20.3";
  src = pkgs.fetchFromGitHub {
    owner = "shamaazi";
    repo = "scythe";
    rev = "<commit on the shamaazi branch>";
    hash = "<nix flake prefetch --json github:shamaazi/scythe/<commit>>";
  };
  cargoLock.lockFile = "${final.src}/Cargo.lock";
  cargoBuildFlags = [ "--package" "scythe-cli" ];
  buildNoDefaultFeatures = true;
  buildFeatures = [ "postgres" "lang-typescript" ];
  doCheck = false;
  meta.mainProgram = "sqlkit";
});
```

Or with Cargo from a checkout: `cargo install --path crates/scythe-cli`.

Cargo features: `postgres` and `sqlite` select the engines (and their live drivers for `inspect`,
`check --database-url` and `schema_source = "execute"`), `lang-typescript` and `lang-rust` the
backends. The default build has all four.

## Quick start

**1. Annotate a query.** `status` is an enum column; `o.total` and `o.notes` sit on the nullable
side of a `LEFT JOIN`.

```sql
-- @name GetUserOrders
-- @returns :many
SELECT u.id, u.name, o.total, o.notes
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
WHERE u.status = $1;
```

**2. Point `sqlkit.toml` at it.**

```toml
[sqlkit]
version = "1"

[[sql]]
name = "main"
engine = "postgresql"
schema = ["sql/schema.sql"]
queries = ["sql/queries.sql"]

[[sql.gen]]
backend = "typescript-bun"
output = "src/generated"
field_case = "camelCase"
params = "object"
```

**3. Generate** with `sqlkit generate`.

**4. Use it.** `total` and `notes` are nullable because the join can fail to match; `id` and `name`
are not, and the enum parameter is typed with the generated union.

```typescript
export interface GetUserOrdersRow {
	id: number;
	name: string;
	total: string | null;
	notes: string | null;
}

export interface GetUserOrdersParams {
	status: UserStatus;
}

export async function getUserOrders(
	sql: SQL,
	params: GetUserOrdersParams,
): Promise<GetUserOrdersRow[]> {
```

## Backends

| Backend | Language | Engines | Driver |
|---------|----------|---------|--------|
| `typescript-bun` | TypeScript | PostgreSQL | Bun's built-in `SQL` |
| `rust-sqlx` | Rust | PostgreSQL, SQLite | sqlx |
| `rust-tokio-postgres` | Rust | PostgreSQL | tokio-postgres |

`typescript-bun` is a driver mode of upstream's postgres.js generator, so `typescript-postgres`
(postgres.js) and the JSDoc variants `javascript-bun` and `javascript-postgres` are also available,
though only `typescript-bun` has an integration project here.

`typescript-bun` and `typescript-postgres` options, set as keys of a `[[sql.gen]]` table:

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
sqlkit fmt sql/                       # format via sqruff
sqlkit inspect $DATABASE_URL          # live PostgreSQL health checks
```

`check`, `lint` and `audit` exit `2` on error-severity findings and `1` on operational failure, so
CI can tell the two apart. `sqlkit <command> --help` lists every flag.

## Development

The development environment and every task live in [devenv.nix](devenv.nix): run `devenv shell`,
then `devenv tasks run <task>`.

| Task | What it runs |
|------|--------------|
| `sqlkit:build` | Debug build of the CLI |
| `sqlkit:test` | Workspace tests, then the core and codegen tests on the `postgres,lang-typescript` build |
| `sqlkit:lint` | `cargo fmt --check` and clippy on the full and minimal builds |
| `sqlkit:generate` | Regenerate the fixture tests and the integration projects' generated code |
| `sqlkit:generated-fresh` | Fail if regeneration changes anything |
| `sqlkit:integration` | The rust-sqlx, rust-tokio-postgres, SQLite and Bun projects against devenv's PostgreSQL |
| `sqlkit:cluster-scope` | Build the libpg_query helpers and run the `audit --cluster-scope` controls |

There is no CI: run `sqlkit:lint`, `sqlkit:test` and `sqlkit:integration` before pushing. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the workflow.

## License

[MIT](LICENSE). Scythe is by Na'aman Hirschfeld and contributors; see [ATTRIBUTIONS.md](ATTRIBUTIONS.md).
