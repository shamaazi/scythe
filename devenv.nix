# The development environment and the task runner: `devenv tasks run <task>` here, and the
# CI workflow runs the same tasks. Builds are debug builds; nothing here builds --release.
{ pkgs, config, ... }:
let
  # What mygiving builds through Nix (its overlay pins this repository): the CLI with the
  # PostgreSQL engine and the TypeScript backends only.
  minimalFeatures = "--no-default-features --features postgres,lang-typescript";
  minimalCodegenFeatures = "--no-default-features --features scythe-codegen/postgres,scythe-codegen/lang-typescript";
  pg = config.services.postgres;
  databaseUrl = "postgres://scythe:scythe@127.0.0.1:${toString pg.port}/scythe_test";
in
{
  languages.rust = {
    enable = true;
    toolchainFile = ./rust-toolchain.toml;
  };
  # OpenSSL for the database drivers; Bun for the typescript-bun integration project.
  packages = [
    pkgs.pkg-config
    pkgs.openssl
    pkgs.bun
  ];

  # The database the PostgreSQL integration projects run against. Each harness applies its
  # own schema (integration_tests/sql/pg/schema.sql), so the database starts empty.
  services.postgres = {
    enable = true;
    package = pkgs.postgresql_18;
    listen_addresses = "127.0.0.1";
    port = 5433;
    initialDatabases = [
      {
        name = "scythe_test";
        user = "scythe";
        pass = "scythe";
      }
    ];
  };

  tasks = {
    "scythe:build" = {
      description = "Build the CLI (debug)";
      exec = "cargo build --locked -p scythe-cli";
    };
    "scythe:test" = {
      description = "Run the workspace tests, then the core and codegen tests on mygiving's minimal feature set";
      exec = ''
        set -euo pipefail
        cargo test --locked --workspace
        cargo test --locked -p scythe-core -p scythe-codegen ${minimalCodegenFeatures}
      '';
    };
    "scythe:lint" = {
      description = "rustfmt and clippy, on the full build and on mygiving's minimal feature set";
      exec = ''
        set -euo pipefail
        cargo fmt --all --check
        cargo clippy --locked --workspace --all-targets -- -D warnings
        cargo clippy --locked -p scythe-cli -p scythe-codegen -p scythe-inspect --all-targets ${minimalFeatures} -- -D warnings
      '';
    };
    # The committed fixture tests (crates/scythe-codegen/tests/generated) and integration
    # projects (integration_tests/*/generated) are both generated; regenerate them after
    # changing testing_data/, a backend or the templates, and commit the result.
    "scythe:generate" = {
      description = "Regenerate the fixture tests and the integration projects' generated code";
      exec = ''
        set -euo pipefail
        cargo run --locked -p test-generator -- --fixtures testing_data --output crates/scythe-codegen/tests/generated
        cargo fmt --all
        cargo build --locked -p scythe-cli
        scythe="$(cargo metadata --format-version 1 --no-deps | ${pkgs.jq}/bin/jq -r .target_directory)/debug/scythe"
        cargo run --locked --quiet -p integration-test-generator
        # These keep their scythe.toml and scaffolding by hand, outside the templates.
        hand_maintained="kotlin-jdbc-ext php-pdo-namespace rust-sqlx-nested-json typescript-bun"
        for backend in $(cargo run --locked --quiet -p integration-test-generator -- --list) $hand_maintained; do
          (cd "integration_tests/$backend" && "$scythe" generate)
        done
      '';
    };
    "scythe:generated-fresh" = {
      description = "Fail if regenerating the fixture tests or integration code changes anything";
      after = [ "scythe:generate" ];
      exec = ''
        status=$(git status --porcelain -- crates/scythe-codegen/tests/generated integration_tests)
        if [ -n "$status" ]; then
          printf '%s\n' "$status"
          echo "Generated code is stale: run 'devenv tasks run scythe:generate' and commit the result." >&2
          exit 1
        fi
      '';
    };
    # `scythe audit --cluster-scope` parses with libpg_query helper programs; this builds them
    # for the host (downloading the pinned libpg_query release) and runs the gate's acceptance
    # controls.
    "scythe:cluster-scope" = {
      description = "Build the PostgreSQL parser helpers and run the cluster-scope gate controls";
      exec = ''
        set -euo pipefail
        sh crates/scythe-cli/src/commands/audit/build_pg_parser_helpers.sh target/pg-parser-helpers
        cargo build --locked -p scythe-cli
        sh scripts/test-cluster-scope-gate.sh target/debug/scythe target/pg-parser-helpers 18
      '';
    };
    "scythe:integration" = {
      description = "Run the PostgreSQL, SQLite and Bun integration projects";
      after = [ "devenv:processes:postgres@ready" ];
      env.DATABASE_URL = databaseUrl;
      exec = ''
        set -euo pipefail
        cd integration_tests
        for project in rust-sqlx rust-sqlx-nested-json rust-tokio-postgres; do
          echo "== $project"
          (cd "$project" && cargo run --quiet)
        done
        echo "== rust-sqlx-sqlite"
        sqlite_db="$(mktemp -d)/scythe_test.db"
        touch "$sqlite_db"
        (cd rust-sqlx-sqlite && SQLITE_PATH="$sqlite_db" DATABASE_URL="sqlite://$sqlite_db" cargo run --quiet)
        echo "== typescript-bun"
        (cd typescript-bun && bun install --frozen-lockfile && bunx tsc --noEmit && bun test.ts)
      '';
    };
  };
}
