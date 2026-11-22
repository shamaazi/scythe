# The development environment and the task runner: `devenv tasks run <task>`. There is no CI;
# git hooks run the checks instead (see `git-hooks` below). Builds are debug builds; nothing
# here builds --release.
{ pkgs, config, ... }:
let
  # What mygiving builds through Nix (its overlay pins this repository): the CLI with
  # live-database support and the TypeScript backends only.
  minimalFeatures = "--no-default-features --features postgres,lang-typescript";
  minimalCodegenFeatures = "--no-default-features --features sqlkit-codegen/lang-typescript";
  pg = config.services.postgres;
  databaseUrl = "postgres://sqlkit:sqlkit@127.0.0.1:${toString pg.port}/sqlkit_test";
in
{
  languages.rust = {
    enable = true;
    toolchainFile = ./rust-toolchain.toml;
    # Link with LLD. The default, clang driving GNU ld, cannot read LLVM bitcode, which
    # `alloca` (criterion's dependency) compiles its C into whenever CC is clang, so the
    # benches failed to link; LLD reads it, and links the debug binaries faster too.
    # This only configures the development shell: mygiving's Nix build is unaffected.
    lld.enable = true;
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
        name = "sqlkit_test";
        user = "sqlkit";
        pass = "sqlkit";
      }
    ];
  };

  # The checks run as git hooks, which entering the shell installs: lint on every commit that
  # touches Rust, tests and generated-code freshness on every push. Each hook runs the task of
  # the same name below, so `devenv tasks run` and the hooks never drift apart.
  # `git commit --no-verify` / `git push --no-verify` skip them in an emergency.
  git-hooks.hooks = {
    sqlkit-lint = {
      enable = true;
      name = "sqlkit:lint (rustfmt, clippy)";
      entry = "devenv tasks run sqlkit:lint";
      files = "\\.rs$|(^|/)Cargo\\.(toml|lock)$|^rust(-toolchain|fmt)\\.toml$";
      pass_filenames = false;
      stages = [ "pre-commit" ];
    };
    sqlkit-test = {
      enable = true;
      name = "sqlkit:test";
      entry = "devenv tasks run sqlkit:test";
      always_run = true;
      pass_filenames = false;
      stages = [ "pre-push" ];
    };
    sqlkit-generated-fresh = {
      enable = true;
      name = "sqlkit:generated-fresh";
      entry = "devenv tasks run sqlkit:generated-fresh";
      always_run = true;
      pass_filenames = false;
      stages = [ "pre-push" ];
    };
  };

  tasks = {
    "sqlkit:build" = {
      description = "Build the CLI (debug)";
      exec = "cargo build --locked -p sqlkit-cli";
    };
    "sqlkit:test" = {
      description = "Run the workspace tests, then the core and codegen tests on mygiving's minimal feature set";
      exec = ''
        set -euo pipefail
        cargo test --locked --workspace
        cargo test --locked -p sqlkit-core -p sqlkit-codegen ${minimalCodegenFeatures}
      '';
    };
    "sqlkit:lint" = {
      description = "rustfmt and clippy, on the full build and on mygiving's minimal feature set";
      exec = ''
        set -euo pipefail
        cargo fmt --all --check
        cargo clippy --locked --workspace --all-targets -- -D warnings
        cargo clippy --locked -p sqlkit-cli -p sqlkit-codegen -p sqlkit-inspect --all-targets ${minimalFeatures} -- -D warnings
      '';
    };
    # The committed fixture tests (crates/sqlkit-codegen/tests/generated) and integration
    # projects (integration_tests/*/generated) are both generated; regenerate them after
    # changing testing_data/, a backend or the templates, and commit the result.
    "sqlkit:generate" = {
      description = "Regenerate the fixture tests and the integration projects' generated code";
      exec = ''
        set -euo pipefail
        cargo run --locked -p test-generator -- --fixtures testing_data --output crates/sqlkit-codegen/tests/generated
        cargo fmt --all
        cargo build --locked -p sqlkit-cli
        sqlkit="$(cargo metadata --format-version 1 --no-deps | ${pkgs.jq}/bin/jq -r .target_directory)/debug/sqlkit"
        cargo run --locked --quiet -p integration-test-generator
        # These keep their sqlkit.toml and scaffolding by hand, outside the templates.
        hand_maintained="rust-sqlx-nested-json typescript-bun"
        for backend in $(cargo run --locked --quiet -p integration-test-generator -- --list) $hand_maintained; do
          (cd "integration_tests/$backend" && "$sqlkit" generate)
        done
      '';
    };
    "sqlkit:generated-fresh" = {
      description = "Fail if regenerating the fixture tests or integration code changes anything";
      after = [ "sqlkit:generate" ];
      exec = ''
        paths="crates/sqlkit-codegen/tests/generated integration_tests"
        # Against the index, so staged but uncommitted work counts as the baseline.
        status=$(git diff --name-only -- $paths; git ls-files --others --exclude-standard -- $paths)
        if [ -n "$status" ]; then
          printf '%s\n' "$status"
          echo "Generated code is stale: run 'devenv tasks run sqlkit:generate' and commit the result." >&2
          exit 1
        fi
      '';
    };
    # `sqlkit audit --cluster-scope` parses with libpg_query helper programs; this builds them
    # for the host (downloading the pinned libpg_query release) and runs the gate's acceptance
    # controls.
    "sqlkit:cluster-scope" = {
      description = "Build the PostgreSQL parser helpers and run the cluster-scope gate controls";
      exec = ''
        set -euo pipefail
        sh crates/sqlkit-cli/src/commands/audit/build_pg_parser_helpers.sh target/pg-parser-helpers
        cargo build --locked -p sqlkit-cli
        sh scripts/test-cluster-scope-gate.sh target/debug/sqlkit target/pg-parser-helpers 18
      '';
    };
    # The live nullability conformance suite (crates/sqlkit-conformance): runs every
    # testing_data/nullability_live fixture against devenv's PostgreSQL and checks the
    # analyzer and generated code against what the database actually returns.
    "sqlkit:conformance" = {
      description = "Run the live nullability conformance suite against PostgreSQL";
      after = [ "devenv:processes:postgres@ready" ];
      env.SQLKIT_CONFORMANCE_POSTGRES_URL = databaseUrl;
      exec = "cargo test --locked -p sqlkit-conformance --features pg,live-tests --test live -- --nocapture";
    };
    # sqlkit-inspect's live tests (schema drift, query verification, the live checks, and the
    # live catalog's value constraints against the DDL-parsed catalog's) on devenv's PostgreSQL.
    "sqlkit:inspect-live" = {
      description = "Run the sqlkit-inspect live tests against PostgreSQL";
      after = [ "devenv:processes:postgres@ready" ];
      env.SQLKIT_TEST_DATABASE_URL = databaseUrl;
      exec = "cargo test --locked -p sqlkit-inspect --features live-tests";
    };
    "sqlkit:integration" = {
      description = "Run the PostgreSQL and Bun integration projects";
      after = [ "devenv:processes:postgres@ready" ];
      env.DATABASE_URL = databaseUrl;
      exec = ''
        set -euo pipefail
        cd integration_tests
        for project in rust-sqlx rust-sqlx-nested-json rust-tokio-postgres; do
          echo "== $project"
          (cd "$project" && cargo run --quiet)
        done
        echo "== typescript-bun"
        (cd typescript-bun && bun install --frozen-lockfile && bunx tsc --noEmit && bun test.ts)
      '';
    };
  };
}
