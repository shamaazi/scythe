# The shamaazi fork's development environment. Upstream works with mise; this file lives
# only on the downstream `shamaazi` branch, never on `main` or topic branches.
{ pkgs, ... }:
let
  # What mygiving generates: PostgreSQL to TypeScript. Builds leave out the other engines'
  # drivers (DuckDB's bundled C++ above all) and other languages; the default Cargo build
  # still includes everything.
  features = "--no-default-features --features postgres,lang-typescript";
  codegenFeatures = "--no-default-features --features scythe-codegen/postgres,scythe-codegen/lang-typescript";
in
{
  languages.rust = {
    enable = true;
    # The toolchain upstream pins, so builds match its CI.
    toolchainFile = ./rust-toolchain.toml;
  };
  # OpenSSL for the database drivers; full builds compile bundled SQLite and DuckDB.
  packages = [
    pkgs.pkg-config
    pkgs.openssl
  ];
  tasks = {
    "scythe:build" = {
      description = "Build the PostgreSQL and TypeScript scythe CLI";
      exec = "cargo build --release --locked -p scythe-cli ${features}";
    };
    "scythe:test" = {
      description = "Test the analyzer and the PostgreSQL and TypeScript code generators";
      exec = "cargo test --locked -p scythe-core -p scythe-codegen ${codegenFeatures}";
    };
    "scythe:lint" = {
      description = "Clippy and rustfmt for the PostgreSQL and TypeScript build";
      exec = ''
        cargo fmt --all --check
        cargo clippy --locked --all-targets -p scythe-core -p scythe-codegen -p scythe-cli ${features} -- -D warnings
      '';
    };
  };
}
