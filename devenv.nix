# The shamaazi fork's development environment. Upstream works with mise; this file lives
# only on the downstream `shamaazi` branch, never on `main` or topic branches.
{ pkgs, ... }:
{
  languages.rust = {
    enable = true;
    # The toolchain upstream pins, so builds match its CI.
    toolchainFile = ./rust-toolchain.toml;
  };
  # OpenSSL for the database drivers; the bundled SQLite and DuckDB builds need a C/C++ compiler.
  packages = [
    pkgs.pkg-config
    pkgs.openssl
  ];
}
