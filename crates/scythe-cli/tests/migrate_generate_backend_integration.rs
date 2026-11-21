//! End-to-end regression tests for GitHub issue #97: `scythe migrate` wrote
//! `target = "<lang>"` verbatim from the sqlc plugin name into
//! `[sql.gen.<lang>]`, and `scythe generate` builds the backend name as
//! `format!("{lang}-{target}")` -- so a migrated Go project got
//! `target = "go"` and the unusable backend `go-go`, and a migrated Kotlin
//! project (for which the legacy `[sql.gen.kotlin]` table had no field at
//! all in `LegacyGenConfig`) was silently dropped and generated `rust-sqlx`
//! output instead, with no error whatsoever.
//!
//! Every test here drives the compiled binary via
//! `Command::new(env!("CARGO_BIN_EXE_scythe"))` with `.current_dir(...)` set
//! on the *child* process -- never a process-wide CWD mutation -- following
//! the idiom in `config_relative_paths.rs` and `migrate_integration.rs`.

use std::path::Path;
use std::process::{Command, Output};

use tempfile::TempDir;

fn scythe_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_scythe"))
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

const SCHEMA_SQL: &str = "CREATE TABLE users (id bigint PRIMARY KEY, name text NOT NULL, email text NOT NULL);\n";

const SQLC_QUERY_SQL: &str = "-- name: GetUser :one\nSELECT id, name, email FROM users WHERE id = sqlc.arg(user_id);\n";

fn run_migrate(config_path: &Path, run_from: &Path) -> Output {
    scythe_bin()
        .args(["migrate", config_path.to_str().unwrap()])
        .current_dir(run_from)
        .output()
        .expect("run scythe migrate")
}

/// A `gen:` language scythe has no backend for must fail migration loudly,
/// naming the offending language, rather than silently writing a
/// `scythe.toml` that omits it entirely.
#[test]
fn migrate_fails_loudly_on_unsupported_gen_language() {
    let project = TempDir::new().unwrap();
    let run_from = TempDir::new().unwrap();

    std::fs::create_dir_all(project.path()).unwrap();
    std::fs::write(project.path().join("schema.sql"), SCHEMA_SQL).unwrap();
    std::fs::create_dir_all(project.path().join("queries")).unwrap();
    std::fs::write(project.path().join("queries").join("q.sql"), SQLC_QUERY_SQL).unwrap();

    // "csharp" is not one of sqlc's built-in gen plugins (go/kotlin/python),
    // and scythe migrate has no mapping for it -- it must be rejected, not
    // silently dropped.
    let config = "version: \"2\"\n\
                   sql:\n\
                   \x20 - schema: schema.sql\n\
                   \x20\x20\x20 queries: queries\n\
                   \x20\x20\x20 engine: postgresql\n\
                   \x20\x20\x20 gen:\n\
                   \x20\x20\x20\x20\x20 csharp:\n\
                   \x20\x20\x20\x20\x20\x20\x20 out: db\n";
    let config_path = project.path().join("sqlc.yaml");
    std::fs::write(&config_path, config).unwrap();

    let migrate_output = run_migrate(&config_path, run_from.path());
    assert!(
        !migrate_output.status.success(),
        "migrate must fail loudly on a gen language it has no backend for, not silently drop it"
    );
    let err = stderr(&migrate_output);
    assert!(
        err.contains("csharp"),
        "error must name the unsupported gen language; stderr: {err}"
    );
}
