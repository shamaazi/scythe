//! `[[sql]] engine` is optional and PostgreSQL is the only engine: every command that reads
//! the config accepts `postgresql`, `postgres` and `pg`, or no `engine` key at all, and
//! rejects anything else as an operational failure (exit 1) naming the value -- never a
//! silent fallback to PostgreSQL, and never a lint finding.

use std::fs;
use std::process::{Command, Output};

use tempfile::TempDir;

const SCHEMA: &str = "CREATE TABLE widgets (id bigint PRIMARY KEY, name text NOT NULL);\n";
const QUERIES: &str = "-- @name ListWidgets\n-- @returns :many\nSELECT id, name FROM widgets;\n";

/// The commands that read `[[sql]]` blocks, as argument lists before `--config`.
const COMMANDS: &[&[&str]] = &[&["generate"], &["check"], &["lint"], &["audit"]];

fn sqlkit_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sqlkit"))
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Write `sqlkit.toml` + `schema.sql` + `queries.sql` into `dir`, with the given `engine`
/// line (`None` omits the key), and return the config path.
fn write_project(dir: &TempDir, engine: Option<&str>) -> String {
    fs::write(dir.path().join("schema.sql"), SCHEMA).expect("write schema.sql");
    fs::write(dir.path().join("queries.sql"), QUERIES).expect("write queries.sql");

    let engine = engine
        .map(|engine| format!("engine = \"{engine}\"\n"))
        .unwrap_or_default();
    let config = format!(
        "[sqlkit]\nversion = \"1\"\n\n\
         [[sql]]\nname = \"main\"\n{engine}\
         schema = [\"schema.sql\"]\nqueries = [\"queries.sql\"]\n\n\
         [[sql.gen]]\nbackend = \"typescript-bun\"\noutput = \"generated\"\n"
    );
    let config_path = dir.path().join("sqlkit.toml");
    fs::write(&config_path, config).expect("write sqlkit.toml");
    config_path.to_string_lossy().into_owned()
}

fn run(command: &[&str], config_path: &str) -> Output {
    sqlkit_bin()
        .args(command)
        .args(["--config", config_path])
        .env_remove("DATABASE_URL")
        .env_remove("SQLKIT_DATABASE_URL")
        .output()
        .expect("run sqlkit")
}

#[test]
fn every_command_rejects_an_engine_other_than_postgresql() {
    for command in COMMANDS {
        let dir = TempDir::new().unwrap();
        let config_path = write_project(&dir, Some("mysql8"));
        let output = run(command, &config_path);
        let err = stderr(&output);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{command:?}: an unsupported engine is an operational failure; stderr: {err}"
        );
        assert!(
            err.contains("unsupported engine 'mysql8'"),
            "{command:?}: the error must name the offending value; stderr: {err}"
        );
    }
}

#[test]
fn explicit_file_lint_rejects_an_engine_other_than_postgresql() {
    let dir = TempDir::new().unwrap();
    let config_path = write_project(&dir, Some("postgersql"));
    let query_path = dir.path().join("queries.sql");
    let output = sqlkit_bin()
        .args(["lint", "--config", &config_path, query_path.to_str().unwrap()])
        .output()
        .expect("run sqlkit lint");
    let err = stderr(&output);
    assert_eq!(output.status.code(), Some(1), "stderr: {err}");
    assert!(err.contains("unsupported engine 'postgersql'"), "stderr: {err}");
}

#[test]
fn every_command_accepts_a_postgresql_alias_or_no_engine() {
    for engine in [Some("postgresql"), Some("postgres"), Some("PG"), None] {
        for command in COMMANDS {
            let dir = TempDir::new().unwrap();
            let config_path = write_project(&dir, engine);
            let output = run(command, &config_path);
            let err = stderr(&output);
            assert_ne!(
                output.status.code(),
                Some(1),
                "{command:?} with engine {engine:?} must not fail; stderr: {err}"
            );
            assert!(!err.contains("unsupported engine"), "{command:?}: stderr: {err}");
        }
    }
}
