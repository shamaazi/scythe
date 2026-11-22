//! `schema_types` writes the schema's enums and domains to one module per
//! target, however many modules `{dir}` generates. Drives the compiled binary.

use std::path::Path;
use std::process::{Command, Output};

use tempfile::TempDir;

const SCHEMA_SQL: &str = "CREATE TYPE currency AS ENUM ('gbp', 'usd');\n\
    CREATE DOMAIN email_address AS varchar(254) CHECK (VALUE ~ '^[^@ ]+@[^@ ]+$');\n\
    CREATE TABLE donors (id text PRIMARY KEY, email email_address NOT NULL, currency currency NOT NULL);\n";

fn sqlkit(project: &Path, command: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sqlkit"))
        .args([command, "--config", project.join("sqlkit.toml").to_str().unwrap()])
        .output()
        .expect("run sqlkit")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn schema_types_module_is_written_once_and_imported_by_every_module() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("schema.sql"), SCHEMA_SQL).unwrap();
    for (module, query) in [
        (
            "a",
            "-- @name GetDonor\n-- @returns :one\nSELECT id, email, currency FROM donors WHERE id = $1;\n",
        ),
        (
            "b",
            "-- @name ListDonors\n-- @returns :many\nSELECT id, currency FROM donors;\n",
        ),
    ] {
        std::fs::create_dir_all(dir.path().join(module)).unwrap();
        std::fs::write(dir.path().join(module).join("queries.sql"), query).unwrap();
    }
    std::fs::write(
        dir.path().join("sqlkit.toml"),
        "[sqlkit]\nversion = \"1\"\n\n[[sql]]\nname = \"main\"\nengine = \"postgresql\"\n\
         schema = [\"schema.sql\"]\nqueries = [\"*/queries.sql\"]\n\n\
         [[sql.gen]]\nbackend = \"typescript-bun\"\noutput = \"{dir}\"\nvalidation = \"jsdoc\"\n\
         schema_types = \"types/schema.ts\"\nschema_types_import = \"../types/schema\"\n",
    )
    .unwrap();

    let output = sqlkit(dir.path(), "generate");
    assert!(output.status.success(), "{}", stderr(&output));

    let schema = std::fs::read_to_string(dir.path().join("types/schema.ts")).unwrap();
    assert!(schema.contains("export type Currency = "), "{schema}");
    assert!(schema.contains("export type EmailAddress = string;"), "{schema}");

    let a = std::fs::read_to_string(dir.path().join("a/queries.ts")).unwrap();
    assert!(
        a.contains("import type { Currency, EmailAddress } from \"../types/schema\";"),
        "{a}"
    );
    assert!(!a.contains("CurrencyValues"), "enums are not declared per module: {a}");
    let b = std::fs::read_to_string(dir.path().join("b/queries.ts")).unwrap();
    assert!(b.contains("import type { Currency } from \"../types/schema\";"), "{b}");

    let output = sqlkit(dir.path(), "check");
    assert!(output.status.success(), "{}", stderr(&output));
}

#[test]
fn schema_types_path_may_not_escape_the_project() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("schema.sql"), SCHEMA_SQL).unwrap();
    std::fs::write(
        dir.path().join("queries.sql"),
        "-- @name ListDonors\n-- @returns :many\nSELECT id FROM donors;\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("sqlkit.toml"),
        "[sqlkit]\nversion = \"1\"\n\n[[sql]]\nname = \"main\"\nengine = \"postgresql\"\n\
         schema = [\"schema.sql\"]\nqueries = [\"queries.sql\"]\n\n\
         [[sql.gen]]\nbackend = \"typescript-bun\"\noutput = \"gen\"\n\
         schema_types = \"../escaped.ts\"\nschema_types_import = \"./schema\"\n",
    )
    .unwrap();
    let output = sqlkit(dir.path(), "generate");
    assert!(!output.status.success());
    assert!(stderr(&output).contains("escapes"), "{}", stderr(&output));
    assert!(!dir.path().parent().unwrap().join("escaped.ts").exists());
}
