//! End-to-end coverage for nested-aggregate codegen (#78).
//!
//! These go through the CLI binary rather than the `scythe-codegen` API
//! because the things they pin only exist at file-assembly time: enums and
//! nested structs are emitted once per output file, deduplicated across
//! queries, and ordered relative to the row structs that reference them.
//! None of that is observable from a single `generate_with_backend` call.

use std::path::{Path, PathBuf};
use std::process::Command;

fn scythe_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_scythe"))
}

/// Render a path for embedding in a TOML basic string. Forward slashes are
/// accepted by globs on every platform; `\` would be a TOML escape.
fn toml_path(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

const SCHEMA: &str = "\
CREATE TYPE order_status AS ENUM ('pending', 'in progress', 'shipped');
CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    status order_status NOT NULL,
    notes TEXT,
    \"createdAt\" TIMESTAMPTZ NOT NULL
);
";

const QUERIES: &str = "\
-- @name GetUserOrders
-- @returns :many
SELECT u.id, json_agg(o.*) AS orders FROM users u JOIN orders o ON o.user_id = u.id GROUP BY u.id;

-- @name GetUserOrdersOuter
-- @returns :many
SELECT u.id, json_agg(o.*) AS orders FROM users u LEFT JOIN orders o ON o.user_id = u.id GROUP BY u.id;
";

/// Run `scythe generate` for one backend over `schema`/`queries` and return
/// the single generated file's contents.
fn generate(backend: &str, extension: &str, schema: &str, queries: &str) -> Result<String, String> {
    let temp = tempfile::TempDir::new().unwrap();
    let schema_path = temp.path().join("schema.sql");
    let queries_path = temp.path().join("queries.sql");
    let output_dir = temp.path().join("out");
    std::fs::write(&schema_path, schema).unwrap();
    std::fs::write(&queries_path, queries).unwrap();

    let config = format!(
        r#"[scythe]
version = "1"

[[sql]]
name = "test"
engine = "postgresql"
schema = ["{schema}"]
queries = ["{queries}"]

[[sql.gen]]
backend = "{backend}"
output = "{output}"
"#,
        schema = toml_path(&schema_path),
        queries = toml_path(&queries_path),
        backend = backend,
        output = toml_path(&output_dir),
    );
    let config_path = temp.path().join("scythe.toml");
    std::fs::write(&config_path, &config).unwrap();

    // `output` above is an absolute path (the temp dir's own `out/`
    // subdirectory), which #207 now rejects by default as escaping the
    // project root; `--allow-output-escape` opts back in, matching the same
    // deliberate-absolute-output pattern in `config_relative_paths.rs`.
    let output = scythe_bin()
        .args([
            "generate",
            "--config",
            config_path.to_str().unwrap(),
            "--allow-output-escape",
        ])
        .current_dir(temp.path())
        .output()
        .expect("failed to run scythe generate");

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }

    Ok(read_generated(&output_dir, extension))
}

/// Locate the generated file by extension rather than by name. Backends do not
/// agree on capitalization -- `java-jdbc` emits `Queries.java` where every
/// other backend emits `queries.<ext>` -- so hardcoding the lowercase form
/// resolves on case-insensitive macOS and fails on Linux.
fn read_generated(output_dir: &Path, extension: &str) -> String {
    let mut matches: Vec<PathBuf> = std::fs::read_dir(output_dir)
        .unwrap_or_else(|err| panic!("output dir {}: {err}", output_dir.display()))
        .map(|entry| entry.expect("dir entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == extension))
        .collect();
    matches.sort();

    assert_eq!(
        matches.len(),
        1,
        "expected exactly one .{extension} file in {}, found {matches:?}",
        output_dir.display()
    );
    std::fs::read_to_string(&matches[0]).expect("generated file")
}

#[test]
fn sqlx_emits_a_nested_struct_per_query_with_json_key_renames() {
    let code = generate("rust-sqlx", "rs", SCHEMA, QUERIES).expect("generate");

    assert!(
        code.contains("pub struct GetUserOrdersRowOrders"),
        "expected a nested struct; got:\n{code}"
    );
    // The JSON key json_agg emits is the raw SQL column name, so the
    // snake_cased Rust field needs an explicit serde rename. Without it,
    // deserialization fails at runtime with `missing field created_at`.
    assert!(
        code.contains("#[serde(rename = \"createdAt\")]"),
        "expected a serde rename for the quoted mixed-case column; got:\n{code}"
    );
    assert!(
        code.contains("pub created_at: chrono::DateTime<chrono::Utc>,"),
        "got:\n{code}"
    );
    // A field whose snake_case form already matches the key must not be
    // renamed -- the attribute is emitted only where it changes behaviour.
    assert!(!code.contains("#[serde(rename = \"user_id\")]"), "got:\n{code}");
}

#[test]
fn sqlx_nested_struct_derives_both_serde_traits() {
    let code = generate("rust-sqlx", "rs", SCHEMA, QUERIES).expect("generate");

    // ~keep Deserialize decodes the column; Serialize is required because
    // `sqlx::types::Json<T>: Serialize` is bounded on `T: Serialize` and a
    // row struct generated with `serde = true` derives Serialize.
    assert!(
        code.contains(
            "#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]\npub struct GetUserOrdersRowOrders"
        ),
        "got:\n{code}"
    );
}

#[test]
fn sqlx_emits_the_enum_reached_only_through_a_nested_struct() {
    let code = generate("rust-sqlx", "rs", SCHEMA, QUERIES).expect("generate");

    // `orders.status` appears in no top-level column -- only inside the
    // nested struct. Without scanning nested fields the file would name
    // `OrderStatus` with no definition anywhere (E0412).
    assert!(code.contains("pub enum OrderStatus"), "got:\n{code}");
    assert!(code.contains("pub status: OrderStatus,"), "got:\n{code}");
    // Decoded by serde_json here, not by the driver, so it needs the serde
    // derives the plain enum path omits...
    assert!(
        code.contains("sqlx::Type, serde::Serialize, serde::Deserialize)]"),
        "got:\n{code}"
    );
    // ...and per-variant renames, because serde would otherwise look for the
    // PascalCase identifier rather than the SQL label.
    assert!(code.contains("#[serde(rename = \"in progress\")]"), "got:\n{code}");
}

#[test]
fn sqlx_left_join_element_is_optional() {
    let code = generate("rust-sqlx", "rs", SCHEMA, QUERIES).expect("generate");

    assert!(
        code.contains("pub orders: Option<sqlx::types::Json<Vec<GetUserOrdersRowOrders>>>,"),
        "an INNER JOIN cannot produce a null element; got:\n{code}"
    );
    assert!(
        code.contains("pub orders: Option<sqlx::types::Json<Vec<Option<GetUserOrdersOuterRowOrders>>>>,"),
        "json_agg over a LEFT JOIN with no match yields [null]; got:\n{code}"
    );
}

/// Two queries whose names collapse onto the same snake_case stem are rejected.
///
/// This assertion is inverted from what it was. It used to generate these two
/// queries successfully and check only that the shared nested struct was
/// emitted once -- while ignoring that the two queries also collapse onto one
/// *function* name, `get_user_orders`, with different bodies (the second
/// carries a `WHERE`). The emitted file therefore had two identically-named
/// functions: E0428, the very defect GH #136 tracks, passing a test whose
/// stated subject was avoiding E0428 on the struct.
///
/// `check_file_level_type_name_collisions` now compares `fn_name` across
/// queries too, so this input fails before anything is written. The
/// deduplication path the old test aimed at is not reachable through colliding
/// query names any more, which is strictly better: a collision the user must
/// resolve with `@name` is now named, rather than half-deduplicated into
/// output that could not compile.
#[test]
fn duplicate_query_names_that_collapse_onto_one_fn_name_are_rejected() {
    let queries = "\
-- @name GetUserOrders
-- @returns :many
SELECT json_agg(o.*) AS orders FROM orders o;

-- @name GETUserOrders
-- @returns :many
SELECT json_agg(o.*) AS orders FROM orders o WHERE o.user_id = $1;
";

    let error = generate("rust-sqlx", "rs", SCHEMA, queries).expect_err("colliding fn names must be rejected");

    assert!(
        error.contains("get_user_orders") && error.contains("GetUserOrders") && error.contains("GETUserOrders"),
        "the error must name the generated declaration and both queries that produced it; got:\n{error}"
    );
}

#[test]
fn duplicate_nested_struct_names_with_different_shapes_are_rejected() {
    let queries = "\
-- @name GetUserOrders
-- @returns :many
SELECT json_agg(o.*) AS orders FROM orders o;

-- @name GETUserOrders
-- @returns :many
SELECT json_agg(u.*) AS orders FROM users u;
";

    let err = generate("rust-sqlx", "rs", SCHEMA, queries).expect_err("should fail");

    assert!(
        err.contains("different row shapes"),
        "expected a name-collision diagnostic, got: {err}"
    );
}
