//! Regression tests for board #199: a schema-qualified composite's `.` reached the generated
//! type name unsanitized.
//!
//! #136 fixed the identical defect for enums by routing `enum_type_name` through
//! `sanitize_for_identifier` before casing. Composites were never fixed the same way: every
//! backend's `generate_composite_def` called `to_pascal_case(&composite.sql_name)` directly, so
//! `CREATE TYPE app.point AS (...)` reached codegen as `composite.sql_name == "app.point"` and
//! `to_pascal_case("app.point")` split only on `_`, producing `"App.point"` -- a `.` inside
//! `pub struct App.point { ... }` (or the target's equivalent), a syntax error in every backend
//! that shared this call.
//!
//! The fix adds `composite_type_name` beside `enum_type_name` in
//! `sqlkit-backend/src/naming.rs` (routed through the same `sanitize_for_identifier`) and moves
//! every backend's declaration call through it, so the `.` becomes `_` before casing runs.

#![cfg_attr(
    not(feature = "all-languages"),
    allow(
        dead_code,
        unused_imports,
        unused_macros,
        reason = "helpers shared with tests of backends this build leaves out"
    )
)]

use sqlkit_codegen::{GeneratedCode, generate_with_backend, get_backend};
use sqlkit_core::analyzer::analyze;
use sqlkit_core::catalog::Catalog;
use sqlkit_core::errors::SqlkitError;
use sqlkit_core::parser::parse_query;

fn generate(schema: &str, query: &str, backend_name: &str) -> Result<GeneratedCode, SqlkitError> {
    let backend = get_backend(backend_name).expect("backend must support postgresql");
    let catalog = Catalog::from_ddl(&[schema]).expect("schema must parse");
    let parsed = parse_query(query).expect("query must parse");
    let analyzed = analyze(&catalog, &parsed).expect("query must analyze");
    generate_with_backend(&analyzed, &*backend)
}

/// A single schema-qualified composite (`public.widget_shape`, no nesting) selected on its own --
/// enough to exercise every backend's declaration-side `generate_composite_def` call, the same
/// call site the top-level enum regression (`enum_and_query_name_regression.rs`) exercises for
/// `enum_type_name`.
const SIMPLE_SCHEMA: &str = "\
    CREATE TYPE public.widget_shape AS (label TEXT, side_count INT); \
    CREATE TABLE widgets (id INT PRIMARY KEY, shape public.widget_shape NOT NULL);";

const SIMPLE_QUERY: &str = "-- @name GetWidget\n-- @returns :one\n\
    SELECT id, shape FROM widgets WHERE id = $1;";

/// Rust: before the fix this line read `pub struct Public.widgetShape {`, which does not parse
/// -- a `.` is not a valid character inside a Rust identifier.
#[cfg(feature = "lang-rust")]
#[test]
fn composite_declaration_sanitizes_schema_qualified_dot_in_rust() {
    let code = generate(SIMPLE_SCHEMA, SIMPLE_QUERY, "rust-sqlx").expect("codegen must succeed");
    let model_struct = code.model_struct.expect("composite definition must be emitted");
    assert!(
        model_struct.contains("pub struct PublicWidgetShape {"),
        "expected the sanitized type name:\n{model_struct}"
    );
    assert!(
        !model_struct.contains("Public.widgetShape") && !model_struct.contains("Public.widget_shape"),
        "the unsanitized, unparseable form must not appear:\n{model_struct}"
    );
}

// -- nested composite: declaration and reference must derive the identical sanitized name -----
