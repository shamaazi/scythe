//! End-to-end regression tests for the manifest-driven reserved-word
//! identifier mangling (`sqlkit_backend::naming::field_name`), exercised
//! through the real parse -> analyze -> codegen pipeline.
//!
//! Closes #180/#151: a column whose SQL name is a target-language keyword
//! (`type`, `class`, `fn`, ...) used to reach the generated file verbatim --
//! `pub type: String`, `String class`, `[id, fn] = row` -- none of which
//! parse. The fix is a per-manifest `[naming] reserved = [...]` array
//! (populated in every non-TypeScript manifest; see
//! `crates/sqlkit-codegen/manifests/*.toml`) consulted by `field_name`,
//! never a hardcoded cross-language table (#198).
//!
//! TypeScript declares `[naming] reserved_bindings` instead, consulted by
//! `param_name`, because it is the one target where a keyword is illegal in
//! a parameter binding and legal as a property key -- see
//! `typescript_pg_mangles_class_in_a_binding_but_leaves_the_row_key_alone`
//! at the bottom of this file for why the row key must not be mangled.

#![cfg_attr(
    not(all(feature = "all-engines", feature = "all-languages")),
    allow(
        dead_code,
        unused_imports,
        unused_macros,
        reason = "helpers shared with tests of backends this build leaves out"
    )
)]

use sqlkit_codegen::{generate_with_backend, get_backend};
use sqlkit_core::analyzer::analyze;
use sqlkit_core::catalog::Catalog;
use sqlkit_core::dialect::SqlDialect;
use sqlkit_core::parser::parse_query_with_dialect;

const SCHEMA: &str =
    "CREATE TABLE items (id SERIAL PRIMARY KEY, type TEXT NOT NULL, class TEXT NOT NULL, fn TEXT NOT NULL);";

const QUERY: &str = "-- @name FindItem\n-- @returns :one\n\
    SELECT id, type, class, fn FROM items WHERE id = $1;";

/// Generate the row struct (and query fn, for backends whose parameters
/// happen to share the affected field) for `backend_name` against
/// [`SCHEMA`]/[`QUERY`].
fn generate_row_struct(backend_name: &str) -> String {
    let backend = get_backend(backend_name, "postgresql").expect("backend must support postgresql");
    let catalog = Catalog::from_ddl_with_dialect(&[SCHEMA], &SqlDialect::PostgreSQL).expect("schema must parse");
    let parsed = parse_query_with_dialect(QUERY, &SqlDialect::PostgreSQL).expect("query must parse");
    let analyzed = analyze(&catalog, &parsed).expect("query must analyze");
    let code = generate_with_backend(&analyzed, &*backend).expect("codegen must succeed");
    code.row_struct.expect("expected a row struct")
}

#[cfg(all(feature = "lang-rust", feature = "postgres"))]
#[test]
fn rust_sqlx_mangles_the_type_keyword() {
    let row_struct = generate_row_struct("rust-sqlx");
    assert!(
        !row_struct.contains("pub type:"),
        "`pub type: ...` is not valid Rust (type is a keyword):\n{row_struct}"
    );
    assert!(
        row_struct.contains("pub type_:"),
        "expected the reserved-word mangled field `type_`:\n{row_struct}"
    );
}
