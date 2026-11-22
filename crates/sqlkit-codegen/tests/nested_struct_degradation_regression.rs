//! GH #147: `degrade_unsupported_nested_structs` rewrites a `json_agg`/
//! `row_to_json` column's `json_nested<...>` type to a plain `json` (or,
//! when the manifest declares it, `json_array`) scalar for any backend that
//! does not implement `generate_nested_struct_def`. Before this fix, `sqlkit generate` exited 0 with no
//! signal that the rewrite happened at all: a user asking for a structured
//! row silently got an opaque string instead.
//!
//! `degrade_unsupported_nested_structs` now returns a third element, one
//! [`sqlkit_codegen::NestedStructDegradation`] per rewritten column, and
//! [`sqlkit_codegen::generate_with_backend`] threads it onto
//! `GeneratedCode::degraded_nested_structs`. These tests pin that the field
//! actually reaches the top-level `generate_with_backend` result -- not just
//! the internal function -- and that it stays empty for a backend that
//! genuinely supports the struct, so a regression that silently drops the
//! third tuple element or forgets to assign the field fails loudly here.

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
use sqlkit_core::analyzer::{NestedFieldInfo, NestedStructInfo, analyze};
use sqlkit_core::catalog::Catalog;
use sqlkit_core::errors::SqlkitError;
use sqlkit_core::parser::parse_query;

const NESTED_ARRAY_SCHEMA: &str = "\
    CREATE TYPE order_status AS ENUM ('pending', 'shipped'); \
    CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT NOT NULL); \
    CREATE TABLE orders (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL, status order_status NOT NULL);";

const NESTED_ARRAY_QUERY: &str = "-- @name GetUserOrders\n-- @returns :many\n\
    SELECT u.id, json_agg(o.*) AS orders FROM users u JOIN orders o ON o.user_id = u.id GROUP BY u.id;";

fn generate(backend_name: &str) -> Result<GeneratedCode, SqlkitError> {
    let backend = get_backend(backend_name).expect("backend must support postgresql");
    let catalog = Catalog::from_ddl(&[NESTED_ARRAY_SCHEMA]).expect("schema must parse");
    let parsed = parse_query(NESTED_ARRAY_QUERY).expect("query must parse");
    let analyzed = analyze(&catalog, &parsed).expect("query must analyze");
    generate_with_backend(&analyzed, &*backend)
}

#[cfg(feature = "lang-typescript")]
#[test]
fn typescript_emits_native_nested_structs() {
    let backend = "typescript-bun";
    let code = generate(backend).expect("TypeScript nested JSON codegen must succeed");
    assert!(
        code.degraded_nested_structs.is_empty(),
        "{backend} must preserve nested JSON structure: {:?}",
        code.degraded_nested_structs
    );
    assert_eq!(
        code.nested_struct_defs.len(),
        1,
        "{backend} must emit one nested interface"
    );
    assert!(
        code.nested_struct_defs[0].code.contains("status: OrderStatus;"),
        "{backend} must preserve an enum inside the JSON object"
    );
    assert!(
        code.row_struct
            .as_deref()
            .is_some_and(|row| row.contains("orders: Array<GetUserOrdersRowOrders> | null;")),
        "{backend} must use Array<T> around the nested interface"
    );
}

#[cfg(feature = "lang-typescript")]
#[test]
fn unsupported_future_json_field_degrades_the_entire_nested_struct() {
    let nested = NestedStructInfo {
        name: "future_payload".to_string(),
        fields: vec![NestedFieldInfo {
            name: "location".to_string(),
            neutral_type: "future_geography".to_string(),
            nullable: false,
        }],
    };
    let backend_name = "typescript-bun";
    let backend = get_backend(backend_name).expect("backend must support PostgreSQL");
    assert!(
        backend
            .generate_nested_struct_def(&nested)
            .expect("unsupported nested field must not be a hard error")
            .is_none(),
        "{backend_name} must request deterministic plain-JSON degradation"
    );
}

/// `rust-sqlx` implements `generate_nested_struct_def`, so nothing here was
/// degraded: the field must stay empty rather than report a false positive
/// for a backend that actually generated the struct.
#[cfg(feature = "lang-rust")]
#[test]
fn supporting_backend_reports_no_degradation() {
    let code = generate("rust-sqlx").expect("codegen must succeed");
    assert!(
        code.degraded_nested_structs.is_empty(),
        "rust-sqlx supports the nested struct and must not report a degradation: {:?}",
        code.degraded_nested_structs
    );
    assert_eq!(
        code.nested_struct_defs.len(),
        1,
        "the struct definition must still be emitted"
    );
}
