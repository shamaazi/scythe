//! Regression tests for board #192: every TypeScript backend's
//! `QueryCommand::One | QueryCommand::Opt` match arm rendered byte-identical
//! code -- the permissive `:opt` shape (`{Struct} | null` return type, `null`
//! result on a missing row). `:opt` is correct under that shape; `:one` means
//! "exactly one row, error if absent" and silently returned `null` instead,
//! exactly the shape `opt_command_regression.rs`'s `KNOWN_UNDIFFERENTIATED_BACKENDS`
//! lists every `typescript-*` backend under.
//!
//! The fix (`crates/sqlkit-codegen/src/backends/typescript_common.rs`,
//! `crates/sqlkit-codegen/src/backends/typescript_*.rs`) splits every such arm
//! into `QueryCommand::One` (non-nullable return, throws a plain `Error` naming
//! the query on a missing row) and `QueryCommand::Opt` (unchanged: nullable
//! return, `null` on a missing row). This file asserts that split held for
//! every backend in the family, with exact expected substrings rather than
//! truthiness -- see `crates/sqlkit-codegen/src/backends/typescript_common.rs`'s
//! `ts_row_not_found_throw` for the exact throw text every backend shares.

#![cfg(feature = "lang-typescript")]

use sqlkit_codegen::{generate_with_backend, get_backend};
use sqlkit_core::analyzer::{AnalyzedColumn, AnalyzedQuery};
use sqlkit_core::parser::QueryCommand;

/// A minimal single-column, param-free, non-`RETURNING` query -- same shape
/// as `opt_command_regression.rs`'s `one_column_query`, so both files exercise
/// exactly the branch under test without any RETURNING-clause, enum, or
/// composite special case needing a per-backend fixture. The column is
/// `NOT NULL` so " | null" cannot appear anywhere in the generated body
/// except in `:opt`'s own nullable annotation -- what makes the " | null"
/// substring check below exact rather than incidental.
fn one_column_query(command: QueryCommand) -> AnalyzedQuery {
    AnalyzedQuery::build(|query| {
        query.name = "GetItem".to_string();
        query.command = command;
        query.sql = "SELECT value FROM t WHERE id = 1".to_string();
        query.columns = vec![AnalyzedColumn {
            name: "value".to_string(),
            neutral_type: "string".to_string(),
            nullable: false,
            sql_type: "string".to_string(),
            ..Default::default()
        }];
    })
}

fn query_fn_for(backend_name: &str, command: QueryCommand) -> String {
    let backend =
        get_backend(backend_name).unwrap_or_else(|error| panic!("{backend_name}: backend must construct: {error}"));
    let query = one_column_query(command.clone());
    let generated = generate_with_backend(&query, &*backend)
        .unwrap_or_else(|error| panic!("{backend_name}: codegen failed for {command:?}: {error}"));
    generated
        .query_fn
        .unwrap_or_else(|| panic!("{backend_name}: {command:?} produced no query fn"))
}

/// The TypeScript backend names registered in `get_backend`.
const TS_BACKENDS: &[&str] = &["typescript-bun"];

/// The exact text `ts_row_not_found_throw("GetItem")` renders -- pinned here
/// independently of that function so a change to either drifts loudly rather
/// than the test quietly re-deriving whatever the source currently does.
const EXPECTED_THROW: &str = "throw new Error(\"no row found for query: GetItem\");";

/// #192, split across the family: `:one` never renders " | null" and always
/// renders the exact throw text; `:opt` always renders " | null" and never
/// renders the throw text (or any fragment of it). Both are exact substring
/// checks, not truthiness -- `" | null"` cannot appear in this fixture's
/// output except in a nullable return-type annotation, since the query's one
/// column is `NOT NULL` and no other type in the generated body is optional.
#[test]
fn one_never_renders_nullable_and_always_throws_on_a_missing_row() {
    let mut failures = Vec::new();

    for &name in TS_BACKENDS {
        let one_fn = query_fn_for(name, QueryCommand::One);

        if one_fn.contains(" | null") {
            failures.push(format!(
                "{name}: `:one` must not render a nullable return type; got:\n{one_fn}"
            ));
        }
        if !one_fn.contains(EXPECTED_THROW) {
            failures.push(format!(
                "{name}: `:one` must throw exactly `{EXPECTED_THROW}` on a missing row; got:\n{one_fn}"
            ));
        }
        if one_fn.contains("?? null") || one_fn.contains("return null;") {
            failures.push(format!(
                "{name}: `:one` must not silently return null on a missing row; got:\n{one_fn}"
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} backends violate the `:one` contract (#192):\n{}",
        failures.len(),
        TS_BACKENDS.len(),
        failures.join("\n\n")
    );
}

/// The `:opt` half of the same split: unchanged from before #192 -- still
/// nullable, still returns `null` rather than throwing, on every backend.
#[test]
fn opt_still_renders_nullable_and_never_throws_on_a_missing_row() {
    let mut failures = Vec::new();

    for &name in TS_BACKENDS {
        let opt_fn = query_fn_for(name, QueryCommand::Opt);

        if !opt_fn.contains(" | null") {
            failures.push(format!(
                "{name}: `:opt` must keep rendering a nullable return type; got:\n{opt_fn}"
            ));
        }
        if opt_fn.contains("no row found for query") {
            failures.push(format!(
                "{name}: `:opt` must not throw on a missing row; got:\n{opt_fn}"
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} backends violate the `:opt` contract (#192 must not have touched it):\n{}",
        failures.len(),
        TS_BACKENDS.len(),
        failures.join("\n\n")
    );
}

/// The regression itself, phrased the way #192 (and #197's census before it)
/// named it: before this fix every one of these backends rendered
/// byte-identical code for `:one` and `:opt`.
#[test]
fn one_and_opt_render_different_code_for_every_backend() {
    let mut failures = Vec::new();

    for &name in TS_BACKENDS {
        let one_fn = query_fn_for(name, QueryCommand::One);
        let opt_fn = query_fn_for(name, QueryCommand::Opt);
        if one_fn == opt_fn {
            failures.push(name.to_string());
        }
    }

    assert!(
        failures.is_empty(),
        "{} backends still render identical code for :one and :opt: {:?}",
        failures.len(),
        failures
    );
}
