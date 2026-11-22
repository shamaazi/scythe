//! Regression tests for GH #197: `-- @returns :opt` must be distinguishable
//! from `-- @returns :one` in generated code.
//!
//! `:one` means "exactly one row, error if absent"; `:opt` means "zero or one
//! row, return null/None/Option". A backend that renders both from one shared
//! match arm silently gives one command the other's contract.
//!
//! `rust-tokio-postgres` is the reference shape: `query_one` for `:one`
//! (errors on a missing row through the driver's own `Result`, never panics)
//! and `query_opt` for `:opt` (returns `Option<Row>`, mapped into
//! `Option<Struct>`).
//!
//! Every backend now distinguishes the two, so
//! `KNOWN_UNDIFFERENTIATED_BACKENDS` is empty. It is kept because the ratchet
//! still fails in both directions and an empty list is what makes a new fold
//! show up as a regression instead of as the status quo.

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
use sqlkit_core::analyzer::{AnalyzedColumn, AnalyzedQuery};
use sqlkit_core::parser::QueryCommand;

/// A minimal single-column, param-free, non-`RETURNING` query: it exercises
/// only the `QueryCommand::One`/`QueryCommand::Opt` branch every backend's
/// `generate_query_fn` has, without touching any of the RETURNING-clause,
/// enum, or composite special cases that would need per-backend fixtures.
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

fn query_fn_for(backend_name: &str, engine: &str, command: QueryCommand) -> String {
    let backend = get_backend(backend_name, engine)
        .unwrap_or_else(|error| panic!("{backend_name}/{engine}: backend must support engine: {error}"));
    let query = one_column_query(command.clone());
    let generated = generate_with_backend(&query, &*backend)
        .unwrap_or_else(|error| panic!("{backend_name}/{engine}: codegen failed for {command:?}: {error}"));
    generated
        .query_fn
        .unwrap_or_else(|| panic!("{backend_name}/{engine}: {command:?} produced no query fn"))
}

// ---------------------------------------------------------------------
// Census: does *any* backend actually distinguish :one from :opt?
// ---------------------------------------------------------------------

/// Every backend name [`sqlkit_codegen::get_backend`] recognises as a
/// primary (non-alias) name, mirroring `sqlkit_codegen::lib::tests::
/// ALL_BACKEND_NAMES` (an independent copy, since that list lives
/// in a private `#[cfg(test)] mod tests`).
const ALL_BACKEND_NAMES: &[&str] = &[
    "rust-sqlx",
    "rust-tokio-postgres",
    "typescript-postgres",
    "javascript-postgres",
    "typescript-bun",
    "javascript-bun",
];

/// Tried in order until one resolves the backend's manifest -- mirrors
/// `sqlkit_codegen::lib::tests::backend_for_select_star`'s `ENGINES` list.
/// This census cares whether `:one` and `:opt` diverge at all, not which
/// engine it observes that on.
const ENGINES: &[&str] = &["postgresql"];

fn first_supported_engine(name: &str) -> &'static str {
    for engine in ENGINES {
        if get_backend(name, engine).is_ok() {
            return engine;
        }
    }
    panic!("no known engine works for backend '{name}' -- ALL_BACKEND_NAMES or ENGINES has gone stale");
}

/// One entry in [`KNOWN_UNDIFFERENTIATED_BACKENDS`]: a backend name paired
/// with why its `:one` and `:opt` output is currently identical, so the list
/// doubles as its own documentation -- same shape as
/// `sqlkit_codegen::lib::tests::KNOWN_DIVERGENT_BACKENDS`.
struct BackendNote {
    backend: &'static str,
    reason: &'static str,
}

/// Ratcheting allowlist, same discipline as `lib.rs`'s
/// `KNOWN_DIVERGENT_BACKENDS`: a backend not listed here whose `:one` and
/// `:opt` output is identical is a regression (or, for a backend nobody has
/// fixed yet, evidence the census undercounted -- investigate either way).
/// A backend listed here whose output has started to differ is a stale
/// entry -- the underlying fold was fixed and the line must be deleted, not
/// left to rot.
///
/// Every entry today folds `:one` and `:opt` into ONE SHARED
/// `QueryCommand::One | QueryCommand::Opt` match arm. `rust-sqlx` was
/// fixed and `rust-tokio-postgres` was always correct.
///
/// `rust-sqlx` is worth remembering as what this ratchet is for. It was
/// listed here as folding the way #197 describes -- `:opt` inheriting
/// `:one`'s `.fetch_one` -- and running the census proved that reason wrong.
/// Its `:opt` output declared `{Struct}` as the return type while
/// `has_row_struct` excluded `Opt`, so the body emitted the anonymous-record
/// `sqlx::query!` rather than `sqlx::query_as!`: the declared type and the
/// produced type disagreed, and the generated code did not compile at all.
/// A reason derived by reading match arms missed that, because the defect
/// was in the interaction between three arms, not in any one of them.
const KNOWN_UNDIFFERENTIATED_BACKENDS: &[BackendNote] = &[];

/// Census guard for #197: does every backend actually render different code for `:one` vs.
/// `:opt`? Every backend not in [`KNOWN_UNDIFFERENTIATED_BACKENDS`] must
/// differ; every backend in it must currently still be identical -- a stale
/// entry fails exactly as loudly as a regression, so the allowlist cannot
/// silently rot as backends get fixed (same discipline as
/// `sqlkit_codegen::lib::tests::test_select_star_declares_and_references_the_same_struct_name_across_all_backends`).
///
/// This intentionally does not assert which *direction* a fold goes (`:opt`
/// inheriting `:one`'s strictness, as pre-fix `rust-sqlx` did, or `:one`
/// inheriting `:opt`'s permissiveness) -- both are silent downgrades of
/// one command's contract into the other's, and both are exactly what
/// "a backend silently downgrades :opt" (or, symmetrically, :one) means.
#[cfg(all(feature = "lang-rust", feature = "lang-typescript", feature = "postgres"))]
#[test]
fn one_and_opt_render_different_code_except_on_the_known_allowlist() {
    let mut regressions = Vec::new();
    let mut stale_entries = Vec::new();

    for &name in ALL_BACKEND_NAMES {
        let engine = first_supported_engine(name);
        let one_fn = query_fn_for(name, engine, QueryCommand::One);
        let opt_fn = query_fn_for(name, engine, QueryCommand::Opt);
        let differs = one_fn != opt_fn;

        let listed = KNOWN_UNDIFFERENTIATED_BACKENDS.iter().find(|n| n.backend == name);
        match (differs, listed) {
            (false, None) => regressions.push(name),
            (true, Some(_)) => stale_entries.push(name),
            // Confirmed still undifferentiated for the reason on file --
            // visible with `--nocapture`.
            (false, Some(note)) => eprintln!("expected fold, {name}: {}", note.reason),
            (true, None) => {}
        }
    }

    let mut failures = Vec::new();
    for name in &regressions {
        failures.push(format!(
            "REGRESSION: {name}: :one and :opt render identical code and {name} is not in \
             KNOWN_UNDIFFERENTIATED_BACKENDS -- investigate before adding a line"
        ));
    }
    for name in &stale_entries {
        failures.push(format!(
            "STALE ALLOWLIST: {name}: listed in KNOWN_UNDIFFERENTIATED_BACKENDS but :one and \
             :opt now render different code -- delete its entry"
        ));
    }

    assert!(
        failures.is_empty(),
        "{} of {} backends need attention:\n{}",
        failures.len(),
        ALL_BACKEND_NAMES.len(),
        failures.join("\n")
    );
}
