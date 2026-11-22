//! End-to-end regression tests for the shared SQL-literal escaping layer
//! (`sqlkit_codegen::sql_literal`), exercised through the real
//! parse -> analyze -> codegen pipeline rather than the escape functions in
//! isolation (those are unit-tested directly in `sql_literal.rs`).
//!
//! This closes issues #179 and #150: every backend here previously spliced raw SQL into a host string literal with
//! no escaping at all. Each test below feeds the pipeline SQL containing the
//! exact trigger shape the issue reported and asserts the *escaped* form
//! reaches the generated file, never the raw one.
//!
//! Where a real compiler is on `PATH`, the generated (or a minimal
//! standalone) file is actually compiled or syntax-checked, mirroring
//! `tool_validation.rs`'s `generate_full_file_from_backend` assembly so the
//! bytes handed to the compiler are the same ones `sqlkit generate` would
//! write. A missing tool skips that one assertion rather than failing the
//! test -- consistent with `validation::ToolOutcome::Missing` elsewhere in
//! this crate -- since this suite must still pass on a machine without them.

#![cfg_attr(
    not(feature = "all-languages"),
    allow(
        dead_code,
        unused_imports,
        unused_macros,
        reason = "helpers shared with tests of backends this build leaves out"
    )
)]

use std::process::Command;

use sqlkit_codegen::validation::strict_mode_enabled;
use sqlkit_codegen::{GeneratedCode, generate_with_backend, get_backend, provenance};
use sqlkit_core::analyzer::analyze;
use sqlkit_core::catalog::Catalog;
use sqlkit_core::parser::parse_query;

const SCHEMA: &str = "CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT NOT NULL);";

/// Assemble one query's generated output into a complete file, mirroring
/// `tool_validation.rs`'s `generate_full_file_from_backend` -- real
/// compilers must see the same bytes `sqlkit generate` would write, not a
/// hand-trimmed fragment.
fn generate_full_file(backend_name: &str, query_sql: &str) -> String {
    let backend = get_backend(backend_name).unwrap_or_else(|e| panic!("backend {backend_name} must construct: {e}"));
    let catalog = Catalog::from_ddl(&[SCHEMA]).expect("schema must parse");
    let parsed = parse_query(query_sql).expect("query must parse");
    let analyzed = analyze(&catalog, &parsed).expect("query must analyze");
    let code = generate_with_backend(&analyzed, &*backend).expect("codegen must succeed");
    let codes = [code];

    let mut full = backend.file_header_for_results(&codes);
    full.push('\n');
    push_bodies(&mut full, &codes);

    provenance::assemble_file(
        &backend.file_preamble(),
        &provenance::header_line(
            &*backend,
            env!("CARGO_PKG_VERSION"),
            provenance::ENGINE,
            "sch1:0123456789abcdef",
            "q1:fedcba9876543210",
        ),
        &full,
    )
}

fn push_defs(out: &mut String, code: &GeneratedCode) {
    if let Some(ref s) = code.enum_def {
        out.push_str(s);
        out.push('\n');
    }
    if let Some(ref s) = code.model_struct {
        out.push_str(s);
        out.push('\n');
    }
    if let Some(ref s) = code.row_struct {
        out.push_str(s);
        out.push('\n');
    }
}

fn push_bodies(out: &mut String, codes: &[GeneratedCode]) {
    for code in codes {
        push_defs(out, code);
        if let Some(ref s) = code.query_fn {
            out.push_str(s);
            out.push('\n');
        }
    }
}

/// Write `code` to a fresh temp file with the given extension and return its
/// path. Each call gets a unique name so parallel `cargo test` threads never
/// collide.
fn write_temp(code: &str, ext: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("sqlkit_sql_literal_regression_{n}{ext}"));
    std::fs::write(&path, code).expect("failed to write temp file");
    path
}

/// Run `tool` with `args`; panics with the tool's output if it exits
/// non-zero. Skips rather than panicking when `tool` is not on `PATH`, so this
/// suite still passes on a machine missing that one toolchain -- see the module
/// doc comment.
///
/// ~keep Under `strict_mode_enabled()` the skip becomes a failure. Every
/// assertion in this suite is downstream of a real compiler accepting the
/// escaped output, so a CI image that loses one of these interpreters turns
/// the whole file into a test that passes having checked nothing. Locally the
/// skip is still the right behaviour -- nobody has all ten toolchains.
fn compiles_or_skipped(tool: &str, probe_arg: &str, args: &[&str]) {
    if Command::new(tool).arg(probe_arg).output().is_err() {
        assert!(
            !strict_mode_enabled(),
            "{tool} is not on PATH, so nothing checked the escaped output; \
             strict mode requires every toolchain this suite names"
        );
        eprintln!("skipping {tool} check: not on PATH");
        return;
    }
    let output = Command::new(tool)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("{tool}: could not be executed: {e}"));
    if !output.status.success() {
        panic!(
            "{tool} rejected escaped output:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

// ---------------------------------------------------------------------
// Quote / backslash: breaks non-interpolating host literals outright
// (issue #150's "loud case" and #179's silent-corruption case)
// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
// Rust raw-string delimiter widening (#179's `"#` raw-string-breaking case)
// ---------------------------------------------------------------------

const RUST_HASH_QUOTE_QUERY: &str = "-- @name FindUser\n-- @returns :one\n\
    SELECT id, name FROM users WHERE name = $1 AND name != 'ends with a hash-quote \"# sequence';";

#[cfg(feature = "lang-rust")]
#[test]
fn tokio_postgres_raw_string_widens_delimiter_for_hash_quote() {
    let file = generate_full_file("rust-tokio-postgres", RUST_HASH_QUOTE_QUERY);
    assert!(
        file.contains("r##\"") && file.contains("\"##"),
        "a `\"#` in the SQL must widen the raw-string delimiter:\n{file}"
    );
    assert!(
        file.contains("ends with a hash-quote \"# sequence"),
        "the payload itself must survive verbatim inside the widened literal:\n{file}"
    );
}

/// A minimal standalone Rust snippet, compiled directly, proving the
/// literal-building helpers produce syntactically valid output without
/// depending on external crates/packages the full generated files reference
/// (`tokio-postgres`) that are not resolvable by a bare `rustc` invocation
/// outside a full build.
#[test]
fn rust_raw_string_literal_compiles_standalone() {
    let sql = "ends with a hash-quote \"# sequence and a 'quote' and a \\backslash";
    let literal = sqlkit_codegen::sql_literal::rust_raw_string_literal(sql);
    let source = format!("fn main() {{ let sql = {literal}; assert_eq!(sql, {literal:?}); }}");
    let path = write_temp(&source, ".rs");
    let out = std::env::temp_dir().join("sqlkit_rustc_check_out");
    compiles_or_skipped(
        "rustc",
        "--version",
        &["--edition", "2024", "-o", out.to_str().unwrap(), path.to_str().unwrap()],
    );
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&out);
}
