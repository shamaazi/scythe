//! End-to-end regression tests for #215: a column name that is not a valid
//! TypeScript identifier (`with-dash`, `my col`, `1st`, `2fa`, `it's`) must
//! never reach a generated file in a position that requires one.
//!
//! There are three such positions, and the original fix only covered the
//! first:
//!
//! 1. a declared property key -- `interface R { my col: string }` is
//!    `TS1131`; `"my col": string` is fine;
//! 2. a property *read* off a driver row or a batch item -- `row.my col`
//!    and `item.2fa` do not parse either, and `row['it's']` closes its own
//!    string literal;
//! 3. a function parameter binding -- `function f(my col: string)`. This one
//!    has no quoted form, so the name is mangled instead (`my_col`) by
//!    `sqlkit_backend::naming::param_name`, which is cross-language and not
//!    a TypeScript decision. Closed by #168; see
//!    `a_scalar_parameter_named_after_a_non_identifier_column_is_mangled` at
//!    the bottom of this file.
//!
//! Exercised through the real parse -> analyze -> codegen pipeline. String
//! assertions are unconditional; the external checkers (`poly` via
//! `validate_with_tools`, and `tsc --strict` when it is on `PATH`) are
//! additive on top -- a machine without them still fails on a regression.

#![cfg_attr(
    not(feature = "all-languages"),
    allow(
        dead_code,
        unused_imports,
        unused_macros,
        reason = "helpers shared with tests of backends this build leaves out"
    )
)]

use std::collections::HashMap;
use std::process::Command;

use sqlkit_codegen::validation::{strict_mode_enabled, validate_with_tools};
use sqlkit_codegen::{CodegenBackend, GeneratedCode, generate_with_backend, get_backend, provenance};
use sqlkit_core::analyzer::analyze;
use sqlkit_core::catalog::Catalog;
use sqlkit_core::parser::parse_query;

/// Every TypeScript backend.
const TS_BACKENDS: [&str; 1] = ["typescript-bun"];

/// A schema/query pair whose column names need quoting.
fn fixture() -> (&'static str, [&'static str; 3]) {
    (
        "CREATE TABLE weird (\
                id INT PRIMARY KEY, \
                \"with-dash\" VARCHAR(50) NOT NULL, \
                \"my col\" VARCHAR(50) NOT NULL, \
                \"2fa\" VARCHAR(50) NOT NULL\
            );",
        [
            "-- @name FindWeird\n-- @returns :one\n\
                 SELECT id, \"with-dash\", \"my col\", \"2fa\" FROM weird WHERE id = $1;",
            "-- @name ListWeird\n-- @returns :many\n\
                 SELECT id, \"with-dash\", \"my col\", \"2fa\" FROM weird;",
            "-- @name AddWeird\n-- @returns :batch\n\
                 INSERT INTO weird (\"with-dash\", \"my col\", \"2fa\") VALUES ($1, $2, $3);",
        ],
    )
}

/// The three keys every fixture projects, spelled as they must appear in the
/// generated file: quoted.
const QUOTED_KEYS: [&str; 3] = ["\"with-dash\"", "\"my col\"", "\"2fa\""];

/// The same three, spelled as a bare identifier -- what #215 emitted.
///
/// Anchored to the tab that opens a declaration line as well as the trailing
/// `:`, so the search matches a *key* position and not the same characters
/// inside a quoted key, inside the SQL text, or at the tail of a mangled
/// param binding: `2fa:` alone also matches the `_2fa:` that `param_name`
/// now emits, which is the fix and not the defect.
const BARE_KEYS: [&str; 3] = ["\twith-dash:", "\tmy col:", "\t2fa:"];

fn generate_all(backend: &dyn CodegenBackend) -> Vec<GeneratedCode> {
    let (schema, queries) = fixture();
    let catalog = Catalog::from_ddl(&[schema]).expect("schema must parse");
    queries
        .iter()
        .map(|sql| {
            let parsed = parse_query(sql).expect("query must parse");
            let analyzed = analyze(&catalog, &parsed).expect("query must analyze");
            generate_with_backend(&analyzed, backend).expect("codegen must succeed")
        })
        .collect()
}

/// Assemble the generated pieces into the file `sqlkit generate` would
/// write, so the checkers below see the same bytes.
fn assemble(backend: &dyn CodegenBackend, codes: &[GeneratedCode]) -> String {
    let mut body = backend.file_header_for_results(codes);
    body.push('\n');
    for code in codes {
        for text in [&code.row_struct, &code.query_fn].into_iter().flatten() {
            body.push_str(text);
            body.push_str("\n\n");
        }
    }
    provenance::assemble_file(
        &provenance::header_line(
            backend,
            env!("CARGO_PKG_VERSION"),
            provenance::ENGINE,
            "sch1:0123456789abcdef",
            "q1:fedcba9876543210",
        ),
        &body,
    )
}

fn build(backend_name: &str, options: &HashMap<String, String>) -> Box<dyn CodegenBackend> {
    let mut backend = get_backend(backend_name).unwrap_or_else(|e| panic!("{backend_name} must construct: {e}"));
    backend.apply_options(options).expect("options must apply");
    backend
}

/// Run the repository's own TypeScript checker over `file`, and -- in strict
/// mode -- fail if it was not actually installed. Never a substitute for the
/// string assertions each caller makes first.
fn tool_check(backend_name: &str, file: &str) {
    let validation = validate_with_tools(file, backend_name);
    assert!(
        validation.errors().is_empty(),
        "{backend_name}: tool validation reported:\n{:#?}\n\nfile:\n{file}",
        validation.errors()
    );
    if strict_mode_enabled() {
        assert!(
            validation.fully_checked(),
            "{backend_name}: strict mode requires every checker to have run, got {:?} run / {:?} missing",
            validation.tools_run(),
            validation.missing_tools()
        );
    }
}

/// This must fail before the fix on every backend: a `:batch` params
/// interface spliced `p.field_name` in bare (`2fa: string;`), the per-item
/// bind read it back with `item.2fa`, and the pg row remaps read
/// driver rows with `row.my col`.
#[cfg(feature = "lang-typescript")]
#[test]
fn every_typescript_backend_quotes_non_identifier_column_names() {
    for backend_name in TS_BACKENDS {
        let backend = build(backend_name, &HashMap::new());
        let codes = generate_all(&*backend);
        let file = assemble(&*backend, &codes);

        for quoted in QUOTED_KEYS {
            assert!(
                file.contains(&format!("{quoted}:")),
                "{backend_name}: expected the quoted key {quoted} in:\n{file}"
            );
        }
        for bare in BARE_KEYS {
            assert!(
                !file.contains(bare),
                "{backend_name}: `{bare}` is a bare non-identifier key (#215) in:\n{file}"
            );
        }
        // The read side: `item.2fa` / `row.my col` do not parse either.
        for bare in ["item.with-dash", "item.my col", "item.2fa", "row.my col", "row.2fa"] {
            assert!(
                !file.contains(bare),
                "{backend_name}: `{bare}` is not a valid property read (#215) in:\n{file}"
            );
        }

        tool_check(backend_name, &file);
    }
}

/// This must fail before the fix: the bracket-access read paths spliced the
/// column name into a single-quoted JS string without escaping, so a column
/// named `it's` produced `row['it's']` -- the literal closes after `it`.
#[cfg(feature = "lang-typescript")]
#[test]
fn an_apostrophe_in_a_column_name_is_escaped_in_bracket_reads() {
    const SCHEMA: &str = "CREATE TABLE weird (id INT PRIMARY KEY, \"it's\" TEXT NOT NULL);";
    const QUERY: &str = "-- @name FindWeird\n-- @returns :many\nSELECT id, \"it's\" FROM weird;";

    let options = HashMap::from([("field_case".to_string(), "camelCase".to_string())]);
    for backend_name in TS_BACKENDS {
        let backend = build(backend_name, &options);
        let catalog = Catalog::from_ddl(&[SCHEMA]).unwrap();
        let parsed = parse_query(QUERY).unwrap();
        let analyzed = analyze(&catalog, &parsed).unwrap();
        let code = generate_with_backend(&analyzed, &*backend).unwrap();
        let query_fn = code.query_fn.expect("expected a query fn");

        assert!(
            !query_fn.contains("['it's']"),
            "{backend_name}: an unescaped apostrophe closes the key literal:\n{query_fn}"
        );
        assert!(
            query_fn.contains("['it\\'s']") || query_fn.contains("[\"it's\"]"),
            "{backend_name}: expected an escaped or double-quoted key:\n{query_fn}"
        );
    }
}

/// Real `tsc --strict` over the declarations and object literals #215 is
/// about, assembled standalone so no driver package has to be installed.
/// Additive: the assertions above already fail on a regression without it.
#[test]
fn tsc_accepts_the_quoted_declarations_and_reads() {
    let source = "export interface WeirdRow {\n\
         \t\"with-dash\": string;\n\
         \t\"my col\": string;\n\
         \t\"2fa\": string;\n\
         }\n\
         const raw: Record<string, unknown> = {};\n\
         export const row: WeirdRow = {\n\
         \t\"with-dash\": raw['with-dash'] as string,\n\
         \t\"my col\": raw[\"my col\"] as string,\n\
         \t\"2fa\": raw['it\\'s'] as string,\n\
         };\n";

    if Command::new("tsc").arg("--version").output().is_err() {
        assert!(!strict_mode_enabled(), "strict mode requires tsc to be installed");
        eprintln!("skipping tsc check: not on PATH");
        return;
    }
    let path = std::env::temp_dir().join("sqlkit_ts_identifier_quoting_check.ts");
    std::fs::write(&path, source).expect("failed to write temp file");
    let output = Command::new("tsc")
        .args(["--strict", "--noEmit", "--target", "es2022", path.to_str().unwrap()])
        .output()
        .expect("tsc could not be executed");
    let _ = std::fs::remove_file(&path);
    assert!(
        output.status.success(),
        "tsc rejected the quoted declarations:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
