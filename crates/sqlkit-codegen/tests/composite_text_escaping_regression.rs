//! Every generated composite text-form parser must accept PostgreSQL's *doubled* double-quote.
//!
//! `record_out` escapes a literal `"` inside a quoted composite field by doubling it, and a
//! literal `\` by backslash-escaping it. Captured from PostgreSQL 16 rather than asserted from
//! memory:
//!
//! ```text
//! # SELECT ROW('he said "hi"', 'back\slash', NULL)::esc_probe::text;
//! ("he said ""hi""","back\\slash",)
//! ```
//!
//! Every parser sqlkit emits handled only the backslash spelling. On a doubled quote each one
//! took the first `"` for the field's closing quote, which does two things at once: it truncates
//! that field's value, and -- because the parser then resynchronizes on the wrong character --
//! it shifts every *subsequent* field of the composite by one. A row whose text column merely
//! contains a quote came back with silently wrong values in unrelated fields.
//!

#![cfg_attr(
    not(all(feature = "all-engines", feature = "all-languages")),
    allow(
        dead_code,
        unused_imports,
        unused_macros,
        reason = "helpers shared with tests of backends this build leaves out"
    )
)]

use sqlkit_codegen::get_backend;
use sqlkit_core::analyzer::analyze;
use sqlkit_core::catalog::Catalog;
use sqlkit_core::dialect::SqlDialect;
use sqlkit_core::parser::parse_query_with_dialect;

const SCHEMA: &str = "CREATE TYPE addr AS (street TEXT, city TEXT); \
    CREATE TABLE things (id SERIAL PRIMARY KEY, home addr NOT NULL);";

const QUERY: &str = "-- @name GetThing\n-- @returns :one\nSELECT id, home FROM things WHERE id = $1;";

fn generated_text_for(schema: &str, query: &str, backend_name: &str) -> String {
    let backend = get_backend(backend_name, "postgresql").expect("backend must support postgresql");
    let catalog = Catalog::from_ddl_with_dialect(&[schema], &SqlDialect::PostgreSQL).expect("schema must parse");
    let parsed = parse_query_with_dialect(query, &SqlDialect::PostgreSQL).expect("query must parse");
    let analyzed = analyze(&catalog, &parsed).expect("query must analyze");
    let code = sqlkit_codegen::generate_with_backend(&analyzed, &*backend).expect("codegen must succeed");

    // `file_header_for_results` first, so a helper emitted there is part of what the needles
    // below search.
    let mut out = backend.file_header_for_results(std::slice::from_ref(&code));
    out.push('\n');
    for text in [&code.enum_def, &code.model_struct, &code.row_struct, &code.query_fn]
        .into_iter()
        .flatten()
    {
        out.push_str(text);
        out.push('\n');
    }
    out
}

fn generated_text(backend_name: &str) -> String {
    generated_text_for(SCHEMA, QUERY, backend_name)
}

/// Every backend that emits a hand-written composite parser, paired with the language's
/// spelling of "the next character is also a quote".
///
/// Deliberately a table rather than one test per backend: the defect was identical in all
/// eight, so a new backend copying the same parser -- which is how it spread the first time --
/// should be added here rather than getting its own bespoke assertion.
const PARSER_BACKENDS: &[(&str, &str)] = &[("typescript-postgres", "inner[i + 1] === '\"'")];

#[cfg(all(feature = "lang-typescript", feature = "postgres"))]
#[test]
fn every_generated_composite_parser_handles_a_doubled_quote() {
    for (backend, needle) in PARSER_BACKENDS {
        let code = generated_text(backend);
        assert!(
            code.contains("i + 1 < n") && code.contains(needle),
            "{backend}: the emitted composite parser must treat a doubled double-quote as one \
             escaped quote, not as the field's closing quote -- looked for `{needle}`;\n\
             generated:\n{code}"
        );
    }
}

const NULLABLE_SCHEMA: &str = "CREATE TYPE mood AS ENUM ('happy', 'sad'); \
    CREATE TYPE geo AS (latitude INTEGER); \
    CREATE TYPE profile AS (age INTEGER, mood mood, geo geo); \
    CREATE TABLE profiles (id INTEGER PRIMARY KEY, details profile NOT NULL);";

const NULLABLE_QUERY: &str = "-- @name GetProfile\n-- @returns :one\nSELECT id, details FROM profiles WHERE id = $1;";

#[cfg(all(feature = "lang-typescript", feature = "postgres"))]
#[test]
fn nullable_composite_fields_skip_scalar_and_static_decoders_for_sql_null() {
    let expectations = [(
        "typescript-postgres",
        [
            "age: f[0] === null ? null : Number(f[0])",
            "mood: f[1] === null ? null : f[1] as Mood",
            "geo: f[2] === null ? null : parseGeo(f[2]) as Geo",
        ],
    )];

    for (backend, needles) in expectations {
        let code = generated_text_for(NULLABLE_SCHEMA, NULLABLE_QUERY, backend);
        for needle in needles {
            assert!(
                code.contains(needle),
                "{backend}: missing `{needle}` in generated code:\n{code}"
            );
        }
    }
}
