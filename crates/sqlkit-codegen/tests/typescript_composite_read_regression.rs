//! Regression tests for board #204: `typescript-postgres` declared a nullable composite column on the generated row `interface`
//! (e.g. `homeAddress: WidgetAddress | null`), but read it with nothing more than a
//! compile-time cast (`row.home_address as WidgetAddress | null`, or the driver's own generic
//! type parameter, e.g. `client.query<GetWidgetRow>(...)`). postgres.js registers no
//! decoder for a user-defined composite type (its `src/types.js` has no
//! `record`/`typtype`/composite handling at all) and hands back PostgreSQL's raw composite
//! *text form* (`"(a,b,c)"`), a plain `string`. A TypeScript `as T` cast is compile-time only,
//! so at runtime `row.home_address` is still that string, and `row.home_address.street` reads
//! `undefined` -- silently, with no thrown error.
//!
//! The fix parses the text form by hand through a generated `parse{Name}` function, routed into every read path (`:one`/`:opt`/`:many`, both `field_case`
//! settings, and `:grouped`) via each backend's own `ts_composite_aware_row_access`.
//!
//! A generated `enum::` column needs no equivalent fix: `generate_enum_def` emits a
//! string-literal union (`export type Status = "active" | "inactive"`), which has no runtime
//! representation distinct from the driver's raw string, so the existing `as Status` cast is
//! already correct at runtime -- confirmed by inspecting `generate_enum_def` directly, not
//! assumed.

#![cfg(all(feature = "lang-typescript", feature = "postgres"))]

use sqlkit_codegen::validation::{ToolValidation, strict_mode_enabled, validate_with_tools};
use sqlkit_codegen::{CodegenBackend, GeneratedCode, generate_with_backend, get_backend};
use sqlkit_core::analyzer::analyze;
use sqlkit_core::catalog::Catalog;
use sqlkit_core::dialect::SqlDialect;
use sqlkit_core::parser::parse_query_with_dialect;

/// `inner_thing` covers int32/string/bool composite-field conversion; `widget_address` embeds
/// it as a field (nested-composite recursion). `tag_only` selects `inner_thing` directly, not
/// only nested, the same way `jvm_composite_read_regression.rs`'s schema does and for the same
/// reason: `analyzed.composites` is built by scanning selected columns, not by walking into
/// another composite's own fields.
const SCHEMA: &str = "CREATE TYPE inner_thing AS (n INTEGER, label TEXT, flag BOOLEAN); \
    CREATE TYPE widget_address AS (street TEXT, city TEXT, tag inner_thing); \
    CREATE TABLE widgets (\
    id SERIAL PRIMARY KEY, \
    home_address widget_address, \
    home_address_required widget_address NOT NULL, \
    tag_only inner_thing NOT NULL\
);";

const QUERY: &str = "-- @name GetWidget\n-- @returns :one\n\
    SELECT id, home_address, home_address_required, tag_only FROM widgets WHERE id = $1;";

fn generate(backend: &dyn CodegenBackend, sql: &str) -> GeneratedCode {
    let catalog = Catalog::from_ddl_with_dialect(&[SCHEMA], &SqlDialect::PostgreSQL).expect("schema must parse");
    let parsed = parse_query_with_dialect(sql, &SqlDialect::PostgreSQL).expect("query must parse");
    let analyzed = analyze(&catalog, &parsed).expect("query must analyze");
    generate_with_backend(&analyzed, backend).expect("codegen must succeed")
}

fn backend_for(name: &str) -> Box<dyn CodegenBackend> {
    get_backend(name, "postgresql").expect("backend must support postgresql")
}

fn generated_text(backend_name: &str, sql: &str) -> String {
    let code = generate(&*backend_for(backend_name), sql);
    let mut out = String::new();
    for text in [&code.enum_def, &code.model_struct, &code.row_struct, &code.query_fn]
        .into_iter()
        .flatten()
    {
        out.push_str(text);
        out.push('\n');
    }
    out
}

fn generated_file(backend_name: &str, sql: &str) -> String {
    let backend = backend_for(backend_name);
    let code = generate(&*backend, sql);
    let all = std::slice::from_ref(&code);

    let mut body = backend.file_header_for_results(all);
    body.push('\n');
    for text in [&code.enum_def, &code.model_struct, &code.row_struct, &code.query_fn]
        .into_iter()
        .flatten()
    {
        body.push_str(text);
        body.push('\n');
    }

    sqlkit_codegen::provenance::assemble_file(
        &backend.file_preamble(),
        &sqlkit_codegen::provenance::header_line(
            &*backend,
            env!("CARGO_PKG_VERSION"),
            "postgresql",
            "sch1:0123456789abcdef",
            "q1:fedcba9876543210",
        ),
        &body,
    )
}

fn assert_contains(backend: &str, code: &str, needle: &str, why: &str) {
    assert!(
        code.contains(needle),
        "{backend}: expected `{needle}` ({why});\ngenerated:\n{code}"
    );
}

// -- pg: composite columns route through parse{Name}, never a bare cast -----------------------

// -- postgres.js: same defect, bracket-access row shape -----------------------------------------

#[test]
fn postgres_reads_composite_columns_through_parse_fn_not_bare_cast() {
    let code = generated_text("typescript-postgres", QUERY);
    assert_contains(
        "typescript-postgres",
        &code,
        "home_address: parseWidgetAddress(row['home_address']) as WidgetAddress | null,",
        "postgres.js hands back the composite's raw text form as a string; it must be parsed",
    );
    assert_contains(
        "typescript-postgres",
        &code,
        "tag_only: parseInnerThing(row['tag_only']) as InnerThing,",
        "a composite selected directly, not only nested, must read the same way",
    );
}

#[test]
fn postgres_composite_parse_fn_returns_null_for_a_null_column() {
    let code = generated_text("typescript-postgres", QUERY);
    assert_contains(
        "typescript-postgres",
        &code,
        "export function parseWidgetAddress(raw: unknown): WidgetAddress | null {",
        "the function must accept the driver's untyped value and be able to return null",
    );
    assert_contains(
        "typescript-postgres",
        &code,
        "if (raw === null || raw === undefined) {\n\t\treturn null;\n\t}",
        "a SQL NULL composite column must produce null",
    );
}

// -- the compilers, additively ---------------------------------------------------------------

fn assert_file_compiles(backend_name: &str, file: String) {
    let validation = validate_with_tools(&file, backend_name);

    assert_ne!(
        validation,
        ToolValidation::Unsupported,
        "{backend_name} lost its tool validator; the compile half of this test is now vacuous"
    );
    for tool in validation.tools_run() {
        eprintln!("  {backend_name}: `{tool}` ran against the generated file");
    }
    for tool in validation.missing_tools() {
        eprintln!("  {backend_name}: `{tool}` is not on PATH -- the compile half went unchecked");
    }
    if strict_mode_enabled() {
        assert!(
            validation.fully_checked(),
            "{backend_name}: tool validation reports nothing actually checked the code"
        );
    }
    if let Err(errors) = validation.into_result() {
        panic!("{backend_name} tool validation: {errors:?}\n\nGenerated file:\n{file}");
    }
}

#[test]
fn postgres_composite_read_file_compiles() {
    assert_file_compiles("typescript-postgres", generated_file("typescript-postgres", QUERY));
}
