//! `validation = "jsdoc"`: schema constraints rendered as JSON Schema JSDoc
//! tags on TypeScript row and params properties, `IN (...)` lists as literal
//! unions, and `constraints = "ignore" | "warn" | "error"` deciding what
//! happens to a constraint the output cannot carry.
//!
//! Pinned for every backend that offers the option: `typescript-bun`,
//! `typescript-postgres` and `typescript-pg`.

#![cfg(feature = "lang-typescript")]

use std::collections::HashMap;

use sqlkit_codegen::{CodegenBackend, GeneratedCode, generate_with_backend, get_backend};
use sqlkit_core::analyzer::analyze;
use sqlkit_core::catalog::Catalog;
use sqlkit_core::errors::ErrorCode;
use sqlkit_core::parser::parse_query;

const SCHEMA: &str = "
CREATE DOMAIN slug AS text CHECK (VALUE ~ '^[a-z0-9-]+$');
CREATE DOMAIN amount AS integer CHECK (VALUE BETWEEN 0 AND 100000000);
COMMENT ON DOMAIN amount IS 'An amount in minor units.';
CREATE TABLE causes (
    id serial PRIMARY KEY,
    slug slug NOT NULL,
    title varchar(255) NOT NULL CHECK (length(trim(title)) > 0),
    goal amount,
    raised bigint CHECK (raised >= 0),
    status varchar(20) NOT NULL CHECK (status IN ('draft', 'live')),
    notes text CHECK (notes ~ '\\w')
);
COMMENT ON COLUMN causes.title IS 'What the cause is called.';
";

const GET: &str = "-- @name GetCause\n-- @returns :one\n\
    SELECT id, slug, title, goal, status FROM causes WHERE id = $1;";

const ADD: &str = "-- @name AddCause\n-- @returns :exec\n\
    -- @param $1 slug\n-- @param $2 title\n-- @param $3 goal?\n-- @param $4 status\n\
    INSERT INTO causes (slug, title, goal, status) VALUES ($1, $2, $3, $4);";

const NOTES: &str = "-- @name CauseNotes\n-- @returns :many\nSELECT notes, raised FROM causes;";

const BACKENDS: [&str; 2] = ["typescript-bun", "typescript-postgres"];

fn backend(name: &str, options: &[(&str, &str)]) -> Box<dyn CodegenBackend> {
    let mut backend = get_backend(name).unwrap_or_else(|e| panic!("{name}: {e}"));
    let options: HashMap<String, String> = options
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    backend
        .apply_options(&options)
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    backend
}

fn generate(backend: &dyn CodegenBackend, sql: &str) -> Result<GeneratedCode, sqlkit_core::errors::SqlkitError> {
    let catalog = Catalog::from_ddl(&[SCHEMA]).unwrap();
    let parsed = parse_query(sql).unwrap();
    let analyzed = analyze(&catalog, &parsed).unwrap();
    generate_with_backend(&analyzed, backend)
}

fn text(code: &GeneratedCode) -> String {
    [&code.row_struct, &code.model_struct, &code.query_fn]
        .into_iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn should_render_row_rules_as_jsdoc_tags() {
    for name in BACKENDS {
        let backend = backend(name, &[("validation", "jsdoc")]);
        let out = text(&generate(&*backend, GET).unwrap());
        assert!(
            out.contains("\t/**\n\t * @pattern ^[a-z0-9\\-]+$\n\t */\n\tslug: string;"),
            "{name}:\n{out}"
        );
        assert!(
            out.contains(
                "\t/**\n\t * What the cause is called.\n\t * @minLength 1\n\t * @maxLength 255\n\t * @pattern [^ ]\n\t */\n\ttitle: string;"
            ),
            "{name}:\n{out}"
        );
        assert!(
            out.contains("\t/**\n\t * An amount in minor units.\n\t * @minimum 0\n\t * @maximum 100000000\n\t */\n\tgoal: number | null;"),
            "{name}:\n{out}"
        );
        assert!(
            out.contains("\t * @maxLength 20\n\t */\n\tstatus: \"draft\" | \"live\";"),
            "{name}:\n{out}"
        );
        assert!(
            out.contains("\tid: number;"),
            "{name}: an unconstrained column has no doc:\n{out}"
        );
    }
}

#[test]
fn should_render_written_parameter_rules() {
    for name in BACKENDS {
        let backend = backend(name, &[("validation", "jsdoc"), ("params", "object")]);
        let out = text(&generate(&*backend, ADD).unwrap());
        assert!(
            out.contains("\t * @maxLength 255\n\t * @pattern [^ ]\n\t */\n\ttitle: string;"),
            "{name}:\n{out}"
        );
        assert!(
            out.contains("\t * @maximum 100000000\n\t */\n\tgoal: number | null;"),
            "{name}:\n{out}"
        );
        assert!(out.contains("\tstatus: \"draft\" | \"live\";"), "{name}:\n{out}");
    }
}

#[test]
fn should_render_nothing_without_the_option() {
    for name in BACKENDS {
        let backend = backend(name, &[]);
        let out = text(&generate(&*backend, GET).unwrap());
        assert!(!out.contains("@pattern"), "{name}:\n{out}");
        assert!(out.contains("status: string;"), "{name}:\n{out}");
    }
}

#[test]
fn should_ignore_untranslated_constraints_by_default() {
    let backend = backend("typescript-bun", &[("validation", "jsdoc")]);
    let code = generate(&*backend, NOTES).unwrap();
    assert!(code.constraint_warnings.is_empty());
}

#[test]
fn should_warn_about_untranslated_and_inexpressible_constraints() {
    let backend = backend("typescript-bun", &[("validation", "jsdoc"), ("constraints", "warn")]);
    let code = generate(&*backend, NOTES).unwrap();
    assert_eq!(code.constraint_warnings.len(), 2, "{:?}", code.constraint_warnings);
    assert!(code.constraint_warnings[0].contains("causes.notes CHECK (notes ~ '\\w') is not translated"));
    assert!(
        code.constraint_warnings[1].contains("column 'raised' (string) cannot carry @minimum"),
        "bigint is a string on Bun: {:?}",
        code.constraint_warnings
    );
}

#[test]
fn should_fail_on_untranslated_constraints_under_error() {
    let backend = backend("typescript-bun", &[("validation", "jsdoc"), ("constraints", "error")]);
    let error = generate(&*backend, NOTES).expect_err("an untranslated constraint must fail generation");
    assert_eq!(error.code, ErrorCode::UntranslatedConstraint);
    assert!(error.message.contains("CauseNotes column 'notes'"), "{}", error.message);
    generate(&*backend, GET).expect("fully translated constraints generate");
}

#[test]
fn should_reject_invalid_option_values_and_js_mode() {
    for (key, value) in [("validation", "zod"), ("constraints", "fail")] {
        let mut backend = get_backend("typescript-bun").unwrap();
        let options = HashMap::from([(key.to_string(), value.to_string())]);
        assert!(backend.apply_options(&options).is_err(), "{key} = {value}");
    }
    for name in ["javascript-bun", "javascript-postgres"] {
        let mut backend = get_backend(name).unwrap();
        let options = HashMap::from([("validation".to_string(), "jsdoc".to_string())]);
        assert!(backend.apply_options(&options).is_err(), "{name}");
    }
}
