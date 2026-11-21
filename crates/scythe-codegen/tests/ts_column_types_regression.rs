//! `column_types = "<module>"`: every row and params property that reads or
//! writes a table column unchanged is declared `Column<'table.column', T>`,
//! with `T` the type it would have had and `| null` outside, and the file
//! imports the module's `Column` once, only when a declaration names it.
//!
//! Pinned for every backend that offers the option: `typescript-bun`,
//! `typescript-postgres` and `typescript-pg`.

#![cfg(all(feature = "lang-typescript", feature = "postgres"))]

use std::collections::HashMap;

use scythe_codegen::{CodegenBackend, GeneratedCode, generate_with_backend, get_backend};
use scythe_core::analyzer::analyze;
use scythe_core::catalog::Catalog;
use scythe_core::dialect::SqlDialect;
use scythe_core::parser::parse_query_with_dialect;

const SCHEMA: &str = "
CREATE TYPE frequency AS ENUM ('monthly', 'yearly');
CREATE TABLE public.schedules (
    id serial PRIMARY KEY,
    causes jsonb NOT NULL,
    metadata jsonb,
    status text NOT NULL CHECK (status IN ('active', 'paused')),
    frequency frequency NOT NULL,
    amount integer NOT NULL CHECK (amount > 0),
    counts integer[]
);
CREATE VIEW active_schedules AS SELECT id, causes, amount * 2 AS doubled FROM schedules WHERE status = 'active';
";

const GET: &str = "-- @name GetSchedule\n-- @returns :one\n\
    SELECT id, causes, metadata, status, frequency, amount + 1 AS next_amount FROM schedules WHERE id = $1;";

const ADD: &str = "-- @name AddSchedule\n-- @returns :exec\n\
    -- $1: causes\n-- $2: metadata?\n-- $3: status\n-- $4: frequency\n-- $5: amount\n\
    INSERT INTO schedules (causes, metadata, status, frequency, amount) VALUES ($1, $2, $3, $4, $5 * 100);";

const ACTIVE: &str = "-- @name ActiveSchedules\n-- @returns :many\nSELECT id, causes, doubled FROM active_schedules;";

const AMOUNTS: &str = "-- @name ScheduleAmounts\n-- @returns :many\nSELECT amount, counts FROM schedules;";

const COUNT: &str = "-- @name CountSchedules\n-- @returns :one\nSELECT count(*) AS total FROM schedules;";

const MODULE: &str = "@app/database/columns";

const BACKENDS: [&str; 3] = ["typescript-bun", "typescript-postgres", "typescript-pg"];

fn backend(name: &str, options: &[(&str, &str)]) -> Box<dyn CodegenBackend> {
    let mut backend = get_backend(name, "postgresql").unwrap_or_else(|e| panic!("{name}: {e}"));
    let options: HashMap<String, String> = options
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    backend
        .apply_options(&options)
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    backend
}

fn generate(backend: &dyn CodegenBackend, sql: &str) -> GeneratedCode {
    let catalog = Catalog::from_ddl_with_dialect(&[SCHEMA], &SqlDialect::PostgreSQL).unwrap();
    let parsed = parse_query_with_dialect(sql, &SqlDialect::PostgreSQL).unwrap();
    let analyzed = analyze(&catalog, &parsed).unwrap();
    generate_with_backend(&analyzed, backend).unwrap()
}

fn text(code: &GeneratedCode) -> String {
    [&code.row_struct, &code.model_struct, &code.query_fn]
        .into_iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>()
        .join("\n")
}

fn json(name: &str) -> &'static str {
    if name == "typescript-postgres" {
        "PostgresJsonValue"
    } else if name == "typescript-bun" {
        "SqlJsonValue"
    } else {
        "Record<string, unknown>"
    }
}

#[test]
fn should_declare_row_properties_by_their_column() {
    for name in BACKENDS {
        let backend = backend(name, &[("column_types", MODULE)]);
        let out = text(&generate(&*backend, GET));
        let json = json(name);
        for property in [
            "\tid: Column<'schedules.id', number>;".to_string(),
            format!("\tcauses: Column<'schedules.causes', {json}>;"),
            format!("\tmetadata: Column<'schedules.metadata', {json}> | null;"),
            "\tstatus: Column<'schedules.status', string>;".to_string(),
            "\tfrequency: Column<'schedules.frequency', Frequency>;".to_string(),
            "\tnext_amount: number;".to_string(),
        ] {
            assert!(out.contains(&property), "{name}: expected {property}:\n{out}");
        }
    }
}

#[test]
fn should_keep_constrained_literal_unions_as_the_own_type() {
    for name in BACKENDS {
        let backend = backend(name, &[("column_types", MODULE), ("validation", "jsdoc")]);
        let out = text(&generate(&*backend, GET));
        assert!(
            out.contains("\tstatus: Column<'schedules.status', \"active\" | \"paused\">;"),
            "{name}:\n{out}"
        );
    }
}

#[test]
fn should_declare_written_parameters_by_their_column() {
    for name in BACKENDS {
        let backend = backend(name, &[("column_types", MODULE), ("params", "object")]);
        let out = text(&generate(&*backend, ADD));
        // Bun binds any value through `sql.json`.
        let json = if name == "typescript-bun" {
            "unknown"
        } else {
            json(name)
        };
        for property in [
            format!("\tcauses: Column<'schedules.causes', {json}>;"),
            format!("\tmetadata: Column<'schedules.metadata', {json}> | null;"),
            "\tstatus: Column<'schedules.status', string>;".to_string(),
            "\tamount: number;".to_string(),
        ] {
            assert!(out.contains(&property), "{name}: expected {property}:\n{out}");
        }
    }
}

#[test]
fn should_resolve_view_columns_to_their_table_column() {
    for name in BACKENDS {
        let backend = backend(name, &[("column_types", MODULE)]);
        let out = text(&generate(&*backend, ACTIVE));
        let json = json(name);
        assert!(
            out.contains(&format!("\tcauses: Column<'schedules.causes', {json}>;")),
            "{name}:\n{out}"
        );
        assert!(
            out.contains("\tdoubled: Column<'active_schedules.doubled', number>;"),
            "{name}: a computed view column is the view's own:\n{out}"
        );
    }
}

#[test]
fn should_import_column_once_and_only_when_used() {
    let import = format!("import type {{ Column }} from \"{MODULE}\";\n");
    for name in BACKENDS {
        let backend = backend(name, &[("column_types", MODULE)]);
        let used = [generate(&*backend, GET), generate(&*backend, ADD)];
        let header = backend.file_header_for_results(&used);
        assert_eq!(header.matches(&import).count(), 1, "{name}:\n{header}");

        let unused = [generate(&*backend, COUNT)];
        let header = backend.file_header_for_results(&unused);
        assert!(!header.contains("Column"), "{name}:\n{header}");
    }
}

#[test]
fn should_leave_output_unchanged_without_the_option() {
    for name in BACKENDS {
        let plain = backend(name, &[]);
        for sql in [GET, ADD, ACTIVE] {
            let code = generate(&*plain, sql);
            let out = text(&code);
            assert!(!out.contains("Column<"), "{name}:\n{out}");
            assert!(!plain.file_header_for_results(&[code]).contains("Column"), "{name}");
        }
    }
}

#[test]
fn should_reject_invalid_modules_zod_and_js_mode() {
    for options in [
        vec![("column_types", "")],
        vec![("column_types", "mod\"ule")],
        vec![("row_type", "zod"), ("column_types", MODULE)],
    ] {
        for name in BACKENDS {
            let mut backend = get_backend(name, "postgresql").unwrap();
            let options: HashMap<String, String> = options
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect();
            assert!(backend.apply_options(&options).is_err(), "{name}: {options:?}");
        }
    }
    for name in ["javascript-bun", "javascript-postgres", "javascript-pg"] {
        let mut backend = get_backend(name, "postgresql").unwrap();
        let options = HashMap::from([("column_types".to_string(), MODULE.to_string())]);
        assert!(backend.apply_options(&options).is_err(), "{name}");
    }
}

#[test]
fn should_keep_validation_tags_and_bun_typed_arrays_on_the_own_type() {
    for name in BACKENDS {
        let backend = backend(name, &[("column_types", MODULE), ("validation", "jsdoc")]);
        let out = text(&generate(&*backend, AMOUNTS));
        assert!(
            out.contains("\t * @exclusiveMinimum 0\n\t */\n\tamount: Column<'schedules.amount', number>;"),
            "{name}:\n{out}"
        );
        let counts = if name == "typescript-bun" {
            "\tcounts: Column<'schedules.counts', Int32Array | Array<number>> | null;"
        } else {
            "\tcounts: Column<'schedules.counts', Array<number>> | null;"
        };
        assert!(out.contains(counts), "{name}:\n{out}");
    }
}

#[test]
fn should_cast_remapped_camel_case_rows_to_the_column_type() {
    for name in BACKENDS {
        let backend = backend(name, &[("column_types", MODULE), ("field_case", "camelCase")]);
        let out = text(&generate(&*backend, GET));
        assert!(
            out.contains("\tnextAmount: number;") && out.contains("as Column<'schedules.metadata', "),
            "{name}:\n{out}"
        );
    }
}
