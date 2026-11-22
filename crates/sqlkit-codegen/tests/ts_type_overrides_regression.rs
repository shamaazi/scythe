//! `type_overrides` entries with `ts_type` (and `ts_import`): a matched row or
//! params property is declared with that TypeScript type, with `| null`
//! outside, while binding, validation and Bun's typed arrays keep working off
//! the value's own type. The file imports each `ts_import` module once, naming
//! only the types it uses.
//!
//! Pinned on `typescript-bun`, the TypeScript backend.

#![cfg(feature = "lang-typescript")]

use std::collections::HashMap;

use sqlkit_codegen::overrides::TsTypeOverride;
use sqlkit_codegen::{CodegenBackend, GeneratedCode, TypeOverride, generate_with_backend_and_overrides, get_backend};
use sqlkit_core::analyzer::analyze;
use sqlkit_core::catalog::Catalog;
use sqlkit_core::parser::parse_query;

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
    -- @param $1 causes\n-- @param $2 metadata?\n-- @param $3 status\n-- @param $4 frequency\n-- @param $5 amount\n\
    INSERT INTO schedules (causes, metadata, status, frequency, amount) VALUES ($1, $2, $3, $4, $5 * 100);";

const BY_STATUS: &str = "-- @name CountByStatus\n-- @returns :one\n\
    SELECT count(*) AS total FROM schedules WHERE status = $1;";

const ACTIVE: &str = "-- @name ActiveSchedules\n-- @returns :many\nSELECT id, causes, doubled FROM active_schedules;";

const AMOUNTS: &str = "-- @name ScheduleAmounts\n-- @returns :many\nSELECT amount, counts FROM schedules;";

const COUNT: &str = "-- @name CountSchedules\n-- @returns :one\nSELECT count(*) AS total FROM schedules;";

const MODULE: &str = "@app/database/columns";

const BACKENDS: [&str; 1] = ["typescript-bun"];

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

fn by_column(column: &str, ts_type: &str, import: Option<&str>) -> TypeOverride {
    TypeOverride {
        column: Some(column.to_string()),
        ts_type: Some(TsTypeOverride {
            ts_type: ts_type.to_string(),
            import: import.map(str::to_string),
        }),
        ..Default::default()
    }
}

/// `schedules.causes` and `schedules.counts` by imported names,
/// `schedules.metadata` and `schedules.status` inline, and the view's own
/// computed `active_schedules.doubled`.
fn overrides() -> Vec<TypeOverride> {
    vec![
        by_column("schedules.causes", "SourceCauses", Some(MODULE)),
        by_column("schedules.metadata", "Record<string, unknown>", None),
        by_column("schedules.status", "'active' | 'paused' | 'archived'", None),
        by_column("schedules.counts", "Counts", Some(MODULE)),
        by_column("active_schedules.doubled", "Doubled", Some("@app/other")),
    ]
}

fn generate(backend: &dyn CodegenBackend, sql: &str) -> GeneratedCode {
    let catalog = Catalog::from_ddl(&[SCHEMA]).unwrap();
    let parsed = parse_query(sql).unwrap();
    let analyzed = analyze(&catalog, &parsed).unwrap();
    generate_with_backend_and_overrides(&analyzed, backend, &overrides()).unwrap()
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
fn should_declare_row_properties_by_their_override() {
    for name in BACKENDS {
        let backend = backend(name, &[]);
        let out = text(&generate(&*backend, GET));
        for property in [
            "\tid: number;",
            "\tcauses: SourceCauses;",
            "\tmetadata: Record<string, unknown> | null;",
            "\tstatus: 'active' | 'paused' | 'archived';",
            "\tfrequency: Frequency;",
            "\tnext_amount: number;",
        ] {
            assert!(out.contains(property), "{name}: expected {property}:\n{out}");
        }
    }
}

/// A constraint-narrowed literal union is replaced by the override, which
/// still carries the schema's validation tags.
#[test]
fn should_replace_constrained_literal_unions_and_keep_tags() {
    for name in BACKENDS {
        let backend = backend(name, &[("validation", "jsdoc")]);
        let out = text(&generate(&*backend, GET));
        assert!(
            out.contains("\tstatus: 'active' | 'paused' | 'archived';"),
            "{name}:\n{out}"
        );
        let out = text(&generate(&*backend, AMOUNTS));
        assert!(
            out.contains("\t * @exclusiveMinimum 0\n\t */\n\tamount: number;"),
            "{name}:\n{out}"
        );
    }
}

/// Parameters written into a column, and those compared with it, are declared
/// by its override, while the value is still bound by its own type.
#[test]
fn should_declare_written_and_compared_parameters_by_their_override() {
    for name in BACKENDS {
        let backend = backend(name, &[("params", "object")]);
        let out = text(&generate(&*backend, ADD));
        for property in [
            "\tcauses: SourceCauses;",
            "\tmetadata: Record<string, unknown> | null;",
            "\tstatus: 'active' | 'paused' | 'archived';",
            "\tamount: number;",
        ] {
            assert!(out.contains(property), "{name}: expected {property}:\n{out}");
        }
        assert!(
            out.contains("${sql.json(params.causes)}"),
            "{name}: binding keeps the json type:\n{out}"
        );
        let out = text(&generate(&*backend, BY_STATUS));
        assert!(
            out.contains("\tstatus: 'active' | 'paused' | 'archived';"),
            "{name}:\n{out}"
        );
    }
}

#[test]
fn should_resolve_view_columns_to_their_table_column() {
    for name in BACKENDS {
        let backend = backend(name, &[]);
        let out = text(&generate(&*backend, ACTIVE));
        assert!(out.contains("\tcauses: SourceCauses;"), "{name}:\n{out}");
        assert!(
            out.contains("\tdoubled: Doubled;"),
            "{name}: a computed view column matches by the view's name:\n{out}"
        );
    }
}

/// Bun widens an `integer[]` column to `Int32Array | Array<number>`; one an
/// override declares keeps the declared type, and one without keeps widening.
#[test]
fn should_leave_bun_typed_arrays_to_the_override() {
    let backend = backend("typescript-bun", &[]);
    let out = text(&generate(&*backend, AMOUNTS));
    assert!(out.contains("\tcounts: Counts | null;"), "{out}");
    let catalog = Catalog::from_ddl(&[SCHEMA]).unwrap();
    let parsed = parse_query(AMOUNTS).unwrap();
    let analyzed = analyze(&catalog, &parsed).unwrap();
    let plain = text(&generate_with_backend_and_overrides(&analyzed, &*backend, &[]).unwrap());
    assert!(
        plain.contains("\tcounts: Int32Array | Array<number> | null;"),
        "{plain}"
    );
}

#[test]
fn should_import_each_module_once_naming_only_used_types() {
    for name in BACKENDS {
        let backend = backend(name, &[]);
        let used = [generate(&*backend, GET), generate(&*backend, ACTIVE)];
        let header = backend.file_header_for_results(&used);
        assert_eq!(
            header
                .matches(&format!("import type {{ SourceCauses }} from \"{MODULE}\";\n"))
                .count(),
            1,
            "{name}:\n{header}"
        );
        assert!(
            header.contains("import type { Doubled } from \"@app/other\";\n"),
            "{name}:\n{header}"
        );
        assert!(!header.contains("Counts"), "{name}:\n{header}");

        let unused = [generate(&*backend, COUNT)];
        let header = backend.file_header_for_results(&unused);
        assert!(!header.contains(MODULE), "{name}:\n{header}");
    }
}

#[test]
fn should_cast_remapped_camel_case_rows_to_the_override() {
    for name in BACKENDS {
        let backend = backend(name, &[("field_case", "camelCase")]);
        let out = text(&generate(&*backend, GET));
        assert!(
            out.contains("\tnextAmount: number;") && out.contains("as Record<string, unknown> | null"),
            "{name}:\n{out}"
        );
    }
}

/// A `db_type` override with only a `ts_type` declares every value of that
/// type, and the Rust backends ignore `ts_type`.
#[test]
fn should_match_ts_types_by_db_type_and_leave_rust_alone() {
    let catalog = Catalog::from_ddl(&[SCHEMA]).unwrap();
    let parsed = parse_query(GET).unwrap();
    let analyzed = analyze(&catalog, &parsed).unwrap();
    let overrides = [TypeOverride {
        db_type: Some("json".to_string()),
        ts_type: Some(TsTypeOverride {
            ts_type: "Document".to_string(),
            import: None,
        }),
        ..Default::default()
    }];
    for name in BACKENDS {
        let backend = backend(name, &[]);
        let out = text(&generate_with_backend_and_overrides(&analyzed, &*backend, &overrides).unwrap());
        assert!(out.contains("\tcauses: Document;"), "{name}:\n{out}");
        assert!(out.contains("\tmetadata: Document | null;"), "{name}:\n{out}");
    }
    #[cfg(feature = "lang-rust")]
    {
        let rust = get_backend("rust-sqlx").unwrap();
        let plain = generate_with_backend_and_overrides(&analyzed, &*rust, &[]).unwrap();
        let overridden = generate_with_backend_and_overrides(&analyzed, &*rust, &overrides).unwrap();
        assert_eq!(text(&plain), text(&overridden));
    }
}
