//! `params = "object"`: TypeScript query functions that take their parameters
//! as one object typed by an exported `<Query>Params` interface.
//!
//! Pinned for every backend that offers the option -- `typescript-bun`,
//! `typescript-postgres` (tagged templates) and `typescript-pg` (a values
//! array) -- with real schema and query text run through the analyzer, so
//! declared names (`-- $N: name`) and nullability reach the generated code.

use std::collections::HashMap;

use sqlkit_codegen::{CodegenBackend, GeneratedCode, generate_with_backend, get_backend};
use sqlkit_core::analyzer::analyze;
use sqlkit_core::catalog::Catalog;
use sqlkit_core::dialect::SqlDialect;
use sqlkit_core::parser::parse_query_with_dialect;

const SCHEMA: &str = "CREATE TABLE donations (\
    id SERIAL PRIMARY KEY, \
    donor_id TEXT NOT NULL, \
    note TEXT, \
    given_at TIMESTAMPTZ NOT NULL\
);";

const RECENT: &str = "-- @name RecentDonations\n-- @returns :many\n\
    -- @param $1 donor_id\n-- @param $2 from?\n\
    SELECT id, donor_id FROM donations WHERE donor_id = $1 AND given_at >= $2;";

const FILTERED: &str = "-- @name FilterDonations\n-- @returns :many\n\
    SELECT id FROM donations WHERE ($1::text IS NULL OR donor_id = $1);";

const NOTE: &str = "-- @name SetNote\n-- @returns :batch\n\
    UPDATE donations SET note = $2 WHERE id = $1;";

const DELETE: &str = "-- @name DeleteDonation\n-- @returns :exec\n\
    DELETE FROM donations WHERE id = $1;";

const COUNT: &str = "-- @name CountDonations\n-- @returns :one\n\
    SELECT count(*) AS total FROM donations;";

const GROUPED: &str = "-- @name DonorsWithDonations\n-- @returns :grouped\n-- @group_by donations.donor_id\n\
    -- @param $1 since\n\
    SELECT donor_id, id FROM donations WHERE given_at >= $1;";

const BACKENDS: [&str; 2] = ["typescript-bun", "typescript-postgres"];

fn generate(backend: &dyn CodegenBackend, sql: &str) -> GeneratedCode {
    let catalog = Catalog::from_ddl_with_dialect(&[SCHEMA], &SqlDialect::PostgreSQL).unwrap();
    let parsed = parse_query_with_dialect(sql, &SqlDialect::PostgreSQL).unwrap();
    let analyzed = analyze(&catalog, &parsed).unwrap();
    generate_with_backend(&analyzed, backend).unwrap_or_else(|e| panic!("codegen failed for {sql}: {e}"))
}

fn backend(name: &str, options: &[(&str, &str)]) -> Box<dyn CodegenBackend> {
    let mut backend = get_backend(name, "postgresql").unwrap_or_else(|e| panic!("{name}: {e}"));
    let options: HashMap<String, String> = options
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    backend.apply_options(&options).unwrap();
    backend
}

fn object_backend(name: &str) -> Box<dyn CodegenBackend> {
    backend(name, &[("params", "object"), ("field_case", "camelCase")])
}

fn query_fn(code: &GeneratedCode) -> &str {
    code.query_fn.as_deref().expect("query function")
}

#[test]
fn takes_one_params_object_typed_by_an_exported_interface() {
    for name in BACKENDS {
        let code = generate(&*object_backend(name), RECENT);
        let query_fn = query_fn(&code);
        assert!(
            query_fn.starts_with(
                "/** Parameters for RecentDonations queries. */\n\
                 export interface RecentDonationsParams {\n\
                 \tdonorId: string;\n\
                 \tfrom: Date | null;\n\
                 }\n\n"
            ),
            "{name}: declared names, camelCased, the `?` one nullable:\n{query_fn}"
        );
        assert!(
            query_fn.contains("params: RecentDonationsParams"),
            "{name}: one params argument:\n{query_fn}"
        );
        assert!(
            !query_fn.contains("donorId: string,"),
            "{name}: no positional args:\n{query_fn}"
        );
    }
}

#[test]
fn tagged_template_backends_bind_the_properties_in_place() {
    for name in ["typescript-bun", "typescript-postgres"] {
        let code = generate(&*object_backend(name), RECENT);
        let query_fn = query_fn(&code);
        assert!(
            query_fn.contains("WHERE donor_id = ${params.donorId} AND given_at >= ${params.from}"),
            "{name}:\n{query_fn}"
        );
    }
}

#[test]
fn inferred_nullable_param_needs_no_declaration() {
    for name in BACKENDS {
        let code = generate(&*object_backend(name), FILTERED);
        let query_fn = query_fn(&code);
        assert!(
            query_fn.contains("export interface FilterDonationsParams {\n\tdonorId: string | null;\n}"),
            "{name}: `$1::text IS NULL` makes it nullable:\n{query_fn}"
        );
    }
}

#[test]
fn batch_items_are_the_params_interface() {
    for name in BACKENDS {
        let code = generate(&*object_backend(name), NOTE);
        let query_fn = query_fn(&code);
        assert!(
            query_fn.contains("export interface SetNoteParams {\n\tid: number;\n\tnote: string | null;\n}"),
            "{name}: a nullable column's parameter is nullable:\n{query_fn}"
        );
        assert!(query_fn.contains("items: SetNoteParams[]"), "{name}:\n{query_fn}");
        assert!(!query_fn.contains("BatchParams"), "{name}: one interface:\n{query_fn}");
        assert!(query_fn.contains("item.note"), "{name}:\n{query_fn}");
    }
}

#[test]
fn single_param_batch_still_takes_the_interface() {
    for name in BACKENDS {
        let batch = DELETE.replace(":exec", ":batch");
        let code = generate(&*object_backend(name), &batch);
        let query_fn = query_fn(&code);
        assert!(
            query_fn.contains("items: DeleteDonationParams[]"),
            "{name}:\n{query_fn}"
        );
        assert!(query_fn.contains("item.id"), "{name}:\n{query_fn}");
    }
}

#[test]
fn query_without_params_takes_only_the_handle() {
    for name in BACKENDS {
        let code = generate(&*object_backend(name), COUNT);
        let query_fn = query_fn(&code);
        assert!(!query_fn.contains("Params"), "{name}:\n{query_fn}");
        assert!(!query_fn.contains("params"), "{name}:\n{query_fn}");
    }
}

#[test]
fn grouped_query_takes_the_params_object() {
    for name in BACKENDS {
        let code = generate(&*object_backend(name), GROUPED);
        let query_fn = query_fn(&code);
        assert!(
            query_fn.contains("export interface DonorsWithDonationsParams {\n\tsince: Date;\n}"),
            "{name}:\n{query_fn}"
        );
        assert!(
            query_fn.contains("params: DonorsWithDonationsParams"),
            "{name}:\n{query_fn}"
        );
        assert!(query_fn.contains("params.since"), "{name}:\n{query_fn}");
    }
}

#[test]
fn structs_only_keeps_the_params_interface() {
    for name in BACKENDS {
        let backend = backend(name, &[("params", "object"), ("structs_only", "true")]);
        let code = generate(&*backend, DELETE);
        assert_eq!(
            code.query_fn.as_deref().unwrap_or_default(),
            "/** Parameters for DeleteDonation queries. */\nexport interface DeleteDonationParams {\n\tid: number;\n}",
            "{name}"
        );
    }
}

#[test]
fn positional_is_the_default_and_unchanged() {
    for name in BACKENDS {
        let default = generate(&*backend(name, &[]), RECENT);
        let explicit = generate(&*backend(name, &[("params", "positional")]), RECENT);
        assert_eq!(query_fn(&default), query_fn(&explicit), "{name}");
        assert!(
            !query_fn(&default).contains("Params"),
            "{name}:\n{}",
            query_fn(&default)
        );
        assert!(
            query_fn(&default).contains("donor_id: string"),
            "{name}:\n{}",
            query_fn(&default)
        );
    }
}

#[test]
fn rejects_an_unknown_params_style() {
    for name in BACKENDS {
        let mut backend = get_backend(name, "postgresql").unwrap();
        let err = backend
            .apply_options(&HashMap::from([("params".to_string(), "named".to_string())]))
            .expect_err("`named` is not a params style");
        assert!(
            err.to_string().contains("expected 'positional' or 'object'"),
            "{name}: {err}"
        );
    }
}

#[test]
fn javascript_backends_reject_the_object_style() {
    for name in ["javascript-bun", "javascript-postgres"] {
        let mut backend = get_backend(name, "postgresql").unwrap();
        let err = backend
            .apply_options(&HashMap::from([("params".to_string(), "object".to_string())]))
            .expect_err("JSDoc mode has no object style");
        assert!(err.to_string().contains("params = \"object\""), "{name}: {err}");
    }
}
