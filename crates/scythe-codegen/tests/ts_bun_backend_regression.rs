//! `typescript-bun` / `javascript-bun`: Bun's built-in `SQL` client.
//!
//! Bun's tagged-template API copies postgres.js's, so the backend shares
//! `typescript_postgres.rs`. These tests pin what differs from postgres.js --
//! the handle type, Bun's result types, the parameter wrappers Bun needs, and
//! the savepoint-aware `:batch` -- across every query kind, with real schema
//! and query text run through the analyzer.

use std::collections::HashMap;

use scythe_codegen::{CodegenBackend, GeneratedCode, generate_with_backend, get_backend};
use scythe_core::analyzer::analyze;
use scythe_core::catalog::Catalog;
use scythe_core::dialect::SqlDialect;
use scythe_core::parser::parse_query_with_dialect;

const SCHEMA: &str = "CREATE TYPE donation_status AS ENUM ('pending', 'paid', 'refunded'); \
    CREATE TABLE donations (\
    id BIGSERIAL PRIMARY KEY, \
    donor_name TEXT NOT NULL, \
    amount NUMERIC(12, 2) NOT NULL, \
    status donation_status NOT NULL, \
    tags TEXT[] NOT NULL, \
    scores INTEGER[], \
    weights REAL[] NOT NULL, \
    receipt BYTEA, \
    metadata JSONB, \
    given_on DATE NOT NULL, \
    given_at TIMESTAMPTZ NOT NULL\
);";

const GET: &str = "-- @name GetDonation\n-- @returns :one\n\
    SELECT id, donor_name, amount, status, tags, scores, weights, receipt, metadata, given_on, given_at \
    FROM donations WHERE id = $1;";

const FIND: &str = "-- @name FindDonationByDonor\n-- @returns :opt\n\
    SELECT id, donor_name FROM donations WHERE donor_name = $1 LIMIT 1;";

const LIST: &str = "-- @name ListDonationsByStatus\n-- @returns :many\n\
    SELECT id, donor_name, status FROM donations WHERE status = ANY($1) ORDER BY id;";

const CREATE: &str = "-- @name CreateDonation\n-- @returns :exec\n\
    INSERT INTO donations (donor_name, amount, status, tags, weights, metadata, given_on, given_at) \
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8);";

const REFUND: &str = "-- @name RefundDonations\n-- @returns :exec_rows\n\
    UPDATE donations SET status = 'refunded' WHERE donor_name = $1;";

const MARK_PAID: &str = "-- @name MarkPaid\n-- @returns :batch\n\
    UPDATE donations SET status = 'paid' WHERE id = $1 AND donor_name = $2;";

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

fn query_fn(code: &GeneratedCode) -> &str {
    code.query_fn.as_deref().expect("query function")
}

fn row_struct(code: &GeneratedCode) -> &str {
    code.row_struct.as_deref().expect("row struct")
}

#[test]
fn registry_names_and_engines() {
    let ts = get_backend("typescript-bun", "postgresql").unwrap();
    assert_eq!(ts.name(), "typescript-bun");
    assert_eq!(ts.output_extension(), "ts");
    let js = get_backend("javascript-bun", "postgresql").unwrap();
    assert_eq!(js.name(), "javascript-bun");
    assert_eq!(js.output_extension(), "js");
    assert!(get_backend("typescript-bun", "cockroachdb").is_ok());
    for engine in ["redshift", "mysql", "sqlite"] {
        assert!(
            get_backend("typescript-bun", engine).is_err(),
            "{engine} must be rejected"
        );
    }
}

#[test]
fn header_imports_the_bun_handle_type_only_as_a_type() {
    let backend = backend("typescript-bun", &[]);
    let codes = [generate(&*backend, GET), generate(&*backend, LIST)];
    let header = backend.file_header_for_results(&codes);
    assert!(header.contains("import type { SQL } from \"bun\";"), "{header}");
    assert!(
        header.contains("type SqlJsonValue = "),
        "GetDonation has a jsonb column: {header}"
    );
    assert!(
        !header.contains("TransactionSQL"),
        "no :batch, no TransactionSQL: {header}"
    );
    assert!(!header.contains("postgres"), "{header}");

    let plain = [generate(&*backend, FIND)];
    assert!(
        !backend.file_header_for_results(&plain).contains("SqlJsonValue"),
        "the JSON alias is declared only when used"
    );
}

#[test]
fn row_types_follow_what_bun_returns() {
    let code = generate(&*backend("typescript-bun", &[]), GET);
    let row = row_struct(&code);
    for field in [
        "id: string;",
        "amount: string;",
        "status: DonationStatus;",
        "tags: Array<string>;",
        "scores: Int32Array | Array<number> | null;",
        "weights: Float32Array | Array<number>;",
        "receipt: Buffer | null;",
        "metadata: SqlJsonValue | null;",
        "given_on: Date;",
        "given_at: Date;",
    ] {
        assert!(row.contains(field), "expected `{field}` in:\n{row}");
    }
}

#[test]
fn one_binds_through_the_tagged_template_and_throws_when_missing() {
    let code = generate(&*backend("typescript-bun", &[]), GET);
    let f = query_fn(&code);
    assert!(
        f.contains("export async function getDonation(\n\tsql: SQL,\n\tid: string,\n): Promise<GetDonationRow> {"),
        "{f}"
    );
    assert!(f.contains("await sql<GetDonationRow[]>`"), "{f}");
    assert!(f.contains("WHERE id = ${id}"), "{f}");
    assert!(f.contains("if (row === undefined) {"), "{f}");
}

#[test]
fn opt_returns_null_when_missing() {
    let code = generate(&*backend("typescript-bun", &[]), FIND);
    let f = query_fn(&code);
    assert!(f.contains("Promise<FindDonationByDonorRow | null>"), "{f}");
    assert!(f.contains("return rows[0] ?? null;"), "{f}");
}

#[test]
fn many_wraps_an_enum_array_param_in_sql_array() {
    let code = generate(&*backend("typescript-bun", &[]), LIST);
    let f = query_fn(&code);
    assert!(f.contains("Promise<ListDonationsByStatusRow[]>"), "{f}");
    assert!(
        f.contains("ANY(${sql.array("),
        "Bun cannot tell an enum array is an array: {f}"
    );
    assert!(f.contains("return rows;"), "{f}");
}

#[test]
fn exec_wraps_json_but_leaves_builtin_arrays_bare() {
    let code = generate(&*backend("typescript-bun", &[]), CREATE);
    let f = query_fn(&code);
    assert!(f.contains("Promise<void>"), "{f}");
    assert!(f.contains("${metadata === null ? null : sql.json(metadata)}"), "{f}");
    assert!(f.contains("${tags}"), "{f}");
    assert!(f.contains("${weights}"), "{f}");
    assert!(f.contains("given_on: Date"), "{f}");
    assert!(f.contains("amount: string"), "{f}");
}

#[test]
fn exec_rows_returns_the_count() {
    let code = generate(&*backend("typescript-bun", &[]), REFUND);
    let f = query_fn(&code);
    assert!(f.contains("Promise<number>"), "{f}");
    assert!(f.contains("return result.count;"), "{f}");
}

#[test]
fn batch_uses_a_savepoint_inside_a_transaction() {
    let backend = backend("typescript-bun", &[]);
    let code = generate(&*backend, MARK_PAID);
    let f = query_fn(&code);
    assert!(f.contains("export async function markPaidBatch("), "{f}");
    assert!(f.contains("const run = async (tx: SQL) => {"), "{f}");
    assert!(f.contains("await tx`"), "{f}");
    assert!(f.contains("${item.id}"), "{f}");
    assert!(
        f.contains("await (\"savepoint\" in sql ? (sql as TransactionSQL).savepoint(run) : sql.begin(run));"),
        "{f}"
    );
    let header = backend.file_header_for_results(std::slice::from_ref(&code));
    assert!(
        header.contains("import type { SQL, TransactionSQL } from \"bun\";"),
        "{header}"
    );
}

#[test]
fn camel_case_remaps_raw_snake_case_keys_itself() {
    let code = generate(&*backend("typescript-bun", &[("field_case", "camelCase")]), GET);
    let row = row_struct(&code);
    assert!(row.contains("donorName: string;"), "{row}");
    assert!(row.contains("givenOn: Date;"), "{row}");
    let f = query_fn(&code);
    assert!(f.contains("await sql<Record<string, unknown>[]>`"), "{f}");
    assert!(
        f.contains("row['donor_name']"),
        "reads the column Bun returned untransformed: {f}"
    );
    assert!(f.contains("Int32Array | Array<number> | null"), "{f}");
}

#[test]
fn enums_are_a_const_object_and_string_union() {
    let backend = backend("typescript-bun", &[]);
    let code = generate(&*backend, GET);
    let def = code.enum_def.as_deref().expect("enum definition");
    assert!(def.contains("export const DonationStatusValues = {"), "{def}");
    assert!(def.contains("Refunded: \"refunded\","), "{def}");
    assert!(
        def.contains("export type DonationStatus = typeof DonationStatusValues[keyof typeof DonationStatusValues];"),
        "{def}"
    );
    assert!(!def.contains("export enum"), "{def}");
}

#[test]
fn structs_only_drops_the_driver_import_and_functions() {
    let backend = backend("typescript-bun", &[("structs_only", "true")]);
    let code = generate(&*backend, GET);
    assert!(code.query_fn.as_deref().is_none_or(str::is_empty));
    let header = backend.file_header_for_results(&[code]);
    assert!(!header.contains("from \"bun\""), "{header}");
    assert!(header.contains("type SqlJsonValue"), "{header}");
}

#[test]
fn zod_row_type_validates_bun_types() {
    let backend = backend("typescript-bun", &[("row_type", "zod")]);
    let code = generate(&*backend, GET);
    let row = row_struct(&code);
    assert!(row.contains("given_on: z.date()"), "{row}");
    assert!(row.contains("receipt: z.instanceof(Buffer).nullable()"), "{row}");
    assert!(row.contains("id: z.string()"), "{row}");
    let header = backend.file_header_for_results(&[code]);
    assert!(header.contains("import { z } from \"zod\";"), "{header}");
}

#[test]
fn outer_join_unions_is_accepted() {
    backend("typescript-bun", &[("outer_join_unions", "true")]);
}

#[test]
fn javascript_bun_types_the_handle_through_jsdoc() {
    let backend = backend("javascript-bun", &[]);
    let code = generate(&*backend, GET);
    let f = query_fn(&code);
    assert!(f.contains("@param {import(\"bun\").SQL} sql"), "{f}");
    assert!(f.contains("export async function getDonation(sql, id) {"), "{f}");

    let batch = generate(&*backend, MARK_PAID);
    let f = query_fn(&batch);
    assert!(f.contains("/** @param {import(\"bun\").SQL} tx */"), "{f}");
    assert!(
        f.contains("/** @type {import(\"bun\").TransactionSQL} */ (sql).savepoint(run)"),
        "{f}"
    );

    for (key, value) in [
        ("row_type", "zod"),
        ("outer_join_unions", "true"),
        ("field_case", "camelCase"),
    ] {
        let mut b = get_backend("javascript-bun", "postgresql").unwrap();
        let options = HashMap::from([(key.to_string(), value.to_string())]);
        let err = b
            .apply_options(&options)
            .expect_err("JSDoc mode rejects TS-only options");
        assert!(err.to_string().contains("javascript-bun"), "{err}");
        assert!(err.to_string().contains("typescript-bun"), "{err}");
    }
}

#[test]
fn postgres_js_output_is_unchanged_by_the_bun_driver() {
    let code = generate(&*backend("typescript-postgres", &[]), MARK_PAID);
    let f = query_fn(&code);
    assert!(f.contains("sql: Sql"), "{f}");
    assert!(f.contains("await sql.begin(async (tx) => {"), "{f}");
    let code = generate(&*backend("typescript-postgres", &[]), GET);
    assert!(row_struct(&code).contains("scores: Array<number> | null;"));
    assert!(
        code.enum_def
            .as_deref()
            .unwrap()
            .contains("export enum DonationStatus {")
    );
}
