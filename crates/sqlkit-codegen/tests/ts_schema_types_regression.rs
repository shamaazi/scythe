//! `schema_types` / `schema_types_import`: the schema's enums and domains as one
//! module, which generated query modules import instead of declaring enums and
//! inlining a domain's base type.

use std::collections::HashMap;

use sqlkit_codegen::schema_types::generate_schema_types;
use sqlkit_codegen::{CodegenBackend, GeneratedCode, generate_with_backend, get_backend};
use sqlkit_core::analyzer::analyze;
use sqlkit_core::catalog::Catalog;
use sqlkit_core::parser::parse_query;

const SCHEMA: &str = "CREATE TYPE currency AS ENUM ('gbp', 'usd'); \
    CREATE TYPE operating_country AS ENUM ('gb', 'us'); \
    CREATE DOMAIN country_code AS varchar(2) CHECK (VALUE ~ '^[a-z]{2}$'); \
    CREATE DOMAIN email_address AS varchar(254) CHECK (VALUE ~ '^[^@ ]+@[^@ ]+$'); \
    COMMENT ON DOMAIN email_address IS 'An email address, as typed.'; \
    CREATE DOMAIN amount AS integer CHECK (VALUE BETWEEN 0 AND 100000000); \
    CREATE DOMAIN tier AS text CHECK (VALUE IN ('gold', 'silver')); \
    CREATE TABLE donors (\
    id TEXT PRIMARY KEY, \
    email email_address NOT NULL, \
    country country_code, \
    currency currency NOT NULL, \
    total amount NOT NULL\
);";

const GET: &str = "-- @name GetDonor\n-- @returns :one\n\
    SELECT id, email, country, currency, total FROM donors WHERE email = $1;";

const CREATE: &str = "-- @name CreateDonor\n-- @returns :exec\n\
    INSERT INTO donors (id, email, country, currency, total) VALUES ($1, $2, $3, $4, $5);";

fn catalog(schema: &str) -> Catalog {
    Catalog::from_ddl(&[schema]).unwrap()
}

fn backend(options: &[(&str, &str)]) -> Box<dyn CodegenBackend> {
    let mut backend = get_backend("typescript-bun").unwrap();
    let options: HashMap<String, String> = options.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    backend.apply_options(&options).unwrap();
    backend
}

fn generate(backend: &dyn CodegenBackend) -> GeneratedCode {
    generate_query(backend, GET)
}

fn generate_query(backend: &dyn CodegenBackend, sql: &str) -> GeneratedCode {
    let catalog = catalog(SCHEMA);
    let analyzed = analyze(&catalog, &parse_query(sql).unwrap()).unwrap();
    generate_with_backend(&analyzed, backend).unwrap()
}

const IMPORTING: &[(&str, &str)] = &[
    ("schema_types_import", "@app/schema"),
    ("validation", "jsdoc"),
    ("constraints", "error"),
];

#[test]
fn module_declares_enums_and_documented_domain_aliases() {
    let backend = backend(IMPORTING);
    let module = generate_schema_types(&catalog(SCHEMA), backend.as_ref()).unwrap();
    let code = module.code;

    assert!(
        code.contains("export const CurrencyValues = {\n\tGbp: \"gbp\",\n\tUsd: \"usd\",\n} as const;"),
        "{code}"
    );
    assert!(
        code.contains("export type Currency = typeof CurrencyValues[keyof typeof CurrencyValues];"),
        "{code}"
    );
    assert!(code.contains("export type OperatingCountry = "), "{code}");
    assert!(
        code.contains("/**\n * @maxLength 2\n * @pattern ^[a-z]{2}$\n */\nexport type CountryCode = string;"),
        "{code}"
    );
    assert!(
        code.contains(
            "/**\n * An email address, as typed.\n * @maxLength 254\n * @pattern ^[^@ ]+@[^@ ]+$\n */\n\
             export type EmailAddress = string;"
        ),
        "{code}"
    );
    assert!(
        code.contains("/**\n * @minimum 0\n * @maximum 100000000\n */\nexport type Amount = number;"),
        "{code}"
    );
    assert!(code.contains("export type Tier = \"gold\" | \"silver\";"), "{code}");
    // Enums first, then domains, each by name.
    let order: Vec<usize> = [
        "CurrencyValues",
        "OperatingCountryValues",
        "Amount =",
        "CountryCode =",
        "EmailAddress =",
        "Tier =",
    ]
    .iter()
    .map(|name| code.find(name).unwrap_or_else(|| panic!("{name}: {code}")))
    .collect();
    assert!(order.windows(2).all(|pair| pair[0] < pair[1]), "{code}");
    assert!(module.warnings.is_empty());
}

#[test]
fn query_modules_import_enums_and_name_domain_values_by_their_alias() {
    let backend = backend(IMPORTING);
    let code = generate(backend.as_ref());

    assert!(
        code.enum_def.is_none(),
        "enums come from the schema module: {:?}",
        code.enum_def
    );
    let row = code.row_struct.as_deref().unwrap();
    assert!(row.contains("\temail: EmailAddress;"), "{row}");
    assert!(row.contains("\tcountry: CountryCode | null;"), "{row}");
    assert!(row.contains("\tcurrency: Currency;"), "{row}");
    assert!(row.contains("\ttotal: Amount;"), "{row}");
    // A compared parameter keeps its own type; a written one is the column's.
    let query_fn = code.query_fn.as_deref().unwrap();
    assert!(query_fn.contains("email: string"), "{query_fn}");
    let create = generate_query(backend.as_ref(), CREATE);
    let create_fn = create.query_fn.as_deref().unwrap();
    for param in [
        "email: EmailAddress",
        "country: CountryCode | null",
        "currency: Currency",
        "total: Amount",
    ] {
        assert!(create_fn.contains(param), "{param}: {create_fn}");
    }

    let header = backend.file_header_for_results(std::slice::from_ref(&code));
    assert!(
        header.contains("import type { Amount, CountryCode, Currency, EmailAddress } from \"@app/schema\";\n"),
        "{header}"
    );
}

/// A `ts_type` override replaces the domain's name, which the module then does
/// not import.
#[test]
fn a_ts_type_override_replaces_the_alias() {
    let catalog = catalog(SCHEMA);
    let analyzed = analyze(&catalog, &parse_query(GET).unwrap()).unwrap();
    let overrides = [sqlkit_codegen::TypeOverride {
        column: Some("donors.email".to_string()),
        ts_type: Some(sqlkit_codegen::overrides::TsTypeOverride {
            ts_type: "Email".to_string(),
            import: Some("@app/columns".to_string()),
        }),
        ..Default::default()
    }];
    let backend = backend(IMPORTING);
    let code = sqlkit_codegen::generate_with_backend_and_overrides(&analyzed, backend.as_ref(), &overrides).unwrap();
    let row = code.row_struct.as_deref().unwrap();
    assert!(row.contains("\temail: Email;"), "{row}");
    assert!(row.contains("\tcountry: CountryCode | null;"), "{row}");
    assert!(
        !code.schema_types.iter().any(|name| name == "EmailAddress"),
        "{:?}",
        code.schema_types
    );
}

#[test]
fn without_schema_types_nothing_changes() {
    let code = generate(backend(&[("validation", "jsdoc")]).as_ref());
    let row = code.row_struct.as_deref().unwrap();
    assert!(row.contains("\temail: string;"), "{row}");
    assert!(code.enum_def.as_deref().is_some_and(|e| e.contains("CurrencyValues")));
    assert!(code.schema_types.is_empty());
}

#[test]
fn an_untranslatable_domain_check_fails_under_constraints_error() {
    let schema = "CREATE DOMAIN slug AS text CHECK (VALUE ~ '^[^\\s]+$');";
    let err = generate_schema_types(&catalog(schema), backend(IMPORTING).as_ref()).unwrap_err();
    assert!(err.to_string().contains("domain slug"), "{err}");

    let mut warn = IMPORTING.to_vec();
    warn.retain(|(key, _)| *key != "constraints");
    warn.push(("constraints", "warn"));
    let module = generate_schema_types(&catalog(schema), backend(&warn).as_ref()).unwrap();
    assert_eq!(module.warnings.len(), 1, "{:?}", module.warnings);
    assert!(module.code.contains("export type Slug = string;"), "{}", module.code);
}

#[test]
fn schema_types_options_are_validated() {
    // `schema_types` is an output the CLI handles, not a backend option.
    let mut backend = get_backend("typescript-bun").unwrap();
    let path = HashMap::from([("schema_types".to_string(), "src/schema.ts".to_string())]);
    assert!(backend.apply_options(&path).is_err());
    let mut backend = get_backend("typescript-bun").unwrap();
    assert!(backend.set_schema_types_import("../types/schema").is_ok());
    assert_eq!(backend.schema_types_import(), Some("../types/schema"));

    let mut backend = get_backend("typescript-bun").unwrap();
    let zod = HashMap::from([
        ("row_type".to_string(), "zod".to_string()),
        ("schema_types_import".to_string(), "@app/schema".to_string()),
    ]);
    assert!(backend.apply_options(&zod).is_err());
}
