//! Validate generated code for all backends using real language tools.
//! All tools are expected to be installed.

#![cfg_attr(
    not(all(feature = "all-engines", feature = "all-languages")),
    allow(
        dead_code,
        unused_imports,
        unused_macros,
        reason = "helpers shared with tests of backends this build leaves out"
    )
)]

use scythe_codegen::provenance;
use scythe_codegen::validation::{ToolValidation, strict_mode_enabled, validate_structural, validate_with_tools};
use scythe_codegen::{CodegenBackend, generate_with_backend, get_backend};
use scythe_core::analyzer::analyze;
use scythe_core::catalog::Catalog;
use scythe_core::dialect::SqlDialect;
use scythe_core::parser::parse_query_with_dialect;

// ~keep #146: the schema shared by every full generate-and-compile round in
// this file. Before this it
// carried zero container or user-defined types, so nothing in this file's
// ~20 PostgreSQL backend tests -- the strongest gate in the project -- ever
// asked a real compiler to accept an array, an enum, an array of enums, a
// composite, a `uuid`, or a `jsonb` column. `role`/`roles`/`tags`/
// `home_address`/`external_id`/`metadata` below exist to close exactly that
// gap; every one of them is selected by `QUERY_ONE`, the query every
// PostgreSQL backend test in this file runs, so widening the schema without
// also widening the query would have added dead columns no generated file
// ever reaches.
const SCHEMA: &str = "CREATE TYPE user_role AS ENUM ('member', 'admin'); \
    CREATE TYPE user_address AS (street TEXT, city TEXT, zip TEXT); \
    CREATE TABLE users (\
    id SERIAL PRIMARY KEY, \
    name TEXT NOT NULL, \
    email TEXT, \
    status TEXT NOT NULL DEFAULT 'active', \
    role user_role NOT NULL DEFAULT 'member', \
    roles user_role[], \
    tags TEXT[], \
    home_address user_address, \
    external_id UUID, \
    metadata JSONB, \
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()\
);";

const QUERY_ONE: &str = "-- @name GetUser\n-- @returns :one\n\
    SELECT id, name, email, status, role, roles, tags, home_address, external_id, metadata, \
    created_at FROM users WHERE id = $1;";

const QUERY_MANY: &str = "-- @name ListUsers\n-- @returns :many\n\
    SELECT id, name, email FROM users ORDER BY name;";

const QUERY_EXEC: &str = "-- @name DeleteUser\n-- @returns :exec\n\
    DELETE FROM users WHERE id = $1;";

fn generate_full_file(backend_name: &str) -> String {
    let backend = get_backend(backend_name, "postgresql").unwrap();
    generate_full_file_from_backend(backend_name, &*backend, &SqlDialect::PostgreSQL)
}

fn generate_full_file_with_options(backend_name: &str, options: &std::collections::HashMap<String, String>) -> String {
    let mut backend = get_backend(backend_name, "postgresql").unwrap();
    backend.apply_options(options).unwrap();
    generate_full_file_from_backend(backend_name, &*backend, &SqlDialect::PostgreSQL)
}

fn generate_full_file_from_backend(backend_name: &str, backend: &dyn CodegenBackend, dialect: &SqlDialect) -> String {
    let (schema, queries, engine) = (SCHEMA, [QUERY_ONE, QUERY_MANY, QUERY_EXEC], "postgresql");

    let catalog = Catalog::from_ddl_with_dialect(&[schema], dialect).unwrap();

    let class_header = backend.query_class_header();
    let use_class_wrapper = !class_header.is_empty();

    // ~keep Swallowing a codegen error here (and letting the loop continue with
    // whatever queries did succeed) let a broken backend pass this harness as
    // long as at least one of the three queries still produced a struct and a
    // function -- the empty-file backstop below can never catch it, since
    // `provenance::assemble_file` always prepends a non-empty header line
    // regardless of how many query bodies actually made it into `all_codes`.
    // A partial failure must fail the test loudly, naming the backend and the
    // query that broke, not get logged to a captured stderr no one reads.
    let mut all_codes = Vec::new();
    for query_sql in queries {
        let parsed = parse_query_with_dialect(query_sql, dialect).unwrap();
        let analyzed = analyze(&catalog, &parsed).unwrap();
        let code = generate_with_backend(&analyzed, backend)
            .unwrap_or_else(|e| panic!("codegen error for backend {backend_name} on query {query_sql:?}: {e}"));
        all_codes.push(code);
    }

    // ~keep Only the *body* is accumulated here. The preamble and the provenance
    // header line are added by `provenance::assemble_file` at the bottom of
    // this function, in the one place that owns their ordering — the same
    // call `scythe-cli`'s `assemble_output` makes.
    let mut full = backend.file_header_for_results(&all_codes);
    full.push('\n');

    if use_class_wrapper {
        for code in &all_codes {
            if let Some(ref s) = code.enum_def {
                full.push_str(s);
                full.push('\n');
            }
            if let Some(ref s) = code.model_struct {
                full.push_str(s);
                full.push('\n');
            }
            if let Some(ref s) = code.row_struct {
                full.push_str(s);
                full.push('\n');
            }
        }
        full.push_str(&class_header);
        full.push('\n');
        for code in &all_codes {
            if let Some(ref s) = code.query_fn {
                full.push_str(s);
                full.push('\n');
            }
        }
        let footer = backend.file_footer();
        if !footer.is_empty() {
            full.push_str(&footer);
            full.push('\n');
        }
    } else {
        for code in &all_codes {
            if let Some(ref s) = code.enum_def {
                full.push_str(s);
                full.push('\n');
            }
            if let Some(ref s) = code.model_struct {
                full.push_str(s);
                full.push('\n');
            }
            if let Some(ref s) = code.row_struct {
                full.push_str(s);
                full.push('\n');
            }
            if let Some(ref s) = code.query_fn {
                full.push_str(s);
                full.push('\n');
            }
        }
        let footer = backend.file_footer();
        if !footer.is_empty() {
            full.push_str(&footer);
            full.push('\n');
        }
    }

    // ~keep The point of this harness is that `php -l`, `ruby -c`, `gofmt`,
    // `python -m py_compile`, `tsc`, and `kotlinc` below are handed the bytes
    // a real `sqlkit generate` writes — provenance header included. Without
    // it, nothing anywhere proves that the header sits in a position each
    // language actually accepts: the structural checks in `validation.rs` are
    // substring matches (`code.contains("<?php")`) that pass regardless of
    // what precedes them, and the ordering assertions in `scythe-cli` are
    // Rust string comparisons that no language tool ever sees. PHP is the
    // sharpest case — `declare(strict_types=1);` must be the file's first
    // *statement*, so only a real `php -l` can confirm a preceding comment is
    // allowed there.
    //
    // The version, engine, schema, and queries values are placeholders: the
    // header's legality depends on its comment prefix and its position, not
    // on its field values.
    provenance::assemble_file(
        &backend.file_preamble(),
        &provenance::header_line(
            backend,
            env!("CARGO_PKG_VERSION"),
            engine,
            "sch1:0123456789abcdef",
            "q1:fedcba9876543210",
        ),
        &full,
    )
}

/// Guard against a validator that is wired up but checks nothing.
///
/// `validate_with_tools` returning `Attempted(vec![])` -- a match arm that
/// builds an empty outcome list, e.g. a future backend added to an existing
/// prefix match without adding its own checker call -- reports zero errors
/// and zero missing tools. `into_result`, even in strict mode, therefore
/// treats it exactly like a `Ran` outcome that found nothing: a clean pass.
/// That is the same "ran vs. never ran" confusion `ToolValidation` exists to
/// prevent in the first place (see `fully_checked`'s own doc comment),
/// reached through a different bug -- and it is the reason `fully_checked`
/// needs a caller here rather than staying something only its own unit tests
/// exercise.
///
/// Gated on strict mode, same as `into_result`'s missing-tool handling:
/// outside strict mode a validator that only ran a subset of its checkers
/// (because one is not installed) is expected, so `fully_checked` legitimately
/// returns `false` on every laptop that doesn't have every tool. `Unsupported`
/// is exempt for the same reason `into_result_with_strictness` exempts it --
/// tracked by the inventory test below instead of failing here with no fix
/// available.
fn assert_tool_validation_is_not_vacuous(validation: &ToolValidation, backend: &str, code: &str) {
    if !strict_mode_enabled() {
        return;
    }
    let unsupported = matches!(validation, ToolValidation::Unsupported);
    assert!(
        unsupported || validation.fully_checked(),
        "{backend} tool validation ran but `fully_checked()` reports nothing actually checked \
         the code -- a validator that dispatches to zero checkers passes vacuously.\n\n\
         Generated code:\n{code}"
    );
}

macro_rules! backend_test {
    ($name:ident, $backend:expr) => {
        #[test]
        fn $name() {
            let code = generate_full_file($backend);
            assert!(
                !code.trim().is_empty(),
                "generated code is empty for {}",
                $backend
            );

            eprintln!("\n=== {} ===\n{}\n=== END ===\n", $backend, code);

            let structural_errors = validate_structural(&code, $backend);
            assert!(
                structural_errors.is_empty(),
                "{} structural: {:?}",
                $backend,
                structural_errors
            );

            let validation = validate_with_tools(&code, $backend);
            assert_tool_validation_is_not_vacuous(&validation, $backend, &code);
            if let Err(tool_errors) = validation.into_result() {
                panic!(
                    "{} tool validation: {:?}\n\nGenerated code:\n{}",
                    $backend, tool_errors, code
                );
            }
        }
    };
}

macro_rules! backend_test_with_options {
    ($name:ident, $backend:expr, $($key:expr => $val:expr),+) => {
        #[test]
        fn $name() {
            let mut options = std::collections::HashMap::new();
            $(options.insert($key.to_string(), $val.to_string());)+
            let code = generate_full_file_with_options($backend, &options);
            assert!(
                !code.trim().is_empty(),
                "generated code is empty for {} with options",
                $backend
            );

            eprintln!("\n=== {} (with options) ===\n{}\n=== END ===\n", $backend, code);

            let structural_errors = validate_structural(&code, $backend);
            assert!(
                structural_errors.is_empty(),
                "{} structural: {:?}",
                $backend,
                structural_errors
            );

            let validation = validate_with_tools(&code, $backend);
            assert_tool_validation_is_not_vacuous(&validation, $backend, &code);
            if let Err(tool_errors) = validation.into_result() {
                panic!(
                    "{} tool validation: {:?}\n\nGenerated code:\n{}",
                    $backend, tool_errors, code
                );
            }
        }
    };
}

#[cfg(all(feature = "lang-rust", feature = "postgres"))]
backend_test!(test_rust_sqlx, "rust-sqlx");
#[cfg(all(feature = "lang-rust", feature = "postgres"))]
backend_test!(test_rust_tokio_postgres, "rust-tokio-postgres");
#[cfg(all(feature = "lang-typescript", feature = "postgres"))]
backend_test!(test_typescript_postgres, "typescript-postgres");
#[cfg(all(feature = "lang-typescript", feature = "postgres"))]
backend_test!(test_typescript_bun, "typescript-bun");

#[cfg(all(feature = "lang-typescript", feature = "postgres"))]
backend_test_with_options!(test_typescript_postgres_zod, "typescript-postgres", "row_type" => "zod");
backend_test_with_options!(test_typescript_bun_zod, "typescript-bun", "row_type" => "zod");
backend_test_with_options!(test_typescript_bun_camel, "typescript-bun", "field_case" => "camelCase");

// -- javascript-* (JSDoc emit mode, #81) -------------------------------------
//
// These backends reuse `generate_full_file*`/`backend_test!` above for
// their `:one`/`:many`/`:exec` coverage (the schema already has
// a nullable `email` column, so that path is exercised for free). The tests
// below add the two cases #81's release plan calls out explicitly and that
// produced real defects during development: a nullable column emitting
// `{T | null}` (never JSDoc's bracket-optional or `?`-suffix syntax), and a
// `:grouped` query (where untyped-return defects
// lived). Both are run through `validate_with_tools`, which for a
// `javascript-*` backend name now shells out to real `node --check` and
// (if present) real `tsc --checkJs --strict` -- see `validate_javascript_tools`
// in `src/validation.rs`.

#[cfg(all(feature = "lang-typescript", feature = "postgres"))]
backend_test!(test_javascript_postgres, "javascript-postgres");
#[cfg(all(feature = "lang-typescript", feature = "postgres"))]
backend_test!(test_javascript_bun, "javascript-bun");

const JS_MODE_POSTGRES_SCHEMA: [&str; 2] = [
    "CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT NOT NULL, bio TEXT, metadata JSONB NOT NULL);",
    "CREATE TABLE orders (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), total NUMERIC);",
];

const JS_MODE_POSTGRES_ONE: &str = "-- @name GetUserById\n-- @returns :one\n\
    SELECT id, name, bio, metadata FROM users WHERE id = $1;";

const JS_MODE_MANY: &str = "-- @name ListUsers\n-- @returns :many\n\
    SELECT id, name, bio FROM users;";

const JS_MODE_GROUPED: &str = "-- @name GetUsersWithOrders\n-- @returns :grouped\n-- @group_by users.id\n\
    SELECT u.id, u.name, o.id AS order_id, o.total\n\
    FROM users u\n\
    JOIN orders o ON o.user_id = u.id;";

/// Generate a full file for a `javascript-*` backend covering a nullable
/// column (`users.bio`, via `one_sql`) and a `:grouped` query
/// (`JS_MODE_GROUPED`) in one file, the same way `generate_full_file_from_backend`
/// assembles `:one`/`:many`/`:exec` output above.
fn generate_js_mode_nullable_and_grouped_file(
    backend_name: &str,
    engine: &str,
    dialect: &SqlDialect,
    schema: &[&str],
    one_sql: &str,
) -> String {
    let backend = get_backend(backend_name, engine).unwrap();
    let catalog = Catalog::from_ddl_with_dialect(schema, dialect).unwrap();

    let mut all_codes = Vec::new();
    for query_sql in [one_sql, JS_MODE_MANY, JS_MODE_GROUPED] {
        let parsed = parse_query_with_dialect(query_sql, dialect).unwrap();
        let analyzed = analyze(&catalog, &parsed).unwrap();
        let code = generate_with_backend(&analyzed, &*backend).unwrap();
        all_codes.push(code);
    }

    let mut full = backend.file_header_for_results(&all_codes);
    full.push('\n');
    for code in &all_codes {
        if let Some(ref s) = code.row_struct {
            full.push_str(s);
            full.push('\n');
        }
        if let Some(ref s) = code.query_fn {
            full.push_str(s);
            full.push('\n');
        }
    }
    full
}

/// Assert the JSDoc row-struct property for `field` is `{T | null}` -- never
/// JSDoc's bracket-optional (`[field]`) or `?`-suffix optional syntax, which
/// mean the property may be *absent* rather than present-and-`null`.
fn assert_js_mode_nullable_property_is_type_or_null(code: &str, field: &str) {
    assert!(
        code.contains(&format!("| null}} {field}")),
        "expected a `{{T | null}}` JSDoc property for '{field}'; got:\n{code}"
    );
    assert!(
        !code.contains(&format!("[{field}]")),
        "must never use bracket-optional syntax for '{field}'; got:\n{code}"
    );
    assert!(
        !code.contains(&format!("{field}?")),
        "must never use `?`-suffix optional syntax for '{field}'; got:\n{code}"
    );
}

/// Run the real `node`/`tsc` tool validation (`validate_with_tools`) and
/// fail loudly if it ran and found errors.
///
/// Outside strict mode an uninstalled `node` or `tsc` is not a test failure
/// -- requiring every contributor to have both would be the wrong tradeoff
/// -- but the skip is printed at this call site so `cargo test --
/// --nocapture` makes it impossible to mistake for a pass. Under
/// `SCYTHE_VALIDATE_STRICT=1`, which CI sets after installing both,
/// `into_result` turns that same skip into a failure.
///
/// This wrapper predates `ToolValidation` and hand-rolled the same
/// skip-is-not-a-pass distinction for these two tools only; it now defers to
/// the type so there is one mechanism rather than two.
fn assert_js_mode_tool_validation_passes(backend_name: &str, code: &str) {
    let validation = validate_with_tools(code, backend_name);

    for tool in validation.tools_run() {
        eprintln!("  {backend_name}: `{tool}` ran against the generated code");
    }
    for tool in validation.missing_tools() {
        eprintln!("  {backend_name}: `{tool}` is not on PATH -- whatever it would have caught went unchecked");
    }

    if let Err(errors) = validation.into_result() {
        panic!("{backend_name} tool validation: {errors:?}\n\nGenerated code:\n{code}");
    }
}

#[cfg(all(feature = "lang-typescript", feature = "postgres"))]
#[test]
fn test_javascript_postgres_grouped_and_nullable_pass_real_tools() {
    let code = generate_js_mode_nullable_and_grouped_file(
        "javascript-postgres",
        "postgresql",
        &SqlDialect::PostgreSQL,
        &JS_MODE_POSTGRES_SCHEMA,
        JS_MODE_POSTGRES_ONE,
    );
    eprintln!("\n=== javascript-postgres (nullable + grouped) ===\n{code}\n=== END ===\n");
    assert_js_mode_nullable_property_is_type_or_null(&code, "bio");
    assert!(
        code.contains("@property {PostgresJsonValue} metadata"),
        "expected the public postgres.js json-parameter type; got:\n{code}"
    );
    assert!(
        code.contains("@typedef {object} GetUsersWithOrdersRow"),
        "expected the grouped parent typedef; got:\n{code}"
    );
    assert_js_mode_tool_validation_passes("javascript-postgres", &code);
}

#[cfg(all(feature = "lang-typescript", feature = "postgres"))]
#[test]
fn test_javascript_bun_grouped_and_nullable_pass_real_tools() {
    let code = generate_js_mode_nullable_and_grouped_file(
        "javascript-bun",
        "postgresql",
        &SqlDialect::PostgreSQL,
        &JS_MODE_POSTGRES_SCHEMA,
        JS_MODE_POSTGRES_ONE,
    );
    eprintln!("\n=== javascript-bun (nullable + grouped) ===\n{code}\n=== END ===\n");
    assert_js_mode_nullable_property_is_type_or_null(&code, "bio");
    assert!(
        code.contains("@property {SqlJsonValue} metadata"),
        "expected the Bun JSON value type; got:\n{code}"
    );
    assert!(
        code.contains("@typedef {object} GetUsersWithOrdersRow"),
        "expected the grouped parent typedef; got:\n{code}"
    );
    assert_js_mode_tool_validation_passes("javascript-bun", &code);
}

/// Inventory of the backends `validate_with_tools` cannot check with any real
/// tool, because no validator has been written for their language.
///
/// This is the other half of #98. Strict mode catches a checker that fell out
/// of the CI image; nothing catches a language that never had one, because
/// `validate_with_tools` returning `Unsupported` is indistinguishable from a
/// pass at a call site that only looks at the error list. That was `_ => None`
/// before `ToolValidation` existed, and it made 18 of this file's backend
/// tests unconditionally green.
///
/// The list is asserted in both directions on purpose:
///
/// * adding a backend in one of these languages without noticing it ships
///   entirely unverified fails here, and
/// * writing a validator for one of them also fails here, prompting whoever
///   did it to shorten the list.
///
/// Rust is the sharpest entry: `validate_structural` returns `vec![]` for the
/// two `rust-*` backends too. Their generated suites parse both with
/// `syn`, but this file still has no real driver-backed validator for them.
#[cfg(all(feature = "lang-rust", feature = "lang-typescript", feature = "postgres"))]
#[test]
fn backends_with_no_tool_validator_are_a_known_and_shrinking_set() {
    const NO_TOOL_VALIDATOR: &[&str] = &[
        // Rust: `rust-sqlx` expands `sqlx::query_as!`/`sqlx::query!` at
        // compile time, needing either a live database or an `SQLX_OFFLINE`
        // `.sqlx` query cache. `rust-tokio-postgres` references its driver crate by fully-qualified path
        // with no `use` to stub around, so resolving them needs `--extern`
        // pointing at real compiled `.rlib`s -- a full Cargo dependency graph
        // per backend. The generated suite provides `syn::parse_file` syntax
        // coverage for both, and `crates/scythe-cli/tests/compile_check.rs`
        // additionally reaches `rust-sqlx`; neither is a real driver-backed
        // validator, so these remain in this inventory.
        "rust-sqlx",
        "rust-tokio-postgres",
    ];

    for backend in NO_TOOL_VALIDATOR {
        assert_eq!(
            validate_with_tools("", backend),
            ToolValidation::Unsupported,
            "{backend} is listed as having no tool validator, but one now answers for it --              remove it from NO_TOOL_VALIDATOR"
        );
    }

    // The languages that do have one must not silently regress into this set.
    const HAS_TOOL_VALIDATOR: &[&str] = &[];

    for backend in HAS_TOOL_VALIDATOR {
        assert_ne!(
            validate_with_tools("", backend),
            ToolValidation::Unsupported,
            "{backend} had a tool validator and no longer does"
        );
    }
}
