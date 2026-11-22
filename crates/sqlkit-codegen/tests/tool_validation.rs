//! Validate generated code for all backends using real language tools.
//! All tools are expected to be installed.

#![cfg_attr(
    not(feature = "all-languages"),
    allow(
        dead_code,
        unused_imports,
        unused_macros,
        reason = "helpers shared with tests of backends this build leaves out"
    )
)]

use sqlkit_codegen::provenance;
use sqlkit_codegen::validation::{ToolValidation, strict_mode_enabled, validate_structural, validate_with_tools};
use sqlkit_codegen::{CodegenBackend, generate_with_backend, get_backend};
use sqlkit_core::analyzer::analyze;
use sqlkit_core::catalog::Catalog;
use sqlkit_core::parser::parse_query;

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
    let backend = get_backend(backend_name).unwrap();
    generate_full_file_from_backend(backend_name, &*backend)
}

fn generate_full_file_with_options(backend_name: &str, options: &std::collections::HashMap<String, String>) -> String {
    let mut backend = get_backend(backend_name).unwrap();
    backend.apply_options(options).unwrap();
    generate_full_file_from_backend(backend_name, &*backend)
}

fn generate_full_file_from_backend(backend_name: &str, backend: &dyn CodegenBackend) -> String {
    let (schema, queries) = (SCHEMA, [QUERY_ONE, QUERY_MANY, QUERY_EXEC]);

    let catalog = Catalog::from_ddl(&[schema]).unwrap();

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
        let parsed = parse_query(query_sql).unwrap();
        let analyzed = analyze(&catalog, &parsed).unwrap();
        let code = generate_with_backend(&analyzed, backend)
            .unwrap_or_else(|e| panic!("codegen error for backend {backend_name} on query {query_sql:?}: {e}"));
        all_codes.push(code);
    }

    // ~keep Only the *body* is accumulated here. The provenance
    // header line is added by `provenance::assemble_file` at the bottom of
    // this function, the same
    // call `sqlkit-cli`'s `assemble_output` makes.
    let mut full = backend.file_header_for_results(&all_codes);
    full.push('\n');

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

    // ~keep The point of this harness is that `tsc` and `node` below are handed
    // the bytes a real `sqlkit generate` writes, provenance header included, so
    // a header in a position the language rejects fails here.
    //
    // The version, schema, and queries values are placeholders: the
    // header's legality depends on its comment prefix and its position, not
    // on its field values.
    provenance::assemble_file(
        &provenance::header_line(
            backend,
            env!("CARGO_PKG_VERSION"),
            provenance::ENGINE,
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

#[cfg(feature = "lang-rust")]
backend_test!(test_rust_sqlx, "rust-sqlx");
#[cfg(feature = "lang-rust")]
backend_test!(test_rust_tokio_postgres, "rust-tokio-postgres");
#[cfg(feature = "lang-typescript")]
backend_test!(test_typescript_bun, "typescript-bun");

#[cfg(feature = "lang-typescript")]
backend_test_with_options!(test_typescript_bun_zod, "typescript-bun", "row_type" => "zod");
backend_test_with_options!(test_typescript_bun_camel, "typescript-bun", "field_case" => "camelCase");

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
#[cfg(all(feature = "lang-rust", feature = "lang-typescript"))]
#[test]
fn backends_with_no_tool_validator_are_a_known_and_shrinking_set() {
    const NO_TOOL_VALIDATOR: &[&str] = &[
        // Rust: `rust-sqlx` expands `sqlx::query_as!`/`sqlx::query!` at
        // compile time, needing either a live database or an `SQLX_OFFLINE`
        // `.sqlx` query cache. `rust-tokio-postgres` references its driver crate by fully-qualified path
        // with no `use` to stub around, so resolving them needs `--extern`
        // pointing at real compiled `.rlib`s -- a full Cargo dependency graph
        // per backend. The generated suite provides `syn::parse_file` syntax
        // coverage for both, and `crates/sqlkit-cli/tests/compile_check.rs`
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
