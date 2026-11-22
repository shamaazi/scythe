//! A column name that is not a valid identifier must not reach a generated
//! field declaration, in any target that cannot quote one.
//!
//! `crates/sqlkit-codegen/tests/ts_identifier_quoting_regression.rs` covers
//! the TypeScript answer, which is to quote: `"my col": string` and
//! `row["my col"]` are both legal, and a TypeScript row type is cast straight
//! onto the driver's rows, so its key has to stay the column's own spelling.
//! No other target has a quoted form for a field, and none of them read a
//! column back by the generated field name -- they use the position or the
//! raw SQL name -- so those manifests set `[naming] sanitize_field_names`
//! and get the name mangled instead.
//!
//! Before that flag existed every one of the backends below emitted its
//! column name verbatim:
//!
//!     pub my col: String      my col: str      My col string      String my col
//!
//! none of which parse.

#![cfg_attr(
    not(all(feature = "all-engines", feature = "all-languages")),
    allow(
        dead_code,
        unused_imports,
        unused_macros,
        reason = "helpers shared with tests of backends this build leaves out"
    )
)]

use sqlkit_codegen::{generate_with_backend, get_backend};
use sqlkit_core::analyzer::analyze;
use sqlkit_core::catalog::Catalog;
use sqlkit_core::parser::parse_query;

const SCHEMA: &str = "CREATE TABLE items (\
    id INT PRIMARY KEY, \
    \"my col\" TEXT NOT NULL, \
    \"with-dash\" TEXT NOT NULL, \
    \"2fa\" TEXT NOT NULL\
);";

const QUERY: &str = "-- @name FindItem\n-- @returns :one\n\
    SELECT id, \"my col\", \"with-dash\", \"2fa\" FROM items WHERE id = $1;";

/// One backend per target language that declares `sanitize_field_names`.
const MANGLING_BACKENDS: [&str; 1] = ["rust-sqlx"];

fn generate(backend_name: &str) -> String {
    let backend = get_backend(backend_name, "postgresql").expect("backend must support postgresql");
    let catalog = Catalog::from_ddl(&[SCHEMA]).expect("schema must parse");
    let parsed = parse_query(QUERY).expect("query must parse");
    let analyzed = analyze(&catalog, &parsed).expect("query must analyze");
    let code = generate_with_backend(&analyzed, &*backend).expect("codegen must succeed");
    [code.row_struct, code.query_fn, code.model_struct]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("\n")
}

/// Everything outside a string literal, so an assertion about generated
/// *code* is not satisfied or defeated by the SQL text, which keeps the
/// column's real name by design.
fn outside_string_literals(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for ch in source.chars() {
        match quote {
            Some(q) => {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == q {
                    quote = None;
                }
                out.push(' ');
            }
            None => {
                if ch == '"' || ch == '\'' {
                    quote = Some(ch);
                    out.push(' ');
                } else {
                    out.push(ch);
                }
            }
        }
    }
    out
}

#[cfg(all(feature = "lang-rust", feature = "postgres"))]
#[test]
fn no_backend_emits_a_space_or_dash_inside_a_generated_name() {
    for backend_name in MANGLING_BACKENDS {
        let code = outside_string_literals(&generate(backend_name));
        for bad in ["my col", "with-dash", "My col", "myCol ", "with-Dash"] {
            assert!(
                !code.contains(bad),
                "{backend_name}: `{bad}` cannot appear in an identifier:\n{code}"
            );
        }
    }
}

/// Compared with the separators and the case removed, because the mangled
/// name is spelled differently per manifest and per backend: `my_col` in
/// Rust, `myCol` under camelCase. What
/// every one of them must agree on is that the two words survived and are
/// joined by something an identifier can hold.
#[cfg(all(feature = "lang-rust", feature = "postgres"))]
#[test]
fn every_backend_emits_the_mangled_names() {
    for backend_name in MANGLING_BACKENDS {
        let code = generate(backend_name);
        let normalized = outside_string_literals(&code).to_lowercase().replace('_', "");
        for expected in ["mycol", "withdash"] {
            assert!(
                normalized.contains(expected),
                "{backend_name}: expected a mangled form of `{expected}`:\n{code}"
            );
        }
    }
}

/// A leading digit needs a prefix, and the prefix has to survive the case
/// conversion the manifest asks for *and* any second conversion a backend
/// applies on top. A bare `_` does not survive either, which is why the guard is a
/// word.
#[cfg(all(feature = "lang-rust", feature = "postgres"))]
#[test]
fn a_leading_digit_never_survives_into_a_generated_name() {
    for backend_name in MANGLING_BACKENDS {
        let code = outside_string_literals(&generate(backend_name));
        for line in code.lines() {
            for (index, _) in line.match_indices("2fa") {
                let preceding = line[..index].chars().next_back();
                assert!(
                    preceding.is_some_and(|c| c.is_alphanumeric() || c == '_'),
                    "{backend_name}: `2fa` starts a name on this line, which is not a valid \
                     identifier in any target language:\n{line}"
                );
            }
        }
    }
}

/// The SQL text is not a generated name and must keep the column exactly as
/// the database spells it -- mangling there would query a column that does
/// not exist.
#[cfg(all(feature = "lang-rust", feature = "postgres"))]
#[test]
fn the_sql_text_still_names_the_columns_as_the_database_does() {
    for backend_name in MANGLING_BACKENDS {
        let code = generate(backend_name);
        assert!(
            code.contains("my col"),
            "{backend_name}: the SQL must still select \"my col\":\n{code}"
        );
    }
}
