//! The plain `--` comment above a query's annotations is the generated
//! function's doc comment in every backend: `///` lines in Rust, JSDoc in
//! TypeScript, `:batch` functions included.

use sqlkit_codegen::{generate_with_backend, get_backend};
use sqlkit_core::analyzer::analyze;
use sqlkit_core::catalog::Catalog;
use sqlkit_core::parser::parse_query;

const SCHEMA: &str = "CREATE TABLE users (id integer PRIMARY KEY, name text NOT NULL);";

const GET: &str = "-- The user, as stored now.\n--\n-- Missing users are an error.\n\
    -- @name GetUser\n-- @returns :one\nSELECT id, name FROM users WHERE id = $1;";

const RENAME: &str = "-- Rename each user.\n-- @name RenameUsers\n-- @returns :batch\n\
    UPDATE users SET name = $2 WHERE id = $1;";

const PLAIN: &str = "-- @name ListUsers\n-- @returns :many\nSELECT id, name FROM users;";

fn query_fn(backend: &str, sql: &str) -> String {
    let catalog = Catalog::from_ddl(&[SCHEMA]).unwrap();
    let analyzed = analyze(&catalog, &parse_query(sql).unwrap()).unwrap();
    let backend = get_backend(backend).unwrap();
    generate_with_backend(&analyzed, backend.as_ref())
        .unwrap()
        .query_fn
        .unwrap()
}

#[cfg(feature = "lang-rust")]
#[test]
fn rust_backends_render_the_description_as_doc_comments() {
    for backend in ["rust-sqlx", "rust-tokio-postgres"] {
        let get = query_fn(backend, GET);
        assert!(
            get.contains("/// The user, as stored now.\n///\n/// Missing users are an error.\npub async fn get_user("),
            "{backend}:\n{get}"
        );
        let rename = query_fn(backend, RENAME);
        assert!(
            rename.contains("/// Rename each user.\npub async fn rename_users_batch("),
            "{backend}:\n{rename}"
        );
        assert!(!query_fn(backend, PLAIN).contains("///"), "{backend}");
    }
}

#[cfg(feature = "lang-typescript")]
#[test]
fn typescript_renders_the_description_on_batch_functions() {
    let rename = query_fn("typescript-bun", RENAME);
    assert!(
        rename.contains("/** Rename each user. */\nexport async function renameUsersBatch("),
        "{rename}"
    );
    let get = query_fn("typescript-bun", GET);
    assert!(
        get.contains("/**\n * The user, as stored now.\n *\n * Missing users are an error.\n */\n"),
        "{get}"
    );
    assert!(query_fn("typescript-bun", PLAIN).contains("/** Fetch all "));
}
