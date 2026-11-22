//! `[[sql.gen]]` `output` containing `{dir}` generates one module per query
//! file, into that file's directory relative to the config, holding only that
//! file's queries -- and `sqlkit check` verifies each module's provenance
//! against its own file.
//!
//! Every test drives the compiled binary via
//! `Command::new(env!("CARGO_BIN_EXE_sqlkit"))`.

use std::path::Path;
use std::process::{Command, Output};

use tempfile::TempDir;

fn sqlkit(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sqlkit"))
        .args(args)
        .output()
        .expect("run sqlkit")
}

/// Both streams: findings go to stdout, progress and errors to stderr.
fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

const SCHEMA_SQL: &str = "CREATE TABLE users (id bigint PRIMARY KEY, name text NOT NULL);\n\
    CREATE TABLE posts (id bigint PRIMARY KEY, user_id bigint NOT NULL, title text NOT NULL);\n";

const USERS_SQL: &str = "-- @name GetUser\n-- @returns :one\nSELECT id, name FROM users WHERE id = $1;\n\n\
    -- @name CountRows\n-- @returns :one\nSELECT count(*) AS total FROM users;\n";

const POSTS_SQL: &str = "-- @name ListPosts\n-- @returns :many\nSELECT id, title FROM posts WHERE user_id = $1;\n\n\
    -- @name CountRows\n-- @returns :one\nSELECT count(*) AS total FROM posts;\n";

const CONFIG: &str = "[sqlkit]\nversion = \"1\"\n\n\
    [[sql]]\nname = \"main\"\nengine = \"postgresql\"\n\
    schema = [\"schema.sql\"]\nqueries = [\"src/**/queries.sql\"]\n\n\
    [[sql.gen]]\nbackend = \"typescript-bun\"\noutput = \"{dir}\"\n";

/// A project with `src/users/queries.sql` and `src/posts/queries.sql`, both
/// defining a `CountRows` query.
fn project() -> TempDir {
    let root = TempDir::new().unwrap();
    let dir = root.path();
    std::fs::write(dir.join("schema.sql"), SCHEMA_SQL).unwrap();
    for (module, sql) in [("users", USERS_SQL), ("posts", POSTS_SQL)] {
        std::fs::create_dir_all(dir.join("src").join(module)).unwrap();
        std::fs::write(dir.join("src").join(module).join("queries.sql"), sql).unwrap();
    }
    std::fs::write(dir.join("sqlkit.toml"), CONFIG).unwrap();
    root
}

fn config_arg(dir: &Path) -> String {
    dir.join("sqlkit.toml").to_str().unwrap().to_string()
}

fn generate(dir: &Path) {
    let output = sqlkit(&["generate", "--config", &config_arg(dir)]);
    assert!(output.status.success(), "generate failed: {}", combined(&output));
}

#[test]
fn dir_output_writes_one_module_per_query_file_with_only_its_queries() {
    let root = project();
    generate(root.path());

    let users = std::fs::read_to_string(root.path().join("src/users/queries.ts")).unwrap();
    let posts = std::fs::read_to_string(root.path().join("src/posts/queries.ts")).unwrap();

    assert!(users.contains("getUser"), "{users}");
    assert!(
        !users.contains("listPosts"),
        "users module must not hold posts queries:\n{users}"
    );
    assert!(posts.contains("listPosts"), "{posts}");
    assert!(
        !posts.contains("getUser"),
        "posts module must not hold users queries:\n{posts}"
    );
    // The same query name in two files is two modules, not a collision.
    assert!(users.contains("FROM users") && users.contains("countRows"), "{users}");
    assert!(posts.contains("FROM posts") && posts.contains("countRows"), "{posts}");
    assert!(
        !root.path().join("{dir}").exists(),
        "the placeholder must never become a literal directory"
    );

    let fingerprint = |module: &str| {
        module
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().find(|field| field.starts_with("queries=")))
            .map(str::to_string)
    };
    assert_ne!(
        fingerprint(&users),
        fingerprint(&posts),
        "each module fingerprints its own queries"
    );
}

#[test]
fn check_verifies_dir_output_provenance_per_query_file() {
    let root = project();
    generate(root.path());

    let output = sqlkit(&["check", "--config", &config_arg(root.path())]);
    let err = combined(&output);
    assert!(output.status.success(), "check must pass after generate: {err}");
    assert!(!err.contains("SC-PRV"), "no provenance findings expected: {err}");
    assert!(!err.contains("SC-C03"), "names repeat only across files: {err}");

    // Editing one file's queries drifts only that file's module.
    let posts = root.path().join("src/posts/queries.sql");
    std::fs::write(
        &posts,
        POSTS_SQL.replace("SELECT id, title", "SELECT id, user_id, title"),
    )
    .unwrap();
    let output = sqlkit(&["check", "--config", &config_arg(root.path())]);
    let err = combined(&output);
    assert!(!output.status.success(), "query drift must fail check: {err}");
    assert!(err.contains("SC-PRV08"), "{err}");
    assert!(err.contains("posts"), "{err}");
    assert!(
        !err.contains(&format!("users{}queries.ts", std::path::MAIN_SEPARATOR)),
        "the untouched module must not drift: {err}"
    );
}

/// Each module is named after its query file, so one directory holds several;
/// a query file with no queries gets no module, and `check` agrees.
#[test]
fn dir_output_names_each_module_after_its_query_file() {
    let root = project();
    std::fs::write(
        root.path().join("src/users/more.sql"),
        "-- @name ListUsers\n-- @returns :many\nSELECT id FROM users;\n",
    )
    .unwrap();
    std::fs::write(root.path().join("src/users/empty.sql"), "").unwrap();
    let config = CONFIG.replace("src/**/queries.sql", "src/**/*.sql");
    std::fs::write(root.path().join("sqlkit.toml"), config).unwrap();
    generate(root.path());

    let users = std::fs::read_to_string(root.path().join("src/users/queries.ts")).unwrap();
    let more = std::fs::read_to_string(root.path().join("src/users/more.ts")).unwrap();
    assert!(users.contains("getUser") && !users.contains("listUsers"), "{users}");
    assert!(more.contains("listUsers") && !more.contains("getUser"), "{more}");
    assert!(
        !root.path().join("src/users/empty.ts").exists(),
        "a query file with no queries gets no module"
    );

    let output = sqlkit(&["check", "--config", &config_arg(root.path())]);
    let err = combined(&output);
    assert!(output.status.success(), "check must pass after generate: {err}");
    assert!(!err.contains("SC-PRV"), "no provenance findings expected: {err}");
}

/// Two query files with the same stem in one directory still collide.
#[test]
fn dir_output_rejects_two_query_files_with_one_module_name() {
    let root = project();
    std::fs::write(
        root.path().join("src/users/queries.pgsql"),
        "-- @name ListUsers\n-- @returns :many\nSELECT id FROM users;\n",
    )
    .unwrap();
    let config = CONFIG.replace("src/**/queries.sql", "src/**/queries.*");
    std::fs::write(root.path().join("sqlkit.toml"), config).unwrap();

    let output = sqlkit(&["generate", "--config", &config_arg(root.path())]);
    let err = combined(&output);
    assert!(!output.status.success(), "the two modules must collide: {err}");
    assert!(err.contains("both write"), "{err}");
    assert!(!root.path().join("src/users/queries.ts").exists(), "nothing written");
}
