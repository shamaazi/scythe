//! The `LiveFixture` model: JSON fixtures under `testing_data/nullability_live/`
//! that describe a live PostgreSQL nullability scenario, plus the loader that
//! validates them before any database is touched.
//!
//! Every fixture file on disk also parses as a `tools/test-generator`
//! `Fixture` -- that tool accepts the `live` block as an opaque JSON value
//! (see its `Fixture::live`), so the block's shape is owned by this module
//! alone.

use std::path::{Path, PathBuf};

use ahash::{AHashMap, AHashSet};
use serde::Deserialize;

use crate::query_shape::{self, QueryShape};

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

/// A JSON fixture under `testing_data/nullability_live/<rule>/`.
#[derive(Debug, Clone, Deserialize)]
pub struct LiveFixture {
    pub name: String,
    pub category: String,
    /// The portable (`tools/test-generator`-flavored) DDL statements the
    /// analyzer sees. Deliberately distinct from `live.schema_profile`'s
    /// file under `_schemas/` -- the analyzer runs against this, the live
    /// database runs against that, and reconciling the two is
    /// `crate::runner`'s job, not this module's (see
    /// `validate_schema_reconciliation`, which checks *declared columns*
    /// exist in the live schema, independent of this field).
    pub schema_sql: Vec<String>,
    pub query_sql: String,
    pub expected: ExpectedBlock,
    pub live: LiveBlock,
    /// Populated after loading -- the path on disk this fixture was read from.
    #[serde(skip)]
    pub file_path: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExpectedBlock {
    pub query: ExpectedQuery,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExpectedQuery {
    pub columns: Vec<ExpectedColumn>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExpectedColumn {
    pub name: String,
    pub nullable: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveBlock {
    /// Names the live schema file `_schemas/<schema_profile>.sql`.
    pub schema_profile: String,
    pub runs: Vec<Run>,
    #[serde(default)]
    pub null_together: Vec<Vec<String>>,
}

impl LiveBlock {
    /// The live schema file this block runs against:
    /// `<schemas_root>/<schema_profile>.sql`.
    pub fn schema_path(&self, schemas_root: &Path) -> PathBuf {
        schemas_root.join(format!("{}.sql", self.schema_profile))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Run {
    pub name: String,
    /// The SQL statements that seed this run's data, executed in order.
    pub seed: Vec<String>,
    pub rows: Vec<RowExpectation>,
}

impl Run {
    /// Fails if the database returned a different number of rows than this
    /// run declares. `rows` is matched ordinally against `query_sql`'s
    /// `ORDER BY`, so a count mismatch means the fixture (or its seed data)
    /// has drifted -- it is always a hard failure, never a skip.
    pub fn check_row_count(&self, observed_row_count: usize) -> Result<(), RowCountMismatch> {
        if self.rows.len() != observed_row_count {
            return Err(RowCountMismatch {
                run: self.name.clone(),
                declared: self.rows.len(),
                observed: observed_row_count,
            });
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("run {run:?} declares {declared} row(s) but the database returned {observed}")]
pub struct RowCountMismatch {
    pub run: String,
    pub declared: usize,
    pub observed: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RowExpectation {
    #[serde(default)]
    pub non_null: Vec<String>,
    #[serde(default)]
    pub null: Vec<String>,
}

impl RowExpectation {
    /// Whether `column` is declared null (`Some(true)`), declared non-null
    /// (`Some(false)`), or not mentioned in this row (`None`).
    pub fn declared_null(&self, column: &str) -> Option<bool> {
        if self.null.iter().any(|c| c == column) {
            Some(true)
        } else if self.non_null.iter().any(|c| c == column) {
            Some(false)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum FixtureError {
    #[error("reading fixture {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parsing fixture {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("glob pattern {pattern:?}: {source}")]
    Glob {
        pattern: String,
        #[source]
        source: glob::PatternError,
    },
    #[error("globbing under {path}: {source}")]
    GlobIter {
        path: PathBuf,
        #[source]
        source: glob::GlobError,
    },
    #[error("fixture {name:?} at {path}: live fixture names must start with 'live_'")]
    MissingLivePrefix { name: String, path: PathBuf },
    #[error("fixture {name:?} at {path}: could not parse query_sql to check for a top-level ORDER BY: {source}")]
    QueryParse {
        name: String,
        path: PathBuf,
        #[source]
        source: sqlparser::parser::ParserError,
    },
    #[error("fixture {name:?} at {path}: query_sql must contain a top-level ORDER BY -- rows are matched ordinally")]
    MissingOrderBy { name: String, path: PathBuf },
    #[error("fixture {name:?} at {path}: live.runs must not be empty -- an empty list asserts nothing")]
    EmptyRuns { name: String, path: PathBuf },
    #[error(
        "fixture {name:?} at {path}: expected.query.columns must not be empty -- an empty list makes every column-level assertion vacuous"
    )]
    EmptyColumns { name: String, path: PathBuf },
    #[error("fixture {name:?} run {run:?}: rows must not be empty -- an empty list asserts nothing")]
    EmptyRows { name: String, run: String },
    #[error(
        "fixture {name:?} run {run:?} row {row}: declared column {column:?} is not mentioned as null or non_null -- every declared column must appear in every row"
    )]
    ColumnMissingFromRow {
        name: String,
        run: String,
        row: usize,
        column: String,
    },
    #[error("duplicate fixture name {name:?} in:\n  {first}\n  {second}")]
    DuplicateName {
        name: String,
        first: PathBuf,
        second: PathBuf,
    },
    #[error("fixture {name:?}: no live schema at {expected}")]
    MissingSchema { name: String, expected: PathBuf },
    #[error("fixture {name:?} run {run:?}: seed must not be empty")]
    EmptySeed { name: String, run: String },
    #[error("fixture {name:?}: null_together group {group:?} must contain at least 2 columns")]
    NullTogetherGroupTooSmall { name: String, group: Vec<String> },
    #[error(
        "fixture {name:?}: null_together group {group:?} references {column:?}, which is not in expected.query.columns"
    )]
    NullTogetherUnknownColumn {
        name: String,
        group: Vec<String>,
        column: String,
    },
    #[error(
        "fixture {name:?} run {run:?} row {row}: null_together group {group:?} is split -- {column} disagrees with the rest of the group"
    )]
    NullTogetherViolation {
        name: String,
        run: String,
        row: usize,
        group: Vec<String>,
        column: String,
    },
    #[error("fixture {name:?}: parsing live schema at {path}: {source}")]
    LiveSchemaParse {
        name: String,
        path: PathBuf,
        #[source]
        source: sqlkit_core::errors::SqlkitError,
    },
    #[error(
        "fixture {name:?}: declared column {column:?} resolves to schema column {physical_column:?}, which does not exist in the live schema at {path} -- the analyzer's schema_sql and the live schema have drifted apart"
    )]
    LiveSchemaColumnMissing {
        name: String,
        column: String,
        physical_column: String,
        path: PathBuf,
    },
}

/// Recursively loads all `.json` fixtures under `fixtures_root`, validating
/// every rule this module enforces before returning. Every fixture must have
/// its live schema file under `schemas_root` and non-empty seed SQL for
/// every run -- checked here, before any database is touched. Returns
/// fixtures sorted by `(category, name)`.
///
/// Any path component starting with `_` (e.g. `_schemas/`) *below
/// `fixtures_root`* is excluded from the glob, so a directory that holds
/// schema files or other non-fixture data can never be silently picked up
/// as a JSON fixture. The check is deliberately scoped to the path
/// *relative to `fixtures_root`* -- `fixtures_root` itself carries the full
/// filesystem path, including every ancestor directory, and checking those
/// too would silently discard every fixture whenever the checkout happens
/// to sit under a `_`-prefixed directory (e.g. `_work`, which is exactly
/// the prefix GitHub Actions self-hosted runners use).
pub fn load_fixtures(fixtures_root: &Path, schemas_root: &Path) -> Result<Vec<LiveFixture>, FixtureError> {
    let pattern = fixtures_root.join("**/*.json");
    let pattern = pattern.to_string_lossy().to_string();

    let mut fixtures = Vec::new();
    for entry in glob::glob(&pattern).map_err(|source| FixtureError::Glob {
        pattern: pattern.clone(),
        source,
    })? {
        let path = entry.map_err(|source| FixtureError::GlobIter {
            path: fixtures_root.to_path_buf(),
            source,
        })?;

        let relative = path.strip_prefix(fixtures_root).unwrap_or(&path);
        if relative
            .components()
            .any(|c| c.as_os_str().to_string_lossy().starts_with('_'))
        {
            continue;
        }

        let contents = std::fs::read_to_string(&path).map_err(|source| FixtureError::Io {
            path: path.clone(),
            source,
        })?;
        let mut fixture: LiveFixture = serde_json::from_str(&contents).map_err(|source| FixtureError::Parse {
            path: path.clone(),
            source,
        })?;
        fixture.file_path = path.clone();
        validate_fixture(&fixture, schemas_root)?;
        fixtures.push(fixture);
    }

    fixtures.sort_by(|a, b| a.category.cmp(&b.category).then_with(|| a.name.cmp(&b.name)));

    let mut seen: AHashMap<String, PathBuf> = AHashMap::new();
    for fixture in &fixtures {
        if let Some(first) = seen.insert(fixture.name.clone(), fixture.file_path.clone()) {
            return Err(FixtureError::DuplicateName {
                name: fixture.name.clone(),
                first,
                second: fixture.file_path.clone(),
            });
        }
    }

    Ok(fixtures)
}

fn validate_fixture(fixture: &LiveFixture, schemas_root: &Path) -> Result<(), FixtureError> {
    if !fixture.name.starts_with("live_") {
        return Err(FixtureError::MissingLivePrefix {
            name: fixture.name.clone(),
            path: fixture.file_path.clone(),
        });
    }

    let shape = query_shape::parse(&fixture.query_sql).map_err(|source| FixtureError::QueryParse {
        name: fixture.name.clone(),
        path: fixture.file_path.clone(),
        source,
    })?;
    if !shape.has_order_by {
        return Err(FixtureError::MissingOrderBy {
            name: fixture.name.clone(),
            path: fixture.file_path.clone(),
        });
    }

    if fixture.live.runs.is_empty() {
        return Err(FixtureError::EmptyRuns {
            name: fixture.name.clone(),
            path: fixture.file_path.clone(),
        });
    }
    if fixture.expected.query.columns.is_empty() {
        return Err(FixtureError::EmptyColumns {
            name: fixture.name.clone(),
            path: fixture.file_path.clone(),
        });
    }

    let schema_path = fixture.live.schema_path(schemas_root);
    if !schema_path.is_file() {
        return Err(FixtureError::MissingSchema {
            name: fixture.name.clone(),
            expected: schema_path,
        });
    }

    for run in &fixture.live.runs {
        if run.seed.is_empty() {
            return Err(FixtureError::EmptySeed {
                name: fixture.name.clone(),
                run: run.name.clone(),
            });
        }
    }

    validate_row_coverage(fixture)?;
    validate_null_together(fixture)?;
    validate_schema_reconciliation(fixture, &schema_path, &shape)?;

    Ok(())
}

/// Rejects an empty row list for any run, and requires every declared
/// column (`expected.query.columns`) to be mentioned -- as null or
/// non-null -- in every row. A row that doesn't mention a declared column
/// asserts nothing about it, which is exactly the fixture-level vacuity
/// this crate exists to prevent (A3 already catches this at the column
/// level; this catches it at the fixture level).
fn validate_row_coverage(fixture: &LiveFixture) -> Result<(), FixtureError> {
    let declared: Vec<&str> = fixture.expected.query.columns.iter().map(|c| c.name.as_str()).collect();

    for run in &fixture.live.runs {
        if run.rows.is_empty() {
            return Err(FixtureError::EmptyRows {
                name: fixture.name.clone(),
                run: run.name.clone(),
            });
        }
        for (row_idx, row) in run.rows.iter().enumerate() {
            for &column in &declared {
                if row.declared_null(column).is_none() {
                    return Err(FixtureError::ColumnMissingFromRow {
                        name: fixture.name.clone(),
                        run: run.name.clone(),
                        row: row_idx,
                        column: column.to_string(),
                    });
                }
            }
        }
    }
    Ok(())
}

/// Validates `live.null_together`: every group must have at least 2
/// columns (a group of 1 validates trivially and asserts nothing), every
/// column named must be a declared column (an unknown/typo'd name would
/// otherwise validate forever, since [`RowExpectation::declared_null`]
/// returns `None` for it and the old check just skipped `None`s), and no
/// declared row may split a group.
fn validate_null_together(fixture: &LiveFixture) -> Result<(), FixtureError> {
    let declared: AHashSet<&str> = fixture.expected.query.columns.iter().map(|c| c.name.as_str()).collect();

    for group in &fixture.live.null_together {
        if group.len() < 2 {
            return Err(FixtureError::NullTogetherGroupTooSmall {
                name: fixture.name.clone(),
                group: group.clone(),
            });
        }
        for column in group {
            if !declared.contains(column.as_str()) {
                return Err(FixtureError::NullTogetherUnknownColumn {
                    name: fixture.name.clone(),
                    group: group.clone(),
                    column: column.clone(),
                });
            }
        }

        for run in &fixture.live.runs {
            for (row_idx, row) in run.rows.iter().enumerate() {
                let mut declared_for_row: Option<(bool, &str)> = None;
                for column in group {
                    let Some(is_null) = row.declared_null(column) else {
                        continue;
                    };
                    match declared_for_row {
                        None => declared_for_row = Some((is_null, column)),
                        Some((expected, _)) if expected != is_null => {
                            return Err(FixtureError::NullTogetherViolation {
                                name: fixture.name.clone(),
                                run: run.name.clone(),
                                row: row_idx,
                                group: group.clone(),
                                column: column.clone(),
                            });
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    Ok(())
}

/// Reconciles the analyzer-facing `schema_sql` implicitly used by the query
/// with the live `_schemas/<profile>.sql` this fixture actually runs
/// against. Without this, nothing stops the two from drifting: the analyzer
/// would be checked against one schema while the live run checks against
/// another, which is the exact failure this crate exists to detect --
/// inverted.
///
/// For each declared column (`expected.query.columns`, plus anything named
/// in row expectations), `shape` is used to find the physical source
/// column it projects (a direct `alias.column` or bare `column` reference).
/// Computed/expression columns and columns this best-effort SQL walk can't
/// resolve to a single physical column are skipped -- a false "missing
/// column" on an expression would be worse than not checking it. Every
/// resolvable column must exist, under that name, somewhere in the live
/// schema.
fn validate_schema_reconciliation(
    fixture: &LiveFixture,
    schema_path: &Path,
    shape: &QueryShape,
) -> Result<(), FixtureError> {
    let mut declared: Vec<&str> = fixture.expected.query.columns.iter().map(|c| c.name.as_str()).collect();
    for run in &fixture.live.runs {
        for row in &run.rows {
            for column in row.non_null.iter().chain(row.null.iter()) {
                if !declared.contains(&column.as_str()) {
                    declared.push(column.as_str());
                }
            }
        }
    }

    let contents = std::fs::read_to_string(schema_path).map_err(|source| FixtureError::Io {
        path: schema_path.to_path_buf(),
        source,
    })?;
    let catalog = sqlkit_core::catalog::Catalog::from_ddl(&[contents.as_str()]).map_err(|source| {
        FixtureError::LiveSchemaParse {
            name: fixture.name.clone(),
            path: schema_path.to_path_buf(),
            source,
        }
    })?;

    for &column in &declared {
        let Some(source) = shape.source_column(column) else {
            continue;
        };
        if !query_shape::column_exists(&catalog, shape, source) {
            return Err(FixtureError::LiveSchemaColumnMissing {
                name: fixture.name.clone(),
                column: column.to_string(),
                physical_column: source.column.to_string(),
                path: schema_path.to_path_buf(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_schema(schemas_root: &Path, profile: &str) {
        std::fs::write(schemas_root.join(format!("{profile}.sql")), "CREATE TABLE t (id INT);").unwrap();
    }

    fn write_fixture(fixtures_root: &Path, file_name: &str, contents: &str) {
        std::fs::write(fixtures_root.join(file_name), contents).unwrap();
    }

    fn minimal_fixture_json(name: &str, query_sql: &str, seed: &str) -> String {
        format!(
            r#"{{
  "name": "{name}",
  "category": "nullability_live/test",
  "schema_sql": ["CREATE TABLE t (id INT)"],
  "query_sql": "{query_sql}",
  "expected": {{ "query": {{ "columns": [{{ "name": "id", "nullable": false }}] }} }},
  "live": {{
    "schema_profile": "profile",
    "runs": [
      {{
        "name": "run1",
        "seed": [{seed}],
        "rows": [{{ "non_null": ["id"], "null": [] }}]
      }}
    ]
  }}
}}"#
        )
    }

    #[test]
    fn schema_path_is_the_profile_dot_sql_under_the_schemas_root() {
        let live = LiveBlock {
            schema_profile: "users_orders".to_string(),
            runs: vec![],
            null_together: vec![],
        };
        assert_eq!(
            live.schema_path(Path::new("/schemas")),
            Path::new("/schemas/users_orders.sql")
        );
    }

    #[test]
    fn row_expectation_declared_null_distinguishes_null_non_null_and_unmentioned() {
        let row = RowExpectation {
            non_null: vec!["id".to_string()],
            null: vec!["total".to_string()],
        };
        assert_eq!(row.declared_null("id"), Some(false));
        assert_eq!(row.declared_null("total"), Some(true));
        assert_eq!(row.declared_null("notes"), None);
    }

    // -- load_fixtures: validation rules -----------------------------------

    #[test]
    fn load_fixtures_rejects_name_without_live_prefix() {
        let fixtures_root = tempfile::tempdir().unwrap();
        let schemas_root = tempfile::tempdir().unwrap();
        write_schema(schemas_root.path(), "profile");
        write_fixture(
            fixtures_root.path(),
            "f.json",
            &minimal_fixture_json("not_prefixed", "SELECT id FROM t ORDER BY id", r#""INSERT""#),
        );
        let result = load_fixtures(fixtures_root.path(), schemas_root.path());
        assert!(
            matches!(result, Err(FixtureError::MissingLivePrefix { .. })),
            "{result:?}"
        );
    }

    #[test]
    fn load_fixtures_rejects_query_without_order_by() {
        let fixtures_root = tempfile::tempdir().unwrap();
        let schemas_root = tempfile::tempdir().unwrap();
        write_schema(schemas_root.path(), "profile");
        write_fixture(
            fixtures_root.path(),
            "f.json",
            &minimal_fixture_json("live_x", "SELECT id FROM t", r#""INSERT""#),
        );
        let result = load_fixtures(fixtures_root.path(), schemas_root.path());
        assert!(matches!(result, Err(FixtureError::MissingOrderBy { .. })), "{result:?}");
    }

    #[test]
    fn load_fixtures_rejects_a_query_that_fails_to_parse() {
        let fixtures_root = tempfile::tempdir().unwrap();
        let schemas_root = tempfile::tempdir().unwrap();
        write_schema(schemas_root.path(), "profile");
        write_fixture(
            fixtures_root.path(),
            "f.json",
            &minimal_fixture_json("live_x", "SELECT FROM WHERE ORDER BY", r#""INSERT""#),
        );
        let result = load_fixtures(fixtures_root.path(), schemas_root.path());
        assert!(matches!(result, Err(FixtureError::QueryParse { .. })), "{result:?}");
    }

    #[test]
    fn load_fixtures_rejects_an_order_by_that_only_appears_inside_a_window_function() {
        // ~keep A substring match on "ORDER BY" would be satisfied by
        // `ROW_NUMBER() OVER (ORDER BY id)`, but that's not a top-level
        // ORDER BY -- row order (and therefore ordinal row matching) is
        // still undefined.
        let fixtures_root = tempfile::tempdir().unwrap();
        let schemas_root = tempfile::tempdir().unwrap();
        write_schema(schemas_root.path(), "profile");
        write_fixture(
            fixtures_root.path(),
            "f.json",
            &minimal_fixture_json(
                "live_x",
                "SELECT id, ROW_NUMBER() OVER (ORDER BY id) AS rn FROM t",
                r#""INSERT""#,
            ),
        );
        let result = load_fixtures(fixtures_root.path(), schemas_root.path());
        assert!(matches!(result, Err(FixtureError::MissingOrderBy { .. })), "{result:?}");
    }

    #[test]
    fn load_fixtures_accepts_an_order_by_split_across_lines() {
        let fixtures_root = tempfile::tempdir().unwrap();
        let schemas_root = tempfile::tempdir().unwrap();
        write_schema(schemas_root.path(), "profile");
        write_fixture(
            fixtures_root.path(),
            "f.json",
            &minimal_fixture_json("live_x", "SELECT id FROM t ORDER\\n  BY id", r#""INSERT""#),
        );
        let result = load_fixtures(fixtures_root.path(), schemas_root.path());
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn load_fixtures_rejects_a_missing_schema_file() {
        let fixtures_root = tempfile::tempdir().unwrap();
        let schemas_root = tempfile::tempdir().unwrap();
        // Deliberately do not write a schema file.
        write_fixture(
            fixtures_root.path(),
            "f.json",
            &minimal_fixture_json("live_x", "SELECT id FROM t ORDER BY id", r#""INSERT""#),
        );
        let result = load_fixtures(fixtures_root.path(), schemas_root.path());
        assert!(matches!(result, Err(FixtureError::MissingSchema { .. })), "{result:?}");
    }

    #[test]
    fn load_fixtures_rejects_a_run_with_an_empty_seed() {
        let fixtures_root = tempfile::tempdir().unwrap();
        let schemas_root = tempfile::tempdir().unwrap();
        write_schema(schemas_root.path(), "profile");
        write_fixture(
            fixtures_root.path(),
            "f.json",
            &minimal_fixture_json("live_x", "SELECT id FROM t ORDER BY id", ""),
        );
        let result = load_fixtures(fixtures_root.path(), schemas_root.path());
        assert!(matches!(result, Err(FixtureError::EmptySeed { .. })), "{result:?}");
    }

    #[test]
    fn load_fixtures_rejects_duplicate_names() {
        let fixtures_root = tempfile::tempdir().unwrap();
        let schemas_root = tempfile::tempdir().unwrap();
        write_schema(schemas_root.path(), "profile");
        let json = minimal_fixture_json("live_dup", "SELECT id FROM t ORDER BY id", r#""INSERT""#);
        write_fixture(fixtures_root.path(), "a.json", &json);
        write_fixture(fixtures_root.path(), "b.json", &json);
        let result = load_fixtures(fixtures_root.path(), schemas_root.path());
        assert!(matches!(result, Err(FixtureError::DuplicateName { .. })), "{result:?}");
    }

    #[test]
    fn load_fixtures_accepts_a_well_formed_fixture() {
        let fixtures_root = tempfile::tempdir().unwrap();
        let schemas_root = tempfile::tempdir().unwrap();
        write_schema(schemas_root.path(), "profile");
        write_fixture(
            fixtures_root.path(),
            "f.json",
            &minimal_fixture_json(
                "live_ok",
                "SELECT id FROM t ORDER BY id",
                r#""INSERT INTO t VALUES (1)""#,
            ),
        );
        let result = load_fixtures(fixtures_root.path(), schemas_root.path()).expect("well-formed fixture must load");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "live_ok");
    }

    #[test]
    fn load_fixtures_excludes_underscore_prefixed_directories_from_the_glob() {
        let fixtures_root = tempfile::tempdir().unwrap();
        let schemas_root = tempfile::tempdir().unwrap();
        write_schema(schemas_root.path(), "profile");
        write_fixture(
            fixtures_root.path(),
            "f.json",
            &minimal_fixture_json("live_ok", "SELECT id FROM t ORDER BY id", r#""INSERT""#),
        );
        let underscore_dir = fixtures_root.path().join("_schemas");
        std::fs::create_dir_all(&underscore_dir).unwrap();
        // Not a valid LiveFixture -- if the glob ever picked this up, load
        // would fail to parse it.
        std::fs::write(underscore_dir.join("not_a_fixture.json"), "{}").unwrap();

        let result = load_fixtures(fixtures_root.path(), schemas_root.path()).expect("underscore dir must be excluded");
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn load_fixtures_loads_normally_when_an_ancestor_of_fixtures_root_starts_with_underscore() {
        // ~keep The exclusion check must only look at path components *below*
        // fixtures_root. `dir.join("**/*.json")` glob results carry the
        // full path, ancestors included -- checking the whole path would
        // silently discard every fixture whenever the checkout sits under
        // a `_`-prefixed directory (e.g. `_work`, the exact prefix GitHub
        // Actions self-hosted runners use), which is precisely the
        // silently-examined-nothing failure this crate exists to catch.
        let parent = tempfile::tempdir().unwrap();
        let underscore_ancestor = parent.path().join("_work");
        let fixtures_root = underscore_ancestor.join("testing_data");
        std::fs::create_dir_all(&fixtures_root).unwrap();
        let schemas_root = tempfile::tempdir().unwrap();
        write_schema(schemas_root.path(), "profile");
        write_fixture(
            &fixtures_root,
            "f.json",
            &minimal_fixture_json("live_ok", "SELECT id FROM t ORDER BY id", r#""INSERT""#),
        );

        let result = load_fixtures(&fixtures_root, schemas_root.path())
            .expect("an underscore-prefixed ancestor of fixtures_root must not suppress fixtures");
        assert_eq!(
            result.len(),
            1,
            "fixtures_root sits under an underscore-prefixed directory but must still load"
        );
    }

    // -- validate_fixture: emptiness rejections ----------------------------

    #[test]
    fn load_fixtures_rejects_empty_columns() {
        let fixtures_root = tempfile::tempdir().unwrap();
        let schemas_root = tempfile::tempdir().unwrap();
        write_schema(schemas_root.path(), "profile");
        let json = r#"{
  "name": "live_x",
  "category": "nullability_live/test",
  "schema_sql": ["CREATE TABLE t (id INT)"],
  "query_sql": "SELECT id FROM t ORDER BY id",
  "expected": { "query": { "columns": [] } },
  "live": {
    "schema_profile": "profile",
    "runs": [
      { "name": "run1", "seed": ["INSERT"], "rows": [{ "non_null": ["id"], "null": [] }] }
    ]
  }
}"#;
        write_fixture(fixtures_root.path(), "f.json", json);
        let result = load_fixtures(fixtures_root.path(), schemas_root.path());
        assert!(matches!(result, Err(FixtureError::EmptyColumns { .. })), "{result:?}");
    }

    #[test]
    fn load_fixtures_rejects_empty_runs() {
        let fixtures_root = tempfile::tempdir().unwrap();
        let schemas_root = tempfile::tempdir().unwrap();
        write_schema(schemas_root.path(), "profile");
        let json = r#"{
  "name": "live_x",
  "category": "nullability_live/test",
  "schema_sql": ["CREATE TABLE t (id INT)"],
  "query_sql": "SELECT id FROM t ORDER BY id",
  "expected": { "query": { "columns": [{ "name": "id", "nullable": false }] } },
  "live": {
    "schema_profile": "profile",
    "runs": []
  }
}"#;
        write_fixture(fixtures_root.path(), "f.json", json);
        let result = load_fixtures(fixtures_root.path(), schemas_root.path());
        assert!(matches!(result, Err(FixtureError::EmptyRuns { .. })), "{result:?}");
    }

    #[test]
    fn load_fixtures_rejects_empty_rows() {
        let fixtures_root = tempfile::tempdir().unwrap();
        let schemas_root = tempfile::tempdir().unwrap();
        write_schema(schemas_root.path(), "profile");
        let json = r#"{
  "name": "live_x",
  "category": "nullability_live/test",
  "schema_sql": ["CREATE TABLE t (id INT)"],
  "query_sql": "SELECT id FROM t ORDER BY id",
  "expected": { "query": { "columns": [{ "name": "id", "nullable": false }] } },
  "live": {
    "schema_profile": "profile",
    "runs": [
      { "name": "run1", "seed": ["INSERT"], "rows": [] }
    ]
  }
}"#;
        write_fixture(fixtures_root.path(), "f.json", json);
        let result = load_fixtures(fixtures_root.path(), schemas_root.path());
        assert!(matches!(result, Err(FixtureError::EmptyRows { .. })), "{result:?}");
    }

    #[test]
    fn load_fixtures_rejects_a_row_missing_a_declared_column() {
        let fixtures_root = tempfile::tempdir().unwrap();
        let schemas_root = tempfile::tempdir().unwrap();
        write_schema(schemas_root.path(), "profile");
        let json = r#"{
  "name": "live_x",
  "category": "nullability_live/test",
  "schema_sql": ["CREATE TABLE t (id INT)"],
  "query_sql": "SELECT id, total FROM t ORDER BY id",
  "expected": { "query": { "columns": [{ "name": "id", "nullable": false }, { "name": "total", "nullable": true }] } },
  "live": {
    "schema_profile": "profile",
    "runs": [
      { "name": "run1", "seed": ["INSERT"], "rows": [{ "non_null": ["id"], "null": [] }] }
    ]
  }
}"#;
        write_fixture(fixtures_root.path(), "f.json", json);
        let result = load_fixtures(fixtures_root.path(), schemas_root.path());
        assert!(
            matches!(result, Err(FixtureError::ColumnMissingFromRow { .. })),
            "{result:?}"
        );
    }

    #[test]
    fn load_fixtures_rejects_a_seed_that_is_not_a_list_of_statements() {
        // ~keep `seed` is a plain list of statements; the keyed-object form
        // (`{ "default": [...] }`) must fail to parse rather than be
        // reinterpreted.

        let fixtures_root = tempfile::tempdir().unwrap();
        let schemas_root = tempfile::tempdir().unwrap();
        write_schema(schemas_root.path(), "profile");
        let json = r#"{
  "name": "live_x",
  "category": "nullability_live/test",
  "schema_sql": ["CREATE TABLE t (id INT)"],
  "query_sql": "SELECT id FROM t ORDER BY id",
  "expected": { "query": { "columns": [{ "name": "id", "nullable": false }] } },
  "live": {
    "schema_profile": "profile",
    "runs": [
      { "name": "run1", "seed": { "default": ["INSERT"] }, "rows": [{ "non_null": ["id"], "null": [] }] }
    ]
  }
}"#;
        write_fixture(fixtures_root.path(), "f.json", json);
        let result = load_fixtures(fixtures_root.path(), schemas_root.path());
        assert!(matches!(result, Err(FixtureError::Parse { .. })), "{result:?}");
    }

    #[test]
    fn load_fixtures_rejects_a_null_together_group_that_disagrees_on_a_row() {
        let fixtures_root = tempfile::tempdir().unwrap();
        let schemas_root = tempfile::tempdir().unwrap();
        write_schema(schemas_root.path(), "profile");
        let json = r#"{
  "name": "live_incoherent",
  "category": "nullability_live/test",
  "schema_sql": ["CREATE TABLE t (id INT)"],
  "query_sql": "SELECT id, a, b FROM t ORDER BY id",
  "expected": { "query": { "columns": [
    { "name": "id", "nullable": false },
    { "name": "a", "nullable": true },
    { "name": "b", "nullable": true }
  ] } },
  "live": {
    "schema_profile": "profile",
    "runs": [
      {
        "name": "run1",
        "seed": ["INSERT"],
        "rows": [{ "non_null": ["id", "a"], "null": ["b"] }]
      }
    ],
    "null_together": [["a", "b"]]
  }
}"#;
        write_fixture(fixtures_root.path(), "f.json", json);
        let result = load_fixtures(fixtures_root.path(), schemas_root.path());
        assert!(
            matches!(result, Err(FixtureError::NullTogetherViolation { .. })),
            "{result:?}"
        );
    }

    #[test]
    fn load_fixtures_rejects_a_null_together_group_of_one_column() {
        let fixtures_root = tempfile::tempdir().unwrap();
        let schemas_root = tempfile::tempdir().unwrap();
        write_schema(schemas_root.path(), "profile");
        let json = r#"{
  "name": "live_x",
  "category": "nullability_live/test",
  "schema_sql": ["CREATE TABLE t (id INT)"],
  "query_sql": "SELECT id FROM t ORDER BY id",
  "expected": { "query": { "columns": [{ "name": "id", "nullable": false }] } },
  "live": {
    "schema_profile": "profile",
    "runs": [
      { "name": "run1", "seed": ["INSERT"], "rows": [{ "non_null": ["id"], "null": [] }] }
    ],
    "null_together": [["id"]]
  }
}"#;
        write_fixture(fixtures_root.path(), "f.json", json);
        let result = load_fixtures(fixtures_root.path(), schemas_root.path());
        assert!(
            matches!(result, Err(FixtureError::NullTogetherGroupTooSmall { .. })),
            "{result:?}"
        );
    }

    #[test]
    fn load_fixtures_rejects_a_null_together_group_with_an_unknown_column() {
        let fixtures_root = tempfile::tempdir().unwrap();
        let schemas_root = tempfile::tempdir().unwrap();
        write_schema(schemas_root.path(), "profile");
        let json = r#"{
  "name": "live_x",
  "category": "nullability_live/test",
  "schema_sql": ["CREATE TABLE t (id INT)"],
  "query_sql": "SELECT id, a FROM t ORDER BY id",
  "expected": { "query": { "columns": [{ "name": "id", "nullable": false }, { "name": "a", "nullable": true }] } },
  "live": {
    "schema_profile": "profile",
    "runs": [
      { "name": "run1", "seed": ["INSERT"], "rows": [{ "non_null": ["id", "a"], "null": [] }] }
    ],
    "null_together": [["a", "totally_typoed_column"]]
  }
}"#;
        write_fixture(fixtures_root.path(), "f.json", json);
        let result = load_fixtures(fixtures_root.path(), schemas_root.path());
        assert!(
            matches!(result, Err(FixtureError::NullTogetherUnknownColumn { .. })),
            "{result:?}"
        );
    }

    // -- validate_schema_reconciliation ------------------------------------

    #[test]
    fn load_fixtures_rejects_a_column_missing_from_the_live_schema() {
        let fixtures_root = tempfile::tempdir().unwrap();
        let schemas_root = tempfile::tempdir().unwrap();
        // The live schema is missing `total`, which the query selects.
        std::fs::write(
            schemas_root.path().join("profile.sql"),
            "CREATE TABLE t (id INT NOT NULL);",
        )
        .unwrap();
        let json = r#"{
  "name": "live_x",
  "category": "nullability_live/test",
  "schema_sql": ["CREATE TABLE t (id INT)"],
  "query_sql": "SELECT id, total FROM t ORDER BY id",
  "expected": { "query": { "columns": [{ "name": "id", "nullable": false }, { "name": "total", "nullable": true }] } },
  "live": {
    "schema_profile": "profile",
    "runs": [
      { "name": "run1", "seed": ["INSERT"], "rows": [{ "non_null": ["id"], "null": ["total"] }] }
    ]
  }
}"#;
        write_fixture(fixtures_root.path(), "f.json", json);
        let result = load_fixtures(fixtures_root.path(), schemas_root.path());
        assert!(
            matches!(result, Err(FixtureError::LiveSchemaColumnMissing { .. })),
            "{result:?}"
        );
    }

    #[test]
    fn load_fixtures_accepts_an_aliased_column_that_resolves_to_a_real_schema_column() {
        let fixtures_root = tempfile::tempdir().unwrap();
        let schemas_root = tempfile::tempdir().unwrap();
        std::fs::write(
            schemas_root.path().join("profile.sql"),
            "CREATE TABLE users (id INT NOT NULL); CREATE TABLE orders (id INT NOT NULL, created_at TIMESTAMPTZ);",
        )
        .unwrap();
        let json = r#"{
  "name": "live_x",
  "category": "nullability_live/test",
  "schema_sql": ["CREATE TABLE t (id INT)"],
  "query_sql": "SELECT u.id, o.created_at AS order_created_at FROM users u LEFT JOIN orders o ON u.id = o.id ORDER BY u.id",
  "expected": { "query": { "columns": [{ "name": "id", "nullable": false }, { "name": "order_created_at", "nullable": true }] } },
  "live": {
    "schema_profile": "profile",
    "runs": [
      { "name": "run1", "seed": ["INSERT"], "rows": [{ "non_null": ["id"], "null": ["order_created_at"] }] }
    ]
  }
}"#;
        write_fixture(fixtures_root.path(), "f.json", json);
        let result = load_fixtures(fixtures_root.path(), schemas_root.path());
        assert!(result.is_ok(), "{result:?}");
    }

    // -- deny_unknown_fields ------------------------------------------------

    #[test]
    fn load_fixtures_rejects_an_unknown_field_in_the_live_block() {
        // ~keep `null_together` is `#[serde(default)]`, so without
        // `deny_unknown_fields` a typo in its key silently evaporates the
        // whole block instead of failing to parse.
        let fixtures_root = tempfile::tempdir().unwrap();
        let schemas_root = tempfile::tempdir().unwrap();
        write_schema(schemas_root.path(), "profile");
        let json = r#"{
  "name": "live_x",
  "category": "nullability_live/test",
  "schema_sql": ["CREATE TABLE t (id INT)"],
  "query_sql": "SELECT id FROM t ORDER BY id",
  "expected": { "query": { "columns": [{ "name": "id", "nullable": false }] } },
  "live": {
    "schema_profile": "profile",
    "runs": [
      { "name": "run1", "seed": ["INSERT"], "rows": [{ "non_null": ["id"], "null": [] }] }
    ],
    "null_togehter": [["id"]]
  }
}"#;
        write_fixture(fixtures_root.path(), "f.json", json);
        let result = load_fixtures(fixtures_root.path(), schemas_root.path());
        assert!(
            matches!(result, Err(FixtureError::Parse { .. })),
            "a typo'd live-block field must fail to parse, not silently vanish: {result:?}"
        );
    }

    #[test]
    fn load_fixtures_rejects_an_unknown_field_in_a_run() {
        let fixtures_root = tempfile::tempdir().unwrap();
        let schemas_root = tempfile::tempdir().unwrap();
        write_schema(schemas_root.path(), "profile");
        let json = r#"{
  "name": "live_x",
  "category": "nullability_live/test",
  "schema_sql": ["CREATE TABLE t (id INT)"],
  "query_sql": "SELECT id FROM t ORDER BY id",
  "expected": { "query": { "columns": [{ "name": "id", "nullable": false }] } },
  "live": {
    "schema_profile": "profile",
    "runs": [
      {
        "name": "run1",
        "seed": ["INSERT"],
        "rows": [{ "non_null": ["id"], "null": [] }],
        "unexpected_field": 1
      }
    ]
  }
}"#;
        write_fixture(fixtures_root.path(), "f.json", json);
        let result = load_fixtures(fixtures_root.path(), schemas_root.path());
        assert!(
            matches!(result, Err(FixtureError::Parse { .. })),
            "a typo'd run field must fail to parse: {result:?}"
        );
    }

    #[test]
    fn load_fixtures_rejects_an_unknown_field_in_a_row_expectation() {
        let fixtures_root = tempfile::tempdir().unwrap();
        let schemas_root = tempfile::tempdir().unwrap();
        write_schema(schemas_root.path(), "profile");
        let json = r#"{
  "name": "live_x",
  "category": "nullability_live/test",
  "schema_sql": ["CREATE TABLE t (id INT)"],
  "query_sql": "SELECT id FROM t ORDER BY id",
  "expected": { "query": { "columns": [{ "name": "id", "nullable": false }] } },
  "live": {
    "schema_profile": "profile",
    "runs": [
      {
        "name": "run1",
        "seed": ["INSERT"],
        "rows": [{ "non_null": ["id"], "null": [], "extra_key": "oops" }]
      }
    ]
  }
}"#;
        write_fixture(fixtures_root.path(), "f.json", json);
        let result = load_fixtures(fixtures_root.path(), schemas_root.path());
        assert!(
            matches!(result, Err(FixtureError::Parse { .. })),
            "a typo'd row-expectation field must fail to parse: {result:?}"
        );
    }

    // -- integration: the committed testing_data/nullability_live tree ------

    #[test]
    fn load_fixtures_loads_the_committed_nullability_live_tree() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testing_data/nullability_live");
        let schemas_root = root.join("_schemas");
        let fixtures = load_fixtures(&root, &schemas_root).expect("committed fixtures must load cleanly");
        assert!(!fixtures.is_empty(), "expected at least one committed live fixture");
        for fixture in &fixtures {
            assert!(fixture.name.starts_with("live_"));
        }
    }
}
