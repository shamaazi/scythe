//! Wires fixtures, the analyzer, codegen, the live PostgreSQL [`Executor`],
//! and the four assertions in [`crate::verdict`] into one real [`Verdict`]
//! per fixture -- the part of this crate that makes every guarantee in
//! [`crate::verdict`] and [`crate::divergence`] real rather than aspirational.
//!
//! ## No silent skips
//!
//! The failure mode this whole crate exists to prevent is a green result
//! produced by examining nothing. So a [`run`] that cannot actually reach
//! PostgreSQL -- the crate was built without the `pg` feature, or no
//! connection URL was configured -- is a **hard error** returned before a
//! single fixture is evaluated, never a skip that could be mistaken for a
//! pass.

use std::path::PathBuf;

use ahash::AHashMap;

use crate::divergence::{DivergenceEntry, DivergenceError};
use crate::executor::{Executor, MissingColumn};
use crate::fixture::{LiveFixture, RowCountMismatch as FixtureRowCountMismatch};
use crate::verdict::{
    ColumnFacts, ColumnFactsError, FixtureFacts, RowCountMismatch as FactsRowCountMismatch, Verdict, evaluate,
};

/// The codegen backend whose rendered output stands in for "what sqlkit
/// actually generates" when computing G. A Rust backend, whose manifest
/// renders an optional column as `Option<{T}>`: A1 fidelity and A2
/// soundness both ask whether the generated code wraps a column.
const REPRESENTATIVE_BACKEND: &str = "rust-sqlx";

/// Connection configuration for one invocation of [`run`]. Built once per
/// process (typically from the environment via [`RunnerConfig::from_env`])
/// and shared read-only across every fixture.
#[derive(Debug, Clone, Default)]
pub struct RunnerConfig {
    /// Root directory holding `<schema_profile>.sql` live schema files
    /// (`testing_data/nullability_live/_schemas` in this repo).
    pub schemas_root: PathBuf,
    /// `postgres://` connection URL. [`run`] fails fast when it is unset.
    pub postgres_url: Option<String>,
}

impl RunnerConfig {
    /// Build a config, reading the connection URL from
    /// `SQLKIT_CONFORMANCE_POSTGRES_URL`. An unset variable becomes `None`;
    /// [`run`] is what turns that into a hard error, not this constructor.
    pub fn from_env(schemas_root: PathBuf) -> Self {
        Self {
            schemas_root,
            postgres_url: std::env::var("SQLKIT_CONFORMANCE_POSTGRES_URL").ok(),
        }
    }
}

/// The outcome of one [`run`] invocation: one real [`Verdict`] per fixture,
/// post-[`crate::divergence::reconcile`].
#[derive(Debug, Clone, Default)]
pub struct RunReport {
    pub verdicts: Vec<Verdict>,
}

impl RunReport {
    /// Whether every fixture passed. Vacuously true for an empty report --
    /// callers that care should also check that `verdicts` is non-empty.
    pub fn is_pass(&self) -> bool {
        self.verdicts.iter().all(Verdict::is_pass)
    }

    /// A human-readable summary listing every failure by fixture name --
    /// suitable for CI logs.
    pub fn summary(&self) -> String {
        use std::fmt::Write as _;

        let failed: Vec<&Verdict> = self.verdicts.iter().filter(|v| !v.is_pass()).collect();
        let mut out = String::new();
        let _ = writeln!(
            out,
            "{} fixture(s) ran ({} passed, {} failed)",
            self.verdicts.len(),
            self.verdicts.len() - failed.len(),
            failed.len(),
        );
        for verdict in &failed {
            let _ = writeln!(out, "  FAIL {}", verdict.fixture);
            for failure in &verdict.failures {
                let _ = writeln!(out, "    - {failure:?}");
            }
        }
        out
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RunnerError {
    #[error("this crate was not compiled with its \"pg\" feature, so it cannot reach PostgreSQL")]
    DriverNotCompiled,
    #[error("no PostgreSQL connection URL was configured (set SQLKIT_CONFORMANCE_POSTGRES_URL)")]
    MissingConnectionConfig,
    #[error("fixture {fixture:?}: connecting: {reason}")]
    Connect { fixture: String, reason: String },
    #[error("fixture {fixture:?}: analyzing schema_sql/query_sql: {source}")]
    Analysis {
        fixture: String,
        #[source]
        source: sqlkit_core::errors::SqlkitError,
    },
    #[error("fixture {fixture:?}: resolving generated columns: {source}")]
    Resolve {
        fixture: String,
        #[source]
        source: sqlkit_core::errors::SqlkitError,
    },
    #[error("fixture {fixture:?}: reading live schema {path:?}: {source}")]
    ReadSchema {
        fixture: String,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("fixture {fixture:?}: driver operation failed: {source}")]
    Driver {
        fixture: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("fixture {fixture:?}: {source}")]
    RowCount {
        fixture: String,
        #[source]
        source: FixtureRowCountMismatch,
    },
    #[error(
        "fixture {fixture:?}: expected.query.columns declares {column:?}, which the analyzer produced no matching \
         column for -- the fixture and query_sql have drifted apart"
    )]
    DeclaredColumnNotAnalyzed { fixture: String, column: String },
    #[error(
        "fixture {fixture:?}: run {run:?} row {row} column {column:?}: the fixture declares this value {declared} but the database returned it {observed}"
    )]
    RowNullnessMismatch {
        fixture: String,
        run: String,
        row: usize,
        column: String,
        declared: &'static str,
        observed: &'static str,
    },
    #[error("fixture {fixture:?}: the returned row does not carry an expected column: {source}")]
    MissingObservedColumn {
        fixture: String,
        #[source]
        source: MissingColumn,
    },
    #[error("fixture {fixture:?}: {source}")]
    Facts {
        fixture: String,
        #[source]
        source: FactsRowCountMismatch,
    },
    #[error("fixture {fixture:?}: {source}")]
    ColumnFacts {
        fixture: String,
        #[source]
        source: ColumnFactsError,
    },
    #[error(transparent)]
    Divergence(#[from] DivergenceError),
}

/// Run every fixture against PostgreSQL, apply the divergence registry, and
/// return the combined report.
///
/// Fails fast -- before evaluating a single fixture -- if the `pg` driver
/// is not compiled in or no connection URL is configured.
///
/// `entries` is passed straight to [`crate::divergence::reconcile`] -- the
/// *only* place this runner touches the divergence registry, so
/// staleness-then-suppression ordering (see that function's docs) cannot
/// be gotten wrong by a caller reaching for `apply`/`check_staleness`
/// directly and getting the order backwards.
pub async fn run(
    fixtures: &[LiveFixture],
    entries: &[DivergenceEntry],
    config: &RunnerConfig,
) -> Result<RunReport, RunnerError> {
    if !cfg!(feature = "pg") {
        return Err(RunnerError::DriverNotCompiled);
    }
    let url = config
        .postgres_url
        .as_deref()
        .ok_or(RunnerError::MissingConnectionConfig)?;

    let mut verdicts = Vec::with_capacity(fixtures.len());
    for fixture in fixtures {
        verdicts.push(run_one_fixture(fixture, url, config).await?);
    }

    let verdicts = crate::divergence::reconcile(entries, verdicts)?;
    Ok(RunReport { verdicts })
}

/// Connect a fresh PostgreSQL executor for `fixture` and evaluate it.
///
/// Without the `pg` feature, [`run`] has already returned
/// [`RunnerError::DriverNotCompiled`], so the arguments go unused there --
/// the `allow` below is scoped to exactly that configuration via
/// `cfg_attr`, so a `pg` build keeps the lint live.
#[cfg_attr(not(feature = "pg"), allow(unused_variables))]
async fn run_one_fixture(fixture: &LiveFixture, url: &str, config: &RunnerConfig) -> Result<Verdict, RunnerError> {
    #[cfg(feature = "pg")]
    {
        let executor = crate::executors::postgres::PgExecutor::connect(url)
            .await
            .map_err(|source| RunnerError::Connect {
                fixture: fixture.name.clone(),
                reason: source.to_string(),
            })?;
        evaluate_fixture(fixture, executor, config).await
    }
    #[cfg(not(feature = "pg"))]
    {
        Err(RunnerError::DriverNotCompiled)
    }
}

/// Drive one fixture end to end through an already-connected `executor`:
/// analyze the fixture's portable `schema_sql`/`query_sql` (A), resolve
/// generated columns against [`REPRESENTATIVE_BACKEND`]'s manifest (G), seed
/// the *live* schema profile (never the analyzer's portable one -- that is
/// the entire point of this crate), run every declared run and observe real
/// nullness (E), and evaluate all four assertions.
///
/// Only called from [`run_one_fixture`]'s feature-gated branch, so it is
/// dead code in a build without the `pg` feature -- see the `allow` there.
#[cfg_attr(not(feature = "pg"), allow(dead_code))]
async fn evaluate_fixture<E: Executor>(
    fixture: &LiveFixture,
    mut executor: E,
    config: &RunnerConfig,
) -> Result<Verdict, RunnerError> {
    let name = || fixture.name.clone();

    let schema_refs: Vec<&str> = fixture.schema_sql.iter().map(String::as_str).collect();
    let catalog = sqlkit_core::catalog::Catalog::from_ddl(&schema_refs).map_err(|source| RunnerError::Analysis {
        fixture: name(),
        source,
    })?;
    let query = sqlkit_core::parser::parse_query(&fixture.query_sql).map_err(|source| RunnerError::Analysis {
        fixture: name(),
        source,
    })?;
    let analyzed = sqlkit_core::analyzer::analyze(&catalog, &query).map_err(|source| RunnerError::Analysis {
        fixture: name(),
        source,
    })?;

    // ~keep Every column `expected.query.columns` names must actually be one
    // the analyzer produced for this query. Without this, a fixture whose
    // `query_sql` drifted out from under its `expected.query.columns` (a
    // rename, a dropped SELECT item) would still load and run: the four
    // assertions below only ever iterate `analyzed.columns`, so a declared
    // column absent from that list is never fed into any of them -- not a
    // failure, not a skip, just silently never examined. `fixture.rs`
    // validates that every declared column is *mentioned* in every row, but
    // that only checks internal consistency of the fixture file itself; it
    // has no way to know what the analyzer will actually produce for
    // `query_sql`, which is only known here.
    for expected_column in &fixture.expected.query.columns {
        if !analyzed.columns.iter().any(|c| c.name == expected_column.name) {
            return Err(RunnerError::DeclaredColumnNotAnalyzed {
                fixture: name(),
                column: expected_column.name.clone(),
            });
        }
    }

    // Representative backend for computing G (rendered nullability).
    let backend = sqlkit_codegen::get_backend(REPRESENTATIVE_BACKEND).map_err(|source| RunnerError::Resolve {
        fixture: name(),
        source,
    })?;
    let manifest = backend.manifest();
    let resolved = sqlkit_codegen::resolve::resolve_columns(&analyzed.columns, manifest, &[]).map_err(|source| {
        RunnerError::Resolve {
            fixture: name(),
            source,
        }
    })?;

    let schema_path = fixture.live.schema_path(&config.schemas_root);
    let live_schema_sql = std::fs::read_to_string(&schema_path).map_err(|source| RunnerError::ReadSchema {
        fixture: name(),
        path: schema_path,
        source,
    })?;
    executor
        .seed_schema(&live_schema_sql)
        .await
        .map_err(|source| RunnerError::Driver {
            fixture: name(),
            source: Box::new(source),
        })?;

    let mut observed_nulls: AHashMap<String, Vec<bool>> = AHashMap::new();
    let mut row_count = 0usize;

    for run in &fixture.live.runs {
        executor
            .seed_run(&run.seed)
            .await
            .map_err(|source| RunnerError::Driver {
                fixture: name(),
                source: Box::new(source),
            })?;

        let observed_rows =
            executor
                .query_nullness(&fixture.query_sql)
                .await
                .map_err(|source| RunnerError::Driver {
                    fixture: name(),
                    source: Box::new(source),
                })?;

        run.check_row_count(observed_rows.len())
            .map_err(|source| RunnerError::RowCount {
                fixture: name(),
                source,
            })?;

        for (row_index, observed_row) in observed_rows.iter().enumerate() {
            // Safe to index: check_row_count above already proved the two
            // lengths agree, and rows are matched ordinally against the
            // query's mandatory ORDER BY.
            let declared_row = &run.rows[row_index];
            for column in &analyzed.columns {
                let is_null =
                    observed_row
                        .is_null(&column.name)
                        .map_err(|source| RunnerError::MissingObservedColumn {
                            fixture: name(),
                            source,
                        })?;

                // A fixture's per-row `null`/`non_null` lists read exactly
                // like assertions, so they must be ones. Without this, a
                // fixture could declare a column NULL in a row where the
                // database returns a value and stay green -- the four
                // assertions below only consume the *observed* nulls, so
                // nothing else ever reads the declaration back. `None` is
                // a column the fixture does not mention for this row (the
                // loader requires every *declared* column to appear, but
                // `analyzed.columns` may be wider), which asserts nothing
                // by design rather than by omission.
                if let Some(declared_null) = declared_row.declared_null(&column.name)
                    && declared_null != is_null
                {
                    return Err(RunnerError::RowNullnessMismatch {
                        fixture: name(),
                        run: run.name.clone(),
                        row: row_index,
                        column: column.name.clone(),
                        declared: if declared_null { "NULL" } else { "non-NULL" },
                        observed: if is_null { "NULL" } else { "non-NULL" },
                    });
                }

                observed_nulls.entry(column.name.clone()).or_default().push(is_null);
            }
            row_count += 1;
        }
    }

    let mut column_facts = Vec::with_capacity(analyzed.columns.len());
    for (analyzed_column, resolved_column) in analyzed.columns.iter().zip(resolved.iter()) {
        let nulls = observed_nulls.remove(&analyzed_column.name).unwrap_or_default();
        let facts = ColumnFacts::from_analyzed_and_generated(analyzed_column, resolved_column, manifest, nulls)
            .map_err(|source| RunnerError::ColumnFacts {
                fixture: name(),
                source,
            })?;
        column_facts.push(facts);
    }

    let facts =
        FixtureFacts::new(fixture.name.clone(), column_facts, row_count).map_err(|source| RunnerError::Facts {
            fixture: name(),
            source,
        })?;

    Ok(evaluate(&facts))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::executor::ObservedRow;
    use crate::fixture::{ExpectedBlock, ExpectedColumn, ExpectedQuery, LiveBlock, LiveFixture, RowExpectation, Run};

    /// A driver double that never touches a network or a file beyond the
    /// schema profile [`evaluate_fixture`] itself reads. It exists to unit
    /// test the *runner's* own reconciliation logic in
    /// [`evaluate_fixture`]/[`run`] -- row-count checking, per-cell nullness
    /// comparison, missing-column detection -- in isolation from any real
    /// database, which is exactly what [`Executor`] (see its module docs)
    /// exists to make possible.
    struct FakeExecutor {
        rows: Vec<ObservedRow>,
    }

    #[derive(Debug, thiserror::Error)]
    #[error("fake executor error")]
    struct FakeExecutorError;

    impl Executor for FakeExecutor {
        type Error = FakeExecutorError;

        async fn seed_schema(&mut self, _schema_sql: &str) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn seed_run(&mut self, _statements: &[String]) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn query_nullness(&mut self, _query_sql: &str) -> Result<Vec<ObservedRow>, Self::Error> {
            Ok(self.rows.clone())
        }
    }

    /// A minimal, otherwise-valid fixture: `SELECT id, total FROM t ORDER BY
    /// id` against `CREATE TABLE t (id INTEGER, total INTEGER)`, declaring
    /// `id` and `total` with one run whose rows are supplied by the caller.
    fn fixture_with_rows(rows: Vec<RowExpectation>) -> LiveFixture {
        fixture_with_columns_and_rows(vec!["id".to_string(), "total".to_string()], rows)
    }

    fn fixture_with_columns_and_rows(declared_columns: Vec<String>, rows: Vec<RowExpectation>) -> LiveFixture {
        LiveFixture {
            name: "live_runner_test".to_string(),
            category: "test".to_string(),
            schema_sql: vec!["CREATE TABLE t (id INTEGER, total INTEGER)".to_string()],
            // ~keep The `-- @name` line is not decoration: the analyzer rejects an
            // unnamed query with MissingAnnotation before it ever reaches the
            // nullness comparison these tests exist to exercise.
            query_sql: "-- @name LiveRunnerProbe\n-- @returns :many\nSELECT id, total FROM t ORDER BY id".to_string(),
            expected: ExpectedBlock {
                query: ExpectedQuery {
                    columns: declared_columns
                        .into_iter()
                        .map(|name| ExpectedColumn { name, nullable: true })
                        .collect(),
                },
            },
            live: LiveBlock {
                schema_profile: "profile".to_string(),
                runs: vec![Run {
                    name: "run1".to_string(),
                    seed: vec!["INSERT INTO t VALUES (1, NULL)".to_string()],
                    rows,
                }],
                null_together: vec![],
            },
            file_path: PathBuf::new(),
        }
    }

    /// Builds a `RunnerConfig` and writes a matching `profile.sql`
    /// live schema file under a fresh temp directory -- `evaluate_fixture`
    /// reads that file from disk before ever calling the executor.
    fn config_with_schema(schemas_root: &std::path::Path) -> RunnerConfig {
        std::fs::write(
            schemas_root.join("profile.sql"),
            "CREATE TABLE t (id INTEGER, total INTEGER);",
        )
        .unwrap();
        RunnerConfig {
            schemas_root: schemas_root.to_path_buf(),
            postgres_url: None,
        }
    }

    #[tokio::test]
    async fn evaluate_fixture_errors_when_a_column_declared_null_is_observed_non_null() {
        let schemas_root = tempfile::tempdir().unwrap();
        let config = config_with_schema(schemas_root.path());
        let fixture = fixture_with_rows(vec![RowExpectation {
            non_null: vec!["id".to_string()],
            null: vec!["total".to_string()],
        }]);
        let executor = FakeExecutor {
            rows: vec![ObservedRow::new([
                ("id".to_string(), false),
                ("total".to_string(), false),
            ])],
        };

        let result = evaluate_fixture(&fixture, executor, &config).await;

        match result {
            Err(RunnerError::RowNullnessMismatch {
                column,
                declared,
                observed,
                row,
                ..
            }) => {
                assert_eq!(column, "total");
                assert_eq!(declared, "NULL");
                assert_eq!(observed, "non-NULL");
                assert_eq!(row, 0);
            }
            other => panic!("expected RowNullnessMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn evaluate_fixture_errors_when_a_column_declared_non_null_is_observed_null() {
        let schemas_root = tempfile::tempdir().unwrap();
        let config = config_with_schema(schemas_root.path());
        let fixture = fixture_with_rows(vec![RowExpectation {
            non_null: vec!["id".to_string()],
            null: vec!["total".to_string()],
        }]);
        let executor = FakeExecutor {
            rows: vec![ObservedRow::new([
                ("id".to_string(), true),
                ("total".to_string(), true),
            ])],
        };

        let result = evaluate_fixture(&fixture, executor, &config).await;

        match result {
            Err(RunnerError::RowNullnessMismatch {
                column,
                declared,
                observed,
                ..
            }) => {
                assert_eq!(column, "id");
                assert_eq!(declared, "non-NULL");
                assert_eq!(observed, "NULL");
            }
            other => panic!("expected RowNullnessMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn evaluate_fixture_errors_when_the_executor_omits_a_declared_column() {
        let schemas_root = tempfile::tempdir().unwrap();
        let config = config_with_schema(schemas_root.path());
        let fixture = fixture_with_rows(vec![RowExpectation {
            non_null: vec!["id".to_string()],
            null: vec!["total".to_string()],
        }]);
        // `total` is never reported at all -- a name/case mismatch, not a
        // nullness disagreement.
        let executor = FakeExecutor {
            rows: vec![ObservedRow::new([("id".to_string(), false)])],
        };

        let result = evaluate_fixture(&fixture, executor, &config).await;

        assert!(
            matches!(result, Err(RunnerError::MissingObservedColumn { .. })),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn evaluate_fixture_errors_when_the_executor_returns_the_wrong_row_count() {
        let schemas_root = tempfile::tempdir().unwrap();
        let config = config_with_schema(schemas_root.path());
        let fixture = fixture_with_rows(vec![RowExpectation {
            non_null: vec!["id".to_string()],
            null: vec!["total".to_string()],
        }]);
        // One row is declared; the executor reports none.
        let executor = FakeExecutor { rows: vec![] };

        let result = evaluate_fixture(&fixture, executor, &config).await;

        assert!(matches!(result, Err(RunnerError::RowCount { .. })), "{result:?}");
    }

    #[tokio::test]
    async fn evaluate_fixture_errors_when_a_declared_column_is_not_produced_by_the_analyzer() {
        // ~keep The direct regression test for the "declared columns are
        // never reconciled" gap: `expected.query.columns` names a column the
        // query does not select. Before this check existed, nothing in this
        // crate ever compared `expected.query.columns` against what the
        // analyzer actually produced, so this column would silently never be
        // fed into any of the four assertions.
        let schemas_root = tempfile::tempdir().unwrap();
        let config = config_with_schema(schemas_root.path());
        let fixture = fixture_with_columns_and_rows(
            vec!["id".to_string(), "total".to_string(), "does_not_exist".to_string()],
            vec![RowExpectation {
                non_null: vec!["id".to_string(), "does_not_exist".to_string()],
                null: vec!["total".to_string()],
            }],
        );
        let executor = FakeExecutor {
            rows: vec![ObservedRow::new([
                ("id".to_string(), false),
                ("total".to_string(), true),
            ])],
        };

        let result = evaluate_fixture(&fixture, executor, &config).await;

        match result {
            Err(RunnerError::DeclaredColumnNotAnalyzed { column, .. }) => {
                assert_eq!(column, "does_not_exist");
            }
            other => panic!("expected DeclaredColumnNotAnalyzed, got {other:?}"),
        }
    }

    #[cfg(not(feature = "pg"))]
    #[tokio::test]
    async fn run_fails_fast_when_the_pg_driver_is_not_compiled() {
        // ~keep This crate's default feature set is `[]` (see Cargo.toml), so
        // `pg` is off unless a caller explicitly opts in. A run that cannot
        // reach PostgreSQL must be a hard error, never a vacuous pass.
        let config = RunnerConfig {
            schemas_root: PathBuf::new(),
            postgres_url: Some("postgres://unused".to_string()),
        };

        let result = run(&[], &[], &config).await;

        assert!(matches!(result, Err(RunnerError::DriverNotCompiled)), "{result:?}");
    }

    #[cfg(feature = "pg")]
    #[tokio::test]
    async fn run_fails_fast_when_no_connection_url_is_configured() {
        let config = RunnerConfig {
            schemas_root: PathBuf::new(),
            postgres_url: None,
        };

        let result = run(&[], &[], &config).await;

        assert!(
            matches!(result, Err(RunnerError::MissingConnectionConfig)),
            "{result:?}"
        );
    }
}
