//! PostgreSQL driver — connects via `tokio-postgres` and runs checks from the
//! TOML-driven registry.

use std::collections::HashMap;

use sqlkit_lint::reporters::Finding;
use sqlkit_lint::types::Severity;
use tokio_postgres::{Client, NoTls};

use crate::error::InspectError;
use crate::registry::CheckRegistry;
use crate::spec::CheckSpec;
use crate::suppression::SuppressionEngine;

pub mod runner;

/// Build the [`Finding`] reported when a check's SQL cannot be executed.
///
/// A check may fail for reasons that have nothing to do with the schema under
/// inspection: a catalog view missing on an unusual build, a role without
/// permission to read it, or a bug in the check's own SQL.  Reporting the
/// failure as a warning keeps the remaining checks useful instead of losing the
/// whole run to one bad query.
///
/// The finding keeps the failing check's `rule_id` so existing suppression
/// rules continue to address it by ID.
fn check_failure_finding(spec: &CheckSpec, error: &InspectError) -> Finding {
    let detail = crate::error::error_chain(error);

    Finding {
        file: String::new(),
        query_name: None,
        rule_id: spec.id.clone(),
        rule_name: Some(format!("{}-check-failed", spec.name)),
        rule_description: Some(spec.description.clone()),
        severity: Severity::Warn,
        message: format!("check `{}` could not be executed: {detail}", spec.id),
        line: None,
        column: None,
        cwe: Vec::new(),
        source: Some("inspect".to_string()),
    }
}

/// The check ID for SC-INS10 (rls-disabled-in-public). When `api_schemas` is
/// configured, the post-run filter restricts SC-INS10 findings to schemas in
/// that list.  When `api_schemas` is empty the filter defaults to `["public"]`.
///
/// SC-INS10's SQL reports tables without RLS across ALL user schemas so the
/// filter (not the SQL) determines scope.  This keeps the SQL simple while
/// making the scope configurable without SQL parameterisation.
const SC_INS10_ID: &str = "SC-INS10";

/// An open connection to a PostgreSQL server, with the server version the
/// checks are gated on.
pub struct PostgresConnection {
    client: Client,
    /// `server_version_num`, e.g. `160004` for PostgreSQL 16.4.
    server_version: u32,
}

impl PostgresConnection {
    /// Connect to `url` and read the server's version.
    ///
    /// # Errors
    ///
    /// [`InspectError::Connect`] when the connection cannot be opened or the
    /// version cannot be read.
    pub async fn open(url: &str) -> Result<Self, InspectError> {
        let (client, connection) = tokio_postgres::connect(url, NoTls)
            .await
            .map_err(|e| InspectError::Connect { source: Box::new(e) })?;

        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("sqlkit-inspect: postgres connection task error: {e}");
            }
        });

        let version_row = client
            .query_one("SHOW server_version_num", &[])
            .await
            .map_err(|e| InspectError::Connect { source: Box::new(e) })?;
        let version: &str = version_row
            .try_get(0)
            .map_err(|e| InspectError::Connect { source: Box::new(e) })?;
        let server_version: u32 = version.parse().map_err(|e| InspectError::Connect {
            source: Box::<dyn std::error::Error + Send + Sync>::from(format!(
                "failed to parse server_version_num {version:?}: {e}"
            )),
        })?;

        Ok(Self { client, server_version })
    }

    /// The underlying client.
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// The server's `server_version_num`.
    pub fn server_version(&self) -> u32 {
        self.server_version
    }
}

/// PostgreSQL driver: the check registry and how its findings are filtered.
///
/// Construction is infallible and connectionless, so `--list-checks` can
/// print the catalog without touching a database. Open a
/// [`PostgresConnection`] and pass it to [`run_checks`](Self::run_checks);
/// [`connect`](Self::connect) and [`run_all`](Self::run_all) do the same in
/// two steps, holding the connection in the driver.
pub struct PostgresDriver {
    /// The connection [`connect`](Self::connect) opened, for
    /// [`run_all`](Self::run_all).
    connection: Option<PostgresConnection>,
    /// Canonical check registry, built at `new()`.
    registry: CheckRegistry,
    /// Suppression engine built from `[[inspect.suppression]]` rules.
    ///
    /// `None` means no suppression rules are configured.
    suppression: Option<SuppressionEngine>,
    /// Schemas to apply for SC-INS10 (rls-disabled-in-public).
    ///
    /// SC-INS10 findings whose `schema_name` binding is NOT in this list are
    /// dropped.  Defaults to `["public"]` when the list is empty.
    api_schemas: Vec<String>,
}

impl PostgresDriver {
    /// Construct an unconnected driver with the canonical check registry.
    pub fn new() -> Self {
        Self::with_registry(CheckRegistry::canonical())
    }

    /// Build a driver with a pre-configured registry (e.g. after applying
    /// severity overrides and user checks from `[inspect]` config).
    pub fn with_registry(registry: CheckRegistry) -> Self {
        Self {
            connection: None,
            registry,
            suppression: None,
            api_schemas: Vec::new(),
        }
    }

    /// Set the suppression engine.
    ///
    /// The engine is bound to this driver's registry here, which is what tells
    /// it *which* result column `[[inspect.suppression]] object = "…"` and
    /// `schema = "…"` compare against. Without that binding it falls back to
    /// searching the row, and searching the row is what made suppression depend
    /// on hash-map iteration order.
    pub fn set_suppression(&mut self, mut engine: SuppressionEngine) {
        engine.bind_to_registry(&self.registry);
        self.suppression = Some(engine);
    }

    /// Set the api_schemas list for SC-INS10 filtering.  An empty list
    /// falls back to `["public"]`.
    pub fn set_api_schemas(&mut self, schemas: Vec<String>) {
        self.api_schemas = schemas;
    }

    /// Borrow the client [`connect`](Self::connect) opened (test/inspection
    /// helper).
    pub fn client(&self) -> Option<&Client> {
        self.connection.as_ref().map(PostgresConnection::client)
    }

    /// Open a connection to `url` for [`run_all`](Self::run_all), replacing
    /// any held one. Errors are returned as [`InspectError::Connect`].
    pub async fn connect(&mut self, url: &str) -> Result<(), InspectError> {
        self.connection = Some(PostgresConnection::open(url).await?);
        Ok(())
    }

    /// [`run_checks`](Self::run_checks) on the connection
    /// [`connect`](Self::connect) opened.
    ///
    /// Returns [`InspectError::NotConnected`] if `connect` has not succeeded.
    pub async fn run_all(&mut self) -> Result<Vec<Finding>, InspectError> {
        let connection = self.connection.as_ref().ok_or(InspectError::NotConnected)?;
        self.run_checks(connection).await
    }

    /// Run every check in the registry against `connection` and return their
    /// findings.
    ///
    /// A per-check failure degrades to a single warning [`Finding`] naming the
    /// check instead of stopping the run, so one bad query never loses the
    /// rest of the report.
    pub async fn run_checks(&self, connection: &PostgresConnection) -> Result<Vec<Finding>, InspectError> {
        let effective_api_schemas: Vec<&str> = if self.api_schemas.is_empty() {
            vec!["public"]
        } else {
            self.api_schemas.iter().map(|s| s.as_str()).collect()
        };

        let mut all_pairs = Vec::new();

        for spec in self.registry.all() {
            if let Some(min_major) = spec.min_pg_version
                && connection.server_version < min_major.saturating_mul(10_000)
            {
                continue;
            }

            let pairs = match runner::run_check_with_bindings(&connection.client, spec).await {
                Ok(pairs) => pairs,
                Err(error) => {
                    all_pairs.push((check_failure_finding(spec, &error), HashMap::new()));
                    continue;
                }
            };

            for (finding, bindings) in pairs {
                // The schema column comes from the check's own declaration, not
                // from a substring search over a randomly-ordered map — the
                // same defect that made suppression non-deterministic.
                if finding.rule_id == SC_INS10_ID
                    && let Some(column) = spec.schema_binding.as_deref()
                    && let Some(schema) = bindings.get(column).map(String::as_str)
                    && !effective_api_schemas.contains(&schema)
                {
                    continue;
                }

                all_pairs.push((finding, bindings));
            }
        }

        let findings = if let Some(sup) = &self.suppression {
            sup.filter(all_pairs)
        } else {
            all_pairs.into_iter().map(|(f, _)| f).collect()
        };

        Ok(findings)
    }
}

impl Default for PostgresDriver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression guard for the SC-INS13 outage: PostgreSQL only defines the
    /// two-argument `round(v, s)` for `numeric`, so `round(float8, int)` fails
    /// with SQLSTATE 42883 on every server version.  Because `run_all` used to
    /// abort on the first failing check, this single expression took the entire
    /// `sqlkit inspect` command down.
    #[test]
    fn no_check_calls_two_arg_round_on_a_float() {
        let registry = CheckRegistry::canonical();
        for spec in registry.all() {
            assert!(
                !spec.sql.contains("round((last_value::float8"),
                "check {} calls round() on a float8 — PostgreSQL has no round(double precision, integer)",
                spec.id
            );
        }
    }

    /// A check whose SQL the server rejects must degrade to a single warning
    /// rather than aborting the run, so the remaining checks still report.
    #[test]
    fn failed_check_becomes_a_warning_finding() {
        let registry = CheckRegistry::canonical();
        let spec = registry.all().first().expect("at least one check");

        let error = InspectError::MessageBindingMissing {
            check_id: spec.id.clone(),
            binding: "schema_name".to_string(),
        };
        let finding = check_failure_finding(spec, &error);

        assert_eq!(finding.rule_id, spec.id);
        assert_eq!(finding.severity, Severity::Warn);
        assert_eq!(finding.source.as_deref(), Some("inspect"));
        assert!(
            finding.message.contains("could not be executed"),
            "message should explain the check did not run: {}",
            finding.message
        );
    }

    #[tokio::test]
    async fn run_all_without_connect_errors() {
        let mut d = PostgresDriver::new();
        let err = d.run_all().await.unwrap_err();
        assert!(matches!(err, InspectError::NotConnected));
    }

    /// Sanity-check the major-version × 10_000 conversion used to gate
    /// `min_pg_version`. PG 12 = 120000, PG 16 = 160000, PG 17 = 170000.
    /// Regression guard: a check with `min_pg_version = 15` must NOT fire
    /// against a server reporting `server_version_num = 140004`, but MUST fire
    /// against one reporting `160007`.
    #[test]
    fn min_pg_version_gates_against_server_version_num_form() {
        let min_major: u32 = 15;
        let pg_14: u32 = 140004;
        let pg_16: u32 = 160007;
        assert!(pg_14 < min_major.saturating_mul(10_000));
        assert!(pg_16 >= min_major.saturating_mul(10_000));
    }
}
