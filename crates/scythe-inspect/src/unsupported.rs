//! The driver used for every engine `scythe inspect` does not implement.
//!
//! Live inspection now covers PostgreSQL and MySQL/MariaDB (see
//! [`crate::postgres::PostgresDriver`] and [`crate::mysql::MySqlDriver`]); every
//! other engine — SQLite, MSSQL, Oracle, Snowflake, Redshift — has no `SC-INS`
//! checks and no equivalent this crate implements. That gap is real and is
//! tracked separately; what this module fixes is the *diagnostic*.
//!
//! Before this, the dispatch fell through to a MySQL stub for every
//! unimplemented engine, so a SQLite user was told `engine "mysql" is not yet
//! supported` — an engine they never mentioned. That reads as a scythe bug
//! rather than an unsupported-engine notice and sends the reader looking for a
//! defect that is not there. [`UnsupportedDriver`] carries the engine the user
//! actually asked for, so the message names it.

use async_trait::async_trait;
use scythe_lint::reporters::Finding;

use crate::driver::{CheckCatalogEntry, DbDriver};
use crate::error::InspectError;

/// A [`DbDriver`] for an engine with no implementation, which refuses every
/// operation with [`InspectError::Unsupported`] naming that engine.
///
/// Construction is infallible and connectionless, exactly like the real
/// drivers, so `--list-checks` and `--explain` keep working without reaching a
/// database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedDriver {
    engine: String,
}

impl UnsupportedDriver {
    /// Build the driver for `engine`, spelled as the user spelled it.
    pub fn new(engine: impl Into<String>) -> Self {
        Self { engine: engine.into() }
    }

    fn unsupported(&self) -> InspectError {
        // Only PostgreSQL and MySQL/MariaDB have inspection drivers; every
        // other engine is unsupported here whether or not its feature is on.
        match disabled_engine(&self.engine) {
            Some(
                error @ InspectError::EngineDisabled {
                    feature: "postgres" | "mysql",
                    ..
                },
            ) => error,
            _ => InspectError::Unsupported {
                engine: self.engine.clone(),
            },
        }
    }
}

/// [`InspectError::EngineDisabled`] when `engine` names an engine whose
/// driver this build left out, `None` when its driver is compiled in or the
/// engine has no driver at all.
///
/// Callers dispatch to a driver only under that driver's Cargo feature and
/// fall back here, so a disabled engine is reported as a missing feature
/// rather than as an engine scythe does not support.
pub fn disabled_engine(engine: &str) -> Option<InspectError> {
    // Each driver feature, the engine names it serves, and whether this build has it.
    const DRIVERS: &[(&str, &[&str], bool)] = &[
        ("duckdb", &["duckdb"], cfg!(feature = "duckdb")),
        ("mysql", &["mysql", "mariadb"], cfg!(feature = "mysql")),
        (
            "postgres",
            &["postgres", "postgresql", "pg", "cockroachdb", "crdb"],
            cfg!(feature = "postgres"),
        ),
        ("sqlite", &["sqlite", "sqlite3"], cfg!(feature = "sqlite")),
    ];
    let engine_lower = engine.to_ascii_lowercase();
    let (feature, _, _) = DRIVERS
        .iter()
        .find(|(_, names, enabled)| !enabled && names.contains(&engine_lower.as_str()))?;
    Some(InspectError::EngineDisabled {
        engine: engine.to_string(),
        feature,
    })
}

#[async_trait]
impl DbDriver for UnsupportedDriver {
    fn engine(&self) -> &str {
        &self.engine
    }

    async fn connect(&mut self, _url: &str) -> Result<(), InspectError> {
        Err(self.unsupported())
    }

    fn checks(&self) -> &[CheckCatalogEntry] {
        &[]
    }

    async fn run_all(&mut self) -> Result<Vec<Finding>, InspectError> {
        Err(self.unsupported())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The defect this type exists for: a SQLite user must not be told about
    /// MySQL. Both the error and `engine()` have to agree with the request.
    #[test]
    fn should_report_the_requested_engine_when_the_engine_is_sqlite() {
        let driver = UnsupportedDriver::new("sqlite");
        assert_eq!(driver.engine(), "sqlite");
    }

    #[tokio::test]
    async fn should_fail_connect_naming_sqlite_when_the_engine_is_sqlite() {
        let mut driver = UnsupportedDriver::new("sqlite");
        let error = driver.connect("sqlite://app.db").await.unwrap_err();

        let InspectError::Unsupported { engine } = &error else {
            panic!("expected Unsupported, got {error:?}");
        };
        assert_eq!(engine, "sqlite");
        // ~keep Checks the *subject* of the message, not bare substring
        // presence: MySQL is now a supported engine the message names in its
        // list, so `!contains("mysql")` would fail for a message that is
        // entirely correct.
        let rendered = error.to_string();
        assert!(
            rendered.starts_with("engine `sqlite` is not supported"),
            "the message must name the engine the user actually asked for: {rendered}"
        );
        assert!(
            !rendered.contains("engine `mysql`"),
            "the message must not name an engine the user never asked for: {rendered}"
        );
    }

    #[tokio::test]
    async fn should_fail_run_all_naming_the_engine_when_never_connected() {
        let mut driver = UnsupportedDriver::new("snowflake");
        let error = driver.run_all().await.unwrap_err();
        assert!(matches!(&error, InspectError::Unsupported { engine } if engine == "snowflake"));
    }

    /// MySQL is no more special than SQLite here — it used to be the engine
    /// every other engine was misreported as, and it must now be reported only
    /// when it is the one that was asked for.
    #[cfg(feature = "mysql")]
    #[tokio::test]
    async fn should_fail_naming_mysql_only_when_mysql_was_requested() {
        let mut driver = UnsupportedDriver::new("mysql");
        let error = driver.connect("mysql://localhost/x").await.unwrap_err();
        assert!(matches!(&error, InspectError::Unsupported { engine } if engine == "mysql"));
    }

    #[test]
    fn should_report_a_disabled_engine_only_when_its_feature_is_off() {
        assert_eq!(disabled_engine("PostgreSQL").is_some(), !cfg!(feature = "postgres"));
        assert_eq!(disabled_engine("mariadb").is_some(), !cfg!(feature = "mysql"));
        assert_eq!(disabled_engine("sqlite3").is_some(), !cfg!(feature = "sqlite"));
        assert_eq!(disabled_engine("duckdb").is_some(), !cfg!(feature = "duckdb"));
        assert!(
            disabled_engine("snowflake").is_none(),
            "an engine with no driver is unsupported, not disabled"
        );
    }

    #[cfg(not(feature = "postgres"))]
    #[tokio::test]
    async fn should_fail_naming_the_feature_when_the_engine_is_disabled() {
        let mut driver = UnsupportedDriver::new("postgres");
        let error = driver.connect("postgres://localhost/x").await.unwrap_err();
        assert!(matches!(&error, InspectError::EngineDisabled { engine, feature: "postgres" } if engine == "postgres"));
        assert!(error.to_string().contains("`--features postgres`"), "{error}");
    }

    #[test]
    fn should_expose_an_empty_check_catalog_for_an_unsupported_engine() {
        assert!(UnsupportedDriver::new("mariadb").checks().is_empty());
    }
}
