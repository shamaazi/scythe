//! The driver for an engine `sqlkit inspect` does not implement: anything but PostgreSQL. It
//! refuses every operation with an error naming the engine the user asked for.

use async_trait::async_trait;
use sqlkit_lint::reporters::Finding;

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
        // Only PostgreSQL has an inspection driver.
        match disabled_engine(&self.engine) {
            Some(
                error @ InspectError::EngineDisabled {
                    feature: "postgres", ..
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
/// rather than as an unsupported engine.
pub fn disabled_engine(engine: &str) -> Option<InspectError> {
    // Each driver feature, the engine names it serves, and whether this build has it.
    const DRIVERS: &[(&str, &[&str], bool)] = &[(
        "postgres",
        &["postgres", "postgresql", "pg"],
        cfg!(feature = "postgres"),
    )];
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

    /// Both the error and `engine()` have to agree with the engine requested.
    #[test]
    fn should_report_the_requested_engine() {
        let driver = UnsupportedDriver::new("nosuchdb");
        assert_eq!(driver.engine(), "nosuchdb");
    }

    #[tokio::test]
    async fn should_fail_connect_naming_the_requested_engine() {
        let mut driver = UnsupportedDriver::new("nosuchdb");
        let error = driver.connect("nosuchdb://app").await.unwrap_err();

        let InspectError::Unsupported { engine } = &error else {
            panic!("expected Unsupported, got {error:?}");
        };
        assert_eq!(engine, "nosuchdb");
        let rendered = error.to_string();
        assert!(
            rendered.starts_with("engine `nosuchdb` is not supported"),
            "the message must name the engine the user actually asked for: {rendered}"
        );
    }

    #[tokio::test]
    async fn should_fail_run_all_naming_the_engine_when_never_connected() {
        let mut driver = UnsupportedDriver::new("nosuchdb");
        let error = driver.run_all().await.unwrap_err();
        assert!(matches!(&error, InspectError::Unsupported { engine } if engine == "nosuchdb"));
    }

    #[test]
    fn should_report_a_disabled_engine_only_when_its_feature_is_off() {
        assert_eq!(disabled_engine("PostgreSQL").is_some(), !cfg!(feature = "postgres"));
        assert!(
            disabled_engine("nosuchdb").is_none(),
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
        assert!(UnsupportedDriver::new("nosuchdb").checks().is_empty());
    }
}
