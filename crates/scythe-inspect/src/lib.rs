//! Live-database health-check engine for scythe.
//!
//! Connects to a running database via a connection URL, runs a set of
//! catalog/operational checks, and surfaces issues as
//! [`scythe_lint::reporters::Finding`] values that can be emitted through the
//! same reporters used by `sqlkit audit` (human / SARIF / JSON).
//!
//! ## Engines
//!
//! The `SC-INS` health checks run against PostgreSQL through [`PostgresDriver`] (backed by
//! `tokio-postgres`), from the TOML check registry `postgres/checks.toml`. Any other engine gets
//! [`UnsupportedDriver`], which refuses every operation with [`InspectError::Unsupported`]
//! naming that engine rather than reporting an empty, clean-looking result.
//!
//! Catalog introspection (tables, columns, neutral types, nullability, primary keys) is a
//! separate concern: [`schema_diff::SchemaCatalogDriver`] reads a live database into a
//! [`SchemaDescription`], implemented by [`PostgresCatalogSource`], and [`fetch_live_catalog`]
//! serves code-generation callers.

pub mod config;
pub mod driver;
pub mod error;
pub mod neutral;
#[cfg(feature = "postgres")]
pub mod postgres;
pub mod registry;
pub mod schema_diff;
pub mod spec;
pub mod suppression;
pub mod unsupported;
#[cfg(feature = "postgres")]
pub mod verify;

pub use config::{InspectConfig, SuppressionRule, parse_inspect_section};
pub use driver::{CheckCatalogEntry, DbDriver};
pub use error::InspectError;
pub use neutral::normalize_neutral_type;
#[cfg(feature = "postgres")]
pub use postgres::PostgresDriver;
pub use registry::CheckRegistry;
pub use schema_diff::{
    CompositeDescription, CompositeFieldDescription, DriftSeverities, SchemaCatalogDriver, SchemaDescription,
    describe_catalog, diff_schemas,
};
#[cfg(feature = "postgres")]
pub use schema_diff::{PostgresCatalogSource, drift_findings, fetch_live_catalog, fetch_live_schema};
pub use spec::{CheckCategory, CheckSpec, ConfigError, load_checks_from_file, parse_check_file};
pub use suppression::SuppressionEngine;
pub use unsupported::{UnsupportedDriver, disabled_engine};
#[cfg(feature = "postgres")]
pub use verify::verify_queries;
