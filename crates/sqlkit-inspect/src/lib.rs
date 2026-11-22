//! Live-database health-check engine for sqlkit.
//!
//! Connects to a running database via a connection URL, runs a set of
//! catalog/operational checks, and surfaces issues as
//! [`sqlkit_lint::reporters::Finding`] values that can be emitted through the
//! same reporters used by `sqlkit audit` (human / SARIF / JSON).
//!
//! ## PostgreSQL
//!
//! With the `postgres` feature, the `SC-INS` health checks run through `PostgresDriver`
//! (backed by `tokio-postgres`), from the TOML check registry `postgres/checks.toml`.
//!
//! Catalog introspection (tables, columns, neutral types, nullability, primary keys) is a
//! separate concern: `PostgresCatalogSource` reads a live database into a
//! [`SchemaDescription`], and `fetch_live_catalog` serves code-generation callers.

pub mod config;
pub mod error;
pub mod neutral;
#[cfg(feature = "postgres")]
pub mod postgres;
pub mod registry;
pub mod schema_diff;
pub mod spec;
pub mod suppression;
#[cfg(feature = "postgres")]
pub mod verify;

pub use config::{InspectConfig, SuppressionRule, parse_inspect_section};
pub use error::InspectError;
pub use neutral::normalize_neutral_type;
#[cfg(feature = "postgres")]
pub use postgres::PostgresDriver;
pub use registry::CheckRegistry;
pub use schema_diff::{
    CompositeDescription, CompositeFieldDescription, DriftSeverities, SchemaDescription, describe_catalog, diff_schemas,
};
#[cfg(feature = "postgres")]
pub use schema_diff::{PostgresCatalogSource, drift_findings, fetch_live_catalog, fetch_live_schema};
pub use spec::{CheckCategory, CheckSpec, ConfigError, load_checks_from_file, parse_check_file};
pub use suppression::SuppressionEngine;
#[cfg(feature = "postgres")]
pub use verify::verify_queries;
