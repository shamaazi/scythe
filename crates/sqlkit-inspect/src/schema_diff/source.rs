//! [`PostgresCatalogSource`]: reads a live database's schema into the neutral
//! [`SchemaDescription`] catalog shape schema drift compares, and the richer
//! code-generation catalog. It wraps [`fetch_live_schema`](super::live::fetch_live_schema)
//! and [`fetch_live_catalog`](super::live::fetch_live_catalog) for callers that
//! do not already own a `tokio_postgres::Client`.
#[cfg(feature = "postgres")]
use sqlkit_core::catalog::Catalog;
#[cfg(feature = "postgres")]
use tokio_postgres::{Client, NoTls};

#[cfg(feature = "postgres")]
use crate::error::InspectError;

#[cfg(feature = "postgres")]
use super::live::{fetch_live_catalog, fetch_live_schema};
#[cfg(feature = "postgres")]
use super::model::SchemaDescription;

/// A live PostgreSQL catalog source: a connection to read schemas through.
#[cfg(feature = "postgres")]
pub struct PostgresCatalogSource {
    client: Client,
}

#[cfg(feature = "postgres")]
impl PostgresCatalogSource {
    /// A source around an established PostgreSQL client.
    pub fn from_client(client: Client) -> Self {
        Self { client }
    }

    /// Connect to `url`.
    ///
    /// # Errors
    ///
    /// [`InspectError::Connect`] when the connection cannot be opened.
    pub async fn connect(url: &str) -> Result<Self, InspectError> {
        let (client, connection) =
            tokio_postgres::connect(url, NoTls)
                .await
                .map_err(|source| InspectError::Connect {
                    source: Box::new(source),
                })?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::warn!(error = %error, "PostgreSQL catalog connection terminated");
            }
        });
        Ok(Self { client })
    }

    /// Fetch a codegen catalog from the database.
    ///
    /// # Errors
    ///
    /// When a PostgreSQL catalog query or catalog validation fails.
    pub async fn fetch_catalog(&self, declared_schemas: &[String]) -> Result<Catalog, InspectError> {
        fetch_live_catalog(&self.client, declared_schemas).await
    }

    /// Read every table this connection can see into a [`SchemaDescription`].
    ///
    /// `declared_schemas` is the schema-qualifier scope the committed DDL
    /// declares -- see [`fetch_live_schema`] for why it is unioned with the
    /// connection's search path.
    pub async fn fetch_schema(&self, declared_schemas: &[String]) -> Result<SchemaDescription, InspectError> {
        fetch_live_schema(&self.client, declared_schemas).await
    }
}
