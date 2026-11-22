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

/// PostgreSQL-backed live catalog source.
#[cfg(feature = "postgres")]
pub struct PostgresCatalogSource {
    client: Option<Client>,
}

#[cfg(feature = "postgres")]
impl PostgresCatalogSource {
    /// Build an unconnected source.
    pub fn new() -> Self {
        Self { client: None }
    }

    /// Build a source around an established PostgreSQL client.
    pub fn from_client(client: Client) -> Self {
        Self { client: Some(client) }
    }

    /// Fetch a codegen catalog from the connected database.
    ///
    /// # Errors
    ///
    /// Returns [`InspectError::NotConnected`] before [`Self::connect`] or
    /// when a PostgreSQL catalog query or catalog validation fails.
    pub async fn fetch_catalog(&mut self, declared_schemas: &[String]) -> Result<Catalog, InspectError> {
        let client = self
            .client
            .as_ref()
            .ok_or(InspectError::NotConnected { engine: "postgres" })?;
        fetch_live_catalog(client, declared_schemas).await
    }
}

#[cfg(feature = "postgres")]
impl Default for PostgresCatalogSource {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "postgres")]
impl PostgresCatalogSource {
    /// Open a connection using `url`, replacing any connection already held.
    pub async fn connect(&mut self, url: &str) -> Result<(), InspectError> {
        let (client, connection) =
            tokio_postgres::connect(url, NoTls)
                .await
                .map_err(|source| InspectError::Connect {
                    engine: "postgres",
                    source: Box::new(source),
                })?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::warn!(error = %error, "PostgreSQL catalog connection terminated");
            }
        });
        self.client = Some(client);
        Ok(())
    }

    /// Read every table this connection can see into a [`SchemaDescription`].
    ///
    /// `declared_schemas` is the schema-qualifier scope the committed DDL
    /// declares -- see [`fetch_live_schema`] for why it is unioned with the
    /// connection's search path.
    pub async fn fetch_schema(&mut self, declared_schemas: &[String]) -> Result<SchemaDescription, InspectError> {
        let client = self
            .client
            .as_ref()
            .ok_or(InspectError::NotConnected { engine: "postgres" })?;
        fetch_live_schema(client, declared_schemas).await
    }
}

#[cfg(all(test, feature = "postgres"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fetch_schema_without_connect_errors() {
        let error = PostgresCatalogSource::new()
            .fetch_schema(&[])
            .await
            .expect_err("unconnected source must fail");
        assert!(matches!(error, InspectError::NotConnected { engine: "postgres" }));
    }

    #[tokio::test]
    async fn fetch_catalog_without_connect_errors() {
        let error = PostgresCatalogSource::new()
            .fetch_catalog(&[])
            .await
            .expect_err("unconnected source must fail");
        assert!(matches!(error, InspectError::NotConnected { engine: "postgres" }));
    }
}
