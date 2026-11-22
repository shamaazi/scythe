/// The SQL dialect queries are parsed and typed as. sqlkit supports PostgreSQL only; the type
/// remains so call sites name the dialect they rely on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SqlDialect {
    #[default]
    PostgreSQL,
}

impl SqlDialect {
    /// Convert to a boxed sqlparser dialect for use with the parser.
    pub fn to_sqlparser_dialect(&self) -> Box<dyn sqlparser::dialect::Dialect> {
        match self {
            SqlDialect::PostgreSQL => Box::new(sqlparser::dialect::PostgreSqlDialect {}),
        }
    }

    /// Parse a dialect name (case-insensitive). Returns `None` for anything but PostgreSQL.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "postgresql" | "postgres" | "pg" => Some(Self::PostgreSQL),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_str_postgresql() {
        assert_eq!(SqlDialect::from_str("postgresql"), Some(SqlDialect::PostgreSQL));
        assert_eq!(SqlDialect::from_str("postgres"), Some(SqlDialect::PostgreSQL));
        assert_eq!(SqlDialect::from_str("pg"), Some(SqlDialect::PostgreSQL));
        assert_eq!(SqlDialect::from_str("PostgreSQL"), Some(SqlDialect::PostgreSQL));
    }

    #[test]
    fn test_from_str_other_engines() {
        for name in [
            "mysql",
            "sqlite",
            "duckdb",
            "mssql",
            "oracle",
            "snowflake",
            "nosuchdb",
            "",
        ] {
            assert_eq!(SqlDialect::from_str(name), None, "{name}");
        }
    }

    #[test]
    fn test_default_is_postgresql() {
        assert_eq!(SqlDialect::default(), SqlDialect::PostgreSQL);
    }
}
