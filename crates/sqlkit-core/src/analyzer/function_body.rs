//! Analysis of a `LANGUAGE sql` function's body, which the catalog uses to
//! prove the function's results non-null.

use ahash::AHashMap;
use sqlparser::ast;

use crate::catalog::Catalog;
use crate::errors::SqlkitError;

use super::helpers::unresolved_type_error;
use super::type_conversion::sql_type_to_neutral;
use super::types::{AnalyzedColumn, Analyzer, ScopeColumn, ScopeSource};

/// An argument as the body sees it: by its name, or by `$n` for its position.
pub(crate) struct BodyArgument<'a> {
    pub(crate) name: String,
    pub(crate) sql_type: &'a str,
}

/// Analyze `body`, the query a function evaluates, with its arguments in an
/// enclosing scope named after the function, so a column of the body's own
/// relations takes precedence over an argument of the same name and
/// `function.argument` names the argument, as in PostgreSQL.
///
/// `arguments_nullable` is whether the body can see a null argument: a
/// STRICT function never evaluates its body for one. Fails when the body
/// does not analyze or a result column has no type.
pub(crate) fn analyze_function_body(
    catalog: &Catalog,
    body: &ast::Query,
    function_name: &str,
    arguments: &[BodyArgument<'_>],
    arguments_nullable: bool,
) -> Result<Vec<AnalyzedColumn>, SqlkitError> {
    let columns = arguments
        .iter()
        .map(|argument| {
            ScopeColumn::from_catalog(
                argument.name.clone(),
                argument.sql_type,
                sql_type_to_neutral(argument.sql_type, catalog).into_owned(),
                arguments_nullable,
            )
        })
        .collect();
    let mut analyzer = Analyzer {
        catalog,
        params: Vec::new(),
        ctes: AHashMap::new(),
        type_errors: Vec::new(),
        pending_nested: Vec::new(),
        next_nested_id: 0,
        outer_sources: vec![ScopeSource {
            alias: function_name.to_string(),
            table_name: function_name.to_string(),
            columns,
            nullable_from_join: false,
        }],
    };
    let columns = analyzer.analyze_query(body)?;
    if let Some(error) = analyzer.type_errors.first() {
        return Err(SqlkitError::type_mismatch(error.clone()));
    }
    for column in &columns {
        if let Some(error) = unresolved_type_error(&column.neutral_type, "function result", &column.name) {
            return Err(error);
        }
    }
    Ok(columns)
}

#[cfg(test)]
mod tests {
    use crate::analyzer::analyze;
    use crate::catalog::Catalog;
    use crate::parser::parse_query;

    fn catalog() -> Catalog {
        Catalog::from_ddl(&[
            "CREATE FUNCTION report(text, reveal boolean) RETURNS TABLE (id integer, email text, shown text)
                LANGUAGE sql STABLE AS $$
                SELECT p.id, p.email, CASE WHEN reveal THEN coalesce(p.email, '') ELSE '' END
                FROM payment_facts p WHERE $1::text IS NULL OR p.email = $1
                $$;",
            "CREATE FUNCTION code(name text) RETURNS text LANGUAGE sql IMMUTABLE STRICT RETURN upper(name);",
            "CREATE FUNCTION ids() RETURNS SETOF integer LANGUAGE sql AS 'SELECT id FROM payments';",
            "CREATE FUNCTION labels() RETURNS SETOF text LANGUAGE sql AS 'SELECT code(email) FROM payments';",
            "CREATE TABLE payments (id integer NOT NULL, email text, name text NOT NULL);",
            "CREATE VIEW payment_facts AS SELECT id, email FROM payments;",
        ])
        .expect("schema should parse")
    }

    fn nullability(sql: &str) -> Vec<(String, bool)> {
        let query = parse_query(sql).expect("query should parse");
        analyze(&catalog(), &query)
            .expect("query should analyze")
            .columns
            .into_iter()
            .map(|column| (column.name, column.nullable))
            .collect()
    }

    #[test]
    fn should_type_function_scan_columns_as_the_body_proves() {
        assert_eq!(
            nullability(
                "-- @name Report\n-- @returns :many\n\
                 WITH facts AS (SELECT * FROM report($1, $2)) SELECT id, email, shown FROM facts;"
            ),
            vec![
                ("id".to_string(), false),
                ("email".to_string(), true),
                ("shown".to_string(), false),
            ]
        );
    }

    #[test]
    fn should_type_a_strict_call_as_null_for_a_null_argument() {
        assert_eq!(
            nullability(
                "-- @name Codes\n-- @returns :many\n\
                 SELECT code(name) AS from_name, code(email) AS from_email FROM payments;"
            ),
            vec![("from_name".to_string(), false), ("from_email".to_string(), true)]
        );
    }

    #[test]
    fn should_type_set_function_elements_as_the_body_proves() {
        assert_eq!(
            nullability(
                "-- @name Labels\n-- @returns :many\n\
                 SELECT i.id, l.label FROM ids() AS i(id) CROSS JOIN labels() AS l(label);"
            ),
            vec![("id".to_string(), false), ("label".to_string(), true)]
        );
    }
}
