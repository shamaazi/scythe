//! Result nullability proved by `LANGUAGE sql` function bodies.
//!
//! PostgreSQL inlines a SQL function into the query that calls it, so the
//! planner sees through it; sqlkit likewise analyzes the body and types the
//! function's results as the body produces them instead of as nullable.

use std::ops::ControlFlow;

use sqlparser::ast::{self, CreateFunctionBody, Expr, GroupByExpr, Ident, SetExpr, Statement, Value};
use sqlparser::parser::Parser;

use crate::analyzer::{BodyArgument, analyze_function_body};
use crate::dialect::SqlDialect;

use super::{Catalog, FunctionArgumentMode, FunctionReturn};

/// Set-returning functions PostgreSQL provides, which make a `SELECT` without
/// `FROM` return any number of rows when they appear in its select list.
const BUILTIN_SET_RETURNING_FUNCTIONS: &[&str] = &[
    "generate_series",
    "generate_subscripts",
    "unnest",
    "json_array_elements",
    "json_array_elements_text",
    "jsonb_array_elements",
    "jsonb_array_elements_text",
    "json_each",
    "json_each_text",
    "jsonb_each",
    "jsonb_each_text",
    "json_object_keys",
    "jsonb_object_keys",
    "json_populate_recordset",
    "jsonb_populate_recordset",
    "json_to_recordset",
    "jsonb_to_recordset",
    "jsonb_path_query",
    "regexp_matches",
    "regexp_split_to_table",
    "string_to_table",
];

/// The query a `LANGUAGE sql` function's body evaluates, when sqlkit can
/// parse it: the last statement of an `AS '...'` body, or `SELECT expr` for a
/// SQL-standard `RETURN expr` body. Each `$n` placeholder becomes a reference
/// to the column `"$n"` that [`Catalog::refine_function_results`] provides
/// for the argument at that position.
pub(super) fn refinable_body(
    body: Option<&CreateFunctionBody>,
    language: Option<&Ident>,
    returns_set: bool,
    return_type: &FunctionReturn,
    dialect: SqlDialect,
) -> Option<Box<ast::Query>> {
    // Output parameters without SETOF describe a single row, which is null
    // when the body returns none.
    if dialect != SqlDialect::PostgreSQL || matches!(return_type, FunctionReturn::Table { .. }) && !returns_set {
        return None;
    }
    let is_sql = |language: Option<&Ident>| language.is_some_and(|language| language.value.eq_ignore_ascii_case("sql"));
    let source = match body? {
        CreateFunctionBody::AsBeforeOptions { body, .. } | CreateFunctionBody::AsAfterOptions(body)
            if is_sql(language) =>
        {
            match body {
                Expr::Value(value) => match &value.value {
                    Value::DollarQuotedString(quoted) => quoted.value.clone(),
                    Value::SingleQuotedString(text) => text.clone(),
                    _ => return None,
                },
                _ => return None,
            }
        }
        CreateFunctionBody::Return(expression) if language.is_none() || is_sql(language) => {
            format!("SELECT {expression}")
        }
        _ => return None,
    };
    let parser_dialect = dialect.to_sqlparser_dialect();
    let Some(Statement::Query(mut query)) = Parser::parse_sql(parser_dialect.as_ref(), &source).ok()?.pop() else {
        return None;
    };
    let _ = ast::visit_expressions_mut(&mut query, |expression| {
        if let Expr::Value(value) = expression
            && let Value::Placeholder(placeholder) = &value.value
            && placeholder
                .strip_prefix('$')
                .is_some_and(|position| !position.is_empty() && position.bytes().all(|byte| byte.is_ascii_digit()))
        {
            *expression = Expr::Identifier(Ident::with_quote('"', placeholder.clone()));
        }
        ControlFlow::<()>::Continue(())
    });
    Some(query)
}

/// Whether `query` returns exactly one row: a `SELECT` with no `FROM`,
/// filter, grouping, limit or set-returning function in its select list.
fn returns_one_row(query: &ast::Query, catalog: &Catalog) -> bool {
    let SetExpr::Select(select) = query.body.as_ref() else {
        return false;
    };
    let ungrouped = match &select.group_by {
        GroupByExpr::Expressions(expressions, modifiers) => expressions.is_empty() && modifiers.is_empty(),
        GroupByExpr::All(_) => false,
    };
    if query.with.is_some()
        || query.limit_clause.is_some()
        || query.fetch.is_some()
        || !select.from.is_empty()
        || select.selection.is_some()
        || select.having.is_some()
        || select.qualify.is_some()
        || !ungrouped
    {
        return false;
    }
    let set_returning = ast::visit_expressions(&select.projection, |expression| {
        if let Expr::Function(function) = expression {
            let name = function.name.to_string().to_lowercase();
            let bare = name.rsplit('.').next().unwrap_or(&name);
            let catalog_set = catalog.get_functions(&name).is_some_and(|overloads| {
                overloads.iter().any(|function| {
                    matches!(
                        function.return_type,
                        FunctionReturn::SetOf { .. } | FunctionReturn::Table { .. }
                    )
                })
            });
            if catalog_set || BUILTIN_SET_RETURNING_FUNCTIONS.contains(&bare) {
                return ControlFlow::Break(());
            }
        }
        ControlFlow::Continue(())
    });
    set_returning.is_continue()
}

impl Catalog {
    /// Refine each SQL function's result nullability from its body, and the
    /// columns of views that call refined functions.
    ///
    /// Results start nullable. Each pass analyzes every body against what
    /// earlier passes proved and clears the `nullable` flags it proves, then
    /// analyzes the views again, until a pass proves nothing new. A pass only
    /// clears flags, so passes end, and an analysis assumes only proven facts,
    /// so a function calling itself or another that calls it back still gets
    /// a sound result.
    pub(super) fn refine_function_results(&mut self) {
        let mut bodies = self
            .functions
            .iter()
            .flat_map(|(key, overloads)| {
                overloads
                    .iter()
                    .enumerate()
                    .filter(|(_, function)| function.body.is_some())
                    .map(|(index, _)| (key.clone(), index))
            })
            .collect::<Vec<_>>();
        bodies.sort();
        loop {
            let mut changed = false;
            for (key, index) in &bodies {
                let Some(proved) = self.body_nullability(key, *index) else {
                    continue;
                };
                let function = &mut self.functions.get_mut(key).expect("function was cataloged")[*index];
                changed |= clear_proved_nullable(&mut function.return_type, &proved);
            }
            if !changed {
                break;
            }
            // Views were analyzed as they were created, before any function
            // was refined; the next pass sees what they now prove.
            self.refine_view_columns();
        }
    }

    /// The nullability of each of the function's result values as its body
    /// analyzes, or `None` when the body does not analyze or does not match
    /// the declared result.
    fn body_nullability(&self, key: &str, index: usize) -> Option<Vec<bool>> {
        let function = &self.functions.get(key)?[index];
        let body = function.body.as_deref()?;
        let mut arguments = Vec::new();
        for (position, argument) in function
            .arguments
            .iter()
            .filter(|argument| argument.mode != FunctionArgumentMode::Out)
            .enumerate()
        {
            arguments.push(BodyArgument {
                name: format!("${}", position + 1),
                sql_type: &argument.sql_type,
            });
            if let Some(name) = &argument.name {
                arguments.push(BodyArgument {
                    name: name.clone(),
                    sql_type: &argument.sql_type,
                });
            }
        }
        let expected = match &function.return_type {
            FunctionReturn::Table { columns } => columns.len(),
            FunctionReturn::Scalar { sql_type, .. } | FunctionReturn::SetOf { sql_type, .. } => {
                // A composite or record result spreads over several columns,
                // whose nullability the function's result does not carry.
                if sql_type.eq_ignore_ascii_case("record") || self.get_composite(sql_type).is_some() {
                    return None;
                }
                // A scalar function returns null when its query returns no rows.
                if matches!(function.return_type, FunctionReturn::Scalar { .. }) && !returns_one_row(body, self) {
                    return None;
                }
                1
            }
        };
        let function_name = key.rsplit('.').next().unwrap_or(key);
        let columns = analyze_function_body(self, body, function_name, &arguments, !function.strict).ok()?;
        (columns.len() == expected).then(|| columns.iter().map(|column| column.nullable).collect())
    }
}

/// Clear each `nullable` flag `proved` clears, reporting whether any changed.
fn clear_proved_nullable(return_type: &mut FunctionReturn, proved: &[bool]) -> bool {
    let mut changed = false;
    let mut clear = |nullable: &mut bool, proved: bool| {
        if *nullable && !proved {
            *nullable = false;
            changed = true;
        }
    };
    match return_type {
        FunctionReturn::Scalar { nullable, .. } | FunctionReturn::SetOf { nullable, .. } => {
            clear(nullable, proved[0]);
        }
        FunctionReturn::Table { columns } => {
            for (column, proved) in columns.iter_mut().zip(proved) {
                clear(&mut column.nullable, *proved);
            }
        }
    }
    changed
}

#[cfg(test)]
mod tests {
    use crate::catalog::{Catalog, FunctionReturn};

    const PAYMENTS: &str = "CREATE TABLE payments (id integer NOT NULL, email text, amount integer NOT NULL);";

    fn table_nullability(catalog: &Catalog, name: &str) -> Vec<(String, bool)> {
        match &catalog.get_functions(name).expect("function should be cataloged")[0].return_type {
            FunctionReturn::Table { columns } => columns
                .iter()
                .map(|column| (column.name.clone(), column.nullable))
                .collect(),
            other => panic!("expected a table function, got {other:?}"),
        }
    }

    fn value_nullable(catalog: &Catalog, name: &str) -> bool {
        match &catalog.get_functions(name).expect("function should be cataloged")[0].return_type {
            FunctionReturn::Scalar { nullable, .. } | FunctionReturn::SetOf { nullable, .. } => *nullable,
            other => panic!("expected a scalar or set function, got {other:?}"),
        }
    }

    #[test]
    fn should_derive_returns_table_nullability_from_the_body() {
        let catalog = Catalog::from_ddl(&[
            PAYMENTS,
            "CREATE FUNCTION facts(text, reveal boolean) RETURNS TABLE (id integer, email text, shown text, total integer)
                LANGUAGE sql STABLE AS $$
                SELECT p.id, p.email, CASE WHEN reveal THEN coalesce(p.email, '') ELSE '' END, p.amount + 1
                FROM payments p WHERE $1::text IS NULL OR p.email = $1
                $$;",
        ])
        .expect("schema should parse");
        assert_eq!(
            table_nullability(&catalog, "facts"),
            vec![
                ("id".to_string(), false),
                ("email".to_string(), true),
                ("shown".to_string(), false),
                ("total".to_string(), false),
            ]
        );
    }

    #[test]
    fn should_derive_setof_nullability_from_a_quoted_body() {
        let catalog = Catalog::from_ddl(&[
            PAYMENTS,
            "CREATE FUNCTION payment_ids() RETURNS SETOF integer LANGUAGE sql AS 'SELECT id FROM payments';",
            "CREATE FUNCTION payment_emails() RETURNS SETOF text LANGUAGE sql AS 'SELECT email FROM payments';",
        ])
        .expect("schema should parse");
        assert!(!value_nullable(&catalog, "payment_ids"));
        assert!(value_nullable(&catalog, "payment_emails"));
    }

    #[test]
    fn should_read_relations_defined_after_the_function() {
        let catalog = Catalog::from_ddl(&[
            "CREATE FUNCTION visible() RETURNS TABLE (id integer, email text) LANGUAGE sql AS $$
                SELECT id, email FROM visible_payments
                $$;",
            PAYMENTS,
            "CREATE VIEW visible_payments AS SELECT id, coalesce(email, '') AS email FROM payments;",
        ])
        .expect("schema should parse");
        assert_eq!(
            table_nullability(&catalog, "visible"),
            vec![("id".to_string(), false), ("email".to_string(), false)]
        );
    }

    #[test]
    fn should_refine_views_that_call_refined_functions() {
        let catalog = Catalog::from_ddl(&[
            "CREATE FUNCTION codes() RETURNS SETOF text LANGUAGE sql AS 'SELECT id_code FROM payment_codes';",
            "CREATE FUNCTION code(name text) RETURNS text LANGUAGE sql IMMUTABLE STRICT RETURN upper(name);",
            PAYMENTS,
            "CREATE VIEW payment_codes AS SELECT code(email) AS code, code(id::text) AS id_code FROM payments;",
        ])
        .expect("schema should parse");
        let view = catalog.get_table("payment_codes").expect("view should be cataloged");
        assert!(view.columns[0].nullable, "a null email makes the strict call null");
        assert!(!view.columns[1].nullable);
        assert!(!value_nullable(&catalog, "codes"), "a body reads the refined view");
    }

    #[test]
    fn should_keep_results_nullable_when_the_body_does_not_analyze() {
        let catalog = Catalog::from_ddl(&[
            PAYMENTS,
            "CREATE FUNCTION missing() RETURNS TABLE (id integer) LANGUAGE sql AS 'SELECT id FROM no_such_table';",
            "CREATE FUNCTION unparsable() RETURNS SETOF integer LANGUAGE sql AS 'SELEC id FROM payments';",
            "CREATE FUNCTION procedural() RETURNS SETOF integer LANGUAGE plpgsql AS $$
                BEGIN RETURN QUERY SELECT id FROM payments; END
                $$;",
            "CREATE FUNCTION mismatched() RETURNS TABLE (id integer) LANGUAGE sql AS 'SELECT id, amount FROM payments';",
            "CREATE FUNCTION single_row(OUT id integer) LANGUAGE sql AS 'SELECT id FROM payments';",
        ])
        .expect("an unanalyzable body must not fail the schema");
        assert_eq!(table_nullability(&catalog, "missing"), vec![("id".to_string(), true)]);
        assert!(value_nullable(&catalog, "unparsable"));
        assert!(value_nullable(&catalog, "procedural"));
        assert_eq!(
            table_nullability(&catalog, "mismatched"),
            vec![("id".to_string(), true)]
        );
        assert_eq!(
            table_nullability(&catalog, "single_row"),
            vec![("id".to_string(), true)],
            "output parameters without SETOF are null when the body returns no rows"
        );
    }

    #[test]
    fn should_prove_a_scalar_only_when_its_query_returns_one_row() {
        let catalog = Catalog::from_ddl(&[
            PAYMENTS,
            "CREATE FUNCTION standard(code text) RETURNS text LANGUAGE sql RETURN coalesce(code, 'none');",
            "CREATE FUNCTION selected(code text) RETURNS text LANGUAGE sql AS 'SELECT coalesce($1, ''none'')';",
            "CREATE FUNCTION first_id() RETURNS integer LANGUAGE sql AS 'SELECT id FROM payments';",
            "CREATE FUNCTION first_series() RETURNS integer LANGUAGE sql AS 'SELECT generate_series(1, 0)';",
        ])
        .expect("schema should parse");
        assert!(!value_nullable(&catalog, "standard"));
        assert!(!value_nullable(&catalog, "selected"));
        assert!(value_nullable(&catalog, "first_id"), "no rows make the result null");
        assert!(value_nullable(&catalog, "first_series"), "no rows make the result null");
    }

    #[test]
    fn should_resolve_named_arguments_after_the_body_columns() {
        let catalog = Catalog::from_ddl(&[
            PAYMENTS,
            "CREATE FUNCTION by_id(id integer, email text) RETURNS TABLE (own text, given text, qualified integer)
                LANGUAGE sql STRICT AS 'SELECT email, coalesce(by_id.email, ''''), by_id.id FROM payments WHERE payments.id = by_id.id';",
        ])
        .expect("schema should parse");
        assert_eq!(
            table_nullability(&catalog, "by_id"),
            vec![
                ("own".to_string(), true),
                ("given".to_string(), false),
                ("qualified".to_string(), false),
            ]
        );
    }

    #[test]
    fn should_see_non_null_arguments_only_in_strict_bodies() {
        let catalog = Catalog::from_ddl(&[
            "CREATE FUNCTION strict_echo(code text) RETURNS text LANGUAGE sql IMMUTABLE STRICT RETURN code;",
            "CREATE FUNCTION lenient_echo(code text) RETURNS text LANGUAGE sql IMMUTABLE RETURN code;",
        ])
        .expect("schema should parse");
        assert!(!value_nullable(&catalog, "strict_echo"));
        assert!(value_nullable(&catalog, "lenient_echo"));
    }

    #[test]
    fn should_settle_functions_that_call_each_other() {
        let catalog = Catalog::from_ddl(&[
            "CREATE FUNCTION outer_value(n integer) RETURNS integer LANGUAGE sql STRICT RETURN inner_value(n);",
            "CREATE FUNCTION inner_value(n integer) RETURNS integer LANGUAGE sql STRICT
                RETURN coalesce(outer_value(n), 0);",
            "CREATE FUNCTION forever(n integer) RETURNS integer LANGUAGE sql STRICT RETURN forever(n + 1);",
        ])
        .expect("recursive functions should not fail the schema");
        assert!(!value_nullable(&catalog, "inner_value"));
        assert!(!value_nullable(&catalog, "outer_value"));
        assert!(
            value_nullable(&catalog, "forever"),
            "a body proving nothing stays nullable"
        );
    }
}
