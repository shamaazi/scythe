use sqlparser::ast::{self, JoinOperator, TableFactor};

use crate::catalog::FunctionReturn;
use crate::errors::SqlkitError;

use super::builtins::{builtin_from_columns, builtin_relation};
use super::expressions::{CallOutcome, CallResolution, catalog_function_return_neutral};
use super::helpers::{
    UNRESOLVED_EXPR_MARKER, function_arg_exprs, ident_name, object_column_name, object_name_to_string, relation_alias,
    unresolved_type_error, widen_neutral_type,
};
use super::type_conversion::{datatype_to_neutral, sql_type_to_neutral};
use super::types::*;

impl<'a> Analyzer<'a> {
    /// `generate_series` is polymorphic: `generate_series(int, int)` yields
    /// `int`/`bigint`, `generate_series(numeric, numeric, numeric)` yields
    /// `numeric`, and `generate_series(timestamptz, timestamptz, interval)`
    /// yields `timestamptz` -- the result column always shares the widened
    /// type of the `start`/`stop` arguments, not a hardcoded `int32` (#123).
    ///
    /// Only the first two arguments (`start`, `stop`) decide the type; the
    /// optional third `step` argument is a different type on the temporal
    /// overload (`interval`, not `timestamptz`) so it is deliberately not
    /// folded in here. Falls back to `int32` -- the previous universal
    /// answer -- when the arguments can't be resolved (no args, or every
    /// arg types as `unknown`).
    fn generate_series_result_type(&mut self, args: &[ast::FunctionArg], scope: &Scope) -> String {
        let exprs = function_arg_exprs(args);
        let mut result_type = "unknown".to_string();
        for arg in exprs.iter().take(2) {
            let ti = self.infer_expr_type(arg, scope);
            result_type = widen_neutral_type(&result_type, &ti.neutral_type);
        }
        if result_type == "unknown" {
            "int32".to_string()
        } else {
            result_type
        }
    }

    pub(super) fn build_scope_from_from(&mut self, from: &[ast::TableWithJoins]) -> Result<Scope, SqlkitError> {
        let mut scope = Scope { sources: Vec::new() };

        for twj in from {
            self.add_table_factor_to_scope(&twj.relation, &mut scope, false)?;

            for join in &twj.joins {
                let nullable_from_join = match &join.join_operator {
                    JoinOperator::Left(_)
                    | JoinOperator::LeftOuter(_)
                    | JoinOperator::LeftSemi(_)
                    | JoinOperator::LeftAnti(_) => true,
                    JoinOperator::Right(_) | JoinOperator::RightOuter(_) => {
                        for source in &mut scope.sources {
                            source.nullable_from_join = true;
                        }
                        false
                    }
                    JoinOperator::FullOuter(_) => {
                        for source in &mut scope.sources {
                            source.nullable_from_join = true;
                        }
                        true
                    }
                    JoinOperator::CrossJoin(_)
                    | JoinOperator::Inner(_)
                    | JoinOperator::CrossApply
                    | JoinOperator::OuterApply => false,
                    _ => false,
                };

                self.add_table_factor_to_scope(&join.relation, &mut scope, nullable_from_join)?;
                self.collect_join_condition_params(&join.join_operator, &scope);
            }
        }

        Ok(scope)
    }

    /// Bind the parameters of a join's `ON` condition, which sees every FROM
    /// item joined so far.
    fn collect_join_condition_params(&mut self, operator: &JoinOperator, scope: &Scope) {
        let constraint = match operator {
            JoinOperator::Join(constraint)
            | JoinOperator::Inner(constraint)
            | JoinOperator::Left(constraint)
            | JoinOperator::LeftOuter(constraint)
            | JoinOperator::Right(constraint)
            | JoinOperator::RightOuter(constraint)
            | JoinOperator::FullOuter(constraint)
            | JoinOperator::CrossJoin(constraint)
            | JoinOperator::Semi(constraint)
            | JoinOperator::LeftSemi(constraint)
            | JoinOperator::RightSemi(constraint)
            | JoinOperator::Anti(constraint)
            | JoinOperator::LeftAnti(constraint)
            | JoinOperator::RightAnti(constraint)
            | JoinOperator::StraightJoin(constraint)
            | JoinOperator::AsOf { constraint, .. } => constraint,
            _ => return,
        };
        if let ast::JoinConstraint::On(condition) = constraint {
            self.collect_params_from_where(condition, scope);
        }
    }

    fn add_table_factor_to_scope(
        &mut self,
        tf: &TableFactor,
        scope: &mut Scope,
        nullable_from_join: bool,
    ) -> Result<(), SqlkitError> {
        match tf {
            TableFactor::Table {
                name,
                alias,
                args,
                with_ordinality,
                ..
            } => {
                // A CTE is named as the query wrote it; a catalog relation or
                // function by the catalog's lower-case key.
                let cte_cols = self.ctes.get(&object_column_name(name)).cloned();
                let table_name = match cte_cols {
                    Some(_) => object_column_name(name),
                    None => object_name_to_string(name).to_lowercase(),
                };
                let alias_name = alias
                    .as_ref()
                    .map(|a| ident_name(&a.name))
                    .unwrap_or_else(|| relation_alias(name));

                let scope_cols = if let Some(cte_cols) = cte_cols {
                    cte_cols
                } else if let Some(table) = self.catalog.get_table(&table_name) {
                    table
                        .columns
                        .iter()
                        .map(|c| {
                            let raw_sql_type = self
                                .catalog
                                .column_raw_sql_type(&table_name, &c.name)
                                .unwrap_or(&c.sql_type);
                            ScopeColumn::from_catalog(
                                c.name.clone(),
                                raw_sql_type,
                                sql_type_to_neutral(&c.sql_type, self.catalog).into_owned(),
                                c.nullable,
                            )
                            .with_origin(&table_name)
                        })
                        .collect()
                } else if args.is_none()
                    && let Some(columns) = builtin_relation(&table_name)
                {
                    columns
                        .iter()
                        .map(|&(name, sql_type)| {
                            // `oid` and `xid` have no neutral type: such a column is
                            // reported when selected rather than mistyped.
                            let neutral = match sql_type {
                                "oid" | "xid" => UNRESOLVED_EXPR_MARKER.to_string(),
                                _ => sql_type_to_neutral(sql_type, self.catalog).into_owned(),
                            };
                            ScopeColumn::from_catalog(name, sql_type, neutral, true)
                        })
                        .collect()
                } else if let Some(function_args) = args
                    && self.catalog.get_functions(&table_name).is_none()
                    && let Some(columns) = self.column_definition_list(alias.as_ref())
                {
                    self.record_function_columns(&table_name, &function_args.args, scope, columns)
                } else if let Some(function_args) = args
                    && self.catalog.get_functions(&table_name).is_some()
                {
                    self.catalog_function_columns(&table_name, &function_args.args, scope, alias.as_ref())?
                } else if let Some(fixed_columns) = builtin_from_columns(&table_name) {
                    let arg_list: &[ast::FunctionArg] = args.as_ref().map(|a| a.args.as_slice()).unwrap_or(&[]);
                    self.collect_set_function_arg_params(&table_name, arg_list, scope);
                    // PostgreSQL table-valued function call syntax (`FROM
                    // generate_series(1, 10)`, no `LATERAL`) parses as
                    // `TableFactor::Table` with `args: Some(...)`, not
                    // `TableFactor::Function` -- this is the arm that
                    // actually runs for ordinary `generate_series` calls (#123).
                    let columns = if table_name == "generate_series" {
                        let result_type = self.generate_series_result_type(arg_list, &*scope);
                        vec![ScopeColumn::new("generate_series", result_type, false)]
                    } else {
                        builtin_scope_columns(fixed_columns)
                    };
                    with_function_alias_columns(columns, alias.as_ref(), *with_ordinality)
                } else {
                    return Err(SqlkitError::new(
                        crate::errors::ErrorCode::UnknownTable,
                        format!("relation \"{}\" does not exist", table_name),
                    ));
                };

                scope.sources.push(ScopeSource {
                    alias: alias_name,
                    table_name,
                    columns: scope_cols,
                    nullable_from_join,
                });
            }
            TableFactor::Derived {
                lateral,
                subquery,
                alias,
                ..
            } => {
                // Every derived table sees the enclosing query levels; only a
                // `LATERAL` one also sees the FROM items before it.
                let preceding = lateral.then(|| scope.sources.clone());
                let sub_cols = self.analyze_nested_query(subquery, preceding)?;

                let alias_name = alias
                    .as_ref()
                    .map(|a| ident_name(&a.name))
                    .unwrap_or_else(|| "subquery".to_string());

                let scope_cols: Vec<ScopeColumn> = sub_cols.iter().map(ScopeColumn::from_analyzed_column).collect();

                scope.sources.push(ScopeSource {
                    alias: alias_name.clone(),
                    table_name: alias_name,
                    columns: scope_cols,
                    nullable_from_join,
                });
            }
            TableFactor::NestedJoin {
                table_with_joins,
                alias: _,
            } => {
                self.add_table_factor_to_scope(&table_with_joins.relation, scope, nullable_from_join)?;
                for join in &table_with_joins.joins {
                    let join_nullable = match &join.join_operator {
                        JoinOperator::Left(_) | JoinOperator::LeftOuter(_) => true,
                        JoinOperator::Right(_) | JoinOperator::RightOuter(_) => {
                            for source in scope.sources.iter_mut() {
                                source.nullable_from_join = true;
                            }
                            false
                        }
                        JoinOperator::FullOuter(_) => {
                            for source in scope.sources.iter_mut() {
                                source.nullable_from_join = true;
                            }
                            true
                        }
                        _ => nullable_from_join,
                    };
                    self.add_table_factor_to_scope(&join.relation, scope, join_nullable)?;
                    self.collect_join_condition_params(&join.join_operator, scope);
                }
            }
            TableFactor::UNNEST {
                alias,
                array_exprs,
                with_ordinality,
                ..
            } => {
                let alias_name = alias
                    .as_ref()
                    .map(|a| ident_name(&a.name))
                    .unwrap_or_else(|| "unnest".to_string());
                let columns = self.unnest_columns(array_exprs, alias.as_ref(), scope);
                scope.sources.push(ScopeSource {
                    alias: alias_name.clone(),
                    table_name: alias_name,
                    columns: with_function_alias_columns(columns, alias.as_ref(), *with_ordinality),
                    nullable_from_join,
                });
            }
            TableFactor::TableFunction { alias, .. } => {
                let alias_name = alias
                    .as_ref()
                    .map(|a| ident_name(&a.name))
                    .unwrap_or_else(|| "func".to_string());
                scope.sources.push(ScopeSource {
                    alias: alias_name.clone(),
                    table_name: alias_name,
                    columns: Vec::new(),
                    nullable_from_join,
                });
            }
            TableFactor::Function { alias, name, args, .. } => {
                let alias_name = alias
                    .as_ref()
                    .map(|a| ident_name(&a.name))
                    .unwrap_or_else(|| relation_alias(name));

                let func_name = object_name_to_string(name).to_lowercase();
                let is_catalog_function = self.catalog.get_functions(&func_name).is_some();
                let definition = if is_catalog_function {
                    None
                } else {
                    self.column_definition_list(alias.as_ref())
                };
                let has_definition = definition.is_some();
                let cols = if let Some(columns) = definition {
                    self.record_function_columns(&func_name, args, scope, columns)
                } else {
                    match func_name.as_str() {
                        "generate_series" => {
                            let result_type = self.generate_series_result_type(args, &*scope);
                            vec![ScopeColumn::new("generate_series", result_type, false)]
                        }
                        // The element type isn't inspected here (unlike the
                        // select-list `unnest(...)` arm in `expressions.rs`, which
                        // does), so there is no type to give this column -- mark
                        // it rather than leave a bare "unknown" that could reach
                        // codegen unexplained if it's ever selected (#223).
                        "unnest" => vec![ScopeColumn::new("unnest", UNRESOLVED_EXPR_MARKER, true)],
                        _ => match builtin_from_columns(&func_name).filter(|columns| !columns.is_empty()) {
                            Some(columns) => builtin_scope_columns(columns),
                            None => self.catalog_function_columns(&func_name, args, scope, alias.as_ref())?,
                        },
                    }
                };

                let cols = if let Some(a) = alias
                    && !is_catalog_function
                    && !has_definition
                {
                    if !a.columns.is_empty() {
                        // An explicit column-alias list on a table function
                        // sqlkit has no per-column type mapping for (or a
                        // known function whose columns were just redeclared --
                        // a separate, pre-existing limitation this fix does
                        // not attempt to lift). Mark each column rather than
                        // leave a bare "unknown" that could reach codegen
                        // unexplained if selected (#223).
                        a.columns
                            .iter()
                            .map(|c| ScopeColumn::new(ident_name(&c.name), UNRESOLVED_EXPR_MARKER, true))
                            .collect()
                    } else {
                        cols
                    }
                } else {
                    cols
                };

                scope.sources.push(ScopeSource {
                    alias: alias_name.clone(),
                    table_name: alias_name,
                    columns: cols,
                    nullable_from_join,
                });
            }
            _ => {}
        }

        Ok(())
    }

    pub(super) fn build_scope_for_table(&self, table_name: &str) -> Result<Scope, SqlkitError> {
        let mut scope = Scope { sources: Vec::new() };

        if let Some(cte_cols) = self.ctes.get(table_name) {
            scope.sources.push(ScopeSource {
                alias: table_name.to_string(),
                table_name: table_name.to_string(),
                columns: cte_cols.clone(),
                nullable_from_join: false,
            });
            return Ok(scope);
        }

        if let Some(table) = self.catalog.get_table(table_name) {
            let scope_cols: Vec<ScopeColumn> = table
                .columns
                .iter()
                .map(|c| {
                    let raw_sql_type = self
                        .catalog
                        .column_raw_sql_type(table_name, &c.name)
                        .unwrap_or(&c.sql_type);
                    ScopeColumn::from_catalog(
                        c.name.clone(),
                        raw_sql_type,
                        sql_type_to_neutral(&c.sql_type, self.catalog).into_owned(),
                        c.nullable,
                    )
                    .with_origin(table_name)
                })
                .collect();
            let bare = table_name
                .rsplit_once('.')
                .map(|(_, n)| n.to_string())
                .unwrap_or_else(|| table_name.to_string());
            scope.sources.push(ScopeSource {
                alias: bare,
                table_name: table_name.to_string(),
                columns: scope_cols,
                nullable_from_join: false,
            });
        }

        Ok(scope)
    }

    pub(super) fn get_column_type(&self, table_name: &str, col_name: &str) -> Option<String> {
        if let Some(table) = self.catalog.get_table(table_name)
            && let Some(col) = table.columns.iter().find(|c| c.name == col_name)
        {
            return Some(sql_type_to_neutral(&col.sql_type, self.catalog).into_owned());
        }
        None
    }

    pub(super) fn is_column_nullable(&self, table_name: &str, col_name: &str) -> bool {
        if let Some(table) = self.catalog.get_table(table_name)
            && let Some(col) = table.columns.iter().find(|c| c.name == col_name)
        {
            return col.nullable;
        }
        false
    }

    /// Bind the parameters a FROM-clause call to a built-in set-returning
    /// function takes. The JSON family's first argument is the document.
    fn collect_set_function_arg_params(&mut self, function_name: &str, args: &[ast::FunctionArg], scope: &Scope) {
        for (index, argument) in function_arg_exprs(args).iter().enumerate() {
            if index == 0 && function_name.starts_with("json") {
                self.collect_param_from_expr(argument, "json", "json");
            }
            let _ = self.infer_expr_type(argument, scope);
        }
    }

    /// The columns of `FROM unnest(a, b, ...)`: one per array, typed by its
    /// elements, which may be NULL. A single array's column takes the table
    /// alias as its name, as PostgreSQL names a scalar function's column.
    fn unnest_columns(
        &mut self,
        array_exprs: &[ast::Expr],
        alias: Option<&ast::TableAlias>,
        scope: &Scope,
    ) -> Vec<ScopeColumn> {
        let single_name = match (array_exprs, alias) {
            ([_], Some(alias)) => Some(ident_name(&alias.name)),
            _ => None,
        };
        array_exprs
            .iter()
            .map(|array| {
                let element_type = super::helpers::array_element_type(&self.infer_expr_type(array, scope).neutral_type)
                    .map_or_else(|| UNRESOLVED_EXPR_MARKER.to_string(), str::to_string);
                let name = single_name.clone().unwrap_or_else(|| "unnest".to_string());
                ScopeColumn::new(name, element_type, true)
            })
            .collect()
    }

    /// The columns a column definition list declares (`AS x(id text, amount
    /// integer)`), which is how PostgreSQL types a function returning
    /// `record`, such as `jsonb_to_recordset`. `None` unless the alias gives
    /// every column a type. The columns are nullable: a record need not hold
    /// a value for each.
    fn column_definition_list(&self, alias: Option<&ast::TableAlias>) -> Option<Vec<ScopeColumn>> {
        let columns = &alias?.columns;
        if columns.is_empty() {
            return None;
        }
        columns
            .iter()
            .map(|column| {
                let data_type = column.data_type.as_ref()?;
                Some(ScopeColumn::from_catalog(
                    ident_name(&column.name),
                    data_type.to_string().to_lowercase(),
                    datatype_to_neutral(data_type, self.catalog),
                    true,
                ))
            })
            .collect()
    }

    /// The columns of a function outside the catalog called with a column
    /// definition list. Its arguments are still analyzed, so their
    /// parameters register; the `json[b]_to_record[set]` family takes JSON.
    fn record_function_columns(
        &mut self,
        function_name: &str,
        args: &[ast::FunctionArg],
        scope: &Scope,
        columns: Vec<ScopeColumn>,
    ) -> Vec<ScopeColumn> {
        let takes_json = matches!(
            function_name,
            "json_to_record" | "jsonb_to_record" | "json_to_recordset" | "jsonb_to_recordset"
        );
        for (index, argument) in function_arg_exprs(args).iter().enumerate() {
            if index == 0 && takes_json {
                self.collect_param_from_expr(argument, "json", "json");
            }
            let _ = self.infer_expr_type(argument, scope);
        }
        columns
    }

    fn catalog_function_columns(
        &mut self,
        function_name: &str,
        args: &[ast::FunctionArg],
        scope: &Scope,
        alias: Option<&ast::TableAlias>,
    ) -> Result<Vec<ScopeColumn>, SqlkitError> {
        let Some(overloads) = self.catalog.get_functions(function_name) else {
            return Err(SqlkitError::unknown_function(function_name));
        };
        let Some(CallResolution { inferred, outcome }) = self.resolve_call(overloads, args, scope) else {
            return Err(SqlkitError::type_mismatch(format!(
                "function \"{function_name}\" has unsupported wildcard arguments"
            )));
        };
        let best = match outcome {
            CallOutcome::Resolved(best) => best,
            CallOutcome::NoMatch => {
                return Err(SqlkitError::type_mismatch(format!(
                    "no overload of function \"{function_name}\" accepts the supplied argument types"
                )));
            }
            CallOutcome::Ambiguous => return Err(SqlkitError::ambiguous_function(function_name)),
        };

        let bare_name = function_name.rsplit('.').next().unwrap_or(function_name);
        let mut columns = match &best.function.return_type {
            FunctionReturn::Scalar { sql_type, nullable } | FunctionReturn::SetOf { sql_type, nullable } => {
                // A STRICT set-returning function returns no rows for a null
                // input, but a scalar one still returns its null row.
                let scalar = matches!(best.function.return_type, FunctionReturn::Scalar { .. });
                let nullable = *nullable || (scalar && best.strict_null_input(&inferred));
                if let Some(composite) = self.catalog.get_composite(sql_type) {
                    composite
                        .fields
                        .iter()
                        .map(|field| {
                            ScopeColumn::from_catalog(
                                field.name.clone(),
                                field.sql_type.clone(),
                                sql_type_to_neutral(&field.sql_type, self.catalog).into_owned(),
                                field.nullable,
                            )
                        })
                        .collect()
                } else if sql_type.eq_ignore_ascii_case("record")
                    && let Some(columns) = self.column_definition_list(alias)
                {
                    columns
                } else {
                    let neutral_type = catalog_function_return_neutral(function_name, sql_type, self.catalog);
                    if let Some(error) = unresolved_type_error(&neutral_type, "function result", bare_name) {
                        return Err(error);
                    }
                    vec![ScopeColumn::from_catalog(bare_name, sql_type, neutral_type, nullable)]
                }
            }
            FunctionReturn::Table { columns } => columns
                .iter()
                .map(|column| {
                    ScopeColumn::from_catalog(
                        column.name.clone(),
                        column.sql_type.clone(),
                        sql_type_to_neutral(&column.sql_type, self.catalog).into_owned(),
                        column.nullable,
                    )
                })
                .collect(),
        };
        if let Some(alias) = alias
            && !alias.columns.is_empty()
        {
            if alias.columns.len() != columns.len() {
                return Err(SqlkitError::column_count_mismatch(alias.columns.len(), columns.len()));
            }
            for (column, alias) in columns.iter_mut().zip(&alias.columns) {
                column.name = ident_name(&alias.name);
            }
        }
        Ok(columns)
    }
}

/// The scope columns of a built-in FROM item's fixed columns.
fn builtin_scope_columns(columns: &[(&str, &str, bool)]) -> Vec<ScopeColumn> {
    columns
        .iter()
        .map(|&(name, neutral_type, nullable)| ScopeColumn::new(name, neutral_type, nullable))
        .collect()
}

/// A set-returning function's columns as its FROM item exposes them: `WITH
/// ORDINALITY` appends a non-null `bigint` counter, and a column alias list
/// (`AS e(value, n)`) renames the columns in order, leaving any it omits.
fn with_function_alias_columns(
    mut columns: Vec<ScopeColumn>,
    alias: Option<&ast::TableAlias>,
    with_ordinality: bool,
) -> Vec<ScopeColumn> {
    if with_ordinality {
        columns.push(ScopeColumn::new("ordinality", "int64", false));
    }
    if let Some(alias) = alias {
        for (column, name) in columns.iter_mut().zip(&alias.columns) {
            column.name = ident_name(&name.name);
        }
    }
    columns
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::Catalog;
    use sqlparser::ast::Statement;
    use sqlparser::dialect::PostgreSqlDialect;
    use sqlparser::parser::Parser;

    fn make_catalog(ddl: &[&str]) -> Catalog {
        Catalog::from_ddl(ddl).unwrap()
    }

    fn make_analyzer(catalog: &Catalog) -> Analyzer<'_> {
        Analyzer::new(catalog)
    }

    fn parse_from(sql: &str) -> Vec<ast::TableWithJoins> {
        let dialect = PostgreSqlDialect {};
        let stmts = Parser::parse_sql(&dialect, sql).unwrap();
        let Statement::Query(q) = &stmts[0] else {
            unreachable!("test SQL must be a SELECT query");
        };
        let ast::SetExpr::Select(sel) = q.body.as_ref() else {
            unreachable!("test SQL must be a simple SELECT");
        };
        sel.from.clone()
    }

    #[test]
    fn test_build_scope_for_table_columns_and_types() {
        let catalog = make_catalog(&["CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT);"]);
        let analyzer = make_analyzer(&catalog);
        let scope = analyzer.build_scope_for_table("users").unwrap();

        assert_eq!(scope.sources.len(), 1);
        let src = &scope.sources[0];
        assert_eq!(src.alias, "users");
        assert_eq!(src.table_name, "users");
        assert!(!src.nullable_from_join);

        assert_eq!(src.columns.len(), 3);
        assert_eq!(src.columns[0].name, "id");
        assert!(!src.columns[0].base_nullable);
        assert_eq!(src.columns[1].name, "name");
        assert!(!src.columns[1].base_nullable);
        assert_eq!(src.columns[2].name, "email");
        assert!(src.columns[2].base_nullable);
    }

    #[test]
    fn test_build_scope_for_table_unknown_returns_empty() {
        let catalog = make_catalog(&["CREATE TABLE users (id INT);"]);
        let analyzer = make_analyzer(&catalog);
        let scope = analyzer.build_scope_for_table("nonexistent").unwrap();
        assert_eq!(scope.sources.len(), 0);
    }

    #[test]
    fn test_build_scope_from_from_single_table() {
        let catalog = make_catalog(&["CREATE TABLE users (id INT NOT NULL, name TEXT NOT NULL);"]);
        let mut analyzer = make_analyzer(&catalog);
        let from = parse_from("SELECT * FROM users");
        let scope = analyzer.build_scope_from_from(&from).unwrap();

        assert_eq!(scope.sources.len(), 1);
        let src = &scope.sources[0];
        assert_eq!(src.alias, "users");
        assert_eq!(src.columns.len(), 2);
        assert_eq!(src.columns[0].name, "id");
        assert_eq!(src.columns[1].name, "name");
        assert!(!src.nullable_from_join);
    }

    #[test]
    fn test_build_scope_from_from_with_alias() {
        let catalog = make_catalog(&["CREATE TABLE users (id INT NOT NULL, name TEXT NOT NULL);"]);
        let mut analyzer = make_analyzer(&catalog);
        let from = parse_from("SELECT * FROM users u");
        let scope = analyzer.build_scope_from_from(&from).unwrap();

        assert_eq!(scope.sources.len(), 1);
        assert_eq!(scope.sources[0].alias, "u");
        assert_eq!(scope.sources[0].table_name, "users");
    }

    #[test]
    fn test_build_scope_from_from_inner_join() {
        let catalog = make_catalog(&[
            "CREATE TABLE users (id INT NOT NULL);",
            "CREATE TABLE orders (id INT NOT NULL, user_id INT NOT NULL);",
        ]);
        let mut analyzer = make_analyzer(&catalog);
        let from = parse_from("SELECT * FROM users INNER JOIN orders ON users.id = orders.user_id");
        let scope = analyzer.build_scope_from_from(&from).unwrap();

        assert_eq!(scope.sources.len(), 2);
        assert!(!scope.sources[0].nullable_from_join);
        assert!(!scope.sources[1].nullable_from_join);
    }

    #[test]
    fn test_build_scope_from_from_left_join() {
        let catalog = make_catalog(&[
            "CREATE TABLE users (id INT NOT NULL);",
            "CREATE TABLE orders (id INT NOT NULL, user_id INT NOT NULL);",
        ]);
        let mut analyzer = make_analyzer(&catalog);
        let from = parse_from("SELECT * FROM users LEFT JOIN orders ON users.id = orders.user_id");
        let scope = analyzer.build_scope_from_from(&from).unwrap();

        assert_eq!(scope.sources.len(), 2);
        assert!(!scope.sources[0].nullable_from_join);
        assert!(scope.sources[1].nullable_from_join);
    }

    #[test]
    fn test_build_scope_from_from_right_join() {
        let catalog = make_catalog(&[
            "CREATE TABLE users (id INT NOT NULL);",
            "CREATE TABLE orders (id INT NOT NULL, user_id INT NOT NULL);",
        ]);
        let mut analyzer = make_analyzer(&catalog);
        let from = parse_from("SELECT * FROM users RIGHT JOIN orders ON users.id = orders.user_id");
        let scope = analyzer.build_scope_from_from(&from).unwrap();

        assert_eq!(scope.sources.len(), 2);
        assert!(scope.sources[0].nullable_from_join);
        assert!(!scope.sources[1].nullable_from_join);
    }

    #[test]
    fn test_build_scope_from_from_full_outer_join() {
        let catalog = make_catalog(&[
            "CREATE TABLE users (id INT NOT NULL);",
            "CREATE TABLE orders (id INT NOT NULL, user_id INT NOT NULL);",
        ]);
        let mut analyzer = make_analyzer(&catalog);
        let from = parse_from("SELECT * FROM users FULL OUTER JOIN orders ON users.id = orders.user_id");
        let scope = analyzer.build_scope_from_from(&from).unwrap();

        assert_eq!(scope.sources.len(), 2);
        assert!(scope.sources[0].nullable_from_join);
        assert!(scope.sources[1].nullable_from_join);
    }

    #[test]
    fn test_add_table_factor_subquery() {
        let catalog = make_catalog(&["CREATE TABLE users (id INT NOT NULL, name TEXT NOT NULL);"]);
        let mut analyzer = make_analyzer(&catalog);
        let from = parse_from("SELECT * FROM (SELECT id, name FROM users) AS sub");
        let scope = analyzer.build_scope_from_from(&from).unwrap();

        assert_eq!(scope.sources.len(), 1);
        assert_eq!(scope.sources[0].alias, "sub");
        assert_eq!(scope.sources[0].columns.len(), 2);
        assert_eq!(scope.sources[0].columns[0].name, "id");
        assert_eq!(scope.sources[0].columns[1].name, "name");
    }

    #[test]
    fn test_derived_table_params_propagate_to_outer_analyzer() {
        let catalog = make_catalog(&["CREATE TABLE posts (id INT NOT NULL, user_id INT NOT NULL);"]);
        let mut analyzer = make_analyzer(&catalog);
        let from = parse_from("SELECT * FROM posts p CROSS JOIN (SELECT $1::text AS bucket) b");
        analyzer.build_scope_from_from(&from).unwrap();
        assert!(
            !analyzer.params.is_empty(),
            "params from derived table subquery must propagate to outer analyzer"
        );
        assert_eq!(
            analyzer.params[0].position, 1,
            "$1 inside derived table must be registered at position 1"
        );
    }

    #[test]
    fn test_cte_reference_in_build_scope_for_table() {
        let catalog = make_catalog(&[]);
        let mut analyzer = make_analyzer(&catalog);

        analyzer.ctes.insert(
            "my_cte".to_string(),
            vec![
                ScopeColumn::new("x", "int32", false),
                ScopeColumn::new("y", "string", true),
            ],
        );

        let scope = analyzer.build_scope_for_table("my_cte").unwrap();
        assert_eq!(scope.sources.len(), 1);
        assert_eq!(scope.sources[0].alias, "my_cte");
        assert_eq!(scope.sources[0].columns.len(), 2);
        assert_eq!(scope.sources[0].columns[0].name, "x");
        assert_eq!(scope.sources[0].columns[1].name, "y");
    }

    #[test]
    fn test_cte_reference_in_from_clause() {
        let catalog = make_catalog(&[]);
        let mut analyzer = make_analyzer(&catalog);

        analyzer
            .ctes
            .insert("my_cte".to_string(), vec![ScopeColumn::new("val", "int32", false)]);

        let from = parse_from("SELECT * FROM my_cte");
        let scope = analyzer.build_scope_from_from(&from).unwrap();
        assert_eq!(scope.sources.len(), 1);
        assert_eq!(scope.sources[0].alias, "my_cte");
        assert_eq!(scope.sources[0].columns[0].name, "val");
    }

    #[test]
    fn test_get_column_type_found() {
        let catalog = make_catalog(&["CREATE TABLE users (id INT NOT NULL, name TEXT);"]);
        let analyzer = make_analyzer(&catalog);

        let ty = analyzer.get_column_type("users", "id");
        assert!(ty.is_some());
        assert_eq!(ty.unwrap(), "int32");

        let ty = analyzer.get_column_type("users", "name");
        assert!(ty.is_some());
        assert_eq!(ty.unwrap(), "string");
    }

    #[test]
    fn test_get_column_type_not_found() {
        let catalog = make_catalog(&["CREATE TABLE users (id INT NOT NULL);"]);
        let analyzer = make_analyzer(&catalog);

        assert!(analyzer.get_column_type("users", "nonexistent").is_none());
        assert!(analyzer.get_column_type("nonexistent", "id").is_none());
    }

    #[test]
    fn test_unknown_table_errors() {
        let catalog = make_catalog(&[]);
        let mut analyzer = make_analyzer(&catalog);
        let from = parse_from("SELECT * FROM nonexistent_table");
        let result = analyzer.build_scope_from_from(&from);
        assert!(result.is_err());
    }

    #[test]
    fn test_known_function_jsonb_array_elements() {
        let catalog = make_catalog(&[]);
        let mut analyzer = make_analyzer(&catalog);
        let from = parse_from("SELECT * FROM jsonb_array_elements('[1,2]')");
        let scope = analyzer.build_scope_from_from(&from).unwrap();
        assert_eq!(scope.sources.len(), 1);
        assert!(scope.sources[0].columns.iter().any(|c| c.name == "value"));
    }
}
