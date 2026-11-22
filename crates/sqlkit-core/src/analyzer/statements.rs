use sqlparser::ast::{self, Expr, SelectItem, SetExpr, Statement};

use crate::errors::SqlkitError;

use super::helpers::*;
use super::types::*;

/// Overwrite a CTE body's inferred output column names with the CTE's explicit
/// column alias list (`WITH t(a, b) AS ...`). A body projection that carries
/// no names of its own — e.g. `SELECT 1` — otherwise names its columns
/// "unknown". PostgreSQL requires the alias count to match the body's column
/// count, so a mismatch is a hard error rather than a positional guess.
fn apply_cte_alias_columns(
    cte_alias: &ast::TableAlias,
    mut cols: Vec<AnalyzedColumn>,
) -> Result<Vec<AnalyzedColumn>, SqlkitError> {
    if cte_alias.columns.is_empty() {
        return Ok(cols);
    }
    if cte_alias.columns.len() != cols.len() {
        return Err(SqlkitError::cte_column_alias_mismatch(
            cte_alias.columns.len(),
            cols.len(),
        ));
    }
    for (col, alias) in cols.iter_mut().zip(&cte_alias.columns) {
        col.name = ident_name(&alias.name);
    }
    Ok(cols)
}

impl<'a> Analyzer<'a> {
    pub(super) fn analyze_statement(
        &mut self,
        stmt: &Statement,
    ) -> Result<(Vec<AnalyzedColumn>, Vec<ParamInfo>), SqlkitError> {
        match stmt {
            Statement::Query(query) => {
                let cols = self.analyze_query(query)?;
                Ok((cols, self.params.clone()))
            }
            Statement::Insert(insert) => self.analyze_insert(insert),
            Statement::Update(update) => self.analyze_update(
                &update.table,
                &update.assignments,
                &update.from,
                &update.selection,
                &update.returning,
            ),
            Statement::Delete(delete) => self.analyze_delete(delete),
            _ => Ok((Vec::new(), Vec::new())),
        }
    }

    pub(super) fn analyze_query(&mut self, query: &ast::Query) -> Result<Vec<AnalyzedColumn>, SqlkitError> {
        let keep_table_row_type = std::mem::take(&mut self.keep_table_row_type);
        if let Some(with) = &query.with {
            for cte in &with.cte_tables {
                let cte_name = ident_name(&cte.alias.name);
                if with.recursive {
                    let is_union = matches!(cte.query.body.as_ref(), SetExpr::SetOperation { .. });
                    if !is_union {
                        let body_sql = format!("{}", cte.query);
                        let body_lower = body_sql.to_lowercase();
                        if body_lower.contains(&format!("from {}", cte_name.to_lowercase()))
                            || body_lower.contains(&format!("join {}", cte_name.to_lowercase()))
                        {
                            return Err(SqlkitError::invalid_recursion(format!(
                                "recursive CTE \"{}\" has no non-recursive base case",
                                cte_name
                            )));
                        }
                    } else {
                        if let SetExpr::SetOperation { left, .. } = cte.query.body.as_ref() {
                            // The recursive term references the CTE by name, so the
                            // anchor's own types must be in scope before it can be
                            // analyzed: seed `self.ctes` with the anchor-only shape
                            // first.
                            let base_cols = self.analyze_set_expr(left)?;
                            // The alias list names the CTE's columns, and the
                            // recursive term references them by name — apply it
                            // before seeding the scope.
                            let base_cols = apply_cte_alias_columns(&cte.alias, base_cols)?;
                            let scope_cols: Vec<ScopeColumn> =
                                base_cols.iter().map(ScopeColumn::from_analyzed_column).collect();
                            self.ctes.insert(cte_name.clone(), scope_cols);

                            // Re-analyze the full anchor-UNION-recursive query and
                            // keep the result instead of discarding it. That takes
                            // the SetOperation path in analyze_set_expr, which
                            // widens nullability across both branches and errors on
                            // a column-count mismatch between them — the same rules
                            // as any other UNION. Anchor-only typing under-reports
                            // nullability whenever the recursive term introduces a
                            // NULL the anchor doesn't have, e.g. a LEFT JOIN or an
                            // explicit NULL literal in a position the anchor fills
                            // with a NOT NULL column.
                            let full_cols = self.analyze_query(&cte.query)?;
                            // The widened union shape takes its names from the left
                            // arm; re-apply the alias list so the registered CTE
                            // columns keep the declared names.
                            let full_cols = apply_cte_alias_columns(&cte.alias, full_cols)?;
                            let widened_scope_cols: Vec<ScopeColumn> =
                                full_cols.iter().map(ScopeColumn::from_analyzed_column).collect();
                            self.ctes.insert(cte_name.clone(), widened_scope_cols);
                            continue;
                        }
                    }
                }
                let cte_cols = self.analyze_query(&cte.query)?;
                let cte_cols = apply_cte_alias_columns(&cte.alias, cte_cols)?;
                let scope_cols: Vec<ScopeColumn> = cte_cols.iter().map(ScopeColumn::from_analyzed_column).collect();
                self.ctes.insert(cte_name, scope_cols);
            }
        }

        let order_by = query.order_by.as_ref().and_then(|order_by| match &order_by.kind {
            ast::OrderByKind::Expressions(items) => Some(items.as_slice()),
            ast::OrderByKind::All(_) => None,
        });
        let result = match query.body.as_ref() {
            SetExpr::Select(select) => {
                self.analyze_select(select, order_by.unwrap_or_default(), keep_table_row_type)?
            }
            body => {
                let columns = self.analyze_set_expr(body)?;
                // A set operation is ordered by its output columns.
                let scope = Scope {
                    sources: vec![ScopeSource {
                        alias: String::new(),
                        table_name: String::new(),
                        columns: columns.iter().map(ScopeColumn::from_analyzed_column).collect(),
                        nullable_from_join: false,
                    }],
                };
                for item in order_by.unwrap_or_default() {
                    self.collect_params_from_where(&item.expr, &scope);
                }
                columns
            }
        };

        if let Some(ref limit_clause) = query.limit_clause {
            match limit_clause {
                sqlparser::ast::LimitClause::LimitOffset { limit, offset, .. } => {
                    if let Some(limit) = limit {
                        self.collect_param_from_expr(limit, "limit", "int64");
                    }
                    if let Some(offset) = offset {
                        self.collect_param_from_expr(&offset.value, "offset", "int64");
                    }
                }
                sqlparser::ast::LimitClause::OffsetCommaLimit { offset, limit } => {
                    self.collect_param_from_expr(limit, "limit", "int64");
                    self.collect_param_from_expr(offset, "offset", "int64");
                }
            }
        }

        Ok(result)
    }

    pub(super) fn analyze_set_expr(&mut self, set_expr: &SetExpr) -> Result<Vec<AnalyzedColumn>, SqlkitError> {
        match set_expr {
            SetExpr::Select(select) => self.analyze_select(select, &[], false),
            SetExpr::Query(query) => self.analyze_query(query),
            SetExpr::SetOperation { left, right, .. } => {
                let left_cols = self.analyze_set_expr(left)?;
                let right_cols = self.analyze_set_expr(right)?;
                if !left_cols.is_empty() && !right_cols.is_empty() && left_cols.len() != right_cols.len() {
                    return Err(SqlkitError::column_count_mismatch(left_cols.len(), right_cols.len()));
                }
                let widened: Vec<AnalyzedColumn> = left_cols
                    .iter()
                    .enumerate()
                    .map(|(i, lc)| {
                        if i < right_cols.len() {
                            let widened_type = self.widen_union_arm_type(&lc.neutral_type, &right_cols[i].neutral_type);
                            // Preserve the source `sql_type` when both sides of the UNION
                            // agree on it; backends may match on `sql_type`, not
                            // `neutral_type`.
                            // Only fall back to the widened neutral type when the sides
                            // genuinely disagree on the source type.
                            let sql_type = if lc.sql_type == right_cols[i].sql_type {
                                lc.sql_type.clone()
                            } else {
                                widened_type.clone()
                            };
                            AnalyzedColumn {
                                name: lc.name.clone(),
                                sql_type,
                                neutral_type: widened_type,
                                nullable: lc.nullable || right_cols[i].nullable,
                                // ~keep Both arms untyped means nothing resolved this column --
                                // survive the taint so `analyze()` still rejects it. Either
                                // arm supplying a real type must clear it, or a NULL arm a
                                // sibling resolves would wrongly stay flagged (the passing
                                // `test_null_projection_widened_by_union_arm_is_not_rejected`).
                                untyped_literal: lc.untyped_literal && right_cols[i].untyped_literal,
                                ..Default::default()
                            }
                        } else {
                            lc.clone()
                        }
                    })
                    .collect();
                Ok(widened)
            }
            // A data-modifying statement in a CTE yields its RETURNING columns.
            SetExpr::Insert(statement)
            | SetExpr::Update(statement)
            | SetExpr::Delete(statement)
            | SetExpr::Merge(statement) => Ok(self.analyze_statement(statement)?.0),
            SetExpr::Values(values) => {
                // Widen every row's type and OR its nullability into the
                // running per-column result instead of reading only the
                // first row -- a later row can both need a wider type
                // (`(1), (2.5)` needs `decimal`, not `int64`) and introduce
                // a NULL the first row didn't have (#121).
                //
                // Tracked as plain `String`/`bool` accumulators rather than
                // folding with `widen_type_info`/`TypeInfo`: `TypeInfo`'s
                // `unknown()` sentinel defaults `nullable: true`, which
                // would OR every column to nullable from the very first
                // fold step regardless of what the rows actually contain.
                let Some(first_row) = values.rows.first() else {
                    return Ok(Vec::new());
                };
                let ncols = first_row.len();
                let mut result_types = vec!["unknown".to_string(); ncols];
                let mut result_nullable = vec![false; ncols];
                let empty_scope = Scope { sources: Vec::new() };
                for row in &values.rows {
                    for (i, expr) in row.iter().enumerate() {
                        let Some(col_type) = result_types.get_mut(i) else {
                            // A malformed VALUES list with a row longer than
                            // the first is a SQL error the parser/engine
                            // would already reject; skip rather than panic.
                            continue;
                        };
                        let ti = self.infer_expr_type(expr, &empty_scope);
                        *col_type = widen_neutral_type(col_type, &ti.neutral_type);
                        if ti.nullable {
                            result_nullable[i] = true;
                        }
                    }
                }
                let cols: Vec<AnalyzedColumn> = result_types
                    .into_iter()
                    .zip(result_nullable)
                    .enumerate()
                    .map(|(i, (neutral_type, nullable))| {
                        AnalyzedColumn::from_type_info(
                            format!("column{}", i + 1),
                            TypeInfo::new(neutral_type, nullable),
                        )
                    })
                    .collect();
                Ok(cols)
            }
            _ => Ok(Vec::new()),
        }
    }

    /// Widen two UNION-arm column types, with a nested-aggregate-aware path
    /// `widen_type` alone can't provide.
    ///
    /// `widen_type` has no concept of `json_nested<...>`, and every
    /// `json_agg`/`row_to_json` call gets a *fresh* `__nested__{id}`
    /// placeholder (see `Analyzer::push_pending_nested`) -- so two arms
    /// producing the exact same nested shape would still carry different
    /// ids and never compare equal there. Left unhandled, `widen_type`'s
    /// existing "genuinely different types -> left wins" fallback would
    /// silently discard whichever arm's shape didn't happen to be on the
    /// left, even when the two arms describe different underlying rows --
    /// this is the one case where "left silently wins" is not an
    /// acceptable degradation, because the discarded shape's fields are
    /// gone with no diagnostic.
    ///
    /// Three outcomes, in order of how the arms pair up:
    /// - both arms nested with the identical shape: widen to the left arm's
    ///   placeholder, which phase 2 then resolves once;
    /// - both arms nested with different shapes: diagnostic;
    /// - exactly one arm nested: also a diagnostic. This is *not* an
    ///   ordinary "different types, left wins" mismatch. If the nested arm
    ///   is on the left, the column keeps the strongly-typed struct and the
    ///   other arm's arbitrary JSON (`'[]'::json`, a `jsonb` column, ...)
    ///   gets deserialized into it at runtime with nothing failing at build
    ///   time; if it is on the right, the struct silently disappears. Both
    ///   directions produce code that compiles and is wrong.
    ///
    /// Two non-nested arms are untouched and fall straight through to
    /// `widen_neutral_type`, so an untyped `NULL` arm on either side is
    /// absorbed into the other arm's real type regardless of arm order
    /// (#224) -- `widen_type` alone is order-sensitive and must not be
    /// called here directly.
    fn widen_union_arm_type(&mut self, left: &str, right: &str) -> String {
        let (left_nested, right_nested) = (find_nested_placeholder_id(left), find_nested_placeholder_id(right));

        let (Some(left_id), Some(right_id)) = (left_nested, right_nested) else {
            if left_nested.is_some() || right_nested.is_some() {
                let (nested_side, other) = if left_nested.is_some() {
                    ("left", right)
                } else {
                    ("right", left)
                };
                self.type_errors.push(format!(
                    "UNION arms disagree: the {nested_side} arm produces a nested aggregate \
                     (json_agg/row_to_json) with an inferred row shape, but the other arm produces \
                     \"{other}\"; there is no way to widen a nested struct against a type that is not one, \
                     and silently keeping either arm would deserialize the other arm's values into the \
                     wrong shape at runtime"
                ));
            }
            return widen_neutral_type(left, right);
        };

        let left_fields = self
            .pending_nested
            .iter()
            .find(|p| p.id == left_id)
            .map(|p| p.fields.clone());
        let right_fields = self
            .pending_nested
            .iter()
            .find(|p| p.id == right_id)
            .map(|p| p.fields.clone());

        if left_fields.is_some() && left_fields == right_fields {
            // Both arms produced the identical nested shape (same fields,
            // same order, same types and nullability) -- interchangeable,
            // so keeping the left arm's placeholder (and letting phase 2
            // resolve just that one) is correct, not merely convenient.
            return left.to_string();
        }

        self.type_errors.push(
            "UNION arms both produce a nested aggregate (json_agg/row_to_json) but with different row \
             shapes; a UNION requires every arm to produce the same column types, and there is no way to \
             widen two different nested struct shapes into one"
                .to_string(),
        );
        left.to_string()
    }

    pub(super) fn analyze_select(
        &mut self,
        select: &ast::Select,
        order_by: &[ast::OrderByExpr],
        keep_table_row_type: bool,
    ) -> Result<Vec<AnalyzedColumn>, SqlkitError> {
        let scope = self.build_scope_from_from(&select.from)?;
        // The projection sees the scope as the filters leave it: each column
        // they prove non-null is, and an outer-joined source they prove
        // present is no longer null-extended. A query whose columns are its
        // table's row type keeps that type; see `AnalyzedQuery::source_table`.
        let projected = if keep_table_row_type {
            scope.clone()
        } else {
            narrowed_by_filters(select, &scope)
        };

        // ~keep Projection is analyzed before WHERE/HAVING even though the scope-building
        // FROM clause runs first: `SELECT ... FROM ... WHERE ...` places the
        // projection ahead of the WHERE/HAVING clauses in the source text, and a
        // bare `?` placeholder's position is assigned in traversal order (`$N`
        // placeholders carry their own number and are unaffected). Visiting
        // WHERE/HAVING first inverted that order and bound a later `?` before an
        // earlier one (#170).
        let mut columns = Vec::new();
        for item in &select.projection {
            match item {
                SelectItem::UnnamedExpr(expr) => {
                    self.collect_params_from_where(expr, &projected);
                    let ti = self.infer_expr_type(expr, &projected);
                    let name = expr_to_name(expr);
                    columns.push(AnalyzedColumn::from_type_info(name, ti));
                }
                SelectItem::ExprWithAlias { expr, alias } => {
                    self.collect_params_from_where(expr, &projected);
                    let ti = self.infer_expr_type(expr, &projected);
                    columns.push(AnalyzedColumn::from_type_info(ident_name(alias), ti));
                }
                SelectItem::ExprWithAliases { expr, aliases } => {
                    self.collect_params_from_where(expr, &projected);
                    let ti = self.infer_expr_type(expr, &projected);
                    for alias in aliases {
                        columns.push(AnalyzedColumn::from_type_info(ident_name(alias), ti.clone()));
                    }
                }
                SelectItem::Wildcard(_) => {
                    for source in &projected.sources {
                        for col in &source.columns {
                            columns.push(AnalyzedColumn::from_type_info(
                                col.name.clone(),
                                TypeInfo::from_scope_column(col, source),
                            ));
                        }
                    }
                }
                SelectItem::QualifiedWildcard(kind, _) => {
                    let qualifier = match kind {
                        ast::SelectItemQualifiedWildcardKind::ObjectName(name) => object_column_name(name),
                        ast::SelectItemQualifiedWildcardKind::Expr(expr) => expr_to_name(expr),
                    };
                    for source in &projected.sources {
                        if source.alias == qualifier || source.table_name == qualifier {
                            for col in &source.columns {
                                columns.push(AnalyzedColumn::from_type_info(
                                    col.name.clone(),
                                    TypeInfo::from_scope_column(col, source),
                                ));
                            }
                        }
                    }
                }
            }
        }

        if let Some(ref selection) = select.selection {
            self.collect_params_from_where(selection, &scope);
        }

        if let ast::GroupByExpr::Expressions(group_by, _) = &select.group_by {
            for expr in group_by {
                self.collect_params_from_where(expr, &scope);
            }
        }

        if let Some(ref having) = select.having {
            self.collect_params_from_where(having, &scope);
        }

        for item in order_by {
            self.collect_params_from_where(&item.expr, &scope);
        }

        reject_unresolved_columns(&columns)?;

        // `SELECT u.id, p.id FROM users u JOIN posts p ...` is an ordinary
        // join projection, not a user error: both columns are renamed
        // (`id_1`, `id_2`) by the same rule the parameter path applies to
        // `WHERE id = $1 OR id = $2` (#175). Unnamed columns are excluded --
        // a projection of bare literals yields several of them by design, and
        // a CTE alias list replaces them later when one exists.
        disambiguate_duplicate_names(
            columns
                .iter_mut()
                .filter(|col| col.name != UNNAMED_COLUMN)
                .map(|col| &mut col.name),
        );

        Ok(columns)
    }

    pub(super) fn analyze_insert(
        &mut self,
        insert: &ast::Insert,
    ) -> Result<(Vec<AnalyzedColumn>, Vec<ParamInfo>), SqlkitError> {
        let table_name = match &insert.table {
            ast::TableObject::TableName(name) => object_name_to_string(name).to_lowercase(),
            ast::TableObject::TableFunction(func) => object_name_to_string(&func.name).to_lowercase(),
            ast::TableObject::TableQuery(_) => {
                return Err(SqlkitError::syntax(
                    "INSERT target must be a table name or table function",
                ));
            }
        };

        let target_scope = self.build_target_scope(
            &table_name,
            insert
                .table_alias
                .as_ref()
                .map(|alias| ident_name(&alias.alias))
                .or_else(|| match &insert.table {
                    ast::TableObject::TableName(name) => Some(relation_alias(name)),
                    _ => None,
                }),
        )?;
        let target_cols: Vec<String> = insert.columns.iter().map(object_column_name).collect();

        if let Some(ref source) = insert.source {
            self.collect_insert_params(&table_name, &target_cols, source)?;
        }

        if let Some(ref on_conflict) = insert.on
            && let ast::OnInsert::OnConflict(oc) = on_conflict
            && let ast::OnConflictAction::DoUpdate(do_update) = &oc.action
        {
            // `excluded` is the row proposed for insertion.
            let mut scope = target_scope.clone();
            if let Some(target) = target_scope.sources.first() {
                scope.sources.push(ScopeSource {
                    alias: "excluded".to_string(),
                    table_name: "excluded".to_string(),
                    columns: target.columns.clone(),
                    nullable_from_join: false,
                });
            }
            self.collect_assignment_params(&table_name, &do_update.assignments, &scope);
            if let Some(ref selection) = do_update.selection {
                self.collect_params_from_where(selection, &scope);
            }
        }

        let columns = if let Some(ref returning) = insert.returning {
            self.analyze_returning(&target_scope, returning)?
        } else {
            Vec::new()
        };

        Ok((columns, self.params.clone()))
    }

    fn collect_insert_params(
        &mut self,
        table_name: &str,
        target_cols: &[String],
        source: &ast::Query,
    ) -> Result<(), SqlkitError> {
        // Resolve the column each source position binds to: the explicit
        // column list, or — when omitted — every column of the table in
        // catalog order (standard SQL positional binding for
        // `INSERT INTO t VALUES (...)`).
        let effective_cols: Vec<Option<(String, String, bool)>> = if target_cols.is_empty() {
            match self.catalog.get_table(table_name) {
                Some(table) => table
                    .columns
                    .iter()
                    .map(|c| Some((c.name.clone(), self.get_column_type(table_name, &c.name)?, c.nullable)))
                    .collect(),
                None => Vec::new(),
            }
        } else {
            target_cols
                .iter()
                .map(|n| {
                    Some((
                        n.clone(),
                        self.get_column_type(table_name, n)?,
                        self.is_column_nullable(table_name, n),
                    ))
                })
                .collect()
        };

        match source.body.as_ref() {
            SetExpr::Values(values) => {
                // A position with no known column falls back to inferring the
                // expression's own type, so placeholders are never dropped
                // silently.
                for row in &values.rows {
                    for (i, expr) in row.iter().enumerate() {
                        let empty_scope = Scope { sources: Vec::new() };
                        if let Some((col_name, col_type, nullable)) = effective_cols.get(i).and_then(|c| c.as_ref()) {
                            let evidence = nullable.then_some(NullEvidence::WrittenToNullable);
                            self.collect_param_from_expr_with_type_nullable(expr, col_type, col_name, evidence);
                            self.bind_written_param(expr, table_name, col_name);
                            // Placeholders nested in the value (a COALESCE
                            // argument, a function argument) are typed from
                            // their own context, as in `SET col = ...`.
                            self.collect_params_from_where(expr, &empty_scope);
                        } else {
                            let ti = self.infer_expr_type(expr, &empty_scope);
                            let name = target_cols.get(i).cloned().unwrap_or_else(|| expr_to_name(expr));
                            self.collect_param_from_expr_with_type_nullable(expr, &ti.neutral_type, &name, None);
                        }
                    }
                }
            }
            body => {
                // `INSERT ... SELECT $1, x FROM ...`: a placeholder that is a
                // whole select-list item is the value written into its column,
                // as PostgreSQL types it.
                if let SetExpr::Select(select) = body {
                    for (i, item) in select.projection.iter().enumerate() {
                        let (SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. }) = item else {
                            continue;
                        };
                        if let Some((col_name, col_type, nullable)) = effective_cols.get(i).and_then(|c| c.as_ref())
                            && placeholder_token(expr).is_some()
                        {
                            let evidence = nullable.then_some(NullEvidence::WrittenToNullable);
                            self.collect_param_from_expr_with_type_nullable(expr, col_type, col_name, evidence);
                            self.bind_written_param(expr, table_name, col_name);
                        }
                    }
                }
                let _ = self.analyze_query(source)?;
            }
        }
        Ok(())
    }

    /// Bind the parameters a `SET col = ...` list writes, typed by their
    /// column and nullable when the column is -- as `INSERT ... VALUES` does.
    /// Placeholders nested deeper in a value (a subquery, a function call)
    /// are typed from their own context.
    fn collect_assignment_params(&mut self, table_name: &str, assignments: &[ast::Assignment], scope: &Scope) {
        for assign in assignments {
            let col_name = assignment_target_name(&assign.target);
            if let Some(col_type) = self.get_column_type(table_name, &col_name) {
                let evidence = self
                    .is_column_nullable(table_name, &col_name)
                    .then_some(NullEvidence::WrittenToNullable);
                self.collect_param_from_expr_with_type_nullable(&assign.value, &col_type, &col_name, evidence);
                self.bind_written_param(&assign.value, table_name, &col_name);
            }
            self.collect_params_from_where(&assign.value, scope);
        }
    }

    pub(super) fn analyze_update(
        &mut self,
        table: &ast::TableWithJoins,
        assignments: &[ast::Assignment],
        from: &Option<ast::UpdateTableFromKind>,
        selection: &Option<Expr>,
        returning: &Option<Vec<SelectItem>>,
    ) -> Result<(Vec<AnalyzedColumn>, Vec<ParamInfo>), SqlkitError> {
        let table_name = table_factor_name(&table.relation);

        let mut scope = self.build_target_scope(&table_name, table_factor_alias(&table.relation))?;
        if let Some(from_kind) = from {
            let tables = match from_kind {
                ast::UpdateTableFromKind::BeforeSet(tables) | ast::UpdateTableFromKind::AfterSet(tables) => tables,
            };
            let from_scope = self.build_scope_from_from(tables)?;
            scope.sources.extend(from_scope.sources);
        }

        self.collect_assignment_params(&table_name, assignments, &scope);

        if let Some(sel) = selection {
            self.collect_params_from_where(sel, &scope);
        }

        let columns = if let Some(returning) = returning {
            self.analyze_returning(&scope, returning)?
        } else {
            Vec::new()
        };

        Ok((columns, self.params.clone()))
    }

    pub(super) fn analyze_delete(
        &mut self,
        delete: &ast::Delete,
    ) -> Result<(Vec<AnalyzedColumn>, Vec<ParamInfo>), SqlkitError> {
        let target = match &delete.from {
            ast::FromTable::WithFromKeyword(tables) | ast::FromTable::WithoutKeyword(tables) => tables.first(),
        };
        let table_name = target.map(|twj| table_factor_name(&twj.relation)).unwrap_or_default();
        let alias = target.and_then(|twj| table_factor_alias(&twj.relation));

        let scope = self.build_target_scope(&table_name, alias)?;

        let mut full_scope = scope;
        if let Some(ref using) = delete.using {
            let using_scope = self.build_scope_from_from(using)?;
            full_scope.sources.extend(using_scope.sources);
        }

        if let Some(ref selection) = delete.selection {
            self.collect_params_from_where(selection, &full_scope);
        }

        let columns = if let Some(ref returning) = delete.returning {
            self.analyze_returning(&full_scope, returning)?
        } else {
            Vec::new()
        };

        Ok((columns, self.params.clone()))
    }

    /// The scope of an INSERT, UPDATE or DELETE target: its table under its
    /// alias, which correlated subqueries and RETURNING refer to it by.
    fn build_target_scope(&self, table_name: &str, alias: Option<String>) -> Result<Scope, SqlkitError> {
        let mut scope = self.build_scope_for_table(table_name)?;
        if let (Some(alias), Some(source)) = (alias, scope.sources.first_mut()) {
            source.alias = alias;
        }
        Ok(scope)
    }

    /// RETURNING sees the target and, for UPDATE ... FROM and DELETE ...
    /// USING, the other FROM items.
    pub(super) fn analyze_returning(
        &mut self,
        scope: &Scope,
        returning: &[SelectItem],
    ) -> Result<Vec<AnalyzedColumn>, SqlkitError> {
        let mut columns = Vec::new();

        for item in returning {
            match item {
                SelectItem::UnnamedExpr(expr) => {
                    let ti = self.infer_expr_type(expr, scope);
                    let name = expr_to_name(expr);
                    columns.push(AnalyzedColumn::from_type_info(name, ti));
                }
                SelectItem::ExprWithAlias { expr, alias } => {
                    let ti = self.infer_expr_type(expr, scope);
                    columns.push(AnalyzedColumn::from_type_info(ident_name(alias), ti));
                }
                SelectItem::ExprWithAliases { expr, aliases } => {
                    let ti = self.infer_expr_type(expr, scope);
                    for alias in aliases {
                        columns.push(AnalyzedColumn::from_type_info(ident_name(alias), ti.clone()));
                    }
                }
                SelectItem::Wildcard(_) => {
                    for source in &scope.sources {
                        for col in &source.columns {
                            columns.push(AnalyzedColumn {
                                name: col.name.clone(),
                                sql_type: col.sql_type.clone(),
                                neutral_type: col.neutral_type.clone(),
                                nullable: col.base_nullable,
                                source_relation: Some(source.table_name.clone()),
                                origin: col.origin.clone(),
                                ..Default::default()
                            });
                        }
                    }
                }
                SelectItem::QualifiedWildcard(kind, _) => {
                    let qualifier = match kind {
                        ast::SelectItemQualifiedWildcardKind::ObjectName(name) => object_column_name(name),
                        ast::SelectItemQualifiedWildcardKind::Expr(expr) => expr_to_name(expr),
                    };
                    for source in &scope.sources {
                        if source.alias == qualifier || source.table_name == qualifier {
                            for col in &source.columns {
                                columns.push(AnalyzedColumn {
                                    name: col.name.clone(),
                                    sql_type: col.sql_type.clone(),
                                    neutral_type: col.neutral_type.clone(),
                                    nullable: col.base_nullable,
                                    source_relation: Some(source.table_name.clone()),
                                    origin: col.origin.clone(),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                }
            }
        }

        // The same two passes `analyze_select` runs, for the same reasons: a
        // typo in `RETURNING` is a user error (`UNKNOWN_COLUMN`), not an
        // internal one, and `RETURNING u.id, p.id` collides exactly the way a
        // projection does. Running only one of the two paths through these is
        // how RETURNING came to report `INTERNAL_ERROR` for a misspelled
        // column (#173).
        reject_unresolved_columns(&columns)?;
        disambiguate_duplicate_names(
            columns
                .iter_mut()
                .filter(|col| col.name != UNNAMED_COLUMN)
                .map(|col| &mut col.name),
        );

        Ok(columns)
    }
}

/// The columns a row must hold a value in to satisfy `condition`: those it
/// tests `IS NOT NULL`, and those it compares, since a comparison with NULL
/// is never true. Only conjuncts count, through `AND` and parentheses.
fn non_null_refs(condition: &Expr, scope: &Scope, refs: &mut Vec<(String, String)>) {
    match condition {
        Expr::Nested(inner) => non_null_refs(inner, scope, refs),
        Expr::BinaryOp {
            left,
            op: ast::BinaryOperator::And,
            right,
        } => {
            non_null_refs(left, scope, refs);
            non_null_refs(right, scope, refs);
        }
        Expr::IsNotNull(inner) => refs.extend(scope_column_ref(inner, scope)),
        Expr::BinaryOp {
            left,
            op:
                ast::BinaryOperator::Eq
                | ast::BinaryOperator::NotEq
                | ast::BinaryOperator::Lt
                | ast::BinaryOperator::LtEq
                | ast::BinaryOperator::Gt
                | ast::BinaryOperator::GtEq,
            right,
        } => {
            refs.extend(scope_column_ref(left, scope));
            refs.extend(scope_column_ref(right, scope));
        }
        _ => {}
    }
}

/// `scope` as the rows `select`'s filters let through see it: each column a
/// filter proves non-null is non-null, and a source one of whose columns a
/// filter proves non-null is not null-extended, since an outer join's
/// missing row is NULL in every column. Its columns return to their own
/// nullability and leave the outer join's group.
fn narrowed_by_filters(select: &ast::Select, scope: &Scope) -> Scope {
    let proven = filtered_non_null_refs(select, scope);
    let mut narrowed = scope.clone();
    for source in &mut narrowed.sources {
        for column in &mut source.columns {
            if proven
                .iter()
                .any(|(alias, name)| *alias == source.alias && *name == column.name)
            {
                column.base_nullable = false;
            }
        }
        if proven.iter().any(|(alias, _)| *alias == source.alias) {
            source.nullable_from_join = false;
        }
    }
    narrowed
}

/// The columns a SELECT's WHERE clause and inner joins' ON conditions prove
/// non-null in its rows. An inner join's condition stops counting when a
/// later RIGHT or FULL join can null-extend its side again, and none counts
/// under ROLLUP, CUBE or GROUPING SETS, whose subtotal rows null them.
fn filtered_non_null_refs(select: &ast::Select, scope: &Scope) -> Vec<(String, String)> {
    let mut refs = Vec::new();
    if let ast::GroupByExpr::Expressions(group_by, _) = &select.group_by
        && group_by
            .iter()
            .any(|expr| matches!(expr, Expr::Rollup(_) | Expr::Cube(_) | Expr::GroupingSets(_)))
    {
        return refs;
    }
    if let Some(selection) = &select.selection {
        non_null_refs(selection, scope, &mut refs);
    }
    for from in &select.from {
        let reextends = from.joins.iter().any(|join| {
            matches!(
                join.join_operator,
                ast::JoinOperator::Right(_) | ast::JoinOperator::RightOuter(_) | ast::JoinOperator::FullOuter(_)
            )
        });
        if reextends {
            continue;
        }
        for join in &from.joins {
            if let ast::JoinOperator::Join(ast::JoinConstraint::On(condition))
            | ast::JoinOperator::Inner(ast::JoinConstraint::On(condition)) = &join.join_operator
            {
                non_null_refs(condition, scope, &mut refs);
            }
        }
    }
    refs
}

#[cfg(test)]
mod union_sql_type_tests {
    use super::*;
    use crate::catalog::Catalog;
    use sqlparser::dialect::PostgreSqlDialect;
    use sqlparser::parser::Parser;

    fn make_catalog(ddl: &[&str]) -> Catalog {
        Catalog::from_ddl(ddl).unwrap()
    }

    fn make_analyzer(catalog: &Catalog) -> Analyzer<'_> {
        Analyzer::new(catalog)
    }

    fn parse_query(sql: &str) -> ast::Query {
        let dialect = PostgreSqlDialect {};
        let stmts = Parser::parse_sql(&dialect, sql).unwrap();
        let Statement::Query(query) = &stmts[0] else {
            unreachable!("test SQL must be a query");
        };
        (**query).clone()
    }

    /// A UNION over columns of the same source `sql_type` keeps that `sql_type` on the result
    /// column instead of overwriting it with the neutral type, so backends that match on
    /// `sql_type` still see it.
    #[test]
    fn test_union_over_matching_xml_columns_preserves_sql_type() {
        let catalog = make_catalog(&[
            "CREATE TABLE a (id INTEGER, notes XML);",
            "CREATE TABLE b (id INTEGER, notes XML);",
        ]);
        let mut analyzer = make_analyzer(&catalog);
        let query = parse_query("SELECT id, notes FROM a UNION SELECT id, notes FROM b");

        let columns = analyzer.analyze_query(&query).unwrap();
        let notes = columns
            .iter()
            .find(|c| c.name == "notes")
            .expect("notes column present");

        assert_eq!(
            notes.sql_type, "xml",
            "UNION over an XML column on both sides must preserve sql_type == \"xml\" \
             (not fall back to the neutral type \"string\"); got sql_type = {:?}",
            notes.sql_type
        );
        assert_eq!(
            notes.neutral_type, "string",
            "neutral_type must still be the widened neutral type"
        );
    }

    /// When the two sides of a UNION genuinely disagree on source `sql_type` (e.g. `XML`
    /// vs `VARCHAR`), there's no single source type to preserve, so the result must fall
    /// back to the widened neutral type rather than picking one side arbitrarily.
    #[test]
    fn test_union_over_mismatched_types_falls_back_to_widened_neutral_type() {
        let catalog = make_catalog(&[
            "CREATE TABLE a (id INTEGER, notes XML);",
            "CREATE TABLE b (id INTEGER, notes VARCHAR(255));",
        ]);
        let mut analyzer = make_analyzer(&catalog);
        let query = parse_query("SELECT id, notes FROM a UNION SELECT id, notes FROM b");

        let columns = analyzer.analyze_query(&query).unwrap();
        let notes = columns
            .iter()
            .find(|c| c.name == "notes")
            .expect("notes column present");

        assert_eq!(notes.neutral_type, "string");
        assert_eq!(
            notes.sql_type, "string",
            "mismatched sql_types across a UNION must fall back to the neutral type; got sql_type = {:?}",
            notes.sql_type
        );
    }
}
