use sqlparser::ast::{self, BinaryOperator, Expr, UnaryOperator};

use crate::catalog::ColumnOrigin;

use super::helpers::*;
use super::type_conversion::datatype_to_neutral;
use super::types::*;

impl<'a> Analyzer<'a> {
    /// Resolve a `$N` placeholder to its position. Any other token (e.g. a
    /// `:bucket` named placeholder) is an error: a message is pushed to
    /// `self.type_errors`, which `analyze()` checks before returning, and
    /// `None` is returned so the caller skips param registration.
    pub(super) fn resolve_placeholder_position(&mut self, placeholder: &str) -> Option<i64> {
        if let Some(pos) = parse_placeholder(placeholder) {
            Some(pos)
        } else {
            self.type_errors.push(format!(
                "unsupported placeholder \"{placeholder}\": named placeholders are not supported; use $N instead",
            ));
            None
        }
    }

    /// The placeholder `expr` is, parenthesised, cast or signed, with its
    /// position resolved and its cast as a neutral type. See
    /// [`placeholder_token`]. Every site that binds a placeholder operand
    /// peels it through this one helper.
    pub(super) fn placeholder_operand(&mut self, expr: &Expr) -> Option<PlaceholderOperand> {
        let token = placeholder_token(expr)?;
        let position = self.resolve_placeholder_position(token.token)?;
        Some(PlaceholderOperand {
            position,
            cast_type: token.cast.map(|data_type| datatype_to_neutral(data_type, self.catalog)),
            signed: token.signed,
        })
    }

    /// Register the placeholder `expr` is, if it is one: named `name`, typed
    /// by its own cast or else by `context_type`. Returns whether it was one.
    pub(super) fn bind_placeholder(
        &mut self,
        expr: &Expr,
        name: Option<String>,
        context_type: Option<String>,
        null_evidence: Option<NullEvidence>,
        source_relation: Option<String>,
    ) -> bool {
        let Some(operand) = self.placeholder_operand(expr) else {
            return false;
        };
        let neutral_type = operand.cast_type.or(context_type);
        self.register_param(operand.position, name, neutral_type, null_evidence, source_relation);
        true
    }

    pub(super) fn register_param(
        &mut self,
        position: i64,
        name: Option<String>,
        neutral_type: Option<String>,
        null_evidence: Option<NullEvidence>,
        source_relation: Option<String>,
    ) {
        if let Some(existing) = self.params.iter_mut().find(|p| p.position == position) {
            // Evidence accumulates where the rest fills blanks: one use that
            // gives the caller a reason to pass NULL makes the parameter
            // nullable, whichever use is visited first.
            existing.null_evidence = existing.null_evidence.or(null_evidence);
            if existing.name.is_none() && name.is_some() {
                existing.name = name;
            }
            if existing.neutral_type.is_none() && neutral_type.is_some() {
                existing.neutral_type = neutral_type;
            }
            if existing.source_relation.is_none() && source_relation.is_some() {
                existing.source_relation = source_relation;
            }
        } else {
            self.params.push(ParamInfo {
                position,
                name,
                neutral_type,
                null_evidence,
                source_relation,
                written_to: Vec::new(),
            });
        }
    }

    /// Record that the placeholder `expr` is -- bare, parenthesised or cast --
    /// the value written into `relation.column`, so the parameter takes that
    /// column's constraints. Call after the placeholder is registered.
    pub(super) fn bind_written_param(&mut self, expr: &Expr, relation: &str, column: &str) {
        // A signed placeholder (`-$1`) writes a value other than its own.
        let Some(PlaceholderOperand {
            position: pos,
            signed: false,
            ..
        }) = self.placeholder_operand(expr)
        else {
            return;
        };
        let origin = ColumnOrigin {
            relation: relation.to_string(),
            column: column.to_string(),
        };
        if let Some(param) = self.params.iter_mut().find(|param| param.position == pos)
            && !param.written_to.contains(&origin)
        {
            param.written_to.push(origin);
        }
    }

    pub(super) fn collect_params_from_where(&mut self, expr: &Expr, scope: &Scope) {
        match expr {
            Expr::BinaryOp { left, op, right } => match op {
                BinaryOperator::Eq
                | BinaryOperator::NotEq
                | BinaryOperator::Lt
                | BinaryOperator::LtEq
                | BinaryOperator::Gt
                | BinaryOperator::GtEq => {
                    self.try_bind_param_from_comparison(left, right, scope, Some(op));
                    self.try_bind_param_from_comparison(right, left, scope, Some(op));
                    let left_ti = self.infer_expr_type(left, scope);
                    let right_ti = self.infer_expr_type(right, scope);
                    if left_ti.neutral_type != "unknown"
                        && right_ti.neutral_type != "unknown"
                        && !left_ti.neutral_type.starts_with("__")
                        && !right_ti.neutral_type.starts_with("__")
                        && left_ti.neutral_type != right_ti.neutral_type
                        && !is_comparable_types(&left_ti.neutral_type, &right_ti.neutral_type)
                    {
                        let left_sql = neutral_to_sql_label(&left_ti.neutral_type);
                        let right_sql = neutral_to_sql_label(&right_ti.neutral_type);
                        let op_str = format!("{}", op);
                        self.type_errors.push(format!(
                            "operator does not exist: {} {} {}",
                            left_sql, op_str, right_sql
                        ));
                    }
                }
                BinaryOperator::And | BinaryOperator::Or => {
                    self.bind_boolean_operand(left);
                    self.bind_boolean_operand(right);
                    self.collect_params_from_where(left, scope);
                    self.collect_params_from_where(right, scope);
                }
                _ => {
                    let _ = self.infer_expr_type(expr, scope);
                    self.collect_params_from_where(left, scope);
                    self.collect_params_from_where(right, scope);
                }
            },
            Expr::Between {
                expr: col_expr,
                low,
                high,
                ..
            } => {
                let col_ti = self.infer_expr_type(col_expr, scope);
                self.collect_param_from_expr_with_type(low, &col_ti.neutral_type, "start");
                self.collect_param_from_expr_with_type(high, &col_ti.neutral_type, "end");
            }
            Expr::Like {
                expr: col_expr,
                pattern,
                ..
            }
            | Expr::ILike {
                expr: col_expr,
                pattern,
                ..
            } => {
                // A LIKE pattern is not always a bare placeholder literal --
                // `'%' || $1 || '%'` (a BinaryOp concat) is the common
                // idiom for a "contains" search, and was previously only
                // matched when `pattern` was exactly `Expr::Value`, so the
                // placeholder inside the concatenation silently registered
                // nothing (#171). `collect_param_from_expr_with_type`
                // already walks `BinaryOp`/`Cast`/`Nested`/... to find the
                // placeholder wherever it sits -- the same helper
                // `infer_expr_type`'s LIKE arm uses, so both traversals of
                // a LIKE pattern agree on what gets registered.
                let name = param_name(col_expr);
                self.collect_param_from_expr_with_type(pattern, "string", &name);
            }
            Expr::InList {
                expr: col_expr, list, ..
            } => {
                let col_ti = self.infer_expr_type(col_expr, scope);
                let col_name = param_name(col_expr);
                for item in list {
                    // No `source_relation`: each `$N` in the list stands for one element
                    // of a set the column is tested against, not a single bound value
                    // compared to that column the way `col = $N` is.
                    self.collect_param_from_expr(item, &col_name, &col_ti.neutral_type);
                }
            }
            // The operand was previously never descended into, so a
            // placeholder used inside it (e.g. `WHERE coalesce(x, $1) IS
            // NULL`) registered nothing and silently dropped a parameter
            // from the signature while `$1` stayed in the emitted SQL
            // (#171). `IS NULL`/`IS NOT NULL` themselves are never
            // placeholders -- there is nothing to bind at
            // this node -- so this only needs to keep walking.
            //
            // Testing a parameter itself for NULL (`$1 IS NULL OR col = $1`,
            // the optional-filter idiom) is the statement saying the
            // parameter may be NULL, so it is registered nullable here.
            Expr::IsNull(inner) | Expr::IsNotNull(inner) => {
                self.bind_null_tested_operand(inner);
                self.collect_params_from_where(inner, scope);
            }
            Expr::Nested(inner) => self.collect_params_from_where(inner, scope),
            Expr::UnaryOp { op, expr: inner } => {
                if *op == UnaryOperator::Not {
                    self.bind_boolean_operand(inner);
                }
                self.collect_params_from_where(inner, scope);
            }
            Expr::AnyOp { left, right, .. } | Expr::AllOp { left, right, .. } => {
                let left_ti = self.infer_expr_type(left, scope);
                self.collect_param_from_any(right, &left_ti, &param_name(left));
                // `$1 = ANY(array_expr)`: the placeholder is an element.
                let right_ti = self.infer_expr_type(right, scope);
                if let Some(element) = array_element_type(&right_ti.neutral_type) {
                    self.collect_param_from_expr(left, &param_name(right), element);
                }
                self.collect_params_from_where(left, scope);
                self.collect_params_from_where(right, scope);
            }
            Expr::InSubquery {
                expr: tested, subquery, ..
            } => {
                // `$1 IN (SELECT id ...)`: the placeholder takes the column's type.
                if let Ok(columns) = self.analyze_correlated_query(subquery, scope)
                    && let [column] = columns.as_slice()
                {
                    self.collect_param_from_expr(tested, &column.name, &column.neutral_type);
                }
                self.collect_params_from_where(tested, scope);
            }
            Expr::Exists { subquery, .. } => {
                let _ = self.analyze_correlated_query(subquery, scope);
            }
            Expr::Subquery(subquery) => {
                let _ = self.analyze_correlated_query(subquery, scope);
            }
            // Every branch can hold parameters in any position, so each is
            // walked like a condition of its own. A searched CASE's conditions
            // are boolean; a simple CASE compares each to its operand.
            Expr::Case {
                operand,
                conditions,
                else_result,
                ..
            } => {
                let operand_type = operand.as_ref().map(|operand| {
                    self.collect_params_from_where(operand, scope);
                    (self.infer_expr_type(operand, scope).neutral_type, param_name(operand))
                });
                for case_when in conditions {
                    match &operand_type {
                        Some((neutral_type, name)) => {
                            self.collect_param_from_expr(&case_when.condition, name, neutral_type);
                        }
                        None => self.bind_boolean_operand(&case_when.condition),
                    }
                    self.collect_params_from_where(&case_when.condition, scope);
                    self.collect_params_from_where(&case_when.result, scope);
                }
                if let Some(else_expr) = else_result {
                    self.collect_params_from_where(else_expr, scope);
                }
                // The CASE as a whole types placeholders among its results.
                let _ = self.infer_expr_type(expr, scope);
            }
            Expr::Function(func) => {
                let _ = self.infer_function_type(func, scope);
                let args = self.get_function_args(func);
                for arg in &args {
                    self.collect_params_from_where(arg, scope);
                }
            }
            Expr::Cast {
                expr: inner, data_type, ..
            } => {
                let neutral = datatype_to_neutral(data_type, self.catalog);
                self.collect_param_type_from_cast(inner, &neutral);
                self.collect_params_from_where(inner, scope);
            }
            _ => {
                let _ = self.infer_expr_type(expr, scope);
            }
        }
    }

    /// Type a placeholder operand of a JSON or containment operator as
    /// PostgreSQL resolves it: a key of `->`/`->>`/`?` is `text` (the string
    /// candidate wins over `integer`), a path of `#>`/`#>>` and the keys of
    /// `?|`/`?&` are `text[]`, and either side of `@>`/`<@` takes the other
    /// side's type.
    pub(super) fn bind_operator_placeholders(
        &mut self,
        left: &Expr,
        op: &BinaryOperator,
        right: &Expr,
        left_ti: &TypeInfo,
        right_ti: &TypeInfo,
    ) {
        let known = |ti: &TypeInfo| ti.neutral_type != "unknown" && !ti.neutral_type.starts_with("__");
        match op {
            BinaryOperator::Arrow | BinaryOperator::LongArrow | BinaryOperator::Question => {
                self.collect_param_from_expr(right, "key", "string");
            }
            BinaryOperator::HashArrow
            | BinaryOperator::HashLongArrow
            | BinaryOperator::QuestionAnd
            | BinaryOperator::QuestionPipe => {
                self.collect_param_from_expr(right, "path", "array<string>");
            }
            BinaryOperator::AtArrow | BinaryOperator::ArrowAt => {
                if known(left_ti) {
                    self.collect_param_from_expr(right, &param_name(left), &left_ti.neutral_type);
                }
                if known(right_ti) {
                    self.collect_param_from_expr(left, &param_name(right), &right_ti.neutral_type);
                }
            }
            _ => {}
        }
    }

    /// Register the placeholder an `IS [NOT] NULL` tests -- bare, parenthesised
    /// or cast (`$1::date IS NULL`) -- as nullable, typed by its cast if any.
    fn bind_null_tested_operand(&mut self, operand: &Expr) {
        if !self.bind_placeholder(operand, None, None, Some(NullEvidence::NullTested), None) {
            self.propagate_null_evidence(operand, NullEvidence::NullTested);
        }
    }

    /// Pass `evidence` that `expr` may be NULL on to the placeholders whose
    /// NULL makes it NULL through a STRICT function call: `$1` in
    /// `coalesce(code($1), 'none')`, where `code` is STRICT, may be NULL as
    /// much as `code($1)` may. Only the evidence passes: the call's own
    /// overload types and names its arguments.
    pub(super) fn propagate_null_evidence(&mut self, expr: &Expr, evidence: NullEvidence) {
        let mut operand = expr;
        while let Expr::Nested(inner) | Expr::Cast { expr: inner, .. } = operand {
            operand = inner;
        }
        let Expr::Function(func) = operand else {
            return;
        };
        if !self.is_strict_function(func) {
            return;
        }
        for argument in self.get_function_args(func) {
            if !self.bind_placeholder(&argument, None, None, Some(evidence), None) {
                self.propagate_null_evidence(&argument, evidence);
            }
        }
    }

    /// Whether every overload of the function `func` calls is STRICT, so a
    /// NULL argument makes the call NULL.
    fn is_strict_function(&self, func: &ast::Function) -> bool {
        let name = object_name_to_string(&func.name).to_lowercase();
        let overloads = self
            .catalog
            .get_functions(&name)
            .or_else(|| self.builtin_overloads(&name))
            .unwrap_or_default();
        !overloads.is_empty() && overloads.iter().all(|function| function.strict)
    }

    /// A placeholder that is an operand of `NOT`, `AND` or `OR` is boolean, as
    /// PostgreSQL infers it: `NOT $1` leaves no other context to type `$1` from.
    fn bind_boolean_operand(&mut self, operand: &Expr) {
        self.bind_placeholder(operand, None, Some("bool".to_string()), None, None);
    }

    pub(super) fn try_bind_param_from_comparison(
        &mut self,
        param_side: &Expr,
        col_side: &Expr,
        scope: &Scope,
        op: Option<&BinaryOperator>,
    ) {
        if placeholder_token(param_side).is_none() {
            return;
        }
        let col_ti = self.infer_expr_type(col_side, scope);
        let col_name = param_name(col_side);
        let param_name = derive_param_name_from_comparison(&col_name, col_side, param_side, op);
        // The one shape where "the column this parameter is bound against" is
        // unambiguous -- `col_side`'s own `source_relation`, the same field
        // `AnalyzedColumn` carries for the same reason (#189). Everywhere else
        // `register_param` is called from, the relation stays `None`.
        self.bind_placeholder(
            param_side,
            Some(param_name),
            Some(col_ti.neutral_type),
            None,
            col_ti.source_relation,
        );
    }

    pub(super) fn collect_param_from_expr(&mut self, expr: &Expr, name: &str, type_str: &str) {
        self.bind_placeholder(expr, Some(name.to_string()), Some(type_str.to_string()), None, None);
    }

    pub(super) fn collect_param_from_expr_with_type(&mut self, expr: &Expr, type_str: &str, name: &str) {
        self.collect_param_from_expr_with_type_nullable(expr, type_str, name, None);
    }

    /// Bind every placeholder in `expr` whose value becomes `expr`'s, typed
    /// and named by the context `expr` is in (the column it is written into,
    /// the pattern it matches), with `nullable` as their null evidence.
    pub(super) fn collect_param_from_expr_with_type_nullable(
        &mut self,
        expr: &Expr,
        type_str: &str,
        name: &str,
        nullable: Option<NullEvidence>,
    ) {
        if self.bind_placeholder(expr, Some(name.to_string()), Some(type_str.to_string()), nullable, None) {
            return;
        }
        match expr {
            Expr::Cast { expr: inner, .. } | Expr::Nested(inner) | Expr::UnaryOp { expr: inner, .. } => {
                self.collect_param_from_expr_with_type_nullable(inner, type_str, name, nullable);
            }
            Expr::BinaryOp { left, right, .. } => {
                self.collect_param_from_expr_with_type_nullable(left, type_str, name, nullable);
                self.collect_param_from_expr_with_type_nullable(right, type_str, name, nullable);
            }
            // A COALESCE argument's own evidence comes from inference, the
            // one place the COALESCE rule lives.
            Expr::Function(func) => {
                for arg in self.get_function_args(func) {
                    self.collect_param_from_expr_with_type_nullable(&arg, type_str, name, nullable);
                }
            }
            Expr::Case {
                operand,
                conditions,
                else_result,
                ..
            } => {
                if let Some(op) = operand {
                    self.collect_param_from_expr_with_type_nullable(op, type_str, name, nullable);
                }
                for case_when in conditions {
                    // A searched CASE's condition is a boolean, not the value written.
                    if operand.is_none() {
                        self.collect_param_from_expr_with_type_nullable(&case_when.condition, "bool", name, None);
                    } else {
                        self.collect_param_from_expr_with_type_nullable(&case_when.condition, type_str, name, nullable);
                    }
                    self.collect_param_from_expr_with_type_nullable(&case_when.result, type_str, name, nullable);
                }
                if let Some(else_expr) = else_result {
                    self.collect_param_from_expr_with_type_nullable(else_expr, type_str, name, nullable);
                }
            }
            _ => {}
        }
    }

    /// Type the placeholder a cast to `neutral_type` is applied to.
    pub(super) fn collect_param_type_from_cast(&mut self, expr: &Expr, neutral_type: &str) {
        let name = (neutral_type == "interval").then(|| "duration".to_string());
        self.bind_placeholder(expr, name, Some(neutral_type.to_string()), None, None);
    }

    /// Bind the placeholders of the array operand of `= ANY(...)`/`= ALL(...)`
    /// compared with a `left_ti` value: the whole array, or each element of
    /// an `ARRAY[...]` constructor.
    pub(super) fn collect_param_from_any(&mut self, expr: &Expr, left_ti: &TypeInfo, left_name: &str) {
        let array_type = format!("array<{}>", left_ti.neutral_type);
        if self.bind_placeholder(expr, Some(pluralize(left_name)), Some(array_type), None, None) {
            return;
        }
        match expr {
            Expr::Nested(inner) => self.collect_param_from_any(inner, left_ti, left_name),
            Expr::Array(arr) => {
                for (i, elem) in arr.elem.iter().enumerate() {
                    let name = format!("{}{}", left_name, i + 1);
                    self.bind_placeholder(elem, Some(name), Some(left_ti.neutral_type.clone()), None, None);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::Catalog;
    use ahash::AHashMap;
    use sqlparser::ast::{Ident, Value, ValueWithSpan};
    use sqlparser::tokenizer::Span;

    fn empty_catalog() -> Catalog {
        Catalog::from_ddl(&[]).unwrap()
    }

    fn make_analyzer(catalog: &Catalog) -> Analyzer<'_> {
        Analyzer {
            catalog,
            params: Vec::new(),
            ctes: AHashMap::new(),
            type_errors: Vec::new(),
            pending_nested: Vec::new(),
            next_nested_id: 0,
            outer_sources: Vec::new(),
        }
    }

    fn placeholder_expr(pos: &str) -> Expr {
        placeholder_expr_at(pos, Span::empty())
    }

    fn placeholder_expr_at(pos: &str, span: Span) -> Expr {
        Expr::Value(ValueWithSpan {
            value: Value::Placeholder(pos.to_string()),
            span,
        })
    }

    #[test]
    fn test_register_param_new() {
        let catalog = empty_catalog();
        let mut analyzer = make_analyzer(&catalog);
        analyzer.register_param(1, Some("id".to_string()), Some("int32".to_string()), None, None);
        assert_eq!(analyzer.params.len(), 1);
        assert_eq!(analyzer.params[0].position, 1);
        assert_eq!(analyzer.params[0].name, Some("id".to_string()));
        assert_eq!(analyzer.params[0].neutral_type, Some("int32".to_string()));
        assert_eq!(analyzer.params[0].null_evidence, None);
    }

    #[test]
    fn test_register_param_dedup_fills_missing() {
        let catalog = empty_catalog();
        let mut analyzer = make_analyzer(&catalog);
        analyzer.register_param(1, None, None, None, None);
        assert_eq!(analyzer.params.len(), 1);
        assert_eq!(analyzer.params[0].name, None);
        assert_eq!(analyzer.params[0].neutral_type, None);

        analyzer.register_param(1, Some("id".to_string()), Some("int32".to_string()), None, None);
        assert_eq!(analyzer.params.len(), 1);
        assert_eq!(analyzer.params[0].name, Some("id".to_string()));
        assert_eq!(analyzer.params[0].neutral_type, Some("int32".to_string()));
    }

    #[test]
    fn test_register_param_does_not_overwrite_existing() {
        let catalog = empty_catalog();
        let mut analyzer = make_analyzer(&catalog);
        analyzer.register_param(1, Some("id".to_string()), Some("int32".to_string()), None, None);
        analyzer.register_param(
            1,
            Some("new_name".to_string()),
            Some("string".to_string()),
            Some(NullEvidence::NullTested),
            None,
        );
        assert_eq!(analyzer.params.len(), 1);
        assert_eq!(analyzer.params[0].name, Some("id".to_string()));
        assert_eq!(analyzer.params[0].neutral_type, Some("int32".to_string()));
    }

    #[test]
    fn test_register_param_fills_missing_source_relation() {
        // Same fill-in-the-blank merge as name/neutral_type: a first registration with no
        // relation (e.g. from `collect_param_from_expr`) must not permanently lock the
        // param out of later picking one up from a comparison site.
        let catalog = empty_catalog();
        let mut analyzer = make_analyzer(&catalog);
        analyzer.register_param(1, Some("id".to_string()), Some("int32".to_string()), None, None);
        assert_eq!(analyzer.params[0].source_relation, None);
        analyzer.register_param(
            1,
            Some("id".to_string()),
            Some("int32".to_string()),
            None,
            Some("users".to_string()),
        );
        assert_eq!(analyzer.params.len(), 1, "still one param, not a second entry");
        assert_eq!(analyzer.params[0].source_relation, Some("users".to_string()));
    }

    #[test]
    fn test_register_param_does_not_overwrite_existing_source_relation() {
        let catalog = empty_catalog();
        let mut analyzer = make_analyzer(&catalog);
        analyzer.register_param(
            1,
            Some("id".to_string()),
            Some("int32".to_string()),
            None,
            Some("users".to_string()),
        );
        analyzer.register_param(
            1,
            Some("id".to_string()),
            Some("int32".to_string()),
            None,
            Some("orders".to_string()),
        );
        assert_eq!(analyzer.params[0].source_relation, Some("users".to_string()));
    }

    #[test]
    fn test_register_multiple_params() {
        let catalog = empty_catalog();
        let mut analyzer = make_analyzer(&catalog);
        analyzer.register_param(1, Some("name".to_string()), Some("string".to_string()), None, None);
        analyzer.register_param(2, Some("age".to_string()), Some("int32".to_string()), None, None);
        assert_eq!(analyzer.params.len(), 2);
        assert_eq!(analyzer.params[0].position, 1);
        assert_eq!(analyzer.params[1].position, 2);
    }

    #[test]
    fn test_try_bind_param_from_comparison_basic() {
        let catalog = Catalog::from_ddl(&["CREATE TABLE users (id INTEGER NOT NULL, name TEXT NOT NULL);"]).unwrap();
        let mut analyzer = Analyzer {
            catalog: &catalog,
            params: Vec::new(),
            ctes: AHashMap::new(),
            type_errors: Vec::new(),
            pending_nested: Vec::new(),
            next_nested_id: 0,
            outer_sources: Vec::new(),
        };
        let scope = Scope {
            sources: vec![ScopeSource {
                alias: "users".to_string(),
                table_name: "users".to_string(),
                columns: vec![
                    ScopeColumn::new("id", "int32", false),
                    ScopeColumn::new("name", "string", false),
                ],
                nullable_from_join: false,
            }],
        };

        let param_side = placeholder_expr("$1");
        let col_side = Expr::Identifier(Ident::new("id"));
        analyzer.try_bind_param_from_comparison(&param_side, &col_side, &scope, Some(&BinaryOperator::Eq));

        assert_eq!(analyzer.params.len(), 1);
        assert_eq!(analyzer.params[0].position, 1);
        assert_eq!(analyzer.params[0].name, Some("id".to_string()));
        assert_eq!(analyzer.params[0].neutral_type, Some("int32".to_string()));
        assert_eq!(
            analyzer.params[0].source_relation,
            Some("users".to_string()),
            "a direct `col = $N` comparison must carry the column's owning relation, the same \
             way AnalyzedColumn::source_relation does (#189)"
        );
    }

    /// The core of #189's remainder: `WHERE u.id = $1` must resolve `source_relation` to the
    /// real table name (`users`), not the query alias (`u`) -- exactly the distinction
    /// `AnalyzedColumn::source_relation` already makes (99227e8e). Must fail before the fix:
    /// `AnalyzedParam` carried no `source_relation` field at all, so a qualified `users.id`
    /// override on a parameter matched nothing outside `SELECT *`.
    #[test]
    fn test_try_bind_param_from_comparison_uses_real_table_name_not_alias() {
        let catalog = Catalog::from_ddl(&["CREATE TABLE users (id INTEGER NOT NULL);"]).unwrap();
        let mut analyzer = Analyzer {
            catalog: &catalog,
            params: Vec::new(),
            ctes: AHashMap::new(),
            type_errors: Vec::new(),
            pending_nested: Vec::new(),
            next_nested_id: 0,
            outer_sources: Vec::new(),
        };
        let scope = Scope {
            sources: vec![ScopeSource {
                alias: "u".to_string(),
                table_name: "users".to_string(),
                columns: vec![ScopeColumn::new("id", "int32", false)],
                nullable_from_join: false,
            }],
        };

        let param_side = placeholder_expr("$1");
        let col_side = Expr::CompoundIdentifier(vec![Ident::new("u"), Ident::new("id")]);
        analyzer.try_bind_param_from_comparison(&param_side, &col_side, &scope, Some(&BinaryOperator::Eq));

        assert_eq!(
            analyzer.params[0].source_relation,
            Some("users".to_string()),
            "must resolve to the real table name, not the `u` alias"
        );
    }

    /// A param bound through an `IN` list has a column it is tested against, but not a single
    /// bound value compared to it the way `col = $N` is -- per #189's remainder, this must
    /// stay `None` rather than guess at a relation.
    #[test]
    fn test_collect_params_from_where_in_list_has_no_source_relation() {
        let catalog = Catalog::from_ddl(&["CREATE TABLE users (id INTEGER NOT NULL);"]).unwrap();
        let mut analyzer = Analyzer {
            catalog: &catalog,
            params: Vec::new(),
            ctes: AHashMap::new(),
            type_errors: Vec::new(),
            pending_nested: Vec::new(),
            next_nested_id: 0,
            outer_sources: Vec::new(),
        };
        let scope = Scope {
            sources: vec![ScopeSource {
                alias: "users".to_string(),
                table_name: "users".to_string(),
                columns: vec![ScopeColumn::new("id", "int32", false)],
                nullable_from_join: false,
            }],
        };
        let expr = Expr::InList {
            expr: Box::new(Expr::Identifier(Ident::new("id"))),
            list: vec![placeholder_expr("$1")],
            negated: false,
        };
        analyzer.collect_params_from_where(&expr, &scope);
        assert_eq!(analyzer.params.len(), 1);
        assert_eq!(
            analyzer.params[0].source_relation, None,
            "an IN-list binding has no single owning column to target with a qualified override"
        );
    }

    #[test]
    fn test_collect_param_type_from_cast_placeholder() {
        let catalog = empty_catalog();
        let mut analyzer = make_analyzer(&catalog);
        let expr = placeholder_expr("$1");
        analyzer.collect_param_type_from_cast(&expr, "int32");
        assert_eq!(analyzer.params.len(), 1);
        assert_eq!(analyzer.params[0].neutral_type, Some("int32".to_string()));
    }

    #[test]
    fn test_collect_param_type_from_cast_interval_name() {
        let catalog = empty_catalog();
        let mut analyzer = make_analyzer(&catalog);
        let expr = placeholder_expr("$1");
        analyzer.collect_param_type_from_cast(&expr, "interval");
        assert_eq!(analyzer.params.len(), 1);
        assert_eq!(analyzer.params[0].name, Some("duration".to_string()));
        assert_eq!(analyzer.params[0].neutral_type, Some("interval".to_string()));
    }

    #[test]
    fn test_collect_param_type_from_cast_non_placeholder_ignored() {
        let catalog = empty_catalog();
        let mut analyzer = make_analyzer(&catalog);
        let expr = Expr::Identifier(Ident::new("x"));
        analyzer.collect_param_type_from_cast(&expr, "int32");
        assert_eq!(analyzer.params.len(), 0, "non-placeholder should not register a param");
    }

    #[test]
    fn test_resolve_placeholder_position_dollar_n() {
        let catalog = empty_catalog();
        let mut analyzer = make_analyzer(&catalog);
        assert_eq!(analyzer.resolve_placeholder_position("$1"), Some(1));
        assert_eq!(analyzer.resolve_placeholder_position("$99"), Some(99));
        assert!(analyzer.type_errors.is_empty());
    }

    #[test]
    fn test_resolve_placeholder_position_named_param_errors() {
        let catalog = empty_catalog();
        let mut analyzer = make_analyzer(&catalog);
        let result = analyzer.resolve_placeholder_position(":bucket");
        assert_eq!(result, None, "named placeholder must return None");
        assert_eq!(analyzer.type_errors.len(), 1, "one error must be recorded");
        assert!(
            analyzer.type_errors[0].contains(":bucket"),
            "error must name the offending token"
        );
        assert!(
            analyzer.type_errors[0].contains("not supported"),
            "error must explain the problem"
        );
    }

    #[test]
    fn test_collect_param_from_expr_placeholder() {
        let catalog = empty_catalog();
        let mut analyzer = make_analyzer(&catalog);
        let expr = placeholder_expr("$2");
        analyzer.collect_param_from_expr(&expr, "email", "string");
        assert_eq!(analyzer.params.len(), 1);
        assert_eq!(analyzer.params[0].position, 2);
        assert_eq!(analyzer.params[0].name, Some("email".to_string()));
        assert_eq!(analyzer.params[0].neutral_type, Some("string".to_string()));
    }

    // Regression tests for #171: a parameter dropped from the generated
    // function signature while the placeholder stays in the emitted SQL.

    #[test]
    fn test_collect_params_from_where_is_null_descends_into_operand() {
        let catalog = empty_catalog();
        let mut analyzer = make_analyzer(&catalog);
        let scope = Scope { sources: Vec::new() };
        // `$1 IS NULL` is a degenerate stand-in for the realistic shape
        // (`coalesce(x, $1) IS NULL`) that exercises the same operand
        // descent without needing to build a full function-call AST node.
        let expr = Expr::IsNull(Box::new(placeholder_expr("$1")));
        analyzer.collect_params_from_where(&expr, &scope);
        assert_eq!(
            analyzer.params.len(),
            1,
            "a placeholder inside an IS NULL operand must not be dropped"
        );
        assert_eq!(analyzer.params[0].position, 1);
    }

    #[test]
    fn test_collect_params_from_where_is_not_null_descends_into_operand() {
        let catalog = empty_catalog();
        let mut analyzer = make_analyzer(&catalog);
        let scope = Scope { sources: Vec::new() };
        let expr = Expr::IsNotNull(Box::new(placeholder_expr("$2")));
        analyzer.collect_params_from_where(&expr, &scope);
        assert_eq!(
            analyzer.params.len(),
            1,
            "a placeholder inside an IS NOT NULL operand must not be dropped"
        );
        assert_eq!(analyzer.params[0].position, 2);
    }

    #[test]
    fn test_collect_params_from_where_like_literal_pattern_still_registers() {
        let catalog = empty_catalog();
        let mut analyzer = make_analyzer(&catalog);
        let scope = Scope { sources: Vec::new() };
        let expr = Expr::Like {
            negated: false,
            any: false,
            expr: Box::new(Expr::Identifier(Ident::new("name"))),
            pattern: Box::new(placeholder_expr("$1")),
            escape_char: None,
        };
        analyzer.collect_params_from_where(&expr, &scope);
        assert_eq!(
            analyzer.params.len(),
            1,
            "the pre-existing literal-pattern case must keep working"
        );
        assert_eq!(analyzer.params[0].position, 1);
        assert_eq!(analyzer.params[0].name, Some("name".to_string()));
        assert_eq!(analyzer.params[0].neutral_type, Some("string".to_string()));
    }

    #[test]
    fn test_collect_params_from_where_like_non_literal_pattern_registers() {
        let catalog = empty_catalog();
        let mut analyzer = make_analyzer(&catalog);
        let scope = Scope { sources: Vec::new() };
        // `'%' || $1` is not an `Expr::Value`, so the old literal-only
        // check silently registered nothing for it (#171).
        let expr = Expr::Like {
            negated: false,
            any: false,
            expr: Box::new(Expr::Identifier(Ident::new("name"))),
            pattern: Box::new(Expr::BinaryOp {
                left: Box::new(Expr::Value(ValueWithSpan {
                    value: Value::SingleQuotedString("%".to_string()),
                    span: Span::empty(),
                })),
                op: BinaryOperator::StringConcat,
                right: Box::new(placeholder_expr("$1")),
            }),
            escape_char: None,
        };
        analyzer.collect_params_from_where(&expr, &scope);
        assert_eq!(
            analyzer.params.len(),
            1,
            "a placeholder inside a non-literal LIKE pattern must not be dropped"
        );
        assert_eq!(analyzer.params[0].position, 1);
        assert_eq!(analyzer.params[0].name, Some("name".to_string()));
        assert_eq!(analyzer.params[0].neutral_type, Some("string".to_string()));
    }
}
