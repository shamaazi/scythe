//! Matcher `"cartesian_join"` — SC-SEC08 cartesian-join.
//!
//! No `matcher_args`.  Emits one `MatcherHit` per cartesian-product shape,
//! with the full message in a `msg` binding (the TOML message is `{msg}`):
//! a comma-separated FROM of two or more independent items and no WHERE, or
//! an `ON true` / `CROSS JOIN` to an independent item.
//!
//! A FROM item is *dependent* — evaluated once per row of the items before
//! it, so joining it expands rows instead of multiplying two sets — when its
//! expressions reference an earlier FROM item; see [`is_row_expansion`].

use std::collections::HashSet;
use std::ops::ControlFlow;

use sqlkit_core::catalog::Catalog;
use sqlparser::ast::{
    Expr, Ident, JoinConstraint, JoinOperator, ObjectName, Query, Select, SelectItem, SetExpr, Statement, TableAlias,
    TableFactor, TableWithJoins, Value, ValueWithSpan, Visit, Visitor, visit_expressions,
};

use crate::audit::registry::MatcherHit;
use crate::types::LintContext;

const MSG_COMMA_FROM: &str = "comma-separated FROM with no WHERE — this is a cartesian product";
const MSG_UNCONSTRAINED_JOIN: &str = "unconstrained join (ON true / CROSS JOIN) — produces a cartesian product";

pub fn match_cartesian_join(ctx: &LintContext<'_>, _args: &toml::Table) -> Vec<MatcherHit> {
    let mut hits = Vec::new();
    if let Statement::Query(q) = ctx.stmt {
        walk_set_expr(&q.body, ctx.catalog, &mut hits);
    }
    hits
}

fn walk_set_expr(set_expr: &SetExpr, catalog: &Catalog, hits: &mut Vec<MatcherHit>) {
    match set_expr {
        SetExpr::Select(select) => {
            // The FROM items seen so far, which a later item may reference.
            let mut earlier: Vec<Bound> = Vec::new();
            let mut independent_items = 0;
            let mut join_hits = Vec::new();
            for twj in &select.from {
                if !is_row_expansion(&twj.relation, &earlier, catalog) {
                    independent_items += 1;
                }
                bind(&twj.relation, catalog, &mut earlier);
                for join in &twj.joins {
                    if join_is_unconstrained(&join.join_operator)
                        && !is_row_expansion(&join.relation, &earlier, catalog)
                    {
                        join_hits.push(MatcherHit::with_binding("msg", MSG_UNCONSTRAINED_JOIN));
                    }
                    bind(&join.relation, catalog, &mut earlier);
                }
            }
            if independent_items > 1 && select.selection.is_none() {
                hits.push(MatcherHit::with_binding("msg", MSG_COMMA_FROM));
            }
            hits.extend(join_hits);
        }
        SetExpr::Query(q) => walk_set_expr(&q.body, catalog, hits),
        SetExpr::SetOperation { left, right, .. } => {
            walk_set_expr(left, catalog, hits);
            walk_set_expr(right, catalog, hits);
        }
        _ => {}
    }
}

/// A FROM item as the items after it see it: the name it is referenced by
/// (its alias, else its table name) and its column names, `None` when they
/// are not known without running the query.
struct Bound {
    name: Option<String>,
    columns: Option<Vec<String>>,
}

/// Whether a FROM item is evaluated per row of the items before it rather
/// than joined to them as an independent set, so an `ON true`, `CROSS JOIN`
/// or comma join to it expands rows instead of multiplying them.
///
/// One rule covers every item that can see earlier items — a function call
/// (`generate_series(…)`, `unnest(…)`, `jsonb_to_recordset(…)`, which
/// PostgreSQL makes implicitly LATERAL), `JSON_TABLE`, `XMLTABLE` and a
/// `LATERAL` subquery: it is row expansion iff one of its expressions (the
/// function's arguments, or anywhere in the subquery) references an earlier
/// FROM item. So `CROSS JOIN generate_series(1, 1000000)` is a cartesian
/// product and `CROSS JOIN unnest(p.tags)` is not. A plain table, or a
/// subquery without `LATERAL`, cannot see earlier items and is never one.
///
/// A reference is found without a full name resolver; see
/// [`references_earlier`] for exactly what counts.
fn is_row_expansion(factor: &TableFactor, earlier: &[Bound], catalog: &Catalog) -> bool {
    match factor {
        TableFactor::Table { args: Some(_), .. }
        | TableFactor::Function { .. }
        | TableFactor::TableFunction { .. }
        | TableFactor::UNNEST { .. }
        | TableFactor::JsonTable { .. }
        | TableFactor::OpenJsonTable { .. }
        | TableFactor::XmlTable { .. } => references_earlier(factor, &InnerScope::empty(), earlier),
        TableFactor::Derived {
            lateral: true,
            subquery,
            ..
        } => references_earlier(subquery.as_ref(), &InnerScope::of(subquery, catalog), earlier),
        _ => false,
    }
}

/// Whether `node` references one of the `earlier` FROM items, given the
/// names `inner` binds within `node` itself (empty for a function call).
///
/// - A qualified column `q.col` references an earlier item named `q`,
///   unless `inner` binds `q` too: in `LATERAL (SELECT u.id FROM users u)`
///   the inner `u` shadows an outer `u`, so the subquery is not correlated.
/// - An unqualified column `col` references an earlier item only when the
///   catalog shows that `inner` cannot bind it — every inner FROM item has
///   known columns, none is named `col`, and no select-list alias is — and
///   some earlier item has a column `col`, or has columns the catalog does
///   not know. An inner item with unknown columns (a CTE, a function without
///   a column list) makes every unqualified column count as inner.
///
/// `inner` holds every name bound anywhere within the subquery, not only at
/// the reference's own level, so a reference shadowed only in a sibling
/// scope is treated as inner. Every approximation errs toward reporting a
/// cartesian product rather than hiding one.
fn references_earlier<V: Visit>(node: &V, inner: &InnerScope, earlier: &[Bound]) -> bool {
    let found = visit_expressions(node, |expr| {
        let outer = match expr {
            Expr::CompoundIdentifier(parts) if parts.len() >= 2 => {
                let qualifier = normalize(&parts[parts.len() - 2]);
                !inner.names.contains(&qualifier) && earlier.iter().any(|b| b.name.as_deref() == Some(&qualifier))
            }
            Expr::Identifier(ident) => {
                let column = normalize(ident);
                !inner.may_bind(&column)
                    && earlier
                        .iter()
                        .any(|b| b.columns.as_ref().is_none_or(|columns| columns.contains(&column)))
            }
            _ => false,
        };
        if outer {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    });
    found.is_break()
}

/// The names a subquery binds within itself: its FROM items, CTEs and
/// select-list aliases, at any depth.
struct InnerScope {
    names: HashSet<String>,
    /// Columns of every inner FROM item; `None` once one is unknown.
    columns: Option<HashSet<String>>,
    aliases: HashSet<String>,
}

impl InnerScope {
    /// The scope of a function call, which binds nothing.
    fn empty() -> Self {
        Self {
            names: HashSet::new(),
            columns: Some(HashSet::new()),
            aliases: HashSet::new(),
        }
    }

    fn of(query: &Query, catalog: &Catalog) -> Self {
        let mut collector = InnerScopeCollector {
            catalog,
            scope: Self::empty(),
        };
        let _ = query.visit(&mut collector);
        collector.scope
    }

    /// Whether an unqualified `column` may resolve within the subquery.
    fn may_bind(&self, column: &str) -> bool {
        self.aliases.contains(column) || self.columns.as_ref().is_none_or(|columns| columns.contains(column))
    }
}

struct InnerScopeCollector<'a> {
    catalog: &'a Catalog,
    scope: InnerScope,
}

impl Visitor for InnerScopeCollector<'_> {
    type Break = ();

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<()> {
        if let Some(with) = &query.with {
            for cte in &with.cte_tables {
                self.scope.names.insert(normalize(&cte.alias.name));
            }
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_select(&mut self, select: &Select) -> ControlFlow<()> {
        for item in &select.projection {
            if let SelectItem::ExprWithAlias { alias, .. } = item {
                self.scope.aliases.insert(normalize(alias));
            }
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_table_factor(&mut self, factor: &TableFactor) -> ControlFlow<()> {
        // A nested join's own items are visited after it.
        if let TableFactor::NestedJoin { alias, .. } = factor {
            if let Some(alias) = alias {
                self.scope.names.insert(normalize(&alias.name));
            }
            return ControlFlow::Continue(());
        }
        let mut bound = Vec::new();
        bind(factor, self.catalog, &mut bound);
        for b in bound {
            self.scope.names.extend(b.name);
            match (b.columns, &mut self.scope.columns) {
                (Some(columns), Some(all)) => all.extend(columns),
                _ => self.scope.columns = None,
            }
        }
        ControlFlow::Continue(())
    }
}

/// Push the FROM items `factor` makes visible to the items after it.
fn bind(factor: &TableFactor, catalog: &Catalog, out: &mut Vec<Bound>) {
    let (alias, columns) = match factor {
        TableFactor::Table { name, alias, args, .. } => {
            let table_columns = || match args {
                None => catalog
                    .get_table(&object_name(name)?)
                    .map(|table| table.columns.iter().map(|c| c.name.clone()).collect()),
                Some(_) => None,
            };
            let Some(alias) = alias else {
                let name = name.0.last().and_then(|part| part.as_ident()).map(normalize);
                out.push(Bound {
                    name,
                    columns: table_columns(),
                });
                return;
            };
            (alias, alias_columns(alias).or_else(table_columns))
        }
        TableFactor::Derived {
            alias: Some(alias),
            subquery,
            ..
        } => (alias, alias_columns(alias).or_else(|| output_names(subquery))),
        TableFactor::NestedJoin {
            alias: None,
            table_with_joins,
        } => {
            let TableWithJoins { relation, joins } = table_with_joins.as_ref();
            bind(relation, catalog, out);
            for join in joins {
                bind(&join.relation, catalog, out);
            }
            return;
        }
        TableFactor::Function { alias: Some(alias), .. }
        | TableFactor::TableFunction { alias: Some(alias), .. }
        | TableFactor::UNNEST { alias: Some(alias), .. }
        | TableFactor::JsonTable { alias: Some(alias), .. }
        | TableFactor::OpenJsonTable { alias: Some(alias), .. }
        | TableFactor::XmlTable { alias: Some(alias), .. }
        | TableFactor::NestedJoin { alias: Some(alias), .. } => (alias, alias_columns(alias)),
        _ => {
            out.push(Bound {
                name: None,
                columns: None,
            });
            return;
        }
    };
    out.push(Bound {
        name: Some(normalize(&alias.name)),
        columns,
    });
}

/// The column list of `AS t(a, b)`, if it has one.
fn alias_columns(alias: &TableAlias) -> Option<Vec<String>> {
    (!alias.columns.is_empty()).then(|| alias.columns.iter().map(|c| normalize(&c.name)).collect())
}

/// The output column names of a simple `SELECT` whose every item is a
/// column or has an alias.
fn output_names(query: &Query) -> Option<Vec<String>> {
    let SetExpr::Select(select) = query.body.as_ref() else {
        return None;
    };
    select
        .projection
        .iter()
        .map(|item| match item {
            SelectItem::ExprWithAlias { alias, .. } => Some(normalize(alias)),
            SelectItem::UnnamedExpr(Expr::Identifier(ident)) => Some(normalize(ident)),
            SelectItem::UnnamedExpr(Expr::CompoundIdentifier(parts)) => parts.last().map(normalize),
            _ => None,
        })
        .collect()
}

/// `name` as the catalog keys it (`schema.table`), when every part is a
/// plain identifier.
fn object_name(name: &ObjectName) -> Option<String> {
    let parts: Option<Vec<String>> = name.0.iter().map(|part| part.as_ident().map(normalize)).collect();
    Some(parts?.join("."))
}

/// An identifier as PostgreSQL folds it: unquoted lowercased, quoted as is.
fn normalize(ident: &Ident) -> String {
    match ident.quote_style {
        Some(_) => ident.value.clone(),
        None => ident.value.to_lowercase(),
    }
}

fn join_is_unconstrained(op: &JoinOperator) -> bool {
    match op {
        JoinOperator::CrossJoin(_) => true,
        JoinOperator::Inner(c)
        | JoinOperator::LeftOuter(c)
        | JoinOperator::RightOuter(c)
        | JoinOperator::FullOuter(c)
        | JoinOperator::Join(c) => match c {
            JoinConstraint::On(expr) => is_literal_true(expr),
            _ => false,
        },
        _ => false,
    }
}

fn is_literal_true(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Value(ValueWithSpan {
            value: Value::Boolean(true),
            ..
        })
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlkit_core::analyzer::AnalyzedQuery;
    use sqlkit_core::catalog::Catalog;
    use sqlkit_core::parser::{Annotations, QueryCommand};
    use sqlparser::dialect::PostgreSqlDialect;
    use sqlparser::parser::Parser;

    fn make_ctx_parts(sql: &str) -> (sqlparser::ast::Statement, AnalyzedQuery, Catalog, Annotations) {
        let stmt = Parser::parse_sql(&PostgreSqlDialect {}, sql).unwrap().remove(0);
        let analyzed = AnalyzedQuery::build(|aq| {
            aq.name = "q".to_string();
            aq.command = QueryCommand::Many;
            aq.sql = sql.to_string();
            aq.columns = vec![];
            aq.params = vec![];
            aq.deprecated = None;
            aq.source_table = None;
            aq.composites = vec![];
            aq.enums = vec![];
            aq.optional_params = vec![];
            aq.group_by = None;
            aq.custom = vec![];
        });
        let catalog = Catalog::from_ddl(&[SCHEMA]).unwrap();
        let annotations = Annotations {
            name: "q".to_string(),
            command: QueryCommand::Many,
            param_docs: vec![],
            nullable_overrides: vec![],
            nonnull_overrides: vec![],
            json_mappings: vec![],
            deprecated: None,
            optional_params: vec![],
            group_by: None,
            positional_param_docs: vec![],
            description: None,
            custom: vec![],
        };
        (stmt, analyzed, catalog, annotations)
    }

    fn make_ctx<'a>(
        sql: &'a str,
        stmt: &'a sqlparser::ast::Statement,
        analyzed: &'a AnalyzedQuery,
        catalog: &'a Catalog,
        annotations: &'a Annotations,
    ) -> LintContext<'a> {
        LintContext {
            sql,
            stmt,
            analyzed,
            catalog,
            annotations,
        }
    }

    #[test]
    fn fires_on_comma_from_no_where() {
        let sql = "SELECT a.id, b.name FROM users a, orders b";
        let (stmt, analyzed, catalog, annotations) = make_ctx_parts(sql);
        let ctx = make_ctx(sql, &stmt, &analyzed, &catalog, &annotations);
        let hits = match_cartesian_join(&ctx, &toml::Table::new());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].bindings.get("msg").map(|s| s.as_str()), Some(MSG_COMMA_FROM));
    }

    #[test]
    fn no_match_with_where_clause() {
        let sql = "SELECT a.id, b.name FROM users a, orders b WHERE a.id = b.user_id";
        let (stmt, analyzed, catalog, annotations) = make_ctx_parts(sql);
        let ctx = make_ctx(sql, &stmt, &analyzed, &catalog, &annotations);
        let hits = match_cartesian_join(&ctx, &toml::Table::new());
        assert!(hits.is_empty());
    }

    #[test]
    fn fires_on_cross_join() {
        let sql = "SELECT a.id, b.name FROM users a CROSS JOIN orders b";
        let (stmt, analyzed, catalog, annotations) = make_ctx_parts(sql);
        let ctx = make_ctx(sql, &stmt, &analyzed, &catalog, &annotations);
        let hits = match_cartesian_join(&ctx, &toml::Table::new());
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].bindings.get("msg").map(|s| s.as_str()),
            Some(MSG_UNCONSTRAINED_JOIN)
        );
    }

    fn hits_for(sql: &str) -> Vec<MatcherHit> {
        let (stmt, analyzed, catalog, annotations) = make_ctx_parts(sql);
        let ctx = make_ctx(sql, &stmt, &analyzed, &catalog, &annotations);
        match_cartesian_join(&ctx, &toml::Table::new())
    }

    /// A join to a set-returning function expands each row; it is not a
    /// cartesian product, however the join is spelled.
    #[test]
    fn no_match_on_join_to_a_lateral_set_returning_function() {
        for sql in [
            "SELECT ca.id FROM facts p JOIN jsonb_to_recordset(p.causes) AS allocation(id text, amount integer) ON true \
             JOIN causes ca ON ca.id = allocation.id",
            "SELECT ca.id FROM facts p, LATERAL jsonb_to_recordset(p.causes) AS allocation(id text, amount integer) \
             JOIN causes ca ON ca.id = allocation.id",
            "SELECT ca.id FROM facts p CROSS JOIN LATERAL jsonb_to_recordset(p.causes) AS allocation(id text, amount integer) \
             JOIN causes ca ON ca.id = allocation.id",
            "SELECT p.id, t.tag FROM posts p CROSS JOIN unnest(p.tags) AS t(tag)",
            "SELECT p.id, x.n FROM posts p, generate_series(1, p.count) AS x(n)",
        ] {
            assert!(hits_for(sql).is_empty(), "{sql}: {:?}", hits_for(sql));
        }
    }

    #[test]
    fn no_match_on_lateral_subquery_referencing_an_earlier_item() {
        let sql = "SELECT u.id, o.id FROM users u CROSS JOIN LATERAL \
                   (SELECT id FROM orders WHERE orders.user_id = u.id LIMIT 1) o";
        assert!(hits_for(sql).is_empty(), "{:?}", hits_for(sql));
    }

    #[test]
    fn fires_on_lateral_subquery_referencing_nothing_earlier() {
        let sql = "SELECT u.id, o.id FROM users u CROSS JOIN LATERAL (SELECT id FROM orders) o";
        let hits = hits_for(sql);
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].bindings.get("msg").map(|s| s.as_str()),
            Some(MSG_UNCONSTRAINED_JOIN)
        );
    }

    #[test]
    fn fires_on_comma_from_with_two_tables_beside_a_function() {
        let hits = hits_for("SELECT 1 FROM users a, orders b, unnest(a.tags) AS t(tag)");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].bindings.get("msg").map(|s| s.as_str()), Some(MSG_COMMA_FROM));
    }

    const SCHEMA: &str = "CREATE TABLE users (id integer PRIMARY KEY, email text, team_id integer);
         CREATE TABLE orders (id integer PRIMARY KEY, user_id integer, total integer);
         CREATE TABLE posts (id integer PRIMARY KEY, tags text[], count integer, body xml);";

    fn assert_unconstrained_join(sql: &str) {
        let hits = hits_for(sql);
        assert_eq!(hits.len(), 1, "{sql}: {hits:?}");
        assert_eq!(
            hits[0].bindings.get("msg").map(|s| s.as_str()),
            Some(MSG_UNCONSTRAINED_JOIN),
            "{sql}"
        );
    }

    /// A function whose arguments reference nothing earlier returns the same
    /// set for every row: joining it is a real cartesian product.
    #[test]
    fn fires_on_join_to_an_independent_set_returning_function() {
        assert_unconstrained_join("SELECT u.id, n FROM users u CROSS JOIN generate_series(1, 1000000) AS g(n)");
        assert_unconstrained_join("SELECT u.id FROM users u JOIN unnest(ARRAY[1, 2, 3]) AS t(x) ON true");
        let hits = hits_for("SELECT u.id, n FROM users u, generate_series(1, 1000000) AS g(n)");
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].bindings.get("msg").map(|s| s.as_str()), Some(MSG_COMMA_FROM));
    }

    /// An unqualified column in a function's arguments can only come from an
    /// earlier item.
    #[test]
    fn no_match_on_function_with_an_unqualified_earlier_column() {
        for sql in [
            "SELECT id, tag FROM posts CROSS JOIN unnest(tags) AS t(tag)",
            "SELECT id, n FROM posts, generate_series(1, count) AS g(n)",
        ] {
            assert!(hits_for(sql).is_empty(), "{sql}: {:?}", hits_for(sql));
        }
    }

    #[test]
    fn xmltable_follows_the_same_rule() {
        assert!(
            hits_for("SELECT x.a FROM posts p CROSS JOIN XMLTABLE('/r' PASSING p.body COLUMNS a integer PATH 'a') x")
                .is_empty()
        );
        assert_unconstrained_join(
            "SELECT x.a FROM posts p CROSS JOIN XMLTABLE('/r' PASSING '<r><a>1</a></r>' COLUMNS a integer PATH 'a') x",
        );
    }

    /// `team_id` is not a column of `orders`, so it resolves to `users`.
    #[test]
    fn no_match_on_lateral_subquery_with_an_unqualified_earlier_column() {
        let sql = "SELECT u.id, o.total FROM users u CROSS JOIN LATERAL \
                   (SELECT total FROM orders WHERE user_id = team_id LIMIT 1) o";
        assert!(hits_for(sql).is_empty(), "{:?}", hits_for(sql));
    }

    /// `id` is a column of `orders` itself, so it does not reach `users`.
    #[test]
    fn fires_on_lateral_subquery_whose_unqualified_column_resolves_inside() {
        assert_unconstrained_join(
            "SELECT u.id, o.total FROM users u CROSS JOIN LATERAL (SELECT total FROM orders WHERE id = 1) o",
        );
        // A select-list alias is not an outer column either.
        assert_unconstrained_join(
            "SELECT u.id, o.n FROM users u CROSS JOIN LATERAL (SELECT count(*) AS team_id FROM orders ORDER BY team_id) o",
        );
    }

    /// With no catalog entry for the inner item, an unqualified column may be
    /// its own, so it is not taken as a reference.
    #[test]
    fn fires_on_lateral_subquery_over_an_item_with_unknown_columns() {
        assert_unconstrained_join(
            "SELECT u.id FROM users u CROSS JOIN LATERAL (SELECT 1 FROM (VALUES (1)) v WHERE team_id = 1) o",
        );
    }

    /// The subquery's own `u` shadows the outer `u`.
    #[test]
    fn fires_on_lateral_subquery_whose_alias_shadows_an_earlier_item() {
        assert_unconstrained_join("SELECT x.id FROM users u CROSS JOIN LATERAL (SELECT u.id FROM users u) x");
    }

    #[test]
    fn items_inside_an_unaliased_nested_join_are_visible_later() {
        let sql = "SELECT t.tag FROM (posts p JOIN users u ON u.id = p.id) CROSS JOIN unnest(p.tags) AS t(tag)";
        assert!(hits_for(sql).is_empty(), "{:?}", hits_for(sql));
    }
}
