//! Matcher `"cartesian_join"` — SC-SEC08 cartesian-join.
//!
//! No `matcher_args`.  Emits empty `MatcherHit` for each cartesian-product
//! shape detected: two messages are possible (comma-FROM and
//! ON-true/CROSS JOIN).  The message field in the TOML carries the
//! comma-FROM variant; the ON-true/CROSS JOIN variant has its own message.
//!
//! The baseline output includes only the comma-FROM message for the smoke
//! fixture, so we emit two distinct MatcherHits for the two shapes — but the
//! TOML message template is shared.  To keep output byte-identical we emit
//! `MatcherHit`s with a `shape` binding that the message template can use,
//! OR we keep both messages hard-coded by emitting pre-rendered strings.
//!
//! The existing rule emits two different message strings for the two cases.
//! The smoke fixture only triggers the comma-FROM shape.  To keep output
//! byte-identical while using a single message template, we need two separate
//! TOML rules — or we include both messages inside one matcher by varying the
//! binding.  The TOML approach uses a `msg` binding for the full text.
//!
//! Decision: emit `MatcherHit::with_binding("msg", <full_message>)` and use
//! `{msg}` as the TOML message template.  This is the cleanest approach that
//! doesn't require two separate TOML rules.

use std::ops::ControlFlow;

use sqlparser::ast::{
    Expr, JoinConstraint, JoinOperator, Query, SetExpr, Statement, TableFactor, Value, ValueWithSpan, visit_expressions,
};

use crate::audit::registry::MatcherHit;
use crate::types::LintContext;

const MSG_COMMA_FROM: &str = "comma-separated FROM with no WHERE — this is a cartesian product";
const MSG_UNCONSTRAINED_JOIN: &str = "unconstrained join (ON true / CROSS JOIN) — produces a cartesian product";

pub fn match_cartesian_join(ctx: &LintContext<'_>, _args: &toml::Table) -> Vec<MatcherHit> {
    let mut hits = Vec::new();
    if let Statement::Query(q) = ctx.stmt {
        walk_set_expr(&q.body, &mut hits);
    }
    hits
}

fn walk_set_expr(set_expr: &SetExpr, hits: &mut Vec<MatcherHit>) {
    match set_expr {
        SetExpr::Select(select) => {
            // Names of the FROM items seen so far, which a later LATERAL item
            // may reference.
            let mut earlier: Vec<String> = Vec::new();
            let mut independent_items = 0;
            let mut join_hits = Vec::new();
            for twj in &select.from {
                if !is_row_expansion(&twj.relation, &earlier) {
                    independent_items += 1;
                }
                earlier.extend(relation_name(&twj.relation));
                for join in &twj.joins {
                    if join_is_unconstrained(&join.join_operator) && !is_row_expansion(&join.relation, &earlier) {
                        join_hits.push(MatcherHit::with_binding("msg", MSG_UNCONSTRAINED_JOIN));
                    }
                    earlier.extend(relation_name(&join.relation));
                }
            }
            if independent_items > 1 && select.selection.is_none() {
                hits.push(MatcherHit::with_binding("msg", MSG_COMMA_FROM));
            }
            hits.extend(join_hits);
        }
        SetExpr::Query(q) => walk_set_expr(&q.body, hits),
        SetExpr::SetOperation { left, right, .. } => {
            walk_set_expr(left, hits);
            walk_set_expr(right, hits);
        }
        _ => {}
    }
}

/// Whether a FROM item is evaluated per row of the items before it rather
/// than joined to them as an independent set, so an `ON true`, `CROSS JOIN`
/// or comma join to it expands rows instead of multiplying them. A function
/// in FROM is implicitly LATERAL in PostgreSQL; a LATERAL subquery counts
/// when it references an earlier FROM item.
fn is_row_expansion(factor: &TableFactor, earlier: &[String]) -> bool {
    match factor {
        TableFactor::Table { args: Some(_), .. }
        | TableFactor::Function { .. }
        | TableFactor::TableFunction { .. }
        | TableFactor::UNNEST { .. }
        | TableFactor::JsonTable { .. }
        | TableFactor::OpenJsonTable { .. }
        | TableFactor::XmlTable { .. } => true,
        TableFactor::Derived {
            lateral: true,
            subquery,
            ..
        } => references_any(subquery, earlier),
        _ => false,
    }
}

/// The name a FROM item is referenced by: its alias, else its table name.
fn relation_name(factor: &TableFactor) -> Option<String> {
    let alias = match factor {
        TableFactor::Table { alias, name, .. } => {
            return Some(match alias {
                Some(alias) => alias.name.value.to_lowercase(),
                None => name.0.last()?.as_ident()?.value.to_lowercase(),
            });
        }
        TableFactor::Derived { alias, .. }
        | TableFactor::Function { alias, .. }
        | TableFactor::TableFunction { alias, .. }
        | TableFactor::UNNEST { alias, .. }
        | TableFactor::NestedJoin { alias, .. } => alias.as_ref(),
        _ => None,
    };
    alias.map(|alias| alias.name.value.to_lowercase())
}

/// Whether `query` uses a column qualified by one of `names`.
fn references_any(query: &Query, names: &[String]) -> bool {
    let found = visit_expressions(query, |expr| match expr {
        Expr::CompoundIdentifier(parts)
            if parts.len() >= 2 && names.contains(&parts[parts.len() - 2].value.to_lowercase()) =>
        {
            ControlFlow::Break(())
        }
        _ => ControlFlow::Continue(()),
    });
    found.is_break()
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
        let catalog = Catalog::from_ddl(&[]).unwrap();
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
}
