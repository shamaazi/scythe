mod builtins;
mod expressions;
mod function_body;
mod helpers;
mod naming;
mod params;
mod query_fingerprint;
mod scope;
mod statements;
mod type_conversion;
mod types;

pub(crate) use function_body::{BodyArgument, analyze_function_body};
pub use type_conversion::sql_type_to_neutral;
pub use types::{
    AnalyzedColumn, AnalyzedParam, AnalyzedQuery, CompositeFieldInfo, CompositeInfo, EnumInfo, GroupByConfig,
    NestedFieldInfo, NestedStructInfo,
};

use std::collections::VecDeque;

use ahash::{AHashMap, AHashSet};

use crate::catalog::Catalog;
use crate::errors::SqlkitError;
use crate::parser::{Query, QueryCommand};

use helpers::{
    detect_select_star_source, disambiguate_duplicate_names, find_nested_placeholder_id, reject_unresolved_params,
};
use types::Analyzer;

pub fn analyze(catalog: &Catalog, query: &Query) -> Result<AnalyzedQuery, SqlkitError> {
    let mut analyzer = Analyzer {
        catalog,
        params: Vec::new(),
        ctes: AHashMap::new(),
        type_errors: Vec::new(),
        pending_nested: Vec::new(),
        next_nested_id: 0,
        outer_sources: Vec::new(),
    };

    let (columns, _) = analyzer.analyze_statement(&query.stmt)?;
    register_unvisited_placeholders(&mut analyzer, &query.stmt);

    if let Some(err_msg) = analyzer.type_errors.first() {
        return Err(SqlkitError::type_mismatch(err_msg.clone()));
    }

    let mut columns = columns;
    for col in &mut columns {
        if query.annotations.nullable_overrides.iter().any(|o| o == &col.name) {
            col.nullable = true;
        }
        if query.annotations.nonnull_overrides.iter().any(|o| o == &col.name) {
            col.nullable = false;
        }
        if let Some(mapping) = query.annotations.json_mappings.iter().find(|m| m.column == col.name) {
            col.neutral_type = format!("json_typed<{}>", mapping.rust_type);
        }
    }

    // ~keep Runs after the annotation loop (a `@json` mapping is a legitimate way to
    // give such a column a type), after every UNION arm has already been widened, and
    // after a derived table's/CTE's columns have been folded back through scope --
    // `AnalyzedColumn::untyped_literal`'s doc comment traces exactly which of those
    // boundaries clear the flag (a UNION arm where either side resolved a real type)
    // and which carry it through (both UNION arms untyped; any derived-table/CTE
    // projection). `jsonb_each` and other set-returning/composite columns are never
    // tainted at all: they reach `neutral_type: "unknown"` through `infer_function_type`,
    // a different `TypeInfo` constructor than the two `Expr::Value` arms that set
    // `untyped_literal`. See `AnalyzedColumn::untyped_literal`.
    for col in &columns {
        if col.untyped_literal && col.neutral_type == "unknown" {
            return Err(SqlkitError::type_mismatch(format!(
                "query \"{}\": column \"{}\" is a bare parameter or NULL literal with no CAST, comparison, \
                 COALESCE, or other typed context -- sqlkit cannot infer its type; add an explicit CAST, e.g. \
                 CAST(? AS <type>)",
                query.name, col.name
            )));
        }
    }

    for col in &mut columns {
        col.constraints = col
            .origin
            .as_ref()
            .and_then(|origin| catalog.column_constraints(&origin.relation, &origin.column));
        col.base_column = col
            .origin
            .as_ref()
            .map(|origin| catalog.base_column(&origin.relation, &origin.column));
    }

    // ~keep Phase 2 of nested-struct naming (see `types::PendingNestedStruct`):
    // columns now have their final names (aliases and overrides applied),
    // so each `__nested__{id}` placeholder pushed during expression
    // inference (phase 1) can be resolved to a real struct name.
    let nested_structs = resolve_nested_struct_names(
        catalog,
        &query.name,
        std::mem::take(&mut analyzer.pending_nested),
        &mut columns,
    );

    analyzer.params.sort_by_key(|p| p.position);
    analyzer.params.dedup_by_key(|p| p.position);

    let mut params: Vec<AnalyzedParam> = analyzer
        .params
        .iter()
        .map(|p| {
            // An explicit `@param $N name` wins over the inferred name, which
            // wins over the `pN` fallback.
            let doc = query
                .annotations
                .positional_param_docs
                .iter()
                .find(|doc| doc.position == p.position);
            let name = doc
                .map(|doc| doc.name.clone())
                .unwrap_or_else(|| p.name.clone().unwrap_or_else(|| format!("p{}", p.position)));
            let neutral_type = p.neutral_type.clone().unwrap_or_else(|| "unknown".to_string());
            AnalyzedParam {
                name,
                neutral_type,
                nullable: p.nullable || doc.is_some_and(|doc| doc.nullable),
                position: p.position,
                source_relation: p.source_relation.clone(),
                constraints: written_constraints(catalog, &p.written_to),
                base_column: written_base_column(catalog, &p.written_to),
            }
        })
        .collect();

    check_param_names(query, &params)?;
    reject_unresolved_params(&params)?;

    for opt_name in &query.annotations.optional_params {
        for p in &mut params {
            if p.name == *opt_name {
                p.nullable = true;
            }
        }
    }

    for opt_name in &query.annotations.optional_params {
        if !params.iter().any(|p| p.name == *opt_name) {
            return Err(SqlkitError::invalid_annotation(format!(
                "@optional references unknown parameter '{}'",
                opt_name
            )));
        }
    }

    // Shared with the result-column path in `analyze_select` /
    // `analyze_returning` -- one rule for every identifier sqlkit generates
    // from a user-supplied name (#175).
    disambiguate_duplicate_names(params.iter_mut().map(|p| &mut p.name));

    let source_table = detect_select_star_source(&query.stmt);

    // ~keep Every neutral type that a generated file must be able to name. Nested
    // struct fields belong here alongside the top-level columns and params:
    // a `json_agg(o.*)` over a table with an enum or composite column puts
    // that type in the *nested* struct's field list and nowhere else, so
    // scanning only `columns`/`params` emits `pub status: OrderStatus` with
    // no `enum OrderStatus` in the file — E0412 in Rust, an undefined type
    // in TypeScript.
    let nested_field_types: Vec<&str> = nested_structs
        .iter()
        .flat_map(|nested| nested.fields.iter())
        .map(|field| field.neutral_type.as_str())
        .collect();

    let mut composites = Vec::new();
    let mut seen_composites: AHashSet<String> = AHashSet::new();
    // Field types discovered while walking composites, fed into the enum scan
    // below so `CREATE TYPE outer AS (status order_status)` -- an enum reachable
    // only through a composite field -- is not left with the same gap this
    // recursion exists to close.
    let mut composite_field_types: Vec<String> = Vec::new();
    // ~keep `params` must feed this worklist the same way `columns` does (#225):
    // a composite bound only as a query parameter -- e.g. an `INSERT` whose
    // composite column never appears in `RETURNING` -- never reached
    // `analyzed.composites` before this chain, so codegen's
    // `pg_composite_bind_expr` silently fell back to binding the whole object
    // instead of emitting `ROW(a, b)::type_name`. The enum scan below already
    // chains `params`; this brings the composite worklist in line with it.
    let mut composite_worklist: VecDeque<String> = columns
        .iter()
        .map(|c| c.neutral_type.as_str())
        .chain(params.iter().map(|p| p.neutral_type.as_str()))
        .chain(nested_field_types.iter().copied())
        .filter_map(|nt| nt.strip_prefix("composite::"))
        .filter(|name| seen_composites.insert((*name).to_string()))
        .map(str::to_string)
        .collect();

    // ~keep A composite field can itself name another composite --
    // `CREATE TYPE outer AS (inner_field inner_type)` -- so walking only the
    // query's own columns/params/nested-struct fields misses `inner` entirely:
    // selecting `outer` alone would reference `Inner` in generated code with no
    // definition ever emitted.
    // `seen_composites` both dedupes a diamond -- two fields naming the same
    // nested composite -- down to one definition, and stops a true cycle from
    // looping forever; PostgreSQL rejects a real composite cycle at `CREATE
    // TYPE` time, but nothing here should assume that has actually been
    // enforced against every catalog this analyzer might see.
    while let Some(comp_name) = composite_worklist.pop_front() {
        let Some(comp) = catalog.get_composite(&comp_name) else {
            continue;
        };
        let fields: Vec<CompositeFieldInfo> = comp
            .fields
            .iter()
            .map(|f| CompositeFieldInfo {
                name: f.name.clone(),
                neutral_type: sql_type_to_neutral(&f.sql_type, catalog).into_owned(),
                nullable: f.nullable,
            })
            .collect();
        for field in &fields {
            composite_field_types.push(field.neutral_type.clone());
            if let Some(nested_name) = field.neutral_type.strip_prefix("composite::")
                && seen_composites.insert(nested_name.to_string())
            {
                composite_worklist.push_back(nested_name.to_string());
            }
        }
        composites.push(CompositeInfo {
            sql_name: comp_name,
            fields,
        });
    }

    let mut enums = Vec::new();
    let mut seen_enums: AHashSet<String> = AHashSet::new();
    let all_types: Vec<&str> = columns
        .iter()
        .map(|c| c.neutral_type.as_str())
        .chain(params.iter().map(|p| p.neutral_type.as_str()))
        .chain(nested_field_types.iter().copied())
        .chain(composite_field_types.iter().map(String::as_str))
        .collect();
    for &nt in &all_types {
        // ~keep `array<enum::x>` / `nullable<enum::x>` (an enum array column, or an
        // enum widened nullable by an outer join) must unwrap to the same `enum::x`
        // an unwrapped column resolves to -- otherwise this loop never inserts that
        // enum's `EnumInfo` into `enums`, and `generate_enum_defs_via_backend`
        // (sqlkit-codegen), which independently recognizes the type as reachable via
        // its own container-unwrapping, falls back to an empty-variants stub instead
        // of finding it here.
        if let Some(enum_name) = unwrap_neutral_containers(nt).strip_prefix("enum::")
            && seen_enums.insert(enum_name.to_string())
            && let Some(enum_type) = catalog.get_enum(enum_name)
        {
            enums.push(EnumInfo {
                sql_name: enum_name.to_string(),
                values: enum_type.values.clone(),
            });
        }
    }

    let group_by = if query.command == QueryCommand::Grouped {
        if let Some(ref group_by_value) = query.annotations.group_by {
            let (table, key_column) = if let Some(dot_pos) = group_by_value.find('.') {
                (
                    group_by_value[..dot_pos].to_string(),
                    group_by_value[dot_pos + 1..].to_string(),
                )
            } else {
                return Err(SqlkitError::invalid_annotation(format!(
                    "@group_by must be in 'table.column' format, got: {}",
                    group_by_value
                )));
            };

            let parent_table_columns: Vec<String> = catalog
                .get_table(&table)
                .map(|t| t.columns.iter().map(|c| c.name.clone()).collect())
                .unwrap_or_default();

            let mut parent_columns = Vec::new();
            let mut child_columns = Vec::new();

            for col in &columns {
                if parent_table_columns.contains(&col.name) {
                    parent_columns.push(col.clone());
                } else {
                    child_columns.push(col.clone());
                }
            }

            // This split matches projected column names against the parent
            // table's catalog columns, so anything that stops a projected
            // name from being the catalog name -- an alias in `@group_by`
            // (`@group_by u.id`, where `u` is not a table), a table that does
            // not exist, or a name the duplicate-column pass had to suffix
            // (`u.id`/`o.id` -> `id_1`/`id_2`, see
            // `disambiguate_duplicate_names`) -- silently sends every column
            // to the child struct and leaves the parent struct empty. That
            // generates a parent row type with no fields at exit 0, so it is
            // reported here instead.
            if parent_columns.is_empty() {
                return Err(SqlkitError::invalid_annotation(format!(
                    "@group_by {group_by_value} matched none of the query's result columns, so the \
                     parent row type would have no fields -- name the table as it appears in the \
                     schema (not a query alias), and make sure the projection selects its columns \
                     under their own names"
                )));
            }

            Some(types::GroupByConfig {
                table,
                key_column,
                parent_columns,
                child_columns,
            })
        } else {
            None
        }
    } else {
        None
    };

    Ok(AnalyzedQuery {
        name: query.name.clone(),
        command: query.command.clone(),
        sql: query.sql.clone(),
        columns,
        params,
        deprecated: query.annotations.deprecated.clone(),
        description: query.annotations.description.clone(),
        source_table,
        composites,
        enums,
        optional_params: query.annotations.optional_params.clone(),
        group_by,
        custom: query.annotations.custom.clone(),
        nested_structs,
    })
}

/// Register every `$N` the statement holds that inference never reached, so
/// a parameter is never silently missing from the signature while the SQL
/// still binds it. Such a parameter has no type until something gives it one;
/// codegen then reports it rather than generating a call with too few values.
fn register_unvisited_placeholders(analyzer: &mut Analyzer<'_>, stmt: &sqlparser::ast::Statement) {
    let mut positions = Vec::new();
    let _ = sqlparser::ast::visit_expressions(stmt, |expr| {
        if let sqlparser::ast::Expr::Value(vws) = expr
            && let Some(position) = helpers::value_is_placeholder(vws).and_then(helpers::parse_placeholder)
        {
            positions.push(position);
        }
        std::ops::ControlFlow::<()>::Continue(())
    });
    for position in positions {
        analyzer.register_param(position, None, None, false, None);
    }
}

/// The constraints a parameter written into `columns` must satisfy: every
/// column's, when it is written into several.
fn written_constraints(
    catalog: &Catalog,
    columns: &[crate::catalog::ColumnOrigin],
) -> Option<crate::constraints::ValueConstraints> {
    let mut resolved = columns
        .iter()
        .filter_map(|origin| catalog.column_constraints(&origin.relation, &origin.column));
    let mut constraints = resolved.next()?;
    for other in resolved {
        constraints.intersect(&other);
    }
    Some(constraints)
}

/// The one table column a parameter written into `columns` is written into,
/// through views; `None` when there is none or they differ.
fn written_base_column(
    catalog: &Catalog,
    columns: &[crate::catalog::ColumnOrigin],
) -> Option<crate::catalog::ColumnOrigin> {
    let mut bases = columns
        .iter()
        .map(|origin| catalog.base_column(&origin.relation, &origin.column));
    let base = bases.next()?;
    bases.all(|other| other == base).then_some(base)
}

/// Reject a parameter name that names no parameter.
///
/// A name for an absent position is always a mistake (a renumbered query, a
/// typo), and would otherwise be dropped without a word. `@param $N name`
/// may name any subset of the parameters; `sqlkit migrate` relies on that.
fn check_param_names(query: &Query, params: &[AnalyzedParam]) -> Result<(), SqlkitError> {
    let docs = &query.annotations.positional_param_docs;
    if let Some(doc) = docs
        .iter()
        .find(|doc| !params.iter().any(|p| p.position == doc.position))
    {
        return Err(SqlkitError::invalid_annotation(format!(
            "query \"{}\": `{}` names ${}, but the query has no ${}",
            query.name, doc.name, doc.position, doc.position
        )));
    }
    Ok(())
}

/// Strip any number of `array<...>` / `nullable<...>` container wrappers from a
/// neutral type, returning the innermost type.
///
/// Mirrors `sqlkit_codegen::unwrap_containers`, duplicated rather than shared because
/// sqlkit-core cannot depend on sqlkit-codegen: that function's own enum/composite
/// reachability checks already unwrap both wrappers, so the caller here has to strip the
/// same ones or it disagrees with codegen about what `enum::x` reachable means. Matching
/// only the bare `"enum::x"` string misses `array<enum::x>` -- e.g. an enum array column --
/// entirely; `nullable<...>` is stripped alongside it for the same reason `array<...>` is,
/// even though no analyzer output currently wraps an `enum::`/`composite::` type in it
/// directly.
fn unwrap_neutral_containers(neutral: &str) -> &str {
    let mut current = neutral;
    loop {
        if let Some(inner) = current.strip_prefix("array<").and_then(|r| r.strip_suffix('>')) {
            current = inner.trim();
        } else if let Some(inner) = current.strip_prefix("nullable<").and_then(|r| r.strip_suffix('>')) {
            current = inner.trim();
        } else {
            return current;
        }
    }
}

/// Phase 2 of nested-struct naming. Walks `columns` for `__nested__{id}`
/// placeholders left by phase-1 expression inference, assigns each a final
/// name (deduping identical shapes, suffixing collisions against the
/// catalog or against a differently-shaped struct), substitutes the
/// placeholder with the resulting PascalCase name in place, and returns the
/// resolved [`NestedStructInfo`] list for `AnalyzedQuery::nested_structs`.
///
fn resolve_nested_struct_names(
    catalog: &Catalog,
    query_name: &str,
    pending: Vec<types::PendingNestedStruct>,
    columns: &mut [AnalyzedColumn],
) -> Vec<NestedStructInfo> {
    if pending.is_empty() {
        return Vec::new();
    }

    let snake_query = naming::to_snake_case(query_name).into_owned();
    let mut resolved: AHashMap<u32, String> = AHashMap::new();
    let mut structs: Vec<NestedStructInfo> = Vec::new();

    for column in columns.iter_mut() {
        while let Some(id) = find_nested_placeholder_id(&column.neutral_type) {
            let final_name = if let Some(name) = resolved.get(&id) {
                name.clone()
            } else {
                let fields = pending
                    .iter()
                    .find(|p| p.id == id)
                    .map(|p| p.fields.clone())
                    .unwrap_or_default();
                let base = format!("{snake_query}_row_{}", column.name);
                let name = assign_nested_struct_name(&base, fields, catalog, &mut structs);
                resolved.insert(id, name.clone());
                name
            };

            let pascal = naming::to_pascal_case(&final_name);
            column.neutral_type = column.neutral_type.replacen(&format!("__nested__{id}"), &pascal, 1);
        }
    }

    structs
}

/// Find a free name for a nested struct, starting from `base` (already
/// snake_case) and trying `{base}_1`, `{base}_2`, ... in order.
///
/// Two independent collision sources are checked per candidate: a catalog
/// composite or enum sharing the name always forces the next suffix; a
/// same-named struct already assigned earlier in this `analyze()` call is
/// reused as-is when its field shape is identical (two output columns can
/// legitimately produce the same nested shape) and otherwise also forces
/// the next suffix.
fn assign_nested_struct_name(
    base: &str,
    fields: Vec<NestedFieldInfo>,
    catalog: &Catalog,
    structs: &mut Vec<NestedStructInfo>,
) -> String {
    let mut suffix: u32 = 0;
    loop {
        let candidate = if suffix == 0 {
            base.to_string()
        } else {
            format!("{base}_{suffix}")
        };

        if let Some(existing) = structs.iter().find(|s| s.name == candidate) {
            if existing.fields == fields {
                return candidate;
            }
            suffix += 1;
            continue;
        }

        if catalog.get_composite(&candidate).is_none() && catalog.get_enum(&candidate).is_none() {
            structs.push(NestedStructInfo {
                name: candidate.clone(),
                fields,
            });
            return candidate;
        }

        suffix += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_query;

    fn make_catalog() -> Catalog {
        Catalog::from_ddl(&[
            "CREATE TABLE users (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                email VARCHAR(255) NOT NULL,
                age INTEGER,
                active BOOLEAN NOT NULL DEFAULT true,
                created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                bio TEXT,
                score NUMERIC
            );",
            "CREATE TABLE posts (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                title TEXT NOT NULL,
                body TEXT,
                published BOOLEAN NOT NULL DEFAULT false,
                created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
            );",
            "CREATE TABLE comments (
                id SERIAL PRIMARY KEY,
                post_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
            );",
        ])
        .unwrap()
    }

    #[test]
    fn test_simple_select() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetUser
-- @returns :one
SELECT id, name, email FROM users WHERE id = $1;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();
        assert_eq!(result.columns.len(), 3);
        assert_eq!(result.columns[0].name, "id");
        assert_eq!(result.columns[0].neutral_type, "int32");
        assert!(!result.columns[0].nullable);
        assert_eq!(result.columns[1].name, "name");
        assert_eq!(result.columns[1].neutral_type, "string");
        assert_eq!(result.columns[2].name, "email");
        assert_eq!(result.columns[2].neutral_type, "string");

        assert_eq!(result.params.len(), 1);
        assert_eq!(result.params[0].position, 1);
        assert_eq!(result.params[0].neutral_type, "int32");
        assert_eq!(result.params[0].name, "id");
    }

    #[test]
    fn test_select_star() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name ListUsers
-- @returns :many
SELECT * FROM users;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();
        assert_eq!(result.columns.len(), 8);
    }

    /// #189: a `column = "table.col"` type override was a silent no-op for any
    /// projection other than `SELECT *`, because only the wildcard-expansion path
    /// carried a source table and the codegen matcher had nothing to bind an
    /// explicit select list's columns to. Before `source_relation` was threaded
    /// through the plain-identifier resolution path (`resolve_column_in_scope`),
    /// every `AnalyzedColumn` produced by an explicit select list left this field
    /// at its `Default` value (`None`) -- indistinguishable from a computed
    /// expression with no owning relation. This pins that an explicit list now
    /// carries the same per-column relation a `SELECT *` expansion always did.
    #[test]
    fn test_source_relation_populated_for_explicit_select_list() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetUser
-- @returns :one
SELECT id, name, email FROM users WHERE id = $1;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();
        assert_eq!(result.columns[0].source_relation.as_deref(), Some("users"));
        assert_eq!(result.columns[1].source_relation.as_deref(), Some("users"));
        assert_eq!(result.columns[2].source_relation.as_deref(), Some("users"));
    }

    /// A column with no single owning relation -- here, an aggregate function
    /// result -- must report `source_relation: None` rather than guessing the
    /// query's only table. A qualified override naming this column is a config
    /// error the caller must diagnose, not something this field should paper
    /// over by pretending the computed value "belongs" to a table.
    #[test]
    fn test_source_relation_none_for_computed_expression() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name UserCount
-- @returns :one
SELECT COUNT(*) as total FROM users;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();
        assert_eq!(result.columns[0].source_relation, None);
    }

    /// A qualified override is documented as `"table.column"` using the real
    /// schema table name (see `website/src/content/docs/guide/custom-types.md`),
    /// not the query's local alias. `source_relation` must resolve to `users`/
    /// `posts` here, not the join aliases `u`/`p` -- otherwise a correctly wired
    /// matcher would still silently fail on any aliased join.
    #[test]
    fn test_source_relation_uses_real_table_name_not_join_alias() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name UsersWithPosts
-- @returns :many
SELECT u.id, p.title FROM users u LEFT JOIN posts p ON u.id = p.user_id;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();
        assert_eq!(result.columns[0].source_relation.as_deref(), Some("users"));
        assert_eq!(result.columns[1].source_relation.as_deref(), Some("posts"));
    }

    /// Regression guard for the one path that already worked: `SELECT *`
    /// expansion must keep carrying a per-column source relation after the
    /// explicit-list path gained the same field.
    #[test]
    fn test_source_relation_still_populated_for_select_star() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name ListUsers
-- @returns :many
SELECT * FROM users;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();
        assert!(
            result
                .columns
                .iter()
                .all(|c| c.source_relation.as_deref() == Some("users"))
        );
    }

    /// `RETURNING` resolves its explicit column list through the same
    /// `infer_expr_type` -> `resolve_column_in_scope` path as a `SELECT` list, so
    /// it must carry the same per-column relation -- an override on an
    /// `INSERT ... RETURNING` column is just as real a use case as one on a
    /// `SELECT`.
    #[test]
    fn test_source_relation_populated_for_returning_explicit_column() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name CreateUser
-- @returns :one
INSERT INTO users (name, email) VALUES ($1, $2) RETURNING id, name, email;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();
        assert_eq!(result.columns[0].source_relation.as_deref(), Some("users"));
        assert_eq!(result.columns[1].source_relation.as_deref(), Some("users"));
        assert_eq!(result.columns[2].source_relation.as_deref(), Some("users"));
    }

    #[test]
    fn test_left_join_nullability() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name UsersWithPosts
-- @returns :many
SELECT u.id, u.name, p.title, p.body FROM users u LEFT JOIN posts p ON u.id = p.user_id;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();
        assert_eq!(result.columns.len(), 4);
        assert!(!result.columns[0].nullable);
        assert!(!result.columns[1].nullable);
        assert!(result.columns[2].nullable);
        assert!(result.columns[3].nullable);
    }

    /// A column the WHERE clause tests `IS NOT NULL` or compares, or an inner
    /// join's ON condition compares, holds a value in every row.
    #[test]
    fn should_narrow_columns_the_filters_prove_non_null() {
        let catalog = make_catalog();
        let nullable = |sql: &str| -> Vec<bool> {
            let query = parse_query(&format!("-- @name Q\n-- @returns :many\n{sql}")).unwrap();
            analyze(&catalog, &query)
                .unwrap()
                .columns
                .iter()
                .map(|c| c.nullable)
                .collect()
        };
        assert_eq!(
            nullable("SELECT bio, age, score FROM users WHERE bio IS NOT NULL AND (age > $1)"),
            [false, false, true]
        );
        assert!(!nullable("SELECT u.* FROM users u WHERE u.bio IS NOT NULL")[6]);
        assert!(
            nullable("SELECT * FROM users WHERE bio IS NOT NULL")[6],
            "a whole-table SELECT * keeps the table model"
        );
        assert_eq!(
            nullable("SELECT p.body, u.age FROM posts p JOIN users u ON u.age = p.user_id"),
            [true, false]
        );
        assert_eq!(
            nullable("SELECT u.bio FROM users u LEFT JOIN posts p ON p.body = u.bio"),
            [true],
            "an outer join's condition filters nothing"
        );
        assert_eq!(
            nullable("SELECT bio FROM users WHERE bio IS NOT NULL OR age > 1"),
            [true],
            "only conjuncts count"
        );
        assert_eq!(
            nullable("SELECT bio FROM users WHERE bio IS NOT NULL GROUP BY ROLLUP (bio)"),
            [true],
            "a subtotal row nulls the grouped column"
        );
        assert_eq!(
            nullable("SELECT u.age FROM users u JOIN posts p ON p.user_id = u.age RIGHT JOIN comments c ON true"),
            [true],
            "a later right join null-extends it again"
        );
    }

    #[test]
    fn test_aggregate_functions() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name UserStats
-- @returns :one
SELECT COUNT(*) as total, AVG(age) as avg_age, MAX(score) as max_score FROM users;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();
        assert_eq!(result.columns.len(), 3);
        assert_eq!(result.columns[0].neutral_type, "int64");
        assert!(!result.columns[0].nullable);
        assert_eq!(result.columns[1].neutral_type, "decimal");
        assert!(result.columns[1].nullable);
        assert!(result.columns[2].nullable);
    }

    #[test]
    fn test_insert_returning() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name CreateUser
-- @returns :one
INSERT INTO users (name, email) VALUES ($1, $2) RETURNING id, name, email;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();
        assert_eq!(result.columns.len(), 3);
        assert_eq!(result.columns[0].name, "id");
        assert_eq!(result.columns[0].neutral_type, "int32");

        assert_eq!(result.params.len(), 2);
        assert_eq!(result.params[0].name, "name");
        assert_eq!(result.params[0].neutral_type, "string");
        assert_eq!(result.params[1].name, "email");
        assert_eq!(result.params[1].neutral_type, "string");
    }

    /// `INSERT INTO t VALUES (...)` with no column list binds positionally to
    /// every column of the table in catalog order. Placeholders must be typed
    /// and named from that ordering, not dropped (regression: F2 — params in a
    /// column-list-less INSERT were silently lost).
    #[test]
    fn test_insert_without_column_list_binds_to_catalog_columns() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name CreateUserFull
-- @returns :exec
INSERT INTO users VALUES ($1, $2, $3, $4, $5, $6, $7, $8);",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();
        assert_eq!(result.params.len(), 8, "all 8 placeholders must be registered");
        let names: Vec<&str> = result.params.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            ["id", "name", "email", "age", "active", "created_at", "bio", "score"]
        );
        assert_eq!(result.params[0].neutral_type, "int32");
        assert_eq!(result.params[1].neutral_type, "string");
        assert_eq!(result.params[3].neutral_type, "int32");
        assert_eq!(result.params[4].neutral_type, "bool");
        assert_eq!(result.params[5].neutral_type, "datetime_tz");
        assert_eq!(result.params[7].neutral_type, "decimal");
        assert!(!result.params[1].nullable, "name is NOT NULL");
        assert!(result.params[3].nullable, "age is nullable");
        assert!(result.params[6].nullable, "bio is nullable");
    }

    /// When neither a column list nor a catalog entry is available, params in a
    /// column-list-less INSERT must still be registered with an inferred type
    /// rather than silently dropped.
    #[test]
    fn test_insert_without_column_list_unknown_table_registers_inferred_params() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name InsertNoSchema
-- @returns :exec
INSERT INTO t VALUES ($1, $2::text);",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();
        assert_eq!(result.params.len(), 2, "$1 and $2 must both be registered");
        assert_eq!(result.params[0].position, 1);
        assert_eq!(result.params[0].name, "p1");
        assert_eq!(result.params[1].position, 2);
        assert_eq!(result.params[1].neutral_type, "string", "$2::text must infer as string");
    }

    /// An explicit column list still names params even when the table has no
    /// catalog entry — only the type falls back to inference.
    #[test]
    fn test_insert_explicit_columns_unknown_table_keeps_declared_names() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name InsertNoSchemaCols
-- @returns :exec
INSERT INTO t (a, b) VALUES ($1, $2);",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();
        assert_eq!(result.params.len(), 2);
        assert_eq!(result.params[0].name, "a");
        assert_eq!(result.params[1].name, "b");
    }

    /// Placeholders nested inside function calls in INSERT VALUES must be
    /// collected (regression: F10 — the `_ => {}` arm swallowed them).
    #[test]
    fn test_insert_coalesce_param_collected() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name InsertBio
-- @returns :exec
INSERT INTO users (bio) VALUES (COALESCE($1, 'unknown'));",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();
        assert_eq!(result.params.len(), 1, "$1 inside COALESCE must be registered");
        assert_eq!(result.params[0].name, "bio");
        assert_eq!(result.params[0].neutral_type, "string");
        assert!(result.params[0].nullable, "bio is nullable");
    }

    /// A COALESCE argument may be NULL even when the column written is NOT
    /// NULL, and a cast does not hide the placeholder.
    #[test]
    fn should_infer_coalesce_placeholders_nullable_when_written_or_cast() {
        let catalog = make_catalog();
        for sql in [
            "INSERT INTO users (name, active) VALUES (coalesce($1, 'anonymous'), coalesce($2::boolean, true));",
            "UPDATE users SET name = coalesce($1, name), active = coalesce($2::boolean, active) WHERE id = $3;",
        ] {
            let query = parse_query(&format!("-- @name Write\n-- @returns :exec\n{sql}")).unwrap();
            let result = analyze(&catalog, &query).unwrap();
            let nullable: Vec<_> = result.params.iter().map(|p| p.nullable).collect();
            assert_eq!(nullable[..2], [true, true], "{sql}");
            assert_eq!(result.params[1].neutral_type, "bool", "{sql}");
        }
    }

    /// A searched CASE written into a column takes its result from the column
    /// type and its condition as a boolean.
    #[test]
    fn should_type_a_written_case_condition_as_boolean() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name SetBio
-- @returns :exec
UPDATE users SET bio = CASE WHEN $1 THEN $2 ELSE bio END WHERE id = $3;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();
        assert_eq!(result.params[0].neutral_type, "bool");
        assert_eq!(result.params[1].neutral_type, "string");
    }

    /// Placeholders inside CASE branches of INSERT VALUES must be collected.
    #[test]
    fn test_insert_case_param_collected() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name InsertName
-- @returns :exec
INSERT INTO users (name) VALUES (CASE WHEN $1 THEN 'x' ELSE 'y' END);",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();
        assert_eq!(result.params.len(), 1, "$1 inside CASE must be registered");
        assert_eq!(result.params[0].name, "name");
        assert_eq!(result.params[0].neutral_type, "bool", "a CASE condition is a boolean");
    }

    /// Placeholders nested in function calls in UPDATE SET must be collected.
    #[test]
    fn test_update_function_arg_param_collected() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name RenameUser
-- @returns :exec
UPDATE users SET name = LOWER(CONCAT($1, '_suffix')) WHERE id = $2;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();
        assert_eq!(result.params.len(), 2, "$1 in nested function args must be registered");
        assert_eq!(result.params[0].name, "name");
        assert_eq!(result.params[0].neutral_type, "string");
        assert_eq!(result.params[1].name, "id");
        assert_eq!(result.params[1].neutral_type, "int32");
    }

    #[test]
    fn test_coalesce_nullability() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetBio
-- @returns :one
SELECT COALESCE(bio, 'No bio') as bio FROM users WHERE id = $1;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();
        assert_eq!(result.columns[0].neutral_type, "string");
        assert!(!result.columns[0].nullable);
    }

    #[test]
    fn test_case_expression() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetStatus
-- @returns :many
SELECT name, CASE WHEN active THEN 'active' ELSE 'inactive' END as status FROM users;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();
        assert_eq!(result.columns[1].name, "status");
        assert_eq!(result.columns[1].neutral_type, "string");
        assert!(!result.columns[1].nullable);
    }

    #[test]
    fn test_nullif() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetScore
-- @returns :many
SELECT NULLIF(score, 0) as adjusted_score FROM users;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();
        assert_eq!(result.columns[0].neutral_type, "decimal");
        assert!(result.columns[0].nullable);
    }

    #[test]
    fn test_cast_expression() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetAgeText
-- @returns :many
SELECT CAST(age AS TEXT) as age_text FROM users;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();
        assert_eq!(result.columns[0].neutral_type, "string");
    }

    #[test]
    fn test_param_inside_derived_table_propagates() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name BucketCounts
-- @returns :many
SELECT b.bucket, count(*) AS n
FROM posts p
CROSS JOIN (SELECT $1::text AS bucket) b
GROUP BY 1;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();
        assert_eq!(
            result.params.len(),
            1,
            "$1 inside derived table must appear in analyzed.params; got {:?}",
            result.params
        );
        assert_eq!(result.params[0].position, 1);
        assert_eq!(result.params[0].neutral_type, "string");
    }

    // Task 3: @param $N name overrides the fallback pN name

    #[test]
    fn test_positional_param_name_override() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetUser
-- @returns :one
-- @param $1 user_id: the primary key
SELECT id, name FROM users WHERE id = $1;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();
        assert_eq!(result.params.len(), 1);
        assert_eq!(result.params[0].name, "user_id");
        assert_eq!(result.params[0].position, 1);
    }

    #[test]
    fn test_positional_param_override_does_not_affect_unrelated_params() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name UpdateUser
-- @returns :exec
-- @param $2 target_id
UPDATE users SET name = $1 WHERE id = $2;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();
        assert_eq!(result.params.len(), 2);
        assert_eq!(result.params[0].name, "name");
        assert_eq!(result.params[1].name, "target_id");
    }

    fn analyze_sql(sql: &str) -> Result<AnalyzedQuery, SqlkitError> {
        analyze(&make_catalog(), &parse_query(sql)?)
    }

    fn param_names(ddl: &[&str], sql: &str) -> Vec<String> {
        let catalog = Catalog::from_ddl(ddl).unwrap();
        let analyzed = analyze(&catalog, &parse_query(sql).unwrap()).unwrap();
        analyzed.params.into_iter().map(|param| param.name).collect()
    }

    const NAMING_DDL: &[&str] = &[
        "CREATE TABLE accounts (id TEXT PRIMARY KEY, charity_id TEXT, email TEXT NOT NULL, \
         country TEXT, widget BOOLEAN, record_type TEXT, metadata JSONB);",
    ];

    #[test]
    fn test_cast_array_placeholders_take_the_pluralized_column_name() {
        let names = param_names(
            NAMING_DDL,
            "-- @name Find\n-- @returns :many\nSELECT id FROM accounts WHERE id = ANY($1::text[]) \
             AND charity_id = ANY($2) AND NOT (country = ANY($3::text[])) AND email <> ALL($4::text[]);",
        );
        assert_eq!(names, ["ids", "charity_ids", "countries", "emails"]);
    }

    #[test]
    fn test_params_look_through_value_preserving_functions_json_keys_and_case() {
        let names = param_names(
            NAMING_DDL,
            "-- @name Find\n-- @returns :many\nSELECT id FROM accounts WHERE lower(email) = $1 \
             AND ($2::boolean IS NULL OR coalesce(widget, false) = $2) \
             AND coalesce(metadata -> 'configuration' ->> 'product', 'evergive') = $3 \
             AND CASE WHEN record_type IN ('a', 'b') THEN record_type END = ANY($4);",
        );
        assert_eq!(names, ["email", "widget", "product", "record_types"]);
    }

    #[test]
    fn test_limit_and_offset_params_are_named_limit_and_offset() {
        let names = param_names(
            NAMING_DDL,
            "-- @name Page\n-- @returns :many\nSELECT id FROM accounts ORDER BY id LIMIT $1 OFFSET $2;",
        );
        assert_eq!(names, ["limit", "offset"]);
    }

    #[test]
    fn test_function_arguments_name_their_params_positionally_and_by_name() {
        let ddl = [
            NAMING_DDL[0],
            "CREATE FUNCTION report(report_profile text, \"group\" text, \"from\" timestamp with time zone, \
             charity_id text DEFAULT NULL) RETURNS TABLE (id text) LANGUAGE sql STABLE AS $$ SELECT id FROM accounts $$;",
        ];
        let positional = param_names(
            &ddl,
            "-- @name Report\n-- @returns :many\nSELECT id FROM report($1, $2, $3, $4);",
        );
        assert_eq!(positional, ["report_profile", "group", "from", "charity_id"]);
        let named = param_names(
            &ddl,
            "-- @name Report\n-- @returns :many\nSELECT id FROM report($1, $2, $3, charity_id => $4);",
        );
        assert_eq!(named, ["report_profile", "group", "from", "charity_id"]);
    }

    #[test]
    fn test_param_tested_for_null_is_nullable() {
        let result = analyze_sql(
            "-- @name FindUsers
-- @returns :many
SELECT id FROM users WHERE (name = $1 OR $1 IS NULL) AND ($2::text IS NOT NULL OR bio = $2) AND id = $3;",
        )
        .unwrap();
        assert!(result.params[0].nullable, "tested after its comparison still counts");
        assert_eq!(result.params[0].neutral_type, "string");
        assert!(result.params[1].nullable);
        assert_eq!(result.params[1].neutral_type, "string", "typed by its cast");
        assert!(!result.params[2].nullable);
    }

    #[test]
    fn test_update_set_nullable_column_makes_param_nullable() {
        let result = analyze_sql(
            "-- @name UpdateUser
-- @returns :exec
UPDATE users SET bio = $1, name = $2 WHERE id = $3;",
        )
        .unwrap();
        assert!(result.params[0].nullable, "bio is nullable");
        assert!(!result.params[1].nullable, "name is NOT NULL");
        assert!(!result.params[2].nullable);
    }

    #[test]
    fn test_on_conflict_update_nullable_column_makes_param_nullable() {
        let result = analyze_sql(
            "-- @name UpsertUser
-- @returns :exec
INSERT INTO users (id, name, email) VALUES ($1, $2, $3)
ON CONFLICT (id) DO UPDATE SET bio = $4, name = EXCLUDED.name;",
        )
        .unwrap();
        assert!(!result.params[1].nullable);
        assert!(result.params[3].nullable, "bio is nullable");
    }

    #[test]
    fn test_positional_params_name_and_mark_nullable() {
        let result = analyze_sql(
            "-- @name RecentPosts
-- @returns :many
-- @param $1 author
-- @param $2 since?
SELECT id FROM posts WHERE user_id = $1 AND created_at >= $2;",
        )
        .unwrap();
        assert_eq!(result.params[0].name, "author");
        assert!(!result.params[0].nullable);
        assert_eq!(result.params[0].neutral_type, "int32", "the inferred type is kept");
        assert_eq!(result.params[1].name, "since");
        assert!(result.params[1].nullable, "`?` makes the parameter nullable");
    }

    #[test]
    fn test_positional_param_question_mark_is_optional_for_inferred_nullable() {
        let result = analyze_sql(
            "-- @name FindUsers
-- @returns :many
-- @param $1 min_age
SELECT id FROM users WHERE ($1::int IS NULL OR age >= $1);",
        )
        .unwrap();
        assert_eq!(result.params[0].name, "min_age");
        assert!(result.params[0].nullable, "already nullable from `IS NULL`");
    }

    #[test]
    fn test_positional_param_for_absent_position_errors() {
        let err = analyze_sql(
            "-- @name GetUser
-- @returns :one
-- @param $3 extra
SELECT id FROM users WHERE id = $1;",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("`extra` names $3"), "{err}");
    }

    #[test]
    fn test_update_set_arithmetic_expr_collects_all_params() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name IncrementUserAge
-- @returns :exec
UPDATE users SET age = age + $2 WHERE id = $1;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();
        assert_eq!(result.params.len(), 2, "both $1 and $2 must be present");
        let positions: Vec<i64> = result.params.iter().map(|p| p.position).collect();
        assert!(positions.contains(&1), "missing $1; got {positions:?}");
        assert!(positions.contains(&2), "missing $2; got {positions:?}");
    }

    #[test]
    fn test_annotation_overrides() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetUser
-- @returns :one
-- @nullable name
-- @nonnull age
SELECT name, age FROM users WHERE id = $1;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();
        assert!(result.columns[0].nullable);
        assert!(!result.columns[1].nullable);
    }

    // -----------------------------------------------------------------
    // Phase-2 nested-struct naming (`resolve_nested_struct_names`).
    //
    // ~keep `Analyzer::infer_nested_aggregate_type` (expressions.rs) is the real
    // producer now, exercised end to end by the json_agg/row_to_json tests
    // further down. These tests instead exercise the resolver directly
    // with a hand-built `pending` list and column set, to pin name
    // derivation, collision handling, and the dialect gate in isolation
    // from expression inference.
    // -----------------------------------------------------------------

    fn nested_column(name: &str, neutral_type: &str) -> AnalyzedColumn {
        AnalyzedColumn {
            name: name.to_string(),
            neutral_type: neutral_type.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn test_resolve_nested_struct_names_derives_name_from_query_and_column() {
        let catalog = make_catalog();
        let pending = vec![types::PendingNestedStruct {
            id: 0,
            fields: vec![NestedFieldInfo {
                name: "title".to_string(),
                neutral_type: "string".to_string(),
                nullable: false,
            }],
        }];
        let mut columns = vec![nested_column("orders", "json_nested<array<__nested__0>>")];

        let structs = resolve_nested_struct_names(&catalog, "GetUserOrders", pending, &mut columns);

        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].name, "get_user_orders_row_orders");
        assert_eq!(structs[0].fields.len(), 1);
        assert_eq!(structs[0].fields[0].name, "title");
    }

    /// The resolver only ever performs `to_pascal_case(name)`, never a
    /// round trip back through `to_snake_case` — pin that the PascalCase
    /// form embedded in the neutral type matches `to_pascal_case` applied
    /// to the returned `NestedStructInfo.name` exactly.
    #[test]
    fn test_resolve_nested_struct_names_pascal_case_matches_neutral_type() {
        let catalog = make_catalog();
        let pending = vec![types::PendingNestedStruct {
            id: 3,
            fields: Vec::new(),
        }];
        let mut columns = vec![nested_column("orders", "json_nested<array<__nested__3>>")];

        let structs = resolve_nested_struct_names(&catalog, "GetUserOrders", pending, &mut columns);

        let expected_pascal = naming::to_pascal_case(&structs[0].name);
        assert_eq!(
            columns[0].neutral_type,
            format!("json_nested<array<{expected_pascal}>>")
        );
    }

    #[test]
    fn test_resolve_nested_struct_names_collision_with_catalog_composite_suffixes() {
        let catalog = Catalog::from_ddl(&["CREATE TYPE get_user_row_profile AS (x TEXT);"]).unwrap();
        let pending = vec![types::PendingNestedStruct {
            id: 0,
            fields: vec![NestedFieldInfo {
                name: "bio".to_string(),
                neutral_type: "string".to_string(),
                nullable: true,
            }],
        }];
        let mut columns = vec![nested_column("profile", "json_nested<__nested__0>")];

        let structs = resolve_nested_struct_names(&catalog, "GetUser", pending, &mut columns);

        assert_eq!(structs.len(), 1);
        assert_eq!(
            structs[0].name, "get_user_row_profile_1",
            "must suffix rather than collide with the catalog composite \"get_user_row_profile\""
        );
        assert_eq!(columns[0].neutral_type, "json_nested<GetUserRowProfile1>");
    }

    #[test]
    fn test_resolve_nested_struct_names_duplicate_column_names_dedupe_identical_shape() {
        let catalog = make_catalog();
        let shared_fields = vec![NestedFieldInfo {
            name: "id".to_string(),
            neutral_type: "int32".to_string(),
            nullable: false,
        }];
        let pending = vec![
            types::PendingNestedStruct {
                id: 0,
                fields: shared_fields.clone(),
            },
            types::PendingNestedStruct {
                id: 1,
                fields: shared_fields,
            },
        ];
        let mut columns = vec![
            nested_column("items", "json_nested<array<__nested__0>>"),
            nested_column("items", "json_nested<array<__nested__1>>"),
        ];

        let structs = resolve_nested_struct_names(&catalog, "GetOrder", pending, &mut columns);

        assert_eq!(
            structs.len(),
            1,
            "two columns with the same name and identical field shape must dedupe to one struct"
        );
        assert_eq!(columns[0].neutral_type, columns[1].neutral_type);
    }

    #[test]
    fn test_resolve_nested_struct_names_duplicate_column_names_differing_shape_suffixes() {
        let catalog = make_catalog();
        let pending = vec![
            types::PendingNestedStruct {
                id: 0,
                fields: vec![NestedFieldInfo {
                    name: "id".to_string(),
                    neutral_type: "int32".to_string(),
                    nullable: false,
                }],
            },
            types::PendingNestedStruct {
                id: 1,
                fields: vec![NestedFieldInfo {
                    name: "name".to_string(),
                    neutral_type: "string".to_string(),
                    nullable: false,
                }],
            },
        ];
        let mut columns = vec![
            nested_column("items", "json_nested<array<__nested__0>>"),
            nested_column("items", "json_nested<array<__nested__1>>"),
        ];

        let structs = resolve_nested_struct_names(&catalog, "GetOrder", pending, &mut columns);

        assert_eq!(
            structs.len(),
            2,
            "same-named columns with different field shapes must not collapse into one struct"
        );
        assert_eq!(structs[0].name, "get_order_row_items");
        assert_eq!(structs[1].name, "get_order_row_items_1");
        assert_ne!(columns[0].neutral_type, columns[1].neutral_type);
    }

    // -----------------------------------------------------------------
    // Phase-1 producer: json_agg / row_to_json nested-aggregate inference
    // end to end through analyze().
    // -----------------------------------------------------------------

    #[test]
    fn test_json_agg_wildcard_produces_nested_struct() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetUserPosts
-- @returns :many
SELECT u.id, json_agg(p.*) AS posts FROM users u JOIN posts p ON u.id = p.user_id GROUP BY u.id;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();

        assert_eq!(result.columns.len(), 2);
        assert_eq!(result.columns[1].name, "posts");
        assert_eq!(
            result.nested_structs.len(),
            1,
            "exactly one nested struct must be produced"
        );

        let nested = &result.nested_structs[0];
        assert_eq!(nested.name, "get_user_posts_row_posts");
        assert_eq!(
            result.columns[1].neutral_type, "json_nested<array<GetUserPostsRowPosts>>",
            "json_agg wraps the resolved name in array<> and must match the PascalCase of nested.name exactly"
        );
        assert!(result.columns[1].nullable);

        let field_names: Vec<&str> = nested.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            field_names,
            ["id", "user_id", "title", "body", "published", "created_at"]
        );
        let title_field = nested.fields.iter().find(|f| f.name == "title").unwrap();
        assert_eq!(title_field.neutral_type, "string");
        assert!(!title_field.nullable, "posts.title is NOT NULL and the join is INNER");
        let body_field = nested.fields.iter().find(|f| f.name == "body").unwrap();
        assert!(body_field.nullable, "posts.body has no NOT NULL constraint");
    }

    /// A LEFT JOIN moves *element* nullability, not field nullability. With
    /// no matching row PostgreSQL makes the whole-row variable `p` itself
    /// NULL, so `json_agg(p.*)` produces the JSON array `[null]` — a null
    /// element, never an object whose fields are all null. The element type
    /// must therefore be optional while each field keeps its schema
    /// nullability.
    #[test]
    fn test_json_agg_left_join_makes_array_elements_nullable() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetUserPostsOuter
-- @returns :many
SELECT u.id, json_agg(p.*) AS posts FROM users u LEFT JOIN posts p ON u.id = p.user_id GROUP BY u.id;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();

        assert_eq!(
            result.columns[1].neutral_type, "json_nested<array<nullable<GetUserPostsOuterRowPosts>>>",
            "json_agg over a LEFT JOIN with no match yields [null], so the element type must be nullable"
        );

        let nested = &result.nested_structs[0];
        let id_field = nested.fields.iter().find(|f| f.name == "id").unwrap();
        assert!(
            !id_field.nullable,
            "posts.id is NOT NULL; inside an object json_agg actually emitted it can never be null, so \
             widening the field instead of the element would model a value PostgreSQL never produces"
        );
        let body_field = nested.fields.iter().find(|f| f.name == "body").unwrap();
        assert!(body_field.nullable, "posts.body has no NOT NULL constraint");
    }

    /// The INNER-JOIN counterpart: every aggregated row matched, so no
    /// element can be null and the `nullable<>` wrapper must be absent.
    #[test]
    fn test_json_agg_inner_join_elements_are_not_nullable() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetUserPostsInner
-- @returns :many
SELECT u.id, json_agg(p.*) AS posts FROM users u JOIN posts p ON u.id = p.user_id GROUP BY u.id;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();

        assert_eq!(
            result.columns[1].neutral_type,
            "json_nested<array<GetUserPostsInnerRowPosts>>"
        );
    }

    /// `row_to_json` over a null-extended row returns SQL NULL, not a JSON
    /// null: the column is nullable and there is no element to wrap, so the
    /// `nullable<>` element wrapper must not appear on this path.
    #[test]
    fn test_row_to_json_left_join_does_not_wrap_element() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetUserPostJson
-- @returns :many
SELECT u.id, row_to_json(p.*) AS post FROM users u LEFT JOIN posts p ON u.id = p.user_id;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();

        assert_eq!(result.columns[1].neutral_type, "json_nested<GetUserPostJsonRowPost>");
        assert!(result.columns[1].nullable, "the column itself carries the NULL");
    }

    #[test]
    fn test_row_to_json_wildcard_produces_nested_struct_without_array() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetPostAsJson
-- @returns :many
SELECT row_to_json(p.*) AS post FROM posts p;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();

        assert_eq!(result.nested_structs.len(), 1);
        assert_eq!(
            result.columns[0].neutral_type, "json_nested<GetPostAsJsonRowPost>",
            "row_to_json must not wrap in array<> -- it emits one object per output row, not an aggregate"
        );
    }

    #[test]
    fn test_json_agg_scalar_argument_falls_back_to_plain_json() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetUserNames
-- @returns :one
SELECT json_agg(u.name) AS names FROM users u;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();

        assert_eq!(
            result.columns[0].neutral_type, "json",
            "a scalar/column argument is not a relation shape -- must match pre-existing json_agg behaviour exactly"
        );
        assert!(result.nested_structs.is_empty());
    }

    #[test]
    fn test_json_agg_bare_wildcard_falls_back_to_plain_json() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetUserCount
-- @returns :one
SELECT json_agg(*) AS everything FROM users;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();

        assert_eq!(result.columns[0].neutral_type, "json");
        assert!(result.nested_structs.is_empty());
    }

    /// Guardrail: `string_agg` must never be reinterpreted as a nested
    /// aggregate, even when its argument is a relation wildcard shape (not
    /// valid SQL for `string_agg`, which expects a text expression, but the
    /// analyzer must not special-case it regardless).
    #[test]
    fn test_string_agg_never_produces_nested_struct() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetUserNamesJoined
-- @returns :one
SELECT string_agg(u.name, ',') AS names FROM users u;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();

        assert_eq!(result.columns[0].neutral_type, "string");
        assert!(result.nested_structs.is_empty());
    }

    /// `jsonb_agg` differs from `json_agg` only in storage type — both
    /// aggregate one JSON object per row into a JSON array — so it must get
    /// the identical nested struct, array wrapper included.
    #[test]
    fn test_jsonb_agg_wildcard_produces_nested_struct() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetUserPostsB
-- @returns :many
SELECT jsonb_agg(p.*) AS posts FROM posts p;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();

        assert_eq!(result.nested_structs.len(), 1);
        assert_eq!(
            result.columns[0].neutral_type,
            "json_nested<array<GetUserPostsBRowPosts>>"
        );
        assert!(result.columns[0].nullable, "an aggregate over zero rows is SQL NULL");

        let field_names: Vec<&str> = result.nested_structs[0]
            .fields
            .iter()
            .map(|f| f.name.as_str())
            .collect();
        assert_eq!(
            field_names,
            ["id", "user_id", "title", "body", "published", "created_at"]
        );
    }

    /// The LEFT JOIN element-nullability rule is a property of the aggregate,
    /// not of the spelling: `jsonb_agg` over a null-extended row yields
    /// `[null]` exactly as `json_agg` does.
    #[test]
    fn test_jsonb_agg_left_join_makes_array_elements_nullable() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetUserPostsBOuter
-- @returns :many
SELECT u.id, jsonb_agg(p.*) AS posts FROM users u LEFT JOIN posts p ON u.id = p.user_id GROUP BY u.id;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();

        assert_eq!(
            result.columns[1].neutral_type,
            "json_nested<array<nullable<GetUserPostsBOuterRowPosts>>>"
        );
    }

    /// `to_json(p.*)` is `row_to_json(p.*)` spelled differently — PostgreSQL
    /// returns the identical document — so it must produce the same single
    /// nested object, with no array wrapper.
    #[test]
    fn test_to_json_wildcard_produces_nested_struct_without_array() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetPostAsJson2
-- @returns :many
SELECT to_json(p.*) AS post FROM posts p;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();

        assert_eq!(result.nested_structs.len(), 1);
        assert_eq!(result.columns[0].neutral_type, "json_nested<GetPostAsJson2RowPost>");
    }

    #[test]
    fn test_to_jsonb_wildcard_produces_nested_struct_without_array() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetPostAsJsonb
-- @returns :many
SELECT to_jsonb(p.*) AS post FROM posts p;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();

        assert_eq!(result.nested_structs.len(), 1);
        assert_eq!(result.columns[0].neutral_type, "json_nested<GetPostAsJsonbRowPost>");
    }

    /// `to_json` is `proisstrict = t`: `to_json(NULL)` is SQL NULL, not the
    /// JSON document `null`, so a scalar conversion inherits its argument's
    /// nullability instead of being unconditionally non-null.
    #[test]
    fn test_to_json_scalar_follows_argument_nullability() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetPostBodyJson
-- @returns :many
SELECT to_json(p.body) AS body_json, to_json(p.title) AS title_json FROM posts p;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();

        assert_eq!(result.columns[0].neutral_type, "json");
        assert!(
            result.columns[0].nullable,
            "posts.body is nullable and to_json is strict"
        );
        assert_eq!(result.columns[1].neutral_type, "json");
        assert!(!result.columns[1].nullable, "posts.title is NOT NULL");
        assert!(result.nested_structs.is_empty());
    }

    /// Guardrail for the deliberate non-change: `json_object_agg(k, v)`
    /// builds a JSON object keyed by the *runtime values* of `k`, so it has
    /// no fixed field set and must stay a flat, nullable `json` even though
    /// its `json_agg` neighbour now infers a struct.
    #[test]
    fn test_json_object_agg_stays_plain_nullable_json() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetPostTitles
-- @returns :one
SELECT json_object_agg(p.id, p.title) AS titles, jsonb_object_agg(p.id, p.title) AS titles_b FROM posts p;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();

        assert_eq!(result.columns[0].neutral_type, "json");
        assert!(result.columns[0].nullable, "an aggregate over zero rows is SQL NULL");
        assert_eq!(result.columns[1].neutral_type, "json");
        assert!(result.columns[1].nullable);
        assert!(result.nested_structs.is_empty());
    }

    /// Guardrail for the other half of the split arm: the `json_build_*`
    /// family is `proisstrict = f` — `json_build_object('a', NULL)` is
    /// `{"a": null}`, a non-NULL document — so it stays non-nullable even
    /// with a nullable argument.
    #[test]
    fn test_json_build_object_stays_non_nullable_with_nullable_argument() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name BuildPostJson
-- @returns :many
SELECT json_build_object('body', p.body) AS built FROM posts p;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();

        assert_eq!(result.columns[0].neutral_type, "json");
        assert!(
            !result.columns[0].nullable,
            "json_build_object embeds a JSON null rather than returning SQL NULL"
        );
    }

    /// Nested-of-nested: an outer `json_agg` over a CTE column that is
    /// itself the result of an inner `json_agg`. Phase 2 naming only walks
    /// the query's own top-level output columns, never recursively into a
    /// NestedStructInfo's own fields, so the inner `__nested__{id}`
    /// placeholder can never be substituted if this were allowed through --
    /// it must be rejected with a clear diagnostic instead of reaching
    /// codegen as a leaked, unresolvable placeholder.
    #[test]
    fn test_nested_of_nested_aggregate_is_rejected_with_clear_diagnostic() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetAllUserPosts
-- @returns :many
WITH user_posts AS (
    SELECT u.id AS user_id, json_agg(p.*) AS posts
    FROM users u JOIN posts p ON p.user_id = u.id
    GROUP BY u.id
)
SELECT up.user_id, json_agg(up.*) AS all_posts FROM user_posts up;",
        )
        .unwrap();

        let err = analyze(&catalog, &query).unwrap_err();

        assert!(
            err.message.contains("nested aggregate over nested aggregate"),
            "expected a clear nested-of-nested diagnostic, got: {}",
            err.message
        );
        assert!(
            err.message.contains("posts"),
            "diagnostic should name the offending field, got: {}",
            err.message
        );
    }

    /// UNION arm widening: two arms that both `json_agg` the *same*
    /// underlying table shape must widen cleanly into one nested struct,
    /// even though each arm's `json_agg` call independently allocated its
    /// own `__nested__{id}` and so never compares textually equal.
    #[test]
    fn test_union_arms_with_identical_nested_shape_widen_to_one_struct() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetUserPostsEitherWay
-- @returns :many
SELECT u.id, json_agg(p.*) AS posts FROM users u JOIN posts p ON p.user_id = u.id GROUP BY u.id
UNION
SELECT u2.id, json_agg(p2.*) AS posts FROM users u2 JOIN posts p2 ON p2.user_id = u2.id GROUP BY u2.id;",
        )
        .unwrap();

        let result = analyze(&catalog, &query).unwrap();

        assert_eq!(
            result.nested_structs.len(),
            1,
            "both arms describe the same posts shape and must widen to a single struct"
        );
        assert!(result.columns[1].neutral_type.starts_with("json_nested<array<"));
    }

    /// UNION arm widening: two arms that `json_agg` genuinely different
    /// table shapes must be rejected with a clear diagnostic, not silently
    /// resolved to whichever arm happened to be on the left -- the pre-fix
    /// behaviour would drop the right arm's shape with no signal at all.
    #[test]
    fn test_union_arms_with_differing_nested_shape_is_rejected_with_clear_diagnostic() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetUserPostsOrComments
-- @returns :many
SELECT u.id, json_agg(p.*) AS posts FROM users u JOIN posts p ON p.user_id = u.id GROUP BY u.id
UNION
SELECT u2.id, json_agg(c.*) AS posts FROM users u2 JOIN comments c ON c.user_id = u2.id GROUP BY u2.id;",
        )
        .unwrap();

        let err = analyze(&catalog, &query).unwrap_err();

        assert!(
            err.message.contains("different row shapes"),
            "expected a clear shape-mismatch diagnostic, got: {}",
            err.message
        );
    }

    /// UNION arm widening, nested against non-nested. `widen_type`'s
    /// "different types, left wins" rule would keep the strongly-typed
    /// struct and then deserialize the right arm's arbitrary JSON into it at
    /// runtime, with nothing failing at build time.
    #[test]
    fn test_union_nested_arm_against_plain_json_arm_is_rejected() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetUserPostsOrEmpty
-- @returns :many
SELECT json_agg(p.*) AS posts FROM posts p
UNION
SELECT '[]'::json AS posts;",
        )
        .unwrap();

        let err = analyze(&catalog, &query).unwrap_err();

        assert!(
            err.message.contains("nested aggregate") && err.message.contains("left arm"),
            "expected a nested-vs-non-nested diagnostic naming the offending side, got: {}",
            err.message
        );
    }

    /// The mirror image: the nested arm on the right, where the pre-fix
    /// behaviour silently discarded the struct entirely.
    #[test]
    fn test_union_plain_json_arm_against_nested_arm_is_rejected() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetEmptyOrUserPosts
-- @returns :many
SELECT '[]'::json AS posts
UNION
SELECT json_agg(p.*) AS posts FROM posts p;",
        )
        .unwrap();

        let err = analyze(&catalog, &query).unwrap_err();

        assert!(
            err.message.contains("nested aggregate") && err.message.contains("right arm"),
            "expected a nested-vs-non-nested diagnostic naming the offending side, got: {}",
            err.message
        );
    }

    /// Guardrail: `array_agg` shares the wildcard-argument shape with
    /// `json_agg` but aggregates into a SQL array, not JSON. It must keep
    /// resolving through the pre-existing `get_first_arg_type` path and
    /// never acquire a nested struct.
    #[test]
    fn test_array_agg_wildcard_never_produces_nested_struct() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetPostIdsAgg
-- @returns :one
SELECT array_agg(p.id) AS ids FROM posts p;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();

        assert_eq!(result.columns[0].neutral_type, "array<int32>");
        assert!(result.nested_structs.is_empty());
    }

    #[test]
    fn test_json_agg_postgresql_engine_still_infers() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetPostsPg
-- @returns :many
SELECT json_agg(p.*) AS posts FROM posts p;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();

        assert_eq!(result.nested_structs.len(), 1);
    }

    /// The explicit column alias list on a CTE (`WITH t(a, b) AS ...`) must
    /// name the CTE's columns even when the body projection carries no names
    /// of its own — `SELECT 1` otherwise labels its column "unknown" and the
    /// outer query's `SELECT a, b` fails with "column a does not exist".
    #[test]
    fn test_cte_column_alias_list_names_literal_columns() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetPair
-- @returns :many
WITH t(a, b) AS (SELECT 1, 2) SELECT a, b FROM t;",
        )
        .unwrap();

        let result = analyze(&catalog, &query).unwrap();

        let names: Vec<&str> = result.columns.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["a", "b"]);
        // `1` and `2` are small integer literals, typed `int32` to match
        // PostgreSQL (see #122).
        assert!(result.columns.iter().all(|c| c.neutral_type == "int32"));
    }

    /// `SELECT *` over a CTE with an explicit column alias list expands to the
    /// aliased names, not the body's inferred ones.
    #[test]
    fn test_cte_column_alias_list_consumed_by_select_star() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetPairStar
-- @returns :many
WITH t(a, b) AS (SELECT 1, 2) SELECT * FROM t;",
        )
        .unwrap();

        let result = analyze(&catalog, &query).unwrap();

        let names: Vec<&str> = result.columns.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["a", "b"]);
    }

    /// A CTE column alias list whose entry count disagrees with the body's
    /// column count is a hard error (PostgreSQL rejects it too), not a
    /// positional guess.
    #[test]
    fn test_cte_column_alias_count_mismatch_is_rejected() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name GetMismatch
-- @returns :many
WITH t(a) AS (SELECT 1, 2) SELECT * FROM t;",
        )
        .unwrap();

        let err = analyze(&catalog, &query).unwrap_err();

        assert!(
            err.message
                .contains("CTE column alias list has 1 entries but the CTE body produces 2 columns"),
            "expected a column-alias-count diagnostic, got: {}",
            err.message
        );
    }

    /// Recursive CTEs resolve column references by name, so the alias list
    /// must also apply to the anchor's seeded scope — `t(n)` must make `n`
    /// referenceable inside the recursive term and in the outer query.
    #[test]
    fn test_recursive_cte_with_column_alias_list_names_columns() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name CountDown
-- @returns :many
WITH RECURSIVE t(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM t WHERE n < 10) SELECT n FROM t;",
        )
        .unwrap();

        let result = analyze(&catalog, &query).unwrap();

        let names: Vec<&str> = result.columns.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["n"]);
        // `1` and `n + 1` are both `int32` (small integer literal, and the
        // anchor-typed `n` widened against another `int32` literal); see
        // #122.
        assert_eq!(result.columns[0].neutral_type, "int32");
    }

    /// A literal `NULL` alone in the projection has nothing to infer a type from.
    #[test]
    fn test_literal_null_alone_in_projection_is_rejected() {
        let catalog = Catalog::from_ddl(&["CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);"]).unwrap();
        let query = parse_query(
            "-- @name BareNull
-- @returns :many
SELECT NULL AS tag, name FROM users;",
        )
        .unwrap();
        let err = analyze(&catalog, &query)
            .expect_err("a bare NULL with no typed context must be rejected the same way a bare placeholder is");
        assert_eq!(err.code, crate::errors::ErrorCode::TypeMismatch);
        assert!(err.message.contains("BareNull") && err.message.contains("tag"));
    }

    /// The rejection must not fire on a UNION arm's own untyped NULL before the
    /// other arm has had a chance to widen it -- `widen_neutral_type` absorbs
    /// `"unknown"` into whatever real type the other arm provides, and the
    /// widened `AnalyzedColumn` clears `untyped_literal` whenever either side
    /// resolved a real type, since that side genuinely widened the column.
    #[test]
    fn test_null_projection_widened_by_union_arm_is_not_rejected() {
        let catalog = Catalog::from_ddl(&[
            "CREATE TABLE a (id INTEGER PRIMARY KEY, x INTEGER);",
            "CREATE TABLE b (id INTEGER PRIMARY KEY);",
        ])
        .unwrap();
        let query = parse_query(
            "-- @name Widened
-- @returns :many
SELECT x FROM a UNION SELECT NULL AS x FROM b;",
        )
        .unwrap();
        let result =
            analyze(&catalog, &query).expect("the NULL arm must be widened by the other arm's int32, not rejected");
        assert_eq!(result.columns[0].neutral_type, "int32");
    }

    /// UNION is commutative -- the widening in the sibling test above must not depend on
    /// which arm the untyped NULL sits in. Before #224, `widen_union_arm_type`'s non-nested
    /// fallthrough called `widen_type` directly instead of `widen_neutral_type`, and
    /// `widen_type` returned its left argument for any pair its numeric ladder did not
    /// handle. So a NULL arm on the left won over the other arm's real type and the column
    /// reached codegen as `"unknown"`, reported there as
    /// `INTERNAL_ERROR: type resolution failed for column 'x': unknown neutral type: unknown`.
    #[test]
    fn test_null_projection_in_first_union_arm_is_widened() {
        let catalog = Catalog::from_ddl(&[
            "CREATE TABLE a (id INTEGER PRIMARY KEY);",
            "CREATE TABLE b (id INTEGER PRIMARY KEY, x INTEGER);",
        ])
        .unwrap();
        let query =
            parse_query("-- @name Widened\n-- @returns :many\nSELECT NULL AS x FROM a UNION SELECT x FROM b;").unwrap();
        let result = analyze(&catalog, &query).expect("the first NULL arm must be widened by the second arm's int32");
        assert_eq!(result.columns[0].neutral_type, "int32");
    }

    /// #223 rejected markers on the *column* path only, and that left the defect it
    /// was filed for reachable through parameters. A placeholder inside a function
    /// whose result is untypeable adopts that result as its own type --
    /// `register_param` takes it verbatim, and `COALESCE`'s arm only guards against
    /// the literal string `"unknown"`, which a marker is not. Nothing downstream
    /// rejected it: `resolve_params` in sqlkit-codegen has no equivalent check, so
    /// this query reported
    /// `INTERNAL_ERROR: type resolution failed for param 'row': unknown neutral
    /// type: __untypeable_row__:` -- sqlkit's internal marker spelling shown to a
    /// user, which is the exact failure #173 and #223 each set out to remove.
    #[test]
    fn test_marker_reaching_a_param_is_rejected_rather_than_leaked_to_codegen() {
        let catalog =
            Catalog::from_ddl(&["CREATE TABLE documents (id SERIAL PRIMARY KEY, data JSONB NOT NULL);"]).unwrap();
        let query = parse_query(
            "-- @name GetDoc
-- @returns :many
SELECT id FROM documents WHERE data::text = COALESCE($1, ROW(id, data))::text;",
        )
        .unwrap();

        let error = analyze(&catalog, &query).expect_err("a marker on a param's type must be rejected at analyze time");

        assert_eq!(error.code, crate::errors::ErrorCode::UnresolvedType, "got: {error}");
        assert!(
            !error.to_string().contains("__untypeable_row__"),
            "the internal marker spelling must never reach the user; got: {error}"
        );
        assert!(
            error.to_string().contains("parameter \"row\""),
            "the message must name the parameter, not call it a column; got: {error}"
        );
    }

    /// When *neither* UNION arm resolves a real type, `widen_type`'s `a == b` fast
    /// path returns `"unknown"` untouched -- nothing in the query ever gave this
    /// column a type, so the taint must survive the widened `AnalyzedColumn` and
    /// still be rejected, the same as a single untyped NULL would be.
    #[test]
    fn test_null_projection_both_union_arms_untyped_is_rejected() {
        let catalog = Catalog::from_ddl(&[
            "CREATE TABLE a (id INTEGER PRIMARY KEY);",
            "CREATE TABLE b (id INTEGER PRIMARY KEY);",
        ])
        .unwrap();
        let query = parse_query(
            "-- @name BothUntyped
-- @returns :many
SELECT NULL AS tag FROM a UNION SELECT NULL AS tag FROM b;",
        )
        .unwrap();
        let err = analyze(&catalog, &query)
            .expect_err("both UNION arms projecting a bare NULL resolves nothing and must be rejected");
        assert_eq!(err.code, crate::errors::ErrorCode::TypeMismatch);
        assert!(
            err.message.contains("BothUntyped") && err.message.contains("tag"),
            "the error must name both the query and the offending column, got: {}",
            err.message
        );
    }

    /// A bare `NULL` projected out of a derived table must still be rejected one
    /// scope level up -- `ScopeColumn::from_analyzed_column` carries the inner
    /// column's `untyped_literal` taint through the subquery boundary instead of
    /// letting it reset to `false` the moment it crosses into the outer scope.
    #[test]
    fn test_null_projection_through_derived_table_is_rejected() {
        let catalog = Catalog::from_ddl(&["CREATE TABLE users (id INTEGER PRIMARY KEY);"]).unwrap();
        let query = parse_query(
            "-- @name ViaSubquery
-- @returns :many
SELECT tag FROM (SELECT NULL AS tag FROM users) sub;",
        )
        .unwrap();
        let err =
            analyze(&catalog, &query).expect_err("a bare NULL projected out of a derived table must still be rejected");
        assert_eq!(err.code, crate::errors::ErrorCode::TypeMismatch);
        assert!(
            err.message.contains("ViaSubquery") && err.message.contains("tag"),
            "the error must name both the query and the offending column, got: {}",
            err.message
        );
    }

    /// Same shape as the derived-table case, through a CTE instead. A bare `?`
    /// inside a CTE body fails earlier with `SYNTAX_ERROR` from `sqlparser`
    /// ("Expected: an expression, found: ?"), so this uses a bare `NULL`, which
    /// parses fine wherever a placeholder would not.
    #[test]
    fn test_null_projection_through_cte_is_rejected() {
        let catalog = Catalog::from_ddl(&["CREATE TABLE users (id INTEGER PRIMARY KEY);"]).unwrap();
        let query = parse_query(
            "-- @name ViaCte
-- @returns :many
WITH cte AS (SELECT NULL AS tag FROM users) SELECT tag FROM cte;",
        )
        .unwrap();
        let err = analyze(&catalog, &query).expect_err("a bare NULL projected out of a CTE must still be rejected");
        assert_eq!(err.code, crate::errors::ErrorCode::TypeMismatch);
        assert!(
            err.message.contains("ViaCte") && err.message.contains("tag"),
            "the error must name both the query and the offending column, got: {}",
            err.message
        );
    }

    /// A `jsonb_each` column carries `UNTYPEABLE_RECORD_MARKER` (not the bare
    /// `"unknown"` this test used to assert -- see #223) all the way through a
    /// derived-table boundary, but not because anything here specially threads
    /// it across the scope crossing: `analyze_select` calls
    /// `reject_unresolved_columns` unconditionally on *every* `SELECT` it
    /// analyzes, nested subqueries included. So the inner
    /// `SELECT jsonb_each(j) AS kv FROM t` is rejected at that inner call --
    /// inside `build_scope_from_from`'s `TableFactor::Derived` arm, before the
    /// outer `SELECT kv FROM (...) sub` is even analyzed -- the same way it
    /// would be rejected as a top-level query. Contrast
    /// `test_null_projection_through_derived_table_is_rejected`, where
    /// `untyped_literal` genuinely does need `ScopeColumn::from_analyzed_column`
    /// to carry it across that boundary, because a bare `NULL` alone is not
    /// rejected by `reject_unresolved_columns`.
    #[test]
    fn test_json_each_through_derived_table_is_rejected() {
        let catalog = Catalog::from_ddl(&["CREATE TABLE t (id INTEGER PRIMARY KEY, j JSONB);"]).unwrap();
        let query = parse_query(
            "-- @name KvViaSubquery
-- @returns :many
SELECT kv FROM (SELECT jsonb_each(j) AS kv FROM t) sub;",
        )
        .unwrap();
        let err = analyze(&catalog, &query).expect_err(
            "a jsonb_each record column through a derived table must be rejected, the same as select-list position",
        );
        assert_eq!(err.code, crate::errors::ErrorCode::UnresolvedType);
        assert!(
            err.message.contains("kv") && err.message.contains("jsonb_each"),
            "the error must name both the column and the function, got: {}",
            err.message
        );
    }

    /// `jsonb_each` in select-list position used to produce a column whose
    /// `neutral_type` was the bare string `"unknown"` (PostgreSQL's `record`
    /// pseudo-type has no neutral-type representation) and reached codegen
    /// unrejected, where every backend failed with
    /// `INTERNAL_ERROR: unknown neutral type: unknown` -- input sqlkit
    /// diagnosed correctly, reported as if sqlkit itself were broken (#223).
    /// This is the exact shape a previous, reverted attempt at this fix broke
    /// by rejecting on `neutral_type == "unknown"` directly: that also caught
    /// the *harmless* accumulator seed `widen_neutral_type` uses (see
    /// `test_widen_neutral_type_unknown_absorbed` in `helpers.rs`), which
    /// broke `test_jsonb_each_select_list` / `..._text_select_list` in
    /// `crates/sqlkit-codegen/tests/generated/test_types.rs`.
    /// `UNTYPEABLE_RECORD_MARKER` is a value no legitimate neutral type or
    /// widening seed ever produces, which is what makes it safe to reject
    /// unconditionally here.
    #[test]
    fn test_json_each_in_select_list_is_rejected() {
        let catalog = Catalog::from_ddl(&["CREATE TABLE t (id INTEGER PRIMARY KEY, j JSONB);"]).unwrap();
        let query = parse_query(
            "-- @name GetKv
-- @returns :many
SELECT jsonb_each(j) AS kv FROM t;",
        )
        .unwrap();
        let err = analyze(&catalog, &query).expect_err(
            "a jsonb_each record column must be rejected with an actionable error, not reach codegen \
             as a bare \"unknown\"",
        );
        assert_eq!(err.code, crate::errors::ErrorCode::UnresolvedType);
        assert!(
            err.message.contains("kv") && err.message.contains("jsonb_each"),
            "the error must name both the column and the function, got: {}",
            err.message
        );
    }

    // Regression tests: `analyzed.composites` was built by scanning selected columns' neutral
    // types, never by walking into a composite's own field list, so a composite reachable
    // only as another composite's field was never collected -- and its definition was never
    // emitted -- even though the outer composite that references it was selected directly.

    /// Must fail before the fix: selecting only `bounds` (typed `outer_shape`) must still
    /// collect `inner_point`, the type of `outer_shape`'s own `origin` field, even though no
    /// column in the query is directly typed `inner_point`.
    #[test]
    fn test_composites_recurse_into_nested_composite_fields() {
        let catalog = Catalog::from_ddl(&[
            "CREATE TYPE inner_point AS (x INTEGER, y INTEGER);",
            "CREATE TYPE outer_shape AS (label TEXT, origin inner_point);",
            "CREATE TABLE shapes (id SERIAL PRIMARY KEY, bounds outer_shape NOT NULL);",
        ])
        .unwrap();
        let query = parse_query(
            "-- @name GetShape
-- @returns :one
SELECT id, bounds FROM shapes WHERE id = $1;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();

        assert!(
            result.composites.iter().any(|c| c.sql_name == "outer_shape"),
            "the directly-selected composite must still be collected"
        );
        let inner = result
            .composites
            .iter()
            .find(|c| c.sql_name == "inner_point")
            .expect("inner_point is reachable only through outer_shape's own field list");
        assert_eq!(inner.fields.len(), 2);
        assert!(inner.fields.iter().any(|f| f.name == "x" && f.neutral_type == "int32"));
        assert!(inner.fields.iter().any(|f| f.name == "y" && f.neutral_type == "int32"));
    }

    /// Two fields of `outer_shape` both name `inner_point` -- a diamond. Must fail before the
    /// fix existed (there was no recursion to produce even a duplicate); after the fix,
    /// `seen_composites` must collapse the diamond to exactly one `CompositeInfo`, not two.
    #[test]
    fn test_composites_diamond_field_emits_exactly_one_definition() {
        let catalog = Catalog::from_ddl(&[
            "CREATE TYPE inner_point AS (x INTEGER, y INTEGER);",
            "CREATE TYPE outer_shape AS (top_left inner_point, bottom_right inner_point);",
            "CREATE TABLE shapes (id SERIAL PRIMARY KEY, bounds outer_shape NOT NULL);",
        ])
        .unwrap();
        let query = parse_query(
            "-- @name GetShape
-- @returns :one
SELECT id, bounds FROM shapes WHERE id = $1;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();

        let inner_count = result.composites.iter().filter(|c| c.sql_name == "inner_point").count();
        assert_eq!(
            inner_count, 1,
            "a composite reached through two sibling fields of the same name must be collected once"
        );
    }

    /// A composite two levels deep (`outer` -> `middle` -> `inner`) must all be collected, not
    /// just the immediate nesting -- proves the walk is a real transitive closure, not a
    /// single extra hop hand-coded for the one-level case.
    #[test]
    fn test_composites_recurse_transitively_two_levels_deep() {
        let catalog = Catalog::from_ddl(&[
            "CREATE TYPE innermost AS (v INTEGER);",
            "CREATE TYPE middle_layer AS (core innermost);",
            "CREATE TYPE outer_layer AS (mid middle_layer);",
            "CREATE TABLE boxes (id SERIAL PRIMARY KEY, contents outer_layer NOT NULL);",
        ])
        .unwrap();
        let query = parse_query(
            "-- @name GetBox
-- @returns :one
SELECT id, contents FROM boxes WHERE id = $1;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();

        for expected in ["outer_layer", "middle_layer", "innermost"] {
            assert!(
                result.composites.iter().any(|c| c.sql_name == expected),
                "{expected} must be collected"
            );
        }
    }

    /// Must fail before the fix: the enum-discovery loop matched only the bare
    /// `"enum::mood"` string, so a column typed `mood[]` -- neutral type
    /// `"array<enum::mood>"` -- was never recognized as referencing `mood` at all.
    /// `analyzed.enums` came back empty, and `sqlkit-codegen`'s
    /// `generate_enum_defs_via_backend` (which *does* unwrap `array<...>` before
    /// matching) then fell back to a stub `EnumInfo` with `values: vec![]` --
    /// emitting an enum declaration with no variants instead of the real ones.
    #[test]
    fn test_enums_reachable_only_through_array_column_are_collected() {
        let catalog = Catalog::from_ddl(&[
            "CREATE TYPE mood AS ENUM ('sad', 'happy', 'ok');",
            "CREATE TABLE t (id SERIAL PRIMARY KEY, moods mood[] NOT NULL);",
        ])
        .unwrap();
        let query = parse_query(
            "-- @name GetMoods
-- @returns :one
SELECT id, moods FROM t WHERE id = $1;",
        )
        .unwrap();
        let result = analyze(&catalog, &query).unwrap();

        let mood = result
            .enums
            .iter()
            .find(|e| e.sql_name == "mood")
            .expect("mood is reachable through the array<enum::mood> column");
        assert_eq!(
            mood.values,
            vec!["sad".to_string(), "happy".to_string(), "ok".to_string()]
        );
    }

    fn function_catalog() -> Catalog {
        Catalog::from_ddl(&[
            "CREATE TABLE values_table (small_value smallint NOT NULL, integer_value integer NOT NULL);",
            "CREATE FUNCTION label(value integer, prefix text DEFAULT 'v') RETURNS text LANGUAGE SQL AS 'SELECT';",
            "CREATE FUNCTION promoted(value bigint) RETURNS bigint LANGUAGE SQL AS 'SELECT value';",
            "CREATE FUNCTION choose(value bigint) RETURNS bigint LANGUAGE SQL AS 'SELECT value';",
            "CREATE FUNCTION choose(value numeric) RETURNS numeric LANGUAGE SQL AS 'SELECT value';",
            "CREATE FUNCTION item_rows(prefix text) RETURNS TABLE(item_count bigint, item_name text) LANGUAGE SQL AS 'SELECT';",
            "CREATE FUNCTION item_names(prefix text) RETURNS SETOF text LANGUAGE SQL AS 'SELECT prefix';",
            "CREATE FUNCTION join_ids(VARIADIC values bigint[]) RETURNS text LANGUAGE SQL AS 'SELECT';",
            "CREATE FUNCTION count(value text) RETURNS text LANGUAGE SQL AS 'SELECT value';",
        ])
        .expect("function catalog should parse")
    }

    #[test]
    fn should_resolve_schema_function_defaults_named_arguments_and_params() {
        let catalog = function_catalog();
        let query = parse_query("-- @name FunctionCall\n-- @returns :one\nSELECT label(value => $1) AS result;")
            .expect("query should parse");
        let analyzed = analyze(&catalog, &query).expect("function should resolve");
        assert_eq!(analyzed.columns[0].neutral_type, "string");
        assert!(analyzed.columns[0].nullable);
        assert_eq!(analyzed.params[0].name, "value");
        assert_eq!(analyzed.params[0].neutral_type, "int32");
    }

    #[test]
    fn should_prefer_exact_function_over_numeric_widening() {
        let catalog = function_catalog();
        let query = parse_query(
            "-- @name FunctionCall\n-- @returns :many\nSELECT promoted(integer_value) AS widened FROM values_table;",
        )
        .expect("query should parse");
        let analyzed = analyze(&catalog, &query).expect("numeric widening should resolve");
        assert_eq!(analyzed.columns[0].neutral_type, "int64");
    }

    #[test]
    fn should_report_equal_best_function_overloads_as_ambiguous() {
        let catalog = function_catalog();
        let query = parse_query("-- @name FunctionCall\n-- @returns :one\nSELECT choose($1) AS result;")
            .expect("query should parse");
        let error = analyze(&catalog, &query).expect_err("unknown placeholder cannot disambiguate overloads");
        assert_eq!(error.code, crate::errors::ErrorCode::AmbiguousFunction);
    }

    #[test]
    fn should_keep_builtin_function_precedence() {
        let catalog = function_catalog();
        let query = parse_query("-- @name FunctionCall\n-- @returns :one\nSELECT count('x') AS result;")
            .expect("query should parse");
        let analyzed = analyze(&catalog, &query).expect("builtin should resolve");
        assert_eq!(analyzed.columns[0].neutral_type, "int64");
        assert!(!analyzed.columns[0].nullable);
    }

    #[test]
    fn should_bind_variadic_schema_function_arguments() {
        let catalog = function_catalog();
        let query = parse_query("-- @name FunctionCall\n-- @returns :one\nSELECT join_ids(1, 2, 3) AS result;")
            .expect("query should parse");
        let analyzed = analyze(&catalog, &query).expect("variadic arguments should resolve");
        assert_eq!(analyzed.columns[0].neutral_type, "string");
    }

    #[test]
    fn should_report_incompatible_schema_function_arguments() {
        let catalog = function_catalog();
        let query = parse_query("-- @name FunctionCall\n-- @returns :one\nSELECT promoted('wrong') AS result;")
            .expect("query should parse");
        let error = analyze(&catalog, &query).expect_err("string cannot bind to bigint");
        assert_eq!(error.code, crate::errors::ErrorCode::TypeMismatch);
    }

    #[test]
    fn should_expand_catalog_table_function_columns_and_aliases() {
        let catalog = function_catalog();
        let query = parse_query(
            "-- @name FunctionRows\n-- @returns :many\nSELECT total, name FROM item_rows('x') AS rows(total, name);",
        )
        .expect("query should parse");
        let analyzed = analyze(&catalog, &query).expect("table function should resolve");
        assert_eq!(analyzed.columns[0].neutral_type, "int64");
        assert_eq!(analyzed.columns[1].neutral_type, "string");
    }

    #[test]
    fn should_resolve_catalog_set_function_in_lateral_function_ast_form() {
        let catalog = function_catalog();
        let query = parse_query(
            "-- @name FunctionRows\n-- @returns :many\nSELECT name FROM LATERAL item_names('x') AS names(name);",
        )
        .expect("query should parse");
        let analyzed = analyze(&catalog, &query).expect("lateral function should resolve");
        assert_eq!(analyzed.columns[0].neutral_type, "string");
    }

    #[test]
    fn should_bind_placeholders_in_variadic_catalog_function_from_calls() {
        let catalog = Catalog::from_ddl(&[
            "CREATE FUNCTION expanded(VARIADIC values bigint[]) RETURNS SETOF bigint LANGUAGE SQL AS 'SELECT';",
        ])
        .expect("function catalog should parse");
        let query =
            parse_query("-- @name Expanded\n-- @returns :many\nSELECT value FROM expanded($1, $2) AS rows(value);")
                .expect("query should parse");

        let analyzed = analyze(&catalog, &query).expect("FROM-call placeholders should bind");
        assert_eq!(analyzed.params.len(), 2);
        assert!(
            analyzed
                .params
                .iter()
                .all(|parameter| parameter.neutral_type == "int64")
        );
    }

    #[test]
    fn should_prefer_exact_sql_type_when_neutral_types_are_equal() {
        let catalog = Catalog::from_ddl(&[
            "CREATE TABLE labels (value varchar(20) NOT NULL);",
            "CREATE FUNCTION classify(value text) RETURNS text LANGUAGE SQL AS 'SELECT value';",
            "CREATE FUNCTION classify(value varchar(20)) RETURNS bigint LANGUAGE SQL AS 'SELECT 1';",
        ])
        .expect("function overloads should parse");
        let query = parse_query("-- @name Classify\n-- @returns :many\nSELECT classify(value) AS result FROM labels;")
            .expect("query should parse");

        let analyzed = analyze(&catalog, &query).expect("varchar overload should win over text");
        assert_eq!(analyzed.columns[0].neutral_type, "int64");
    }

    #[test]
    fn should_prefer_domain_over_base_type_overload() {
        use crate::catalog::{
            CatalogBuilder, CatalogObjectName, ColumnDefinition, DomainDefinition, FunctionArgumentDefinition,
            FunctionDefinition, FunctionReturnDefinition, RelationDefinition,
        };

        let catalog = CatalogBuilder::new(crate::dialect::SqlDialect::PostgreSQL)
            .domain(DomainDefinition::new(
                CatalogObjectName::new("user_id"),
                "integer",
                true,
            ))
            .relation(RelationDefinition::table(
                CatalogObjectName::new("users"),
                vec![ColumnDefinition::new("id", "user_id", false)],
            ))
            .function(FunctionDefinition::new(
                CatalogObjectName::new("identify"),
                vec![FunctionArgumentDefinition::new("integer")],
                FunctionReturnDefinition::Scalar("text".to_string()),
            ))
            .function(FunctionDefinition::new(
                CatalogObjectName::new("identify"),
                vec![FunctionArgumentDefinition::new("user_id")],
                FunctionReturnDefinition::Scalar("bigint".to_string()),
            ))
            .build()
            .expect("live-style catalog should build");
        let query = parse_query("-- @name Identify\n-- @returns :many\nSELECT identify(id) AS result FROM users;")
            .expect("query should parse");

        let analyzed = analyze(&catalog, &query).expect("domain overload should win over its base type");
        assert_eq!(analyzed.columns[0].neutral_type, "int64");
    }

    #[test]
    fn should_report_catalog_record_returns_in_select_and_from() {
        let catalog = Catalog::from_ddl(&[
            "CREATE FUNCTION anonymous_row(value integer) RETURNS record LANGUAGE SQL AS 'SELECT value';",
        ])
        .expect("record-returning function should be cataloged");
        for sql in [
            "-- @name RecordSelect\n-- @returns :one\nSELECT anonymous_row(1) AS result;",
            "-- @name RecordFrom\n-- @returns :many\nSELECT result FROM anonymous_row(1) AS rows(result);",
        ] {
            let query = parse_query(sql).expect("query should parse");
            let error = analyze(&catalog, &query).expect_err("anonymous record must be rejected before codegen");
            assert_eq!(error.code, crate::errors::ErrorCode::UnresolvedType);
            assert!(error.message.contains("RETURNS TABLE/OUT"), "got: {}", error.message);
        }
    }

    #[test]
    fn should_resolve_named_composite_function_returns() {
        let catalog = Catalog::from_ddl(&[
            "CREATE TYPE payload AS (id bigint, label text);",
            "CREATE FUNCTION make_payload() RETURNS payload LANGUAGE SQL AS 'SELECT';",
        ])
        .expect("composite-returning function should be cataloged");
        let select_query = parse_query("-- @name PayloadValue\n-- @returns :one\nSELECT make_payload() AS payload;")
            .expect("query should parse");
        let from_query =
            parse_query("-- @name PayloadFields\n-- @returns :many\nSELECT id, label FROM make_payload();")
                .expect("query should parse");

        let selected = analyze(&catalog, &select_query).expect("named composite should resolve in SELECT");
        assert_eq!(selected.columns[0].neutral_type, "composite::payload");
        let expanded = analyze(&catalog, &from_query).expect("named composite should expand in FROM");
        assert_eq!(expanded.columns[0].neutral_type, "int64");
        assert_eq!(expanded.columns[1].neutral_type, "string");
    }

    #[test]
    fn should_resolve_lateral_derived_table_references_to_preceding_from_items() {
        let catalog = Catalog::from_ddl(&[
            "CREATE TYPE payment_status AS ENUM ('pending', 'succeeded');",
            "CREATE FUNCTION payment_status(stored character varying) RETURNS payment_status \
             LANGUAGE sql IMMUTABLE RETURN stored::payment_status;",
            "CREATE TABLE transactions (id integer PRIMARY KEY, payment_status character varying(255) NOT NULL);",
        ])
        .expect("schema should parse");
        let query = parse_query(
            "-- @name Statuses\n-- @returns :many\n\
             SELECT t.id, a.status, a.label FROM transactions t \
             CROSS JOIN LATERAL (SELECT payment_status(t.payment_status) AS status, t.payment_status AS label) a;",
        )
        .expect("query should parse");
        let result = analyze(&catalog, &query).expect("LATERAL may reference preceding FROM items");
        assert_eq!(result.columns[1].neutral_type, "enum::payment_status");
        assert_eq!(result.columns[2].neutral_type, "string");
        assert!(!result.columns[2].nullable);
    }

    #[test]
    fn should_not_resolve_sibling_references_in_a_derived_table_without_lateral() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name Sibling\n-- @returns :many\n\
             SELECT d.name FROM users u, (SELECT u.name) d;",
        )
        .expect("query should parse");
        let error = analyze(&catalog, &query).expect_err("a plain derived table cannot see its siblings");
        assert!(error.message.contains("name"), "got: {}", error.message);
    }

    #[test]
    fn should_resolve_correlated_scalar_subquery_references_to_the_enclosing_query() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name LatestTitle\n-- @returns :many\n\
             SELECT u.id, (SELECT u.score FROM posts p WHERE p.user_id = u.id LIMIT 1) AS latest \
             FROM users u;",
        )
        .expect("query should parse");
        let result = analyze(&catalog, &query).expect("correlated references should resolve");
        assert_eq!(result.columns[1].neutral_type, "decimal");
        assert!(result.columns[1].nullable, "a scalar subquery may match no rows");
    }

    #[test]
    fn should_prefer_the_inner_source_when_a_correlated_name_is_shadowed() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name Shadowed\n-- @returns :many\n\
             SELECT (SELECT id FROM posts WHERE posts.user_id = users.id LIMIT 1) AS post_id FROM users;",
        )
        .expect("query should parse");
        let result = analyze(&catalog, &query).expect("the unqualified name resolves to posts.id");
        assert_eq!(result.columns[0].neutral_type, "int32");
    }

    #[test]
    fn should_type_array_subquery_as_non_null_array_of_its_column() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name UserPostTitles\n-- @returns :many\n\
             SELECT u.id, ARRAY(SELECT p.title FROM posts p WHERE p.user_id = u.id ORDER BY p.id) AS titles, \
             ARRAY(SELECT p.body FROM posts p WHERE p.user_id = u.id) AS bodies \
             FROM users u;",
        )
        .expect("query should parse");
        let result = analyze(&catalog, &query).expect("ARRAY(subquery) should resolve");
        assert_eq!(result.columns[1].neutral_type, "array<string>");
        assert!(!result.columns[1].nullable, "no rows give an empty array, not NULL");
        assert_eq!(result.columns[2].neutral_type, "array<string>");
        assert!(!result.columns[2].nullable);
    }

    #[test]
    fn should_type_array_subquery_in_a_view_through_coalesce() {
        let catalog = Catalog::from_ddl(&[
            "CREATE TABLE articles (id integer PRIMARY KEY, title text NOT NULL);",
            "CREATE TABLE article_tags (article_id integer NOT NULL, tag varchar(40) NOT NULL);",
            "CREATE VIEW article_summaries AS SELECT a.id, \
             coalesce(ARRAY(SELECT t.tag::text FROM article_tags t WHERE t.article_id = a.id ORDER BY t.tag), '{}') \
             AS tags FROM articles a;",
        ])
        .expect("a view with ARRAY(subquery) should parse");
        let query = parse_query("-- @name Tags\n-- @returns :many\nSELECT tags FROM article_summaries;")
            .expect("query should parse");
        let result = analyze(&catalog, &query).expect("the view column should resolve");
        assert_eq!(result.columns[0].neutral_type, "array<string>");
        assert!(!result.columns[0].nullable);
    }

    #[test]
    fn should_reject_array_subquery_with_more_than_one_column() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name Pairs\n-- @returns :many\nSELECT ARRAY(SELECT p.id, p.title FROM posts p) AS pairs FROM users;",
        )
        .expect("query should parse");
        let error = analyze(&catalog, &query).expect_err("ARRAY(subquery) takes one column");
        assert!(error.message.contains("only one column"), "got: {}", error.message);
    }

    fn allocation_catalog() -> Catalog {
        Catalog::from_ddl(&[
            "CREATE TABLE schedules (id integer PRIMARY KEY, causes jsonb NOT NULL);",
            "CREATE TABLE causes (id text PRIMARY KEY, title text NOT NULL);",
        ])
        .expect("schema should parse")
    }

    #[test]
    fn should_type_record_function_columns_from_a_column_definition_list() {
        let catalog = allocation_catalog();
        for sql in [
            "SELECT s.id, allocation.id AS cause, allocation.amount \
             FROM schedules s, jsonb_to_recordset(s.causes) AS allocation(id text, amount integer)",
            "SELECT s.id, allocation.id AS cause, allocation.amount \
             FROM schedules s JOIN jsonb_to_recordset(s.causes) AS allocation(id text, amount integer) ON true",
            "SELECT s.id, allocation.id AS cause, allocation.amount \
             FROM schedules s CROSS JOIN LATERAL json_to_recordset(s.causes::json) AS allocation(id text, amount int)",
        ] {
            let query =
                parse_query(&format!("-- @name Allocations\n-- @returns :many\n{sql};")).expect("query should parse");
            let result = analyze(&catalog, &query).expect("a column definition list types the record");
            let types: Vec<_> = result
                .columns
                .iter()
                .map(|c| (c.neutral_type.as_str(), c.nullable))
                .collect();
            assert_eq!(
                types,
                [("int32", false), ("string", true), ("int32", true)],
                "for {sql}"
            );
        }
    }

    #[test]
    fn should_type_json_input_of_a_record_function_parameter() {
        let catalog = allocation_catalog();
        let query = parse_query(
            "-- @name Parse\n-- @returns :many\nSELECT x.id FROM jsonb_to_record($1) AS x(id bigint, note text);",
        )
        .expect("query should parse");
        let result = analyze(&catalog, &query).expect("the parameter takes JSON");
        assert_eq!(result.params[0].neutral_type, "json");
        assert_eq!(result.columns[0].neutral_type, "int64");
        assert!(result.columns[0].nullable);
    }

    #[test]
    fn should_type_catalog_record_function_from_a_column_definition_list() {
        let catalog =
            Catalog::from_ddl(&["CREATE FUNCTION pairs() RETURNS SETOF record LANGUAGE SQL AS 'SELECT 1, ''a''';"])
                .expect("record-returning function should be cataloged");
        let query =
            parse_query("-- @name Pairs\n-- @returns :many\nSELECT n, label FROM pairs() AS p(n integer, label text);")
                .expect("query should parse");
        let result = analyze(&catalog, &query).expect("a column definition list types the record");
        assert_eq!(result.columns[0].neutral_type, "int32");
        assert_eq!(result.columns[1].neutral_type, "string");
    }

    #[test]
    fn should_require_a_column_definition_list_for_unknown_record_functions() {
        let catalog = allocation_catalog();
        let query = parse_query(
            "-- @name Untyped\n-- @returns :many\nSELECT a.id FROM schedules s, jsonb_to_recordset(s.causes) AS a(id);",
        )
        .expect("query should parse");
        let error = analyze(&catalog, &query).expect_err("columns without types cannot be typed");
        assert_eq!(error.code, crate::errors::ErrorCode::UnknownTable);
    }

    #[test]
    fn should_type_ordered_string_agg_over_a_record_function_in_a_scalar_subquery() {
        let catalog = allocation_catalog();
        let query = parse_query(
            "-- @name CauseTitles\n-- @returns :many\n\
             SELECT s.id, (SELECT string_agg(ca.title, ', ' ORDER BY ca.id) \
             FROM jsonb_to_recordset(s.causes) AS allocation(id text, amount integer) \
             JOIN causes ca ON ca.id = allocation.id) AS titles \
             FROM schedules s;",
        )
        .expect("query should parse");
        let result = analyze(&catalog, &query).expect("the subquery should resolve");
        assert_eq!(result.columns[1].neutral_type, "string");
        assert!(result.columns[1].nullable, "string_agg over no rows is NULL");
    }

    #[test]
    fn should_type_placeholders_used_as_boolean_operands_as_bool() {
        let catalog = make_catalog();
        let query = parse_query(
            "-- @name Filtered\n-- @returns :many\n\
             SELECT id FROM users WHERE (NOT $1 OR age IS NULL) AND (($2) OR active) AND NOT ($3);",
        )
        .expect("query should parse");
        let result = analyze(&catalog, &query).expect("NOT, AND and OR operands are boolean");
        let types: Vec<_> = result
            .params
            .iter()
            .map(|p| (p.position, p.neutral_type.as_str()))
            .collect();
        assert_eq!(types, [(1, "bool"), (2, "bool"), (3, "bool")]);
    }

    fn param_types(result: &AnalyzedQuery) -> Vec<(i64, &str)> {
        result
            .params
            .iter()
            .map(|p| (p.position, p.neutral_type.as_str()))
            .collect()
    }

    #[test]
    fn should_collect_placeholders_inside_case_branches_and_their_subqueries() {
        let result = analyze_sql(
            "-- @name Search\n-- @returns :many\n\
             SELECT u.id FROM users u WHERE CASE WHEN $1::boolean THEN u.id = $2 \
             ELSE ($3::text IS NOT NULL AND EXISTS (SELECT 1 FROM posts p WHERE p.user_id = u.id AND p.title = $3)) \
             END;",
        )
        .expect("every CASE branch is analyzed");
        assert_eq!(param_types(&result), [(1, "bool"), (2, "int32"), (3, "string")]);
    }

    #[test]
    fn should_collect_placeholders_in_order_by_group_by_and_join_conditions() {
        let result = analyze_sql(
            "-- @name Sorted\n-- @returns :many\n\
             SELECT u.id, count(p.id) AS posts FROM users u \
             JOIN posts p ON p.user_id = u.id AND p.published = $1 \
             GROUP BY u.id, $2::text \
             ORDER BY (CASE WHEN $3 THEN u.name END) ASC, CASE WHEN $4 = 'age' THEN u.age END;",
        )
        .expect("ON, GROUP BY and ORDER BY placeholders are parameters");
        assert_eq!(
            param_types(&result),
            [(1, "bool"), (2, "string"), (3, "bool"), (4, "string")]
        );
    }

    #[test]
    fn should_type_unnest_and_ordinality_columns_in_from() {
        let result = analyze_sql(
            "-- @name Tags\n-- @returns :many\n\
             SELECT tag, e.item, e.n FROM unnest($1::text[]) AS tag, \
             jsonb_array_elements($2::jsonb) WITH ORDINALITY AS e(item, n);",
        )
        .expect("FROM-clause function arguments and columns resolve");
        assert_eq!(param_types(&result), [(1, "array<string>"), (2, "json")]);
        let columns: Vec<_> = result
            .columns
            .iter()
            .map(|c| (c.name.as_str(), c.neutral_type.as_str(), c.nullable))
            .collect();
        assert_eq!(
            columns,
            [("tag", "string", true), ("item", "json", true), ("n", "int64", false)]
        );
    }

    #[test]
    fn should_type_rows_of_a_multi_array_unnest_in_a_subquery() {
        let result = analyze_sql(
            "-- @name DeletePairs\n-- @returns :exec\n\
             DELETE FROM posts WHERE (user_id, title) IN (SELECT * FROM unnest($1::integer[], $2::text[]));",
        )
        .expect("an IN subquery's FROM placeholders are parameters");
        assert_eq!(param_types(&result), [(1, "array<int32>"), (2, "array<string>")]);
    }

    #[test]
    fn should_collect_placeholders_of_data_modifying_ctes() {
        let result = analyze_sql(
            "-- @name DeleteUsers\n-- @returns :exec\n\
             WITH removed AS (DELETE FROM posts WHERE user_id = ANY($1::integer[])), \
             renamed AS (UPDATE comments SET body = $2 WHERE user_id = ANY($1)) \
             DELETE FROM users WHERE id = ANY($1);",
        )
        .expect("data-modifying CTEs are analyzed");
        assert_eq!(param_types(&result), [(1, "array<int32>"), (2, "string")]);
    }

    #[test]
    fn should_type_insert_select_placeholders_by_their_target_columns() {
        let result = analyze_sql(
            "-- @name CopyTitles\n-- @returns :exec\n\
             INSERT INTO posts (user_id, title) \
             SELECT $1, t FROM unnest($2::text[]) WITH ORDINALITY AS x(t, n) ORDER BY x.n \
             ON CONFLICT DO NOTHING;",
        )
        .expect("a select-list placeholder takes its target column's type");
        assert_eq!(param_types(&result), [(1, "int32"), (2, "array<string>")]);
        assert_eq!(result.params[0].name, "user_id");
    }

    #[test]
    fn should_type_a_placeholder_compared_with_any_of_an_array_expression() {
        let catalog =
            Catalog::from_ddl(&["CREATE TABLE teams (id integer PRIMARY KEY, member_ids integer[] NOT NULL);"])
                .expect("schema should parse");
        let query = parse_query(
            "-- @name Teams\n-- @returns :many\n\
             SELECT id FROM teams WHERE $1 = ANY(member_ids) AND $2::bigint <> ALL(member_ids);",
        )
        .expect("query should parse");
        let result = analyze(&catalog, &query).expect("the placeholder is an array element");
        assert_eq!(param_types(&result), [(1, "int32"), (2, "int64")]);
    }

    #[test]
    fn should_collect_placeholders_nested_in_update_assignments() {
        let result = analyze_sql(
            "-- @name Retitle\n-- @returns :exec\n\
             UPDATE posts SET title = (SELECT u.name FROM users u WHERE u.id = $1) WHERE id = $2;",
        )
        .expect("a subquery in SET is analyzed");
        assert_eq!(param_types(&result), [(1, "int32"), (2, "int32")]);
    }

    #[test]
    fn should_register_placeholders_inference_never_reaches() {
        let result = analyze_sql(
            "-- @name Page\n-- @returns :many\n\
             SELECT id FROM users ORDER BY id OFFSET $1 ROWS FETCH NEXT $2 ROWS ONLY;",
        )
        .expect("query should analyze");
        let positions: Vec<_> = result.params.iter().map(|p| p.position).collect();
        assert_eq!(positions, [1, 2], "no placeholder is dropped from the signature");
    }

    fn reminder_catalog() -> Catalog {
        Catalog::from_ddl(&[
            "CREATE TABLE users (id text PRIMARY KEY, email text NOT NULL);",
            "CREATE TABLE reminders (\"userId\" text NOT NULL, topic text NOT NULL, PRIMARY KEY (\"userId\", topic));",
        ])
        .expect("schema should parse")
    }

    #[test]
    fn should_keep_the_case_of_quoted_column_identifiers() {
        let catalog = reminder_catalog();
        let query = parse_query(
            "-- @name Subscriber\n-- @returns :many\n\
             SELECT u.email, r.\"userId\", \"userId\" AS \"ownerId\" FROM reminders r \
             JOIN users u ON u.id = r.\"userId\" WHERE r.\"userId\" = $1 AND r.topic = $2;",
        )
        .expect("query should parse");
        let result = analyze(&catalog, &query).expect("a quoted identifier names its exact column");
        let names: Vec<_> = result.columns.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["email", "userId", "ownerId"]);
        assert_eq!(param_types(&result), [(1, "string"), (2, "string")]);
    }

    #[test]
    fn should_bind_writes_to_quoted_columns_by_their_exact_name() {
        let catalog = reminder_catalog();
        let query = parse_query(
            "-- @name Save\n-- @returns :exec\n\
             INSERT INTO reminders (\"userId\", topic) VALUES ($1, $2) ON CONFLICT (\"userId\", topic) \
             DO UPDATE SET \"userId\" = $3;",
        )
        .expect("query should parse");
        let result = analyze(&catalog, &query).expect("quoted target columns resolve");
        assert_eq!(param_types(&result), [(1, "string"), (2, "string"), (3, "string")]);
        let names: Vec<_> = result.params.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["userId_1", "topic", "userId_2"]);
    }

    #[test]
    fn should_fold_unquoted_identifiers_that_name_a_quoted_column() {
        let catalog = reminder_catalog();
        let query = parse_query("-- @name Folded\n-- @returns :many\nSELECT r.userId FROM reminders r;")
            .expect("query should parse");
        let error = analyze(&catalog, &query).expect_err("an unquoted userId folds to userid, which does not exist");
        assert!(error.message.contains("userid"), "got: {}", error.message);
    }

    #[test]
    fn should_resolve_aliased_update_targets_in_correlated_subqueries_and_returning() {
        let result = analyze_sql(
            "-- @name Unpublish\n-- @returns :many\n\
             UPDATE posts p SET published = false, title = (SELECT u.name FROM users u WHERE u.id = p.user_id) \
             WHERE p.user_id = $1 AND NOT EXISTS (SELECT 1 FROM comments c WHERE c.post_id = p.id AND c.user_id = $2) \
             RETURNING p.id, (SELECT u.email FROM users u WHERE u.id = p.user_id) AS email;",
        )
        .expect("the target alias is in scope everywhere");
        assert_eq!(param_types(&result), [(1, "int32"), (2, "int32")]);
        let columns: Vec<_> = result
            .columns
            .iter()
            .map(|c| (c.name.as_str(), c.neutral_type.as_str()))
            .collect();
        assert_eq!(columns, [("id", "int32"), ("email", "string")]);
    }

    #[test]
    fn should_resolve_aliased_delete_targets_in_correlated_subqueries() {
        let result = analyze_sql(
            "-- @name DeleteSilent\n-- @returns :many\n\
             DELETE FROM posts p WHERE p.user_id = $1 \
             AND NOT EXISTS (SELECT 1 FROM comments c WHERE c.post_id = p.id) RETURNING p.title;",
        )
        .expect("the target alias is in scope");
        assert_eq!(param_types(&result), [(1, "int32")]);
        assert_eq!(result.columns[0].neutral_type, "string");
    }

    #[test]
    fn should_resolve_aliased_insert_targets_and_excluded_in_on_conflict() {
        let result = analyze_sql(
            "-- @name Upsert\n-- @returns :many\n\
             INSERT INTO posts AS p (id, user_id, title) VALUES ($1, $2, $3) \
             ON CONFLICT (id) DO UPDATE SET title = excluded.title WHERE p.title <> $4 \
             RETURNING p.id;",
        )
        .expect("the insert alias and excluded are in scope");
        assert_eq!(
            param_types(&result),
            [(1, "int32"), (2, "int32"), (3, "string"), (4, "string")]
        );
    }

    fn brand_catalog() -> Catalog {
        Catalog::from_ddl(&[
            "CREATE TYPE brand AS ENUM ('myfajr', 'myfridays');",
            "CREATE DOMAIN code AS character varying(8);",
            "CREATE FUNCTION record_type(brand brand) RETURNS character varying LANGUAGE sql IMMUTABLE STRICT \
             RETURN brand::text;",
            "CREATE FUNCTION described(value text) RETURNS text LANGUAGE sql RETURN value;",
            "CREATE FUNCTION described(value brand) RETURNS integer LANGUAGE sql RETURN 1;",
            "CREATE FUNCTION decoded(value code) RETURNS brand LANGUAGE sql RETURN 'myfajr';",
            "CREATE TABLE schedules (id integer PRIMARY KEY, brand brand NOT NULL, \
             record_type character varying(255) NOT NULL);",
        ])
        .expect("schema should parse")
    }

    #[test]
    fn should_resolve_enum_function_arguments_from_literals_columns_and_casts() {
        let catalog = brand_catalog();
        let query = parse_query(
            "-- @name Friday\n-- @returns :many\n\
             SELECT record_type(brand) AS code, decoded(record_type) AS decoded FROM schedules \
             WHERE record_type = record_type('myfridays') AND record_type = record_type($1::brand) \
             AND record_type <> record_type($2);",
        )
        .expect("query should parse");
        let result = analyze(&catalog, &query).expect("enum and domain arguments resolve");
        let columns: Vec<_> = result.columns.iter().map(|c| c.neutral_type.as_str()).collect();
        assert_eq!(columns, ["string", "enum::brand"]);
        assert_eq!(param_types(&result), [(1, "enum::brand"), (2, "enum::brand")]);
    }

    #[test]
    fn should_prefer_a_string_overload_for_an_untyped_literal() {
        let catalog = brand_catalog();
        let query = parse_query(
            "-- @name Described\n-- @returns :one\nSELECT described('myfajr') AS text_overload, \
             described('myfajr'::brand) AS enum_overload;",
        )
        .expect("query should parse");
        let result = analyze(&catalog, &query).expect("a literal prefers the string overload");
        let columns: Vec<_> = result.columns.iter().map(|c| c.neutral_type.as_str()).collect();
        assert_eq!(columns, ["string", "int32"]);
    }

    #[test]
    fn should_reject_a_literal_that_is_not_a_label_of_the_enum_argument() {
        let catalog = brand_catalog();
        let query = parse_query("-- @name Unknown\n-- @returns :one\nSELECT record_type('mytuesdays') AS code;")
            .expect("query should parse");
        let error = analyze(&catalog, &query).expect_err("mytuesdays is not a brand");
        assert_eq!(error.code, crate::errors::ErrorCode::TypeMismatch);
    }

    #[test]
    fn should_resolve_postgres_builtin_lock_hash_and_setting_functions() {
        let result = analyze_sql(
            "-- @name Lock\n-- @returns :one\n\
             SELECT pg_advisory_xact_lock(hashtextextended($1, 0)) AS locked, \
             pg_try_advisory_xact_lock($2, $3) AS tried, \
             set_config('statement_timeout', $4::text, true) AS timeout, \
             current_setting('app.user', true) AS app_user;",
        )
        .expect("built-in functions resolve");
        let columns: Vec<_> = result
            .columns
            .iter()
            .map(|c| (c.name.as_str(), c.neutral_type.as_str()))
            .collect();
        assert_eq!(
            columns,
            [
                ("locked", "string"),
                ("tried", "bool"),
                ("timeout", "string"),
                ("app_user", "string")
            ]
        );
        assert!(result.columns[3].nullable, "a missing setting reads as null");
        assert_eq!(
            param_types(&result),
            [(1, "string"), (2, "int32"), (3, "int32"), (4, "string")]
        );
        assert!(result.params.iter().all(|p| !p.nullable));
    }

    #[test]
    fn should_prefer_a_schema_function_over_a_builtin_of_the_same_name() {
        let catalog =
            Catalog::from_ddl(&["CREATE FUNCTION hashtext(value integer) RETURNS integer LANGUAGE sql RETURN value;"])
                .expect("schema should parse");
        let query =
            parse_query("-- @name Hash\n-- @returns :one\nSELECT hashtext($1) AS hash;").expect("query should parse");
        let result = analyze(&catalog, &query).expect("the schema's function resolves");
        assert_eq!(param_types(&result), [(1, "int32")]);
    }

    #[test]
    fn should_resolve_pg_stat_activity_and_pg_blocking_pids() {
        let result = analyze_sql(
            "-- @name Blocked\n-- @returns :one\n\
             SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1::integer = ANY(pg_blocking_pids(pid))) AS blocked, \
             (SELECT count(*) FROM pg_catalog.pg_stat_activity a WHERE a.state = $2) AS active;",
        )
        .expect("the system view resolves");
        assert_eq!(param_types(&result), [(1, "int32"), (2, "string")]);
        let error = analyze_sql("-- @name Oids\n-- @returns :many\nSELECT datid FROM pg_stat_activity;")
            .expect_err("an oid column has no neutral type");
        assert!(error.message.contains("datid"), "got: {}", error.message);
    }

    #[test]
    fn should_type_placeholders_of_builtin_date_and_string_functions() {
        let result = analyze_sql(
            "-- @name Series\n-- @returns :many\n\
             SELECT to_char(date_trunc($1, created_at AT TIME ZONE 'UTC'), $2) AS bucket FROM users \
             WHERE starts_with(name, $3) GROUP BY 1;",
        )
        .expect("built-in argument types type the placeholders");
        assert_eq!(param_types(&result), [(1, "string"), (2, "string"), (3, "string")]);
        let names: Vec<_> = result.params.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["field", "format", "prefix"]);
    }

    #[test]
    fn should_type_placeholder_operands_of_json_operators() {
        let catalog = Catalog::from_ddl(&["CREATE TABLE audit_logs (id integer PRIMARY KEY, data jsonb NOT NULL);"])
            .expect("schema should parse");
        let query = parse_query(
            "-- @name Recorded\n-- @returns :many\n\
             SELECT id FROM audit_logs WHERE data->>$1 = $2 AND data #>> $3 IS NOT NULL \
             AND data @> $4 AND data ? $5 AND data->$6 IS NOT NULL;",
        )
        .expect("query should parse");
        let result = analyze(&catalog, &query).expect("JSON operator operands are typed");
        assert_eq!(
            param_types(&result),
            [
                (1, "string"),
                (2, "string"),
                (3, "array<string>"),
                (4, "json"),
                (5, "string"),
                (6, "string")
            ]
        );
    }

    #[test]
    fn should_analyze_an_insert_select_list_that_ends_at_on_conflict() {
        let catalog = reminder_catalog();
        let query = parse_query(
            "-- @name AddReminders\n-- @returns :exec\n\
             INSERT INTO reminders (\"userId\", topic) SELECT $1, unnest($2::text[]) ON CONFLICT DO NOTHING;",
        )
        .expect("query should parse");
        let result = analyze(&catalog, &query).expect("the select list binds the target columns");
        assert_eq!(param_types(&result), [(1, "string"), (2, "array<string>")]);
        assert!(!result.sql.contains("WHERE true"), "codegen keeps the original SQL");
    }
}
