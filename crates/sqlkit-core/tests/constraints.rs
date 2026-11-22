//! Schema constraints: what the catalog records per column and domain, and
//! how the analyzer carries the resolved rules to result columns (straight
//! from a column, through views, CTEs and derived tables) and to parameters
//! written into a column.

use sqlkit_core::analyzer::{AnalyzedQuery, analyze};
use sqlkit_core::catalog::Catalog;
use sqlkit_core::constraints::{AllowedValue, Rules, ValueConstraints};
use sqlkit_core::parser::parse_query;

const SCHEMA: &str = "
CREATE DOMAIN slug AS text CHECK (VALUE ~ '^[a-z0-9-]+$');
CREATE DOMAIN currency_code AS varchar(3)
    CONSTRAINT currency_code_letters CHECK (VALUE ~ '^[a-zA-Z]{3}$');
CREATE DOMAIN amount AS integer NOT NULL CHECK (VALUE BETWEEN 0 AND 100000000);
CREATE DOMAIN positive_amount AS amount CHECK (VALUE > 0);
COMMENT ON DOMAIN amount IS 'An amount in minor units.';

CREATE TABLE causes (
    id serial PRIMARY KEY,
    slug slug NOT NULL,
    title varchar(255) NOT NULL CHECK (length(trim(title)) > 0),
    position integer CHECK (position >= 0),
    goal amount,
    currency currency_code NOT NULL,
    status varchar(20) NOT NULL,
    code char(4),
    ratio numeric(5, 2),
    notes text,
    CONSTRAINT causes_status CHECK ((status)::text = ANY ((ARRAY['draft'::character varying, 'live'::character varying])::text[])),
    CONSTRAINT causes_notes CHECK (octet_length(notes) < 1000 AND length(notes) <= 500),
    CONSTRAINT causes_scope CHECK (position IS NULL OR goal IS NOT NULL)
);
COMMENT ON COLUMN causes.title IS 'What the cause is called.';

CREATE VIEW live_causes AS SELECT id, slug, title AS name, goal, position + 1 AS rank FROM causes WHERE status = 'live';
";

fn catalog() -> Catalog {
    Catalog::from_ddl(&[SCHEMA]).expect("schema must parse")
}

fn constraints(relation: &str, column: &str) -> ValueConstraints {
    catalog()
        .column_constraints(relation, column)
        .unwrap_or_else(|| panic!("{relation}.{column} has constraints"))
}

fn analyzed(sql: &str) -> AnalyzedQuery {
    let catalog = catalog();
    let query = parse_query(sql).expect("query must parse");
    analyze(&catalog, &query).expect("query must analyze")
}

fn s(value: &str) -> Option<String> {
    Some(value.to_string())
}

#[test]
fn should_record_varchar_and_char_lengths() {
    assert_eq!(constraints("causes", "status").rules.max_length, Some(20));
    assert_eq!(constraints("causes", "code").rules.max_length, Some(4));
}

#[test]
fn should_record_numeric_precision_without_rules() {
    let catalog = catalog();
    let facts = catalog.column_constraint_facts("causes", "ratio").unwrap();
    assert_eq!(facts.precision, Some((5, 2)));
    assert_eq!(catalog.column_constraints("causes", "ratio"), None);
}

#[test]
fn should_translate_column_checks_and_comments() {
    let title = constraints("causes", "title");
    assert_eq!(title.description.as_deref(), Some("What the cause is called."));
    assert_eq!(
        title.rules,
        Rules {
            min_length: Some(1),
            max_length: Some(255),
            pattern: s("[^ ]"),
            ..Rules::default()
        }
    );
    assert!(title.untranslated.is_empty());
    assert_eq!(constraints("causes", "position").rules.minimum, s("0"));
}

#[test]
fn should_attach_table_checks_that_reference_one_column() {
    assert_eq!(
        constraints("causes", "status").rules.allowed,
        Some(vec![
            AllowedValue::String("draft".to_string()),
            AllowedValue::String("live".to_string())
        ])
    );
    // A check relating two columns is not a value rule of either.
    let position = constraints("causes", "position");
    assert!(position.untranslated.is_empty(), "{:?}", position.untranslated);
}

#[test]
fn should_keep_translated_parts_and_report_the_rest() {
    let notes = constraints("causes", "notes");
    assert_eq!(notes.rules.max_length, Some(500));
    assert_eq!(notes.untranslated.len(), 1);
    let entry = &notes.untranslated[0];
    assert_eq!(entry.source, "causes.notes");
    assert_eq!(entry.constraint, "causes_notes CHECK (octet_length(notes) < 1000)");
    assert!(entry.reason.contains("bytes"), "{}", entry.reason);
}

#[test]
fn should_apply_domain_constraints_to_columns() {
    let slug = constraints("causes", "slug");
    assert_eq!(slug.domain.as_deref(), Some("slug"));
    assert_eq!(slug.rules.pattern, s("^[a-z0-9\\-]+$"));

    let currency = constraints("causes", "currency");
    assert_eq!(currency.domain.as_deref(), Some("currency_code"));
    assert_eq!(currency.rules.max_length, Some(3));
    assert_eq!(currency.rules.pattern, s("^[a-zA-Z]{3}$"));

    let goal = constraints("causes", "goal");
    assert_eq!(goal.description.as_deref(), Some("An amount in minor units."));
    assert_eq!((goal.rules.minimum, goal.rules.maximum), (s("0"), s("100000000")));
}

#[test]
fn should_inherit_parent_domain_constraints() {
    let positive = catalog().domain_constraints("positive_amount").unwrap();
    assert_eq!(positive.domain.as_deref(), Some("positive_amount"));
    assert_eq!(positive.rules.exclusive_minimum, s("0"));
    assert_eq!(positive.rules.maximum, s("100000000"));
    assert_eq!(positive.description.as_deref(), Some("An amount in minor units."));
}

#[test]
fn should_parse_domain_checks_on_their_own_lines() {
    let catalog = Catalog::from_ddl(&[
        "CREATE DOMAIN public.code AS character varying(8)\n\tCONSTRAINT code_check CHECK ((length(TRIM(BOTH FROM VALUE)) > 0));",
    ])
    .unwrap();
    assert_eq!(catalog.get_domain_base_type("code"), Some("varchar(8)"));
    let code = catalog.domain_constraints("public.code").unwrap();
    assert_eq!(code.rules.max_length, Some(8));
    assert_eq!(code.rules.pattern, s("[^ ]"));
}

#[test]
fn should_follow_alter_table_constraints() {
    let catalog = Catalog::from_ddl(&[
        "CREATE TABLE t (a integer, b text);",
        "ALTER TABLE t ADD CONSTRAINT t_a CHECK (a < 10);",
        "ALTER TABLE t ADD COLUMN c varchar(5) CHECK (c <> '');",
        "ALTER TABLE t ADD CONSTRAINT t_b CHECK (b LIKE 'x%');",
        "ALTER TABLE t DROP CONSTRAINT t_b;",
        "ALTER TABLE t ALTER COLUMN b TYPE varchar(9);",
    ])
    .unwrap();
    assert_eq!(
        catalog.column_constraints("t", "a").unwrap().rules.exclusive_maximum,
        s("10")
    );
    let c = catalog.column_constraints("t", "c").unwrap();
    assert_eq!(c.rules.max_length, Some(5));
    assert_eq!(c.untranslated.len(), 1);
    let b = catalog.column_constraints("t", "b").unwrap();
    assert_eq!(
        b.rules,
        Rules {
            max_length: Some(9),
            ..Rules::default()
        }
    );
}

#[test]
fn should_carry_rules_to_result_columns() {
    let query = analyzed(
        "-- @name Get\n-- @returns :one\nSELECT c.title, c.slug AS handle, upper(c.title) AS loud FROM causes c WHERE c.id = $1;",
    );
    assert_eq!(
        query.columns[0].constraints.as_ref().unwrap().rules.max_length,
        Some(255)
    );
    assert_eq!(
        query.columns[1].constraints.as_ref().unwrap().domain.as_deref(),
        Some("slug")
    );
    assert_eq!(
        query.columns[2].constraints, None,
        "a computed column has no constraints"
    );
    assert_eq!(
        query.params[0].constraints, None,
        "a compared parameter takes no constraints"
    );
}

#[test]
fn should_carry_rules_through_views_ctes_and_outer_joins() {
    let query = analyzed(
        "-- @name Live\n-- @returns :many\n\
         WITH named AS (SELECT name, rank FROM live_causes)\n\
         SELECT n.name, n.rank, s.goal FROM named n LEFT JOIN (SELECT goal FROM causes) s ON true;",
    );
    let name = query.columns[0].constraints.as_ref().unwrap();
    assert_eq!(name.rules.max_length, Some(255));
    assert_eq!(name.description.as_deref(), Some("What the cause is called."));
    assert_eq!(query.columns[1].constraints, None);
    assert_eq!(query.columns[2].constraints.as_ref().unwrap().rules.minimum, s("0"));
}

#[test]
fn should_carry_rules_to_written_parameters() {
    let insert = analyzed(
        "-- @name Add\n-- @returns :exec\n\
         INSERT INTO causes (slug, title, currency, status, position) VALUES ($1, $2::text, $3, $4, coalesce($5, 0))\n\
         ON CONFLICT (slug) DO UPDATE SET title = $2;",
    );
    let rules = |i: usize| insert.params[i].constraints.as_ref().map(|c| c.rules.clone());
    assert_eq!(rules(0).unwrap().pattern, s("^[a-z0-9\\-]+$"));
    assert_eq!(rules(1).unwrap().max_length, Some(255));
    assert_eq!(rules(2).unwrap().max_length, Some(3));
    assert!(rules(3).unwrap().allowed.is_some());
    assert_eq!(
        rules(4),
        None,
        "a parameter written through coalesce is not written directly"
    );

    let update = analyzed("-- @name Move\n-- @returns :exec\nUPDATE causes SET position = $2 WHERE slug = $1;");
    assert_eq!(update.params[0].constraints, None);
    assert_eq!(update.params[1].constraints.as_ref().unwrap().rules.minimum, s("0"));
}

#[test]
fn should_require_every_column_a_parameter_is_written_into() {
    let query = analyzed("-- @name Two\n-- @returns :exec\nUPDATE causes SET title = $1, code = $1 WHERE id = $2;");
    let rules = &query.params[0].constraints.as_ref().unwrap().rules;
    assert_eq!(rules.max_length, Some(4));
    assert_eq!(rules.pattern, s("[^ ]"));
}

#[test]
fn should_name_the_base_column_of_columns_and_written_parameters() {
    let name = |column: Option<&sqlkit_core::catalog::ColumnOrigin>| column.map(|c| c.name());
    let query = analyzed(
        "-- @name Live\n-- @returns :many\n\
         WITH named AS (SELECT name, rank FROM live_causes)\n\
         SELECT n.name, n.rank, s.goal, length(n.name) AS size FROM named n LEFT JOIN (SELECT goal FROM causes) s ON true;",
    );
    let columns: Vec<_> = query.columns.iter().map(|c| name(c.base_column.as_ref())).collect();
    assert_eq!(
        columns,
        [s("causes.title"), s("live_causes.rank"), s("causes.goal"), None],
        "views resolve to their table column, a computed view column stays the view's"
    );

    let insert = analyzed(
        "-- @name Add\n-- @returns :exec\n\
         INSERT INTO causes (slug, title, status) VALUES ($1, $2, coalesce($3, 'draft')) RETURNING id;",
    );
    let params: Vec<_> = insert.params.iter().map(|p| name(p.base_column.as_ref())).collect();
    assert_eq!(params, [s("causes.slug"), s("causes.title"), None]);

    let two = analyzed("-- @name Two\n-- @returns :exec\nUPDATE causes SET title = $1, code = $1 WHERE id = $2;");
    assert_eq!(two.params[0].base_column, None, "written into two columns");
    assert_eq!(two.params[1].base_column, None, "a comparison is not a write");
}

#[test]
fn should_name_the_base_column_of_returning_wildcards() {
    let name = |column: Option<&sqlkit_core::catalog::ColumnOrigin>| column.map(|c| c.name());
    for returning in ["*", "c.*", "c.id, c.title"] {
        let query = analyzed(&format!(
            "-- @name Add\n-- @returns :one\n\
             INSERT INTO causes AS c (slug, title, currency, status) VALUES ($1, $2, $3, $4) RETURNING {returning};"
        ));
        let columns: Vec<_> = query
            .columns
            .iter()
            .filter(|c| c.name == "id" || c.name == "title")
            .map(|c| name(c.base_column.as_ref()))
            .collect();
        assert_eq!(columns, [s("causes.id"), s("causes.title")], "RETURNING {returning}");
    }
}
