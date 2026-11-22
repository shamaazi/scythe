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
fn should_not_turn_numeric_precision_into_rules() {
    assert_eq!(catalog().column_constraints("causes", "ratio"), None);
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

#[test]
fn should_leave_not_valid_checks_out_of_read_values_only() {
    let catalog = Catalog::from_ddl(&[
        "CREATE TABLE t (a integer, b integer);",
        "ALTER TABLE t ADD CONSTRAINT t_a CHECK (a < 10) NOT VALID;",
        "ALTER TABLE t ADD CONSTRAINT t_b CHECK (b < 10) NOT VALID;",
        "ALTER TABLE t VALIDATE CONSTRAINT t_b;",
    ])
    .unwrap();
    assert_eq!(catalog.column_constraints("t", "a"), None);
    assert_eq!(
        catalog
            .written_column_constraints("t", "a")
            .unwrap()
            .rules
            .exclusive_maximum,
        s("10")
    );
    assert_eq!(
        catalog.column_constraints("t", "b").unwrap().rules.exclusive_maximum,
        s("10")
    );

    let query = {
        let query = parse_query("-- @name Set\n-- @returns :one\nUPDATE t SET a = $1 RETURNING a;").unwrap();
        analyze(&catalog, &query).unwrap()
    };
    assert_eq!(query.columns[0].constraints, None, "a read value may predate the check");
    assert_eq!(
        query.params[0].constraints.as_ref().unwrap().rules.exclusive_maximum,
        s("10"),
        "a written value must pass it"
    );
}

#[test]
fn should_drop_unnamed_checks_by_their_generated_names() {
    let catalog = Catalog::from_ddl(&[
        "CREATE TABLE t (a integer CHECK (a > 0), b integer, CHECK (b > 0), CHECK (b < 100), CHECK (a < b));",
        "ALTER TABLE t DROP CONSTRAINT t_a_check;",
        "ALTER TABLE t DROP CONSTRAINT t_b_check1;",
    ])
    .unwrap();
    assert_eq!(catalog.column_constraints("t", "a"), None);
    let b = catalog.column_constraints("t", "b").unwrap();
    assert_eq!((b.rules.exclusive_minimum, b.rules.exclusive_maximum), (s("0"), None));
    let names: Vec<_> = catalog
        .column_constraint_facts("t", "b")
        .unwrap()
        .checks
        .iter()
        .map(|c| c.system_name.as_str())
        .collect();
    assert_eq!(names, ["t_b_check"]);
}

#[test]
fn should_follow_alter_domain_constraints() {
    let catalog = Catalog::from_ddl(&[
        "CREATE DOMAIN code AS text CHECK (VALUE ~ '^[a-z]+$');",
        "ALTER DOMAIN code ADD CONSTRAINT code_short CHECK (length(VALUE) <= 8);",
        "ALTER DOMAIN code ADD CHECK (length(VALUE) >= 2) NOT VALID;",
        "ALTER DOMAIN code DROP CONSTRAINT code_check;",
        "ALTER DOMAIN code RENAME CONSTRAINT code_short TO code_length;",
        "CREATE TABLE t (c code);",
    ])
    .unwrap();
    let read = catalog.domain_constraints("code").unwrap().rules;
    assert_eq!((read.pattern, read.min_length, read.max_length), (None, None, Some(8)));
    let written = catalog.written_column_constraints("t", "c").unwrap().rules;
    assert_eq!(written.min_length, Some(2), "the NOT VALID check binds writes");

    let validated = Catalog::from_ddl(&[
        "CREATE DOMAIN code AS text;",
        "ALTER DOMAIN code ADD CHECK (length(VALUE) >= 2) NOT VALID;",
        "ALTER DOMAIN code VALIDATE CONSTRAINT code_check;",
        "ALTER DOMAIN code DROP CONSTRAINT IF EXISTS code_length;",
    ])
    .unwrap();
    assert_eq!(validated.domain_constraints("code").unwrap().rules.min_length, Some(2));
}

#[test]
fn should_read_alter_domain_not_valid_across_whitespace_and_comments() {
    let validated = |add: &str| {
        let catalog = Catalog::from_ddl(&["CREATE DOMAIN code AS text;", add]).unwrap();
        catalog.domain_constraints("code").unwrap().rules.min_length.is_some()
    };
    for not_valid in [
        "ALTER DOMAIN code ADD CHECK (length(VALUE) >= 2) NOT VALID;",
        "ALTER DOMAIN code ADD CHECK (length(VALUE) >= 2) not\n\tvalid;",
        "ALTER DOMAIN code ADD CHECK (length(VALUE) >= 2) NOT /* still */ VALID;",
        "ALTER DOMAIN code ADD CHECK (length(VALUE) >= 2) NOT -- still\n VALID;",
    ] {
        assert!(!validated(not_valid), "{not_valid:?} is NOT VALID");
    }
    for valid in [
        "ALTER DOMAIN code ADD CHECK (length(VALUE) >= 2);",
        "ALTER DOMAIN code ADD CHECK (length(VALUE) >= 2 AND VALUE <> 'NOT VALID');",
        "ALTER DOMAIN code ADD CHECK (length(VALUE) >= 2) /* NOT VALID */;",
        "ALTER DOMAIN code ADD CHECK (length(VALUE) >= 2) -- NOT VALID\n;",
        "ALTER DOMAIN code ADD CONSTRAINT \"NOT\" CHECK (length(VALUE) >= 2);",
    ] {
        assert!(validated(valid), "{valid:?} is validated");
    }
}

#[test]
fn should_not_translate_text_comparisons_on_citext_or_collated_values() {
    let catalog = Catalog::from_ddl(&[
        "CREATE DOMAIN email AS citext CHECK (VALUE ~ '^[^@]+@[^@]+$');",
        "CREATE DOMAIN tag AS text COLLATE \"und-x-icu\" CHECK (VALUE IN ('a', 'b'));",
        "CREATE TABLE t (
            e email,
            name citext CHECK (name LIKE 'x%' AND length(name) <= 5),
            tag tag,
            label text COLLATE \"en_US\" CHECK (label = 'x'),
            code text COLLATE \"C\" CHECK (code ~ '^[a-z]+$')
        );",
    ])
    .unwrap();
    let e = catalog.column_constraints("t", "e").unwrap();
    assert_eq!(e.rules.pattern, None);
    assert!(e.untranslated[0].reason.contains("citext"), "{:?}", e.untranslated);
    let name = catalog.column_constraints("t", "name").unwrap();
    assert_eq!((name.rules.pattern, name.rules.max_length), (None, Some(5)));
    assert_eq!(name.untranslated.len(), 1);
    let tag = catalog.column_constraints("t", "tag").unwrap();
    assert_eq!(tag.rules.allowed, None);
    assert!(
        tag.untranslated[0].reason.contains("und-x-icu"),
        "{:?}",
        tag.untranslated
    );
    let label = catalog.column_constraints("t", "label").unwrap();
    assert!(
        label.untranslated[0].reason.contains("\"en_US\""),
        "{:?}",
        label.untranslated
    );
    assert_eq!(
        catalog.column_constraints("t", "code").unwrap().rules.pattern,
        s("^[a-z]+$"),
        "the C collation compares byte by byte"
    );
}

#[test]
fn should_split_smart_tags_from_comments() {
    let catalog = Catalog::from_ddl(&[
        "CREATE DOMAIN amount AS integer;",
        "COMMENT ON DOMAIN amount IS 'In minor units.';",
        "CREATE TABLE t (a amount, b text);",
        "COMMENT ON COLUMN t.a IS E'@deprecated\\n@since 2024';",
        "COMMENT ON COLUMN t.b IS E'@omit create\\nA name.\\n@pattern ^x$';",
    ])
    .unwrap();
    let a = catalog.column_constraints("t", "a").unwrap();
    assert_eq!(
        a.description.as_deref(),
        Some("In minor units."),
        "only tags: the domain's description stays"
    );
    assert_eq!(
        a.tags,
        [
            ("deprecated".to_string(), String::new()),
            ("since".to_string(), "2024".to_string())
        ]
    );
    let b = catalog.column_constraints("t", "b").unwrap();
    assert_eq!(b.tags, [("omit".to_string(), "create".to_string())]);
    assert_eq!(b.description.as_deref(), Some("A name.\n@pattern ^x$"));
    assert_eq!(b.rules.pattern, None, "a description line is never a rule");
}

/// The names the catalog gives every check of `relation`'s columns, as
/// `(column, name)` in the order the checks were added.
fn check_names(catalog: &Catalog, relation: &str) -> Vec<(String, String)> {
    let table = catalog.get_table(relation).unwrap();
    let mut names = Vec::new();
    for column in &table.columns {
        for check in &column.constraints.checks {
            names.push((column.name.clone(), check.system_name.clone()));
        }
    }
    names
}

fn named(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs.iter().map(|(c, n)| (c.to_string(), n.to_string())).collect()
}

// Each expectation below is what PostgreSQL 18 names the same DDL, read back
// from `pg_constraint`.

#[test]
fn should_name_create_table_checks_in_written_order() {
    let catalog = Catalog::from_ddl(&[
        "CREATE TABLE t4 (a int, CHECK (b > 0), b int CHECK (b < 5));",
        "CREATE TABLE t4b (b int CHECK (b < 5), CHECK (b > 0));",
        "CREATE TABLE t1 (a int CHECK (a > 0), CHECK (a < 10), b int CHECK (b > 0), CHECK (a < b), CHECK (a <> 5));",
        "CREATE TABLE a3 (a int, b int CHECK (b > 0) CHECK (a < b), CHECK (a > 0));",
        "CREATE TABLE t5 (a int, CONSTRAINT t5_a_check CHECK (a < 9), CHECK (a > 0));",
    ])
    .unwrap();
    // A table check written before a column's own check is named first.
    assert_eq!(
        check_names(&catalog, "t4"),
        named(&[("b", "t4_b_check"), ("b", "t4_b_check1")])
    );
    assert_eq!(
        check_names(&catalog, "t4b"),
        named(&[("b", "t4b_b_check"), ("b", "t4b_b_check1")])
    );
    assert_eq!(
        check_names(&catalog, "t1"),
        named(&[
            ("a", "t1_a_check"),
            ("a", "t1_a_check1"),
            ("a", "t1_a_check2"),
            ("b", "t1_b_check")
        ])
    );
    // `CHECK (a < b)` takes `a3_check`; the later `CHECK (a > 0)` is `a3_a_check`.
    assert_eq!(
        check_names(&catalog, "a3"),
        named(&[("a", "a3_a_check"), ("b", "a3_b_check")])
    );
    assert_eq!(
        check_names(&catalog, "t5"),
        named(&[("a", "t5_a_check"), ("a", "t5_a_check1")])
    );
}

#[test]
fn should_name_alter_table_checks_in_postgresql_pass_order() {
    let catalog = Catalog::from_ddl(&[
        "CREATE TABLE a1 (a int CHECK (a > 0));",
        // Added columns' checks are named before added constraints, whatever
        // the written order.
        "ALTER TABLE a1 ADD CHECK (a > 1), ADD COLUMN b int CHECK (a > 2), ADD COLUMN c int CHECK (c > 0), \
         ADD CONSTRAINT x CHECK (a > 3);",
        // A dropped constraint's name is free again, even written after.
        "ALTER TABLE a1 ADD CHECK (a > 4), DROP CONSTRAINT a1_a_check;",
    ])
    .unwrap();
    let a1 = catalog.get_table("a1").unwrap();
    let a: Vec<(&str, &str)> = a1.columns[0]
        .constraints
        .checks
        .iter()
        .map(|check| (check.system_name.as_str(), check.sql.as_str()))
        .collect();
    assert_eq!(
        a,
        [
            ("a1_a_check1", "a > 2"),
            ("a1_a_check2", "a > 1"),
            ("x", "a > 3"),
            ("a1_a_check", "a > 4")
        ]
    );
    assert_eq!(
        check_names(&catalog, "a1").last().unwrap(),
        &named(&[("c", "a1_c_check")])[0]
    );
}

#[test]
fn should_not_take_the_name_of_any_constraint_in_the_schema() {
    let catalog = Catalog::from_ddl(&[
        // Another relation's check on several columns, and a domain's check.
        "CREATE TABLE t11_a (x int, y int, CHECK (x < y));",
        "CREATE DOMAIN t12_a AS int CHECK (VALUE > 0);",
        "CREATE TABLE t11 (a int CHECK (a > 0));",
        "CREATE TABLE t12 (a int CHECK (a > 0));",
    ])
    .unwrap();
    let with_checks = Catalog::from_ddl(&[
        "CREATE TABLE p (id int PRIMARY KEY);",
        "CREATE TABLE t7 (a int, CONSTRAINT t7_a_check UNIQUE (a));",
        "ALTER TABLE t7 ADD CHECK (a > 0);",
        "CREATE TABLE t8 (a int, CONSTRAINT t8_a_check PRIMARY KEY (a));",
        "ALTER TABLE t8 ADD CHECK (a > 0);",
        "CREATE TABLE t9 (a int CONSTRAINT t9_a_check NOT NULL);",
        "ALTER TABLE t9 ADD CHECK (a > 0);",
        "CREATE TABLE t10 (a int CONSTRAINT t10_a_check REFERENCES p);",
        "ALTER TABLE t10 ADD CHECK (a > 0);",
        "CREATE TABLE t13 (a int, CONSTRAINT t13_a_check EXCLUDE (a WITH =));",
        "ALTER TABLE t13 ADD CHECK (a > 0);",
        "CREATE TABLE t16 (a int, b int);",
        "ALTER TABLE t16 ADD CONSTRAINT t16_a_check FOREIGN KEY (b) REFERENCES p;",
        "ALTER TABLE t16 ADD CHECK (a > 0);",
    ])
    .unwrap();
    for table in ["t7", "t8", "t9", "t10", "t13", "t16"] {
        assert_eq!(
            check_names(&with_checks, table),
            named(&[("a", &format!("{table}_a_check1"))]),
            "{table}"
        );
    }
    assert_eq!(check_names(&catalog, "t11"), named(&[("a", "t11_a_check1")]));
    assert_eq!(check_names(&catalog, "t12"), named(&[("a", "t12_a_check1")]));
}

#[test]
fn should_only_avoid_constraint_names_in_the_same_schema() {
    let catalog = Catalog::from_ddl(&[
        "CREATE TABLE e2.x (a int, CONSTRAINT t15_a_check CHECK (a > 0));",
        "CREATE TABLE t15 (a int CHECK (a > 0));",
        "CREATE TABLE e2.t15 (a int CHECK (a > 0));",
        "CREATE TABLE public.y (a int, b int, CONSTRAINT t17_a_check UNIQUE (b));",
        "CREATE TABLE t17 (a int CHECK (a > 0));",
    ])
    .unwrap();
    assert_eq!(check_names(&catalog, "t15"), named(&[("a", "t15_a_check")]));
    assert_eq!(check_names(&catalog, "e2.t15"), named(&[("a", "t15_a_check1")]));
    // A bare name is created in `public`, the default search path's schema.
    assert_eq!(check_names(&catalog, "t17"), named(&[("a", "t17_a_check1")]));
}

#[test]
fn should_free_constraint_names_with_what_owns_them() {
    let catalog = Catalog::from_ddl(&[
        "CREATE TABLE t (a int, b int, CONSTRAINT t_a_check UNIQUE (b), CHECK (a < b));",
        "ALTER TABLE t DROP CONSTRAINT t_check;",
        "ALTER TABLE t DROP COLUMN b;",
        "ALTER TABLE t ADD CHECK (a > 0), ADD CHECK (a <> b2), ADD COLUMN b2 int;",
        "ALTER TABLE t RENAME CONSTRAINT t_check TO renamed;",
        "ALTER TABLE t ADD CHECK (a <> 1);",
        "ALTER TABLE t ADD CHECK (a < b2);",
    ])
    .unwrap();
    assert_eq!(
        check_names(&catalog, "t"),
        named(&[("a", "t_a_check"), ("a", "t_a_check1")])
    );
}

#[test]
fn should_keep_quoted_text_literals_as_strings_and_cast_numbers_as_numbers() {
    let catalog = Catalog::from_ddl(&[
        // `code = '10'::text` is how pg_get_constraintdef prints a text check.
        "CREATE TABLE t (
            code text CHECK (code IN ('10', '20')),
            single text CHECK (single = '10'::text),
            amount numeric CHECK (amount >= '-1.5'::numeric AND amount < '1e3'::numeric),
            level integer CHECK (level IN ('1'::integer, '2'::integer)),
            ratio numeric CHECK (ratio < 'NaN'::numeric),
            score real CHECK (score <= 'Infinity'::real)
        );",
    ])
    .unwrap();
    let strings = |values: &[&str]| Some(values.iter().map(|v| AllowedValue::String(v.to_string())).collect());
    assert_eq!(
        catalog.column_constraints("t", "code").unwrap().rules.allowed,
        strings(&["10", "20"])
    );
    assert_eq!(
        catalog.column_constraints("t", "single").unwrap().rules.allowed,
        strings(&["10"])
    );
    let amount = catalog.column_constraints("t", "amount").unwrap().rules;
    assert_eq!((amount.minimum, amount.exclusive_maximum), (s("-1.5"), s("1e3")));
    assert_eq!(
        catalog.column_constraints("t", "level").unwrap().rules.allowed,
        Some(vec![
            AllowedValue::Number("1".to_string()),
            AllowedValue::Number("2".to_string())
        ])
    );
    for column in ["ratio", "score"] {
        let constraints = catalog.column_constraints("t", column).unwrap();
        assert!(constraints.rules.is_empty(), "{column}: {constraints:?}");
        assert_eq!(constraints.untranslated.len(), 1, "{column}");
    }
}

#[test]
fn should_read_alter_domain_constraint_names_as_postgresql_does() {
    let catalog = Catalog::from_ddl(&[
        "CREATE DOMAIN code AS text
            CONSTRAINT \"Has Letters\" CHECK (VALUE ~ '^[a-z]+$')
            CONSTRAINT \"too long\" CHECK (length(VALUE) <= 8)
            CONSTRAINT Short CHECK (length(VALUE) <= 20)
            CONSTRAINT \"Long\" CHECK (length(VALUE) >= 1);",
        "ALTER DOMAIN code ADD CONSTRAINT /* ä */ \"min\n2\" CHECK (length(VALUE) >= 2) NOT VALID;",
        // Quoted names keep their spaces and case.
        "ALTER DOMAIN code DROP CONSTRAINT \"too long\" CASCADE;",
        // An unquoted name is lowercased, so this drops `short`, not `Long`.
        "ALTER DOMAIN code DROP /* a comment */ CONSTRAINT\n\tIF EXISTS SHORT RESTRICT;",
        "ALTER DOMAIN code DROP CONSTRAINT IF EXISTS long;",
        "ALTER DOMAIN code VALIDATE -- a comment\n CONSTRAINT \"min\n2\";",
        "ALTER DOMAIN code RENAME CONSTRAINT \"Has Letters\" TO \"Is Lower\";",
    ])
    .unwrap();
    let facts = catalog.domain_constraint_facts("code").unwrap();
    let names: Vec<_> = facts.checks.iter().map(|c| c.system_name.as_str()).collect();
    assert_eq!(names, ["Is Lower", "Long", "min\n2"]);
    let rules = catalog.domain_constraints("code").unwrap().rules;
    assert_eq!(
        (rules.pattern, rules.min_length, rules.max_length),
        (s("^[a-z]+$"), Some(2), None),
        "the NOT VALID check was validated by its quoted name"
    );
}

#[test]
fn should_read_collation_names_as_case_sensitive_identifiers() {
    let catalog = Catalog::from_ddl(&[
        "CREATE DOMAIN posix_text AS text COLLATE pg_catalog.\"POSIX\";",
        "CREATE TABLE t (
            a text COLLATE \"C\" CHECK (a = 'x'),
            b text COLLATE \"default\" CHECK (b = 'x'),
            c posix_text CHECK (c = 'x'),
            d text COLLATE \"en_US\" CHECK (d = 'x')
        );",
    ])
    .unwrap();
    for column in ["a", "b", "c"] {
        let constraints = catalog.column_constraints("t", column).unwrap();
        assert_eq!(constraints.rules.allowed.map(|a| a.len()), Some(1), "{column}");
    }
    let posix = catalog.domain_constraint_facts("posix_text").unwrap();
    assert_eq!(posix.collation.as_ref().map(|c| c.name()), Some("POSIX"));
    let d = catalog.column_constraint_facts("t", "d").unwrap();
    assert_eq!(d.collation.as_ref().map(|c| c.name()), Some("en_US"));
    assert!(catalog.column_constraints("t", "d").unwrap().rules.allowed.is_none());
}
