//! Live-PG test that a catalog read from a database records the same value
//! constraints as the same schema parsed from DDL: `CHECK`s (with the names
//! PostgreSQL gave them and whether they are validated), `varchar(n)` and
//! `char(n)` lengths, `COLLATE` and `COMMENT ON` text, of columns and
//! domains alike. Runs only with the `live-tests` feature and
//! `$SQLKIT_TEST_DATABASE_URL` set, like the other live tests
//! (`devenv tasks run sqlkit:inspect-live` sets both).

#![cfg(all(feature = "live-tests", feature = "postgres"))]

use sqlkit_core::catalog::{Catalog, ColumnConstraints};
use sqlkit_core::constraints::ValueConstraints;
use sqlkit_inspect::schema_diff::fetch_live_catalog;
use tokio_postgres::NoTls;

const SCHEMA: &str = "sqlkit_catalog_constraints_live";

const DDL: &str = r#"
CREATE DOMAIN slug AS text CHECK (VALUE ~ '^[a-z0-9-]+$');
CREATE DOMAIN code AS varchar(8) COLLATE "C"
    CONSTRAINT code_letters CHECK (VALUE ~ '^[A-Z]+$')
    CHECK (length(VALUE) >= 2);
ALTER DOMAIN code ADD CHECK (VALUE <> 'XX') NOT VALID;
CREATE DOMAIN amount AS integer NOT NULL CHECK (VALUE BETWEEN 0 AND 100000000);
CREATE DOMAIN positive_amount AS amount CHECK (VALUE > 0);
COMMENT ON DOMAIN amount IS 'An amount in minor units.';

CREATE TABLE causes (
    id serial PRIMARY KEY,
    slug slug NOT NULL,
    CHECK (position < 1000),
    title varchar(255) NOT NULL CHECK (length(trim(title)) > 0),
    position integer CHECK (position >= 0),
    goal positive_amount CHECK (goal < 500000),
    code code,
    status varchar(20) NOT NULL,
    initials char(4) COLLATE "C",
    notes text COLLATE "POSIX",
    CONSTRAINT causes_status CHECK (status IN ('draft', 'live')),
    CONSTRAINT causes_scope CHECK (position IS NULL OR goal IS NOT NULL),
    CONSTRAINT causes_title_check2 UNIQUE (status)
);
ALTER TABLE causes ADD CONSTRAINT causes_notes CHECK (length(notes) <= 500) NOT VALID;
ALTER TABLE causes ADD CHECK (title <> 'x') NOT VALID, ADD CHECK (title <> 'y'),
    ADD COLUMN extra text CHECK (title <> 'z');
COMMENT ON COLUMN causes.title IS E'@deprecated\nWhat the cause is called.';
"#;

/// A domain or relation key without its schema.
fn bare(key: &str) -> &str {
    key.rsplit_once('.').map_or(key, |(_, name)| name)
}

/// The facts both paths must agree on, with the schema the live catalog
/// qualifies names with removed and the check's SQL left out: PostgreSQL
/// prints an expression back in its own form (casts, parentheses).
fn facts(facts: &ColumnConstraints) -> String {
    let checks: Vec<String> = facts
        .checks
        .iter()
        .map(|check| format!("{:?} {} validated={}", check.name, check.system_name, check.validated))
        .collect();
    format!(
        "domain={:?} max_length={:?} collation={:?} comment={:?} checks={checks:?}",
        facts.domain.as_deref().map(bare),
        facts.max_length,
        facts.collation,
        facts.comment
    )
}

/// The resolved constraints, normalized the same way: an untranslated
/// constraint is compared by where it is declared and why, not by its SQL.
fn resolved(constraints: Option<ValueConstraints>) -> String {
    let Some(mut constraints) = constraints else {
        return "none".to_string();
    };
    constraints.domain = constraints.domain.as_deref().map(|d| bare(d).to_string());
    let untranslated: Vec<String> = constraints
        .untranslated
        .iter()
        .map(|entry| format!("{}: {}", entry.source.replace(&format!("{SCHEMA}."), ""), entry.reason))
        .collect();
    format!(
        "domain={:?} description={:?} tags={:?} rules={:?} untranslated={untranslated:?}",
        constraints.domain, constraints.description, constraints.tags, constraints.rules
    )
}

#[tokio::test]
async fn live_catalog_records_the_same_constraints_as_ddl() {
    let url = std::env::var("SQLKIT_TEST_DATABASE_URL").expect("SQLKIT_TEST_DATABASE_URL must be set for live-tests");
    let (client, connection) = tokio_postgres::connect(&url, NoTls).await.expect("connect");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
        .batch_execute(&format!(
            "DROP SCHEMA IF EXISTS {SCHEMA} CASCADE; CREATE SCHEMA {SCHEMA}; SET search_path TO {SCHEMA}; {DDL}"
        ))
        .await
        .expect("apply the schema");

    let ddl = Catalog::from_ddl(&[DDL]).expect("catalog from DDL");
    let live = fetch_live_catalog(&client, &[]).await.expect("live catalog");

    let mut compared = 0;
    for (key, table) in ddl.tables_iter() {
        let live_key = format!("{SCHEMA}.{key}");
        for column in &table.columns {
            let live_facts = live
                .column_constraint_facts(&live_key, &column.name)
                .unwrap_or_else(|| panic!("{live_key}.{} in the live catalog", column.name));
            assert_eq!(
                facts(live_facts),
                facts(&column.constraints),
                "facts of {key}.{}",
                column.name
            );
            assert_eq!(
                resolved(live.column_constraints(&live_key, &column.name)),
                resolved(ddl.column_constraints(key, &column.name)),
                "read constraints of {key}.{}",
                column.name
            );
            assert_eq!(
                resolved(live.written_column_constraints(&live_key, &column.name)),
                resolved(ddl.written_column_constraints(key, &column.name)),
                "written constraints of {key}.{}",
                column.name
            );
            compared += 1;
        }
    }
    assert_eq!(compared, 10, "every column of causes was compared");
    for domain in ["slug", "code", "amount", "positive_amount"] {
        let live_domain = format!("{SCHEMA}.{domain}");
        assert_eq!(
            facts(live.domain_constraint_facts(&live_domain).expect("live domain")),
            facts(ddl.domain_constraint_facts(domain).expect("DDL domain")),
            "facts of domain {domain}"
        );
        assert_eq!(
            resolved(live.domain_constraints(&live_domain)),
            resolved(ddl.domain_constraints(domain)),
            "constraints of domain {domain}"
        );
    }

    // The names PostgreSQL gave, which both catalogs must carry.
    let names = |column: &str| -> Vec<String> {
        live.column_constraint_facts(&format!("{SCHEMA}.causes"), column)
            .unwrap()
            .checks
            .iter()
            .map(|check| format!("{} {}", check.system_name, check.validated))
            .collect()
    };
    assert_eq!(
        names("position"),
        ["causes_position_check true", "causes_position_check1 true"]
    );
    assert_eq!(
        names("title"),
        [
            "causes_title_check true",
            "causes_title_check1 true",
            "causes_title_check3 false",
            "causes_title_check4 true"
        ]
    );
    assert_eq!(names("notes"), ["causes_notes false"]);
    let code = live.domain_constraint_facts(&format!("{SCHEMA}.code")).unwrap();
    let code: Vec<String> = code
        .checks
        .iter()
        .map(|check| format!("{} {}", check.system_name, check.validated))
        .collect();
    assert_eq!(code, ["code_letters true", "code_check true", "code_check1 false"]);
}
