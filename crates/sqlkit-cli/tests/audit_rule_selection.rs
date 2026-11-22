//! `sqlkit audit` regressions for the two ways its rule set could shrink
//! without saying so:
//!
//! - CWE ids were scraped out of `LintRule::description()` instead of read
//!   from `LintRule::cwe()`, where the rule declares them. Every canonical
//!   rule happens to repeat its declared ids in its description prose, so the
//!   two agreed by hand-maintained coincidence; a user rule that declares
//!   `cwe` without restating it in prose got no CWE at all.
//! - `LintRule::is_applicable_to` gates a rule to the dialects its spec
//!   declares, and `MatcherRule::check_query` applies that gate internally by
//!   returning an empty `Vec` -- indistinguishable from "the rule ran and
//!   found nothing". A whole dialect's worth of rules could vanish silently,
//!   including all of them.

use std::fs;

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

/// Trips SC-SEC01 (`dangerous-function`, `cwe = ["CWE-78"]`), which declares
/// no `dialects` restriction and so applies to every engine.
const DANGEROUS_SQL: &str = "SELECT pg_read_file('/etc/passwd');\n";

fn run_audit(args: &[&str]) -> std::process::Output {
    Command::cargo_bin("sqlkit")
        .expect("sqlkit binary must exist")
        .args(args)
        .output()
        .expect("run sqlkit audit")
}

/// Path to a `sqlkit.toml` that does not exist, so the audit falls back to
/// the canonical registry.
fn absent_config(dir: &TempDir) -> String {
    dir.path().join("sqlkit.toml").to_string_lossy().into_owned()
}

/// A user rule that declares `cwe = ["CWE-89"]` but never writes "CWE" in its
/// description. Scraping the description finds nothing; reading
/// `LintRule::cwe()` finds the declaration.
fn write_user_rule_config(dir: &TempDir, dialects: &str) -> String {
    fs::write(
        dir.path().join("sqlkit.toml"),
        format!(
            r#"[sqlkit]
version = "1"

[[audit.rule]]
id = "USER-PG01"
name = "postgres-only-rule"
category = "security"
severity = "error"
cwe = ["CWE-89"]
{dialects}
description = "a rule whose prose never names the weakness it maps to"
message = "call to `{{func}}`"
matcher = "function_name_in_set"

[audit.rule.matcher_args]
functions = ["my_dangerous_call"]
"#
        ),
    )
    .expect("write sqlkit.toml");
    dir.path().join("sqlkit.toml").to_string_lossy().into_owned()
}

#[test]
fn audit_sarif_carries_the_cwe_the_rule_declares() {
    let dir = TempDir::new().expect("tempdir");
    let sql_path = dir.path().join("q.sql");
    fs::write(&sql_path, "SELECT my_dangerous_call(1);\n").expect("write q.sql");
    let config = write_user_rule_config(&dir, "");

    let output = run_audit(&[
        "audit",
        "--config",
        &config,
        "--format",
        "sarif",
        &sql_path.to_string_lossy(),
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let sarif: Value = serde_json::from_str(&stdout).expect("audit --format sarif must emit valid JSON");

    let user_rule = sarif["runs"][0]["results"]
        .as_array()
        .expect("results array")
        .iter()
        .find(|r| r["ruleId"] == "USER-PG01")
        .unwrap_or_else(|| panic!("USER-PG01 must fire; sarif was: {stdout}"));

    assert_eq!(
        user_rule["properties"]["cwe"],
        serde_json::json!(["CWE-89"]),
        "the CWE the rule declares must reach SARIF even though its description never says \"CWE\""
    );
    assert_eq!(output.status.code(), Some(2), "the rule is error severity");
}

#[test]
fn audit_explain_prints_the_cwe_the_rule_declares() {
    let dir = TempDir::new().expect("tempdir");
    let config = write_user_rule_config(&dir, "");

    let output = run_audit(&["audit", "--config", &config, "--explain", "USER-PG01"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("cwe:      CWE-89"),
        "--explain must print the rule's declared CWE list; stdout: {stdout}"
    );
    assert_eq!(output.status.code(), Some(0));
}

/// A canonical rule declares its CWE ids *and* repeats them in its
/// description. Both readings agree today, and this pins that they keep
/// agreeing -- the drift between them is what the two tests above catch.
#[test]
fn audit_canonical_rule_cwe_matches_its_description() {
    let dir = TempDir::new().expect("tempdir");
    let sql_path = dir.path().join("dangerous.sql");
    fs::write(&sql_path, DANGEROUS_SQL).expect("write dangerous.sql");

    let output = run_audit(&[
        "audit",
        "--config",
        &absent_config(&dir),
        "--format",
        "sarif",
        &sql_path.to_string_lossy(),
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let sarif: Value = serde_json::from_str(&stdout).expect("valid SARIF");

    let sec01 = sarif["runs"][0]["results"]
        .as_array()
        .expect("results array")
        .iter()
        .find(|r| r["ruleId"] == "SC-SEC01")
        .unwrap_or_else(|| panic!("SC-SEC01 must fire on pg_read_file; sarif was: {stdout}"));

    assert_eq!(sec01["properties"]["cwe"], serde_json::json!(["CWE-78"]));
    assert!(
        sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .expect("rules array")
            .iter()
            .any(|r| r["id"] == "SC-SEC01"
                && r["shortDescription"]["text"]
                    .as_str()
                    .is_some_and(|d| d.contains("CWE-78"))),
        "SC-SEC01's description must keep naming the same CWE its spec declares"
    );
    assert_eq!(output.status.code(), Some(2));
}

/// An audit with nothing left to run must fail loudly. Configuring every
/// audit-executed category `off` used to produce an empty report and exit 0 --
/// a security gate reporting success having examined zero rules.
#[test]
fn audit_with_no_executable_rule_fails_instead_of_reporting_clean() {
    let dir = TempDir::new().expect("tempdir");
    let sql_path = dir.path().join("dangerous.sql");
    fs::write(&sql_path, DANGEROUS_SQL).expect("write dangerous.sql");
    let config_path = dir.path().join("sqlkit.toml");
    fs::write(
        &config_path,
        r#"[sqlkit]
version = "1"

[lint.categories]
security = "off"
migration = "off"
antipattern = "off"
"#,
    )
    .expect("write sqlkit.toml");

    let output = run_audit(&[
        "audit",
        "--config",
        &config_path.to_string_lossy(),
        "--format",
        "json",
        &sql_path.to_string_lossy(),
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let findings: Vec<Value> = serde_json::from_str::<Value>(&stdout)
        .expect("valid JSON")
        .as_array()
        .expect("array")
        .clone();

    assert_eq!(
        findings.len(),
        1,
        "the only finding must be the one saying nothing ran; stdout: {stdout}"
    );
    assert_eq!(findings[0]["rule_id"], "SC-AUDIT00");
    assert_eq!(findings[0]["severity"], "error");
    assert!(
        findings[0]["message"]
            .as_str()
            .expect("message")
            .contains("audit examined 0 rules"),
        "the message must say plainly that nothing was examined; got {}",
        findings[0]["message"]
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "an audit that examined nothing must not pass a CI gate"
    );
}

/// `--exit-zero` still applies to the "nothing ran" finding, so a project
/// that deliberately disables audit can keep its pipeline green while the
/// report still records that nothing was examined.
#[test]
fn audit_with_no_executable_rule_still_honours_exit_zero() {
    let dir = TempDir::new().expect("tempdir");
    let sql_path = dir.path().join("dangerous.sql");
    fs::write(&sql_path, DANGEROUS_SQL).expect("write dangerous.sql");
    let config_path = dir.path().join("sqlkit.toml");
    fs::write(
        &config_path,
        r#"[sqlkit]
version = "1"

[lint.categories]
security = "off"
migration = "off"
antipattern = "off"
"#,
    )
    .expect("write sqlkit.toml");

    let output = run_audit(&[
        "audit",
        "--config",
        &config_path.to_string_lossy(),
        "--format",
        "json",
        "--exit-zero",
        &sql_path.to_string_lossy(),
    ]);

    assert_eq!(output.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("SC-AUDIT00"),
        "the finding must still be reported"
    );
}
