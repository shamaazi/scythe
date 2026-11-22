//! `sqlkit audit` — run security-category lint rules with security-flavoured
//! defaults (all-on, error-by-default) and emit findings in human / SARIF /
//! JSON format.
//!
//! Supports:
//! - Inline `-- sqlkit-audit: ignore[ID]` suppression annotations.
//! - User-supplied rules via `[[audit.rule]]` in `sqlkit.toml` and optional
//!   `extra_rules = [...]` TOML files.

use std::fs::File;
use std::io::Write;
use std::path::Path;

mod cluster_scope;

use sqlkit_core::analyzer::AnalyzedQuery;
use sqlkit_core::catalog::Catalog;
use sqlkit_core::parser::Annotations;
use sqlkit_lint::reporters::{Finding, Format};
use sqlkit_lint::{
    AuditConfigError, LintContext, LintRule, MatcherRegistry, RuleCategory, RuleRegistry, RuleSpec, Severity,
    SuppressionSet, default_registry, emit_findings, load_rules_from_file, parse_statements_lenient,
    register_user_rules,
};

use super::shared::{
    CatalogLoadRequest, LintRegistries, LoadedCatalog, PostgresEngine, config_dir, load_catalog, read_config,
    read_optional_config, resolve_globs,
};

const TOOL_NAME: &str = "sqlkit-audit";
const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Inputs to `run_audit`. Mirrors the clap `Commands::Audit` shape so the CLI
/// layer can forward fields by name instead of long positional argument lists.
pub struct RunAuditOpts {
    pub config_path: String,
    pub format: String,
    pub list_rules: bool,
    pub explain: Option<String>,
    pub severity: Option<String>,
    pub exit_zero: bool,
    pub output: Option<String>,
    pub ignore_suppressions: bool,
    pub cluster_scope: bool,
    pub pg_version: Option<String>,
    pub files: Vec<String>,
}

pub fn run_audit(opts: RunAuditOpts) -> Result<(), Box<dyn std::error::Error>> {
    // Every input that can be wrong is validated *before* any output sink is
    // opened -- `--format`/`--severity`/`--explain`'s rule id --
    // so a bad flag is reported as a bad flag instead of truncating
    // `--output`'s file to 0 bytes and then erroring (#212): `File::create`
    // truncates immediately on open, so opening it ahead of validation
    // destroys any existing report before the error is even known.
    let format = Format::parse(&opts.format)
        .ok_or_else(|| format!("unknown --format '{}' (expected human|sarif|json)", opts.format))?;

    let severity_floor = match opts.severity.as_deref() {
        Some(s) => Some(
            Severity::parse_cli(s).ok_or_else(|| format!("unknown --severity '{}' (expected off|warn|error)", s))?,
        ),
        None => None,
    };

    if opts.cluster_scope {
        return run_cluster_scope_gate(&opts, format);
    }

    if opts.list_rules || opts.explain.is_some() {
        let registry = load_explicit_config(&opts.config_path)?.registry;

        // Validated before `open_output` opens (and, for a file path,
        // truncates) the sink: `--explain <typo'd-id> --output report.json`
        // used to truncate `report.json` to 0 bytes and only then report
        // the unknown id, destroying whatever the file held before. See
        // #212.
        if let Some(id) = &opts.explain
            && !registry.all_rules().iter().any(|(r, _)| r.id() == id.as_str())
        {
            return Err(format!("no rule with id '{}' — try `sqlkit audit --list-rules`", id).into());
        }

        let mut out: Box<dyn Write> = open_output(opts.output.as_deref())?;
        if opts.list_rules {
            print_rule_catalog(&registry, out.as_mut())?;
            return Ok(());
        }
        if let Some(id) = &opts.explain {
            print_rule_explanation(&registry, id, out.as_mut())?;
            return Ok(());
        }
    }

    let mut findings: Vec<Finding> = Vec::new();

    if opts.files.is_empty() {
        findings.extend(audit_from_config(&opts.config_path, opts.ignore_suppressions)?);
    } else {
        findings.extend(audit_explicit_files(
            &opts.files,
            opts.ignore_suppressions,
            &opts.config_path,
        )?);
    }

    let parse_failure_count = findings.iter().filter(|f| f.rule_id == "SC-PARSE01").count();

    if let Some(floor) = severity_floor {
        findings.retain(|f| f.severity >= floor);
    }

    let mut out: Box<dyn Write> = open_output(opts.output.as_deref())?;
    emit_findings(format, TOOL_NAME, TOOL_VERSION, &findings, out.as_mut())?;
    out.flush()?;

    if parse_failure_count > 0 {
        return Err(
            format!("audit could not parse {parse_failure_count} statement(s); the audit is incomplete").into(),
        );
    }

    let error_count = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Error))
        .count();
    if error_count > 0 && !opts.exit_zero {
        std::process::exit(2);
    }
    Ok(())
}

/// Run the #269 fail-closed cluster-scope gate over explicit planned-schema files.
///
/// This is deliberately separate from the SQL lint/audit registry: it never
/// consults rule severities, suppressions, `--severity`, or `--exit-zero`, so a
/// parse gap or a cluster-scoped statement can never be turned green.
fn run_cluster_scope_gate(opts: &RunAuditOpts, format: Format) -> Result<(), Box<dyn std::error::Error>> {
    let version = match opts.pg_version.as_deref() {
        Some(raw) => cluster_scope::helper::PgVersion::parse(raw)
            .ok_or_else(|| format!("unknown --pg-version '{raw}' (expected 15|18)"))?,
        None => cluster_scope::helper::PgVersion::default(),
    };
    if opts.files.is_empty() {
        return Err("sqlkit audit --cluster-scope requires explicit planned-schema file(s)".into());
    }

    let report = cluster_scope::run(&opts.files, version)?;
    let findings: Vec<Finding> = report
        .findings
        .iter()
        .map(|finding| Finding {
            file: finding.file.clone(),
            query_name: None,
            rule_id: finding.code.to_string(),
            rule_name: Some("cluster-scope".to_string()),
            rule_description: Some(cluster_scope_description(finding.code).to_string()),
            severity: Severity::Error,
            message: finding.message.clone(),
            line: finding.line,
            column: None,
            cwe: Vec::new(),
            source: Some("audit".to_string()),
        })
        .collect();

    let mut out: Box<dyn Write> = open_output(opts.output.as_deref())?;
    emit_findings(format, TOOL_NAME, TOOL_VERSION, &findings, out.as_mut())?;
    out.flush()?;

    if findings.is_empty() {
        eprintln!(
            "checked {} planned schema input(s), {} executable statement(s) (PostgreSQL {}.x); no cluster-scoped privilege statements",
            report.inputs,
            report.statements,
            version.major()
        );
        return Ok(());
    }

    eprintln!(
        "checked {} planned schema input(s), {} executable statement(s) (PostgreSQL {}.x); {} cluster-scope finding(s)",
        report.inputs,
        report.statements,
        version.major(),
        findings.len()
    );
    std::process::exit(2);
}

fn cluster_scope_description(code: &str) -> &'static str {
    match code {
        "SC-CLUSTER01" => {
            "writes cluster-global shared state (role, database, tablespace, subscription, parameter privilege, ALTER SYSTEM, or shared ownership)"
        }
        "SC-CLUSTER02" => "statement kind is outside the database-local allow-list",
        "SC-CLUSTER03" => "dynamic SQL could not be proven database-local",
        _ => "planned-schema statement or routine body could not be inspected (fail closed)",
    }
}

/// Open the output sink for a reporter. `None` → stdout. `Some(path)` →
/// truncating file write. Parent directory must already exist.
fn open_output(path: Option<&str>) -> Result<Box<dyn Write>, Box<dyn std::error::Error>> {
    match path {
        None => Ok(Box::new(std::io::stdout())),
        Some(p) => {
            let f = File::create(p).map_err(|e| format!("failed to open output file '{}': {}", p, e))?;
            Ok(Box::new(std::io::BufWriter::new(f)))
        }
    }
}

/// What `sqlkit.toml`'s `[lint]` and `[audit]` sections configure for audit
/// without `[[sql]]` blocks: the rule registry -- canonical rules plus
/// severity overrides, plus any user-defined rules from `[[audit.rule]]` and
/// `extra_rules` -- and `SC-PARSE01`'s severity.
///
/// Used two ways:
/// - Discovery (`--list-rules` / `--explain`): the registry is never
///   executed, so the catalog reflects severities and rules as configured.
/// - Explicit-file mode (`sqlkit audit <file>...`): the *same* registry is
///   executed by [`audit_explicit_files`] -- before this, explicit-file mode
///   built a bare `default_registry()` and ignored `sqlkit.toml` entirely,
///   so a rule configured `"off"` still fired and `[[audit.rule]]` entries
///   never ran (issue #206, item 2).
///
/// Returns the canonical configuration, unmodified, when `config_path` does
/// not exist -- explicit-file mode is meant to work without a config at all.
/// The file is read once for both.
struct ExplicitAuditConfig {
    registry: RuleRegistry,
    parse_severity: Severity,
}

fn load_explicit_config(config_path: &str) -> Result<ExplicitAuditConfig, Box<dyn std::error::Error>> {
    let Some(parsed) = read_optional_config::<toml::Value>(config_path)? else {
        return Ok(ExplicitAuditConfig {
            registry: default_registry(),
            parse_severity: LintRegistries::from_config(None).parse_severities.unparseable,
        });
    };
    let lint_config = parse_lint_section(&parsed, config_path)?;
    let LintRegistries {
        rules: mut registry,
        parse_severities,
    } = LintRegistries::from_config(lint_config.as_ref());
    if let Some(audit_section) = parsed.get("audit") {
        let base_dir = config_dir(config_path);
        let matcher_registry = MatcherRegistry::canonical();
        let mut user_specs: Vec<(RuleSpec, String)> = Vec::new();
        if let Some(rules) = audit_section.get("rule").and_then(|v| v.as_array()) {
            for r in rules {
                if let Ok(spec) = r.clone().try_into::<RuleSpec>() {
                    user_specs.push((spec, config_path.to_string()));
                }
            }
        }
        if let Some(extras) = audit_section.get("extra_rules").and_then(|v| v.as_array()) {
            for v in extras {
                if let Some(rel_path) = v.as_str() {
                    let abs_path = base_dir.join(rel_path);
                    let path_str = abs_path.display().to_string();
                    let specs = load_rules_from_file(&abs_path).map_err(|e: AuditConfigError| e.to_string())?;
                    for spec in specs {
                        user_specs.push((spec, path_str.clone()));
                    }
                }
            }
        }
        if !user_specs.is_empty() {
            register_user_rules(&mut registry, &matcher_registry, &user_specs)
                .map_err(|e: AuditConfigError| e.to_string())?;
        }
    }
    Ok(ExplicitAuditConfig {
        registry,
        parse_severity: parse_severities.unparseable,
    })
}

/// The `[lint]` table of a parsed `sqlkit.toml`, if it has one. A malformed
/// table is an error, as it is for `sqlkit lint` and `sqlkit check`, rather
/// than an audit that quietly runs without the configured severities.
fn parse_lint_section(
    parsed: &toml::Value,
    config_path: &str,
) -> Result<Option<sqlkit_lint::types::LintConfig>, Box<dyn std::error::Error>> {
    let Some(lint_section) = parsed.get("lint") else {
        return Ok(None);
    };
    let lint_config = lint_section
        .clone()
        .try_into()
        .map_err(|e| format!("invalid [lint] table in '{}': {}", config_path, e))?;
    Ok(Some(lint_config))
}

/// Print the rule catalog, grouped by category, in a fixed-width table.
pub(crate) fn print_rule_catalog(
    registry: &RuleRegistry,
    out: &mut dyn Write,
) -> Result<(), Box<dyn std::error::Error>> {
    // `all_rules`, not `active_rules`: this is a catalog listing, not the set
    // of rules that will fire. SC-A02 and SC-C01 are `Off` by default but are
    // still real, registered rules — omitting them from `--list-rules` would
    // undercount the documented rule set (see `RuleRegistry::all_rules`).
    let mut rows: Vec<(&dyn LintRule, Severity)> = registry.all_rules();
    rows.sort_by_key(|(r, _)| (r.category() as u8, r.id()));

    let id_w = rows.iter().map(|(r, _)| r.id().len()).max().unwrap_or(2).max(2);
    let name_w = rows.iter().map(|(r, _)| r.name().len()).max().unwrap_or(4).max(4);

    let mut current_category: Option<RuleCategory> = None;
    for (rule, sev) in &rows {
        let cat = rule.category();
        if Some(cat) != current_category {
            if current_category.is_some() {
                writeln!(out)?;
            }
            writeln!(out, "[{}]", cat)?;
            current_category = Some(cat);
        }
        writeln!(
            out,
            "  {id:<id_w$}  {name:<name_w$}  {sev:<5}  {desc}",
            id = rule.id(),
            name = rule.name(),
            sev = severity_label(*sev),
            desc = rule.description(),
            id_w = id_w,
            name_w = name_w,
        )?;
    }
    Ok(())
}

/// Print the full description and CWE references for a rule, looked up by id.
pub(crate) fn print_rule_explanation(
    registry: &RuleRegistry,
    rule_id: &str,
    out: &mut dyn Write,
) -> Result<(), Box<dyn std::error::Error>> {
    // Same reasoning as `print_rule_catalog`: `--explain` must be able to
    // explain an off-by-default rule like SC-A02 or SC-C01, not just the
    // ones that would currently fire.
    let rules = registry.all_rules();
    let Some((rule, sev)) = rules.iter().find(|(r, _)| r.id() == rule_id) else {
        return Err(format!("no rule with id '{}' — try `sqlkit audit --list-rules`", rule_id).into());
    };
    writeln!(out, "{} — {}", rule.id(), rule.name())?;
    writeln!(out, "  category: {}", rule.category())?;
    writeln!(out, "  severity: {}", severity_label(*sev))?;
    // `LintRule::cwe()`, not a regex scrape of `description()`. The rule
    // declares its CWE list (`cwe = ["CWE-78"]`); every canonical rule also
    // repeats those ids in its description prose, so the scrape happened to
    // agree -- a second derivation of one fact, held in sync by hand and by
    // nothing else. It does not agree for a user rule that declares `cwe`
    // without restating it in prose, which then reported no CWE at all.
    // `MatcherRule::cwe` keeps the description scrape as its own fallback for
    // the reverse case.
    let cwes = rule.cwe();
    if !cwes.is_empty() {
        writeln!(out, "  cwe:      {}", cwes.join(", "))?;
    }
    writeln!(out)?;
    writeln!(out, "{}", rule.description())?;
    Ok(())
}

/// Select the rules `sqlkit audit` will actually execute: the Security, Migration and
/// Antipattern rules; the rest of the registry is irrelevant here.
///
/// Returns the rules to run plus, when *nothing* is left to run, an
/// error-severity [`Finding`]. A zero-rule audit that prints no findings and
/// exits 0 is a verification apparatus reporting success without verifying:
/// the finding turns it into an exit-2 failure that names the cause.
/// `--exit-zero` still suppresses the exit code, as for any other finding.
fn prepare_audit_rules<'a>(
    rules: &[(&'a dyn LintRule, Severity)],
) -> (Vec<(&'a dyn LintRule, Severity)>, Option<Finding>) {
    let applicable: Vec<(&'a dyn LintRule, Severity)> = rules
        .iter()
        .filter(|(rule, _)| {
            matches!(
                rule.category(),
                RuleCategory::Security | RuleCategory::Migration | RuleCategory::Antipattern
            )
        })
        .copied()
        .collect();

    if applicable.is_empty() {
        let finding = Finding {
            file: String::new(),
            query_name: None,
            rule_id: "SC-AUDIT00".to_string(),
            rule_name: Some("no-applicable-rules".to_string()),
            rule_description: Some(
                "sqlkit audit had no rule to run, so it examined nothing. Reported as an error rather \
                 than an empty (clean-looking) report so an audit that verified nothing cannot pass a \
                 CI gate."
                    .to_string(),
            ),
            severity: Severity::Error,
            message: "every audit rule is configured off — audit examined 0 rules and cannot report on this \
                      project"
                .to_string(),
            line: None,
            column: None,
            cwe: Vec::new(),
            source: Some("audit".to_string()),
        };
        return (applicable, Some(finding));
    }

    (applicable, None)
}

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Off => "off",
        Severity::Warn => "warn",
        Severity::Error => "error",
    }
}

fn audit_from_config(config_path: &str, ignore_suppressions: bool) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    use serde::Deserialize;

    #[derive(Deserialize, Default)]
    struct AuditConfig {
        #[serde(default)]
        extra_rules: Vec<String>,
        #[serde(default, rename = "rule")]
        rules: Vec<RuleSpec>,
    }

    #[derive(Deserialize)]
    struct SqlkitConfig {
        sql: Vec<SqlConfig>,
        #[serde(default)]
        lint: Option<sqlkit_lint::types::LintConfig>,
        #[serde(default)]
        audit: AuditConfig,
    }

    #[derive(Deserialize)]
    struct SqlConfig {
        name: String,
        schema: Vec<String>,
        queries: Vec<String>,
        #[serde(default, rename = "engine")]
        _engine: PostgresEngine,
    }

    if !Path::new(config_path).exists() {
        return Err(format!("no files specified and config '{}' not found", config_path).into());
    }

    let config: SqlkitConfig = read_config(config_path)?;

    // `SC-PARSE01` has its own registry: an unparseable statement cannot
    // pick up its severity through `registry` -- see `ParseSeverities`.
    let LintRegistries {
        rules: mut registry,
        parse_severities,
    } = LintRegistries::from_config(config.lint.as_ref());
    let parse_severity = parse_severities.unparseable;

    let base_dir = config_dir(config_path);
    let matcher_registry = MatcherRegistry::canonical();

    let mut user_specs: Vec<(RuleSpec, String)> = config
        .audit
        .rules
        .into_iter()
        .map(|spec| (spec, config_path.to_string()))
        .collect();

    for rel_path in &config.audit.extra_rules {
        let abs_path = base_dir.join(rel_path);
        let path_str = abs_path.display().to_string();
        let specs = load_rules_from_file(&abs_path).map_err(|e: AuditConfigError| e.to_string())?;
        for spec in specs {
            user_specs.push((spec, path_str.clone()));
        }
    }

    if !user_specs.is_empty() {
        register_user_rules(&mut registry, &matcher_registry, &user_specs)
            .map_err(|e: AuditConfigError| e.to_string())?;
    }

    let rules = registry.active_rules();
    let (rules, no_rules_finding) = prepare_audit_rules(&rules);

    let mut findings = Vec::new();
    findings.extend(no_rules_finding);

    for sql_config in &config.sql {
        let schema_files = resolve_globs(&sql_config.schema, base_dir, &format!("[{}] schema", sql_config.name))?;
        let LoadedCatalog {
            catalog,
            schema_contents,
            ..
        } = load_catalog(CatalogLoadRequest {
            command: "audit",
            config_name: &sql_config.name,
            schema_files: &schema_files,
        })?;

        for (path, content) in schema_files.iter().zip(schema_contents.iter()) {
            findings.extend(run_security_rules_over_sql(
                path,
                content,
                &catalog,
                &rules,
                ignore_suppressions,
                parse_severity,
            ));
        }

        let query_files = resolve_globs(&sql_config.queries, base_dir, &format!("[{}] queries", sql_config.name))?;
        for query_file in &query_files {
            let content = std::fs::read_to_string(query_file)
                .map_err(|e| format!("failed to read query file '{}': {}", query_file, e))?;
            findings.extend(run_security_rules_over_sql(
                query_file,
                &content,
                &catalog,
                &rules,
                ignore_suppressions,
                parse_severity,
            ));
        }

        eprintln!(
            "[{}] audited {} schema file(s), {} query file(s)",
            sql_config.name,
            schema_files.len(),
            query_files.len()
        );
    }

    Ok(findings)
}

pub(crate) fn audit_explicit_files(
    files: &[String],
    ignore_suppressions: bool,
    config_path: &str,
) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let catalog = Catalog::from_ddl(&[]).expect("empty catalog");

    // Loads `sqlkit.toml`'s `[lint]`/`[audit]` sections when `config_path`
    // exists, falling back to the canonical registry when it does not --
    // explicit-file mode must still work with no config at all. Before
    // this, explicit-file mode always used a bare `default_registry()`, so
    // a rule turned `"off"` in `sqlkit.toml` still fired and `[[audit.rule]]`
    // user rules never ran (#206, item 2).
    let ExplicitAuditConfig {
        registry,
        parse_severity,
    } = load_explicit_config(config_path)?;
    let all_active = registry.active_rules();
    let (rules, no_rules_finding) = prepare_audit_rules(&all_active);

    let mut findings = Vec::new();
    if let Some(finding) = no_rules_finding {
        findings.push(finding);
    }
    for path in files {
        let content = std::fs::read_to_string(path).map_err(|e| format!("failed to read '{}': {}", path, e))?;
        findings.extend(run_security_rules_over_sql(
            path,
            &content,
            &catalog,
            &rules,
            ignore_suppressions,
            parse_severity,
        ));
    }
    Ok(findings)
}

/// Parse `sql` statement-by-statement and run every security rule over each.
///
/// # Recovery
///
/// Uses [`parse_statements_lenient`], not
/// [`sqlparser::parser::Parser::parse_sql`]: a statement that fails to parse
/// is skipped (and reported as its own `SC-PARSE01` finding, at
/// `parse_severity`, naming the line and the parser's message) rather than
/// discarding every statement already parsed. See #208. `parse_severity` is
/// resolved by the caller from [`sqlkit_lint::parse_registry`] (see
/// [`load_explicit_config`]) rather than hardcoded here, so `[lint.rules]
/// "SC-PARSE01" = "warn"` reaches this finding too.
///
/// # Rule set
///
/// `rules` must already be narrowed to audit's categories by [`prepare_audit_rules`].
///
/// # Suppression
///
/// A `SuppressionSet` is built once from the full SQL string and looked up by
/// each statement's starting byte offset ([`sqlkit_lint::ParsedStatement::offset`]) -- see
/// its module docs. An index counted separately by `SuppressionSet` could
/// disagree with the statements that actually parsed and move suppressions
/// onto the wrong statement; a position cannot.
///
/// # Reported line numbers
///
/// Statement start lines (used for [`Finding::line`], *not* for suppression
/// lookup) come from [`parse_statements_lenient`], which reads them from the
/// parser's own token positions. This avoids re-splitting on `;` (which is
/// quote-unsafe) and gives accurate 1-based line numbers even for multi-line
/// statements.
pub(crate) fn run_security_rules_over_sql(
    path: &str,
    sql: &str,
    catalog: &Catalog,
    rules: &[(&dyn sqlkit_lint::LintRule, Severity)],
    ignore_suppressions: bool,
    parse_severity: Severity,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let suppressions = SuppressionSet::parse(sql);

    let (statements, failures) = parse_statements_lenient(sql);

    for failure in &failures {
        eprintln!(
            "warning: failed to parse a statement in '{}' at line {}: {}",
            path, failure.line, failure.message
        );
        findings.push(Finding {
            file: path.to_string(),
            query_name: None,
            rule_id: "SC-PARSE01".to_string(),
            rule_name: Some("unparseable statement".to_string()),
            rule_description: Some(
                "A statement could not be parsed and was skipped, so no security rule could examine it. \
                 This is reported as an error rather than only a stderr warning so a parser gap cannot \
                 silently disable auditing for part of a file."
                    .to_string(),
            ),
            severity: parse_severity,
            message: format!(
                "failed to parse statement at line {}: {}",
                failure.line, failure.message
            ),
            line: Some(failure.line),
            column: None,
            cwe: Vec::new(),
            source: Some("audit".to_string()),
        });
    }

    let empty_annotations = Annotations::default();
    let empty_analyzed = AnalyzedQuery::default();

    for statement in &statements {
        let ctx = LintContext {
            sql,
            stmt: &statement.stmt,
            analyzed: &empty_analyzed,
            catalog,
            annotations: &empty_annotations,
        };

        for (rule, severity) in rules {
            for violation in rule.check_query(&ctx) {
                if !ignore_suppressions
                    && !suppressions.is_empty()
                    && suppressions.is_suppressed(&violation.rule_id, statement.offset)
                {
                    continue;
                }

                findings.push(Finding {
                    file: path.to_string(),
                    query_name: None,
                    rule_id: violation.rule_id.to_string(),
                    rule_name: Some(rule.name().to_string()),
                    rule_description: Some(rule.description().to_string()),
                    severity: *severity,
                    message: violation.message,
                    line: Some(statement.line),
                    column: None,
                    // `LintRule::cwe()`, not `extract_cwe(rule.description())`
                    // -- the rule's declaration rather than a regex over its
                    // prose. See `print_rule_explanation` for what the scrape
                    // got wrong.
                    cwe: rule.cwe(),
                    source: Some("audit".to_string()),
                });
            }
        }
    }

    findings
}
