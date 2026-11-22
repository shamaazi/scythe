use std::borrow::Cow;

use ahash::AHashMap;

use super::registry::RuleRegistry;
use super::rule::LintRule;
use super::rules::codegen::DuplicateQueryNames;
use super::types::{LintContext, Severity, Violation};
use sqlkit_core::catalog::Catalog;

// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct QueryViolation {
    pub query_name: String,
    pub rule_id: Cow<'static, str>,
    pub severity: Severity,
    pub message: String,
}

#[derive(Debug)]
pub struct LintReport {
    pub violations: Vec<QueryViolation>,
    pub queries_checked: usize,
    pub rules_active: usize,
}

impl LintReport {
    pub fn has_errors(&self) -> bool {
        self.violations.iter().any(|v| matches!(v.severity, Severity::Error))
    }

    pub fn has_warnings(&self) -> bool {
        self.violations.iter().any(|v| matches!(v.severity, Severity::Warn))
    }
}

pub struct LintEngine {
    registry: RuleRegistry,
}

impl LintEngine {
    pub fn new(registry: RuleRegistry) -> Self {
        Self { registry }
    }

    /// Lint a single query, returning violations.
    pub fn check_query(&self, ctx: &LintContext<'_>) -> Vec<(Violation, Severity)> {
        let mut results = Vec::new();
        for (rule, sev) in self.registry.active_rules() {
            for v in rule.check_query(ctx) {
                results.push((v, sev));
            }
        }
        results
    }

    /// Lint the catalog (table naming, etc.), returning violations.
    pub fn check_catalog(&self, catalog: &Catalog) -> Vec<(Violation, Severity)> {
        let mut results = Vec::new();
        for (rule, sev) in self.registry.active_rules() {
            for v in rule.check_catalog(catalog) {
                results.push((v, sev));
            }
        }
        results
    }

    /// The cross-query duplicate-`@name` check (`SC-C03`).
    ///
    /// Separate from [`check_query`](Self::check_query) because it is not a
    /// per-query question: `DuplicateQueryNames` implements no `check_query`
    /// and never can, since a `LintContext` describes one query and cannot
    /// see the others. That left `SC-C03` advertised at `error` severity by
    /// `sqlkit audit --list-rules` while being unable to produce a finding
    /// from any command (#137).
    ///
    /// This is the one implementation of the check; [`build_report`] calls
    /// it, and a caller that drives `check_query` itself must call it too, or
    /// duplicate `@name`s go unreported and `sqlkit generate` emits two
    /// functions with the same name.
    ///
    /// Returns nothing when `DuplicateQueryNames` is not registered or is
    /// configured `off` — its severity comes from the registry, so
    /// `[lint.rules] "SC-C03" = "warn"` is honoured rather than overridden by
    /// a hardcoded `Severity::Error`. Each duplicated name is reported once,
    /// however many times it occurs, with the occurrence count in the
    /// message.
    pub fn check_duplicate_query_names<'n>(&self, names: impl IntoIterator<Item = &'n str>) -> Vec<QueryViolation> {
        self.check_duplicate_query_names_scoped(names.into_iter().map(|name| (0, name)))
    }

    /// [`check_duplicate_query_names`](Self::check_duplicate_query_names)
    /// where a name only has to be unique within its scope: each name comes
    /// with the index of the module it is generated into. A block whose every
    /// `[[sql.gen]]` target writes one module per query file (`{dir}`)
    /// scopes names by query file; any other block uses a single scope.
    pub fn check_duplicate_query_names_scoped<'n>(
        &self,
        names: impl IntoIterator<Item = (usize, &'n str)>,
    ) -> Vec<QueryViolation> {
        // The id comes from the rule itself rather than a `"SC-C03"` literal:
        // the rule struct and the finding it produces must not be two
        // derivations of one id that can drift apart.
        let wanted_id = DuplicateQueryNames.id();
        let Some(severity) = self
            .registry
            .active_rules()
            .iter()
            .find(|(rule, _)| rule.id() == wanted_id)
            .map(|(_, sev)| *sev)
        else {
            return Vec::new();
        };

        let mut counts: AHashMap<(usize, &str), usize> = AHashMap::new();
        let mut first_seen: Vec<(usize, &str)> = Vec::new();
        for scoped in names {
            let count = counts.entry(scoped).or_insert(0);
            *count += 1;
            if *count == 1 {
                first_seen.push(scoped);
            }
        }

        first_seen
            .into_iter()
            .filter_map(|scoped| {
                let count = counts[&scoped];
                let (_, name) = scoped;
                (count > 1).then(|| QueryViolation {
                    query_name: name.to_string(),
                    rule_id: Cow::Borrowed(wanted_id),
                    severity,
                    message: format!("duplicate query name: \"{}\" ({} occurrences)", name, count),
                })
            })
            .collect()
    }

    /// Run all checks over a set of queries and produce a report.
    ///
    /// `queries` is an iterator of `LintContext` for each query.
    /// The engine also performs cross-query checks (e.g. duplicate names).
    pub fn build_report<'a>(&self, queries: impl Iterator<Item = LintContext<'a>>, catalog: &Catalog) -> LintReport {
        self.build_report_scoped(queries.map(|ctx| (0, ctx)), catalog)
    }

    /// [`build_report`](Self::build_report) with each query paired with the
    /// scope its name must be unique in; see
    /// [`check_duplicate_query_names_scoped`](Self::check_duplicate_query_names_scoped).
    pub fn build_report_scoped<'a>(
        &self,
        queries: impl Iterator<Item = (usize, LintContext<'a>)>,
        catalog: &Catalog,
    ) -> LintReport {
        let active = self.registry.active_rules();
        let rules_active = active.len();
        let mut violations = Vec::new();
        let mut queries_checked: usize = 0;
        let mut names: Vec<(usize, String)> = Vec::new();

        for (scope, ctx) in queries {
            queries_checked += 1;
            names.push((scope, ctx.analyzed.name.clone()));

            for (rule, sev) in &active {
                for v in rule.check_query(&ctx) {
                    violations.push(QueryViolation {
                        query_name: ctx.analyzed.name.clone(),
                        rule_id: v.rule_id,
                        severity: *sev,
                        message: v.message,
                    });
                }
            }
        }

        violations
            .extend(self.check_duplicate_query_names_scoped(names.iter().map(|(scope, name)| (*scope, name.as_str()))));

        for (rule, sev) in &active {
            for v in rule.check_catalog(catalog) {
                violations.push(QueryViolation {
                    query_name: String::new(),
                    rule_id: v.rule_id,
                    severity: *sev,
                    message: v.message,
                });
            }
        }

        LintReport {
            violations,
            queries_checked,
            rules_active,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::RuleRegistry;
    use crate::rule::LintRule;
    use crate::types::{LintConfig, LintContext, RuleCategory, Violation};
    use sqlkit_core::analyzer::AnalyzedQuery;
    use sqlkit_core::catalog::Catalog;
    use sqlkit_core::parser::{Annotations, QueryCommand};
    use sqlparser::ast::Statement;
    use sqlparser::dialect::PostgreSqlDialect;
    use sqlparser::parser::Parser;
    use std::borrow::Cow;

    /// A test rule that always emits one query-level violation.
    struct AlwaysWarnRule;

    impl LintRule for AlwaysWarnRule {
        fn id(&self) -> &'static str {
            "TEST-01"
        }
        fn name(&self) -> &'static str {
            "always-warn"
        }
        fn category(&self) -> RuleCategory {
            RuleCategory::Safety
        }
        fn default_severity(&self) -> Severity {
            Severity::Warn
        }
        fn description(&self) -> &'static str {
            "always fires"
        }
        fn check_query(&self, _ctx: &LintContext<'_>) -> Vec<Violation> {
            vec![Violation {
                rule_id: Cow::Borrowed("TEST-01"),
                message: "always fires".to_string(),
                fix: None,
            }]
        }
    }

    /// A test rule that always emits one catalog-level violation.
    struct CatalogRule;

    impl LintRule for CatalogRule {
        fn id(&self) -> &'static str {
            "TEST-CAT"
        }
        fn name(&self) -> &'static str {
            "catalog-rule"
        }
        fn category(&self) -> RuleCategory {
            RuleCategory::Naming
        }
        fn default_severity(&self) -> Severity {
            Severity::Error
        }
        fn description(&self) -> &'static str {
            "catalog level check"
        }
        fn check_catalog(&self, _catalog: &Catalog) -> Vec<Violation> {
            vec![Violation {
                rule_id: Cow::Borrowed("TEST-CAT"),
                message: "catalog issue".to_string(),
                fix: None,
            }]
        }
    }

    /// A silent rule that never fires.
    struct SilentRule;

    impl LintRule for SilentRule {
        fn id(&self) -> &'static str {
            "TEST-SILENT"
        }
        fn name(&self) -> &'static str {
            "silent-rule"
        }
        fn category(&self) -> RuleCategory {
            RuleCategory::Style
        }
        fn default_severity(&self) -> Severity {
            Severity::Warn
        }
        fn description(&self) -> &'static str {
            "never fires"
        }
    }

    fn parse_stmt(sql: &str) -> Statement {
        let dialect = PostgreSqlDialect {};
        Parser::parse_sql(&dialect, sql).unwrap().remove(0)
    }

    fn empty_catalog() -> Catalog {
        Catalog::from_ddl(&[]).unwrap()
    }

    fn dummy_analyzed(name: &str) -> AnalyzedQuery {
        AnalyzedQuery::build(|aq| {
            aq.name = name.to_string();
            aq.command = QueryCommand::Many;
            aq.sql = "SELECT 1".to_string();
            aq.columns = vec![];
            aq.params = vec![];
            aq.deprecated = None;
            aq.source_table = None;
            aq.composites = vec![];
            aq.enums = vec![];
            aq.optional_params = vec![];
            aq.group_by = None;
            aq.custom = vec![];
        })
    }

    fn dummy_annotations(name: &str) -> Annotations {
        Annotations {
            name: name.to_string(),
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
        }
    }

    fn make_ctx<'a>(
        sql: &'a str,
        stmt: &'a Statement,
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
    fn lint_engine_new_creates_engine() {
        let reg = RuleRegistry::new();
        let engine = LintEngine::new(reg);
        let catalog = empty_catalog();
        let report = engine.build_report(std::iter::empty(), &catalog);
        assert_eq!(report.rules_active, 0);
        assert_eq!(report.queries_checked, 0);
        assert!(report.violations.is_empty());
    }

    #[test]
    fn check_query_returns_violations_from_active_rules() {
        let mut reg = RuleRegistry::new();
        reg.register(Box::new(AlwaysWarnRule));
        let engine = LintEngine::new(reg);

        let sql = "SELECT 1";
        let stmt = parse_stmt(sql);
        let catalog = empty_catalog();
        let analyzed = dummy_analyzed("test_query");
        let annotations = dummy_annotations("test_query");
        let ctx = make_ctx(sql, &stmt, &analyzed, &catalog, &annotations);

        let results = engine.check_query(&ctx);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0.rule_id, "TEST-01");
        assert_eq!(results[0].1, Severity::Warn);
    }

    #[test]
    fn check_query_respects_severity_overrides_off() {
        let mut reg = RuleRegistry::new();
        reg.register(Box::new(AlwaysWarnRule));
        let mut config = LintConfig::default();
        config.rules.insert("TEST-01".to_string(), Severity::Off);
        reg.apply_config(&config);
        let engine = LintEngine::new(reg);

        let sql = "SELECT 1";
        let stmt = parse_stmt(sql);
        let catalog = empty_catalog();
        let analyzed = dummy_analyzed("test_query");
        let annotations = dummy_annotations("test_query");
        let ctx = make_ctx(sql, &stmt, &analyzed, &catalog, &annotations);

        let results = engine.check_query(&ctx);
        assert!(results.is_empty(), "Off rule should not fire");
    }

    #[test]
    fn check_catalog_returns_catalog_level_violations() {
        let mut reg = RuleRegistry::new();
        reg.register(Box::new(CatalogRule));
        let engine = LintEngine::new(reg);

        let catalog = empty_catalog();
        let results = engine.check_catalog(&catalog);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0.rule_id, "TEST-CAT");
        assert_eq!(results[0].1, Severity::Error);
    }

    #[test]
    fn build_report_counts_errors_vs_warnings() {
        let mut reg = RuleRegistry::new();
        reg.register(Box::new(AlwaysWarnRule));
        let engine = LintEngine::new(reg);

        let sql = "SELECT 1";
        let stmt = parse_stmt(sql);
        let catalog = empty_catalog();
        let analyzed = dummy_analyzed("q1");
        let annotations = dummy_annotations("q1");
        let ctx = make_ctx(sql, &stmt, &analyzed, &catalog, &annotations);

        let report = engine.build_report(std::iter::once(ctx), &catalog);
        assert_eq!(report.queries_checked, 1);
        assert_eq!(report.rules_active, 1);
        assert!(report.has_warnings());
        assert!(!report.has_errors());
    }

    #[test]
    fn build_report_with_mixed_severities() {
        let mut reg = RuleRegistry::new();
        reg.register(Box::new(AlwaysWarnRule));
        reg.register(Box::new(CatalogRule));
        reg.register(Box::new(SilentRule));
        let engine = LintEngine::new(reg);

        let sql = "SELECT 1";
        let stmt = parse_stmt(sql);
        let catalog = empty_catalog();
        let analyzed = dummy_analyzed("q1");
        let annotations = dummy_annotations("q1");
        let ctx = make_ctx(sql, &stmt, &analyzed, &catalog, &annotations);

        let report = engine.build_report(std::iter::once(ctx), &catalog);
        assert_eq!(report.queries_checked, 1);
        assert_eq!(report.rules_active, 3);
        assert!(report.has_warnings());
        assert!(report.has_errors());
        assert_eq!(report.violations.len(), 2);
    }

    #[test]
    fn build_report_duplicate_query_names() {
        let mut reg = RuleRegistry::new();
        reg.register(Box::new(SilentRule));
        reg.register(Box::new(crate::rules::codegen::DuplicateQueryNames));
        let engine = LintEngine::new(reg);

        let sql = "SELECT 1";
        let stmt = parse_stmt(sql);
        let catalog = empty_catalog();

        let analyzed1 = dummy_analyzed("dup_name");
        let annotations1 = dummy_annotations("dup_name");
        let analyzed2 = dummy_analyzed("dup_name");
        let annotations2 = dummy_annotations("dup_name");
        let analyzed3 = dummy_analyzed("unique_name");
        let annotations3 = dummy_annotations("unique_name");

        let queries = vec![
            make_ctx(sql, &stmt, &analyzed1, &catalog, &annotations1),
            make_ctx(sql, &stmt, &analyzed2, &catalog, &annotations2),
            make_ctx(sql, &stmt, &analyzed3, &catalog, &annotations3),
        ];

        let report = engine.build_report(queries.into_iter(), &catalog);
        assert_eq!(report.queries_checked, 3);

        let dup_violations: Vec<_> = report.violations.iter().filter(|v| v.rule_id == "SC-C03").collect();
        assert_eq!(dup_violations.len(), 1);
        assert_eq!(dup_violations[0].query_name, "dup_name");
        assert_eq!(dup_violations[0].severity, Severity::Error);
        assert!(dup_violations[0].message.contains("duplicate query name"));
    }

    /// Regression for #137: `engine.rs` used to hardcode `Severity::Error`
    /// for SC-C03 regardless of `[lint.rules]`, so
    /// `"SC-C03" = "warn"` had no effect. The emitted violation's severity
    /// must now track the rule's effective (configured) severity.
    #[test]
    fn build_report_duplicate_query_names_honours_severity_override() {
        let mut reg = RuleRegistry::new();
        reg.register(Box::new(crate::rules::codegen::DuplicateQueryNames));
        let mut config = LintConfig::default();
        config.rules.insert("SC-C03".to_string(), Severity::Warn);
        reg.apply_config(&config);
        let engine = LintEngine::new(reg);

        let sql = "SELECT 1";
        let stmt = parse_stmt(sql);
        let catalog = empty_catalog();

        let analyzed1 = dummy_analyzed("dup_name");
        let annotations1 = dummy_annotations("dup_name");
        let analyzed2 = dummy_analyzed("dup_name");
        let annotations2 = dummy_annotations("dup_name");

        let queries = vec![
            make_ctx(sql, &stmt, &analyzed1, &catalog, &annotations1),
            make_ctx(sql, &stmt, &analyzed2, &catalog, &annotations2),
        ];

        let report = engine.build_report(queries.into_iter(), &catalog);
        let dup_violations: Vec<_> = report.violations.iter().filter(|v| v.rule_id == "SC-C03").collect();
        assert_eq!(dup_violations.len(), 1);
        assert_eq!(
            dup_violations[0].severity,
            Severity::Warn,
            "SC-C03 severity override must be honoured, not hardcoded to Error"
        );
    }

    /// Regression for #137: when `DuplicateQueryNames` is not registered at
    /// all (nothing has configured a severity for SC-C03), build_report must
    /// not synthesize an SC-C03 violation out of thin air.
    #[test]
    fn build_report_no_duplicate_violation_when_rule_not_registered() {
        let reg = RuleRegistry::new();
        let engine = LintEngine::new(reg);

        let sql = "SELECT 1";
        let stmt = parse_stmt(sql);
        let catalog = empty_catalog();

        let analyzed1 = dummy_analyzed("dup_name");
        let annotations1 = dummy_annotations("dup_name");
        let analyzed2 = dummy_analyzed("dup_name");
        let annotations2 = dummy_annotations("dup_name");

        let queries = vec![
            make_ctx(sql, &stmt, &analyzed1, &catalog, &annotations1),
            make_ctx(sql, &stmt, &analyzed2, &catalog, &annotations2),
        ];

        let report = engine.build_report(queries.into_iter(), &catalog);
        let dup_violations: Vec<_> = report.violations.iter().filter(|v| v.rule_id == "SC-C03").collect();
        assert!(dup_violations.is_empty());
    }

    /// Regression for #137: `[lint.rules] "SC-C03" = "off"` must silence the
    /// duplicate-name check entirely, same as any other rule.
    #[test]
    fn build_report_duplicate_query_names_off_produces_no_violation() {
        let mut reg = RuleRegistry::new();
        reg.register(Box::new(crate::rules::codegen::DuplicateQueryNames));
        let mut config = LintConfig::default();
        config.rules.insert("SC-C03".to_string(), Severity::Off);
        reg.apply_config(&config);
        let engine = LintEngine::new(reg);

        let sql = "SELECT 1";
        let stmt = parse_stmt(sql);
        let catalog = empty_catalog();

        let analyzed1 = dummy_analyzed("dup_name");
        let annotations1 = dummy_annotations("dup_name");
        let analyzed2 = dummy_analyzed("dup_name");
        let annotations2 = dummy_annotations("dup_name");

        let queries = vec![
            make_ctx(sql, &stmt, &analyzed1, &catalog, &annotations1),
            make_ctx(sql, &stmt, &analyzed2, &catalog, &annotations2),
        ];

        let report = engine.build_report(queries.into_iter(), &catalog);
        let dup_violations: Vec<_> = report.violations.iter().filter(|v| v.rule_id == "SC-C03").collect();
        assert!(dup_violations.is_empty());
    }

    #[test]
    fn build_report_no_duplicates_when_names_unique() {
        let reg = RuleRegistry::new();
        let engine = LintEngine::new(reg);

        let sql = "SELECT 1";
        let stmt = parse_stmt(sql);
        let catalog = empty_catalog();

        let analyzed1 = dummy_analyzed("alpha");
        let annotations1 = dummy_annotations("alpha");
        let analyzed2 = dummy_analyzed("beta");
        let annotations2 = dummy_annotations("beta");

        let queries = vec![
            make_ctx(sql, &stmt, &analyzed1, &catalog, &annotations1),
            make_ctx(sql, &stmt, &analyzed2, &catalog, &annotations2),
        ];

        let report = engine.build_report(queries.into_iter(), &catalog);
        assert_eq!(report.queries_checked, 2);
        let dup_violations: Vec<_> = report.violations.iter().filter(|v| v.rule_id == "SC-C03").collect();
        assert!(dup_violations.is_empty());
    }

    #[test]
    fn lint_report_has_errors_and_has_warnings() {
        let report = LintReport {
            violations: vec![
                QueryViolation {
                    query_name: "q1".to_string(),
                    rule_id: Cow::Borrowed("R1"),
                    severity: Severity::Warn,
                    message: "warning".to_string(),
                },
                QueryViolation {
                    query_name: "q2".to_string(),
                    rule_id: Cow::Borrowed("R2"),
                    severity: Severity::Error,
                    message: "error".to_string(),
                },
            ],
            queries_checked: 2,
            rules_active: 1,
        };
        assert!(report.has_errors());
        assert!(report.has_warnings());
    }

    #[test]
    fn lint_report_empty_has_no_errors_or_warnings() {
        let report = LintReport {
            violations: vec![],
            queries_checked: 0,
            rules_active: 0,
        };
        assert!(!report.has_errors());
        assert!(!report.has_warnings());
    }

    /// #137: the duplicate-name check must be reachable *without* going
    /// through `build_report`. `sqlkit lint` drives `check_query` /
    /// `check_catalog` directly and never calls `build_report`, which is
    /// exactly why SC-C03 could not fire from any command. A caller in that
    /// shape needs one call it can make with the names it already has.
    #[test]
    fn check_duplicate_query_names_reports_duplicates_without_build_report() {
        let mut reg = RuleRegistry::new();
        reg.register(Box::new(crate::rules::codegen::DuplicateQueryNames));
        let engine = LintEngine::new(reg);

        let violations = engine.check_duplicate_query_names(["GetUser", "ListUsers", "GetUser"]);

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule_id, "SC-C03");
        assert_eq!(violations[0].query_name, "GetUser");
        assert_eq!(violations[0].severity, Severity::Error);
        assert_eq!(
            violations[0].message,
            "duplicate query name: \"GetUser\" (2 occurrences)"
        );
    }

    /// #137: a name repeated three times is one problem, not two. The old
    /// code pushed a violation per *extra* occurrence, so three `GetUser`
    /// queries produced two identical findings.
    #[test]
    fn check_duplicate_query_names_reports_each_name_once_with_its_count() {
        let mut reg = RuleRegistry::new();
        reg.register(Box::new(crate::rules::codegen::DuplicateQueryNames));
        let engine = LintEngine::new(reg);

        let violations = engine.check_duplicate_query_names(["GetUser", "GetUser", "GetUser", "Other"]);

        assert_eq!(violations.len(), 1);
        assert_eq!(
            violations[0].message,
            "duplicate query name: \"GetUser\" (3 occurrences)"
        );
    }

    /// Under per-file output each query file is its own module, so a name may
    /// repeat across scopes; only a repeat within one scope is a duplicate.
    #[test]
    fn check_duplicate_query_names_scoped_allows_repeats_across_scopes() {
        let mut reg = RuleRegistry::new();
        reg.register(Box::new(crate::rules::codegen::DuplicateQueryNames));
        let engine = LintEngine::new(reg);

        let violations = engine.check_duplicate_query_names_scoped([(0, "GetUser"), (1, "GetUser"), (1, "GetUser")]);

        assert_eq!(violations.len(), 1);
        assert_eq!(
            violations[0].message,
            "duplicate query name: \"GetUser\" (2 occurrences)"
        );
    }

    /// #137: unique names must produce nothing at all — the check must not
    /// be able to fire vacuously on a healthy project.
    #[test]
    fn check_duplicate_query_names_is_silent_when_every_name_is_unique() {
        let mut reg = RuleRegistry::new();
        reg.register(Box::new(crate::rules::codegen::DuplicateQueryNames));
        let engine = LintEngine::new(reg);

        assert!(engine.check_duplicate_query_names(["A", "B", "C"]).is_empty());
        assert!(engine.check_duplicate_query_names([]).is_empty());
    }

    /// #137: the id on the finding must come from the rule, so the rule the
    /// registry advertises and the finding a run emits cannot drift apart.
    #[test]
    fn check_duplicate_query_names_uses_the_rules_own_id() {
        use crate::rule::LintRule;

        let mut reg = RuleRegistry::new();
        reg.register(Box::new(crate::rules::codegen::DuplicateQueryNames));
        let engine = LintEngine::new(reg);

        let violations = engine.check_duplicate_query_names(["dup", "dup"]);
        assert_eq!(violations.len(), 1);
        assert_eq!(
            violations[0].rule_id,
            crate::rules::codegen::DuplicateQueryNames.id(),
            "the finding's id must be the registered rule's id"
        );
    }

    /// #137: `build_report` and the standalone check must be the same
    /// derivation — a caller must not get a different verdict depending on
    /// which entry point it used.
    #[test]
    fn build_report_and_check_duplicate_query_names_agree() {
        let mut reg = RuleRegistry::new();
        reg.register(Box::new(crate::rules::codegen::DuplicateQueryNames));
        let engine = LintEngine::new(reg);

        let sql = "SELECT 1";
        let stmt = parse_stmt(sql);
        let catalog = empty_catalog();

        let names = ["dup", "dup", "dup", "solo"];
        let analyzed: Vec<_> = names.iter().map(|n| dummy_analyzed(n)).collect();
        let annotations: Vec<_> = names.iter().map(|n| dummy_annotations(n)).collect();
        let queries: Vec<_> = analyzed
            .iter()
            .zip(annotations.iter())
            .map(|(a, ann)| make_ctx(sql, &stmt, a, &catalog, ann))
            .collect();

        let report = engine.build_report(queries.into_iter(), &catalog);
        let from_report: Vec<(&str, &str)> = report
            .violations
            .iter()
            .filter(|v| v.rule_id == "SC-C03")
            .map(|v| (v.query_name.as_str(), v.message.as_str()))
            .collect();

        let standalone = engine.check_duplicate_query_names(names);
        let from_standalone: Vec<(&str, &str)> = standalone
            .iter()
            .map(|v| (v.query_name.as_str(), v.message.as_str()))
            .collect();

        assert_eq!(from_report, from_standalone);
        assert_eq!(from_report.len(), 1);
    }
}
