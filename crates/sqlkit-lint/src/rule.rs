use super::types::{LintConfig, LintContext, RuleCategory, Severity, Violation};
use sqlkit_core::catalog::Catalog;

/// A single lint rule that can inspect queries and/or the catalog.
pub trait LintRule: Send + Sync {
    /// Unique identifier, e.g. "SC-S01".
    fn id(&self) -> &'static str;

    /// Human-readable short name.
    fn name(&self) -> &'static str;

    /// Category this rule belongs to.
    fn category(&self) -> RuleCategory;

    /// Default severity when no config overrides it.
    fn default_severity(&self) -> Severity;

    /// One-line description of what the rule checks.
    fn description(&self) -> &'static str;

    /// CWE identifiers this rule maps to (e.g. `["CWE-78"]`), if any.
    ///
    /// Defaults to empty: most `LintRule` implementors are plain SQL-shape
    /// checks with no CWE mapping. [`crate::audit::MatcherRule`] overrides
    /// this to expose its [`crate::audit::RuleSpec::cwe`] — falling back to
    /// scanning [`description`](Self::description) for a `CWE-\d+` pattern
    /// only when the spec declared none — so a caller reporting security
    /// findings (e.g. as SARIF) never has to know whether it is looking at a
    /// canonical or a user-supplied rule to get the right CWE list.
    fn cwe(&self) -> Vec<String> {
        Vec::new()
    }

    /// Read this rule's settings from the `[lint]` table. The registry calls
    /// it on every rule whenever a configuration is applied, so a rule with
    /// options (SC-N03 reads `[lint.naming] query_prefixes`) takes them here;
    /// a rule without options keeps this no-op default.
    fn configure(&mut self, _config: &LintConfig) {}

    /// Check a single parsed + analyzed query.  Returns violations found.
    fn check_query(&self, _ctx: &LintContext<'_>) -> Vec<Violation> {
        Vec::new()
    }

    /// Check the full catalog (useful for cross-table / naming rules).
    fn check_catalog(&self, _catalog: &Catalog) -> Vec<Violation> {
        Vec::new()
    }
}
