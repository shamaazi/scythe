pub mod audit;
pub mod engine;
pub mod registry;
pub mod reporters;
pub mod rule;
pub mod rules;
pub mod sqruff_adapter;
pub mod types;

pub use audit::{
    AuditConfigError, MatcherArgsError, MatcherFn, MatcherHit, MatcherRegistry, MatcherRule, ParsedStatement, RuleSpec,
    StatementParseFailure, SuppressionSet, canonical_specs, first_token_offset, load_rules_from_file, parse_rule_file,
    parse_statements_lenient, register_user_rules, validate_matcher_args,
};
pub use engine::{LintEngine, LintReport, NameScope, QueryViolation};
pub use registry::{RuleRegistry, default_registry, drift_registry, parse_registry, provenance_registry};
pub use reporters::{Finding, Format, emit as emit_findings, extract_cwe};
pub use rule::LintRule;
pub use sqruff_adapter::{SqruffConfigError, SqruffLinter, SqruffViolation};
pub use types::{LintConfig, LintContext, LintFix, RuleCategory, Severity, SqruffConfig, Violation};
