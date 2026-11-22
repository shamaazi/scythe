//! Inline suppression comments — `-- sqlkit-audit: ignore[ID1,ID2,...]`.
//!
//! # Annotation syntax
//!
//! ```text
//! -- sqlkit-audit: ignore[SC-SEC01,SC-SEC02] reason="vetted by security team"
//! ```
//!
//! - Leading whitespace is allowed.
//! - The comment prefix must be `--` (two dashes); block comments are not supported.
//! - IDs are `[A-Z][A-Z0-9-]*`, separated by commas with no internal whitespace.
//! - The optional `reason="..."` clause is parsed and discarded.
//! - Malformed annotations are silently ignored (no panic, no suppression created).
//!
//! # Attachment rules
//!
//! An annotation attaches only to the statement whose first non-blank,
//! non-comment line **immediately** follows it — a blank line between the
//! annotation and the statement discards the pending annotation entirely (it
//! does not "reach through" the blank line). Multiple consecutive annotation
//! lines stack their ID sets onto whatever statement follows them.
//!
//! # Keying: statement position, not index
//!
//! Suppressions are keyed by the **byte offset** at which the annotated
//! statement starts: the first non-whitespace character of the content line
//! following the annotation. A caller looks a statement up by the offset of
//! its first token in the same SQL string
//! ([`ParsedStatement::offset`](super::ParsedStatement::offset), or
//! [`first_token_offset`](super::first_token_offset) for a single-statement
//! block), so:
//!
//! - two statements on one line (`DROP TABLE a; DROP TABLE b;`) are told
//!   apart -- only the first starts where the line's content does;
//! - a statement spanning several lines is looked up once, by its start;
//! - an annotation followed by a line that continues an earlier statement
//!   attaches to nothing;
//! - nothing depends on how many statements came before. Keying by a
//!   statement *index* counted from the `;`s on each line drifted whenever
//!   the caller numbered statements differently -- a statement that failed
//!   to parse, an empty statement (`;;`), or a `;` inside a string literal,
//!   comment or dollar-quoted body moved every later suppression onto the
//!   wrong statement.
//!
//! Because the key is where the content line starts, the statement must
//! begin its line: one that follows a block comment on the same line
//! (`/* c */ SELECT ...`) does not receive the annotation.

use ahash::{AHashMap, AHashSet};

/// The literal prefix that introduces a suppression annotation.
const ANNOTATION_PREFIX: &str = "-- sqlkit-audit: ignore[";

/// Set of per-statement rule-ID suppressions parsed from inline annotations.
#[derive(Debug, Default)]
pub struct SuppressionSet {
    /// Map: byte offset where the annotated statement starts → set of
    /// suppressed rule IDs.
    by_offset: AHashMap<usize, AHashSet<String>>,
}

impl SuppressionSet {
    /// Parse a complete SQL string and build the suppression set from every
    /// `-- sqlkit-audit: ignore[…]` annotation found in it.
    pub fn parse(sql: &str) -> Self {
        let mut set = Self::default();
        let mut pending: AHashSet<String> = AHashSet::new();
        let mut line_start = 0;

        for line in sql.split('\n') {
            let offset = line_start;
            line_start += line.len() + 1;

            let trimmed = line.trim();
            if trimmed.is_empty() {
                pending.clear();
                continue;
            }
            if let Some(ids) = try_parse_annotation(trimmed) {
                pending.extend(ids);
                continue;
            }
            if trimmed.starts_with("--") {
                continue;
            }

            // A content line: the pending annotation belongs to whichever
            // statement starts where this line's content does.
            if !pending.is_empty() {
                let start = offset + (line.len() - line.trim_start().len());
                set.by_offset.entry(start).or_default().extend(pending.drain());
            }
        }

        set
    }

    /// Return `true` if `rule_id` is suppressed on the statement whose first
    /// token is at byte `stmt_offset` of the parsed SQL (see the module docs).
    pub fn is_suppressed(&self, rule_id: &str, stmt_offset: usize) -> bool {
        self.by_offset
            .get(&stmt_offset)
            .is_some_and(|ids| ids.contains(rule_id))
    }

    /// Return `true` if no suppressions are recorded.
    pub fn is_empty(&self) -> bool {
        self.by_offset.is_empty()
    }
}

/// Attempt to parse a trimmed line as a `-- sqlkit-audit: ignore[ID,...]`
/// annotation.  Returns `Some(ids)` on success; `None` if the line is not a
/// matching annotation or the annotation is malformed.
fn try_parse_annotation(trimmed: &str) -> Option<Vec<String>> {
    let rest = trimmed.strip_prefix(ANNOTATION_PREFIX)?;

    let close = rest.find(']')?;
    let id_part = &rest[..close];

    if id_part.is_empty() {
        return None;
    }

    let ids: Vec<String> = id_part.split(',').map(|s| s.trim().to_string()).collect();

    for id in &ids {
        if !is_valid_rule_id(id) {
            return None;
        }
    }

    Some(ids)
}

/// Check that `s` matches `[A-Z][A-Z0-9-]*`.
fn is_valid_rule_id(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_uppercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::parse_statements_lenient;

    /// Whether `rule_id` is suppressed on the `nth` statement that parsed,
    /// looked up the way `sqlkit audit` looks it up.
    fn suppressed(set: &SuppressionSet, sql: &str, rule_id: &str, nth: usize) -> bool {
        let (statements, _) = parse_statements_lenient(sql);
        statements
            .get(nth)
            .is_some_and(|s| set.is_suppressed(rule_id, s.offset))
    }

    /// A statement that fails to parse must not shift a later annotation
    /// onto the statement after the one it precedes.
    #[test]
    fn failed_statement_in_the_middle_does_not_shift_suppressions() {
        let sql = "GRANT ALL ON a TO x;\nNOT A STATEMENT;\n-- sqlkit-audit: ignore[SC-SEC02]\nGRANT ALL ON b TO y;\nGRANT ALL ON c TO z;";
        let set = SuppressionSet::parse(sql);
        let (statements, failures) = parse_statements_lenient(sql);
        assert_eq!((statements.len(), failures.len()), (3, 1));
        assert!(!suppressed(&set, sql, "SC-SEC02", 0));
        assert!(suppressed(&set, sql, "SC-SEC02", 1), "the annotated GRANT on b");
        assert!(!suppressed(&set, sql, "SC-SEC02", 2));
    }

    #[test]
    fn semicolon_inside_a_string_literal_does_not_shift_suppressions() {
        let sql = "SELECT 'a;b';\n-- sqlkit-audit: ignore[SC-SEC02]\nGRANT ALL ON b TO y;\nGRANT ALL ON c TO z;";
        let set = SuppressionSet::parse(sql);
        assert!(!suppressed(&set, sql, "SC-SEC02", 0));
        assert!(suppressed(&set, sql, "SC-SEC02", 1));
        assert!(!suppressed(&set, sql, "SC-SEC02", 2));
    }

    #[test]
    fn empty_statement_does_not_shift_suppressions() {
        let sql = "SELECT 1;;\n-- sqlkit-audit: ignore[SC-SEC02]\nGRANT ALL ON b TO y;\nGRANT ALL ON c TO z;";
        let set = SuppressionSet::parse(sql);
        assert!(!suppressed(&set, sql, "SC-SEC02", 0));
        assert!(suppressed(&set, sql, "SC-SEC02", 1));
        assert!(!suppressed(&set, sql, "SC-SEC02", 2));
    }

    #[test]
    fn two_statements_on_one_line_after_others_only_first_is_suppressed() {
        let sql = "SELECT 1;\n-- sqlkit-audit: ignore[SC-MIG01]\n  DROP TABLE a; DROP TABLE b;\nDROP TABLE c;";
        let set = SuppressionSet::parse(sql);
        assert!(!suppressed(&set, sql, "SC-MIG01", 0));
        assert!(suppressed(&set, sql, "SC-MIG01", 1));
        assert!(!suppressed(&set, sql, "SC-MIG01", 2));
        assert!(!suppressed(&set, sql, "SC-MIG01", 3));
    }

    /// An annotation inside a multi-line statement precedes a continuation
    /// line, not the start of a statement, so it attaches to nothing.
    #[test]
    fn annotation_before_a_continuation_line_attaches_to_nothing() {
        let sql = "GRANT ALL\n-- sqlkit-audit: ignore[SC-SEC02]\nON a TO x;\nGRANT ALL ON b TO y;";
        let set = SuppressionSet::parse(sql);
        assert!(!suppressed(&set, sql, "SC-SEC02", 0));
        assert!(!suppressed(&set, sql, "SC-SEC02", 1));
    }

    #[test]
    fn single_rule_ignore_suppresses_next_statement() {
        let sql = "-- sqlkit-audit: ignore[SC-SEC02]\nGRANT ALL ON users TO bob;";
        let set = SuppressionSet::parse(sql);
        assert!(suppressed(&set, sql, "SC-SEC02", 0));
        assert!(!suppressed(&set, sql, "SC-SEC01", 0));
    }

    #[test]
    fn multi_rule_ignore_suppresses_both_ids() {
        let sql = "-- sqlkit-audit: ignore[SC-SEC01,SC-SEC02]\nSELECT 1;";
        let set = SuppressionSet::parse(sql);
        assert!(suppressed(&set, sql, "SC-SEC01", 0));
        assert!(suppressed(&set, sql, "SC-SEC02", 0));
        assert!(!suppressed(&set, sql, "SC-SEC03", 0));
    }

    #[test]
    fn reason_clause_is_parsed_and_discarded() {
        let sql = r#"-- sqlkit-audit: ignore[SC-SEC01] reason="vetted"
SELECT pg_read_file('foo');"#;
        let set = SuppressionSet::parse(sql);
        assert!(suppressed(&set, sql, "SC-SEC01", 0));
    }

    #[test]
    fn stacked_annotations_union_ids() {
        let sql = "-- sqlkit-audit: ignore[SC-SEC01]\n-- sqlkit-audit: ignore[SC-SEC02]\nSELECT 1;";
        let set = SuppressionSet::parse(sql);
        assert!(suppressed(&set, sql, "SC-SEC01", 0));
        assert!(suppressed(&set, sql, "SC-SEC02", 0));
    }

    #[test]
    fn multi_line_statement_suppressed_at_single_statement_index() {
        let sql = "-- sqlkit-audit: ignore[SC-SEC08]\nSELECT *\nFROM a, b\nWHERE a.id = b.id;";
        let set = SuppressionSet::parse(sql);
        assert!(suppressed(&set, sql, "SC-SEC08", 0));
        // There is only ever one statement here, so index 1 is meaningless,
        // but it must not spuriously appear suppressed either.
        assert!(!suppressed(&set, sql, "SC-SEC08", 1));
    }

    #[test]
    fn blank_line_terminates_suppression_scope() {
        let sql = "-- sqlkit-audit: ignore[SC-SEC02]\nGRANT ALL ON a TO x;\n\nGRANT ALL ON b TO y;";
        let set = SuppressionSet::parse(sql);
        assert!(suppressed(&set, sql, "SC-SEC02", 0));
        assert!(!suppressed(&set, sql, "SC-SEC02", 1));
    }

    #[test]
    fn semicolon_terminates_statement() {
        let sql = "-- sqlkit-audit: ignore[SC-SEC02]\nGRANT ALL ON a TO x;\nGRANT ALL ON b TO y;";
        let set = SuppressionSet::parse(sql);
        assert!(suppressed(&set, sql, "SC-SEC02", 0));
        assert!(!suppressed(&set, sql, "SC-SEC02", 1));
    }

    /// Regression for #140: two statements sharing one physical line must
    /// resolve to two different statement indices, so an annotation meant
    /// for the first does not silently cover the second.
    #[test]
    fn two_statements_on_one_line_only_first_is_suppressed() {
        let sql = "-- sqlkit-audit: ignore[SC-MIG01]\nDROP TABLE a; DROP TABLE b;";
        let set = SuppressionSet::parse(sql);
        assert!(
            suppressed(&set, sql, "SC-MIG01", 0),
            "the first statement on the annotated line must be suppressed"
        );
        assert!(
            !suppressed(&set, sql, "SC-MIG01", 1),
            "the second statement sharing the line must NOT inherit the first's suppression"
        );
    }

    /// Regression for #140's documentation/behavior mismatch: the module
    /// doc used to claim an annotation "attaches to the next non-blank,
    /// non-comment line", but the code cleared `pending` on any blank line
    /// first -- so a blank line between the annotation and the statement
    /// silently dropped the suppression. That is now the documented,
    /// intentional contract: verify it holds.
    #[test]
    fn blank_line_between_annotation_and_statement_drops_the_suppression() {
        let sql = "-- sqlkit-audit: ignore[SC-SEC02]\n\nGRANT ALL ON x TO y;";
        let set = SuppressionSet::parse(sql);
        assert!(
            !suppressed(&set, sql, "SC-SEC02", 0),
            "a blank line between the annotation and the statement must drop the suppression"
        );
    }

    #[test]
    fn annotation_at_eof_with_no_following_statement_is_harmless() {
        let sql = "SELECT 1;\n-- sqlkit-audit: ignore[SC-SEC02]";
        let set = SuppressionSet::parse(sql);
        assert!(!suppressed(&set, sql, "SC-SEC02", 0));
        assert!(!suppressed(&set, sql, "SC-SEC02", 1));
    }

    #[test]
    fn ordinary_comment_does_not_consume_pending_suppression() {
        let sql = "-- sqlkit-audit: ignore[SC-SEC02]\n-- just a comment\nGRANT ALL ON x TO y;";
        let set = SuppressionSet::parse(sql);
        assert!(suppressed(&set, sql, "SC-SEC02", 0));
    }

    #[test]
    fn malformed_annotation_empty_brackets_is_silently_ignored() {
        let sql = "-- sqlkit-audit: ignore[]\nGRANT ALL ON x TO y;";
        let set = SuppressionSet::parse(sql);
        assert!(set.is_empty());
    }

    #[test]
    fn malformed_annotation_space_in_id_is_silently_ignored() {
        let sql = "-- sqlkit-audit: ignore[SC SEC01]\nSELECT 1;";
        let set = SuppressionSet::parse(sql);
        assert!(set.is_empty());
    }

    #[test]
    fn is_suppressed_returns_false_for_unknown_id() {
        let sql = "-- sqlkit-audit: ignore[SC-SEC02]\nGRANT ALL ON x TO y;";
        let set = SuppressionSet::parse(sql);
        assert!(!suppressed(&set, sql, "SC-SEC99", 0));
    }

    #[test]
    fn is_suppressed_returns_true_for_known_id_on_suppressed_statement() {
        let sql = "-- sqlkit-audit: ignore[SC-SEC02]\nGRANT ALL ON x TO y;";
        let set = SuppressionSet::parse(sql);
        assert!(suppressed(&set, sql, "SC-SEC02", 0));
    }

    #[test]
    fn unsuppressed_statement_returns_false() {
        let sql = "GRANT ALL ON x TO y;";
        let set = SuppressionSet::parse(sql);
        assert!(!suppressed(&set, sql, "SC-SEC02", 0));
    }

    #[test]
    fn is_empty_when_no_annotations() {
        let sql = "SELECT 1; SELECT 2;";
        let set = SuppressionSet::parse(sql);
        assert!(set.is_empty());
    }
}
