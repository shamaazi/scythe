//! Validation rules derived from the constraints a database enforces on a
//! value.
//!
//! The catalog records, per column and per domain, what PostgreSQL checks when
//! a value is written: a `varchar(n)`/`char(n)` length, `CHECK` constraints,
//! an explicit `COLLATE`, and the `COMMENT ON` text. Each `CHECK` is
//! translated, when its rules are resolved, into a neutral [`Rules`] set using
//! JSON Schema's validation vocabulary; what it cannot express exactly is kept
//! as an [`Untranslated`] entry instead of being approximated. Text
//! comparisons are translated as byte-exact (ECMAScript's `===` and regular
//! expressions), so a check on a `citext` value, or on one with a collation
//! other than the default, `C` or `POSIX`, keeps its patterns and string
//! literals untranslated.
//!
//! A `CHECK` added `NOT VALID` binds only rows written after it, so it narrows
//! values written into a column ([`Catalog::written_column_constraints`])
//! but not values read from one ([`Catalog::column_constraints`]).
//!
//! [`Catalog::written_column_constraints`]: crate::catalog::Catalog::written_column_constraints
//! [`Catalog::column_constraints`]: crate::catalog::Catalog::column_constraints The analyzer then
//! attaches the resolved [`ValueConstraints`] to result columns read straight
//! from a column and to parameters written straight into one, for code
//! generators to render as validation.
//!
//! Rules describe non-null values only: PostgreSQL passes a `CHECK` whose
//! expression is NULL, and nullability is already part of the generated type.

use std::cmp::Ordering;

pub mod pattern;
mod translate;

pub(crate) use translate::{TextComparison, referenced_columns, translate_check};

/// One literal an `IN (...)` or `= ANY (ARRAY[...])` constraint allows.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AllowedValue {
    String(String),
    /// A numeric literal, spelled as SQL wrote it (`10`, `-2.5`).
    Number(String),
}

/// Validation rules for a value, named after the JSON Schema keywords they
/// correspond to. Every bound is inclusive unless its name says otherwise, and
/// numeric bounds are decimal literals as SQL spelled them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Rules {
    pub min_length: Option<u64>,
    pub max_length: Option<u64>,
    /// An ECMAScript regular expression the value must contain a match for.
    pub pattern: Option<String>,
    pub minimum: Option<String>,
    pub maximum: Option<String>,
    pub exclusive_minimum: Option<String>,
    pub exclusive_maximum: Option<String>,
    pub multiple_of: Option<String>,
    /// The only values allowed, in declaration order.
    pub allowed: Option<Vec<AllowedValue>>,
}

impl Rules {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Whether any keyword applies to numbers rather than strings.
    pub fn has_numeric_bounds(&self) -> bool {
        self.minimum.is_some()
            || self.maximum.is_some()
            || self.exclusive_minimum.is_some()
            || self.exclusive_maximum.is_some()
            || self.multiple_of.is_some()
    }

    /// Whether any keyword applies to strings.
    pub fn has_string_rules(&self) -> bool {
        self.min_length.is_some() || self.max_length.is_some() || self.pattern.is_some()
    }

    /// Narrow these rules to values that satisfy both `self` and `other`.
    ///
    /// Returns a description of what could not be combined -- two different
    /// `multipleOf` values -- which the caller records as untranslated.
    pub fn intersect(&mut self, other: &Rules) -> Option<String> {
        self.min_length = max_option(self.min_length, other.min_length);
        self.max_length = match (self.max_length, other.max_length) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        self.pattern = match (self.pattern.take(), &other.pattern) {
            (Some(a), Some(b)) if a == *b => Some(a),
            (Some(a), Some(b)) => Some(all_of_patterns(&a, b)),
            (a, b) => a.or_else(|| b.clone()),
        };
        self.minimum = tighter(self.minimum.take(), &other.minimum, true);
        self.maximum = tighter(self.maximum.take(), &other.maximum, false);
        self.exclusive_minimum = tighter(self.exclusive_minimum.take(), &other.exclusive_minimum, true);
        self.exclusive_maximum = tighter(self.exclusive_maximum.take(), &other.exclusive_maximum, false);
        self.allowed = match (self.allowed.take(), &other.allowed) {
            (Some(a), Some(b)) => Some(
                a.into_iter()
                    .filter(|value| b.iter().any(|other| same_value(value, other)))
                    .collect(),
            ),
            (a, b) => a.or_else(|| b.clone()),
        };
        match (&self.multiple_of, &other.multiple_of) {
            (Some(a), Some(b)) if a != b => Some(format!("`multipleOf {a}` combined with `multipleOf {b}`")),
            (None, Some(b)) => {
                self.multiple_of = Some(b.clone());
                None
            }
            _ => None,
        }
    }
}

/// A constraint that applies to a value but has no exact [`Rules`] form.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Untranslated {
    /// Where the constraint is declared: `table.column` or `domain name`.
    pub source: String,
    /// The constraint's SQL, e.g. `CHECK (length(btrim(title)) > 1)`.
    pub constraint: String,
    /// Why it was not translated.
    pub reason: String,
}

/// Everything the schema declares about a column's or parameter's values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ValueConstraints {
    /// The domain the value's column is declared with, if any.
    #[cfg_attr(feature = "serde", serde(default))]
    pub domain: Option<String>,
    /// The description of the `COMMENT ON COLUMN` text, or of the domain's
    /// `COMMENT ON DOMAIN` text: what follows its smart tags (see
    /// [`SmartComment`]).
    #[cfg_attr(feature = "serde", serde(default))]
    pub description: Option<String>,
    /// The smart tags leading the same comment, as `(tag, value)` in order;
    /// the value is empty for a bare `@tag`. sqlkit gives them no meaning:
    /// they are for consumers.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub tags: Vec<(String, String)>,
    #[cfg_attr(feature = "serde", serde(default))]
    pub rules: Rules,
    #[cfg_attr(feature = "serde", serde(default))]
    pub untranslated: Vec<Untranslated>,
}

impl ValueConstraints {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Narrow to values that satisfy both `self` and `other` -- a parameter
    /// written into two columns.
    pub fn intersect(&mut self, other: &ValueConstraints) {
        if self.domain != other.domain {
            self.domain = None;
        }
        if self.description.is_none() {
            self.description = other.description.clone();
        }
        if self.tags.is_empty() {
            self.tags = other.tags.clone();
        }
        self.add_rules(&other.rules, "", "");
        for entry in &other.untranslated {
            if !self.untranslated.contains(entry) {
                self.untranslated.push(entry.clone());
            }
        }
    }

    /// Add `rules`, recording a conflict that cannot be expressed as
    /// untranslated under `source`.
    pub(crate) fn add_rules(&mut self, rules: &Rules, source: &str, constraint: &str) {
        if let Some(reason) = self.rules.intersect(rules) {
            self.untranslated.push(Untranslated {
                source: source.to_string(),
                constraint: constraint.to_string(),
                reason,
            });
        }
    }
}

/// A `COMMENT ON` text split the way PostGraphile reads "smart comments":
/// leading lines of the form `@tag` or `@tag value` are tags, and the rest of
/// the text is the description.
///
/// Only lines before the first line that is not a tag are tags (blank lines
/// among them are skipped), so an `@` further down belongs to the
/// description, which a code generator must then keep from reading as a tag
/// of its own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SmartComment {
    /// `(tag, value)` in order; the value is empty for a bare `@tag`, and a
    /// tag may repeat.
    pub tags: Vec<(String, String)>,
    /// The text after the tags, trimmed; `None` when there is none.
    pub description: Option<String>,
}

impl SmartComment {
    pub fn parse(text: &str) -> Self {
        let mut tags = Vec::new();
        let mut lines = text.lines().peekable();
        while let Some(line) = lines.peek() {
            let line = line.trim_end();
            if line.is_empty() {
                lines.next();
                continue;
            }
            let Some(rest) = line.strip_prefix('@') else {
                break;
            };
            let name_len = rest
                .char_indices()
                .find(|&(i, c)| !(c.is_ascii_alphabetic() || (i > 0 && (c.is_ascii_digit() || c == '_'))))
                .map_or(rest.len(), |(i, _)| i);
            let after = &rest[name_len..];
            if name_len == 0 || !(after.is_empty() || after.starts_with(char::is_whitespace)) {
                break;
            }
            tags.push((rest[..name_len].to_string(), after.trim().to_string()));
            lines.next();
        }
        let description = lines.collect::<Vec<_>>().join("\n");
        let description = description.trim();
        Self {
            tags,
            description: (!description.is_empty()).then(|| description.to_string()),
        }
    }
}

/// The result of translating one constraint.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Translation {
    pub(crate) rules: Rules,
    /// `(constraint SQL, reason)` for each part left untranslated.
    pub(crate) untranslated: Vec<(String, String)>,
}

fn max_option(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    }
}

/// The tighter of two numeric bounds: the larger lower bound or the smaller
/// upper bound. Of two bounds that cannot be compared, `a` is kept.
fn tighter(a: Option<String>, b: &Option<String>, lower: bool) -> Option<String> {
    match (a, b) {
        (Some(a), Some(b)) => {
            let keep_b = match compare_decimals(&a, b) {
                Some(Ordering::Less) => lower,
                Some(Ordering::Greater) => !lower,
                _ => false,
            };
            if keep_b { Some(b.clone()) } else { Some(a) }
        }
        (a, b) => a.or_else(|| b.clone()),
    }
}

/// Whether two allowed values are the same value: numbers compare by value,
/// so `1.0` is `1`.
fn same_value(a: &AllowedValue, b: &AllowedValue) -> bool {
    match (a, b) {
        (AllowedValue::Number(x), AllowedValue::Number(y)) => x == y || compare_decimals(x, y) == Some(Ordering::Equal),
        _ => a == b,
    }
}

/// A decimal literal (`-12.50`, `1e3`, `.5`) as sign, significant digits and
/// the power of ten of the last digit, without leading or trailing zeros;
/// zero is `(false, "", 0)`.
fn normalize_decimal(literal: &str) -> Option<(bool, String, i64)> {
    let literal = literal.trim();
    let (negative, unsigned) = match literal.as_bytes().first()? {
        b'-' => (true, &literal[1..]),
        b'+' => (false, &literal[1..]),
        _ => (false, literal),
    };
    let (mantissa, exponent) = match unsigned.find(['e', 'E']) {
        Some(at) => (&unsigned[..at], unsigned[at + 1..].parse::<i64>().ok()?),
        None => (unsigned, 0),
    };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if whole.is_empty() && fraction.is_empty() || !whole.bytes().chain(fraction.bytes()).all(|b| b.is_ascii_digit()) {
        return None;
    }
    let digits = format!("{whole}{fraction}");
    let digits = digits.trim_start_matches('0');
    let significant = digits.trim_end_matches('0');
    if significant.is_empty() {
        return Some((false, String::new(), 0));
    }
    let exponent = exponent
        .checked_sub(i64::try_from(fraction.len()).ok()?)?
        .checked_add(i64::try_from(digits.len() - significant.len()).ok()?)?;
    Some((negative, significant.to_string(), exponent))
}

/// Compare two decimal literals exactly, or `None` when either is not one.
fn compare_decimals(a: &str, b: &str) -> Option<Ordering> {
    let (a, b) = (normalize_decimal(a)?, normalize_decimal(b)?);
    let sign = |(negative, digits, _): &(bool, String, i64)| match (digits.is_empty(), negative) {
        (true, _) => 0,
        (false, true) => -1,
        (false, false) => 1,
    };
    let (sa, sb) = (sign(&a), sign(&b));
    if sa != sb || sa == 0 {
        return Some(sa.cmp(&sb));
    }
    // Same sign, neither zero: compare magnitudes by the position of the
    // leading digit, then digit by digit.
    let lead = |(_, digits, exponent): &(bool, String, i64)| exponent.saturating_add(digits.len() as i64);
    let magnitude = lead(&a).cmp(&lead(&b)).then_with(|| {
        let width = a.1.len().max(b.1.len());
        format!("{:0<width$}", a.1).cmp(&format!("{:0<width$}", b.1))
    });
    Some(if sa < 0 { magnitude.reverse() } else { magnitude })
}

/// One pattern requiring a match for each of `a` and `b`.
///
/// Both are searches anywhere in the string, so each becomes a lookahead from
/// the start that may skip any prefix.
fn all_of_patterns(a: &str, b: &str) -> String {
    let lookahead = |p: &str| {
        if p.starts_with("^(?=[\\s\\S]*(?:") {
            // Already a conjunction built here: reuse its lookaheads.
            p.trim_start_matches('^').to_string()
        } else {
            format!("(?=[\\s\\S]*(?:{p}))")
        }
    };
    format!("^{}{}", lookahead(a), lookahead(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_keep_the_tighter_bounds_when_intersecting() {
        let mut rules = Rules {
            min_length: Some(1),
            max_length: Some(255),
            minimum: Some("0".to_string()),
            ..Rules::default()
        };
        rules.intersect(&Rules {
            min_length: Some(3),
            max_length: Some(300),
            minimum: Some("-5".to_string()),
            maximum: Some("10".to_string()),
            ..Rules::default()
        });
        assert_eq!(rules.min_length, Some(3));
        assert_eq!(rules.max_length, Some(255));
        assert_eq!(rules.minimum.as_deref(), Some("0"));
        assert_eq!(rules.maximum.as_deref(), Some("10"));
    }

    #[test]
    fn should_require_both_patterns_when_intersecting() {
        let mut rules = Rules {
            pattern: Some("^a".to_string()),
            ..Rules::default()
        };
        rules.intersect(&Rules {
            pattern: Some("b$".to_string()),
            ..Rules::default()
        });
        assert_eq!(
            rules.pattern.as_deref(),
            Some("^(?=[\\s\\S]*(?:^a))(?=[\\s\\S]*(?:b$))")
        );
    }

    #[test]
    fn should_keep_only_common_allowed_values() {
        let mut rules = Rules {
            allowed: Some(vec![
                AllowedValue::String("a".to_string()),
                AllowedValue::String("b".to_string()),
            ]),
            ..Rules::default()
        };
        rules.intersect(&Rules {
            allowed: Some(vec![AllowedValue::String("b".to_string())]),
            ..Rules::default()
        });
        assert_eq!(rules.allowed, Some(vec![AllowedValue::String("b".to_string())]));
    }

    #[test]
    fn should_compare_numeric_bounds_exactly() {
        let mut rules = Rules {
            minimum: Some("0.30000000000000000001".to_string()),
            maximum: Some("1e3".to_string()),
            ..Rules::default()
        };
        rules.intersect(&Rules {
            minimum: Some("0.3".to_string()),
            maximum: Some("999.99999999999999999".to_string()),
            ..Rules::default()
        });
        assert_eq!(rules.minimum.as_deref(), Some("0.30000000000000000001"));
        assert_eq!(rules.maximum.as_deref(), Some("999.99999999999999999"));
        assert_eq!(compare_decimals("-2.5", "-10"), Some(Ordering::Greater));
        assert_eq!(compare_decimals("-0.0", "0"), Some(Ordering::Equal));
        assert_eq!(compare_decimals("100", "99.5"), Some(Ordering::Greater));
        assert_eq!(compare_decimals(".5", "0.50"), Some(Ordering::Equal));
        assert_eq!(compare_decimals("1e2", "100"), Some(Ordering::Equal));
        assert_eq!(compare_decimals("abc", "1"), None);
    }

    #[test]
    fn should_match_allowed_numbers_by_value() {
        let mut rules = Rules {
            allowed: Some(vec![
                AllowedValue::Number("1.0".to_string()),
                AllowedValue::Number("2".to_string()),
            ]),
            ..Rules::default()
        };
        rules.intersect(&Rules {
            allowed: Some(vec![AllowedValue::Number("1".to_string())]),
            ..Rules::default()
        });
        assert_eq!(rules.allowed, Some(vec![AllowedValue::Number("1.0".to_string())]));
    }

    #[test]
    fn should_split_smart_comment_tags_from_the_description() {
        let comment = SmartComment::parse("@name amount\n\n@deprecated\nThe total.\n@pattern x\n");
        assert_eq!(
            comment.tags,
            [
                ("name".to_string(), "amount".to_string()),
                ("deprecated".to_string(), String::new())
            ]
        );
        assert_eq!(comment.description.as_deref(), Some("The total.\n@pattern x"));
        assert_eq!(SmartComment::parse("@omit").description, None);
        assert!(SmartComment::parse("@ not a tag").tags.is_empty());
        assert_eq!(
            SmartComment::parse("email@example.com").description.as_deref(),
            Some("email@example.com")
        );
    }

    #[test]
    fn should_report_conflicting_multiples() {
        let mut rules = Rules {
            multiple_of: Some("2".to_string()),
            ..Rules::default()
        };
        let conflict = rules.intersect(&Rules {
            multiple_of: Some("3".to_string()),
            ..Rules::default()
        });
        assert!(conflict.is_some());
    }
}
