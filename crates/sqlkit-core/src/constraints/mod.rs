//! Validation rules derived from the constraints a database enforces on a
//! value.
//!
//! The catalog records, per column and per domain, what PostgreSQL checks when
//! a value is written: a `varchar(n)`/`char(n)` length, a `numeric(p, s)`
//! precision, `CHECK` constraints and the `COMMENT ON` text. [`translate`]
//! turns each `CHECK` into a neutral [`Rules`] set using JSON Schema's
//! validation vocabulary; what it cannot express exactly is kept as an
//! [`Untranslated`] entry instead of being approximated. The analyzer then
//! attaches the resolved [`ValueConstraints`] to result columns read straight
//! from a column and to parameters written straight into one, for code
//! generators to render as validation.
//!
//! Rules describe non-null values only: PostgreSQL passes a `CHECK` whose
//! expression is NULL, and nullability is already part of the generated type.

pub mod pattern;
mod translate;

pub(crate) use translate::{referenced_columns, translate_check};

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
            (Some(a), Some(b)) => Some(a.into_iter().filter(|value| b.contains(value)).collect()),
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
    /// `COMMENT ON COLUMN` text, or the domain's `COMMENT ON DOMAIN` text.
    #[cfg_attr(feature = "serde", serde(default))]
    pub description: Option<String>,
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
/// upper bound.
fn tighter(a: Option<String>, b: &Option<String>, lower: bool) -> Option<String> {
    match (a, b) {
        (Some(a), Some(b)) => {
            let (x, y) = (
                a.parse::<f64>().unwrap_or(f64::NAN),
                b.parse::<f64>().unwrap_or(f64::NAN),
            );
            let keep_a = if lower { x >= y } else { x <= y };
            if keep_a { Some(a) } else { Some(b.clone()) }
        }
        (a, b) => a.or_else(|| b.clone()),
    }
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
