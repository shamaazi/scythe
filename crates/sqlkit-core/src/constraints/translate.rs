//! Translation of `CHECK` expressions into [`Rules`].
//!
//! Works on the sqlparser AST. Each conjunct of a `CHECK` is translated on its
//! own: a conjunct either becomes rules that accept exactly the values it
//! accepts, or is reported untranslated -- never approximated, so a validator
//! built from the rules rejects nothing the database would store, and the
//! untranslated list says where it may accept something the database rejects.

use std::ops::ControlFlow;

use sqlparser::ast::{
    BinaryOperator, CastKind, DataType, Expr, Function, FunctionArg, FunctionArgExpr, FunctionArguments, UnaryOperator,
    Value, visit_expressions,
};

use super::pattern::{like_to_ecmascript, posix_to_ecmascript};
use super::{AllowedValue, Rules, Translation};

const UNSUPPORTED: &str = "the expression has no JSON Schema equivalent";

/// The pattern of a value that is not blank: it has a character other than
/// a space.
const NOT_BLANK: &str = "[^ ]";

/// The names of the columns `expr` references, lowercased and deduplicated, in
/// order of first appearance.
pub(crate) fn referenced_columns(expr: &Expr) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let _ = visit_expressions(expr, |e| {
        let name = match e {
            Expr::Identifier(ident) => Some(ident.value.to_lowercase()),
            Expr::CompoundIdentifier(parts) => parts.last().map(|ident| ident.value.to_lowercase()),
            _ => None,
        };
        if let Some(name) = name
            && !names.contains(&name)
        {
            names.push(name);
        }
        ControlFlow::<()>::Continue(())
    });
    names
}

/// How the subject compares as text, which decides whether its string
/// equalities and patterns mean what ECMAScript's `===` and regular
/// expressions mean.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) enum TextComparison {
    /// Byte by byte: the default collation (deterministic, as every
    /// database default is), `C` or `POSIX`.
    #[default]
    Exact,
    /// Otherwise -- `citext`, or another collation -- with the reason.
    Inexact(String),
}

/// Translate the `CHECK` expression `expr` constraining `subject`: a column
/// name, or `value` for a domain's `VALUE`.
pub(crate) fn translate_check(expr: &Expr, subject: &str, text: &TextComparison) -> Translation {
    let mut translation = Translation::default();
    translate_into(expr, subject, text, &mut translation);
    translation
}

fn translate_into(expr: &Expr, subject: &str, text: &TextComparison, translation: &mut Translation) {
    match expr {
        Expr::Nested(inner) => translate_into(inner, subject, text, translation),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => {
            translate_into(left, subject, text, translation);
            translate_into(right, subject, text, translation);
        }
        // `x IS NULL OR <rule on x>` is how a nullable value is often guarded,
        // and is equivalent: the check passes for NULL either way.
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Or,
            right,
        } if is_null_test_of(left, subject) || is_null_test_of(right, subject) => {
            let other = if is_null_test_of(left, subject) { right } else { left };
            translate_into(other, subject, text, translation);
        }
        _ => match translate_atom(expr, subject).and_then(|rules| exact_text(rules, text)) {
            Ok(rules) => {
                if let Some(reason) = translation.rules.intersect(&rules) {
                    translation.untranslated.push((expr.to_string(), reason));
                }
            }
            Err(reason) => translation.untranslated.push((expr.to_string(), reason)),
        },
    }
}

/// `rules`, unless they compare text and `text` says the subject's text does
/// not compare byte by byte: a pattern or an allowed string.
fn exact_text(rules: Rules, text: &TextComparison) -> Result<Rules, String> {
    let TextComparison::Inexact(reason) = text else {
        return Ok(rules);
    };
    // The not-blank rule of a trimmed length only looks for a character other
    // than a space, which neither case folding nor a collation changes.
    let not_blank = rules.min_length == Some(1) && rules.pattern.as_deref() == Some(NOT_BLANK);
    let pattern = rules.pattern.is_some() && !not_blank;
    let string_values = rules
        .allowed
        .iter()
        .flatten()
        .any(|value| matches!(value, AllowedValue::String(_)));
    if pattern || string_values {
        return Err(reason.clone());
    }
    Ok(rules)
}

fn is_null_test_of(expr: &Expr, subject: &str) -> bool {
    match expr {
        Expr::Nested(inner) => is_null_test_of(inner, subject),
        Expr::IsNull(inner) => is_subject(inner, subject),
        _ => false,
    }
}

/// Translate one conjunct.
fn translate_atom(expr: &Expr, subject: &str) -> Result<Rules, String> {
    match expr {
        Expr::Nested(inner) => translate_atom(inner, subject),
        Expr::BinaryOp { left, op, right } => translate_binary(left, op, right, subject),
        Expr::Between {
            expr: operand,
            negated: false,
            low,
            high,
        } => {
            let low = number(low).ok_or("BETWEEN bounds must be numeric literals")?;
            let high = number(high).ok_or("BETWEEN bounds must be numeric literals")?;
            if is_subject(operand, subject) {
                Ok(Rules {
                    minimum: Some(low),
                    maximum: Some(high),
                    ..Rules::default()
                })
            } else if let Some(Measure::Length) = measure(operand, subject) {
                Ok(Rules {
                    min_length: Some(length_bound(&low)?),
                    max_length: Some(length_bound(&high)?),
                    ..Rules::default()
                })
            } else {
                Err(UNSUPPORTED.to_string())
            }
        }
        Expr::InList {
            expr: operand,
            list,
            negated: false,
        } if is_subject(operand, subject) => Ok(Rules {
            allowed: Some(allowed_values(list.iter())?),
            ..Rules::default()
        }),
        Expr::AnyOp {
            left,
            compare_op: BinaryOperator::Eq,
            right,
            ..
        } if is_subject(left, subject) => {
            let elements = array_elements(right).ok_or("`= ANY` needs an ARRAY[...] of literals")?;
            Ok(Rules {
                allowed: Some(allowed_values(elements.iter())?),
                ..Rules::default()
            })
        }
        Expr::Like {
            negated,
            any: false,
            expr: operand,
            pattern,
            escape_char,
        } if is_subject(operand, subject) => {
            let pattern = string(pattern).ok_or("the LIKE pattern must be a string literal")?;
            let escape = match escape_char.as_deref() {
                None => Some('\\'),
                Some(escape) => {
                    let escape = string(escape).ok_or("the LIKE escape must be a string literal")?;
                    let mut chars = escape.chars();
                    match (chars.next(), chars.next()) {
                        (None, _) => None,
                        (Some(c), None) => Some(c),
                        _ => return Err("the LIKE escape must be one character".to_string()),
                    }
                }
            };
            let translated = like_to_ecmascript(&pattern, escape)?;
            Ok(pattern_rule(if *negated { negate(&translated) } else { translated }))
        }
        Expr::ILike { .. } | Expr::SimilarTo { .. } => {
            Err("case-insensitive and SIMILAR TO patterns are not translated".to_string())
        }
        Expr::IsNotNull(inner) if is_subject(inner, subject) => {
            Err("NOT NULL in a CHECK is nullability, which validation rules do not carry".to_string())
        }
        _ => Err(UNSUPPORTED.to_string()),
    }
}

fn translate_binary(left: &Expr, op: &BinaryOperator, right: &Expr, subject: &str) -> Result<Rules, String> {
    use BinaryOperator::*;
    match op {
        PGRegexMatch | PGRegexNotMatch if is_subject(left, subject) => {
            let pattern = string(right).ok_or("the regular expression must be a string literal")?;
            let translated = posix_to_ecmascript(&pattern)?;
            Ok(pattern_rule(if *op == PGRegexNotMatch {
                negate(&translated)
            } else {
                translated
            }))
        }
        PGRegexIMatch | PGRegexNotIMatch => Err("case-insensitive regular expressions are not translated".to_string()),
        Eq | NotEq | Lt | LtEq | Gt | GtEq => {
            // Normalise to `<operand> <op> <literal>`.
            let (operand, op, literal) = if constant(right) {
                (left, op.clone(), right)
            } else if constant(left) {
                (right, flip(op), left)
            } else {
                return Err(UNSUPPORTED.to_string());
            };
            compare(operand, &op, literal, subject)
        }
        _ => Err(UNSUPPORTED.to_string()),
    }
}

/// `<operand> <op> <literal>`.
fn compare(operand: &Expr, op: &BinaryOperator, literal: &Expr, subject: &str) -> Result<Rules, String> {
    use BinaryOperator::*;
    if is_subject(operand, subject) {
        if let Some(n) = number(literal) {
            let mut rules = Rules::default();
            match op {
                Gt => rules.exclusive_minimum = Some(n),
                GtEq => rules.minimum = Some(n),
                Lt => rules.exclusive_maximum = Some(n),
                LtEq => rules.maximum = Some(n),
                Eq => rules.allowed = Some(vec![AllowedValue::Number(n)]),
                _ => return Err("`<>` has no JSON Schema equivalent".to_string()),
            }
            return Ok(rules);
        }
        if let (Some(s), Eq) = (string(literal), op) {
            return Ok(Rules {
                allowed: Some(vec![AllowedValue::String(s)]),
                ..Rules::default()
            });
        }
        return Err(
            "only numeric bounds are translated; text and date comparisons depend on collation and type".to_string(),
        );
    }
    // `x % n = 0`
    if let Expr::BinaryOp {
        left,
        op: Modulo,
        right,
    } = strip(operand)
        && is_subject(left, subject)
        && *op == Eq
        && number(literal).as_deref() == Some("0")
    {
        let divisor = number(right).ok_or("the divisor must be a numeric literal")?;
        if divisor.starts_with('-') || divisor.parse::<f64>().is_ok_and(|d| d == 0.0) {
            return Err("the divisor must be positive".to_string());
        }
        return Ok(Rules {
            multiple_of: Some(divisor),
            ..Rules::default()
        });
    }
    match measure(operand, subject) {
        Some(Measure::Length) => {
            let n = number(literal).ok_or("a length must be compared with an integer literal")?;
            let n: i64 = n
                .parse()
                .map_err(|_| "a length must be compared with an integer literal")?;
            let out_of_range = || "the length bound is out of range".to_string();
            let (min, max) = match op {
                Gt => (Some(n.checked_add(1).ok_or_else(out_of_range)?), None),
                GtEq => (Some(n), None),
                Lt => (None, Some(n.checked_sub(1).ok_or_else(out_of_range)?)),
                LtEq => (None, Some(n)),
                Eq => (Some(n), Some(n)),
                _ => return Err("`<>` has no JSON Schema equivalent".to_string()),
            };
            // A maximum below zero admits no value, which `maxLength` cannot say.
            if max.is_some_and(|max| max < 0) {
                return Err("no length satisfies the bound".to_string());
            }
            Ok(Rules {
                min_length: min.map(|n| n.max(0) as u64),
                max_length: max.map(|n| n.max(0) as u64),
                ..Rules::default()
            })
        }
        Some(Measure::TrimmedLength) => {
            // A trimmed length above zero says the value is not blank: it
            // contains a character other than the space `trim` removes. That
            // is a pattern; any other bound on a trimmed length is not.
            let n = number(literal).and_then(|n| n.parse::<i64>().ok());
            let not_blank = matches!((op, n), (Gt, Some(0)) | (GtEq, Some(1)) | (NotEq, Some(0)));
            if not_blank {
                Ok(Rules {
                    min_length: Some(1),
                    pattern: Some(NOT_BLANK.to_string()),
                    ..Rules::default()
                })
            } else {
                Err("only a trimmed length above zero (not blank) is translated".to_string())
            }
        }
        Some(Measure::Octets) => Err("octet lengths count bytes, not characters".to_string()),
        None => Err(UNSUPPORTED.to_string()),
    }
}

enum Measure {
    Length,
    TrimmedLength,
    Octets,
}

/// What a length function of the subject measures, if `expr` is one.
fn measure(expr: &Expr, subject: &str) -> Option<Measure> {
    let Expr::Function(function) = strip(expr) else {
        return None;
    };
    let name = function.name.to_string().to_lowercase();
    let args = function_args(function)?;
    let [argument] = args.as_slice() else {
        return None;
    };
    match name.as_str() {
        "length" | "char_length" | "character_length" => {
            if is_subject(argument, subject) {
                Some(Measure::Length)
            } else if is_trim_of(argument, subject) {
                Some(Measure::TrimmedLength)
            } else {
                None
            }
        }
        "octet_length" if is_subject(argument, subject) => Some(Measure::Octets),
        _ => None,
    }
}

/// Whether `expr` removes spaces (and only spaces) from either end of the
/// subject: `trim(x)`, `TRIM(BOTH ' ' FROM x)`, `btrim(x)`, `ltrim(x)`, ...
fn is_trim_of(expr: &Expr, subject: &str) -> bool {
    match strip(expr) {
        // Any side: a trimmed value is empty exactly when the value is blank.
        Expr::Trim {
            trim_what,
            expr: inner,
            trim_characters,
            ..
        } => {
            let spaces_only = trim_what
                .as_deref()
                .is_none_or(|what| string(what).as_deref() == Some(" "))
                && trim_characters
                    .as_ref()
                    .is_none_or(|chars| chars.len() == 1 && string(&chars[0]).as_deref() == Some(" "));
            spaces_only && is_subject(inner, subject)
        }
        Expr::Function(function) => {
            let name = function.name.to_string().to_lowercase();
            if !matches!(name.as_str(), "btrim" | "ltrim" | "rtrim" | "trim") {
                return false;
            }
            match function_args(function).as_deref() {
                Some([argument]) => is_subject(argument, subject),
                Some([argument, characters]) => {
                    is_subject(argument, subject) && string(characters).as_deref() == Some(" ")
                }
                _ => false,
            }
        }
        _ => false,
    }
}

fn function_args(function: &Function) -> Option<Vec<&Expr>> {
    let FunctionArguments::List(list) = &function.args else {
        return None;
    };
    if list.duplicate_treatment.is_some() || !list.clauses.is_empty() {
        return None;
    }
    list.args
        .iter()
        .map(|arg| match arg {
            FunctionArg::Unnamed(FunctionArgExpr::Expr(expr)) => Some(expr),
            _ => None,
        })
        .collect()
}

/// `expr` without parentheses or casts that keep its value: casts to text
/// types without a length, and to numeric types without a precision.
fn strip(expr: &Expr) -> &Expr {
    match expr {
        Expr::Nested(inner) => strip(inner),
        Expr::Cast {
            kind: CastKind::Cast | CastKind::DoubleColon,
            expr: inner,
            data_type,
            ..
        } if value_preserving(data_type) => strip(inner),
        _ => expr,
    }
}

fn value_preserving(data_type: &DataType) -> bool {
    match data_type {
        DataType::Text
        | DataType::Varchar(None)
        | DataType::CharacterVarying(None)
        | DataType::Numeric(sqlparser::ast::ExactNumberInfo::None)
        | DataType::Decimal(sqlparser::ast::ExactNumberInfo::None) => true,
        DataType::Array(_) => true,
        DataType::Custom(name, modifiers) => {
            modifiers.is_empty() && matches!(name.to_string().to_lowercase().as_str(), "text" | "citext")
        }
        _ => false,
    }
}

fn is_subject(expr: &Expr, subject: &str) -> bool {
    match strip(expr) {
        Expr::Identifier(ident) => ident.value.eq_ignore_ascii_case(subject),
        Expr::CompoundIdentifier(parts) => parts.last().is_some_and(|i| i.value.eq_ignore_ascii_case(subject)),
        _ => false,
    }
}

fn constant(expr: &Expr) -> bool {
    literal(expr).is_some()
}

/// A numeric literal: a number as written, negated or not, or a quoted one
/// cast to a numeric type that keeps its value (`'-5'::integer`, which is how
/// PostgreSQL prints a negative constant).
fn number(expr: &Expr) -> Option<String> {
    match literal(expr)? {
        AllowedValue::Number(n) => Some(n),
        AllowedValue::String(_) => None,
    }
}

/// A string literal, through casts to anything but a number (`'x'::text`,
/// `'x'::character varying`, `'active'::status`).
fn string(expr: &Expr) -> Option<String> {
    match literal(expr)? {
        AllowedValue::String(s) => Some(s),
        AllowedValue::Number(_) => None,
    }
}

fn allowed_values<'a>(list: impl Iterator<Item = &'a Expr>) -> Result<Vec<AllowedValue>, String> {
    list.map(|item| literal(item).ok_or_else(|| "every listed value must be a literal".to_string()))
        .collect()
}

/// The value of a literal, a number or a string. A quoted literal stays a
/// string through casts, except a cast to a numeric type, which makes it the
/// number it spells: `'10'::numeric` is 10, `'10'::text` is "10".
///
/// `None` when the value has no exact JSON form: a cast that may change it
/// (to `numeric(p, s)`, a fraction to an integer type, a number `real` does
/// not hold exactly), a number PostgreSQL accepts but JSON has no form for
/// (`'NaN'`, `'Infinity'`, `'0x1F'`, `'1_000'`), or a number cast to a
/// non-numeric type, whose value is no longer a number.
fn literal(expr: &Expr) -> Option<AllowedValue> {
    match expr {
        Expr::Nested(inner) => literal(inner),
        Expr::Value(value) => match &value.value {
            Value::Number(n, _) => json_number(n).map(AllowedValue::Number),
            Value::SingleQuotedString(s)
            | Value::EscapedStringLiteral(s)
            | Value::NationalStringLiteral(s)
            | Value::UnicodeStringLiteral(s) => Some(AllowedValue::String(s.clone())),
            Value::DollarQuotedString(s) => Some(AllowedValue::String(s.value.clone())),
            _ => None,
        },
        Expr::UnaryOp {
            op: UnaryOperator::Minus,
            expr: inner,
        } => match literal(inner)? {
            AllowedValue::Number(n) => Some(AllowedValue::Number(match n.strip_prefix('-') {
                Some(n) => n.to_string(),
                None => format!("-{n}"),
            })),
            AllowedValue::String(_) => None,
        },
        Expr::UnaryOp {
            op: UnaryOperator::Plus,
            expr: inner,
        } => match literal(inner)? {
            number @ AllowedValue::Number(_) => Some(number),
            AllowedValue::String(_) => None,
        },
        Expr::Cast {
            expr: inner, data_type, ..
        } => match (numeric_cast(data_type), literal(inner)?) {
            (Some(cast), AllowedValue::Number(n)) => cast.keeps(&n).then_some(AllowedValue::Number(n)),
            // PostgreSQL trims the input of a numeric type.
            (Some(cast), AllowedValue::String(s)) => json_number(s.trim())
                .filter(|n| cast.keeps(n))
                .map(AllowedValue::Number),
            (None, string @ AllowedValue::String(_)) => Some(string),
            (None, AllowedValue::Number(_)) => None,
        },
        _ => None,
    }
}

/// A cast to a numeric type, by what it does to the number cast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NumericCast {
    /// `smallint`, `integer`, `bigint`: an integer stays; a fraction is
    /// rounded.
    Integer,
    /// `real`: an integer it holds exactly stays; a fraction is rounded to
    /// binary.
    Real,
    /// `numeric` without a typmod, `double precision`: a JSON number stays
    /// (JSON validators compare as doubles, like `double precision`).
    Exact,
    /// `numeric(p, s)`, which rounds to its scale and limits its precision.
    Rounded,
}

impl NumericCast {
    /// Whether the cast leaves the JSON number `n` unchanged.
    fn keeps(self, n: &str) -> bool {
        let integer = || n.parse::<i64>().ok();
        match self {
            Self::Integer => integer().is_some(),
            Self::Real => integer().is_some_and(|n| n.unsigned_abs() <= 1 << 24),
            Self::Exact => true,
            Self::Rounded => false,
        }
    }
}

/// The numeric cast `data_type` names, if it is a built-in numeric type. A
/// domain over one is not recognised (its base type is not known here), so
/// a literal cast to it is not translated.
fn numeric_cast(data_type: &DataType) -> Option<NumericCast> {
    use sqlparser::ast::ExactNumberInfo;
    Some(match data_type {
        DataType::SmallInt(_)
        | DataType::Int2(_)
        | DataType::Int(_)
        | DataType::Int4(_)
        | DataType::Integer(_)
        | DataType::BigInt(_)
        | DataType::Int8(_) => NumericCast::Integer,
        DataType::Real | DataType::Float4 => NumericCast::Real,
        // `float(p)` is `real` up to 24 bits of precision.
        DataType::Float(ExactNumberInfo::Precision(p)) if *p <= 24 => NumericCast::Real,
        DataType::Float(_) | DataType::Float8 | DataType::DoublePrecision => NumericCast::Exact,
        DataType::Numeric(ExactNumberInfo::None)
        | DataType::Decimal(ExactNumberInfo::None)
        | DataType::Dec(ExactNumberInfo::None) => NumericCast::Exact,
        DataType::Numeric(_) | DataType::Decimal(_) | DataType::Dec(_) => NumericCast::Rounded,
        DataType::Custom(name, modifiers) => match name.to_string().to_lowercase().as_str() {
            "int2" | "int4" | "int8" | "smallint" | "integer" | "bigint" => NumericCast::Integer,
            "float4" => NumericCast::Real,
            "float8" => NumericCast::Exact,
            "numeric" | "decimal" if modifiers.is_empty() => NumericCast::Exact,
            "numeric" | "decimal" => NumericCast::Rounded,
            _ => return None,
        },
        _ => return None,
    })
}

/// `text` as a JSON number, if it spells a decimal one -- an optional sign,
/// digits with an optional fraction, an optional exponent -- written as JSON
/// requires: no `+`, no leading zeros, digits on both sides of a point.
fn json_number(text: &str) -> Option<String> {
    let (negative, unsigned) = match text.as_bytes().first()? {
        b'-' => (true, &text[1..]),
        b'+' => (false, &text[1..]),
        _ => (false, text),
    };
    let (mantissa, exponent) = match unsigned.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => (mantissa, Some(exponent)),
        None => (unsigned, None),
    };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if (whole.is_empty() && fraction.is_empty()) || !digits(whole) || !digits(fraction) {
        return None;
    }
    let mut out = String::new();
    if negative {
        out.push('-');
    }
    let whole = whole.trim_start_matches('0');
    out.push_str(if whole.is_empty() { "0" } else { whole });
    if !fraction.is_empty() {
        out.push('.');
        out.push_str(fraction);
    }
    if let Some(exponent) = exponent {
        let magnitude = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
        if magnitude.is_empty() || !digits(magnitude) {
            return None;
        }
        out.push('e');
        out.push_str(exponent);
    }
    Some(out)
}

/// The elements of `ARRAY[...]`, through parentheses and casts.
fn array_elements(expr: &Expr) -> Option<&[Expr]> {
    match expr {
        Expr::Nested(inner) => array_elements(inner),
        Expr::Cast { expr: inner, .. } => array_elements(inner),
        Expr::Array(array) => Some(&array.elem),
        _ => None,
    }
}

fn flip(op: &BinaryOperator) -> BinaryOperator {
    use BinaryOperator::*;
    match op {
        Lt => Gt,
        LtEq => GtEq,
        Gt => Lt,
        GtEq => LtEq,
        other => other.clone(),
    }
}

fn length_bound(n: &str) -> Result<u64, String> {
    n.parse::<u64>()
        .map_err(|_| "a length bound must be a non-negative integer".to_string())
}

fn pattern_rule(pattern: String) -> Rules {
    Rules {
        pattern: Some(pattern),
        ..Rules::default()
    }
}

/// A pattern matching exactly the strings `pattern` finds no match in.
fn negate(pattern: &str) -> String {
    format!("^(?![\\s\\S]*(?:{pattern}))")
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlparser::dialect::PostgreSqlDialect;
    use sqlparser::parser::Parser;

    fn parse(sql: &str) -> Expr {
        Parser::new(&PostgreSqlDialect {})
            .try_with_sql(sql)
            .unwrap()
            .parse_expr()
            .unwrap()
    }

    fn rules(sql: &str, subject: &str) -> Rules {
        let translation = translate_check(&parse(sql), subject, &TextComparison::Exact);
        assert!(
            translation.untranslated.is_empty(),
            "{sql}: {:?}",
            translation.untranslated
        );
        translation.rules
    }

    fn refused(sql: &str, subject: &str) -> String {
        let translation = translate_check(&parse(sql), subject, &TextComparison::Exact);
        assert_eq!(translation.untranslated.len(), 1, "{sql}: {translation:?}");
        translation.untranslated[0].1.clone()
    }

    fn s(value: &str) -> Option<String> {
        Some(value.to_string())
    }

    #[test]
    fn should_translate_numeric_comparisons() {
        assert_eq!(rules("position >= 0", "position").minimum, s("0"));
        assert_eq!(rules("position > 0", "position").exclusive_minimum, s("0"));
        assert_eq!(rules("0 < position", "position").exclusive_minimum, s("0"));
        assert_eq!(rules("position <= -1.5", "position").maximum, s("-1.5"));
        assert_eq!(rules("VALUE < 10", "value").exclusive_maximum, s("10"));
    }

    #[test]
    fn should_translate_between_and_conjunctions() {
        let between = rules("VALUE BETWEEN 0 AND 100000000", "value");
        assert_eq!((between.minimum, between.maximum), (s("0"), s("100000000")));
        let both = rules("amount >= 1 AND amount <= 5", "amount");
        assert_eq!((both.minimum, both.maximum), (s("1"), s("5")));
    }

    #[test]
    fn should_translate_lengths() {
        assert_eq!(rules("length(title) <= 500000", "title").max_length, Some(500000));
        assert_eq!(rules("char_length(VALUE) > 2", "value").min_length, Some(3));
        let between = rules("length(code) BETWEEN 2 AND 4", "code");
        assert_eq!((between.min_length, between.max_length), (Some(2), Some(4)));
    }

    #[test]
    fn should_translate_a_not_blank_trimmed_length() {
        for sql in [
            "length(trim(title)) > 0",
            "length(btrim(title)) > 0",
            "length(TRIM(BOTH ' ' FROM title)) >= 1",
            "char_length(ltrim(title)) <> 0",
        ] {
            let translated = rules(sql, "title");
            assert_eq!(translated.pattern, s("[^ ]"), "{sql}");
            assert_eq!(translated.min_length, Some(1), "{sql}");
        }
        assert!(refused("length(btrim(title)) > 3", "title").contains("not blank"));
        assert!(
            !translate_check(&parse("length(btrim(title, 'x')) > 0"), "title", &TextComparison::Exact)
                .untranslated
                .is_empty()
        );
    }

    #[test]
    fn should_refuse_octet_lengths() {
        assert!(refused("octet_length(body) < 100", "body").contains("bytes"));
    }

    #[test]
    fn should_translate_patterns() {
        assert_eq!(
            rules("slug ~ '^[a-z0-9-]+$'::text", "slug").pattern,
            s("^[a-z0-9\\-]+$")
        );
        assert_eq!(rules("VALUE !~ '^x'", "value").pattern, s("^(?![\\s\\S]*(?:^x))"));
        assert_eq!(rules("code LIKE 'GB%'", "code").pattern, s("^GB[\\s\\S]*$"));
        assert!(refused("slug ~ '\\w+'", "slug").contains("locale"));
        assert!(refused("slug ~* 'abc'", "slug").contains("case-insensitive"));
    }

    #[test]
    fn should_translate_allowed_values() {
        let expected = Some(vec![
            AllowedValue::String("mygiving".to_string()),
            AllowedValue::String("help".to_string()),
        ]);
        assert_eq!(
            rules("publication::text IN ('mygiving', 'help')", "publication").allowed,
            expected
        );
        assert_eq!(
            rules(
                "(publication)::text = ANY ((ARRAY['mygiving'::character varying, 'help'::character varying])::text[])",
                "publication"
            )
            .allowed,
            expected
        );
        assert_eq!(
            rules("level IN (1, 2)", "level").allowed,
            Some(vec![
                AllowedValue::Number("1".to_string()),
                AllowedValue::Number("2".to_string())
            ])
        );
    }

    #[test]
    fn should_refuse_text_comparisons_that_are_not_byte_exact() {
        let citext = TextComparison::Inexact("citext compares case-insensitively".to_string());
        for sql in [
            "email ~ '^[a-z]+$'",
            "email LIKE 'a%'",
            "email IN ('a', 'b')",
            "email = 'a'",
        ] {
            let translation = translate_check(&parse(sql), "email", &citext);
            assert!(translation.rules.is_empty(), "{sql}: {translation:?}");
            assert_eq!(translation.untranslated.len(), 1, "{sql}");
            assert!(translation.untranslated[0].1.contains("citext"), "{sql}");
        }
        let kept = translate_check(
            &parse("length(email) <= 5 AND length(trim(email)) > 0"),
            "email",
            &citext,
        );
        assert!(kept.untranslated.is_empty(), "{kept:?}");
        assert_eq!(kept.rules.max_length, Some(5));
        assert_eq!(kept.rules.pattern, s(NOT_BLANK));
    }

    #[test]
    fn should_keep_quoted_literals_cast_to_text_as_strings() {
        let strings = |values: &[&str]| {
            Some(
                values
                    .iter()
                    .map(|v| AllowedValue::String(v.to_string()))
                    .collect::<Vec<_>>(),
            )
        };
        // How pg_get_constraintdef prints `CHECK (code = '10')` and
        // `CHECK (code IN ('10', '20'))` on a text column.
        assert_eq!(rules("code = '10'::text", "code").allowed, strings(&["10"]));
        assert_eq!(rules("code IN ('10', '20')", "code").allowed, strings(&["10", "20"]));
        assert_eq!(
            rules("code = ANY (ARRAY['10'::text, '20'::text])", "code").allowed,
            strings(&["10", "20"])
        );
        assert_eq!(
            rules("code = '1e3'::character varying", "code").allowed,
            strings(&["1e3"])
        );
        // A string bound on text is a collation-dependent comparison.
        refused("code >= '10'::text", "code");
    }

    #[test]
    fn should_read_quoted_literals_cast_to_numeric_types_as_numbers() {
        // How PostgreSQL prints a negative constant.
        assert_eq!(rules("amount > '-1'::integer", "amount").exclusive_minimum, s("-1"));
        assert_eq!(rules("amount >= '2.50'::numeric", "amount").minimum, s("2.50"));
        assert_eq!(rules("amount <= ' +.5 '::double precision", "amount").maximum, s("0.5"));
        assert_eq!(
            rules("amount < (0.5)::double precision", "amount").exclusive_maximum,
            s("0.5")
        );
        assert_eq!(rules("amount <= '007'::bigint", "amount").maximum, s("7"));
        assert_eq!(
            rules("amount = '1E3'::numeric", "amount").allowed,
            Some(vec![AllowedValue::Number("1e3".to_string())])
        );
        assert_eq!(
            rules("amount IN ('1'::integer, '-2'::integer)", "amount").allowed,
            Some(vec![
                AllowedValue::Number("1".to_string()),
                AllowedValue::Number("-2".to_string())
            ])
        );
        assert_eq!(rules("amount >= '5'::int4", "amount").minimum, s("5"));
    }

    #[test]
    fn should_refuse_numbers_without_an_exact_json_form() {
        for sql in [
            "amount < 'NaN'::numeric",
            "amount = 'NaN'::numeric",
            "amount < 'Infinity'::double precision",
            "amount < 'inf'::real",
            "amount IN ('NaN'::numeric)",
            "amount > '0x1F'::integer",
            "amount > '1_000'::integer",
            // Casts that change the value.
            "amount > 5.5::integer",
            "amount > '1.25'::numeric(3, 1)",
            "amount > 0.1::real",
            "amount > 16777217::real",
            // A number cast to text is text.
            "amount = (10)::text",
        ] {
            refused(sql, "amount");
        }
        assert_eq!(
            rules("amount > 16777216::real", "amount").exclusive_minimum,
            s("16777216")
        );
    }

    #[test]
    fn should_refuse_length_bounds_out_of_range() {
        refused("length(code) > 9223372036854775807", "code");
        refused("length(code) < 0", "code");
        assert_eq!(rules("length(code) < 1", "code").max_length, Some(0));
    }

    #[test]
    fn should_translate_multiples() {
        assert_eq!(rules("amount % 5 = 0", "amount").multiple_of, s("5"));
    }

    #[test]
    fn should_ignore_a_null_guard() {
        assert_eq!(rules("position IS NULL OR position >= 0", "position").minimum, s("0"));
    }

    #[test]
    fn should_keep_translated_conjuncts_and_report_the_rest() {
        let translation = translate_check(
            &parse("position >= 0 AND position <> 3"),
            "position",
            &TextComparison::Exact,
        );
        assert_eq!(translation.rules.minimum, s("0"));
        assert_eq!(translation.untranslated.len(), 1);
        assert_eq!(translation.untranslated[0].0, "position <> 3");
    }

    #[test]
    fn should_refuse_other_shapes() {
        refused("name > 'a'", "name");
        refused("lower(name) = name", "name");
        refused("position >= 0 OR position < -10", "position");
        refused("name NOT IN ('a')", "name");
    }

    #[test]
    fn should_list_referenced_columns() {
        assert_eq!(referenced_columns(&parse("length(btrim(title)) > 0")), vec!["title"]);
        assert_eq!(
            referenced_columns(&parse("num_nonnulls(daf_account_id, platform) = 1")),
            vec!["daf_account_id", "platform"]
        );
    }
}
