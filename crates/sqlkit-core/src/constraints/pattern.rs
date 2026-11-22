//! Translation of PostgreSQL patterns into ECMAScript regular expressions.
//!
//! JSON Schema's `pattern` keyword is an ECMA-262 regular expression matched
//! anywhere in the string, which is also how PostgreSQL's `~` operator applies
//! an advanced regular expression (ARE). Only a subset of ARE syntax means the
//! same thing in both engines, so [`posix_to_ecmascript`] translates that
//! subset and refuses everything else rather than emit a pattern that accepts
//! or rejects different strings than the database does.
//!
//! The output is valid both with and without the `u` flag (validators commonly
//! compile JSON Schema patterns with it), and never contains `*/`, so it can be
//! written into a block comment: `/` is always escaped.

/// Characters that must be escaped to stand for themselves outside a class.
const SYNTAX: &str = "^$\\.*+?()[]{}|/";

/// Translate a PostgreSQL advanced regular expression into an equivalent
/// ECMAScript pattern, or explain why it cannot be translated.
///
/// Translated: literals, `.`, `^`, `$`, groups (`(...)`, `(?:...)`, `(?=...)`,
/// `(?!...)`), alternation, the quantifiers `*`, `+`, `?` and `{m}`, `{m,}`,
/// `{m,n}` (greedy or non-greedy), bracket expressions with ranges, negation
/// and `[:digit:]`, the escapes `\d`, `\D`, `\n`, `\t`, `\r`, `\f`, `\v`, `\A`,
/// `\Z`, `\uXXXX`, and escaped punctuation. `.` becomes `[\s\S]` because an
/// ARE's `.` matches a newline and ECMAScript's does not.
///
/// `\d` and `[:digit:]` become the ASCII `0-9`, which assumes the database's
/// regular expressions classify characters through a libc locale, as
/// PostgreSQL does for the default and libc collations: libc counts only the
/// ASCII digits as digits there. Under an ICU collation `\d` also matches
/// other scripts' decimal digits, and the translated pattern rejects values
/// the database accepts.
///
/// Refused: locale-dependent classes (`\w`, `\s`, `[:alpha:]`, ...), word
/// boundaries and ARE-only escapes (`\m`, `\M`, `\y`, `\Y`, `\b`), back
/// references, collating elements, embedded options and directors (`***`,
/// `(?i)`), and lookbehind.
pub fn posix_to_ecmascript(pattern: &str) -> Result<String, String> {
    if pattern.starts_with("***") {
        return Err("regular expression directors (`***`) are not translated".to_string());
    }
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::with_capacity(pattern.len() + 8);
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\\' => {
                let next = *chars.get(i + 1).ok_or("a trailing backslash is not a valid pattern")?;
                i += 2;
                match next {
                    'd' | 'D' | 'n' | 't' | 'r' | 'f' | 'v' => {
                        out.push('\\');
                        out.push(next);
                    }
                    'A' => out.push('^'),
                    'Z' => out.push('$'),
                    'u' => {
                        let hex: String = chars.iter().skip(i).take(4).collect();
                        if hex.len() != 4 || !hex.chars().all(|h| h.is_ascii_hexdigit()) {
                            return Err("`\\u` must be followed by four hexadecimal digits".to_string());
                        }
                        out.push_str("\\u");
                        out.push_str(&hex);
                        i += 4;
                    }
                    'w' | 'W' | 's' | 'S' => {
                        return Err(format!(
                            "`\\{next}` depends on the database locale and differs from ECMAScript's"
                        ));
                    }
                    other if other.is_ascii_alphanumeric() => {
                        return Err(format!("the escape `\\{other}` has no ECMAScript equivalent"));
                    }
                    other => push_literal(&mut out, other),
                }
            }
            '[' => {
                i = translate_bracket(&chars, i, &mut out)?;
            }
            '(' => {
                if chars.get(i + 1) == Some(&'?') {
                    match chars.get(i + 2) {
                        Some(':') | Some('=') | Some('!') => {
                            out.push_str("(?");
                            out.push(chars[i + 2]);
                            i += 3;
                        }
                        _ => {
                            return Err("embedded options and lookbehind are not translated".to_string());
                        }
                    }
                } else {
                    out.push('(');
                    i += 1;
                }
            }
            '{' => {
                let close = chars[i..]
                    .iter()
                    .position(|&ch| ch == '}')
                    .map(|offset| i + offset)
                    .ok_or("an unterminated `{` bound")?;
                let body: String = chars[i + 1..close].iter().collect();
                if !is_bound(&body) {
                    return Err(format!("`{{{body}}}` is not a supported bound"));
                }
                out.push('{');
                out.push_str(&body);
                out.push('}');
                i = close + 1;
                if chars.get(i) == Some(&'?') {
                    out.push('?');
                    i += 1;
                }
            }
            '.' => {
                out.push_str("[\\s\\S]");
                i += 1;
            }
            '^' | '$' | '*' | '+' | '?' | ')' | '|' => {
                out.push(c);
                i += 1;
            }
            other => {
                push_literal(&mut out, other);
                i += 1;
            }
        }
    }
    Ok(out)
}

/// Translate a `LIKE` pattern into an anchored ECMAScript pattern.
///
/// `%` matches any run of characters and `_` any one character; `escape`
/// (backslash by default, `None` for `ESCAPE ''`) makes the next character
/// literal.
pub fn like_to_ecmascript(pattern: &str, escape: Option<char>) -> Result<String, String> {
    let mut out = String::from("^");
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        if Some(c) == escape {
            let literal = chars
                .next()
                .ok_or("a LIKE pattern must not end with its escape character")?;
            push_literal(&mut out, literal);
        } else if c == '%' {
            out.push_str("[\\s\\S]*");
        } else if c == '_' {
            out.push_str("[\\s\\S]");
        } else {
            push_literal(&mut out, c);
        }
    }
    out.push('$');
    Ok(out)
}

fn push_literal(out: &mut String, c: char) {
    if SYNTAX.contains(c) {
        out.push('\\');
    }
    out.push(c);
}

/// Whether `body` (the text between `{` and `}`) is `m`, `m,` or `m,n`.
fn is_bound(body: &str) -> bool {
    let mut parts = body.splitn(2, ',');
    let low = parts.next().unwrap_or("");
    let digits = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
    match parts.next() {
        None => digits(low),
        Some(high) => digits(low) && (high.is_empty() || digits(high)),
    }
}

/// Translate the bracket expression opening at `chars[start]`, returning the
/// index just past its closing `]`.
fn translate_bracket(chars: &[char], start: usize, out: &mut String) -> Result<usize, String> {
    let mut i = start + 1;
    out.push('[');
    if chars.get(i) == Some(&'^') {
        out.push('^');
        i += 1;
    }
    let mut first = true;
    loop {
        let c = *chars.get(i).ok_or("an unterminated bracket expression")?;
        if c == ']' && !first {
            out.push(']');
            return Ok(i + 1);
        }
        first = false;
        let (item, next) = bracket_item(chars, i)?;
        i = next;
        // A range `a-z`: a `-` that is neither the first nor the last item.
        if chars.get(i) == Some(&'-') && chars.get(i + 1).is_some_and(|&n| n != ']') {
            let BracketItem::Char(low) = item else {
                return Err("a character class cannot start a range".to_string());
            };
            let (high, after) = bracket_item(chars, i + 1)?;
            let BracketItem::Char(high) = high else {
                return Err("a character class cannot end a range".to_string());
            };
            push_class_char(out, low);
            out.push('-');
            push_class_char(out, high);
            i = after;
            continue;
        }
        match item {
            BracketItem::Char(ch) => push_class_char(out, ch),
            BracketItem::Class(class) => out.push_str(class),
        }
    }
}

enum BracketItem {
    Char(char),
    Class(&'static str),
}

/// One element of a bracket expression starting at `chars[i]`.
fn bracket_item(chars: &[char], i: usize) -> Result<(BracketItem, usize), String> {
    let c = chars[i];
    match c {
        '[' => match chars.get(i + 1) {
            Some(':') => {
                let rest: String = chars[i..].iter().collect();
                let end = rest.find(":]").ok_or("an unterminated character class")?;
                let name = &rest[2..end];
                let consumed = rest[..end + 2].chars().count();
                match name {
                    "digit" => Ok((BracketItem::Class("0-9"), i + consumed)),
                    _ => Err(format!(
                        "`[:{name}:]` depends on the database locale and is not translated"
                    )),
                }
            }
            Some('.') | Some('=') => Err("collating elements and equivalence classes are not translated".to_string()),
            _ => Ok((BracketItem::Char('['), i + 1)),
        },
        '\\' => {
            let next = *chars.get(i + 1).ok_or("a trailing backslash is not a valid pattern")?;
            match next {
                'd' => Ok((BracketItem::Class("\\d"), i + 2)),
                'n' => Ok((BracketItem::Char('\n'), i + 2)),
                't' => Ok((BracketItem::Char('\t'), i + 2)),
                'r' => Ok((BracketItem::Char('\r'), i + 2)),
                other if other.is_ascii_alphanumeric() => Err(format!(
                    "the escape `\\{other}` inside a bracket expression is not translated"
                )),
                other => Ok((BracketItem::Char(other), i + 2)),
            }
        }
        other => Ok((BracketItem::Char(other), i + 1)),
    }
}

fn push_class_char(out: &mut String, c: char) {
    match c {
        '\\' | ']' | '[' | '^' | '-' | '/' => {
            out.push('\\');
            out.push(c);
        }
        '\n' => out.push_str("\\n"),
        '\t' => out.push_str("\\t"),
        '\r' => out.push_str("\\r"),
        _ => out.push(c),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_keep_a_compatible_pattern() {
        assert_eq!(posix_to_ecmascript("^[a-z0-9-]+$").unwrap(), "^[a-z0-9\\-]+$");
        assert_eq!(posix_to_ecmascript("^[a-zA-Z]{3}$").unwrap(), "^[a-zA-Z]{3}$");
        assert_eq!(posix_to_ecmascript("^(?:ab|cd)+?x{2,}$").unwrap(), "^(?:ab|cd)+?x{2,}$");
    }

    #[test]
    fn should_make_dot_match_newlines() {
        assert_eq!(posix_to_ecmascript("a.c").unwrap(), "a[\\s\\S]c");
    }

    #[test]
    fn should_translate_digit_classes_and_anchors() {
        assert_eq!(posix_to_ecmascript("\\A[[:digit:]]+\\Z").unwrap(), "^[0-9]+$");
        assert_eq!(posix_to_ecmascript("^\\d{4}$").unwrap(), "^\\d{4}$");
    }

    #[test]
    fn should_escape_literals_for_unicode_mode() {
        assert_eq!(posix_to_ecmascript("a\\-b").unwrap(), "a-b");
        assert_eq!(posix_to_ecmascript("a]b}").unwrap(), "a\\]b\\}");
        assert_eq!(posix_to_ecmascript("a\\.b").unwrap(), "a\\.b");
        assert_eq!(posix_to_ecmascript("[]a]").unwrap(), "[\\]a]");
        assert_eq!(posix_to_ecmascript("[a^]").unwrap(), "[a\\^]");
    }

    #[test]
    fn should_never_emit_a_comment_terminator() {
        let translated = posix_to_ecmascript("^a*/b[/]$").unwrap();
        assert!(!translated.contains("*/"), "{translated}");
        assert_eq!(translated, "^a*\\/b[\\/]$");
    }

    #[test]
    fn should_refuse_locale_dependent_classes() {
        for pattern in ["\\w+", "\\s", "[[:alpha:]]", "[\\w]"] {
            assert!(posix_to_ecmascript(pattern).is_err(), "{pattern}");
        }
    }

    #[test]
    fn should_refuse_are_only_syntax() {
        for pattern in [
            "***:abc",
            "(?i)abc",
            "\\mword\\M",
            "(a)\\1",
            "[[.a.]]",
            "a{x}",
            "\\x41",
            "(?<=a)b",
        ] {
            assert!(posix_to_ecmascript(pattern).is_err(), "{pattern}");
        }
    }

    #[test]
    fn should_translate_like_patterns() {
        assert_eq!(like_to_ecmascript("ab%", Some('\\')).unwrap(), "^ab[\\s\\S]*$");
        assert_eq!(like_to_ecmascript("a_c", Some('\\')).unwrap(), "^a[\\s\\S]c$");
        assert_eq!(like_to_ecmascript("100\\%.", Some('\\')).unwrap(), "^100%\\.$");
        assert!(like_to_ecmascript("a\\", Some('\\')).is_err());
    }
}
