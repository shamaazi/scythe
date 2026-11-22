//! Escape SQL text for safe splicing into a target-language string literal.
//!
//! Every backend embeds the query's SQL text directly into the generated source as a
//! string literal (`conn.prepare("SELECT ...")`, `sqlx::query!("SELECT ...")`, and so on).
//! An unescaped backslash or embedded quote either changes what the database receives (a
//! `LIKE 'a\_b%'` backslash silently becomes a real escape) or breaks the literal outright
//! (a quoted SQL identifier like `SELECT "type"` terminates the host string early).
//!
//! One function per **host literal form** lives here, not one per backend, because the
//! literal form -- not the driver -- determines what needs escaping. Every function takes
//! the already-cleaned SQL text (post `clean_sql`/`clean_sql_oneline`/placeholder rewriting)
//! and returns text safe to splice verbatim between that host form's delimiters. None of
//! them touch delimiters themselves except [`rust_raw_string_literal`], which must choose
//! its own delimiter width. The TypeScript backends escape through
//! [`escape_ts_template_literal`](crate::backends::typescript_common::escape_ts_template_literal) and
//! [`escape_ts_double_quoted_literal`](crate::backends::typescript_common::escape_ts_double_quoted_literal).

/// Escape SQL text for splicing into a Rust plain `"..."` string literal.
///
/// Rust string literals permit raw newlines, so only backslash and `"` need escaping.
/// Used by `rust-sqlx` (its `sqlx::query!`/`query_as!` macros
/// receive the *decoded* string value at compile time, identical to the unescaped source
/// text, so escaping here has no effect on the macro's compile-time query verification).
pub fn escape_rust_string(sql: &str) -> String {
    escape_char_by_char(sql, |ch| match ch {
        '\\' => Some("\\\\"),
        '"' => Some("\\\""),
        _ => None,
    })
}

/// Build a complete Rust raw string literal (`r#"..."#`, widened as needed) containing
/// `sql` verbatim.
///
/// Raw strings cannot escape anything -- that is the point of using one -- so a SQL body
/// containing the delimiter sequence `"#` breaks a fixed `r#"..."#` literal outright
/// (issue #179's `rust-tokio-postgres` case: `"#` anywhere in the query,
/// including inside an ordinary comment or string, ends the literal early and leaves the
/// rest as malformed Rust). This widens the hash run only as far as the content requires:
/// plain SQL gets the same `r#"..."#` these backends always emitted, and only a query that
/// actually contains `"#`, `"##`, ... pays for a wider delimiter.
///
/// Returns the full literal, delimiters included, ready to splice directly in place of a
/// hand-written `r#"{}"#`.
pub fn rust_raw_string_literal(sql: &str) -> String {
    let mut hashes = 1usize;
    loop {
        let marker = format!("\"{}", "#".repeat(hashes));
        if !sql.contains(&marker) {
            break;
        }
        hashes += 1;
    }
    let delim = "#".repeat(hashes);
    format!("r{delim}\"{sql}\"{delim}")
}

/// Shared implementation for host literals whose escape set is a fixed per-character
/// substitution table with no multi-character lookahead (i.e. everything except the
/// `#{`/`${`-style interpolation escapes, which need [`escape_interpolating_double_quoted`]
/// or their own bespoke pass).
///
/// `substitute` returns `Some(replacement)` when it handled `ch` itself, `None` to fall
/// through to pushing `ch` unchanged. Iterating character-by-character rather than chaining
/// `str::replace` calls sidesteps the classic bug where an earlier pass's *output*
/// accidentally matches a later pass's pattern (e.g. escaping `"` before `\` would turn `"`
/// into `\"`, and the backslash pass would then re-escape the very backslash the quote pass
/// just inserted).
fn escape_char_by_char(sql: &str, substitute: impl Fn(char) -> Option<&'static str>) -> String {
    let mut out = String::with_capacity(sql.len());
    for ch in sql.chars() {
        match substitute(ch) {
            Some(replacement) => out.push_str(replacement),
            None => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Adversarial corpus shared by every round-trip test below: interpolation markers for
    /// every interpolating host, the raw-string-breaking sequence, quote/backslash pairs a
    /// naive single-pass replace gets wrong, whitespace control characters, non-ASCII text,
    /// and a full SQL fragment with a doubled-apostrophe string literal.
    fn adversarial_corpus() -> Vec<&'static str> {
        vec![
            "",
            "$var",
            "${x}",
            "#{x}",
            "`backtick`",
            "single'quote",
            "double\"quote",
            "back\\slash",
            "double\\\\backslash",
            "new\nline",
            "tab\tchar",
            "carriage\rreturn",
            "quote\"then\\backslash",
            "backslash\\then\"quote",
            "\"#",
            "\"##",
            "café",
            "日本語",
            "SELECT * FROM t WHERE name = 'O''Brien'",
            "SELECT \"type\", \"class\" FROM items WHERE note = 'a\\_b%' AND tag = '$name' AND memo = '#{x}'",
        ]
    }

    /// Decode [`escape_rust_string`]'s output: only `\\` and `\"` are escapes, and real
    /// newlines/tabs pass through untouched.
    fn unescape_backslash_quote_control_no_nrt(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                match chars.next() {
                    Some('\\') => out.push('\\'),
                    Some('"') => out.push('"'),
                    Some(other) => panic!("unexpected escape \\{other}"),
                    None => panic!("dangling backslash"),
                }
            } else {
                out.push(ch);
            }
        }
        out
    }

    // --- Rust -------------------------------------------------------------

    #[test]
    fn rust_plain_round_trips_over_adversarial_corpus() {
        for input in adversarial_corpus() {
            let escaped = escape_rust_string(input);
            assert_eq!(
                unescape_backslash_quote_control_no_nrt(&escaped),
                input,
                "input: {input:?} -> {escaped:?}"
            );
        }
    }

    /// Extracts the SQL body back out of a full `rN#"..."N#` literal built by
    /// [`rust_raw_string_literal`], for round-trip assertions.
    fn unwrap_rust_raw_string_literal(literal: &str) -> &str {
        let rest = literal.strip_prefix('r').expect("must start with r");
        let hashes = rest.chars().take_while(|&c| c == '#').count();
        let delim = &rest[..hashes];
        let opened = &rest[hashes..];
        let opened = opened.strip_prefix('"').expect("must open with a quote");
        let closer = format!("\"{delim}");
        opened
            .strip_suffix(&closer)
            .expect("must close with matching delimiter")
    }

    #[test]
    fn rust_raw_string_round_trips_over_adversarial_corpus() {
        for input in adversarial_corpus() {
            let literal = rust_raw_string_literal(input);
            assert_eq!(
                unwrap_rust_raw_string_literal(&literal),
                input,
                "input: {input:?} -> {literal:?}"
            );
        }
    }

    /// Direct regression test for the raw-string-breaking case in issue #179: `"#` anywhere
    /// in the SQL must not terminate a fixed `r#"..."#` literal early. The widened
    /// delimiter must not appear inside the SQL body itself, or the same problem recurs one
    /// level up.
    #[test]
    fn rust_raw_string_widens_delimiter_when_sql_contains_hash_quote() {
        let sql = "a\"#b";
        let literal = rust_raw_string_literal(sql);
        assert_eq!(literal, "r##\"a\"#b\"##");
        assert_eq!(unwrap_rust_raw_string_literal(&literal), sql);
    }

    #[test]
    fn rust_raw_string_plain_sql_uses_single_hash() {
        let literal = rust_raw_string_literal("SELECT 1");
        assert_eq!(literal, "r#\"SELECT 1\"#");
    }

    #[test]
    fn rust_raw_string_widens_again_for_double_hash() {
        let sql = "a\"##b";
        let literal = rust_raw_string_literal(sql);
        assert_eq!(literal, "r###\"a\"##b\"###");
        assert_eq!(unwrap_rust_raw_string_literal(&literal), sql);
    }
}
