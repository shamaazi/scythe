// The helpers below are shared by the backends of several languages. A build that
// compiles only some languages leaves some of them unused; the default build,
// which compiles every language, is the one dead-code analysis applies to.
#![cfg_attr(not(feature = "all-languages"), allow(dead_code))]

#[cfg(feature = "lang-rust")]
pub(crate) mod sqlx;
#[cfg(feature = "lang-rust")]
pub(crate) mod tokio_postgres;
#[cfg(feature = "lang-typescript")]
pub(crate) mod typescript_common;
#[cfg(feature = "lang-typescript")]
pub(crate) mod typescript_postgres;

use sqlkit_backend::manifest::BackendManifest;
use sqlkit_core::analyzer::AnalyzedParam;
use sqlkit_core::errors::{ErrorCode, SqlkitError};

use crate::backend_trait::CodegenBackend;

/// Parse a backend's compiled-in manifest.
///
/// Manifest selection is a pure function of the backend. There is
/// deliberately no filesystem lookup here: generated output must not depend
/// on the process working directory (#82).
/// The summary a generator writes above a query's function: the free-text
/// description from the query header when there is one, otherwise the
/// generator's own `fallback` wording. May span several lines.
pub(crate) fn query_doc_text<'a>(analyzed: &'a sqlkit_core::analyzer::AnalyzedQuery, fallback: &'a str) -> &'a str {
    analyzed.description.as_deref().unwrap_or(fallback)
}

pub(crate) fn parse_manifest(manifest_toml: &str) -> Result<BackendManifest, SqlkitError> {
    toml::from_str(manifest_toml).map_err(|e| SqlkitError::new(ErrorCode::InternalError, format!("manifest: {e}")))
}

/// Parse a boolean backend option strictly.
///
/// Accepts (case-insensitively) `true`/`false`, `1`/`0`, and `yes`/`no`. Any
/// other value — a typo, `"on"`, an empty string — is rejected with an error
/// naming the option and the offending value, rather than being silently
/// coerced to `false` as `matches!` or `== "true"` would do.
pub(crate) fn parse_bool_option(option_name: &str, value: &str) -> Result<bool, SqlkitError> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(SqlkitError::new(
            ErrorCode::InvalidConfig,
            format!("invalid {option_name} '{value}': expected 'true'/'false', '1'/'0', or 'yes'/'no'"),
        )),
    }
}

/// A classified span of SQL text produced by [`tokenize_sql`].
///
/// One lexer pass drives both comment-stripping (`clean_sql`,
/// `clean_sql_oneline`) and placeholder-rewriting (`rewrite_pg_placeholders`)
/// -- see #186 and board #148, where two independent character scanners each got
/// string/comment handling wrong in a different way. `Code` spans are the
/// only spans either consumer may rewrite; every other span is opaque SQL
/// text that must be reproduced byte-for-byte (module the caller's own
/// whitespace joining).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SqlSpanKind {
    /// Ordinary SQL: identifiers, keywords, operators, placeholders.
    Code,
    /// A `'...'` string literal, with `''` as the escape for an embedded quote.
    SingleQuoted,
    /// A `"..."` quoted identifier, with `""` as the escape for an embedded quote.
    DoubleQuoted,
    /// A PostgreSQL `$$...$$` or `$tag$...$tag$` dollar-quoted string.
    DollarQuoted,
    /// A `-- ...` comment, running to end of line (the newline itself is not
    /// part of the span).
    LineComment,
    /// A `/* ... */` comment. PostgreSQL nests these, so this tracks nesting
    /// depth; an unterminated comment consumes to end of input.
    BlockComment,
}

/// Tokenize `sql` into a sequence of classified spans whose text
/// concatenates back to exactly `sql`.
///
/// This is the single source of truth for "is this character part of a
/// string/identifier/comment, or is it live SQL".
fn tokenize_sql(sql: &str) -> Vec<(SqlSpanKind, String)> {
    let chars: Vec<char> = sql.chars().collect();
    let len = chars.len();
    let mut spans: Vec<(SqlSpanKind, String)> = Vec::new();
    let mut code_buf = String::new();
    let mut i = 0;

    while i < len {
        let c = chars[i];

        if c == '-' && i + 1 < len && chars[i + 1] == '-' {
            flush_code_buf(&mut code_buf, &mut spans);
            let start = i;
            i += 2;
            while i < len && chars[i] != '\n' {
                i += 1;
            }
            spans.push((SqlSpanKind::LineComment, chars[start..i].iter().collect()));
            continue;
        }

        if c == '/' && i + 1 < len && chars[i + 1] == '*' {
            flush_code_buf(&mut code_buf, &mut spans);
            let start = i;
            i += 2;
            let mut depth = 1u32;
            while i < len && depth > 0 {
                if chars[i] == '/' && i + 1 < len && chars[i + 1] == '*' {
                    depth += 1;
                    i += 2;
                } else if chars[i] == '*' && i + 1 < len && chars[i + 1] == '/' {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            spans.push((SqlSpanKind::BlockComment, chars[start..i].iter().collect()));
            continue;
        }

        if c == '\'' {
            flush_code_buf(&mut code_buf, &mut spans);
            let start = i;
            i += 1;
            while i < len {
                if chars[i] == '\'' {
                    if i + 1 < len && chars[i + 1] == '\'' {
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                i += 1;
            }
            spans.push((SqlSpanKind::SingleQuoted, chars[start..i].iter().collect()));
            continue;
        }

        if c == '"' {
            flush_code_buf(&mut code_buf, &mut spans);
            let start = i;
            i += 1;
            while i < len {
                if chars[i] == '"' {
                    if i + 1 < len && chars[i + 1] == '"' {
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                i += 1;
            }
            spans.push((SqlSpanKind::DoubleQuoted, chars[start..i].iter().collect()));
            continue;
        }

        if c == '$'
            && let Some(open_end) = match_dollar_quote_open(&chars, i)
        {
            flush_code_buf(&mut code_buf, &mut spans);
            let start = i;
            let delim: Vec<char> = chars[i..open_end].to_vec();
            let mut j = open_end;
            let mut found = false;
            while j < len {
                if chars[j] == '$' && j + delim.len() <= len && chars[j..j + delim.len()] == delim[..] {
                    j += delim.len();
                    found = true;
                    break;
                }
                j += 1;
            }
            if !found {
                j = len;
            }
            spans.push((SqlSpanKind::DollarQuoted, chars[start..j].iter().collect()));
            i = j;
            continue;
        }

        code_buf.push(c);
        i += 1;
    }

    flush_code_buf(&mut code_buf, &mut spans);
    spans
}

fn flush_code_buf(code_buf: &mut String, spans: &mut Vec<(SqlSpanKind, String)>) {
    if !code_buf.is_empty() {
        spans.push((SqlSpanKind::Code, std::mem::take(code_buf)));
    }
}

/// If `chars[i]` (a `$`) opens a dollar-quote delimiter (`$$` or `$tag$`),
/// return the index just past the opening delimiter. A tag follows SQL
/// identifier rules (must not start with a digit), which is exactly what
/// keeps this from misfiring on a `$1`-style placeholder.
fn match_dollar_quote_open(chars: &[char], i: usize) -> Option<usize> {
    let mut j = i + 1;
    if j < chars.len() && chars[j] == '$' {
        return Some(j + 1);
    }
    let tag_start = j;
    while j < chars.len() && (chars[j].is_alphanumeric() || chars[j] == '_') {
        j += 1;
    }
    if j > tag_start && j < chars.len() && chars[j] == '$' && !chars[tag_start].is_ascii_digit() {
        return Some(j + 1);
    }
    None
}

/// Strip SQL comments, trailing semicolons, and excess whitespace.
/// Preserves newlines between lines.
pub(crate) fn clean_sql(sql: &str) -> String {
    clean_sql_lines(sql)
        .join("\n")
        .trim()
        .trim_end_matches(';')
        .trim()
        .to_string()
}

/// Split `sql` into lines with every comment (`--` and `/* */`, string- and
/// dollar-quote-aware) removed, dropping any line whose content was entirely
/// a comment.
///
/// A line is dropped only when a comment is what emptied it -- a line that
/// was already blank in the source (no comment token touched it) is kept,
/// matching the previous behaviour of the naive `starts_with("--")` filter
/// for every case that filter got right. This is what lets a mid-line
/// trailing comment (board #148) be stripped without deleting the rest of the
/// query, while a `-- @name Foo` header line still disappears instead of
/// leaving a blank line behind (every generated fixture depends on that).
fn clean_sql_lines(sql: &str) -> Vec<String> {
    let normalized = sql.replace("\r\n", "\n");
    let spans = tokenize_sql(&normalized);

    let mut lines: Vec<String> = vec![String::new()];
    let mut touched_by_comment: Vec<bool> = vec![false];

    for (kind, text) in &spans {
        let is_comment = matches!(kind, SqlSpanKind::LineComment | SqlSpanKind::BlockComment);
        for ch in text.chars() {
            if ch == '\n' {
                if is_comment {
                    *touched_by_comment.last_mut().expect("at least one line") = true;
                }
                lines.push(String::new());
                touched_by_comment.push(false);
            } else if is_comment {
                *touched_by_comment.last_mut().expect("at least one line") = true;
            } else {
                lines.last_mut().expect("at least one line").push(ch);
            }
        }
    }

    lines
        .into_iter()
        .zip(touched_by_comment)
        .filter(|(kept, touched)| !(*touched && kept.trim().is_empty()))
        .map(|(kept, _)| kept)
        .collect()
}

/// Rewrite SQL for optional parameters.
///
/// For each optional param, finds `column = $N` (or `column <> $N`, `column != $N`)
/// and rewrites to `($N IS NULL OR column = $N)`. This allows callers to pass NULL
/// to skip a filter condition at runtime.
///
/// This operates on the raw SQL before any backend-specific placeholder rewriting.
pub(crate) fn rewrite_optional_params(sql: &str, optional_params: &[String], params: &[AnalyzedParam]) -> String {
    if optional_params.is_empty() {
        return sql.to_string();
    }

    let mut result = sql.to_string();

    for opt_name in optional_params {
        let Some(param) = params.iter().find(|p| p.name == *opt_name) else {
            continue;
        };
        let placeholder = format!("${}", param.position);

        for op in &[
            ">=",
            "<=",
            "<>",
            "!=",
            ">",
            "<",
            "=",
            "NOT ILIKE",
            "not ilike",
            "NOT LIKE",
            "not like",
            "ILIKE",
            "ilike",
            "LIKE",
            "like",
        ] {
            result = rewrite_comparison(&result, &placeholder, op);
        }
    }

    result
}

/// Rewrite a single `column <op> $N` pattern to `($N IS NULL OR column <op> $N)`.
/// Handles both `column <op> $N` and `$N <op> column` orderings.
fn rewrite_comparison(sql: &str, placeholder: &str, op: &str) -> String {
    let mut result = String::with_capacity(sql.len() + 32);
    let chars: Vec<char> = sql.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        if let Some((_start, col, end)) = try_match_col_op_ph(&chars, i, op, placeholder) {
            result.push_str(&format!("({placeholder} IS NULL OR {col} {op} {placeholder})"));
            i = end;
            continue;
        }

        if let Some((end, col)) = try_match_ph_op_col(&chars, i, op, placeholder) {
            result.push_str(&format!("({placeholder} IS NULL OR {col} {op} {placeholder})"));
            i = end;
            continue;
        }

        result.push(chars[i]);
        i += 1;
    }

    result
}

/// Keywords that `is_ident_char` would happily scan as a column name but
/// that can never actually be one in this position. Without this check, a
/// compound operator like `NOT LIKE` gets misread: the scanner captures
/// `NOT` as "the column" and matches `LIKE` as "the operator", producing
/// `col NOT ($N IS NULL OR LIKE $N)` -- invalid SQL that silently drops the
/// real column (#186 item 3). This also guards against a second rewrite
/// pass (e.g. plain `LIKE` running after `NOT LIKE` already matched) seeing
/// the literal word `NOT` it just emitted and matching on that.
fn is_reserved_non_column_keyword(ident: &str) -> bool {
    matches!(
        ident.to_ascii_uppercase().as_str(),
        "NOT" | "AND" | "OR" | "IS" | "NULL"
    )
}

/// Match `op`, split on whitespace, against `chars` starting at `j`,
/// tolerating any amount of whitespace between words of a compound operator
/// (`NOT LIKE`, `NOT ILIKE`). Single-word operators degenerate to an exact
/// literal match, same as before. Returns the index just past the match.
fn match_op_tokens(chars: &[char], mut j: usize, op: &str) -> Option<usize> {
    for (idx, word) in op.split_whitespace().enumerate() {
        if idx > 0 {
            let ws_start = j;
            while j < chars.len() && chars[j].is_whitespace() {
                j += 1;
            }
            if j == ws_start {
                return None;
            }
        }
        let word_chars: Vec<char> = word.chars().collect();
        if j + word_chars.len() > chars.len() {
            return None;
        }
        for (k, wc) in word_chars.iter().enumerate() {
            if chars[j + k] != *wc {
                return None;
            }
        }
        j += word_chars.len();
    }
    Some(j)
}

/// Try to match `identifier <ws>* <op> <ws>* placeholder` starting at position `i`.
/// Returns `(match_start, column_name, match_end)` if found.
fn try_match_col_op_ph(chars: &[char], i: usize, op: &str, placeholder: &str) -> Option<(usize, String, usize)> {
    if !is_ident_char(chars[i]) {
        return None;
    }
    if i > 0 && is_ident_char(chars[i - 1]) {
        return None;
    }

    let ident_start = i;
    let mut j = i;
    while j < chars.len() && is_ident_char(chars[j]) {
        j += 1;
    }
    let ident: String = chars[ident_start..j].iter().collect();
    if is_reserved_non_column_keyword(&ident) {
        return None;
    }

    while j < chars.len() && chars[j].is_whitespace() {
        j += 1;
    }

    j = match_op_tokens(chars, j, op)?;

    while j < chars.len() && chars[j].is_whitespace() {
        j += 1;
    }

    let ph_chars: Vec<char> = placeholder.chars().collect();
    if j + ph_chars.len() > chars.len() {
        return None;
    }
    for (k, pc) in ph_chars.iter().enumerate() {
        if chars[j + k] != *pc {
            return None;
        }
    }
    j += ph_chars.len();

    if j < chars.len() && chars[j].is_ascii_digit() {
        return None;
    }

    Some((i, ident, j))
}

/// Try to match `placeholder <ws>* <op> <ws>* identifier` starting at position `i`.
/// Returns `(match_end, column_name)` if found.
fn try_match_ph_op_col(chars: &[char], i: usize, op: &str, placeholder: &str) -> Option<(usize, String)> {
    let ph_chars: Vec<char> = placeholder.chars().collect();
    if i + ph_chars.len() > chars.len() {
        return None;
    }

    if i > 0 && (chars[i - 1] == '$' || chars[i - 1].is_ascii_digit()) {
        return None;
    }

    for (k, pc) in ph_chars.iter().enumerate() {
        if chars[i + k] != *pc {
            return None;
        }
    }
    let mut j = i + ph_chars.len();

    if j < chars.len() && chars[j].is_ascii_digit() {
        return None;
    }

    while j < chars.len() && chars[j].is_whitespace() {
        j += 1;
    }

    j = match_op_tokens(chars, j, op)?;

    while j < chars.len() && chars[j].is_whitespace() {
        j += 1;
    }

    if j >= chars.len() || !is_ident_char(chars[j]) {
        return None;
    }
    let ident_start = j;
    while j < chars.len() && is_ident_char(chars[j]) {
        j += 1;
    }
    let ident: String = chars[ident_start..j].iter().collect();

    if is_reserved_non_column_keyword(&ident) {
        return None;
    }

    Some((j, ident))
}

/// Clean SQL and apply optional parameter rewriting.
/// Dialect-blind; see [`clean_sql`]'s doc comment.
pub(crate) fn clean_sql_with_optional(sql: &str, optional_params: &[String], params: &[AnalyzedParam]) -> String {
    let cleaned = clean_sql(sql);
    rewrite_optional_params(&cleaned, optional_params, params)
}

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '.'
}

/// Rewrite SQL placeholders (`$N` or `?`) to a target format.
///
/// Skips placeholders inside single-/double-quoted and dollar-quoted spans,
/// and inside comments (see [`tokenize_sql`]). The `formatter` closure
/// receives the parameter number (1-based) and returns the replacement.
///
/// Dialect-blind, kept for the call sites this multi-agent change did not
/// reach: whether a bare `?` is a placeholder is decided by scanning the code
/// spans for a `$`-followed-by-digit occurrence, and treating a bare `?` as a
/// placeholder only when none exists. That heuristic has a known gap --
/// [`rewrite_placeholders_indexed`]'s doc comment explains why, and is what
/// every owned call site now uses instead.
///
/// `?|`, `?&`, `?-`, `?-|`, `?||`, and `@?` are multi-character PostgreSQL
/// operators (JSONB key/path existence, geometric comparisons) that are
/// **never** valid placeholder syntax in any dialect this crate targets, so
/// [`rewrite_code_span_placeholders`] recognizes and skips them unconditionally
/// -- independent of the `$N` heuristic above, and correct even for a
/// zero-placeholder query that has no `$N` to anchor that heuristic on.
pub(crate) fn rewrite_pg_placeholders(sql: &str, formatter: impl Fn(u32) -> String) -> String {
    let spans = tokenize_sql(sql);
    let uses_dollar_placeholders = spans
        .iter()
        .any(|(kind, text)| *kind == SqlSpanKind::Code && code_span_has_dollar_number(text));

    let mut result = String::with_capacity(sql.len());
    let mut positional_counter: u32 = 0;
    let mut occurrences: Vec<u32> = Vec::new();
    for (kind, text) in &spans {
        if *kind == SqlSpanKind::Code {
            rewrite_code_span_placeholders(
                text,
                !uses_dollar_placeholders,
                &formatter,
                &mut positional_counter,
                &mut result,
                &mut occurrences,
            );
        } else {
            result.push_str(text);
        }
    }
    result
}

/// Whether `text` (a `Code`-span substring, guaranteed free of strings and
/// comments) contains a `$` immediately followed by an ASCII digit.
fn code_span_has_dollar_number(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    (0..chars.len()).any(|i| chars[i] == '$' && chars.get(i + 1).is_some_and(|c| c.is_ascii_digit()))
}

/// Multi-character PostgreSQL operators built on `?` or `@?` that are never
/// placeholder syntax in any dialect this crate targets -- JSONB key-array
/// existence (`?|`, `?&`) and jsonpath existence (`@?`), plus the geometric
/// comparison operators (`?-`, `?-|`, `?||`). Longer operators are listed
/// before the shorter operators they prefix (`?-|` before `?-`, `?||` before
/// `?|`) so the greedy match in [`match_unambiguous_operator`] picks the
/// longest one, not "the first two characters".
const UNAMBIGUOUS_OPERATORS: [&str; 6] = ["?-|", "?||", "?|", "?&", "?-", "@?"];

/// If `chars[i..]` starts with one of [`UNAMBIGUOUS_OPERATORS`], return its
/// length so the caller can copy it through untouched.
fn match_unambiguous_operator(chars: &[char], i: usize) -> Option<usize> {
    UNAMBIGUOUS_OPERATORS.iter().find_map(|op| {
        let op_chars: Vec<char> = op.chars().collect();
        let end = i + op_chars.len();
        (end <= chars.len() && chars[i..end] == op_chars[..]).then_some(op_chars.len())
    })
}

/// Rewrite `$N` and (when `bare_question_is_placeholder` is true) bare `?`
/// placeholders within a single `Code` span, appending the result to `out`,
/// advancing `counter` for each `?` consumed, and recording each rewritten
/// occurrence's resolved position (in output order) into `occurrences`.
///
/// Shared by [`rewrite_pg_placeholders`] (which computes
/// `bare_question_is_placeholder` from the `$N`-occurrence heuristic and
/// discards `occurrences`) and [`rewrite_placeholders_indexed`] (which
/// computes it from the dialect and returns `occurrences`) -- the actual
/// rewriting is one implementation; only how the two callers decide whether a
/// bare `?` counts differs. The multi-character operators in
/// [`UNAMBIGUOUS_OPERATORS`] have no such ambiguity and are always passed
/// through, regardless of `bare_question_is_placeholder`.
fn rewrite_code_span_placeholders(
    text: &str,
    bare_question_is_placeholder: bool,
    formatter: &impl Fn(u32) -> String,
    counter: &mut u32,
    out: &mut String,
    occurrences: &mut Vec<u32>,
) {
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    let mut i = 0;
    while i < len {
        if let Some(op_len) = match_unambiguous_operator(&chars, i) {
            out.extend(&chars[i..i + op_len]);
            i += op_len;
            continue;
        }

        let ch = chars[i];
        if ch == '$' && chars.get(i + 1).is_some_and(|c| c.is_ascii_digit()) {
            let mut j = i + 1;
            let mut num_str = String::new();
            while j < len && chars[j].is_ascii_digit() {
                num_str.push(chars[j]);
                j += 1;
            }
            let num: u32 = num_str.parse().unwrap_or(0);
            out.push_str(&formatter(num));
            occurrences.push(num);
            i = j;
        } else if ch == '?' && bare_question_is_placeholder && !chars.get(i + 1).is_some_and(|c| c.is_ascii_digit()) {
            *counter += 1;
            out.push_str(&formatter(*counter));
            occurrences.push(*counter);
            i += 1;
        } else {
            out.push(ch);
            i += 1;
        }
    }
}

/// Get a backend by name.
///
/// A backend whose language feature this build was compiled without is
/// rejected with an error naming that feature.
pub fn get_backend(name: &str) -> Result<Box<dyn CodegenBackend>, SqlkitError> {
    // Constructs a backend whose module `$feature` compiles in, or reports
    // the feature that would.
    macro_rules! backend {
        ($feature:literal, $construct:expr) => {{
            #[cfg(feature = $feature)]
            let backend: Result<Box<dyn CodegenBackend>, SqlkitError> =
                $construct.map(|backend| Box::new(backend) as Box<dyn CodegenBackend>);
            #[cfg(not(feature = $feature))]
            let backend: Result<Box<dyn CodegenBackend>, SqlkitError> =
                Err(disabled_feature(&format!("backend '{name}'"), $feature));
            backend?
        }};
    }

    let backend: Box<dyn CodegenBackend> = match name {
        "rust-sqlx" | "sqlx" | "rust" => backend!("lang-rust", sqlx::SqlxBackend::new()),
        "rust-tokio-postgres" | "tokio-postgres" => {
            backend!("lang-rust", tokio_postgres::TokioPostgresBackend::new())
        }
        "typescript-postgres" | "ts" | "typescript" => {
            backend!("lang-typescript", typescript_postgres::TypescriptPostgresBackend::new())
        }
        "javascript-postgres" => backend!(
            "lang-typescript",
            typescript_postgres::TypescriptPostgresBackend::new_js()
        ),
        "typescript-bun" => backend!(
            "lang-typescript",
            typescript_postgres::TypescriptPostgresBackend::new_bun()
        ),
        "javascript-bun" => backend!(
            "lang-typescript",
            typescript_postgres::TypescriptPostgresBackend::new_bun_js()
        ),
        _ => {
            return Err(SqlkitError::new(
                ErrorCode::InvalidConfig,
                format!("unknown backend: {}", name),
            ));
        }
    };

    Ok(backend)
}

/// The error for a backend left out of this build.
#[cfg(not(all(feature = "lang-rust", feature = "lang-typescript")))]
fn disabled_feature(subject: &str, feature: &str) -> SqlkitError {
    SqlkitError::new(
        ErrorCode::InvalidConfig,
        format!(
            "{subject} is not available in this build: it was compiled without the `{feature}` Cargo feature \
             (rebuild with `--features {feature}` or with default features)"
        ),
    )
}

/// Exact-value characterization tests for `clean_sql`, `clean_sql_oneline`,
/// and `rewrite_pg_placeholders`, kept in their own file so the pinned
/// behaviour is readable as a specification for the planned dialect-aware
/// tokenizer.
#[cfg(test)]
mod sql_text_characterization_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn param(name: &str, position: i64) -> AnalyzedParam {
        AnalyzedParam {
            constraints: None,
            base_column: None,
            name: name.to_string(),
            neutral_type: "string".to_string(),
            nullable: true,
            position,
            source_relation: None,
        }
    }

    /// Structural guard for #82: no source file under `src/backends` may
    /// reference a manifest path relative to the process working directory,
    /// however that reference is spelled. This catches a reintroduction of
    /// the filesystem-lookup pattern written differently from the original
    /// (different variable names, a helper function, etc.) that a simple
    /// function-name grep for the old `load_or_default_manifest` helper would
    /// miss.
    ///
    /// The forbidden needle is built at runtime, not written as a literal
    /// here, so this check does not trip over its own source describing what
    /// it looks for.
    #[test]
    fn test_no_backends_relative_manifest_path_literals() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/src/backends");
        let word: String = format!("backend{}", "s/");
        let needle: String = format!("{}{}", '"', word);

        let mut offenders = Vec::new();
        collect_rs_files(std::path::Path::new(root), &mut offenders);

        let offenders: Vec<_> = offenders
            .into_iter()
            .filter(|path| {
                let contents = std::fs::read_to_string(path).expect("failed to read source file");
                contents.contains(&needle)
            })
            .collect();

        assert!(
            offenders.is_empty(),
            "found a working-directory-relative manifest path literal in: {offenders:?} (#82 regression \
             -- manifest selection must be a pure function of the backend, no filesystem lookup)"
        );
    }

    /// Recursively collect every `.rs` file path under `dir`.
    fn collect_rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let entries = std::fs::read_dir(dir).expect("failed to read backends dir");
        for entry in entries {
            let entry = entry.expect("failed to read dir entry");
            let path = entry.path();
            if path.is_dir() {
                collect_rs_files(&path, out);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }

    #[cfg(not(feature = "lang-typescript"))]
    #[test]
    fn get_backend_names_the_language_feature_a_disabled_backend_needs() {
        let error = get_backend("typescript-bun")
            .err()
            .expect("typescript-bun is not compiled in");
        assert_eq!(error.code, ErrorCode::InvalidConfig);
        assert!(
            error.to_string().contains(
                "backend 'typescript-bun' is not available in this build: it was compiled without the `lang-typescript`"
            ),
            "{error}"
        );
    }

    #[test]
    fn test_rewrite_simple_equality() {
        let sql = "SELECT * FROM users WHERE status = $1";
        let params = vec![param("status", 1)];
        let result = rewrite_optional_params(sql, &["status".to_string()], &params);
        assert_eq!(result, "SELECT * FROM users WHERE ($1 IS NULL OR status = $1)");
    }

    #[test]
    fn test_rewrite_qualified_column() {
        let sql = "SELECT * FROM users u WHERE u.status = $1";
        let params = vec![param("status", 1)];
        let result = rewrite_optional_params(sql, &["status".to_string()], &params);
        assert_eq!(result, "SELECT * FROM users u WHERE ($1 IS NULL OR u.status = $1)");
    }

    #[test]
    fn test_rewrite_multiple_optional() {
        let sql = "SELECT * FROM users WHERE status = $1 AND name = $2";
        let params = vec![param("status", 1), param("name", 2)];
        let result = rewrite_optional_params(sql, &["status".to_string(), "name".to_string()], &params);
        assert_eq!(
            result,
            "SELECT * FROM users WHERE ($1 IS NULL OR status = $1) AND ($2 IS NULL OR name = $2)"
        );
    }

    #[test]
    fn test_rewrite_mixed_optional_required() {
        let sql = "SELECT * FROM users WHERE id = $1 AND status = $2";
        let params = vec![param("id", 1), param("status", 2)];
        let result = rewrite_optional_params(sql, &["status".to_string()], &params);
        assert_eq!(
            result,
            "SELECT * FROM users WHERE id = $1 AND ($2 IS NULL OR status = $2)"
        );
    }

    #[test]
    fn test_rewrite_like_operator() {
        let sql = "SELECT * FROM users WHERE name LIKE $1";
        let params = vec![param("name", 1)];
        let result = rewrite_optional_params(sql, &["name".to_string()], &params);
        assert_eq!(result, "SELECT * FROM users WHERE ($1 IS NULL OR name LIKE $1)");
    }

    #[test]
    fn test_rewrite_ilike_operator() {
        let sql = "SELECT * FROM users WHERE name ILIKE $1";
        let params = vec![param("name", 1)];
        let result = rewrite_optional_params(sql, &["name".to_string()], &params);
        assert_eq!(result, "SELECT * FROM users WHERE ($1 IS NULL OR name ILIKE $1)");
    }

    #[test]
    fn test_rewrite_comparison_operators() {
        let sql = "SELECT * FROM users WHERE age >= $1";
        let params = vec![param("age", 1)];
        let result = rewrite_optional_params(sql, &["age".to_string()], &params);
        assert_eq!(result, "SELECT * FROM users WHERE ($1 IS NULL OR age >= $1)");
    }

    #[test]
    fn test_rewrite_less_than() {
        let sql = "SELECT * FROM users WHERE age < $1";
        let params = vec![param("age", 1)];
        let result = rewrite_optional_params(sql, &["age".to_string()], &params);
        assert_eq!(result, "SELECT * FROM users WHERE ($1 IS NULL OR age < $1)");
    }

    #[test]
    fn test_no_rewrite_without_optional() {
        let sql = "SELECT * FROM users WHERE status = $1";
        let params = vec![param("status", 1)];
        let result = rewrite_optional_params(sql, &[], &params);
        assert_eq!(result, sql);
    }

    #[test]
    fn test_rewrite_not_equal() {
        let sql = "SELECT * FROM users WHERE status <> $1";
        let params = vec![param("status", 1)];
        let result = rewrite_optional_params(sql, &["status".to_string()], &params);
        assert_eq!(result, "SELECT * FROM users WHERE ($1 IS NULL OR status <> $1)");
    }

    #[test]
    fn test_rewrite_does_not_match_similar_placeholder() {
        let sql = "SELECT * FROM users WHERE status = $10";
        let params = vec![param("status", 1)];
        let result = rewrite_optional_params(sql, &["status".to_string()], &params);
        assert_eq!(result, sql);
    }

    // -----------------------------------------------------------------
    // SQL lexer / rewriting tests (board #148, #186, #149-adjacent).
    //
    // These pin down the behaviour of `clean_sql`, `clean_sql_oneline`, and
    // `rewrite_pg_placeholders` against a real SQL lexer instead of the
    // character-scanning implementation these functions previously had.
    // Written before the lexer existed, to prove each defect is real.
    // -----------------------------------------------------------------

    #[test]
    fn test_clean_sql_strips_mid_line_comment_but_keeps_rest_of_query() {
        let sql = "SELECT id\nFROM users\nWHERE id > $1 -- skip low ids\nAND active = true;";
        let result = clean_sql(sql);
        assert!(result.contains("AND active = true"), "got: {result:?}");
        assert!(!result.contains("--"), "got: {result:?}");
    }

    #[test]
    fn test_clean_sql_drops_lines_that_are_only_a_header_comment() {
        // Regression guard: header comment lines (`-- @name ...`) must be
        // deleted entirely, not replaced by a blank line -- every generated
        // fixture depends on this.
        let sql = "-- @name Foo\n-- @returns :many\nSELECT id FROM t WHERE id = $1;";
        let result = clean_sql(sql);
        assert_eq!(result, "SELECT id FROM t WHERE id = $1");
    }

    #[test]
    fn test_rewrite_pg_placeholders_preserves_dollar_quoted_body() {
        let sql =
            "SELECT id FROM t WHERE body = $$literal -- not comment, ' quote, $1 not a placeholder$$ AND id = $2;";
        let result = rewrite_pg_placeholders(sql, |n| format!("@p{n}"));
        assert!(
            result.contains("$$literal -- not comment, ' quote, $1 not a placeholder$$"),
            "dollar-quoted body must survive untouched, got: {result:?}"
        );
        assert!(result.contains("id = @p2"), "got: {result:?}");
    }

    #[test]
    fn test_rewrite_pg_placeholders_handles_escaped_single_quotes() {
        let sql = "SELECT id FROM t WHERE label = 'it''s $1 not a placeholder' AND id = $2;";
        let result = rewrite_pg_placeholders(sql, |n| format!("@p{n}"));
        assert!(result.contains("'it''s $1 not a placeholder'"), "got: {result:?}");
        assert!(result.contains("id = @p2"), "got: {result:?}");
    }

    #[test]
    fn test_rewrite_pg_placeholders_preserves_jsonb_operators() {
        let sql = "SELECT id FROM docs WHERE data ? 'mykey' AND tags ?| array['a','b'] AND tags ?& array['a','b'] AND id = $1;";
        let result = rewrite_pg_placeholders(sql, |n| format!("@p{n}"));
        assert!(result.contains("data ? 'mykey'"), "got: {result:?}");
        assert!(result.contains("tags ?| array"), "got: {result:?}");
        assert!(result.contains("tags ?& array"), "got: {result:?}");
        assert!(result.contains("id = @p1"), "got: {result:?}");
    }

    /// Coordinator repro: a JSONB query with *zero* `$N` placeholders, so the
    /// `uses_dollar_placeholders` heuristic has nothing to anchor on. `?|`
    /// and `?&` are unambiguous -- never placeholder syntax in any dialect
    /// this crate targets -- so they must survive regardless of that
    /// heuristic. The bare `?` (`data ? 'active'`) is genuinely ambiguous
    /// without dialect information and is intentionally still rewritten
    /// here; see the residual-limitation comment on
    /// `rewrite_code_span_placeholders`.
    #[test]
    fn test_rewrite_pg_placeholders_preserves_jsonb_multi_char_operators_with_zero_dollar_placeholders() {
        let sql = "SELECT * FROM docs WHERE data ? 'active' AND tags ?| ARRAY['a'] AND meta ?& ARRAY['b']";
        let result = rewrite_pg_placeholders(sql, |n| format!("${n}"));
        assert!(result.contains("tags ?| ARRAY['a']"), "got: {result:?}");
        assert!(result.contains("meta ?& ARRAY['b']"), "got: {result:?}");
    }

    #[test]
    fn test_rewrite_pg_placeholders_preserves_geometry_operators() {
        let sql = "SELECT id FROM shapes WHERE line1 ?- line2 AND line1 ?-| line2 AND line1 ?|| line2 AND id = $1;";
        let result = rewrite_pg_placeholders(sql, |n| format!("@p{n}"));
        assert!(result.contains("line1 ?- line2"), "got: {result:?}");
        assert!(result.contains("line1 ?-| line2"), "got: {result:?}");
        assert!(result.contains("line1 ?|| line2"), "got: {result:?}");
        assert!(result.contains("id = @p1"), "got: {result:?}");
    }

    #[test]
    fn test_rewrite_pg_placeholders_preserves_operators_mixed_with_dollar_placeholder() {
        let sql = "SELECT id FROM docs WHERE tags ?| ARRAY['a'] AND doc @? '$.a' AND id = $1;";
        let result = rewrite_pg_placeholders(sql, |n| format!("@p{n}"));
        assert!(result.contains("tags ?| ARRAY['a']"), "got: {result:?}");
        assert!(result.contains("doc @? '$.a'"), "got: {result:?}");
        assert!(result.contains("id = @p1"), "got: {result:?}");
    }

    #[test]
    fn test_rewrite_pg_placeholders_number_boundary() {
        let sql = "SELECT $1, $10, $1x";
        let result = rewrite_pg_placeholders(sql, |n| format!("P{n}"));
        assert_eq!(result, "SELECT P1, P10, P1x");
    }

    #[test]
    fn test_rewrite_pg_placeholders_ignores_question_mark_inside_string_literal() {
        let sql = "SELECT id FROM t WHERE note = 'is this a question?' AND age > ?;";
        let result = rewrite_pg_placeholders(sql, |n| format!("${n}"));
        assert!(result.contains("'is this a question?'"), "got: {result:?}");
        assert!(result.contains("age > $1"), "got: {result:?}");
    }

    #[test]
    fn test_clean_sql_handles_crlf_line_endings() {
        let sql = "SELECT id\r\nFROM users\r\n-- a comment\r\nWHERE id = $1;";
        let result = clean_sql(sql);
        assert!(!result.contains('\r'), "got: {result:?}");
        assert!(!result.contains("-- a comment"), "got: {result:?}");
        assert_eq!(result, "SELECT id\nFROM users\nWHERE id = $1");
    }

    #[test]
    fn test_rewrite_optional_params_handles_not_like() {
        let sql = "SELECT id FROM t WHERE name NOT LIKE $1";
        let params = vec![param("name", 1)];
        let result = rewrite_optional_params(sql, &["name".to_string()], &params);
        assert_eq!(result, "SELECT id FROM t WHERE ($1 IS NULL OR name NOT LIKE $1)");
    }

    /// PostgreSQL's `#>`/`#>>` JSON operators are not comments.
    #[test]
    fn test_clean_sql_hash_is_not_a_comment() {
        let sql = "SELECT data #> '{a,b}' AS x FROM t";
        assert_eq!(clean_sql(sql), sql);
    }
}
