//! Splitting a SQL file into the statements `sqlkit audit` examines.
//!
//! Every statement keeps its position in the source -- its 1-based starting
//! line for reporting and the byte offset of its first token for looking up
//! [`SuppressionSet`](super::SuppressionSet) annotations. Positions, unlike
//! statement indices, cannot drift: a statement that fails to parse, an empty
//! statement (`;;`) or a `;` inside a string or comment leaves every other
//! statement's position where it is.

use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;
use sqlparser::tokenizer::{Location, Token, Tokenizer};

/// One statement [`parse_statements_lenient`] parsed.
#[derive(Debug)]
pub struct ParsedStatement {
    pub stmt: sqlparser::ast::Statement,
    /// 1-based line of the statement's first token.
    pub line: usize,
    /// Byte offset in the parsed SQL of the statement's first token.
    pub offset: usize,
}

/// One statement [`parse_statements_lenient`] could not parse: its 1-based
/// starting line and the parser's error message.
#[derive(Debug)]
pub struct StatementParseFailure {
    pub line: usize,
    pub message: String,
}

/// The byte offset in `sql` of a tokenizer location (1-based line, 1-based
/// column counted in characters), clamped to `sql.len()`.
fn byte_offset(sql: &str, location: Location) -> usize {
    let line_start = if location.line <= 1 {
        0
    } else {
        sql.match_indices('\n')
            .nth(location.line as usize - 2)
            .map_or(sql.len(), |(index, _)| index + 1)
    };
    sql[line_start..]
        .char_indices()
        .nth((location.column as usize).saturating_sub(1))
        .map_or(sql.len(), |(index, _)| line_start + index)
}

/// The byte offset of the first token in `sql` that is not whitespace or a
/// comment -- where a single-statement block's statement starts -- or `None`
/// when `sql` has no such token or does not tokenize.
pub fn first_token_offset(sql: &str) -> Option<usize> {
    let tokens = Tokenizer::new(&PostgreSqlDialect {}, sql)
        .tokenize_with_location()
        .ok()?;
    tokens
        .iter()
        .find(|t| !matches!(t.token, Token::Whitespace(_)))
        .map(|t| byte_offset(sql, t.span.start))
}

/// Parse `sql` into individual statements, recovering from a parse error on
/// one statement by skipping to the next top-level `;` (or EOF) and
/// continuing, instead of discarding every statement already parsed.
///
/// [`Parser::parse_sql`] parses the whole input as one unit and fails on the
/// first unparseable statement, taking every statement before it down too.
/// For `sqlkit audit`, that meant a single statement using SQL syntax the
/// parser does not yet support silently disabled every finding in the rest
/// of the file. See issue #208.
///
/// Each statement's position is read from the token span at the point
/// `parse_statement` was called, so it stays correct even when earlier
/// statements were skipped.
pub fn parse_statements_lenient(sql: &str) -> (Vec<ParsedStatement>, Vec<StatementParseFailure>) {
    let mut parser = match Parser::new(&PostgreSqlDialect {}).try_with_sql(sql) {
        Ok(p) => p,
        Err(e) => {
            return (
                Vec::new(),
                vec![StatementParseFailure {
                    line: 1,
                    message: e.to_string(),
                }],
            );
        }
    };

    let mut statements = Vec::new();
    let mut failures = Vec::new();

    loop {
        while parser.consume_token(&Token::SemiColon) {}
        if matches!(parser.peek_token_ref().token, Token::EOF) {
            break;
        }

        let start = parser.peek_token_ref().span.start;
        let line = (start.line as usize).max(1);
        let offset = byte_offset(sql, start);

        // A statement only parsed if the parser stopped at its end: sqlparser
        // can accept a prefix (`INSERT ... SELECT x` before `ON CONFLICT`)
        // and leave the rest to be misread as the next statement.
        let parsed =
            parser
                .parse_statement()
                .map_err(|e| e.to_string())
                .and_then(|stmt| match &parser.peek_token_ref().token {
                    Token::EOF | Token::SemiColon => Ok(stmt),
                    token => Err(format!(
                        "sql parser error: unexpected {token} after a complete statement"
                    )),
                });
        match parsed {
            Ok(stmt) => statements.push(ParsedStatement { stmt, line, offset }),
            Err(message) => {
                // Recover by skipping to the next top-level `;` (or EOF) so
                // the statements after this one still get a chance to parse
                // and be audited, rather than aborting the whole file.
                loop {
                    match parser.peek_token_ref().token {
                        Token::EOF | Token::SemiColon => break,
                        _ => {
                            parser.next_token();
                        }
                    }
                }
                // The statement may use PostgreSQL syntax sqlparser cannot
                // read directly (e.g. `INSERT ... SELECT ... ON CONFLICT`):
                // retry it alone through the same rewrites `parse_query`
                // applies, so audit and the analyzer agree on what parses.
                let end = match parser.peek_token_ref().token {
                    Token::EOF => sql.len(),
                    _ => byte_offset(sql, parser.peek_token_ref().span.start),
                };
                let text = &sql[offset.min(end)..end];
                let rewritten = sqlkit_core::parser::rewrite_for_sqlparser(text);
                match Parser::parse_sql(&PostgreSqlDialect {}, &rewritten) {
                    Ok(mut parsed) if parsed.len() == 1 => statements.push(ParsedStatement {
                        stmt: parsed.remove(0),
                        line,
                        offset,
                    }),
                    _ => failures.push(StatementParseFailure { line, message }),
                }
            }
        }
    }

    (statements, failures)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// sqlparser accepts `INSERT ... SELECT x` and stops before
    /// `ON CONFLICT`; the statement must still be audited whole, through the
    /// rewrites `parse_query` applies, not split into a parsed prefix and an
    /// unparseable `CONFLICT ...` remainder.
    #[test]
    fn insert_select_on_conflict_parses_as_one_statement() {
        let sql = "INSERT INTO t (a, b)\nSELECT $1, unnest($2::text[])\nON CONFLICT DO NOTHING;\n\nDELETE FROM t WHERE a = $1;\n";
        let (statements, failures) = parse_statements_lenient(sql);
        assert!(
            failures.is_empty(),
            "unexpected failures: {:?}",
            failures.iter().map(|f| &f.message).collect::<Vec<_>>()
        );
        assert_eq!(statements.len(), 2);
        assert_eq!(statements[0].line, 1);
        assert_eq!(statements[1].line, 5);
        assert_eq!(&sql[statements[1].offset..][..6], "DELETE");
    }

    /// A statement that no rewrite rescues is still reported, at its own
    /// line, and the statements around it are still parsed.
    #[test]
    fn unparseable_statement_is_reported_and_skipped() {
        let sql = "SELECT 1;\nNOT A STATEMENT;\nSELECT 2;\n";
        let (statements, failures) = parse_statements_lenient(sql);
        assert_eq!(statements.len(), 2);
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].line, 2);
    }

    #[test]
    fn offsets_point_at_each_statements_first_token() {
        let sql = "SELECT ';';; SELECT 2;\n  /* c */ SELECT 3;";
        let (statements, _) = parse_statements_lenient(sql);
        let starts: Vec<&str> = statements.iter().map(|s| &sql[s.offset..s.offset + 8]).collect();
        assert_eq!(starts, ["SELECT '", "SELECT 2", "SELECT 3"]);
    }

    #[test]
    fn first_token_offset_skips_comments_and_whitespace() {
        let sql = "-- name: q\n-- note\n\n  SELECT 1";
        assert_eq!(first_token_offset(sql), sql.find("SELECT"));
        assert_eq!(first_token_offset("-- only a comment\n"), None);
    }
}
