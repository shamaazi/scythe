use sqlparser::parser::Parser;

use crate::dialect::SqlDialect;
use crate::errors::SqlkitError;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum QueryCommand {
    One,
    Opt,
    Many,
    #[default]
    Exec,
    ExecResult,
    ExecRows,
    Batch,
    Grouped,
}

impl std::fmt::Display for QueryCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryCommand::One => write!(f, "one"),
            QueryCommand::Opt => write!(f, "opt"),
            QueryCommand::Many => write!(f, "many"),
            QueryCommand::Exec => write!(f, "exec"),
            QueryCommand::ExecResult => write!(f, "exec_result"),
            QueryCommand::ExecRows => write!(f, "exec_rows"),
            QueryCommand::Batch => write!(f, "batch"),
            QueryCommand::Grouped => write!(f, "grouped"),
        }
    }
}

impl QueryCommand {
    fn from_str(s: &str) -> Result<Self, SqlkitError> {
        match s {
            "one" => Ok(QueryCommand::One),
            "opt" => Ok(QueryCommand::Opt),
            "many" => Ok(QueryCommand::Many),
            "exec" => Ok(QueryCommand::Exec),
            "exec_result" => Ok(QueryCommand::ExecResult),
            "exec_rows" => Ok(QueryCommand::ExecRows),
            "batch" => Ok(QueryCommand::Batch),
            "grouped" => Ok(QueryCommand::Grouped),
            other => Err(SqlkitError::invalid_annotation(format!(
                "invalid @returns value: {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ParamDoc {
    pub name: String,
    pub description: String,
}

/// A name bound to a parameter position, overriding the name the analyzer
/// would otherwise infer (or its `pN` fallback).
///
/// Written `-- @param $N name[?][: description]`, which may name any subset
/// of the parameters. The positional form (`$N` as first token) is distinct
/// from the docs-only `-- @param name: description` form, which is preserved
/// unchanged for backward compatibility. A trailing `?` on the name marks the
/// parameter as accepting NULL.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PositionalParamDoc {
    /// 1-based parameter position (`$N`).
    pub position: i64,
    /// Caller-chosen name that replaces the inferred or `pN` name.
    pub name: String,
    /// Optional description (everything after the `:` separator).
    pub description: String,
    /// The name carried a trailing `?`: the parameter accepts NULL even when
    /// the analyzer infers it as non-null.
    #[cfg_attr(feature = "serde", serde(default))]
    pub nullable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct JsonMapping {
    pub column: String,
    pub rust_type: String,
}

/// A custom (non-native) annotation captured verbatim from the SQL source.
///
/// Sqlkit parses its known annotations (`@name`, `@returns`, `@param`, `@nullable`,
/// `@nonnull`, `@json`, `@optional`, `@group_by`, `@deprecated`) into typed fields.
/// Any other `-- @<name> <value>` line is captured here as an opaque triple and
/// exposed to crate consumers, who can layer their own annotation vocabulary on
/// top of sqlkit without coupling sqlkit to their domain.
///
/// That escape hatch means an unrecognised annotation can never be a hard parse
/// error -- rejecting it outright would break every legitimate consumer-defined
/// annotation (e.g. `@http`, `@http_auth`) alongside the typos it was meant to
/// catch. [`suggested_keyword`](Self::suggested_keyword) is the softer signal:
/// it flags names close enough to a known keyword to plausibly be a typo of it
/// (`@nullible` for `@nullable`, `@optionall` for `@optional`), for a caller to
/// surface as a warning without duplicating sqlkit's keyword list or edit-distance
/// logic. See #152 -- before this field existed, a misspelled `@nullable` /
/// `@nonnull` / `@optional` was captured here and never inspected by anything,
/// so `sqlkit generate`, `sqlkit check` and `sqlkit lint` all reported success
/// while the override it named was silently discarded.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CustomAnnotation {
    /// Annotation name, lowercased, without the leading `@` (e.g. `http`, `http_param`).
    pub name: String,
    /// Everything after the name on the line, trimmed. Empty if the annotation had no value.
    pub value: String,
    /// 1-based line number within the query SQL, for diagnostics.
    pub line: usize,
    /// A known annotation keyword within edit distance 2 of `name`, if any -- e.g.
    /// `Some("nullable".to_string())` for `nullible`. `None` when `name` is not close to
    /// any known keyword (the common case: a genuine consumer-defined annotation). An owned
    /// `String` rather than `&'static str` so the type stays trivially `Deserialize` (a
    /// borrowed-forever `&'static str` field cannot round-trip through an arbitrary
    /// deserializer's input lifetime).
    #[cfg_attr(feature = "serde", serde(default))]
    pub suggested_keyword: Option<String>,
}

/// The annotation keywords [`parse_query_with_dialect`] recognises natively. Anything else
/// becomes a [`CustomAnnotation`]; [`suggest_known_keyword`] checks a rejected name against
/// this list to flag likely typos.
const KNOWN_ANNOTATION_KEYWORDS: &[&str] = &[
    "name",
    "returns",
    "param",
    "nullable",
    "nonnull",
    "json",
    "deprecated",
    "group_by",
    "optional",
];

/// Maximum Levenshtein edit distance at which an unrecognised annotation name is flagged as a
/// likely typo of a known keyword. Matches the threshold `sqlkit-codegen::backend_options` and
/// `sqlkit-backend::manifest` already use for "did you mean" suggestions on unknown option/type
/// keys -- close enough to catch `nullible` -> `nullable` or `optionall` -> `optional` without
/// false-positiving on a genuinely unrelated custom annotation name.
const ANNOTATION_TYPO_DISTANCE_THRESHOLD: usize = 2;

/// Suggest a known annotation keyword for an unrecognised annotation `name`, if one is within
/// [`ANNOTATION_TYPO_DISTANCE_THRESHOLD`] edits.
fn suggest_known_keyword(name: &str) -> Option<&'static str> {
    KNOWN_ANNOTATION_KEYWORDS
        .iter()
        .map(|&candidate| (candidate, annotation_levenshtein_distance(name, candidate)))
        .filter(|&(_, distance)| distance <= ANNOTATION_TYPO_DISTANCE_THRESHOLD)
        .min_by_key(|&(_, distance)| distance)
        .map(|(candidate, _)| candidate)
}

/// Levenshtein edit distance between two strings, used by [`suggest_known_keyword`].
fn annotation_levenshtein_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();

    let mut prev_row: Vec<usize> = (0..=b.len()).collect();
    let mut curr_row = vec![0usize; b.len() + 1];

    for (i, &char_a) in a.iter().enumerate() {
        curr_row[0] = i + 1;
        for (j, &char_b) in b.iter().enumerate() {
            let substitution_cost = usize::from(char_a != char_b);
            curr_row[j + 1] = (prev_row[j + 1] + 1)
                .min(curr_row[j] + 1)
                .min(prev_row[j] + substitution_cost);
        }
        std::mem::swap(&mut prev_row, &mut curr_row);
    }

    prev_row[b.len()]
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Annotations {
    pub name: String,
    pub command: QueryCommand,
    pub param_docs: Vec<ParamDoc>,
    pub nullable_overrides: Vec<String>,
    pub nonnull_overrides: Vec<String>,
    pub json_mappings: Vec<JsonMapping>,
    pub deprecated: Option<String>,
    pub optional_params: Vec<String>,
    pub group_by: Option<String>,
    /// Explicit `-- @param $N name[: description]` annotations that override
    /// the inferred or fallback `pN` name for a specific positional parameter.
    #[cfg_attr(feature = "serde", serde(default))]
    pub positional_param_docs: Vec<PositionalParamDoc>,
    /// Free text from the plain `--` comment lines of the query header (the
    /// lines before the first SQL line), joined with `\n`; `None` when the
    /// header has none. Generators render it as the query function's doc
    /// comment. The comment lines themselves stay in the query's SQL text.
    #[cfg_attr(feature = "serde", serde(default))]
    pub description: Option<String>,
    /// Annotations sqlkit does not natively recognise, preserved in source order
    /// for crate consumers to interpret.
    pub custom: Vec<CustomAnnotation>,
}

#[derive(Debug)]
pub struct Query {
    pub name: String,
    pub command: QueryCommand,
    pub sql: String,
    pub stmt: sqlparser::ast::Statement,
    pub annotations: Annotations,
}

/// Reject an `@name` value that cannot become an identifier in generated
/// code.
///
/// Every backend uses this value verbatim (after case conversion) as the
/// generated function's name and as the stem of its row type, so anything
/// that is not an identifier produces a file that does not compile -- and
/// says so nowhere. `-- @name` with no value was accepted outright until
/// #174: it emitted `async def (conn):` in Python and collapsed the row type
/// to a bare `Row` that collides with every other unnamed query in the file,
/// at exit code 0.
///
/// The accepted set is deliberately the intersection every target language
/// can spell: an ASCII letter or `_` followed by ASCII letters, digits and
/// `_`. A dot, dash, space or quote in the value is a mistake in every one of
/// them.
fn validate_query_name(name: &str) -> Result<(), SqlkitError> {
    if name.is_empty() {
        return Err(SqlkitError::invalid_annotation(
            "@name requires a value (e.g. `-- @name GetUser`)",
        ));
    }

    let mut chars = name.chars();
    let first = chars.next().expect("name is non-empty");
    if !first.is_ascii_alphabetic() && first != '_' {
        return Err(SqlkitError::invalid_annotation(format!(
            "@name \"{name}\" must start with an ASCII letter or underscore to be a valid \
             identifier in generated code"
        )));
    }
    if let Some(invalid) = chars.find(|c| !c.is_ascii_alphanumeric() && *c != '_') {
        return Err(SqlkitError::invalid_annotation(format!(
            "@name \"{name}\" contains '{invalid}'; only ASCII letters, digits and underscores \
             are valid in generated code"
        )));
    }

    Ok(())
}

/// Reject a parameter position named more than once: which name won would
/// otherwise depend on line order.
fn reject_duplicate_param_names(query_name: &str, docs: &[PositionalParamDoc]) -> Result<(), SqlkitError> {
    for (index, doc) in docs.iter().enumerate() {
        if let Some(earlier) = docs[..index].iter().find(|earlier| earlier.position == doc.position) {
            return Err(SqlkitError::invalid_annotation(format!(
                "query \"{query_name}\": ${} is named twice (`{}` and `{}`); name each parameter once",
                doc.position, earlier.name, doc.name
            )));
        }
    }
    Ok(())
}

/// Join a query header's comment lines into its description. Blank lines at
/// either end are dropped and a run of blank lines inside collapses to one,
/// so paragraphs survive but stray spacing does not.
fn query_description(lines: &[&str]) -> Option<String> {
    let mut kept: Vec<&str> = Vec::new();
    for &line in lines {
        if line.is_empty() && kept.last().is_none_or(|last| last.is_empty()) {
            continue;
        }
        kept.push(line);
    }
    while kept.last().is_some_and(|last| last.is_empty()) {
        kept.pop();
    }
    (!kept.is_empty()).then(|| kept.join("\n"))
}

/// Parse a single annotated SQL query into a `Query` using the PostgreSQL dialect.
pub fn parse_query(query_sql: &str) -> Result<Query, SqlkitError> {
    parse_query_with_dialect(query_sql, &SqlDialect::PostgreSQL)
}

/// Parse a single annotated SQL query into a `Query` using the specified dialect.
pub fn parse_query_with_dialect(query_sql: &str, dialect: &SqlDialect) -> Result<Query, SqlkitError> {
    let mut name: Option<String> = None;
    let mut command: Option<QueryCommand> = None;
    let mut param_docs = Vec::new();
    let mut positional_param_docs: Vec<PositionalParamDoc> = Vec::new();
    let mut nullable_overrides = Vec::new();
    let mut nonnull_overrides = Vec::new();
    let mut json_mappings = Vec::new();
    let mut deprecated: Option<String> = None;
    let mut optional_params = Vec::new();
    let mut group_by: Option<String> = None;
    let mut custom: Vec<CustomAnnotation> = Vec::new();
    // Plain comment lines seen before the first SQL line, i.e. the header.
    let mut description_lines: Vec<&str> = Vec::new();
    let mut in_header = true;

    let mut sql_lines = Vec::new();

    for (line_idx, line) in query_sql.lines().enumerate() {
        let line_no = line_idx + 1;
        let trimmed = line.trim();

        let annotation_body = trimmed
            .strip_prefix("--")
            .and_then(|rest| rest.trim_start().strip_prefix('@'));

        if let Some(body) = annotation_body {
            let (keyword, value) = match body.find(|c: char| c.is_whitespace()) {
                Some(pos) => (&body[..pos], body[pos..].trim()),
                None => (body, ""),
            };

            match keyword.to_ascii_lowercase().as_str() {
                "name" => {
                    name = Some(value.to_string());
                }
                "returns" => {
                    let cmd_str = value.strip_prefix(':').unwrap_or(value);
                    command = Some(QueryCommand::from_str(cmd_str)?);
                }
                "param" => {
                    //   Positional: -- @param $N name[: description]
                    //   Docs-only:  -- @param name[: description]
                    let first_end = value.find(|c: char| c.is_whitespace());
                    let first_token = first_end.map(|p| &value[..p]).unwrap_or(value);

                    if let Some(digits) = first_token.strip_prefix('$')
                        && let Ok(pos) = digits.parse::<i64>()
                        && pos > 0
                    {
                        let rest = first_end.map(|p| value[p..].trim()).unwrap_or("").trim();
                        if !rest.is_empty() {
                            let (param_name, description) = match rest.split_once(':') {
                                Some((param_name, description)) => (param_name.trim(), description.trim()),
                                None => (rest, ""),
                            };
                            let (param_name, nullable) = match param_name.strip_suffix('?') {
                                Some(param_name) => (param_name.trim_end(), true),
                                None => (param_name, false),
                            };
                            if !param_name.is_empty() {
                                positional_param_docs.push(PositionalParamDoc {
                                    position: pos,
                                    name: param_name.to_string(),
                                    description: description.to_string(),
                                    nullable,
                                });
                            }
                        }
                    } else {
                        if let Some(colon_pos) = value.find(':') {
                            let param_name = value[..colon_pos].trim().to_string();
                            let description = value[colon_pos + 1..].trim().to_string();
                            param_docs.push(ParamDoc {
                                name: param_name,
                                description,
                            });
                        } else {
                            param_docs.push(ParamDoc {
                                name: value.to_string(),
                                description: String::new(),
                            });
                        }
                    }
                }
                "nullable" => {
                    for col in value.split(',') {
                        let col = col.trim();
                        if !col.is_empty() {
                            nullable_overrides.push(col.to_string());
                        }
                    }
                }
                "nonnull" => {
                    for col in value.split(',') {
                        let col = col.trim();
                        if !col.is_empty() {
                            nonnull_overrides.push(col.to_string());
                        }
                    }
                }
                "json" => {
                    if let Some(eq_pos) = value.find('=') {
                        let column = value[..eq_pos].trim().to_string();
                        let rust_type = value[eq_pos + 1..].trim().to_string();
                        json_mappings.push(JsonMapping { column, rust_type });
                    }
                }
                "deprecated" => {
                    deprecated = Some(value.to_string());
                }
                "group_by" => {
                    group_by = Some(value.to_string());
                }
                "optional" => {
                    for param in value.split(',') {
                        let param = param.trim();
                        if !param.is_empty() {
                            optional_params.push(param.to_string());
                        }
                    }
                }
                other => {
                    custom.push(CustomAnnotation {
                        name: other.to_string(),
                        value: value.to_string(),
                        line: line_no,
                        suggested_keyword: suggest_known_keyword(other).map(str::to_string),
                    });
                }
            }
        } else {
            if in_header {
                if let Some(comment) = trimmed.strip_prefix("--") {
                    let comment = comment.strip_prefix(' ').unwrap_or(comment);
                    description_lines.push(comment.trim_end());
                } else if trimmed.is_empty() {
                    description_lines.push("");
                } else {
                    in_header = false;
                }
            }
            sql_lines.push(line);
        }
    }
    let description = query_description(&description_lines);

    let name = name.ok_or_else(|| SqlkitError::missing_annotation("name"))?;
    validate_query_name(&name)?;
    reject_duplicate_param_names(&name, &positional_param_docs)?;
    let command = command.ok_or_else(|| SqlkitError::missing_annotation("returns"))?;

    if command == QueryCommand::Grouped && group_by.is_none() {
        return Err(SqlkitError::invalid_annotation(
            "@returns :grouped requires a @group_by annotation (e.g. @group_by users.id)",
        ));
    }

    let sql = sql_lines.join("\n").trim().to_string();

    if sql.is_empty() {
        return Err(SqlkitError::syntax("empty SQL body"));
    }

    let parse_sql =
        spell_out_default_trim_characters(&end_select_list_before_on_conflict(&preprocess_postgres_sql(&sql)));

    let parser_dialect = dialect.to_sqlparser_dialect();
    let statements = Parser::parse_sql(parser_dialect.as_ref(), &parse_sql)
        .map_err(|e| SqlkitError::syntax(format!("syntax error: {}", e)))?;

    if statements.len() != 1 {
        let non_empty: Vec<_> = statements
            .into_iter()
            .filter(|s| !matches!(s, sqlparser::ast::Statement::Flush { .. }) && format!("{s}") != "")
            .collect();
        if non_empty.len() != 1 {
            return Err(SqlkitError::syntax("expected exactly one SQL statement"));
        }
        let stmt = non_empty.into_iter().next().expect("filtered to exactly one statement");
        let annotations = Annotations {
            name: name.clone(),
            command: command.clone(),
            param_docs,
            positional_param_docs: positional_param_docs.clone(),
            description: description.clone(),
            nullable_overrides,
            nonnull_overrides,
            json_mappings,
            deprecated,
            optional_params,
            group_by: group_by.clone(),
            custom,
        };
        return Ok(Query {
            name,
            command,
            sql,
            stmt,
            annotations,
        });
    }

    let stmt = statements
        .into_iter()
        .next()
        .expect("filtered to exactly one statement");

    let annotations = Annotations {
        name: name.clone(),
        command: command.clone(),
        param_docs,
        positional_param_docs,
        description,
        nullable_overrides,
        nonnull_overrides,
        json_mappings,
        deprecated,
        optional_params,
        group_by,
        custom,
    };

    Ok(Query {
        name,
        command,
        sql,
        stmt,
        annotations,
    })
}

/// Strip the `WHERE …` predicate that PostgreSQL allows between
/// `ON CONFLICT (cols)` and `DO …` (the index-inference form for partial
/// unique indexes). sqlparser-rs through 0.61 does not parse this construct;
/// we lift it out for the parser and let the caller keep the original SQL
/// for codegen + runtime, where Postgres validates it.
fn preprocess_postgres_sql(sql: &str) -> String {
    let mask = mask_postgres_for_scan(sql);
    let mask_bytes = mask.as_bytes();
    let bytes = sql.as_bytes();
    let mut search_from = 0;
    let mut result = String::with_capacity(sql.len());
    let mut last = 0;
    while let Some(rel) = find_keyword(&mask[search_from..], "ON CONFLICT") {
        let on_conflict_pos = search_from + rel;
        let after_on_conflict = on_conflict_pos + "ON CONFLICT".len();
        let mut idx = after_on_conflict;
        while idx < mask_bytes.len() && mask_bytes[idx].is_ascii_whitespace() {
            idx += 1;
        }
        if idx >= mask_bytes.len() || mask_bytes[idx] != b'(' {
            search_from = after_on_conflict;
            continue;
        }
        let mut depth = 0i32;
        let mut close = idx;
        while close < mask_bytes.len() {
            match mask_bytes[close] {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            close += 1;
        }
        if depth != 0 {
            return sql.to_string();
        }
        let mut after_cols = close + 1;
        while after_cols < mask_bytes.len() && mask_bytes[after_cols].is_ascii_whitespace() {
            after_cols += 1;
        }
        if mask[after_cols..].starts_with("WHERE")
            && let Some(do_rel) = find_keyword(&mask[after_cols + "WHERE".len()..], "DO")
        {
            let do_abs = after_cols + "WHERE".len() + do_rel;
            result.push_str(std::str::from_utf8(&bytes[last..after_cols]).unwrap_or(""));
            last = do_abs;
            search_from = do_abs;
            continue;
        }
        search_from = close + 1;
    }
    result.push_str(std::str::from_utf8(&bytes[last..]).unwrap_or(""));
    result
}

/// Spell out the implicit `' '` in `TRIM([BOTH | LEADING | TRAILING] FROM x)`.
///
/// PostgreSQL accepts a trim specification with no characters to remove, and
/// emits exactly that form when it deparses a constraint or view (`pg_dump`
/// writes `btrim(title)` back as `TRIM(BOTH FROM title)`). sqlparser 0.63 parses
/// the token after the specification as the characters expression, so it reads
/// `FROM` as an identifier and then fails on the operand. The characters
/// default to a single space, so inserting `' '` before `FROM` gives the same
/// expression in a form sqlparser parses. Comments and string literals are
/// skipped; every other byte is copied unchanged.
pub(crate) fn spell_out_default_trim_characters(sql: &str) -> String {
    let mask = mask_postgres_for_scan(sql);
    let mask_bytes = mask.as_bytes();
    let sql_bytes = sql.as_bytes();
    let mut result = String::with_capacity(sql.len());
    let mut last = 0;
    let mut search_from = 0;
    while let Some(relative) = find_word(&mask[search_from..], "TRIM") {
        let trim_end = search_from + relative + "TRIM".len();
        search_from = trim_end;
        let open = skip_blank(mask_bytes, sql_bytes, trim_end);
        if mask_bytes.get(open) != Some(&b'(') {
            continue;
        }
        let mut cursor = skip_blank(mask_bytes, sql_bytes, open + 1);
        if let Some(specification) = ["BOTH", "LEADING", "TRAILING"]
            .into_iter()
            .find(|keyword| word_at(&mask, cursor, keyword))
        {
            cursor = skip_blank(mask_bytes, sql_bytes, cursor + specification.len());
        }
        if word_at(&mask, cursor, "FROM") {
            result.push_str(&sql[last..cursor]);
            result.push_str("' ' ");
            last = cursor;
        }
    }
    result.push_str(&sql[last..]);
    result
}

/// End an `INSERT ... SELECT` list that runs into `ON CONFLICT` with
/// `WHERE true`.
///
/// PostgreSQL reserves `ON`, so in `INSERT INTO t (a, b) SELECT $1, x ON
/// CONFLICT DO NOTHING` the select list ends at `ON`. sqlparser 0.63 reads a
/// bare `ON` after a select item as the item's alias and then fails on
/// `CONFLICT`. Where the clause before `ON CONFLICT` at its nesting level is
/// the select list itself, `WHERE true` is inserted before `ON`: it ends the
/// list for sqlparser and filters nothing. Comments, string literals and
/// quoted identifiers are skipped; every other byte is copied unchanged.
fn end_select_list_before_on_conflict(sql: &str) -> String {
    const CLAUSES: &[&str] = &[
        "SELECT", "FROM", "WHERE", "GROUP", "HAVING", "WINDOW", "ORDER", "LIMIT", "OFFSET", "FETCH", "VALUES",
    ];
    let mask = mask_postgres_for_scan(sql);
    let bytes = mask.as_bytes();
    let sql_bytes = sql.as_bytes();
    // The last clause keyword seen at each parenthesis depth.
    let mut clauses: Vec<Option<&str>> = vec![None];
    let mut in_identifier = false;
    let mut insertions = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'"' {
            in_identifier = !in_identifier;
        } else if in_identifier {
            // A quoted identifier is a name, never a keyword.
        } else if byte == b'(' {
            clauses.push(None);
        } else if byte == b')' {
            if clauses.len() > 1 {
                clauses.pop();
            }
        } else if is_word_byte(byte) && (index == 0 || !is_word_byte(bytes[index - 1])) {
            if let Some(clause) = CLAUSES.iter().find(|clause| word_at(&mask, index, clause)) {
                *clauses.last_mut().expect("depth 0 is never popped") = Some(clause);
            } else if word_at(&mask, index, "ON")
                && word_at(&mask, skip_blank(bytes, sql_bytes, index + "ON".len()), "CONFLICT")
                && clauses.last().copied().flatten() == Some("SELECT")
            {
                insertions.push(index);
            }
        }
        index += 1;
    }
    let mut result = String::with_capacity(sql.len() + insertions.len() * "WHERE true ".len());
    let mut last = 0;
    for position in insertions {
        result.push_str(&sql[last..position]);
        result.push_str("WHERE true ");
        last = position;
    }
    result.push_str(&sql[last..]);
    result
}

/// Skip whitespace and comments (blank in `mask`), stopping at a string
/// literal's opening quote: the mask blanks a literal too, but it is an operand.
fn skip_blank(mask: &[u8], sql: &[u8], mut index: usize) -> usize {
    while mask.get(index).is_some_and(u8::is_ascii_whitespace) && sql[index] != b'\'' {
        index += 1;
    }
    index
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$'
}

/// Whether the uppercase `mask` holds the whole word `word` at `index`.
fn word_at(mask: &str, index: usize, word: &str) -> bool {
    let bytes = mask.as_bytes();
    mask.get(index..).is_some_and(|rest| rest.starts_with(word))
        && (index == 0 || !is_word_byte(bytes[index - 1]))
        && !bytes.get(index + word.len()).copied().is_some_and(is_word_byte)
}

/// The byte offset of the first whole word `word` in the uppercase `haystack`.
/// Unlike [`find_keyword`], `_` and `$` count as word characters, so `my_trim`
/// is not `TRIM`.
fn find_word(haystack: &str, word: &str) -> Option<usize> {
    haystack
        .match_indices(word)
        .map(|(index, _)| index)
        .find(|index| word_at(haystack, *index, word))
}

/// Build an ASCII-uppercase, fixed-byte-offset mask of `sql` where `--` line
/// comments, `/* … */` block comments, and `'…'` / `$$…$$` string literals are
/// replaced with spaces. Multi-byte UTF-8 is collapsed to ASCII spaces of the
/// same byte length so positions in the mask line up with the original `sql`.
fn mask_postgres_for_scan(sql: &str) -> String {
    let bytes = sql.as_bytes();
    let mut out = vec![b' '; bytes.len()];
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'-' && i + 1 < bytes.len() && bytes[i + 1] == b'-' {
            while i < bytes.len() && bytes[i] != b'\n' {
                out[i] = b' ';
                i += 1;
            }
            continue;
        }
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            out[i] = b' ';
            out[i + 1] = b' ';
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                out[i] = b' ';
                i += 1;
            }
            if i + 1 < bytes.len() {
                out[i] = b' ';
                out[i + 1] = b' ';
                i += 2;
            }
            continue;
        }
        if b == b'\'' {
            out[i] = b' ';
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\'' {
                    if i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                        out[i] = b' ';
                        out[i + 1] = b' ';
                        i += 2;
                        continue;
                    }
                    out[i] = b' ';
                    i += 1;
                    break;
                }
                out[i] = b' ';
                i += 1;
            }
            continue;
        }
        if b.is_ascii() {
            out[i] = b.to_ascii_uppercase();
        } else {
            out[i] = b' ';
        }
        i += 1;
    }
    String::from_utf8(out).expect("mask is ASCII by construction")
}

/// Locate a whitespace-separated keyword in an uppercase haystack. Returns the
/// byte offset of the keyword's start, or None if not found.
fn find_keyword(haystack: &str, keyword: &str) -> Option<usize> {
    let bytes = haystack.as_bytes();
    let key = keyword.as_bytes();
    let mut i = 0;
    while i + key.len() <= bytes.len() {
        if &bytes[i..i + key.len()] == key {
            let prev_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
            let next = i + key.len();
            let next_ok = next >= bytes.len() || !bytes[next].is_ascii_alphanumeric();
            if prev_ok && next_ok {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::ErrorCode;

    fn parse(sql: &str) -> Result<Query, SqlkitError> {
        parse_query(sql)
    }

    #[test]
    fn test_basic_parse() {
        let input = "-- @name GetUsers\n-- @returns :many\nSELECT * FROM users;";
        let q = parse(input).unwrap();
        assert_eq!(q.name, "GetUsers");
        assert_eq!(q.command, QueryCommand::Many);
        assert!(q.sql.contains("SELECT"));
    }

    #[test]
    fn test_all_command_types() {
        let cases = vec![
            (":one", QueryCommand::One),
            (":many", QueryCommand::Many),
            (":exec", QueryCommand::Exec),
            (":exec_result", QueryCommand::ExecResult),
            (":exec_rows", QueryCommand::ExecRows),
        ];
        for (tag, expected) in cases {
            let input = format!("-- @name Q\n-- @returns {}\nSELECT 1", tag);
            let q = parse(&input).unwrap();
            assert_eq!(q.command, expected, "failed for {}", tag);
        }
    }

    #[test]
    fn test_case_insensitive_keywords() {
        let input = "-- @Name GetUsers\n-- @RETURNS :many\nSELECT 1";
        let q = parse(input).unwrap();
        assert_eq!(q.name, "GetUsers");
        assert_eq!(q.command, QueryCommand::Many);
    }

    #[test]
    fn test_missing_name_errors() {
        let input = "-- @returns :many\nSELECT 1";
        let err = parse(input).unwrap_err();
        assert_eq!(err.code, ErrorCode::MissingAnnotation);
        assert!(err.message.contains("name"));
    }

    #[test]
    fn test_missing_returns_errors() {
        let input = "-- @name Foo\nSELECT 1";
        let err = parse(input).unwrap_err();
        assert_eq!(err.code, ErrorCode::MissingAnnotation);
        assert!(err.message.contains("returns"));
    }

    #[test]
    fn test_invalid_returns_value() {
        let input = "-- @name Foo\n-- @returns :invalid\nSELECT 1";
        let err = parse(input).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidAnnotation);
    }

    /// Inverted with #174: this used to assert that `-- @name` with no value
    /// parses to an empty name, which generated `async def (conn):` and a
    /// bare `Row` type at exit 0.
    #[test]
    fn test_empty_name_value_is_rejected() {
        let input = "-- @name\n-- @returns :one\nSELECT 1";
        let err = parse(input).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidAnnotation);
        assert!(
            err.message.contains("@name requires a value"),
            "message must say what is missing; got: {}",
            err.message
        );
    }

    #[test]
    fn test_name_value_that_is_not_an_identifier_is_rejected() {
        for bad in ["Get User", "get-user", "users.get", "2fast", "\"GetUser\""] {
            let input = format!("-- @name {bad}\n-- @returns :one\nSELECT 1");
            let err = parse(&input).unwrap_err();
            assert_eq!(
                err.code,
                ErrorCode::InvalidAnnotation,
                "@name \"{bad}\" must be rejected"
            );
        }
    }

    #[test]
    fn test_identifier_name_values_are_accepted() {
        for good in ["GetUser", "get_user", "_private", "Query2"] {
            let input = format!("-- @name {good}\n-- @returns :one\nSELECT 1");
            let query = parse(&input).unwrap_or_else(|e| panic!("@name \"{good}\" must parse; got: {e}"));
            assert_eq!(query.name, good);
        }
    }

    #[test]
    fn test_param_annotation() {
        let input = "-- @name Foo\n-- @returns :one\n-- @param id: the user ID\nSELECT 1";
        let q = parse(input).unwrap();
        assert_eq!(q.annotations.param_docs.len(), 1);
        assert_eq!(q.annotations.param_docs[0].name, "id");
        assert_eq!(q.annotations.param_docs[0].description, "the user ID");
    }

    #[test]
    fn test_param_no_description() {
        let input = "-- @name Foo\n-- @returns :one\n-- @param id\nSELECT 1";
        let q = parse(input).unwrap();
        assert_eq!(q.annotations.param_docs.len(), 1);
        assert_eq!(q.annotations.param_docs[0].name, "id");
        assert_eq!(q.annotations.param_docs[0].description, "");
    }

    #[test]
    fn test_nullable_annotation() {
        let input = "-- @name Foo\n-- @returns :one\n-- @nullable col1, col2\nSELECT 1";
        let q = parse(input).unwrap();
        assert_eq!(q.annotations.nullable_overrides, vec!["col1", "col2"]);
    }

    #[test]
    fn test_nonnull_annotation() {
        let input = "-- @name Foo\n-- @returns :one\n-- @nonnull col1\nSELECT 1";
        let q = parse(input).unwrap();
        assert_eq!(q.annotations.nonnull_overrides, vec!["col1"]);
    }

    #[test]
    fn test_json_annotation() {
        let input = "-- @name Foo\n-- @returns :one\n-- @json data = EventData\nSELECT 1";
        let q = parse(input).unwrap();
        assert_eq!(q.annotations.json_mappings.len(), 1);
        assert_eq!(q.annotations.json_mappings[0].column, "data");
        assert_eq!(q.annotations.json_mappings[0].rust_type, "EventData");
    }

    #[test]
    fn test_custom_annotations_captured() {
        let input = "-- @name GetUser
-- @returns :one
-- @http GET /users/{id}
-- @http_auth bearer:jwt
-- @http_status 200,404
SELECT id FROM users WHERE id = $1";
        let q = parse(input).unwrap();
        assert_eq!(q.annotations.custom.len(), 3);
        assert_eq!(q.annotations.custom[0].name, "http");
        assert_eq!(q.annotations.custom[0].value, "GET /users/{id}");
        assert_eq!(q.annotations.custom[0].line, 3);
        assert_eq!(q.annotations.custom[1].name, "http_auth");
        assert_eq!(q.annotations.custom[1].value, "bearer:jwt");
        assert_eq!(q.annotations.custom[1].line, 4);
        assert_eq!(q.annotations.custom[2].name, "http_status");
        assert_eq!(q.annotations.custom[2].value, "200,404");
        assert_eq!(q.annotations.custom[2].line, 5);
    }

    #[test]
    fn test_custom_annotation_without_value() {
        let input = "-- @name GetUser
-- @returns :one
-- @http_internal
SELECT 1";
        let q = parse(input).unwrap();
        assert_eq!(q.annotations.custom.len(), 1);
        assert_eq!(q.annotations.custom[0].name, "http_internal");
        assert_eq!(q.annotations.custom[0].value, "");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_custom_annotation_serde_round_trip() {
        let original = CustomAnnotation {
            name: "http".to_string(),
            value: "GET /users/{id}".to_string(),
            line: 7,
            suggested_keyword: None,
        };
        let json = serde_json::to_string(&original).unwrap();
        let back: CustomAnnotation = serde_json::from_str(&json).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn test_custom_annotation_name_lowercased() {
        let input = "-- @name GetUser
-- @returns :one
-- @HTTP_Auth Bearer
SELECT 1";
        let q = parse(input).unwrap();
        assert_eq!(q.annotations.custom.len(), 1);
        assert_eq!(q.annotations.custom[0].name, "http_auth");
        assert_eq!(q.annotations.custom[0].value, "Bearer");
    }

    /// Regression for #152: a misspelled `@nullable` / `@nonnull` / `@optional` used to be
    /// captured as an opaque `CustomAnnotation` that nothing ever inspected -- `sqlkit generate`,
    /// `sqlkit check` and `sqlkit lint` all reported success while the nullability override the
    /// user wrote never took effect. `suggested_keyword` must name the intended keyword so a
    /// caller can turn this into a warning instead of silence.
    #[test]
    fn test_typo_annotation_suggests_known_keyword() {
        let input = "-- @name GetUser
-- @returns :one
-- @nullible email
-- @optionall email
-- @nonull name
SELECT id, name, email FROM users WHERE id = $1";
        let q = parse(input).unwrap();
        assert_eq!(q.annotations.custom.len(), 3);
        assert_eq!(q.annotations.custom[0].name, "nullible");
        assert_eq!(q.annotations.custom[0].suggested_keyword.as_deref(), Some("nullable"));
        assert_eq!(q.annotations.custom[1].name, "optionall");
        assert_eq!(q.annotations.custom[1].suggested_keyword.as_deref(), Some("optional"));
        assert_eq!(q.annotations.custom[2].name, "nonull");
        assert_eq!(q.annotations.custom[2].suggested_keyword.as_deref(), Some("nonnull"));

        // The override itself must NOT have silently applied under its misspelled name --
        // otherwise the typo would behave identically to the real keyword and there would be
        // nothing to warn about.
        assert!(q.annotations.nullable_overrides.is_empty());
        assert!(q.annotations.optional_params.is_empty());
        assert!(q.annotations.nonnull_overrides.is_empty());
    }

    /// A genuinely consumer-defined annotation vocabulary (`@http`, `@http_auth`, ...) must not
    /// be flagged -- `suggested_keyword` is a typo signal, not a closed-vocabulary rejection; see
    /// the `CustomAnnotation` doc comment for why an unrecognised annotation is never a hard
    /// error.
    #[test]
    fn test_custom_annotation_far_from_any_keyword_has_no_suggestion() {
        let input = "-- @name GetUser
-- @returns :one
-- @http GET /users/{id}
-- @http_auth bearer:jwt
-- @http_status 200,404
SELECT id FROM users WHERE id = $1";
        let q = parse(input).unwrap();
        assert_eq!(q.annotations.custom.len(), 3);
        for annotation in &q.annotations.custom {
            assert_eq!(
                annotation.suggested_keyword, None,
                "{:?} must not be flagged as a typo of a known keyword",
                annotation.name
            );
        }
    }

    // ---- @param positional form ----

    #[test]
    fn test_positional_param_basic() {
        let input = "-- @name Foo\n-- @returns :one\n-- @param $1 user_id\nSELECT 1";
        let q = parse(input).unwrap();
        assert_eq!(q.annotations.positional_param_docs.len(), 1);
        assert_eq!(q.annotations.positional_param_docs[0].position, 1);
        assert_eq!(q.annotations.positional_param_docs[0].name, "user_id");
        assert_eq!(q.annotations.positional_param_docs[0].description, "");
        assert_eq!(q.annotations.param_docs.len(), 0);
    }

    #[test]
    fn test_header_comment_becomes_description() {
        let input = "-- @name Account\n-- @returns :many\n-- The account a credential belongs to, as stored now.\nSELECT * FROM users WHERE id = $1";
        let q = parse(input).unwrap();
        assert_eq!(
            q.annotations.description.as_deref(),
            Some("The account a credential belongs to, as stored now.")
        );
    }

    #[test]
    fn test_description_keeps_lines_and_paragraphs_but_not_annotations() {
        let input = "-- @name Foo\n\
                     --   Leading indent past the first space stays.\n\
                     -- @returns :one\n\
                     -- Second line.\n\
                     --\n\
                     --\n\
                     -- New paragraph.\n\
                     -- @param $1 id\n\
                     --\n\
                     SELECT 1 WHERE 1 = $1";
        let q = parse(input).unwrap();
        assert_eq!(
            q.annotations.description.as_deref(),
            Some("  Leading indent past the first space stays.\nSecond line.\n\nNew paragraph.")
        );
    }

    #[test]
    fn test_comments_after_the_first_sql_line_are_not_description() {
        let input = "-- @name Foo\n-- @returns :one\nSELECT 1\n-- not a description\nFROM t";
        let q = parse(input).unwrap();
        assert_eq!(q.annotations.description, None);
    }

    #[test]
    fn test_description_comment_stays_in_sql_text() {
        let input = "-- @name Foo\n-- @returns :one\n-- Says hello.\nSELECT 1";
        let q = parse(input).unwrap();
        assert_eq!(q.sql, "-- Says hello.\nSELECT 1");
    }

    #[test]
    fn test_no_header_comment_means_no_description() {
        let input = "-- @name Foo\n-- @returns :one\n\nSELECT 1";
        let q = parse(input).unwrap();
        assert_eq!(q.annotations.description, None);
    }

    #[test]
    fn test_positional_param_with_description() {
        let input = "-- @name Foo\n-- @returns :one\n-- @param $4 bucket: time bucket as text\nSELECT 1";
        let q = parse(input).unwrap();
        assert_eq!(q.annotations.positional_param_docs.len(), 1);
        assert_eq!(q.annotations.positional_param_docs[0].position, 4);
        assert_eq!(q.annotations.positional_param_docs[0].name, "bucket");
        assert_eq!(
            q.annotations.positional_param_docs[0].description,
            "time bucket as text"
        );
    }

    #[test]
    fn test_positional_param_does_not_affect_docs_only_param() {
        let input = "-- @name Foo\n-- @returns :one\n-- @param id: the user ID\n-- @param $2 name\nSELECT 1";
        let q = parse(input).unwrap();
        assert_eq!(q.annotations.param_docs.len(), 1);
        assert_eq!(q.annotations.param_docs[0].name, "id");
        assert_eq!(q.annotations.positional_param_docs.len(), 1);
        assert_eq!(q.annotations.positional_param_docs[0].position, 2);
        assert_eq!(q.annotations.positional_param_docs[0].name, "name");
    }

    #[test]
    fn test_positional_param_multiple() {
        let input =
            "-- @name Foo\n-- @returns :one\n-- @param $1 start_date: start\n-- @param $2 end_date: end\nSELECT 1";
        let q = parse(input).unwrap();
        assert_eq!(q.annotations.positional_param_docs.len(), 2);
        assert_eq!(q.annotations.positional_param_docs[0].position, 1);
        assert_eq!(q.annotations.positional_param_docs[0].name, "start_date");
        assert_eq!(q.annotations.positional_param_docs[1].position, 2);
        assert_eq!(q.annotations.positional_param_docs[1].name, "end_date");
    }

    #[test]
    fn test_positional_param_trailing_question_mark_marks_nullable() {
        let input = "-- @name Foo\n-- @returns :one\n-- @param $1 since?: lower bound\n-- @param $2 id\nSELECT 1";
        let docs = parse(input).unwrap().annotations.positional_param_docs;
        assert_eq!(docs[0].name, "since");
        assert_eq!(docs[0].description, "lower bound");
        assert!(docs[0].nullable);
        assert!(!docs[1].nullable);
    }

    #[test]
    fn test_dollar_colon_header_comment_is_an_ordinary_comment() {
        let input = "-- @name Foo\n-- @returns :one\n-- $1: user_id\nSELECT 1";
        let q = parse(input).unwrap();
        assert!(q.annotations.positional_param_docs.is_empty());
        assert!(q.sql.contains("-- $1: user_id"));
    }

    #[test]
    fn test_duplicate_positional_param_errors() {
        let input = "-- @name Foo\n-- @returns :one\n-- @param $1 user_id\n-- @param $1 account_id?\nSELECT 1";
        let err = parse(input).unwrap_err().to_string();
        assert!(err.contains("$1 is named twice (`user_id` and `account_id`)"), "{err}");
    }

    #[test]
    fn test_deprecated_annotation() {
        let input = "-- @name Foo\n-- @returns :one\n-- @deprecated Use V2\nSELECT 1";
        let q = parse(input).unwrap();
        assert_eq!(q.annotations.deprecated, Some("Use V2".to_string()));
    }

    #[test]
    fn test_sql_syntax_error() {
        let input = "-- @name Foo\n-- @returns :one\nSELCT * FROM users";
        let err = parse(input).unwrap_err();
        assert_eq!(err.code, ErrorCode::SyntaxError);
    }

    #[test]
    fn test_trailing_semicolon() {
        let input = "-- @name Foo\n-- @returns :one\nSELECT 1;";
        let q = parse(input).unwrap();
        assert_eq!(q.name, "Foo");
    }

    #[test]
    fn test_multiple_statements_error() {
        let input = "-- @name Foo\n-- @returns :one\nSELECT 1; SELECT 2;";
        let err = parse(input).unwrap_err();
        assert_eq!(err.code, ErrorCode::SyntaxError);
    }

    #[test]
    fn test_sql_preserved_without_annotations() {
        let input = "-- @name Foo\n-- @returns :one\nSELECT id, name FROM users WHERE id = $1";
        let q = parse(input).unwrap();
        assert_eq!(q.sql, "SELECT id, name FROM users WHERE id = $1");
    }

    #[test]
    fn test_returns_without_colon_prefix() {
        let input = "-- @name Foo\n-- @returns many\nSELECT 1";
        let q = parse(input).unwrap();
        assert_eq!(q.command, QueryCommand::Many);
    }

    #[test]
    fn test_batch_command() {
        let input = "-- @name Foo\n-- @returns :batch\nSELECT 1";
        let q = parse(input).unwrap();
        assert_eq!(q.command, QueryCommand::Batch);
    }

    #[test]
    fn test_grouped_command_with_group_by() {
        let input = "-- @name GetUsersWithOrders\n-- @returns :grouped\n-- @group_by users.id\nSELECT u.id, u.name FROM users u JOIN orders o ON o.user_id = u.id";
        let q = parse(input).unwrap();
        assert_eq!(q.command, QueryCommand::Grouped);
        assert_eq!(q.annotations.group_by, Some("users.id".to_string()));
    }

    #[test]
    fn test_grouped_command_without_group_by_errors() {
        let input = "-- @name Foo\n-- @returns :grouped\nSELECT 1";
        let err = parse(input).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidAnnotation);
        assert!(err.message.contains("@group_by"));
    }

    #[test]
    fn test_group_by_without_grouped_is_ignored() {
        let input = "-- @name Foo\n-- @returns :many\n-- @group_by users.id\nSELECT 1";
        let q = parse(input).unwrap();
        assert_eq!(q.command, QueryCommand::Many);
        assert_eq!(q.annotations.group_by, Some("users.id".to_string()));
    }

    #[test]
    fn test_preprocess_postgres_strips_partial_index_where() {
        let sql = "INSERT INTO billing_events (project_id, stripe_event_id) \
                   VALUES ($1, $2) \
                   ON CONFLICT (stripe_event_id) WHERE stripe_event_id IS NOT NULL DO NOTHING";
        let cleaned = preprocess_postgres_sql(sql);
        assert!(
            !cleaned.to_uppercase().contains("WHERE STRIPE_EVENT_ID IS NOT NULL"),
            "WHERE clause must be stripped between ON CONFLICT cols and DO; got: {cleaned}"
        );
        assert!(
            cleaned
                .to_uppercase()
                .contains("ON CONFLICT (STRIPE_EVENT_ID) DO NOTHING")
        );
        sqlparser::parser::Parser::parse_sql(&sqlparser::dialect::PostgreSqlDialect {}, &cleaned)
            .expect("cleaned SQL should parse");
    }

    #[test]
    fn test_preprocess_postgres_no_op_when_no_partial_clause() {
        let sql = "INSERT INTO t (a) VALUES ($1) ON CONFLICT (a) DO UPDATE SET a = EXCLUDED.a";
        assert_eq!(preprocess_postgres_sql(sql), sql);
    }

    #[test]
    fn test_preprocess_postgres_leaves_on_conflict_on_constraint_alone() {
        let sql = "INSERT INTO t (a) VALUES ($1) ON CONFLICT ON CONSTRAINT t_a_uidx DO NOTHING";
        assert_eq!(preprocess_postgres_sql(sql), sql);
    }

    #[test]
    fn test_preprocess_postgres_handles_compound_index_cols() {
        let sql = "INSERT INTO t (a, b) VALUES ($1, $2) \
                   ON CONFLICT (a, b) WHERE a IS NOT NULL AND b > 0 DO UPDATE SET b = EXCLUDED.b";
        let cleaned = preprocess_postgres_sql(sql);
        assert!(cleaned.to_uppercase().contains("ON CONFLICT (A, B) DO UPDATE"));
        assert!(!cleaned.to_uppercase().contains("WHERE A IS NOT NULL"));
    }

    #[test]
    fn test_preprocess_postgres_preserves_unrelated_where() {
        let sql = "DELETE FROM t WHERE id = $1";
        assert_eq!(preprocess_postgres_sql(sql), sql);
    }

    #[test]
    fn test_preprocess_postgres_ignores_text_inside_line_comments() {
        let sql = "-- inline doc: `ON CONFLICT (col) WHERE …` is the partial form\n\
                   INSERT INTO t (a) VALUES ($1) \
                   ON CONFLICT (a) WHERE a IS NOT NULL DO NOTHING";
        let cleaned = preprocess_postgres_sql(sql);
        assert!(
            cleaned.contains("-- inline doc"),
            "comment must survive the pass; got: {cleaned}"
        );
        assert!(cleaned.contains("ON CONFLICT (a) DO NOTHING"));
    }

    #[test]
    fn test_preprocess_postgres_ignores_text_inside_string_literals() {
        let sql = "SELECT 'ON CONFLICT (a) WHERE a IS NOT NULL DO NOTHING' AS s";
        assert_eq!(preprocess_postgres_sql(sql), sql);
    }

    #[test]
    fn test_spell_out_default_trim_characters_inserts_space_before_from() {
        assert_eq!(
            spell_out_default_trim_characters("CHECK ((length(TRIM(BOTH FROM title)) > 0))"),
            "CHECK ((length(TRIM(BOTH ' ' FROM title)) > 0))"
        );
        assert_eq!(
            spell_out_default_trim_characters("SELECT trim( leading\n from name), trim(FROM a) FROM t"),
            "SELECT trim( leading\n ' ' from name), trim(' ' FROM a) FROM t"
        );
        assert_eq!(
            spell_out_default_trim_characters("SELECT TRIM(TRAILING /* none */ FROM a)"),
            "SELECT TRIM(TRAILING /* none */ ' ' FROM a)"
        );
    }

    #[test]
    fn test_spell_out_default_trim_characters_leaves_other_forms_alone() {
        for sql in [
            "SELECT trim(name) FROM t",
            "SELECT trim(BOTH 'x' FROM name) FROM t",
            "SELECT trim(BOTH ' ' FROM name) FROM t",
            "SELECT my_trim(FROM_x) FROM t",
            "SELECT 'trim(BOTH FROM x)' -- trim(FROM y)\nFROM t",
            "SELECT trim FROM t",
        ] {
            assert_eq!(spell_out_default_trim_characters(sql), sql);
        }
    }

    #[test]
    fn test_trim_without_characters_parses_and_keeps_original_sql() {
        let query = parse_query("-- @name Trimmed\n-- @returns :many\nSELECT TRIM(LEADING FROM name) AS name FROM t")
            .expect("TRIM with a specification and no characters should parse");
        assert!(
            query.sql.contains("TRIM(LEADING FROM name)"),
            "codegen keeps the original SQL"
        );
    }

    #[test]
    fn test_end_select_list_before_on_conflict_inserts_where_true() {
        assert_eq!(
            end_select_list_before_on_conflict(
                "INSERT INTO t (a, b) SELECT $1, unnest($2::text[])\nON CONFLICT DO NOTHING"
            ),
            "INSERT INTO t (a, b) SELECT $1, unnest($2::text[])\nWHERE true ON CONFLICT DO NOTHING"
        );
        assert_eq!(
            end_select_list_before_on_conflict(
                "WITH x AS (SELECT 1) INSERT INTO t SELECT DISTINCT ON (a) a on  conflict (a) do nothing"
            ),
            "WITH x AS (SELECT 1) INSERT INTO t SELECT DISTINCT ON (a) a WHERE true on  conflict (a) do nothing"
        );
        assert_eq!(
            end_select_list_before_on_conflict("INSERT INTO t (a) SELECT (SELECT 1 FROM u) ON CONFLICT DO NOTHING"),
            "INSERT INTO t (a) SELECT (SELECT 1 FROM u) WHERE true ON CONFLICT DO NOTHING"
        );
    }

    #[test]
    fn test_end_select_list_before_on_conflict_leaves_other_forms_alone() {
        for sql in [
            "INSERT INTO t (a) SELECT x FROM y ON CONFLICT DO NOTHING",
            "INSERT INTO t (a) SELECT x FROM y WHERE z ON CONFLICT DO NOTHING",
            "INSERT INTO t (a) VALUES ($1) ON CONFLICT DO NOTHING",
            "INSERT INTO t (a) SELECT 'ON CONFLICT' FROM y",
            "INSERT INTO t (a) SELECT \"on\" FROM y ON CONFLICT DO NOTHING",
            "SELECT a FROM t JOIN u ON t.id = u.id",
        ] {
            assert_eq!(end_select_list_before_on_conflict(sql), sql);
        }
    }

    #[test]
    fn test_insert_select_without_from_before_on_conflict_parses_and_keeps_original_sql() {
        let sql = "INSERT INTO reminders (\"userId\", topic)\nSELECT $1, unnest($2::text[])\nON CONFLICT DO NOTHING";
        let query = parse_query(&format!("-- @name AddReminders\n-- @returns :exec\n{sql};"))
            .expect("an INSERT ... SELECT list ending at ON CONFLICT should parse");
        assert_eq!(query.sql, format!("{sql};"), "codegen keeps the original SQL");
    }
}
