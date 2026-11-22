mod builder;
mod constraints;
mod fingerprint;
mod function_body;
pub(crate) mod type_normalizer;
mod view_resolver;

use ahash::AHashMap;
use sqlparser::ast::Spanned;
use sqlparser::ast::{
    AlterColumnOperation, AlterTableOperation, AlterTypeOperation, ArgMode, ColumnOption, CommentObject,
    CreateFunction, DataType, Expr, FunctionCalledOnNull, FunctionReturnType, ObjectName, Statement, TableConstraint,
    UserDefinedTypeRepresentation,
};
use sqlparser::parser::Parser;
use sqlparser::tokenizer::Location;

use crate::errors::SqlkitError;
use sqlparser::dialect::PostgreSqlDialect;

use type_normalizer::{bare_name, ident_to_lower, normalize_data_type, object_name_to_key, object_name_to_raw_name};

pub use constraints::{CheckConstraint, Collation, ColumnConstraints, ColumnOrigin};
use constraints::{DomainConstraint, NamedConstraint, attach_check};

pub use builder::{
    CatalogBuilder, CatalogObjectName, CheckDefinition, ColumnDefinition, CompositeDefinition,
    CompositeFieldDefinition, DomainDefinition, EnumDefinition, FunctionArgumentDefinition, FunctionDefinition,
    FunctionResultColumnDefinition, FunctionReturnDefinition, GeneratedColumnKind, RelationDefinition, RelationKind,
};

#[derive(Debug)]
pub struct Catalog {
    tables: AHashMap<String, Table>,
    enums: AHashMap<String, EnumType>,
    composites: AHashMap<String, CompositeType>,
    functions: AHashMap<String, Vec<Function>>,
    /// Domain name -> resolved base type (lowercase)
    domains: AHashMap<String, DomainDef>,
    search_path: Option<Vec<String>>,
    relation_names: AHashMap<String, CatalogObjectName>,
    relation_kinds: AHashMap<String, RelationKind>,
    raw_column_types: AHashMap<String, AHashMap<String, String>>,
    generated_column_kinds: AHashMap<String, AHashMap<String, GeneratedColumnKind>>,
    enum_names: AHashMap<String, CatalogObjectName>,
    composite_names: AHashMap<String, CatalogObjectName>,
    domain_names: AHashMap<String, CatalogObjectName>,
    raw_domain_types: AHashMap<String, String>,
    /// Each view's defining query, in the order the schema defines them, so
    /// views can be analyzed again once function results are refined.
    view_queries: Vec<(String, sqlparser::ast::Query)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FunctionArgumentMode {
    In,
    Out,
    InOut,
    Variadic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionArgument {
    pub name: Option<String>,
    pub sql_type: String,
    pub mode: FunctionArgumentMode,
    pub has_default: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionResultColumn {
    pub name: String,
    pub sql_type: String,
    pub nullable: bool,
}

/// A function's result. Each `nullable` says whether a value (the scalar
/// result, an element of the set, a table column) can be null when every
/// argument is non-null; it stays `true` unless the function's SQL body
/// proves otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FunctionReturn {
    Scalar { sql_type: String, nullable: bool },
    SetOf { sql_type: String, nullable: bool },
    Table { columns: Vec<FunctionResultColumn> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Function {
    pub arguments: Vec<FunctionArgument>,
    pub return_type: FunctionReturn,
    /// `STRICT` (`RETURNS NULL ON NULL INPUT`): a null argument makes a call
    /// return null, or no rows from a set-returning function, without
    /// evaluating the body.
    pub strict: bool,
    /// The `LANGUAGE sql` body whose analysis refines the result's
    /// nullability, as the query it evaluates: `RETURN expr` reads as
    /// `SELECT expr`, and each `$n` placeholder as the column `"$n"` of the
    /// arguments' scope. `None` for other languages, for bodies sqlkit cannot
    /// parse, and for output parameters without `SETOF`, whose single row is
    /// null when the body returns none.
    pub body: Option<Box<sqlparser::ast::Query>>,
}

#[derive(Debug, Clone)]
pub(crate) struct DomainDef {
    pub(crate) base_type: String,
    pub(crate) not_null: bool,
    pub(crate) constraints: ColumnConstraints,
    /// The names of the constraints it was given other than its checks:
    /// named `NOT NULL`s, which count in the schema's constraint namespace.
    pub(crate) other_constraints: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Table {
    pub columns: Vec<Column>,
    /// The table (or view) name exactly as the DDL spelled its final
    /// identifier part, independent of the catalog's lowercase lookup key.
    ///
    /// This exists because [`Catalog`]'s tables map is keyed by
    /// [`object_name_to_key`], which lowercases every identifier
    /// unconditionally -- quoted or not -- so that lookups stay
    /// case-insensitive the way PostgreSQL treats
    /// unqualified references. That lowercasing is correct for lookup but
    /// destroys the one signal a naming-convention lint needs: whether the
    /// author actually wrote `"UserProfile"`.
    ///
    /// `raw_name` is populated via [`object_name_to_raw_name`], which
    /// mirrors [`ident_to_lower`]'s quote-aware rule: a quoted identifier
    /// keeps its literal casing, an unquoted one is folded to lowercase (the
    /// same case-folding PostgreSQL applies to unquoted
    /// identifiers). Concretely: for a bare `CREATE TABLE user_profiles`,
    /// `raw_name` is `"user_profiles"` -- identical to the lookup key's bare
    /// name, so a lint keyed on `raw_name` behaves exactly as it would
    /// against the normalised key. It only diverges, and only becomes
    /// interesting, when the DDL quoted a mixed-case or uppercase
    /// identifier, e.g. `CREATE TABLE "UserProfile"` yields
    /// `raw_name == "UserProfile"` while the lookup key is
    /// `"userprofile"`.
    ///
    /// Always the bare (unqualified) name, never schema-qualified, since
    /// every current consumer (SC-N02) only ever checks bare table casing.
    pub raw_name: String,
    /// The constraints recorded by name only; see [`NamedConstraint`].
    pub(crate) other_constraints: Vec<NamedConstraint>,
}

impl Table {
    pub(crate) fn new(columns: Vec<Column>, raw_name: String) -> Self {
        Self {
            columns,
            raw_name,
            other_constraints: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Column {
    pub name: String,
    pub sql_type: String,
    pub nullable: bool,
    pub default: Option<String>,
    pub primary_key: bool,
    /// What the schema declares about the column's values. See
    /// [`Catalog::column_constraints`] for the resolved rules.
    pub constraints: ColumnConstraints,
}

#[derive(Debug, Clone)]
pub struct EnumType {
    pub values: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CompositeType {
    pub fields: Vec<CompositeField>,
}

#[derive(Debug, Clone)]
pub struct CompositeField {
    pub name: String,
    pub sql_type: String,
    pub nullable: bool,
}

fn input_signature(function: &Function) -> Vec<&str> {
    function
        .arguments
        .iter()
        .filter(|argument| argument.mode != FunctionArgumentMode::Out)
        .map(|argument| argument.sql_type.as_str())
        .collect()
}

impl Catalog {
    pub fn from_ddl(schema_sql: &[&str]) -> Result<Catalog, SqlkitError> {
        let mut catalog = Catalog {
            tables: AHashMap::new(),
            enums: AHashMap::new(),
            composites: AHashMap::new(),
            functions: AHashMap::new(),
            domains: AHashMap::new(),
            search_path: None,
            relation_names: AHashMap::new(),
            relation_kinds: AHashMap::new(),
            raw_column_types: AHashMap::new(),
            generated_column_kinds: AHashMap::new(),
            enum_names: AHashMap::new(),
            composite_names: AHashMap::new(),
            domain_names: AHashMap::new(),
            raw_domain_types: AHashMap::new(),
            view_queries: Vec::new(),
        };

        for sql in schema_sql {
            let filtered = Self::strip_psql_meta_commands(sql);
            let mut cleaned = catalog.extract_unsupported_statements(&filtered);
            cleaned = crate::parser::spell_out_default_trim_characters(&cleaned);

            let trimmed = cleaned.trim();
            if trimmed.is_empty() {
                continue;
            }

            let statements =
                Parser::parse_sql(&PostgreSqlDialect {}, &cleaned).map_err(|e| SqlkitError::syntax(e.to_string()))?;

            for stmt in statements {
                catalog.process_statement(stmt)?;
            }
        }

        // Bodies may read relations and call functions defined anywhere in
        // the schema, so they are analyzed once all of it is loaded.
        catalog.refine_function_results();
        Ok(catalog)
    }

    pub fn get_table(&self, name: &str) -> Option<&Table> {
        lookup_qualified(&self.tables, name, self.search_path.as_deref())
    }

    pub fn get_enum(&self, name: &str) -> Option<&EnumType> {
        lookup_qualified(&self.enums, name, self.search_path.as_deref())
    }

    /// Iterate over all table names in the catalog.
    pub fn tables(&self) -> impl Iterator<Item = &String> {
        self.tables.keys()
    }

    /// Iterate over all `(name, table)` pairs in the catalog. Useful for
    /// consumers that need to walk every table's schema (e.g. auto-CRUD
    /// generators).
    pub fn tables_iter(&self) -> impl Iterator<Item = (&String, &Table)> {
        self.tables.iter()
    }

    /// Iterate over all enum names in the catalog.
    pub fn enums_iter(&self) -> impl Iterator<Item = (&String, &EnumType)> {
        self.enums.iter()
    }

    /// Iterate over all `(name, composite)` pairs in the catalog. Mirrors
    /// [`Self::enums_iter`] -- added so callers (in particular the
    /// fixture-generated catalog tests, see #161) can assert a *total*
    /// composite count instead of only checking that specific composites
    /// exist, which left extra, unexpected composites invisible.
    pub fn composites_iter(&self) -> impl Iterator<Item = (&String, &CompositeType)> {
        self.composites.iter()
    }

    /// The lookup name of every domain the schema declares, in no particular order.
    pub fn domain_names(&self) -> impl Iterator<Item = &String> {
        self.domains.keys()
    }

    /// Look up a domain's resolved base type by name.
    pub fn get_domain_base_type(&self, name: &str) -> Option<&str> {
        lookup_qualified(&self.domains, name, self.search_path.as_deref()).map(|d| d.base_type.as_str())
    }

    pub fn get_composite(&self, name: &str) -> Option<&CompositeType> {
        lookup_qualified(&self.composites, name, self.search_path.as_deref())
    }

    pub fn get_functions(&self, name: &str) -> Option<&[Function]> {
        lookup_qualified(&self.functions, name, self.search_path.as_deref()).map(Vec::as_slice)
    }

    pub fn functions_iter(&self) -> impl Iterator<Item = (&String, &[Function])> {
        self.functions
            .iter()
            .map(|(name, functions)| (name, functions.as_slice()))
    }

    /// Return the preserved qualified spelling of an inspected relation name.
    pub fn relation_name(&self, name: &str) -> Option<&CatalogObjectName> {
        lookup_qualified(&self.relation_names, name, self.search_path.as_deref())
    }

    /// Return whether an inspected relation is a table or view.
    pub fn relation_kind(&self, name: &str) -> Option<RelationKind> {
        lookup_qualified(&self.relation_kinds, name, self.search_path.as_deref()).copied()
    }

    /// Return the database-reported SQL type before catalog normalization.
    pub fn column_raw_sql_type(&self, relation: &str, column: &str) -> Option<&str> {
        lookup_qualified(&self.raw_column_types, relation, self.search_path.as_deref())?
            .get(&column.to_lowercase())
            .map(String::as_str)
    }

    /// Return how an inspected generated column is persisted by the engine.
    pub fn column_generated_kind(&self, relation: &str, column: &str) -> Option<GeneratedColumnKind> {
        lookup_qualified(&self.generated_column_kinds, relation, self.search_path.as_deref())?
            .get(&column.to_lowercase())
            .copied()
    }

    /// Return the preserved qualified spelling of an inspected enum name.
    pub fn enum_name(&self, name: &str) -> Option<&CatalogObjectName> {
        lookup_qualified(&self.enum_names, name, self.search_path.as_deref())
    }

    /// Return the preserved qualified spelling of an inspected composite name.
    pub fn composite_name(&self, name: &str) -> Option<&CatalogObjectName> {
        lookup_qualified(&self.composite_names, name, self.search_path.as_deref())
    }

    /// Return the preserved qualified spelling of an inspected domain name.
    pub fn domain_name(&self, name: &str) -> Option<&CatalogObjectName> {
        lookup_qualified(&self.domain_names, name, self.search_path.as_deref())
    }

    /// Return an inspected domain's database-reported base type.
    pub fn domain_raw_base_type(&self, name: &str) -> Option<&str> {
        lookup_qualified(&self.raw_domain_types, name, self.search_path.as_deref()).map(String::as_str)
    }
}

impl Catalog {
    /// Pre-process a SQL string to extract statements that sqlparser cannot handle
    /// (CREATE DOMAIN, CREATE SCHEMA and triggers).
    /// Processes them internally and returns the remaining SQL with those
    /// statements removed.
    fn extract_unsupported_statements(&mut self, sql: &str) -> String {
        let mut result = String::with_capacity(sql.len());
        for raw_stmt in Self::split_top_level_statements(sql) {
            let trimmed = raw_stmt.trim();
            if trimmed.is_empty() || trimmed.starts_with("--") && !trimmed.contains('\n') {
                result.push_str(raw_stmt);
                continue;
            }
            let no_comments = Self::strip_leading_comments(trimmed);
            let upper = no_comments.to_uppercase();
            if upper.starts_with("CREATE DOMAIN") {
                self.try_parse_create_domain(no_comments);
            } else if upper.starts_with("ALTER DOMAIN") {
                self.process_alter_domain(no_comments);
            } else if upper.starts_with("CREATE SCHEMA") {
            } else if Self::is_create_trigger(&upper) {
                // Trigger definitions add no catalog state and may have bodies
                // sqlparser cannot parse, so they are dropped before parsing.
            } else {
                let stmt_to_add = Self::rewrite_returns_table(raw_stmt);
                result.push_str(&stmt_to_add);
                if !stmt_to_add.ends_with(';') {
                    result.push(';');
                }
            }
        }
        result
    }

    fn rewrite_returns_table(sql: &str) -> String {
        let outside = sql_outside_mask(sql);
        let Some(marker) = find_keyword_sequence(sql, &outside, &["RETURNS", "TABLE"]) else {
            return sql.to_string();
        };
        let Some(table_open) = find_char_outside(sql, &outside, '(', marker) else {
            return sql.to_string();
        };
        let Some(table_close) = matching_parenthesis(sql, &outside, table_open) else {
            return sql.to_string();
        };
        let Some(function_open) = find_char_outside(sql, &outside, '(', 0).filter(|open| *open < marker) else {
            return sql.to_string();
        };
        let Some(function_close) = matching_parenthesis(sql, &outside, function_open) else {
            return sql.to_string();
        };
        if function_close > marker {
            return sql.to_string();
        }
        let output_arguments = split_top_level_commas(&sql[table_open + 1..table_close])
            .into_iter()
            .map(|column| format!("OUT {}", column.trim()))
            .collect::<Vec<_>>()
            .join(", ");
        let existing_arguments = sql[function_open + 1..function_close].trim();
        let separator = if existing_arguments.is_empty() { "" } else { ", " };
        // `RETURNS TABLE` returns a set of rows, unlike output parameters alone.
        format!(
            "{}{}{}{} RETURNS SETOF record{}",
            &sql[..function_close],
            separator,
            output_arguments,
            &sql[function_close..=function_close],
            &sql[table_close + 1..]
        )
    }

    /// Split SQL text into top-level statements by semicolons, preserving
    /// the semicolons and whitespace in the returned fragments.
    fn split_top_level_statements(sql: &str) -> Vec<&str> {
        let mut statements = Vec::new();
        let mut start = 0;
        let mut in_single_quote = false;
        let mut in_double_quote = false;
        let mut in_line_comment = false;
        let mut in_block_comment = false;
        let bytes = sql.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if in_line_comment {
                if bytes[i] == b'\n' {
                    in_line_comment = false;
                }
                i += 1;
                continue;
            }
            if in_block_comment {
                if i + 1 < bytes.len() && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                    in_block_comment = false;
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }
            if in_single_quote {
                if bytes[i] == b'\'' {
                    if i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                        i += 2;
                    } else {
                        in_single_quote = false;
                        i += 1;
                    }
                } else {
                    i += 1;
                }
                continue;
            }
            if in_double_quote {
                if bytes[i] == b'"' {
                    in_double_quote = false;
                }
                i += 1;
                continue;
            }
            match bytes[i] {
                b'\'' => {
                    in_single_quote = true;
                    i += 1;
                }
                b'"' => {
                    in_double_quote = true;
                    i += 1;
                }
                b'-' if i + 1 < bytes.len() && bytes[i + 1] == b'-' => {
                    in_line_comment = true;
                    i += 2;
                }
                b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                    in_block_comment = true;
                    i += 2;
                }
                b';' => {
                    statements.push(&sql[start..=i]);
                    start = i + 1;
                    i += 1;
                }
                _ => {
                    i += 1;
                }
            }
        }
        if start < sql.len() {
            let remainder = &sql[start..];
            if !remainder.trim().is_empty() {
                statements.push(remainder);
            }
        }
        statements
    }

    /// True if `upper` (an already-uppercased, comment-stripped statement) is
    /// a `CREATE TRIGGER` or `CREATE OR REPLACE TRIGGER` statement.
    fn is_create_trigger(upper: &str) -> bool {
        upper.starts_with("CREATE TRIGGER") || upper.starts_with("CREATE OR REPLACE TRIGGER")
    }

    /// Remove psql client meta-command lines from a SQL string.
    ///
    /// `pg_dump 18+` and tools such as `dbmate` emit lines like
    /// `\restrict <token>` and `\unrestrict <token>` that are psql client
    /// directives, not SQL.  `sqlparser` rejects any token starting with `\`,
    /// so we strip those lines before handing the text to the parser.
    ///
    /// Only lines whose **first non-whitespace character** is `\` are removed.
    /// Each dropped line is replaced with an empty line so that error
    /// line-number offsets remain meaningful.  No `\connect`, `\i`, `\copy`,
    /// or `\set` semantics are interpreted — the lines are simply discarded.
    fn strip_psql_meta_commands(sql: &str) -> String {
        let mut out = String::with_capacity(sql.len());
        for line in sql.split('\n') {
            if line.trim_start().starts_with('\\') {
                out.push('\n');
            } else {
                out.push_str(line);
                out.push('\n');
            }
        }
        if !sql.ends_with('\n') && out.ends_with('\n') {
            out.pop();
        }
        out
    }

    /// Strip leading SQL comments (-- and /* */) from a string.
    fn strip_leading_comments(s: &str) -> &str {
        let mut rest = s;
        loop {
            rest = rest.trim_start();
            if rest.starts_with("--") {
                if let Some(nl) = rest.find('\n') {
                    rest = &rest[nl + 1..];
                } else {
                    return "";
                }
            } else if rest.starts_with("/*") {
                if let Some(end) = rest.find("*/") {
                    rest = &rest[end + 2..];
                } else {
                    return "";
                }
            } else {
                return rest;
            }
        }
    }

    /// Try to parse `CREATE DOMAIN <name> AS <type> [NOT NULL] [CHECK ...]`.
    /// Returns true if the SQL was a CREATE DOMAIN statement (even if parsing
    /// was only partial).
    fn try_parse_create_domain(&mut self, sql: &str) -> bool {
        let trimmed = sql.trim();
        if !trimmed.to_ascii_uppercase().starts_with("CREATE DOMAIN") {
            return false;
        }
        let trimmed = trimmed.trim_end_matches(';').trim();
        // `to_ascii_uppercase` (never `to_uppercase`) is required here: it
        // only rewrites the ASCII a-z range, one byte for one byte, so
        // `upper` is guaranteed to have exactly `trimmed`'s byte length and
        // char boundaries. Every byte offset found below is computed on
        // `upper` and then used to slice `trimmed` directly.
        // `str::to_uppercase()` cannot make that guarantee -- full Unicode
        // case folding can change a character's byte length (e.g. U+FB01
        // "ﬁ" becomes the two-byte-longer "FI"), which silently produced
        // offsets that landed inside a multi-byte character and panicked.
        // See issue #184.
        let upper = trimmed.to_ascii_uppercase();

        let name_start = skip_ws(&upper, "CREATE DOMAIN".len());
        let name_end = find_ws(&upper, name_start);
        if name_end <= name_start {
            return true;
        }
        let domain_name = trimmed[name_start..name_end].trim().to_lowercase();

        let after_name = skip_ws(&upper, name_end);
        // PostgreSQL's `AS` between the domain name and its base type is
        // optional (`CREATE DOMAIN x TEXT NOT NULL;` is valid) -- see #166
        // and #184.
        let has_as = upper[after_name..].starts_with("AS")
            && upper
                .as_bytes()
                .get(after_name + 2)
                .is_none_or(|b| b.is_ascii_whitespace());
        let type_start = if has_as {
            skip_ws(&upper, after_name + 2)
        } else {
            after_name
        };

        let rest = trimmed[type_start..].trim_end();
        let rest_upper = upper[type_start..].trim_end();

        // ` CONSTRAINT ` also terminates the base type: PostgreSQL allows a
        // named `CONSTRAINT <name> CHECK (...)` between the type and the
        // check body, and without this the constraint name and keyword were
        // folded into the reported base type. See #166.
        // Any whitespace may separate the type from its constraints (`pg_dump`
        // puts each constraint on its own indented line); ASCII whitespace
        // maps to a space byte for byte, so offsets stay valid for `rest`.
        let rest_spaced: String = rest_upper
            .chars()
            .map(|c| if c.is_ascii_whitespace() { ' ' } else { c })
            .collect();
        let end_pos = [" NOT NULL", " CHECK", " DEFAULT", " CONSTRAINT "]
            .iter()
            .filter_map(|kw| rest_spaced.find(kw))
            .min()
            .unwrap_or(rest.len());
        let base_type_raw = rest[..end_pos].trim();
        if base_type_raw.is_empty() {
            return true;
        }

        // Only a `NOT NULL` appearing outside of any parenthesized group
        // (and outside of any single-quoted string literal) is the `NOT
        // NULL` constraint keyword -- a `CHECK` body's payload may itself
        // contain the literal text `NOT NULL`, e.g.
        // `CHECK (VALUE <> 'NOT NULL')`, which must not be mistaken for the
        // keyword. See #166.
        let not_null = top_level_contains_keyword(rest_upper, "NOT NULL");

        let mut constraints = ColumnConstraints::default();
        let normalized = match Parser::parse_sql(
            &PostgreSqlDialect {},
            &format!("CREATE TABLE _domain_tmp_ (_col_ {})", base_type_raw),
        ) {
            Ok(stmts) => {
                if let Some(Statement::CreateTable(ct)) = stmts.into_iter().next() {
                    if let Some(col) = ct.columns.first() {
                        constraints = ColumnConstraints::from_type(&col.data_type, &col.options, &self.domains);
                        let (t, _) = normalize_data_type(&col.data_type, &self.domains);
                        t
                    } else {
                        base_type_raw.to_lowercase()
                    }
                } else {
                    base_type_raw.to_lowercase()
                }
            }
            Err(_) => base_type_raw.to_lowercase(),
        };

        let namespace = self.namespace_of(&domain_name).to_string();
        let mut taken = self.constraint_names(&namespace);
        let mut other_constraints = Vec::new();
        for constraint in constraints::domain_constraints(&rest[end_pos..]) {
            match constraint {
                DomainConstraint::Check { name, body } => {
                    let check = self.domain_check(&domain_name, name, &body, &mut taken);
                    constraints.checks.push(check);
                }
                DomainConstraint::NamedNotNull(name) => {
                    taken.insert(name.clone());
                    other_constraints.push(name);
                }
            }
        }

        self.domains.insert(
            domain_name,
            DomainDef {
                base_type: normalized,
                not_null,
                constraints,
                other_constraints,
            },
        );
        true
    }

    /// Follow the `ALTER DOMAIN` forms that change a domain's checks: `ADD
    /// [CONSTRAINT name] CHECK (...) [NOT VALID]`, `DROP CONSTRAINT [IF
    /// EXISTS] name`, `VALIDATE CONSTRAINT name` and `RENAME CONSTRAINT a TO
    /// b`. sqlparser does not parse `ALTER DOMAIN`, so the statement is read
    /// here; its other forms change nothing the catalog records about values
    /// and are skipped.
    fn process_alter_domain(&mut self, sql: &str) {
        use sqlparser::tokenizer::Token;
        let sql = sql.trim().trim_end_matches(';').trim_end();
        let Some(tokens) = sql_tokens(sql) else {
            return;
        };
        let [alter, domain, rest @ ..] = tokens.as_slice() else {
            return;
        };
        if !alter.is_keyword("ALTER") || !domain.is_keyword("DOMAIN") {
            return;
        }
        // The name, `name` or `schema.name`, keyed as `CREATE DOMAIN` keys it.
        let mut name_end = 0;
        while matches!(rest.get(name_end).map(|t| &t.token), Some(Token::Word(_))) {
            name_end += 1;
            if !matches!(rest.get(name_end).map(|t| &t.token), Some(Token::Period)) {
                break;
            }
            name_end += 1;
        }
        let name: String = rest[..name_end].iter().map(|token| token.token.to_string()).collect();
        let Some(key) = self.domain_key(&name.to_lowercase()) else {
            return;
        };
        let identifier = |token: &SqlToken| token.identifier();
        match &rest[name_end..] {
            [add, after_add, ..] if add.is_keyword("ADD") => {
                let tail = &sql[after_add.offset..];
                let not_valid = top_level_keywords(tail, &["NOT", "VALID"]);
                let namespace = self.namespace_of(&key).to_string();
                let mut taken = self.constraint_names(&namespace);
                let mut checks = Vec::new();
                let mut other_constraints = Vec::new();
                for constraint in constraints::domain_constraints(tail) {
                    match constraint {
                        DomainConstraint::Check { name, body } => {
                            let mut check = self.domain_check(&key, name, &body, &mut taken);
                            check.validated = !not_valid;
                            checks.push(check);
                        }
                        DomainConstraint::NamedNotNull(name) => other_constraints.push(name),
                    }
                }
                if let Some(domain) = self.domains.get_mut(&key) {
                    domain.constraints.checks.extend(checks);
                    domain.other_constraints.extend(other_constraints);
                }
            }
            [drop, constraint, if_, exists, name, ..]
                if drop.is_keyword("DROP")
                    && constraint.is_keyword("CONSTRAINT")
                    && if_.is_keyword("IF")
                    && exists.is_keyword("EXISTS") =>
            {
                if let Some(name) = identifier(name) {
                    self.drop_domain_constraint(&key, &name);
                }
            }
            [drop, constraint, name, ..] if drop.is_keyword("DROP") && constraint.is_keyword("CONSTRAINT") => {
                if let Some(name) = identifier(name) {
                    self.drop_domain_constraint(&key, &name);
                }
            }
            [validate, constraint, name, ..]
                if validate.is_keyword("VALIDATE") && constraint.is_keyword("CONSTRAINT") =>
            {
                if let (Some(name), Some(domain)) = (identifier(name), self.domains.get_mut(&key)) {
                    validate_check(&mut domain.constraints.checks, &name);
                }
            }
            [rename, constraint, old, to, new, ..]
                if rename.is_keyword("RENAME") && constraint.is_keyword("CONSTRAINT") && to.is_keyword("TO") =>
            {
                if let (Some(old), Some(new), Some(domain)) =
                    (identifier(old), identifier(new), self.domains.get_mut(&key))
                {
                    rename_check(&mut domain.constraints.checks, &old, &new);
                    for other in domain.other_constraints.iter_mut().filter(|other| **other == old) {
                        other.clone_from(&new);
                    }
                }
            }
            _ => {}
        }
    }

    /// Drop the constraint PostgreSQL knows as `name` from the domain `key`.
    fn drop_domain_constraint(&mut self, key: &str, name: &str) {
        if let Some(domain) = self.domains.get_mut(key) {
            domain.constraints.checks.retain(|check| check.system_name != name);
            domain.other_constraints.retain(|other| other != name);
        }
    }

    /// The schema of the table `key` names, resolved as `get_table_mut`
    /// resolves it.
    fn table_namespace(&self, key: &str) -> String {
        let mut resolved = key.to_string();
        if !self.tables.contains_key(key) && !key.contains('.') {
            let suffix = format!(".{key}");
            if let Some(found) = self.tables.keys().filter(|k| k.ends_with(&suffix)).min() {
                resolved.clone_from(found);
            }
        }
        self.namespace_of(&resolved).to_string()
    }

    /// The key of the domain `key` names: itself, or the first (sorted)
    /// schema-qualified key it is the bare name of.
    fn domain_key(&self, key: &str) -> Option<String> {
        if self.domains.contains_key(key) {
            return Some(key.to_string());
        }
        let suffix = format!(".{key}");
        let mut candidates: Vec<&String> = self.domains.keys().filter(|k| k.ends_with(&suffix)).collect();
        candidates.sort();
        candidates.first().map(|k| (*k).clone())
    }
}

/// Mark the check PostgreSQL knows as `name` validated.
fn validate_check(checks: &mut [CheckConstraint], name: &str) {
    for check in checks.iter_mut().filter(|check| check.system_name == name) {
        check.validated = true;
    }
}

/// Rename the check PostgreSQL knows as `old`.
fn rename_check(checks: &mut [CheckConstraint], old: &str, new: &str) {
    for check in checks.iter_mut().filter(|check| check.system_name == old) {
        check.name = Some(new.to_string());
        check.system_name = new.to_string();
    }
}

impl Catalog {
    fn process_statement(&mut self, stmt: Statement) -> Result<(), SqlkitError> {
        match stmt {
            Statement::CreateTable(ct) => self.process_create_table(ct),
            Statement::AlterTable(alter_table) => self.process_alter_table(alter_table.name, alter_table.operations),
            Statement::CreateType { name, representation } => {
                if let Some(repr) = representation {
                    self.process_create_type(name, repr)
                } else {
                    Ok(())
                }
            }
            Statement::AlterType(alter_type) => self.process_alter_type(alter_type.name, alter_type.operation),
            Statement::CreateView(cv) => self.process_create_view(cv.name, cv.columns, *cv.query, cv.materialized),
            Statement::CreateFunction(function) => self.process_create_function(function),
            Statement::Comment {
                object_type,
                object_name,
                comment,
                ..
            } => {
                self.process_comment(object_type, &object_name, comment);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Record `COMMENT ON COLUMN` and `COMMENT ON DOMAIN` text; other comments
    /// carry nothing the catalog uses.
    fn process_comment(&mut self, object_type: CommentObject, object_name: &ObjectName, comment: Option<String>) {
        match object_type {
            CommentObject::Column => {
                let Some((relation, column)) = constraints::comment_column_target(object_name) else {
                    return;
                };
                if let Some(table) = get_table_mut(&mut self.tables, &relation)
                    && let Some(target) = table.columns.iter_mut().find(|c| c.name == column)
                {
                    target.constraints.comment = comment;
                }
            }
            CommentObject::Domain => {
                let key = self.domain_key(&object_name_to_key(object_name));
                if let Some(domain) = key.and_then(|key| self.domains.get_mut(&key)) {
                    domain.constraints.comment = comment;
                }
            }
            _ => {}
        }
    }

    fn process_create_function(&mut self, definition: CreateFunction) -> Result<(), SqlkitError> {
        let key = object_name_to_key(&definition.name);
        let mut arguments = Vec::new();
        for argument in definition.args.unwrap_or_default() {
            let sql_type = function_sql_type(&argument.data_type, &self.domains);
            let mode = match argument.mode {
                None | Some(ArgMode::In) => FunctionArgumentMode::In,
                Some(ArgMode::Out) => FunctionArgumentMode::Out,
                Some(ArgMode::InOut) => FunctionArgumentMode::InOut,
                Some(ArgMode::Variadic) => FunctionArgumentMode::Variadic,
            };
            arguments.push(FunctionArgument {
                name: argument.name.map(|name| ident_to_lower(&name)),
                sql_type,
                mode,
                has_default: argument.default_expr.is_some(),
            });
        }

        let output_columns = arguments
            .iter()
            .filter(|argument| matches!(argument.mode, FunctionArgumentMode::Out | FunctionArgumentMode::InOut))
            .enumerate()
            .map(|(index, argument)| FunctionResultColumn {
                name: argument.name.clone().unwrap_or_else(|| format!("column{}", index + 1)),
                sql_type: argument.sql_type.clone(),
                nullable: true,
            })
            .collect::<Vec<_>>();
        let returns_set = matches!(definition.return_type, Some(FunctionReturnType::SetOf(_)));
        let return_type = if !output_columns.is_empty() {
            FunctionReturn::Table {
                columns: output_columns,
            }
        } else {
            match definition.return_type {
                Some(FunctionReturnType::DataType(data_type)) => FunctionReturn::Scalar {
                    sql_type: function_sql_type(&data_type, &self.domains),
                    nullable: true,
                },
                Some(FunctionReturnType::SetOf(data_type)) => FunctionReturn::SetOf {
                    sql_type: function_sql_type(&data_type, &self.domains),
                    nullable: true,
                },
                None => return Ok(()),
            }
        };

        let strict = matches!(
            definition.called_on_null,
            Some(FunctionCalledOnNull::Strict | FunctionCalledOnNull::ReturnsNullOnNullInput)
        );
        let body = function_body::refinable_body(
            definition.function_body.as_ref(),
            definition.language.as_ref(),
            returns_set,
            &return_type,
        );
        let function = Function {
            arguments,
            return_type,
            strict,
            body,
        };
        let overloads = self.functions.entry(key.clone()).or_default();
        let signature = input_signature(&function);
        if let Some(index) = overloads
            .iter()
            .position(|existing| input_signature(existing) == signature)
        {
            if definition.or_replace || definition.or_alter {
                overloads[index] = function;
            } else if !definition.if_not_exists {
                return Err(SqlkitError::syntax(format!(
                    "function \"{key}\" with the same input signature already exists"
                )));
            }
        } else {
            overloads.push(function);
        }
        Ok(())
    }

    fn process_create_table(&mut self, ct: sqlparser::ast::CreateTable) -> Result<(), SqlkitError> {
        let table_name = object_name_to_key(&ct.name);
        let raw_name = object_name_to_raw_name(&ct.name);

        let table = if ct.columns.is_empty() {
            match ct.query {
                // `CREATE TABLE ... AS SELECT`: the schema comes entirely
                // from the query's projected columns. Resolve it through
                // the same analyzer path an ordinary annotated query uses,
                // rather than silently registering a zero-column table. See
                // issue #183.
                // A table copies the query's column types but none of its
                // sources' constraints, so its columns keep no origin.
                Some(query) => Table::new(
                    self.resolve_select_columns(*query)?
                        .into_iter()
                        .map(|column| Column {
                            constraints: ColumnConstraints::default(),
                            ..column
                        })
                        .collect(),
                    raw_name,
                ),
                None => Table::new(Vec::new(), raw_name),
            }
        } else {
            let mut table = Table::new(Vec::new(), raw_name);
            // Checks, column-level or not, attached once every column exists:
            // a column-level check may name another column. Each is kept with
            // where it was written, the order PostgreSQL names them in.
            let mut pending_checks: Vec<(Location, Option<String>, Expr)> = Vec::new();
            // Other constraints given a name, which PostgreSQL creates after
            // the checks: they take no name a check of this table could.
            let mut named_constraints: Vec<NamedConstraint> = Vec::new();

            for col_def in &ct.columns {
                let col_name = ident_to_lower(&col_def.name);
                let (sql_type, is_serial) = normalize_data_type(&col_def.data_type, &self.domains);

                let mut nullable = !is_serial;
                let mut default: Option<String> = None;
                let mut primary_key = false;
                let constraints = ColumnConstraints::from_type(&col_def.data_type, &col_def.options, &self.domains);

                for opt_def in &col_def.options {
                    if let ColumnOption::Check(check) = &opt_def.option {
                        let name = check.name.as_ref().or(opt_def.name.as_ref()).map(ident_to_lower);
                        pending_checks.push((opt_def.span().start, name, (*check.expr).clone()));
                    }
                    if let Some(name) = column_option_constraint_name(opt_def) {
                        named_constraints.push(NamedConstraint {
                            name,
                            columns: vec![col_name.clone()],
                        });
                    }
                    match &opt_def.option {
                        ColumnOption::Null => {
                            nullable = true;
                        }
                        ColumnOption::NotNull => {
                            nullable = false;
                        }
                        ColumnOption::Default(expr) => {
                            default = Some(expr.to_string());
                        }
                        ColumnOption::PrimaryKey(_) => {
                            primary_key = true;
                            nullable = false;
                        }
                        ColumnOption::Unique(_) => {}
                        ColumnOption::Generated {
                            generation_expr: Some(expr),
                            ..
                        } => {
                            default = Some(format!("GENERATED ALWAYS AS ({})", expr));
                        }
                        _ => {}
                    }
                }

                table.columns.push(Column {
                    name: col_name,
                    sql_type,
                    nullable,
                    default,
                    primary_key,
                    constraints,
                });
            }

            for constraint in &ct.constraints {
                if let TableConstraint::Check(check) = constraint {
                    let name = check.name.as_ref().map(ident_to_lower);
                    pending_checks.push((constraint.span().start, name, (*check.expr).clone()));
                }
                named_constraints.extend(named_table_constraint(constraint));
                if let TableConstraint::PrimaryKey(pk_constraint) = constraint {
                    for idx_col in &pk_constraint.columns {
                        let pk_name = pk_column_name(&idx_col.column.expr);
                        if let Some(col) = table.columns.iter_mut().find(|c| c.name == pk_name) {
                            col.primary_key = true;
                            col.nullable = false;
                        }
                    }
                }
            }

            // PostgreSQL names a table's checks in the order they are written,
            // column and table constraints interleaved: `transformCreateStmt`
            // collects both into one list as it walks the table's elements.
            // Without positions (none are ever missing from parsed SQL) the
            // columns' checks stay first.
            if pending_checks.iter().all(|(location, ..)| location.line > 0) {
                pending_checks.sort_by_key(|(location, ..)| *location);
            }
            let namespace = self.namespace_of(&table_name).to_string();
            let mut taken = self.constraint_names(&namespace);
            for (_, name, expr) in pending_checks {
                attach_check(&mut table, name, &expr, true, &mut taken);
            }
            table.other_constraints.extend(named_constraints);
            table
        };

        // `CREATE TABLE IF NOT EXISTS` on a table that is already
        // registered is a no-op in PostgreSQL -- it must not silently
        // replace the existing definition, which is exactly the idiom used
        // in idempotent migration files. See issue #183.
        if ct.if_not_exists && self.tables.contains_key(&table_name) {
            return Ok(());
        }

        self.tables.insert(table_name, table);
        Ok(())
    }

    fn process_alter_table(
        &mut self,
        name: ObjectName,
        operations: Vec<AlterTableOperation>,
    ) -> Result<(), SqlkitError> {
        let table_key = object_name_to_key(&name);
        let mut operations = operations;
        // PostgreSQL runs an `ALTER TABLE`'s subcommands in passes, not in
        // the order written; the order matters here for the names it gives
        // unnamed checks (and a dropped constraint's name is free again).
        operations.sort_by_key(alter_table_pass);

        for op in operations {
            match op {
                AlterTableOperation::AddColumn { column_def, .. } => {
                    let mut taken = self.constraint_names(&self.table_namespace(&table_key));
                    let Some(table) = get_table_mut(&mut self.tables, &table_key) else {
                        return Err(SqlkitError::unknown_table(&table_key));
                    };
                    let col_name = ident_to_lower(&column_def.name);
                    let (sql_type, is_serial) = normalize_data_type(&column_def.data_type, &self.domains);
                    let mut nullable = !is_serial;
                    let mut default = None;
                    let mut primary_key = false;

                    for opt_def in &column_def.options {
                        match &opt_def.option {
                            ColumnOption::Null => nullable = true,
                            ColumnOption::NotNull => nullable = false,
                            ColumnOption::Default(expr) => {
                                default = Some(expr.to_string());
                            }
                            ColumnOption::PrimaryKey(_) => {
                                primary_key = true;
                                nullable = false;
                            }
                            _ => {}
                        }
                    }

                    table.columns.push(Column {
                        name: col_name,
                        sql_type,
                        nullable,
                        default,
                        primary_key,
                        constraints: ColumnConstraints::from_type(
                            &column_def.data_type,
                            &column_def.options,
                            &self.domains,
                        ),
                    });
                    let mut named_constraints = Vec::new();
                    for opt_def in &column_def.options {
                        if let ColumnOption::Check(check) = &opt_def.option {
                            let name = check.name.as_ref().or(opt_def.name.as_ref()).map(ident_to_lower);
                            attach_check(table, name, &check.expr, true, &mut taken);
                        }
                        if let Some(name) = column_option_constraint_name(opt_def) {
                            named_constraints.push(NamedConstraint {
                                name,
                                columns: vec![ident_to_lower(&column_def.name)],
                            });
                        }
                    }
                    table.other_constraints.extend(named_constraints);
                }
                AlterTableOperation::DropColumn { column_names, .. } => {
                    let Some(table) = get_table_mut(&mut self.tables, &table_key) else {
                        return Err(SqlkitError::unknown_table(&table_key));
                    };
                    for column_name in &column_names {
                        let col_lower = ident_to_lower(column_name);
                        table.columns.retain(|c| c.name != col_lower);
                        // So are the constraints that cover it.
                        table.other_constraints.retain(|c| !c.columns.contains(&col_lower));
                    }
                }
                AlterTableOperation::RenameColumn {
                    old_column_name,
                    new_column_name,
                } => {
                    let Some(table) = get_table_mut(&mut self.tables, &table_key) else {
                        return Err(SqlkitError::unknown_table(&table_key));
                    };
                    let old_name = ident_to_lower(&old_column_name);
                    let new_name = ident_to_lower(&new_column_name);
                    let covered = table.other_constraints.iter_mut().flat_map(|c| c.columns.iter_mut());
                    for column in covered.filter(|column| **column == old_name) {
                        column.clone_from(&new_name);
                    }
                    if let Some(col) = table.columns.iter_mut().find(|c| c.name == old_name) {
                        col.name = new_name;
                    }
                }
                AlterTableOperation::RenameTable { table_name } => {
                    let (new_key, new_raw_name) = match &table_name {
                        sqlparser::ast::RenameTableNameKind::To(name)
                        | sqlparser::ast::RenameTableNameKind::As(name) => {
                            (object_name_to_key(name), object_name_to_raw_name(name))
                        }
                    };
                    let removed = match self.tables.remove(&table_key) {
                        Some(table) => Some(table),
                        None => {
                            let bare = bare_name(&table_key).to_string();
                            self.tables.remove(&bare)
                        }
                    };
                    // Every other operation in this match (AddColumn,
                    // DropColumn, RenameColumn, AlterColumn, AddConstraint)
                    // rejects an unknown target table with
                    // `SqlkitError::unknown_table` rather than silently doing
                    // nothing. `RENAME TO` was the one exception: a typo'd
                    // table name in a migration no-opped without any signal,
                    // making it indistinguishable from a correct rename.
                    // Follow the same precedent here.
                    let Some(mut table) = removed else {
                        return Err(SqlkitError::unknown_table(&table_key));
                    };
                    // `raw_name` must track the rename too, not just the
                    // lookup key -- otherwise a table renamed to CamelCase
                    // would keep reporting its pre-rename (possibly
                    // snake_case) spelling to SC-N02 forever.
                    table.raw_name = new_raw_name;
                    self.tables.insert(new_key, table);
                }
                AlterTableOperation::AlterColumn { column_name, op } => {
                    let Some(table) = get_table_mut(&mut self.tables, &table_key) else {
                        return Err(SqlkitError::unknown_table(&table_key));
                    };
                    let col_lower = ident_to_lower(&column_name);
                    if let Some(col) = table.columns.iter_mut().find(|c| c.name == col_lower) {
                        match op {
                            AlterColumnOperation::SetNotNull => {
                                col.nullable = false;
                            }
                            AlterColumnOperation::DropNotNull => {
                                col.nullable = true;
                            }
                            AlterColumnOperation::SetDataType { data_type, .. } => {
                                let (new_type, _) = normalize_data_type(&data_type, &self.domains);
                                col.sql_type = new_type;
                                col.constraints.retype(&data_type, &self.domains);
                            }
                            AlterColumnOperation::SetDefault { value } => {
                                col.default = Some(value.to_string());
                            }
                            AlterColumnOperation::DropDefault => {
                                col.default = None;
                            }
                            _ => {}
                        }
                    }
                }
                AlterTableOperation::AddConstraint { constraint, not_valid } => {
                    let mut taken = self.constraint_names(&self.table_namespace(&table_key));
                    let Some(table) = get_table_mut(&mut self.tables, &table_key) else {
                        return Err(SqlkitError::unknown_table(&table_key));
                    };
                    if let TableConstraint::Check(check) = &constraint {
                        // `NOT VALID` leaves the rows already stored unchecked.
                        let name = check.name.as_ref().map(ident_to_lower);
                        attach_check(table, name, &check.expr, !not_valid, &mut taken);
                    }
                    table.other_constraints.extend(named_table_constraint(&constraint));
                    if let TableConstraint::PrimaryKey(pk_constraint) = &constraint {
                        for idx_col in &pk_constraint.columns {
                            let pk_name = pk_column_name(&idx_col.column.expr);
                            if let Some(col) = table.columns.iter_mut().find(|c| c.name == pk_name) {
                                col.primary_key = true;
                                col.nullable = false;
                            }
                        }
                    }
                }
                AlterTableOperation::DropConstraint { name, .. } => {
                    // By the name PostgreSQL knows it by, which for an unnamed
                    // check is the one it generated.
                    let name = ident_to_lower(&name);
                    if let Some(table) = get_table_mut(&mut self.tables, &table_key) {
                        for col in &mut table.columns {
                            col.constraints.checks.retain(|check| check.system_name != name);
                        }
                        table.other_constraints.retain(|other| other.name != name);
                    }
                }
                AlterTableOperation::ValidateConstraint { name } => {
                    let name = ident_to_lower(&name);
                    if let Some(table) = get_table_mut(&mut self.tables, &table_key) {
                        for col in &mut table.columns {
                            validate_check(&mut col.constraints.checks, &name);
                        }
                    }
                }
                AlterTableOperation::RenameConstraint { old_name, new_name } => {
                    let (old, new) = (ident_to_lower(&old_name), ident_to_lower(&new_name));
                    if let Some(table) = get_table_mut(&mut self.tables, &table_key) {
                        for col in &mut table.columns {
                            rename_check(&mut col.constraints.checks, &old, &new);
                        }
                        for other in table.other_constraints.iter_mut().filter(|other| other.name == old) {
                            other.name.clone_from(&new);
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn process_create_type(
        &mut self,
        name: ObjectName,
        repr: UserDefinedTypeRepresentation,
    ) -> Result<(), SqlkitError> {
        let type_key = object_name_to_key(&name);

        match repr {
            UserDefinedTypeRepresentation::Enum { labels } => {
                let values: Vec<String> = labels.iter().map(|l| l.value.clone()).collect();
                self.enums.insert(type_key, EnumType { values });
            }
            UserDefinedTypeRepresentation::Composite { attributes } => {
                let fields: Vec<CompositeField> = attributes
                    .iter()
                    .map(|attr| {
                        let (ft, _) = normalize_data_type(&attr.data_type, &self.domains);
                        CompositeField {
                            name: ident_to_lower(&attr.name),
                            sql_type: ft,
                            nullable: true,
                        }
                    })
                    .collect();
                self.composites.insert(type_key, CompositeType { fields });
            }
            _ => {}
        }

        Ok(())
    }

    fn process_alter_type(&mut self, name: ObjectName, operation: AlterTypeOperation) -> Result<(), SqlkitError> {
        let type_key = object_name_to_key(&name);

        match operation {
            AlterTypeOperation::AddValue(add_val) => {
                if let Some(enum_type) = self.enums.get_mut(&type_key) {
                    enum_type.values.push(add_val.value.value.clone());
                }
            }
            AlterTypeOperation::RenameValue(rename_val) => {
                if let Some(enum_type) = self.enums.get_mut(&type_key) {
                    let from = &rename_val.from.value;
                    if let Some(v) = enum_type.values.iter_mut().find(|v| v == &from) {
                        *v = rename_val.to.value.clone();
                    }
                }
            }
            AlterTypeOperation::Rename(rename) => {
                let new_key = rename.new_name.value.to_lowercase();
                if let Some(e) = self.enums.remove(&type_key) {
                    self.enums.insert(new_key.clone(), e);
                }
                if let Some(c) = self.composites.remove(&type_key) {
                    self.composites.insert(new_key, c);
                }
            }
        }

        Ok(())
    }
}

fn function_sql_type(data_type: &DataType, domains: &AHashMap<String, DomainDef>) -> String {
    match data_type {
        DataType::Custom(name, _) if lookup_qualified(domains, &object_name_to_key(name), None).is_some() => {
            object_name_to_key(name)
        }
        DataType::Array(element) => {
            let inner = match element {
                sqlparser::ast::ArrayElemTypeDef::SquareBracket(inner, _)
                | sqlparser::ast::ArrayElemTypeDef::AngleBracket(inner)
                | sqlparser::ast::ArrayElemTypeDef::Parenthesis(inner)
                | sqlparser::ast::ArrayElemTypeDef::Qualified(inner, _) => inner.as_ref(),
                sqlparser::ast::ArrayElemTypeDef::None => return "unknown[]".to_string(),
            };
            if let DataType::Custom(name, _) = inner
                && lookup_qualified(domains, &object_name_to_key(name), None).is_some()
            {
                return format!("{}[]", object_name_to_key(name));
            }
            normalize_data_type(data_type, domains).0
        }
        _ => normalize_data_type(data_type, domains).0,
    }
}

fn get_table_mut<'a>(tables: &'a mut AHashMap<String, Table>, key: &str) -> Option<&'a mut Table> {
    if tables.contains_key(key) {
        return tables.get_mut(key);
    }
    if key.contains('.') {
        // A schema-qualified key must match a real, equally-qualified
        // registration -- do not silently strip the qualifier and resolve
        // a bare-registered table. Mirrors `lookup_qualified`; see #185.
        return None;
    }
    let suffix = format!(".{key}");
    let found_key = {
        let mut candidates: Vec<&String> = tables.keys().filter(|k| k.ends_with(&suffix)).collect();
        // Deterministic regardless of `AHashMap`'s per-process-random
        // iteration order -- see #177.
        candidates.sort();
        candidates.first().map(|k| (*k).clone())
    };
    found_key.and_then(move |k| tables.get_mut(&k))
}

/// Look up `name` in `map`, tolerating a *single* schema qualifier on
/// either side of the lookup/registration boundary:
///
/// - An unqualified lookup (`"users"`) also matches an entry registered
///   under any single leading qualifier (`"public.users"`). When the catalog
///   has an explicit search path, schemas are probed in that order. Otherwise,
///   the lexicographically smallest matching key preserves the deterministic
///   legacy behavior from #177.
/// - A qualified lookup (`"wrong_schema.users"`) matches *only* an exact,
///   equally-qualified entry. It must never fall back to a bare-registered
///   entry under a different qualifier than the one asked for: doing so
///   silently accepted any schema qualifier for a bare-registered table --
///   see #185.
///
/// Shared by [`Catalog::get_table`], [`Catalog::get_enum`],
/// [`Catalog::get_composite`], [`Catalog::get_domain_base_type`], and (via
/// `super::lookup_qualified`) `type_normalizer::normalize_data_type`'s own
/// domain lookup -- keeping every domain-name resolution on one path is
/// exactly what #184 (item 3) required.
fn lookup_qualified<'a, T>(map: &'a AHashMap<String, T>, name: &str, search_path: Option<&[String]>) -> Option<&'a T> {
    let lower = name.to_lowercase();
    if let Some(value) = map.get(&lower) {
        return Some(value);
    }
    if lower.contains('.') {
        return None;
    }
    if let Some(search_path) = search_path {
        return search_path
            .iter()
            .find_map(|schema| map.get(&format!("{schema}.{lower}")));
    }
    let suffix = format!(".{lower}");
    map.iter()
        .filter(|(k, _)| k.ends_with(&suffix))
        .min_by(|(a, _), (b, _)| a.cmp(b))
        .map(|(_, v)| v)
}

/// Extract the column name referenced by a `PRIMARY KEY (...)` constraint
/// entry, normalized the same way column names are registered
/// ([`ident_to_lower`]): an unquoted identifier is lowercased, a quoted
/// identifier keeps its exact case and loses its quote characters.
/// `expr.to_string()` alone retains the quote characters themselves, which
/// then never matches a registered column name. See issue #178.
/// The pass PostgreSQL's `ALTER TABLE` runs a subcommand in
/// (`AlterTablePass` in `tablecmds.c`): drops first, then column type
/// changes, added columns (with their own constraints), added checks, other
/// added constraints, column attributes, defaults and the rest. Subcommands of one pass keep their
/// written order.
fn alter_table_pass(operation: &AlterTableOperation) -> u8 {
    match operation {
        AlterTableOperation::DropColumn { .. } | AlterTableOperation::DropConstraint { .. } => 0,
        AlterTableOperation::AlterColumn { op, .. } => match op {
            AlterColumnOperation::DropNotNull | AlterColumnOperation::DropDefault => 0,
            AlterColumnOperation::SetDataType { .. } => 1,
            AlterColumnOperation::SetNotNull => 5,
            AlterColumnOperation::SetDefault { .. } => 6,
            _ => 7,
        },
        AlterTableOperation::AddColumn { .. } => 2,
        AlterTableOperation::AddConstraint {
            constraint: TableConstraint::Check(_),
            ..
        } => 3,
        AlterTableOperation::AddConstraint { .. } => 4,
        _ => 7,
    }
}

/// The name a column option gives the constraint it declares, for the kinds
/// PostgreSQL records as constraints other than checks: `NOT NULL`, `PRIMARY
/// KEY`, `UNIQUE` and `REFERENCES`.
fn column_option_constraint_name(option: &sqlparser::ast::ColumnOptionDef) -> Option<String> {
    let own = match &option.option {
        ColumnOption::NotNull => None,
        ColumnOption::PrimaryKey(constraint) => constraint.name.as_ref(),
        ColumnOption::Unique(constraint) => constraint.name.as_ref(),
        ColumnOption::ForeignKey(constraint) => constraint.name.as_ref(),
        _ => return None,
    };
    own.or(option.name.as_ref()).map(ident_to_lower)
}

/// A table constraint other than a check that was given a name, with the
/// columns it covers.
fn named_table_constraint(constraint: &TableConstraint) -> Option<NamedConstraint> {
    let index_columns = |columns: &[sqlparser::ast::IndexColumn]| -> Vec<String> {
        columns
            .iter()
            .map(|column| pk_column_name(&column.column.expr))
            .collect()
    };
    let (name, columns) = match constraint {
        TableConstraint::PrimaryKey(c) => (c.name.as_ref(), index_columns(&c.columns)),
        TableConstraint::Unique(c) => (c.name.as_ref(), index_columns(&c.columns)),
        TableConstraint::ForeignKey(c) => (c.name.as_ref(), c.columns.iter().map(ident_to_lower).collect()),
        TableConstraint::Exclude(c) => (
            c.name.as_ref(),
            c.elements
                .iter()
                .map(|element| pk_column_name(&element.column.column.expr))
                .collect(),
        ),
        TableConstraint::PrimaryKeyUsingIndex(c) | TableConstraint::UniqueUsingIndex(c) => {
            (c.name.as_ref(), Vec::new())
        }
        _ => return None,
    };
    Some(NamedConstraint {
        name: ident_to_lower(name?),
        columns,
    })
}

fn pk_column_name(expr: &Expr) -> String {
    match expr {
        Expr::Identifier(ident) => ident_to_lower(ident),
        other => other.to_string().to_lowercase(),
    }
}

/// Byte offset of the first non-whitespace character in `s` at or after
/// `from`, or `s.len()` if none. Used by [`Catalog::try_parse_create_domain`].
fn skip_ws(s: &str, from: usize) -> usize {
    s[from..]
        .find(|c: char| !c.is_whitespace())
        .map_or(s.len(), |p| from + p)
}

/// Byte offset of the first whitespace character in `s` at or after
/// `from`, or `s.len()` if none. Used by [`Catalog::try_parse_create_domain`].
fn find_ws(s: &str, from: usize) -> usize {
    s[from..].find(char::is_whitespace).map_or(s.len(), |p| from + p)
}

fn matching_parenthesis(sql: &str, outside: &[bool], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, character) in sql[open..].char_indices() {
        if !outside[open + offset] {
            continue;
        }
        match character {
            '(' => depth += 1,
            ')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(open + offset);
                }
            }
            _ => {}
        }
    }
    None
}

fn split_top_level_commas(value: &str) -> Vec<&str> {
    let outside = sql_outside_mask(value);
    let mut fields = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;
    for (offset, character) in value.char_indices() {
        if !outside[offset] {
            continue;
        }
        match character {
            '(' | '[' => depth += 1,
            ')' | ']' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                fields.push(&value[start..offset]);
                start = offset + 1;
            }
            _ => {}
        }
    }
    fields.push(&value[start..]);
    fields
}

fn find_keyword_sequence(sql: &str, outside: &[bool], keywords: &[&str]) -> Option<usize> {
    let bytes = sql.as_bytes();
    let first = keywords.first()?;
    let mut index = 0usize;
    while index + first.len() <= bytes.len() {
        if outside[index] && keyword_at(bytes, index, first) {
            let mut cursor = index + first.len();
            let mut matched = true;
            for keyword in &keywords[1..] {
                while cursor < bytes.len() && (!outside[cursor] || bytes[cursor].is_ascii_whitespace()) {
                    cursor += 1;
                }
                if !outside.get(cursor).copied().unwrap_or(false) || !keyword_at(bytes, cursor, keyword) {
                    matched = false;
                    break;
                }
                cursor += keyword.len();
            }
            if matched {
                return Some(index);
            }
        }
        index += 1;
    }
    None
}

fn keyword_at(bytes: &[u8], index: usize, keyword: &str) -> bool {
    let end = index + keyword.len();
    end <= bytes.len()
        && bytes[index..end].eq_ignore_ascii_case(keyword.as_bytes())
        && index
            .checked_sub(1)
            .is_none_or(|previous| !is_identifier_byte(bytes[previous]))
        && bytes.get(end).is_none_or(|next| !is_identifier_byte(*next))
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn find_char_outside(sql: &str, outside: &[bool], target: char, from: usize) -> Option<usize> {
    sql[from..]
        .char_indices()
        .find(|(offset, character)| *character == target && outside[from + offset])
        .map(|(offset, _)| from + offset)
}

fn sql_outside_mask(sql: &str) -> Vec<bool> {
    enum Delimiter {
        Quote(u8),
        LineComment,
        BlockComment,
        DollarQuote(usize),
    }

    let bytes = sql.as_bytes();
    let mut outside = vec![true; bytes.len()];
    let mut index = 0usize;
    while index < bytes.len() {
        let delimiter = match bytes[index] {
            b'\'' => Some(Delimiter::Quote(b'\'')),
            b'"' => Some(Delimiter::Quote(b'"')),
            b'-' if bytes.get(index + 1) == Some(&b'-') => Some(Delimiter::LineComment),
            b'/' if bytes.get(index + 1) == Some(&b'*') => Some(Delimiter::BlockComment),
            b'$' => dollar_quote_delimiter(&sql[index..]).map(Delimiter::DollarQuote),
            _ => None,
        };
        let Some(delimiter) = delimiter else {
            index += 1;
            continue;
        };
        let start = index;
        match delimiter {
            Delimiter::Quote(quote) => {
                index += 1;
                while index < bytes.len() {
                    if quote == b'\'' && bytes[index] == b'\\' {
                        index = (index + 2).min(bytes.len());
                        continue;
                    }
                    if bytes[index] == quote {
                        if bytes.get(index + 1) == Some(&quote) {
                            index += 2;
                            continue;
                        }
                        index += 1;
                        break;
                    }
                    index += 1;
                }
            }
            Delimiter::LineComment => {
                index += 2;
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            Delimiter::BlockComment => {
                index += 2;
                let mut depth = 1usize;
                while index + 1 < bytes.len() && depth > 0 {
                    if bytes[index] == b'/' && bytes[index + 1] == b'*' {
                        depth += 1;
                        index += 2;
                    } else if bytes[index] == b'*' && bytes[index + 1] == b'/' {
                        depth -= 1;
                        index += 2;
                    } else {
                        index += 1;
                    }
                }
                if depth > 0 {
                    index = bytes.len();
                }
            }
            Delimiter::DollarQuote(delimiter_length) => {
                let tag = &sql[start..start + delimiter_length];
                index += delimiter_length;
                if let Some(close) = sql[index..].find(tag) {
                    index += close + delimiter_length;
                } else {
                    index = bytes.len();
                }
            }
        }
        outside[start..index].fill(false);
    }
    outside
}

fn dollar_quote_delimiter(value: &str) -> Option<usize> {
    let closing = value[1..].find('$')? + 1;
    value[1..closing]
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        .then_some(closing + 1)
}

/// A token of SQL other than whitespace or a comment, with the byte offset
/// it starts at.
pub(crate) struct SqlToken {
    pub(crate) offset: usize,
    pub(crate) token: sqlparser::tokenizer::Token,
}

impl SqlToken {
    /// Whether the token is the unquoted keyword `keyword`, in any case.
    pub(crate) fn is_keyword(&self, keyword: &str) -> bool {
        matches!(&self.token, sqlparser::tokenizer::Token::Word(word)
            if word.quote_style.is_none() && word.value.eq_ignore_ascii_case(keyword))
    }

    /// The identifier the token spells, as PostgreSQL stores it: a quoted
    /// one verbatim, an unquoted one lowercased.
    pub(crate) fn identifier(&self) -> Option<String> {
        match &self.token {
            sqlparser::tokenizer::Token::Word(word) if word.quote_style == Some('"') => Some(word.value.clone()),
            sqlparser::tokenizer::Token::Word(word) if word.quote_style.is_none() => Some(word.value.to_lowercase()),
            _ => None,
        }
    }
}

/// The tokens of `sql` as PostgreSQL's lexer reads them, without whitespace
/// and comments, or `None` if `sql` does not tokenize (an unterminated
/// string or quoted identifier).
pub(crate) fn sql_tokens(sql: &str) -> Option<Vec<SqlToken>> {
    use sqlparser::tokenizer::{Token, Tokenizer};
    let tokens = Tokenizer::new(&PostgreSqlDialect {}, sql)
        .tokenize_with_location()
        .ok()?;
    // The tokenizer locates a token by line (split at `\n`) and column (in
    // characters), both from 1.
    let line_starts: Vec<usize> = std::iter::once(0)
        .chain(sql.match_indices('\n').map(|(at, _)| at + 1))
        .collect();
    let offset = |location: Location| {
        let line_start = usize::try_from(location.line)
            .ok()
            .and_then(|line| line_starts.get(line.checked_sub(1)?))
            .copied()
            .unwrap_or(sql.len());
        let column = usize::try_from(location.column.saturating_sub(1)).unwrap_or(usize::MAX);
        sql[line_start..]
            .char_indices()
            .nth(column)
            .map_or(sql.len(), |(at, _)| line_start + at)
    };
    Some(
        tokens
            .into_iter()
            .filter(|token| !matches!(token.token, Token::Whitespace(_) | Token::EOF))
            .map(|token| SqlToken {
                offset: offset(token.span.start),
                token: token.token,
            })
            .collect(),
    )
}

/// Whether the words `keywords` follow each other in `sql` outside any
/// parentheses, with only whitespace and comments between them -- how
/// PostgreSQL's grammar reads a keyword sequence such as `NOT VALID`. String
/// literals, quoted identifiers and comments never match.
fn top_level_keywords(sql: &str, keywords: &[&str]) -> bool {
    use sqlparser::tokenizer::Token;
    let Some(tokens) = sql_tokens(sql) else {
        return false;
    };
    let mut depth = 0usize;
    let mut top_level = Vec::with_capacity(tokens.len());
    for token in &tokens {
        let at_top = depth == 0;
        match token.token {
            Token::LParen => depth += 1,
            Token::RParen => depth = depth.saturating_sub(1),
            _ => {}
        }
        top_level.push(at_top && depth == 0);
    }
    (0..tokens.len().saturating_sub(keywords.len() - 1)).any(|start| {
        keywords
            .iter()
            .enumerate()
            .all(|(i, keyword)| top_level[start + i] && tokens[start + i].is_keyword(keyword))
    })
}

/// Whether `keyword` (already ASCII-uppercase) appears in `haystack`
/// (already ASCII-uppercase) outside of any parenthesized group and outside
/// of any single-quoted string literal -- so a `CHECK (...)` payload
/// containing the literal text `NOT NULL` (e.g. `CHECK (VALUE <> 'NOT
/// NULL')`) is never mistaken for the `NOT NULL` constraint keyword. See
/// issue #166.
fn top_level_contains_keyword(haystack: &str, keyword: &str) -> bool {
    let bytes = haystack.as_bytes();
    let mut depth: i32 = 0;
    let mut in_quote = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if in_quote {
            if b == b'\'' {
                in_quote = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'\'' => {
                in_quote = true;
                i += 1;
                continue;
            }
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ => {}
        }
        if depth <= 0 && haystack[i..].starts_with(keyword) {
            return true;
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_create_table() {
        let catalog = Catalog::from_ddl(&["CREATE TABLE users (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                email VARCHAR(255),
                age INTEGER DEFAULT 0,
                active BOOLEAN NOT NULL DEFAULT true
            );"])
        .unwrap();

        let table = catalog.get_table("users").unwrap();
        assert_eq!(table.columns.len(), 5);

        let id = &table.columns[0];
        assert_eq!(id.name, "id");
        assert_eq!(id.sql_type, "integer");
        assert!(!id.nullable);
        assert!(id.primary_key);

        let name_col = &table.columns[1];
        assert_eq!(name_col.name, "name");
        assert_eq!(name_col.sql_type, "text");
        assert!(!name_col.nullable);

        let email = &table.columns[2];
        assert_eq!(email.name, "email");
        assert_eq!(email.sql_type, "varchar(255)");
        assert!(email.nullable);

        let age = &table.columns[3];
        assert_eq!(age.sql_type, "integer");
        assert!(age.default.is_some());

        let active = &table.columns[4];
        assert_eq!(active.sql_type, "boolean");
        assert!(!active.nullable);
    }

    #[test]
    fn test_enum_type() {
        let catalog = Catalog::from_ddl(&["CREATE TYPE mood AS ENUM ('sad', 'ok', 'happy');"]).unwrap();

        let mood = catalog.get_enum("mood").unwrap();
        assert_eq!(mood.values, vec!["sad", "ok", "happy"]);
    }

    #[test]
    fn test_composite_type() {
        let catalog = Catalog::from_ddl(&["CREATE TYPE address AS (street TEXT, city TEXT, zip INTEGER);"]).unwrap();

        let addr = catalog.get_composite("address").unwrap();
        assert_eq!(addr.fields.len(), 3);
        assert_eq!(addr.fields[0].name, "street");
        assert_eq!(addr.fields[0].sql_type, "text");
    }

    #[test]
    fn test_alter_table_add_column() {
        let catalog = Catalog::from_ddl(&[
            "CREATE TABLE t (id INTEGER);",
            "ALTER TABLE t ADD COLUMN name TEXT NOT NULL;",
        ])
        .unwrap();

        let table = catalog.get_table("t").unwrap();
        assert_eq!(table.columns.len(), 2);
        assert_eq!(table.columns[1].name, "name");
        assert!(!table.columns[1].nullable);
    }

    #[test]
    fn test_alter_type_add_value() {
        let catalog = Catalog::from_ddl(&[
            "CREATE TYPE mood AS ENUM ('sad', 'happy');",
            "ALTER TYPE mood ADD VALUE 'ok';",
        ])
        .unwrap();

        let mood = catalog.get_enum("mood").unwrap();
        assert_eq!(mood.values, vec!["sad", "happy", "ok"]);
    }

    #[test]
    fn test_serial_types() {
        let catalog = Catalog::from_ddl(&["CREATE TABLE t (
                a SERIAL,
                b BIGSERIAL,
                c SMALLSERIAL
            );"])
        .unwrap();

        let table = catalog.get_table("t").unwrap();
        assert_eq!(table.columns[0].sql_type, "integer");
        assert!(!table.columns[0].nullable);
        assert_eq!(table.columns[1].sql_type, "bigint");
        assert!(!table.columns[1].nullable);
        assert_eq!(table.columns[2].sql_type, "smallint");
        assert!(!table.columns[2].nullable);
    }

    #[test]
    fn test_table_level_primary_key() {
        let catalog = Catalog::from_ddl(&["CREATE TABLE t (
                a INTEGER,
                b TEXT,
                PRIMARY KEY (a)
            );"])
        .unwrap();

        let table = catalog.get_table("t").unwrap();
        assert!(table.columns[0].primary_key);
        assert!(!table.columns[0].nullable);
        assert!(!table.columns[1].primary_key);
    }

    #[test]
    fn test_schema_qualified_name() {
        let catalog = Catalog::from_ddl(&["CREATE TABLE public.users (id INTEGER);"]).unwrap();

        assert!(catalog.get_table("public.users").is_some());
        assert!(catalog.get_table("users").is_some());
    }

    #[test]
    fn test_array_type() {
        let catalog = Catalog::from_ddl(&["CREATE TABLE t (tags TEXT[], scores INTEGER[]);"]).unwrap();

        let table = catalog.get_table("t").unwrap();
        assert_eq!(table.columns[0].sql_type, "text[]");
        assert_eq!(table.columns[1].sql_type, "int[]");
    }

    #[test]
    fn test_timestamp_types() {
        let catalog = Catalog::from_ddl(&["CREATE TABLE t (
                a TIMESTAMP,
                b TIMESTAMP WITH TIME ZONE,
                c TIMESTAMPTZ
            );"])
        .unwrap();

        let table = catalog.get_table("t").unwrap();
        assert_eq!(table.columns[0].sql_type, "timestamp");
        assert_eq!(table.columns[1].sql_type, "timestamptz");
        assert_eq!(table.columns[2].sql_type, "timestamptz");
    }

    #[test]
    fn test_from_ddl_backward_compat() {
        let catalog = Catalog::from_ddl(&["CREATE TABLE t (id INTEGER);"]).unwrap();
        assert!(catalog.get_table("t").is_some());
    }

    #[test]
    fn test_postgresql_generated_identity_is_preserved() {
        let catalog = Catalog::from_ddl(&["CREATE TABLE test (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                name TEXT NOT NULL
            );"])
        .unwrap();

        let table = catalog.get_table("test").unwrap();
        assert_eq!(table.columns.len(), 2);
        assert_eq!(table.columns[0].name, "id");
        assert_eq!(table.columns[0].sql_type, "bigint");
        assert!(table.columns[0].primary_key);
    }

    #[test]
    fn test_identity_column_name_is_preserved() {
        let catalog = Catalog::from_ddl(&["CREATE TABLE test (
                id BIGINT PRIMARY KEY,
                identity TEXT NOT NULL,
                other INTEGER
            );"])
        .unwrap();

        let table = catalog.get_table("test").unwrap();
        assert_eq!(table.columns.len(), 3);
        assert_eq!(table.columns[1].name, "identity");
        assert_eq!(table.columns[1].sql_type, "text");
        assert!(!table.columns[1].nullable);
    }

    #[test]
    fn test_skips_psql_restrict_meta_command() {
        let schema = "\
-- PostgreSQL database dump\n\
-- Dumped from database version 18.0\n\
\n\
\\restrict pq7iUOIh6kaSGp222hdriGzvRgqMRbZgU76Lw2XJsigT6TAJ0gcLqz6yTyHGDMO\n\
\n\
SET statement_timeout = 0;\n\
SET lock_timeout = 0;\n\
SET standard_conforming_strings = on;\n\
\n\
CREATE TABLE public.t (\n\
    id uuid NOT NULL,\n\
    meta jsonb\n\
);\n\
\n\
ALTER TABLE ONLY public.t\n\
    ADD CONSTRAINT t_pkey PRIMARY KEY (id);\n\
\n\
\\unrestrict pq7iUOIh6kaSGp222hdriGzvRgqMRbZgU76Lw2XJsigT6TAJ0gcLqz6yTyHGDMO\n\
";
        let catalog = Catalog::from_ddl(&[schema]).expect("parse must succeed");

        let table = catalog.get_table("t").expect("table t must exist");
        assert_eq!(table.columns.len(), 2);

        let id_col = &table.columns[0];
        assert_eq!(id_col.name, "id");
        assert_eq!(id_col.sql_type, "uuid");
        assert!(!id_col.nullable);
        assert!(id_col.primary_key);

        let meta_col = &table.columns[1];
        assert_eq!(meta_col.name, "meta");
        assert_eq!(meta_col.sql_type, "jsonb");
        assert!(meta_col.nullable);
    }

    #[test]
    fn test_skips_leading_backslash_line() {
        let schema = "\\restrict dbmate\nCREATE TABLE items (id SERIAL PRIMARY KEY, name TEXT NOT NULL);";
        let catalog = Catalog::from_ddl(&[schema]).expect("parse must succeed");

        let table = catalog.get_table("items").expect("table items must exist");
        assert_eq!(table.columns.len(), 2);
        assert_eq!(table.columns[0].name, "id");
        assert_eq!(table.columns[0].sql_type, "integer");
        assert!(!table.columns[0].nullable);
        assert!(table.columns[0].primary_key);
        assert_eq!(table.columns[1].name, "name");
        assert!(!table.columns[1].nullable);
    }

    #[test]
    fn test_normal_ddl_without_backslash_unaffected() {
        let schema = "CREATE TABLE products (id INTEGER PRIMARY KEY, price NUMERIC(10,2) NOT NULL);";
        let catalog = Catalog::from_ddl(&[schema]).expect("parse must succeed");

        let table = catalog.get_table("products").expect("table products must exist");
        assert_eq!(table.columns.len(), 2);

        let id_col = &table.columns[0];
        assert_eq!(id_col.name, "id");
        assert_eq!(id_col.sql_type, "integer");
        assert!(!id_col.nullable);
        assert!(id_col.primary_key);

        let price_col = &table.columns[1];
        assert_eq!(price_col.name, "price");
        assert_eq!(price_col.sql_type, "numeric(10,2)");
        assert!(!price_col.nullable);
    }

    #[test]
    fn should_skip_postgresql_trigger_with_function_argument() {
        let schema = "\
CREATE TABLE audit_events (id uuid PRIMARY KEY);\n\
CREATE OR REPLACE FUNCTION audit_row() RETURNS TRIGGER LANGUAGE plpgsql AS $$\n\
BEGIN\n\
    RAISE NOTICE '%', TG_ARGV[0];\n\
    RETURN NULL;\n\
END;\n\
$$;\n\
CREATE TRIGGER audit_events_insert\n\
AFTER INSERT ON audit_events\n\
FOR EACH ROW\n\
EXECUTE FUNCTION audit_row('api_key');\n";

        let schema = format!("{schema}CREATE TABLE audit_targets (id uuid PRIMARY KEY);\n");

        let catalog =
            Catalog::from_ddl(&[&schema]).expect("PostgreSQL trigger arguments must not prevent catalog construction");

        assert_eq!(catalog.tables_iter().count(), 2);
        assert_eq!(
            catalog
                .get_table("audit_events")
                .expect("table must exist")
                .columns
                .len(),
            1
        );
        assert!(catalog.get_table("audit_targets").is_some());
    }

    #[test]
    fn should_skip_postgresql_or_replace_trigger_with_procedure_argument() {
        let schema = "\
CREATE TABLE audit_events (id uuid PRIMARY KEY);\n\
CREATE OR REPLACE TRIGGER audit_events_insert\n\
AFTER INSERT ON audit_events\n\
FOR EACH ROW\n\
EXECUTE PROCEDURE audit_row('api_key');\n";

        let schema = format!("{schema}CREATE TABLE audit_targets (id uuid PRIMARY KEY);\n");

        let catalog = Catalog::from_ddl(&[&schema])
            .expect("legacy PostgreSQL procedure trigger arguments must not prevent catalog construction");

        assert_eq!(catalog.tables_iter().count(), 2);
        assert_eq!(
            catalog
                .get_table("audit_events")
                .expect("table must exist")
                .columns
                .len(),
            1
        );
        assert!(catalog.get_table("audit_targets").is_some());
    }

    // -- #178: quoted PRIMARY KEY column names ------------------------------

    #[test]
    fn test_quoted_primary_key_name_applies_not_null() {
        // A quoted PRIMARY KEY column name retained its quotes when
        // lowercased for comparison, so it never matched the registered
        // column and the PK constraint (and the NOT NULL it implies) was
        // silently dropped.
        let catalog = Catalog::from_ddl(&[r#"CREATE TABLE t ("Id" INTEGER, note TEXT, PRIMARY KEY ("Id"));"#]).unwrap();
        let table = catalog.get_table("t").unwrap();
        let id_col = table
            .columns
            .iter()
            .find(|c| c.name == "Id")
            .expect("quoted PK column must be registered as \"Id\"");
        assert!(
            id_col.primary_key,
            "quoted PRIMARY KEY (\"Id\") must mark the column primary_key"
        );
        assert!(!id_col.nullable, "a quoted PRIMARY KEY column must still be NOT NULL");
    }

    #[test]
    fn test_quoted_primary_key_via_alter_table_add_constraint() {
        // The pg_dump `ALTER TABLE ... ADD CONSTRAINT ... PRIMARY KEY` form
        // of the same bug.
        let catalog = Catalog::from_ddl(&[
            r#"CREATE TABLE t ("UserId" INTEGER, note TEXT);"#,
            r#"ALTER TABLE t ADD CONSTRAINT t_pkey PRIMARY KEY ("UserId");"#,
        ])
        .unwrap();
        let table = catalog.get_table("t").unwrap();
        let user_id = table.columns.iter().find(|c| c.name == "UserId").unwrap();
        assert!(user_id.primary_key);
        assert!(!user_id.nullable);
    }

    // -- #183: CTAS, IF NOT EXISTS, ALTER on an unknown table ----------------

    #[test]
    fn test_create_table_as_select_registers_columns() {
        let catalog = Catalog::from_ddl(&[
            "CREATE TABLE base (id INTEGER NOT NULL, name TEXT NOT NULL);",
            "CREATE TABLE derived AS SELECT id, name FROM base;",
        ])
        .unwrap();
        let derived = catalog.get_table("derived").expect("CTAS must register a table");
        assert_eq!(
            derived.columns.len(),
            2,
            "CTAS must carry the query's projected columns, not zero"
        );
        assert_eq!(derived.columns[0].name, "id");
        assert_eq!(derived.columns[0].sql_type, "integer");
        assert_eq!(derived.columns[1].name, "name");
        assert_eq!(derived.columns[1].sql_type, "text");
    }

    #[test]
    fn test_create_table_if_not_exists_does_not_replace_existing_definition() {
        let catalog = Catalog::from_ddl(&[
            "CREATE TABLE u (id INTEGER NOT NULL, a TEXT NOT NULL);",
            "CREATE TABLE IF NOT EXISTS u (id INTEGER NOT NULL);",
        ])
        .unwrap();
        let table = catalog.get_table("u").unwrap();
        assert_eq!(
            table.columns.len(),
            2,
            "IF NOT EXISTS on an already-registered table must be a no-op"
        );
        assert!(
            table.columns.iter().any(|c| c.name == "a"),
            "column `a` from the original definition must survive"
        );
    }

    #[test]
    fn test_alter_table_add_column_on_unknown_table_errors() {
        let result = Catalog::from_ddl(&[
            "CREATE TABLE users (id INTEGER NOT NULL);",
            "ALTER TABLE userz ADD COLUMN email TEXT NOT NULL;",
        ]);
        assert!(
            result.is_err(),
            "ALTER TABLE against an unknown table must error, not silently no-op"
        );
        assert_eq!(result.unwrap_err().code, crate::errors::ErrorCode::UnknownTable);
    }

    #[test]
    fn test_alter_table_drop_column_on_unknown_table_errors() {
        let result = Catalog::from_ddl(&[
            "CREATE TABLE users (id INTEGER NOT NULL);",
            "ALTER TABLE userz DROP COLUMN id;",
        ]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, crate::errors::ErrorCode::UnknownTable);
    }

    #[test]
    fn test_alter_table_rename_table_on_unknown_table_errors() {
        // A typo'd table name in a migration's `RENAME TO` must not
        // disappear silently -- every other ALTER TABLE operation here
        // already rejects an unknown target (see the two tests above); a
        // rename that quietly no-ops is indistinguishable from a correct
        // one and leaves the catalog with neither the old nor the new name
        // registered under a real definition.
        let result = Catalog::from_ddl(&[
            "CREATE TABLE users (id INTEGER NOT NULL);",
            "ALTER TABLE userz RENAME TO people;",
        ]);
        assert!(
            result.is_err(),
            "RENAME TO against an unknown table must error, not silently no-op"
        );
        assert_eq!(result.unwrap_err().code, crate::errors::ErrorCode::UnknownTable);
    }

    #[test]
    fn test_alter_table_rename_table_on_known_table_still_renames() {
        // Regression guard alongside the error-path test above: fixing the
        // unknown-table case must not break the ordinary successful rename,
        // including keeping `raw_name` in sync with the new name.
        let catalog = Catalog::from_ddl(&[
            "CREATE TABLE users (id INTEGER NOT NULL);",
            "ALTER TABLE users RENAME TO people;",
        ])
        .unwrap();
        assert!(
            catalog.get_table("users").is_none(),
            "the old name must no longer resolve"
        );
        let renamed = catalog.get_table("people").expect("the new name must resolve");
        assert_eq!(renamed.raw_name, "people");
        assert_eq!(renamed.columns.len(), 1);
    }

    // -- #184: CREATE DOMAIN panic, schema-qualified NOT NULL ----------------

    #[test]
    fn test_create_domain_with_non_ascii_name_does_not_panic() {
        // A domain name whose uppercase form has a different byte length
        // than its original (U+FB01 "ﬁ" uppercases to the two-byte-longer
        // "FI") panicked when that offset was sliced against the original.
        let catalog = Catalog::from_ddl(&[
            "CREATE DOMAIN \u{fb01}\u{fb01} AS TEXT NOT NULL;",
            "CREATE TABLE t (id INTEGER NOT NULL);",
        ])
        .unwrap();
        assert!(catalog.get_table("t").is_some());
    }

    #[test]
    fn test_schema_qualified_domain_not_null_matches_bare_reference() {
        let catalog = Catalog::from_ddl(&[
            "CREATE DOMAIN app.nn AS TEXT NOT NULL;",
            "CREATE DOMAIN plain_nn AS TEXT NOT NULL;",
            "CREATE TABLE t (a nn, b plain_nn, c app.nn);",
        ])
        .unwrap();
        let table = catalog.get_table("t").unwrap();
        let a = table.columns.iter().find(|c| c.name == "a").unwrap();
        let b = table.columns.iter().find(|c| c.name == "b").unwrap();
        let c = table.columns.iter().find(|c| c.name == "c").unwrap();
        assert_eq!(a.sql_type, "text");
        assert!(
            !a.nullable,
            "a bare reference to a schema-qualified domain must resolve its NOT NULL the same as its type"
        );
        assert!(!b.nullable);
        assert!(!c.nullable);
    }

    // -- #166: CHECK-body substring, AS-optional, CONSTRAINT termination ----

    #[test]
    fn test_domain_check_body_containing_not_null_text_is_still_nullable() {
        let catalog = Catalog::from_ddl(&[
            "CREATE DOMAIN nickname AS TEXT CHECK (VALUE <> 'NOT NULL');",
            "CREATE DOMAIN plainname AS TEXT CHECK (VALUE <> 'x');",
            "CREATE TABLE users (id INTEGER NOT NULL, nick nickname, plain plainname);",
        ])
        .unwrap();
        let table = catalog.get_table("users").unwrap();
        let nick = table.columns.iter().find(|c| c.name == "nick").unwrap();
        let plain = table.columns.iter().find(|c| c.name == "plain").unwrap();
        assert!(
            nick.nullable,
            "a CHECK body merely containing the literal text NOT NULL must not be mistaken for the NOT NULL keyword"
        );
        assert!(plain.nullable);
    }

    #[test]
    fn test_create_domain_without_as_keyword() {
        let catalog = Catalog::from_ddl(&[
            "CREATE DOMAIN email_no_as TEXT NOT NULL;",
            "CREATE TABLE t (b email_no_as);",
        ])
        .unwrap();
        let table = catalog.get_table("t").unwrap();
        assert_eq!(table.columns[0].sql_type, "text");
        assert!(!table.columns[0].nullable);
    }

    #[test]
    fn test_create_domain_with_named_constraint_check() {
        let catalog = Catalog::from_ddl(&[
            "CREATE DOMAIN money_amount AS NUMERIC(10,2) CONSTRAINT positive_amount CHECK (VALUE > 0);",
            "CREATE TABLE t (amt money_amount);",
        ])
        .unwrap();
        let table = catalog.get_table("t").unwrap();
        assert_eq!(table.columns[0].sql_type, "numeric(10,2)");
    }

    // -- #185: bare-registered table must reject an arbitrary schema qualifier

    #[test]
    fn test_bare_table_rejects_wrong_schema_qualifier() {
        let catalog = Catalog::from_ddl(&["CREATE TABLE users (id INTEGER NOT NULL, name TEXT NOT NULL);"]).unwrap();
        assert!(catalog.get_table("users").is_some());
        assert!(
            catalog.get_table("totally_wrong_schema.users").is_none(),
            "a bare-registered table must not accept an arbitrary schema qualifier"
        );
    }

    // -- #177: deterministic ambiguous-table resolution ----------------------

    #[test]
    fn test_ambiguous_table_lookup_is_deterministic_across_instances() {
        // `get_table`'s fallback iterated `AHashMap::iter().find(...)` --
        // whose order is randomized per `AHashMap` instance -- so an
        // unqualified lookup that matched more than one schema-qualified
        // table could resolve to a different table across otherwise
        // identical catalogs.
        let ddl = [
            "CREATE TABLE a.t (acol INTEGER NOT NULL);",
            "CREATE TABLE b.t (bcol TEXT NOT NULL);",
        ];
        let first = Catalog::from_ddl(&ddl).unwrap();
        let first_col = first.get_table("t").unwrap().columns[0].name.clone();

        for _ in 0..50 {
            let catalog = Catalog::from_ddl(&ddl).unwrap();
            let col = &catalog.get_table("t").unwrap().columns[0].name;
            assert_eq!(
                *col, first_col,
                "ambiguous unqualified lookup must resolve the same way across independently constructed catalogs"
            );
        }
    }

    // -- PRIMARY KEY implies NOT NULL -----------------------------------------

    #[test]
    fn test_postgresql_primary_key_still_implies_not_null() {
        let catalog = Catalog::from_ddl(&["CREATE TABLE t (k INT PRIMARY KEY);"]).unwrap();
        let table = catalog.get_table("t").unwrap();
        let k = &table.columns[0];
        assert!(k.primary_key);
        assert!(
            !k.nullable,
            "PostgreSQL PRIMARY KEY must remain unconditionally NOT NULL"
        );
    }

    #[test]
    fn test_postgresql_composite_primary_key_still_implies_not_null() {
        let catalog = Catalog::from_ddl(&["CREATE TABLE t (a INT, b INT, PRIMARY KEY (a, b));"]).unwrap();
        let table = catalog.get_table("t").unwrap();
        let a = table.columns.iter().find(|c| c.name == "a").unwrap();
        let b = table.columns.iter().find(|c| c.name == "b").unwrap();
        assert!(!a.nullable);
        assert!(!b.nullable);
    }

    #[test]
    fn should_parse_deparsed_trim_without_characters_in_check_constraint() {
        // `pg_dump` deparses `btrim(title)` as `TRIM(BOTH FROM title)`.
        let catalog = Catalog::from_ddl(&["CREATE TABLE articles (
                title text NOT NULL,
                CONSTRAINT articles_title CHECK ((length(TRIM(BOTH FROM title)) > 0))
            );"])
        .expect("a deparsed TRIM with no characters should parse");
        assert_eq!(catalog.get_table("articles").unwrap().columns[0].name, "title");
    }

    #[test]
    fn should_catalog_function_overloads_modes_defaults_and_returns() {
        let catalog = Catalog::from_ddl(&[
            "CREATE FUNCTION item_count(prefix text DEFAULT '') RETURNS bigint LANGUAGE SQL AS 'SELECT 0';",
            "CREATE FUNCTION item_count(INOUT value integer, OUT label text) LANGUAGE SQL AS 'SELECT';",
            "CREATE FUNCTION items_named(prefix text) RETURNS SETOF text LANGUAGE SQL AS 'SELECT prefix';",
        ])
        .expect("function DDL should parse");

        let overloads = catalog
            .get_functions("item_count")
            .expect("function should be cataloged");
        assert_eq!(overloads.len(), 2);
        assert!(overloads[0].arguments[0].has_default);
        assert_eq!(overloads[1].arguments[0].mode, FunctionArgumentMode::InOut);
        assert_eq!(overloads[1].arguments[1].mode, FunctionArgumentMode::Out);
        assert!(matches!(&overloads[1].return_type, FunctionReturn::Table { columns } if columns.len() == 2));
        assert!(matches!(
            &catalog.get_functions("items_named").expect("set function")[0].return_type,
            FunctionReturn::SetOf { sql_type, .. } if sql_type == "text"
        ));
    }

    #[test]
    fn should_rewrite_returns_table_only_in_the_function_header() {
        let catalog = Catalog::from_ddl(&[
            "CREATE FUNCTION tricky(value text DEFAULT ') RETURNS TABLE(fake integer)') \
             RETURNS /* result shape */\nTABLE(real_value numeric(10, 2), label text) LANGUAGE SQL AS $$ SELECT 1, value $$;",
        ])
        .expect("quoted header text must not confuse RETURNS TABLE preprocessing");

        let function = &catalog.get_functions("tricky").expect("function should be cataloged")[0];
        assert_eq!(function.arguments.len(), 3);
        assert_eq!(function.arguments[0].name.as_deref(), Some("value"));
        assert!(matches!(
            &function.return_type,
            FunctionReturn::Table { columns }
                if columns.iter().map(|column| column.name.as_str()).collect::<Vec<_>>()
                    == vec!["real_value", "label"]
        ));
    }

    #[test]
    fn should_preserve_domain_function_signatures_for_overload_resolution() {
        let catalog = Catalog::from_ddl(&[
            "CREATE DOMAIN user_id AS integer;",
            "CREATE FUNCTION identify(value user_id) RETURNS bigint LANGUAGE SQL AS 'SELECT value';",
            "CREATE FUNCTION identify(value integer) RETURNS text LANGUAGE SQL AS 'SELECT value::text';",
        ])
        .expect("domain and base-type overloads should remain distinct");

        let overloads = catalog
            .get_functions("identify")
            .expect("overloads should be cataloged");
        assert_eq!(overloads.len(), 2);
        assert_eq!(overloads[0].arguments[0].sql_type, "user_id");
        assert_eq!(overloads[1].arguments[0].sql_type, "integer");
    }

    #[test]
    fn should_replace_only_an_identical_function_input_signature() {
        let catalog = Catalog::from_ddl(&[
            "CREATE FUNCTION f(value integer) RETURNS integer LANGUAGE SQL AS 'SELECT value';",
            "CREATE OR REPLACE FUNCTION f(value integer) RETURNS text LANGUAGE SQL AS 'SELECT value::text';",
            "CREATE FUNCTION f(value bigint) RETURNS bigint LANGUAGE SQL AS 'SELECT value';",
        ])
        .expect("replacement and overload should catalog");
        let overloads = catalog.get_functions("f").expect("function should exist");
        assert_eq!(overloads.len(), 2);
        assert!(matches!(&overloads[0].return_type, FunctionReturn::Scalar { sql_type, .. } if sql_type == "text"));
    }

    #[test]
    fn should_include_functions_in_schema_fingerprint() {
        let integer =
            Catalog::from_ddl(&["CREATE FUNCTION f(value integer) RETURNS integer LANGUAGE SQL AS 'SELECT value';"])
                .expect("integer function");
        let text = Catalog::from_ddl(&["CREATE FUNCTION f(value text) RETURNS text LANGUAGE SQL AS 'SELECT value';"])
            .expect("text function");
        assert_ne!(integer.fingerprint(), text.fingerprint());
    }
}
