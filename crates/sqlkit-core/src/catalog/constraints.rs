//! The constraints the catalog records per column and per domain, and their
//! resolution into [`ValueConstraints`].

use ahash::{AHashMap, AHashSet};
use sqlparser::ast::{ColumnOption, ColumnOptionDef, DataType, Expr, ObjectName, ObjectNamePart};

use super::type_normalizer::{ident_to_lower, normalize_data_type, object_name_to_key};
use super::{Catalog, DomainDef, lookup_qualified};
use crate::constraints::{
    SmartComment, TextComparison, Translation, Untranslated, ValueConstraints, referenced_columns, translate_check,
};

/// A relation's column, by catalog key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ColumnOrigin {
    pub relation: String,
    pub column: String,
}

impl ColumnOrigin {
    /// `table.column`, the relation without its schema -- how the schema
    /// constraints name a column, and the key a per-column type is looked up by.
    pub fn name(&self) -> String {
        format!("{}.{}", super::type_normalizer::bare_name(&self.relation), self.column)
    }
}

/// What the schema declares about a column's (or a domain's) values.
#[derive(Debug, Clone, Default)]
pub struct ColumnConstraints {
    /// The domain the column is declared with, or a domain's parent domain.
    pub domain: Option<String>,
    /// `n` of `varchar(n)`/`char(n)`, as the normalized SQL type spells it;
    /// `None` for a column declared with a domain, whose own length applies.
    pub max_length: Option<u64>,
    /// The collation an explicit `COLLATE` names.
    pub collation: Option<Collation>,
    pub checks: Vec<CheckConstraint>,
    /// `COMMENT ON COLUMN` / `COMMENT ON DOMAIN` text, as written: see
    /// [`SmartComment`] for how it is read.
    pub comment: Option<String>,
    /// For a view column that reads another relation's column unchanged: that
    /// column, whose constraints it shares.
    pub origin: Option<ColumnOrigin>,
}

impl ColumnConstraints {
    /// The facts a column's declared type and options contribute.
    pub(crate) fn from_type(
        data_type: &DataType,
        options: &[ColumnOptionDef],
        domains: &AHashMap<String, DomainDef>,
    ) -> Self {
        let mut facts = Self::default();
        facts.retype(data_type, domains);
        facts.collation = collation(options);
        facts
    }

    /// Replace the facts that come from the declared type, keeping checks,
    /// comment and origin -- `ALTER COLUMN ... TYPE`, which also resets the
    /// collation to the new type's default.
    pub(crate) fn retype(&mut self, data_type: &DataType, domains: &AHashMap<String, DomainDef>) {
        self.domain = match data_type {
            DataType::Custom(name, _) => {
                let key = object_name_to_key(name);
                lookup_qualified(domains, &key, None).map(|_| key)
            }
            _ => None,
        };
        self.max_length = match self.domain {
            Some(_) => None,
            None => max_length(&normalize_data_type(data_type, domains).0),
        };
        self.collation = None;
    }
}

/// The `n` of a normalized `varchar(n)` or `char(n)`.
fn max_length(sql_type: &str) -> Option<u64> {
    sql_type
        .strip_prefix("varchar(")
        .or_else(|| sql_type.strip_prefix("char("))?
        .strip_suffix(')')?
        .parse()
        .ok()
}

/// The collation a column's `COLLATE` option names.
fn collation(options: &[ColumnOptionDef]) -> Option<Collation> {
    options.iter().find_map(|option| match &option.option {
        ColumnOption::Collation(name) => Collation::from_sql(name),
        _ => None,
    })
}

/// A collation, by the name PostgreSQL stores it under
/// (`pg_collation.collname`). Collation names are identifiers, so they are
/// case-sensitive once read: `COLLATE "C"` names the C collation, while an
/// unquoted `COLLATE C` names `c`, which PostgreSQL does not have.
///
/// The schema is not kept, as a live catalog reports the name alone: a
/// collation named `C`, `POSIX` or `default` created outside `pg_catalog`
/// would be taken for the built-in one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Collation(String);

impl Collation {
    /// The collation stored as `name`, as `pg_collation.collname` reads.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// The collation an SQL name refers to: a quoted identifier verbatim, an
    /// unquoted one lowercased, without its schema.
    pub(crate) fn from_sql(name: &ObjectName) -> Option<Self> {
        match name.0.last()? {
            ObjectNamePart::Identifier(ident) => Some(Self(ident_to_lower(ident))),
            _ => None,
        }
    }

    pub fn name(&self) -> &str {
        &self.0
    }

    /// Whether text compares byte by byte under the collation: the
    /// database default (deterministic, as every database default is), `C`
    /// or `POSIX`.
    pub fn compares_bytes(&self) -> bool {
        matches!(self.0.as_str(), "default" | "C" | "POSIX")
    }
}

impl std::fmt::Display for Collation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One `CHECK` constraint on a single value.
#[derive(Debug, Clone)]
pub struct CheckConstraint {
    /// The name the DDL gave the constraint.
    pub name: Option<String>,
    /// The name PostgreSQL knows the constraint by: [`Self::name`], or the
    /// one it generates for an unnamed check (see [`generated_check_name`]).
    pub system_name: String,
    /// The check's expression as SQL.
    pub sql: String,
    /// `false` for a check added `NOT VALID` and not validated since: rows
    /// written before it may violate it.
    pub validated: bool,
    /// The parsed expression; `None` when it could not be parsed.
    expr: Option<Expr>,
    /// What the expression calls the constrained value: the column's name
    /// when the check was added (renaming the column later does not rewrite
    /// it here), or `value` in a domain.
    subject: String,
}

impl CheckConstraint {
    /// A check on `subject` (a column name, or `value` in a domain).
    pub(crate) fn new(name: Option<String>, system_name: String, expr: &Expr, subject: &str) -> Self {
        Self {
            name,
            system_name,
            sql: expr.to_string(),
            validated: true,
            expr: Some(expr.clone()),
            subject: subject.to_string(),
        }
    }

    /// A check whose expression could not be parsed: kept, untranslated.
    pub(crate) fn unparsed(name: Option<String>, system_name: String, sql: &str) -> Self {
        Self {
            name,
            system_name,
            sql: sql.to_string(),
            validated: true,
            expr: None,
            subject: String::new(),
        }
    }

    /// The rules this check translates to, for a value whose text compares
    /// as `text` says.
    fn translate(&self, text: &TextComparison) -> Translation {
        match &self.expr {
            Some(expr) => translate_check(expr, &self.subject, text),
            None => Translation {
                untranslated: vec![(self.sql.clone(), "the expression could not be parsed".to_string())],
                ..Translation::default()
            },
        }
    }
}

/// PostgreSQL's maximum identifier length in bytes (`NAMEDATALEN - 1`).
const MAX_IDENTIFIER_BYTES: usize = 63;

/// The name PostgreSQL gives an unnamed check: `<table>_<column>_check` for
/// one that references a single column, `<table>_check` for one that
/// references several, `<domain>_check` for a domain's. This is
/// `ChooseConstraintName`: the parts are truncated (the longer one first) so
/// the name fits in 63 bytes, and when the name is `taken` by another
/// constraint in the schema the label becomes `check1`, `check2`, ...
///
/// `taken` holds the names of the constraints of the schema (see
/// [`Catalog::constraint_names`]) and those the statement has already named:
/// the `others` list PostgreSQL passes, of the checks named before this one.
pub(crate) fn generated_check_name(name1: &str, name2: Option<&str>, taken: &AHashSet<String>) -> String {
    let mut label = "check".to_string();
    let mut pass = 0;
    loop {
        let name = make_object_name(name1, name2, &label);
        if !taken.contains(&name) {
            return name;
        }
        pass += 1;
        label = format!("check{pass}");
    }
}

/// PostgreSQL's `makeObjectName`.
fn make_object_name(name1: &str, name2: Option<&str>, label: &str) -> String {
    let overhead = label.len() + 1 + usize::from(name2.is_some());
    let available = MAX_IDENTIFIER_BYTES.saturating_sub(overhead);
    let (mut chars1, mut chars2) = (name1.len(), name2.map_or(0, str::len));
    while chars1 + chars2 > available {
        if chars1 > chars2 {
            chars1 -= 1;
        } else {
            chars2 -= 1;
        }
    }
    let clip = |name: &str, len: usize| name[..name.floor_char_boundary(len)].to_string();
    let mut out = clip(name1, chars1);
    if let Some(name2) = name2 {
        out.push('_');
        out.push_str(&clip(name2, chars2));
    }
    out.push('_');
    out.push_str(label);
    out
}

/// The single column a table-level (or column-level) check constrains, or
/// `None` when it references several -- those relate columns to each other and
/// are not value rules.
pub(crate) fn single_column(expr: &Expr) -> Option<String> {
    match referenced_columns(expr).as_slice() {
        [only] => Some(only.clone()),
        _ => None,
    }
}

/// How many domain or view hops resolution follows before giving up, which
/// only a cyclic definition reaches.
const MAX_DEPTH: usize = 16;

/// What a value's constraints are resolved for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Use {
    /// A value read from the database: only validated checks hold for every
    /// stored row.
    Read,
    /// A value written into the database: every check, validated or not,
    /// applies to it.
    Write,
}

impl Catalog {
    /// The constraints the schema declares on values read from
    /// `relation.column`, or `None` when it declares none. A check added
    /// `NOT VALID` is left out: rows written before it may violate it.
    pub fn column_constraints(&self, relation: &str, column: &str) -> Option<ValueConstraints> {
        let mut out = ValueConstraints::default();
        self.resolve_column(relation, column, Use::Read, &mut out, 0);
        (!out.is_empty()).then_some(out)
    }

    /// The constraints a value written into `relation.column` must satisfy,
    /// or `None` when the schema declares none: [`Self::column_constraints`]
    /// and the checks added `NOT VALID`, which PostgreSQL enforces on every
    /// write.
    pub fn written_column_constraints(&self, relation: &str, column: &str) -> Option<ValueConstraints> {
        let mut out = ValueConstraints::default();
        self.resolve_column(relation, column, Use::Write, &mut out, 0);
        (!out.is_empty()).then_some(out)
    }

    /// The column `relation.column` reads unchanged, following views to the
    /// table column underneath; the column itself when it is a table's, or a
    /// view's that computes its value.
    pub fn base_column(&self, relation: &str, column: &str) -> ColumnOrigin {
        let mut base = ColumnOrigin {
            relation: relation.to_string(),
            column: column.to_string(),
        };
        for _ in 0..MAX_DEPTH {
            match self
                .column_constraint_facts(&base.relation, &base.column)
                .and_then(|facts| facts.origin.as_ref())
            {
                Some(origin) => base = origin.clone(),
                None => break,
            }
        }
        base
    }

    /// The constraints a domain declares on its values, including its parent
    /// domains', or `None` when it is not a domain or declares none. Like
    /// [`Self::column_constraints`], it leaves out checks added `NOT VALID`.
    pub fn domain_constraints(&self, name: &str) -> Option<ValueConstraints> {
        let mut out = ValueConstraints::default();
        self.resolve_domain(name, Use::Read, &mut out, 0);
        (!out.is_empty()).then_some(out)
    }

    /// The raw constraint facts recorded for `relation.column`.
    pub fn column_constraint_facts(&self, relation: &str, column: &str) -> Option<&ColumnConstraints> {
        self.find_column(relation, column).map(|c| &c.constraints)
    }

    /// The raw constraint facts recorded for the domain `name`.
    pub fn domain_constraint_facts(&self, name: &str) -> Option<&ColumnConstraints> {
        lookup_qualified(&self.domains, name, self.search_path.as_deref()).map(|d| &d.constraints)
    }

    fn find_column(&self, relation: &str, column: &str) -> Option<&super::Column> {
        let table = self.get_table(relation)?;
        let column = column.to_lowercase();
        table.columns.iter().find(|c| c.name == column)
    }

    /// The schema the relation or domain keyed `key` lives in: its qualifier,
    /// or for a bare name the schema PostgreSQL creates it in, the first on
    /// the search path (`public` when the catalog has none).
    pub(crate) fn namespace_of<'a>(&'a self, key: &'a str) -> &'a str {
        match key.rsplit_once('.') {
            Some((schema, _)) => schema,
            None => self
                .search_path
                .as_ref()
                .and_then(|path| path.first())
                .map_or("public", String::as_str),
        }
    }

    /// The names of the constraints the catalog records in `namespace`, of
    /// relations and domains alike, which an unnamed check's generated name
    /// must not take: PostgreSQL's `ChooseConstraintName` rejects a name any
    /// constraint of the schema already has, whatever its kind or owner.
    ///
    /// Only explicitly named non-check constraints are recorded: the names
    /// PostgreSQL generates for them end in `pkey`, `key`, `fkey`, `excl` or
    /// `not_null` (with an optional number), never in `check`, so they cannot
    /// collide with a generated check name.
    pub(crate) fn constraint_names(&self, namespace: &str) -> AHashSet<String> {
        let mut names = AHashSet::new();
        for (key, table) in &self.tables {
            if self.namespace_of(key) == namespace {
                let checks = table.columns.iter().flat_map(|c| &c.constraints.checks);
                names.extend(checks.map(|check| check.system_name.clone()));
                names.extend(table.other_constraints.iter().map(|c| c.name.clone()));
            }
        }
        for (key, domain) in &self.domains {
            if self.namespace_of(key) == namespace {
                names.extend(domain.constraints.checks.iter().map(|check| check.system_name.clone()));
                names.extend(domain.other_constraints.iter().cloned());
            }
        }
        names
    }

    fn resolve_column(&self, relation: &str, column: &str, use_: Use, out: &mut ValueConstraints, depth: usize) {
        if depth > MAX_DEPTH {
            return;
        }
        let Some(found) = self.find_column(relation, column) else {
            return;
        };
        let facts = &found.constraints;
        if let Some(origin) = &facts.origin {
            self.resolve_column(&origin.relation, &origin.column, use_, out, depth + 1);
        }
        let source = format!(
            "{}.{}",
            super::type_normalizer::bare_name(relation),
            column.to_lowercase()
        );
        self.apply_facts(facts, &found.sql_type, &source, use_, out, depth);
    }

    fn resolve_domain(&self, name: &str, use_: Use, out: &mut ValueConstraints, depth: usize) {
        if depth > MAX_DEPTH {
            return;
        }
        let Some(domain) = lookup_qualified(&self.domains, name, self.search_path.as_deref()) else {
            return;
        };
        let source = format!("domain {}", name.to_lowercase());
        self.apply_facts(&domain.constraints, &domain.base_type, &source, use_, out, depth);
        out.domain = Some(name.to_lowercase());
    }

    fn apply_facts(
        &self,
        facts: &ColumnConstraints,
        sql_type: &str,
        source: &str,
        use_: Use,
        out: &mut ValueConstraints,
        depth: usize,
    ) {
        if let Some(domain) = &facts.domain {
            self.resolve_domain(domain, use_, out, depth + 1);
        }
        // `numeric(p, s)` precision is deliberately not a rule, like an integer
        // type's range: PostgreSQL rounds to the scale rather than rejecting,
        // and generated code commonly carries decimals as strings.
        let length = crate::constraints::Rules {
            max_length: facts.max_length,
            ..Default::default()
        };
        out.add_rules(&length, source, "");
        let text = self.text_comparison(facts, sql_type);
        for check in &facts.checks {
            if use_ == Use::Read && !check.validated {
                continue;
            }
            let constraint = |sql: &str| match &check.name {
                Some(name) => format!("{name} CHECK ({sql})"),
                None => format!("CHECK ({sql})"),
            };
            let translation = check.translate(&text);
            out.add_rules(&translation.rules, source, &constraint(&check.sql));
            for (sql, reason) in translation.untranslated {
                let entry = Untranslated {
                    source: source.to_string(),
                    constraint: constraint(&sql),
                    reason,
                };
                if !out.untranslated.contains(&entry) {
                    out.untranslated.push(entry);
                }
            }
        }
        if let Some(comment) = &facts.comment {
            // A column's comment overrides its domain's, part by part.
            let comment = SmartComment::parse(comment);
            if comment.description.is_some() {
                out.description = comment.description;
            }
            if !comment.tags.is_empty() {
                out.tags = comment.tags;
            }
        }
    }

    /// How a value of `sql_type` with `facts` compares as text in its checks:
    /// `citext` folds case, and a collation (its own, or the nearest one its
    /// domains declare) other than the default, `C` or `POSIX` may compare
    /// strings equal that differ in bytes.
    fn text_comparison(&self, facts: &ColumnConstraints, sql_type: &str) -> TextComparison {
        if sql_type == "citext" || sql_type.ends_with(".citext") {
            return TextComparison::Inexact("`citext` compares text case-insensitively".to_string());
        }
        let mut collation = facts.collation.clone();
        let mut domain = facts.domain.clone();
        for _ in 0..MAX_DEPTH {
            if collation.is_some() {
                break;
            }
            let Some(def) = domain.and_then(|d| lookup_qualified(&self.domains, &d, self.search_path.as_deref()))
            else {
                break;
            };
            collation = def.constraints.collation.clone();
            domain = def.constraints.domain.clone();
        }
        match collation {
            Some(collation) if !collation.compares_bytes() => TextComparison::Inexact(format!(
                "text compares under the collation \"{collation}\", which need not be byte by byte"
            )),
            _ => TextComparison::Exact,
        }
    }
}

/// The table key and column of a `COMMENT ON COLUMN` target.
pub(crate) fn comment_column_target(name: &ObjectName) -> Option<(String, String)> {
    let key = object_name_to_key(name);
    let (relation, column) = key.rsplit_once('.')?;
    Some((relation.to_string(), column.to_string()))
}

/// A constraint of a relation the catalog records by name only: a check
/// that relates several columns (or none), or a primary key, unique, foreign
/// key, exclusion or not-null constraint given an explicit name. Their names
/// count in the schema's constraint namespace (see
/// [`Catalog::constraint_names`]).
#[derive(Debug, Clone)]
pub(crate) struct NamedConstraint {
    pub(crate) name: String,
    /// The columns it covers, which dropping any of drops it.
    pub(crate) columns: Vec<String>,
}

/// Attach a check on `table` to the one column it constrains, naming it as
/// PostgreSQL would when it is unnamed and recording that name in `taken`. A
/// check on several columns (or none) relates values to each other: it is
/// recorded by name only.
pub(crate) fn attach_check(
    table: &mut super::Table,
    name: Option<String>,
    expr: &Expr,
    validated: bool,
    taken: &mut AHashSet<String>,
) {
    let column = single_column(expr);
    let system_name = name
        .clone()
        .unwrap_or_else(|| generated_check_name(&table.raw_name, column.as_deref(), taken));
    taken.insert(system_name.clone());
    let target = column
        .as_ref()
        .and_then(|column| table.columns.iter_mut().find(|c| &c.name == column));
    match (column, target) {
        (Some(column), Some(target)) => {
            let mut check = CheckConstraint::new(name, system_name, expr, &column);
            check.validated = validated;
            target.constraints.checks.push(check);
        }
        _ => table.other_constraints.push(NamedConstraint {
            name: system_name,
            columns: referenced_columns(expr),
        }),
    }
}

/// A constraint of a `CREATE DOMAIN` statement's tail (everything after the
/// base type), or of an `ALTER DOMAIN ... ADD`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DomainConstraint {
    /// `[CONSTRAINT name] CHECK (body)`.
    Check { name: Option<String>, body: String },
    /// `CONSTRAINT name NOT NULL`: only its name matters here.
    NamedNotNull(String),
}

/// The constraints of a `CREATE DOMAIN` statement's tail or an `ALTER DOMAIN
/// ... ADD`, in the order written: the checks, and the not-null constraints
/// given a name.
pub(crate) fn domain_constraints(tail: &str) -> Vec<DomainConstraint> {
    use sqlparser::tokenizer::Token;
    let Some(tokens) = super::sql_tokens(tail) else {
        return Vec::new();
    };
    // The index of the `)` closing the `(` at `open`.
    let closing = |open: usize| {
        let mut depth = 0usize;
        (open..tokens.len()).find(|&at| {
            match tokens[at].token {
                Token::LParen => depth += 1,
                Token::RParen => depth = depth.saturating_sub(1),
                _ => {}
            }
            depth == 0
        })
    };
    let mut constraints = Vec::new();
    let mut name: Option<String> = None;
    let mut index = 0usize;
    while let Some(token) = tokens.get(index) {
        index += 1;
        if token.token == Token::LParen {
            // A parenthesized group outside a check (a typmod, a `DEFAULT`
            // expression) holds no constraint keywords.
            index = closing(index - 1).map_or(tokens.len(), |close| close + 1);
        } else if token.is_keyword("CONSTRAINT") {
            name = tokens.get(index).and_then(super::SqlToken::identifier);
            index += 1;
        } else if token.is_keyword("NOT") {
            if let Some(name) = name.take() {
                constraints.push(DomainConstraint::NamedNotNull(name));
            }
        } else if token.is_keyword("NULL") {
            // `NULL` is not stored, and neither is the name given to it.
            name = None;
        } else if token.is_keyword("CHECK") {
            let Some(close) = tokens
                .get(index)
                .filter(|open| open.token == Token::LParen)
                .and_then(|_| closing(index))
            else {
                break;
            };
            constraints.push(DomainConstraint::Check {
                name: name.take(),
                body: tail[tokens[index].offset + 1..tokens[close].offset].trim().to_string(),
            });
            index = close + 1;
        }
    }
    constraints
}

impl Catalog {
    /// A domain's check from the SQL of its expression, named `name` or as
    /// PostgreSQL names an unnamed one, recording the name in `taken`.
    pub(crate) fn domain_check(
        &self,
        domain: &str,
        name: Option<String>,
        body: &str,
        taken: &mut AHashSet<String>,
    ) -> CheckConstraint {
        let bare = super::type_normalizer::bare_name(domain);
        let system_name = name.clone().unwrap_or_else(|| generated_check_name(bare, None, taken));
        taken.insert(system_name.clone());
        check_from_sql(name, system_name, body, "value")
    }
}

/// A check from the SQL of its expression, as written in DDL or as
/// PostgreSQL prints it back.
fn check_from_sql(name: Option<String>, system_name: String, body: &str, subject: &str) -> CheckConstraint {
    let body = crate::parser::spell_out_default_trim_characters(body);
    let parsed = sqlparser::parser::Parser::new(&sqlparser::dialect::PostgreSqlDialect {})
        .try_with_sql(&body)
        .and_then(|mut parser| parser.parse_expr());
    match parsed {
        Ok(expr) => CheckConstraint::new(name, system_name, &expr, subject),
        Err(_) => CheckConstraint::unparsed(name, system_name, &body),
    }
}

/// A check read from a live database's `pg_constraint`: `conname`, the
/// expression as `pg_get_expr` prints it, and whether it is validated.
/// `owner` is the relation or domain it belongs to and `column` the one
/// column of a relation it constrains.
///
/// The database does not say whether a name was written or generated: one
/// PostgreSQL would have generated for the check (see
/// [`generated_check_name`]) is taken as generated, so the check reads the
/// same as the DDL that created it.
///
/// `base_type` is the constrained value's type with every domain resolved,
/// normalized: PostgreSQL's casts of the value to it are dropped (see
/// [`strip_base_type_casts`]).
pub(crate) fn inspected_check(
    conname: &str,
    owner: &str,
    column: Option<&str>,
    expression: &str,
    validated: bool,
    base_type: Option<&str>,
) -> CheckConstraint {
    let digits = &conname[conname.trim_end_matches(|c: char| c.is_ascii_digit()).len()..];
    let label = format!("check{digits}");
    let generated =
        make_object_name(owner, column, &label) == conname && (digits.is_empty() || !digits.starts_with('0'));
    let name = (!generated).then(|| conname.to_string());
    let mut check = check_from_sql(name, conname.to_string(), expression, column.unwrap_or("value"));
    if let Some(mut expr) = check.expr.take() {
        // `pg_get_expr` wraps the whole expression in parentheses.
        if let Expr::Nested(inner) = expr {
            expr = *inner;
        }
        if let Some(base_type) = base_type {
            strip_base_type_casts(&mut expr, &check.subject, base_type);
        }
        check.sql = expr.to_string();
        check.expr = Some(expr);
    }
    check.validated = validated;
    check
}

/// Remove the casts of `subject` to `base_type` (normalized) from `expr`.
///
/// PostgreSQL applies an operator to a domain value through the value's base
/// type, and prints that coercion back as a cast: `CHECK (VALUE > 0)` on a
/// domain over another integer domain reads back as `(VALUE)::integer > 0`,
/// and so does `CHECK (goal > 0)` on a column of that domain. The cast does
/// not change the value, so the check reads as written.
fn strip_base_type_casts(expr: &mut Expr, subject: &str, base_type: &str) {
    use sqlparser::ast::{CastKind, visit_expressions_mut};
    let _ = visit_expressions_mut(expr, |node| {
        if let Expr::Cast {
            kind: CastKind::Cast | CastKind::DoubleColon,
            expr: inner,
            data_type,
            ..
        } = node
        {
            let mut operand = inner.as_ref();
            while let Expr::Nested(nested) = operand {
                operand = nested;
            }
            let is_subject = matches!(operand, Expr::Identifier(ident) if ident.value.eq_ignore_ascii_case(subject));
            if is_subject && normalize_data_type(data_type, &AHashMap::new()).0 == base_type {
                *node = operand.clone();
            }
        }
        std::ops::ControlFlow::<()>::Continue(())
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_generate_postgresql_check_names() {
        let mut taken = AHashSet::new();
        assert_eq!(generated_check_name("users", Some("age"), &taken), "users_age_check");
        assert_eq!(generated_check_name("users", None, &taken), "users_check");
        taken.insert("users_age_check".to_string());
        taken.insert("users_age_check1".to_string());
        assert_eq!(generated_check_name("users", Some("age"), &taken), "users_age_check2");
    }

    /// Each relation's constraint names the catalog records, as
    /// `relation: name` sorted; what PostgreSQL 18 names the same DDL.
    fn all_names(catalog: &Catalog) -> Vec<String> {
        let mut names = Vec::new();
        for (key, table) in &catalog.tables {
            for check in table.columns.iter().flat_map(|c| &c.constraints.checks) {
                names.push(format!("{key}: {}", check.system_name));
            }
            names.extend(table.other_constraints.iter().map(|c| format!("{key}: {}", c.name)));
        }
        for (key, domain) in &catalog.domains {
            for check in &domain.constraints.checks {
                names.push(format!("{key}: {}", check.system_name));
            }
            names.extend(domain.other_constraints.iter().map(|c| format!("{key}: {c}")));
        }
        names.sort();
        names
    }

    #[test]
    fn should_name_checks_on_several_columns_like_postgresql() {
        let catalog = Catalog::from_ddl(&[
            "CREATE TABLE t (a int, b int, CONSTRAINT t_a_check UNIQUE (b), CHECK (a < b));",
            "ALTER TABLE t DROP CONSTRAINT t_check;",
            "ALTER TABLE t DROP COLUMN b;",
            "ALTER TABLE t ADD CHECK (a > 0), ADD CHECK (a <> b2), ADD COLUMN b2 int;",
            "ALTER TABLE t RENAME CONSTRAINT t_check TO renamed;",
            "ALTER TABLE t ADD CHECK (a <> 1);",
            "ALTER TABLE t ADD CHECK (a < b2);",
            "CREATE TABLE m (a int, b int, CHECK (a < b), CHECK (b > a), CONSTRAINT m_check2 CHECK (a <> b), \
             CHECK (a + b > 0));",
            "ALTER TABLE m RENAME COLUMN b TO c;",
            "ALTER TABLE m ADD CHECK (a < c);",
        ])
        .unwrap();
        assert_eq!(
            all_names(&catalog),
            [
                "m: m_check",
                "m: m_check1",
                "m: m_check2",
                "m: m_check3",
                "m: m_check4",
                "t: renamed",
                "t: t_a_check",
                "t: t_a_check1",
                "t: t_check",
            ]
        );
    }

    #[test]
    fn should_name_domain_checks_in_written_order_around_named_constraints() {
        let catalog = Catalog::from_ddl(&[
            "CREATE DOMAIN d1 AS int CHECK (VALUE > 0) CHECK (VALUE < 9) CONSTRAINT d1_check2 CHECK (VALUE <> 3) \
             CHECK (VALUE <> 4);",
            "CREATE DOMAIN d2 AS int CONSTRAINT d2_check NOT NULL CHECK (VALUE > 0);",
            "CREATE DOMAIN d3 AS int CONSTRAINT ignored NULL CHECK (VALUE > 0);",
            "CREATE DOMAIN d4 AS int;",
            "ALTER DOMAIN d4 ADD CONSTRAINT d4_check NOT NULL;",
            "ALTER DOMAIN d4 ADD CHECK (VALUE > 0);",
        ])
        .unwrap();
        assert_eq!(
            all_names(&catalog),
            [
                "d1: d1_check",
                "d1: d1_check1",
                "d1: d1_check2",
                "d1: d1_check3",
                "d2: d2_check",
                "d2: d2_check1",
                "d3: d3_check",
                "d4: d4_check",
                "d4: d4_check1",
            ]
        );
    }

    #[test]
    fn should_truncate_generated_check_names_to_63_bytes() {
        let table = "t".repeat(40);
        let column = "c".repeat(40);
        let name = generated_check_name(&table, Some(&column), &AHashSet::new());
        // 63 - "_check".len() - "_".len() = 56 bytes, split evenly.
        assert_eq!(name, format!("{}_{}_check", "t".repeat(28), "c".repeat(28)));
        assert_eq!(name.len(), 63);
        let short = generated_check_name("t", Some(&"c".repeat(70)), &AHashSet::new());
        assert_eq!(short, format!("t_{}_check", "c".repeat(55)));
        // Multi-byte characters are clipped at a character boundary.
        let wide = generated_check_name(&"é".repeat(40), None, &AHashSet::new());
        assert!(wide.len() <= 63 && wide.ends_with("_check"), "{wide}");
    }
}
