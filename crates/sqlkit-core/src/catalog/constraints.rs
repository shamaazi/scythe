//! The constraints the catalog records per column and per domain, and their
//! resolution into [`ValueConstraints`].

use ahash::{AHashMap, AHashSet};
use sqlparser::ast::{ColumnOption, ColumnOptionDef, DataType, Expr, ObjectName};

use super::type_normalizer::{normalize_data_type, object_name_to_key};
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
    /// The collation an explicit `COLLATE` names, lowercased and unqualified.
    pub collation: Option<String>,
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
fn collation(options: &[ColumnOptionDef]) -> Option<String> {
    options.iter().find_map(|option| match &option.option {
        ColumnOption::Collation(name) => Some(collation_name(name)),
        _ => None,
    })
}

/// A collation's name, lowercased and without its schema.
pub(crate) fn collation_name(name: &ObjectName) -> String {
    super::type_normalizer::bare_name(&object_name_to_key(name)).to_string()
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
/// `taken` holds the names of the checks this catalog records; constraints it
/// does not record (keys, other schemas' checks) are not considered, and
/// neither are checks on several columns from earlier statements.
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

    fn find_column(&self, relation: &str, column: &str) -> Option<&super::Column> {
        let table = self.get_table(relation)?;
        let column = column.to_lowercase();
        table.columns.iter().find(|c| c.name == column)
    }

    /// The names of every check the catalog records, which an unnamed
    /// check's generated name must not take.
    pub(crate) fn check_names(&self) -> AHashSet<String> {
        let tables = self
            .tables
            .values()
            .flat_map(|t| t.columns.iter().map(|c| &c.constraints));
        let domains = self.domains.values().map(|d| &d.constraints);
        tables
            .chain(domains)
            .flat_map(|facts| facts.checks.iter().map(|check| check.system_name.clone()))
            .collect()
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
        match collation.as_deref() {
            None | Some("default" | "c" | "posix") => TextComparison::Exact,
            Some(name) => TextComparison::Inexact(format!(
                "text compares under the collation \"{name}\", which need not be byte by byte"
            )),
        }
    }
}

/// The table key and column of a `COMMENT ON COLUMN` target.
pub(crate) fn comment_column_target(name: &ObjectName) -> Option<(String, String)> {
    let key = object_name_to_key(name);
    let (relation, column) = key.rsplit_once('.')?;
    Some((relation.to_string(), column.to_string()))
}

/// Attach a check on `table` to the one column of `columns` it constrains,
/// naming it as PostgreSQL would when it is unnamed and recording that name
/// in `taken`. A check on several columns (or none) relates values to each
/// other and is not recorded, though its generated name is taken.
pub(crate) fn attach_check(
    table: &str,
    columns: &mut [super::Column],
    name: Option<String>,
    expr: &Expr,
    validated: bool,
    taken: &mut AHashSet<String>,
) {
    let column = single_column(expr);
    let system_name = name
        .clone()
        .unwrap_or_else(|| generated_check_name(table, column.as_deref(), taken));
    taken.insert(system_name.clone());
    let Some(column) = column else {
        return;
    };
    if let Some(target) = columns.iter_mut().find(|c| c.name == column) {
        let mut check = CheckConstraint::new(name, system_name, expr, &column);
        check.validated = validated;
        target.constraints.checks.push(check);
    }
}

/// The `CHECK` constraints of a `CREATE DOMAIN` statement's tail (everything
/// after the base type), or of an `ALTER DOMAIN ... ADD`, as
/// `(constraint name, expression SQL)`.
pub(crate) fn domain_checks(tail: &str) -> Vec<(Option<String>, String)> {
    let outside = super::sql_outside_mask(tail);
    let bytes = tail.as_bytes();
    let mut checks = Vec::new();
    let mut depth = 0usize;
    let mut name: Option<String> = None;
    let mut index = 0usize;
    while index < bytes.len() {
        if !outside[index] {
            index += 1;
            continue;
        }
        match bytes[index] {
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            _ if depth == 0 && super::keyword_at(bytes, index, "CONSTRAINT") => {
                let start = super::skip_ws(tail, index + "CONSTRAINT".len());
                let end = super::find_ws(tail, start);
                name = Some(unquote_identifier(&tail[start..end]));
                index = end;
                continue;
            }
            _ if depth == 0 && super::keyword_at(bytes, index, "NOT") => name = None,
            _ if depth == 0 && super::keyword_at(bytes, index, "CHECK") => {
                let Some(open) = super::find_char_outside(tail, &outside, '(', index) else {
                    break;
                };
                let Some(close) = super::matching_parenthesis(tail, &outside, open) else {
                    break;
                };
                checks.push((name.take(), tail[open + 1..close].trim().to_string()));
                index = close + 1;
                continue;
            }
            _ => {}
        }
        index += 1;
    }
    checks
}

/// An identifier as PostgreSQL stores it: a quoted one verbatim, an unquoted
/// one lowercased.
pub(crate) fn unquote_identifier(identifier: &str) -> String {
    match identifier.strip_prefix('"').and_then(|rest| rest.strip_suffix('"')) {
        Some(quoted) => quoted.replace("\"\"", "\""),
        None => identifier.to_lowercase(),
    }
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
        let body = crate::parser::spell_out_default_trim_characters(body);
        let parsed = sqlparser::parser::Parser::new(&sqlparser::dialect::PostgreSqlDialect {})
            .try_with_sql(&body)
            .and_then(|mut parser| parser.parse_expr());
        match parsed {
            Ok(expr) => CheckConstraint::new(name, system_name, &expr, "value"),
            Err(_) => CheckConstraint::unparsed(name, system_name, &body),
        }
    }
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
