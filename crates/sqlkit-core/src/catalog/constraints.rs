//! The constraints the catalog records per column and per domain, and their
//! resolution into [`ValueConstraints`].

use sqlparser::ast::{CharacterLength, DataType, ExactNumberInfo, Expr, ObjectName};

use super::type_normalizer::object_name_to_key;
use super::{Catalog, DomainDef, lookup_qualified};
use crate::constraints::{Rules, Translation, Untranslated, ValueConstraints, referenced_columns, translate_check};

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
    /// `n` of `varchar(n)`/`char(n)`.
    pub max_length: Option<u64>,
    /// `(p, s)` of `numeric(p, s)`.
    pub precision: Option<(u64, u64)>,
    pub checks: Vec<CheckConstraint>,
    /// `COMMENT ON COLUMN` / `COMMENT ON DOMAIN` text.
    pub comment: Option<String>,
    /// For a view column that reads another relation's column unchanged: that
    /// column, whose constraints it shares.
    pub origin: Option<ColumnOrigin>,
}

impl ColumnConstraints {
    /// The facts a column's declared type contributes.
    pub(crate) fn from_type(data_type: &DataType, domains: &ahash::AHashMap<String, DomainDef>) -> Self {
        let (max_length, precision) = type_bounds(data_type);
        let domain = match data_type {
            DataType::Custom(name, _) => {
                let key = object_name_to_key(name);
                lookup_qualified(domains, &key, None).map(|_| key)
            }
            _ => None,
        };
        Self {
            domain,
            max_length,
            precision,
            ..Self::default()
        }
    }

    /// Replace the facts that come from the declared type, keeping checks,
    /// comment and origin -- `ALTER COLUMN ... TYPE`.
    pub(crate) fn retype(&mut self, data_type: &DataType, domains: &ahash::AHashMap<String, DomainDef>) {
        let typed = Self::from_type(data_type, domains);
        self.domain = typed.domain;
        self.max_length = typed.max_length;
        self.precision = typed.precision;
    }
}

/// One `CHECK` constraint on a single value.
#[derive(Debug, Clone)]
pub struct CheckConstraint {
    pub name: Option<String>,
    /// The check's expression as SQL.
    pub sql: String,
    pub(crate) translation: Translation,
}

impl CheckConstraint {
    /// A check on `subject` (a column name, or `value` in a domain).
    pub(crate) fn new(name: Option<String>, expr: &Expr, subject: &str) -> Self {
        Self {
            name,
            sql: expr.to_string(),
            translation: translate_check(expr, subject),
        }
    }

    /// The rules this check translates to.
    pub fn rules(&self) -> &Rules {
        &self.translation.rules
    }
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

/// `varchar(n)`/`char(n)` length and `numeric(p, s)` precision of a type.
fn type_bounds(data_type: &DataType) -> (Option<u64>, Option<(u64, u64)>) {
    let length = |len: &Option<CharacterLength>| match len {
        Some(CharacterLength::IntegerLength { length, .. }) => Some(*length),
        _ => None,
    };
    let precision = |info: &ExactNumberInfo| match info {
        ExactNumberInfo::Precision(p) => Some((*p, 0)),
        ExactNumberInfo::PrecisionAndScale(p, s) if *s >= 0 => Some((*p, *s as u64)),
        _ => None,
    };
    match data_type {
        DataType::Varchar(len)
        | DataType::CharacterVarying(len)
        | DataType::CharVarying(len)
        | DataType::Nvarchar(len)
        | DataType::Char(len)
        | DataType::Character(len) => (length(len), None),
        DataType::Numeric(info) | DataType::Decimal(info) | DataType::Dec(info) => (None, precision(info)),
        _ => (None, None),
    }
}

/// How many domain or view hops resolution follows before giving up, which
/// only a cyclic definition reaches.
const MAX_DEPTH: usize = 16;

impl Catalog {
    /// The constraints the schema declares on `relation.column`'s values, or
    /// `None` when it declares none.
    pub fn column_constraints(&self, relation: &str, column: &str) -> Option<ValueConstraints> {
        let mut out = ValueConstraints::default();
        self.resolve_column(relation, column, &mut out, 0);
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
    /// domains', or `None` when it is not a domain or declares none.
    pub fn domain_constraints(&self, name: &str) -> Option<ValueConstraints> {
        let mut out = ValueConstraints::default();
        self.resolve_domain(name, &mut out, 0);
        (!out.is_empty()).then_some(out)
    }

    /// The raw constraint facts recorded for `relation.column`.
    pub fn column_constraint_facts(&self, relation: &str, column: &str) -> Option<&ColumnConstraints> {
        let table = self.get_table(relation)?;
        let column = column.to_lowercase();
        table.columns.iter().find(|c| c.name == column).map(|c| &c.constraints)
    }

    fn resolve_column(&self, relation: &str, column: &str, out: &mut ValueConstraints, depth: usize) {
        if depth > MAX_DEPTH {
            return;
        }
        let Some(facts) = self.column_constraint_facts(relation, column) else {
            return;
        };
        if let Some(origin) = &facts.origin {
            self.resolve_column(&origin.relation, &origin.column, out, depth + 1);
        }
        let source = format!(
            "{}.{}",
            super::type_normalizer::bare_name(relation),
            column.to_lowercase()
        );
        self.apply_facts(facts, &source, out, depth);
    }

    fn resolve_domain(&self, name: &str, out: &mut ValueConstraints, depth: usize) {
        if depth > MAX_DEPTH {
            return;
        }
        let Some(domain) = lookup_qualified(&self.domains, name, self.search_path.as_deref()) else {
            return;
        };
        let source = format!("domain {}", name.to_lowercase());
        self.apply_facts(&domain.constraints, &source, out, depth);
        out.domain = Some(name.to_lowercase());
    }

    fn apply_facts(&self, facts: &ColumnConstraints, source: &str, out: &mut ValueConstraints, depth: usize) {
        if let Some(domain) = &facts.domain {
            self.resolve_domain(domain, out, depth + 1);
        }
        // `numeric(p, s)` precision is recorded but, like an integer type's range, not a
        // rule: PostgreSQL rounds to the scale rather than rejecting, and generated
        // code commonly carries decimals as strings.
        let rules = Rules {
            max_length: facts.max_length,
            ..Rules::default()
        };
        out.add_rules(&rules, source, "");
        for check in &facts.checks {
            let constraint = |sql: &str| match &check.name {
                Some(name) => format!("{name} CHECK ({sql})"),
                None => format!("CHECK ({sql})"),
            };
            out.add_rules(&check.translation.rules, source, &constraint(&check.sql));
            for (sql, reason) in &check.translation.untranslated {
                let entry = Untranslated {
                    source: source.to_string(),
                    constraint: constraint(sql),
                    reason: reason.clone(),
                };
                if !out.untranslated.contains(&entry) {
                    out.untranslated.push(entry);
                }
            }
        }
        if facts.comment.is_some() {
            out.description = facts.comment.clone();
        }
    }
}

/// The table key and column of a `COMMENT ON COLUMN` target.
pub(crate) fn comment_column_target(name: &ObjectName) -> Option<(String, String)> {
    let key = object_name_to_key(name);
    let (relation, column) = key.rsplit_once('.')?;
    Some((relation.to_string(), column.to_string()))
}

/// Attach a check to the one column of `columns` it constrains; a check on
/// several columns (or none) relates values to each other and is skipped.
pub(crate) fn attach_check(columns: &mut [super::Column], name: Option<String>, expr: &Expr) {
    let Some(column) = single_column(expr) else {
        return;
    };
    if let Some(target) = columns.iter_mut().find(|c| c.name == column) {
        target
            .constraints
            .checks
            .push(CheckConstraint::new(name, expr, &column));
    }
}

impl CheckConstraint {
    /// A check whose expression could not be parsed: kept, untranslated.
    pub(crate) fn unparsed(name: Option<String>, sql: &str) -> Self {
        Self {
            name,
            sql: sql.to_string(),
            translation: Translation {
                untranslated: vec![(sql.to_string(), "the expression could not be parsed".to_string())],
                ..Translation::default()
            },
        }
    }
}

/// The `CHECK` constraints of a `CREATE DOMAIN` statement's tail (everything
/// after the base type), as `(constraint name, expression SQL)`.
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
                name = Some(tail[start..end].trim_matches('"').to_lowercase());
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
