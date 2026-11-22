use ahash::AHashSet;

use sqlkit_core::analyzer::{AnalyzedColumn, AnalyzedParam};

/// A type override that replaces the inferred type of a column or SQL type.
///
/// Overrides are evaluated in order: the first match wins. A `column` match
/// (e.g. `"users.metadata"`) takes priority over a `db_type` match when both
/// fields are set on the same override entry, but a `column` that fails to
/// match falls through to `db_type` on the same entry rather than making the
/// whole entry a no-op (#189) -- the two predicates degrade independently,
/// they don't gate each other.
#[derive(Debug, Clone, Default)]
pub struct TypeOverride {
    /// Fully-qualified column reference in `"table.column"` format.
    pub column: Option<String>,
    /// SQL type name (matched case-insensitively against the column's neutral type).
    pub db_type: Option<String>,
    /// Target neutral type to substitute (e.g. `"string"`, `"json"`).
    pub neutral_type: Option<String>,
    /// The TypeScript type a matched value is declared as. It changes only the
    /// rendered type: binding, validation and parsing keep working off the
    /// neutral type. Backends for other languages ignore it.
    pub ts_type: Option<TsTypeOverride>,
}

/// The `ts_type` (and optional `ts_import`) of a `type_overrides` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsTypeOverride {
    /// A TypeScript type expression, or, with `import`, an identifier that
    /// module exports.
    pub ts_type: String,
    /// The module `ts_type` is imported from as a type.
    pub import: Option<String>,
}

impl TypeOverride {
    /// Check if this override matches a value.
    ///
    /// `column_keys` are the `"table.column"` names the value is known by (see
    /// [`column_keys`] and [`param_keys`]); `col_neutral_type` is the neutral
    /// type inferred by the analyzer.
    pub fn matches(&self, column_keys: &[String], col_neutral_type: &str) -> bool {
        if let Some(ref col) = self.column
            && column_keys.iter().any(|key| key == col)
        {
            return true;
        }
        if let Some(ref dt) = self.db_type {
            return dt.eq_ignore_ascii_case(col_neutral_type);
        }
        false
    }
}

/// The `"table.column"` names a result column is matched by: its
/// [`AnalyzedColumn::base_column`] (followed through views to the table
/// column, or the view column where the view computes it), then the relation
/// it is read from directly ([`AnalyzedColumn::source_relation`], #189).
pub fn column_keys(col: &AnalyzedColumn) -> Vec<String> {
    let mut keys = Vec::with_capacity(2);
    if let Some(base) = &col.base_column {
        keys.push(base.name());
    }
    if let Some(relation) = &col.source_relation {
        push_unique(&mut keys, format!("{relation}.{}", col.name));
    }
    keys
}

/// The `"table.column"` names a parameter is matched by: the column it is
/// written into directly ([`AnalyzedParam::base_column`]), the column it is
/// compared against ([`AnalyzedParam::source_relation`]), and, when it has
/// neither, the query-level `source_table` (empty for none).
pub fn param_keys(param: &AnalyzedParam, source_table: &str) -> Vec<String> {
    let mut keys = Vec::with_capacity(2);
    if let Some(base) = &param.base_column {
        keys.push(base.name());
    }
    if let Some(relation) = &param.source_relation {
        push_unique(&mut keys, format!("{relation}.{}", param.name));
    }
    if keys.is_empty() && !source_table.is_empty() {
        keys.push(format!("{source_table}.{}", param.name));
    }
    keys
}

fn push_unique(keys: &mut Vec<String>, key: String) {
    if !keys.contains(&key) {
        keys.push(key);
    }
}

/// Every `"table.column"` reference actually present across a set of resolved
/// columns: each column's [`column_keys`]. A computed expression, a literal or
/// a function result contributes nothing, which is exactly what a qualified
/// `column` override can never legitimately target either.
pub fn column_references<'a>(columns: impl Iterator<Item = &'a AnalyzedColumn>) -> AHashSet<String> {
    columns.flat_map(column_keys).collect()
}

/// Every `"table.column"` reference present across a set of parameters: each
/// parameter's [`param_keys`] without the query-level fallback, which names no
/// column the parameter itself touches.
pub fn param_references<'a>(params: impl Iterator<Item = &'a AnalyzedParam>) -> AHashSet<String> {
    params.flat_map(|param| param_keys(param, "")).collect()
}

/// `column` overrides whose target names no `"table.column"` pair in `known_references`.
///
/// This is the other half of #189: fixing `column_match` to bind per-column stops the
/// override from silently doing nothing, but a `column` that names a table or column that
/// plain doesn't exist in this schema (a typo, a renamed table) would otherwise go quiet
/// again the same way -- it just never gets a chance to fire. `db_type`-only entries are
/// never reported here: they have no single column to miss.
pub fn unmatched_column_overrides<'a>(
    overrides: &'a [TypeOverride],
    known_references: &AHashSet<String>,
) -> Vec<&'a TypeOverride> {
    overrides
        .iter()
        .filter(|o| matches!(&o.column, Some(c) if !known_references.contains(c)))
        .collect()
}

/// Find the first override that matches a value.
///
/// Returns `None` when no override matches — the caller should fall through to
/// the default type-resolution path.
pub fn find_override<'a>(
    overrides: &'a [TypeOverride],
    column_keys: &[String],
    col_neutral_type: &str,
) -> Option<&'a TypeOverride> {
    overrides.iter().find(|o| o.matches(column_keys, col_neutral_type))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlkit_core::catalog::ColumnOrigin;

    fn keys(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_string()).collect()
    }

    fn neutral(column: Option<&str>, db_type: Option<&str>, neutral_type: &str) -> TypeOverride {
        TypeOverride {
            column: column.map(str::to_string),
            db_type: db_type.map(str::to_string),
            neutral_type: Some(neutral_type.to_string()),
            ts_type: None,
        }
    }

    #[test]
    fn test_column_override_matches() {
        let o = neutral(Some("users.metadata"), None, "json");
        assert!(o.matches(&keys(&["users.metadata"]), "jsonb"));
        assert!(!o.matches(&keys(&["posts.metadata"]), "jsonb"));
    }

    #[test]
    fn test_column_override_matches_any_key() {
        let o = neutral(Some("users.metadata"), None, "json");
        assert!(o.matches(&keys(&["user_records.metadata", "users.metadata"]), "jsonb"));
    }

    #[test]
    fn test_db_type_override_matches() {
        let o = neutral(None, Some("ltree"), "string");
        assert!(o.matches(&[], "ltree"));
        assert!(o.matches(&keys(&["any.col"]), "LTREE"));
        assert!(!o.matches(&keys(&["any.col"]), "text"));
    }

    #[test]
    fn test_column_takes_priority_over_db_type() {
        let o = neutral(Some("users.name"), Some("text"), "custom");
        assert!(o.matches(&keys(&["users.name"]), "int32"));
        assert!(!o.matches(&keys(&["other.name"]), "int32"));
    }

    /// Must fail before the fix: `matches` used to return `false` as soon as `column` was
    /// set and didn't match, without ever checking `db_type` -- so a combined entry went
    /// completely silent for every column except the one literally named in `column`,
    /// instead of degrading to the type-level rule (#189).
    #[test]
    fn test_column_miss_falls_through_to_db_type() {
        let o = neutral(Some("users.name"), Some("text"), "custom");
        assert!(o.matches(&keys(&["other.name"]), "text"));
        assert!(o.matches(&keys(&["other.name"]), "TEXT"));
    }

    #[test]
    fn test_find_override_first_match_wins() {
        let overrides = vec![
            neutral(Some("users.metadata"), None, "json"),
            neutral(None, Some("jsonb"), "string"),
        ];
        let found = |k: &[&str], t: &str| find_override(&overrides, &keys(k), t).and_then(|o| o.neutral_type.clone());
        assert_eq!(found(&["users.metadata"], "jsonb").as_deref(), Some("json"));
        assert_eq!(found(&["posts.data"], "jsonb").as_deref(), Some("string"));
        assert_eq!(found(&["posts.data"], "text"), None);
    }

    #[test]
    fn test_find_override_empty_list() {
        assert!(find_override(&[], &keys(&["users.id"]), "int32").is_none());
    }

    fn column(name: &str, relation: Option<&str>) -> AnalyzedColumn {
        AnalyzedColumn {
            name: name.to_string(),
            neutral_type: "string".to_string(),
            source_relation: relation.map(str::to_string),
            ..Default::default()
        }
    }

    /// A column read through a view is known by the table column the view
    /// reads first, then by the view column it is selected from.
    #[test]
    fn test_column_keys_follow_the_base_column_first() {
        let col = AnalyzedColumn {
            base_column: Some(ColumnOrigin {
                relation: "public.users".to_string(),
                column: "email".to_string(),
            }),
            ..column("email", Some("user_records"))
        };
        assert_eq!(column_keys(&col), keys(&["users.email", "user_records.email"]));
    }

    /// A parameter written into a column is known by that column; one with no
    /// column falls back to the query-level source table.
    #[test]
    fn test_param_keys_prefer_the_written_column() {
        let written = AnalyzedParam {
            name: "email".to_string(),
            base_column: Some(ColumnOrigin {
                relation: "users".to_string(),
                column: "email".to_string(),
            }),
            ..Default::default()
        };
        assert_eq!(param_keys(&written, "accounts"), keys(&["users.email"]));
        let loose = AnalyzedParam {
            name: "id".to_string(),
            ..Default::default()
        };
        assert_eq!(param_keys(&loose, "accounts"), keys(&["accounts.id"]));
        assert!(param_references([loose].iter()).is_empty());
    }

    /// A computed expression, literal, or function result -- `source_relation: None` --
    /// contributes no `"table.column"` reference: it is exactly what a qualified `column`
    /// override can never legitimately target either (#189).
    #[test]
    fn test_column_references_skips_columns_with_no_source_relation() {
        let columns = [column("id", Some("users")), column("total", None)];
        let refs = column_references(columns.iter());
        assert_eq!(refs.len(), 1);
        assert!(refs.contains("users.id"));
    }

    /// Must fail before the fix existed: a `column` override naming a table or column
    /// present nowhere in `known_references` (a typo) must be reported; a matching one and
    /// a `db_type`-only one (no single column to miss) must not be.
    #[test]
    fn test_unmatched_column_overrides_reports_only_the_typo() {
        let known = column_references([column("id", Some("users"))].iter());
        let overrides = vec![
            neutral(Some("users.id"), None, "string"),
            neutral(Some("users.emial"), None, "string"),
            neutral(None, Some("jsonb"), "string"),
        ];
        let unmatched = unmatched_column_overrides(&overrides, &known);
        assert_eq!(unmatched.len(), 1);
        assert_eq!(unmatched[0].column.as_deref(), Some("users.emial"));
    }
}
