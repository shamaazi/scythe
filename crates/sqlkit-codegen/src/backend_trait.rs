use sqlkit_backend::naming::row_struct_name;
use sqlkit_core::analyzer::{AnalyzedQuery, CompositeInfo, EnumInfo, NestedStructInfo};
use sqlkit_core::constraints::{Rules, ValueConstraints};
use sqlkit_core::errors::{ErrorCode, SqlkitError};

use crate::GeneratedCode;
use crate::constraints::ConstraintPolicy;
pub use crate::overrides::TsTypeOverride;

/// A column with its type resolved to the target language.
#[derive(Debug, Clone, Default)]
pub struct ResolvedColumn {
    pub name: String,
    pub field_name: String,
    pub lang_type: String,
    pub full_type: String,
    pub neutral_type: String,
    pub nullable: bool,
    /// Alias of the outer-joined relation this column came from, when the
    /// column was widened to nullable by that join. See
    /// [`sqlkit_core::analyzer::AnalyzedColumn::join_group`].
    pub join_group: Option<String>,
    /// Whether the column was nullable in the schema, before outer-join
    /// widening.
    pub nullable_before_join: bool,
    /// The raw SQL type this column was derived from (see
    /// [`sqlkit_core::analyzer::AnalyzedColumn::sql_type`]). Backends that need
    /// to distinguish storage representations the neutral type collapses
    /// (e.g. `xml` vs. `text`, both `neutral_type == "string"`) match on
    /// this instead of `neutral_type`.
    pub sql_type: String,
    /// The schema's constraints on this column's values (see
    /// [`sqlkit_core::analyzer::AnalyzedColumn::constraints`]); `None` unless the
    /// backend renders validation ([`CodegenBackend::constraint_policy`]).
    pub constraints: Option<ValueConstraints>,
    /// The TypeScript type a `type_overrides` entry declares this column as;
    /// `lang_type` and `full_type` keep the type the value has of its own.
    pub ts_type: Option<TsTypeOverride>,
}

impl ResolvedColumn {
    /// Whether this column can only be null because its outer join found no
    /// row — making it a usable discriminant for a union.
    pub fn is_join_discriminant(&self) -> bool {
        self.join_group.is_some() && !self.nullable_before_join
    }

    /// The TypeScript type this column is declared as, without `| null`: its
    /// `ts_type` override, or its own `lang_type`.
    pub fn ts_lang_type(&self) -> &str {
        ts_lang_type(self.ts_type.as_ref(), &self.lang_type)
    }

    /// [`Self::ts_lang_type`] with `| null` when the column is nullable.
    pub fn ts_full_type(&self) -> std::borrow::Cow<'_, str> {
        ts_full_type(self.ts_type.as_ref(), &self.full_type, self.nullable)
    }
}

impl ResolvedParam {
    /// The TypeScript type this parameter is declared as, without `| null`:
    /// its `ts_type` override, or its own `lang_type`.
    pub fn ts_lang_type(&self) -> &str {
        ts_lang_type(self.ts_type.as_ref(), &self.lang_type)
    }

    /// [`Self::ts_lang_type`] with `| null` when the parameter is nullable.
    pub fn ts_full_type(&self) -> std::borrow::Cow<'_, str> {
        ts_full_type(self.ts_type.as_ref(), &self.full_type, self.nullable)
    }
}

fn ts_lang_type<'a>(ts_type: Option<&'a TsTypeOverride>, lang_type: &'a str) -> &'a str {
    ts_type.map_or(lang_type, TsTypeOverride::name)
}

fn ts_full_type<'a>(
    ts_type: Option<&'a TsTypeOverride>,
    full_type: &'a str,
    nullable: bool,
) -> std::borrow::Cow<'a, str> {
    match ts_type {
        None => std::borrow::Cow::Borrowed(full_type),
        Some(t) if nullable => std::borrow::Cow::Owned(format!("{} | null", t.name())),
        Some(t) => std::borrow::Cow::Borrowed(t.name()),
    }
}

/// A parameter with its type resolved to the target language.
#[derive(Debug, Clone, Default)]
pub struct ResolvedParam {
    pub name: String,
    pub field_name: String,
    pub lang_type: String,
    pub full_type: String,
    pub borrowed_type: String,
    pub neutral_type: String,
    pub nullable: bool,
    /// The schema's constraints on the values this parameter is written as (see
    /// [`sqlkit_core::analyzer::AnalyzedParam::constraints`]); `None` unless the
    /// backend renders validation ([`CodegenBackend::constraint_policy`]).
    pub constraints: Option<ValueConstraints>,
    /// The TypeScript type a `type_overrides` entry declares this parameter as;
    /// `lang_type` and `full_type` keep the type the value has of its own.
    pub ts_type: Option<TsTypeOverride>,
}

/// Inputs for [`CodegenBackend::generate_grouped_query_fn`].
///
/// The grouped query-fn contract carries enough context (analyzed query, both
/// struct names, the flat and split column sets, params, and the grouping key)
/// that passing it positionally trips `clippy::too_many_arguments`. Bundling it
/// into one struct keeps the per-language implementations uniform as backends
/// opt in to grouped codegen.
pub struct GroupedQueryFn<'a> {
    /// Full analyzed query (SQL, name, params, optional_params, deprecated, …).
    pub analyzed: &'a AnalyzedQuery,
    /// Name of the generated parent struct.
    pub parent_struct_name: &'a str,
    /// Name of the generated child struct.
    pub child_struct_name: &'a str,
    /// All resolved columns in flat SELECT order; used for row decoding.
    pub all_columns: &'a [ResolvedColumn],
    /// Resolved columns belonging to the parent struct.
    pub parent_columns: &'a [ResolvedColumn],
    /// Resolved columns belonging to the child struct(s).
    pub child_columns: &'a [ResolvedColumn],
    /// Resolved query parameters.
    pub params: &'a [ResolvedParam],
    /// Grouping key column name in the flat result row
    /// (matches [`sqlkit_core::analyzer::GroupByConfig::key_column`]).
    pub key_column: &'a str,
}

/// Trait that all codegen backends must implement.
pub trait CodegenBackend: Send + Sync {
    /// The backend's name (e.g. "rust-sqlx", "rust-tokio-postgres").
    fn name(&self) -> &str;

    /// The backend's manifest (type mappings, naming conventions, etc).
    fn manifest(&self) -> &sqlkit_backend::manifest::BackendManifest;

    /// Mutable access to the backend's own manifest, so a per-target manifest
    /// overlay (`manifest = "..."` in `[[sql.gen]]`) can be merged in right
    /// after construction.
    ///
    /// Deliberately required rather than defaulted: backends read
    /// `self.manifest` directly for naming and type resolution, so a default
    /// that silently did nothing would make `manifest = "..."` a no-op for
    /// whichever backends forgot to override it — the exact class of silent,
    /// per-backend divergence that #82 was filed for. Making it required
    /// turns that into a compile error.
    fn manifest_mut(&mut self) -> &mut sqlkit_backend::manifest::BackendManifest;

    /// Whether this backend renders the schema's constraints as validation, and
    /// if so how a constraint it cannot render is reported.
    ///
    /// `None` (the default) renders none: resolved columns and parameters then
    /// carry no [`ValueConstraints`], and nothing is reported.
    fn constraint_policy(&self) -> Option<ConstraintPolicy> {
        None
    }

    /// The parts of `rules` this backend cannot express on a value of
    /// `lang_type` (before any [`Self::constrained_type`] narrowing), described
    /// for a report. Reported like an untranslated constraint.
    fn inexpressible_rules(&self, _rules: &Rules, _lang_type: &str) -> Vec<String> {
        Vec::new()
    }

    /// The `(lang_type, full_type)` that expresses `constraints` in the type
    /// itself -- a union of the allowed literals -- or `None` to keep the type.
    fn constrained_type(
        &self,
        _constraints: &ValueConstraints,
        _lang_type: &str,
        _nullable: bool,
    ) -> Option<(String, String)> {
        None
    }

    /// The module this backend is configured to import the schema's named
    /// types from (see [`crate::schema_types`]) for every module it generates,
    /// or `None`. Which module a given generated module imports from is
    /// per-call context: see [`crate::ModuleContext`].
    fn schema_types_import(&self) -> Option<&str> {
        None
    }

    /// Check that generated code can import the schema types from
    /// `specifier` -- the configured [`Self::schema_types_import`], or the
    /// relative one the CLI computes per module for a `schema_types` output
    /// without it. The default rejects every specifier: a backend that cannot
    /// import schema types says so.
    fn check_schema_types_import(&self, specifier: &str) -> Result<(), SqlkitError> {
        Err(SqlkitError::new(
            ErrorCode::InvalidConfig,
            format!(
                "backend '{}' cannot import schema types from '{specifier}'",
                self.name()
            ),
        ))
    }

    /// The declaration importing, from `module`, the schema types `generated`
    /// names, placed after [`Self::file_header_for_results`]; empty when it
    /// names none.
    fn schema_types_import_decl(&self, _module: &str, _generated: &[GeneratedCode]) -> String {
        String::new()
    }

    /// The `(lang_type, full_type)` naming the schema type `sql_name` (a
    /// domain) when the module imports the schema types, or `None` to keep
    /// the value's own type.
    fn schema_type(&self, _sql_name: &str, _nullable: bool) -> Option<(String, String)> {
        None
    }

    /// Reject `type_overrides` this backend, as configured, cannot honour.
    /// Backends for other languages ignore `ts_type`, so the default accepts
    /// everything.
    fn check_type_overrides(&self, _overrides: &[crate::TypeOverride]) -> Result<(), SqlkitError> {
        Ok(())
    }

    /// Render the module declaring the schema's enums and domains as named
    /// types, or `None` when this backend cannot.
    fn generate_schema_types(&self, _types: &crate::schema_types::SchemaTypes) -> Option<Result<String, SqlkitError>> {
        None
    }

    /// Emit a row-shaped type declaration under an *already final* name.
    ///
    /// `struct_name` is the exact identifier to declare — this method must
    /// not case-convert it, and must not append
    /// [`NamingConfig::row_suffix`](sqlkit_backend::naming::NamingConfig::row_suffix)
    /// or anything else to it. `doc_name` is prose only: the SQL-side name
    /// ("GetActiveUsers", "User") that backends interpolate into a
    /// docstring or moduledoc. Nothing may derive an identifier from it.
    ///
    /// This split is the fix for #164. Both callers below used to compute a
    /// name each and hand it to one method that suffixed whatever it got,
    /// so `generate_model_struct` declared `UserRow` while the query
    /// function referenced `User`. Now the name is decided once, above the
    /// backend, and the backend only renders it.
    ///
    /// ## Provided, but not optional
    ///
    /// The default returns [`ErrorCode::InternalError`] rather than
    /// falling back to something plausible: a fallback that quietly
    /// re-derived the name is precisely the defect this method exists to
    /// remove. It is provided rather than required only so that a backend
    /// which emits no types at all can override
    /// [`generate_row_struct`](Self::generate_row_struct) and
    /// [`generate_model_struct`](Self::generate_model_struct) directly and
    /// never reach this. Any backend that does emit row types must
    /// override this one and let both callers below default.
    fn generate_struct_decl(
        &self,
        struct_name: &str,
        doc_name: &str,
        columns: &[ResolvedColumn],
    ) -> Result<String, SqlkitError> {
        let _ = (struct_name, doc_name, columns);
        Err(SqlkitError::new(
            ErrorCode::InternalError,
            format!(
                "backend '{}' emits row types but does not implement generate_struct_decl",
                self.name()
            ),
        ))
    }

    /// Generate a row struct for a query result.
    ///
    /// Applies the manifest's `struct_case` and `row_suffix` to the query
    /// name and renders through
    /// [`generate_struct_decl`](Self::generate_struct_decl).
    fn generate_row_struct(&self, query_name: &str, columns: &[ResolvedColumn]) -> Result<String, SqlkitError> {
        let struct_name = row_struct_name(query_name, &self.manifest().naming);
        self.generate_struct_decl(&struct_name, query_name, columns)
    }

    /// Generate a model struct for a table — the type a `SELECT *` shares
    /// across every query over that table.
    ///
    /// Names it through [`crate::model_struct_name`], the same function
    /// `determine_struct_name` uses to decide what the generated query
    /// functions *reference*, so declaration and reference cannot disagree
    /// (#164). Backends whose model type is not a row type at all (Exposed
    /// emits a table object) override this.
    fn generate_model_struct(&self, table_name: &str, columns: &[ResolvedColumn]) -> Result<String, SqlkitError> {
        let struct_name = crate::model_struct_name(table_name, &self.manifest().naming);
        self.generate_struct_decl(&struct_name, &struct_name, columns)
    }

    /// Generate a query function.
    fn generate_query_fn(
        &self,
        analyzed: &AnalyzedQuery,
        struct_name: &str,
        columns: &[ResolvedColumn],
        params: &[ResolvedParam],
    ) -> Result<String, SqlkitError>;

    /// Generate an enum definition.
    fn generate_enum_def(&self, enum_info: &EnumInfo) -> Result<String, SqlkitError>;

    /// Generate a composite type definition.
    fn generate_composite_def(&self, composite: &CompositeInfo) -> Result<String, SqlkitError>;

    /// Generate text that must be the literal first bytes of the generated
    /// file — before any comment, including the provenance header that
    /// assembly prepends ahead of [`file_header`](Self::file_header).
    ///
    /// For syntax that loses its meaning, or becomes a syntax error, if
    /// anything precedes it (a magic first-line directive). Backends with such
    /// a constraint override this method; everything else that may
    /// legally follow a leading comment (imports, docstrings, `#!`-style
    /// banners) stays in [`file_header`](Self::file_header).
    ///
    /// Returns an empty string by default; backends may override.
    fn file_preamble(&self) -> String {
        String::new()
    }

    /// Generate a struct definition for a nested-aggregate result shape
    /// (`json_agg(o.*)`, `row_to_json(u.*)`, ...). PostgreSQL only; see
    /// [`sqlkit_core::analyzer::AnalyzedQuery::nested_structs`].
    ///
    /// ## Opt-in, not opt-out
    ///
    /// Returns `Ok(None)` by default — "I do not support this" — so a
    /// backend is only at risk from this feature if it explicitly
    /// overrides the method. `crates/sqlkit-codegen/src/lib.rs` rewrites
    /// any column referencing a struct this returns `Ok(None)` for to a safe
    /// fallback *before* type resolution. The default is plain `json`, so a
    /// backend stays byte-identical to its pre-inference output; a manifest
    /// may explicitly define the distinct `json_array` scalar when its
    /// driver exposes an array-shaped JSON document as a structural value.
    /// `json_array` is not the SQL-array container `array<json>`.
    ///
    /// Deliberately not the same shape as `generate_composite_def`, which
    /// always returns a definition (`CompositeInfo` only ever exists because
    /// a column already referenced a real catalog composite; there is
    /// nothing to opt out of). Overriding to return `Ok(Some(_))` is safe
    /// only when the backend's row-decoding path actually deserializes the
    /// resulting JSON into the generated type — a backend whose
    /// `json_nested<T>` container merely names the type without decoding it
    /// would produce code that compiles and is wrong, which is worse than
    /// not supporting it. `Err(_)` is reserved for a genuine failure (e.g. a
    /// field's neutral type doesn't resolve) and must propagate rather than
    /// degrade.
    fn generate_nested_struct_def(&self, _nested: &NestedStructInfo) -> Result<Option<String>, SqlkitError> {
        Ok(None)
    }

    /// Generate an enum definition for an enum reachable from a nested
    /// aggregate's field list.
    ///
    /// Same enum, different requirements: a value inside a `json_agg` result
    /// arrives as JSON and is decoded by the language's JSON library, not by
    /// the database driver, so a backend whose ordinary
    /// [`Self::generate_enum_def`] emits only driver traits (`sqlx::Type`,
    /// `postgres_types`) must add the JSON ones here or the nested struct
    /// will not satisfy its own `Deserialize` bound. Defaults to
    /// `generate_enum_def`, which is correct for every backend that already
    /// decodes enums as plain strings.
    fn generate_enum_def_for_nested(&self, enum_info: &EnumInfo) -> Result<String, SqlkitError> {
        self.generate_enum_def(enum_info)
    }

    /// Composite counterpart of [`Self::generate_enum_def_for_nested`], for a
    /// composite type reachable from a nested aggregate's field list.
    fn generate_composite_def_for_nested(&self, composite: &CompositeInfo) -> Result<String, SqlkitError> {
        self.generate_composite_def(composite)
    }

    /// Generate a file-level header (imports, docstring, etc).
    /// Returns an empty string by default; backends may override.
    fn file_header(&self) -> String {
        String::new()
    }

    /// Generate a file-level header using already generated code as context.
    ///
    /// Backends with conditional imports can inspect generated fragments and avoid
    /// broad engine-level import guesses. The default preserves existing behavior.
    fn file_header_for_results(&self, _generated: &[GeneratedCode]) -> String {
        self.file_header()
    }

    /// Generate parent and child structs for a `:grouped` query.
    ///
    /// A `:grouped` query folds flat rows from a normal SQL SELECT into a nested
    /// parent/child structure entirely on the client side — the SQL itself is
    /// unchanged from a regular `:many` query.
    ///
    /// ## Struct layout
    ///
    /// * **Child struct** (`child_struct_name`): contains all `child_columns`.
    ///   Defined first in the output to avoid forward references.
    /// * **Parent struct** (`parent_struct_name`): contains all `parent_columns`
    ///   plus one extra field `children: Vec<child_struct_name>` (or the
    ///   language-native equivalent collection type).
    ///
    /// ## Grouping semantics
    ///
    /// The generated query function fetches flat rows and folds them into an
    /// **order-preserving** list of parent structs, appending each row's child
    /// fields to the matching parent's collection. Equality on `key_column` is
    /// the fold predicate.
    ///
    /// ## Parameters
    ///
    /// * `parent_struct_name` – fully qualified struct/class name for the parent
    ///   (e.g. `"GetUsersWithOrdersRow"`).
    /// * `child_struct_name` – fully qualified struct/class name for the child
    ///   (e.g. `"GetUsersWithOrdersChildRow"`).
    /// * `parent_columns` – resolved columns belonging to the parent table.
    /// * `child_columns` – resolved columns belonging to child table(s).
    /// * `key_column` – SQL column name used as the grouping key; identifies
    ///   the boundary between parent groups (matches [`GroupByConfig::key_column`]).
    ///
    /// ## Return value
    ///
    /// A string containing both struct definitions (child first, parent second),
    /// stored in [`GeneratedCode::row_struct`].
    ///
    /// ## Default implementation
    ///
    /// Returns an error:
    /// *"grouped queries are not yet supported by the '\<name\>' backend"*.
    /// Backends opt in by overriding this method.
    fn generate_grouped_structs(
        &self,
        _parent_struct_name: &str,
        _child_struct_name: &str,
        _parent_columns: &[ResolvedColumn],
        _child_columns: &[ResolvedColumn],
        _key_column: &str,
    ) -> Result<String, SqlkitError> {
        Err(SqlkitError::new(
            ErrorCode::InternalError,
            format!("grouped queries are not yet supported by the '{}' backend", self.name()),
        ))
    }

    /// Generate the query function for a `:grouped` query.
    ///
    /// The function runs the flat SQL from `analyzed.sql`, decodes each row,
    /// and folds the rows into an **order-preserving** `Vec<parent_struct_name>`
    /// (or the language-native equivalent), grouping by `key_column` and
    /// appending each row's child fields to the matching parent's `children`
    /// collection.
    ///
    /// ## Parameters
    ///
    /// All inputs are bundled in [`GroupedQueryFn`]: the analyzed query, both
    /// generated struct names, the flat and split (parent/child) column sets,
    /// the resolved params, and the grouping key column.
    ///
    /// ## Return value
    ///
    /// A string containing the full query function definition, stored in
    /// [`GeneratedCode::query_fn`].
    ///
    /// ## Default implementation
    ///
    /// Returns an error:
    /// *"grouped queries are not yet supported by the '\<name\>' backend"*.
    /// Backends opt in by overriding this method.
    fn generate_grouped_query_fn(&self, _request: &GroupedQueryFn<'_>) -> Result<String, SqlkitError> {
        Err(SqlkitError::new(
            ErrorCode::InternalError,
            format!("grouped queries are not yet supported by the '{}' backend", self.name()),
        ))
    }

    /// Apply per-backend configuration options from [[sql.gen]].
    ///
    /// Backends that take options override this: parse each one, and reject
    /// anything else via [`crate::backend_options::reject_unknown_options`]
    /// against that backend's own known-key list -- see any TypeScript
    /// backend's `apply_options` for the established shape.
    ///
    /// The default rejects every key (an empty known-key list), which is the
    /// correct behavior for the majority of backends that take no options at
    /// all -- and, just as importantly, is what a brand-new backend gets for
    /// free if its author forgets to override this. Before #103 the default
    /// was `Ok(())`, so any unrecognized key -- a typo, or a real key that
    /// TOML happily parsed but no override read -- was silently discarded
    /// everywhere except the 11 TypeScript backends, which called
    /// `reject_unknown_options` explicitly. The same typo behaving
    /// differently depending on target language was itself a trap; inverting
    /// the default closes it for every backend at once instead of requiring
    /// each one to opt in.
    fn apply_options(&mut self, options: &std::collections::HashMap<String, String>) -> Result<(), SqlkitError> {
        crate::backend_options::reject_unknown_options(&[], options)
    }
}
