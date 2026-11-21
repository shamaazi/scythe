use scythe_backend::manifest::BackendManifest;
use scythe_backend::naming::{composite_type_name, enum_type_name, enum_variant_name, fn_name, to_camel_case};
use scythe_backend::types::resolve_type;
use std::fmt::Write;

use scythe_core::analyzer::{AnalyzedQuery, CompositeInfo, EnumInfo};
use scythe_core::errors::{ErrorCode, ScytheError};
use scythe_core::parser::QueryCommand;

use crate::backend_options::reject_unknown_options;
use crate::backend_trait::GroupedQueryFn;
use crate::backend_trait::{CodegenBackend, ResolvedColumn, ResolvedParam};
use crate::backends::typescript_common::{
    TsFieldCase, TsParamStyle, TsQueryParams, TsRowShape, TsRowType, escape_ts_template_literal,
    generate_grouped_interface_structs, generate_js_grouped_typedef_structs, generate_js_typedef,
    generate_js_typedef_row_struct, generate_jsdoc_fn_header, generate_ts_grouped_fold_body,
    generate_ts_interface_row_struct, generate_ts_json_composite_interface, generate_ts_many_row_remap,
    generate_ts_nested_interface, generate_ts_one_row_remap, generate_ts_union_row_struct, generate_zod_enum,
    generate_zod_grouped_structs, generate_zod_row_struct, generate_zod_union_row_struct, js_fn_signature_line,
    js_type_cast, parse_bool_option, ts_index_access, ts_member_access, ts_property_key, ts_row_not_found_throw,
};

const DEFAULT_MANIFEST_TOML: &str = include_str!("../../manifests/typescript-postgres.toml");
const DEFAULT_MANIFEST_REDSHIFT: &str = include_str!("../../manifests/typescript-postgres.redshift.toml");
const BUN_MANIFEST_TOML: &str = include_str!("../../manifests/typescript-bun.toml");

/// The JSON value alias the Bun header declares: what Bun's adapter parses a
/// `json`/`jsonb` column into, and what `sql.json(...)` accepts back.
const BUN_JSON_VALUE_TS: &str = "type SqlJsonValue = null | string | number | boolean | readonly SqlJsonValue[] | { readonly [key: string]: undefined | SqlJsonValue };\n";
const BUN_JSON_VALUE_JS: &str = "/** @typedef {null | string | number | boolean | readonly SqlJsonValue[] | {[key: string]: undefined | SqlJsonValue}} SqlJsonValue */\n";

/// The client a generated module drives through PostgreSQL's tagged-template
/// query API.
///
/// Bun's built-in `SQL` client copies postgres.js's surface -- `` sql`...${v}` ``
/// binds `v` as a parameter, `sql.json`, `sql.begin`, `result.count`, nested
/// `` sql`...` `` fragments -- so both share this backend. What differs is the
/// handle type, the manifest (Bun returns `int8` as a string and `date` as a
/// `Date`), how a few parameter kinds must be wrapped, and how `:batch` opens
/// its transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TemplateDriver {
    /// postgres.js (`import type { Sql } from "postgres"`).
    PostgresJs,
    /// Bun's built-in client (`import type { SQL } from "bun"`).
    Bun,
}

impl TemplateDriver {
    /// The handle's type in a TypeScript signature.
    fn ts_handle_type(self) -> &'static str {
        match self {
            Self::PostgresJs => "Sql",
            Self::Bun => "SQL",
        }
    }

    /// The handle's type in a JSDoc `@param` tag.
    fn js_handle_type(self) -> &'static str {
        match self {
            Self::PostgresJs => "import(\"postgres\").Sql",
            Self::Bun => "import(\"bun\").SQL",
        }
    }

    /// The registry name of the TypeScript emit mode.
    fn ts_name(self) -> &'static str {
        match self {
            Self::PostgresJs => "typescript-postgres",
            Self::Bun => "typescript-bun",
        }
    }

    /// The registry name of the JSDoc emit mode.
    fn js_name(self) -> &'static str {
        match self {
            Self::PostgresJs => "javascript-postgres",
            Self::Bun => "javascript-bun",
        }
    }

    /// How the driver names itself in generated comments.
    fn label(self) -> &'static str {
        match self {
            Self::PostgresJs => "postgres.js",
            Self::Bun => "Bun SQL",
        }
    }
}

/// Bun reads an `integer[]` or `real[]` column in binary as an `Int32Array` /
/// `Float32Array` -- unless the array holds a `NULL` or has more than one
/// dimension, which no typed array can carry, so the same column can yield
/// either shape row by row. The manifest maps containers generically, so
/// these two element types are widened here, on the columns only:
/// parameters keep the plain array type, which Bun binds as an array literal.
/// A column whose type a user override replaced is left alone.
fn bun_typed_array(column: &ResolvedColumn) -> Option<&'static str> {
    if column.lang_type != "Array<number>" {
        return None;
    }
    match column.neutral_type.as_str() {
        "array<int32>" => Some("Int32Array"),
        "array<float32>" => Some("Float32Array"),
        _ => None,
    }
}

/// `columns` with every [`bun_typed_array`] column's type widened to
/// `TypedArray | Array<number>`. Borrows when nothing needs widening.
fn bun_columns(columns: &[ResolvedColumn]) -> std::borrow::Cow<'_, [ResolvedColumn]> {
    if !columns.iter().any(|c| bun_typed_array(c).is_some()) {
        return std::borrow::Cow::Borrowed(columns);
    }
    let widened = columns
        .iter()
        .map(|c| {
            let Some(typed) = bun_typed_array(c) else {
                return c.clone();
            };
            let lang_type = format!("{typed} | {}", c.lang_type);
            let full_type = if c.nullable {
                format!("{lang_type} | null")
            } else {
                lang_type.clone()
            };
            ResolvedColumn {
                lang_type,
                full_type,
                ..c.clone()
            }
        })
        .collect();
    std::borrow::Cow::Owned(widened)
}

/// Board #204: postgres.js registers no parser for a user-defined composite type either
/// (verified by reading the vendored driver's own source -- `postgres/src/types.js` has no
/// `record`/`typtype`/composite handling at all, not from memory), so a composite column
/// arrives as PostgreSQL's raw composite *text form* (`"(a,b,c)"`), a plain `string` -- not the
/// generated `interface`. See `typescript_pg.rs`'s identical fix (`ts_parse_composite_fields_helper`
/// and friends) for the full rationale and the escaping rules; this is that same fix targeting
/// postgres.js's bracket-access row shape (`row['field']`, via `ts_index_access`) instead of
/// `pg`'s dot access.
fn ts_parse_composite_fields_helper(name: &str) -> String {
    format!(
        "function parse{name}Fields(text: string): (string | null)[] {{\n\
\t// ~keep Splits a PostgreSQL composite's text form (\"(a,b,c)\") into its raw field\n\
\t// tokens, honoring its escaping rules: an empty unquoted field is SQL NULL (returned as\n\
\t// null); a field needing quoting (comma, paren, quote, backslash, leading/trailing\n\
\t// space, or the empty string) is wrapped in double quotes; every other field is\n\
\t// unquoted and taken literally. Inside a quoted field `record_out` writes a literal\n\
\t// '\"' as '\"\"' and a literal '\\\\' as '\\\\\\\\' -- reading '\"\"' as a closing quote both\n\
\t// truncates the value and desynchronizes every field after it. Verified against\n\
\t// PostgreSQL 16.\n\
\tconst fields: (string | null)[] = [];\n\
\tconst inner = text.slice(1, -1);\n\
\tlet i = 0;\n\
\tconst n = inner.length;\n\
\tfor (;;) {{\n\
\t\tlet chars = \"\";\n\
\t\tlet isNull = false;\n\
\t\tif (i < n && inner[i] === '\"') {{\n\
\t\t\ti++;\n\
\t\t\twhile (i < n) {{\n\
\t\t\t\tconst c = inner[i];\n\
\t\t\t\tif (c === \"\\\\\" && i + 1 < n) {{\n\
\t\t\t\t\tchars += inner[i + 1];\n\
\t\t\t\t\ti += 2;\n\
\t\t\t\t}} else if (c === '\"' && i + 1 < n && inner[i + 1] === '\"') {{\n\
\t\t\t\t\tchars += '\"';\n\
\t\t\t\t\ti += 2;\n\
\t\t\t\t}} else if (c === '\"') {{\n\
\t\t\t\t\ti++;\n\
\t\t\t\t\tbreak;\n\
\t\t\t\t}} else {{\n\
\t\t\t\t\tchars += c;\n\
\t\t\t\t\ti++;\n\
\t\t\t\t}}\n\
\t\t\t}}\n\
\t\t}} else {{\n\
\t\t\tconst start = i;\n\
\t\t\twhile (i < n && inner[i] !== \",\") {{\n\
\t\t\t\ti++;\n\
\t\t\t}}\n\
\t\t\tchars = inner.slice(start, i);\n\
\t\t\tisNull = chars.length === 0;\n\
\t\t}}\n\
\t\tfields.push(isNull ? null : chars);\n\
\t\tif (i < n && inner[i] === \",\") {{\n\
\t\t\ti++;\n\
\t\t\tcontinue;\n\
\t\t}}\n\
\t\tbreak;\n\
\t}}\n\
\treturn fields;\n\
}}"
    )
}

/// PostgreSQL's default `bytea` text output is hex (`"\x48656c6c6f"`); decode the digits after
/// the `\x` prefix back into a `Buffer`. Emitted only when a composite has a `bytes` field.
fn ts_parse_composite_bytes_helper(name: &str) -> String {
    format!(
        "function parse{name}Bytes(hex: string): Buffer {{\n\
\t// ~keep PostgreSQL's default bytea text output is hex: \"\\x48656c6c6f\". Decode the hex\n\
\t// digits after the \"\\x\" prefix back into a Buffer.\n\
\treturn Buffer.from(hex.slice(2), \"hex\");\n\
}}"
    )
}

/// PostgreSQL's default `timestamptz` text output uses a space instead of `T` and omits the
/// offset's minutes when they are zero; normalize both before handing the text to the `Date`
/// constructor. Emitted only when a composite has a `datetime_tz` field.
fn ts_parse_composite_offset_datetime_helper(name: &str) -> String {
    format!(
        "function parse{name}OffsetDateTime(raw: string): Date {{\n\
\t// ~keep PostgreSQL's default timestamptz text output uses a space instead of \"T\"\n\
\t// (\"2024-01-15 10:30:00+00\") and omits the offset's minutes when they are zero (\"+00\"\n\
\t// rather than \"+00:00\"); normalize both before parsing.\n\
\tlet s = raw.replace(\" \", \"T\");\n\
\tconst sign = s[s.length - 3];\n\
\tif (sign === \"+\" || sign === \"-\") {{\n\
\t\ts = s + \":00\";\n\
\t}}\n\
\treturn new Date(s);\n\
}}"
    )
}

fn ts_composite_needs_bytes_helper(composite: &CompositeInfo) -> bool {
    composite.fields.iter().any(|f| f.neutral_type == "bytes")
}

fn ts_composite_needs_offset_datetime_helper(composite: &CompositeInfo) -> bool {
    composite.fields.iter().any(|f| f.neutral_type == "datetime_tz")
}

/// The TypeScript expression converting one composite field's raw text token into its declared
/// type. Nullable fields return `null` before conversion, and `field_type` is always the
/// non-null manifest spelling used by static calls and type assertions.
fn ts_composite_field_from_text(
    neutral_type: &str,
    field_type: &str,
    raw: &str,
    nullable: bool,
    composite_name: &str,
) -> String {
    let converted = if neutral_type.strip_prefix("composite::").is_some() {
        format!("parse{field_type}({raw}) as {field_type}")
    } else if neutral_type.starts_with("enum::") {
        format!("{raw} as {field_type}")
    } else {
        // ~keep The manifest decides the declared type: Bun declares `int64` as
        // `string` and `date` as `Date`, postgres.js the other way round.
        match neutral_type {
            "bool" => format!("{raw} === \"t\""),
            "int16" | "int32" | "int64" | "float32" | "float64" if field_type == "number" => format!("Number({raw})"),
            "date" if field_type == "Date" => format!("new Date({raw} as string)"),
            "bytes" => format!("parse{composite_name}Bytes({raw} as string)"),
            "datetime" => format!("new Date(({raw} as string).replace(\" \", \"T\"))"),
            "datetime_tz" => format!("parse{composite_name}OffsetDateTime({raw} as string)"),
            _ => format!("{raw} as {field_type}"),
        }
    };
    if nullable {
        format!("{raw} === null ? null : {converted}")
    } else {
        converted
    }
}

/// The `field: value` overrides a composite-column read path must splice into an otherwise
/// spread-through row object, for every `composite::` column in `columns`. Empty when the
/// query selects no composite column, so a caller can skip the spread rewrite entirely in the
/// common case. Uses `ts_index_access` (`row['field']`), postgres.js's row shape.
fn ts_composite_field_overrides(columns: &[ResolvedColumn], var: &str) -> Vec<(String, String)> {
    columns
        .iter()
        .filter(|c| c.neutral_type.starts_with("composite::"))
        .map(|c| {
            let key = ts_property_key(&c.field_name);
            let member = ts_index_access(var, &c.name);
            (key, format!("parse{}({member}) as {}", c.lang_type, c.full_type))
        })
        .collect()
}

/// Build a `row_access` closure for [`generate_ts_one_row_remap`]/[`generate_ts_many_row_remap`]/
/// [`generate_ts_grouped_fold_body`] that routes a `composite::` column through its generated
/// `parse{Name}` function instead of a bare (compile-time-only) cast. Every other column keeps
/// the plain `row['field'] as T` cast these three callers already emitted.
fn ts_composite_aware_row_access(columns: &[ResolvedColumn]) -> impl Fn(&str, &str) -> String + '_ {
    move |name: &str, ty: &str| {
        let member = ts_index_access("row", name);
        if let Some(col) = columns.iter().find(|c| c.name == name)
            && col.neutral_type.starts_with("composite::")
        {
            return format!("parse{}({member}) as {ty}", col.lang_type);
        }
        format!("{member} as {ty}")
    }
}

/// Rewrite the `$N` placeholders of an escaped `:batch` statement into
/// postgres.js `${item.field}` interpolations.
///
/// `sql` must already have been through [`escape_ts_template_literal`], and
/// `param_map` maps a 1-based placeholder position to the batch item's
/// resolved param (its field name, and its neutral type for the composite
/// case -- see [`pg_bind_expr`]).
///
/// This exists so the `:batch` path goes through the same literal-aware
/// [`super::rewrite_pg_placeholders`] the `:one`/`:many`/`:exec` paths use
/// (#219). It previously ran `sql.replace("$1", "${item.a}")` over the raw
/// text, which does not know what a SQL string literal is: given
/// `VALUES ($1, 'lit $1 end')` it rewrote *both* occurrences, so the inert
/// text inside the literal became a second live postgres.js binding. That
/// silently changes what the statement inserts -- and, unlike a syntax
/// error, nothing downstream notices.
fn batch_item_sql(
    driver: TemplateDriver,
    sql: &str,
    param_map: &std::collections::HashMap<u32, &ResolvedParam>,
    composites: &[CompositeInfo],
) -> String {
    super::rewrite_pg_placeholders(sql, |n| {
        param_map.get(&n).map_or_else(
            || "${item.?}".to_string(),
            |rp| {
                let access = ts_member_access("item", &rp.field_name);
                pg_bind_expr(driver, &access, &rp.neutral_type, rp.nullable, composites)
            },
        )
    })
}

/// As [`batch_item_sql`], for the one-parameter `:batch` shape, where the
/// whole item -- not one of its fields -- is what gets bound, so every
/// placeholder rewrites to the same `${item}`.
///
/// This used to be `sql_template.replace(&format!("${{{}}}", field_name),
/// "${item}")`, run over the *already placeholder-rewritten* SQL. That is
/// literal-safe against a bare `$N` -- `rewrite_pg_placeholders` had already
/// turned every real one into `${field_name}` by that point -- but not
/// against a SQL string literal that itself contains the text
/// `${field_name}`: `escape_ts_template_literal` turns that into the inert
/// `\${field_name}`, and the blind `.replace` still matches its tail,
/// silently corrupting the stored literal to `\${item}`. Rewriting straight
/// from the escaped-but-not-yet-placeholder-rewritten SQL, through the same
/// span-aware [`super::rewrite_pg_placeholders`] the multi-parameter branch
/// uses, closes that gap the same way #219 closed it there.
fn batch_item_sql_single(
    driver: TemplateDriver,
    sql: &str,
    param: &ResolvedParam,
    composites: &[CompositeInfo],
) -> String {
    super::rewrite_pg_placeholders(sql, |_| {
        pg_bind_expr(driver, "item", &param.neutral_type, param.nullable, composites)
    })
}

/// Render the postgres.js binding text for a parameter read through
/// `access_expr` (a TS/JS expression, e.g. a field name or `item.field`).
///
/// Delegates to [`pg_composite_bind_expr`] when `neutral_type` is a
/// composite; every other type keeps the plain `${access_expr}`
/// substitution every param used before #179.
///
/// Bun needs three further wrappers, each guarded so a `null` stays SQL
/// `NULL` (`sql.json(null)` is the JSON value `null`, and `sql.array(null)`
/// is not an array):
/// - `json` goes through `sql.json`, as on postgres.js: a bare JS string or
///   number would otherwise bind as itself, not as JSON.
/// - an array of an enum goes through `sql.array`: Bun binds a JS array as an
///   array literal only when it knows the parameter is an array, and it
///   cannot tell that of a user-defined type's array.
/// - an array of `json` goes through `sql.array(..., "JSONB")`, so each
///   element is encoded as JSON rather than stringified.
fn pg_bind_expr(
    driver: TemplateDriver,
    access_expr: &str,
    neutral_type: &str,
    nullable: bool,
    composites: &[CompositeInfo],
) -> String {
    if let Some(sql_name) = neutral_type.strip_prefix("composite::") {
        return pg_composite_bind_expr(driver, access_expr, sql_name, composites);
    }
    let wrapped = match driver {
        TemplateDriver::PostgresJs if neutral_type == "json" => return format!("${{sql.json({access_expr})}}"),
        TemplateDriver::PostgresJs => return format!("${{{access_expr}}}"),
        TemplateDriver::Bun if neutral_type == "json" => format!("sql.json({access_expr})"),
        TemplateDriver::Bun if neutral_type == "array<json>" => format!("sql.array({access_expr}, \"JSONB\")"),
        TemplateDriver::Bun if neutral_type.starts_with("array<enum::") => format!("sql.array({access_expr})"),
        TemplateDriver::Bun => return format!("${{{access_expr}}}"),
    };
    if nullable {
        format!("${{{access_expr} === null ? null : {wrapped}}}")
    } else {
        format!("${{{wrapped}}}")
    }
}

/// Render `access_expr` (a TS/JS expression reading a whole composite
/// value) as postgres.js binding text for the Postgres composite type
/// `sql_name`.
///
/// (#179) postgres.js's tagged-template `${}` binds one scalar/array/json
/// value at a time; its type declarations reject a plain object typed as a
/// Postgres composite (`ParameterOrFragment<never>`, a TS2345 the caller
/// cannot work around), and it has no runtime serializer that could accept
/// one either -- unlike scalars, a composite has no fixed OID postgres.js
/// could dispatch a serializer on without a live catalog lookup, which
/// codegen has no access to. Postgres itself accepts a composite value
/// spelled as a row constructor cast to the type name (`ROW(a, b)::address`),
/// built here from one `${}` binding per scalar field -- each field is a
/// value postgres.js already knows how to bind, so the composite as a whole
/// never has to be. `ROW(`, the field separators, and `)::sql_name` are
/// literal SQL text spliced around those per-field bindings; they do not
/// themselves flow through `${}`.
///
/// A field that is itself a composite recurses through the same
/// construction. A composite this query's `composites` catalog does not
/// carry (should not happen -- the analyzer collects every composite a
/// query's params and columns reference) falls back to binding the whole
/// object directly: that fails exactly the way every composite param failed
/// before this fix, not worse.
fn pg_composite_bind_expr(
    driver: TemplateDriver,
    access_expr: &str,
    sql_name: &str,
    composites: &[CompositeInfo],
) -> String {
    let Some(info) = composites.iter().find(|c| c.sql_name == sql_name) else {
        return format!("${{{access_expr}}}");
    };
    let fields: Vec<String> = info
        .fields
        .iter()
        .map(|field| {
            let field_access = ts_member_access(access_expr, &to_camel_case(&field.name));
            pg_bind_expr(driver, &field_access, &field.neutral_type, field.nullable, composites)
        })
        .collect();
    let row = format!("ROW({})::{sql_name}", fields.join(", "));
    format!("${{{access_expr} === null ? sql`NULL::{sql_name}` : sql`{row}`}}")
}

pub struct TypescriptPostgresBackend {
    manifest: BackendManifest,
    row_type: TsRowType,
    /// Emit outer-join nullability as a discriminated union instead of
    /// independent per-column optionals. Opt-in: the flat shape stays the
    /// default and the cross-target shape.
    outer_join_unions: bool,
    /// When true, only emit type definitions (interfaces/Zod schemas, enums,
    /// composites) — no query functions, and no `postgres` driver import
    /// (which would otherwise be unused).
    structs_only: bool,
    /// Under `Camel`, `:one`/`:opt`/`:many` reconstruct the row field by
    /// field from the driver's raw (snake_case) keys instead of trusting the
    /// `sql<StructName[]>` tag's generic. `Snake` (the default) keeps that
    /// generic, which is sound there.
    field_case: TsFieldCase,
    /// Whether query functions take one argument per parameter or one
    /// `params` object -- see [`TsParamStyle`].
    params_style: TsParamStyle,
    /// Emit plain, JSDoc-annotated `.js` instead of `.ts` -- the
    /// `javascript-postgres` registry name (#81). See
    /// `TypescriptPgBackend::js_mode` for the shared rationale, including why
    /// `row_type = "zod"`, `outer_join_unions`, and `field_case =
    /// "camelCase"` are rejected outright in this mode.
    js_mode: bool,
    /// Which tagged-template client the generated code drives: postgres.js
    /// (`typescript-postgres`) or Bun's built-in `SQL` (`typescript-bun`).
    driver: TemplateDriver,
}

impl TypescriptPostgresBackend {
    pub fn new(engine: &str) -> Result<Self, ScytheError> {
        let default_toml = match engine {
            "postgresql" | "postgres" | "pg" => DEFAULT_MANIFEST_TOML,
            "redshift" => DEFAULT_MANIFEST_REDSHIFT,
            _ => {
                return Err(ScytheError::new(
                    ErrorCode::InvalidConfig,
                    format!(
                        "typescript-postgres only supports PostgreSQL/Redshift, got engine '{}'",
                        engine
                    ),
                ));
            }
        };
        let mut manifest = super::parse_manifest(default_toml)?;
        manifest
            .types
            .scalars
            .insert("json".to_string(), "PostgresJsonValue".to_string());
        Ok(Self {
            manifest,
            row_type: TsRowType::default(),
            outer_join_unions: false,
            structs_only: false,
            field_case: TsFieldCase::default(),
            params_style: TsParamStyle::default(),
            js_mode: false,
            driver: TemplateDriver::PostgresJs,
        })
    }

    /// As [`Self::new`], but selecting the `javascript-postgres` JSDoc emit mode.
    pub fn new_js(engine: &str) -> Result<Self, ScytheError> {
        let mut backend = Self::new(engine)?;
        backend.js_mode = true;
        Ok(backend)
    }

    /// The `typescript-bun` backend: the same tagged-template codegen, driving
    /// Bun's built-in `SQL` client with Bun's own type mappings. PostgreSQL
    /// only -- Bun's adapter is not a Redshift client.
    pub fn new_bun(engine: &str) -> Result<Self, ScytheError> {
        if !matches!(engine, "postgresql" | "postgres" | "pg") {
            return Err(ScytheError::new(
                ErrorCode::InvalidConfig,
                format!("typescript-bun only supports PostgreSQL, got engine '{engine}'"),
            ));
        }
        Ok(Self {
            manifest: super::parse_manifest(BUN_MANIFEST_TOML)?,
            row_type: TsRowType::default(),
            outer_join_unions: false,
            structs_only: false,
            field_case: TsFieldCase::default(),
            params_style: TsParamStyle::default(),
            js_mode: false,
            driver: TemplateDriver::Bun,
        })
    }

    /// As [`Self::new_bun`], but selecting the `javascript-bun` JSDoc emit mode.
    pub fn new_bun_js(engine: &str) -> Result<Self, ScytheError> {
        let mut backend = Self::new_bun(engine)?;
        backend.js_mode = true;
        Ok(backend)
    }

    /// The TypeScript header for Bun: the handle import, plus the JSON alias
    /// and the `TransactionSQL` import only when generated code names them.
    fn bun_ts_header(&self, needs_json_value: bool, needs_transaction: bool) -> String {
        let mut header = String::new();
        if needs_json_value {
            header.push_str(BUN_JSON_VALUE_TS);
        }
        if !self.structs_only {
            if needs_transaction {
                header.push_str("import type { SQL, TransactionSQL } from \"bun\";\n");
            } else {
                header.push_str("import type { SQL } from \"bun\";\n");
            }
        }
        if self.row_type == TsRowType::Zod {
            header.push_str("import { z } from \"zod\";\n");
        }
        header
    }

    /// The columns as this driver returns them -- see [`bun_columns`].
    fn driver_columns<'a>(&self, columns: &'a [ResolvedColumn]) -> std::borrow::Cow<'a, [ResolvedColumn]> {
        match self.driver {
            TemplateDriver::PostgresJs => std::borrow::Cow::Borrowed(columns),
            TemplateDriver::Bun => bun_columns(columns),
        }
    }

    /// Write a `:batch` function's body: run `statement` once per
    /// `loop_header` iteration inside one transaction, leaving the closing
    /// brace to the caller.
    ///
    /// postgres.js opens it with `sql.begin`. Bun rejects `begin()` on a
    /// transaction's own client (`ERR_POSTGRES_INVALID_TRANSACTION_STATE`),
    /// and the handle may be one -- `TransactionSQL` extends `SQL` -- so Bun
    /// nests the batch in a savepoint there instead. Only a transaction
    /// client has `savepoint`, which is what the `in` check reads.
    fn write_batch_body(&self, out: &mut String, loop_header: &str, statement: &str) {
        if self.driver == TemplateDriver::PostgresJs {
            let _ = writeln!(out, "\tawait sql.begin(async (tx) => {{");
            let _ = writeln!(out, "\t\t{loop_header} {{");
            let _ = writeln!(out, "\t\t\tawait tx`");
            let _ = writeln!(out, "    {statement}");
            let _ = writeln!(out, "  `;");
            let _ = writeln!(out, "\t\t}}");
            let _ = writeln!(out, "\t}});");
            return;
        }
        if self.js_mode {
            let _ = writeln!(out, "\t/** @param {{{}}} tx */", self.driver.js_handle_type());
            let _ = writeln!(out, "\tconst run = async (tx) => {{");
        } else {
            let _ = writeln!(out, "\tconst run = async (tx: SQL) => {{");
        }
        let _ = writeln!(out, "\t\t{loop_header} {{");
        let _ = writeln!(out, "\t\t\tawait tx`");
        let _ = writeln!(out, "    {statement}");
        let _ = writeln!(out, "  `;");
        let _ = writeln!(out, "\t\t}}");
        let _ = writeln!(out, "\t}};");
        let savepoint_client = if self.js_mode {
            js_type_cast("import(\"bun\").TransactionSQL", "sql")
        } else {
            "(sql as TransactionSQL)".to_string()
        };
        let _ = writeln!(
            out,
            "\tawait (\"savepoint\" in sql ? {savepoint_client}.savepoint(run) : sql.begin(run));"
        );
    }
}

impl CodegenBackend for TypescriptPostgresBackend {
    fn name(&self) -> &str {
        if self.js_mode {
            self.driver.js_name()
        } else {
            self.driver.ts_name()
        }
    }

    /// The manifest is shared with the TypeScript emit mode and says `ts`; JSDoc
    /// output is plain JavaScript and must land in a `.js` file to be runnable.
    fn output_extension(&self) -> &str {
        if self.js_mode {
            "js"
        } else {
            &self.manifest.backend.file_extension
        }
    }

    fn manifest(&self) -> &scythe_backend::manifest::BackendManifest {
        &self.manifest
    }

    fn manifest_mut(&mut self) -> &mut scythe_backend::manifest::BackendManifest {
        &mut self.manifest
    }

    fn supported_engines(&self) -> &[&str] {
        match self.driver {
            TemplateDriver::PostgresJs => &["postgresql", "redshift"],
            TemplateDriver::Bun => &["postgresql"],
        }
    }

    fn file_header(&self) -> String {
        // ~keep See `TypescriptPgBackend::file_header` for why `.js` output needs
        // no import at all: the driver type goes straight into the JSDoc
        // `@param` tag as `import("postgres").Sql`, and Zod is rejected in
        // this mode.
        if self.driver == TemplateDriver::Bun {
            if self.js_mode {
                return BUN_JSON_VALUE_JS.to_string();
            }
            return self.bun_ts_header(true, false);
        }
        if self.js_mode {
            // Nothing left for this header to carry: the "do not edit"
            // notice lives in the scythe:provenance line every backend emits.
            return "/** @typedef {null | string | number | boolean | Date | readonly PostgresJsonValue[] | {[key: string]: undefined | PostgresJsonValue}} PostgresJsonValue */\n".to_string();
        }
        if self.structs_only {
            if self.row_type == TsRowType::Zod {
                return "import { z } from \"zod\";\n".to_string();
            }
            return String::new();
        }
        let mut header = "type PostgresJsonValue = null | string | number | boolean | Date | readonly PostgresJsonValue[] | { readonly [key: string]: undefined | PostgresJsonValue };\nimport type { Sql } from \"postgres\";\n".to_string();
        if self.row_type == TsRowType::Zod {
            header.push_str("import { z } from \"zod\";\n");
        }
        header
    }

    /// Bun's TypeScript header declares `SqlJsonValue` and imports
    /// `TransactionSQL` only when some generated fragment names them, so a
    /// file without JSON columns or `:batch` queries carries no unused
    /// binding. postgres.js keeps its unconditional header.
    fn file_header_for_results(&self, generated: &[crate::GeneratedCode]) -> String {
        if self.driver != TemplateDriver::Bun || self.js_mode {
            return self.file_header();
        }
        let texts = || {
            generated.iter().flat_map(|code| {
                [
                    code.query_fn.as_deref(),
                    code.row_struct.as_deref(),
                    code.model_struct.as_deref(),
                    code.enum_def.as_deref(),
                ]
                .into_iter()
                .flatten()
                .chain(code.nested_struct_defs.iter().map(|def| def.code.as_str()))
            })
        };
        let needs_json_value = texts().any(|body| body.contains("SqlJsonValue"));
        let needs_transaction = generated
            .iter()
            .filter_map(|code| code.query_fn.as_deref())
            .any(|body| body.contains("TransactionSQL"));
        self.bun_ts_header(needs_json_value, needs_transaction)
    }

    fn generate_struct_decl(
        &self,
        struct_name: &str,
        query_name: &str,
        columns: &[ResolvedColumn],
    ) -> Result<String, ScytheError> {
        let columns = self.driver_columns(columns);
        let columns = &*columns;
        if self.js_mode {
            return Ok(generate_js_typedef_row_struct(struct_name, query_name, columns));
        }
        if self.row_type == TsRowType::Zod {
            if self.outer_join_unions {
                return Ok(generate_zod_union_row_struct(struct_name, query_name, columns));
            }
            return Ok(generate_zod_row_struct(struct_name, query_name, columns));
        }
        if self.outer_join_unions {
            return Ok(generate_ts_union_row_struct(struct_name, query_name, columns, None));
        }
        Ok(generate_ts_interface_row_struct(struct_name, query_name, columns))
    }

    fn generate_query_fn(
        &self,
        analyzed: &AnalyzedQuery,
        struct_name: &str,
        columns: &[ResolvedColumn],
        params: &[ResolvedParam],
    ) -> Result<String, ScytheError> {
        if self.js_mode {
            return self.generate_query_fn_js(analyzed, struct_name, params);
        }
        let query_params = TsQueryParams::new(self.params_style, &analyzed.name, params, &self.manifest.naming);
        if self.structs_only {
            return Ok(query_params.declaration(&analyzed.name).trim_end().to_string());
        }
        let params = &query_params.params[..];
        let columns = self.driver_columns(columns);
        let columns = &*columns;

        let func_name = fn_name(&analyzed.name, &self.manifest.naming);
        let mut out = query_params.declaration(&analyzed.name);

        let sql_clean = super::clean_sql_with_optional(&analyzed.sql, &analyzed.optional_params, &analyzed.params);
        // Escape the user's SQL before postgres.js's own `${}` interpolations
        // are inserted below — otherwise a literal `${` in the user's SQL
        // becomes a live binding, and escaping afterwards would also mangle
        // the interpolations this pass is about to add.
        let sql_clean = escape_ts_template_literal(&sql_clean);
        let param_map: std::collections::HashMap<u32, &ResolvedParam> = analyzed
            .params
            .iter()
            .zip(params.iter())
            .map(|(ap, rp)| (ap.position as u32, rp))
            .collect();
        let sql_template = super::rewrite_pg_placeholders(&sql_clean, |n| {
            param_map.get(&n).map_or_else(
                || "${?}".to_string(),
                |rp| {
                    pg_bind_expr(
                        self.driver,
                        &query_params.access(rp),
                        &rp.neutral_type,
                        rp.nullable,
                        &analyzed.composites,
                    )
                },
            )
        });

        let write_fn_sig = |out: &mut String, name: &str, sig_params: &[(String, String)], ret: &str| {
            let params_inline = sig_params
                .iter()
                .map(|(n, t)| format!("{n}: {t}"))
                .collect::<Vec<_>>()
                .join(", ");
            let oneliner = format!("export async function {}({}): {} {{", name, params_inline, ret);
            if oneliner.len() <= 80 {
                let _ = writeln!(out, "{}", oneliner);
            } else {
                let _ = writeln!(out, "export async function {}(", name);
                for (n, t) in sig_params {
                    let _ = writeln!(out, "\t{}: {},", n, t);
                }
                let _ = writeln!(out, "): {} {{", ret);
            }
        };

        let query_sig_params: Vec<(String, String)> =
            std::iter::once(("sql".to_string(), self.driver.ts_handle_type().to_string()))
                .chain(query_params.signature())
                .collect();

        match &analyzed.command {
            QueryCommand::One => {
                let _ = writeln!(out, "/** Fetch a single {}. */", struct_name);
                let ret = format!("Promise<{}>", struct_name);
                write_fn_sig(&mut out, &func_name, &query_sig_params, &ret);
                match self.field_case {
                    TsFieldCase::Snake => {
                        let _ = writeln!(out, "\tconst rows = await sql<{}[]>`", struct_name);
                        let _ = writeln!(out, "    {}", sql_template);
                        let _ = writeln!(out, "  `;");
                        let _ = writeln!(out, "\tconst row = rows[0];");
                        let _ = writeln!(out, "\tif (row === undefined) {{");
                        let _ = writeln!(out, "\t\t{}", ts_row_not_found_throw(&analyzed.name));
                        let _ = writeln!(out, "\t}}");
                        let overrides = ts_composite_field_overrides(columns, "row");
                        if overrides.is_empty() {
                            let _ = writeln!(out, "\treturn row;");
                        } else {
                            let _ = writeln!(out, "\treturn {{");
                            let _ = writeln!(out, "\t\t...row,");
                            for (key, expr) in &overrides {
                                let _ = writeln!(out, "\t\t{key}: {expr},");
                            }
                            let _ = writeln!(out, "\t}};");
                        }
                    }
                    TsFieldCase::Camel => {
                        let _ = writeln!(out, "\tconst rows = await sql<Record<string, unknown>[]>`");
                        let _ = writeln!(out, "    {}", sql_template);
                        let _ = writeln!(out, "  `;");
                        let _ = writeln!(out, "\tconst row = rows[0];");
                        out.push_str(&generate_ts_one_row_remap(
                            columns,
                            TsRowShape::from_outer_join_unions(self.outer_join_unions),
                            &analyzed.command,
                            &analyzed.name,
                            ts_composite_aware_row_access(columns),
                        ));
                    }
                }
                let _ = write!(out, "}}");
            }
            QueryCommand::Opt => {
                let _ = writeln!(out, "/** Fetch a single {} or null. */", struct_name);
                let ret = format!("Promise<{} | null>", struct_name);
                write_fn_sig(&mut out, &func_name, &query_sig_params, &ret);
                match self.field_case {
                    TsFieldCase::Snake => {
                        let _ = writeln!(out, "\tconst rows = await sql<{}[]>`", struct_name);
                        let _ = writeln!(out, "    {}", sql_template);
                        let _ = writeln!(out, "  `;");
                        let overrides = ts_composite_field_overrides(columns, "row");
                        if overrides.is_empty() {
                            let _ = writeln!(out, "\treturn rows[0] ?? null;");
                        } else {
                            let _ = writeln!(out, "\tconst row = rows[0];");
                            let _ = writeln!(out, "\tif (row === undefined) {{");
                            let _ = writeln!(out, "\t\treturn null;");
                            let _ = writeln!(out, "\t}}");
                            let _ = writeln!(out, "\treturn {{");
                            let _ = writeln!(out, "\t\t...row,");
                            for (key, expr) in &overrides {
                                let _ = writeln!(out, "\t\t{key}: {expr},");
                            }
                            let _ = writeln!(out, "\t}};");
                        }
                    }
                    TsFieldCase::Camel => {
                        let _ = writeln!(out, "\tconst rows = await sql<Record<string, unknown>[]>`");
                        let _ = writeln!(out, "    {}", sql_template);
                        let _ = writeln!(out, "  `;");
                        let _ = writeln!(out, "\tconst row = rows[0];");
                        out.push_str(&generate_ts_one_row_remap(
                            columns,
                            TsRowShape::from_outer_join_unions(self.outer_join_unions),
                            &analyzed.command,
                            &analyzed.name,
                            ts_composite_aware_row_access(columns),
                        ));
                    }
                }
                let _ = write!(out, "}}");
            }
            QueryCommand::Batch => {
                let batch_fn_name = format!("{}Batch", func_name);
                if params.len() > 1 || query_params.interface.is_some() {
                    let params_type_name = match &query_params.interface {
                        Some(interface) => interface.clone(),
                        None => {
                            let params_type_name = format!("{}BatchParams", struct_name);
                            let _ = writeln!(out, "/** Params for {} batch operation. */", struct_name);
                            let _ = writeln!(out, "export interface {} {{", params_type_name);
                            for p in params {
                                let _ = writeln!(out, "\t{}: {};", ts_property_key(&p.field_name), p.full_type);
                            }
                            let _ = writeln!(out, "}}");
                            let _ = writeln!(out);
                            params_type_name
                        }
                    };
                    let _ = writeln!(
                        out,
                        "/** Execute {} for each item in the batch within a transaction. */",
                        analyzed.name
                    );
                    let batch_sig_params = vec![
                        ("sql".to_string(), self.driver.ts_handle_type().to_string()),
                        ("items".to_string(), format!("{}[]", params_type_name)),
                    ];
                    write_fn_sig(&mut out, &batch_fn_name, &batch_sig_params, "Promise<void>");
                    let batch_sql = batch_item_sql(self.driver, &sql_clean, &param_map, &analyzed.composites);
                    self.write_batch_body(&mut out, "for (const item of items)", &batch_sql);
                    let _ = write!(out, "}}");
                } else if params.len() == 1 {
                    let _ = writeln!(
                        out,
                        "/** Execute {} for each item in the batch within a transaction. */",
                        analyzed.name
                    );
                    let batch_sig_params = vec![
                        ("sql".to_string(), self.driver.ts_handle_type().to_string()),
                        ("items".to_string(), format!("{}[]", params[0].full_type)),
                    ];
                    write_fn_sig(&mut out, &batch_fn_name, &batch_sig_params, "Promise<void>");
                    let batch_sql = batch_item_sql_single(self.driver, &sql_clean, &params[0], &analyzed.composites);
                    self.write_batch_body(&mut out, "for (const item of items)", &batch_sql);
                    let _ = write!(out, "}}");
                } else {
                    let _ = writeln!(
                        out,
                        "/** Execute {} for each item in the batch within a transaction. */",
                        analyzed.name
                    );
                    let batch_sig_params = vec![
                        ("sql".to_string(), self.driver.ts_handle_type().to_string()),
                        ("count".to_string(), "number".to_string()),
                    ];
                    write_fn_sig(&mut out, &batch_fn_name, &batch_sig_params, "Promise<void>");
                    self.write_batch_body(&mut out, "for (let i = 0; i < count; i++)", &sql_template);
                    let _ = write!(out, "}}");
                }
            }
            QueryCommand::Many => {
                let _ = writeln!(out, "/** Fetch all {} rows. */", struct_name);
                let ret = format!("Promise<{}[]>", struct_name);
                write_fn_sig(&mut out, &func_name, &query_sig_params, &ret);
                match self.field_case {
                    TsFieldCase::Snake => {
                        let _ = writeln!(out, "\tconst rows = await sql<{}[]>`", struct_name);
                        let _ = writeln!(out, "    {}", sql_template);
                        let _ = writeln!(out, "  `;");
                        let overrides = ts_composite_field_overrides(columns, "row");
                        if overrides.is_empty() {
                            let _ = writeln!(out, "\treturn rows;");
                        } else {
                            let _ = writeln!(out, "\treturn rows.map((row) => ({{");
                            let _ = writeln!(out, "\t\t...row,");
                            for (key, expr) in &overrides {
                                let _ = writeln!(out, "\t\t{key}: {expr},");
                            }
                            let _ = writeln!(out, "\t}}));");
                        }
                    }
                    TsFieldCase::Camel => {
                        let _ = writeln!(out, "\tconst rows = await sql<Record<string, unknown>[]>`");
                        let _ = writeln!(out, "    {}", sql_template);
                        let _ = writeln!(out, "  `;");
                        out.push_str(&generate_ts_many_row_remap(
                            columns,
                            TsRowShape::from_outer_join_unions(self.outer_join_unions),
                            ts_composite_aware_row_access(columns),
                        ));
                    }
                }
                let _ = write!(out, "}}");
            }
            QueryCommand::Exec => {
                let _ = writeln!(out, "/** Execute a query returning no rows. */");
                write_fn_sig(&mut out, &func_name, &query_sig_params, "Promise<void>");
                let _ = writeln!(out, "\tawait sql`");
                let _ = writeln!(out, "    {}", sql_template);
                let _ = writeln!(out, "  `;");
                let _ = write!(out, "}}");
            }
            QueryCommand::ExecResult | QueryCommand::ExecRows => {
                let _ = writeln!(out, "/** Execute a query and return the number of affected rows. */");
                write_fn_sig(&mut out, &func_name, &query_sig_params, "Promise<number>");
                let _ = writeln!(out, "\tconst result = await sql`");
                let _ = writeln!(out, "    {}", sql_template);
                let _ = writeln!(out, "  `;");
                let _ = writeln!(out, "\treturn result.count;");
                let _ = write!(out, "}}");
            }
            QueryCommand::Grouped => {
                unreachable!("Grouped command is routed through generate_grouped_query_fn, not generate_query_fn")
            }
        }

        Ok(out)
    }

    fn generate_grouped_structs(
        &self,
        parent_struct_name: &str,
        child_struct_name: &str,
        parent_columns: &[ResolvedColumn],
        child_columns: &[ResolvedColumn],
        _key_column: &str,
    ) -> Result<String, ScytheError> {
        let parent_columns = self.driver_columns(parent_columns);
        let parent_columns = &*parent_columns;
        let child_columns = self.driver_columns(child_columns);
        let child_columns = &*child_columns;
        if self.js_mode {
            return Ok(generate_js_grouped_typedef_structs(
                child_struct_name,
                parent_struct_name,
                parent_columns,
                child_columns,
            ));
        }
        if self.row_type == TsRowType::Zod {
            return Ok(generate_zod_grouped_structs(
                child_struct_name,
                parent_struct_name,
                parent_columns,
                child_columns,
            ));
        }
        Ok(generate_grouped_interface_structs(
            child_struct_name,
            parent_struct_name,
            parent_columns,
            child_columns,
        ))
    }

    fn generate_grouped_query_fn(&self, request: &GroupedQueryFn<'_>) -> Result<String, ScytheError> {
        if self.js_mode {
            return self.generate_grouped_query_fn_js(request);
        }
        let analyzed = request.analyzed;
        let parent_struct_name = request.parent_struct_name;
        let child_struct_name = request.child_struct_name;
        let parent_columns = self.driver_columns(request.parent_columns);
        let parent_columns = &*parent_columns;
        let child_columns = self.driver_columns(request.child_columns);
        let child_columns = &*child_columns;
        let key_column = request.key_column;
        let query_params = TsQueryParams::new(self.params_style, &analyzed.name, request.params, &self.manifest.naming);

        if self.structs_only {
            return Ok(query_params.declaration(&analyzed.name).trim_end().to_string());
        }
        let params = &query_params.params[..];

        let func_name = fn_name(&analyzed.name, &self.manifest.naming);
        let sql_clean = super::clean_sql_with_optional(&analyzed.sql, &analyzed.optional_params, &analyzed.params);
        let sql_clean = escape_ts_template_literal(&sql_clean);
        let param_map: std::collections::HashMap<u32, &ResolvedParam> = analyzed
            .params
            .iter()
            .zip(params.iter())
            .map(|(ap, rp)| (ap.position as u32, rp))
            .collect();
        let sql_template = super::rewrite_pg_placeholders(&sql_clean, |n| {
            param_map.get(&n).map_or_else(
                || "${?}".to_string(),
                |rp| {
                    pg_bind_expr(
                        self.driver,
                        &query_params.access(rp),
                        &rp.neutral_type,
                        rp.nullable,
                        &analyzed.composites,
                    )
                },
            )
        });

        let signature = query_params.signature();
        let inline_params = std::iter::once(format!("sql: {}", self.driver.ts_handle_type()))
            .chain(signature.iter().map(|(n, t)| format!("{n}: {t}")))
            .collect::<Vec<_>>()
            .join(", ");
        let ret = format!("Promise<{parent_struct_name}[]>");

        let mut out = query_params.declaration(&analyzed.name);
        let oneliner = format!("export async function {func_name}({inline_params}): {ret} {{");
        if oneliner.len() <= 80 {
            let _ = writeln!(out, "/** Fetch grouped {} rows. */", analyzed.name);
            let _ = writeln!(out, "{oneliner}");
        } else {
            let _ = writeln!(out, "/** Fetch grouped {} rows. */", analyzed.name);
            let _ = writeln!(out, "export async function {func_name}(");
            let _ = writeln!(out, "\tsql: {},", self.driver.ts_handle_type());
            for (n, t) in &signature {
                let _ = writeln!(out, "\t{n}: {t},");
            }
            let _ = writeln!(out, "): {ret} {{");
        }

        let _ = writeln!(out, "\tconst flatRows = await sql<Record<string, unknown>[]>`");
        let _ = writeln!(out, "    {sql_template}");
        let _ = writeln!(out, "  `;");

        let all_columns: Vec<ResolvedColumn> = parent_columns.iter().chain(child_columns.iter()).cloned().collect();
        let fold = generate_ts_grouped_fold_body(
            parent_struct_name,
            child_struct_name,
            parent_columns,
            child_columns,
            key_column,
            false,
            ts_composite_aware_row_access(&all_columns),
        );
        out.push_str(&fold);
        let _ = write!(out, "}}");
        Ok(out)
    }

    fn generate_enum_def(&self, enum_info: &EnumInfo) -> Result<String, ScytheError> {
        if self.js_mode {
            return self.generate_enum_def_js(enum_info);
        }
        let type_name = enum_type_name(&enum_info.sql_name, &self.manifest.naming);
        if self.row_type == TsRowType::Zod {
            return Ok(generate_zod_enum(&type_name, &enum_info.values, &self.manifest.naming));
        }
        let mut out = String::new();
        // ~keep Bun takes the `const` object plus string-union form of
        // `typescript-pg`: the driver hands back plain strings, which a union
        // accepts as-is, and the output stays erasable TypeScript (no runtime
        // `enum`), as `erasableSyntaxOnly` and Node's type stripping require.
        if self.driver == TemplateDriver::Bun {
            let values_name = format!("{type_name}Values");
            let _ = writeln!(out, "export const {values_name} = {{");
            for value in &enum_info.values {
                let variant = enum_variant_name(value, &self.manifest.naming);
                let _ = writeln!(out, "\t{variant}: \"{value}\",");
            }
            let _ = writeln!(out, "}} as const;");
            let _ = writeln!(out);
            let _ = write!(
                out,
                "export type {type_name} = typeof {values_name}[keyof typeof {values_name}];"
            );
            return Ok(out);
        }
        let _ = writeln!(out, "export enum {} {{", type_name);
        for value in &enum_info.values {
            let variant = enum_variant_name(value, &self.manifest.naming);
            let _ = writeln!(out, "\t{} = \"{}\",", variant, value);
        }
        let _ = write!(out, "}}");
        Ok(out)
    }

    fn generate_composite_def(&self, composite: &CompositeInfo) -> Result<String, ScytheError> {
        if self.js_mode {
            return self.generate_composite_def_js(composite);
        }
        let name = composite_type_name(&composite.sql_name, &self.manifest.naming);
        let mut out = String::new();
        let _ = writeln!(out, "/** Composite type {}. */", composite.sql_name);
        let _ = writeln!(out, "export interface {} {{", name);
        // ~keep board #204: a composite with zero fields cannot exist in PostgreSQL
        // (`CREATE TYPE ... AS ()` is rejected), so there is no reachable runtime value that
        // would need `parse{name}` here.
        if composite.fields.is_empty() {
            let _ = write!(out, "}}");
            return Ok(out);
        }
        let mut field_types: Vec<String> = Vec::with_capacity(composite.fields.len());
        for field in &composite.fields {
            let ts_type = resolve_type(&field.neutral_type, &self.manifest, field.nullable)
                .map(|t| t.into_owned())
                .map_err(|e| {
                    ScytheError::new(ErrorCode::InternalError, format!("composite field type error: {}", e))
                })?;
            let _ = writeln!(out, "\t{}: {};", ts_property_key(&to_camel_case(&field.name)), ts_type);
            field_types.push(ts_type);
        }
        let _ = writeln!(out, "}}");

        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "// ~keep board #204: {} has no adapter for a user-defined composite -- it",
            self.driver.label()
        );
        let _ = writeln!(
            out,
            "// hands back the driver's raw text form as a plain string. Parse it here."
        );
        let _ = writeln!(out, "export function parse{name}(raw: unknown): {name} | null {{");
        let _ = writeln!(out, "\tif (raw === null || raw === undefined) {{");
        let _ = writeln!(out, "\t\treturn null;");
        let _ = writeln!(out, "\t}}");
        let _ = writeln!(out, "\tconst f = parse{name}Fields(raw as string);");
        let _ = writeln!(out, "\treturn {{");
        for (i, field) in composite.fields.iter().enumerate() {
            let raw = format!("f[{i}]");
            let conversion_type = resolve_type(&field.neutral_type, &self.manifest, false)
                .map(|t| t.into_owned())
                .map_err(|e| {
                    ScytheError::new(ErrorCode::InternalError, format!("composite field type error: {}", e))
                })?;
            let value_expr =
                ts_composite_field_from_text(&field.neutral_type, &conversion_type, &raw, field.nullable, &name);
            let _ = writeln!(
                out,
                "\t\t{}: {value_expr},",
                ts_property_key(&to_camel_case(&field.name))
            );
        }
        let _ = writeln!(out, "\t}};");
        let _ = writeln!(out, "}}");
        let _ = writeln!(out);
        out.push_str(&ts_parse_composite_fields_helper(&name));
        if ts_composite_needs_bytes_helper(composite) {
            let _ = writeln!(out);
            let _ = writeln!(out);
            out.push_str(&ts_parse_composite_bytes_helper(&name));
        }
        if ts_composite_needs_offset_datetime_helper(composite) {
            let _ = writeln!(out);
            let _ = writeln!(out);
            out.push_str(&ts_parse_composite_offset_datetime_helper(&name));
        }
        Ok(out)
    }

    fn generate_nested_struct_def(
        &self,
        nested: &scythe_core::analyzer::NestedStructInfo,
    ) -> Result<Option<String>, ScytheError> {
        if self.js_mode || !self.manifest.types.containers.contains_key("json_nested") {
            return Ok(None);
        }
        Ok(generate_ts_nested_interface(nested, &self.manifest).ok())
    }

    fn generate_composite_def_for_nested(&self, composite: &CompositeInfo) -> Result<String, ScytheError> {
        let mut out = self.generate_composite_def(composite)?;
        if !self.js_mode && self.manifest.types.containers.contains_key("json_nested") {
            out.push_str("\n\n");
            out.push_str(&generate_ts_json_composite_interface(composite, &self.manifest)?);
        }
        Ok(out)
    }

    fn apply_options(&mut self, options: &std::collections::HashMap<String, String>) -> Result<(), ScytheError> {
        reject_unknown_options(
            &["row_type", "outer_join_unions", "structs_only", "field_case", "params"],
            options,
        )?;

        if let Some(value) = options.get("row_type") {
            self.row_type = TsRowType::from_option(value)?;
        }
        if let Some(value) = options.get("outer_join_unions") {
            self.outer_join_unions = parse_bool_option("outer_join_unions", value)?;
        }
        if let Some(value) = options.get("structs_only") {
            self.structs_only = parse_bool_option("structs_only", value)?;
        }
        if let Some(value) = options.get("field_case") {
            self.field_case = TsFieldCase::from_option(value)?;
            // Keeps the central rename in `resolve.rs` (which reads this
            // string, not `TsFieldCase`) in sync with the runtime remap
            // decision above -- one option, one source of truth for both.
            self.manifest.naming.field_case = value.clone();
        }
        if let Some(value) = options.get("params") {
            self.params_style = TsParamStyle::from_option(value)?;
        }

        // ~keep See `TypescriptPgBackend::apply_options` for why these are
        // rejected outright in JSDoc mode rather than silently ignored.
        if self.js_mode {
            if self.params_style == TsParamStyle::Object {
                return Err(ScytheError::new(
                    ErrorCode::InvalidConfig,
                    format!(
                        "{} does not support params = \"object\" -- use {}",
                        self.driver.js_name(),
                        self.driver.ts_name()
                    ),
                ));
            }
            if self.row_type == TsRowType::Zod {
                return Err(ScytheError::new(
                    ErrorCode::InternalError,
                    format!(
                        "{} does not support row_type = \"zod\": the inferred `export type X = \
                         z.infer<...>` alias is TypeScript-only syntax a plain .js file cannot carry -- use \
                         {} for Zod row types",
                        self.driver.js_name(),
                        self.driver.ts_name()
                    ),
                ));
            }
            if self.outer_join_unions {
                return Err(ScytheError::new(
                    ErrorCode::InternalError,
                    format!(
                        "{} does not support outer_join_unions: the discriminated union is a \
                         TypeScript `type X = A & (B | C)` alias, which plain .js cannot carry -- use {}",
                        self.driver.js_name(),
                        self.driver.ts_name()
                    ),
                ));
            }
            if self.field_case == TsFieldCase::Camel {
                return Err(ScytheError::new(
                    ErrorCode::InternalError,
                    format!(
                        "{} does not support field_case = \"camelCase\": the field remap needs a \
                         TypeScript `as T` assertion, which plain .js cannot carry -- use {}",
                        self.driver.js_name(),
                        self.driver.ts_name()
                    ),
                ));
            }
        }
        Ok(())
    }
}

impl TypescriptPostgresBackend {
    /// JSDoc-mode counterpart of `generate_query_fn` -- see
    /// `TypescriptPgBackend::generate_query_fn_js` for why `field_case =
    /// "camelCase"` needs no handling here.
    fn generate_query_fn_js(
        &self,
        analyzed: &AnalyzedQuery,
        struct_name: &str,
        params: &[ResolvedParam],
    ) -> Result<String, ScytheError> {
        if self.structs_only {
            return Ok(String::new());
        }

        let sql_type = self.driver.js_handle_type();

        let func_name = fn_name(&analyzed.name, &self.manifest.naming);
        let mut out = String::new();

        let sql_clean = super::clean_sql_with_optional(&analyzed.sql, &analyzed.optional_params, &analyzed.params);
        let sql_clean = escape_ts_template_literal(&sql_clean);
        let param_map: std::collections::HashMap<u32, &ResolvedParam> = analyzed
            .params
            .iter()
            .zip(params.iter())
            .map(|(ap, rp)| (ap.position as u32, rp))
            .collect();
        let sql_template = super::rewrite_pg_placeholders(&sql_clean, |n| {
            param_map.get(&n).map_or_else(
                || "${?}".to_string(),
                |rp| {
                    pg_bind_expr(
                        self.driver,
                        &rp.field_name,
                        &rp.neutral_type,
                        rp.nullable,
                        &analyzed.composites,
                    )
                },
            )
        });

        let query_sig_params: Vec<(String, String)> = std::iter::once(("sql".to_string(), sql_type.to_string()))
            .chain(params.iter().map(|p| (p.field_name.clone(), p.full_type.clone())))
            .collect();

        let write_signature = |out: &mut String, description: &str, sig_params: &[(String, String)], ret: &str| {
            out.push_str(&generate_jsdoc_fn_header(description, sig_params, ret));
            let _ = writeln!(out);
            let _ = writeln!(out, "{}", js_fn_signature_line(true, &func_name, sig_params));
        };

        match &analyzed.command {
            QueryCommand::One => {
                write_signature(
                    &mut out,
                    &format!("Fetch a single {}.", struct_name),
                    &query_sig_params,
                    &format!("Promise<{}>", struct_name),
                );
                // ~keep postgres.js's `sql` tag defaults to its own untyped `Row`
                // shape without a type argument -- and unlike
                // `client.query(...)` (pg) or `pool.execute(...)` (mysql2),
                // that default is a *concrete* type, not `any`, so `rows[0]`
                // does not structurally match `StructName` and `tsc
                // --strict` rejects the assignment on `return`. The TS path
                // supplies `sql<StructName[]>` to fix this; JS mode has no
                // generic call syntax, so the JSDoc inline cast substitutes.
                let query_expr = format!("await sql`\n    {sql_template}\n  `");
                let _ = writeln!(
                    out,
                    "\tconst rows = {};",
                    js_type_cast(&format!("Array<{struct_name}>"), &query_expr)
                );
                let _ = writeln!(out, "\tconst row = rows[0];");
                let _ = writeln!(out, "\tif (row === undefined) {{");
                let _ = writeln!(out, "\t\t{}", ts_row_not_found_throw(&analyzed.name));
                let _ = writeln!(out, "\t}}");
                let _ = writeln!(out, "\treturn row;");
                let _ = write!(out, "}}");
            }
            QueryCommand::Opt => {
                write_signature(
                    &mut out,
                    &format!("Fetch a single {} or null.", struct_name),
                    &query_sig_params,
                    &format!("Promise<{} | null>", struct_name),
                );
                // ~keep postgres.js's `sql` tag defaults to its own untyped `Row`
                // shape without a type argument -- and unlike
                // `client.query(...)` (pg) or `pool.execute(...)` (mysql2),
                // that default is a *concrete* type, not `any`, so `rows[0]`
                // does not structurally match `StructName` and `tsc
                // --strict` rejects the assignment on `return`. The TS path
                // supplies `sql<StructName[]>` to fix this; JS mode has no
                // generic call syntax, so the JSDoc inline cast substitutes.
                let query_expr = format!("await sql`\n    {sql_template}\n  `");
                let _ = writeln!(
                    out,
                    "\tconst rows = {};",
                    js_type_cast(&format!("Array<{struct_name}>"), &query_expr)
                );
                let _ = writeln!(out, "\treturn rows[0] ?? null;");
                let _ = write!(out, "}}");
            }
            QueryCommand::Many => {
                write_signature(
                    &mut out,
                    &format!("Fetch all {} rows.", struct_name),
                    &query_sig_params,
                    &format!("Promise<{}[]>", struct_name),
                );
                let query_expr = format!("await sql`\n    {sql_template}\n  `");
                let _ = writeln!(
                    out,
                    "\tconst rows = {};",
                    js_type_cast(&format!("Array<{struct_name}>"), &query_expr)
                );
                let _ = writeln!(out, "\treturn rows;");
                let _ = write!(out, "}}");
            }
            QueryCommand::Exec => {
                write_signature(
                    &mut out,
                    "Execute a query returning no rows.",
                    &query_sig_params,
                    "Promise<void>",
                );
                let _ = writeln!(out, "\tawait sql`");
                let _ = writeln!(out, "    {}", sql_template);
                let _ = writeln!(out, "  `;");
                let _ = write!(out, "}}");
            }
            QueryCommand::ExecResult | QueryCommand::ExecRows => {
                write_signature(
                    &mut out,
                    "Execute a query and return the number of affected rows.",
                    &query_sig_params,
                    "Promise<number>",
                );
                let _ = writeln!(out, "\tconst result = await sql`");
                let _ = writeln!(out, "    {}", sql_template);
                let _ = writeln!(out, "  `;");
                let _ = writeln!(out, "\treturn result.count;");
                let _ = write!(out, "}}");
            }
            QueryCommand::Batch => {
                let batch_fn_name = format!("{}Batch", func_name);
                if params.len() > 1 {
                    let params_type_name = format!("{}BatchParams", struct_name);
                    let fields: Vec<(String, String)> = params
                        .iter()
                        .map(|p| (p.field_name.clone(), p.full_type.clone()))
                        .collect();
                    out.push_str(&generate_js_typedef(
                        &params_type_name,
                        &format!("Params for {} batch operation.", struct_name),
                        &fields,
                    ));
                    let _ = writeln!(out);
                    let _ = writeln!(out);
                    let batch_sig_params = vec![
                        ("sql".to_string(), sql_type.to_string()),
                        ("items".to_string(), format!("Array<{}>", params_type_name)),
                    ];
                    out.push_str(&generate_jsdoc_fn_header(
                        &format!(
                            "Execute {} for each item in the batch within a transaction.",
                            analyzed.name
                        ),
                        &batch_sig_params,
                        "Promise<void>",
                    ));
                    let _ = writeln!(out);
                    let _ = writeln!(out, "{}", js_fn_signature_line(true, &batch_fn_name, &batch_sig_params));
                    let batch_sql = batch_item_sql(self.driver, &sql_clean, &param_map, &analyzed.composites);
                    self.write_batch_body(&mut out, "for (const item of items)", &batch_sql);
                    let _ = write!(out, "}}");
                } else if params.len() == 1 {
                    let batch_sig_params = vec![
                        ("sql".to_string(), sql_type.to_string()),
                        ("items".to_string(), format!("Array<{}>", params[0].full_type)),
                    ];
                    out.push_str(&generate_jsdoc_fn_header(
                        &format!(
                            "Execute {} for each item in the batch within a transaction.",
                            analyzed.name
                        ),
                        &batch_sig_params,
                        "Promise<void>",
                    ));
                    let _ = writeln!(out);
                    let _ = writeln!(out, "{}", js_fn_signature_line(true, &batch_fn_name, &batch_sig_params));
                    let batch_sql = batch_item_sql_single(self.driver, &sql_clean, &params[0], &analyzed.composites);
                    self.write_batch_body(&mut out, "for (const item of items)", &batch_sql);
                    let _ = write!(out, "}}");
                } else {
                    let batch_sig_params = vec![
                        ("sql".to_string(), sql_type.to_string()),
                        ("count".to_string(), "number".to_string()),
                    ];
                    out.push_str(&generate_jsdoc_fn_header(
                        &format!(
                            "Execute {} for each item in the batch within a transaction.",
                            analyzed.name
                        ),
                        &batch_sig_params,
                        "Promise<void>",
                    ));
                    let _ = writeln!(out);
                    let _ = writeln!(out, "{}", js_fn_signature_line(true, &batch_fn_name, &batch_sig_params));
                    self.write_batch_body(&mut out, "for (let i = 0; i < count; i++)", &sql_template);
                    let _ = write!(out, "}}");
                }
            }
            QueryCommand::Grouped => {
                unreachable!("Grouped command is routed through generate_grouped_query_fn, not generate_query_fn")
            }
        }

        Ok(out)
    }

    /// JSDoc-mode counterpart of `generate_grouped_query_fn`.
    fn generate_grouped_query_fn_js(&self, request: &GroupedQueryFn<'_>) -> Result<String, ScytheError> {
        let analyzed = request.analyzed;
        let parent_struct_name = request.parent_struct_name;
        let child_struct_name = request.child_struct_name;
        let parent_columns = self.driver_columns(request.parent_columns);
        let parent_columns = &*parent_columns;
        let child_columns = self.driver_columns(request.child_columns);
        let child_columns = &*child_columns;
        let params = request.params;
        let key_column = request.key_column;

        if self.structs_only {
            return Ok(String::new());
        }

        let sql_type = self.driver.js_handle_type();

        let func_name = fn_name(&analyzed.name, &self.manifest.naming);
        let sql_clean = super::clean_sql_with_optional(&analyzed.sql, &analyzed.optional_params, &analyzed.params);
        let sql_clean = escape_ts_template_literal(&sql_clean);
        let param_map: std::collections::HashMap<u32, &ResolvedParam> = analyzed
            .params
            .iter()
            .zip(params.iter())
            .map(|(ap, rp)| (ap.position as u32, rp))
            .collect();
        let sql_template = super::rewrite_pg_placeholders(&sql_clean, |n| {
            param_map.get(&n).map_or_else(
                || "${?}".to_string(),
                |rp| {
                    pg_bind_expr(
                        self.driver,
                        &rp.field_name,
                        &rp.neutral_type,
                        rp.nullable,
                        &analyzed.composites,
                    )
                },
            )
        });

        let sig_params: Vec<(String, String)> = std::iter::once(("sql".to_string(), sql_type.to_string()))
            .chain(params.iter().map(|p| (p.field_name.clone(), p.full_type.clone())))
            .collect();
        let ret = format!("Promise<{parent_struct_name}[]>");

        let mut out = String::new();
        out.push_str(&generate_jsdoc_fn_header(
            &format!("Fetch grouped {} rows.", analyzed.name),
            &sig_params,
            &ret,
        ));
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", js_fn_signature_line(true, &func_name, &sig_params));

        let _ = writeln!(out, "\tconst flatRows = await sql`");
        let _ = writeln!(out, "    {sql_template}");
        let _ = writeln!(out, "  `;");

        let fold = generate_ts_grouped_fold_body(
            parent_struct_name,
            child_struct_name,
            parent_columns,
            child_columns,
            key_column,
            true,
            |name, _ty| ts_index_access("row", name),
        );
        out.push_str(&fold);
        let _ = write!(out, "}}");
        Ok(out)
    }

    /// JSDoc-mode counterpart of `generate_enum_def`.
    fn generate_enum_def_js(&self, enum_info: &EnumInfo) -> Result<String, ScytheError> {
        let type_name = enum_type_name(&enum_info.sql_name, &self.manifest.naming);
        let variants: Vec<(String, String)> = enum_info
            .values
            .iter()
            .map(|value| {
                (
                    enum_variant_name(value, &self.manifest.naming).to_string(),
                    value.clone(),
                )
            })
            .collect();
        Ok(super::typescript_common::generate_js_enum_def(&type_name, &variants))
    }

    /// JSDoc-mode counterpart of `generate_composite_def`.
    fn generate_composite_def_js(&self, composite: &CompositeInfo) -> Result<String, ScytheError> {
        let name = composite_type_name(&composite.sql_name, &self.manifest.naming);
        let mut fields = Vec::with_capacity(composite.fields.len());
        for field in &composite.fields {
            let ts_type = resolve_type(&field.neutral_type, &self.manifest, field.nullable)
                .map(|t| t.into_owned())
                .map_err(|e| {
                    ScytheError::new(ErrorCode::InternalError, format!("composite field type error: {}", e))
                })?;
            fields.push((to_camel_case(&field.name).into_owned(), ts_type));
        }
        Ok(generate_js_typedef(
            &name,
            &format!("Composite type {}.", composite.sql_name),
            &fields,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{TemplateDriver, TypescriptPostgresBackend, pg_bind_expr};
    use crate::backend_trait::CodegenBackend;
    use scythe_core::analyzer::{AnalyzedColumn, AnalyzedParam, AnalyzedQuery, GroupByConfig};
    use scythe_core::analyzer::{CompositeFieldInfo, CompositeInfo};
    use scythe_core::parser::QueryCommand;

    fn discriminated_join_columns() -> Vec<crate::backend_trait::ResolvedColumn> {
        use crate::backend_trait::ResolvedColumn;
        vec![
            ResolvedColumn {
                name: "id".to_string(),
                field_name: "id".to_string(),
                lang_type: "number".to_string(),
                full_type: "number".to_string(),
                neutral_type: "int32".to_string(),
                sql_type: "int4".to_string(),
                nullable: false,
                join_group: None,
                nullable_before_join: false,
            },
            ResolvedColumn {
                name: "total".to_string(),
                field_name: "total".to_string(),
                lang_type: "string".to_string(),
                full_type: "string | null".to_string(),
                neutral_type: "decimal".to_string(),
                sql_type: "numeric".to_string(),
                nullable: true,
                join_group: Some("o".to_string()),
                nullable_before_join: false,
            },
        ]
    }

    #[test]
    fn test_zod_row_type_combined_with_outer_join_unions_emits_a_real_union_schema() {
        let mut backend = TypescriptPostgresBackend::new("postgresql").unwrap();
        backend
            .apply_options(&std::collections::HashMap::from([
                ("row_type".to_string(), "zod".to_string()),
                ("outer_join_unions".to_string(), "true".to_string()),
            ]))
            .unwrap();

        let row_struct = backend
            .generate_row_struct("GetUserOrders", &discriminated_join_columns())
            .unwrap();

        assert!(
            row_struct.contains(".and(z.union(["),
            "must emit a real discriminated union; got:\n{row_struct}"
        );
    }

    #[test]
    fn test_zod_row_type_without_outer_join_unions_is_unchanged() {
        let mut backend = TypescriptPostgresBackend::new("postgresql").unwrap();
        backend
            .apply_options(&std::collections::HashMap::from([(
                "row_type".to_string(),
                "zod".to_string(),
            )]))
            .unwrap();

        let row_struct = backend
            .generate_row_struct("GetUserOrders", &discriminated_join_columns())
            .unwrap();

        assert_eq!(
            row_struct,
            crate::backends::typescript_common::generate_zod_row_struct(
                "GetUserOrdersRow",
                "GetUserOrders",
                &discriminated_join_columns()
            )
        );
    }

    fn make_one_query(sql: &str, params: Vec<AnalyzedParam>) -> AnalyzedQuery {
        AnalyzedQuery::build(|aq| {
            aq.name = "GetUserById".to_string();
            aq.command = QueryCommand::One;
            aq.sql = sql.to_string();
            aq.columns = vec![AnalyzedColumn {
                name: "id".to_string(),
                neutral_type: "int32".to_string(),
                nullable: false,
                ..Default::default()
            }];
            aq.params = params;
            aq.deprecated = None;
            aq.source_table = None;
            aq.composites = vec![];
            aq.enums = vec![];
            aq.optional_params = vec![];
            aq.group_by = None;
            aq.custom = vec![];
        })
    }

    /// postgres.js's `sql` tag turns every `${}` into a live parameter
    /// binding, so a literal `${` surviving from the user's SQL would be
    /// misread as one. It must come out as inert escaped text while
    /// scythe's own binding for `$1` stays live.
    #[test]
    fn test_query_fn_escapes_user_dollar_brace_but_keeps_own_param_bindings_live() {
        let backend = TypescriptPostgresBackend::new("postgresql").unwrap();
        let query = make_one_query(
            "SELECT id FROM users WHERE name = 'literal ${not_a_binding}' AND id = $1",
            vec![AnalyzedParam {
                constraints: None,
                name: "id".to_string(),
                neutral_type: "int32".to_string(),
                nullable: false,
                position: 1,
                source_relation: None,
            }],
        );
        let result = crate::generate_with_backend(&query, &backend).unwrap();
        let query_fn = result.query_fn.as_deref().unwrap();

        assert!(
            query_fn.contains(r"'literal \${not_a_binding}'"),
            "user's literal ${{}} must be escaped inert text; got:\n{query_fn}"
        );
        assert!(
            query_fn.contains("AND id = ${id}"),
            "scythe's own param binding must stay a live interpolation; got:\n{query_fn}"
        );
    }

    /// A literal backslash in the user's SQL must be doubled so it stays a
    /// single literal backslash in the generated JS template literal.
    #[test]
    fn test_query_fn_escapes_user_backslash_in_sql() {
        let backend = TypescriptPostgresBackend::new("postgresql").unwrap();
        let query = make_one_query(r"SELECT id FROM users WHERE name = E'a\\b'", vec![]);
        let result = crate::generate_with_backend(&query, &backend).unwrap();
        let query_fn = result.query_fn.as_deref().unwrap();

        assert!(
            query_fn.contains(r"E'a\\\\b'"),
            "user backslash must be doubled; got:\n{query_fn}"
        );
    }

    /// A literal backtick in the user's SQL must not terminate the `sql`
    /// tag's template literal early.
    #[test]
    fn test_query_fn_escapes_user_backtick_in_sql() {
        let backend = TypescriptPostgresBackend::new("postgresql").unwrap();
        let query = make_one_query("SELECT id FROM users WHERE name = `oops`", vec![]);
        let result = crate::generate_with_backend(&query, &backend).unwrap();
        let query_fn = result.query_fn.as_deref().unwrap();

        assert!(
            query_fn.contains(r"WHERE name = \`oops\`"),
            "user backtick must be escaped; got:\n{query_fn}"
        );
    }

    fn make_grouped_query() -> AnalyzedQuery {
        let parent_cols = vec![
            AnalyzedColumn {
                name: "id".to_string(),
                neutral_type: "int32".to_string(),
                nullable: false,
                ..Default::default()
            },
            AnalyzedColumn {
                name: "name".to_string(),
                neutral_type: "string".to_string(),
                nullable: false,
                ..Default::default()
            },
            AnalyzedColumn {
                name: "email".to_string(),
                neutral_type: "string".to_string(),
                nullable: false,
                ..Default::default()
            },
        ];
        let child_cols = vec![
            AnalyzedColumn {
                name: "order_id".to_string(),
                neutral_type: "int32".to_string(),
                nullable: false,
                ..Default::default()
            },
            AnalyzedColumn {
                name: "total".to_string(),
                neutral_type: "decimal".to_string(),
                nullable: true,
                ..Default::default()
            },
            AnalyzedColumn {
                name: "order_date".to_string(),
                neutral_type: "datetime".to_string(),
                nullable: false,
                ..Default::default()
            },
        ];
        let all_cols = [parent_cols.clone(), child_cols.clone()].concat();
        AnalyzedQuery::build(|aq| {
            aq.name = "GetUsersWithOrders".to_string();
            aq.command = QueryCommand::Grouped;
            aq.sql = "SELECT u.id, u.name, u.email, o.id AS order_id, o.total, o.created_at AS order_date\nFROM users u\nJOIN orders o ON o.user_id = u.id".to_string();
            aq.columns = all_cols;
            aq.params = vec![];
            aq.deprecated = None;
            aq.source_table = None;
            aq.composites = vec![];
            aq.enums = vec![];
            aq.optional_params = vec![];
            aq.group_by = Some(GroupByConfig {
                table: "users".to_string(),
                key_column: "id".to_string(),
                parent_columns: parent_cols,
                child_columns: child_cols,
            });
            aq.custom = vec![];
        })
    }

    #[test]
    fn test_grouped_typescript_postgres_structs() {
        let backend = TypescriptPostgresBackend::new("postgresql").unwrap();
        let query = make_grouped_query();
        let result = crate::generate_with_backend(&query, &backend).unwrap();
        let row_struct = result.row_struct.as_deref().unwrap();

        assert!(
            row_struct.contains("interface GetUsersWithOrdersChildRow"),
            "missing child; got:\n{row_struct}"
        );
        assert!(
            row_struct.contains("order_id: number"),
            "child missing order_id; got:\n{row_struct}"
        );
        assert!(
            row_struct.contains("interface GetUsersWithOrdersRow"),
            "missing parent; got:\n{row_struct}"
        );
        assert!(
            row_struct.contains("children: GetUsersWithOrdersChildRow[]"),
            "missing children; got:\n{row_struct}"
        );
        let child_pos = row_struct.find("GetUsersWithOrdersChildRow").unwrap();
        let parent_pos = row_struct.find("interface GetUsersWithOrdersRow").unwrap();
        assert!(child_pos < parent_pos, "child must precede parent");
    }

    #[test]
    fn test_grouped_typescript_postgres_query_fn() {
        let backend = TypescriptPostgresBackend::new("postgresql").unwrap();
        let query = make_grouped_query();
        let result = crate::generate_with_backend(&query, &backend).unwrap();
        let query_fn = result.query_fn.as_deref().unwrap();

        assert!(query_fn.contains("getUsersWithOrders"), "missing fn; got:\n{query_fn}");
        assert!(
            query_fn.contains("Promise<GetUsersWithOrdersRow[]>"),
            "wrong return type; got:\n{query_fn}"
        );
        assert!(
            query_fn.contains("sql<Record<string, unknown>[]>"),
            "must use typed sql template; got:\n{query_fn}"
        );
        assert!(
            query_fn.contains("new Map<unknown, GetUsersWithOrdersRow>()"),
            "must use Map; got:\n{query_fn}"
        );
        assert!(
            query_fn.contains("parent.children.push"),
            "must fold children; got:\n{query_fn}"
        );
        assert!(
            query_fn.contains("return result"),
            "must return result; got:\n{query_fn}"
        );
    }

    #[test]
    fn test_structs_only_suppresses_query_fn_and_driver_import() {
        let mut backend = TypescriptPostgresBackend::new("postgresql").unwrap();
        backend
            .apply_options(&std::collections::HashMap::from([(
                "structs_only".to_string(),
                "true".to_string(),
            )]))
            .unwrap();

        let query = make_one_query("SELECT id FROM users WHERE id = $1", vec![]);
        let result = crate::generate_with_backend(&query, &backend).unwrap();

        assert_eq!(
            result.query_fn.as_deref(),
            Some(""),
            "structs_only must suppress the query function"
        );
        assert!(
            result
                .row_struct
                .as_deref()
                .unwrap()
                .contains("interface GetUserByIdRow"),
            "row struct must still be emitted"
        );

        let header = backend.file_header();
        assert!(
            !header.contains("postgres"),
            "the unused postgres driver import must be dropped; got:\n{header}"
        );
    }

    #[test]
    fn test_structs_only_unset_leaves_query_fn_present() {
        let backend = TypescriptPostgresBackend::new("postgresql").unwrap();
        let query = make_one_query("SELECT id FROM users WHERE id = $1", vec![]);
        let result = crate::generate_with_backend(&query, &backend).unwrap();

        assert!(
            !result.query_fn.as_deref().unwrap().is_empty(),
            "without structs_only the query function must still be generated"
        );
        assert!(backend.file_header().contains("import type { Sql } from \"postgres\";"));
    }

    #[test]
    fn test_structs_only_rejects_invalid_value() {
        let mut backend = TypescriptPostgresBackend::new("postgresql").unwrap();
        let result = backend.apply_options(&std::collections::HashMap::from([(
            "structs_only".to_string(),
            "maybe".to_string(),
        )]));
        assert!(result.is_err(), "expected 'maybe' to be rejected");
    }

    #[test]
    fn test_structs_only_combined_with_zod_row_type_keeps_zod_import_and_schema() {
        let mut backend = TypescriptPostgresBackend::new("postgresql").unwrap();
        backend
            .apply_options(&std::collections::HashMap::from([
                ("structs_only".to_string(), "true".to_string()),
                ("row_type".to_string(), "zod".to_string()),
            ]))
            .unwrap();

        let query = make_one_query("SELECT id FROM users WHERE id = $1", vec![]);
        let result = crate::generate_with_backend(&query, &backend).unwrap();

        assert_eq!(result.query_fn.as_deref(), Some(""));
        assert!(
            result.row_struct.as_deref().unwrap().contains("z.object({"),
            "zod schema must still be emitted"
        );

        let header = backend.file_header();
        assert!(header.contains("import { z } from \"zod\";"), "got:\n{header}");
        assert!(!header.contains("postgres"), "got:\n{header}");
    }

    fn make_batch_query(name: &str, sql: &str, params: Vec<AnalyzedParam>) -> AnalyzedQuery {
        AnalyzedQuery::build(|aq| {
            aq.name = name.to_string();
            aq.command = QueryCommand::Batch;
            aq.sql = sql.to_string();
            aq.columns = vec![];
            aq.params = params;
            aq.deprecated = None;
            aq.source_table = None;
            aq.composites = vec![];
            aq.enums = vec![];
            aq.optional_params = vec![];
            aq.group_by = None;
            aq.custom = vec![];
        })
    }

    /// Regression test: `write_fn_sig`'s wrapped (>80 char) branch used to
    /// discard the `params_inline`/`sig_params` it was given and rebuild the
    /// signature from the outer per-column `params` slice instead. For a
    /// `:batch` function that slice is wrong -- the actual signature takes
    /// `items: XBatchParams[]`, not the raw columns -- so the emitted
    /// function declared parameters that didn't match its body (which
    /// references `items`). This must fail if that fallback is reinstated.
    #[test]
    fn test_batch_signature_wrap_declares_items_not_raw_columns() {
        let backend = TypescriptPostgresBackend::new("postgresql").unwrap();
        let query = make_batch_query(
            "CreateUserAccountRecord",
            "INSERT INTO user_account_record (name, email) VALUES ($1, $2)",
            vec![
                AnalyzedParam {
                    constraints: None,
                    name: "name".to_string(),
                    neutral_type: "string".to_string(),
                    nullable: false,
                    position: 1,
                    source_relation: None,
                },
                AnalyzedParam {
                    constraints: None,
                    name: "email".to_string(),
                    neutral_type: "string".to_string(),
                    nullable: false,
                    position: 2,
                    source_relation: None,
                },
            ],
        );

        let result = crate::generate_with_backend(&query, &backend).unwrap();
        let query_fn = result.query_fn.as_deref().unwrap();

        assert!(
            query_fn.contains("\titems: CreateUserAccountRecordRowBatchParams[],"),
            "wrapped batch signature must declare items with the batch params type; got:\n{query_fn}"
        );
        assert!(
            !query_fn.contains("\tname: string,") && !query_fn.contains("\temail: string,"),
            "wrapped batch signature must not fall back to the raw per-column params; got:\n{query_fn}"
        );
        assert!(
            query_fn.contains("for (const item of items)"),
            "every identifier the body references (items) must be declared in the signature; got:\n{query_fn}"
        );
    }

    /// Regression test guarding against a naive fix that splits
    /// `params_inline` on top-level `", "` to recover individual parameters.
    /// The synthetic type contains a top-level-looking `", "` inside its
    /// generic arguments. The structured `(name, type)` pairs must survive a
    /// wrapped signature intact.
    #[test]
    fn test_batch_signature_wrap_preserves_type_with_internal_comma() {
        let mut backend = TypescriptPostgresBackend::new("postgresql").unwrap();
        backend
            .manifest
            .types
            .scalars
            .insert("json".to_string(), "Record<string, unknown>".to_string());
        let query = make_batch_query(
            "CreateUserAccountRecordPayload",
            "INSERT INTO user_account_record_payload (payload) VALUES ($1)",
            vec![AnalyzedParam {
                constraints: None,
                name: "payload".to_string(),
                neutral_type: "json".to_string(),
                nullable: false,
                position: 1,
                source_relation: None,
            }],
        );

        let result = crate::generate_with_backend(&query, &backend).unwrap();
        let query_fn = result.query_fn.as_deref().unwrap();

        assert!(
            query_fn.contains("\titems: Record<string, unknown>[],"),
            "the synthetic param type must survive intact on the items line, not be split \
             on its internal ', '; got:\n{query_fn}"
        );
        assert!(
            !query_fn.contains("Record<string,\n"),
            "the synthetic type must not be split at its internal comma; got:\n{query_fn}"
        );
    }

    #[test]
    fn test_json_uses_postgres_driver_json_parameter_type() {
        let backend = TypescriptPostgresBackend::new("postgresql").unwrap();
        assert_eq!(
            backend.manifest.types.scalars.get("json").map(String::as_str),
            Some("PostgresJsonValue")
        );
    }

    #[test]
    fn test_pg_bind_expr_serializes_json_and_preserves_null_composites() {
        let composites = vec![CompositeInfo {
            sql_name: "address".to_string(),
            fields: vec![
                CompositeFieldInfo {
                    name: "street".to_string(),
                    neutral_type: "string".to_string(),
                    nullable: false,
                },
                CompositeFieldInfo {
                    name: "metadata".to_string(),
                    neutral_type: "json".to_string(),
                    nullable: false,
                },
            ],
        }];

        assert_eq!(
            pg_bind_expr(TemplateDriver::PostgresJs, "metadata", "json", false, &composites),
            "${sql.json(metadata)}"
        );
        assert_eq!(
            pg_bind_expr(
                TemplateDriver::PostgresJs,
                "home_address",
                "composite::address",
                true,
                &composites
            ),
            "${home_address === null ? sql`NULL::address` : sql`ROW(${home_address.street}, ${sql.json(home_address.metadata)})::address`}"
        );
    }

    /// #219 (`$N` half): the multi-parameter `:batch` path used to run a raw
    /// `sql.replace("$1", "${item.a}")` over the whole statement, which does
    /// not know a SQL string literal from live code -- `'cost is $1 today'`
    /// got rewritten right alongside the real `$1` placeholder, so
    /// postgres.js sent one extra live binding for text that was never meant
    /// to be one. `batch_item_sql` now routes through the literal-aware
    /// `rewrite_pg_placeholders`, so only the real placeholder is live.
    #[test]
    fn test_batch_multi_param_does_not_rewrite_dollar_n_inside_sql_string_literal() {
        let backend = TypescriptPostgresBackend::new("postgresql").unwrap();
        let query = make_batch_query(
            "UpdateItemPrice",
            "UPDATE prices SET a = $1, note = 'cost is $1 today' WHERE id = $2",
            vec![
                AnalyzedParam {
                    constraints: None,
                    name: "a".to_string(),
                    neutral_type: "int32".to_string(),
                    nullable: false,
                    position: 1,
                    source_relation: None,
                },
                AnalyzedParam {
                    constraints: None,
                    name: "id".to_string(),
                    neutral_type: "int32".to_string(),
                    nullable: false,
                    position: 2,
                    source_relation: None,
                },
            ],
        );

        let result = crate::generate_with_backend(&query, &backend).unwrap();
        let query_fn = result.query_fn.as_deref().unwrap();

        assert!(
            query_fn.contains("SET a = ${item.a}, note = 'cost is $1 today' WHERE id = ${item.id}"),
            "the literal's inert `$1` text must survive unrewritten while the two real \
             placeholders become live bindings; got:\n{query_fn}"
        );
        assert!(
            !query_fn.contains("cost is ${item.a} today"),
            "the literal must not gain a second live binding; got:\n{query_fn}"
        );
    }

    /// #219 (`${fieldName}` half): the single-parameter `:batch` path used to
    /// run `sql_template.replace("${field}", "${item}")` over the
    /// already-escaped, already-placeholder-rewritten SQL. That blindly
    /// matched the tail of an *escaped* `\${field}` a SQL string literal
    /// could itself contain, silently corrupting it to `\${item}`.
    /// `batch_item_sql_single` now runs `rewrite_pg_placeholders` on the
    /// escaped-but-not-yet-rewritten SQL, so it only ever touches the real
    /// `$N` placeholder.
    #[test]
    fn test_batch_single_param_does_not_rewrite_escaped_dollar_brace_inside_sql_string_literal() {
        let backend = TypescriptPostgresBackend::new("postgresql").unwrap();
        let query = make_batch_query(
            "UpdateItemAmount",
            "UPDATE prices SET amount = $1 WHERE note = 'the ${amount} field'",
            vec![AnalyzedParam {
                constraints: None,
                name: "amount".to_string(),
                neutral_type: "int32".to_string(),
                nullable: false,
                position: 1,
                source_relation: None,
            }],
        );

        let result = crate::generate_with_backend(&query, &backend).unwrap();
        let query_fn = result.query_fn.as_deref().unwrap();

        assert!(
            query_fn.contains("SET amount = ${item} WHERE note = 'the \\${amount} field'"),
            "the real placeholder must become `${{item}}` while the literal's escaped \
             `\\${{amount}}` must survive untouched; got:\n{query_fn}"
        );
        assert!(
            !query_fn.contains(r"\${item}"),
            "the literal must not be corrupted into an escaped reference to `item`; got:\n{query_fn}"
        );
    }

    fn make_query_with_snake_case_column(command: QueryCommand) -> AnalyzedQuery {
        AnalyzedQuery::build(|q| {
            q.name = "GetUserById".to_string();
            q.command = command;
            q.sql = "SELECT id, user_id FROM sessions WHERE id = $1".to_string();
            q.columns = vec![
                AnalyzedColumn {
                    name: "id".to_string(),
                    neutral_type: "int32".to_string(),
                    nullable: false,
                    ..Default::default()
                },
                AnalyzedColumn {
                    name: "user_id".to_string(),
                    neutral_type: "int32".to_string(),
                    nullable: false,
                    ..Default::default()
                },
            ];
            q.params = vec![];
            q.deprecated = None;
            q.source_table = None;
            q.composites = vec![];
            q.enums = vec![];
            q.optional_params = vec![];
            q.group_by = None;
            q.custom = vec![];
        })
    }

    /// This must fail before the fix: the `sql<StructName[]>` tag's generic
    /// is a type-level trust boundary only -- postgres.js still returns the
    /// driver's raw (snake_case) keys, so `field_case = "camelCase"`
    /// renaming the declared fields makes `tsc` believe the shape changed
    /// while every field reads back `undefined` at runtime.
    #[test]
    fn test_one_query_fn_remaps_fields_under_camel_case() {
        let mut backend = TypescriptPostgresBackend::new("postgresql").unwrap();
        backend
            .apply_options(&std::collections::HashMap::from([(
                "field_case".to_string(),
                "camelCase".to_string(),
            )]))
            .unwrap();
        let query = make_query_with_snake_case_column(QueryCommand::One);
        let result = crate::generate_with_backend(&query, &backend).unwrap();
        let query_fn = result.query_fn.as_deref().unwrap();

        assert!(
            query_fn.contains("sql<Record<string, unknown>[]>"),
            "must not trust the struct-typed generic; got:\n{query_fn}"
        );
        assert!(
            query_fn.contains("userId: row['user_id'] as number,"),
            "must remap the declared camelCase field from the driver's raw key; got:\n{query_fn}"
        );
        assert!(
            !query_fn.contains("sql<GetUserByIdRow[]>"),
            "must not use the old struct-typed generic under camelCase; got:\n{query_fn}"
        );
    }

    #[test]
    fn test_many_query_fn_remaps_fields_under_camel_case() {
        let mut backend = TypescriptPostgresBackend::new("postgresql").unwrap();
        backend
            .apply_options(&std::collections::HashMap::from([(
                "field_case".to_string(),
                "camelCase".to_string(),
            )]))
            .unwrap();
        let query = make_query_with_snake_case_column(QueryCommand::Many);
        let result = crate::generate_with_backend(&query, &backend).unwrap();
        let query_fn = result.query_fn.as_deref().unwrap();

        assert!(
            query_fn.contains("sql<Record<string, unknown>[]>"),
            "must not trust the struct-typed generic; got:\n{query_fn}"
        );
        assert!(
            query_fn.contains("return rows.map((row) => ({"),
            "must map each row; got:\n{query_fn}"
        );
        assert!(
            query_fn.contains("userId: row['user_id'] as number,"),
            "must remap the declared camelCase field from the driver's raw key; got:\n{query_fn}"
        );
    }

    #[test]
    fn test_one_query_fn_keeps_the_struct_generic_under_the_default_snake_case() {
        let backend = TypescriptPostgresBackend::new("postgresql").unwrap();
        let query = make_query_with_snake_case_column(QueryCommand::One);
        let result = crate::generate_with_backend(&query, &backend).unwrap();
        let query_fn = result.query_fn.as_deref().unwrap();

        assert!(
            query_fn.contains("sql<GetUserByIdRow[]>"),
            "default field_case must keep the original struct-typed generic unchanged; got:\n{query_fn}"
        );
        assert!(
            !query_fn.contains("Record<string, unknown>"),
            "must not switch to the remap path under the default; got:\n{query_fn}"
        );
    }

    // -- javascript-postgres (JSDoc emit mode, #81) --------------------------

    fn js_backend() -> TypescriptPostgresBackend {
        TypescriptPostgresBackend::new_js("postgresql").unwrap()
    }

    fn resolved_columns_with_a_nullable_and_a_non_nullable_field() -> Vec<crate::backend_trait::ResolvedColumn> {
        use crate::backend_trait::ResolvedColumn;
        vec![
            ResolvedColumn {
                name: "id".to_string(),
                field_name: "id".to_string(),
                lang_type: "number".to_string(),
                full_type: "number".to_string(),
                neutral_type: "int32".to_string(),
                sql_type: "int4".to_string(),
                nullable: false,
                join_group: None,
                nullable_before_join: false,
            },
            ResolvedColumn {
                name: "bio".to_string(),
                field_name: "bio".to_string(),
                lang_type: "string".to_string(),
                full_type: "string | null".to_string(),
                neutral_type: "string".to_string(),
                sql_type: "text".to_string(),
                nullable: true,
                join_group: None,
                nullable_before_join: false,
            },
        ]
    }

    fn query_with_nullable_and_non_nullable_columns(command: QueryCommand) -> AnalyzedQuery {
        AnalyzedQuery::build(|q| {
            q.name = "GetUserById".to_string();
            q.command = command;
            q.sql = "SELECT id, bio FROM users WHERE id = $1".to_string();
            q.columns = vec![
                AnalyzedColumn {
                    name: "id".to_string(),
                    neutral_type: "int32".to_string(),
                    nullable: false,
                    ..Default::default()
                },
                AnalyzedColumn {
                    name: "bio".to_string(),
                    neutral_type: "string".to_string(),
                    nullable: true,
                    ..Default::default()
                },
            ];
            q.params = vec![AnalyzedParam {
                constraints: None,
                name: "id".to_string(),
                neutral_type: "int32".to_string(),
                nullable: false,
                position: 1,
                source_relation: None,
            }];
            q.deprecated = None;
            q.source_table = None;
            q.composites = vec![];
            q.enums = vec![];
            q.optional_params = vec![];
            q.group_by = None;
            q.custom = vec![];
        })
    }

    #[test]
    fn test_js_mode_name_is_javascript_postgres() {
        assert_eq!(js_backend().name(), "javascript-postgres");
    }

    #[test]
    fn test_js_mode_file_header_has_no_ts_only_imports() {
        let header = js_backend().file_header();
        assert!(header.contains("@typedef"), "got:\n{header}");
        assert!(!header.contains("import type"), "got:\n{header}");
    }

    #[test]
    fn test_js_mode_row_struct_emits_nullable_column_as_type_or_null() {
        let backend = js_backend();
        let row_struct = backend
            .generate_row_struct(
                "GetUserById",
                &resolved_columns_with_a_nullable_and_a_non_nullable_field(),
            )
            .unwrap();

        assert!(
            row_struct.contains(" * @property {string | null} bio"),
            "nullable column must be `{{T | null}}`, never optional; got:\n{row_struct}"
        );
        assert!(row_struct.contains(" * @property {number} id"), "got:\n{row_struct}");
        assert!(!row_struct.contains("[bio]"), "{row_struct}");
        assert!(!row_struct.contains("bio?"), "{row_struct}");
    }

    #[test]
    fn test_js_mode_one_query_fn_is_plain_js_with_jsdoc_types() {
        let backend = js_backend();
        let query = query_with_nullable_and_non_nullable_columns(QueryCommand::One);
        let result = crate::generate_with_backend(&query, &backend).unwrap();
        let query_fn = result.query_fn.as_deref().unwrap();

        assert!(
            query_fn.contains("@param {import(\"postgres\").Sql} sql"),
            "got:\n{query_fn}"
        );
        assert!(query_fn.contains("@param {number} id"), "got:\n{query_fn}");
        assert!(
            query_fn.contains("@returns {Promise<GetUserByIdRow>}"),
            "`:one` must not be nullable; got:\n{query_fn}"
        );
        assert!(
            query_fn.contains("export async function getUserById(sql, id) {"),
            "signature must have no type annotations; got:\n{query_fn}"
        );
        assert!(
            !query_fn.contains("sql<"),
            "must not use a TS generic type argument; got:\n{query_fn}"
        );
        assert!(
            !query_fn.contains(" as "),
            "must not use a TS `as` assertion; got:\n{query_fn}"
        );
        assert!(
            query_fn.contains("SELECT id, bio FROM users WHERE id = ${id}"),
            "got:\n{query_fn}"
        );
        // Regression: postgres.js's `sql` tag defaults to its own untyped
        // `Row` shape without a type argument -- that default is concrete,
        // not `any`, so `rows[0]` fails to structurally match
        // `GetUserByIdRow` under `tsc --strict` without this cast (verified
        // against real `tsc --checkJs --strict`).
        assert!(
            query_fn.contains("const rows = /** @type {Array<GetUserByIdRow>} */ (await sql`"),
            "got:\n{query_fn}"
        );
        assert!(
            query_fn.contains(
                "const row = rows[0];\n\tif (row === undefined) {\n\t\tthrow new Error(\"no row found for query: GetUserById\");\n\t}\n\treturn row;"
            ),
            "`:one` must throw on a missing row, not return null; got:\n{query_fn}"
        );
        assert!(
            !query_fn.contains("?? null"),
            "`:one` must not return null; got:\n{query_fn}"
        );
    }

    #[test]
    fn test_js_mode_many_query_fn_returns_promise_array() {
        let backend = js_backend();
        let query = query_with_nullable_and_non_nullable_columns(QueryCommand::Many);
        let result = crate::generate_with_backend(&query, &backend).unwrap();
        let query_fn = result.query_fn.as_deref().unwrap();

        assert!(
            query_fn.contains("@returns {Promise<GetUserByIdRow[]>}"),
            "got:\n{query_fn}"
        );
        assert!(query_fn.contains("return rows;"), "got:\n{query_fn}");
        assert!(!query_fn.contains(" as "), "got:\n{query_fn}");
    }

    #[test]
    fn test_js_mode_exec_query_fn_returns_promise_void() {
        let backend = js_backend();
        let mut query = query_with_nullable_and_non_nullable_columns(QueryCommand::Exec);
        query.sql = "DELETE FROM users WHERE id = $1".to_string();
        let result = crate::generate_with_backend(&query, &backend).unwrap();
        let query_fn = result.query_fn.as_deref().unwrap();

        assert!(query_fn.contains("@returns {Promise<void>}"), "got:\n{query_fn}");
        assert!(
            query_fn.contains("export async function getUserById(sql, id) {"),
            "got:\n{query_fn}"
        );
    }

    #[test]
    fn test_js_mode_rejects_zod_row_type_and_camel_case_and_outer_join_unions() {
        for (key, value) in [
            ("row_type", "zod"),
            ("field_case", "camelCase"),
            ("outer_join_unions", "true"),
        ] {
            let mut backend = js_backend();
            let err = backend
                .apply_options(&std::collections::HashMap::from([(key.to_string(), value.to_string())]))
                .expect_err(&format!("javascript-postgres must reject {key} = {value}"));
            assert!(err.to_string().contains("javascript-postgres"), "{err}");
        }
    }
}
