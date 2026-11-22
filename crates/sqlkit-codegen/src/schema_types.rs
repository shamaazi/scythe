//! The schema's user-defined types as one module: every enum and domain the
//! catalog declares, rendered once so application code can name them outside
//! query functions, and generated query modules can import them.

use sqlkit_backend::types::resolve_type;
use sqlkit_core::analyzer::{EnumInfo, sql_type_to_neutral};
use sqlkit_core::catalog::Catalog;
use sqlkit_core::constraints::ValueConstraints;
use sqlkit_core::errors::{ErrorCode, SqlkitError};

use crate::backend_trait::CodegenBackend;
use crate::constraints::ConstraintPolicy;

/// A domain declared by `CREATE DOMAIN name AS base ...`.
#[derive(Debug, Clone)]
pub struct SchemaDomain {
    pub sql_name: String,
    /// The base type, neutral: `string` for `varchar(2)`.
    pub neutral_type: String,
    /// The base type in the target language, before any narrowing.
    pub lang_type: String,
    /// Its checks, length, and `COMMENT ON DOMAIN`, as analysis attaches them
    /// to a column of the domain.
    pub constraints: Option<ValueConstraints>,
}

/// The schema types one module declares, each list sorted by SQL name.
#[derive(Debug, Clone, Default)]
pub struct SchemaTypes {
    pub enums: Vec<EnumInfo>,
    pub domains: Vec<SchemaDomain>,
}

/// The rendered schema types module, with any constraint the backend could not
/// carry under `constraints = "warn"`.
#[derive(Debug, Clone)]
pub struct SchemaTypesModule {
    pub code: String,
    pub warnings: Vec<String>,
}

impl SchemaTypes {
    /// Every enum and domain in `catalog`, domain base types resolved through
    /// `backend`'s manifest.
    pub fn from_catalog(catalog: &Catalog, backend: &dyn CodegenBackend) -> Result<Self, SqlkitError> {
        let mut enums: Vec<EnumInfo> = catalog
            .enums_iter()
            .map(|(name, enum_type)| EnumInfo {
                sql_name: name.clone(),
                values: enum_type.values.clone(),
            })
            .collect();
        enums.sort_by(|a, b| a.sql_name.cmp(&b.sql_name));

        let mut names: Vec<&String> = catalog.domain_names().collect();
        names.sort();
        let mut domains = Vec::with_capacity(names.len());
        for name in names {
            let Some(base) = catalog.get_domain_base_type(name) else {
                continue;
            };
            let neutral_type = sql_type_to_neutral(base, catalog).into_owned();
            let lang_type = resolve_type(&neutral_type, backend.manifest(), false)
                .map_err(|e| {
                    SqlkitError::new(
                        ErrorCode::InvalidConfig,
                        format!("domain {name}: no {} type for {neutral_type}: {e}", backend.name()),
                    )
                })?
                .into_owned();
            domains.push(SchemaDomain {
                sql_name: name.clone(),
                neutral_type,
                lang_type,
                constraints: catalog.domain_constraints(name),
            });
        }
        Ok(Self { enums, domains })
    }
}

/// Render `catalog`'s schema types module through `backend`.
///
/// A domain constraint the backend cannot express follows its
/// [`CodegenBackend::constraint_policy`], as it does on a column: an error
/// under `constraints = "error"`, a warning under `"warn"`.
pub fn generate_schema_types(
    catalog: &Catalog,
    backend: &dyn CodegenBackend,
) -> Result<SchemaTypesModule, SqlkitError> {
    let types = SchemaTypes::from_catalog(catalog, backend)?;

    let mut problems = Vec::new();
    if backend.constraint_policy().is_some() {
        for domain in &types.domains {
            let Some(constraints) = &domain.constraints else {
                continue;
            };
            problems.extend(crate::constraints::missing_from_validation(
                backend,
                &format!("domain {}", domain.sql_name),
                constraints,
                &domain.lang_type,
            ));
        }
    }
    let warnings = match backend.constraint_policy() {
        Some(ConstraintPolicy::Error) if !problems.is_empty() => {
            return Err(SqlkitError::new(
                ErrorCode::UntranslatedConstraint,
                format!(
                    "schema types: domain constraints missing from the generated validation \
                     (constraints = \"error\"):\n  {}",
                    problems.join("\n  ")
                ),
            ));
        }
        Some(ConstraintPolicy::Warn) => problems,
        _ => Vec::new(),
    };

    let code = backend.generate_schema_types(&types).unwrap_or_else(|| {
        Err(SqlkitError::new(
            ErrorCode::InvalidConfig,
            format!("backend '{}' does not support schema_types", backend.name()),
        ))
    })?;
    Ok(SchemaTypesModule { code, warnings })
}
