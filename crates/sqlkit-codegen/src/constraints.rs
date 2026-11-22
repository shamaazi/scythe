//! Preparing schema constraints for a backend that renders them as
//! validation, and reporting what it cannot render.

use sqlkit_core::constraints::ValueConstraints;
use sqlkit_core::errors::{ErrorCode, SqlkitError};

use crate::backend_trait::{CodegenBackend, ResolvedColumn, ResolvedParam};

/// What happens to a constraint that applies to a generated column or
/// parameter but is missing from its validation: one that has no translation
/// (see [`sqlkit_core::constraints`]) or that the backend cannot express on the
/// value's type. Selected by the `constraints` backend option.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ConstraintPolicy {
    /// Generate without it, silently -- the behaviour without validation.
    #[default]
    Ignore,
    /// Generate without it and print a warning naming it.
    Warn,
    /// Fail generation, naming it.
    Error,
}

impl ConstraintPolicy {
    /// Parse a `constraints` option value.
    pub fn from_option(value: &str) -> Result<Self, SqlkitError> {
        match value {
            "ignore" => Ok(Self::Ignore),
            "warn" => Ok(Self::Warn),
            "error" => Ok(Self::Error),
            _ => Err(SqlkitError::new(
                ErrorCode::InvalidConfig,
                format!("invalid constraints '{value}': expected 'ignore', 'warn' or 'error'"),
            )),
        }
    }
}

/// One column or parameter's view of its constraints, for
/// [`apply_constraint_policy`].
struct Target<'a> {
    kind: &'static str,
    name: &'a str,
    constraints: &'a mut Option<ValueConstraints>,
    lang_type: &'a mut String,
    full_type: &'a mut String,
    nullable: bool,
}

/// Prepare `columns` and `params` for `backend`: without a
/// [`CodegenBackend::constraint_policy`] their constraints are dropped;
/// otherwise each type is narrowed by [`CodegenBackend::constrained_type`] and
/// every constraint missing from the validation is handled per the policy --
/// pushed onto `warnings` under [`ConstraintPolicy::Warn`], returned as one
/// error under [`ConstraintPolicy::Error`].
pub fn apply_constraint_policy(
    backend: &dyn CodegenBackend,
    query_name: &str,
    columns: &mut [ResolvedColumn],
    params: &mut [ResolvedParam],
    warnings: &mut Vec<String>,
) -> Result<(), SqlkitError> {
    let targets = columns
        .iter_mut()
        .map(|c| Target {
            kind: "column",
            name: &c.name,
            constraints: &mut c.constraints,
            lang_type: &mut c.lang_type,
            full_type: &mut c.full_type,
            nullable: c.nullable,
        })
        .chain(params.iter_mut().map(|p| Target {
            kind: "parameter",
            name: &p.name,
            constraints: &mut p.constraints,
            lang_type: &mut p.lang_type,
            full_type: &mut p.full_type,
            nullable: p.nullable,
        }));

    let Some(policy) = backend.constraint_policy() else {
        for target in targets {
            *target.constraints = None;
        }
        return Ok(());
    };

    let mut problems = Vec::new();
    for target in targets {
        let Some(constraints) = target.constraints.as_ref() else {
            continue;
        };
        let subject = format!("{query_name} {} '{}'", target.kind, target.name);
        problems.extend(missing_from_validation(
            backend,
            &subject,
            constraints,
            target.lang_type,
        ));
        if let Some((lang_type, full_type)) = backend.constrained_type(constraints, target.lang_type, target.nullable) {
            *target.lang_type = lang_type;
            *target.full_type = full_type;
        }
    }

    match policy {
        ConstraintPolicy::Ignore => Ok(()),
        ConstraintPolicy::Warn => {
            warnings.extend(problems);
            Ok(())
        }
        ConstraintPolicy::Error if problems.is_empty() => Ok(()),
        ConstraintPolicy::Error => Err(SqlkitError::new(
            ErrorCode::UntranslatedConstraint,
            format!(
                "query '{query_name}': schema constraints missing from the generated validation \
                 (constraints = \"error\"):\n  {}",
                problems.join("\n  ")
            ),
        )),
    }
}

/// Each part of `constraints` missing from `backend`'s validation of a value of
/// `lang_type`, as one message about `subject`: a constraint with no
/// translation, or a rule the backend cannot express on that type. Shared by
/// query columns and parameters and the schema types module's domains.
pub(crate) fn missing_from_validation(
    backend: &dyn CodegenBackend,
    subject: &str,
    constraints: &ValueConstraints,
    lang_type: &str,
) -> Vec<String> {
    let untranslated = constraints.untranslated.iter().map(|entry| {
        let constraint = if entry.constraint.is_empty() {
            entry.source.clone()
        } else {
            format!("{} {}", entry.source, entry.constraint)
        };
        format!("{subject}: {constraint} is not translated: {}", entry.reason)
    });
    let inexpressible = backend
        .inexpressible_rules(&constraints.rules, lang_type)
        .into_iter()
        .map(|rule| format!("{subject} ({lang_type}) cannot carry {rule}"));
    untranslated.chain(inexpressible).collect()
}
