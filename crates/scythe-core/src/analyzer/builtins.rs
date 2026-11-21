//! Signatures of PostgreSQL built-in functions and system views.
//!
//! The schema catalog only holds what the schema defines, so a call to a
//! built-in function outside the inference arms of `infer_function_type` was
//! an unknown function, and a placeholder passed to one (`date_trunc($1,
//! ...)`) had no type. These signatures resolve such calls by the same
//! overload rules as schema functions: they type placeholder arguments and,
//! for functions without an inference arm, the result.

use std::sync::OnceLock;

use ahash::AHashMap;

use crate::catalog::{Function, FunctionArgument, FunctionArgumentMode, FunctionReturn};

/// `(name, arguments, result, strict)`: arguments are `name type` pairs
/// separated by commas, as `pg_proc` documents them; one name per overload.
const FUNCTIONS: &[(&str, &str, &str, bool)] = &[
    // Advisory locks.
    ("pg_advisory_lock", "key bigint", "void", true),
    ("pg_advisory_lock", "key1 integer, key2 integer", "void", true),
    ("pg_advisory_lock_shared", "key bigint", "void", true),
    ("pg_advisory_lock_shared", "key1 integer, key2 integer", "void", true),
    ("pg_advisory_xact_lock", "key bigint", "void", true),
    ("pg_advisory_xact_lock", "key1 integer, key2 integer", "void", true),
    ("pg_advisory_xact_lock_shared", "key bigint", "void", true),
    (
        "pg_advisory_xact_lock_shared",
        "key1 integer, key2 integer",
        "void",
        true,
    ),
    ("pg_try_advisory_lock", "key bigint", "boolean", true),
    ("pg_try_advisory_lock", "key1 integer, key2 integer", "boolean", true),
    ("pg_try_advisory_lock_shared", "key bigint", "boolean", true),
    (
        "pg_try_advisory_lock_shared",
        "key1 integer, key2 integer",
        "boolean",
        true,
    ),
    ("pg_try_advisory_xact_lock", "key bigint", "boolean", true),
    (
        "pg_try_advisory_xact_lock",
        "key1 integer, key2 integer",
        "boolean",
        true,
    ),
    ("pg_try_advisory_xact_lock_shared", "key bigint", "boolean", true),
    (
        "pg_try_advisory_xact_lock_shared",
        "key1 integer, key2 integer",
        "boolean",
        true,
    ),
    ("pg_advisory_unlock", "key bigint", "boolean", true),
    ("pg_advisory_unlock", "key1 integer, key2 integer", "boolean", true),
    ("pg_advisory_unlock_shared", "key bigint", "boolean", true),
    (
        "pg_advisory_unlock_shared",
        "key1 integer, key2 integer",
        "boolean",
        true,
    ),
    ("pg_advisory_unlock_all", "", "void", true),
    ("pg_blocking_pids", "pid integer", "integer[]", true),
    ("pg_backend_pid", "", "integer", true),
    ("pg_sleep", "seconds double precision", "void", true),
    // Hashing.
    ("hashtext", "value text", "integer", true),
    ("hashtextextended", "value text, seed bigint", "bigint", true),
    // Configuration. `set_config` is not strict: a null value resets the setting.
    (
        "set_config",
        "setting_name text, new_value text, is_local boolean",
        "text",
        false,
    ),
    ("current_setting", "setting_name text", "text", true),
    // With `missing_ok`, an unknown setting reads as null.
    (
        "current_setting",
        "setting_name text, missing_ok boolean",
        "text?",
        true,
    ),
    // Strings.
    ("starts_with", "string text, prefix text", "boolean", true),
    ("split_part", "string text, delimiter text, n integer", "text", true),
    ("string_to_array", "string text, delimiter text", "text[]", false),
    (
        "string_to_array",
        "string text, delimiter text, null_string text",
        "text[]",
        false,
    ),
    ("strpos", "string text, substring text", "integer", true),
    ("left", "string text, n integer", "text", true),
    ("right", "string text, n integer", "text", true),
    ("lpad", "string text, length integer", "text", true),
    ("lpad", "string text, length integer, fill text", "text", true),
    ("rpad", "string text, length integer", "text", true),
    ("rpad", "string text, length integer, fill text", "text", true),
    ("repeat", "string text, number integer", "text", true),
    ("replace", "string text, pattern text, replacement text", "text", true),
    (
        "regexp_replace",
        "string text, pattern text, replacement text",
        "text",
        true,
    ),
    (
        "regexp_replace",
        "string text, pattern text, replacement text, flags text",
        "text",
        true,
    ),
    ("md5", "string text", "text", true),
    // Date and time.
    (
        "date_trunc",
        "field text, source timestamp with time zone",
        "timestamp with time zone",
        true,
    ),
    (
        "date_trunc",
        "field text, source timestamp with time zone, zone text",
        "timestamp with time zone",
        true,
    ),
    (
        "date_trunc",
        "field text, source timestamp without time zone",
        "timestamp without time zone",
        true,
    ),
    ("date_trunc", "field text, source interval", "interval", true),
    (
        "date_part",
        "field text, source timestamp with time zone",
        "double precision",
        true,
    ),
    (
        "date_part",
        "field text, source timestamp without time zone",
        "double precision",
        true,
    ),
    ("date_part", "field text, source interval", "double precision", true),
    ("to_char", "value timestamp with time zone, format text", "text", true),
    (
        "to_char",
        "value timestamp without time zone, format text",
        "text",
        true,
    ),
    ("to_char", "value interval, format text", "text", true),
    ("to_char", "value numeric, format text", "text", true),
    ("to_char", "value double precision, format text", "text", true),
    ("to_char", "value bigint, format text", "text", true),
    ("to_char", "value integer, format text", "text", true),
    ("to_date", "string text, format text", "date", true),
    (
        "to_timestamp",
        "string text, format text",
        "timestamp with time zone",
        true,
    ),
    (
        "to_timestamp",
        "epoch double precision",
        "timestamp with time zone",
        true,
    ),
];

/// `(name, columns)`: the system views queries read, with `name type`
/// columns. A column whose type has no neutral type (`oid`, `xid`) is left
/// untyped, so selecting it is reported rather than mistyped.
const RELATIONS: &[(&str, &str)] = &[(
    "pg_stat_activity",
    "datid oid, datname text, pid integer, leader_pid integer, usesysid oid, usename text, \
     application_name text, client_addr inet, client_hostname text, client_port integer, \
     backend_start timestamp with time zone, xact_start timestamp with time zone, \
     query_start timestamp with time zone, state_change timestamp with time zone, wait_event_type text, \
     wait_event text, state text, backend_xid xid, backend_xmin xid, query_id bigint, query text, \
     backend_type text",
)];

fn declarations(list: &'static str) -> impl Iterator<Item = (&'static str, &'static str)> {
    list.split(',')
        .map(str::trim)
        .filter(|declaration| !declaration.is_empty())
        .filter_map(|declaration| declaration.split_once(' '))
}

fn functions() -> &'static AHashMap<&'static str, Vec<Function>> {
    static FUNCTION_MAP: OnceLock<AHashMap<&'static str, Vec<Function>>> = OnceLock::new();
    FUNCTION_MAP.get_or_init(|| {
        let mut map: AHashMap<&'static str, Vec<Function>> = AHashMap::new();
        for (name, arguments, result, strict) in FUNCTIONS {
            let (sql_type, nullable) = match result.strip_suffix('?') {
                Some(sql_type) => (sql_type, true),
                None => (*result, false),
            };
            map.entry(name).or_default().push(Function {
                arguments: declarations(arguments)
                    .map(|(argument, sql_type)| FunctionArgument {
                        name: Some(argument.to_string()),
                        sql_type: sql_type.to_string(),
                        mode: FunctionArgumentMode::In,
                        has_default: false,
                    })
                    .collect(),
                return_type: FunctionReturn::Scalar {
                    sql_type: sql_type.to_string(),
                    nullable,
                },
                strict: *strict,
                body: None,
            });
        }
        map
    })
}

/// The overloads of the PostgreSQL built-in function `name`, which may be
/// qualified with `pg_catalog`.
pub(super) fn builtin_functions(name: &str) -> Option<&'static [Function]> {
    let name = name.strip_prefix("pg_catalog.").unwrap_or(name);
    functions().get(name).map(Vec::as_slice)
}

/// The `(name, sql_type)` columns of the PostgreSQL system view `name`, which
/// may be qualified with `pg_catalog`. Every column is nullable.
pub(super) fn builtin_relation(name: &str) -> Option<impl Iterator<Item = (&'static str, &'static str)>> {
    let name = name.strip_prefix("pg_catalog.").unwrap_or(name);
    RELATIONS
        .iter()
        .find(|(relation, _)| *relation == name)
        .map(|(_, columns)| declarations(columns))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_parse_every_signature() {
        for (name, arguments, _, _) in FUNCTIONS {
            let expected = arguments.split(',').filter(|a| !a.trim().is_empty()).count();
            let parsed = builtin_functions(name)
                .expect("declared")
                .iter()
                .any(|function| function.arguments.len() == expected);
            assert!(parsed, "{name}({arguments})");
        }
        assert_eq!(
            builtin_relation("pg_catalog.pg_stat_activity").map(Iterator::count),
            Some(22)
        );
    }
}
