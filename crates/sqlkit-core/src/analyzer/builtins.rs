//! What sqlkit knows about PostgreSQL's built-in functions and system views,
//! in one table.
//!
//! The schema catalog only holds what the schema defines. Everything the
//! analyzer and the catalog know about `pg_catalog` beyond that lives here:
//! the overloads of the built-ins it types by the catalog's overload rules
//! (which type placeholder arguments and, without an inference arm, the
//! result), which built-ins return a set, which keep their argument's
//! meaning (a parameter compared with `lower(email)` is named `email`), the
//! columns a set-returning function gives a FROM item, and the columns of the
//! system views queries read.
//!
//! `infer_function_type`'s match arms remain the rules for results that
//! depend on the arguments' types (`sum`, `coalesce`, `date_trunc`, ...);
//! they are rules, not facts this table could hold.
//!
//! A typed table rather than a prelude of `CREATE FUNCTION` DDL loaded
//! through the catalog: the catalog types every function result nullable
//! unless a SQL body proves otherwise, has no notion of a value-preserving
//! function, and cannot type pseudo-type signatures (`anyelement`,
//! `record`) by its overload rules.

use std::sync::OnceLock;

use ahash::AHashMap;

use crate::catalog::{Function, FunctionArgument, FunctionArgumentMode, FunctionReturn};

/// One overload: `(name, sql_type)` arguments, the result type, whether the
/// result can be NULL for non-NULL arguments, and `STRICT`.
struct Signature {
    arguments: &'static [(&'static str, &'static str)],
    result: &'static str,
    result_nullable: bool,
    strict: bool,
}

/// The columns a set-returning function gives a FROM item: `(name,
/// neutral_type, nullable)`.
type FromColumns = &'static [(&'static str, &'static str, bool)];

struct Builtin {
    name: &'static str,
    signatures: &'static [Signature],
    /// Returns a set, so a select list calling it returns any number of rows.
    set_returning: bool,
    /// Its result means what its first non-literal argument means.
    value_preserving: bool,
    /// Its columns as a FROM item, empty where its arguments decide them;
    /// `None` where sqlkit does not take it as one.
    from_columns: Option<FromColumns>,
}

const fn strict(arguments: &'static [(&'static str, &'static str)], result: &'static str) -> Signature {
    Signature {
        arguments,
        result,
        result_nullable: false,
        strict: true,
    }
}

const fn function(name: &'static str, signatures: &'static [Signature]) -> Builtin {
    Builtin {
        name,
        signatures,
        set_returning: false,
        value_preserving: false,
        from_columns: None,
    }
}

const fn value_preserving(name: &'static str, signatures: &'static [Signature]) -> Builtin {
    Builtin {
        value_preserving: true,
        ..function(name, signatures)
    }
}

const fn set_returning(name: &'static str, from_columns: Option<FromColumns>) -> Builtin {
    Builtin {
        set_returning: true,
        from_columns,
        ..function(name, &[])
    }
}

const KEY: &[(&str, &str)] = &[("key", "bigint")];
const KEYS: &[(&str, &str)] = &[("key1", "integer"), ("key2", "integer")];
const ADVISORY_VOID: &[Signature] = &[strict(KEY, "void"), strict(KEYS, "void")];
const ADVISORY_BOOL: &[Signature] = &[strict(KEY, "boolean"), strict(KEYS, "boolean")];
const JSON_EACH: FromColumns = &[("key", "string", false), ("value", "json", true)];
const JSON_EACH_TEXT: FromColumns = &[("key", "string", false), ("value", "string", true)];
const JSON_ELEMENTS: FromColumns = &[("value", "json", true)];
const JSON_KEYS: FromColumns = &[("jsonb_object_keys", "string", false)];
const LPAD: &[Signature] = &[
    strict(&[("string", "text"), ("length", "integer")], "text"),
    strict(&[("string", "text"), ("length", "integer"), ("fill", "text")], "text"),
];
const REGEXP_REPLACE: &[Signature] = &[
    strict(
        &[("string", "text"), ("pattern", "text"), ("replacement", "text")],
        "text",
    ),
    strict(
        &[
            ("string", "text"),
            ("pattern", "text"),
            ("replacement", "text"),
            ("flags", "text"),
        ],
        "text",
    ),
];
const STRING_N: &[Signature] = &[strict(&[("string", "text"), ("n", "integer")], "text")];
const TIMESTAMPTZ: &str = "timestamp with time zone";
const TIMESTAMP: &str = "timestamp without time zone";

const BUILTINS: &[Builtin] = &[
    // Advisory locks.
    function("pg_advisory_lock", ADVISORY_VOID),
    function("pg_advisory_lock_shared", ADVISORY_VOID),
    function("pg_advisory_xact_lock", ADVISORY_VOID),
    function("pg_advisory_xact_lock_shared", ADVISORY_VOID),
    function("pg_try_advisory_lock", ADVISORY_BOOL),
    function("pg_try_advisory_lock_shared", ADVISORY_BOOL),
    function("pg_try_advisory_xact_lock", ADVISORY_BOOL),
    function("pg_try_advisory_xact_lock_shared", ADVISORY_BOOL),
    function("pg_advisory_unlock", ADVISORY_BOOL),
    function("pg_advisory_unlock_shared", ADVISORY_BOOL),
    function("pg_advisory_unlock_all", &[strict(&[], "void")]),
    function("pg_blocking_pids", &[strict(&[("pid", "integer")], "integer[]")]),
    function("pg_backend_pid", &[strict(&[], "integer")]),
    function("pg_sleep", &[strict(&[("seconds", "double precision")], "void")]),
    // Hashing.
    function("hashtext", &[strict(&[("value", "text")], "integer")]),
    function(
        "hashtextextended",
        &[strict(&[("value", "text"), ("seed", "bigint")], "bigint")],
    ),
    // Configuration. `set_config` is not strict: a null value resets the setting.
    function(
        "set_config",
        &[Signature {
            strict: false,
            ..strict(
                &[("setting_name", "text"), ("new_value", "text"), ("is_local", "boolean")],
                "text",
            )
        }],
    ),
    function(
        "current_setting",
        &[
            strict(&[("setting_name", "text")], "text"),
            // With `missing_ok`, an unknown setting reads as null.
            Signature {
                result_nullable: true,
                ..strict(&[("setting_name", "text"), ("missing_ok", "boolean")], "text")
            },
        ],
    ),
    // Strings.
    function(
        "starts_with",
        &[strict(&[("string", "text"), ("prefix", "text")], "boolean")],
    ),
    function(
        "split_part",
        &[strict(
            &[("string", "text"), ("delimiter", "text"), ("n", "integer")],
            "text",
        )],
    ),
    function(
        "string_to_array",
        &[
            Signature {
                strict: false,
                ..strict(&[("string", "text"), ("delimiter", "text")], "text[]")
            },
            Signature {
                strict: false,
                ..strict(
                    &[("string", "text"), ("delimiter", "text"), ("null_string", "text")],
                    "text[]",
                )
            },
        ],
    ),
    function(
        "strpos",
        &[strict(&[("string", "text"), ("substring", "text")], "integer")],
    ),
    value_preserving("left", STRING_N),
    value_preserving("right", STRING_N),
    value_preserving("lpad", LPAD),
    value_preserving("rpad", LPAD),
    function(
        "repeat",
        &[strict(&[("string", "text"), ("number", "integer")], "text")],
    ),
    value_preserving(
        "replace",
        &[strict(
            &[("string", "text"), ("pattern", "text"), ("replacement", "text")],
            "text",
        )],
    ),
    value_preserving("regexp_replace", REGEXP_REPLACE),
    function("md5", &[strict(&[("string", "text")], "text")]),
    value_preserving("lower", &[]),
    value_preserving("upper", &[]),
    value_preserving("initcap", &[]),
    value_preserving("trim", &[]),
    value_preserving("btrim", &[]),
    value_preserving("ltrim", &[]),
    value_preserving("rtrim", &[]),
    value_preserving("unaccent", &[]),
    value_preserving("normalize", &[]),
    value_preserving("substring", &[]),
    value_preserving("substr", &[]),
    value_preserving("translate", &[]),
    // Conditionals and numbers.
    value_preserving("coalesce", &[]),
    value_preserving("nullif", &[]),
    value_preserving("greatest", &[]),
    value_preserving("least", &[]),
    value_preserving("abs", &[]),
    value_preserving("round", &[]),
    value_preserving("trunc", &[]),
    value_preserving("floor", &[]),
    value_preserving("ceil", &[]),
    value_preserving("ceiling", &[]),
    // Date and time.
    value_preserving(
        "date_trunc",
        &[
            strict(&[("field", "text"), ("source", TIMESTAMPTZ)], TIMESTAMPTZ),
            strict(
                &[("field", "text"), ("source", TIMESTAMPTZ), ("zone", "text")],
                TIMESTAMPTZ,
            ),
            strict(&[("field", "text"), ("source", TIMESTAMP)], TIMESTAMP),
            strict(&[("field", "text"), ("source", "interval")], "interval"),
        ],
    ),
    function(
        "date_part",
        &[
            strict(&[("field", "text"), ("source", TIMESTAMPTZ)], "double precision"),
            strict(&[("field", "text"), ("source", TIMESTAMP)], "double precision"),
            strict(&[("field", "text"), ("source", "interval")], "double precision"),
        ],
    ),
    function(
        "to_char",
        &[
            strict(&[("value", TIMESTAMPTZ), ("format", "text")], "text"),
            strict(&[("value", TIMESTAMP), ("format", "text")], "text"),
            strict(&[("value", "interval"), ("format", "text")], "text"),
            strict(&[("value", "numeric"), ("format", "text")], "text"),
            strict(&[("value", "double precision"), ("format", "text")], "text"),
            strict(&[("value", "bigint"), ("format", "text")], "text"),
            strict(&[("value", "integer"), ("format", "text")], "text"),
        ],
    ),
    function("to_date", &[strict(&[("string", "text"), ("format", "text")], "date")]),
    function(
        "to_timestamp",
        &[
            strict(&[("string", "text"), ("format", "text")], TIMESTAMPTZ),
            strict(&[("epoch", "double precision")], TIMESTAMPTZ),
        ],
    ),
    // Set-returning functions.
    set_returning("generate_series", Some(&[])),
    set_returning("generate_subscripts", None),
    set_returning("unnest", Some(&[])),
    set_returning("json_array_elements", Some(JSON_ELEMENTS)),
    set_returning("jsonb_array_elements", Some(JSON_ELEMENTS)),
    set_returning("json_array_elements_text", None),
    set_returning("jsonb_array_elements_text", None),
    set_returning("json_each", Some(JSON_EACH)),
    set_returning("jsonb_each", Some(JSON_EACH)),
    set_returning("json_each_text", Some(JSON_EACH_TEXT)),
    set_returning("jsonb_each_text", Some(JSON_EACH_TEXT)),
    set_returning("json_object_keys", Some(JSON_KEYS)),
    set_returning("jsonb_object_keys", Some(JSON_KEYS)),
    set_returning("json_populate_recordset", Some(&[])),
    set_returning("jsonb_populate_recordset", Some(&[])),
    set_returning("json_to_recordset", None),
    set_returning("jsonb_to_recordset", None),
    set_returning("jsonb_path_query", None),
    set_returning("regexp_matches", Some(&[])),
    set_returning("regexp_split_to_table", None),
    set_returning("string_to_table", Some(&[])),
    // Not set-returning, but FROM items all the same.
    Builtin {
        from_columns: Some(&[]),
        ..function("json_populate_record", &[])
    },
    Builtin {
        from_columns: Some(&[]),
        ..function("jsonb_populate_record", &[])
    },
];

/// `(name, columns)`: the system views queries read, with `(name, sql_type)`
/// columns, every one nullable. A column whose type has no neutral type
/// (`oid`, `xid`) is left untyped, so selecting it is reported rather than
/// mistyped.
const RELATIONS: &[(&str, &[(&str, &str)])] = &[(
    "pg_stat_activity",
    &[
        ("datid", "oid"),
        ("datname", "text"),
        ("pid", "integer"),
        ("leader_pid", "integer"),
        ("usesysid", "oid"),
        ("usename", "text"),
        ("application_name", "text"),
        ("client_addr", "inet"),
        ("client_hostname", "text"),
        ("client_port", "integer"),
        ("backend_start", TIMESTAMPTZ),
        ("xact_start", TIMESTAMPTZ),
        ("query_start", TIMESTAMPTZ),
        ("state_change", TIMESTAMPTZ),
        ("wait_event_type", "text"),
        ("wait_event", "text"),
        ("state", "text"),
        ("backend_xid", "xid"),
        ("backend_xmin", "xid"),
        ("query_id", "bigint"),
        ("query", "text"),
        ("backend_type", "text"),
    ],
)];

/// The built-in `name`, which may be qualified with `pg_catalog`.
fn builtin(name: &str) -> Option<&'static Builtin> {
    static INDEX: OnceLock<AHashMap<&'static str, &'static Builtin>> = OnceLock::new();
    let name = name.strip_prefix("pg_catalog.").unwrap_or(name);
    INDEX
        .get_or_init(|| BUILTINS.iter().map(|builtin| (builtin.name, builtin)).collect())
        .get(name)
        .copied()
}

/// The overloads of the built-in function `name` the catalog's overload
/// rules can type, as catalog functions.
pub(super) fn builtin_functions(name: &str) -> Option<&'static [Function]> {
    static FUNCTIONS: OnceLock<AHashMap<&'static str, Vec<Function>>> = OnceLock::new();
    let builtin = builtin(name)?;
    let functions = FUNCTIONS.get_or_init(|| {
        BUILTINS
            .iter()
            .filter(|builtin| !builtin.signatures.is_empty())
            .map(|builtin| (builtin.name, builtin.signatures.iter().map(catalog_function).collect()))
            .collect()
    });
    functions.get(builtin.name).map(Vec::as_slice)
}

fn catalog_function(signature: &Signature) -> Function {
    Function {
        arguments: signature
            .arguments
            .iter()
            .map(|(name, sql_type)| FunctionArgument {
                name: Some((*name).to_string()),
                sql_type: (*sql_type).to_string(),
                mode: FunctionArgumentMode::In,
                has_default: false,
            })
            .collect(),
        return_type: FunctionReturn::Scalar {
            sql_type: signature.result.to_string(),
            nullable: signature.result_nullable,
        },
        strict: signature.strict,
        body: None,
    }
}

/// Whether the built-in function `name` returns a set.
pub(crate) fn is_set_returning(name: &str) -> bool {
    builtin(name).is_some_and(|builtin| builtin.set_returning)
}

/// Whether the built-in function `name`'s result means what its first
/// non-literal argument means, so a parameter compared with the call is
/// named after that argument.
pub(super) fn is_value_preserving(name: &str) -> bool {
    builtin(&name.to_lowercase()).is_some_and(|builtin| builtin.value_preserving)
}

/// The `(name, neutral_type, nullable)` columns the built-in `name` gives a
/// FROM item, none where they depend on its arguments; `None` when it is not
/// a FROM item sqlkit types, such as a `record` function, which needs a
/// column definition list.
pub(super) fn builtin_from_columns(name: &str) -> Option<FromColumns> {
    builtin(name)?.from_columns
}

/// The `(name, sql_type)` columns of the PostgreSQL system view `name`, which
/// may be qualified with `pg_catalog`. Every column is nullable.
pub(super) fn builtin_relation(name: &str) -> Option<&'static [(&'static str, &'static str)]> {
    let name = name.strip_prefix("pg_catalog.").unwrap_or(name);
    RELATIONS
        .iter()
        .find(|(relation, _)| *relation == name)
        .map(|(_, columns)| *columns)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_hold_each_name_once() {
        let mut names = BUILTINS.iter().map(|builtin| builtin.name).collect::<Vec<_>>();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "a built-in is listed twice");
    }

    #[test]
    fn should_expose_signatures_set_returning_and_relations() {
        assert_eq!(builtin_functions("pg_catalog.date_trunc").map(<[_]>::len), Some(4));
        assert!(builtin_functions("lower").is_none(), "an inference arm types it");
        assert!(is_set_returning("generate_series"));
        assert!(!is_set_returning("date_trunc"));
        assert!(is_value_preserving("LOWER"));
        assert_eq!(
            builtin_relation("pg_catalog.pg_stat_activity").map(<[_]>::len),
            Some(22)
        );
    }
}
