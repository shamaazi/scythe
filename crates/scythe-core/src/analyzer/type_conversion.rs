use std::borrow::Cow;

use sqlparser::ast::{self, DataType, TimezoneInfo};

use crate::catalog::Catalog;

use super::helpers::object_name_to_string;

/// Map a PostgreSQL DDL type name onto sqlkit's neutral type vocabulary.
///
/// Re-exported from [`crate::analyzer`] because schema-drift checking has to
/// speak the same type vocabulary as query analysis.  Giving the drift checker
/// its own DDL-to-neutral table would let the two definitions diverge, and a
/// drift checker whose type mapping disagrees with the generator reports
/// mismatches the generated code does not actually have.
pub fn sql_type_to_neutral(sql_type: &str, catalog: &Catalog) -> Cow<'static, str> {
    let lower = sql_type.to_lowercase();
    let normalized = strip_precision(&lower);

    if let Some(neutral) = bit_type_to_neutral(&lower) {
        return neutral;
    }

    match normalized.as_str() {
        "integer" | "int" | "int4" | "serial" => Cow::Borrowed("int32"),
        "smallint" | "int2" | "smallserial" => Cow::Borrowed("int16"),
        "bigint" | "int8" | "bigserial" => Cow::Borrowed("int64"),

        "real" | "float4" => Cow::Borrowed("float32"),
        "double precision" | "float8" => Cow::Borrowed("float64"),
        // Bare `FLOAT` is `FLOAT(53)`, i.e. double precision.
        "float" => Cow::Borrowed("float64"),
        "numeric" | "decimal" => Cow::Borrowed("decimal"),
        "money" => Cow::Borrowed("decimal"),

        "text" | "character varying" | "character" | "varchar" | "char" => Cow::Borrowed("string"),
        "xml" => Cow::Borrowed("string"),
        // PostGIS's spatial types, surfaced as text.
        "geography" | "geometry" => Cow::Borrowed("string"),

        // A `void` result (`SELECT pg_advisory_xact_lock(...)`) is sent as
        // the empty string PostgreSQL's `void_out` renders.
        "void" => Cow::Borrowed("string"),

        "boolean" | "bool" => Cow::Borrowed("bool"),

        "bytea" => Cow::Borrowed("bytes"),

        "uuid" => Cow::Borrowed("uuid"),

        "date" => Cow::Borrowed("date"),
        "time" | "time without time zone" => Cow::Borrowed("time"),
        "time with time zone" | "timetz" => Cow::Borrowed("time_tz"),
        "timestamp" | "timestamp without time zone" => Cow::Borrowed("datetime"),
        "timestamp with time zone" | "timestamptz" => Cow::Borrowed("datetime_tz"),
        "interval" => Cow::Borrowed("interval"),

        "json" | "jsonb" => Cow::Borrowed("json"),

        "inet" | "cidr" | "macaddr" => Cow::Borrowed("inet"),

        // ~keep Bare `BIT` (no width) is `BIT(1)` per the SQL standard, which is
        // boolean-ish. `BIT VARYING`/`VARBIT` has no fixed width and is a genuine
        // bit string, so it maps to `bytes` (see `bit_type_to_neutral` for the
        // width-bearing `BIT(n)` cases).
        "bit" => Cow::Borrowed("bool"),
        "bit varying" | "varbit" => Cow::Borrowed("bytes"),

        "integer[]" | "int4[]" | "int[]" => Cow::Borrowed("array<int32>"),
        "text[]" | "character varying[]" | "varchar[]" => Cow::Borrowed("array<string>"),
        "boolean[]" | "bool[]" => Cow::Borrowed("array<bool>"),
        "bigint[]" | "int8[]" => Cow::Borrowed("array<int64>"),
        "smallint[]" | "int2[]" => Cow::Borrowed("array<int16>"),
        "real[]" | "float4[]" => Cow::Borrowed("array<float32>"),
        "double precision[]" | "float8[]" => Cow::Borrowed("array<float64>"),
        "uuid[]" => Cow::Borrowed("array<uuid>"),
        "numeric[]" | "decimal[]" => Cow::Borrowed("array<decimal>"),
        "jsonb[]" | "json[]" => Cow::Borrowed("array<json>"),

        "int4range" => Cow::Borrowed("range<int32>"),
        "int8range" => Cow::Borrowed("range<int64>"),
        "tstzrange" => Cow::Borrowed("range<datetime_tz>"),
        "tsrange" => Cow::Borrowed("range<datetime>"),
        "daterange" => Cow::Borrowed("range<date>"),
        "numrange" => Cow::Borrowed("range<decimal>"),
        _ => {
            if let Some(inner) = normalized.strip_suffix("[]") {
                let inner_neutral = sql_type_to_neutral(inner, catalog);
                return Cow::Owned(format!("array<{}>", inner_neutral));
            }
            if let Some(base_type) = catalog.get_domain_base_type(&normalized) {
                return sql_type_to_neutral(base_type, catalog);
            }
            if catalog.get_enum(&normalized).is_some() {
                return Cow::Owned(format!("enum::{}", normalized));
            }
            if catalog.get_composite(&normalized).is_some() {
                return Cow::Owned(format!("composite::{}", normalized));
            }
            Cow::Owned(normalized.to_string())
        }
    }
}

/// Resolve a width-bearing `BIT(n)` string (as produced by `normalize_data_type`,
/// which keeps the width). `BIT(1)` is boolean-ish; `BIT(n>1)` is a true bit
/// string with no numeric interpretation, hence `bytes`.
fn bit_type_to_neutral(lower: &str) -> Option<Cow<'static, str>> {
    let inner = lower.strip_prefix("bit(")?.strip_suffix(')')?;
    let width: u64 = inner.trim().parse().ok()?;
    Some(if width <= 1 {
        Cow::Borrowed("bool")
    } else {
        Cow::Borrowed("bytes")
    })
}

pub(super) fn strip_precision(s: &str) -> String {
    if let Some(idx) = s.rfind('(')
        && s.ends_with(')')
    {
        let prefix = s[..idx].trim();
        let inner = &s[idx + 1..s.len() - 1];
        if inner.chars().all(|c| c.is_ascii_digit() || c == ',' || c == ' ') {
            return prefix.to_string();
        }
    }
    s.to_string()
}

pub(super) fn datatype_to_neutral(dt: &DataType, catalog: &Catalog) -> String {
    match dt {
        DataType::Int(_) | DataType::Int4(_) | DataType::Integer(_) => "int32".to_string(),
        DataType::SmallInt(_) | DataType::Int2(_) => "int16".to_string(),
        DataType::BigInt(_) | DataType::Int8(_) => "int64".to_string(),
        DataType::Real | DataType::Float4 => "float32".to_string(),
        DataType::DoublePrecision | DataType::Float8 => "float64".to_string(),
        DataType::Float(info) => {
            use sqlparser::ast::ExactNumberInfo;
            match info {
                ExactNumberInfo::Precision(p) if *p <= 24 => "float32".to_string(),
                _ => "float64".to_string(),
            }
        }
        DataType::Numeric(_) | DataType::Decimal(_) | DataType::Dec(_) => "decimal".to_string(),
        DataType::Varchar(_)
        | DataType::CharVarying(_)
        | DataType::CharacterVarying(_)
        | DataType::Text
        | DataType::Char(_)
        | DataType::Character(_) => "string".to_string(),
        DataType::Bool | DataType::Boolean => "bool".to_string(),
        DataType::Bytea => "bytes".to_string(),
        DataType::Uuid => "uuid".to_string(),
        // See `bit_type_to_neutral`: `BIT(n>1)` is a bit string.
        DataType::Bit(width) => match width {
            Some(w) if *w > 1 => "bytes".to_string(),
            _ => "bool".to_string(),
        },
        DataType::BitVarying(_) | DataType::VarBit(_) => "bytes".to_string(),
        DataType::Date => "date".to_string(),
        DataType::Time(_, tz) => match tz {
            TimezoneInfo::WithTimeZone | TimezoneInfo::Tz => "time_tz".to_string(),
            _ => "time".to_string(),
        },
        DataType::Timestamp(_, tz) => match tz {
            TimezoneInfo::WithTimeZone | TimezoneInfo::Tz => "datetime_tz".to_string(),
            _ => "datetime".to_string(),
        },
        DataType::Interval { .. } => "interval".to_string(),
        DataType::JSON => "json".to_string(),
        DataType::JSONB => "json".to_string(),
        DataType::Array(elem) => {
            let inner = match elem {
                ast::ArrayElemTypeDef::SquareBracket(inner_dt, _) => datatype_to_neutral(inner_dt, catalog),
                ast::ArrayElemTypeDef::AngleBracket(inner_dt) => datatype_to_neutral(inner_dt, catalog),
                ast::ArrayElemTypeDef::Parenthesis(inner_dt) => datatype_to_neutral(inner_dt, catalog),
                ast::ArrayElemTypeDef::Qualified(inner_dt, _) => datatype_to_neutral(inner_dt, catalog),
                ast::ArrayElemTypeDef::None => "unknown".to_string(),
            };
            format!("array<{}>", inner)
        }
        DataType::Custom(name, _) => {
            let raw = object_name_to_string(name).to_lowercase();
            match raw.as_str() {
                "timestamptz" => "datetime_tz".to_string(),
                "timetz" => "time_tz".to_string(),
                "serial" | "serial4" => "int32".to_string(),
                "bigserial" | "serial8" => "int64".to_string(),
                "smallserial" | "serial2" => "int16".to_string(),
                _ => sql_type_to_neutral(&raw, catalog).into_owned(),
            }
        }
        _ => {
            let s = dt.to_string().to_lowercase();
            sql_type_to_neutral(&s, catalog).into_owned()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_catalog() -> Catalog {
        Catalog::from_ddl(&[]).unwrap()
    }

    #[test]
    fn test_money_maps_to_decimal() {
        assert_eq!(sql_type_to_neutral("money", &empty_catalog()), "decimal");
    }

    #[test]
    fn test_bit_widths() {
        let c = empty_catalog();
        assert_eq!(sql_type_to_neutral("bit", &c), "bool");
        assert_eq!(sql_type_to_neutral("bit(1)", &c), "bool");
        assert_eq!(sql_type_to_neutral("bit(8)", &c), "bytes");
        assert_eq!(sql_type_to_neutral("varbit", &c), "bytes");
    }

    #[test]
    fn test_bare_float_is_float64() {
        assert_eq!(sql_type_to_neutral("float", &empty_catalog()), "float64");
    }

    #[test]
    fn test_integer_types() {
        let c = empty_catalog();
        assert_eq!(sql_type_to_neutral("integer", &c), "int32");
        assert_eq!(sql_type_to_neutral("int", &c), "int32");
        assert_eq!(sql_type_to_neutral("int4", &c), "int32");
        assert_eq!(sql_type_to_neutral("serial", &c), "int32");
        assert_eq!(sql_type_to_neutral("smallint", &c), "int16");
        assert_eq!(sql_type_to_neutral("int2", &c), "int16");
        assert_eq!(sql_type_to_neutral("smallserial", &c), "int16");
        assert_eq!(sql_type_to_neutral("bigint", &c), "int64");
        assert_eq!(sql_type_to_neutral("int8", &c), "int64");
        assert_eq!(sql_type_to_neutral("bigserial", &c), "int64");
    }

    #[test]
    fn test_float_types() {
        let c = empty_catalog();
        assert_eq!(sql_type_to_neutral("real", &c), "float32");
        assert_eq!(sql_type_to_neutral("float4", &c), "float32");
        assert_eq!(sql_type_to_neutral("double precision", &c), "float64");
        assert_eq!(sql_type_to_neutral("float8", &c), "float64");
        assert_eq!(sql_type_to_neutral("numeric", &c), "decimal");
        assert_eq!(sql_type_to_neutral("decimal", &c), "decimal");
    }

    #[test]
    fn test_string_types() {
        let c = empty_catalog();
        assert_eq!(sql_type_to_neutral("text", &c), "string");
        assert_eq!(sql_type_to_neutral("varchar", &c), "string");
        assert_eq!(sql_type_to_neutral("character varying", &c), "string");
        assert_eq!(sql_type_to_neutral("character", &c), "string");
        assert_eq!(sql_type_to_neutral("char", &c), "string");
    }

    #[test]
    fn test_boolean() {
        let c = empty_catalog();
        assert_eq!(sql_type_to_neutral("boolean", &c), "bool");
        assert_eq!(sql_type_to_neutral("bool", &c), "bool");
    }

    #[test]
    fn test_temporal_types() {
        let c = empty_catalog();
        assert_eq!(sql_type_to_neutral("timestamp", &c), "datetime");
        assert_eq!(sql_type_to_neutral("timestamp without time zone", &c), "datetime");
        assert_eq!(sql_type_to_neutral("timestamp with time zone", &c), "datetime_tz");
        assert_eq!(sql_type_to_neutral("timestamptz", &c), "datetime_tz");
        assert_eq!(sql_type_to_neutral("date", &c), "date");
        assert_eq!(sql_type_to_neutral("time", &c), "time");
        assert_eq!(sql_type_to_neutral("time without time zone", &c), "time");
        assert_eq!(sql_type_to_neutral("time with time zone", &c), "time_tz");
        assert_eq!(sql_type_to_neutral("timetz", &c), "time_tz");
        assert_eq!(sql_type_to_neutral("interval", &c), "interval");
    }

    #[test]
    fn test_binary_types() {
        let c = empty_catalog();
        assert_eq!(sql_type_to_neutral("bytea", &c), "bytes");
    }

    #[test]
    fn test_json_types() {
        let c = empty_catalog();
        assert_eq!(sql_type_to_neutral("json", &c), "json");
        assert_eq!(sql_type_to_neutral("jsonb", &c), "json");
    }

    #[test]
    fn test_uuid() {
        let c = empty_catalog();
        assert_eq!(sql_type_to_neutral("uuid", &c), "uuid");
    }

    #[test]
    fn test_network_types() {
        let c = empty_catalog();
        assert_eq!(sql_type_to_neutral("inet", &c), "inet");
        assert_eq!(sql_type_to_neutral("cidr", &c), "inet");
        assert_eq!(sql_type_to_neutral("macaddr", &c), "inet");
    }

    #[test]
    fn test_array_types() {
        let c = empty_catalog();
        assert_eq!(sql_type_to_neutral("integer[]", &c), "array<int32>");
        assert_eq!(sql_type_to_neutral("int4[]", &c), "array<int32>");
        assert_eq!(sql_type_to_neutral("int[]", &c), "array<int32>");
        assert_eq!(sql_type_to_neutral("text[]", &c), "array<string>");
        assert_eq!(sql_type_to_neutral("boolean[]", &c), "array<bool>");
        assert_eq!(sql_type_to_neutral("bool[]", &c), "array<bool>");
        assert_eq!(sql_type_to_neutral("bigint[]", &c), "array<int64>");
        assert_eq!(sql_type_to_neutral("uuid[]", &c), "array<uuid>");
        assert_eq!(sql_type_to_neutral("jsonb[]", &c), "array<json>");
        assert_eq!(sql_type_to_neutral("numeric[]", &c), "array<decimal>");
    }

    #[test]
    fn test_range_types() {
        let c = empty_catalog();
        assert_eq!(sql_type_to_neutral("int4range", &c), "range<int32>");
        assert_eq!(sql_type_to_neutral("int8range", &c), "range<int64>");
        assert_eq!(sql_type_to_neutral("tstzrange", &c), "range<datetime_tz>");
        assert_eq!(sql_type_to_neutral("tsrange", &c), "range<datetime>");
        assert_eq!(sql_type_to_neutral("daterange", &c), "range<date>");
        assert_eq!(sql_type_to_neutral("numrange", &c), "range<decimal>");
    }

    #[test]
    fn test_unknown_type() {
        let c = empty_catalog();
        assert_eq!(sql_type_to_neutral("somecustomtype", &c), "somecustomtype");
        assert_eq!(sql_type_to_neutral("hstore", &c), "hstore");
    }

    #[test]
    fn test_case_insensitive() {
        let c = empty_catalog();
        assert_eq!(sql_type_to_neutral("INTEGER", &c), "int32");
        assert_eq!(sql_type_to_neutral("Text", &c), "string");
        assert_eq!(sql_type_to_neutral("BOOLEAN", &c), "bool");
        assert_eq!(sql_type_to_neutral("TIMESTAMP WITH TIME ZONE", &c), "datetime_tz");
    }

    #[test]
    fn test_strip_precision() {
        assert_eq!(
            strip_precision("timestamp with time zone(6)"),
            "timestamp with time zone"
        );
        assert_eq!(strip_precision("numeric(10,2)"), "numeric");
        assert_eq!(strip_precision("varchar(255)"), "varchar");
        assert_eq!(strip_precision("foo(bar)"), "foo(bar)");
        assert_eq!(strip_precision("integer"), "integer");
    }

    #[test]
    fn test_type_with_precision() {
        let c = empty_catalog();
        assert_eq!(sql_type_to_neutral("numeric(10,2)", &c), "decimal");
        assert_eq!(sql_type_to_neutral("timestamp with time zone(6)", &c), "datetime_tz");
    }

    #[test]
    fn test_enum_type_lookup() {
        let c = Catalog::from_ddl(&["CREATE TYPE mood AS ENUM ('sad', 'ok', 'happy');"]).unwrap();
        assert_eq!(sql_type_to_neutral("mood", &c), "enum::mood");
    }

    #[test]
    fn test_composite_type_lookup() {
        let c = Catalog::from_ddl(&["CREATE TYPE address AS (street TEXT, city TEXT, zip INTEGER);"]).unwrap();
        assert_eq!(sql_type_to_neutral("address", &c), "composite::address");
    }

    #[test]
    fn test_generic_array_fallback() {
        let c = empty_catalog();
        assert_eq!(sql_type_to_neutral("timestamptz[]", &c), "array<datetime_tz>");
    }
}
