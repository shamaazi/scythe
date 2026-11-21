---
title: Schema Constraints
description: Carry varchar lengths, CHECK constraints, domains and column comments into generated validation.
---

The schema already says which values a column accepts: `varchar(255)` caps a length, a `CHECK`
names a range or a pattern, a domain bundles both under a name, and `COMMENT ON` describes the
column. Scythe reads these from the schema, translates them into a neutral set of validation
rules, and attaches the rules to the result columns and parameters that read or write the column.
A backend that supports it renders them -- the TypeScript backends as JSON Schema JSDoc tags (see
[`validation`](/scythe/backends/typescript/#options)) -- so the database
schema is the one place the rules are declared.

```sql
CREATE DOMAIN slug AS text CHECK (VALUE ~ '^[a-z0-9-]+$');
CREATE DOMAIN amount AS integer CHECK (VALUE BETWEEN 0 AND 100000000);
COMMENT ON DOMAIN amount IS 'An amount in minor units.';

CREATE TABLE causes (
    id serial PRIMARY KEY,
    slug slug NOT NULL,
    title varchar(255) NOT NULL CHECK (length(trim(title)) > 0),
    goal amount,
    status varchar(20) NOT NULL CHECK (status IN ('draft', 'live'))
);
```

```typescript
export interface GetCauseRow {
	/**
	 * @pattern ^[a-z0-9\-]+$
	 */
	slug: string;
	/**
	 * @minLength 1
	 * @maxLength 255
	 * @pattern [^ ]
	 */
	title: string;
	/**
	 * An amount in minor units.
	 * @minimum 0
	 * @maximum 100000000
	 */
	goal: number | null;
	/**
	 * @maxLength 20
	 */
	status: "draft" | "live";
}
```

## What the catalog records

Per column, and per domain:

| Declaration | Recorded as |
|-------------|-------------|
| `varchar(n)`, `character varying(n)`, `char(n)` | `maxLength n` |
| `numeric(p, s)` | precision and scale, available to embedders -- not a rule (see below) |
| Column `CHECK`, `CONSTRAINT ... CHECK` in the table, `ALTER TABLE ... ADD CONSTRAINT ... CHECK` | the check, when it references exactly one column |
| `CREATE DOMAIN ... CHECK (VALUE ...)` | the check, applied to every column of the domain |
| `COMMENT ON COLUMN`, `COMMENT ON DOMAIN` | the description; a column's own comment wins over its domain's |

A column declared with a domain takes the domain's constraints (and its parent domains'), keeps the
domain's name, and adds its own. `ALTER TABLE ... DROP CONSTRAINT` removes a named check and
`ALTER COLUMN ... TYPE` replaces the length. A check that references several columns
(`CHECK (num_nonnulls(a, b) = 1)`) relates values to each other rather than constraining one value,
so it is not a column's rule and is not reported.

`numeric(p, s)` precision is recorded but not turned into bounds: PostgreSQL rounds a value to the
scale instead of rejecting it, and generated code commonly carries decimals as strings, so -- like
an integer type's range -- it is left to the type.

## Rules

Rules use JSON Schema's validation vocabulary and describe non-null values: PostgreSQL passes a
`CHECK` whose expression is NULL, and nullability is already part of the generated type.

| Rule | Keyword |
|------|---------|
| Minimum / maximum length in characters | `minLength`, `maxLength` |
| ECMAScript regular expression the value must contain a match for | `pattern` |
| Inclusive numeric bounds | `minimum`, `maximum` |
| Exclusive numeric bounds | `exclusiveMinimum`, `exclusiveMaximum` |
| Divisor | `multipleOf` |
| The only allowed values | `enum` (rendered by TypeScript as a literal union) |

Several constraints on one value combine into the tightest rules: the larger minimum, the smaller
maximum, the common allowed values, and two patterns into one pattern that requires both.

## Translation

Each `CHECK` is translated from its parsed expression, one `AND`-ed condition at a time. A
condition becomes rules that accept exactly the values it accepts, or it is left **untranslated**
-- never approximated. The column (or `VALUE`) may be wrapped in parentheses or a cast to an
unsized text or numeric type, and literals may be cast.

| `CHECK` condition | Rules |
|-------------------|-------|
| `x >= 0`, `x > 0`, `x <= 10`, `x < 10` (either side) | `minimum`, `exclusiveMinimum`, `maximum`, `exclusiveMaximum` |
| `x BETWEEN 0 AND 100` | `minimum 0`, `maximum 100` |
| `x = 5`, `x = 'a'` | allowed values |
| `x IN ('a', 'b')`, `x = ANY (ARRAY['a', 'b'])` | allowed values |
| `x % 5 = 0` | `multipleOf 5` |
| `length(x) >= 1` (also `char_length`, `character_length`, `=`, `BETWEEN`) | `minLength`, `maxLength` |
| `length(trim(x)) > 0` (also `btrim`, `ltrim`, `rtrim`, `TRIM(BOTH ' ' FROM x)`, `>= 1`, `<> 0`) | `minLength 1`, `pattern [^ ]` |
| `x ~ '...'` | `pattern`, when the expression translates (below) |
| `x !~ '...'` | `pattern ^(?![\s\S]*(?:...))` |
| `x LIKE '...'`, `x NOT LIKE '...'` | an anchored `pattern` |
| `x IS NULL OR <condition>` | the condition's rules |
| `a AND b` | both conditions' rules |

**Trim.** `trim` removes spaces, so a trimmed length above zero says the value contains a character
other than a space: exactly `pattern [^ ]`, with the `minLength 1` it implies. Any other bound on a
trimmed length (`length(btrim(x)) >= 3`), or trimming other characters (`btrim(x, '-')`), has no
exact equivalent and is untranslated.

**Patterns.** A PostgreSQL regular expression is translated to ECMAScript only where both engines
mean the same thing, and the result works with or without the `u` flag: literals and escaped
punctuation, `.` (as `[\s\S]`, because PostgreSQL's `.` matches a newline), `^`, `$`, `\A`, `\Z`,
groups, `(?:...)`, `(?=...)`, `(?!...)`, alternation, greedy and non-greedy quantifiers and bounds,
bracket expressions with ranges and negation, `[:digit:]`, `\d`, `\D`, and `\n`, `\t`, `\r`, `\f`,
`\v`, `\uXXXX`. Locale-dependent classes (`\w`, `\s`, `[:alpha:]` and the other named classes),
word boundaries and other ARE-only escapes, back references, collating elements, embedded options,
lookbehind and case-insensitive operators (`~*`, `ILIKE`) are refused.

**Untranslated.** Everything else is kept as an untranslated constraint naming where it was
declared, its SQL and the reason: `<>`, `NOT IN`, comparisons with text or dates (which depend on
collation and type), `octet_length` (bytes, not characters), `OR` of other conditions, function
calls, and refused patterns. The translated conditions of the same `CHECK` still apply.

## Where rules apply

- **Result columns** read a column unchanged -- directly, through an alias, a view, a CTE, a derived
  table, or an outer join -- take that column's rules. A computed value (`upper(title)`,
  `position + 1`, a `CASE`, a cast) takes none.
- **Parameters** written straight into a column -- `INSERT ... VALUES ($1)`,
  `UPDATE ... SET col = $1`, `ON CONFLICT DO UPDATE SET col = $1`, parenthesised or cast -- take that
  column's rules; one written into several columns must satisfy all of them. A parameter that is
  only compared (`WHERE slug = $1`, `IN ($1, $2)`) takes none: a value no row holds simply matches
  nothing, and a parameter reused across conditions (`id = $1 OR slug = $1`) would otherwise be held
  to rules that are not its own. One written through an expression (`coalesce($1, 0)`) takes none.

## Untranslated constraints

A backend that renders validation also reports what is missing from it: every untranslated
constraint on a generated column or parameter, and every rule the backend cannot express on the
value's type -- for example `@minimum` on a `bigint` the backend maps to `string`. The
`constraints` option chooses what happens:

| `constraints` | Effect |
|---------------|--------|
| `ignore` (default) | Generate without it, silently -- the behaviour without validation |
| `warn` | Generate without it and print a warning naming the query, column, constraint and reason |
| `error` | Fail generation with the same message |

With `error`, the generated validation is complete: every constraint the database enforces on a
generated value is either rendered or the build stops.
