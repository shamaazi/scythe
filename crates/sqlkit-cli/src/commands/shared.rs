use std::borrow::Cow;
use std::path::{Path, PathBuf};

use sqlkit_core::catalog::Catalog;

/// Inputs shared by generate, check, lint, and configured audit catalog loading.
pub struct CatalogLoadRequest<'a> {
    pub command: &'static str,
    pub config_name: &'a str,
    pub schema_files: &'a [String],
}

/// A catalog and the exact configured schema inputs that produced it.
pub struct LoadedCatalog {
    pub catalog: Catalog,
    pub schema_contents: Vec<String>,
}

/// Read and parse one configured schema into a catalog.
pub fn load_catalog(request: CatalogLoadRequest<'_>) -> Result<LoadedCatalog, Box<dyn std::error::Error>> {
    let schema_contents = request
        .schema_files
        .iter()
        .map(|path| {
            std::fs::read_to_string(path).map_err(|error| {
                format!(
                    "{} [{}] failed to read schema file `{}`: {}",
                    request.command, request.config_name, path, error
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let schema_refs = schema_contents.iter().map(String::as_str).collect::<Vec<_>>();
    let catalog = Catalog::from_ddl(&schema_refs).map_err(|error| {
        format!(
            "{} [{}] failed to parse configured schema: {}",
            request.command, request.config_name, error
        )
    })?;

    Ok(LoadedCatalog {
        catalog,
        schema_contents,
    })
}

/// Splits a .sql file containing multiple queries separated by `-- name:` or
/// `-- @name` annotations. Returns one string per query block (annotation +
/// SQL). Content before the first annotation is discarded -- see
/// [`has_unannotated_sql`] for detecting when that discard is silently
/// dropping real SQL rather than an intentional header comment.
pub fn split_query_file(content: &str) -> Vec<String> {
    let mut blocks: Vec<String> = Vec::new();
    let mut current_block: Option<String> = None;

    for line in content.lines() {
        let trimmed = line.trim_start();
        let is_annotation = trimmed.starts_with("-- name:") || trimmed.starts_with("-- @name");

        if is_annotation {
            if let Some(block) = current_block.take() {
                blocks.push(block);
            }
            current_block = Some(String::from(line));
        } else if let Some(ref mut block) = current_block {
            block.push('\n');
            block.push_str(line);
        }
    }

    if let Some(block) = current_block {
        blocks.push(block);
    }

    blocks
}

/// Whether `content` has SQL text that [`split_query_file`] would silently
/// discard: a non-blank, non-`--`-comment line appearing before the first
/// `-- name:`/`-- @name` annotation, or -- when the file has no annotation
/// at all -- anywhere in the file.
///
/// A line counts as "content" only if it is non-blank and not an ordinary
/// `--` comment, so a file that opens with a license header or a plain
/// explanatory comment does not trip this check; only a file containing a
/// forgotten or mistyped annotation (or none at all) does. See issue #204:
/// `sqlkit generate`/`sqlkit check` used to report success on a query file
/// reduced to zero blocks, and `sqlkit audit` on the same file found real
/// findings the other commands never saw because they never looked at the
/// SQL at all.
pub fn has_unannotated_sql(content: &str) -> bool {
    let mut saw_content = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("-- name:") || trimmed.starts_with("-- @name") {
            return saw_content;
        }
        if !trimmed.starts_with("--") {
            saw_content = true;
        }
    }
    saw_content
}

/// A `[[sql]] engine` key. The key is optional, since PostgreSQL is the only engine; when
/// present it must name PostgreSQL. Every command reads `engine` as this type, so this is
/// the one place it is validated.
#[derive(Debug, Default)]
pub struct PostgresEngine;

impl<'de> serde::Deserialize<'de> for PostgresEngine {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let engine = String::deserialize(deserializer)?;
        match engine.to_ascii_lowercase().as_str() {
            "postgresql" | "postgres" | "pg" => Ok(PostgresEngine),
            _ => Err(serde::de::Error::custom(format!(
                "unsupported engine '{engine}': sqlkit supports PostgreSQL only (`postgresql`, `postgres` or \
                 `pg`; the key may also be omitted)"
            ))),
        }
    }
}

/// Redact the password component of a connection URL like
/// `postgres://user:secret@host:5432/db` before it is printed to stderr, a
/// log line, or a CI console — never the URL itself.
///
/// Only the password between `:` and `@` in the userinfo component is
/// replaced with `***`; the scheme, username, host, port, path, and query
/// string are left intact so the message stays useful for debugging. URLs
/// with no `user:password@` component (or non-URL strings) are returned
/// unchanged since there is nothing to redact.
pub fn redact_url_password(url: &str) -> String {
    let Ok(re) = regex::Regex::new(r"(?P<prefix>://[^:/?#@\s]+):[^@/?#\s]+@") else {
        return url.to_string();
    };
    re.replace(url, "${prefix}:***@").into_owned()
}

/// The directory a `sqlkit.toml` config file lives in. `schema`/`queries`
/// glob patterns and `output` directories in the config are resolved
/// relative to this directory, not the process's current working directory.
///
/// Falls back to `"."` when `config_path` has no parent component (e.g. a
/// bare filename like `"sqlkit.toml"`).
///
/// `Path::parent()` returns `Some(Path::new(""))` -- not `None` -- for a
/// single-component relative path like `"sqlkit.toml"`, so the `None`
/// fallback above never actually fires for the common case of running from
/// the project root with the default config name. Left unhandled, every
/// message that prints this directory (e.g. `resolve_globs`'s "config dir:"
/// line) rendered an empty string instead of the intended `.`. Both the
/// `None` and `Some("")` cases are normalized to `"."` here.
pub fn config_dir(config_path: &str) -> &Path {
    let parent = Path::new(config_path).parent().unwrap_or_else(|| Path::new("."));
    if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    }
}

/// Returns `true` when `output` (a relative path from `[[sql.gen]]`'s
/// `output = "..."`) would, once joined onto the project root, resolve
/// outside it -- i.e. a leading run of `..` components that is never
/// balanced by a preceding normal component. Absolute paths (including
/// Windows-style rooted paths, via [`Path::has_root`]) always escape,
/// regardless of the base directory.
///
/// Purely lexical: it walks `output`'s own components and tracks a
/// directory-depth counter, going negative exactly when a `..` pops past
/// the join point. This is deliberately *not* implemented by canonicalizing
/// `base_dir.join(output)` and checking `starts_with` -- the output
/// directory frequently does not exist yet (that is what `sqlkit generate`
/// is about to create), and canonicalization requires the path to exist.
/// It is also not implemented by naively collapsing `..` against an
/// accumulator that silently drops unmatched leading `..` components (the
/// way e.g. `cargo_util::paths::normalize_path` does) -- that approach is
/// designed for cleaning up already-safe paths, not for a security
/// containment check, and would make `"../../ESCAPED"` normalize to
/// `"ESCAPED"` and pass. See issue #207.
pub fn output_escapes_base(output: &Path) -> bool {
    use std::path::Component;

    if output.is_absolute() || output.has_root() {
        return true;
    }

    let mut depth: i64 = 0;
    for component in output.components() {
        match component {
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return true;
                }
            }
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => return true,
        }
    }
    false
}

/// Join `output` onto `base_dir`, rejecting the result when it escapes
/// `base_dir` (see [`output_escapes_base`]) unless `allow_escape` is set.
///
/// `label` identifies the config entry in the error message (e.g. the
/// backend name) so a rejected path can be traced back to the `[[sql.gen]]`
/// entry that produced it.
pub fn resolve_contained_output(
    base_dir: &Path,
    output: &str,
    label: &str,
    allow_escape: bool,
) -> Result<PathBuf, String> {
    let joined = base_dir.join(output);
    if allow_escape || !output_escapes_base(Path::new(output)) {
        return Ok(joined);
    }
    Err(format!(
        "{label}: output '{output}' escapes the project root '{base}'; sqlkit refuses to create \
         directories or write files outside the project by default -- pass --allow-output-escape \
         if writing there is deliberate",
        base = base_dir.display(),
    ))
}

/// Rebase a single glob pattern onto `base_dir`, unless the pattern is
/// already absolute or `base_dir` carries no information.
///
/// Rules, in order:
/// 1. Absolute patterns (checked via [`Path::has_root`], not
///    [`Path::is_absolute`] — on Windows a Unix-style absolute pattern like
///    `/abs/x` is *not* `is_absolute()` but *is* `has_root()`) pass through
///    unchanged.
/// 2. An empty or `"."` `base_dir` (e.g. `config_dir("sqlkit.toml")`, or
///    `config_dir("./sqlkit.toml")`) is treated as identity: the pattern is
///    returned unchanged rather than joined, so `"./db/*.sql"` and
///    `"db/*.sql"` report matches under the same spelling the user wrote.
///    This keeps `FileViolation.file` / SARIF / JSON output byte-stable
///    across equivalent `--config` spellings.
/// 3. Otherwise the pattern is prefixed with `base_dir`, escaping `base_dir`
///    (not the pattern) via [`glob::Pattern::escape`] so directory names
///    containing glob metacharacters (`[`, `]`, `?`, `*`, ...) are treated as
///    literal path components rather than compiled as glob syntax. Plain
///    `format!` string concatenation is used instead of [`Path::join`]: glob
///    accepts `/` as a separator on every platform, and `join` would
///    re-parse the escaped string and could reintroduce a platform separator
///    that disturbs the escaping.
pub(crate) fn rebase_pattern<'a>(pattern: &'a str, base_dir: &Path) -> Cow<'a, str> {
    let p = Path::new(pattern);
    if p.is_absolute() || p.has_root() {
        return Cow::Borrowed(pattern);
    }

    if base_dir.as_os_str().is_empty() || base_dir == Path::new(".") {
        return Cow::Borrowed(pattern);
    }

    let escaped_base = glob::Pattern::escape(&base_dir.to_string_lossy());
    let escaped_base = escaped_base.trim_end_matches(['/', '\\']);
    Cow::Owned(format!("{escaped_base}/{pattern}"))
}

/// Resolve a list of glob patterns relative to `base_dir` (see
/// [`rebase_pattern`]) and return every matched path as a string.
///
/// `label` identifies the call site (e.g. `"[main] schema"`) for the error
/// message emitted when a pattern matches no files — matching nothing is
/// treated as a hard configuration error rather than a warning, since paths
/// in `sqlkit.toml` resolve relative to the config file's directory (not the
/// process's current working directory) as of 0.13.0, and an empty match is
/// the most common symptom of a stale CWD-relative pattern.
pub fn resolve_globs(
    patterns: &[String],
    base_dir: &Path,
    label: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut paths = Vec::new();
    for pattern in patterns {
        let rebased = rebase_pattern(pattern, base_dir);
        let matches: Vec<_> = glob::glob(&rebased)?.collect::<Result<Vec<_>, _>>()?;
        if matches.is_empty() {
            return Err(format!(
                "{label} pattern '{pattern}' matched no files\n  \
                 config dir: {config_dir}\n  \
                 resolved:   {resolved}\n  \
                 note: paths in sqlkit.toml resolve relative to the config file's directory,\n        \
                 not the current working directory (changed in 0.13.0)",
                config_dir = base_dir.display(),
                resolved = rebased,
            )
            .into());
        }
        for path in matches {
            paths.push(path.display().to_string());
        }
    }
    Ok(paths)
}

/// Effective severity of `SC-PARSE01` (query fails to parse) and
/// `SC-PARSE02` (query fails to analyze), resolved once from
/// [`sqlkit_lint::parse_registry`] after applying `sqlkit.toml`'s `[lint]`
/// table.
///
/// Both findings are produced outside the `LintRule::check_*` path -- a
/// query that fails to parse never becomes an `AnalyzedQuery`, so there is
/// no `LintContext` to run a rule against -- so they cannot pick up their
/// severity by being iterated out of a [`sqlkit_lint::RuleRegistry`]'s
/// `active_rules`, the way a SQL rule does. Resolving them here through
/// [`sqlkit_lint::RuleRegistry::effective_severity`] -- the same call every
/// other rule's severity goes through -- is what keeps them configurable
/// anyway: `check`, `lint`, and `audit` each build this from their own
/// parsed `[lint]` table, so `[lint.rules] "SC-PARSE01" = "warn"` reaches
/// all three commands identically. Before this existed, each command
/// hardcoded `Severity::Error` at the point its own ad hoc finding was
/// constructed, so `[lint]` had no effect on either id anywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseSeverities {
    pub unparseable: sqlkit_lint::types::Severity,
    pub unanalyzable: sqlkit_lint::types::Severity,
}

impl ParseSeverities {
    /// Resolve both parse-failure severities against `registry`.
    pub fn from_registry(registry: &sqlkit_lint::RuleRegistry) -> Self {
        use sqlkit_lint::rules::parse;

        Self {
            unparseable: registry.effective_severity(&parse::UnparseableQuery),
            unanalyzable: registry.effective_severity(&parse::UnanalyzableQuery),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_catalog_parses_the_configured_schema() {
        let directory = tempfile::tempdir().unwrap();
        let schema_path = directory.path().join("schema.sql");
        let schema = "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL);";
        std::fs::write(&schema_path, schema).unwrap();
        let schema_files = vec![schema_path.display().to_string()];
        let expected = Catalog::from_ddl(&[schema]).unwrap();

        let loaded = load_catalog(CatalogLoadRequest {
            command: "generate",
            config_name: "main",
            schema_files: &schema_files,
        })
        .unwrap();

        assert_eq!(loaded.schema_contents, vec![schema]);
        assert_eq!(loaded.catalog.fingerprint(), expected.fingerprint());
    }

    /// Unconfigured, `ParseSeverities` must reflect `parse_registry`'s own
    /// defaults (both `Error`) rather than a second, hand-written copy of
    /// them -- a change to either rule's `default_severity()` must show up
    /// here automatically.
    #[test]
    fn parse_severities_default_to_error() {
        let severities = ParseSeverities::from_registry(&sqlkit_lint::parse_registry());
        assert_eq!(severities.unparseable, sqlkit_lint::types::Severity::Error);
        assert_eq!(severities.unanalyzable, sqlkit_lint::types::Severity::Error);
    }

    /// The behaviour this struct exists for: `[lint.rules]` overrides
    /// applied to `parse_registry()` before `from_registry` runs must be
    /// visible in the resolved severities.
    #[test]
    fn parse_severities_follow_lint_config_overrides() {
        let mut registry = sqlkit_lint::parse_registry();
        let mut config = sqlkit_lint::types::LintConfig::default();
        config
            .rules
            .insert("SC-PARSE01".to_string(), sqlkit_lint::types::Severity::Warn);
        config
            .rules
            .insert("SC-PARSE02".to_string(), sqlkit_lint::types::Severity::Off);
        registry.apply_config(&config);

        let severities = ParseSeverities::from_registry(&registry);
        assert_eq!(severities.unparseable, sqlkit_lint::types::Severity::Warn);
        assert_eq!(severities.unanalyzable, sqlkit_lint::types::Severity::Off);
    }

    #[test]
    fn redact_url_password_masks_password_only() {
        let redacted = redact_url_password("postgres://sqlkit:hunter2@localhost:5432/mydb?sslmode=disable");
        assert_eq!(redacted, "postgres://sqlkit:***@localhost:5432/mydb?sslmode=disable");
        assert!(!redacted.contains("hunter2"), "password must not survive redaction");
    }

    #[test]
    fn redact_url_password_leaves_urls_without_password_unchanged() {
        assert_eq!(
            redact_url_password("postgres://localhost:5432/mydb"),
            "postgres://localhost:5432/mydb"
        );
        assert_eq!(
            redact_url_password("postgres://sqlkit@localhost:5432/mydb"),
            "postgres://sqlkit@localhost:5432/mydb"
        );
    }

    #[test]
    fn redact_url_password_leaves_non_url_strings_unchanged() {
        assert_eq!(redact_url_password("not a url at all"), "not a url at all");
        assert_eq!(redact_url_password(""), "");
    }

    /// Absolute patterns pass through untouched regardless of `base_dir`.
    ///
    /// `has_root()` (not `is_absolute()`) is what `rebase_pattern` checks,
    /// because a Unix-style absolute pattern like `/abs/x` is NOT
    /// `is_absolute()` on Windows but IS `has_root()` there — so this is the
    /// check that keeps such patterns passing through unchanged on every
    /// platform. A Windows drive-letter pattern (`C:\x`) is only meaningfully
    /// "absolute" under Windows path semantics, so that half of the
    /// assertion is compiled in for Windows only; `has_root()`/
    /// `is_absolute()` both report `false` for it on Unix, where it is just
    /// an ordinary (if unusual) relative filename.
    #[test]
    fn rebase_pattern_passes_absolute_through() {
        let base = Path::new("/some/base");
        assert_eq!(rebase_pattern("/abs/x", base), Cow::Borrowed("/abs/x"));

        #[cfg(windows)]
        {
            let win_base = Path::new(r"C:\some\base");
            assert_eq!(rebase_pattern(r"C:\x", win_base), Cow::Borrowed(r"C:\x"));
        }
    }

    /// An empty `base_dir` (from `config_dir("sqlkit.toml")`) and an
    /// explicit `"."` `base_dir` (from `config_dir("./sqlkit.toml")`) must
    /// both be treated as identity, so equivalent `--config` spellings
    /// report matched paths using the exact string the caller wrote instead
    /// of a `./`-prefixed variant.
    #[test]
    fn rebase_pattern_is_identity_for_empty_and_dot_base() {
        assert_eq!(rebase_pattern("db/*.sql", Path::new("")), Cow::Borrowed("db/*.sql"));
        assert_eq!(rebase_pattern("db/*.sql", Path::new(".")), Cow::Borrowed("db/*.sql"));
    }

    /// A base directory containing glob metacharacters (e.g. a project
    /// literally named `a[b]`) must be escaped via `glob::Pattern::escape`
    /// before being prefixed onto the pattern, or the bracket would be
    /// compiled as a character class and silently match nothing. Only the
    /// base is escaped — the user's own pattern passes through untouched.
    #[test]
    fn rebase_pattern_escapes_metacharacters_in_base() {
        let base = Path::new("a[b]");
        assert_eq!(
            rebase_pattern("x.sql", base),
            Cow::<str>::Owned("a[[]b[]]/x.sql".to_string())
        );
    }

    /// #204 regression: a file with real SQL and no annotation at all must
    /// be flagged, not treated the same as a comment-only stub.
    #[test]
    fn has_unannotated_sql_detects_a_file_with_no_annotation_at_all() {
        let content = "SELECT id, name FROM users WHERE id = $1;\nDELETE FROM users;\n";
        assert!(has_unannotated_sql(content));
    }

    /// A real statement sitting before the first annotation is exactly the
    /// case `split_query_file` silently discards.
    #[test]
    fn has_unannotated_sql_detects_content_before_first_annotation() {
        let content = "DELETE FROM users;\n-- name: GetUser :one\nSELECT * FROM users WHERE id = $1;\n";
        assert!(has_unannotated_sql(content));
    }

    /// A header comment (not an annotation) before the first real annotation
    /// is the normal, intentional case and must not be flagged.
    #[test]
    fn has_unannotated_sql_allows_a_leading_comment_header() {
        let content =
            "-- License: MIT\n-- Copyright 2024\n\n-- name: GetUser :one\nSELECT * FROM users WHERE id = $1;\n";
        assert!(!has_unannotated_sql(content));
    }

    /// A comment-only file (or an empty one) has nothing to silently drop.
    #[test]
    fn has_unannotated_sql_allows_comment_only_file() {
        assert!(!has_unannotated_sql("-- just a comment\n"));
        assert!(!has_unannotated_sql(""));
    }

    /// A well-formed file (annotation first, statement after) is never
    /// flagged regardless of how many blocks it has.
    #[test]
    fn has_unannotated_sql_allows_well_formed_file() {
        let content = "-- name: GetUser :one\nSELECT * FROM users WHERE id = $1;\n\n-- name: ListUsers :many\nSELECT * FROM users;\n";
        assert!(!has_unannotated_sql(content));
    }

    #[test]
    fn config_dir_normalizes_bare_filename_to_dot() {
        assert_eq!(config_dir("sqlkit.toml"), Path::new("."));
        assert_eq!(config_dir("./sqlkit.toml"), Path::new("."));
    }

    #[test]
    fn config_dir_keeps_a_real_parent() {
        assert_eq!(config_dir("project/sqlkit.toml"), Path::new("project"));
    }

    /// #207: an absolute `output` always escapes, regardless of `base_dir`.
    #[test]
    fn output_escapes_base_rejects_absolute_paths() {
        assert!(output_escapes_base(Path::new("/tmp/ABSOLUTE")));
    }

    /// #207: `../../ESCAPED` pops past the join point immediately.
    #[test]
    fn output_escapes_base_rejects_parent_traversal() {
        assert!(output_escapes_base(Path::new("../../ESCAPED")));
    }

    /// `..` that stays balanced by a preceding normal component (e.g.
    /// `sub/../thing`) never leaves the project root and must be allowed.
    #[test]
    fn output_escapes_base_allows_balanced_parent_traversal() {
        assert!(!output_escapes_base(Path::new("sub/../thing")));
        assert!(!output_escapes_base(Path::new("generated")));
        assert!(!output_escapes_base(Path::new("./generated")));
    }

    #[test]
    fn resolve_contained_output_rejects_escape_by_default() {
        let err = resolve_contained_output(Path::new("proj"), "../../ESCAPED", "rust-sqlx", false).unwrap_err();
        assert!(err.contains("rust-sqlx"));
        assert!(err.contains("../../ESCAPED"));
        assert!(err.contains("--allow-output-escape"));
    }

    #[test]
    fn resolve_contained_output_allows_escape_with_opt_out() {
        let result = resolve_contained_output(Path::new("proj"), "../../ESCAPED", "rust-sqlx", true);
        assert!(result.is_ok());
    }

    #[test]
    fn resolve_contained_output_allows_contained_paths() {
        let result = resolve_contained_output(Path::new("proj"), "generated", "rust-sqlx", false);
        assert_eq!(result.unwrap(), Path::new("proj/generated"));
    }
}
