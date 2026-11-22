//! `sqlkit inspect` — connect to a live database and run operational health
//! checks, emitting findings in the same reporter shapes used by `sqlkit
//! audit` (human / SARIF / JSON).
//!
//! Phase 1C additions:
//! - `[inspect]` config section in `sqlkit.toml` (database_url, api_schemas,
//!   extra_rules, severity_overrides, suppression rules, inline checks).
//! - `--explain <CHECK_ID>` flag: prints full rationale without a DB connection.
//! - Suppression engine applied to findings before emission.
//! - Severity overrides applied to the registry before running.
//! - URL precedence: CLI positional > `$DATABASE_URL` > `$SQLKIT_DATABASE_URL`
//!   > `[inspect].database_url` in `sqlkit.toml`.

use std::fs::File;
use std::io::Write;
use std::path::Path;

use sqlkit_inspect::{CheckRegistry, InspectConfig, InspectError, parse_inspect_section};
#[cfg(feature = "postgres")]
use sqlkit_inspect::{PostgresDriver, SuppressionEngine};
use sqlkit_lint::reporters::{Finding, Format};
use sqlkit_lint::{Severity, emit_findings};

const TOOL_NAME: &str = "sqlkit-inspect";
const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The engine name the inspect check specs declare (`engines = ["postgres"]`).
const CHECK_ENGINE: &str = "postgres";

/// Inputs to [`run_inspect`]. Mirrors the clap `Commands::Inspect` shape.
pub struct RunInspectOpts {
    /// Positional database URL, if supplied.
    pub database_url: Option<String>,
    /// Reporter format string (human / sarif / json).
    pub format: String,
    /// `--list-checks` flag: print the catalog and exit 0.
    pub list_checks: bool,
    /// `--explain <CHECK_ID>` flag: print the check's rationale and exit 0.
    pub explain: Option<String>,
    /// Severity floor — drop findings below this level.
    pub severity: Option<String>,
    /// `--exit-zero` flag: always exit 0 even with error findings.
    pub exit_zero: bool,
    /// Output path; `None` means stdout.
    pub output: Option<String>,
    /// Path to `sqlkit.toml` (default: `"sqlkit.toml"`).
    pub config_path: String,
}

pub fn run_inspect(opts: RunInspectOpts) -> Result<(), Box<dyn std::error::Error>> {
    let inspect_config: Option<InspectConfig> =
        parse_inspect_section(Path::new(&opts.config_path)).unwrap_or_else(|e| {
            eprintln!("sqlkit-inspect: warning: could not parse [inspect] config: {e}");
            None
        });

    let registry = build_registry(&inspect_config)?;

    if opts.list_checks || opts.explain.is_some() {
        let mut out = open_output(opts.output.as_deref())?;
        if opts.list_checks {
            print_check_catalog_from_registry(&registry, out.as_mut())?;
            return Ok(());
        }
        if let Some(id) = &opts.explain {
            print_explanation(&registry, id, out.as_mut())?;
            return Ok(());
        }
    }

    let format = Format::parse(&opts.format)
        .ok_or_else(|| format!("unknown --format '{}' (expected human|sarif|json)", opts.format))?;

    let severity_floor = match opts.severity.as_deref() {
        Some(s) => Some(
            Severity::parse_cli(s).ok_or_else(|| format!("unknown --severity '{}' (expected off|warn|error)", s))?,
        ),
        None => None,
    };

    let config_db_url = inspect_config.as_ref().and_then(|c| c.database_url.as_deref());
    let url = resolve_url(opts.database_url.as_deref(), config_db_url)?;

    let mut findings = live_findings(&url, registry, &inspect_config)?;
    if let Some(floor) = severity_floor {
        findings.retain(|f| f.severity >= floor);
    }

    let mut out = open_output(opts.output.as_deref())?;
    emit_findings(format, TOOL_NAME, TOOL_VERSION, &findings, out.as_mut())?;
    out.flush().ok();

    let error_count = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Error))
        .count();
    if error_count > 0 && !opts.exit_zero {
        std::process::exit(2);
    }
    Ok(())
}

/// Build a [`CheckRegistry`] with:
/// 1. The canonical built-in checks.
/// 2. Inline user checks from `[[inspect.check]]`.
/// 3. Extra rules from `extra_rules` paths (already resolved to absolute by
///    `parse_inspect_section`).
/// 4. Severity overrides from `[inspect.severity_overrides]`.
pub(crate) fn build_registry(
    inspect_config: &Option<InspectConfig>,
) -> Result<CheckRegistry, Box<dyn std::error::Error>> {
    let mut registry = CheckRegistry::canonical();

    if let Some(cfg) = inspect_config {
        if !cfg.check.is_empty() {
            registry = registry.with_inline_checks(cfg.check.clone());
        }

        for abs_path in &cfg.extra_rules {
            registry = registry
                .with_user_checks(Path::new(abs_path))
                .map_err(|e| format!("failed to load extra_rules '{}': {}", abs_path, e))?;
        }

        if !cfg.severity_overrides.is_empty() {
            registry.apply_severity_overrides(&cfg.severity_overrides);
        }
    }

    Ok(registry)
}

/// Connect to `url` and run every check in `registry`, applying the
/// `[inspect]` suppression rules and `api_schemas`.
#[cfg(feature = "postgres")]
pub(crate) fn live_findings(
    url: &str,
    registry: CheckRegistry,
    inspect_config: &Option<InspectConfig>,
) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let mut driver = PostgresDriver::with_registry(registry);
    if let Some(cfg) = inspect_config {
        if !cfg.suppression.is_empty() {
            driver.set_suppression(SuppressionEngine::new(cfg.suppression.clone()));
        }
        if !cfg.api_schemas.is_empty() {
            driver.set_api_schemas(cfg.api_schemas.clone());
        }
    }

    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    Ok(runtime.block_on(async {
        driver.connect(url).await?;
        driver.run_all().await
    })?)
}

/// Without the `postgres` feature there is no database client to inspect with.
#[cfg(not(feature = "postgres"))]
pub(crate) fn live_findings(
    _url: &str,
    _registry: CheckRegistry,
    _inspect_config: &Option<InspectConfig>,
) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    Err(
        "live inspection needs the PostgreSQL client: this build was compiled without the `postgres` Cargo \
         feature"
            .into(),
    )
}

/// Resolve the database URL with the full precedence chain:
/// CLI positional > `$DATABASE_URL` > `$SQLKIT_DATABASE_URL` >
/// `[inspect].database_url` in sqlkit.toml.
pub(crate) fn resolve_url(
    positional: Option<&str>,
    config_url: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    resolve_url_inner(
        positional,
        std::env::var("DATABASE_URL").ok().as_deref(),
        std::env::var("SQLKIT_DATABASE_URL").ok().as_deref(),
        config_url,
    )
}

/// Pure-function precedence resolver — separated so tests can inject env
/// values without racing on `std::env::set_var`.
fn resolve_url_inner(
    positional: Option<&str>,
    env_database_url: Option<&str>,
    env_sqlkit_database_url: Option<&str>,
    config_url: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(u) = positional {
        return Ok(u.to_string());
    }
    resolve_url_inner_opt(env_database_url, env_sqlkit_database_url, config_url)
        .ok_or_else(|| Box::new(InspectError::UrlMissing) as Box<dyn std::error::Error>)
}

/// Pure infallible URL resolver behind [`resolve_url`], which wraps it in a
/// `Result`.
///
/// Precedence (highest → lowest): `$DATABASE_URL` > `$SQLKIT_DATABASE_URL`
/// > config file.
///
/// `sqlkit lint`'s inspect auto-run used to share this via a now-removed
/// `resolve_inspect_url` wrapper. It no longer does: falling back to a bare
/// environment variable meant a linter could open an outbound database
/// connection purely because `$DATABASE_URL` happened to be set, with no
/// flag to request it and no visible diagnostic if it failed (#210). `lint`
/// now only honours an explicit `--database-url` or `[inspect].database_url`
/// in `sqlkit.toml` — see `lint_cmd::try_run_inspect`.
fn resolve_url_inner_opt(
    env_database_url: Option<&str>,
    env_sqlkit_database_url: Option<&str>,
    config_url: Option<&str>,
) -> Option<String> {
    if let Some(u) = env_database_url {
        return Some(u.to_string());
    }
    if let Some(u) = env_sqlkit_database_url {
        return Some(u.to_string());
    }
    config_url.map(|u| u.to_string())
}

fn open_output(path: Option<&str>) -> Result<Box<dyn Write>, Box<dyn std::error::Error>> {
    match path {
        None => Ok(Box::new(std::io::stdout())),
        Some(p) => {
            let f = File::create(p).map_err(|e| format!("failed to open output file '{}': {}", p, e))?;
            Ok(Box::new(std::io::BufWriter::new(f)))
        }
    }
}

/// Print the check catalog from a [`CheckRegistry`].
fn print_check_catalog_from_registry(
    registry: &CheckRegistry,
    out: &mut dyn Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let checks: Vec<_> = registry.for_engine(CHECK_ENGINE).collect();
    if checks.is_empty() {
        writeln!(out, "no checks available")?;
        return Ok(());
    }

    let id_w = checks.iter().map(|c| c.id.len()).max().unwrap_or(2).max(2);
    let name_w = checks.iter().map(|c| c.name.len()).max().unwrap_or(4).max(4);

    writeln!(out, "[{CHECK_ENGINE}]")?;
    for check in checks {
        writeln!(
            out,
            "  {id:<id_w$}  {name:<name_w$}  {sev:<5}  {desc}",
            id = check.id,
            name = check.name,
            sev = severity_label(check.severity),
            desc = check.description,
            id_w = id_w,
            name_w = name_w,
        )?;
    }
    Ok(())
}

/// Print the full explanation for a single check ID.
///
/// Mirrors `audit::print_rule_explanation` for consistency.
///
/// Exits with an error message if the ID is not found.
pub(crate) fn print_explanation(
    registry: &CheckRegistry,
    id: &str,
    out: &mut dyn Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let spec = registry
        .get(id)
        .filter(|s| s.engines.iter().any(|e| e == CHECK_ENGINE))
        .ok_or_else(|| format!("no check with id '{id}' — try `sqlkit inspect --list-checks`"))?;

    writeln!(out, "{} — {}", spec.id, spec.name)?;
    writeln!(out, "  category: {}", spec.category)?;
    writeln!(out, "  severity: {}", severity_label(spec.severity))?;
    writeln!(out, "  engines:  {}", spec.engines.join(", "))?;
    if !spec.cwe.is_empty() {
        writeln!(out, "  cwe:      {}", spec.cwe.join(", "))?;
    }
    writeln!(out)?;
    writeln!(out, "{}", spec.description)?;
    if let Some(explanation) = &spec.explanation {
        writeln!(out)?;
        writeln!(out, "Explanation")?;
        writeln!(out, "-----------")?;
        writeln!(out, "{explanation}")?;
    }
    if let Some(remediation) = &spec.remediation {
        writeln!(out)?;
        writeln!(out, "Remediation")?;
        writeln!(out, "-----------")?;
        writeln!(out, "{remediation}")?;
    }
    writeln!(out)?;
    writeln!(out, "SQL")?;
    writeln!(out, "---")?;
    writeln!(out, "{}", spec.sql.trim())?;
    Ok(())
}

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Off => "off",
        Severity::Warn => "warn",
        Severity::Error => "error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_url_prefers_positional() {
        let url = resolve_url(Some("postgres://positional/db"), Some("postgres://config/db")).unwrap();
        assert_eq!(url, "postgres://positional/db");
    }

    #[test]
    fn resolve_url_inner_prefers_positional_over_everything() {
        let url = resolve_url_inner(
            Some("postgres://cli/db"),
            Some("postgres://env-db/db"),
            Some("postgres://env-sqlkit/db"),
            Some("postgres://config/db"),
        )
        .unwrap();
        assert_eq!(url, "postgres://cli/db");
    }

    #[test]
    fn resolve_url_inner_prefers_database_url_over_sqlkit_and_config() {
        let url = resolve_url_inner(
            None,
            Some("postgres://env-db/db"),
            Some("postgres://env-sqlkit/db"),
            Some("postgres://config/db"),
        )
        .unwrap();
        assert_eq!(url, "postgres://env-db/db");
    }

    #[test]
    fn resolve_url_inner_prefers_sqlkit_database_url_over_config() {
        let url = resolve_url_inner(
            None,
            None,
            Some("postgres://env-sqlkit/db"),
            Some("postgres://config/db"),
        )
        .unwrap();
        assert_eq!(url, "postgres://env-sqlkit/db");
    }

    #[test]
    fn resolve_url_inner_falls_back_to_config_when_no_cli_or_env() {
        let url = resolve_url_inner(None, None, None, Some("postgres://config/db")).unwrap();
        assert_eq!(url, "postgres://config/db");
    }

    #[test]
    fn resolve_url_inner_returns_clear_error_when_all_sources_absent() {
        let err = resolve_url_inner(None, None, None, None).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("DATABASE_URL") || s.contains("no database URL"));
    }

    #[test]
    fn resolve_inspect_url_returns_none_when_no_url_configured() {
        let result = resolve_url_inner_opt(None, None, None);
        assert!(result.is_none());
    }

    #[test]
    fn resolve_inspect_url_inner_opt_prefers_database_url_over_sqlkit_and_config() {
        let result = resolve_url_inner_opt(
            Some("postgres://env-db/db"),
            Some("postgres://env-sqlkit/db"),
            Some("postgres://config/db"),
        );
        assert_eq!(result.as_deref(), Some("postgres://env-db/db"));
    }

    #[test]
    fn resolve_inspect_url_inner_opt_prefers_sqlkit_database_url_over_config() {
        let result = resolve_url_inner_opt(None, Some("postgres://env-sqlkit/db"), Some("postgres://config/db"));
        assert_eq!(result.as_deref(), Some("postgres://env-sqlkit/db"));
    }

    #[test]
    fn resolve_inspect_url_inner_opt_falls_back_to_config() {
        let result = resolve_url_inner_opt(None, None, Some("postgres://config/db"));
        assert_eq!(result.as_deref(), Some("postgres://config/db"));
    }

    #[test]
    fn resolve_inspect_url_returns_none_from_empty_config() {
        let config: Option<InspectConfig> = Some(InspectConfig::default());
        let result = resolve_url_inner_opt(None, None, config.as_ref().and_then(|c| c.database_url.as_deref()));
        assert!(result.is_none());
    }

    #[test]
    fn resolve_inspect_url_returns_url_from_config_database_url() {
        let config = InspectConfig {
            database_url: Some("postgres://from-config/db".to_string()),
            ..Default::default()
        };
        let result = resolve_url_inner_opt(None, None, config.database_url.as_deref());
        assert_eq!(result.as_deref(), Some("postgres://from-config/db"));
    }

    #[test]
    fn explain_known_id_prints_body() {
        let registry = CheckRegistry::canonical();
        let mut buf = Vec::new();
        print_explanation(&registry, "SC-INS04", &mut buf).expect("explain SC-INS04");
        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("no-primary-key"),
            "output should contain check name; got:\n{output}"
        );
        assert!(output.contains("SC-INS04"));
    }

    #[test]
    fn explain_unknown_id_errors() {
        let registry = CheckRegistry::canonical();
        let mut buf = Vec::new();
        let result = print_explanation(&registry, "SC-NOPE", &mut buf);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("SC-NOPE"),
            "error message should include the unknown ID; got: {msg}"
        );
    }
}
