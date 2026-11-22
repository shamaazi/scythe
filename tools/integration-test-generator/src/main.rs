use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use clap::Parser;
use minijinja::Environment;
use scythe_codegen::backends::get_backend;
use serde::{Deserialize, Serialize};

/// Integration test generator for scythe.
///
/// Renders language-specific integration tests from minijinja templates.
/// Each backend produces: sqlkit.toml, a test file, and a dependency file.
#[derive(Parser, Debug)]
#[command(name = "integration-test-generator", version, about)]
struct Cli {
    /// Output directory for generated integration test directories.
    #[arg(long, default_value = "integration_tests")]
    output: PathBuf,

    /// Directory containing minijinja templates.
    #[arg(long, default_value = "tools/integration-test-generator/templates")]
    templates: PathBuf,

    /// Skip backends whose output directory already exists.
    #[arg(long)]
    skip_existing: bool,

    /// Only generate for these backends (comma-separated). If empty, generate all.
    #[arg(long, value_delimiter = ',')]
    only: Vec<String>,

    /// Print backend directory names (one per line) and exit without generating anything.
    ///
    /// This is the manifest of record for `build_backends()` — consumers such as
    /// `integration_tests/mise.toml` should derive their backend lists from this
    /// output instead of hand-maintaining a copy, so the two can never drift.
    #[arg(long)]
    list: bool,
}

#[derive(Debug, Clone, Serialize)]
struct BackendConfig {
    /// Directory name under integration_tests/, e.g. "rust-sqlx".
    name: String,
    /// Language identifier for template selection.
    language: String,
    /// Database engine: "postgresql".
    engine: String,
    /// Driver name used by the scythe backend, e.g. "psycopg3", "asyncpg".
    driver: String,
    /// Environment variable for the database connection string.
    connection_env: String,
    /// The scythe backend identifier (used in sqlkit.toml gen section).
    backend: String,
    /// Extra options passed to templates (e.g. row_type).
    options: HashMap<String, String>,
}

/// Context passed to every template render.
#[derive(Debug, Serialize)]
struct TemplateContext {
    backend_name: String,
    language: String,
    engine: String,
    driver: String,
    connection_env: String,
    backend: String,
    options: HashMap<String, String>,
    /// Relative path from the backend dir to the schema SQL directory.
    schema_dir: String,
    /// Schema SQL filename within `schema_dir`.
    schema_file: String,
    /// Relative path from the backend dir to the queries SQL directory.
    queries_dir: String,
}

impl From<&BackendConfig> for TemplateContext {
    fn from(cfg: &BackendConfig) -> Self {
        let engine_dir = match cfg.engine.as_str() {
            "postgresql" => "pg",
            other => other,
        };
        Self {
            backend_name: cfg.name.clone(),
            language: cfg.language.clone(),
            engine: cfg.engine.clone(),
            driver: cfg.driver.clone(),
            connection_env: cfg.connection_env.clone(),
            backend: cfg.backend.clone(),
            options: cfg.options.clone(),
            schema_dir: format!("../sql/{engine_dir}"),
            schema_file: "schema.sql".to_string(),
            queries_dir: format!("../sql/{engine_dir}/queries"),
        }
    }
}

/// Which files to generate for each language.
struct LanguageOutputs {
    test_template: String,
    test_filename: &'static str,
    dep_template: String,
    dep_filename: &'static str,
    /// Additional files (template, filename) pairs.
    extra: Vec<(&'static str, &'static str)>,
}

fn language_outputs(language: &str) -> LanguageOutputs {
    match language {
        "rust" => LanguageOutputs {
            test_template: "rust.rs.jinja".into(),
            test_filename: "src/main.rs",
            dep_template: "Cargo.toml.integration.jinja".into(),
            dep_filename: "Cargo.toml",
            extra: vec![],
        },
        other => {
            eprintln!("warning: unsupported language '{other}', using generic outputs");
            LanguageOutputs {
                test_template: format!("{other}.jinja"),
                test_filename: "test",
                dep_template: "deps.jinja".into(),
                dep_filename: "deps",
                extra: vec![],
            }
        }
    }
}

/// The hand-maintained half of `build_backends()`: driver, connection env var
/// and per-variant options (row_type, structs_only, etc.) for every project
/// this generator ships. This data cannot come from the manifests directory —
/// a manifest declares only (name, language, engine), not which driver
/// crate/package exercises it or which one-off option combinations are worth
/// their own project — so it stays a literal list.
///
/// What *is* derived, in `build_backends()` below, is completeness: every
/// manifest under `crates/scythe-codegen/manifests` must be reachable from
/// this list (resolved through the real backend resolver, not a re-derived
/// fallback table) or be named in `coverage-exemptions.txt`. That is what
/// keeps a new backend from shipping a manifest with no project (issue #134).
fn backend_variants() -> Vec<BackendConfig> {
    vec![
        BackendConfig {
            name: "rust-sqlx".into(),
            language: "rust".into(),
            engine: "postgresql".into(),
            driver: "sqlx".into(),
            connection_env: "DATABASE_URL".into(),
            backend: "rust-sqlx".into(),
            options: HashMap::new(),
        },
        BackendConfig {
            name: "rust-tokio-postgres".into(),
            language: "rust".into(),
            engine: "postgresql".into(),
            driver: "tokio-postgres".into(),
            connection_env: "DATABASE_URL".into(),
            backend: "rust-tokio-postgres".into(),
            options: HashMap::new(),
        },
    ]
}

/// The `[backend]` fields this generator needs out of a manifest TOML file.
/// Mirrors `ManifestBackend` in
/// `tools/integration-test-generator/tests/coverage_completeness.rs` — kept
/// as a separate, minimal struct (rather than depending on
/// `scythe_backend::manifest::BackendManifest`) because this is the disk-read
/// half of the check, not the resolved half; the resolved half goes through
/// `get_backend` instead, below.
#[derive(Debug, Deserialize)]
struct ManifestFile {
    backend: ManifestBackendMeta,
}

#[derive(Debug, Deserialize)]
struct ManifestBackendMeta {
    name: String,
    engine: String,
}

/// Every manifest that ships, keyed by the (name, engine) pair the backend
/// resolver uses. This is the disk-derived side of the completeness check:
/// `build_backends()` cannot ship a project for a manifest this function does
/// not find.
fn discover_manifest_pairs(manifests_dir: &Path) -> BTreeSet<(String, String)> {
    let entries =
        fs::read_dir(manifests_dir).unwrap_or_else(|err| panic!("reading {}: {err}", manifests_dir.display()));
    let mut pairs = BTreeSet::new();
    for entry in entries {
        let path = entry
            .unwrap_or_else(|err| panic!("reading manifest entry: {err}"))
            .path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        let contents = fs::read_to_string(&path).unwrap_or_else(|err| panic!("reading {}: {err}", path.display()));
        let parsed: ManifestFile =
            toml::from_str(&contents).unwrap_or_else(|err| panic!("parsing manifest {}: {err}", path.display()));
        pairs.insert((parsed.backend.name, parsed.backend.engine));
    }
    assert!(
        !pairs.is_empty(),
        "no manifests found under {}",
        manifests_dir.display()
    );
    pairs
}

/// Parses the `[manifests]` section of `coverage-exemptions.txt`: lines
/// shaped `<name>|<engine> : <reason>`. Deliberately reads the same file
/// `tests/coverage_completeness.rs` reads (rather than a second, generator-only
/// opt-out list), because both are asserting the same fact — a manifest with
/// no project — and two allowlists for one fact is exactly the drift issue
/// #134 exists to close.
fn load_manifest_exemptions(exemptions_path: &Path) -> HashMap<String, String> {
    let contents = fs::read_to_string(exemptions_path)
        .unwrap_or_else(|err| panic!("reading {}: {err}", exemptions_path.display()));
    let mut in_section = false;
    let mut entries = HashMap::new();
    for raw in contents.lines() {
        let line = raw.trim();
        if let Some(header) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            in_section = header == "manifests";
            continue;
        }
        if line.is_empty() || line.starts_with('#') || !in_section {
            continue;
        }
        let Some((key, reason)) = line.split_once(':') else {
            panic!("exemption line in [manifests] is not '<key> : <reason>': {line}");
        };
        let (key, reason) = (key.trim().to_string(), reason.trim().to_string());
        assert!(!reason.is_empty(), "exemption '{key}' in [manifests] has no reason");
        entries.insert(key, reason);
    }
    entries
}

/// Integration projects kept by hand outside `backend_variants()` (their
/// scaffolding is not rendered from the templates), as `(backend, engine)`.
/// Their committed `sqlkit.toml` still exercises the manifest, which
/// `tests/coverage_completeness.rs` counts, so the build-time check counts it
/// too instead of demanding an exemption that test would call stale.
const HAND_MAINTAINED_BACKENDS: &[(&str, &str)] = &[("typescript-bun", "postgresql")];

/// Cross-checks `backend_variants()` against the manifests directory and
/// `coverage-exemptions.txt`, failing the build in both directions — a
/// manifest with no covering variant and no exemption, or an exemption whose
/// manifest is covered now — the usual stale-entry ratchet. See `backend_variants()`'s doc comment for why the entries
/// themselves cannot be generated from the manifest directly.
fn validate_manifest_coverage(variants: &[BackendConfig], manifests_dir: &Path, exemptions_path: &Path) {
    let shipped = discover_manifest_pairs(manifests_dir);

    // A variant names the (backend, engine) it *asks* for, but the resolver
    // can answer with a manifest declared under a different engine. So coverage is whatever the real
    // resolver reaches, not a literal pair match -- re-deriving that
    // fallback table here would reintroduce the "two derivations, never
    // cross-checked" shape this check exists to kill.
    let mut covered: BTreeSet<(String, String)> = BTreeSet::new();
    for variant in variants {
        let backend = get_backend(&variant.backend, &variant.engine).unwrap_or_else(|err| {
            panic!(
                "backend_variants() entry '{}' requests backend '{}' on engine '{}', which does not \
                 resolve to any manifest: {err}",
                variant.name, variant.backend, variant.engine
            )
        });
        let meta = &backend.manifest().backend;
        covered.insert((meta.name.clone(), meta.engine.clone()));
    }
    for (backend, engine) in HAND_MAINTAINED_BACKENDS {
        let backend = get_backend(backend, engine)
            .unwrap_or_else(|err| panic!("hand-maintained backend '{backend}' on '{engine}' does not resolve: {err}"));
        let meta = &backend.manifest().backend;
        covered.insert((meta.name.clone(), meta.engine.clone()));
    }

    let exemptions = load_manifest_exemptions(exemptions_path);
    let mut failures = Vec::new();

    for (name, engine) in shipped.difference(&covered) {
        let key = format!("{name}|{engine}");
        if !exemptions.contains_key(&key) {
            failures.push(format!(
                "manifest '{name}' (engine '{engine}') has no entry in backend_variants() and no \
                 exemption in {}",
                exemptions_path.display()
            ));
        }
    }
    for key in exemptions.keys() {
        let Some((name, engine)) = key.split_once('|') else {
            failures.push(format!(
                "malformed exemption key '{key}' in {}",
                exemptions_path.display()
            ));
            continue;
        };
        if covered.contains(&(name.to_string(), engine.to_string())) {
            failures.push(format!(
                "exemption '{key}' in {} is stale -- it is covered now, delete the line",
                exemptions_path.display()
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "manifest coverage check failed:\n{}",
        failures.iter().map(|f| format!("  {f}")).collect::<Vec<_>>().join("\n")
    );
}

/// Repo root, derived from the compiled-in manifest dir rather than the
/// process's current directory, so the coverage check below is correct
/// regardless of where the binary is invoked from.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate is two levels below the repo root")
        .to_path_buf()
}

/// The list `main()` actually uses: `backend_variants()`, validated against
/// `crates/scythe-codegen/manifests` and `coverage-exemptions.txt` so a
/// manifest can never ship silently uncovered (issue #134).
fn build_backends() -> Vec<BackendConfig> {
    let variants = backend_variants();
    let root = repo_root();
    validate_manifest_coverage(
        &variants,
        &root.join("crates/scythe-codegen/manifests"),
        &root.join("tools/integration-test-generator/coverage-exemptions.txt"),
    );
    variants
}

fn load_templates(env: &mut Environment<'_>, templates_dir: &Path) -> Result<(), String> {
    if !templates_dir.is_dir() {
        return Err(format!(
            "templates directory does not exist: {}",
            templates_dir.display()
        ));
    }

    let entries = fs::read_dir(templates_dir).map_err(|err| format!("reading templates dir: {err}"))?;

    for entry in entries {
        let entry = entry.map_err(|err| format!("reading template entry: {err}"))?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("jinja") {
            let name = path
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| format!("invalid template filename: {}", path.display()))?
                .to_string();
            let content =
                fs::read_to_string(&path).map_err(|err| format!("reading template {}: {err}", path.display()))?;
            env.add_template_owned(name, content)
                .map_err(|err| format!("parsing template {}: {err}", path.display()))?;
        }
    }

    Ok(())
}

fn render_template(env: &Environment<'_>, template_name: &str, context: &TemplateContext) -> Result<String, String> {
    let tmpl = env
        .get_template(template_name)
        .map_err(|err| format!("template '{template_name}' not found: {err}"))?;
    // ~keep minijinja 3 removed the blanket `impl From<&T: Serialize> for Value`;
    // ~keep serializable data now goes through the `value::Serde` wrapper.
    let mut output = tmpl
        .render(minijinja::value::Serde(context))
        .map_err(|err| format!("rendering '{template_name}': {err}"))?;
    if !output.ends_with('\n') {
        output.push('\n');
    }
    Ok(output)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let backends = build_backends();

    if cli.list {
        for backend in &backends {
            if !cli.only.is_empty() && !cli.only.contains(&backend.name) {
                continue;
            }
            println!("{}", backend.name);
        }
        return Ok(());
    }

    let mut env = Environment::new();
    load_templates(&mut env, &cli.templates)?;

    let mut generated = 0u32;
    let mut skipped = 0u32;

    for backend in &backends {
        if !cli.only.is_empty() && !cli.only.contains(&backend.name) {
            continue;
        }

        let output_dir = cli.output.join(&backend.name);
        if cli.skip_existing && output_dir.exists() {
            eprintln!("skip (exists): {}", backend.name);
            skipped += 1;
            continue;
        }

        let outputs = language_outputs(&backend.language);
        let context = TemplateContext::from(backend);

        if env.get_template(&outputs.test_template).is_err() {
            eprintln!(
                "warning: skipping {} — template '{}' not found",
                backend.name, outputs.test_template
            );
            skipped += 1;
            continue;
        }

        fs::create_dir_all(&output_dir)?;

        let scythe_toml = render_template(&env, "sqlkit.toml.jinja", &context)?;
        fs::write(output_dir.join("sqlkit.toml"), scythe_toml)?;

        let test_path = output_dir.join(outputs.test_filename);
        if let Some(parent) = test_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let test_content = render_template(&env, &outputs.test_template, &context)?;
        fs::write(&test_path, test_content)?;

        if env.get_template(&outputs.dep_template).is_ok() {
            let dep_content = render_template(&env, &outputs.dep_template, &context)?;
            fs::write(output_dir.join(outputs.dep_filename), dep_content)?;
        }

        for (tmpl, filename) in &outputs.extra {
            if env.get_template(tmpl).is_ok() {
                let content = render_template(&env, tmpl, &context)?;
                if content.trim().is_empty() {
                    continue;
                }
                let extra_path = output_dir.join(filename);
                if let Some(parent) = extra_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(extra_path, content)?;
            }
        }

        println!("generated: {}", backend.name);
        generated += 1;
    }

    println!(
        "\ndone: {generated} generated, {skipped} skipped, {} total backends",
        backends.len()
    );

    Ok(())
}
