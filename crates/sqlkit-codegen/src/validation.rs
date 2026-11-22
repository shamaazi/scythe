use std::process::Command;

/// Validate generated code structurally for a given backend.
/// Returns a list of errors (empty = passed).
pub fn validate_structural(code: &str, backend_name: &str) -> Vec<String> {
    match backend_name {
        "typescript-bun" => validate_typescript(code),
        "rust-sqlx" | "rust-tokio-postgres" => vec![],
        _ => vec![format!("unknown backend: {}", backend_name)],
    }
}

fn validate_typescript(code: &str) -> Vec<String> {
    let mut errors = Vec::new();

    let has_function = code.contains("export async function") || code.contains("export function");

    let has_zod = code.contains("z.object(") || code.contains("z.infer<");
    if !code.contains("export interface") && !code.contains("export type") && !has_zod && !has_function {
        errors.push("missing `export interface` or `export type` (for DTOs)".into());
    }

    if !has_function {
        errors.push("missing `export async function` or `export function`".into());
    }

    for line in code.lines() {
        let trimmed = line.trim();
        if find_disallowed_any_usage(trimmed).is_some() {
            errors.push(format!(
                "contains `any` type (should use `unknown` or specific): {}",
                trimmed
            ));
            break;
        }
    }

    errors
}

/// Scan a line of generated TypeScript for a standalone `any` type token.
///
/// This is token-aware (matches `any` at identifier boundaries) rather than
/// the previous fixed set of punctuation suffixes (`: any`, `<any>`, `any;`,
/// `any,`, `any)`), which happened to omit `any>`.
fn find_disallowed_any_usage(trimmed: &str) -> Option<&str> {
    let mut offset = 0;
    while let Some(rel) = trimmed[offset..].find("any") {
        let start = offset + rel;
        let end = start + "any".len();
        let before_is_ident = start > 0 && is_ident_byte(trimmed.as_bytes()[start - 1]);
        let after_is_ident = end < trimmed.len() && is_ident_byte(trimmed.as_bytes()[end]);
        if !before_is_ident && !after_is_ident {
            return Some(trimmed);
        }
        offset = end;
    }
    None
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Environment variable that turns on strict tool validation.
///
/// Set to `1` (or `true`) to make a missing tool a hard failure instead of a
/// skip. CI sets it after installing every checker; a developer's laptop
/// leaves it unset and still gets whatever checkers they happen to have.
pub const STRICT_ENV_VAR: &str = "SQLKIT_VALIDATE_STRICT";

/// Whether strict mode is on, read from [`STRICT_ENV_VAR`].
///
/// Deliberately an environment variable rather than a separate
/// `validate_with_tools_strict` entry point. The call sites that matter are
/// the generated-code assertions in `tests/tool_validation.rs`, and the
/// property we want is "CI checks every language, a laptop checks what it
/// can" -- with a second entry point every one of those call sites would have
/// to branch on the environment itself, which is precisely the per-call-site
/// policy decision that let the original `None`-is-a-pass bug spread to nine
/// places. One switch, read in one function, cannot drift.
pub fn strict_mode_enabled() -> bool {
    matches!(
        std::env::var(STRICT_ENV_VAR).as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE")
    )
}

/// What happened when one external checker was pointed at a generated file.
///
/// The distinction between these variants is the whole point of this type.
/// `Ran { errors: [] }` means a real tool inspected the code and found
/// nothing wrong; `Missing` means nothing was inspected at all. Collapsing
/// the two -- which is what returning `Option<Vec<String>>` did, since both
/// arrived at the call site as "no errors to report" -- turns an uninstalled
/// linter into a green check mark.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolOutcome {
    /// The tool was found and ran to completion. An empty `errors` genuinely
    /// means this checker is satisfied.
    Ran {
        /// Executable name, as it would be typed on a command line.
        tool: &'static str,
        /// Findings, already prefixed with the tool name.
        errors: Vec<String>,
    },
    /// The tool is not on `PATH`, so whatever it would have caught went
    /// unchecked. Never an error outside strict mode, never a pass inside it.
    Missing {
        /// Executable name that was looked for and not found.
        tool: &'static str,
    },
    /// The tool is installed but the harness could not run it -- a temp file
    /// that would not write, a process that would not spawn.
    ///
    /// This is neither a pass nor a skip: it is always an error, strict mode
    /// or not. The previous implementation reached these paths through `?` on
    /// an `Option` and returned `None`, i.e. reported a broken harness as an
    /// uninstalled tool, which then read as a pass.
    Failed {
        /// Executable name the harness was trying to drive.
        tool: &'static str,
        /// What went wrong, in the harness rather than in the checked code.
        reason: String,
    },
}

/// Every checker's verdict for one generated file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolValidation {
    /// No tool-based validator exists for this backend's language.
    ///
    /// Distinct from "the tools are missing": Rust has no validator written
    /// for it at all, and reporting that as a skip
    /// would suggest installing something would help.
    Unsupported,
    /// A validator exists; one entry per checker it tried to run.
    Attempted(Vec<ToolOutcome>),
}

impl ToolValidation {
    /// Findings from the checkers that actually ran.
    pub fn errors(&self) -> Vec<&str> {
        match self {
            Self::Unsupported => vec![],
            Self::Attempted(outcomes) => outcomes
                .iter()
                .flat_map(|outcome| match outcome {
                    ToolOutcome::Ran { errors, .. } => errors.iter().map(String::as_str).collect::<Vec<_>>(),
                    ToolOutcome::Missing { .. } => vec![],
                    ToolOutcome::Failed { reason, .. } => vec![reason.as_str()],
                })
                .collect(),
        }
    }

    /// Checkers that were not installed.
    pub fn missing_tools(&self) -> Vec<&'static str> {
        match self {
            Self::Unsupported => vec![],
            Self::Attempted(outcomes) => outcomes
                .iter()
                .filter_map(|outcome| match outcome {
                    ToolOutcome::Missing { tool } => Some(*tool),
                    _ => None,
                })
                .collect(),
        }
    }

    /// Checkers that ran to completion.
    pub fn tools_run(&self) -> Vec<&'static str> {
        match self {
            Self::Unsupported => vec![],
            Self::Attempted(outcomes) => outcomes
                .iter()
                .filter_map(|outcome| match outcome {
                    ToolOutcome::Ran { tool, .. } => Some(*tool),
                    _ => None,
                })
                .collect(),
        }
    }

    /// Whether every checker this validator knows about actually ran.
    ///
    /// False for [`Self::Unsupported`]: nothing checked the code, so claiming
    /// it was fully checked would be the same lie in a different shape.
    pub fn fully_checked(&self) -> bool {
        match self {
            Self::Unsupported => false,
            Self::Attempted(outcomes) => {
                !outcomes.is_empty()
                    && outcomes
                        .iter()
                        .all(|outcome| matches!(outcome, ToolOutcome::Ran { .. }))
            }
        }
    }

    /// Collapse to pass/fail under the current [`strict_mode_enabled`] policy.
    ///
    /// Outside strict mode a missing tool is tolerated. Inside it, a missing
    /// tool is a failure -- that is what stops a checker from quietly falling
    /// out of CI and taking its coverage with it.
    pub fn into_result(self) -> Result<(), Vec<String>> {
        self.into_result_with_strictness(strict_mode_enabled())
    }

    /// [`Self::into_result`] with the policy passed explicitly, so tests can
    /// exercise both modes without mutating process-global environment state
    /// (which races under `cargo test`'s thread-per-test execution).
    ///
    /// [`Self::Unsupported`] is deliberately **not** a strict-mode failure.
    /// Strict mode exists to catch a checker that fell out of the CI image,
    /// and every one of its failures should be fixable by installing
    /// something. A language with no validator written for it (Rust) is a real gap,
    /// but installing a tool does not close it, so failing here would leave a permanently red build with no
    /// action attached. That gap is tracked by an explicit inventory test
    /// (`backends_with_no_tool_validator_are_a_known_and_shrinking_set` in
    /// `tests/tool_validation.rs`) which fails when the set changes in either
    /// direction, rather than by a signal nobody can act on.
    pub fn into_result_with_strictness(self, strict: bool) -> Result<(), Vec<String>> {
        let mut failures: Vec<String> = self.errors().into_iter().map(str::to_string).collect();

        if strict {
            for tool in self.missing_tools() {
                failures.push(format!(
                    "strict validation: `{tool}` is not installed, so nothing it checks was verified"
                ));
            }
        }

        if failures.is_empty() { Ok(()) } else { Err(failures) }
    }
}

/// A generated source file written to a temporary path, removed on drop.
///
/// `Drop` rather than a trailing `remove_file` call: every validator below
/// has early-return paths, and the previous hand-rolled cleanup was skipped
/// on all of them, leaking a temp file per failed validation.
struct TempSource {
    path: std::path::PathBuf,
}

impl TempSource {
    fn new(tool: &'static str, code: &str, ext: &str) -> Result<Self, ToolOutcome> {
        write_temp(code, ext)
            .map(|path| Self { path })
            .ok_or_else(|| ToolOutcome::Failed {
                tool,
                reason: format!("{tool}: could not write a temporary `{ext}` file"),
            })
    }

    fn arg(&self, tool: &'static str) -> Result<&str, ToolOutcome> {
        self.path.to_str().ok_or_else(|| ToolOutcome::Failed {
            tool,
            reason: format!("{tool}: temporary file path is not valid UTF-8"),
        })
    }
}

impl Drop for TempSource {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Whether `tool` is on `PATH`, probed by running it with `probe_arg`.
fn tool_present(tool: &str, probe_arg: &str) -> bool {
    Command::new(tool).arg(probe_arg).output().is_ok()
}

/// Run `tool` with `args` and turn a non-zero exit into findings, read from
/// stdout and stderr concatenated (`poly` splits its report across the two).
///
/// `max_lines` caps how much of the diagnostic output is kept; a syntax error
/// can produce hundreds of cascading lines and only the first few locate it.
fn run_tool(tool: &'static str, args: &[&str], max_lines: usize) -> Result<Vec<String>, ToolOutcome> {
    let output = Command::new(tool)
        .args(args)
        .output()
        .map_err(|error| ToolOutcome::Failed {
            tool,
            reason: format!("{tool}: could not be executed: {error}"),
        })?;

    if output.status.success() {
        return Ok(vec![]);
    }

    let raw = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    Ok(raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .take(max_lines)
        .map(|line| format!("{tool}: {line}"))
        .collect())
}

/// Run one checker end to end: probe, write the source, execute, collect.
fn check_with(
    tool: &'static str,
    probe_arg: &str,
    code: &str,
    ext: &str,
    build_args: impl Fn(&str) -> Vec<String>,
    max_lines: usize,
) -> ToolOutcome {
    if !tool_present(tool, probe_arg) {
        return ToolOutcome::Missing { tool };
    }

    let source = match TempSource::new(tool, code, ext) {
        Ok(source) => source,
        Err(outcome) => return outcome,
    };
    let path = match source.arg(tool) {
        Ok(path) => path,
        Err(outcome) => return outcome,
    };

    let args = build_args(path);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();

    match run_tool(tool, &args, max_lines) {
        Ok(errors) => ToolOutcome::Ran { tool, errors },
        Err(outcome) => outcome,
    }
}

/// Validate generated code with the real compilers and linters for its
/// language.
///
/// Returns [`ToolValidation::Unsupported`] when no validator exists for the
/// backend's language, and a per-tool [`ToolOutcome`] list otherwise. Callers
/// must not treat "no errors" as "checked" without consulting
/// [`ToolValidation::fully_checked`] or [`ToolValidation::into_result`] --
/// see [`ToolOutcome`] for why.
pub fn validate_with_tools(code: &str, backend_name: &str) -> ToolValidation {
    let outcomes = match backend_name {
        name if name.starts_with("typescript") => validate_typescript_tools(code),
        // Rust: `rust-sqlx` expands `sqlx::query_as!`/`sqlx::query!` at
        // compile time, which needs either a live database connection or an
        // `SQLX_OFFLINE` `.sqlx` query cache -- there is no way to satisfy
        // that from a bare generated file. `rust-tokio-postgres`
        // references its driver crate by
        // fully-qualified path (`tokio_postgres::Row`, etc.) with no `use`
        // to stub around; making `rustc --emit=metadata` resolve them needs
        // `--extern` pointing at real compiled `.rlib`s, i.e. standing up a
        // full Cargo dependency graph per backend -- disproportionate to a
        // single-file lightweight check when every one of these backends'
        // generated code is already syntax-checked by `syn::parse_file` in
        // `crates/sqlkit-cli/tests/compile_check.rs` and the generated test
        // suite.
        _ => return ToolValidation::Unsupported,
    };

    ToolValidation::Attempted(outcomes)
}

/// A validation result for one backend's generated output, shaped for a
/// caller (the CLI, in particular) to report directly to a user rather than
/// for a test assertion to pick apart.
///
/// Three variants, not two, on purpose: collapsing [`Self::Unsupported`] into
/// [`Self::Passed`] is the exact dishonesty [`ToolValidation`] exists to
/// prevent -- see that type's doc comment. A caller that only distinguished
/// pass from fail would report "OK" for a Rust file that no compiler
/// ever looked at, which is the bug this whole module was written to
/// close.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationOutcome {
    /// No tool-based validator exists for this backend's language at all
    /// (see [`ToolValidation::Unsupported`]). Not a pass and not a failure --
    /// report it as "not checked", never as "checked, no problems".
    Unsupported,
    /// A validator exists and every checker that ran found nothing wrong.
    ///
    /// `tools_run` names the checkers that actually inspected the code;
    /// `tools_missing` names any this validator would also have liked to run
    /// but could not find on `PATH`. Both are carried through rather than
    /// collapsed, because "passed, nothing was installed to check it"
    /// (`tools_run` empty) and "passed, `poly` verified it" are different
    /// claims a caller may want to report differently even though neither is
    /// a build failure under the default, non-strict policy this is built
    /// on (see [`ToolValidation::into_result_with_strictness`]).
    Passed {
        /// Checkers that ran to completion and found nothing wrong.
        tools_run: Vec<&'static str>,
        /// Checkers this validator wanted to run but could not find.
        tools_missing: Vec<&'static str>,
    },
    /// A checker found a problem with the generated code, or the harness
    /// itself could not drive an installed tool. Never produced by a
    /// merely-missing tool -- see [`ToolOutcome::Missing`] vs.
    /// [`ToolOutcome::Failed`], which is exactly the distinction that keeps
    /// an uninstalled linter from reading as a build failure here.
    Failed {
        /// Checkers that ran to completion (regardless of whether they were
        /// the one that reported a problem).
        tools_run: Vec<&'static str>,
        /// Checkers this validator wanted to run but could not find.
        tools_missing: Vec<&'static str>,
        /// Findings, already prefixed with the tool name that reported each
        /// one -- see [`ToolValidation::errors`].
        errors: Vec<String>,
    },
}

impl ValidationOutcome {
    /// Whether this outcome should stop a build: `true` only for
    /// [`Self::Failed`].
    ///
    /// Both [`Self::Unsupported`] and [`Self::Passed`] are "let it through"
    /// outcomes under the default policy -- a caller that wants "no
    /// validator for this language" to also block a build (unusual: it would
    /// stop every Rust backend from ever generating) must match on the variant itself rather than use
    /// this helper.
    #[must_use]
    pub fn is_failure(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }
}

/// Validate one backend's generated output with the real compilers and
/// linters for its target language, collapsed to the three outcomes a
/// caller needs to decide what to print and whether to fail a build.
///
/// This is [`validate_with_tools`] built on top of, not reimplemented: the
/// pass/fail split follows the same non-strict policy as
/// [`ToolValidation::into_result`] outside [`STRICT_ENV_VAR`] -- a tool that
/// is not installed is tolerated, never a build failure. Keeping the collapse
/// here, delegating to [`ToolValidation::into_result_with_strictness`] rather
/// than re-deriving "missing is fine, a real finding is not" a second time,
/// is what keeps that policy defined in exactly one place; see the doc
/// comment on [`ToolValidation::into_result_with_strictness`] for why
/// [`ValidationOutcome::Unsupported`] is exempt from strictness entirely
/// rather than becoming a fourth, stricter failure case.
///
/// # This shells out to real external tools
///
/// `poly`, `tsc` and `node`, depending on `backend_name` -- see [`validate_with_tools`]'s match
/// arms. When a tool is not installed, probing for it
/// (`Command::new(tool).arg(probe_arg).output()`) fails fast: the OS reports
/// "no such file" as soon as it tries to spawn the process, so an absent
/// tool costs microseconds and never blocks. The cost that matters is the
/// opposite case -- a tool that *is* installed. `tsc --checkJs --strict`
/// runs a full TypeScript typecheck. A caller that
/// invokes this unconditionally on every `sqlkit generate` would make every
/// run pay that cost for every backend the file targets, on any machine that
/// happens to have the tool installed -- and would silently validate less on
/// a machine that doesn't, with no way for the user to tell which happened
/// short of reading [`ValidationOutcome::Passed`]'s `tools_run`/
/// `tools_missing` fields. **Callers should gate this behind an explicit
/// opt-in (e.g. a `--verify` flag), not run it unconditionally on every
/// generate.**
#[must_use]
pub fn validate_generated_code(code: &str, backend_name: &str) -> ValidationOutcome {
    let validation = validate_with_tools(code, backend_name);
    if matches!(validation, ToolValidation::Unsupported) {
        return ValidationOutcome::Unsupported;
    }

    let tools_run = validation.tools_run();
    let tools_missing = validation.missing_tools();

    match validation.into_result_with_strictness(false) {
        Ok(()) => ValidationOutcome::Passed {
            tools_run,
            tools_missing,
        },
        Err(errors) => ValidationOutcome::Failed {
            tools_run,
            tools_missing,
            errors,
        },
    }
}

fn write_temp(code: &str, ext: &str) -> Option<std::path::PathBuf> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let basename = format!("sqlkit_validate_{n}");
    let path = std::env::temp_dir().join(format!("{basename}{ext}"));
    let trimmed = format!("{}\n", code.trim_end());
    std::fs::write(&path, trimmed).ok()?;
    Some(path)
}

/// Run `poly` against a generated file.
///
/// `poly` is this repository's linter and formatter, and it bundles the
/// engines it needs in-process (`oxc` for JavaScript and TypeScript), so it
/// replaces a separately-installed linter such as `biome`.
///
/// `--no-workspace` is not optional. Without it `poly lint` also runs the
/// whole-project tier -- `cargo clippy` over this very workspace -- once per
/// generated file, turning a millisecond check into minutes.
///
/// `poly` exits non-zero only on error-severity findings, so warnings appear
/// in the message without failing the check. That is the same threshold the
/// repository's own `poly lint .` gate uses.
fn poly_check(code: &str, ext: &str) -> ToolOutcome {
    let config = generated_code_poly_config();
    check_with(
        "poly",
        "--version",
        code,
        ext,
        |path| {
            ["lint", "--no-workspace", "--config", &config.to_string_lossy(), path]
                .iter()
                .map(|arg| (*arg).to_string())
                .collect()
        },
        6,
    )
}

/// Path to the poly config used for generated code.
///
/// Passed explicitly rather than left to discovery: poly resolves config by
/// walking up from the file it is given, and the file here is a temporary one
/// outside the repository, so poly would find nothing and fall back to its
/// built-in defaults. What CI enforced would then depend on where the system
/// temp directory happens to sit. See the config file's own header for why it
/// differs from the repository's `poly.toml`.
fn generated_code_poly_config() -> std::path::PathBuf {
    std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/generated-code-poly.toml")).to_path_buf()
}

/// `poly`'s bundled `oxc`.
///
/// This was `biome check` until #98 installed biome and discovered the choice
/// had never been tested: `check` also runs the formatter, whose only
/// complaints about generated code are that sqlkit indents with spaces where
/// biome would use tabs, and where it would break a line. Generated-code
/// layout is the backends' contract and `sqlkit fmt` owns it, so running the
/// formatter here failed 8 TypeScript backends purely on indentation.
///
/// `poly` lints with `oxc` and does not impose a formatter, so it keeps what
/// is worth knowing -- unused bindings, unsafe casts, `useLiteralKeys` and the
/// rest of the correctness rules -- and drops a third-party install entirely.
fn validate_typescript_tools(code: &str) -> Vec<ToolOutcome> {
    vec![poly_check(code, ".ts")]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unknown_backend() {
        let errors = validate_structural("some code", "unknown-backend");
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("unknown backend"));
    }

    #[test]
    fn test_rust_backends_skip() {
        assert!(validate_structural("anything", "rust-sqlx").is_empty());
        assert!(validate_structural("anything", "rust-tokio-postgres").is_empty());
    }

    #[test]
    fn test_typescript_valid() {
        let code = r#"export interface ListUsersRow {
  id: number;
  name: string;
}

export async function listUsers(): Promise<ListUsersRow[]> {
  // ...
}
"#;
        let errors = validate_structural(code, "typescript-bun");
        assert!(errors.is_empty(), "expected no errors, got: {:?}", errors);
    }

    #[test]
    fn test_typescript_rejects_any_before_closing_angle_bracket() {
        // Regression test: the old suffix-list check (`: any`, `<any>`,
        // `any;`, `any,`, `any)`) never looked for `any` immediately before
        // `>`, so `Array<any>` (or any other `any>` usage)
        // slipped through undetected.
        let code = r#"export async function listUsers(): Promise<Array<any>> {
  return [];
}
"#;
        let errors = validate_structural(code, "typescript-bun");
        assert!(
            errors.iter().any(|e| e.contains("any")),
            "expected an `any` violation, got: {:?}",
            errors
        );
    }

    /// The bug this whole type exists to prevent: before `ToolValidation`,
    /// a tool that was never installed and a tool that ran and found nothing
    /// both arrived at the call site as "no errors", so an uninstalled linter
    /// read as a green check mark.
    #[test]
    fn a_missing_tool_is_not_the_same_as_a_clean_run() {
        let clean = ToolValidation::Attempted(vec![ToolOutcome::Ran {
            tool: "tsc",
            errors: vec![],
        }]);
        let absent = ToolValidation::Attempted(vec![ToolOutcome::Missing { tool: "tsc" }]);

        // Both report zero findings -- that is exactly why the old
        // `Option<Vec<String>>` could not tell them apart.
        assert!(clean.errors().is_empty());
        assert!(absent.errors().is_empty());

        // The type still distinguishes them.
        assert!(clean.fully_checked(), "a tool that ran is a real check");
        assert!(!absent.fully_checked(), "a tool that never ran checked nothing");
        assert_eq!(absent.missing_tools(), vec!["tsc"]);
        assert!(clean.missing_tools().is_empty());
    }

    #[test]
    fn strict_mode_turns_a_missing_tool_into_a_failure() {
        let absent = ToolValidation::Attempted(vec![ToolOutcome::Missing { tool: "poly" }]);

        assert!(
            absent.clone().into_result_with_strictness(false).is_ok(),
            "outside strict mode a missing tool is tolerated"
        );

        let failures = absent
            .into_result_with_strictness(true)
            .expect_err("strict mode must fail on a missing tool");
        assert_eq!(failures.len(), 1);
        assert!(
            failures[0].contains("poly") && failures[0].contains("not installed"),
            "the failure must name the tool and say it never ran: {failures:?}"
        );
    }

    /// A validator that runs two tools and finds only one of them has
    /// verified half of what it claims to. `validate_python_tools` shipped
    /// exactly this shape -- `node` present, `tsc` absent, `Some([])`
    /// returned -- which is the strongest possible false signal.
    #[test]
    fn a_partially_run_validation_is_not_fully_checked() {
        let partial = ToolValidation::Attempted(vec![
            ToolOutcome::Ran {
                tool: "node",
                errors: vec![],
            },
            ToolOutcome::Missing { tool: "tsc" },
        ]);

        assert!(partial.errors().is_empty());
        assert!(!partial.fully_checked(), "one of two tools running is not a full check");
        assert_eq!(partial.tools_run(), vec!["node"]);
        assert_eq!(partial.missing_tools(), vec!["tsc"]);
        assert!(partial.into_result_with_strictness(true).is_err());
    }

    /// TypeScript is checked by `poly` alone -- one binary, no separate
    /// install. A regression that reintroduced a separate `biome` invocation
    /// would show up here as an extra outcome.
    #[test]
    fn poly_backed_typescript_reports_exactly_one_tool() {
        let outcomes = validate_typescript_tools("export const x = 1;\n");
        assert_eq!(outcomes.len(), 1, "typescript must be checked by poly alone");
        let tool = match &outcomes[0] {
            ToolOutcome::Ran { tool, .. } | ToolOutcome::Missing { tool } | ToolOutcome::Failed { tool, .. } => *tool,
        };
        assert_eq!(tool, "poly", "typescript must go through poly");
    }

    /// A language with no validator must not masquerade as a clean pass
    /// either -- `_ => None` previously made every unvalidated language
    /// unconditionally green. Rust has no single-file validator (see
    /// `validate_with_tools`), so it is what this test exercises.
    #[test]
    fn a_backend_with_no_validator_is_unsupported_not_clean() {
        let validation = validate_with_tools("pub struct Foo;", "rust-sqlx");

        assert_eq!(validation, ToolValidation::Unsupported);
        assert!(validation.errors().is_empty());
        assert!(!validation.fully_checked(), "no validator means nothing was checked");
        assert!(validation.clone().into_result_with_strictness(false).is_ok());
        assert!(
            validation.into_result_with_strictness(true).is_ok(),
            "strict mode is for tools that can be installed; a language with no \
             validator is tracked by an inventory test instead -- see \
             into_result_with_strictness"
        );
    }

    /// A harness that cannot run an installed tool is a failure in both
    /// modes. The old code reached these paths through `?` on an `Option`
    /// and reported them as "tool not installed", which then read as a pass.
    #[test]
    fn a_harness_failure_is_an_error_even_outside_strict_mode() {
        let broken = ToolValidation::Attempted(vec![ToolOutcome::Failed {
            tool: "node",
            reason: "node: could not be executed: permission denied".into(),
        }]);

        assert!(!broken.fully_checked());
        let failures = broken
            .into_result_with_strictness(false)
            .expect_err("a broken harness is never a pass");
        assert!(failures[0].contains("node"));
    }

    #[test]
    fn strict_mode_reads_the_documented_environment_variable() {
        // Guard: the constant and the docs must not drift apart.
        assert_eq!(STRICT_ENV_VAR, "SQLKIT_VALIDATE_STRICT");
    }
}
