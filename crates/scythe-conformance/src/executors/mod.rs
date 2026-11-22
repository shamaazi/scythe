//! Per-engine live drivers, each behind its own Cargo feature so
//! `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`
//! never link a database driver by default. See [`crate::runner`] for how
//! these are dispatched -- [`crate::executor::Executor`] is not
//! dyn-compatible, so callers select a concrete type per engine rather than
//! holding these behind a trait object.

#[cfg(feature = "pg")]
pub mod postgres;

/// A namespace name (a PostgreSQL schema) unique to this call, for an executor to isolate itself into.
///
/// It must be unique per *connection*, not per process. `run_one_leg`
/// connects once per (fixture, engine), and the test binary runs its
/// `#[tokio::test]`s in parallel by default -- so a fixed name meant two
/// concurrent tests issued `DROP ... IF EXISTS` / `CREATE ...` against the
/// same namespace and dropped it out from under each other mid-run. That
/// surfaced as an opaque "preparing an isolated schema: db error", and
/// would have failed every live run.
///
/// The process id keeps concurrent `cargo test` invocations (and leftovers
/// from an earlier crashed run) from colliding; the counter separates
/// connections within one process. Digits only, so the result is always a
/// safe SQL identifier.
///
/// Namespaces are not dropped at the end of a run: there is no async
/// `Drop`, and test databases are usually discarded wholesale. A developer
/// pointing this at a long-lived database will accumulate
/// `scythe_conformance_*` namespaces and can drop them by prefix.
#[cfg(feature = "pg")]
pub(crate) fn unique_namespace() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("scythe_conformance_{}_{}", std::process::id(), n)
}
