//! Live-database conformance test against PostgreSQL, gated by the `pg` feature. The whole
//! file is gated by `live-tests` -- without it, this compiles to an empty test binary rather
//! than running against a real database.
#![cfg(feature = "live-tests")]

use std::path::Path;

use sqlkit_conformance::{RunnerConfig, fixture, run};

fn testing_data_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testing_data/nullability_live")
}

fn load_fixtures_and_divergences() -> (Vec<fixture::LiveFixture>, Vec<sqlkit_conformance::DivergenceEntry>) {
    let root = testing_data_root();
    let schemas_root = root.join("_schemas");
    let fixtures = fixture::load_fixtures(&root, &schemas_root).expect("committed fixtures must load cleanly");
    let divergences_path = root.join("DIVERGENCES.toml");
    let divergences =
        sqlkit_conformance::divergence::load(&divergences_path).expect("committed DIVERGENCES.toml must load cleanly");
    (fixtures, divergences)
}

#[cfg(feature = "pg")]
#[tokio::test]
async fn postgres_is_sound() {
    let config = RunnerConfig::from_env(testing_data_root().join("_schemas"));
    assert!(
        config.postgres_url.is_some(),
        "SQLKIT_CONFORMANCE_POSTGRES_URL must be set to run the live suite"
    );
    let (fixtures, divergences) = load_fixtures_and_divergences();
    let report = run(&fixtures, &divergences, &config)
        .await
        .expect("run must not hard-error");
    println!("{}", report.summary());
    assert!(report.is_pass(), "{}", report.summary());
    assert!(
        !report.verdicts.is_empty(),
        "expected at least one fixture to actually run"
    );
}
