//! Live-database conformance test against PostgreSQL, gated by the `pg` feature. The whole
//! file is gated by `live-tests` -- without it, this compiles to an empty test binary rather
//! than running against a real database.
#![cfg(feature = "live-tests")]

use std::path::Path;

use scythe_conformance::{Engine, RunnerConfig, fixture, run};

fn testing_data_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testing_data/nullability_live")
}

fn load_fixtures_and_divergences() -> (Vec<fixture::LiveFixture>, Vec<scythe_conformance::DivergenceEntry>) {
    let root = testing_data_root();
    let schemas_root = root.join("_schemas");
    let fixtures = fixture::load_fixtures(&root, &schemas_root).expect("committed fixtures must load cleanly");
    let divergences_path = root.join("DIVERGENCES.toml");
    let divergences =
        scythe_conformance::divergence::load(&divergences_path).expect("committed DIVERGENCES.toml must load cleanly");
    (fixtures, divergences)
}

#[cfg(feature = "pg")]
#[tokio::test]
async fn postgres_leg_is_sound() {
    let url = std::env::var("SCYTHE_CONFORMANCE_POSTGRES_URL")
        .expect("SCYTHE_CONFORMANCE_POSTGRES_URL must be set to run this leg");
    let (fixtures, divergences) = load_fixtures_and_divergences();
    let mut config = RunnerConfig::from_env(vec![Engine::Postgresql], testing_data_root().join("_schemas"));
    config.postgres_url = Some(url);
    let report = run(&fixtures, &divergences, &config)
        .await
        .expect("run must not hard-error");
    println!("{}", report.summary());
    assert!(report.is_pass(), "{}", report.summary());
    assert!(
        !report.verdicts.is_empty(),
        "expected at least one PostgreSQL leg to actually run"
    );
}
