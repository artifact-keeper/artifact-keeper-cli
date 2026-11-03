//! E2E tests for `ak doctor`.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use predicates::prelude::*;

/// The backend under test runs the pinned API version, so it must be supported.
#[test]
#[ignore = "requires E2E backend"]
fn doctor_reports_supported_server_version() {
    let env = common::TestEnv::setup();
    let pin = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/API_VERSION")).unwrap();

    env.ak_cmd()
        .arg("doctor")
        .assert()
        .success()
        .stderr(predicate::str::contains(format!(
            "server version {}",
            pin.trim()
        )))
        .stderr(predicate::str::contains("unsupported").not())
        .stderr(predicate::str::contains("upgrade ak").not());
}
