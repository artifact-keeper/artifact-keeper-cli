//! E2E tests for `ak doctor`.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use predicates::prelude::*;

/// The backend under test is the pinned version or the previous minor, and ak
/// supports both.
#[test]
#[ignore = "requires E2E backend"]
fn doctor_reports_supported_server_version() {
    let env = common::TestEnv::setup();

    env.ak_cmd()
        .arg("doctor")
        .assert()
        .success()
        .stderr(predicate::str::contains(format!(
            "server version {}",
            common::server_version()
        )))
        .stderr(predicate::str::contains("unsupported").not())
        .stderr(predicate::str::contains("upgrade ak").not());
}
