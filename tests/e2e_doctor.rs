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

#[test]
#[ignore = "requires E2E backend"]
fn doctor_reports_as_json_and_passes_on_a_working_instance() {
    let env = common::TestEnv::setup();
    let output = env.ak_cmd().arg("doctor").output().unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ok"], true, "{report}");
    assert_eq!(report["failures"], 0, "{report}");
}
