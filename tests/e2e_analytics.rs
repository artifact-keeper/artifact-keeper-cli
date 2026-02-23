//! E2E tests for `ak analytics` commands.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

#[test]
#[ignore = "requires E2E backend"]
fn analytics_downloads() {
    let env = common::TestEnv::setup();
    env.ak_cmd()
        .args(["analytics", "downloads"])
        .assert()
        .success();
}

#[test]
#[ignore = "requires E2E backend"]
fn analytics_storage() {
    let env = common::TestEnv::setup();
    env.ak_cmd()
        .args(["analytics", "storage"])
        .assert()
        .success();
}

#[test]
#[ignore = "requires E2E backend"]
fn analytics_growth() {
    let env = common::TestEnv::setup();
    env.ak_cmd()
        .args(["analytics", "growth"])
        .assert()
        .success();
}
