//! E2E tests for `ak scan` commands.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

#[test]
#[ignore = "requires E2E backend"]
fn scan_list() {
    let env = common::TestEnv::setup();
    env.ak_cmd()
        .args(["scan", "list"])
        .assert()
        .success();
}
