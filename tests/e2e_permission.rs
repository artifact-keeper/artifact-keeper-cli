//! E2E tests for `ak permission` commands.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

#[test]
#[ignore = "requires E2E backend"]
fn permission_list() {
    let env = common::TestEnv::setup();
    env.ak_cmd()
        .args(["permission", "list"])
        .assert()
        .success();
}
