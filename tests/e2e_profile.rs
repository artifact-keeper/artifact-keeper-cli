//! E2E tests for `ak profile` commands.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use predicates::prelude::*;

#[test]
#[ignore = "requires E2E backend"]
fn profile_show() {
    let env = common::TestEnv::setup();
    env.ak_cmd()
        .args(["profile", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("admin"));
}
