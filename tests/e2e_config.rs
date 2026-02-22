//! E2E tests for `ak config` commands.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use predicates::prelude::*;

#[test]
#[ignore = "requires E2E backend"]
fn config_list() {
    let env = common::TestEnv::setup();
    env.ak_cmd_table()
        .args(["config", "list"])
        .assert()
        .success();
}

#[test]
#[ignore = "requires E2E backend"]
fn config_path() {
    let env = common::TestEnv::setup();
    env.ak_cmd_table()
        .args(["config", "path"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}
