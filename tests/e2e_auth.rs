//! E2E tests for `ak auth` commands.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use predicates::prelude::*;

#[test]
#[ignore = "requires E2E backend"]
fn auth_whoami_json() {
    let env = common::TestEnv::setup();
    env.ak_cmd()
        .args(["auth", "whoami"])
        .assert()
        .success()
        .stdout(predicate::str::contains("admin"));
}

#[test]
#[ignore = "requires E2E backend"]
fn auth_whoami_table() {
    let env = common::TestEnv::setup();
    env.ak_cmd_table()
        .args(["auth", "whoami"])
        .assert()
        .success()
        .stdout(predicate::str::contains("admin"));
}

#[test]
#[ignore = "requires E2E backend"]
fn auth_token_list() {
    let env = common::TestEnv::setup();
    env.ak_cmd()
        .args(["auth", "token", "list"])
        .assert()
        .success();
}
