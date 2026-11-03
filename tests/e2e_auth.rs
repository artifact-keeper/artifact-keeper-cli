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

/// A failed assertion on a command prints the command, its environment and its
/// output, and in CI that goes to the log.
#[test]
#[ignore = "requires E2E backend"]
fn a_failing_command_does_not_print_the_token() {
    let env = common::TestEnv::setup();
    let mut cmd = env.ak_cmd();
    cmd.args(["repo", "show", "e2e-no-such-repository"]);

    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        cmd.assert().success();
    }))
    .expect_err("the command should fail");
    let printed = panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(ToString::to_string))
        .expect("a panic message");

    assert!(
        printed.contains("e2e-no-such-repository"),
        "this isn't the failure it should be"
    );
    assert!(!printed.contains(&env.token), "the token was printed");
}
