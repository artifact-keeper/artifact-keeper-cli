//! E2E tests for `ak label` commands.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use predicates::prelude::*;

#[test]
#[ignore = "requires E2E backend"]
fn label_repo_lifecycle() {
    let env = common::TestEnv::setup();

    // Create a repo first
    let repo_key = format!("e2e-label-repo-{}", std::process::id());
    env.ak_cmd()
        .args(["repo", "create", &repo_key, "--pkg-format", "generic", "--repo-type", "local"])
        .assert()
        .success();

    // List labels (should be empty initially)
    env.ak_cmd()
        .args(["label", "repo", "list", &repo_key])
        .assert()
        .success();

    // Add a label
    env.ak_cmd()
        .args(["label", "repo", "add", &repo_key, "env=test"])
        .assert()
        .success();

    // List again, should contain the label key
    env.ak_cmd()
        .args(["label", "repo", "list", &repo_key])
        .assert()
        .success()
        .stdout(predicate::str::contains("env"));

    // Remove label
    env.ak_cmd()
        .args(["label", "repo", "remove", &repo_key, "env"])
        .assert()
        .success();

    // Cleanup repo
    env.ak_cmd()
        .args(["repo", "delete", &repo_key, "--yes"])
        .assert()
        .success();
}
