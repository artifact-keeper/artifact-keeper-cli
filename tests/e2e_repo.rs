//! E2E tests for `ak repo` commands.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use predicates::prelude::*;

#[test]
#[ignore = "requires E2E backend"]
fn repo_list_succeeds() {
    let env = common::TestEnv::setup();
    env.ak_cmd().args(["repo", "list"]).assert().success();
}

#[test]
#[ignore = "requires E2E backend"]
fn repo_create_show_delete_lifecycle() {
    let env = common::TestEnv::setup();
    let repo_key = format!("e2e-test-{}", std::process::id());

    // Create
    env.ak_cmd()
        .args([
            "repo",
            "create",
            &repo_key,
            "--pkg-format",
            "generic",
            "--repo-type",
            "local",
        ])
        .assert()
        .success();

    // Show
    env.ak_cmd()
        .args(["repo", "show", &repo_key])
        .assert()
        .success()
        .stdout(predicate::str::contains(&repo_key));

    // Delete
    env.ak_cmd()
        .args(["repo", "delete", &repo_key, "--yes"])
        .assert()
        .success();
}

#[test]
#[ignore = "requires E2E backend"]
fn repo_list_with_format_filter() {
    let env = common::TestEnv::setup();
    env.ak_cmd()
        .args(["repo", "list", "--pkg-format", "generic"])
        .assert()
        .success();
}

#[test]
#[ignore = "requires E2E backend"]
fn repo_update_partial_preserves_other_fields() {
    let env = common::TestEnv::setup();
    let key = format!("e2e-upd-{}", std::process::id());

    env.ak_cmd()
        .args(["repo", "create", &key, "--pkg-format", "npm"])
        .assert()
        .success();

    // Set a description via PATCH.
    env.ak_cmd()
        .args(["repo", "update", &key, "--description", "e2e-desc"])
        .assert()
        .success();

    // Update only the name; description must survive (partial semantics).
    env.ak_cmd()
        .args(["repo", "update", &key, "--name", "Renamed"])
        .assert()
        .success();

    env.ak_cmd()
        .args(["repo", "show", &key])
        .assert()
        .success()
        .stdout(predicate::str::contains("e2e-desc"))
        .stdout(predicate::str::contains("Renamed"));

    env.ak_cmd()
        .args(["repo", "delete", &key, "--yes"])
        .assert()
        .success();
}

#[test]
#[ignore = "requires E2E backend"]
fn repo_cache_ttl_get_set_on_remote() {
    let env = common::TestEnv::setup();
    let key = format!("e2e-cache-{}", std::process::id());

    env.ak_cmd()
        .args([
            "repo",
            "create",
            &key,
            "--pkg-format",
            "npm",
            "--repo-type",
            "remote",
            "--upstream-url",
            "https://registry.npmjs.org",
        ])
        .assert()
        .success();

    env.ak_cmd()
        .args(["repo", "cache", "set-ttl", &key, "3600"])
        .assert()
        .success();

    env.ak_cmd()
        .args(["repo", "cache", "get-ttl", &key])
        .assert()
        .success()
        .stdout(predicate::str::contains("3600"));

    env.ak_cmd()
        .args(["repo", "delete", &key, "--yes"])
        .assert()
        .success();
}

#[test]
#[ignore = "requires E2E backend"]
fn repo_virtual_members_lifecycle() {
    let env = common::TestEnv::setup();
    let pid = std::process::id();
    let member = format!("e2e-mem-{pid}");
    let virt = format!("e2e-virt-{pid}");

    env.ak_cmd()
        .args(["repo", "create", &member, "--pkg-format", "npm"])
        .assert()
        .success();
    env.ak_cmd()
        .args([
            "repo",
            "create",
            &virt,
            "--pkg-format",
            "npm",
            "--repo-type",
            "virtual",
        ])
        .assert()
        .success();

    env.ak_cmd()
        .args(["repo", "members", "add", &virt, &member, "--priority", "10"])
        .assert()
        .success();

    env.ak_cmd()
        .args(["repo", "members", "list", &virt])
        .assert()
        .success()
        .stdout(predicate::str::contains(&member));

    env.ak_cmd()
        .args(["repo", "members", "remove", &virt, &member])
        .assert()
        .success();

    env.ak_cmd()
        .args(["repo", "delete", &virt, "--yes"])
        .assert()
        .success();
    env.ak_cmd()
        .args(["repo", "delete", &member, "--yes"])
        .assert()
        .success();
}
