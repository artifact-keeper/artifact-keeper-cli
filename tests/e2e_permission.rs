//! E2E tests for `ak permission`.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use predicates::prelude::*;
use serde_json::Value;

fn json_of(cmd: &mut assert_cmd::Command) -> Value {
    let output = cmd.output().expect("run ak");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("JSON")
}

#[test]
#[ignore = "requires E2E backend"]
fn create_show_filter_update_and_delete_by_repository_key() {
    let env = common::TestEnv::setup();
    let repo = format!("e2e-perm-{}", std::process::id());
    env.ak_cmd()
        .args(["repo", "create", &repo, "--pkg-format", "generic"])
        .assert()
        .success();
    let me = json_of(env.ak_cmd().args(["auth", "whoami"]));
    let principal = me["id"].as_str().unwrap();

    let created = json_of(env.ak_cmd().args([
        "permission",
        "create",
        "--principal",
        principal,
        "--principal-type",
        "user",
        "--target",
        &repo,
        "--target-type",
        "repository",
        "--actions",
        "read",
    ]));
    let id = created["id"].as_str().unwrap().to_string();
    assert_eq!(created["target_name"], repo.as_str());

    let shown = json_of(env.ak_cmd().args(["permission", "show", &id]));
    assert_eq!(shown["id"], id.as_str());

    // Filters reach the server: this repository has one rule, whatever others exist.
    let listed = json_of(env.ak_cmd().args([
        "permission",
        "list",
        "--target-type",
        "repository",
        "--target",
        &repo,
        "--principal",
        principal,
    ]));
    let items = listed["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{listed}");
    assert_eq!(items[0]["id"], id.as_str());

    let mut update = env.ak_cmd();
    update.args([
        "permission",
        "update",
        &id,
        "--principal",
        principal,
        "--principal-type",
        "user",
        "--target",
        &repo,
        "--target-type",
        "repository",
        "--actions",
        "read,write",
        "--conditions",
        r#"{"allowed_cidrs":["10.0.0.0/8"]}"#,
    ]);
    if common::server_older_than(1, 11, "permission conditions") {
        // A 1.10 server would drop the condition and keep a broader grant.
        update
            .assert()
            .failure()
            .stderr(predicate::str::contains("1.11"));
    } else {
        let updated = json_of(&mut update);
        assert_eq!(
            updated["conditions"]["allowed_cidrs"],
            serde_json::json!(["10.0.0.0/8"])
        );
        assert_eq!(updated["actions"], serde_json::json!(["read", "write"]));
    }

    env.ak_cmd()
        .args(["permission", "delete", &id, "--yes"])
        .assert()
        .success();
    env.ak_cmd()
        .args(["permission", "show", &id])
        .assert()
        .failure();
    let _ = env.api_delete(&format!("/api/v1/repositories/{repo}"));
}

#[test]
#[ignore = "requires E2E backend"]
fn an_unknown_condition_is_refused_rather_than_dropped() {
    let env = common::TestEnv::setup();
    env.ak_cmd()
        .args(["permission", "create"])
        .args(["--principal", "00000000-0000-0000-0000-000000000000"])
        .args(["--principal-type", "user"])
        .args(["--target", "00000000-0000-0000-0000-000000000000"])
        .args(["--target-type", "repository"])
        .args(["--actions", "read"])
        .args(["--conditions", r#"{"nope":1}"#])
        .assert()
        .failure()
        .stderr(predicate::str::contains("nope"));
}
