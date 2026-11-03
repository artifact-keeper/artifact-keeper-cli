//! E2E tests for `ak group` commands.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use predicates::prelude::*;

#[test]
#[ignore = "requires E2E backend"]
fn group_list() {
    let env = common::TestEnv::setup();
    env.ak_cmd().args(["group", "list"]).assert().success();
}

#[test]
#[ignore = "requires E2E backend"]
fn group_create_show_delete_lifecycle() {
    let env = common::TestEnv::setup();
    let group_name = format!("e2e-group-{}", std::process::id());

    // Create group via API (CLI show/delete require UUIDs)
    let resp = env.api_post(
        "/api/v1/groups",
        &serde_json::json!({
            "name": group_name,
            "description": "E2E test group"
        }),
    );
    assert!(
        resp.status().is_success(),
        "Failed to create group via API: {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().unwrap();
    let group_id = body["id"]
        .as_str()
        .expect("No group id in response")
        .to_string();

    // Show
    env.ak_cmd()
        .args(["group", "show", &group_id])
        .assert()
        .success()
        .stdout(predicate::str::contains(&group_name));

    // List should contain the new group
    env.ak_cmd()
        .args(["group", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains(&group_name));

    // Delete
    env.ak_cmd()
        .args(["group", "delete", &group_id, "--yes"])
        .assert()
        .success();
}

fn json_of(cmd: &mut assert_cmd::Command) -> serde_json::Value {
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
fn show_pages_through_members() {
    let env = common::TestEnv::setup();
    let name = format!("e2e-group-pages-{}", std::process::id());
    let group = json_of(env.ak_cmd().args(["group", "create", &name]));
    let id = group["id"].as_str().unwrap().to_string();
    let me = json_of(env.ak_cmd().args(["auth", "whoami"]));
    let me = me["id"].as_str().unwrap().to_string();
    env.ak_cmd()
        .args(["group", "add-member", &id, &me])
        .assert()
        .success();
    let all = json_of(env.ak_cmd().args(["group", "show", &id]));
    assert_eq!(all["members"].as_array().unwrap().len(), 1, "{all}");
    // Past the end there are no members, though the total still counts one.
    let past = json_of(env.ak_cmd().args([
        "group",
        "show",
        &id,
        "--member-limit",
        "1",
        "--member-offset",
        "1",
    ]));
    assert!(past["members"].as_array().unwrap().is_empty(), "{past}");
    env.ak_cmd()
        .args(["group", "delete", &id, "--yes"])
        .assert()
        .success();
}
