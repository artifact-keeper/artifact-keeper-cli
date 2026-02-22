//! E2E tests for `ak webhook` commands.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use predicates::prelude::*;

#[test]
#[ignore = "requires E2E backend"]
fn webhook_list() {
    let env = common::TestEnv::setup();
    env.ak_cmd()
        .args(["webhook", "list"])
        .assert()
        .success();
}

#[test]
#[ignore = "requires E2E backend"]
fn webhook_create_show_delete_lifecycle() {
    let env = common::TestEnv::setup();
    let name = format!("e2e-hook-{}", std::process::id());

    // Create webhook via API
    let resp = env.api_post(
        "/api/v1/webhooks",
        &serde_json::json!({
            "name": name,
            "url": "https://httpbin.org/post",
            "events": ["artifact.created"],
            "enabled": true
        }),
    );
    assert!(
        resp.status().is_success(),
        "Failed to create webhook: {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().unwrap();
    let webhook_id = body["id"]
        .as_str()
        .or_else(|| body["webhook"]["id"].as_str())
        .expect("No webhook id in response")
        .to_string();

    // Verify in list
    env.ak_cmd()
        .args(["webhook", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains(&name));

    // Delete
    env.api_delete(&format!("/api/v1/webhooks/{webhook_id}"));
}
