//! E2E tests for `ak admin` commands.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use predicates::prelude::*;

#[test]
#[ignore = "requires E2E backend"]
fn admin_users_list() {
    let env = common::TestEnv::setup();
    env.ak_cmd()
        .args(["admin", "users", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("admin"));
}

#[test]
#[ignore = "requires E2E backend"]
fn admin_stats() {
    let env = common::TestEnv::setup();
    env.ak_cmd()
        .args(["admin", "stats"])
        .assert()
        .success();
}

#[test]
#[ignore = "requires E2E backend"]
fn admin_user_create_delete_lifecycle() {
    let env = common::TestEnv::setup();
    let username = format!("e2e-user-{}", std::process::id());

    // Create user via API (CLI create requires interactive password)
    let resp = env.api_post(
        "/api/v1/users",
        &serde_json::json!({
            "username": username,
            "email": format!("{username}@test.local"),
            "display_name": "E2E Test User",
            "password": "TestPass123!",
            "is_admin": false
        }),
    );
    assert!(
        resp.status().is_success(),
        "Failed to create user via API: {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().unwrap();
    let user_id = body["user"]["id"]
        .as_str()
        .or_else(|| body["id"].as_str())
        .expect("No user id in response")
        .to_string();

    // Verify user shows in list
    env.ak_cmd()
        .args(["admin", "users", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains(&username));

    // Delete user
    env.api_delete(&format!("/api/v1/users/{user_id}"));
}
