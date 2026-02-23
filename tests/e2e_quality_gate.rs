//! E2E tests for `ak quality-gate` commands.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use predicates::prelude::*;

#[test]
#[ignore = "requires E2E backend"]
fn quality_gate_list() {
    let env = common::TestEnv::setup();
    env.ak_cmd()
        .args(["quality-gate", "list"])
        .assert()
        .success();
}

#[test]
#[ignore = "requires E2E backend"]
fn quality_gate_create_show_delete_lifecycle() {
    let env = common::TestEnv::setup();
    let gate_name = format!("e2e-gate-{}", std::process::id());

    // Create gate via API (CLI show/delete require UUIDs)
    let resp = env.api_post(
        "/api/v1/quality/gates",
        &serde_json::json!({
            "name": gate_name,
            "description": "E2E test quality gate",
            "action": "warn",
            "max_critical_issues": 0,
            "max_high_issues": 5,
            "required_checks": []
        }),
    );
    assert!(
        resp.status().is_success(),
        "Failed to create quality gate via API: {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().unwrap();
    let gate_id = body["id"]
        .as_str()
        .expect("No gate id in response")
        .to_string();

    // Show
    env.ak_cmd()
        .args(["quality-gate", "show", &gate_id])
        .assert()
        .success()
        .stdout(predicate::str::contains(&gate_name));

    // Delete gate
    env.ak_cmd()
        .args(["quality-gate", "delete", &gate_id, "--yes"])
        .assert()
        .success();
}
