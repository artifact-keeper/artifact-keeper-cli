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
fn create_and_update_keep_every_threshold() {
    let env = common::TestEnv::setup();
    let name = format!("e2e-gate-fields-{}", std::process::id());
    let created = json_of(env.ak_cmd().args([
        "quality-gate",
        "create",
        &name,
        "--min-health-score",
        "10",
        "--min-metadata-score",
        "11",
        "--min-quality-score",
        "12",
        "--min-security-score",
        "13",
        "--enforce-on-download",
        "true",
        "--enforce-on-promotion",
        "false",
    ]));
    let id = created["id"].as_str().unwrap().to_string();
    assert_eq!(created["min_health_score"], 10);
    assert_eq!(created["min_metadata_score"], 11);
    assert_eq!(created["min_quality_score"], 12);
    assert_eq!(created["min_security_score"], 13);
    assert_eq!(created["enforce_on_download"], true);
    assert_eq!(created["enforce_on_promotion"], false);

    let updated = json_of(env.ak_cmd().args([
        "quality-gate",
        "update",
        &id,
        "--max-medium",
        "4",
        "--description",
        "changed",
        "--required-checks",
        "a,b",
        "--min-health-score",
        "20",
        "--enforce-on-download",
        "false",
    ]));
    assert_eq!(updated["max_medium_issues"], 4);
    assert_eq!(updated["description"], "changed");
    assert_eq!(updated["required_checks"], serde_json::json!(["a", "b"]));
    assert_eq!(updated["min_health_score"], 20);
    assert_eq!(updated["enforce_on_download"], false);
    assert_eq!(updated["min_security_score"], 13, "the rest stays");

    env.ak_cmd()
        .args(["quality-gate", "delete", &id, "--yes"])
        .assert()
        .success();
}
