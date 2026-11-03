//! E2E: `--no-input` and `AK_NO_INPUT` never consent to anything. Only `--yes` does.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

use common::TestEnv;

fn repo(env: &TestEnv) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let key = format!("e2e-no-input-{nanos}");
    let created = env.api_post(
        "/api/v1/repositories",
        &json!({"key": key, "name": key, "format": "generic", "repo_type": "local"}),
    );
    assert!(created.status().is_success());
    key
}

fn exists(env: &TestEnv, key: &str) -> bool {
    env.ak_cmd()
        .args(["repo", "show", key])
        .output()
        .unwrap()
        .status
        .success()
}

#[test]
#[ignore = "requires E2E backend"]
fn a_delete_needs_yes_with_no_input() {
    let env = TestEnv::setup();
    let key = repo(&env);

    // ak_cmd passes --no-input.
    let refused = env
        .ak_cmd()
        .args(["repo", "delete", &key])
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("--yes"));
    assert!(exists(&env, &key), "--no-input deleted the repository");

    let by_env = env
        .ak_cmd()
        .env("AK_NO_INPUT", "1")
        .args(["repo", "delete", &key])
        .output()
        .unwrap();
    assert_eq!(by_env.status.code(), Some(2));
    assert!(exists(&env, &key), "AK_NO_INPUT deleted the repository");

    env.ak_cmd()
        .args(["repo", "delete", &key, "-y"])
        .assert()
        .success();
    assert!(!exists(&env, &key), "-y didn't delete the repository");
}
