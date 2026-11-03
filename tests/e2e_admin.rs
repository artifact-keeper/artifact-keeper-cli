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
    env.ak_cmd().args(["admin", "stats"]).assert().success();
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

fn admin_json(cmd: &mut assert_cmd::Command) -> serde_json::Value {
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
fn backup_create_takes_a_scope_and_list_filters() {
    let env = common::TestEnv::setup();
    let suffix = std::process::id();
    let repo = format!("e2e-backup-{suffix}");
    env.ak_cmd()
        .args(["repo", "create", &repo, "--pkg-format", "generic"])
        .assert()
        .success();
    let name = format!("e2e-backup-{suffix}");
    let created = admin_json(env.ak_cmd().args([
        "admin",
        "backup",
        "create",
        "--type",
        "incremental",
        "--name",
        &name,
        "--repos",
        &repo,
        "--since",
        "2026-01-01T00:00:00Z",
    ]));
    let id = created["id"].as_str().unwrap().to_string();
    assert_eq!(created["type"], "incremental");
    assert!(
        created["storage_path"].as_str().unwrap().contains(&name),
        "the name didn't reach the server: {created}"
    );

    let by_type = admin_json(env.ak_cmd().args([
        "admin",
        "backup",
        "list",
        "--type",
        "incremental",
        "--status",
        created["status"].as_str().unwrap(),
    ]));
    let found = by_type["items"].as_array().unwrap();
    assert!(found.iter().any(|b| b["id"] == id.as_str()), "{by_type}");
    let by_other_type = admin_json(
        env.ak_cmd()
            .args(["admin", "backup", "list", "--type", "full"]),
    );
    assert!(
        !by_other_type["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["id"] == id.as_str()),
        "the filter didn't reach the server: {by_other_type}"
    );

    env.ak_cmd()
        .args([
            "admin",
            "backup",
            "create",
            "--exclude-repos",
            "no-such-repo",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("no-such-repo"));

    env.ak_cmd()
        .args(["admin", "backup", "delete", &id, "--yes"])
        .assert()
        .success();
    let _ = env.api_delete(&format!("/api/v1/repositories/{repo}"));
}

/// The server's refusal of an empty key set proves `--static-jwks` reached it. A 1.10
/// server would drop it and go on trusting the issuer's keys, so `ak` stops first.
#[test]
#[ignore = "requires E2E backend"]
fn ci_oidc_static_keys_reach_the_server_or_are_refused_before_1_11() {
    let env = common::TestEnv::setup();
    let name = format!("e2e-ci-oidc-{}", std::process::id());
    let expected = if common::server_older_than(1, 11, "CI OIDC static keys") {
        "1.11"
    } else {
        "static_jwks"
    };
    env.ak_cmd()
        .args([
            "admin",
            "ci-oidc",
            "create",
            &name,
            "https://ci.example.com",
        ])
        .args(["--key-source", "static", "--static-jwks", r#"{"keys":[]}"#])
        .assert()
        .failure()
        .stderr(predicates::str::contains(expected));
}

#[test]
#[ignore = "requires E2E backend"]
fn cleanup_stale_uploads_reaches_the_server() {
    let env = common::TestEnv::setup();
    let cleaned = admin_json(
        env.ak_cmd()
            .args(["admin", "cleanup", "--stale-uploads", "--yes"]),
    );
    assert!(cleaned["stale_uploads_deleted"].is_number(), "{cleaned}");
}

#[test]
#[ignore = "requires E2E backend"]
fn builds_create_takes_a_start_time() {
    let env = common::TestEnv::setup();
    let name = format!("e2e-build-{}", std::process::id());
    let build = admin_json(env.ak_cmd().args([
        "builds",
        "create",
        &name,
        "--number",
        "1",
        "--started-at",
        "2026-01-01T00:00:00Z",
    ]));
    assert!(
        build["started_at"]
            .as_str()
            .unwrap()
            .starts_with("2026-01-01T00:00:00"),
        "{build}"
    );
}

#[test]
#[ignore = "requires E2E backend"]
fn peer_register_takes_its_key_from_stdin_and_list_pages() {
    let env = common::TestEnv::setup();
    let name = format!("e2e-peer-{}", std::process::id());
    let output = env
        .ak_cmd()
        .args(["peer", "register", &name])
        .args(["--url", "https://peer.example.com"])
        .arg("--api-key-stdin")
        .args(["--cache-size-bytes", "1048576"])
        .args(["--sync-filter", r#"{"a":1}"#])
        .write_stdin("the-peer-api-key")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!all.contains("the-peer-api-key"), "{all}");
    let peer: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(peer["cache_size_bytes"], 1048576);

    let page = admin_json(
        env.ak_cmd()
            .args(["peer", "list", "--page", "1", "--per-page", "1"]),
    );
    assert_eq!(page["items"].as_array().unwrap().len(), 1, "{page}");
    assert!(page["total"].as_i64().unwrap() >= 2, "{page}");

    let id = peer["id"].as_str().unwrap();
    let tasks =
        admin_json(
            env.ak_cmd()
                .args(["peer", "tasks", id, "--page", "1", "--per-page", "5"]),
        );
    assert!(tasks.is_array() || tasks["items"].is_array(), "{tasks}");
    env.ak_cmd()
        .args(["peer", "unregister", id, "--yes"])
        .assert()
        .success();
}
