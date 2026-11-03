//! E2E tests for `ak webhook` commands.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use predicates::prelude::*;

#[test]
#[ignore = "requires E2E backend"]
fn webhook_list() {
    let env = common::TestEnv::setup();
    env.ak_cmd().args(["webhook", "list"]).assert().success();
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
            "events": ["artifact_uploaded"],
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
fn create_sets_every_field_and_list_pages() {
    let env = common::TestEnv::setup();
    let name = format!("e2e-fields-{}", std::process::id());
    let created = json_of(
        env.ak_cmd()
            .args(["webhook", "create", &name])
            .args(["--url", "https://hook.example.com/in"])
            .args(["--events", "artifact_uploaded"])
            .args(["--header", "X-Team=platform"])
            .args(["--event-schema-version", "2026-04-01"])
            .args(["--payload-template", "slack"]),
    );
    let id = created["id"].as_str().unwrap().to_string();
    assert_eq!(created["payload_template"], "slack");
    assert_eq!(created["event_schema_version"], "2026-04-01");

    let page = json_of(
        env.ak_cmd()
            .args(["webhook", "list", "--page", "1", "--per-page", "1"]),
    );
    assert_eq!(page["items"].as_array().unwrap().len(), 1, "{page}");
    let deliveries = json_of(env.ak_cmd().args([
        "webhook",
        "deliveries",
        &id,
        "--page",
        "1",
        "--per-page",
        "5",
    ]));
    assert!(deliveries["items"].is_array(), "{deliveries}");
    env.ak_cmd()
        .args(["webhook", "delete", &id, "--yes"])
        .assert()
        .success();
}

/// The plain backend has no signing key, so it refuses `both`. That it says so proves
/// the field reached it. `hmac` needs no key. A 1.10 server would drop the field and
/// sign with HMAC whatever was asked for, so `ak` stops first.
#[test]
#[ignore = "requires E2E backend"]
fn signing_mode_reaches_the_server_or_is_refused_before_1_11() {
    let env = common::TestEnv::setup();
    let name = format!("e2e-signing-{}", std::process::id());
    let create = |mode: &str| {
        let mut cmd = env.ak_cmd();
        cmd.args(["webhook", "create", &name])
            .args(["--url", "https://hook.example.com/in"])
            .args(["--events", "artifact_uploaded"])
            .args(["--signing-mode", mode]);
        cmd
    };
    if common::server_older_than(1, 11, "webhook signing modes") {
        create("hmac")
            .assert()
            .failure()
            .stderr(predicate::str::contains("1.11"));
        env.ak_cmd()
            .args(["webhook", "jwks"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("1.11"));
        return;
    }
    create("both")
        .assert()
        .failure()
        .stderr(predicate::str::contains("AK_WEBHOOK_SECRET_KEY"));
    let created = json_of(&mut create("hmac"));
    assert_eq!(created["signing_mode"], "hmac");
    env.ak_cmd()
        .args([
            "webhook",
            "delete",
            created["id"].as_str().unwrap(),
            "--yes",
        ])
        .assert()
        .success();

    let jwks = json_of(env.ak_cmd().args(["webhook", "jwks"]));
    assert!(jwks["keys"].is_array(), "{jwks}");
}
