//! E2E tests for `ak sync-policy`.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use serde_json::{Value, json};

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
fn create_update_toggle_preview_and_delete() {
    let env = common::TestEnv::setup();
    let suffix = std::process::id();
    let repo = format!("e2e-sync-{suffix}");
    env.ak_cmd()
        .args(["repo", "create", &repo, "--pkg-format", "generic"])
        .assert()
        .success();
    let name = format!("e2e-sync-{suffix}");
    let selector = format!(r#"{{"match_pattern":"{repo}"}}"#);

    let created = json_of(env.ak_cmd().args([
        "sync-policy",
        "create",
        &name,
        "--mode",
        "push",
        "--description",
        "from the E2E tests",
        "--priority",
        "5",
        "--enabled",
        "false",
        "--repo-selector",
        &selector,
        "--peer-selector",
        r#"{"all":true}"#,
        "--artifact-filter",
        r#"{"max_age_days":3}"#,
        "--precedence",
        "2",
        "--filter",
        "*.bin",
    ]));
    let id = created["id"].as_str().unwrap().to_string();
    assert_eq!(created["replication_mode"], "push");
    assert_eq!(created["description"], "from the E2E tests");
    assert_eq!(created["priority"], 5);
    assert_eq!(created["enabled"], false);
    assert_eq!(created["repo_selector"]["match_pattern"], repo.as_str());
    assert_eq!(created["peer_selector"]["all"], true);
    assert_eq!(created["artifact_filter"]["max_age_days"], 3);
    assert_eq!(created["precedence"], 2);
    assert_eq!(created["filter"], "*.bin");

    let shown = json_of(env.ak_cmd().args(["sync-policy", "show", &id]));
    assert_eq!(shown["id"], id.as_str());
    let listed = json_of(env.ak_cmd().args(["sync-policy", "list"]));
    assert!(
        listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["id"] == id.as_str()),
        "{listed}"
    );

    let updated = json_of(env.ak_cmd().args([
        "sync-policy",
        "update",
        &id,
        "--name",
        &format!("{name}-2"),
        "--mode",
        "pull",
        "--description",
        "changed",
        "--priority",
        "6",
        "--precedence",
        "3",
        "--enabled",
        "true",
        "--artifact-filter",
        r#"{"max_age_days":9}"#,
    ]));
    assert_eq!(updated["name"], format!("{name}-2").as_str());
    assert_eq!(updated["replication_mode"], "pull");
    assert_eq!(updated["description"], "changed");
    assert_eq!(updated["priority"], 6);
    assert_eq!(updated["precedence"], 3);
    assert_eq!(updated["enabled"], true);
    assert_eq!(updated["artifact_filter"]["max_age_days"], 9);
    assert_eq!(
        updated["repo_selector"]["match_pattern"],
        repo.as_str(),
        "a selector not given must stay"
    );

    let off = json_of(
        env.ak_cmd()
            .args(["sync-policy", "toggle", &id, "--disable"]),
    );
    assert_eq!(off["enabled"], false);

    let preview = json_of(env.ak_cmd().args([
        "sync-policy",
        "preview",
        "--repo-selector",
        &selector,
        "--peer-selector",
        r#"{"all":true}"#,
        "--mode",
        "pull",
        "--priority",
        "1",
        "--precedence",
        "1",
        "--enabled",
        "true",
        "--description",
        "a preview",
    ]));
    let keys: Vec<&Value> = preview["matched_repositories"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| &r["key"])
        .collect();
    assert_eq!(keys, vec![&json!(repo)], "{preview}");

    let evaluated = json_of(env.ak_cmd().args(["sync-policy", "evaluate"]));
    assert!(evaluated["policies_evaluated"].is_number(), "{evaluated}");

    env.ak_cmd()
        .args(["sync-policy", "delete", &id, "--yes"])
        .assert()
        .success();
    env.ak_cmd()
        .args(["sync-policy", "show", &id])
        .assert()
        .failure();
    let _ = env.api_delete(&format!("/api/v1/repositories/{repo}"));
}

#[test]
#[ignore = "requires E2E backend"]
fn a_selector_that_is_not_json_is_refused_before_any_request() {
    let env = common::TestEnv::setup();
    env.ak_cmd()
        .args([
            "sync-policy",
            "create",
            "e2e-never",
            "--repo-selector",
            "nope",
        ])
        .assert()
        .failure();
    let listed = json_of(env.ak_cmd().args(["sync-policy", "list"]));
    assert!(
        !listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "e2e-never")
    );
}
