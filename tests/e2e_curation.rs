//! E2E tests for `ak curation` against a real backend.
//!
//! Requires the E2E backend: ./tests/start-backend.sh
//!
//! No API on 1.11.10 links a staging repository to its source, so a repository
//! made here has nothing to sync and no packages. These tests prove every command
//! reaches the real route and shows what the server answers. Approving and
//! publishing a real package isn't covered here.

mod common;

use common::TestEnv;
use serde_json::Value;

fn stdout_json(output: std::process::Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("stdout isn't JSON")
}

fn unique(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4().simple())
}

fn staging_repo(env: &TestEnv) -> String {
    let key = unique("cur");
    env.ak_cmd()
        .args([
            "repo",
            "create",
            &key,
            "--pkg-format",
            "rpm",
            "--repo-type",
            "staging",
        ])
        .assert()
        .success();
    key
}

fn delete_rule(env: &TestEnv, id: &str) {
    env.ak_cmd()
        .args(["curation", "delete-rule", id, "--yes"])
        .assert()
        .success();
}

#[test]
#[ignore = "requires E2E backend"]
fn rule_lifecycle_keeps_what_an_update_does_not_name() {
    let env = TestEnv::setup();
    let pattern = unique("left-pad");
    let rule = stdout_json(
        env.ak_cmd()
            .args([
                "curation",
                "create-rule",
                &pattern,
                "--action",
                "block",
                "--reason",
                "banned",
                "--priority",
                "7",
                "--architecture",
                "x86_64",
                "--version-constraint",
                ">=1",
            ])
            .output()
            .unwrap(),
    );
    let id = rule["id"].as_str().unwrap().to_string();
    assert_eq!(rule["rule_type"], "pattern");
    assert_eq!(rule["scope"], "global");

    // PUT replaces the rule, and omitted fields go back to the server's defaults:
    // this rule would turn on again, at priority 100, for every architecture.
    env.ak_cmd()
        .args(["curation", "update-rule", &id, "--disabled"])
        .assert()
        .success();
    let updated = stdout_json(
        env.ak_cmd()
            .args(["curation", "update-rule", &id, "--reason", "still banned"])
            .output()
            .unwrap(),
    );
    assert_eq!(updated["enabled"], false);
    assert_eq!(updated["priority"], 7);
    assert_eq!(updated["architecture"], "x86_64");
    assert_eq!(updated["version_constraint"], ">=1");
    assert_eq!(updated["package_pattern"], pattern.as_str());
    assert_eq!(updated["action"], "block");
    assert_eq!(updated["reason"], "still banned");

    let shown = stdout_json(
        env.ak_cmd()
            .args(["curation", "rule", &id])
            .output()
            .unwrap(),
    );
    assert_eq!(shown["reason"], "still banned");

    delete_rule(&env, &id);
    env.ak_cmd()
        .args(["curation", "rule", &id])
        .assert()
        .failure();
}

#[test]
#[ignore = "requires E2E backend"]
fn typed_rule_config_and_scope_reach_the_server() {
    let env = TestEnv::setup();
    let reason = unique("popular");
    let rule = stdout_json(
        env.ak_cmd()
            .args([
                "curation",
                "create-rule",
                "--action",
                "block",
                "--reason",
                &reason,
                "--rule-type",
                "popularity",
                "--config",
                r#"{"min_downloads":5}"#,
                "--scope",
                "global",
            ])
            .output()
            .unwrap(),
    );
    let id = rule["id"].as_str().unwrap().to_string();
    assert_eq!(rule["rule_type"], "popularity");
    assert_eq!(rule["config"]["min_downloads"], 5);
    assert_eq!(rule["scope"], "global");
    assert_eq!(rule["package_pattern"], "*");

    let updated = stdout_json(
        env.ak_cmd()
            .args([
                "curation",
                "update-rule",
                &id,
                "--config",
                r#"{"min_downloads":9}"#,
            ])
            .output()
            .unwrap(),
    );
    assert_eq!(updated["rule_type"], "popularity");
    assert_eq!(updated["config"]["min_downloads"], 9);

    let global = stdout_json(
        env.ak_cmd()
            .args(["curation", "rules", "--scope", "global"])
            .output()
            .unwrap(),
    );
    assert!(
        global
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["id"] == id.as_str()),
        "{global}"
    );

    // The server's answer to a value it refuses, not a generic failure.
    let refused = env
        .ak_cmd()
        .args([
            "curation",
            "create-rule",
            "--action",
            "block",
            "--reason",
            "r",
            "--scope",
            "nope",
        ])
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("nope"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );

    delete_rule(&env, &id);
}

#[test]
#[ignore = "requires E2E backend"]
fn search_sync_and_versions_reach_their_routes() {
    let env = TestEnv::setup();
    let key = staging_repo(&env);

    let found = stdout_json(
        env.ak_cmd()
            .args([
                "curation", "search", &key, "--q", "x", "--arch", "x86_64", "--status", "pending",
                "--limit", "5", "--offset", "0",
            ])
            .output()
            .unwrap(),
    );
    assert_eq!(found, serde_json::json!([]));

    let synced = stdout_json(
        env.ak_cmd()
            .args(["curation", "sync", &key])
            .output()
            .unwrap(),
    );
    assert_eq!(synced["repository"], key.as_str());
    assert_eq!(synced["triggered"], true);

    let no_packages = env
        .ak_cmd()
        .args(["curation", "version", "create", &key])
        .output()
        .unwrap();
    assert!(!no_packages.status.success());
    assert!(
        String::from_utf8_lossy(&no_packages.stderr).contains("no approved packages"),
        "{}",
        String::from_utf8_lossy(&no_packages.stderr)
    );

    let no_version = env
        .ak_cmd()
        .args(["curation", "version", "publish", &key, "99", "--yes"])
        .output()
        .unwrap();
    assert!(!no_version.status.success());
    assert!(
        String::from_utf8_lossy(&no_version.stderr).contains("404"),
        "{}",
        String::from_utf8_lossy(&no_version.stderr)
    );
}

#[test]
#[ignore = "requires E2E backend"]
fn staging_key_works_for_packages_stats_and_re_evaluate() {
    let env = TestEnv::setup();
    let key = staging_repo(&env);

    let packages = stdout_json(
        env.ak_cmd()
            .args(["curation", "packages", "--staging-repo", &key])
            .output()
            .unwrap(),
    );
    assert_eq!(packages, serde_json::json!([]));

    let stats = stdout_json(
        env.ak_cmd()
            .args(["curation", "stats", "--staging-repo", &key])
            .output()
            .unwrap(),
    );
    assert_eq!(stats["counts"], serde_json::json!([]));

    env.ak_cmd()
        .args([
            "curation",
            "re-evaluate",
            "--staging-repo",
            &key,
            "--default-action",
            "block",
            "--yes",
        ])
        .assert()
        .success();
}
