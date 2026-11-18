//! E2E tests for `ak curation` against a real backend.
//!
//! Requires the E2E backend: ./tests/start-backend.sh
//!
//! A staging repository made here has a source (on 1.12; 1.11 has no way to link
//! one) whose upstream holds nothing, so a sync finds no packages. These tests
//! prove every command reaches the real route and shows what the server answers.
//! Approving and publishing a real package isn't covered here.

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

fn create_repo(env: &TestEnv, key: &str, args: &[&str]) {
    env.ak_cmd()
        .args(["repo", "create", key, "--pkg-format", "rpm"])
        .args(args)
        .assert()
        .success();
}

/// A staging repository. On 1.12, which syncs only a repository with curation
/// enabled and a source, it has both: a remote whose upstream is an empty public
/// local repository of this same backend. That has no signing key, so the staging
/// repository takes unverified metadata.
fn staging_repo(env: &TestEnv) -> String {
    let key = unique("cur");
    if common::server_older_than(1, 12, "curation sources") {
        create_repo(env, &key, &["--repo-type", "staging"]);
        return key;
    }
    let local = unique("cur-local");
    create_repo(env, &local, &["--repo-type", "local", "--public"]);
    let source = unique("cur-source");
    let upstream = format!("http://ak-upstream:8080/rpm/{local}");
    create_repo(
        env,
        &source,
        &["--repo-type", "remote", "--upstream-url", &upstream],
    );
    let created = stdout_json(
        env.ak_cmd()
            .args([
                "repo",
                "create",
                &key,
                "--pkg-format",
                "rpm",
                "--repo-type",
                "staging",
                "--curation-source",
                &source,
                "--curation-enabled",
                "true",
                "--curation-default-action",
                "review",
                "--curation-allow-unverified",
                "true",
            ])
            .output()
            .unwrap(),
    );
    assert_eq!(created["curation_enabled"], true, "{created}");
    assert_eq!(created["curation_default_action"], "review", "{created}");
    assert!(created["curation_source_repo_id"].is_string(), "{created}");
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

    let sync = env
        .ak_cmd()
        .args(["curation", "sync", &key])
        .output()
        .unwrap();
    let synced = stdout_json(sync);
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
fn curation_source_is_refused_before_1_12_and_can_be_removed() {
    let env = TestEnv::setup();
    if !common::server_older_than(1, 12, "a refusal of --curation-source") {
        let key = staging_repo(&env);
        let updated = stdout_json(
            env.ak_cmd()
                .args(["repo", "update", &key, "--curation-source", ""])
                .output()
                .unwrap(),
        );
        assert_eq!(updated["key"], key.as_str(), "{updated}");
        let shown = stdout_json(env.ak_cmd().args(["repo", "show", &key]).output().unwrap());
        assert!(shown["curation_source_repo_id"].is_null(), "{shown}");
        return;
    }
    let key = unique("cur");
    let refused = env
        .ak_cmd()
        .args([
            "repo",
            "create",
            &key,
            "--pkg-format",
            "rpm",
            "--repo-type",
            "staging",
            "--curation-source",
            "elsewhere",
        ])
        .output()
        .unwrap();
    assert!(!refused.status.success());
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("--curation-source needs a server on 1.12"),
        "{stderr}"
    );
    env.ak_cmd().args(["repo", "show", &key]).assert().failure();
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
