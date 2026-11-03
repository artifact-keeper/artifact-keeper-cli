//! E2E tests for `ak promotion` commands.

mod common;

use serde_json::{Value, json};

struct Fixture {
    env: common::TestEnv,
    source: String,
    target: String,
    artifact: String,
    rule: String,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self
            .env
            .api_delete(&format!("/api/v1/promotion-rules/{}", self.rule));
        for repo in [&self.source, &self.target] {
            let _ = self.env.api_delete(&format!("/api/v1/repositories/{repo}"));
        }
    }
}

/// A staging repository holding one artifact, and a rule that blocks promoting it
/// to the release repository: it wants the artifact in staging for 1000 hours.
fn blocked_promotion(name: &str) -> Fixture {
    let env = common::TestEnv::setup();
    let suffix = format!("{name}-{}", std::process::id());
    let source = format!("e2e-stg-{suffix}");
    let target = format!("e2e-rel-{suffix}");

    let mut ids = Vec::new();
    for (key, repo_type) in [(&source, "staging"), (&target, "local")] {
        let repo: Value = env
            .api_post(
                "/api/v1/repositories",
                &json!({"key": key, "name": key, "format": "generic", "repo_type": repo_type}),
            )
            .json()
            .unwrap();
        ids.push(repo["id"].as_str().expect("repository id").to_string());
    }

    let artifact: Value = env
        .api_client()
        .put(format!(
            "{}/api/v1/repositories/{source}/artifacts/a.bin",
            env.url
        ))
        .bearer_auth(&env.token)
        .body("promotion e2e")
        .send()
        .unwrap()
        .json()
        .unwrap();
    let artifact = artifact["id"].as_str().expect("artifact id").to_string();

    let rule: Value = env
        .api_post(
            "/api/v1/promotion-rules",
            &json!({
                "name": format!("e2e-hold-{suffix}"),
                "source_repo_id": ids[0],
                "target_repo_id": ids[1],
                "is_enabled": true,
                "min_staging_hours": 1000
            }),
        )
        .json()
        .unwrap();
    let rule = rule["id"].as_str().expect("rule id").to_string();

    Fixture {
        env,
        source,
        target,
        artifact,
        rule,
    }
}

fn stderr_words(output: &std::process::Output) -> String {
    // miette wraps at the width of the output, so compare words.
    String::from_utf8_lossy(&output.stderr)
        .split_whitespace()
        .filter(|word| *word != "\u{2502}")
        .collect::<Vec<_>>()
        .join(" ")
}

/// The server answers 200 when a rule blocks a promotion. A script has to see a
/// failure, with the rule's reason, in every output format.
#[test]
#[ignore = "requires E2E backend"]
fn promote_blocked_by_a_rule_fails_with_the_reason() {
    let fx = blocked_promotion("single");
    let args = [
        "promotion",
        "promote",
        "--from",
        &fx.source,
        "--to",
        &fx.target,
        &fx.artifact,
    ];

    let output = fx
        .env
        .ak_cmd()
        .args(args)
        .assert()
        .failure()
        .get_output()
        .clone();
    assert_eq!(output.status.code(), Some(1));
    let body: Value = serde_json::from_slice(&output.stdout).expect("JSON on stdout");
    assert_eq!(body["promoted"], false);
    assert!(!body["policy_violations"].as_array().unwrap().is_empty());
    let err = stderr_words(&output);
    assert!(
        err.contains("Promotion blocked by promotion rule violations"),
        "{err}"
    );

    let output = fx
        .env
        .ak_cmd_table()
        .args(args)
        .assert()
        .failure()
        .get_output()
        .clone();
    let err = stderr_words(&output);
    assert!(err.contains("Promotion blocked"), "{err}");

    // Nothing reached the target.
    let list: Value = fx
        .env
        .api_client()
        .get(format!(
            "{}/api/v1/repositories/{}/artifacts",
            fx.env.url, fx.target
        ))
        .bearer_auth(&fx.env.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(list["items"].as_array().unwrap().len(), 0);

    // The documented override still works, so the failure above was the rule.
    let promoted = fx
        .env
        .ak_cmd()
        .args(args)
        .arg("--skip-checks")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let promoted: Value = serde_json::from_slice(&promoted).unwrap();
    assert_eq!(promoted["promoted"], true);
}

#[test]
#[ignore = "requires E2E backend"]
fn bulk_promote_with_a_refusal_fails_and_names_it() {
    let fx = blocked_promotion("bulk");
    let output = fx
        .env
        .ak_cmd()
        .args([
            "promotion",
            "bulk-promote",
            "--from",
            &fx.source,
            "--to",
            &fx.target,
            "--artifact",
            &fx.artifact,
        ])
        .assert()
        .failure()
        .get_output()
        .clone();
    let body: Value = serde_json::from_slice(&output.stdout).expect("JSON on stdout");
    assert_eq!(body["failed"], 1);
    let err = stderr_words(&output);
    assert!(err.contains("1 of 1"), "{err}");
    assert!(err.contains("a.bin"), "{err}");
}

fn json_of(cmd: &mut assert_cmd::Command) -> Value {
    let output = cmd.output().expect("run ak");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("JSON")
}

/// A staging repository with the given artifact, a target, and the artifact's ID.
fn staged(env: &common::TestEnv, tag: &str, path: &str) -> (String, String, String) {
    let suffix = std::process::id();
    let (staging, target) = (
        format!("e2e-pro-{tag}-{suffix}"),
        format!("e2e-pro-{tag}-t-{suffix}"),
    );
    env.ak_cmd()
        .args(["repo", "create", &staging, "--pkg-format", "generic"])
        .args(["--repo-type", "staging"])
        .assert()
        .success();
    env.ak_cmd()
        .args(["repo", "create", &target, "--pkg-format", "generic"])
        .assert()
        .success();
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), format!("{staging}/{path}")).unwrap();
    env.ak_cmd()
        .args(["artifact", "push", &staging])
        .arg(file.path())
        .args(["--path", path])
        .assert()
        .success();
    let info = json_of(env.ak_cmd().args(["artifact", "info", &staging, path]));
    (staging, target, info["id"].as_str().unwrap().to_string())
}

#[test]
#[ignore = "requires E2E backend"]
fn promote_moves_the_artifact_and_history_records_it() {
    let env = common::TestEnv::setup();
    let (staging, target, id) = staged(&env, "move", "moved.bin");

    let promoted = json_of(env.ak_cmd().args([
        "promotion",
        "promote",
        &id,
        "--from",
        &staging,
        "--to",
        &target,
        "--notes",
        "from the E2E tests",
        "--skip-checks",
    ]));
    assert_eq!(promoted["promoted"], true, "{promoted}");

    // Really in the target now.
    let there = json_of(
        env.ak_cmd()
            .args(["artifact", "info", &target, "moved.bin"]),
    );
    assert_eq!(there["path"], "moved.bin");

    let history = json_of(env.ak_cmd().args([
        "promotion",
        "history",
        "--repo",
        &staging,
        "--artifact",
        &format!("{staging}/moved.bin"),
    ]));
    let items = history["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{history}");
    assert_eq!(items[0]["target_repo_key"], target.as_str());
    assert_eq!(items[0]["notes"], "from the E2E tests");

    // No other artifact has this history. Servers up to at least 1.11.10 ignore the
    // parameter (artifact-keeper#5209), and `ak` filters what it gets.
    let other = json_of(env.ak_cmd().args([
        "promotion",
        "history",
        "--repo",
        &staging,
        "--artifact",
        "00000000-0000-0000-0000-000000000000",
    ]));
    assert!(other["items"].as_array().unwrap().is_empty(), "{other}");
}

#[test]
#[ignore = "requires E2E backend"]
fn a_rule_keeps_every_requirement_and_can_be_evaluated() {
    let env = common::TestEnv::setup();
    let (staging, target, _) = staged(&env, "rule", "ruled.bin");
    let name = format!("e2e-rule-{}", std::process::id());

    let created = json_of(env.ak_cmd().args([
        "promotion",
        "rule",
        "create",
        &name,
        "--from",
        &staging,
        "--to",
        &target,
        "--auto",
        "--disabled",
        "--min-staging-hours",
        "2",
        "--max-artifact-age-days",
        "9",
        "--max-cve-severity",
        "high",
        "--min-health-score",
        "50",
        "--allowed-licenses",
        "MIT,ISC",
        "--require-signature",
        "true",
    ]));
    let id = created["id"].as_str().unwrap().to_string();
    assert_eq!(created["is_enabled"], false);
    assert_eq!(created["auto_promote"], true);
    assert_eq!(created["min_staging_hours"], 2);
    assert_eq!(created["max_artifact_age_days"], 9);
    assert_eq!(created["max_cve_severity"], "high");
    assert_eq!(created["min_health_score"], 50);
    assert_eq!(
        created["allowed_licenses"],
        serde_json::json!(["MIT", "ISC"])
    );
    assert_eq!(created["require_signature"], true);

    let shown = json_of(env.ak_cmd().args(["promotion", "rule", "get", &id]));
    assert_eq!(shown["id"], id.as_str());
    let listed = json_of(
        env.ak_cmd()
            .args(["promotion", "rule", "list", "--from", &staging]),
    );
    assert_eq!(listed["items"].as_array().unwrap().len(), 1, "{listed}");

    let updated = json_of(env.ak_cmd().args([
        "promotion",
        "rule",
        "update",
        &id,
        "--enabled",
        "true",
        "--min-health-score",
        "3",
    ]));
    assert_eq!(updated["is_enabled"], true);
    assert_eq!(updated["min_health_score"], 3);

    // With no scan, signature or licence on record the artifact can't pass.
    let evaluated = json_of(env.ak_cmd().args(["promotion", "rule", "evaluate", &id]));
    assert_eq!(evaluated["total_artifacts"], 1, "{evaluated}");
    assert_eq!(evaluated["failed"], 1, "{evaluated}");

    env.ak_cmd()
        .args(["promotion", "rule", "delete", &id, "--yes"])
        .assert()
        .success();
    env.ak_cmd()
        .args(["promotion", "rule", "get", &id])
        .assert()
        .failure();
}

#[test]
#[ignore = "requires E2E backend"]
fn reject_is_recorded() {
    let env = common::TestEnv::setup();
    let (staging, _target, id) = staged(&env, "rej", "rejected.bin");
    let rejected = json_of(env.ak_cmd().args([
        "promotion",
        "reject",
        &id,
        "--from",
        &staging,
        "--reason",
        "from the E2E tests",
    ]));
    assert_eq!(rejected["rejected"], true, "{rejected}");
    assert_eq!(rejected["reason"], "from the E2E tests");
    let history = json_of(env.ak_cmd().args([
        "promotion",
        "history",
        "--repo",
        &staging,
        "--status",
        "rejected",
    ]));
    assert_eq!(history["items"].as_array().unwrap().len(), 1, "{history}");
}
