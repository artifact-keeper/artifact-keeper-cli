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
