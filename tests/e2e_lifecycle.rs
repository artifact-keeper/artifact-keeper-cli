//! E2E tests for `ak lifecycle` commands.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use serde_json::Value;

/// Deletes the repository and policies when dropped, so tests clean up even if
/// an assertion fails partway.
struct Cleanup {
    url: String,
    token: String,
    repo: String,
    policies: Vec<String>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let client = reqwest::blocking::Client::new();
        let mut paths: Vec<String> = self
            .policies
            .iter()
            .map(|id| format!("/api/v1/admin/lifecycle/{id}"))
            .collect();
        paths.push(format!("/api/v1/repositories/{}", self.repo));
        for path in paths {
            let _ = client
                .delete(format!("{}{path}", self.url))
                .bearer_auth(&self.token)
                .send();
        }
    }
}

fn json_output(cmd: &mut assert_cmd::Command) -> Value {
    let output = cmd.assert().success().get_output().stdout.clone();
    serde_json::from_slice(&output).expect("command output is not JSON")
}

/// Create a repository holding one artifact, named so that only this test's
/// policies match it.
fn repo_with_artifact(env: &common::TestEnv, repo: &str, name: &str) -> Cleanup {
    env.ak_cmd()
        .args(["repo", "create", repo, "--pkg-format", "generic"])
        .assert()
        .success();
    let file = env.config_dir.path().join(name);
    std::fs::write(&file, b"lifecycle e2e").unwrap();
    env.ak_cmd()
        .args([
            "artifact",
            "push",
            repo,
            file.to_str().unwrap(),
            "--path",
            name,
        ])
        .assert()
        .success();
    Cleanup {
        url: env.url.clone(),
        token: env.token.clone(),
        repo: repo.to_string(),
        policies: Vec::new(),
    }
}

fn matched(env: &common::TestEnv, id: &str) -> i64 {
    let preview = json_output(env.ak_cmd().args(["lifecycle", "preview", id]));
    preview["artifacts_matched"].as_i64().unwrap()
}

/// A policy created without `--repo` applies to all repositories. Backend 1.11
/// made a policy without a repository dormant unless `applies_to_all` is sent, so
/// the policy has to match something, not merely be created.
#[test]
#[ignore = "requires E2E backend"]
fn create_without_repo_applies_to_all_and_matches() {
    let env = common::TestEnv::setup();
    let suffix = std::process::id();
    let artifact = format!("lifecycle-global-{suffix}.bin");
    let mut guard = repo_with_artifact(&env, &format!("e2e-lc-global-{suffix}"), &artifact);

    let config = format!(r#"{{"pattern":"^{artifact}"}}"#);
    let policy = json_output(env.ak_cmd().args([
        "lifecycle",
        "create",
        &format!("e2e-global-{suffix}"),
        "--policy-type",
        "tag_pattern_delete",
        "--config",
        &config,
    ]));
    let id = policy["id"].as_str().unwrap().to_string();
    guard.policies.push(id.clone());

    assert_eq!(policy["applies_to_all"], true);
    let shown = json_output(env.ak_cmd().args(["lifecycle", "show", &id]));
    assert_eq!(shown["applies_to_all"], true);
    assert_eq!(matched(&env, &id), 1);

    // The dormant policy `ak` used to create doesn't match: this is the bug.
    let dormant: Value = env
        .api_post(
            "/api/v1/admin/lifecycle",
            &serde_json::json!({
                "name": format!("e2e-dormant-{suffix}"),
                "policy_type": "tag_pattern_delete",
                "config": { "pattern": format!("^{artifact}") },
            }),
        )
        .json()
        .unwrap();
    let dormant_id = dormant["id"].as_str().unwrap().to_string();
    guard.policies.push(dormant_id.clone());
    assert_eq!(matched(&env, &dormant_id), 0);
}

#[test]
#[ignore = "requires E2E backend"]
fn create_with_repo_applies_to_that_repo_and_update_keeps_scope() {
    let env = common::TestEnv::setup();
    let suffix = std::process::id();
    let artifact = format!("lifecycle-repo-{suffix}.bin");
    let repo = format!("e2e-lc-repo-{suffix}");
    let mut guard = repo_with_artifact(&env, &repo, &artifact);

    // `ak repo show` doesn't print the ID.
    let repo_id: Value = env
        .api_client()
        .get(format!("{}/api/v1/repositories/{repo}", env.url))
        .bearer_auth(&env.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let repo_id = repo_id["id"].as_str().unwrap();

    let config = format!(r#"{{"pattern":"^{artifact}"}}"#);
    let policy = json_output(env.ak_cmd().args([
        "lifecycle",
        "create",
        &format!("e2e-repo-{suffix}"),
        "--policy-type",
        "tag_pattern_delete",
        "--config",
        &config,
        "--repo",
        repo_id,
    ]));
    let id = policy["id"].as_str().unwrap().to_string();
    guard.policies.push(id.clone());

    assert_eq!(policy["applies_to_all"], false);
    assert_eq!(policy["repository_ids"][0], repo_id);
    assert_eq!(matched(&env, &id), 1);

    // PATCH goes through the strict SDK method.
    let updated = json_output(env.ak_cmd().args([
        "lifecycle",
        "update",
        &id,
        "--description",
        "updated",
        "--disabled",
    ]));
    assert_eq!(updated["description"], "updated");
    assert_eq!(updated["enabled"], false);
    assert_eq!(updated["repository_ids"][0], repo_id);
}
