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

/// Create a policy that the scheduler won't run. An enabled one gets executed for
/// real within about a minute, which deletes the artifact a test is about to
/// preview. A 1.10 server can't create one disabled, so there it starts out
/// matching nothing, and gets its real config in the update that disables it.
fn create_held(env: &common::TestEnv, name: &str, config: &str, scope: &[&str]) -> Value {
    let older = common::server_older_than(1, 11, "--disabled on create");
    let initial = if older {
        r#"{"pattern":"^nothing-has-this-name$"}"#
    } else {
        config
    };
    let mut args = vec![
        "lifecycle",
        "create",
        name,
        "--policy-type",
        "tag_pattern_delete",
        "--config",
        initial,
    ];
    args.extend_from_slice(scope);
    if !older {
        args.push("--disabled");
    }
    let policy = json_output(env.ak_cmd().args(&args));
    if older {
        let id = policy["id"].as_str().unwrap();
        env.ak_cmd()
            .args(["lifecycle", "update", id, "--disabled", "--config", config])
            .assert()
            .success();
    }
    policy
}

/// With no scope given nothing is created, whatever the server would have done
/// with it: a policy deletes, and it's enabled from the start.
#[test]
#[ignore = "requires E2E backend"]
fn create_without_a_scope_is_refused_and_creates_nothing() {
    let env = common::TestEnv::setup();
    let name = format!("e2e-noscope-{}", std::process::id());

    let output = env
        .ak_cmd()
        .args([
            "lifecycle",
            "create",
            &name,
            "--policy-type",
            "max_age_days",
            "--config",
            r#"{"days":3650}"#,
        ])
        .assert()
        .failure()
        .get_output()
        .stderr
        .clone();
    let stderr = String::from_utf8_lossy(&output);
    assert!(stderr.contains("--all-repos"), "{stderr}");

    let policies: Value = env
        .api_client()
        .get(format!("{}/api/v1/admin/lifecycle", env.url))
        .bearer_auth(&env.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let names: Vec<_> = policies
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert!(!names.contains(&name.as_str()), "{names:?}");
}

/// `--all-repos` has to reach another repository's artifacts, not merely create
/// a policy: backend 1.11 makes a policy with no repository dormant unless
/// `applies_to_all` is sent.
#[test]
#[ignore = "requires E2E backend"]
fn create_with_all_repos_applies_to_all_and_matches() {
    let env = common::TestEnv::setup();
    let suffix = std::process::id();
    let artifact = format!("lifecycle-global-{suffix}.bin");
    let mut guard = repo_with_artifact(&env, &format!("e2e-lc-global-{suffix}"), &artifact);

    let config = format!(r#"{{"pattern":"^{artifact}"}}"#);
    let policy = create_held(
        &env,
        &format!("e2e-global-{suffix}"),
        &config,
        &["--all-repos", "--yes"],
    );
    let id = policy["id"].as_str().unwrap().to_string();
    guard.policies.push(id.clone());

    // applies_to_all is new in 1.11. A 1.10 policy with no repository applies to all.
    let older = common::server_older_than(1, 11, "applies_to_all");
    if !older {
        assert_eq!(policy["applies_to_all"], true);
        let shown = json_output(env.ak_cmd().args(["lifecycle", "show", &id]));
        assert_eq!(shown["applies_to_all"], true);
    }
    assert_eq!(matched(&env, &id), 1);

    if older {
        return;
    }

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
    // Holds the same name, so a policy that reached past its repository matches 2.
    let other = format!("e2e-lc-other-{suffix}");
    let _other = repo_with_artifact(&env, &other, &artifact);

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
    let policy = create_held(
        &env,
        &format!("e2e-repo-{suffix}"),
        &config,
        &["--repo", repo_id],
    );
    let id = policy["id"].as_str().unwrap().to_string();
    guard.policies.push(id.clone());

    let older = common::server_older_than(1, 11, "applies_to_all");
    if older {
        assert_eq!(policy["repository_id"], repo_id);
    } else {
        assert_eq!(policy["applies_to_all"], false);
        assert_eq!(policy["repository_ids"][0], repo_id);
    }
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
    let scope = if older {
        "repository_id"
    } else {
        "repository_ids"
    };
    let kept = if older {
        &updated[scope]
    } else {
        &updated[scope][0]
    };
    assert_eq!(*kept, repo_id);
}

/// `--disabled` on create is the only way to look at a policy before it can
/// delete. A server that ignores it mustn't be given the chance.
#[test]
#[ignore = "requires E2E backend"]
fn create_disabled_stays_disabled_or_is_refused() {
    let env = common::TestEnv::setup();
    let suffix = std::process::id();
    let artifact = format!("lifecycle-held-{suffix}.bin");
    let repo = format!("e2e-lc-held-{suffix}");
    let mut guard = repo_with_artifact(&env, &repo, &artifact);
    let name = format!("e2e-held-{suffix}");
    let config = format!(r#"{{"pattern":"^{artifact}"}}"#);
    let args = [
        "lifecycle",
        "create",
        &name,
        "--policy-type",
        "tag_pattern_delete",
        "--config",
        &config,
        "--repo",
        &repo,
        "--disabled",
    ];

    if common::server_older_than(1, 11, "--disabled on create") {
        env.ak_cmd().args(args).assert().failure();
        let policies: Value = env
            .api_client()
            .get(format!("{}/api/v1/admin/lifecycle", env.url))
            .bearer_auth(&env.token)
            .send()
            .unwrap()
            .json()
            .unwrap();
        let found = policies
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == name);
        assert!(!found, "a refused create left a policy");
        return;
    }

    let policy = json_output(env.ak_cmd().args(args));
    let id = policy["id"].as_str().unwrap().to_string();
    guard.policies.push(id.clone());
    assert_eq!(policy["enabled"], false);
    let shown = json_output(env.ak_cmd().args(["lifecycle", "show", &id]));
    assert_eq!(shown["enabled"], false);

    // It can be previewed, but not run.
    assert_eq!(matched(&env, &id), 1);
    env.ak_cmd()
        .args(["lifecycle", "execute", &id, "--yes"])
        .assert()
        .failure();
    assert_eq!(matched(&env, &id), 1);

    let enabled = json_output(env.ak_cmd().args(["lifecycle", "update", &id, "--enabled"]));
    assert_eq!(enabled["enabled"], true);
}

fn repo_id_of(env: &common::TestEnv, repo: &str) -> String {
    let repo: Value = env
        .api_client()
        .get(format!("{}/api/v1/repositories/{repo}", env.url))
        .bearer_auth(&env.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    repo["id"].as_str().unwrap().to_string()
}

#[test]
#[ignore = "requires E2E backend"]
fn attach_and_detach_change_which_repositories_a_policy_applies_to() {
    let env = common::TestEnv::setup();
    let suffix = std::process::id();
    let artifact = format!("lifecycle-attach-{suffix}.bin");
    let repo = format!("e2e-lc-attach-{suffix}");
    let mut guard = repo_with_artifact(&env, &repo, &artifact);
    let other = format!("e2e-lc-attach2-{suffix}");
    let _other = repo_with_artifact(&env, &other, &artifact);
    let config = format!(r#"{{"pattern":"^{artifact}"}}"#);

    if common::server_older_than(1, 11, "lifecycle attach and detach") {
        // A 1.10 server would ignore `repository_ids` and make this policy global.
        env.ak_cmd()
            .args(["lifecycle", "create", &format!("e2e-never-{suffix}")])
            .args(["--policy-type", "tag_pattern_delete", "--config", &config])
            .args(["--repos", &format!("{repo},{other}")])
            .assert()
            .failure()
            .stderr(predicates::str::contains("1.11"));
        let policy = json_output(env.ak_cmd().args([
            "lifecycle",
            "create",
            &format!("e2e-attach-{suffix}"),
            "--policy-type",
            "tag_pattern_delete",
            "--config",
            r#"{"pattern":"^nothing-has-this-name$"}"#,
            "--repo",
            &repo,
        ]));
        let id = policy["id"].as_str().unwrap().to_string();
        guard.policies.push(id.clone());
        for args in [
            vec!["lifecycle", "attach", &id, &other],
            vec!["lifecycle", "detach", &id, &other],
            vec!["lifecycle", "update", &id, "--repos", &other],
            vec!["lifecycle", "update", &id, "--all-repos", "true", "--yes"],
            vec!["lifecycle", "capabilities"],
        ] {
            env.ak_cmd()
                .args(&args)
                .assert()
                .failure()
                .stderr(predicates::str::contains("1.11"));
        }
        return;
    }

    let capabilities = json_output(env.ak_cmd().args(["lifecycle", "capabilities"]));
    assert_eq!(capabilities["explicit_repository_assignment"], true);

    // Disabled, or the scheduler can run it first and delete what the preview counts.
    let policy = json_output(env.ak_cmd().args([
        "lifecycle",
        "create",
        &format!("e2e-attach-{suffix}"),
        "--policy-type",
        "tag_pattern_delete",
        "--config",
        &config,
        "--repos",
        &format!("{repo},{other}"),
        "--disabled",
    ]));
    assert_eq!(policy["enabled"], false);
    let id = policy["id"].as_str().unwrap().to_string();
    guard.policies.push(id.clone());
    let (repo_id, other_id) = (repo_id_of(&env, &repo), repo_id_of(&env, &other));
    let ids = |policy: &Value| -> Vec<String> {
        let mut ids: Vec<String> = policy["repository_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| id.as_str().unwrap().to_string())
            .collect();
        ids.sort();
        ids
    };
    let mut both = vec![repo_id.clone(), other_id.clone()];
    both.sort();
    assert_eq!(ids(&policy), both);
    assert_eq!(matched(&env, &id), 2);

    // By key, as a user knows it.
    let detached = json_output(env.ak_cmd().args(["lifecycle", "detach", &id, &other]));
    assert_eq!(ids(&detached), vec![repo_id.clone()]);
    assert_eq!(matched(&env, &id), 1);

    let attached = json_output(env.ak_cmd().args(["lifecycle", "attach", &id, &other]));
    assert_eq!(ids(&attached), both);
    assert_eq!(matched(&env, &id), 2);

    let updated = json_output(
        env.ak_cmd()
            .args(["lifecycle", "update", &id, "--repos", &repo]),
    );
    assert_eq!(ids(&updated), vec![repo_id.clone()]);

    let cleared = json_output(
        env.ak_cmd()
            .args(["lifecycle", "update", &id, "--repos", ""]),
    );
    assert!(ids(&cleared).is_empty(), "{cleared}");
    assert_eq!(matched(&env, &id), 0);

    let global = json_output(env.ak_cmd().args([
        "lifecycle",
        "update",
        &id,
        "--all-repos",
        "true",
        "--yes",
    ]));
    assert_eq!(global["applies_to_all"], true);
    // A policy on every repository can't name any.
    env.ak_cmd()
        .args(["lifecycle", "attach", &id, &repo])
        .assert()
        .failure();
    let local =
        json_output(
            env.ak_cmd()
                .args(["lifecycle", "update", &id, "--all-repos", "false"]),
        );
    assert_eq!(local["applies_to_all"], false);
}
