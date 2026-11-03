//! E2E tests for `ak quarantine` and `ak attestation` against a real backend.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use common::TestEnv;
use serde_json::Value;
use tempfile::TempDir;

const UPSTREAM: &str = "http://ak-upstream:8080/api/v1/repositories";

fn unique(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4().simple())
}

fn json_of(env: &TestEnv, args: &[&str]) -> Value {
    let output = env.ak_cmd().args(args).output().unwrap();
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("stdout isn't JSON")
}

fn stderr_of(env: &TestEnv, args: &[&str]) -> String {
    let output = env.ak_cmd().args(args).output().unwrap();
    assert!(!output.status.success(), "{args:?} should fail");
    String::from_utf8_lossy(&output.stderr)
        .split_whitespace()
        .filter(|word| *word != "│")
        .collect::<Vec<_>>()
        .join(" ")
}

fn repo_with_file(env: &TestEnv, public: bool) -> String {
    let key = unique("quar");
    let mut args = vec!["repo", "create", &key, "--pkg-format", "generic"];
    if public {
        args.push("--public");
    }
    env.ak_cmd().args(&args).assert().success();
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("f.bin");
    std::fs::write(&file, unique("content")).unwrap();
    env.ak_cmd()
        .args([
            "artifact",
            "push",
            &key,
            file.to_str().unwrap(),
            "--path",
            "f.bin",
        ])
        .assert()
        .success();
    key
}

fn download_status(env: &TestEnv, repo: &str) -> reqwest::StatusCode {
    env.api_client()
        .get(format!(
            "{}/api/v1/repositories/{repo}/download/f.bin",
            env.url
        ))
        .bearer_auth(&env.token)
        .send()
        .unwrap()
        .status()
}

/// A proxied artifact is held on its way in, and only `release-proxy` can reach it,
/// because it has no artifact ID.
#[test]
#[ignore = "requires E2E backend"]
fn a_held_cached_path_is_released_and_its_download_works() {
    let env = TestEnv::setup();
    let upstream = repo_with_file(&env, true);
    let remote = unique("quar-remote");
    env.ak_cmd()
        .args([
            "repo",
            "create",
            &remote,
            "--pkg-format",
            "generic",
            "--repo-type",
            "remote",
            "--upstream-url",
            &format!("{UPSTREAM}/{upstream}/download"),
        ])
        .assert()
        .success();

    if common::server_older_than(1, 11, "POST /quarantine/proxy-cache/{repo}/release") {
        let refused = stderr_of(
            &env,
            &[
                "quarantine",
                "release-proxy",
                &remote,
                "--path",
                "f.bin",
                "--yes",
            ],
        );
        assert!(refused.contains("needs a server on 1.11"), "{refused}");
        return;
    }

    env.ak_cmd()
        .args([
            "repo",
            "update",
            &remote,
            "--quarantine-enabled",
            "true",
            "--quarantine-duration-minutes",
            "60",
        ])
        .assert()
        .success();

    assert_eq!(download_status(&env, &remote), 409);
    assert!(
        stderr_of(
            &env,
            &[
                "quarantine",
                "release-proxy",
                &remote,
                "--path",
                "missing",
                "--yes"
            ]
        )
        .contains("404")
    );

    let released = json_of(
        &env,
        &[
            "quarantine",
            "release-proxy",
            &remote,
            "--path",
            "f.bin",
            "--yes",
        ],
    );
    assert_eq!(released["released"], true);
    assert_eq!(released["path"], "f.bin");
    assert_eq!(released["repository"], remote.as_str());
    assert_eq!(download_status(&env, &remote), 200);

    let again = stderr_of(
        &env,
        &[
            "quarantine",
            "release-proxy",
            &remote,
            "--path",
            "f.bin",
            "--yes",
        ],
    );
    assert!(again.contains("409"), "{again}");
}

#[test]
#[ignore = "requires E2E backend"]
fn a_hosted_artifact_is_held_and_released() {
    let env = TestEnv::setup();
    let repo = repo_with_file(&env, false);
    let artifact = format!("{repo}/f.bin");

    let held = json_of(
        &env,
        &[
            "quarantine",
            "hold",
            &artifact,
            "--reason",
            "suspicious",
            "--yes",
        ],
    );
    assert_eq!(held["new_status"], "quarantined", "{held}");
    assert_eq!(download_status(&env, &repo), 409);

    let status = json_of(&env, &["quarantine", "status", &artifact]);
    assert_eq!(status["is_blocked"], true, "{status}");

    let released = json_of(&env, &["quarantine", "release", &artifact, "--yes"]);
    assert_eq!(released["new_status"], "released", "{released}");
    assert_eq!(download_status(&env, &repo), 200);

    json_of(&env, &["quarantine", "hold", &artifact, "--yes"]);
    let rejected = json_of(
        &env,
        &[
            "quarantine",
            "reject",
            &artifact,
            "--reason",
            "malware",
            "--yes",
        ],
    );
    assert_eq!(rejected["artifact_id"], status["artifact_id"], "{rejected}");
    assert_ne!(download_status(&env, &repo), 200);
}

#[test]
#[ignore = "requires E2E backend"]
fn the_attestation_policy_is_shown_on_1_11_and_says_so_on_1_10() {
    let env = TestEnv::setup();
    if common::server_older_than(1, 11, "GET /attestations/policy") {
        let refused = stderr_of(&env, &["attestation", "policy"]);
        assert!(refused.contains("needs a server on 1.11"), "{refused}");
        return;
    }
    let policy = json_of(&env, &["attestation", "policy"]);
    assert!(policy["require_verified"].is_boolean(), "{policy}");
    assert!(policy["issuers"].is_array(), "{policy}");
    assert!(policy["keys"].is_array(), "{policy}");
}
