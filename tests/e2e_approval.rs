//! E2E tests for `ak approval`. The server won't let anyone approve their own request,
//! so a second admin reviews.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use assert_cmd::Command;
use serde_json::{Value, json};

const REVIEWER_PASSWORD: &str = "E2e-Reviewer!2026-long";

fn json_of(cmd: &mut Command) -> Value {
    let output = cmd.output().expect("run ak");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("JSON")
}

struct Reviewer<'a> {
    env: &'a common::TestEnv,
    id: String,
    token: String,
}

impl Reviewer<'_> {
    fn ak(&self) -> Command {
        let mut cmd = Command::cargo_bin("ak").unwrap();
        cmd.env("AK_CONFIG_DIR", self.env.config_dir.path())
            .env("AK_TOKEN", &self.token)
            .args(["--no-input", "--format", "json"]);
        cmd
    }
}

impl Drop for Reviewer<'_> {
    fn drop(&mut self) {
        let _ = self.env.api_delete(&format!("/api/v1/users/{}", self.id));
    }
}

fn reviewer(env: &common::TestEnv) -> Reviewer<'_> {
    let name = format!("e2e-reviewer-{}", std::process::id());
    let created = json_of(
        env.ak_cmd()
            .args(["admin", "users", "create", &name, "--admin"])
            .args(["--email", &format!("{name}@example.com")])
            .args(["--password", REVIEWER_PASSWORD]),
    );
    let login: Value = env
        .api_client()
        .post(format!("{}/api/v1/auth/login", env.url))
        .json(&json!({"username": name, "password": REVIEWER_PASSWORD}))
        .send()
        .unwrap()
        .json()
        .unwrap();
    Reviewer {
        env,
        id: created["user"]["id"].as_str().unwrap().to_string(),
        token: login["access_token"].as_str().unwrap().to_string(),
    }
}

/// A staging repository with two artifacts, a target, and the artifacts' IDs.
fn staged(env: &common::TestEnv) -> (String, String, String, String) {
    let suffix = std::process::id();
    let (staging, target) = (format!("e2e-apr-{suffix}"), format!("e2e-apr-t-{suffix}"));
    env.ak_cmd()
        .args(["repo", "create", &staging, "--pkg-format", "generic"])
        .args(["--repo-type", "staging"])
        .assert()
        .success();
    env.ak_cmd()
        .args(["repo", "create", &target, "--pkg-format", "generic"])
        .assert()
        .success();
    let mut ids = Vec::new();
    for path in ["approved.bin", "rejected.bin"] {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), path).unwrap();
        env.ak_cmd()
            .args(["artifact", "push", &staging])
            .arg(file.path())
            .args(["--path", path])
            .assert()
            .success();
        let info = json_of(env.ak_cmd().args(["artifact", "info", &staging, path]));
        ids.push(info["id"].as_str().unwrap().to_string());
    }
    let rejected = ids.pop().unwrap();
    (staging, target, ids.pop().unwrap(), rejected)
}

#[test]
#[ignore = "requires E2E backend"]
fn a_request_is_approved_or_rejected_by_someone_else() {
    let env = common::TestEnv::setup();
    let (staging, target, approved, rejected) = staged(&env);
    let reviewer = reviewer(&env);

    // A reviewer needs a grant on both repositories, even an admin.
    for repo in [&staging, &target] {
        env.ak_cmd()
            .args(["permission", "create", "--principal", &reviewer.id])
            .args(["--principal-type", "user", "--target", repo])
            .args(["--target-type", "repository", "--actions", "read,write"])
            .assert()
            .success();
    }

    let good = json_of(env.ak_cmd().args([
        "approval", "request", &approved, "--source", &staging, "--target", &target, "--notes",
        "please",
    ]));
    let good_id = good["id"].as_str().unwrap().to_string();
    assert_eq!(good["status"], "pending");
    assert_eq!(good["notes"], "please");

    let bad = json_of(env.ak_cmd().args([
        "approval",
        "request",
        &rejected,
        "--source",
        &staging,
        "--target",
        &target,
        "--skip-policy-check",
    ]));
    let bad_id = bad["id"].as_str().unwrap().to_string();

    let pending = json_of(env.ak_cmd().args(["approval", "list", "--repo", &staging]));
    assert_eq!(pending["items"].as_array().unwrap().len(), 2, "{pending}");
    let shown = json_of(env.ak_cmd().args(["approval", "show", &good_id]));
    assert_eq!(shown["id"], good_id.as_str());

    // The requester can't approve their own.
    env.ak_cmd()
        .args(["approval", "approve", &good_id])
        .assert()
        .failure()
        .stderr(predicates::str::contains("403"));

    let done = json_of(reviewer.ak().args([
        "approval",
        "approve",
        &good_id,
        "--comment",
        "fine",
        "--skip-policy-check",
    ]));
    assert_eq!(done["status"], "approved", "{done}");
    assert_eq!(done["review_notes"], "fine");
    let there = json_of(
        env.ak_cmd()
            .args(["artifact", "info", &target, "approved.bin"]),
    );
    assert_eq!(there["path"], "approved.bin");

    let no = json_of(
        reviewer
            .ak()
            .args(["approval", "reject", &bad_id, "--comment", "no"]),
    );
    assert_eq!(no["status"], "rejected", "{no}");
    env.ak_cmd()
        .args(["artifact", "info", &target, "rejected.bin"])
        .assert()
        .failure();

    for (status, id) in [("approved", &good_id), ("rejected", &bad_id)] {
        let history = json_of(
            env.ak_cmd()
                .args(["approval", "list", "--status", status, "--repo", &staging]),
        );
        let items = history["items"].as_array().unwrap();
        assert_eq!(items.len(), 1, "{history}");
        assert_eq!(items[0]["id"], id.as_str());
    }
}
