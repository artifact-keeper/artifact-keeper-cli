//! E2E tests for `ak events tail`, against the real event stream.

mod common;

use assert_cmd::cargo::CommandCargoExt;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

#[test]
#[ignore = "requires E2E backend"]
fn tail_shows_a_change_as_it_happens() {
    let env = common::TestEnv::setup();
    let repo = format!("e2e-events-{}", std::process::id());
    let mut child = Command::cargo_bin("ak")
        .unwrap()
        .env("AK_CONFIG_DIR", env.config_dir.path())
        .args(["--no-input", "--format", "json", "events", "tail"])
        .args(["--count", "1", "--max-time", "30"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();

    // Change something only once the stream is open, or the event would be missed.
    let first: serde_json::Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
    assert_eq!(first["event"], "connected");
    env.ak_cmd()
        .args(["repo", "create", &repo, "--pkg-format", "generic"])
        .assert()
        .success();

    let change: serde_json::Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
    assert_eq!(change["event"], "entity.changed");
    assert_eq!(change["data"]["type"], "repository.created");
    assert!(child.wait().unwrap().success());
    let _ = env.api_delete(&format!("/api/v1/repositories/{repo}"));
}

#[test]
#[ignore = "requires E2E backend"]
fn tail_without_a_login_shows_the_servers_refusal() {
    let env = common::TestEnv::setup();
    let output = Command::cargo_bin("ak")
        .unwrap()
        .env("AK_CONFIG_DIR", env.config_dir.path())
        .env("AK_TOKEN", "not-a-token")
        .args(["--no-input", "events", "tail", "--max-time", "5"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("401"));
}
