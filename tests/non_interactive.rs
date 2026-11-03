//! Running with no terminal: no hanging on stdin, and prompts say what to do.

use std::io::Write;
use std::process::Stdio;
use std::time::{Duration, Instant};

use assert_cmd::Command;
use serde_json::json;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn config(dir: &TempDir, url: &str) {
    std::fs::write(
        dir.path().join("config.toml"),
        format!("default_instance = \"t\"\n[instances.t]\nurl = \"{url}\"\napi_version = \"v1\"\n"),
    )
    .expect("write config");
}

#[tokio::test]
async fn webhook_create_with_no_input_does_not_wait_on_open_stdin() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/webhooks"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({"message": "stop here"})))
        .mount(&server)
        .await;
    let dir = TempDir::new().unwrap();
    config(&dir, &server.uri());

    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("ak"))
        .env("AK_CONFIG_DIR", dir.path())
        .env("AK_TOKEN", "t")
        .env("AK_CREDENTIAL_STORE", "file")
        .env("AK_NO_INPUT", "true")
        .args([
            "webhook",
            "create",
            "w",
            "--url",
            "http://example.test/hook",
            "--events",
            "artifact_uploaded",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // Open and silent, like a pipe a parent process never writes to.
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(b"").unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        assert!(
            Instant::now() < deadline,
            "webhook create is waiting on stdin"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    drop(stdin);
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[test]
fn a_prompt_with_no_terminal_says_what_to_do() {
    let dir = TempDir::new().unwrap();
    config(&dir, "http://127.0.0.1:1");
    let output = Command::cargo_bin("ak")
        .unwrap()
        .env_remove("AK_NO_INPUT")
        .env("AK_CONFIG_DIR", dir.path())
        .env("AK_TOKEN", "t")
        .env("AK_CREDENTIAL_STORE", "file")
        .args(["repo", "delete", "r"])
        .write_stdin("")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--yes"), "{stderr}");
    assert!(!stderr.contains("IO error"), "{stderr}");
}
