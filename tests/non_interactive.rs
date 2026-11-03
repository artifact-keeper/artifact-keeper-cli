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

/// These prompts report their own failure, naming what they were asking for.
#[test]
fn a_secret_prompt_with_no_terminal_says_what_to_do() {
    let dir = TempDir::new().unwrap();
    config(&dir, "http://127.0.0.1:1");
    for args in [vec!["totp", "disable"], vec!["profile", "change-password"]] {
        let output = Command::cargo_bin("ak")
            .unwrap()
            .env_remove("AK_NO_INPUT")
            .env("AK_CONFIG_DIR", dir.path())
            .env("AK_TOKEN", "t")
            .env("AK_CREDENTIAL_STORE", "file")
            .args(&args)
            .write_stdin("")
            .output()
            .unwrap();
        assert!(!output.status.success());
        // A diagnostic wraps its lines, which can fall inside the phrase.
        let stderr = String::from_utf8_lossy(&output.stderr)
            .split_whitespace()
            .filter(|word| *word != "│")
            .collect::<Vec<_>>()
            .join(" ");
        assert!(stderr.contains("no terminal"), "{args:?}: {stderr}");
        assert!(!stderr.contains("IO error"), "{args:?}: {stderr}");
    }
}

/// A server's message can say anything. It's shown as it is, and it can't make
/// `ak` give advice about prompts when there wasn't one.
#[tokio::test]
async fn a_server_message_saying_not_a_terminal_is_shown_as_it_is() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/repositories"))
        .respond_with(
            ResponseTemplate::new(400).set_body_json(json!({"message": "this is not a terminal"})),
        )
        .mount(&server)
        .await;
    let dir = TempDir::new().unwrap();
    config(&dir, &server.uri());
    let config_dir = dir.path().to_path_buf();

    let output = tokio::task::spawn_blocking(move || {
        Command::cargo_bin("ak")
            .unwrap()
            .env_remove("AK_NO_INPUT")
            .env("AK_CONFIG_DIR", config_dir)
            .env("AK_TOKEN", "t")
            .env("AK_CREDENTIAL_STORE", "file")
            .args(["repo", "list"])
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ak::server_error"), "{stderr}");
    // One word, because the message wraps at the width of the output.
    assert!(stderr.contains("terminal"), "{stderr}");
    assert!(!stderr.contains("--no-input"), "{stderr}");
}

const ID: &str = "00000000-0000-4000-8000-000000000001";

/// What `--no-input` must not answer. Each has to fail and send nothing, with the flag
/// and with the variable, and each goes ahead with `--yes`.
const NEED_YES: &[&[&str]] = &[
    &["quarantine", "release", ID],
    &["quarantine", "release-proxy", "r", "--path", "p"],
    &["quarantine", "reject", ID],
    &["quarantine", "hold", ID],
    &["curation", "approve", ID],
    &["curation", "block", ID],
    &["sign", "key", "revoke", ID],
    &["sign", "key", "rotate", ID],
    &["repo", "delete", "r"],
    &["artifact", "delete", "r", "p"],
    &["import", "job", "delete", ID],
    &["import", "source", "delete", ID],
    &["admin", "backup", "restore", ID],
];

fn ak(dir: &TempDir, env_no_input: Option<&str>, args: &[&str]) -> std::process::Output {
    let mut command = Command::cargo_bin("ak").unwrap();
    command
        .env_remove("AK_NO_INPUT")
        .env_remove("AK_FORMAT")
        .env("AK_CONFIG_DIR", dir.path())
        .env("AK_TOKEN", "t")
        .env("AK_CREDENTIAL_STORE", "file")
        .env("NO_COLOR", "1")
        .args(args)
        .write_stdin("");
    if let Some(value) = env_no_input {
        command.env("AK_NO_INPUT", value);
    }
    command.output().unwrap()
}

/// A diagnostic wraps its lines, which can fall inside a phrase.
fn unwrapped(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .split_whitespace()
        .filter(|word| *word != "│")
        .collect::<Vec<_>>()
        .join(" ")
}

#[tokio::test(flavor = "multi_thread")]
async fn no_input_is_not_a_yes() {
    let server = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({"message": "reached"})))
        .mount(&server)
        .await;
    let dir = TempDir::new().unwrap();
    config(&dir, &server.uri());

    for args in NEED_YES {
        let with_flag = [&["--no-input"], *args].concat();
        for output in [
            ak(&dir, None, &with_flag),
            ak(&dir, Some("true"), args),
            ak(&dir, Some("1"), args),
            ak(&dir, Some("yes"), args),
        ] {
            assert_eq!(output.status.code(), Some(2), "{args:?}");
            let stderr = unwrapped(&output.stderr);
            assert!(stderr.contains("Nothing was done"), "{args:?}: {stderr}");
            assert!(stderr.contains("Pass --yes"), "{args:?}: {stderr}");
        }
        let sent = server.received_requests().await.unwrap();
        assert!(sent.is_empty(), "{args:?} sent {sent:?}");
    }

    for args in NEED_YES {
        server.reset().await;
        Mock::given(wiremock::matchers::any())
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({"message": "reached"})))
            .mount(&server)
            .await;
        let with_yes = [&["--no-input"], *args, &["--yes"]].concat();
        let output = ak(&dir, None, &with_yes);
        let stderr = unwrapped(&output.stderr);
        assert!(!stderr.contains("Nothing was done"), "{args:?}: {stderr}");
        let sent = server.received_requests().await.unwrap();
        assert!(!sent.is_empty(), "{args:?} sent nothing with --yes");
    }
}

/// Only what decides something changes. `--no-input` still runs everything else.
#[tokio::test(flavor = "multi_thread")]
async fn no_input_still_runs_what_has_no_confirmation() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/repositories"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({"message": "reached"})))
        .mount(&server)
        .await;
    let dir = TempDir::new().unwrap();
    config(&dir, &server.uri());
    let output = ak(&dir, None, &["--no-input", "repo", "list"]);
    assert!(!unwrapped(&output.stderr).contains("Nothing was done"));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

/// It used to make every command exit 2, with any value but `true` or `false`.
#[tokio::test(flavor = "multi_thread")]
async fn ak_no_input_takes_the_values_ci_systems_set() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/repositories"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({"message": "reached"})))
        .mount(&server)
        .await;
    let dir = TempDir::new().unwrap();
    config(&dir, &server.uri());
    let values = ["1", "true", "yes", "0", "false", "no", ""];
    for value in values {
        let output = ak(&dir, Some(value), &["repo", "list"]);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{value:?}: reached the server"
        );
    }
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        values.len()
    );
    let bad = ak(&dir, Some("maybe"), &["repo", "list"]);
    assert_eq!(bad.status.code(), Some(2));
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        values.len()
    );
}

/// Off means prompts are on, so with no terminal a delete still has nobody to ask.
#[tokio::test(flavor = "multi_thread")]
async fn ak_no_input_off_never_authorises_anything() {
    let server = MockServer::start().await;
    let dir = TempDir::new().unwrap();
    config(&dir, &server.uri());
    for value in ["0", "false", "no", ""] {
        let output = ak(&dir, Some(value), &["repo", "delete", "r"]);
        assert_eq!(output.status.code(), Some(2), "{value:?}");
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn short_y_consents() {
    let server = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({"message": "reached"})))
        .mount(&server)
        .await;
    let dir = TempDir::new().unwrap();
    config(&dir, &server.uri());
    ak(&dir, Some("1"), &["repo", "delete", "r", "-y"]);
    assert!(!server.received_requests().await.unwrap().is_empty());
}

#[test]
fn the_help_says_what_no_input_means() {
    let output = Command::cargo_bin("ak")
        .unwrap()
        .arg("--help")
        .output()
        .unwrap();
    let help = unwrapped(&output.stdout);
    assert!(help.contains("need --yes"), "{help}");
}
