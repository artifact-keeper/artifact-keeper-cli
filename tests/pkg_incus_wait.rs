//! How `ak pkg incus publish` waits for an image the server stores in the background.
//! Contract, not E2E: a real server can't be made to fail or stall on request. The real
//! success path is in `tests/e2e_pkg_system.rs`.

use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const SESSION: &str = "00000000-0000-4000-8000-000000000001";

/// Each poll gets the next answer, and the last one for ever after.
struct Polls {
    answers: Vec<Value>,
    seen: AtomicUsize,
}

impl Respond for Polls {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        let at = self.seen.fetch_add(1, Ordering::SeqCst);
        let answer = &self.answers[at.min(self.answers.len() - 1)];
        ResponseTemplate::new(200).set_body_json(answer)
    }
}

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
    polls: usize,
}

async fn publish(answers: Vec<Value>, extra: &[&str]) -> Run {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/incus/r/images/p/1/incus.tar.xz"))
        .respond_with(
            ResponseTemplate::new(202)
                .set_body_json(json!({"session_id": SESSION, "status": "finalizing"})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/incus/r/uploads/{SESSION}")))
        .respond_with(Polls {
            answers,
            seen: AtomicUsize::new(0),
        })
        .mount(&server)
        .await;
    let home = tempfile::TempDir::new().unwrap();
    let file = home.path().join("incus.tar.xz");
    std::fs::write(&file, "image").unwrap();
    std::fs::write(
        home.path().join("config.toml"),
        format!(
            "default_instance = \"t\"\n[instances.t]\nurl = \"{}\"\napi_version = \"v1\"\n",
            server.uri()
        ),
    )
    .unwrap();
    let extra: Vec<String> = extra.iter().map(|s| s.to_string()).collect();
    let home_path = home.path().to_path_buf();
    let output = tokio::task::spawn_blocking(move || {
        assert_cmd::Command::cargo_bin("ak")
            .unwrap()
            .env_clear()
            .env("AK_TOKEN", "t")
            .env("HOME", &home_path)
            .env("AK_CONFIG_DIR", &home_path)
            .env("AK_CREDENTIAL_STORE", "file")
            .env("NO_COLOR", "1")
            .args(["--no-input", "--format", "json"])
            .args(["pkg", "incus", "publish", "r", "p", "1"])
            .arg(home_path.join("incus.tar.xz"))
            .args(extra)
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    let polls = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.method.as_str() == "GET" && r.url.path().contains("/uploads/"))
        .count();
    Run {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        polls,
    }
}

#[tokio::test]
async fn it_returns_when_the_server_has_stored_the_image() {
    let run = publish(
        vec![
            json!({"status": "finalizing"}),
            json!({"status": "finalizing"}),
            json!({"status": "completed", "artifact_id": "a"}),
        ],
        &[],
    )
    .await;
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(run.polls, 3);
    // The session's final state, which has the artifact.
    assert!(run.stdout.contains("\"artifact_id\""), "{}", run.stdout);
}

#[tokio::test]
async fn a_failed_store_is_a_failed_publish() {
    let run = publish(
        vec![json!({"status": "failed", "finalize_error": "disk full"})],
        &[],
    )
    .await;
    assert_eq!(run.code, Some(7));
    assert!(run.stderr.contains("disk full"), "{}", run.stderr);
    // miette wraps long lines, at a hyphen too, and draws a border in the wrap.
    let unwrapped: String = run.stderr.replace('│', "").split_whitespace().collect();
    assert!(unwrapped.contains(SESSION), "{}", run.stderr);
}

#[tokio::test]
async fn a_session_handed_back_is_a_failed_publish() {
    let run = publish(
        vec![json!({"status": "receiving", "finalize_error": "storage hiccup"})],
        &[],
    )
    .await;
    assert_eq!(run.code, Some(7));
    assert!(run.stderr.contains("storage hiccup"), "{}", run.stderr);
}

#[tokio::test]
async fn it_gives_up_at_the_timeout_and_says_how_to_look() {
    let run = publish(
        vec![json!({"status": "finalizing"})],
        &["--wait-timeout", "0"],
    )
    .await;
    assert_eq!(run.code, Some(6));
    assert!(run.stderr.contains("still storing"), "{}", run.stderr);
    assert!(run.stderr.contains("/incus/r/uploads/"), "{}", run.stderr);
}

#[tokio::test]
async fn no_wait_doesnt_ask() {
    let run = publish(vec![json!({"status": "failed"})], &["--no-wait"]).await;
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(run.polls, 0);
    assert!(run.stdout.contains("finalizing"), "{}", run.stdout);
}
