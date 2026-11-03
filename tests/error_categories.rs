//! What kind of failure a command reports, and whether it says what to do next.
//! Against a mock server, so a contract, not E2E: the E2E is in `e2e_exit_codes`.

use std::process::Output;

use assert_cmd::Command;
use serde_json::json;
use tempfile::TempDir;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "sentinel-token-for-categories";

fn ak(url: &str, dir: &TempDir, args: &[&str]) -> Output {
    std::fs::write(
        dir.path().join("config.toml"),
        format!("default_instance = \"t\"\n[instances.t]\nurl = \"{url}\"\napi_version = \"v1\"\n"),
    )
    .expect("write config");
    Command::cargo_bin("ak")
        .expect("ak binary")
        .env("AK_CONFIG_DIR", dir.path())
        .env("AK_TOKEN", TOKEN)
        .env("AK_CREDENTIAL_STORE", "file")
        .env("NO_COLOR", "1")
        .env("COLUMNS", "200")
        .env_remove("AK_INSTANCE")
        .current_dir(dir.path())
        .arg("--no-input")
        .args(args)
        .output()
        .expect("run ak")
}

/// stderr with miette's wrapping and border taken out.
fn flat(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr)
        .replace('│', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

async fn answering(status: u16, message: &str, args: &[&str]) -> String {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(".*"))
        .respond_with(
            ResponseTemplate::new(status).set_body_json(json!({"code": "X", "message": message})),
        )
        .mount(&server)
        .await;
    let dir = TempDir::new().expect("temp dir");
    let text = flat(&ak(&server.uri(), &dir, args));
    assert!(!text.contains(TOKEN), "the token was printed: {text}");
    text
}

#[tokio::test]
async fn a_401_says_to_log_in() {
    let text = answering(401, "Authentication required", &["repo", "list"]).await;
    assert!(text.contains("ak::not_authenticated"), "{text}");
    assert!(text.contains("Not authenticated"), "{text}");
    assert!(!text.contains("Server error"), "{text}");
    assert!(text.contains("ak auth login"), "{text}");
    assert!(text.contains("AK_TOKEN"), "{text}");
}

#[tokio::test]
async fn a_403_is_permission_denied_and_not_a_login_problem() {
    let text = answering(403, "Admin only", &["admin", "users", "list"]).await;
    assert!(text.contains("ak::forbidden"), "{text}");
    assert!(text.contains("Permission denied"), "{text}");
    assert!(text.contains("Admin only"), "{text}");
    assert!(text.contains("ak auth whoami"), "{text}");
    assert!(!text.contains("Server error"), "{text}");
}

#[tokio::test]
async fn a_404_is_not_found() {
    let text = answering(404, "Repository not found", &["repo", "show", "x"]).await;
    assert!(text.contains("ak::not_found"), "{text}");
    assert!(text.contains("Repository not found"), "{text}");
    assert!(!text.contains("Server error"), "{text}");
}

#[tokio::test]
async fn another_status_stays_a_server_error() {
    let text = answering(500, "Boom", &["repo", "list"]).await;
    assert!(text.contains("ak::server_error"), "{text}");
    assert!(text.contains("Boom"), "{text}");
}

#[test]
fn a_refused_connection_is_a_network_error_with_the_doctor_hint() {
    let dir = TempDir::new().expect("temp dir");
    for args in [
        &["repo", "list"][..],
        &["auth", "whoami"],
        &["artifact", "pull", "r", "f"],
    ] {
        let text = flat(&ak("http://127.0.0.1:1", &dir, args));
        assert!(text.contains("ak::network_error"), "{args:?}: {text}");
        assert!(text.contains("ak doctor"), "{args:?}: {text}");
        assert!(!text.contains("Server error"), "{args:?}: {text}");
    }
}

#[test]
fn a_network_error_doesnt_print_userinfo_or_a_query() {
    let dir = TempDir::new().expect("temp dir");
    let text = flat(&ak(
        "http://someone:sentinel-url-password@127.0.0.1:1",
        &dir,
        &["repo", "list"],
    ));
    assert!(text.contains("ak::network_error"), "{text}");
    assert!(!text.contains("sentinel-url-password"), "{text}");
}

#[test]
fn what_the_user_typed_isnt_a_configuration_error() {
    let dir = TempDir::new().expect("temp dir");
    let existing = dir.path().join("exists.bin");
    std::fs::write(&existing, b"keep").expect("write");
    let text = flat(&ak(
        "http://127.0.0.1:1",
        &dir,
        &["group", "show", "not-a-uuid"],
    ));
    assert!(text.contains("Invalid group ID"), "{text}");
    assert!(!text.contains("Configuration error"), "{text}");
    assert!(text.contains("ak::usage"), "{text}");
}

#[tokio::test]
async fn an_existing_output_file_isnt_a_configuration_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(".*"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"data".to_vec()))
        .mount(&server)
        .await;
    let dir = TempDir::new().expect("temp dir");
    std::fs::write(dir.path().join("exists.bin"), b"keep").expect("write");
    let text = flat(&ak(
        &server.uri(),
        &dir,
        &["artifact", "pull", "r", "f", "-o", "exists.bin"],
    ));
    assert!(text.contains("already exists"), "{text}");
    assert!(!text.contains("Configuration error"), "{text}");
    assert!(text.contains("ak::usage"), "{text}");
}

#[tokio::test]
async fn a_version_gate_isnt_a_server_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("^/health$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"version": "1.10.2"})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(".*"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(json!({"code": "X", "message": "nope"})),
        )
        .mount(&server)
        .await;
    let dir = TempDir::new().expect("temp dir");
    let text = flat(&ak(&server.uri(), &dir, &["attestation", "policy"]));
    assert!(text.contains("ak::unsupported_server"), "{text}");
    assert!(text.contains("needs a server on 1.11"), "{text}");
    assert!(!text.contains("Server error"), "{text}");
}
