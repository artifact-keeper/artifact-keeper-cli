//! A first login, and an instance given as a URL. Against a mock server, so a
//! contract, not E2E: `e2e_auth` has the same on a real server.

use std::io::Write;
use std::process::{Output, Stdio};

use assert_cmd::cargo::cargo_bin;
use serde_json::json;
use tempfile::TempDir;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "sentinel-first-run-token";

fn user() -> serde_json::Value {
    json!({
        "id": "00000000-0000-4000-8000-000000000001",
        "username": "u",
        "email": "u@example.com",
        "display_name": null,
        "is_admin": false,
        "totp_enabled": false
    })
}

fn ak(dir: &TempDir, envs: &[(&str, &str)], args: &[&str], stdin: Option<&str>) -> Output {
    let mut cmd = std::process::Command::new(cargo_bin("ak"));
    cmd.env("AK_CONFIG_DIR", dir.path())
        .env("HOME", dir.path())
        .env("AK_CREDENTIAL_STORE", "file")
        .env("NO_COLOR", "1")
        .env("COLUMNS", "200")
        .env_remove("AK_TOKEN")
        .env_remove("AK_INSTANCE")
        .env_remove("AK_FORMAT")
        .env_remove("AK_ALLOW_INSECURE_HTTP")
        .envs(envs.iter().copied())
        .arg("--no-input")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn ak");
    if let Some(text) = stdin {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
    }
    drop(child.stdin.take());
    child.wait_with_output().expect("run ak")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr)
        .replace('│', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn config_text(dir: &TempDir) -> String {
    std::fs::read_to_string(dir.path().join("config.toml")).unwrap_or_default()
}

async fn server_taking(token: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/me"))
        .and(header("authorization", format!("Bearer {token}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(user()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/me"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"message": "bad token"})))
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn login_with_a_url_adds_the_instance_named_from_its_host() {
    let server = server_taking(TOKEN).await;
    let dir = TempDir::new().unwrap();
    let output = ak(
        &dir,
        &[],
        &["auth", "login", &server.uri(), "--token-stdin"],
        Some(TOKEN),
    );
    assert!(output.status.success(), "{output:?}");
    let config = config_text(&dir);
    assert!(
        config.contains("default_instance = \"127.0.0.1\""),
        "{config}"
    );
    assert!(config.contains(&server.uri()), "{config}");

    let output = ak(&dir, &[], &["auth", "whoami", "--format", "json"], None);
    assert!(output.status.success(), "{output:?}");
    assert!(!String::from_utf8_lossy(&output.stdout).contains(TOKEN));
}

#[tokio::test]
async fn a_failed_login_leaves_no_instance_behind() {
    let server = server_taking(TOKEN).await;
    let dir = TempDir::new().unwrap();
    let output = ak(
        &dir,
        &[],
        &["auth", "login", &server.uri(), "--token-stdin"],
        Some("wrong"),
    );
    assert_eq!(output.status.code(), Some(4), "{output:?}");
    assert!(!config_text(&dir).contains(&server.uri()));
}

#[tokio::test]
async fn logging_in_to_a_known_url_uses_that_instance() {
    let server = server_taking(TOKEN).await;
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("config.toml"),
        format!("[instances.mine]\nurl = \"{}\"\n", server.uri()),
    )
    .unwrap();
    let output = ak(
        &dir,
        &[],
        &[
            "auth",
            "login",
            &format!("{}/", server.uri()),
            "--token-stdin",
        ],
        Some(TOKEN),
    );
    assert!(output.status.success(), "{output:?}");
    assert!(
        !config_text(&dir).contains("127.0.0.1\"]"),
        "{}",
        config_text(&dir)
    );
}

#[tokio::test]
async fn a_second_server_on_the_same_host_gets_its_own_name() {
    let (first, second) = (server_taking(TOKEN).await, server_taking(TOKEN).await);
    let dir = TempDir::new().unwrap();
    for server in [&first, &second] {
        let output = ak(
            &dir,
            &[],
            &["auth", "login", &server.uri(), "--token-stdin"],
            Some(TOKEN),
        );
        assert!(output.status.success(), "{output:?}");
    }
    let config = config_text(&dir);
    assert!(
        config.contains(&first.uri()) && config.contains(&second.uri()),
        "{config}"
    );
    let port = second.address().port();
    assert!(config.contains(&format!("127.0.0.1-{port}")), "{config}");
    assert!(
        config.contains("default_instance = \"127.0.0.1\""),
        "{config}"
    );
}

#[test]
fn a_password_over_plain_http_is_still_refused_for_a_new_url() {
    let dir = TempDir::new().unwrap();
    let output = ak(
        &dir,
        &[],
        &[
            "auth",
            "login",
            "http://registry.example.invalid",
            "--username",
            "u",
            "--password-stdin",
        ],
        Some("sentinel-password"),
    );
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let text = stderr(&output);
    assert!(text.contains("Refusing to send a password"), "{text}");
    assert!(!text.contains("sentinel-password"), "{text}");
    assert!(config_text(&dir).is_empty());
}

#[tokio::test]
async fn env_vars_alone_are_enough_with_no_config_file() {
    let server = server_taking(TOKEN).await;
    let dir = TempDir::new().unwrap();
    let output = ak(
        &dir,
        &[("AK_INSTANCE", &server.uri()), ("AK_TOKEN", TOKEN)],
        &["auth", "whoami", "--format", "json"],
        None,
    );
    assert!(output.status.success(), "{output:?}");
    assert!(
        !dir.path().join("config.toml").exists(),
        "it wrote a config"
    );

    // And as a flag.
    let output = ak(
        &dir,
        &[("AK_TOKEN", TOKEN)],
        &["--instance", &server.uri(), "auth", "whoami"],
        None,
    );
    assert!(output.status.success(), "{output:?}");
}

/// A stored login is only for its own instance, even with another URL named.
#[tokio::test]
async fn a_stored_login_never_goes_to_another_url() {
    let (mine, other) = (server_taking(TOKEN).await, MockServer::start().await);
    let dir = TempDir::new().unwrap();
    let output = ak(
        &dir,
        &[],
        &["auth", "login", &mine.uri(), "--token-stdin"],
        Some(TOKEN),
    );
    assert!(output.status.success(), "{output:?}");

    let output = ak(
        &dir,
        &[("AK_INSTANCE", &other.uri())],
        &["auth", "whoami"],
        None,
    );
    assert_eq!(output.status.code(), Some(4), "{output:?}");
    assert!(
        other.received_requests().await.unwrap().is_empty(),
        "a request reached a URL with no login"
    );

    // The instance's own URL does get its login.
    let output = ak(
        &dir,
        &[("AK_INSTANCE", &mine.uri())],
        &["auth", "whoami"],
        None,
    );
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn an_empty_ak_instance_is_the_same_as_none() {
    let dir = TempDir::new().unwrap();
    let output = ak(&dir, &[("AK_INSTANCE", "")], &["auth", "whoami"], None);
    let text = stderr(&output);
    assert!(text.contains("No instance configured"), "{text}");
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn instance_add_rejects_what_isnt_a_usable_url() {
    let dir = TempDir::new().unwrap();
    for (url, says) in [
        ("registry.example.com", "no scheme"),
        ("localhost:8080", "no scheme"),
        ("ftp://registry.example.com", "https://"),
        (
            "https://u:sentinel-pw@registry.example.com",
            "username or password",
        ),
        ("https://registry.example.com?token=sentinel-pw", "query"),
    ] {
        let output = ak(&dir, &[], &["instance", "add", "x", url], None);
        assert_eq!(output.status.code(), Some(2), "{url}: {output:?}");
        let text = stderr(&output);
        assert!(text.contains(says), "{url}: {text}");
        assert!(!text.contains("sentinel-pw"), "{url}: {text}");
    }
    assert!(config_text(&dir).is_empty());
}

#[test]
fn instance_add_strips_api_v1_and_says_so() {
    let dir = TempDir::new().unwrap();
    let output = ak(
        &dir,
        &[],
        &[
            "instance",
            "add",
            "x",
            "https://registry.example.com/api/v1/",
        ],
        None,
    );
    assert!(output.status.success(), "{output:?}");
    let text = stderr(&output);
    assert!(
        text.contains("Warning") && text.contains("/api/v1"),
        "{text}"
    );
    let config = config_text(&dir);
    assert!(
        config.contains("url = \"https://registry.example.com\""),
        "{config}"
    );
}

#[test]
fn a_path_prefix_on_an_instance_url_is_kept() {
    let dir = TempDir::new().unwrap();
    let output = ak(
        &dir,
        &[],
        &["instance", "add", "x", "https://example.com/registry/"],
        None,
    );
    assert!(output.status.success(), "{output:?}");
    assert!(config_text(&dir).contains("url = \"https://example.com/registry\""));
}
