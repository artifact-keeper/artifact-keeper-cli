//! What a failed command shows: the server's message and the status, and never
//! response headers.

use std::process::Output;

use assert_cmd::Command;
use serde_json::json;
use tempfile::TempDir;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SECRET_HEADER_VALUE: &str = "sentinel-header-value-8e2f";
const TOKEN: &str = "sentinel-request-token-41bc";

fn with_auth_headers(template: ResponseTemplate) -> ResponseTemplate {
    template
        .insert_header("set-cookie", format!("ak_session={SECRET_HEADER_VALUE}"))
        .insert_header("www-authenticate", format!("Bearer {SECRET_HEADER_VALUE}"))
        .insert_header("x-correlation-id", SECRET_HEADER_VALUE)
}

async fn run_against(template: ResponseTemplate, args: &[&str]) -> Output {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(".*"))
        .respond_with(with_auth_headers(template))
        .mount(&server)
        .await;
    let dir = TempDir::new().expect("temp dir");
    std::fs::write(
        dir.path().join("config.toml"),
        format!(
            "default_instance = \"t\"\n[instances.t]\nurl = \"{}\"\napi_version = \"v1\"\n",
            server.uri()
        ),
    )
    .expect("write config");
    Command::cargo_bin("ak")
        .expect("ak binary")
        .env("AK_CONFIG_DIR", dir.path())
        .env("AK_TOKEN", TOKEN)
        .env("AK_CREDENTIAL_STORE", "file")
        .env("NO_COLOR", "1")
        .env("COLUMNS", "200")
        .current_dir(dir.path())
        .args(["--no-input"])
        .args(args)
        .output()
        .expect("run ak")
}

fn check(output: &Output, expected: &[&str]) {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // miette wraps long lines and draws a border in the wrap.
    let flat = text
        .replace('│', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(!output.status.success(), "{flat}");
    for want in expected {
        assert!(flat.contains(want), "missing {want:?} in: {flat}");
    }
    assert!(
        !flat.contains(SECRET_HEADER_VALUE),
        "a response header was printed"
    );
    assert!(!flat.contains(TOKEN), "the request's token was printed");
    assert!(!flat.contains("headers:"), "{flat}");
    assert!(!flat.contains("Response {"), "{flat}");
}

#[tokio::test]
async fn a_documented_error_shows_the_json_message() {
    let body = json!({"code": "NOT_FOUND", "message": "Repository 'x' does not exist"});
    let output = run_against(
        ResponseTemplate::new(404).set_body_json(body),
        &["repo", "show", "x"],
    )
    .await;
    check(&output, &["404 Not Found", "Repository 'x' does not exist"]);
}

#[tokio::test]
async fn the_error_field_is_used_too() {
    let output = run_against(
        ResponseTemplate::new(403).set_body_json(json!({"error": "Blocked by policy"})),
        &["repo", "show", "x"],
    )
    .await;
    check(&output, &["403 Forbidden", "Blocked by policy"]);
}

#[tokio::test]
async fn an_undocumented_status_shows_the_message_rather_than_a_debug_dump() {
    let output = run_against(
        ResponseTemplate::new(418).set_body_json(json!({"message": "Teapot says no"})),
        &["repo", "show", "x"],
    )
    .await;
    check(&output, &["418", "Teapot says no"]);
}

#[tokio::test]
async fn artifact_pull_shows_why_a_download_was_refused() {
    let body = json!({"code": "QUARANTINED", "message": "Artifact is under quarantine hold"});
    let output = run_against(
        ResponseTemplate::new(403).set_body_json(body),
        &["artifact", "pull", "r", "a.bin", "-o", "out.bin"],
    )
    .await;
    check(
        &output,
        &["403 Forbidden", "Artifact is under quarantine hold"],
    );
}

#[tokio::test]
async fn plain_text_errors_are_shown() {
    let output = run_against(
        ResponseTemplate::new(403).set_body_string("Token does not have required scope: x"),
        &["repo", "show", "x"],
    )
    .await;
    check(&output, &["Token does not have required scope: x"]);
}

#[tokio::test]
async fn an_html_error_page_gives_just_the_status() {
    let output = run_against(
        ResponseTemplate::new(502)
            .set_body_string("<html><body>Bad Gateway from nginx</body></html>"),
        &["repo", "show", "x"],
    )
    .await;
    check(&output, &["502 Bad Gateway"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("<html>"), "{stderr}");
}
