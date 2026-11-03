//! `--format json` and `yaml` print what the server sent, so a field the SDK has
//! never heard of still reaches the user. Each command here is one that has
//! moved to `output::render_raw`.

use std::process::Output;

use assert_cmd::Command;
use serde_json::{Value, json};
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const UUID: &str = "00000000-0000-0000-0000-000000000001";

fn repository() -> Value {
    json!({
        "id": UUID, "key": "r", "name": "r", "format": "generic", "repo_type": "local",
        "visibility": "private", "is_public": false, "allow_anonymous_access": false,
        "promotion_only": false, "versioning_enabled": false, "repodata_depth": 0,
        "repodata_depth_editable": false, "storage_backend": "filesystem",
        "storage_used_bytes": 0, "has_trusted_gpg_key": false,
        "upstream_url_has_credentials": false, "upstream_auth_configured": false,
        "public_with_upstream_credentials": false,
        "allow_public_with_upstream_credentials": false, "curation_enabled": false,
        "curation_default_action": "allow", "created_at": "2026-01-15T12:00:00Z",
        "updated_at": "2026-01-15T12:00:00Z", "from_a_newer_server": {"nested": [1, 2]}
    })
}

fn artifact() -> Value {
    json!({
        "id": UUID, "repository_key": "r", "path": "a.bin", "name": "a.bin",
        "size_bytes": 3, "checksum_sha256": "abc", "content_type": "text/plain",
        "download_count": 0, "created_at": "2026-01-15T12:00:00Z", "analyzable": false,
        "quarantine_status": "clean", "from_a_newer_server": {"nested": [1, 2]}
    })
}

fn list_of(item: Value) -> Value {
    json!({
        "items": [item],
        "pagination": {"page": 1, "per_page": 20, "total": 1, "total_pages": 1},
        "from_a_newer_server": true
    })
}

async fn run(route: &str, verb: &str, body: &Value, args: &[&str]) -> Output {
    let server = MockServer::start().await;
    Mock::given(method(verb))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
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
        .env_remove("AK_FORMAT")
        .env("AK_CONFIG_DIR", dir.path())
        .env("AK_TOKEN", "t")
        .env("AK_CREDENTIAL_STORE", "file")
        .args(["--no-input"])
        .args(args)
        .output()
        .expect("run ak")
}

async fn assert_prints_the_body(route: &str, verb: &str, body: Value, args: &[&str]) {
    let mut with_format = args.to_vec();
    with_format.extend(["--format", "json"]);
    let output = run(route, verb, &body, &with_format).await;
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(output.status.code(), Some(0), "{args:?}: {stderr}");
    let shown: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("{args:?}: not JSON: {e}"));
    assert_eq!(shown, body, "{args:?}");

    let mut with_format = args.to_vec();
    with_format.extend(["--format", "yaml"]);
    let output = run(route, verb, &body, &with_format).await;
    let shown: Value = serde_yaml::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("{args:?}: not YAML: {e}"));
    assert_eq!(shown, body, "{args:?}");
}

#[tokio::test]
async fn repo_commands() {
    assert_prints_the_body(
        "/api/v1/repositories",
        "GET",
        list_of(repository()),
        &["repo", "list"],
    )
    .await;
    assert_prints_the_body(
        "/api/v1/repositories/r",
        "GET",
        repository(),
        &["repo", "show", "r"],
    )
    .await;
    assert_prints_the_body(
        "/api/v1/repositories",
        "POST",
        repository(),
        &["repo", "create", "r", "--pkg-format", "generic"],
    )
    .await;
}

#[tokio::test]
async fn artifact_commands() {
    assert_prints_the_body(
        "/api/v1/repositories/r/artifacts",
        "GET",
        list_of(artifact()),
        &["artifact", "list", "r"],
    )
    .await;
    assert_prints_the_body(
        "/api/v1/repositories/r/artifacts/a.bin",
        "GET",
        artifact(),
        &["artifact", "info", "r", "a.bin"],
    )
    .await;
    assert_prints_the_body(
        &format!("/api/v1/artifacts/{UUID}"),
        "GET",
        artifact(),
        &["artifact", "show", UUID],
    )
    .await;
}

#[tokio::test]
async fn whoami() {
    assert_prints_the_body(
        "/api/v1/auth/me",
        "GET",
        json!({
            "id": UUID, "username": "admin", "email": "a@example.com", "is_admin": true,
            "totp_enabled": false, "from_a_newer_server": 1
        }),
        &["auth", "whoami"],
    )
    .await;
}

#[tokio::test]
async fn an_empty_list_still_prints_the_body() {
    let empty = json!({
        "items": [],
        "pagination": {"page": 1, "per_page": 20, "total": 0, "total_pages": 0}
    });
    assert_prints_the_body("/api/v1/repositories", "GET", empty, &["repo", "list"]).await;
}

#[tokio::test]
async fn the_table_is_unchanged() {
    let output = run(
        "/api/v1/repositories/r",
        "GET",
        &repository(),
        &["repo", "show", "r", "--format", "table"],
    )
    .await;
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Key:"), "{stdout}");
    assert!(!stdout.contains("from_a_newer_server"), "{stdout}");
}
