//! What `ak repo create`, `update` and `delete` send, and how `delete` reads a
//! background job. Contract, not E2E: these run against a mock server. The same
//! commands run against a real backend in `tests/e2e_repo.rs`.

use std::process::Output;

use assert_cmd::Command;
use serde_json::{Value, json};
use tempfile::TempDir;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const JOB: &str = "00000000-0000-0000-0000-0000000000aa";
const PROJECT: &str = "00000000-0000-0000-0000-0000000000bb";

fn repository() -> Value {
    json!({
        "id": "00000000-0000-0000-0000-000000000001", "key": "r", "name": "r",
        "format": "generic", "repo_type": "local", "visibility": "private", "is_public": false,
        "allow_anonymous_access": false, "promotion_only": false, "versioning_enabled": false,
        "repodata_depth": 0, "repodata_depth_editable": false, "storage_backend": "filesystem",
        "storage_used_bytes": 0, "has_trusted_gpg_key": false,
        "upstream_url_has_credentials": false, "upstream_auth_configured": false,
        "public_with_upstream_credentials": false,
        "allow_public_with_upstream_credentials": false, "curation_enabled": false,
        "curation_default_action": "allow", "created_at": "2026-01-15T12:00:00Z",
        "updated_at": "2026-01-15T12:00:00Z"
    })
}

fn job(status: &str) -> Value {
    json!({
        "id": JOB, "job_type": "repository_delete", "status": status, "repository_key": "r",
        "status_url": format!("/api/v1/repository-deletions/{JOB}"), "error_summary": null
    })
}

fn ak(server: &MockServer, args: &[&str]) -> Output {
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

async fn sent_body(server: &MockServer) -> Value {
    let requests = server.received_requests().await.expect("recorded requests");
    serde_json::from_slice(&requests.last().expect("a request").body).expect("JSON body")
}

async fn accepting(verb: &str, route: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method(verb))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200).set_body_json(repository()))
        .mount(&server)
        .await;
    server
}

// ---- #154 ----

#[tokio::test]
async fn proxy_is_sent_as_remote_with_a_name() {
    let server = accepting("POST", "/api/v1/repositories").await;
    let output = ak(
        &server,
        &[
            "repo",
            "create",
            "mirror",
            "--pkg-format",
            "npm",
            "--repo-type",
            "proxy",
            "--upstream-url",
            "https://registry.example.com",
        ],
    );
    assert!(output.status.success(), "{output:?}");
    let body = sent_body(&server).await;
    assert_eq!(body["repo_type"], "remote");
    assert_eq!(body["name"], "mirror");
}

#[tokio::test]
async fn proxy_needs_an_upstream_like_remote_does() {
    let server = MockServer::start().await;
    let output = ak(
        &server,
        &[
            "repo",
            "create",
            "m",
            "--pkg-format",
            "npm",
            "--repo-type",
            "proxy",
        ],
    );
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("--upstream-url"));
}

#[tokio::test]
async fn repo_list_filters_proxy_as_remote() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/repositories"))
        .and(wiremock::matchers::query_param("type", "remote"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [],
            "pagination": {"page": 1, "per_page": 50, "total": 0, "total_pages": 0}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let output = ak(&server, &["repo", "list", "--repo-type", "proxy"]);
    assert!(output.status.success(), "{output:?}");
}

// ---- fields ----

#[tokio::test]
async fn create_binds_every_field() {
    let server = accepting("POST", "/api/v1/repositories").await;
    let output = ak(
        &server,
        &[
            "repo",
            "create",
            "k",
            "--pkg-format",
            "generic",
            "--repo-type",
            "remote",
            "--name",
            "N",
            "--upstream-url",
            "https://u.example.com",
            "--description",
            "D",
            "--public",
            "--allow-anonymous",
            "true",
            "--promotion-only",
            "true",
            "--quota-bytes",
            "7",
            "--index-upstream-url",
            "https://i.example.com",
            "--pypi-upstream-index-path",
            "simple",
            "--format-key",
            "fk",
            "--member",
            "a",
            "--member",
            "b=3",
            "--storage-backend",
            "s3",
            "--upstream-auth-type",
            "basic",
            "--upstream-username",
            "bob",
            "--upstream-password",
            "pw",
            "--visibility",
            "internal",
            "--allow-public-with-upstream-credentials",
            "true",
            "--project-id",
            PROJECT,
            "--versioning-enabled",
            "true",
            "--repodata-depth",
            "2",
            "--custom-user-agent",
            "ua",
            "--trusted-gpg-key",
            "KEY",
            "--curation-allow-unverified",
            "true",
            "--debian",
            r#"{"components":["main"]}"#,
            "--apt-origin",
            "o",
            "--apt-label",
            "l",
            "--apt-description",
            "d",
            "--apt-release-version",
            "v",
            "--npm-allowed-scopes",
            "@a,@b",
            "--npm-allowed-name-patterns",
            "x*",
            "--npm-allow-unscoped",
            "true",
            "--npm-virtual-isolate-hosted-names",
            "true",
            "--oci-trusted-bearer-realms",
            "https://r.example.com",
        ],
    );
    assert!(output.status.success(), "{output:?}");
    let body = sent_body(&server).await;
    assert_eq!(
        body,
        json!({
            "key": "k", "name": "N", "format": "generic", "repo_type": "remote",
            "upstream_url": "https://u.example.com", "description": "D", "is_public": true,
            "allow_anonymous_access": true, "promotion_only": true, "quota_bytes": 7,
            "index_upstream_url": "https://i.example.com", "pypi_upstream_index_path": "simple",
            "format_key": "fk",
            "member_repos": [{"repo_key": "a"}, {"repo_key": "b", "priority": 3}],
            "storage_backend": "s3", "upstream_auth_type": "basic", "upstream_username": "bob",
            "upstream_password": "pw", "visibility": "internal",
            "allow_public_with_upstream_credentials": true, "project_id": PROJECT,
            "versioning_enabled": true, "repodata_depth": 2, "custom_user_agent": "ua",
            "trusted_gpg_key": "KEY", "curation_allow_unverified": true,
            "debian": body["debian"].clone(),
            "apt_origin": "o", "apt_label": "l", "apt_description": "d",
            "apt_release_version": "v", "npm_allowed_scopes": ["@a", "@b"],
            "npm_allowed_name_patterns": ["x*"], "npm_allow_unscoped": true,
            "npm_virtual_isolate_hosted_names": true,
            "oci_trusted_bearer_realms": ["https://r.example.com"]
        })
    );
    assert_eq!(body["debian"]["components"], json!(["main"]));
}

#[tokio::test]
async fn create_says_nothing_about_public_unless_asked() {
    let server = accepting("POST", "/api/v1/repositories").await;
    let output = ak(
        &server,
        &[
            "repo",
            "create",
            "k",
            "--pkg-format",
            "generic",
            "--visibility",
            "internal",
        ],
    );
    assert!(output.status.success(), "{output:?}");
    let body = sent_body(&server).await;
    assert!(body.get("is_public").is_none(), "{body}");
    assert!(body.get("visibility").is_some(), "{body}");
}

#[tokio::test]
async fn update_binds_every_field() {
    let server = accepting("PATCH", "/api/v1/repositories/k").await;
    let output = ak(
        &server,
        &[
            "repo",
            "update",
            "k",
            "--new-key",
            "k2",
            "--name",
            "N",
            "--description",
            "D",
            "--public",
            "true",
            "--allow-anonymous",
            "true",
            "--promotion-only",
            "true",
            "--quota-bytes",
            "7",
            "--quarantine-enabled",
            "true",
            "--quarantine-duration-minutes",
            "5",
            "--index-upstream-url",
            "https://i.example.com",
            "--pypi-upstream-index-path",
            "simple",
            "--release-repository-key",
            "rel",
            "--upstream-url",
            "https://u.example.com",
            "--curation-enabled",
            "true",
            "--curation-default-action",
            "review",
            "--virtual-metadata-partial",
            "true",
            "--visibility",
            "public",
            "--allow-public-with-upstream-credentials",
            "true",
            "--project-id",
            PROJECT,
            "--versioning-enabled",
            "true",
            "--repodata-depth",
            "1",
            "--custom-user-agent",
            "",
            "--trusted-gpg-key",
            "KEY",
            "--curation-allow-unverified",
            "true",
            "--debian",
            r#"{"components":["main"]}"#,
            "--apt-origin",
            "o",
            "--apt-label",
            "l",
            "--apt-description",
            "d",
            "--apt-release-version",
            "v",
            "--npm-allowed-scopes",
            "",
            "--npm-allowed-name-patterns",
            "x*,y*",
            "--npm-allow-unscoped",
            "false",
            "--npm-virtual-isolate-hosted-names",
            "true",
            "--oci-trusted-bearer-realms",
            "https://r.example.com",
        ],
    );
    assert!(output.status.success(), "{output:?}");
    let body = sent_body(&server).await;
    assert_eq!(
        body,
        json!({
            "key": "k2", "name": "N", "description": "D", "is_public": true,
            "allow_anonymous_access": true, "promotion_only": true, "quota_bytes": 7,
            "quarantine_enabled": true, "quarantine_duration_minutes": 5,
            "index_upstream_url": "https://i.example.com", "pypi_upstream_index_path": "simple",
            "release_repository_key": "rel", "upstream_url": "https://u.example.com",
            "curation_enabled": true, "curation_default_action": "review",
            "virtual_metadata_partial": true, "visibility": "public",
            "allow_public_with_upstream_credentials": true, "project_id": PROJECT,
            "versioning_enabled": true, "repodata_depth": 1, "custom_user_agent": "",
            "trusted_gpg_key": "KEY", "curation_allow_unverified": true,
            "debian": body["debian"].clone(),
            "apt_origin": "o", "apt_label": "l", "apt_description": "d",
            "apt_release_version": "v", "npm_allowed_scopes": [],
            "npm_allowed_name_patterns": ["x*", "y*"], "npm_allow_unscoped": false,
            "npm_virtual_isolate_hosted_names": true,
            "oci_trusted_bearer_realms": ["https://r.example.com"]
        })
    );
}

#[tokio::test]
async fn clearing_a_field_sends_null_and_keeps_the_others() {
    let server = accepting("PATCH", "/api/v1/repositories/k").await;
    let output = ak(
        &server,
        &[
            "--format",
            "json",
            "repo",
            "update",
            "k",
            "--clear-project",
            "--clear-trusted-gpg-key",
            "--name",
            "N",
        ],
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        sent_body(&server).await,
        json!({"project_id": null, "trusted_gpg_key": null, "name": "N"})
    );
    let printed: Value = serde_json::from_slice(&output.stdout).expect("JSON output");
    assert_eq!(printed["key"], "r");
}

#[tokio::test]
async fn a_clear_shows_the_servers_refusal() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .respond_with(
            ResponseTemplate::new(403).set_body_json(json!({"message": "needs project admin"})),
        )
        .mount(&server)
        .await;
    let output = ak(&server, &["repo", "update", "k", "--clear-project"]);
    assert_eq!(output.status.code(), Some(4), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("403") && stderr.contains("admin"),
        "{stderr}"
    );
}

#[tokio::test]
async fn a_debian_flag_with_an_unknown_field_is_refused_before_sending() {
    let server = MockServer::start().await;
    let output = ak(
        &server,
        &[
            "repo",
            "update",
            "k",
            "--debian",
            r#"{"componets":["main"]}"#,
        ],
    );
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("componets"));
    assert!(
        server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty()
    );
}

// ---- #182: DELETE answering 202 with a job ----

async fn deleting(answer: ResponseTemplate) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/api/v1/repositories/r"))
        .respond_with(answer)
        .mount(&server)
        .await;
    server
}

async fn job_answers(server: &MockServer, answer: ResponseTemplate) {
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/repository-deletions/{JOB}")))
        .respond_with(answer)
        .mount(server)
        .await;
}

#[tokio::test]
async fn a_200_delete_still_reports_deleted() {
    let server = deleting(ResponseTemplate::new(200)).await;
    let output = ak(
        &server,
        &["--format", "json", "repo", "delete", "r", "--yes", "--wait"],
    );
    assert!(output.status.success(), "{output:?}");
    let printed: Value = serde_json::from_slice(&output.stdout).expect("JSON output");
    assert_eq!(printed["status"], "deleted");
}

#[tokio::test]
async fn a_202_delete_is_a_success_and_names_the_job() {
    let server = deleting(ResponseTemplate::new(202).set_body_json(job("pending"))).await;

    let output = ak(
        &server,
        &["--format", "json", "repo", "delete", "r", "--yes"],
    );
    assert!(output.status.success(), "{output:?}");
    let printed: Value = serde_json::from_slice(&output.stdout).expect("JSON output");
    assert_eq!(printed["id"], JOB);

    let output = ak(
        &server,
        &["--format", "quiet", "repo", "delete", "r", "--yes"],
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), JOB);

    let output = ak(
        &server,
        &["--format", "table", "repo", "delete", "r", "--yes"],
    );
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains(JOB));
}

#[tokio::test]
async fn a_202_with_a_body_it_cant_read_is_still_accepted() {
    let server = deleting(ResponseTemplate::new(202).set_body_string("ok")).await;
    let output = ak(
        &server,
        &["--format", "table", "repo", "delete", "r", "--yes"],
    );
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("accepted"));
}

#[tokio::test]
async fn wait_needs_a_job_id_to_follow() {
    let server = deleting(ResponseTemplate::new(202)).await;
    let output = ak(&server, &["repo", "delete", "r", "--yes", "--wait"]);
    assert_eq!(output.status.code(), Some(6), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("no job ID"));
}

#[tokio::test]
async fn wait_follows_the_job_to_completion() {
    let server = deleting(ResponseTemplate::new(202).set_body_json(job("pending"))).await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/repository-deletions/{JOB}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(job("running")))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    job_answers(
        &server,
        ResponseTemplate::new(200).set_body_json(job("completed")),
    )
    .await;

    let output = ak(
        &server,
        &["--format", "json", "repo", "delete", "r", "--yes", "--wait"],
    );
    assert!(output.status.success(), "{output:?}");
    let printed: Value = serde_json::from_slice(&output.stdout).expect("JSON output");
    assert_eq!(printed["status"], "completed");
}

#[tokio::test]
async fn wait_reports_a_failed_job_with_its_reason() {
    let server = deleting(ResponseTemplate::new(202).set_body_json(job("pending"))).await;
    let mut failed = job("failed");
    failed["error_summary"] = json!("storage is down");
    job_answers(&server, ResponseTemplate::new(200).set_body_json(failed)).await;

    let output = ak(&server, &["repo", "delete", "r", "--yes", "--wait"]);
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    // miette wraps long lines and draws a border in the wrap.
    let stderr = String::from_utf8_lossy(&output.stderr)
        .replace('│', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        stderr.contains("failed") && stderr.contains("storage is down"),
        "{stderr}"
    );
}

#[tokio::test]
async fn wait_gives_up_at_the_timeout_and_says_the_job_is_still_running() {
    let server = deleting(ResponseTemplate::new(202).set_body_json(job("pending"))).await;
    job_answers(
        &server,
        ResponseTemplate::new(200).set_body_json(job("running")),
    )
    .await;

    let output = ak(
        &server,
        &[
            "repo",
            "delete",
            "r",
            "--yes",
            "--wait",
            "--wait-timeout",
            "0",
        ],
    );
    assert_eq!(output.status.code(), Some(6), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("still"));
}

#[tokio::test]
async fn wait_reports_a_job_it_isnt_allowed_to_see() {
    let server = deleting(ResponseTemplate::new(202).set_body_json(job("pending"))).await;
    job_answers(
        &server,
        ResponseTemplate::new(404).set_body_json(json!({"message": "no such job"})),
    )
    .await;

    let output = ak(&server, &["repo", "delete", "r", "--yes", "--wait"]);
    assert_eq!(output.status.code(), Some(5), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("no such job"));
}

#[tokio::test]
async fn a_delete_the_server_refuses_is_still_an_error() {
    let server =
        deleting(ResponseTemplate::new(403).set_body_json(json!({"message": "not yours"}))).await;
    let output = ak(&server, &["repo", "delete", "r", "--yes"]);
    assert_eq!(output.status.code(), Some(4), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("not yours"));
}

#[tokio::test]
async fn create_defaults_the_name_to_the_key() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/repositories"))
        .and(body_partial_json(
            json!({"key": "k", "name": "k", "repo_type": "local"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(repository()))
        .expect(1)
        .mount(&server)
        .await;
    let output = ak(&server, &["repo", "create", "k", "--pkg-format", "generic"]);
    assert!(output.status.success(), "{output:?}");
}

// ---- a server before 1.11 ----

async fn server_on(version: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"version": version})))
        .mount(&server)
        .await;
    server
}

fn one_line(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr)
        .replace('│', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Sends nothing but the version check, and says what's wrong.
#[tokio::test]
async fn flags_an_older_server_would_drop_are_refused_before_anything_changes() {
    for args in [
        vec![
            "repo",
            "create",
            "k",
            "--pkg-format",
            "generic",
            "--visibility",
            "internal",
        ],
        vec![
            "repo",
            "create",
            "k",
            "--pkg-format",
            "rpm",
            "--repodata-depth",
            "2",
        ],
        vec![
            "repo",
            "create",
            "k",
            "--pkg-format",
            "npm",
            "--npm-virtual-isolate-hosted-names",
            "true",
        ],
        vec![
            "repo",
            "create",
            "k",
            "--pkg-format",
            "docker",
            "--oci-trusted-bearer-realms",
            "https://a",
        ],
        vec![
            "repo",
            "create",
            "k",
            "--pkg-format",
            "generic",
            "--allow-public-with-upstream-credentials",
            "true",
        ],
        vec!["repo", "update", "k", "--visibility", "internal"],
        vec![
            "repo",
            "update",
            "k",
            "--upstream-url",
            "https://u.example.com",
        ],
        vec!["repo", "update", "k", "--virtual-metadata-partial", "true"],
        vec!["repo", "update", "k", "--clear-project"],
        vec![
            "repo",
            "upstream-auth",
            "k",
            "--type",
            "none",
            "--allow-public-with-upstream-credentials",
            "true",
        ],
    ] {
        let server = server_on("1.10.2").await;
        let output = ak(&server, &args);
        assert_eq!(output.status.code(), Some(6), "{args:?}: {output:?}");
        let stderr = one_line(&output);
        assert!(
            stderr.contains("needs a server on 1.11 or newer. This one is 1.10.2")
                && stderr.contains("Nothing was changed"),
            "{args:?}: {stderr}"
        );
        let requests = server.received_requests().await.expect("recorded");
        assert!(
            requests.iter().all(|r| r.url.path() == "/health"),
            "{args:?}"
        );
    }
}

#[tokio::test]
async fn the_same_flags_go_through_on_a_current_server() {
    let server = server_on("1.11.10").await;
    Mock::given(method("PATCH"))
        .and(path("/api/v1/repositories/k"))
        .respond_with(ResponseTemplate::new(200).set_body_json(repository()))
        .expect(1)
        .mount(&server)
        .await;
    let output = ak(
        &server,
        &["repo", "update", "k", "--visibility", "internal"],
    );
    assert!(output.status.success(), "{output:?}");
}

/// Flags 1.10 does honour don't need a version check at all.
#[tokio::test]
async fn other_flags_go_through_on_an_older_server() {
    let server = server_on("1.10.2").await;
    Mock::given(method("PATCH"))
        .and(path("/api/v1/repositories/k"))
        .respond_with(ResponseTemplate::new(200).set_body_json(repository()))
        .expect(1)
        .mount(&server)
        .await;
    let output = ak(&server, &["repo", "update", "k", "--project-id", PROJECT]);
    assert!(output.status.success(), "{output:?}");
    let requests = server.received_requests().await.expect("recorded");
    assert!(requests.iter().all(|r| r.url.path() != "/health"));
}

/// A server with no such route answers 404 "Repository not found".
#[tokio::test]
async fn a_route_new_in_1_11_says_so_on_an_older_server() {
    for args in [
        vec!["repo", "capabilities"],
        vec!["repo", "allowlist", "get", "k"],
        vec!["repo", "allowlist", "delete", "k", "--yes"],
        vec!["repo", "allowlist", "set", "k", "--package", "a"],
        vec!["repo", "upstream-filter", "get", "k"],
        vec!["repo", "upstream-filter", "delete", "k", "--yes"],
        vec!["repo", "upstream-filter", "set", "k", "--include", "a"],
        vec!["artifact", "missing", "k", "--item", "a=1"],
        vec![
            "artifact",
            "package-analysis",
            "00000000-0000-0000-0000-000000000001",
        ],
    ] {
        let server = server_on("1.10.2").await;
        Mock::given(wiremock::matchers::any())
            .respond_with(ResponseTemplate::new(404).set_body_string("Repository not found"))
            .mount(&server)
            .await;
        let output = ak(&server, &args);
        assert_eq!(output.status.code(), Some(6), "{args:?}: {output:?}");
        let stderr = one_line(&output);
        assert!(
            stderr.contains("needs a server on 1.11 or newer. This one is 1.10.2"),
            "{args:?}: {stderr}"
        );
    }
}

/// A 404 from a server that has the route is the server's own answer.
#[tokio::test]
async fn a_404_from_a_current_server_keeps_its_message() {
    let server = server_on("1.11.10").await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "no such repo"})))
        .mount(&server)
        .await;
    let output = ak(&server, &["repo", "allowlist", "get", "k"]);
    assert_eq!(output.status.code(), Some(5), "{output:?}");
    assert!(one_line(&output).contains("no such repo"));
}
