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
async fn wait_takes_a_job_that_left_objects_behind_as_done_with_a_warning() {
    let server = deleting(ResponseTemplate::new(202).set_body_json(job("pending"))).await;
    let mut ended = job("completed_with_errors");
    ended["failed_items"] = json!(2);
    ended["error_summary"] = json!("2 objects not deleted: a/b\u{1b}[31m, c/d");
    job_answers(&server, ResponseTemplate::new(200).set_body_json(ended)).await;

    let output = ak(
        &server,
        &["--format", "json", "repo", "delete", "r", "--yes", "--wait"],
    );
    assert!(output.status.success(), "{output:?}");
    let printed: Value = serde_json::from_slice(&output.stdout).expect("JSON output");
    assert_eq!(printed["status"], "completed_with_errors");
    let stderr = one_line(&output);
    assert!(
        stderr.contains("Warning") && stderr.contains("2 of its stored objects"),
        "{stderr}"
    );
    assert!(stderr.contains("2 objects not deleted: a/b"), "{stderr}");
    // The server's words reach a terminal, without its escape sequences.
    assert!(!stderr.contains('\u{1b}'), "{stderr}");
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

// ---- version checks ----

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

/// A repository flag needs no version check.
#[tokio::test]
async fn repo_flags_need_no_version_check() {
    let server = server_on("1.11.10").await;
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

// ---- #310: curation ----

fn staging() -> Value {
    let mut repo = repository();
    repo["repo_type"] = json!("staging");
    repo
}

#[tokio::test]
async fn create_links_a_source_and_then_sets_curation() {
    let server = server_on("1.12.1").await;
    Mock::given(method("POST"))
        .and(path("/api/v1/repositories"))
        .respond_with(ResponseTemplate::new(200).set_body_json(staging()))
        .expect(1)
        .mount(&server)
        .await;
    let mut enabled = staging();
    enabled["curation_enabled"] = json!(true);
    enabled["curation_default_action"] = json!("review");
    Mock::given(method("PATCH"))
        .and(path("/api/v1/repositories/r"))
        .respond_with(ResponseTemplate::new(200).set_body_json(enabled))
        .expect(1)
        .mount(&server)
        .await;

    let output = ak(
        &server,
        &[
            "--format",
            "json",
            "repo",
            "create",
            "r",
            "--pkg-format",
            "rpm",
            "--repo-type",
            "staging",
            "--curation-source",
            "upstream",
            "--curation-enabled",
            "true",
            "--curation-default-action",
            "review",
        ],
    );
    assert!(output.status.success(), "{output:?}");
    let requests = server.received_requests().await.expect("recorded");
    let body = |verb: &str| -> Value {
        let request = requests
            .iter()
            .find(|r| r.method.as_str() == verb)
            .expect("request");
        serde_json::from_slice(&request.body).expect("JSON body")
    };
    let created = body("POST");
    assert_eq!(created["curation_source_repository_key"], "upstream");
    // The server refuses these on create, so they wait for the PATCH.
    assert!(created.get("curation_enabled").is_none(), "{created}");
    assert!(
        created.get("curation_default_action").is_none(),
        "{created}"
    );
    assert_eq!(
        body("PATCH"),
        json!({"curation_enabled": true, "curation_default_action": "review"})
    );
    // What it prints is the repository as the PATCH left it.
    let printed: Value = serde_json::from_slice(&output.stdout).expect("JSON output");
    assert_eq!(printed["curation_enabled"], true);
}

#[tokio::test]
async fn create_without_curation_flags_sends_one_request() {
    let server = accepting("POST", "/api/v1/repositories").await;
    let output = ak(&server, &["repo", "create", "r", "--pkg-format", "rpm"]);
    assert!(output.status.success(), "{output:?}");
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "{requests:?}");
}

#[tokio::test]
async fn a_failed_curation_update_says_the_repository_was_created() {
    let server = accepting("POST", "/api/v1/repositories").await;
    Mock::given(method("PATCH"))
        .and(path("/api/v1/repositories/r"))
        .respond_with(
            ResponseTemplate::new(400).set_body_json(json!({"message": "curation is broken"})),
        )
        .mount(&server)
        .await;
    let output = ak(
        &server,
        &[
            "repo",
            "create",
            "r",
            "--pkg-format",
            "rpm",
            "--curation-enabled",
            "true",
        ],
    );
    assert_eq!(output.status.code(), Some(6), "{output:?}");
    let stderr = one_line(&output);
    assert!(
        stderr.contains("Created repository 'r'")
            && stderr.contains("curation is broken")
            && stderr.contains("ak repo update r"),
        "{stderr}"
    );
}

#[tokio::test]
async fn curation_default_action_takes_only_what_the_server_does() {
    let server = MockServer::start().await;
    let output = ak(
        &server,
        &["repo", "update", "r", "--curation-default-action", "block"],
    );
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn update_removes_a_source_with_an_empty_key() {
    let server = server_on("1.12.1").await;
    Mock::given(method("PATCH"))
        .and(path("/api/v1/repositories/r"))
        .respond_with(ResponseTemplate::new(200).set_body_json(staging()))
        .expect(1)
        .mount(&server)
        .await;
    let output = ak(&server, &["repo", "update", "r", "--curation-source", ""]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        sent_body(&server).await,
        json!({"curation_source_repository_key": ""})
    );
}

#[tokio::test]
async fn a_curation_source_is_refused_on_1_11_before_anything_changes() {
    for command in [
        vec![
            "repo",
            "create",
            "r",
            "--pkg-format",
            "rpm",
            "--curation-source",
            "s",
        ],
        vec!["repo", "update", "r", "--curation-source", "s"],
    ] {
        let server = server_on("1.11.14").await;
        let output = ak(&server, &command);
        assert_eq!(output.status.code(), Some(6), "{output:?}");
        let stderr = one_line(&output);
        assert!(
            stderr.contains("--curation-source needs a server on 1.12")
                && stderr.contains("1.11.14"),
            "{stderr}"
        );
        let requests = server.received_requests().await.expect("recorded");
        assert!(
            requests.iter().all(|r| r.url.path() == "/health"),
            "{requests:?}"
        );
    }
}

// ---- #313: 1.12 repository settings ----

#[tokio::test]
async fn create_sends_the_1_12_settings_and_links_the_release_repository_after() {
    let server = server_on("1.12.1").await;
    Mock::given(method("POST"))
        .and(path("/api/v1/repositories"))
        .respond_with(ResponseTemplate::new(200).set_body_json(repository()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/api/v1/repositories/r"))
        .respond_with(ResponseTemplate::new(200).set_body_json(repository()))
        .expect(1)
        .mount(&server)
        .await;

    let output = ak(
        &server,
        &[
            "repo",
            "create",
            "r",
            "--pkg-format",
            "rpm",
            "--repo-type",
            "remote",
            "--upstream-url",
            "https://mirror.example.com/el9",
            "--quarantine-enabled",
            "true",
            "--quarantine-duration-minutes",
            "90",
            "--virtual-metadata-partial",
            "false",
            "--upstream-mode",
            "cache_only",
            "--egress-proxy-mode",
            "explicit",
            "--egress-proxy-url",
            "http://proxy.example.com:3128",
            "--egress-no-proxy",
            "internal.example.com",
            "--repodata-mode",
            "on_request",
            "--virtual-member-fallback",
            "strict",
            "--release-repository-key",
            "release",
        ],
    );
    assert!(output.status.success(), "{output:?}");
    let requests = server.received_requests().await.expect("recorded");
    let body = |verb: &str| -> Value {
        let request = requests
            .iter()
            .find(|r| r.method.as_str() == verb)
            .expect("request");
        serde_json::from_slice(&request.body).expect("JSON body")
    };
    let created = body("POST");
    assert_eq!(created["quarantine_enabled"], true);
    assert_eq!(created["quarantine_duration_minutes"], 90);
    assert_eq!(created["virtual_metadata_partial"], false);
    assert_eq!(created["upstream_mode"], "cache_only");
    assert_eq!(
        created["egress_proxy"],
        json!({"mode": "explicit", "proxy_url": "http://proxy.example.com:3128",
               "no_proxy": "internal.example.com"})
    );
    assert_eq!(created["repodata_mode"], "on_request");
    assert_eq!(created["virtual_member_fallback"], "strict");
    // The server refuses a release repository on create (#5324).
    assert!(created.get("release_repository_key").is_none(), "{created}");
    assert_eq!(body("PATCH"), json!({"release_repository_key": "release"}));
}

#[tokio::test]
async fn create_reads_the_egress_proxy_url_from_stdin() {
    let server = accepting("POST", "/api/v1/repositories").await;
    let dir = TempDir::new().expect("temp dir");
    std::fs::write(
        dir.path().join("config.toml"),
        format!(
            "default_instance = \"t\"\n[instances.t]\nurl = \"{}\"\napi_version = \"v1\"\n",
            server.uri()
        ),
    )
    .expect("write config");
    let output = Command::cargo_bin("ak")
        .expect("ak binary")
        .env_remove("AK_FORMAT")
        .env("AK_CONFIG_DIR", dir.path())
        .env("AK_TOKEN", "t")
        .env("AK_CREDENTIAL_STORE", "file")
        .args([
            "--no-input",
            "repo",
            "create",
            "r",
            "--pkg-format",
            "npm",
            "--repo-type",
            "remote",
            "--upstream-url",
            "https://registry.example.com",
            "--egress-proxy-mode",
            "explicit",
            "--egress-proxy-url-stdin",
        ])
        .write_stdin("http://u:secret@proxy.example.com:3128\n")
        .output()
        .expect("run ak");
    assert!(output.status.success(), "{output:?}");
    let body = sent_body(&server).await;
    assert_eq!(
        body["egress_proxy"]["proxy_url"],
        "http://u:secret@proxy.example.com:3128"
    );
}

#[tokio::test]
async fn an_egress_proxy_url_needs_a_mode() {
    let server = MockServer::start().await;
    let output = ak(
        &server,
        &[
            "repo",
            "create",
            "r",
            "--pkg-format",
            "npm",
            "--egress-proxy-url",
            "http://proxy.example.com",
        ],
    );
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn create_with_only_default_follow_ups_sends_one_request() {
    let server = accepting("POST", "/api/v1/repositories").await;
    let output = ak(
        &server,
        &[
            "repo",
            "create",
            "r",
            "--pkg-format",
            "rpm",
            "--curation-enabled",
            "false",
            "--curation-default-action",
            "allow",
            "--release-repository-key",
            "",
        ],
    );
    assert!(output.status.success(), "{output:?}");
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "{requests:?}");
}

#[tokio::test]
async fn update_sends_the_1_12_settings() {
    let server = server_on("1.12.1").await;
    Mock::given(method("PATCH"))
        .and(path("/api/v1/repositories/r"))
        .respond_with(ResponseTemplate::new(200).set_body_json(repository()))
        .expect(1)
        .mount(&server)
        .await;
    let output = ak(
        &server,
        &[
            "repo",
            "update",
            "r",
            "--repodata-mode",
            "precomputed",
            "--virtual-member-fallback",
            "available",
        ],
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        sent_body(&server).await,
        json!({"repodata_mode": "precomputed", "virtual_member_fallback": "available"})
    );
}

#[tokio::test]
async fn the_1_12_settings_are_refused_on_1_11_before_anything_changes() {
    let create = |extra: &[&'static str]| {
        let mut args = vec!["repo", "create", "r", "--pkg-format", "rpm"];
        args.extend_from_slice(extra);
        args
    };
    for (args, flag) in [
        (
            create(&["--quarantine-enabled", "true"]),
            "--quarantine-enabled",
        ),
        (
            create(&["--quarantine-duration-minutes", "5"]),
            "--quarantine-duration-minutes",
        ),
        (
            create(&["--virtual-metadata-partial", "true"]),
            "--virtual-metadata-partial",
        ),
        (create(&["--upstream-mode", "online"]), "--upstream-mode"),
        (
            create(&["--egress-proxy-mode", "direct"]),
            "--egress-proxy-mode",
        ),
        (
            create(&["--repodata-mode", "precomputed"]),
            "--repodata-mode",
        ),
        (
            create(&["--virtual-member-fallback", "strict"]),
            "--virtual-member-fallback",
        ),
        (
            vec!["repo", "update", "r", "--repodata-mode", "on_request"],
            "--repodata-mode",
        ),
        (
            vec!["repo", "update", "r", "--virtual-member-fallback", "strict"],
            "--virtual-member-fallback",
        ),
    ] {
        let server = server_on("1.11.14").await;
        let output = ak(&server, &args);
        assert_eq!(output.status.code(), Some(6), "{args:?}: {output:?}");
        let stderr = one_line(&output);
        assert!(
            stderr.contains(&format!("{flag} needs a server on 1.12"))
                && stderr.contains("1.11.14"),
            "{stderr}"
        );
        let requests = server.received_requests().await.expect("recorded");
        assert!(
            requests.iter().all(|r| r.url.path() == "/health"),
            "{requests:?}"
        );
    }
}

/// 1.11 takes these on update, and `repo create` sends them in the update that
/// follows, so they need no 1.12 server.
#[tokio::test]
async fn a_release_repository_on_create_goes_through_on_1_11() {
    let server = server_on("1.11.14").await;
    Mock::given(method("POST"))
        .and(path("/api/v1/repositories"))
        .respond_with(ResponseTemplate::new(200).set_body_json(staging()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/api/v1/repositories/r"))
        .respond_with(ResponseTemplate::new(200).set_body_json(staging()))
        .expect(1)
        .mount(&server)
        .await;
    let output = ak(
        &server,
        &[
            "repo",
            "create",
            "r",
            "--pkg-format",
            "rpm",
            "--repo-type",
            "staging",
            "--release-repository-key",
            "release",
        ],
    );
    assert!(output.status.success(), "{output:?}");
}

#[tokio::test]
async fn the_left_behind_warning_is_one_line_and_quiet_leaves_out_the_server_text() {
    let mut ended = job("completed_with_errors");
    ended["failed_items"] = json!(2);
    ended["error_summary"] = json!("2 objects not deleted:\na/b\nc/d");

    let server = deleting(ResponseTemplate::new(202).set_body_json(job("pending"))).await;
    job_answers(
        &server,
        ResponseTemplate::new(200).set_body_json(ended.clone()),
    )
    .await;
    let output = ak(
        &server,
        &[
            "--format", "table", "repo", "delete", "r", "--yes", "--wait",
        ],
    );
    assert!(output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let warning: Vec<&str> = stderr.lines().filter(|l| l.contains("Warning")).collect();
    assert_eq!(warning.len(), 1, "{stderr}");
    assert!(
        warning[0].contains("2 objects not deleted: a/b c/d"),
        "{stderr}"
    );

    let server = deleting(ResponseTemplate::new(202).set_body_json(job("pending"))).await;
    job_answers(&server, ResponseTemplate::new(200).set_body_json(ended)).await;
    let output = ak(
        &server,
        &[
            "--format", "quiet", "repo", "delete", "r", "--yes", "--wait",
        ],
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), JOB);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stderr.trim().lines().count(), 1, "{stderr}");
    assert!(stderr.contains("2 of its stored objects"), "{stderr}");
    assert!(!stderr.contains("a/b"), "{stderr}");
}
