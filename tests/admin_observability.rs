//! Contract, not E2E: what the admin observability commands send and print,
//! against a mock server. `e2e_admin_observability.rs` runs them for real.

use std::process::Output;

use assert_cmd::Command;
use serde_json::{Value, json};
use tempfile::TempDir;
use wiremock::matchers::{body_json, method, path, query_param};
use wiremock::{Mock, MockBuilder, MockServer, ResponseTemplate};

const UUID: &str = "00000000-0000-0000-0000-000000000001";
const UUID2: &str = "00000000-0000-0000-0000-000000000002";
const UUID3: &str = "00000000-0000-0000-0000-000000000003";
const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

async fn ak(server: &MockServer, args: &[&str]) -> Output {
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
        .env_remove("AK_NO_INPUT")
        .env("AK_CONFIG_DIR", dir.path())
        .env("AK_TOKEN", "t")
        .env("AK_CREDENTIAL_STORE", "file")
        .args(args)
        .output()
        .expect("run ak")
}

/// Mount `mock` to answer once with `body`, run `args` with JSON output, and
/// check that it printed the body it was sent. The mock's matchers check the
/// request. A newer server's field has to survive.
async fn check(mock: MockBuilder, mut body: Value, args: &[&str]) {
    body["from_a_newer_server"] = json!(true);
    let server = MockServer::start().await;
    mock.respond_with(ResponseTemplate::new(200).set_body_json(&body))
        .expect(1)
        .mount(&server)
        .await;
    let mut all = vec!["--format", "json"];
    all.extend_from_slice(args);
    let output = ak(&server, &all).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{args:?}: {stderr}");
    let printed: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("{args:?}: not JSON: {e}: {stderr}"));
    assert_eq!(printed, body, "{args:?}");
}

fn downloads() -> Value {
    json!({"downloads": [], "total": 0, "page": 3, "per_page": 7})
}

fn blast_radius() -> Value {
    json!({
        "target": {"kind": "cve", "value": "CVE-1"},
        "summary": {
            "affected_artifact_count": 1, "affected_repo_count": 1, "downloader_user_count": 1,
            "anonymous_download_present": false, "distinct_ip_count": 1, "total_download_count": 1
        },
        "proxy_exposure": {
            "coverage": "included", "affected_digest_count": 0, "affected_repo_count": 0,
            "download_count": 0, "downloader_user_count": 0, "anonymous_download_present": false
        },
        "affected_repos": [],
        "downloaders": [],
        "total_downloaders": 0,
        "page": 3,
        "per_page": 7
    })
}

fn accessible_users() -> Value {
    json!({
        "target": {"kind": "cve", "value": "CVE-1"},
        "repository": {"repository_id": UUID, "repository_key": "r", "access_scope": "public"},
        "exposure": "enumerable",
        "accessible_not_downloaded": [],
        "page": 3,
        "per_page": 7
    })
}

fn verdicts() -> Value {
    json!({
        "digest": DIGEST,
        "verdicts": [{
            "checksum_sha256": "a", "scan_type": "trivy", "verdict": "clean", "findings_count": 0,
            "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0,
            "scanned_at": "2026-01-15T12:00:00Z"
        }]
    })
}

fn review() -> Value {
    json!({
        "id": UUID, "repository_key": "r", "package_name": "p", "package_version": "1",
        "status": "pending", "requested_at": "2026-01-15T12:00:00Z", "request_count": 1,
        "last_requested_at": "2026-01-15T12:00:00Z"
    })
}

#[tokio::test]
async fn audit_list_sends_every_filter() {
    check(
        Mock::given(method("GET"))
            .and(path("/api/v1/admin/audit"))
            .and(query_param("user_id", UUID))
            .and(query_param("action", "LOGIN"))
            .and(query_param("resource_type", "user"))
            .and(query_param("resource_id", UUID2))
            .and(query_param("correlation_id", "c"))
            .and(query_param("from", "2026-01-01T00:00:00Z"))
            .and(query_param("to", "2026-01-02T00:00:00Z"))
            .and(query_param("page", "3"))
            .and(query_param("per_page", "7")),
        json!({"items": [], "total": 0, "page": 3, "per_page": 7}),
        &[
            "admin",
            "audit",
            "list",
            "--user",
            UUID,
            "--action",
            "LOGIN",
            "--resource-type",
            "user",
            "--resource-id",
            UUID2,
            "--correlation-id",
            "c",
            "--from",
            "2026-01-01T00:00:00Z",
            "--to",
            "2026-01-02T00:00:00Z",
            "--page",
            "3",
            "--per-page",
            "7",
        ],
    )
    .await;
}

#[tokio::test]
async fn downloads_list_sends_every_filter() {
    check(
        Mock::given(method("GET"))
            .and(path("/api/v1/admin/downloads"))
            .and(query_param("artifact_id", UUID))
            .and(query_param("user_id", UUID2))
            .and(query_param("ip", "10.0.0.1"))
            .and(query_param("from", "a"))
            .and(query_param("to", "b"))
            .and(query_param("source", "proxy"))
            .and(query_param("repository_id", UUID3))
            .and(query_param("page", "3"))
            .and(query_param("per_page", "7")),
        downloads(),
        &[
            "admin",
            "downloads",
            "list",
            "--artifact",
            UUID,
            "--user",
            UUID2,
            "--ip",
            "10.0.0.1",
            "--from",
            "a",
            "--to",
            "b",
            "--source",
            "proxy",
            "--repo",
            UUID3,
            "--page",
            "3",
            "--per-page",
            "7",
        ],
    )
    .await;
}

#[tokio::test]
async fn downloads_by_ip_and_by_user_send_every_filter() {
    let filters = [
        "--artifact",
        UUID2,
        "--source",
        "hosted",
        "--repo",
        UUID3,
        "--from",
        "a",
        "--to",
        "b",
        "--page",
        "3",
        "--per-page",
        "7",
    ];
    for (route, command, other) in [
        (
            "/api/v1/admin/downloads/by-ip/10.0.0.1".to_string(),
            ["admin", "downloads", "by-ip", "10.0.0.1", "--user", UUID],
            ("user_id", UUID),
        ),
        (
            format!("/api/v1/admin/downloads/by-user/{UUID}"),
            ["admin", "downloads", "by-user", UUID, "--ip", "10.0.0.1"],
            ("ip", "10.0.0.1"),
        ),
    ] {
        let mut args = command.to_vec();
        args.extend_from_slice(&filters);
        check(
            Mock::given(method("GET"))
                .and(path(route))
                .and(query_param(other.0, other.1))
                .and(query_param("artifact_id", UUID2))
                .and(query_param("source", "hosted"))
                .and(query_param("repository_id", UUID3))
                .and(query_param("from", "a"))
                .and(query_param("to", "b"))
                .and(query_param("page", "3"))
                .and(query_param("per_page", "7")),
            downloads(),
            &args,
        )
        .await;
    }
}

#[tokio::test]
async fn blast_radius_sends_every_filter() {
    let window = ["--from", "a", "--to", "b", "--page", "3", "--per-page", "7"];
    for (route, command) in [
        (
            format!("/api/v1/admin/security/artifact/{UUID}/blast-radius"),
            vec!["admin", "blast-radius", "artifact", UUID],
        ),
        (
            "/api/v1/admin/security/cve/CVE-1/blast-radius".to_string(),
            vec!["admin", "blast-radius", "cve", "CVE-1"],
        ),
    ] {
        let mut args = command;
        args.extend_from_slice(&window);
        check(
            Mock::given(method("GET"))
                .and(path(route))
                .and(query_param("from", "a"))
                .and(query_param("to", "b"))
                .and(query_param("page", "3"))
                .and(query_param("per_page", "7")),
            blast_radius(),
            &args,
        )
        .await;
    }
}

#[tokio::test]
async fn accessible_users_sends_every_filter() {
    let filters = [
        "--accessible-users",
        "--repo",
        UUID2,
        "--page",
        "3",
        "--per-page",
        "7",
    ];
    for (route, command) in [
        (
            format!("/api/v1/admin/security/artifact/{UUID}/accessible-users"),
            vec!["admin", "blast-radius", "artifact", UUID],
        ),
        (
            "/api/v1/admin/security/cve/CVE-1/accessible-users".to_string(),
            vec!["admin", "blast-radius", "cve", "CVE-1"],
        ),
    ] {
        let mut args = command;
        args.extend_from_slice(&filters);
        check(
            Mock::given(method("GET"))
                .and(path(route))
                .and(query_param("repository_id", UUID2))
                .and(query_param("page", "3"))
                .and(query_param("per_page", "7")),
            accessible_users(),
            &args,
        )
        .await;
    }
}

#[tokio::test]
async fn window_flags_do_not_apply_to_accessible_users() {
    let server = MockServer::start().await;
    let output = ak(
        &server,
        &[
            "admin",
            "blast-radius",
            "cve",
            "CVE-1",
            "--accessible-users",
            "--from",
            "a",
        ],
    )
    .await;
    assert!(!output.status.success());
    let output = ak(
        &server,
        &["admin", "blast-radius", "cve", "CVE-1", "--repo", "r"],
    )
    .await;
    assert!(!output.status.success());
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn proxy_scan_verdict_show() {
    check(
        Mock::given(method("GET")).and(path(format!("/api/v1/admin/proxy-scan-verdicts/{DIGEST}"))),
        verdicts(),
        &["admin", "proxy-scan-verdict", "show", DIGEST],
    )
    .await;
}

#[tokio::test]
async fn proxy_scan_verdict_delete_with_yes() {
    check(
        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/admin/proxy-scan-verdicts/{DIGEST}"))),
        verdicts(),
        &["admin", "proxy-scan-verdict", "delete", DIGEST, "--yes"],
    )
    .await;
}

#[tokio::test]
async fn proxy_scan_verdict_delete_without_yes_sends_nothing() {
    let server = MockServer::start().await;
    let output = ak(&server, &["admin", "proxy-scan-verdict", "delete", DIGEST]).await;
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--yes"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn npm_feed_status() {
    check(
        Mock::given(method("GET")).and(path("/api/v1/admin/npm/upstream-feed/status")),
        json!({
            "replica_id": "r", "enabled": false, "feed_url": "u", "consumer_running": false,
            "is_leader": false, "cluster_leader_active": false, "leader_term_secs": 300
        }),
        &["admin", "npm-feed", "status"],
    )
    .await;
}

#[tokio::test]
async fn holds_quarantine_sends_every_filter() {
    check(
        Mock::given(method("GET"))
            .and(path("/api/v1/admin/holds/quarantine"))
            .and(query_param("repository_key", "r"))
            .and(query_param("kind", "active"))
            .and(query_param("page", "3"))
            .and(query_param("per_page", "7")),
        json!({
            "items": [],
            "pagination": {"page": 3, "per_page": 7, "total": 0, "total_pages": 0}
        }),
        &[
            "admin",
            "holds",
            "quarantine",
            "--repo",
            "r",
            "--kind",
            "active",
            "--page",
            "3",
            "--per-page",
            "7",
        ],
    )
    .await;
}

#[tokio::test]
async fn holds_summary() {
    check(
        Mock::given(method("GET")).and(path("/api/v1/admin/holds/summary")),
        json!({"age_gate_pending": 1, "quarantine_active": 2, "quarantine_rejected": 3}),
        &["admin", "holds", "summary"],
    )
    .await;
}

#[tokio::test]
async fn age_gate_reopen_sends_the_reason() {
    check(
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/admin/age-gate/reviews/{UUID}/reopen"
            )))
            .and(body_json(json!({"reason": "second look"}))),
        review(),
        &["age-gate", "reopen", UUID, "--reason", "second look"],
    )
    .await;
}

#[tokio::test]
async fn quality_checks_all_sends_every_filter() {
    check(
        Mock::given(method("GET"))
            .and(path("/api/v1/admin/quality-checks"))
            .and(query_param("artifact_id", UUID))
            .and(query_param("repository_id", UUID2))
            .and(query_param("status", "failed"))
            .and(query_param("page", "3"))
            .and(query_param("per_page", "7")),
        json!({"items": [], "total": 0, "page": 3, "per_page": 7}),
        &[
            "quality-gate",
            "checks",
            "--all",
            "--artifact",
            UUID,
            "--repo",
            UUID2,
            "--status",
            "failed",
            "--page",
            "3",
            "--per-page",
            "7",
        ],
    )
    .await;
}

#[tokio::test]
async fn quality_checks_for_an_artifact_filters_the_body_by_repository() {
    let check_of = |repo: &str| {
        json!({
            "id": UUID3, "artifact_id": UUID, "repository_id": repo, "check_type": "t",
            "status": "completed", "issues_count": 0, "critical_count": 0, "high_count": 0,
            "medium_count": 0, "low_count": 0, "info_count": 0,
            "created_at": "2026-01-15T12:00:00Z", "from_a_newer_server": true
        })
    };
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/quality/checks"))
        .and(query_param("artifact_id", UUID))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!([check_of(UUID2), check_of(UUID3)])),
        )
        .mount(&server)
        .await;
    let output = ak(
        &server,
        &[
            "--format",
            "json",
            "quality-gate",
            "checks",
            "--artifact",
            UUID,
            "--repo",
            UUID2,
        ],
    )
    .await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    let printed: Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(printed, json!([check_of(UUID2)]));
}
