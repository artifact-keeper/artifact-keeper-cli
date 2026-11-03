//! What `ak scan` sends and how it reads the answer. Contract, not E2E: these run
//! against a mock server, for what the plain backend can't do (a rescan's verdict
//! needs a scanner) or shouldn't be asked to. The same commands reach a real backend
//! in `tests/e2e_scan.rs`.

#[path = "common/mock.rs"]
mod mock;

use mock::{Mocked, unwrapped};
use serde_json::{Value, json};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

const ID: &str = "00000000-0000-0000-0000-000000000011";

fn config() -> Value {
    json!({
        "id": ID, "repository_id": ID, "scan_enabled": true, "scan_on_upload": true,
        "scan_on_proxy": false, "block_on_policy_violation": false, "severity_threshold": "high",
        "proxy_scan_action": "fail_open", "created_at": "2026-01-15T12:00:00Z",
        "updated_at": "2026-01-15T12:00:00Z", "new_on_the_server": 1
    })
}

fn policy() -> Value {
    json!({
        "id": ID, "name": "p", "max_severity": "high", "block_on_fail": true,
        "block_unscanned": false, "is_enabled": true, "require_signature": true,
        "created_at": "2026-01-15T12:00:00Z", "updated_at": "2026-01-15T12:00:00Z",
        "new_on_the_server": 1
    })
}

fn verdict() -> Value {
    json!({
        "repository_key": "rem", "path": "a/b", "digest": "abc", "state": "vulnerable",
        "max_severity": "high", "findings_count": 2, "critical_count": 0, "high_count": 2,
        "medium_count": 0, "low_count": 0, "package_count": 3,
        "findings": [{"cve_id": "CVE-1", "severity": "high"}], "new_on_the_server": 1
    })
}

#[tokio::test]
async fn a_rescan_sends_the_path_and_prints_the_verdict() {
    let mocked = Mocked::start().await;
    mocked
        .respond(
            "POST",
            "/api/v1/repositories/rem/security/proxy-scans/rescan",
            200,
            verdict(),
        )
        .await;
    let shown = mocked.json(&["scan", "proxy", "rescan", "rem", "--path", "a/b"]);
    assert_eq!(shown, verdict());
    let (_, body) = mocked.last("POST").await;
    assert_eq!(body, json!({"path": "a/b"}));

    let output = mocked.ak(&[
        "scan", "proxy", "rescan", "rem", "--path", "a/b", "--format", "table",
    ]);
    assert!(
        unwrapped(&output.stderr).contains("a/b: vulnerable (2 finding(s): C:0 H:2 M:0 L:0)"),
        "{}",
        unwrapped(&output.stderr)
    );
}

#[tokio::test]
async fn proxy_list_shows_what_blocked_a_path() {
    let mocked = Mocked::start().await;
    let body = json!({
        "repository_key": "rem", "scan_on_proxy": true, "proxy_scan_action": "block",
        "items": [{
            "path": "a/b", "state": "vulnerable", "cached_at": "2026-01-15T12:00:00Z",
            "size_bytes": 1, "findings_count": 1, "high_count": 1,
            "findings": [{"cve_id": "CVE-2021-44228", "severity": "high",
                          "package_name": "log4j", "fixed_version": "2.17"}]
        }],
        "total": 1, "page": 2, "per_page": 3, "new_on_the_server": 1
    });
    Mock::given(method("GET"))
        .and(path("/api/v1/repositories/rem/security/proxy-scans"))
        .and(query_param("path", "a/b"))
        .and(query_param("page", "2"))
        .and(query_param("per_page", "3"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body))
        .mount(&mocked.server)
        .await;
    let args = [
        "scan",
        "proxy",
        "list",
        "rem",
        "--path",
        "a/b",
        "--page",
        "2",
        "--per-page",
        "3",
    ];
    assert_eq!(mocked.json(&args), body);

    let mut table = args.to_vec();
    table.extend(["--format", "table"]);
    let output = mocked.ak(&table);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("CVE-2021-44228"), "{stdout}");
    assert!(stdout.contains("2.17"), "{stdout}");
}

/// This used to send `false` for every flag not given, so setting one turned
/// scanning and blocking off.
#[tokio::test]
async fn security_update_sends_only_what_it_is_given() {
    let mocked = Mocked::start().await;
    mocked
        .respond("PUT", "/api/v1/repositories/r/security", 200, config())
        .await;
    let shown = mocked.json(&["scan", "security", "update", "r", "--scan-on-upload"]);
    assert_eq!(shown, config());
    let (_, body) = mocked.last("PUT").await;
    assert_eq!(body, json!({"scan_on_upload": true}));

    mocked.json(&[
        "scan",
        "security",
        "update",
        "r",
        "--scan-on-proxy",
        "false",
    ]);
    let (_, body) = mocked.last("PUT").await;
    assert_eq!(body, json!({"scan_on_proxy": false}));
}

#[tokio::test]
async fn security_update_with_nothing_to_do_sends_nothing() {
    let mocked = Mocked::start().await;
    let output = mocked.ak(&["scan", "security", "update", "r"]);
    assert!(!output.status.success());
    assert!(unwrapped(&output.stderr).contains("Nothing to update"));
    assert!(mocked.server.received_requests().await.unwrap().is_empty());
}

/// A mistyped predicate would otherwise be dropped, and the policy would allow what
/// it was written to block.
#[tokio::test]
async fn a_mistyped_predicate_is_refused_at_any_depth() {
    let mocked = Mocked::start().await;
    let output = mocked.ak(&[
        "scan",
        "policy",
        "create",
        "p",
        "--max-severity",
        "high",
        "--predicates",
        r#"{"conda":{"denied_licenses":["gpl"],"denied_chanels":["x"]}}"#,
    ]);
    assert!(!output.status.success());
    assert!(
        unwrapped(&output.stderr).contains("conda.denied_chanels"),
        "{}",
        unwrapped(&output.stderr)
    );
    assert!(mocked.server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn policy_update_sends_only_what_it_is_given() {
    let mocked = Mocked::start().await;
    mocked
        .respond(
            "PUT",
            &format!("/api/v1/security/policies/{ID}"),
            200,
            policy(),
        )
        .await;
    let shown = mocked.json(&[
        "scan",
        "policy",
        "update",
        ID,
        "--max-artifact-age-days",
        "4",
    ]);
    assert_eq!(shown, policy());
    let (_, body) = mocked.last("PUT").await;
    assert_eq!(body, json!({"max_artifact_age_days": 4}));
}

#[tokio::test]
async fn a_whole_repository_scan_sends_its_id() {
    let mocked = Mocked::start().await;
    mocked
        .respond(
            "GET",
            "/api/v1/repositories/r",
            200,
            json!({"id": ID, "key": "r", "name": "r", "format": "generic", "repo_type": "local",
                   "is_public": false, "allow_anonymous_access": false, "promotion_only": false,
                   "versioning_enabled": false, "storage_used_bytes": 0, "has_trusted_gpg_key": false,
                   "upstream_auth_configured": false, "curation_enabled": false,
                   "curation_default_action": "allow", "created_at": "2026-01-15T12:00:00Z",
                   "updated_at": "2026-01-15T12:00:00Z"}),
        )
        .await;
    let body = json!({"message": "queued", "artifacts_queued": 3, "new_on_the_server": 1});
    mocked
        .respond("POST", "/api/v1/security/scan", 200, body.clone())
        .await;
    assert_eq!(mocked.json(&["scan", "run", "r", "--bypass-dedup"]), body);
    let (_, sent) = mocked.last("POST").await;
    assert_eq!(sent, json!({"repository_id": ID, "bypass_dedup": true}));
}

/// `--severity` filters on this side, so the printed body has to agree with it.
#[tokio::test]
async fn the_severity_filter_applies_to_the_printed_body() {
    let mocked = Mocked::start().await;
    mocked
        .respond(
            "GET",
            &format!("/api/v1/security/scans/{ID}"),
            200,
            json!({
                "id": ID, "artifact_id": ID, "repository_id": ID, "scan_type": "external",
                "status": "completed", "findings_count": 2, "critical_count": 0, "high_count": 0,
                "medium_count": 1, "low_count": 1, "info_count": 0, "is_reused": false,
                "scan_completeness": "full", "created_at": "2026-01-15T12:00:00Z"
            }),
        )
        .await;
    let finding = |id: &str, severity: &str| {
        json!({
            "id": id, "scan_result_id": ID, "artifact_id": ID, "severity": severity, "title": "t",
            "is_acknowledged": false, "finding_class": "vulnerability",
            "created_at": "2026-01-15T12:00:00Z"
        })
    };
    let medium = finding("00000000-0000-0000-0000-000000000021", "medium");
    let low = finding("00000000-0000-0000-0000-000000000022", "low");
    mocked
        .respond(
            "GET",
            &format!("/api/v1/security/scans/{ID}/findings"),
            200,
            json!({"items": [medium, low], "total": 2}),
        )
        .await;
    let shown = mocked.json(&["scan", "show", ID, "--severity", "medium"]);
    assert_eq!(shown["items"], json!([medium]));
}

#[tokio::test]
async fn ingest_refuses_a_mistyped_finding_before_sending() {
    let mocked = Mocked::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let file = dir.path().join("f.json");
    std::fs::write(&file, r#"[{"title":"t","severity":"high","cve":"CVE-1"}]"#).unwrap();
    let output = mocked.ak(&[
        "scan",
        "finding",
        "ingest",
        file.to_str().unwrap(),
        "--artifact",
        ID,
        "--scanner",
        "s",
    ]);
    assert!(!output.status.success());
    assert!(
        unwrapped(&output.stderr).contains("cve"),
        "{}",
        unwrapped(&output.stderr)
    );
    assert!(mocked.server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_decision_on_a_finding_needs_yes_with_no_terminal() {
    let dir = tempfile::TempDir::new().unwrap();
    let file = dir.path().join("f.json");
    std::fs::write(&file, r#"[{"title":"t","severity":"high"}]"#).unwrap();
    let file = file.to_str().unwrap();
    for args in [
        vec!["scan", "finding", "ack", ID, "--reason", "r"],
        vec!["scan", "finding", "revoke", ID],
        vec![
            "scan",
            "finding",
            "ingest",
            file,
            "--artifact",
            ID,
            "--scanner",
            "s",
        ],
    ] {
        let mocked = Mocked::start().await;
        let output = mocked.ak_prompting(&args);
        assert!(!output.status.success(), "{args:?}");
        assert!(
            unwrapped(&output.stderr).contains("--yes"),
            "{args:?}: {}",
            unwrapped(&output.stderr)
        );
        assert!(
            mocked.server.received_requests().await.unwrap().is_empty(),
            "{args:?}"
        );
    }
}
