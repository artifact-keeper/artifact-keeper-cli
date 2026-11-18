//! What the 1.12 security commands send, and how they refuse a 1.11 server: scoped
//! acknowledgements, the coverage and proxy-blocked views, the uncataloged policy,
//! instance locks, the repository's own age-gate queue, digest-bound quarantine and
//! grade status on gates and rules. Contract, not E2E: these run against a mock
//! server. The routes that a plain backend can answer are in `tests/e2e_scan.rs`.

#[path = "common/mock.rs"]
mod mock;

use mock::{Mocked, unwrapped};
use serde_json::{Value, json};

const ID: &str = "00000000-0000-0000-0000-000000000011";
const REPO: &str = "00000000-0000-0000-0000-000000000022";
const AT: &str = "2026-01-15T12:00:00Z";
const HELD: &str = "00000000-0000-0000-0000-000000000033";

/// A mock server whose `/health` reports `version`.
async fn on(version: &str) -> Mocked {
    let mocked = Mocked::start().await;
    mocked
        .respond(
            "GET",
            "/health",
            200,
            json!({"status": "healthy", "version": version, "checks": {}}),
        )
        .await;
    mocked
}

fn finding() -> Value {
    json!({
        "id": ID, "scan_result_id": ID, "artifact_id": ID, "severity": "high", "title": "t",
        "is_acknowledged": true, "created_at": AT, "finding_class": "vulnerability"
    })
}

fn acknowledgement() -> Value {
    json!({
        "id": ID, "lineage_id": ID, "checksum_sha256": "abc", "finding_class": "vulnerability",
        "advisory": "CVE-2026-1", "component": "lib", "component_version": "1.0",
        "max_severity": "high", "acknowledged_at": AT, "created_via": "api", "state": "active",
        "repository_id": null, "expires_at": "2026-12-31T00:00:00Z", "reason": "accepted"
    })
}

fn score() -> Value {
    json!({
        "id": ID, "repository_id": REPO, "score": 100, "grade": "A", "grade_status": "incomplete",
        "total_findings": 0, "critical_count": 0, "high_count": 0, "medium_count": 0,
        "low_count": 0, "acknowledged_count": 0, "calculated_at": AT, "has_failed_scan": false,
        "has_uncataloged_scan": true,
        "coverage": {"artifacts": 4, "scanned": 3, "cataloged": 2, "partial": 0, "failed": 0,
                     "uncataloged": 1, "coverage_pct": 50}
    })
}

fn review() -> Value {
    json!({
        "id": ID, "repository_key": "npm-proxy", "package_name": "left-pad",
        "package_version": "1.3.0", "status": "approved", "requested_at": AT,
        "instance_locked": false, "request_count": 2, "last_requested_at": AT
    })
}

fn gate() -> Value {
    json!({
        "id": ID, "name": "g", "action": "warn", "is_enabled": true,
        "enforce_on_download": false, "enforce_on_promotion": true, "required_checks": [],
        "accepted_grade_status": "any", "created_at": AT, "updated_at": AT
    })
}

fn rule() -> Value {
    json!({
        "id": ID, "name": "r", "source_repo_id": REPO, "target_repo_id": REPO,
        "auto_promote": false, "is_enabled": true, "require_signature": false,
        "accepted_grade_status": "incomplete", "created_at": AT, "updated_at": AT
    })
}

fn failed(output: &std::process::Output) -> String {
    assert!(!output.status.success(), "{output:?}");
    unwrapped(&output.stderr)
}

async fn paths(mocked: &Mocked) -> Vec<String> {
    mocked
        .server
        .received_requests()
        .await
        .expect("recording on")
        .iter()
        .map(|r| format!("{} {}", r.method, r.url.path()))
        .collect()
}

// ---- acknowledgements ----

#[tokio::test]
async fn ack_sends_its_scope_expiry_and_repository() {
    let mocked = on("1.12.1").await;
    let route = format!("/api/v1/security/findings/{ID}/acknowledge");
    mocked.respond("POST", &route, 200, finding()).await;
    mocked.json(&[
        "scan",
        "finding",
        "ack",
        ID,
        "--reason",
        "accepted",
        "--scope",
        "all_repositories",
        "--expires-at",
        "2026-12-31T00:00:00Z",
        "--repository-id",
        REPO,
        "--yes",
    ]);
    let (_, body) = mocked.last("POST").await;
    assert_eq!(body["reason"], "accepted");
    assert_eq!(body["scope"], "all_repositories");
    assert_eq!(body["repository_id"], REPO);
    assert_eq!(
        chrono::DateTime::parse_from_rfc3339(body["expires_at"].as_str().unwrap()).unwrap(),
        chrono::DateTime::parse_from_rfc3339("2026-12-31T00:00:00Z").unwrap()
    );
}

#[tokio::test]
async fn ack_with_only_a_reason_sends_only_the_reason() {
    let mocked = on("1.11.14").await;
    let route = format!("/api/v1/security/findings/{ID}/acknowledge");
    mocked.respond("POST", &route, 200, finding()).await;
    mocked.json(&["scan", "finding", "ack", ID, "--reason", "r", "--yes"]);
    let (_, body) = mocked.last("POST").await;
    assert_eq!(body, json!({"reason": "r"}));
}

/// A 1.11 server would take the reason and drop the scope: the decision would apply
/// wider or longer than asked.
#[tokio::test]
async fn ack_scope_is_refused_on_1_11_and_nothing_is_acknowledged() {
    let mocked = on("1.11.14").await;
    let output = mocked.ak(&[
        "scan",
        "finding",
        "ack",
        ID,
        "--reason",
        "r",
        "--expires-at",
        "2026-12-31T00:00:00Z",
        "--yes",
    ]);
    let stderr = failed(&output);
    assert!(
        stderr.contains("--expires-at needs a server on 1.12 or newer"),
        "{stderr}"
    );
    assert_eq!(paths(&mocked).await, vec!["GET /health"]);
}

#[tokio::test]
async fn an_expiry_that_is_not_a_time_is_a_usage_error() {
    let mocked = Mocked::start().await;
    let output = mocked.ak(&[
        "scan",
        "finding",
        "ack",
        ID,
        "--reason",
        "r",
        "--expires-at",
        "tomorrow",
        "--yes",
    ]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(paths(&mocked).await.is_empty());
}

#[tokio::test]
async fn unacknowledge_names_the_repository() {
    let mocked = on("1.12.1").await;
    let route = format!("/api/v1/security/findings/{ID}/acknowledge");
    mocked.respond("DELETE", &route, 200, finding()).await;
    mocked.json(&[
        "scan",
        "finding",
        "revoke",
        ID,
        "--repository-id",
        REPO,
        "--yes",
    ]);
    let (query, _) = mocked.last("DELETE").await;
    assert_eq!(query, vec![("repository_id".into(), REPO.into())]);

    let mut left = finding();
    left["is_acknowledged"] = json!(false);
    left["acknowledgements_left_effective"] = json!(2);
    let mocked = on("1.12.1").await;
    mocked.respond("DELETE", &route, 200, left).await;
    let output = mocked.ak(&[
        "scan", "finding", "revoke", ID, "--yes", "--format", "table",
    ]);
    assert!(output.status.success(), "{output:?}");
    let stderr = unwrapped(&output.stderr);
    assert!(stderr.contains("2 other decisions"), "{stderr}");
}

#[tokio::test]
async fn ack_list_sends_its_filters_and_shows_the_decisions() {
    let mocked = on("1.12.1").await;
    let body = json!({"items": [acknowledgement()], "total": 1});
    mocked
        .respond(
            "GET",
            "/api/v1/security/acknowledgements",
            200,
            body.clone(),
        )
        .await;
    let args = [
        "scan",
        "ack",
        "list",
        "--repo",
        REPO,
        "--checksum",
        "abc",
        "--advisory",
        "CVE-2026-1",
        "--include-inactive",
        "--page",
        "2",
        "--per-page",
        "5",
    ];
    assert_eq!(mocked.json(&args), body);
    let (mut query, _) = mocked.last("GET").await;
    query.sort();
    assert_eq!(
        query,
        vec![
            ("advisory".into(), "CVE-2026-1".into()),
            ("checksum_sha256".into(), "abc".into()),
            ("include_inactive".into(), "true".into()),
            ("page".into(), "2".into()),
            ("per_page".into(), "5".into()),
            ("repository_id".into(), REPO.into()),
        ]
    );

    let output = mocked.ak(&["scan", "ack", "list", "--format", "table"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    for shown in ["CVE-2026-1", "lib 1.0", "active", "2026-12-31", "all"] {
        assert!(stdout.contains(shown), "{shown}: {stdout}");
    }
}

#[tokio::test]
async fn ack_list_on_1_11_says_it_needs_1_12() {
    let mocked = on("1.11.14").await;
    mocked
        .respond(
            "GET",
            "/api/v1/security/acknowledgements",
            404,
            json!({"error": "Not found"}),
        )
        .await;
    let stderr = failed(&mocked.ak(&["scan", "ack", "list"]));
    assert!(
        stderr.contains("`ak scan ack list` needs a server on 1.12 or newer. This one is 1.11.14"),
        "{stderr}"
    );
}

#[tokio::test]
async fn ack_revoke_asks_first_and_reports_what_is_left() {
    let mocked = on("1.12.1").await;
    let route = format!("/api/v1/security/acknowledgements/{ID}");
    mocked
        .respond(
            "DELETE",
            &route,
            200,
            json!({"revoked": 2, "left_effective": 1}),
        )
        .await;

    let output = mocked.ak(&["scan", "ack", "revoke", ID]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(unwrapped(&output.stderr).contains("--yes"));
    assert!(paths(&mocked).await.is_empty());

    let output = mocked.ak(&["scan", "ack", "revoke", ID, "--yes", "--format", "table"]);
    assert!(output.status.success(), "{output:?}");
    let stderr = unwrapped(&output.stderr);
    assert!(stderr.contains("Revoked 2 decisions"), "{stderr}");
    assert!(stderr.contains("1 other decision"), "{stderr}");
}

// ---- policies, coverage and the proxy gate ----

#[tokio::test]
async fn policies_take_block_uncataloged() {
    let mocked = on("1.12.1").await;
    let policy = json!({
        "id": ID, "name": "p", "max_severity": "high", "block_on_fail": true,
        "block_unscanned": false, "block_uncataloged": true, "is_enabled": true,
        "require_signature": false, "predicates": {}, "created_at": AT, "updated_at": AT
    });
    mocked
        .respond("POST", "/api/v1/security/policies", 200, policy.clone())
        .await;
    mocked
        .respond(
            "PUT",
            &format!("/api/v1/security/policies/{ID}"),
            200,
            policy,
        )
        .await;
    mocked.json(&[
        "scan",
        "policy",
        "create",
        "p",
        "--max-severity",
        "high",
        "--block-uncataloged",
    ]);
    let (_, body) = mocked.last("POST").await;
    assert_eq!(body["block_uncataloged"], true);

    mocked.json(&[
        "scan",
        "policy",
        "update",
        ID,
        "--block-uncataloged",
        "false",
    ]);
    let (_, body) = mocked.last("PUT").await;
    assert_eq!(body, json!({"block_uncataloged": false}));
}

#[tokio::test]
async fn block_uncataloged_is_refused_on_1_11() {
    let mocked = on("1.11.14").await;
    let output = mocked.ak(&[
        "scan",
        "policy",
        "create",
        "p",
        "--max-severity",
        "high",
        "--block-uncataloged",
    ]);
    assert!(failed(&output).contains("--block-uncataloged needs a server on 1.12"));
    assert_eq!(paths(&mocked).await, vec!["GET /health"]);
}

#[tokio::test]
async fn the_uncataloged_policy_is_set_and_the_new_score_shown() {
    let mocked = on("1.12.1").await;
    let body = json!({"uncataloged_policy": "warn", "score": score()});
    mocked
        .respond(
            "PUT",
            "/api/v1/repositories/r/security/uncataloged-policy",
            200,
            body.clone(),
        )
        .await;
    assert_eq!(
        mocked.json(&[
            "scan",
            "security",
            "uncataloged-policy",
            "set",
            "r",
            "warn",
            "--yes"
        ]),
        body
    );
    let (_, sent) = mocked.last("PUT").await;
    assert_eq!(sent, json!({"uncataloged_policy": "warn"}));

    let output = mocked.ak(&[
        "scan",
        "security",
        "uncataloged-policy",
        "set",
        "r",
        "warn",
        "--yes",
        "--format",
        "table",
    ]);
    let stderr = unwrapped(&output.stderr);
    assert!(stderr.contains("is now warn"), "{stderr}");
    assert!(stderr.contains("status incomplete"), "{stderr}");
    assert!(stderr.contains("50%, 3 of 4 artifacts scanned"), "{stderr}");
}

/// Warn lets an artifact no scanner could read count as assessed: a security
/// decision, so `--yes` is the only consent.
#[tokio::test]
async fn the_uncataloged_policy_needs_yes() {
    let mocked = on("1.12.1").await;
    let output = mocked.ak(&["scan", "security", "uncataloged-policy", "set", "r", "warn"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(unwrapped(&output.stderr).contains("--yes"));
    assert!(paths(&mocked).await.is_empty());
}

/// `--instance-locked` takes its value only after `=`, so a repository key after it
/// isn't read as the value.
#[tokio::test]
async fn instance_locked_does_not_swallow_the_repository() {
    let mocked = on("1.12.1").await;
    mocked
        .respond(
            "PUT",
            "/api/v1/repositories/npm-proxy/age-gate",
            200,
            json!({"repository_key": "npm-proxy", "enabled": true, "min_age_days": 3,
                   "mode": "upstream", "instance_locked": true}),
        )
        .await;
    mocked.json(&[
        "age-gate",
        "set",
        "--min-age-days",
        "3",
        "--instance-locked",
        "npm-proxy",
    ]);
    let (_, body) = mocked.last("PUT").await;
    assert_eq!(body["instance_locked"], true);
}

#[tokio::test]
async fn security_update_hands_the_proxy_policy_back() {
    let mocked = on("1.12.1").await;
    let config = json!({
        "id": ID, "repository_id": REPO, "scan_enabled": true, "scan_on_upload": true,
        "scan_on_proxy": true, "block_on_policy_violation": false, "severity_threshold": "high",
        "proxy_scan_action": "fail_open", "instance_locked": false, "created_at": AT,
        "updated_at": AT
    });
    mocked
        .respond("PUT", "/api/v1/repositories/r/security", 200, config)
        .await;
    mocked.json(&["scan", "security", "update", "r", "--instance-locked=false"]);
    let (_, body) = mocked.last("PUT").await;
    assert_eq!(body, json!({"instance_locked": false}));
}

#[tokio::test]
async fn coverage_lists_the_artifacts_behind_the_grade() {
    let mocked = on("1.12.1").await;
    let body = json!({
        "repository_id": REPO, "total": 1, "limit": 10, "offset": 0,
        "counts": {"failed": 0, "uncataloged": 1, "partial": 0, "cataloged": 2, "unscanned": 1},
        "items": [{"artifact_id": ID, "name": "a.tar", "path": "x/a.tar",
                   "coverage_status": "uncataloged",
                   "scans": [{"scan_id": ID, "scan_type": "trivy", "status": "completed",
                              "scan_completeness": "not_cataloged"}]}]
    });
    mocked
        .respond(
            "GET",
            "/api/v1/repositories/r/security/coverage/artifacts",
            200,
            body.clone(),
        )
        .await;
    let args = [
        "scan",
        "coverage",
        "artifacts",
        "r",
        "--status",
        "uncataloged,failed",
        "--limit",
        "10",
        "--offset",
        "0",
    ];
    assert_eq!(mocked.json(&args), body);
    let (mut query, _) = mocked.last("GET").await;
    query.sort();
    assert_eq!(
        query,
        vec![
            ("limit".into(), "10".into()),
            ("offset".into(), "0".into()),
            ("status".into(), "uncataloged,failed".into()),
        ]
    );
    let output = mocked.ak(&["scan", "coverage", "artifacts", "r", "--format", "table"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Uncataloged: 1"), "{stdout}");
    assert!(
        stdout.contains("trivy completed (not_cataloged)"),
        "{stdout}"
    );
}

#[tokio::test]
async fn proxy_blocked_sends_its_filters_and_the_preview_summary_is_shown() {
    let mocked = on("1.12.1").await;
    let body = json!({
        "items": [{"repository_id": REPO, "repository_key": "npm-remote",
                   "repository_format": "npm", "path": "lodash/-/lodash-4.17.20.tgz",
                   "name": "lodash-4.17.20.tgz", "checksum_sha256": "abc",
                   "max_severity": "critical", "findings_count": 1, "critical_count": 1,
                   "high_count": 0, "medium_count": 0, "low_count": 0,
                   "cve_ids": ["CVE-2021-23337"], "scanned_at": AT,
                   "proxy_scan_action": "record_only"}],
        "pagination": {"page": 1, "per_page": 20, "total": 1, "total_pages": 1},
        "would_block_summary": {"would_block_digests": 1, "no_verdict": 2, "stale_verdict": 0,
                                "clean_graded_nothing": 3}
    });
    mocked
        .respond("GET", "/api/v1/security/proxy-blocked", 200, body.clone())
        .await;
    let args = [
        "scan",
        "proxy-blocked",
        "--repo",
        "npm-remote",
        "--min-severity",
        "high",
        "--would-block",
    ];
    assert_eq!(mocked.json(&args), body);
    let (mut query, _) = mocked.last("GET").await;
    query.sort();
    assert_eq!(
        query,
        vec![
            ("min_severity".into(), "high".into()),
            ("repository".into(), "npm-remote".into()),
            ("would_block".into(), "true".into()),
        ]
    );
    let mut table = args.to_vec();
    table.extend(["--format", "table"]);
    let stdout = String::from_utf8_lossy(&mocked.ak(&table).stdout).into_owned();
    assert!(stdout.contains("CVE-2021-23337"), "{stdout}");
    assert!(stdout.contains("record_only"), "{stdout}");
    assert!(stdout.contains("Would block 1 digests"), "{stdout}");
}

#[tokio::test]
async fn findings_of_one_copy_send_its_artifact() {
    let mocked = on("1.12.1").await;
    let scan = json!({
        "id": ID, "artifact_id": ID, "repository_id": REPO, "scan_type": "trivy",
        "status": "completed", "findings_count": 0, "critical_count": 0, "high_count": 0,
        "medium_count": 0, "low_count": 0, "info_count": 0, "created_at": AT,
        "is_reused": true, "scan_completeness": "complete"
    });
    mocked
        .respond("GET", &format!("/api/v1/security/scans/{ID}"), 200, scan)
        .await;
    mocked
        .respond(
            "GET",
            &format!("/api/v1/security/scans/{ID}/findings"),
            200,
            json!({"items": [], "total": 0}),
        )
        .await;
    mocked.json(&["scan", "show", ID, "--artifact-id", REPO]);
    let (query, _) = mocked.last("GET").await;
    assert!(
        query.contains(&("artifact_id".into(), REPO.into())),
        "{query:?}"
    );
}

#[tokio::test]
async fn scores_and_dashboard_show_grade_status_coverage_and_proxy_blocks() {
    let mocked = on("1.12.1").await;
    mocked
        .respond("GET", "/api/v1/security/scores", 200, json!([score()]))
        .await;
    mocked
        .respond(
            "GET",
            "/api/v1/security/dashboard",
            200,
            json!({
                "repos_with_scanning": 1, "total_scans": 2, "total_findings": 3,
                "critical_findings": 0, "high_findings": 1, "policy_violations_blocked": 0,
                "proxy_blocked": 7, "proxy_would_block": 9, "repos_grade_a": 1,
                "repos_grade_f": 0, "repos_rated": 4, "repos_incomplete": 5, "repos_unrated": 6
            }),
        )
        .await;
    let output = mocked.ak(&["scan", "scores", "--format", "table"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("incomplete"), "{stdout}");
    assert!(stdout.contains("50% (2/4)"), "{stdout}");

    let output = mocked.ak(&["scan", "dashboard", "--format", "table"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in [
        "Proxy Paths Blocked:   7",
        "Proxy Would Block:     9",
        "Unrated Repos:         6",
    ] {
        assert!(stdout.contains(line), "{line}: {stdout}");
    }
}

// ---- admin ----

#[tokio::test]
async fn admin_security_findings_and_scan_queue_send_their_filters() {
    let mocked = on("1.12.1").await;
    let findings = json!({
        "items": [{"artifact_id": ID, "artifact_path": "a/b", "repository_id": REPO,
                   "repository_key": "r", "cve_id": "CVE-2026-2", "severity": "high",
                   "is_acknowledged": false, "first_detected_at": AT}],
        "artifacts": [], "total": 1
    });
    mocked
        .respond(
            "GET",
            "/api/v1/admin/security/findings",
            200,
            findings.clone(),
        )
        .await;
    let args = [
        "admin",
        "security",
        "findings",
        "--repo",
        REPO,
        "--severity",
        "high",
        "--state",
        "open",
        "--page",
        "1",
        "--per-page",
        "10",
    ];
    assert_eq!(mocked.json(&args), findings);
    let (mut query, _) = mocked.last("GET").await;
    query.sort();
    assert_eq!(
        query,
        vec![
            ("page".into(), "1".into()),
            ("per_page".into(), "10".into()),
            ("repository_id".into(), REPO.into()),
            ("severity".into(), "high".into()),
            ("state".into(), "open".into()),
        ]
    );
    mocked.json(&["admin", "security", "findings", "--group-by", "artifact"]);
    let (query, _) = mocked.last("GET").await;
    assert_eq!(query, vec![("group_by".into(), "artifact".into())]);

    let queue = json!({
        "enabled": true, "total": 1,
        "depth": [{"kind": "rescan", "state": "pending", "jobs": 1, "oldest_pending_secs": 4.0}],
        "items": [{"id": ID, "kind": "rescan", "state": "pending", "priority": 1,
                   "attempts": 0, "max_attempts": 5, "created_at": AT, "next_attempt_at": AT}]
    });
    mocked
        .respond(
            "GET",
            "/api/v1/admin/security/scan-queue",
            200,
            queue.clone(),
        )
        .await;
    assert_eq!(
        mocked.json(&[
            "admin",
            "security",
            "scan-queue",
            "--state",
            "pending",
            "--kind",
            "rescan"
        ]),
        queue
    );
    let (mut query, _) = mocked.last("GET").await;
    query.sort();
    assert_eq!(
        query,
        vec![
            ("kind".into(), "rescan".into()),
            ("state".into(), "pending".into())
        ]
    );
}

#[tokio::test]
async fn holds_filter_by_source_and_list_policy_blocks() {
    let mocked = on("1.12.1").await;
    mocked
        .respond(
            "GET",
            "/api/v1/admin/holds/quarantine",
            200,
            json!({"items": [],
                   "pagination": {"page": 1, "per_page": 20, "total": 0, "total_pages": 0}}),
        )
        .await;
    mocked.json(&[
        "admin",
        "holds",
        "quarantine",
        "--hold-source",
        "scan_policy",
    ]);
    let (query, _) = mocked.last("GET").await;
    assert!(
        query.contains(&("hold_source".into(), "scan_policy".into())),
        "{query:?}"
    );

    let blocks = json!({
        "items": [{"source": "hosted", "repository_key": "r", "repository_format": "npm",
                   "path": "a/b", "name": "b", "checksum_sha256": "abc",
                   "violations": ["critical CVE-2026-3"], "hold_source": "scan_policy",
                   "quarantine_status": "quarantined"}],
        "evaluated": 50, "next_cursor": "next-page"
    });
    mocked
        .respond(
            "GET",
            "/api/v1/admin/holds/policy-blocks",
            200,
            blocks.clone(),
        )
        .await;
    let args = [
        "admin",
        "holds",
        "policy-blocks",
        "--repo",
        "r",
        "--cursor",
        "c1",
        "--per-page",
        "5",
    ];
    assert_eq!(mocked.json(&args), blocks);
    let (mut query, _) = mocked.last("GET").await;
    query.sort();
    assert_eq!(
        query,
        vec![
            ("cursor".into(), "c1".into()),
            ("per_page".into(), "5".into()),
            ("repository_key".into(), "r".into()),
        ]
    );
    let output = mocked.ak(&["admin", "holds", "policy-blocks", "--format", "table"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("critical CVE-2026-3"), "{stdout}");
    assert!(unwrapped(&output.stderr).contains("--cursor next-page"));
}

#[tokio::test]
async fn hold_source_is_refused_on_1_11() {
    let mocked = on("1.11.14").await;
    let output = mocked.ak(&["admin", "holds", "quarantine", "--hold-source", "upload"]);
    assert!(failed(&output).contains("--hold-source needs a server on 1.12"));
    assert_eq!(paths(&mocked).await, vec!["GET /health"]);
}

// ---- age gate ----

#[tokio::test]
async fn repo_reviews_use_the_repository_routes() {
    let mocked = on("1.12.1").await;
    let base = "/api/v1/repositories/npm-proxy/age-gate/reviews";
    mocked
        .respond(
            "GET",
            base,
            200,
            json!({"items": [review()],
                   "pagination": {"page": 1, "per_page": 20, "total": 1, "total_pages": 1}}),
        )
        .await;
    mocked
        .respond("GET", &format!("{base}/{ID}"), 200, review())
        .await;
    mocked
        .respond("POST", &format!("{base}/{ID}/approve"), 200, review())
        .await;
    mocked
        .respond("POST", &format!("{base}/{ID}/reopen"), 200, review())
        .await;

    mocked.json(&[
        "age-gate",
        "repo-reviews",
        "list",
        "--repo",
        "npm-proxy",
        "--status",
        "pending",
    ]);
    let (query, _) = mocked.last("GET").await;
    assert!(
        query.contains(&("status".into(), "pending".into())),
        "{query:?}"
    );

    let shown = mocked.json(&[
        "age-gate",
        "repo-reviews",
        "show",
        ID,
        "--repo",
        "npm-proxy",
    ]);
    assert_eq!(shown["instance_locked"], false);

    // Approving serves a version before it's old enough: --yes is the only consent.
    let output = mocked.ak(&[
        "age-gate",
        "repo-reviews",
        "approve",
        ID,
        "--repo",
        "npm-proxy",
    ]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(!paths(&mocked).await.iter().any(|p| p.starts_with("POST")));

    mocked.json(&[
        "age-gate",
        "repo-reviews",
        "approve",
        ID,
        "--repo",
        "npm-proxy",
        "--reason",
        "vetted",
        "--yes",
    ]);
    let (_, body) = mocked.last("POST").await;
    assert_eq!(body, json!({"reason": "vetted"}));

    mocked.json(&[
        "age-gate",
        "repo-reviews",
        "reopen",
        ID,
        "--repo",
        "npm-proxy",
    ]);
    assert!(
        paths(&mocked)
            .await
            .contains(&format!("POST {base}/{ID}/reopen"))
    );
}

#[tokio::test]
async fn repo_reviews_on_1_11_say_they_need_1_12() {
    let mocked = on("1.11.14").await;
    let stderr = failed(&mocked.ak(&["age-gate", "repo-reviews", "list", "--repo", "r"]));
    assert!(
        stderr.contains("`ak age-gate repo-reviews list` needs a server on 1.12 or newer"),
        "{stderr}"
    );
}

#[tokio::test]
async fn age_gate_set_hands_the_policy_back() {
    let mocked = on("1.12.1").await;
    mocked
        .respond(
            "PUT",
            "/api/v1/repositories/npm-proxy/age-gate",
            200,
            json!({"repository_key": "npm-proxy", "enabled": true, "min_age_days": 3,
                   "mode": "upstream", "instance_locked": false}),
        )
        .await;
    let output = mocked.ak(&[
        "age-gate",
        "set",
        "npm-proxy",
        "--min-age-days",
        "3",
        "--instance-locked=false",
        "--format",
        "table",
    ]);
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("Instance Locked:  no"));
    let (_, body) = mocked.last("PUT").await;
    assert_eq!(body["instance_locked"], false);
}

// ---- quarantine, gates and rules ----

#[tokio::test]
async fn quarantine_names_the_digest_it_means() {
    let mocked = on("1.12.1").await;
    // The tag moved from sha256:aaa to sha256:bbb before the hold landed: the server
    // held the old image's row, {HELD}, and left the new one alone.
    let action = json!({
        "artifact_id": ID, "new_status": "quarantined",
        "message": "The tag moved to sha256:bbb before the action landed",
        "held_artifact_id": HELD, "held_digest": "sha256:aaa",
        "moved_to_digest": "sha256:bbb"
    });
    mocked
        .respond(
            "GET",
            &format!("/api/v1/quarantine/{ID}"),
            200,
            json!({"artifact_id": ID, "is_blocked": false, "quarantine_status": "none"}),
        )
        .await;
    for verb in ["quarantine", "reject"] {
        mocked
            .respond(
                "POST",
                &format!("/api/v1/quarantine/{ID}/{verb}"),
                200,
                action.clone(),
            )
            .await;
    }
    let output = mocked.ak(&[
        "quarantine",
        "hold",
        ID,
        "--reason",
        "r",
        "--expected-digest",
        "sha256:aaa",
        "--yes",
        "--format",
        "table",
    ]);
    assert!(output.status.success(), "{output:?}");
    let stderr = unwrapped(&output.stderr);
    assert!(
        stderr.contains(&format!("Quarantined artifact {HELD} (sha256:aaa)")),
        "{stderr}"
    );
    assert!(!stderr.contains(&format!("artifact {ID}")), "{stderr}");
    let (_, body) = mocked.last("POST").await;
    assert_eq!(body["expected_digest"], "sha256:aaa");

    // Quiet prints the ID that was held, so piping it to `release` frees that image.
    let quiet = mocked.ak(&[
        "quarantine",
        "hold",
        ID,
        "--reason",
        "r",
        "--expected-digest",
        "sha256:aaa",
        "--yes",
        "--format",
        "quiet",
    ]);
    assert_eq!(String::from_utf8_lossy(&quiet.stdout).trim(), HELD);

    let shown = mocked.json(&[
        "quarantine",
        "reject",
        ID,
        "--expected-digest",
        "sha256:aaa",
        "--yes",
    ]);
    assert_eq!(shown["held_artifact_id"], HELD);
    assert_eq!(shown["held_digest"], "sha256:aaa");
    let (_, body) = mocked.last("POST").await;
    assert_eq!(body["expected_digest"], "sha256:aaa");
    let quiet = mocked.ak(&[
        "quarantine",
        "reject",
        ID,
        "--expected-digest",
        "sha256:aaa",
        "--yes",
        "--format",
        "quiet",
    ]);
    assert_eq!(String::from_utf8_lossy(&quiet.stdout).trim(), HELD);
}

#[tokio::test]
async fn expected_digest_is_refused_on_1_11() {
    let mocked = on("1.11.14").await;
    let output = mocked.ak(&[
        "quarantine",
        "reject",
        ID,
        "--expected-digest",
        "sha256:aaa",
        "--yes",
    ]);
    assert!(failed(&output).contains("--expected-digest needs a server on 1.12"));
    assert_eq!(paths(&mocked).await, vec!["GET /health"]);
}

#[tokio::test]
async fn gates_and_rules_take_an_accepted_grade_status() {
    let mocked = on("1.12.1").await;
    mocked
        .respond("POST", "/api/v1/quality/gates", 200, gate())
        .await;
    mocked
        .respond("PUT", &format!("/api/v1/quality/gates/{ID}"), 200, gate())
        .await;
    mocked
        .respond("GET", &format!("/api/v1/quality/gates/{ID}"), 200, gate())
        .await;
    mocked
        .respond("PUT", &format!("/api/v1/promotion-rules/{ID}"), 200, rule())
        .await;
    mocked
        .respond("GET", &format!("/api/v1/promotion-rules/{ID}"), 200, rule())
        .await;

    mocked.json(&[
        "quality-gate",
        "create",
        "g",
        "--min-security-score",
        "80",
        "--accepted-grade-status",
        "any",
    ]);
    let (_, body) = mocked.last("POST").await;
    assert_eq!(body["accepted_grade_status"], "any");

    mocked.json(&[
        "quality-gate",
        "update",
        ID,
        "--accepted-grade-status",
        "incomplete",
    ]);
    let (_, body) = mocked.last("PUT").await;
    assert_eq!(body["accepted_grade_status"], "incomplete");

    mocked.json(&[
        "promotion",
        "rule",
        "update",
        ID,
        "--accepted-grade-status",
        "incomplete",
    ]);
    let (_, body) = mocked.last("PUT").await;
    assert_eq!(body["accepted_grade_status"], "incomplete");

    let gate_table = mocked.ak(&["quality-gate", "show", ID, "--format", "table"]);
    assert!(String::from_utf8_lossy(&gate_table.stdout).contains("Grade Status:        any"));
    let rule_table = mocked.ak(&["promotion", "rule", "get", ID, "--format", "table"]);
    assert!(String::from_utf8_lossy(&rule_table.stdout).contains("Grade status:     incomplete"));
}

#[tokio::test]
async fn accepted_grade_status_is_refused_on_1_11() {
    let mocked = on("1.11.14").await;
    let output = mocked.ak(&[
        "quality-gate",
        "update",
        ID,
        "--accepted-grade-status",
        "any",
    ]);
    assert!(failed(&output).contains("--accepted-grade-status needs a server on 1.12"));
    assert_eq!(paths(&mocked).await, vec!["GET /health"]);
}
