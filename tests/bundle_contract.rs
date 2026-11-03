//! What `ak bundle` sends and prints, against a mock server.
//!
//! Contract, not E2E, for `export` and `import`: the 1.11.11 server answers both
//! with 501, so these are the only tests of what happens when one succeeds. The
//! other commands also run against a real backend in tests/e2e_bundle.rs.

#[path = "common/mock.rs"]
mod mock;

use mock::Mocked;
use serde_json::{Value, json};

const JOB: &str = "00000000-0000-0000-0000-000000000001";

fn not_implemented(what: &str) -> Value {
    json!({
        "code": "NOT_IMPLEMENTED",
        "message": format!("bundle {what} is not implemented in this release"),
        "tracking_issue": "#2464"
    })
}

fn job() -> Value {
    json!({
        "id": JOB, "direction": "export", "status": "failed", "bundle_id": null,
        "manifest_schema_version": null, "manifest_sha256": null, "bundle_kind": "full",
        "media_profile": null, "volume_count": null, "repository_keys": ["libs"],
        "total_items": 2, "completed_items": 1, "failed_items": 1, "skipped_items": 0,
        "total_bytes": 30, "transferred_bytes": 10, "error_summary": "disk full",
        "created_by": null, "created_at": "2026-01-15T12:00:00Z", "started_at": null,
        "finished_at": null, "from_a_newer_server": {"nested": [1, 2]}
    })
}

fn report(valid: bool) -> Value {
    json!({
        "valid": valid, "supported_by_importer": valid, "importable": false,
        "schema_version": null, "supported_schema_versions": [1, 1], "bundle_id": null,
        "kind": null, "repository_count": 0, "item_count": 0, "total_bytes": 0,
        "scan_evidence_count": 0, "manifest_sha256": "abc",
        "problems": if valid { json!([]) } else { json!(["manifest is not a JSON object"]) },
        "unsupported_features": [], "from_a_newer_server": true
    })
}

#[tokio::test]
async fn export_sends_every_field() {
    let m = Mocked::start().await;
    m.respond("POST", "/api/v1/bundles/exports", 202, job())
        .await;
    let shown = m.json(&[
        "bundle",
        "export",
        "--repo",
        "a",
        "--repo",
        "b,c",
        "--media-profile",
        "bd_r",
        "--media-control-number",
        "MCN-1",
    ]);
    assert_eq!(shown, job(), "a 2xx prints what the server sent");
    let (_, body) = m.last("POST").await;
    assert_eq!(
        body,
        json!({
            "repository_keys": ["a", "b", "c"],
            "media_profile": "bd_r",
            "media_control_number": "MCN-1"
        })
    );
}

#[tokio::test]
async fn export_shows_the_servers_501() {
    let m = Mocked::start().await;
    m.respond(
        "POST",
        "/api/v1/bundles/exports",
        501,
        not_implemented("export"),
    )
    .await;
    let output = m.ak(&["bundle", "export", "--repo", "a"]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = mock::unwrapped(&output.stderr);
    assert!(stderr.contains("501"), "{stderr}");
    assert!(stderr.contains("is not implemented"), "{stderr}");
}

#[tokio::test]
async fn import_posts_and_shows_the_servers_501() {
    let m = Mocked::start().await;
    m.respond(
        "POST",
        "/api/v1/bundles/imports",
        501,
        not_implemented("import"),
    )
    .await;
    let output = m.ak(&["bundle", "import"]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = mock::unwrapped(&output.stderr);
    assert!(stderr.contains("is not implemented"), "{stderr}");
    assert!(m.last_body("POST").await.is_empty());
}

#[tokio::test]
async fn import_prints_the_body_of_a_2xx() {
    let m = Mocked::start().await;
    m.respond("POST", "/api/v1/bundles/imports", 202, job())
        .await;
    assert_eq!(m.json(&["bundle", "import"]), job());
}

#[tokio::test]
async fn validate_sends_the_file_unchanged_and_exits_0_when_valid() {
    let m = Mocked::start().await;
    m.respond(
        "POST",
        "/api/v1/bundles/manifest/validate",
        200,
        report(true),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("manifest.json");
    std::fs::write(&file, b"  not even json \n").unwrap();
    let shown = m.json(&["bundle", "validate-manifest", file.to_str().unwrap()]);
    assert_eq!(shown, report(true));
    assert_eq!(m.last_body("POST").await, b"  not even json \n");
}

#[tokio::test]
async fn validate_prints_the_report_and_exits_1_when_invalid() {
    let m = Mocked::start().await;
    m.respond(
        "POST",
        "/api/v1/bundles/manifest/validate",
        200,
        report(false),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("manifest.json");
    std::fs::write(&file, b"x").unwrap();
    let output = m.ak(&[
        "--format",
        "json",
        "bundle",
        "validate-manifest",
        file.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(1));
    let shown: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(shown, report(false));
}

#[tokio::test]
async fn jobs_list_sends_every_filter() {
    let m = Mocked::start().await;
    let list = json!({"items": [job()], "page": 2, "per_page": 5});
    m.respond("GET", "/api/v1/bundles/jobs", 200, list.clone())
        .await;
    let shown = m.json(&[
        "bundle",
        "jobs",
        "list",
        "--direction",
        "export",
        "--status",
        "failed",
        "--page",
        "2",
        "--per-page",
        "5",
    ]);
    assert_eq!(shown, list);
    let (mut query, _) = m.last("GET").await;
    query.sort();
    assert_eq!(
        query,
        [
            ("direction", "export"),
            ("page", "2"),
            ("per_page", "5"),
            ("status", "failed")
        ]
        .map(|(k, v)| (k.to_string(), v.to_string()))
    );
}

#[tokio::test]
async fn jobs_show_and_items_print_the_body() {
    let m = Mocked::start().await;
    m.respond("GET", &format!("/api/v1/bundles/jobs/{JOB}"), 200, job())
        .await;
    assert_eq!(m.json(&["bundle", "jobs", "show", JOB]), job());

    let items = json!({
        "items": [{
            "id": JOB, "job_id": JOB, "repository_key": "libs", "logical_path": "a.jar",
            "sha256": "abc", "size_bytes": 10, "blob_path": "blobs/ab/abc.jar",
            "status": "failed", "artifact_id": null, "error_message": "boom",
            "created_at": "2026-01-15T12:00:00Z", "updated_at": "2026-01-15T12:00:00Z"
        }],
        "page": 1, "per_page": 1
    });
    m.respond(
        "GET",
        &format!("/api/v1/bundles/jobs/{JOB}/items"),
        200,
        items.clone(),
    )
    .await;
    let shown = m.json(&[
        "bundle",
        "jobs",
        "items",
        JOB,
        "--status",
        "failed",
        "--page",
        "1",
        "--per-page",
        "1",
    ]);
    assert_eq!(shown, items);
    let (mut query, _) = m.last("GET").await;
    query.sort();
    assert_eq!(
        query,
        [("page", "1"), ("per_page", "1"), ("status", "failed")]
            .map(|(k, v)| (k.to_string(), v.to_string()))
    );
}
