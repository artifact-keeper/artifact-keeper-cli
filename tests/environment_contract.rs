//! What `ak environment` sends and prints, against a mock server. Contract, not
//! E2E: tests/e2e_environment.rs runs these commands against a real backend, but a
//! plain backend has no advisory feeds, so rows of `advisories` and
//! `advisory-transitions` are only checked here.

#[path = "common/mock.rs"]
mod mock;

use mock::Mocked;
use serde_json::{Value, json};

const ID: &str = "00000000-0000-0000-0000-000000000001";

fn stored() -> Value {
    json!({
        "id": ID, "repository": "r", "name": "prod", "contentSha256": "abc", "replaced": false,
        "summary": {"scopes": 1, "memberships": 3, "distinctPackages": 3, "edges": 2},
        "from_a_newer_server": true
    })
}

#[tokio::test]
async fn ingest_sends_the_bytes_and_the_query() {
    let m = Mocked::start().await;
    m.respond("POST", "/api/v1/repositories/r/environments", 201, stored())
        .await;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("Cargo.lock");
    std::fs::write(&file, b"lockfile bytes").unwrap();

    let shown = m.json(&[
        "environment",
        "ingest",
        "r",
        file.to_str().unwrap(),
        "--name",
        "prod",
    ]);
    assert_eq!(shown, stored());
    assert_eq!(m.last_body("POST").await, b"lockfile bytes");
    let (mut query, _) = m.last("POST").await;
    query.sort();
    assert_eq!(
        query,
        [("filename", "Cargo.lock"), ("name", "prod")].map(|(k, v)| (k.to_string(), v.to_string()))
    );

    m.json(&[
        "environment",
        "ingest",
        "r",
        file.to_str().unwrap(),
        "--filename",
        "uv.lock",
    ]);
    let (query, _) = m.last("POST").await;
    assert_eq!(query, vec![("filename".to_string(), "uv.lock".to_string())]);
}

#[tokio::test]
async fn names_are_resolved_through_the_list() {
    let m = Mocked::start().await;
    let list = json!({"environments": [{"id": ID, "name": "prod"}]});
    m.respond(
        "GET",
        "/api/v1/repositories/r/environments",
        200,
        list.clone(),
    )
    .await;
    assert_eq!(m.json(&["environment", "list", "r"]), list);

    let route = format!("/api/v1/repositories/r/environments/{ID}");
    let detail = json!({"id": ID, "name": "prod", "scopes": []});
    m.respond("GET", &route, 200, detail.clone()).await;
    assert_eq!(m.json(&["environment", "show", "r", "prod"]), detail);

    m.respond_empty("DELETE", &route, 204).await;
    m.json(&["environment", "delete", "r", "prod", "--yes"]);

    let output = m.ak(&["environment", "show", "r", "nope"]);
    assert_eq!(output.status.code(), Some(5));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("No environment named 'nope'"), "{stderr}");
}

#[tokio::test]
async fn lookup_sends_the_purl_and_max_paths() {
    let m = Mocked::start().await;
    let hits = json!({"query": {"purl": "pkg:npm/qs@1"}, "truncated": false, "hits": []});
    m.respond("GET", "/api/v1/environments/lookup", 200, hits.clone())
        .await;
    let shown = m.json(&["environment", "lookup", "pkg:npm/qs@1", "--max-paths", "2"]);
    assert_eq!(shown, hits);
    let (mut query, _) = m.last("GET").await;
    query.sort();
    assert_eq!(
        query,
        [("max_paths", "2"), ("purl", "pkg:npm/qs@1")].map(|(k, v)| (k.to_string(), v.to_string()))
    );
}

#[tokio::test]
async fn advisory_transitions_sends_every_filter_and_shows_rows() {
    let m = Mocked::start().await;
    let body = json!({"transitions": [{
        "environment": {"id": ID, "name": "prod"},
        "repository": {"id": ID, "key": "r"},
        "advisory": {"id": "GHSA-1", "severity": "high"},
        "package": {"ecosystem": "npm", "name": "qs", "version": "1"},
        "kind": "new-affected",
        "detectedAt": "2026-01-15T12:00:00Z"
    }]});
    m.respond(
        "GET",
        "/api/v1/environments/advisory-transitions",
        200,
        body.clone(),
    )
    .await;
    let filters = [
        "environment",
        "advisory-transitions",
        "--advisory",
        "GHSA-1",
        "--kind",
        "new-affected",
        "--since",
        "2026-01-01T00:00:00Z",
        "--until",
        "2026-02-01T00:00:00Z",
        "--limit",
        "5",
    ];
    assert_eq!(m.json(&filters), body);
    let (mut query, _) = m.last("GET").await;
    query.sort();
    let names: Vec<_> = query.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(names, ["advisory", "kind", "limit", "since", "until"]);

    let mut as_table = vec!["--format", "table"];
    as_table.extend(filters);
    let table = String::from_utf8_lossy(&m.ak(&as_table).stdout).into_owned();
    assert!(
        table.contains("GHSA-1") && table.contains("qs@1"),
        "{table}"
    );
}

#[tokio::test]
async fn advisories_show_rows() {
    let m = Mocked::start().await;
    let body = json!({"affected": [{
        "advisory": {"id": "GHSA-1", "severity": "high", "fixedVersion": "2"},
        "package": {"ecosystem": "npm", "name": "qs", "version": "1"},
        "affectedSince": "2026-01-15T12:00:00Z",
        "lastEvaluatedAt": "2026-01-15T12:00:00Z"
    }]});
    m.respond(
        "GET",
        &format!("/api/v1/repositories/r/environments/{ID}/advisories"),
        200,
        body.clone(),
    )
    .await;
    assert_eq!(m.json(&["environment", "advisories", "r", ID]), body);
    let output = m.ak(&["--format", "table", "environment", "advisories", "r", ID]);
    let table = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        table.contains("GHSA-1") && table.contains("qs@1"),
        "{table}"
    );
}

#[tokio::test]
async fn a_bad_time_is_refused_before_any_request() {
    let m = Mocked::start().await;
    let output = m.ak(&[
        "environment",
        "advisory-transitions",
        "--since",
        "yesterday",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(m.server.received_requests().await.unwrap().is_empty());
}
