//! What `ak curation` sends and how it reads the answer. Contract, not E2E: these
//! run against a mock server, because no API on 1.11.11 links a staging repository
//! to its source, so a real one never has a package to approve or a failing sync.
//! The commands reach a real backend in `tests/e2e_curation.rs`.

#[path = "common/mock.rs"]
mod mock;

use mock::{Mocked, unwrapped};
use serde_json::{Value, json};
use wiremock::matchers::{body_json, body_partial_json, method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

const RULE: &str = "00000000-0000-0000-0000-000000000011";
const PACKAGE: &str = "00000000-0000-0000-0000-000000000022";

fn rule() -> Value {
    json!({
        "id": RULE, "package_pattern": "left*", "version_constraint": ">=1",
        "architecture": "x86_64", "action": "block", "priority": 7, "reason": "banned",
        "enabled": false, "rule_type": "popularity", "config": {"min": 1}, "scope": "global",
        "created_at": "2026-01-15T12:00:00Z", "updated_at": "2026-01-15T12:00:00Z",
        "new_on_the_server": true
    })
}

fn package() -> Value {
    json!({
        "id": PACKAGE, "staging_repo_id": RULE, "remote_repo_id": RULE, "format": "rpm",
        "package_name": "hello", "version": "1.0", "upstream_path": "p.rpm", "status": "pending",
        "metadata": {}, "first_seen_at": "2026-01-15T12:00:00Z", "attestation_state": "unverified",
        "new_on_the_server": true
    })
}

#[tokio::test]
async fn search_sends_every_filter_and_prints_the_body() {
    let mocked = Mocked::start().await;
    let body = json!([package()]);
    Mock::given(method("GET"))
        .and(path("/api/v1/curation/repos/stg/packages/search"))
        .and(query_param("q", "hel"))
        .and(query_param("arch", "x86_64"))
        .and(query_param("status", "pending"))
        .and(query_param("limit", "5"))
        .and(query_param("offset", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body))
        .expect(1)
        .mount(&mocked.server)
        .await;
    let output = mocked.ak(&[
        "curation", "search", "stg", "--q", "hel", "--arch", "x86_64", "--status", "pending",
        "--limit", "5", "--offset", "2", "--format", "json",
    ]);
    assert!(output.status.success(), "{}", unwrapped(&output.stderr));
    let shown: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(shown, body);
}

#[tokio::test]
async fn an_empty_search_is_still_json() {
    let mocked = Mocked::start().await;
    mocked
        .respond(
            "GET",
            "/api/v1/curation/repos/stg/packages/search",
            200,
            json!([]),
        )
        .await;
    let output = mocked.ak(&["curation", "search", "stg", "--format", "json"]);
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "[]");
}

#[tokio::test]
async fn a_sync_that_failed_upstream_fails_the_command() {
    let mocked = Mocked::start().await;
    let body = json!({"repository": "stg", "triggered": true, "succeeded": false});
    mocked
        .respond("POST", "/api/v1/curation/repos/stg/sync", 200, body.clone())
        .await;
    let output = mocked.ak(&["curation", "sync", "stg", "--format", "json"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        unwrapped(&output.stderr).contains("failed upstream"),
        "{}",
        unwrapped(&output.stderr)
    );
    let shown: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(shown, body);
}

#[tokio::test]
async fn a_version_is_created_and_published() {
    let mocked = Mocked::start().await;
    let created =
        json!({"repository": "stg", "version_number": 3, "package_count": 2, "published": false});
    let published =
        json!({"repository": "stg", "version_number": 3, "package_count": 2, "published": true});
    mocked
        .respond(
            "POST",
            "/api/v1/curation/repos/stg/versions",
            201,
            created.clone(),
        )
        .await;
    mocked
        .respond(
            "POST",
            "/api/v1/curation/repos/stg/versions/3/publish",
            200,
            published.clone(),
        )
        .await;

    let output = mocked.ak(&["curation", "version", "create", "stg", "--format", "json"]);
    assert!(output.status.success(), "{}", unwrapped(&output.stderr));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        created
    );

    let output = mocked.ak(&[
        "curation", "version", "publish", "stg", "3", "--yes", "--format", "json",
    ]);
    assert!(output.status.success(), "{}", unwrapped(&output.stderr));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        published
    );

    let output = mocked.ak(&["curation", "version", "create", "stg", "--format", "quiet"]);
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "3");
}

#[tokio::test]
async fn create_rule_sends_every_field() {
    let mocked = Mocked::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/curation/rules"))
        .and(body_partial_json(json!({
            "action": "block", "reason": "r", "package_pattern": "left*",
            "rule_type": "publisher_trust", "config": {"owners": ["a"]}, "scope": "global",
            "architecture": "x86_64", "priority": 3, "version_constraint": ">=1"
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(rule()))
        .expect(1)
        .mount(&mocked.server)
        .await;
    let output = mocked.ak(&[
        "curation",
        "create-rule",
        "left*",
        "--action",
        "block",
        "--reason",
        "r",
        "--rule-type",
        "publisher_trust",
        "--config",
        r#"{"owners":["a"]}"#,
        "--scope",
        "global",
        "--architecture",
        "x86_64",
        "--priority",
        "3",
        "--version-constraint",
        ">=1",
        "--format",
        "json",
    ]);
    assert!(output.status.success(), "{}", unwrapped(&output.stderr));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        rule()
    );
}

#[tokio::test]
async fn create_rule_leaves_a_typed_rule_pattern_to_the_server() {
    let mocked = Mocked::start().await;
    mocked
        .respond("POST", "/api/v1/curation/rules", 201, rule())
        .await;
    let output = mocked.ak(&[
        "curation",
        "create-rule",
        "--action",
        "block",
        "--reason",
        "r",
        "--rule-type",
        "popularity",
    ]);
    assert!(output.status.success(), "{}", unwrapped(&output.stderr));
    let (_, body) = mocked.last("POST").await;
    assert_eq!(body["rule_type"], "popularity");
    assert!(body.get("package_pattern").is_none(), "{body}");
}

#[tokio::test]
async fn a_config_that_is_not_an_object_is_refused_before_sending() {
    let mocked = Mocked::start().await;
    let output = mocked.ak(&[
        "curation",
        "create-rule",
        "--action",
        "block",
        "--reason",
        "r",
        "--config",
        "[1]",
    ]);
    assert!(!output.status.success());
    assert!(unwrapped(&output.stderr).contains("--config"));
    assert!(mocked.server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn update_rule_sends_the_current_value_of_what_it_does_not_change() {
    let mocked = Mocked::start().await;
    mocked
        .respond(
            "GET",
            &format!("/api/v1/curation/rules/{RULE}"),
            200,
            rule(),
        )
        .await;
    Mock::given(method("PUT"))
        .and(path(format!("/api/v1/curation/rules/{RULE}")))
        .and(body_json(json!({
            "package_pattern": "left*", "version_constraint": ">=1", "architecture": "x86_64",
            "action": "block", "priority": 7, "reason": "new", "enabled": false,
            "rule_type": "popularity", "config": {"min": 1}
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(rule()))
        .expect(1)
        .mount(&mocked.server)
        .await;
    let output = mocked.ak(&["curation", "update-rule", RULE, "--reason", "new"]);
    assert!(output.status.success(), "{}", unwrapped(&output.stderr));
}

/// A decision on a package or a version asks first, in the form every prompt takes
/// with no terminal, and sends nothing without an answer.
#[tokio::test]
async fn a_decision_needs_yes_with_no_terminal() {
    for args in [
        vec!["curation", "approve", PACKAGE],
        vec!["curation", "block", PACKAGE],
        vec!["curation", "bulk-approve", PACKAGE, "--reason", "r"],
        vec!["curation", "bulk-block", PACKAGE, "--reason", "r"],
        vec!["curation", "version", "publish", "stg", "1"],
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

#[tokio::test]
async fn yes_makes_the_decision() {
    let mocked = Mocked::start().await;
    mocked
        .respond(
            "POST",
            &format!("/api/v1/curation/packages/{PACKAGE}/approve"),
            200,
            package(),
        )
        .await;
    let output =
        mocked.ak_prompting(&["curation", "approve", PACKAGE, "--yes", "--format", "json"]);
    assert!(output.status.success(), "{}", unwrapped(&output.stderr));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        package()
    );
}
