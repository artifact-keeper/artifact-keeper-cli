//! What `ak project` sends and prints, against a mock server. Contract, not E2E:
//! tests/e2e_project.rs runs the same commands against a real backend.

#[path = "common/mock.rs"]
mod mock;

use mock::Mocked;
use serde_json::{Value, json};

const UUID: &str = "00000000-0000-0000-0000-000000000001";
const USER: &str = "00000000-0000-0000-0000-000000000002";

fn project() -> Value {
    json!({
        "id": UUID, "key": "payments", "name": "Payments", "description": null,
        "quota_bytes": null, "created_at": "2026-01-15T12:00:00Z",
        "updated_at": "2026-01-15T12:00:00Z", "from_a_newer_server": {"nested": [1, 2]}
    })
}

#[tokio::test]
async fn create_sends_every_field_and_prints_the_body() {
    let m = Mocked::start().await;
    m.respond("POST", "/api/v1/projects", 200, project()).await;
    let shown = m.json(&[
        "project",
        "create",
        "payments",
        "--name",
        "Payments",
        "--description",
        "d",
        "--quota-bytes",
        "1024",
    ]);
    assert_eq!(shown, project());
    let (_, body) = m.last("POST").await;
    assert_eq!(
        body,
        json!({"key": "payments", "name": "Payments", "description": "d", "quota_bytes": 1024})
    );
}

#[tokio::test]
async fn create_defaults_the_name_to_the_key() {
    let m = Mocked::start().await;
    m.respond("POST", "/api/v1/projects", 200, project()).await;
    m.json(&["project", "create", "payments"]);
    let (_, body) = m.last("POST").await;
    assert_eq!(body["name"], "payments");
}

#[tokio::test]
async fn update_sends_only_what_was_passed_and_resolves_the_key() {
    let m = Mocked::start().await;
    m.respond(
        "GET",
        "/api/v1/projects",
        200,
        json!({"items": [project()]}),
    )
    .await;
    m.respond("PUT", &format!("/api/v1/projects/{UUID}"), 200, project())
        .await;
    let shown = m.json(&["project", "update", "payments", "--quota-bytes", "-1"]);
    assert_eq!(shown, project());
    let (_, body) = m.last("PUT").await;
    assert_eq!(body, json!({"quota_bytes": -1}));
}

#[tokio::test]
async fn update_with_nothing_to_change_sends_nothing() {
    let m = Mocked::start().await;
    let output = m.ak(&["project", "update", UUID]);
    assert_eq!(output.status.code(), Some(1));
    assert!(m.server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn an_unknown_key_says_so() {
    let m = Mocked::start().await;
    m.respond("GET", "/api/v1/projects", 200, json!({"items": []}))
        .await;
    let output = m.ak(&["project", "show", "nope"]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("No project with key 'nope'"), "{stderr}");
}

#[tokio::test]
async fn members_add_and_remove_send_the_principal() {
    let m = Mocked::start().await;
    let route = format!("/api/v1/projects/{UUID}/members");
    let member =
        json!({"principal_type": "group", "principal_id": USER, "actions": ["read", "write"]});
    m.respond("POST", &route, 200, member.clone()).await;
    m.respond_empty("DELETE", &route, 200).await;

    let shown = m.json(&[
        "project",
        "members",
        "add",
        UUID,
        "--principal",
        USER,
        "--principal-type",
        "group",
        "--actions",
        "read,write",
    ]);
    assert_eq!(shown, member);
    let (_, body) = m.last("POST").await;
    assert_eq!(body, member);

    m.json(&[
        "project",
        "members",
        "remove",
        UUID,
        "--principal",
        USER,
        "--principal-type",
        "group",
        "--yes",
    ]);
    let (_, body) = m.last("DELETE").await;
    assert_eq!(
        body,
        json!({"principal_type": "group", "principal_id": USER})
    );
}

#[tokio::test]
async fn a_bad_principal_is_refused_before_any_request() {
    let m = Mocked::start().await;
    let output = m.ak(&[
        "project",
        "members",
        "add",
        UUID,
        "--principal",
        "alice",
        "--actions",
        "read",
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(m.server.received_requests().await.unwrap().is_empty());
}
