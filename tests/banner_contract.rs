//! What `ak banner` sends and prints, against a mock server. Contract, not E2E:
//! tests/e2e_banner.rs runs the same commands against a real backend.

#[path = "common/mock.rs"]
mod mock;

use mock::Mocked;
use serde_json::{Value, json};

const UUID: &str = "00000000-0000-0000-0000-000000000001";

fn banner() -> Value {
    json!({
        "id": UUID, "title": "t", "message": "m", "severity": "warning", "target": "ui",
        "link_url": "https://status.example.com", "enabled": true, "active": true,
        "starts_at": "2026-02-01T00:00:00Z", "ends_at": "2026-03-01T00:00:00Z",
        "created_at": "2026-01-15T12:00:00Z", "updated_at": "2026-01-15T12:00:00Z",
        "from_a_newer_server": {"nested": [1, 2]}
    })
}

#[tokio::test]
async fn create_sends_every_field_and_prints_the_body() {
    let m = Mocked::start().await;
    m.respond("POST", "/api/v1/admin/banners", 201, banner())
        .await;
    let shown = m.json(&[
        "banner",
        "create",
        "t",
        "--message",
        "m",
        "--severity",
        "critical",
        "--target",
        "api",
        "--link-url",
        "https://status.example.com",
        "--starts-at",
        "2026-02-01T00:00:00Z",
        "--ends-at",
        "2026-03-01T01:00:00+01:00",
        "--disabled",
    ]);
    assert_eq!(shown, banner());
    let (_, body) = m.last("POST").await;
    assert_eq!(body["title"], "t");
    assert_eq!(body["message"], "m");
    assert_eq!(body["severity"], "critical");
    assert_eq!(body["target"], "api");
    assert_eq!(body["link_url"], "https://status.example.com");
    assert_eq!(body["enabled"], false);
    assert_eq!(body["starts_at"], "2026-02-01T00:00:00Z");
    assert_eq!(body["ends_at"], "2026-03-01T00:00:00Z");
}

#[tokio::test]
async fn create_leaves_the_defaults_to_the_server() {
    let m = Mocked::start().await;
    m.respond("POST", "/api/v1/admin/banners", 201, banner())
        .await;
    m.json(&["banner", "create", "t", "--message", "m"]);
    let (_, body) = m.last("POST").await;
    assert_eq!(body, json!({"title": "t", "message": "m"}));
}

#[tokio::test]
async fn update_replaces_the_banner_with_the_changes_on_top() {
    let m = Mocked::start().await;
    let route = format!("/api/v1/admin/banners/{UUID}");
    m.respond("GET", &route, 200, banner()).await;
    m.respond("PUT", &route, 200, banner()).await;
    let shown = m.json(&["banner", "update", UUID, "--title", "new", "--no-ends-at"]);
    assert_eq!(shown, banner());
    let (_, body) = m.last("PUT").await;
    assert_eq!(body["title"], "new");
    assert_eq!(body["message"], "m");
    assert_eq!(body["severity"], "warning");
    assert_eq!(body["target"], "ui");
    assert_eq!(body["enabled"], true);
    assert_eq!(body["link_url"], "https://status.example.com");
    assert_eq!(body["starts_at"], "2026-02-01T00:00:00Z");
    assert!(body.get("ends_at").is_none(), "{body}");
}

#[tokio::test]
async fn active_filters_by_target_and_prints_the_body() {
    let m = Mocked::start().await;
    let list = json!({"banners": [], "from_a_newer_server": true});
    m.respond("GET", "/api/v1/banners", 200, list.clone()).await;
    assert_eq!(m.json(&["banner", "active", "--target", "ui"]), list);
    let (query, _) = m.last("GET").await;
    assert_eq!(query, vec![("target".to_string(), "ui".to_string())]);
}

#[tokio::test]
async fn a_bad_time_is_refused_before_any_request() {
    let m = Mocked::start().await;
    let output = m.ak(&[
        "banner",
        "create",
        "t",
        "--message",
        "m",
        "--ends-at",
        "soon",
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(m.server.received_requests().await.unwrap().is_empty());
}
