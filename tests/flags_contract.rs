//! Fields that a plain backend can't show working, against a mock server. Contract, not
//! E2E: restoring a backup needs a finished archive, and these others need keys or
//! groups the E2E stack doesn't set up.

#[path = "common/mock.rs"]
mod mock;

use mock::Mocked;
use serde_json::{Value, json};

const ID: &str = "00000000-0000-0000-0000-000000000001";
const GROUP: &str = "00000000-0000-0000-0000-000000000002";

fn provider() -> Value {
    json!({
        "id": ID, "name": "n", "provider_type": "github", "issuer_url": "https://i",
        "audience": "a", "is_enabled": true, "key_source": "static", "mapping_count": 0,
        "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
        "from_a_newer_server": 1
    })
}

fn mapping() -> Value {
    json!({
        "id": ID, "provider_id": ID, "name": "m", "claim_filters": {}, "priority": 0,
        "allowed_repo_ids": [], "group_binding_ids": [GROUP], "is_enabled": true,
        "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"
    })
}

#[tokio::test]
async fn ci_oidc_sends_its_key_source_and_keys() {
    let m = Mocked::start().await;
    m.respond("POST", "/api/v1/admin/ci-oidc", 200, provider())
        .await;
    let shown = m.json(&[
        "admin",
        "ci-oidc",
        "create",
        "n",
        "https://i",
        "--key-source",
        "static",
        "--static-jwks",
        r#"{"keys":[{"kid":"k"}]}"#,
    ]);
    assert_eq!(shown, provider());
    let (_, body) = m.last("POST").await;
    assert_eq!(body["key_source"], "static");
    assert_eq!(body["static_jwks"], json!({"keys": [{"kid": "k"}]}));

    let route = format!("/api/v1/admin/ci-oidc/{ID}");
    m.respond("PUT", &route, 200, provider()).await;
    m.json(&[
        "admin",
        "ci-oidc",
        "update",
        ID,
        "--key-source",
        "discovery",
    ]);
    let (_, body) = m.last("PUT").await;
    assert_eq!(body["key_source"], "discovery");
}

#[tokio::test]
async fn ci_oidc_mappings_send_group_bindings() {
    let m = Mocked::start().await;
    let route = format!("/api/v1/admin/ci-oidc/{ID}/mappings");
    m.respond("POST", &route, 200, mapping()).await;
    m.json(&[
        "admin",
        "ci-oidc",
        "mapping",
        "create",
        ID,
        "m",
        "--group-binding-ids",
        GROUP,
    ]);
    let (_, body) = m.last("POST").await;
    assert_eq!(body["group_binding_ids"], json!([GROUP]));

    let one = format!("{route}/{ID}");
    m.respond("PUT", &one, 200, mapping()).await;
    m.json(&[
        "admin",
        "ci-oidc",
        "mapping",
        "update",
        ID,
        ID,
        "--group-binding-ids",
        GROUP,
    ]);
    let (_, body) = m.last("PUT").await;
    assert_eq!(body["group_binding_ids"], json!([GROUP]));
}

#[tokio::test]
async fn backup_restore_sends_its_target_and_the_unverified_flag() {
    let m = Mocked::start().await;
    let route = format!("/api/v1/admin/backups/{ID}/restore");
    let restored = json!({
        "tables_restored": [], "artifacts_restored": 0, "errors": [],
        "integrity_anchor": "verified", "from_a_newer_server": 1
    });
    m.respond("POST", &route, 200, restored).await;
    let output = m.ak(&[
        "--format",
        "json",
        "admin",
        "backup",
        "restore",
        ID,
        "--artifacts",
        "--target-repo",
        GROUP,
        "--allow-unverified-archive",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let (_, body) = m.last("POST").await;
    assert_eq!(body["target_repository_id"], GROUP);
    assert_eq!(body["allow_unverified_archive"], true);
    assert_eq!(body["restore_artifacts"], true);
}

#[tokio::test]
async fn backup_create_sends_every_scope_field() {
    let m = Mocked::start().await;
    let backup = json!({
        "id": ID, "type": "full", "status": "pending", "size_bytes": 0, "artifact_count": 0,
        "created_at": "2026-01-01T00:00:00Z", "from_a_newer_server": 1
    });
    m.respond("POST", "/api/v1/admin/backups", 200, backup)
        .await;
    let output = m.ak(&[
        "--format",
        "json",
        "admin",
        "backup",
        "create",
        "--name",
        "b",
        "--repos",
        ID,
        "--exclude-repos",
        GROUP,
        "--since",
        "2026-01-01T01:00:00+01:00",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let (_, body) = m.last("POST").await;
    assert_eq!(body["name"], "b");
    assert_eq!(body["repository_ids"], json!([ID]));
    assert_eq!(body["exclude_repositories"], json!([GROUP]));
    assert_eq!(body["since"], "2026-01-01T00:00:00Z");
}

#[tokio::test]
async fn ldap_ca_certificate_takes_a_file() {
    let m = Mocked::start().await;
    let ldap = json!({
        "id": ID, "name": "l", "server_url": "ldaps://l", "user_base_dn": "d",
        "has_bind_password": false, "has_ca_certificate": true, "use_starttls": false,
        "insecure_skip_verify": false, "is_enabled": true, "priority": 1,
        "user_filter": "f", "username_attribute": "u", "email_attribute": "e",
        "display_name_attribute": "d", "groups_attribute": "g",
        "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"
    });
    m.respond("POST", "/api/v1/admin/sso/ldap", 200, ldap).await;
    let pem = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(pem.path(), "the certificate text").unwrap();
    let at_file = format!("@{}", pem.path().display());
    m.json(&[
        "sso",
        "create",
        "ldap",
        "l",
        "--server-url",
        "ldaps://l",
        "--user-base-dn",
        "d",
        "--ca-certificate",
        &at_file,
    ]);
    let (_, body) = m.last("POST").await;
    assert_eq!(body["ca_certificate"], "the certificate text");
}

#[tokio::test]
async fn webhook_header_needs_a_name_and_a_value() {
    let m = Mocked::start().await;
    let output = m.ak(&[
        "webhook",
        "create",
        "w",
        "--url",
        "https://h",
        "--events",
        "e",
        "--header",
        "no-equals-sign",
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(m.server.received_requests().await.unwrap().is_empty());
}
