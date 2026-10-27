//! End-to-end command test for `ak auth login --oidc-device`.
//!
//! The backend is mocked, so this runs without the E2E stack. Its job is the
//! security contract the issue calls out: the verification URL and user code
//! are shown, but neither the device code nor either token is ever printed.

use assert_cmd::Command;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn user_json() -> serde_json::Value {
    json!({
        "id": "00000000-0000-0000-0000-000000000000",
        "username": "alice",
        "email": "alice@example.com",
        "display_name": "Alice",
        "is_admin": false,
        "totp_enabled": false,
        "created_at": "2026-01-15T12:00:00Z",
        "updated_at": "2026-01-15T12:00:00Z"
    })
}

#[tokio::test]
async fn device_login_never_prints_tokens() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/auth/device/code"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "device_code": "device-secret-code",
            "user_code": "BCDF-GHJK",
            "verification_uri": format!("{}/device", server.uri()),
            "expires_in": 60,
            "interval": 0
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/v1/auth/device/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "device-access-token",
            "token_type": "Bearer",
            "expires_in": 1800,
            "refresh_token": "device-refresh-token",
            "scope": "read:artifacts"
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/auth/me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(user_json()))
        .mount(&server)
        .await;

    let config_dir = tempfile::TempDir::new().expect("temp config dir");
    std::fs::write(
        config_dir.path().join("config.toml"),
        format!(
            "default_instance = \"device-e2e\"\n\n[instances.device-e2e]\nurl = \"{}\"\napi_version = \"v1\"\n",
            server.uri()
        ),
    )
    .expect("write config");

    let output = Command::cargo_bin("ak")
        .expect("ak binary")
        .env("AK_CONFIG_DIR", config_dir.path())
        .env_remove("AK_TOKEN")
        .arg("--no-input")
        .arg("--format")
        .arg("json")
        .arg("auth")
        .arg("login")
        .arg("--oidc-device")
        .output()
        .expect("run ak");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "device login failed\nstdout: {stdout}\nstderr: {stderr}"
    );

    for secret in [
        "device-access-token",
        "device-refresh-token",
        "device-secret-code",
    ] {
        assert!(!stdout.contains(secret), "stdout leaked {secret}: {stdout}");
        assert!(!stderr.contains(secret), "stderr leaked {secret}: {stderr}");
    }

    assert!(stderr.contains("BCDF-GHJK"), "user code missing: {stderr}");
    assert!(
        stderr.contains("/device"),
        "verification URI missing: {stderr}"
    );
    assert!(
        stderr.contains("alice"),
        "account confirmation missing: {stderr}"
    );
}
