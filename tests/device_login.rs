//! End-to-end command test for `ak auth login --device`.
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
        .env("AK_CREDENTIAL_STORE", "file")
        .arg("--no-input")
        .arg("--format")
        .arg("json")
        .arg("auth")
        .arg("login")
        .arg("--device")
        .output()
        .expect("run ak");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Assertion messages leave out the output: on a failure here it may contain
    // the token material this test exists to keep out of logs.
    assert!(
        output.status.success(),
        "device login failed: {:?}",
        output.status.code()
    );

    for secret in [
        "device-access-token",
        "device-refresh-token",
        "device-secret-code",
    ] {
        assert!(!stdout.contains(secret), "token material found in stdout");
        assert!(!stderr.contains(secret), "token material found in stderr");
    }

    assert!(
        stderr.contains("BCDF-GHJK"),
        "user code missing from stderr"
    );
    assert!(
        stderr.contains("/device"),
        "verification URI missing from stderr"
    );
    assert!(
        stderr.contains("Logged in"),
        "confirmation missing from stderr"
    );
    assert!(!stderr.contains("alice"), "account details found in stderr");
}

/// Device sign-in is the default only at a terminal. A script's bare `ak auth login`
/// does what it did before 1.12, and doesn't ask the server about it either, even
/// when the server offers it.
#[tokio::test]
async fn a_bare_login_without_a_terminal_keeps_the_old_behaviour() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/system/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "max_upload_size_bytes": 1,
            "demo_mode": false,
            "guest_access_enabled": false,
            "auth": {
                "ldap_enabled": false,
                "local_login_enabled": true,
                "oidc_enabled": false,
                "silent_sso_enabled": false,
                "sso_enabled": false,
                "device_authorization_enabled": true
            }
        })))
        .mount(&server)
        .await;

    let config_dir = tempfile::TempDir::new().expect("temp config dir");
    std::fs::write(
        config_dir.path().join("config.toml"),
        format!(
            "default_instance = \"t\"\n\n[instances.t]\nurl = \"{}\"\napi_version = \"v1\"\n",
            server.uri()
        ),
    )
    .expect("write config");

    let output = Command::cargo_bin("ak")
        .expect("ak binary")
        .env("AK_CONFIG_DIR", config_dir.path())
        .env_remove("AK_TOKEN")
        .env("AK_CREDENTIAL_STORE", "file")
        .args(["--no-input", "auth", "login"])
        .output()
        .expect("run ak");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("--password-stdin"), "{stderr}");
    let requests = server.received_requests().await.unwrap_or_default();
    assert!(requests.is_empty(), "{requests:?}");
}

/// A JWT with these claims. The CLI reads them without checking the signature.
fn jwt(claims: serde_json::Value) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    format!("{header}.{payload}.sig")
}

/// Log in with the device grant and the given access token, then run `ak admin
/// settings show` against a server that refuses it for admin. Returns its exit code
/// and stderr.
async fn refused_after_device_login(access_token: String) -> (Option<i32>, String) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/device/code"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "device_code": "d",
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
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 1800,
            "refresh_token": "r",
            "scope": "read:artifacts"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(user_json()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/admin/settings"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "code": "FORBIDDEN",
            "message": "Admin access required"
        })))
        .mount(&server)
        .await;

    let config_dir = tempfile::TempDir::new().expect("temp config dir");
    std::fs::write(
        config_dir.path().join("config.toml"),
        format!(
            "default_instance = \"t\"\n\n[instances.t]\nurl = \"{}\"\napi_version = \"v1\"\n",
            server.uri()
        ),
    )
    .expect("write config");
    let ak = |args: &[&str]| {
        Command::cargo_bin("ak")
            .expect("ak binary")
            .env("AK_CONFIG_DIR", config_dir.path())
            .env_remove("AK_TOKEN")
            .env("AK_CREDENTIAL_STORE", "file")
            .arg("--no-input")
            .args(args)
            .output()
            .expect("run ak")
    };
    let login = ak(&["auth", "login", "--device"]);
    assert!(login.status.success(), "login failed: {:?}", login.status);
    let refused = ak(&["admin", "settings", "show"]);
    // miette wraps the report to the terminal width: compare the words.
    let stderr = String::from_utf8_lossy(&refused.stderr)
        .split_whitespace()
        .filter(|word| *word != "│")
        .collect::<Vec<_>>()
        .join(" ");
    (refused.status.code(), stderr)
}

/// An admin on a browser session is refused admin work for the session's scopes, not
/// the account's rights, and is told how to get a session that has them.
#[tokio::test]
async fn an_admin_refused_on_a_device_session_is_told_to_log_in_with_a_password() {
    let token = jwt(json!({"is_admin": true, "scopes": ["read:artifacts"], "exp": 4102444800i64}));
    let (code, stderr) = refused_after_device_login(token).await;
    assert_eq!(code, Some(4), "{stderr}");
    assert!(stderr.contains("Admin access required"), "{stderr}");
    assert!(stderr.contains("ak auth login --password"), "{stderr}");
    assert!(stderr.contains("read:artifacts"), "{stderr}");
}

/// The same refusal to a session without a scope list (a password login) keeps the
/// plain permission error.
#[tokio::test]
async fn the_same_refusal_to_an_unscoped_session_is_not_about_the_session() {
    let token = jwt(json!({"is_admin": true, "exp": 4102444800i64}));
    let (code, stderr) = refused_after_device_login(token).await;
    assert_eq!(code, Some(4), "{stderr}");
    assert!(!stderr.contains("ak auth login --password"), "{stderr}");
}
