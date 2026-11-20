//! Credentials and plain HTTP to a host that isn't this machine: `ak` sends none
//! unless the instance allows it (`ak instance add|update --insecure-http`) or
//! `AK_ALLOW_INSECURE_HTTP=1` is set, and a refused command sends nothing at all.
//!
//! The mock server listens on 0.0.0.0, and the instance's URL names it as
//! `http://0.0.0.0:<port>`: that address isn't loopback, so `ak` treats it as a
//! remote host, and on Linux and macOS a connection to it still reaches this one.
#![cfg(unix)]

#[path = "common/mock.rs"]
mod mock;

use std::process::Output;

use assert_cmd::Command;
use serde_json::json;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "the-stored-token";

struct Remote {
    server: MockServer,
    dir: TempDir,
}

impl Remote {
    async fn start(allow: bool) -> Self {
        let listener = std::net::TcpListener::bind("0.0.0.0:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = MockServer::builder().listener(listener).start().await;
        let dir = TempDir::new().expect("temp dir");
        let mut config = format!(
            "default_instance = \"lan\"\n[instances.lan]\nurl = \"http://0.0.0.0:{port}\"\n"
        );
        if allow {
            config.push_str("allow_insecure_http = true\n");
        }
        std::fs::write(dir.path().join("config.toml"), config).expect("write config");
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/ci/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "minted", "token_type": "Bearer",
                "expires_in": 900, "username": "ci"
            })))
            .mount(&server)
            .await;
        Self { server, dir }
    }

    fn ak(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut command = Command::cargo_bin("ak").expect("ak binary");
        command
            .env_remove("AK_FORMAT")
            .env_remove("AK_INSTANCE")
            .env_remove("AK_ALLOW_INSECURE_HTTP")
            .env("AK_CONFIG_DIR", self.dir.path())
            .env("AK_TOKEN", TOKEN)
            .env("AK_CREDENTIAL_STORE", "file")
            .arg("--no-input")
            .args(args);
        for (name, value) in env {
            command.env(name, value);
        }
        command.output().expect("run ak")
    }

    /// The Authorization header of each request the server got.
    async fn authorizations(&self) -> Vec<Option<String>> {
        self.server
            .received_requests()
            .await
            .expect("recording on")
            .iter()
            .map(|r| {
                r.headers
                    .get("authorization")
                    .map(|v| v.to_str().unwrap_or_default().to_string())
            })
            .collect()
    }
}

fn stderr(output: &Output) -> String {
    mock::unwrapped(&output.stderr)
}

/// One command per way of attaching the instance's credentials: the SDK client,
/// the raw `Wire` transport and resolve_base_url_and_auth behind it, `ak api`, an
/// SSE stream, a CI token exchange and the TOTP steps of a login.
const AUTHENTICATED: &[&[&str]] = &[
    &["repo", "list"],
    &["auth", "whoami"],
    &["pkg", "conda", "attest", "r", "noarch", "f.conda", "{}"],
    &["events", "tail", "--count", "1"],
    // A login's one-time ticket and code, finished on their own.
    &["auth", "verify-totp", "123456", "--totp-token", "ticket"],
    &["totp", "enroll", "setup", "--totp-token", "ticket"],
    &[
        "totp",
        "enroll",
        "complete",
        "--totp-token",
        "ticket",
        "--code",
        "123456",
    ],
    &[
        "auth",
        "ci-exchange",
        "--provider-id",
        "00000000-0000-0000-0000-000000000001",
        "--jwt",
        "j",
    ],
];

#[tokio::test]
async fn every_authenticated_command_is_refused_and_sends_nothing() {
    let remote = Remote::start(false).await;
    for args in AUTHENTICATED {
        let output = remote.ak(args, &[]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            stderr(&output)
        );
        let err = stderr(&output);
        assert!(
            err.contains("Refusing to send credentials over unencrypted HTTP to http://0.0.0.0:"),
            "{args:?}: {err}"
        );
        assert!(
            err.contains("`ak instance update lan --insecure-http`"),
            "{args:?}: {err}"
        );
        assert!(err.contains("AK_ALLOW_INSECURE_HTTP=1"), "{args:?}: {err}");
    }
    assert!(remote.authorizations().await.is_empty());
}

#[tokio::test]
async fn ak_api_is_refused_with_its_own_exit_code_and_sends_nothing() {
    let remote = Remote::start(false).await;
    let output = remote.ak(&["api", "GET", "/api/v1/repositories"], &[]);
    // `ak api` has its own table: 3 is a request that didn't complete for a local
    // setting.
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(stderr(&output).contains("Refusing to send credentials"));
    assert!(remote.authorizations().await.is_empty());

    // --anon sends no credentials, so it isn't refused.
    let output = remote.ak(&["api", "GET", "/api/v1/repositories", "--anon"], &[]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(remote.authorizations().await, vec![None]);
}

#[tokio::test]
async fn a_token_login_is_refused_before_anything_is_sent() {
    let remote = Remote::start(false).await;
    let mut command = Command::cargo_bin("ak").expect("ak binary");
    let output = command
        .env_remove("AK_TOKEN")
        .env_remove("AK_ALLOW_INSECURE_HTTP")
        .env("AK_CONFIG_DIR", remote.dir.path())
        .env("AK_CREDENTIAL_STORE", "file")
        .args(["--no-input", "auth", "login", "--token-stdin"])
        .write_stdin("a-token")
        .output()
        .expect("run ak");
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("Refusing to send credentials"));
    assert!(remote.authorizations().await.is_empty());
    assert!(!remote.dir.path().join("credentials.json").exists());
}

#[tokio::test]
async fn the_instance_setting_lets_credentials_through() {
    let remote = Remote::start(true).await;
    let output = remote.ak(&["api", "GET", "/api/v1/repositories"], &[]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        remote.authorizations().await,
        vec![Some(format!("Bearer {TOKEN}"))]
    );
}

#[tokio::test]
async fn ak_instance_update_records_the_opt_in_and_takes_it_back() {
    let remote = Remote::start(false).await;
    let output = remote.ak(&["instance", "update", "lan", "--insecure-http"], &[]);
    assert!(output.status.success(), "{}", stderr(&output));
    let config = std::fs::read_to_string(remote.dir.path().join("config.toml")).unwrap();
    assert!(config.contains("allow_insecure_http = true"), "{config}");

    // The empty body doesn't fit the response type, but the request goes with the token.
    remote.ak(&["auth", "whoami", "--format", "json"], &[]);
    assert_eq!(
        remote.authorizations().await,
        vec![Some(format!("Bearer {TOKEN}"))]
    );

    let output = remote.ak(&["instance", "update", "lan", "--insecure-http=false"], &[]);
    assert!(output.status.success(), "{}", stderr(&output));
    let output = remote.ak(&["repo", "list"], &[]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert_eq!(remote.authorizations().await.len(), 1);
}

#[tokio::test]
async fn the_env_var_lets_credentials_through_for_one_command() {
    let remote = Remote::start(false).await;
    let output = remote.ak(
        &["api", "GET", "/api/v1/repositories"],
        &[("AK_ALLOW_INSECURE_HTTP", "1")],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        remote.authorizations().await,
        vec![Some(format!("Bearer {TOKEN}"))]
    );
    // The next command without it is refused again.
    let output = remote.ak(&["api", "GET", "/api/v1/repositories"], &[]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert_eq!(remote.authorizations().await.len(), 1);
}

#[tokio::test]
async fn doctor_reports_plain_http_and_sends_no_credentials() {
    let remote = Remote::start(false).await;
    let output = remote.ak(&["doctor", "--format", "json"], &[]);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("not JSON ({e}): {}", stderr(&output)));
    let checks = report["checks"].as_array().unwrap();
    let transport = checks
        .iter()
        .find(|c| {
            c["message"]
                .as_str()
                .is_some_and(|m| m.contains("unencrypted HTTP"))
        })
        .unwrap_or_else(|| panic!("no plain-HTTP check: {report}"));
    // Logged in (AK_TOKEN), so every command needing it would fail: a failure.
    assert_eq!(transport["status"], "fail", "{transport}");
    assert!(
        transport["message"]
            .as_str()
            .unwrap()
            .contains("ak instance update lan --insecure-http")
    );
    assert!(
        remote.authorizations().await.iter().all(Option::is_none),
        "doctor sent credentials"
    );

    // Allowed, it's a warning that says so, and the checks use the login.
    let remote = Remote::start(true).await;
    let output = remote.ak(&["doctor", "--format", "json"], &[]);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let transport = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| {
            c["message"]
                .as_str()
                .is_some_and(|m| m.contains("unencrypted HTTP"))
        })
        .unwrap_or_else(|| panic!("no plain-HTTP check: {report}"));
    assert_eq!(transport["status"], "warn", "{transport}");
    assert!(
        remote
            .authorizations()
            .await
            .contains(&Some(format!("Bearer {TOKEN}")))
    );
}

#[tokio::test]
async fn loopback_plain_http_is_allowed() {
    let m = mock::Mocked::start().await;
    m.respond("GET", "/api/v1/repositories", 200, json!({}))
        .await;
    let output = m.ak(&["api", "GET", "/api/v1/repositories"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let requests = m.server.received_requests().await.unwrap();
    assert_eq!(
        requests[0].headers.get("authorization").unwrap(),
        "Bearer t"
    );
}
