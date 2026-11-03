//! What `ak sbom`, `sign`, `quarantine` and `attestation` send and print. Contract, not
//! E2E: these run against a mock server, for what a plain backend can't do (an SBOM of
//! a proxied artifact needs a scanner, a populated attestation policy needs server
//! config). The same commands reach a real backend in `tests/e2e_sbom.rs`,
//! `tests/e2e_sign.rs` and `tests/e2e_quarantine.rs`.

#[path = "common/mock.rs"]
mod mock;

use mock::{Mocked, unwrapped};
use serde_json::{Value, json};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

const ID: &str = "00000000-0000-0000-0000-000000000011";

#[tokio::test]
async fn a_proxy_sbom_prints_and_saves_the_document() {
    let mocked = Mocked::start().await;
    let document = json!({"bomFormat": "CycloneDX", "components": [{"name": "a"}]});
    Mock::given(method("GET"))
        .and(path("/api/v1/repositories/rem/security/proxy-sbom"))
        .and(query_param("path", "a b/c"))
        .and(query_param("format", "spdx"))
        .and(header("authorization", "Bearer t"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&document))
        .mount(&mocked.server)
        .await;
    let args = [
        "sbom",
        "proxy",
        "rem",
        "--path",
        "a b/c",
        "--sbom-format",
        "spdx",
    ];
    assert_eq!(mocked.json(&args), document);

    let dir = tempfile::TempDir::new().unwrap();
    let file = dir.path().join("sbom.json");
    let mut to_file = args.to_vec();
    to_file.extend(["-o", file.to_str().unwrap()]);
    let output = mocked.ak(&to_file);
    assert!(output.status.success(), "{}", unwrapped(&output.stderr));
    assert!(output.stdout.is_empty());
    let saved: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    assert_eq!(saved, document);
}

#[tokio::test]
async fn a_proxy_sbom_shows_the_server_message_on_failure() {
    let mocked = Mocked::start().await;
    mocked
        .respond(
            "GET",
            "/api/v1/repositories/rem/security/proxy-sbom",
            404,
            json!({"code": "NOT_FOUND", "message": "No SBOM recorded"}),
        )
        .await;
    let output = mocked.ak(&["sbom", "proxy", "rem", "--path", "a"]);
    assert_eq!(output.status.code(), Some(5));
    assert!(
        unwrapped(&output.stderr).contains("404 Not Found: No SBOM recorded"),
        "{}",
        unwrapped(&output.stderr)
    );
}

#[tokio::test]
async fn an_environment_sbom_sends_the_lockfile_and_every_filter() {
    let mocked = Mocked::start().await;
    let body = json!({"lockfile": "uv.lock", "graphs": []});
    Mock::given(method("POST"))
        .and(path("/api/v1/sbom/environment"))
        .and(query_param("filename", "uv.lock"))
        .and(query_param("format", "spdx"))
        .and(query_param("environment", "prod"))
        .and(query_param("platform", "linux-64"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body))
        .mount(&mocked.server)
        .await;
    let dir = tempfile::TempDir::new().unwrap();
    let file = dir.path().join("uv.lock");
    std::fs::write(&file, "lock bytes").unwrap();
    let shown = mocked.json(&[
        "sbom",
        "environment",
        file.to_str().unwrap(),
        "--sbom-format",
        "spdx",
        "--environment",
        "prod",
        "--platform",
        "linux-64",
    ]);
    assert_eq!(shown, body);
    assert_eq!(mocked.last_body("POST").await, b"lock bytes");
}

#[tokio::test]
async fn a_populated_attestation_policy_prints_in_every_format() {
    let mocked = Mocked::start().await;
    let body = json!({
        "require_verified": true,
        "issuers": ["https://issuer.example"],
        "identities": ["https://issuer.example/acme/*"],
        "keys": [{"id": "k1", "name": "acme-ci", "fingerprint": "ab:cd", "algorithm": "ES256"}],
        "new_on_the_server": 1
    });
    mocked
        .respond("GET", "/api/v1/attestations/policy", 200, body.clone())
        .await;
    assert_eq!(mocked.json(&["attestation", "policy"]), body);

    let output = mocked.ak(&["attestation", "policy", "--format", "table"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("https://issuer.example/acme/*"), "{stdout}");
    assert!(stdout.contains("acme-ci"), "{stdout}");
    assert!(stdout.contains("ab:cd"), "{stdout}");
}

#[tokio::test]
async fn sign_config_update_sends_only_what_it_is_given() {
    let mocked = Mocked::start().await;
    let config = json!({
        "id": ID, "repository_id": ID, "require_signatures": false, "sign_metadata": false,
        "sign_packages": false, "created_at": "2026-01-15T12:00:00Z",
        "updated_at": "2026-01-15T12:00:00Z", "new_on_the_server": 1
    });
    mocked
        .respond(
            "POST",
            &format!("/api/v1/signing/repositories/{ID}/config"),
            200,
            config.clone(),
        )
        .await;
    let shown = mocked.json(&[
        "sign",
        "config",
        "update",
        ID,
        "--require-signatures",
        "false",
    ]);
    assert_eq!(shown, config);
    let (_, body) = mocked.last("POST").await;
    assert_eq!(body, json!({"require_signatures": false}));
}

#[tokio::test]
async fn release_proxy_sends_the_path_and_prints_the_body() {
    let mocked = Mocked::start().await;
    let body = json!({
        "repository": "rem", "path": "a/b", "released": true, "message": "m",
        "new_on_the_server": 1
    });
    mocked
        .respond(
            "POST",
            "/api/v1/quarantine/proxy-cache/rem/release",
            200,
            body.clone(),
        )
        .await;
    let shown = mocked.json(&[
        "quarantine",
        "release-proxy",
        "rem",
        "--path",
        "a/b",
        "--yes",
    ]);
    assert_eq!(shown, body);
    let (_, sent) = mocked.last("POST").await;
    assert_eq!(sent, json!({"path": "a/b"}));
}

const NOT_RECORDED: &str = "No cached artifact at that path";

/// A server answers 409 for a held download before it has recorded the hold, so the
/// first releases after it get a 404.
#[tokio::test]
async fn release_proxy_waits_for_a_hold_to_be_recorded() {
    let mocked = Mocked::start().await;
    let route = "/api/v1/quarantine/proxy-cache/rem/release";
    Mock::given(method("POST"))
        .and(path(route))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"code": "NOT_FOUND", "message": NOT_RECORDED})),
        )
        .up_to_n_times(2)
        .mount(&mocked.server)
        .await;
    let body = json!({"repository": "rem", "path": "a", "released": true, "message": "m"});
    mocked.respond("POST", route, 200, body.clone()).await;

    let shown = mocked.json(&["quarantine", "release-proxy", "rem", "--path", "a", "--yes"]);
    assert_eq!(shown, body);
    assert_eq!(mocked.server.received_requests().await.unwrap().len(), 3);
}

/// It gives up in a few seconds, and never reports a release the server didn't make.
#[tokio::test]
async fn release_proxy_stops_waiting_and_says_nothing_was_released() {
    let mocked = Mocked::start().await;
    mocked
        .respond(
            "POST",
            "/api/v1/quarantine/proxy-cache/rem/release",
            404,
            json!({"code": "NOT_FOUND", "message": NOT_RECORDED}),
        )
        .await;
    let started = std::time::Instant::now();
    let output = mocked.ak(&[
        "quarantine",
        "release-proxy",
        "rem",
        "--path",
        "a",
        "--yes",
        "--format",
        "json",
    ]);
    assert!(started.elapsed() < std::time::Duration::from_secs(15));
    assert_eq!(output.status.code(), Some(6));
    assert!(output.stdout.is_empty());
    let stderr = unwrapped(&output.stderr);
    assert!(
        stderr.contains("404 Not Found: No cached artifact"),
        "{stderr}"
    );
    assert!(stderr.contains("Nothing was released"), "{stderr}");
    assert!(stderr.contains("recording the hold"), "{stderr}");
    assert_eq!(mocked.server.received_requests().await.unwrap().len(), 5);
}

/// Only that answer means "not recorded yet". Anything else is final at once.
#[tokio::test]
async fn release_proxy_does_not_wait_on_any_other_failure() {
    for (status, message, code) in [
        (404, "Repository not found", 5),
        (
            409,
            "Cached artifact is not in quarantined state; release not allowed",
            6,
        ),
        (403, "Admin access required", 4),
    ] {
        let mocked = Mocked::start().await;
        mocked
            .respond(
                "POST",
                "/api/v1/quarantine/proxy-cache/rem/release",
                status,
                json!({"message": message}),
            )
            .await;
        let output = mocked.ak(&["quarantine", "release-proxy", "rem", "--path", "a", "--yes"]);
        assert_eq!(output.status.code(), Some(code));
        assert!(
            unwrapped(&output.stderr).contains(message),
            "{}",
            unwrapped(&output.stderr)
        );
        let posts = mocked
            .server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method.as_str() == "POST")
            .count();
        assert_eq!(posts, 1, "{status} {message}");
    }
}

/// Anything that opens a gate, vouches for something, or can't be undone asks first,
/// and sends nothing without an answer.
#[tokio::test]
async fn a_security_decision_needs_yes_with_no_terminal() {
    for args in [
        vec!["quarantine", "hold", ID],
        vec!["quarantine", "release", ID],
        vec!["quarantine", "release-proxy", "rem", "--path", "a"],
        vec!["quarantine", "reject", ID],
        vec!["quarantine", "purge", ID],
        vec!["sign", "artifact", ID],
        vec!["sign", "key", "revoke", ID],
        vec!["sign", "key", "rotate", ID],
        vec!["sbom", "cve", "update-status", ID, "--status", "fixed"],
        vec![
            "sbom",
            "cve",
            "update-status-by-artifact-cve",
            ID,
            "CVE-1",
            "--status",
            "acknowledged",
        ],
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
