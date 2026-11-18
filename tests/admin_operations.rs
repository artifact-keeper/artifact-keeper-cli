//! Contract, not E2E: what the 1.12 admin and operations commands send, and that
//! each refuses on a 1.11 server rather than sending what it would drop or doesn't
//! have. `e2e_admin_operations.rs` runs them for real.

use std::process::Output;

use assert_cmd::Command;
use serde_json::{Value, json};
use tempfile::TempDir;
use wiremock::matchers::{body_json, method, path, query_param, query_param_is_missing};
use wiremock::{Mock, MockServer, ResponseTemplate};

const UUID: &str = "00000000-0000-0000-0000-000000000001";
const AT: &str = "2026-01-15T12:00:00Z";

async fn ak_in(server: &MockServer, dir: &TempDir, args: &[&str]) -> Output {
    std::fs::write(
        dir.path().join("config.toml"),
        format!(
            "default_instance = \"t\"\n[instances.t]\nurl = \"{}\"\napi_version = \"v1\"\n",
            server.uri()
        ),
    )
    .expect("write config");
    Command::cargo_bin("ak")
        .expect("ak binary")
        .env_remove("AK_FORMAT")
        .env_remove("AK_NO_INPUT")
        .env("AK_CONFIG_DIR", dir.path())
        .env("AK_TOKEN", "t")
        .env("AK_CREDENTIAL_STORE", "file")
        .args(args)
        .output()
        .expect("run ak")
}

async fn ak(server: &MockServer, args: &[&str]) -> Output {
    let dir = TempDir::new().expect("temp dir");
    ak_in(server, &dir, args).await
}

/// A server that says it's `version`.
async fn server_on(version: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"status": "healthy", "version": version, "checks": {}})),
        )
        .mount(&server)
        .await;
    server
}

fn one_line(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr)
        .replace('│', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// What reached the server, other than the version check.
async fn sent(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() != "/health")
        .map(|r| format!("{} {}", r.method, r.url.path()))
        .collect()
}

/// On a 1.11 server, `args` fails saying it needs 1.12, and sends nothing but what
/// `sends` lists.
async fn needs_1_12(server: &MockServer, args: &[&str], needle: &str, sends: &[&str]) {
    let output = ak(server, args).await;
    assert!(!output.status.success(), "{args:?}: {output:?}");
    let stderr = one_line(&output);
    assert!(stderr.contains(needle), "{args:?}: {stderr}");
    assert!(stderr.contains("1.12"), "{args:?}: {stderr}");
    assert_eq!(sent(server).await, sends, "{args:?}");
}

// ---- admin config ----

fn document() -> Value {
    json!({"schema_version": 1, "exported_at": AT, "producer": "artifact-keeper 1.12.1",
           "repositories": [], "from_a_newer_server": true})
}

fn plan(applicable: bool) -> Value {
    json!({"applicable": applicable, "applied": false, "create": ["new"],
           "update": [{"key": "changed", "changes": ["description"]}],
           "unchanged": ["same"], "not_in_document": ["old"],
           "missing_secrets": if applicable { json!([]) } else { json!(["upstream_auth/new"]) },
           "errors": []})
}

#[tokio::test]
async fn config_export_prints_the_document_as_sent() {
    let server = server_on("1.12.1").await;
    Mock::given(method("GET"))
        .and(path("/api/v1/admin/config/export"))
        .and(query_param("repositories", "a,b"))
        .respond_with(ResponseTemplate::new(200).set_body_json(document()))
        .expect(2)
        .mount(&server)
        .await;
    let output = ak(
        &server,
        &["admin", "config", "export", "--repositories", "a,b"],
    )
    .await;
    assert!(output.status.success(), "{output:?}");
    let printed: Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(printed, document());

    let dir = TempDir::new().unwrap();
    let file = dir.path().join("doc.json");
    let output = ak_in(
        &server,
        &dir,
        &[
            "admin",
            "config",
            "export",
            "--repositories",
            "a,b",
            "-o",
            file.to_str().unwrap(),
        ],
    )
    .await;
    assert!(output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty());
    let written: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    assert_eq!(written, document());
}

#[tokio::test]
async fn config_plan_sends_the_document_and_its_secrets() {
    let server = server_on("1.12.1").await;
    let dir = TempDir::new().unwrap();
    let doc = dir.path().join("doc.json");
    std::fs::write(&doc, document().to_string()).unwrap();
    let secrets = dir.path().join("secrets.json");
    std::fs::write(&secrets, r#"{"upstream_auth/new":"pw"}"#).unwrap();
    Mock::given(method("POST"))
        .and(path("/api/v1/admin/config/import"))
        .and(query_param("mode", "plan"))
        .and(query_param_is_missing("prune"))
        .and(body_json(json!({"document": document(),
                              "secrets": {"upstream_auth/new": "pw"}})))
        .respond_with(ResponseTemplate::new(200).set_body_json(plan(true)))
        .expect(1)
        .mount(&server)
        .await;
    let output = ak_in(
        &server,
        &dir,
        &[
            "--format",
            "table",
            "admin",
            "config",
            "plan",
            doc.to_str().unwrap(),
            "--secrets-file",
            secrets.to_str().unwrap(),
        ],
    )
    .await;
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("+ create new"), "{stdout}");
    assert!(stdout.contains("~ update changed: description"), "{stdout}");
}

#[tokio::test]
async fn config_plan_fails_on_a_document_that_cant_be_applied() {
    let server = server_on("1.12.1").await;
    let dir = TempDir::new().unwrap();
    let doc = dir.path().join("doc.json");
    std::fs::write(&doc, document().to_string()).unwrap();
    Mock::given(method("POST"))
        .and(path("/api/v1/admin/config/import"))
        .respond_with(ResponseTemplate::new(200).set_body_json(plan(false)))
        .expect(1)
        .mount(&server)
        .await;
    let output = ak_in(
        &server,
        &dir,
        &["admin", "config", "plan", doc.to_str().unwrap()],
    )
    .await;
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    assert!(
        one_line(&output).contains("1 secret(s) missing: upstream_auth/new"),
        "{output:?}"
    );
}

#[tokio::test]
async fn config_apply_with_yes_applies_and_prune_is_sent() {
    for prune in [false, true] {
        let server = server_on("1.12.1").await;
        let dir = TempDir::new().unwrap();
        let doc = dir.path().join("doc.json");
        std::fs::write(&doc, document().to_string()).unwrap();
        let mut applied = plan(true);
        applied["applied"] = json!(true);
        let mock = Mock::given(method("POST"))
            .and(path("/api/v1/admin/config/import"))
            .and(query_param("mode", "apply"))
            .and(body_json(json!({"document": document()})));
        let mock = if prune {
            mock.and(query_param("prune", "true"))
        } else {
            mock.and(query_param_is_missing("prune"))
        };
        mock.respond_with(ResponseTemplate::new(200).set_body_json(&applied))
            .expect(1)
            .mount(&server)
            .await;
        let mut args = vec![
            "--format",
            "json",
            "admin",
            "config",
            "apply",
            doc.to_str().unwrap(),
            "--yes",
        ];
        if prune {
            args.push("--prune");
        }
        let output = ak_in(&server, &dir, &args).await;
        assert!(output.status.success(), "{output:?}");
        let printed: Value = serde_json::from_slice(&output.stdout).expect("JSON");
        assert_eq!(printed, applied);
        assert_eq!(sent(&server).await, ["POST /api/v1/admin/config/import"]);
    }
}

#[tokio::test]
async fn config_apply_and_trash_purge_send_nothing_without_yes() {
    let server = server_on("1.12.1").await;
    let dir = TempDir::new().unwrap();
    let doc = dir.path().join("doc.json");
    std::fs::write(&doc, document().to_string()).unwrap();
    for args in [
        vec![
            "--no-input",
            "admin",
            "config",
            "apply",
            doc.to_str().unwrap(),
        ],
        vec![
            "--no-input",
            "admin",
            "config",
            "apply",
            doc.to_str().unwrap(),
            "--prune",
        ],
        vec!["--no-input", "admin", "trash", "purge", UUID],
    ] {
        let output = ak_in(&server, &dir, &args).await;
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(one_line(&output).contains("--yes"), "{args:?}: {output:?}");
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn config_on_1_11_needs_1_12() {
    let server = server_on("1.11.14").await;
    let dir = TempDir::new().unwrap();
    let doc = dir.path().join("doc.json");
    std::fs::write(&doc, document().to_string()).unwrap();
    let doc = doc.to_str().unwrap().to_string();
    needs_1_12(
        &server,
        &["admin", "config", "export"],
        "`ak admin config export` needs a server on 1.12",
        &["GET /api/v1/admin/config/export"],
    )
    .await;
    let server = server_on("1.11.14").await;
    needs_1_12(
        &server,
        &["admin", "config", "plan", &doc],
        "`ak admin config plan` needs a server on 1.12",
        &["POST /api/v1/admin/config/import"],
    )
    .await;
    let server = server_on("1.11.14").await;
    needs_1_12(
        &server,
        &["admin", "config", "apply", &doc, "--yes"],
        "`ak admin config apply` needs a server on 1.12",
        &["POST /api/v1/admin/config/import"],
    )
    .await;
}

// ---- admin trash purge, admin repo backfill-debian ----

#[tokio::test]
async fn trash_purge_with_yes() {
    let server = server_on("1.12.1").await;
    let purged = json!({"id": UUID, "repository_id": UUID, "repository_key": "r",
                        "path": "a/b.txt", "name": "b.txt", "size_bytes": 2048,
                        "checksum_sha256": "c", "storage_reclaimed": true});
    Mock::given(method("DELETE"))
        .and(path(format!("/api/v1/admin/trash/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&purged))
        .expect(1)
        .mount(&server)
        .await;
    let output = ak(
        &server,
        &[
            "--format", "table", "admin", "trash", "purge", UUID, "--yes",
        ],
    )
    .await;
    assert!(output.status.success(), "{output:?}");
    assert!(
        one_line(&output).contains("Purged 'a/b.txt' in repository 'r'"),
        "{output:?}"
    );
    assert!(one_line(&output).contains("freed 2.0 KB"), "{output:?}");
}

#[tokio::test]
async fn backfill_debian_sends_every_field() {
    let server = server_on("1.12.1").await;
    let result = json!({"dry_run": true, "artifacts_scanned": 3, "packages_registered": 2,
                        "packages_relocated": 1, "artifacts_skipped": 0, "artifacts_failed": 0,
                        "dists_removed": 1, "truncated": true, "next_after": UUID,
                        "registered_paths": ["pool/main/a.deb"], "errors": []});
    Mock::given(method("POST"))
        .and(path("/api/v1/admin/repositories/deb/backfill-debian"))
        .and(body_json(
            json!({"dry_run": true, "limit": 5, "after": UUID}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(&result))
        .expect(1)
        .mount(&server)
        .await;
    let output = ak(
        &server,
        &[
            "--format",
            "table",
            "admin",
            "repo",
            "backfill-debian",
            "deb",
            "--dry-run",
            "--limit",
            "5",
            "--after",
            UUID,
        ],
    )
    .await;
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(&format!("--after {UUID}")), "{stdout}");
    assert!(stdout.contains("Registered: pool/main/a.deb"), "{stdout}");
}

#[tokio::test]
async fn backfill_debian_asks_unless_it_is_a_dry_run() {
    let server = server_on("1.12.1").await;
    let output = ak(
        &server,
        &["--no-input", "admin", "repo", "backfill-debian", "deb"],
    )
    .await;
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn trash_purge_and_backfill_on_1_11_need_1_12_and_send_nothing() {
    // The version check comes before the prompt, and before the request.
    let server = server_on("1.11.14").await;
    needs_1_12(
        &server,
        &["admin", "trash", "purge", UUID, "--yes"],
        "`ak admin trash purge` needs a server on 1.12",
        &[],
    )
    .await;
    let server = server_on("1.11.14").await;
    needs_1_12(
        &server,
        &["admin", "repo", "backfill-debian", "deb", "--yes"],
        "`ak admin repo backfill-debian` needs a server on 1.12",
        &[],
    )
    .await;
}

// ---- system quota ----

fn quota() -> Value {
    json!({"max_upload_bytes": 0, "quota_help_url": "https://example.com/quota",
           "storage_quota": {"enabled": true, "used_bytes": 1024, "quota_bytes": 4096,
                             "percent": 25.0, "state": "ok", "warn_percent": 80},
           "transfer_quota": {"enabled": false, "used_bytes": 0, "grace_percent": 10,
                              "warn_percent": 80, "state": "ok",
                              "period_start": "2026-11-01T00:00:00Z",
                              "period_end": "2026-12-01T00:00:00Z"},
           "from_a_newer_server": true})
}

#[tokio::test]
async fn system_quota_prints_the_quotas() {
    let server = server_on("1.12.1").await;
    Mock::given(method("GET"))
        .and(path("/api/v1/system/quota"))
        .respond_with(ResponseTemplate::new(200).set_body_json(quota()))
        .expect(2)
        .mount(&server)
        .await;
    let output = ak(&server, &["--format", "json", "system", "quota"]).await;
    assert!(output.status.success(), "{output:?}");
    let printed: Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(printed, quota());

    let output = ak(&server, &["--format", "table", "system", "quota"]).await;
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("1.0 KB of 4.0 KB (25.0%), ok"), "{stdout}");
    assert!(stdout.contains("0 B used, no quota"), "{stdout}");
    assert!(stdout.contains("unlimited"), "{stdout}");
}

#[tokio::test]
async fn system_quota_on_1_11_needs_1_12() {
    let server = server_on("1.11.14").await;
    needs_1_12(
        &server,
        &["system", "quota"],
        "`ak system quota` needs a server on 1.12",
        &["GET /api/v1/system/quota"],
    )
    .await;
}

// ---- flags new in 1.12 on existing commands ----

#[tokio::test]
async fn downloads_send_the_downloader() {
    let server = server_on("1.12.1").await;
    let empty = json!({"downloads": [], "page": 1, "per_page": 20, "total": 0});
    for route in [
        "/api/v1/admin/downloads".to_string(),
        "/api/v1/admin/downloads/by-ip/10.0.0.1".to_string(),
        format!("/api/v1/admin/downloads/by-user/{UUID}"),
    ] {
        Mock::given(method("GET"))
            .and(path(route))
            .and(query_param("downloader", "anonymous"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&empty))
            .expect(1)
            .mount(&server)
            .await;
    }
    for args in [
        vec!["admin", "downloads", "list"],
        vec!["admin", "downloads", "by-ip", "10.0.0.1"],
        vec!["admin", "downloads", "by-user", UUID],
    ] {
        let mut args = args.clone();
        args.extend(["--downloader", "anonymous"]);
        let output = ak(&server, &args).await;
        assert!(output.status.success(), "{args:?}: {output:?}");
    }
}

#[tokio::test]
async fn runtime_settings_send_the_new_fields() {
    let response = json!({"guest_access_enabled": true, "guest_access_source": "database",
                          "guest_access_editable": true, "hidden_nav_items": ["/peers"],
                          "upstream_jobs_paused": true, "upstream_jobs_paused_source": "database",
                          "upstream_jobs_paused_stored": true});
    for (args, body) in [
        (
            vec!["--hidden-nav-items", "/peers,/builds"],
            json!({"hidden_nav_items": ["/peers", "/builds"]}),
        ),
        (
            vec!["--no-hidden-nav-items"],
            json!({"hidden_nav_items": []}),
        ),
        (
            vec!["--upstream-jobs-paused", "true", "--guest-access", "false"],
            json!({"upstream_jobs_paused": true, "guest_access_enabled": false}),
        ),
    ] {
        let server = server_on("1.12.1").await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/admin/settings/system"))
            .and(body_json(&body))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .expect(1)
            .mount(&server)
            .await;
        let mut all = vec!["--format", "table", "admin", "settings", "system", "update"];
        all.extend(args);
        let output = ak(&server, &all).await;
        assert!(output.status.success(), "{all:?}: {output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("Upstream jobs paused: true"), "{stdout}");
        assert!(stdout.contains("Hidden nav items:     /peers"), "{stdout}");
    }
    // Something has to change.
    let server = server_on("1.12.1").await;
    let output = ak(&server, &["admin", "settings", "system", "update"]).await;
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    // An empty list isn't how to clear it.
    let output = ak(
        &server,
        &[
            "admin",
            "settings",
            "system",
            "update",
            "--hidden-nav-items",
            "",
        ],
    )
    .await;
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(
        one_line(&output).contains("--no-hidden-nav-items"),
        "{output:?}"
    );
    assert!(sent(&server).await.is_empty());
}

fn provider() -> Value {
    json!({"id": UUID, "name": "gh", "issuer_url": "https://token.actions.githubusercontent.com",
           "audience": "ak", "provider_type": "github", "is_enabled": true,
           "key_source": "discovery", "mapping_count": 0, "token_ttl_secs": 600,
           "created_at": AT, "updated_at": AT})
}

#[tokio::test]
async fn ci_oidc_sends_the_token_ttl() {
    let server = server_on("1.12.1").await;
    Mock::given(method("POST"))
        .and(path("/api/v1/admin/ci-oidc"))
        .and(body_json(json!({"name": "gh",
                              "issuer_url": "https://token.actions.githubusercontent.com",
                              "token_ttl_secs": 600})))
        .respond_with(ResponseTemplate::new(200).set_body_json(provider()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path(format!("/api/v1/admin/ci-oidc/{UUID}")))
        .and(body_json(json!({"token_ttl_secs": 600})))
        .respond_with(ResponseTemplate::new(200).set_body_json(provider()))
        .expect(1)
        .mount(&server)
        .await;
    for args in [
        vec![
            "admin",
            "ci-oidc",
            "create",
            "gh",
            "https://token.actions.githubusercontent.com",
            "--token-ttl-secs",
            "600",
        ],
        vec![
            "admin",
            "ci-oidc",
            "update",
            UUID,
            "--token-ttl-secs",
            "600",
        ],
    ] {
        let output = ak(&server, &args).await;
        assert!(output.status.success(), "{args:?}: {output:?}");
    }
}

#[tokio::test]
async fn proxy_patch_sends_a_patch() {
    let server = server_on("1.12.1").await;
    Mock::given(method("PATCH"))
        .and(path(format!("/api/v1/instances/{UUID}/proxy/x")))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let output = ak(
        &server,
        &[
            "admin", "instance", "proxy", "patch", UUID, "x", "--body", "{}",
        ],
    )
    .await;
    assert!(output.status.success(), "{output:?}");
}

#[tokio::test]
async fn proxy_patch_on_1_11_needs_1_12() {
    let server = server_on("1.11.14").await;
    Mock::given(method("PATCH"))
        .respond_with(ResponseTemplate::new(405))
        .mount(&server)
        .await;
    needs_1_12(
        &server,
        &["admin", "instance", "proxy", "patch", UUID, "x"],
        "`ak admin instance proxy patch` needs a server on 1.12",
        &[&format!("PATCH /api/v1/instances/{UUID}/proxy/x")],
    )
    .await;
}

#[tokio::test]
async fn catalog_versions_sends_the_repository() {
    let server = server_on("1.12.1").await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/packages/{UUID}/versions")))
        .and(query_param("repository_key", "npm-local"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"versions": []})))
        .expect(1)
        .mount(&server)
        .await;
    let output = ak(
        &server,
        &["catalog", "versions", UUID, "--repository-key", "npm-local"],
    )
    .await;
    assert!(output.status.success(), "{output:?}");
}

#[tokio::test]
async fn the_new_flags_are_refused_on_1_11_before_anything_is_sent() {
    let cases: &[(&[&str], &str)] = &[
        (
            &["admin", "downloads", "list", "--downloader", "anonymous"],
            "--downloader",
        ),
        (
            &[
                "admin",
                "downloads",
                "by-ip",
                "10.0.0.1",
                "--downloader",
                "all",
            ],
            "--downloader",
        ),
        (
            &[
                "admin",
                "settings",
                "system",
                "update",
                "--guest-access",
                "true",
                "--hidden-nav-items",
                "/peers",
            ],
            "--hidden-nav-items",
        ),
        (
            &[
                "admin",
                "settings",
                "system",
                "update",
                "--no-hidden-nav-items",
            ],
            "--no-hidden-nav-items",
        ),
        (
            &[
                "admin",
                "settings",
                "system",
                "update",
                "--upstream-jobs-paused",
                "true",
            ],
            "--upstream-jobs-paused",
        ),
        (
            &[
                "admin",
                "ci-oidc",
                "create",
                "gh",
                "https://token.actions.githubusercontent.com",
                "--token-ttl-secs",
                "600",
            ],
            "--token-ttl-secs",
        ),
        (
            &[
                "admin",
                "ci-oidc",
                "update",
                UUID,
                "--token-ttl-secs",
                "600",
            ],
            "--token-ttl-secs",
        ),
        (
            &["catalog", "versions", UUID, "--repository-key", "npm-local"],
            "--repository-key",
        ),
    ];
    for (args, flag) in cases {
        let server = server_on("1.11.14").await;
        let output = ak(&server, args).await;
        assert!(!output.status.success(), "{args:?}: {output:?}");
        let stderr = one_line(&output);
        assert!(
            stderr.contains(&format!("{flag} needs a server on 1.12")),
            "{args:?}: {stderr}"
        );
        assert!(stderr.contains("Nothing was changed"), "{args:?}: {stderr}");
        assert!(sent(&server).await.is_empty(), "{args:?} sent a request");
    }
}
