//! Contract, not E2E: what the admin settings and storage commands send and
//! print, against a mock server. `e2e_admin_settings_storage.rs` runs them for
//! real, except for `admin diag`, which needs a server built with its `profiling`
//! feature and so is only tested here.

use std::process::Output;

use assert_cmd::Command;
use serde_json::{Value, json};
use tempfile::TempDir;
use wiremock::matchers::{body_json, method, path, query_param};
use wiremock::{Mock, MockBuilder, MockServer, Request, ResponseTemplate};

const UUID: &str = "00000000-0000-0000-0000-000000000001";

async fn ak(server: &MockServer, args: &[&str]) -> Output {
    let dir = TempDir::new().expect("temp dir");
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

/// Mount `mock` to answer once with `body`, run `args` with JSON output, and
/// check that it printed the body it was sent. The mock's matchers check the
/// request. A newer server's field has to survive.
async fn check(mock: MockBuilder, mut body: Value, args: &[&str]) {
    body["from_a_newer_server"] = json!(true);
    let server = MockServer::start().await;
    mock.respond_with(ResponseTemplate::new(200).set_body_json(&body))
        .expect(1)
        .mount(&server)
        .await;
    let mut all = vec!["--format", "json"];
    all.extend_from_slice(args);
    let output = ak(&server, &all).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{args:?}: {stderr}");
    let printed: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("{args:?}: not JSON: {e}: {stderr}"));
    assert_eq!(printed, body, "{args:?}");
}

/// With no terminal and no `--yes`, a command that asks first sends nothing.
async fn refuses_without_yes(args: &[&str]) {
    let server = MockServer::start().await;
    let output = ak(&server, args).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{args:?}");
    assert!(stderr.contains("--yes"), "{args:?}: {stderr}");
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "{args:?} sent a request"
    );
}

fn runtime_settings() -> Value {
    json!({
        "guest_access_enabled": false, "guest_access_source": "database",
        "guest_access_stored": false, "guest_access_editable": true
    })
}

fn token_policy() -> Value {
    json!({
        "policy": {
            "require_expiration": false, "min_days": 1, "max_days": 90, "default_days": 30,
            "apply_to_service_accounts": false
        },
        "source": "database", "editable": true, "non_expiring_user_tokens": 0,
        "non_expiring_service_account_tokens": 0
    })
}

fn totp_policy() -> Value {
    json!({
        "policy": "required_for_admins", "source": "database", "editable": true,
        "local_admins": 1, "local_admins_with_totp": 1, "local_users": 1,
        "local_users_with_totp": 1, "caller_totp_enabled": true
    })
}

fn scrub_result() -> Value {
    json!({
        "objects_checked": 1, "bytes_read": 1, "intact": 1, "corrupt": 0, "missing": 0,
        "repaired": 0, "unverifiable": 0, "skipped_concurrent": 0, "cycle_completed": true,
        "findings": [], "errors": []
    })
}

fn trashed() -> Value {
    json!({
        "id": UUID, "repository_id": UUID, "repository_key": "r", "path": "a", "name": "a",
        "size_bytes": 1, "checksum_sha256": "c", "restorable": true
    })
}

fn plugin() -> Value {
    json!({
        "id": UUID, "name": "p", "version": "1", "display_name": "P", "status": "disabled",
        "plugin_type": "formathandler", "config_schema": null,
        "installed_at": "2026-01-15T12:00:00Z"
    })
}

#[tokio::test]
async fn settings_reads() {
    for (route, body, args) in [
        (
            "/api/v1/admin/settings/system",
            runtime_settings(),
            vec!["admin", "settings", "system", "show"],
        ),
        (
            "/api/v1/admin/settings/token-policy",
            token_policy(),
            vec!["admin", "settings", "token-policy", "show"],
        ),
        (
            "/api/v1/admin/settings/totp-policy",
            totp_policy(),
            vec!["admin", "settings", "totp-policy", "show"],
        ),
    ] {
        check(Mock::given(method("GET")).and(path(route)), body, &args).await;
    }
}

#[tokio::test]
async fn system_update_sends_guest_access() {
    check(
        Mock::given(method("PATCH"))
            .and(path("/api/v1/admin/settings/system"))
            .and(body_json(json!({"guest_access_enabled": false}))),
        runtime_settings(),
        &[
            "admin",
            "settings",
            "system",
            "update",
            "--guest-access",
            "false",
        ],
    )
    .await;
}

/// `set` replaces the policy, so what you don't name keeps its current value.
async fn token_policy_set_sends(args: &[&str], sent: Value) {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/admin/settings/token-policy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(token_policy()))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/v1/admin/settings/token-policy"))
        .and(body_json(json!({ "policy": sent })))
        .respond_with(ResponseTemplate::new(200).set_body_json(token_policy()))
        .expect(1)
        .mount(&server)
        .await;
    let mut all = vec![
        "--format",
        "json",
        "admin",
        "settings",
        "token-policy",
        "set",
    ];
    all.extend_from_slice(args);
    let output = ak(&server, &all).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn token_policy_set_merges_with_the_current_policy() {
    token_policy_set_sends(
        &["--max-days", "60"],
        json!({
            "require_expiration": false, "min_days": 1, "max_days": 60, "default_days": 30,
            "apply_to_service_accounts": false
        }),
    )
    .await;
}

#[tokio::test]
async fn token_policy_set_binds_every_field() {
    token_policy_set_sends(
        &[
            "--require-expiration",
            "true",
            "--min-days",
            "2",
            "--max-days",
            "60",
            "--default-days",
            "7",
            "--apply-to-service-accounts",
            "true",
        ],
        json!({
            "require_expiration": true, "min_days": 2, "max_days": 60, "default_days": 7,
            "apply_to_service_accounts": true
        }),
    )
    .await;
}

#[tokio::test]
async fn token_policy_set_can_clear_the_default() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/admin/settings/token-policy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(token_policy()))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/v1/admin/settings/token-policy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(token_policy()))
        .mount(&server)
        .await;
    let output = ak(
        &server,
        &[
            "--format",
            "json",
            "admin",
            "settings",
            "token-policy",
            "set",
            "--no-default-days",
        ],
    )
    .await;
    assert!(output.status.success());
    let requests = server.received_requests().await.unwrap();
    let put: &Request = requests
        .iter()
        .find(|r| r.method.as_str() == "PUT")
        .unwrap();
    let body: Value = serde_json::from_slice(&put.body).unwrap();
    assert!(body["policy"]["default_days"].is_null(), "{body}");
    assert_eq!(body["policy"]["max_days"], 90);
}

#[tokio::test]
async fn token_policy_set_with_nothing_to_change_sends_nothing() {
    let server = MockServer::start().await;
    let output = ak(&server, &["admin", "settings", "token-policy", "set"]).await;
    assert!(!output.status.success());
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn totp_policy_set() {
    check(
        Mock::given(method("PUT"))
            .and(path("/api/v1/admin/settings/totp-policy"))
            .and(body_json(json!({"policy": "required_for_admins"}))),
        totp_policy(),
        &[
            "admin",
            "settings",
            "totp-policy",
            "set",
            "required-for-admins",
            "--yes",
        ],
    )
    .await;
}

#[tokio::test]
async fn storage_scrub_run_binds_every_field() {
    check(
        Mock::given(method("POST"))
            .and(path("/api/v1/admin/storage-scrub"))
            .and(body_json(json!({
                "repair": true, "repository": "r", "max_objects": 5, "max_bytes": 6
            }))),
        scrub_result(),
        &[
            "admin",
            "storage-scrub",
            "run",
            "--repair",
            "--repository",
            "r",
            "--max-objects",
            "5",
            "--max-bytes",
            "6",
            "--yes",
        ],
    )
    .await;
}

#[tokio::test]
async fn storage_scrub_findings_sends_every_filter() {
    let server_body = json!([{
        "object_kind": "artifact", "object_id": UUID, "repository_id": UUID,
        "storage_key": "k", "expected_sha256": "e", "status": "corrupt",
        "from_a_newer_server": true
    }]);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/admin/storage-scrub/findings"))
        .and(query_param("status", "corrupt"))
        .and(query_param("limit", "5"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&server_body))
        .expect(1)
        .mount(&server)
        .await;
    let output = ak(
        &server,
        &[
            "--format",
            "json",
            "admin",
            "storage-scrub",
            "findings",
            "--status",
            "corrupt",
            "--limit",
            "5",
        ],
    )
    .await;
    assert!(output.status.success());
    let printed: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(printed, server_body);
}

#[tokio::test]
async fn reindex_storage_binds_every_field() {
    let result = json!({
        "dry_run": true, "scanned": 1, "registered": 0, "skipped": 1, "missing_objects": 0,
        "skipped_recent": 0, "skipped_unknown_age": 0, "truncated": false,
        "registered_paths": [], "missing_object_paths": [], "errors": []
    });
    check(
        Mock::given(method("POST"))
            .and(path("/api/v1/admin/repositories/r/reindex-storage"))
            .and(body_json(json!({"dry_run": true, "limit": 5}))),
        result.clone(),
        &["admin", "reindex-storage", "r", "--dry-run", "--limit", "5"],
    )
    .await;
    check(
        Mock::given(method("POST"))
            .and(path("/api/v1/admin/repositories/r/reindex-storage"))
            .and(body_json(json!({"dry_run": false}))),
        result,
        &["admin", "reindex-storage", "r", "--yes"],
    )
    .await;
}

#[tokio::test]
async fn ledger_backfill() {
    check(
        Mock::given(method("POST")).and(path("/api/v1/admin/storage/ledger/backfill")),
        json!({
            "repositories_checked": 0, "repositories_repaired": 0, "repositories_skipped": 0,
            "total_drift_bytes": 0, "before_total_storage_bytes": 0,
            "after_total_storage_bytes": 0, "repositories": []
        }),
        &["admin", "storage", "ledger-backfill"],
    )
    .await;
}

#[tokio::test]
async fn trash_list_sends_every_filter() {
    check(
        Mock::given(method("GET"))
            .and(path("/api/v1/admin/trash"))
            .and(query_param("repository", "r"))
            .and(query_param("page", "3"))
            .and(query_param("per_page", "7")),
        json!({
            "items": [trashed()],
            "pagination": {"page": 3, "per_page": 7, "total": 1, "total_pages": 1},
            "retention_days": 30
        }),
        &[
            "admin",
            "trash",
            "list",
            "--repository",
            "r",
            "--page",
            "3",
            "--per-page",
            "7",
        ],
    )
    .await;
}

#[tokio::test]
async fn trash_restore_with_yes() {
    check(
        Mock::given(method("POST")).and(path(format!("/api/v1/admin/trash/{UUID}/restore"))),
        trashed(),
        &["admin", "trash", "restore", UUID, "--yes"],
    )
    .await;
}

#[tokio::test]
async fn what_asks_first_sends_nothing_without_yes() {
    refuses_without_yes(&["admin", "trash", "restore", UUID]).await;
    refuses_without_yes(&["admin", "storage-scrub", "run"]).await;
    refuses_without_yes(&["admin", "storage-scrub", "run", "--repair"]).await;
    refuses_without_yes(&["admin", "reindex-storage", "r"]).await;
    refuses_without_yes(&["admin", "settings", "totp-policy", "set", "disabled"]).await;
}

#[tokio::test]
async fn packages_backfill_sends_the_repository() {
    check(
        Mock::given(method("POST"))
            .and(path("/api/v1/admin/packages/backfill"))
            .and(query_param("repository_key", "r")),
        json!({
            "message": "m", "artifacts_scanned": 0, "packages_registered": 0,
            "artifacts_skipped": 0, "artifacts_failed": 0
        }),
        &["catalog", "backfill", "--repo", "r"],
    )
    .await;
}

#[tokio::test]
async fn plugins_install_uploads_a_manifest_as_multipart() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("plugin.json");
    std::fs::write(&file, r#"{"name":"sent-to-the-server"}"#).unwrap();

    let mut body = plugin();
    body["from_a_newer_server"] = json!(true);
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/plugins"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body))
        .expect(1)
        .mount(&server)
        .await;
    let output = ak(
        &server,
        &[
            "--format",
            "json",
            "admin",
            "plugins",
            "install",
            file.to_str().unwrap(),
        ],
    )
    .await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let printed: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(printed, body);

    let requests = server.received_requests().await.unwrap();
    let sent = String::from_utf8_lossy(&requests[0].body);
    let content_type = requests[0].headers["content-type"].to_str().unwrap();
    assert!(
        content_type.starts_with("multipart/form-data"),
        "{content_type}"
    );
    assert!(sent.contains(r#"name="manifest""#), "{sent}");
    assert!(sent.contains(r#"{"name":"sent-to-the-server"}"#), "{sent}");
}

#[tokio::test]
async fn plugins_install_still_takes_a_git_url() {
    check(
        Mock::given(method("POST"))
            .and(path("/api/v1/plugins/install/git"))
            .and(body_json(json!({
                "url": "https://example.test/p.git", "ref": "v1"
            }))),
        json!({
            "plugin_id": UUID, "name": "p", "version": "1", "format_key": "f", "message": "m"
        }),
        &[
            "admin",
            "plugins",
            "install",
            "https://example.test/p.git",
            "--ref",
            "v1",
        ],
    )
    .await;
}

#[tokio::test]
async fn plugins_install_sends_a_zip_to_the_zip_route() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("plugin.zip");
    std::fs::write(&file, b"PK").unwrap();
    check(
        Mock::given(method("POST")).and(path("/api/v1/plugins/install/zip")),
        json!({
            "plugin_id": UUID, "name": "p", "version": "1", "format_key": "f", "message": "m"
        }),
        &["admin", "plugins", "install", file.to_str().unwrap()],
    )
    .await;
}

#[tokio::test]
async fn plugins_install_catches_a_mistyped_file_and_a_ref_on_a_file() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("plugin.json");
    std::fs::write(&file, "{}").unwrap();
    let server = MockServer::start().await;
    let missing = ak(&server, &["admin", "plugins", "install", "nothere.json"]).await;
    assert!(!missing.status.success());
    let with_ref = ak(
        &server,
        &[
            "admin",
            "plugins",
            "install",
            file.to_str().unwrap(),
            "--ref",
            "v1",
        ],
    )
    .await;
    assert!(!with_ref.status.success());
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_plugin_with_a_null_config_schema_can_be_listed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/plugins"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items": [plugin()]})))
        .mount(&server)
        .await;
    let output = ak(&server, &["--format", "table", "admin", "plugins", "list"]).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn diag_memory_prints_the_body_and_a_table() {
    let body = json!({"allocator": "jemalloc", "allocated_bytes": 2048});
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/admin/memory-stats"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body))
        .mount(&server)
        .await;
    let json_output = ak(&server, &["--format", "json", "admin", "diag", "memory"]).await;
    assert!(json_output.status.success());
    let printed: Value = serde_json::from_slice(&json_output.stdout).unwrap();
    assert_eq!(printed, body);

    let table = ak(&server, &["--format", "table", "admin", "diag", "memory"]).await;
    let stdout = String::from_utf8_lossy(&table.stdout);
    assert!(stdout.contains("allocated_bytes: 2.0 KB"), "{stdout}");
}

#[tokio::test]
async fn diag_heap_profile_saves_the_bytes_it_got() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/admin/heap-profile"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0u8, 255, 1]))
        .mount(&server)
        .await;
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("out.prof");
    let output = ak(
        &server,
        &[
            "admin",
            "diag",
            "heap-profile",
            "-o",
            file.to_str().unwrap(),
        ],
    )
    .await;
    assert!(output.status.success());
    assert_eq!(std::fs::read(&file).unwrap(), vec![0u8, 255, 1]);

    let stdout = ak(&server, &["admin", "diag", "heap-profile", "-o", "-"]).await;
    assert_eq!(stdout.stdout, vec![0u8, 255, 1]);
}

#[tokio::test]
async fn diag_heap_profile_activates_and_deactivates() {
    for (flag, query) in [("--activate", "activate"), ("--deactivate", "deactivate")] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/admin/heap-profile"))
            .and(query_param(query, "true"))
            .respond_with(ResponseTemplate::new(200).set_body_string("done\n"))
            .expect(1)
            .mount(&server)
            .await;
        let output = ak(&server, &["admin", "diag", "heap-profile", flag]).await;
        assert!(output.status.success(), "{flag}");
    }
}

#[tokio::test]
async fn diag_on_a_server_without_the_routes_says_so_and_writes_nothing() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(json!({"message": "Repository not found"})),
        )
        .mount(&server)
        .await;
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("out.prof");
    std::fs::write(&file, "keep me").unwrap();
    let output = ak(
        &server,
        &[
            "admin",
            "diag",
            "heap-profile",
            "-o",
            file.to_str().unwrap(),
        ],
    )
    .await;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr).replace("│", " ");
    let flat = stderr.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(flat.contains("profiling"), "{flat}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "keep me");
}

#[tokio::test]
async fn the_operator_commands_stay_out_of_the_help_but_have_their_own() {
    let server = MockServer::start().await;
    let help = ak(&server, &["admin", "--help"]).await;
    let text = String::from_utf8_lossy(&help.stdout);
    assert!(text.contains("storage-scrub"), "{text}");
    for line in text.lines() {
        let word = line.split_whitespace().next().unwrap_or("");
        assert!(word != "diag" && word != "storage", "{line}");
    }
    let diag = ak(&server, &["admin", "diag", "--help"]).await;
    assert!(String::from_utf8_lossy(&diag.stdout).contains("heap-profile"));
}

// ---- #301: admin settings update ----

/// `GET /api/v1/admin/settings` as 1.12 answers it.
fn settings_1_12() -> Value {
    json!({
        "storage_backend": "filesystem", "storage_path": "/data", "environment": "test",
        "max_upload_size_bytes": 10_737_418_240_i64, "retention_days": 365,
        "audit_retention_days": 0, "backup_retention_count": 10,
        "edge_stale_threshold_minutes": 5
    })
}

/// The same as 1.11 answers it, with the field 1.12 removed.
fn settings_1_11() -> Value {
    let mut settings = settings_1_12();
    settings["allow_anonymous_download"] = json!(false);
    settings
}

async fn settings_server(current: Value) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/admin/settings"))
        .respond_with(ResponseTemplate::new(200).set_body_json(current))
        .mount(&server)
        .await;
    server
}

async fn posted(server: &MockServer) -> Vec<Value> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.method.as_str() == "POST")
        .map(|r| serde_json::from_slice(&r.body).expect("JSON body"))
        .collect()
}

fn one_line(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr)
        .replace('│', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[tokio::test]
async fn settings_update_sends_only_the_change_to_1_12() {
    let server = settings_server(settings_1_12()).await;
    let mut after = settings_1_12();
    after["retention_days"] = json!(30);
    Mock::given(method("POST"))
        .and(path("/api/v1/admin/settings"))
        .and(body_json(json!({"retention_days": 30})))
        .respond_with(ResponseTemplate::new(200).set_body_json(after))
        .expect(1)
        .mount(&server)
        .await;
    let output = ak(
        &server,
        &[
            "--format",
            "table",
            "admin",
            "settings",
            "update",
            "--json",
            r#"{"retention_days":30}"#,
        ],
    )
    .await;
    assert!(output.status.success(), "{output:?}");
    assert!(
        one_line(&output).contains("retention_days 365 -> 30"),
        "{output:?}"
    );
}

#[tokio::test]
async fn settings_update_sends_the_whole_body_to_1_11() {
    let server = settings_server(settings_1_11()).await;
    let mut full = settings_1_11();
    full["audit_retention_days"] = json!(90);
    Mock::given(method("POST"))
        .and(path("/api/v1/admin/settings"))
        .and(body_json(full.clone()))
        .respond_with(ResponseTemplate::new(200).set_body_json(full))
        .expect(1)
        .mount(&server)
        .await;
    let output = ak(
        &server,
        &[
            "--format",
            "json",
            "admin",
            "settings",
            "update",
            "--json",
            r#"{"audit_retention_days":90}"#,
        ],
    )
    .await;
    assert!(output.status.success(), "{output:?}");
    let printed: Value = serde_json::from_slice(&output.stdout).expect("JSON output");
    assert_eq!(printed["audit_retention_days"], 90);
}

#[tokio::test]
async fn settings_update_takes_a_show_body_sent_back() {
    let server = settings_server(settings_1_12()).await;
    Mock::given(method("POST"))
        .and(path("/api/v1/admin/settings"))
        .respond_with(ResponseTemplate::new(200).set_body_json(settings_1_12()))
        .expect(1)
        .mount(&server)
        .await;
    let mut body = settings_1_12();
    body["backup_retention_count"] = json!(3);
    let output = ak(
        &server,
        &["admin", "settings", "update", "--json", &body.to_string()],
    )
    .await;
    assert!(output.status.success(), "{output:?}");
    // The read-only fields, unchanged, aren't sent.
    assert_eq!(
        posted(&server).await,
        vec![json!({"retention_days": 365, "audit_retention_days": 0,
                    "backup_retention_count": 3, "edge_stale_threshold_minutes": 5})]
    );
}

#[tokio::test]
async fn settings_update_refuses_what_the_server_would_not_apply() {
    let cases: &[(Value, &str, &[&str])] = &[
        (
            settings_1_12(),
            r#"{"retention_dayz":1,"colour":"red","audit_retention_days":1}"#,
            &[
                "unknown settings retention_dayz, colour",
                "Nothing was changed",
            ],
        ),
        (
            settings_1_12(),
            r#"{"allow_anonymous_download":true}"#,
            &[
                "allow_anonymous_download can't be changed",
                "--guest-access",
            ],
        ),
        (
            settings_1_11(),
            r#"{"allow_anonymous_download":true}"#,
            &[
                "allow_anonymous_download can't be changed",
                "--guest-access",
            ],
        ),
        (
            settings_1_12(),
            r#"{"max_upload_size_bytes":1}"#,
            &[
                "max_upload_size_bytes can't be changed",
                "MAX_UPLOAD_SIZE",
                "10737418240",
            ],
        ),
        (
            settings_1_11(),
            r#"{"storage_path":"/elsewhere"}"#,
            &["storage_path can't be changed", "STORAGE_PATH"],
        ),
        (settings_1_12(), r#"{}"#, &["changes nothing"]),
        (settings_1_12(), r#"[1]"#, &["must be a JSON object"]),
        (settings_1_12(), r#"{"retention_days":"a"}"#, &["--json"]),
    ];
    for (current, json, expected) in cases {
        let server = settings_server(current.clone()).await;
        let output = ak(&server, &["admin", "settings", "update", "--json", json]).await;
        assert_eq!(output.status.code(), Some(2), "{json}: {output:?}");
        let stderr = one_line(&output);
        for needle in *expected {
            assert!(stderr.contains(needle), "{json}: {stderr}");
        }
        assert!(posted(&server).await.is_empty(), "{json} was sent");
    }
}

async fn reports_version(server: &MockServer, version: &str) {
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"status": "healthy", "version": version})),
        )
        .mount(server)
        .await;
}

#[tokio::test]
async fn settings_update_goes_by_the_server_version() {
    // A 1.11 server whose body doesn't name allow_anonymous_download still gets the
    // whole body.
    let server = settings_server(settings_1_12()).await;
    reports_version(&server, "1.11.14").await;
    let mut full = settings_1_12();
    full["retention_days"] = json!(30);
    Mock::given(method("POST"))
        .and(path("/api/v1/admin/settings"))
        .and(body_json(full.clone()))
        .respond_with(ResponseTemplate::new(200).set_body_json(full))
        .expect(1)
        .mount(&server)
        .await;
    let args = [
        "admin",
        "settings",
        "update",
        "--json",
        r#"{"retention_days":30}"#,
    ];
    let output = ak(&server, &args).await;
    assert!(output.status.success(), "{output:?}");

    // A 1.12 server that still reports it gets only the change.
    let server = settings_server(settings_1_11()).await;
    reports_version(&server, "1.12.1").await;
    let mut after = settings_1_12();
    after["retention_days"] = json!(30);
    Mock::given(method("POST"))
        .and(path("/api/v1/admin/settings"))
        .and(body_json(json!({"retention_days": 30})))
        .respond_with(ResponseTemplate::new(200).set_body_json(after))
        .expect(1)
        .mount(&server)
        .await;
    let output = ak(&server, &args).await;
    assert!(output.status.success(), "{output:?}");
}

#[tokio::test]
async fn settings_update_refuses_a_null() {
    for current in [settings_1_12(), settings_1_11()] {
        let server = settings_server(current).await;
        let output = ak(
            &server,
            &[
                "admin",
                "settings",
                "update",
                "--json",
                r#"{"retention_days":null}"#,
            ],
        )
        .await;
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        let stderr = one_line(&output);
        assert!(stderr.contains("retention_days can't be null"), "{stderr}");
        assert!(posted(&server).await.is_empty(), "a null was sent");
    }
}

#[tokio::test]
async fn settings_update_compares_read_only_numbers_by_value() {
    let server = settings_server(settings_1_12()).await;
    Mock::given(method("POST"))
        .and(path("/api/v1/admin/settings"))
        .respond_with(ResponseTemplate::new(200).set_body_json(settings_1_12()))
        .expect(1)
        .mount(&server)
        .await;
    let output = ak(
        &server,
        &[
            "admin",
            "settings",
            "update",
            "--json",
            r#"{"max_upload_size_bytes":10737418240.0,"retention_days":30}"#,
        ],
    )
    .await;
    assert!(output.status.success(), "{output:?}");
    assert_eq!(posted(&server).await, vec![json!({"retention_days": 30})]);
}
