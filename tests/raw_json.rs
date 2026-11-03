//! `--format json` and `yaml` print what the server sent, so a field the SDK has
//! never heard of still reaches the user. Each command here is one that has
//! moved to `output::render_raw`.

use std::process::Output;

use assert_cmd::Command;
use serde_json::{Value, json};
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const UUID: &str = "00000000-0000-0000-0000-000000000001";

fn repository() -> Value {
    json!({
        "id": UUID, "key": "r", "name": "r", "format": "generic", "repo_type": "local",
        "visibility": "private", "is_public": false, "allow_anonymous_access": false,
        "promotion_only": false, "versioning_enabled": false, "repodata_depth": 0,
        "repodata_depth_editable": false, "storage_backend": "filesystem",
        "storage_used_bytes": 0, "has_trusted_gpg_key": false,
        "upstream_url_has_credentials": false, "upstream_auth_configured": false,
        "public_with_upstream_credentials": false,
        "allow_public_with_upstream_credentials": false, "curation_enabled": false,
        "curation_default_action": "allow", "created_at": "2026-01-15T12:00:00Z",
        "updated_at": "2026-01-15T12:00:00Z", "from_a_newer_server": {"nested": [1, 2]}
    })
}

fn artifact() -> Value {
    json!({
        "id": UUID, "repository_key": "r", "path": "a.bin", "name": "a.bin",
        "size_bytes": 3, "checksum_sha256": "abc", "content_type": "text/plain",
        "download_count": 0, "created_at": "2026-01-15T12:00:00Z", "analyzable": false,
        "quarantine_status": "clean", "from_a_newer_server": {"nested": [1, 2]}
    })
}

fn list_of(item: Value) -> Value {
    json!({
        "items": [item],
        "pagination": {"page": 1, "per_page": 20, "total": 1, "total_pages": 1},
        "from_a_newer_server": true
    })
}

async fn run(route: &str, verb: &str, body: &Value, args: &[&str]) -> Output {
    let server = MockServer::start().await;
    Mock::given(method(verb))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;
    run_against(&server, args)
}

fn run_against(server: &MockServer, args: &[&str]) -> Output {
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
        .env("AK_CONFIG_DIR", dir.path())
        .env("AK_TOKEN", "t")
        .env("AK_CREDENTIAL_STORE", "file")
        .args(["--no-input"])
        .args(args)
        .output()
        .expect("run ak")
}

async fn assert_prints_the_body(route: &str, verb: &str, body: Value, args: &[&str]) {
    let mut with_format = args.to_vec();
    with_format.extend(["--format", "json"]);
    let output = run(route, verb, &body, &with_format).await;
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(output.status.code(), Some(0), "{args:?}: {stderr}");
    let shown: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("{args:?}: not JSON: {e}"));
    assert_eq!(shown, body, "{args:?}");

    let mut with_format = args.to_vec();
    with_format.extend(["--format", "yaml"]);
    let output = run(route, verb, &body, &with_format).await;
    let shown: Value = serde_yaml::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("{args:?}: not YAML: {e}"));
    assert_eq!(shown, body, "{args:?}");
}

#[tokio::test]
async fn repo_commands() {
    assert_prints_the_body(
        "/api/v1/repositories",
        "GET",
        list_of(repository()),
        &["repo", "list"],
    )
    .await;
    assert_prints_the_body(
        "/api/v1/repositories/r",
        "GET",
        repository(),
        &["repo", "show", "r"],
    )
    .await;
    assert_prints_the_body(
        "/api/v1/repositories",
        "POST",
        repository(),
        &["repo", "create", "r", "--pkg-format", "generic"],
    )
    .await;
}

#[tokio::test]
async fn artifact_commands() {
    assert_prints_the_body(
        "/api/v1/repositories/r/artifacts",
        "GET",
        list_of(artifact()),
        &["artifact", "list", "r"],
    )
    .await;
    assert_prints_the_body(
        "/api/v1/repositories/r/artifacts/a.bin",
        "GET",
        artifact(),
        &["artifact", "info", "r", "a.bin"],
    )
    .await;
    assert_prints_the_body(
        &format!("/api/v1/artifacts/{UUID}"),
        "GET",
        artifact(),
        &["artifact", "show", UUID],
    )
    .await;
}

#[tokio::test]
async fn whoami() {
    assert_prints_the_body(
        "/api/v1/auth/me",
        "GET",
        json!({
            "id": UUID, "username": "admin", "email": "a@example.com", "is_admin": true,
            "totp_enabled": false, "from_a_newer_server": 1
        }),
        &["auth", "whoami"],
    )
    .await;
}

#[tokio::test]
async fn an_empty_list_still_prints_the_body() {
    let empty = json!({
        "items": [],
        "pagination": {"page": 1, "per_page": 20, "total": 0, "total_pages": 0}
    });
    assert_prints_the_body("/api/v1/repositories", "GET", empty, &["repo", "list"]).await;
}

#[tokio::test]
async fn the_table_is_unchanged() {
    let output = run(
        "/api/v1/repositories/r",
        "GET",
        &repository(),
        &["repo", "show", "r", "--format", "table"],
    )
    .await;
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Key:"), "{stdout}");
    assert!(!stdout.contains("from_a_newer_server"), "{stdout}");
}

/// One runtime per case: many mock servers on a single test's runtime stall.
#[test]
fn repo_settings_commands() {
    let allowlist = json!({
        "repository_key": "r", "enabled": true, "scope": "all_members",
        "entries": [{"name": "numpy"}], "entry_count": 1, "from_a_newer_server": 1
    });
    let filter = json!({
        "repository_key": "r", "include_patterns": ["a"], "exclude_patterns": [],
        "active": true, "from_a_newer_server": 1
    });
    let proxy = json!({
        "mode": "explicit", "proxy_url": "https://***@p.example.com/",
        "proxy_credentials_configured": true, "from_a_newer_server": 1
    });
    let npm = json!({
        "repository_key": "r", "allowed_scopes": ["@a"], "allow_unscoped": false,
        "active": true, "from_a_newer_server": 1
    });
    let storage = json!({
        "repository_key": "r", "logical_bytes": 1, "blob_count": 1, "dedup_scope": "per_repo",
        "from_a_newer_server": 1
    });
    let node = json!({
        "prefix": "", "depth": 0, "logical_bytes": 1, "physical_bytes": 1, "file_count": 1,
        "blob_count": 1
    });
    let tree = json!({
        "repository_key": "r", "node": node, "children": [node], "truncated": false,
        "max_materialized_depth": 16, "from_a_newer_server": 1
    });
    let gc = json!({
        "dry_run": true, "storage_keys_deleted": 0, "artifacts_removed": 0, "bytes_freed": 0,
        "errors": [], "from_a_newer_server": 1
    });
    let caps = json!({
        "rpm_repodata_depth": {"supported": true, "min": 0, "max": 9, "default": 0},
        "from_a_newer_server": 1
    });
    let base = "/api/v1/repositories/r";
    let cases: Vec<(String, &str, Value, Vec<&str>)> = vec![
        (
            format!("{base}/allowlist"),
            "GET",
            allowlist.clone(),
            vec!["repo", "allowlist", "get", "r"],
        ),
        (
            format!("{base}/allowlist"),
            "PUT",
            allowlist.clone(),
            vec!["repo", "allowlist", "set", "r", "--package", "numpy"],
        ),
        (
            format!("{base}/allowlist"),
            "DELETE",
            allowlist,
            vec!["repo", "allowlist", "delete", "r", "--yes"],
        ),
        (
            format!("{base}/upstream-filter"),
            "GET",
            filter.clone(),
            vec!["repo", "upstream-filter", "get", "r"],
        ),
        (
            format!("{base}/upstream-filter"),
            "PUT",
            filter.clone(),
            vec!["repo", "upstream-filter", "set", "r", "--include", "a"],
        ),
        (
            format!("{base}/upstream-filter"),
            "DELETE",
            filter,
            vec!["repo", "upstream-filter", "delete", "r", "--yes"],
        ),
        (
            format!("{base}/egress-proxy"),
            "GET",
            proxy.clone(),
            vec!["repo", "egress-proxy", "get", "r"],
        ),
        (
            format!("{base}/egress-proxy"),
            "PUT",
            proxy,
            vec!["repo", "egress-proxy", "set", "r", "--mode", "direct"],
        ),
        (
            format!("{base}/npm-scope-policy"),
            "GET",
            npm.clone(),
            vec!["repo", "npm-scope-policy", "get", "r"],
        ),
        (
            format!("{base}/npm-scope-policy"),
            "PUT",
            npm,
            vec![
                "repo",
                "npm-scope-policy",
                "set",
                "r",
                "--allowed-scopes",
                "@a",
            ],
        ),
        (
            format!("{base}/storage"),
            "GET",
            storage,
            vec!["repo", "storage", "r"],
        ),
        (
            format!("{base}/storage/tree"),
            "GET",
            tree,
            vec!["repo", "storage", "r", "--tree"],
        ),
        (
            format!("{base}/storage-gc"),
            "POST",
            gc,
            vec!["repo", "storage-gc", "r", "--dry-run"],
        ),
        (
            "/api/v1/repositories/_/capabilities".to_string(),
            "GET",
            caps,
            vec!["repo", "capabilities"],
        ),
        (
            format!("{base}/routing-rules"),
            "GET",
            json!({"repository_key": "r", "rules": [], "from_a_newer_server": 1}),
            vec!["repo", "routing-rules", "get", "r"],
        ),
        (
            format!("{base}/routing-rules"),
            "POST",
            json!({"repository_key": "r", "rules": [], "from_a_newer_server": 1}),
            vec!["repo", "routing-rules", "set", "r", "--rule", "a=>b"],
        ),
        (
            format!("{base}/routing-rules"),
            "DELETE",
            json!({"message": "Routing rules deleted", "from_a_newer_server": 1}),
            vec!["repo", "routing-rules", "delete", "r", "--yes"],
        ),
        (
            format!("{base}/cache-ttl"),
            "GET",
            json!({"repository_key": "r", "cache_ttl_seconds": 1, "from_a_newer_server": 1}),
            vec!["repo", "cache", "get-ttl", "r"],
        ),
        (
            format!("{base}/cache-ttl"),
            "PUT",
            json!({"repository_key": "r", "cache_ttl_seconds": 1, "from_a_newer_server": 1}),
            vec!["repo", "cache", "set-ttl", "r", "1"],
        ),
        (
            format!("{base}/cache/invalidate"),
            "POST",
            json!({"repository_key": "r", "path": "p", "invalidated": true, "from_a_newer_server": 1}),
            vec!["repo", "cache", "invalidate", "r", "p"],
        ),
        (
            format!("{base}/pypi-tracks"),
            "GET",
            json!({"items": [], "from_a_newer_server": 1}),
            vec!["repo", "pypi-tracks", "list", "r"],
        ),
        (
            format!("{base}/upstream-auth"),
            "PUT",
            json!({"message": "Upstream auth removed", "from_a_newer_server": 1}),
            vec!["repo", "upstream-auth", "r", "--type", "none"],
        ),
        (
            format!("{base}/test-upstream"),
            "POST",
            json!({"status": "ok", "from_a_newer_server": 1}),
            vec!["repo", "test-upstream", "r"],
        ),
        (
            "/api/v1/tree".to_string(),
            "GET",
            json!({"nodes": [], "from_a_newer_server": 1}),
            vec!["repo", "tree", "r"],
        ),
    ];
    for (route, verb, body, args) in cases {
        tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(assert_prints_the_body(&route, verb, body, &args));
    }
}

fn admin_user() -> Value {
    json!({
        "id": UUID, "username": "alice", "email": "alice@example.com", "is_admin": false,
        "is_active": true, "is_service_account": false, "must_change_password": false,
        "auth_provider": "local", "created_at": "2026-01-15T12:00:00Z",
        "from_a_newer_server": {"nested": [1, 2]}
    })
}

fn plugin_install() -> Value {
    json!({
        "plugin_id": UUID, "name": "p", "version": "1.0.0", "format_key": "f",
        "message": "Installed", "from_a_newer_server": true
    })
}

fn gate() -> Value {
    json!({
        "id": UUID, "name": "g", "action": "warn", "is_enabled": true,
        "enforce_on_download": false, "enforce_on_promotion": false, "required_checks": [],
        "created_at": "2026-01-15T12:00:00Z", "updated_at": "2026-01-15T12:00:00Z",
        "from_a_newer_server": {"nested": [1, 2]}
    })
}

fn age_gate_config() -> Value {
    json!({
        "repository_key": "r", "enabled": true, "min_age_days": 3, "mode": "block",
        "from_a_newer_server": true
    })
}

fn package() -> Value {
    json!({
        "id": UUID, "name": "p", "version": "1.0.0", "format": "generic",
        "repository_key": "r", "size_bytes": 3, "download_count": 0, "metadata": {},
        "created_at": "2026-01-15T12:00:00Z", "updated_at": "2026-01-15T12:00:00Z",
        "from_a_newer_server": {"nested": [1, 2]}
    })
}

#[tokio::test]
async fn admin_reads() {
    assert_prints_the_body(
        "/api/v1/admin/stats",
        "GET",
        json!({
            "active_peers": 0, "pending_sync_tasks": 0, "proxy_artifact_count": 0,
            "proxy_storage_bytes": 0, "total_artifacts": 1, "total_downloads": 2,
            "total_repositories": 3, "total_storage_bytes": 4, "total_users": 5,
            "from_a_newer_server": true
        }),
        &["admin", "stats"],
    )
    .await;
    assert_prints_the_body(
        "/api/v1/users",
        "GET",
        list_of(admin_user()),
        &["admin", "users", "list"],
    )
    .await;
    assert_prints_the_body(
        &format!("/api/v1/users/{UUID}"),
        "GET",
        admin_user(),
        &["admin", "users", "show", UUID],
    )
    .await;
}

#[tokio::test]
async fn admin_mutations() {
    assert_prints_the_body(
        &format!("/api/v1/users/{UUID}"),
        "PATCH",
        admin_user(),
        &["admin", "users", "update", UUID, "--email", "a@example.com"],
    )
    .await;
    assert_prints_the_body(
        &format!("/api/v1/admin/backups/{UUID}/restore"),
        "POST",
        json!({
            "artifacts_restored": 1, "errors": [], "integrity_anchor": "none",
            "tables_restored": ["t"], "from_a_newer_server": true
        }),
        &["admin", "backup", "restore", UUID],
    )
    .await;
}

/// These printed nothing on stdout in JSON mode, so their response was lost.
#[tokio::test]
async fn mutations_that_used_to_lose_the_body() {
    assert_prints_the_body(
        "/api/v1/plugins/install/git",
        "POST",
        plugin_install(),
        &["admin", "plugins", "install", "https://example.com/p.git"],
    )
    .await;
    assert_prints_the_body(
        &format!("/api/v1/users/{UUID}/password/reset"),
        "POST",
        json!({"temporary_password": "not-a-real-password", "from_a_newer_server": true}),
        &["admin", "users", "reset-password", UUID],
    )
    .await;

    let dir = TempDir::new().expect("temp dir");
    let zip = dir.path().join("p.zip");
    std::fs::write(&zip, b"PK").expect("write zip");
    assert_prints_the_body(
        "/api/v1/plugins/install/zip",
        "POST",
        plugin_install(),
        &[
            "admin",
            "plugins",
            "install-zip",
            zip.to_str().expect("utf-8 path"),
        ],
    )
    .await;
}

/// An update reads the settings first. What's printed is the update's response.
#[tokio::test]
async fn telemetry_update_prints_the_update_not_the_read_before_it() {
    let server = MockServer::start().await;
    let settings = |marker: &str| {
        json!({
            "enabled": true, "include_logs": false, "review_before_send": true,
            "scrub_level": "standard", "from_a_newer_server": marker
        })
    };
    Mock::given(method("GET"))
        .and(path("/api/v1/admin/telemetry/settings"))
        .respond_with(ResponseTemplate::new(200).set_body_json(settings("read")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/admin/telemetry/settings"))
        .respond_with(ResponseTemplate::new(200).set_body_json(settings("update")))
        .mount(&server)
        .await;
    let output = run_against(
        &server,
        &["admin", "telemetry", "update", "--format", "json"],
    );
    let shown: Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(shown, settings("update"));
}

#[tokio::test]
async fn quality_gate_commands() {
    assert_prints_the_body(
        "/api/v1/quality/gates",
        "GET",
        json!([gate()]),
        &["quality-gate", "list"],
    )
    .await;
    assert_prints_the_body(
        "/api/v1/quality/gates",
        "POST",
        gate(),
        &["quality-gate", "create", "g"],
    )
    .await;
    assert_prints_the_body(
        &format!("/api/v1/quality/gates/{UUID}"),
        "DELETE",
        json!({"deleted": true, "from_a_newer_server": 1}),
        &["quality-gate", "delete", UUID, "--yes"],
    )
    .await;
    assert_prints_the_body(
        "/api/v1/quality/gates",
        "GET",
        json!([]),
        &["quality-gate", "list"],
    )
    .await;
}

#[tokio::test]
async fn age_gate_commands() {
    assert_prints_the_body(
        "/api/v1/repositories/r/age-gate",
        "GET",
        age_gate_config(),
        &["age-gate", "get", "r"],
    )
    .await;
    assert_prints_the_body(
        "/api/v1/repositories/r/age-gate",
        "PUT",
        age_gate_config(),
        &["age-gate", "set", "r", "--min-age-days", "3"],
    )
    .await;
}

#[tokio::test]
async fn package_commands() {
    assert_prints_the_body(
        "/api/v1/packages",
        "GET",
        list_of(package()),
        &["packages", "list"],
    )
    .await;
    assert_prints_the_body(
        &format!("/api/v1/packages/{UUID}"),
        "GET",
        package(),
        &["packages", "show", UUID],
    )
    .await;
}

/// Moving these onto `emit_mutation_raw` must not change what people see.
#[tokio::test]
async fn human_and_quiet_output_of_moved_mutations_is_unchanged() {
    let route = format!("/api/v1/users/{UUID}/password/reset");
    let body = json!({"temporary_password": "not-a-real-password"});
    let reset = ["admin", "users", "reset-password", UUID];

    let output = run(
        &route,
        "POST",
        &body,
        &[&reset[..], &["--format", "table"]].concat(),
    )
    .await;
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        format!(
            "Password reset for user {UUID}.\nTemporary password: not-a-real-password\n\
             (User will be prompted to change on first login.)\n"
        )
    );

    let output = run(
        &route,
        "POST",
        &body,
        &[&reset[..], &["--format", "quiet"]].concat(),
    )
    .await;
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "not-a-real-password\n"
    );

    let install = [
        "admin",
        "plugins",
        "install",
        "https://example.com/p.git",
        "--format",
    ];
    let route = "/api/v1/plugins/install/git";
    let output = run(
        route,
        "POST",
        &plugin_install(),
        &[&install[..], &["table"]].concat(),
    )
    .await;
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "Plugin 'p' v1.0.0 installed (format: f).\nInstalled\n"
    );
    let output = run(
        route,
        "POST",
        &plugin_install(),
        &[&install[..], &["quiet"]].concat(),
    )
    .await;
    assert_eq!(String::from_utf8_lossy(&output.stdout), format!("{UUID}\n"));
}
