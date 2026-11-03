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
    run_with_status(200, route, verb, body, args).await
}

async fn run_with_status(
    status: u16,
    route: &str,
    verb: &str,
    body: &Value,
    args: &[&str],
) -> Output {
    let server = MockServer::start().await;
    Mock::given(method(verb))
        .and(path(route))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
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

/// [`assert_prints_the_body`] for an operation whose success is a 201.
async fn assert_created_prints_the_body(route: &str, verb: &str, body: Value, args: &[&str]) {
    assert_status_prints_the_body(201, route, verb, body, args).await;
}

async fn assert_status_prints_the_body(
    status: u16,
    route: &str,
    verb: &str,
    body: Value,
    args: &[&str],
) {
    let mut with_format = args.to_vec();
    with_format.extend(["--format", "json"]);
    let output = run_with_status(status, route, verb, &body, &with_format).await;
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(output.status.code(), Some(0), "{args:?}: {stderr}");
    let shown: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("{args:?}: not JSON: {e}"));
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

/// A new subcommand with a flag can clash with `--version`, which `ak` adds to
/// every subcommand. Clap only reports that when the subcommand runs.
#[test]
fn every_subcommand_definition_is_valid() {
    for args in [
        vec!["artifact", "pull", "--help"],
        vec!["artifact", "info", "--help"],
        vec!["artifact", "search", "--help"],
        vec!["artifact", "push", "--help"],
        vec!["repo", "create", "--help"],
        vec!["repo", "update", "--help"],
    ] {
        Command::cargo_bin("ak")
            .expect("ak binary")
            .args(&args)
            .assert()
            .success();
    }
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
        &["admin", "backup", "restore", UUID, "--yes"],
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

#[test]
fn artifact_detail_commands() {
    let analysis = json!({
        "format": "pypi", "completeness": {"status": "complete"}, "vendored_components": [],
        "install_scripts": [], "from_a_newer_server": 1
    });
    let versions = json!({
        "repository_key": "r", "path": "a", "items": [{
            "revision": 1, "size_bytes": 1, "checksum_sha256": "x", "content_type": "t",
            "created_at": "2026-01-15T12:00:00Z"
        }], "from_a_newer_server": 1
    });
    let missing = json!({"checked": 1, "missing": [], "from_a_newer_server": 1});
    let session = json!({
        "session_id": UUID, "status": "pending", "total_size": 1, "bytes_received": 0,
        "chunks_completed": 0, "chunks_total": 1, "repository_key": "r", "artifact_path": "a",
        "created_at": "t", "expires_at": "t", "from_a_newer_server": 1
    });
    let cases: Vec<(String, &str, Value, Vec<&str>)> = vec![
        (
            format!("/api/v1/artifacts/{UUID}/package-analysis"),
            "GET",
            analysis,
            vec!["artifact", "package-analysis", UUID],
        ),
        (
            "/api/v1/repositories/r/versions/a".to_string(),
            "GET",
            versions,
            vec!["artifact", "versions", "r", "a"],
        ),
        (
            "/api/v1/repositories/r/artifacts-missing".to_string(),
            "POST",
            missing,
            vec!["artifact", "missing", "r", "--item", "a=1"],
        ),
        (
            format!("/api/v1/uploads/{UUID}"),
            "GET",
            session,
            vec!["artifact", "upload-session", "status", UUID],
        ),
    ];
    for (route, verb, body, args) in cases {
        tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(assert_prints_the_body(&route, verb, body, &args));
    }
}

// Contract, not E2E: the bodies below are written for the mock. Run for real, these
// commands were also compared with curl on a 1.11.11 backend, with Dependency-Track
// replaced by a stand-in upstream.

const OTHER: &str = "00000000-0000-0000-0000-000000000002";

fn dt_component() -> Value {
    json!({"uuid": UUID, "name": "c", "from_a_newer_server": 1})
}

fn dt_finding(severity: &str) -> Value {
    json!({
        "component": dt_component(),
        "vulnerability": {
            "uuid": UUID, "vulnId": "CVE-1", "source": "NVD", "severity": severity,
            "from_a_newer_server": 1
        },
        "from_a_newer_server": 1
    })
}

fn dt_metrics() -> Value {
    json!({
        "critical": 1, "high": 0, "medium": 0, "low": 0, "unassigned": 0,
        "findingsTotal": 1, "findingsAudited": 0, "findingsUnaudited": 1, "suppressions": 0,
        "inheritedRiskScore": 1.0, "policyViolationsFail": 0, "policyViolationsWarn": 0,
        "policyViolationsInfo": 0, "policyViolationsTotal": 0, "projects": 1,
        "from_a_newer_server": 1
    })
}

fn dt_project(uuid: &str) -> Value {
    json!({"uuid": uuid, "name": "p", "from_a_newer_server": 1})
}

#[tokio::test]
async fn dt_commands() {
    let base = "/api/v1/dependency-track";
    let project = format!("{base}/projects/{UUID}");
    assert_prints_the_body(
        &format!("{base}/status"),
        "GET",
        json!({"enabled": true, "healthy": true, "from_a_newer_server": 1}),
        &["dt", "status"],
    )
    .await;
    assert_prints_the_body(
        &format!("{base}/projects"),
        "GET",
        json!([dt_project(UUID)]),
        &["dt", "project", "list"],
    )
    .await;
    assert_prints_the_body(
        &project,
        "GET",
        json!([dt_finding("LOW")]),
        &["dt", "project", "get", UUID],
    )
    .await;
    assert_prints_the_body(
        &format!("{project}/findings"),
        "GET",
        json!([dt_finding("LOW")]),
        &["dt", "project", "findings", UUID],
    )
    .await;
    assert_prints_the_body(
        &format!("{project}/components"),
        "GET",
        json!([dt_component()]),
        &["dt", "project", "components", UUID],
    )
    .await;
    assert_prints_the_body(
        &format!("{project}/violations"),
        "GET",
        json!([{
            "uuid": UUID, "type": "LICENSE", "component": dt_component(),
            "policyCondition": {
                "uuid": UUID, "subject": "s", "operator": "o", "value": "v",
                "policy": {"uuid": UUID, "name": "n", "violationState": "FAIL"}
            },
            "from_a_newer_server": 1
        }]),
        &["dt", "project", "violations", UUID],
    )
    .await;
    assert_prints_the_body(
        &format!("{project}/metrics"),
        "GET",
        dt_metrics(),
        &["dt", "project", "metrics", UUID],
    )
    .await;
    assert_prints_the_body(
        &format!("{project}/metrics/history"),
        "GET",
        json!([dt_metrics()]),
        &["dt", "project", "metrics-history", UUID],
    )
    .await;
    assert_prints_the_body(
        &format!("{base}/metrics/portfolio"),
        "GET",
        dt_metrics(),
        &["dt", "metrics"],
    )
    .await;
    assert_prints_the_body(
        &format!("{base}/policies"),
        "GET",
        json!([{
            "uuid": UUID, "name": "n", "violationState": "FAIL", "policyConditions": [],
            "projects": [], "tags": [], "from_a_newer_server": 1
        }]),
        &["dt", "policies"],
    )
    .await;
    assert_prints_the_body(
        &format!("{base}/analysis"),
        "PUT",
        json!({"analysisState": "NOT_AFFECTED", "isSuppressed": false, "from_a_newer_server": 1}),
        &[
            "dt",
            "analyze",
            "--project",
            UUID,
            "--vulnerability",
            UUID,
            "--component",
            UUID,
            "--state",
            "NOT_AFFECTED",
        ],
    )
    .await;
}

#[tokio::test]
async fn dt_project_show_keeps_only_that_project_as_sent() {
    let list = json!([dt_project(OTHER), dt_project(UUID)]);
    let output = run(
        "/api/v1/dependency-track/projects",
        "GET",
        &list,
        &["dt", "project", "show", UUID, "--format", "json"],
    )
    .await;
    let shown: Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(shown, dt_project(UUID));
}

#[tokio::test]
async fn dt_findings_severity_filters_the_body_and_can_print_none() {
    let route = format!("/api/v1/dependency-track/projects/{UUID}/findings");
    let list = json!([dt_finding("LOW"), dt_finding("CRITICAL")]);
    let args = [
        "dt",
        "project",
        "findings",
        UUID,
        "--format",
        "json",
        "--severity",
    ];

    let with = |severity: &'static str| {
        let mut all = args.to_vec();
        all.push(severity);
        all
    };
    let output = run(&route, "GET", &list, &with("critical")).await;
    let shown: Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(shown, json!([dt_finding("CRITICAL")]));

    let output = run(&route, "GET", &list, &with("medium")).await;
    let shown: Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(shown, json!([]));
}

fn connection() -> Value {
    json!({
        "id": UUID, "name": "s", "url": "https://example.com", "auth_type": "api_token",
        "source_type": "artifactory", "created_at": "2026-01-15T12:00:00Z",
        "from_a_newer_server": 1
    })
}

fn migration_job() -> Value {
    json!({
        "id": UUID, "source_connection_id": UUID, "status": "paused", "job_type": "full",
        "config": {}, "total_items": 0, "completed_items": 0, "failed_items": 0,
        "skipped_items": 0, "total_bytes": 0, "transferred_bytes": 0,
        "progress_percent": 0.0, "created_at": "2026-01-15T12:00:00Z",
        "from_a_newer_server": 1
    })
}

#[tokio::test]
async fn import_commands() {
    let connections = "/api/v1/migrations/connections";
    let jobs = "/api/v1/migrations";
    assert_created_prints_the_body(
        connections,
        "POST",
        connection(),
        &[
            "import",
            "source",
            "add",
            "s",
            "https://example.com",
            "--auth-type",
            "api_token",
            "--token",
            "t",
        ],
    )
    .await;
    assert_prints_the_body(
        &format!("{connections}/{UUID}"),
        "GET",
        connection(),
        &["import", "source", "show", UUID],
    )
    .await;
    assert_prints_the_body(
        &format!("{connections}/{UUID}/test"),
        "POST",
        json!({"success": true, "message": "ok", "from_a_newer_server": 1}),
        &["import", "source", "test", UUID],
    )
    .await;
    assert_prints_the_body(
        &format!("{connections}/{UUID}/repositories"),
        "GET",
        json!([{
            "key": "r", "type": "local", "package_type": "npm", "url": "https://example.com/r",
            "from_a_newer_server": 1
        }]),
        &["import", "source", "repos", UUID],
    )
    .await;
    assert_created_prints_the_body(
        jobs,
        "POST",
        migration_job(),
        &["import", "job", "create", "--source", UUID],
    )
    .await;
    for (verb, command, tail) in [
        ("GET", "status", ""),
        ("POST", "start", "/start"),
        ("POST", "pause", "/pause"),
        ("POST", "resume", "/resume"),
        ("POST", "cancel", "/cancel"),
    ] {
        assert_prints_the_body(
            &format!("{jobs}/{UUID}{tail}"),
            verb,
            migration_job(),
            &["import", "job", command, UUID],
        )
        .await;
    }
    assert_status_prints_the_body(
        202,
        &format!("{jobs}/{UUID}/assess"),
        "POST",
        migration_job(),
        &["import", "assess", "run", UUID],
    )
    .await;
    assert_prints_the_body(
        &format!("{jobs}/{UUID}/assessment"),
        "GET",
        json!({
            "job_id": UUID, "status": "completed", "repositories": [], "users_count": 0,
            "groups_count": 0, "permissions_count": 0, "total_artifacts": 0,
            "total_size_bytes": 0, "estimated_duration_seconds": 0, "warnings": [],
            "blockers": [], "from_a_newer_server": 1
        }),
        &["import", "assess", "result", UUID],
    )
    .await;
    assert_prints_the_body(
        &format!("{jobs}/{UUID}/report"),
        "GET",
        json!({
            "id": UUID, "job_id": UUID, "generated_at": "2026-01-15T12:00:00Z",
            "summary": {}, "warnings": {}, "errors": {}, "recommendations": {},
            "from_a_newer_server": 1
        }),
        &["import", "job", "report", UUID],
    )
    .await;
}

#[tokio::test]
async fn analytics_commands() {
    let base = "/api/v1/admin/analytics";
    let snapshot = json!({
        "snapshot_date": "2026-01-15", "total_repositories": 0, "total_artifacts": 0,
        "total_storage_bytes": 0, "total_downloads": 0, "total_users": 0,
        "proxy_artifact_count": 0, "proxy_download_count": 0, "proxy_storage_bytes": 0,
        "from_a_newer_server": 1
    });
    assert_prints_the_body(
        &format!("{base}/downloads/trend"),
        "GET",
        json!([{"date": "2026-01-15", "download_count": 1, "from_a_newer_server": 1}]),
        &["analytics", "downloads"],
    )
    .await;
    assert_prints_the_body(
        &format!("{base}/storage/breakdown"),
        "GET",
        json!([{
            "repository_id": UUID, "repository_key": "r", "repository_name": "r",
            "format": "generic", "artifact_count": 1, "storage_bytes": 1, "download_count": 1,
            "proxy_artifact_count": 0, "proxy_storage_bytes": 0, "proxy_download_count": 0,
            "from_a_newer_server": 1
        }]),
        &["analytics", "storage"],
    )
    .await;
    assert_prints_the_body(
        &format!("{base}/storage/growth"),
        "GET",
        json!({
            "period_start": "2026-01-01", "period_end": "2026-01-15", "storage_bytes_start": 0,
            "storage_bytes_end": 0, "storage_growth_bytes": 0, "storage_growth_percent": 0.0,
            "artifacts_start": 0, "artifacts_end": 0, "artifacts_added": 0,
            "downloads_in_period": 0, "from_a_newer_server": 1
        }),
        &["analytics", "growth"],
    )
    .await;
    assert_prints_the_body(
        &format!("{base}/storage/trend"),
        "GET",
        json!([snapshot.clone()]),
        &["analytics", "storage-trend"],
    )
    .await;
    assert_prints_the_body(
        &format!("{base}/artifacts/stale"),
        "GET",
        json!([{
            "artifact_id": UUID, "repository_key": "r", "name": "a", "path": "a",
            "size_bytes": 1, "days_since_download": 90, "download_count": 0,
            "created_at": "2026-01-15T12:00:00Z", "from_a_newer_server": 1
        }]),
        &["analytics", "top-stale"],
    )
    .await;
    assert_prints_the_body(
        &format!("{base}/snapshot"),
        "POST",
        snapshot,
        &["analytics", "snapshot"],
    )
    .await;
    assert_prints_the_body(
        &format!("{base}/repositories/{UUID}/trend"),
        "GET",
        json!([{
            "repository_id": UUID, "snapshot_date": "2026-01-15", "artifact_count": 1,
            "storage_bytes": 1, "download_count": 1, "proxy_artifact_count": 0,
            "proxy_storage_bytes": 0, "proxy_download_count": 0, "from_a_newer_server": 1
        }]),
        &["analytics", "repo-trend", UUID],
    )
    .await;
}

fn health_entry() -> Value {
    json!({
        "service_name": "db", "status": "ok", "checked_at": "2026-01-15T12:00:00Z",
        "from_a_newer_server": 1
    })
}

#[tokio::test]
async fn monitoring_commands() {
    assert_prints_the_body(
        "/health",
        "GET",
        json!({
            "status": "healthy", "version": "1", "demo_mode": false,
            "checks": {"database": {"status": "ok"}, "storage": {"status": "ok"}},
            "from_a_newer_server": 1
        }),
        &["monitoring", "health"],
    )
    .await;
    assert_prints_the_body(
        "/livez",
        "GET",
        json!({"status": "ok", "from_a_newer_server": 1}),
        &["monitoring", "live"],
    )
    .await;
    assert_prints_the_body(
        "/readyz",
        "GET",
        json!({
            "status": "ready",
            "checks": {
                "database": {"status": "ok"}, "migrations": {"status": "ok"},
                "setup_complete": {"status": "ok"}
            },
            "dependencies": {
                "opensearch": {"status": "ok", "required": false},
                "storage": {"status": "ok", "required": false},
                "scanner": {"status": "ok", "required": false},
                "ldap": {"status": "ok", "required": false}
            },
            "from_a_newer_server": 1
        }),
        &["monitoring", "ready"],
    )
    .await;
    assert_prints_the_body(
        "/api/v1/admin/monitoring/alerts",
        "GET",
        json!([{
            "service_name": "db", "current_status": "ok", "consecutive_failures": 0,
            "updated_at": "2026-01-15T12:00:00Z", "from_a_newer_server": 1
        }]),
        &["monitoring", "alerts"],
    )
    .await;
    assert_prints_the_body(
        "/api/v1/admin/monitoring/check",
        "POST",
        json!([health_entry()]),
        &["monitoring", "check"],
    )
    .await;
    assert_prints_the_body(
        "/api/v1/admin/monitoring/health-log",
        "GET",
        json!([health_entry()]),
        &["monitoring", "health-log"],
    )
    .await;
}

fn service_account() -> Value {
    json!({
        "id": UUID, "username": "svc-a", "is_active": true,
        "created_at": "2026-01-15T12:00:00Z", "updated_at": "2026-01-15T12:00:00Z",
        "from_a_newer_server": 1
    })
}

fn service_account_token() -> Value {
    json!({
        "id": UUID, "name": "t", "token_prefix": "ak_", "scopes": [], "is_expired": false,
        "created_at": "2026-01-15T12:00:00Z", "repository_ids": [], "from_a_newer_server": 1
    })
}

#[tokio::test]
async fn service_account_commands() {
    let base = "/api/v1/service-accounts";
    let summary = json!({
        "id": UUID, "username": "svc-a", "is_active": true, "token_count": 0,
        "created_at": "2026-01-15T12:00:00Z", "updated_at": "2026-01-15T12:00:00Z",
        "from_a_newer_server": 1
    });
    assert_prints_the_body(
        base,
        "GET",
        json!({"items": [summary], "from_a_newer_server": 1}),
        &["service-account", "list"],
    )
    .await;
    assert_prints_the_body(
        base,
        "POST",
        service_account(),
        &["service-account", "create", "a"],
    )
    .await;
    assert_prints_the_body(
        &format!("{base}/{UUID}"),
        "GET",
        service_account(),
        &["service-account", "show", UUID],
    )
    .await;
    assert_prints_the_body(
        &format!("{base}/{UUID}"),
        "PATCH",
        service_account(),
        &["service-account", "update", UUID, "--inactive"],
    )
    .await;
    assert_prints_the_body(
        &format!("{base}/{UUID}/tokens"),
        "GET",
        json!({"items": [service_account_token()], "from_a_newer_server": 1}),
        &["service-account", "token", "list", UUID],
    )
    .await;
    assert_prints_the_body(
        &format!("{base}/repo-selector/preview"),
        "POST",
        json!({
            "matched_repositories": [{"id": UUID, "key": "r", "format": "generic"}],
            "total": 1, "from_a_newer_server": 1
        }),
        &["service-account", "preview-selector", "--selector", "{}"],
    )
    .await;
}

/// A new token is the one secret these commands print, because the server shows it
/// once and showing it is the point of the command.
#[tokio::test]
async fn creating_a_token_shows_it_once() {
    assert_prints_the_body(
        &format!("/api/v1/service-accounts/{UUID}/tokens"),
        "POST",
        json!({
            "id": UUID, "name": "t", "token": "the-new-token", "policy_applied": false,
            "from_a_newer_server": 1
        }),
        &[
            "service-account",
            "token",
            "create",
            UUID,
            "t",
            "--scope",
            "read",
        ],
    )
    .await;
    assert_prints_the_body(
        "/api/v1/repositories/r/tokens",
        "POST",
        json!({
            "id": UUID, "name": "t", "token": "the-new-token", "repository_key": "r",
            "policy_applied": false, "from_a_newer_server": 1
        }),
        &["repo-token", "create", "r", "t"],
    )
    .await;
}

#[tokio::test]
async fn repo_token_commands() {
    let token = json!({
        "id": UUID, "name": "t", "token_prefix": "ak_", "scopes": [], "is_expired": false,
        "is_revoked": false, "created_at": "2026-01-15T12:00:00Z", "from_a_newer_server": 1
    });
    assert_prints_the_body(
        "/api/v1/repositories/r/tokens",
        "GET",
        json!({"items": [token.clone()], "from_a_newer_server": 1}),
        &["repo-token", "list", "r"],
    )
    .await;
    assert_prints_the_body(
        &format!("/api/v1/repositories/r/tokens/{UUID}"),
        "GET",
        token,
        &["repo-token", "show", "r", UUID],
    )
    .await;
}

fn label(owner: &str) -> Value {
    json!({
        "id": UUID, owner: UUID, "key": "k", "value": "v",
        "created_at": "2026-01-15T12:00:00Z", "from_a_newer_server": 1
    })
}

#[tokio::test]
async fn label_commands() {
    let repo = "/api/v1/repositories/r/labels";
    let artifact = format!("/api/v1/artifacts/{UUID}/labels");
    let repo_list =
        json!({"items": [label("repository_id")], "total": 1, "from_a_newer_server": 1});
    let artifact_list =
        json!({"items": [label("artifact_id")], "total": 1, "from_a_newer_server": 1});

    assert_prints_the_body(
        repo,
        "GET",
        repo_list.clone(),
        &["label", "repo", "list", "r"],
    )
    .await;
    assert_prints_the_body(
        &format!("{repo}/k"),
        "POST",
        label("repository_id"),
        &["label", "repo", "add", "r", "k=v"],
    )
    .await;
    assert_prints_the_body(
        repo,
        "PUT",
        repo_list,
        &["label", "repo", "set", "r", "k=v"],
    )
    .await;
    assert_prints_the_body(
        &artifact,
        "GET",
        artifact_list.clone(),
        &["label", "artifact", "list", UUID],
    )
    .await;
    assert_prints_the_body(
        &format!("{artifact}/k"),
        "POST",
        label("artifact_id"),
        &["label", "artifact", "add", UUID, "k=v"],
    )
    .await;
    assert_prints_the_body(
        &artifact,
        "PUT",
        artifact_list,
        &["label", "artifact", "set", UUID, "k=v"],
    )
    .await;
}

#[tokio::test]
async fn email_subscription_commands() {
    let route = "/api/v1/repositories/r/email-subscriptions";
    let sub = json!({
        "id": UUID, "repository_id": UUID, "event_types": ["e"], "recipients": ["a@example.com"],
        "enabled": true, "created_at": "2026-01-15T12:00:00Z",
        "updated_at": "2026-01-15T12:00:00Z", "from_a_newer_server": 1
    });
    assert_prints_the_body(
        route,
        "GET",
        json!({"subscriptions": [sub.clone()], "from_a_newer_server": 1}),
        &["email-subscriptions", "list", "r"],
    )
    .await;
    assert_created_prints_the_body(
        route,
        "POST",
        sub,
        &[
            "email-subscriptions",
            "subscribe",
            "r",
            "--recipients",
            "a@example.com",
            "--events",
            "e",
        ],
    )
    .await;
}

#[tokio::test]
async fn system_commands() {
    assert_prints_the_body(
        "/api/v1/system/config",
        "GET",
        json!({
            "max_upload_size_bytes": 1, "demo_mode": false, "guest_access_enabled": true,
            "auth": {
                "oidc_enabled": false, "ldap_enabled": false, "sso_enabled": false,
                "local_login_enabled": true, "silent_sso_enabled": true
            },
            "from_a_newer_server": 1
        }),
        &["system", "config"],
    )
    .await;
    assert_prints_the_body(
        "/health",
        "GET",
        json!({
            "status": "healthy", "version": "1", "demo_mode": false,
            "checks": {"database": {"status": "ok"}, "storage": {"status": "ok"}},
            "from_a_newer_server": 1
        }),
        &["system", "health"],
    )
    .await;
}

/// `sso list` is three requests, so it prints each body under its type, and `null`
/// for a type the server wouldn't list.
#[tokio::test]
async fn sso_list_prints_each_body_under_its_type() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/admin/sso/oidc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/admin/sso/saml"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"message": "no"})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/admin/sso/ldap"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([ldap_config()])))
        .mount(&server)
        .await;

    let output = run_against(&server, &["sso", "list", "--format", "json"]);
    let shown: Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(
        shown,
        json!({"ldap": [ldap_config()], "oidc": [], "saml": null})
    );
}

fn ldap_config() -> Value {
    json!({
        "id": UUID, "name": "l", "server_url": "ldap://x", "bind_dn": null,
        "has_bind_password": true, "user_base_dn": "dc=x", "user_filter": "(uid={0})",
        "username_attribute": "uid", "email_attribute": "mail",
        "display_name_attribute": "cn", "groups_attribute": "memberOf", "group_base_dn": null,
        "group_filter": null, "admin_group_dn": null, "use_starttls": false,
        "is_enabled": true, "priority": 0, "insecure_skip_verify": false,
        "has_ca_certificate": false, "created_at": "2026-01-15T12:00:00Z",
        "updated_at": "2026-01-15T12:00:00Z", "from_a_newer_server": 1
    })
}

#[tokio::test]
async fn an_empty_list_prints_its_body_on_every_moved_command() {
    for (route, verb, body, args) in [
        (
            "/api/v1/admin/analytics/downloads/trend",
            "GET",
            json!([]),
            vec!["analytics", "downloads"],
        ),
        (
            "/api/v1/admin/monitoring/alerts",
            "GET",
            json!([]),
            vec!["monitoring", "alerts"],
        ),
        (
            "/api/v1/dependency-track/projects",
            "GET",
            json!([]),
            vec!["dt", "project", "list"],
        ),
        (
            "/api/v1/repositories/r/tokens",
            "GET",
            json!({"items": []}),
            vec!["repo-token", "list", "r"],
        ),
        (
            "/api/v1/service-accounts",
            "GET",
            json!({"items": []}),
            vec!["service-account", "list"],
        ),
        (
            "/api/v1/repositories/r/labels",
            "GET",
            json!({"items": [], "total": 0}),
            vec!["label", "repo", "list", "r"],
        ),
    ] {
        assert_prints_the_body(route, verb, body, &args).await;
    }
}
