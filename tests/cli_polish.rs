//! Help, completions and man pages, `ak doctor`, the public view and holding an
//! artifact twice. Against a mock server where one is needed, so a contract, not E2E:
//! `e2e_doctor` and `e2e_quarantine` have the same on a real server.

use std::process::Output;

use assert_cmd::Command;
use serde_json::{Value, json};
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn ak(dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("ak").expect("ak binary");
    cmd.env("AK_CONFIG_DIR", dir.path())
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path())
        .env("AK_CREDENTIAL_STORE", "file")
        .env("NO_COLOR", "1")
        .env("COLUMNS", "200")
        .env_remove("AK_TOKEN")
        .env_remove("AK_INSTANCE")
        .env_remove("AK_FORMAT");
    cmd
}

fn config(dir: &TempDir, url: &str) {
    std::fs::write(
        dir.path().join("config.toml"),
        format!("default_instance = \"t\"\n[instances.t]\nurl = \"{url}\"\n"),
    )
    .unwrap();
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr)
        .replace('│', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn help(args: &[&str]) -> String {
    let dir = TempDir::new().unwrap();
    stdout(&ak(&dir).args(args).arg("--help").output().unwrap())
}

#[test]
fn pkg_format_has_a_value_name_and_its_values() {
    let text = help(&["repo", "create"]);
    assert!(text.contains("--pkg-format <FORMAT>"), "{text}");
    assert!(!text.contains("pkg_format_create"), "{text}");
    assert!(
        text.contains("generic") && text.contains("rubygems"),
        "{text}"
    );
}

#[test]
fn root_help_has_no_issue_numbers_and_starts_with_the_core_commands() {
    let text = help(&[]);
    assert!(!text.contains("#1770"), "{text}");
    let commands: Vec<&str> = text
        .lines()
        .skip_while(|line| !line.starts_with("Commands:"))
        .skip(1)
        .take(4)
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    assert_eq!(commands, ["instance", "auth", "repo", "artifact"], "{text}");
}

#[test]
fn every_help_has_global_options_under_their_own_heading() {
    for args in [&[][..], &["repo"], &["repo", "list"], &["pkg", "npm"]] {
        let text = help(args);
        let (before, after) = text.split_once("Global options:").unwrap_or_else(|| {
            panic!("{args:?}: no heading in {text}");
        });
        assert!(after.contains("--instance"), "{args:?}: {text}");
        assert!(after.contains("--format"), "{args:?}: {text}");
        assert!(!before.contains("--instance <"), "{args:?}: {text}");
    }
}

#[test]
fn root_help_says_what_exits_and_json_mean() {
    let text = help(&[]);
    assert!(text.contains("Exit codes:"), "{text}");
    assert!(text.contains("the server's response as sent"), "{text}");
    assert!(text.contains("stable IDs"), "{text}");
}

#[test]
fn hidden_commands_arent_in_completions_or_man_pages() {
    let dir = TempDir::new().unwrap();
    for shell in ["bash", "zsh", "fish"] {
        let script = stdout(&ak(&dir).args(["completion", shell]).output().unwrap());
        assert!(!script.is_empty(), "{shell}");
        assert!(script.contains("artifact"), "{shell}");
        for hidden in ["__registry", "revoke-token", "swagger-ui"] {
            assert!(!script.contains(hidden), "{shell} has {hidden}");
        }
    }

    let man = dir.path().join("man");
    let output = ak(&dir).args(["man-pages"]).arg(&man).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(man.join("ak.1").exists());
    assert!(man.join("ak-catalog.1").exists());
    assert!(!man.join("ak-__registry.1").exists());
    assert!(!man.join("ak-auth-revoke-token.1").exists());
    let root = std::fs::read_to_string(man.join("ak.1")).unwrap();
    assert!(!root.contains("__registry"), "{root}");
}

async fn health_server(version: &str) -> MockServer {
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

#[test]
fn doctor_exits_1_when_a_check_fails() {
    let dir = TempDir::new().unwrap();
    config(&dir, "http://127.0.0.1:1");
    let output = ak(&dir).arg("doctor").output().unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
}

#[test]
fn doctor_exits_1_with_no_instances() {
    let dir = TempDir::new().unwrap();
    let output = ak(&dir).arg("doctor").output().unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(stderr(&output).contains("No instances configured"));
}

#[test]
fn doctor_honours_format_json_on_stdout() {
    let dir = TempDir::new().unwrap();
    config(&dir, "http://127.0.0.1:1");
    let output = ak(&dir)
        .args(["--format", "json", "doctor"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("JSON on stdout");
    assert_eq!(report["ok"], false);
    assert!(report["failures"].as_u64().unwrap() >= 1);
    let checks = report["checks"].as_array().unwrap();
    assert!(
        checks.iter().any(|check| check["status"] == "fail"),
        "{report}"
    );
    assert!(
        checks.iter().any(|check| check["section"] == "Instances"),
        "{report}"
    );
    for target in [
        "npm", "pip", "cargo", "maven", "gradle", "helm", "nuget", "go", "yum", "apt", "docker",
    ] {
        assert!(
            checks.iter().any(|check| check["message"]
                .as_str()
                .unwrap_or_default()
                .to_lowercase()
                .starts_with(target)),
            "doctor says nothing about {target}: {report}"
        );
    }
}

#[tokio::test]
async fn doctor_checks_only_the_instance_it_was_given() {
    let dir = TempDir::new().unwrap();
    config(&dir, "http://127.0.0.1:1");
    let server = health_server("1.11.11").await;
    let output = ak(&dir)
        .env("AK_TOKEN", "x")
        .args(["--format", "json", "--instance", &server.uri(), "doctor"])
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&output.stdout).expect("JSON on stdout");
    assert!(
        !report.to_string().contains("127.0.0.1:1 "),
        "it checked the other instance: {report}"
    );
    assert!(report.to_string().contains(&server.uri()), "{report}");
}

#[tokio::test]
async fn with_no_login_a_list_says_its_the_public_view_on_stderr() {
    let server = MockServer::start().await;
    let body = json!({"items": [], "pagination": {"page": 1, "per_page": 50, "total": 0, "total_pages": 0}});
    Mock::given(method("GET"))
        .and(path("/api/v1/repositories"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body))
        .mount(&server)
        .await;
    let dir = TempDir::new().unwrap();
    config(&dir, &server.uri());

    let output = ak(&dir)
        .args(["--format", "json", "repo", "list"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(stderr(&output).contains("public view"), "{output:?}");
    assert!(stderr(&output).contains("ak auth login"), "{output:?}");
    let printed: Value = serde_json::from_slice(&output.stdout).expect("only JSON on stdout");
    assert_eq!(printed, body);

    let output = ak(&dir)
        .env("AK_TOKEN", "x")
        .args(["--format", "json", "repo", "list"])
        .output()
        .unwrap();
    assert!(!stderr(&output).contains("public view"), "{output:?}");
}

#[tokio::test]
async fn a_servers_health_doesnt_mention_the_public_view() {
    let server = health_server("1.11.11").await;
    let dir = TempDir::new().unwrap();
    config(&dir, &server.uri());
    let output = ak(&dir).args(["monitoring", "health"]).output().unwrap();
    assert!(!stderr(&output).contains("public view"), "{output:?}");
}

const ARTIFACT: &str = "00000000-0000-4000-8000-000000000009";

async fn held_server(status: Value) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/quarantine/{ARTIFACT}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(status))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "artifact_id": ARTIFACT,
            "new_status": "quarantined",
            "message": "Artifact quarantined"
        })))
        .mount(&server)
        .await;
    server
}

fn holding(server: &MockServer, dir: &TempDir, more: &[&str]) -> Output {
    config(dir, &server.uri());
    ak(dir)
        .env("AK_TOKEN", "x")
        .args(["--format", "json", "quarantine", "hold", ARTIFACT, "--yes"])
        .args(more)
        .output()
        .unwrap()
}

async fn holds_sent(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|request| request.method.as_str() == "POST")
        .count()
}

/// The server replaces the stored reason with its default, which loses the only record
/// of why it was held.
#[tokio::test]
async fn holding_a_held_artifact_with_no_reason_is_refused() {
    let server = held_server(json!({
        "artifact_id": ARTIFACT,
        "quarantine_status": "quarantined",
        "quarantine_reason": "sentinel first reason",
        "is_blocked": true
    }))
    .await;
    let dir = TempDir::new().unwrap();
    let output = holding(&server, &dir, &[]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(
        stderr(&output).contains("sentinel first reason"),
        "{output:?}"
    );
    assert!(stderr(&output).contains("--reason"), "{output:?}");
    assert_eq!(holds_sent(&server).await, 0, "it sent the hold");
}

#[tokio::test]
async fn holding_a_held_artifact_with_a_reason_warns_and_goes_ahead() {
    let server = held_server(json!({
        "artifact_id": ARTIFACT,
        "quarantine_status": "quarantined",
        "quarantine_reason": "sentinel first reason",
        "is_blocked": true
    }))
    .await;
    let dir = TempDir::new().unwrap();
    let output = holding(&server, &dir, &["--reason", "second"]);
    assert!(output.status.success(), "{output:?}");
    assert!(
        stderr(&output).contains("sentinel first reason"),
        "{output:?}"
    );
    assert_eq!(holds_sent(&server).await, 1);
}

#[tokio::test]
async fn holding_an_artifact_that_isnt_held_says_nothing_extra() {
    let server = held_server(json!({
        "artifact_id": ARTIFACT,
        "quarantine_status": "not_quarantined",
        "quarantine_reason": null,
        "is_blocked": false
    }))
    .await;
    let dir = TempDir::new().unwrap();
    let output = holding(&server, &dir, &[]);
    assert!(output.status.success(), "{output:?}");
    assert!(!stderr(&output).contains("already held"), "{output:?}");
    assert_eq!(holds_sent(&server).await, 1);
}

/// `.npmrc` has no extension, so its backup name is the case worth pinning.
#[cfg(unix)]
#[tokio::test]
async fn a_setup_backup_is_owner_only_whatever_the_original_was() {
    use std::os::unix::fs::PermissionsExt;

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/repositories"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [], "pagination": {"page": 1, "per_page": 50, "total": 0, "total_pages": 0}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/repositories/r"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"key": "r"})))
        .mount(&server)
        .await;
    let dir = TempDir::new().unwrap();
    config(&dir, &server.uri());
    let npmrc = dir.path().join(".npmrc");
    std::fs::write(&npmrc, "registry=https://elsewhere.example/\n").unwrap();
    std::fs::set_permissions(&npmrc, std::fs::Permissions::from_mode(0o644)).unwrap();

    let output = ak(&dir)
        .env("AK_TOKEN", "api-token-not-a-jwt")
        .args(["--no-input", "setup", "npm", "--repo", "r"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let backup = dir.path().join(".npmrc.bak");
    let mode = std::fs::metadata(&backup)
        .unwrap_or_else(|e| panic!("no .npmrc.bak: {e}: {output:?}"))
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "{mode:o}");
}
