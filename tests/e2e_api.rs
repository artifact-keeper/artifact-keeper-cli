//! E2E tests for `ak api`: the same requests curl would make, against a real
//! backend.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use serde_json::Value;

fn stdout_of(cmd: &mut assert_cmd::Command) -> Vec<u8> {
    cmd.assert().success().get_output().stdout.clone()
}

fn api(env: &common::TestEnv, args: &[&str]) -> Vec<u8> {
    stdout_of(env.ak_cmd().arg("api").args(args))
}

fn make_repo(env: &common::TestEnv, key: &str, format: &str) {
    let body =
        format!(r#"{{"key":"{key}","name":"{key}","format":"{format}","repo_type":"local"}}"#);
    api(env, &["POST", "/api/v1/repositories", "--body", &body]);
}

fn delete_repo(env: &common::TestEnv, key: &str) {
    let _ = env.api_delete(&format!("/api/v1/repositories/{key}"));
}

#[test]
#[ignore = "requires the E2E backend"]
fn get_auth_me_matches_whoami() {
    let env = common::TestEnv::setup();
    let raw: Value = serde_json::from_slice(&api(&env, &["GET", "/api/v1/auth/me"])).unwrap();
    let whoami: Value =
        serde_json::from_slice(&stdout_of(env.ak_cmd().args(["auth", "whoami"]))).unwrap();
    assert_eq!(whoami, raw);
    assert_eq!(raw["username"], "admin");
}

#[test]
#[ignore = "requires the E2E backend"]
fn head_and_options_work() {
    let env = common::TestEnv::setup();
    let head = api(&env, &["HEAD", "/health", "--include"]);
    let head = String::from_utf8_lossy(&head);
    assert!(head.contains("200 OK"), "{head}");
    assert!(head.to_lowercase().contains("content-type:"), "{head}");

    let options = env
        .ak_cmd()
        .args([
            "api",
            "OPTIONS",
            "/api/v1/repositories",
            "--include",
            "--no-fail",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert!(String::from_utf8_lossy(&options).starts_with("HTTP/"));
}

#[test]
#[ignore = "requires the E2E backend"]
fn a_package_manager_route_works() {
    let env = common::TestEnv::setup();
    make_repo(&env, "api-e2e-helm", "helm");
    let index = api(&env, &["GET", "/helm/api-e2e-helm/index.yaml"]);
    delete_repo(&env, "api-e2e-helm");
    assert!(String::from_utf8_lossy(&index).contains("apiVersion"));
}

#[test]
#[ignore = "requires the E2E backend"]
fn anon_is_refused_by_a_private_route() {
    let env = common::TestEnv::setup();
    let output = env
        .ak_cmd()
        .args(["api", "GET", "/api/v1/auth/me", "--anon", "--fail"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(22));
    let output = env
        .ak_cmd()
        .args(["api", "GET", "/api/v1/auth/me", "--anon"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("401"));
}

#[test]
#[ignore = "requires the E2E backend"]
fn raw_upload_then_full_and_range_download() {
    let env = common::TestEnv::setup();
    let key = "api-e2e-raw";
    make_repo(&env, key, "generic");

    let dir = tempfile::TempDir::new().unwrap();
    let source = dir.path().join("source.bin");
    let content: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&source, &content).unwrap();

    let at_source = format!("@{}", source.display());
    let upload = format!("/api/v1/repositories/{key}/artifacts/dir/source.bin");
    api(&env, &["PUT", &upload, "--raw-body", &at_source]);

    let download = format!("/api/v1/repositories/{key}/download/dir/source.bin");
    let whole = dir.path().join("whole.bin");
    api(&env, &["GET", &download, "-o", whole.to_str().unwrap()]);
    assert_eq!(std::fs::read(&whole).unwrap(), content);

    let part = api(&env, &["GET", &download, "-H", "Range: bytes=100-199"]);
    delete_repo(&env, key);
    assert_eq!(part, content[100..200]);
}

#[test]
#[ignore = "requires the E2E backend"]
fn raw_upload_from_stdin() {
    let env = common::TestEnv::setup();
    let key = "api-e2e-stdin";
    make_repo(&env, key, "generic");
    let upload = format!("/api/v1/repositories/{key}/artifacts/piped.txt");
    env.ak_cmd()
        .args(["api", "PUT", &upload, "--raw-body", "@-"])
        .write_stdin("from stdin")
        .assert()
        .success();
    let download = format!("/api/v1/repositories/{key}/download/piped.txt");
    let got = api(&env, &["GET", &download]);
    delete_repo(&env, key);
    assert_eq!(got, b"from stdin");
}

#[test]
#[ignore = "requires the E2E backend"]
fn plugins_multipart_installs_a_plugin() {
    // POST /api/v1/plugins has no first-class command, and curl can do this.
    let env = common::TestEnv::setup();
    let name = format!("api-e2e-plugin-{}", std::process::id());
    let dir = tempfile::TempDir::new().unwrap();
    let manifest = dir.path().join("manifest.json");
    std::fs::write(
        &manifest,
        format!(r#"{{"name":"{name}","version":"1.0.0","display_name":"E2E","plugin_type":"format_handler"}}"#),
    )
    .unwrap();

    let form = format!("manifest=@{};type=application/json", manifest.display());
    let installed: Value =
        serde_json::from_slice(&api(&env, &["POST", "/api/v1/plugins", "--form", &form])).unwrap();
    assert_eq!(installed["name"], name.as_str());
    let id = installed["id"].as_str().expect("plugin id");

    api(&env, &["DELETE", &format!("/api/v1/plugins/{id}")]);
}

#[test]
#[ignore = "requires the E2E backend"]
fn a_bad_multipart_shows_the_servers_message() {
    let env = common::TestEnv::setup();
    let output = env
        .ak_cmd()
        .args([
            "api",
            "POST",
            "/api/v1/plugins",
            "--form",
            "manifest=not-json",
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("400"), "{stderr}");
    assert!(stderr.contains("Invalid plugin manifest"), "{stderr}");
}
