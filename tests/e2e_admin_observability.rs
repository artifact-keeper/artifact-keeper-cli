//! E2E tests for the admin observability commands.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use serde_json::Value;

fn json_of(output: std::process::Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("JSON output")
}

/// A generic repository holding one artifact, for a test that needs one.
fn repo_with_artifact(env: &common::TestEnv, name: &str) -> (String, String) {
    let key = format!("e2e-{name}-{}", std::process::id());
    env.ak_cmd()
        .args(["repo", "create", &key, "--pkg-format", "generic"])
        .assert()
        .success();
    let dir = tempfile::TempDir::new().unwrap();
    let file = dir.path().join("a.bin");
    std::fs::write(&file, name).unwrap();
    env.ak_cmd()
        .args(["artifact", "push", &key, file.to_str().unwrap()])
        .args(["--path", "a.bin"])
        .assert()
        .success();
    let info = json_of(
        env.ak_cmd()
            .args(["artifact", "info", &key, "a.bin"])
            .output()
            .unwrap(),
    );
    (key, info["id"].as_str().unwrap().to_string())
}

#[test]
#[ignore = "requires E2E backend"]
fn audit_list_finds_the_login() {
    let env = common::TestEnv::setup();
    let body = json_of(
        env.ak_cmd()
            .args(["admin", "audit", "list", "--action", "LOGIN"])
            .args(["--from", "2020-01-01T00:00:00Z", "--per-page", "5"])
            .output()
            .unwrap(),
    );
    assert_eq!(body["per_page"], 5);
    let items = body["items"].as_array().unwrap();
    assert!(!items.is_empty(), "{body}");
    assert!(items.iter().all(|i| i["action"] == "LOGIN"), "{body}");
}

#[test]
#[ignore = "requires E2E backend"]
fn a_pull_shows_in_downloads_and_filters_work() {
    let env = common::TestEnv::setup();
    let (key, id) = repo_with_artifact(&env, "downloads");
    let dir = tempfile::TempDir::new().unwrap();
    env.ak_cmd()
        .args(["artifact", "pull", &key, "a.bin", "-o"])
        .arg(dir.path().join("out"))
        .assert()
        .success();

    let body = json_of(
        env.ak_cmd()
            .args(["admin", "downloads", "list", "--repo", &key])
            .args(["--artifact", &format!("{key}/a.bin"), "--source", "hosted"])
            .output()
            .unwrap(),
    );
    assert_eq!(body["total"], 1, "{body}");
    let download = &body["downloads"][0];
    assert_eq!(download["artifact_id"], id.as_str());
    let user = download["user_id"].as_str().unwrap().to_string();
    let ip = download["ip_address"].as_str().unwrap().to_string();

    let by_ip = json_of(
        env.ak_cmd()
            .args(["admin", "downloads", "by-ip", &ip, "--repo", &key])
            .output()
            .unwrap(),
    );
    assert_eq!(by_ip["total"], 1, "{by_ip}");
    let by_user = json_of(
        env.ak_cmd()
            .args(["admin", "downloads", "by-user", &user, "--repo", &key])
            .output()
            .unwrap(),
    );
    assert_eq!(by_user["total"], 1, "{by_user}");
    let proxy = json_of(
        env.ak_cmd()
            .args([
                "admin",
                "downloads",
                "list",
                "--repo",
                &key,
                "--source",
                "proxy",
            ])
            .output()
            .unwrap(),
    );
    assert_eq!(proxy["total"], 0, "{proxy}");
}

#[test]
#[ignore = "requires E2E backend"]
fn blast_radius_of_an_artifact_and_a_cve() {
    let env = common::TestEnv::setup();
    let (key, id) = repo_with_artifact(&env, "blast");

    let body = json_of(
        env.ak_cmd()
            .args(["admin", "blast-radius", "artifact", &format!("{key}/a.bin")])
            .output()
            .unwrap(),
    );
    assert_eq!(body["target"]["kind"], "artifact");
    assert_eq!(body["target"]["value"], id.as_str());

    let body = json_of(
        env.ak_cmd()
            .args([
                "admin",
                "blast-radius",
                "artifact",
                &id,
                "--accessible-users",
            ])
            .args(["--repo", &key])
            .output()
            .unwrap(),
    );
    assert_eq!(body["repository"]["repository_key"], key.as_str());

    let body = json_of(
        env.ak_cmd()
            .args(["admin", "blast-radius", "cve", "CVE-2000-0001"])
            .output()
            .unwrap(),
    );
    assert_eq!(body["target"]["value"], "CVE-2000-0001");
}

#[test]
#[ignore = "requires E2E backend"]
fn a_quarantine_hold_shows_in_holds() {
    let env = common::TestEnv::setup();
    let (key, id) = repo_with_artifact(&env, "holds");
    env.ak_cmd()
        .args(["quarantine", "hold", &id, "--reason", "e2e"])
        .assert()
        .success();

    let body = json_of(
        env.ak_cmd()
            .args([
                "admin",
                "holds",
                "quarantine",
                "--repo",
                &key,
                "--kind",
                "active",
            ])
            .output()
            .unwrap(),
    );
    assert_eq!(body["pagination"]["total"], 1, "{body}");
    assert_eq!(body["items"][0]["artifact_id"], id.as_str());
    let summary = json_of(
        env.ak_cmd()
            .args(["admin", "holds", "summary"])
            .output()
            .unwrap(),
    );
    assert!(
        summary["quarantine_active"].as_i64().unwrap() >= 1,
        "{summary}"
    );

    env.ak_cmd()
        .args(["quarantine", "release", &id])
        .assert()
        .success();
}

#[test]
#[ignore = "requires E2E backend"]
fn npm_feed_status_reads() {
    let env = common::TestEnv::setup();
    let body = json_of(
        env.ak_cmd()
            .args(["admin", "npm-feed", "status"])
            .output()
            .unwrap(),
    );
    assert!(body["enabled"].is_boolean(), "{body}");
}

#[test]
#[ignore = "requires E2E backend"]
fn proxy_scan_verdict_for_an_unknown_digest_shows_the_server_message() {
    let env = common::TestEnv::setup();
    let digest = format!("sha256:{}", "b".repeat(64));
    for args in [
        vec!["admin", "proxy-scan-verdict", "show", &digest],
        vec!["admin", "proxy-scan-verdict", "delete", &digest, "--yes"],
    ] {
        let output = env.ak_cmd().args(args).output().unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("404"), "{stderr}");
    }
}

#[test]
#[ignore = "requires E2E backend"]
fn quality_checks_across_the_server() {
    let env = common::TestEnv::setup();
    let (key, id) = repo_with_artifact(&env, "checks");
    env.ak_cmd()
        .args(["quality-gate", "check-trigger", "--repo", &key])
        .assert()
        .success();
    let body = json_of(
        env.ak_cmd()
            .args(["quality-gate", "checks", "--all", "--repo", &key])
            .output()
            .unwrap(),
    );
    assert!(body["total"].is_i64(), "{body}");
    for item in body["items"].as_array().unwrap() {
        assert_eq!(item["artifact_id"], id.as_str());
    }
}
