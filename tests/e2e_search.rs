//! E2E tests for `ak search`.

mod common;

use serde_json::Value;

fn json_of(cmd: &mut assert_cmd::Command) -> Value {
    let output = cmd.output().expect("run ak");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("JSON")
}

/// A repository with one artifact in it, and the artifact's SHA-256.
fn pushed(env: &common::TestEnv, repo: &str, name: &str, content: &str) -> String {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), content).unwrap();
    env.ak_cmd()
        .args(["repo", "create", repo, "--pkg-format", "generic"])
        .assert()
        .success();
    env.ak_cmd()
        .args(["artifact", "push", repo])
        .arg(file.path())
        .args(["--path", name])
        .assert()
        .success();
    let info = json_of(env.ak_cmd().args(["artifact", "info", repo, name]));
    info["checksum_sha256"].as_str().unwrap().to_string()
}

#[test]
#[ignore = "requires E2E backend"]
fn every_search_finds_a_pushed_artifact() {
    let env = common::TestEnv::setup();
    let repo = format!("e2e-search-{}", std::process::id());
    let name = format!("searched-{}.txt", std::process::id());
    let sha = pushed(&env, &repo, &name, &format!("content of {repo}"));

    let quick = json_of(
        env.ak_cmd()
            .args(["search", "quick", &name, "--limit", "5"]),
    );
    let found = quick["results"].as_array().unwrap();
    assert!(found.iter().any(|r| r["name"] == name.as_str()), "{quick}");

    let by_sum = json_of(env.ak_cmd().args(["search", "checksum", &sha]));
    let found = by_sum["artifacts"].as_array().unwrap();
    assert_eq!(found.len(), 1, "{by_sum}");
    assert_eq!(found[0]["repository_key"], repo.as_str());
    assert_eq!(found[0]["checksum_sha256"], sha.as_str());

    let suggest = json_of(env.ak_cmd().args(["search", "suggest", &name[..12]]));
    let found = suggest["suggestions"].as_array().unwrap();
    assert!(found.iter().any(|s| s == name.as_str()), "{suggest}");

    let recent = json_of(env.ak_cmd().args(["search", "recent", "--limit", "5"]));
    let found = recent.as_array().unwrap();
    assert!(found.len() <= 5, "the limit wasn't sent: {recent}");
    assert!(found.iter().any(|r| r["name"] == name.as_str()), "{recent}");

    let trending = json_of(
        env.ak_cmd()
            .args(["search", "trending", "--days", "7", "--limit", "1"]),
    );
    assert!(trending.as_array().unwrap().len() <= 1, "{trending}");

    let quiet = env
        .ak_cmd_table()
        .args(["--format", "quiet", "search", "checksum", &sha])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&quiet.stdout).trim(),
        found_id(&by_sum)
    );

    let _ = env.api_delete(&format!("/api/v1/repositories/{repo}"));
}

fn found_id(by_sum: &Value) -> &str {
    by_sum["artifacts"][0]["id"].as_str().unwrap()
}

#[test]
#[ignore = "requires E2E backend"]
fn a_bad_algorithm_shows_the_servers_message() {
    let env = common::TestEnv::setup();
    let output = env
        .ak_cmd()
        .args(["search", "checksum", "abc", "--algorithm", "crc32"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Unsupported"));
}
