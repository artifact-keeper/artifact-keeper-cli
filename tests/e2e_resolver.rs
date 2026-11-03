//! E2E tests for passing a repository key wherever the API wants a repository
//! UUID, and for finding IDs without leaving the CLI.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use serde_json::Value;

const NOT_A_REPO: &str = "no-such-repo-resolver";

/// Deletes what a test made when dropped, so it cleans up even if an assertion
/// fails partway.
struct Cleanup<'a> {
    env: &'a common::TestEnv,
    paths: Vec<String>,
}

impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        for path in self.paths.iter().rev() {
            let _ = self.env.api_delete(path);
        }
    }
}

fn json_of(cmd: &mut assert_cmd::Command) -> Value {
    let output = cmd.assert().success().get_output().stdout.clone();
    serde_json::from_slice(&output).expect("command output is not JSON")
}

fn make_repo(env: &common::TestEnv, key: &str, cleanup: &mut Cleanup<'_>) -> String {
    env.ak_cmd()
        .args(["repo", "create", key, "--pkg-format", "generic"])
        .assert()
        .success();
    cleanup.paths.push(format!("/api/v1/repositories/{key}"));
    let shown = json_of(env.ak_cmd().args(["repo", "show", key]));
    shown["id"]
        .as_str()
        .expect("repo show has an id")
        .to_string()
}

#[test]
#[ignore = "requires the E2E backend"]
fn repo_show_and_list_expose_the_id() {
    let env = common::TestEnv::setup();
    let mut cleanup = Cleanup {
        env: &env,
        paths: Vec::new(),
    };
    let id = make_repo(&env, "resolver-ids", &mut cleanup);
    assert!(id.parse::<uuid::Uuid>().is_ok(), "{id}");

    let list = json_of(env.ak_cmd().args(["repo", "list", "--per-page", "100"]));
    let found = list
        .as_array()
        .expect("repo list is an array")
        .iter()
        .find(|r| r["key"] == "resolver-ids")
        .expect("repo in list");
    assert_eq!(found["id"], id.as_str());
}

#[test]
#[ignore = "requires the E2E backend"]
fn commands_taking_a_repo_id_accept_the_key() {
    let env = common::TestEnv::setup();
    let mut cleanup = Cleanup {
        env: &env,
        paths: Vec::new(),
    };
    let key = "resolver-key";
    let id = make_repo(&env, key, &mut cleanup);

    // Reads that take a repository, each with the key.
    for args in [
        vec!["sign", "key", "list", "--repo", key],
        vec!["sign", "config", "show", key],
        vec!["lifecycle", "list", "--repo", key],
        vec!["curation", "packages", "--staging-repo", key],
        vec!["curation", "rules", "--staging-repo", key],
        vec!["curation", "stats", "--staging-repo", key],
        vec!["promotion", "rule", "list", "--from", key],
        vec!["sbom", "list", "--repo", key],
        vec!["webhook", "list", "--repo", key],
        vec!["analytics", "repo-trend", key],
    ] {
        env.ak_cmd().args(&args).assert().success();
    }

    // A write that stores the ID: what's stored must be the repository's UUID.
    let key_made = json_of(env.ak_cmd().args([
        "sign",
        "key",
        "create",
        "resolver-signing",
        "--type",
        "rsa",
        "--repo",
        key,
    ]));
    let key_id = key_made["id"].as_str().expect("signing key id");
    cleanup.paths.push(format!("/api/v1/signing/keys/{key_id}"));
    assert_eq!(key_made["repository_id"], id.as_str());

    let policy = json_of(env.ak_cmd().args([
        "lifecycle",
        "create",
        "resolver-policy",
        "--policy-type",
        "max_age_days",
        "--config",
        r#"{"days":30}"#,
        "--repo",
        key,
    ]));
    let policy_id = policy["id"].as_str().expect("policy id");
    cleanup
        .paths
        .push(format!("/api/v1/admin/lifecycle/{policy_id}"));
    assert_eq!(policy["repository_id"], id.as_str());

    let license_policy = json_of(env.ak_cmd().args([
        "license",
        "policy",
        "create",
        "resolver-license",
        "--repo",
        key,
    ]));
    let license_id = license_policy["id"].as_str().expect("license policy id");
    cleanup
        .paths
        .push(format!("/api/v1/sbom/license-policies/{license_id}"));
    env.ak_cmd()
        .args(["license", "check", "--repo", key, "--licenses", "MIT"])
        .assert()
        .success();

    // The UUID still works.
    env.ak_cmd()
        .args(["sign", "config", "show", &id])
        .assert()
        .success();
}

#[test]
#[ignore = "requires the E2E backend"]
fn an_unknown_key_is_a_clear_error() {
    let env = common::TestEnv::setup();
    let output = env
        .ak_cmd()
        .args(["sign", "config", "show", NOT_A_REPO])
        .assert()
        .failure()
        .get_output()
        .stderr
        .clone();
    let stderr = String::from_utf8_lossy(&output).replace('│', " ");
    let stderr = stderr.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(stderr.contains(NOT_A_REPO), "{stderr}");
    assert!(stderr.contains("ak repo list"), "{stderr}");
}

#[test]
#[ignore = "requires the E2E backend"]
fn artifact_output_exposes_the_id_and_quarantine_takes_a_path() {
    let env = common::TestEnv::setup();
    let mut cleanup = Cleanup {
        env: &env,
        paths: Vec::new(),
    };
    let key = "resolver-art";
    make_repo(&env, key, &mut cleanup);

    let dir = tempfile::TempDir::new().expect("temp dir");
    let file = dir.path().join("resolver.txt");
    std::fs::write(&file, "hello").expect("write file");
    env.ak_cmd()
        .args(["artifact", "push", key])
        .arg(&file)
        .args(["--path", "docs/resolver.txt"])
        .assert()
        .success();

    let info = json_of(
        env.ak_cmd()
            .args(["artifact", "info", key, "docs/resolver.txt"]),
    );
    let id = info["id"].as_str().expect("artifact info has an id");
    assert!(id.parse::<uuid::Uuid>().is_ok(), "{id}");

    let list = json_of(env.ak_cmd().args(["artifact", "list", key]));
    assert_eq!(list[0]["id"], id);

    // By ID and by <repo>/<path>, the same artifact.
    let by_id = json_of(env.ak_cmd().args(["quarantine", "status", id]));
    let by_path =
        json_of(
            env.ak_cmd()
                .args(["quarantine", "status", "resolver-art/docs/resolver.txt"]),
        );
    assert_eq!(by_id["artifact_id"], id);
    assert_eq!(by_path["artifact_id"], id);

    let missing = env
        .ak_cmd()
        .args(["quarantine", "status", "resolver-art/docs/absent.txt"])
        .assert()
        .failure()
        .get_output()
        .stderr
        .clone();
    assert!(String::from_utf8_lossy(&missing).contains("absent.txt"));
}
