//! E2E tests for `ak bundle`.
//!
//! Requires the E2E backend: ./tests/start-backend.sh
//!
//! `export` and `import` aren't here: the 1.11.11 server answers both with 501.
//! See tests/bundle_contract.rs.

mod common;

use predicates::prelude::*;
use predicates::str::contains;
use serde_json::Value;

const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn json_output(cmd: &mut assert_cmd::Command) -> Value {
    let output = cmd.assert().success().get_output().stdout.clone();
    serde_json::from_slice(&output).expect("command output is not JSON")
}

fn manifest() -> Value {
    serde_json::json!({
        "format": "akbundle",
        "schema_version": 1,
        "bundle_id": "00000000-0000-0000-0000-000000000000",
        "created_at": "2026-10-01T00:00:00Z",
        "producer": {"product": "artifact-keeper", "version": "1.11.0"},
        "kind": "full",
        "volume_set": {
            "set_id": "00000000-0000-0000-0000-000000000000",
            "media_profile": "unbounded",
            "volume_count": 1
        },
        "repositories": [{
            "key": "libs", "format": "maven", "repo_type": "local",
            "metadata_path": "repos/libs/repo.json",
            "artifacts_path": "repos/libs/artifacts.json"
        }],
        "items": [{
            "repository_key": "libs", "logical_path": "a-1.0.jar", "sha256": SHA,
            "size_bytes": 10, "blob_path": format!("blobs/aa/{SHA}.jar"), "volume": 1
        }]
    })
}

#[test]
#[ignore = "requires E2E backend"]
fn format_describes_what_the_server_can_do() {
    if common::server_older_than(1, 11, "bundles") {
        return;
    }
    let env = common::TestEnv::setup();
    let format = json_output(env.ak_cmd().args(["bundle", "format"]));
    assert_eq!(format["format"], "akbundle");
    assert!(format["export_available"].is_boolean());
    assert!(!format["media_profiles"].as_array().unwrap().is_empty());

    env.ak_cmd_table()
        .args(["--format", "table", "bundle", "format"])
        .assert()
        .success()
        .stdout(contains("Media profiles:").and(contains("bd_r")));
}

#[test]
#[ignore = "requires E2E backend"]
fn a_valid_manifest_passes() {
    if common::server_older_than(1, 11, "bundles") {
        return;
    }
    let env = common::TestEnv::setup();
    let file = env.config_dir.path().join("manifest.json");
    std::fs::write(&file, manifest().to_string()).unwrap();
    let report =
        json_output(
            env.ak_cmd()
                .args(["bundle", "validate-manifest", file.to_str().unwrap()]),
        );
    assert_eq!(report["valid"], true, "{report}");
    assert_eq!(report["item_count"], 1);
    assert_eq!(report["total_bytes"], 10);
}

#[test]
#[ignore = "requires E2E backend"]
fn an_invalid_manifest_is_reported_and_exits_1() {
    if common::server_older_than(1, 11, "bundles") {
        return;
    }
    let env = common::TestEnv::setup();
    let mut bad = manifest();
    bad["surprise"] = Value::Bool(true);
    let file = env.config_dir.path().join("manifest.json");
    std::fs::write(&file, bad.to_string()).unwrap();
    let output = env
        .ak_cmd()
        .args(["bundle", "validate-manifest", file.to_str().unwrap()])
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["valid"], false);
    assert!(
        report["problems"][0].as_str().unwrap().contains("surprise"),
        "{report}"
    );

    // Not JSON at all still reaches the server, whose job it is to say so.
    std::fs::write(&file, "not json").unwrap();
    env.ak_cmd_table()
        .args([
            "--format",
            "table",
            "bundle",
            "validate-manifest",
            file.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stdout(contains("Problems:"));
}

#[test]
#[ignore = "requires E2E backend"]
fn jobs_list_takes_filters_and_rejects_a_bad_one() {
    if common::server_older_than(1, 11, "bundles") {
        return;
    }
    let env = common::TestEnv::setup();
    let list = json_output(env.ak_cmd().args([
        "bundle",
        "jobs",
        "list",
        "--direction",
        "export",
        "--status",
        "completed",
        "--page",
        "2",
        "--per-page",
        "5",
    ]));
    assert_eq!(list["page"], 2);
    assert_eq!(list["per_page"], 5);

    env.ak_cmd()
        .args(["bundle", "jobs", "list", "--direction", "sideways"])
        .assert()
        .failure()
        .stderr(contains("direction must"));
}

#[test]
#[ignore = "requires E2E backend"]
fn a_missing_job_is_a_404() {
    if common::server_older_than(1, 11, "bundles") {
        return;
    }
    let env = common::TestEnv::setup();
    let missing = "00000000-0000-0000-0000-000000000001";
    for args in [
        ["bundle", "jobs", "show", missing].as_slice(),
        ["bundle", "jobs", "items", missing].as_slice(),
    ] {
        env.ak_cmd()
            .args(args)
            .assert()
            .failure()
            .stderr(contains("Bundle job"));
    }
}
