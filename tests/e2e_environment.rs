//! E2E tests for `ak environment`.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use predicates::prelude::*;
use predicates::str::contains;
use serde_json::Value;

const LOCKFILE: &str = r#"{"name":"demo","version":"1.0.0","lockfileVersion":3,"requires":true,
"packages":{"":{"name":"demo","version":"1.0.0","dependencies":{"express":"4.18.2"}},
"node_modules/express":{"version":"4.18.2","dependencies":{"qs":"6.11.0"}},
"node_modules/qs":{"version":"6.11.0"}}}"#;

/// Deletes the repository when dropped, so tests clean up even if one fails.
struct Cleanup {
    url: String,
    token: String,
    repo: String,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = reqwest::blocking::Client::new()
            .delete(format!("{}/api/v1/repositories/{}", self.url, self.repo))
            .bearer_auth(&self.token)
            .send();
    }
}

fn json_output(cmd: &mut assert_cmd::Command) -> Value {
    let output = cmd.assert().success().get_output().stdout.clone();
    serde_json::from_slice(&output).expect("command output is not JSON")
}

fn repo(env: &common::TestEnv, name: &str) -> Cleanup {
    env.ak_cmd()
        .args(["repo", "create", name, "--pkg-format", "generic"])
        .assert()
        .success();
    Cleanup {
        url: env.url.clone(),
        token: env.token.clone(),
        repo: name.to_string(),
    }
}

#[test]
#[ignore = "requires E2E backend"]
fn environment_lifecycle() {
    if common::server_older_than(1, 11, "environments") {
        return;
    }
    let env = common::TestEnv::setup();
    let suffix = std::process::id();
    let name = format!("e2e-env-{suffix}");
    let _guard = repo(&env, &name);
    let file = env.config_dir.path().join("package-lock.json");
    std::fs::write(&file, LOCKFILE).unwrap();
    let path = file.to_str().unwrap();

    let empty = json_output(env.ak_cmd().args(["environment", "list", &name]));
    assert_eq!(empty["environments"].as_array().unwrap().len(), 0);

    let stored = json_output(env.ak_cmd().args(["environment", "ingest", &name, path]));
    let id = stored["id"].as_str().unwrap().to_string();
    assert_eq!(
        stored["name"], "package-lock.json",
        "defaults to the file name"
    );
    assert_eq!(stored["replaced"], false);
    assert_eq!(stored["summary"]["distinctPackages"], 3);

    let replaced = json_output(env.ak_cmd().args(["environment", "ingest", &name, path]));
    assert_eq!(replaced["id"], id.as_str());
    assert_eq!(replaced["replaced"], true);

    // From stdin, under a name of its own.
    let named = json_output(
        env.ak_cmd()
            .args(["environment", "ingest", &name, "-"])
            .args(["--filename", "package-lock.json", "--name", "prod"])
            .write_stdin(LOCKFILE),
    );
    assert_eq!(named["name"], "prod");
    assert_ne!(named["id"], id.as_str());

    let list = json_output(env.ak_cmd().args(["environment", "list", &name]));
    assert_eq!(list["environments"].as_array().unwrap().len(), 2);

    // By name and by ID.
    let by_name = json_output(env.ak_cmd().args(["environment", "show", &name, "prod"]));
    let by_id = json_output(env.ak_cmd().args([
        "environment",
        "show",
        &name,
        named["id"].as_str().unwrap(),
    ]));
    assert_eq!(by_name, by_id);
    assert_eq!(by_name["lockfileFormat"], "package-lock.json");
    assert_eq!(by_name["scopes"][0]["memberships"], 3);

    let advisories = json_output(
        env.ak_cmd()
            .args(["environment", "advisories", &name, "prod"]),
    );
    assert_eq!(advisories["affected"].as_array().unwrap().len(), 0);

    env.ak_cmd_table()
        .args(["--format", "table", "environment", "list", &name])
        .assert()
        .success()
        .stdout(contains("prod").and(contains("package-lock.json")));

    env.ak_cmd()
        .args(["environment", "delete", &name, "prod", "--yes"])
        .assert()
        .success();
    env.ak_cmd()
        .args(["environment", "show", &name, "prod"])
        .assert()
        .failure()
        .stderr(contains("No environment named 'prod'"));
}

#[test]
#[ignore = "requires E2E backend"]
fn lookup_finds_a_component_and_what_pulls_it_in() {
    if common::server_older_than(1, 11, "environments") {
        return;
    }
    let env = common::TestEnv::setup();
    let name = format!("e2e-env-lookup-{}", std::process::id());
    let _guard = repo(&env, &name);
    let file = env.config_dir.path().join("package-lock.json");
    std::fs::write(&file, LOCKFILE).unwrap();
    json_output(
        env.ak_cmd()
            .args(["environment", "ingest", &name, file.to_str().unwrap()]),
    );

    let found = json_output(env.ak_cmd().args([
        "environment",
        "lookup",
        "pkg:npm/qs@6.11.0",
        "--max-paths",
        "1",
    ]));
    let hit = found["hits"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["repository"]["key"] == name.as_str())
        .unwrap_or_else(|| panic!("no hit in {name}: {found}"));
    assert_eq!(hit["package"]["name"], "qs");
    assert_eq!(hit["paths"][0][1], "express@4.18.2");

    env.ak_cmd_table()
        .args([
            "--format",
            "table",
            "environment",
            "lookup",
            "pkg:npm/qs@6.11.0",
        ])
        .assert()
        .success()
        .stdout(contains("express@4.18.2 > qs@6.11.0"));

    let none = json_output(
        env.ak_cmd()
            .args(["environment", "lookup", "pkg:npm/no-such@1"]),
    );
    assert_eq!(none["hits"].as_array().unwrap().len(), 0);
}

#[test]
#[ignore = "requires E2E backend"]
fn advisory_transitions_take_every_filter() {
    if common::server_older_than(1, 11, "environments") {
        return;
    }
    let env = common::TestEnv::setup();
    let list = json_output(env.ak_cmd().args([
        "environment",
        "advisory-transitions",
        "--advisory",
        "GHSA-none",
        "--kind",
        "new-affected",
        "--since",
        "2026-01-01T00:00:00Z",
        "--until",
        "2099-01-01T00:00:00Z",
        "--limit",
        "5",
    ]));
    assert_eq!(list["transitions"].as_array().unwrap().len(), 0);

    env.ak_cmd()
        .args(["environment", "advisory-transitions", "--kind", "bad"])
        .assert()
        .failure()
        .stderr(contains("must be `new-affected`"));
}

#[test]
#[ignore = "requires E2E backend"]
fn a_lockfile_the_server_cant_parse_shows_its_message() {
    if common::server_older_than(1, 11, "environments") {
        return;
    }
    let env = common::TestEnv::setup();
    let name = format!("e2e-env-bad-{}", std::process::id());
    let _guard = repo(&env, &name);
    let file = env.config_dir.path().join("mystery.txt");
    std::fs::write(&file, "?").unwrap();
    env.ak_cmd()
        .args(["environment", "ingest", &name, file.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(contains("400"));
}
