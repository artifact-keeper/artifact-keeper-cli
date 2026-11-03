//! E2E tests for `ak license`.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

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

#[test]
#[ignore = "requires E2E backend"]
fn a_policy_decides_the_check_and_is_gone_after_delete() {
    let env = common::TestEnv::setup();
    let suffix = std::process::id();
    let repo = format!("e2e-lic-{suffix}");
    env.ak_cmd()
        .args(["repo", "create", &repo, "--pkg-format", "generic"])
        .assert()
        .success();

    let name = format!("e2e-lic-{suffix}");
    let policy = json_of(env.ak_cmd().args([
        "license",
        "policy",
        "create",
        &name,
        "--allowed",
        "MIT,Apache-2.0",
        "--denied",
        "GPL-3.0",
        "--action",
        "block",
        "--description",
        "from the E2E tests",
        "--repo",
        &repo,
    ]));
    let id = policy["id"].as_str().unwrap().to_string();
    assert_eq!(policy["name"], name.as_str());
    assert_eq!(
        policy["allowed_licenses"],
        serde_json::json!(["MIT", "Apache-2.0"])
    );
    assert_eq!(policy["denied_licenses"], serde_json::json!(["GPL-3.0"]));
    assert_eq!(policy["action"], "block");
    assert_eq!(policy["description"], "from the E2E tests");

    let shown = json_of(env.ak_cmd().args(["license", "policy", "show", &id]));
    assert_eq!(shown["id"], id.as_str());
    let listed = json_of(env.ak_cmd().args(["license", "policy", "list"]));
    assert!(
        listed
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["id"] == id.as_str()),
        "{listed}"
    );

    let compliant =
        json_of(
            env.ak_cmd()
                .args(["license", "check", "--licenses", "MIT", "--repo", &repo]),
        );
    assert_eq!(compliant["compliant"], true);

    // Not compliant is a failure a script can see, and still prints the reasons.
    let output = env
        .ak_cmd()
        .args(["license", "check", "--licenses", "GPL-3.0", "--repo", &repo])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let denied: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(denied["compliant"], false);
    assert!(
        denied["violations"][0]
            .as_str()
            .unwrap()
            .contains("GPL-3.0"),
        "{denied}"
    );

    env.ak_cmd()
        .args(["license", "policy", "delete", &id, "--yes"])
        .assert()
        .success();
    env.ak_cmd()
        .args(["license", "policy", "show", &id])
        .assert()
        .failure();
    let _ = env.api_delete(&format!("/api/v1/repositories/{repo}"));
}

#[test]
#[ignore = "requires E2E backend"]
fn a_repository_that_does_not_exist_is_refused() {
    let env = common::TestEnv::setup();
    env.ak_cmd()
        .args([
            "license",
            "check",
            "--licenses",
            "MIT",
            "--repo",
            "no-such-repo",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("no-such-repo"));
}
