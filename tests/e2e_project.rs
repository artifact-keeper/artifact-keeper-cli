//! E2E tests for `ak project`.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use serde_json::Value;

/// Deletes the project when dropped, so tests clean up even if an assertion fails.
struct Cleanup {
    url: String,
    token: String,
    id: String,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = reqwest::blocking::Client::new()
            .delete(format!("{}/api/v1/projects/{}", self.url, self.id))
            .bearer_auth(&self.token)
            .send();
    }
}

fn json_output(cmd: &mut assert_cmd::Command) -> Value {
    let output = cmd.assert().success().get_output().stdout.clone();
    serde_json::from_slice(&output).expect("command output is not JSON")
}

#[test]
fn project_lifecycle_by_key_and_by_id() {
    let env = common::TestEnv::setup();
    let key = format!("e2e-project-{}", std::process::id());

    let created = json_output(env.ak_cmd().args([
        "project",
        "create",
        &key,
        "--name",
        "E2E",
        "--description",
        "first",
        "--quota-bytes",
        "1048576",
    ]));
    let id = created["id"].as_str().unwrap().to_string();
    let _guard = Cleanup {
        url: env.url.clone(),
        token: env.token.clone(),
        id: id.clone(),
    };
    assert_eq!(created["key"], key.as_str());
    assert_eq!(created["name"], "E2E");
    assert_eq!(created["description"], "first");
    assert_eq!(created["quota_bytes"], 1048576);

    let list = json_output(env.ak_cmd().args(["project", "list"]));
    assert!(
        list["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["id"] == id.as_str()),
        "{list}"
    );

    assert_eq!(
        json_output(env.ak_cmd().args(["project", "show", &key])),
        json_output(env.ak_cmd().args(["project", "show", &id]))
    );

    let updated =
        json_output(
            env.ak_cmd()
                .args(["project", "update", &key, "--description", "second"]),
        );
    assert_eq!(updated["description"], "second");
    assert_eq!(
        updated["name"], "E2E",
        "an update keeps what it wasn't given"
    );
    assert_eq!(updated["quota_bytes"], 1048576);

    env.ak_cmd_table()
        .args(["project", "list"])
        .assert()
        .success()
        .stdout(predicates::str::contains(key.as_str()));

    env.ak_cmd()
        .args(["project", "delete", &key, "--yes"])
        .assert()
        .success();
    env.ak_cmd()
        .args(["project", "show", &id])
        .assert()
        .failure();
}

#[test]
fn project_members_add_list_remove() {
    let env = common::TestEnv::setup();
    let key = format!("e2e-project-members-{}", std::process::id());
    let created = json_output(env.ak_cmd().args(["project", "create", &key]));
    let _guard = Cleanup {
        url: env.url.clone(),
        token: env.token.clone(),
        id: created["id"].as_str().unwrap().to_string(),
    };
    let me = json_output(env.ak_cmd().args(["auth", "whoami"]));
    let user = me["id"].as_str().unwrap();

    let empty = json_output(env.ak_cmd().args(["project", "members", "list", &key]));
    assert_eq!(empty["items"].as_array().unwrap().len(), 0);

    let member = json_output(env.ak_cmd().args([
        "project",
        "members",
        "add",
        &key,
        "--principal",
        user,
        "--actions",
        "read,write",
    ]));
    assert_eq!(member["principal_type"], "user");
    assert_eq!(member["principal_id"], user);
    assert_eq!(member["actions"], serde_json::json!(["read", "write"]));

    let list = json_output(env.ak_cmd().args(["project", "members", "list", &key]));
    assert_eq!(list["items"][0]["principal_id"], user);

    env.ak_cmd()
        .args([
            "project",
            "members",
            "remove",
            &key,
            "--principal",
            user,
            "--yes",
        ])
        .assert()
        .success();
    let list = json_output(env.ak_cmd().args(["project", "members", "list", &key]));
    assert_eq!(list["items"].as_array().unwrap().len(), 0);

    // The grant is gone, so the server's 404 must come through.
    env.ak_cmd()
        .args([
            "project",
            "members",
            "remove",
            &key,
            "--principal",
            user,
            "--yes",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("not found"));
}

#[test]
fn a_duplicate_key_shows_the_servers_message() {
    let env = common::TestEnv::setup();
    let key = format!("e2e-project-dup-{}", std::process::id());
    let created = json_output(env.ak_cmd().args(["project", "create", &key]));
    let _guard = Cleanup {
        url: env.url.clone(),
        token: env.token.clone(),
        id: created["id"].as_str().unwrap().to_string(),
    };
    env.ak_cmd()
        .args(["project", "create", &key])
        .assert()
        .failure()
        .stderr(predicates::str::contains("already exists"));
}
