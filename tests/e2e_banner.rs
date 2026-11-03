//! E2E tests for `ak banner`.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use serde_json::Value;

/// Deletes the banner when dropped, so a failed test leaves none showing.
struct Cleanup {
    url: String,
    token: String,
    id: String,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = reqwest::blocking::Client::new()
            .delete(format!("{}/api/v1/admin/banners/{}", self.url, self.id))
            .bearer_auth(&self.token)
            .send();
    }
}

fn json_output(cmd: &mut assert_cmd::Command) -> Value {
    let output = cmd.assert().success().get_output().stdout.clone();
    serde_json::from_slice(&output).expect("command output is not JSON")
}

fn shows(list: &Value, id: &str) -> bool {
    list["banners"]
        .as_array()
        .unwrap()
        .iter()
        .any(|b| b["id"] == id)
}

#[test]
#[ignore = "requires E2E backend"]
fn banner_lifecycle() {
    if common::server_older_than(1, 11, "banners") {
        return;
    }
    let env = common::TestEnv::setup();
    let created = json_output(env.ak_cmd().args([
        "banner",
        "create",
        "E2E maintenance",
        "--message",
        "Down soon",
        "--severity",
        "critical",
        "--target",
        "api",
        "--link-url",
        "https://status.example.com",
        "--ends-at",
        "2099-01-01T00:00:00Z",
    ]));
    let id = created["id"].as_str().unwrap().to_string();
    let _guard = Cleanup {
        url: env.url.clone(),
        token: env.token.clone(),
        id: id.clone(),
    };
    assert_eq!(created["severity"], "critical");
    assert_eq!(created["target"], "api");
    assert_eq!(created["enabled"], true);
    assert_eq!(created["active"], true);
    assert_eq!(created["link_url"], "https://status.example.com/");

    assert_eq!(
        json_output(env.ak_cmd().args(["banner", "show", &id]))["id"],
        id.as_str()
    );
    assert!(shows(
        &json_output(env.ak_cmd().args(["banner", "list"])),
        &id
    ));

    // The target filter reaches the server.
    let api = json_output(env.ak_cmd().args(["banner", "active", "--target", "api"]));
    assert!(shows(&api, &id), "{api}");
    let ui = json_output(env.ak_cmd().args(["banner", "active", "--target", "ui"]));
    assert!(!shows(&ui, &id), "{ui}");

    // `active` is public: it works with no credentials at all.
    let (mut anonymous, _anonymous_config) = env.anonymous_cmd();
    let anonymous = json_output(anonymous.args(["banner", "active"]));
    assert!(shows(&anonymous, &id), "{anonymous}");

    // An update keeps what it wasn't told to change, and can clear a field.
    let updated = json_output(env.ak_cmd().args([
        "banner",
        "update",
        &id,
        "--title",
        "Renamed",
        "--no-link-url",
    ]));
    assert_eq!(updated["title"], "Renamed");
    assert_eq!(updated["message"], "Down soon");
    assert_eq!(updated["severity"], "critical");
    assert_eq!(updated["target"], "api");
    assert_eq!(updated["ends_at"], "2099-01-01T00:00:00Z");
    assert!(updated["link_url"].is_null(), "{updated}");

    let disabled = json_output(env.ak_cmd().args(["banner", "update", &id, "--disable"]));
    assert_eq!(disabled["enabled"], false);
    assert_eq!(disabled["active"], false);
    assert!(!shows(
        &json_output(env.ak_cmd().args(["banner", "active"])),
        &id
    ));

    env.ak_cmd_table()
        .args(["banner", "show", &id])
        .assert()
        .success()
        .stdout(predicates::str::contains("Renamed"));

    env.ak_cmd()
        .args(["banner", "delete", &id, "--yes"])
        .assert()
        .success();
    env.ak_cmd()
        .args(["banner", "show", &id])
        .assert()
        .failure();
}

#[test]
#[ignore = "requires E2E backend"]
fn an_invalid_banner_shows_the_servers_message() {
    if common::server_older_than(1, 11, "banners") {
        return;
    }
    let env = common::TestEnv::setup();
    env.ak_cmd()
        .args([
            "banner",
            "create",
            "t",
            "--message",
            "m",
            "--link-url",
            "ftp://x",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("400"));
}
