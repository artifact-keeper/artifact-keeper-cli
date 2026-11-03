//! E2E tests for `ak auth` commands.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use predicates::prelude::*;

#[test]
#[ignore = "requires E2E backend"]
fn auth_whoami_json() {
    let env = common::TestEnv::setup();
    env.ak_cmd()
        .args(["auth", "whoami"])
        .assert()
        .success()
        .stdout(predicate::str::contains("admin"));
}

#[test]
#[ignore = "requires E2E backend"]
fn auth_whoami_table() {
    let env = common::TestEnv::setup();
    env.ak_cmd_table()
        .args(["auth", "whoami"])
        .assert()
        .success()
        .stdout(predicate::str::contains("admin"));
}

#[test]
#[ignore = "requires E2E backend"]
fn auth_token_list() {
    let env = common::TestEnv::setup();
    env.ak_cmd()
        .args(["auth", "token", "list"])
        .assert()
        .success();
}

/// A failed assertion on a command prints the command, its environment and its
/// output, and in CI that goes to the log.
#[test]
#[ignore = "requires E2E backend"]
fn a_failing_command_does_not_print_the_token() {
    let env = common::TestEnv::setup();
    let mut cmd = env.ak_cmd();
    cmd.args(["repo", "show", "e2e-no-such-repository"]);

    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        cmd.assert().success();
    }))
    .expect_err("the command should fail");
    let printed = panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(ToString::to_string))
        .expect("a panic message");

    assert!(
        printed.contains("e2e-no-such-repository"),
        "this isn't the failure it should be"
    );
    assert!(!printed.contains(&env.token), "the token was printed");
}

/// `ak` with a config for the backend and nothing stored. `whoami` works only if a
/// login stored a session.
fn stored_only(env: &common::TestEnv) -> (tempfile::TempDir, impl Fn() -> assert_cmd::Command) {
    let home = tempfile::TempDir::new().unwrap();
    std::fs::write(
        home.path().join("config.toml"),
        format!(
            "default_instance = \"e2e\"\n[instances.e2e]\nurl = \"{}\"\napi_version = \"v1\"\n",
            env.url
        ),
    )
    .unwrap();
    let dir = home.path().to_path_buf();
    let ak = move || {
        let mut cmd = assert_cmd::Command::cargo_bin("ak").unwrap();
        cmd.env_remove("AK_TOKEN")
            .env("AK_CONFIG_DIR", &dir)
            .env("AK_CREDENTIAL_STORE", "file")
            .args(["--no-input", "--format", "json"]);
        cmd
    };
    (home, ak)
}

const ADMIN_PASSWORD: &str = "TestRunner!2026secure";

#[test]
#[ignore = "requires E2E backend"]
fn login_with_password_on_stdin_stores_a_session_and_prints_no_secret() {
    let env = common::TestEnv::setup();
    let (_home, ak) = stored_only(&env);
    ak().args(["auth", "whoami"]).assert().failure();

    let output = ak()
        .args(["auth", "login", "--username", "admin", "--password-stdin"])
        .write_stdin(ADMIN_PASSWORD)
        .output()
        .unwrap();
    assert!(output.status.success());
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!all.contains(ADMIN_PASSWORD), "{all}");
    assert!(!all.contains("eyJ"), "{all}");

    ak().args(["auth", "whoami"])
        .assert()
        .success()
        .stdout(predicate::str::contains("admin"));
}

#[test]
#[ignore = "requires E2E backend"]
fn a_wrong_password_stores_nothing() {
    let env = common::TestEnv::setup();
    let (_home, ak) = stored_only(&env);
    ak().args(["auth", "login", "--username", "admin", "--password-stdin"])
        .write_stdin("not-the-password")
        .assert()
        .failure()
        .stderr(predicate::str::contains("not-the-password").not());
    ak().args(["auth", "whoami"]).assert().failure();
}

#[test]
#[ignore = "requires E2E backend"]
fn login_with_a_token_on_stdin_checks_it_first() {
    let env = common::TestEnv::setup();
    let (_home, ak) = stored_only(&env);
    ak().args(["auth", "login", "--token-stdin"])
        .write_stdin("not-a-token")
        .assert()
        .failure();
    ak().args(["auth", "whoami"]).assert().failure();
    // Not `.assert()`: a failed one would print its stdin, which holds the token.
    let output = ak()
        .args(["auth", "login", "--token-stdin"])
        .write_stdin(env.token.clone())
        .output()
        .unwrap();
    assert!(output.status.success());
    ak().args(["auth", "whoami"]).assert().success();
}

/// A bad code gets the server's refusal. A good one needs a browser and an identity
/// provider: see the contract tests in tests/auth_contract.rs.
#[test]
#[ignore = "requires E2E backend"]
fn sso_exchange_refuses_a_bad_code() {
    let env = common::TestEnv::setup();
    let (_home, ak) = stored_only(&env);
    ak().args(["auth", "sso-exchange", "--code-stdin"])
        .write_stdin("not-a-code")
        .assert()
        .failure()
        .stderr(predicate::str::contains("401"));
    ak().args(["auth", "whoami"]).assert().failure();
}

fn id_of(output: &[u8]) -> String {
    let value: serde_json::Value = serde_json::from_slice(output).unwrap();
    value["id"].as_str().unwrap().to_string()
}

#[test]
#[ignore = "requires E2E backend"]
fn token_create_sends_scopes_and_a_selector() {
    let env = common::TestEnv::setup();
    let name = format!("e2e-scoped-{}", std::process::id());
    let output = env
        .ak_cmd()
        .args(["auth", "token", "create", "--description", &name])
        .args(["--scope", "read:artifacts"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let id = id_of(&output.stdout);
    let list: serde_json::Value = serde_json::from_slice(
        &env.ak_cmd()
            .args(["auth", "token", "list"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let token = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["id"] == id.as_str())
        .expect("the new token is listed");
    assert_eq!(token["scopes"], serde_json::json!(["read:artifacts"]));
    env.ak_cmd()
        .args(["auth", "revoke-token", &id])
        .assert()
        .success();

    // The server refuses a selector with no criteria, so this proves it got there.
    env.ak_cmd()
        .args(["auth", "token", "create", "--description", &name])
        .args(["--repo-selector", "{}"])
        .assert()
        .failure();
    let output = env
        .ak_cmd()
        .args(["auth", "token", "create", "--description", &name])
        .args(["--repo-selector", r#"{"match_formats":["npm"]}"#])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    env.ak_cmd()
        .args(["auth", "revoke-token", &id_of(&output.stdout)])
        .assert()
        .success();
}

#[test]
#[ignore = "requires E2E backend"]
fn profile_access_tokens_create_list_and_revoke() {
    let env = common::TestEnv::setup();
    let name = format!("e2e-access-{}", std::process::id());
    let output = env
        .ak_cmd()
        .args(["profile", "access-tokens", "create", &name])
        .args(["--scope", "read:artifacts", "--expires-in-days", "2"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let id = id_of(&output.stdout);
    let listed = |id: &str| -> bool {
        let output = env
            .ak_cmd()
            .args(["profile", "access-tokens", "list"])
            .output()
            .unwrap();
        let list: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        list["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["id"] == id && t["scopes"] == serde_json::json!(["read:artifacts"]))
    };
    assert!(listed(&id));
    env.ak_cmd()
        .args(["profile", "access-tokens", "revoke", &id])
        .assert()
        .success();
    assert!(!listed(&id));
}

#[test]
#[ignore = "requires E2E backend"]
fn set_password_then_change_password_as_the_user() {
    let env = common::TestEnv::setup();
    let name = format!("e2e-pw-{}", std::process::id());
    let first = "E2e-FirstPass!2026-long";
    let second = "E2e-SecondPass!2026-long";
    let third = "E2e-ThirdPass!2026-long";

    let output = env
        .ak_cmd()
        .args(["admin", "users", "create", &name])
        .args(["--email", &format!("{name}@example.com")])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let created: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let id = created["user"]["id"].as_str().unwrap().to_string();

    // An admin needs no current password.
    let output = env
        .ak_cmd()
        .args([
            "admin",
            "users",
            "set-password",
            &id,
            "--new-password-stdin",
        ])
        .write_stdin(first)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(first));

    let (_home, ak) = stored_only(&env);
    ak().args(["auth", "login", "--username", &name, "--password-stdin"])
        .write_stdin(first)
        .assert()
        .success();

    // A user does, and the server checks it.
    let output = ak()
        .args(["profile", "change-password", "--new-password-stdin"])
        .env("AK_CURRENT_PASSWORD", "not-the-password")
        .write_stdin(second)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let output = ak()
        .args(["profile", "change-password", "--new-password-stdin"])
        .env("AK_CURRENT_PASSWORD", first)
        .write_stdin(second)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The new one works, and the old one doesn't.
    ak().args(["auth", "login", "--username", &name, "--password-stdin"])
        .write_stdin(first)
        .assert()
        .failure();
    ak().args(["auth", "login", "--username", &name, "--password-stdin"])
        .write_stdin(second)
        .assert()
        .success();

    // The same through the other route.
    let output = ak()
        .args([
            "admin",
            "users",
            "set-password",
            &id,
            "--new-password-stdin",
        ])
        .env("AK_CURRENT_PASSWORD", second)
        .write_stdin(third)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = env.api_delete(&format!("/api/v1/users/{id}"));
}

#[test]
#[ignore = "requires E2E backend"]
fn users_list_filters_reach_the_server() {
    let env = common::TestEnv::setup();
    let output = env
        .ak_cmd()
        .args(["admin", "users", "list", "--is-admin", "true"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let list: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let items = list["items"].as_array().unwrap();
    assert!(!items.is_empty());
    assert!(items.iter().all(|u| u["is_admin"] == true), "{list}");
}
