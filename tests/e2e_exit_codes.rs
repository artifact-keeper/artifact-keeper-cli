//! The exit codes in `ak --help`, on a real server, across a sample of commands.

mod common;

use assert_cmd::Command;

fn code(cmd: &mut Command) -> i32 {
    cmd.output().expect("run ak").status.code().expect("a code")
}

#[test]
#[ignore = "requires E2E backend"]
fn zero_on_success() {
    let env = common::TestEnv::setup();
    assert_eq!(code(env.ak_cmd().args(["repo", "list"])), 0);
    assert_eq!(code(env.ak_cmd().args(["auth", "whoami"])), 0);
}

#[test]
#[ignore = "requires E2E backend"]
fn two_on_usage_and_validation() {
    let env = common::TestEnv::setup();
    assert_eq!(code(env.ak_cmd().args(["repo", "list", "--bogus"])), 2);
    assert_eq!(code(env.ak_cmd().args(["group", "show", "not-a-uuid"])), 2);
    assert_eq!(
        code(env.ak_cmd().args(["--instance", "nope", "repo", "list"])),
        2
    );
    assert_eq!(code(env.ak_cmd().args(["project", "update", "x"])), 2);
}

#[test]
#[ignore = "requires E2E backend"]
fn three_on_a_network_failure() {
    let dir = tempfile::TempDir::new().expect("temp dir");
    std::fs::write(
        dir.path().join("config.toml"),
        "default_instance = \"gone\"\n[instances.gone]\nurl = \"http://127.0.0.1:1\"\n",
    )
    .expect("write config");
    for args in [
        &["repo", "list"][..],
        &["auth", "whoami"],
        &["artifact", "pull", "r", "f"],
    ] {
        let got = code(
            Command::cargo_bin("ak")
                .expect("ak")
                .env("AK_CONFIG_DIR", dir.path())
                .env("AK_TOKEN", "unused")
                .env("AK_CREDENTIAL_STORE", "file")
                .current_dir(dir.path())
                .args(args),
        );
        assert_eq!(got, 3, "{args:?}");
    }
}

#[test]
#[ignore = "requires E2E backend"]
fn four_on_a_bad_token_or_no_right() {
    let env = common::TestEnv::setup();
    let dir = tempfile::TempDir::new().expect("temp dir");
    std::fs::copy(
        env.config_dir.path().join("config.toml"),
        dir.path().join("config.toml"),
    )
    .expect("copy config");
    for args in [
        &["repo", "list"][..],
        &["auth", "whoami"],
        &["admin", "stats"],
    ] {
        let got = code(
            Command::cargo_bin("ak")
                .expect("ak")
                .env("AK_CONFIG_DIR", dir.path())
                .env("AK_TOKEN", "not-a-real-token")
                .env("AK_CREDENTIAL_STORE", "file")
                .args(["--no-input"])
                .args(args),
        );
        assert_eq!(got, 4, "{args:?}");
    }
}

#[test]
#[ignore = "requires E2E backend"]
fn five_on_not_found() {
    let env = common::TestEnv::setup();
    assert_eq!(code(env.ak_cmd().args(["repo", "show", "no-such-repo"])), 5);
    assert_eq!(
        code(env.ak_cmd().args(["artifact", "show", "no-such-repo", "x"])),
        5
    );
    assert_eq!(
        code(
            env.ak_cmd()
                .args(["webhook", "show", "00000000-0000-4000-8000-000000000000"])
        ),
        5
    );
}

#[test]
#[ignore = "requires E2E backend"]
fn six_on_another_server_error() {
    let env = common::TestEnv::setup();
    // A repository key the server rejects.
    assert_eq!(
        code(env.ak_cmd().args([
            "repo",
            "create",
            "not a valid key!",
            "--pkg-format",
            "generic",
            "--repo-type",
            "local",
        ])),
        6
    );
    if common::server_older_than(1, 11, "`ak attestation policy` gates on 1.10") {
        assert_eq!(code(env.ak_cmd().args(["attestation", "policy"])), 6);
    }
}

// 7, a failure in a 2xx response, is checked where the failure is set up: `license
// check` in e2e_license, a blocked promotion in e2e_promotion and `bundle validate` in
// e2e_bundle.

#[test]
#[ignore = "requires E2E backend"]
fn ak_api_keeps_its_own_table() {
    let env = common::TestEnv::setup();
    let path = "/api/v1/repositories/no-such-repo";
    assert_eq!(code(env.ak_cmd().args(["api", "GET", path])), 1);
    assert_eq!(code(env.ak_cmd().args(["api", "--fail", "GET", path])), 22);
    assert_eq!(
        code(env.ak_cmd().args(["api", "--no-fail", "GET", path])),
        0
    );
    assert_eq!(
        code(
            env.ak_cmd()
                .args(["api", "GET", "/api/v1/repositories", "--bogus"])
        ),
        2
    );
    assert_eq!(
        code(
            env.ak_cmd()
                .args(["--instance", "nope", "api", "GET", "/health"])
        ),
        3
    );
}
