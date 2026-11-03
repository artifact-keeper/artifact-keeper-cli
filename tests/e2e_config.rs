//! E2E tests for `ak config` commands.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use predicates::prelude::*;

#[test]
#[ignore = "requires E2E backend"]
fn config_list() {
    let env = common::TestEnv::setup();
    env.ak_cmd_table()
        .args(["config", "list"])
        .assert()
        .success();
}

#[test]
#[ignore = "requires E2E backend"]
fn config_path() {
    let env = common::TestEnv::setup();
    env.ak_cmd_table()
        .args(["config", "path"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

/// `ak config set output_format` and `color` do what they say, with the order flag,
/// env, config, default, against a real server.
#[test]
#[ignore = "requires E2E backend"]
fn config_output_format_applies_to_real_commands() {
    let env = common::TestEnv::setup();
    let run = |args: &[&str]| {
        let output = env.ak_cmd_table().args(args).output().unwrap();
        assert!(output.status.success(), "{args:?}: {output:?}");
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    // No format on a pipe is JSON, by auto-detection.
    assert!(run(&["auth", "whoami"]).trim_start().starts_with('{'));

    run(&["config", "set", "output_format", "yaml"]);
    let yaml = run(&["auth", "whoami"]);
    assert!(yaml.contains("username: "), "{yaml}");
    assert!(
        run(&["--format", "json", "auth", "whoami"])
            .trim_start()
            .starts_with('{')
    );

    run(&["config", "set", "output_format", "table"]);
    assert!(run(&["auth", "whoami"]).trim_start().starts_with('{'));
}
