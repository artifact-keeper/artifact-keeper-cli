//! E2E tests for the admin settings and storage commands. They change server-wide
//! settings, so point them only at a throwaway backend. Each test puts back what
//! it changes.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use serde_json::Value;

fn json_of(output: std::process::Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("JSON output")
}

fn run(env: &common::TestEnv, args: &[&str]) -> Value {
    json_of(env.ak_cmd().args(args).output().unwrap())
}

/// A command that needs a newer server says so, rather than repeating the
/// server's "Repository not found".
fn says_it_needs_1_11(env: &common::TestEnv, args: &[&str]) {
    let output = env.ak_cmd().args(args).output().unwrap();
    assert!(!output.status.success(), "{args:?}");
    let stderr = String::from_utf8_lossy(&output.stderr)
        .replace('│', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(stderr.contains("1.11 or newer"), "{args:?}: {stderr}");
}

fn unique(name: &str) -> String {
    format!("e2e-{name}-{}", std::process::id())
}

#[test]
#[ignore = "requires E2E backend"]
fn guest_access_can_be_changed_and_put_back() {
    let env = common::TestEnv::setup();
    if common::server_older_than(1, 11, "admin settings system") {
        says_it_needs_1_11(&env, &["admin", "settings", "system", "show"]);
        return;
    }
    let before = run(&env, &["admin", "settings", "system", "show"]);
    let original = before["guest_access_enabled"].as_bool().unwrap();
    let flipped = (!original).to_string();

    let after = run(
        &env,
        &[
            "admin",
            "settings",
            "system",
            "update",
            "--guest-access",
            &flipped,
        ],
    );
    assert_eq!(after["guest_access_enabled"], !original, "{after}");
    run(
        &env,
        &[
            "admin",
            "settings",
            "system",
            "update",
            "--guest-access",
            &original.to_string(),
        ],
    );
}

#[test]
#[ignore = "requires E2E backend"]
fn token_policy_set_keeps_what_it_does_not_name() {
    let env = common::TestEnv::setup();
    let before = run(&env, &["admin", "settings", "token-policy", "show"]);
    let policy = &before["policy"];
    let max_days = policy["max_days"].as_i64().unwrap();
    let changed = (max_days + 1).to_string();

    let after = run(
        &env,
        &[
            "admin",
            "settings",
            "token-policy",
            "set",
            "--max-days",
            &changed,
        ],
    );
    assert_eq!(after["policy"]["max_days"], max_days + 1, "{after}");
    assert_eq!(after["policy"]["min_days"], policy["min_days"], "{after}");
    assert_eq!(
        after["policy"]["require_expiration"], policy["require_expiration"],
        "{after}"
    );
    run(
        &env,
        &[
            "admin",
            "settings",
            "token-policy",
            "set",
            "--max-days",
            &max_days.to_string(),
        ],
    );
}

#[test]
#[ignore = "requires E2E backend"]
fn totp_policy_refuses_an_admin_with_no_totp_and_shows_why() {
    let env = common::TestEnv::setup();
    let before = run(&env, &["admin", "settings", "totp-policy", "show"]);
    assert_eq!(before["caller_totp_enabled"], false, "{before}");

    let output = env
        .ak_cmd()
        .args(["admin", "settings", "totp-policy", "set"])
        .args(["required-for-all", "--yes"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("409"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let after = run(&env, &["admin", "settings", "totp-policy", "show"]);
    assert_eq!(after["policy"], before["policy"]);
}

#[test]
#[ignore = "requires E2E backend"]
fn a_deleted_artifact_can_be_restored_from_the_trash() {
    let env = common::TestEnv::setup();
    if common::server_older_than(1, 11, "admin trash") {
        says_it_needs_1_11(&env, &["admin", "trash", "list"]);
        return;
    }
    let key = unique("trash");
    run(&env, &["repo", "create", &key, "--pkg-format", "generic"]);
    let dir = tempfile::TempDir::new().unwrap();
    let file = dir.path().join("a.bin");
    std::fs::write(&file, "restore me").unwrap();
    env.ak_cmd()
        .args(["artifact", "push", &key, file.to_str().unwrap()])
        .args(["--path", "a.bin"])
        .assert()
        .success();
    let id = run(&env, &["artifact", "info", &key, "a.bin"])["id"]
        .as_str()
        .unwrap()
        .to_string();
    env.ak_cmd()
        .args(["artifact", "delete", &key, "a.bin", "--yes"])
        .assert()
        .success();

    let trash = run(&env, &["admin", "trash", "list", "--repository", &key]);
    assert_eq!(trash["items"][0]["id"], id.as_str(), "{trash}");

    let restored = run(&env, &["admin", "trash", "restore", &id, "--yes"]);
    assert_eq!(restored["id"], id.as_str(), "{restored}");
    let out = dir.path().join("out.bin");
    env.ak_cmd()
        .args(["artifact", "pull", &key, "a.bin", "-o"])
        .arg(&out)
        .assert()
        .success();
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "restore me");
    let trash = run(&env, &["admin", "trash", "list", "--repository", &key]);
    assert_eq!(trash["pagination"]["total"], 0, "{trash}");
}

#[test]
#[ignore = "requires E2E backend"]
fn storage_scrub_of_an_intact_repository() {
    let env = common::TestEnv::setup();
    if common::server_older_than(1, 11, "admin storage-scrub") {
        says_it_needs_1_11(&env, &["admin", "storage-scrub", "findings"]);
        says_it_needs_1_11(&env, &["admin", "storage-scrub", "run", "--yes"]);
        return;
    }
    let key = unique("scrub");
    run(&env, &["repo", "create", &key, "--pkg-format", "generic"]);
    let dir = tempfile::TempDir::new().unwrap();
    let file = dir.path().join("a.bin");
    std::fs::write(&file, "intact").unwrap();
    env.ak_cmd()
        .args(["artifact", "push", &key, file.to_str().unwrap()])
        .args(["--path", "a.bin"])
        .assert()
        .success();

    let result = run(
        &env,
        &[
            "admin",
            "storage-scrub",
            "run",
            "--yes",
            "--repository",
            &key,
        ],
    );
    assert_eq!(result["objects_checked"], 1, "{result}");
    assert_eq!(result["intact"], 1, "{result}");
    run(
        &env,
        &["admin", "storage-scrub", "findings", "--limit", "5"],
    );
}

#[test]
#[ignore = "requires E2E backend"]
fn reindex_storage_dry_run_and_its_refusal_for_other_formats() {
    let env = common::TestEnv::setup();
    if common::server_older_than(1, 11, "admin reindex-storage") {
        let key = unique("reindex-old");
        run(&env, &["repo", "create", &key, "--pkg-format", "maven"]);
        says_it_needs_1_11(&env, &["admin", "reindex-storage", &key, "--dry-run"]);
        return;
    }
    let maven = unique("reindex-mvn");
    run(&env, &["repo", "create", &maven, "--pkg-format", "maven"]);
    let result = run(&env, &["admin", "reindex-storage", &maven, "--dry-run"]);
    assert_eq!(result["dry_run"], true, "{result}");

    let generic = unique("reindex-gen");
    run(
        &env,
        &["repo", "create", &generic, "--pkg-format", "generic"],
    );
    let output = env
        .ak_cmd()
        .args(["admin", "reindex-storage", &generic, "--dry-run"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("422"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "requires E2E backend"]
fn ledger_and_package_backfills_report() {
    let env = common::TestEnv::setup();
    let ledger = run(&env, &["admin", "storage", "ledger-backfill"]);
    assert!(ledger["repositories_checked"].is_i64(), "{ledger}");
    let packages = run(&env, &["packages", "backfill"]);
    assert!(packages["artifacts_scanned"].is_i64(), "{packages}");
}

#[test]
#[ignore = "requires E2E backend"]
fn a_plugin_manifest_installs_and_the_plugin_list_still_reads() {
    let env = common::TestEnv::setup();
    let name = unique("plugin");
    let dir = tempfile::TempDir::new().unwrap();
    let file = dir.path().join("manifest.json");
    // No config schema: the server stores null for it.
    std::fs::write(
        &file,
        serde_json::json!({
            "name": name, "version": "1.0.0", "display_name": "E2E",
            "plugin_type": "format_handler"
        })
        .to_string(),
    )
    .unwrap();

    let plugin = run(
        &env,
        &["admin", "plugins", "install", file.to_str().unwrap()],
    );
    assert_eq!(plugin["name"], name.as_str(), "{plugin}");
    let id = plugin["id"].as_str().unwrap();
    let listed = env
        .ak_cmd()
        .args(["admin", "plugins", "list"])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    assert!(String::from_utf8_lossy(&listed.stdout).contains(&name));
    env.ak_cmd()
        .args(["admin", "plugins", "remove", id, "--yes"])
        .assert()
        .success();
}

#[test]
#[ignore = "requires E2E backend"]
fn diag_says_a_plain_server_has_no_profiling() {
    let env = common::TestEnv::setup();
    let output = env
        .ak_cmd()
        .args(["admin", "diag", "memory"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr).replace('│', " ");
    let flat = stderr.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(flat.contains("profiling"), "{flat}");
}
