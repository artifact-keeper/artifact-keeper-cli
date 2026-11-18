//! E2E tests for the 1.12 admin and operations commands: config as code, trash
//! purge, the Debian backfill, quotas, and the 1.12 flags on runtime settings,
//! downloads and CI OIDC. On a 1.11 server each checks the refusal instead. Each
//! test puts back what it changes.
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

fn unique(name: &str) -> String {
    format!("e2e-{name}-{}", std::process::id())
}

/// On a server older than 1.12, `args` fails saying it needs 1.12. True when it
/// did, so the test stops there.
fn refused_before_1_12(env: &common::TestEnv, args: &[&str]) -> bool {
    if !common::server_older_than(1, 12, "this command") {
        return false;
    }
    let output = env.ak_cmd().args(args).output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr)
        .replace('│', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(!output.status.success(), "{args:?}: {stderr}");
    assert!(
        stderr.contains("needs a server on 1.12"),
        "{args:?}: {stderr}"
    );
    true
}

#[test]
#[ignore = "requires E2E backend"]
fn config_export_plan_and_apply_round_trip() {
    let env = common::TestEnv::setup();
    let key = unique("config");
    let dir = tempfile::TempDir::new().unwrap();
    let file = dir.path().join("config.json");
    let file = file.to_str().unwrap();
    if refused_before_1_12(&env, &["admin", "config", "export"]) {
        std::fs::write(file, r#"{"schema_version":1,"repositories":[]}"#).unwrap();
        assert!(refused_before_1_12(
            &env,
            &["admin", "config", "plan", file]
        ));
        assert!(refused_before_1_12(
            &env,
            &["admin", "config", "apply", file, "--yes"]
        ));
        return;
    }
    run(
        &env,
        &[
            "repo",
            "create",
            &key,
            "--pkg-format",
            "generic",
            "--description",
            "before",
        ],
    );

    env.ak_cmd()
        .args([
            "admin",
            "config",
            "export",
            "--repositories",
            &key,
            "-o",
            file,
        ])
        .assert()
        .success();
    let mut document: Value = serde_json::from_slice(&std::fs::read(file).unwrap()).unwrap();
    assert_eq!(
        document["repositories"][0]["key"],
        key.as_str(),
        "{document}"
    );

    let plan = run(&env, &["admin", "config", "plan", file]);
    assert!(
        plan["unchanged"]
            .as_array()
            .unwrap()
            .contains(&Value::from(key.as_str())),
        "{plan}"
    );

    document["repositories"][0]["description"] = Value::from("after");
    std::fs::write(file, document.to_string()).unwrap();
    let plan = run(&env, &["admin", "config", "plan", file]);
    assert_eq!(plan["update"][0]["key"], key.as_str(), "{plan}");

    // Without --yes, nothing is applied.
    let output = env
        .ak_cmd()
        .args(["admin", "config", "apply", file])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let applied = run(&env, &["admin", "config", "apply", file, "--yes"]);
    assert_eq!(applied["applied"], true, "{applied}");
    let shown = run(&env, &["repo", "show", &key]);
    assert_eq!(shown["description"], "after", "{shown}");

    // 1.12.1 doesn't delete yet, and says so.
    let output = env
        .ak_cmd()
        .args(["admin", "config", "plan", file, "--prune"])
        .output()
        .unwrap();
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("prune"),
        "{output:?}"
    );
    let _ = env.api_delete(&format!("/api/v1/repositories/{key}"));
}

#[test]
#[ignore = "requires E2E backend"]
fn a_trashed_artifact_can_be_purged_and_its_path_reused() {
    let env = common::TestEnv::setup();
    if refused_before_1_12(
        &env,
        &[
            "admin",
            "trash",
            "purge",
            "00000000-0000-4000-8000-000000000001",
            "--yes",
        ],
    ) {
        return;
    }
    let key = unique("purge");
    run(&env, &["repo", "create", &key, "--pkg-format", "generic"]);
    let dir = tempfile::TempDir::new().unwrap();
    let file = dir.path().join("a.bin");
    std::fs::write(&file, "purge me").unwrap();
    let push = || {
        env.ak_cmd()
            .args(["artifact", "push", &key, file.to_str().unwrap()])
            .args(["--path", "a.bin"])
            .assert()
            .success();
    };
    push();
    let id = run(&env, &["artifact", "show", &key, "a.bin"])["id"]
        .as_str()
        .unwrap()
        .to_string();
    env.ak_cmd()
        .args(["artifact", "delete", &key, "a.bin", "--yes"])
        .assert()
        .success();

    let purged = run(&env, &["admin", "trash", "purge", &id, "--yes"]);
    assert_eq!(purged["id"], id.as_str(), "{purged}");
    let trash = run(&env, &["admin", "trash", "list", "--repository", &key]);
    assert_eq!(trash["pagination"]["total"], 0, "{trash}");
    push();
    let _ = env.api_delete(&format!("/api/v1/repositories/{key}"));
}

#[test]
#[ignore = "requires E2E backend"]
fn debian_backfill_dry_run() {
    let env = common::TestEnv::setup();
    let key = unique("debian");
    run(&env, &["repo", "create", &key, "--pkg-format", "debian"]);
    if !refused_before_1_12(
        &env,
        &["admin", "repo", "backfill-debian", &key, "--dry-run"],
    ) {
        let result = run(
            &env,
            &["admin", "repo", "backfill-debian", &key, "--dry-run"],
        );
        assert_eq!(result["dry_run"], true, "{result}");
        assert_eq!(result["artifacts_scanned"], 0, "{result}");
    }
    let _ = env.api_delete(&format!("/api/v1/repositories/{key}"));
}

#[test]
#[ignore = "requires E2E backend"]
fn system_quota_reports_storage_and_transfer() {
    let env = common::TestEnv::setup();
    // 1.11.14 has the route, backported, and 1.11.11 doesn't.
    let output = env.ak_cmd().args(["system", "quota"]).output().unwrap();
    if !output.status.success() && common::server_older_than(1, 12, "a quota route") {
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("needs a server on 1.12"),
            "{output:?}"
        );
        return;
    }
    let quota = json_of(output);
    assert!(quota["storage_quota"]["used_bytes"].is_i64(), "{quota}");
    assert!(quota["transfer_quota"]["state"].is_string(), "{quota}");
}

#[test]
#[ignore = "requires E2E backend"]
fn runtime_settings_pause_upstream_jobs_and_hide_nav_items() {
    let env = common::TestEnv::setup();
    let update = ["admin", "settings", "system", "update"];
    if refused_before_1_12(
        &env,
        &[&update[..], &["--upstream-jobs-paused", "true"]].concat(),
    ) {
        assert!(refused_before_1_12(
            &env,
            &[&update[..], &["--hidden-nav-items", "/peers"]].concat(),
        ));
        return;
    }
    let before = run(&env, &["admin", "settings", "system", "show"]);
    let paused = before["upstream_jobs_paused_stored"]
        .as_bool()
        .unwrap_or(false);
    let flipped = (!paused).to_string();
    let after = run(
        &env,
        &[&update[..], &["--upstream-jobs-paused", &flipped]].concat(),
    );
    assert_eq!(after["upstream_jobs_paused_stored"], !paused, "{after}");
    run(
        &env,
        &[
            &update[..],
            &["--upstream-jobs-paused", &paused.to_string()],
        ]
        .concat(),
    );

    let hidden: Vec<String> = before["hidden_nav_items"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let after = run(
        &env,
        &[&update[..], &["--hidden-nav-items", "/peers,/builds"]].concat(),
    );
    assert_eq!(
        after["hidden_nav_items"],
        serde_json::json!(["/builds", "/peers"]),
        "{after}"
    );
    let cleared = run(&env, &[&update[..], &["--no-hidden-nav-items"]].concat());
    assert_eq!(
        cleared["hidden_nav_items"],
        serde_json::json!([]),
        "{cleared}"
    );
    if !hidden.is_empty() {
        run(
            &env,
            &[&update[..], &["--hidden-nav-items", &hidden.join(",")]].concat(),
        );
    }
}

#[test]
#[ignore = "requires E2E backend"]
fn downloads_filter_by_downloader() {
    let env = common::TestEnv::setup();
    let args = ["admin", "downloads", "list", "--downloader", "anonymous"];
    if refused_before_1_12(&env, &args) {
        return;
    }
    let body = run(&env, &args);
    assert!(
        body["downloads"]
            .as_array()
            .unwrap()
            .iter()
            .all(|d| d["user_id"].is_null()),
        "{body}"
    );
}

#[test]
#[ignore = "requires E2E backend"]
fn ci_oidc_provider_takes_a_token_ttl() {
    let env = common::TestEnv::setup();
    let name = unique("ci-oidc-ttl");
    let create = [
        "admin",
        "ci-oidc",
        "create",
        &name,
        "https://ci.example.com",
        "--token-ttl-secs",
        "600",
    ];
    if refused_before_1_12(&env, &create) {
        return;
    }
    let created = run(&env, &create);
    assert_eq!(created["token_ttl_secs"], 600, "{created}");
    let id = created["id"].as_str().unwrap().to_string();
    let updated = run(
        &env,
        &[
            "admin",
            "ci-oidc",
            "update",
            &id,
            "--token-ttl-secs",
            "1200",
        ],
    );
    assert_eq!(updated["token_ttl_secs"], 1200, "{updated}");
    env.ak_cmd()
        .args(["admin", "ci-oidc", "delete", &id, "--yes"])
        .assert()
        .success();
}
