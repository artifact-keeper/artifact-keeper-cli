//! E2E tests for `ak repo` commands.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use predicates::prelude::*;

#[test]
#[ignore = "requires E2E backend"]
fn repo_list_succeeds() {
    let env = common::TestEnv::setup();
    env.ak_cmd().args(["repo", "list"]).assert().success();
}

#[test]
#[ignore = "requires E2E backend"]
fn repo_create_show_delete_lifecycle() {
    let env = common::TestEnv::setup();
    let repo_key = format!("e2e-test-{}", std::process::id());

    // Create
    env.ak_cmd()
        .args([
            "repo",
            "create",
            &repo_key,
            "--pkg-format",
            "generic",
            "--repo-type",
            "local",
        ])
        .assert()
        .success();

    // Show
    env.ak_cmd()
        .args(["repo", "show", &repo_key])
        .assert()
        .success()
        .stdout(predicate::str::contains(&repo_key));

    // Delete
    env.ak_cmd()
        .args(["repo", "delete", &repo_key, "--yes"])
        .assert()
        .success();
}

#[test]
#[ignore = "requires E2E backend"]
fn repo_list_with_format_filter() {
    let env = common::TestEnv::setup();
    env.ak_cmd()
        .args(["repo", "list", "--pkg-format", "generic"])
        .assert()
        .success();
}

#[test]
#[ignore = "requires E2E backend"]
fn repo_update_partial_preserves_other_fields() {
    let env = common::TestEnv::setup();
    let key = format!("e2e-upd-{}", std::process::id());

    env.ak_cmd()
        .args(["repo", "create", &key, "--pkg-format", "npm"])
        .assert()
        .success();

    // Set a description via PATCH.
    env.ak_cmd()
        .args(["repo", "update", &key, "--description", "e2e-desc"])
        .assert()
        .success();

    // Update only the name; description must survive (partial semantics).
    env.ak_cmd()
        .args(["repo", "update", &key, "--name", "Renamed"])
        .assert()
        .success();

    env.ak_cmd()
        .args(["repo", "show", &key])
        .assert()
        .success()
        .stdout(predicate::str::contains("e2e-desc"))
        .stdout(predicate::str::contains("Renamed"));

    env.ak_cmd()
        .args(["repo", "delete", &key, "--yes"])
        .assert()
        .success();
}

#[test]
#[ignore = "requires E2E backend"]
fn repo_cache_ttl_get_set_on_remote() {
    let env = common::TestEnv::setup();
    let key = format!("e2e-cache-{}", std::process::id());

    env.ak_cmd()
        .args([
            "repo",
            "create",
            &key,
            "--pkg-format",
            "npm",
            "--repo-type",
            "remote",
            "--upstream-url",
            "https://registry.npmjs.org",
        ])
        .assert()
        .success();

    env.ak_cmd()
        .args(["repo", "cache", "set-ttl", &key, "3600"])
        .assert()
        .success();

    env.ak_cmd()
        .args(["repo", "cache", "get-ttl", &key])
        .assert()
        .success()
        .stdout(predicate::str::contains("3600"));

    env.ak_cmd()
        .args(["repo", "delete", &key, "--yes"])
        .assert()
        .success();
}

#[test]
#[ignore = "requires E2E backend"]
fn repo_virtual_members_lifecycle() {
    let env = common::TestEnv::setup();
    let pid = std::process::id();
    let member = format!("e2e-mem-{pid}");
    let virt = format!("e2e-virt-{pid}");

    env.ak_cmd()
        .args(["repo", "create", &member, "--pkg-format", "npm"])
        .assert()
        .success();
    env.ak_cmd()
        .args([
            "repo",
            "create",
            &virt,
            "--pkg-format",
            "npm",
            "--repo-type",
            "virtual",
        ])
        .assert()
        .success();

    env.ak_cmd()
        .args(["repo", "members", "add", &virt, &member, "--priority", "10"])
        .assert()
        .success();

    env.ak_cmd()
        .args(["repo", "members", "list", &virt])
        .assert()
        .success()
        .stdout(predicate::str::contains(&member));

    env.ak_cmd()
        .args(["repo", "members", "remove", &virt, &member])
        .assert()
        .success();

    env.ak_cmd()
        .args(["repo", "delete", &virt, "--yes"])
        .assert()
        .success();
    env.ak_cmd()
        .args(["repo", "delete", &member, "--yes"])
        .assert()
        .success();
}

/// A virtual repository stores nothing itself, so its size is its members' total.
#[test]
#[ignore = "requires E2E backend"]
fn repo_virtual_shows_member_storage() {
    if common::server_older_than(1, 11, "member_storage_used_bytes") {
        return;
    }
    let env = common::TestEnv::setup();
    let suffix = std::process::id();
    let member = format!("e2e-virt-member-{suffix}");
    let virt = format!("e2e-virt-{suffix}");

    env.ak_cmd()
        .args(["repo", "create", &member, "--pkg-format", "generic"])
        .assert()
        .success();
    env.ak_cmd()
        .args([
            "repo",
            "create",
            &virt,
            "--pkg-format",
            "generic",
            "--repo-type",
            "virtual",
        ])
        .assert()
        .success();
    env.ak_cmd()
        .args(["repo", "members", "add", &virt, &member])
        .assert()
        .success();

    let file = env.config_dir.path().join("member.bin");
    std::fs::write(&file, vec![7u8; 2048]).unwrap();
    env.ak_cmd()
        .args(["artifact", "push", &member, file.to_str().unwrap()])
        .assert()
        .success();

    let output = env
        .ak_cmd()
        .args(["repo", "show", &virt])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let shown: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(shown["storage_used_bytes"], 0);
    assert_eq!(shown["member_storage_used_bytes"], 2048);

    env.ak_cmd_table()
        .args(["repo", "show", &virt, "--format", "table"])
        .assert()
        .success()
        .stdout(predicate::str::contains("2.0 KB (members)"));

    env.api_delete(&format!("/api/v1/repositories/{virt}"));
    env.api_delete(&format!("/api/v1/repositories/{member}"));
}

/// Parse the JSON a command printed.
fn json_stdout(assert: assert_cmd::assert::Assert) -> serde_json::Value {
    serde_json::from_slice(&assert.get_output().stdout).expect("JSON on stdout")
}

#[test]
#[ignore = "requires E2E backend"]
fn repo_create_proxy_means_remote_and_defaults_the_name() {
    let env = common::TestEnv::setup();
    let key = format!("e2e-proxy-{}", std::process::id());

    let created = json_stdout(
        env.ak_cmd()
            .args([
                "repo",
                "create",
                &key,
                "--pkg-format",
                "generic",
                "--repo-type",
                "proxy",
                "--upstream-url",
                "https://upstream.example.com/x",
            ])
            .assert()
            .success(),
    );
    assert_eq!(created["repo_type"], "remote");
    assert_eq!(created["name"], key.as_str());

    let listed = json_stdout(
        env.ak_cmd()
            .args(["repo", "list", "--repo-type", "proxy", "--search", &key])
            .assert()
            .success(),
    );
    assert_eq!(listed["items"][0]["key"], key.as_str());

    env.ak_cmd()
        .args(["repo", "delete", &key, "--yes", "--wait"])
        .assert()
        .success();
}

#[test]
#[ignore = "requires E2E backend"]
fn repo_create_and_update_set_the_fields_the_server_returns() {
    let env = common::TestEnv::setup();
    let pid = std::process::id();
    let member = format!("e2e-fld-m-{pid}");
    let virt = format!("e2e-fld-v-{pid}");
    let npm = format!("e2e-fld-n-{pid}");

    let created = json_stdout(
        env.ak_cmd()
            .args([
                "repo",
                "create",
                &member,
                "--pkg-format",
                "generic",
                "--name",
                "Named",
                "--versioning-enabled",
                "true",
                "--quota-bytes",
                "1048576",
            ])
            .assert()
            .success(),
    );
    assert_eq!(created["name"], "Named");
    assert_eq!(created["versioning_enabled"], true);
    assert_eq!(created["quota_bytes"], 1048576);

    env.ak_cmd()
        .args([
            "repo",
            "create",
            &virt,
            "--pkg-format",
            "generic",
            "--repo-type",
            "virtual",
            "--member",
            &format!("{member}=7"),
        ])
        .assert()
        .success();
    let members = json_stdout(
        env.ak_cmd()
            .args(["repo", "members", "list", &virt])
            .assert()
            .success(),
    );
    assert_eq!(members["members"][0]["member_repo_key"], member.as_str());
    assert_eq!(members["members"][0]["priority"], 7);

    let created = json_stdout(
        env.ak_cmd()
            .args([
                "repo",
                "create",
                &npm,
                "--pkg-format",
                "npm",
                "--repo-type",
                "remote",
                "--upstream-url",
                "https://upstream.example.com/npm",
                "--npm-allowed-scopes",
                "@a,@b",
                "--npm-allow-unscoped",
                "true",
                "--custom-user-agent",
                "ua/1",
            ])
            .assert()
            .success(),
    );
    assert_eq!(
        created["npm_allowed_scopes"],
        serde_json::json!(["@a", "@b"])
    );
    assert_eq!(created["custom_user_agent"], "ua/1");

    let updated = json_stdout(
        env.ak_cmd()
            .args([
                "repo",
                "update",
                &npm,
                "--npm-allow-unscoped",
                "false",
                "--custom-user-agent",
                "ua/2",
                "--curation-enabled",
                "true",
                "--curation-default-action",
                "review",
            ])
            .assert()
            .success(),
    );
    assert_eq!(updated["npm_allow_unscoped"], false);
    assert_eq!(updated["custom_user_agent"], "ua/2");
    assert_eq!(updated["curation_enabled"], true);
    assert_eq!(updated["curation_default_action"], "review");

    for key in [&virt, &npm, &member] {
        env.ak_cmd()
            .args(["repo", "delete", key, "--yes", "--wait"])
            .assert()
            .success();
    }
}

#[test]
#[ignore = "requires E2E backend"]
fn repo_update_assigns_and_clears_a_project() {
    let env = common::TestEnv::setup();
    let key = format!("e2e-proj-{}", std::process::id());
    let project: serde_json::Value = env
        .api_post(
            "/api/v1/projects",
            &serde_json::json!({"key": key, "name": key}),
        )
        .json()
        .expect("project JSON");
    let project_id = project["id"].as_str().expect("project id");

    env.ak_cmd()
        .args(["repo", "create", &key, "--pkg-format", "generic"])
        .assert()
        .success();

    let assigned = json_stdout(
        env.ak_cmd()
            .args(["repo", "update", &key, "--project-id", project_id])
            .assert()
            .success(),
    );
    assert_eq!(assigned["project_id"], project_id);

    if common::server_older_than(1, 11, "clearing a project by sending null") {
        // It would answer 200 and keep the project, so the command refuses.
        env.ak_cmd()
            .args(["repo", "update", &key, "--clear-project"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("needs a server on 1.11"));
        let kept = json_stdout(env.ak_cmd().args(["repo", "show", &key]).assert().success());
        assert_eq!(kept["project_id"], project_id);
    } else {
        let cleared = json_stdout(
            env.ak_cmd()
                .args(["repo", "update", &key, "--clear-project"])
                .assert()
                .success(),
        );
        assert!(cleared["project_id"].is_null(), "{cleared}");
    }

    env.ak_cmd()
        .args(["repo", "delete", &key, "--yes", "--wait"])
        .assert()
        .success();
}

/// On 1.11 the delete answers 200 and on 1.12 it answers 202 with a job, so this
/// holds on both: once `--wait` returns, the repository is gone.
#[test]
#[ignore = "requires E2E backend"]
fn repo_delete_wait_returns_once_the_repository_is_gone() {
    let env = common::TestEnv::setup();
    let key = format!("e2e-delw-{}", std::process::id());
    env.ak_cmd()
        .args(["repo", "create", &key, "--pkg-format", "generic"])
        .assert()
        .success();
    env.ak_cmd()
        .args(["repo", "delete", &key, "--yes", "--wait"])
        .assert()
        .success();
    env.ak_cmd().args(["repo", "show", &key]).assert().failure();
}

#[test]
#[ignore = "requires E2E backend"]
fn repo_capabilities_reports_rpm_depth() {
    if common::server_older_than(1, 11, "repository capabilities") {
        let env = common::TestEnv::setup();
        env.ak_cmd()
            .args(["repo", "capabilities"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("needs a server on 1.11"));
        return;
    }
    let env = common::TestEnv::setup();
    let caps = json_stdout(
        env.ak_cmd()
            .args(["repo", "capabilities"])
            .assert()
            .success(),
    );
    assert!(
        caps["rpm_repodata_depth"]["supported"].is_boolean(),
        "{caps}"
    );
}

#[test]
#[ignore = "requires E2E backend"]
fn repo_allowlist_set_get_delete() {
    if common::server_older_than(1, 11, "a conda allowlist") {
        let env = common::TestEnv::setup();
        env.ak_cmd()
            .args(["repo", "allowlist", "get", "any"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("needs a server on 1.11"));
        return;
    }
    let env = common::TestEnv::setup();
    let pid = std::process::id();
    let member = format!("e2e-al-m-{pid}");
    let virt = format!("e2e-al-v-{pid}");
    env.ak_cmd()
        .args(["repo", "create", &member, "--pkg-format", "conda"])
        .assert()
        .success();
    env.ak_cmd()
        .args([
            "repo",
            "create",
            &virt,
            "--pkg-format",
            "conda",
            "--repo-type",
            "virtual",
            "--member",
            &member,
        ])
        .assert()
        .success();

    let set = json_stdout(
        env.ak_cmd()
            .args([
                "repo",
                "allowlist",
                "set",
                &virt,
                "--package",
                "numpy=>=2,<3",
                "--entries",
                r#"[{"name":"pandas","subdirs":["noarch"]}]"#,
                "--scope",
                "remote_only",
            ])
            .assert()
            .success(),
    );
    assert_eq!(set["enabled"], true);
    assert_eq!(set["scope"], "remote_only");
    assert_eq!(set["entry_count"], 2);

    let got = json_stdout(
        env.ak_cmd()
            .args(["repo", "allowlist", "get", &virt])
            .assert()
            .success(),
    );
    assert_eq!(got["entries"][1]["version"], ">=2,<3");
    assert_eq!(got["entries"][0]["subdirs"][0], "noarch");

    let off = json_stdout(
        env.ak_cmd()
            .args(["repo", "allowlist", "set", &virt, "--enabled", "false"])
            .assert()
            .success(),
    );
    assert_eq!(off["enabled"], false);

    let removed = json_stdout(
        env.ak_cmd()
            .args(["repo", "allowlist", "delete", &virt, "--yes"])
            .assert()
            .success(),
    );
    assert_eq!(removed["entry_count"], 0);

    for key in [&virt, &member] {
        env.ak_cmd()
            .args(["repo", "delete", key, "--yes", "--wait"])
            .assert()
            .success();
    }
}

#[test]
#[ignore = "requires E2E backend"]
fn repo_remote_settings_round_trip() {
    let env = common::TestEnv::setup();
    let key = format!("e2e-rem-{}", std::process::id());
    env.ak_cmd()
        .args([
            "repo",
            "create",
            &key,
            "--pkg-format",
            "npm",
            "--repo-type",
            "remote",
            "--upstream-url",
            "https://upstream.example.com/npm",
        ])
        .assert()
        .success();

    // Upstream filter
    if common::server_older_than(1, 11, "upstream filters") {
        env.ak_cmd()
            .args(["repo", "upstream-filter", "get", &key])
            .assert()
            .failure()
            .stderr(predicate::str::contains("needs a server on 1.11"));
    } else {
        let set = json_stdout(
            env.ak_cmd()
                .args([
                    "repo",
                    "upstream-filter",
                    "set",
                    &key,
                    "--include",
                    "^a/",
                    "--exclude",
                    r"x{1,2}\.tgz$",
                ])
                .assert()
                .success(),
        );
        assert_eq!(set["active"], true);
        assert_eq!(set["exclude_patterns"][0], r"x{1,2}\.tgz$");
        let got = json_stdout(
            env.ak_cmd()
                .args(["repo", "upstream-filter", "get", &key])
                .assert()
                .success(),
        );
        assert_eq!(got["include_patterns"][0], "^a/");
        let removed = json_stdout(
            env.ak_cmd()
                .args(["repo", "upstream-filter", "delete", &key, "--yes"])
                .assert()
                .success(),
        );
        assert_eq!(removed["active"], false);
    }

    // Egress proxy: the server masks credentials and the CLI shows what it masks.
    let set = json_stdout(
        env.ak_cmd()
            .args([
                "repo",
                "egress-proxy",
                "set",
                &key,
                "--mode",
                "explicit",
                "--proxy-url",
                "https://u:p@proxy.example.com:8443",
                "--no-proxy",
                "a.example.com",
            ])
            .assert()
            .success(),
    );
    assert_eq!(set["proxy_credentials_configured"], true);
    assert!(!set["proxy_url"].as_str().unwrap().contains("u:p"), "{set}");
    let got = json_stdout(
        env.ak_cmd()
            .args(["repo", "egress-proxy", "get", &key])
            .assert()
            .success(),
    );
    assert_eq!(got["mode"], "explicit");
    assert_eq!(got["no_proxy"], "a.example.com");

    // npm scope policy
    let set = json_stdout(
        env.ak_cmd()
            .args([
                "repo",
                "npm-scope-policy",
                "set",
                &key,
                "--allowed-scopes",
                "@a,@b",
                "--allow-unscoped",
                "true",
            ])
            .assert()
            .success(),
    );
    assert_eq!(set["allowed_scopes"], serde_json::json!(["@a", "@b"]));
    assert_eq!(set["allow_unscoped"], true);
    let empty = json_stdout(
        env.ak_cmd()
            .args([
                "repo",
                "npm-scope-policy",
                "set",
                &key,
                "--allowed-scopes",
                "",
            ])
            .assert()
            .success(),
    );
    assert_eq!(empty["allowed_scopes"], serde_json::json!([]));
    assert_eq!(empty["active"], true);
    let got = json_stdout(
        env.ak_cmd()
            .args(["repo", "npm-scope-policy", "get", &key])
            .assert()
            .success(),
    );
    assert_eq!(got["active"], true);

    // Upstream auth: the server's own answer comes through.
    let auth = json_stdout(
        env.ak_cmd()
            .args(["repo", "upstream-auth", &key, "--type", "none"])
            .assert()
            .success(),
    );
    assert!(auth["message"].is_string(), "{auth}");

    env.ak_cmd()
        .args(["repo", "delete", &key, "--yes", "--wait"])
        .assert()
        .success();
}

#[test]
#[ignore = "requires E2E backend"]
fn repo_storage_and_gc() {
    let env = common::TestEnv::setup();
    let key = format!("e2e-sto-{}", std::process::id());
    env.ak_cmd()
        .args(["repo", "create", &key, "--pkg-format", "generic"])
        .assert()
        .success();

    let stats = json_stdout(
        env.ak_cmd()
            .args(["repo", "storage", &key])
            .assert()
            .success(),
    );
    assert_eq!(stats["repository_key"], key.as_str());
    assert!(stats["blob_count"].is_number(), "{stats}");

    let tree = json_stdout(
        env.ak_cmd()
            .args([
                "repo", "storage", &key, "--tree", "--prefix", "dir", "--depth", "2", "--limit",
                "5",
            ])
            .assert()
            .success(),
    );
    assert_eq!(tree["node"]["prefix"], "dir");

    let gc = json_stdout(
        env.ak_cmd()
            .args(["repo", "storage-gc", &key, "--dry-run"])
            .assert()
            .success(),
    );
    assert_eq!(gc["dry_run"], true);
    let gc = json_stdout(
        env.ak_cmd()
            .args(["repo", "storage-gc", &key, "--yes"])
            .assert()
            .success(),
    );
    assert_eq!(gc["dry_run"], false);

    env.ak_cmd()
        .args(["repo", "delete", &key, "--yes", "--wait"])
        .assert()
        .success();
}

/// A server before 1.11 answers 200 to these and drops them, so the command has to
/// refuse rather than report a change that never happened.
#[test]
#[ignore = "requires E2E backend"]
fn repo_flags_a_server_would_drop_are_refused_there() {
    if !common::server_older_than(1, 11, "--visibility") {
        return;
    }
    let env = common::TestEnv::setup();
    let key = format!("e2e-old-{}", std::process::id());
    let refused = |args: &[&str]| {
        env.ak_cmd()
            .args(args)
            .assert()
            .failure()
            .stderr(predicate::str::contains("needs a server on 1.11"));
    };
    refused(&[
        "repo",
        "create",
        &key,
        "--pkg-format",
        "generic",
        "--visibility",
        "internal",
    ]);
    env.ak_cmd().args(["repo", "show", &key]).assert().failure();

    env.ak_cmd()
        .args(["repo", "create", &key, "--pkg-format", "generic"])
        .assert()
        .success();
    refused(&["repo", "update", &key, "--visibility", "internal"]);
    refused(&[
        "repo",
        "update",
        &key,
        "--upstream-url",
        "https://u.example.com",
    ]);
    env.ak_cmd()
        .args(["repo", "delete", &key, "--yes"])
        .assert()
        .success();
}
