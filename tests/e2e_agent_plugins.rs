//! E2E tests for `ak agent plugins`: publish, install --path, list, update, search and
//! delete against a real Agent Plugins repository.
//!
//! Requires the E2E backend: ./tests/start-backend.sh. A server without Agent Plugins
//! repositories refuses to create one, and each test then skips and says so.

mod common;

use std::path::Path;

use serde_json::Value;

/// Deletes the repository when dropped, so each test cleans up after itself.
struct RepoGuard {
    url: String,
    token: String,
    key: String,
}

impl Drop for RepoGuard {
    fn drop(&mut self) {
        let _ = reqwest::blocking::Client::new()
            .delete(format!("{}/api/v1/repositories/{}", self.url, self.key))
            .bearer_auth(&self.token)
            .send();
    }
}

/// An Agent Plugins repository, or `None` on a server that has no such format.
fn plugin_repo(env: &common::TestEnv, name: &str) -> Option<RepoGuard> {
    let key = format!("e2e-ap-{name}-{}", std::process::id());
    let output = env
        .ak_cmd()
        .args([
            "repo",
            "create",
            &key,
            "--pkg-format",
            "agentplugins",
            "--repo-type",
            "local",
        ])
        .output()
        .expect("run ak repo create");
    if !output.status.success() {
        eprintln!(
            "Skipping: server {} can't create an agentplugins repository: {}",
            common::server_version(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
        return None;
    }
    Some(RepoGuard {
        url: env.url.clone(),
        token: env.token.clone(),
        key,
    })
}

/// A Claude Code layout plugin called `slug` at `version`.
fn claude_plugin(dir: &Path, slug: &str, version: &str) {
    std::fs::create_dir_all(dir.join(".claude-plugin")).unwrap();
    std::fs::create_dir_all(dir.join("skills/hello")).unwrap();
    std::fs::write(
        dir.join(".claude-plugin/plugin.json"),
        format!(
            r#"{{"name":"{slug}","version":"{version}","description":"E2E demo","keywords":["e2e-keyword"]}}"#
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("skills/hello/SKILL.md"),
        "---\nname: hello\ndescription: Say hello\n---\nSay hello.\n",
    )
    .unwrap();
}

fn json(output: &[u8]) -> Value {
    serde_json::from_slice(output)
        .unwrap_or_else(|e| panic!("not JSON ({e}): {}", String::from_utf8_lossy(output)))
}

fn run_json(env: &common::TestEnv, args: &[&str]) -> Value {
    let output = env
        .ak_cmd()
        .args(args)
        .assert()
        .success()
        .get_output()
        .clone();
    json(&output.stdout)
}

#[test]
#[ignore = "requires E2E backend"]
fn publish_install_list_update_and_delete() {
    let env = common::TestEnv::setup();
    let Some(repo) = plugin_repo(&env, "flow") else {
        return;
    };
    let repo = repo.key.clone();
    let work = tempfile::TempDir::new().unwrap();
    let plugin = work.path().join("src");
    let installs = work.path().join("installs");
    claude_plugin(&plugin, "e2e-demo", "1.0.0");
    let plugin = plugin.to_str().unwrap();
    let installs_arg = installs.to_str().unwrap();

    // Publish 1.0.0 from the manifest's version.
    let published = run_json(
        &env,
        &["agent", "plugins", "publish", plugin, "--repo", &repo],
    );
    assert_eq!(published["name"], "e2e-demo", "{published}");
    assert_eq!(published["version"], "1.0.0", "{published}");
    assert_eq!(
        published["sha256"].as_str().unwrap().len(),
        64,
        "{published}"
    );
    assert!(
        published["harnesses"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h == "claude"),
        "{published}"
    );

    // The same version again is refused, and says why.
    let again = env
        .ak_cmd()
        .args(["agent", "plugins", "publish", plugin, "--repo", &repo])
        .assert()
        .failure()
        .get_output()
        .clone();
    let stderr = String::from_utf8_lossy(&again.stderr);
    assert!(stderr.contains("can't be replaced"), "{stderr}");

    // Install into a directory of our own.
    let installed = run_json(
        &env,
        &[
            "agent",
            "plugins",
            "install",
            "e2e-demo",
            "--repo",
            &repo,
            "--harness",
            "claude",
            "--path",
            installs_arg,
        ],
    );
    assert_eq!(installed[0]["version"], "1.0.0", "{installed}");
    let dir = installs.join("e2e-demo");
    assert!(dir.join(".claude-plugin/plugin.json").is_file());
    assert!(dir.join("skills/hello/SKILL.md").is_file());
    let info = json(&std::fs::read(dir.join(".ak/plugin-info.json")).unwrap());
    assert_eq!(info["slug"], "e2e-demo");
    assert_eq!(info["repo"], repo.as_str());
    assert_eq!(info["version"], "1.0.0");
    assert_eq!(info["harness"], "claude");
    assert_eq!(info["sha256"], published["sha256"]);

    // A version that isn't there names the ones that are.
    let missing = env
        .ak_cmd()
        .args([
            "agent",
            "plugins",
            "install",
            "e2e-demo",
            "--repo",
            &repo,
            "--harness",
            "claude",
            "--path",
            installs_arg,
            "--version",
            "9.9.9",
        ])
        .assert()
        .failure()
        .get_output()
        .clone();
    let stderr = String::from_utf8_lossy(&missing.stderr);
    assert!(stderr.contains("It has: 1.0.0"), "{stderr}");

    let listed = run_json(&env, &["agent", "plugins", "list", "--path", installs_arg]);
    assert_eq!(listed.as_array().unwrap().len(), 1, "{listed}");
    assert_eq!(listed[0]["version"], "1.0.0", "{listed}");

    // A newer version, with --version rewriting the manifest in the upload only.
    let newer = run_json(
        &env,
        &[
            "agent",
            "plugins",
            "publish",
            plugin,
            "--repo",
            &repo,
            "--version",
            "1.1.0",
        ],
    );
    assert_eq!(newer["version"], "1.1.0", "{newer}");
    let manifest =
        std::fs::read_to_string(work.path().join("src/.claude-plugin/plugin.json")).unwrap();
    assert!(
        manifest.contains("\"1.0.0\""),
        "the source was changed: {manifest}"
    );

    let checked = run_json(
        &env,
        &[
            "agent",
            "plugins",
            "list",
            "--path",
            installs_arg,
            "--check-updates",
        ],
    );
    assert_eq!(checked[0]["status"], "behind", "{checked}");
    assert_eq!(checked[0]["latest"], "1.1.0", "{checked}");

    let updated = run_json(
        &env,
        &[
            "agent",
            "plugins",
            "update",
            "e2e-demo",
            "--path",
            installs_arg,
        ],
    );
    assert_eq!(updated[0]["status"], "updated", "{updated}");
    let info = json(&std::fs::read(dir.join(".ak/plugin-info.json")).unwrap());
    assert_eq!(info["version"], "1.1.0");

    // Delete 1.1.0: the server's newest is 1.0.0 again, so the install is ahead.
    env.ak_cmd()
        .args([
            "agent",
            "plugins",
            "delete",
            "e2e-demo",
            "--version",
            "1.1.0",
            "--repo",
            &repo,
            "--yes",
        ])
        .assert()
        .success();
    let checked = run_json(
        &env,
        &[
            "agent",
            "plugins",
            "list",
            "--path",
            installs_arg,
            "--check-updates",
        ],
    );
    assert_eq!(checked[0]["latest"], "1.0.0", "{checked}");
    assert_eq!(checked[0]["status"], "ahead", "{checked}");

    run_json(
        &env,
        &[
            "agent",
            "plugins",
            "uninstall",
            "e2e-demo",
            "--path",
            installs_arg,
        ],
    );
    assert!(!dir.exists());
}

#[test]
#[ignore = "requires E2E backend"]
fn search_finds_a_plugin_by_keyword_and_agent() {
    let env = common::TestEnv::setup();
    let Some(repo) = plugin_repo(&env, "search") else {
        return;
    };
    let repo = repo.key.clone();
    let work = tempfile::TempDir::new().unwrap();
    claude_plugin(work.path(), "e2e-found", "0.1.0");
    run_json(
        &env,
        &[
            "agent",
            "plugins",
            "publish",
            work.path().to_str().unwrap(),
            "--repo",
            &repo,
        ],
    );

    let found = run_json(
        &env,
        &["agent", "plugins", "search", "e2e-keyword", "--repo", &repo],
    );
    assert_eq!(found.as_array().unwrap().len(), 1, "{found}");
    assert_eq!(found[0]["name"], "e2e-found", "{found}");
    assert_eq!(found[0]["source"]["source"], "archive", "{found}");

    let claude = run_json(
        &env,
        &[
            "agent",
            "plugins",
            "search",
            "--repo",
            &repo,
            "--harness",
            "claude",
        ],
    );
    assert_eq!(claude.as_array().unwrap().len(), 1, "{claude}");
    let cursor = run_json(
        &env,
        &[
            "agent",
            "plugins",
            "search",
            "--repo",
            &repo,
            "--harness",
            "cursor",
        ],
    );
    assert!(cursor.as_array().unwrap().is_empty(), "{cursor}");
}

#[test]
#[ignore = "requires E2E backend"]
fn dry_run_sends_nothing() {
    let env = common::TestEnv::setup();
    let Some(repo) = plugin_repo(&env, "dry") else {
        return;
    };
    let repo = repo.key.clone();
    let work = tempfile::TempDir::new().unwrap();
    claude_plugin(work.path(), "e2e-dry", "1.0.0");
    let dry = run_json(
        &env,
        &[
            "agent",
            "plugins",
            "publish",
            work.path().to_str().unwrap(),
            "--repo",
            &repo,
            "--dry-run",
        ],
    );
    assert_eq!(dry["entries"][0], ".claude-plugin/plugin.json", "{dry}");

    let found = run_json(&env, &["agent", "plugins", "search", "--repo", &repo]);
    assert!(found.as_array().unwrap().is_empty(), "{found}");
}
