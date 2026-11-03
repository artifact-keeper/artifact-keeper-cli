//! E2E tests for `ak sign` against a real backend.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use common::TestEnv;
use serde_json::Value;
use tempfile::TempDir;

fn unique(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4().simple())
}

fn json_of(env: &TestEnv, args: &[&str]) -> Value {
    let output = env.ak_cmd().args(args).output().unwrap();
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("stdout isn't JSON")
}

fn stderr_of(env: &TestEnv, args: &[&str]) -> String {
    let output = env.ak_cmd().args(args).output().unwrap();
    assert!(!output.status.success(), "{args:?} should fail");
    String::from_utf8_lossy(&output.stderr)
        .split_whitespace()
        .filter(|word| *word != "│")
        .collect::<Vec<_>>()
        .join(" ")
}

fn repo_with_file(env: &TestEnv, repo_type: Option<&str>) -> String {
    let key = unique("sign");
    env.ak_cmd()
        .args(["repo", "create", &key, "--pkg-format", "generic"])
        .args(repo_type.map(|t| ["--repo-type", t]).into_iter().flatten())
        .assert()
        .success();
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("f.bin");
    std::fs::write(&file, unique("content")).unwrap();
    env.ak_cmd()
        .args([
            "artifact",
            "push",
            &key,
            file.to_str().unwrap(),
            "--path",
            "f.bin",
        ])
        .assert()
        .success();
    key
}

fn key_for(env: &TestEnv, repo: &str) -> Value {
    json_of(
        env,
        &[
            "sign",
            "key",
            "create",
            &unique("key"),
            "--type",
            "rsa",
            "--algorithm",
            "rsa2048",
            "--repo",
            repo,
            "--uid-name",
            "Tester",
            "--uid-email",
            "tester@example.test",
        ],
    )
}

fn artifact_id(env: &TestEnv, repo: &str) -> String {
    let artifact = json_of(env, &["artifact", "info", repo, "f.bin"]);
    artifact["id"].as_str().unwrap().to_string()
}

/// What signing is for: a policy that requires a signature stops a promotion until the
/// artifact is signed.
#[test]
#[ignore = "requires E2E backend"]
fn signing_an_artifact_satisfies_a_policy_that_requires_it() {
    let env = TestEnv::setup();
    let staging = repo_with_file(&env, Some("staging"));
    let release = unique("sign-release");
    env.ak_cmd()
        .args(["repo", "create", &release, "--pkg-format", "generic"])
        .assert()
        .success();
    let artifact = format!("{staging}/f.bin");
    let id = artifact_id(&env, &staging);

    let policy = json_of(
        &env,
        &[
            "scan",
            "policy",
            "create",
            &unique("needs-signature"),
            "--max-severity",
            "critical",
            "--repo",
            &staging,
            "--block-on-fail",
            "--require-signature",
        ],
    );
    let policy = policy["id"].as_str().unwrap().to_string();
    let promote = [
        "promotion",
        "promote",
        &id,
        "--from",
        &staging,
        "--to",
        &release,
    ];

    let blocked = env.ak_cmd().args(promote).output().unwrap();
    let blocked_text = format!(
        "{}{}",
        String::from_utf8_lossy(&blocked.stdout),
        String::from_utf8_lossy(&blocked.stderr)
    );
    assert!(
        blocked_text.to_lowercase().contains("signature"),
        "the policy should stop it for its signature: {blocked_text}"
    );

    // With no key there's nothing to sign with, and the server says so.
    assert!(stderr_of(&env, &["sign", "artifact", &artifact, "--yes"]).contains("409"));

    let key = key_for(&env, &staging);
    let key_id = key["id"].as_str().unwrap().to_string();
    assert_eq!(key["is_active"], true);
    assert_eq!(key["uid_name"], "Tester");

    // By the repository's key, not its ID.
    let config = json_of(
        &env,
        &[
            "sign",
            "config",
            "update",
            &staging,
            "--signing-key-id",
            &key_id,
            "--sign-metadata",
        ],
    );
    assert_eq!(config["sign_metadata"], true);
    assert_eq!(config["signing_key_id"], key_id.as_str());

    let signed = json_of(&env, &["sign", "artifact", &artifact, "--yes"]);
    assert_eq!(signed["key_id"], key_id.as_str());
    assert_eq!(signed["artifact_id"], id.as_str());
    assert_eq!(signed["signature_sha256"].as_str().unwrap().len(), 64);

    env.ak_cmd().args(promote).assert().success();
    let in_release = env
        .ak_cmd()
        .args(["artifact", "info", &release, "f.bin"])
        .output()
        .unwrap();
    assert!(
        in_release.status.success(),
        "it should be in the target now: {}",
        String::from_utf8_lossy(&in_release.stderr)
    );

    env.ak_cmd()
        .args(["scan", "policy", "delete", &policy, "--yes"])
        .assert()
        .success();
}

#[test]
#[ignore = "requires E2E backend"]
fn a_config_update_changes_only_what_it_is_given() {
    let env = TestEnv::setup();
    let repo = repo_with_file(&env, None);

    let on = json_of(
        &env,
        &[
            "sign",
            "config",
            "update",
            &repo,
            "--sign-packages",
            "--sign-metadata",
            "true",
        ],
    );
    assert_eq!(on["sign_packages"], true);
    assert_eq!(on["sign_metadata"], true);

    // It could only ever turn these on. Now they turn off, one at a time.
    let off = json_of(
        &env,
        &[
            "sign",
            "config",
            "update",
            &repo,
            "--sign-metadata",
            "false",
        ],
    );
    assert_eq!(off["sign_metadata"], false);
    assert_eq!(off["sign_packages"], true);

    let shown = json_of(&env, &["sign", "config", "show", &repo]);
    assert_eq!(shown["sign_metadata"], false);
    assert_eq!(shown["sign_packages"], true);

    assert!(stderr_of(&env, &["sign", "config", "update", &repo]).contains("Nothing to update"));
}

#[test]
#[ignore = "requires E2E backend"]
fn a_key_is_listed_exported_rotated_revoked_and_deleted() {
    let env = TestEnv::setup();
    let repo = repo_with_file(&env, None);
    let key = key_for(&env, &repo);
    let id = key["id"].as_str().unwrap().to_string();

    let listed = json_of(&env, &["sign", "key", "list", "--repo", &repo]);
    assert_eq!(listed["total"], 1, "{listed}");
    assert_eq!(listed["keys"][0]["id"], id.as_str());
    assert_eq!(
        json_of(&env, &["sign", "key", "show", &id])["id"],
        id.as_str()
    );

    let exported = env
        .ak_cmd()
        .args(["sign", "key", "export", &id])
        .output()
        .unwrap();
    assert!(exported.status.success());
    assert!(String::from_utf8_lossy(&exported.stdout).contains("PUBLIC KEY"));

    let rotated = json_of(&env, &["sign", "key", "rotate", &id, "--yes"]);
    let new_id = rotated["id"].as_str().unwrap().to_string();
    assert_ne!(new_id, id);
    assert_eq!(rotated["is_active"], true);

    let revoked = json_of(&env, &["sign", "key", "revoke", &new_id, "--yes"]);
    assert!(revoked.is_object(), "{revoked}");
    assert_eq!(
        json_of(&env, &["sign", "key", "show", &new_id])["is_active"],
        false
    );

    let deleted = env
        .ak_cmd()
        .args(["sign", "key", "delete", &new_id, "--yes"])
        .output()
        .unwrap();
    assert!(
        deleted.status.success(),
        "{}",
        String::from_utf8_lossy(&deleted.stderr)
    );
    assert!(stderr_of(&env, &["sign", "key", "show", &new_id]).contains("404"));
}
