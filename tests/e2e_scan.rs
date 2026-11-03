//! E2E tests for `ak scan` against a real backend.
//!
//! Requires the E2E backend: ./tests/start-backend.sh
//!
//! Whether the backend can finish a vulnerability scan depends on its setup, so
//! findings come from `scan finding ingest`, and what a command prints for a rescan's
//! findings is covered in `tests/scan_contract.rs`.

mod common;

use common::TestEnv;
use serde_json::{Value, json};
use tempfile::TempDir;

/// How the backend reaches itself as an upstream. It refuses `backend` and loopback,
/// so the E2E backend has this network alias and allows private addresses.
const UPSTREAM: &str = "http://ak-upstream:8080/api/v1/repositories";

fn unique(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4().simple())
}

fn stdout_json(output: std::process::Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("stdout isn't JSON")
}

fn json_of(env: &TestEnv, args: &[&str]) -> Value {
    stdout_json(env.ak_cmd().args(args).output().unwrap())
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

/// A public generic repository holding one file, which a remote can use as upstream.
fn hosted_repo(env: &TestEnv, path: &str) -> String {
    let key = unique("scan");
    env.ak_cmd()
        .args([
            "repo",
            "create",
            &key,
            "--pkg-format",
            "generic",
            "--public",
        ])
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
            path,
        ])
        .assert()
        .success();
    key
}

#[test]
#[ignore = "requires E2E backend"]
fn scan_list() {
    let env = TestEnv::setup();
    let body = json_of(&env, &["scan", "list", "--page", "1", "--per-page", "1"]);
    assert!(body["items"].is_array(), "{body}");
    assert!(body["total"].is_number(), "{body}");
}

#[test]
#[ignore = "requires E2E backend"]
fn dashboard_scores_and_configs_print_the_body() {
    let env = TestEnv::setup();
    assert!(json_of(&env, &["scan", "dashboard"])["total_scans"].is_number());
    assert!(json_of(&env, &["scan", "scores"]).is_array());
    assert!(json_of(&env, &["scan", "config", "list"]).is_array());
    assert!(json_of(&env, &["scan", "policy", "list"]).is_array());
}

#[test]
#[ignore = "requires E2E backend"]
fn an_external_finding_goes_from_ingest_to_acknowledged() {
    let env = TestEnv::setup();
    let repo = hosted_repo(&env, "d/f.bin");
    let artifact = format!("{repo}/d/f.bin");
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("findings.json");
    std::fs::write(
        &file,
        json!([{
            "title": "A problem",
            "severity": "medium",
            "cve_id": "CVE-2026-0001",
            "affected_component": "lib",
            "affected_version": "1",
            "fixed_version": "2",
            "description": "d",
            "source": "vendor",
            "source_url": "https://example.test/1"
        }])
        .to_string(),
    )
    .unwrap();

    let ingested = json_of(
        &env,
        &[
            "scan",
            "finding",
            "ingest",
            file.to_str().unwrap(),
            "--artifact",
            &artifact,
            "--scanner",
            "acme",
            "--scanner-version",
            "9",
            "--yes",
        ],
    );
    assert_eq!(ingested["findings_ingested"], 1);
    let scan = ingested["scan_id"].as_str().unwrap().to_string();

    // By key and by the artifact's path, through both listing routes.
    let by_repo = json_of(
        &env,
        &["scan", "list", "--repo", &repo, "--scan-type", "external"],
    );
    assert!(
        by_repo["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["id"] == scan.as_str()),
        "{by_repo}"
    );
    assert_eq!(by_repo["items"][0]["scanner_version"], "9");
    let by_artifact = json_of(
        &env,
        &[
            "scan",
            "list",
            "--artifact",
            &artifact,
            "--status",
            "completed",
        ],
    );
    assert!(by_artifact["total"].as_i64().unwrap() >= 1, "{by_artifact}");
    let of_artifact = json_of(
        &env,
        &["scan", "artifact", &artifact, "--status", "completed"],
    );
    assert_eq!(of_artifact["total"], by_artifact["total"]);

    let findings = json_of(
        &env,
        &[
            "scan",
            "show",
            &scan,
            "--source",
            "vendor",
            "--cve",
            "CVE-2026-0001",
        ],
    );
    assert_eq!(findings["total"], 1, "{findings}");
    assert_eq!(findings["items"][0]["fixed_version"], "2");
    let finding = findings["items"][0]["id"].as_str().unwrap().to_string();
    let no_match = json_of(&env, &["scan", "show", &scan, "--cve", "CVE-1999-0001"]);
    assert_eq!(no_match["items"], json!([]));
    let exact = json_of(&env, &["scan", "show", &scan, "--exact-severity", "low"]);
    assert_eq!(exact["items"], json!([]));

    if common::server_older_than(1, 11, "finding_class") {
        assert!(
            stderr_of(
                &env,
                &["scan", "show", &scan, "--finding-class", "vulnerability"]
            )
            .contains("1.11"),
        );
    } else {
        let classed = json_of(
            &env,
            &["scan", "show", &scan, "--finding-class", "vulnerability"],
        );
        assert_eq!(classed["total"], 1, "{classed}");
    }

    let acknowledged = json_of(
        &env,
        &[
            "scan", "finding", "ack", &finding, "--reason", "accepted", "--yes",
        ],
    );
    assert_eq!(acknowledged["is_acknowledged"], true);
    assert_eq!(acknowledged["acknowledged_reason"], "accepted");
    let revoked = json_of(&env, &["scan", "finding", "revoke", &finding, "--yes"]);
    assert_eq!(revoked["is_acknowledged"], false);
}

#[test]
#[ignore = "requires E2E backend"]
fn a_scan_runs_on_an_artifact_or_a_whole_repository() {
    let env = TestEnv::setup();
    let repo = hosted_repo(&env, "f.bin");
    let one = json_of(&env, &["scan", "run", &repo, "f.bin", "--bypass-dedup"]);
    assert_eq!(one["artifacts_queued"], 1, "{one}");
    let all = json_of(&env, &["scan", "run", &repo]);
    assert_eq!(all["artifacts_queued"], 1, "{all}");
    assert!(stderr_of(&env, &["scan", "run", &repo, "missing.bin"]).contains("missing.bin"));
}

#[test]
#[ignore = "requires E2E backend"]
fn policy_flags_reach_the_server_and_an_update_keeps_the_rest() {
    let env = TestEnv::setup();
    // Bound to a repository of its own: a global policy would block other tests.
    let repo = hosted_repo(&env, "f.bin");
    let name = unique("policy");
    let policy = json_of(
        &env,
        &[
            "scan",
            "policy",
            "create",
            &name,
            "--max-severity",
            "high",
            "--repo",
            &repo,
            "--block-on-fail",
            "--require-signature",
            "--min-staging-hours",
            "5",
            "--max-artifact-age-days",
            "9",
        ],
    );
    let id = policy["id"].as_str().unwrap().to_string();
    assert_eq!(policy["require_signature"], true);
    assert_eq!(policy["min_staging_hours"], 5);
    assert_eq!(policy["max_artifact_age_days"], 9);
    assert_eq!(policy["block_on_fail"], true);

    let updated = json_of(
        &env,
        &["scan", "policy", "update", &id, "--min-staging-hours", "6"],
    );
    assert_eq!(updated["min_staging_hours"], 6);
    assert_eq!(updated["max_artifact_age_days"], 9);
    assert_eq!(updated["require_signature"], true);
    assert_eq!(updated["block_on_fail"], true);
    assert_eq!(updated["name"], name.as_str());

    let off = json_of(
        &env,
        &[
            "scan",
            "policy",
            "update",
            &id,
            "--require-signature",
            "false",
            "--enabled",
            "false",
        ],
    );
    assert_eq!(off["require_signature"], false);
    assert_eq!(off["is_enabled"], false);

    let predicates =
        r#"{"conda":{"denied_licenses":["gpl"]},"origin":{"allowed_kinds":["hosted"]}}"#;
    if common::server_older_than(1, 11, "policy predicates") {
        // It would answer 200 and drop them.
        let refused = stderr_of(
            &env,
            &["scan", "policy", "update", &id, "--predicates", predicates],
        );
        assert!(refused.contains("1.11"), "{refused}");
    } else {
        let with = json_of(
            &env,
            &["scan", "policy", "update", &id, "--predicates", predicates],
        );
        assert_eq!(
            with["predicates"]["conda"]["denied_licenses"],
            json!(["gpl"])
        );
        assert_eq!(
            with["predicates"]["origin"]["allowed_kinds"],
            json!(["hosted"])
        );

        let kept = json_of(
            &env,
            &[
                "scan",
                "policy",
                "update",
                &id,
                "--name",
                &unique("renamed"),
            ],
        );
        assert_eq!(
            kept["predicates"]["conda"]["denied_licenses"],
            json!(["gpl"])
        );

        let name = unique("policy");
        let created = json_of(
            &env,
            &[
                "scan",
                "policy",
                "create",
                &name,
                "--max-severity",
                "high",
                "--repo",
                &repo,
                "--predicates",
                predicates,
            ],
        );
        assert_eq!(
            created["predicates"]["conda"]["denied_licenses"],
            json!(["gpl"])
        );
        env.ak_cmd()
            .args([
                "scan",
                "policy",
                "delete",
                created["id"].as_str().unwrap(),
                "--yes",
            ])
            .assert()
            .success();
    }

    assert_eq!(
        json_of(&env, &["scan", "policy", "show", &id])["id"],
        id.as_str()
    );
    env.ak_cmd()
        .args(["scan", "policy", "delete", &id, "--yes"])
        .assert()
        .success();
}

#[test]
#[ignore = "requires E2E backend"]
fn security_update_changes_only_what_it_is_given() {
    let env = TestEnv::setup();
    let repo = hosted_repo(&env, "f.bin");

    let set = json_of(
        &env,
        &[
            "scan",
            "security",
            "update",
            &repo,
            "--scanning-enabled",
            "--block-on-violation",
            "true",
            "--severity-threshold",
            "critical",
        ],
    );
    assert_eq!(set["scan_enabled"], true);
    assert_eq!(set["block_on_policy_violation"], true);
    assert_eq!(set["severity_threshold"], "critical");

    // This used to turn scanning and blocking off and put the threshold back to HIGH.
    let changed = json_of(
        &env,
        &[
            "scan",
            "security",
            "update",
            &repo,
            "--scan-on-upload",
            "true",
        ],
    );
    assert_eq!(changed["scan_on_upload"], true);
    assert_eq!(changed["scan_enabled"], true);
    assert_eq!(changed["block_on_policy_violation"], true);
    assert_eq!(changed["severity_threshold"], "critical");

    let off = json_of(
        &env,
        &[
            "scan",
            "security",
            "update",
            &repo,
            "--scanning-enabled",
            "false",
        ],
    );
    assert_eq!(off["scan_enabled"], false);

    let shown = json_of(&env, &["scan", "security", "show", &repo]);
    assert_eq!(shown["config"]["scan_enabled"], false);
    assert_eq!(shown["config"]["scan_on_upload"], true);

    assert!(stderr_of(&env, &["scan", "security", "update", &repo]).contains("Nothing to update"));

    if common::server_older_than(1, 11, "proxy_scan_action") {
        assert!(
            stderr_of(
                &env,
                &[
                    "scan",
                    "security",
                    "update",
                    &repo,
                    "--proxy-scan-action",
                    "record_only"
                ]
            )
            .contains("1.11")
        );
    } else {
        let action = json_of(
            &env,
            &[
                "scan",
                "security",
                "update",
                &repo,
                "--proxy-scan-action",
                "record_only",
            ],
        );
        assert_eq!(action["proxy_scan_action"], "record_only");
    }
}

#[test]
#[ignore = "requires E2E backend"]
fn a_cached_path_is_listed_and_a_rescan_reports_the_server_answer() {
    let env = TestEnv::setup();
    let upstream = hosted_repo(&env, "d/f.bin");
    let remote = unique("scan-remote");
    env.ak_cmd()
        .args([
            "repo",
            "create",
            &remote,
            "--pkg-format",
            "generic",
            "--repo-type",
            "remote",
            "--upstream-url",
            &format!("{UPSTREAM}/{upstream}/download"),
        ])
        .assert()
        .success();

    let empty = json_of(&env, &["scan", "proxy", "list", &remote]);
    assert_eq!(empty["items"], json!([]));

    env.ak_cmd()
        .args([
            "api",
            "GET",
            &format!("/api/v1/repositories/{remote}/download/d/f.bin"),
        ])
        .assert()
        .success();

    let listed = json_of(
        &env,
        &[
            "scan",
            "proxy",
            "list",
            &remote,
            "--page",
            "1",
            "--per-page",
            "5",
        ],
    );
    assert_eq!(listed["items"][0]["path"], "d/f.bin", "{listed}");
    assert_eq!(listed["repository_key"], remote.as_str());
    let one = json_of(
        &env,
        &["scan", "proxy", "list", &remote, "--path", "d/f.bin"],
    );
    assert_eq!(one["total"], 1, "{one}");
    assert!(
        stderr_of(
            &env,
            &["scan", "proxy", "list", &remote, "--path", "missing"]
        )
        .contains("404")
    );

    assert!(
        stderr_of(
            &env,
            &["scan", "proxy", "rescan", &remote, "--path", "missing"]
        )
        .contains("404")
    );
    // Whether a scan can finish depends on the server's scanner setup. Either it
    // gives a verdict, or it says the scan failed and that the old verdict stands.
    let rescan = env
        .ak_cmd()
        .args(["scan", "proxy", "rescan", &remote, "--path", "d/f.bin"])
        .output()
        .unwrap();
    if rescan.status.success() {
        let verdict: Value = serde_json::from_slice(&rescan.stdout).unwrap();
        assert_eq!(verdict["path"], "d/f.bin", "{verdict}");
        assert!(verdict["state"].is_string(), "{verdict}");
    } else {
        let stderr = String::from_utf8_lossy(&rescan.stderr);
        assert!(stderr.contains("503"), "{stderr}");
    }
}
