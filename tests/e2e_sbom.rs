//! E2E tests for `ak sbom` against a real backend.
//!
//! Requires the E2E backend: ./tests/start-backend.sh
//!
//! An SBOM of a proxied artifact needs the inventory taken by a scan on download, so
//! a successful `sbom proxy` is covered in `tests/security_contract.rs`.

mod common;

use common::TestEnv;
use serde_json::{Value, json};
use tempfile::TempDir;

const UPSTREAM: &str = "http://ak-upstream:8080/api/v1/repositories";

const UV_LOCK: &str = "version = 1\nrequires-python = \">=3.8\"\n\n[[package]]\nname = \"a\"\n\
                       version = \"1\"\nsource = { registry = \"https://pypi.org/simple\" }\n";

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

fn repo_with_file(env: &TestEnv) -> String {
    let key = unique("sbom");
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
            "f.bin",
        ])
        .assert()
        .success();
    key
}

#[test]
#[ignore = "requires E2E backend"]
fn an_sbom_goes_from_generated_to_deleted() {
    let env = TestEnv::setup();
    let repo = repo_with_file(&env);
    let artifact = format!("{repo}/f.bin");

    let generated = json_of(
        &env,
        &[
            "sbom",
            "generate",
            &artifact,
            "--sbom-format",
            "cyclonedx",
            "--force",
        ],
    );
    let id = generated["id"].as_str().unwrap().to_string();
    assert_eq!(generated["format"], "cyclonedx");

    assert_eq!(
        json_of(&env, &["sbom", "show", &artifact])["id"],
        id.as_str()
    );
    let got = json_of(&env, &["sbom", "get", &id]);
    assert_eq!(got["content"]["bomFormat"], "CycloneDX");
    assert!(json_of(&env, &["sbom", "components", &id]).is_array());

    let listed = json_of(
        &env,
        &[
            "sbom",
            "list",
            "--repo",
            &repo,
            "--artifact",
            &artifact,
            "--sbom-format",
            "cyclonedx",
        ],
    );
    assert_eq!(listed[0]["id"], id.as_str(), "{listed}");

    // The file is the document itself, in both forms, so another tool can read it.
    let dir = TempDir::new().unwrap();
    let as_is = dir.path().join("a.json");
    env.ak_cmd()
        .args(["sbom", "export", &id, "-o", as_is.to_str().unwrap()])
        .assert()
        .success();
    let document: Value = serde_json::from_slice(&std::fs::read(&as_is).unwrap()).unwrap();
    assert_eq!(document["bomFormat"], "CycloneDX");
    let converted = dir.path().join("b.json");
    env.ak_cmd()
        .args([
            "sbom",
            "export",
            &id,
            "-o",
            converted.to_str().unwrap(),
            "--target-format",
            "spdx",
        ])
        .assert()
        .success();
    let document: Value = serde_json::from_slice(&std::fs::read(&converted).unwrap()).unwrap();
    assert_eq!(document["SPDXID"], "SPDXRef-DOCUMENT", "{document}");

    env.ak_cmd()
        .args(["sbom", "delete", &id, "--yes"])
        .assert()
        .success();
    assert!(stderr_of(&env, &["sbom", "get", &id]).contains("404"));
}

/// A CVE record appears when a finding is ingested, and takes a status decision.
#[test]
#[ignore = "requires E2E backend"]
fn a_cve_status_can_be_set_on_a_real_record() {
    let env = TestEnv::setup();
    let repo = repo_with_file(&env);
    let artifact = format!("{repo}/f.bin");
    let number = uuid::Uuid::new_v4().as_u128() % 90_000_000 + 10_000_000;
    let cve = format!("CVE-2026-{number}");

    let dir = TempDir::new().unwrap();
    let file = dir.path().join("findings.json");
    std::fs::write(
        &file,
        json!([{"title": "t", "severity": "medium", "cve_id": cve}]).to_string(),
    )
    .unwrap();
    env.ak_cmd()
        .args([
            "scan",
            "finding",
            "ingest",
            file.to_str().unwrap(),
            "--artifact",
            &artifact,
            "--scanner",
            "acme",
            "--yes",
        ])
        .assert()
        .success();

    let by_cve = json_of(&env, &["sbom", "cve", "history-by-cve", &cve]);
    assert_eq!(by_cve[0]["cve_id"], cve.as_str(), "{by_cve}");
    let by_artifact = json_of(&env, &["sbom", "cve", "history-by-artifact", &artifact]);
    assert_eq!(by_artifact[0]["cve_id"], cve.as_str(), "{by_artifact}");
    let overloaded = json_of(&env, &["sbom", "cve", "history", &artifact]);
    assert_eq!(overloaded[0]["cve_id"], cve.as_str(), "{overloaded}");

    let marked = json_of(
        &env,
        &[
            "sbom",
            "cve",
            "update-status-by-artifact-cve",
            &artifact,
            &cve,
            "--status",
            "acknowledged",
            "--reason",
            "not exploitable",
            "--yes",
        ],
    );
    assert_eq!(marked["status"], "acknowledged");

    let id = marked["id"].as_str().unwrap().to_string();
    let reopened = json_of(
        &env,
        &[
            "sbom",
            "cve",
            "update-status",
            &id,
            "--status",
            "open",
            "--yes",
        ],
    );
    assert_eq!(reopened["status"], "open");

    assert!(
        json_of(
            &env,
            &["sbom", "cve", "trends", "--days", "7", "--repo", &repo]
        )["total_cves"]
            .is_number()
    );
}

#[test]
#[ignore = "requires E2E backend"]
fn a_lockfile_becomes_an_sbom_on_1_11_and_says_so_on_1_10() {
    let env = TestEnv::setup();
    let dir = TempDir::new().unwrap();
    let lockfile = dir.path().join("uv.lock");
    std::fs::write(&lockfile, UV_LOCK).unwrap();
    let lockfile = lockfile.to_str().unwrap();

    if common::server_older_than(1, 11, "POST /sbom/environment") {
        let refused = stderr_of(&env, &["sbom", "environment", lockfile]);
        assert!(refused.contains("needs a server on 1.11"), "{refused}");
        return;
    }

    let body = json_of(
        &env,
        &["sbom", "environment", lockfile, "--sbom-format", "spdx"],
    );
    assert_eq!(body["sbomFormat"], "spdx", "{body}");
    assert_eq!(body["summary"]["distinctPackages"], 1, "{body}");

    let renamed = dir.path().join("whatever.txt");
    std::fs::write(&renamed, UV_LOCK).unwrap();
    let out = dir.path().join("env.json");
    env.ak_cmd()
        .args([
            "sbom",
            "environment",
            renamed.to_str().unwrap(),
            "--filename",
            "uv.lock",
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();
    let written: Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    assert_eq!(written["lockfile"], "uv.lock", "{written}");

    let no_match = stderr_of(
        &env,
        &["sbom", "environment", lockfile, "--platform", "no-such"],
    );
    assert!(no_match.contains("400"), "{no_match}");
}

#[test]
#[ignore = "requires E2E backend"]
fn a_cached_path_with_no_inventory_is_an_error_not_an_empty_sbom() {
    let env = TestEnv::setup();
    let upstream = repo_with_file(&env);
    let remote = unique("sbom-remote");
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
    env.ak_cmd()
        .args([
            "api",
            "GET",
            &format!("/api/v1/repositories/{remote}/download/f.bin"),
        ])
        .assert()
        .success();

    // The server records a proxied download after the client has the last byte.
    common::wait_until("the download to be recorded", || {
        env.ak_cmd()
            .args(["scan", "proxy", "list", &remote, "--path", "f.bin"])
            .output()
            .unwrap()
            .status
            .success()
            .then_some(())
    });

    let unknown = stderr_of(&env, &["sbom", "proxy", &remote, "--path", "missing"]);
    assert!(unknown.contains("404"), "{unknown}");
    let not_recorded = stderr_of(&env, &["sbom", "proxy", &remote, "--path", "f.bin"]);
    assert!(not_recorded.contains("No SBOM recorded"), "{not_recorded}");
}
