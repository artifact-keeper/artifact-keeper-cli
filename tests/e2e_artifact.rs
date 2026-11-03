//! E2E tests for `ak artifact` commands (push, pull, list, search, copy, delete).
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use predicates::prelude::*;

/// Deletes the repository (and any artifacts in it) when dropped, so each
/// test cleans up after itself even if an assertion fails mid-test.
struct RepoGuard {
    url: String,
    token: String,
    key: String,
}

impl RepoGuard {
    /// Create a local repository via the CLI and return a cleanup guard.
    fn create(env: &common::TestEnv, key: &str, pkg_format: &str) -> Self {
        env.ak_cmd()
            .args([
                "repo",
                "create",
                key,
                "--pkg-format",
                pkg_format,
                "--repo-type",
                "local",
            ])
            .assert()
            .success();

        RepoGuard {
            url: env.url.clone(),
            token: env.token.clone(),
            key: key.to_string(),
        }
    }
}

impl Drop for RepoGuard {
    fn drop(&mut self) {
        // Best-effort cleanup; the backend cascades artifact deletion.
        let _ = reqwest::blocking::Client::new()
            .delete(format!("{}/api/v1/repositories/{}", self.url, self.key))
            .bearer_auth(&self.token)
            .send();
    }
}

/// Write `size` bytes of deterministic, non-repeating-friendly content.
fn write_test_file(path: &std::path::Path, size: usize) -> Vec<u8> {
    let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    std::fs::write(path, &data).expect("Failed to write test file");
    data
}

/// The `content_type` the server stored for an artifact.
fn stored_content_type(env: &common::TestEnv, repo: &str, path: &str) -> String {
    let output = env
        .ak_cmd()
        .args(["artifact", "info", repo, path])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let info: serde_json::Value = serde_json::from_slice(&output).expect("artifact info JSON");
    info["content_type"]
        .as_str()
        .expect("artifact info has content_type")
        .to_string()
}

#[test]
#[ignore = "requires E2E backend"]
fn artifact_push_stores_detected_content_type() {
    let env = common::TestEnv::setup();
    let pid = std::process::id();
    let repo = format!("e2e-art-ctype-{pid}");
    let _guard = RepoGuard::create(&env, &repo, "generic");
    let dir = tempfile::TempDir::new().unwrap();

    // Single PUT: the Content-Type header.
    for (name, expected) in [
        ("pkg-1.0-1.noarch.rpm", "application/x-rpm"),
        ("pkg-1.0.tgz", "application/gzip"),
        ("pkg-1.0.crate", "application/octet-stream"),
    ] {
        let file = dir.path().join(name);
        write_test_file(&file, 1024);
        env.ak_cmd()
            .args(["artifact", "push", &repo, file.to_str().unwrap()])
            .assert()
            .success();
        assert_eq!(stored_content_type(&env, &repo, name), expected, "{name}");
    }

    // Explicit --content-type wins over detection.
    let file = dir.path().join("override.rpm");
    write_test_file(&file, 1024);
    env.ak_cmd()
        .args([
            "artifact",
            "push",
            &repo,
            file.to_str().unwrap(),
            "--content-type",
            "application/x-custom",
        ])
        .assert()
        .success();
    assert_eq!(
        stored_content_type(&env, &repo, "override.rpm"),
        "application/x-custom"
    );

    // Chunked: the upload session's content_type.
    let file = dir.path().join("chunked-1.0.jar");
    write_test_file(&file, 6 * 1024 * 1024);
    env.ak_cmd()
        .env("AK_CHUNKED_THRESHOLD", "1MB")
        .args([
            "artifact",
            "push",
            &repo,
            file.to_str().unwrap(),
            "--chunk-size",
            "5MB",
        ])
        .assert()
        .success();
    assert_eq!(
        stored_content_type(&env, &repo, "chunked-1.0.jar"),
        "application/java-archive"
    );
}

#[test]
#[ignore = "requires E2E backend"]
fn artifact_push_small_file_single_put() {
    let env = common::TestEnv::setup();
    let pid = std::process::id();
    let repo = format!("e2e-art-push-{pid}");
    let _guard = RepoGuard::create(&env, &repo, "generic");

    let dir = tempfile::TempDir::new().unwrap();
    let file = dir.path().join(format!("small-{pid}.bin"));
    write_test_file(&file, 4 * 1024);

    // Small file goes through the single-PUT path (backend answers 201).
    env.ak_cmd()
        .args(["artifact", "push", &repo, file.to_str().unwrap()])
        .assert()
        .success();

    // The artifact must exist in the repository.
    env.ak_cmd()
        .args(["artifact", "list", &repo])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!("small-{pid}.bin")));
}

#[test]
#[ignore = "requires E2E backend"]
fn artifact_push_large_file_chunked() {
    let env = common::TestEnv::setup();
    let pid = std::process::id();
    let repo = format!("e2e-art-chunk-{pid}");
    let _guard = RepoGuard::create(&env, &repo, "generic");

    let dir = tempfile::TempDir::new().unwrap();
    let file = dir.path().join(format!("large-{pid}.bin"));
    write_test_file(&file, 12 * 1024 * 1024);

    // Lower the chunking threshold so a 12MB file exercises the chunked
    // upload path (session create -> chunk PUTs -> finalize) without
    // shipping 100MB+ through the test suite.
    env.ak_cmd()
        .env("AK_CHUNKED_THRESHOLD", "1MB")
        .args([
            "artifact",
            "push",
            &repo,
            file.to_str().unwrap(),
            "--chunk-size",
            "5MB",
        ])
        .assert()
        .success();

    env.ak_cmd()
        .args(["artifact", "list", &repo])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!("large-{pid}.bin")));
}

#[test]
#[ignore = "requires E2E backend"]
fn artifact_pull_roundtrip_bytes_match() {
    let env = common::TestEnv::setup();
    let pid = std::process::id();
    let repo = format!("e2e-art-pull-{pid}");
    let _guard = RepoGuard::create(&env, &repo, "generic");

    let dir = tempfile::TempDir::new().unwrap();
    let src = dir.path().join(format!("roundtrip-{pid}.bin"));
    let pushed = write_test_file(&src, 64 * 1024);

    env.ak_cmd()
        .args(["artifact", "push", &repo, src.to_str().unwrap()])
        .assert()
        .success();

    // Pull to a fresh path and verify the bytes survive the round trip.
    let out = dir.path().join("pulled.bin");
    env.ak_cmd()
        .args([
            "artifact",
            "pull",
            &repo,
            &format!("roundtrip-{pid}.bin"),
            "--output",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    let pulled = std::fs::read(&out).expect("Pulled file missing");
    assert_eq!(pulled, pushed, "Pulled bytes differ from pushed bytes");
}

#[test]
#[ignore = "requires E2E backend"]
fn artifact_pull_existing_file_requires_force() {
    let env = common::TestEnv::setup();
    let pid = std::process::id();
    let repo = format!("e2e-art-force-{pid}");
    let _guard = RepoGuard::create(&env, &repo, "generic");

    let dir = tempfile::TempDir::new().unwrap();
    let src = dir.path().join(format!("force-{pid}.bin"));
    let pushed = write_test_file(&src, 16 * 1024);

    env.ak_cmd()
        .args(["artifact", "push", &repo, src.to_str().unwrap()])
        .assert()
        .success();

    // Pre-existing output file with sentinel content.
    let out = dir.path().join("existing.bin");
    let sentinel = b"do-not-clobber".to_vec();
    std::fs::write(&out, &sentinel).unwrap();

    // Without --force: the pull must fail and leave the file untouched.
    env.ak_cmd()
        .args([
            "artifact",
            "pull",
            &repo,
            &format!("force-{pid}.bin"),
            "--output",
            out.to_str().unwrap(),
        ])
        .assert()
        .failure()
        // miette may wrap the message, so match a single word of it.
        .stderr(predicate::str::contains("exists"));
    assert_eq!(
        std::fs::read(&out).unwrap(),
        sentinel,
        "Pull without --force must not modify the existing file"
    );

    // With --force: the file is overwritten with the artifact contents.
    env.ak_cmd()
        .args([
            "artifact",
            "pull",
            &repo,
            &format!("force-{pid}.bin"),
            "--output",
            out.to_str().unwrap(),
            "--force",
        ])
        .assert()
        .success();
    assert_eq!(
        std::fs::read(&out).unwrap(),
        pushed,
        "Pull with --force must overwrite with the artifact bytes"
    );
}

#[test]
#[ignore = "requires E2E backend"]
fn artifact_copy_between_repositories() {
    let env = common::TestEnv::setup();
    let pid = std::process::id();
    let src_repo = format!("e2e-art-cp-src-{pid}");
    let dst_repo = format!("e2e-art-cp-dst-{pid}");
    let _src_guard = RepoGuard::create(&env, &src_repo, "generic");
    let _dst_guard = RepoGuard::create(&env, &dst_repo, "generic");

    let dir = tempfile::TempDir::new().unwrap();
    let file = dir.path().join(format!("copy-me-{pid}.bin"));
    write_test_file(&file, 8 * 1024);

    env.ak_cmd()
        .args(["artifact", "push", &src_repo, file.to_str().unwrap()])
        .assert()
        .success();

    // Same-instance copy: repo/path -> destination repo.
    env.ak_cmd()
        .args([
            "artifact",
            "copy",
            &format!("{src_repo}/copy-me-{pid}.bin"),
            &dst_repo,
        ])
        .assert()
        .success();

    // The artifact must land in the destination repository.
    env.ak_cmd()
        .args(["artifact", "list", &dst_repo])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!("copy-me-{pid}.bin")));
}

#[test]
#[ignore = "requires E2E backend"]
fn artifact_list_search_and_delete() {
    let env = common::TestEnv::setup();
    let pid = std::process::id();
    let repo = format!("e2e-art-find-{pid}");
    let _guard = RepoGuard::create(&env, &repo, "generic");

    let dir = tempfile::TempDir::new().unwrap();
    let needle = format!("needle-{pid}.bin");
    let file = dir.path().join(&needle);
    write_test_file(&file, 2 * 1024);

    env.ak_cmd()
        .args(["artifact", "push", &repo, file.to_str().unwrap()])
        .assert()
        .success();

    // In-repo search finds the artifact.
    env.ak_cmd()
        .args(["artifact", "list", &repo, "--search", &needle])
        .assert()
        .success()
        .stdout(predicate::str::contains(&needle));

    // Global search scoped to the repo finds it too.
    env.ak_cmd()
        .args(["artifact", "search", &needle, "--repo", &repo])
        .assert()
        .success()
        .stdout(predicate::str::contains(&needle));

    // Delete it, then verify it is gone.
    env.ak_cmd()
        .args(["artifact", "delete", &repo, &needle, "--yes"])
        .assert()
        .success();

    env.ak_cmd()
        .args(["artifact", "list", &repo])
        .assert()
        .success()
        .stdout(predicate::str::contains(&needle).not());
}

fn json_stdout(assert: assert_cmd::assert::Assert) -> serde_json::Value {
    serde_json::from_slice(&assert.get_output().stdout).expect("JSON on stdout")
}

#[test]
#[ignore = "requires E2E backend"]
fn artifact_copy_to_a_path_and_by_exact_source() {
    let env = common::TestEnv::setup();
    let pid = std::process::id();
    let src = format!("e2e-cp2-src-{pid}");
    let dst = format!("e2e-cp2-dst-{pid}");
    let _src_guard = RepoGuard::create(&env, &src, "generic");
    let _dst_guard = RepoGuard::create(&env, &dst, "generic");

    let dir = tempfile::TempDir::new().unwrap();
    let file = dir.path().join("a.txt");
    let body = write_test_file(&file, 2048);
    let decoy = dir.path().join("decoy.txt");
    write_test_file(&decoy, 16);
    env.ak_cmd()
        .args([
            "artifact",
            "push",
            &src,
            file.to_str().unwrap(),
            "--path",
            "d/a.txt",
        ])
        .assert()
        .success();
    // Sorts before d/a.txt and matches a search for it, as a search used to find.
    env.ak_cmd()
        .args([
            "artifact",
            "push",
            &src,
            decoy.to_str().unwrap(),
            "--path",
            "b/d/a.txt.old",
        ])
        .assert()
        .success();

    // A destination with a different path used to be sent whole as the target repository.
    env.ak_cmd()
        .args([
            "artifact",
            "copy",
            &format!("{src}/d/a.txt"),
            &format!("{dst}/new/b.txt"),
        ])
        .assert()
        .success();
    let copied = json_stdout(
        env.ak_cmd()
            .args(["artifact", "info", &dst, "new/b.txt"])
            .assert()
            .success(),
    );
    assert_eq!(copied["size_bytes"], 2048);
    assert_eq!(copied["content_type"], "text/plain");

    let out = dir.path().join("out");
    env.ak_cmd()
        .args([
            "artifact",
            "pull",
            &dst,
            "new/b.txt",
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert_eq!(std::fs::read(&out).unwrap(), body);

    // A destination of a repository with the same path, with and without the path.
    let promoted = json_stdout(
        env.ak_cmd()
            .args(["artifact", "copy", &format!("{src}/d/a.txt"), &dst])
            .assert()
            .success(),
    );
    assert_eq!(promoted["promoted"], true);
    assert_eq!(promoted["target"], format!("{dst}/d/a.txt"));
    let same = json_stdout(
        env.ak_cmd()
            .args(["artifact", "info", &dst, "d/a.txt"])
            .assert()
            .success(),
    );
    assert_eq!(same["size_bytes"], 2048, "the exact source, not the decoy");
}

#[test]
#[ignore = "requires E2E backend"]
fn artifact_pull_of_a_quarantined_artifact_shows_the_reason() {
    let env = common::TestEnv::setup();
    let repo = format!("e2e-art-q-{}", std::process::id());
    let _guard = RepoGuard::create(&env, &repo, "generic");
    let dir = tempfile::TempDir::new().unwrap();
    let file = dir.path().join("a.txt");
    write_test_file(&file, 64);
    env.ak_cmd()
        .args(["artifact", "push", &repo, file.to_str().unwrap()])
        .assert()
        .success();
    env.ak_cmd()
        .args([
            "quarantine",
            "hold",
            &format!("{repo}/a.txt"),
            "--reason",
            "e2e",
            "--yes",
        ])
        .assert()
        .success();

    let out = dir.path().join("out");
    let assert = env
        .ak_cmd()
        .args([
            "artifact",
            "pull",
            &repo,
            "a.txt",
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
    assert!(
        stderr.contains("409") && stderr.contains("quarantined"),
        "{stderr}"
    );
    assert!(!stderr.contains("Response {"), "{stderr}");
    assert!(!out.exists());
}

#[test]
#[ignore = "requires E2E backend"]
fn artifact_multipart_reaches_both_routes() {
    let env = common::TestEnv::setup();
    let repo = format!("e2e-art-mp-{}", std::process::id());
    let _guard = RepoGuard::create(&env, &repo, "generic");
    let dir = tempfile::TempDir::new().unwrap();
    let file = dir.path().join("m.bin");
    write_test_file(&file, 512);
    let path_of = |args: &[&str]| -> String {
        let mut all = vec![
            "artifact",
            "push",
            &repo,
            file.to_str().unwrap(),
            "--multipart",
        ];
        all.extend(args);
        let shown = json_stdout(env.ak_cmd().args(&all).assert().success());
        shown["path"].as_str().unwrap().to_string()
    };
    assert_eq!(path_of(&[]), "m.bin");
    assert_eq!(path_of(&["--path", "dir/"]), "dir/m.bin");
    assert_eq!(path_of(&["--path", "x/full.bin"]), "x/full.bin");
}

#[test]
#[ignore = "requires E2E backend"]
fn artifact_session_fields_and_skip_if_present() {
    let env = common::TestEnv::setup();
    let repo = format!("e2e-art-se-{}", std::process::id());
    let _guard = RepoGuard::create(&env, &repo, "generic");
    let dir = tempfile::TempDir::new().unwrap();
    let file = dir.path().join("s.bin");
    write_test_file(&file, 4096);
    let file = file.to_str().unwrap();

    env.ak_cmd()
        .args([
            "artifact",
            "push",
            &repo,
            file,
            "--path",
            "s.bin",
            "--artifact-name",
            "named",
            "--artifact-version",
            "9.9",
        ])
        .assert()
        .success();
    let info = json_stdout(
        env.ak_cmd()
            .args(["artifact", "info", &repo, "s.bin"])
            .assert()
            .success(),
    );
    assert_eq!(info["name"], "named");
    assert_eq!(info["version"], "9.9");

    if common::server_older_than(1, 11, "skip_if_present") {
        // It would ignore the flag and upload anyway, so the command refuses.
        env.ak_cmd()
            .args([
                "artifact",
                "push",
                &repo,
                file,
                "--path",
                "s.bin",
                "--skip-if-present",
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains("needs a server on 1.11"));
        return;
    }
    let again = json_stdout(
        env.ak_cmd()
            .args([
                "artifact",
                "push",
                &repo,
                file,
                "--path",
                "s.bin",
                "--skip-if-present",
            ])
            .assert()
            .success(),
    );
    assert_eq!(again["already_present"], true);
}

#[test]
#[ignore = "requires E2E backend"]
fn artifact_upload_session_status_and_cancel() {
    let env = common::TestEnv::setup();
    let repo = format!("e2e-art-us-{}", std::process::id());
    let _guard = RepoGuard::create(&env, &repo, "generic");
    let created: serde_json::Value = env
        .api_post(
            "/api/v1/uploads",
            &serde_json::json!({
                "repository_key": repo,
                "artifact_path": "x.bin",
                "total_size": 3,
                "checksum_sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            }),
        )
        .json()
        .expect("session JSON");
    let session = created["session_id"].as_str().expect("session id");

    let status = json_stdout(
        env.ak_cmd()
            .args(["artifact", "upload-session", "status", session])
            .assert()
            .success(),
    );
    assert_eq!(status["artifact_path"], "x.bin");

    env.ak_cmd()
        .args(["artifact", "upload-session", "cancel", session, "--yes"])
        .assert()
        .success();
    let status = json_stdout(
        env.ak_cmd()
            .args(["artifact", "upload-session", "status", session])
            .assert()
            .success(),
    );
    assert_eq!(status["status"], "cancelled");
}

#[test]
#[ignore = "requires E2E backend"]
fn artifact_versions_labels_and_pull_by_revision() {
    let env = common::TestEnv::setup();
    let repo = format!("e2e-art-ve-{}", std::process::id());
    env.ak_cmd()
        .args([
            "repo",
            "create",
            &repo,
            "--pkg-format",
            "generic",
            "--versioning-enabled",
            "true",
        ])
        .assert()
        .success();
    let dir = tempfile::TempDir::new().unwrap();
    let file = dir.path().join("v.txt");
    for (content, label) in [("first", "one"), ("second", "two")] {
        std::fs::write(&file, content).unwrap();
        env.ak_cmd()
            .args([
                "artifact",
                "push",
                &repo,
                file.to_str().unwrap(),
                "--version-label",
                label,
            ])
            .assert()
            .success();
    }

    let versions = json_stdout(
        env.ak_cmd()
            .args(["artifact", "versions", &repo, "v.txt"])
            .assert()
            .success(),
    );
    assert_eq!(versions["items"].as_array().unwrap().len(), 2);
    assert_eq!(versions["items"][0]["version_label"], "two");

    let out = dir.path().join("out");
    env.ak_cmd()
        .args([
            "artifact",
            "pull",
            &repo,
            "v.txt",
            "-o",
            out.to_str().unwrap(),
            "--version",
            "1",
        ])
        .assert()
        .success();
    assert_eq!(std::fs::read(&out).unwrap(), b"first");

    let first = json_stdout(
        env.ak_cmd()
            .args(["artifact", "info", &repo, "v.txt", "--version", "1"])
            .assert()
            .success(),
    );
    assert_eq!(first["version"], "one");

    env.ak_cmd()
        .args(["repo", "delete", &repo, "--yes", "--wait"])
        .assert()
        .success();
}

#[test]
#[ignore = "requires E2E backend"]
fn artifact_missing_reports_what_the_repository_lacks() {
    if common::server_older_than(1, 11, "artifacts-missing") {
        let env = common::TestEnv::setup();
        env.ak_cmd()
            .args(["artifact", "missing", "any", "--item", "a=1"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("needs a server on 1.11"));
        return;
    }
    let env = common::TestEnv::setup();
    let repo = format!("e2e-art-mi-{}", std::process::id());
    let _guard = RepoGuard::create(&env, &repo, "generic");
    let dir = tempfile::TempDir::new().unwrap();
    let file = dir.path().join("h.txt");
    std::fs::write(&file, "abc").unwrap();
    env.ak_cmd()
        .args(["artifact", "push", &repo, file.to_str().unwrap()])
        .assert()
        .success();
    let held = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    let sums = dir.path().join("sums");
    std::fs::write(&sums, format!("{held}  other.txt\n")).unwrap();
    let report = json_stdout(
        env.ak_cmd()
            .args([
                "artifact",
                "missing",
                &repo,
                "--item",
                &format!("h.txt={held}"),
                "--from",
                sums.to_str().unwrap(),
            ])
            .assert()
            .success(),
    );
    assert_eq!(report["checked"], 2);
    assert_eq!(report["missing"].as_array().unwrap().len(), 1);
    assert_eq!(report["missing"][0]["path"], "other.txt");
    assert_eq!(report["missing"][0]["reason"], "not_found");
}

#[test]
#[ignore = "requires E2E backend"]
fn artifact_commands_take_a_repo_and_path() {
    let env = common::TestEnv::setup();
    let repo = format!("e2e-art-rp-{}", std::process::id());
    let _guard = RepoGuard::create(&env, &repo, "generic");
    let dir = tempfile::TempDir::new().unwrap();
    let file = dir.path().join("p.txt");
    write_test_file(&file, 32);
    env.ak_cmd()
        .args([
            "artifact",
            "push",
            &repo,
            file.to_str().unwrap(),
            "--path",
            "d/p.txt",
        ])
        .assert()
        .success();

    let shown = json_stdout(
        env.ak_cmd()
            .args(["artifact", "show", &format!("{repo}/d/p.txt")])
            .assert()
            .success(),
    );
    assert_eq!(shown["path"], "d/p.txt");
    env.ak_cmd()
        .args(["artifact", "stats", &format!("{repo}/d/p.txt")])
        .assert()
        .success();

    // A generic file gets no analysis. The server's own 404 has to come through.
    let assert = env
        .ak_cmd()
        .args(["artifact", "package-analysis", &format!("{repo}/d/p.txt")])
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
    let expected = if common::server_older_than(1, 11, "package analysis") {
        "needs a server on 1.11"
    } else {
        "404"
    };
    assert!(stderr.contains(expected), "{stderr}");

    let filtered = json_stdout(
        env.ak_cmd()
            .args([
                "artifact",
                "list",
                &repo,
                "--path-prefix",
                "d",
                "--count",
                "exact",
            ])
            .assert()
            .success(),
    );
    assert_eq!(filtered["items"][0]["path"], "d/p.txt");
}
