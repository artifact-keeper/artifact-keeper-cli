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
