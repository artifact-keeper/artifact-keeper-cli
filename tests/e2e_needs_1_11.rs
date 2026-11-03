//! On a server older than 1.11, `ak banner`, `bundle` and `environment`
//! say what's wrong rather than "Repository not found". On a current
//! server, a 404 stays the server's own.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use predicates::prelude::*;
use predicates::str::contains;

const MISSING: &str = "00000000-0000-0000-0000-000000000001";

/// Deletes the repository when dropped, so tests clean up even if one fails.
struct Cleanup {
    url: String,
    token: String,
    repo: String,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = reqwest::blocking::Client::new()
            .delete(format!("{}/api/v1/repositories/{}", self.url, self.repo))
            .bearer_auth(&self.token)
            .send();
    }
}

#[test]
#[ignore = "requires E2E backend"]
fn an_older_server_gets_the_real_reason() {
    if !common::server_older_than(1, 11, "nothing: this test is for older servers") {
        return;
    }
    let env = common::TestEnv::setup();
    // A real repository, so a 404 can only be the missing route.
    let repo = format!("e2e-needs-111-{}", std::process::id());
    env.ak_cmd()
        .args(["repo", "create", &repo, "--pkg-format", "generic"])
        .assert()
        .success();
    let _guard = Cleanup {
        url: env.url.clone(),
        token: env.token.clone(),
        repo: repo.clone(),
    };
    let file = env.config_dir.path().join("package-lock.json");
    std::fs::write(&file, "{}").unwrap();
    let path = file.to_str().unwrap();

    for args in [
        vec!["banner", "active"],
        vec!["banner", "list"],
        vec!["banner", "show", MISSING],
        vec!["banner", "create", "t", "--message", "m"],
        vec!["banner", "update", MISSING, "--title", "t"],
        vec!["banner", "delete", MISSING, "--yes"],
        vec!["bundle", "format"],
        vec!["bundle", "validate-manifest", path],
        vec!["bundle", "export", "--repo", &repo],
        vec!["bundle", "import"],
        vec!["bundle", "jobs", "list"],
        vec!["bundle", "jobs", "show", MISSING],
        vec!["bundle", "jobs", "items", MISSING],
        vec!["environment", "ingest", &repo, path],
        vec!["environment", "list", &repo],
        vec!["environment", "show", &repo, MISSING],
        vec!["environment", "delete", &repo, MISSING, "--yes"],
        vec!["environment", "advisories", &repo, MISSING],
        vec!["environment", "lookup", "pkg:npm/qs@1"],
        vec!["environment", "advisory-transitions"],
    ] {
        env.ak_cmd()
            .args(&args)
            .assert()
            .failure()
            .stderr(contains("1.11 or newer").and(contains("Repository not found").not()));
    }
}

#[test]
#[ignore = "requires E2E backend"]
fn a_real_404_on_a_current_server_stays_a_404() {
    if common::server_older_than(1, 11, "these routes") {
        return;
    }
    let env = common::TestEnv::setup();
    let no_repo = "e2e-no-such-repo";
    for args in [
        vec!["image-build", "settings", no_repo],
        vec!["banner", "show", MISSING],
        vec!["banner", "delete", MISSING, "--yes"],
        vec!["bundle", "jobs", "show", MISSING],
        vec!["bundle", "jobs", "items", MISSING],
        vec!["environment", "list", no_repo],
        vec!["environment", "show", no_repo, MISSING],
    ] {
        env.ak_cmd()
            .args(&args)
            .assert()
            .failure()
            .stderr(contains("404").and(contains("1.11 or newer").not()));
    }
}
