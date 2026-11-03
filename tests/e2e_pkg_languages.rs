//! E2E tests for `ak pkg`: npm, pypi, cargo, helm and nuget. Each publishes, then reads
//! back what that format's client reads. `tests/pkg-clients.sh` runs the real clients.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;
#[path = "common/pkg_fixtures.rs"]
mod pkg_fixtures;

use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};

use common::TestEnv;
use pkg_fixtures as fx;

fn unique(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{prefix}-{nanos}")
}

/// A hosted repository, deleted when dropped.
struct Repo<'a> {
    env: &'a TestEnv,
    key: String,
}

impl<'a> Repo<'a> {
    fn new(env: &'a TestEnv, format: &str) -> Self {
        let key = unique(&format!("pkg-{format}"));
        let created = env.api_post(
            "/api/v1/repositories",
            &json!({"key": key, "name": key, "format": format, "repo_type": "local",
                    "is_public": true}),
        );
        assert!(created.status().is_success(), "{}", created.status());
        Self { env, key }
    }

    fn get(&self, path: &str) -> reqwest::blocking::Response {
        self.env
            .api_client()
            .get(format!("{}{path}", self.env.url))
            .bearer_auth(&self.env.token)
            .send()
            .expect("GET")
    }

    fn json(&self, path: &str) -> Value {
        let response = self.get(path);
        assert!(
            response.status().is_success(),
            "{path}: {}",
            response.status()
        );
        response.json().expect("JSON")
    }

    fn text(&self, path: &str) -> String {
        let response = self.get(path);
        assert!(
            response.status().is_success(),
            "{path}: {}",
            response.status()
        );
        response.text().expect("text")
    }
}

impl Drop for Repo<'_> {
    fn drop(&mut self) {
        let _ = self
            .env
            .api_delete(&format!("/api/v1/repositories/{}", self.key));
    }
}

fn dir() -> tempfile::TempDir {
    tempfile::TempDir::new().expect("temp dir")
}

#[test]
#[ignore = "requires E2E backend"]
fn npm_publish_tag_and_unpublish() {
    let env = TestEnv::setup();
    let repo = Repo::new(&env, "npm");
    let tmp = dir();
    let key = repo.key.as_str();

    for version in ["1.0.0", "2.0.0"] {
        let file = fx::npm_tarball(tmp.path(), "demo", version);
        env.ak_cmd()
            .args(["pkg", "npm", "publish", key])
            .arg(&file)
            .assert()
            .success();
    }
    let scoped_dir = dir();
    let scoped = fx::npm_tarball(scoped_dir.path(), "@ak/demo", "1.0.0");
    env.ak_cmd()
        .args(["pkg", "npm", "publish", key])
        .arg(&scoped)
        .assert()
        .success();

    let doc = repo.json(&format!("/npm/{key}/demo"));
    assert_eq!(doc["name"], "demo");
    assert!(doc["versions"]["1.0.0"]["dist"]["tarball"].is_string());
    let tarball = doc["versions"]["1.0.0"]["dist"]["tarball"]
        .as_str()
        .unwrap()
        .to_string();
    let fetched = repo.get(
        tarball
            .split_once("/npm/")
            .map(|(_, p)| format!("/npm/{p}"))
            .unwrap()
            .as_str(),
    );
    assert_eq!(
        fetched.bytes().unwrap().to_vec(),
        std::fs::read(tmp.path().join("demo-1.0.0.tgz")).unwrap()
    );
    assert_eq!(
        repo.json(&format!("/npm/{key}/@ak/demo"))["name"],
        "@ak/demo"
    );

    // A dist-tag on a version that exists, and its removal.
    env.ak_cmd()
        .args([
            "pkg", "npm", "dist-tag", "set", key, "demo", "beta", "1.0.0",
        ])
        .assert()
        .success();
    assert_eq!(
        repo.json(&format!("/npm/{key}/demo"))["dist-tags"]["beta"],
        "1.0.0"
    );
    env.ak_cmd()
        .args(["pkg", "npm", "dist-tag", "rm", key, "demo", "beta"])
        .assert()
        .success();
    assert!(repo.json(&format!("/npm/{key}/demo"))["dist-tags"]["beta"].is_null());

    // An audit of a hosted repository has nothing to find, and says so as JSON.
    env.ak_cmd()
        .args([
            "pkg",
            "npm",
            "audit",
            key,
            "--body",
            "{\"demo\":[\"1.0.0\"]}",
        ])
        .assert()
        .success();

    if common::server_older_than(1, 11, "npm unpublish routes") {
        let refused = env
            .ak_cmd()
            .args(["pkg", "npm", "unpublish", key, "demo", "--yes"])
            .assert()
            .failure();
        let stderr = String::from_utf8_lossy(&refused.get_output().stderr).to_string();
        assert!(stderr.contains("1.11"), "{stderr}");
        return;
    }

    // One version goes, and the other stays.
    env.ak_cmd()
        .args([
            "pkg",
            "npm",
            "unpublish",
            key,
            "demo",
            "--version",
            "1.0.0",
            "--yes",
        ])
        .assert()
        .success();
    let doc = repo.json(&format!("/npm/{key}/demo"));
    assert!(doc["versions"]["1.0.0"].is_null());
    assert!(doc["versions"]["2.0.0"].is_object());

    // A version that isn't there is refused before anything changes.
    env.ak_cmd()
        .args([
            "pkg",
            "npm",
            "unpublish",
            key,
            "demo",
            "--version",
            "9.9.9",
            "--yes",
        ])
        .assert()
        .failure();

    // By tarball, then a whole scoped package under both URL shapes.
    env.ak_cmd()
        .args([
            "pkg",
            "npm",
            "unpublish",
            key,
            "demo",
            "--tarball",
            "demo-2.0.0.tgz",
            "--yes",
        ])
        .assert()
        .success();
    assert!(!repo.get(&format!("/npm/{key}/demo")).status().is_success());
    env.ak_cmd()
        .args([
            "pkg",
            "npm",
            "unpublish",
            key,
            "@ak/demo",
            "--encoded-name",
            "--yes",
        ])
        .assert()
        .success();
    assert!(
        !repo
            .get(&format!("/npm/{key}/@ak/demo"))
            .status()
            .is_success()
    );
}

#[test]
#[ignore = "requires E2E backend"]
fn pypi_publish_shows_in_the_simple_index() {
    let env = TestEnv::setup();
    let repo = Repo::new(&env, "pypi");
    let tmp = dir();
    let key = repo.key.as_str();
    let file = fx::sdist(tmp.path(), "demo_ak", "1.0");
    let sent = std::fs::read(&file).unwrap();
    let output = env
        .ak_cmd()
        .args(["pkg", "pypi", "publish", key])
        .arg(&file)
        .assert()
        .success();
    assert!(!output.get_output().stdout.is_empty());

    let index = repo.text(&format!("/pypi/{key}/simple/demo-ak/"));
    assert!(index.contains("demo_ak-1.0.tar.gz"), "{index}");
    let got = repo.get(&format!("/pypi/{key}/simple/demo-ak/demo_ak-1.0.tar.gz"));
    assert_eq!(got.bytes().unwrap().to_vec(), sent);

    // The XML-RPC API lists what was published.
    let listed = env
        .ak_cmd()
        .args(["pkg", "pypi", "xmlrpc", key, "list_packages"])
        .assert()
        .success();
    let text = String::from_utf8_lossy(&listed.get_output().stdout).to_string();
    assert!(text.contains("demo"), "{text}");
}

#[test]
#[ignore = "requires E2E backend"]
fn cargo_publish_writes_dependencies_to_the_index() {
    let env = TestEnv::setup();
    let repo = Repo::new(&env, "cargo");
    let tmp = dir();
    let key = repo.key.as_str();
    let file = fx::crate_file(
        tmp.path(),
        "akdemo",
        "1.0.0",
        "[features]\nextra = []\n[dependencies.serde]\nversion = \"1\"\nfeatures = [\"derive\"]\n",
    );
    env.ak_cmd()
        .args(["pkg", "cargo", "publish", key])
        .arg(&file)
        .assert()
        .success();

    let entry: Value =
        serde_json::from_str(repo.text(&format!("/cargo/{key}/ak/de/akdemo")).trim()).unwrap();
    assert_eq!(entry["vers"], "1.0.0");
    assert_eq!(entry["features"]["extra"], json!([]));
    assert_eq!(entry["deps"][0]["name"], "serde");
    assert_eq!(entry["deps"][0]["req"], "1");
    assert_eq!(entry["deps"][0]["features"], json!(["derive"]));

    // The other URL, and what's downloaded is what was sent.
    let second = fx::crate_file(tmp.path(), "akdemo", "1.0.1", "");
    env.ak_cmd()
        .args(["pkg", "cargo", "publish", key, "--endpoint", "api-cargo"])
        .arg(&second)
        .assert()
        .success();
    let got = repo.get(&format!("/cargo/{key}/api/v1/crates/akdemo/1.0.1/download"));
    assert_eq!(
        got.bytes().unwrap().to_vec(),
        std::fs::read(&second).unwrap()
    );

    // A file that isn't a crate is refused before anything's sent.
    let junk = tmp.path().join("junk.crate");
    std::fs::write(&junk, "nope").unwrap();
    env.ak_cmd()
        .args(["pkg", "cargo", "publish", key])
        .arg(&junk)
        .assert()
        .failure();
}

#[test]
#[ignore = "requires E2E backend"]
fn helm_publish_and_delete() {
    let env = TestEnv::setup();
    let repo = Repo::new(&env, "helm");
    let tmp = dir();
    let key = repo.key.as_str();
    let first = fx::helm_chart(tmp.path(), "demo", "1.0.0");
    let second = fx::helm_chart(tmp.path(), "other", "1.0.0");
    env.ak_cmd()
        .args(["pkg", "helm", "publish", key])
        .arg(&first)
        .assert()
        .success();
    env.ak_cmd()
        .args(["pkg", "helm", "publish", key, "--endpoint", "api-helm"])
        .arg(&second)
        .assert()
        .success();
    let index = repo.text(&format!("/helm/{key}/index.yaml"));
    assert!(index.contains("demo") && index.contains("other"), "{index}");

    env.ak_cmd()
        .args(["pkg", "helm", "delete", key, "other", "1.0.0"])
        .assert()
        .success();
    env.ak_cmd()
        .args([
            "pkg",
            "helm",
            "delete",
            key,
            "demo",
            "1.0.0",
            "--endpoint",
            "api-helm",
        ])
        .assert()
        .success();
    let index = repo.text(&format!("/helm/{key}/index.yaml"));
    assert!(
        !index.contains("other") && !index.contains("demo"),
        "{index}"
    );
}

#[test]
#[ignore = "requires E2E backend"]
fn nuget_publish_shows_in_the_flat_container() {
    let env = TestEnv::setup();
    let repo = Repo::new(&env, "nuget");
    let tmp = dir();
    let key = repo.key.as_str();
    let file = fx::nupkg(tmp.path(), "Demo.Ak", "1.0.0");
    env.ak_cmd()
        .args(["pkg", "nuget", "publish", key])
        .arg(&file)
        .assert()
        .success();
    let versions = repo.json(&format!("/nuget/{key}/v3/flatcontainer/demo.ak/index.json"));
    assert_eq!(versions["versions"], json!(["1.0.0"]));
}
