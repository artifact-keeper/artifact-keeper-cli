//! E2E tests for `ak pkg`: debian, alpine, pacman and incus/lxc. Each publishes, then
//! reads back the index that format's client reads. `tests/pkg-clients.sh` runs apt,
//! dnf, apk, pacman and micromamba. rpm and conda are only tested there, because a real
//! package of either can't be built here without a tool for it.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;
#[path = "common/pkg_fixtures.rs"]
mod pkg_fixtures;

use serde_json::json;
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
fn debian_publish_shows_in_packages() {
    let env = TestEnv::setup();
    let repo = Repo::new(&env, "debian");
    let tmp = dir();
    let key = repo.key.as_str();
    env.ak_cmd()
        .args(["pkg", "debian", "publish", key])
        .arg(fx::deb(tmp.path(), "demoak", "1.0"))
        .assert()
        .success();
    env.ak_cmd()
        .args(["pkg", "debian", "publish", key, "--endpoint", "upload"])
        .arg(fx::deb(tmp.path(), "libakdemo", "1.0"))
        .assert()
        .success();
    let index = repo.text(&format!(
        "/debian/{key}/dists/stable/main/binary-all/Packages"
    ));
    assert!(index.contains("Package: demoak"), "{index}");
    assert!(
        index.contains("Filename: pool/main/d/demoak/demoak_1.0_all.deb"),
        "{index}"
    );
    assert!(index.contains("Package: libakdemo"), "{index}");
    assert!(index.contains("pool/main/liba/libakdemo/"), "{index}");

    // A name the server can't read isn't sent.
    let odd = tmp.path().join("odd.deb");
    std::fs::write(&odd, "x").unwrap();
    env.ak_cmd()
        .args(["pkg", "debian", "publish", key])
        .arg(&odd)
        .assert()
        .failure();
}

#[test]
#[ignore = "requires E2E backend"]
fn alpine_publish_by_both_routes() {
    let env = TestEnv::setup();
    let repo = Repo::new(&env, "alpine");
    let tmp = dir();
    let key = repo.key.as_str();
    let one = tmp.path().join("akone-1.0-r0.apk");
    let two = tmp.path().join("aktwo-1.0-r0.apk");
    fx::pkginfo_package(&one, "akone", "1.0-r0", "x86_64");
    fx::pkginfo_package(&two, "aktwo", "1.0-r0", "x86_64");
    env.ak_cmd()
        .args(["pkg", "alpine", "publish", key, "--arch", "x86_64"])
        .arg(&one)
        .assert()
        .success();
    env.ak_cmd()
        .args([
            "pkg",
            "alpine",
            "publish",
            key,
            "--endpoint",
            "path",
            "--arch",
            "x86_64",
        ])
        .arg(&two)
        .assert()
        .success();
    let got = repo.get(&format!("/alpine/{key}/edge/main/x86_64/aktwo-1.0-r0.apk"));
    assert_eq!(got.bytes().unwrap().to_vec(), std::fs::read(&two).unwrap());
    let got = repo.get(&format!("/alpine/{key}/edge/main/x86_64/akone-1.0-r0.apk"));
    assert_eq!(got.bytes().unwrap().to_vec(), std::fs::read(&one).unwrap());

    // The path route needs an architecture, and says so before sending.
    env.ak_cmd()
        .args(["pkg", "alpine", "publish", key, "--endpoint", "path"])
        .arg(&one)
        .assert()
        .failure();
}

#[test]
#[ignore = "requires E2E backend"]
fn pacman_publish_and_delete() {
    if common::server_older_than(1, 11, "pacman repositories") {
        return;
    }
    let env = TestEnv::setup();
    let repo = Repo::new(&env, "pacman");
    let tmp = dir();
    let key = repo.key.as_str();
    let file = tmp.path().join("akdemo-1.0-1-any.pkg.tar.gz");
    fx::pkginfo_package(&file, "akdemo", "1.0-1", "any");
    env.ak_cmd()
        .args(["pkg", "pacman", "publish", key])
        .arg(&file)
        .assert()
        .success();
    let path = format!("/pacman/{key}/x86_64/akdemo-1.0-1-any.pkg.tar.gz");
    assert_eq!(
        repo.get(&path).bytes().unwrap().to_vec(),
        std::fs::read(&file).unwrap()
    );

    env.ak_cmd()
        .args([
            "pkg",
            "pacman",
            "delete",
            key,
            "x86_64",
            "akdemo-1.0-1-any.pkg.tar.gz",
            "--yes",
        ])
        .assert()
        .success();
    assert!(!repo.get(&path).status().is_success());
}

fn incus_flow(format: &str, prefix: &str) {
    let env = TestEnv::setup();
    let repo = Repo::new(&env, format);
    let tmp = dir();
    let key = repo.key.as_str();

    let whole = tmp.path().join("incus.tar.xz");
    let content: Vec<u8> = (0u8..=255).cycle().take(3 * 1024 * 1024 + 7).collect();
    std::fs::write(&whole, &content).unwrap();
    env.ak_cmd()
        .args(["pkg", prefix, "publish", key, "demo", "20260101"])
        .arg(&whole)
        .assert()
        .success();
    let path = format!("/{prefix}/{key}/images/demo/20260101/incus.tar.xz");
    assert_eq!(repo.get(&path).bytes().unwrap().to_vec(), content);

    // In chunks, which the server joins after it has answered.
    let chunked = tmp.path().join("rootfs.squashfs");
    std::fs::write(&chunked, &content).unwrap();
    env.ak_cmd()
        .args([
            "pkg",
            prefix,
            "publish",
            key,
            "demo",
            "20260102",
            "--chunked",
            "--chunk-size",
            "1",
        ])
        .arg(&chunked)
        .assert()
        .success();
    let path = format!("/{prefix}/{key}/images/demo/20260102/rootfs.squashfs");
    common::wait_until("the chunked image", || {
        let got = repo.get(&path);
        got.status()
            .is_success()
            .then(|| got.bytes().unwrap().to_vec())
    })
    .eq(&content)
    .then_some(())
    .expect("the joined image differs");

    // A session can be cancelled.
    let started = repo
        .env
        .api_client()
        .post(format!(
            "{}/{prefix}/{key}/images/demo/20260103/incus.tar.xz/uploads",
            env.url
        ))
        .bearer_auth(&env.token)
        .send()
        .unwrap();
    let session: serde_json::Value = started.json().unwrap();
    env.ak_cmd()
        .args([
            "pkg",
            prefix,
            "upload-cancel",
            key,
            session["session_id"].as_str().unwrap(),
        ])
        .assert()
        .success();

    env.ak_cmd()
        .args([
            "pkg",
            prefix,
            "delete",
            key,
            "demo",
            "20260101",
            "incus.tar.xz",
            "--yes",
        ])
        .assert()
        .success();
    assert!(
        !repo
            .get(&format!(
                "/{prefix}/{key}/images/demo/20260101/incus.tar.xz"
            ))
            .status()
            .is_success()
    );
}

#[test]
#[ignore = "requires E2E backend"]
fn incus_publish_chunked_cancel_delete() {
    incus_flow("incus", "incus");
}

#[test]
#[ignore = "requires E2E backend"]
fn lxc_is_the_same_under_its_own_url() {
    incus_flow("lxc", "lxc");
}
