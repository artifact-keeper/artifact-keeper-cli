//! E2E tests for `ak pkg`: maven, ivy, bazel, go, gems, composer, cran, hex, pub and
//! terraform. Each publishes, then reads back what that format's client reads.
//! `tests/pkg-clients.sh` runs the real clients where one can run in a container.
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

    fn bytes(&self, path: &str) -> Vec<u8> {
        let response = self.get(path);
        assert!(
            response.status().is_success(),
            "{path}: {}",
            response.status()
        );
        response.bytes().expect("bytes").to_vec()
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
fn maven_publish_with_checksums_and_generated_pom() {
    let env = TestEnv::setup();
    let repo = Repo::new(&env, "maven");
    let tmp = dir();
    let key = repo.key.as_str();
    let jar = tmp.path().join("demo.jar");
    std::fs::write(&jar, b"jar bytes").unwrap();
    env.ak_cmd()
        .args(["pkg", "maven", "publish", key])
        .arg(&jar)
        .args([
            "--group",
            "com.acme",
            "--artifact",
            "demo",
            "--version",
            "1.0",
        ])
        .assert()
        .success();
    let base = format!("/maven/{key}/com/acme/demo/1.0/demo-1.0");
    assert_eq!(repo.bytes(&format!("{base}.jar")), b"jar bytes");
    assert_eq!(repo.text(&format!("{base}.jar.sha1")).trim().len(), 40);
    assert_eq!(repo.text(&format!("{base}.jar.md5")).trim().len(), 32);
    assert_eq!(repo.text(&format!("{base}.jar.sha256")).trim().len(), 64);
    assert_eq!(repo.text(&format!("{base}.jar.sha512")).trim().len(), 128);
    assert!(
        repo.text(&format!("{base}.pom"))
            .contains("<artifactId>demo</artifactId>")
    );

    // A classifier leaves the POM alone.
    env.ak_cmd()
        .args(["pkg", "maven", "publish", key])
        .arg(&jar)
        .args([
            "--group",
            "com.acme",
            "--artifact",
            "demo",
            "--version",
            "1.0",
        ])
        .args(["--classifier", "sources"])
        .assert()
        .success();
    assert_eq!(repo.bytes(&format!("{base}-sources.jar")), b"jar bytes");

    // Any single file, with --path.
    let meta = tmp.path().join("maven-metadata.xml");
    std::fs::write(&meta, "<metadata/>").unwrap();
    env.ak_cmd()
        .args(["pkg", "maven", "publish", key])
        .arg(&meta)
        .args(["--path", "com/acme/demo/maven-metadata.xml"])
        .assert()
        .success();
    assert_eq!(
        repo.text(&format!("/maven/{key}/com/acme/demo/maven-metadata.xml")),
        "<metadata/>"
    );
}

#[test]
#[ignore = "requires E2E backend"]
fn ivy_publish_descriptor_and_artifact() {
    let env = TestEnv::setup();
    let repo = Repo::new(&env, "sbt");
    let tmp = dir();
    let key = repo.key.as_str();
    let jar = tmp.path().join("whatever.jar");
    std::fs::write(&jar, b"jar").unwrap();
    let ivy = tmp.path().join("ivy.xml");
    std::fs::write(&ivy, "<ivy-module version=\"2.0\"/>").unwrap();
    let args = ["--org", "com.acme", "--module", "demo", "--revision", "1.0"];
    env.ak_cmd()
        .args(["pkg", "ivy", "publish", key])
        .arg(&jar)
        .args(args)
        .assert()
        .success();
    env.ak_cmd()
        .args(["pkg", "ivy", "publish", key, "--descriptor"])
        .arg(&ivy)
        .args(args)
        .assert()
        .success();
    assert_eq!(
        repo.bytes(&format!("/ivy/{key}/com.acme/demo/1.0/jars/demo-1.0.jar")),
        b"jar"
    );
    assert!(
        repo.text(&format!("/ivy/{key}/com.acme/demo/1.0/ivy-1.0.xml"))
            .contains("ivy-module")
    );
}

#[test]
#[ignore = "requires E2E backend"]
fn bazel_publish_module_files() {
    let env = TestEnv::setup();
    let repo = Repo::new(&env, "bazel");
    let tmp = dir();
    let key = repo.key.as_str();
    let module = tmp.path().join("MODULE.bazel");
    std::fs::write(&module, "module(name = \"demo\", version = \"1.0\")\n").unwrap();
    if common::server_older_than(1, 11, "the Bazel publish route") {
        let refused = env
            .ak_cmd()
            .args(["pkg", "bazel", "publish", key, "demo", "1.0"])
            .arg(&module)
            .assert()
            .failure();
        let stderr = String::from_utf8_lossy(&refused.get_output().stderr).to_string();
        assert!(stderr.contains("1.11"), "{stderr}");
        return;
    }
    let source = tmp.path().join("source.json");
    std::fs::write(
        &source,
        "{\"url\":\"https://example.com/a.tgz\",\"integrity\":\"x\"}",
    )
    .unwrap();
    env.ak_cmd()
        .args(["pkg", "bazel", "publish", key, "demo", "1.0"])
        .arg(&module)
        .arg(&source)
        .assert()
        .success();
    let metadata = repo.text(&format!("/bazel/{key}/modules/demo/metadata.json"));
    assert!(metadata.contains("1.0"), "{metadata}");
    assert!(
        repo.text(&format!("/bazel/{key}/modules/demo/1.0/MODULE.bazel"))
            .contains("demo")
    );
}

#[test]
#[ignore = "requires E2E backend"]
fn go_publish_takes_the_module_from_the_zip() {
    let env = TestEnv::setup();
    let repo = Repo::new(&env, "go");
    let tmp = dir();
    let key = repo.key.as_str();
    let zip = fx::zip(
        &tmp.path().join("m.zip"),
        &[
            (
                "example.com/Demo@v1.0.0/go.mod",
                b"module example.com/Demo\n",
            ),
            ("example.com/Demo@v1.0.0/d.go", b"package demo\n"),
        ],
    );
    env.ak_cmd()
        .args(["pkg", "go", "publish", key])
        .arg(&zip)
        .assert()
        .success();
    assert_eq!(
        repo.text(&format!("/go/{key}/example.com/!demo/@v/v1.0.0.mod")),
        "module example.com/Demo\n"
    );
    assert_eq!(
        repo.bytes(&format!("/go/{key}/example.com/!demo/@v/v1.0.0.zip")),
        std::fs::read(&zip).unwrap()
    );

    // A zip that isn't a module's is refused before anything is sent.
    let plain = fx::zip(&tmp.path().join("p.zip"), &[("a.txt", b"x")]);
    env.ak_cmd()
        .args(["pkg", "go", "publish", key])
        .arg(&plain)
        .assert()
        .failure();
}

#[test]
#[ignore = "requires E2E backend"]
fn gems_composer_cran_hex_pub_publish() {
    let env = TestEnv::setup();
    let tmp = dir();

    let gems = Repo::new(&env, "rubygems");
    env.ak_cmd()
        .args(["pkg", "gems", "publish", &gems.key])
        .arg(fx::gem(tmp.path(), "akdemo", "1.0.0"))
        .assert()
        .success();
    assert!(
        gems.text(&format!("/gems/{}/api/v1/gems/akdemo", gems.key))
            .contains("akdemo")
    );

    let composer = Repo::new(&env, "composer");
    let archive = fx::zip(
        &tmp.path().join("c.zip"),
        &[(
            "composer.json",
            b"{\"name\":\"acme/demo\",\"version\":\"1.0.0\"}",
        )],
    );
    env.ak_cmd()
        .args(["pkg", "composer", "publish", &composer.key])
        .arg(&archive)
        .assert()
        .success();
    let second = fx::zip(
        &tmp.path().join("d.zip"),
        &[(
            "composer.json",
            b"{\"name\":\"acme/other\",\"version\":\"1.0.0\"}",
        )],
    );
    env.ak_cmd()
        .args(["pkg", "composer", "publish", &composer.key, "--put"])
        .arg(&second)
        .assert()
        .success();
    let index = composer.text(&format!("/composer/{}/packages.json", composer.key));
    assert!(
        index.contains("acme/demo") || index.contains("metadata-url"),
        "{index}"
    );
    assert!(
        composer
            .text(&format!("/composer/{}/p2/acme/other.json", composer.key))
            .contains("1.0.0")
    );

    let cran = Repo::new(&env, "cran");
    let source = fx::tar_gz(
        &tmp.path().join("akdemo_1.0.0.tar.gz"),
        &[("akdemo/DESCRIPTION", b"Package: akdemo\nVersion: 1.0.0\n")],
    );
    env.ak_cmd()
        .args(["pkg", "cran", "publish", &cran.key])
        .arg(&source)
        .assert()
        .success();
    assert!(
        cran.text(&format!("/cran/{}/src/contrib/PACKAGES", cran.key))
            .contains("akdemo")
    );

    let hex = Repo::new(&env, "hex");
    let tarball = fx::hex_package(tmp.path(), "akdemo", "1.0.0");
    env.ak_cmd()
        .args(["pkg", "hex", "publish", &hex.key])
        .arg(&tarball)
        .assert()
        .success();
    assert_eq!(
        hex.bytes(&format!("/hex/{}/tarballs/akdemo-1.0.0.tar", hex.key)),
        std::fs::read(&tarball).unwrap()
    );

    let dart = Repo::new(&env, "pub");
    let package = fx::tar_gz(
        &tmp.path().join("akdemo.tar.gz"),
        &[
            ("pubspec.yaml", b"name: akdemo\nversion: 1.0.0\n"),
            ("lib/a.dart", b"\n"),
        ],
    );
    env.ak_cmd()
        .args(["pkg", "pub", "publish", &dart.key])
        .arg(&package)
        .assert()
        .success();
    assert!(
        dart.text(&format!("/pub/{}/api/packages/akdemo", dart.key))
            .contains("1.0.0")
    );
}

#[test]
#[ignore = "requires E2E backend"]
fn terraform_publish_module_and_provider() {
    let env = TestEnv::setup();
    let repo = Repo::new(&env, "terraform");
    let tmp = dir();
    let key = repo.key.as_str();
    let module = fx::tar_gz(&tmp.path().join("m.tar.gz"), &[("main.tf", b"\n")]);
    env.ak_cmd()
        .args([
            "pkg",
            "terraform",
            "publish-module",
            key,
            "acme",
            "vpc",
            "aws",
            "1.0.0",
        ])
        .arg(&module)
        .assert()
        .success();
    assert!(
        repo.text(&format!(
            "/terraform/{key}/v1/modules/acme/vpc/aws/versions"
        ))
        .contains("1.0.0")
    );

    let provider = fx::zip(
        &tmp.path().join("p.zip"),
        &[("terraform-provider-demo", b"bin")],
    );
    env.ak_cmd()
        .args([
            "pkg",
            "terraform",
            "publish-provider",
            key,
            "acme",
            "demo",
            "1.0.0",
            "linux",
            "amd64",
        ])
        .arg(&provider)
        .assert()
        .success();
    assert!(
        repo.text(&format!("/terraform/{key}/v1/providers/acme/demo/versions"))
            .contains("1.0.0")
    );
}
