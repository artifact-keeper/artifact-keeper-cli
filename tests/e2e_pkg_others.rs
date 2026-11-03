//! E2E tests for `ak pkg`: ansible, chef, puppet, cocoapods, jetbrains, vscode, huggingface,
//! swift, lfs, conan and proto. Each publishes, then reads back from the route a client
//! reads. `tests/pkg-clients.sh` runs the real clients where one can run in a container.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;
#[path = "common/pkg_fixtures.rs"]
mod pkg_fixtures;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
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

fn stdout(assert: assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&assert.success().get_output().stdout).to_string()
}

#[test]
#[ignore = "requires E2E backend"]
fn ansible_publish_shows_in_the_galaxy_api() {
    let env = TestEnv::setup();
    let repo = Repo::new(&env, "ansible");
    let tmp = dir();
    let manifest = br#"{"collection_info":{"namespace":"acme","name":"demo","version":"1.0.0"}}"#;
    let file = fx::tar_gz(
        &tmp.path().join("acme-demo-1.0.0.tar.gz"),
        &[
            ("MANIFEST.json", manifest),
            ("FILES.json", b"{\"files\":[]}"),
        ],
    );
    env.ak_cmd()
        .args(["pkg", "ansible", "publish", &repo.key])
        .arg(&file)
        .assert()
        .success();
    let versions = repo.text(&format!(
        "/ansible/{}/api/v3/collections/acme/demo/versions/",
        repo.key
    ));
    assert!(versions.contains("1.0.0"), "{versions}");
}

#[test]
#[ignore = "requires E2E backend"]
fn chef_puppet_and_cocoapods_read_their_metadata() {
    let env = TestEnv::setup();
    let tmp = dir();

    let chef = Repo::new(&env, "chef");
    let cookbook = fx::tar_gz(
        &tmp.path().join("demo.tar.gz"),
        &[(
            "demo/metadata.json",
            br#"{"name":"demo","version":"1.0.0"}"#,
        )],
    );
    env.ak_cmd()
        .args(["pkg", "chef", "publish", &chef.key])
        .arg(&cookbook)
        .assert()
        .success();
    assert!(
        chef.text(&format!("/chef/{}/api/v1/cookbooks/demo", chef.key))
            .contains("1.0.0")
    );
    // No metadata.json, so the name and version have to come from flags.
    let bare = fx::tar_gz(
        &tmp.path().join("bare.tar.gz"),
        &[("bare/metadata.rb", b"\n")],
    );
    env.ak_cmd()
        .args(["pkg", "chef", "publish", &chef.key])
        .arg(&bare)
        .assert()
        .failure();
    env.ak_cmd()
        .args([
            "pkg",
            "chef",
            "publish",
            &chef.key,
            "--name",
            "bare",
            "--version",
            "2.0.0",
        ])
        .arg(&bare)
        .assert()
        .success();
    assert!(
        chef.text(&format!("/chef/{}/api/v1/cookbooks/bare", chef.key))
            .contains("2.0.0")
    );

    let puppet = Repo::new(&env, "puppet");
    let module = fx::tar_gz(
        &tmp.path().join("acme-demo-1.0.0.tar.gz"),
        &[(
            "acme-demo-1.0.0/metadata.json",
            br#"{"name":"acme-demo","version":"1.0.0"}"#,
        )],
    );
    env.ak_cmd()
        .args(["pkg", "puppet", "publish", &puppet.key])
        .arg(&module)
        .assert()
        .success();
    assert_eq!(
        puppet.bytes(&format!(
            "/puppet/{}/v3/files/acme-demo-1.0.0.tar.gz",
            puppet.key
        )),
        std::fs::read(&module).unwrap()
    );

    let pods = Repo::new(&env, "cocoapods");
    let pod = fx::tar_gz(
        &tmp.path().join("Demo-1.0.0.tar.gz"),
        &[(
            "Demo.podspec.json",
            br#"{"name":"Demo","version":"1.0.0","authors":"a","summary":"s","source":{}}"#,
        )],
    );
    env.ak_cmd()
        .args(["pkg", "cocoapods", "publish", &pods.key])
        .arg(&pod)
        .assert()
        .success();
    assert!(
        pods.text(&format!("/cocoapods/{}/all_specs", pods.key))
            .contains("Demo")
    );
}

#[test]
#[ignore = "requires E2E backend"]
fn jetbrains_and_vscode_publish() {
    let env = TestEnv::setup();
    let tmp = dir();

    let plugins = Repo::new(&env, "jetbrains");
    let plugin = fx::zip(&tmp.path().join("p.zip"), &[("a.txt", b"x")]);
    env.ak_cmd()
        .args(["pkg", "jetbrains", "publish", &plugins.key])
        .args(["--name", "com.acme.demo", "--version", "1.0.0"])
        .arg(&plugin)
        .assert()
        .success();
    let listing = plugins.text(&format!(
        "/jetbrains/{}/plugin/details/com.acme.demo",
        plugins.key
    ));
    assert!(
        listing.contains("com.acme.demo") && listing.contains("1.0.0"),
        "{listing}"
    );

    let vsx = Repo::new(&env, "vscode");
    let extension = fx::vsix(tmp.path(), "acme", "demo", "1.0.0");
    env.ak_cmd()
        .args(["pkg", "vscode", "publish", &vsx.key])
        .arg(&extension)
        .assert()
        .success();
    if common::server_older_than(1, 11, "the gallery query") {
        return;
    }
    let query =
        "{\"filters\":[{\"criteria\":[{\"filterType\":10,\"value\":\"demo\"}]}],\"flags\":0}";
    let found = stdout(
        env.ak_cmd()
            .args(["pkg", "vscode", "query", &vsx.key, "--body", query])
            .assert(),
    );
    assert!(found.contains("demo"), "{found}");
}

#[test]
#[ignore = "requires E2E backend"]
fn huggingface_upload_with_and_without_a_namespace() {
    let env = TestEnv::setup();
    let repo = Repo::new(&env, "huggingface");
    let tmp = dir();
    let key = repo.key.as_str();
    let file = tmp.path().join("config.json");
    std::fs::write(&file, "{\"a\":1}").unwrap();
    env.ak_cmd()
        .args(["pkg", "huggingface", "upload", key, "acme/demo"])
        .arg(&file)
        .assert()
        .success();
    env.ak_cmd()
        .args([
            "pkg",
            "huggingface",
            "upload",
            key,
            "bare",
            "--filename",
            "other.json",
        ])
        .arg(&file)
        .assert()
        .success();
    assert_eq!(
        repo.bytes(&format!(
            "/huggingface/{key}/acme/demo/resolve/main/config.json"
        )),
        b"{\"a\":1}"
    );
    assert_eq!(
        repo.bytes(&format!("/huggingface/{key}/bare/resolve/main/other.json")),
        b"{\"a\":1}"
    );
}

#[test]
#[ignore = "requires E2E backend"]
fn swift_publish_shows_in_the_registry_api() {
    let env = TestEnv::setup();
    let repo = Repo::new(&env, "swift");
    let tmp = dir();
    let key = repo.key.as_str();
    let archive = fx::zip(
        &tmp.path().join("Demo.zip"),
        &[("Demo/Package.swift", b"// swift-tools-version:5.9\n")],
    );
    env.ak_cmd()
        .args(["pkg", "swift", "publish", key, "acme", "Demo", "1.0.0"])
        .args(["--metadata", "{\"description\":\"d\"}"])
        .arg(&archive)
        .assert()
        .success();
    let client = env.api_client();
    let got = client
        .get(format!("{}/swift/{key}/acme/Demo", env.url))
        .bearer_auth(&env.token)
        .header("accept", "application/vnd.swift.registry.v1+json")
        .send()
        .unwrap()
        .text()
        .unwrap();
    assert!(got.contains("1.0.0"), "{got}");
}

#[test]
#[ignore = "requires E2E backend"]
fn lfs_upload_lock_and_unlock() {
    let env = TestEnv::setup();
    let repo = Repo::new(&env, "gitlfs");
    let tmp = dir();
    let key = repo.key.as_str();
    let file = tmp.path().join("model.bin");
    std::fs::write(&file, b"lfs bytes").unwrap();
    let oid = hex::encode(Sha256::digest(b"lfs bytes"));

    let first: Value = serde_json::from_str(&stdout(
        env.ak_cmd()
            .args(["pkg", "lfs", "upload", key])
            .arg(&file)
            .assert(),
    ))
    .unwrap();
    assert_eq!(first["oid"], oid.as_str());
    assert_eq!(first["uploaded"], true);
    assert_eq!(
        repo.bytes(&format!("/lfs/{key}/objects/{oid}")),
        b"lfs bytes"
    );
    // Already there, so nothing's sent.
    let second: Value = serde_json::from_str(&stdout(
        env.ak_cmd()
            .args(["pkg", "lfs", "upload", key])
            .arg(&file)
            .assert(),
    ))
    .unwrap();
    assert_eq!(second["uploaded"], false);

    let locked: Value = serde_json::from_str(&stdout(
        env.ak_cmd()
            .args([
                "pkg",
                "lfs",
                "lock",
                key,
                "a/b.bin",
                "--ref",
                "refs/heads/main",
            ])
            .assert(),
    ))
    .unwrap();
    let id = locked["lock"]["id"].as_str().unwrap().to_string();
    let verified = stdout(
        env.ak_cmd()
            .args(["pkg", "lfs", "locks-verify", key])
            .assert(),
    );
    assert!(verified.contains("a/b.bin"), "{verified}");
    env.ak_cmd()
        .args(["pkg", "lfs", "unlock", key, &id, "--force"])
        .assert()
        .success();
    let verified = stdout(
        env.ak_cmd()
            .args(["pkg", "lfs", "locks-verify", key])
            .assert(),
    );
    assert!(!verified.contains("a/b.bin"), "{verified}");
}

#[test]
#[ignore = "requires E2E backend"]
fn conan_upload_and_remove() {
    let env = TestEnv::setup();
    let repo = Repo::new(&env, "conan");
    let tmp = dir();
    let key = repo.key.as_str();
    let write = |name: &str, content: &str| {
        let path = tmp.path().join(name);
        std::fs::write(&path, content).unwrap();
        path
    };
    let conanfile = write("conanfile.py", "# recipe\n");
    let manifest = write("conanmanifest.txt", "1\nconanfile.py: x\n");
    // The manifest comes first here, and the helper has to send it last.
    env.ak_cmd()
        .args([
            "pkg",
            "conan",
            "upload",
            key,
            "demo/1.0",
            "--revision",
            "rrev",
        ])
        .arg(&manifest)
        .arg(&conanfile)
        .assert()
        .success();
    let base = format!("/conan/{key}/v2/conans/demo/1.0/_/_/revisions/rrev");
    assert_eq!(
        repo.text(&format!("{base}/files/conanfile.py")),
        "# recipe\n"
    );

    let token = stdout(
        env.ak_cmd()
            .args(["pkg", "conan", "authenticate", key])
            .assert(),
    );
    assert!(!token.trim().is_empty());

    if common::server_older_than(1, 11, "Conan removal") {
        let refused = env
            .ak_cmd()
            .args(["pkg", "conan", "remove", key, "demo/1.0", "--yes"])
            .assert()
            .failure();
        let stderr = String::from_utf8_lossy(&refused.get_output().stderr).to_string();
        assert!(stderr.contains("1.11"), "{stderr}");
        return;
    }

    // A package's files, then all of the revision's packages removed.
    let info = write("conaninfo.txt", "[settings]\n");
    let package = write("conan_package.tgz", "not read\n");
    let package_manifest = write("conanmanifest.txt", "1\n");
    env.ak_cmd()
        .args([
            "pkg",
            "conan",
            "upload",
            key,
            "demo/1.0",
            "--revision",
            "rrev",
        ])
        .args(["--package-id", "pid", "--package-revision", "prev"])
        .arg(&package_manifest)
        .arg(&info)
        .arg(&package)
        .assert()
        .success();
    env.ak_cmd()
        .args([
            "pkg",
            "conan",
            "remove",
            key,
            "demo/1.0",
            "--revision",
            "rrev",
            "--all-packages",
            "--yes",
        ])
        .assert()
        .success();
    env.ak_cmd()
        .args([
            "pkg",
            "conan",
            "remove",
            key,
            "demo/1.0",
            "--revision",
            "rrev",
            "--yes",
        ])
        .assert()
        .success();
    assert!(
        !repo
            .get(&format!("{base}/files/conanfile.py"))
            .status()
            .is_success()
    );
}

#[test]
#[ignore = "requires E2E backend"]
fn proto_publish_and_call() {
    let env = TestEnv::setup();
    let repo = Repo::new(&env, "protobuf");
    let tmp = dir();
    let key = repo.key.as_str();
    let file = tmp.path().join("a.proto");
    std::fs::write(&file, "syntax = \"proto3\";\npackage demo;\n").unwrap();
    env.ak_cmd()
        .args([
            "pkg",
            "proto",
            "publish",
            key,
            "acme/demo",
            "--label",
            "main",
            "--root",
        ])
        .arg(tmp.path())
        .arg(&file)
        .assert()
        .success();
    let modules = stdout(
        env.ak_cmd()
            .args(["pkg", "proto", "call", key, "get-modules", "--body"])
            .arg("{\"moduleRefs\":[{\"owner\":\"acme\",\"module\":\"demo\"}]}")
            .assert(),
    );
    assert!(modules.contains("demo"), "{modules}");
    // Download isn't here: on 1.11.11 it answers 500 for a module's latest commit, which
    // is artifact-keeper#5197, fixed after that release.
    let commits = stdout(
        env.ak_cmd()
            .args(["pkg", "proto", "call", key, "list-commits", "--body"])
            .arg("{\"owner\":\"acme\",\"module\":\"demo\"}")
            .assert(),
    );
    assert!(commits.contains("acme/demo"), "{commits}");
}
