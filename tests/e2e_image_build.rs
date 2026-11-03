//! E2E tests for `ak image-build`, on the plain backend.
//!
//! Requires the E2E backend: ./tests/start-backend.sh
//!
//! The backend has no builder, so no build ever runs here: see
//! tests/image_build_contract.rs for what a successful one looks like.

mod common;

use predicates::prelude::*;
use predicates::str::contains;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

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

fn json_output(cmd: &mut assert_cmd::Command) -> Value {
    let output = cmd.assert().success().get_output().stdout.clone();
    serde_json::from_slice(&output).expect("command output is not JSON")
}

fn docker_repo(env: &common::TestEnv, suffix: &str) -> (String, Cleanup) {
    let name = format!("e2e-img-{suffix}-{}", std::process::id());
    env.ak_cmd()
        .args(["repo", "create", &name, "--pkg-format", "docker"])
        .assert()
        .success();
    let guard = Cleanup {
        url: env.url.clone(),
        token: env.token.clone(),
        repo: name.clone(),
    };
    (name, guard)
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Push a one-layer image over the OCI protocol, the way a client would.
fn push_image(env: &common::TestEnv, repo: &str, image: &str, tag: &str) {
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let base = format!("{}/v2/{repo}/{image}", env.url);
    let push_blob = |bytes: &[u8]| {
        let start = client
            .post(format!("{base}/blobs/uploads/"))
            .bearer_auth(&env.token)
            .send()
            .unwrap();
        assert!(start.status().is_success(), "{}", start.status());
        let location = start.headers()["location"].to_str().unwrap().to_string();
        let url = if location.starts_with("http") {
            location
        } else {
            format!("{}{location}", env.url)
        };
        let sep = if url.contains('?') { '&' } else { '?' };
        let done = client
            .put(format!("{url}{sep}digest={}", digest(bytes)))
            .bearer_auth(&env.token)
            .header("content-type", "application/octet-stream")
            .body(bytes.to_vec())
            .send()
            .unwrap();
        assert!(done.status().is_success(), "{}", done.status());
    };

    let layer = b"not really a tarball".to_vec();
    let config = json!({
        "architecture": "amd64",
        "os": "linux",
        "config": {"Cmd": ["serve"], "User": "1000"},
        "rootfs": {"type": "layers", "diff_ids": [digest(&layer)]},
        "history": [{"created_by": "e2e"}]
    })
    .to_string()
    .into_bytes();
    push_blob(&layer);
    push_blob(&config);

    let manifest = json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": digest(&config),
            "size": config.len()
        },
        "layers": [{
            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "digest": digest(&layer),
            "size": layer.len()
        }]
    })
    .to_string();
    let put = client
        .put(format!("{base}/manifests/{tag}"))
        .bearer_auth(&env.token)
        .header("content-type", "application/vnd.oci.image.manifest.v1+json")
        .body(manifest)
        .send()
        .unwrap();
    assert!(put.status().is_success(), "{}", put.status());
}

#[test]
#[ignore = "requires E2E backend"]
fn settings_and_an_empty_list() {
    let env = common::TestEnv::setup();
    let (repo, _guard) = docker_repo(&env, "settings");

    let settings = json_output(env.ak_cmd().args(["image-build", "settings", &repo]));
    assert_eq!(settings["enabled"], false);
    assert_eq!(settings["repository_buildable"], true);

    env.ak_cmd_table()
        .args(["--format", "table", "image-build", "settings", &repo])
        .assert()
        .success()
        .stdout(contains("Builds enabled:       no"));

    let list = json_output(env.ak_cmd().args(["image-build", "list", &repo]));
    assert_eq!(list["total"], 0);
}

#[test]
#[ignore = "requires E2E backend"]
fn render_prints_the_containerfile_from_each_kind_of_input() {
    let env = common::TestEnv::setup();
    let (repo, _guard) = docker_repo(&env, "render");

    let rendered = json_output(env.ak_cmd().args([
        "image-build",
        "render",
        &repo,
        "--base-image",
        "python:3.12-slim",
        "--pip",
        "requests==2.31.0",
        "--apt",
        "curl",
        "--conda",
        "numpy",
        "--conda-channel",
        "conda-forge",
        "--env",
        "A=1",
        "--label",
        "team=x",
        "--user",
        "1000",
        "--workdir",
        "/app",
    ]));
    let containerfile = rendered["containerfile"].as_str().unwrap();
    for expected in [
        "FROM python:3.12-slim",
        "requests==2.31.0",
        "'curl'",
        "numpy",
        "conda-forge",
        "ENV A=",
        "\"team\"=\"x\"",
        "USER 1000",
        "WORKDIR /app",
    ] {
        assert!(
            containerfile.contains(expected),
            "{expected}: {containerfile}"
        );
    }

    // A warning goes to stderr, so stdout stays a usable Containerfile.
    env.ak_cmd_table()
        .args(["--format", "table", "image-build", "render", &repo])
        .args(["--base-image", "python:3.12-slim", "--pip", "requests"])
        .assert()
        .success()
        .stdout(contains("# syntax=").and(contains("Warning").not()))
        .stderr(contains("not pinned"));

    // `--spec` from a file, with a flag on top, and install steps as JSON.
    let file = env.config_dir.path().join("spec.json");
    std::fs::write(
        &file,
        json!({"base_image": "alpine:3", "user": "1000"}).to_string(),
    )
    .unwrap();
    let rendered = json_output(env.ak_cmd().args([
        "image-build",
        "render",
        &repo,
        "--spec",
        &format!("@{}", file.display()),
        "--packages",
        r#"[{"manager":"apk","packages":["git"]}]"#,
        "--user",
        "2000",
    ]));
    let containerfile = rendered["containerfile"].as_str().unwrap();
    assert!(containerfile.contains("apk add"), "{containerfile}");
    assert!(containerfile.contains("USER 2000"), "{containerfile}");
}

#[test]
#[ignore = "requires E2E backend"]
fn the_servers_refusals_come_through() {
    let env = common::TestEnv::setup();
    let (repo, _guard) = docker_repo(&env, "refusals");

    // Each is a policy the plain backend applies.
    for (flag, value, message) in [
        ("--run", "echo hi", "RUN lines"),
        ("--apt", "curl", "install"),
    ] {
        env.ak_cmd()
            .args([
                "image-build",
                "render",
                &repo,
                "--base-image",
                "x",
                flag,
                value,
            ])
            .assert()
            .failure()
            .stderr(contains("400").and(contains(message)));
    }

    // No builder on this backend.
    env.ak_cmd()
        .args([
            "image-build",
            "create",
            &repo,
            "team/app",
            "1.0",
            "--base-image",
            "x",
        ])
        .assert()
        .failure()
        .stderr(contains("503").and(contains("not configured")));

    let missing = "00000000-0000-0000-0000-000000000001";
    for args in [
        ["image-build", "show", &repo, missing].as_slice(),
        ["image-build", "log", &repo, missing].as_slice(),
        ["image-build", "inspect", &repo, "nope", "1.0"].as_slice(),
    ] {
        env.ak_cmd()
            .args(args)
            .assert()
            .failure()
            .stderr(contains("404"));
    }
}

#[test]
#[ignore = "requires E2E backend"]
fn inspect_and_base_info_describe_a_pushed_image() {
    let env = common::TestEnv::setup();
    let (repo, _guard) = docker_repo(&env, "inspect");

    let unknown = json_output(
        env.ak_cmd()
            .args(["image-build", "base-info", &repo, "nope:1"]),
    );
    assert_eq!(unknown["found"], false);

    push_image(&env, &repo, "team/app", "1.0");

    let inspected =
        json_output(
            env.ak_cmd()
                .args(["image-build", "inspect", &repo, "team/app", "1.0"]),
        );
    assert_eq!(inspected["reference"], format!("{repo}/team/app:1.0"));
    assert_eq!(inspected["platforms"][0]["os"], "linux");
    assert_eq!(inspected["config"]["cmd"], json!(["serve"]));
    assert_eq!(inspected["layers"].as_array().unwrap().len(), 1);

    env.ak_cmd_table()
        .args([
            "--format",
            "table",
            "image-build",
            "inspect",
            &repo,
            "team/app",
            "1.0",
        ])
        .assert()
        .success()
        .stdout(contains("Platforms:  linux/amd64").and(contains("LAYER")));

    let known = json_output(env.ak_cmd().args([
        "image-build",
        "base-info",
        &repo,
        &format!("{repo}/team/app:1.0"),
    ]));
    assert_eq!(known["found"], true, "{known}");
    assert_eq!(known["digest"], inspected["digest"]);
}
