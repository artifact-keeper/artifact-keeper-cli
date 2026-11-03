//! E2E tests for `ak pkg oci`. The test uploads its own blobs with the OCI session calls,
//! since pushing is docker's job, not `ak`'s. `tests/pkg-clients.sh` does the same with a
//! real push and pull.
//!
//! Requires the E2E backend: ./tests/start-backend.sh

mod common;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

use common::TestEnv;

const MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

fn digest_of(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn push_blob(env: &TestEnv, name: &str, bytes: &[u8]) -> String {
    let client = env.api_client();
    let digest = digest_of(bytes);
    let started = client
        .post(format!("{}/v2/{name}/blobs/uploads/", env.url))
        .bearer_auth(&env.token)
        .send()
        .unwrap();
    assert!(started.status().is_success(), "{}", started.status());
    let location = started.headers()["location"].to_str().unwrap().to_string();
    let target = if location.starts_with("http") {
        location
    } else {
        format!("{}{location}", env.url)
    };
    let joiner = if target.contains('?') { '&' } else { '?' };
    let done = client
        .put(format!("{target}{joiner}digest={digest}"))
        .bearer_auth(&env.token)
        .body(bytes.to_vec())
        .send()
        .unwrap();
    assert!(done.status().is_success(), "{}", done.status());
    digest
}

fn stdout(assert: assert_cmd::assert::Assert) -> Vec<u8> {
    assert.success().get_output().stdout.clone()
}

#[test]
#[ignore = "requires E2E backend"]
fn oci_tags_manifests_and_blobs() {
    let env = TestEnv::setup();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let key = format!("pkg-oci-{nanos}");
    let created = env.api_post(
        "/api/v1/repositories",
        &json!({"key": key, "name": key, "format": "docker", "repo_type": "local",
                "is_public": true}),
    );
    assert!(created.status().is_success());
    let name = format!("{key}/team/app");

    let config = b"{\"architecture\":\"amd64\",\"os\":\"linux\"}";
    let layer = b"layer bytes";
    let config_digest = push_blob(&env, &name, config);
    let layer_digest = push_blob(&env, &name, layer);
    let manifest = json!({
        "schemaVersion": 2,
        "mediaType": MANIFEST,
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                   "digest": config_digest, "size": config.len()},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": layer_digest, "size": layer.len()}],
    })
    .to_string();
    let dir = tempfile::TempDir::new().unwrap();
    let file = dir.path().join("manifest.json");
    std::fs::write(&file, &manifest).unwrap();

    // Stored under two tags, and its type comes from the document.
    for tag in ["1.0", "2.0"] {
        let out: Value = serde_json::from_slice(&stdout(
            env.ak_cmd()
                .args(["pkg", "oci", "manifest", "put", &name, tag])
                .arg(&file)
                .assert(),
        ))
        .unwrap();
        assert_eq!(out["digest"], digest_of(manifest.as_bytes()).as_str());
    }

    let tags: Value = serde_json::from_slice(&stdout(
        env.ak_cmd().args(["pkg", "oci", "tags", &name]).assert(),
    ))
    .unwrap();
    assert_eq!(tags["tags"], json!(["1.0", "2.0"]));
    // One tag a page, joined up by following the Link header.
    let tags: Value = serde_json::from_slice(&stdout(
        env.ak_cmd()
            .args(["pkg", "oci", "tags", &name, "--all", "--limit", "1"])
            .assert(),
    ))
    .unwrap();
    assert_eq!(tags["tags"], json!(["1.0", "2.0"]));
    let catalog = stdout(
        env.ak_cmd()
            .args(["pkg", "oci", "catalog", "--all"])
            .assert(),
    );
    assert!(String::from_utf8_lossy(&catalog).contains(&name));

    // The exact bytes, whose digest is the one the head reports.
    let got = stdout(
        env.ak_cmd()
            .args(["pkg", "oci", "manifest", "get", &name, "1.0"])
            .assert(),
    );
    assert_eq!(got, manifest.as_bytes());
    let head: Value = serde_json::from_slice(&stdout(
        env.ak_cmd()
            .args(["pkg", "oci", "manifest", "head", &name, "1.0"])
            .assert(),
    ))
    .unwrap();
    assert_eq!(head["digest"], digest_of(manifest.as_bytes()).as_str());
    assert_eq!(head["media_type"], MANIFEST);

    // A blob comes back as sent, to a file only if it matches its digest.
    let out = dir.path().join("layer");
    env.ak_cmd()
        .args(["pkg", "oci", "blob", "get", &name, &layer_digest, "-o"])
        .arg(&out)
        .assert()
        .success();
    assert_eq!(std::fs::read(&out).unwrap(), layer);

    let referrers = stdout(
        env.ak_cmd()
            .args([
                "pkg",
                "oci",
                "referrers",
                &name,
                &digest_of(manifest.as_bytes()),
            ])
            .assert(),
    );
    assert!(String::from_utf8_lossy(&referrers).contains("manifests"));

    env.ak_cmd()
        .args(["pkg", "oci", "manifest", "delete", &name, "2.0", "--yes"])
        .assert()
        .success();
    let tags: Value = serde_json::from_slice(&stdout(
        env.ak_cmd().args(["pkg", "oci", "tags", &name]).assert(),
    ))
    .unwrap();
    assert_eq!(tags["tags"], json!(["1.0"]));

    let _ = env.api_delete(&format!("/api/v1/repositories/{key}"));
}
