//! `-o -` means stdout, and a reader that goes away isn't a failure. Against a mock
//! server, so a contract, not E2E: `e2e_artifact` has the real pipeline.

use std::io::Read;
use std::process::{Command as StdCommand, Stdio};

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin;
use serde_json::json;
use tempfile::TempDir;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const BYTES: &[u8] = b"\x1f\x8b not text \xff\nthe rest\n";

async fn serving(body: &[u8]) -> (MockServer, TempDir) {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(".*"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
        .mount(&server)
        .await;
    let dir = TempDir::new().expect("temp dir");
    std::fs::write(
        dir.path().join("config.toml"),
        format!(
            "default_instance = \"t\"\n[instances.t]\nurl = \"{}\"\napi_version = \"v1\"\n",
            server.uri()
        ),
    )
    .expect("write config");
    (server, dir)
}

fn ak(dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("ak").expect("ak binary");
    cmd.env("AK_CONFIG_DIR", dir.path())
        .env("AK_TOKEN", "unused")
        .env("AK_CREDENTIAL_STORE", "file")
        .env_remove("AK_INSTANCE")
        .current_dir(dir.path())
        .arg("--no-input");
    cmd
}

#[tokio::test]
async fn artifact_pull_writes_the_bytes_to_stdout_and_no_file() {
    let (_server, dir) = serving(BYTES).await;
    let output = ak(&dir)
        .args(["artifact", "pull", "r", "a.tgz", "-o", "-"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, BYTES, "only the artifact on stdout");
    assert!(!dir.path().join("-").exists(), "a file named -");
    assert!(!dir.path().join("a.tgz").exists());
}

#[tokio::test]
async fn a_failed_pull_to_stdout_puts_nothing_on_stdout() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(".*"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "gone"})))
        .mount(&server)
        .await;
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("config.toml"),
        format!(
            "default_instance = \"t\"\n[instances.t]\nurl = \"{}\"\n",
            server.uri()
        ),
    )
    .unwrap();
    let output = ak(&dir)
        .args(["artifact", "pull", "r", "a.tgz", "-o", "-"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(5), "{output:?}");
    assert!(output.stdout.is_empty());
}

#[tokio::test]
async fn sbom_proxy_and_oci_manifest_write_to_stdout() {
    let (_server, dir) = serving(br#"{"bomFormat":"CycloneDX"}"#).await;
    for args in [
        &["sbom", "proxy", "r", "--path", "p", "-o", "-"][..],
        &["pkg", "oci", "manifest", "get", "r/app", "1.0", "-o", "-"],
    ] {
        let output = ak(&dir).args(args).output().unwrap();
        assert!(output.status.success(), "{args:?}: {output:?}");
        assert_eq!(output.stdout, br#"{"bomFormat":"CycloneDX"}"#, "{args:?}");
        assert!(!dir.path().join("-").exists(), "{args:?}: a file named -");
    }
}

/// `ak ... | head -1`: a pipe whose reader closes after the first bytes.
fn with_reader_gone(dir: Option<&TempDir>, args: &[&str]) -> std::process::ExitStatus {
    let mut cmd = StdCommand::new(cargo_bin("ak"));
    if let Some(dir) = dir {
        cmd.env("AK_CONFIG_DIR", dir.path())
            .env("AK_TOKEN", "unused")
            .env("AK_CREDENTIAL_STORE", "file")
            .env_remove("AK_INSTANCE");
    }
    let mut child = cmd
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ak");
    drop(child.stdout.take());
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    let status = child.wait().unwrap();
    assert!(!stderr.contains("panicked"), "{args:?}: {stderr}");
    status
}

#[test]
fn completion_with_the_reader_gone_exits_0() {
    let status = with_reader_gone(None, &["completion", "bash"]);
    assert_eq!(status.code(), Some(0));
}

#[tokio::test]
async fn pull_and_println_with_the_reader_gone_exit_0() {
    let (_server, dir) = serving(&vec![b'x'; 256 * 1024]).await;
    let status = with_reader_gone(Some(&dir), &["artifact", "pull", "r", "a", "-o", "-"]);
    assert_eq!(status.code(), Some(0));
    let status = with_reader_gone(Some(&dir), &["api", "GET", "/x"]);
    assert_eq!(status.code(), Some(0));
    let status = with_reader_gone(None, &["--help"]);
    assert_eq!(status.code(), Some(0));
}
