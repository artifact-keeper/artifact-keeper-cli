//! A wiremock server and an `ak` configured to use it, for checking what a command
//! sends and prints. Include it with `#[path = "common/mock.rs"] mod mock;`.

// Each test binary uses part of this.
#![allow(dead_code)]

use std::process::Output;

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;
use wiremock::MockServer;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

/// Stderr with the line wrapping of a miette diagnostic undone, to search for a
/// whole message.
pub fn unwrapped(stderr: &[u8]) -> String {
    String::from_utf8_lossy(stderr)
        .split_whitespace()
        .filter(|word| *word != "│")
        .collect::<Vec<_>>()
        .join(" ")
}

pub struct Mocked {
    pub server: MockServer,
    dir: TempDir,
}

impl Mocked {
    pub async fn start() -> Self {
        let server = MockServer::start().await;
        let dir = TempDir::new().expect("temp dir");
        std::fs::write(
            dir.path().join("config.toml"),
            format!(
                "default_instance = \"t\"\n[instances.t]\nurl = \"{}\"\napi_version = \"v1\"\n",
                server.uri()
            ),
        )
        .expect("write config");
        Self { server, dir }
    }

    /// Answer `verb route` with `status` and a JSON body.
    pub async fn respond(&self, verb: &str, route: &str, status: u16, body: Value) {
        Mock::given(method(verb))
            .and(path(route))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .mount(&self.server)
            .await;
    }

    /// Answer `verb route` with `status` and no body.
    pub async fn respond_empty(&self, verb: &str, route: &str, status: u16) {
        Mock::given(method(verb))
            .and(path(route))
            .respond_with(ResponseTemplate::new(status))
            .mount(&self.server)
            .await;
    }

    /// Run `ak --no-input <args>`, adding nothing else to the output format.
    pub fn ak(&self, args: &[&str]) -> Output {
        Command::cargo_bin("ak")
            .expect("ak binary")
            .env_remove("AK_FORMAT")
            .env("AK_CONFIG_DIR", self.dir.path())
            .env("AK_TOKEN", "t")
            .env("AK_CREDENTIAL_STORE", "file")
            .arg("--no-input")
            .args(args)
            .output()
            .expect("run ak")
    }

    /// Run `ak <args>` with no terminal and without `--no-input`, so a confirmation
    /// prompt really asks.
    pub fn ak_prompting(&self, args: &[&str]) -> Output {
        Command::cargo_bin("ak")
            .expect("ak binary")
            .env_remove("AK_FORMAT")
            .env_remove("AK_NO_INPUT")
            .env("AK_CONFIG_DIR", self.dir.path())
            .env("AK_TOKEN", "t")
            .env("AK_CREDENTIAL_STORE", "file")
            .args(args)
            .write_stdin("")
            .output()
            .expect("run ak")
    }

    /// `ak --format json <args>`: it must succeed, and it must print the body as
    /// the server sent it.
    pub fn json(&self, args: &[&str]) -> Value {
        let mut all = vec!["--format", "json"];
        all.extend(args);
        let output = self.ak(&all);
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap_or_else(|e| panic!("{args:?}: not JSON: {e}"))
    }

    /// The last request the server got with this method, as (query, JSON body).
    pub async fn last(&self, verb: &str) -> (Vec<(String, String)>, Value) {
        let requests = self.server.received_requests().await.expect("recording on");
        let request = requests
            .iter()
            .rev()
            .find(|r| r.method.as_str() == verb)
            .unwrap_or_else(|| panic!("no {verb} request"));
        let query = request
            .url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let body = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
        (query, body)
    }

    /// The raw body of the last request with this method.
    pub async fn last_body(&self, verb: &str) -> Vec<u8> {
        let requests = self.server.received_requests().await.expect("recording on");
        requests
            .iter()
            .rev()
            .find(|r| r.method.as_str() == verb)
            .unwrap_or_else(|| panic!("no {verb} request"))
            .body
            .clone()
    }
}
