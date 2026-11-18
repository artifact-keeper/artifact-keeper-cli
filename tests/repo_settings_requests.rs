//! What the 1.12 repository settings commands send, and how they read a 1.11 server:
//! `ak repo proxy-cache-cap`, `on-upstream-not-found`, `stale-if-error-grace`,
//! `upstream-mode`, `cache seed` and `rpm repodata rebuild`. Contract, not E2E: these
//! run against a mock server. The same commands run against a real backend in
//! `tests/e2e_repo.rs`.

use std::process::Output;

use assert_cmd::Command;
use serde_json::{Value, json};
use tempfile::TempDir;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const JOB: &str = "00000000-0000-0000-0000-0000000000aa";

fn ak_with_stdin(server: &MockServer, args: &[&str], stdin: &str) -> Output {
    let dir = TempDir::new().expect("temp dir");
    std::fs::write(
        dir.path().join("config.toml"),
        format!(
            "default_instance = \"t\"\n[instances.t]\nurl = \"{}\"\napi_version = \"v1\"\n",
            server.uri()
        ),
    )
    .expect("write config");
    Command::cargo_bin("ak")
        .expect("ak binary")
        .env_remove("AK_FORMAT")
        .env("AK_CONFIG_DIR", dir.path())
        .env("AK_TOKEN", "t")
        .env("AK_CREDENTIAL_STORE", "file")
        .args(["--no-input"])
        .args(args)
        .write_stdin(stdin)
        .output()
        .expect("run ak")
}

fn ak(server: &MockServer, args: &[&str]) -> Output {
    ak_with_stdin(server, args, "")
}

async fn server_on(version: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"version": version})))
        .mount(&server)
        .await;
    server
}

async fn answer(server: &MockServer, verb: &str, route: &str, answer: ResponseTemplate) {
    Mock::given(method(verb))
        .and(path(route))
        .respond_with(answer)
        .mount(server)
        .await;
}

async fn sent(server: &MockServer, verb: &str) -> Vec<Request> {
    server
        .received_requests()
        .await
        .expect("recorded")
        .into_iter()
        .filter(|r| r.method.as_str() == verb)
        .collect()
}

fn body(request: &Request) -> Value {
    serde_json::from_slice(&request.body).expect("JSON body")
}

fn one_line(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr)
        .replace('│', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn cap(bytes: Option<i64>) -> Value {
    json!({"repository_key": "r", "cap_bytes": bytes, "at_cap": "evict_lru",
           "usage": {"bytes": 2048, "entries": 3}, "refusing_fills": false})
}

#[tokio::test]
async fn proxy_cache_cap_takes_a_size_and_clears_with_a_delete() {
    let server = server_on("1.12.1").await;
    let route = "/api/v1/repositories/r/proxy-cache-cap";
    answer(
        &server,
        "PUT",
        route,
        ResponseTemplate::new(200).set_body_json(cap(Some(20 * 1024 * 1024 * 1024))),
    )
    .await;
    answer(
        &server,
        "DELETE",
        route,
        ResponseTemplate::new(200).set_body_json(cap(None)),
    )
    .await;
    answer(
        &server,
        "GET",
        route,
        ResponseTemplate::new(200).set_body_json(cap(None)),
    )
    .await;

    let output = ak(
        &server,
        &[
            "--format",
            "table",
            "repo",
            "proxy-cache-cap",
            "set",
            "r",
            "20G",
        ],
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        body(&sent(&server, "PUT").await[0]),
        json!({"cap_bytes": 20_i64 * 1024 * 1024 * 1024})
    );
    assert!(one_line(&output).contains("Capped the proxy cache of 'r'"));

    let output = ak(&server, &["repo", "proxy-cache-cap", "clear", "r"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(sent(&server, "DELETE").await.len(), 1);

    let output = ak(
        &server,
        &["--format", "table", "repo", "proxy-cache-cap", "show", "r"],
    );
    assert!(output.status.success(), "{output:?}");
    let shown = String::from_utf8_lossy(&output.stdout);
    assert!(
        shown.contains("none") && shown.contains("3 entries"),
        "{shown}"
    );
}

#[tokio::test]
async fn a_cap_that_isnt_a_size_sends_nothing() {
    let server = MockServer::start().await;
    let output = ak(&server, &["repo", "proxy-cache-cap", "set", "r", "lots"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn the_settings_send_the_value_given() {
    let server = server_on("1.12.1").await;
    answer(
        &server,
        "PUT",
        "/api/v1/repositories/r/on-upstream-not-found",
        ResponseTemplate::new(200)
            .set_body_json(json!({"repository_key": "r", "on_upstream_not_found": "keep"})),
    )
    .await;
    answer(
        &server,
        "PUT",
        "/api/v1/repositories/r/stale-if-error-grace",
        ResponseTemplate::new(200).set_body_json(
            json!({"repository_key": "r", "stale_if_error_grace_seconds": 600,
                   "override_seconds": 600}),
        ),
    )
    .await;
    answer(
        &server,
        "PUT",
        "/api/v1/repositories/r/upstream-mode",
        ResponseTemplate::new(200)
            .set_body_json(json!({"repository_key": "r", "upstream_mode": "cache_only",
                   "effective_upstream_mode": "cache_only"})),
    )
    .await;

    for args in [
        vec!["repo", "on-upstream-not-found", "set", "r", "keep"],
        vec!["repo", "stale-if-error-grace", "set", "r", "600"],
        vec!["repo", "upstream-mode", "set", "r", "cache_only"],
    ] {
        let output = ak(&server, &args);
        assert!(output.status.success(), "{args:?}: {output:?}");
    }
    let bodies: Vec<Value> = sent(&server, "PUT").await.iter().map(body).collect();
    assert_eq!(
        bodies,
        vec![
            json!({"on_upstream_not_found": "keep"}),
            json!({"stale_if_error_grace_seconds": 600}),
            json!({"upstream_mode": "cache_only"}),
        ]
    );
}

#[tokio::test]
async fn upstream_mode_says_when_the_instance_overrides_it() {
    let server = server_on("1.12.1").await;
    answer(
        &server,
        "PUT",
        "/api/v1/repositories/r/upstream-mode",
        ResponseTemplate::new(200)
            .set_body_json(json!({"repository_key": "r", "upstream_mode": "online",
                   "effective_upstream_mode": "cache_only"})),
    )
    .await;
    let output = ak(
        &server,
        &[
            "--format",
            "table",
            "repo",
            "upstream-mode",
            "set",
            "r",
            "online",
        ],
    );
    assert!(output.status.success(), "{output:?}");
    assert!(
        one_line(&output).contains("The instance forces cache_only"),
        "{output:?}"
    );
}

#[tokio::test]
async fn a_setting_value_the_server_doesnt_take_sends_nothing() {
    let server = MockServer::start().await;
    for args in [
        vec!["repo", "on-upstream-not-found", "set", "r", "purge"],
        vec!["repo", "upstream-mode", "set", "r", "offline"],
    ] {
        let output = ak(&server, &args);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

/// A 1.11 server has none of these routes, and answers 404 "Repository not found".
#[tokio::test]
async fn a_1_11_server_is_told_apart_from_a_missing_repository() {
    for args in [
        vec!["repo", "proxy-cache-cap", "show", "r"],
        vec!["repo", "proxy-cache-cap", "set", "r", "1G"],
        vec!["repo", "proxy-cache-cap", "clear", "r"],
        vec!["repo", "on-upstream-not-found", "show", "r"],
        vec!["repo", "on-upstream-not-found", "set", "r", "keep"],
        vec!["repo", "stale-if-error-grace", "show", "r"],
        vec!["repo", "stale-if-error-grace", "set", "r", "60"],
        vec!["repo", "upstream-mode", "show", "r"],
        vec!["repo", "upstream-mode", "set", "r", "online"],
        vec!["repo", "cache", "seed", "start", "r", "--path", "a/b"],
        vec!["repo", "cache", "seed", "status", "r", JOB],
        vec!["repo", "rpm", "repodata", "rebuild", "r"],
    ] {
        let server = server_on("1.11.14").await;
        Mock::given(wiremock::matchers::path_regex("^/api/v1/repositories/"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(json!({"code": "NOT_FOUND", "message": "Repository not found"})),
            )
            .mount(&server)
            .await;
        let output = ak(&server, &args);
        assert_eq!(output.status.code(), Some(6), "{args:?}: {output:?}");
        let stderr = one_line(&output);
        let command = args[..args.len() - 1]
            .iter()
            .take_while(|a| !a.starts_with('-'))
            .copied()
            .collect::<Vec<_>>();
        assert!(
            stderr.contains("needs a server on 1.12") && stderr.contains("1.11.14"),
            "{args:?}: {stderr}"
        );
        assert!(
            stderr.contains(&format!("`ak {}", command[..2].join(" "))),
            "{stderr}"
        );
    }
}

/// On a 1.12 server a 404 is the server's own answer.
#[tokio::test]
async fn a_404_from_a_1_12_server_keeps_its_message() {
    let server = server_on("1.12.1").await;
    Mock::given(wiremock::matchers::path_regex("^/api/v1/repositories/"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(json!({"message": "no such repository"})),
        )
        .mount(&server)
        .await;
    let output = ak(&server, &["repo", "upstream-mode", "show", "r"]);
    assert_eq!(output.status.code(), Some(5), "{output:?}");
    assert!(one_line(&output).contains("no such repository"));
}

// ---- cache seed ----

fn accepted() -> Value {
    json!({"job_id": JOB, "repository_key": "r", "kind": "paths", "status": "pending",
           "total_items": 3, "duplicates_ignored": 0, "concurrency": 4,
           "status_url": format!("/api/v1/repositories/r/cache/seed/{JOB}")})
}

fn seed_job(status: &str, items: Value) -> Value {
    let failed = items
        .as_array()
        .map_or(0, |i| i.iter().filter(|x| x["state"] == "failed").count());
    json!({"job_id": JOB, "repository_key": "r", "kind": "paths", "status": status,
           "concurrency": 4, "total_items": 3, "created_at": "2026-01-15T12:00:00Z",
           "error_summary": null, "items": items,
           "summary": {"pending": 0, "cached": 2, "already_cached": 0, "refused": 0,
                       "failed": failed, "cached_bytes": 10}})
}

async fn seeding(server: &MockServer, job: Value) {
    answer(
        server,
        "POST",
        "/api/v1/repositories/r/cache/seed",
        ResponseTemplate::new(202).set_body_json(accepted()),
    )
    .await;
    answer(
        server,
        "GET",
        &format!("/api/v1/repositories/r/cache/seed/{JOB}"),
        ResponseTemplate::new(200).set_body_json(job),
    )
    .await;
}

#[tokio::test]
async fn seed_start_sends_the_paths_as_a_list_and_reports_the_job() {
    let server = server_on("1.12.1").await;
    seeding(&server, seed_job("pending", json!([]))).await;
    let output = ak_with_stdin(
        &server,
        &[
            "--format",
            "quiet",
            "repo",
            "cache",
            "seed",
            "start",
            "r",
            "--path",
            "a/one.jar",
            "--paths-file",
            "-",
            "--concurrency",
            "8",
            "--max-total-bytes",
            "1K",
        ],
        "# a comment\n\nb/two.jar\n  c/three.jar  \n",
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), JOB);
    assert_eq!(
        body(&sent(&server, "POST").await[0]),
        json!({"kind": "paths", "content": ["a/one.jar", "b/two.jar", "c/three.jar"],
               "options": {"concurrency": 8, "max_total_bytes": 1024}})
    );
    // Without --wait, nothing follows the job.
    assert!(
        sent(&server, "GET")
            .await
            .iter()
            .all(|r| r.url.path() == "/health")
    );
}

#[tokio::test]
async fn seed_start_needs_a_path() {
    let server = MockServer::start().await;
    let output = ak(&server, &["repo", "cache", "seed", "start", "r"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(one_line(&output).contains("--path"), "{output:?}");
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn seed_wait_follows_the_job_to_its_end() {
    let server = server_on("1.12.1").await;
    let items = json!([
        {"position": 0, "path": "a", "state": "cached"},
        {"position": 1, "path": "b", "state": "cached"},
        {"position": 2, "path": "c", "state": "refused", "reason": "over the byte budget"}
    ]);
    seeding(&server, seed_job("completed", items)).await;
    let output = ak(
        &server,
        &[
            "--format", "json", "repo", "cache", "seed", "start", "r", "--path", "a", "--path",
            "b", "--path", "c", "--wait",
        ],
    );
    // A refused path is a gate saying no, not a failure.
    assert!(output.status.success(), "{output:?}");
    let printed: Value = serde_json::from_slice(&output.stdout).expect("JSON output");
    assert_eq!(printed["status"], "completed");
}

#[tokio::test]
async fn a_path_that_failed_fails_a_wait() {
    let server = server_on("1.12.1").await;
    let items = json!([
        {"position": 0, "path": "a", "state": "cached"},
        {"position": 1, "path": "gone.jar", "state": "failed", "status": 404,
         "reason": "upstream\nanswered 404"}
    ]);
    seeding(&server, seed_job("completed", items)).await;
    let output = ak(
        &server,
        &[
            "--format", "table", "repo", "cache", "seed", "status", "r", JOB, "--wait",
        ],
    );
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    let stderr = one_line(&output);
    assert!(
        stderr.contains("gone.jar: upstream answered 404"),
        "{stderr}"
    );
    // The table names what didn't make it.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("gone.jar") && stdout.contains("failed"),
        "{stdout}"
    );
}

#[tokio::test]
async fn a_failed_job_fails_its_status() {
    let server = server_on("1.12.1").await;
    let mut job = seed_job("failed", json!([]));
    job["error_summary"] = json!("proxy service not configured");
    seeding(&server, job).await;
    let output = ak(&server, &["repo", "cache", "seed", "status", "r", JOB]);
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    assert!(one_line(&output).contains("proxy service not configured"));
}

#[tokio::test]
async fn seed_wait_gives_up_at_the_timeout() {
    let server = server_on("1.12.1").await;
    seeding(&server, seed_job("running", json!([]))).await;
    let output = ak(
        &server,
        &[
            "repo",
            "cache",
            "seed",
            "status",
            "r",
            JOB,
            "--wait",
            "--wait-timeout",
            "0",
        ],
    );
    assert_eq!(output.status.code(), Some(6), "{output:?}");
    let stderr = one_line(&output);
    assert!(
        stderr.contains("Seed job") && stderr.contains("still running"),
        "{stderr}"
    );
}

// ---- rpm repodata rebuild ----

#[tokio::test]
async fn rebuild_sends_the_root_and_wait() {
    let server = server_on("1.12.1").await;
    Mock::given(method("POST"))
        .and(path("/api/v1/repositories/r/rpm/repodata/rebuild"))
        .and(query_param("root", "el9/x86_64"))
        .and(query_param("wait", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"root": "el9/x86_64", "status": "built", "revision": 4, "packages": 12}),
        ))
        .expect(1)
        .mount(&server)
        .await;
    let output = ak(
        &server,
        &[
            "--format",
            "table",
            "repo",
            "rpm",
            "repodata",
            "rebuild",
            "r",
            "--root",
            "el9/x86_64",
            "--wait",
        ],
    );
    assert!(output.status.success(), "{output:?}");
    assert!(
        one_line(&output).contains("revision 4, 12 packages"),
        "{output:?}"
    );
}

#[tokio::test]
async fn rebuild_without_wait_says_it_was_queued() {
    let server = server_on("1.12.1").await;
    Mock::given(method("POST"))
        .and(path("/api/v1/repositories/r/rpm/repodata/rebuild"))
        .respond_with(
            ResponseTemplate::new(202).set_body_json(json!({"root": "", "status": "queued"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let output = ak(
        &server,
        &[
            "--format", "table", "repo", "rpm", "repodata", "rebuild", "r",
        ],
    );
    assert!(output.status.success(), "{output:?}");
    let requests = sent(&server, "POST").await;
    assert!(requests[0].url.query().is_none(), "{:?}", requests[0].url);
    assert!(one_line(&output).contains("next tick"), "{output:?}");
}
