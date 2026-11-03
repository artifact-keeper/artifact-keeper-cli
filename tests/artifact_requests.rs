//! What `ak artifact` sends for chunked sessions, multipart uploads and copies.
//! Contract, not E2E: these run against a mock server. The same commands run
//! against a real backend in `tests/e2e_artifact.rs`.

use std::process::Output;

use assert_cmd::Command;
use serde_json::{Value, json};
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SESSION: &str = "00000000-0000-0000-0000-0000000000cc";
const ARTIFACT: &str = "00000000-0000-0000-0000-000000000001";

fn artifact(at: &str) -> Value {
    json!({
        "id": ARTIFACT, "repository_key": "r", "path": at, "name": "a", "size_bytes": 3,
        "checksum_sha256": "abc", "content_type": "text/plain", "download_count": 0,
        "created_at": "2026-01-15T12:00:00Z", "analyzable": false, "quarantine_status": "clean"
    })
}

struct Fixture {
    server: MockServer,
    dir: TempDir,
}

impl Fixture {
    async fn new() -> Self {
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
        std::fs::write(dir.path().join("a.txt"), "abc").expect("write file");
        Self { server, dir }
    }

    fn file(&self) -> String {
        self.dir.path().join("a.txt").display().to_string()
    }

    fn ak(&self, args: &[&str]) -> Output {
        Command::cargo_bin("ak")
            .expect("ak binary")
            .env_remove("AK_FORMAT")
            .env("AK_CONFIG_DIR", self.dir.path())
            .env("AK_TOKEN", "t")
            .env("AK_CREDENTIAL_STORE", "file")
            .args(["--no-input"])
            .args(args)
            .output()
            .expect("run ak")
    }

    async fn answer(&self, verb: &str, route: &str, answer: ResponseTemplate) {
        Mock::given(method(verb))
            .and(path(route))
            .respond_with(answer)
            .mount(&self.server)
            .await;
    }

    async fn requests(&self) -> Vec<wiremock::Request> {
        self.server.received_requests().await.expect("recorded")
    }

    /// Answer the routes of a chunked upload that runs to the end.
    async fn accept_session(&self) {
        self.answer(
            "POST",
            "/api/v1/uploads",
            ResponseTemplate::new(201).set_body_json(json!({
                "session_id": SESSION, "chunk_count": 1, "chunk_size": 8388608,
                "expires_at": "2026-01-15T12:00:00Z"
            })),
        )
        .await;
        self.answer(
            "PATCH",
            &format!("/api/v1/uploads/{SESSION}"),
            ResponseTemplate::new(200).set_body_json(json!({
                "chunk_index": 0, "bytes_received": 3, "chunks_completed": 1, "chunks_remaining": 0
            })),
        )
        .await;
        self.answer(
            "PUT",
            &format!("/api/v1/uploads/{SESSION}/complete"),
            ResponseTemplate::new(200).set_body_json(json!({
                "artifact_id": ARTIFACT, "path": "a.txt", "size": 3, "checksum_sha256": "abc",
                "from_a_newer_server": 1
            })),
        )
        .await;
    }
}

#[tokio::test]
async fn a_session_field_makes_a_small_file_chunked_and_binds_every_field() {
    let f = Fixture::new().await;
    f.accept_session().await;
    let file = f.file();
    let output = f.ak(&[
        "--format",
        "json",
        "artifact",
        "push",
        "r",
        &file,
        "--skip-if-present",
        "--artifact-name",
        "nm",
        "--artifact-version",
        "9",
        "--package-description",
        "pd",
        "--package-metadata",
        r#"{"a":1}"#,
        "--artifact-metadata",
        r#"{"m":1}"#,
        "--artifact-metadata-format",
        "generic",
        "--artifact-metadata-properties",
        r#"{"p":1}"#,
    ]);
    assert!(output.status.success(), "{output:?}");

    let printed: Value = serde_json::from_slice(&output.stdout).expect("JSON output");
    assert_eq!(
        printed["from_a_newer_server"], 1,
        "the final body as received"
    );

    let requests = f.requests().await;
    let create = requests
        .iter()
        .find(|r| r.url.path() == "/api/v1/uploads")
        .expect("session created");
    let body: Value = serde_json::from_slice(&create.body).expect("JSON body");
    for (field, expected) in [
        ("skip_if_present", json!(true)),
        ("artifact_name", json!("nm")),
        ("artifact_version", json!("9")),
        ("package_description", json!("pd")),
        ("package_metadata", json!({"a": 1})),
        ("artifact_metadata", json!({"m": 1})),
        ("artifact_metadata_format", json!("generic")),
        ("artifact_metadata_properties", json!({"p": 1})),
    ] {
        assert_eq!(body[field], expected, "{field}");
    }
}

#[tokio::test]
async fn already_present_stops_before_any_chunk() {
    let f = Fixture::new().await;
    let answer = json!({
        "already_present": true, "artifact_id": ARTIFACT, "path": "a.txt", "size": 3,
        "checksum_sha256": "abc"
    });
    f.answer(
        "POST",
        "/api/v1/uploads",
        ResponseTemplate::new(200).set_body_json(&answer),
    )
    .await;
    let file = f.file();
    let output = f.ak(&[
        "--format",
        "json",
        "artifact",
        "push",
        "r",
        &file,
        "--skip-if-present",
    ]);
    assert!(output.status.success(), "{output:?}");
    let printed: Value = serde_json::from_slice(&output.stdout).expect("JSON output");
    assert_eq!(printed, answer);
    let requests = f.requests().await;
    let sent = requests.iter().filter(|r| r.url.path() != "/health");
    assert_eq!(sent.count(), 1);
}

#[tokio::test]
async fn a_plain_small_push_stays_a_put() {
    let f = Fixture::new().await;
    f.answer(
        "PUT",
        "/api/v1/repositories/r/artifacts/a.txt",
        ResponseTemplate::new(201).set_body_json(artifact("a.txt")),
    )
    .await;
    let file = f.file();
    let output = f.ak(&["artifact", "push", "r", &file, "--version-label", "one"]);
    assert!(output.status.success(), "{output:?}");
    let requests = f.requests().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].headers.get("x-artifact-version").unwrap(),
        "one"
    );
}

async fn multipart_case(args: &[&str], route: &str) -> String {
    let f = Fixture::new().await;
    f.answer(
        "POST",
        route,
        ResponseTemplate::new(201).set_body_json(artifact("a.txt")),
    )
    .await;
    let file = f.file();
    let mut all = vec!["artifact", "push", "r", file.as_str(), "--multipart"];
    all.extend(args);
    let output = f.ak(&all);
    assert!(output.status.success(), "{output:?}");
    let requests = f.requests().await;
    assert_eq!(requests.len(), 1);
    String::from_utf8_lossy(&requests[0].body).into_owned()
}

#[tokio::test]
async fn multipart_without_a_path_lets_the_server_name_it() {
    let body = multipart_case(&[], "/api/v1/repositories/r/artifacts").await;
    assert!(body.contains("name=\"file\""), "{body}");
    assert!(body.contains("filename=\"a.txt\""), "{body}");
    assert!(body.contains("abc"), "{body}");
    assert!(!body.contains("name=\"path\""), "{body}");
}

#[tokio::test]
async fn multipart_with_a_directory_sends_the_path_field() {
    let body = multipart_case(&["--path", "d/"], "/api/v1/repositories/r/artifacts").await;
    assert!(body.contains("name=\"path\""), "{body}");
    assert!(body.contains("d/"), "{body}");
}

#[tokio::test]
async fn multipart_with_a_full_path_puts_it_in_the_url() {
    let body = multipart_case(
        &["--path", "d/e.txt"],
        "/api/v1/repositories/r/artifacts/d/e.txt",
    )
    .await;
    assert!(!body.contains("name=\"path\""), "{body}");
}

#[tokio::test]
async fn multipart_refuses_flags_it_cant_honour() {
    let f = Fixture::new().await;
    let file = f.file();
    for flag in [
        vec!["--skip-if-present"],
        vec!["--no-chunked"],
        vec!["--content-type", "text/x"],
    ] {
        let mut all = vec!["artifact", "push", "r", file.as_str(), "--multipart"];
        all.extend(flag.iter().copied());
        let output = f.ak(&all);
        assert_eq!(output.status.code(), Some(2), "{flag:?}: {output:?}");
    }
    assert!(f.requests().await.is_empty());
}

#[tokio::test]
async fn upload_session_cancel_says_so_and_forgets_the_local_copy() {
    let f = Fixture::new().await;
    f.answer(
        "DELETE",
        &format!("/api/v1/uploads/{SESSION}"),
        ResponseTemplate::new(204),
    )
    .await;
    let uploads = f.dir.path().join("uploads");
    std::fs::create_dir_all(&uploads).unwrap();
    std::fs::write(
        uploads.join("x.json"),
        json!({
            "session_id": SESSION, "file_path": "/f", "file_sha256": "s", "total_size": 3,
            "chunk_size": 8388608, "chunk_count": 1, "repository_key": "r",
            "artifact_path": "a", "created_at": "2026-01-15T12:00:00Z"
        })
        .to_string(),
    )
    .unwrap();

    let listed = f.ak(&["--format", "quiet", "artifact", "upload-session", "list"]);
    assert_eq!(String::from_utf8_lossy(&listed.stdout).trim(), SESSION);

    let output = f.ak(&["artifact", "upload-session", "cancel", SESSION, "--yes"]);
    assert!(output.status.success(), "{output:?}");
    assert!(!uploads.join("x.json").exists());
}

/// A session this machine remembers but the server has ended, in each way the
/// server reports that. The push must start a new one and finish.
#[tokio::test]
async fn a_dead_cached_session_starts_again() {
    for status in [
        ResponseTemplate::new(404).set_body_json(json!({"error": "session not found"})),
        ResponseTemplate::new(410),
        ResponseTemplate::new(200).set_body_json(json!({
            "session_id": "00000000-0000-0000-0000-0000000000dd", "status": "cancelled",
            "total_size": 3, "bytes_received": 0, "chunks_completed": 0, "chunks_total": 1,
            "repository_key": "r", "artifact_path": "a.txt", "created_at": "t", "expires_at": "t"
        })),
    ] {
        let f = Fixture::new().await;
        f.accept_session().await;
        f.answer(
            "GET",
            "/api/v1/uploads/00000000-0000-0000-0000-0000000000dd",
            status,
        )
        .await;
        seed_cache(&f, "r", "a.txt");
        let file = f.file();
        let output = f.ak(&["artifact", "push", "r", &file, "--skip-if-present"]);
        assert!(output.status.success(), "{output:?}");
        assert!(
            f.requests()
                .await
                .iter()
                .any(|r| r.url.path() == "/api/v1/uploads"),
            "a new session"
        );
    }
}

/// The same file going to another repository is a new upload, not a resume.
#[tokio::test]
async fn a_cached_session_for_another_destination_isnt_resumed() {
    let f = Fixture::new().await;
    f.accept_session().await;
    seed_cache(&f, "other-repo", "a.txt");
    let file = f.file();
    let output = f.ak(&["artifact", "push", "r", &file, "--skip-if-present"]);
    assert!(output.status.success(), "{output:?}");
    let requests = f.requests().await;
    assert!(
        !requests
            .iter()
            .any(|r| r.url.path().ends_with("0000000000dd")),
        "the old session wasn't touched"
    );
}

fn seed_cache(f: &Fixture, repo: &str, artifact_path: &str) {
    use sha2::{Digest, Sha256};
    let file = std::fs::canonicalize(f.file()).unwrap();
    let key = hex::encode(Sha256::digest(file.to_string_lossy().as_bytes()));
    let sha = hex::encode(Sha256::digest(b"abc"));
    let uploads = f.dir.path().join("uploads");
    std::fs::create_dir_all(&uploads).unwrap();
    std::fs::write(
        uploads.join(format!("{key}.json")),
        json!({
            "session_id": "00000000-0000-0000-0000-0000000000dd", "file_path": file,
            "file_sha256": sha, "total_size": 3, "chunk_size": 8388608, "chunk_count": 1,
            "repository_key": repo, "artifact_path": artifact_path,
            "created_at": "2026-01-15T12:00:00Z"
        })
        .to_string(),
    )
    .unwrap();
}

// ---- copy ----

const PROMOTE: &str =
    "/api/v1/promotion/repositories/s/artifacts/00000000-0000-0000-0000-000000000001/promote";

async fn source_exists(f: &Fixture, at: &str) {
    f.answer(
        "GET",
        &format!("/api/v1/repositories/s/artifacts/{at}"),
        ResponseTemplate::new(200).set_body_json(artifact(at)),
    )
    .await;
}

#[tokio::test]
async fn copy_to_a_repository_promotes_to_that_repository() {
    let f = Fixture::new().await;
    source_exists(&f, "a.txt").await;
    f.answer(
        "POST",
        PROMOTE,
        ResponseTemplate::new(200).set_body_json(json!({
            "promoted": true, "source": "s/a.txt", "target": "t/a.txt", "policy_violations": []
        })),
    )
    .await;
    let output = f.ak(&["artifact", "copy", "s/a.txt", "t"]);
    assert!(output.status.success(), "{output:?}");
    let requests = f.requests().await;
    let body: Value = serde_json::from_slice(&requests.last().unwrap().body).unwrap();
    assert_eq!(body["target_repository"], "t");
}

#[tokio::test]
async fn copy_with_the_same_path_sends_only_the_repository() {
    let f = Fixture::new().await;
    source_exists(&f, "a.txt").await;
    f.answer(
        "POST",
        PROMOTE,
        ResponseTemplate::new(200).set_body_json(json!({
            "promoted": true, "source": "s/a.txt", "target": "t/a.txt", "policy_violations": []
        })),
    )
    .await;
    let output = f.ak(&["artifact", "copy", "s/a.txt", "t/a.txt"]);
    assert!(output.status.success(), "{output:?}");
    let requests = f.requests().await;
    let body: Value = serde_json::from_slice(&requests.last().unwrap().body).unwrap();
    assert_eq!(body["target_repository"], "t");
}

#[tokio::test]
async fn copy_binds_the_promotion_fields_and_refuses_them_without_a_promotion() {
    let f = Fixture::new().await;
    source_exists(&f, "a.txt").await;
    f.answer(
        "POST",
        PROMOTE,
        ResponseTemplate::new(200).set_body_json(json!({
            "promoted": true, "source": "s/a.txt", "target": "t/a.txt", "policy_violations": []
        })),
    )
    .await;
    let output = f.ak(&[
        "artifact",
        "copy",
        "s/a.txt",
        "t",
        "--notes",
        "why",
        "--skip-policy-check",
    ]);
    assert!(output.status.success(), "{output:?}");
    let requests = f.requests().await;
    let body: Value = serde_json::from_slice(&requests.last().unwrap().body).unwrap();
    assert_eq!(
        body,
        json!({"target_repository": "t", "notes": "why", "skip_policy_check": true})
    );

    let output = f.ak(&["artifact", "copy", "s/a.txt", "t/b.txt", "--notes", "why"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
}

#[tokio::test]
async fn copy_to_another_path_transfers_and_keeps_the_content_type() {
    let f = Fixture::new().await;
    f.answer(
        "GET",
        "/api/v1/repositories/s/download/d/a.txt",
        ResponseTemplate::new(200)
            .insert_header("content-type", "application/x-special")
            .set_body_bytes("abc".as_bytes()),
    )
    .await;
    f.answer(
        "PUT",
        "/api/v1/repositories/t/artifacts/e/b.bin",
        ResponseTemplate::new(201).set_body_json(artifact("e/b.bin")),
    )
    .await;
    let output = f.ak(&["artifact", "copy", "s/d/a.txt", "t/e/b.bin"]);
    assert!(output.status.success(), "{output:?}");
    let requests = f.requests().await;
    let put = requests.last().unwrap();
    assert_eq!(put.body, b"abc");
    assert_eq!(
        put.headers.get("content-type").unwrap(),
        "application/x-special"
    );
}

#[tokio::test]
async fn a_promotion_a_policy_refused_is_a_failure() {
    let f = Fixture::new().await;
    source_exists(&f, "a.txt").await;
    f.answer(
        "POST",
        PROMOTE,
        ResponseTemplate::new(200).set_body_json(json!({
            "promoted": false, "source": "s/a.txt", "target": "t/a.txt",
            "message": "blocked",
            "policy_violations": [{"rule": "r", "severity": "high", "message": "bad licence"}]
        })),
    )
    .await;
    let output = f.ak(&["artifact", "copy", "s/a.txt", "t"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("blocked") && stderr.contains("licence"),
        "{stderr}"
    );
}

// ---- pull ----

#[tokio::test]
async fn a_quarantined_pull_shows_the_message_and_leaves_no_file() {
    let f = Fixture::new().await;
    f.answer(
        "GET",
        "/api/v1/repositories/r/download/a.txt",
        ResponseTemplate::new(409).set_body_json(json!({
            "code": "CONFLICT", "message": "Artifact is quarantined"
        })),
    )
    .await;
    let out = f.dir.path().join("out");
    let out_str = out.display().to_string();
    let output = f.ak(&["artifact", "pull", "r", "a.txt", "-o", &out_str]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("409") && stderr.contains("quarantined"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("headers") && !stderr.contains("Response {"),
        "{stderr}"
    );
    assert!(!out.exists());
}

#[tokio::test]
async fn pull_asks_for_a_revision() {
    let f = Fixture::new().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/repositories/r/download/a.txt"))
        .and(wiremock::matchers::query_param("version", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes("two".as_bytes()))
        .expect(1)
        .mount(&f.server)
        .await;
    let out = f.dir.path().join("out");
    let out_str = out.display().to_string();
    let output = f.ak(&[
        "artifact",
        "pull",
        "r",
        "a.txt",
        "-o",
        &out_str,
        "--version",
        "2",
    ]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(std::fs::read(&out).unwrap(), b"two");
}

// ---- list and search ----

#[tokio::test]
async fn list_and_search_send_every_filter() {
    let f = Fixture::new().await;
    f.answer(
        "GET",
        "/api/v1/repositories/r/artifacts",
        ResponseTemplate::new(200).set_body_json(json!({
            "items": [], "pagination": {"page": 1, "per_page": 50, "total": 0, "total_pages": 0}
        })),
    )
    .await;
    f.answer(
        "GET",
        "/api/v1/search/advanced",
        ResponseTemplate::new(200).set_body_json(json!({
            "items": [], "pagination": {"page": 1, "per_page": 20, "total": 0, "total_pages": 0},
            "facets": {"formats": [], "repositories": [], "content_types": []}
        })),
    )
    .await;

    let output = f.ak(&[
        "artifact",
        "list",
        "r",
        "--path-prefix",
        "p",
        "--group-by",
        "g",
        "--cursor",
        "c",
        "--count",
        "exact",
    ]);
    assert!(output.status.success(), "{output:?}");
    let output = f.ak(&[
        "artifact",
        "search",
        "--name",
        "n",
        "--path",
        "p",
        "--version",
        "v",
        "--min-size",
        "1",
        "--max-size",
        "2",
        "--created-after",
        "a",
        "--created-before",
        "b",
        "--sort-by",
        "s",
        "--sort-order",
        "o",
        "--page",
        "3",
        "--per-page",
        "4",
    ]);
    assert!(output.status.success(), "{output:?}");

    let requests = f.requests().await;
    let query = |i: usize| {
        requests[i]
            .url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect::<std::collections::HashMap<_, _>>()
    };
    let list = query(0);
    for (k, v) in [
        ("path_prefix", "p"),
        ("group_by", "g"),
        ("cursor", "c"),
        ("count", "exact"),
    ] {
        assert_eq!(list.get(k).map(String::as_str), Some(v), "{k}");
    }
    let search = query(1);
    for (k, v) in [
        ("name", "n"),
        ("path", "p"),
        ("version", "v"),
        ("min_size", "1"),
        ("max_size", "2"),
        ("created_after", "a"),
        ("created_before", "b"),
        ("sort_by", "s"),
        ("sort_order", "o"),
        ("page", "3"),
        ("per_page", "4"),
    ] {
        assert_eq!(search.get(k).map(String::as_str), Some(v), "{k}");
    }
    assert!(!search.contains_key("query"));
}

// ---- a server before 1.11 ----

/// It would ignore the flag and upload anyway.
#[tokio::test]
async fn skip_if_present_is_refused_on_a_server_that_would_ignore_it() {
    let f = Fixture::new().await;
    f.answer(
        "GET",
        "/health",
        ResponseTemplate::new(200).set_body_json(json!({"version": "1.10.2"})),
    )
    .await;
    let file = f.file();
    let output = f.ak(&["artifact", "push", "r", &file, "--skip-if-present"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let requests = f.requests().await;
    assert!(requests.iter().all(|r| r.url.path() == "/health"));
}
