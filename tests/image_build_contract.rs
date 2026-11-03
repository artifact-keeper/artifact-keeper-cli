//! What `ak image-build` sends and prints, against a mock server.
//!
//! Contract, not E2E, for a build that succeeds: a plain backend has no builder, so
//! `create` only gets as far as a 503 there, and `list`, `show` and `log` have no
//! real build to show. tests/e2e_image_build.rs runs the rest against a real backend.

#[path = "common/mock.rs"]
mod mock;

use mock::Mocked;
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const ID: &str = "00000000-0000-0000-0000-000000000001";

fn build() -> Value {
    json!({
        "id": ID, "repository_key": "r", "image": "team/app", "tag": "1.0",
        "reference": "r/team/app:1.0", "status": "queued", "spec": {"base_image": "b"},
        "containerfile": "FROM b", "requested_by": "admin",
        "created_at": "2026-01-15T12:00:00Z", "log_bytes": 0,
        "from_a_newer_server": {"nested": [1, 2]}
    })
}

#[tokio::test]
async fn create_sends_the_image_tag_and_spec() {
    let m = Mocked::start().await;
    m.respond("POST", "/api/v1/repositories/r/image-builds", 202, build())
        .await;
    let shown = m.json(&[
        "image-build",
        "create",
        "r",
        "team/app",
        "1.0",
        "--base-image",
        "b",
        "--pip",
        "x==1,<2",
        "--pip",
        "y==2",
        "--user",
        "1000",
    ]);
    assert_eq!(shown, build());
    let (_, body) = m.last("POST").await;
    assert_eq!(
        body,
        json!({
            "image": "team/app",
            "tag": "1.0",
            "spec": {"base_image": "b", "pip": ["x==1,<2", "y==2"], "user": "1000"}
        })
    );
}

#[tokio::test]
async fn a_spec_field_this_cli_does_not_know_reaches_the_server() {
    let m = Mocked::start().await;
    m.respond(
        "POST",
        "/api/v1/repositories/r/image-builds/render",
        200,
        json!({"containerfile": "FROM b\n", "warnings": []}),
    )
    .await;
    m.json(&[
        "image-build",
        "render",
        "r",
        "--spec",
        r#"{"base_image":"b","from_a_newer_server":1}"#,
    ]);
    let (_, body) = m.last("POST").await;
    assert_eq!(
        body,
        json!({"spec": {"base_image": "b", "from_a_newer_server": 1}})
    );
}

#[tokio::test]
async fn a_dockerfile_goes_in_the_spec_as_text() {
    let m = Mocked::start().await;
    m.respond(
        "POST",
        "/api/v1/repositories/r/image-builds/render",
        200,
        json!({"containerfile": "FROM b\n", "warnings": []}),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("Dockerfile");
    std::fs::write(&file, "FROM b\nRUN true\n").unwrap();
    m.json(&[
        "image-build",
        "render",
        "r",
        "--dockerfile",
        file.to_str().unwrap(),
    ]);
    let (_, body) = m.last("POST").await;
    assert_eq!(body["spec"]["dockerfile"], "FROM b\nRUN true\n");
}

#[tokio::test]
async fn render_keeps_stdout_a_usable_containerfile() {
    let m = Mocked::start().await;
    let rendered = json!({"containerfile": "FROM b\n", "warnings": ["not pinned"]});
    m.respond(
        "POST",
        "/api/v1/repositories/r/image-builds/render",
        200,
        rendered.clone(),
    )
    .await;
    let output = m.ak(&[
        "--format",
        "table",
        "image-build",
        "render",
        "r",
        "--base-image",
        "b",
    ]);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "FROM b\n");
    assert!(String::from_utf8_lossy(&output.stderr).contains("not pinned"));
    assert_eq!(
        m.json(&["image-build", "render", "r", "--base-image", "b"]),
        rendered
    );
}

#[tokio::test]
async fn list_and_show_print_the_body() {
    let m = Mocked::start().await;
    let list = json!({"items": [build()], "total": 1});
    m.respond(
        "GET",
        "/api/v1/repositories/r/image-builds",
        200,
        list.clone(),
    )
    .await;
    m.respond(
        "GET",
        &format!("/api/v1/repositories/r/image-builds/{ID}"),
        200,
        build(),
    )
    .await;
    assert_eq!(m.json(&["image-build", "list", "r"]), list);
    assert_eq!(m.json(&["image-build", "show", "r", ID]), build());
}

#[tokio::test]
async fn log_prints_the_text() {
    let m = Mocked::start().await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/api/v1/repositories/r/image-builds/{ID}/log"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_string("step 1\nstep 2\n"))
        .mount(&m.server)
        .await;
    let output = m.ak(&["image-build", "log", "r", ID]);
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "step 1\nstep 2\n");
}

#[tokio::test]
async fn reads_send_their_query() {
    let m = Mocked::start().await;
    let info = json!({"found": false, "has_pip": false, "has_conda": false, "extra": 1});
    m.respond(
        "GET",
        "/api/v1/repositories/r/image-builds/base-info",
        200,
        info.clone(),
    )
    .await;
    assert_eq!(m.json(&["image-build", "base-info", "r", "alpine:3"]), info);
    let (query, _) = m.last("GET").await;
    assert_eq!(query, vec![("image".to_string(), "alpine:3".to_string())]);

    let inspected = json!({
        "reference": "r/a:1", "digest": "sha256:x", "platforms": [], "size_bytes": 0,
        "config": {"env": {}, "entrypoint": [], "cmd": [], "user": "", "working_dir": "",
                   "exposed_ports": [], "labels": {}},
        "history": [], "layers": [], "source": "registry", "extra": 1
    });
    m.respond(
        "GET",
        "/api/v1/repositories/r/image-inspect",
        200,
        inspected.clone(),
    )
    .await;
    assert_eq!(
        m.json(&["image-build", "inspect", "r", "a", "1"]),
        inspected
    );
    let (mut query, _) = m.last("GET").await;
    query.sort();
    assert_eq!(
        query,
        [("image", "a"), ("reference", "1")].map(|(k, v)| (k.to_string(), v.to_string()))
    );
}

#[tokio::test]
async fn bad_input_is_refused_before_any_request() {
    let m = Mocked::start().await;
    for args in [
        ["image-build", "render", "r", "--spec", "[]"].as_slice(),
        ["image-build", "render", "r", "--env", "novalue"].as_slice(),
        ["image-build", "show", "r", "not-a-uuid"].as_slice(),
    ] {
        assert_eq!(m.ak(args).status.code(), Some(2), "{args:?}");
    }
    assert!(m.server.received_requests().await.unwrap().is_empty());
}
