//! A server older than 1.11 has none of these routes, and answers 404 "Repository
//! not found", which names the wrong problem. `ak image-build` isn't here: 1.10
//! has those routes. Contract, not E2E:
//! tests/e2e_needs_1_11.rs runs these against real servers.

#[path = "common/mock.rs"]
mod mock;

use mock::Mocked;
use serde_json::json;
use wiremock::{Mock, ResponseTemplate, matchers::any};

const ID: &str = "00000000-0000-0000-0000-000000000001";

/// A server on `version` that answers 404 "Repository not found" to all but /health.
async fn server_without_the_routes(version: &str) -> Mocked {
    let m = Mocked::start().await;
    m.respond("GET", "/health", 200, json!({"version": version}))
        .await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(404).set_body_string("Repository not found"))
        .mount(&m.server)
        .await;
    m
}

fn every_command(file: &str) -> Vec<Vec<String>> {
    [
        "banner active",
        "banner list",
        &format!("banner show {ID}"),
        "banner create t --message m",
        &format!("banner update {ID} --title t"),
        &format!("banner delete {ID} --yes"),
        "bundle format",
        &format!("bundle validate-manifest {file}"),
        "bundle export --repo r",
        "bundle import",
        "bundle jobs list",
        &format!("bundle jobs show {ID}"),
        &format!("bundle jobs items {ID}"),
        &format!("environment ingest r {file}"),
        "environment list r",
        &format!("environment show r {ID}"),
        &format!("environment delete r {ID} --yes"),
        &format!("environment advisories r {ID}"),
        "environment show r by-name",
        "environment lookup pkg:npm/qs@1",
        "environment advisory-transitions",
    ]
    .iter()
    .map(|line| line.split_whitespace().map(str::to_string).collect())
    .collect()
}

fn lockfile(dir: &tempfile::TempDir) -> String {
    let file = dir.path().join("uv.lock");
    std::fs::write(&file, "x").unwrap();
    file.to_str().unwrap().to_string()
}

#[tokio::test]
async fn every_command_says_so_on_an_older_server() {
    let m = server_without_the_routes("1.10.2").await;
    let dir = tempfile::tempdir().unwrap();
    for args in every_command(&lockfile(&dir)) {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let output = m.ak(&args);
        assert_eq!(output.status.code(), Some(6), "{args:?}");
        let stderr = mock::unwrapped(&output.stderr);
        assert!(
            stderr.contains(&format!("`ak {}` needs a server on 1.11 or newer", args[0])),
            "{args:?}: {stderr}"
        );
        assert!(stderr.contains("This one is 1.10.2"), "{args:?}: {stderr}");
        assert!(
            !stderr.contains("Repository not found"),
            "{args:?}: {stderr}"
        );
    }
}

#[tokio::test]
async fn a_404_from_a_current_server_stays_a_404() {
    let m = server_without_the_routes("1.11.10").await;
    let dir = tempfile::tempdir().unwrap();
    for args in every_command(&lockfile(&dir)) {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let output = m.ak(&args);
        assert_eq!(output.status.code(), Some(5), "{args:?}");
        let stderr = mock::unwrapped(&output.stderr);
        assert!(stderr.contains("404"), "{args:?}: {stderr}");
        assert!(!stderr.contains("1.11 or newer"), "{args:?}: {stderr}");
    }
}

#[tokio::test]
async fn an_older_server_that_fails_some_other_way_keeps_its_own_error() {
    let m = Mocked::start().await;
    m.respond("GET", "/health", 200, json!({"version": "1.10.2"}))
        .await;
    m.respond(
        "GET",
        "/api/v1/admin/banners",
        403,
        json!({"code": "FORBIDDEN", "message": "Admin privileges required"}),
    )
    .await;
    let output = m.ak(&["banner", "list"]);
    let stderr = mock::unwrapped(&output.stderr);
    assert!(stderr.contains("Admin privileges required"), "{stderr}");
    assert!(!stderr.contains("1.11 or newer"), "{stderr}");
}

/// 1.10 has the image-build routes, so a 404 there means what it says.
#[tokio::test]
async fn image_build_keeps_the_servers_404_on_an_older_server() {
    let m = Mocked::start().await;
    m.respond("GET", "/health", 200, json!({"version": "1.10.2"}))
        .await;
    m.respond(
        "GET",
        &format!("/api/v1/repositories/r/image-builds/{ID}"),
        404,
        json!({"code": "NOT_FOUND", "message": "no build in repository r"}),
    )
    .await;
    let output = m.ak(&["image-build", "show", "r", ID]);
    let stderr = mock::unwrapped(&output.stderr);
    assert!(stderr.contains("no build in repository r"), "{stderr}");
    assert!(!stderr.contains("1.11 or newer"), "{stderr}");
}
