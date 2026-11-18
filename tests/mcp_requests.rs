//! What `ak mcp` sends, what it prints, and how it refuses: namespace proofs, a Remote
//! registry's catalog and decisions, sync and seed jobs and `--wait`, server health
//! and the approval queue. Contract, not E2E: these run against a mock server. The
//! same commands against a real backend are in `tests/e2e_mcp.rs`.

#[path = "common/mock.rs"]
mod mock;

use mock::{Mocked, unwrapped};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const ID: &str = "00000000-0000-0000-0000-000000000011";
const OTHER: &str = "00000000-0000-0000-0000-000000000022";
const JOB: &str = "00000000-0000-0000-0000-000000000033";
const AT: &str = "2026-01-15T12:00:00Z";
const REPO: &str = "mcp-official";
const CATALOG: &str = "/api/v1/repositories/mcp-official/mcp/catalog";

/// A mock server whose `/health` reports `version`.
async fn on(version: &str) -> Mocked {
    let mocked = Mocked::start().await;
    mocked
        .respond(
            "GET",
            "/health",
            200,
            json!({"status": "healthy", "version": version, "checks": {}}),
        )
        .await;
    mocked
}

fn proof(status: &str, last_error: Value) -> Value {
    json!({
        "id": ID, "namespace": "com.acme", "domain": "acme.com", "method": "dns",
        "status": status, "last_error": last_error, "created_by": OTHER, "created_at": AT,
        "last_checked_at": null, "verified_at": null,
        "challenge": {"type": "TXT", "name": "_ak-mcp-challenge.acme.com",
                      "value": "ak-mcp-verification=abc"},
        "x_new_field": "kept"
    })
}

fn item(status: &str) -> Value {
    json!({
        "id": ID, "name": "io.github.acme/weather", "namespace": "io.github.acme",
        "status": status, "versions": ["1.0.0", "1.2.0"], "latestVersion": "1.2.0",
        "flags": {"typosquat": {"similarTo": "io.github.acme/weathr"}},
        "approvalRequests": {"count": 2}, "firstSeenAt": AT, "pins": [], "denied": false,
        "ingested": [{"version": "1.2.0", "artifactId": OTHER, "upstreamStatus": "active",
                      "unresolved": []}],
        "summary": {"transports": ["streamable-http"], "registryTypes": ["npm"],
                    "secretsCount": 1, "packagesCount": 1, "remotesCount": 1,
                    "lint": {"version": "1.2.0", "block": 0, "review": 1, "warn": 2}},
        "x_new_field": "kept"
    })
}

fn decision(status: &str, ingest_error: Value) -> Value {
    json!({"item": item(status), "ingestError": ingest_error})
}

fn failed(output: &std::process::Output) -> String {
    assert!(!output.status.success(), "{output:?}");
    unwrapped(&output.stderr)
}

async fn paths(mocked: &Mocked) -> Vec<String> {
    mocked
        .server
        .received_requests()
        .await
        .expect("recording on")
        .iter()
        .filter(|r| r.url.path() != "/health")
        .map(|r| format!("{} {}", r.method, r.url.path()))
        .collect()
}

// ---- namespace proofs ----

#[tokio::test]
async fn a_proof_is_created_and_its_challenge_shown() {
    let mocked = on("1.12.1").await;
    let route = "/api/v1/admin/mcp/namespace-proofs";
    mocked
        .respond("POST", route, 200, proof("pending", Value::Null))
        .await;

    let printed = mocked.json(&[
        "mcp",
        "namespace-proof",
        "create",
        "com.acme",
        "--method",
        "dns",
    ]);
    assert_eq!(printed["x_new_field"], "kept", "the body as sent");
    let (_, body) = mocked.last("POST").await;
    assert_eq!(body, json!({"namespace": "com.acme", "method": "dns"}));

    let output = mocked.ak(&[
        "--format",
        "table",
        "mcp",
        "namespace-proof",
        "create",
        "com.acme",
        "--method",
        "dns",
    ]);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Publish a TXT record at _ak-mcp-challenge.acme.com"),
        "{stdout}"
    );
    assert!(stdout.contains("ak-mcp-verification=abc"), "{stdout}");
    assert!(
        unwrapped(&output.stderr).contains(&format!("ak mcp namespace-proof verify {ID}")),
        "{output:?}"
    );
}

#[tokio::test]
async fn a_method_other_than_dns_or_http_is_refused_locally() {
    let mocked = on("1.12.1").await;
    let output = mocked.ak(&[
        "mcp",
        "namespace-proof",
        "create",
        "com.acme",
        "--method",
        "email",
    ]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(paths(&mocked).await.is_empty());
}

#[tokio::test]
async fn proofs_are_listed_and_shown() {
    let mocked = on("1.12.1").await;
    let route = "/api/v1/admin/mcp/namespace-proofs";
    mocked
        .respond(
            "GET",
            route,
            200,
            json!({"items": [proof("verified", Value::Null)]}),
        )
        .await;
    mocked
        .respond(
            "GET",
            &format!("{route}/{ID}"),
            200,
            proof("pending", Value::Null),
        )
        .await;

    let output = mocked.ak(&["--format", "table", "mcp", "namespace-proof", "list"]);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("com.acme") && stdout.contains("verified"),
        "{stdout}"
    );

    let output = mocked.ak(&["--quiet", "mcp", "namespace-proof", "list"]);
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), ID);

    let printed = mocked.json(&["mcp", "namespace-proof", "show", ID]);
    assert_eq!(printed["x_new_field"], "kept");
}

#[tokio::test]
async fn a_proof_that_fails_its_check_is_a_reported_failure() {
    let mocked = on("1.12.1").await;
    let route = format!("/api/v1/admin/mcp/namespace-proofs/{ID}/verify");
    mocked
        .respond("POST", &route, 200, proof("failed", json!("no TXT record")))
        .await;
    let output = mocked.ak(&["mcp", "namespace-proof", "verify", ID]);
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    assert!(
        unwrapped(&output.stderr).contains("no TXT record"),
        "{output:?}"
    );

    let verified = on("1.12.1").await;
    verified
        .respond("POST", &route, 200, proof("verified", Value::Null))
        .await;
    let output = verified.ak(&["mcp", "namespace-proof", "verify", ID]);
    assert!(output.status.success(), "{output:?}");
}

#[tokio::test]
async fn deleting_a_proof_needs_yes() {
    let mocked = on("1.12.1").await;
    let route = format!("/api/v1/admin/mcp/namespace-proofs/{ID}");
    mocked.respond_empty("DELETE", &route, 200).await;

    let output = mocked.ak(&["mcp", "namespace-proof", "delete", ID]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(unwrapped(&output.stderr).contains("--yes"));
    assert!(paths(&mocked).await.is_empty());

    let output = mocked.ak(&["mcp", "namespace-proof", "delete", ID, "--yes"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(paths(&mocked).await, vec![format!("DELETE {route}")]);
}

// ---- the catalog ----

#[tokio::test]
async fn the_catalog_list_sends_its_filters() {
    let mocked = on("1.12.1").await;
    mocked
        .respond(
            "GET",
            CATALOG,
            200,
            json!({"items": [item("pending")], "counts": {"pending": 1, "approved": 4},
                   "nextCursor": "c2", "x_new_field": "kept"}),
        )
        .await;

    let printed = mocked.json(&[
        "mcp",
        "catalog",
        "list",
        "--repo",
        REPO,
        "--search",
        "weather",
        "--status",
        "pending",
        "--namespace",
        "io.github.acme",
        "--requested",
        "--queue",
        "--cursor",
        "c1",
        "--limit",
        "20",
    ]);
    assert_eq!(printed["x_new_field"], "kept");
    let (query, _) = mocked.last("GET").await;
    let mut query = query;
    query.sort();
    let want: Vec<(String, String)> = [
        ("cursor", "c1"),
        ("limit", "20"),
        ("namespace", "io.github.acme"),
        ("queue", "true"),
        ("requested", "true"),
        ("search", "weather"),
        ("status", "pending"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    assert_eq!(query, want);

    let output = mocked.ak(&[
        "--format", "table", "mcp", "catalog", "list", "--repo", REPO,
    ]);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("io.github.acme/weather"), "{stdout}");
    assert!(stdout.contains("typosquat"), "{stdout}");
    let stderr = unwrapped(&output.stderr);
    assert!(stderr.contains("--cursor c2"), "{stderr}");
    assert!(stderr.contains("pending 1"), "{stderr}");

    let (query, _) = mocked.last("GET").await;
    assert!(query.is_empty(), "no filters unless given: {query:?}");
}

#[tokio::test]
async fn a_server_with_one_slash_goes_split_and_any_other_name_encoded() {
    let mocked = on("1.12.1").await;
    mocked
        .respond(
            "GET",
            &format!("{CATALOG}/servers/io.github.acme/weather"),
            200,
            item("approved"),
        )
        .await;
    mocked
        .respond(
            "GET",
            &format!("{CATALOG}/servers/weather"),
            200,
            item("approved"),
        )
        .await;
    mocked
        .respond(
            "GET",
            &format!("{CATALOG}/servers/a%2Fb%2Fc"),
            200,
            item("approved"),
        )
        .await;

    let printed = mocked.json(&[
        "mcp",
        "catalog",
        "show",
        "--repo",
        REPO,
        "io.github.acme/weather",
    ]);
    assert_eq!(
        printed["x_new_field"], "kept",
        "the split route's body as sent"
    );
    mocked.json(&["mcp", "catalog", "show", "--repo", REPO, "weather"]);
    mocked.json(&["mcp", "catalog", "show", "--repo", REPO, "a/b/c"]);
    assert_eq!(
        paths(&mocked).await,
        vec![
            format!("GET {CATALOG}/servers/io.github.acme/weather"),
            format!("GET {CATALOG}/servers/weather"),
            format!("GET {CATALOG}/servers/a%2Fb%2Fc"),
        ]
    );

    let output = mocked.ak(&[
        "--format",
        "table",
        "mcp",
        "catalog",
        "show",
        "--repo",
        REPO,
        "io.github.acme/weather",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Transports:      streamable-http"),
        "{stdout}"
    );
    assert!(
        stdout.contains("1 block") || stdout.contains("0 block"),
        "{stdout}"
    );
}

#[tokio::test]
async fn approve_and_block_need_yes_and_send_the_reason() {
    for (verb, status) in [("approve", "approved"), ("block", "blocked")] {
        let mocked = on("1.12.1").await;
        let route = format!("{CATALOG}/{ID}/{verb}");
        mocked
            .respond("POST", &route, 200, decision(status, Value::Null))
            .await;

        let output = mocked.ak(&["mcp", "catalog", verb, "--repo", REPO, ID]);
        assert_eq!(output.status.code(), Some(2), "{verb}: {output:?}");
        assert!(unwrapped(&output.stderr).contains("--yes"));
        assert!(paths(&mocked).await.is_empty(), "{verb} sent something");

        let printed = mocked.json(&[
            "mcp", "catalog", verb, "--repo", REPO, ID, "--reason", "vetted", "--yes",
        ]);
        assert_eq!(printed["item"]["x_new_field"], "kept");
        let (_, body) = mocked.last("POST").await;
        assert_eq!(body, json!({"reason": "vetted"}), "{verb}");
        assert_eq!(paths(&mocked).await, vec![format!("POST {route}")]);
    }
}

#[tokio::test]
async fn reopen_asks_nothing() {
    let mocked = on("1.12.1").await;
    let route = format!("{CATALOG}/{ID}/reopen");
    mocked
        .respond("POST", &route, 200, decision("review", Value::Null))
        .await;
    let output = mocked.ak(&["mcp", "catalog", "reopen", "--repo", REPO, ID]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(paths(&mocked).await, vec![format!("POST {route}")]);
}

#[tokio::test]
async fn an_approval_whose_ingest_waits_says_so() {
    let mocked = on("1.12.1").await;
    let route = format!("{CATALOG}/{ID}/approve");
    mocked
        .respond(
            "POST",
            &route,
            200,
            decision("approved", json!("upstream unreachable")),
        )
        .await;
    let output = mocked.ak(&["mcp", "catalog", "approve", "--repo", REPO, ID, "--yes"]);
    assert!(output.status.success(), "{output:?}");
    let stderr = unwrapped(&output.stderr);
    assert!(
        stderr.contains("not ingested yet: upstream unreachable"),
        "{stderr}"
    );
}

#[tokio::test]
async fn request_approval_sends_the_note() {
    let mocked = on("1.12.1").await;
    let route = format!("{CATALOG}/{ID}/request-approval");
    mocked.respond("POST", &route, 200, item("pending")).await;
    let output = mocked.ak(&[
        "--format",
        "table",
        "mcp",
        "catalog",
        "request-approval",
        "--repo",
        REPO,
        ID,
        "--note",
        "for the weather bot",
    ]);
    assert!(output.status.success(), "{output:?}");
    let (_, body) = mocked.last("POST").await;
    assert_eq!(body, json!({"note": "for the weather bot"}));
    assert!(unwrapped(&output.stderr).contains("2 request(s)"));
}

#[tokio::test]
async fn bulk_approve_confirms_unless_a_dry_run() {
    let mocked = on("1.12.1").await;
    let route = format!("{CATALOG}/bulk-approve");
    mocked
        .respond(
            "POST",
            &route,
            200,
            json!({"approved": 2, "blocked": 0, "names": ["io.github.acme/a", "io.github.acme/b"],
                   "skippedDenied": 1, "skippedReview": 3, "dryRun": true}),
        )
        .await;

    let output = mocked.ak(&[
        "mcp",
        "catalog",
        "bulk-approve",
        "--repo",
        REPO,
        "io.github.acme/*",
    ]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(paths(&mocked).await.is_empty());

    let output = mocked.ak(&[
        "--format",
        "table",
        "mcp",
        "catalog",
        "bulk-approve",
        "--repo",
        REPO,
        "io.github.acme/*",
        "--dry-run",
        "--include-review",
    ]);
    assert!(output.status.success(), "{output:?}");
    let (_, body) = mocked.last("POST").await;
    assert_eq!(
        body,
        json!({"pattern": "io.github.acme/*", "dryRun": true, "includeReview": true})
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("io.github.acme/b"), "{stdout}");
    let stderr = unwrapped(&output.stderr);
    assert!(
        stderr.contains("Dry run: 2 name(s) would be approved"),
        "{stderr}"
    );
    assert!(stderr.contains("3 flagged for review"), "{stderr}");

    mocked.json(&[
        "mcp",
        "catalog",
        "bulk-approve",
        "--repo",
        REPO,
        "io.github.acme/*",
        "--reason",
        "team",
        "--yes",
    ]);
    let (_, body) = mocked.last("POST").await;
    assert_eq!(
        body,
        json!({"pattern": "io.github.acme/*", "reason": "team"})
    );
}

#[tokio::test]
async fn bulk_block_needs_yes() {
    let mocked = on("1.12.1").await;
    let route = format!("{CATALOG}/bulk-block");
    mocked
        .respond(
            "POST",
            &route,
            200,
            json!({"approved": 0, "blocked": 1, "names": ["com.evil/x"], "skippedDenied": 0,
                   "skippedReview": 0, "dryRun": false}),
        )
        .await;
    let output = mocked.ak(&["mcp", "catalog", "bulk-block", "--repo", REPO, "com.evil/*"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(paths(&mocked).await.is_empty());

    let output = mocked.ak(&[
        "--quiet",
        "mcp",
        "catalog",
        "bulk-block",
        "--repo",
        REPO,
        "com.evil/*",
        "--yes",
    ]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "com.evil/x");
}

#[tokio::test]
async fn bulk_decide_sends_the_ids_and_fails_on_ids_not_in_the_catalog() {
    let mocked = on("1.12.1").await;
    let route = format!("{CATALOG}/bulk-decide");
    mocked
        .respond(
            "POST",
            &route,
            200,
            json!({"action": "block", "decided": [ID], "unchanged": [], "skippedDenied": [],
                   "notFound": [OTHER]}),
        )
        .await;
    let output = mocked.ak(&[
        "mcp",
        "catalog",
        "bulk-decide",
        "--repo",
        REPO,
        "--action",
        "block",
        ID,
        OTHER,
    ]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(paths(&mocked).await.is_empty());

    let output = mocked.ak(&[
        "--format",
        "table",
        "mcp",
        "catalog",
        "bulk-decide",
        "--repo",
        REPO,
        "--action",
        "block",
        ID,
        OTHER,
        "--reason",
        "r",
        "--yes",
    ]);
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    assert!(
        unwrapped(&output.stderr).contains("1 ID(s) aren't rows of the catalog"),
        "{output:?}"
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("not found"));
    let (_, body) = mocked.last("POST").await;
    assert_eq!(
        body,
        json!({"action": "block", "ids": [ID, OTHER], "reason": "r"})
    );

    let output = mocked.ak(&[
        "mcp",
        "catalog",
        "bulk-decide",
        "--repo",
        REPO,
        "--action",
        "approve",
        "not-a-uuid",
        "--yes",
    ]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
}

#[tokio::test]
async fn pin_needs_yes_and_sends_the_version() {
    let mocked = on("1.12.1").await;
    let route = format!("{CATALOG}/pins");
    mocked
        .respond("POST", &route, 200, decision("approved", Value::Null))
        .await;
    let output = mocked.ak(&[
        "mcp",
        "catalog",
        "pin",
        "--repo",
        REPO,
        "io.github.acme/weather",
        "1.2.0",
    ]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(paths(&mocked).await.is_empty());

    mocked.json(&[
        "mcp",
        "catalog",
        "pin",
        "--repo",
        REPO,
        "io.github.acme/weather",
        "1.2.0",
        "--yes",
    ]);
    let (_, body) = mocked.last("POST").await;
    assert_eq!(
        body,
        json!({"name": "io.github.acme/weather", "version": "1.2.0"})
    );
}

// ---- sync and seed ----

#[tokio::test]
async fn sync_start_prints_how_to_follow_it() {
    let mocked = on("1.12.1").await;
    let route = "/api/v1/repositories/mcp-official/mcp/sync";
    mocked
        .respond(
            "POST",
            route,
            202,
            json!({"repository": REPO, "status": "running", "statusUrl": route}),
        )
        .await;
    let output = mocked.ak(&["--format", "table", "mcp", "sync", "start", "--repo", REPO]);
    assert!(output.status.success(), "{output:?}");
    assert!(
        unwrapped(&output.stderr).contains("ak mcp sync status --repo mcp-official --wait"),
        "{output:?}"
    );
    assert_eq!(paths(&mocked).await, vec![format!("POST {route}")]);
}

#[tokio::test]
async fn sync_wait_follows_the_pass_and_fails_on_its_error() {
    let mocked = on("1.12.1").await;
    let route = "/api/v1/repositories/mcp-official/mcp/sync";
    mocked
        .respond(
            "POST",
            route,
            202,
            json!({"repository": REPO, "status": "running", "statusUrl": route}),
        )
        .await;
    Mock::given(method("GET"))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"running": true})))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&mocked.server)
        .await;
    mocked
        .respond(
            "GET",
            route,
            200,
            json!({"running": false, "lastFinishedAt": AT, "lastError": "upstream 503",
                   "lastSummary": {"pages": 0, "complete": false, "errors": []}}),
        )
        .await;

    let output = mocked.ak(&[
        "--format", "json", "mcp", "sync", "start", "--repo", REPO, "--wait",
    ]);
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    assert!(unwrapped(&output.stderr).contains("upstream 503"));
    let printed: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(
        printed["lastError"], "upstream 503",
        "the final state as sent"
    );
    let sent = paths(&mocked).await;
    assert_eq!(
        sent.iter().filter(|p| p.starts_with("GET")).count(),
        2,
        "{sent:?}"
    );
}

#[tokio::test]
async fn sync_status_shows_the_last_pass() {
    let mocked = on("1.12.1").await;
    let route = "/api/v1/repositories/mcp-official/mcp/sync";
    mocked
        .respond(
            "GET",
            route,
            200,
            json!({"running": false, "lastStartedAt": AT, "lastFinishedAt": AT,
                   "lastSucceededAt": AT, "lastError": null,
                   "lastSummary": {"pages": 3, "entries": 120, "namesNew": 7, "autoApproved": 2,
                                   "flagged": 1, "ingested": 2, "drifted": 0, "unresolved": 0,
                                   "complete": true, "errors": []}}),
        )
        .await;
    let output = mocked.ak(&["--format", "table", "mcp", "sync", "status", "--repo", REPO]);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("3 page(s), 120 entries, 7 new name(s)"),
        "{stdout}"
    );
    assert!(stdout.contains("Reached the end: yes"), "{stdout}");
}

#[tokio::test]
async fn seed_start_needs_yes_and_name_at_version() {
    let mocked = on("1.12.1").await;
    let route = "/api/v1/repositories/mcp-official/mcp/seed";
    mocked
        .respond(
            "POST",
            route,
            202,
            json!({"jobId": JOB, "repository": REPO, "status": "pending", "total": 2,
                   "statusUrl": format!("{route}/{JOB}")}),
        )
        .await;

    let servers = ["io.github.acme/weather@1.2.0", "io.github.acme/tide@2.0.0"];
    let mut args = vec!["--format", "table", "mcp", "seed", "start", "--repo", REPO];
    args.extend(servers);
    let output = mocked.ak(&args);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(paths(&mocked).await.is_empty());

    let output = mocked.ak(&[
        "mcp",
        "seed",
        "start",
        "--repo",
        REPO,
        "io.github.acme/weather",
        "--yes",
    ]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(unwrapped(&output.stderr).contains("NAME@VERSION"));
    assert!(paths(&mocked).await.is_empty());

    args.extend(["--reason", "lab seed", "--yes"]);
    let output = mocked.ak(&args);
    assert!(output.status.success(), "{output:?}");
    let (_, body) = mocked.last("POST").await;
    assert_eq!(
        body,
        json!({"reason": "lab seed", "servers": [
            {"name": "io.github.acme/weather", "version": "1.2.0"},
            {"name": "io.github.acme/tide", "version": "2.0.0"}]})
    );
    let stderr = unwrapped(&output.stderr);
    assert!(
        stderr.contains(&format!(
            "ak mcp seed status --repo mcp-official {JOB} --wait"
        )),
        "{stderr}"
    );
}

#[tokio::test]
async fn seed_wait_fails_when_a_version_was_not_pinned() {
    let mocked = on("1.12.1").await;
    let route = "/api/v1/repositories/mcp-official/mcp/seed";
    let job = format!("{route}/{JOB}");
    mocked
        .respond(
            "POST",
            route,
            202,
            json!({"jobId": JOB, "repository": REPO, "status": "pending", "total": 2,
                   "statusUrl": job}),
        )
        .await;
    Mock::given(method("GET"))
        .and(path(job.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"jobId": JOB, "repository": REPO, "status": "running", "createdAt": AT,
                   "items": []}),
        ))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&mocked.server)
        .await;
    mocked
        .respond(
            "GET",
            &job,
            200,
            json!({"jobId": JOB, "repository": REPO, "status": "completed", "createdAt": AT,
                   "items": [
                       {"name": "io.github.acme/weather", "version": "1.2.0", "state": "pinned"},
                       {"name": "io.github.acme/tide", "version": "2.0.0", "state": "refused",
                        "reason": "upstream lists 1.0.0"}]}),
        )
        .await;

    let output = mocked.ak(&[
        "--format",
        "table",
        "mcp",
        "seed",
        "start",
        "--repo",
        REPO,
        "io.github.acme/weather@1.2.0",
        "io.github.acme/tide@2.0.0",
        "--wait",
        "--yes",
    ]);
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    assert!(
        unwrapped(&output.stderr).contains("io.github.acme/tide@2.0.0"),
        "{output:?}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("upstream lists 1.0.0"), "{stdout}");
}

#[tokio::test]
async fn seed_status_prints_the_job_as_sent() {
    let mocked = on("1.12.1").await;
    let job = format!("/api/v1/repositories/mcp-official/mcp/seed/{JOB}");
    mocked
        .respond(
            "GET",
            &job,
            200,
            json!({"jobId": JOB, "repository": REPO, "status": "running", "createdAt": AT,
                   "items": [], "x_new_field": "kept"}),
        )
        .await;
    let printed = mocked.json(&["mcp", "seed", "status", "--repo", REPO, JOB]);
    assert_eq!(printed["x_new_field"], "kept");
}

// ---- health and the queue ----

#[tokio::test]
async fn health_goes_split_for_a_name_with_one_slash() {
    let mocked = on("1.12.1").await;
    let split = "/api/v1/repositories/mcp-local/mcp/servers/com.acme/weather/versions/1.2.0/health";
    let encoded = "/api/v1/repositories/mcp-local/mcp/servers/weather/versions/1.2.0/health";
    let health = json!({
        "name": "com.acme/weather", "version": "1.2.0", "artifactId": ID, "status": "warning",
        "packagePolicy": "own-repos",
        "packages": [{"index": 0, "package": "npm:@acme/weather-mcp@1.2.0", "registryType": "npm",
                      "repository": "npm-local", "scanned": true, "score": 97, "grade": "A",
                      "critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0,
                      "gate": "allowed", "status": "warning"}],
        "lint": {"ran": true, "block": 0, "review": 1, "warn": 0, "findings": [
            {"id": OTHER, "rule": "secret_unmarked", "action": "review", "severity": "high",
             "path": "packages[0].environmentVariables[0].isSecret", "acknowledged": false}]},
        "x_new_field": "kept"
    });
    mocked.respond("GET", split, 200, health.clone()).await;
    mocked.respond("GET", encoded, 200, health).await;

    let printed = mocked.json(&[
        "mcp",
        "health",
        "--repo",
        "mcp-local",
        "com.acme/weather",
        "1.2.0",
        "--include-deleted",
    ]);
    assert_eq!(printed["x_new_field"], "kept");
    let (query, _) = mocked.last("GET").await;
    assert_eq!(
        query,
        vec![("include_deleted".to_string(), "true".to_string())]
    );

    let output = mocked.ak(&[
        "--format",
        "table",
        "mcp",
        "health",
        "--repo",
        "mcp-local",
        "weather",
        "1.2.0",
    ]);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("npm:@acme/weather-mcp@1.2.0"), "{stdout}");
    assert!(stdout.contains("secret_unmarked"), "{stdout}");
    assert_eq!(
        paths(&mocked).await,
        vec![format!("GET {split}"), format!("GET {encoded}")]
    );
}

#[tokio::test]
async fn pending_counts_the_queue() {
    let mocked = on("1.12.1").await;
    mocked
        .respond(
            "GET",
            "/api/v1/mcp/pending-summary",
            200,
            json!({"pending": 3, "review": 1, "drifted": 1, "total": 5,
                   "repositories": [{"key": REPO, "pending": 3, "review": 1, "drifted": 1}]}),
        )
        .await;
    let output = mocked.ak(&["--format", "table", "mcp", "pending"]);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("5 waiting: 3 pending, 1 for review, 1 drifted"),
        "{stdout}"
    );
    assert!(stdout.contains(REPO), "{stdout}");
    let output = mocked.ak(&["--quiet", "mcp", "pending"]);
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "5");
}

// ---- a 1.11 server ----

#[tokio::test]
async fn on_1_11_each_command_says_it_needs_1_12() {
    let mocked = on("1.11.14").await;
    let cases: &[&[&str]] = &[
        &["mcp", "pending"],
        &["mcp", "namespace-proof", "list"],
        &["mcp", "catalog", "list", "--repo", REPO],
        &[
            "mcp",
            "catalog",
            "show",
            "--repo",
            REPO,
            "io.github.acme/weather",
        ],
        &["mcp", "catalog", "approve", "--repo", REPO, ID, "--yes"],
        &["mcp", "sync", "status", "--repo", REPO],
        &["mcp", "health", "--repo", REPO, "com.acme/weather", "1.0.0"],
    ];
    for args in cases {
        let output = mocked.ak(args);
        assert_eq!(output.status.code(), Some(6), "{args:?}: {output:?}");
        let stderr = failed(&output);
        let command = args
            .iter()
            .take_while(|a| !a.starts_with('-'))
            .take(if args[1] == "pending" || args[1] == "health" {
                2
            } else {
                3
            })
            .copied()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            stderr.contains(&format!(
                "`ak {command}` needs a server on 1.12 or newer. This one is 1.11.14"
            )),
            "{args:?}: {stderr}"
        );
    }
}

#[tokio::test]
async fn seed_wait_ends_at_a_status_it_does_not_know() {
    let mocked = on("1.12.1").await;
    let job = format!("/api/v1/repositories/mcp-official/mcp/seed/{JOB}");
    // No createdAt: a body the SDK's type doesn't fit is still the job.
    mocked
        .respond(
            "GET",
            &job,
            200,
            json!({"jobId": JOB, "repository": REPO, "status": "cancelled", "items": []}),
        )
        .await;
    let output = mocked.ak(&["mcp", "seed", "status", "--repo", REPO, JOB, "--wait"]);
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    assert!(
        unwrapped(&output.stderr).contains("ended cancelled"),
        "{output:?}"
    );
    assert_eq!(paths(&mocked).await.len(), 1, "one look, no polling");
}
