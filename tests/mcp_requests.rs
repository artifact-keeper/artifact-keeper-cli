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

/// The server lets go of the sync lock before it records a failed pass, so "not
/// running" with the previous pass's state isn't the end of this one.
#[tokio::test]
async fn sync_wait_waits_for_the_pass_to_be_recorded() {
    let mocked = on("1.12.1").await;
    let route = "/api/v1/repositories/mcp-official/mcp/sync";
    let earlier = "2026-01-15T11:00:00Z";
    mocked
        .respond(
            "POST",
            route,
            202,
            json!({"repository": REPO, "status": "running", "statusUrl": route}),
        )
        .await;
    // Read before the trigger, then once more after it, before the failure lands.
    Mock::given(method("GET"))
        .and(path(route))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                json!({"running": false, "lastFinishedAt": earlier, "lastError": null}),
            ),
        )
        .up_to_n_times(2)
        .with_priority(1)
        .mount(&mocked.server)
        .await;
    mocked
        .respond(
            "GET",
            route,
            200,
            json!({"running": false, "lastFinishedAt": AT, "lastError": "database: gone"}),
        )
        .await;

    let output = mocked.ak(&[
        "--format", "json", "mcp", "sync", "start", "--repo", REPO, "--wait",
    ]);
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    assert!(
        unwrapped(&output.stderr).contains("database: gone"),
        "{output:?}"
    );
    let sent = paths(&mocked).await;
    assert_eq!(
        sent,
        vec![
            format!("GET {route}"),
            format!("POST {route}"),
            format!("GET {route}"),
            format!("GET {route}"),
        ]
    );
}

#[tokio::test]
async fn health_refuses_a_name_or_version_that_would_reach_another_route() {
    let mocked = on("1.12.1").await;
    for (server, version) in [
        ("../x", "1.0.0"),
        ("com.acme/..", "1.0.0"),
        ("com.acme/w%2F", "1.0.0"),
        ("com.acme/w", ".."),
    ] {
        let output = mocked.ak(&["mcp", "health", "--repo", "r", server, version]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{server} {version}: {output:?}"
        );
    }
    let output = mocked.ak(&["mcp", "catalog", "show", "--repo", "r", "com.acme/.."]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(paths(&mocked).await.is_empty());
}

#[tokio::test]
async fn reopen_takes_yes_and_ignores_it() {
    let mocked = on("1.12.1").await;
    let route = format!("{CATALOG}/{ID}/reopen");
    mocked
        .respond("POST", &route, 200, decision("review", Value::Null))
        .await;
    let output = mocked.ak(&["mcp", "catalog", "reopen", "--repo", REPO, ID, "--yes"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(paths(&mocked).await, vec![format!("POST {route}")]);
}

// ---- one version on the registry's own routes ----

const SERVERS: &str = "/mcp/mcp-local/v0.1/servers";

/// A served entry, as the registry's write routes answer.
fn entry(name: &str, version: &str, status: &str) -> Value {
    json!({
        "server": {"name": name, "version": version, "description": "d"},
        "_meta": {
            "io.modelcontextprotocol.registry/official": {"status": status, "isLatest": false},
            "com.artifactkeeper.registry/source": {"repository": "mcp-local"}
        },
        "x_new_field": "kept"
    })
}

#[tokio::test]
async fn version_status_sends_the_status_and_message() {
    let mocked = on("1.12.1").await;
    let route = format!("{SERVERS}/io.github.acme/weather/versions/1.0.0/status");
    mocked
        .respond(
            "PATCH",
            &route,
            200,
            entry("io.github.acme/weather", "1.0.0", "deprecated"),
        )
        .await;

    let printed = mocked.json(&[
        "mcp",
        "version",
        "status",
        "--repo",
        "mcp-local",
        "io.github.acme/weather",
        "1.0.0",
        "--status",
        "deprecated",
        "--message",
        "use 2.x",
    ]);
    assert_eq!(printed["x_new_field"], "kept", "the body as sent");
    let (_, body) = mocked.last("PATCH").await;
    assert_eq!(
        body,
        json!({"status": "deprecated", "statusMessage": "use 2.x"})
    );

    let output = mocked.ak(&[
        "--format",
        "table",
        "mcp",
        "version",
        "status",
        "--repo",
        "mcp-local",
        "io.github.acme/weather",
        "1.0.0",
        "--status",
        "deprecated",
    ]);
    assert!(output.status.success(), "{output:?}");
    assert!(
        unwrapped(&output.stderr)
            .contains("io.github.acme/weather@1.0.0 in 'mcp-local' is now deprecated."),
        "{output:?}"
    );
    let (_, body) = mocked.last("PATCH").await;
    assert_eq!(
        body,
        json!({"status": "deprecated"}),
        "no message unless given"
    );
}

#[tokio::test]
async fn version_status_without_a_version_changes_the_whole_server() {
    let mocked = on("1.12.1").await;
    let route = format!("{SERVERS}/io.github.acme/weather/status");
    mocked
        .respond(
            "PATCH",
            &route,
            200,
            json!({"updatedCount": 2, "servers": [
                entry("io.github.acme/weather", "1.0.0", "deprecated"),
                entry("io.github.acme/weather", "1.2.0", "deprecated"),
            ]}),
        )
        .await;

    let output = mocked.ak(&[
        "--format",
        "quiet",
        "mcp",
        "version",
        "status",
        "--repo",
        "mcp-local",
        "io.github.acme/weather",
        "--status",
        "deprecated",
    ]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "io.github.acme/weather@1.0.0\nio.github.acme/weather@1.2.0\n"
    );
    assert_eq!(paths(&mocked).await, vec![format!("PATCH {route}")]);
}

#[tokio::test]
async fn version_status_deleted_needs_yes_and_active_takes_no_message() {
    let mocked = on("1.12.1").await;
    let route = format!("{SERVERS}/weather/versions/1.0.0/status");
    mocked
        .respond("PATCH", &route, 200, entry("weather", "1.0.0", "deleted"))
        .await;
    let base = [
        "mcp",
        "version",
        "status",
        "--repo",
        "mcp-local",
        "weather",
        "1.0.0",
    ];

    let output = mocked.ak(&[&base[..], &["--status", "deleted"]].concat());
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(unwrapped(&output.stderr).contains("--yes"), "{output:?}");
    assert!(paths(&mocked).await.is_empty());

    let output = mocked.ak(&[&base[..], &["--status", "active", "--message", "m"]].concat());
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(paths(&mocked).await.is_empty());

    mocked.json(&[&base[..], &["--status", "deleted", "--yes"]].concat());
    assert_eq!(
        paths(&mocked).await,
        vec![format!("PATCH {route}")],
        "a name with no slash goes as one segment"
    );
}

#[tokio::test]
async fn version_delete_needs_yes_and_sends_the_message() {
    let mocked = on("1.12.1").await;
    let route = format!("{SERVERS}/io.github.acme/weather/versions/1.0.0");
    mocked
        .respond(
            "DELETE",
            &route,
            200,
            entry("io.github.acme/weather", "1.0.0", "deleted"),
        )
        .await;
    let base = [
        "mcp",
        "version",
        "delete",
        "--repo",
        "mcp-local",
        "io.github.acme/weather",
        "1.0.0",
    ];

    let output = mocked.ak(&base);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(unwrapped(&output.stderr).contains("--yes"));
    assert!(paths(&mocked).await.is_empty());

    let output = mocked.ak(&[&base[..], &["--message", "malicious", "-y", "-q"]].concat());
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "io.github.acme/weather@1.0.0\n"
    );
    let (_, body) = mocked.last("DELETE").await;
    assert_eq!(body, json!({"statusMessage": "malicious"}));
    assert_eq!(paths(&mocked).await, vec![format!("DELETE {route}")]);
}

#[tokio::test]
async fn version_purge_needs_yes_and_says_what_stays_pinned() {
    let mocked = on("1.12.1").await;
    let route = format!("{SERVERS}/io.github.acme/weather/versions/1.0.0/purge");
    mocked
        .respond(
            "POST",
            &route,
            200,
            json!({
                "server": "io.github.acme/weather", "version": "1.0.0", "purged": true,
                "trashed": ["servers/io.github.acme/weather/1.0.0/server.json"],
                "releasedDigests": [{"repository_id": ID, "image": "acme/weather",
                    "digest": "sha256:aa", "still_pinned": true}]
            }),
        )
        .await;
    let base = [
        "mcp",
        "version",
        "purge",
        "--repo",
        "mcp-local",
        "io.github.acme/weather",
        "1.0.0",
    ];

    let output = mocked.ak(&base);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = unwrapped(&output.stderr);
    assert!(stderr.contains("--yes"), "{stderr}");
    assert!(stderr.contains("confirmation_refused"), "{stderr}");
    assert!(paths(&mocked).await.is_empty(), "nothing is sent");

    let printed = mocked.json(&[&base[..], &["--yes"]].concat());
    assert_eq!(printed["purged"], true);
    let body = mocked.last_body("POST").await;
    assert!(body.is_empty(), "a purge sends no body");

    let output = mocked.ak(&[&["--format", "table"], &base[..], &["--yes"]].concat());
    assert!(output.status.success(), "{output:?}");
    let stderr = unwrapped(&output.stderr);
    assert!(
        stderr.contains("Purged io.github.acme/weather@1.0.0 from 'mcp-local': 1 file(s)"),
        "{stderr}"
    );
    assert!(stderr.contains("sha256:aa is still pinned"), "{stderr}");
}

/// A refusal as the registry's routes write one (`problem_body`): the code in
/// `error`, the explanation in `detail`.
fn problem(status: u16, title: &str, code: &str, detail: &str) -> Value {
    json!({"type": "about:blank", "title": title, "status": status, "detail": detail,
           "error": code})
}

#[tokio::test]
async fn a_purge_the_server_refuses_shows_its_explanation() {
    let mocked = on("1.12.1").await;
    let route = format!("{SERVERS}/io.github.acme/weather/versions/1.0.0/purge");
    let detail = "Only a deleted server version can be purged: delete it first with \
                  DELETE .../servers/{serverName}/versions/{version}";
    let mut body = problem(409, "Conflict", "mcp_version_not_deleted", detail);
    body["status_now"] = json!("active");
    mocked.respond("POST", &route, 409, body).await;
    let output = mocked.ak(&[
        "mcp",
        "version",
        "purge",
        "--repo",
        "mcp-local",
        "io.github.acme/weather",
        "1.0.0",
        "--yes",
    ]);
    let stderr = failed(&output);
    assert!(
        stderr.contains(
            "mcp_version_not_deleted: Only a deleted server version can be purged: delete it \
             first"
        ),
        "{stderr}"
    );
}

#[tokio::test]
async fn a_probe_with_introspection_off_says_why() {
    let mocked = on("1.12.1").await;
    let route = format!("{SERVERS}/io.github.acme/weather/versions/1.0.0/capabilities/probe");
    mocked
        .respond(
            "POST",
            &route,
            409,
            problem(
                409,
                "Conflict",
                "mcp_introspection_disabled",
                "Introspection is off for this repository (mcp_probe_remotes, \
                 mcp_sandbox_introspection)",
            ),
        )
        .await;
    let output = mocked.ak(&[
        "mcp",
        "version",
        "probe",
        "--repo",
        "mcp-local",
        "io.github.acme/weather",
        "1.0.0",
    ]);
    let stderr = failed(&output);
    assert!(
        stderr.contains("mcp_introspection_disabled: Introspection is off for this repository"),
        "{stderr}"
    );
}

#[tokio::test]
async fn a_version_a_1_12_server_does_not_have_is_not_found() {
    let mocked = on("1.12.1").await;
    let route = format!("{SERVERS}/io.github.acme/weather/versions/9.9.9/purge");
    mocked
        .respond(
            "POST",
            &route,
            404,
            json!({"detail": "Server not found", "status": 404, "title": "Not Found",
                   "type": "about:blank"}),
        )
        .await;
    let output = mocked.ak(&[
        "mcp",
        "version",
        "purge",
        "--repo",
        "mcp-local",
        "io.github.acme/weather",
        "9.9.9",
        "--yes",
    ]);
    assert_eq!(output.status.code(), Some(5), "{output:?}");
    let stderr = failed(&output);
    assert!(stderr.contains("Server not found"), "{stderr}");
    assert!(!stderr.contains("needs a server on"), "{stderr}");
}

#[tokio::test]
async fn a_name_without_one_slash_goes_as_one_encoded_segment() {
    let mocked = on("1.12.1").await;
    let delete = format!("{SERVERS}/a%2Fb%2Fc/versions/1.0.0");
    let probe = format!("{SERVERS}/weather/versions/1.0.0/capabilities/probe");
    mocked
        .respond("DELETE", &delete, 200, entry("a/b/c", "1.0.0", "deleted"))
        .await;
    mocked
        .respond("POST", &probe, 202, json!({"queued": [], "jobs": []}))
        .await;

    let output = mocked.ak(&[
        "-q",
        "mcp",
        "version",
        "delete",
        "--repo",
        "mcp-local",
        "a/b/c",
        "1.0.0",
        "--yes",
    ]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), "a/b/c@1.0.0\n");
    mocked.json(&[
        "mcp",
        "version",
        "probe",
        "--repo",
        "mcp-local",
        "weather",
        "1.0.0",
    ]);
    assert_eq!(
        paths(&mocked).await,
        vec![format!("DELETE {delete}"), format!("POST {probe}")]
    );
}

#[tokio::test]
async fn version_edit_puts_the_document_at_its_own_name() {
    let mocked = on("1.12.1").await;
    let route = format!("{SERVERS}/io.github.acme/weather/versions/1.2.0");
    mocked
        .respond(
            "PUT",
            &route,
            200,
            entry("io.github.acme/weather", "1.2.0", "active"),
        )
        .await;
    let doc = r#"{"name":"io.github.acme/weather","version":"1.2.0","description":"new"}"#;
    let dir = tempfile::TempDir::new().expect("temp dir");
    let file = dir.path().join("server.json");
    std::fs::write(&file, doc).expect("write");
    let at_file = format!("@{}", file.display());

    let printed = mocked.json(&[
        "mcp",
        "version",
        "edit",
        "--repo",
        "mcp-local",
        "--document",
        &at_file,
    ]);
    assert_eq!(printed["x_new_field"], "kept");
    assert_eq!(
        mocked.last_body("PUT").await,
        doc.as_bytes(),
        "the document as given"
    );
    assert_eq!(paths(&mocked).await, vec![format!("PUT {route}")]);

    let output = mocked.ak(&[
        "mcp",
        "version",
        "edit",
        "--repo",
        "mcp-local",
        "--document",
        r#"{"name":"io.github.acme/weather"}"#,
    ]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(
        unwrapped(&output.stderr).contains("no \"version\" string"),
        "{output:?}"
    );
}

#[tokio::test]
async fn version_probe_lists_the_queued_jobs() {
    let mocked = on("1.12.1").await;
    let route = format!("{SERVERS}/io.github.acme/weather/versions/1.0.0/capabilities/probe");
    mocked
        .respond(
            "POST",
            &route,
            202,
            json!({"queued": [JOB], "jobs": [{
                "id": JOB, "kind": "remote_probe", "target": "https://weather.example/mcp",
                "status": "pending", "attempts": 0, "maxAttempts": 3}]}),
        )
        .await;
    let base = [
        "mcp",
        "version",
        "probe",
        "--repo",
        "mcp-local",
        "io.github.acme/weather",
        "1.0.0",
    ];

    let output = mocked.ak(&[&["-q"], &base[..]].concat());
    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), format!("{JOB}\n"));

    let output = mocked.ak(&[&["--format", "table"], &base[..]].concat());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Queued 1 introspection job(s) for io.github.acme/weather@1.0.0."),
        "{stdout}"
    );
    assert!(stdout.contains("remote_probe"), "{stdout}");
}

#[tokio::test]
async fn on_1_11_each_version_command_says_it_needs_1_12() {
    let mocked = on("1.11.14").await;
    let doc = r#"{"name":"io.github.acme/weather","version":"1.0.0"}"#;
    let cases: &[(&str, &[&str])] = &[
        (
            "status",
            &["io.github.acme/weather", "1.0.0", "--status", "deprecated"],
        ),
        ("delete", &["io.github.acme/weather", "1.0.0", "--yes"]),
        ("purge", &["io.github.acme/weather", "1.0.0", "--yes"]),
        ("edit", &["--document", doc]),
        ("probe", &["io.github.acme/weather", "1.0.0"]),
    ];
    for (command, rest) in cases {
        let args = [
            &["mcp", "version", command, "--repo", "mcp-local"][..],
            rest,
        ]
        .concat();
        let output = mocked.ak(&args);
        assert_eq!(output.status.code(), Some(6), "{args:?}: {output:?}");
        let stderr = failed(&output);
        assert!(
            stderr.contains(&format!(
                "`ak mcp version {command}` needs a server on 1.12 or newer. This one is 1.11.14"
            )),
            "{args:?}: {stderr}"
        );
    }
}
