//! E2E tests for `ak mcp` against a real backend: a version's health on a Local MCP
//! registry, namespace proofs, and a Remote registry's sync, catalog, decisions and
//! seed jobs.
//!
//! Requires the E2E backend: ./tests/start-backend.sh, with
//! UPSTREAM_ALLOW_PRIVATE_IPS=true and the network alias `ak-upstream`.
//!
//! `ak mcp` is the management API only, so a server gets into a Local registry by a
//! raw publish through `ak api`. A Remote registry's upstream here is a public Local
//! registry of this same backend (`http://ak-upstream:8080/mcp/<key>`): another
//! Artifact Keeper is one of the upstreams a Remote takes. Every server has only
//! `remotes`, no `packages`, so no backing package repositories are needed.
//!
//! On a 1.11 server, which has no MCP registries, the 1.12 tests skip and say so,
//! and one test checks that the commands refuse.

mod common;

use common::TestEnv;
use serde_json::{Value, json};

/// Deletes the repositories when dropped, Remotes first, so each test cleans up
/// after itself.
struct RepoGuard {
    url: String,
    token: String,
    keys: Vec<String>,
}

impl RepoGuard {
    fn new(env: &TestEnv) -> Self {
        RepoGuard {
            url: env.url.clone(),
            token: env.token.clone(),
            keys: Vec::new(),
        }
    }
}

impl Drop for RepoGuard {
    fn drop(&mut self) {
        for key in self.keys.iter().rev() {
            let _ = reqwest::blocking::Client::new()
                .delete(format!("{}/api/v1/repositories/{key}", self.url))
                .bearer_auth(&self.token)
                .send();
        }
    }
}

/// Deletes namespace proofs when dropped, for a test that fails before it deletes
/// them itself. A proof already deleted answers 404, which is fine.
struct ProofGuard {
    url: String,
    token: String,
    ids: Vec<String>,
}

impl Drop for ProofGuard {
    fn drop(&mut self) {
        for id in &self.ids {
            let _ = reqwest::blocking::Client::new()
                .delete(format!(
                    "{}/api/v1/admin/mcp/namespace-proofs/{id}",
                    self.url
                ))
                .bearer_auth(&self.token)
                .send();
        }
    }
}

fn unique(prefix: &str) -> String {
    format!(
        "{prefix}-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    )
}

/// A namespace of this run's own, so names never meet another run's.
fn namespace() -> String {
    format!(
        "com.example.e2e{}",
        &uuid::Uuid::new_v4().simple().to_string()[..10]
    )
}

fn json_of(output: &[u8]) -> Value {
    serde_json::from_slice(output)
        .unwrap_or_else(|e| panic!("not JSON ({e}): {}", String::from_utf8_lossy(output)))
}

fn run_json(env: &TestEnv, args: &[&str]) -> Value {
    let output = env.ak_cmd().args(args).output().expect("run ak");
    assert!(
        output.status.success(),
        "ak {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    json_of(&output.stdout)
}

/// Table output (stdout isn't a terminal, so it has to be asked for), and stderr.
fn run_table(env: &TestEnv, args: &[&str]) -> (String, String) {
    let output = env
        .ak_cmd_table()
        .args(["--format", "table"])
        .args(args)
        .output()
        .expect("run ak");
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(output.status.success(), "ak {args:?} failed: {stderr}");
    (String::from_utf8_lossy(&output.stdout).to_string(), stderr)
}

/// Run a command that has to fail, and give its exit code and stderr.
fn run_failing(env: &TestEnv, args: &[&str]) -> (i32, String, String) {
    let output = env.ak_cmd().args(args).output().expect("run ak");
    assert!(!output.status.success(), "ak {args:?} succeeded");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

/// A Local MCP registry, made public when `public` so a Remote of this backend can
/// read it without credentials.
fn local_repo(env: &TestEnv, guard: &mut RepoGuard, public: bool) -> String {
    let key = unique("e2e-mcp-local");
    let mut args = vec![
        "repo",
        "create",
        &key,
        "--pkg-format",
        "mcp",
        "--repo-type",
        "local",
    ];
    if public {
        args.push("--public");
    }
    run_json(env, &args);
    guard.keys.push(key.clone());
    key
}

/// A Remote MCP registry whose upstream is `local`, served by this same backend.
fn remote_repo(env: &TestEnv, guard: &mut RepoGuard, local: &str) -> String {
    let key = unique("e2e-mcp-remote");
    let upstream = format!("http://ak-upstream:8080/mcp/{local}");
    let created = run_json(
        env,
        &[
            "repo",
            "create",
            &key,
            "--pkg-format",
            "mcp",
            "--repo-type",
            "remote",
            "--upstream-url",
            &upstream,
        ],
    );
    assert_eq!(created["repo_type"], "remote", "{created}");
    guard.keys.push(key.clone());
    key
}

/// Publish a server.json with one streamable-http remote and no packages, through
/// the registry's own publish route.
fn publish(env: &TestEnv, repo: &str, name: &str, version: &str) -> Value {
    let doc = json!({
        "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
        "name": name,
        "description": "E2E server",
        "version": version,
        "remotes": [{"type": "streamable-http", "url": "https://mcp.example.test/mcp"}],
    })
    .to_string();
    let published = run_json(
        env,
        &[
            "api",
            "POST",
            &format!("/mcp/{repo}/v0.1/publish"),
            "--body",
            &doc,
        ],
    );
    assert_eq!(published["server"]["name"], name, "{published}");
    published
}

/// The catalog row of `name` in `remote`.
fn catalog_row(env: &TestEnv, remote: &str, name: &str) -> Value {
    run_json(env, &["mcp", "catalog", "show", "--repo", remote, name])
}

fn row_id(row: &Value) -> String {
    row["id"].as_str().expect("row without id").to_string()
}

// ---- health on a Local registry ----

#[test]
#[ignore = "requires E2E backend"]
fn health_of_a_published_version() {
    let env = TestEnv::setup();
    if common::server_older_than(1, 12, "MCP registries") {
        return;
    }
    let mut guard = RepoGuard::new(&env);
    let repo = local_repo(&env, &mut guard, false);
    let ns = namespace();
    let name = format!("{ns}/weather");
    let published = publish(&env, &repo, &name, "1.0.0");
    let artifact = &published["_meta"]["com.artifactkeeper.registry/source"]["artifactId"];

    // JSON is the server's body: the split route, since the name has one slash.
    let health = run_json(&env, &["mcp", "health", "--repo", &repo, &name, "1.0.0"]);
    assert_eq!(health["name"], name.as_str(), "{health}");
    assert_eq!(health["version"], "1.0.0", "{health}");
    assert_eq!(&health["artifactId"], artifact, "{health}");
    assert_eq!(health["packagePolicy"], "own-repos", "{health}");
    assert_eq!(health["packages"], json!([]), "{health}");
    assert!(health["status"].is_string(), "{health}");
    assert!(health["lint"]["ran"].is_boolean(), "{health}");

    // The same answer as the server gives the URL-encoded route.
    let encoded: Value = env
        .api_client()
        .get(format!(
            "{}/api/v1/repositories/{repo}/mcp/servers/{}/versions/1.0.0/health",
            env.url,
            name.replace('/', "%2F")
        ))
        .bearer_auth(&env.token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(health, encoded);

    let (table, _) = run_table(&env, &["mcp", "health", "--repo", &repo, &name, "1.0.0"]);
    assert!(
        table.contains(&format!("Server:         {name}@1.0.0")),
        "{table}"
    );
    assert!(table.contains("Package policy: own-repos"), "{table}");
    assert!(table.contains("Lint:"), "{table}");

    // An unknown version is not found.
    let (code, _, stderr) = run_failing(&env, &["mcp", "health", "--repo", &repo, &name, "9.9.9"]);
    assert_eq!(code, 5, "{stderr}");

    // A soft-deleted version answers only with --include-deleted.
    publish(&env, &repo, &name, "1.1.0");
    let deleted = run_json(
        &env,
        &[
            "api",
            "DELETE",
            &format!(
                "/mcp/{repo}/v0.1/servers/{}/versions/1.1.0",
                name.replace('/', "%2F")
            ),
        ],
    );
    assert_eq!(
        deleted["_meta"]["io.modelcontextprotocol.registry/official"]["status"], "deleted",
        "{deleted}"
    );
    let (code, _, stderr) = run_failing(&env, &["mcp", "health", "--repo", &repo, &name, "1.1.0"]);
    assert_eq!(code, 5, "{stderr}");
    let health = run_json(
        &env,
        &[
            "mcp",
            "health",
            "--repo",
            &repo,
            &name,
            "1.1.0",
            "--include-deleted",
        ],
    );
    assert_eq!(health["version"], "1.1.0", "{health}");
}

// ---- namespace proofs ----

#[test]
#[ignore = "requires E2E backend"]
fn namespace_proof_lifecycle() {
    let env = TestEnv::setup();
    if common::server_older_than(1, 12, "MCP namespace proofs") {
        return;
    }
    // A namespace of its own: proofs aren't per repository, and this one is deleted
    // at the end.
    let mut guard = ProofGuard {
        url: env.url.clone(),
        token: env.token.clone(),
        ids: Vec::new(),
    };
    let ns = namespace();
    let domain = ns.split('.').rev().collect::<Vec<_>>().join(".");

    let dns = run_json(
        &env,
        &["mcp", "namespace-proof", "create", &ns, "--method", "dns"],
    );
    assert_eq!(dns["namespace"], ns.as_str(), "{dns}");
    assert_eq!(dns["domain"], domain.as_str(), "{dns}");
    assert_eq!(dns["method"], "dns", "{dns}");
    assert_eq!(dns["status"], "pending", "{dns}");
    assert_eq!(dns["challenge"]["type"], "TXT", "{dns}");
    assert_eq!(
        dns["challenge"]["name"],
        format!("_ak-mcp-challenge.{domain}").as_str(),
        "{dns}"
    );
    let dns_id = row_id(&dns);
    guard.ids.push(dns_id.clone());

    // The table says what to publish, and how to check it.
    let (table, stderr) = run_table(
        &env,
        &["mcp", "namespace-proof", "create", &ns, "--method", "http"],
    );
    assert!(
        table.contains(&format!(
            "Serve https://{domain}/.well-known/ak-mcp-challenge"
        )),
        "{table}"
    );
    assert!(
        table.contains("with this line:    ak-mcp-verification="),
        "{table}"
    );
    assert!(
        stderr.contains("Then check it: ak mcp namespace-proof verify "),
        "{stderr}"
    );
    let http_id = table
        .lines()
        .find_map(|l| l.strip_prefix("ID:"))
        .expect("no ID line")
        .trim()
        .to_string();
    guard.ids.push(http_id.clone());

    let listed = run_json(&env, &["mcp", "namespace-proof", "list"]);
    let mine: Vec<&Value> = listed["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["namespace"] == ns.as_str())
        .collect();
    assert_eq!(mine.len(), 2, "{listed}");

    let shown = run_json(&env, &["mcp", "namespace-proof", "show", &http_id]);
    assert_eq!(shown["method"], "http", "{shown}");
    assert!(
        shown["challenge"]["content"]
            .as_str()
            .unwrap()
            .starts_with("ak-mcp-verification="),
        "{shown}"
    );

    // Nothing publishes the challenge, so the check fails (with or without a network)
    // and says why: the proof is printed, and the exit code is a reported failure.
    for id in [&dns_id, &http_id] {
        let (code, stdout, stderr) = run_failing(&env, &["mcp", "namespace-proof", "verify", id]);
        assert_eq!(code, 7, "{stderr}");
        let proof = json_of(stdout.as_bytes());
        assert_eq!(proof["status"], "failed", "{proof}");
        assert!(proof["last_checked_at"].is_string(), "{proof}");
        let reason = proof["last_error"].as_str().unwrap();
        assert!(!reason.is_empty(), "{proof}");
        assert!(
            stderr.contains(&format!("Namespace proof {id} is failed: ")),
            "{stderr}"
        );
    }

    // Under --no-input a delete needs --yes, and without it deletes nothing.
    let (code, _, stderr) = run_failing(&env, &["mcp", "namespace-proof", "delete", &dns_id]);
    assert_eq!(code, 2, "{stderr}");
    run_json(&env, &["mcp", "namespace-proof", "show", &dns_id]);

    for id in [&dns_id, &http_id] {
        let deleted = run_json(&env, &["mcp", "namespace-proof", "delete", id, "--yes"]);
        assert_eq!(deleted["status"], "deleted", "{deleted}");
        let (code, _, stderr) = run_failing(&env, &["mcp", "namespace-proof", "show", id]);
        assert_eq!(code, 5, "{stderr}");
    }
}

// ---- a Remote registry ----

/// A public Local registry holding `servers` (name, version) and a Remote of it,
/// synced once.
fn synced_remote(
    env: &TestEnv,
    guard: &mut RepoGuard,
    servers: &[(&str, &str)],
) -> (String, String) {
    let local = local_repo(env, guard, true);
    for (name, version) in servers {
        publish(env, &local, name, version);
    }
    let remote = remote_repo(env, guard, &local);
    let synced = run_json(env, &["mcp", "sync", "start", "--repo", &remote, "--wait"]);
    assert_eq!(synced["running"], false, "{synced}");
    assert_eq!(synced["lastError"], Value::Null, "{synced}");
    assert_eq!(synced["lastSummary"]["complete"], true, "{synced}");
    (local, remote)
}

#[test]
#[ignore = "requires E2E backend"]
fn remote_sync_catalog_and_decisions() {
    let env = TestEnv::setup();
    if common::server_older_than(1, 12, "MCP registries") {
        return;
    }
    let mut guard = RepoGuard::new(&env);
    let ns = namespace();
    let weather = format!("{ns}/weather");
    let tides = format!("{ns}/tides");
    let radar = format!("{ns}/radar");
    let (_, remote) = synced_remote(
        &env,
        &mut guard,
        &[
            (&weather, "1.0.0"),
            (&weather, "1.1.0"),
            (&tides, "1.0.0"),
            (&radar, "2.0.0"),
        ],
    );

    let status = run_json(&env, &["mcp", "sync", "status", "--repo", &remote]);
    assert_eq!(status["running"], false, "{status}");
    assert_eq!(status["lastSummary"]["namesNew"], 3, "{status}");
    assert_eq!(status["lastSummary"]["entries"], 4, "{status}");
    assert!(status["lastSucceededAt"].is_string(), "{status}");
    let (table, _) = run_table(&env, &["mcp", "sync", "status", "--repo", &remote]);
    assert!(table.contains("Running:        no"), "{table}");
    assert!(table.contains("Reached the end: yes"), "{table}");

    // Every name starts pending: nothing is approved by default.
    let page = run_json(&env, &["mcp", "catalog", "list", "--repo", &remote]);
    let names: Vec<&str> = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["name"].as_str().unwrap())
        .collect();
    assert_eq!(names.len(), 3, "{page}");
    for name in [&weather, &tides, &radar] {
        assert!(names.contains(&name.as_str()), "{page}");
    }
    assert_eq!(page["counts"]["pending"], 3, "{page}");
    for filter in [
        vec!["--status", "pending"],
        vec!["--queue"],
        vec!["--namespace", &ns],
    ] {
        let mut args = vec!["mcp", "catalog", "list", "--repo", &remote];
        args.extend(filter.iter().copied());
        let page = run_json(&env, &args);
        assert_eq!(
            page["items"].as_array().unwrap().len(),
            3,
            "{args:?}: {page}"
        );
    }
    let page = run_json(
        &env,
        &[
            "mcp", "catalog", "list", "--repo", &remote, "--search", "tide",
        ],
    );
    assert_eq!(page["items"].as_array().unwrap().len(), 1, "{page}");
    assert_eq!(page["items"][0]["name"], tides.as_str(), "{page}");
    let page = run_json(
        &env,
        &[
            "mcp", "catalog", "list", "--repo", &remote, "--status", "approved",
        ],
    );
    assert_eq!(page["items"], json!([]), "{page}");

    // Pages of two: the cursor reaches the third name.
    let first = run_json(
        &env,
        &["mcp", "catalog", "list", "--repo", &remote, "--limit", "2"],
    );
    assert_eq!(first["items"].as_array().unwrap().len(), 2, "{first}");
    let cursor = first["nextCursor"].as_str().expect("no nextCursor");
    let second = run_json(
        &env,
        &[
            "mcp", "catalog", "list", "--repo", &remote, "--limit", "2", "--cursor", cursor,
        ],
    );
    assert_eq!(second["items"].as_array().unwrap().len(), 1, "{second}");
    assert_eq!(second["nextCursor"], Value::Null, "{second}");
    let (table, stderr) = run_table(
        &env,
        &["mcp", "catalog", "list", "--repo", &remote, "--limit", "2"],
    );
    assert!(table.contains("pending"), "{table}");
    assert!(stderr.contains("In the repository: pending 3"), "{stderr}");
    assert!(
        stderr.contains(&format!(
            "More: ak mcp catalog list --repo {remote} --cursor "
        )),
        "{stderr}"
    );

    // A name shows by its split route.
    let row = catalog_row(&env, &remote, &weather);
    assert_eq!(row["name"], weather.as_str(), "{row}");
    assert_eq!(row["namespace"], ns.as_str(), "{row}");
    assert_eq!(row["status"], "pending", "{row}");
    assert_eq!(row["latestVersion"], "1.1.0", "{row}");
    assert_eq!(row["versions"], json!(["1.1.0", "1.0.0"]), "{row}");
    assert_eq!(row["summary"]["remotesCount"], 1, "{row}");
    assert_eq!(row["ingested"], json!([]), "{row}");
    let weather_id = row_id(&row);
    let (table, _) = run_table(
        &env,
        &["mcp", "catalog", "show", "--repo", &remote, &weather],
    );
    assert!(table.contains("Status:          pending"), "{table}");
    assert!(
        table.contains("Transports:      streamable-http"),
        "{table}"
    );
    let (code, _, stderr) = run_failing(
        &env,
        &[
            "mcp",
            "catalog",
            "show",
            "--repo",
            &remote,
            &format!("{ns}/none"),
        ],
    );
    assert_eq!(code, 5, "{stderr}");

    // Asking for approval is counted, and --requested finds it.
    let asked = run_json(
        &env,
        &[
            "mcp",
            "catalog",
            "request-approval",
            "--repo",
            &remote,
            &weather_id,
            "--note",
            "for the e2e suite",
        ],
    );
    assert_eq!(asked["approvalRequests"]["count"], 1, "{asked}");
    let page = run_json(
        &env,
        &["mcp", "catalog", "list", "--repo", &remote, "--requested"],
    );
    assert_eq!(page["items"].as_array().unwrap().len(), 1, "{page}");
    assert_eq!(page["items"][0]["id"], weather_id.as_str(), "{page}");

    // The queue across registries names this one.
    let pending = run_json(&env, &["mcp", "pending"]);
    let mine = pending["repositories"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["key"] == remote.as_str())
        .unwrap_or_else(|| panic!("{remote} not in {pending}"));
    assert_eq!(mine["pending"], 3, "{pending}");
    assert!(pending["total"].as_i64().unwrap() >= 3, "{pending}");
    let (table, _) = run_table(&env, &["mcp", "pending"]);
    assert!(table.contains(&remote), "{table}");

    // Under --no-input a decision needs --yes, and without it changes nothing.
    for verb in ["approve", "block"] {
        let (code, _, stderr) = run_failing(
            &env,
            &["mcp", "catalog", verb, "--repo", &remote, &weather_id],
        );
        assert_eq!(code, 2, "{verb}: {stderr}");
    }
    assert_eq!(catalog_row(&env, &remote, &weather)["status"], "pending");

    // Approving a name ingests its versions.
    let approved = run_json(
        &env,
        &[
            "mcp",
            "catalog",
            "approve",
            "--repo",
            &remote,
            &weather_id,
            "--reason",
            "e2e",
            "--yes",
        ],
    );
    assert_eq!(approved["item"]["status"], "approved", "{approved}");
    assert_eq!(approved["ingestError"], Value::Null, "{approved}");
    let row = catalog_row(&env, &remote, &weather);
    assert_eq!(row["evaluationReason"], "e2e", "{row}");
    let mut ingested: Vec<&str> = row["ingested"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["version"].as_str().unwrap())
        .collect();
    ingested.sort();
    assert_eq!(ingested, ["1.0.0", "1.1.0"], "{row}");

    // The Remote's ingested version has a health of its own.
    let health = run_json(
        &env,
        &["mcp", "health", "--repo", &remote, &weather, "1.1.0"],
    );
    assert_eq!(health["name"], weather.as_str(), "{health}");
    assert_eq!(health["version"], "1.1.0", "{health}");
    let artifact = row["ingested"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["version"] == "1.1.0")
        .unwrap()["artifactId"]
        .clone();
    assert_eq!(health["artifactId"], artifact, "{health}");

    // Block, then reopen (which asks nothing): back to review.
    let blocked = run_json(
        &env,
        &[
            "mcp",
            "catalog",
            "block",
            "--repo",
            &remote,
            &weather_id,
            "--yes",
        ],
    );
    assert_eq!(blocked["item"]["status"], "blocked", "{blocked}");
    let (_, stderr) = run_table(
        &env,
        &["mcp", "catalog", "reopen", "--repo", &remote, &weather_id],
    );
    assert!(
        stderr.contains(&format!("Reopened {weather} in '{remote}': now review.")),
        "{stderr}"
    );
    let page = run_json(
        &env,
        &[
            "mcp", "catalog", "list", "--repo", &remote, "--status", "review",
        ],
    );
    assert_eq!(page["items"].as_array().unwrap().len(), 1, "{page}");
    assert_eq!(page["items"][0]["id"], weather_id.as_str(), "{page}");
}

#[test]
#[ignore = "requires E2E backend"]
fn remote_pins_bulk_decisions_and_seed() {
    let env = TestEnv::setup();
    if common::server_older_than(1, 12, "MCP registries") {
        return;
    }
    let mut guard = RepoGuard::new(&env);
    let ns = namespace();
    let weather = format!("{ns}/weather");
    let tides = format!("{ns}/tides");
    let radar = format!("{ns}/radar");
    let (local, remote) = synced_remote(
        &env,
        &mut guard,
        &[
            (&weather, "1.0.0"),
            (&weather, "1.1.0"),
            (&tides, "1.0.0"),
            (&radar, "2.0.0"),
        ],
    );

    // A pin approves one version of a name, which stays pending, and ingests it.
    let (code, _, stderr) = run_failing(
        &env,
        &[
            "mcp", "catalog", "pin", "--repo", &remote, &weather, "1.0.0",
        ],
    );
    assert_eq!(code, 2, "{stderr}");
    let pinned = run_json(
        &env,
        &[
            "mcp", "catalog", "pin", "--repo", &remote, &weather, "1.0.0", "--yes",
        ],
    );
    assert_eq!(pinned["item"]["status"], "pending", "{pinned}");
    assert_eq!(pinned["ingestError"], Value::Null, "{pinned}");
    let pins = pinned["item"]["pins"].as_array().unwrap();
    assert_eq!(pins.len(), 1, "{pinned}");
    assert_eq!(pins[0]["version"], "1.0.0", "{pinned}");
    assert_eq!(pins[0]["status"], "approved", "{pinned}");
    let health = run_json(
        &env,
        &["mcp", "health", "--repo", &remote, &weather, "1.0.0"],
    );
    assert_eq!(health["version"], "1.0.0", "{health}");

    // A dry run lists what a bulk approval would take, and changes nothing.
    let pattern = format!("{ns}/*");
    let dry = run_json(
        &env,
        &[
            "mcp",
            "catalog",
            "bulk-approve",
            "--repo",
            &remote,
            &pattern,
            "--dry-run",
        ],
    );
    assert_eq!(dry["dryRun"], true, "{dry}");
    assert_eq!(dry["approved"], 3, "{dry}");
    assert_eq!(dry["names"].as_array().unwrap().len(), 3, "{dry}");
    let (_, stderr) = run_table(
        &env,
        &[
            "mcp",
            "catalog",
            "bulk-approve",
            "--repo",
            &remote,
            &pattern,
            "--dry-run",
        ],
    );
    assert!(
        stderr.contains("Dry run: 3 name(s) would be approved. Nothing was changed."),
        "{stderr}"
    );
    let page = run_json(
        &env,
        &[
            "mcp", "catalog", "list", "--repo", &remote, "--status", "pending",
        ],
    );
    assert_eq!(page["items"].as_array().unwrap().len(), 3, "{page}");

    // Without --dry-run, under --no-input, it needs --yes.
    let (code, _, stderr) = run_failing(
        &env,
        &[
            "mcp",
            "catalog",
            "bulk-approve",
            "--repo",
            &remote,
            &pattern,
        ],
    );
    assert_eq!(code, 2, "{stderr}");

    // Bulk block one server, then approve the rest of the namespace.
    let blocked = run_json(
        &env,
        &[
            "mcp",
            "catalog",
            "bulk-block",
            "--repo",
            &remote,
            &radar,
            "--yes",
        ],
    );
    assert_eq!(blocked["blocked"], 1, "{blocked}");
    assert_eq!(blocked["names"], json!([radar]), "{blocked}");
    let approved = run_json(
        &env,
        &[
            "mcp",
            "catalog",
            "bulk-approve",
            "--repo",
            &remote,
            &pattern,
            "--yes",
        ],
    );
    assert_eq!(approved["dryRun"], false, "{approved}");
    assert_eq!(approved["approved"], 2, "{approved}");
    let page = run_json(
        &env,
        &[
            "mcp", "catalog", "list", "--repo", &remote, "--status", "approved",
        ],
    );
    assert_eq!(page["items"].as_array().unwrap().len(), 2, "{page}");

    // By id: approve the blocked name and an approved one, which is unchanged.
    let radar_id = row_id(&catalog_row(&env, &remote, &radar));
    let tides_id = row_id(&catalog_row(&env, &remote, &tides));
    let decided = run_json(
        &env,
        &[
            "mcp",
            "catalog",
            "bulk-decide",
            "--repo",
            &remote,
            "--action",
            "approve",
            &radar_id,
            &tides_id,
            "--yes",
        ],
    );
    assert_eq!(decided["action"], "approve", "{decided}");
    assert_eq!(decided["decided"], json!([radar_id]), "{decided}");
    assert_eq!(decided["unchanged"], json!([tides_id]), "{decided}");
    assert_eq!(catalog_row(&env, &remote, &radar)["status"], "approved");

    // An id that isn't a row of this catalog is a reported failure.
    let stranger = uuid::Uuid::new_v4().to_string();
    let (code, stdout, stderr) = run_failing(
        &env,
        &[
            "mcp",
            "catalog",
            "bulk-decide",
            "--repo",
            &remote,
            "--action",
            "block",
            &stranger,
            "--yes",
        ],
    );
    assert_eq!(code, 7, "{stderr}");
    assert_eq!(json_of(stdout.as_bytes())["notFound"], json!([stranger]));
    assert!(stderr.contains("aren't rows of the catalog"), "{stderr}");

    // A seed pins a version of a name the catalog hasn't seen yet: published
    // upstream after the sync.
    let late = format!("{ns}/sonar");
    publish(&env, &local, &late, "3.0.0");
    let (code, _, stderr) = run_failing(
        &env,
        &[
            "mcp", "catalog", "pin", "--repo", &remote, &late, "3.0.0", "--yes",
        ],
    );
    assert_eq!(code, 5, "{stderr}");
    let seeded = run_json(
        &env,
        &[
            "mcp",
            "seed",
            "start",
            "--repo",
            &remote,
            &format!("{late}@3.0.0"),
            "--reason",
            "e2e seed",
            "--yes",
            "--wait",
        ],
    );
    assert_eq!(seeded["status"], "completed", "{seeded}");
    assert_eq!(seeded["items"][0]["name"], late.as_str(), "{seeded}");
    assert_eq!(seeded["items"][0]["state"], "pinned", "{seeded}");
    let job = seeded["jobId"].as_str().unwrap().to_string();
    let status = run_json(&env, &["mcp", "seed", "status", "--repo", &remote, &job]);
    assert_eq!(status["jobId"], job.as_str(), "{status}");
    assert_eq!(status["items"][0]["state"], "pinned", "{status}");
    let (table, _) = run_table(&env, &["mcp", "seed", "status", "--repo", &remote, &job]);
    assert!(
        table.contains(&format!("Job {job} in '{remote}': completed")),
        "{table}"
    );
    let health = run_json(&env, &["mcp", "health", "--repo", &remote, &late, "3.0.0"]);
    assert_eq!(health["version"], "3.0.0", "{health}");

    // Seeding it again finds it pinned already; a version upstream doesn't list is
    // refused, and the job's exit code says so.
    let again = run_json(
        &env,
        &[
            "mcp",
            "seed",
            "start",
            "--repo",
            &remote,
            &format!("{late}@3.0.0"),
            "--yes",
            "--wait",
        ],
    );
    assert_eq!(again["items"][0]["state"], "already_pinned", "{again}");
    let (code, stdout, stderr) = run_failing(
        &env,
        &[
            "mcp",
            "seed",
            "start",
            "--repo",
            &remote,
            &format!("{late}@9.9.9"),
            "--yes",
            "--wait",
        ],
    );
    assert_eq!(code, 7, "{stderr}");
    assert_eq!(json_of(stdout.as_bytes())["items"][0]["state"], "refused");
    assert!(stderr.contains(&format!("{late}@9.9.9")), "{stderr}");
}

// ---- a 1.11 server ----

#[test]
#[ignore = "requires E2E backend"]
fn a_1_11_server_refuses_mcp_commands() {
    let env = TestEnv::setup();
    if !common::server_older_than(1, 12, "a refusal of ak mcp") {
        return;
    }
    for args in [
        vec!["mcp", "pending"],
        vec!["mcp", "catalog", "list", "--repo", "x"],
    ] {
        let (code, _, stderr) = run_failing(&env, &args);
        assert_eq!(code, 6, "{args:?}: {stderr}");
        assert!(
            stderr.contains("needs a server on 1.12 or newer"),
            "{args:?}: {stderr}"
        );
    }
}
