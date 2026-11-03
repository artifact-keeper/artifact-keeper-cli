//! Does each line of `src/registry.rs` tell the truth? Contract, not E2E.
//!
//! A registry line says "this command sends this request, and these flags set these
//! fields". This test runs the real `ak` binary against a mock server that answers
//! everything, and looks at what arrived. The command tree comes from `ak __registry`,
//! so nothing here is a second list of flags to keep in step.
//!
//! Arguments are worked out rather than written down. A required argument is tried
//! with placeholders until the command sends something. For a field, each argument of
//! the command is varied in turn, and a field whose value changes is bound to it.
//!
//! A command whose route is only reached after an earlier call gets its answer from
//! [`preflight`]. One that needs a particular argument gets it from [`hints`].
//!
//! The tests are `#[ignore]` so that `cargo test` stays quick. The Coverage CI job, and
//! `cargo test --test registry_contract -- --include-ignored`, run them.
//!
//! `AK_REGISTRY_PROBE=<file>` also walks every leaf command, in or out of the
//! registry, and writes what each one sent. The coverage measurement reads that.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use tempfile::TempDir;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate, matchers::any};

#[path = "common/pkg_fixtures.rs"]
mod pkg_fixtures;

const UUID: &str = "00000000-0000-4000-8000-000000000001";
const OTHER_UUID: &str = "00000000-0000-4000-8000-000000000002";
const STDIN: &str = "from-stdin";

/// Commands that don't talk to the instance's API as their job, or that write outside
/// the sandbox. `setup` configures local tools and `api` sends whatever it's told.
const NOT_PROBED: &[&str] = &[
    "api",
    "completion",
    "config",
    "doctor",
    "instance",
    "man-pages",
    "setup",
    "tui",
];

#[derive(Debug, Clone)]
struct Arg {
    id: String,
    long: Option<String>,
    positional: bool,
    required: bool,
    kind: String,
    values: Vec<String>,
}

#[derive(Debug, Clone)]
struct Leaf {
    command: String,
    args: Vec<Arg>,
}

#[derive(Debug, Clone)]
struct Line {
    method: String,
    path: String,
    command: String,
    binds: Vec<String>,
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn registry() -> (Vec<Line>, Vec<Leaf>) {
    let out = assert_cmd::Command::cargo_bin("ak")
        .expect("ak binary")
        .arg("__registry")
        .output()
        .expect("run ak __registry");
    assert!(out.status.success(), "ak __registry failed");
    let dump: Value = serde_json::from_slice(&out.stdout).expect("__registry prints JSON");
    let lines = dump["commands"]
        .as_array()
        .expect("commands")
        .iter()
        .filter(|c| c["excluded"].is_null())
        .map(|c| Line {
            method: c["method"].as_str().unwrap_or("").to_string(),
            path: c["path"].as_str().unwrap_or("").to_string(),
            command: c["command"].as_str().unwrap_or("").to_string(),
            binds: strings(&c["binds"]),
        })
        .collect();
    let leaves = dump["leaves"]
        .as_array()
        .expect("leaves")
        .iter()
        .map(|l| Leaf {
            command: l["command"].as_str().unwrap_or("").to_string(),
            args: l["args"]
                .as_array()
                .expect("args")
                .iter()
                .map(|a| Arg {
                    id: a["id"].as_str().unwrap_or("").to_string(),
                    long: a["long"].as_str().map(str::to_string),
                    positional: a["positional"].as_bool().unwrap_or(false),
                    required: a["required"].as_bool().unwrap_or(false),
                    kind: a["kind"].as_str().unwrap_or("string").to_string(),
                    values: strings(&a["values"]),
                })
                .collect(),
        })
        .collect();
    (lines, leaves)
}

/// One request as the server saw it: its method, path and the fields it carried.
#[derive(Debug, Clone, PartialEq)]
struct Seen {
    method: String,
    path: String,
    fields: BTreeMap<String, String>,
}

fn fields_of(request: &Request) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    for (key, value) in request.url.query_pairs() {
        fields.insert(key.to_string(), value.to_string());
    }
    if let Ok(Value::Object(body)) = serde_json::from_slice::<Value>(&request.body) {
        for (key, value) in body {
            fields.insert(key, value.to_string());
        }
        return fields;
    }
    let text = String::from_utf8_lossy(&request.body);
    let content_type = request
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if content_type.starts_with("multipart/") {
        for part in text.split("form-data; name=\"").skip(1) {
            if let Some((name, rest)) = part.split_once('"') {
                fields.insert(name.to_string(), rest.chars().take(200).collect());
            }
        }
    } else if content_type.starts_with("application/x-www-form-urlencoded") {
        for pair in text.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                fields.insert(key.to_string(), value.to_string());
            }
        }
    }
    fields
}

/// `/a/{x}/b` against `/a/1/b`. A trailing parameter can take several segments, as a
/// catch-all does. Parameter names don't count.
fn route_matches(template: &str, path: &str) -> bool {
    let want: Vec<&str> = template.trim_end_matches('/').split('/').collect();
    let got: Vec<&str> = path.trim_end_matches('/').split('/').collect();
    if got.len() < want.len() {
        return false;
    }
    for (i, segment) in want.iter().enumerate() {
        let is_param = segment.starts_with('{') && segment.ends_with('}');
        // npm's `@{scope}`: a parameter after a literal character.
        let is_scope = segment.starts_with("@{") && got[i].starts_with('@');
        if !is_param && !is_scope && *segment != got[i] {
            return false;
        }
    }
    got.len() == want.len()
        || want
            .last()
            .is_some_and(|s| s.starts_with('{') && s.ends_with('}'))
}

/// Earlier calls a command makes before the route under test, and what they need
/// back. Everything else gets 200 `{}`. The bodies are the required fields of each
/// response in the spec.
fn preflight(method: &str, path: &str) -> Option<(u16, Value)> {
    let at = "2026-01-01T00:00:00Z";
    let table: Vec<(&str, &str, u16, Value)> = vec![
        (
            "GET",
            "/health",
            200,
            json!({"status": "healthy", "version": "1.11.11", "checks": {}}),
        ),
        (
            "GET",
            "/npm/{repo}/{package}",
            200,
            json!({"name": "demo", "versions": {"1.0.0": {}, "2.0.0": {}}}),
        ),
        (
            "GET",
            "/npm/{repo}/@{scope}/{package}",
            200,
            json!({"name": "@a/demo", "versions": {"1.0.0": {}, "2.0.0": {}}}),
        ),
        (
            "POST",
            "/lfs/{repo}/objects/batch",
            200,
            json!({"objects": [{"actions": {"upload": {"href": "x"}}}]}),
        ),
        (
            "POST",
            "/incus/{repo}/images/{product}/{version}/{file}/uploads",
            201,
            json!({"session_id": UUID}),
        ),
        (
            "POST",
            "/lxc/{repo}/images/{product}/{version}/{file}/uploads",
            201,
            json!({"session_id": UUID}),
        ),
        (
            "GET",
            "/api/v1/auth/me",
            200,
            json!({"id": UUID, "username": "x", "email": "x", "is_admin": true,
                   "totp_enabled": true}),
        ),
        (
            "GET",
            "/api/v1/admin/banners/{id}",
            200,
            json!({"id": UUID, "title": "x", "message": "x", "severity": "info", "target": "all",
                   "enabled": true, "created_at": at, "updated_at": at, "active": true}),
        ),
        (
            "GET",
            "/api/v1/admin/settings/token-policy",
            200,
            json!({"policy": {"require_expiration": true, "min_days": 1, "max_days": 1},
                   "source": "environment", "editable": true, "non_expiring_user_tokens": 1,
                   "non_expiring_service_account_tokens": 1}),
        ),
        (
            "GET",
            "/api/v1/admin/settings",
            200,
            json!({"storage_backend": "x", "storage_path": "x", "allow_anonymous_download": true,
                   "max_upload_size_bytes": 1, "retention_days": 1, "audit_retention_days": 1,
                   "backup_retention_count": 1, "edge_stale_threshold_minutes": 1}),
        ),
        (
            "GET",
            "/api/v1/admin/telemetry/settings",
            200,
            json!({"enabled": true, "review_before_send": true, "scrub_level": "x",
                   "include_logs": true}),
        ),
        (
            "GET",
            "/api/v1/curation/rules/{id}",
            200,
            json!({"id": UUID, "package_pattern": "x", "version_constraint": "x",
                   "architecture": "x", "action": "x", "priority": 1, "reason": "x",
                   "enabled": true, "rule_type": "x", "config": {}, "scope": "x",
                   "created_at": at, "updated_at": at}),
        ),
        (
            "GET",
            "/api/v1/security/scans/{id}",
            200,
            json!({"id": UUID, "artifact_id": UUID, "repository_id": UUID, "scan_type": "x",
                   "status": "x", "findings_count": 1, "critical_count": 1, "high_count": 1,
                   "medium_count": 1, "low_count": 1, "info_count": 1, "created_at": at,
                   "is_reused": true, "scan_completeness": "x"}),
        ),
        (
            "POST",
            "/api/v1/uploads",
            201,
            json!({"session_id": UUID, "chunk_count": 1, "chunk_size": 1048576,
                   "expires_at": at}),
        ),
        (
            "POST",
            "/api/v1/auth/login",
            200,
            json!({"access_token": "a", "refresh_token": "r", "expires_in": 1800,
                   "token_type": "Bearer", "must_change_password": false,
                   "totp_required": false}),
        ),
        (
            "PATCH",
            "/api/v1/uploads/{session_id}",
            200,
            json!({"chunk_index": 0, "bytes_received": 1, "chunks_completed": 1,
                   "chunks_remaining": 0}),
        ),
        (
            "PUT",
            "/api/v1/uploads/{session_id}/complete",
            200,
            json!({"path": "x", "size": 1, "checksum_sha256": "x", "artifact_id": UUID}),
        ),
        (
            "GET",
            "/api/v1/repositories/{key}/artifacts/{path}",
            200,
            json!({"id": UUID, "repository_key": "x", "path": "x", "name": "x", "size_bytes": 1,
                   "checksum_sha256": "x", "content_type": "x", "download_count": 1,
                   "created_at": at, "analyzable": true, "quarantine_status": "x"}),
        ),
    ];
    table
        .into_iter()
        .find(|(m, p, _, _)| *m == method && exact_route(p, path))
        .map(|(_, _, status, body)| (status, body))
}

/// [`route_matches`] without the catch-all: same number of segments.
fn exact_route(template: &str, path: &str) -> bool {
    template.split('/').count() == path.split('/').count() && route_matches(template, path)
}

struct Answers;

impl Respond for Answers {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let (status, body) =
            preflight(request.method.as_str(), request.url.path()).unwrap_or((200, json!({})));
        ResponseTemplate::new(status).set_body_json(body)
    }
}

/// One mock server and one sandbox. Commands run in here can't reach the real home.
struct Rig {
    server: MockServer,
    home: TempDir,
    env: std::sync::Mutex<Vec<(&'static str, &'static str)>>,
    /// Use what's stored instead of `AK_TOKEN`, which would win over it.
    stored_login: std::sync::atomic::AtomicBool,
}

struct Outcome {
    parsed: bool,
    requests: Vec<Seen>,
}

impl Rig {
    async fn start() -> Self {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(Answers)
            .mount(&server)
            .await;
        Self {
            server,
            home: TempDir::new().expect("temp dir"),
            env: std::sync::Mutex::new(Vec::new()),
            stored_login: std::sync::atomic::AtomicBool::new(false),
        }
    }

    async fn run(&self, args: Vec<String>) -> Outcome {
        self.server.reset().await;
        Mock::given(any())
            .respond_with(Answers)
            .mount(&self.server)
            .await;
        let home = self.home.path().to_path_buf();
        // A cached upload session would turn the next push into a resume.
        let _ = std::fs::remove_dir_all(home.join("uploads"));
        std::fs::write(
            home.join("config.toml"),
            format!(
                "default_instance = \"t\"\n[instances.t]\nurl = \"{}\"\napi_version = \"v1\"\n",
                self.server.uri()
            ),
        )
        .expect("write config");
        let env = self.env.lock().expect("env").clone();
        let stored_login = self.stored_login.load(Ordering::Relaxed);
        let output = tokio::task::spawn_blocking(move || {
            let mut command = assert_cmd::Command::cargo_bin("ak").expect("ak binary");
            command.env_clear();
            if !stored_login {
                command.env("AK_TOKEN", "contract-test");
            }
            command
                .envs(env)
                .env("HOME", &home)
                .env("XDG_CONFIG_HOME", &home)
                .env("XDG_CACHE_HOME", &home)
                .env("XDG_DATA_HOME", &home)
                .env("AK_CONFIG_DIR", &home)
                .env("AK_CREDENTIAL_STORE", "file")
                .env("AK_FORMAT", "json")
                .env("NO_COLOR", "1")
                .current_dir(&home)
                .arg("--no-input")
                .args(&args)
                .write_stdin(format!("{STDIN}\n"))
                .timeout(Duration::from_secs(6))
                .output()
        })
        .await
        .expect("join");
        let parsed = output
            .as_ref()
            .map(|o| o.status.code() != Some(2))
            .unwrap_or(true);
        let requests = self
            .server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .map(|r| Seen {
                method: r.method.to_string(),
                path: r.url.path().to_string(),
                fields: fields_of(r),
            })
            .collect();
        Outcome { parsed, requests }
    }

    fn file(&self, name: &str, content: &str) -> String {
        let path = self.home.path().join(name);
        std::fs::write(&path, content).expect("write");
        path.to_string_lossy().to_string()
    }
}

/// Values to try for an argument, most likely first.
fn candidates(rig: &Rig, arg: &Arg) -> Vec<String> {
    if !arg.values.is_empty() {
        return arg.values.clone();
    }
    match arg.kind.as_str() {
        "int" => return vec!["7".to_string(), "1".to_string()],
        "bool" => return vec!["true".to_string(), "false".to_string()],
        "path" => return vec![rig.file("input.json", "{}")],
        _ => {}
    }
    let json_file = rig.file("input.json", "{}");
    let list_file = rig.file("list.json", "[ ]");
    let name = arg.id.as_str();
    let mut out: Vec<String> = Vec::new();
    // `lifecycle create` sends one repository in its legacy field.
    if name == "repos" {
        out.push(
            "00000000-0000-0000-0000-00000000000a,00000000-0000-0000-0000-00000000000b".to_string(),
        );
    }
    // `admin settings update` parses the whole of `SystemSettings`, so no fragment of
    // it would do. The second body differs in every field.
    let first_settings = "{\"storage_backend\":\"a\",\"storage_path\":\"a\",\
        \"allow_anonymous_download\":true,\"max_upload_size_bytes\":1,\"retention_days\":1,\
        \"audit_retention_days\":1,\"backup_retention_count\":1,\
        \"edge_stale_threshold_minutes\":1,\"environment\":\"a\"}";
    let second_settings = "{\"storage_backend\":\"b\",\"storage_path\":\"b\",\
        \"allow_anonymous_download\":false,\"max_upload_size_bytes\":2,\"retention_days\":2,\
        \"audit_retention_days\":2,\"backup_retention_count\":2,\
        \"edge_stale_threshold_minutes\":2,\"environment\":\"b\"}";
    if name == "json" {
        out.push(first_settings.to_string());
        out.push(second_settings.to_string());
    }
    let specific: &[&str] = match name {
        "signing_mode" => &["hmac", "asymmetric"],
        "payload_template" => &["slack", "discord"],
        "rules" => &["pattern=>rewrite"],
        "artifacts" => &["name:path:sha:1"],
        "members" => &["member=1"],
        "bitmap" => &["1,2", "3"],
        "aws" => &["{\"region\":\"r\"}"],
        "recipients" => &["a@example.com"],
        _ => &[],
    };
    out.extend(specific.iter().map(|v| v.to_string()));
    if name.contains("file") || name.contains("path") || name.contains("archive") {
        out.push(json_file.clone());
    }
    if name.contains("url") || name.contains("uri") {
        out.push("http://127.0.0.1:9/x".to_string());
    }
    if name.contains("json")
        || name.contains("config")
        || name.contains("predicates")
        || name.contains("conditions")
    {
        out.push("{}".to_string());
    }
    out.extend(
        [
            UUID,
            OTHER_UUID,
            "{}",
            "{\"probe\":\"x\"}",
            "[]",
            "[\"x\"]",
            "a=b",
            "a=1",
            "7",
            "true",
            "http://127.0.0.1:9/x",
            "2026-01-01T00:00:00Z",
            "2026-01-01",
            "repo/path",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ]
        .map(str::to_string),
    );
    out.push(json_file.clone());
    out.push(list_file.clone());
    out.push(format!("@{json_file}"));
    out.push(format!("@{list_file}"));
    out
}

/// Does this request field carry a value given on the command line? An argument with
/// one workable value can't be varied, and stdin never changes, but the value shows
/// where it went: `a=>b` in a list of rules, the password in the body.
fn echoes(field_value: &str, given: &str) -> bool {
    given
        .split(['=', '>', ':', ',', '@', '/'])
        .filter(|piece| piece.len() >= 3 && !matches!(*piece, "true" | "false"))
        .any(|piece| field_value.contains(piece))
}

/// The argv for one argument with one value. A flag takes no value.
fn argv(arg: &Arg, value: &str) -> Vec<String> {
    match (&arg.long, arg.kind.as_str()) {
        (_, _) if arg.positional => vec![value.to_string()],
        (Some(long), "flag") => vec![format!("--{long}")],
        (Some(long), _) => vec![format!("--{long}"), value.to_string()],
        (None, _) => Vec::new(),
    }
}

/// How far a set of arguments got. Higher is better.
fn score(outcome: &Outcome, expect: Option<(&str, &str)>) -> u8 {
    if !outcome.parsed {
        return 0;
    }
    if outcome.requests.is_empty() {
        return 1;
    }
    match expect {
        Some((method, path)) => {
            if hits(outcome, method, path) {
                3
            } else {
                2
            }
        }
        // A version check on its own isn't what the command is for.
        None if outcome.requests.iter().all(|r| r.path == "/health") => 2,
        None => 3,
    }
}

fn hits(outcome: &Outcome, method: &str, path: &str) -> bool {
    outcome
        .requests
        .iter()
        .any(|r| (method == "ANY" || r.method == method) && route_matches(path, &r.path))
}

/// The arguments and first answer for a command, trying placeholders until it sends
/// the expected request, or anything if none is expected.
struct Base {
    /// Which argument has which value. Positionals stay in declaration order.
    chosen: Vec<(Arg, String)>,
    outcome: Outcome,
    best: u8,
}

fn build(leaf: &Leaf, chosen: &[(Arg, String)]) -> Vec<String> {
    let mut args: Vec<String> = leaf
        .command
        .split_whitespace()
        .map(str::to_string)
        .collect();
    for (arg, value) in chosen {
        if !arg.positional {
            args.extend(argv(arg, value));
        }
    }
    if leaf.args.iter().any(|a| a.id == "yes") {
        args.push("--yes".to_string());
    }
    // `artifact pull` refuses to overwrite what the previous run wrote.
    if leaf.command == "artifact pull" {
        args.push("--force".to_string());
    }
    // A positional after `--` can begin with a dash, and comes after every flag.
    for (arg, value) in chosen {
        if arg.positional {
            args.push(value.clone());
        }
    }
    args
}

/// Arguments and environment a line needs that placeholders won't find.
fn hints(
    home: &std::path::Path,
    line: &Line,
) -> (
    Vec<(&'static str, String)>,
    Vec<(&'static str, &'static str)>,
) {
    let id = || UUID.to_string();
    match (
        line.command.as_str(),
        line.method.as_str(),
        line.path.as_str(),
    ) {
        ("auth login", _, p) if p.contains("/sso/ldap/") => (
            vec![
                ("sso", format!("ldap:{UUID}")),
                ("username", "u".to_string()),
                ("password_stdin", String::new()),
            ],
            vec![],
        ),
        ("auth login", _, p) if p.contains("/sso/oidc/") => {
            (vec![("sso", format!("oidc:{UUID}"))], vec![])
        }
        ("auth login", _, p) if p.contains("/sso/saml/") => {
            (vec![("sso", format!("saml:{UUID}"))], vec![])
        }
        ("auth login", _, "/api/v1/auth/login") => (
            vec![
                ("username", "u".to_string()),
                ("password_stdin", String::new()),
            ],
            vec![],
        ),
        ("auth verify-totp", ..) => (
            vec![("code", "123456".to_string()), ("totp_token", id())],
            vec![],
        ),
        ("totp enroll complete", ..) => (
            vec![("code", "123456".to_string()), ("totp_token", id())],
            vec![],
        ),
        ("totp disable", ..) => (
            vec![
                ("code", "123456".to_string()),
                ("password", "p".to_string()),
            ],
            vec![],
        ),
        ("lifecycle create", ..) => (
            vec![
                ("policy_type", "max_versions".to_string()),
                ("config", "{\"keep\":3}".to_string()),
                ("repo", id()),
            ],
            vec![],
        ),
        ("artifact push", _, p) if p.contains("/uploads") => {
            (vec![], vec![("AK_CHUNKED_THRESHOLD", "1")])
        }
        ("artifact push", "POST", "/api/v1/repositories/{key}/artifacts") => (
            vec![("multipart", String::new()), ("path", "dir/".to_string())],
            vec![],
        ),
        ("artifact push", "POST", _) => (vec![("multipart", String::new())], vec![]),
        ("email-subscriptions subscribe", ..) => (
            vec![
                ("recipients", "a@example.com".to_string()),
                ("events", "artifact_uploaded".to_string()),
            ],
            vec![],
        ),
        ("system swagger-ui", _, "/swagger-ui/{path}") => {
            (vec![("path", "index.html".to_string())], vec![])
        }
        ("scan finding ingest", ..) => {
            let file = home.join("findings.json");
            let findings = json!([{"severity": "high", "title": "t"}]);
            std::fs::write(&file, findings.to_string()).expect("write");
            (
                vec![
                    ("file", file.to_string_lossy().to_string()),
                    ("artifact", id()),
                    ("scanner", "s".to_string()),
                ],
                vec![],
            )
        }
        (command, _, _) if command.starts_with("pkg ") => (pkg_hints(home, line), Vec::new()),
        _ => (Vec::new(), Vec::new()),
    }
}

fn fx_plain(home: &std::path::Path, name: &str) -> std::path::PathBuf {
    let path = home.join(name);
    std::fs::write(&path, "package").expect("write");
    path
}

/// `ak pkg` reads the package it's given, so it needs a real one. A format's other URL
/// for the same handler is chosen with `--endpoint`.
fn pkg_hints(home: &std::path::Path, line: &Line) -> Vec<(&'static str, String)> {
    use pkg_fixtures as fx;
    let path = line.path.as_str();
    let mut args: Vec<(&'static str, String)> = Vec::new();
    let as_file = |p: std::path::PathBuf| ("file", p.to_string_lossy().to_string());
    match line.command.as_str() {
        "pkg cargo publish" => args.push(as_file(fx::crate_file(home, "demo", "1.0.0", ""))),
        "pkg pypi publish" => args.push(as_file(fx::sdist(home, "demo", "1.0.0"))),
        "pkg npm publish" if path.contains("@{scope}") => {
            args.push(as_file(fx::npm_tarball(home, "@a/demo", "1.0.0")));
        }
        "pkg npm publish" => args.push(as_file(fx::npm_tarball(home, "demo", "1.0.0"))),
        "pkg npm unpublish" => {
            let scoped = path.contains("@{scope}");
            args.push((
                "package",
                if scoped { "@a/demo" } else { "demo" }.to_string(),
            ));
            if path.contains("/-/{filename}") {
                args.push(("tarball", "demo-1.0.0.tgz".to_string()));
            } else if line.method == "PUT" {
                args.push(("package_version", "1.0.0".to_string()));
            }
            if path.ends_with("/{version}") {
                args.push(("encoded_name", String::new()));
            }
        }
        "pkg debian publish" => {
            args.push(as_file(fx_plain(home, "demo_1.0_all.deb")));
            if path.ends_with("/upload") {
                args.push(("endpoint", "upload".to_string()));
            }
        }
        "pkg rpm publish" if path.ends_with("/upload") => {
            args.push(("endpoint", "upload".to_string()));
        }
        "pkg rpm publish" if path.ends_with("{upstream_path}") => {
            args.push(("path", "a/demo.rpm".to_string()));
        }
        "pkg alpine publish" if path.contains("{branch}") => {
            args.push(("endpoint", "path".to_string()));
            args.push(("arch", "x86_64".to_string()));
        }
        "pkg conda publish" | "pkg conda attest" => {
            if path.contains("{subdir}") && line.command == "pkg conda publish" {
                args.push(("subdir", "noarch".to_string()));
            }
            if path.starts_with("/conda/t/") {
                args.push(("token_in_url", "conda-t".to_string()));
            }
            if path.starts_with("/t/") {
                args.push(("token_in_url", "t-conda".to_string()));
            }
        }
        "pkg incus publish" | "pkg lxc publish"
            if !path.contains("/images/") || path.ends_with("/uploads") =>
        {
            args.push(("chunked", String::new()));
        }
        "pkg composer publish" if line.method == "PUT" => {
            args.push(("put", String::new()));
        }
        "pkg maven publish" => {
            args.push(("group", "com.acme".to_string()));
            args.push(("artifact", "demo".to_string()));
            args.push(("artifact_version", "1.0".to_string()));
            args.push(as_file(fx_plain(home, "demo.jar")));
        }
        "pkg ivy publish" => {
            args.push(("org", "com.acme".to_string()));
            args.push(("module", "demo".to_string()));
            args.push(("revision", "1.0".to_string()));
            args.push(as_file(fx_plain(home, "demo.jar")));
        }
        "pkg go publish" => args.push(as_file(pkg_fixtures::zip(
            &home.join("m.zip"),
            &[("example.com/d@v1.0.0/go.mod", b"module example.com/d\n")],
        ))),
        "pkg chef publish" => {
            let meta = br#"{"name":"demo","version":"1.0.0"}"#;
            args.push(as_file(fx::tar_gz(
                &home.join("demo.tgz"),
                &[("demo/metadata.json", meta)],
            )));
        }
        "pkg puppet publish" => {
            let meta = br#"{"name":"acme-demo","version":"1.0.0"}"#;
            args.push(as_file(fx::tar_gz(
                &home.join("acme-demo.tgz"),
                &[("acme-demo/metadata.json", meta)],
            )));
        }
        "pkg huggingface upload" if path.contains("{namespace}") => {
            args.push(("model", "acme/demo".to_string()));
        }
        "pkg huggingface upload" => args.push(("model", "demo".to_string())),
        "pkg conan upload" | "pkg conan remove" => {
            args.push(("reference", "demo/1.0".to_string()));
            if path.contains("/revisions/{revision}") {
                args.push(("revision", "rev".to_string()));
            }
            if path.ends_with("/packages") {
                args.push(("all_packages", String::new()));
            }
            if path.contains("{package_id}") {
                args.push(("package_id", "pid".to_string()));
                args.push(("package_revision", "prev".to_string()));
            }
        }
        "pkg proto publish" => args.push(("module", "acme/demo".to_string())),
        "pkg oci tags"
        | "pkg oci referrers"
        | "pkg oci blob get"
        | "pkg oci manifest get"
        | "pkg oci manifest head"
        | "pkg oci manifest put"
        | "pkg oci manifest delete" => {
            args.push(("name", "app".to_string()));
            if line.command == "pkg oci manifest put" {
                args.push(("media_type", "application/json".to_string()));
            }
        }
        "pkg npm audit" => {
            let kind = if path.ends_with("quick") {
                "quick"
            } else {
                "bulk"
            };
            args.push(("kind", kind.to_string()));
            args.push(("body", "{}".to_string()));
        }
        _ => {}
    }
    if path.starts_with("/api/cargo") {
        args.push(("endpoint", "api-cargo".to_string()));
    }
    if path.starts_with("/api/helm") {
        args.push(("endpoint", "api-helm".to_string()));
    }
    args
}

async fn find_base(
    rig: &Rig,
    leaf: &Leaf,
    expect: Option<(&str, &str)>,
    extra: &[(&str, String)],
) -> Base {
    let mut chosen: Vec<(Arg, String)> = Vec::new();
    for arg in &leaf.args {
        if let Some((_, value)) = extra.iter().find(|(id, _)| *id == arg.id) {
            chosen.push((arg.clone(), value.clone()));
        } else if arg.required && arg.id != "yes" {
            let first = candidates(rig, arg).into_iter().next().unwrap_or_default();
            chosen.push((arg.clone(), first));
        }
    }
    let mut outcome = rig.run(build(leaf, &chosen)).await;
    let mut best = score(&outcome, expect);
    // Try each required argument's other values, keeping whatever gets further.
    if best < 3 {
        for i in 0..chosen.len() {
            if extra.iter().any(|(id, _)| *id == chosen[i].0.id) {
                continue;
            }
            let start = chosen[i].1.clone();
            let mut keep = start;
            for candidate in candidates(rig, &chosen[i].0).into_iter().skip(1) {
                chosen[i].1 = candidate.clone();
                let tried = rig.run(build(leaf, &chosen)).await;
                let s = score(&tried, expect);
                if s > best {
                    best = s;
                    outcome = tried;
                    keep = candidate;
                    if best == 3 {
                        break;
                    }
                }
            }
            chosen[i].1 = keep;
            if best == 3 {
                break;
            }
        }
    }
    // Some routes need an optional flag: `--all`, `--artifact`, `--tree`.
    if best < 3 {
        let optional: Vec<Arg> = leaf
            .args
            .iter()
            .filter(|a| !chosen.iter().any(|(c, _)| c.id == a.id) && a.id != "yes")
            .cloned()
            .collect();
        'flags: for arg in optional {
            for candidate in candidates(rig, &arg) {
                let mut with = chosen.clone();
                with.push((arg.clone(), candidate));
                let tried = rig.run(build(leaf, &with)).await;
                let s = score(&tried, expect);
                if s > best {
                    best = s;
                    outcome = tried;
                    chosen = with;
                    if best == 3 {
                        break 'flags;
                    }
                }
                if arg.kind == "flag" {
                    break;
                }
            }
        }
    }
    Base {
        chosen,
        outcome,
        best,
    }
}

fn hit_with_field(outcome: &Outcome, line: &Line, field: &str) -> bool {
    outcome.requests.iter().any(|r| {
        r.method == line.method
            && route_matches(&line.path, &r.path)
            && r.fields.contains_key(field)
    })
}

fn matches_expect_static(expect: Option<(&str, &str)>, seen: &Seen) -> bool {
    match expect {
        Some((method, path)) => {
            (method == "ANY" || seen.method == method) && route_matches(path, &seen.path)
        }
        None => true,
    }
}

/// What each argument sets: vary it, and see which fields of which request change.
///
/// An argument that passes JSON through to the body gets the claimed fields in one
/// object, inline and from a file, since no single placeholder could show those.
async fn probe_fields(
    rig: &Rig,
    leaf: &Leaf,
    base: &Base,
    expect: Option<(&str, &str)>,
    claimed: &[String],
) -> BTreeMap<String, BTreeSet<String>> {
    let mut bound: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let baseline = &base.outcome.requests;
    for request in baseline.iter().filter(|r| matches_expect_static(expect, r)) {
        for (field, value) in &request.fields {
            let carried = echoes(value, STDIN)
                || base.chosen.iter().any(|(arg, given)| {
                    arg.kind != "flag" && !given.is_empty() && echoes(value, given)
                });
            if carried {
                bound
                    .entry(format!("{} {}", request.method, request.path))
                    .or_default()
                    .insert(field.clone());
            }
        }
    }
    let matches_expect = |s: &Seen| matches_expect_static(expect, s);
    for arg in &leaf.args {
        if arg.id == "yes" {
            continue;
        }
        let at = base.chosen.iter().position(|(c, _)| c.id == arg.id);
        let mut list = candidates(rig, arg);
        if arg.kind == "string" && arg.values.is_empty() && !claimed.is_empty() {
            let object: serde_json::Map<String, Value> = claimed
                .iter()
                .map(|field| (field.clone(), json!("probe")))
                .collect();
            let text = Value::Object(object).to_string();
            let file = rig.file("claimed.json", &text);
            list.push(text);
            list.push(file.clone());
            list.push(format!("@{file}"));
        }
        for candidate in list {
            let mut chosen = base.chosen.clone();
            match at {
                Some(i) if chosen[i].1 == candidate => continue,
                Some(i) => chosen[i].1 = candidate,
                None => chosen.push((arg.clone(), candidate)),
            }
            let mut tried = rig.run(build(leaf, &chosen)).await;
            if !tried.parsed {
                // It may conflict with an optional flag the base needed: try without.
                chosen.retain(|(a, _)| a.required || a.id == arg.id);
                tried = rig.run(build(leaf, &chosen)).await;
                if !tried.parsed {
                    continue;
                }
            }
            let mut changed = false;
            for request in tried.requests.iter().filter(|r| matches_expect(r)) {
                // A route this argument alone reaches is worth knowing, field or not.
                bound
                    .entry(format!("{} {}", request.method, request.path))
                    .or_default();
                let before = baseline
                    .iter()
                    .find(|b| b.method == request.method && b.path == request.path)
                    .or_else(|| {
                        baseline
                            .iter()
                            .find(|b| b.method == request.method && matches_expect(b))
                    });
                for (field, value) in &request.fields {
                    let same = before.is_some_and(|b| b.fields.get(field) == Some(value));
                    if !same {
                        bound
                            .entry(format!("{} {}", request.method, request.path))
                            .or_default()
                            .insert(field.clone());
                        changed = true;
                    }
                }
            }
            if changed || arg.kind == "flag" {
                break;
            }
        }
    }
    bound
}

async fn check_line(rig: &Rig, leaf: Option<&Leaf>, line: &Line) -> Result<(), String> {
    let Some(leaf) = leaf else {
        return Err(format!("no such command: ak {}", line.command));
    };
    let expect = Some((line.method.as_str(), line.path.as_str()));
    let dump_fields = std::env::var("AK_REGISTRY_LINES").is_ok_and(|p| !p.is_empty());
    let (extra, env) = hints(rig.home.path(), line);
    *rig.env.lock().expect("env") = env;
    let refreshing = matches!(line.command.as_str(), "auth refresh" | "auth logout");
    rig.stored_login.store(refreshing, Ordering::Relaxed);
    if refreshing {
        // Refreshing needs a stored refresh token, and only a login stores one.
        let login = ["auth", "login", "--username", "u", "--password-stdin"];
        rig.run(login.iter().map(|a| a.to_string()).collect()).await;
    }
    let base = find_base(rig, leaf, expect, &extra).await;
    if base.best < 3 {
        let sent: Vec<String> = base
            .outcome
            .requests
            .iter()
            .map(|r| format!("{} {}", r.method, r.path))
            .collect();
        return Err(format!(
            "ak {} never sent {} {} (sent {sent:?}, score {})",
            line.command, line.method, line.path, base.best
        ));
    }
    if line.binds.is_empty() && !dump_fields {
        return Ok(());
    }
    let bound = probe_fields(rig, leaf, &base, expect, &line.binds).await;
    // Only what an argument changed counts. A field the command always sends with a
    // fixed value reaches the server, but no flag sets it.
    let mut set: BTreeSet<&str> = bound.values().flatten().map(String::as_str).collect();
    // Not a flag: the refresh token the login stored, which is what these commands do.
    if matches!(line.command.as_str(), "auth refresh" | "auth logout")
        && hit_with_field(&base.outcome, line, "refresh_token")
    {
        set.insert("refresh_token");
    }
    if dump_fields {
        let names: Vec<&&str> = set.iter().collect();
        eprintln!(
            "FOUND\t{}\t{}\t{}\t{}",
            line.method,
            line.path,
            line.command,
            json!(names)
        );
    }
    let lies: Vec<&String> = line
        .binds
        .iter()
        .filter(|b| !set.contains(b.as_str()))
        .collect();
    if lies.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "ak {} says it binds {lies:?} on {} {}, but no argument sets them (saw {set:?})",
            line.command, line.method, line.path
        ))
    }
}

/// Run `work` over `items` on several rigs at once.
async fn shards<T, R, F, Fut>(items: Vec<T>, work: F) -> Vec<R>
where
    T: Send + Sync + 'static,
    R: Send + 'static,
    F: Fn(Arc<Rig>, Arc<T>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = R> + Send,
{
    let items: Arc<Vec<Arc<T>>> = Arc::new(items.into_iter().map(Arc::new).collect());
    let next = Arc::new(AtomicUsize::new(0));
    let work = Arc::new(work);
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(12);
    let mut handles = Vec::new();
    for _ in 0..workers {
        let (items, next, work) = (items.clone(), next.clone(), work.clone());
        handles.push(tokio::spawn(async move {
            let rig = Arc::new(Rig::start().await);
            let mut out = Vec::new();
            loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(item) = items.get(i) else { break };
                out.push(work(rig.clone(), item.clone()).await);
            }
            out
        }));
    }
    let mut all = Vec::new();
    for handle in handles {
        all.extend(handle.await.expect("worker"));
    }
    all
}

#[tokio::test(flavor = "multi_thread", worker_threads = 12)]
#[ignore = "run by the Coverage job"]
async fn every_registry_line_tells_the_truth() {
    let (lines, leaves) = registry();
    let leaves: Arc<BTreeMap<String, Leaf>> =
        Arc::new(leaves.into_iter().map(|l| (l.command.clone(), l)).collect());
    let map = leaves.clone();
    let results = shards(lines, move |rig, line: Arc<Line>| {
        let map = map.clone();
        async move {
            let leaf = map.get(&line.command);
            let result = check_line(&rig, leaf, &line).await;
            ((*line).clone(), result)
        }
    })
    .await;
    let lies: Vec<String> = results
        .iter()
        .filter_map(|(_, result)| result.as_ref().err().cloned())
        .collect();
    if let Some(path) = std::env::var("AK_REGISTRY_LINES")
        .ok()
        .filter(|p| !p.is_empty())
    {
        let out: Vec<Value> = results
            .iter()
            .map(|(l, r)| {
                json!({"method": l.method, "path": l.path, "command": l.command,
                       "ok": r.is_ok(), "why": r.as_ref().err()})
            })
            .collect();
        std::fs::write(path, serde_json::to_string_pretty(&out).unwrap_or_default())
            .expect("write");
    }
    assert!(
        lies.is_empty(),
        "{} of {} registry lines aren't what the command does:\n{}",
        lies.len(),
        results.len(),
        lies.join("\n")
    );
}

/// The check has to be able to fail: each of these lines is false.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run by the Coverage job"]
async fn a_registry_line_that_lies_is_caught() {
    let (_, leaves) = registry();
    let show = leaves.iter().find(|l| l.command == "repo show").cloned();
    let rig = Rig::start().await;
    let lie = |method: &str, path: &str, binds: &[&str]| Line {
        method: method.to_string(),
        path: path.to_string(),
        command: "repo show".to_string(),
        binds: binds.iter().map(|b| b.to_string()).collect(),
    };

    let truth = lie("GET", "/api/v1/repositories/{key}", &[]);
    assert_eq!(check_line(&rig, show.as_ref(), &truth).await, Ok(()));

    let wrong_method = lie("DELETE", "/api/v1/repositories/{key}", &[]);
    assert!(
        check_line(&rig, show.as_ref(), &wrong_method)
            .await
            .is_err()
    );

    let wrong_path = lie("GET", "/api/v1/users/{id}", &[]);
    assert!(check_line(&rig, show.as_ref(), &wrong_path).await.is_err());

    let wrong_bind = lie("GET", "/api/v1/repositories/{key}", &["no_such_field"]);
    assert!(check_line(&rig, show.as_ref(), &wrong_bind).await.is_err());

    let no_command = check_line(&rig, None, &truth).await;
    assert!(no_command.is_err());
}

/// L0: every route the server has can be sent with `ak api`, by method and path.
#[tokio::test(flavor = "multi_thread", worker_threads = 12)]
#[ignore = "run by the Coverage job"]
async fn every_route_can_be_sent_with_ak_api() {
    let table: Value = serde_json::from_str(include_str!("../ROUTES.json")).expect("ROUTES.json");
    let oci: Value =
        serde_json::from_str(include_str!("../OCI_ROUTES.json")).expect("OCI_ROUTES.json");
    let routes: Vec<(String, String)> = table["routes"]
        .as_array()
        .expect("routes")
        .iter()
        .chain(oci.as_array().expect("OCI routes"))
        .map(|r| {
            (
                r["method"].as_str().unwrap_or("").to_string(),
                r["path"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    let total = routes.len();
    let failures: Vec<String> = shards(routes, |rig, route: Arc<(String, String)>| async move {
        let (method, template) = &*route;
        let sent = if method == "ANY" {
            "GET"
        } else {
            method.as_str()
        };
        let path: String = template
            .split('/')
            .map(|segment| match segment.find('{') {
                Some(at) => format!("{}x", &segment[..at]),
                None => segment.to_string(),
            })
            .collect::<Vec<_>>()
            .join("/");
        let run = rig
            .run(vec!["api".to_string(), sent.to_string(), path.clone()])
            .await;
        let arrived = run
            .requests
            .iter()
            .any(|r| r.method == sent && r.path == path);
        (!arrived).then(|| format!("{sent} {path} didn't arrive: {:?}", run.requests))
    })
    .await
    .into_iter()
    .flatten()
    .collect();
    assert!(
        failures.is_empty(),
        "{} of {total} routes can't be sent:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Not a check: what every leaf command sends, for the coverage measurement.
#[tokio::test(flavor = "multi_thread", worker_threads = 12)]
#[ignore = "run by the Coverage job"]
async fn probe_every_leaf() {
    let Ok(path) = std::env::var("AK_REGISTRY_PROBE") else {
        return;
    };
    let (_, leaves) = registry();
    let leaves: Vec<Leaf> = leaves
        .into_iter()
        .filter(|l| {
            let group = l.command.split_whitespace().next().unwrap_or("");
            !NOT_PROBED.contains(&group)
        })
        .collect();
    let results = shards(leaves, |rig, leaf: Arc<Leaf>| async move {
        let base = find_base(&rig, &leaf, None, &[]).await;
        let bound = probe_fields(&rig, &leaf, &base, None, &[]).await;
        let chosen: Vec<Value> = base
            .chosen
            .iter()
            .map(|(a, v)| json!({"arg": a.id, "value": v}))
            .collect();
        let requests: Vec<Value> = base
            .outcome
            .requests
            .iter()
            .map(|r| json!({"method": r.method, "path": r.path, "fields": r.fields}))
            .collect();
        json!({
            "command": leaf.command,
            "best": base.best,
            "chosen": chosen,
            "requests": requests,
            "bound": bound,
        })
    })
    .await;
    std::fs::write(
        path,
        serde_json::to_string_pretty(&results).unwrap_or_default(),
    )
    .expect("write");
}
