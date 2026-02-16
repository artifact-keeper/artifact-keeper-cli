use std::time::Duration;

use artifact_keeper_sdk::{ClientAuthExt, ClientHealthExt};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use console::style;
use miette::Result;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};

use crate::config::credentials::{StoredCredential, get_credential};
use crate::config::{AppConfig, InstanceConfig};

const CHECK: &str = "*";
const CROSS: &str = "x";
const WARN: &str = "!";
const DOT: &str = "-";

/// Shorter timeouts than the normal SDK client -- diagnostics should fail fast.
const DIAG_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DIAG_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

struct DiagResult {
    passes: u32,
    warnings: u32,
    failures: u32,
}

impl DiagResult {
    fn new() -> Self {
        Self {
            passes: 0,
            warnings: 0,
            failures: 0,
        }
    }

    fn pass(&mut self, msg: &str) {
        self.passes += 1;
        eprintln!("  {} {}", style(CHECK).green(), msg);
    }

    fn warn(&mut self, msg: &str) {
        self.warnings += 1;
        eprintln!("  {} {}", style(WARN).yellow(), msg);
    }

    fn fail(&mut self, msg: &str) {
        self.failures += 1;
        eprintln!("  {} {}", style(CROSS).red(), msg);
    }

    fn skip(&self, msg: &str) {
        eprintln!("  {} {}", style(DOT).dim(), msg);
    }
}

pub async fn execute(_global: &crate::cli::GlobalArgs) -> Result<()> {
    let config = AppConfig::load()?;

    eprintln!();
    eprintln!("  {}", style("Artifact Keeper Doctor").bold());
    eprintln!("  {}", style("=".repeat(22)).dim());
    eprintln!();

    let mut diag = DiagResult::new();

    if config.instances.is_empty() {
        diag.fail("No instances configured. Run `ak instance add <name> <url>` to get started.");
        print_summary(&diag);
        return Ok(());
    }

    eprintln!("  {}", style("Instances").bold().underlined());
    for (name, instance) in &config.instances {
        check_instance(name, instance, &mut diag).await;
    }
    eprintln!();

    eprintln!("  {}", style("Authentication").bold().underlined());
    for (name, instance) in &config.instances {
        check_auth(name, instance, &mut diag).await;
    }
    eprintln!();

    eprintln!("  {}", style("Package Manager Configs").bold().underlined());
    check_package_configs(&config, &mut diag);
    eprintln!();

    eprintln!("  {}", style("CLI").bold().underlined());
    check_cli(&mut diag);
    eprintln!();

    print_summary(&diag);
    Ok(())
}

fn print_summary(diag: &DiagResult) {
    let total_issues = diag.failures + diag.warnings;
    if total_issues == 0 {
        eprintln!(
            "  {} {}",
            style(CHECK).green(),
            style("All checks passed!").green().bold()
        );
    } else {
        let mut parts = Vec::new();
        if diag.failures > 0 {
            parts.push(format!(
                "{} {}",
                diag.failures,
                pluralize(diag.failures, "issue", "issues")
            ));
        }
        if diag.warnings > 0 {
            parts.push(format!(
                "{} {}",
                diag.warnings,
                pluralize(diag.warnings, "warning", "warnings")
            ));
        }
        eprintln!("  Summary: {}", style(parts.join(", ")).yellow().bold());
    }
    eprintln!();
}

fn pluralize<'a>(count: u32, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

// ---------------------------------------------------------------------------
// Instance connectivity
// ---------------------------------------------------------------------------

fn build_diag_client(
    instance: &InstanceConfig,
) -> std::result::Result<artifact_keeper_sdk::Client, reqwest::Error> {
    let http_client = reqwest::ClientBuilder::new()
        .connect_timeout(DIAG_CONNECT_TIMEOUT)
        .timeout(DIAG_REQUEST_TIMEOUT)
        .build()?;

    let base_url = format!("{}/api/{}", instance.url, instance.api_version);
    Ok(artifact_keeper_sdk::Client::new_with_client(
        &base_url,
        http_client,
    ))
}

fn build_diag_client_with_auth(
    instance: &InstanceConfig,
    cred: &StoredCredential,
) -> std::result::Result<artifact_keeper_sdk::Client, String> {
    let auth_value = format!("Bearer {}", cred.access_token);
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&auth_value).map_err(|e| e.to_string())?,
    );

    let http_client = reqwest::ClientBuilder::new()
        .default_headers(headers)
        .connect_timeout(DIAG_CONNECT_TIMEOUT)
        .timeout(DIAG_REQUEST_TIMEOUT)
        .build()
        .map_err(|e| e.to_string())?;

    let base_url = format!("{}/api/{}", instance.url, instance.api_version);
    Ok(artifact_keeper_sdk::Client::new_with_client(
        &base_url,
        http_client,
    ))
}

async fn check_instance(name: &str, instance: &InstanceConfig, diag: &mut DiagResult) {
    let client = match build_diag_client(instance) {
        Ok(c) => c,
        Err(e) => {
            diag.fail(&format!(
                "{name} ({}) -- failed to build HTTP client: {e}",
                instance.url
            ));
            return;
        }
    };

    match client.health_check().send().await {
        Ok(resp) => {
            let version = &resp.version;
            let sub_issues = collect_health_issues(&resp.checks);

            if sub_issues.is_empty() && resp.status == "healthy" {
                diag.pass(&format!("{name} ({}) -- v{version}, healthy", instance.url));
            } else if resp.status == "healthy" {
                diag.warn(&format!(
                    "{name} ({}) -- v{version}, degraded: {}",
                    instance.url,
                    sub_issues.join("; ")
                ));
            } else {
                diag.fail(&format!(
                    "{name} ({}) -- v{version}, {}: {}",
                    instance.url,
                    resp.status,
                    sub_issues.join("; ")
                ));
            }
        }
        Err(e) => {
            diag.fail(&format!(
                "{name} ({}) -- {}",
                instance.url,
                classify_connection_error(&e.to_string())
            ));
        }
    }
}

/// Collect human-readable issue strings from the health check sub-components.
fn collect_health_issues(checks: &artifact_keeper_sdk::types::HealthChecks) -> Vec<String> {
    let mut issues = Vec::new();
    for (label, check) in [("database", &checks.database), ("storage", &checks.storage)] {
        if check.status != "healthy" {
            let detail = check.message.as_deref().unwrap_or(&check.status);
            issues.push(format!("{label}: {detail}"));
        }
    }
    issues
}

/// Turn a raw error string into a concise diagnostic message.
fn classify_connection_error(err: &str) -> String {
    let err_lower = err.to_lowercase();
    if err_lower.contains("connection refused") {
        "connection refused".to_string()
    } else if err_lower.contains("timed out") || err_lower.contains("timeout") {
        "connection timed out".to_string()
    } else if err_lower.contains("dns") || err_lower.contains("resolve") {
        "DNS resolution failed".to_string()
    } else if err_lower.contains("certificate")
        || err_lower.contains("ssl")
        || err_lower.contains("tls")
    {
        format!("TLS/certificate error: {err}")
    } else {
        err.to_string()
    }
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

async fn check_auth(name: &str, instance: &InstanceConfig, diag: &mut DiagResult) {
    let cred = match get_credential(name) {
        Ok(c) => c,
        Err(_) => {
            diag.skip(&format!(
                "{name} -- not authenticated (run: ak auth login --instance {name})"
            ));
            return;
        }
    };

    let client = match build_diag_client_with_auth(instance, &cred) {
        Ok(c) => c,
        Err(_) => {
            diag.fail(&format!("{name} -- invalid credentials format"));
            return;
        }
    };

    match client.get_current_user().send().await {
        Ok(user) => {
            let mut details = format!("authenticated as {}", user.username);
            if user.is_admin {
                details.push_str(" (admin)");
            }

            if let Some(exp) = decode_jwt_expiry(&cred.access_token) {
                let now = chrono::Utc::now().timestamp();
                let days_left = (exp - now) / 86400;
                if days_left < 0 {
                    diag.fail(&format!(
                        "{name} -- token expired (run: ak auth login --instance {name})"
                    ));
                    return;
                } else if days_left <= 7 {
                    diag.warn(&format!(
                        "{name} -- {details}, token expires in {days_left} days (run: ak auth login --instance {name})"
                    ));
                    return;
                } else {
                    details.push_str(&format!(", token expires in {days_left} days"));
                }
            }

            diag.pass(&format!("{name} -- {details}"));
        }
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("401") || err_str.contains("Unauthorized") {
                diag.fail(&format!(
                    "{name} -- token invalid or expired (run: ak auth login --instance {name})"
                ));
            } else if err_str.contains("connection") || err_str.contains("timeout") {
                diag.skip(&format!("{name} -- cannot reach server"));
            } else {
                diag.fail(&format!("{name} -- auth check failed: {err_str}"));
            }
        }
    }
}

/// Decode JWT expiry claim without verifying the signature.
fn decode_jwt_expiry(token: &str) -> Option<i64> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    json.get("exp")?.as_i64()
}

// ---------------------------------------------------------------------------
// Package manager configs
// ---------------------------------------------------------------------------

fn check_package_configs(config: &AppConfig, diag: &mut DiagResult) {
    let cwd = std::env::current_dir().unwrap_or_default();
    let home = dirs::home_dir().unwrap_or_default();
    let config_base = dirs::config_dir().unwrap_or_default();

    let pip_filename = if cfg!(windows) { "pip.ini" } else { "pip.conf" };

    let configs: &[(&str, &str, Vec<std::path::PathBuf>)] = &[
        (
            "npm",
            ".npmrc",
            vec![cwd.join(".npmrc"), home.join(".npmrc")],
        ),
        (
            "pip",
            pip_filename,
            vec![config_base.join("pip").join(pip_filename)],
        ),
        (
            "cargo",
            "config.toml",
            vec![home.join(".cargo/config.toml")],
        ),
        ("maven", "settings.xml", vec![home.join(".m2/settings.xml")]),
    ];

    let instance_urls: Vec<&str> = config.instances.values().map(|i| i.url.as_str()).collect();

    for (name, desc, paths) in configs {
        match paths.iter().find(|p| p.exists()) {
            Some(path) => {
                let content = std::fs::read_to_string(path).unwrap_or_default();
                let points_to_ak = instance_urls.iter().any(|url| content.contains(url));

                if points_to_ak {
                    diag.pass(&format!(
                        "{name} ({desc}) -- configured, points to Artifact Keeper"
                    ));
                } else {
                    diag.warn(&format!(
                        "{name} ({desc}) -- found at {} but doesn't reference any configured instance",
                        path.display()
                    ));
                }
            }
            None => {
                diag.skip(&format!("{name} -- not configured"));
            }
        }
    }

    check_docker_config(&home, &instance_urls, diag);
}

fn check_docker_config(home: &std::path::Path, instance_urls: &[&str], diag: &mut DiagResult) {
    let docker_config = home.join(".docker/config.json");
    if !docker_config.exists() {
        diag.skip("docker -- not configured");
        return;
    }

    let content = std::fs::read_to_string(&docker_config).unwrap_or_default();
    let points_to_ak = instance_urls.iter().any(|url| {
        url::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(|h| content.contains(h)))
            .unwrap_or(false)
    });

    if points_to_ak {
        diag.pass("docker (config.json) -- logged in to Artifact Keeper registry");
    } else {
        diag.skip("docker -- not configured for any Artifact Keeper instance");
    }
}

// ---------------------------------------------------------------------------
// CLI info
// ---------------------------------------------------------------------------

fn check_cli(diag: &mut DiagResult) {
    let version = env!("CARGO_PKG_VERSION");
    diag.pass(&format!("CLI version: {version}"));

    match crate::config::config_dir() {
        Ok(dir) => {
            if dir.exists() {
                diag.pass(&format!("Config directory: {}", dir.display()));
            } else {
                diag.warn(&format!(
                    "Config directory doesn't exist: {} (will be created on first use)",
                    dir.display()
                ));
            }
        }
        Err(_) => {
            diag.fail("Cannot determine config directory");
        }
    }
}
