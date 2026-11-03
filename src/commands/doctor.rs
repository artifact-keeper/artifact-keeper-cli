use std::time::Duration;

use artifact_keeper_sdk::{ClientAuthExt, ClientRepositoriesExt};
use console::style;
use miette::Result;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};

use super::helpers::decode_jwt_expiry;
use crate::config::credentials::{StoredCredential, get_credential};
use crate::config::{AppConfig, InstanceConfig};

const CHECK: &str = "*";
const CROSS: &str = "x";
const WARN: &str = "!";
const DOT: &str = "-";

/// Shorter timeouts than the normal SDK client -- diagnostics should fail fast.
const DIAG_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DIAG_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The server API version this build of `ak` is generated from.
const AK_API_VERSION: &str = include_str!("../../API_VERSION").trim_ascii();

#[derive(Default)]
struct DiagResult {
    passes: u32,
    warnings: u32,
    failures: u32,
}

impl DiagResult {
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

    let mut diag = DiagResult::default();

    if config.instances.is_empty() {
        diag.fail("No instances configured. Run `ak instance add <name> <url>` to get started.");
        print_summary(&diag);
        return Ok(());
    }

    eprintln!("  {}", style("Instances").bold().underlined());
    for (name, instance) in &config.instances {
        check_instance(name, instance, &mut diag).await;
        check_server_version(name, instance, &mut diag).await;
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
) -> std::result::Result<artifact_keeper_sdk::Client, String> {
    let builder = reqwest::ClientBuilder::new()
        .connect_timeout(DIAG_CONNECT_TIMEOUT)
        .timeout(DIAG_REQUEST_TIMEOUT);
    let http_client = crate::transport::apply_custom_ca(builder)
        .map_err(|e| e.to_string())?
        .build()
        .map_err(|e| e.to_string())?;

    Ok(artifact_keeper_sdk::Client::new_with_client(
        &instance.url,
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

    let builder = reqwest::ClientBuilder::new()
        .default_headers(headers)
        .redirect(super::client::redirect_policy())
        .connect_timeout(DIAG_CONNECT_TIMEOUT)
        .timeout(DIAG_REQUEST_TIMEOUT);
    let http_client = crate::transport::apply_custom_ca(builder)
        .map_err(|e| e.to_string())?
        .build()
        .map_err(|e| e.to_string())?;

    Ok(artifact_keeper_sdk::Client::new_with_client(
        &instance.url,
        http_client,
    ))
}

async fn check_instance(name: &str, instance: &InstanceConfig, diag: &mut DiagResult) {
    // With credentials the count means something: without them, the server only
    // counts public repositories, which read as "0 repos" on a private instance.
    let cred = get_credential(name).ok();
    let built = match &cred {
        Some(cred) => build_diag_client_with_auth(instance, cred),
        None => build_diag_client(instance),
    };
    let client = match built {
        Ok(c) => c,
        Err(e) => {
            diag.fail(&format!(
                "{name} ({}) -- failed to build HTTP client: {e}",
                instance.url
            ));
            return;
        }
    };

    // Probe the API by listing repos (page=1, per_page=1) — works without auth
    // and validates connectivity, API routing, and database access in one call.
    match client.list_repositories().page(1).per_page(1).send().await {
        Ok(resp) => {
            let scope = if cred.is_some() { "" } else { "public " };
            diag.pass(&format!(
                "{name} ({}) -- reachable, {} {scope}repos",
                instance.url, resp.pagination.total
            ));
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

/// Fetch the server version from `/health`.
///
/// This reads the one field it needs instead of using the generated client, so
/// it still works on an old server whose response no longer fits the SDK types,
/// which is exactly when the answer matters.
async fn fetch_server_version(instance: &InstanceConfig) -> std::result::Result<String, String> {
    let builder = reqwest::ClientBuilder::new()
        .connect_timeout(DIAG_CONNECT_TIMEOUT)
        .timeout(DIAG_REQUEST_TIMEOUT);
    let http = crate::transport::apply_custom_ca(builder)
        .map_err(|e| e.to_string())?
        .build()
        .map_err(|e| e.to_string())?;

    let url = format!("{}/health", instance.url.trim_end_matches('/'));
    let body: serde_json::Value = http
        .get(url)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;

    body.get("version")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| "no version in the /health response".to_string())
}

async fn check_server_version(name: &str, instance: &InstanceConfig, diag: &mut DiagResult) {
    match fetch_server_version(instance).await {
        Ok(server) => match server_support(&server, AK_API_VERSION) {
            ServerSupport::Supported => {
                diag.pass(&format!("{name} -- server version {server}"));
            }
            ServerSupport::TooOld => diag.warn(&format!(
                "{name} -- server version {server} is unsupported by ak {} \
                 (built for API {AK_API_VERSION}), upgrade the server",
                env!("CARGO_PKG_VERSION"),
            )),
            ServerSupport::TooNew => diag.warn(&format!(
                "{name} -- server version {server} is newer than ak {} \
                 (built for API {AK_API_VERSION}), upgrade ak",
                env!("CARGO_PKG_VERSION"),
            )),
            ServerSupport::Unknown => diag.warn(&format!(
                "{name} -- could not interpret server version '{server}'"
            )),
        },
        Err(e) => diag.warn(&format!(
            "{name} -- could not read the server version: {}",
            classify_connection_error(&e)
        )),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ServerSupport {
    Supported,
    TooOld,
    TooNew,
    Unknown,
}

/// `ak` supports the server minor it is built for and the one before it.
fn server_support(server: &str, api: &str) -> ServerSupport {
    let (Some(server), Some(api)) = (major_minor(server), major_minor(api)) else {
        return ServerSupport::Unknown;
    };
    if server > api {
        ServerSupport::TooNew
    } else if server.0 == api.0 && server.1 + 1 >= api.1 {
        ServerSupport::Supported
    } else {
        ServerSupport::TooOld
    }
}

fn major_minor(version: &str) -> Option<(u64, u64)> {
    let mut parts = version.trim().trim_start_matches('v').split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
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

    let user = match client.get_current_user().send().await {
        Ok(user) => user,
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
            return;
        }
    };

    let mut details = format!("authenticated as {}", user.username);
    if user.is_admin {
        details.push_str(" (admin)");
    }

    if let Some(exp) = decode_jwt_expiry(&cred.access_token) {
        let seconds_left = exp - chrono::Utc::now().timestamp();
        match token_expiry_status(seconds_left) {
            TokenExpiry::Expired => {
                diag.fail(&format!(
                    "{name} -- token expired (run: ak auth login --instance {name})"
                ));
                return;
            }
            TokenExpiry::Session(minutes) => {
                details.push_str(&format!(", login session expires in {minutes} minutes"));
            }
            TokenExpiry::Soon(days) => {
                diag.warn(&format!(
                    "{name} -- {details}, token expires in {days} days (run: ak auth login --instance {name})"
                ));
                return;
            }
            TokenExpiry::Later(days) => {
                details.push_str(&format!(", token expires in {days} days"));
            }
        }
    }

    diag.pass(&format!("{name} -- {details}"));
}

#[derive(Debug, PartialEq, Eq)]
enum TokenExpiry {
    Expired,
    /// A login token, under a day: minutes left. These are short-lived by design,
    /// so this isn't a warning.
    Session(i64),
    /// A longer-lived token within a week of expiring: days left.
    Soon(i64),
    Later(i64),
}

fn token_expiry_status(seconds_left: i64) -> TokenExpiry {
    const DAY: i64 = 86_400;
    if seconds_left < 0 {
        TokenExpiry::Expired
    } else if seconds_left < DAY {
        TokenExpiry::Session(seconds_left / 60)
    } else if seconds_left <= 7 * DAY {
        TokenExpiry::Soon(seconds_left / DAY)
    } else {
        TokenExpiry::Later(seconds_left / DAY)
    }
}

// ---------------------------------------------------------------------------
// Package manager configs
// ---------------------------------------------------------------------------

fn check_package_configs(config: &AppConfig, diag: &mut DiagResult) {
    let cwd = std::env::current_dir().unwrap_or_default();
    let home = dirs::home_dir().unwrap_or_default();
    let config_base = dirs::config_dir().unwrap_or_default();

    let pip_filename = if cfg!(windows) { "pip.ini" } else { "pip.conf" };

    // The last field is the route that tool's endpoints are mounted at.
    let configs: &[(&str, &str, Vec<std::path::PathBuf>, &str)] = &[
        (
            "npm",
            ".npmrc",
            vec![cwd.join(".npmrc"), home.join(".npmrc")],
            "npm",
        ),
        (
            "pip",
            pip_filename,
            vec![config_base.join("pip").join(pip_filename)],
            "pypi",
        ),
        (
            "cargo",
            "config.toml",
            vec![home.join(".cargo/config.toml")],
            "cargo",
        ),
        (
            "maven",
            "settings.xml",
            vec![home.join(".m2/settings.xml")],
            "maven",
        ),
    ];

    let instance_urls: Vec<&str> = config.instances.values().map(|i| i.url.as_str()).collect();

    for (name, desc, paths, route) in configs {
        match paths.iter().find(|p| p.exists()) {
            Some(path) => {
                let content = std::fs::read_to_string(path).unwrap_or_default();
                match config_reference(&content, &instance_urls, route) {
                    ConfigReference::Working => diag.pass(&format!(
                        "{name} ({desc}) -- configured, points to Artifact Keeper"
                    )),
                    ConfigReference::WrongRoute => diag.warn(&format!(
                        "{name} ({desc}) -- points at an instance, but not at its /{route}/ route, \
                         so it won't work (run: ak setup {name})"
                    )),
                    ConfigReference::None => diag.warn(&format!(
                        "{name} ({desc}) -- found at {} but doesn't reference any configured instance",
                        path.display()
                    )),
                }
            }
            None => {
                diag.skip(&format!("{name} -- not configured"));
            }
        }
    }

    check_docker_config(&home, &instance_urls, diag);
}

#[derive(Debug, PartialEq, Eq)]
enum ConfigReference {
    Working,
    /// Mentions the instance at some other path, such as the `/api/v1/<format>/`
    /// URLs that older versions of `ak setup` wrote.
    WrongRoute,
    None,
}

/// How a package manager's config relates to the configured instances. Compares
/// host and port rather than the URL, because a config can have credentials
/// between the scheme and the host.
fn config_reference(content: &str, instance_urls: &[&str], route: &str) -> ConfigReference {
    let mut mentioned = false;
    for url in instance_urls {
        let Some(authority) = url::Url::parse(url).ok().and_then(|u| {
            u.host_str()
                .map(|h| u.port().map_or(h.to_string(), |p| format!("{h}:{p}")))
        }) else {
            continue;
        };
        if content.contains(&format!("{authority}/{route}/")) {
            return ConfigReference::Working;
        }
        mentioned |= content.contains(&authority);
    }
    if mentioned {
        ConfigReference::WrongRoute
    } else {
        ConfigReference::None
    }
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

/// Proxy-related environment variables honored by the HTTP client (reqwest).
const PROXY_ENV_VARS: &[&str] = &[
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
];

/// Redact the userinfo part of a proxy URL (e.g. `http://user:pass@host`)
/// so credentials embedded in proxy settings are not echoed to the terminal.
fn redact_proxy_value(value: &str) -> String {
    if let Some(at) = value.rfind('@') {
        let scheme_end = value.find("://").map(|i| i + 3).unwrap_or(0);
        if at > scheme_end {
            return format!("{}***@{}", &value[..scheme_end], &value[at + 1..]);
        }
    }
    value.to_string()
}

/// Surface any active proxy configuration so users can tell when CLI traffic
/// is being routed through an intermediary.
fn check_proxy_env(diag: &mut DiagResult) {
    let mut found = false;
    for var in PROXY_ENV_VARS {
        if let Ok(value) = std::env::var(var) {
            if value.is_empty() {
                continue;
            }
            found = true;
            diag.skip(&format!(
                "Proxy: {var}={} (requests are routed through this proxy)",
                redact_proxy_value(&value)
            ));
        }
    }
    if !found {
        diag.skip("No proxy environment variables set");
    }
}

fn check_cli(diag: &mut DiagResult) {
    let version = env!("CARGO_PKG_VERSION");
    diag.pass(&format!("CLI version: {version}"));

    check_proxy_env(diag);

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

#[cfg(test)]
mod tests {
    use super::*;

    // ---- server version support ----

    #[test]
    fn server_support_allows_current_and_previous_minor() {
        assert_eq!(
            server_support("1.11.10", "1.11.10"),
            ServerSupport::Supported
        );
        assert_eq!(
            server_support("1.11.0", "1.11.10"),
            ServerSupport::Supported
        );
        assert_eq!(
            server_support("1.11.99", "1.11.10"),
            ServerSupport::Supported
        );
        assert_eq!(
            server_support("1.10.2", "1.11.10"),
            ServerSupport::Supported
        );
        assert_eq!(
            server_support("v1.10.2", "1.11.10"),
            ServerSupport::Supported
        );
    }

    #[test]
    fn server_support_flags_old_servers() {
        assert_eq!(server_support("1.9.1", "1.11.10"), ServerSupport::TooOld);
        assert_eq!(server_support("0.11.0", "1.11.10"), ServerSupport::TooOld);
        assert_eq!(server_support("1.99.0", "2.0.0"), ServerSupport::TooOld);
    }

    #[test]
    fn server_support_flags_new_servers() {
        assert_eq!(server_support("1.12.0", "1.11.10"), ServerSupport::TooNew);
        assert_eq!(server_support("2.0.0", "1.11.10"), ServerSupport::TooNew);
    }

    #[test]
    fn server_support_unknown_on_unparseable_version() {
        assert_eq!(server_support("dev", "1.11.10"), ServerSupport::Unknown);
        assert_eq!(server_support("", "1.11.10"), ServerSupport::Unknown);
    }

    #[test]
    fn api_version_is_pinned() {
        assert!(major_minor(AK_API_VERSION).is_some());
    }

    async fn version_check_diag(body: serde_json::Value) -> DiagResult {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;
        let instance = InstanceConfig {
            url: server.uri(),
            api_version: "v1".to_string(),
            allow_insecure_http: true,
        };
        let mut diag = DiagResult::default();
        check_server_version("test", &instance, &mut diag).await;
        diag
    }

    #[tokio::test]
    async fn check_server_version_passes_current_server() {
        let diag = version_check_diag(serde_json::json!({ "version": AK_API_VERSION })).await;
        assert_eq!((diag.passes, diag.warnings), (1, 0));
    }

    #[tokio::test]
    async fn check_server_version_warns_on_old_server() {
        // Only `version` is present: an old server may not fit the SDK's types.
        let diag = version_check_diag(serde_json::json!({ "version": "0.1.0" })).await;
        assert_eq!((diag.passes, diag.warnings), (0, 1));
    }

    #[tokio::test]
    async fn check_server_version_warns_without_version() {
        let diag = version_check_diag(serde_json::json!({ "status": "healthy" })).await;
        assert_eq!((diag.passes, diag.warnings), (0, 1));
    }

    // ---- DiagResult ----

    #[test]
    fn diag_result_default() {
        let diag = DiagResult::default();
        assert_eq!(diag.passes, 0);
        assert_eq!(diag.warnings, 0);
        assert_eq!(diag.failures, 0);
    }

    #[test]
    fn diag_result_pass_increments() {
        let mut diag = DiagResult::default();
        diag.pass("test pass");
        assert_eq!(diag.passes, 1);
        assert_eq!(diag.warnings, 0);
        assert_eq!(diag.failures, 0);
    }

    #[test]
    fn diag_result_warn_increments() {
        let mut diag = DiagResult::default();
        diag.warn("test warn");
        assert_eq!(diag.passes, 0);
        assert_eq!(diag.warnings, 1);
        assert_eq!(diag.failures, 0);
    }

    #[test]
    fn diag_result_fail_increments() {
        let mut diag = DiagResult::default();
        diag.fail("test fail");
        assert_eq!(diag.passes, 0);
        assert_eq!(diag.warnings, 0);
        assert_eq!(diag.failures, 1);
    }

    #[test]
    fn diag_result_mixed() {
        let mut diag = DiagResult::default();
        diag.pass("p1");
        diag.pass("p2");
        diag.warn("w1");
        diag.fail("f1");
        diag.fail("f2");
        diag.fail("f3");
        assert_eq!(diag.passes, 2);
        assert_eq!(diag.warnings, 1);
        assert_eq!(diag.failures, 3);
    }

    // ---- pluralize ----

    #[test]
    fn pluralize_zero() {
        assert_eq!(pluralize(0, "issue", "issues"), "issues");
    }

    #[test]
    fn pluralize_one() {
        assert_eq!(pluralize(1, "issue", "issues"), "issue");
    }

    #[test]
    fn pluralize_many() {
        assert_eq!(pluralize(5, "issue", "issues"), "issues");
    }

    // ---- classify_connection_error ----

    #[test]
    fn classify_connection_refused() {
        assert_eq!(
            classify_connection_error("Connection refused (os error 61)"),
            "connection refused"
        );
    }

    #[test]
    fn classify_timeout() {
        assert_eq!(
            classify_connection_error("operation timed out"),
            "connection timed out"
        );
    }

    #[test]
    fn classify_timeout_variant() {
        assert_eq!(
            classify_connection_error("request timeout after 10s"),
            "connection timed out"
        );
    }

    #[test]
    fn classify_dns() {
        assert_eq!(
            classify_connection_error("DNS resolution failed for host"),
            "DNS resolution failed"
        );
    }

    #[test]
    fn classify_dns_resolve() {
        assert_eq!(
            classify_connection_error("failed to resolve hostname"),
            "DNS resolution failed"
        );
    }

    #[test]
    fn classify_tls() {
        let result = classify_connection_error("SSL certificate problem");
        assert!(result.starts_with("TLS/certificate error:"));
    }

    #[test]
    fn classify_certificate() {
        let result = classify_connection_error("certificate verify failed");
        assert!(result.starts_with("TLS/certificate error:"));
    }

    #[test]
    fn classify_tls_variant() {
        let result = classify_connection_error("TLS handshake failed");
        assert!(result.starts_with("TLS/certificate error:"));
    }

    #[test]
    fn classify_unknown() {
        assert_eq!(
            classify_connection_error("something else happened"),
            "something else happened"
        );
    }

    // ---- token_expiry_status ----

    #[test]
    fn a_login_token_is_not_a_warning_about_zero_days() {
        assert_eq!(token_expiry_status(1800), TokenExpiry::Session(30));
        assert_eq!(token_expiry_status(86_399), TokenExpiry::Session(1439));
    }

    #[test]
    fn longer_tokens_warn_within_a_week() {
        assert_eq!(token_expiry_status(-1), TokenExpiry::Expired);
        assert_eq!(token_expiry_status(3 * 86_400), TokenExpiry::Soon(3));
        assert_eq!(token_expiry_status(30 * 86_400), TokenExpiry::Later(30));
    }

    // ---- config_reference ----

    #[test]
    fn a_config_with_the_real_route_is_working() {
        let urls = ["http://ak.test:8080"];
        assert_eq!(
            config_reference("registry=http://ak.test:8080/npm/r/\n", &urls, "npm"),
            ConfigReference::Working
        );
        // Credentials between the scheme and the host.
        assert_eq!(
            config_reference(
                "index-url = http://__token__:x@ak.test:8080/pypi/r/simple/\n",
                &urls,
                "pypi"
            ),
            ConfigReference::Working
        );
    }

    #[test]
    fn a_config_from_the_old_setup_is_not_reported_as_working() {
        let urls = ["https://ak.test"];
        assert_eq!(
            config_reference("registry=https://ak.test/api/v1/npm/r/\n", &urls, "npm"),
            ConfigReference::WrongRoute
        );
    }

    #[test]
    fn a_config_for_another_registry_is_no_reference() {
        assert_eq!(
            config_reference(
                "registry=https://registry.npmjs.org/\n",
                &["https://ak.test"],
                "npm"
            ),
            ConfigReference::None
        );
    }

    // ---- decode_jwt_expiry ----

    #[test]
    fn decode_jwt_valid() {
        // JWT payload: {"exp": 1700000000, "sub": "user"}
        // base64url("{"exp":1700000000,"sub":"user"}") = eyJleHAiOjE3MDAwMDAwMDAsInN1YiI6InVzZXIifQ
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3MDAwMDAwMDAsInN1YiI6InVzZXIifQ.signature";
        assert_eq!(decode_jwt_expiry(token), Some(1700000000));
    }

    #[test]
    fn decode_jwt_no_exp() {
        // JWT payload: {"sub": "user"} (no exp claim)
        // base64url("{"sub":"user"}") = eyJzdWIiOiJ1c2VyIn0
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature";
        assert_eq!(decode_jwt_expiry(token), None);
    }

    #[test]
    fn decode_jwt_invalid_base64() {
        let token = "header.!!!invalid!!!.signature";
        assert_eq!(decode_jwt_expiry(token), None);
    }

    #[test]
    fn decode_jwt_no_parts() {
        assert_eq!(decode_jwt_expiry("no-dots-here"), None);
    }

    #[test]
    fn decode_jwt_one_part() {
        assert_eq!(decode_jwt_expiry("header."), None);
    }

    #[test]
    fn decode_jwt_invalid_json() {
        // base64url("not json") = bm90IGpzb24
        let token = "header.bm90IGpzb24.signature";
        assert_eq!(decode_jwt_expiry(token), None);
    }

    // ---- redact_proxy_value ----

    #[test]
    fn redact_proxy_plain_url_unchanged() {
        assert_eq!(
            redact_proxy_value("http://proxy.corp:3128"),
            "http://proxy.corp:3128"
        );
    }

    #[test]
    fn redact_proxy_credentials_hidden() {
        assert_eq!(
            redact_proxy_value("http://user:secret@proxy.corp:3128"),
            "http://***@proxy.corp:3128"
        );
    }

    #[test]
    fn redact_proxy_no_scheme_with_credentials() {
        assert_eq!(
            redact_proxy_value("user:secret@proxy.corp:3128"),
            "***@proxy.corp:3128"
        );
    }

    #[test]
    fn redact_proxy_no_proxy_list_unchanged() {
        assert_eq!(
            redact_proxy_value("localhost,127.0.0.1,.internal"),
            "localhost,127.0.0.1,.internal"
        );
    }

    // ---- print_summary ----

    #[test]
    fn print_summary_all_pass() {
        let mut diag = DiagResult::default();
        diag.passes = 5;
        // Just verify it doesn't panic
        print_summary(&diag);
    }

    #[test]
    fn print_summary_with_failures() {
        let mut diag = DiagResult::default();
        diag.failures = 2;
        diag.warnings = 1;
        print_summary(&diag);
    }
}
