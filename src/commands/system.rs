use artifact_keeper_sdk::ClientSystemExt;
use clap::Subcommand;
use miette::Result;

use super::client::{client_for_optional_auth, raw_http_client};
use super::helpers::{raw_err, sdk_err};
use crate::cli::GlobalArgs;
use crate::config::AppConfig;
use crate::config::credentials::get_credential;
use crate::error::AkError;
use crate::output::{self, format_bytes};

#[derive(Subcommand)]
pub enum SystemCommand {
    /// Show the instance runtime configuration
    ///
    /// Security-posture fields (scanners, auth providers, storage backend,
    /// permission enforcement, plugin signing) are only returned to
    /// authenticated admins; for other callers they are omitted.
    Config,

    /// Show instance health. Use `ak monitoring health`
    #[command(hide = true, alias = "info")]
    Health,

    /// Print the server's OpenAPI document. The server has to run with ENABLE_SWAGGER=true
    Openapi,

    /// Fetch the server's Swagger UI, or a file of it. Needs ENABLE_SWAGGER=true
    #[command(hide = true)]
    SwaggerUi {
        /// A file under /swagger-ui
        path: Option<String>,
    },

    /// Ask /healthz, the same check as /health under its probe name
    #[command(hide = true)]
    Healthz,

    /// Ask /ready, the same check as /readyz under its older name
    #[command(hide = true)]
    Ready,
}

impl SystemCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Config => show_config(global).await,
            Self::Health => super::monitoring::health(global).await,
            Self::Openapi => print_raw("/api/v1/openapi.json", global).await,
            Self::SwaggerUi { path: Some(path) } => {
                print_raw(&format!("/swagger-ui/{path}"), global).await
            }
            Self::SwaggerUi { path: None } => print_raw("/swagger-ui", global).await,
            Self::Healthz => print_raw("/healthz", global).await,
            Self::Ready => print_raw("/ready", global).await,
        }
    }
}

/// GET a route the spec doesn't document and print what comes back.
async fn print_raw(route: &str, global: &GlobalArgs) -> Result<()> {
    let config = AppConfig::load()?;
    let (name, instance) = config.resolve_instance(global.instance.as_deref())?;
    let mut request =
        raw_http_client()?.get(format!("{}{route}", instance.url.trim_end_matches('/')));
    // These answer without a login, so being logged out isn't an error.
    if let Ok(credential) = get_credential(name) {
        request = request.header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", credential.access_token),
        );
    }
    let response = request
        .send()
        .await
        .map_err(|e| AkError::NetworkError(format!("GET {route} failed: {e}")))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| AkError::NetworkError(format!("GET {route} failed: {e}")))?;
    if !status.is_success() {
        return Err(raw_err(&format!("GET {route}"), status, &body).into());
    }
    println!("{}", body.trim_end());
    Ok(())
}

async fn show_config(global: &GlobalArgs) -> Result<()> {
    let client = client_for_optional_auth(global)?;
    let spinner = output::spinner("Fetching system configuration...");

    let (config, raw) = artifact_keeper_sdk::raw::capture(client.get_system_config().send()).await;
    let config = config
        .map_err(|e| sdk_err("get system configuration", e))?
        .into_inner();

    spinner.finish_and_clear();

    let table_str = format_config_detail(&config);
    println!(
        "{}",
        output::render_raw(raw.as_deref(), &config, &global.format, Some(table_str))
    );

    Ok(())
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn format_config_detail(config: &artifact_keeper_sdk::types::SystemConfigResponse) -> String {
    let max_upload = if config.max_upload_size_bytes == 0 {
        "unlimited".to_string()
    } else {
        format_bytes(config.max_upload_size_bytes)
    };

    let scanners = config
        .scanners
        .as_ref()
        .map(|s| {
            format!(
                "trivy={} openscap={} dependency-track={}",
                yes_no(s.trivy_enabled),
                yes_no(s.openscap_enabled),
                yes_no(s.dependency_track_enabled),
            )
        })
        .unwrap_or_else(|| "-".to_string());

    let permissions = config
        .permissions
        .as_ref()
        .map(|p| {
            format!(
                "enforced={} rules-exist={}",
                yes_no(p.enforcement_enabled),
                yes_no(p.rules_exist),
            )
        })
        .unwrap_or_else(|| "-".to_string());

    let plugin_signing = config
        .plugin_signing
        .as_ref()
        .map(|p| {
            format!(
                "required={} trusted-key={}",
                yes_no(p.required),
                yes_no(p.trusted_key_configured),
            )
        })
        .unwrap_or_else(|| "-".to_string());

    format!(
        "Demo Mode:         {}\n\
         Guest Access:      {}\n\
         Max Upload:        {}\n\
         OIDC Issuer:       {}\n\
         Auth (LDAP):       {}\n\
         Auth (OIDC):       {}\n\
         Auth (SSO):        {}\n\
         Search Engine:     {}\n\
         Storage Backend:   {}\n\
         Scanners:          {}\n\
         Permissions:       {}\n\
         Plugin Signing:    {}",
        yes_no(config.demo_mode),
        yes_no(config.guest_access_enabled),
        max_upload,
        config.oidc_issuer.as_deref().unwrap_or("-"),
        yes_no(config.auth.ldap_enabled),
        yes_no(config.auth.oidc_enabled),
        yes_no(config.auth.sso_enabled),
        config.search_engine.as_deref().unwrap_or("-"),
        config.storage_backend.as_deref().unwrap_or("-"),
        scanners,
        permissions,
        plugin_signing,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use serde_json::json;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: SystemCommand,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).unwrap()
    }

    // ---- parsing ----

    #[test]
    fn parse_config() {
        let cli = parse(&["test", "config"]);
        assert!(matches!(cli.command, SystemCommand::Config));
    }

    #[test]
    fn parse_health() {
        let cli = parse(&["test", "health"]);
        assert!(matches!(cli.command, SystemCommand::Health));
    }

    #[test]
    fn parse_health_info_alias() {
        let cli = parse(&["test", "info"]);
        assert!(matches!(cli.command, SystemCommand::Health));
    }

    #[test]
    fn parse_unknown_subcommand_fails() {
        assert!(TestCli::try_parse_from(["test", "bogus"]).is_err());
    }

    // ---- helpers ----

    #[test]
    fn yes_no_renders() {
        assert_eq!(yes_no(true), "yes");
        assert_eq!(yes_no(false), "no");
    }

    // ---- format functions ----

    fn config_json() -> serde_json::Value {
        json!({
            "auth": {
                "ldap_enabled": false,
                "local_login_enabled": false,
                "oidc_enabled": true,
                "silent_sso_enabled": false,
                "sso_enabled": true
            },
            "demo_mode": false,
            "guest_access_enabled": true,
            "max_upload_size_bytes": 1048576,
            "oidc_issuer": "https://sso.example.com",
            "permissions": { "enforcement_enabled": true, "rules_exist": false },
            "plugin_signing": { "required": true, "trusted_key_configured": false },
            "scanners": { "trivy_enabled": true, "openscap_enabled": false, "dependency_track_enabled": true },
            "search_engine": "opensearch",
            "storage_backend": "s3"
        })
    }

    fn config_json_minimal() -> serde_json::Value {
        // Non-admin caller: security-posture fields omitted.
        json!({
            "auth": {
                "ldap_enabled": false,
                "local_login_enabled": true,
                "oidc_enabled": false,
                "silent_sso_enabled": false,
                "sso_enabled": false
            },
            "demo_mode": false,
            "guest_access_enabled": false,
            "max_upload_size_bytes": 0
        })
    }

    fn health_json() -> serde_json::Value {
        json!({
            "status": "healthy",
            "version": "1.4.0",
            "commit": "abc1234",
            "dirty": false,
            "demo_mode": false,
            "checks": {
                "database": { "status": "healthy", "message": null },
                "storage": { "status": "healthy", "message": "write/read ok" },
                "ldap": null,
                "opensearch": { "status": "degraded", "message": "slow" },
                "security_scanner": null
            },
            "db_pool": { "active_connections": 1, "idle_connections": 4, "max_connections": 10, "size": 5 }
        })
    }

    #[test]
    fn format_config_detail_full() {
        let config: artifact_keeper_sdk::types::SystemConfigResponse =
            serde_json::from_value(config_json()).unwrap();
        let detail = format_config_detail(&config);
        assert!(detail.contains("trivy=yes"));
        assert!(detail.contains("s3"));
        assert!(detail.contains("opensearch"));
        assert!(detail.contains("1.0 MB"));
    }

    #[test]
    fn format_config_detail_minimal_unlimited() {
        let config: artifact_keeper_sdk::types::SystemConfigResponse =
            serde_json::from_value(config_json_minimal()).unwrap();
        let detail = format_config_detail(&config);
        assert!(detail.contains("unlimited"));
        // Omitted admin-only fields render as "-".
        assert!(detail.contains("Scanners:          -"));
    }

    // ---- wiremock handler tests ----

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    #[tokio::test]
    async fn handler_show_config() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/system/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(config_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = show_config(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_config_minimal() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/system/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(config_json_minimal()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Table);
        let result = show_config(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_health() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200).set_body_json(health_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = crate::commands::monitoring::health(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_health_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200).set_body_json(health_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = crate::commands::monitoring::health(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    // ---- insta snapshot ----

    #[test]
    fn snapshot_system_config_json() {
        let config: serde_json::Value = config_json();
        let output = crate::output::render(&config, &crate::output::OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("system_config_json", parsed);
    }
}
