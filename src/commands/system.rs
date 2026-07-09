use artifact_keeper_sdk::{ClientHealthExt, ClientSystemExt};
use clap::Subcommand;
use miette::Result;

use super::client::client_for_optional_auth;
use super::helpers::sdk_err;
use crate::cli::GlobalArgs;
use crate::output::{self, OutputFormat, format_bytes};

#[derive(Subcommand)]
pub enum SystemCommand {
    /// Show the instance runtime configuration
    ///
    /// Security-posture fields (scanners, auth providers, storage backend,
    /// permission enforcement, plugin signing) are only returned to
    /// authenticated admins; for other callers they are omitted.
    Config,

    /// Show instance health, version, and dependency status
    #[command(visible_alias = "info")]
    Health,
}

impl SystemCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Config => show_config(global).await,
            Self::Health => show_health(global).await,
        }
    }
}

async fn show_config(global: &GlobalArgs) -> Result<()> {
    let client = client_for_optional_auth(global)?;
    let spinner = output::spinner("Fetching system configuration...");

    let config = client
        .get_system_config()
        .send()
        .await
        .map_err(|e| sdk_err("get system configuration", e))?
        .into_inner();

    spinner.finish_and_clear();

    let table_str = format_config_detail(&config);
    println!(
        "{}",
        output::render(&config, &global.format, Some(table_str))
    );

    Ok(())
}

async fn show_health(global: &GlobalArgs) -> Result<()> {
    let client = client_for_optional_auth(global)?;
    let spinner = output::spinner("Fetching system health...");

    let health = client
        .health_check()
        .send()
        .await
        .map_err(|e| sdk_err("get system health", e))?
        .into_inner();

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", health.status);
        return Ok(());
    }

    let table_str = format_health_detail(&health);
    println!(
        "{}",
        output::render(&health, &global.format, Some(table_str))
    );

    Ok(())
}

fn opt_bool(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "yes",
        Some(false) => "no",
        None => "-",
    }
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

fn format_health_detail(health: &artifact_keeper_sdk::types::HealthResponse) -> String {
    let check = |c: &artifact_keeper_sdk::types::CheckStatus| -> String {
        match &c.message {
            Some(m) => format!("{} ({m})", c.status),
            None => c.status.clone(),
        }
    };
    let opt_check = |c: &Option<artifact_keeper_sdk::types::CheckStatus>| -> String {
        c.as_ref().map(check).unwrap_or_else(|| "-".to_string())
    };

    let db_pool = health
        .db_pool
        .as_ref()
        .map(|p| {
            format!(
                "active={} idle={} size={} max={}",
                p.active_connections, p.idle_connections, p.size, p.max_connections
            )
        })
        .unwrap_or_else(|| "-".to_string());

    format!(
        "Status:            {}\n\
         Version:           {}\n\
         Commit:            {}\n\
         Dirty:             {}\n\
         Demo Mode:         {}\n\
         DB:                {}\n\
         Storage:           {}\n\
         LDAP:              {}\n\
         OpenSearch:        {}\n\
         Security Scanner:  {}\n\
         DB Pool:           {}",
        health.status,
        health.version,
        health.commit.as_deref().unwrap_or("-"),
        opt_bool(health.dirty),
        yes_no(health.demo_mode),
        check(&health.checks.database),
        check(&health.checks.storage),
        opt_check(&health.checks.ldap),
        opt_check(&health.checks.opensearch),
        opt_check(&health.checks.security_scanner),
        db_pool,
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

    #[test]
    fn opt_bool_renders() {
        assert_eq!(opt_bool(Some(true)), "yes");
        assert_eq!(opt_bool(Some(false)), "no");
        assert_eq!(opt_bool(None), "-");
    }

    // ---- format functions ----

    fn config_json() -> serde_json::Value {
        json!({
            "auth": { "ldap_enabled": false, "oidc_enabled": true, "sso_enabled": true },
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
            "auth": { "ldap_enabled": false, "oidc_enabled": false, "sso_enabled": false },
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

    #[test]
    fn format_health_detail_renders() {
        let health: artifact_keeper_sdk::types::HealthResponse =
            serde_json::from_value(health_json()).unwrap();
        let detail = format_health_detail(&health);
        assert!(detail.contains("healthy"));
        assert!(detail.contains("1.4.0"));
        assert!(detail.contains("degraded (slow)"));
        assert!(detail.contains("active=1"));
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
        let result = show_health(&global).await;
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
        let result = show_health(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    // ---- insta snapshot ----

    #[test]
    fn snapshot_system_config_json() {
        let config: serde_json::Value = config_json();
        let output = crate::output::render(&config, &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("system_config_json", parsed);
    }
}
