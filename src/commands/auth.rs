use artifact_keeper_sdk::{ClientAuthExt, ClientUsersExt};
use clap::Subcommand;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use miette::{IntoDiagnostic, Result};

use super::client::{authenticated_client, build_client, client_for};
use crate::cli::GlobalArgs;
use crate::config::credentials::{StoredCredential, delete_credential, store_credential};
use crate::config::{AppConfig, InstanceConfig};
use crate::error::AkError;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum AuthCommand {
    /// Log in to an Artifact Keeper instance
    Login {
        /// Instance URL (uses default instance if omitted)
        url: Option<String>,

        /// Skip interactive prompt and go straight to token authentication
        #[arg(long)]
        token: bool,
    },

    /// Log out and remove stored credentials
    Logout {
        /// Instance to log out from (uses default if omitted)
        instance: Option<String>,
    },

    /// Manage API tokens
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },

    /// Show current authenticated user and instance
    Whoami,

    /// Switch between accounts on the same instance
    Switch,
}

#[derive(Subcommand)]
pub enum TokenCommand {
    /// Create a new API token
    Create {
        /// Token name/description
        #[arg(long)]
        description: Option<String>,

        /// Expiration in days
        #[arg(long, default_value = "90")]
        expires_in: u32,
    },

    /// List active API tokens
    List,
}

impl AuthCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Login { url, token } => login(url.as_deref(), token, global).await,
            Self::Logout { instance } => logout(instance.as_deref(), global),
            Self::Token { command } => match command {
                TokenCommand::Create {
                    description,
                    expires_in,
                } => token_create(description.as_deref(), expires_in, global).await,
                TokenCommand::List => token_list(global).await,
            },
            Self::Whoami => whoami(global).await,
            Self::Switch => {
                eprintln!("Account switching is not yet implemented.");
                eprintln!("Use `ak auth login` to log in with a different account.");
                Ok(())
            }
        }
    }
}

async fn login(url: Option<&str>, use_token: bool, global: &GlobalArgs) -> Result<()> {
    let config = AppConfig::load()?;
    let (instance_name, instance) = if let Some(url) = url {
        let (name, inst) = config
            .instances
            .iter()
            .find(|(_, inst)| inst.url == url)
            .ok_or_else(|| {
                AkError::ConfigError(format!(
                    "No instance configured with URL '{url}'. Run `ak instance add <name> {url}` first."
                ))
            })?;
        (name.to_string(), inst.clone())
    } else {
        let (name, inst) = config.resolve_instance(global.instance.as_deref())?;
        (name.to_string(), inst.clone())
    };

    if global.no_input {
        let hint = if use_token {
            "Cannot prompt for token in non-interactive mode. Set AK_TOKEN environment variable instead."
        } else {
            "Cannot prompt for credentials in non-interactive mode. Use `--token` flag or set AK_TOKEN."
        };
        return Err(AkError::ConfigError(hint.into()).into());
    }

    // If --token flag was explicitly passed, go straight to token flow
    if use_token {
        return login_with_token(&instance_name, &instance).await;
    }

    // Interactive: let user choose how to authenticate
    eprintln!("Logging in to '{}' ({})\n", instance_name, instance.url);

    let methods = &[
        "Login with username and password",
        "Paste an authentication token",
    ];
    let selection = dialoguer::Select::new()
        .with_prompt("How would you like to authenticate?")
        .items(methods)
        .default(0)
        .interact()
        .into_diagnostic()?;

    match selection {
        0 => login_with_password(&instance_name, &instance).await,
        1 => login_with_token(&instance_name, &instance).await,
        _ => unreachable!(),
    }
}

async fn login_with_token(instance_name: &str, instance: &InstanceConfig) -> Result<()> {
    eprintln!(
        "Paste your API token for '{instance_name}' ({}):",
        instance.url
    );
    let token = dialoguer::Password::new()
        .with_prompt("Token")
        .interact()
        .into_diagnostic()?;

    let cred = StoredCredential {
        access_token: token.trim().to_string(),
        refresh_token: None,
    };

    let client = build_client(instance_name, instance, Some(&cred))?;
    let resp = client
        .get_current_user()
        .send()
        .await
        .map_err(|e| AkError::NotAuthenticated(format!("Token validation failed: {e}")))?;

    store_credential(instance_name, &cred)?;
    eprintln!(
        "Logged in to '{instance_name}' as {} ({})",
        resp.username, resp.email
    );
    Ok(())
}

async fn login_with_password(instance_name: &str, instance: &InstanceConfig) -> Result<()> {
    let username: String = dialoguer::Input::new()
        .with_prompt("Username")
        .interact_text()
        .into_diagnostic()?;

    let password = dialoguer::Password::new()
        .with_prompt("Password")
        .interact()
        .into_diagnostic()?;

    let anon_client = artifact_keeper_sdk::Client::new(&instance.url);

    let body = artifact_keeper_sdk::types::LoginRequest {
        username: username.clone(),
        password,
    };

    let resp = anon_client
        .login()
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::NotAuthenticated(format!("Login failed: {e}")))?;

    if resp.totp_required == Some(true) {
        eprintln!("TOTP verification is required but not yet supported in the CLI.");
        eprintln!("Use `--token` with an API token instead.");
        return Ok(());
    }

    let cred = StoredCredential {
        access_token: resp.access_token.clone(),
        refresh_token: Some(resp.refresh_token.clone()),
    };
    store_credential(instance_name, &cred)?;

    eprintln!("Logged in to '{instance_name}' as {username}");
    if resp.must_change_password {
        eprintln!("Warning: You must change your password. Visit the web UI to update it.");
    }

    Ok(())
}

fn logout(instance: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let config = AppConfig::load()?;
    let (instance_name, _) = config.resolve_instance(instance.or(global.instance.as_deref()))?;

    delete_credential(instance_name)?;
    eprintln!("Logged out from '{instance_name}'.");
    Ok(())
}

async fn whoami(global: &GlobalArgs) -> Result<()> {
    let (instance_name, instance, client) = authenticated_client(global)?;

    let user = client
        .get_current_user()
        .send()
        .await
        .map_err(|e| AkError::NotAuthenticated(format!("Failed to get user info: {e}")))?;

    let info = serde_json::json!({
        "username": user.username,
        "email": user.email,
        "display_name": user.display_name,
        "admin": user.is_admin,
        "totp_enabled": user.totp_enabled,
        "instance": instance_name,
        "url": instance.url,
    });

    let table_str = format!(
        "Username:     {}\n\
         Email:        {}\n\
         Display Name: {}\n\
         Admin:        {}\n\
         TOTP:         {}\n\
         Instance:     {} ({})",
        user.username,
        user.email,
        user.display_name.as_deref().unwrap_or("-"),
        if user.is_admin { "yes" } else { "no" },
        if user.totp_enabled {
            "enabled"
        } else {
            "disabled"
        },
        instance_name,
        instance.url,
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn token_create(
    description: Option<&str>,
    expires_in: u32,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;

    let default_name = format!("ak-cli-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
    let name = match description {
        Some(desc) => desc.to_string(),
        None if global.no_input => default_name,
        None => dialoguer::Input::new()
            .with_prompt("Token name")
            .default(default_name)
            .interact_text()
            .into_diagnostic()?,
    };

    let body = artifact_keeper_sdk::types::CreateApiTokenRequest {
        name,
        scopes: vec!["*".to_string()],
        expires_in_days: Some(i64::from(expires_in)),
    };

    let resp = client
        .create_api_token()
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to create token: {e}")))?;

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", resp.token);
        return Ok(());
    }

    let info = serde_json::json!({
        "id": resp.id.to_string(),
        "name": resp.name,
        "token": resp.token,
    });

    let table_str = format!(
        "Token created successfully!\n\n\
         ID:    {}\n\
         Name:  {}\n\
         Token: {}\n\n\
         Save this token — it won't be shown again.",
        resp.id, resp.name, resp.token,
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

fn format_optional_date(date: Option<chrono::DateTime<chrono::Utc>>, fmt: &str) -> String {
    date.map(|d| d.format(fmt).to_string())
        .unwrap_or_else(|| "never".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- format_optional_date ----

    #[test]
    fn format_optional_date_none() {
        let result = format_optional_date(None, "%Y-%m-%d");
        assert_eq!(result, "never");
    }

    #[test]
    fn format_optional_date_some() {
        use chrono::TimeZone;
        let date = chrono::Utc
            .with_ymd_and_hms(2026, 1, 15, 12, 30, 0)
            .unwrap();
        let result = format_optional_date(Some(date), "%Y-%m-%d");
        assert_eq!(result, "2026-01-15");
    }

    #[test]
    fn format_optional_date_rfc3339() {
        use chrono::TimeZone;
        let date = chrono::Utc
            .with_ymd_and_hms(2026, 1, 15, 12, 30, 0)
            .unwrap();
        let result = format_optional_date(Some(date), "%+");
        assert!(result.contains("2026-01-15"));
    }

    // ---- AuthCommand enum ----

    #[test]
    fn auth_switch_stub() {
        // Verify the switch command doesn't panic
        let global = GlobalArgs {
            format: crate::output::OutputFormat::Quiet,
            instance: None,
            no_input: true,
        };
        let cmd = AuthCommand::Switch;
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(cmd.execute(&global)).unwrap();
    }

    // ---- wiremock handler tests ----

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    static NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

    fn setup_env(tmp: &tempfile::TempDir) -> std::sync::MutexGuard<'static, ()> {
        let guard = crate::test_utils::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::set_var("AK_CONFIG_DIR", tmp.path());
            std::env::set_var("AK_TOKEN", "test-token");
        }
        guard
    }

    fn teardown_env() {
        unsafe {
            std::env::remove_var("AK_CONFIG_DIR");
            std::env::remove_var("AK_TOKEN");
        }
    }

    fn user_json() -> serde_json::Value {
        serde_json::json!({
            "id": NIL_UUID,
            "username": "alice",
            "email": "alice@example.com",
            "display_name": "Alice",
            "is_admin": false,
            "totp_enabled": false,
            "created_at": "2026-01-15T12:00:00Z",
            "updated_at": "2026-01-15T12:00:00Z"
        })
    }

    #[tokio::test]
    async fn handler_whoami_json() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/auth/me"))
            .respond_with(ResponseTemplate::new(200).set_body_json(user_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = whoami(&global).await;
        assert!(result.is_ok());
        teardown_env();
    }

    #[tokio::test]
    async fn handler_token_create_json() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/auth/tokens"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": NIL_UUID,
                "name": "ak-cli-test",
                "token": "ak_test_abcdef1234567890",
                "token_prefix": "ak_test_",
                "scopes": ["*"],
                "created_at": "2026-01-15T12:00:00Z",
                "expires_at": "2026-04-15T12:00:00Z"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = token_create(Some("test token"), 90, &global).await;
        assert!(result.is_ok());
        teardown_env();
    }

    #[tokio::test]
    async fn handler_token_create_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/auth/tokens"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": NIL_UUID,
                "name": "ak-cli-test",
                "token": "ak_test_abcdef1234567890",
                "token_prefix": "ak_test_",
                "scopes": ["*"],
                "created_at": "2026-01-15T12:00:00Z",
                "expires_at": "2026-04-15T12:00:00Z"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = token_create(Some("test token"), 90, &global).await;
        assert!(result.is_ok());
        teardown_env();
    }

    #[tokio::test]
    async fn handler_token_list_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = setup_env(&tmp);

        // token_list calls get_current_user first, then list_user_tokens
        Mock::given(method("GET"))
            .and(path("/api/v1/auth/me"))
            .respond_with(ResponseTemplate::new(200).set_body_json(user_json()))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/users/{NIL_UUID}/tokens")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": []
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = token_list(&global).await;
        assert!(result.is_ok());
        teardown_env();
    }

    #[tokio::test]
    async fn handler_token_list_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/auth/me"))
            .respond_with(ResponseTemplate::new(200).set_body_json(user_json()))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/users/{NIL_UUID}/tokens")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": [{
                    "id": NIL_UUID,
                    "name": "my-token",
                    "token_prefix": "ak_xxxx_",
                    "scopes": ["*"],
                    "created_at": "2026-01-15T12:00:00Z",
                    "expires_at": "2026-04-15T12:00:00Z",
                    "last_used_at": null
                }]
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = token_list(&global).await;
        assert!(result.is_ok());
        teardown_env();
    }

    #[tokio::test]
    async fn handler_token_list_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/auth/me"))
            .respond_with(ResponseTemplate::new(200).set_body_json(user_json()))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/users/{NIL_UUID}/tokens")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": [{
                    "id": NIL_UUID,
                    "name": "my-token",
                    "token_prefix": "ak_xxxx_",
                    "scopes": ["*"],
                    "created_at": "2026-01-15T12:00:00Z",
                    "expires_at": null,
                    "last_used_at": null
                }]
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = token_list(&global).await;
        assert!(result.is_ok());
        teardown_env();
    }

    #[tokio::test]
    async fn handler_login_no_input_returns_error() {
        let (_server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = setup_env(&tmp);

        let global = crate::test_utils::test_global(OutputFormat::Json);
        // no_input=true should produce an error for login
        let result = login(None, false, &global).await;
        assert!(result.is_err());
        teardown_env();
    }
}

async fn token_list(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;

    let user = client
        .get_current_user()
        .send()
        .await
        .map_err(|e| AkError::NotAuthenticated(format!("Failed to get user info: {e}")))?;

    let tokens = client
        .list_user_tokens()
        .id(user.id)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to list tokens: {e}")))?;

    if tokens.items.is_empty() {
        eprintln!("No API tokens found. Run `ak auth token create` to create one.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for t in &tokens.items {
            println!("{}", t.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = tokens
        .items
        .iter()
        .map(|t| {
            serde_json::json!({
                "id": t.id.to_string(),
                "name": t.name,
                "prefix": t.token_prefix,
                "scopes": t.scopes.join(", "),
                "created_at": t.created_at.to_rfc3339(),
                "expires_at": format_optional_date(t.expires_at, "%+"),
                "last_used": format_optional_date(t.last_used_at, "%+"),
            })
        })
        .collect();

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            "ID",
            "NAME",
            "PREFIX",
            "SCOPES",
            "CREATED",
            "EXPIRES",
            "LAST USED",
        ]);

    for t in &tokens.items {
        table.add_row(vec![
            &t.id.to_string()[..8],
            &t.name,
            &t.token_prefix,
            &t.scopes.join(", "),
            &t.created_at.format("%Y-%m-%d").to_string(),
            &format_optional_date(t.expires_at, "%Y-%m-%d"),
            &format_optional_date(t.last_used_at, "%Y-%m-%d"),
        ]);
    }

    let table_str = table.to_string();

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}
