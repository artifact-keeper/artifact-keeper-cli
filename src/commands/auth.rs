use artifact_keeper_sdk::{ClientAuthExt, ClientUsersExt};
use clap::Subcommand;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use miette::{IntoDiagnostic, Result};

use super::client::{authenticated_client, build_client, client_for};
use super::helpers::{parse_uuid, resolve_secret, sdk_err};
use crate::cli::GlobalArgs;
use crate::config::credentials::{
    StoredCredential, delete_credential, get_credential, store_credential,
};
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

    /// Refresh the stored access token using the saved refresh token
    Refresh {
        /// Instance to refresh (uses default if omitted)
        instance: Option<String>,
    },

    /// Revoke an API token by ID
    RevokeToken {
        /// ID of the API token to revoke
        id: String,
    },

    /// Verify a TOTP code to complete two-factor login
    VerifyTotp {
        /// The code from your authenticator app
        code: String,

        /// The one-time totp_token returned by `ak auth login` when 2FA is required
        #[arg(long)]
        totp_token: String,
    },

    /// Create a short-lived, single-use download ticket for a resource
    DownloadTicket {
        /// Resource path the ticket should grant access to
        resource_path: String,

        /// Purpose of the ticket
        #[arg(long, default_value = "download")]
        purpose: String,
    },

    /// Exchange a CI-issued OIDC JWT for an Artifact Keeper access token
    CiExchange {
        /// The pre-configured CI OIDC provider ID (UUID)
        #[arg(long)]
        provider_id: String,

        /// The OIDC JWT to exchange (falls back to the AK_CI_JWT env var)
        #[arg(long, env = "AK_CI_JWT", hide_env_values = true)]
        jwt: Option<String>,

        /// Read the OIDC JWT from stdin (avoids exposing it on the command
        /// line)
        #[arg(long)]
        jwt_stdin: bool,
    },

    /// Show whether initial setup (password change) is required
    SetupStatus,
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
            Self::Logout { instance } => logout(instance.as_deref(), global).await,
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
            Self::Refresh { instance } => refresh(instance.as_deref(), global).await,
            Self::RevokeToken { id } => revoke_token(&id, global).await,
            Self::VerifyTotp { code, totp_token } => verify_totp(&code, &totp_token, global).await,
            Self::DownloadTicket {
                resource_path,
                purpose,
            } => download_ticket(&resource_path, &purpose, global).await,
            Self::CiExchange {
                provider_id,
                jwt,
                jwt_stdin,
            } => {
                // Resolve the JWT off the command line: --jwt-stdin / piped
                // stdin / AK_CI_JWT / no-echo prompt on a TTY.
                let jwt =
                    resolve_secret(jwt, jwt_stdin, "--jwt", Some("OIDC JWT"), global.no_input)?;
                ci_exchange(&provider_id, jwt.as_deref(), global).await
            }
            Self::SetupStatus => setup_status(global).await,
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

async fn logout(instance: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let config = AppConfig::load()?;
    let (instance_name, instance_cfg) =
        config.resolve_instance(instance.or(global.instance.as_deref()))?;
    let instance_name = instance_name.to_string();

    // Best-effort server-side session invalidation. Never block a local logout
    // on it — if the token is already invalid or the server is unreachable we
    // still want to clear the local credential.
    if let Ok(cred) = get_credential(&instance_name) {
        if let Ok(client) = build_client(&instance_name, instance_cfg, Some(&cred)) {
            let body = artifact_keeper_sdk::types::RefreshTokenRequest {
                refresh_token: cred.refresh_token.clone(),
            };
            if let Err(e) = client.logout().body(body).send().await {
                eprintln!(
                    "Warning: server-side logout failed ({e}); clearing local credentials anyway."
                );
            }
        }
    }

    delete_credential(&instance_name)?;
    eprintln!("Logged out from '{instance_name}'.");
    Ok(())
}

async fn refresh(instance: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let config = AppConfig::load()?;
    let (instance_name, instance_cfg) =
        config.resolve_instance(instance.or(global.instance.as_deref()))?;
    let instance_name = instance_name.to_string();

    let cred = get_credential(&instance_name)?;
    let refresh_token = cred.refresh_token.clone().ok_or_else(|| {
        AkError::NotAuthenticated(format!(
            "No refresh token stored for '{instance_name}'. Log in with username/password \
             (`ak auth login`) to obtain one."
        ))
    })?;

    let client = build_client(&instance_name, instance_cfg, Some(&cred))?;
    let body = artifact_keeper_sdk::types::RefreshTokenRequest {
        refresh_token: Some(refresh_token),
    };

    let resp = client
        .refresh_token()
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::NotAuthenticated(format!("Token refresh failed: {e}")))?;

    let new_cred = StoredCredential {
        access_token: resp.access_token.clone(),
        refresh_token: Some(resp.refresh_token.clone()),
    };
    store_credential(&instance_name, &new_cred)?;

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", resp.access_token);
        return Ok(());
    }

    let info = serde_json::json!({
        "instance": instance_name,
        "expires_in": resp.expires_in,
        "token_type": resp.token_type,
    });

    let table_str = format!(
        "Access token refreshed for '{instance_name}'.\n\
         Expires in: {} seconds\n\
         Token type: {}",
        resp.expires_in, resp.token_type,
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));
    Ok(())
}

async fn revoke_token(id: &str, global: &GlobalArgs) -> Result<()> {
    let token_id = parse_uuid(id, "token")?;

    let client = client_for(global)?;
    client
        .revoke_api_token()
        .token_id(token_id)
        .send()
        .await
        .map_err(|e| sdk_err("revoke API token", e))?;

    eprintln!("API token {id} revoked.");
    Ok(())
}

async fn verify_totp(code: &str, totp_token: &str, global: &GlobalArgs) -> Result<()> {
    let config = AppConfig::load()?;
    let (instance_name, instance_cfg) = config.resolve_instance(global.instance.as_deref())?;
    let instance_name = instance_name.to_string();

    let anon_client = artifact_keeper_sdk::Client::new(&instance_cfg.url);
    let body = artifact_keeper_sdk::types::TotpVerifyRequest {
        code: code.to_string(),
        totp_token: totp_token.to_string(),
    };

    let resp = anon_client
        .verify_totp()
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::NotAuthenticated(format!("TOTP verification failed: {e}")))?;

    let cred = StoredCredential {
        access_token: resp.access_token.clone(),
        refresh_token: Some(resp.refresh_token.clone()),
    };
    store_credential(&instance_name, &cred)?;

    eprintln!("Two-factor verification succeeded; logged in to '{instance_name}'.");
    if resp.must_change_password {
        eprintln!("Warning: You must change your password. Visit the web UI to update it.");
    }
    Ok(())
}

async fn download_ticket(resource_path: &str, purpose: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let body = artifact_keeper_sdk::types::CreateTicketRequest {
        purpose: purpose.to_string(),
        resource_path: Some(resource_path.to_string()),
    };

    let resp = client
        .create_download_ticket()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("create download ticket", e))?;

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", resp.ticket);
        return Ok(());
    }

    let info = serde_json::json!({
        "ticket": resp.ticket,
        "expires_in": resp.expires_in,
        "resource_path": resource_path,
    });

    let table_str = format!(
        "Download ticket created (single-use, expires in {} seconds):\n\
         {}\n\n\
         Note: this value grants access to '{}'. Consume it immediately and never log \
         or share the URL that contains it.",
        resp.expires_in, resp.ticket, resource_path,
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));
    Ok(())
}

async fn ci_exchange(provider_id: &str, jwt: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let provider = parse_uuid(provider_id, "provider")?;
    let jwt = jwt.ok_or_else(|| {
        AkError::ConfigError(
            "No OIDC JWT provided. Pipe it to --jwt-stdin, set AK_CI_JWT, or pass --jwt <token>."
                .into(),
        )
    })?;

    let config = AppConfig::load()?;
    let (instance_name, instance_cfg) = config.resolve_instance(global.instance.as_deref())?;
    let instance_name = instance_name.to_string();

    // The CI-issued JWT must be presented as the Bearer token on the exchange request.
    let jwt_cred = StoredCredential {
        access_token: jwt.to_string(),
        refresh_token: None,
    };
    let client = build_client(&instance_name, instance_cfg, Some(&jwt_cred))?;

    let body = artifact_keeper_sdk::types::CiTokenRequest {
        provider_id: provider,
    };

    let resp = client
        .exchange_ci_token()
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::NotAuthenticated(format!("CI token exchange failed: {e}")))?;

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", resp.access_token);
        return Ok(());
    }

    let info = serde_json::json!({
        "access_token": resp.access_token,
        "token_type": resp.token_type,
        "expires_in": resp.expires_in,
        "username": resp.username,
    });

    let table_str = format!(
        "Exchanged CI OIDC token for an access token (user: {}).\n\
         Token type:   {}\n\
         Expires in:   {} seconds\n\
         Access token: {}",
        resp.username, resp.token_type, resp.expires_in, resp.access_token,
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));
    Ok(())
}

async fn setup_status(global: &GlobalArgs) -> Result<()> {
    let config = AppConfig::load()?;
    let (_instance_name, instance_cfg) = config.resolve_instance(global.instance.as_deref())?;

    // Setup status is a pre-auth endpoint; no credentials required.
    let client = artifact_keeper_sdk::Client::new(&instance_cfg.url);

    let resp = client
        .setup_status()
        .send()
        .await
        .map_err(|e| sdk_err("get setup status", e))?;

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", resp.setup_required);
        return Ok(());
    }

    let info = serde_json::json!({
        "setup_required": resp.setup_required,
    });

    let table_str = format!(
        "Initial setup required: {}",
        if resp.setup_required { "yes" } else { "no" },
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));
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
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/auth/me"))
            .respond_with(ResponseTemplate::new(200).set_body_json(user_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = whoami(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_token_create_json() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

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
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_token_create_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

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
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_token_list_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

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
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_token_list_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

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
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_token_list_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

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
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_login_no_input_returns_error() {
        let (_server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        let global = crate::test_utils::test_global(OutputFormat::Json);
        // no_input=true should produce an error for login
        let result = login(None, false, &global).await;
        assert!(result.is_err());
        crate::test_utils::teardown_env();
    }

    // ---- parsing tests for new subcommands ----

    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: AuthCommand,
    }

    fn parse_auth(args: &[&str]) -> AuthCommand {
        TestCli::try_parse_from(args).unwrap().command
    }

    #[test]
    fn parse_refresh_default() {
        match parse_auth(&["auth", "refresh"]) {
            AuthCommand::Refresh { instance } => assert!(instance.is_none()),
            _ => panic!("expected Refresh"),
        }
    }

    #[test]
    fn parse_revoke_token() {
        match parse_auth(&["auth", "revoke-token", "abc-123"]) {
            AuthCommand::RevokeToken { id } => assert_eq!(id, "abc-123"),
            _ => panic!("expected RevokeToken"),
        }
    }

    #[test]
    fn parse_revoke_token_missing_id() {
        assert!(TestCli::try_parse_from(["auth", "revoke-token"]).is_err());
    }

    #[test]
    fn parse_verify_totp() {
        match parse_auth(&["auth", "verify-totp", "123456", "--totp-token", "tok"]) {
            AuthCommand::VerifyTotp { code, totp_token } => {
                assert_eq!(code, "123456");
                assert_eq!(totp_token, "tok");
            }
            _ => panic!("expected VerifyTotp"),
        }
    }

    #[test]
    fn parse_verify_totp_requires_totp_token() {
        assert!(TestCli::try_parse_from(["auth", "verify-totp", "123456"]).is_err());
    }

    #[test]
    fn parse_download_ticket_default_purpose() {
        match parse_auth(&["auth", "download-ticket", "npm-local/left-pad/1.0.0"]) {
            AuthCommand::DownloadTicket {
                resource_path,
                purpose,
            } => {
                assert_eq!(resource_path, "npm-local/left-pad/1.0.0");
                assert_eq!(purpose, "download");
            }
            _ => panic!("expected DownloadTicket"),
        }
    }

    #[test]
    fn parse_ci_exchange() {
        match parse_auth(&[
            "auth",
            "ci-exchange",
            "--provider-id",
            "00000000-0000-0000-0000-000000000000",
            "--jwt",
            "ey.jwt.here",
        ]) {
            AuthCommand::CiExchange {
                provider_id,
                jwt,
                jwt_stdin,
            } => {
                assert_eq!(provider_id, "00000000-0000-0000-0000-000000000000");
                assert_eq!(jwt.as_deref(), Some("ey.jwt.here"));
                assert!(!jwt_stdin);
            }
            _ => panic!("expected CiExchange"),
        }
    }

    #[test]
    fn parse_ci_exchange_jwt_stdin() {
        match parse_auth(&[
            "auth",
            "ci-exchange",
            "--provider-id",
            "00000000-0000-0000-0000-000000000000",
            "--jwt-stdin",
        ]) {
            AuthCommand::CiExchange { jwt_stdin, .. } => {
                assert!(jwt_stdin);
            }
            _ => panic!("expected CiExchange"),
        }
    }

    #[test]
    fn parse_setup_status() {
        assert!(matches!(
            parse_auth(&["auth", "setup-status"]),
            AuthCommand::SetupStatus
        ));
    }

    // ---- wiremock handler tests for new operations ----

    fn login_response_json() -> serde_json::Value {
        serde_json::json!({
            "access_token": "new_access_token",
            "refresh_token": "new_refresh_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "must_change_password": false
        })
    }

    #[tokio::test]
    async fn handler_logout_calls_server_then_clears() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/auth/logout"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = logout(None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_logout_succeeds_when_server_errors() {
        // No mock mounted for /logout -> server returns 404; logout must still succeed.
        let (_server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = logout(None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_refresh_no_token_errors() {
        // setup_env sets AK_TOKEN (access only, no refresh) -> refresh must error.
        let (_server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = refresh(None, &global).await;
        assert!(result.is_err());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_refresh_happy_path() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        // Drop AK_TOKEN so the stored file credential (with a refresh token) is used.
        unsafe { std::env::remove_var("AK_TOKEN") };
        let cred = serde_json::json!({
            "access_token": "old_access",
            "refresh_token": "old_refresh"
        })
        .to_string();
        let mut all = std::collections::HashMap::new();
        all.insert("test".to_string(), cred);
        std::fs::write(
            tmp.path().join("credentials.json"),
            serde_json::to_string(&all).unwrap(),
        )
        .unwrap();

        Mock::given(method("POST"))
            .and(path("/api/v1/auth/refresh"))
            .respond_with(ResponseTemplate::new(200).set_body_json(login_response_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = refresh(None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_revoke_token() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/auth/tokens/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = revoke_token(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_revoke_token_bad_uuid() {
        let (_server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = revoke_token("not-a-uuid", &global).await;
        assert!(result.is_err());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_verify_totp() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/auth/totp/verify"))
            .respond_with(ResponseTemplate::new(200).set_body_json(login_response_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = verify_totp("123456", "totp-token", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_download_ticket() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/auth/ticket"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ticket": "tkt_abc123",
                "expires_in": 30
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = download_ticket("npm-local/left-pad/1.0.0", "download", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_download_ticket_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/auth/ticket"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ticket": "tkt_abc123",
                "expires_in": 30
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = download_ticket("some/path", "download", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_ci_exchange() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/auth/ci/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "ci_access_token",
                "token_type": "Bearer",
                "expires_in": 900,
                "username": "ci-runner"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = ci_exchange(NIL_UUID, Some("ey.jwt.here"), &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_ci_exchange_missing_jwt() {
        let (_server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = ci_exchange(NIL_UUID, None, &global).await;
        assert!(result.is_err());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_setup_status() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/setup/status"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "setup_required": false })),
            )
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = setup_status(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_setup_status_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/setup/status"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "setup_required": true })),
            )
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = setup_status(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    // ---- insta snapshot tests ----

    #[test]
    fn snapshot_whoami_json() {
        let data = user_json();
        let output = crate::output::render(&data, &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("auth_whoami_json", parsed);
    }

    #[test]
    fn snapshot_token_list_json() {
        let tokens = serde_json::json!([{
            "id": NIL_UUID,
            "name": "ci-deploy",
            "prefix": "ak_xxxx_",
            "scopes": "read, write",
            "created_at": "2026-01-15T12:00:00+00:00",
            "expires_at": "never",
            "last_used": "never"
        }]);
        let output = crate::output::render(&tokens, &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("auth_token_list_json", parsed);
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
