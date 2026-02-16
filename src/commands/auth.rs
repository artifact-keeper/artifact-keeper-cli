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

        /// Authenticate with an API token instead of browser flow
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
                eprintln!("Use `ak auth login --token` with a different token to switch accounts.");
                Ok(())
            }
        }
    }
}

async fn login(url: Option<&str>, use_token: bool, global: &GlobalArgs) -> Result<()> {
    let config = AppConfig::load()?;
    let (instance_name, instance) = match url {
        Some(url) => {
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
        }
        None => {
            let (name, inst) = config.resolve_instance(global.instance.as_deref())?;
            (name.to_string(), inst.clone())
        }
    };

    if global.no_input {
        let hint = if use_token {
            "Cannot prompt for token in non-interactive mode. Set AK_TOKEN environment variable instead."
        } else {
            "Cannot prompt for credentials in non-interactive mode. Use `--token` flag or set AK_TOKEN."
        };
        return Err(AkError::ConfigError(hint.into()).into());
    }

    if use_token {
        login_with_token(&instance_name, &instance).await
    } else {
        login_with_password(&instance_name, &instance).await
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

    let base_url = format!("{}/api/{}", instance.url, instance.api_version);
    let anon_client = artifact_keeper_sdk::Client::new(&base_url);

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
    let name = if let Some(desc) = description {
        desc.to_string()
    } else if global.no_input {
        default_name
    } else {
        dialoguer::Input::new()
            .with_prompt("Token name")
            .default(default_name)
            .interact_text()
            .into_diagnostic()?
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
