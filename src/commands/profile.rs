use artifact_keeper_sdk::ClientAuthExt;
use artifact_keeper_sdk::ClientUsersExt;
use artifact_keeper_sdk::types::{
    AdminUserResponse, ApiTokenCreatedResponse, ApiTokenResponse, ChangePasswordRequest,
    CreateUserApiTokenRequest, UpdateUserRequest,
};
use clap::Subcommand;
use miette::Result;
use serde_json::Value;
use std::io::IsTerminal;

use super::client::{client_for, raw_http_client, resolve_base_url_and_auth};
use super::helpers::{
    emit_mutation, emit_mutation_raw, new_table, parse_uuid, raw_err, require_secret,
    resolve_secret, sdk_err, short_id,
};
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum ProfileCommand {
    /// Show your user profile. Use `ak auth whoami`
    #[command(hide = true)]
    Show,

    /// Show your full account record (self-service `/users/me`)
    Whoami,

    /// Update your profile fields
    Update {
        /// New display name
        #[arg(long)]
        display_name: Option<String>,

        /// New email address
        #[arg(long)]
        email: Option<String>,
    },

    /// Change your password. Asks at a terminal; otherwise see the flags
    ChangePassword {
        #[command(flatten)]
        passwords: PasswordArgs,
    },

    /// Manage API tokens through /users/me/tokens. Use `ak auth token`. A token made
    /// here has no scopes unless you give some
    #[command(hide = true)]
    Tokens {
        #[command(subcommand)]
        command: TokenCommand,
    },

    /// Manage API tokens through /profile/access-tokens, the route the web UI uses.
    /// A token made here defaults to the read scope, and one made with `ak auth token`
    /// to all of your access
    AccessTokens {
        #[command(subcommand)]
        command: AccessTokenCommand,
    },
}

/// A change of password. A secret on the command line goes into shell history, so
/// these flags warn: use the stdin flag, the variable or the prompt. Stdin can only
/// carry one of the two.
#[derive(clap::Args)]
pub struct PasswordArgs {
    /// Your current password. Admins don't need it
    #[arg(long, env = "AK_CURRENT_PASSWORD", hide_env_values = true)]
    current_password: Option<String>,

    /// Read the current password from stdin
    #[arg(long, conflicts_with = "new_password_stdin")]
    current_password_stdin: bool,

    /// The new password
    #[arg(long, env = "AK_NEW_PASSWORD", hide_env_values = true)]
    new_password: Option<String>,

    /// Read the new password from stdin
    #[arg(long)]
    new_password_stdin: bool,
}

impl PasswordArgs {
    /// The request to send. `ask_current` says whether to ask for a current password
    /// that wasn't given: only your own change can need one.
    pub fn resolve(self, ask_current: bool, global: &GlobalArgs) -> Result<ChangePasswordRequest> {
        let current_password = resolve_secret(
            self.current_password,
            self.current_password_stdin,
            "--current-password",
            ask_current.then_some("Current password"),
            // Stdin may be the new password, so only ask at a terminal.
            global.no_input || !std::io::stdin().is_terminal(),
        )?;
        let at_terminal = !global.no_input && std::io::stdin().is_terminal();
        let new_password = if self.new_password.is_none() && !self.new_password_stdin && at_terminal
        {
            dialoguer::Password::new()
                .with_prompt("New password")
                .with_confirmation("Confirm new password", "Passwords do not match")
                .interact()
                .map_err(|e| super::helpers::prompt_err("Failed to read password", e))?
        } else {
            require_secret(
                resolve_secret(
                    self.new_password,
                    self.new_password_stdin,
                    "--new-password",
                    None,
                    global.no_input,
                )?,
                "The new password",
                "--new-password-stdin or AK_NEW_PASSWORD",
            )?
        };
        Ok(ChangePasswordRequest {
            current_password,
            new_password,
        })
    }
}

#[derive(Subcommand)]
pub enum AccessTokenCommand {
    /// List your API tokens
    List,

    /// Create an API token
    Create {
        /// Token name
        name: String,

        /// Scope to grant (repeatable, or comma-separated)
        #[arg(long = "scope", value_delimiter = ',')]
        scopes: Vec<String>,

        /// Number of days until the token expires
        #[arg(long)]
        expires_in_days: Option<i64>,
    },

    /// Revoke an API token
    Revoke {
        /// Token ID
        id: String,
    },
}

#[derive(Subcommand)]
pub enum TokenCommand {
    /// List your API tokens
    List,

    /// Create a new API token
    Create {
        /// Token name
        name: String,

        /// Comma-separated scopes (e.g. read,write)
        #[arg(long)]
        scopes: Option<String>,

        /// Number of days until the token expires
        #[arg(long)]
        expires_in_days: Option<i64>,
    },

    /// Revoke an API token
    Revoke {
        /// Token ID
        id: String,
    },
}

impl ProfileCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Show => super::auth::whoami(global).await,
            Self::Whoami => whoami(global).await,
            Self::Update {
                display_name,
                email,
            } => update_profile(display_name.as_deref(), email.as_deref(), global).await,
            Self::ChangePassword { passwords } => change_password(passwords, global).await,
            Self::AccessTokens { command } => match command {
                AccessTokenCommand::List => access_tokens_list(global).await,
                AccessTokenCommand::Create {
                    name,
                    scopes,
                    expires_in_days,
                } => access_token_create(&name, scopes, expires_in_days, global).await,
                AccessTokenCommand::Revoke { id } => access_token_revoke(&id, global).await,
            },
            Self::Tokens { command } => match command {
                TokenCommand::List => list_tokens(global).await,
                TokenCommand::Create {
                    name,
                    scopes,
                    expires_in_days,
                } => create_token(&name, scopes.as_deref(), expires_in_days, global).await,
                TokenCommand::Revoke { id } => revoke_token(&id, global).await,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Handler functions
// ---------------------------------------------------------------------------

async fn whoami(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching account record...");

    let (resp, raw) =
        artifact_keeper_sdk::raw::capture(client.get_current_user_record().send()).await;
    let user = resp
        .map_err(|e| sdk_err("get current user record", e))?
        .into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", user.id);
        return Ok(());
    }

    let (info, table_str) = format_whoami_detail(&user);
    println!(
        "{}",
        output::render_raw(raw.as_deref(), &info, &global.format, Some(table_str))
    );

    Ok(())
}

async fn update_profile(
    display_name: Option<&str>,
    email: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    if display_name.is_none() && email.is_none() {
        return Err(AkError::Usage(
            "Provide at least one of --display-name or --email to update.".to_string(),
        )
        .into());
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching current user...");

    let me_resp = client
        .get_current_user()
        .send()
        .await
        .map_err(|e| sdk_err("get current user", e))?;
    let me = me_resp.into_inner();
    spinner.finish_and_clear();

    let body = UpdateUserRequest {
        display_name: display_name.map(|s| s.to_string()),
        email: email.map(|s| s.to_string()),
        is_active: None,
        is_admin: None,
    };

    let spinner = output::spinner("Updating profile...");
    let (updated, raw) =
        artifact_keeper_sdk::raw::capture(client.update_user().id(me.id).body(body).send()).await;
    updated.map_err(|e| sdk_err("update profile", e))?;
    spinner.finish_and_clear();

    emit_mutation_raw(
        raw.as_deref(),
        &serde_json::json!({ "status": "updated" }),
        "profile",
        "Profile updated.",
        global,
    );
    Ok(())
}

async fn change_password(passwords: PasswordArgs, global: &GlobalArgs) -> Result<()> {
    let body = passwords.resolve(true, global)?;
    let client = client_for(global)?;

    let spinner = output::spinner("Changing password...");
    client
        .change_current_user_password()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("change password", e))?;
    spinner.finish_and_clear();

    eprintln!("Password changed.");
    Ok(())
}

async fn list_tokens(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching API tokens...");

    let (resp, raw) =
        artifact_keeper_sdk::raw::capture(client.list_current_user_tokens().send()).await;
    let list = resp
        .map_err(|e| sdk_err("list API tokens", e))?
        .into_inner();
    spinner.finish_and_clear();

    if list.items.is_empty() && !output::is_machine_format(&global.format) {
        eprintln!("No API tokens found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for token in &list.items {
            println!("{}", token.id);
        }
        return Ok(());
    }

    let (entries, table_str) = format_tokens_table(&list.items);
    println!(
        "{}",
        output::render_raw(raw.as_deref(), &entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn create_token(
    name: &str,
    scopes: Option<&str>,
    expires_in_days: Option<i64>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;

    let scope_list: Vec<String> = scopes
        .map(|s| s.split(',').map(|v| v.trim().to_string()).collect())
        .unwrap_or_default();

    let body = CreateUserApiTokenRequest {
        name: name.to_string(),
        scopes: scope_list,
        expires_in_days,
    };

    let spinner = output::spinner("Creating API token...");
    let (resp, raw) =
        artifact_keeper_sdk::raw::capture(client.create_current_user_api_token().body(body).send())
            .await;
    let created = resp
        .map_err(|e| sdk_err("create API token", e))?
        .into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", created.token);
        return Ok(());
    }

    let (info, table_str) = format_created_token(&created);
    println!(
        "{}",
        output::render_raw(raw.as_deref(), &info, &global.format, Some(table_str))
    );

    Ok(())
}

async fn revoke_token(id: &str, global: &GlobalArgs) -> Result<()> {
    let token_id = parse_uuid(id, "token")?;

    let client = client_for(global)?;

    let spinner = output::spinner("Revoking API token...");
    client
        .revoke_current_user_api_token()
        .token_id(token_id)
        .send()
        .await
        .map_err(|e| sdk_err("revoke API token", e))?;
    spinner.finish_and_clear();

    emit_mutation(
        &serde_json::json!({ "id": id, "status": "revoked" }),
        id,
        &format!("Token {id} revoked."),
        global,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// /profile/access-tokens. Not in the spec, so not in the SDK
// ---------------------------------------------------------------------------

/// Send a request to `/api/v1/profile/access-tokens<suffix>` and return its status
/// and body, or an error with the server's message.
async fn access_tokens_request(
    method: reqwest::Method,
    suffix: &str,
    body: Option<&Value>,
    action: &str,
    global: &GlobalArgs,
) -> Result<Vec<u8>> {
    let (base_url, auth_header) = resolve_base_url_and_auth(global)?;
    let url = format!(
        "{}/api/v1/profile/access-tokens{suffix}",
        base_url.trim_end_matches('/')
    );
    let mut req = raw_http_client()?
        .request(method, &url)
        .header(reqwest::header::AUTHORIZATION, auth_header)
        .timeout(std::time::Duration::from_secs(30));
    if let Some(body) = body {
        req = req.json(body);
    }
    let resp = req.send().await.map_err(|e| sdk_err(action, e))?;
    let status = resp.status();
    let bytes = resp.bytes().await.map_err(|e| sdk_err(action, e))?;
    if !status.is_success() {
        let text = String::from_utf8_lossy(&bytes);
        return Err(raw_err(&format!("Failed to {action}"), status, &text).into());
    }
    Ok(bytes.to_vec())
}

async fn access_tokens_list(global: &GlobalArgs) -> Result<()> {
    let spinner = output::spinner("Fetching API tokens...");
    let raw =
        access_tokens_request(reqwest::Method::GET, "", None, "list API tokens", global).await?;
    spinner.finish_and_clear();
    let list: artifact_keeper_sdk::types::ApiTokenListResponse = serde_json::from_slice(&raw)
        .map_err(|e| crate::commands::helpers::bad_response("read the API token list", e))?;

    if list.items.is_empty() && !output::is_machine_format(&global.format) {
        eprintln!("No API tokens found.");
        return Ok(());
    }
    if matches!(global.format, OutputFormat::Quiet) {
        for token in &list.items {
            println!("{}", token.id);
        }
        return Ok(());
    }
    let (entries, table_str) = format_tokens_table(&list.items);
    println!(
        "{}",
        output::render_raw(Some(&raw), &entries, &global.format, Some(table_str))
    );
    Ok(())
}

async fn access_token_create(
    name: &str,
    scopes: Vec<String>,
    expires_in_days: Option<i64>,
    global: &GlobalArgs,
) -> Result<()> {
    let mut body = serde_json::json!({ "name": name });
    if !scopes.is_empty() {
        body["scopes"] = scopes.into();
    }
    if let Some(days) = expires_in_days {
        body["expires_in_days"] = days.into();
    }
    let spinner = output::spinner("Creating API token...");
    let raw = access_tokens_request(
        reqwest::Method::POST,
        "",
        Some(&body),
        "create API token",
        global,
    )
    .await?;
    spinner.finish_and_clear();
    let created: ApiTokenCreatedResponse = serde_json::from_slice(&raw)
        .map_err(|e| crate::commands::helpers::bad_response("read the new API token", e))?;

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", created.token);
        return Ok(());
    }
    let (info, table_str) = format_created_token(&created);
    println!(
        "{}",
        output::render_raw(Some(&raw), &info, &global.format, Some(table_str))
    );
    Ok(())
}

async fn access_token_revoke(id: &str, global: &GlobalArgs) -> Result<()> {
    let token_id = parse_uuid(id, "token")?;
    let spinner = output::spinner("Revoking API token...");
    access_tokens_request(
        reqwest::Method::DELETE,
        &format!("/{token_id}"),
        None,
        "revoke API token",
        global,
    )
    .await?;
    spinner.finish_and_clear();
    emit_mutation(
        &serde_json::json!({ "id": id, "status": "revoked" }),
        id,
        &format!("Token {id} revoked."),
        global,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Formatting helpers (pure functions, testable without HTTP)
// ---------------------------------------------------------------------------

fn format_whoami_detail(user: &AdminUserResponse) -> (Value, String) {
    let display = user.display_name.as_deref().unwrap_or("-");
    let last_login = user
        .last_login_at
        .map(|t| t.to_rfc3339())
        .unwrap_or_else(|| "never".to_string());

    let info = serde_json::json!({
        "id": user.id.to_string(),
        "username": user.username,
        "email": user.email,
        "display_name": display,
        "is_admin": user.is_admin,
        "is_active": user.is_active,
        "auth_provider": user.auth_provider,
        "must_change_password": user.must_change_password,
        "created_at": user.created_at.to_rfc3339(),
        "last_login_at": user.last_login_at.map(|t| t.to_rfc3339()),
    });

    let table_str = format!(
        "ID:                    {}\n\
         Username:              {}\n\
         Email:                 {}\n\
         Display Name:          {}\n\
         Admin:                 {}\n\
         Active:                {}\n\
         Auth Provider:         {}\n\
         Must Change Password:  {}\n\
         Last Login:            {}",
        user.id,
        user.username,
        user.email,
        display,
        if user.is_admin { "yes" } else { "no" },
        if user.is_active { "yes" } else { "no" },
        user.auth_provider,
        if user.must_change_password {
            "yes"
        } else {
            "no"
        },
        last_login,
    );

    (info, table_str)
}

fn format_tokens_table(tokens: &[ApiTokenResponse]) -> (Vec<Value>, String) {
    let entries: Vec<_> = tokens
        .iter()
        .map(|t| {
            serde_json::json!({
                "id": t.id.to_string(),
                "name": t.name,
                "token_prefix": t.token_prefix,
                "scopes": t.scopes,
                "created_at": t.created_at.to_rfc3339(),
                "expires_at": t.expires_at.map(|e| e.to_rfc3339()),
                "last_used_at": t.last_used_at.map(|l| l.to_rfc3339()),
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["ID", "NAME", "SCOPES", "CREATED", "EXPIRES"]);

        for t in tokens {
            let id_short = short_id(&t.id);
            let scopes = if t.scopes.is_empty() {
                "-".to_string()
            } else {
                t.scopes.join(", ")
            };
            let created = t.created_at.format("%Y-%m-%d").to_string();
            let expires = t
                .expires_at
                .map(|e| e.format("%Y-%m-%d").to_string())
                .unwrap_or_else(|| "never".to_string());
            table.add_row(vec![&id_short, &t.name, &scopes, &created, &expires]);
        }

        table.to_string()
    };

    (entries, table_str)
}

fn format_created_token(token: &ApiTokenCreatedResponse) -> (Value, String) {
    let info = serde_json::json!({
        "id": token.id.to_string(),
        "name": token.name,
        "token": token.token,
    });

    let table_str = format!(
        "Token created successfully.\n\n\
         ID:    {}\n\
         Name:  {}\n\
         Token: {}\n\n\
         Save this token now. It will not be shown again.",
        token.id, token.name, token.token,
    );

    (info, table_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use clap::Parser;
    use uuid::Uuid;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: ProfileCommand,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).unwrap()
    }

    fn try_parse(args: &[&str]) -> std::result::Result<TestCli, clap::Error> {
        TestCli::try_parse_from(args)
    }

    // ---- Parsing tests ----

    #[test]
    fn parse_show() {
        let cli = parse(&["test", "show"]);
        assert!(matches!(cli.command, ProfileCommand::Show));
    }

    #[test]
    fn parse_whoami() {
        let cli = parse(&["test", "whoami"]);
        assert!(matches!(cli.command, ProfileCommand::Whoami));
    }

    #[test]
    fn parse_update_display_name() {
        let cli = parse(&["test", "update", "--display-name", "Alice Smith"]);
        if let ProfileCommand::Update {
            display_name,
            email,
        } = cli.command
        {
            assert_eq!(display_name.unwrap(), "Alice Smith");
            assert!(email.is_none());
        } else {
            panic!("Expected Update");
        }
    }

    #[test]
    fn parse_update_email() {
        let cli = parse(&["test", "update", "--email", "alice@example.com"]);
        if let ProfileCommand::Update {
            display_name,
            email,
        } = cli.command
        {
            assert!(display_name.is_none());
            assert_eq!(email.unwrap(), "alice@example.com");
        } else {
            panic!("Expected Update");
        }
    }

    #[test]
    fn parse_update_both() {
        let cli = parse(&[
            "test",
            "update",
            "--display-name",
            "Alice",
            "--email",
            "alice@example.com",
        ]);
        if let ProfileCommand::Update {
            display_name,
            email,
        } = cli.command
        {
            assert_eq!(display_name.unwrap(), "Alice");
            assert_eq!(email.unwrap(), "alice@example.com");
        } else {
            panic!("Expected Update");
        }
    }

    #[test]
    fn parse_change_password() {
        let cli = parse(&["test", "change-password"]);
        assert!(matches!(cli.command, ProfileCommand::ChangePassword { .. }));
    }

    #[test]
    fn parse_tokens_list() {
        let cli = parse(&["test", "tokens", "list"]);
        if let ProfileCommand::Tokens {
            command: TokenCommand::List,
        } = cli.command
        {
            // ok
        } else {
            panic!("Expected Tokens List");
        }
    }

    #[test]
    fn parse_tokens_create() {
        let cli = parse(&[
            "test",
            "tokens",
            "create",
            "ci-token",
            "--scopes",
            "read,write",
        ]);
        if let ProfileCommand::Tokens {
            command:
                TokenCommand::Create {
                    name,
                    scopes,
                    expires_in_days,
                },
        } = cli.command
        {
            assert_eq!(name, "ci-token");
            assert_eq!(scopes.unwrap(), "read,write");
            assert!(expires_in_days.is_none());
        } else {
            panic!("Expected Tokens Create");
        }
    }

    #[test]
    fn parse_tokens_create_with_expiry() {
        let cli = parse(&[
            "test",
            "tokens",
            "create",
            "deploy-token",
            "--scopes",
            "read",
            "--expires-in-days",
            "90",
        ]);
        if let ProfileCommand::Tokens {
            command:
                TokenCommand::Create {
                    name,
                    scopes,
                    expires_in_days,
                },
        } = cli.command
        {
            assert_eq!(name, "deploy-token");
            assert_eq!(scopes.unwrap(), "read");
            assert_eq!(expires_in_days.unwrap(), 90);
        } else {
            panic!("Expected Tokens Create with expiry");
        }
    }

    #[test]
    fn parse_tokens_revoke() {
        let cli = parse(&["test", "tokens", "revoke", "some-token-id"]);
        if let ProfileCommand::Tokens {
            command: TokenCommand::Revoke { id },
        } = cli.command
        {
            assert_eq!(id, "some-token-id");
        } else {
            panic!("Expected Tokens Revoke");
        }
    }

    #[test]
    fn parse_tokens_revoke_missing_id() {
        let result = try_parse(&["test", "tokens", "revoke"]);
        assert!(result.is_err());
    }

    // ---- Format function tests ----

    fn make_admin_user() -> AdminUserResponse {
        AdminUserResponse {
            is_service_account: false,
            id: Uuid::nil(),
            username: "alice".to_string(),
            email: "alice@example.com".to_string(),
            display_name: Some("Alice Smith".to_string()),
            is_admin: false,
            is_active: true,
            auth_provider: "local".to_string(),
            must_change_password: false,
            created_at: Utc::now(),
            last_login_at: None,
        }
    }

    #[test]
    fn format_whoami_detail_populated() {
        let user = make_admin_user();
        let (info, table_str) = format_whoami_detail(&user);

        assert_eq!(info["username"], "alice");
        assert_eq!(info["is_active"], true);
        assert_eq!(info["auth_provider"], "local");
        assert_eq!(info["must_change_password"], false);
        assert_eq!(info["last_login_at"], serde_json::Value::Null);

        assert!(table_str.contains("Auth Provider:         local"));
        assert!(table_str.contains("Last Login:            never"));
    }

    #[test]
    fn format_tokens_table_empty() {
        let (entries, table_str) = format_tokens_table(&[]);
        assert!(entries.is_empty());
        assert!(table_str.contains("ID"));
        assert!(table_str.contains("NAME"));
        assert!(table_str.contains("SCOPES"));
    }

    #[test]
    fn format_tokens_table_with_data() {
        let tokens = vec![ApiTokenResponse {
            id: Uuid::nil(),
            name: "ci-token".to_string(),
            token_prefix: "ak_".to_string(),
            scopes: vec!["read".to_string(), "write".to_string()],
            created_at: Utc::now(),
            expires_at: Some(Utc::now()),
            last_used_at: None,
        }];
        let (entries, table_str) = format_tokens_table(&tokens);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["name"], "ci-token");
        assert_eq!(entries[0]["token_prefix"], "ak_");

        assert!(table_str.contains("ci-token"));
        assert!(table_str.contains("read, write"));
    }

    #[test]
    fn format_tokens_table_no_scopes() {
        let tokens = vec![ApiTokenResponse {
            id: Uuid::nil(),
            name: "basic-token".to_string(),
            token_prefix: "ak_".to_string(),
            scopes: vec![],
            created_at: Utc::now(),
            expires_at: None,
            last_used_at: None,
        }];
        let (_, table_str) = format_tokens_table(&tokens);
        assert!(table_str.contains("never")); // no expiry
    }

    #[test]
    fn format_created_token_output() {
        let token = ApiTokenCreatedResponse {
            expires_at: None,
            policy_applied: false,
            id: Uuid::nil(),
            name: "my-token".to_string(),
            token: "ak_secretvalue123".to_string(),
        };
        let (info, table_str) = format_created_token(&token);

        assert_eq!(info["name"], "my-token");
        assert_eq!(info["token"], "ak_secretvalue123");

        assert!(table_str.contains("my-token"));
        assert!(table_str.contains("ak_secretvalue123"));
        assert!(table_str.contains("Save this token now"));
    }

    // ---- wiremock handler tests ----

    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    static NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

    fn user_json() -> serde_json::Value {
        json!({
            "id": NIL_UUID,
            "username": "alice",
            "email": "alice@example.com",
            "display_name": "Alice Smith",
            "is_admin": false,
            "totp_enabled": false
        })
    }

    fn admin_user_json() -> serde_json::Value {
        json!({
            "id": NIL_UUID,
            "username": "alice",
            "email": "alice@example.com",
            "display_name": "Alice Smith",
            "is_admin": false,
            "is_active": true,
            "auth_provider": "local",
            "must_change_password": false,
            "created_at": "2026-01-01T00:00:00Z",
            "last_login_at": null,
            "is_service_account": false
        })
    }

    #[tokio::test]
    async fn handler_show_profile() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/auth/me"))
            .respond_with(ResponseTemplate::new(200).set_body_json(user_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = crate::commands::auth::whoami(&global).await;
        assert!(result.is_ok());

        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_whoami() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/users/me"))
            .respond_with(ResponseTemplate::new(200).set_body_json(admin_user_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = whoami(&global).await;
        assert!(result.is_ok());

        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_update_profile() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/auth/me"))
            .respond_with(ResponseTemplate::new(200).set_body_json(user_json()))
            .mount(&server)
            .await;

        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/users/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": NIL_UUID,
                "username": "alice",
                "email": "newemail@example.com",
                "display_name": "Alice New",
                "is_admin": false,
                "is_active": true,
                "auth_provider": "local",
                "must_change_password": false,
                "created_at": "2026-01-01T00:00:00Z",
                "last_login_at": null,
                "is_service_account": false
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = update_profile(Some("Alice New"), Some("newemail@example.com"), &global).await;
        assert!(result.is_ok());

        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_tokens() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/users/me/tokens"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{
                    "id": NIL_UUID,
                    "name": "ci-token",
                    "token_prefix": "ak_",
                    "scopes": ["read", "write"],
                    "created_at": "2026-01-01T00:00:00Z",
                    "expires_at": "2026-04-01T00:00:00Z",
                    "last_used_at": null
                }]
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_tokens(&global).await;
        assert!(result.is_ok());

        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_create_token() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/users/me/tokens"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": NIL_UUID,
                "name": "deploy-token",
                "token": "ak_secretvalue123",
                "policy_applied": false
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = create_token("deploy-token", Some("read,write"), Some(90), &global).await;
        assert!(result.is_ok());

        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_revoke_token() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/users/me/tokens/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = revoke_token(NIL_UUID, &global).await;
        assert!(result.is_ok());

        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_profile_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/auth/me"))
            .respond_with(ResponseTemplate::new(200).set_body_json(user_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = crate::commands::auth::whoami(&global).await;
        assert!(result.is_ok());

        crate::test_utils::teardown_env();
    }

    // ---- insta snapshot tests ----

    #[test]
    fn snapshot_profile_show_json() {
        let data = user_json();
        let output = crate::output::render(&data, &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("profile_show_json", parsed);
    }
}
