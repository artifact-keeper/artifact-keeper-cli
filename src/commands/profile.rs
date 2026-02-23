use artifact_keeper_sdk::ClientAuthExt;
use artifact_keeper_sdk::ClientUsersExt;
use artifact_keeper_sdk::types::{
    ApiTokenCreatedResponse, ApiTokenResponse, ChangePasswordRequest, CreateApiTokenRequest,
    UpdateUserRequest, UserResponse,
};
use clap::Subcommand;
use miette::Result;
use serde_json::Value;

use super::client::client_for;
use super::helpers::{new_table, parse_uuid, sdk_err, short_id};
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum ProfileCommand {
    /// Show your user profile
    Show,

    /// Update your profile fields
    Update {
        /// New display name
        #[arg(long)]
        display_name: Option<String>,

        /// New email address
        #[arg(long)]
        email: Option<String>,
    },

    /// Change your password (interactive)
    ChangePassword,

    /// Manage API tokens
    Tokens {
        #[command(subcommand)]
        command: TokenCommand,
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
            Self::Show => show_profile(global).await,
            Self::Update {
                display_name,
                email,
            } => update_profile(display_name.as_deref(), email.as_deref(), global).await,
            Self::ChangePassword => change_password(global).await,
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

async fn show_profile(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching profile...");

    let resp = client
        .get_current_user()
        .send()
        .await
        .map_err(|e| sdk_err("get current user", e))?;
    let user = resp.into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", user.id);
        return Ok(());
    }

    let (info, table_str) = format_profile_detail(&user);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn update_profile(
    display_name: Option<&str>,
    email: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    if display_name.is_none() && email.is_none() {
        return Err(AkError::ConfigError(
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
    client
        .update_user()
        .id(me.id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("update profile", e))?;
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", me.id);
        return Ok(());
    }

    eprintln!("Profile updated.");
    Ok(())
}

async fn change_password(global: &GlobalArgs) -> Result<()> {
    if global.no_input {
        return Err(AkError::ConfigError(
            "Password change requires interactive input. Remove --no-input to continue."
                .to_string(),
        )
        .into());
    }

    let current = dialoguer::Password::new()
        .with_prompt("Current password")
        .interact()
        .map_err(|e| AkError::ConfigError(format!("Failed to read password: {e}")))?;

    let new_pass = dialoguer::Password::new()
        .with_prompt("New password")
        .with_confirmation("Confirm new password", "Passwords do not match")
        .interact()
        .map_err(|e| AkError::ConfigError(format!("Failed to read password: {e}")))?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching current user...");

    let me_resp = client
        .get_current_user()
        .send()
        .await
        .map_err(|e| sdk_err("get current user", e))?;
    let me = me_resp.into_inner();
    spinner.finish_and_clear();

    let body = ChangePasswordRequest {
        current_password: Some(current),
        new_password: new_pass,
    };

    let spinner = output::spinner("Changing password...");
    client
        .change_password()
        .id(me.id)
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
    let spinner = output::spinner("Fetching current user...");

    let me_resp = client
        .get_current_user()
        .send()
        .await
        .map_err(|e| sdk_err("get current user", e))?;
    let me = me_resp.into_inner();
    spinner.finish_and_clear();

    let spinner = output::spinner("Fetching API tokens...");
    let resp = client
        .list_user_tokens()
        .id(me.id)
        .send()
        .await
        .map_err(|e| sdk_err("list API tokens", e))?;
    let list = resp.into_inner();
    spinner.finish_and_clear();

    if list.items.is_empty() {
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
        output::render(&entries, &global.format, Some(table_str))
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
    let spinner = output::spinner("Fetching current user...");

    let me_resp = client
        .get_current_user()
        .send()
        .await
        .map_err(|e| sdk_err("get current user", e))?;
    let me = me_resp.into_inner();
    spinner.finish_and_clear();

    let scope_list: Vec<String> = scopes
        .map(|s| s.split(',').map(|v| v.trim().to_string()).collect())
        .unwrap_or_default();

    let body = CreateApiTokenRequest {
        name: name.to_string(),
        scopes: scope_list,
        expires_in_days,
    };

    let spinner = output::spinner("Creating API token...");
    let resp = client
        .create_user_api_token()
        .id(me.id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("create API token", e))?;
    let created = resp.into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", created.token);
        return Ok(());
    }

    let (info, table_str) = format_created_token(&created);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn revoke_token(id: &str, global: &GlobalArgs) -> Result<()> {
    let token_id = parse_uuid(id, "token")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching current user...");

    let me_resp = client
        .get_current_user()
        .send()
        .await
        .map_err(|e| sdk_err("get current user", e))?;
    let me = me_resp.into_inner();
    spinner.finish_and_clear();

    let spinner = output::spinner("Revoking API token...");
    client
        .revoke_user_api_token()
        .id(me.id)
        .token_id(token_id)
        .send()
        .await
        .map_err(|e| sdk_err("revoke API token", e))?;
    spinner.finish_and_clear();

    eprintln!("Token {id} revoked.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Formatting helpers (pure functions, testable without HTTP)
// ---------------------------------------------------------------------------

fn format_profile_detail(user: &UserResponse) -> (Value, String) {
    let display = user.display_name.as_deref().unwrap_or("-");

    let info = serde_json::json!({
        "id": user.id.to_string(),
        "username": user.username,
        "email": user.email,
        "display_name": display,
        "is_admin": user.is_admin,
        "totp_enabled": user.totp_enabled,
    });

    let table_str = format!(
        "ID:            {}\n\
         Username:      {}\n\
         Email:         {}\n\
         Display Name:  {}\n\
         Admin:         {}\n\
         TOTP Enabled:  {}",
        user.id,
        user.username,
        user.email,
        display,
        if user.is_admin { "yes" } else { "no" },
        if user.totp_enabled { "yes" } else { "no" },
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
        assert!(matches!(cli.command, ProfileCommand::ChangePassword));
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

    fn make_user() -> UserResponse {
        UserResponse {
            id: Uuid::nil(),
            username: "alice".to_string(),
            email: "alice@example.com".to_string(),
            display_name: Some("Alice Smith".to_string()),
            is_admin: false,
            totp_enabled: true,
        }
    }

    #[test]
    fn format_profile_detail_populated() {
        let user = make_user();
        let (info, table_str) = format_profile_detail(&user);

        assert_eq!(info["username"], "alice");
        assert_eq!(info["email"], "alice@example.com");
        assert_eq!(info["display_name"], "Alice Smith");
        assert_eq!(info["is_admin"], false);
        assert_eq!(info["totp_enabled"], true);

        assert!(table_str.contains("alice"));
        assert!(table_str.contains("alice@example.com"));
        assert!(table_str.contains("Alice Smith"));
        assert!(table_str.contains("no")); // is_admin
        assert!(table_str.contains("yes")); // totp_enabled
    }

    #[test]
    fn format_profile_detail_no_display_name() {
        let mut user = make_user();
        user.display_name = None;
        let (info, table_str) = format_profile_detail(&user);

        assert_eq!(info["display_name"], "-");
        assert!(table_str.contains("Display Name:  -"));
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
        let result = show_profile(&global).await;
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
                "last_login_at": null
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
            .and(path("/api/v1/auth/me"))
            .respond_with(ResponseTemplate::new(200).set_body_json(user_json()))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/users/{NIL_UUID}/tokens")))
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

        Mock::given(method("GET"))
            .and(path("/api/v1/auth/me"))
            .respond_with(ResponseTemplate::new(200).set_body_json(user_json()))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!("/api/v1/users/{NIL_UUID}/tokens")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": NIL_UUID,
                "name": "deploy-token",
                "token": "ak_secretvalue123"
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

        Mock::given(method("GET"))
            .and(path("/api/v1/auth/me"))
            .respond_with(ResponseTemplate::new(200).set_body_json(user_json()))
            .mount(&server)
            .await;

        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/users/{NIL_UUID}/tokens/{NIL_UUID}")))
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
        let result = show_profile(&global).await;
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
