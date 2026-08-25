use artifact_keeper_sdk::ClientServiceAccountsExt;
use clap::Subcommand;
use miette::Result;

use super::client::client_for;
use super::helpers::{confirm_action, new_table, parse_uuid, sdk_err, short_id};
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum ServiceAccountCommand {
    /// List all service accounts
    List,

    /// Show service account details
    Show {
        /// Service account ID
        id: String,
    },

    /// Create a new service account
    Create {
        /// Name for the service account (prefixed with "svc-" server-side)
        name: String,

        /// Description
        #[arg(long)]
        description: Option<String>,
    },

    /// Update a service account
    Update {
        /// Service account ID
        id: String,

        /// New display name
        #[arg(long)]
        display_name: Option<String>,

        /// Mark the account active
        #[arg(long, conflicts_with = "inactive")]
        active: bool,

        /// Mark the account inactive
        #[arg(long)]
        inactive: bool,
    },

    /// Delete a service account
    Delete {
        /// Service account ID
        id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Manage service account access tokens
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },

    /// Preview which repositories a repo-selector would match
    PreviewSelector {
        /// Repo selector as a JSON object (e.g. '{"formats":["npm"]}')
        #[arg(long)]
        selector: String,
    },
}

#[derive(Subcommand)]
pub enum TokenCommand {
    /// List tokens for a service account
    List {
        /// Service account ID
        account: String,
    },

    /// Create a token for a service account
    Create {
        /// Service account ID
        account: String,

        /// Token name
        name: String,

        /// Scope to grant (repeatable, e.g. --scope read --scope write)
        #[arg(long = "scope", required = true)]
        scopes: Vec<String>,

        /// Expiry in days (default: server policy)
        #[arg(long)]
        expires_in_days: Option<i64>,

        /// Restrict to specific repository IDs (repeatable)
        #[arg(long = "repository-id")]
        repository_ids: Vec<String>,

        /// Dynamic repo selector as a JSON object (mutually exclusive with --repository-id)
        #[arg(long, conflicts_with = "repository_ids")]
        repo_selector: Option<String>,

        /// Description
        #[arg(long)]
        description: Option<String>,
    },

    /// Revoke a service account token
    Revoke {
        /// Service account ID
        account: String,

        /// Token ID
        token: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}

impl ServiceAccountCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List => list_accounts(global).await,
            Self::Show { id } => show_account(&id, global).await,
            Self::Create { name, description } => {
                create_account(&name, description.as_deref(), global).await
            }
            Self::Update {
                id,
                display_name,
                active,
                inactive,
            } => {
                let is_active = if active {
                    Some(true)
                } else if inactive {
                    Some(false)
                } else {
                    None
                };
                update_account(&id, display_name.as_deref(), is_active, global).await
            }
            Self::Delete { id, yes } => delete_account(&id, yes, global).await,
            Self::Token { command } => command.execute(global).await,
            Self::PreviewSelector { selector } => preview_selector(&selector, global).await,
        }
    }
}

impl TokenCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List { account } => list_tokens(&account, global).await,
            Self::Create {
                account,
                name,
                scopes,
                expires_in_days,
                repository_ids,
                repo_selector,
                description,
            } => {
                create_token(
                    &account,
                    &name,
                    &scopes,
                    expires_in_days,
                    &repository_ids,
                    repo_selector.as_deref(),
                    description.as_deref(),
                    global,
                )
                .await
            }
            Self::Revoke {
                account,
                token,
                yes,
            } => revoke_token(&account, &token, yes, global).await,
        }
    }
}

/// Parse a JSON object string into a serde_json map, with a friendly error.
fn parse_json_object(raw: &str, label: &str) -> Result<serde_json::Map<String, serde_json::Value>> {
    let value: serde_json::Value = serde_json::from_str(raw)
        .map_err(|e| AkError::ConfigError(format!("Invalid {label} JSON: {e}")))?;
    match value {
        serde_json::Value::Object(map) => Ok(map),
        _ => Err(AkError::ConfigError(format!("{label} must be a JSON object")).into()),
    }
}

async fn list_accounts(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching service accounts...");

    let resp = client
        .list_service_accounts()
        .send()
        .await
        .map_err(|e| sdk_err("list service accounts", e))?;

    spinner.finish_and_clear();

    if resp.items.is_empty() {
        eprintln!("No service accounts found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for sa in &resp.items {
            println!("{}", sa.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp
        .items
        .iter()
        .map(|sa| {
            serde_json::json!({
                "id": sa.id.to_string(),
                "username": sa.username,
                "display_name": sa.display_name,
                "is_active": sa.is_active,
                "token_count": sa.token_count,
                "created_at": sa.created_at.to_rfc3339(),
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec![
            "ID",
            "USERNAME",
            "DISPLAY NAME",
            "ACTIVE",
            "TOKENS",
            "CREATED",
        ]);

        for sa in &resp.items {
            let id_short = short_id(&sa.id);
            let display = sa.display_name.as_deref().unwrap_or("-");
            let active = if sa.is_active { "yes" } else { "no" };
            let created = sa.created_at.format("%Y-%m-%d").to_string();
            table.add_row(vec![
                &id_short,
                &sa.username,
                display,
                active,
                &sa.token_count.to_string(),
                &created,
            ]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn show_account(id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let account_id = parse_uuid(id, "service account")?;

    let spinner = output::spinner("Fetching service account...");
    let sa = client
        .get_service_account()
        .id(account_id)
        .send()
        .await
        .map_err(|e| sdk_err("get service account", e))?;
    spinner.finish_and_clear();

    let info = serde_json::json!({
        "id": sa.id.to_string(),
        "username": sa.username,
        "display_name": sa.display_name,
        "is_active": sa.is_active,
        "created_at": sa.created_at.to_rfc3339(),
        "updated_at": sa.updated_at.to_rfc3339(),
    });

    let table_str = format!(
        "ID:           {}\n\
         Username:     {}\n\
         Display Name: {}\n\
         Active:       {}\n\
         Created:      {}\n\
         Updated:      {}",
        sa.id,
        sa.username,
        sa.display_name.as_deref().unwrap_or("-"),
        if sa.is_active { "yes" } else { "no" },
        sa.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
        sa.updated_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn create_account(name: &str, description: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Creating service account...");

    let body = artifact_keeper_sdk::types::CreateServiceAccountRequest {
        name: name.to_string(),
        description: description.map(|s| s.to_string()),
    };

    // The v1.6.0 spec declares this endpoint as `201 Created`, matching the
    // strict generated client, so the #98 raw-HTTP workaround (which accepted
    // the backend's earlier `200 OK`) is no longer needed.
    let resp = client
        .create_service_account()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("create service account", e))?;
    let sa = resp.into_inner();

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", sa.id);
        return Ok(());
    }

    eprintln!("Service account '{}' created (ID: {}).", sa.username, sa.id);

    Ok(())
}

async fn update_account(
    id: &str,
    display_name: Option<&str>,
    is_active: Option<bool>,
    global: &GlobalArgs,
) -> Result<()> {
    if display_name.is_none() && is_active.is_none() {
        return Err(AkError::ConfigError(
            "Nothing to update: provide --display-name and/or --active/--inactive".to_string(),
        )
        .into());
    }

    let client = client_for(global)?;
    let account_id = parse_uuid(id, "service account")?;
    let spinner = output::spinner("Updating service account...");

    let body = artifact_keeper_sdk::types::UpdateServiceAccountRequest {
        display_name: display_name.map(|s| s.to_string()),
        is_active,
    };

    let sa = client
        .update_service_account()
        .id(account_id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("update service account", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", sa.id);
        return Ok(());
    }

    eprintln!("Service account '{}' updated.", sa.username);

    Ok(())
}

async fn delete_account(id: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    let account_id = parse_uuid(id, "service account")?;

    if !confirm_action(
        &format!("Delete service account {id}?"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Deleting service account...");

    client
        .delete_service_account()
        .id(account_id)
        .send()
        .await
        .map_err(|e| sdk_err("delete service account", e))?;

    spinner.finish_and_clear();
    eprintln!("Service account {id} deleted.");

    Ok(())
}

async fn list_tokens(account: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let account_id = parse_uuid(account, "service account")?;
    let spinner = output::spinner("Fetching tokens...");

    let resp = client
        .list_tokens()
        .id(account_id)
        .send()
        .await
        .map_err(|e| sdk_err("list tokens", e))?;

    spinner.finish_and_clear();

    if resp.items.is_empty() {
        eprintln!("No tokens found for service account {account}.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for t in &resp.items {
            println!("{}", t.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp
        .items
        .iter()
        .map(|t| {
            serde_json::json!({
                "id": t.id.to_string(),
                "name": t.name,
                "token_prefix": t.token_prefix,
                "scopes": t.scopes,
                "is_expired": t.is_expired,
                "expires_at": t.expires_at.map(|d| d.to_rfc3339()),
                "last_used_at": t.last_used_at.map(|d| d.to_rfc3339()),
                "repository_ids": t.repository_ids.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
                "created_at": t.created_at.to_rfc3339(),
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec![
            "ID",
            "NAME",
            "PREFIX",
            "SCOPES",
            "EXPIRED",
            "EXPIRES",
            "LAST USED",
        ]);

        for t in &resp.items {
            let id_short = short_id(&t.id);
            let scopes = t.scopes.join(",");
            let expired = if t.is_expired { "yes" } else { "no" };
            let expires = t
                .expires_at
                .map(|d| d.format("%Y-%m-%d").to_string())
                .unwrap_or_else(|| "never".to_string());
            let last_used = t
                .last_used_at
                .map(|d| d.format("%Y-%m-%d").to_string())
                .unwrap_or_else(|| "-".to_string());
            table.add_row(vec![
                &id_short,
                &t.name,
                &t.token_prefix,
                &scopes,
                expired,
                &expires,
                &last_used,
            ]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn create_token(
    account: &str,
    name: &str,
    scopes: &[String],
    expires_in_days: Option<i64>,
    repository_ids: &[String],
    repo_selector: Option<&str>,
    description: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let account_id = parse_uuid(account, "service account")?;

    let repo_ids = if repository_ids.is_empty() {
        None
    } else {
        let ids = repository_ids
            .iter()
            .map(|r| parse_uuid(r, "repository"))
            .collect::<Result<Vec<_>>>()?;
        Some(ids)
    };

    let selector = match repo_selector {
        Some(raw) => Some(parse_json_object(raw, "repo selector")?),
        None => None,
    };

    let spinner = output::spinner("Creating token...");

    let body = artifact_keeper_sdk::types::CreateTokenRequest {
        name: name.to_string(),
        scopes: scopes.to_vec(),
        expires_in_days,
        repository_ids: repo_ids,
        repo_selector: selector,
        description: description.map(|s| s.to_string()),
    };

    let resp = client
        .create_token()
        .id(account_id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("create token", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", resp.token);
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Json | OutputFormat::Yaml) {
        let info = serde_json::json!({
            "id": resp.id.to_string(),
            "name": resp.name,
            "token": resp.token,
        });
        println!("{}", output::render(&info, &global.format, None));
        return Ok(());
    }

    eprintln!(
        "Token '{}' created (ID: {}).\n\
         Save this token now - it will not be shown again:",
        resp.name, resp.id
    );
    println!("{}", resp.token);

    Ok(())
}

async fn revoke_token(
    account: &str,
    token: &str,
    skip_confirm: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let account_id = parse_uuid(account, "service account")?;
    let token_id = parse_uuid(token, "token")?;

    if !confirm_action(
        &format!("Revoke token {token}?"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Revoking token...");

    client
        .revoke_token()
        .id(account_id)
        .token_id(token_id)
        .send()
        .await
        .map_err(|e| sdk_err("revoke token", e))?;

    spinner.finish_and_clear();
    eprintln!("Token {token} revoked.");

    Ok(())
}

async fn preview_selector(selector: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let repo_selector = parse_json_object(selector, "repo selector")?;

    let spinner = output::spinner("Evaluating selector...");

    let body = artifact_keeper_sdk::types::PreviewRepoSelectorRequest { repo_selector };

    let resp = client
        .preview_repo_selector()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("preview repo selector", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        for r in &resp.matched_repositories {
            println!("{}", r.key);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp
        .matched_repositories
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id.to_string(),
                "key": r.key,
                "format": r.format,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["KEY", "FORMAT", "ID"]);
        for r in &resp.matched_repositories {
            let id_short = short_id(&r.id);
            table.add_row(vec![r.key.as_str(), r.format.as_str(), &id_short]);
        }
        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    eprintln!("{} repositories matched.", resp.total);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use serde_json::json;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: ServiceAccountCommand,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).unwrap()
    }

    fn try_parse(args: &[&str]) -> Result<TestCli, clap::Error> {
        TestCli::try_parse_from(args)
    }

    // ---- List ----

    #[test]
    fn parse_list() {
        let cli = parse(&["test", "list"]);
        assert!(matches!(cli.command, ServiceAccountCommand::List));
    }

    // ---- Show ----

    #[test]
    fn parse_show() {
        let cli = parse(&["test", "show", "abc"]);
        if let ServiceAccountCommand::Show { id } = cli.command {
            assert_eq!(id, "abc");
        } else {
            panic!("expected Show");
        }
    }

    #[test]
    fn parse_show_missing_id_fails() {
        assert!(try_parse(&["test", "show"]).is_err());
    }

    // ---- Create ----

    #[test]
    fn parse_create() {
        let cli = parse(&["test", "create", "ci-bot", "--description", "CI robot"]);
        if let ServiceAccountCommand::Create { name, description } = cli.command {
            assert_eq!(name, "ci-bot");
            assert_eq!(description.as_deref(), Some("CI robot"));
        } else {
            panic!("expected Create");
        }
    }

    #[test]
    fn parse_create_missing_name_fails() {
        assert!(try_parse(&["test", "create"]).is_err());
    }

    // ---- Update ----

    #[test]
    fn parse_update_display_name() {
        let cli = parse(&["test", "update", "id1", "--display-name", "New Name"]);
        if let ServiceAccountCommand::Update {
            id,
            display_name,
            active,
            inactive,
        } = cli.command
        {
            assert_eq!(id, "id1");
            assert_eq!(display_name.as_deref(), Some("New Name"));
            assert!(!active);
            assert!(!inactive);
        } else {
            panic!("expected Update");
        }
    }

    #[test]
    fn parse_update_active_and_inactive_conflict() {
        assert!(try_parse(&["test", "update", "id1", "--active", "--inactive"]).is_err());
    }

    // ---- Delete ----

    #[test]
    fn parse_delete_with_yes() {
        let cli = parse(&["test", "delete", "id1", "--yes"]);
        if let ServiceAccountCommand::Delete { id, yes } = cli.command {
            assert_eq!(id, "id1");
            assert!(yes);
        } else {
            panic!("expected Delete");
        }
    }

    // ---- Token subcommands ----

    #[test]
    fn parse_token_list() {
        let cli = parse(&["test", "token", "list", "acc1"]);
        if let ServiceAccountCommand::Token {
            command: TokenCommand::List { account },
        } = cli.command
        {
            assert_eq!(account, "acc1");
        } else {
            panic!("expected Token::List");
        }
    }

    #[test]
    fn parse_token_create() {
        let cli = parse(&[
            "test",
            "token",
            "create",
            "acc1",
            "deploy",
            "--scope",
            "read",
            "--scope",
            "write",
            "--expires-in-days",
            "30",
        ]);
        if let ServiceAccountCommand::Token {
            command:
                TokenCommand::Create {
                    account,
                    name,
                    scopes,
                    expires_in_days,
                    ..
                },
        } = cli.command
        {
            assert_eq!(account, "acc1");
            assert_eq!(name, "deploy");
            assert_eq!(scopes, vec!["read".to_string(), "write".to_string()]);
            assert_eq!(expires_in_days, Some(30));
        } else {
            panic!("expected Token::Create");
        }
    }

    #[test]
    fn parse_token_create_requires_scope() {
        assert!(try_parse(&["test", "token", "create", "acc1", "deploy"]).is_err());
    }

    #[test]
    fn parse_token_create_selector_conflicts_repo_ids() {
        assert!(
            try_parse(&[
                "test",
                "token",
                "create",
                "acc1",
                "deploy",
                "--scope",
                "read",
                "--repository-id",
                "r1",
                "--repo-selector",
                "{}",
            ])
            .is_err()
        );
    }

    #[test]
    fn parse_token_revoke() {
        let cli = parse(&["test", "token", "revoke", "acc1", "tok1", "--yes"]);
        if let ServiceAccountCommand::Token {
            command:
                TokenCommand::Revoke {
                    account,
                    token,
                    yes,
                },
        } = cli.command
        {
            assert_eq!(account, "acc1");
            assert_eq!(token, "tok1");
            assert!(yes);
        } else {
            panic!("expected Token::Revoke");
        }
    }

    // ---- PreviewSelector ----

    #[test]
    fn parse_preview_selector() {
        let cli = parse(&[
            "test",
            "preview-selector",
            "--selector",
            "{\"formats\":[\"npm\"]}",
        ]);
        if let ServiceAccountCommand::PreviewSelector { selector } = cli.command {
            assert_eq!(selector, "{\"formats\":[\"npm\"]}");
        } else {
            panic!("expected PreviewSelector");
        }
    }

    // ---- parse_json_object ----

    #[test]
    fn parse_json_object_valid() {
        let m = parse_json_object("{\"formats\":[\"npm\"]}", "test").unwrap();
        assert!(m.contains_key("formats"));
    }

    #[test]
    fn parse_json_object_not_object() {
        assert!(parse_json_object("[1,2,3]", "test").is_err());
    }

    #[test]
    fn parse_json_object_invalid_json() {
        assert!(parse_json_object("{not json", "test").is_err());
    }

    // ---- wiremock handler tests ----

    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, ResponseTemplate};

    fn sa_summary_json(id: &str, username: &str) -> serde_json::Value {
        json!({
            "id": id,
            "username": username,
            "display_name": "Bot",
            "is_active": true,
            "token_count": 2_i64,
            "created_at": "2026-01-15T12:00:00Z",
            "updated_at": "2026-01-15T12:00:00Z"
        })
    }

    fn sa_json(id: &str, username: &str) -> serde_json::Value {
        json!({
            "id": id,
            "username": username,
            "display_name": "Bot",
            "is_active": true,
            "created_at": "2026-01-15T12:00:00Z",
            "updated_at": "2026-01-15T12:00:00Z"
        })
    }

    const SA_ID: &str = "00000000-0000-0000-0000-000000000001";
    const TOK_ID: &str = "00000000-0000-0000-0000-0000000000a1";

    #[tokio::test]
    async fn handler_list_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/service-accounts"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "items": [] })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(list_accounts(&global).await.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/service-accounts"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [sa_summary_json(SA_ID, "svc-ci")]
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(list_accounts(&global).await.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/service-accounts/{SA_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(sa_json(SA_ID, "svc-ci")))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(show_account(SA_ID, &global).await.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_create() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/service-accounts"))
            .respond_with(ResponseTemplate::new(201).set_body_json(sa_json(SA_ID, "svc-ci")))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        assert!(create_account("ci", Some("robot"), &global).await.is_ok());
        crate::test_utils::teardown_env();
    }

    /// #98 fixed: the v1.6.0 spec declares `201 Created`, so the CLI now uses
    /// the strict generated client. A non-201 success (the backend's earlier
    /// `200 OK`) is treated as an unexpected response rather than success.
    #[tokio::test]
    async fn handler_create_rejects_non_201() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/service-accounts"))
            .respond_with(ResponseTemplate::new(200).set_body_json(sa_json(SA_ID, "svc-ci")))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        assert!(create_account("ci", Some("robot"), &global).await.is_err());
        crate::test_utils::teardown_env();
    }

    /// Genuine HTTP failures must still error with the status attached.
    #[tokio::test]
    async fn handler_create_403_is_error() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/service-accounts"))
            .respond_with(
                ResponseTemplate::new(403).set_body_json(json!({"error": "admin required"})),
            )
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = create_account("ci", None, &global).await;
        assert!(result.is_err());
        let msg = format!("{:?}", result.unwrap_err());
        assert!(msg.contains("403"), "error should carry the status: {msg}");
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_update() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/service-accounts/{SA_ID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(sa_json(SA_ID, "svc-ci")))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        assert!(
            update_account(SA_ID, Some("Renamed"), Some(false), &global)
                .await
                .is_ok()
        );
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_update_nothing_errors() {
        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        assert!(update_account(SA_ID, None, None, &global).await.is_err());
    }

    #[tokio::test]
    async fn handler_delete() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/service-accounts/{SA_ID}")))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(delete_account(SA_ID, true, &global).await.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_token_list() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/service-accounts/{SA_ID}/tokens")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{
                    "id": TOK_ID,
                    "name": "deploy",
                    "token_prefix": "ak_abc",
                    "scopes": ["read", "write"],
                    "is_expired": false,
                    "expires_at": null,
                    "last_used_at": null,
                    "repository_ids": [],
                    "created_at": "2026-01-15T12:00:00Z"
                }]
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(list_tokens(SA_ID, &global).await.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_token_create() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!("/api/v1/service-accounts/{SA_ID}/tokens")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": TOK_ID,
                "name": "deploy",
                "token": "ak_secret_value"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let scopes = vec!["read".to_string()];
        assert!(
            create_token(SA_ID, "deploy", &scopes, None, &[], None, None, &global)
                .await
                .is_ok()
        );
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_token_revoke() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path(format!(
                "/api/v1/service-accounts/{SA_ID}/tokens/{TOK_ID}"
            )))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(revoke_token(SA_ID, TOK_ID, true, &global).await.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_preview_selector() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path_regex("/api/v1/service-accounts/repo-selector/preview"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "matched_repositories": [{
                    "id": SA_ID,
                    "key": "npm-local",
                    "format": "npm"
                }],
                "total": 1_i64
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(
            preview_selector("{\"formats\":[\"npm\"]}", &global)
                .await
                .is_ok()
        );
        crate::test_utils::teardown_env();
    }
}
