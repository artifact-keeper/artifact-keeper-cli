use artifact_keeper_sdk::ClientRepositoryTokensExt;
use artifact_keeper_sdk::types::{
    CreateRepoTokenRequest, CreateRepoTokenResponse, RepoTokenResponse,
};
use clap::Subcommand;
use miette::Result;
use serde_json::Value;

use super::client::client_for;
use super::helpers::{new_table, parse_uuid, sdk_err, short_id};
use crate::cli::GlobalArgs;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum RepoTokenCommand {
    /// List access tokens configured on a repository
    List {
        /// Repository key
        key: String,
    },

    /// Show details of a specific repository token
    Show {
        /// Repository key
        key: String,

        /// Token ID
        id: String,
    },

    /// Create a new access token scoped to a repository
    Create {
        /// Repository key
        key: String,

        /// Token name
        name: String,

        /// Comma-separated scopes (e.g. read,write)
        #[arg(long)]
        scopes: Option<String>,

        /// Optional human-readable description
        #[arg(long)]
        description: Option<String>,

        /// Number of days until the token expires (1-365)
        #[arg(long)]
        expires_in_days: Option<i64>,
    },

    /// Revoke an access token from a repository
    Revoke {
        /// Repository key
        key: String,

        /// Token ID
        id: String,
    },
}

impl RepoTokenCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List { key } => list_repo_tokens(&key, global).await,
            Self::Show { key, id } => show_repo_token(&key, &id, global).await,
            Self::Create {
                key,
                name,
                scopes,
                description,
                expires_in_days,
            } => {
                create_repo_token(
                    &key,
                    &name,
                    scopes.as_deref(),
                    description.as_deref(),
                    expires_in_days,
                    global,
                )
                .await
            }
            Self::Revoke { key, id } => revoke_repo_token(&key, &id, global).await,
        }
    }
}

async fn list_repo_tokens(key: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;

    let spinner = output::spinner("Fetching repository tokens...");
    let resp = client
        .list_repo_tokens()
        .key(key)
        .send()
        .await
        .map_err(|e| sdk_err("list repository tokens", e))?;
    let list = resp.into_inner();
    spinner.finish_and_clear();

    if list.items.is_empty() {
        eprintln!("No tokens found on repository '{key}'.");
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

async fn show_repo_token(key: &str, id: &str, global: &GlobalArgs) -> Result<()> {
    let token_id = parse_uuid(id, "token")?;
    let client = client_for(global)?;

    let spinner = output::spinner("Fetching repository token...");
    let resp = client
        .get_repo_token()
        .key(key)
        .token_id(token_id)
        .send()
        .await
        .map_err(|e| sdk_err("get repository token", e))?;
    let token = resp.into_inner();
    spinner.finish_and_clear();

    let (info, table_str) = format_token_detail(&token);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn create_repo_token(
    key: &str,
    name: &str,
    scopes: Option<&str>,
    description: Option<&str>,
    expires_in_days: Option<i64>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;

    let scope_list: Vec<String> = scopes
        .map(|s| s.split(',').map(|v| v.trim().to_string()).collect())
        .unwrap_or_default();

    let body = CreateRepoTokenRequest {
        name: name.to_string(),
        scopes: scope_list,
        description: description.map(|d| d.to_string()),
        expires_in_days,
    };

    let spinner = output::spinner("Creating repository token...");
    let resp = client
        .create_repo_token()
        .key(key)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("create repository token", e))?;
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

async fn revoke_repo_token(key: &str, id: &str, global: &GlobalArgs) -> Result<()> {
    let token_id = parse_uuid(id, "token")?;
    let client = client_for(global)?;

    let spinner = output::spinner("Revoking repository token...");
    client
        .revoke_repo_token()
        .key(key)
        .token_id(token_id)
        .send()
        .await
        .map_err(|e| sdk_err("revoke repository token", e))?;
    spinner.finish_and_clear();

    eprintln!("Token {id} revoked from repository '{key}'.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Formatting helpers (pure functions, testable without HTTP)
// ---------------------------------------------------------------------------

fn format_tokens_table(tokens: &[RepoTokenResponse]) -> (Vec<Value>, String) {
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
                "is_expired": t.is_expired,
                "is_revoked": t.is_revoked,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["ID", "NAME", "SCOPES", "CREATED", "EXPIRES", "STATUS"]);

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
            let status = token_status(t);
            table.add_row(vec![&id_short, &t.name, &scopes, &created, &expires, &status]);
        }

        table.to_string()
    };

    (entries, table_str)
}

fn format_token_detail(token: &RepoTokenResponse) -> (Value, String) {
    let info = serde_json::json!({
        "id": token.id.to_string(),
        "name": token.name,
        "token_prefix": token.token_prefix,
        "scopes": token.scopes,
        "description": token.description,
        "created_by": token.created_by,
        "created_at": token.created_at.to_rfc3339(),
        "expires_at": token.expires_at.map(|e| e.to_rfc3339()),
        "last_used_at": token.last_used_at.map(|l| l.to_rfc3339()),
        "is_expired": token.is_expired,
        "is_revoked": token.is_revoked,
    });

    let scopes = if token.scopes.is_empty() {
        "-".to_string()
    } else {
        token.scopes.join(", ")
    };

    let table_str = format!(
        "ID:           {}\n\
         Name:         {}\n\
         Prefix:       {}\n\
         Scopes:       {}\n\
         Description:  {}\n\
         Created By:   {}\n\
         Created:      {}\n\
         Expires:      {}\n\
         Last Used:    {}\n\
         Status:       {}",
        token.id,
        token.name,
        token.token_prefix,
        scopes,
        token.description.as_deref().unwrap_or("-"),
        token.created_by.as_deref().unwrap_or("-"),
        token.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
        token
            .expires_at
            .map(|e| e.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "never".to_string()),
        token
            .last_used_at
            .map(|l| l.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "never".to_string()),
        token_status(token),
    );

    (info, table_str)
}

fn format_created_token(token: &CreateRepoTokenResponse) -> (Value, String) {
    let info = serde_json::json!({
        "id": token.id.to_string(),
        "name": token.name,
        "repository_key": token.repository_key,
        "token": token.token,
    });

    let table_str = format!(
        "Token created successfully.\n\n\
         ID:         {}\n\
         Name:       {}\n\
         Repository: {}\n\
         Token:      {}\n\n\
         Save this token now. It will not be shown again.",
        token.id, token.name, token.repository_key, token.token,
    );

    (info, table_str)
}

fn token_status(token: &RepoTokenResponse) -> String {
    if token.is_revoked {
        "revoked".to_string()
    } else if token.is_expired {
        "expired".to_string()
    } else {
        "active".to_string()
    }
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
        command: RepoTokenCommand,
    }

    fn sample_token() -> RepoTokenResponse {
        RepoTokenResponse {
            created_at: Utc::now(),
            created_by: Some("admin".to_string()),
            description: Some("ci token".to_string()),
            expires_at: None,
            id: Uuid::new_v4(),
            is_expired: false,
            is_revoked: false,
            last_used_at: None,
            name: "ci".to_string(),
            scopes: vec!["read".to_string(), "write".to_string()],
            token_prefix: "ak_repo_abc".to_string(),
        }
    }

    #[test]
    fn parses_list() {
        let cli = TestCli::parse_from(["ak", "list", "my-repo"]);
        assert!(matches!(cli.command, RepoTokenCommand::List { .. }));
    }

    #[test]
    fn parses_create_with_scopes() {
        let cli =
            TestCli::parse_from(["ak", "create", "my-repo", "ci", "--scopes", "read,write"]);
        match cli.command {
            RepoTokenCommand::Create { key, name, scopes, .. } => {
                assert_eq!(key, "my-repo");
                assert_eq!(name, "ci");
                assert_eq!(scopes.as_deref(), Some("read,write"));
            }
            _ => panic!("expected Create"),
        }
    }

    #[test]
    fn parses_revoke() {
        let cli = TestCli::parse_from(["ak", "revoke", "my-repo", "some-id"]);
        assert!(matches!(cli.command, RepoTokenCommand::Revoke { .. }));
    }

    #[test]
    fn table_reports_status() {
        let mut token = sample_token();
        token.is_revoked = true;
        let (_entries, table) = format_tokens_table(std::slice::from_ref(&token));
        assert!(table.contains("revoked"));
    }

    #[test]
    fn detail_renders_scopes() {
        let token = sample_token();
        let (_info, table) = format_token_detail(&token);
        assert!(table.contains("read, write"));
        assert!(table.contains("ak_repo_abc"));
    }
}
