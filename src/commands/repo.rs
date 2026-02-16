use artifact_keeper_sdk::ClientRepositoriesExt;
use clap::Subcommand;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use miette::{IntoDiagnostic, Result};

use super::client::{client_for, client_for_optional_auth};
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat, format_bytes};

#[derive(Subcommand)]
pub enum RepoCommand {
    /// List repositories (filtered by your permissions)
    List {
        /// Filter by package format (npm, pypi, maven, docker, etc.)
        #[arg(long = "pkg-format", id = "pkg_format")]
        pkg_format: Option<String>,

        /// Filter by repository type (local, remote, virtual)
        #[arg(long, name = "type")]
        repo_type: Option<String>,

        /// Search by name
        #[arg(long)]
        search: Option<String>,

        /// Page number
        #[arg(long, default_value = "1")]
        page: i32,

        /// Results per page
        #[arg(long, default_value = "50")]
        per_page: i32,
    },

    /// Show repository details
    Show {
        /// Repository key
        key: String,
    },

    /// Create a new repository
    Create {
        /// Repository key (URL slug)
        key: String,

        /// Package format
        #[arg(long = "pkg-format", id = "pkg_format_create")]
        pkg_format: String,

        /// Repository type
        #[arg(long, default_value = "local")]
        repo_type: String,

        /// Description
        #[arg(long)]
        description: Option<String>,
    },

    /// Delete a repository
    Delete {
        /// Repository key
        key: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Interactively browse artifacts in a repository
    Browse {
        /// Repository key
        key: String,
    },
}

impl RepoCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List {
                pkg_format,
                repo_type,
                search,
                page,
                per_page,
            } => {
                list_repos(
                    pkg_format.as_deref(),
                    repo_type.as_deref(),
                    search.as_deref(),
                    page,
                    per_page,
                    global,
                )
                .await
            }
            Self::Show { key } => show_repo(&key, global).await,
            Self::Create {
                key,
                pkg_format,
                repo_type,
                description,
            } => {
                create_repo(
                    &key,
                    &pkg_format,
                    &repo_type,
                    description.as_deref(),
                    global,
                )
                .await
            }
            Self::Delete { key, yes } => delete_repo(&key, yes, global).await,
            Self::Browse { key } => browse_repo(&key, global).await,
        }
    }
}

async fn list_repos(
    format_filter: Option<&str>,
    type_filter: Option<&str>,
    search: Option<&str>,
    page: i32,
    per_page: i32,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for_optional_auth(global)?;

    let spinner = crate::output::spinner("Fetching repositories...");

    let mut req = client.list_repositories().page(page).per_page(per_page);

    if let Some(fmt) = format_filter {
        req = req.format(fmt);
    }
    if let Some(t) = type_filter {
        req = req.type_(t);
    }
    if let Some(q) = search {
        req = req.q(q);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to list repositories: {e}")))?;

    spinner.finish_and_clear();

    if resp.items.is_empty() {
        eprintln!("No repositories found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for repo in &resp.items {
            println!("{}", repo.key);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp
        .items
        .iter()
        .map(|r| {
            serde_json::json!({
                "key": r.key,
                "name": r.name,
                "format": r.format,
                "type": r.repo_type,
                "public": r.is_public,
                "storage_used": format_bytes(r.storage_used_bytes),
                "storage_used_bytes": r.storage_used_bytes,
                "description": r.description,
            })
        })
        .collect();

    let table_str = {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec!["KEY", "NAME", "FORMAT", "TYPE", "PUBLIC", "STORAGE"]);

        for r in &resp.items {
            let public = if r.is_public { "yes" } else { "no" };
            let storage = format_bytes(r.storage_used_bytes);
            table.add_row(vec![
                r.key.as_str(),
                r.name.as_str(),
                r.format.as_str(),
                r.repo_type.as_str(),
                public,
                &storage,
            ]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    // Show pagination info on stderr
    if resp.pagination.total_pages > 1 {
        eprintln!(
            "Page {} of {} ({} total repositories)",
            resp.pagination.page, resp.pagination.total_pages, resp.pagination.total
        );
    }

    Ok(())
}

async fn show_repo(key: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for_optional_auth(global)?;

    let repo = client
        .get_repository()
        .key(key)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to get repository: {e}")))?;

    let info = serde_json::json!({
        "key": repo.key,
        "name": repo.name,
        "format": repo.format,
        "type": repo.repo_type,
        "public": repo.is_public,
        "description": repo.description,
        "storage_used": format_bytes(repo.storage_used_bytes),
        "storage_used_bytes": repo.storage_used_bytes,
        "quota_bytes": repo.quota_bytes,
        "created_at": repo.created_at.to_rfc3339(),
        "updated_at": repo.updated_at.to_rfc3339(),
    });

    let table_str = format!(
        "Key:          {}\n\
         Name:         {}\n\
         Format:       {}\n\
         Type:         {}\n\
         Public:       {}\n\
         Description:  {}\n\
         Storage Used: {}\n\
         Quota:        {}\n\
         Created:      {}\n\
         Updated:      {}",
        repo.key,
        repo.name,
        repo.format,
        repo.repo_type,
        if repo.is_public { "yes" } else { "no" },
        repo.description.as_deref().unwrap_or("-"),
        format_bytes(repo.storage_used_bytes),
        repo.quota_bytes
            .map(format_bytes)
            .unwrap_or_else(|| "unlimited".into()),
        repo.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
        repo.updated_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn create_repo(
    key: &str,
    format: &str,
    repo_type: &str,
    description: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;

    let body = artifact_keeper_sdk::types::CreateRepositoryRequest {
        key: key.to_string(),
        name: key.to_string(),
        format: format.to_string(),
        repo_type: repo_type.to_string(),
        description: description.map(|d| d.to_string()),
        is_public: None,
        quota_bytes: None,
        upstream_url: None,
    };

    let resp = client
        .create_repository()
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to create repository: {e}")))?;

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", resp.key);
        return Ok(());
    }

    eprintln!(
        "Created repository '{}' (format: {}, type: {})",
        resp.key, resp.format, resp.repo_type
    );

    Ok(())
}

async fn delete_repo(key: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;

    let needs_confirmation = !skip_confirm && !global.no_input;
    if needs_confirmation {
        let confirmed = dialoguer::Confirm::new()
            .with_prompt(format!("Delete repository '{key}'? This cannot be undone"))
            .default(false)
            .interact()
            .into_diagnostic()?;

        if !confirmed {
            eprintln!("Cancelled.");
            return Ok(());
        }
    }

    client
        .delete_repository()
        .key(key)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to delete repository: {e}")))?;

    eprintln!("Deleted repository '{key}'.");
    Ok(())
}

async fn browse_repo(key: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for_optional_auth(global)?;

    let spinner = crate::output::spinner("Loading artifacts...");

    let resp = client
        .list_artifacts()
        .key(key)
        .per_page(100)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to list artifacts: {e}")))?;

    spinner.finish_and_clear();

    if resp.items.is_empty() {
        eprintln!("No artifacts in repository '{key}'.");
        return Ok(());
    }

    if global.no_input {
        // Non-interactive: just list artifacts
        for a in &resp.items {
            println!("{}", a.path);
        }
        return Ok(());
    }

    // Interactive fuzzy select
    let items: Vec<String> = resp.items.iter().map(|a| a.path.clone()).collect();

    let selection = dialoguer::FuzzySelect::new()
        .with_prompt(format!("Browse artifacts in '{key}'"))
        .items(&items)
        .interact_opt()
        .into_diagnostic()?;

    if let Some(idx) = selection {
        let artifact = &resp.items[idx];
        println!(
            "{}",
            serde_json::to_string_pretty(artifact).unwrap_or_default()
        );
    }

    Ok(())
}
