use artifact_keeper_sdk::ClientLifecycleExt;
use clap::Subcommand;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use miette::{IntoDiagnostic, Result};

use super::client::client_for;
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat, format_bytes};

#[derive(Subcommand)]
pub enum LifecycleCommand {
    /// List lifecycle policies
    List {
        /// Filter by repository ID
        #[arg(long)]
        repo: Option<String>,
    },

    /// Show lifecycle policy details
    Show {
        /// Policy ID
        id: String,
    },

    /// Create a lifecycle policy
    Create {
        /// Policy name
        name: String,

        /// Maximum vulnerability severity to allow (e.g. critical, high, medium, low)
        #[arg(long)]
        max_severity: String,

        /// Block artifacts that fail policy checks
        #[arg(long)]
        block_on_fail: bool,

        /// Block unscanned artifacts
        #[arg(long)]
        block_unscanned: bool,

        /// Maximum artifact age in days
        #[arg(long)]
        max_age_days: Option<i32>,

        /// Minimum staging time in hours
        #[arg(long)]
        min_staging_hours: Option<i32>,

        /// Bind to a specific repository ID
        #[arg(long)]
        repo: Option<String>,

        /// Require artifact signatures
        #[arg(long)]
        require_signature: bool,
    },

    /// Delete a lifecycle policy
    Delete {
        /// Policy ID
        id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Preview what a policy would affect (dry-run)
    Preview {
        /// Policy ID
        id: String,
    },

    /// Execute a policy now
    Execute {
        /// Policy ID
        id: String,
    },
}

impl LifecycleCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List { repo } => list_policies(repo.as_deref(), global).await,
            Self::Show { id } => show_policy(&id, global).await,
            Self::Create {
                name,
                max_severity,
                block_on_fail,
                block_unscanned,
                max_age_days,
                min_staging_hours,
                repo,
                require_signature,
            } => {
                create_policy(
                    &name,
                    &max_severity,
                    block_on_fail,
                    block_unscanned,
                    max_age_days,
                    min_staging_hours,
                    repo.as_deref(),
                    require_signature,
                    global,
                )
                .await
            }
            Self::Delete { id, yes } => delete_policy(&id, yes, global).await,
            Self::Preview { id } => preview_policy(&id, global).await,
            Self::Execute { id } => execute_policy(&id, global).await,
        }
    }
}

async fn list_policies(repo_id: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching lifecycle policies...");

    let mut req = client.list_lifecycle_policies();
    if let Some(id) = repo_id {
        let uid: uuid::Uuid = id
            .parse()
            .map_err(|_| AkError::ConfigError(format!("Invalid repository ID: {id}")))?;
        req = req.repository_id(uid);
    }

    let policies = req
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to list lifecycle policies: {e}")))?;

    let policies = policies.into_inner();
    spinner.finish_and_clear();

    if policies.is_empty() {
        eprintln!("No lifecycle policies found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for p in &policies {
            println!("{}", p.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = policies
        .iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id.to_string(),
                "name": p.name,
                "policy_type": p.policy_type,
                "enabled": p.enabled,
                "priority": p.priority,
                "description": p.description,
                "last_run_at": p.last_run_at.map(|t| t.to_rfc3339()),
                "last_run_items_removed": p.last_run_items_removed,
            })
        })
        .collect();

    let table_str = {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                "ID", "NAME", "TYPE", "ENABLED", "PRIORITY", "LAST RUN",
            ]);

        for p in &policies {
            let id_short = &p.id.to_string()[..8];
            let enabled = if p.enabled { "yes" } else { "no" };
            let last_run = p
                .last_run_at
                .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| "-".to_string());
            table.add_row(vec![
                id_short,
                &p.name,
                &p.policy_type,
                enabled,
                &p.priority.to_string(),
                &last_run,
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

async fn show_policy(id: &str, global: &GlobalArgs) -> Result<()> {
    let policy_id: uuid::Uuid = id
        .parse()
        .map_err(|_| AkError::ConfigError(format!("Invalid policy ID: {id}")))?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching lifecycle policy...");

    let policy = client
        .get_lifecycle_policy()
        .id(policy_id)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to get lifecycle policy: {e}")))?;

    spinner.finish_and_clear();

    let info = serde_json::json!({
        "id": policy.id.to_string(),
        "name": policy.name,
        "policy_type": policy.policy_type,
        "enabled": policy.enabled,
        "priority": policy.priority,
        "description": policy.description,
        "config": policy.config,
        "repository_id": policy.repository_id.map(|u| u.to_string()),
        "last_run_at": policy.last_run_at.map(|t| t.to_rfc3339()),
        "last_run_items_removed": policy.last_run_items_removed,
        "created_at": policy.created_at.to_rfc3339(),
        "updated_at": policy.updated_at.to_rfc3339(),
    });

    let table_str = format!(
        "ID:              {}\n\
         Name:            {}\n\
         Type:            {}\n\
         Enabled:         {}\n\
         Priority:        {}\n\
         Description:     {}\n\
         Repository:      {}\n\
         Last Run:        {}\n\
         Items Removed:   {}\n\
         Created:         {}\n\
         Updated:         {}",
        policy.id,
        policy.name,
        policy.policy_type,
        if policy.enabled { "yes" } else { "no" },
        policy.priority,
        policy.description.as_deref().unwrap_or("-"),
        policy
            .repository_id
            .map(|u| u.to_string())
            .unwrap_or_else(|| "all".to_string()),
        policy
            .last_run_at
            .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "-".to_string()),
        policy
            .last_run_items_removed
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string()),
        policy.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
        policy.updated_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn create_policy(
    name: &str,
    max_severity: &str,
    block_on_fail: bool,
    block_unscanned: bool,
    max_age_days: Option<i32>,
    min_staging_hours: Option<i32>,
    repo_id: Option<&str>,
    require_signature: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let repository_id = repo_id
        .map(|id| {
            id.parse::<uuid::Uuid>()
                .map_err(|_| AkError::ConfigError(format!("Invalid repository ID: {id}")))
        })
        .transpose()?;

    let client = client_for(global)?;
    let spinner = output::spinner("Creating lifecycle policy...");

    let body = artifact_keeper_sdk::types::CreatePolicyRequest {
        name: name.to_string(),
        max_severity: max_severity.to_string(),
        block_on_fail,
        block_unscanned,
        max_artifact_age_days: max_age_days,
        min_staging_hours,
        repository_id,
        require_signature: require_signature.then_some(true),
    };

    let policy = client
        .create_lifecycle_policy()
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to create lifecycle policy: {e}")))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", policy.id);
        return Ok(());
    }

    eprintln!(
        "Lifecycle policy '{}' created (ID: {}).",
        policy.name, policy.id
    );

    Ok(())
}

async fn delete_policy(id: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    let policy_id: uuid::Uuid = id
        .parse()
        .map_err(|_| AkError::ConfigError(format!("Invalid policy ID: {id}")))?;

    let needs_confirmation = !skip_confirm && !global.no_input;
    if needs_confirmation {
        let confirmed = dialoguer::Confirm::new()
            .with_prompt(format!("Delete lifecycle policy {id}?"))
            .default(false)
            .interact()
            .into_diagnostic()?;

        if !confirmed {
            eprintln!("Cancelled.");
            return Ok(());
        }
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Deleting lifecycle policy...");

    client
        .delete_lifecycle_policy()
        .id(policy_id)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to delete lifecycle policy: {e}")))?;

    spinner.finish_and_clear();
    eprintln!("Lifecycle policy {id} deleted.");

    Ok(())
}

async fn preview_policy(id: &str, global: &GlobalArgs) -> Result<()> {
    let policy_id: uuid::Uuid = id
        .parse()
        .map_err(|_| AkError::ConfigError(format!("Invalid policy ID: {id}")))?;

    let client = client_for(global)?;
    let spinner = output::spinner("Previewing policy execution...");

    let result = client
        .preview_policy()
        .id(policy_id)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to preview policy: {e}")))?;

    spinner.finish_and_clear();
    print_execution_result(&result, "Preview", global);

    Ok(())
}

async fn execute_policy(id: &str, global: &GlobalArgs) -> Result<()> {
    let policy_id: uuid::Uuid = id
        .parse()
        .map_err(|_| AkError::ConfigError(format!("Invalid policy ID: {id}")))?;

    let client = client_for(global)?;
    let spinner = output::spinner("Executing policy...");

    let result = client
        .execute_policy()
        .id(policy_id)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to execute policy: {e}")))?;

    spinner.finish_and_clear();
    print_execution_result(&result, "Execution", global);

    Ok(())
}

fn print_execution_result(
    result: &artifact_keeper_sdk::types::PolicyExecutionResult,
    label: &str,
    global: &GlobalArgs,
) {
    let info = serde_json::json!({
        "policy_id": result.policy_id.to_string(),
        "policy_name": result.policy_name,
        "dry_run": result.dry_run,
        "artifacts_matched": result.artifacts_matched,
        "artifacts_removed": result.artifacts_removed,
        "bytes_freed": result.bytes_freed,
        "errors": result.errors,
    });

    if matches!(global.format, OutputFormat::Table) {
        eprintln!(
            "{} complete for policy '{}'{}:",
            label,
            result.policy_name,
            if result.dry_run { " (dry run)" } else { "" }
        );
        eprintln!("  Artifacts matched: {}", result.artifacts_matched);
        eprintln!("  Artifacts removed: {}", result.artifacts_removed);
        eprintln!("  Space freed:       {}", format_bytes(result.bytes_freed));
        if !result.errors.is_empty() {
            eprintln!("  Errors:");
            for err in &result.errors {
                eprintln!("    - {err}");
            }
        }
    } else {
        println!("{}", output::render(&info, &global.format, None));
    }
}
