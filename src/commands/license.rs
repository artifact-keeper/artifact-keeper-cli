use artifact_keeper_sdk::ClientSbomExt;
use clap::Subcommand;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use miette::Result;

use super::client::client_for;
use super::helpers::{confirm_action, parse_optional_uuid, parse_uuid};
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum LicenseCommand {
    /// Manage license policies
    #[command(subcommand)]
    Policy(PolicyCommand),

    /// Check license compliance against active policies
    Check {
        /// SPDX license identifiers to check (comma-separated)
        #[arg(long, value_delimiter = ',')]
        licenses: Vec<String>,

        /// Scope check to a specific repository
        #[arg(long)]
        repo: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum PolicyCommand {
    /// List all license policies
    List,

    /// Show license policy details
    Show {
        /// Policy ID
        id: String,
    },

    /// Create a license policy
    Create {
        /// Policy name
        name: String,

        /// Allowed SPDX license identifiers (comma-separated)
        #[arg(long, value_delimiter = ',')]
        allowed: Vec<String>,

        /// Denied SPDX license identifiers (comma-separated)
        #[arg(long, value_delimiter = ',')]
        denied: Vec<String>,

        /// Allow artifacts with unknown licenses
        #[arg(long)]
        allow_unknown: bool,

        /// Enforcement action (allow, warn, block)
        #[arg(long)]
        action: Option<String>,

        /// Policy description
        #[arg(long)]
        description: Option<String>,

        /// Enable policy on creation (default: true)
        #[arg(long)]
        enabled: Option<bool>,

        /// Bind to a specific repository ID
        #[arg(long)]
        repo: Option<String>,
    },

    /// Delete a license policy
    Delete {
        /// Policy ID
        id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}

impl LicenseCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Policy(cmd) => cmd.execute(global).await,
            Self::Check { licenses, repo } => {
                check_compliance(licenses, repo.as_deref(), global).await
            }
        }
    }
}

impl PolicyCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List => list_policies(global).await,
            Self::Show { id } => show_policy(&id, global).await,
            Self::Create {
                name,
                allowed,
                denied,
                allow_unknown,
                action,
                description,
                enabled,
                repo,
            } => {
                create_policy(
                    &name,
                    allowed,
                    denied,
                    allow_unknown,
                    action.as_deref(),
                    description.as_deref(),
                    enabled,
                    repo.as_deref(),
                    global,
                )
                .await
            }
            Self::Delete { id, yes } => delete_policy(&id, yes, global).await,
        }
    }
}

async fn list_policies(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching license policies...");

    let policies = client
        .list_license_policies()
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to list license policies: {e}")))?;

    let policies = policies.into_inner();
    spinner.finish_and_clear();

    if policies.is_empty() {
        eprintln!("No license policies found.");
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
                "action": p.action,
                "allow_unknown": p.allow_unknown,
                "enabled": p.is_enabled,
                "allowed_licenses": p.allowed_licenses,
                "denied_licenses": p.denied_licenses,
            })
        })
        .collect();

    let table_str = {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                "ID",
                "NAME",
                "ACTION",
                "ALLOW UNKNOWN",
                "ENABLED",
                "ALLOWED",
                "DENIED",
            ]);

        for p in &policies {
            let id_short = &p.id.to_string()[..8];
            let enabled = if p.is_enabled { "yes" } else { "no" };
            let allow_unknown = if p.allow_unknown { "yes" } else { "no" };
            let allowed = if p.allowed_licenses.is_empty() {
                "-".to_string()
            } else {
                p.allowed_licenses.join(", ")
            };
            let denied = if p.denied_licenses.is_empty() {
                "-".to_string()
            } else {
                p.denied_licenses.join(", ")
            };
            table.add_row(vec![
                id_short,
                &p.name,
                &p.action,
                allow_unknown,
                enabled,
                &allowed,
                &denied,
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
    let policy_id = parse_uuid(id, "license policy")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching license policy...");

    let policy = client
        .get_license_policy()
        .id(policy_id)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to get license policy: {e}")))?;

    spinner.finish_and_clear();

    let info = serde_json::json!({
        "id": policy.id.to_string(),
        "name": policy.name,
        "description": policy.description,
        "action": policy.action,
        "enabled": policy.is_enabled,
        "allow_unknown": policy.allow_unknown,
        "allowed_licenses": policy.allowed_licenses,
        "denied_licenses": policy.denied_licenses,
        "repository_id": policy.repository_id.map(|u| u.to_string()),
        "created_at": policy.created_at.to_rfc3339(),
        "updated_at": policy.updated_at.map(|u| u.to_rfc3339()),
    });

    let allowed = if policy.allowed_licenses.is_empty() {
        "-".to_string()
    } else {
        policy.allowed_licenses.join(", ")
    };
    let denied = if policy.denied_licenses.is_empty() {
        "-".to_string()
    } else {
        policy.denied_licenses.join(", ")
    };

    let table_str = format!(
        "ID:            {}\n\
         Name:          {}\n\
         Description:   {}\n\
         Action:        {}\n\
         Enabled:       {}\n\
         Allow Unknown: {}\n\
         Allowed:       {}\n\
         Denied:        {}\n\
         Repository:    {}\n\
         Created:       {}",
        policy.id,
        policy.name,
        policy.description.as_deref().unwrap_or("-"),
        policy.action,
        if policy.is_enabled { "yes" } else { "no" },
        if policy.allow_unknown { "yes" } else { "no" },
        allowed,
        denied,
        policy
            .repository_id
            .map(|u| u.to_string())
            .unwrap_or_else(|| "global".to_string()),
        policy.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn create_policy(
    name: &str,
    allowed: Vec<String>,
    denied: Vec<String>,
    allow_unknown: bool,
    action: Option<&str>,
    description: Option<&str>,
    enabled: Option<bool>,
    repo_id: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let repository_id = parse_optional_uuid(repo_id, "repository")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Creating license policy...");

    let body = artifact_keeper_sdk::types::UpsertLicensePolicyRequest {
        name: name.to_string(),
        allowed_licenses: allowed,
        denied_licenses: denied,
        allow_unknown: Some(allow_unknown),
        action: action.map(|s| s.to_string()),
        description: description.map(|s| s.to_string()),
        is_enabled: enabled,
        repository_id,
    };

    let policy = client
        .upsert_license_policy()
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to create license policy: {e}")))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", policy.id);
        return Ok(());
    }

    eprintln!(
        "License policy '{}' created (ID: {}).",
        policy.name, policy.id
    );

    Ok(())
}

async fn delete_policy(id: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    let policy_id = parse_uuid(id, "license policy")?;

    if !confirm_action(
        &format!("Delete license policy {id}?"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Deleting license policy...");

    client
        .delete_license_policy()
        .id(policy_id)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to delete license policy: {e}")))?;

    spinner.finish_and_clear();
    eprintln!("License policy {id} deleted.");

    Ok(())
}

async fn check_compliance(
    licenses: Vec<String>,
    repo_id: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let repository_id = parse_optional_uuid(repo_id, "repository")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Checking license compliance...");

    let body = artifact_keeper_sdk::types::CheckLicenseComplianceRequest {
        licenses,
        repository_id,
    };

    let result = client
        .check_license_compliance()
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to check license compliance: {e}")))?;

    let result = result.into_inner();
    spinner.finish_and_clear();

    let info = serde_json::json!({
        "compliant": result.compliant,
        "violations": result.violations,
        "warnings": result.warnings,
    });

    if matches!(global.format, OutputFormat::Table) {
        if result.compliant {
            eprintln!("COMPLIANT: All licenses pass policy checks.");
        } else {
            eprintln!("NON-COMPLIANT: License policy violations detected.");
            if !result.violations.is_empty() {
                eprintln!("Violations:");
                for v in &result.violations {
                    eprintln!("  - {v}");
                }
            }
            if !result.warnings.is_empty() {
                eprintln!("Warnings:");
                for w in &result.warnings {
                    eprintln!("  - {w}");
                }
            }
        }
    } else {
        println!("{}", output::render(&info, &global.format, None));
    }

    if !result.compliant {
        std::process::exit(1);
    }

    Ok(())
}
