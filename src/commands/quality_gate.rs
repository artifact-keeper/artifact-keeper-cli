use artifact_keeper_sdk::ClientQualityExt;
use clap::Subcommand;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use miette::{IntoDiagnostic, Result};

use super::client::client_for;
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum QualityGateCommand {
    /// List all quality gates
    List,

    /// Show quality gate details
    Show {
        /// Quality gate ID
        id: String,
    },

    /// Create a quality gate
    Create {
        /// Gate name
        name: String,

        /// Maximum critical issues allowed
        #[arg(long)]
        max_critical: Option<i32>,

        /// Maximum high issues allowed
        #[arg(long)]
        max_high: Option<i32>,

        /// Maximum medium issues allowed
        #[arg(long)]
        max_medium: Option<i32>,

        /// Enforcement action (allow, warn, block)
        #[arg(long)]
        action: Option<String>,

        /// Description
        #[arg(long)]
        description: Option<String>,

        /// Bind to a specific repository ID
        #[arg(long)]
        repo: Option<String>,

        /// Required checks (comma-separated)
        #[arg(long, value_delimiter = ',')]
        required_checks: Vec<String>,
    },

    /// Update a quality gate
    Update {
        /// Quality gate ID
        id: String,

        /// Gate name
        #[arg(long)]
        name: Option<String>,

        /// Maximum critical issues allowed
        #[arg(long)]
        max_critical: Option<i32>,

        /// Maximum high issues allowed
        #[arg(long)]
        max_high: Option<i32>,

        /// Enforcement action (allow, warn, block)
        #[arg(long)]
        action: Option<String>,

        /// Enable or disable
        #[arg(long)]
        enabled: Option<bool>,
    },

    /// Delete a quality gate
    Delete {
        /// Quality gate ID
        id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Check an artifact against quality gates
    Check {
        /// Artifact ID
        artifact: String,

        /// Repository ID (optional)
        #[arg(long)]
        repo: Option<String>,
    },
}

impl QualityGateCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List => list_gates(global).await,
            Self::Show { id } => show_gate(&id, global).await,
            Self::Create {
                name,
                max_critical,
                max_high,
                max_medium,
                action,
                description,
                repo,
                required_checks,
            } => {
                create_gate(
                    &name,
                    max_critical,
                    max_high,
                    max_medium,
                    action.as_deref(),
                    description.as_deref(),
                    repo.as_deref(),
                    required_checks,
                    global,
                )
                .await
            }
            Self::Update {
                id,
                name,
                max_critical,
                max_high,
                action,
                enabled,
            } => {
                update_gate(
                    &id,
                    name.as_deref(),
                    max_critical,
                    max_high,
                    action.as_deref(),
                    enabled,
                    global,
                )
                .await
            }
            Self::Delete { id, yes } => delete_gate(&id, yes, global).await,
            Self::Check { artifact, repo } => {
                check_artifact(&artifact, repo.as_deref(), global).await
            }
        }
    }
}

async fn list_gates(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching quality gates...");

    let gates = client
        .list_gates()
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to list quality gates: {e}")))?;

    let gates = gates.into_inner();
    spinner.finish_and_clear();

    if gates.is_empty() {
        eprintln!("No quality gates found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for g in &gates {
            println!("{}", g.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = gates
        .iter()
        .map(|g| {
            serde_json::json!({
                "id": g.id.to_string(),
                "name": g.name,
                "action": g.action,
                "enabled": g.is_enabled,
                "max_critical": g.max_critical_issues,
                "max_high": g.max_high_issues,
                "description": g.description,
            })
        })
        .collect();

    let table_str = {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                "ID", "NAME", "ACTION", "ENABLED", "MAX CRIT", "MAX HIGH",
            ]);

        for g in &gates {
            let id_short = &g.id.to_string()[..8];
            let enabled = if g.is_enabled { "yes" } else { "no" };
            let max_crit = g
                .max_critical_issues
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string());
            let max_high = g
                .max_high_issues
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string());
            table.add_row(vec![
                id_short, &g.name, &g.action, enabled, &max_crit, &max_high,
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

async fn show_gate(id: &str, global: &GlobalArgs) -> Result<()> {
    let gate_id: uuid::Uuid = id
        .parse()
        .map_err(|_| AkError::ConfigError(format!("Invalid quality gate ID: {id}")))?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching quality gate...");

    let gate = client
        .get_gate()
        .id(gate_id)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to get quality gate: {e}")))?;

    spinner.finish_and_clear();

    let info = serde_json::json!({
        "id": gate.id.to_string(),
        "name": gate.name,
        "description": gate.description,
        "action": gate.action,
        "enabled": gate.is_enabled,
        "max_critical_issues": gate.max_critical_issues,
        "max_high_issues": gate.max_high_issues,
        "max_medium_issues": gate.max_medium_issues,
        "min_health_score": gate.min_health_score,
        "min_quality_score": gate.min_quality_score,
        "min_security_score": gate.min_security_score,
        "required_checks": gate.required_checks,
        "enforce_on_download": gate.enforce_on_download,
        "enforce_on_promotion": gate.enforce_on_promotion,
        "repository_id": gate.repository_id.map(|u| u.to_string()),
    });

    let table_str = format!(
        "ID:                  {}\n\
         Name:                {}\n\
         Description:         {}\n\
         Action:              {}\n\
         Enabled:             {}\n\
         Max Critical:        {}\n\
         Max High:            {}\n\
         Max Medium:          {}\n\
         Min Health Score:    {}\n\
         Required Checks:     {}\n\
         Enforce on Download: {}\n\
         Enforce on Promote:  {}",
        gate.id,
        gate.name,
        gate.description.as_deref().unwrap_or("-"),
        gate.action,
        if gate.is_enabled { "yes" } else { "no" },
        gate.max_critical_issues
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string()),
        gate.max_high_issues
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string()),
        gate.max_medium_issues
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string()),
        gate.min_health_score
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string()),
        if gate.required_checks.is_empty() {
            "-".to_string()
        } else {
            gate.required_checks.join(", ")
        },
        if gate.enforce_on_download {
            "yes"
        } else {
            "no"
        },
        if gate.enforce_on_promotion {
            "yes"
        } else {
            "no"
        },
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn create_gate(
    name: &str,
    max_critical: Option<i32>,
    max_high: Option<i32>,
    max_medium: Option<i32>,
    action: Option<&str>,
    description: Option<&str>,
    repo_id: Option<&str>,
    required_checks: Vec<String>,
    global: &GlobalArgs,
) -> Result<()> {
    let repository_id = repo_id
        .map(|id| {
            id.parse::<uuid::Uuid>()
                .map_err(|_| AkError::ConfigError(format!("Invalid repository ID: {id}")))
        })
        .transpose()?;

    let client = client_for(global)?;
    let spinner = output::spinner("Creating quality gate...");

    let body = artifact_keeper_sdk::types::CreateGateRequest {
        name: name.to_string(),
        description: description.map(|s| s.to_string()),
        action: action.map(|s| s.to_string()),
        max_critical_issues: max_critical,
        max_high_issues: max_high,
        max_medium_issues: max_medium,
        min_health_score: None,
        min_metadata_score: None,
        min_quality_score: None,
        min_security_score: None,
        enforce_on_download: None,
        enforce_on_promotion: None,
        repository_id,
        required_checks,
    };

    let gate = client
        .create_gate()
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to create quality gate: {e}")))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", gate.id);
        return Ok(());
    }

    eprintln!("Quality gate '{}' created (ID: {}).", gate.name, gate.id);

    Ok(())
}

async fn update_gate(
    id: &str,
    name: Option<&str>,
    max_critical: Option<i32>,
    max_high: Option<i32>,
    action: Option<&str>,
    enabled: Option<bool>,
    global: &GlobalArgs,
) -> Result<()> {
    let gate_id: uuid::Uuid = id
        .parse()
        .map_err(|_| AkError::ConfigError(format!("Invalid quality gate ID: {id}")))?;

    let client = client_for(global)?;
    let spinner = output::spinner("Updating quality gate...");

    let body = artifact_keeper_sdk::types::UpdateGateRequest {
        name: name.map(|s| s.to_string()),
        action: action.map(|s| s.to_string()),
        max_critical_issues: max_critical,
        max_high_issues: max_high,
        max_medium_issues: None,
        is_enabled: enabled,
        description: None,
        enforce_on_download: None,
        enforce_on_promotion: None,
        min_health_score: None,
        min_metadata_score: None,
        min_quality_score: None,
        min_security_score: None,
        required_checks: None,
    };

    let gate = client
        .update_gate()
        .id(gate_id)
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to update quality gate: {e}")))?;

    spinner.finish_and_clear();
    eprintln!("Quality gate '{}' updated.", gate.name);

    Ok(())
}

async fn delete_gate(id: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    let gate_id: uuid::Uuid = id
        .parse()
        .map_err(|_| AkError::ConfigError(format!("Invalid quality gate ID: {id}")))?;

    let needs_confirmation = !skip_confirm && !global.no_input;
    if needs_confirmation {
        let confirmed = dialoguer::Confirm::new()
            .with_prompt(format!("Delete quality gate {id}?"))
            .default(false)
            .interact()
            .into_diagnostic()?;

        if !confirmed {
            eprintln!("Cancelled.");
            return Ok(());
        }
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Deleting quality gate...");

    client
        .delete_gate()
        .id(gate_id)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to delete quality gate: {e}")))?;

    spinner.finish_and_clear();
    eprintln!("Quality gate {id} deleted.");

    Ok(())
}

async fn check_artifact(
    artifact_id: &str,
    repo_id: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let aid: uuid::Uuid = artifact_id
        .parse()
        .map_err(|_| AkError::ConfigError(format!("Invalid artifact ID: {artifact_id}")))?;

    let client = client_for(global)?;
    let spinner = output::spinner("Evaluating quality gates...");

    let mut req = client.evaluate_gate().artifact_id(aid);
    if let Some(rid) = repo_id {
        let repo_uuid: uuid::Uuid = rid
            .parse()
            .map_err(|_| AkError::ConfigError(format!("Invalid repository ID: {rid}")))?;
        req = req.repository_id(repo_uuid);
    }

    let result = req
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to evaluate quality gates: {e}")))?;

    spinner.finish_and_clear();

    let info = serde_json::json!({
        "passed": result.passed,
        "gate_name": result.gate_name,
        "action": result.action,
        "health_score": result.health_score,
        "health_grade": result.health_grade,
        "violations": result.violations.iter().map(|v| {
            serde_json::json!({
                "rule": v.rule,
                "message": v.message,
                "expected": v.expected,
                "actual": v.actual,
            })
        }).collect::<Vec<_>>(),
    });

    if matches!(global.format, OutputFormat::Table) {
        if result.passed {
            eprintln!(
                "PASSED: Gate '{}' (score: {}, grade: {})",
                result.gate_name, result.health_score, result.health_grade
            );
        } else {
            eprintln!(
                "FAILED: Gate '{}' (action: {}, score: {}, grade: {})",
                result.gate_name, result.action, result.health_score, result.health_grade
            );
            if !result.violations.is_empty() {
                eprintln!("Violations:");
                for v in &result.violations {
                    eprintln!(
                        "  - {}: {} (expected: {}, actual: {})",
                        v.rule, v.message, v.expected, v.actual
                    );
                }
            }
        }
    } else {
        println!("{}", output::render(&info, &global.format, None));
    }

    if !result.passed {
        std::process::exit(1);
    }

    Ok(())
}
