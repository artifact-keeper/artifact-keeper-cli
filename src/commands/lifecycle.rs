use artifact_keeper_sdk::ClientLifecycleExt;
use clap::Subcommand;
use miette::Result;

use super::client::client_for;
use super::helpers::{
    confirm_action, emit_mutation, emit_mutation_raw, new_table, parse_uuid,
    refuse_flags_before_1_11, sdk_err, short_id, since_1_11, since_1_11_any_status,
};
use super::helpers::{resolve_optional_repo_id, resolve_repo_id};
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat, format_bytes};

#[derive(Subcommand)]
pub enum LifecycleCommand {
    /// List lifecycle policies
    List {
        /// Filter by repository key or ID
        #[arg(long)]
        repo: Option<String>,
    },

    /// Show lifecycle policy details
    Show {
        /// Policy ID
        id: String,
    },

    /// Create a lifecycle policy. Say what it applies to with --repo or --all-repos.
    /// Unless it's --disabled, it's live at once, and the server's scheduler can start
    /// deleting within about a minute, with or without a --cron-schedule
    Create {
        /// Policy name
        name: String,

        /// Policy type. One of: max_age_days, max_versions, no_downloads_days,
        /// tag_pattern_keep, tag_pattern_delete, size_quota_bytes
        #[arg(long)]
        policy_type: String,

        /// Policy configuration as a JSON object. Required keys by type:
        /// max_age_days / no_downloads_days => {"days": N};
        /// max_versions => {"keep": N};
        /// size_quota_bytes => {"quota_bytes": N};
        /// tag_pattern_keep / tag_pattern_delete => {"pattern": "<regex>"}
        #[arg(long)]
        config: String,

        /// Policy description
        #[arg(long)]
        description: Option<String>,

        /// Priority (higher priority policies run first)
        #[arg(long)]
        priority: Option<i32>,

        /// Apply to one repository key or ID
        #[arg(long, conflicts_with = "all_repos")]
        repo: Option<String>,

        /// Apply to these repository keys or IDs, comma-separated. Needs a 1.11
        /// server
        #[arg(long, value_delimiter = ',', conflicts_with_all = ["repo", "all_repos"])]
        repos: Vec<String>,

        /// Apply to every repository. A 1.10 server refuses this for max_versions
        /// and size_quota_bytes, which there need --repo
        #[arg(long)]
        all_repos: bool,

        /// Create it disabled, so nothing runs until `lifecycle update <id> --enabled`.
        /// `lifecycle preview` still works, to see what it would delete. Needs a 1.11
        /// server: 1.10 ignores this and would create a live policy, so it's refused
        #[arg(long)]
        disabled: bool,

        /// Cron schedule for automatic execution (e.g. "0 2 * * *")
        #[arg(long)]
        cron_schedule: Option<String>,
    },

    /// Update a lifecycle policy (only provided fields are changed)
    Update {
        /// Policy ID
        id: String,

        /// New policy name
        #[arg(long)]
        name: Option<String>,

        /// Enable the policy
        #[arg(long, conflicts_with = "disabled")]
        enabled: bool,

        /// Disable the policy
        #[arg(long, conflicts_with = "enabled")]
        disabled: bool,

        /// New priority (higher priority policies run first)
        #[arg(long)]
        priority: Option<i32>,

        /// New description
        #[arg(long)]
        description: Option<String>,

        /// New policy configuration as a JSON object (see `create` for shape)
        #[arg(long)]
        config: Option<String>,

        /// New cron schedule for automatic execution (e.g. "0 2 * * *")
        #[arg(long)]
        cron_schedule: Option<String>,

        /// Apply to exactly these repository keys or IDs, comma-separated, or to
        /// none with an empty value (--repos ''). Needs a 1.11 server
        #[arg(long, value_delimiter = ',')]
        repos: Option<Vec<String>>,

        /// Apply to every repository (true), or stop doing so (false). Needs a 1.11
        /// server
        #[arg(long)]
        all_repos: Option<bool>,
    },

    /// Delete a lifecycle policy
    Delete {
        /// Policy ID
        id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Execute all enabled policies now
    ExecuteAll,

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

    /// Add a repository to what a policy applies to. Needs a 1.11 server
    Attach {
        /// Policy ID
        id: String,

        /// Repository key or ID
        repo: String,
    },

    /// Remove a repository from what a policy applies to. Needs a 1.11 server
    Detach {
        /// Policy ID
        id: String,

        /// Repository key or ID
        repo: String,
    },

    /// Show what this server's lifecycle API can do. Needs a 1.11 server
    Capabilities,
}

impl LifecycleCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List { repo } => list_policies(repo.as_deref(), global).await,
            Self::Show { id } => show_policy(&id, global).await,
            Self::Create {
                name,
                policy_type,
                config,
                description,
                priority,
                repo,
                repos,
                all_repos,
                disabled,
                cron_schedule,
            } => {
                create_policy(
                    &name,
                    &policy_type,
                    &config,
                    description.as_deref(),
                    priority,
                    repo.as_deref(),
                    &repos,
                    all_repos,
                    disabled,
                    cron_schedule.as_deref(),
                    global,
                )
                .await
            }
            Self::Update {
                id,
                name,
                enabled,
                disabled,
                priority,
                description,
                config,
                cron_schedule,
                repos,
                all_repos,
            } => {
                update_policy(
                    &id,
                    name.as_deref(),
                    enabled,
                    disabled,
                    priority,
                    description.as_deref(),
                    config.as_deref(),
                    cron_schedule.as_deref(),
                    repos.as_deref(),
                    all_repos,
                    global,
                )
                .await
            }
            Self::Delete { id, yes } => delete_policy(&id, yes, global).await,
            Self::ExecuteAll => execute_all_policies(global).await,
            Self::Preview { id } => preview_policy(&id, global).await,
            Self::Execute { id } => execute_policy(&id, global).await,
            Self::Attach { id, repo } => change_scope(&id, &repo, true, global).await,
            Self::Detach { id, repo } => change_scope(&id, &repo, false, global).await,
            Self::Capabilities => capabilities(global).await,
        }
    }
}

async fn list_policies(repo_id: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching lifecycle policies...");

    let mut req = client.list_lifecycle_policies();
    if let Some(id) = repo_id {
        let uid = resolve_repo_id(&client, id).await?;
        req = req.repository_id(uid);
    }

    let (policies, raw) = artifact_keeper_sdk::raw::capture(req.send()).await;
    let policies = policies.map_err(|e| sdk_err("list lifecycle policies", e))?;

    let policies = policies.into_inner();
    spinner.finish_and_clear();

    if policies.is_empty() && !output::is_machine_format(&global.format) {
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
                "applies_to_all": p.applies_to_all,
                "repository_ids": p.repository_ids,
                "last_run_at": p.last_run_at.map(|t| t.to_rfc3339()),
                "last_run_items_removed": p.last_run_items_removed,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec![
            "ID", "NAME", "TYPE", "SCOPE", "ENABLED", "PRIORITY", "LAST RUN",
        ]);

        for p in &policies {
            let id_short = short_id(&p.id);
            let enabled = if p.enabled { "yes" } else { "no" };
            let last_run = p
                .last_run_at
                .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| "-".to_string());
            table.add_row(vec![
                &id_short,
                &p.name,
                &p.policy_type,
                &policy_scope(p),
                enabled,
                &p.priority.to_string(),
                &last_run,
            ]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render_raw(raw.as_deref(), &entries, &global.format, Some(table_str))
    );

    Ok(())
}

/// What a policy applies to. Since backend 1.11, a policy with no repository is
/// dormant unless `applies_to_all` is set. A 1.10 server sends neither field, and
/// there a policy with no `repository_id` is global.
fn policy_scope(policy: &artifact_keeper_sdk::types::LifecyclePolicy) -> String {
    let Some(applies_to_all) = policy.applies_to_all else {
        return policy
            .repository_id
            .map_or_else(|| "all repositories".to_string(), |id| id.to_string());
    };
    if applies_to_all {
        return "all repositories".to_string();
    }
    if policy.repository_ids.is_empty() {
        return "none (dormant)".to_string();
    }
    policy
        .repository_ids
        .iter()
        .map(|id| id.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

async fn show_policy(id: &str, global: &GlobalArgs) -> Result<()> {
    let policy_id = parse_uuid(id, "policy")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching lifecycle policy...");

    let (policy, raw) =
        artifact_keeper_sdk::raw::capture(client.get_lifecycle_policy().id(policy_id).send()).await;
    let policy = policy.map_err(|e| sdk_err("get lifecycle policy", e))?;

    spinner.finish_and_clear();

    let info = serde_json::json!({
        "id": policy.id.to_string(),
        "name": policy.name,
        "policy_type": policy.policy_type,
        "enabled": policy.enabled,
        "priority": policy.priority,
        "description": policy.description,
        "config": policy.config,
        "applies_to_all": policy.applies_to_all,
        "repository_ids": policy.repository_ids,
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
         Scope:           {}\n\
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
        policy_scope(&policy),
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

    println!(
        "{}",
        output::render_raw(raw.as_deref(), &info, &global.format, Some(table_str))
    );

    Ok(())
}

/// Valid lifecycle policy types accepted by the backend
/// (`POST /api/v1/admin/lifecycle`).
const VALID_POLICY_TYPES: &[&str] = &[
    "max_age_days",
    "max_versions",
    "no_downloads_days",
    "tag_pattern_keep",
    "tag_pattern_delete",
    "size_quota_bytes",
];

#[allow(clippy::too_many_arguments)]
async fn create_policy(
    name: &str,
    policy_type: &str,
    config: &str,
    description: Option<&str>,
    priority: Option<i32>,
    repo_id: Option<&str>,
    repos: &[String],
    all_repos: bool,
    disabled: bool,
    cron_schedule: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    // A policy is live once it's created and it deletes, so its reach has to be
    // asked for, not assumed from a flag that was left off.
    if repo_id.is_none() && repos.is_empty() && !all_repos {
        return Err(AkError::ConfigError(
            "say what this policy applies to: --repo <key> for one repository, --repos for \
             several, or --all-repos for every repository. Unless it's --disabled, it's live \
             as soon as it's created"
                .to_string(),
        )
        .into());
    }

    let client = client_for(global)?;
    if !VALID_POLICY_TYPES.contains(&policy_type) {
        return Err(AkError::ConfigError(format!(
            "Invalid policy type '{policy_type}'. Must be one of: {}",
            VALID_POLICY_TYPES.join(", ")
        ))
        .into());
    }

    let config_map = parse_config(config)?;
    let repository_id = resolve_optional_repo_id(&client, repo_id).await?;
    // A 1.10 server ignores `repository_ids`, and there a policy with no repository
    // deletes across every repository. So it mustn't get as far as being sent.
    if !repos.is_empty() {
        refuse_flags_before_1_11(&["--repos"], global).await?;
    }
    let repository_ids = resolve_repos(&client, repos).await?;

    // A 1.10 server ignores `enabled`, and the policy it then creates is live.
    if disabled {
        refuse_flags_before_1_11(&["--disabled"], global).await?;
    }

    let body = artifact_keeper_sdk::types::CreateLifecyclePolicyRequest {
        // 1.11 needs this for a global policy: with no repository and no
        // `applies_to_all`, it creates a dormant one that never deletes anything.
        // 1.10 ignores the field, and there no repository means every repository.
        applies_to_all: all_repos.then_some(true),
        config: config_map,
        cron_schedule: cron_schedule.map(str::to_string),
        description: description.map(str::to_string),
        enabled: disabled.then_some(false),
        name: name.to_string(),
        policy_type: policy_type.to_string(),
        priority,
        // The legacy single field, because it works on both supported minors:
        // 1.10 ignores `repository_ids` and would create a policy for every
        // repository, and 1.11 stores this as a one-element `repository_ids`.
        repository_id,
        repository_ids: (!repository_ids.is_empty()).then_some(repository_ids),
    };

    let spinner = output::spinner("Creating lifecycle policy...");

    let (resp, raw) =
        artifact_keeper_sdk::raw::capture(client.create_lifecycle_policy().body(body).send()).await;
    let resp = resp.map_err(|e| sdk_err("create lifecycle policy", e))?;

    spinner.finish_and_clear();

    let policy = resp.into_inner();
    let id = policy.id.to_string();

    // The version check can't tell if the server's version couldn't be read. A
    // policy that's live when it was asked not to be mustn't stay.
    if disabled && policy.enabled {
        let outcome = match client.delete_lifecycle_policy().id(policy.id).send().await {
            Ok(_) => "so it was deleted again".to_string(),
            Err(e) => format!(
                "and it couldn't be deleted ({e}). IT IS LIVE: run `ak lifecycle delete {id} --yes`"
            ),
        };
        return Err(AkError::ServerError(format!(
            "The server ignored --disabled and created an enabled policy, {outcome}"
        ))
        .into());
    }

    emit_mutation_raw(
        raw.as_deref(),
        &policy,
        &id,
        &format!(
            "Lifecycle policy '{}' created (ID: {id}, scope: {}, {}).",
            policy.name,
            policy_scope(&policy),
            if policy.enabled {
                "enabled"
            } else {
                "disabled"
            }
        ),
        global,
    );

    Ok(())
}

/// The IDs of repositories given by key or ID.
async fn resolve_repos(
    client: &artifact_keeper_sdk::Client,
    repos: &[String],
) -> Result<Vec<uuid::Uuid>> {
    let mut ids = Vec::with_capacity(repos.len());
    for repo in repos {
        ids.push(resolve_repo_id(client, repo).await?);
    }
    Ok(ids)
}

/// Parse a `--config` value, which must be a JSON object.
fn parse_config(config: &str) -> Result<serde_json::Map<String, serde_json::Value>> {
    let value: serde_json::Value = serde_json::from_str(config)
        .map_err(|e| AkError::ConfigError(format!("--config must be a JSON object: {e}")))?;
    match value {
        serde_json::Value::Object(map) => Ok(map),
        _ => Err(AkError::ConfigError("--config must be a JSON object".into()).into()),
    }
}

#[allow(clippy::too_many_arguments)]
async fn update_policy(
    id: &str,
    name: Option<&str>,
    enabled: bool,
    disabled: bool,
    priority: Option<i32>,
    description: Option<&str>,
    config: Option<&str>,
    cron_schedule: Option<&str>,
    repos: Option<&[String]>,
    all_repos: Option<bool>,
    global: &GlobalArgs,
) -> Result<()> {
    let policy_id = parse_uuid(id, "policy")?;

    // `--enabled` / `--disabled` are mutually exclusive (enforced by clap); only
    // send the field when one was explicitly given.
    let enabled_field = if enabled {
        Some(true)
    } else if disabled {
        Some(false)
    } else {
        None
    };

    let config_field = config.map(parse_config).transpose()?;

    if name.is_none()
        && enabled_field.is_none()
        && priority.is_none()
        && description.is_none()
        && config_field.is_none()
        && cron_schedule.is_none()
        && repos.is_none()
        && all_repos.is_none()
    {
        return Err(AkError::ConfigError(
            "No fields to update; provide at least one of --name/--enabled/--disabled/--priority/--description/--config/--cron-schedule/--repos/--all-repos".into(),
        )
        .into());
    }

    let client = client_for(global)?;
    let mut scope_flags = Vec::new();
    if repos.is_some() {
        scope_flags.push("--repos");
    }
    if all_repos.is_some() {
        scope_flags.push("--all-repos");
    }
    refuse_flags_before_1_11(&scope_flags, global).await?;
    let repository_ids = match repos {
        Some(repos) => {
            let repos: Vec<String> = repos.iter().filter(|r| !r.is_empty()).cloned().collect();
            Some(resolve_repos(&client, &repos).await?)
        }
        None => None,
    };

    let body = artifact_keeper_sdk::types::UpdateLifecyclePolicyRequest {
        applies_to_all: all_repos,
        config: config_field,
        cron_schedule: cron_schedule.map(str::to_string),
        description: description.map(str::to_string),
        enabled: enabled_field,
        name: name.map(str::to_string),
        priority,
        repository_ids,
    };

    let spinner = output::spinner("Updating lifecycle policy...");

    let (resp, raw) = artifact_keeper_sdk::raw::capture(
        client
            .update_lifecycle_policy()
            .id(policy_id)
            .body(body)
            .send(),
    )
    .await;
    let resp = resp.map_err(|e| sdk_err("update lifecycle policy", e))?;

    spinner.finish_and_clear();

    let policy = resp.into_inner();

    emit_mutation_raw(
        raw.as_deref(),
        &policy,
        id,
        &format!("Lifecycle policy '{}' updated (ID: {id}).", policy.name),
        global,
    );

    Ok(())
}

async fn execute_all_policies(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Executing all policies...");

    let (results, raw) =
        artifact_keeper_sdk::raw::capture(client.execute_all_policies().send()).await;
    let results = results
        .map_err(|e| sdk_err("execute all policies", e))?
        .into_inner();

    spinner.finish_and_clear();

    if results.is_empty() && !output::is_machine_format(&global.format) {
        eprintln!("No policies were executed.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Table) {
        eprintln!("Executed {} policy/policies:", results.len());
        for result in &results {
            print_execution_result(result, None, "Execution", global);
        }
    } else {
        let entries: Vec<_> = results
            .iter()
            .map(|r| {
                serde_json::json!({
                    "policy_id": r.policy_id.to_string(),
                    "policy_name": r.policy_name,
                    "dry_run": r.dry_run,
                    "artifacts_matched": r.artifacts_matched,
                    "artifacts_removed": r.artifacts_removed,
                    "bytes_freed": r.bytes_freed,
                    "errors": r.errors,
                })
            })
            .collect();
        println!(
            "{}",
            output::render_raw(raw.as_deref(), &entries, &global.format, None)
        );
    }

    Ok(())
}

async fn delete_policy(id: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    let policy_id = parse_uuid(id, "policy")?;

    if !confirm_action(
        &format!("Delete lifecycle policy {id}?"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Deleting lifecycle policy...");

    client
        .delete_lifecycle_policy()
        .id(policy_id)
        .send()
        .await
        .map_err(|e| sdk_err("delete lifecycle policy", e))?;

    spinner.finish_and_clear();
    emit_mutation(
        &serde_json::json!({ "id": id, "deleted": true }),
        id,
        &format!("Lifecycle policy {id} deleted."),
        global,
    );

    Ok(())
}

async fn preview_policy(id: &str, global: &GlobalArgs) -> Result<()> {
    let policy_id = parse_uuid(id, "policy")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Previewing policy execution...");

    let (result, raw) =
        artifact_keeper_sdk::raw::capture(client.preview_policy().id(policy_id).send()).await;
    let result = result.map_err(|e| sdk_err("preview policy", e))?;

    spinner.finish_and_clear();
    print_execution_result(&result, raw.as_deref(), "Preview", global);

    Ok(())
}

async fn execute_policy(id: &str, global: &GlobalArgs) -> Result<()> {
    let policy_id = parse_uuid(id, "policy")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Executing policy...");

    let (result, raw) =
        artifact_keeper_sdk::raw::capture(client.execute_policy().id(policy_id).send()).await;
    let result = result.map_err(|e| sdk_err("execute policy", e))?;

    spinner.finish_and_clear();
    print_execution_result(&result, raw.as_deref(), "Execution", global);

    Ok(())
}

/// Add a repository to a policy's scope, or remove it.
async fn change_scope(id: &str, repo: &str, attach: bool, global: &GlobalArgs) -> Result<()> {
    let policy_id = parse_uuid(id, "policy")?;
    let client = client_for(global)?;
    let repository_id = resolve_repo_id(&client, repo).await?;
    let spinner = output::spinner("Changing what the policy applies to...");
    let (policy, raw) = if attach {
        let req = client
            .attach_lifecycle_repository()
            .id(policy_id)
            .repository_id(repository_id);
        artifact_keeper_sdk::raw::capture(req.send()).await
    } else {
        let req = client
            .detach_lifecycle_repository()
            .id(policy_id)
            .repository_id(repository_id);
        artifact_keeper_sdk::raw::capture(req.send()).await
    };
    spinner.finish_and_clear();
    let policy = match policy {
        Ok(policy) => policy.into_inner(),
        Err(e) => {
            let (action, command) = if attach {
                ("attach repository", "lifecycle attach")
            } else {
                ("detach repository", "lifecycle detach")
            };
            return Err(since_1_11(e, action, command, global).await.into());
        }
    };
    emit_mutation_raw(
        raw.as_deref(),
        &policy,
        id,
        &format!(
            "Policy '{}' now applies to: {}.",
            policy.name,
            policy_scope(&policy)
        ),
        global,
    );
    Ok(())
}

async fn capabilities(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let (resp, raw) =
        artifact_keeper_sdk::raw::capture(client.get_lifecycle_capabilities().send()).await;
    let resp = match resp {
        Ok(resp) => resp.into_inner(),
        Err(e) => {
            let action = "get lifecycle capabilities";
            return Err(
                since_1_11_any_status(e, action, "lifecycle capabilities", global)
                    .await
                    .into(),
            );
        }
    };
    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", resp.explicit_repository_assignment);
        return Ok(());
    }
    let table = format!(
        "Explicit repository assignment: {}",
        if resp.explicit_repository_assignment {
            "yes"
        } else {
            "no"
        }
    );
    println!(
        "{}",
        output::render_raw(raw.as_deref(), &resp, &global.format, Some(table))
    );
    Ok(())
}

fn print_execution_result(
    result: &artifact_keeper_sdk::types::PolicyExecutionResult,
    raw: Option<&[u8]>,
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
        println!("{}", output::render_raw(raw, &info, &global.format, None));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use serde_json::json;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: LifecycleCommand,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).unwrap()
    }

    fn try_parse(args: &[&str]) -> Result<TestCli, clap::Error> {
        TestCli::try_parse_from(args)
    }

    // ---- parsing: list ----

    #[test]
    fn parse_list_no_filter() {
        let cli = parse(&["test", "list"]);
        match cli.command {
            LifecycleCommand::List { repo } => {
                assert!(repo.is_none());
            }
            _ => panic!("expected List"),
        }
    }

    #[test]
    fn parse_list_with_repo() {
        let cli = parse(&["test", "list", "--repo", "some-repo-id"]);
        match cli.command {
            LifecycleCommand::List { repo } => {
                assert_eq!(repo.as_deref(), Some("some-repo-id"));
            }
            _ => panic!("expected List"),
        }
    }

    // ---- parsing: show ----

    #[test]
    fn parse_show() {
        let cli = parse(&["test", "show", "policy-id"]);
        match cli.command {
            LifecycleCommand::Show { id } => {
                assert_eq!(id, "policy-id");
            }
            _ => panic!("expected Show"),
        }
    }

    #[test]
    fn parse_show_missing_id() {
        let result = try_parse(&["test", "show"]);
        assert!(result.is_err());
    }

    // ---- parsing: create ----

    #[test]
    fn parse_create_minimal() {
        let cli = parse(&[
            "test",
            "create",
            "retention-policy",
            "--policy-type",
            "max_age_days",
            "--config",
            "{\"days\": 90}",
        ]);
        match cli.command {
            LifecycleCommand::Create {
                name,
                policy_type,
                config,
                description,
                priority,
                repo,
                all_repos,
                disabled,
                cron_schedule,
                ..
            } => {
                assert_eq!(name, "retention-policy");
                assert_eq!(policy_type, "max_age_days");
                assert_eq!(config, "{\"days\": 90}");
                assert!(description.is_none());
                assert!(priority.is_none());
                assert!(repo.is_none());
                assert!(!all_repos);
                assert!(!disabled);
                assert!(cron_schedule.is_none());
            }
            _ => panic!("expected Create"),
        }
    }

    #[test]
    fn parse_create_all_options() {
        let cli = parse(&[
            "test",
            "create",
            "strict-policy",
            "--policy-type",
            "max_versions",
            "--config",
            "{\"keep\": 5}",
            "--description",
            "keep latest 5",
            "--priority",
            "10",
            "--repo",
            "repo-id",
            "--cron-schedule",
            "0 2 * * *",
        ]);
        match cli.command {
            LifecycleCommand::Create {
                name,
                policy_type,
                config,
                description,
                priority,
                repo,
                all_repos,
                disabled,
                cron_schedule,
                ..
            } => {
                assert_eq!(name, "strict-policy");
                assert_eq!(policy_type, "max_versions");
                assert_eq!(config, "{\"keep\": 5}");
                assert_eq!(description.as_deref(), Some("keep latest 5"));
                assert_eq!(priority, Some(10));
                assert_eq!(repo.as_deref(), Some("repo-id"));
                assert!(!all_repos);
                assert!(!disabled);
                assert_eq!(cron_schedule.as_deref(), Some("0 2 * * *"));
            }
            _ => panic!("expected Create"),
        }
    }

    #[test]
    fn parse_create_all_repos_conflicts_with_repo() {
        let args = [
            "test",
            "create",
            "p",
            "--policy-type",
            "max_age_days",
            "--config",
            "{}",
            "--repo",
            "r",
            "--all-repos",
        ];
        let err = try_parse(&args).err().expect("should conflict");
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn parse_create_missing_name() {
        let result = try_parse(&[
            "test",
            "create",
            "--policy-type",
            "max_age_days",
            "--config",
            "{\"days\": 90}",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_create_missing_policy_type() {
        let result = try_parse(&["test", "create", "policy-name", "--config", "{}"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_create_missing_config() {
        let result = try_parse(&[
            "test",
            "create",
            "policy-name",
            "--policy-type",
            "max_age_days",
        ]);
        assert!(result.is_err());
    }

    // ---- parsing: update ----

    #[test]
    fn parse_update_name_only() {
        let cli = parse(&["test", "update", "policy-id", "--name", "renamed"]);
        match cli.command {
            LifecycleCommand::Update {
                id,
                name,
                enabled,
                disabled,
                priority,
                description,
                config,
                cron_schedule,
                ..
            } => {
                assert_eq!(id, "policy-id");
                assert_eq!(name.as_deref(), Some("renamed"));
                assert!(!enabled);
                assert!(!disabled);
                assert!(priority.is_none());
                assert!(description.is_none());
                assert!(config.is_none());
                assert!(cron_schedule.is_none());
            }
            _ => panic!("expected Update"),
        }
    }

    #[test]
    fn parse_update_all_fields() {
        let cli = parse(&[
            "test",
            "update",
            "policy-id",
            "--name",
            "renamed",
            "--disabled",
            "--priority",
            "9",
            "--description",
            "desc",
            "--config",
            "{\"days\": 60}",
            "--cron-schedule",
            "0 2 * * *",
        ]);
        match cli.command {
            LifecycleCommand::Update {
                name,
                enabled,
                disabled,
                priority,
                description,
                config,
                cron_schedule,
                ..
            } => {
                assert_eq!(name.as_deref(), Some("renamed"));
                assert!(!enabled);
                assert!(disabled);
                assert_eq!(priority, Some(9));
                assert_eq!(description.as_deref(), Some("desc"));
                assert_eq!(config.as_deref(), Some("{\"days\": 60}"));
                assert_eq!(cron_schedule.as_deref(), Some("0 2 * * *"));
            }
            _ => panic!("expected Update"),
        }
    }

    #[test]
    fn parse_update_enabled_disabled_conflict() {
        let result = try_parse(&["test", "update", "policy-id", "--enabled", "--disabled"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_update_missing_id() {
        let result = try_parse(&["test", "update"]);
        assert!(result.is_err());
    }

    // ---- parsing: execute-all ----

    #[test]
    fn parse_execute_all() {
        let cli = parse(&["test", "execute-all"]);
        assert!(matches!(cli.command, LifecycleCommand::ExecuteAll));
    }

    // ---- parsing: delete ----

    #[test]
    fn parse_delete_no_yes() {
        let cli = parse(&["test", "delete", "policy-id"]);
        match cli.command {
            LifecycleCommand::Delete { id, yes } => {
                assert_eq!(id, "policy-id");
                assert!(!yes);
            }
            _ => panic!("expected Delete"),
        }
    }

    #[test]
    fn parse_delete_with_yes() {
        let cli = parse(&["test", "delete", "policy-id", "--yes"]);
        match cli.command {
            LifecycleCommand::Delete { yes, .. } => {
                assert!(yes);
            }
            _ => panic!("expected Delete"),
        }
    }

    #[test]
    fn parse_delete_missing_id() {
        let result = try_parse(&["test", "delete"]);
        assert!(result.is_err());
    }

    // ---- parsing: preview ----

    #[test]
    fn parse_preview() {
        let cli = parse(&["test", "preview", "policy-id"]);
        match cli.command {
            LifecycleCommand::Preview { id } => {
                assert_eq!(id, "policy-id");
            }
            _ => panic!("expected Preview"),
        }
    }

    #[test]
    fn parse_preview_missing_id() {
        let result = try_parse(&["test", "preview"]);
        assert!(result.is_err());
    }

    // ---- parsing: execute ----

    #[test]
    fn parse_execute() {
        let cli = parse(&["test", "execute", "policy-id"]);
        match cli.command {
            LifecycleCommand::Execute { id } => {
                assert_eq!(id, "policy-id");
            }
            _ => panic!("expected Execute"),
        }
    }

    #[test]
    fn parse_execute_missing_id() {
        let result = try_parse(&["test", "execute"]);
        assert!(result.is_err());
    }

    // ---- format functions ----

    // ---- wiremock handler tests ----

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    static NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

    fn policy_with(scope: serde_json::Value) -> artifact_keeper_sdk::types::LifecyclePolicy {
        let mut policy = lifecycle_policy_json();
        policy.as_object_mut().unwrap().remove("applies_to_all");
        policy.as_object_mut().unwrap().remove("repository_ids");
        for (key, value) in scope.as_object().unwrap() {
            policy[key] = value.clone();
        }
        serde_json::from_value(policy).unwrap()
    }

    #[test]
    fn policy_scope_describes_each_case() {
        const ID: &str = "00000000-0000-0000-0000-000000000009";
        let scope = |value| policy_scope(&policy_with(value));

        assert_eq!(
            scope(json!({ "applies_to_all": true, "repository_ids": [] })),
            "all repositories"
        );
        assert_eq!(
            scope(json!({ "applies_to_all": false, "repository_ids": [] })),
            "none (dormant)"
        );
        assert_eq!(
            scope(json!({ "applies_to_all": false, "repository_ids": [ID] })),
            ID
        );
        // A 1.10 server sends neither field.
        assert_eq!(scope(json!({ "repository_id": null })), "all repositories");
        assert_eq!(scope(json!({ "repository_id": ID })), ID);
    }

    #[tokio::test]
    async fn handler_create_policy_all_repos_sends_applies_to_all() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/admin/lifecycle"))
            .and(wiremock::matchers::body_partial_json(
                json!({ "applies_to_all": true }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(lifecycle_policy_json()))
            .expect(1)
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = create_policy(
            "p",
            "max_age_days",
            r#"{"days":30}"#,
            None,
            None,
            None,
            &[],
            true,
            false,
            None,
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    /// Create with `--disabled` against a mock on this server version, answering
    /// with this `enabled`.
    async fn create_disabled(
        version: &str,
        answer_enabled: bool,
        expected_posts: u64,
        expected_deletes: u64,
    ) -> Result<()> {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "version": version })))
            .mount(&server)
            .await;
        let mut policy = lifecycle_policy_json();
        policy["enabled"] = json!(answer_enabled);
        Mock::given(method("POST"))
            .and(path("/api/v1/admin/lifecycle"))
            .and(wiremock::matchers::body_partial_json(
                json!({ "enabled": false }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(policy))
            .expect(expected_posts)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/admin/lifecycle/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .expect(expected_deletes)
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = create_policy(
            "p",
            "max_age_days",
            r#"{"days":30}"#,
            None,
            None,
            None,
            &[],
            true,
            true,
            None,
            &global,
        )
        .await;
        server.verify().await;
        crate::test_utils::teardown_env();
        result
    }

    #[tokio::test]
    async fn create_disabled_sends_enabled_false() {
        assert!(create_disabled("1.11.10", false, 1, 0).await.is_ok());
    }

    #[tokio::test]
    async fn create_disabled_is_refused_before_1_11_with_nothing_sent() {
        let err = create_disabled("1.10.2", true, 0, 0).await.unwrap_err();
        assert!(err.to_string().contains("--disabled"), "{err}");
    }

    #[tokio::test]
    async fn create_disabled_deletes_a_policy_that_came_back_enabled() {
        let err = create_disabled("1.11.10", true, 1, 1).await.unwrap_err();
        assert!(err.to_string().contains("deleted again"), "{err}");
    }

    #[tokio::test]
    async fn handler_create_policy_with_no_scope_sends_nothing() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(lifecycle_policy_json()))
            .expect(0)
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let err = create_policy(
            "p",
            "max_age_days",
            r#"{"days":30}"#,
            None,
            None,
            None,
            &[],
            false,
            false,
            None,
            &global,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("--repo"), "{err}");
        assert!(err.contains("--all-repos"), "{err}");
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_create_policy_with_repo_sends_legacy_repository_id() {
        const ID: &str = "00000000-0000-0000-0000-000000000009";
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/admin/lifecycle"))
            .and(wiremock::matchers::body_json(json!({
                "config": { "days": 30 },
                "name": "p",
                "policy_type": "max_age_days",
                "repository_id": ID,
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(lifecycle_policy_json()))
            .expect(1)
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = create_policy(
            "p",
            "max_age_days",
            r#"{"days":30}"#,
            None,
            None,
            Some(ID),
            &[],
            false,
            false,
            None,
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    fn lifecycle_policy_json() -> serde_json::Value {
        json!({
            "id": NIL_UUID,
            "name": "cleanup-old",
            "policy_type": "retention",
            "enabled": true,
            "priority": 10,
            "description": "Remove old artifacts",
            "config": {},
            "repository_id": null,
            "last_run_at": null,
            "last_run_items_removed": null,
            "created_at": "2026-01-15T12:00:00Z",
            "updated_at": "2026-01-15T12:00:00Z",
            "applies_to_all": true,
            "repository_ids": []
        })
    }

    fn execution_result_json() -> serde_json::Value {
        json!({
            "policy_id": NIL_UUID,
            "policy_name": "cleanup-old",
            "dry_run": false,
            "artifacts_matched": 10,
            "artifacts_removed": 5,
            "bytes_freed": 1048576_i64,
            "errors": [],
            "bytes_matched": 2097152_i64,
            "proxy_cache": {"entries_matched": 0, "entries_removed": 0, "bytes_matched": 0, "bytes_freed": 0}
        })
    }

    #[tokio::test]
    async fn handler_list_policies_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/admin/lifecycle"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_policies(None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_policies_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/admin/lifecycle"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!([lifecycle_policy_json()])),
            )
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_policies(None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_policies_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/admin/lifecycle"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!([lifecycle_policy_json()])),
            )
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = list_policies(None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_policy() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/admin/lifecycle/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(lifecycle_policy_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = show_policy(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_create_policy_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/admin/lifecycle"))
            .respond_with(ResponseTemplate::new(200).set_body_json(lifecycle_policy_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = create_policy(
            "cleanup-old",
            "max_age_days",
            "{\"days\": 90}",
            None,
            None,
            None,
            &[],
            true,
            false,
            None,
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_create_policy_json() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/admin/lifecycle"))
            .respond_with(ResponseTemplate::new(200).set_body_json(lifecycle_policy_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = create_policy(
            "cleanup-old",
            "max_age_days",
            "{\"days\": 90}",
            Some("desc"),
            Some(5),
            None,
            &[],
            true,
            false,
            None,
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_create_policy_invalid_type() {
        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = create_policy(
            "bad",
            "not_a_type",
            "{}",
            None,
            None,
            None,
            &[],
            true,
            false,
            None,
            &global,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handler_create_policy_invalid_config() {
        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = create_policy(
            "bad",
            "max_age_days",
            "not-json",
            None,
            None,
            None,
            &[],
            true,
            false,
            None,
            &global,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handler_delete_policy() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/admin/lifecycle/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = delete_policy(NIL_UUID, true, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_update_policy_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/admin/lifecycle/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(lifecycle_policy_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = update_policy(
            NIL_UUID,
            Some("renamed"),
            false,
            true,
            Some(5),
            None,
            None,
            None,
            None,
            None,
            &global,
        )
        .await;
        assert!(result.is_ok(), "update failed: {:?}", result.err());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_update_policy_no_fields() {
        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = update_policy(
            NIL_UUID, None, false, false, None, None, None, None, None, None, &global,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handler_update_policy_invalid_config() {
        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = update_policy(
            NIL_UUID,
            None,
            false,
            false,
            None,
            None,
            Some("not-json"),
            None,
            None,
            None,
            &global,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handler_execute_all_policies() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/admin/lifecycle/execute-all"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!([execution_result_json()])),
            )
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = execute_all_policies(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_execute_all_policies_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/admin/lifecycle/execute-all"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Table);
        let result = execute_all_policies(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_preview_policy() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!("/api/v1/admin/lifecycle/{NIL_UUID}/preview")))
            .respond_with(ResponseTemplate::new(200).set_body_json(execution_result_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = preview_policy(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_execute_policy() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!("/api/v1/admin/lifecycle/{NIL_UUID}/execute")))
            .respond_with(ResponseTemplate::new(200).set_body_json(execution_result_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = execute_policy(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    // ---- insta snapshot tests ----

    #[test]
    fn snapshot_lifecycle_list_json() {
        let items = vec![lifecycle_policy_json()];
        let output = crate::output::render(&items, &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("lifecycle_list_json", parsed);
    }
}
