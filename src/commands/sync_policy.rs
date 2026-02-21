use artifact_keeper_sdk::ClientPeersExt;
use artifact_keeper_sdk::types::{
    CreateSyncPolicyPayload, EvaluationResultResponse, PreviewPolicyPayload, PreviewResultResponse,
    SyncPolicyResponse, TogglePolicyPayload, UpdateSyncPolicyPayload,
};
use clap::Subcommand;
use miette::{Result, miette};
use serde_json::Value;

use super::client::client_for;
use super::helpers::{confirm_action, new_table, parse_uuid, sdk_err, short_id};
use crate::cli::GlobalArgs;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum SyncPolicyCommand {
    /// List all sync policies
    List,

    /// Show sync policy details
    Show {
        /// Policy ID
        id: String,
    },

    /// Create a new sync policy
    Create {
        /// Policy name
        name: String,

        /// Replication mode (push, pull, or mirror)
        #[arg(long)]
        mode: Option<String>,

        /// Description of the policy
        #[arg(long)]
        description: Option<String>,

        /// Priority (higher values evaluated first)
        #[arg(long)]
        priority: Option<i32>,

        /// Whether the policy is enabled at creation
        #[arg(long)]
        enabled: Option<bool>,

        /// Repository selector as JSON object
        #[arg(long, value_name = "JSON")]
        repo_selector: Option<String>,

        /// Peer selector as JSON object
        #[arg(long, value_name = "JSON")]
        peer_selector: Option<String>,

        /// Artifact filter as JSON object
        #[arg(long, value_name = "JSON")]
        artifact_filter: Option<String>,
    },

    /// Update an existing sync policy
    Update {
        /// Policy ID
        id: String,

        /// New policy name
        #[arg(long)]
        name: Option<String>,

        /// Replication mode (push, pull, or mirror)
        #[arg(long)]
        mode: Option<String>,

        /// New description
        #[arg(long)]
        description: Option<String>,

        /// New priority
        #[arg(long)]
        priority: Option<i32>,
    },

    /// Delete a sync policy
    Delete {
        /// Policy ID
        id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Enable or disable a sync policy
    Toggle {
        /// Policy ID
        id: String,

        /// Enable the policy
        #[arg(long, conflicts_with = "disable")]
        enable: bool,

        /// Disable the policy
        #[arg(long, conflicts_with = "enable")]
        disable: bool,
    },

    /// Force re-evaluate all sync policies
    Evaluate,

    /// Preview which repositories and peers a policy would match
    Preview {
        /// Policy name for the preview
        #[arg(long, default_value = "preview")]
        name: Option<String>,

        /// Repository selector as JSON object
        #[arg(long, value_name = "JSON")]
        repo_selector: Option<String>,

        /// Peer selector as JSON object
        #[arg(long, value_name = "JSON")]
        peer_selector: Option<String>,

        /// Artifact filter as JSON object
        #[arg(long, value_name = "JSON")]
        artifact_filter: Option<String>,
    },
}

impl SyncPolicyCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List => list_policies(global).await,
            Self::Show { id } => show_policy(&id, global).await,
            Self::Create {
                name,
                mode,
                description,
                priority,
                enabled,
                repo_selector,
                peer_selector,
                artifact_filter,
            } => {
                create_policy(
                    &name,
                    mode.as_deref(),
                    description.as_deref(),
                    priority,
                    enabled,
                    repo_selector.as_deref(),
                    peer_selector.as_deref(),
                    artifact_filter.as_deref(),
                    global,
                )
                .await
            }
            Self::Update {
                id,
                name,
                mode,
                description,
                priority,
            } => {
                update_policy(
                    &id,
                    name.as_deref(),
                    mode.as_deref(),
                    description.as_deref(),
                    priority,
                    global,
                )
                .await
            }
            Self::Delete { id, yes } => delete_policy(&id, yes, global).await,
            Self::Toggle {
                id,
                enable,
                disable,
            } => toggle_policy(&id, enable, disable, global).await,
            Self::Evaluate => evaluate_policies(global).await,
            Self::Preview {
                name,
                repo_selector,
                peer_selector,
                artifact_filter,
            } => {
                preview_policy(
                    name.as_deref(),
                    repo_selector.as_deref(),
                    peer_selector.as_deref(),
                    artifact_filter.as_deref(),
                    global,
                )
                .await
            }
        }
    }
}

// ---------------------------------------------------------------------------
// JSON map parsing helper
// ---------------------------------------------------------------------------

fn parse_json_map(input: Option<&str>) -> Result<serde_json::Map<String, serde_json::Value>> {
    match input {
        None => Ok(serde_json::Map::new()),
        Some(s) => {
            let v: serde_json::Value =
                serde_json::from_str(s).map_err(|e| miette!("Invalid JSON: {e}"))?;
            match v {
                serde_json::Value::Object(map) => Ok(map),
                _ => Err(miette!("Expected a JSON object, got: {}", v)),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Command handlers
// ---------------------------------------------------------------------------

async fn list_policies(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching sync policies...");

    let resp = client
        .list_sync_policies()
        .send()
        .await
        .map_err(|e| sdk_err("list sync policies", e))?;

    let list = resp.into_inner();
    spinner.finish_and_clear();

    if list.items.is_empty() {
        eprintln!("No sync policies found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for p in &list.items {
            println!("{}", p.id);
        }
        return Ok(());
    }

    let (entries, table_str) = format_policies_table(&list.items);
    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn show_policy(id: &str, global: &GlobalArgs) -> Result<()> {
    let policy_id = parse_uuid(id, "sync policy")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching sync policy...");

    let policy = client
        .get_sync_policy()
        .id(policy_id)
        .send()
        .await
        .map_err(|e| sdk_err("get sync policy", e))?;

    spinner.finish_and_clear();

    let (info, table_str) = format_policy_detail(&policy);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn create_policy(
    name: &str,
    mode: Option<&str>,
    description: Option<&str>,
    priority: Option<i32>,
    enabled: Option<bool>,
    repo_selector: Option<&str>,
    peer_selector: Option<&str>,
    artifact_filter: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let repo_sel = parse_json_map(repo_selector)?;
    let peer_sel = parse_json_map(peer_selector)?;
    let art_filter = parse_json_map(artifact_filter)?;

    let client = client_for(global)?;
    let spinner = output::spinner("Creating sync policy...");

    let body = CreateSyncPolicyPayload {
        name: name.to_string(),
        replication_mode: mode.map(|m| m.to_string()),
        description: description.map(|d| d.to_string()),
        priority,
        precedence: None,
        enabled,
        repo_selector: repo_sel,
        peer_selector: peer_sel,
        artifact_filter: art_filter,
    };

    let policy = client
        .create_sync_policy()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("create sync policy", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", policy.id);
        return Ok(());
    }

    eprintln!("Sync policy '{}' created (ID: {}).", policy.name, policy.id);

    Ok(())
}

async fn update_policy(
    id: &str,
    name: Option<&str>,
    mode: Option<&str>,
    description: Option<&str>,
    priority: Option<i32>,
    global: &GlobalArgs,
) -> Result<()> {
    let policy_id = parse_uuid(id, "sync policy")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Updating sync policy...");

    let body = UpdateSyncPolicyPayload {
        name: name.map(|n| n.to_string()),
        replication_mode: mode.map(|m| m.to_string()),
        description: description.map(|d| d.to_string()),
        priority,
        precedence: None,
        enabled: None,
        repo_selector: serde_json::Map::new(),
        peer_selector: serde_json::Map::new(),
        artifact_filter: serde_json::Map::new(),
    };

    let policy = client
        .update_sync_policy()
        .id(policy_id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("update sync policy", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", policy.id);
        return Ok(());
    }

    eprintln!("Sync policy '{}' updated.", policy.name);

    Ok(())
}

async fn delete_policy(id: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    let policy_id = parse_uuid(id, "sync policy")?;

    if !confirm_action(
        &format!("Delete sync policy {id}?"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Deleting sync policy...");

    client
        .delete_sync_policy()
        .id(policy_id)
        .send()
        .await
        .map_err(|e| sdk_err("delete sync policy", e))?;

    spinner.finish_and_clear();
    eprintln!("Sync policy {id} deleted.");

    Ok(())
}

async fn toggle_policy(id: &str, enable: bool, disable: bool, global: &GlobalArgs) -> Result<()> {
    if !enable && !disable {
        return Err(miette!(
            "Specify either --enable or --disable to toggle the policy."
        ));
    }

    let policy_id = parse_uuid(id, "sync policy")?;
    let enabled = enable;

    let client = client_for(global)?;
    let action = if enabled { "Enabling" } else { "Disabling" };
    let spinner = output::spinner(&format!("{action} sync policy..."));

    let body = TogglePolicyPayload { enabled };

    let policy = client
        .toggle_policy()
        .id(policy_id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("toggle sync policy", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", policy.enabled);
        return Ok(());
    }

    let state = if policy.enabled {
        "enabled"
    } else {
        "disabled"
    };
    eprintln!("Sync policy '{}' {state}.", policy.name);

    Ok(())
}

async fn evaluate_policies(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Evaluating sync policies...");

    let result = client
        .evaluate_policies()
        .send()
        .await
        .map_err(|e| sdk_err("evaluate sync policies", e))?;

    let result = result.into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", result.policies_evaluated);
        return Ok(());
    }

    let (info, table_str) = format_evaluation_result(&result);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn preview_policy(
    name: Option<&str>,
    repo_selector: Option<&str>,
    peer_selector: Option<&str>,
    artifact_filter: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let repo_sel = parse_json_map(repo_selector)?;
    let peer_sel = parse_json_map(peer_selector)?;
    let art_filter = parse_json_map(artifact_filter)?;

    let client = client_for(global)?;
    let spinner = output::spinner("Previewing sync policy...");

    let body = PreviewPolicyPayload {
        name: name.unwrap_or("preview").to_string(),
        replication_mode: None,
        description: None,
        priority: None,
        precedence: None,
        enabled: None,
        repo_selector: repo_sel,
        peer_selector: peer_sel,
        artifact_filter: art_filter,
    };

    let result = client
        .preview_sync_policy()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("preview sync policy", e))?;

    let result = result.into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", result.subscription_count);
        return Ok(());
    }

    let (info, table_str) = format_preview_result(&result);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

// ---------------------------------------------------------------------------
// Formatting helpers (pure functions, testable without HTTP)
// ---------------------------------------------------------------------------

fn format_policies_table(policies: &[SyncPolicyResponse]) -> (Vec<Value>, String) {
    let entries: Vec<_> = policies
        .iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id.to_string(),
                "name": p.name,
                "replication_mode": p.replication_mode,
                "enabled": p.enabled,
                "priority": p.priority,
                "description": p.description,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec![
            "ID",
            "NAME",
            "MODE",
            "ENABLED",
            "PRIORITY",
            "DESCRIPTION",
        ]);

        for p in policies {
            let id_short = short_id(&p.id);
            let enabled = if p.enabled { "yes" } else { "no" };
            let priority = p.priority.to_string();
            let desc = if p.description.len() > 40 {
                format!("{}...", &p.description[..37])
            } else {
                p.description.clone()
            };
            table.add_row(vec![
                &id_short,
                &p.name,
                &p.replication_mode,
                enabled,
                &priority,
                &desc,
            ]);
        }

        table.to_string()
    };

    (entries, table_str)
}

fn format_policy_detail(policy: &SyncPolicyResponse) -> (Value, String) {
    let info = serde_json::json!({
        "id": policy.id.to_string(),
        "name": policy.name,
        "description": policy.description,
        "replication_mode": policy.replication_mode,
        "enabled": policy.enabled,
        "priority": policy.priority,
        "precedence": policy.precedence,
        "repo_selector": policy.repo_selector,
        "peer_selector": policy.peer_selector,
        "artifact_filter": policy.artifact_filter,
        "created_at": policy.created_at.to_rfc3339(),
        "updated_at": policy.updated_at.to_rfc3339(),
    });

    let repo_sel = serde_json::to_string(&policy.repo_selector).unwrap_or_default();
    let peer_sel = serde_json::to_string(&policy.peer_selector).unwrap_or_default();
    let art_filter = serde_json::to_string(&policy.artifact_filter).unwrap_or_default();

    let table_str = format!(
        "ID:              {}\n\
         Name:            {}\n\
         Description:     {}\n\
         Mode:            {}\n\
         Enabled:         {}\n\
         Priority:        {}\n\
         Precedence:      {}\n\
         Repo Selector:   {}\n\
         Peer Selector:   {}\n\
         Artifact Filter: {}\n\
         Created:         {}\n\
         Updated:         {}",
        policy.id,
        policy.name,
        if policy.description.is_empty() {
            "-"
        } else {
            &policy.description
        },
        policy.replication_mode,
        if policy.enabled { "yes" } else { "no" },
        policy.priority,
        policy.precedence,
        if repo_sel == "{}" { "-" } else { &repo_sel },
        if peer_sel == "{}" { "-" } else { &peer_sel },
        if art_filter == "{}" { "-" } else { &art_filter },
        policy.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
        policy.updated_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    (info, table_str)
}

fn format_evaluation_result(result: &EvaluationResultResponse) -> (Value, String) {
    let info = serde_json::json!({
        "policies_evaluated": result.policies_evaluated,
        "created": result.created,
        "updated": result.updated,
        "removed": result.removed,
    });

    let table_str = format!(
        "Policies Evaluated: {}\n\
         Subscriptions Created: {}\n\
         Subscriptions Updated: {}\n\
         Subscriptions Removed: {}",
        result.policies_evaluated, result.created, result.updated, result.removed,
    );

    (info, table_str)
}

fn format_preview_result(result: &PreviewResultResponse) -> (Value, String) {
    let peers: Vec<_> = result
        .matched_peers
        .iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id.to_string(),
                "name": p.name,
                "region": p.region.as_deref().unwrap_or("-"),
            })
        })
        .collect();

    let repos: Vec<_> = result
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

    let info = serde_json::json!({
        "subscription_count": result.subscription_count,
        "matched_peers": peers,
        "matched_repositories": repos,
    });

    let mut parts = vec![format!(
        "Subscriptions: {}\n\
         Matched Peers: {}\n\
         Matched Repositories: {}",
        result.subscription_count,
        result.matched_peers.len(),
        result.matched_repositories.len(),
    )];

    if !result.matched_peers.is_empty() {
        let mut table = new_table(vec!["PEER ID", "PEER NAME", "REGION"]);
        for p in &result.matched_peers {
            let id_short = short_id(&p.id);
            let region = p.region.as_deref().unwrap_or("-");
            table.add_row(vec![&id_short, &p.name, region]);
        }
        parts.push(format!("\nMatched Peers:\n{table}"));
    }

    if !result.matched_repositories.is_empty() {
        let mut table = new_table(vec!["REPO ID", "KEY", "FORMAT"]);
        for r in &result.matched_repositories {
            let id_short = short_id(&r.id);
            table.add_row(vec![&id_short, &r.key, &r.format]);
        }
        parts.push(format!("\nMatched Repositories:\n{table}"));
    }

    let table_str = parts.join("\n");

    (info, table_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use artifact_keeper_sdk::types::{MatchedPeerSchema, MatchedRepoSchema};
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: SyncPolicyCommand,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).unwrap()
    }

    fn try_parse(args: &[&str]) -> std::result::Result<TestCli, clap::Error> {
        TestCli::try_parse_from(args)
    }

    // ---- Parsing tests ----

    #[test]
    fn parse_list() {
        let cli = parse(&["test", "list"]);
        assert!(matches!(cli.command, SyncPolicyCommand::List));
    }

    #[test]
    fn parse_show() {
        let cli = parse(&["test", "show", "policy-id"]);
        if let SyncPolicyCommand::Show { id } = cli.command {
            assert_eq!(id, "policy-id");
        } else {
            panic!("Expected Show");
        }
    }

    #[test]
    fn parse_show_missing_id() {
        let result = try_parse(&["test", "show"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_create_minimal() {
        let cli = parse(&["test", "create", "my-policy"]);
        if let SyncPolicyCommand::Create {
            name,
            mode,
            description,
            priority,
            enabled,
            repo_selector,
            peer_selector,
            artifact_filter,
        } = cli.command
        {
            assert_eq!(name, "my-policy");
            assert!(mode.is_none());
            assert!(description.is_none());
            assert!(priority.is_none());
            assert!(enabled.is_none());
            assert!(repo_selector.is_none());
            assert!(peer_selector.is_none());
            assert!(artifact_filter.is_none());
        } else {
            panic!("Expected Create");
        }
    }

    #[test]
    fn parse_create_with_mode() {
        let cli = parse(&["test", "create", "my-policy", "--mode", "push"]);
        if let SyncPolicyCommand::Create { name, mode, .. } = cli.command {
            assert_eq!(name, "my-policy");
            assert_eq!(mode.unwrap(), "push");
        } else {
            panic!("Expected Create with mode");
        }
    }

    #[test]
    fn parse_create_full() {
        let cli = parse(&[
            "test",
            "create",
            "my-policy",
            "--mode",
            "mirror",
            "--description",
            "Full replication",
            "--priority",
            "10",
            "--enabled",
            "true",
            "--repo-selector",
            r#"{"match_keys":["npm-*"]}"#,
            "--peer-selector",
            r#"{"regions":["us-east-1"]}"#,
            "--artifact-filter",
            r#"{"formats":["npm"]}"#,
        ]);
        if let SyncPolicyCommand::Create {
            name,
            mode,
            description,
            priority,
            enabled,
            repo_selector,
            peer_selector,
            artifact_filter,
        } = cli.command
        {
            assert_eq!(name, "my-policy");
            assert_eq!(mode.unwrap(), "mirror");
            assert_eq!(description.unwrap(), "Full replication");
            assert_eq!(priority.unwrap(), 10);
            assert_eq!(enabled.unwrap(), true);
            assert!(repo_selector.is_some());
            assert!(peer_selector.is_some());
            assert!(artifact_filter.is_some());
        } else {
            panic!("Expected Create with full args");
        }
    }

    #[test]
    fn parse_create_missing_name() {
        let result = try_parse(&["test", "create"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_update_minimal() {
        let cli = parse(&["test", "update", "policy-id"]);
        if let SyncPolicyCommand::Update {
            id,
            name,
            mode,
            description,
            priority,
        } = cli.command
        {
            assert_eq!(id, "policy-id");
            assert!(name.is_none());
            assert!(mode.is_none());
            assert!(description.is_none());
            assert!(priority.is_none());
        } else {
            panic!("Expected Update");
        }
    }

    #[test]
    fn parse_update_with_all_options() {
        let cli = parse(&[
            "test",
            "update",
            "policy-id",
            "--name",
            "new-name",
            "--mode",
            "pull",
            "--description",
            "Updated desc",
            "--priority",
            "20",
        ]);
        if let SyncPolicyCommand::Update {
            id,
            name,
            mode,
            description,
            priority,
        } = cli.command
        {
            assert_eq!(id, "policy-id");
            assert_eq!(name.unwrap(), "new-name");
            assert_eq!(mode.unwrap(), "pull");
            assert_eq!(description.unwrap(), "Updated desc");
            assert_eq!(priority.unwrap(), 20);
        } else {
            panic!("Expected Update with options");
        }
    }

    #[test]
    fn parse_update_missing_id() {
        let result = try_parse(&["test", "update"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_delete() {
        let cli = parse(&["test", "delete", "policy-id"]);
        if let SyncPolicyCommand::Delete { id, yes } = cli.command {
            assert_eq!(id, "policy-id");
            assert!(!yes);
        } else {
            panic!("Expected Delete");
        }
    }

    #[test]
    fn parse_delete_with_yes() {
        let cli = parse(&["test", "delete", "policy-id", "--yes"]);
        if let SyncPolicyCommand::Delete { id, yes } = cli.command {
            assert_eq!(id, "policy-id");
            assert!(yes);
        } else {
            panic!("Expected Delete with --yes");
        }
    }

    #[test]
    fn parse_delete_missing_id() {
        let result = try_parse(&["test", "delete"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_toggle_enable() {
        let cli = parse(&["test", "toggle", "policy-id", "--enable"]);
        if let SyncPolicyCommand::Toggle {
            id,
            enable,
            disable,
        } = cli.command
        {
            assert_eq!(id, "policy-id");
            assert!(enable);
            assert!(!disable);
        } else {
            panic!("Expected Toggle with --enable");
        }
    }

    #[test]
    fn parse_toggle_disable() {
        let cli = parse(&["test", "toggle", "policy-id", "--disable"]);
        if let SyncPolicyCommand::Toggle {
            id,
            enable,
            disable,
        } = cli.command
        {
            assert_eq!(id, "policy-id");
            assert!(!enable);
            assert!(disable);
        } else {
            panic!("Expected Toggle with --disable");
        }
    }

    #[test]
    fn parse_toggle_conflicts() {
        let result = try_parse(&["test", "toggle", "policy-id", "--enable", "--disable"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_toggle_missing_id() {
        let result = try_parse(&["test", "toggle"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_evaluate() {
        let cli = parse(&["test", "evaluate"]);
        assert!(matches!(cli.command, SyncPolicyCommand::Evaluate));
    }

    #[test]
    fn parse_preview_no_args() {
        let cli = parse(&["test", "preview"]);
        if let SyncPolicyCommand::Preview {
            repo_selector,
            peer_selector,
            artifact_filter,
            ..
        } = cli.command
        {
            assert!(repo_selector.is_none());
            assert!(peer_selector.is_none());
            assert!(artifact_filter.is_none());
        } else {
            panic!("Expected Preview");
        }
    }

    #[test]
    fn parse_preview_with_selectors() {
        let cli = parse(&[
            "test",
            "preview",
            "--repo-selector",
            r#"{"match_keys":["npm-*"]}"#,
            "--peer-selector",
            r#"{"regions":["us-east-1"]}"#,
        ]);
        if let SyncPolicyCommand::Preview {
            repo_selector,
            peer_selector,
            ..
        } = cli.command
        {
            assert!(repo_selector.is_some());
            assert!(peer_selector.is_some());
        } else {
            panic!("Expected Preview with selectors");
        }
    }

    // ---- parse_json_map tests ----

    #[test]
    fn parse_json_map_none() {
        let result = parse_json_map(None).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn parse_json_map_empty_object() {
        let result = parse_json_map(Some("{}")).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn parse_json_map_with_keys() {
        let result = parse_json_map(Some(r#"{"match_keys":["npm-*"]}"#)).unwrap();
        assert!(result.contains_key("match_keys"));
    }

    #[test]
    fn parse_json_map_invalid_json() {
        let result = parse_json_map(Some("not json"));
        assert!(result.is_err());
    }

    #[test]
    fn parse_json_map_non_object() {
        let result = parse_json_map(Some("[1,2,3]"));
        assert!(result.is_err());
    }

    #[test]
    fn parse_json_map_string_value() {
        let result = parse_json_map(Some(r#""hello""#));
        assert!(result.is_err());
    }

    #[test]
    fn parse_json_map_nested_object() {
        let result = parse_json_map(Some(r#"{"filter":{"type":"npm","pattern":"*"}}"#)).unwrap();
        assert!(result.contains_key("filter"));
    }

    // ---- Format function tests ----

    use chrono::Utc;
    use uuid::Uuid;

    fn make_test_policy(name: &str, mode: &str, enabled: bool) -> SyncPolicyResponse {
        SyncPolicyResponse {
            id: Uuid::nil(),
            name: name.to_string(),
            description: "Test policy description".to_string(),
            replication_mode: mode.to_string(),
            enabled,
            priority: 10,
            precedence: 1,
            repo_selector: serde_json::Map::new(),
            peer_selector: serde_json::Map::new(),
            artifact_filter: serde_json::Map::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn make_test_eval_result() -> EvaluationResultResponse {
        EvaluationResultResponse {
            policies_evaluated: 5,
            created: 3,
            updated: 1,
            removed: 0,
        }
    }

    fn make_test_preview_result() -> PreviewResultResponse {
        PreviewResultResponse {
            subscription_count: 2,
            matched_peers: vec![MatchedPeerSchema {
                id: Uuid::nil(),
                name: "test-peer".to_string(),
                region: Some("us-east-1".to_string()),
            }],
            matched_repositories: vec![MatchedRepoSchema {
                id: Uuid::nil(),
                key: "npm-releases".to_string(),
                format: "npm".to_string(),
            }],
        }
    }

    // ---- format_policies_table ----

    #[test]
    fn format_policies_table_single() {
        let policies = vec![make_test_policy("my-policy", "push", true)];
        let (entries, table_str) = format_policies_table(&policies);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["name"], "my-policy");
        assert_eq!(entries[0]["replication_mode"], "push");
        assert_eq!(entries[0]["enabled"], true);

        assert!(table_str.contains("NAME"));
        assert!(table_str.contains("MODE"));
        assert!(table_str.contains("my-policy"));
        assert!(table_str.contains("push"));
        assert!(table_str.contains("yes"));
    }

    #[test]
    fn format_policies_table_multiple() {
        let policies = vec![
            make_test_policy("policy-a", "push", true),
            make_test_policy("policy-b", "pull", false),
        ];
        let (entries, table_str) = format_policies_table(&policies);

        assert_eq!(entries.len(), 2);
        assert!(table_str.contains("policy-a"));
        assert!(table_str.contains("policy-b"));
        assert!(table_str.contains("push"));
        assert!(table_str.contains("pull"));
    }

    #[test]
    fn format_policies_table_empty() {
        let (entries, table_str) = format_policies_table(&[]);
        assert!(entries.is_empty());
        assert!(table_str.contains("NAME"));
    }

    #[test]
    fn format_policies_table_disabled() {
        let policies = vec![make_test_policy("disabled-policy", "mirror", false)];
        let (entries, table_str) = format_policies_table(&policies);

        assert_eq!(entries[0]["enabled"], false);
        assert!(table_str.contains("no"));
    }

    #[test]
    fn format_policies_table_long_description() {
        let mut policy = make_test_policy("desc-policy", "push", true);
        policy.description =
            "This is a really long description that should be truncated in the table view"
                .to_string();
        let (_, table_str) = format_policies_table(&[policy]);

        assert!(table_str.contains("..."));
    }

    // ---- format_policy_detail ----

    #[test]
    fn format_policy_detail_full() {
        let policy = make_test_policy("detail-policy", "push", true);
        let (info, table_str) = format_policy_detail(&policy);

        assert_eq!(info["name"], "detail-policy");
        assert_eq!(info["replication_mode"], "push");
        assert_eq!(info["enabled"], true);
        assert_eq!(info["priority"], 10);
        assert_eq!(info["precedence"], 1);

        assert!(table_str.contains("detail-policy"));
        assert!(table_str.contains("push"));
        assert!(table_str.contains("yes"));
        assert!(table_str.contains("10"));
    }

    #[test]
    fn format_policy_detail_disabled() {
        let policy = make_test_policy("disabled", "pull", false);
        let (info, table_str) = format_policy_detail(&policy);

        assert_eq!(info["enabled"], false);
        assert!(table_str.contains("no"));
    }

    #[test]
    fn format_policy_detail_empty_description() {
        let mut policy = make_test_policy("no-desc", "push", true);
        policy.description = String::new();
        let (_, table_str) = format_policy_detail(&policy);

        assert!(table_str.contains("Description:     -"));
    }

    #[test]
    fn format_policy_detail_with_selectors() {
        let mut policy = make_test_policy("sel-policy", "mirror", true);
        policy
            .repo_selector
            .insert("match_keys".to_string(), serde_json::json!(["npm-*"]));
        let (info, table_str) = format_policy_detail(&policy);

        // repo_selector should be in the JSON info
        assert!(info["repo_selector"].is_object());
        // and in the table output (not just "-")
        assert!(table_str.contains("match_keys"));
    }

    // ---- format_evaluation_result ----

    #[test]
    fn format_evaluation_result_full() {
        let result = make_test_eval_result();
        let (info, table_str) = format_evaluation_result(&result);

        assert_eq!(info["policies_evaluated"], 5);
        assert_eq!(info["created"], 3);
        assert_eq!(info["updated"], 1);
        assert_eq!(info["removed"], 0);

        assert!(table_str.contains("5"));
        assert!(table_str.contains("3"));
        assert!(table_str.contains("Policies Evaluated"));
    }

    #[test]
    fn format_evaluation_result_zeros() {
        let result = EvaluationResultResponse {
            policies_evaluated: 0,
            created: 0,
            updated: 0,
            removed: 0,
        };
        let (info, table_str) = format_evaluation_result(&result);

        assert_eq!(info["policies_evaluated"], 0);
        assert!(table_str.contains("0"));
    }

    // ---- format_preview_result ----

    #[test]
    fn format_preview_result_full() {
        let result = make_test_preview_result();
        let (info, table_str) = format_preview_result(&result);

        assert_eq!(info["subscription_count"], 2);
        assert_eq!(info["matched_peers"].as_array().unwrap().len(), 1);
        assert_eq!(info["matched_repositories"].as_array().unwrap().len(), 1);

        assert!(table_str.contains("Subscriptions: 2"));
        assert!(table_str.contains("test-peer"));
        assert!(table_str.contains("us-east-1"));
        assert!(table_str.contains("npm-releases"));
        assert!(table_str.contains("npm"));
    }

    #[test]
    fn format_preview_result_empty() {
        let result = PreviewResultResponse {
            subscription_count: 0,
            matched_peers: vec![],
            matched_repositories: vec![],
        };
        let (info, table_str) = format_preview_result(&result);

        assert_eq!(info["subscription_count"], 0);
        assert!(table_str.contains("Subscriptions: 0"));
        assert!(table_str.contains("Matched Peers: 0"));
        // Should not have peer/repo tables when empty
        assert!(!table_str.contains("PEER ID"));
    }

    #[test]
    fn format_preview_result_no_region() {
        let result = PreviewResultResponse {
            subscription_count: 1,
            matched_peers: vec![MatchedPeerSchema {
                id: Uuid::nil(),
                name: "regionless-peer".to_string(),
                region: None,
            }],
            matched_repositories: vec![],
        };
        let (info, table_str) = format_preview_result(&result);

        let peers = info["matched_peers"].as_array().unwrap();
        assert_eq!(peers[0]["region"], "-");
        assert!(table_str.contains("regionless-peer"));
    }

    // ---- wiremock handler tests ----

    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    static NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

    fn policy_json() -> serde_json::Value {
        json!({
            "id": NIL_UUID,
            "name": "test-policy",
            "description": "Test sync policy",
            "replication_mode": "push",
            "enabled": true,
            "priority": 10,
            "precedence": 1,
            "repo_selector": {},
            "peer_selector": {},
            "artifact_filter": {},
            "created_at": "2026-01-15T12:00:00Z",
            "updated_at": "2026-01-15T12:00:00Z"
        })
    }

    fn evaluation_json() -> serde_json::Value {
        json!({
            "policies_evaluated": 5,
            "created": 3,
            "updated": 1,
            "removed": 0
        })
    }

    fn preview_json() -> serde_json::Value {
        json!({
            "subscription_count": 2,
            "matched_peers": [{
                "id": NIL_UUID,
                "name": "test-peer",
                "region": "us-east-1"
            }],
            "matched_repositories": [{
                "id": NIL_UUID,
                "key": "npm-releases",
                "format": "npm"
            }]
        })
    }

    #[tokio::test]
    async fn handler_list_policies_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/sync-policies"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [],
                "total": 0
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_policies(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_policies_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/sync-policies"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [policy_json()],
                "total": 1
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_policies(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_policies_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/sync-policies"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [policy_json()],
                "total": 1
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = list_policies(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_policy() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/sync-policies/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(policy_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = show_policy(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_create_policy() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/sync-policies"))
            .respond_with(ResponseTemplate::new(200).set_body_json(policy_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = create_policy(
            "test-policy",
            Some("push"),
            Some("Test sync policy"),
            Some(10),
            Some(true),
            None,
            None,
            None,
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_create_policy_with_selectors() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/sync-policies"))
            .respond_with(ResponseTemplate::new(200).set_body_json(policy_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = create_policy(
            "test-policy",
            Some("push"),
            None,
            None,
            None,
            Some(r#"{"match_keys":["npm-*"]}"#),
            Some(r#"{"regions":["us-east-1"]}"#),
            Some(r#"{"formats":["npm"]}"#),
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_update_policy() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("PUT"))
            .and(path(format!("/api/v1/sync-policies/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(policy_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = update_policy(
            NIL_UUID,
            Some("new-name"),
            Some("pull"),
            Some("Updated description"),
            Some(20),
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_update_policy_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("PUT"))
            .and(path(format!("/api/v1/sync-policies/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(policy_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = update_policy(NIL_UUID, None, None, None, None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_delete_policy() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/sync-policies/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = delete_policy(NIL_UUID, true, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_toggle_policy_enable() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!("/api/v1/sync-policies/{NIL_UUID}/toggle")))
            .respond_with(ResponseTemplate::new(200).set_body_json(policy_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = toggle_policy(NIL_UUID, true, false, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_toggle_policy_disable() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        let mut disabled = policy_json();
        disabled["enabled"] = json!(false);

        Mock::given(method("POST"))
            .and(path(format!("/api/v1/sync-policies/{NIL_UUID}/toggle")))
            .respond_with(ResponseTemplate::new(200).set_body_json(disabled))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = toggle_policy(NIL_UUID, false, true, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_toggle_policy_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!("/api/v1/sync-policies/{NIL_UUID}/toggle")))
            .respond_with(ResponseTemplate::new(200).set_body_json(policy_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = toggle_policy(NIL_UUID, true, false, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_toggle_policy_neither_flag() {
        let result = toggle_policy(
            NIL_UUID,
            false,
            false,
            &crate::test_utils::test_global(crate::output::OutputFormat::Json),
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handler_evaluate_policies() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/sync-policies/evaluate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(evaluation_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = evaluate_policies(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_evaluate_policies_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/sync-policies/evaluate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(evaluation_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = evaluate_policies(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_preview_policy() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/sync-policies/preview"))
            .respond_with(ResponseTemplate::new(200).set_body_json(preview_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = preview_policy(None, None, None, None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_preview_policy_with_selectors() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/sync-policies/preview"))
            .respond_with(ResponseTemplate::new(200).set_body_json(preview_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = preview_policy(
            Some("test-preview"),
            Some(r#"{"match_keys":["npm-*"]}"#),
            Some(r#"{"regions":["us-east-1"]}"#),
            Some(r#"{"formats":["npm"]}"#),
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_preview_policy_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/sync-policies/preview"))
            .respond_with(ResponseTemplate::new(200).set_body_json(preview_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = preview_policy(None, None, None, None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }
}
