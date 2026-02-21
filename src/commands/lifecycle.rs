use artifact_keeper_sdk::ClientLifecycleExt;
use clap::Subcommand;
use miette::Result;

use super::client::client_for;
use super::helpers::{
    confirm_action, new_table, parse_optional_uuid, parse_uuid, sdk_err, short_id,
};
use crate::cli::GlobalArgs;
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
        let uid = parse_uuid(id, "repository")?;
        req = req.repository_id(uid);
    }

    let policies = req
        .send()
        .await
        .map_err(|e| sdk_err("list lifecycle policies", e))?;

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
        let mut table = new_table(vec![
            "ID", "NAME", "TYPE", "ENABLED", "PRIORITY", "LAST RUN",
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
    let policy_id = parse_uuid(id, "policy")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching lifecycle policy...");

    let policy = client
        .get_lifecycle_policy()
        .id(policy_id)
        .send()
        .await
        .map_err(|e| sdk_err("get lifecycle policy", e))?;

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

#[allow(clippy::too_many_arguments)]
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
    let repository_id = parse_optional_uuid(repo_id, "repository")?;

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
        .map_err(|e| sdk_err("create lifecycle policy", e))?;

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
    eprintln!("Lifecycle policy {id} deleted.");

    Ok(())
}

async fn preview_policy(id: &str, global: &GlobalArgs) -> Result<()> {
    let policy_id = parse_uuid(id, "policy")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Previewing policy execution...");

    let result = client
        .preview_policy()
        .id(policy_id)
        .send()
        .await
        .map_err(|e| sdk_err("preview policy", e))?;

    spinner.finish_and_clear();
    print_execution_result(&result, "Preview", global);

    Ok(())
}

async fn execute_policy(id: &str, global: &GlobalArgs) -> Result<()> {
    let policy_id = parse_uuid(id, "policy")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Executing policy...");

    let result = client
        .execute_policy()
        .id(policy_id)
        .send()
        .await
        .map_err(|e| sdk_err("execute policy", e))?;

    spinner.finish_and_clear();
    print_execution_result(&result, "Execution", global);

    Ok(())
}

fn format_policy_table(items: &[serde_json::Value]) -> String {
    let mut table = new_table(vec![
        "ID", "NAME", "TYPE", "ENABLED", "PRIORITY", "LAST RUN",
    ]);

    for p in items {
        let id = p["id"].as_str().unwrap_or("-");
        let id_short = if id.len() >= 8 { &id[..8] } else { id };
        let enabled = if p["enabled"].as_bool().unwrap_or(false) {
            "yes"
        } else {
            "no"
        };
        let last_run = p["last_run_at"].as_str().unwrap_or("-");
        table.add_row(vec![
            id_short,
            p["name"].as_str().unwrap_or("-"),
            p["policy_type"].as_str().unwrap_or("-"),
            enabled,
            &p["priority"].to_string(),
            last_run,
        ]);
    }

    table.to_string()
}

fn format_policy_detail(item: &serde_json::Value) -> String {
    format!(
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
        item["id"].as_str().unwrap_or("-"),
        item["name"].as_str().unwrap_or("-"),
        item["policy_type"].as_str().unwrap_or("-"),
        if item["enabled"].as_bool().unwrap_or(false) {
            "yes"
        } else {
            "no"
        },
        item["priority"],
        item["description"].as_str().unwrap_or("-"),
        item["repository_id"].as_str().unwrap_or("all"),
        item["last_run_at"].as_str().unwrap_or("-"),
        item["last_run_items_removed"]
            .as_i64()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string()),
        item["created_at"].as_str().unwrap_or("-"),
        item["updated_at"].as_str().unwrap_or("-"),
    )
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
            "security-policy",
            "--max-severity",
            "high",
        ]);
        match cli.command {
            LifecycleCommand::Create {
                name,
                max_severity,
                block_on_fail,
                block_unscanned,
                max_age_days,
                min_staging_hours,
                repo,
                require_signature,
            } => {
                assert_eq!(name, "security-policy");
                assert_eq!(max_severity, "high");
                assert!(!block_on_fail);
                assert!(!block_unscanned);
                assert!(max_age_days.is_none());
                assert!(min_staging_hours.is_none());
                assert!(repo.is_none());
                assert!(!require_signature);
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
            "--max-severity",
            "critical",
            "--block-on-fail",
            "--block-unscanned",
            "--max-age-days",
            "90",
            "--min-staging-hours",
            "24",
            "--repo",
            "repo-id",
            "--require-signature",
        ]);
        match cli.command {
            LifecycleCommand::Create {
                name,
                max_severity,
                block_on_fail,
                block_unscanned,
                max_age_days,
                min_staging_hours,
                repo,
                require_signature,
            } => {
                assert_eq!(name, "strict-policy");
                assert_eq!(max_severity, "critical");
                assert!(block_on_fail);
                assert!(block_unscanned);
                assert_eq!(max_age_days, Some(90));
                assert_eq!(min_staging_hours, Some(24));
                assert_eq!(repo.as_deref(), Some("repo-id"));
                assert!(require_signature);
            }
            _ => panic!("expected Create"),
        }
    }

    #[test]
    fn parse_create_missing_name() {
        let result = try_parse(&["test", "create", "--max-severity", "high"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_create_missing_max_severity() {
        let result = try_parse(&["test", "create", "policy-name"]);
        assert!(result.is_err());
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

    #[test]
    fn format_policy_table_renders() {
        let items = vec![json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "name": "cleanup-old",
            "policy_type": "retention",
            "enabled": true,
            "priority": 10,
            "last_run_at": "2026-01-15 12:00",
        })];
        let table = format_policy_table(&items);
        assert!(table.contains("00000000"));
        assert!(table.contains("cleanup-old"));
        assert!(table.contains("retention"));
        assert!(table.contains("yes"));
        assert!(table.contains("10"));
    }

    #[test]
    fn format_policy_table_disabled_no_last_run() {
        let items = vec![json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "name": "new-policy",
            "policy_type": "security",
            "enabled": false,
            "priority": 5,
            "last_run_at": null,
        })];
        let table = format_policy_table(&items);
        assert!(table.contains("new-policy"));
        assert!(table.contains("no"));
    }

    #[test]
    fn format_policy_table_multiple_rows() {
        let items = vec![
            json!({
                "id": "00000000-0000-0000-0000-000000000001",
                "name": "policy-a",
                "policy_type": "retention",
                "enabled": true,
                "priority": 10,
                "last_run_at": "2026-01-15",
            }),
            json!({
                "id": "11111111-1111-1111-1111-111111111111",
                "name": "policy-b",
                "policy_type": "security",
                "enabled": false,
                "priority": 20,
                "last_run_at": null,
            }),
        ];
        let table = format_policy_table(&items);
        assert!(table.contains("policy-a"));
        assert!(table.contains("policy-b"));
        assert!(table.contains("retention"));
        assert!(table.contains("security"));
    }

    #[test]
    fn format_policy_detail_renders() {
        let item = json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "name": "cleanup-old",
            "policy_type": "retention",
            "enabled": true,
            "priority": 10,
            "description": "Remove artifacts older than 90 days",
            "repository_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "last_run_at": "2026-01-15T12:00:00Z",
            "last_run_items_removed": 42,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-15T12:00:00Z",
        });
        let detail = format_policy_detail(&item);
        assert!(detail.contains("00000000-0000-0000-0000-000000000001"));
        assert!(detail.contains("cleanup-old"));
        assert!(detail.contains("retention"));
        assert!(detail.contains("yes"));
        assert!(detail.contains("10"));
        assert!(detail.contains("Remove artifacts older than 90 days"));
        assert!(detail.contains("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"));
        assert!(detail.contains("42"));
    }

    #[test]
    fn format_policy_detail_null_optionals() {
        let item = json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "name": "new-policy",
            "policy_type": "security",
            "enabled": false,
            "priority": 5,
            "description": null,
            "repository_id": null,
            "last_run_at": null,
            "last_run_items_removed": null,
            "created_at": "2026-01-01",
            "updated_at": "2026-01-01",
        });
        let detail = format_policy_detail(&item);
        assert!(detail.contains("new-policy"));
        assert!(detail.contains("no")); // enabled = false
        assert!(detail.contains("Repository:      all")); // null repo shows "all"
        assert!(detail.contains("Last Run:        -"));
        assert!(detail.contains("Items Removed:   -"));
    }

    #[test]
    fn format_policy_detail_zero_items_removed() {
        let item = json!({
            "id": "id",
            "name": "policy",
            "policy_type": "retention",
            "enabled": true,
            "priority": 1,
            "description": null,
            "repository_id": null,
            "last_run_at": "2026-01-15",
            "last_run_items_removed": 0,
            "created_at": "2026-01-01",
            "updated_at": "2026-01-15",
        });
        let detail = format_policy_detail(&item);
        assert!(detail.contains("Items Removed:   0"));
    }

    // ---- wiremock handler tests ----

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    static NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

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
            "updated_at": "2026-01-15T12:00:00Z"
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
            "errors": []
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
            "high",
            false,
            false,
            None,
            None,
            None,
            false,
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
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
}
