use artifact_keeper_sdk::ClientQualityExt;
use clap::Subcommand;
use miette::Result;

use super::client::client_for;
use super::helpers::{
    confirm_action, new_table, parse_optional_uuid, parse_uuid, sdk_err, short_id,
};
use crate::cli::GlobalArgs;
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
        .map_err(|e| sdk_err("list quality gates", e))?;

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
        let mut table = new_table(vec![
            "ID", "NAME", "ACTION", "ENABLED", "MAX CRIT", "MAX HIGH",
        ]);

        for g in &gates {
            let id_short = short_id(&g.id);
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
                &id_short, &g.name, &g.action, enabled, &max_crit, &max_high,
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
    let gate_id = parse_uuid(id, "quality gate")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching quality gate...");

    let gate = client
        .get_gate()
        .id(gate_id)
        .send()
        .await
        .map_err(|e| sdk_err("get quality gate", e))?;

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
    let repository_id = parse_optional_uuid(repo_id, "repository")?;

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
        .map_err(|e| sdk_err("create quality gate", e))?;

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
    let gate_id = parse_uuid(id, "quality gate")?;

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
        .map_err(|e| sdk_err("update quality gate", e))?;

    spinner.finish_and_clear();
    eprintln!("Quality gate '{}' updated.", gate.name);

    Ok(())
}

async fn delete_gate(id: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    let gate_id = parse_uuid(id, "quality gate")?;

    if !confirm_action(
        &format!("Delete quality gate {id}?"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Deleting quality gate...");

    client
        .delete_gate()
        .id(gate_id)
        .send()
        .await
        .map_err(|e| sdk_err("delete quality gate", e))?;

    spinner.finish_and_clear();
    eprintln!("Quality gate {id} deleted.");

    Ok(())
}

fn format_gate_table(items: &[serde_json::Value]) -> String {
    let mut table = new_table(vec![
        "ID", "NAME", "ACTION", "ENABLED", "MAX CRIT", "MAX HIGH",
    ]);

    for g in items {
        let id = g["id"].as_str().unwrap_or("-");
        let id_short = if id.len() >= 8 { &id[..8] } else { id };
        let enabled = if g["enabled"].as_bool().unwrap_or(false) {
            "yes"
        } else {
            "no"
        };
        let max_crit = g["max_critical"]
            .as_i64()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string());
        let max_high = g["max_high"]
            .as_i64()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string());
        table.add_row(vec![
            id_short,
            g["name"].as_str().unwrap_or("-"),
            g["action"].as_str().unwrap_or("-"),
            enabled,
            &max_crit,
            &max_high,
        ]);
    }

    table.to_string()
}

fn format_gate_detail(item: &serde_json::Value) -> String {
    let required_checks = item["required_checks"]
        .as_array()
        .map(|a| {
            if a.is_empty() {
                "-".to_string()
            } else {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        })
        .unwrap_or_else(|| "-".to_string());

    format!(
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
        item["id"].as_str().unwrap_or("-"),
        item["name"].as_str().unwrap_or("-"),
        item["description"].as_str().unwrap_or("-"),
        item["action"].as_str().unwrap_or("-"),
        if item["enabled"].as_bool().unwrap_or(false) {
            "yes"
        } else {
            "no"
        },
        item["max_critical_issues"]
            .as_i64()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string()),
        item["max_high_issues"]
            .as_i64()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string()),
        item["max_medium_issues"]
            .as_i64()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string()),
        item["min_health_score"]
            .as_f64()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string()),
        required_checks,
        if item["enforce_on_download"].as_bool().unwrap_or(false) {
            "yes"
        } else {
            "no"
        },
        if item["enforce_on_promotion"].as_bool().unwrap_or(false) {
            "yes"
        } else {
            "no"
        },
    )
}

async fn check_artifact(
    artifact_id: &str,
    repo_id: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let aid = parse_uuid(artifact_id, "artifact")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Evaluating quality gates...");

    let mut req = client.evaluate_gate().artifact_id(aid);
    if let Some(rid) = repo_id {
        req = req.repository_id(parse_uuid(rid, "repository")?);
    }

    let result = req
        .send()
        .await
        .map_err(|e| sdk_err("evaluate quality gates", e))?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use serde_json::json;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: QualityGateCommand,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).unwrap()
    }

    fn try_parse(args: &[&str]) -> Result<TestCli, clap::Error> {
        TestCli::try_parse_from(args)
    }

    // ---- parsing: list ----

    #[test]
    fn parse_list() {
        let cli = parse(&["test", "list"]);
        assert!(matches!(cli.command, QualityGateCommand::List));
    }

    // ---- parsing: show ----

    #[test]
    fn parse_show() {
        let cli = parse(&["test", "show", "gate-id"]);
        match cli.command {
            QualityGateCommand::Show { id } => {
                assert_eq!(id, "gate-id");
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
        let cli = parse(&["test", "create", "security-gate"]);
        match cli.command {
            QualityGateCommand::Create {
                name,
                max_critical,
                max_high,
                max_medium,
                action,
                description,
                repo,
                required_checks,
            } => {
                assert_eq!(name, "security-gate");
                assert!(max_critical.is_none());
                assert!(max_high.is_none());
                assert!(max_medium.is_none());
                assert!(action.is_none());
                assert!(description.is_none());
                assert!(repo.is_none());
                assert!(required_checks.is_empty());
            }
            _ => panic!("expected Create"),
        }
    }

    #[test]
    fn parse_create_all_options() {
        let cli = parse(&[
            "test",
            "create",
            "strict-gate",
            "--max-critical",
            "0",
            "--max-high",
            "5",
            "--max-medium",
            "10",
            "--action",
            "block",
            "--description",
            "Strict security policy",
            "--repo",
            "some-repo-id",
            "--required-checks",
            "trivy,grype,snyk",
        ]);
        match cli.command {
            QualityGateCommand::Create {
                name,
                max_critical,
                max_high,
                max_medium,
                action,
                description,
                repo,
                required_checks,
            } => {
                assert_eq!(name, "strict-gate");
                assert_eq!(max_critical, Some(0));
                assert_eq!(max_high, Some(5));
                assert_eq!(max_medium, Some(10));
                assert_eq!(action.as_deref(), Some("block"));
                assert_eq!(description.as_deref(), Some("Strict security policy"));
                assert_eq!(repo.as_deref(), Some("some-repo-id"));
                assert_eq!(required_checks, vec!["trivy", "grype", "snyk"]);
            }
            _ => panic!("expected Create"),
        }
    }

    #[test]
    fn parse_create_single_required_check() {
        let cli = parse(&["test", "create", "basic-gate", "--required-checks", "trivy"]);
        match cli.command {
            QualityGateCommand::Create {
                required_checks, ..
            } => {
                assert_eq!(required_checks, vec!["trivy"]);
            }
            _ => panic!("expected Create"),
        }
    }

    #[test]
    fn parse_create_missing_name() {
        let result = try_parse(&["test", "create"]);
        assert!(result.is_err());
    }

    // ---- parsing: update ----

    #[test]
    fn parse_update_minimal() {
        let cli = parse(&["test", "update", "gate-id"]);
        match cli.command {
            QualityGateCommand::Update {
                id,
                name,
                max_critical,
                max_high,
                action,
                enabled,
            } => {
                assert_eq!(id, "gate-id");
                assert!(name.is_none());
                assert!(max_critical.is_none());
                assert!(max_high.is_none());
                assert!(action.is_none());
                assert!(enabled.is_none());
            }
            _ => panic!("expected Update"),
        }
    }

    #[test]
    fn parse_update_all_options() {
        let cli = parse(&[
            "test",
            "update",
            "gate-id",
            "--name",
            "new-name",
            "--max-critical",
            "1",
            "--max-high",
            "10",
            "--action",
            "warn",
            "--enabled",
            "true",
        ]);
        match cli.command {
            QualityGateCommand::Update {
                id,
                name,
                max_critical,
                max_high,
                action,
                enabled,
            } => {
                assert_eq!(id, "gate-id");
                assert_eq!(name.as_deref(), Some("new-name"));
                assert_eq!(max_critical, Some(1));
                assert_eq!(max_high, Some(10));
                assert_eq!(action.as_deref(), Some("warn"));
                assert_eq!(enabled, Some(true));
            }
            _ => panic!("expected Update"),
        }
    }

    #[test]
    fn parse_update_enabled_false() {
        let cli = parse(&["test", "update", "gate-id", "--enabled", "false"]);
        match cli.command {
            QualityGateCommand::Update { enabled, .. } => {
                assert_eq!(enabled, Some(false));
            }
            _ => panic!("expected Update"),
        }
    }

    #[test]
    fn parse_update_missing_id() {
        let result = try_parse(&["test", "update"]);
        assert!(result.is_err());
    }

    // ---- parsing: delete ----

    #[test]
    fn parse_delete_no_yes() {
        let cli = parse(&["test", "delete", "gate-id"]);
        match cli.command {
            QualityGateCommand::Delete { id, yes } => {
                assert_eq!(id, "gate-id");
                assert!(!yes);
            }
            _ => panic!("expected Delete"),
        }
    }

    #[test]
    fn parse_delete_with_yes() {
        let cli = parse(&["test", "delete", "gate-id", "--yes"]);
        match cli.command {
            QualityGateCommand::Delete { yes, .. } => {
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

    // ---- parsing: check ----

    #[test]
    fn parse_check_minimal() {
        let cli = parse(&["test", "check", "artifact-id"]);
        match cli.command {
            QualityGateCommand::Check { artifact, repo } => {
                assert_eq!(artifact, "artifact-id");
                assert!(repo.is_none());
            }
            _ => panic!("expected Check"),
        }
    }

    #[test]
    fn parse_check_with_repo() {
        let cli = parse(&["test", "check", "artifact-id", "--repo", "repo-id"]);
        match cli.command {
            QualityGateCommand::Check { artifact, repo } => {
                assert_eq!(artifact, "artifact-id");
                assert_eq!(repo.as_deref(), Some("repo-id"));
            }
            _ => panic!("expected Check"),
        }
    }

    #[test]
    fn parse_check_missing_artifact() {
        let result = try_parse(&["test", "check"]);
        assert!(result.is_err());
    }

    // ---- format functions ----

    #[test]
    fn format_gate_table_renders() {
        let items = vec![json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "name": "security-gate",
            "action": "block",
            "enabled": true,
            "max_critical": 0,
            "max_high": 5,
        })];
        let table = format_gate_table(&items);
        assert!(table.contains("00000000"));
        assert!(table.contains("security-gate"));
        assert!(table.contains("block"));
        assert!(table.contains("yes"));
        assert!(table.contains("0"));
        assert!(table.contains("5"));
    }

    #[test]
    fn format_gate_table_disabled_null_limits() {
        let items = vec![json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "name": "basic-gate",
            "action": "warn",
            "enabled": false,
            "max_critical": null,
            "max_high": null,
        })];
        let table = format_gate_table(&items);
        assert!(table.contains("basic-gate"));
        assert!(table.contains("warn"));
        assert!(table.contains("no"));
    }

    #[test]
    fn format_gate_table_multiple_rows() {
        let items = vec![
            json!({
                "id": "00000000-0000-0000-0000-000000000001",
                "name": "gate-a",
                "action": "block",
                "enabled": true,
                "max_critical": 0,
                "max_high": 3,
            }),
            json!({
                "id": "11111111-1111-1111-1111-111111111111",
                "name": "gate-b",
                "action": "warn",
                "enabled": false,
                "max_critical": null,
                "max_high": null,
            }),
        ];
        let table = format_gate_table(&items);
        assert!(table.contains("gate-a"));
        assert!(table.contains("gate-b"));
    }

    #[test]
    fn format_gate_detail_renders() {
        let item = json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "name": "security-gate",
            "description": "Block critical vulns",
            "action": "block",
            "enabled": true,
            "max_critical_issues": 0,
            "max_high_issues": 5,
            "max_medium_issues": 20,
            "min_health_score": 80.0,
            "required_checks": ["trivy", "grype"],
            "enforce_on_download": true,
            "enforce_on_promotion": false,
        });
        let detail = format_gate_detail(&item);
        assert!(detail.contains("00000000-0000-0000-0000-000000000001"));
        assert!(detail.contains("security-gate"));
        assert!(detail.contains("Block critical vulns"));
        assert!(detail.contains("block"));
        assert!(detail.contains("yes")); // enabled
        assert!(detail.contains("0")); // max_critical
        assert!(detail.contains("5")); // max_high
        assert!(detail.contains("20")); // max_medium
        assert!(detail.contains("80")); // min_health_score
        assert!(detail.contains("trivy, grype"));
    }

    #[test]
    fn format_gate_detail_null_optionals() {
        let item = json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "name": "basic-gate",
            "description": null,
            "action": "allow",
            "enabled": false,
            "max_critical_issues": null,
            "max_high_issues": null,
            "max_medium_issues": null,
            "min_health_score": null,
            "required_checks": [],
            "enforce_on_download": false,
            "enforce_on_promotion": false,
        });
        let detail = format_gate_detail(&item);
        assert!(detail.contains("basic-gate"));
        assert!(detail.contains("allow"));
        // Null fields should show "-"
        assert!(detail.contains("Max Critical:        -"));
        assert!(detail.contains("Required Checks:     -"));
    }

    #[test]
    fn format_gate_detail_empty_checks() {
        let item = json!({
            "id": "id",
            "name": "gate",
            "description": null,
            "action": "warn",
            "enabled": true,
            "max_critical_issues": null,
            "max_high_issues": null,
            "max_medium_issues": null,
            "min_health_score": null,
            "required_checks": [],
            "enforce_on_download": false,
            "enforce_on_promotion": true,
        });
        let detail = format_gate_detail(&item);
        assert!(detail.contains("Required Checks:     -"));
        assert!(detail.contains("Enforce on Promote:  yes"));
    }

    // ---- wiremock handler tests ----

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    static NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

    fn setup_env(tmp: &tempfile::TempDir) -> std::sync::MutexGuard<'static, ()> {
        let guard = crate::test_utils::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::set_var("AK_CONFIG_DIR", tmp.path());
            std::env::set_var("AK_TOKEN", "test-token");
        }
        guard
    }

    fn teardown_env() {
        unsafe {
            std::env::remove_var("AK_CONFIG_DIR");
            std::env::remove_var("AK_TOKEN");
        }
    }

    fn gate_json() -> serde_json::Value {
        json!({
            "id": NIL_UUID,
            "name": "security-gate",
            "description": "Block critical vulns",
            "action": "block",
            "is_enabled": true,
            "max_critical_issues": 0,
            "max_high_issues": 5,
            "max_medium_issues": null,
            "min_health_score": null,
            "min_metadata_score": null,
            "min_quality_score": null,
            "min_security_score": null,
            "required_checks": ["trivy"],
            "enforce_on_download": false,
            "enforce_on_promotion": true,
            "repository_id": null,
            "created_at": "2026-01-15T12:00:00Z",
            "updated_at": "2026-01-15T12:00:00Z"
        })
    }

    #[tokio::test]
    async fn handler_list_gates_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/quality/gates"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_gates(&global).await;
        assert!(result.is_ok());
        teardown_env();
    }

    #[tokio::test]
    async fn handler_list_gates_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/quality/gates"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([gate_json()])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_gates(&global).await;
        assert!(result.is_ok());
        teardown_env();
    }

    #[tokio::test]
    async fn handler_list_gates_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/quality/gates"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([gate_json()])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = list_gates(&global).await;
        assert!(result.is_ok());
        teardown_env();
    }

    #[tokio::test]
    async fn handler_show_gate() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/quality/gates/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(gate_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = show_gate(NIL_UUID, &global).await;
        assert!(result.is_ok());
        teardown_env();
    }

    #[tokio::test]
    async fn handler_create_gate_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/quality/gates"))
            .respond_with(ResponseTemplate::new(200).set_body_json(gate_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = create_gate(
            "security-gate",
            Some(0),
            Some(5),
            None,
            Some("block"),
            None,
            None,
            vec![],
            &global,
        )
        .await;
        assert!(result.is_ok());
        teardown_env();
    }

    #[tokio::test]
    async fn handler_update_gate() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = setup_env(&tmp);

        Mock::given(method("PUT"))
            .and(path(format!("/api/v1/quality/gates/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(gate_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = update_gate(NIL_UUID, Some("renamed"), None, None, None, None, &global).await;
        assert!(result.is_ok());
        teardown_env();
    }

    #[tokio::test]
    async fn handler_delete_gate() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/quality/gates/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = delete_gate(NIL_UUID, true, &global).await;
        assert!(result.is_ok());
        teardown_env();
    }
}
