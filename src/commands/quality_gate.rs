use artifact_keeper_sdk::ClientQualityExt;
use clap::Subcommand;
use miette::Result;

use super::client::client_for;
use super::helpers::{
    confirm_action, emit_mutation, new_table, parse_optional_uuid, parse_uuid, sdk_err, short_id,
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

    /// List quality checks (optionally filtered by artifact or repository)
    Checks {
        /// Filter by artifact ID
        #[arg(long)]
        artifact: Option<String>,

        /// Filter by repository ID
        #[arg(long)]
        repo: Option<String>,
    },

    /// Show a single quality check result
    CheckShow {
        /// Check result ID
        id: String,
    },

    /// Trigger quality checks for an artifact or repository
    CheckTrigger {
        /// Artifact ID to check
        #[arg(long)]
        artifact: Option<String>,

        /// Repository ID to check
        #[arg(long)]
        repo: Option<String>,
    },

    /// List issues found by a quality check
    CheckIssues {
        /// Check result ID
        id: String,
    },

    /// Show the aggregate health dashboard across all repositories
    HealthDashboard,

    /// Show health for a single artifact
    ArtifactHealth {
        /// Artifact ID
        artifact: String,
    },

    /// Show health for a repository
    RepoHealth {
        /// Repository key
        key: String,
    },

    /// Suppress a quality issue
    Suppress {
        /// Issue ID
        id: String,

        /// Reason for suppression
        #[arg(long)]
        reason: String,
    },

    /// Remove suppression from a quality issue
    Unsuppress {
        /// Issue ID
        id: String,
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
            Self::Checks { artifact, repo } => {
                list_checks(artifact.as_deref(), repo.as_deref(), global).await
            }
            Self::CheckShow { id } => show_check(&id, global).await,
            Self::CheckTrigger { artifact, repo } => {
                trigger_checks(artifact.as_deref(), repo.as_deref(), global).await
            }
            Self::CheckIssues { id } => list_check_issues(&id, global).await,
            Self::HealthDashboard => health_dashboard(global).await,
            Self::ArtifactHealth { artifact } => artifact_health(&artifact, global).await,
            Self::RepoHealth { key } => repo_health(&key, global).await,
            Self::Suppress { id, reason } => suppress_issue(&id, &reason, global).await,
            Self::Unsuppress { id } => unsuppress_issue(&id, global).await,
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

    emit_mutation(
        &*gate,
        &gate.id.to_string(),
        &format!("Quality gate '{}' created (ID: {}).", gate.name, gate.id),
        global,
    );

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
    emit_mutation(
        &*gate,
        &gate.id.to_string(),
        &format!("Quality gate '{}' updated.", gate.name),
        global,
    );

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
    emit_mutation(
        &serde_json::json!({ "id": id, "status": "deleted" }),
        id,
        &format!("Quality gate {id} deleted."),
        global,
    );

    Ok(())
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

// ---- quality checks ----

async fn list_checks(
    artifact: Option<&str>,
    repo: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let artifact_id = parse_optional_uuid(artifact, "artifact")?;
    let repository_id = parse_optional_uuid(repo, "repository")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching quality checks...");

    let mut req = client.list_checks();
    if let Some(a) = artifact_id {
        req = req.artifact_id(a);
    }

    let checks = req
        .send()
        .await
        .map_err(|e| sdk_err("list quality checks", e))?;

    // The `repository_id` query parameter was dropped from the API (the
    // backend ignored it); apply the `--repository` filter client-side so
    // the documented behavior is preserved.
    let mut checks = checks.into_inner();
    if let Some(r) = repository_id {
        checks.retain(|c| c.repository_id == r);
    }
    spinner.finish_and_clear();

    if checks.is_empty() {
        eprintln!("No quality checks found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for c in &checks {
            println!("{}", c.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = checks
        .iter()
        .map(|c| {
            serde_json::json!({
                "id": c.id.to_string(),
                "artifact_id": c.artifact_id.to_string(),
                "check_type": c.check_type,
                "status": c.status,
                "score": c.score,
                "issues_count": c.issues_count,
                "passed": c.passed,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec![
            "ID", "ARTIFACT", "TYPE", "STATUS", "SCORE", "ISSUES", "PASSED",
        ]);
        for c in &checks {
            let id_short = short_id(&c.id);
            let art_short = short_id(&c.artifact_id);
            let score = c
                .score
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string());
            let passed = match c.passed {
                Some(true) => "yes",
                Some(false) => "no",
                None => "-",
            };
            let issues = c.issues_count.to_string();
            table.add_row(vec![
                &id_short,
                &art_short,
                &c.check_type,
                &c.status,
                &score,
                &issues,
                passed,
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

async fn show_check(id: &str, global: &GlobalArgs) -> Result<()> {
    let check_id = parse_uuid(id, "check")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching quality check...");

    let check = client
        .get_check()
        .id(check_id)
        .send()
        .await
        .map_err(|e| sdk_err("get quality check", e))?;

    spinner.finish_and_clear();

    let info = serde_json::json!({
        "id": check.id.to_string(),
        "artifact_id": check.artifact_id.to_string(),
        "repository_id": check.repository_id.to_string(),
        "check_type": check.check_type,
        "checker_version": check.checker_version,
        "status": check.status,
        "passed": check.passed,
        "score": check.score,
        "issues_count": check.issues_count,
        "critical_count": check.critical_count,
        "high_count": check.high_count,
        "medium_count": check.medium_count,
        "low_count": check.low_count,
        "info_count": check.info_count,
        "error_message": check.error_message,
        "started_at": check.started_at.map(|t| t.to_rfc3339()),
        "completed_at": check.completed_at.map(|t| t.to_rfc3339()),
        "created_at": check.created_at.to_rfc3339(),
    });

    let table_str = format!(
        "ID:              {}\n\
         Artifact:        {}\n\
         Repository:      {}\n\
         Type:            {}\n\
         Checker Version: {}\n\
         Status:          {}\n\
         Passed:          {}\n\
         Score:           {}\n\
         Issues:          {} (crit {}, high {}, med {}, low {}, info {})\n\
         Error:           {}",
        check.id,
        check.artifact_id,
        check.repository_id,
        check.check_type,
        check.checker_version.as_deref().unwrap_or("-"),
        check.status,
        match check.passed {
            Some(true) => "yes",
            Some(false) => "no",
            None => "-",
        },
        check
            .score
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string()),
        check.issues_count,
        check.critical_count,
        check.high_count,
        check.medium_count,
        check.low_count,
        check.info_count,
        check.error_message.as_deref().unwrap_or("-"),
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn trigger_checks(
    artifact: Option<&str>,
    repo: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let artifact_id = parse_optional_uuid(artifact, "artifact")?;
    let repository_id = parse_optional_uuid(repo, "repository")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Triggering quality checks...");

    let body = artifact_keeper_sdk::types::TriggerChecksRequest {
        artifact_id,
        repository_id,
    };

    let result = client
        .trigger_checks()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("trigger quality checks", e))?;

    spinner.finish_and_clear();

    emit_mutation(
        &*result,
        &result.artifacts_queued.to_string(),
        &format!(
            "{} ({} artifact(s) queued).",
            result.message, result.artifacts_queued
        ),
        global,
    );

    Ok(())
}

async fn list_check_issues(id: &str, global: &GlobalArgs) -> Result<()> {
    let check_id = parse_uuid(id, "check")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching check issues...");

    let issues = client
        .list_check_issues()
        .id(check_id)
        .send()
        .await
        .map_err(|e| sdk_err("list check issues", e))?;

    let issues = issues.into_inner();
    spinner.finish_and_clear();

    if issues.is_empty() {
        eprintln!("No issues found for this check.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for i in &issues {
            println!("{}", i.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = issues
        .iter()
        .map(|i| {
            serde_json::json!({
                "id": i.id.to_string(),
                "severity": i.severity,
                "category": i.category,
                "title": i.title,
                "location": i.location,
                "is_suppressed": i.is_suppressed,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["ID", "SEVERITY", "CATEGORY", "TITLE", "SUPPRESSED"]);
        for i in &issues {
            let id_short = short_id(&i.id);
            let suppressed = if i.is_suppressed { "yes" } else { "no" };
            table.add_row(vec![
                &id_short,
                &i.severity,
                &i.category,
                &i.title,
                suppressed,
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

// ---- health dashboards ----

async fn health_dashboard(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching health dashboard...");

    let dash = client
        .get_health_dashboard()
        .send()
        .await
        .map_err(|e| sdk_err("get health dashboard", e))?;

    spinner.finish_and_clear();

    let info = serde_json::json!({
        "total_repositories": dash.total_repositories,
        "total_artifacts_evaluated": dash.total_artifacts_evaluated,
        "avg_health_score": dash.avg_health_score,
        "repos_grade_a": dash.repos_grade_a,
        "repos_grade_b": dash.repos_grade_b,
        "repos_grade_c": dash.repos_grade_c,
        "repos_grade_d": dash.repos_grade_d,
        "repos_grade_f": dash.repos_grade_f,
        "repositories": dash.repositories.iter().map(|r| {
            serde_json::json!({
                "repository_id": r.repository_id.to_string(),
                "repository_key": r.repository_key,
                "health_score": r.health_score,
                "health_grade": r.health_grade,
                "artifacts_evaluated": r.artifacts_evaluated,
                "artifacts_passing": r.artifacts_passing,
                "artifacts_failing": r.artifacts_failing,
            })
        }).collect::<Vec<_>>(),
    });

    let table_str = {
        let mut out = format!(
            "Repositories:        {}\n\
             Artifacts Evaluated: {}\n\
             Avg Health Score:    {}\n\
             Grades:              A {} / B {} / C {} / D {} / F {}\n",
            dash.total_repositories,
            dash.total_artifacts_evaluated,
            dash.avg_health_score,
            dash.repos_grade_a,
            dash.repos_grade_b,
            dash.repos_grade_c,
            dash.repos_grade_d,
            dash.repos_grade_f,
        );

        if !dash.repositories.is_empty() {
            let mut table = new_table(vec![
                "REPOSITORY",
                "GRADE",
                "SCORE",
                "EVALUATED",
                "PASSING",
                "FAILING",
            ]);
            for r in &dash.repositories {
                table.add_row(vec![
                    r.repository_key.clone(),
                    r.health_grade.clone(),
                    r.health_score.to_string(),
                    r.artifacts_evaluated.to_string(),
                    r.artifacts_passing.to_string(),
                    r.artifacts_failing.to_string(),
                ]);
            }
            out.push_str(&table.to_string());
        }

        out
    };

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn artifact_health(artifact: &str, global: &GlobalArgs) -> Result<()> {
    let artifact_id = parse_uuid(artifact, "artifact")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching artifact health...");

    let health = client
        .get_artifact_health()
        .artifact_id(artifact_id)
        .send()
        .await
        .map_err(|e| sdk_err("get artifact health", e))?;

    spinner.finish_and_clear();

    let info = serde_json::json!({
        "artifact_id": health.artifact_id.to_string(),
        "health_score": health.health_score,
        "health_grade": health.health_grade,
        "security_score": health.security_score,
        "quality_score": health.quality_score,
        "license_score": health.license_score,
        "metadata_score": health.metadata_score,
        "total_issues": health.total_issues,
        "critical_issues": health.critical_issues,
        "checks_total": health.checks_total,
        "checks_passed": health.checks_passed,
        "last_checked_at": health.last_checked_at.map(|t| t.to_rfc3339()),
        "checks": health.checks.iter().map(|c| {
            serde_json::json!({
                "check_type": c.check_type,
                "status": c.status,
                "passed": c.passed,
                "score": c.score,
                "issues_count": c.issues_count,
            })
        }).collect::<Vec<_>>(),
    });

    let table_str = {
        let opt_score =
            |v: Option<i32>| v.map(|s| s.to_string()).unwrap_or_else(|| "-".to_string());
        let mut out = format!(
            "Artifact:       {}\n\
             Health Score:   {} (grade {})\n\
             Security Score: {}\n\
             Quality Score:  {}\n\
             License Score:  {}\n\
             Metadata Score: {}\n\
             Issues:         {} ({} critical)\n\
             Checks:         {}/{} passed\n",
            health.artifact_id,
            health.health_score,
            health.health_grade,
            opt_score(health.security_score),
            opt_score(health.quality_score),
            opt_score(health.license_score),
            opt_score(health.metadata_score),
            health.total_issues,
            health.critical_issues,
            health.checks_passed,
            health.checks_total,
        );

        if !health.checks.is_empty() {
            let mut table = new_table(vec!["TYPE", "STATUS", "PASSED", "SCORE", "ISSUES"]);
            for c in &health.checks {
                let passed = match c.passed {
                    Some(true) => "yes",
                    Some(false) => "no",
                    None => "-",
                };
                table.add_row(vec![
                    c.check_type.clone(),
                    c.status.clone(),
                    passed.to_string(),
                    c.score
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    c.issues_count.to_string(),
                ]);
            }
            out.push_str(&table.to_string());
        }

        out
    };

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn repo_health(key: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching repository health...");

    let health = client
        .get_repo_health()
        .key(key)
        .send()
        .await
        .map_err(|e| sdk_err("get repository health", e))?;

    spinner.finish_and_clear();

    let info = serde_json::json!({
        "repository_id": health.repository_id.to_string(),
        "repository_key": health.repository_key,
        "health_score": health.health_score,
        "health_grade": health.health_grade,
        "avg_security_score": health.avg_security_score,
        "avg_quality_score": health.avg_quality_score,
        "avg_license_score": health.avg_license_score,
        "avg_metadata_score": health.avg_metadata_score,
        "artifacts_evaluated": health.artifacts_evaluated,
        "artifacts_passing": health.artifacts_passing,
        "artifacts_failing": health.artifacts_failing,
        "last_evaluated_at": health.last_evaluated_at.map(|t| t.to_rfc3339()),
    });

    let opt_score = |v: Option<i32>| v.map(|s| s.to_string()).unwrap_or_else(|| "-".to_string());
    let table_str = format!(
        "Repository:          {}\n\
         Health Score:        {} (grade {})\n\
         Avg Security Score:  {}\n\
         Avg Quality Score:   {}\n\
         Avg License Score:   {}\n\
         Avg Metadata Score:  {}\n\
         Artifacts Evaluated: {}\n\
         Artifacts Passing:   {}\n\
         Artifacts Failing:   {}",
        health.repository_key,
        health.health_score,
        health.health_grade,
        opt_score(health.avg_security_score),
        opt_score(health.avg_quality_score),
        opt_score(health.avg_license_score),
        opt_score(health.avg_metadata_score),
        health.artifacts_evaluated,
        health.artifacts_passing,
        health.artifacts_failing,
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

// ---- issue suppression ----

async fn suppress_issue(id: &str, reason: &str, global: &GlobalArgs) -> Result<()> {
    let issue_id = parse_uuid(id, "issue")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Suppressing issue...");

    let body = artifact_keeper_sdk::types::SuppressIssueRequest {
        reason: reason.to_string(),
    };

    let issue = client
        .suppress_issue()
        .id(issue_id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("suppress issue", e))?;

    spinner.finish_and_clear();

    emit_mutation(
        &*issue,
        &issue.id.to_string(),
        &format!("Issue '{}' suppressed.", issue.title),
        global,
    );

    Ok(())
}

async fn unsuppress_issue(id: &str, global: &GlobalArgs) -> Result<()> {
    let issue_id = parse_uuid(id, "issue")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Removing issue suppression...");

    let issue = client
        .unsuppress_issue()
        .id(issue_id)
        .send()
        .await
        .map_err(|e| sdk_err("unsuppress issue", e))?;

    spinner.finish_and_clear();

    emit_mutation(
        &*issue,
        &issue.id.to_string(),
        &format!("Suppression removed from issue '{}'.", issue.title),
        global,
    );

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

    // ---- wiremock handler tests ----

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    static NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

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
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/quality/gates"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_gates(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_gates_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/quality/gates"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([gate_json()])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_gates(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_gates_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/quality/gates"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([gate_json()])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = list_gates(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_gate() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/quality/gates/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(gate_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = show_gate(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_create_gate_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

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
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_update_gate() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("PUT"))
            .and(path(format!("/api/v1/quality/gates/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(gate_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = update_gate(NIL_UUID, Some("renamed"), None, None, None, None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_delete_gate() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/quality/gates/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = delete_gate(NIL_UUID, true, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    // ---- insta snapshot tests ----

    #[test]
    fn snapshot_gate_list_json() {
        let items = vec![gate_json()];
        let output = crate::output::render(&items, &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("gate_list_json", parsed);
    }

    // ---- parsing: checks / health / suppression ----

    #[test]
    fn parse_checks_minimal() {
        let cli = parse(&["test", "checks"]);
        match cli.command {
            QualityGateCommand::Checks { artifact, repo } => {
                assert!(artifact.is_none());
                assert!(repo.is_none());
            }
            _ => panic!("expected Checks"),
        }
    }

    #[test]
    fn parse_checks_with_filters() {
        let cli = parse(&["test", "checks", "--artifact", "a-id", "--repo", "r-id"]);
        match cli.command {
            QualityGateCommand::Checks { artifact, repo } => {
                assert_eq!(artifact.as_deref(), Some("a-id"));
                assert_eq!(repo.as_deref(), Some("r-id"));
            }
            _ => panic!("expected Checks"),
        }
    }

    #[test]
    fn parse_check_show() {
        let cli = parse(&["test", "check-show", "check-id"]);
        match cli.command {
            QualityGateCommand::CheckShow { id } => assert_eq!(id, "check-id"),
            _ => panic!("expected CheckShow"),
        }
    }

    #[test]
    fn parse_check_trigger() {
        let cli = parse(&["test", "check-trigger", "--artifact", "a-id"]);
        match cli.command {
            QualityGateCommand::CheckTrigger { artifact, repo } => {
                assert_eq!(artifact.as_deref(), Some("a-id"));
                assert!(repo.is_none());
            }
            _ => panic!("expected CheckTrigger"),
        }
    }

    #[test]
    fn parse_check_issues() {
        let cli = parse(&["test", "check-issues", "check-id"]);
        match cli.command {
            QualityGateCommand::CheckIssues { id } => assert_eq!(id, "check-id"),
            _ => panic!("expected CheckIssues"),
        }
    }

    #[test]
    fn parse_health_dashboard() {
        let cli = parse(&["test", "health-dashboard"]);
        assert!(matches!(cli.command, QualityGateCommand::HealthDashboard));
    }

    #[test]
    fn parse_artifact_health() {
        let cli = parse(&["test", "artifact-health", "a-id"]);
        match cli.command {
            QualityGateCommand::ArtifactHealth { artifact } => assert_eq!(artifact, "a-id"),
            _ => panic!("expected ArtifactHealth"),
        }
    }

    #[test]
    fn parse_repo_health() {
        let cli = parse(&["test", "repo-health", "my-repo"]);
        match cli.command {
            QualityGateCommand::RepoHealth { key } => assert_eq!(key, "my-repo"),
            _ => panic!("expected RepoHealth"),
        }
    }

    #[test]
    fn parse_suppress() {
        let cli = parse(&["test", "suppress", "issue-id", "--reason", "false positive"]);
        match cli.command {
            QualityGateCommand::Suppress { id, reason } => {
                assert_eq!(id, "issue-id");
                assert_eq!(reason, "false positive");
            }
            _ => panic!("expected Suppress"),
        }
    }

    #[test]
    fn parse_suppress_missing_reason() {
        let result = try_parse(&["test", "suppress", "issue-id"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_unsuppress() {
        let cli = parse(&["test", "unsuppress", "issue-id"]);
        match cli.command {
            QualityGateCommand::Unsuppress { id } => assert_eq!(id, "issue-id"),
            _ => panic!("expected Unsuppress"),
        }
    }

    // ---- wiremock handler tests: checks / health / suppression ----

    fn check_json() -> serde_json::Value {
        json!({
            "id": NIL_UUID,
            "artifact_id": NIL_UUID,
            "repository_id": NIL_UUID,
            "check_type": "vulnerability",
            "checker_version": "1.0.0",
            "status": "completed",
            "passed": true,
            "score": 92,
            "issues_count": 3,
            "critical_count": 0,
            "high_count": 1,
            "medium_count": 2,
            "low_count": 0,
            "info_count": 0,
            "details": null,
            "error_message": null,
            "started_at": "2026-01-15T12:00:00Z",
            "completed_at": "2026-01-15T12:01:00Z",
            "created_at": "2026-01-15T12:00:00Z",
            "updated_at": "2026-01-15T12:01:00Z"
        })
    }

    fn issue_json() -> serde_json::Value {
        json!({
            "id": NIL_UUID,
            "artifact_id": NIL_UUID,
            "check_result_id": NIL_UUID,
            "severity": "high",
            "category": "vulnerability",
            "title": "CVE-2026-0001",
            "description": "Example vulnerability",
            "location": "package.json",
            "is_suppressed": false,
            "suppressed_at": null,
            "suppressed_by": null,
            "suppressed_reason": null,
            "created_at": "2026-01-15T12:00:00Z"
        })
    }

    fn repo_health_json() -> serde_json::Value {
        json!({
            "repository_id": NIL_UUID,
            "repository_key": "my-repo",
            "health_score": 85,
            "health_grade": "B",
            "avg_security_score": 88,
            "avg_quality_score": 82,
            "avg_license_score": null,
            "avg_metadata_score": 90,
            "artifacts_evaluated": 10,
            "artifacts_passing": 8,
            "artifacts_failing": 2,
            "last_evaluated_at": "2026-01-15T12:00:00Z"
        })
    }

    #[tokio::test]
    async fn handler_list_checks_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/quality/checks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        // artifact_id is now a required query parameter.
        let result = list_checks(Some(NIL_UUID), None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_checks_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/quality/checks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([check_json()])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_checks(Some(NIL_UUID), None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_check() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/quality/checks/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(check_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = show_check(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_trigger_checks() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/quality/checks/trigger"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "artifacts_queued": 4,
                "message": "queued"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = trigger_checks(None, None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_check_issues() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/quality/checks/{NIL_UUID}/issues")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([issue_json()])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_check_issues(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_health_dashboard() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/quality/health/dashboard"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "total_repositories": 1,
                "total_artifacts_evaluated": 10,
                "avg_health_score": 85,
                "repos_grade_a": 0,
                "repos_grade_b": 1,
                "repos_grade_c": 0,
                "repos_grade_d": 0,
                "repos_grade_f": 0,
                "repositories": [repo_health_json()]
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = health_dashboard(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_artifact_health() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/quality/health/artifacts/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "artifact_id": NIL_UUID,
                "health_score": 90,
                "health_grade": "A",
                "security_score": 95,
                "quality_score": 88,
                "license_score": null,
                "metadata_score": 92,
                "total_issues": 2,
                "critical_issues": 0,
                "checks_total": 3,
                "checks_passed": 3,
                "last_checked_at": "2026-01-15T12:00:00Z",
                "checks": [{
                    "check_type": "vulnerability",
                    "completed_at": "2026-01-15T12:01:00Z",
                    "issues_count": 2,
                    "passed": true,
                    "score": 95,
                    "status": "completed"
                }]
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = artifact_health(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_repo_health() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/quality/health/repositories/my-repo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(repo_health_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = repo_health("my-repo", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_suppress_issue() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!("/api/v1/quality/issues/{NIL_UUID}/suppress")))
            .respond_with(ResponseTemplate::new(200).set_body_json(issue_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = suppress_issue(NIL_UUID, "false positive", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_unsuppress_issue() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/quality/issues/{NIL_UUID}/suppress")))
            .respond_with(ResponseTemplate::new(200).set_body_json(issue_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = unsuppress_issue(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }
}
