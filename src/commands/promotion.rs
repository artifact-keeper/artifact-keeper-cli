use artifact_keeper_sdk::ClientPromotionExt;
use clap::Subcommand;
use miette::Result;

use super::client::client_for;
use super::helpers::{
    confirm_action, emit_mutation, new_table, parse_uuid, print_page_info, sdk_err, short_id,
};
use crate::cli::GlobalArgs;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum PromotionCommand {
    /// Promote an artifact from one repo to another
    Promote {
        /// Source repository key
        #[arg(long)]
        from: String,

        /// Artifact ID
        artifact: String,

        /// Target repository key
        #[arg(long)]
        to: String,

        /// Optional notes
        #[arg(long)]
        notes: Option<String>,

        /// Skip policy checks
        #[arg(long)]
        skip_checks: bool,
    },

    /// Promote multiple artifacts from a staging repo in a single request
    BulkPromote {
        /// Source repository key
        #[arg(long)]
        from: String,

        /// Artifact IDs to promote (comma-separated or repeated)
        #[arg(long = "artifact", value_delimiter = ',', required = true)]
        artifacts: Vec<String>,

        /// Target repository key (defaults to the repo's linked release target)
        #[arg(long)]
        to: Option<String>,

        /// Optional notes
        #[arg(long)]
        notes: Option<String>,

        /// Skip policy checks
        #[arg(long)]
        skip_checks: bool,
    },

    /// Reject an artifact promotion
    Reject {
        /// Source repository key
        #[arg(long)]
        from: String,

        /// Artifact ID
        artifact: String,

        /// Reason for rejection
        #[arg(long)]
        reason: String,

        /// Optional notes
        #[arg(long)]
        notes: Option<String>,
    },

    /// Manage promotion rules
    Rule {
        #[command(subcommand)]
        command: PromotionRuleCommand,
    },

    /// Manage a staging repository's release target
    ReleaseTarget {
        #[command(subcommand)]
        command: ReleaseTargetCommand,
    },

    /// View promotion history
    History {
        /// Repository key
        #[arg(long)]
        repo: String,

        /// Filter by status (pending, approved, rejected, completed)
        #[arg(long)]
        status: Option<String>,

        /// Page number
        #[arg(long, default_value = "1")]
        page: i32,

        /// Results per page
        #[arg(long, default_value = "20")]
        per_page: i32,
    },
}

#[derive(Subcommand)]
pub enum PromotionRuleCommand {
    /// List promotion rules
    List {
        /// Filter by source repository ID
        #[arg(long)]
        from: Option<String>,
    },

    /// Show a promotion rule
    Get {
        /// Rule ID
        id: String,
    },

    /// Create a promotion rule
    Create {
        /// Rule name
        name: String,

        /// Source repository ID
        #[arg(long)]
        from: String,

        /// Target repository ID
        #[arg(long)]
        to: String,

        /// Enable auto-promotion
        #[arg(long)]
        auto: bool,
    },

    /// Update a promotion rule
    Update {
        /// Rule ID
        id: String,

        /// New rule name
        #[arg(long)]
        name: Option<String>,

        /// Enable or disable auto-promotion
        #[arg(long)]
        auto: Option<bool>,

        /// Enable or disable the rule
        #[arg(long)]
        enabled: Option<bool>,

        /// Minimum hours an artifact must stay in staging
        #[arg(long)]
        min_staging_hours: Option<i32>,

        /// Maximum artifact age in days
        #[arg(long)]
        max_artifact_age_days: Option<i32>,

        /// Maximum allowed CVE severity (none, low, medium, high, critical)
        #[arg(long)]
        max_cve_severity: Option<String>,

        /// Minimum health score (0-100)
        #[arg(long)]
        min_health_score: Option<i32>,

        /// Allowed licenses (comma-separated)
        #[arg(long, value_delimiter = ',')]
        allowed_licenses: Option<Vec<String>>,

        /// Require artifacts to be signed
        #[arg(long)]
        require_signature: Option<bool>,
    },

    /// Evaluate a promotion rule against candidate artifacts
    Evaluate {
        /// Rule ID
        id: String,
    },

    /// Delete a promotion rule
    Delete {
        /// Rule ID
        id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
pub enum ReleaseTargetCommand {
    /// Show the release target linked to a staging repository
    Get {
        /// Staging repository key
        #[arg(long)]
        repo: String,
    },

    /// Link (or unlink) a staging repository's release target
    Set {
        /// Staging repository key
        #[arg(long)]
        repo: String,

        /// Release repository key to link (omit to unlink)
        #[arg(long)]
        release_repo: Option<String>,
    },
}

impl PromotionCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Promote {
                from,
                artifact,
                to,
                notes,
                skip_checks,
            } => {
                promote_artifact(&from, &artifact, &to, notes.as_deref(), skip_checks, global).await
            }
            Self::BulkPromote {
                from,
                artifacts,
                to,
                notes,
                skip_checks,
            } => {
                bulk_promote(
                    &from,
                    &artifacts,
                    to.as_deref(),
                    notes.as_deref(),
                    skip_checks,
                    global,
                )
                .await
            }
            Self::Reject {
                from,
                artifact,
                reason,
                notes,
            } => reject_artifact(&from, &artifact, &reason, notes.as_deref(), global).await,
            Self::Rule { command } => match command {
                PromotionRuleCommand::List { from } => list_rules(from.as_deref(), global).await,
                PromotionRuleCommand::Get { id } => get_rule(&id, global).await,
                PromotionRuleCommand::Create {
                    name,
                    from,
                    to,
                    auto,
                } => create_rule(&name, &from, &to, auto, global).await,
                PromotionRuleCommand::Update {
                    id,
                    name,
                    auto,
                    enabled,
                    min_staging_hours,
                    max_artifact_age_days,
                    max_cve_severity,
                    min_health_score,
                    allowed_licenses,
                    require_signature,
                } => {
                    update_rule(
                        &id,
                        RuleUpdate {
                            name,
                            auto,
                            enabled,
                            min_staging_hours,
                            max_artifact_age_days,
                            max_cve_severity,
                            min_health_score,
                            allowed_licenses,
                            require_signature,
                        },
                        global,
                    )
                    .await
                }
                PromotionRuleCommand::Evaluate { id } => evaluate_rule(&id, global).await,
                PromotionRuleCommand::Delete { id, yes } => delete_rule(&id, yes, global).await,
            },
            Self::ReleaseTarget { command } => match command {
                ReleaseTargetCommand::Get { repo } => get_release_target(&repo, global).await,
                ReleaseTargetCommand::Set { repo, release_repo } => {
                    set_release_target(&repo, release_repo.as_deref(), global).await
                }
            },
            Self::History {
                repo,
                status,
                page,
                per_page,
            } => promotion_history(&repo, status.as_deref(), page, per_page, global).await,
        }
    }
}

/// Optional fields for a promotion-rule update. Grouped into a struct to keep
/// the `update_rule` signature within clippy's argument-count budget.
struct RuleUpdate {
    name: Option<String>,
    auto: Option<bool>,
    enabled: Option<bool>,
    min_staging_hours: Option<i32>,
    max_artifact_age_days: Option<i32>,
    max_cve_severity: Option<String>,
    min_health_score: Option<i32>,
    allowed_licenses: Option<Vec<String>>,
    require_signature: Option<bool>,
}

async fn promote_artifact(
    from: &str,
    artifact_id: &str,
    to: &str,
    notes: Option<&str>,
    skip_checks: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let aid = parse_uuid(artifact_id, "artifact")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Promoting artifact...");

    let body = artifact_keeper_sdk::types::PromoteArtifactRequest {
        target_repository: Some(to.to_string()),
        notes: notes.map(|s| s.to_string()),
        skip_policy_check: skip_checks.then_some(true),
    };

    let resp = client
        .promote_artifact()
        .key(from)
        .artifact_id(aid)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("promote artifact", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        if let Some(id) = &resp.promotion_id {
            println!("{id}");
        }
        return Ok(());
    }

    if resp.promoted {
        eprintln!("Artifact promoted: {} -> {}", resp.source, resp.target);
        if let Some(msg) = &resp.message {
            eprintln!("{msg}");
        }
    } else {
        eprintln!("Promotion blocked.");
        if let Some(msg) = &resp.message {
            eprintln!("{msg}");
        }
        if !resp.policy_violations.is_empty() {
            eprintln!("Policy violations:");
            for v in &resp.policy_violations {
                let info = serde_json::to_string(v).unwrap_or_default();
                eprintln!("  - {info}");
            }
        }
    }

    Ok(())
}

async fn list_rules(source_repo_id: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching promotion rules...");

    let mut req = client.list_rules();
    if let Some(id) = source_repo_id {
        let uid = parse_uuid(id, "repository")?;
        req = req.source_repo_id(uid);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| sdk_err("list promotion rules", e))?;

    spinner.finish_and_clear();

    if resp.items.is_empty() {
        eprintln!("No promotion rules found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for r in &resp.items {
            println!("{}", r.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp
        .items
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id.to_string(),
                "name": r.name,
                "source_repo_id": r.source_repo_id.to_string(),
                "target_repo_id": r.target_repo_id.to_string(),
                "auto_promote": r.auto_promote,
                "is_enabled": r.is_enabled,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["ID", "NAME", "SOURCE", "TARGET", "AUTO", "ENABLED"]);

        for r in &resp.items {
            let id_short = short_id(&r.id);
            let src_short = short_id(&r.source_repo_id);
            let tgt_short = short_id(&r.target_repo_id);
            let auto = if r.auto_promote { "yes" } else { "no" };
            let enabled = if r.is_enabled { "yes" } else { "no" };
            table.add_row(vec![
                &id_short, &r.name, &src_short, &tgt_short, auto, enabled,
            ]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    eprintln!("{} rules total.", resp.total);

    Ok(())
}

async fn create_rule(
    name: &str,
    from: &str,
    to: &str,
    auto: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let source_id = parse_uuid(from, "source repository")?;
    let target_id = parse_uuid(to, "target repository")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Creating promotion rule...");

    let body = artifact_keeper_sdk::types::CreateRuleRequest {
        name: name.to_string(),
        source_repo_id: source_id,
        target_repo_id: target_id,
        auto_promote: auto.then_some(true),
        is_enabled: Some(true),
        min_staging_hours: None,
        max_artifact_age_days: None,
        max_cve_severity: None,
        min_health_score: None,
        allowed_licenses: None,
        require_signature: None,
    };

    let rule = client
        .create_rule()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("create promotion rule", e))?;

    spinner.finish_and_clear();

    emit_mutation(
        &*rule,
        &rule.id.to_string(),
        &format!("Promotion rule '{}' created (ID: {}).", rule.name, rule.id),
        global,
    );

    Ok(())
}

async fn delete_rule(id: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    let rule_id = parse_uuid(id, "rule")?;

    if !confirm_action(
        &format!("Delete promotion rule {id}?"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Deleting promotion rule...");

    client
        .delete_rule()
        .id(rule_id)
        .send()
        .await
        .map_err(|e| sdk_err("delete promotion rule", e))?;

    spinner.finish_and_clear();
    emit_mutation(
        &serde_json::json!({ "id": id, "status": "deleted" }),
        id,
        &format!("Promotion rule {id} deleted."),
        global,
    );

    Ok(())
}

fn rule_detail(
    rule: &artifact_keeper_sdk::types::PromotionRuleResponse,
) -> (serde_json::Value, String) {
    let info = serde_json::json!({
        "id": rule.id.to_string(),
        "name": rule.name,
        "source_repo_id": rule.source_repo_id.to_string(),
        "target_repo_id": rule.target_repo_id.to_string(),
        "auto_promote": rule.auto_promote,
        "is_enabled": rule.is_enabled,
        "min_staging_hours": rule.min_staging_hours,
        "max_artifact_age_days": rule.max_artifact_age_days,
        "max_cve_severity": rule.max_cve_severity,
        "min_health_score": rule.min_health_score,
        "allowed_licenses": rule.allowed_licenses,
        "require_signature": rule.require_signature,
        "created_at": rule.created_at.to_rfc3339(),
        "updated_at": rule.updated_at.to_rfc3339(),
    });

    let licenses = rule
        .allowed_licenses
        .as_ref()
        .map(|l| l.join(", "))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "-".to_string());

    let table_str = format!(
        "ID:               {}\n\
         Name:             {}\n\
         Source:           {}\n\
         Target:           {}\n\
         Auto-promote:     {}\n\
         Enabled:          {}\n\
         Min staging (h):  {}\n\
         Max age (days):   {}\n\
         Max CVE severity: {}\n\
         Min health score: {}\n\
         Allowed licenses: {}\n\
         Require signature: {}\n\
         Created:          {}\n\
         Updated:          {}",
        rule.id,
        rule.name,
        rule.source_repo_id,
        rule.target_repo_id,
        if rule.auto_promote { "yes" } else { "no" },
        if rule.is_enabled { "yes" } else { "no" },
        opt_display(&rule.min_staging_hours),
        opt_display(&rule.max_artifact_age_days),
        rule.max_cve_severity.as_deref().unwrap_or("-"),
        opt_display(&rule.min_health_score),
        licenses,
        if rule.require_signature { "yes" } else { "no" },
        rule.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
        rule.updated_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    (info, table_str)
}

fn opt_display<T: std::fmt::Display>(v: &Option<T>) -> String {
    v.as_ref()
        .map(|x| x.to_string())
        .unwrap_or_else(|| "-".to_string())
}

async fn get_rule(id: &str, global: &GlobalArgs) -> Result<()> {
    let rule_id = parse_uuid(id, "rule")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching promotion rule...");

    let rule = client
        .get_rule()
        .id(rule_id)
        .send()
        .await
        .map_err(|e| sdk_err("get promotion rule", e))?;

    spinner.finish_and_clear();

    let (info, table_str) = rule_detail(&rule);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn update_rule(id: &str, update: RuleUpdate, global: &GlobalArgs) -> Result<()> {
    let rule_id = parse_uuid(id, "rule")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Updating promotion rule...");

    let body = artifact_keeper_sdk::types::UpdateRuleRequest {
        name: update.name,
        auto_promote: update.auto,
        is_enabled: update.enabled,
        min_staging_hours: update.min_staging_hours,
        max_artifact_age_days: update.max_artifact_age_days,
        max_cve_severity: update.max_cve_severity,
        min_health_score: update.min_health_score,
        allowed_licenses: update.allowed_licenses,
        require_signature: update.require_signature,
    };

    let rule = client
        .update_rule()
        .id(rule_id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("update promotion rule", e))?;

    spinner.finish_and_clear();

    emit_mutation(
        &*rule,
        &rule.id.to_string(),
        &format!("Promotion rule '{}' updated (ID: {}).", rule.name, rule.id),
        global,
    );

    Ok(())
}

async fn evaluate_rule(id: &str, global: &GlobalArgs) -> Result<()> {
    let rule_id = parse_uuid(id, "rule")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Evaluating promotion rule...");

    let resp = client
        .evaluate_rule()
        .id(rule_id)
        .send()
        .await
        .map_err(|e| sdk_err("evaluate promotion rule", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        for entry in &resp.results {
            println!("{}", entry.artifact_id);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp
        .results
        .iter()
        .map(|r| {
            serde_json::json!({
                "artifact_id": r.artifact_id.to_string(),
                "passed": r.passed,
                "violations": r.violations,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["ARTIFACT", "PASSED", "VIOLATIONS"]);
        for r in &resp.results {
            let id_short = short_id(&r.artifact_id);
            let passed = if r.passed { "yes" } else { "no" };
            let violations = if r.violations.is_empty() {
                "-".to_string()
            } else {
                r.violations.join("; ")
            };
            table.add_row(vec![&id_short, passed, &violations]);
        }
        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    eprintln!(
        "Rule '{}': {} passed, {} failed of {} artifacts.",
        resp.rule_name, resp.passed, resp.failed, resp.total_artifacts
    );

    Ok(())
}

async fn bulk_promote(
    from: &str,
    artifact_ids: &[String],
    to: Option<&str>,
    notes: Option<&str>,
    skip_checks: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let mut ids = Vec::with_capacity(artifact_ids.len());
    for a in artifact_ids {
        ids.push(parse_uuid(a, "artifact")?);
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Promoting artifacts...");

    let body = artifact_keeper_sdk::types::BulkPromoteRequest {
        artifact_ids: ids,
        target_repository: to.map(|s| s.to_string()),
        notes: notes.map(|s| s.to_string()),
        skip_policy_check: skip_checks.then_some(true),
    };

    let resp = client
        .promote_artifacts_bulk()
        .key(from)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("bulk-promote artifacts", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        for r in &resp.results {
            if let Some(pid) = &r.promotion_id {
                println!("{pid}");
            }
        }
        return Ok(());
    }

    let entries: Vec<_> = resp
        .results
        .iter()
        .map(|r| {
            serde_json::json!({
                "promoted": r.promoted,
                "source": r.source,
                "target": r.target,
                "promotion_id": r.promotion_id.map(|id| id.to_string()),
                "message": r.message,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["PROMOTED", "SOURCE", "TARGET", "MESSAGE"]);
        for r in &resp.results {
            let promoted = if r.promoted { "yes" } else { "no" };
            let msg = r.message.as_deref().unwrap_or("-");
            table.add_row(vec![promoted, &r.source, &r.target, msg]);
        }
        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    eprintln!(
        "{} promoted, {} failed of {} artifacts.",
        resp.promoted, resp.failed, resp.total
    );

    Ok(())
}

async fn reject_artifact(
    from: &str,
    artifact_id: &str,
    reason: &str,
    notes: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let aid = parse_uuid(artifact_id, "artifact")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Rejecting artifact...");

    let body = artifact_keeper_sdk::types::RejectArtifactRequest {
        reason: reason.to_string(),
        notes: notes.map(|s| s.to_string()),
    };

    let resp = client
        .reject_artifact()
        .key(from)
        .artifact_id(aid)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("reject artifact", e))?;

    spinner.finish_and_clear();

    emit_mutation(
        &*resp,
        &resp.rejection_id.to_string(),
        &format!(
            "Artifact {} rejected from {} (reason: {}).",
            resp.artifact_id, resp.source, resp.reason
        ),
        global,
    );

    Ok(())
}

async fn get_release_target(repo: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching release target...");

    let resp = client
        .get_release_target()
        .key(repo)
        .send()
        .await
        .map_err(|e| sdk_err("get release target", e))?;

    spinner.finish_and_clear();

    let (info, table_str) = release_target_detail(&resp);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn set_release_target(
    repo: &str,
    release_repo: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let action = if release_repo.is_some() {
        "Linking release target..."
    } else {
        "Unlinking release target..."
    };
    let spinner = output::spinner(action);

    let body = artifact_keeper_sdk::types::SetReleaseTargetRequest {
        release_repository_key: release_repo.map(|s| s.to_string()),
    };

    let resp = client
        .set_release_target()
        .key(repo)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("set release target", e))?;

    spinner.finish_and_clear();

    let human = if resp.linked {
        format!(
            "Release target for '{}' set to '{}'.",
            repo,
            resp.release_repository_key.as_deref().unwrap_or("-")
        )
    } else {
        format!("Release target for '{repo}' unlinked.")
    };

    let (info, _table) = release_target_detail(&resp);
    emit_mutation(&info, repo, &human, global);

    Ok(())
}

fn release_target_detail(
    resp: &artifact_keeper_sdk::types::ReleaseTargetResponse,
) -> (serde_json::Value, String) {
    let info = serde_json::json!({
        "linked": resp.linked,
        "release_repository_id": resp.release_repository_id.map(|id| id.to_string()),
        "release_repository_key": resp.release_repository_key,
    });

    let table_str = format!(
        "Linked:          {}\n\
         Release repo:    {}\n\
         Release repo ID: {}",
        if resp.linked { "yes" } else { "no" },
        resp.release_repository_key.as_deref().unwrap_or("-"),
        resp.release_repository_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| "-".to_string()),
    );

    (info, table_str)
}

async fn promotion_history(
    repo: &str,
    status: Option<&str>,
    page: i32,
    per_page: i32,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching promotion history...");

    let mut req = client
        .promotion_history()
        .key(repo)
        .page(page)
        .per_page(per_page);

    if let Some(s) = status {
        req = req.status(s);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| sdk_err("fetch promotion history", e))?;

    spinner.finish_and_clear();

    if resp.items.is_empty() {
        eprintln!("No promotion history found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for entry in &resp.items {
            println!("{}", entry.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp
        .items
        .iter()
        .map(|e| {
            serde_json::json!({
                "id": e.id.to_string(),
                "artifact_path": e.artifact_path,
                "source_repo": e.source_repo_key,
                "target_repo": e.target_repo_key,
                "status": e.status,
                "created_at": e.created_at.to_rfc3339(),
                "promoted_by": e.promoted_by_username,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["ID", "ARTIFACT", "SOURCE", "TARGET", "STATUS", "DATE"]);

        for e in &resp.items {
            let id_short = short_id(&e.id);
            let date = e.created_at.format("%Y-%m-%d %H:%M").to_string();
            table.add_row(vec![
                &id_short,
                &e.artifact_path,
                &e.source_repo_key,
                &e.target_repo_key,
                &e.status,
                &date,
            ]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    print_page_info(
        resp.pagination.page,
        resp.pagination.total_pages,
        resp.pagination.total,
        "entries",
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
        command: PromotionCommand,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).unwrap()
    }

    fn try_parse(args: &[&str]) -> Result<TestCli, clap::Error> {
        TestCli::try_parse_from(args)
    }

    // ---- parsing: promote ----

    #[test]
    fn parse_promote_minimal() {
        let cli = parse(&[
            "test",
            "promote",
            "--from",
            "maven-staging",
            "00000000-0000-0000-0000-000000000001",
            "--to",
            "maven-releases",
        ]);
        match cli.command {
            PromotionCommand::Promote {
                from,
                artifact,
                to,
                notes,
                skip_checks,
            } => {
                assert_eq!(from, "maven-staging");
                assert_eq!(artifact, "00000000-0000-0000-0000-000000000001");
                assert_eq!(to, "maven-releases");
                assert!(notes.is_none());
                assert!(!skip_checks);
            }
            _ => panic!("expected Promote"),
        }
    }

    #[test]
    fn parse_promote_with_notes_and_skip() {
        let cli = parse(&[
            "test",
            "promote",
            "--from",
            "staging",
            "artifact-id",
            "--to",
            "prod",
            "--notes",
            "Approved by QA",
            "--skip-checks",
        ]);
        match cli.command {
            PromotionCommand::Promote {
                notes, skip_checks, ..
            } => {
                assert_eq!(notes.as_deref(), Some("Approved by QA"));
                assert!(skip_checks);
            }
            _ => panic!("expected Promote"),
        }
    }

    #[test]
    fn parse_promote_missing_from() {
        let result = try_parse(&["test", "promote", "artifact-id", "--to", "prod"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_promote_missing_to() {
        let result = try_parse(&["test", "promote", "--from", "staging", "artifact-id"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_promote_missing_artifact() {
        let result = try_parse(&["test", "promote", "--from", "staging", "--to", "prod"]);
        assert!(result.is_err());
    }

    // ---- parsing: rule list ----

    #[test]
    fn parse_rule_list_no_filter() {
        let cli = parse(&["test", "rule", "list"]);
        match cli.command {
            PromotionCommand::Rule {
                command: PromotionRuleCommand::List { from },
            } => {
                assert!(from.is_none());
            }
            _ => panic!("expected Rule List"),
        }
    }

    #[test]
    fn parse_rule_list_with_from() {
        let cli = parse(&[
            "test",
            "rule",
            "list",
            "--from",
            "00000000-0000-0000-0000-000000000001",
        ]);
        match cli.command {
            PromotionCommand::Rule {
                command: PromotionRuleCommand::List { from },
            } => {
                assert_eq!(
                    from.as_deref(),
                    Some("00000000-0000-0000-0000-000000000001")
                );
            }
            _ => panic!("expected Rule List"),
        }
    }

    // ---- parsing: rule create ----

    #[test]
    fn parse_rule_create_minimal() {
        let cli = parse(&[
            "test",
            "rule",
            "create",
            "staging-to-prod",
            "--from",
            "repo-a-id",
            "--to",
            "repo-b-id",
        ]);
        match cli.command {
            PromotionCommand::Rule {
                command:
                    PromotionRuleCommand::Create {
                        name,
                        from,
                        to,
                        auto,
                    },
            } => {
                assert_eq!(name, "staging-to-prod");
                assert_eq!(from, "repo-a-id");
                assert_eq!(to, "repo-b-id");
                assert!(!auto);
            }
            _ => panic!("expected Rule Create"),
        }
    }

    #[test]
    fn parse_rule_create_with_auto() {
        let cli = parse(&[
            "test",
            "rule",
            "create",
            "auto-rule",
            "--from",
            "id1",
            "--to",
            "id2",
            "--auto",
        ]);
        match cli.command {
            PromotionCommand::Rule {
                command: PromotionRuleCommand::Create { auto, .. },
            } => {
                assert!(auto);
            }
            _ => panic!("expected Rule Create"),
        }
    }

    #[test]
    fn parse_rule_create_missing_name() {
        let result = try_parse(&["test", "rule", "create", "--from", "id1", "--to", "id2"]);
        assert!(result.is_err());
    }

    // ---- parsing: rule delete ----

    #[test]
    fn parse_rule_delete() {
        let cli = parse(&["test", "rule", "delete", "rule-id"]);
        match cli.command {
            PromotionCommand::Rule {
                command: PromotionRuleCommand::Delete { id, yes },
            } => {
                assert_eq!(id, "rule-id");
                assert!(!yes);
            }
            _ => panic!("expected Rule Delete"),
        }
    }

    #[test]
    fn parse_rule_delete_with_yes() {
        let cli = parse(&["test", "rule", "delete", "rule-id", "--yes"]);
        match cli.command {
            PromotionCommand::Rule {
                command: PromotionRuleCommand::Delete { yes, .. },
            } => {
                assert!(yes);
            }
            _ => panic!("expected Rule Delete"),
        }
    }

    #[test]
    fn parse_rule_delete_missing_id() {
        let result = try_parse(&["test", "rule", "delete"]);
        assert!(result.is_err());
    }

    // ---- parsing: history ----

    #[test]
    fn parse_history_minimal() {
        let cli = parse(&["test", "history", "--repo", "maven-releases"]);
        match cli.command {
            PromotionCommand::History {
                repo,
                status,
                page,
                per_page,
            } => {
                assert_eq!(repo, "maven-releases");
                assert!(status.is_none());
                assert_eq!(page, 1);
                assert_eq!(per_page, 20);
            }
            _ => panic!("expected History"),
        }
    }

    #[test]
    fn parse_history_with_all_options() {
        let cli = parse(&[
            "test",
            "history",
            "--repo",
            "npm-local",
            "--status",
            "completed",
            "--page",
            "2",
            "--per-page",
            "50",
        ]);
        match cli.command {
            PromotionCommand::History {
                repo,
                status,
                page,
                per_page,
            } => {
                assert_eq!(repo, "npm-local");
                assert_eq!(status.as_deref(), Some("completed"));
                assert_eq!(page, 2);
                assert_eq!(per_page, 50);
            }
            _ => panic!("expected History"),
        }
    }

    #[test]
    fn parse_history_missing_repo() {
        let result = try_parse(&["test", "history"]);
        assert!(result.is_err());
    }

    // ---- parsing: missing subcommand ----

    #[test]
    fn parse_rule_missing_subcommand() {
        let result = try_parse(&["test", "rule"]);
        assert!(result.is_err());
    }

    // ---- format functions ----

    // ---- wiremock handler tests ----

    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, ResponseTemplate};

    static NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

    fn rule_json() -> serde_json::Value {
        json!({
            "id": NIL_UUID,
            "name": "staging-to-prod",
            "source_repo_id": NIL_UUID,
            "target_repo_id": NIL_UUID,
            "auto_promote": false,
            "is_enabled": true,
            "require_signature": false,
            "created_at": "2026-01-15T12:00:00Z",
            "updated_at": "2026-01-15T12:00:00Z"
        })
    }

    #[tokio::test]
    async fn handler_promote_artifact_json() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/promotion/repositories/staging/artifacts/{NIL_UUID}/promote"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "promoted": true,
                "source": "staging",
                "target": "releases",
                "message": "Promoted successfully",
                "promotion_id": NIL_UUID,
                "policy_violations": []
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = promote_artifact("staging", NIL_UUID, "releases", None, false, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_promote_artifact_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/promotion/repositories/staging/artifacts/{NIL_UUID}/promote"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "promoted": true,
                "source": "staging",
                "target": "releases",
                "promotion_id": NIL_UUID,
                "policy_violations": []
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = promote_artifact("staging", NIL_UUID, "releases", None, false, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_rules_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/promotion-rules"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [],
                "total": 0
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_rules(None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_rules_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/promotion-rules"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [rule_json()],
                "total": 1
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_rules(None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_rules_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/promotion-rules"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [rule_json()],
                "total": 1
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = list_rules(None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_create_rule_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/promotion-rules"))
            .respond_with(ResponseTemplate::new(200).set_body_json(rule_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = create_rule("staging-to-prod", NIL_UUID, NIL_UUID, false, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_delete_rule() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/promotion-rules/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = delete_rule(NIL_UUID, true, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_promotion_history_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex(
                "/api/v1/promotion/repositories/.*/promotion-history",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [],
                "pagination": { "page": 1, "per_page": 20, "total": 0, "total_pages": 0 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = promotion_history("maven-releases", None, 1, 20, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_promotion_history_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex(
                "/api/v1/promotion/repositories/.*/promotion-history",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{
                    "id": NIL_UUID,
                    "artifact_id": NIL_UUID,
                    "artifact_path": "com/example/app/1.0.0",
                    "source_repo_key": "maven-staging",
                    "target_repo_key": "maven-releases",
                    "status": "completed",
                    "promoted_by_username": "admin",
                    "created_at": "2026-01-15T12:00:00Z"
                }],
                "pagination": { "page": 1, "per_page": 20, "total": 1_i64, "total_pages": 1 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = promotion_history("maven-releases", None, 1, 20, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    // ---- parsing: bulk-promote / reject / rule get-update-evaluate / release-target ----

    #[test]
    fn parse_bulk_promote_minimal() {
        let cli = parse(&[
            "test",
            "bulk-promote",
            "--from",
            "staging",
            "--artifact",
            "00000000-0000-0000-0000-000000000001,00000000-0000-0000-0000-000000000002",
        ]);
        match cli.command {
            PromotionCommand::BulkPromote {
                from,
                artifacts,
                to,
                notes,
                skip_checks,
            } => {
                assert_eq!(from, "staging");
                assert_eq!(artifacts.len(), 2);
                assert!(to.is_none());
                assert!(notes.is_none());
                assert!(!skip_checks);
            }
            _ => panic!("expected BulkPromote"),
        }
    }

    #[test]
    fn parse_bulk_promote_with_options() {
        let cli = parse(&[
            "test",
            "bulk-promote",
            "--from",
            "staging",
            "--artifact",
            "id1",
            "--artifact",
            "id2",
            "--to",
            "releases",
            "--notes",
            "batch",
            "--skip-checks",
        ]);
        match cli.command {
            PromotionCommand::BulkPromote {
                artifacts,
                to,
                notes,
                skip_checks,
                ..
            } => {
                assert_eq!(artifacts, vec!["id1", "id2"]);
                assert_eq!(to.as_deref(), Some("releases"));
                assert_eq!(notes.as_deref(), Some("batch"));
                assert!(skip_checks);
            }
            _ => panic!("expected BulkPromote"),
        }
    }

    #[test]
    fn parse_bulk_promote_missing_artifact() {
        let result = try_parse(&["test", "bulk-promote", "--from", "staging"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_reject_minimal() {
        let cli = parse(&[
            "test",
            "reject",
            "--from",
            "staging",
            "artifact-id",
            "--reason",
            "cve",
        ]);
        match cli.command {
            PromotionCommand::Reject {
                from,
                artifact,
                reason,
                notes,
            } => {
                assert_eq!(from, "staging");
                assert_eq!(artifact, "artifact-id");
                assert_eq!(reason, "cve");
                assert!(notes.is_none());
            }
            _ => panic!("expected Reject"),
        }
    }

    #[test]
    fn parse_reject_missing_reason() {
        let result = try_parse(&["test", "reject", "--from", "staging", "artifact-id"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_rule_get() {
        let cli = parse(&["test", "rule", "get", "rule-id"]);
        match cli.command {
            PromotionCommand::Rule {
                command: PromotionRuleCommand::Get { id },
            } => assert_eq!(id, "rule-id"),
            _ => panic!("expected Rule Get"),
        }
    }

    #[test]
    fn parse_rule_update_fields() {
        let cli = parse(&[
            "test",
            "rule",
            "update",
            "rule-id",
            "--name",
            "renamed",
            "--auto",
            "true",
            "--enabled",
            "false",
            "--min-staging-hours",
            "24",
            "--max-cve-severity",
            "high",
            "--allowed-licenses",
            "MIT,Apache-2.0",
            "--require-signature",
            "true",
        ]);
        match cli.command {
            PromotionCommand::Rule {
                command:
                    PromotionRuleCommand::Update {
                        id,
                        name,
                        auto,
                        enabled,
                        min_staging_hours,
                        max_cve_severity,
                        allowed_licenses,
                        require_signature,
                        ..
                    },
            } => {
                assert_eq!(id, "rule-id");
                assert_eq!(name.as_deref(), Some("renamed"));
                assert_eq!(auto, Some(true));
                assert_eq!(enabled, Some(false));
                assert_eq!(min_staging_hours, Some(24));
                assert_eq!(max_cve_severity.as_deref(), Some("high"));
                assert_eq!(
                    allowed_licenses,
                    Some(vec!["MIT".to_string(), "Apache-2.0".to_string()])
                );
                assert_eq!(require_signature, Some(true));
            }
            _ => panic!("expected Rule Update"),
        }
    }

    #[test]
    fn parse_rule_update_no_fields() {
        let cli = parse(&["test", "rule", "update", "rule-id"]);
        match cli.command {
            PromotionCommand::Rule {
                command: PromotionRuleCommand::Update { id, name, auto, .. },
            } => {
                assert_eq!(id, "rule-id");
                assert!(name.is_none());
                assert!(auto.is_none());
            }
            _ => panic!("expected Rule Update"),
        }
    }

    #[test]
    fn parse_rule_evaluate() {
        let cli = parse(&["test", "rule", "evaluate", "rule-id"]);
        match cli.command {
            PromotionCommand::Rule {
                command: PromotionRuleCommand::Evaluate { id },
            } => assert_eq!(id, "rule-id"),
            _ => panic!("expected Rule Evaluate"),
        }
    }

    #[test]
    fn parse_release_target_get() {
        let cli = parse(&["test", "release-target", "get", "--repo", "maven-staging"]);
        match cli.command {
            PromotionCommand::ReleaseTarget {
                command: ReleaseTargetCommand::Get { repo },
            } => assert_eq!(repo, "maven-staging"),
            _ => panic!("expected ReleaseTarget Get"),
        }
    }

    #[test]
    fn parse_release_target_set_link() {
        let cli = parse(&[
            "test",
            "release-target",
            "set",
            "--repo",
            "maven-staging",
            "--release-repo",
            "maven-releases",
        ]);
        match cli.command {
            PromotionCommand::ReleaseTarget {
                command: ReleaseTargetCommand::Set { repo, release_repo },
            } => {
                assert_eq!(repo, "maven-staging");
                assert_eq!(release_repo.as_deref(), Some("maven-releases"));
            }
            _ => panic!("expected ReleaseTarget Set"),
        }
    }

    #[test]
    fn parse_release_target_set_unlink() {
        let cli = parse(&["test", "release-target", "set", "--repo", "maven-staging"]);
        match cli.command {
            PromotionCommand::ReleaseTarget {
                command: ReleaseTargetCommand::Set { release_repo, .. },
            } => assert!(release_repo.is_none()),
            _ => panic!("expected ReleaseTarget Set"),
        }
    }

    // ---- detail formatters ----

    #[test]
    fn rule_detail_renders() {
        let rule: artifact_keeper_sdk::types::PromotionRuleResponse =
            serde_json::from_value(rule_json()).unwrap();
        let (info, table) = rule_detail(&rule);
        assert_eq!(info["name"], "staging-to-prod");
        assert!(table.contains("staging-to-prod"));
        assert!(table.contains("Auto-promote:"));
        assert!(table.contains("Require signature:"));
    }

    #[test]
    fn release_target_detail_linked() {
        let resp: artifact_keeper_sdk::types::ReleaseTargetResponse =
            serde_json::from_value(json!({
                "linked": true,
                "release_repository_id": NIL_UUID,
                "release_repository_key": "maven-releases"
            }))
            .unwrap();
        let (info, table) = release_target_detail(&resp);
        assert_eq!(info["linked"], true);
        assert!(table.contains("maven-releases"));
        assert!(table.contains("yes"));
    }

    #[test]
    fn release_target_detail_unlinked() {
        let resp: artifact_keeper_sdk::types::ReleaseTargetResponse =
            serde_json::from_value(json!({
                "linked": false
            }))
            .unwrap();
        let (info, table) = release_target_detail(&resp);
        assert_eq!(info["linked"], false);
        assert!(table.contains("no"));
    }

    // ---- wiremock handler tests: new ops ----

    #[tokio::test]
    async fn handler_get_rule() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/promotion-rules/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(rule_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = get_rule(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_update_rule() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("PUT"))
            .and(path(format!("/api/v1/promotion-rules/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(rule_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let update = RuleUpdate {
            name: Some("renamed".to_string()),
            auto: Some(true),
            enabled: None,
            min_staging_hours: Some(12),
            max_artifact_age_days: None,
            max_cve_severity: Some("high".to_string()),
            min_health_score: None,
            allowed_licenses: Some(vec!["MIT".to_string()]),
            require_signature: Some(true),
        };
        let result = update_rule(NIL_UUID, update, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_evaluate_rule() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!("/api/v1/promotion-rules/{NIL_UUID}/evaluate")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "rule_id": NIL_UUID,
                "rule_name": "staging-to-prod",
                "total_artifacts": 2_u64,
                "passed": 1_u64,
                "failed": 1_u64,
                "results": [
                    { "artifact_id": NIL_UUID, "passed": true, "violations": [] },
                    { "artifact_id": NIL_UUID, "passed": false, "violations": ["cve too high"] }
                ]
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = evaluate_rule(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_bulk_promote() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/promotion/repositories/staging/promote"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "total": 2_u64,
                "promoted": 2_u64,
                "failed": 0_u64,
                "results": [
                    {
                        "promoted": true,
                        "source": "staging",
                        "target": "releases",
                        "promotion_id": NIL_UUID,
                        "policy_violations": []
                    },
                    {
                        "promoted": true,
                        "source": "staging",
                        "target": "releases",
                        "promotion_id": NIL_UUID,
                        "policy_violations": []
                    }
                ]
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let ids = vec![NIL_UUID.to_string(), NIL_UUID.to_string()];
        let result = bulk_promote("staging", &ids, Some("releases"), None, false, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_bulk_promote_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/promotion/repositories/staging/promote"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "total": 1_u64,
                "promoted": 1_u64,
                "failed": 0_u64,
                "results": [{
                    "promoted": true,
                    "source": "staging",
                    "target": "releases",
                    "promotion_id": NIL_UUID,
                    "policy_violations": []
                }]
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let ids = vec![NIL_UUID.to_string()];
        let result = bulk_promote("staging", &ids, None, None, false, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_reject_artifact() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/promotion/repositories/staging/artifacts/{NIL_UUID}/reject"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "rejected": true,
                "rejection_id": NIL_UUID,
                "artifact_id": NIL_UUID,
                "source": "staging",
                "reason": "cve too high"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = reject_artifact("staging", NIL_UUID, "cve too high", None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_get_release_target() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path(
                "/api/v1/promotion/repositories/maven-staging/release-target",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "linked": true,
                "release_repository_id": NIL_UUID,
                "release_repository_key": "maven-releases"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = get_release_target("maven-staging", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_set_release_target_link() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("PUT"))
            .and(path(
                "/api/v1/promotion/repositories/maven-staging/release-target",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "linked": true,
                "release_repository_id": NIL_UUID,
                "release_repository_key": "maven-releases"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Table);
        let result = set_release_target("maven-staging", Some("maven-releases"), &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_set_release_target_unlink() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("PUT"))
            .and(path(
                "/api/v1/promotion/repositories/maven-staging/release-target",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "linked": false
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = set_release_target("maven-staging", None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    // ---- insta snapshot tests ----

    #[test]
    fn snapshot_promotion_rule_json() {
        let items = vec![rule_json()];
        let output = crate::output::render(&items, &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("promotion_rule_json", parsed);
    }
}
