use artifact_keeper_sdk::ClientPromotionExt;
use clap::Subcommand;
use miette::Result;

use super::client::client_for;
use super::helpers::{confirm_action, new_table, parse_uuid, print_page_info, sdk_err, short_id};
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

    /// Manage promotion rules
    Rule {
        #[command(subcommand)]
        command: PromotionRuleCommand,
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

    /// Delete a promotion rule
    Delete {
        /// Rule ID
        id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
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
            Self::Rule { command } => match command {
                PromotionRuleCommand::List { from } => list_rules(from.as_deref(), global).await,
                PromotionRuleCommand::Create {
                    name,
                    from,
                    to,
                    auto,
                } => create_rule(&name, &from, &to, auto, global).await,
                PromotionRuleCommand::Delete { id, yes } => delete_rule(&id, yes, global).await,
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
        target_repository: to.to_string(),
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

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", rule.id);
        return Ok(());
    }

    eprintln!("Promotion rule '{}' created (ID: {}).", rule.name, rule.id);

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
    eprintln!("Promotion rule {id} deleted.");

    Ok(())
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
