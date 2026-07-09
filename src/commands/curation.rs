use artifact_keeper_sdk::ClientCurationExt;
use clap::Subcommand;
use futures::StreamExt;
use miette::Result;

use super::client::{client_for, client_for_optional_auth};
use super::helpers::{confirm_action, new_table, parse_optional_uuid, parse_uuid, sdk_err};
use crate::cli::GlobalArgs;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum CurationCommand {
    /// List packages awaiting curation in a staging repository
    Packages {
        /// Staging repository ID (UUID)
        #[arg(long, visible_alias = "staging-repo-id")]
        staging_repo: String,

        /// Filter by curation status (e.g. pending, approved, blocked)
        #[arg(long)]
        status: Option<String>,

        /// Maximum number of packages to return
        #[arg(long)]
        limit: Option<i64>,

        /// Number of packages to skip
        #[arg(long)]
        offset: Option<i64>,
    },

    /// Show a single curation package
    Package {
        /// Package ID (UUID)
        id: String,
    },

    /// Approve a single package for release
    Approve {
        /// Package ID (UUID)
        id: String,
    },

    /// Block a single package from release
    Block {
        /// Package ID (UUID)
        id: String,
    },

    /// Approve multiple packages in one request
    BulkApprove {
        /// Package IDs (UUIDs) to approve
        #[arg(required = true)]
        ids: Vec<String>,

        /// Reason for the bulk decision
        #[arg(long)]
        reason: String,
    },

    /// Block multiple packages in one request
    BulkBlock {
        /// Package IDs (UUIDs) to block
        #[arg(required = true)]
        ids: Vec<String>,

        /// Reason for the bulk decision
        #[arg(long)]
        reason: String,
    },

    /// Re-evaluate all pending packages in a staging repo against the rules
    ReEvaluate {
        /// Staging repository ID (UUID)
        #[arg(long, visible_alias = "staging-repo-id")]
        staging_repo: String,

        /// Default action for packages that match no rule (e.g. approve, block)
        #[arg(long)]
        default_action: String,
    },

    /// List curation rules
    Rules {
        /// Filter by staging repository ID (UUID)
        #[arg(long, visible_alias = "staging-repo-id")]
        staging_repo: Option<String>,
    },

    /// Show a single curation rule
    Rule {
        /// Rule ID (UUID)
        id: String,
    },

    /// Create a curation rule
    CreateRule {
        /// Package name pattern the rule matches (glob)
        package_pattern: String,

        /// Action to take on a match (e.g. approve, block)
        #[arg(long)]
        action: String,

        /// Human-readable reason for the rule
        #[arg(long)]
        reason: String,

        /// Restrict the rule to a staging repository ID (UUID)
        #[arg(long, visible_alias = "staging-repo-id")]
        staging_repo: Option<String>,

        /// Restrict the rule to an architecture
        #[arg(long)]
        architecture: Option<String>,

        /// Rule priority (higher wins)
        #[arg(long)]
        priority: Option<i32>,

        /// Version constraint the rule applies to
        #[arg(long)]
        version_constraint: Option<String>,
    },

    /// Update an existing curation rule
    UpdateRule {
        /// Rule ID (UUID)
        id: String,

        /// Action to take on a match (e.g. approve, block)
        #[arg(long)]
        action: String,

        /// Package name pattern the rule matches (glob)
        #[arg(long)]
        package_pattern: String,

        /// Human-readable reason for the rule
        #[arg(long)]
        reason: String,

        /// Enable the rule
        #[arg(long, conflicts_with = "disabled")]
        enabled: bool,

        /// Disable the rule
        #[arg(long, conflicts_with = "enabled")]
        disabled: bool,

        /// Restrict the rule to an architecture
        #[arg(long)]
        architecture: Option<String>,

        /// Rule priority (higher wins)
        #[arg(long)]
        priority: Option<i32>,

        /// Version constraint the rule applies to
        #[arg(long)]
        version_constraint: Option<String>,
    },

    /// Delete a curation rule
    DeleteRule {
        /// Rule ID (UUID)
        id: String,

        /// Skip the confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Show curation statistics for a staging repository
    Stats {
        /// Staging repository ID (UUID)
        #[arg(long, visible_alias = "staging-repo-id")]
        staging_repo: String,
    },
}

impl CurationCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Packages {
                staging_repo,
                status,
                limit,
                offset,
            } => list_packages(&staging_repo, status.as_deref(), limit, offset, global).await,
            Self::Package { id } => show_package(&id, global).await,
            Self::Approve { id } => package_decision(&id, true, global).await,
            Self::Block { id } => package_decision(&id, false, global).await,
            Self::BulkApprove { ids, reason } => bulk_decision(&ids, &reason, true, global).await,
            Self::BulkBlock { ids, reason } => bulk_decision(&ids, &reason, false, global).await,
            Self::ReEvaluate {
                staging_repo,
                default_action,
            } => re_evaluate(&staging_repo, &default_action, global).await,
            Self::Rules { staging_repo } => list_rules(staging_repo.as_deref(), global).await,
            Self::Rule { id } => show_rule(&id, global).await,
            Self::CreateRule {
                package_pattern,
                action,
                reason,
                staging_repo,
                architecture,
                priority,
                version_constraint,
            } => {
                create_rule(
                    &package_pattern,
                    &action,
                    &reason,
                    staging_repo.as_deref(),
                    architecture.as_deref(),
                    priority,
                    version_constraint.as_deref(),
                    global,
                )
                .await
            }
            Self::UpdateRule {
                id,
                action,
                package_pattern,
                reason,
                enabled,
                disabled,
                architecture,
                priority,
                version_constraint,
            } => {
                update_rule(
                    &id,
                    &action,
                    &package_pattern,
                    &reason,
                    enabled,
                    disabled,
                    architecture.as_deref(),
                    priority,
                    version_constraint.as_deref(),
                    global,
                )
                .await
            }
            Self::DeleteRule { id, yes } => delete_rule(&id, yes, global).await,
            Self::Stats { staging_repo } => show_stats(&staging_repo, global).await,
        }
    }
}

// ---------------------------------------------------------------------------
// Packages
// ---------------------------------------------------------------------------

async fn list_packages(
    staging_repo: &str,
    status: Option<&str>,
    limit: Option<i64>,
    offset: Option<i64>,
    global: &GlobalArgs,
) -> Result<()> {
    let staging_id = parse_uuid(staging_repo, "staging repository")?;

    let client = client_for_optional_auth(global)?;
    let spinner = output::spinner("Fetching curation packages...");

    let mut req = client.list_curation_packages().staging_repo_id(staging_id);
    if let Some(s) = status {
        req = req.status(s);
    }
    if let Some(l) = limit {
        req = req.limit(l);
    }
    if let Some(o) = offset {
        req = req.offset(o);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| sdk_err("list curation packages", e))?;
    let packages = resp.into_inner();

    spinner.finish_and_clear();

    if packages.is_empty() {
        eprintln!("No curation packages found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for p in &packages {
            println!("{}", p.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = packages
        .iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id.to_string(),
                "name": p.name,
                "version": p.version,
                "format": p.format,
                "repository_key": p.repository_key,
                "size_bytes": p.size_bytes,
                "download_count": p.download_count,
                "created_at": p.created_at.to_rfc3339(),
            })
        })
        .collect();

    let table_str = format_packages_table(&entries);
    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn show_package(id: &str, global: &GlobalArgs) -> Result<()> {
    let package_id = parse_uuid(id, "package")?;

    let client = client_for_optional_auth(global)?;
    let spinner = output::spinner("Fetching curation package...");

    let resp = client
        .get_curation_package()
        .id(package_id)
        .send()
        .await
        .map_err(|e| sdk_err("get curation package", e))?;
    let package = resp.into_inner();

    spinner.finish_and_clear();

    let info = package_json(&package);
    let table_str = format_package_detail(&info);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn package_decision(id: &str, approve: bool, global: &GlobalArgs) -> Result<()> {
    let package_id = parse_uuid(id, "package")?;

    let client = client_for(global)?;
    let action = if approve { "Approving" } else { "Blocking" };
    let spinner = output::spinner(&format!("{action} package..."));

    let resp = if approve {
        client
            .approve_package()
            .id(package_id)
            .send()
            .await
            .map_err(|e| sdk_err("approve package", e))?
    } else {
        client
            .block_package()
            .id(package_id)
            .send()
            .await
            .map_err(|e| sdk_err("block package", e))?
    };
    let package = resp.into_inner();

    spinner.finish_and_clear();

    let verb = if approve { "approved" } else { "blocked" };
    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", package.id);
        return Ok(());
    }
    if matches!(global.format, OutputFormat::Json | OutputFormat::Yaml) {
        let info = package_json(&package);
        println!("{}", output::render(&info, &global.format, None));
        return Ok(());
    }
    eprintln!(
        "Package {verb}: {} {} ({}).",
        package.name, package.version, package.id
    );

    Ok(())
}

async fn bulk_decision(
    ids: &[String],
    reason: &str,
    approve: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let parsed: Vec<uuid::Uuid> = ids
        .iter()
        .map(|s| parse_uuid(s, "package"))
        .collect::<Result<_>>()?;

    let client = client_for(global)?;
    let action = if approve { "Approving" } else { "Blocking" };
    let spinner = output::spinner(&format!("{action} packages..."));

    let body = artifact_keeper_sdk::types::BulkStatusRequest {
        ids: parsed,
        reason: reason.to_string(),
    };

    let resp = if approve {
        client
            .bulk_approve()
            .body(body)
            .send()
            .await
            .map_err(|e| sdk_err("bulk approve packages", e))?
    } else {
        client
            .bulk_block()
            .body(body)
            .send()
            .await
            .map_err(|e| sdk_err("bulk block packages", e))?
    };

    let body = drain_stream(resp).await?;
    spinner.finish_and_clear();
    emit_stream_result(&body, ids.len(), approve, global);

    Ok(())
}

async fn re_evaluate(staging_repo: &str, default_action: &str, global: &GlobalArgs) -> Result<()> {
    let staging_id = parse_uuid(staging_repo, "staging repository")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Re-evaluating packages against curation rules...");

    let body = artifact_keeper_sdk::types::ReEvaluateRequest {
        staging_repo_id: staging_id,
        default_action: default_action.to_string(),
    };

    let resp = client
        .re_evaluate()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("re-evaluate curation packages", e))?;

    let body = drain_stream(resp).await?;
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Json | OutputFormat::Yaml) {
        print_stream_body(&body, global);
    } else {
        eprintln!("Re-evaluation complete for staging repo {staging_repo}.");
        if !body.trim().is_empty() {
            eprintln!("{}", body.trim());
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

async fn list_rules(staging_repo: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let staging_id = parse_optional_uuid(staging_repo, "staging repository")?;

    let client = client_for_optional_auth(global)?;
    let spinner = output::spinner("Fetching curation rules...");

    let mut req = client.list_curation_rules();
    if let Some(id) = staging_id {
        req = req.staging_repo_id(id);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| sdk_err("list curation rules", e))?;
    let rules = resp.into_inner();

    spinner.finish_and_clear();

    if rules.is_empty() {
        eprintln!("No curation rules found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for r in &rules {
            println!("{}", r.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = rules.iter().map(rule_json).collect();

    let table_str = format_rules_table(&entries);
    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn show_rule(id: &str, global: &GlobalArgs) -> Result<()> {
    let rule_id = parse_uuid(id, "rule")?;

    let client = client_for_optional_auth(global)?;
    let spinner = output::spinner("Fetching curation rule...");

    let resp = client
        .get_curation_rule()
        .id(rule_id)
        .send()
        .await
        .map_err(|e| sdk_err("get curation rule", e))?;
    let rule = resp.into_inner();

    spinner.finish_and_clear();

    let info = rule_json(&rule);
    let table_str = format_rule_detail(&info);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn create_rule(
    package_pattern: &str,
    action: &str,
    reason: &str,
    staging_repo: Option<&str>,
    architecture: Option<&str>,
    priority: Option<i32>,
    version_constraint: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let staging_id = parse_optional_uuid(staging_repo, "staging repository")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Creating curation rule...");

    let body = artifact_keeper_sdk::types::CurationCreateRuleRequest {
        action: action.to_string(),
        package_pattern: package_pattern.to_string(),
        reason: reason.to_string(),
        staging_repo_id: staging_id,
        architecture: architecture.map(|s| s.to_string()),
        priority,
        version_constraint: version_constraint.map(|s| s.to_string()),
    };

    let resp = client
        .create_curation_rule()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("create curation rule", e))?;
    let rule = resp.into_inner();

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", rule.id);
        return Ok(());
    }
    if matches!(global.format, OutputFormat::Json | OutputFormat::Yaml) {
        let info = rule_json(&rule);
        println!("{}", output::render(&info, &global.format, None));
        return Ok(());
    }
    eprintln!(
        "Created rule {} ({} -> {}).",
        rule.id, rule.package_pattern, rule.action
    );

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn update_rule(
    id: &str,
    action: &str,
    package_pattern: &str,
    reason: &str,
    enabled: bool,
    disabled: bool,
    architecture: Option<&str>,
    priority: Option<i32>,
    version_constraint: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let rule_id = parse_uuid(id, "rule")?;

    // Only set `enabled` when the user explicitly asked for it.
    let enabled_flag = if enabled {
        Some(true)
    } else if disabled {
        Some(false)
    } else {
        None
    };

    let client = client_for(global)?;
    let spinner = output::spinner("Updating curation rule...");

    let body = artifact_keeper_sdk::types::CurationUpdateRuleRequest {
        action: action.to_string(),
        package_pattern: package_pattern.to_string(),
        reason: reason.to_string(),
        enabled: enabled_flag,
        architecture: architecture.map(|s| s.to_string()),
        priority,
        version_constraint: version_constraint.map(|s| s.to_string()),
    };

    let resp = client
        .update_curation_rule()
        .id(rule_id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("update curation rule", e))?;
    let rule = resp.into_inner();

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", rule.id);
        return Ok(());
    }
    if matches!(global.format, OutputFormat::Json | OutputFormat::Yaml) {
        let info = rule_json(&rule);
        println!("{}", output::render(&info, &global.format, None));
        return Ok(());
    }
    eprintln!(
        "Updated rule {} ({} -> {}, enabled: {}).",
        rule.id, rule.package_pattern, rule.action, rule.enabled
    );

    Ok(())
}

async fn delete_rule(id: &str, yes: bool, global: &GlobalArgs) -> Result<()> {
    let rule_id = parse_uuid(id, "rule")?;

    if !confirm_action(&format!("Delete curation rule {id}?"), yes, global.no_input)? {
        return Ok(());
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Deleting curation rule...");

    client
        .delete_curation_rule()
        .id(rule_id)
        .send()
        .await
        .map_err(|e| sdk_err("delete curation rule", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{id}");
    } else if matches!(global.format, OutputFormat::Json | OutputFormat::Yaml) {
        let info = serde_json::json!({ "id": id, "status": "deleted" });
        println!("{}", output::render(&info, &global.format, None));
    } else {
        eprintln!("Rule {id} deleted.");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

async fn show_stats(staging_repo: &str, global: &GlobalArgs) -> Result<()> {
    let staging_id = parse_uuid(staging_repo, "staging repository")?;

    let client = client_for_optional_auth(global)?;
    let spinner = output::spinner("Fetching curation statistics...");

    let resp = client
        .stats()
        .staging_repo_id(staging_id)
        .send()
        .await
        .map_err(|e| sdk_err("get curation stats", e))?;
    let stats = resp.into_inner();

    spinner.finish_and_clear();

    let counts: Vec<_> = stats
        .counts
        .iter()
        .map(|c| {
            serde_json::json!({
                "status": c.status,
                "count": c.count,
            })
        })
        .collect();

    let info = serde_json::json!({
        "staging_repo_id": stats.staging_repo_id.to_string(),
        "counts": counts,
    });

    let table_str = format_stats_table(&stats.staging_repo_id.to_string(), &counts);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

// ---------------------------------------------------------------------------
// ByteStream helpers
// ---------------------------------------------------------------------------

/// Collect a streaming SDK response body into a UTF-8 string.
async fn drain_stream(
    resp: artifact_keeper_sdk::ResponseValue<artifact_keeper_sdk::ByteStream>,
) -> Result<String> {
    let mut stream = resp.into_inner();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| sdk_err("read curation response", e))?;
        buf.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Pretty-print a raw JSON body honoring the output format.
fn print_stream_body(body: &str, global: &GlobalArgs) {
    match serde_json::from_str::<serde_json::Value>(body) {
        Ok(value) => println!("{}", output::render(&value, &global.format, None)),
        Err(_) => println!("{}", body.trim()),
    }
}

/// Emit the result of a bulk approve/block honoring the output format.
fn emit_stream_result(body: &str, requested: usize, approve: bool, global: &GlobalArgs) {
    match global.format {
        OutputFormat::Json | OutputFormat::Yaml => print_stream_body(body, global),
        OutputFormat::Quiet => {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(body) {
                println!("{value}");
            }
        }
        OutputFormat::Table => {
            let verb = if approve { "approved" } else { "blocked" };
            eprintln!("Bulk {verb} {requested} package(s).");
            if !body.trim().is_empty() {
                eprintln!("{}", body.trim());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// JSON projections
// ---------------------------------------------------------------------------

fn package_json(p: &artifact_keeper_sdk::types::PackageResponse) -> serde_json::Value {
    serde_json::json!({
        "id": p.id.to_string(),
        "name": p.name,
        "version": p.version,
        "format": p.format,
        "repository_key": p.repository_key,
        "description": p.description,
        "size_bytes": p.size_bytes,
        "download_count": p.download_count,
        "created_at": p.created_at.to_rfc3339(),
        "updated_at": p.updated_at.to_rfc3339(),
        "metadata": p.metadata,
    })
}

fn rule_json(r: &artifact_keeper_sdk::types::RuleResponse) -> serde_json::Value {
    serde_json::json!({
        "id": r.id.to_string(),
        "package_pattern": r.package_pattern,
        "version_constraint": r.version_constraint,
        "architecture": r.architecture,
        "action": r.action,
        "priority": r.priority,
        "reason": r.reason,
        "enabled": r.enabled,
        "staging_repo_id": r.staging_repo_id.map(|u| u.to_string()),
        "created_by": r.created_by.map(|u| u.to_string()),
        "created_at": r.created_at,
        "updated_at": r.updated_at,
    })
}

// ---------------------------------------------------------------------------
// Table formatting
// ---------------------------------------------------------------------------

fn short8(s: &str) -> &str {
    if s.len() >= 8 { &s[..8] } else { s }
}

fn format_packages_table(items: &[serde_json::Value]) -> String {
    let mut table = new_table(vec![
        "ID",
        "NAME",
        "VERSION",
        "FORMAT",
        "REPOSITORY",
        "SIZE",
        "DOWNLOADS",
    ]);
    for p in items {
        table.add_row(vec![
            short8(p["id"].as_str().unwrap_or("-")),
            p["name"].as_str().unwrap_or("-"),
            p["version"].as_str().unwrap_or("-"),
            p["format"].as_str().unwrap_or("-"),
            p["repository_key"].as_str().unwrap_or("-"),
            &p["size_bytes"].as_i64().unwrap_or(0).to_string(),
            &p["download_count"].as_i64().unwrap_or(0).to_string(),
        ]);
    }
    table.to_string()
}

fn format_package_detail(item: &serde_json::Value) -> String {
    format!(
        "ID:             {}\n\
         Name:           {}\n\
         Version:        {}\n\
         Format:         {}\n\
         Repository:     {}\n\
         Description:    {}\n\
         Size (bytes):   {}\n\
         Downloads:      {}\n\
         Created At:     {}\n\
         Updated At:     {}",
        item["id"].as_str().unwrap_or("-"),
        item["name"].as_str().unwrap_or("-"),
        item["version"].as_str().unwrap_or("-"),
        item["format"].as_str().unwrap_or("-"),
        item["repository_key"].as_str().unwrap_or("-"),
        item["description"].as_str().unwrap_or("-"),
        item["size_bytes"].as_i64().unwrap_or(0),
        item["download_count"].as_i64().unwrap_or(0),
        item["created_at"].as_str().unwrap_or("-"),
        item["updated_at"].as_str().unwrap_or("-"),
    )
}

fn format_rules_table(items: &[serde_json::Value]) -> String {
    let mut table = new_table(vec![
        "ID", "PATTERN", "VERSION", "ARCH", "ACTION", "PRIORITY", "ENABLED",
    ]);
    for r in items {
        table.add_row(vec![
            short8(r["id"].as_str().unwrap_or("-")),
            r["package_pattern"].as_str().unwrap_or("-"),
            r["version_constraint"].as_str().unwrap_or("-"),
            r["architecture"].as_str().unwrap_or("-"),
            r["action"].as_str().unwrap_or("-"),
            &r["priority"].as_i64().unwrap_or(0).to_string(),
            if r["enabled"].as_bool().unwrap_or(false) {
                "yes"
            } else {
                "no"
            },
        ]);
    }
    table.to_string()
}

fn format_rule_detail(item: &serde_json::Value) -> String {
    format!(
        "ID:                 {}\n\
         Package Pattern:    {}\n\
         Version Constraint: {}\n\
         Architecture:       {}\n\
         Action:             {}\n\
         Priority:           {}\n\
         Reason:             {}\n\
         Enabled:            {}\n\
         Staging Repo:       {}\n\
         Created By:         {}\n\
         Created At:         {}\n\
         Updated At:         {}",
        item["id"].as_str().unwrap_or("-"),
        item["package_pattern"].as_str().unwrap_or("-"),
        item["version_constraint"].as_str().unwrap_or("-"),
        item["architecture"].as_str().unwrap_or("-"),
        item["action"].as_str().unwrap_or("-"),
        item["priority"].as_i64().unwrap_or(0),
        item["reason"].as_str().unwrap_or("-"),
        if item["enabled"].as_bool().unwrap_or(false) {
            "yes"
        } else {
            "no"
        },
        item["staging_repo_id"].as_str().unwrap_or("-"),
        item["created_by"].as_str().unwrap_or("-"),
        item["created_at"].as_str().unwrap_or("-"),
        item["updated_at"].as_str().unwrap_or("-"),
    )
}

fn format_stats_table(staging_repo_id: &str, counts: &[serde_json::Value]) -> String {
    let mut table = new_table(vec!["STATUS", "COUNT"]);
    for c in counts {
        table.add_row(vec![
            c["status"].as_str().unwrap_or("-"),
            &c["count"].as_i64().unwrap_or(0).to_string(),
        ]);
    }
    format!("Staging Repo: {staging_repo_id}\n{}", table)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use serde_json::json;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: CurationCommand,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).unwrap()
    }

    fn try_parse(args: &[&str]) -> Result<TestCli, clap::Error> {
        TestCli::try_parse_from(args)
    }

    static NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

    // ---- parsing ----

    #[test]
    fn parse_packages_defaults() {
        let cli = parse(&["test", "packages", "--staging-repo", NIL_UUID]);
        match cli.command {
            CurationCommand::Packages {
                staging_repo,
                status,
                limit,
                offset,
            } => {
                assert_eq!(staging_repo, NIL_UUID);
                assert!(status.is_none());
                assert!(limit.is_none());
                assert!(offset.is_none());
            }
            _ => panic!("expected Packages"),
        }
    }

    #[test]
    fn parse_packages_with_filters() {
        let cli = parse(&[
            "test",
            "packages",
            "--staging-repo",
            NIL_UUID,
            "--status",
            "pending",
            "--limit",
            "10",
            "--offset",
            "5",
        ]);
        match cli.command {
            CurationCommand::Packages {
                status,
                limit,
                offset,
                ..
            } => {
                assert_eq!(status.as_deref(), Some("pending"));
                assert_eq!(limit, Some(10));
                assert_eq!(offset, Some(5));
            }
            _ => panic!("expected Packages"),
        }
    }

    #[test]
    fn parse_packages_missing_staging_repo() {
        assert!(try_parse(&["test", "packages"]).is_err());
    }

    #[test]
    fn parse_package_show() {
        let cli = parse(&["test", "package", NIL_UUID]);
        assert!(matches!(cli.command, CurationCommand::Package { .. }));
    }

    #[test]
    fn parse_approve_and_block() {
        assert!(matches!(
            parse(&["test", "approve", NIL_UUID]).command,
            CurationCommand::Approve { .. }
        ));
        assert!(matches!(
            parse(&["test", "block", NIL_UUID]).command,
            CurationCommand::Block { .. }
        ));
    }

    #[test]
    fn parse_bulk_approve() {
        let cli = parse(&[
            "test",
            "bulk-approve",
            NIL_UUID,
            "11111111-1111-1111-1111-111111111111",
            "--reason",
            "Vetted",
        ]);
        match cli.command {
            CurationCommand::BulkApprove { ids, reason } => {
                assert_eq!(ids.len(), 2);
                assert_eq!(reason, "Vetted");
            }
            _ => panic!("expected BulkApprove"),
        }
    }

    #[test]
    fn parse_bulk_approve_requires_ids() {
        assert!(try_parse(&["test", "bulk-approve", "--reason", "x"]).is_err());
    }

    #[test]
    fn parse_bulk_approve_requires_reason() {
        assert!(try_parse(&["test", "bulk-approve", NIL_UUID]).is_err());
    }

    #[test]
    fn parse_re_evaluate() {
        let cli = parse(&[
            "test",
            "re-evaluate",
            "--staging-repo",
            NIL_UUID,
            "--default-action",
            "block",
        ]);
        match cli.command {
            CurationCommand::ReEvaluate {
                staging_repo,
                default_action,
            } => {
                assert_eq!(staging_repo, NIL_UUID);
                assert_eq!(default_action, "block");
            }
            _ => panic!("expected ReEvaluate"),
        }
    }

    #[test]
    fn parse_rules_optional_filter() {
        let cli = parse(&["test", "rules"]);
        match cli.command {
            CurationCommand::Rules { staging_repo } => assert!(staging_repo.is_none()),
            _ => panic!("expected Rules"),
        }
        let cli = parse(&["test", "rules", "--staging-repo", NIL_UUID]);
        match cli.command {
            CurationCommand::Rules { staging_repo } => {
                assert_eq!(staging_repo.as_deref(), Some(NIL_UUID))
            }
            _ => panic!("expected Rules"),
        }
    }

    #[test]
    fn parse_create_rule() {
        let cli = parse(&[
            "test",
            "create-rule",
            "lodash*",
            "--action",
            "block",
            "--reason",
            "banned",
            "--priority",
            "10",
        ]);
        match cli.command {
            CurationCommand::CreateRule {
                package_pattern,
                action,
                reason,
                priority,
                ..
            } => {
                assert_eq!(package_pattern, "lodash*");
                assert_eq!(action, "block");
                assert_eq!(reason, "banned");
                assert_eq!(priority, Some(10));
            }
            _ => panic!("expected CreateRule"),
        }
    }

    #[test]
    fn parse_create_rule_missing_action() {
        assert!(try_parse(&["test", "create-rule", "lodash*", "--reason", "x"]).is_err());
    }

    #[test]
    fn parse_update_rule_enabled() {
        let cli = parse(&[
            "test",
            "update-rule",
            NIL_UUID,
            "--action",
            "approve",
            "--package-pattern",
            "left-pad*",
            "--reason",
            "ok",
            "--enabled",
        ]);
        match cli.command {
            CurationCommand::UpdateRule {
                enabled, disabled, ..
            } => {
                assert!(enabled);
                assert!(!disabled);
            }
            _ => panic!("expected UpdateRule"),
        }
    }

    #[test]
    fn parse_update_rule_enabled_disabled_conflict() {
        assert!(
            try_parse(&[
                "test",
                "update-rule",
                NIL_UUID,
                "--action",
                "approve",
                "--package-pattern",
                "x",
                "--reason",
                "y",
                "--enabled",
                "--disabled",
            ])
            .is_err()
        );
    }

    #[test]
    fn parse_delete_rule_yes() {
        let cli = parse(&["test", "delete-rule", NIL_UUID, "-y"]);
        match cli.command {
            CurationCommand::DeleteRule { yes, .. } => assert!(yes),
            _ => panic!("expected DeleteRule"),
        }
    }

    #[test]
    fn parse_stats() {
        let cli = parse(&["test", "stats", "--staging-repo", NIL_UUID]);
        assert!(matches!(cli.command, CurationCommand::Stats { .. }));
    }

    // ---- format functions ----

    fn package_sample() -> serde_json::Value {
        json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "name": "left-pad",
            "version": "1.3.0",
            "format": "npm",
            "repository_key": "npm-staging",
            "description": "pads strings",
            "size_bytes": 1024,
            "download_count": 7,
            "created_at": "2026-07-01T12:00:00Z",
            "updated_at": "2026-07-02T12:00:00Z",
            "metadata": {},
        })
    }

    fn rule_sample() -> serde_json::Value {
        json!({
            "id": "00000000-0000-0000-0000-000000000002",
            "package_pattern": "lodash*",
            "version_constraint": "*",
            "architecture": "any",
            "action": "block",
            "priority": 10,
            "reason": "banned",
            "enabled": true,
            "staging_repo_id": "00000000-0000-0000-0000-000000000003",
            "created_by": null,
            "created_at": "2026-07-01T12:00:00Z",
            "updated_at": "2026-07-01T12:00:00Z",
        })
    }

    #[test]
    fn format_packages_table_renders() {
        let table = format_packages_table(&[package_sample()]);
        assert!(table.contains("00000000"));
        assert!(table.contains("left-pad"));
        assert!(table.contains("npm"));
    }

    #[test]
    fn format_package_detail_renders() {
        let detail = format_package_detail(&package_sample());
        assert!(detail.contains("left-pad"));
        assert!(detail.contains("1.3.0"));
        assert!(detail.contains("Downloads:"));
    }

    #[test]
    fn format_rules_table_renders() {
        let table = format_rules_table(&[rule_sample()]);
        assert!(table.contains("lodash*"));
        assert!(table.contains("block"));
        assert!(table.contains("yes"));
    }

    #[test]
    fn format_rule_detail_renders() {
        let detail = format_rule_detail(&rule_sample());
        assert!(detail.contains("lodash*"));
        assert!(detail.contains("banned"));
        assert!(detail.contains("Enabled:"));
    }

    #[test]
    fn format_stats_table_renders() {
        let counts = vec![
            json!({ "status": "pending", "count": 3 }),
            json!({ "status": "approved", "count": 5 }),
        ];
        let table = format_stats_table("00000000-0000-0000-0000-000000000003", &counts);
        assert!(table.contains("pending"));
        assert!(table.contains("approved"));
        assert!(table.contains("Staging Repo:"));
    }

    #[test]
    fn short8_truncates() {
        assert_eq!(short8("0123456789"), "01234567");
        assert_eq!(short8("abc"), "abc");
    }

    // ---- wiremock handler tests ----

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    fn package_body() -> serde_json::Value {
        json!({
            "id": NIL_UUID,
            "name": "left-pad",
            "version": "1.3.0",
            "format": "npm",
            "repository_key": "npm-staging",
            "description": null,
            "size_bytes": 1024,
            "download_count": 7,
            "created_at": "2026-07-01T12:00:00Z",
            "updated_at": "2026-07-02T12:00:00Z",
            "metadata": {}
        })
    }

    fn rule_body() -> serde_json::Value {
        json!({
            "id": NIL_UUID,
            "package_pattern": "lodash*",
            "version_constraint": "*",
            "architecture": "any",
            "action": "block",
            "priority": 10,
            "reason": "banned",
            "enabled": true,
            "staging_repo_id": null,
            "created_by": null,
            "created_at": "2026-07-01T12:00:00Z",
            "updated_at": "2026-07-01T12:00:00Z"
        })
    }

    #[tokio::test]
    async fn handler_list_packages() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/curation/packages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([package_body()])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list_packages(NIL_UUID, Some("pending"), Some(10), None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_packages_empty_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/curation/packages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = list_packages(NIL_UUID, None, None, None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_package() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/curation/packages/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(package_body()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = show_package(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_approve_package() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/curation/packages/{NIL_UUID}/approve"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(package_body()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = package_decision(NIL_UUID, true, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_block_package() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!("/api/v1/curation/packages/{NIL_UUID}/block")))
            .respond_with(ResponseTemplate::new(200).set_body_json(package_body()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = package_decision(NIL_UUID, false, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_bulk_approve() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/curation/packages/bulk-approve"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "updated": 2 })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = bulk_decision(
            &[NIL_UUID.to_string(), NIL_UUID.to_string()],
            "Vetted",
            true,
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_re_evaluate() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/curation/packages/re-evaluate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "re_evaluated": 4 })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = re_evaluate(NIL_UUID, "block", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_rules() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/curation/rules"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([rule_body()])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list_rules(None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_rule() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/curation/rules/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(rule_body()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = show_rule(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_create_rule() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/curation/rules"))
            .respond_with(ResponseTemplate::new(201).set_body_json(rule_body()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = create_rule(
            "lodash*",
            "block",
            "banned",
            None,
            None,
            Some(10),
            None,
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_update_rule() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("PUT"))
            .and(path(format!("/api/v1/curation/rules/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(rule_body()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = update_rule(
            NIL_UUID,
            "approve",
            "left-pad*",
            "ok",
            true,
            false,
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
    async fn handler_delete_rule() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/curation/rules/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = delete_rule(NIL_UUID, true, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_stats() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/curation/stats"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "staging_repo_id": NIL_UUID,
                "counts": [
                    { "status": "pending", "count": 3 },
                    { "status": "approved", "count": 5 }
                ]
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = show_stats(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }
}
