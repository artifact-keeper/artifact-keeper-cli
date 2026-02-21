use artifact_keeper_sdk::{ClientRepositoriesExt, ClientSecurityExt};
use clap::Subcommand;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use console::style;
use miette::Result;

use super::client::client_for;
use super::helpers::{confirm_action, parse_optional_uuid, parse_uuid};
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum ScanCommand {
    /// Trigger a security scan on an artifact
    Run {
        /// Repository key
        repo: String,
        /// Artifact path
        path: String,
    },

    /// List recent scan results
    List {
        /// Filter by repository
        #[arg(long)]
        repo: Option<String>,

        /// Page number
        #[arg(long, default_value = "1")]
        page: i64,

        /// Results per page
        #[arg(long, default_value = "20")]
        per_page: i64,
    },

    /// Show scan findings (vulnerabilities)
    Show {
        /// Scan ID
        id: String,

        /// Filter by minimum severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        #[arg(long)]
        severity: Option<String>,

        /// Page number
        #[arg(long, default_value = "1")]
        page: i64,

        /// Results per page
        #[arg(long, default_value = "50")]
        per_page: i64,
    },

    /// View security dashboard overview
    Dashboard,

    /// List security scores for all repositories
    Scores,

    /// Manage scan configurations
    Config {
        #[command(subcommand)]
        command: ScanConfigCommand,
    },

    /// Manage scan findings (acknowledge/revoke)
    Finding {
        #[command(subcommand)]
        command: ScanFindingCommand,
    },

    /// Manage security policies
    Policy {
        #[command(subcommand)]
        command: ScanPolicyCommand,
    },

    /// Manage repository security settings
    Security {
        #[command(subcommand)]
        command: ScanSecurityCommand,
    },
}

#[derive(Subcommand)]
pub enum ScanConfigCommand {
    /// List all scan configurations
    List,
}

#[derive(Subcommand)]
pub enum ScanFindingCommand {
    /// Acknowledge a finding (mark as accepted risk)
    Ack {
        /// Finding ID
        id: String,

        /// Reason for acknowledging the finding
        #[arg(long)]
        reason: String,
    },

    /// Revoke a previously acknowledged finding
    Revoke {
        /// Finding ID
        id: String,
    },
}

#[derive(Subcommand)]
pub enum ScanPolicyCommand {
    /// List security policies
    List,

    /// Show security policy details
    Show {
        /// Policy ID
        id: String,
    },

    /// Create a security policy
    Create {
        /// Policy name
        name: String,

        /// Maximum vulnerability severity to allow (e.g. CRITICAL, HIGH, MEDIUM, LOW)
        #[arg(long)]
        max_severity: String,

        /// Block artifacts that fail policy checks
        #[arg(long)]
        block_on_fail: bool,

        /// Block unscanned artifacts
        #[arg(long)]
        block_unscanned: bool,

        /// Bind to a specific repository ID
        #[arg(long)]
        repo: Option<String>,
    },

    /// Update a security policy
    Update {
        /// Policy ID
        id: String,

        /// New policy name
        #[arg(long)]
        name: Option<String>,

        /// Maximum vulnerability severity to allow
        #[arg(long)]
        max_severity: Option<String>,

        /// Block artifacts that fail policy checks
        #[arg(long)]
        block_on_fail: Option<bool>,

        /// Block unscanned artifacts
        #[arg(long)]
        block_unscanned: Option<bool>,

        /// Enable or disable the policy
        #[arg(long)]
        enabled: Option<bool>,
    },

    /// Delete a security policy
    Delete {
        /// Policy ID
        id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
pub enum ScanSecurityCommand {
    /// Show repository security configuration
    Show {
        /// Repository key
        repo_key: String,
    },

    /// Update repository security configuration
    Update {
        /// Repository key
        repo_key: String,

        /// Enable or disable scanning
        #[arg(long)]
        scanning_enabled: bool,

        /// Scan artifacts on upload
        #[arg(long)]
        scan_on_upload: bool,

        /// Scan proxied artifacts
        #[arg(long)]
        scan_on_proxy: bool,

        /// Block on policy violation
        #[arg(long)]
        block_on_violation: bool,

        /// Minimum severity to report (e.g. CRITICAL, HIGH, MEDIUM, LOW)
        #[arg(long, default_value = "HIGH")]
        severity_threshold: String,
    },
}

impl ScanCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Run { repo, path } => run_scan(&repo, &path, global).await,
            Self::List {
                repo,
                page,
                per_page,
            } => list_scans(repo.as_deref(), page, per_page, global).await,
            Self::Show {
                id,
                severity,
                page,
                per_page,
            } => show_findings(&id, severity.as_deref(), page, per_page, global).await,
            Self::Dashboard => show_dashboard(global).await,
            Self::Scores => show_scores(global).await,
            Self::Config { command } => match command {
                ScanConfigCommand::List => list_scan_configs(global).await,
            },
            Self::Finding { command } => match command {
                ScanFindingCommand::Ack { id, reason } => {
                    acknowledge_finding(&id, &reason, global).await
                }
                ScanFindingCommand::Revoke { id } => revoke_finding(&id, global).await,
            },
            Self::Policy { command } => match command {
                ScanPolicyCommand::List => list_policies(global).await,
                ScanPolicyCommand::Show { id } => show_policy(&id, global).await,
                ScanPolicyCommand::Create {
                    name,
                    max_severity,
                    block_on_fail,
                    block_unscanned,
                    repo,
                } => {
                    create_policy(
                        &name,
                        &max_severity,
                        block_on_fail,
                        block_unscanned,
                        repo.as_deref(),
                        global,
                    )
                    .await
                }
                ScanPolicyCommand::Update {
                    id,
                    name,
                    max_severity,
                    block_on_fail,
                    block_unscanned,
                    enabled,
                } => {
                    update_policy(
                        &id,
                        name.as_deref(),
                        max_severity.as_deref(),
                        block_on_fail,
                        block_unscanned,
                        enabled,
                        global,
                    )
                    .await
                }
                ScanPolicyCommand::Delete { id, yes } => delete_policy(&id, yes, global).await,
            },
            Self::Security { command } => match command {
                ScanSecurityCommand::Show { repo_key } => {
                    show_repo_security(&repo_key, global).await
                }
                ScanSecurityCommand::Update {
                    repo_key,
                    scanning_enabled,
                    scan_on_upload,
                    scan_on_proxy,
                    block_on_violation,
                    severity_threshold,
                } => {
                    update_repo_security(
                        &repo_key,
                        scanning_enabled,
                        scan_on_upload,
                        scan_on_proxy,
                        block_on_violation,
                        &severity_threshold,
                        global,
                    )
                    .await
                }
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Existing handlers
// ---------------------------------------------------------------------------

async fn run_scan(repo: &str, artifact_path: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;

    let spinner = crate::output::spinner("Finding artifact...");

    let artifacts = client
        .list_artifacts()
        .key(repo)
        .q(artifact_path)
        .per_page(1)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to find artifact: {e}")))?;

    let artifact = artifacts.items.first().ok_or_else(|| {
        AkError::ServerError(format!("Artifact '{artifact_path}' not found in '{repo}'"))
    })?;

    spinner.set_message("Triggering scan...");

    let body = artifact_keeper_sdk::types::TriggerScanRequest {
        artifact_id: Some(artifact.id),
        repository_id: None,
    };

    let scan = client
        .trigger_scan()
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to trigger scan: {e}")))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", scan.artifacts_queued);
        return Ok(());
    }

    eprintln!(
        "Scan triggered: {} ({} artifact(s) queued)",
        scan.message, scan.artifacts_queued
    );
    eprintln!("Run `ak scan list --repo {repo}` to check scan status.");

    Ok(())
}

async fn list_scans(
    repo: Option<&str>,
    page: i64,
    per_page: i64,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;

    let spinner = crate::output::spinner("Fetching scans...");

    let resp = if let Some(repo_key) = repo {
        client
            .list_repo_scans()
            .key(repo_key)
            .page(page)
            .per_page(per_page)
            .send()
            .await
            .map_err(|e| AkError::ServerError(format!("Failed to list scans: {e}")))?
    } else {
        client
            .list_scans()
            .page(page)
            .per_page(per_page)
            .send()
            .await
            .map_err(|e| AkError::ServerError(format!("Failed to list scans: {e}")))?
    };

    spinner.finish_and_clear();

    if resp.items.is_empty() {
        eprintln!("No scans found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for scan in &resp.items {
            println!("{}", scan.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp
        .items
        .iter()
        .map(|s| {
            serde_json::json!({
                "id": s.id.to_string(),
                "status": s.status,
                "type": s.scan_type,
                "findings": s.findings_count,
                "critical": s.critical_count,
                "high": s.high_count,
                "medium": s.medium_count,
                "low": s.low_count,
                "artifact": s.artifact_name,
                "created_at": s.created_at.to_rfc3339(),
            })
        })
        .collect();

    let table_str = {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                "ID", "STATUS", "TYPE", "FINDINGS", "C", "H", "M", "L", "ARTIFACT", "CREATED",
            ]);

        for s in &resp.items {
            let id_short = &s.id.to_string()[..8];
            let artifact = s.artifact_name.as_deref().unwrap_or("-");
            let created = s.created_at.format("%Y-%m-%d %H:%M").to_string();
            table.add_row(vec![
                id_short,
                &s.status,
                &s.scan_type,
                &s.findings_count.to_string(),
                &format_severity_count(s.critical_count, "CRITICAL"),
                &format_severity_count(s.high_count, "HIGH"),
                &format_severity_count(s.medium_count, "MEDIUM"),
                &format_severity_count(s.low_count, "LOW"),
                artifact,
                &created,
            ]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    eprintln!("{} scans total.", resp.total);

    Ok(())
}

async fn show_findings(
    scan_id: &str,
    severity_filter: Option<&str>,
    page: i64,
    per_page: i64,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;

    let id = parse_uuid(scan_id, "scan")?;

    let spinner = crate::output::spinner("Fetching scan details...");

    let scan = client
        .get_scan()
        .id(id)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to get scan: {e}")))?;

    let findings = client
        .list_findings()
        .id(id)
        .page(page)
        .per_page(per_page)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to get findings: {e}")))?;

    spinner.finish_and_clear();

    if !matches!(global.format, OutputFormat::Json | OutputFormat::Yaml) {
        eprintln!(
            "Scan {} — {} ({})",
            &scan.id.to_string()[..8],
            scan.status,
            scan.scan_type
        );
        if let Some(artifact) = &scan.artifact_name {
            let version = scan.artifact_version.as_deref().unwrap_or("");
            eprintln!("Artifact: {artifact} {version}");
        }
        eprintln!(
            "Findings: {} total (C:{} H:{} M:{} L:{} I:{})",
            scan.findings_count,
            scan.critical_count,
            scan.high_count,
            scan.medium_count,
            scan.low_count,
            scan.info_count
        );
        eprintln!();
    }

    let severity_levels = parse_severity_filter(severity_filter);
    let filtered: Vec<_> = findings
        .items
        .iter()
        .filter(|f| {
            severity_levels.is_empty()
                || severity_levels
                    .iter()
                    .any(|s| s.eq_ignore_ascii_case(&f.severity))
        })
        .collect();

    if filtered.is_empty() {
        let msg = if severity_filter.is_some() {
            "No findings match the severity filter."
        } else {
            "No findings."
        };
        eprintln!("{msg}");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for f in &filtered {
            println!("{}", f.cve_id.as_deref().unwrap_or(&f.id.to_string()));
        }
        return Ok(());
    }

    let entries: Vec<_> = filtered
        .iter()
        .map(|f| {
            serde_json::json!({
                "id": f.id.to_string(),
                "severity": f.severity,
                "cve_id": f.cve_id,
                "title": f.title,
                "affected_component": f.affected_component,
                "affected_version": f.affected_version,
                "fixed_version": f.fixed_version,
                "source": f.source,
                "acknowledged": f.is_acknowledged,
            })
        })
        .collect();

    let table_str = {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                "SEVERITY",
                "CVE",
                "TITLE",
                "COMPONENT",
                "VERSION",
                "FIX",
            ]);

        for f in &filtered {
            let sev = format_severity(&f.severity);
            let cve = f.cve_id.as_deref().unwrap_or("-");
            let title = truncate(&f.title, 50);
            let component = f.affected_component.as_deref().unwrap_or("-");
            let version = f.affected_version.as_deref().unwrap_or("-");
            let fix = f.fixed_version.as_deref().unwrap_or("-");
            table.add_row(vec![&sev, cve, &title, component, version, fix]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    let has_critical_or_high = filtered.iter().any(|f| {
        f.severity.eq_ignore_ascii_case("CRITICAL") || f.severity.eq_ignore_ascii_case("HIGH")
    });

    if has_critical_or_high {
        eprintln!(
            "{}",
            style("Critical or high severity findings detected.")
                .red()
                .bold()
        );
        std::process::exit(1);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Dashboard & scores
// ---------------------------------------------------------------------------

async fn show_dashboard(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;

    let spinner = crate::output::spinner("Fetching security dashboard...");

    let dash = client
        .get_dashboard()
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to fetch dashboard: {e}")))?;

    spinner.finish_and_clear();

    let d = dash.into_inner();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", d.total_findings);
        return Ok(());
    }

    let entry = serde_json::json!({
        "total_scans": d.total_scans,
        "total_findings": d.total_findings,
        "critical_findings": d.critical_findings,
        "high_findings": d.high_findings,
        "policy_violations_blocked": d.policy_violations_blocked,
        "repos_with_scanning": d.repos_with_scanning,
        "repos_grade_a": d.repos_grade_a,
        "repos_grade_f": d.repos_grade_f,
    });

    let table_str = format!(
        "Security Dashboard:\n\
         \x20 Total Scans:           {}\n\
         \x20 Total Findings:        {}\n\
         \x20 Critical:              {}\n\
         \x20 High:                  {}\n\
         \x20 Policy Violations:     {}\n\
         \x20 Repos with Scanning:   {}\n\
         \x20 Grade A Repos:         {}\n\
         \x20 Grade F Repos:         {}",
        d.total_scans,
        d.total_findings,
        format_severity_count(d.critical_findings as i32, "CRITICAL"),
        format_severity_count(d.high_findings as i32, "HIGH"),
        d.policy_violations_blocked,
        d.repos_with_scanning,
        d.repos_grade_a,
        d.repos_grade_f,
    );

    println!(
        "{}",
        output::render(&[entry], &global.format, Some(table_str))
    );

    Ok(())
}

async fn show_scores(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;

    let spinner = crate::output::spinner("Fetching security scores...");

    let scores = client
        .get_all_scores()
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to fetch scores: {e}")))?;

    spinner.finish_and_clear();

    let items = scores.into_inner();

    if items.is_empty() {
        eprintln!("No security scores available.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for s in &items {
            println!("{}", s.repository_id);
        }
        return Ok(());
    }

    let entries: Vec<_> = items
        .iter()
        .map(|s| {
            serde_json::json!({
                "repository_id": s.repository_id.to_string(),
                "grade": s.grade,
                "score": s.score,
                "critical": s.critical_count,
                "high": s.high_count,
                "medium": s.medium_count,
                "low": s.low_count,
                "total_findings": s.total_findings,
                "acknowledged": s.acknowledged_count,
                "last_scan_at": s.last_scan_at.map(|t| t.to_rfc3339()),
                "calculated_at": s.calculated_at.to_rfc3339(),
            })
        })
        .collect();

    let table_str = {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                "REPO",
                "GRADE",
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW",
                "SCANNED",
                "UNSCANNED",
                "UPDATED",
            ]);

        for s in &items {
            let repo_short = &s.repository_id.to_string()[..8];
            let scanned = s
                .last_scan_at
                .map(|t| t.format("%Y-%m-%d").to_string())
                .unwrap_or_else(|| "-".to_string());
            let unscanned = s.total_findings - s.acknowledged_count;
            table.add_row(vec![
                repo_short,
                &s.grade,
                &format_severity_count(s.critical_count, "CRITICAL"),
                &format_severity_count(s.high_count, "HIGH"),
                &format_severity_count(s.medium_count, "MEDIUM"),
                &s.low_count.to_string(),
                &scanned,
                &unscanned.to_string(),
                &s.calculated_at.format("%Y-%m-%d").to_string(),
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

// ---------------------------------------------------------------------------
// Scan configs
// ---------------------------------------------------------------------------

async fn list_scan_configs(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;

    let spinner = crate::output::spinner("Fetching scan configurations...");

    let configs = client
        .list_scan_configs()
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to list scan configs: {e}")))?;

    spinner.finish_and_clear();

    let items = configs.into_inner();

    if items.is_empty() {
        eprintln!("No scan configurations found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for c in &items {
            println!("{}", c.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = items
        .iter()
        .map(|c| {
            serde_json::json!({
                "id": c.id.to_string(),
                "repository_id": c.repository_id.to_string(),
                "scan_enabled": c.scan_enabled,
                "scan_on_upload": c.scan_on_upload,
                "scan_on_proxy": c.scan_on_proxy,
                "block_on_policy_violation": c.block_on_policy_violation,
                "severity_threshold": c.severity_threshold,
                "created_at": c.created_at.to_rfc3339(),
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
                "REPO",
                "ENABLED",
                "ON UPLOAD",
                "ON PROXY",
                "BLOCK",
                "THRESHOLD",
            ]);

        for c in &items {
            let id_short = &c.id.to_string()[..8];
            let repo_short = &c.repository_id.to_string()[..8];
            table.add_row(vec![
                id_short,
                repo_short,
                if c.scan_enabled { "yes" } else { "no" },
                if c.scan_on_upload { "yes" } else { "no" },
                if c.scan_on_proxy { "yes" } else { "no" },
                if c.block_on_policy_violation {
                    "yes"
                } else {
                    "no"
                },
                &c.severity_threshold,
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

// ---------------------------------------------------------------------------
// Finding management
// ---------------------------------------------------------------------------

async fn acknowledge_finding(finding_id: &str, reason: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(finding_id, "finding")?;

    let spinner = crate::output::spinner("Acknowledging finding...");

    let body = artifact_keeper_sdk::types::AcknowledgeRequest {
        reason: reason.to_string(),
    };

    let finding = client
        .acknowledge_finding()
        .id(id)
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to acknowledge finding: {e}")))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", finding.id);
        return Ok(());
    }

    let entry = serde_json::json!({
        "id": finding.id.to_string(),
        "severity": finding.severity,
        "title": finding.title,
        "is_acknowledged": finding.is_acknowledged,
        "acknowledged_reason": finding.acknowledged_reason,
    });

    if matches!(global.format, OutputFormat::Json | OutputFormat::Yaml) {
        println!("{}", output::render(&[entry], &global.format, None));
    } else {
        eprintln!(
            "Finding {} acknowledged: {}",
            &finding.id.to_string()[..8],
            reason
        );
    }

    Ok(())
}

async fn revoke_finding(finding_id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(finding_id, "finding")?;

    let spinner = crate::output::spinner("Revoking acknowledgment...");

    let finding = client
        .revoke_acknowledgment()
        .id(id)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to revoke acknowledgment: {e}")))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", finding.id);
        return Ok(());
    }

    let entry = serde_json::json!({
        "id": finding.id.to_string(),
        "severity": finding.severity,
        "title": finding.title,
        "is_acknowledged": finding.is_acknowledged,
    });

    if matches!(global.format, OutputFormat::Json | OutputFormat::Yaml) {
        println!("{}", output::render(&[entry], &global.format, None));
    } else {
        eprintln!(
            "Acknowledgment revoked for finding {}.",
            &finding.id.to_string()[..8]
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Policy CRUD
// ---------------------------------------------------------------------------

async fn list_policies(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;

    let spinner = crate::output::spinner("Fetching security policies...");

    let policies = client
        .list_policies()
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to list policies: {e}")))?;

    spinner.finish_and_clear();

    let items = policies.into_inner();

    if items.is_empty() {
        eprintln!("No security policies found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for p in &items {
            println!("{}", p.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = items
        .iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id.to_string(),
                "name": p.name,
                "max_severity": p.max_severity,
                "block_on_fail": p.block_on_fail,
                "block_unscanned": p.block_unscanned,
                "is_enabled": p.is_enabled,
                "require_signature": p.require_signature,
                "repository_id": p.repository_id.map(|id| id.to_string()),
                "created_at": p.created_at.to_rfc3339(),
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
                "MAX SEV",
                "BLOCK FAIL",
                "BLOCK UNSCAN",
                "ENABLED",
                "REPO",
            ]);

        for p in &items {
            let id_short = &p.id.to_string()[..8];
            let repo = p
                .repository_id
                .map(|id| id.to_string()[..8].to_string())
                .unwrap_or_else(|| "global".to_string());
            table.add_row(vec![
                id_short,
                &p.name,
                &p.max_severity,
                if p.block_on_fail { "yes" } else { "no" },
                if p.block_unscanned { "yes" } else { "no" },
                if p.is_enabled { "yes" } else { "no" },
                &repo,
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

async fn show_policy(policy_id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(policy_id, "policy")?;

    let spinner = crate::output::spinner("Fetching policy...");

    let policy = client
        .get_policy()
        .id(id)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to get policy: {e}")))?;

    spinner.finish_and_clear();

    let p = policy.into_inner();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", p.id);
        return Ok(());
    }

    let entry = serde_json::json!({
        "id": p.id.to_string(),
        "name": p.name,
        "max_severity": p.max_severity,
        "block_on_fail": p.block_on_fail,
        "block_unscanned": p.block_unscanned,
        "is_enabled": p.is_enabled,
        "require_signature": p.require_signature,
        "repository_id": p.repository_id.map(|id| id.to_string()),
        "max_artifact_age_days": p.max_artifact_age_days,
        "min_staging_hours": p.min_staging_hours,
        "created_at": p.created_at.to_rfc3339(),
        "updated_at": p.updated_at.to_rfc3339(),
    });

    let table_str = format!(
        "Policy: {} ({})\n\
         \x20 Max Severity:        {}\n\
         \x20 Block on Fail:       {}\n\
         \x20 Block Unscanned:     {}\n\
         \x20 Enabled:             {}\n\
         \x20 Require Signature:   {}\n\
         \x20 Repository:          {}\n\
         \x20 Max Age (days):      {}\n\
         \x20 Min Staging (hours): {}\n\
         \x20 Created:             {}\n\
         \x20 Updated:             {}",
        p.name,
        &p.id.to_string()[..8],
        p.max_severity,
        p.block_on_fail,
        p.block_unscanned,
        p.is_enabled,
        p.require_signature,
        p.repository_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| "global".to_string()),
        p.max_artifact_age_days
            .map(|d| d.to_string())
            .unwrap_or_else(|| "-".to_string()),
        p.min_staging_hours
            .map(|h| h.to_string())
            .unwrap_or_else(|| "-".to_string()),
        p.created_at.format("%Y-%m-%d %H:%M"),
        p.updated_at.format("%Y-%m-%d %H:%M"),
    );

    println!(
        "{}",
        output::render(&[entry], &global.format, Some(table_str))
    );

    Ok(())
}

async fn create_policy(
    name: &str,
    max_severity: &str,
    block_on_fail: bool,
    block_unscanned: bool,
    repo: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let repo_id = parse_optional_uuid(repo, "repository")?;

    let spinner = crate::output::spinner("Creating security policy...");

    let body = artifact_keeper_sdk::types::CreatePolicyRequest {
        name: name.to_string(),
        max_severity: max_severity.to_string(),
        block_on_fail,
        block_unscanned,
        repository_id: repo_id,
        max_artifact_age_days: None,
        min_staging_hours: None,
        require_signature: None,
    };

    let policy = client
        .create_policy()
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to create policy: {e}")))?;

    spinner.finish_and_clear();

    let p = policy.into_inner();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", p.id);
        return Ok(());
    }

    let entry = serde_json::json!({
        "id": p.id.to_string(),
        "name": p.name,
        "max_severity": p.max_severity,
        "block_on_fail": p.block_on_fail,
        "block_unscanned": p.block_unscanned,
        "is_enabled": p.is_enabled,
    });

    if matches!(global.format, OutputFormat::Json | OutputFormat::Yaml) {
        println!("{}", output::render(&[entry], &global.format, None));
    } else {
        eprintln!(
            "Policy '{}' created (ID: {}).",
            p.name,
            &p.id.to_string()[..8]
        );
    }

    Ok(())
}

async fn update_policy(
    policy_id: &str,
    name: Option<&str>,
    max_severity: Option<&str>,
    block_on_fail: Option<bool>,
    block_unscanned: Option<bool>,
    enabled: Option<bool>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(policy_id, "policy")?;

    let spinner = crate::output::spinner("Fetching current policy...");

    // Fetch existing policy first since UpdatePolicyRequest has required fields
    let existing = client
        .get_policy()
        .id(id)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to get policy: {e}")))?;

    let existing = existing.into_inner();

    spinner.set_message("Updating policy...");

    let body = artifact_keeper_sdk::types::UpdatePolicyRequest {
        name: name.unwrap_or(&existing.name).to_string(),
        max_severity: max_severity.unwrap_or(&existing.max_severity).to_string(),
        block_on_fail: block_on_fail.unwrap_or(existing.block_on_fail),
        block_unscanned: block_unscanned.unwrap_or(existing.block_unscanned),
        is_enabled: enabled.unwrap_or(existing.is_enabled),
        max_artifact_age_days: existing.max_artifact_age_days,
        min_staging_hours: existing.min_staging_hours,
        require_signature: Some(existing.require_signature),
    };

    let policy = client
        .update_policy()
        .id(id)
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to update policy: {e}")))?;

    spinner.finish_and_clear();

    let p = policy.into_inner();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", p.id);
        return Ok(());
    }

    let entry = serde_json::json!({
        "id": p.id.to_string(),
        "name": p.name,
        "max_severity": p.max_severity,
        "block_on_fail": p.block_on_fail,
        "block_unscanned": p.block_unscanned,
        "is_enabled": p.is_enabled,
    });

    if matches!(global.format, OutputFormat::Json | OutputFormat::Yaml) {
        println!("{}", output::render(&[entry], &global.format, None));
    } else {
        eprintln!(
            "Policy '{}' updated (ID: {}).",
            p.name,
            &p.id.to_string()[..8]
        );
    }

    Ok(())
}

async fn delete_policy(policy_id: &str, yes: bool, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(policy_id, "policy")?;

    if !confirm_action(&format!("Delete policy {policy_id}?"), yes, global.no_input)? {
        return Ok(());
    }

    let spinner = crate::output::spinner("Deleting policy...");

    client
        .delete_policy()
        .id(id)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to delete policy: {e}")))?;

    spinner.finish_and_clear();

    if !matches!(global.format, OutputFormat::Quiet) {
        eprintln!("Policy {} deleted.", &policy_id);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Repository security config
// ---------------------------------------------------------------------------

async fn show_repo_security(repo_key: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;

    let spinner = crate::output::spinner("Fetching repository security config...");

    let resp = client
        .get_repo_security()
        .key(repo_key)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to get repo security: {e}")))?;

    spinner.finish_and_clear();

    let sec = resp.into_inner();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{repo_key}");
        return Ok(());
    }

    let entry = serde_json::json!({
        "repo_key": repo_key,
        "config": sec.config.as_ref().map(|c| serde_json::json!({
            "scan_enabled": c.scan_enabled,
            "scan_on_upload": c.scan_on_upload,
            "scan_on_proxy": c.scan_on_proxy,
            "block_on_policy_violation": c.block_on_policy_violation,
            "severity_threshold": c.severity_threshold,
        })),
        "score": sec.score.as_ref().map(|s| serde_json::json!({
            "grade": s.grade,
            "score": s.score,
            "critical": s.critical_count,
            "high": s.high_count,
            "medium": s.medium_count,
            "low": s.low_count,
        })),
    });

    let table_str = {
        let mut lines = vec![format!("Repository: {repo_key}")];

        if let Some(c) = &sec.config {
            lines.push(format!("  Scanning Enabled:        {}", c.scan_enabled));
            lines.push(format!("  Scan on Upload:          {}", c.scan_on_upload));
            lines.push(format!("  Scan on Proxy:           {}", c.scan_on_proxy));
            lines.push(format!(
                "  Block on Violation:      {}",
                c.block_on_policy_violation
            ));
            lines.push(format!(
                "  Severity Threshold:      {}",
                c.severity_threshold
            ));
        } else {
            lines.push("  No scan configuration.".to_string());
        }

        if let Some(s) = &sec.score {
            lines.push(format!("  Grade: {} (score: {})", s.grade, s.score));
            lines.push(format!(
                "  Findings: C:{} H:{} M:{} L:{}",
                s.critical_count, s.high_count, s.medium_count, s.low_count
            ));
        }

        lines.join("\n")
    };

    println!(
        "{}",
        output::render(&[entry], &global.format, Some(table_str))
    );

    Ok(())
}

async fn update_repo_security(
    repo_key: &str,
    scanning_enabled: bool,
    scan_on_upload: bool,
    scan_on_proxy: bool,
    block_on_violation: bool,
    severity_threshold: &str,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;

    let spinner = crate::output::spinner("Updating repository security config...");

    let body = artifact_keeper_sdk::types::UpsertScanConfigRequest {
        scan_enabled: scanning_enabled,
        scan_on_upload,
        scan_on_proxy,
        block_on_policy_violation: block_on_violation,
        severity_threshold: severity_threshold.to_string(),
    };

    let config = client
        .update_repo_security()
        .key(repo_key)
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to update repo security: {e}")))?;

    spinner.finish_and_clear();

    let c = config.into_inner();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", c.id);
        return Ok(());
    }

    let entry = serde_json::json!({
        "id": c.id.to_string(),
        "repository_id": c.repository_id.to_string(),
        "scan_enabled": c.scan_enabled,
        "scan_on_upload": c.scan_on_upload,
        "scan_on_proxy": c.scan_on_proxy,
        "block_on_policy_violation": c.block_on_policy_violation,
        "severity_threshold": c.severity_threshold,
    });

    if matches!(global.format, OutputFormat::Json | OutputFormat::Yaml) {
        println!("{}", output::render(&[entry], &global.format, None));
    } else {
        eprintln!("Security config updated for repository '{repo_key}'.");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers (scan-specific)
// ---------------------------------------------------------------------------

fn format_severity(severity: &str) -> String {
    match severity.to_uppercase().as_str() {
        "CRITICAL" => style(severity).red().bold().to_string(),
        "HIGH" => style(severity).red().to_string(),
        "MEDIUM" => style(severity).yellow().to_string(),
        "LOW" | "INFO" => style(severity).dim().to_string(),
        _ => severity.to_string(),
    }
}

fn format_severity_count(count: i32, severity: &str) -> String {
    if count == 0 {
        return style("0").dim().to_string();
    }
    match severity.to_uppercase().as_str() {
        "CRITICAL" => style(count).red().bold().to_string(),
        "HIGH" => style(count).red().to_string(),
        "MEDIUM" => style(count).yellow().to_string(),
        _ => count.to_string(),
    }
}

fn parse_severity_filter(filter: Option<&str>) -> Vec<String> {
    let Some(filter) = filter else {
        return Vec::new();
    };
    filter.split(',').map(|s| s.trim().to_uppercase()).collect()
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max.saturating_sub(3)).collect();
        format!("{truncated}...")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- truncate ----

    #[test]
    fn truncate_short_string() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_exact_length() {
        assert_eq!(truncate("hello", 5), "hello");
    }

    #[test]
    fn truncate_long_string() {
        assert_eq!(truncate("hello world", 8), "hello...");
    }

    #[test]
    fn truncate_empty() {
        assert_eq!(truncate("", 5), "");
    }

    #[test]
    fn truncate_zero_max() {
        assert_eq!(truncate("hello", 0), "...");
    }

    #[test]
    fn truncate_one_max() {
        assert_eq!(truncate("hello", 1), "...");
    }

    #[test]
    fn truncate_three_max() {
        assert_eq!(truncate("hello", 3), "...");
    }

    #[test]
    fn truncate_four_max() {
        assert_eq!(truncate("hello", 4), "h...");
    }

    #[test]
    fn truncate_unicode() {
        assert_eq!(truncate("héllo wörld", 8), "héllo...");
    }

    // ---- parse_severity_filter ----

    #[test]
    fn parse_severity_filter_none() {
        let result = parse_severity_filter(None);
        assert!(result.is_empty());
    }

    #[test]
    fn parse_severity_filter_single() {
        let result = parse_severity_filter(Some("CRITICAL"));
        assert_eq!(result, vec!["CRITICAL"]);
    }

    #[test]
    fn parse_severity_filter_multiple() {
        let result = parse_severity_filter(Some("CRITICAL,HIGH,MEDIUM"));
        assert_eq!(result, vec!["CRITICAL", "HIGH", "MEDIUM"]);
    }

    #[test]
    fn parse_severity_filter_lowercase() {
        let result = parse_severity_filter(Some("critical,high"));
        assert_eq!(result, vec!["CRITICAL", "HIGH"]);
    }

    #[test]
    fn parse_severity_filter_with_spaces() {
        let result = parse_severity_filter(Some("CRITICAL , HIGH , LOW"));
        assert_eq!(result, vec!["CRITICAL", "HIGH", "LOW"]);
    }

    #[test]
    fn parse_severity_filter_mixed_case() {
        let result = parse_severity_filter(Some("Critical,hIGH"));
        assert_eq!(result, vec!["CRITICAL", "HIGH"]);
    }

    // ---- format_severity ----

    #[test]
    fn format_severity_critical() {
        let result = format_severity("CRITICAL");
        assert!(result.contains("CRITICAL"));
    }

    #[test]
    fn format_severity_high() {
        let result = format_severity("HIGH");
        assert!(result.contains("HIGH"));
    }

    #[test]
    fn format_severity_medium() {
        let result = format_severity("MEDIUM");
        assert!(result.contains("MEDIUM"));
    }

    #[test]
    fn format_severity_low() {
        let result = format_severity("LOW");
        assert!(result.contains("LOW"));
    }

    #[test]
    fn format_severity_info() {
        let result = format_severity("INFO");
        assert!(result.contains("INFO"));
    }

    #[test]
    fn format_severity_unknown() {
        assert_eq!(format_severity("UNKNOWN"), "UNKNOWN");
    }

    // ---- format_severity_count ----

    #[test]
    fn format_severity_count_zero() {
        let result = format_severity_count(0, "CRITICAL");
        assert!(result.contains("0"));
    }

    #[test]
    fn format_severity_count_nonzero_critical() {
        let result = format_severity_count(5, "CRITICAL");
        assert!(result.contains("5"));
    }

    #[test]
    fn format_severity_count_nonzero_high() {
        let result = format_severity_count(3, "HIGH");
        assert!(result.contains("3"));
    }

    #[test]
    fn format_severity_count_nonzero_medium() {
        let result = format_severity_count(7, "MEDIUM");
        assert!(result.contains("7"));
    }

    #[test]
    fn format_severity_count_nonzero_low() {
        let result = format_severity_count(2, "LOW");
        assert_eq!(result, "2");
    }
}
