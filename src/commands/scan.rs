use artifact_keeper_sdk::{ClientRepositoriesExt, ClientSecurityExt};
use clap::Subcommand;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use console::style;
use miette::Result;

use super::client::client_for;
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
        }
    }
}

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

    let id: uuid::Uuid = scan_id
        .parse()
        .map_err(|_| AkError::ConfigError(format!("Invalid scan ID: {scan_id}")))?;

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
