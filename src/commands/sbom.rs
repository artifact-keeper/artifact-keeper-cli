use artifact_keeper_sdk::ClientSbomExt;
use clap::Subcommand;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use miette::Result;

use super::client::client_for;
use super::helpers::{confirm_action, parse_optional_uuid, parse_uuid};
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum SbomCommand {
    /// Generate an SBOM for an artifact
    Generate {
        /// Artifact ID
        artifact_id: String,

        /// SBOM format (spdx or cyclonedx)
        #[arg(long = "sbom-format")]
        sbom_format: Option<String>,

        /// Force regeneration even if an SBOM already exists
        #[arg(long)]
        force: bool,
    },

    /// Show SBOM content for an artifact
    Show {
        /// Artifact ID
        artifact_id: String,
    },

    /// List SBOMs with optional filters
    List {
        /// Filter by repository ID
        #[arg(long)]
        repo: Option<String>,

        /// Filter by SBOM format (spdx or cyclonedx)
        #[arg(long = "sbom-format")]
        sbom_format: Option<String>,

        /// Filter by artifact ID
        #[arg(long)]
        artifact: Option<String>,
    },

    /// Get SBOM by ID with full content
    Get {
        /// SBOM ID
        sbom_id: String,
    },

    /// Delete an SBOM
    Delete {
        /// SBOM ID
        sbom_id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// List components of an SBOM
    Components {
        /// SBOM ID
        sbom_id: String,
    },

    /// Export an SBOM, optionally converting to a different format
    Export {
        /// SBOM ID
        sbom_id: String,

        /// Output file path
        #[arg(long, short)]
        output: String,

        /// Target format to convert to (e.g. spdx, cyclonedx)
        #[arg(long = "target-format")]
        target_format: Option<String>,
    },

    /// CVE (Common Vulnerabilities and Exposures) operations
    #[command(subcommand)]
    Cve(SbomCveCommand),
}

#[derive(Subcommand)]
pub enum SbomCveCommand {
    /// Show CVE history for an artifact
    History {
        /// Artifact ID
        artifact_id: String,
    },

    /// Show CVE trends and statistics
    Trends {
        /// Number of days to look back
        #[arg(long, default_value = "30")]
        days: i32,

        /// Filter by repository ID
        #[arg(long)]
        repo: Option<String>,
    },

    /// Update the status of a CVE entry
    UpdateStatus {
        /// CVE history entry ID
        cve_id: String,

        /// New status (open, fixed, acknowledged, false_positive)
        #[arg(long)]
        status: String,

        /// Reason for the status change
        #[arg(long)]
        reason: Option<String>,
    },
}

impl SbomCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Generate {
                artifact_id,
                sbom_format,
                force,
            } => generate_sbom(&artifact_id, sbom_format.as_deref(), force, global).await,
            Self::Show { artifact_id } => show_sbom(&artifact_id, global).await,
            Self::List {
                repo,
                sbom_format,
                artifact,
            } => {
                list_sboms(
                    repo.as_deref(),
                    sbom_format.as_deref(),
                    artifact.as_deref(),
                    global,
                )
                .await
            }
            Self::Get { sbom_id } => get_sbom(&sbom_id, global).await,
            Self::Delete { sbom_id, yes } => delete_sbom(&sbom_id, yes, global).await,
            Self::Components { sbom_id } => get_components(&sbom_id, global).await,
            Self::Export {
                sbom_id,
                output,
                target_format,
            } => export_sbom(&sbom_id, &output, target_format.as_deref(), global).await,
            Self::Cve(cmd) => cmd.execute(global).await,
        }
    }
}

impl SbomCveCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::History { artifact_id } => cve_history(&artifact_id, global).await,
            Self::Trends { days, repo } => cve_trends(days, repo.as_deref(), global).await,
            Self::UpdateStatus {
                cve_id,
                status,
                reason,
            } => cve_update_status(&cve_id, &status, reason.as_deref(), global).await,
        }
    }
}

// ---------------------------------------------------------------------------
// SBOM handlers
// ---------------------------------------------------------------------------

async fn generate_sbom(
    artifact_id: &str,
    sbom_format: Option<&str>,
    force: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let aid = parse_uuid(artifact_id, "artifact")?;

    let spinner = output::spinner("Generating SBOM...");

    let body = artifact_keeper_sdk::types::GenerateSbomRequest {
        artifact_id: aid,
        force_regenerate: if force { Some(true) } else { None },
        format: sbom_format.map(|s| s.to_string()),
    };

    let resp = client
        .generate_sbom()
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to generate SBOM: {e}")))?;

    let sbom = resp.into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", sbom.id);
        return Ok(());
    }

    let info = serde_json::json!({
        "id": sbom.id.to_string(),
        "artifact_id": sbom.artifact_id.to_string(),
        "format": sbom.format,
        "format_version": sbom.format_version,
        "component_count": sbom.component_count,
        "license_count": sbom.license_count,
        "generated_at": sbom.generated_at.to_rfc3339(),
    });

    let table_str = format!(
        "SBOM generated successfully.\n\n\
         ID:              {}\n\
         Artifact:        {}\n\
         Format:          {} {}\n\
         Components:      {}\n\
         Licenses:        {}\n\
         Generated:       {}",
        sbom.id,
        sbom.artifact_id,
        sbom.format,
        sbom.format_version,
        sbom.component_count,
        sbom.license_count,
        sbom.generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn show_sbom(artifact_id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let aid = parse_uuid(artifact_id, "artifact")?;

    let spinner = output::spinner("Fetching SBOM...");

    let resp = client
        .get_sbom_by_artifact()
        .artifact_id(aid)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to get SBOM: {e}")))?;

    let sbom = resp.into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", sbom.id);
        return Ok(());
    }

    let info = serde_json::json!({
        "id": sbom.id.to_string(),
        "artifact_id": sbom.artifact_id.to_string(),
        "format": sbom.format,
        "format_version": sbom.format_version,
        "component_count": sbom.component_count,
        "dependency_count": sbom.dependency_count,
        "license_count": sbom.license_count,
        "licenses": sbom.licenses,
        "content_hash": sbom.content_hash,
        "generated_at": sbom.generated_at.to_rfc3339(),
        "content": sbom.content,
    });

    let table_str = format!(
        "ID:              {}\n\
         Artifact:        {}\n\
         Format:          {} {}\n\
         Components:      {}\n\
         Dependencies:    {}\n\
         Licenses:        {} ({})\n\
         Content Hash:    {}\n\
         Generated:       {}",
        sbom.id,
        sbom.artifact_id,
        sbom.format,
        sbom.format_version,
        sbom.component_count,
        sbom.dependency_count,
        sbom.license_count,
        sbom.licenses.join(", "),
        sbom.content_hash,
        sbom.generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn list_sboms(
    repo: Option<&str>,
    sbom_format: Option<&str>,
    artifact: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching SBOMs...");

    let repo_id = parse_optional_uuid(repo, "repository")?;
    let artifact_id = parse_optional_uuid(artifact, "artifact")?;

    let mut req = client.list_sboms();
    if let Some(rid) = repo_id {
        req = req.repository_id(rid);
    }
    if let Some(fmt) = sbom_format {
        req = req.format(fmt);
    }
    if let Some(aid) = artifact_id {
        req = req.artifact_id(aid);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to list SBOMs: {e}")))?;

    let sboms = resp.into_inner();
    spinner.finish_and_clear();

    if sboms.is_empty() {
        eprintln!("No SBOMs found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for s in &sboms {
            println!("{}", s.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = sboms
        .iter()
        .map(|s| {
            serde_json::json!({
                "id": s.id.to_string(),
                "artifact_id": s.artifact_id.to_string(),
                "format": s.format,
                "component_count": s.component_count,
                "license_count": s.license_count,
                "generated_at": s.generated_at.to_rfc3339(),
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
                "ARTIFACT",
                "FORMAT",
                "COMPONENTS",
                "LICENSES",
                "GENERATED",
            ]);

        for s in &sboms {
            let id_short = &s.id.to_string()[..8];
            let artifact_short = &s.artifact_id.to_string()[..8];

            table.add_row(vec![
                id_short.to_string(),
                artifact_short.to_string(),
                s.format.clone(),
                s.component_count.to_string(),
                s.license_count.to_string(),
                s.generated_at.format("%Y-%m-%d %H:%M").to_string(),
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

async fn get_sbom(sbom_id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let sid = parse_uuid(sbom_id, "SBOM")?;

    let spinner = output::spinner("Fetching SBOM...");

    let resp = client
        .get_sbom()
        .id(sid)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to get SBOM: {e}")))?;

    let sbom = resp.into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", sbom.id);
        return Ok(());
    }

    let info = serde_json::json!({
        "id": sbom.id.to_string(),
        "artifact_id": sbom.artifact_id.to_string(),
        "format": sbom.format,
        "format_version": sbom.format_version,
        "component_count": sbom.component_count,
        "dependency_count": sbom.dependency_count,
        "license_count": sbom.license_count,
        "licenses": sbom.licenses,
        "content_hash": sbom.content_hash,
        "generated_at": sbom.generated_at.to_rfc3339(),
        "content": sbom.content,
    });

    let table_str = format!(
        "ID:              {}\n\
         Artifact:        {}\n\
         Format:          {} {}\n\
         Components:      {}\n\
         Dependencies:    {}\n\
         Licenses:        {} ({})\n\
         Content Hash:    {}\n\
         Generated:       {}",
        sbom.id,
        sbom.artifact_id,
        sbom.format,
        sbom.format_version,
        sbom.component_count,
        sbom.dependency_count,
        sbom.license_count,
        sbom.licenses.join(", "),
        sbom.content_hash,
        sbom.generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn delete_sbom(sbom_id: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    let sid = parse_uuid(sbom_id, "SBOM")?;

    if !confirm_action(
        &format!("Delete SBOM {sbom_id}?"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Deleting SBOM...");

    client
        .delete_sbom()
        .id(sid)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to delete SBOM: {e}")))?;

    spinner.finish_and_clear();
    eprintln!("SBOM {sbom_id} deleted.");

    Ok(())
}

async fn get_components(sbom_id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let sid = parse_uuid(sbom_id, "SBOM")?;

    let spinner = output::spinner("Fetching SBOM components...");

    let resp = client
        .get_sbom_components()
        .id(sid)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to get SBOM components: {e}")))?;

    let components = resp.into_inner();
    spinner.finish_and_clear();

    if components.is_empty() {
        eprintln!("No components found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for c in &components {
            println!("{}", c.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = components
        .iter()
        .map(|c| {
            serde_json::json!({
                "id": c.id.to_string(),
                "name": c.name,
                "version": c.version,
                "type": c.component_type,
                "purl": c.purl,
                "licenses": c.licenses,
            })
        })
        .collect();

    let table_str = {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec!["ID", "NAME", "VERSION", "TYPE", "PURL", "LICENSES"]);

        for c in &components {
            let id_short = &c.id.to_string()[..8];
            let version = c.version.as_deref().unwrap_or("-");
            let ctype = c.component_type.as_deref().unwrap_or("-");
            let purl = c.purl.as_deref().unwrap_or("-");
            let licenses = if c.licenses.is_empty() {
                "-".to_string()
            } else {
                c.licenses.join(", ")
            };

            table.add_row(vec![
                id_short.to_string(),
                c.name.clone(),
                version.to_string(),
                ctype.to_string(),
                purl.to_string(),
                licenses,
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

async fn export_sbom(
    sbom_id: &str,
    output_path: &str,
    target_format: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let sid = parse_uuid(sbom_id, "SBOM")?;

    let spinner = output::spinner("Exporting SBOM...");

    let resp = if let Some(fmt) = target_format {
        let body = artifact_keeper_sdk::types::ConvertSbomRequest {
            target_format: fmt.to_string(),
        };
        client
            .convert_sbom()
            .id(sid)
            .body(body)
            .send()
            .await
            .map_err(|e| AkError::ServerError(format!("Failed to convert SBOM: {e}")))?
    } else {
        // No conversion needed: fetch the SBOM content and write it directly
        let content_resp = client
            .get_sbom()
            .id(sid)
            .send()
            .await
            .map_err(|e| AkError::ServerError(format!("Failed to get SBOM: {e}")))?;

        let content = content_resp.into_inner();
        let json = serde_json::to_string_pretty(&content.content)
            .map_err(|e| AkError::ServerError(format!("Failed to serialize SBOM content: {e}")))?;

        std::fs::write(output_path, json)
            .map_err(|e| AkError::ServerError(format!("Failed to write file: {e}")))?;

        spinner.finish_and_clear();
        eprintln!("SBOM exported to {output_path}");
        return Ok(());
    };

    let sbom = resp.into_inner();

    // Write the response as JSON to the output file
    let json = serde_json::to_string_pretty(&sbom)
        .map_err(|e| AkError::ServerError(format!("Failed to serialize SBOM: {e}")))?;

    std::fs::write(output_path, json)
        .map_err(|e| AkError::ServerError(format!("Failed to write file: {e}")))?;

    spinner.finish_and_clear();
    eprintln!("SBOM exported to {output_path} (format: {})", sbom.format);

    Ok(())
}

// ---------------------------------------------------------------------------
// CVE handlers
// ---------------------------------------------------------------------------

async fn cve_history(artifact_id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let aid = parse_uuid(artifact_id, "artifact")?;

    let spinner = output::spinner("Fetching CVE history...");

    let resp = client
        .get_cve_history()
        .artifact_id(aid)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to get CVE history: {e}")))?;

    let entries = resp.into_inner();
    spinner.finish_and_clear();

    if entries.is_empty() {
        eprintln!("No CVE history found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for e in &entries {
            println!("{}", e.cve_id);
        }
        return Ok(());
    }

    let json_entries: Vec<_> = entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "id": e.id.to_string(),
                "cve_id": e.cve_id,
                "severity": e.severity,
                "affected_component": e.affected_component,
                "status": e.status,
                "cvss_score": e.cvss_score,
                "first_detected_at": e.first_detected_at.to_rfc3339(),
            })
        })
        .collect();

    let table_str = {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                "CVE",
                "SEVERITY",
                "COMPONENT",
                "STATUS",
                "CVSS",
                "DISCOVERED",
            ]);

        for e in &entries {
            let severity = e.severity.as_deref().unwrap_or("-");
            let component = e.affected_component.as_deref().unwrap_or("-");
            let cvss = e
                .cvss_score
                .map(|s| format!("{s:.1}"))
                .unwrap_or_else(|| "-".to_string());

            table.add_row(vec![
                e.cve_id.clone(),
                severity.to_string(),
                component.to_string(),
                e.status.clone(),
                cvss,
                e.first_detected_at.format("%Y-%m-%d %H:%M").to_string(),
            ]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render(&json_entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn cve_trends(days: i32, repo: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let repo_id = parse_optional_uuid(repo, "repository")?;

    let spinner = output::spinner("Fetching CVE trends...");

    let mut req = client.get_cve_trends().days(days);
    if let Some(rid) = repo_id {
        req = req.repository_id(rid);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to get CVE trends: {e}")))?;

    let trends = resp.into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", trends.total_cves);
        return Ok(());
    }

    let info = serde_json::json!({
        "total_cves": trends.total_cves,
        "open_cves": trends.open_cves,
        "fixed_cves": trends.fixed_cves,
        "acknowledged_cves": trends.acknowledged_cves,
        "critical_count": trends.critical_count,
        "high_count": trends.high_count,
        "medium_count": trends.medium_count,
        "low_count": trends.low_count,
        "avg_days_to_fix": trends.avg_days_to_fix,
        "timeline_entries": trends.timeline.len(),
    });

    let avg_fix = trends
        .avg_days_to_fix
        .map(|d| format!("{d:.1} days"))
        .unwrap_or_else(|| "-".to_string());

    let table_str = format!(
        "CVE Trends ({days}-day window)\n\n\
         Total CVEs:      {}\n\
         Open:            {}\n\
         Fixed:           {}\n\
         Acknowledged:    {}\n\n\
         By Severity:\n\
         Critical:        {}\n\
         High:            {}\n\
         Medium:          {}\n\
         Low:             {}\n\n\
         Avg Time to Fix: {}",
        trends.total_cves,
        trends.open_cves,
        trends.fixed_cves,
        trends.acknowledged_cves,
        trends.critical_count,
        trends.high_count,
        trends.medium_count,
        trends.low_count,
        avg_fix,
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn cve_update_status(
    cve_id: &str,
    status: &str,
    reason: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(cve_id, "CVE history entry")?;

    let spinner = output::spinner("Updating CVE status...");

    let body = artifact_keeper_sdk::types::UpdateCveStatusRequest {
        status: status.to_string(),
        reason: reason.map(|s| s.to_string()),
    };

    let resp = client
        .update_cve_status()
        .id(id)
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to update CVE status: {e}")))?;

    let entry = resp.into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", entry.id);
        return Ok(());
    }

    let info = serde_json::json!({
        "id": entry.id.to_string(),
        "cve_id": entry.cve_id,
        "status": entry.status,
        "severity": entry.severity,
        "affected_component": entry.affected_component,
        "updated_at": entry.updated_at.to_rfc3339(),
    });

    let table_str = format!(
        "CVE status updated.\n\n\
         ID:              {}\n\
         CVE:             {}\n\
         Status:          {}\n\
         Severity:        {}\n\
         Component:       {}\n\
         Updated:         {}",
        entry.id,
        entry.cve_id,
        entry.status,
        entry.severity.as_deref().unwrap_or("-"),
        entry.affected_component.as_deref().unwrap_or("-"),
        entry.updated_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}
