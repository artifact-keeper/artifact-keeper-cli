use artifact_keeper_sdk::ClientSbomExt;
use artifact_keeper_sdk::types::{ComponentResponse, CveHistoryEntry, SbomResponse};
use clap::Subcommand;
use miette::Result;
use serde_json::Value;

use super::client::client_for;
use super::helpers::{
    confirm_action, new_table, parse_optional_uuid, parse_uuid, sdk_err, short_id,
};
use crate::cli::GlobalArgs;
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
        .map_err(|e| sdk_err("generate SBOM", e))?;

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
        .map_err(|e| sdk_err("get SBOM", e))?;

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

    let resp = req.send().await.map_err(|e| sdk_err("list SBOMs", e))?;

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

    let (entries, table_str) = format_sboms_table(&sboms);

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
        .map_err(|e| sdk_err("get SBOM", e))?;

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
        .map_err(|e| sdk_err("delete SBOM", e))?;

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
        .map_err(|e| sdk_err("get SBOM components", e))?;

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

    let (entries, table_str) = format_components_table(&components);

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
            .map_err(|e| sdk_err("convert SBOM", e))?
    } else {
        // No conversion needed: fetch the SBOM content and write it directly
        let content_resp = client
            .get_sbom()
            .id(sid)
            .send()
            .await
            .map_err(|e| sdk_err("get SBOM", e))?;

        let content = content_resp.into_inner();
        let json = serde_json::to_string_pretty(&content.content)
            .map_err(|e| sdk_err("serialize SBOM content", e))?;

        std::fs::write(output_path, json).map_err(|e| sdk_err("write file", e))?;

        spinner.finish_and_clear();
        eprintln!("SBOM exported to {output_path}");
        return Ok(());
    };

    let sbom = resp.into_inner();

    // Write the response as JSON to the output file
    let json = serde_json::to_string_pretty(&sbom).map_err(|e| sdk_err("serialize SBOM", e))?;

    std::fs::write(output_path, json).map_err(|e| sdk_err("write file", e))?;

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
        .map_err(|e| sdk_err("get CVE history", e))?;

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

    let (json_entries, table_str) = format_cve_history_table(&entries);

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

    let resp = req.send().await.map_err(|e| sdk_err("get CVE trends", e))?;

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
        .map_err(|e| sdk_err("update CVE status", e))?;

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

// ---------------------------------------------------------------------------
// Formatting helpers (pure functions, testable without HTTP)
// ---------------------------------------------------------------------------

fn format_sboms_table(sboms: &[SbomResponse]) -> (Vec<Value>, String) {
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
        let mut table = new_table(vec![
            "ID",
            "ARTIFACT",
            "FORMAT",
            "COMPONENTS",
            "LICENSES",
            "GENERATED",
        ]);

        for s in sboms {
            let id_short = short_id(&s.id);
            let artifact_short = short_id(&s.artifact_id);

            table.add_row(vec![
                id_short.clone(),
                artifact_short.clone(),
                s.format.clone(),
                s.component_count.to_string(),
                s.license_count.to_string(),
                s.generated_at.format("%Y-%m-%d %H:%M").to_string(),
            ]);
        }

        table.to_string()
    };

    (entries, table_str)
}

fn format_components_table(components: &[ComponentResponse]) -> (Vec<Value>, String) {
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
        let mut table = new_table(vec!["ID", "NAME", "VERSION", "TYPE", "PURL", "LICENSES"]);

        for c in components {
            let id_short = short_id(&c.id);
            let version = c.version.as_deref().unwrap_or("-");
            let ctype = c.component_type.as_deref().unwrap_or("-");
            let purl = c.purl.as_deref().unwrap_or("-");
            let licenses = if c.licenses.is_empty() {
                "-".to_string()
            } else {
                c.licenses.join(", ")
            };

            table.add_row(vec![
                id_short.clone(),
                c.name.clone(),
                version.to_string(),
                ctype.to_string(),
                purl.to_string(),
                licenses,
            ]);
        }

        table.to_string()
    };

    (entries, table_str)
}

fn format_cve_history_table(entries: &[CveHistoryEntry]) -> (Vec<Value>, String) {
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
        let mut table = new_table(vec![
            "CVE",
            "SEVERITY",
            "COMPONENT",
            "STATUS",
            "CVSS",
            "DISCOVERED",
        ]);

        for e in entries {
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

    (json_entries, table_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: SbomCommand,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).unwrap()
    }

    fn try_parse(args: &[&str]) -> Result<TestCli, clap::Error> {
        TestCli::try_parse_from(args)
    }

    // ---- SbomCommand top-level ----

    #[test]
    fn parse_generate_minimal() {
        let cli = parse(&["test", "generate", "00000000-0000-0000-0000-000000000001"]);
        if let SbomCommand::Generate {
            artifact_id,
            sbom_format,
            force,
        } = cli.command
        {
            assert_eq!(artifact_id, "00000000-0000-0000-0000-000000000001");
            assert!(sbom_format.is_none());
            assert!(!force);
        } else {
            panic!("Expected Generate");
        }
    }

    #[test]
    fn parse_generate_with_format_and_force() {
        let cli = parse(&[
            "test",
            "generate",
            "00000000-0000-0000-0000-000000000001",
            "--sbom-format",
            "cyclonedx",
            "--force",
        ]);
        if let SbomCommand::Generate {
            sbom_format, force, ..
        } = cli.command
        {
            assert_eq!(sbom_format.unwrap(), "cyclonedx");
            assert!(force);
        } else {
            panic!("Expected Generate with format and force");
        }
    }

    #[test]
    fn parse_show() {
        let cli = parse(&["test", "show", "00000000-0000-0000-0000-000000000001"]);
        if let SbomCommand::Show { artifact_id } = cli.command {
            assert_eq!(artifact_id, "00000000-0000-0000-0000-000000000001");
        } else {
            panic!("Expected Show");
        }
    }

    #[test]
    fn parse_list_no_filters() {
        let cli = parse(&["test", "list"]);
        if let SbomCommand::List {
            repo,
            sbom_format,
            artifact,
        } = cli.command
        {
            assert!(repo.is_none());
            assert!(sbom_format.is_none());
            assert!(artifact.is_none());
        } else {
            panic!("Expected List");
        }
    }

    #[test]
    fn parse_list_with_filters() {
        let cli = parse(&[
            "test",
            "list",
            "--repo",
            "00000000-0000-0000-0000-000000000001",
            "--sbom-format",
            "spdx",
            "--artifact",
            "00000000-0000-0000-0000-000000000002",
        ]);
        if let SbomCommand::List {
            repo,
            sbom_format,
            artifact,
        } = cli.command
        {
            assert_eq!(repo.unwrap(), "00000000-0000-0000-0000-000000000001");
            assert_eq!(sbom_format.unwrap(), "spdx");
            assert_eq!(artifact.unwrap(), "00000000-0000-0000-0000-000000000002");
        } else {
            panic!("Expected List with filters");
        }
    }

    #[test]
    fn parse_get() {
        let cli = parse(&["test", "get", "sbom-id-123"]);
        if let SbomCommand::Get { sbom_id } = cli.command {
            assert_eq!(sbom_id, "sbom-id-123");
        } else {
            panic!("Expected Get");
        }
    }

    #[test]
    fn parse_delete() {
        let cli = parse(&["test", "delete", "sbom-id-123"]);
        if let SbomCommand::Delete { sbom_id, yes } = cli.command {
            assert_eq!(sbom_id, "sbom-id-123");
            assert!(!yes);
        } else {
            panic!("Expected Delete");
        }
    }

    #[test]
    fn parse_delete_with_yes() {
        let cli = parse(&["test", "delete", "sbom-id-123", "--yes"]);
        if let SbomCommand::Delete { yes, .. } = cli.command {
            assert!(yes);
        } else {
            panic!("Expected Delete with --yes");
        }
    }

    #[test]
    fn parse_components() {
        let cli = parse(&["test", "components", "sbom-id-123"]);
        if let SbomCommand::Components { sbom_id } = cli.command {
            assert_eq!(sbom_id, "sbom-id-123");
        } else {
            panic!("Expected Components");
        }
    }

    #[test]
    fn parse_export_minimal() {
        let cli = parse(&[
            "test",
            "export",
            "sbom-id-123",
            "--output",
            "/tmp/sbom.json",
        ]);
        if let SbomCommand::Export {
            sbom_id,
            output,
            target_format,
        } = cli.command
        {
            assert_eq!(sbom_id, "sbom-id-123");
            assert_eq!(output, "/tmp/sbom.json");
            assert!(target_format.is_none());
        } else {
            panic!("Expected Export");
        }
    }

    #[test]
    fn parse_export_with_target_format() {
        let cli = parse(&[
            "test",
            "export",
            "sbom-id-123",
            "--output",
            "/tmp/sbom.json",
            "--target-format",
            "cyclonedx",
        ]);
        if let SbomCommand::Export { target_format, .. } = cli.command {
            assert_eq!(target_format.unwrap(), "cyclonedx");
        } else {
            panic!("Expected Export with target format");
        }
    }

    #[test]
    fn parse_export_missing_output() {
        let result = try_parse(&["test", "export", "sbom-id-123"]);
        assert!(result.is_err());
    }

    // ---- SbomCveCommand ----

    #[test]
    fn parse_cve_history() {
        let cli = parse(&[
            "test",
            "cve",
            "history",
            "00000000-0000-0000-0000-000000000001",
        ]);
        if let SbomCommand::Cve(SbomCveCommand::History { artifact_id }) = cli.command {
            assert_eq!(artifact_id, "00000000-0000-0000-0000-000000000001");
        } else {
            panic!("Expected Cve History");
        }
    }

    #[test]
    fn parse_cve_trends_defaults() {
        let cli = parse(&["test", "cve", "trends"]);
        if let SbomCommand::Cve(SbomCveCommand::Trends { days, repo }) = cli.command {
            assert_eq!(days, 30);
            assert!(repo.is_none());
        } else {
            panic!("Expected Cve Trends");
        }
    }

    #[test]
    fn parse_cve_trends_with_args() {
        let cli = parse(&[
            "test",
            "cve",
            "trends",
            "--days",
            "90",
            "--repo",
            "00000000-0000-0000-0000-000000000001",
        ]);
        if let SbomCommand::Cve(SbomCveCommand::Trends { days, repo }) = cli.command {
            assert_eq!(days, 90);
            assert_eq!(repo.unwrap(), "00000000-0000-0000-0000-000000000001");
        } else {
            panic!("Expected Cve Trends with args");
        }
    }

    #[test]
    fn parse_cve_update_status() {
        let cli = parse(&[
            "test",
            "cve",
            "update-status",
            "cve-id-123",
            "--status",
            "fixed",
        ]);
        if let SbomCommand::Cve(SbomCveCommand::UpdateStatus {
            cve_id,
            status,
            reason,
        }) = cli.command
        {
            assert_eq!(cve_id, "cve-id-123");
            assert_eq!(status, "fixed");
            assert!(reason.is_none());
        } else {
            panic!("Expected Cve UpdateStatus");
        }
    }

    #[test]
    fn parse_cve_update_status_with_reason() {
        let cli = parse(&[
            "test",
            "cve",
            "update-status",
            "cve-id-123",
            "--status",
            "false_positive",
            "--reason",
            "Not applicable to our usage",
        ]);
        if let SbomCommand::Cve(SbomCveCommand::UpdateStatus { reason, .. }) = cli.command {
            assert_eq!(reason.unwrap(), "Not applicable to our usage");
        } else {
            panic!("Expected Cve UpdateStatus with reason");
        }
    }

    #[test]
    fn parse_cve_update_status_missing_status() {
        let result = try_parse(&["test", "cve", "update-status", "cve-id-123"]);
        assert!(result.is_err());
    }

    // ---- Format function tests ----

    use artifact_keeper_sdk::types::{ComponentResponse, CveHistoryEntry, SbomResponse};
    use chrono::Utc;
    use uuid::Uuid;

    fn make_test_sbom(format: &str, components: i32, licenses: i32) -> SbomResponse {
        SbomResponse {
            id: Uuid::nil(),
            artifact_id: Uuid::nil(),
            repository_id: Uuid::nil(),
            format: format.to_string(),
            format_version: "1.0".to_string(),
            component_count: components,
            dependency_count: 0,
            license_count: licenses,
            licenses: vec!["MIT".to_string()],
            content_hash: "sha256:abc".to_string(),
            generated_at: Utc::now(),
            created_at: Utc::now(),
            generator: None,
            generator_version: None,
            spec_version: None,
        }
    }

    fn make_test_component(name: &str, version: Option<&str>) -> ComponentResponse {
        ComponentResponse {
            id: Uuid::nil(),
            sbom_id: Uuid::nil(),
            name: name.to_string(),
            version: version.map(|v| v.to_string()),
            component_type: Some("library".to_string()),
            purl: Some(format!("pkg:npm/{name}@{}", version.unwrap_or("0.0.0"))),
            licenses: vec!["MIT".to_string()],
            author: None,
            cpe: None,
            md5: None,
            sha1: None,
            sha256: None,
            supplier: None,
        }
    }

    fn make_test_cve(cve_id: &str, severity: Option<&str>, cvss: Option<f64>) -> CveHistoryEntry {
        CveHistoryEntry {
            id: Uuid::nil(),
            artifact_id: Uuid::nil(),
            cve_id: cve_id.to_string(),
            severity: severity.map(|s| s.to_string()),
            affected_component: Some("lodash".to_string()),
            status: "open".to_string(),
            cvss_score: cvss,
            first_detected_at: Utc::now(),
            last_detected_at: Utc::now(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            acknowledged_at: None,
            acknowledged_by: None,
            acknowledged_reason: None,
            affected_version: None,
            component_id: None,
            cve_published_at: None,
            fixed_version: None,
            sbom_id: None,
            scan_result_id: None,
        }
    }

    #[test]
    fn format_sboms_table_single() {
        let sboms = vec![make_test_sbom("spdx", 42, 5)];
        let (entries, table_str) = format_sboms_table(&sboms);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["format"], "spdx");
        assert_eq!(entries[0]["component_count"], 42);
        assert_eq!(entries[0]["license_count"], 5);

        assert!(table_str.contains("FORMAT"));
        assert!(table_str.contains("COMPONENTS"));
        assert!(table_str.contains("spdx"));
        assert!(table_str.contains("42"));
    }

    #[test]
    fn format_sboms_table_multiple() {
        let sboms = vec![
            make_test_sbom("spdx", 10, 3),
            make_test_sbom("cyclonedx", 20, 7),
        ];
        let (entries, table_str) = format_sboms_table(&sboms);

        assert_eq!(entries.len(), 2);
        assert!(table_str.contains("spdx"));
        assert!(table_str.contains("cyclonedx"));
    }

    #[test]
    fn format_sboms_table_empty() {
        let (entries, table_str) = format_sboms_table(&[]);
        assert!(entries.is_empty());
        assert!(table_str.contains("ID"));
    }

    #[test]
    fn format_components_table_single() {
        let components = vec![make_test_component("lodash", Some("4.17.21"))];
        let (entries, table_str) = format_components_table(&components);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["name"], "lodash");
        assert_eq!(entries[0]["version"], "4.17.21");

        assert!(table_str.contains("NAME"));
        assert!(table_str.contains("lodash"));
        assert!(table_str.contains("library"));
        assert!(table_str.contains("MIT"));
    }

    #[test]
    fn format_components_table_no_version() {
        let components = vec![make_test_component("unknown-pkg", None)];
        let (entries, table_str) = format_components_table(&components);

        assert!(entries[0]["version"].is_null());
        assert!(table_str.contains("-"));
    }

    #[test]
    fn format_components_table_no_licenses() {
        let mut comp = make_test_component("bare-pkg", Some("1.0.0"));
        comp.licenses = vec![];
        comp.component_type = None;
        comp.purl = None;
        let (entries, table_str) = format_components_table(&[comp]);

        let licenses = entries[0]["licenses"].as_array().unwrap();
        assert!(licenses.is_empty());
        // The table shows "-" for empty licenses
        assert!(table_str.contains("-"));
    }

    #[test]
    fn format_components_table_empty() {
        let (entries, table_str) = format_components_table(&[]);
        assert!(entries.is_empty());
        assert!(table_str.contains("NAME"));
    }

    #[test]
    fn format_cve_history_table_single() {
        let cves = vec![make_test_cve("CVE-2024-1234", Some("HIGH"), Some(8.5))];
        let (entries, table_str) = format_cve_history_table(&cves);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["cve_id"], "CVE-2024-1234");
        assert_eq!(entries[0]["severity"], "HIGH");
        assert_eq!(entries[0]["status"], "open");

        assert!(table_str.contains("CVE"));
        assert!(table_str.contains("SEVERITY"));
        assert!(table_str.contains("CVE-2024-1234"));
        assert!(table_str.contains("HIGH"));
        assert!(table_str.contains("8.5"));
    }

    #[test]
    fn format_cve_history_table_no_severity() {
        let cves = vec![make_test_cve("CVE-2024-0000", None, None)];
        let (entries, table_str) = format_cve_history_table(&cves);

        assert!(entries[0]["severity"].is_null());
        assert!(entries[0]["cvss_score"].is_null());
        assert!(table_str.contains("-"));
    }

    #[test]
    fn format_cve_history_table_multiple() {
        let cves = vec![
            make_test_cve("CVE-2024-1111", Some("CRITICAL"), Some(9.8)),
            make_test_cve("CVE-2024-2222", Some("LOW"), Some(2.0)),
        ];
        let (entries, table_str) = format_cve_history_table(&cves);

        assert_eq!(entries.len(), 2);
        assert!(table_str.contains("CVE-2024-1111"));
        assert!(table_str.contains("CVE-2024-2222"));
        assert!(table_str.contains("CRITICAL"));
        assert!(table_str.contains("LOW"));
    }

    #[test]
    fn format_cve_history_table_empty() {
        let (entries, table_str) = format_cve_history_table(&[]);
        assert!(entries.is_empty());
        assert!(table_str.contains("CVE"));
    }

    // ========================================================================
    // Wiremock-based handler tests
    // ========================================================================

    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, ResponseTemplate};

    /// Set up env vars for handler tests; returns a guard that must be held.

    static NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

    #[tokio::test]
    async fn handler_generate_sbom() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/sbom"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": NIL_UUID,
                "artifact_id": NIL_UUID,
                "repository_id": NIL_UUID,
                "format": "spdx",
                "format_version": "2.3",
                "component_count": 42,
                "dependency_count": 10,
                "license_count": 5,
                "licenses": ["MIT", "Apache-2.0"],
                "content_hash": "sha256:abc123",
                "generated_at": "2024-02-21T00:00:00Z",
                "created_at": "2024-02-21T00:00:00Z",
                "generator": null,
                "generator_version": null,
                "spec_version": null
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = generate_sbom(NIL_UUID, Some("spdx"), false, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_generate_sbom_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/sbom"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": NIL_UUID,
                "artifact_id": NIL_UUID,
                "repository_id": NIL_UUID,
                "format": "cyclonedx",
                "format_version": "1.5",
                "component_count": 10,
                "dependency_count": 5,
                "license_count": 2,
                "licenses": ["MIT"],
                "content_hash": "sha256:def456",
                "generated_at": "2024-02-21T00:00:00Z",
                "created_at": "2024-02-21T00:00:00Z",
                "generator": null,
                "generator_version": null,
                "spec_version": null
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = generate_sbom(NIL_UUID, None, true, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_sbom() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/sbom/by-artifact/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": NIL_UUID,
                "artifact_id": NIL_UUID,
                "repository_id": NIL_UUID,
                "format": "spdx",
                "format_version": "2.3",
                "component_count": 42,
                "dependency_count": 10,
                "license_count": 3,
                "licenses": ["MIT", "Apache-2.0", "BSD-3-Clause"],
                "content_hash": "sha256:abc123",
                "content": {"packages": []},
                "generated_at": "2024-02-21T00:00:00Z",
                "created_at": "2024-02-21T00:00:00Z",
                "generator": null,
                "generator_version": null,
                "spec_version": null
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = show_sbom(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_sboms_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/sbom"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list_sboms(None, None, None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_sboms_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/sbom"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "id": NIL_UUID,
                    "artifact_id": NIL_UUID,
                    "repository_id": NIL_UUID,
                    "format": "spdx",
                    "format_version": "2.3",
                    "component_count": 42,
                    "dependency_count": 10,
                    "license_count": 5,
                    "licenses": ["MIT"],
                    "content_hash": "sha256:abc",
                    "generated_at": "2024-02-21T00:00:00Z",
                    "created_at": "2024-02-21T00:00:00Z",
                    "generator": null,
                    "generator_version": null,
                    "spec_version": null
                }
            ])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list_sboms(None, Some("spdx"), None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_get_sbom() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/sbom/[0-9a-f-]+$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": NIL_UUID,
                "artifact_id": NIL_UUID,
                "repository_id": NIL_UUID,
                "format": "cyclonedx",
                "format_version": "1.5",
                "component_count": 20,
                "dependency_count": 8,
                "license_count": 2,
                "licenses": ["MIT", "ISC"],
                "content_hash": "sha256:xyz",
                "content": {"components": []},
                "generated_at": "2024-02-21T00:00:00Z",
                "created_at": "2024-02-21T00:00:00Z",
                "generator": null,
                "generator_version": null,
                "spec_version": null
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = get_sbom(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_delete_sbom() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path_regex("/api/v1/sbom/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "message": "SBOM deleted"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        // skip_confirm=true because no_input=true in test_global
        let result = delete_sbom(NIL_UUID, true, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_get_components_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/sbom/.+/components"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = get_components(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_get_components_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/sbom/.+/components"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "id": NIL_UUID,
                    "sbom_id": NIL_UUID,
                    "name": "lodash",
                    "version": "4.17.21",
                    "component_type": "library",
                    "purl": "pkg:npm/lodash@4.17.21",
                    "licenses": ["MIT"],
                    "author": null,
                    "cpe": null,
                    "md5": null,
                    "sha1": null,
                    "sha256": null,
                    "supplier": null
                }
            ])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = get_components(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_cve_history_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/sbom/cve/history/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = cve_history(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_cve_history_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/sbom/cve/history/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "id": NIL_UUID,
                    "artifact_id": NIL_UUID,
                    "cve_id": "CVE-2024-1234",
                    "severity": "HIGH",
                    "affected_component": "lodash",
                    "status": "open",
                    "cvss_score": 8.5,
                    "first_detected_at": "2024-02-21T00:00:00Z",
                    "last_detected_at": "2024-02-21T00:00:00Z",
                    "created_at": "2024-02-21T00:00:00Z",
                    "updated_at": "2024-02-21T00:00:00Z",
                    "acknowledged_at": null,
                    "acknowledged_by": null,
                    "acknowledged_reason": null,
                    "affected_version": null,
                    "component_id": null,
                    "cve_published_at": null,
                    "fixed_version": null,
                    "sbom_id": null,
                    "scan_result_id": null
                }
            ])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = cve_history(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_cve_trends() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/sbom/cve/trends"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total_cves": 50,
                "open_cves": 20,
                "fixed_cves": 25,
                "acknowledged_cves": 5,
                "critical_count": 3,
                "high_count": 10,
                "medium_count": 20,
                "low_count": 17,
                "avg_days_to_fix": 14.5,
                "timeline": []
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = cve_trends(30, None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_cve_trends_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/sbom/cve/trends"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total_cves": 42,
                "open_cves": 10,
                "fixed_cves": 30,
                "acknowledged_cves": 2,
                "critical_count": 1,
                "high_count": 5,
                "medium_count": 15,
                "low_count": 21,
                "avg_days_to_fix": null,
                "timeline": []
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = cve_trends(90, None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_cve_update_status() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path_regex("/api/v1/sbom/cve/status/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": NIL_UUID,
                "artifact_id": NIL_UUID,
                "cve_id": "CVE-2024-1234",
                "severity": "HIGH",
                "affected_component": "lodash",
                "status": "fixed",
                "cvss_score": 8.5,
                "first_detected_at": "2024-02-21T00:00:00Z",
                "last_detected_at": "2024-02-21T00:00:00Z",
                "created_at": "2024-02-21T00:00:00Z",
                "updated_at": "2024-02-21T12:00:00Z",
                "acknowledged_at": null,
                "acknowledged_by": null,
                "acknowledged_reason": null,
                "affected_version": null,
                "component_id": null,
                "cve_published_at": null,
                "fixed_version": null,
                "sbom_id": null,
                "scan_result_id": null
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = cve_update_status(NIL_UUID, "fixed", Some("Patched in v2"), &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_cve_update_status_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path_regex("/api/v1/sbom/cve/status/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": NIL_UUID,
                "artifact_id": NIL_UUID,
                "cve_id": "CVE-2024-5678",
                "severity": "LOW",
                "affected_component": "express",
                "status": "false_positive",
                "cvss_score": 2.0,
                "first_detected_at": "2024-02-21T00:00:00Z",
                "last_detected_at": "2024-02-21T00:00:00Z",
                "created_at": "2024-02-21T00:00:00Z",
                "updated_at": "2024-02-21T12:00:00Z",
                "acknowledged_at": null,
                "acknowledged_by": null,
                "acknowledged_reason": null,
                "affected_version": null,
                "component_id": null,
                "cve_published_at": null,
                "fixed_version": null,
                "sbom_id": null,
                "scan_result_id": null
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = cve_update_status(NIL_UUID, "false_positive", None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }
}
