use artifact_keeper_sdk::ClientSecurityExt;
use clap::Subcommand;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use miette::Result;

use super::client::client_for;
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum DtCommand {
    /// Show Dependency-Track integration status
    Status,

    /// Manage Dependency-Track projects
    #[command(subcommand)]
    Project(DtProjectCommand),

    /// Show portfolio-level metrics
    Metrics,

    /// List Dependency-Track policies
    Policies,

    /// Update analysis (triage) for a finding
    Analyze {
        /// Project UUID
        #[arg(long)]
        project: String,

        /// Vulnerability UUID
        #[arg(long)]
        vulnerability: String,

        /// Component UUID
        #[arg(long)]
        component: String,

        /// Analysis state (e.g. NOT_AFFECTED, EXPLOITABLE, IN_TRIAGE, FALSE_POSITIVE, NOT_SET, RESOLVED)
        #[arg(long)]
        state: String,

        /// Justification for the analysis state
        #[arg(long)]
        justification: Option<String>,

        /// Additional details
        #[arg(long)]
        details: Option<String>,

        /// Whether the finding is suppressed
        #[arg(long)]
        suppressed: Option<bool>,
    },
}

#[derive(Subcommand)]
pub enum DtProjectCommand {
    /// List all projects
    List,

    /// Show project details
    Show {
        /// Project UUID
        uuid: String,
    },

    /// List components in a project
    Components {
        /// Project UUID
        uuid: String,
    },

    /// List findings (vulnerabilities) for a project
    Findings {
        /// Project UUID
        uuid: String,

        /// Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, UNASSIGNED)
        #[arg(long)]
        severity: Option<String>,
    },

    /// List policy violations for a project
    Violations {
        /// Project UUID
        uuid: String,
    },

    /// Show project metrics
    Metrics {
        /// Project UUID
        uuid: String,
    },

    /// Show project metrics history
    MetricsHistory {
        /// Project UUID
        uuid: String,

        /// Number of days of history
        #[arg(long, default_value = "30")]
        days: i32,
    },
}

impl DtCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Status => dt_status(global).await,
            Self::Project(cmd) => cmd.execute(global).await,
            Self::Metrics => portfolio_metrics(global).await,
            Self::Policies => list_policies(global).await,
            Self::Analyze {
                project,
                vulnerability,
                component,
                state,
                justification,
                details,
                suppressed,
            } => {
                update_analysis(
                    &project,
                    &vulnerability,
                    &component,
                    &state,
                    justification.as_deref(),
                    details.as_deref(),
                    suppressed,
                    global,
                )
                .await
            }
        }
    }
}

impl DtProjectCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List => project_list(global).await,
            Self::Show { uuid } => project_show(&uuid, global).await,
            Self::Components { uuid } => project_components(&uuid, global).await,
            Self::Findings { uuid, severity } => {
                project_findings(&uuid, severity.as_deref(), global).await
            }
            Self::Violations { uuid } => project_violations(&uuid, global).await,
            Self::Metrics { uuid } => project_metrics(&uuid, global).await,
            Self::MetricsHistory { uuid, days } => {
                project_metrics_history(&uuid, days, global).await
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn dt_status(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = crate::output::spinner("Checking Dependency-Track status...");

    let resp = client
        .dt_status()
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to get DT status: {e}")))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        let status = if resp.healthy { "healthy" } else { "unhealthy" };
        println!("{status}");
        return Ok(());
    }

    let data = serde_json::json!({
        "enabled": resp.enabled,
        "healthy": resp.healthy,
        "url": resp.url,
    });

    let table_str = format!(
        "Enabled:  {}\nHealthy:  {}\nURL:      {}",
        resp.enabled,
        resp.healthy,
        resp.url.as_deref().unwrap_or("-"),
    );

    println!("{}", output::render(&data, &global.format, Some(table_str)));

    Ok(())
}

async fn project_list(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = crate::output::spinner("Fetching projects...");

    let projects = client
        .list_projects()
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to list projects: {e}")))?;

    spinner.finish_and_clear();

    let projects = projects.into_inner();

    if projects.is_empty() {
        eprintln!("No projects found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for p in &projects {
            println!("{}", p.uuid);
        }
        return Ok(());
    }

    let entries: Vec<_> = projects
        .iter()
        .map(|p| {
            serde_json::json!({
                "uuid": p.uuid,
                "name": p.name,
                "version": p.version,
                "last_bom_import": p.last_bom_import,
            })
        })
        .collect();

    let table_str = {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec!["UUID", "NAME", "VERSION", "LAST BOM IMPORT"]);

        for p in &projects {
            let version = p.version.as_deref().unwrap_or("-");
            let last_bom = p
                .last_bom_import
                .map(format_timestamp)
                .unwrap_or_else(|| "-".to_string());
            table.add_row(vec![&p.uuid, &p.name, version, &last_bom]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn project_show(uuid: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = crate::output::spinner("Fetching project...");

    // get_project() returns Vec<DtFinding> in the SDK, so we list all projects
    // and find the matching one to get project details.
    let projects = client
        .list_projects()
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to fetch projects: {e}")))?;

    let project = projects
        .into_inner()
        .into_iter()
        .find(|p| p.uuid == uuid)
        .ok_or_else(|| AkError::ServerError(format!("Project not found: {uuid}")))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", project.uuid);
        return Ok(());
    }

    let data = serde_json::json!({
        "uuid": project.uuid,
        "name": project.name,
        "version": project.version,
        "description": project.description,
        "last_bom_import": project.last_bom_import,
        "last_bom_import_format": project.last_bom_import_format,
    });

    let table_str = format!(
        "UUID:              {}\nName:              {}\nVersion:           {}\nDescription:       {}\nLast BOM Import:   {}\nBOM Format:        {}",
        project.uuid,
        project.name,
        project.version.as_deref().unwrap_or("-"),
        project.description.as_deref().unwrap_or("-"),
        project
            .last_bom_import
            .map(format_timestamp)
            .unwrap_or_else(|| "-".to_string()),
        project.last_bom_import_format.as_deref().unwrap_or("-"),
    );

    println!("{}", output::render(&data, &global.format, Some(table_str)));

    Ok(())
}

async fn project_components(uuid: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = crate::output::spinner("Fetching components...");

    let components = client
        .get_project_components()
        .project_uuid(uuid)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to get components: {e}")))?;

    spinner.finish_and_clear();

    let components = components.into_inner();

    if components.is_empty() {
        eprintln!("No components found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for c in &components {
            println!("{}", c.uuid);
        }
        return Ok(());
    }

    let entries: Vec<_> = components
        .iter()
        .map(|c| {
            serde_json::json!({
                "uuid": c.uuid,
                "group": c.group,
                "name": c.name,
                "version": c.version,
                "purl": c.purl,
                "cpe": c.cpe,
                "is_internal": c.is_internal,
            })
        })
        .collect();

    let table_str = {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec!["UUID", "GROUP", "NAME", "VERSION", "PURL"]);

        for c in &components {
            let group = c.group.as_deref().unwrap_or("-");
            let version = c.version.as_deref().unwrap_or("-");
            let purl = c.purl.as_deref().unwrap_or("-");
            table.add_row(vec![&c.uuid, group, &c.name, version, purl]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    eprintln!("{} component(s).", components.len());

    Ok(())
}

async fn project_findings(
    uuid: &str,
    severity_filter: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let spinner = crate::output::spinner("Fetching findings...");

    let findings = client
        .get_project_findings()
        .project_uuid(uuid)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to get findings: {e}")))?;

    spinner.finish_and_clear();

    let findings = findings.into_inner();

    let filtered: Vec<_> = if let Some(sev) = severity_filter {
        let sev_upper = sev.to_uppercase();
        findings
            .iter()
            .filter(|f| f.vulnerability.severity.eq_ignore_ascii_case(&sev_upper))
            .collect()
    } else {
        findings.iter().collect()
    };

    if filtered.is_empty() {
        let msg = if severity_filter.is_some() {
            "No findings match the severity filter."
        } else {
            "No findings found."
        };
        eprintln!("{msg}");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for f in &filtered {
            println!("{}", f.vulnerability.vuln_id);
        }
        return Ok(());
    }

    let entries: Vec<_> = filtered
        .iter()
        .map(|f| {
            serde_json::json!({
                "vuln_id": f.vulnerability.vuln_id,
                "severity": f.vulnerability.severity,
                "source": f.vulnerability.source,
                "component": f.component.name,
                "component_version": f.component.version,
                "title": f.vulnerability.title,
                "cvss_v3": f.vulnerability.cvss_v3_base_score,
            })
        })
        .collect();

    let table_str = {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                "VULN ID",
                "SEVERITY",
                "SOURCE",
                "COMPONENT",
                "VERSION",
                "CVSS v3",
            ]);

        for f in &filtered {
            let version = f.component.version.as_deref().unwrap_or("-");
            let cvss = f
                .vulnerability
                .cvss_v3_base_score
                .map(|s| format!("{s:.1}"))
                .unwrap_or_else(|| "-".to_string());
            table.add_row(vec![
                &f.vulnerability.vuln_id,
                &f.vulnerability.severity,
                &f.vulnerability.source,
                &f.component.name,
                version,
                &cvss,
            ]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    eprintln!("{} finding(s).", filtered.len());

    Ok(())
}

async fn project_violations(uuid: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = crate::output::spinner("Fetching violations...");

    let violations = client
        .get_project_violations()
        .project_uuid(uuid)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to get violations: {e}")))?;

    spinner.finish_and_clear();

    let violations = violations.into_inner();

    if violations.is_empty() {
        eprintln!("No policy violations found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for v in &violations {
            println!("{}", v.uuid);
        }
        return Ok(());
    }

    let entries: Vec<_> = violations
        .iter()
        .map(|v| {
            serde_json::json!({
                "uuid": v.uuid,
                "type": v.type_,
                "component": v.component.name,
                "component_version": v.component.version,
                "policy": v.policy_condition.policy.name,
                "condition_subject": v.policy_condition.subject,
                "condition_operator": v.policy_condition.operator,
                "condition_value": v.policy_condition.value,
            })
        })
        .collect();

    let table_str = {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                "UUID",
                "TYPE",
                "COMPONENT",
                "VERSION",
                "POLICY",
                "SUBJECT",
            ]);

        for v in &violations {
            let version = v.component.version.as_deref().unwrap_or("-");
            table.add_row(vec![
                &v.uuid,
                &v.type_,
                &v.component.name,
                version,
                &v.policy_condition.policy.name,
                &v.policy_condition.subject,
            ]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    eprintln!("{} violation(s).", violations.len());

    Ok(())
}

async fn project_metrics(uuid: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = crate::output::spinner("Fetching project metrics...");

    let metrics = client
        .get_project_metrics()
        .project_uuid(uuid)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to get project metrics: {e}")))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        let total = metrics.vulnerabilities.unwrap_or(0);
        println!("{total}");
        return Ok(());
    }

    let data = serde_json::json!({
        "critical": metrics.critical,
        "high": metrics.high,
        "medium": metrics.medium,
        "low": metrics.low,
        "unassigned": metrics.unassigned,
        "findings_audited": metrics.findings_audited,
        "findings_total": metrics.findings_total,
        "inherited_risk_score": metrics.inherited_risk_score,
        "policy_violations_total": metrics.policy_violations_total,
        "suppressions": metrics.suppressions,
    });

    let table_str = format!(
        "Critical:     {}\nHigh:         {}\nMedium:       {}\nLow:          {}\nUnassigned:   {}\nAudited:      {}/{}",
        metrics.critical.unwrap_or(0),
        metrics.high.unwrap_or(0),
        metrics.medium.unwrap_or(0),
        metrics.low.unwrap_or(0),
        metrics.unassigned.unwrap_or(0),
        metrics.findings_audited.unwrap_or(0),
        metrics.findings_total.unwrap_or(0),
    );

    println!("{}", output::render(&data, &global.format, Some(table_str)));

    Ok(())
}

async fn project_metrics_history(uuid: &str, days: i32, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = crate::output::spinner("Fetching metrics history...");

    let history = client
        .get_project_metrics_history()
        .project_uuid(uuid)
        .days(days)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to get metrics history: {e}")))?;

    spinner.finish_and_clear();

    let history = history.into_inner();

    if history.is_empty() {
        eprintln!("No metrics history found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", history.len());
        return Ok(());
    }

    let entries: Vec<_> = history
        .iter()
        .map(|m| {
            serde_json::json!({
                "critical": m.critical,
                "high": m.high,
                "medium": m.medium,
                "low": m.low,
                "unassigned": m.unassigned,
                "findings_total": m.findings_total,
                "findings_audited": m.findings_audited,
                "first_occurrence": m.first_occurrence,
                "last_occurrence": m.last_occurrence,
            })
        })
        .collect();

    let table_str = {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                "DATE",
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW",
                "UNASSIGNED",
                "TOTAL",
                "AUDITED",
            ]);

        for m in &history {
            let date = m
                .last_occurrence
                .map(format_timestamp)
                .unwrap_or_else(|| "-".to_string());
            table.add_row(vec![
                &date,
                &m.critical.unwrap_or(0).to_string(),
                &m.high.unwrap_or(0).to_string(),
                &m.medium.unwrap_or(0).to_string(),
                &m.low.unwrap_or(0).to_string(),
                &m.unassigned.unwrap_or(0).to_string(),
                &m.findings_total.unwrap_or(0).to_string(),
                &m.findings_audited.unwrap_or(0).to_string(),
            ]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    eprintln!("{} data point(s) over {} days.", history.len(), days);

    Ok(())
}

async fn portfolio_metrics(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = crate::output::spinner("Fetching portfolio metrics...");

    let metrics = client
        .get_portfolio_metrics()
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to get portfolio metrics: {e}")))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        let total = metrics.vulnerabilities.unwrap_or(0);
        println!("{total}");
        return Ok(());
    }

    let data = serde_json::json!({
        "critical": metrics.critical,
        "high": metrics.high,
        "medium": metrics.medium,
        "low": metrics.low,
        "unassigned": metrics.unassigned,
        "findings_audited": metrics.findings_audited,
        "findings_total": metrics.findings_total,
        "projects": metrics.projects,
        "inherited_risk_score": metrics.inherited_risk_score,
        "policy_violations_total": metrics.policy_violations_total,
        "suppressions": metrics.suppressions,
    });

    let table_str = format!(
        "Projects:     {}\nCritical:     {}\nHigh:         {}\nMedium:       {}\nLow:          {}\nUnassigned:   {}\nAudited:      {}/{}",
        metrics.projects.unwrap_or(0),
        metrics.critical.unwrap_or(0),
        metrics.high.unwrap_or(0),
        metrics.medium.unwrap_or(0),
        metrics.low.unwrap_or(0),
        metrics.unassigned.unwrap_or(0),
        metrics.findings_audited.unwrap_or(0),
        metrics.findings_total.unwrap_or(0),
    );

    println!("{}", output::render(&data, &global.format, Some(table_str)));

    Ok(())
}

async fn list_policies(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = crate::output::spinner("Fetching policies...");

    let policies = client
        .list_dependency_track_policies()
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to list policies: {e}")))?;

    spinner.finish_and_clear();

    let policies = policies.into_inner();

    if policies.is_empty() {
        eprintln!("No policies found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for p in &policies {
            println!("{}", p.uuid);
        }
        return Ok(());
    }

    let entries: Vec<_> = policies
        .iter()
        .map(|p| {
            serde_json::json!({
                "uuid": p.uuid,
                "name": p.name,
                "violation_state": p.violation_state,
                "conditions": p.policy_conditions.len(),
                "projects": p.projects.len(),
                "include_children": p.include_children,
            })
        })
        .collect();

    let table_str = {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                "UUID",
                "NAME",
                "VIOLATION STATE",
                "CONDITIONS",
                "PROJECTS",
            ]);

        for p in &policies {
            table.add_row(vec![
                &p.uuid,
                &p.name,
                &p.violation_state,
                &p.policy_conditions.len().to_string(),
                &p.projects.len().to_string(),
            ]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    eprintln!("{} policy/policies.", policies.len());

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn update_analysis(
    project_uuid: &str,
    vulnerability_uuid: &str,
    component_uuid: &str,
    state: &str,
    justification: Option<&str>,
    details: Option<&str>,
    suppressed: Option<bool>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let spinner = crate::output::spinner("Updating analysis...");

    let body = artifact_keeper_sdk::types::UpdateAnalysisBody {
        project_uuid: project_uuid.to_string(),
        vulnerability_uuid: vulnerability_uuid.to_string(),
        component_uuid: component_uuid.to_string(),
        state: state.to_string(),
        justification: justification.map(|s| s.to_string()),
        details: details.map(|s| s.to_string()),
        suppressed,
    };

    let resp = client
        .update_analysis()
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to update analysis: {e}")))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", resp.analysis_state);
        return Ok(());
    }

    let data = serde_json::json!({
        "analysis_state": resp.analysis_state,
        "is_suppressed": resp.is_suppressed,
        "analysis_justification": resp.analysis_justification,
        "analysis_details": resp.analysis_details,
    });

    let table_str = format!(
        "State:          {}\nSuppressed:     {}\nJustification:  {}\nDetails:        {}",
        resp.analysis_state,
        resp.is_suppressed,
        resp.analysis_justification.as_deref().unwrap_or("-"),
        resp.analysis_details.as_deref().unwrap_or("-"),
    );

    println!("{}", output::render(&data, &global.format, Some(table_str)));

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn format_timestamp(epoch_millis: i64) -> String {
    let secs = epoch_millis / 1000;
    let dt = chrono::DateTime::from_timestamp(secs, 0);
    match dt {
        Some(d) => d.format("%Y-%m-%d %H:%M").to_string(),
        None => epoch_millis.to_string(),
    }
}
