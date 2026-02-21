use artifact_keeper_sdk::ClientSecurityExt;
use artifact_keeper_sdk::types::{
    DtComponentFull, DtFinding, DtPolicyFull, DtPortfolioMetrics, DtProject, DtProjectMetrics,
};
use clap::Subcommand;
use miette::Result;
use serde_json::Value;

use super::client::client_for;
use super::helpers::{new_table, sdk_err};
use crate::cli::GlobalArgs;
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
        .map_err(|e| sdk_err("get DT status", e))?;

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
        .map_err(|e| sdk_err("list projects", e))?;

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

    let (entries, table_str) = format_projects_table(&projects);

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
        .map_err(|e| sdk_err("fetch projects", e))?;

    let project = projects
        .into_inner()
        .into_iter()
        .find(|p| p.uuid == uuid)
        .ok_or_else(|| sdk_err("find project", format!("not found: {uuid}")))?;

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
        "lastBomImportFormat": project.last_bom_import_format,
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
        .map_err(|e| sdk_err("get components", e))?;

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

    let (entries, table_str) = format_dt_components_table(&components);

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
        .map_err(|e| sdk_err("get findings", e))?;

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

    let findings_count = filtered.len();
    let findings_vec: Vec<_> = filtered.into_iter().cloned().collect();
    let (entries, table_str) = format_findings_table(&findings_vec);

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    eprintln!("{} finding(s).", findings_count);

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
        .map_err(|e| sdk_err("get violations", e))?;

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
        let mut table = new_table(vec![
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
        .map_err(|e| sdk_err("get project metrics", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        let total = metrics.vulnerabilities.unwrap_or(0);
        println!("{total}");
        return Ok(());
    }

    let (data, table_str) = format_project_metrics_detail(&metrics);

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
        .map_err(|e| sdk_err("get metrics history", e))?;

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
                "findingsTotal": m.findings_total,
                "findingsAudited": m.findings_audited,
                "firstOccurrence": m.first_occurrence,
                "lastOccurrence": m.last_occurrence,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec![
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
        .map_err(|e| sdk_err("get portfolio metrics", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        let total = metrics.vulnerabilities.unwrap_or(0);
        println!("{total}");
        return Ok(());
    }

    let (data, table_str) = format_portfolio_metrics_detail(&metrics);

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
        .map_err(|e| sdk_err("list policies", e))?;

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

    let (entries, table_str) = format_dt_policies_table(&policies);

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
        .map_err(|e| sdk_err("update analysis", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", resp.analysis_state);
        return Ok(());
    }

    let data = serde_json::json!({
        "analysisState": resp.analysis_state,
        "isSuppressed": resp.is_suppressed,
        "analysisJustification": resp.analysis_justification,
        "analysisDetails": resp.analysis_details,
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

// ---------------------------------------------------------------------------
// Formatting helpers (pure functions, testable without HTTP)
// ---------------------------------------------------------------------------

fn format_projects_table(projects: &[DtProject]) -> (Vec<Value>, String) {
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
        let mut table = new_table(vec!["UUID", "NAME", "VERSION", "LAST BOM IMPORT"]);

        for p in projects {
            let version = p.version.as_deref().unwrap_or("-");
            let last_bom = p
                .last_bom_import
                .map(format_timestamp)
                .unwrap_or_else(|| "-".to_string());
            table.add_row(vec![&p.uuid, &p.name, version, &last_bom]);
        }

        table.to_string()
    };

    (entries, table_str)
}

fn format_dt_components_table(components: &[DtComponentFull]) -> (Vec<Value>, String) {
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
        let mut table = new_table(vec!["UUID", "GROUP", "NAME", "VERSION", "PURL"]);

        for c in components {
            let group = c.group.as_deref().unwrap_or("-");
            let version = c.version.as_deref().unwrap_or("-");
            let purl = c.purl.as_deref().unwrap_or("-");
            table.add_row(vec![&c.uuid, group, &c.name, version, purl]);
        }

        table.to_string()
    };

    (entries, table_str)
}

fn format_findings_table(findings: &[DtFinding]) -> (Vec<Value>, String) {
    let entries: Vec<_> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "vulnId": f.vulnerability.vuln_id,
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
        let mut table = new_table(vec![
            "VULN ID",
            "SEVERITY",
            "SOURCE",
            "COMPONENT",
            "VERSION",
            "CVSS v3",
        ]);

        for f in findings {
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

    (entries, table_str)
}

fn format_project_metrics_detail(metrics: &DtProjectMetrics) -> (Value, String) {
    let data = serde_json::json!({
        "critical": metrics.critical,
        "high": metrics.high,
        "medium": metrics.medium,
        "low": metrics.low,
        "unassigned": metrics.unassigned,
        "findingsAudited": metrics.findings_audited,
        "findingsTotal": metrics.findings_total,
        "inheritedRiskScore": metrics.inherited_risk_score,
        "policyViolationsTotal": metrics.policy_violations_total,
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

    (data, table_str)
}

fn format_portfolio_metrics_detail(metrics: &DtPortfolioMetrics) -> (Value, String) {
    let data = serde_json::json!({
        "critical": metrics.critical,
        "high": metrics.high,
        "medium": metrics.medium,
        "low": metrics.low,
        "unassigned": metrics.unassigned,
        "findingsAudited": metrics.findings_audited,
        "findingsTotal": metrics.findings_total,
        "projects": metrics.projects,
        "inheritedRiskScore": metrics.inherited_risk_score,
        "policyViolationsTotal": metrics.policy_violations_total,
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

    (data, table_str)
}

fn format_dt_policies_table(policies: &[DtPolicyFull]) -> (Vec<Value>, String) {
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
        let mut table = new_table(vec![
            "UUID",
            "NAME",
            "VIOLATION STATE",
            "CONDITIONS",
            "PROJECTS",
        ]);

        for p in policies {
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

    (entries, table_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: DtCommand,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).unwrap()
    }

    fn try_parse(args: &[&str]) -> Result<TestCli, clap::Error> {
        TestCli::try_parse_from(args)
    }

    // ---- format_timestamp ----

    #[test]
    fn format_timestamp_known_date() {
        // 2024-02-21 05:20:00 UTC = 1708492800000 ms
        let result = format_timestamp(1708492800000);
        assert!(result.contains("2024"));
        assert!(result.contains("-"));
    }

    #[test]
    fn format_timestamp_zero() {
        let result = format_timestamp(0);
        assert_eq!(result, "1970-01-01 00:00");
    }

    #[test]
    fn format_timestamp_epoch_start() {
        let result = format_timestamp(1000);
        assert_eq!(result, "1970-01-01 00:00");
    }

    #[test]
    fn format_timestamp_recent() {
        // 2025-01-01 00:00:00 UTC
        let result = format_timestamp(1735689600000);
        assert!(result.starts_with("2025-01-01"));
    }

    #[test]
    fn format_timestamp_negative() {
        // Negative timestamps represent dates before epoch
        let result = format_timestamp(-86400000); // 1 day before epoch
        assert!(result.contains("1969"));
    }

    // ---- DtCommand top-level ----

    #[test]
    fn parse_status() {
        let cli = parse(&["test", "status"]);
        assert!(matches!(cli.command, DtCommand::Status));
    }

    #[test]
    fn parse_metrics() {
        let cli = parse(&["test", "metrics"]);
        assert!(matches!(cli.command, DtCommand::Metrics));
    }

    #[test]
    fn parse_policies() {
        let cli = parse(&["test", "policies"]);
        assert!(matches!(cli.command, DtCommand::Policies));
    }

    #[test]
    fn parse_project_subcommand() {
        let cli = parse(&["test", "project", "list"]);
        assert!(matches!(cli.command, DtCommand::Project(_)));
    }

    #[test]
    fn parse_analyze() {
        let cli = parse(&[
            "test",
            "analyze",
            "--project",
            "proj-uuid",
            "--vulnerability",
            "vuln-uuid",
            "--component",
            "comp-uuid",
            "--state",
            "NOT_AFFECTED",
        ]);
        if let DtCommand::Analyze {
            project,
            vulnerability,
            component,
            state,
            justification,
            details,
            suppressed,
        } = cli.command
        {
            assert_eq!(project, "proj-uuid");
            assert_eq!(vulnerability, "vuln-uuid");
            assert_eq!(component, "comp-uuid");
            assert_eq!(state, "NOT_AFFECTED");
            assert!(justification.is_none());
            assert!(details.is_none());
            assert!(suppressed.is_none());
        } else {
            panic!("Expected Analyze");
        }
    }

    #[test]
    fn parse_analyze_with_options() {
        let cli = parse(&[
            "test",
            "analyze",
            "--project",
            "proj-uuid",
            "--vulnerability",
            "vuln-uuid",
            "--component",
            "comp-uuid",
            "--state",
            "FALSE_POSITIVE",
            "--justification",
            "Not exploitable in this context",
            "--details",
            "Reviewed by security team",
            "--suppressed",
            "true",
        ]);
        if let DtCommand::Analyze {
            justification,
            details,
            suppressed,
            ..
        } = cli.command
        {
            assert_eq!(justification.unwrap(), "Not exploitable in this context");
            assert_eq!(details.unwrap(), "Reviewed by security team");
            assert_eq!(suppressed, Some(true));
        } else {
            panic!("Expected Analyze with options");
        }
    }

    #[test]
    fn parse_analyze_missing_required() {
        let result = try_parse(&["test", "analyze", "--project", "uuid"]);
        assert!(result.is_err());
    }

    // ---- DtProjectCommand ----

    #[test]
    fn parse_project_list() {
        let cli = parse(&["test", "project", "list"]);
        if let DtCommand::Project(DtProjectCommand::List) = cli.command {
            // pass
        } else {
            panic!("Expected Project List");
        }
    }

    #[test]
    fn parse_project_show() {
        let cli = parse(&["test", "project", "show", "proj-uuid-123"]);
        if let DtCommand::Project(DtProjectCommand::Show { uuid }) = cli.command {
            assert_eq!(uuid, "proj-uuid-123");
        } else {
            panic!("Expected Project Show");
        }
    }

    #[test]
    fn parse_project_components() {
        let cli = parse(&["test", "project", "components", "proj-uuid"]);
        if let DtCommand::Project(DtProjectCommand::Components { uuid }) = cli.command {
            assert_eq!(uuid, "proj-uuid");
        } else {
            panic!("Expected Project Components");
        }
    }

    #[test]
    fn parse_project_findings() {
        let cli = parse(&["test", "project", "findings", "proj-uuid"]);
        if let DtCommand::Project(DtProjectCommand::Findings { uuid, severity }) = cli.command {
            assert_eq!(uuid, "proj-uuid");
            assert!(severity.is_none());
        } else {
            panic!("Expected Project Findings");
        }
    }

    #[test]
    fn parse_project_findings_with_severity() {
        let cli = parse(&[
            "test",
            "project",
            "findings",
            "proj-uuid",
            "--severity",
            "CRITICAL",
        ]);
        if let DtCommand::Project(DtProjectCommand::Findings { severity, .. }) = cli.command {
            assert_eq!(severity.unwrap(), "CRITICAL");
        } else {
            panic!("Expected Project Findings with severity");
        }
    }

    #[test]
    fn parse_project_violations() {
        let cli = parse(&["test", "project", "violations", "proj-uuid"]);
        if let DtCommand::Project(DtProjectCommand::Violations { uuid }) = cli.command {
            assert_eq!(uuid, "proj-uuid");
        } else {
            panic!("Expected Project Violations");
        }
    }

    #[test]
    fn parse_project_metrics() {
        let cli = parse(&["test", "project", "metrics", "proj-uuid"]);
        if let DtCommand::Project(DtProjectCommand::Metrics { uuid }) = cli.command {
            assert_eq!(uuid, "proj-uuid");
        } else {
            panic!("Expected Project Metrics");
        }
    }

    #[test]
    fn parse_project_metrics_history_defaults() {
        let cli = parse(&["test", "project", "metrics-history", "proj-uuid"]);
        if let DtCommand::Project(DtProjectCommand::MetricsHistory { uuid, days }) = cli.command {
            assert_eq!(uuid, "proj-uuid");
            assert_eq!(days, 30);
        } else {
            panic!("Expected Project MetricsHistory");
        }
    }

    #[test]
    fn parse_project_metrics_history_custom_days() {
        let cli = parse(&[
            "test",
            "project",
            "metrics-history",
            "proj-uuid",
            "--days",
            "90",
        ]);
        if let DtCommand::Project(DtProjectCommand::MetricsHistory { days, .. }) = cli.command {
            assert_eq!(days, 90);
        } else {
            panic!("Expected Project MetricsHistory with custom days");
        }
    }

    // ---- Format function tests ----

    use artifact_keeper_sdk::types::{
        DtComponent, DtComponentFull, DtFinding, DtPolicyConditionFull, DtPolicyFull,
        DtPortfolioMetrics, DtProject, DtProjectMetrics, DtVulnerability,
    };

    fn make_test_project(name: &str, version: Option<&str>) -> DtProject {
        DtProject {
            uuid: "proj-uuid-1234".to_string(),
            name: name.to_string(),
            version: version.map(|v| v.to_string()),
            description: Some("A test project".to_string()),
            last_bom_import: Some(1708492800000), // 2024-02-21
            last_bom_import_format: Some("CycloneDX".to_string()),
        }
    }

    fn make_test_dt_component(name: &str, version: Option<&str>) -> DtComponentFull {
        DtComponentFull {
            uuid: "comp-uuid-1234".to_string(),
            name: name.to_string(),
            version: version.map(|v| v.to_string()),
            group: Some("org.example".to_string()),
            purl: Some(format!("pkg:maven/org.example/{name}")),
            cpe: None,
            is_internal: Some(false),
            resolved_license: None,
        }
    }

    fn make_test_finding(vuln_id: &str, severity: &str, cvss: Option<f64>) -> DtFinding {
        DtFinding {
            vulnerability: DtVulnerability {
                uuid: "vuln-uuid-1234".to_string(),
                vuln_id: vuln_id.to_string(),
                severity: severity.to_string(),
                source: "NVD".to_string(),
                title: Some("Test vulnerability".to_string()),
                cvss_v3_base_score: cvss,
                cwe: None,
                description: None,
            },
            component: DtComponent {
                uuid: "comp-uuid-1234".to_string(),
                name: "lodash".to_string(),
                version: Some("4.17.20".to_string()),
                group: None,
                purl: None,
            },
            analysis: None,
            attribution: None,
        }
    }

    fn make_test_project_metrics(critical: i64, high: i64, medium: i64) -> DtProjectMetrics {
        DtProjectMetrics {
            critical: Some(critical),
            high: Some(high),
            medium: Some(medium),
            low: Some(1),
            unassigned: Some(0),
            findings_audited: Some(5),
            findings_total: Some(10),
            inherited_risk_score: Some(42.5),
            policy_violations_total: Some(2),
            suppressions: Some(1),
            vulnerabilities: Some(critical + high + medium + 1),
            findings_unaudited: Some(5),
            first_occurrence: None,
            last_occurrence: None,
            policy_violations_fail: None,
            policy_violations_info: None,
            policy_violations_warn: None,
        }
    }

    fn make_test_portfolio_metrics() -> DtPortfolioMetrics {
        DtPortfolioMetrics {
            critical: Some(3),
            high: Some(10),
            medium: Some(25),
            low: Some(50),
            unassigned: Some(5),
            findings_audited: Some(20),
            findings_total: Some(93),
            projects: Some(12),
            inherited_risk_score: Some(150.0),
            policy_violations_total: Some(8),
            suppressions: Some(3),
            vulnerabilities: Some(93),
            findings_unaudited: Some(73),
            policy_violations_fail: None,
            policy_violations_info: None,
            policy_violations_warn: None,
        }
    }

    // ---- format_projects_table ----

    #[test]
    fn format_projects_table_single() {
        let projects = vec![make_test_project("my-app", Some("1.0.0"))];
        let (entries, table_str) = format_projects_table(&projects);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["name"], "my-app");
        assert_eq!(entries[0]["version"], "1.0.0");

        assert!(table_str.contains("UUID"));
        assert!(table_str.contains("NAME"));
        assert!(table_str.contains("my-app"));
        assert!(table_str.contains("1.0.0"));
    }

    #[test]
    fn format_projects_table_no_version() {
        let projects = vec![make_test_project("no-ver", None)];
        let (entries, table_str) = format_projects_table(&projects);

        assert!(entries[0]["version"].is_null());
        assert!(table_str.contains("-"));
    }

    #[test]
    fn format_projects_table_no_bom_import() {
        let mut project = make_test_project("no-bom", Some("2.0"));
        project.last_bom_import = None;
        let (_entries, table_str) = format_projects_table(&[project]);

        assert!(table_str.contains("-"));
    }

    #[test]
    fn format_projects_table_empty() {
        let (entries, table_str) = format_projects_table(&[]);
        assert!(entries.is_empty());
        assert!(table_str.contains("UUID"));
    }

    // ---- format_dt_components_table ----

    #[test]
    fn format_dt_components_table_single() {
        let components = vec![make_test_dt_component("spring-core", Some("5.3.21"))];
        let (entries, table_str) = format_dt_components_table(&components);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["name"], "spring-core");
        assert_eq!(entries[0]["group"], "org.example");

        assert!(table_str.contains("spring-core"));
        assert!(table_str.contains("org.example"));
    }

    #[test]
    fn format_dt_components_table_no_optional_fields() {
        let mut comp = make_test_dt_component("bare-lib", None);
        comp.group = None;
        comp.purl = None;
        let (entries, table_str) = format_dt_components_table(&[comp]);

        assert!(entries[0]["version"].is_null());
        assert!(entries[0]["group"].is_null());
        assert!(table_str.contains("-"));
    }

    #[test]
    fn format_dt_components_table_empty() {
        let (entries, table_str) = format_dt_components_table(&[]);
        assert!(entries.is_empty());
        assert!(table_str.contains("UUID"));
    }

    // ---- format_findings_table ----

    #[test]
    fn format_findings_table_single() {
        let findings = vec![make_test_finding("CVE-2024-1234", "CRITICAL", Some(9.8))];
        let (entries, table_str) = format_findings_table(&findings);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["vulnId"], "CVE-2024-1234");
        assert_eq!(entries[0]["severity"], "CRITICAL");
        assert_eq!(entries[0]["source"], "NVD");

        assert!(table_str.contains("CVE-2024-1234"));
        assert!(table_str.contains("CRITICAL"));
        assert!(table_str.contains("9.8"));
    }

    #[test]
    fn format_findings_table_no_cvss() {
        let findings = vec![make_test_finding("CVE-2024-0000", "LOW", None)];
        let (entries, table_str) = format_findings_table(&findings);

        assert!(entries[0]["cvss_v3"].is_null());
        assert!(table_str.contains("-"));
    }

    #[test]
    fn format_findings_table_multiple() {
        let findings = vec![
            make_test_finding("CVE-2024-1111", "CRITICAL", Some(9.8)),
            make_test_finding("CVE-2024-2222", "MEDIUM", Some(5.5)),
        ];
        let (entries, table_str) = format_findings_table(&findings);

        assert_eq!(entries.len(), 2);
        assert!(table_str.contains("CVE-2024-1111"));
        assert!(table_str.contains("CVE-2024-2222"));
    }

    #[test]
    fn format_findings_table_empty() {
        let (entries, table_str) = format_findings_table(&[]);
        assert!(entries.is_empty());
        assert!(table_str.contains("VULN ID"));
    }

    // ---- format_project_metrics_detail ----

    #[test]
    fn format_project_metrics_with_values() {
        let metrics = make_test_project_metrics(5, 10, 20);
        let (data, table_str) = format_project_metrics_detail(&metrics);

        assert_eq!(data["critical"], 5);
        assert_eq!(data["high"], 10);
        assert_eq!(data["medium"], 20);

        assert!(table_str.contains("Critical:"));
        assert!(table_str.contains("5"));
        assert!(table_str.contains("10"));
        assert!(table_str.contains("Audited:"));
        assert!(table_str.contains("5/10"));
    }

    #[test]
    fn format_project_metrics_all_zero() {
        let metrics = DtProjectMetrics {
            critical: None,
            high: None,
            medium: None,
            low: None,
            unassigned: None,
            findings_audited: None,
            findings_total: None,
            inherited_risk_score: None,
            policy_violations_total: None,
            suppressions: None,
            vulnerabilities: None,
            findings_unaudited: None,
            first_occurrence: None,
            last_occurrence: None,
            policy_violations_fail: None,
            policy_violations_info: None,
            policy_violations_warn: None,
        };
        let (data, table_str) = format_project_metrics_detail(&metrics);

        assert!(data["critical"].is_null());
        // When None, defaults to 0 in the table
        assert!(table_str.contains("0"));
    }

    // ---- format_portfolio_metrics_detail ----

    #[test]
    fn format_portfolio_metrics_with_values() {
        let metrics = make_test_portfolio_metrics();
        let (data, table_str) = format_portfolio_metrics_detail(&metrics);

        assert_eq!(data["projects"], 12);
        assert_eq!(data["critical"], 3);
        assert_eq!(data["high"], 10);

        assert!(table_str.contains("Projects:"));
        assert!(table_str.contains("12"));
        assert!(table_str.contains("Critical:"));
        assert!(table_str.contains("3"));
        assert!(table_str.contains("Audited:"));
    }

    #[test]
    fn format_portfolio_metrics_all_none() {
        let metrics = DtPortfolioMetrics {
            critical: None,
            high: None,
            medium: None,
            low: None,
            unassigned: None,
            findings_audited: None,
            findings_total: None,
            projects: None,
            inherited_risk_score: None,
            policy_violations_total: None,
            suppressions: None,
            vulnerabilities: None,
            findings_unaudited: None,
            policy_violations_fail: None,
            policy_violations_info: None,
            policy_violations_warn: None,
        };
        let (_data, table_str) = format_portfolio_metrics_detail(&metrics);

        assert!(table_str.contains("0"));
    }

    // ---- format_dt_policies_table ----

    #[test]
    fn format_dt_policies_table_single() {
        let policies = vec![DtPolicyFull {
            uuid: "pol-uuid-1234".to_string(),
            name: "security-policy".to_string(),
            violation_state: "FAIL".to_string(),
            policy_conditions: vec![DtPolicyConditionFull {
                uuid: "cond-uuid".to_string(),
                subject: "SEVERITY".to_string(),
                operator: "IS".to_string(),
                value: "CRITICAL".to_string(),
            }],
            projects: vec![],
            tags: vec![],
            include_children: Some(true),
        }];
        let (entries, table_str) = format_dt_policies_table(&policies);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["name"], "security-policy");
        assert_eq!(entries[0]["violation_state"], "FAIL");
        assert_eq!(entries[0]["conditions"], 1);
        assert_eq!(entries[0]["projects"], 0);

        assert!(table_str.contains("security-policy"));
        assert!(table_str.contains("FAIL"));
    }

    #[test]
    fn format_dt_policies_table_empty() {
        let (entries, table_str) = format_dt_policies_table(&[]);
        assert!(entries.is_empty());
        assert!(table_str.contains("UUID"));
    }

    // ---- additional format_timestamp tests ----

    #[test]
    fn format_timestamp_large_value() {
        // Year 2100
        let result = format_timestamp(4102444800000);
        assert!(result.contains("2099") || result.contains("2100"));
    }

    #[test]
    fn format_timestamp_milliseconds_precision() {
        // 2024-06-15 12:30:00 UTC = 1718451000000
        let result = format_timestamp(1718451000000);
        assert!(result.starts_with("2024-06-15"));
    }

    // ========================================================================
    // Wiremock-based handler tests
    // ========================================================================

    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, ResponseTemplate};

    /// Set up env vars for handler tests; returns a guard that must be held.

    #[tokio::test]
    async fn handler_dt_status() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/dependency-track/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "enabled": true,
                "healthy": true,
                "url": "https://dt.example.com"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = dt_status(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_dt_status_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/dependency-track/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "enabled": true,
                "healthy": false,
                "url": null
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = dt_status(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_project_list_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/dependency-track/projects"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = project_list(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_project_list_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/dependency-track/projects"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "uuid": "proj-uuid-1",
                    "name": "my-project",
                    "version": "1.0.0",
                    "description": "test",
                    "lastBomImport": 1708492800000_i64,
                    "lastBomImportFormat": "CycloneDX"
                }
            ])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = project_list(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_project_show() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        // project_show calls list_projects then filters by uuid
        Mock::given(method("GET"))
            .and(path("/api/v1/dependency-track/projects"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "uuid": "proj-uuid-1",
                    "name": "my-project",
                    "version": "2.0.0",
                    "description": "test desc",
                    "lastBomImport": 1708492800000_i64,
                    "lastBomImportFormat": "SPDX"
                }
            ])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = project_show("proj-uuid-1", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_project_components_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex(
                "/api/v1/dependency-track/projects/.+/components",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = project_components("some-uuid", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_project_components_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex(
                "/api/v1/dependency-track/projects/.+/components",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "uuid": "comp-uuid-1",
                    "name": "spring-core",
                    "version": "5.3.21",
                    "group": "org.springframework",
                    "purl": "pkg:maven/org.springframework/spring-core@5.3.21",
                    "cpe": null,
                    "isInternal": false,
                    "resolvedLicense": null
                }
            ])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = project_components("some-uuid", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_project_findings_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/dependency-track/projects/.+/findings"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = project_findings("some-uuid", None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_project_findings_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/dependency-track/projects/.+/findings"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "vulnerability": {
                        "uuid": "vuln-uuid-1",
                        "vulnId": "CVE-2024-1234",
                        "severity": "CRITICAL",
                        "source": "NVD",
                        "title": "Test vuln",
                        "cvssV3BaseScore": 9.8,
                        "cwe": null,
                        "description": null
                    },
                    "component": {
                        "uuid": "comp-uuid-1",
                        "name": "lodash",
                        "version": "4.17.20",
                        "group": null,
                        "purl": null
                    },
                    "analysis": null,
                    "attribution": null
                }
            ])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = project_findings("some-uuid", None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_project_findings_with_severity_filter() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/dependency-track/projects/.+/findings"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "vulnerability": {
                        "uuid": "vuln-uuid-1",
                        "vulnId": "CVE-2024-1234",
                        "severity": "CRITICAL",
                        "source": "NVD",
                        "title": "Test vuln",
                        "cvssV3BaseScore": 9.8,
                        "cwe": null,
                        "description": null
                    },
                    "component": {
                        "uuid": "comp-uuid-1",
                        "name": "lodash",
                        "version": "4.17.20",
                        "group": null,
                        "purl": null
                    },
                    "analysis": null,
                    "attribution": null
                },
                {
                    "vulnerability": {
                        "uuid": "vuln-uuid-2",
                        "vulnId": "CVE-2024-5678",
                        "severity": "LOW",
                        "source": "NVD",
                        "title": "Minor vuln",
                        "cvssV3BaseScore": 2.0,
                        "cwe": null,
                        "description": null
                    },
                    "component": {
                        "uuid": "comp-uuid-2",
                        "name": "express",
                        "version": "4.18.0",
                        "group": null,
                        "purl": null
                    },
                    "analysis": null,
                    "attribution": null
                }
            ])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = project_findings("some-uuid", Some("CRITICAL"), &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_project_violations_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex(
                "/api/v1/dependency-track/projects/.+/violations",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = project_violations("some-uuid", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_project_violations_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex(
                "/api/v1/dependency-track/projects/.+/violations",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "uuid": "viol-uuid-1",
                    "type": "LICENSE",
                    "component": {
                        "uuid": "comp-uuid-1",
                        "name": "gpl-lib",
                        "version": "1.0.0",
                        "group": null,
                        "purl": null
                    },
                    "policyCondition": {
                        "uuid": "cond-uuid-1",
                        "subject": "LICENSE",
                        "operator": "IS",
                        "value": "GPL-3.0",
                        "policy": {
                            "uuid": "pol-uuid-1",
                            "name": "no-gpl",
                            "violationState": "FAIL"
                        }
                    }
                }
            ])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = project_violations("some-uuid", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_project_metrics() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/dependency-track/projects/.+/metrics"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "critical": 2,
                "high": 5,
                "medium": 10,
                "low": 20,
                "unassigned": 1,
                "findingsAudited": 8,
                "findingsTotal": 38,
                "inheritedRiskScore": 75.5,
                "policyViolationsTotal": 3,
                "suppressions": 2,
                "vulnerabilities": 38,
                "findingsUnaudited": 30,
                "firstOccurrence": null,
                "lastOccurrence": null,
                "policyViolationsFail": null,
                "policyViolationsInfo": null,
                "policyViolationsWarn": null
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = project_metrics("some-uuid", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_project_metrics_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/dependency-track/projects/.+/metrics"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "unassigned": 0,
                "findingsAudited": 0,
                "findingsTotal": 0,
                "inheritedRiskScore": 0.0,
                "policyViolationsTotal": 0,
                "suppressions": 0,
                "vulnerabilities": 5,
                "findingsUnaudited": 0,
                "firstOccurrence": null,
                "lastOccurrence": null,
                "policyViolationsFail": null,
                "policyViolationsInfo": null,
                "policyViolationsWarn": null
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = project_metrics("some-uuid", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_project_metrics_history_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex(
                "/api/v1/dependency-track/projects/.+/metrics/history",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = project_metrics_history("some-uuid", 30, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_project_metrics_history_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex(
                "/api/v1/dependency-track/projects/.+/metrics/history",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "critical": 1,
                    "high": 3,
                    "medium": 5,
                    "low": 10,
                    "unassigned": 0,
                    "findingsTotal": 19,
                    "findingsAudited": 5,
                    "firstOccurrence": 1708492800000_i64,
                    "lastOccurrence": 1708579200000_i64
                }
            ])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = project_metrics_history("some-uuid", 30, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_portfolio_metrics() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/dependency-track/metrics/portfolio"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "critical": 3,
                "high": 10,
                "medium": 25,
                "low": 50,
                "unassigned": 5,
                "findingsAudited": 20,
                "findingsTotal": 93,
                "projects": 12,
                "inheritedRiskScore": 150.0,
                "policyViolationsTotal": 8,
                "suppressions": 3,
                "vulnerabilities": 93,
                "findingsUnaudited": 73,
                "policyViolationsFail": null,
                "policyViolationsInfo": null,
                "policyViolationsWarn": null
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = portfolio_metrics(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_portfolio_metrics_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/dependency-track/metrics/portfolio"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "unassigned": 0,
                "findingsAudited": 0,
                "findingsTotal": 0,
                "projects": 0,
                "inheritedRiskScore": 0.0,
                "policyViolationsTotal": 0,
                "suppressions": 0,
                "vulnerabilities": 42,
                "findingsUnaudited": 0,
                "policyViolationsFail": null,
                "policyViolationsInfo": null,
                "policyViolationsWarn": null
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = portfolio_metrics(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_policies_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/dependency-track/policies"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list_policies(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_policies_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/dependency-track/policies"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "uuid": "pol-uuid-1",
                    "name": "security-policy",
                    "violationState": "FAIL",
                    "policyConditions": [
                        {
                            "uuid": "cond-uuid-1",
                            "subject": "SEVERITY",
                            "operator": "IS",
                            "value": "CRITICAL"
                        }
                    ],
                    "projects": [],
                    "tags": [],
                    "includeChildren": true
                }
            ])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list_policies(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_update_analysis() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("PUT"))
            .and(path("/api/v1/dependency-track/analysis"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "analysisState": "NOT_AFFECTED",
                "isSuppressed": false,
                "analysisJustification": "Not exploitable",
                "analysisDetails": "Reviewed by team"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = update_analysis(
            "proj-uuid",
            "vuln-uuid",
            "comp-uuid",
            "NOT_AFFECTED",
            Some("Not exploitable"),
            Some("Reviewed by team"),
            Some(false),
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_update_analysis_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("PUT"))
            .and(path("/api/v1/dependency-track/analysis"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "analysisState": "FALSE_POSITIVE",
                "isSuppressed": true,
                "analysisJustification": null,
                "analysisDetails": null
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = update_analysis(
            "proj-uuid",
            "vuln-uuid",
            "comp-uuid",
            "FALSE_POSITIVE",
            None,
            None,
            None,
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }
}
