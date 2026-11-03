use artifact_keeper_sdk::ClientSecurityExt;
use artifact_keeper_sdk::raw::capture;
use artifact_keeper_sdk::types::{
    DashboardResponse, ExternalFindingInput, PolicyPredicates, PolicyResponse, ProxyScanEntry,
    ScanResponse, ScoreResponse,
};
use clap::Subcommand;
use console::style;
use miette::Result;
use serde_json::Value;

use super::client::client_for;
use super::helpers::{
    confirm_action, emit_mutation_raw, new_table, parse_json_arg, parse_uuid,
    refuse_flags_before_1_11, resolve_artifact_id, resolve_optional_repo_id, resolve_repo_id,
    sdk_err, short_id,
};
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum ScanCommand {
    /// Trigger a security scan on an artifact, or on a whole repository
    Run {
        /// Repository key
        repo: String,

        /// Artifact path. Leave it out to scan every artifact in the repository
        path: Option<String>,

        /// Scan again even if an identical artifact has a result to reuse
        #[arg(long)]
        bypass_dedup: bool,
    },

    /// List recent scan results
    List {
        /// Filter by repository key or ID
        #[arg(long)]
        repo: Option<String>,

        /// Filter by artifact ID, or <repo-key>/<path>
        #[arg(long)]
        artifact: Option<String>,

        /// Filter by scan status
        #[arg(long)]
        status: Option<String>,

        /// Filter by scan type
        #[arg(long)]
        scan_type: Option<String>,

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

        /// Filter by minimum severity (CRITICAL, HIGH, MEDIUM, LOW, INFO), within the page
        #[arg(long)]
        severity: Option<String>,

        /// Ask the server for this severity only
        #[arg(long, value_name = "SEVERITY", conflicts_with = "severity")]
        exact_severity: Option<String>,

        /// Filter by the scanner that reported the finding
        #[arg(long)]
        source: Option<String>,

        /// Filter by CVE ID
        #[arg(long)]
        cve: Option<String>,

        /// Filter by finding class (needs a 1.11 server)
        #[arg(long)]
        finding_class: Option<String>,

        /// Page number
        #[arg(long, default_value = "1")]
        page: i64,

        /// Results per page
        #[arg(long, default_value = "50")]
        per_page: i64,
    },

    /// List scans for a specific artifact
    Artifact {
        /// Artifact ID, or <repo-key>/<path>
        artifact_id: String,

        /// Filter by scan status
        #[arg(long)]
        status: Option<String>,

        /// Page number
        #[arg(long, default_value = "1")]
        page: i64,

        /// Results per page
        #[arg(long, default_value = "20")]
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

    /// Manage scan findings (acknowledge, revoke, ingest)
    #[command(visible_alias = "findings")]
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

    /// See and rescan what a remote repository has cached from its upstream
    Proxy {
        #[command(subcommand)]
        command: ScanProxyCommand,
    },
}

#[derive(Subcommand)]
pub enum ScanProxyCommand {
    /// List the scan verdict of each cached path, or show one path's CVEs
    List {
        /// Remote repository key
        repo: String,

        /// Show this cached path, with the findings behind its counts
        #[arg(long)]
        path: Option<String>,

        /// Page number
        #[arg(long)]
        page: Option<i64>,

        /// Results per page
        #[arg(long)]
        per_page: Option<i64>,
    },

    /// Scan a cached path again now, and record the new verdict
    Rescan {
        /// Remote repository key
        repo: String,

        /// Cached path
        #[arg(long)]
        path: String,
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

        /// Skip the confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Revoke a previously acknowledged finding
    Revoke {
        /// Finding ID
        id: String,

        /// Skip the confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Record an external scanner's findings against an artifact (admin only)
    ///
    /// Every gate reads the result, so a finding can block downloads. Submitting again
    /// supersedes the scanner's earlier verdict.
    Ingest {
        /// JSON array of findings, in a file or - for stdin. Each one needs `title` and
        /// `severity`, and can have `affected_component`, `affected_version`, `cve_id`,
        /// `description`, `fixed_version`, `source` and `source_url`
        file: String,

        /// Artifact ID, or <repo-key>/<path>
        #[arg(long)]
        artifact: String,

        /// Name of the scanner that reported these
        #[arg(long)]
        scanner: String,

        /// Version of the scanner
        #[arg(long)]
        scanner_version: Option<String>,

        /// Skip the confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
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

        /// Bind to a specific repository key or ID
        #[arg(long)]
        repo: Option<String>,

        /// Block artifacts with no signature
        #[arg(long)]
        require_signature: bool,

        /// Block artifacts staged for fewer than this many hours
        #[arg(long)]
        min_staging_hours: Option<i32>,

        /// Block artifacts older than this many days
        #[arg(long)]
        max_artifact_age_days: Option<i32>,

        /// Conda and origin checks: a JSON object as text, @file, or @- for stdin (needs a
        /// 1.11 server)
        #[arg(long, value_name = "JSON")]
        predicates: Option<String>,
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

        /// Block artifacts with no signature
        #[arg(long)]
        require_signature: Option<bool>,

        /// Block artifacts staged for fewer than this many hours
        #[arg(long)]
        min_staging_hours: Option<i32>,

        /// Block artifacts older than this many days
        #[arg(long)]
        max_artifact_age_days: Option<i32>,

        /// Conda and origin checks, replacing the current ones: a JSON object as text,
        /// @file, or @- for stdin (needs a 1.11 server)
        #[arg(long, value_name = "JSON")]
        predicates: Option<String>,
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

    /// Update repository security configuration. Only what you pass changes
    Update {
        /// Repository key
        repo_key: String,

        /// Enable or disable scanning. On its own, the flag means true
        #[arg(long, num_args = 0..=1, default_missing_value = "true", value_name = "BOOL")]
        scanning_enabled: Option<bool>,

        /// Scan artifacts on upload. On its own, the flag means true
        #[arg(long, num_args = 0..=1, default_missing_value = "true", value_name = "BOOL")]
        scan_on_upload: Option<bool>,

        /// Scan proxied artifacts. On its own, the flag means true
        #[arg(long, num_args = 0..=1, default_missing_value = "true", value_name = "BOOL")]
        scan_on_proxy: Option<bool>,

        /// Block on policy violation. On its own, the flag means true
        #[arg(long, num_args = 0..=1, default_missing_value = "true", value_name = "BOOL")]
        block_on_violation: Option<bool>,

        /// Minimum severity to report (e.g. CRITICAL, HIGH, MEDIUM, LOW)
        #[arg(long)]
        severity_threshold: Option<String>,

        /// What a vulnerable proxied artifact does, such as fail_open or record_only (needs a
        /// 1.11 server)
        #[arg(long)]
        proxy_scan_action: Option<String>,
    },
}

/// The optional fields of `scan policy create` and `update`.
#[derive(Default)]
struct PolicyLimits {
    min_staging_hours: Option<i32>,
    max_artifact_age_days: Option<i32>,
    predicates: Option<String>,
}

impl PolicyLimits {
    /// The predicates to send. They need a 1.11 server: an older one answers 200 and
    /// drops them, leaving a policy weaker than the one asked for.
    async fn parse_predicates(&self, global: &GlobalArgs) -> Result<Option<PolicyPredicates>> {
        let Some(predicates) = self.predicates.as_deref() else {
            return Ok(None);
        };
        let parsed = parse_json_arg(predicates, "--predicates")?;
        refuse_flags_before_1_11(&["--predicates"], global).await?;
        Ok(Some(parsed))
    }
}

/// The settings `scan security update` can change.
#[derive(Default)]
struct SecuritySettings {
    scanning_enabled: Option<bool>,
    scan_on_upload: Option<bool>,
    scan_on_proxy: Option<bool>,
    block_on_violation: Option<bool>,
    severity_threshold: Option<String>,
    proxy_scan_action: Option<String>,
}

impl ScanCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Run {
                repo,
                path,
                bypass_dedup,
            } => run_scan(&repo, path.as_deref(), bypass_dedup, global).await,
            Self::List {
                repo,
                artifact,
                status,
                scan_type,
                page,
                per_page,
            } => {
                list_scans(
                    repo.as_deref(),
                    artifact.as_deref(),
                    status.as_deref(),
                    scan_type.as_deref(),
                    page,
                    per_page,
                    global,
                )
                .await
            }
            Self::Show {
                id,
                severity,
                exact_severity,
                source,
                cve,
                finding_class,
                page,
                per_page,
            } => {
                show_findings(
                    &id,
                    severity.as_deref(),
                    FindingFilters {
                        severity: exact_severity,
                        source,
                        cve_id: cve,
                        finding_class,
                    },
                    page,
                    per_page,
                    global,
                )
                .await
            }
            Self::Artifact {
                artifact_id,
                status,
                page,
                per_page,
            } => list_artifact_scans(&artifact_id, status.as_deref(), page, per_page, global).await,
            Self::Dashboard => show_dashboard(global).await,
            Self::Scores => show_scores(global).await,
            Self::Config { command } => match command {
                ScanConfigCommand::List => list_scan_configs(global).await,
            },
            Self::Finding { command } => match command {
                ScanFindingCommand::Ack { id, reason, yes } => {
                    acknowledge_finding(&id, &reason, yes, global).await
                }
                ScanFindingCommand::Revoke { id, yes } => revoke_finding(&id, yes, global).await,
                ScanFindingCommand::Ingest {
                    file,
                    artifact,
                    scanner,
                    scanner_version,
                    yes,
                } => {
                    ingest_findings(&file, &artifact, &scanner, scanner_version, yes, global).await
                }
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
                    require_signature,
                    min_staging_hours,
                    max_artifact_age_days,
                    predicates,
                } => {
                    create_policy(
                        &name,
                        &max_severity,
                        block_on_fail,
                        block_unscanned,
                        repo.as_deref(),
                        require_signature,
                        PolicyLimits {
                            min_staging_hours,
                            max_artifact_age_days,
                            predicates,
                        },
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
                    require_signature,
                    min_staging_hours,
                    max_artifact_age_days,
                    predicates,
                } => {
                    update_policy(
                        &id,
                        artifact_keeper_sdk::types::UpdatePolicyRequest {
                            name,
                            max_severity,
                            block_on_fail,
                            block_unscanned,
                            is_enabled: enabled,
                            require_signature,
                            min_staging_hours,
                            max_artifact_age_days,
                            predicates: None,
                        },
                        predicates,
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
                    proxy_scan_action,
                } => {
                    update_repo_security(
                        &repo_key,
                        SecuritySettings {
                            scanning_enabled,
                            scan_on_upload,
                            scan_on_proxy,
                            block_on_violation,
                            severity_threshold,
                            proxy_scan_action,
                        },
                        global,
                    )
                    .await
                }
            },
            Self::Proxy { command } => match command {
                ScanProxyCommand::List {
                    repo,
                    path,
                    page,
                    per_page,
                } => list_proxy_scans(&repo, path.as_deref(), page, per_page, global).await,
                ScanProxyCommand::Rescan { repo, path } => {
                    rescan_proxy_path(&repo, &path, global).await
                }
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Existing handlers
// ---------------------------------------------------------------------------

async fn run_scan(
    repo: &str,
    artifact_path: Option<&str>,
    bypass_dedup: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;

    let spinner = crate::output::spinner("Finding what to scan...");

    let (artifact_id, repository_id) = match artifact_path {
        Some(path) => (
            Some(resolve_artifact_id(&client, &format!("{repo}/{path}")).await?),
            None,
        ),
        None => (None, Some(resolve_repo_id(&client, repo).await?)),
    };

    spinner.set_message("Triggering scan...");

    let body = artifact_keeper_sdk::types::TriggerScanRequest {
        artifact_id,
        repository_id,
        bypass_dedup: bypass_dedup.then_some(true),
    };

    let (resp, raw) = capture(client.trigger_scan().body(body).send()).await;
    let scan = resp.map_err(|e| sdk_err("trigger scan", e))?.into_inner();

    spinner.finish_and_clear();

    emit_mutation_raw(
        raw.as_deref(),
        &scan,
        &scan.artifacts_queued.to_string(),
        &format!(
            "Scan triggered: {} ({} artifact(s) queued)\n\
             Run `ak scan list --repo {repo}` to check scan status.",
            scan.message, scan.artifacts_queued
        ),
        global,
    );

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn list_scans(
    repo: Option<&str>,
    artifact: Option<&str>,
    status: Option<&str>,
    scan_type: Option<&str>,
    page: i64,
    per_page: i64,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let artifact_id = match artifact {
        Some(artifact) => Some(resolve_artifact_id(&client, artifact).await?),
        None => None,
    };

    let spinner = crate::output::spinner("Fetching scans...");

    // A key goes in the route that takes one. An ID goes in the filter on all scans.
    let repo_key = repo.filter(|r| uuid::Uuid::parse_str(r).is_err());
    let (resp, raw) = if let Some(repo_key) = repo_key {
        let mut req = client
            .list_repo_scans()
            .key(repo_key)
            .page(page)
            .per_page(per_page);
        if let Some(id) = artifact_id {
            req = req.artifact_id(id);
        }
        if let Some(status) = status {
            req = req.status(status);
        }
        if let Some(scan_type) = scan_type {
            req = req.scan_type(scan_type);
        }
        capture(req.send()).await
    } else {
        let mut req = client.list_scans().page(page).per_page(per_page);
        if let Some(id) = repo.and_then(|r| uuid::Uuid::parse_str(r).ok()) {
            req = req.repository_id(id);
        }
        if let Some(id) = artifact_id {
            req = req.artifact_id(id);
        }
        if let Some(status) = status {
            req = req.status(status);
        }
        if let Some(scan_type) = scan_type {
            req = req.scan_type(scan_type);
        }
        capture(req.send()).await
    };
    let resp = resp.map_err(|e| sdk_err("list scans", e))?;

    spinner.finish_and_clear();

    print_scans(raw.as_deref(), &resp, "No scans found.", global);

    Ok(())
}

/// Print a page of scans: the server's body as JSON or YAML, otherwise a table.
fn print_scans(
    raw: Option<&[u8]>,
    resp: &artifact_keeper_sdk::types::ScanListResponse,
    empty: &str,
    global: &GlobalArgs,
) {
    if resp.items.is_empty() && !output::is_machine_format(&global.format) {
        eprintln!("{empty}");
        return;
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for scan in &resp.items {
            println!("{}", scan.id);
        }
        return;
    }

    let (entries, table_str) = format_scans_table(&resp.items);

    println!(
        "{}",
        output::render_raw(raw, &entries, &global.format, Some(table_str))
    );

    eprintln!("{} scans total.", resp.total);
}

async fn list_artifact_scans(
    artifact_id: &str,
    status: Option<&str>,
    page: i64,
    per_page: i64,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let aid = resolve_artifact_id(&client, artifact_id).await?;

    let spinner = crate::output::spinner("Fetching artifact scans...");

    let mut req = client
        .list_artifact_scans()
        .artifact_id(aid)
        .page(page)
        .per_page(per_page);
    if let Some(s) = status {
        req = req.status(s);
    }

    let (resp, raw) = capture(req.send()).await;
    let resp = resp.map_err(|e| sdk_err("list artifact scans", e))?;

    spinner.finish_and_clear();

    print_scans(
        raw.as_deref(),
        &resp,
        "No scans found for artifact.",
        global,
    );

    Ok(())
}

/// Build the JSON entries and rendered table for a list of scans.
fn format_scans_table(items: &[ScanResponse]) -> (Vec<Value>, String) {
    let entries: Vec<_> = items
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

    let mut table = new_table(vec![
        "ID", "STATUS", "TYPE", "FINDINGS", "C", "H", "M", "L", "ARTIFACT", "CREATED",
    ]);

    for s in items {
        let id_short = short_id(&s.id);
        let artifact = s.artifact_name.as_deref().unwrap_or("-");
        let created = s.created_at.format("%Y-%m-%d %H:%M").to_string();
        table.add_row(vec![
            &id_short,
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

    (entries, table.to_string())
}

/// What `scan show` asks the server to filter on.
#[derive(Default)]
struct FindingFilters {
    severity: Option<String>,
    source: Option<String>,
    cve_id: Option<String>,
    finding_class: Option<String>,
}

async fn show_findings(
    scan_id: &str,
    severity_filter: Option<&str>,
    filters: FindingFilters,
    page: i64,
    per_page: i64,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;

    let id = parse_uuid(scan_id, "scan")?;

    if filters.finding_class.is_some() {
        // An older server ignores this filter, and every finding looks like a match.
        refuse_flags_before_1_11(&["--finding-class"], global).await?;
    }

    let spinner = crate::output::spinner("Fetching scan details...");

    let scan = client
        .get_scan()
        .id(id)
        .send()
        .await
        .map_err(|e| sdk_err("get scan", e))?;

    let mut req = client.list_findings().id(id).page(page).per_page(per_page);
    if let Some(severity) = filters.severity {
        req = req.severity(severity);
    }
    if let Some(source) = filters.source {
        req = req.source(source);
    }
    if let Some(cve_id) = filters.cve_id {
        req = req.cve_id(cve_id);
    }
    if let Some(finding_class) = filters.finding_class {
        req = req.finding_class(finding_class);
    }
    let (resp, raw) = capture(req.send()).await;
    let findings = resp.map_err(|e| sdk_err("get findings", e))?;

    spinner.finish_and_clear();

    if !matches!(global.format, OutputFormat::Json | OutputFormat::Yaml) {
        eprintln!(
            "Scan {} — {} ({})",
            short_id(&scan.id),
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

    // `--severity` filters here, so the printed body has to lose the same findings.
    let raw = match raw.as_deref().map(serde_json::from_slice::<Value>) {
        Some(Ok(mut body)) if !severity_levels.is_empty() => {
            if let Some(items) = body.get_mut("items").and_then(Value::as_array_mut) {
                items.retain(|item| {
                    item["severity"].as_str().is_some_and(|severity| {
                        severity_levels
                            .iter()
                            .any(|s| s.eq_ignore_ascii_case(severity))
                    })
                });
            }
            serde_json::to_vec(&body).ok()
        }
        _ => raw,
    };

    if filtered.is_empty() && !output::is_machine_format(&global.format) {
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
        let mut table = new_table(vec![
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
        output::render_raw(raw.as_deref(), &entries, &global.format, Some(table_str))
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

    let (dash, raw) = capture(client.get_dashboard().send()).await;
    let dash = dash.map_err(|e| sdk_err("fetch dashboard", e))?;

    spinner.finish_and_clear();

    let d = dash.into_inner();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", d.total_findings);
        return Ok(());
    }

    let (entries, table_str) = format_dashboard(&d);

    println!(
        "{}",
        output::render_raw(raw.as_deref(), &entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn show_scores(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;

    let spinner = crate::output::spinner("Fetching security scores...");

    let (scores, raw) = capture(client.get_all_scores().send()).await;
    let scores = scores.map_err(|e| sdk_err("fetch scores", e))?;

    spinner.finish_and_clear();

    let items = scores.into_inner();

    if items.is_empty() && !output::is_machine_format(&global.format) {
        eprintln!("No security scores available.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for s in &items {
            println!("{}", s.repository_id);
        }
        return Ok(());
    }

    let (entries, table_str) = format_scores_table(&items);

    println!(
        "{}",
        output::render_raw(raw.as_deref(), &entries, &global.format, Some(table_str))
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Scan configs
// ---------------------------------------------------------------------------

async fn list_scan_configs(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;

    let spinner = crate::output::spinner("Fetching scan configurations...");

    let (configs, raw) = capture(client.list_scan_configs().send()).await;
    let configs = configs.map_err(|e| sdk_err("list scan configs", e))?;

    spinner.finish_and_clear();

    let items = configs.into_inner();

    if items.is_empty() && !output::is_machine_format(&global.format) {
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
        let mut table = new_table(vec![
            "ID",
            "REPO",
            "ENABLED",
            "ON UPLOAD",
            "ON PROXY",
            "BLOCK",
            "THRESHOLD",
        ]);

        for c in &items {
            let id_short = short_id(&c.id);
            let repo_short = short_id(&c.repository_id);
            table.add_row(vec![
                id_short.as_str(),
                repo_short.as_str(),
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
        output::render_raw(raw.as_deref(), &entries, &global.format, Some(table_str))
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Finding management
// ---------------------------------------------------------------------------

async fn acknowledge_finding(
    finding_id: &str,
    reason: &str,
    yes: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let id = parse_uuid(finding_id, "finding")?;

    if !confirm_action(
        &format!("Accept the risk of finding {finding_id}? It stops counting against the gates."),
        yes,
        global.no_input,
    )? {
        return Ok(());
    }

    let client = client_for(global)?;

    let spinner = crate::output::spinner("Acknowledging finding...");

    let body = artifact_keeper_sdk::types::AcknowledgeRequest {
        reason: reason.to_string(),
    };

    let (resp, raw) = capture(client.acknowledge_finding().id(id).body(body).send()).await;
    let finding = resp
        .map_err(|e| sdk_err("acknowledge finding", e))?
        .into_inner();

    spinner.finish_and_clear();

    emit_mutation_raw(
        raw.as_deref(),
        &finding,
        &finding.id.to_string(),
        &format!("Finding {} acknowledged: {}", short_id(&finding.id), reason),
        global,
    );

    Ok(())
}

async fn revoke_finding(finding_id: &str, yes: bool, global: &GlobalArgs) -> Result<()> {
    let id = parse_uuid(finding_id, "finding")?;

    if !confirm_action(
        &format!(
            "Revoke the acknowledgment of finding {finding_id}? It counts against the gates again."
        ),
        yes,
        global.no_input,
    )? {
        return Ok(());
    }

    let client = client_for(global)?;

    let spinner = crate::output::spinner("Revoking acknowledgment...");

    let (resp, raw) = capture(client.revoke_acknowledgment().id(id).send()).await;
    let finding = resp
        .map_err(|e| sdk_err("revoke acknowledgment", e))?
        .into_inner();

    spinner.finish_and_clear();

    emit_mutation_raw(
        raw.as_deref(),
        &finding,
        &finding.id.to_string(),
        &format!(
            "Acknowledgment revoked for finding {}.",
            short_id(&finding.id)
        ),
        global,
    );

    Ok(())
}

async fn ingest_findings(
    file: &str,
    artifact: &str,
    scanner: &str,
    scanner_version: Option<String>,
    yes: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let source = if file == "-" {
        "@-".to_string()
    } else {
        format!("@{file}")
    };
    let findings: Vec<ExternalFindingInput> = parse_json_arg(&source, "the findings file")?;

    let client = client_for(global)?;
    let artifact_id = resolve_artifact_id(&client, artifact).await?;

    if !confirm_action(
        &format!(
            "Record {} finding(s) from '{scanner}' against {artifact}? They can block downloads \
             of it.",
            findings.len()
        ),
        yes,
        global.no_input,
    )? {
        return Ok(());
    }

    let spinner = crate::output::spinner("Ingesting findings...");

    let body = artifact_keeper_sdk::types::IngestExternalFindingsRequest {
        artifact_id,
        findings,
        scanner: scanner.to_string(),
        scanner_version,
    };

    let (resp, raw) = capture(client.ingest_external_findings().body(body).send()).await;
    let result = resp
        .map_err(|e| sdk_err("ingest findings", e))?
        .into_inner();

    spinner.finish_and_clear();

    emit_mutation_raw(
        raw.as_deref(),
        &result,
        &result.scan_id.to_string(),
        &format!(
            "Ingested {} finding(s) as scan {}. The repository's score is now {} (grade {}).",
            result.findings_ingested,
            short_id(&result.scan_id),
            result.score,
            result.grade
        ),
        global,
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Proxy scans
// ---------------------------------------------------------------------------

async fn list_proxy_scans(
    repo: &str,
    path: Option<&str>,
    page: Option<i64>,
    per_page: Option<i64>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;

    let spinner = crate::output::spinner("Fetching proxy scans...");

    let mut req = client.get_repo_proxy_scans().key(repo);
    if let Some(path) = path {
        req = req.path(path);
    }
    if let Some(page) = page {
        req = req.page(page);
    }
    if let Some(per_page) = per_page {
        req = req.per_page(per_page);
    }
    let (resp, raw) = capture(req.send()).await;
    let resp = resp
        .map_err(|e| sdk_err("list proxy scans", e))?
        .into_inner();

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        for entry in &resp.items {
            println!("{}", entry.path);
        }
        return Ok(());
    }

    let table_str = if resp.items.is_empty() {
        format!("Nothing is cached in '{repo}'.")
    } else {
        let mut lines = vec![format_proxy_scans_table(&resp.items)];
        lines.push(format!(
            "Scan on proxy: {}. Action: {}. {} path(s) total.",
            resp.scan_on_proxy, resp.proxy_scan_action, resp.total
        ));
        if let Some(summary) = &resp.summary {
            lines.push(format!(
                "Digests: {} clean, {} vulnerable, {} not scanned.",
                summary.clean, summary.vulnerable, summary.not_scanned
            ));
        }
        lines.extend(resp.items.iter().flat_map(|entry| {
            entry.findings.iter().flatten().map(|f| {
                format!(
                    "{} {} {} {}",
                    format_severity(&f.severity),
                    f.cve_id,
                    f.package_name.as_deref().unwrap_or("-"),
                    f.fixed_version.as_deref().unwrap_or("-")
                )
            })
        }));
        lines.join("\n")
    };

    println!(
        "{}",
        output::render_raw(raw.as_deref(), &resp, &global.format, Some(table_str))
    );

    Ok(())
}

fn format_proxy_scans_table(items: &[ProxyScanEntry]) -> String {
    let mut table = new_table(vec![
        "PATH", "STATE", "FINDINGS", "C", "H", "M", "L", "CACHED",
    ]);
    let count = |n: Option<i32>| n.map_or_else(|| "-".to_string(), |n| n.to_string());
    for entry in items {
        table.add_row(vec![
            entry.path.clone(),
            entry.state.clone(),
            count(entry.findings_count),
            count(entry.critical_count),
            count(entry.high_count),
            count(entry.medium_count),
            count(entry.low_count),
            entry.cached_at.format("%Y-%m-%d %H:%M").to_string(),
        ]);
    }
    table.to_string()
}

async fn rescan_proxy_path(repo: &str, path: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;

    let spinner = crate::output::spinner("Rescanning cached path...");

    let body = artifact_keeper_sdk::types::ProxyRescanRequest {
        path: path.to_string(),
    };
    let (resp, raw) = capture(
        client
            .rescan_proxy_cached_path()
            .key(repo)
            .body(body)
            .send(),
    )
    .await;
    let verdict = resp
        .map_err(|e| sdk_err("rescan cached path", e))?
        .into_inner();

    spinner.finish_and_clear();

    emit_mutation_raw(
        raw.as_deref(),
        &verdict,
        &verdict.state,
        &format!(
            "{}: {} ({} finding(s): C:{} H:{} M:{} L:{}).",
            verdict.path,
            verdict.state,
            verdict.findings_count,
            verdict.critical_count,
            verdict.high_count,
            verdict.medium_count,
            verdict.low_count
        ),
        global,
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Policy CRUD
// ---------------------------------------------------------------------------

async fn list_policies(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;

    let spinner = crate::output::spinner("Fetching security policies...");

    let (policies, raw) = capture(client.list_policies().send()).await;
    let policies = policies.map_err(|e| sdk_err("list policies", e))?;

    spinner.finish_and_clear();

    let items = policies.into_inner();

    if items.is_empty() && !output::is_machine_format(&global.format) {
        eprintln!("No security policies found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for p in &items {
            println!("{}", p.id);
        }
        return Ok(());
    }

    let (entries, table_str) = format_scan_policies_table(&items);

    println!(
        "{}",
        output::render_raw(raw.as_deref(), &entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn show_policy(policy_id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(policy_id, "policy")?;

    let spinner = crate::output::spinner("Fetching policy...");

    let (policy, raw) = capture(client.get_policy().id(id).send()).await;
    let policy = policy.map_err(|e| sdk_err("get policy", e))?;

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
        short_id(&p.id),
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
        output::render_raw(raw.as_deref(), &[entry], &global.format, Some(table_str))
    );

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn create_policy(
    name: &str,
    max_severity: &str,
    block_on_fail: bool,
    block_unscanned: bool,
    repo: Option<&str>,
    require_signature: bool,
    limits: PolicyLimits,
    global: &GlobalArgs,
) -> Result<()> {
    let predicates = limits.parse_predicates(global).await?;

    let client = client_for(global)?;
    let repo_id = resolve_optional_repo_id(&client, repo).await?;

    let spinner = crate::output::spinner("Creating security policy...");

    let body = artifact_keeper_sdk::types::CreatePolicyRequest {
        name: name.to_string(),
        max_severity: max_severity.to_string(),
        block_on_fail,
        block_unscanned: Some(block_unscanned),
        repository_id: repo_id,
        max_artifact_age_days: limits.max_artifact_age_days,
        min_staging_hours: limits.min_staging_hours,
        predicates,
        require_signature: require_signature.then_some(true),
    };

    let (policy, raw) = capture(client.create_policy().body(body).send()).await;
    let p = policy
        .map_err(|e| sdk_err("create policy", e))?
        .into_inner();

    spinner.finish_and_clear();

    emit_mutation_raw(
        raw.as_deref(),
        &p,
        &p.id.to_string(),
        &format!("Policy '{}' created (ID: {}).", p.name, short_id(&p.id)),
        global,
    );

    Ok(())
}

async fn update_policy(
    policy_id: &str,
    mut body: artifact_keeper_sdk::types::UpdatePolicyRequest,
    predicates: Option<String>,
    global: &GlobalArgs,
) -> Result<()> {
    let id = parse_uuid(policy_id, "policy")?;
    body.predicates = PolicyLimits {
        predicates,
        ..PolicyLimits::default()
    }
    .parse_predicates(global)
    .await?;

    let client = client_for(global)?;

    let spinner = crate::output::spinner("Updating policy...");

    // Every field is optional and an omitted one keeps its value, so only what was
    // asked for is sent. Echoing the current policy back would drop any part of its
    // predicates this SDK doesn't know about.
    let (policy, raw) = capture(client.update_policy().id(id).body(body).send()).await;
    let p = policy
        .map_err(|e| sdk_err("update policy", e))?
        .into_inner();

    spinner.finish_and_clear();

    emit_mutation_raw(
        raw.as_deref(),
        &p,
        &p.id.to_string(),
        &format!("Policy '{}' updated (ID: {}).", p.name, short_id(&p.id)),
        global,
    );

    Ok(())
}

async fn delete_policy(policy_id: &str, yes: bool, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(policy_id, "policy")?;

    if !confirm_action(&format!("Delete policy {policy_id}?"), yes, global.no_input)? {
        return Ok(());
    }

    let spinner = crate::output::spinner("Deleting policy...");

    let (resp, raw) = capture(client.delete_policy().id(id).send()).await;
    resp.map_err(|e| sdk_err("delete policy", e))?;

    spinner.finish_and_clear();

    emit_mutation_raw(
        raw.as_deref(),
        &serde_json::json!({ "id": policy_id, "status": "deleted" }),
        policy_id,
        &format!("Policy {} deleted.", policy_id),
        global,
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Repository security config
// ---------------------------------------------------------------------------

async fn show_repo_security(repo_key: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;

    let spinner = crate::output::spinner("Fetching repository security config...");

    let (resp, raw) = capture(client.get_repo_security().key(repo_key).send()).await;
    let resp = resp.map_err(|e| sdk_err("get repo security", e))?;

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
            lines.push(format!(
                "  Proxy Scan Action:       {}",
                c.proxy_scan_action
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
        output::render_raw(raw.as_deref(), &[entry], &global.format, Some(table_str))
    );

    Ok(())
}

async fn update_repo_security(
    repo_key: &str,
    settings: SecuritySettings,
    global: &GlobalArgs,
) -> Result<()> {
    // Sending a false for every flag that wasn't given would turn scanning and
    // blocking off on a repository, as a side effect of changing something else.
    if settings.scanning_enabled.is_none()
        && settings.scan_on_upload.is_none()
        && settings.scan_on_proxy.is_none()
        && settings.block_on_violation.is_none()
        && settings.severity_threshold.is_none()
        && settings.proxy_scan_action.is_none()
    {
        return Err(AkError::Usage(
            "Nothing to update. Pass at least one setting, such as --scanning-enabled true."
                .to_string(),
        )
        .into());
    }
    // A 1.10 server stores fail_closed and fail_open, and turns record_only into
    // fail_open, which is the reverse of keeping a record of what it let through.
    if settings.proxy_scan_action.as_deref() == Some("record_only")
        && let Some(version) =
            crate::commands::helpers::guard_flags("--proxy-scan-action", (1, 11, 0), global).await
    {
        return Err(AkError::UnsupportedServer(format!(
            "--proxy-scan-action record_only needs a server on 1.11 or newer. This one is \
             {version}, which would store fail_open instead. Nothing was changed."
        ))
        .into());
    }
    let wanted_action = settings.proxy_scan_action.clone();

    let client = client_for(global)?;

    let spinner = crate::output::spinner("Updating repository security config...");

    let body = artifact_keeper_sdk::types::UpsertScanConfigRequest {
        scan_enabled: settings.scanning_enabled,
        scan_on_upload: settings.scan_on_upload,
        scan_on_proxy: settings.scan_on_proxy,
        block_on_policy_violation: settings.block_on_violation,
        proxy_scan_action: settings.proxy_scan_action,
        severity_threshold: settings.severity_threshold,
    };

    let (resp, raw) = capture(
        client
            .update_repo_security()
            .key(repo_key)
            .body(body)
            .send(),
    )
    .await;
    let config = resp
        .map_err(|e| sdk_err("update repo security", e))?
        .into_inner();

    spinner.finish_and_clear();

    // The version check can't tell if the server's version couldn't be read.
    if let Some(wanted) = &wanted_action
        && wanted != &config.proxy_scan_action
    {
        return Err(AkError::ServerError(format!(
            "The server stored proxy_scan_action {}, not {wanted}. Check this repository's \
             security config.",
            config.proxy_scan_action
        ))
        .into());
    }

    emit_mutation_raw(
        raw.as_deref(),
        &config,
        repo_key,
        &format!("Security config updated for repository '{repo_key}'."),
        global,
    );

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

// ---------------------------------------------------------------------------
// Formatting helpers (pure functions, testable without HTTP)
// ---------------------------------------------------------------------------

fn format_dashboard(d: &DashboardResponse) -> (Vec<Value>, String) {
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

    (vec![entry], table_str)
}

fn format_scores_table(items: &[ScoreResponse]) -> (Vec<Value>, String) {
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
        let mut table = new_table(vec![
            "REPO", "GRADE", "CRITICAL", "HIGH", "MEDIUM", "LOW", "SCANNED", "OPEN", "UPDATED",
        ]);

        for s in items {
            let repo_short = short_id(&s.repository_id);
            let scanned = s
                .last_scan_at
                .map(|t| t.format("%Y-%m-%d").to_string())
                .unwrap_or_else(|| "-".to_string());
            table.add_row(vec![
                &repo_short,
                &s.grade,
                &format_severity_count(s.critical_count, "CRITICAL"),
                &format_severity_count(s.high_count, "HIGH"),
                &format_severity_count(s.medium_count, "MEDIUM"),
                &s.low_count.to_string(),
                &scanned,
                &s.total_findings.to_string(),
                &s.calculated_at.format("%Y-%m-%d").to_string(),
            ]);
        }

        table.to_string()
    };

    (entries, table_str)
}

fn format_scan_policies_table(items: &[PolicyResponse]) -> (Vec<Value>, String) {
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
        let mut table = new_table(vec![
            "ID",
            "NAME",
            "MAX SEV",
            "BLOCK FAIL",
            "BLOCK UNSCAN",
            "ENABLED",
            "REPO",
        ]);

        for p in items {
            let id_short = short_id(&p.id);
            let repo = p
                .repository_id
                .map(|id| short_id(&id))
                .unwrap_or_else(|| "global".to_string());
            table.add_row(vec![
                id_short.as_str(),
                &p.name,
                &p.max_severity,
                if p.block_on_fail { "yes" } else { "no" },
                if p.block_unscanned { "yes" } else { "no" },
                if p.is_enabled { "yes" } else { "no" },
                repo.as_str(),
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
        command: ScanCommand,
    }

    fn parse_scan(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).unwrap()
    }

    fn try_parse_scan(args: &[&str]) -> Result<TestCli, clap::Error> {
        TestCli::try_parse_from(args)
    }

    // ---- ScanCommand clap parsing ----

    #[test]
    fn parse_run() {
        let cli = parse_scan(&["test", "run", "my-repo", "pkg/foo-1.0.tar.gz"]);
        if let ScanCommand::Run { repo, path, .. } = cli.command {
            assert_eq!(repo, "my-repo");
            assert_eq!(path.as_deref(), Some("pkg/foo-1.0.tar.gz"));
        } else {
            panic!("Expected Run");
        }
    }

    #[test]
    fn parse_list_defaults() {
        let cli = parse_scan(&["test", "list"]);
        if let ScanCommand::List {
            repo,
            page,
            per_page,
            ..
        } = cli.command
        {
            assert!(repo.is_none());
            assert_eq!(page, 1);
            assert_eq!(per_page, 20);
        } else {
            panic!("Expected List");
        }
    }

    #[test]
    fn parse_scan_artifact_defaults() {
        let cli = parse_scan(&["test", "artifact", "art-uuid-123"]);
        if let ScanCommand::Artifact {
            artifact_id,
            status,
            page,
            per_page,
        } = cli.command
        {
            assert_eq!(artifact_id, "art-uuid-123");
            assert!(status.is_none());
            assert_eq!(page, 1);
            assert_eq!(per_page, 20);
        } else {
            panic!("Expected Artifact");
        }
    }

    #[test]
    fn parse_scan_artifact_with_status() {
        let cli = parse_scan(&[
            "test",
            "artifact",
            "art-uuid-123",
            "--status",
            "completed",
            "--page",
            "2",
        ]);
        if let ScanCommand::Artifact {
            artifact_id,
            status,
            page,
            ..
        } = cli.command
        {
            assert_eq!(artifact_id, "art-uuid-123");
            assert_eq!(status.as_deref(), Some("completed"));
            assert_eq!(page, 2);
        } else {
            panic!("Expected Artifact");
        }
    }

    #[test]
    fn parse_list_with_options() {
        let cli = parse_scan(&[
            "test",
            "list",
            "--repo",
            "my-repo",
            "--page",
            "3",
            "--per-page",
            "50",
        ]);
        if let ScanCommand::List {
            repo,
            page,
            per_page,
            ..
        } = cli.command
        {
            assert_eq!(repo.unwrap(), "my-repo");
            assert_eq!(page, 3);
            assert_eq!(per_page, 50);
        } else {
            panic!("Expected List with options");
        }
    }

    #[test]
    fn parse_show_defaults() {
        let cli = parse_scan(&["test", "show", "scan-id-123"]);
        if let ScanCommand::Show {
            id,
            severity,
            page,
            per_page,
            ..
        } = cli.command
        {
            assert_eq!(id, "scan-id-123");
            assert!(severity.is_none());
            assert_eq!(page, 1);
            assert_eq!(per_page, 50);
        } else {
            panic!("Expected Show");
        }
    }

    #[test]
    fn parse_show_with_severity() {
        let cli = parse_scan(&["test", "show", "scan-id-123", "--severity", "CRITICAL,HIGH"]);
        if let ScanCommand::Show { severity, .. } = cli.command {
            assert_eq!(severity.unwrap(), "CRITICAL,HIGH");
        } else {
            panic!("Expected Show with severity");
        }
    }

    #[test]
    fn parse_dashboard() {
        let cli = parse_scan(&["test", "dashboard"]);
        assert!(matches!(cli.command, ScanCommand::Dashboard));
    }

    #[test]
    fn parse_scores() {
        let cli = parse_scan(&["test", "scores"]);
        assert!(matches!(cli.command, ScanCommand::Scores));
    }

    // ---- ScanConfigCommand ----

    #[test]
    fn parse_config_list() {
        let cli = parse_scan(&["test", "config", "list"]);
        if let ScanCommand::Config {
            command: ScanConfigCommand::List,
        } = cli.command
        {
            // pass
        } else {
            panic!("Expected Config List");
        }
    }

    // ---- ScanFindingCommand ----

    #[test]
    fn parse_finding_ack() {
        let cli = parse_scan(&[
            "test",
            "finding",
            "ack",
            "finding-id-123",
            "--reason",
            "Accepted risk",
        ]);
        if let ScanCommand::Finding {
            command: ScanFindingCommand::Ack { id, reason, .. },
        } = cli.command
        {
            assert_eq!(id, "finding-id-123");
            assert_eq!(reason, "Accepted risk");
        } else {
            panic!("Expected Finding Ack");
        }
    }

    #[test]
    fn parse_finding_ack_missing_reason() {
        let result = try_parse_scan(&["test", "finding", "ack", "finding-id"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_finding_revoke() {
        let cli = parse_scan(&["test", "finding", "revoke", "finding-id-123"]);
        if let ScanCommand::Finding {
            command: ScanFindingCommand::Revoke { id, .. },
        } = cli.command
        {
            assert_eq!(id, "finding-id-123");
        } else {
            panic!("Expected Finding Revoke");
        }
    }

    // ---- ScanPolicyCommand ----

    #[test]
    fn parse_policy_list() {
        let cli = parse_scan(&["test", "policy", "list"]);
        if let ScanCommand::Policy {
            command: ScanPolicyCommand::List,
        } = cli.command
        {
            // pass
        } else {
            panic!("Expected Policy List");
        }
    }

    #[test]
    fn parse_policy_show() {
        let cli = parse_scan(&["test", "policy", "show", "policy-id"]);
        if let ScanCommand::Policy {
            command: ScanPolicyCommand::Show { id },
        } = cli.command
        {
            assert_eq!(id, "policy-id");
        } else {
            panic!("Expected Policy Show");
        }
    }

    #[test]
    fn parse_policy_create_minimal() {
        let cli = parse_scan(&[
            "test",
            "policy",
            "create",
            "my-policy",
            "--max-severity",
            "HIGH",
        ]);
        if let ScanCommand::Policy {
            command:
                ScanPolicyCommand::Create {
                    name,
                    max_severity,
                    block_on_fail,
                    block_unscanned,
                    repo,
                    ..
                },
        } = cli.command
        {
            assert_eq!(name, "my-policy");
            assert_eq!(max_severity, "HIGH");
            assert!(!block_on_fail);
            assert!(!block_unscanned);
            assert!(repo.is_none());
        } else {
            panic!("Expected Policy Create");
        }
    }

    #[test]
    fn parse_policy_create_full() {
        let cli = parse_scan(&[
            "test",
            "policy",
            "create",
            "strict",
            "--max-severity",
            "CRITICAL",
            "--block-on-fail",
            "--block-unscanned",
            "--repo",
            "00000000-0000-0000-0000-000000000001",
        ]);
        if let ScanCommand::Policy {
            command:
                ScanPolicyCommand::Create {
                    block_on_fail,
                    block_unscanned,
                    repo,
                    ..
                },
        } = cli.command
        {
            assert!(block_on_fail);
            assert!(block_unscanned);
            assert_eq!(repo.unwrap(), "00000000-0000-0000-0000-000000000001");
        } else {
            panic!("Expected Policy Create full");
        }
    }

    #[test]
    fn parse_policy_update() {
        let cli = parse_scan(&[
            "test",
            "policy",
            "update",
            "policy-id",
            "--name",
            "updated-name",
            "--max-severity",
            "MEDIUM",
        ]);
        if let ScanCommand::Policy {
            command:
                ScanPolicyCommand::Update {
                    id,
                    name,
                    max_severity,
                    block_on_fail,
                    block_unscanned,
                    enabled,
                    ..
                },
        } = cli.command
        {
            assert_eq!(id, "policy-id");
            assert_eq!(name.unwrap(), "updated-name");
            assert_eq!(max_severity.unwrap(), "MEDIUM");
            assert!(block_on_fail.is_none());
            assert!(block_unscanned.is_none());
            assert!(enabled.is_none());
        } else {
            panic!("Expected Policy Update");
        }
    }

    #[test]
    fn parse_policy_delete() {
        let cli = parse_scan(&["test", "policy", "delete", "policy-id"]);
        if let ScanCommand::Policy {
            command: ScanPolicyCommand::Delete { id, yes },
        } = cli.command
        {
            assert_eq!(id, "policy-id");
            assert!(!yes);
        } else {
            panic!("Expected Policy Delete");
        }
    }

    #[test]
    fn parse_policy_delete_with_yes() {
        let cli = parse_scan(&["test", "policy", "delete", "policy-id", "--yes"]);
        if let ScanCommand::Policy {
            command: ScanPolicyCommand::Delete { yes, .. },
        } = cli.command
        {
            assert!(yes);
        } else {
            panic!("Expected Policy Delete with --yes");
        }
    }

    // ---- ScanSecurityCommand ----

    #[test]
    fn parse_security_show() {
        let cli = parse_scan(&["test", "security", "show", "my-repo"]);
        if let ScanCommand::Security {
            command: ScanSecurityCommand::Show { repo_key },
        } = cli.command
        {
            assert_eq!(repo_key, "my-repo");
        } else {
            panic!("Expected Security Show");
        }
    }

    #[test]
    fn parse_security_update_defaults() {
        let cli = parse_scan(&["test", "security", "update", "my-repo"]);
        if let ScanCommand::Security {
            command:
                ScanSecurityCommand::Update {
                    repo_key,
                    scanning_enabled,
                    scan_on_upload,
                    scan_on_proxy,
                    block_on_violation,
                    severity_threshold,
                    proxy_scan_action,
                },
        } = cli.command
        {
            assert_eq!(repo_key, "my-repo");
            assert!(scanning_enabled.is_none());
            assert!(scan_on_upload.is_none());
            assert!(scan_on_proxy.is_none());
            assert!(block_on_violation.is_none());
            assert!(severity_threshold.is_none());
            assert!(proxy_scan_action.is_none());
        } else {
            panic!("Expected Security Update");
        }
    }

    #[test]
    fn parse_security_update_with_flags() {
        let cli = parse_scan(&[
            "test",
            "security",
            "update",
            "my-repo",
            "--scanning-enabled",
            "--scan-on-upload",
            "--scan-on-proxy",
            "--block-on-violation",
            "--severity-threshold",
            "CRITICAL",
        ]);
        if let ScanCommand::Security {
            command:
                ScanSecurityCommand::Update {
                    scanning_enabled,
                    scan_on_upload,
                    scan_on_proxy,
                    block_on_violation,
                    severity_threshold,
                    ..
                },
        } = cli.command
        {
            assert_eq!(scanning_enabled, Some(true));
            assert_eq!(scan_on_upload, Some(true));
            assert_eq!(scan_on_proxy, Some(true));
            assert_eq!(block_on_violation, Some(true));
            assert_eq!(severity_threshold.as_deref(), Some("CRITICAL"));
        } else {
            panic!("Expected Security Update with flags");
        }
    }

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

    // ---- Format function tests ----

    use artifact_keeper_sdk::types::{DashboardResponse, PolicyResponse, ScoreResponse};
    use chrono::Utc;
    use uuid::Uuid;

    fn make_test_dashboard() -> DashboardResponse {
        DashboardResponse {
            total_scans: 150,
            total_findings: 42,
            critical_findings: 3,
            high_findings: 8,
            policy_violations_blocked: 5,
            repos_with_scanning: 12,
            repos_grade_a: 8,
            repos_grade_f: 1,
        }
    }

    fn make_test_score(grade: &str, critical: i32, high: i32) -> ScoreResponse {
        ScoreResponse {
            has_uncataloged_scan: Some(false),
            id: Uuid::nil(),
            repository_id: Uuid::nil(),
            grade: grade.to_string(),
            score: 85,
            critical_count: critical,
            high_count: high,
            medium_count: 5,
            low_count: 10,
            total_findings: critical + high + 5 + 10,
            acknowledged_count: 3,
            has_failed_scan: false,
            last_scan_at: Some(Utc::now()),
            calculated_at: Utc::now(),
        }
    }

    fn make_test_scan_policy(name: &str, max_severity: &str) -> PolicyResponse {
        PolicyResponse {
            predicates: Default::default(),
            id: Uuid::nil(),
            name: name.to_string(),
            max_severity: max_severity.to_string(),
            block_on_fail: true,
            block_unscanned: false,
            is_enabled: true,
            require_signature: false,
            repository_id: None,
            max_artifact_age_days: None,
            min_staging_hours: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    // ---- format_dashboard ----

    #[test]
    fn format_dashboard_with_data() {
        let d = make_test_dashboard();
        let (entries, table_str) = format_dashboard(&d);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["total_scans"], 150);
        assert_eq!(entries[0]["total_findings"], 42);
        assert_eq!(entries[0]["critical_findings"], 3);
        assert_eq!(entries[0]["repos_grade_a"], 8);

        assert!(table_str.contains("Security Dashboard:"));
        assert!(table_str.contains("Total Scans:"));
        assert!(table_str.contains("150"));
        assert!(table_str.contains("42"));
        assert!(table_str.contains("Grade A Repos:"));
        assert!(table_str.contains("8"));
    }

    #[test]
    fn format_dashboard_zero_findings() {
        let d = DashboardResponse {
            total_scans: 10,
            total_findings: 0,
            critical_findings: 0,
            high_findings: 0,
            policy_violations_blocked: 0,
            repos_with_scanning: 5,
            repos_grade_a: 5,
            repos_grade_f: 0,
        };
        let (entries, table_str) = format_dashboard(&d);

        assert_eq!(entries[0]["total_findings"], 0);
        assert!(table_str.contains("Security Dashboard:"));
    }

    // ---- format_scores_table ----

    #[test]
    fn format_scores_table_single() {
        let scores = vec![make_test_score("A", 0, 1)];
        let (entries, table_str) = format_scores_table(&scores);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["grade"], "A");
        assert_eq!(entries[0]["score"], 85);
        assert_eq!(entries[0]["critical"], 0);
        assert_eq!(entries[0]["high"], 1);

        assert!(table_str.contains("REPO"));
        assert!(table_str.contains("GRADE"));
    }

    #[test]
    fn format_scores_table_multiple() {
        let scores = vec![make_test_score("A", 0, 0), make_test_score("C", 2, 5)];
        let (entries, table_str) = format_scores_table(&scores);

        assert_eq!(entries.len(), 2);
        assert!(table_str.contains("GRADE"));
    }

    #[test]
    fn format_scores_table_no_last_scan() {
        let mut score = make_test_score("B", 1, 2);
        score.last_scan_at = None;
        let (entries, table_str) = format_scores_table(&[score]);

        assert!(entries[0]["last_scan_at"].is_null());
        assert!(table_str.contains("-"));
    }

    #[test]
    fn format_scores_table_empty() {
        let (entries, table_str) = format_scores_table(&[]);
        assert!(entries.is_empty());
        assert!(table_str.contains("REPO"));
    }

    // ---- format_scan_policies_table ----

    #[test]
    fn format_scan_policies_table_single() {
        let policies = vec![make_test_scan_policy("strict", "HIGH")];
        let (entries, table_str) = format_scan_policies_table(&policies);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["name"], "strict");
        assert_eq!(entries[0]["max_severity"], "HIGH");
        assert_eq!(entries[0]["block_on_fail"], true);
        assert_eq!(entries[0]["is_enabled"], true);

        assert!(table_str.contains("strict"));
        assert!(table_str.contains("HIGH"));
        assert!(table_str.contains("yes"));
        assert!(table_str.contains("global"));
    }

    #[test]
    fn format_scan_policies_table_with_repo() {
        let mut policy = make_test_scan_policy("repo-policy", "CRITICAL");
        policy.repository_id = Some(Uuid::nil());
        let (entries, table_str) = format_scan_policies_table(&[policy]);

        assert!(entries[0]["repository_id"].is_string());
        // Should show short UUID instead of "global"
        assert!(table_str.contains("00000000"));
    }

    #[test]
    fn format_scan_policies_table_disabled() {
        let mut policy = make_test_scan_policy("disabled", "LOW");
        policy.is_enabled = false;
        policy.block_on_fail = false;
        policy.block_unscanned = false;
        let (_entries, table_str) = format_scan_policies_table(&[policy]);

        // "no" should appear for disabled flags
        assert!(table_str.contains("no"));
    }

    #[test]
    fn format_scan_policies_table_empty() {
        let (entries, table_str) = format_scan_policies_table(&[]);
        assert!(entries.is_empty());
        assert!(table_str.contains("NAME"));
    }

    #[test]
    fn format_scan_policies_table_multiple() {
        let policies = vec![
            make_test_scan_policy("policy-a", "HIGH"),
            make_test_scan_policy("policy-b", "CRITICAL"),
        ];
        let (entries, table_str) = format_scan_policies_table(&policies);

        assert_eq!(entries.len(), 2);
        assert!(table_str.contains("policy-a"));
        assert!(table_str.contains("policy-b"));
    }

    // ========================================================================
    // Wiremock-based handler tests
    // ========================================================================

    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, ResponseTemplate};

    /// Set up env vars for handler tests; returns a guard that must be held.

    #[tokio::test]
    async fn handler_list_scans_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/security/scans"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": [],
                "total": 0_i64
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list_scans(None, None, None, None, 1, 20, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_scans_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/security/scans"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": [{
                    "id": "00000000-0000-0000-0000-000000000001",
                    "artifact_id": "00000000-0000-0000-0000-000000000099",
                    "repository_id": "00000000-0000-0000-0000-000000000002",
                    "status": "completed",
                    "scan_type": "trivy",
                    "findings_count": 3,
                    "critical_count": 1,
                    "high_count": 1,
                    "medium_count": 1,
                    "low_count": 0,
                    "info_count": 0,
                    "is_reused": false,
                    "artifact_name": "pkg.jar",
                    "artifact_version": "1.0",
                    "created_at": "2026-01-15T10:00:00Z",
                    "scan_completeness": "complete"
                }],
                "total": 1_i64
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list_scans(None, None, None, None, 1, 20, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_scans_with_repo_filter() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/repositories/.+/security/scans"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": [],
                "total": 0_i64
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = list_scans(Some("my-repo"), None, None, None, 1, 20, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_artifact_scans_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/security/artifacts/.+/scans"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": [],
                "total": 0_i64
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result =
            list_artifact_scans("00000000-0000-0000-0000-000000000099", None, 1, 20, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_artifact_scans_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/security/artifacts/.+/scans"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": [{
                    "id": "00000000-0000-0000-0000-000000000001",
                    "artifact_id": "00000000-0000-0000-0000-000000000099",
                    "repository_id": "00000000-0000-0000-0000-000000000002",
                    "status": "completed",
                    "scan_type": "trivy",
                    "findings_count": 3,
                    "critical_count": 1,
                    "high_count": 1,
                    "medium_count": 1,
                    "low_count": 0,
                    "info_count": 0,
                    "is_reused": false,
                    "artifact_name": "pkg.jar",
                    "artifact_version": "1.0",
                    "created_at": "2026-01-15T10:00:00Z",
                    "scan_completeness": "complete"
                }],
                "total": 1_i64
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = list_artifact_scans(
            "00000000-0000-0000-0000-000000000099",
            Some("completed"),
            1,
            20,
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_dashboard() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/security/dashboard"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total_scans": 100,
                "total_findings": 25,
                "critical_findings": 2,
                "high_findings": 5,
                "policy_violations_blocked": 3,
                "repos_with_scanning": 10,
                "repos_grade_a": 7,
                "repos_grade_f": 0
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = show_dashboard(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_dashboard_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/security/dashboard"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "total_scans": 10,
                "total_findings": 0,
                "critical_findings": 0,
                "high_findings": 0,
                "policy_violations_blocked": 0,
                "repos_with_scanning": 5,
                "repos_grade_a": 5,
                "repos_grade_f": 0
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = show_dashboard(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_scores_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/security/scores"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = show_scores(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_scores_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/security/scores"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                    "id": "00000000-0000-0000-0000-000000000001",
                    "repository_id": "00000000-0000-0000-0000-000000000002",
                    "grade": "A",
                    "score": 95,
                    "critical_count": 0,
                    "high_count": 1,
                    "medium_count": 3,
                    "low_count": 5,
                    "total_findings": 9,
                    "acknowledged_count": 2,
                    "has_failed_scan": false,
                    "last_scan_at": "2026-01-15T10:00:00Z",
                    "calculated_at": "2026-01-15T10:00:00Z",
                    "has_uncataloged_scan": false
                }])),
            )
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = show_scores(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_scan_configs_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/security/configs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list_scan_configs(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_scan_configs_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/security/configs"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                    "id": "00000000-0000-0000-0000-000000000001",
                    "repository_id": "00000000-0000-0000-0000-000000000002",
                    "scan_enabled": true,
                    "scan_on_upload": true,
                    "scan_on_proxy": false,
                    "block_on_policy_violation": true,
                    "severity_threshold": "HIGH",
                    "created_at": "2026-01-15T10:00:00Z",
                    "updated_at": "2026-01-15T10:00:00Z",
                    "proxy_scan_action": "fail_open"
                }])),
            )
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list_scan_configs(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_policies_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/security/policies"))
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
            .and(path("/api/v1/security/policies"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{
                    "id": "00000000-0000-0000-0000-000000000001",
                    "name": "strict-policy",
                    "max_severity": "HIGH",
                    "block_on_fail": true,
                    "block_unscanned": false,
                    "is_enabled": true,
                    "require_signature": false,
                    "repository_id": null,
                    "max_artifact_age_days": null,
                    "min_staging_hours": null,
                    "created_at": "2026-01-15T10:00:00Z",
                    "updated_at": "2026-01-15T10:00:00Z",
                    "predicates": {}
                }])),
            )
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list_policies(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_policy() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/security/policies/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "00000000-0000-0000-0000-000000000001",
                "name": "test-policy",
                "max_severity": "CRITICAL",
                "block_on_fail": true,
                "block_unscanned": true,
                "is_enabled": true,
                "require_signature": false,
                "repository_id": null,
                "max_artifact_age_days": null,
                "min_staging_hours": null,
                "created_at": "2026-01-15T10:00:00Z",
                "updated_at": "2026-01-15T10:00:00Z",
                "predicates": {}
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = show_policy("00000000-0000-0000-0000-000000000001", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_create_policy() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/security/policies"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "00000000-0000-0000-0000-000000000001",
                "name": "new-policy",
                "max_severity": "HIGH",
                "block_on_fail": true,
                "block_unscanned": false,
                "is_enabled": true,
                "require_signature": false,
                "repository_id": null,
                "max_artifact_age_days": null,
                "min_staging_hours": null,
                "created_at": "2026-01-15T10:00:00Z",
                "updated_at": "2026-01-15T10:00:00Z",
                "predicates": {}
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = create_policy(
            "new-policy",
            "HIGH",
            true,
            false,
            None,
            false,
            PolicyLimits::default(),
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_delete_policy() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path_regex("/api/v1/security/policies/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        // yes=true to skip confirmation, no_input is also true in test_global
        let result = delete_policy("00000000-0000-0000-0000-000000000001", true, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_acknowledge_finding() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path_regex("/api/v1/security/findings/.+/acknowledge"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "00000000-0000-0000-0000-000000000001",
                "artifact_id": "00000000-0000-0000-0000-000000000099",
                "severity": "HIGH",
                "title": "CVE-2024-1234",
                "cve_id": "CVE-2024-1234",
                "affected_component": "lodash",
                "affected_version": "4.17.20",
                "fixed_version": "4.17.21",
                "source": "trivy",
                "is_acknowledged": true,
                "acknowledged_reason": "Accepted risk",
                "scan_result_id": "00000000-0000-0000-0000-000000000002",
                "created_at": "2026-01-15T10:00:00Z",
                "finding_class": "vulnerability"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = acknowledge_finding(
            "00000000-0000-0000-0000-000000000001",
            "Accepted risk",
            true,
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_revoke_finding() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path_regex("/api/v1/security/findings/.+/acknowledge"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "00000000-0000-0000-0000-000000000001",
                "artifact_id": "00000000-0000-0000-0000-000000000099",
                "severity": "HIGH",
                "title": "CVE-2024-1234",
                "cve_id": "CVE-2024-1234",
                "affected_component": "lodash",
                "affected_version": "4.17.20",
                "fixed_version": "4.17.21",
                "source": "trivy",
                "is_acknowledged": false,
                "acknowledged_reason": null,
                "scan_result_id": "00000000-0000-0000-0000-000000000002",
                "created_at": "2026-01-15T10:00:00Z",
                "finding_class": "vulnerability"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = revoke_finding("00000000-0000-0000-0000-000000000001", true, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_repo_security() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/repositories/.+/security"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "config": {
                    "id": "00000000-0000-0000-0000-000000000001",
                    "repository_id": "00000000-0000-0000-0000-000000000002",
                    "scan_enabled": true,
                    "scan_on_upload": true,
                    "scan_on_proxy": false,
                    "block_on_policy_violation": true,
                    "severity_threshold": "HIGH",
                    "created_at": "2026-01-15T10:00:00Z",
                    "updated_at": "2026-01-15T10:00:00Z",
                    "proxy_scan_action": "fail_open"
                },
                "score": {
                    "id": "00000000-0000-0000-0000-000000000003",
                    "repository_id": "00000000-0000-0000-0000-000000000002",
                    "grade": "A",
                    "score": 95,
                    "critical_count": 0,
                    "high_count": 1,
                    "medium_count": 3,
                    "low_count": 5,
                    "total_findings": 9,
                    "acknowledged_count": 2,
                    "has_failed_scan": false,
                    "last_scan_at": "2026-01-15T10:00:00Z",
                    "calculated_at": "2026-01-15T10:00:00Z",
                    "has_uncataloged_scan": false
                }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = show_repo_security("my-repo", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_update_repo_security() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("PUT"))
            .and(path_regex("/api/v1/repositories/.+/security"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "00000000-0000-0000-0000-000000000001",
                "repository_id": "00000000-0000-0000-0000-000000000002",
                "scan_enabled": true,
                "scan_on_upload": true,
                "scan_on_proxy": true,
                "block_on_policy_violation": true,
                "severity_threshold": "CRITICAL",
                "created_at": "2026-01-15T10:00:00Z",
                "updated_at": "2026-01-15T12:00:00Z",
                "proxy_scan_action": "fail_open"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = update_repo_security(
            "my-repo",
            SecuritySettings {
                scanning_enabled: Some(true),
                severity_threshold: Some("CRITICAL".to_string()),
                ..SecuritySettings::default()
            },
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_findings() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        let scan_id = "00000000-0000-0000-0000-000000000001";

        // Mock for get_scan
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/security/scans/{scan_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": scan_id,
                "artifact_id": "00000000-0000-0000-0000-000000000099",
                "repository_id": "00000000-0000-0000-0000-000000000002",
                "status": "completed",
                "scan_type": "trivy",
                "findings_count": 1,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 1,
                "low_count": 0,
                "info_count": 0,
                "is_reused": false,
                "artifact_name": "pkg.jar",
                "artifact_version": "1.0",
                "created_at": "2026-01-15T10:00:00Z",
                "scan_completeness": "complete"
            })))
            .mount(&server)
            .await;

        // Mock for list_findings
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/security/scans/{scan_id}/findings")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": [{
                    "id": "00000000-0000-0000-0000-000000000010",
                    "artifact_id": "00000000-0000-0000-0000-000000000099",
                    "severity": "MEDIUM",
                    "title": "Test finding",
                    "cve_id": "CVE-2024-9999",
                    "affected_component": "test-lib",
                    "affected_version": "1.0.0",
                    "fixed_version": "1.0.1",
                    "source": "trivy",
                    "is_acknowledged": false,
                    "acknowledged_reason": null,
                    "scan_result_id": scan_id,
                    "created_at": "2026-01-15T10:00:00Z",
                    "finding_class": "vulnerability"
                }],
                "total": 1_i64
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = show_findings(scan_id, None, FindingFilters::default(), 1, 50, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_run_scan() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        // Mock for finding the artifact
        Mock::given(method("GET"))
            .and(path_regex("/api/v1/repositories/my-repo/artifacts/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "00000000-0000-0000-0000-000000000099",
                "path": "pkg/foo-1.0.tar.gz",
                "name": "foo",
                "size_bytes": 1024_i64,
                "content_type": "application/gzip",
                "checksum_sha256": "abc123",
                "analyzable": true,
                "download_count": 5_i64,
                "repository_key": "my-repo",
                "created_at": "2026-01-15T10:00:00Z",
                "quarantine_status": "not_quarantined"
            })))
            .mount(&server)
            .await;

        // Mock for trigger_scan
        Mock::given(method("POST"))
            .and(path("/api/v1/security/scan"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "message": "Scan triggered",
                "artifacts_queued": 1
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = run_scan("my-repo", Some("pkg/foo-1.0.tar.gz"), false, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_update_policy() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        let policy_id = "00000000-0000-0000-0000-000000000001";

        // Mock for get_policy (fetching existing)
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/security/policies/{policy_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": policy_id,
                "name": "old-name",
                "max_severity": "HIGH",
                "block_on_fail": false,
                "block_unscanned": false,
                "is_enabled": true,
                "require_signature": false,
                "repository_id": null,
                "max_artifact_age_days": null,
                "min_staging_hours": null,
                "created_at": "2026-01-15T10:00:00Z",
                "updated_at": "2026-01-15T10:00:00Z",
                "predicates": {}
            })))
            .mount(&server)
            .await;

        // Mock for update_policy
        Mock::given(method("PUT"))
            .and(path(format!("/api/v1/security/policies/{policy_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": policy_id,
                "name": "updated-name",
                "max_severity": "CRITICAL",
                "block_on_fail": true,
                "block_unscanned": false,
                "is_enabled": true,
                "require_signature": false,
                "repository_id": null,
                "max_artifact_age_days": null,
                "min_staging_hours": null,
                "created_at": "2026-01-15T10:00:00Z",
                "updated_at": "2026-01-15T12:00:00Z",
                "predicates": {}
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = update_policy(
            policy_id,
            artifact_keeper_sdk::types::UpdatePolicyRequest {
                name: Some("updated-name".to_string()),
                max_severity: Some("CRITICAL".to_string()),
                block_on_fail: Some(true),
                block_unscanned: None,
                is_enabled: None,
                max_artifact_age_days: None,
                min_staging_hours: None,
                predicates: None,
                require_signature: None,
            },
            None,
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    // ---- insta snapshot tests ----

    #[test]
    fn snapshot_scan_dashboard_json() {
        let data = serde_json::json!({
            "total_scans": 142,
            "passed": 120,
            "failed": 22,
            "critical": 3,
            "high": 8,
            "medium": 11,
            "low": 0,
            "unscanned_artifacts": 5,
            "last_scan_at": "2026-01-20T14:30:00Z"
        });
        let output = crate::output::render(&data, &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("scan_dashboard_json", parsed);
    }

    #[test]
    fn snapshot_scan_policy_list_json() {
        let data = serde_json::json!([{
            "id": "00000000-0000-0000-0000-000000000001",
            "name": "strict-policy",
            "max_severity": "CRITICAL",
            "block_on_fail": true,
            "block_unscanned": true,
            "repository_id": null,
            "created_at": "2026-01-15T10:00:00Z",
            "updated_at": "2026-01-15T12:00:00Z"
        }]);
        let output = crate::output::render(&data, &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("scan_policy_list_json", parsed);
    }
}
