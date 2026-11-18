//! `ak admin security`: the vulnerabilities behind the dashboard tiles, and the scan
//! queue. Both are new in 1.12.

use artifact_keeper_sdk::ClientAdminExt;
use artifact_keeper_sdk::raw::capture;
use clap::Subcommand;
use miette::Result;

use crate::cli::GlobalArgs;
use crate::commands::client::client_for;
use crate::commands::helpers::{Minor, new_table, or_since, resolve_optional_repo_id};
use crate::output::{self, OutputFormat};

const V1_12: Minor = (1, 12);

#[derive(Subcommand)]
pub enum SecurityCommand {
    /// List the vulnerabilities a dashboard tile counts: one row per artifact and
    /// advisory, at its highest severity
    Findings {
        /// Only this repository, by key or ID
        #[arg(long)]
        repo: Option<String>,

        /// Only this severity: critical, high, medium or low
        #[arg(long)]
        severity: Option<String>,

        /// open, acknowledged or all (the server's default)
        #[arg(long)]
        state: Option<String>,

        /// artifact: one row per affected artifact, with its counts
        #[arg(long, value_parser = ["artifact"])]
        group_by: Option<String>,

        /// Page number
        #[arg(long)]
        page: Option<i32>,

        /// Results per page
        #[arg(long)]
        per_page: Option<i32>,
    },

    /// Show the live scan queue: pending, running and failed jobs, and the depth behind
    /// them
    ScanQueue {
        /// Only jobs in this state: pending, running or failed
        #[arg(long)]
        state: Option<String>,

        /// Only jobs of this kind: proxy_file, hosted_artifact, hosted_upload,
        /// hosted_image or rescan
        #[arg(long)]
        kind: Option<String>,

        /// Page number
        #[arg(long)]
        page: Option<i32>,

        /// Results per page
        #[arg(long)]
        per_page: Option<i32>,
    },
}

impl SecurityCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Findings {
                repo,
                severity,
                state,
                group_by,
                page,
                per_page,
            } => {
                list_findings(
                    repo.as_deref(),
                    (severity, state, group_by),
                    (page, per_page),
                    global,
                )
                .await
            }
            Self::ScanQueue {
                state,
                kind,
                page,
                per_page,
            } => scan_queue(state, kind, (page, per_page), global).await,
        }
    }
}

type Filters = (Option<String>, Option<String>, Option<String>);

async fn list_findings(
    repo: Option<&str>,
    (severity, state, group_by): Filters,
    (page, per_page): (Option<i32>, Option<i32>),
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let repository_id = resolve_optional_repo_id(&client, repo).await?;
    let by_artifact = group_by.is_some();

    let spinner = output::spinner("Fetching findings...");
    let mut req = client.list_cve_findings();
    if let Some(id) = repository_id {
        req = req.repository_id(id);
    }
    if let Some(severity) = severity {
        req = req.severity(severity);
    }
    if let Some(state) = state {
        req = req.state(state);
    }
    if let Some(group_by) = group_by {
        req = req.group_by(group_by);
    }
    if let Some(page) = page {
        req = req.page(page);
    }
    if let Some(per_page) = per_page {
        req = req.per_page(per_page);
    }
    let (resp, raw) = capture(req.send()).await;
    let findings = or_since(
        V1_12,
        resp,
        "list findings",
        "admin security findings",
        global,
    )
    .await?
    .into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        if by_artifact {
            for a in &findings.artifacts {
                println!("{}", a.artifact_id);
            }
        } else {
            for f in &findings.items {
                println!("{}", f.cve_id);
            }
        }
        return Ok(());
    }

    let shown = if by_artifact {
        findings.artifacts.len()
    } else {
        findings.items.len()
    };
    let table_str = if shown == 0 {
        "No findings.".to_string()
    } else if by_artifact {
        let mut table = new_table(vec![
            "ARTIFACT", "PATH", "CRITICAL", "HIGH", "MEDIUM", "LOW", "TOTAL",
        ]);
        for a in &findings.artifacts {
            table.add_row(vec![
                a.artifact_id.to_string(),
                a.artifact_path.clone(),
                a.critical.to_string(),
                a.high.to_string(),
                a.medium.to_string(),
                a.low.to_string(),
                a.total.to_string(),
            ]);
        }
        table.to_string()
    } else {
        let mut table = new_table(vec![
            "CVE",
            "SEVERITY",
            "REPOSITORY",
            "PATH",
            "COMPONENT",
            "FIX",
            "ACK",
            "FIRST SEEN",
        ]);
        for f in &findings.items {
            let component = match (&f.affected_component, &f.affected_version) {
                (Some(name), Some(version)) => format!("{name} {version}"),
                (Some(name), None) => name.clone(),
                _ => "-".to_string(),
            };
            let ack = match (f.is_acknowledged, f.acknowledgement_expires_at) {
                (true, Some(until)) => format!("until {}", until.format("%Y-%m-%d")),
                (true, None) => "yes".to_string(),
                (false, _) => "no".to_string(),
            };
            table.add_row(vec![
                f.cve_id.clone(),
                f.severity.clone(),
                f.repository_key.clone(),
                f.artifact_path.clone(),
                component,
                f.fixed_version.clone().unwrap_or_else(|| "-".to_string()),
                ack,
                f.first_detected_at.format("%Y-%m-%d").to_string(),
            ]);
        }
        table.to_string()
    };
    println!(
        "{}",
        output::render_raw(raw.as_deref(), &findings, &global.format, Some(table_str))
    );
    if findings.total > shown as i64 {
        eprintln!("Showing {shown} of {}.", findings.total);
    }
    Ok(())
}

async fn scan_queue(
    state: Option<String>,
    kind: Option<String>,
    (page, per_page): (Option<i32>, Option<i32>),
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching the scan queue...");
    let mut req = client.get_scan_queue();
    if let Some(state) = state {
        req = req.state(state);
    }
    if let Some(kind) = kind {
        req = req.kind(kind);
    }
    if let Some(page) = page {
        req = req.page(page);
    }
    if let Some(per_page) = per_page {
        req = req.per_page(per_page);
    }
    let (resp, raw) = capture(req.send()).await;
    let queue = or_since(
        V1_12,
        resp,
        "read the scan queue",
        "admin security scan-queue",
        global,
    )
    .await?
    .into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        for job in &queue.items {
            println!("{}", job.id);
        }
        return Ok(());
    }

    let mut out = Vec::new();
    if !queue.enabled {
        out.push(
            "The scan queue is off on this instance: scans run in-process, and this only \
             holds what was left from when it was on."
                .to_string(),
        );
    }
    if !queue.depth.is_empty() {
        let mut depth = new_table(vec!["KIND", "STATE", "JOBS", "OLDEST DUE"]);
        for d in &queue.depth {
            depth.add_row(vec![
                d.kind.clone(),
                d.state.clone(),
                d.jobs.to_string(),
                d.oldest_pending_secs
                    .map(|secs| format!("{secs:.0}s"))
                    .unwrap_or_else(|| "-".to_string()),
            ]);
        }
        out.push(depth.to_string());
    }
    if queue.items.is_empty() {
        out.push("No jobs.".to_string());
    } else {
        let mut jobs = new_table(vec![
            "ID", "KIND", "STATE", "PRIORITY", "ATTEMPTS", "TARGET", "NEXT", "ERROR",
        ]);
        for job in &queue.items {
            let target = job
                .target
                .clone()
                .or_else(|| job.digest.clone())
                .or_else(|| job.artifact_id.map(|id| id.to_string()))
                .unwrap_or_else(|| "-".to_string());
            jobs.add_row(vec![
                job.id.to_string(),
                job.kind.clone(),
                job.state.clone(),
                job.priority.to_string(),
                format!("{}/{}", job.attempts, job.max_attempts),
                target,
                job.next_attempt_at.format("%Y-%m-%d %H:%M").to_string(),
                job.last_error.clone().unwrap_or_else(|| "-".to_string()),
            ]);
        }
        out.push(jobs.to_string());
    }
    println!(
        "{}",
        output::render_raw(raw.as_deref(), &queue, &global.format, Some(out.join("\n")))
    );
    if queue.total > queue.items.len() as i64 {
        eprintln!("Showing {} of {} jobs.", queue.items.len(), queue.total);
    }
    Ok(())
}
