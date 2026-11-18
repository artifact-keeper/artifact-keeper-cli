//! `ak admin holds`: everything currently held back from download.

use artifact_keeper_sdk::ClientHoldsExt;
use clap::Subcommand;
use miette::Result;

use super::PageArgs;
use crate::cli::GlobalArgs;
use crate::commands::client::client_for;
use crate::commands::helpers::{
    Minor, new_table, or_since, print_page_info, refuse_flags_before, sdk_err,
};
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum HoldsCommand {
    /// List quarantine holds
    Quarantine {
        /// Only this repository, by key
        #[arg(long)]
        repo: Option<String>,

        /// Only this kind of hold, as the server names it
        #[arg(long)]
        kind: Option<String>,

        /// Only hosted holds recorded with this source. Proxy-cache holds record none, so
        /// they're left out (needs a 1.12 server)
        #[arg(long, value_parser = ["upload", "admin", "scan_policy"])]
        hold_source: Option<String>,

        #[command(flatten)]
        paging: PageArgs,
    },

    /// Count age-gate and quarantine holds
    Summary,

    /// List what the download gate's scan policy refuses now, across every
    /// repository, whether or not a hold was recorded (needs a 1.12 server)
    PolicyBlocks {
        /// Only this repository, by key
        #[arg(long)]
        repo: Option<String>,

        /// Where to start: the cursor the previous page printed
        #[arg(long)]
        cursor: Option<String>,

        /// Results per page
        #[arg(long)]
        per_page: Option<i32>,
    },
}

const V1_12: Minor = (1, 12);

impl HoldsCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        let client = client_for(global)?;
        match self {
            Self::Quarantine {
                repo,
                kind,
                hold_source,
                paging,
            } => {
                // An older server ignores the filter and lists every hold.
                if hold_source.is_some() {
                    refuse_flags_before(&["--hold-source"], V1_12, global).await?;
                }
                let mut req = client
                    .list_quarantine()
                    .page(paging.page)
                    .per_page(paging.per_page);
                if let Some(repo) = repo {
                    req = req.repository_key(repo);
                }
                if let Some(kind) = kind {
                    req = req.kind(kind);
                }
                if let Some(hold_source) = hold_source {
                    req = req.hold_source(hold_source);
                }
                let spinner = output::spinner("Fetching quarantine holds...");
                let (resp, raw) = artifact_keeper_sdk::raw::capture(req.send()).await;
                let resp = resp
                    .map_err(|e| sdk_err("list quarantine holds", e))?
                    .into_inner();
                spinner.finish_and_clear();

                if resp.items.is_empty() && !output::is_machine_format(&global.format) {
                    eprintln!("No quarantine holds found.");
                    return Ok(());
                }
                if matches!(global.format, OutputFormat::Quiet) {
                    for item in &resp.items {
                        match &item.artifact_id {
                            Some(id) => println!("{id}"),
                            None => println!("{}/{}", item.repository_key, item.path),
                        }
                    }
                    return Ok(());
                }

                let mut table = new_table(vec![
                    "REPOSITORY",
                    "FORMAT",
                    "NAME",
                    "VERSION",
                    "PATH",
                    "KIND",
                    "STATUS",
                    "SOURCE",
                    "BLOCKED",
                    "UNTIL",
                    "CREATED",
                    "ARTIFACT ID",
                ]);
                for item in &resp.items {
                    table.add_row(vec![
                        item.repository_key.clone(),
                        item.repository_format.clone(),
                        item.name.clone(),
                        item.version.clone().unwrap_or_else(|| "-".into()),
                        item.path.clone(),
                        item.kind.clone(),
                        item.quarantine_status.clone(),
                        match &item.hold_source {
                            Some(hold_source) => format!("{} ({hold_source})", item.source),
                            None => item.source.clone(),
                        },
                        if item.is_blocked { "yes" } else { "no" }.to_string(),
                        item.quarantine_until
                            .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                            .unwrap_or_else(|| "-".into()),
                        item.created_at.format("%Y-%m-%d %H:%M").to_string(),
                        item.artifact_id
                            .map(|id| id.to_string())
                            .unwrap_or_else(|| "-".into()),
                    ]);
                }
                println!(
                    "{}",
                    output::render_raw(
                        raw.as_deref(),
                        &resp,
                        &global.format,
                        Some(table.to_string())
                    )
                );
                print_page_info(
                    resp.pagination.page,
                    resp.pagination.total_pages,
                    resp.pagination.total,
                    "holds",
                );
            }
            Self::Summary => {
                let spinner = output::spinner("Fetching holds summary...");
                let (resp, raw) =
                    artifact_keeper_sdk::raw::capture(client.holds_summary().send()).await;
                let summary = resp
                    .map_err(|e| sdk_err("get holds summary", e))?
                    .into_inner();
                spinner.finish_and_clear();
                if matches!(global.format, OutputFormat::Quiet) {
                    println!(
                        "{}",
                        summary.age_gate_pending
                            + summary.quarantine_active
                            + summary.quarantine_rejected
                    );
                    return Ok(());
                }
                let table = format!(
                    "Age gate pending:    {}\n\
                     Quarantine active:   {}\n\
                     Quarantine rejected: {}",
                    summary.age_gate_pending,
                    summary.quarantine_active,
                    summary.quarantine_rejected,
                );
                println!(
                    "{}",
                    output::render_raw(raw.as_deref(), &summary, &global.format, Some(table))
                );
            }
            Self::PolicyBlocks {
                repo,
                cursor,
                per_page,
            } => {
                let mut req = client.list_policy_blocks();
                if let Some(repo) = repo {
                    req = req.repository_key(repo);
                }
                if let Some(cursor) = cursor {
                    req = req.cursor(cursor);
                }
                if let Some(per_page) = per_page {
                    req = req.per_page(per_page);
                }
                let spinner = output::spinner("Fetching policy blocks...");
                let (resp, raw) = artifact_keeper_sdk::raw::capture(req.send()).await;
                let resp = or_since(
                    V1_12,
                    resp,
                    "list policy blocks",
                    "admin holds policy-blocks",
                    global,
                )
                .await?
                .into_inner();
                spinner.finish_and_clear();

                if matches!(global.format, OutputFormat::Quiet) {
                    for item in &resp.items {
                        match &item.artifact_id {
                            Some(id) => println!("{id}"),
                            None => println!("{}/{}", item.repository_key, item.path),
                        }
                    }
                    return Ok(());
                }

                let table = if resp.items.is_empty() {
                    "No policy blocks on this page.".to_string()
                } else {
                    let mut table = new_table(vec![
                        "REPOSITORY",
                        "FORMAT",
                        "NAME",
                        "VERSION",
                        "PATH",
                        "SOURCE",
                        "MAX SEV",
                        "HOLD",
                        "VIOLATIONS",
                    ]);
                    for item in &resp.items {
                        let hold = match (&item.quarantine_status, &item.hold_source) {
                            (Some(status), Some(source)) => format!("{status} ({source})"),
                            (Some(status), None) => status.clone(),
                            _ => "-".to_string(),
                        };
                        table.add_row(vec![
                            item.repository_key.clone(),
                            item.repository_format.clone(),
                            item.name.clone(),
                            item.version.clone().unwrap_or_else(|| "-".into()),
                            item.path.clone(),
                            item.source.clone(),
                            item.max_severity.clone().unwrap_or_else(|| "-".into()),
                            hold,
                            item.violations.join("; "),
                        ]);
                    }
                    table.to_string()
                };
                println!(
                    "{}",
                    output::render_raw(raw.as_deref(), &resp, &global.format, Some(table))
                );
                eprintln!(
                    "{} hosted artifacts evaluated on this page.",
                    resp.evaluated
                );
                if let Some(next) = &resp.next_cursor {
                    eprintln!("More to check: pass --cursor {next}");
                }
            }
        }
        Ok(())
    }
}
