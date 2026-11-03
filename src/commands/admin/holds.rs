//! `ak admin holds`: everything currently held back from download.

use artifact_keeper_sdk::ClientHoldsExt;
use clap::Subcommand;
use miette::Result;

use super::PageArgs;
use crate::cli::GlobalArgs;
use crate::commands::client::client_for;
use crate::commands::helpers::{new_table, or_since_1_11, print_page_info};
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

        #[command(flatten)]
        paging: PageArgs,
    },

    /// Count age-gate and quarantine holds
    Summary,
}

impl HoldsCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        let client = client_for(global)?;
        match self {
            Self::Quarantine { repo, kind, paging } => {
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
                let spinner = output::spinner("Fetching quarantine holds...");
                let (resp, raw) = artifact_keeper_sdk::raw::capture(req.send()).await;
                let resp = or_since_1_11(resp, "list quarantine holds", "admin holds", global)
                    .await?
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
                        item.source.clone(),
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
                let summary = or_since_1_11(resp, "get holds summary", "admin holds", global)
                    .await?
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
        }
        Ok(())
    }
}
