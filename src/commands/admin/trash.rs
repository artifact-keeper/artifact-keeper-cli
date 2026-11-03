//! `ak admin trash`: soft-deleted artifacts that can still be restored.

use artifact_keeper_sdk::ClientAdminExt;
use clap::Subcommand;
use miette::Result;

use super::PageArgs;
use crate::cli::GlobalArgs;
use crate::commands::client::client_for;
use crate::commands::helpers::{
    confirm_action, emit_mutation_raw, new_table, or_since_1_11, parse_uuid, print_page_info,
};
use crate::output::{self, OutputFormat, format_bytes};

#[derive(Subcommand)]
pub enum TrashCommand {
    /// List soft-deleted artifacts
    List {
        /// Only this repository, by key
        #[arg(long)]
        repository: Option<String>,

        #[command(flatten)]
        paging: PageArgs,
    },

    /// Put a soft-deleted artifact back. The server refuses if its path has been
    /// taken or its object is gone, and for OCI and proxy-cache content
    Restore {
        /// Artifact ID, from `ak admin trash list`
        id: String,

        /// Skip confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

impl TrashCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        let client = client_for(global)?;
        match self {
            Self::List { repository, paging } => {
                let mut req = client
                    .list_trash()
                    .page(paging.page)
                    .per_page(paging.per_page);
                if let Some(repository) = repository {
                    req = req.repository(repository);
                }
                let spinner = output::spinner("Fetching trash...");
                let (resp, raw) = artifact_keeper_sdk::raw::capture(req.send()).await;
                let resp = or_since_1_11(resp, "list trash", "admin trash", global)
                    .await?
                    .into_inner();
                spinner.finish_and_clear();

                if resp.items.is_empty() && !output::is_machine_format(&global.format) {
                    eprintln!("The trash is empty.");
                    return Ok(());
                }
                if matches!(global.format, OutputFormat::Quiet) {
                    for item in &resp.items {
                        println!("{}", item.id);
                    }
                    return Ok(());
                }

                let mut table = new_table(vec![
                    "ID",
                    "REPOSITORY",
                    "REPOSITORY ID",
                    "PATH",
                    "NAME",
                    "VERSION",
                    "SIZE",
                    "SHA256",
                    "DELETED",
                    "PURGE AFTER",
                    "RESTORABLE",
                ]);
                for item in &resp.items {
                    table.add_row(vec![
                        item.id.to_string(),
                        item.repository_key.clone(),
                        item.repository_id.to_string(),
                        item.path.clone(),
                        item.name.clone(),
                        item.version.clone().unwrap_or_else(|| "-".into()),
                        format_bytes(item.size_bytes),
                        item.checksum_sha256.clone(),
                        item.deleted_at
                            .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                            .unwrap_or_else(|| "-".into()),
                        item.purge_eligible_at
                            .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                            .unwrap_or_else(|| "-".into()),
                        match (&item.restorable, &item.restore_blocked_reason) {
                            (true, _) => "yes".to_string(),
                            (false, Some(reason)) => format!("no: {reason}"),
                            (false, None) => "no".to_string(),
                        },
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
                if matches!(global.format, OutputFormat::Table) {
                    eprintln!("Retention: {} days.", resp.retention_days);
                }
                print_page_info(
                    resp.pagination.page,
                    resp.pagination.total_pages,
                    resp.pagination.total,
                    "artifacts",
                );
            }
            Self::Restore { id, yes } => {
                let artifact_id = parse_uuid(&id, "artifact")?;
                if !confirm_action(
                    &format!("Restore artifact {artifact_id} from the trash?"),
                    yes,
                    global.no_input,
                )? {
                    return Ok(());
                }
                let spinner = output::spinner("Restoring artifact...");
                let (resp, raw) = artifact_keeper_sdk::raw::capture(
                    client.restore_trashed_artifact().id(artifact_id).send(),
                )
                .await;
                let restored = or_since_1_11(resp, "restore artifact", "admin trash", global)
                    .await?
                    .into_inner();
                spinner.finish_and_clear();
                emit_mutation_raw(
                    raw.as_deref(),
                    &restored,
                    &restored.id.to_string(),
                    &format!(
                        "Restored '{}' in repository '{}' (ID: {}).",
                        restored.path, restored.repository_key, restored.id
                    ),
                    global,
                );
            }
        }
        Ok(())
    }
}
