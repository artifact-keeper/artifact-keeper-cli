//! `ak admin audit`: the server's audit log.

use artifact_keeper_sdk::ClientAdminExt;
use chrono::{DateTime, Utc};
use clap::Subcommand;
use miette::Result;

use super::PageArgs;
use crate::cli::GlobalArgs;
use crate::commands::client::client_for;
use crate::commands::helpers::{new_table, parse_uuid, print_page_info, sdk_err, short_id};
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum AuditCommand {
    /// List audit log entries
    List {
        /// Only entries by this user ID
        #[arg(long)]
        user: Option<String>,

        /// Only this action, as the server names it
        #[arg(long)]
        action: Option<String>,

        /// Only this resource type
        #[arg(long)]
        resource_type: Option<String>,

        /// Only this resource ID
        #[arg(long)]
        resource_id: Option<String>,

        /// Only entries from one request, by correlation ID
        #[arg(long)]
        correlation_id: Option<String>,

        /// Earliest time, RFC 3339 (2026-01-15T00:00:00Z)
        #[arg(long)]
        from: Option<DateTime<Utc>>,

        /// Latest time, RFC 3339 (2026-01-15T23:59:59Z)
        #[arg(long)]
        to: Option<DateTime<Utc>>,

        #[command(flatten)]
        paging: PageArgs,
    },
}

impl AuditCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List {
                user,
                action,
                resource_type,
                resource_id,
                correlation_id,
                from,
                to,
                paging,
            } => {
                let client = client_for(global)?;
                let mut req = client
                    .list_audit_logs()
                    .page(paging.page)
                    .per_page(paging.per_page);
                if let Some(user) = user {
                    req = req.user_id(parse_uuid(&user, "user")?);
                }
                if let Some(action) = action {
                    req = req.action(action);
                }
                if let Some(resource_type) = resource_type {
                    req = req.resource_type(resource_type);
                }
                if let Some(resource_id) = resource_id {
                    req = req.resource_id(parse_uuid(&resource_id, "resource")?);
                }
                if let Some(correlation_id) = correlation_id {
                    req = req.correlation_id(correlation_id);
                }
                if let Some(from) = from {
                    req = req.from(from);
                }
                if let Some(to) = to {
                    req = req.to(to);
                }

                let spinner = output::spinner("Fetching audit log...");
                let (resp, raw) = artifact_keeper_sdk::raw::capture(req.send()).await;
                let resp = resp.map_err(|e| sdk_err("list audit log", e))?.into_inner();
                spinner.finish_and_clear();

                if resp.items.is_empty() && !output::is_machine_format(&global.format) {
                    eprintln!("No audit log entries found.");
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
                    "TIME",
                    "ACTOR",
                    "ACTION",
                    "RESOURCE",
                    "RESOURCE ID",
                    "IP",
                    "CORRELATION ID",
                ]);
                for item in &resp.items {
                    table.add_row(vec![
                        short_id(&item.id),
                        item.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
                        item.actor_username.clone().unwrap_or_else(|| "-".into()),
                        item.action.clone(),
                        item.resource_type.clone(),
                        item.resource_id
                            .map(|id| id.to_string())
                            .unwrap_or_else(|| "-".into()),
                        item.ip_address.clone().unwrap_or_else(|| "-".into()),
                        item.correlation_id.clone(),
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
                    resp.page,
                    super::total_pages(resp.total, resp.per_page),
                    resp.total,
                    "entries",
                );
                Ok(())
            }
        }
    }
}
