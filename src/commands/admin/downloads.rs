//! `ak admin downloads`: who downloaded what.

use artifact_keeper_sdk::ClientAdminExt;
use artifact_keeper_sdk::types::{DownloadListResponse, DownloadSource};
use clap::{Args, Subcommand, ValueEnum};
use miette::Result;

use super::PageArgs;
use crate::cli::GlobalArgs;
use crate::commands::client::client_for;
use crate::commands::helpers::{
    new_table, parse_uuid, print_page_info, resolve_artifact_id, resolve_repo_id, sdk_err,
};
use crate::error::AkError;
use crate::output::{self, OutputFormat};

#[derive(Clone, Copy, ValueEnum)]
pub enum SourceArg {
    /// A hosted artifact
    Hosted,
    /// A pull-through serve from a remote repository
    Proxy,
}

impl From<SourceArg> for DownloadSource {
    fn from(source: SourceArg) -> Self {
        match source {
            SourceArg::Hosted => DownloadSource::Hosted,
            SourceArg::Proxy => DownloadSource::Proxy,
        }
    }
}

/// Filters every download listing takes.
#[derive(Args)]
pub struct DownloadFilters {
    /// Only this artifact: an ID or <repo-key>/<path>
    #[arg(long)]
    artifact: Option<String>,

    /// Only downloads served from this repository, by key or ID. Needs a 1.11
    /// server
    #[arg(long)]
    repo: Option<String>,

    /// Only hosted downloads or only proxy serves. Needs a 1.11 server
    #[arg(long, value_enum)]
    source: Option<SourceArg>,

    /// Earliest time, RFC 3339 (2026-01-15T00:00:00Z)
    #[arg(long)]
    from: Option<String>,

    /// Latest time, RFC 3339 (2026-01-15T23:59:59Z)
    #[arg(long)]
    to: Option<String>,

    #[command(flatten)]
    paging: PageArgs,
}

#[derive(Subcommand)]
pub enum DownloadsCommand {
    /// List downloads. The server records them in the background, so a download
    /// can take a moment to appear
    List {
        /// Only downloads by this user ID
        #[arg(long)]
        user: Option<String>,

        /// Only downloads from this client IP
        #[arg(long)]
        ip: Option<String>,

        #[command(flatten)]
        filters: DownloadFilters,
    },

    /// List downloads from one client IP
    ByIp {
        /// Client IP address
        ip: String,

        /// Only downloads by this user ID
        #[arg(long)]
        user: Option<String>,

        #[command(flatten)]
        filters: DownloadFilters,
    },

    /// List downloads by one user
    ByUser {
        /// User ID
        user: String,

        /// Only downloads from this client IP
        #[arg(long)]
        ip: Option<String>,

        #[command(flatten)]
        filters: DownloadFilters,
    },
}

/// Set the shared filters on a request. The three builders have the same setters
/// but no common type.
macro_rules! apply_filters {
    ($req:ident, $client:ident, $filters:ident) => {{
        $req = $req
            .page($filters.paging.page)
            .per_page($filters.paging.per_page);
        if let Some(artifact) = &$filters.artifact {
            $req = $req.artifact_id(resolve_artifact_id(&$client, artifact).await?);
        }
        if let Some(repo) = &$filters.repo {
            $req = $req.repository_id(resolve_repo_id(&$client, repo).await?);
        }
        if let Some(source) = $filters.source {
            $req = $req.source(DownloadSource::from(source));
        }
        if let Some(from) = $filters.from {
            $req = $req.from(from);
        }
        if let Some(to) = $filters.to {
            $req = $req.to(to);
        }
    }};
}

impl DownloadsCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        let client = client_for(global)?;
        let narrowed = self.filters().repo.is_some() || self.filters().source.is_some();
        let spinner = output::spinner("Fetching downloads...");
        let (resp, raw) = match self {
            Self::List { user, ip, filters } => {
                let mut req = client.list_downloads();
                apply_filters!(req, client, filters);
                if let Some(user) = user {
                    req = req.user_id(parse_uuid(&user, "user")?);
                }
                if let Some(ip) = ip {
                    req = req.ip(ip);
                }
                artifact_keeper_sdk::raw::capture(req.send()).await
            }
            Self::ByIp { ip, user, filters } => {
                let mut req = client.list_downloads_by_ip().ip(ip);
                apply_filters!(req, client, filters);
                if let Some(user) = user {
                    req = req.user_id(parse_uuid(&user, "user")?);
                }
                artifact_keeper_sdk::raw::capture(req.send()).await
            }
            Self::ByUser { user, ip, filters } => {
                let mut req = client
                    .list_downloads_by_user()
                    .user_id(parse_uuid(&user, "user")?);
                apply_filters!(req, client, filters);
                if let Some(ip) = ip {
                    req = req.ip(ip);
                }
                artifact_keeper_sdk::raw::capture(req.send()).await
            }
        };
        let resp = resp.map_err(|e| sdk_err("list downloads", e))?.into_inner();
        spinner.finish_and_clear();
        // A server before 1.11 ignores both filters, so it sends downloads they
        // should have removed. It also leaves out `source`, which is how to tell.
        if narrowed && resp.downloads.iter().any(|d| d.source.is_none()) {
            return Err(AkError::UnsupportedServer(
                "This server ignores --repo and --source, which need a server on 1.11 or \
                 newer, so its answer isn't filtered. Run this without them."
                    .into(),
            )
            .into());
        }
        print_downloads(&resp, raw.as_deref(), global);
        Ok(())
    }

    fn filters(&self) -> &DownloadFilters {
        match self {
            Self::List { filters, .. }
            | Self::ByIp { filters, .. }
            | Self::ByUser { filters, .. } => filters,
        }
    }
}

fn print_downloads(resp: &DownloadListResponse, raw: Option<&[u8]>, global: &GlobalArgs) {
    if resp.downloads.is_empty() && !output::is_machine_format(&global.format) {
        eprintln!("No downloads found.");
        return;
    }
    if matches!(global.format, OutputFormat::Quiet) {
        // A download event has no ID of its own. A proxy serve has no artifact.
        for download in &resp.downloads {
            match (&download.artifact_id, &download.path) {
                (Some(id), _) => println!("{id}"),
                (None, Some(path)) => println!("{path}"),
                (None, None) => {}
            }
        }
        return;
    }

    let mut table = new_table(vec![
        "TIME", "SOURCE", "USER", "IP", "ARTIFACT", "PATH", "CLIENT",
    ]);
    for d in &resp.downloads {
        table.add_row(vec![
            d.downloaded_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            d.source
                .map(|source| source.to_string())
                .unwrap_or_else(|| "-".into()),
            d.username
                .clone()
                .or_else(|| d.user_id.map(|id| id.to_string()))
                .unwrap_or_else(|| "anonymous".into()),
            d.ip_address.clone().unwrap_or_else(|| "-".into()),
            d.artifact_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "-".into()),
            d.path.clone().unwrap_or_else(|| "-".into()),
            d.user_agent.clone().unwrap_or_else(|| "-".into()),
        ]);
    }
    println!(
        "{}",
        output::render_raw(raw, resp, &global.format, Some(table.to_string()))
    );
    print_page_info(
        resp.page,
        super::total_pages(resp.total, resp.per_page),
        resp.total,
        "downloads",
    );
}
