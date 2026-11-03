//! `ak admin blast-radius`: who a bad artifact or CVE reached.

use artifact_keeper_sdk::ClientAdminExt;
use artifact_keeper_sdk::types::{AccessibleUsersResponse, BlastRadiusResponse};
use clap::{Args, Subcommand};
use miette::Result;

use super::PageArgs;
use crate::cli::GlobalArgs;
use crate::commands::client::client_for;
use crate::commands::helpers::{
    new_table, print_page_info, resolve_artifact_id, resolve_repo_id, sdk_err,
};
use crate::output::{self, OutputFormat};

/// What both targets take.
#[derive(Args)]
pub struct BlastArgs {
    /// List users who could download it but haven't, rather than who did
    #[arg(long)]
    accessible_users: bool,

    /// With --accessible-users: which repository to check, by key or ID
    #[arg(long, requires = "accessible_users")]
    repo: Option<String>,

    /// Earliest download, RFC 3339. Not with --accessible-users
    #[arg(long, conflicts_with = "accessible_users")]
    from: Option<String>,

    /// Latest download, RFC 3339. Not with --accessible-users
    #[arg(long, conflicts_with = "accessible_users")]
    to: Option<String>,

    #[command(flatten)]
    paging: PageArgs,
}

#[derive(Subcommand)]
pub enum BlastRadiusCommand {
    /// Show who an artifact reached. The server counts only downloads of an
    /// artifact with scan findings, so one with no findings shows zero
    Artifact {
        /// Artifact ID or <repo-key>/<path>
        artifact: String,

        #[command(flatten)]
        args: BlastArgs,
    },

    /// Show who the artifacts affected by a CVE reached
    Cve {
        /// CVE ID, for example CVE-2024-1234
        cve: String,

        #[command(flatten)]
        args: BlastArgs,
    },
}

/// Send one of the two reports for a target. The artifact and CVE builders have
/// the same setters but no common type.
macro_rules! report {
    ($client:ident, $global:ident, $args:ident, $accessible:ident, $radius:ident, $setter:ident, $target:expr) => {{
        let spinner = output::spinner("Computing blast radius...");
        if $args.accessible_users {
            let mut req = $client
                .$accessible()
                .$setter($target)
                .page($args.paging.page)
                .per_page($args.paging.per_page);
            if let Some(repo) = &$args.repo {
                req = req.repository_id(resolve_repo_id(&$client, repo).await?);
            }
            let (resp, raw) = artifact_keeper_sdk::raw::capture(req.send()).await;
            let resp = resp
                .map_err(|e| sdk_err("list accessible users", e))?
                .into_inner();
            spinner.finish_and_clear();
            print_accessible(&resp, raw.as_deref(), $global);
        } else {
            let mut req = $client
                .$radius()
                .$setter($target)
                .page($args.paging.page)
                .per_page($args.paging.per_page);
            if let Some(from) = $args.from {
                req = req.from(from);
            }
            if let Some(to) = $args.to {
                req = req.to(to);
            }
            let (resp, raw) = artifact_keeper_sdk::raw::capture(req.send()).await;
            let resp = resp
                .map_err(|e| sdk_err("get blast radius", e))?
                .into_inner();
            spinner.finish_and_clear();
            print_blast_radius(&resp, raw.as_deref(), $global);
        }
    }};
}

impl BlastRadiusCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        let client = client_for(global)?;
        match self {
            Self::Artifact { artifact, args } => {
                let id = resolve_artifact_id(&client, &artifact).await?;
                report!(
                    client,
                    global,
                    args,
                    artifact_accessible_users,
                    artifact_blast_radius,
                    artifact_id,
                    id
                );
            }
            Self::Cve { cve, args } => {
                report!(
                    client,
                    global,
                    args,
                    cve_accessible_users,
                    cve_blast_radius,
                    cve_id,
                    cve
                );
            }
        }
        Ok(())
    }
}

fn print_blast_radius(resp: &BlastRadiusResponse, raw: Option<&[u8]>, global: &GlobalArgs) {
    if matches!(global.format, OutputFormat::Quiet) {
        for repo in &resp.affected_repos {
            println!("{}", repo.repository_key);
        }
        return;
    }

    let summary = &resp.summary;
    let proxy = &resp.proxy_exposure;
    let mut text = format!(
        "Target:              {} {}\n\
         Affected artifacts:  {}\n\
         Affected repos:      {}\n\
         Downloading users:   {}\n\
         Downloads:           {}\n\
         Distinct IPs:        {}\n\
         Anonymous downloads: {}\n\
         Proxy coverage:      {}\n\
         Proxy digests:       {}\n\
         Proxy repos:         {}\n\
         Proxy downloads:     {}\n\
         Proxy users:         {}\n\
         Proxy anonymous:     {}",
        resp.target.kind,
        resp.target.value,
        summary.affected_artifact_count,
        summary.affected_repo_count,
        summary.downloader_user_count,
        summary.total_download_count,
        summary.distinct_ip_count,
        yes_no(summary.anonymous_download_present),
        proxy.coverage,
        proxy.affected_digest_count,
        proxy.affected_repo_count,
        proxy.download_count,
        proxy.downloader_user_count,
        yes_no(proxy.anonymous_download_present),
    );

    if !resp.affected_repos.is_empty() {
        let mut table = new_table(vec!["REPOSITORY", "ID", "PUBLIC", "ACCESS"]);
        for repo in &resp.affected_repos {
            table.add_row(vec![
                repo.repository_key.clone(),
                repo.repository_id.to_string(),
                yes_no(repo.is_public).to_string(),
                repo.access_scope.clone(),
            ]);
        }
        text.push_str(&format!("\n\n{table}"));
    }
    if !resp.downloaders.is_empty() {
        let mut table = new_table(vec![
            "USER",
            "DOWNLOADS",
            "IPS",
            "FIRST",
            "LAST",
            "IP ADDRESSES",
        ]);
        for d in &resp.downloaders {
            table.add_row(vec![
                d.username
                    .clone()
                    .or_else(|| d.user_id.map(|id| id.to_string()))
                    .unwrap_or_else(|| "anonymous".into()),
                d.download_count.to_string(),
                d.distinct_ip_count.to_string(),
                d.first_download.format("%Y-%m-%d %H:%M").to_string(),
                d.last_download.format("%Y-%m-%d %H:%M").to_string(),
                d.ip_addresses.join(", "),
            ]);
        }
        text.push_str(&format!("\n\n{table}"));
    }

    println!(
        "{}",
        output::render_raw(raw, resp, &global.format, Some(text))
    );
    print_page_info(
        resp.page,
        super::total_pages(resp.total_downloaders, resp.per_page),
        resp.total_downloaders,
        "downloaders",
    );
}

fn print_accessible(resp: &AccessibleUsersResponse, raw: Option<&[u8]>, global: &GlobalArgs) {
    if matches!(global.format, OutputFormat::Quiet) {
        for user in &resp.accessible_not_downloaded {
            println!("{}", user.user_id);
        }
        return;
    }

    let mut text = format!(
        "Target:     {} {}\n\
         Repository: {} ({})\n\
         Access:     {}\n\
         Exposure:   {}",
        resp.target.kind,
        resp.target.value,
        resp.repository.repository_key,
        resp.repository.repository_id,
        resp.repository.access_scope,
        resp.exposure,
    );
    if resp.accessible_not_downloaded.is_empty() {
        text.push_str("\n\nNo users have access without having downloaded it.");
    } else {
        let mut table = new_table(vec!["USER", "ID", "REASON", "VIA"]);
        for user in &resp.accessible_not_downloaded {
            table.add_row(vec![
                user.username.clone(),
                user.user_id.to_string(),
                user.reason.clone(),
                user.via.clone(),
            ]);
        }
        text.push_str(&format!("\n\n{table}"));
    }
    println!(
        "{}",
        output::render_raw(raw, resp, &global.format, Some(text))
    );
    if let Some(total) = resp.total {
        print_page_info(
            resp.page,
            super::total_pages(total, resp.per_page),
            total,
            "users",
        );
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}
