//! `ak search`: quick, checksum, suggest, recent and trending. `ak artifact search`
//! is the one with filters.

use artifact_keeper_sdk::ClientSearchExt;
use artifact_keeper_sdk::types::{ChecksumArtifact, SearchResultItem};
use clap::Subcommand;
use miette::Result;

use super::client::client_for;
use super::helpers::{new_table, sdk_err};
use crate::cli::GlobalArgs;
use crate::output::{self, OutputFormat, format_bytes};

#[derive(Subcommand)]
pub enum SearchCommand {
    /// Search across repositories and artifacts by name
    Quick {
        /// What to look for
        query: String,

        /// Most results to return
        #[arg(long)]
        limit: Option<i64>,

        /// Only these kinds of result, comma-separated (e.g. artifact,package)
        #[arg(long)]
        types: Option<String>,
    },

    /// Find artifacts by checksum
    Checksum {
        /// The checksum, in hex
        checksum: String,

        /// The checksum's algorithm: sha256 (the server's default), sha1 or md5
        #[arg(long)]
        algorithm: Option<String>,
    },

    /// Suggest names that start with a prefix
    Suggest {
        /// The start of a name
        prefix: String,

        /// Most suggestions to return
        #[arg(long)]
        limit: Option<i64>,
    },

    /// List the newest artifacts
    Recent {
        /// Most results to return
        #[arg(long)]
        limit: Option<i64>,
    },

    /// List the most downloaded artifacts
    Trending {
        /// How many days back to count downloads
        #[arg(long)]
        days: Option<i64>,

        /// Most results to return
        #[arg(long)]
        limit: Option<i64>,
    },
}

impl SearchCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        let client = client_for(global)?;
        let spinner = output::spinner("Searching...");
        match self {
            Self::Quick {
                query,
                limit,
                types,
            } => {
                let mut req = client.quick_search().q(query);
                if let Some(limit) = limit {
                    req = req.limit(limit);
                }
                if let Some(types) = types {
                    req = req.types(types);
                }
                let (resp, raw) = artifact_keeper_sdk::raw::capture(req.send()).await;
                let resp = resp.map_err(|e| sdk_err("search", e))?.into_inner();
                spinner.finish_and_clear();
                print_results(&resp.results, &resp, raw.as_deref(), global);
            }
            Self::Checksum {
                checksum,
                algorithm,
            } => {
                let mut req = client.checksum_search().checksum(checksum);
                if let Some(algorithm) = algorithm {
                    req = req.algorithm(algorithm);
                }
                let (resp, raw) = artifact_keeper_sdk::raw::capture(req.send()).await;
                let resp = resp
                    .map_err(|e| sdk_err("search by checksum", e))?
                    .into_inner();
                spinner.finish_and_clear();
                print_checksum_matches(&resp.artifacts, &resp, raw.as_deref(), global);
            }
            Self::Suggest { prefix, limit } => {
                let mut req = client.suggest().prefix(prefix);
                if let Some(limit) = limit {
                    req = req.limit(limit);
                }
                let (resp, raw) = artifact_keeper_sdk::raw::capture(req.send()).await;
                let resp = resp
                    .map_err(|e| sdk_err("get suggestions", e))?
                    .into_inner();
                spinner.finish_and_clear();
                if resp.suggestions.is_empty() && !output::is_machine_format(&global.format) {
                    eprintln!("No suggestions.");
                    return Ok(());
                }
                if matches!(global.format, OutputFormat::Quiet | OutputFormat::Table) {
                    for suggestion in &resp.suggestions {
                        println!("{suggestion}");
                    }
                    return Ok(());
                }
                println!(
                    "{}",
                    output::render_raw(raw.as_deref(), &resp, &global.format, None)
                );
            }
            Self::Recent { limit } => {
                let mut req = client.recent();
                if let Some(limit) = limit {
                    req = req.limit(limit);
                }
                let (resp, raw) = artifact_keeper_sdk::raw::capture(req.send()).await;
                let resp = resp
                    .map_err(|e| sdk_err("list recent artifacts", e))?
                    .into_inner();
                spinner.finish_and_clear();
                print_results(&resp, &resp, raw.as_deref(), global);
            }
            Self::Trending { days, limit } => {
                let mut req = client.trending();
                if let Some(days) = days {
                    req = req.days(days);
                }
                if let Some(limit) = limit {
                    req = req.limit(limit);
                }
                let (resp, raw) = artifact_keeper_sdk::raw::capture(req.send()).await;
                let resp = resp
                    .map_err(|e| sdk_err("list trending artifacts", e))?
                    .into_inner();
                spinner.finish_and_clear();
                print_results(&resp, &resp, raw.as_deref(), global);
            }
        }
        Ok(())
    }
}

fn print_results<T: serde::Serialize>(
    results: &[SearchResultItem],
    fallback: &T,
    raw: Option<&[u8]>,
    global: &GlobalArgs,
) {
    if results.is_empty() && !output::is_machine_format(&global.format) {
        eprintln!("No results.");
        return;
    }
    if matches!(global.format, OutputFormat::Quiet) {
        for item in results {
            println!("{}", item.id);
        }
        return;
    }
    let mut table = new_table(vec![
        "ID",
        "TYPE",
        "NAME",
        "VERSION",
        "REPOSITORY",
        "PATH",
        "SIZE",
        "CREATED",
    ]);
    for item in results {
        table.add_row(vec![
            item.id.to_string(),
            item.type_.clone(),
            item.name.clone(),
            item.version.clone().unwrap_or_else(|| "-".into()),
            item.repository_key.clone(),
            item.path.clone().unwrap_or_else(|| "-".into()),
            item.size_bytes.map_or_else(|| "-".into(), format_bytes),
            item.created_at.format("%Y-%m-%d %H:%M").to_string(),
        ]);
    }
    println!(
        "{}",
        output::render_raw(raw, fallback, &global.format, Some(table.to_string()))
    );
}

fn print_checksum_matches<T: serde::Serialize>(
    artifacts: &[ChecksumArtifact],
    fallback: &T,
    raw: Option<&[u8]>,
    global: &GlobalArgs,
) {
    if artifacts.is_empty() && !output::is_machine_format(&global.format) {
        eprintln!("No artifacts have that checksum.");
        return;
    }
    if matches!(global.format, OutputFormat::Quiet) {
        for artifact in artifacts {
            println!("{}", artifact.id);
        }
        return;
    }
    let mut table = new_table(vec![
        "ID",
        "NAME",
        "VERSION",
        "REPOSITORY",
        "PATH",
        "SIZE",
        "DOWNLOADS",
        "CREATED",
    ]);
    for artifact in artifacts {
        table.add_row(vec![
            artifact.id.to_string(),
            artifact.name.clone(),
            artifact.version.clone().unwrap_or_else(|| "-".into()),
            artifact.repository_key.clone(),
            artifact.path.clone(),
            format_bytes(artifact.size_bytes),
            artifact.download_count.to_string(),
            artifact.created_at.format("%Y-%m-%d %H:%M").to_string(),
        ]);
    }
    println!(
        "{}",
        output::render_raw(raw, fallback, &global.format, Some(table.to_string()))
    );
}
