use std::path::{Path, PathBuf};

use artifact_keeper_sdk::{ClientPromotionExt, ClientRepositoriesExt, ClientSearchExt};
use clap::Subcommand;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use futures::StreamExt;
use miette::{IntoDiagnostic, Result};

use super::client::client_for;
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat, format_bytes};

#[derive(Subcommand)]
pub enum ArtifactCommand {
    /// Upload an artifact to a repository
    Push {
        /// Repository key
        repo: String,

        /// File(s) to upload (supports glob patterns)
        #[arg(required = true)]
        files: Vec<String>,

        /// Target path within the repository
        #[arg(long)]
        path: Option<String>,
    },

    /// Download an artifact from a repository
    Pull {
        /// Repository key
        repo: String,

        /// Artifact path within the repository
        path: String,

        /// Output file path (defaults to artifact filename)
        #[arg(short, long)]
        output: Option<String>,
    },

    /// List artifacts in a repository
    List {
        /// Repository key
        repo: String,

        /// Search within the repository
        #[arg(long)]
        search: Option<String>,

        /// Page number
        #[arg(long, default_value = "1")]
        page: i32,

        /// Results per page
        #[arg(long, default_value = "50")]
        per_page: i32,
    },

    /// Show artifact metadata and details
    Info {
        /// Repository key
        repo: String,

        /// Artifact path
        path: String,
    },

    /// Delete an artifact
    Delete {
        /// Repository key
        repo: String,

        /// Artifact path
        path: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Search artifacts across all repositories
    Search {
        /// Search query
        query: String,

        /// Filter by repository
        #[arg(long)]
        repo: Option<String>,

        /// Filter by package format
        #[arg(long)]
        format: Option<String>,
    },

    /// Copy an artifact between repositories
    Copy {
        /// Source: repo/path
        source: String,

        /// Destination repository key
        destination: String,
    },
}

impl ArtifactCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Push { repo, files, path } => push(&repo, &files, path.as_deref(), global).await,
            Self::Pull { repo, path, output } => {
                pull(&repo, &path, output.as_deref(), global).await
            }
            Self::List {
                repo,
                search,
                page,
                per_page,
            } => list(&repo, search.as_deref(), page, per_page, global).await,
            Self::Info { repo, path } => info(&repo, &path, global).await,
            Self::Delete { repo, path, yes } => delete(&repo, &path, yes, global).await,
            Self::Search {
                query,
                repo,
                format,
            } => search(&query, repo.as_deref(), format.as_deref(), global).await,
            Self::Copy {
                source,
                destination,
            } => copy(&source, &destination, global).await,
        }
    }
}

async fn push(
    repo: &str,
    file_patterns: &[String],
    target_path: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;

    let mut files_to_upload: Vec<PathBuf> = Vec::new();
    for pattern in file_patterns {
        let matches: Vec<_> = glob::glob(pattern)
            .into_diagnostic()?
            .filter_map(|r| r.ok())
            .filter(|p| p.is_file())
            .collect();

        if matches.is_empty() {
            let path = PathBuf::from(pattern);
            if path.is_file() {
                files_to_upload.push(path);
            } else {
                return Err(
                    AkError::ConfigError(format!("No files match pattern: {pattern}")).into(),
                );
            }
        } else {
            files_to_upload.extend(matches);
        }
    }

    for file_path in &files_to_upload {
        let file_name = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        let artifact_path = target_path
            .map(|p| {
                if p.ends_with('/') {
                    format!("{p}{file_name}")
                } else if files_to_upload.len() > 1 {
                    format!("{p}/{file_name}")
                } else {
                    p.to_string()
                }
            })
            .unwrap_or_else(|| file_name.to_string());

        let file_size = tokio::fs::metadata(file_path)
            .await
            .into_diagnostic()?
            .len();

        let pb = indicatif::ProgressBar::new(file_size);
        pb.set_style(
            indicatif::ProgressStyle::with_template(
                "{msg} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})",
            )
            .unwrap()
            .progress_chars("█▉▊▋▌▍▎▏ "),
        );
        pb.set_message(format!("Uploading {file_name}"));

        let file_bytes = tokio::fs::read(file_path).await.into_diagnostic()?;
        pb.set_position(file_size); // Show as complete after read

        let body = reqwest::Body::from(file_bytes);

        let resp = client
            .upload_artifact()
            .key(repo)
            .path(&artifact_path)
            .body(body)
            .send()
            .await
            .map_err(|e| AkError::ServerError(format!("Upload failed: {e}")))?;

        pb.finish_with_message(format!("Uploaded {file_name}"));

        if matches!(global.format, OutputFormat::Quiet) {
            println!("{}", resp.path);
        } else {
            eprintln!(
                "  {} ({}) -> {}:{}",
                file_name,
                format_bytes(resp.size_bytes),
                repo,
                resp.path
            );
        }
    }

    if !matches!(global.format, OutputFormat::Quiet) && files_to_upload.len() > 1 {
        eprintln!("Uploaded {} files.", files_to_upload.len());
    }

    Ok(())
}

async fn pull(
    repo: &str,
    artifact_path: &str,
    output: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;

    let out_path = output.map(PathBuf::from).unwrap_or_else(|| {
        let filename = Path::new(artifact_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("download");
        PathBuf::from(filename)
    });

    let spinner = crate::output::spinner(&format!("Downloading {artifact_path}..."));

    let resp = client
        .download_artifact()
        .key(repo)
        .path(artifact_path)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Download failed: {e}")))?;

    spinner.finish_and_clear();

    let mut bytes = Vec::new();
    let mut stream = resp.into_inner();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.into_diagnostic()?;
        bytes.extend_from_slice(&chunk);
    }

    tokio::fs::write(&out_path, &bytes)
        .await
        .into_diagnostic()?;

    eprintln!(
        "Downloaded {}:{} -> {} ({})",
        repo,
        artifact_path,
        out_path.display(),
        format_bytes(bytes.len() as i64),
    );

    Ok(())
}

async fn list(
    repo: &str,
    search: Option<&str>,
    page: i32,
    per_page: i32,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;

    let spinner = crate::output::spinner("Fetching artifacts...");

    let mut req = client
        .list_artifacts()
        .key(repo)
        .page(page)
        .per_page(per_page);
    if let Some(q) = search {
        req = req.q(q);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to list artifacts: {e}")))?;

    spinner.finish_and_clear();

    if resp.items.is_empty() {
        eprintln!("No artifacts found in '{repo}'.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for a in &resp.items {
            println!("{}", a.path);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp
        .items
        .iter()
        .map(|a| {
            serde_json::json!({
                "path": a.path,
                "name": a.name,
                "version": a.version,
                "size": format_bytes(a.size_bytes),
                "size_bytes": a.size_bytes,
                "downloads": a.download_count,
                "created_at": a.created_at.to_rfc3339(),
            })
        })
        .collect();

    let table_str = {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec!["PATH", "VERSION", "SIZE", "DOWNLOADS", "CREATED"]);

        for a in &resp.items {
            let version = a.version.as_deref().unwrap_or("-");
            let size = format_bytes(a.size_bytes);
            let created = a.created_at.format("%Y-%m-%d").to_string();
            table.add_row(vec![
                a.path.as_str(),
                version,
                &size,
                &a.download_count.to_string(),
                &created,
            ]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    if resp.pagination.total_pages > 1 {
        eprintln!(
            "Page {} of {} ({} total artifacts)",
            resp.pagination.page, resp.pagination.total_pages, resp.pagination.total
        );
    }

    Ok(())
}

async fn info(repo: &str, artifact_path: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;

    let artifacts = client
        .list_artifacts()
        .key(repo)
        .q(artifact_path)
        .per_page(1)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to find artifact: {e}")))?;

    let artifact = artifacts.items.first().ok_or_else(|| {
        AkError::ServerError(format!("Artifact '{artifact_path}' not found in '{repo}'"))
    })?;

    let info = serde_json::json!({
        "path": artifact.path,
        "name": artifact.name,
        "version": artifact.version,
        "size": format_bytes(artifact.size_bytes),
        "size_bytes": artifact.size_bytes,
        "content_type": artifact.content_type,
        "sha256": artifact.checksum_sha256,
        "downloads": artifact.download_count,
        "repository": artifact.repository_key,
        "created_at": artifact.created_at.to_rfc3339(),
    });

    let table_str = format!(
        "Path:         {}\n\
         Name:         {}\n\
         Version:      {}\n\
         Size:         {}\n\
         Content Type: {}\n\
         SHA-256:      {}\n\
         Downloads:    {}\n\
         Repository:   {}\n\
         Created:      {}",
        artifact.path,
        artifact.name,
        artifact.version.as_deref().unwrap_or("-"),
        format_bytes(artifact.size_bytes),
        artifact.content_type,
        artifact.checksum_sha256,
        artifact.download_count,
        artifact.repository_key,
        artifact.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn delete(
    repo: &str,
    artifact_path: &str,
    skip_confirm: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;

    let needs_confirmation = !skip_confirm && !global.no_input;
    if needs_confirmation {
        let confirmed = dialoguer::Confirm::new()
            .with_prompt(format!(
                "Delete '{artifact_path}' from '{repo}'? This cannot be undone"
            ))
            .default(false)
            .interact()
            .into_diagnostic()?;

        if !confirmed {
            eprintln!("Cancelled.");
            return Ok(());
        }
    }

    client
        .delete_artifact()
        .key(repo)
        .path(artifact_path)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to delete artifact: {e}")))?;

    eprintln!("Deleted '{artifact_path}' from '{repo}'.");
    Ok(())
}

async fn search(
    query: &str,
    repo: Option<&str>,
    format: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;

    let spinner = crate::output::spinner("Searching...");

    let mut req = client.advanced_search().query(query);
    if let Some(r) = repo {
        req = req.repository_key(r);
    }
    if let Some(f) = format {
        req = req.format(f);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Search failed: {e}")))?;

    spinner.finish_and_clear();

    if resp.items.is_empty() {
        eprintln!("No results found for '{query}'.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for item in &resp.items {
            println!("{}", item.name);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp
        .items
        .iter()
        .map(|item| {
            serde_json::json!({
                "name": item.name,
                "path": item.path,
                "repository": item.repository_key,
                "format": item.format,
                "version": item.version,
                "type": item.type_,
                "size": item.size_bytes.map(format_bytes),
            })
        })
        .collect();

    let table_str = {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec!["NAME", "REPOSITORY", "FORMAT", "VERSION", "SIZE"]);

        for item in &resp.items {
            let version = item.version.as_deref().unwrap_or("-");
            let format_str = item.format.as_deref().unwrap_or("-");
            let size = item
                .size_bytes
                .map(format_bytes)
                .unwrap_or_else(|| "-".into());
            table.add_row(vec![
                item.name.as_str(),
                item.repository_key.as_str(),
                format_str,
                version,
                &size,
            ]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    eprintln!("{} results found.", resp.items.len());

    Ok(())
}

async fn copy(source: &str, destination: &str, global: &GlobalArgs) -> Result<()> {
    let (src_repo, src_path) = source
        .split_once('/')
        .ok_or_else(|| AkError::ConfigError("Source must be in format 'repo/path'".into()))?;

    let client = client_for(global)?;

    let artifacts = client
        .list_artifacts()
        .key(src_repo)
        .q(src_path)
        .per_page(1)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to find source artifact: {e}")))?;

    let artifact = artifacts.items.first().ok_or_else(|| {
        AkError::ServerError(format!("Artifact '{src_path}' not found in '{src_repo}'"))
    })?;

    let body = artifact_keeper_sdk::types::PromoteArtifactRequest {
        target_repository: destination.to_string(),
        notes: None,
        skip_policy_check: None,
    };

    client
        .promote_artifact()
        .key(src_repo)
        .artifact_id(artifact.id)
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Copy failed: {e}")))?;

    eprintln!(
        "Copied '{}' from '{}' to '{}'.",
        src_path, src_repo, destination
    );

    Ok(())
}
