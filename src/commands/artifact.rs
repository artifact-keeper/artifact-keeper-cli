use std::path::{Path, PathBuf};

use artifact_keeper_sdk::{ClientPromotionExt, ClientRepositoriesExt, ClientSearchExt};
use clap::Subcommand;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use futures::StreamExt;
use miette::{IntoDiagnostic, Result};

use super::client::{build_client, client_for, client_for_optional_auth};
use crate::cli::GlobalArgs;
use crate::config::AppConfig;
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
        #[arg(long = "pkg-format", id = "pkg_format")]
        pkg_format: Option<String>,
    },

    /// Copy an artifact between repositories (same or cross-instance)
    Copy {
        /// Source: repo/path
        source: String,

        /// Destination: repo or repo/path
        destination: String,

        /// Source instance (defaults to current instance)
        #[arg(long)]
        from_instance: Option<String>,

        /// Destination instance (defaults to current instance)
        #[arg(long)]
        to_instance: Option<String>,
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
                pkg_format,
            } => search(&query, repo.as_deref(), pkg_format.as_deref(), global).await,
            Self::Copy {
                source,
                destination,
                from_instance,
                to_instance,
            } => {
                copy(
                    &source,
                    &destination,
                    from_instance.as_deref(),
                    to_instance.as_deref(),
                    global,
                )
                .await
            }
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

    let spinner = output::spinner(&format!("Downloading {artifact_path}..."));

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
    let client = client_for_optional_auth(global)?;

    let spinner = output::spinner("Fetching artifacts...");

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
    let client = client_for_optional_auth(global)?;

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
    let client = client_for_optional_auth(global)?;

    let spinner = output::spinner("Searching...");

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

async fn copy(
    source: &str,
    destination: &str,
    from_instance: Option<&str>,
    to_instance: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let (src_repo, src_path) = source
        .split_once('/')
        .ok_or_else(|| AkError::ConfigError("Source must be in format 'repo/path'".into()))?;

    let is_cross_instance = from_instance.is_some() || to_instance.is_some();

    if is_cross_instance {
        cross_instance_copy(
            src_repo,
            src_path,
            destination,
            from_instance,
            to_instance,
            global,
        )
        .await
    } else {
        same_instance_copy(src_repo, src_path, destination, global).await
    }
}

async fn same_instance_copy(
    src_repo: &str,
    src_path: &str,
    destination: &str,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;

    let spinner = output::spinner("Finding artifact...");

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

    spinner.set_message("Copying...");

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

    spinner.finish_and_clear();

    eprintln!(
        "Copied '{}' from '{}' to '{}'.",
        src_path, src_repo, destination
    );

    Ok(())
}

async fn cross_instance_copy(
    src_repo: &str,
    src_path: &str,
    destination: &str,
    from_instance: Option<&str>,
    to_instance: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let config = AppConfig::load()?;

    let (src_name, src_instance) =
        config.resolve_instance(from_instance.or(global.instance.as_deref()))?;
    let (dst_name, dst_instance) = config.resolve_instance(to_instance)?;

    let src_client = build_client(src_name, src_instance, None)?;
    let dst_client = build_client(dst_name, dst_instance, None)?;

    let spinner = output::spinner(&format!(
        "Downloading from {src_name}:{src_repo}/{src_path}..."
    ));

    let resp = src_client
        .download_artifact()
        .key(src_repo)
        .path(src_path)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Download from source failed: {e}")))?;

    let mut bytes = Vec::new();
    let mut stream = resp.into_inner();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.into_diagnostic()?;
        bytes.extend_from_slice(&chunk);
    }

    let (dst_repo, dst_path) = match destination.split_once('/') {
        Some((repo, path)) => (repo, path.to_string()),
        None => (destination, src_path.to_string()),
    };

    spinner.set_message(format!("Uploading to {dst_name}:{dst_repo}/{dst_path}..."));

    let size = bytes.len() as i64;
    let body = reqwest::Body::from(bytes);

    dst_client
        .upload_artifact()
        .key(dst_repo)
        .path(&dst_path)
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Upload to destination failed: {e}")))?;

    spinner.finish_and_clear();

    eprintln!(
        "Copied {src_name}:{src_repo}/{src_path} -> {dst_name}:{dst_repo}/{dst_path} ({})",
        format_bytes(size),
    );

    Ok(())
}

/// Format a list of artifact entries as a table string.
fn format_artifacts_table(items: &[serde_json::Value]) -> String {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec!["PATH", "VERSION", "SIZE", "DOWNLOADS", "CREATED"]);

    for a in items {
        table.add_row(vec![
            a["path"].as_str().unwrap_or("-"),
            a["version"].as_str().unwrap_or("-"),
            a["size"].as_str().unwrap_or("-"),
            &a["downloads"]
                .as_i64()
                .map(|n| n.to_string())
                .unwrap_or_else(|| "-".into()),
            a["created_at"].as_str().unwrap_or("-"),
        ]);
    }

    table.to_string()
}

/// Format search results as a table string.
fn format_search_results_table(items: &[serde_json::Value]) -> String {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec!["NAME", "REPOSITORY", "FORMAT", "VERSION", "SIZE"]);

    for item in items {
        table.add_row(vec![
            item["name"].as_str().unwrap_or("-"),
            item["repository"].as_str().unwrap_or("-"),
            item["format"].as_str().unwrap_or("-"),
            item["version"].as_str().unwrap_or("-"),
            item["size"].as_str().unwrap_or("-"),
        ]);
    }

    table.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use serde_json::json;

    // ---- TestCli wrapper for parsing ----

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: ArtifactCommand,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).unwrap()
    }

    fn try_parse(args: &[&str]) -> Result<TestCli, clap::Error> {
        TestCli::try_parse_from(args)
    }

    // ---- Push subcommand parsing ----

    #[test]
    fn parse_push_single_file() {
        let cli = parse(&["test", "push", "my-repo", "package.tar.gz"]);
        if let ArtifactCommand::Push { repo, files, path } = cli.command {
            assert_eq!(repo, "my-repo");
            assert_eq!(files, vec!["package.tar.gz"]);
            assert!(path.is_none());
        } else {
            panic!("Expected ArtifactCommand::Push");
        }
    }

    #[test]
    fn parse_push_multiple_files() {
        let cli = parse(&[
            "test",
            "push",
            "my-repo",
            "file1.jar",
            "file2.jar",
            "file3.jar",
        ]);
        if let ArtifactCommand::Push { repo, files, path } = cli.command {
            assert_eq!(repo, "my-repo");
            assert_eq!(files, vec!["file1.jar", "file2.jar", "file3.jar"]);
            assert!(path.is_none());
        } else {
            panic!("Expected ArtifactCommand::Push");
        }
    }

    #[test]
    fn parse_push_with_path() {
        let cli = parse(&[
            "test",
            "push",
            "my-repo",
            "package.tar.gz",
            "--path",
            "org/pkg/1.0/",
        ]);
        if let ArtifactCommand::Push { repo, files, path } = cli.command {
            assert_eq!(repo, "my-repo");
            assert_eq!(files, vec!["package.tar.gz"]);
            assert_eq!(path.as_deref(), Some("org/pkg/1.0/"));
        } else {
            panic!("Expected ArtifactCommand::Push");
        }
    }

    #[test]
    fn parse_push_glob_pattern() {
        let cli = parse(&["test", "push", "my-repo", "*.tar.gz"]);
        if let ArtifactCommand::Push { repo, files, .. } = cli.command {
            assert_eq!(repo, "my-repo");
            assert_eq!(files, vec!["*.tar.gz"]);
        } else {
            panic!("Expected ArtifactCommand::Push");
        }
    }

    #[test]
    fn parse_push_missing_files_fails() {
        assert!(try_parse(&["test", "push", "my-repo"]).is_err());
    }

    #[test]
    fn parse_push_missing_repo_fails() {
        assert!(try_parse(&["test", "push"]).is_err());
    }

    // ---- Pull subcommand parsing ----

    #[test]
    fn parse_pull() {
        let cli = parse(&["test", "pull", "my-repo", "org/pkg/1.0/pkg.jar"]);
        if let ArtifactCommand::Pull { repo, path, output } = cli.command {
            assert_eq!(repo, "my-repo");
            assert_eq!(path, "org/pkg/1.0/pkg.jar");
            assert!(output.is_none());
        } else {
            panic!("Expected ArtifactCommand::Pull");
        }
    }

    #[test]
    fn parse_pull_with_output() {
        let cli = parse(&[
            "test",
            "pull",
            "my-repo",
            "org/pkg/1.0/pkg.jar",
            "-o",
            "local-pkg.jar",
        ]);
        if let ArtifactCommand::Pull { repo, path, output } = cli.command {
            assert_eq!(repo, "my-repo");
            assert_eq!(path, "org/pkg/1.0/pkg.jar");
            assert_eq!(output.as_deref(), Some("local-pkg.jar"));
        } else {
            panic!("Expected ArtifactCommand::Pull");
        }
    }

    #[test]
    fn parse_pull_with_long_output() {
        let cli = parse(&[
            "test",
            "pull",
            "my-repo",
            "path/to/file",
            "--output",
            "out.bin",
        ]);
        if let ArtifactCommand::Pull { output, .. } = cli.command {
            assert_eq!(output.as_deref(), Some("out.bin"));
        } else {
            panic!("Expected ArtifactCommand::Pull");
        }
    }

    #[test]
    fn parse_pull_missing_path_fails() {
        assert!(try_parse(&["test", "pull", "my-repo"]).is_err());
    }

    #[test]
    fn parse_pull_missing_repo_fails() {
        assert!(try_parse(&["test", "pull"]).is_err());
    }

    // ---- List subcommand parsing ----

    #[test]
    fn parse_list() {
        let cli = parse(&["test", "list", "my-repo"]);
        if let ArtifactCommand::List {
            repo,
            search,
            page,
            per_page,
        } = cli.command
        {
            assert_eq!(repo, "my-repo");
            assert!(search.is_none());
            assert_eq!(page, 1);
            assert_eq!(per_page, 50);
        } else {
            panic!("Expected ArtifactCommand::List");
        }
    }

    #[test]
    fn parse_list_with_search() {
        let cli = parse(&["test", "list", "my-repo", "--search", "log4j"]);
        if let ArtifactCommand::List { search, .. } = cli.command {
            assert_eq!(search.as_deref(), Some("log4j"));
        } else {
            panic!("Expected ArtifactCommand::List");
        }
    }

    #[test]
    fn parse_list_custom_pagination() {
        let cli = parse(&["test", "list", "my-repo", "--page", "3", "--per-page", "25"]);
        if let ArtifactCommand::List { page, per_page, .. } = cli.command {
            assert_eq!(page, 3);
            assert_eq!(per_page, 25);
        } else {
            panic!("Expected ArtifactCommand::List");
        }
    }

    #[test]
    fn parse_list_missing_repo_fails() {
        assert!(try_parse(&["test", "list"]).is_err());
    }

    // ---- Info subcommand parsing ----

    #[test]
    fn parse_info() {
        let cli = parse(&["test", "info", "my-repo", "org/pkg/1.0/pkg.jar"]);
        if let ArtifactCommand::Info { repo, path } = cli.command {
            assert_eq!(repo, "my-repo");
            assert_eq!(path, "org/pkg/1.0/pkg.jar");
        } else {
            panic!("Expected ArtifactCommand::Info");
        }
    }

    #[test]
    fn parse_info_missing_path_fails() {
        assert!(try_parse(&["test", "info", "my-repo"]).is_err());
    }

    #[test]
    fn parse_info_missing_repo_fails() {
        assert!(try_parse(&["test", "info"]).is_err());
    }

    // ---- Delete subcommand parsing ----

    #[test]
    fn parse_delete() {
        let cli = parse(&["test", "delete", "my-repo", "org/pkg/1.0/pkg.jar"]);
        if let ArtifactCommand::Delete { repo, path, yes } = cli.command {
            assert_eq!(repo, "my-repo");
            assert_eq!(path, "org/pkg/1.0/pkg.jar");
            assert!(!yes);
        } else {
            panic!("Expected ArtifactCommand::Delete");
        }
    }

    #[test]
    fn parse_delete_with_yes() {
        let cli = parse(&["test", "delete", "my-repo", "path/to/file", "--yes"]);
        if let ArtifactCommand::Delete { repo, path, yes } = cli.command {
            assert_eq!(repo, "my-repo");
            assert_eq!(path, "path/to/file");
            assert!(yes);
        } else {
            panic!("Expected ArtifactCommand::Delete");
        }
    }

    #[test]
    fn parse_delete_missing_path_fails() {
        assert!(try_parse(&["test", "delete", "my-repo"]).is_err());
    }

    // ---- Search subcommand parsing ----

    #[test]
    fn parse_search() {
        let cli = parse(&["test", "search", "log4j"]);
        if let ArtifactCommand::Search {
            query,
            repo,
            pkg_format,
        } = cli.command
        {
            assert_eq!(query, "log4j");
            assert!(repo.is_none());
            assert!(pkg_format.is_none());
        } else {
            panic!("Expected ArtifactCommand::Search");
        }
    }

    #[test]
    fn parse_search_with_repo_filter() {
        let cli = parse(&["test", "search", "log4j", "--repo", "maven-central"]);
        if let ArtifactCommand::Search { query, repo, .. } = cli.command {
            assert_eq!(query, "log4j");
            assert_eq!(repo.as_deref(), Some("maven-central"));
        } else {
            panic!("Expected ArtifactCommand::Search");
        }
    }

    #[test]
    fn parse_search_with_format_filter() {
        let cli = parse(&["test", "search", "express", "--pkg-format", "npm"]);
        if let ArtifactCommand::Search {
            query, pkg_format, ..
        } = cli.command
        {
            assert_eq!(query, "express");
            assert_eq!(pkg_format.as_deref(), Some("npm"));
        } else {
            panic!("Expected ArtifactCommand::Search");
        }
    }

    #[test]
    fn parse_search_all_options() {
        let cli = parse(&[
            "test",
            "search",
            "flask",
            "--repo",
            "pypi-repo",
            "--pkg-format",
            "pypi",
        ]);
        if let ArtifactCommand::Search {
            query,
            repo,
            pkg_format,
        } = cli.command
        {
            assert_eq!(query, "flask");
            assert_eq!(repo.as_deref(), Some("pypi-repo"));
            assert_eq!(pkg_format.as_deref(), Some("pypi"));
        } else {
            panic!("Expected ArtifactCommand::Search");
        }
    }

    #[test]
    fn parse_search_missing_query_fails() {
        assert!(try_parse(&["test", "search"]).is_err());
    }

    // ---- Copy subcommand parsing ----

    #[test]
    fn parse_copy() {
        let cli = parse(&["test", "copy", "src-repo/path/to/file", "dst-repo"]);
        if let ArtifactCommand::Copy {
            source,
            destination,
            from_instance,
            to_instance,
        } = cli.command
        {
            assert_eq!(source, "src-repo/path/to/file");
            assert_eq!(destination, "dst-repo");
            assert!(from_instance.is_none());
            assert!(to_instance.is_none());
        } else {
            panic!("Expected ArtifactCommand::Copy");
        }
    }

    #[test]
    fn parse_copy_cross_instance() {
        let cli = parse(&[
            "test",
            "copy",
            "src/path",
            "dst/path",
            "--from-instance",
            "staging",
            "--to-instance",
            "prod",
        ]);
        if let ArtifactCommand::Copy {
            source,
            destination,
            from_instance,
            to_instance,
        } = cli.command
        {
            assert_eq!(source, "src/path");
            assert_eq!(destination, "dst/path");
            assert_eq!(from_instance.as_deref(), Some("staging"));
            assert_eq!(to_instance.as_deref(), Some("prod"));
        } else {
            panic!("Expected ArtifactCommand::Copy");
        }
    }

    #[test]
    fn parse_copy_from_instance_only() {
        let cli = parse(&[
            "test",
            "copy",
            "src/path",
            "dst/path",
            "--from-instance",
            "staging",
        ]);
        if let ArtifactCommand::Copy {
            from_instance,
            to_instance,
            ..
        } = cli.command
        {
            assert_eq!(from_instance.as_deref(), Some("staging"));
            assert!(to_instance.is_none());
        } else {
            panic!("Expected ArtifactCommand::Copy");
        }
    }

    #[test]
    fn parse_copy_missing_destination_fails() {
        assert!(try_parse(&["test", "copy", "src/path"]).is_err());
    }

    #[test]
    fn parse_copy_missing_source_fails() {
        assert!(try_parse(&["test", "copy"]).is_err());
    }

    // ---- Error cases ----

    #[test]
    fn parse_no_subcommand_fails() {
        assert!(try_parse(&["test"]).is_err());
    }

    #[test]
    fn parse_unknown_subcommand_fails() {
        assert!(try_parse(&["test", "unknown"]).is_err());
    }

    // ---- Format function tests ----

    #[test]
    fn format_artifacts_table_renders() {
        let items = vec![json!({
            "path": "org/example/lib/1.0.0/lib-1.0.0.jar",
            "version": "1.0.0",
            "size": "2.5 MB",
            "downloads": 150,
            "created_at": "2026-01-15",
        })];
        let table = format_artifacts_table(&items);
        assert!(table.contains("org/example/lib/1.0.0/lib-1.0.0.jar"));
        assert!(table.contains("1.0.0"));
        assert!(table.contains("2.5 MB"));
        assert!(table.contains("150"));
        assert!(table.contains("2026-01-15"));
    }

    #[test]
    fn format_artifacts_table_empty() {
        let items: Vec<serde_json::Value> = vec![];
        let table = format_artifacts_table(&items);
        assert!(table.contains("PATH"));
        assert!(table.contains("VERSION"));
        assert!(table.contains("SIZE"));
        assert!(table.contains("DOWNLOADS"));
    }

    #[test]
    fn format_artifacts_table_missing_version() {
        let items = vec![json!({
            "path": "my-file.tar.gz",
            "size": "10.0 KB",
            "downloads": 5,
            "created_at": "2026-02-01",
        })];
        let table = format_artifacts_table(&items);
        assert!(table.contains("my-file.tar.gz"));
        assert!(table.contains("-")); // missing version
    }

    #[test]
    fn format_artifacts_table_multiple_rows() {
        let items = vec![
            json!({
                "path": "pkg-a/1.0/a.jar",
                "version": "1.0",
                "size": "1.0 MB",
                "downloads": 100,
                "created_at": "2026-01-01",
            }),
            json!({
                "path": "pkg-b/2.0/b.whl",
                "version": "2.0",
                "size": "500.0 KB",
                "downloads": 50,
                "created_at": "2026-01-02",
            }),
        ];
        let table = format_artifacts_table(&items);
        assert!(table.contains("pkg-a/1.0/a.jar"));
        assert!(table.contains("pkg-b/2.0/b.whl"));
        assert!(table.contains("100"));
        assert!(table.contains("50"));
    }

    #[test]
    fn format_search_results_table_renders() {
        let items = vec![json!({
            "name": "log4j-core",
            "repository": "maven-central",
            "format": "maven",
            "version": "2.17.1",
            "size": "1.8 MB",
        })];
        let table = format_search_results_table(&items);
        assert!(table.contains("log4j-core"));
        assert!(table.contains("maven-central"));
        assert!(table.contains("maven"));
        assert!(table.contains("2.17.1"));
        assert!(table.contains("1.8 MB"));
    }

    #[test]
    fn format_search_results_table_empty() {
        let items: Vec<serde_json::Value> = vec![];
        let table = format_search_results_table(&items);
        assert!(table.contains("NAME"));
        assert!(table.contains("REPOSITORY"));
        assert!(table.contains("FORMAT"));
    }

    #[test]
    fn format_search_results_table_missing_optional_fields() {
        let items = vec![json!({
            "name": "my-package",
            "repository": "local-repo",
        })];
        let table = format_search_results_table(&items);
        assert!(table.contains("my-package"));
        assert!(table.contains("local-repo"));
    }

    #[test]
    fn format_search_results_multiple() {
        let items = vec![
            json!({
                "name": "express",
                "repository": "npm-repo",
                "format": "npm",
                "version": "4.18.2",
                "size": "200.0 KB",
            }),
            json!({
                "name": "flask",
                "repository": "pypi-repo",
                "format": "pypi",
                "version": "3.0.0",
                "size": "100.0 KB",
            }),
        ];
        let table = format_search_results_table(&items);
        assert!(table.contains("express"));
        assert!(table.contains("flask"));
        assert!(table.contains("npm"));
        assert!(table.contains("pypi"));
    }

    // ========================================================================
    // Wiremock-based handler tests
    // ========================================================================

    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, ResponseTemplate};

    #[tokio::test]
    async fn handler_list_artifacts_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/repositories/.+/artifacts"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [],
                "pagination": { "page": 1, "per_page": 50, "total": 0_i64, "total_pages": 0 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list("my-repo", None, 1, 50, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_artifacts_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/repositories/.+/artifacts"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{
                    "id": "00000000-0000-0000-0000-000000000001",
                    "path": "org/example/lib/1.0/lib-1.0.jar",
                    "name": "lib",
                    "version": "1.0",
                    "size_bytes": 2621440_i64,
                    "content_type": "application/java-archive",
                    "checksum_sha256": "abc123def456",
                    "download_count": 150_i64,
                    "repository_key": "maven-central",
                    "created_at": "2026-01-15T10:00:00Z"
                }],
                "pagination": { "page": 1, "per_page": 50, "total": 1_i64, "total_pages": 1 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list("maven-central", None, 1, 50, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_artifact_info() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/repositories/.+/artifacts"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{
                    "id": "00000000-0000-0000-0000-000000000001",
                    "path": "org/example/lib/1.0/lib-1.0.jar",
                    "name": "lib",
                    "version": "1.0",
                    "size_bytes": 2621440_i64,
                    "content_type": "application/java-archive",
                    "checksum_sha256": "abc123def456",
                    "download_count": 150_i64,
                    "repository_key": "maven-central",
                    "created_at": "2026-01-15T10:00:00Z"
                }],
                "pagination": { "page": 1, "per_page": 50, "total": 1_i64, "total_pages": 1 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = info("maven-central", "org/example/lib/1.0/lib-1.0.jar", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_artifact_info_not_found() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/repositories/.+/artifacts"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [],
                "pagination": { "page": 1, "per_page": 50, "total": 0_i64, "total_pages": 0 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = info("my-repo", "nonexistent", &global).await;
        assert!(result.is_err());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_search_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/search/advanced"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [],
                "facets": { "formats": [], "repositories": [], "content_types": [] },
                "pagination": { "page": 1, "per_page": 50, "total": 0_i64, "total_pages": 0 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = search("nonexistent", None, None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_search_with_results() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/search/advanced"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{
                    "id": "00000000-0000-0000-0000-000000000001",
                    "name": "log4j-core",
                    "path": "org/apache/logging/log4j/log4j-core/2.17.1/log4j-core-2.17.1.jar",
                    "repository_key": "maven-central",
                    "format": "maven",
                    "version": "2.17.1",
                    "type": "library",
                    "size_bytes": 1887436_i64,
                    "created_at": "2026-01-15T10:00:00Z"
                }],
                "facets": { "formats": [], "repositories": [], "content_types": [] },
                "pagination": { "page": 1, "per_page": 50, "total": 1_i64, "total_pages": 1 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = search("log4j", None, None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_delete_artifact() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path_regex("/api/v1/repositories/.+/artifacts/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;

        // no_input=true in test_global, so no confirmation prompt
        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = delete("my-repo", "path/to/file", true, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_same_instance_copy() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        // Mock for finding the source artifact
        Mock::given(method("GET"))
            .and(path_regex("/api/v1/repositories/.+/artifacts"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{
                    "id": "00000000-0000-0000-0000-000000000099",
                    "path": "pkg/lib-1.0.jar",
                    "name": "lib",
                    "version": "1.0",
                    "size_bytes": 1024_i64,
                    "content_type": "application/java-archive",
                    "checksum_sha256": "abc123",
                    "download_count": 5_i64,
                    "repository_key": "src-repo",
                    "created_at": "2026-01-15T10:00:00Z"
                }],
                "pagination": { "page": 1, "per_page": 1, "total": 1_i64, "total_pages": 1 }
            })))
            .mount(&server)
            .await;

        // Mock for promote_artifact
        Mock::given(method("POST"))
            .and(path_regex(
                "/api/v1/promotion/repositories/.+/artifacts/.+/promote",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "promoted": true,
                "source": "src-repo",
                "target": "dst-repo",
                "policy_violations": [],
                "message": "Artifact promoted"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = same_instance_copy("src-repo", "pkg/lib-1.0.jar", "dst-repo", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    // ---- insta snapshot tests ----

    #[test]
    fn snapshot_artifact_list_json() {
        let items = vec![json!({
            "path": "org/example/lib/1.0.0/lib-1.0.0.jar",
            "version": "1.0.0",
            "size": "2.5 MB",
            "downloads": 150,
            "created_at": "2026-01-15",
        })];
        let output = crate::output::render(&items, &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("artifact_list_json", parsed);
    }

    #[test]
    fn snapshot_artifact_list_table() {
        let items = vec![
            json!({
                "path": "org/example/lib/1.0.0/lib-1.0.0.jar",
                "version": "1.0.0",
                "size": "2.5 MB",
                "downloads": 150,
                "created_at": "2026-01-15",
            }),
            json!({
                "path": "com/mycompany/app/2.0.0/app-2.0.0.war",
                "version": "2.0.0",
                "size": "45.3 MB",
                "downloads": 25,
                "created_at": "2026-02-01",
            }),
        ];
        let table = format_artifacts_table(&items);
        insta::assert_snapshot!("artifact_list_table", table);
    }

    #[test]
    fn snapshot_search_results_json() {
        let items = vec![json!({
            "name": "log4j-core",
            "repository": "maven-central",
            "format": "maven",
            "version": "2.17.1",
            "size": "1.8 MB",
        })];
        let output = crate::output::render(&items, &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("artifact_search_json", parsed);
    }

    #[test]
    fn snapshot_search_results_table() {
        let items = vec![
            json!({
                "name": "log4j-core",
                "repository": "maven-central",
                "format": "maven",
                "version": "2.17.1",
                "size": "1.8 MB",
            }),
            json!({
                "name": "express",
                "repository": "npm-local",
                "format": "npm",
                "version": "4.18.2",
                "size": "200.0 KB",
            }),
        ];
        let table = format_search_results_table(&items);
        insta::assert_snapshot!("artifact_search_table", table);
    }
}
