//! `ak admin diag`: operator debugging routes. They're in the server only when
//! it's built with its `profiling` feature, and not in the OpenAPI spec, so they
//! go over raw HTTP.

use std::path::{Path, PathBuf};

use clap::Subcommand;
use miette::{IntoDiagnostic, Result};

use crate::cli::GlobalArgs;
use crate::commands::client::{raw_http_client, resolve_base_url_and_auth};
use crate::commands::helpers::raw_err;
use crate::error::AkError;
use crate::output::{self, OutputFormat, format_bytes};

#[derive(Subcommand)]
pub enum DiagCommand {
    /// Show the server's jemalloc memory statistics
    Memory,

    /// Save a heap profile, or turn profiling on or off
    HeapProfile {
        /// Turn profiling on, without saving a profile
        #[arg(long, conflicts_with_all = ["deactivate", "output"])]
        activate: bool,

        /// Turn profiling off, without saving a profile
        #[arg(long, conflicts_with = "output")]
        deactivate: bool,

        /// Where to save the profile. `-` writes to stdout
        #[arg(short, long, default_value = "heap.prof")]
        output: PathBuf,
    },
}

impl DiagCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Memory => memory(global).await,
            Self::HeapProfile {
                activate,
                deactivate,
                output,
            } => {
                if activate || deactivate {
                    let query = if activate { "activate" } else { "deactivate" };
                    let body = get("heap-profile", &[(query, "true")], global).await?;
                    let message = String::from_utf8_lossy(&body);
                    if matches!(global.format, OutputFormat::Quiet) {
                        return Ok(());
                    }
                    eprintln!("{}", output::sanitize_terminal(message.trim()));
                    Ok(())
                } else {
                    let body = get("heap-profile", &[], global).await?;
                    save_profile(&body, &output)
                }
            }
        }
    }
}

/// GET one of the routes. A 404 means the server doesn't have them, and its own
/// message for that names a repository, so say what's really wrong.
async fn get(route: &str, query: &[(&str, &str)], global: &GlobalArgs) -> Result<Vec<u8>> {
    let (base_url, auth_header) = resolve_base_url_and_auth(global)?;
    let url = format!("{}/api/v1/admin/{route}", base_url.trim_end_matches('/'));
    let resp = raw_http_client()?
        .get(&url)
        .header(reqwest::header::AUTHORIZATION, auth_header)
        .query(query)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to get {route}: {e}")))?;
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(AkError::ServerError(format!(
            "This server has no {route} route. It exists only in a server built with the \
             `profiling` feature."
        ))
        .into());
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(raw_err(&format!("Failed to get {route}"), status, &body).into());
    }
    Ok(resp.bytes().await.into_diagnostic()?.to_vec())
}

fn save_profile(body: &[u8], path: &Path) -> Result<()> {
    if path == Path::new("-") {
        use std::io::Write;
        return std::io::stdout().write_all(body).into_diagnostic();
    }
    std::fs::write(path, body)
        .map_err(|e| AkError::ConfigError(format!("Couldn't write {}: {e}", path.display())))?;
    eprintln!(
        "Saved heap profile to {} ({}).",
        path.display(),
        format_bytes(i64::try_from(body.len()).unwrap_or(i64::MAX))
    );
    Ok(())
}

async fn memory(global: &GlobalArgs) -> Result<()> {
    let body = get("memory-stats", &[], global).await?;
    let stats: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| AkError::ServerError(format!("Failed to parse memory-stats response: {e}")))?;
    if matches!(global.format, OutputFormat::Quiet) {
        if let Some(allocated) = stats["allocated_bytes"].as_i64() {
            println!("{allocated}");
        }
        return Ok(());
    }
    println!(
        "{}",
        output::render_raw(
            Some(&body),
            &stats,
            &global.format,
            Some(memory_table(&stats))
        )
    );
    Ok(())
}

fn memory_table(stats: &serde_json::Value) -> String {
    let mut lines = Vec::new();
    if let Some(fields) = stats.as_object() {
        for (name, value) in fields {
            let shown = match (name.strip_suffix("_bytes"), value.as_i64()) {
                (Some(_), Some(bytes)) => format_bytes(bytes),
                _ => value
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| value.to_string()),
            };
            lines.push(format!("{name}: {shown}"));
        }
    }
    lines.join("\n")
}
