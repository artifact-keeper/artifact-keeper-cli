//! `ak pkg vscode`: publishing an extension, and the gallery's query API.

use std::io::Read;
use std::path::{Path, PathBuf};

use clap::Subcommand;
use miette::Result;
use reqwest::Method;
use serde_json::Value;

use super::wire::{Upload, Wire, publish_file};
use crate::cli::GlobalArgs;
use crate::commands::helpers::read_inline_or_file;
use crate::error::AkError;

#[derive(Subcommand)]
pub enum VscodeCommand {
    /// Upload a .vsix. The server reads its manifest
    #[command(after_help = "Examples:\n  ak pkg vscode publish my-vsx demo-1.0.0.vsix")]
    Publish {
        /// Repository key
        repo: String,
        /// The .vsix file
        file: PathBuf,
    },
    /// Send a gallery query, as VS Code does when it searches
    #[command(after_help = "\
A query needs the gallery's own Accept header, which this adds. Only a public repository
answers.

Examples:
  ak pkg vscode query my-vsx --body '{\"filters\":[{\"criteria\":[{\"filterType\":10,\"value\":\"demo\"}]}],\"flags\":0}'")]
    Query {
        /// Repository key
        repo: String,
        /// JSON body: the text itself, @file, or @- for stdin
        #[arg(long)]
        body: String,
    },
}

/// The publisher, name and version in `extension/package.json`. A file that doesn't have
/// them gets the server's own verdict, which is better than a guess here.
fn read_identity(file: &Path) -> Option<(String, String, String)> {
    let opened = std::fs::File::open(file).ok()?;
    let mut archive = zip::ZipArchive::new(opened).ok()?;
    let mut entry = archive.by_name("extension/package.json").ok()?;
    let mut content = Vec::new();
    entry.read_to_end(&mut content).ok()?;
    let package: Value = serde_json::from_slice(&content).ok()?;
    let field = |key: &str| package[key].as_str().map(str::to_string);
    Some((field("publisher")?, field("name")?, field("version")?))
}

pub async fn execute(command: VscodeCommand, global: &GlobalArgs) -> Result<()> {
    let wire = Wire::new(global)?;
    match command {
        VscodeCommand::Publish { repo, file } => {
            let upload = Upload::open(&file)?;
            let url = wire.url(&["vscode", &repo, "api", "extensions"]);
            let mut request = wire.request(Method::POST, url);
            // A 1.11 server reads the .vsix. An older one needs to be told.
            if let Some((publisher, name, version)) = read_identity(&file) {
                request = request
                    .header("x-publisher", publisher)
                    .header("x-extension-name", name)
                    .header("x-extension-version", version);
            }
            publish_file(&wire, request, &upload, &repo, global).await
        }
        VscodeCommand::Query { repo, body } => {
            let body = read_inline_or_file(&body, "--body")?;
            let parsed: Value = serde_json::from_slice(&body)
                .map_err(|e| AkError::Usage(format!("--body isn't JSON: {e}")))?;
            let url = wire.url(&["vscode", &repo, "gallery", "extensionquery"]);
            let reply = wire
                .send_since_1_11(
                    "send the query",
                    "pkg vscode query",
                    global,
                    wire.request(Method::POST, url)
                        .header(
                            reqwest::header::ACCEPT,
                            "application/json;api-version=3.0-preview.1",
                        )
                        .json(&parsed),
                )
                .await?;
            println!("{}", String::from_utf8_lossy(&reply.body).trim());
            Ok(())
        }
    }
}
