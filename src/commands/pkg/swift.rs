//! `ak pkg swift publish`: what `swift package-registry publish` sends, a multipart form
//! with the source archive and a metadata document.

use std::path::PathBuf;

use clap::Subcommand;
use miette::Result;
use reqwest::Method;
use reqwest::multipart::{Form, Part};

use super::wire::{Upload, Wire, emit};
use crate::cli::GlobalArgs;
use crate::commands::helpers::read_inline_or_file;

#[derive(Subcommand)]
pub enum SwiftCommand {
    /// Upload a source archive, from `swift package archive-source`
    #[command(after_help = "\
Examples:
  ak pkg swift publish my-swift acme Demo 1.0.0 Demo.zip
  ak pkg swift publish my-swift acme Demo 1.0.0 Demo.zip --metadata @metadata.json")]
    Publish {
        /// Repository key
        repo: String,
        /// Package scope
        scope: String,
        /// Package name
        name: String,
        /// Version
        #[arg(id = "package_version")]
        version: String,
        /// The .zip
        file: PathBuf,
        /// Release metadata JSON: the text itself, @file, or @- for stdin
        #[arg(long)]
        metadata: Option<String>,
    },
}

pub async fn execute(command: SwiftCommand, global: &GlobalArgs) -> Result<()> {
    let SwiftCommand::Publish {
        repo,
        scope,
        name,
        version,
        file,
        metadata,
    } = command;
    let wire = Wire::new(global)?;
    let upload = Upload::open(&file)?;
    let mut form = Form::new().part("source-archive", upload.part("application/zip").await?);
    if let Some(metadata) = metadata {
        let body = read_inline_or_file(&metadata, "--metadata")?;
        let part = Part::bytes(body)
            .mime_str("application/json")
            .map_err(|e| crate::error::AkError::Usage(e.to_string()))?;
        form = form.part("metadata", part);
    }
    let url = wire.url(&["swift", &repo, &scope, &name, &version]);
    let reply = wire
        .send(
            "upload the release",
            wire.request(Method::PUT, url)
                .header(
                    reqwest::header::ACCEPT,
                    "application/vnd.swift.registry.v1+json",
                )
                .multipart(form),
        )
        .await?;
    let id = format!("{scope}.{name}@{version}");
    emit(&reply, &id, &format!("Published {id} to {repo}."), global);
    Ok(())
}
