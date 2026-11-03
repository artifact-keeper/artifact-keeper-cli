//! `ak pkg rpm publish`. The server reads the name and version from the RPM's header.

use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};
use miette::Result;
use reqwest::Method;

use super::wire::{Upload, Wire, emit, split_path};
use crate::cli::GlobalArgs;

const CONTENT_TYPE: &str = "application/x-rpm";

#[derive(Clone, Copy, ValueEnum)]
pub enum Endpoint {
    /// PUT /rpm/<repo>/packages/<file>
    Packages,
    /// POST /rpm/<repo>/upload, with the file name in a header
    Upload,
}

#[derive(Subcommand)]
pub enum RpmCommand {
    /// Upload an .rpm, and have it indexed in the repository's repodata
    #[command(after_help = "\
A repository with a repodata depth keeps its directory layout. Use --path there to
say where in the tree the file goes.

Examples:
  ak pkg rpm publish my-rpm demo-1.0-1.x86_64.rpm
  ak pkg rpm publish my-rpm demo-1.0-1.x86_64.rpm --path 9/x86_64/demo-1.0-1.x86_64.rpm")]
    Publish {
        /// Repository key
        repo: String,
        /// The .rpm file
        file: PathBuf,
        /// Which upload route to use
        #[arg(long, value_enum, default_value = "packages", conflicts_with = "path")]
        endpoint: Endpoint,
        /// Path in the repository, for one with a repodata depth: PUT /rpm/<repo>/<path>
        #[arg(long)]
        path: Option<String>,
    },
}

pub async fn execute(command: RpmCommand, global: &GlobalArgs) -> Result<()> {
    let RpmCommand::Publish {
        repo,
        file,
        endpoint,
        path,
    } = command;
    let wire = Wire::new(global)?;
    let upload = Upload::open(&file)?;
    let request = if let Some(path) = &path {
        let mut segments = vec!["rpm", repo.as_str()];
        segments.extend(split_path(path, "--path")?);
        wire.request(Method::PUT, wire.url(&segments))
    } else {
        match endpoint {
            Endpoint::Packages => wire.request(
                Method::PUT,
                wire.url(&["rpm", &repo, "packages", &upload.name]),
            ),
            Endpoint::Upload => wire
                .request(Method::POST, wire.url(&["rpm", &repo, "upload"]))
                .header("X-Package-Filename", &upload.name),
        }
    };
    let request = upload.attach(request, CONTENT_TYPE).await?;
    let reply = wire.send("upload the RPM", request).await?;
    emit(
        &reply,
        &upload.name,
        &format!("Published {} to {repo}.", upload.name),
        global,
    );
    Ok(())
}
