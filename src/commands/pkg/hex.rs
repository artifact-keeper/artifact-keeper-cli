//! `ak pkg hex publish`: what `mix hex.publish` sends. The server reads `metadata.config`.

use std::path::PathBuf;

use clap::Subcommand;
use miette::Result;
use reqwest::Method;

use super::wire::{Upload, Wire, publish_file};
use crate::cli::GlobalArgs;

#[derive(Subcommand)]
pub enum HexCommand {
    /// Upload a package tarball from `mix hex.build`
    #[command(after_help = "Examples:\n  ak pkg hex publish my-hex demo-1.0.0.tar")]
    Publish {
        /// Repository key
        repo: String,
        /// The .tar file
        file: PathBuf,
    },
}

pub async fn execute(command: HexCommand, global: &GlobalArgs) -> Result<()> {
    let HexCommand::Publish { repo, file } = command;
    let wire = Wire::new(global)?;
    let upload = Upload::open(&file)?;
    let request = wire.request(Method::POST, wire.url(&["hex", &repo, "publish"]));
    publish_file(&wire, request, &upload, &repo, global).await
}
