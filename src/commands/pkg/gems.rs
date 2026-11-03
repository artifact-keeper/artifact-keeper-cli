//! `ak pkg gems publish`: what `gem push` sends. The server reads the gemspec.

use std::path::PathBuf;

use clap::Subcommand;
use miette::Result;
use reqwest::Method;

use super::wire::{Upload, Wire, publish_file};
use crate::cli::GlobalArgs;

#[derive(Subcommand)]
pub enum GemsCommand {
    /// Push a .gem, as `gem push` does
    #[command(after_help = "Examples:\n  ak pkg gems publish my-gems demo-1.0.0.gem")]
    Publish {
        /// Repository key
        repo: String,
        /// The .gem file
        file: PathBuf,
    },
}

pub async fn execute(command: GemsCommand, global: &GlobalArgs) -> Result<()> {
    let GemsCommand::Publish { repo, file } = command;
    let wire = Wire::new(global)?;
    let upload = Upload::open(&file)?;
    let request = wire.request(
        Method::POST,
        wire.url(&["gems", &repo, "api", "v1", "gems"]),
    );
    publish_file(&wire, request, &upload, &repo, global).await
}
