//! `ak pkg composer publish`. The server reads `composer.json` from the archive. It has
//! no client of its own to imitate: this registry's upload route takes POST or PUT.

use std::path::PathBuf;

use clap::Subcommand;
use miette::Result;
use reqwest::Method;

use super::wire::{Upload, Wire, publish_file};
use crate::cli::GlobalArgs;

#[derive(Subcommand)]
pub enum ComposerCommand {
    /// Upload a package archive with composer.json inside
    #[command(after_help = "Examples:\n  ak pkg composer publish my-composer demo-1.0.0.zip")]
    Publish {
        /// Repository key
        repo: String,
        /// The .zip or .tar.gz
        file: PathBuf,
        /// Send with PUT, rather than POST
        #[arg(long)]
        put: bool,
    },
}

pub async fn execute(command: ComposerCommand, global: &GlobalArgs) -> Result<()> {
    let ComposerCommand::Publish { repo, file, put } = command;
    let wire = Wire::new(global)?;
    let upload = Upload::open(&file)?;
    let method = if put { Method::PUT } else { Method::POST };
    let request = wire.request(method, wire.url(&["composer", &repo, "api", "packages"]));
    publish_file(&wire, request, &upload, &repo, global).await
}
