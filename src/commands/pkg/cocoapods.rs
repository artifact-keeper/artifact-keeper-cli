//! `ak pkg cocoapods publish`. A pod is a `.tar.gz` holding its `.podspec.json`, which
//! the server reads.

use std::path::PathBuf;

use clap::Subcommand;
use miette::Result;
use reqwest::Method;

use super::wire::{Upload, Wire, publish_file};
use crate::cli::GlobalArgs;

#[derive(Subcommand)]
pub enum CocoapodsCommand {
    /// Upload a pod archive with its .podspec.json inside
    #[command(after_help = "Examples:\n  ak pkg cocoapods publish my-pods Demo-1.0.0.tar.gz")]
    Publish {
        /// Repository key
        repo: String,
        /// The .tar.gz
        file: PathBuf,
    },
}

pub async fn execute(command: CocoapodsCommand, global: &GlobalArgs) -> Result<()> {
    let CocoapodsCommand::Publish { repo, file } = command;
    let wire = Wire::new(global)?;
    let upload = Upload::open(&file)?;
    let request = wire.request(Method::POST, wire.url(&["cocoapods", &repo, "pods"]));
    publish_file(&wire, request, &upload, &repo, global).await
}
