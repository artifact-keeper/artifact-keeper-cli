//! `ak pkg cran publish`. The name and version come from the file name.

use std::path::PathBuf;

use clap::Subcommand;
use miette::Result;
use reqwest::Method;

use super::wire::{Upload, Wire, publish_file};
use crate::cli::GlobalArgs;

#[derive(Subcommand)]
pub enum CranCommand {
    /// Upload a source package from `R CMD build`
    #[command(after_help = "Examples:\n  ak pkg cran publish my-cran demo_1.0.0.tar.gz")]
    Publish {
        /// Repository key
        repo: String,
        /// The file, named <name>_<version>.tar.gz
        file: PathBuf,
    },
}

pub async fn execute(command: CranCommand, global: &GlobalArgs) -> Result<()> {
    let CranCommand::Publish { repo, file } = command;
    let wire = Wire::new(global)?;
    let upload = Upload::open(&file)?;
    let url = wire.url(&["cran", &repo, "src", "contrib", &upload.name]);
    publish_file(
        &wire,
        wire.request(Method::PUT, url),
        &upload,
        &repo,
        global,
    )
    .await
}
