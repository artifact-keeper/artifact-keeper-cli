//! `ak pkg bazel publish`. A module version in a registry is a few files in one
//! directory. The server generates `metadata.json` from what's published.

use std::path::PathBuf;

use clap::Subcommand;
use miette::Result;
use reqwest::Method;

use super::wire::{Upload, Wire, emit};
use crate::cli::GlobalArgs;

#[derive(Subcommand)]
pub enum BazelCommand {
    /// Upload a module version's files: MODULE.bazel, source.json and any others
    #[command(after_help = "\
Examples:
  ak pkg bazel publish my-bazel demo 1.0.0 MODULE.bazel source.json")]
    Publish {
        /// Repository key
        repo: String,
        /// Module name
        name: String,
        /// Module version
        #[arg(id = "module_version")]
        version: String,
        /// The files, stored under their own names
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },
}

pub async fn execute(command: BazelCommand, global: &GlobalArgs) -> Result<()> {
    let BazelCommand::Publish {
        repo,
        name,
        version,
        files,
    } = command;
    let wire = Wire::new(global)?;
    // All of them are readable before the first is sent.
    let uploads = files
        .iter()
        .map(|file| Upload::open(file))
        .collect::<Result<Vec<_>>>()?;
    for upload in &uploads {
        let url = wire.url(&["bazel", &repo, "modules", &name, &version, &upload.name]);
        let request = upload
            .attach(wire.request(Method::PUT, url), "application/octet-stream")
            .await?;
        let reply = wire
            .send_since_1_11("upload the file", "pkg bazel publish", global, request)
            .await?;
        emit(
            &reply,
            &upload.name,
            &format!("Published {} for {name} {version}.", upload.name),
            global,
        );
    }
    Ok(())
}
