//! `ak pkg ansible publish`: what `ansible-galaxy collection publish` sends.
//! The namespace, name and version come from the file's name and its `MANIFEST.json`.

use std::path::PathBuf;

use clap::Subcommand;
use miette::Result;
use reqwest::Method;
use reqwest::multipart::Form;

use super::wire::{Upload, Wire, emit};
use crate::cli::GlobalArgs;

#[derive(Subcommand)]
pub enum AnsibleCommand {
    /// Upload a collection from `ansible-galaxy collection build`
    #[command(after_help = "Examples:\n  ak pkg ansible publish my-galaxy acme-demo-1.0.0.tar.gz")]
    Publish {
        /// Repository key
        repo: String,
        /// The <namespace>-<name>-<version>.tar.gz
        file: PathBuf,
    },
}

pub async fn execute(command: AnsibleCommand, global: &GlobalArgs) -> Result<()> {
    let AnsibleCommand::Publish { repo, file } = command;
    let wire = Wire::new(global)?;
    let upload = Upload::open(&file)?;
    let form = Form::new()
        .text("sha256", upload.sha256().await?)
        .part("file", upload.part("application/gzip").await?);
    let url = wire.url(&[
        "ansible",
        &repo,
        "api",
        "v3",
        "artifacts",
        "collections",
        "",
    ]);
    let reply = wire
        .send(
            "upload the collection",
            wire.request(Method::POST, url).multipart(form),
        )
        .await?;
    emit(
        &reply,
        &upload.name,
        &format!("Published {} to {repo}.", upload.name),
        global,
    );
    Ok(())
}
