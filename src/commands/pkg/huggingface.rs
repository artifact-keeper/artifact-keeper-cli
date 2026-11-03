//! `ak pkg huggingface upload`. One file at a time, whose name goes in a header.

use std::path::PathBuf;

use clap::Subcommand;
use miette::Result;
use reqwest::Method;

use super::wire::{Upload, Wire, emit};
use crate::cli::GlobalArgs;

#[derive(Subcommand)]
pub enum HuggingfaceCommand {
    /// Upload a file to a model
    #[command(after_help = "\
A model is `name`, or `namespace/name`, and each goes to its own route.

Examples:
  ak pkg huggingface upload my-hf acme/demo model.safetensors
  ak pkg huggingface upload my-hf demo config.json --revision v1 --filename subdir/config.json")]
    Upload {
        /// Repository key
        repo: String,
        /// Model: name, or namespace/name
        model: String,
        /// The file
        file: PathBuf,
        /// Revision
        #[arg(long, default_value = "main")]
        revision: String,
        /// Name in the model, instead of the file's own
        #[arg(long)]
        filename: Option<String>,
    },
}

pub async fn execute(command: HuggingfaceCommand, global: &GlobalArgs) -> Result<()> {
    let HuggingfaceCommand::Upload {
        repo,
        model,
        file,
        revision,
        filename,
    } = command;
    let wire = Wire::new(global)?;
    let upload = Upload::open(&file)?;
    let name = filename.unwrap_or_else(|| upload.name.clone());
    let mut segments = vec!["huggingface", repo.as_str(), "api", "models"];
    segments.extend(model.split('/'));
    segments.extend(["upload", revision.as_str()]);
    let request = upload
        .attach(
            wire.request(Method::POST, wire.url(&segments))
                .header("x-filename", &name),
            "application/octet-stream",
        )
        .await?;
    let reply = wire.send("upload the file", request).await?;
    emit(
        &reply,
        &name,
        &format!("Published {name} to {model} in {repo}."),
        global,
    );
    Ok(())
}
