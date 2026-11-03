//! `ak pkg jetbrains publish`: what the Plugin Repository's upload takes.

use std::path::PathBuf;

use clap::Subcommand;
use miette::Result;
use reqwest::Method;
use reqwest::multipart::Form;

use super::wire::{Upload, Wire, emit};
use crate::cli::GlobalArgs;

#[derive(Subcommand)]
pub enum JetbrainsCommand {
    /// Upload a plugin .zip or .jar
    #[command(
        disable_version_flag = true,
        after_help = "\
The server reads the name and version from plugin.xml unless they're given.

Examples:
  ak pkg jetbrains publish my-plugins demo-1.0.0.zip
  ak pkg jetbrains publish my-plugins demo.jar --name com.acme.demo --version 1.0.0"
    )]
    Publish {
        /// Repository key
        repo: String,
        /// The plugin archive
        file: PathBuf,
        /// Plugin name
        #[arg(long)]
        name: Option<String>,
        /// Plugin version
        #[arg(id = "plugin_version", long = "version")]
        version: Option<String>,
    },
}

pub async fn execute(command: JetbrainsCommand, global: &GlobalArgs) -> Result<()> {
    let JetbrainsCommand::Publish {
        repo,
        file,
        name,
        version,
    } = command;
    let wire = Wire::new(global)?;
    let upload = Upload::open(&file)?;
    let mut form = Form::new().part("file", upload.part("application/zip").await?);
    if let Some(name) = name {
        form = form.text("name", name);
    }
    if let Some(version) = version {
        form = form.text("version", version);
    }
    let url = wire.url(&["jetbrains", &repo, "plugin", "uploadPlugin"]);
    let reply = wire
        .send(
            "upload the plugin",
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
