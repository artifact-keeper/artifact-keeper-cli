//! `ak pkg chef publish`: what `knife supermarket share` sends. The server needs the
//! cookbook's name and version in a JSON field beside the tarball, so they're read from
//! `<cookbook>/metadata.json` inside it.

use std::path::PathBuf;

use clap::Subcommand;
use miette::Result;
use reqwest::Method;
use reqwest::multipart::Form;
use serde_json::{Value, json};

use super::archive::tar_gz_entry;
use super::wire::{Upload, Wire, emit};
use crate::cli::GlobalArgs;
use crate::error::AkError;

#[derive(Subcommand)]
pub enum ChefCommand {
    /// Upload a cookbook tarball
    #[command(
        disable_version_flag = true,
        after_help = "\
The name and version come from metadata.json in the tarball. A cookbook with only a
metadata.rb needs --name and --version.

Examples:
  ak pkg chef publish my-chef demo-1.0.0.tar.gz
  ak pkg chef publish my-chef demo.tgz --name demo --version 1.0.0"
    )]
    Publish {
        /// Repository key
        repo: String,
        /// The cookbook's .tar.gz
        file: PathBuf,
        /// Cookbook name, instead of the one in metadata.json
        #[arg(long)]
        name: Option<String>,
        /// Version, instead of the one in metadata.json
        #[arg(id = "cookbook_version", long = "version")]
        version: Option<String>,
    },
}

pub async fn execute(command: ChefCommand, global: &GlobalArgs) -> Result<()> {
    let ChefCommand::Publish {
        repo,
        file,
        name,
        version,
    } = command;
    let wire = Wire::new(global)?;
    let upload = Upload::open(&file)?;
    let metadata: Value = tar_gz_entry(&file, |parts| {
        parts.len() == 2 && parts[1] == "metadata.json"
    })?
    .and_then(|(_, content)| serde_json::from_slice(&content).ok())
    .unwrap_or(Value::Null);
    let from_file = |key: &str| metadata[key].as_str().map(str::to_string);
    let (Some(name), Some(version)) = (
        name.or_else(|| from_file("name")),
        version.or_else(|| from_file("version")),
    ) else {
        return Err(AkError::Usage(format!(
            "{} has no metadata.json with a name and version. Give --name and --version",
            file.display()
        ))
        .into());
    };
    let cookbook = json!({"name": name, "version": version, "metadata": metadata});
    let form = Form::new()
        .text("cookbook", cookbook.to_string())
        .part("tarball", upload.part("application/gzip").await?);
    let url = wire.url(&["chef", &repo, "api", "v1", "cookbooks"]);
    let reply = wire
        .send(
            "upload the cookbook",
            wire.request(Method::POST, url).multipart(form),
        )
        .await?;
    emit(
        &reply,
        &format!("{name}-{version}"),
        &format!("Published {name} {version} to {repo}."),
        global,
    );
    Ok(())
}
