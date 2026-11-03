//! `ak pkg nuget publish`: what `dotnet nuget push` sends.

use std::path::PathBuf;

use clap::Subcommand;
use miette::Result;
use reqwest::Method;
use reqwest::multipart::Form;

use super::wire::{Upload, Wire, emit};
use crate::cli::GlobalArgs;

#[derive(Subcommand)]
pub enum NugetCommand {
    /// Push a .nupkg, as `dotnet nuget push` does
    #[command(after_help = "\
Examples:
  ak pkg nuget publish my-nuget bin/Release/Demo.1.0.0.nupkg")]
    Publish {
        /// Repository key
        repo: String,
        /// The .nupkg file
        file: PathBuf,
    },
}

pub async fn execute(command: NugetCommand, global: &GlobalArgs) -> Result<()> {
    let NugetCommand::Publish { repo, file } = command;
    let wire = Wire::new(global)?;
    let upload = Upload::open(&file)?;
    let form = Form::new().part("package", upload.part("application/octet-stream").await?);
    let url = wire.url(&["nuget", &repo, "api", "v2", "package"]);
    let reply = wire
        .send(
            "push the package",
            wire.request(Method::PUT, url).multipart(form),
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
