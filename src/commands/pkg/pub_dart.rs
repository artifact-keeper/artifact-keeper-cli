//! `ak pkg pub publish`: what `dart pub publish` does. It's three requests: ask where to
//! upload, send the file there as a form, and call the URL that gives back to finish.

use std::path::PathBuf;

use clap::Subcommand;
use miette::Result;
use reqwest::multipart::Form;
use reqwest::{Method, Url};

use super::wire::{Upload, Wire, emit};
use crate::cli::GlobalArgs;
use crate::error::AkError;

#[derive(Subcommand)]
pub enum PubCommand {
    /// Upload a package archive, as `dart pub publish` does
    #[command(after_help = "\
The archive is a .tar.gz with pubspec.yaml at its top level.

Examples:
  ak pkg pub publish my-pub demo-1.0.0.tar.gz")]
    Publish {
        /// Repository key
        repo: String,
        /// The .tar.gz
        file: PathBuf,
    },
}

pub async fn execute(command: PubCommand, global: &GlobalArgs) -> Result<()> {
    let PubCommand::Publish { repo, file } = command;
    let wire = Wire::new(global)?;
    let upload = Upload::open(&file)?;
    let base = ["pub", repo.as_str(), "api", "packages", "versions"];
    // The URLs in the replies are the server's, built from a header it was sent, so
    // they may not say how we reach it. The routes are fixed, so use those.
    let start = wire.url(&[&base[..], &["new"]].concat());
    wire.send(
        "start the upload",
        wire.request(Method::GET, start)
            .header(reqwest::header::ACCEPT, "application/vnd.pub.v2+json"),
    )
    .await?;
    let form = Form::new().part("file", upload.part("application/gzip").await?);
    let target: Url = wire.url(&[&base[..], &["newUpload"]].concat());
    wire.send(
        "upload the package",
        wire.request(Method::POST, target).multipart(form),
    )
    .await?;
    let finish = wire.url(&[&base[..], &["newUploadFinish"]].concat());
    let reply = wire
        .send(
            "finish the upload",
            wire.request(Method::GET, finish)
                .header(reqwest::header::ACCEPT, "application/vnd.pub.v2+json"),
        )
        .await
        .map_err(|e| AkError::ServerError(format!("The package was sent, but: {e}")))?;
    emit(
        &reply,
        &upload.name,
        &format!("Published {} to {repo}.", upload.name),
        global,
    );
    Ok(())
}
