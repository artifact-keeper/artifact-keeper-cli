//! `ak pkg alpine publish`. The server reads `.PKGINFO` from the package.

use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};
use miette::Result;
use reqwest::Method;

use super::wire::{Upload, Wire, emit};
use crate::cli::GlobalArgs;
use crate::error::AkError;

const CONTENT_TYPE: &str = "application/octet-stream";

#[derive(Clone, Copy, ValueEnum)]
pub enum Endpoint {
    /// POST /alpine/<repo>/upload, with the place in headers
    Upload,
    /// PUT /alpine/<repo>/<branch>/<repository>/<arch>/<file>
    Path,
}

#[derive(Subcommand)]
pub enum AlpineCommand {
    /// Upload an .apk, and have it indexed for apk
    #[command(after_help = "\
Examples:
  ak pkg alpine publish my-apk demo-1.0-r0.apk --branch v3.20 --arch x86_64")]
    Publish {
        /// Repository key
        repo: String,
        /// The .apk file
        file: PathBuf,
        /// Alpine branch
        #[arg(long, default_value = "edge")]
        branch: String,
        /// Repository name within the branch
        #[arg(long, default_value = "main")]
        repository: String,
        /// Architecture. Required with --endpoint path
        #[arg(long)]
        arch: Option<String>,
        /// Which upload route to use
        #[arg(long, value_enum, default_value = "upload")]
        endpoint: Endpoint,
    },
}

pub async fn execute(command: AlpineCommand, global: &GlobalArgs) -> Result<()> {
    let AlpineCommand::Publish {
        repo,
        file,
        branch,
        repository,
        arch,
        endpoint,
    } = command;
    let wire = Wire::new(global)?;
    let upload = Upload::open(&file)?;
    let request = match endpoint {
        Endpoint::Upload => {
            let mut request = wire
                .request(Method::POST, wire.url(&["alpine", &repo, "upload"]))
                .header("X-Package-Filename", &upload.name)
                .header("X-Alpine-Branch", &branch)
                .header("X-Alpine-Repository", &repository);
            if let Some(arch) = &arch {
                request = request.header("X-Alpine-Arch", arch);
            }
            request
        }
        Endpoint::Path => {
            let Some(arch) = &arch else {
                return Err(
                    AkError::ConfigError("--endpoint path needs --arch".to_string()).into(),
                );
            };
            wire.request(
                Method::PUT,
                wire.url(&["alpine", &repo, &branch, &repository, arch, &upload.name]),
            )
        }
    };
    let request = upload.attach(request, CONTENT_TYPE).await?;
    let reply = wire.send("upload the package", request).await?;
    emit(
        &reply,
        &upload.name,
        &format!("Published {} to {repo}.", upload.name),
        global,
    );
    Ok(())
}
