//! `ak pkg terraform`. A module and a provider are each one archive at a fixed URL.

use std::path::PathBuf;

use clap::Subcommand;
use miette::Result;
use reqwest::Method;

use super::wire::{Upload, Wire, publish_file};
use crate::cli::GlobalArgs;

#[derive(Subcommand)]
pub enum TerraformCommand {
    /// Upload a module archive, a .tar.gz or .zip
    #[command(
        name = "publish-module",
        after_help = "Examples:\n  ak pkg terraform publish-module my-tf acme vpc aws 1.0.0 vpc.tar.gz"
    )]
    PublishModule {
        /// Repository key
        repo: String,
        /// Module namespace
        namespace: String,
        /// Module name
        name: String,
        /// Provider the module is for
        provider: String,
        /// Version
        #[arg(id = "module_version")]
        version: String,
        /// The archive
        file: PathBuf,
    },
    /// Upload a provider build for one platform, a .zip
    #[command(
        name = "publish-provider",
        after_help = "Examples:\n  ak pkg terraform publish-provider my-tf acme demo 1.0.0 linux amd64 provider.zip"
    )]
    PublishProvider {
        /// Repository key
        repo: String,
        /// Provider namespace
        namespace: String,
        /// Provider type
        #[arg(id = "type_name")]
        type_name: String,
        /// Version
        #[arg(id = "provider_version")]
        version: String,
        /// Operating system
        os: String,
        /// Architecture
        arch: String,
        /// The .zip
        file: PathBuf,
    },
}

pub async fn execute(command: TerraformCommand, global: &GlobalArgs) -> Result<()> {
    let wire = Wire::new(global)?;
    match command {
        TerraformCommand::PublishModule {
            repo,
            namespace,
            name,
            provider,
            version,
            file,
        } => {
            let upload = Upload::open(&file)?;
            let url = wire.url(&[
                "terraform",
                &repo,
                "v1",
                "modules",
                &namespace,
                &name,
                &provider,
                &version,
            ]);
            publish_file(
                &wire,
                wire.request(Method::PUT, url),
                &upload,
                &repo,
                global,
            )
            .await
        }
        TerraformCommand::PublishProvider {
            repo,
            namespace,
            type_name,
            version,
            os,
            arch,
            file,
        } => {
            let upload = Upload::open(&file)?;
            let url = wire.url(&[
                "terraform",
                &repo,
                "v1",
                "providers",
                &namespace,
                &type_name,
                &version,
                &os,
                &arch,
            ]);
            publish_file(
                &wire,
                wire.request(Method::PUT, url),
                &upload,
                &repo,
                global,
            )
            .await
        }
    }
}
