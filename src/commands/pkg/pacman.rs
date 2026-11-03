//! `ak pkg pacman`. The server reads `.PKGINFO` from the package, and takes a package's
//! detached `.sig` the same way as the package.

use std::path::PathBuf;

use clap::Subcommand;
use miette::Result;
use reqwest::Method;

use super::wire::{Upload, Wire, emit};
use crate::cli::GlobalArgs;
use crate::commands::helpers::confirm_action;

const CONTENT_TYPE: &str = "application/octet-stream";

#[derive(Subcommand)]
pub enum PacmanCommand {
    /// Upload a package, or its detached .sig once the package is there
    #[command(after_help = "\
Examples:
  ak pkg pacman publish my-arch demo-1.0-1-x86_64.pkg.tar.zst
  ak pkg pacman publish my-arch demo-1.0-1-x86_64.pkg.tar.zst.sig")]
    Publish {
        /// Repository key
        repo: String,
        /// The package, or its .sig
        file: PathBuf,
    },
    /// Delete a package
    Delete {
        /// Repository key
        repo: String,
        /// Architecture directory, such as x86_64
        arch: String,
        /// Package file name
        filename: String,
        /// Don't ask for confirmation
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

pub async fn execute(command: PacmanCommand, global: &GlobalArgs) -> Result<()> {
    let wire = Wire::new(global)?;
    match command {
        PacmanCommand::Publish { repo, file } => {
            let upload = Upload::open(&file)?;
            let request = upload
                .attach(
                    wire.request(Method::PUT, wire.url(&["pacman", &repo, &upload.name])),
                    CONTENT_TYPE,
                )
                .await?;
            let reply = wire
                .send_since_1_11("upload the package", "pkg pacman publish", global, request)
                .await?;
            emit(
                &reply,
                &upload.name,
                &format!("Published {} to {repo}.", upload.name),
                global,
            );
        }
        PacmanCommand::Delete {
            repo,
            arch,
            filename,
            yes,
        } => {
            if !confirm_action(
                &format!("Delete {filename} from {repo}?"),
                yes,
                global.no_input,
            )? {
                return Ok(());
            }
            let reply = wire
                .send(
                    "delete the package",
                    wire.request(
                        Method::DELETE,
                        wire.url(&["pacman", &repo, &arch, &filename]),
                    ),
                )
                .await?;
            emit(&reply, &filename, &format!("Deleted {filename}."), global);
        }
    }
    Ok(())
}
