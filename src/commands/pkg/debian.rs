//! `ak pkg debian publish`. The server reads the control file from the `.deb`.

use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};
use miette::Result;
use reqwest::Method;

use super::wire::{Upload, Wire, emit};
use crate::cli::GlobalArgs;
use crate::error::AkError;

const CONTENT_TYPE: &str = "application/vnd.debian.binary-package";

#[derive(Clone, Copy, ValueEnum)]
pub enum Endpoint {
    /// PUT /debian/<repo>/pool/<component>/<prefix>/<name>/<file>, as `dput` and curl do
    Pool,
    /// POST /debian/<repo>/upload, with the file name in a header. Always component main
    Upload,
}

#[derive(Subcommand)]
pub enum DebianCommand {
    /// Upload a .deb, and have it indexed for apt
    #[command(after_help = "\
Examples:
  ak pkg debian publish my-apt demo_1.0_amd64.deb
  ak pkg debian publish my-apt demo_1.0_amd64.deb --component contrib")]
    Publish {
        /// Repository key
        repo: String,
        /// The .deb, named <name>_<version>_<arch>.deb
        file: PathBuf,
        /// Archive component
        #[arg(long, default_value = "main", conflicts_with = "endpoint")]
        component: String,
        /// Which upload route to use
        #[arg(long, value_enum, default_value = "pool")]
        endpoint: Endpoint,
    },
}

pub async fn execute(command: DebianCommand, global: &GlobalArgs) -> Result<()> {
    let DebianCommand::Publish {
        repo,
        file,
        component,
        endpoint,
    } = command;
    let wire = Wire::new(global)?;
    let upload = Upload::open(&file)?;
    let name = package_name(&upload.name)?;
    let request = match endpoint {
        Endpoint::Pool => wire.request(
            Method::PUT,
            wire.url(&[
                "debian",
                &repo,
                "pool",
                &component,
                pool_prefix(name),
                name,
                &upload.name,
            ]),
        ),
        Endpoint::Upload => wire
            .request(Method::POST, wire.url(&["debian", &repo, "upload"]))
            .header("X-Filename", &upload.name),
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

/// `demo` of `demo_1.0_amd64.deb`.
fn package_name(file: &str) -> Result<&str> {
    match file
        .strip_suffix(".deb")
        .map(|stem| stem.split('_').collect::<Vec<_>>())
    {
        Some(parts) if parts.len() == 3 && parts.iter().all(|p| !p.is_empty()) => {
            Ok(file.split('_').next().unwrap_or_default())
        }
        _ => Err(AkError::Usage(format!(
            "`{file}` isn't named <name>_<version>_<arch>.deb, which the server needs"
        ))
        .into()),
    }
}

/// The pool's directory for a package: `d` for demo, `libf` for libfoo.
fn pool_prefix(name: &str) -> &str {
    if name.starts_with("lib") && name.len() > 4 {
        &name[..4]
    } else {
        name.get(..1).unwrap_or("_")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_paths_follow_debian_layout() {
        assert_eq!(pool_prefix("demo"), "d");
        assert_eq!(pool_prefix("libfoo"), "libf");
        assert_eq!(pool_prefix("lib"), "l");
    }

    #[test]
    fn the_file_name_has_to_have_three_parts() {
        assert_eq!(package_name("demo_1.0_amd64.deb").unwrap(), "demo");
        assert!(package_name("demo-1.0.deb").is_err());
        assert!(package_name("demo_1.0_amd64.rpm").is_err());
    }
}
