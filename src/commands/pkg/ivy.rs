//! `ak pkg ivy publish`: an Ivy layout, which sbt and Ant read.
//! `<org>/<module>/<revision>/ivy-<revision>.xml` and
//! `<org>/<module>/<revision>/<type>s/<artifact>-<revision>.<ext>`.

use std::path::PathBuf;

use clap::Subcommand;
use miette::Result;
use reqwest::Method;

use super::wire::{Upload, Wire, publish_file};
use crate::cli::GlobalArgs;
use crate::error::AkError;

#[derive(Subcommand)]
pub enum IvyCommand {
    /// Upload an artifact, or with --descriptor an ivy.xml
    #[command(after_help = "\
Examples:
  ak pkg ivy publish my-ivy demo.jar --org com.acme --module demo --revision 1.0.0
  ak pkg ivy publish my-ivy ivy.xml --descriptor --org com.acme --module demo --revision 1.0.0")]
    Publish {
        /// Repository key
        repo: String,
        /// The file
        file: PathBuf,
        /// Organisation
        #[arg(long)]
        org: String,
        /// Module
        #[arg(long)]
        module: String,
        /// Revision
        #[arg(long)]
        revision: String,
        /// The file is the module's ivy.xml
        #[arg(long)]
        descriptor: bool,
        /// Artifact type, which sets the directory. Default: the file's extension
        #[arg(long = "type", conflicts_with = "descriptor")]
        kind: Option<String>,
    },
}

pub async fn execute(command: IvyCommand, global: &GlobalArgs) -> Result<()> {
    let IvyCommand::Publish {
        repo,
        file,
        org,
        module,
        revision,
        descriptor,
        kind,
    } = command;
    let wire = Wire::new(global)?;
    let upload = Upload::open(&file)?;
    let tail = artifact_path(
        &upload.name,
        &revision,
        descriptor,
        kind.as_deref(),
        &module,
    )?;
    let mut segments = vec![
        "ivy",
        repo.as_str(),
        org.as_str(),
        module.as_str(),
        revision.as_str(),
    ];
    segments.extend(tail.iter().map(String::as_str));
    let url = wire.url(&segments);
    publish_file(
        &wire,
        wire.request(Method::PUT, url),
        &upload,
        &repo,
        global,
    )
    .await
}

fn artifact_path(
    file: &str,
    revision: &str,
    descriptor: bool,
    kind: Option<&str>,
    module: &str,
) -> Result<Vec<String>> {
    if descriptor {
        return Ok(vec![format!("ivy-{revision}.xml")]);
    }
    let Some((_, ext)) = file.rsplit_once('.') else {
        return Err(AkError::Usage(format!(
            "`{file}` has no extension to make an Ivy path from"
        ))
        .into());
    };
    let kind = kind.unwrap_or(ext);
    Ok(vec![
        format!("{kind}s"),
        format!("{module}-{revision}.{ext}"),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_follow_the_ivy_layout() {
        assert_eq!(
            artifact_path("x.jar", "1.0", false, None, "demo").unwrap(),
            ["jars", "demo-1.0.jar"]
        );
        assert_eq!(
            artifact_path("x.jar", "1.0", false, Some("bundle"), "demo").unwrap(),
            ["bundles", "demo-1.0.jar"]
        );
        assert_eq!(
            artifact_path("ivy.xml", "1.0", true, None, "demo").unwrap(),
            ["ivy-1.0.xml"]
        );
        assert!(artifact_path("noext", "1.0", false, None, "demo").is_err());
    }
}
