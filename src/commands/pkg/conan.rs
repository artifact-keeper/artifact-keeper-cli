//! `ak pkg conan`: the Conan v2 API that `conan upload` and `conan remove` use.
//! Files go up one at a time under a recipe revision, and for a package, under its
//! package ID and package revision too. A revision is whatever the caller says it is:
//! `conan` computes it, and `conan list` shows it.

use std::path::PathBuf;

use clap::Subcommand;
use miette::Result;
use reqwest::Method;

use super::wire::{Upload, Wire, emit};
use crate::cli::GlobalArgs;
use crate::commands::helpers::confirm_action;
use crate::error::AkError;

#[derive(Subcommand)]
pub enum ConanCommand {
    /// Exchange the current credentials for a Conan token, as `conan remote login` does
    #[command(after_help = "\
It prints the token, which `conan` keeps and sends as a bearer token. Treat it as a
password.

Examples:
  ak pkg conan authenticate my-conan")]
    Authenticate {
        /// Repository key
        repo: String,
    },
    /// Upload a recipe's or a package's files
    #[command(after_help = "\
Without --package-id they're recipe files: conanfile.py, conanmanifest.txt and
conan_export.tgz. With it they're package files: conaninfo.txt, conanmanifest.txt and
conan_package.tgz.

Examples:
  ak pkg conan upload my-conan demo/1.0@_/_ --revision abc123 conanfile.py conanmanifest.txt
  ak pkg conan upload my-conan demo/1.0 --revision abc123 --package-id def --package-revision 456 \\
    conaninfo.txt conanmanifest.txt conan_package.tgz")]
    Upload {
        /// Repository key
        repo: String,
        /// Reference: name/version or name/version@user/channel
        reference: String,
        /// Recipe revision
        #[arg(long)]
        revision: String,
        /// Package ID, for package files
        #[arg(long, requires = "package_revision")]
        package_id: Option<String>,
        /// Package revision, for package files
        #[arg(long, requires = "package_id")]
        package_revision: Option<String>,
        /// The files, stored under their own names
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },
    /// Remove a recipe, a recipe revision, or packages
    #[command(after_help = "\
Examples:
  ak pkg conan remove my-conan demo/1.0 --yes
  ak pkg conan remove my-conan demo/1.0 --revision abc123 --yes
  ak pkg conan remove my-conan demo/1.0 --revision abc123 --all-packages --yes
  ak pkg conan remove my-conan demo/1.0 --revision abc123 --package-id def --package-revision 456 --yes")]
    Remove {
        /// Repository key
        repo: String,
        /// Reference: name/version or name/version@user/channel
        reference: String,
        /// Only this recipe revision
        #[arg(long)]
        revision: Option<String>,
        /// All of this revision's packages, keeping the recipe
        #[arg(long, requires = "revision", conflicts_with = "package_id")]
        all_packages: bool,
        /// One package
        #[arg(long, requires_all = ["revision", "package_revision"])]
        package_id: Option<String>,
        /// That package's revision
        #[arg(long, requires = "package_id")]
        package_revision: Option<String>,
        /// Don't ask for confirmation
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

/// `name/version[@user/channel]` as its four URL segments. A missing user and channel are `_`.
fn parse_reference(reference: &str) -> Result<[&str; 4]> {
    let (name_version, user_channel) = match reference.split_once('@') {
        Some((left, right)) => (left, Some(right)),
        None => (reference, None),
    };
    let bad = || {
        AkError::ConfigError(format!(
            "`{reference}` isn't a reference: use name/version or name/version@user/channel"
        ))
    };
    let (name, version) = name_version.split_once('/').ok_or_else(bad)?;
    let (user, channel) = match user_channel {
        Some(both) => both.split_once('/').ok_or_else(bad)?,
        None => ("_", "_"),
    };
    if [name, version, user, channel].iter().any(|s| s.is_empty()) {
        return Err(bad().into());
    }
    Ok([name, version, user, channel])
}

pub async fn execute(command: ConanCommand, global: &GlobalArgs) -> Result<()> {
    let wire = Wire::new(global)?;
    match command {
        ConanCommand::Authenticate { repo } => {
            let reply = wire
                .send(
                    "get a Conan token",
                    wire.request(
                        Method::POST,
                        wire.url(&["conan", &repo, "v2", "users", "authenticate"]),
                    ),
                )
                .await?;
            println!("{}", String::from_utf8_lossy(&reply.body).trim());
        }
        ConanCommand::Upload {
            repo,
            reference,
            revision,
            package_id,
            package_revision,
            files,
        } => {
            let [name, version, user, channel] = parse_reference(&reference)?;
            let mut uploads = files
                .iter()
                .map(|file| Upload::open(file))
                .collect::<Result<Vec<_>>>()?;
            // The manifest publishes the revision, and the server refuses it until the
            // files it lists are there. `conan upload` sends it last too.
            uploads.sort_by_key(|upload| upload.name == "conanmanifest.txt");
            let mut base = vec![
                "conan",
                &repo,
                "v2",
                "conans",
                name,
                version,
                user,
                channel,
                "revisions",
                &revision,
            ];
            if let (Some(id), Some(package_revision)) = (&package_id, &package_revision) {
                base.extend(["packages", id, "revisions", package_revision]);
            }
            base.push("files");
            for upload in &uploads {
                let mut segments = base.clone();
                segments.push(&upload.name);
                let request = upload
                    .attach(
                        wire.request(Method::PUT, wire.url(&segments)),
                        "application/octet-stream",
                    )
                    .await?;
                let reply = wire
                    .send(&format!("upload {}", upload.name), request)
                    .await?;
                emit(
                    &reply,
                    &upload.name,
                    &format!("Uploaded {} for {reference}.", upload.name),
                    global,
                );
            }
        }
        ConanCommand::Remove {
            repo,
            reference,
            revision,
            all_packages,
            package_id,
            package_revision,
            yes,
        } => {
            let [name, version, user, channel] = parse_reference(&reference)?;
            let mut segments = vec!["conan", &repo, "v2", "conans", name, version, user, channel];
            if let Some(revision) = &revision {
                segments.extend(["revisions", revision]);
            }
            if all_packages {
                segments.push("packages");
            }
            if let (Some(id), Some(package_revision)) = (&package_id, &package_revision) {
                segments.extend(["packages", id, "revisions", package_revision]);
            }
            let what = segments[4..].join("/");
            if !confirm_action(&format!("Remove {what}?"), yes, global.no_input)? {
                return Ok(());
            }
            let reply = wire
                .send_since_1_11(
                    "remove it",
                    "pkg conan remove",
                    global,
                    wire.request(Method::DELETE, wire.url(&segments)),
                )
                .await?;
            emit(&reply, &what, &format!("Removed {what}."), global);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_with_and_without_a_user() {
        assert_eq!(parse_reference("a/1").unwrap(), ["a", "1", "_", "_"]);
        assert_eq!(parse_reference("a/1@u/c").unwrap(), ["a", "1", "u", "c"]);
        assert!(parse_reference("a").is_err());
        assert!(parse_reference("a/1@u").is_err());
        assert!(parse_reference("/1").is_err());
    }
}
