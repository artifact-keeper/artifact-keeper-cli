//! `ak pkg npm`: what `npm publish`, `npm dist-tag`, `npm unpublish` and `npm audit` send.
//!
//! A publish is one JSON document holding the `package.json`, the tarball's digests and
//! the tarball itself in base64. Scoped names are `@scope/name`.

use std::path::PathBuf;

use base64::Engine;
use clap::{Subcommand, ValueEnum};
use miette::Result;
use reqwest::Method;
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::{Digest, Sha512};

use super::archive::require_tar_gz_entry;
use super::wire::{Upload, Wire, emit};
use crate::cli::GlobalArgs;
use crate::commands::helpers::read_inline_or_file;
use crate::error::AkError;

/// The revision the server is told when it has none to give. It ignores the value.
const NO_REV: &str = "0-0";

#[derive(Clone, Copy, ValueEnum)]
pub enum AuditKind {
    /// /-/npm/v1/security/advisories/bulk, what `npm audit` sends first
    Bulk,
    /// /-/npm/v1/security/audits/quick, its fallback
    Quick,
}

#[derive(Subcommand)]
pub enum NpmCommand {
    /// Publish a tarball from `npm pack`, as `npm publish` does
    #[command(after_help = "\
Examples:
  ak pkg npm publish my-npm demo-1.0.0.tgz
  ak pkg npm publish my-npm scope-demo-1.0.0.tgz --tag next")]
    Publish {
        /// Repository key
        repo: String,
        /// The .tgz, with package/package.json inside
        file: PathBuf,
        /// The dist-tag to give this version
        #[arg(long, default_value = "latest")]
        tag: String,
    },
    /// Point a dist-tag at a version, or remove it
    #[command(name = "dist-tag", subcommand)]
    DistTag(DistTagCommand),
    /// Remove a version, a tarball, or a whole package, as `npm unpublish` does
    #[command(
        after_help = "\
With only a package it removes the whole package. A scoped name goes in the URL as
@scope/name, or as @scope%2fname with --encoded-name, which is what npm itself sends.

Examples:
  ak pkg npm unpublish my-npm demo --version 1.0.0
  ak pkg npm unpublish my-npm demo --tarball demo-1.0.0.tgz
  ak pkg npm unpublish my-npm @scope/demo",
        disable_version_flag = true
    )]
    Unpublish {
        /// Repository key
        repo: String,
        /// Package name
        package: String,
        /// Remove only this version, keeping the others
        #[arg(id = "package_version", long = "version", conflicts_with = "tarball")]
        version: Option<String>,
        /// Remove only the version this tarball holds
        #[arg(long)]
        tarball: Option<String>,
        /// Send @scope%2fname rather than @scope/name, as npm does
        #[arg(long, conflicts_with = "tarball")]
        encoded_name: bool,
        /// Don't ask for confirmation
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Send an audit request, as `npm audit` does
    #[command(after_help = "\
A hosted repository answers with no advisories. A remote one asks its upstream.

Examples:
  ak pkg npm audit my-npm --body '{\"lodash\":[\"4.17.0\"]}'
  ak pkg npm audit my-npm --kind quick --body @audit.json")]
    Audit {
        /// Repository key
        repo: String,
        /// JSON body: the text itself, or @file
        #[arg(long)]
        body: String,
        /// Which of the two audit endpoints to call
        #[arg(long, value_enum, default_value = "bulk")]
        kind: AuditKind,
    },
}

#[derive(Subcommand)]
pub enum DistTagCommand {
    /// Point a tag at a version that exists
    Set {
        /// Repository key
        repo: String,
        /// Package name
        package: String,
        /// Tag name
        tag: String,
        /// Version
        #[arg(id = "package_version")]
        version: String,
    },
    /// Remove a tag
    Rm {
        /// Repository key
        repo: String,
        /// Package name
        package: String,
        /// Tag name
        tag: String,
    },
}

pub async fn execute(command: NpmCommand, global: &GlobalArgs) -> Result<()> {
    let wire = Wire::new(global)?;
    match command {
        NpmCommand::Publish { repo, file, tag } => publish(&wire, &repo, file, &tag, global).await,
        NpmCommand::DistTag(DistTagCommand::Set {
            repo,
            package,
            tag,
            version,
        }) => {
            let url = wire.url(&["npm", &repo, "-", "package", &package, "dist-tags", &tag]);
            let reply = wire
                .send(
                    "set the dist-tag",
                    wire.request(Method::PUT, url).json(&json!(version)),
                )
                .await?;
            emit(
                &reply,
                &tag,
                &format!("{package}: {tag} now points to {version}."),
                global,
            );
            Ok(())
        }
        NpmCommand::DistTag(DistTagCommand::Rm { repo, package, tag }) => {
            let url = wire.url(&["npm", &repo, "-", "package", &package, "dist-tags", &tag]);
            let reply = wire
                .send("remove the dist-tag", wire.request(Method::DELETE, url))
                .await?;
            emit(&reply, &tag, &format!("{package}: removed {tag}."), global);
            Ok(())
        }
        NpmCommand::Unpublish {
            repo,
            package,
            version,
            tarball,
            encoded_name,
            yes,
        } => {
            let what = match (&version, &tarball) {
                (Some(v), _) => format!("{package} {v}"),
                (_, Some(t)) => format!("{t} of {package}"),
                _ => format!("all of {package}"),
            };
            if !crate::commands::helpers::confirm_action(
                &format!("Remove {what} from {repo}?"),
                yes,
                global.no_input,
            )? {
                return Ok(());
            }
            const COMMAND: &str = "pkg npm unpublish";
            let rev = current_rev(&wire, &repo, &package).await;
            let package_segments = name_segments(&package, encoded_name);
            let rev_url = |tail: &[&str]| {
                let mut segments = vec!["npm", repo.as_str()];
                segments.extend(package_segments.iter().map(String::as_str));
                segments.extend(tail);
                wire.url(&segments)
            };
            let reply = if let Some(tarball) = &tarball {
                wire.send_since_1_11(
                    "remove the tarball",
                    COMMAND,
                    global,
                    wire.request(Method::DELETE, rev_url(&["-", tarball, "-rev", &rev])),
                )
                .await?
            } else if let Some(version) = &version {
                let kept = packument_without(&wire, &repo, &package, version).await?;
                wire.send_since_1_11(
                    "remove the version",
                    COMMAND,
                    global,
                    wire.request(Method::PUT, rev_url(&["-rev", &rev]))
                        .json(&kept),
                )
                .await?
            } else {
                wire.send_since_1_11(
                    "remove the package",
                    COMMAND,
                    global,
                    wire.request(Method::DELETE, rev_url(&["-rev", &rev])),
                )
                .await?
            };
            emit(&reply, &package, &format!("Removed {what}."), global);
            Ok(())
        }
        NpmCommand::Audit { repo, body, kind } => {
            let text = read_inline_or_file(&body, "--body")?;
            let parsed: Value = serde_json::from_slice(&text)
                .map_err(|e| AkError::ConfigError(format!("--body isn't JSON: {e}")))?;
            let tail: &[&str] = match kind {
                AuditKind::Bulk => &["advisories", "bulk"],
                AuditKind::Quick => &["audits", "quick"],
            };
            let mut segments = vec!["npm", repo.as_str(), "-", "npm", "v1", "security"];
            segments.extend(tail);
            let reply = wire
                .send(
                    "send the audit request",
                    wire.request(Method::POST, wire.url(&segments))
                        .json(&parsed),
                )
                .await?;
            println!("{}", String::from_utf8_lossy(&reply.body).trim());
            Ok(())
        }
    }
}

async fn publish(
    wire: &Wire,
    repo: &str,
    file: PathBuf,
    tag: &str,
    global: &GlobalArgs,
) -> Result<()> {
    let upload = Upload::open(&file)?;
    let manifest = require_tar_gz_entry(&file, "package/package.json", |parts| {
        parts.len() == 2 && parts[1] == "package.json"
    })?;
    let manifest: Value = serde_json::from_slice(&manifest)
        .map_err(|e| AkError::ConfigError(format!("The package.json in the tarball: {e}")))?;
    let tarball = upload.read().await?;
    let tarball_url = wire.url(&[]).to_string();
    let document = publish_document(manifest, &tarball, tag, repo, &tarball_url)?;
    let name = document["name"].as_str().unwrap_or_default().to_string();
    let version = document["dist-tags"][tag]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let segments = name_segments(&name, false);
    let mut path = vec!["npm", repo];
    path.extend(segments.iter().map(String::as_str));
    let reply = wire
        .send(
            "publish the package",
            wire.request(Method::PUT, wire.url(&path)).json(&document),
        )
        .await?;
    emit(
        &reply,
        &format!("{name}@{version}"),
        &format!("Published {name} {version} to {repo}."),
        global,
    );
    Ok(())
}

/// A scoped name is one path segment when encoded, and two when not.
fn name_segments(package: &str, encoded: bool) -> Vec<String> {
    match package.split_once('/') {
        Some((scope, name)) if !encoded && scope.starts_with('@') => {
            vec![scope.to_string(), name.to_string()]
        }
        _ => vec![package.to_string()],
    }
}

/// The document `npm publish` sends. See libnpmpublish.
fn publish_document(
    mut manifest: Value,
    tarball: &[u8],
    tag: &str,
    repo: &str,
    base: &str,
) -> Result<Value> {
    let (Some(name), Some(version)) = (
        manifest["name"].as_str().map(str::to_string),
        manifest["version"].as_str().map(str::to_string),
    ) else {
        return Err(AkError::ConfigError(
            "The tarball's package.json has no name or version".to_string(),
        )
        .into());
    };
    let short = name.rsplit('/').next().unwrap_or(&name);
    let filename = format!("{short}-{version}.tgz");
    let base64 = base64::engine::general_purpose::STANDARD;
    manifest["_id"] = json!(format!("{name}@{version}"));
    manifest["dist"] = json!({
        "integrity": format!("sha512-{}", base64.encode(Sha512::digest(tarball))),
        "shasum": hex::encode(Sha1::digest(tarball)),
        "tarball": format!("{}/npm/{repo}/{name}/-/{filename}", base.trim_end_matches('/')),
    });
    Ok(json!({
        "_id": name,
        "name": name,
        "description": manifest["description"],
        "dist-tags": {tag: version},
        "versions": {version.clone(): manifest},
        "_attachments": {
            filename: {
                "content_type": "application/octet-stream",
                "data": base64.encode(tarball),
                "length": tarball.len(),
            }
        },
    }))
}

/// The package's revision if the server gives one. A failure here isn't one worth
/// reporting: the request that follows says what's really wrong.
async fn current_rev(wire: &Wire, repo: &str, package: &str) -> String {
    packument(wire, repo, package)
        .await
        .ok()
        .and_then(|doc| doc["_rev"].as_str().map(str::to_string))
        .unwrap_or_else(|| NO_REV.to_string())
}

async fn packument(wire: &Wire, repo: &str, package: &str) -> Result<Value> {
    let mut path = vec!["npm", repo];
    let segments = name_segments(package, false);
    path.extend(segments.iter().map(String::as_str));
    let reply = wire
        .send(
            "read the package",
            wire.request(Method::GET, wire.url(&path)),
        )
        .await?;
    reply
        .json()
        .ok_or_else(|| AkError::ServerError("The package metadata isn't JSON".to_string()).into())
}

/// The package's document minus one version, which is how a client says to remove it.
async fn packument_without(wire: &Wire, repo: &str, package: &str, version: &str) -> Result<Value> {
    let mut document = packument(wire, repo, package).await?;
    let removed = document
        .get_mut("versions")
        .and_then(|v| v.as_object_mut())
        .and_then(|versions| versions.remove(version));
    if removed.is_none() {
        return Err(AkError::ConfigError(format!("{package} has no version {version}")).into());
    }
    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_names_are_one_or_two_segments() {
        assert_eq!(name_segments("demo", false), ["demo"]);
        assert_eq!(name_segments("@a/b", false), ["@a", "b"]);
        assert_eq!(name_segments("@a/b", true), ["@a/b"]);
    }

    #[test]
    fn publish_document_has_what_the_server_and_clients_read() {
        let doc = publish_document(
            json!({"name": "@a/b", "version": "1.0.0", "description": "d"}),
            b"tar",
            "next",
            "r",
            "http://h/",
        )
        .unwrap();
        assert_eq!(doc["name"], "@a/b");
        assert_eq!(doc["dist-tags"]["next"], "1.0.0");
        let version = &doc["versions"]["1.0.0"];
        assert_eq!(version["_id"], "@a/b@1.0.0");
        assert_eq!(version["dist"]["shasum"].as_str().unwrap().len(), 40);
        assert!(
            version["dist"]["integrity"]
                .as_str()
                .unwrap()
                .starts_with("sha512-")
        );
        assert_eq!(
            version["dist"]["tarball"],
            "http://h/npm/r/@a/b/-/b-1.0.0.tgz"
        );
        assert_eq!(doc["_attachments"]["b-1.0.0.tgz"]["data"], "dGFy");
        assert_eq!(doc["_attachments"]["b-1.0.0.tgz"]["length"], 3);
    }

    #[test]
    fn publish_document_needs_a_name_and_version() {
        assert!(publish_document(json!({"name": "a"}), b"", "latest", "r", "http://h").is_err());
    }
}
