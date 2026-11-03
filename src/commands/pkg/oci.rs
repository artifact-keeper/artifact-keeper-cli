//! `ak pkg oci`: the OCI registry API, for looking at and editing what `docker` and
//! `oras` push. Pushing an image is theirs: the blob upload session is a chunk protocol.
//!
//! An image's name is `<repository key>/<image>`, and may have more segments.

use std::io::Write;
use std::path::PathBuf;

use clap::Subcommand;
use futures::StreamExt;
use miette::{IntoDiagnostic, Result};
use reqwest::{Method, Url};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::wire::{Reply, Wire, emit};
use crate::cli::GlobalArgs;
use crate::commands::helpers::{confirm_action, read_inline_or_file};
use crate::error::AkError;
use crate::output::{self, OutputFormat};

/// What a manifest can be. A server answers with the first it has, so a request with no
/// list like this one gets an older form, or nothing.
const MANIFEST_TYPES: &str = "application/vnd.oci.image.manifest.v1+json, \
    application/vnd.oci.image.index.v1+json, \
    application/vnd.docker.distribution.manifest.v2+json, \
    application/vnd.docker.distribution.manifest.list.v2+json";
const DIGEST_HEADER: &str = "docker-content-digest";

#[derive(Subcommand)]
pub enum OciCommand {
    /// List the images in the registry
    #[command(after_help = "\
Examples:
  ak pkg oci catalog
  ak pkg oci catalog --all
  ak pkg oci catalog --limit 50 --last my-repo/app")]
    Catalog {
        /// Page size
        #[arg(long)]
        limit: Option<u32>,
        /// Start after this name
        #[arg(long)]
        last: Option<String>,
        /// Follow the pages, and print them as one list
        #[arg(long, conflicts_with = "last")]
        all: bool,
    },
    /// List an image's tags
    #[command(after_help = "\
Examples:
  ak pkg oci tags my-repo/app
  ak pkg oci tags my-repo/app --all")]
    Tags {
        /// Image name: <repository key>/<image>
        name: String,
        /// Page size
        #[arg(long)]
        limit: Option<u32>,
        /// Start after this tag
        #[arg(long)]
        last: Option<String>,
        /// Follow the pages, and print them as one list
        #[arg(long, conflicts_with = "last")]
        all: bool,
    },
    /// Read, store or delete a manifest
    #[command(subcommand)]
    Manifest(ManifestCommand),
    /// Read a blob
    #[command(subcommand)]
    Blob(BlobCommand),
    /// List what refers to a manifest, such as signatures and SBOMs
    #[command(after_help = "\
Examples:
  ak pkg oci referrers my-repo/app sha256:abc...
  ak pkg oci referrers my-repo/app sha256:abc... --artifact-type application/spdx+json")]
    Referrers {
        /// Image name: <repository key>/<image>
        name: String,
        /// The manifest's digest
        digest: String,
        /// Only this artifact type
        #[arg(long)]
        artifact_type: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum ManifestCommand {
    /// Print a manifest as stored, with every media type accepted
    #[command(after_help = "\
Examples:
  ak pkg oci manifest get my-repo/app 1.0
  ak pkg oci manifest get my-repo/app sha256:abc... -o manifest.json")]
    Get {
        /// Image name: <repository key>/<image>
        name: String,
        /// Tag or digest
        reference: String,
        /// Write to a file instead of stdout
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
    },
    /// Show a manifest's digest, media type and size
    #[command(after_help = "\
Examples:
  ak pkg oci manifest head my-repo/app 1.0
  ak pkg oci manifest head my-repo/app 1.0 --format quiet")]
    Head {
        /// Image name: <repository key>/<image>
        name: String,
        /// Tag or digest
        reference: String,
    },
    /// Store a manifest under a tag or digest
    #[command(after_help = "\
Its blobs have to be in the repository already. The media type comes from the manifest's
own mediaType field unless it's given. This checks that the digest the server reports
is the digest of what was sent.

Examples:
  ak pkg oci manifest put my-repo/app 1.0-copy manifest.json")]
    Put {
        /// Image name: <repository key>/<image>
        name: String,
        /// Tag or digest
        reference: String,
        /// The manifest: @file, @- for stdin, or a path
        file: String,
        /// Media type, instead of the manifest's own
        #[arg(long)]
        media_type: Option<String>,
    },
    /// Delete a manifest
    #[command(after_help = "\
Examples:
  ak pkg oci manifest delete my-repo/app sha256:abc... --yes")]
    Delete {
        /// Image name: <repository key>/<image>
        name: String,
        /// Tag or digest
        reference: String,
        /// Don't ask for confirmation
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
pub enum BlobCommand {
    /// Download a blob, and check it against its digest
    #[command(after_help = "\
The file only appears once its sha256 has matched. To stdout, a mismatch is an error
after the bytes went out.

Examples:
  ak pkg oci blob get my-repo/app sha256:abc... -o layer.tar.gz")]
    Get {
        /// Image name: <repository key>/<image>
        name: String,
        /// The blob's digest
        digest: String,
        /// Write to a file instead of stdout
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
    },
}

/// `/v2/<name segments>/<tail...>`.
fn image_url(wire: &Wire, name: &str, tail: &[&str]) -> Url {
    let mut segments = vec!["v2"];
    segments.extend(name.split('/'));
    segments.extend(tail);
    wire.url(&segments)
}

fn with_page(mut url: Url, limit: Option<u32>, last: Option<&str>) -> Url {
    {
        let mut query = url.query_pairs_mut();
        if let Some(limit) = limit {
            query.append_pair("n", &limit.to_string());
        }
        if let Some(last) = last {
            query.append_pair("last", last);
        }
    }
    if url.query() == Some("") {
        url.set_query(None);
    }
    url
}

/// The next page from a `Link: </v2/...?n=1&last=x>; rel="next"` header. It's a path on
/// this registry, and only the query of it is used, so a server can't send this elsewhere.
fn next_page(reply: &Reply, current: &Url) -> Option<Url> {
    let link = reply.headers.get("link")?.to_str().ok()?;
    let target = link.split(';').next()?.trim();
    let target = target.strip_prefix('<')?.strip_suffix('>')?;
    let query = target.split_once('?')?.1;
    let mut next = current.clone();
    next.set_query(Some(query));
    Some(next)
}

/// One page as received, or with `all`, the named list from each page joined up.
async fn list(
    wire: &Wire,
    action: &str,
    url: Url,
    key: &str,
    all: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let mut reply = wire
        .send(action, wire.request(Method::GET, url.clone()))
        .await?;
    let mut items: Vec<Value> = Vec::new();
    let mut body = reply.json().unwrap_or(Value::Null);
    if all {
        loop {
            items.extend(body[key].as_array().cloned().unwrap_or_default());
            let Some(next) = next_page(&reply, &url) else {
                break;
            };
            reply = wire.send(action, wire.request(Method::GET, next)).await?;
            body = reply.json().unwrap_or(Value::Null);
        }
    } else {
        items = body[key].as_array().cloned().unwrap_or_default();
    }
    let names: Vec<String> = items
        .iter()
        .filter_map(|item| item.as_str().map(str::to_string))
        .collect();
    let joined = {
        let mut whole = body.clone();
        if whole.is_object() {
            whole[key] = json!(items);
        }
        whole
    };
    let raw = (!all).then_some(reply.body.as_slice());
    match global.format {
        OutputFormat::Table => println!("{}", names.join("\n")),
        OutputFormat::Quiet => println!("{}", names.join("\n")),
        _ => println!("{}", output::render_raw(raw, &joined, &global.format, None)),
    }
    Ok(())
}

pub async fn execute(command: OciCommand, global: &GlobalArgs) -> Result<()> {
    let wire = Wire::new(global)?;
    match command {
        OciCommand::Catalog { limit, last, all } => {
            let url = with_page(wire.url(&["v2", "_catalog"]), limit, last.as_deref());
            list(&wire, "list the catalog", url, "repositories", all, global).await
        }
        OciCommand::Tags {
            name,
            limit,
            last,
            all,
        } => {
            let url = with_page(
                image_url(&wire, &name, &["tags", "list"]),
                limit,
                last.as_deref(),
            );
            list(&wire, "list the tags", url, "tags", all, global).await
        }
        OciCommand::Referrers {
            name,
            digest,
            artifact_type,
        } => {
            let mut url = image_url(&wire, &name, &["referrers", &digest]);
            if let Some(artifact_type) = artifact_type {
                url.query_pairs_mut()
                    .append_pair("artifactType", &artifact_type);
            }
            let reply = wire
                .send(
                    "list the referrers",
                    wire.request(Method::GET, url).header(
                        reqwest::header::ACCEPT,
                        "application/vnd.oci.image.index.v1+json",
                    ),
                )
                .await?;
            println!("{}", String::from_utf8_lossy(&reply.body).trim());
            Ok(())
        }
        OciCommand::Manifest(command) => manifest(&wire, command, global).await,
        OciCommand::Blob(command) => blob(&wire, command).await,
    }
}

fn header(reply: &Reply, name: &str) -> Option<String> {
    reply
        .headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

async fn manifest(wire: &Wire, command: ManifestCommand, global: &GlobalArgs) -> Result<()> {
    match command {
        ManifestCommand::Get {
            name,
            reference,
            output,
        } => {
            let url = image_url(wire, &name, &["manifests", &reference]);
            let reply = wire
                .send(
                    "read the manifest",
                    wire.request(Method::GET, url)
                        .header(reqwest::header::ACCEPT, MANIFEST_TYPES),
                )
                .await?;
            // The digest is of these exact bytes, so they aren't reformatted.
            match output {
                Some(path) => std::fs::write(&path, &reply.body).map_err(|e| {
                    AkError::ConfigError(format!("Can't write {}: {e}", path.display()))
                })?,
                None => std::io::stdout().write_all(&reply.body).into_diagnostic()?,
            }
            Ok(())
        }
        ManifestCommand::Head { name, reference } => {
            let url = image_url(wire, &name, &["manifests", &reference]);
            let reply = wire
                .send(
                    "read the manifest",
                    wire.request(Method::HEAD, url)
                        .header(reqwest::header::ACCEPT, MANIFEST_TYPES),
                )
                .await?;
            let digest = header(&reply, DIGEST_HEADER).unwrap_or_default();
            let media_type = header(&reply, "content-type").unwrap_or_default();
            let size = header(&reply, "content-length").unwrap_or_default();
            let info = Reply::new(json!({
                "digest": digest, "media_type": media_type,
                "size": size.parse::<u64>().ok(),
            }));
            emit(
                &info,
                &digest,
                &format!("{digest}\n{media_type}\n{size} bytes"),
                global,
            );
            if matches!(global.format, OutputFormat::Table) {
                println!("{digest}");
            }
            Ok(())
        }
        ManifestCommand::Put {
            name,
            reference,
            file,
            media_type,
        } => {
            let body = if file.starts_with('@') {
                read_inline_or_file(&file, "the manifest")?
            } else {
                std::fs::read(&file)
                    .map_err(|e| AkError::ConfigError(format!("Can't read {file}: {e}")))?
            };
            let parsed: Value = serde_json::from_slice(&body)
                .map_err(|e| AkError::ConfigError(format!("The manifest isn't JSON: {e}")))?;
            let media_type = match media_type.or_else(|| manifest_type(&parsed)) {
                Some(media_type) => media_type,
                None => {
                    return Err(AkError::ConfigError(
                        "The manifest has no mediaType. Give --media-type".to_string(),
                    )
                    .into());
                }
            };
            let digest = format!("sha256:{}", hex::encode(Sha256::digest(&body)));
            let url = image_url(wire, &name, &["manifests", &reference]);
            let reply = wire
                .send(
                    "store the manifest",
                    wire.request(Method::PUT, url)
                        .header(reqwest::header::CONTENT_TYPE, &media_type)
                        .body(body),
                )
                .await?;
            if let Some(stored) = header(&reply, DIGEST_HEADER)
                && stored != digest
            {
                return Err(AkError::ServerError(format!(
                    "The server stored {stored}, but what was sent is {digest}"
                ))
                .into());
            }
            let info = Reply::new(json!({"digest": digest, "media_type": media_type}));
            emit(
                &info,
                &digest,
                &format!("Stored {name}:{reference} as {digest}."),
                global,
            );
            Ok(())
        }
        ManifestCommand::Delete {
            name,
            reference,
            yes,
        } => {
            if !confirm_action(&format!("Delete {name}:{reference}?"), yes, global.no_input)? {
                return Ok(());
            }
            let url = image_url(wire, &name, &["manifests", &reference]);
            let reply = wire
                .send("delete the manifest", wire.request(Method::DELETE, url))
                .await?;
            emit(
                &reply,
                &reference,
                &format!("Deleted {name}:{reference}."),
                global,
            );
            Ok(())
        }
    }
}

/// The manifest's own media type. An OCI image manifest may leave it out.
fn manifest_type(manifest: &Value) -> Option<String> {
    if let Some(media_type) = manifest["mediaType"].as_str() {
        return Some(media_type.to_string());
    }
    if manifest["manifests"].is_array() {
        return Some("application/vnd.oci.image.index.v1+json".to_string());
    }
    manifest["config"]
        .is_object()
        .then(|| "application/vnd.oci.image.manifest.v1+json".to_string())
}

async fn blob(wire: &Wire, command: BlobCommand) -> Result<()> {
    match command {
        BlobCommand::Get {
            name,
            digest,
            output,
        } => {
            let url = image_url(wire, &name, &["blobs", &digest]);
            let response = wire
                .send_streaming("read the blob", wire.request(Method::GET, url))
                .await?;
            let expected = digest.strip_prefix("sha256:").map(str::to_string);
            let mut hasher = Sha256::new();
            let mut stream = response.bytes_stream();
            match output {
                Some(path) => {
                    let dir = path
                        .parent()
                        .filter(|p| !p.as_os_str().is_empty())
                        .map_or_else(|| PathBuf::from("."), PathBuf::from);
                    let mut temp = tempfile::NamedTempFile::new_in(&dir).map_err(|e| {
                        AkError::ConfigError(format!("Can't write in {}: {e}", dir.display()))
                    })?;
                    while let Some(chunk) = stream.next().await {
                        let chunk = chunk.into_diagnostic()?;
                        hasher.update(&chunk);
                        temp.write_all(&chunk).into_diagnostic()?;
                    }
                    check_digest(hasher, expected.as_deref())?;
                    temp.persist(&path).map_err(|e| {
                        AkError::ConfigError(format!("Can't write {}: {e}", path.display()))
                    })?;
                }
                None => {
                    let mut stdout = std::io::stdout();
                    while let Some(chunk) = stream.next().await {
                        let chunk = chunk.into_diagnostic()?;
                        hasher.update(&chunk);
                        stdout.write_all(&chunk).into_diagnostic()?;
                    }
                    check_digest(hasher, expected.as_deref())?;
                }
            }
            Ok(())
        }
    }
}

/// Only sha256 can be checked here. Another algorithm is the server's word for it.
fn check_digest(hasher: Sha256, expected: Option<&str>) -> Result<()> {
    if let Some(expected) = expected {
        let got = hex::encode(hasher.finalize());
        if got != expected {
            return Err(AkError::ServerError(format!(
                "The blob's sha256 is {got}, not {expected}. Nothing was kept"
            ))
            .into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_manifest_says_or_implies_its_type() {
        assert_eq!(
            manifest_type(&json!({"mediaType": "x"})).as_deref(),
            Some("x")
        );
        assert_eq!(
            manifest_type(&json!({"manifests": []})).as_deref(),
            Some("application/vnd.oci.image.index.v1+json")
        );
        assert_eq!(
            manifest_type(&json!({"config": {}})).as_deref(),
            Some("application/vnd.oci.image.manifest.v1+json")
        );
        assert_eq!(manifest_type(&json!({})), None);
    }

    #[test]
    fn the_next_page_keeps_this_registry() {
        let current = Url::parse("http://registry.example/v2/_catalog").unwrap();
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "link",
            "<http://elsewhere.example/v2/_catalog?n=1&last=a>; rel=\"next\""
                .parse()
                .unwrap(),
        );
        let reply = Reply {
            status: reqwest::StatusCode::OK,
            headers,
            body: Vec::new(),
        };
        let next = next_page(&reply, &current).unwrap();
        assert_eq!(
            next.as_str(),
            "http://registry.example/v2/_catalog?n=1&last=a"
        );
    }

    #[test]
    fn a_wrong_digest_is_an_error() {
        let mut hasher = Sha256::new();
        hasher.update(b"abc");
        assert!(check_digest(hasher, Some("00")).is_err());
        let mut hasher = Sha256::new();
        hasher.update(b"abc");
        assert!(
            check_digest(
                hasher,
                Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            )
            .is_ok()
        );
    }
}
