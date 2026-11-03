//! `ak pkg incus` and `ak pkg lxc`: the same handlers under two URLs.
//!
//! An image goes up whole, or in a session of chunks that the server joins when it's
//! told the file's checksum. The server finishes a chunked upload after it answers.

use std::path::PathBuf;

use clap::Subcommand;
use miette::{IntoDiagnostic, Result};
use reqwest::Method;
use tokio::io::AsyncReadExt;

use super::wire::{Upload, Wire, emit};
use crate::cli::GlobalArgs;
use crate::commands::helpers::confirm_action;
use crate::error::AkError;

const CONTENT_TYPE: &str = "application/octet-stream";
const DEFAULT_CHUNK_MIB: u64 = 64;

#[derive(Subcommand)]
pub enum IncusCommand {
    /// Upload an image file
    #[command(after_help = "\
Examples:
  ak pkg incus publish my-images ubuntu-noble 20260101 incus.tar.xz
  ak pkg incus publish my-images ubuntu-noble 20260101 rootfs.squashfs --chunked")]
    Publish {
        /// Repository key
        repo: String,
        /// Product, such as ubuntu-noble-x86_64
        product: String,
        /// Version
        #[arg(id = "image_version")]
        version: String,
        /// The image file: its name says what kind it is
        file: PathBuf,
        /// Upload in a resumable session of chunks, rather than all at once
        #[arg(long)]
        chunked: bool,
        /// Chunk size in MiB
        #[arg(long, default_value_t = DEFAULT_CHUNK_MIB, value_parser = clap::value_parser!(u64).range(1..))]
        chunk_size: u64,
    },
    /// Delete an image file
    Delete {
        /// Repository key
        repo: String,
        /// Product
        product: String,
        /// Version
        #[arg(id = "image_version")]
        version: String,
        /// File name
        filename: String,
        /// Don't ask for confirmation
        #[arg(long)]
        yes: bool,
    },
    /// Cancel a chunked upload session
    #[command(name = "upload-cancel")]
    UploadCancel {
        /// Repository key
        repo: String,
        /// Session ID, from the start of the upload
        session: String,
    },
}

/// `prefix` is the URL the command was reached under: `incus` or `lxc`.
pub async fn execute(prefix: &str, command: IncusCommand, global: &GlobalArgs) -> Result<()> {
    let wire = Wire::new(global)?;
    match command {
        IncusCommand::Publish {
            repo,
            product,
            version,
            file,
            chunked,
            chunk_size,
        } => {
            let upload = Upload::open(&file)?;
            let image: [&str; 5] = ["images", &product, &version, &upload.name, "uploads"];
            let mut whole = vec![prefix, repo.as_str()];
            whole.extend(&image[..4]);
            let reply = if chunked {
                let mut start = vec![prefix, repo.as_str()];
                start.extend(image);
                let session = wire
                    .send(
                        "start the upload",
                        wire.request(Method::POST, wire.url(&start)),
                    )
                    .await?;
                let id = session
                    .json()
                    .and_then(|body| body["session_id"].as_str().map(str::to_string))
                    .ok_or_else(|| {
                        AkError::ServerError("The server gave no upload session".to_string())
                    })?;
                let session_url = wire.url(&[prefix, &repo, "uploads", &id]);
                let sent = send_chunks(&wire, &session_url, &upload, chunk_size).await;
                match sent {
                    Ok(()) => {}
                    Err(e) => {
                        // Leave no session behind. The chunk's error is the one to report.
                        let _ = wire
                            .send(
                                "cancel the upload",
                                wire.request(Method::DELETE, session_url.clone()),
                            )
                            .await;
                        return Err(e);
                    }
                }
                wire.send(
                    "finish the upload",
                    wire.request(Method::PUT, session_url)
                        .header("X-Checksum-Sha256", upload.sha256().await?),
                )
                .await?
            } else {
                let request = upload
                    .attach(wire.request(Method::PUT, wire.url(&whole)), CONTENT_TYPE)
                    .await?;
                wire.send("upload the image", request).await?
            };
            emit(
                &reply,
                &upload.name,
                &format!("Published {} to {repo}.", upload.name),
                global,
            );
        }
        IncusCommand::Delete {
            repo,
            product,
            version,
            filename,
            yes,
        } => {
            if !confirm_action(&format!("Delete {filename}?"), yes, global.no_input)? {
                return Ok(());
            }
            let url = wire.url(&[prefix, &repo, "images", &product, &version, &filename]);
            let reply = wire
                .send("delete the image", wire.request(Method::DELETE, url))
                .await?;
            emit(&reply, &filename, &format!("Deleted {filename}."), global);
        }
        IncusCommand::UploadCancel { repo, session } => {
            let url = wire.url(&[prefix, &repo, "uploads", &session]);
            let reply = wire
                .send("cancel the upload", wire.request(Method::DELETE, url))
                .await?;
            emit(&reply, &session, &format!("Cancelled {session}."), global);
        }
    }
    Ok(())
}

async fn send_chunks(
    wire: &Wire,
    url: &reqwest::Url,
    upload: &Upload,
    chunk_mib: u64,
) -> Result<()> {
    let chunk_size = usize::try_from(chunk_mib * 1024 * 1024).into_diagnostic()?;
    let mut file = tokio::fs::File::open(&upload.path)
        .await
        .into_diagnostic()?;
    let mut buffer = vec![0u8; chunk_size];
    loop {
        let mut filled = 0;
        while filled < chunk_size {
            let read = file.read(&mut buffer[filled..]).await.into_diagnostic()?;
            if read == 0 {
                break;
            }
            filled += read;
        }
        if filled == 0 {
            return Ok(());
        }
        wire.send(
            "send a chunk",
            wire.request(Method::PATCH, url.clone())
                .header(reqwest::header::CONTENT_TYPE, CONTENT_TYPE)
                .body(buffer[..filled].to_vec()),
        )
        .await?;
        if filled < chunk_size {
            return Ok(());
        }
    }
}
