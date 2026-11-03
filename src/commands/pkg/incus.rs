//! `ak pkg incus` and `ak pkg lxc`: the same handlers under two URLs.
//!
//! An image goes up whole, or in a session of chunks that the server joins when it's
//! told the file's checksum. Either way the server answers 202 and stores the image in
//! the background, where it can still fail, so `publish` waits for the outcome. Until
//! then a read of the image answers 404.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::Subcommand;
use miette::{IntoDiagnostic, Result};
use reqwest::Method;
use tokio::io::AsyncReadExt;

use super::wire::{Reply, Upload, Wire, emit};
use crate::cli::GlobalArgs;
use crate::commands::helpers::confirm_action;
use crate::error::AkError;

const CONTENT_TYPE: &str = "application/octet-stream";
const DEFAULT_CHUNK_MIB: u64 = 64;
const DEFAULT_WAIT_SECS: u64 = 600;
const POLL_FIRST: Duration = Duration::from_millis(50);
const POLL_MOST: Duration = Duration::from_secs(2);

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
        /// Return as soon as the server has the file, before it has stored the image.
        /// The image isn't readable yet, and storing it can still fail
        #[arg(long)]
        no_wait: bool,
        /// How long to wait for the server to store the image, in seconds
        #[arg(long, default_value_t = DEFAULT_WAIT_SECS, conflicts_with = "no_wait")]
        wait_timeout: u64,
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
        #[arg(long, short = 'y')]
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
            no_wait,
            wait_timeout,
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
            if !no_wait && let Some(session) = finalizing_session(&reply) {
                let url = wire.url(&[prefix, &repo, "uploads", &session]);
                let done = wait_for_image(&wire, url, &session, wait_timeout).await?;
                emit(
                    &done,
                    &upload.name,
                    &format!("Published {} to {repo}.", upload.name),
                    global,
                );
                return Ok(());
            }
            let human = if finalizing_session(&reply).is_some() {
                format!(
                    "Sent {} to {repo}. The server is still storing it.",
                    upload.name
                )
            } else {
                format!("Published {} to {repo}.", upload.name)
            };
            emit(&reply, &upload.name, &human, global);
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

/// The session to wait for, if the server is storing the image in the background.
fn finalizing_session(reply: &Reply) -> Option<String> {
    let body = reply.json()?;
    if body["status"].as_str() != Some("finalizing") {
        return None;
    }
    body["session_id"].as_str().map(str::to_string)
}

/// Ask the session how it went until it has an answer, and hand back its last state.
async fn wait_for_image(
    wire: &Wire,
    url: reqwest::Url,
    session: &str,
    timeout_secs: u64,
) -> Result<Reply> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut pause = POLL_FIRST;
    loop {
        let reply = wire
            .send(
                "check on the upload",
                wire.request(Method::GET, url.clone()),
            )
            .await?;
        let body = reply.json().unwrap_or_default();
        match body["status"].as_str() {
            Some("completed") => return Ok(reply),
            // `receiving` is a finalize that gave the session back, to be tried again.
            Some("failed" | "receiving") => {
                let reason = body["finalize_error"]
                    .as_str()
                    .unwrap_or("the server gave no reason");
                return Err(AkError::ServerError(format!(
                    "The server couldn't store the image: {reason} (session {session})"
                ))
                .into());
            }
            _ => {}
        }
        if Instant::now() >= deadline {
            return Err(AkError::ServerError(format!(
                "The server is still storing the image after {timeout_secs}s. It may yet finish: \
                 `ak api GET {}` shows how it's going",
                url.path()
            ))
            .into());
        }
        tokio::time::sleep(pause).await;
        pause = (pause * 2).min(POLL_MOST);
    }
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
