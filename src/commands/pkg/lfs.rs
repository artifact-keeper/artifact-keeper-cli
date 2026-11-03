//! `ak pkg lfs`: the Git LFS batch API, what `git lfs push` and `git lfs lock` send.
//!
//! An upload is three requests: the batch says which objects it wants, the object goes
//! up by its sha256, and the server is asked to verify it.

use std::path::PathBuf;

use clap::Subcommand;
use miette::Result;
use reqwest::{Method, RequestBuilder, Url};
use serde_json::{Value, json};

use super::wire::{Reply, Upload, Wire, emit};
use crate::cli::GlobalArgs;

const LFS_JSON: &str = "application/vnd.git-lfs+json";

#[derive(Subcommand)]
pub enum LfsCommand {
    /// Upload a file as an LFS object, unless the server already has it
    #[command(after_help = "\
It prints the object's oid, which is what a pointer file in git refers to.

Examples:
  ak pkg lfs upload my-lfs model.bin")]
    Upload {
        /// Repository key
        repo: String,
        /// The file
        file: PathBuf,
    },
    /// Lock a path
    Lock {
        /// Repository key
        repo: String,
        /// Path in the repository
        path: String,
        /// The ref the lock is for, such as refs/heads/main
        #[arg(long = "ref")]
        lock_ref: Option<String>,
    },
    /// List locks, split into yours and others'
    #[command(name = "locks-verify")]
    LocksVerify {
        /// Repository key
        repo: String,
        /// The ref to check
        #[arg(long = "ref")]
        lock_ref: Option<String>,
    },
    /// Release a lock
    Unlock {
        /// Repository key
        repo: String,
        /// Lock ID
        id: String,
        /// Release someone else's lock
        #[arg(long)]
        force: bool,
    },
}

fn lfs_json(wire: &Wire, url: Url, body: &Value) -> RequestBuilder {
    wire.request(Method::POST, url)
        .header(reqwest::header::ACCEPT, LFS_JSON)
        .header(reqwest::header::CONTENT_TYPE, LFS_JSON)
        .body(body.to_string())
}

fn ref_field(lock_ref: Option<String>) -> Value {
    lock_ref.map_or(Value::Null, |name| json!({"name": name}))
}

pub async fn execute(command: LfsCommand, global: &GlobalArgs) -> Result<()> {
    let wire = Wire::new(global)?;
    match command {
        LfsCommand::Upload { repo, file } => {
            let upload = Upload::open(&file)?;
            let oid = upload.sha256().await?;
            let object = json!({"oid": oid, "size": upload.len});
            let batch = wire
                .send(
                    "ask to upload the object",
                    lfs_json(
                        &wire,
                        wire.url(&["lfs", &repo, "objects", "batch"]),
                        &json!({"operation": "upload", "transfers": ["basic"],
                                "objects": [object]}),
                    ),
                )
                .await?;
            // A server that has the object offers no upload action.
            let wants_upload = batch
                .json()
                .map(|body| !body["objects"][0]["actions"]["upload"].is_null())
                .unwrap_or(true);
            if wants_upload {
                let request = upload
                    .attach(
                        wire.request(Method::PUT, wire.url(&["lfs", &repo, "objects", &oid])),
                        "application/octet-stream",
                    )
                    .await?;
                wire.send("upload the object", request).await?;
                wire.send(
                    "verify the object",
                    lfs_json(&wire, wire.url(&["lfs", &repo, "verify"]), &object),
                )
                .await?;
            }
            let reply =
                Reply::new(json!({"oid": oid, "size": upload.len, "uploaded": wants_upload}));
            let human = if wants_upload {
                format!("Uploaded {} as {oid}.", upload.name)
            } else {
                format!("{repo} already has {oid}.")
            };
            emit(&reply, &oid, &human, global);
        }
        LfsCommand::Lock {
            repo,
            path,
            lock_ref,
        } => {
            let reply = wire
                .send(
                    "lock the path",
                    lfs_json(
                        &wire,
                        wire.url(&["lfs", &repo, "locks"]),
                        &json!({"path": path, "ref": ref_field(lock_ref)}),
                    ),
                )
                .await?;
            let id = reply
                .json()
                .and_then(|body| body["lock"]["id"].as_str().map(str::to_string))
                .unwrap_or_default();
            emit(&reply, &id, &format!("Locked {path}: {id}."), global);
        }
        LfsCommand::LocksVerify { repo, lock_ref } => {
            let reply = wire
                .send(
                    "list the locks",
                    lfs_json(
                        &wire,
                        wire.url(&["lfs", &repo, "locks", "verify"]),
                        &json!({"ref": ref_field(lock_ref)}),
                    ),
                )
                .await?;
            println!("{}", String::from_utf8_lossy(&reply.body).trim());
        }
        LfsCommand::Unlock { repo, id, force } => {
            let reply = wire
                .send(
                    "release the lock",
                    lfs_json(
                        &wire,
                        wire.url(&["lfs", &repo, "locks", &id, "unlock"]),
                        &json!({"force": force}),
                    ),
                )
                .await?;
            emit(&reply, &id, &format!("Released {id}."), global);
        }
    }
    Ok(())
}
