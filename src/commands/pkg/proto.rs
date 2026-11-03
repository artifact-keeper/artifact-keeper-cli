//! `ak pkg proto`: the Buf registry API, Connect RPC with JSON bodies.
//!
//! `publish` builds an Upload request from files on disk, with their contents in base64.
//! `call` sends any other RPC of the API by its short name, with the Connect headers.

use std::path::{Path, PathBuf};

use base64::Engine;
use clap::{Subcommand, ValueEnum};
use miette::Result;
use reqwest::Method;
use serde_json::{Value, json};

use super::wire::{Reply, Wire, emit};
use crate::cli::GlobalArgs;
use crate::commands::helpers::read_inline_or_file;
use crate::error::AkError;

#[derive(Clone, Copy, ValueEnum)]
pub enum Rpc {
    GetCommits,
    ListCommits,
    GetGraph,
    CreateOrUpdateLabels,
    GetLabels,
    CreateModules,
    GetModules,
    GetResources,
    Download,
    Upload,
}

impl Rpc {
    /// The route's last segment, which names the Connect service and method.
    fn path(self) -> (&'static str, &'static str) {
        match self {
            Rpc::GetCommits => ("buf.registry.module.v1.CommitService", "GetCommits"),
            Rpc::ListCommits => ("buf.registry.module.v1.CommitService", "ListCommits"),
            Rpc::GetGraph => ("buf.registry.module.v1.GraphService", "GetGraph"),
            Rpc::CreateOrUpdateLabels => (
                "buf.registry.module.v1.LabelService",
                "CreateOrUpdateLabels",
            ),
            Rpc::GetLabels => ("buf.registry.module.v1.LabelService", "GetLabels"),
            Rpc::CreateModules => ("buf.registry.module.v1.ModuleService", "CreateModules"),
            Rpc::GetModules => ("buf.registry.module.v1.ModuleService", "GetModules"),
            Rpc::GetResources => ("buf.registry.module.v1.ResourceService", "GetResources"),
            Rpc::Download => ("buf.registry.module.v1beta1.DownloadService", "Download"),
            Rpc::Upload => ("buf.registry.module.v1beta1.UploadService", "Upload"),
        }
    }
}

#[derive(Subcommand)]
pub enum ProtoCommand {
    /// Upload a module's .proto files, as `buf push` does
    #[command(after_help = "\
Each file's path in the module is its path under --root, which defaults to the current
directory.

Examples:
  ak pkg proto publish my-buf acme/demo demo/v1/a.proto buf.yaml
  ak pkg proto publish my-buf acme/demo --root src src/demo/v1/a.proto --label main")]
    Publish {
        /// Repository key
        repo: String,
        /// Module: owner/name
        module: String,
        /// The files
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Directory the paths in the module are relative to
        #[arg(long)]
        root: Option<PathBuf>,
        /// Label to set on the commit (repeatable)
        #[arg(long)]
        label: Vec<String>,
    },
    /// Call an RPC, with a JSON request body
    #[command(after_help = "\
Examples:
  ak pkg proto call my-buf get-modules --body '{\"moduleRefs\":[{\"owner\":\"acme\",\"module\":\"demo\"}]}'
  ak pkg proto call my-buf list-commits --body @request.json")]
    Call {
        /// Repository key
        repo: String,
        /// The RPC
        #[arg(value_enum)]
        rpc: Rpc,
        /// JSON body: the text itself, @file, or @- for stdin. Default: {}
        #[arg(long)]
        body: Option<String>,
    },
}

async fn rpc(wire: &Wire, repo: &str, which: Rpc, body: &Value) -> Result<Reply> {
    let (service, method) = which.path();
    wire.send(
        &format!("call {method}"),
        wire.request(Method::POST, wire.url(&["proto", repo, service, method]))
            .header("Connect-Protocol-Version", "1")
            .json(body),
    )
    .await
}

pub async fn execute(command: ProtoCommand, global: &GlobalArgs) -> Result<()> {
    let wire = Wire::new(global)?;
    match command {
        ProtoCommand::Publish {
            repo,
            module,
            files,
            root,
            label,
        } => {
            let body = upload_request(&module, &files, root.as_deref(), &label)?;
            let reply = rpc(&wire, &repo, Rpc::Upload, &body).await?;
            emit(
                &reply,
                &module,
                &format!("Published {module} to {repo}."),
                global,
            );
        }
        ProtoCommand::Call {
            repo,
            rpc: which,
            body,
        } => {
            let body: Value = match body {
                Some(body) => {
                    let text = read_inline_or_file(&body, "--body")?;
                    serde_json::from_slice(&text)
                        .map_err(|e| AkError::ConfigError(format!("--body isn't JSON: {e}")))?
                }
                None => json!({}),
            };
            let reply = rpc(&wire, &repo, which, &body).await?;
            println!("{}", String::from_utf8_lossy(&reply.body).trim());
        }
    }
    Ok(())
}

/// The Upload request for one module.
fn upload_request(
    module: &str,
    files: &[PathBuf],
    root: Option<&Path>,
    labels: &[String],
) -> Result<Value> {
    let Some((owner, name)) = module.split_once('/') else {
        return Err(
            AkError::ConfigError(format!("`{module}` isn't a module: use owner/name")).into(),
        );
    };
    let mut entries = Vec::with_capacity(files.len());
    for file in files {
        let content = std::fs::read(file)
            .map_err(|e| AkError::ConfigError(format!("Can't read {}: {e}", file.display())))?;
        let relative = match root {
            Some(root) => file.strip_prefix(root).map_err(|_| {
                AkError::ConfigError(format!("{} isn't under {}", file.display(), root.display()))
            })?,
            None => file.as_path(),
        };
        entries.push(json!({
            "path": relative.to_string_lossy().replace('\\', "/"),
            "content": base64::engine::general_purpose::STANDARD.encode(content),
        }));
    }
    let label_refs: Vec<Value> = labels.iter().map(|label| json!({"name": label})).collect();
    Ok(json!({
        "contents": [{
            "moduleRef": {"owner": owner, "module": name},
            "files": entries,
            "labelRefs": label_refs,
        }]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_upload_has_base64_contents_and_relative_paths() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("a.proto");
        std::fs::write(&file, "abc").unwrap();
        let request = upload_request(
            "acme/demo",
            &[file],
            Some(dir.path()),
            &["main".to_string()],
        )
        .unwrap();
        let content = &request["contents"][0];
        assert_eq!(content["moduleRef"]["module"], "demo");
        assert_eq!(content["files"][0]["path"], "a.proto");
        assert_eq!(content["files"][0]["content"], "YWJj");
        assert!(upload_request("nomodule", &[], None, &[]).is_err());
    }
}
