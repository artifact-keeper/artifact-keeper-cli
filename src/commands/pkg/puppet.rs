//! `ak pkg puppet publish`: the Forge upload. The server needs the module's owner, name
//! and version in a JSON field beside the tarball, so they're read from
//! `<module>/metadata.json` inside it, where the name is `owner-module`.

use std::path::PathBuf;

use clap::Subcommand;
use miette::Result;
use reqwest::Method;
use reqwest::multipart::Form;
use serde_json::{Value, json};

use super::archive::require_tar_gz_entry;
use super::wire::{Upload, Wire, emit};
use crate::cli::GlobalArgs;
use crate::error::AkError;

#[derive(Subcommand)]
pub enum PuppetCommand {
    /// Upload a module from `pdk build`
    #[command(after_help = "Examples:\n  ak pkg puppet publish my-forge acme-demo-1.0.0.tar.gz")]
    Publish {
        /// Repository key
        repo: String,
        /// The module's .tar.gz, with metadata.json inside
        file: PathBuf,
    },
}

pub async fn execute(command: PuppetCommand, global: &GlobalArgs) -> Result<()> {
    let PuppetCommand::Publish { repo, file } = command;
    let wire = Wire::new(global)?;
    let upload = Upload::open(&file)?;
    let metadata = require_tar_gz_entry(&file, "metadata.json", |parts| {
        parts.len() == 2 && parts[1] == "metadata.json"
    })?;
    let metadata: Value = serde_json::from_slice(&metadata)
        .map_err(|e| AkError::Usage(format!("The metadata.json in the module: {e}")))?;
    let module = module_field(&metadata)?;
    let label = format!(
        "{}-{}-{}",
        module["owner"].as_str().unwrap_or_default(),
        module["name"].as_str().unwrap_or_default(),
        module["version"].as_str().unwrap_or_default()
    );
    let form = Form::new()
        .text("module", module.to_string())
        .part("file", upload.part("application/gzip").await?);
    let url = wire.url(&["puppet", &repo, "v3", "releases"]);
    let reply = wire
        .send(
            "upload the module",
            wire.request(Method::POST, url).multipart(form),
        )
        .await?;
    emit(
        &reply,
        &label,
        &format!("Published {label} to {repo}."),
        global,
    );
    Ok(())
}

/// `{"name": "acme-demo", ...}` as the owner, module name and version the server wants.
/// The whole document goes too, which the server keeps with the release.
fn module_field(metadata: &Value) -> Result<Value> {
    let full = metadata["name"].as_str().unwrap_or_default();
    let split = full.split_once('-').or_else(|| full.split_once('/'));
    let (Some((owner, name)), Some(version)) = (split, metadata["version"].as_str()) else {
        return Err(AkError::Usage(
            "The module's metadata.json needs a name like owner-module, and a version".to_string(),
        )
        .into());
    };
    let mut module = metadata.clone();
    module["owner"] = json!(owner);
    module["name"] = json!(name);
    module["version"] = json!(version);
    Ok(module)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_name_is_split_into_owner_and_module() {
        let module =
            module_field(&json!({"name": "acme-demo", "version": "1.0.0", "license": "MIT"}))
                .unwrap();
        assert_eq!(module["owner"], "acme");
        assert_eq!(module["name"], "demo");
        assert_eq!(module["license"], "MIT");
        assert!(module_field(&json!({"name": "demo", "version": "1"})).is_err());
    }
}
