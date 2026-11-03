//! `ak pkg go publish`. A module zip already says what it is: every path in it starts
//! with `<module>@<version>/`, and its `go.mod` is inside. The proxy route takes the
//! zip and the `.mod` as two files.

use std::io::Read;
use std::path::{Path, PathBuf};

use clap::Subcommand;
use miette::{IntoDiagnostic, Result};
use reqwest::Method;

use super::wire::{Upload, Wire, emit};
use crate::cli::GlobalArgs;
use crate::error::AkError;

#[derive(Subcommand)]
pub enum GoCommand {
    /// Upload a module zip and its go.mod
    #[command(after_help = "\
Make the zip with `go mod download`, or anything that follows the module zip layout.

Examples:
  ak pkg go publish my-go example.com-demo-v1.0.0.zip
  ak pkg go publish my-go v1.0.0.zip --mod go.mod")]
    Publish {
        /// Repository key
        repo: String,
        /// The module zip
        file: PathBuf,
        /// go.mod to use, instead of the one in the zip
        #[arg(long, value_name = "FILE")]
        r#mod: Option<PathBuf>,
    },
}

pub async fn execute(command: GoCommand, global: &GlobalArgs) -> Result<()> {
    let GoCommand::Publish { repo, file, r#mod } = command;
    let wire = Wire::new(global)?;
    let upload = Upload::open(&file)?;
    let zip_path = file.clone();
    let contents = tokio::task::spawn_blocking(move || read_module_zip(&zip_path))
        .await
        .into_diagnostic()??;
    let go_mod = match &r#mod {
        Some(path) => tokio::fs::read(path)
            .await
            .map_err(|e| AkError::ConfigError(format!("Can't read {}: {e}", path.display())))?,
        None => contents.go_mod.ok_or_else(|| {
            AkError::ConfigError(format!(
                "{} has no go.mod at its top level. Give one with --mod",
                file.display()
            ))
        })?,
    };
    let module = escape_module_path(&contents.module);
    let mut base: Vec<&str> = vec!["go", repo.as_str()];
    base.extend(module.split('/'));
    base.push("@v");

    // The .mod first: a proxy that lists a version needs both.
    let mod_name = format!("{}.mod", contents.version);
    let mut segments = base.clone();
    segments.push(&mod_name);
    wire.send(
        "upload go.mod",
        wire.request(Method::PUT, wire.url(&segments)).body(go_mod),
    )
    .await?;

    let zip_name = format!("{}.zip", contents.version);
    let mut segments = base.clone();
    segments.push(&zip_name);
    let request = upload
        .attach(
            wire.request(Method::PUT, wire.url(&segments)),
            "application/zip",
        )
        .await?;
    let reply = wire.send("upload the module", request).await?;
    let id = format!("{}@{}", contents.module, contents.version);
    emit(&reply, &id, &format!("Published {id} to {repo}."), global);
    Ok(())
}

struct ModuleZip {
    module: String,
    version: String,
    go_mod: Option<Vec<u8>>,
}

fn read_module_zip(file: &Path) -> Result<ModuleZip> {
    let bad = |e: String| AkError::ConfigError(format!("{}: {e}", file.display()));
    let opened = std::fs::File::open(file).map_err(|e| bad(e.to_string()))?;
    let mut archive = zip::ZipArchive::new(opened).map_err(|e| bad(e.to_string()))?;
    let first = archive
        .by_index(0)
        .map_err(|e| bad(e.to_string()))?
        .name()
        .map_err(|e| bad(e.to_string()))?
        .to_string();
    let prefix = first
        .split_once("@")
        .and_then(|(module, rest)| {
            rest.split_once('/')
                .map(|(version, _)| (module.to_string(), version.to_string()))
        })
        .ok_or_else(|| {
            bad(format!(
                "paths in a module zip start with <module>@<version>/, and `{first}` doesn't"
            ))
        })?;
    let go_mod_path = format!("{}@{}/go.mod", prefix.0, prefix.1);
    let go_mod = match archive.by_name(&go_mod_path) {
        Ok(mut entry) => {
            let mut content = Vec::new();
            entry
                .read_to_end(&mut content)
                .map_err(|e| bad(e.to_string()))?;
            Some(content)
        }
        Err(_) => None,
    };
    Ok(ModuleZip {
        module: prefix.0,
        version: prefix.1,
        go_mod,
    })
}

/// The proxy protocol writes an uppercase letter as `!` and the lowercase one.
fn escape_module_path(module: &str) -> String {
    let mut out = String::with_capacity(module.len());
    for c in module.chars() {
        if c.is_ascii_uppercase() {
            out.push('!');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_paths_are_case_escaped() {
        assert_eq!(
            escape_module_path("github.com/Azure/demo"),
            "github.com/!azure/demo"
        );
    }
}
