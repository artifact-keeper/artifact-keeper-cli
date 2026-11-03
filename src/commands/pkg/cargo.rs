//! `ak pkg cargo publish`: what `cargo publish` sends.
//!
//! The body is a little-endian u32 length and a JSON description, then a u32 length
//! and the `.crate`. The registry's index is built from that JSON, so it has to carry
//! the dependencies and features of the crate: the `Cargo.toml` inside a `.crate` is
//! the normalized one cargo wrote, and has what's needed.

use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};
use miette::Result;
use reqwest::Method;
use serde_json::{Map, Value, json};

use super::archive::{require_tar_gz_entry, tar_gz_entry};
use super::wire::{Upload, Wire, emit};
use crate::cli::GlobalArgs;
use crate::error::AkError;

/// Where a dependency with no `registry-index` comes from.
const CRATES_IO_INDEX: &str = "https://github.com/rust-lang/crates.io-index";

#[derive(Clone, Copy, ValueEnum)]
pub enum Endpoint {
    /// /cargo/<repo>/api/v1/crates/new
    Cargo,
    /// /api/cargo/<repo>/api/v1/crates/new, the same handler
    ApiCargo,
}

#[derive(Subcommand)]
pub enum CargoCommand {
    /// Publish a .crate file, as `cargo publish` does
    #[command(after_help = "\
Make the file with `cargo package`. Its name, version, dependencies and features are
read from the Cargo.toml inside it, so dependents can resolve it from the index.

Examples:
  ak pkg cargo publish my-cargo target/package/demo-1.0.0.crate")]
    Publish {
        /// Repository key
        repo: String,
        /// The .crate file
        file: PathBuf,
        /// Which of the server's two equivalent URLs to send to
        #[arg(long, value_enum, default_value = "cargo")]
        endpoint: Endpoint,
    },
}

pub async fn execute(command: CargoCommand, global: &GlobalArgs) -> Result<()> {
    let CargoCommand::Publish {
        repo,
        file,
        endpoint,
    } = command;
    let wire = Wire::new(global)?;
    let upload = Upload::open(&file)?;
    let manifest = require_tar_gz_entry(&file, "Cargo.toml", |parts| {
        parts.len() == 2 && parts[1] == "Cargo.toml"
    })?;
    let manifest: toml::Value = toml::from_str(&String::from_utf8_lossy(&manifest))
        .map_err(|e| AkError::Usage(format!("The Cargo.toml in the crate: {e}")))?;
    let mut metadata = publish_metadata(&manifest, &repo)?;
    if let Some(readme) = manifest
        .get("package")
        .and_then(|p| p.get("readme"))
        .and_then(|r| r.as_str())
    {
        let wanted = readme.trim_start_matches("./").to_string();
        let found = tar_gz_entry(&file, |parts| {
            parts[1..].join("/") == wanted && parts.len() > 1
        })?;
        if let Some((_, content)) = found {
            metadata["readme"] = json!(String::from_utf8_lossy(&content));
        }
    }
    let name = metadata["name"].as_str().unwrap_or_default().to_string();
    let version = metadata["vers"].as_str().unwrap_or_default().to_string();
    let body = frame(&metadata, &upload.read().await?)?;
    let segments: &[&str] = match endpoint {
        Endpoint::Cargo => &["cargo", &repo, "api", "v1", "crates", "new"],
        Endpoint::ApiCargo => &["api", "cargo", &repo, "api", "v1", "crates", "new"],
    };
    let reply = wire
        .send(
            "publish the crate",
            wire.request(Method::PUT, wire.url(segments)).body(body),
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

/// The length-prefixed body of a publish.
fn frame(metadata: &Value, crate_file: &[u8]) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(metadata).expect("JSON value serializes");
    let too_big = |_| AkError::Usage("The crate is too large to publish".to_string());
    let json_len = u32::try_from(json.len()).map_err(too_big)?;
    let crate_len = u32::try_from(crate_file.len()).map_err(too_big)?;
    let mut body = Vec::with_capacity(8 + json.len() + crate_file.len());
    body.extend_from_slice(&json_len.to_le_bytes());
    body.extend_from_slice(&json);
    body.extend_from_slice(&crate_len.to_le_bytes());
    body.extend_from_slice(crate_file);
    Ok(body)
}

/// The JSON cargo sends for a manifest. See `NewCrate` in the `crates-io` crate.
fn publish_metadata(manifest: &toml::Value, repo: &str) -> Result<Value> {
    let package = manifest
        .get("package")
        .ok_or_else(|| AkError::Usage("The crate's Cargo.toml has no [package]".to_string()))?;
    let text = |key: &str| package.get(key).and_then(|v| v.as_str());
    let list = |key: &str| {
        package
            .get(key)
            .map(toml_to_json)
            .filter(Value::is_array)
            .unwrap_or_else(|| json!([]))
    };
    let (Some(name), Some(version)) = (text("name"), text("version")) else {
        return Err(AkError::Usage(
            "The crate's Cargo.toml has no package name or version".to_string(),
        )
        .into());
    };

    let mut deps = Vec::new();
    let sections = [
        ("dependencies", "normal"),
        ("dev-dependencies", "dev"),
        ("build-dependencies", "build"),
        // Cargo accepts the old spellings in a manifest it didn't normalize.
        ("dev_dependencies", "dev"),
        ("build_dependencies", "build"),
    ];
    for (section, kind) in sections {
        collect_deps(manifest.get(section), kind, None, repo, &mut deps);
        if let Some(targets) = manifest.get("target").and_then(|t| t.as_table()) {
            for (target, table) in targets {
                collect_deps(table.get(section), kind, Some(target), repo, &mut deps);
            }
        }
    }

    Ok(json!({
        "name": name,
        "vers": version,
        "deps": deps,
        "features": manifest.get("features").map(toml_to_json).unwrap_or_else(|| json!({})),
        "authors": list("authors"),
        "description": text("description"),
        "documentation": text("documentation"),
        "homepage": text("homepage"),
        "readme": null,
        "readme_file": text("readme"),
        "keywords": list("keywords"),
        "categories": list("categories"),
        "license": text("license"),
        "license_file": text("license-file"),
        "repository": text("repository"),
        "badges": {},
        "links": text("links"),
        "rust_version": text("rust-version"),
    }))
}

fn collect_deps(
    section: Option<&toml::Value>,
    kind: &str,
    target: Option<&str>,
    repo: &str,
    deps: &mut Vec<Value>,
) {
    let Some(table) = section.and_then(|s| s.as_table()) else {
        return;
    };
    for (key, dep) in table {
        deps.push(dependency(key, dep, kind, target, repo));
    }
}

fn dependency(key: &str, dep: &toml::Value, kind: &str, target: Option<&str>, repo: &str) -> Value {
    let field = |name: &str| dep.get(name);
    let version = dep
        .as_str()
        .or_else(|| field("version").and_then(|v| v.as_str()))
        .unwrap_or("*");
    let renamed = field("package").and_then(|p| p.as_str());
    let default_features = field("default-features")
        .or_else(|| field("default_features"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    // None means this same registry, as it does to cargo. A dependency that names no
    // registry in a packaged manifest comes from crates.io.
    let registry = match field("registry-index").and_then(|v| v.as_str()) {
        Some(index)
            if index.contains(&format!("/{repo}/")) || index.ends_with(&format!("/{repo}")) =>
        {
            None
        }
        Some(index) => Some(index.to_string()),
        None => Some(CRATES_IO_INDEX.to_string()),
    };
    let mut out = Map::new();
    out.insert(
        "optional".into(),
        json!(field("optional").and_then(|v| v.as_bool()).unwrap_or(false)),
    );
    out.insert("default_features".into(), json!(default_features));
    out.insert("name".into(), json!(renamed.unwrap_or(key)));
    out.insert(
        "features".into(),
        field("features")
            .map(toml_to_json)
            .unwrap_or_else(|| json!([])),
    );
    out.insert("version_req".into(), json!(version));
    out.insert("target".into(), json!(target));
    out.insert("kind".into(), json!(kind));
    out.insert("registry".into(), json!(registry));
    out.insert("explicit_name_in_toml".into(), json!(renamed.map(|_| key)));
    Value::Object(out)
}

fn toml_to_json(value: &toml::Value) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_is_two_length_prefixed_parts() {
        let body = frame(&json!({"name": "a"}), b"CRATE").unwrap();
        let json_len = u32::from_le_bytes(body[0..4].try_into().unwrap()) as usize;
        let parsed: Value = serde_json::from_slice(&body[4..4 + json_len]).unwrap();
        assert_eq!(parsed["name"], "a");
        let at = 4 + json_len;
        assert_eq!(u32::from_le_bytes(body[at..at + 4].try_into().unwrap()), 5);
        assert_eq!(&body[at + 4..], b"CRATE");
    }

    #[test]
    fn metadata_carries_what_the_index_needs() {
        let manifest: toml::Value = toml::from_str(
            r#"
            [package]
            name = "demo"
            version = "1.2.3"
            license = "MIT"
            rust-version = "1.70"
            keywords = ["a"]

            [features]
            default = ["x"]
            x = []

            [dependencies.serde]
            version = "1.0"
            features = ["derive"]
            default-features = false

            [dependencies.renamed]
            version = "2"
            package = "real"
            optional = true
            registry-index = "sparse+http://h/cargo/here/"

            [dev-dependencies.tester]
            version = "3"

            [target."cfg(unix)".dependencies.libc]
            version = "0.2"
            "#,
        )
        .unwrap();
        let meta = publish_metadata(&manifest, "here").unwrap();
        assert_eq!(meta["vers"], "1.2.3");
        assert_eq!(meta["rust_version"], "1.70");
        assert_eq!(meta["features"]["default"], json!(["x"]));
        let deps = meta["deps"].as_array().unwrap();
        let find = |name: &str| deps.iter().find(|d| d["name"] == name).unwrap();
        assert_eq!(find("serde")["default_features"], false);
        assert_eq!(find("serde")["features"], json!(["derive"]));
        assert_eq!(find("serde")["registry"], CRATES_IO_INDEX);
        assert_eq!(find("real")["explicit_name_in_toml"], "renamed");
        assert_eq!(find("real")["optional"], true);
        assert_eq!(find("real")["registry"], Value::Null);
        assert_eq!(find("tester")["kind"], "dev");
        assert_eq!(find("libc")["target"], "cfg(unix)");
    }
}
