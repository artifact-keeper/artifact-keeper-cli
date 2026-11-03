//! `ak admin plugins install <source>`: a manifest file, a ZIP or a git URL.

use std::path::Path;

use artifact_keeper_sdk::types::PluginResponse;
use miette::Result;

use crate::cli::GlobalArgs;
use crate::commands::client::{raw_http_client, resolve_base_url_and_auth};
use crate::commands::helpers::{emit_mutation_raw, raw_err, sdk_err};
use crate::error::AkError;
use crate::output;

#[derive(Debug, PartialEq, Eq)]
enum Source {
    Manifest,
    Zip,
    Git,
}

/// A file that exists is uploaded. Anything else that can't be a git URL is
/// probably a mistyped file name, so it shouldn't go to the server as a URL.
fn classify(source: &str, is_file: bool) -> std::result::Result<Source, String> {
    let is_zip = Path::new(source)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("zip"));
    if is_file {
        return Ok(if is_zip {
            Source::Zip
        } else {
            Source::Manifest
        });
    }
    let is_url = source.contains("://") || source.starts_with("git@");
    if !is_url
        && (is_zip
            || Path::new(source)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("json")))
    {
        return Err(format!("No such file: {source}"));
    }
    Ok(Source::Git)
}

pub async fn install(source: &str, git_ref: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let kind = classify(source, Path::new(source).is_file()).map_err(AkError::ConfigError)?;
    if kind != Source::Git && git_ref.is_some() {
        return Err(AkError::Usage(
            "--ref applies only to a git URL, and this is a local file.".into(),
        )
        .into());
    }
    match kind {
        Source::Manifest => install_manifest(source, global).await,
        Source::Zip => super::install_plugin_zip(source, global).await,
        Source::Git => super::install_plugin(source, git_ref, global).await,
    }
}

async fn install_manifest(path: &str, global: &GlobalArgs) -> Result<()> {
    // Not in the generated SDK, as it's multipart.
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|e| AkError::Usage(format!("Failed to read {path}: {e}")))?;
    let file_name = Path::new(path)
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("manifest.json")
        .to_string();
    let part = reqwest::multipart::Part::bytes(bytes)
        .file_name(file_name)
        .mime_str("application/json")
        .map_err(|e| sdk_err("build plugin upload", e))?;
    let form = reqwest::multipart::Form::new().part("manifest", part);

    let (base_url, auth_header) = resolve_base_url_and_auth(global)?;
    let url = format!("{}/api/v1/plugins", base_url.trim_end_matches('/'));
    let spinner = output::spinner("Installing plugin...");
    let resp = raw_http_client()?
        .post(&url)
        .header(reqwest::header::AUTHORIZATION, auth_header)
        .multipart(form)
        .send()
        .await
        .map_err(|e| sdk_err("install plugin", e))?;
    let status = resp.status();
    let body = resp
        .bytes()
        .await
        .map_err(|e| sdk_err("read plugin install response", e))?;
    spinner.finish_and_clear();
    if !status.is_success() {
        return Err(raw_err(
            "Failed to install plugin",
            status,
            &String::from_utf8_lossy(&body),
        )
        .into());
    }

    let plugin: PluginResponse = serde_json::from_slice(&body)
        .map_err(|e| crate::commands::helpers::bad_response("parse plugin install response", e))?;
    emit_mutation_raw(
        Some(&body),
        &plugin,
        &plugin.id.to_string(),
        &format!(
            "Plugin '{}' v{} installed (ID: {}, type: {}, status: {}).",
            plugin.name, plugin.version, plugin.id, plugin.plugin_type, plugin.status
        ),
        global,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_is_uploaded_by_its_extension() {
        assert_eq!(classify("plugin.json", true), Ok(Source::Manifest));
        assert_eq!(classify("manifest", true), Ok(Source::Manifest));
        assert_eq!(classify("plugin.ZIP", true), Ok(Source::Zip));
    }

    #[test]
    fn a_url_goes_to_git() {
        assert_eq!(classify("https://x.test/p.git", false), Ok(Source::Git));
        assert_eq!(classify("https://x.test/p.zip", false), Ok(Source::Git));
        assert_eq!(classify("git@x.test:p.git", false), Ok(Source::Git));
        assert_eq!(classify("x.test/p", false), Ok(Source::Git));
    }

    #[test]
    fn a_missing_file_is_not_sent_as_a_url() {
        assert!(classify("plugin.json", false).is_err());
        assert!(classify("dir/plugin.zip", false).is_err());
    }
}
