use std::time::Duration;

use miette::{IntoDiagnostic, Result};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};

use crate::cli::GlobalArgs;
use crate::config::credentials::{StoredCredential, get_credential};
use crate::config::{AppConfig, InstanceConfig};
use crate::error::AkError;

/// Build an authenticated SDK client for the resolved instance.
///
/// If `cred` is `None`, loads from the credential store (keychain/file/env).
pub fn build_client(
    instance_name: &str,
    instance: &InstanceConfig,
    cred: Option<&StoredCredential>,
) -> Result<artifact_keeper_sdk::Client> {
    let owned_cred;
    let cred = match cred {
        Some(c) => c,
        None => {
            owned_cred = get_credential(instance_name)?;
            &owned_cred
        }
    };

    let auth_value = format!("Bearer {}", cred.access_token);
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&auth_value)
            .map_err(|e| AkError::ConfigError(format!("Invalid token: {e}")))?,
    );

    let http_client = reqwest::ClientBuilder::new()
        .default_headers(headers)
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(30))
        .build()
        .into_diagnostic()?;

    Ok(artifact_keeper_sdk::Client::new_with_client(
        &instance.url,
        http_client,
    ))
}

/// Resolve instance and build an authenticated client from GlobalArgs.
///
/// Returns the instance name, config, and SDK client for commands that
/// need all three (e.g. auth commands that display the instance name).
pub fn authenticated_client(
    global: &GlobalArgs,
) -> Result<(String, InstanceConfig, artifact_keeper_sdk::Client)> {
    let config = AppConfig::load()?;
    let (name, instance) = config.resolve_instance(global.instance.as_deref())?;
    let client = build_client(name, instance, None)?;
    Ok((name.to_string(), instance.clone(), client))
}

/// Resolve instance and return only the authenticated SDK client.
///
/// Convenience wrapper for commands that don't need the instance metadata.
pub fn client_for(global: &GlobalArgs) -> Result<artifact_keeper_sdk::Client> {
    let config = AppConfig::load()?;
    let (name, instance) = config.resolve_instance(global.instance.as_deref())?;
    build_client(name, instance, None)
}

/// Build an SDK client for the resolved instance.
///
/// Tries authenticated first; falls back to unauthenticated if no credentials are available.
/// Use this for commands that can work without auth (public repos, etc.).
pub fn client_for_optional_auth(global: &GlobalArgs) -> Result<artifact_keeper_sdk::Client> {
    let config = AppConfig::load()?;
    let (name, instance) = config.resolve_instance(global.instance.as_deref())?;

    // Try authenticated first, fall back to unauthenticated
    if let Ok(client) = build_client(name, instance, None) {
        return Ok(client);
    }

    let http_client = reqwest::ClientBuilder::new()
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(30))
        .build()
        .into_diagnostic()?;

    Ok(artifact_keeper_sdk::Client::new_with_client(
        &instance.url,
        http_client,
    ))
}
