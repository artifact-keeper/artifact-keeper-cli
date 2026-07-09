use std::time::Duration;

use miette::{IntoDiagnostic, Result};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};

use crate::cli::GlobalArgs;
use crate::config::credentials::{StoredCredential, get_credential};
use crate::config::{AppConfig, InstanceConfig};
use crate::error::AkError;
use crate::transport;

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

    // Sending a bearer token over plaintext HTTP to a non-loopback host
    // exposes it to on-path observers; warn unless the user opted in.
    transport::warn_if_insecure(instance_name, instance);

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

/// Resolve instance and return the base URL and Bearer auth header value.
///
/// Used by chunked upload which makes raw HTTP calls outside the SDK.
pub fn resolve_base_url_and_auth(global: &GlobalArgs) -> Result<(String, String)> {
    let config = AppConfig::load()?;
    let (name, instance) = config.resolve_instance(global.instance.as_deref())?;
    transport::warn_if_insecure(name, instance);
    let cred = get_credential(name)?;
    let auth_header = format!("Bearer {}", cred.access_token);
    Ok((instance.url.clone(), auth_header))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_client_with_valid_token() {
        let instance = InstanceConfig {
            url: "https://example.com".to_string(),
            api_version: "v1".to_string(),
            allow_insecure_http: false,
        };
        let cred = StoredCredential {
            access_token: "test-token-abc123".to_string(),
            refresh_token: None,
        };

        let client = build_client("test", &instance, Some(&cred));
        assert!(client.is_ok());
    }

    #[test]
    fn build_client_with_empty_token() {
        let instance = InstanceConfig {
            url: "https://example.com".to_string(),
            api_version: "v1".to_string(),
            allow_insecure_http: false,
        };
        let cred = StoredCredential {
            access_token: String::new(),
            refresh_token: None,
        };

        // Empty token is technically valid for header construction
        let client = build_client("test", &instance, Some(&cred));
        assert!(client.is_ok());
    }

    #[test]
    fn build_client_different_urls() {
        let urls = vec![
            "https://registry.example.com",
            "http://localhost:8080",
            "https://internal.corp.net:8443/api",
        ];

        for url in urls {
            let instance = InstanceConfig {
                url: url.to_string(),
                api_version: "v1".to_string(),
                allow_insecure_http: false,
            };
            let cred = StoredCredential {
                access_token: "token".to_string(),
                refresh_token: None,
            };

            let client = build_client("test", &instance, Some(&cred));
            assert!(client.is_ok(), "Failed to build client for URL: {url}");
        }
    }
}
