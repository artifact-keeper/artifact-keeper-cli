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

    let builder = reqwest::ClientBuilder::new()
        .default_headers(headers)
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(30));
    let http_client = transport::apply_custom_ca(builder)?
        .build()
        .into_diagnostic()?;

    Ok(artifact_keeper_sdk::Client::new_with_client(
        &instance.url,
        http_client,
    ))
}

/// Build an unauthenticated SDK client for a URL, honoring the custom CA
/// configuration (`--ca-cert` / `AK_CA_CERT`).
///
/// Used by pre-auth flows (login, TOTP verify, setup status) that must work
/// against instances behind a private CA before any credentials exist.
pub fn anon_client(url: &str) -> Result<artifact_keeper_sdk::Client> {
    let builder = reqwest::ClientBuilder::new()
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(30));
    let http_client = transport::apply_custom_ca(builder)?
        .build()
        .into_diagnostic()?;
    Ok(artifact_keeper_sdk::Client::new_with_client(
        url,
        http_client,
    ))
}

/// Build a plain reqwest client (no default auth headers) honoring the custom
/// CA configuration, for raw HTTP calls made outside the SDK (chunked upload,
/// SSE streams, multipart imports).
///
/// Deliberately sets no overall request timeout: these paths stream large
/// bodies (uploads/downloads) where a fixed deadline would be wrong.
pub fn raw_http_client() -> Result<reqwest::Client> {
    let builder = reqwest::ClientBuilder::new().connect_timeout(Duration::from_secs(15));
    transport::apply_custom_ca(builder)?
        .build()
        .into_diagnostic()
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

    anon_client(&instance.url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_client_with_valid_token() {
        // These "clean state" build tests must not observe an `AK_CA_CERT` set
        // by a concurrently-running custom-CA test (in this module or in
        // `transport`), which would make `build_client` fail loading that CA.
        // Serialize on the shared env lock and clear the var, matching the
        // custom-CA tests below.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var(transport::CA_CERT_ENV) };

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
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var(transport::CA_CERT_ENV) };

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
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var(transport::CA_CERT_ENV) };

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

    // ---- custom CA (--ca-cert / AK_CA_CERT) ----

    use crate::test_utils::ENV_LOCK;
    use crate::transport::test_ca::{TEST_CA_PEM_1, TEST_CA_PEM_2};

    fn https_instance() -> InstanceConfig {
        InstanceConfig {
            url: "https://registry.internal.corp:8443".to_string(),
            api_version: "v1".to_string(),
            allow_insecure_http: false,
        }
    }

    fn cred() -> StoredCredential {
        StoredCredential {
            access_token: "token".to_string(),
            refresh_token: None,
        }
    }

    #[test]
    fn build_client_with_custom_ca_bundle() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("bundle.pem");
        std::fs::write(&path, format!("{TEST_CA_PEM_1}{TEST_CA_PEM_2}")).unwrap();
        unsafe { std::env::set_var(transport::CA_CERT_ENV, &path) };

        let client = build_client("test", &https_instance(), Some(&cred()));
        assert!(client.is_ok(), "{:?}", client.err());
        assert!(anon_client("https://registry.internal.corp:8443").is_ok());
        assert!(raw_http_client().is_ok());

        unsafe { std::env::remove_var(transport::CA_CERT_ENV) };
    }

    #[test]
    fn build_client_with_invalid_ca_is_clear_error() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("bad.pem");
        std::fs::write(&path, "not a certificate").unwrap();
        unsafe { std::env::set_var(transport::CA_CERT_ENV, &path) };

        for msg in [
            build_client("test", &https_instance(), Some(&cred()))
                .err()
                .map(|e| e.to_string()),
            anon_client("https://registry.internal.corp:8443")
                .err()
                .map(|e| e.to_string()),
            raw_http_client().err().map(|e| e.to_string()),
        ] {
            let msg = msg.expect("client build must fail with an invalid CA file");
            assert!(msg.contains("CA certificate error"), "{msg}");
        }

        unsafe { std::env::remove_var(transport::CA_CERT_ENV) };
    }

    #[test]
    fn build_client_with_missing_ca_file_is_clear_error() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var(transport::CA_CERT_ENV, "/nonexistent/ca.pem") };

        let err = build_client("test", &https_instance(), Some(&cred()))
            .map(|_| ())
            .expect_err("client build must fail with a missing CA file");
        assert!(err.to_string().contains("cannot read"), "{err}");

        unsafe { std::env::remove_var(transport::CA_CERT_ENV) };
    }
}
