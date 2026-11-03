use std::time::Duration;

use miette::{IntoDiagnostic, Result};
use reqwest::Url;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};

use crate::cli::GlobalArgs;
use crate::config::credentials::{StoredCredential, get_credential};
use crate::config::{AppConfig, InstanceConfig};
use crate::error::AkError;
use crate::transport;

/// The redirect policy for every client that can send a credential.
///
/// reqwest decides whether to keep `Authorization` one hop at a time, looking only
/// at that hop's host and port, and a policy can't change what it sends: only
/// follow or refuse. So refuse the hops where the header would come back, or stay,
/// somewhere it shouldn't. Everything else, including a redirect to storage on
/// another host, which gets no token, goes by reqwest's default policy.
pub fn redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        match unsafe_redirect(attempt.previous(), attempt.url()) {
            Some(reason) => attempt.error(reason),
            None => reqwest::redirect::Policy::default().redirect(attempt),
        }
    })
}

/// Why following a redirect to `to` would expose a credential, if it would.
/// `chain` is every URL requested so far, the one that redirected last.
fn unsafe_redirect(chain: &[Url], to: &Url) -> Option<&'static str> {
    let (origin, from) = (chain.first()?, chain.last()?);
    // reqwest drops the header on any other hop, so nothing to protect there. On
    // this kind of hop it sends the header, even if the hop before dropped it.
    let header_sent = from.host_str() == to.host_str()
        && from.port_or_known_default() == to.port_or_known_default();
    if !header_sent {
        return None;
    }
    if to.scheme() == "http" && chain.iter().any(|url| url.scheme() == "https") {
        return Some(
            "refusing a redirect from https to plain http, which would send your \
             credentials unencrypted",
        );
    }
    if chain.iter().any(|url| !same_server(url, origin)) {
        return Some(
            "refusing a redirect that has left the instance, which would send your \
             credentials to another server",
        );
    }
    None
}

/// The same host and port, where `http://host` and `https://host` count as the
/// same: redirecting from one to the other is how a server moves clients to TLS.
/// `api.rs` has a stricter `same_origin`, because it can drop the token itself.
fn same_server(a: &Url, b: &Url) -> bool {
    a.host_str() == b.host_str()
        && (a.port_or_known_default() == b.port_or_known_default()
            || (a.port().is_none() && b.port().is_none()))
}

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
        .redirect(redirect_policy())
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
        .redirect(redirect_policy())
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
    let builder = raw_http_client_builder(redirect_policy());
    transport::apply_custom_ca(builder)?
        .build()
        .into_diagnostic()
}

/// The starting point of [`raw_http_client`], for a caller that sets its own
/// redirect policy. Apply the custom CA before building.
pub fn raw_http_client_builder(redirects: reqwest::redirect::Policy) -> reqwest::ClientBuilder {
    reqwest::ClientBuilder::new()
        .connect_timeout(Duration::from_secs(15))
        .redirect(redirects)
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

    fn is_refused(chain: &[&str], to: &str) -> bool {
        let chain: Vec<Url> = chain.iter().map(|u| Url::parse(u).unwrap()).collect();
        unsafe_redirect(&chain, &Url::parse(to).unwrap()).is_some()
    }

    #[test]
    fn redirects_that_would_expose_the_token_are_refused() {
        for (chain, to) in [
            // Same host and port, so reqwest keeps the header.
            (vec!["https://h:8443/a"], "http://h:8443/a"),
            // https://h to http://h drops it, and the next hop brings it back.
            (vec!["https://h/a", "http://h/a"], "http://h/b"),
            // Off to another server, which redirects to itself: it's sent the token.
            (vec!["https://h/a", "https://other/a"], "https://other/b"),
            (vec!["https://h/a", "https://h:8443/a"], "https://h:8443/b"),
            // Back on the instance, but another server chose where.
            (
                vec!["https://h/a", "https://other/a", "https://h/b"],
                "https://h/c",
            ),
        ] {
            assert!(is_refused(&chain, to), "{chain:?} -> {to}");
        }
    }

    #[test]
    fn normal_redirects_are_followed() {
        for (chain, to) in [
            // Within the origin.
            (vec!["https://h/a"], "https://h/b"),
            (
                vec!["https://h:8443/a", "https://h:8443/b"],
                "https://h:8443/c",
            ),
            (vec!["http://h:8080/a"], "http://h:8080/b"),
            // An upgrade to TLS, then a redirect there.
            (vec!["http://h/a"], "https://h/a"),
            (vec!["http://h/a", "https://h/a"], "https://h/b"),
            (vec!["http://h:8080/a"], "https://h:8080/a"),
            // Elsewhere, where reqwest drops the header: presigned storage URLs.
            (vec!["https://h/a"], "https://storage/a"),
            (vec!["https://h/a"], "http://storage:9000/a"),
            (vec!["https://h/a"], "http://h/a"),
        ] {
            assert!(!is_refused(&chain, to), "{chain:?} -> {to}");
        }
    }

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
