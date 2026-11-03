use std::time::Duration;

use miette::{IntoDiagnostic, Result};
use reqwest::Url;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};

use crate::cli::GlobalArgs;
use crate::config::credentials::{StoredCredential, get_credential};
use crate::config::{AppConfig, InstanceConfig};
use crate::error::AkError;
use crate::transport;

/// The redirect policy for every client except a download's.
///
/// An API request stays on its server, over TLS if it started that way. A policy
/// can follow or refuse, but it can't see the method, and a redirect can resend the
/// body: tower-http only turns a POST into a GET on a 301 or 302, so a PUT or PATCH
/// keeps its body, and that body can be a password or a client secret. reqwest
/// dropping the token doesn't protect a body. There's no loss in refusing, because
/// without the token another server has nothing to answer an API request with.
pub fn redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        match api_redirect_refusal(attempt.previous(), attempt.url()) {
            Some(reason) => refuse(attempt, reason),
            None => reqwest::redirect::Policy::default().redirect(attempt),
        }
    })
}

/// The redirect policy for a client that only makes GET requests for content. With
/// no body to protect, it can go on to storage on another host, which can be plain
/// HTTP, such as a presigned URL for MinIO in a cluster.
fn download_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        match download_redirect_refusal(attempt.previous(), attempt.url()) {
            Some(reason) => refuse(attempt, reason),
            None => reqwest::redirect::Policy::default().redirect(attempt),
        }
    })
}

/// Refuse a redirect, and say why here too: most raw HTTP callers print reqwest's
/// error without its cause, which reads only "error following redirect".
fn refuse(
    attempt: reqwest::redirect::Attempt<'_>,
    reason: &'static str,
) -> reqwest::redirect::Action {
    eprintln!("Not following the redirect: {reason}");
    attempt.error(reason)
}

const REFUSED_DOWNGRADE: &str = "refusing a redirect from https to plain http, which would send \
     your credentials or the request body unencrypted";
const REFUSED_OTHER_SERVER: &str = "refusing a redirect that leaves the instance, which would \
     send your credentials or the request body to another server";

fn is_downgrade(chain: &[Url], to: &Url) -> bool {
    to.scheme() == "http" && chain.iter().any(|url| url.scheme() == "https")
}

/// Why an API request shouldn't follow a redirect to `to`, if so. `chain` is every
/// URL requested so far, the one that redirected last.
fn api_redirect_refusal(chain: &[Url], to: &Url) -> Option<&'static str> {
    if is_downgrade(chain, to) {
        return Some(REFUSED_DOWNGRADE);
    }
    (!same_server(chain.first()?, to)).then_some(REFUSED_OTHER_SERVER)
}

/// Why a download shouldn't follow a redirect to `to`, if so. Its only secret is the
/// token. reqwest decides about `Authorization` one hop at a time, from that hop's
/// host and port, so these are the hops where it would send it somewhere it shouldn't.
fn download_redirect_refusal(chain: &[Url], to: &Url) -> Option<&'static str> {
    let (origin, from) = (chain.first()?, chain.last()?);
    let header_sent = from.host_str() == to.host_str()
        && from.port_or_known_default() == to.port_or_known_default();
    if !header_sent {
        return None;
    }
    if is_downgrade(chain, to) {
        return Some(REFUSED_DOWNGRADE);
    }
    chain
        .iter()
        .any(|url| !same_server(url, origin))
        .then_some(REFUSED_OTHER_SERVER)
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
    sdk_client(instance_name, instance, cred, redirect_policy())
}

/// [`build_client`] for a client used only to read and download, as `migrate` reads
/// its source. Its redirects can reach presigned storage.
pub fn build_reading_client(
    instance_name: &str,
    instance: &InstanceConfig,
    cred: Option<&StoredCredential>,
) -> Result<artifact_keeper_sdk::Client> {
    sdk_client(instance_name, instance, cred, download_redirect_policy())
}

fn sdk_client(
    instance_name: &str,
    instance: &InstanceConfig,
    cred: Option<&StoredCredential>,
    redirects: reqwest::redirect::Policy,
) -> Result<artifact_keeper_sdk::Client> {
    build_client_with_timeout(
        instance_name,
        instance,
        cred,
        Duration::from_secs(30),
        redirects,
    )
}

fn build_client_with_timeout(
    instance_name: &str,
    instance: &InstanceConfig,
    cred: Option<&StoredCredential>,
    timeout: Duration,
    redirects: reqwest::redirect::Policy,
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
        .redirect(redirects)
        .connect_timeout(Duration::from_secs(15))
        .timeout(timeout);
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

/// [`raw_http_client`] for GET requests that fetch content. Its redirects can reach
/// presigned storage.
pub fn raw_download_client() -> Result<reqwest::Client> {
    let builder = raw_http_client_builder(download_redirect_policy());
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

/// [`client_for`] for a server operation that can run for minutes. The server
/// keeps working after a client gives up, so timing out at the usual 30 seconds
/// would report a failure for something that's still happening. This outlasts the
/// server's own 120-second limit on admin requests.
pub fn client_for_slow(global: &GlobalArgs) -> Result<artifact_keeper_sdk::Client> {
    let config = AppConfig::load()?;
    let (name, instance) = config.resolve_instance(global.instance.as_deref())?;
    build_client_with_timeout(
        name,
        instance,
        None,
        Duration::from_secs(150),
        redirect_policy(),
    )
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

    // An empty list reads as "there's nothing", when it can mean "nothing you can see".
    eprintln!("Note: not logged in to '{name}', so this is the public view. Run `ak auth login`.");
    anon_client(&instance.url)
}

/// [`client_for_optional_auth`] for what's the same whoever asks, such as a server's
/// health, so not being logged in isn't worth mentioning.
pub fn client_for_public(global: &GlobalArgs) -> Result<artifact_keeper_sdk::Client> {
    let config = AppConfig::load()?;
    let (name, instance) = config.resolve_instance(global.instance.as_deref())?;
    if let Ok(client) = build_client(name, instance, None) {
        return Ok(client);
    }
    anon_client(&instance.url)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn urls(chain: &[&str]) -> Vec<Url> {
        chain.iter().map(|u| Url::parse(u).unwrap()).collect()
    }

    fn api_refuses(chain: &[&str], to: &str) -> bool {
        api_redirect_refusal(&urls(chain), &Url::parse(to).unwrap()).is_some()
    }

    fn download_refuses(chain: &[&str], to: &str) -> bool {
        download_redirect_refusal(&urls(chain), &Url::parse(to).unwrap()).is_some()
    }

    #[test]
    fn an_api_request_stays_on_its_server_and_over_tls() {
        for (chain, to) in [
            // Plain HTTP, on any host or port: a PUT keeps its body on a 302.
            (vec!["https://h/a"], "http://h/a"),
            (vec!["https://h:8443/a"], "http://h:8443/a"),
            (vec!["https://h/a"], "http://storage:9000/a"),
            (vec!["https://h/a", "https://h/b"], "http://h/c"),
            // Another server.
            (vec!["https://h/a"], "https://other/a"),
            (vec!["https://h/a"], "https://h:8443/a"),
            (vec!["http://h:8080/a"], "http://other:8080/a"),
            (vec!["https://h/a", "https://h/b"], "https://other/c"),
        ] {
            assert!(api_refuses(&chain, to), "{chain:?} -> {to}");
        }
        for (chain, to) in [
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
        ] {
            assert!(!api_refuses(&chain, to), "{chain:?} -> {to}");
        }
    }

    #[test]
    fn a_download_can_reach_storage_but_not_expose_the_token() {
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
            assert!(download_refuses(&chain, to), "{chain:?} -> {to}");
        }
        for (chain, to) in [
            (vec!["https://h/a"], "https://h/b"),
            (vec!["http://h/a", "https://h/a"], "https://h/b"),
            // Elsewhere, where reqwest drops the header: presigned storage URLs.
            (vec!["https://h/a"], "https://storage/a"),
            (vec!["https://h/a"], "http://storage:9000/a"),
            (vec!["https://h/a"], "http://h/a"),
            (
                vec!["https://h/a", "http://storage:9000/a"],
                "http://storage:9001/a",
            ),
        ] {
            assert!(!download_refuses(&chain, to), "{chain:?} -> {to}");
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
