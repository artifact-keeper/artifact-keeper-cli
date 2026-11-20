//! Transport-security classification for instance URLs.
//!
//! The CLI sends bearer tokens (and, on login, passwords and one-time codes) to
//! the configured instance URL. Over plain `http://` those credentials travel in
//! cleartext, so `ak` refuses to send any of them to a non-loopback HTTP URL
//! unless the user opted in: for good with the instance's `allow_insecure_http`
//! setting (`ak instance add|update --insecure-http`), or for one command with
//! `AK_ALLOW_INSECURE_HTTP=1`. Loopback hosts (localhost / 127.0.0.0/8 / ::1)
//! are exempt because plain HTTP is the normal local development setup.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::config::InstanceConfig;
use crate::error::AkError;

/// Environment variable that globally opts in to sending credentials over
/// plaintext HTTP to non-loopback hosts.
pub const ALLOW_INSECURE_HTTP_ENV: &str = "AK_ALLOW_INSECURE_HTTP";

/// Environment variable pointing at a PEM file with additional root CA
/// certificate(s) to trust (equivalent to the global `--ca-cert` flag).
pub const CA_CERT_ENV: &str = "AK_CA_CERT";

/// Process-wide value of the `--ca-cert` flag, recorded once at startup.
///
/// Clients are constructed in many places (SDK wrappers, raw chunked-upload
/// HTTP, doctor, TUI), several of which have no access to parsed CLI args, so
/// the flag is stashed here — mirroring how `AK_ALLOW_INSECURE_HTTP` is read
/// process-globally.
static CA_CERT_OVERRIDE: OnceLock<PathBuf> = OnceLock::new();

/// Record the `--ca-cert` flag value. Called once from `Cli::execute`;
/// subsequent calls are ignored.
pub fn set_ca_cert_override(path: PathBuf) {
    let _ = CA_CERT_OVERRIDE.set(path);
}

/// Resolve the effective custom CA bundle path: the `--ca-cert` flag if given,
/// otherwise the `AK_CA_CERT` environment variable, otherwise none.
pub fn ca_cert_path() -> Option<PathBuf> {
    if let Some(path) = CA_CERT_OVERRIDE.get() {
        return Some(path.clone());
    }
    std::env::var_os(CA_CERT_ENV)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// Load one or more PEM-encoded certificates from a file.
///
/// Accepts a single certificate or a bundle (multiple concatenated
/// `-----BEGIN CERTIFICATE-----` blocks). Fails with a descriptive error if
/// the file is missing, unreadable, or contains no valid certificate.
pub fn load_ca_certificates(path: &Path) -> Result<Vec<reqwest::Certificate>, AkError> {
    let pem = std::fs::read(path).map_err(|e| {
        AkError::CaCert(format!(
            "cannot read CA certificate file '{}': {e}",
            path.display()
        ))
    })?;

    let certs = reqwest::Certificate::from_pem_bundle(&pem).map_err(|e| {
        AkError::CaCert(format!(
            "'{}' is not a valid PEM certificate file: {e}",
            path.display()
        ))
    })?;

    if certs.is_empty() {
        return Err(AkError::CaCert(format!(
            "no certificates found in '{}' (expected at least one \
             '-----BEGIN CERTIFICATE-----' block)",
            path.display()
        )));
    }

    Ok(certs)
}

/// Add the configured custom CA certificate(s) (`--ca-cert` / `AK_CA_CERT`),
/// if any, to a reqwest client builder.
///
/// The custom roots are ADDED to the default trust store — certificate
/// verification stays fully enabled. This is the supported way to talk to an
/// instance behind a private/enterprise CA; there is deliberately no
/// "disable verification" escape hatch.
pub fn apply_custom_ca(
    mut builder: reqwest::ClientBuilder,
) -> Result<reqwest::ClientBuilder, AkError> {
    if let Some(path) = ca_cert_path() {
        for cert in load_ca_certificates(&path)? {
            builder = builder.add_root_certificate(cert);
        }
    }
    Ok(builder)
}

/// The `User-Agent` the CLI sends: `ak/<version> (<os>; <arch>)`, such as
/// `ak/1.12.0 (linux; x86_64)`, so a server's access log can tell `ak` and its
/// version apart from other clients.
pub fn user_agent() -> &'static str {
    static UA: OnceLock<String> = OnceLock::new();
    UA.get_or_init(|| {
        format!(
            "ak/{} ({}; {})",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    })
}

/// The starting point for every HTTP client the CLI builds, the SDK's and the
/// raw ones alike. It sets the [`user_agent`]; apply the custom CA with
/// [`apply_custom_ca`] before building.
pub fn client_builder() -> reqwest::ClientBuilder {
    reqwest::ClientBuilder::new().user_agent(user_agent())
}

/// How safe it is to send credentials to a given instance URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportSecurity {
    /// `https://` — encrypted in transit.
    Https,
    /// `http://` to a loopback host — normal for local development.
    HttpLoopback,
    /// `http://` to a non-loopback host — credentials cross the network in
    /// cleartext.
    HttpRemote,
    /// Anything else (unparseable URL, non-http scheme). Left to the HTTP
    /// client to reject; no transport warning is emitted.
    Other,
}

/// Classify an instance URL by how it transports credentials.
pub fn classify_url(raw: &str) -> TransportSecurity {
    let parsed = match url::Url::parse(raw) {
        Ok(u) => u,
        Err(_) => return TransportSecurity::Other,
    };

    match parsed.scheme() {
        "https" => TransportSecurity::Https,
        "http" => match parsed.host() {
            Some(host) if is_loopback_host(&host) => TransportSecurity::HttpLoopback,
            Some(_) => TransportSecurity::HttpRemote,
            None => TransportSecurity::Other,
        },
        _ => TransportSecurity::Other,
    }
}

/// Whether a parsed URL host resolves to the local machine's loopback
/// interface: `localhost` (and `*.localhost`, per RFC 6761), `127.0.0.0/8`,
/// or `::1` (including the IPv4-mapped form).
fn is_loopback_host(host: &url::Host<&str>) -> bool {
    match host {
        url::Host::Domain(domain) => {
            let d = domain.to_ascii_lowercase();
            d == "localhost" || d.ends_with(".localhost")
        }
        url::Host::Ipv4(ip) => ip.is_loopback(),
        url::Host::Ipv6(ip) => {
            ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

/// Whether the `AK_ALLOW_INSECURE_HTTP` environment variable opts in to
/// plaintext HTTP for this invocation.
pub fn insecure_http_allowed_by_env() -> bool {
    matches!(
        std::env::var(ALLOW_INSECURE_HTTP_ENV).as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

/// Whether the user has opted in to plaintext HTTP for this instance, either
/// persistently (`ak instance add|update --insecure-http`) or for this
/// invocation (`AK_ALLOW_INSECURE_HTTP=1`).
pub fn insecure_http_allowed(instance: &InstanceConfig) -> bool {
    instance.allow_insecure_http || insecure_http_allowed_by_env()
}

/// Whether credentials may go to this instance: anything but plain HTTP to a
/// non-loopback host without an opt-in.
pub fn credentials_allowed(instance: &InstanceConfig) -> bool {
    classify_url(&instance.url) != TransportSecurity::HttpRemote || insecure_http_allowed(instance)
}

/// Refuse, before anything is sent, to attach credentials (a bearer token, a
/// password, a one-time code) to a request for an instance on plain HTTP to a
/// non-loopback host, unless the user opted in. Every path that sends the
/// instance's credentials calls this first.
pub fn require_secure_transport(
    instance_name: &str,
    instance: &InstanceConfig,
) -> Result<(), AkError> {
    if credentials_allowed(instance) {
        Ok(())
    } else {
        Err(AkError::InsecureTransport {
            url: instance.url.clone(),
            help: opt_in_help(instance_name, &instance.url),
        })
    }
}

/// The command that records the opt-in for good: `ak instance update` for a
/// configured instance, `ak instance add` for a URL that isn't one yet.
pub fn record_opt_in_command(instance_name: &str, url: &str) -> String {
    let is_url = crate::config::is_instance_url(instance_name);
    let configured = !is_url
        && crate::config::AppConfig::load()
            .is_ok_and(|config| config.instances.contains_key(instance_name));
    if configured {
        format!("`ak instance update {instance_name} --insecure-http`")
    } else if is_url {
        format!("`ak instance add <name> {url} --insecure-http`")
    } else {
        format!("`ak instance add {instance_name} {url} --insecure-http`")
    }
}

/// How to opt in to plain HTTP for this instance: a command that records it in
/// the config, and the variable for one command.
fn opt_in_help(instance_name: &str, url: &str) -> String {
    let record = record_opt_in_command(instance_name, url);
    format!(
        "Anyone on the network path can read what is sent over plain http://. Use an \
         https:// URL if the server has one. To send credentials to this server anyway, \
         allow it for good with {record}, or for one command with \
         {ALLOW_INSECURE_HTTP_ENV}=1."
    )
}

/// Say on stderr that `ak` won't send credentials to this instance, if it's on
/// plain HTTP to a non-loopback host without an opt-in, as when it's added.
///
/// Returns `true` if the warning was emitted.
pub fn warn_if_insecure(instance_name: &str, instance: &InstanceConfig) -> bool {
    if credentials_allowed(instance) {
        return false;
    }
    eprintln!(
        "Warning: instance '{instance_name}' uses unencrypted HTTP ({}), so ak won't send \
         it your credentials, which anyone on the network path could read.\n\
         Use an https:// URL, or allow it with {} (or {ALLOW_INSECURE_HTTP_ENV}=1 for \
         one command).",
        instance.url,
        record_opt_in_command(instance_name, &instance.url),
    );
    true
}

/// Self-signed throwaway CA certificates shared by transport and client tests.
#[cfg(test)]
pub(crate) mod test_ca {
    /// Self-signed test CA (CN=AK Test CA 1), P-256, generated for these tests.
    pub const TEST_CA_PEM_1: &str = "-----BEGIN CERTIFICATE-----
MIIBhDCCASmgAwIBAgIUc9CR+p5OHSH4QMsCfuxAyJK5Wd0wCgYIKoZIzj0EAwIw
FzEVMBMGA1UEAwwMQUsgVGVzdCBDQSAxMB4XDTI2MDcwOTIxMjE1NVoXDTI2MDgw
ODIxMjE1NVowFzEVMBMGA1UEAwwMQUsgVGVzdCBDQSAxMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAET46Pidr+fHLEc9Q7FEd+dqkKgDU/+i1JAJbZudtGjEE87tuG
SKckU/P6f1eTRjhktFlD2OuyM7h8YqM2FPR6oKNTMFEwHQYDVR0OBBYEFPjfTLd9
p1qbNhEqnIlv9sCo9XShMB8GA1UdIwQYMBaAFPjfTLd9p1qbNhEqnIlv9sCo9XSh
MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhALiCGONXjb1HDfi7
opgJ26ReB2DqbmfeZZNfrbMhrZqJAiEAqJJu5nsnp4v/i+i2lTYhy8RnFlDWO9Zu
ze/9pEYSScE=
-----END CERTIFICATE-----
";

    /// A second, distinct self-signed test CA (CN=AK Test CA 2).
    pub const TEST_CA_PEM_2: &str = "-----BEGIN CERTIFICATE-----
MIIBgzCCASmgAwIBAgIUZsU+wackrRfZYXZIP0rfk+SUmBMwCgYIKoZIzj0EAwIw
FzEVMBMGA1UEAwwMQUsgVGVzdCBDQSAyMB4XDTI2MDcwOTIxMjE1NVoXDTI2MDgw
ODIxMjE1NVowFzEVMBMGA1UEAwwMQUsgVGVzdCBDQSAyMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEUFwH5yhlBaPfCWMwpHDTw+O8MYRZDSzQqGnRRr88zSrSRZ+j
e4csqx797H4bQscJ4D99XQY+gXizqaceHVcfPKNTMFEwHQYDVR0OBBYEFK7XgrHC
QbeZ3/O175I1NmBMKjSGMB8GA1UdIwQYMBaAFK7XgrHCQbeZ3/O175I1NmBMKjSG
MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAJz+Yz/eMcRzyJ9J
WWp+uGnGQgcpALGLLUOCgLAIii+qAiB2T2Uc8Tsk/uosedAywcwiZ06+S615+MNb
RrZxwmFE/Q==
-----END CERTIFICATE-----
";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::ENV_LOCK;

    fn instance(url: &str, allow: bool) -> InstanceConfig {
        InstanceConfig {
            url: url.to_string(),
            api_version: "v1".to_string(),
            allow_insecure_http: allow,
        }
    }

    // ---- classify_url ----

    #[test]
    fn https_is_secure() {
        assert_eq!(
            classify_url("https://registry.example.com"),
            TransportSecurity::Https
        );
        assert_eq!(
            classify_url("https://10.1.2.3:8443/api"),
            TransportSecurity::Https
        );
    }

    #[test]
    fn http_localhost_is_loopback() {
        assert_eq!(
            classify_url("http://localhost:8080"),
            TransportSecurity::HttpLoopback
        );
        assert_eq!(
            classify_url("http://LOCALHOST:8080"),
            TransportSecurity::HttpLoopback
        );
        assert_eq!(
            classify_url("http://registry.localhost:8080"),
            TransportSecurity::HttpLoopback
        );
    }

    #[test]
    fn http_loopback_ips_are_loopback() {
        assert_eq!(
            classify_url("http://127.0.0.1:8080"),
            TransportSecurity::HttpLoopback
        );
        assert_eq!(
            classify_url("http://127.1.2.3"),
            TransportSecurity::HttpLoopback
        );
        assert_eq!(
            classify_url("http://[::1]:8080"),
            TransportSecurity::HttpLoopback
        );
        assert_eq!(
            classify_url("http://[::ffff:127.0.0.1]:8080"),
            TransportSecurity::HttpLoopback
        );
    }

    #[test]
    fn http_remote_hosts_are_remote() {
        assert_eq!(
            classify_url("http://registry.example.com"),
            TransportSecurity::HttpRemote
        );
        assert_eq!(
            classify_url("http://10.0.0.5:8080"),
            TransportSecurity::HttpRemote
        );
        assert_eq!(
            classify_url("http://[2001:db8::1]:8080"),
            TransportSecurity::HttpRemote
        );
        // Looks local but is NOT loopback — traffic still leaves the host.
        assert_eq!(
            classify_url("http://localhost.example.com"),
            TransportSecurity::HttpRemote
        );
        assert_eq!(
            classify_url("http://192.168.1.10"),
            TransportSecurity::HttpRemote
        );
    }

    #[test]
    fn non_http_and_garbage_are_other() {
        assert_eq!(classify_url("ftp://example.com"), TransportSecurity::Other);
        assert_eq!(classify_url("not a url"), TransportSecurity::Other);
        assert_eq!(classify_url(""), TransportSecurity::Other);
    }

    // ---- opt-in resolution ----

    #[test]
    fn env_opt_in_values() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for (val, expected) in [
            ("1", true),
            ("true", true),
            ("yes", true),
            ("0", false),
            ("false", false),
            ("", false),
        ] {
            unsafe { std::env::set_var(ALLOW_INSECURE_HTTP_ENV, val) };
            assert_eq!(insecure_http_allowed_by_env(), expected, "value: {val:?}");
        }
        unsafe { std::env::remove_var(ALLOW_INSECURE_HTTP_ENV) };
        assert!(!insecure_http_allowed_by_env());
    }

    #[test]
    fn instance_flag_opts_in() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var(ALLOW_INSECURE_HTTP_ENV) };
        assert!(insecure_http_allowed(&instance("http://example.com", true)));
        assert!(!insecure_http_allowed(&instance(
            "http://example.com",
            false
        )));
    }

    // ---- require_secure_transport ----

    fn refused(name: &str, url: &str, allow: bool) -> Option<String> {
        match require_secure_transport(name, &instance(url, allow)) {
            Ok(()) => None,
            Err(AkError::InsecureTransport { url: shown, help }) => {
                assert_eq!(shown, url);
                Some(help)
            }
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn remote_http_is_refused_without_an_opt_in() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var(ALLOW_INSECURE_HTTP_ENV) };
        for url in [
            "http://registry.example.com",
            "http://192.168.1.10:8080",
            "http://[2001:db8::1]:8080",
            "http://0.0.0.0:8080",
        ] {
            assert!(refused("t", url, false).is_some(), "{url}");
        }
    }

    #[test]
    fn the_config_setting_allows_remote_http() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var(ALLOW_INSECURE_HTTP_ENV) };
        assert!(refused("t", "http://registry.example.com", true).is_none());
    }

    #[test]
    fn the_env_var_allows_remote_http_for_one_command() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var(ALLOW_INSECURE_HTTP_ENV, "1") };
        let allowed = refused("t", "http://registry.example.com", false).is_none();
        unsafe { std::env::remove_var(ALLOW_INSECURE_HTTP_ENV) };
        assert!(allowed);
    }

    #[test]
    fn loopback_and_https_are_never_refused() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var(ALLOW_INSECURE_HTTP_ENV) };
        for url in [
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://127.4.5.6",
            "http://[::1]:8080",
            "https://registry.example.com",
            "https://192.168.1.10:8443",
        ] {
            assert!(refused("t", url, false).is_none(), "{url}");
        }
    }

    #[test]
    fn the_refusal_says_how_to_opt_in() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var(ALLOW_INSECURE_HTTP_ENV) };
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("config.toml"),
            "[instances.nas]\nurl = \"http://192.168.1.20:8080\"\n",
        )
        .unwrap();
        unsafe { std::env::set_var("AK_CONFIG_DIR", dir.path()) };

        let url = "http://192.168.1.20:8080";
        let configured = refused("nas", url, false).unwrap();
        let new = refused("other", url, false).unwrap();
        let by_url = refused(url, url, false).unwrap();
        unsafe { std::env::remove_var("AK_CONFIG_DIR") };

        assert!(
            configured.contains("`ak instance update nas --insecure-http`"),
            "{configured}"
        );
        assert!(
            new.contains(&format!("`ak instance add other {url} --insecure-http`")),
            "{new}"
        );
        assert!(
            by_url.contains(&format!("`ak instance add <name> {url} --insecure-http`")),
            "{by_url}"
        );
        for help in [&configured, &new, &by_url] {
            assert!(help.contains("AK_ALLOW_INSECURE_HTTP=1"), "{help}");
        }
    }

    #[test]
    fn the_refusal_is_a_usage_error() {
        let err = AkError::InsecureTransport {
            url: "http://x".into(),
            help: String::new(),
        };
        assert_eq!(err.exit_code(), crate::error::EXIT_USAGE);
        assert_eq!(
            err.to_string(),
            "Refusing to send credentials over unencrypted HTTP to http://x"
        );
    }

    // ---- warn_if_insecure ----

    #[test]
    fn warns_only_for_unacknowledged_remote_http() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var(ALLOW_INSECURE_HTTP_ENV) };

        assert!(warn_if_insecure(
            "t",
            &instance("http://registry.example.com", false)
        ));
        assert!(!warn_if_insecure(
            "t",
            &instance("http://registry.example.com", true)
        ));
        assert!(!warn_if_insecure(
            "t",
            &instance("http://localhost:8080", false)
        ));
        assert!(!warn_if_insecure(
            "t",
            &instance("https://registry.example.com", false)
        ));
    }

    // ---- custom CA certificates ----

    use test_ca::{TEST_CA_PEM_1, TEST_CA_PEM_2};

    fn write_temp(contents: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("ca.pem");
        std::fs::write(&path, contents).unwrap();
        (dir, path)
    }

    #[test]
    fn load_single_ca_certificate() {
        let (_dir, path) = write_temp(TEST_CA_PEM_1);
        let certs = load_ca_certificates(&path).unwrap();
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn load_ca_bundle_with_multiple_certs() {
        let bundle = format!("{TEST_CA_PEM_1}{TEST_CA_PEM_2}");
        let (_dir, path) = write_temp(&bundle);
        let certs = load_ca_certificates(&path).unwrap();
        assert_eq!(certs.len(), 2);
    }

    #[test]
    fn load_missing_file_is_clear_error() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("does-not-exist.pem");
        let err = load_ca_certificates(&path).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("cannot read CA certificate file"), "{msg}");
        assert!(msg.contains("does-not-exist.pem"), "{msg}");
    }

    #[test]
    fn load_invalid_pem_is_clear_error() {
        let (_dir, path) = write_temp("this is not a certificate");
        let err = load_ca_certificates(&path).unwrap_err();
        let msg = err.to_string();
        // Depending on how the parser treats garbage, this surfaces as either
        // an invalid-PEM error or an empty bundle — both must be clear errors.
        assert!(
            msg.contains("not a valid PEM certificate file") || msg.contains("no certificates"),
            "{msg}"
        );
    }

    #[test]
    fn load_empty_file_is_clear_error() {
        let (_dir, path) = write_temp("");
        let err = load_ca_certificates(&path).unwrap_err();
        assert!(err.to_string().contains("no certificates"), "{}", err);
    }

    #[test]
    fn ca_cert_path_from_env() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var(CA_CERT_ENV, "/some/ca.pem") };
        assert_eq!(
            ca_cert_path(),
            Some(std::path::PathBuf::from("/some/ca.pem"))
        );
        unsafe { std::env::set_var(CA_CERT_ENV, "") };
        assert_eq!(ca_cert_path(), None);
        unsafe { std::env::remove_var(CA_CERT_ENV) };
        assert_eq!(ca_cert_path(), None);
    }

    #[test]
    fn apply_custom_ca_builds_client() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let bundle = format!("{TEST_CA_PEM_1}{TEST_CA_PEM_2}");
        let (_dir, path) = write_temp(&bundle);
        unsafe { std::env::set_var(CA_CERT_ENV, &path) };

        let builder = apply_custom_ca(reqwest::ClientBuilder::new()).unwrap();
        assert!(builder.build().is_ok());

        unsafe { std::env::remove_var(CA_CERT_ENV) };
    }

    #[test]
    fn apply_custom_ca_propagates_load_errors() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (_dir, path) = write_temp("garbage");
        unsafe { std::env::set_var(CA_CERT_ENV, &path) };

        let err = apply_custom_ca(reqwest::ClientBuilder::new()).unwrap_err();
        assert!(matches!(err, AkError::CaCert(_)));

        unsafe { std::env::remove_var(CA_CERT_ENV) };
    }

    #[test]
    fn apply_custom_ca_noop_without_config() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var(CA_CERT_ENV) };
        let builder = apply_custom_ca(reqwest::ClientBuilder::new()).unwrap();
        assert!(builder.build().is_ok());
    }
}
