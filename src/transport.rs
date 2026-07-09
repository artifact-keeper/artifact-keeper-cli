//! Transport-security classification for instance URLs.
//!
//! The CLI sends bearer tokens (and, on interactive login, passwords) to the
//! configured instance URL. Over plain `http://` those credentials travel in
//! cleartext, so non-loopback HTTP instances get a loud warning — and
//! interactive password login refuses outright — unless the user explicitly
//! opts in. Loopback hosts (localhost / 127.0.0.0/8 / ::1) are exempt because
//! plain HTTP is the normal local development setup.

use crate::config::InstanceConfig;

/// Environment variable that globally opts in to sending credentials over
/// plaintext HTTP to non-loopback hosts.
pub const ALLOW_INSECURE_HTTP_ENV: &str = "AK_ALLOW_INSECURE_HTTP";

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
/// persistently (`ak instance add --insecure-http`) or for this invocation
/// (`AK_ALLOW_INSECURE_HTTP=1`).
pub fn insecure_http_allowed(instance: &InstanceConfig) -> bool {
    instance.allow_insecure_http || insecure_http_allowed_by_env()
}

/// Emit the standard cleartext-credential warning to stderr if (and only if)
/// the instance uses plaintext HTTP to a non-loopback host without an opt-in.
///
/// Returns `true` if the warning was emitted.
pub fn warn_if_insecure(instance_name: &str, instance: &InstanceConfig) -> bool {
    if classify_url(&instance.url) == TransportSecurity::HttpRemote
        && !insecure_http_allowed(instance)
    {
        eprintln!(
            "Warning: instance '{instance_name}' uses unencrypted HTTP ({}).\n\
             Credentials (bearer tokens) are sent in cleartext and can be read by anyone \
             on the network path.\n\
             Use an https:// URL, or acknowledge the risk with \
             `ak instance add --insecure-http` or {ALLOW_INSECURE_HTTP_ENV}=1.",
            instance.url
        );
        true
    } else {
        false
    }
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
}
