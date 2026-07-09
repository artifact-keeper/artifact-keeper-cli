use miette::Diagnostic;
use thiserror::Error;

#[derive(Error, Diagnostic, Debug)]
pub enum AkError {
    #[error("No instance configured")]
    #[diagnostic(
        code(ak::no_instance),
        help("Run `ak instance add <name> <url>` to add an Artifact Keeper server")
    )]
    NoInstance,

    #[error("Instance '{0}' not found")]
    #[diagnostic(
        code(ak::instance_not_found),
        help("Run `ak instance list` to see configured instances")
    )]
    InstanceNotFound(String),

    #[error("Not authenticated with '{0}'")]
    #[diagnostic(
        code(ak::not_authenticated),
        help("Run `ak auth login` to authenticate, or set AK_TOKEN environment variable")
    )]
    NotAuthenticated(String),

    #[error("Server error: {0}")]
    #[diagnostic(code(ak::server_error))]
    ServerError(String),

    #[error("Network error: {0}")]
    #[diagnostic(
        code(ak::network_error),
        help("Check your network connection. Run `ak doctor` to diagnose issues.")
    )]
    NetworkError(String),

    #[error("Configuration error: {0}")]
    #[diagnostic(code(ak::config_error))]
    ConfigError(String),

    #[error("CA certificate error: {0}")]
    #[diagnostic(
        code(ak::ca_cert),
        help(
            "Provide a readable PEM-encoded certificate file (one or more \
             '-----BEGIN CERTIFICATE-----' blocks) via --ca-cert <path> or AK_CA_CERT."
        )
    )]
    CaCert(String),

    #[error("Refusing to send a password over unencrypted HTTP to '{0}'")]
    #[diagnostic(
        code(ak::insecure_transport),
        help(
            "Anyone on the network path can read credentials sent over plain http://. \
             Use an https:// URL, or explicitly accept the risk by re-adding the instance \
             with `ak instance add --insecure-http` or setting AK_ALLOW_INSECURE_HTTP=1."
        )
    )]
    InsecureTransport(String),

    #[error(transparent)]
    #[diagnostic(code(ak::io_error))]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    #[diagnostic(code(ak::http_error))]
    Http(#[from] reqwest::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use miette::Diagnostic;

    #[test]
    fn no_instance_display() {
        let err = AkError::NoInstance;
        assert_eq!(err.to_string(), "No instance configured");
    }

    #[test]
    fn no_instance_code() {
        let err = AkError::NoInstance;
        assert_eq!(err.code().unwrap().to_string(), "ak::no_instance");
    }

    #[test]
    fn no_instance_help() {
        let err = AkError::NoInstance;
        let help = err.help().unwrap().to_string();
        assert!(help.contains("ak instance add"));
    }

    #[test]
    fn instance_not_found_display() {
        let err = AkError::InstanceNotFound("prod".into());
        assert_eq!(err.to_string(), "Instance 'prod' not found");
    }

    #[test]
    fn instance_not_found_code() {
        let err = AkError::InstanceNotFound("prod".into());
        assert_eq!(err.code().unwrap().to_string(), "ak::instance_not_found");
    }

    #[test]
    fn not_authenticated_display() {
        let err = AkError::NotAuthenticated("staging".into());
        assert_eq!(err.to_string(), "Not authenticated with 'staging'");
    }

    #[test]
    fn not_authenticated_help() {
        let err = AkError::NotAuthenticated("staging".into());
        let help = err.help().unwrap().to_string();
        assert!(help.contains("ak auth login"));
    }

    #[test]
    fn server_error_display() {
        let err = AkError::ServerError("500 internal".into());
        assert_eq!(err.to_string(), "Server error: 500 internal");
    }

    #[test]
    fn network_error_display() {
        let err = AkError::NetworkError("connection refused".into());
        assert_eq!(err.to_string(), "Network error: connection refused");
    }

    #[test]
    fn network_error_help() {
        let err = AkError::NetworkError("timeout".into());
        let help = err.help().unwrap().to_string();
        assert!(help.contains("ak doctor"));
    }

    #[test]
    fn config_error_display() {
        let err = AkError::ConfigError("bad key".into());
        assert_eq!(err.to_string(), "Configuration error: bad key");
    }

    #[test]
    fn config_error_code() {
        let err = AkError::ConfigError("x".into());
        assert_eq!(err.code().unwrap().to_string(), "ak::config_error");
    }

    #[test]
    fn io_error_wraps() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = AkError::from(io_err);
        assert!(err.to_string().contains("file not found"));
        assert_eq!(err.code().unwrap().to_string(), "ak::io_error");
    }
}
