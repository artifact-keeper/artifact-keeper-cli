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

    #[error("Authentication token expired for '{0}'")]
    #[diagnostic(
        code(ak::token_expired),
        help("Run `ak auth login --instance {0}` to re-authenticate")
    )]
    TokenExpired(String),

    #[error("Permission denied: {0}")]
    #[diagnostic(code(ak::permission_denied))]
    PermissionDenied(String),

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

    #[error(transparent)]
    #[diagnostic(code(ak::io_error))]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    #[diagnostic(code(ak::http_error))]
    Http(#[from] reqwest::Error),
}
