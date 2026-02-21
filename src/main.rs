use clap::Parser;
use miette::Result;

mod cli;
mod commands;
mod config;
mod error;
mod output;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = cli::Cli::parse();
    cli.execute().await
}

/// Shared test utilities — single ENV_LOCK for all modules that touch AK_CONFIG_DIR.
#[cfg(test)]
pub(crate) mod test_utils {
    use std::sync::Mutex;
    pub static ENV_LOCK: Mutex<()> = Mutex::new(());

    use crate::cli::GlobalArgs;
    use crate::output::OutputFormat;
    use tempfile::TempDir;
    use wiremock::MockServer;

    /// Start a wiremock server and create a temp config directory pointing at it.
    pub async fn mock_setup() -> (MockServer, TempDir) {
        let server = MockServer::start().await;
        let tmp = TempDir::new().unwrap();
        let config = format!(
            "default_instance = \"test\"\n[instances.test]\nurl = \"{}\"\napi_version = \"v1\"\n",
            server.uri()
        );
        std::fs::write(tmp.path().join("config.toml"), config).unwrap();
        (server, tmp)
    }

    /// Build a GlobalArgs suitable for tests (non-interactive, quiet or json output).
    pub fn test_global(format: OutputFormat) -> GlobalArgs {
        GlobalArgs {
            format,
            instance: Some("test".to_string()),
            no_input: true,
        }
    }
}
