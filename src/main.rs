use clap::Parser;
use miette::Result;

mod cli;
mod commands;
mod config;
mod error;
mod output;
mod registry;
mod transport;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = cli::Cli::parse();
    cli.execute().await.map_err(explain_no_terminal)
}

/// A prompt with no terminal fails deep inside dialoguer, in 20-odd places, with
/// "not a terminal" and no way forward. Say what to do instead.
fn explain_no_terminal(e: miette::Report) -> miette::Report {
    if is_no_terminal(&e) {
        error::AkError::NoTerminal.into()
    } else {
        e
    }
}

/// Goes by the error's type, not its text: a server's message can say anything,
/// and it reaches here as text.
fn is_no_terminal(e: &miette::Report) -> bool {
    e.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(commands::helpers::is_no_terminal_io_error)
    })
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

    /// Set up env vars for wiremock tests. Returns a MutexGuard that must be held for the test.
    pub fn setup_env(tmp: &TempDir) -> std::sync::MutexGuard<'static, ()> {
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::set_var("AK_CONFIG_DIR", tmp.path());
            std::env::set_var("AK_TOKEN", "test-token");
        }
        guard
    }

    /// Clean up env vars after wiremock tests.
    pub fn teardown_env() {
        unsafe {
            std::env::remove_var("AK_CONFIG_DIR");
            std::env::remove_var("AK_TOKEN");
        }
    }
}

#[cfg(test)]
mod no_terminal_tests {
    use miette::IntoDiagnostic;

    use super::*;

    fn prompt_error() -> dialoguer::Error {
        std::io::Error::new(std::io::ErrorKind::NotConnected, "not a terminal").into()
    }

    #[test]
    fn a_failed_prompt_is_recognised() {
        let e = Err::<(), _>(prompt_error()).into_diagnostic().unwrap_err();
        assert!(is_no_terminal(&e));
    }

    #[test]
    fn a_message_saying_the_same_thing_is_not() {
        for message in [
            "not a terminal",
            "IO error: not a terminal",
            "Failed to read password: IO error: not a terminal",
        ] {
            let server: miette::Report = error::AkError::ServerError(message.to_string()).into();
            assert!(!is_no_terminal(&server), "{message}");
            let config: miette::Report = error::AkError::ConfigError(message.to_string()).into();
            assert!(!is_no_terminal(&config), "{message}");
        }
    }

    #[test]
    fn another_io_error_is_not() {
        let e = Err::<(), _>(std::io::Error::other("not a terminal"))
            .into_diagnostic()
            .unwrap_err();
        assert!(!is_no_terminal(&e));
    }
}
