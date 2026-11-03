use std::process::ExitCode;

mod cli;
mod commands;
mod config;
mod error;
mod output;
mod registry;
mod transport;

#[tokio::main]
async fn main() -> ExitCode {
    quiet_exit_on_closed_pipe();
    let cli = cli::Cli::parse_args();
    match cli.execute().await.map_err(explain_no_terminal) {
        Ok(()) => ExitCode::SUCCESS,
        // The reader has what it wanted, as with `ak repo list | head -1`.
        Err(e) if is_broken_pipe(&e) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e:?}");
            ExitCode::from(exit_code(&e))
        }
    }
}

/// `println!` and `eprintln!` panic when the reader has gone. With `| head -1` that's
/// normal, so leave quietly, as the command would have if it had finished.
fn quiet_exit_on_closed_pipe() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let message = info
            .payload()
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| info.payload().downcast_ref::<&str>().copied())
            .unwrap_or_default();
        if is_closed_pipe_panic(message) {
            std::process::exit(0);
        }
        default_hook(info);
    }));
}

/// The text is the standard library's, and nothing from a server reaches it. Windows
/// has its own error numbers for a pipe that's closed or being closed.
fn is_closed_pipe_panic(message: &str) -> bool {
    (message.starts_with("failed printing to stdout")
        || message.starts_with("failed printing to stderr"))
        && (message.contains("Broken pipe")
            || message.contains("os error 32")
            || message.contains("os error 109")
            || message.contains("os error 232"))
}

/// Goes by the error's type. A failure from another pipe the command has open, such
/// as a child's stdin, isn't this: those are reported with their own message.
fn is_broken_pipe(e: &miette::Report) -> bool {
    matches!(
        e.downcast_ref::<error::AkError>(),
        Some(error::AkError::Io(io)) if io.kind() == std::io::ErrorKind::BrokenPipe
    )
}

/// The exit code for a failed command: that of the `AkError` in its chain, which a
/// `wrap_err` doesn't hide, or 1 for anything else.
fn exit_code(e: &miette::Report) -> u8 {
    e.downcast_ref::<error::AkError>()
        .or_else(|| {
            e.chain()
                .find_map(|cause| cause.downcast_ref::<error::AkError>())
        })
        .map_or(error::EXIT_GENERIC, error::AkError::exit_code)
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
mod closed_pipe_tests {
    use super::*;

    #[test]
    fn a_closed_pipe_panic_is_recognised() {
        assert!(is_closed_pipe_panic(
            "failed printing to stdout: Broken pipe (os error 32)"
        ));
        assert!(is_closed_pipe_panic(
            "failed printing to stderr: The pipe is being closed. (os error 232)"
        ));
    }

    #[test]
    fn another_panic_isnt() {
        assert!(!is_closed_pipe_panic("index out of bounds"));
        assert!(!is_closed_pipe_panic("the server said: Broken pipe"));
        assert!(!is_closed_pipe_panic(
            "failed printing to stdout: Permission denied (os error 13)"
        ));
    }
}

#[cfg(test)]
mod exit_code_tests {
    use super::*;
    use crate::error::AkError;

    #[test]
    fn each_failure_has_its_code() {
        let cases: Vec<(AkError, u8)> = vec![
            (AkError::Usage("x".into()), 2),
            (AkError::NoInstance, 2),
            (AkError::InstanceNotFound("x".into()), 2),
            (AkError::NoTerminal, 2),
            (AkError::ConfirmationRefused("x".into()), 2),
            (AkError::NetworkError("x".into()), 3),
            (AkError::NotAuthenticated("x".into()), 4),
            (AkError::Forbidden("x".into()), 4),
            (AkError::NotFound("x".into()), 5),
            (AkError::ServerError("x".into()), 6),
            (AkError::UnsupportedServer("x".into()), 6),
            (AkError::ReportedFailure("x".into()), 7),
            (AkError::PromotionBlocked("x".into()), 7),
            (AkError::ConfigError("x".into()), 1),
            (AkError::Local("x".into()), 1),
        ];
        for (error, code) in cases {
            let shown = error.to_string();
            assert_eq!(exit_code(&error.into()), code, "{shown}");
        }
    }

    #[test]
    fn wrapping_an_error_keeps_its_code() {
        let wrapped: miette::Report = miette::Report::new(AkError::NotFound("x".into()));
        assert_eq!(exit_code(&wrapped.wrap_err("while doing y")), 5);
    }

    #[test]
    fn an_error_that_isnt_ours_is_generic() {
        assert_eq!(exit_code(&miette::miette!("anything")), 1);
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
