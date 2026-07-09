use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use miette::{IntoDiagnostic, Result};
use serde::Serialize;

use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat};

/// Create a new table with the standard preset and headers.
pub fn new_table(headers: Vec<&str>) -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(headers);
    table
}

/// Format a UUID as an 8-character short ID.
pub fn short_id(id: &uuid::Uuid) -> String {
    id.to_string()[..8].to_string()
}

/// Map an SDK error to an AkError with a descriptive message.
pub fn sdk_err(action: &str, e: impl std::fmt::Display) -> AkError {
    AkError::ServerError(format!("Failed to {action}: {e}"))
}

/// Emit the result of a mutation (create/update/delete) honoring the output
/// format so results are machine-consumable.
///
/// - `Quiet`: prints just the `id` to stdout (for scripting `$(... )` capture).
/// - `Json`/`Yaml`: renders the full `value` object to **stdout** so callers can
///   pipe it to `jq` and extract the created/updated ID.
/// - `Table`: prints the human-readable `human` message to **stderr** (leaving
///   stdout clean).
pub fn emit_mutation<T: Serialize>(value: &T, id: &str, human: &str, global: &GlobalArgs) {
    match global.format {
        OutputFormat::Quiet => println!("{id}"),
        OutputFormat::Json | OutputFormat::Yaml => {
            println!("{}", output::render(value, &global.format, None));
        }
        OutputFormat::Table => eprintln!("{human}"),
    }
}

/// Parse a string as a UUID, returning a friendly error with the given label.
pub fn parse_uuid(id: &str, label: &str) -> Result<uuid::Uuid> {
    id.parse()
        .map_err(|_| AkError::ConfigError(format!("Invalid {label} ID: {id}")).into())
}

/// Parse an optional string as a UUID.
pub fn parse_optional_uuid(id: Option<&str>, label: &str) -> Result<Option<uuid::Uuid>> {
    id.map(|v| parse_uuid(v, label)).transpose()
}

/// True when the given long option (e.g. `--password`) appears on the
/// command line itself, as opposed to being filled from an env var default.
fn flag_on_argv(flag: &str) -> bool {
    std::env::args().skip(1).any(|arg| {
        arg == flag
            || arg
                .strip_prefix(flag)
                .is_some_and(|rest| rest.starts_with('='))
    })
}

/// Return `None` for an empty secret so "just press Enter" and empty piped
/// input both mean "no secret".
fn non_empty(secret: String) -> Option<String> {
    if secret.is_empty() {
        None
    } else {
        Some(secret)
    }
}

/// Read a secret from a reader (stdin), trimming trailing newlines.
fn read_secret<R: std::io::Read>(reader: &mut R) -> Result<String> {
    let mut buf = String::new();
    reader
        .read_to_string(&mut buf)
        .map_err(|e| AkError::ConfigError(format!("Failed to read secret from stdin: {e}")))?;
    Ok(buf.trim_end_matches(['\r', '\n']).to_string())
}

/// Resolve a secret-valued option without requiring it on the command line.
///
/// Sources, in order of precedence:
/// 1. `from_stdin` (`--<flag>-stdin` was passed): read the secret from stdin.
/// 2. An explicit value (`--<flag> <value>` on argv, or its env-var default).
///    When the value was visibly passed on argv, a soft warning is printed to
///    stderr since command-line values leak into shell history and process
///    listings.
/// 3. If `prompt` is `Some` and stdin is not a TTY (piped/redirected input),
///    read the secret from stdin.
/// 4. If `prompt` is `Some`, stdin is a TTY, and `--no-input` was not given,
///    prompt interactively with no echo. Empty input means "no secret".
/// 5. Otherwise resolve to `None`.
///
/// Pass `prompt: None` for inputs that must never fall back to prompting or
/// implicit stdin reads (e.g. update commands where an omitted secret means
/// "keep the existing one").
pub fn resolve_secret(
    value: Option<String>,
    from_stdin: bool,
    flag: &str,
    prompt: Option<&str>,
    no_input: bool,
) -> Result<Option<String>> {
    if value.is_some() && flag_on_argv(flag) {
        eprintln!(
            "warning: passing {flag} on the command line exposes the secret to shell history \
             and process listings; prefer {flag}-stdin, the corresponding environment \
             variable, or the interactive prompt"
        );
    }
    let stdin_is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
    resolve_secret_from(value, from_stdin, prompt, no_input, stdin_is_tty, || {
        std::io::stdin().lock()
    })
}

/// Testable core of [`resolve_secret`]; see its docs for the precedence rules.
///
/// `reader` is only invoked on the branches that actually read stdin — it must
/// NOT be acquired eagerly, because the interactive prompt also reads from
/// stdin and a held `StdinLock` would deadlock it.
fn resolve_secret_from<R: std::io::Read>(
    value: Option<String>,
    from_stdin: bool,
    prompt: Option<&str>,
    no_input: bool,
    stdin_is_tty: bool,
    reader: impl FnOnce() -> R,
) -> Result<Option<String>> {
    if from_stdin {
        return read_secret(&mut reader()).map(non_empty);
    }
    if value.is_some() {
        return Ok(value);
    }
    let Some(prompt) = prompt else {
        return Ok(None);
    };
    if !stdin_is_tty {
        // Piped/redirected input: take the secret from stdin so it never has
        // to appear on the command line.
        return read_secret(&mut reader()).map(non_empty);
    }
    if no_input {
        return Ok(None);
    }
    let entered = dialoguer::Password::new()
        .with_prompt(prompt)
        .allow_empty_password(true)
        .interact()
        .into_diagnostic()?;
    Ok(non_empty(entered))
}

/// Prompt the user to confirm a destructive action. Returns `true` if the
/// action should proceed, `false` if cancelled.
pub fn confirm_action(prompt: &str, skip_confirm: bool, no_input: bool) -> Result<bool> {
    if skip_confirm || no_input {
        return Ok(true);
    }
    let confirmed = dialoguer::Confirm::new()
        .with_prompt(prompt)
        .default(false)
        .interact()
        .into_diagnostic()?;
    if !confirmed {
        eprintln!("Cancelled.");
    }
    Ok(confirmed)
}

/// Print pagination info when there are multiple pages.
pub fn print_page_info(page: i32, total_pages: i32, total: i64, label: &str) {
    if total_pages > 1 {
        eprintln!("Page {page} of {total_pages} ({total} total {label})");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- parse_uuid ----

    #[test]
    fn parse_uuid_valid() {
        let result = parse_uuid("00000000-0000-0000-0000-000000000001", "test");
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().to_string(),
            "00000000-0000-0000-0000-000000000001"
        );
    }

    #[test]
    fn parse_uuid_valid_v4() {
        let result = parse_uuid("550e8400-e29b-41d4-a716-446655440000", "artifact");
        assert!(result.is_ok());
    }

    #[test]
    fn parse_uuid_invalid_string() {
        let result = parse_uuid("not-a-uuid", "test");
        assert!(result.is_err());
    }

    #[test]
    fn parse_uuid_empty_string() {
        let result = parse_uuid("", "test");
        assert!(result.is_err());
    }

    #[test]
    fn parse_uuid_too_short() {
        let result = parse_uuid("550e8400-e29b", "repository");
        assert!(result.is_err());
    }

    #[test]
    fn parse_uuid_no_hyphens() {
        // UUID without hyphens is valid for the uuid crate
        let result = parse_uuid("550e8400e29b41d4a716446655440000", "test");
        assert!(result.is_ok());
    }

    // ---- parse_optional_uuid ----

    #[test]
    fn parse_optional_uuid_none() {
        let result = parse_optional_uuid(None, "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn parse_optional_uuid_some_valid() {
        let result = parse_optional_uuid(Some("00000000-0000-0000-0000-000000000001"), "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn parse_optional_uuid_some_invalid() {
        let result = parse_optional_uuid(Some("bad"), "test");
        assert!(result.is_err());
    }

    #[test]
    fn parse_optional_uuid_some_empty() {
        let result = parse_optional_uuid(Some(""), "repository");
        assert!(result.is_err());
    }

    // ---- confirm_action ----

    #[test]
    fn confirm_action_skip_confirm() {
        let result = confirm_action("Delete?", true, false);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn confirm_action_no_input() {
        let result = confirm_action("Delete?", false, true);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn confirm_action_both_flags() {
        let result = confirm_action("Really?", true, true);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    // ---- print_page_info ----

    #[test]
    fn print_page_info_single_page() {
        // Should not panic; does not print anything for single page
        print_page_info(1, 1, 5, "items");
    }

    #[test]
    fn print_page_info_multiple_pages() {
        // Should not panic; prints page info to stderr
        print_page_info(2, 5, 100, "artifacts");
    }

    #[test]
    fn print_page_info_first_of_many() {
        print_page_info(1, 3, 60, "scans");
    }

    #[test]
    fn print_page_info_last_page() {
        print_page_info(10, 10, 200, "results");
    }

    // ---- short_id ----

    #[test]
    fn short_id_format() {
        let id = uuid::Uuid::nil();
        assert_eq!(short_id(&id), "00000000");
    }

    // ---- sdk_err ----

    #[test]
    fn sdk_err_message() {
        let err = sdk_err("list keys", "connection refused");
        assert!(err.to_string().contains("Failed to list keys"));
        assert!(err.to_string().contains("connection refused"));
    }

    // ---- new_table ----

    #[test]
    fn new_table_has_headers() {
        let table = new_table(vec!["A", "B", "C"]);
        let s = table.to_string();
        assert!(s.contains("A"));
        assert!(s.contains("B"));
        assert!(s.contains("C"));
    }

    // ---- resolve_secret_from ----

    fn cursor(s: &str) -> std::io::Cursor<Vec<u8>> {
        std::io::Cursor::new(s.as_bytes().to_vec())
    }

    #[test]
    fn secret_from_stdin_flag_reads_and_trims() {
        let mut input = cursor("s3cr3t\n");
        let got =
            resolve_secret_from(None, true, Some("Secret"), false, true, || &mut input).unwrap();
        assert_eq!(got.as_deref(), Some("s3cr3t"));
    }

    #[test]
    fn secret_from_stdin_flag_trims_crlf() {
        let mut input = cursor("s3cr3t\r\n");
        let got =
            resolve_secret_from(None, true, Some("Secret"), false, true, || &mut input).unwrap();
        assert_eq!(got.as_deref(), Some("s3cr3t"));
    }

    #[test]
    fn secret_from_stdin_flag_wins_over_value() {
        let mut input = cursor("from-stdin\n");
        let got = resolve_secret_from(
            Some("from-flag".into()),
            true,
            Some("Secret"),
            false,
            true,
            || &mut input,
        )
        .unwrap();
        assert_eq!(got.as_deref(), Some("from-stdin"));
    }

    #[test]
    fn secret_from_stdin_flag_empty_means_none() {
        let mut input = cursor("\n");
        let got =
            resolve_secret_from(None, true, Some("Secret"), false, true, || &mut input).unwrap();
        assert_eq!(got, None);
    }

    #[test]
    fn secret_explicit_value_used_verbatim() {
        let mut input = cursor("ignored");
        let got = resolve_secret_from(
            Some("from-flag".into()),
            false,
            Some("Secret"),
            true,
            false,
            || &mut input,
        )
        .unwrap();
        assert_eq!(got.as_deref(), Some("from-flag"));
        // Nothing was consumed from stdin.
        assert_eq!(input.position(), 0);
    }

    #[test]
    fn secret_piped_stdin_read_when_omitted() {
        let mut input = cursor("piped-secret\n");
        let got =
            resolve_secret_from(None, false, Some("Secret"), false, false, || &mut input).unwrap();
        assert_eq!(got.as_deref(), Some("piped-secret"));
    }

    #[test]
    fn secret_piped_stdin_empty_means_none() {
        let mut input = cursor("");
        let got =
            resolve_secret_from(None, false, Some("Secret"), true, false, || &mut input).unwrap();
        assert_eq!(got, None);
    }

    #[test]
    fn secret_no_input_on_tty_means_none() {
        let mut input = cursor("should-not-be-read");
        let got =
            resolve_secret_from(None, false, Some("Secret"), true, true, || &mut input).unwrap();
        assert_eq!(got, None);
        assert_eq!(input.position(), 0);
    }

    #[test]
    fn secret_without_prompt_never_reads_stdin() {
        // prompt: None = update-style flows; omitted secret stays omitted even
        // when stdin is piped.
        let mut input = cursor("should-not-be-read");
        let got = resolve_secret_from(None, false, None, false, false, || &mut input).unwrap();
        assert_eq!(got, None);
        assert_eq!(input.position(), 0);
    }
}
