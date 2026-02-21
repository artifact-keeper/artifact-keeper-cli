use miette::{IntoDiagnostic, Result};

use crate::error::AkError;

/// Parse a string as a UUID, returning a friendly error with the given label.
pub fn parse_uuid(id: &str, label: &str) -> Result<uuid::Uuid> {
    id.parse()
        .map_err(|_| AkError::ConfigError(format!("Invalid {label} ID: {id}")).into())
}

/// Parse an optional string as a UUID.
pub fn parse_optional_uuid(id: Option<&str>, label: &str) -> Result<Option<uuid::Uuid>> {
    id.map(|v| parse_uuid(v, label)).transpose()
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
