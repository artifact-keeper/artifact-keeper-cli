use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use miette::{IntoDiagnostic, Result};

use crate::error::AkError;

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
}
