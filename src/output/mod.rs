use serde::Serialize;

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum OutputFormat {
    Table,
    Json,
    Yaml,
    Quiet,
}

impl OutputFormat {
    /// Resolve the effective format, auto-detecting piped output.
    ///
    /// When the user hasn't explicitly set a format (i.e. the default "table" is
    /// in effect) and stdout is not a TTY, switch to JSON for pipe-friendly output.
    pub fn resolve(self, explicitly_set: bool) -> Self {
        if !explicitly_set && matches!(self, Self::Table) && !console::Term::stdout().is_term() {
            Self::Json
        } else {
            self
        }
    }
}

/// Returns `true` for control characters that must not be written verbatim to a
/// terminal. Covers the C0 range (0x00–0x1F, including ESC 0x1B, BEL 0x07 and CR
/// 0x0D), DEL (0x7F) and the C1 range (0x80–0x9F). Tab (0x09) and line feed
/// (0x0A) are intentionally allowed so tables and multi-line values still render.
fn is_unsafe_control(c: char) -> bool {
    match c {
        '\t' | '\n' => false,
        '\u{00}'..='\u{1f}' | '\u{7f}' => true,
        '\u{80}'..='\u{9f}' => true,
        _ => false,
    }
}

/// Neutralize server-derived strings before they are displayed on a terminal.
///
/// A malicious publisher or hostile server can embed ANSI/OSC/cursor-control
/// escape sequences in artifact names, paths, labels, descriptions or search
/// results. When those are printed verbatim they execute in the victim's
/// terminal: spoofing output, rewriting the window title, hiding or overwriting
/// lines, or triggering terminal-emulator exploits. This helper rewrites every
/// dangerous control character into its visible, inert escaped form (e.g. ESC
/// becomes the literal text `\u{1b}`) so the data stays readable but can no
/// longer drive the terminal. Tab and newline are preserved.
///
/// This must only be applied to human/quiet display paths. JSON and YAML output
/// is already safe (serde escapes control characters) and is the machine-readable
/// path, so it must not be run through this function.
pub fn sanitize_terminal(s: &str) -> String {
    if !s.chars().any(is_unsafe_control) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if is_unsafe_control(c) {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// Render any serializable data in the requested format.
/// For table output, the caller should provide a pre-formatted table string.
pub fn render<T: Serialize>(data: &T, format: &OutputFormat, table: Option<String>) -> String {
    match format {
        // The table/human path is a terminal display surface, so any
        // server-derived content it carries is sanitized centrally here. Box
        // drawing, tabs and newlines are preserved; escape/control bytes are
        // neutralized. JSON/YAML below are left untouched (serde-escaped).
        OutputFormat::Table => sanitize_terminal(
            &table.unwrap_or_else(|| serde_json::to_string_pretty(data).unwrap_or_default()),
        ),
        OutputFormat::Json => {
            if console::Term::stdout().is_term() {
                serde_json::to_string_pretty(data).unwrap_or_default()
            } else {
                serde_json::to_string(data).unwrap_or_default()
            }
        }
        OutputFormat::Yaml => serde_yaml::to_string(data).unwrap_or_default(),
        OutputFormat::Quiet => String::new(),
    }
}

/// Format a byte count as a human-readable string (e.g., "1.5 MB").
pub fn format_bytes(bytes: i64) -> String {
    const KB: i64 = 1024;
    const MB: i64 = KB * 1024;
    const GB: i64 = MB * 1024;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// Create a progress spinner on stderr for long-running operations.
pub fn spinner(message: &str) -> indicatif::ProgressBar {
    let pb = indicatif::ProgressBar::new_spinner();
    pb.set_style(
        indicatif::ProgressStyle::with_template("{spinner:.cyan} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "✓"]),
    );
    pb.set_message(message.to_string());
    pb.enable_steady_tick(std::time::Duration::from_millis(80));
    pb
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- format_bytes ----

    #[test]
    fn format_bytes_zero() {
        assert_eq!(format_bytes(0), "0 B");
    }

    #[test]
    fn format_bytes_small() {
        assert_eq!(format_bytes(1), "1 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1023), "1023 B");
    }

    #[test]
    fn format_bytes_kilobytes() {
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(10240), "10.0 KB");
        // Just below 1 MB
        assert_eq!(format_bytes(1024 * 1023), "1023.0 KB");
    }

    #[test]
    fn format_bytes_megabytes() {
        assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(format_bytes(1024 * 1024 * 5), "5.0 MB");
        assert_eq!(format_bytes(1024 * 1024 + 512 * 1024), "1.5 MB");
    }

    #[test]
    fn format_bytes_gigabytes() {
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GB");
        assert_eq!(format_bytes(1024_i64 * 1024 * 1024 * 2), "2.0 GB");
        assert_eq!(format_bytes(1024_i64 * 1024 * 1024 * 100), "100.0 GB");
    }

    #[test]
    fn format_bytes_negative() {
        assert_eq!(format_bytes(-1), "-1 B");
        assert_eq!(format_bytes(-100), "-100 B");
    }

    // ---- render ----

    #[test]
    fn render_quiet_returns_empty() {
        let data = serde_json::json!({"key": "value"});
        assert_eq!(render(&data, &OutputFormat::Quiet, None), "");
    }

    #[test]
    fn render_quiet_ignores_table() {
        let data = serde_json::json!({"key": "value"});
        assert_eq!(
            render(&data, &OutputFormat::Quiet, Some("table".into())),
            ""
        );
    }

    #[test]
    fn render_table_uses_provided_string() {
        let data = serde_json::json!({"key": "value"});
        let table = "my table output".to_string();
        assert_eq!(
            render(&data, &OutputFormat::Table, Some(table)),
            "my table output"
        );
    }

    #[test]
    fn render_table_fallback_to_json() {
        let data = serde_json::json!({"key": "value"});
        let result = render(&data, &OutputFormat::Table, None);
        assert!(result.contains("key"));
        assert!(result.contains("value"));
    }

    #[test]
    fn render_json_contains_data() {
        let data = serde_json::json!({"name": "test", "count": 42});
        let result = render(&data, &OutputFormat::Json, None);
        assert!(result.contains("name"));
        assert!(result.contains("test"));
        assert!(result.contains("42"));
    }

    #[test]
    fn render_yaml_output() {
        let data = serde_json::json!({"key": "value"});
        let result = render(&data, &OutputFormat::Yaml, None);
        assert!(result.contains("key"));
        assert!(result.contains("value"));
    }

    #[test]
    fn render_yaml_ignores_table() {
        let data = serde_json::json!({"key": "value"});
        let result = render(&data, &OutputFormat::Yaml, Some("table".into()));
        // YAML format ignores the provided table
        assert!(result.contains("key"));
        assert!(result.contains("value"));
    }

    #[test]
    fn render_json_ignores_table() {
        let data = serde_json::json!({"key": "value"});
        let result = render(&data, &OutputFormat::Json, Some("table".into()));
        // JSON format ignores the provided table
        assert!(result.contains("key"));
        assert!(result.contains("value"));
    }

    #[test]
    fn render_array_data() {
        let data = serde_json::json!([{"a": 1}, {"a": 2}]);
        let result = render(&data, &OutputFormat::Json, None);
        assert!(result.contains("["));
        assert!(result.contains("1"));
        assert!(result.contains("2"));
    }

    // ---- OutputFormat::resolve ----

    #[test]
    fn resolve_keeps_explicit_table() {
        let fmt = OutputFormat::Table;
        let resolved = fmt.resolve(true);
        assert!(matches!(resolved, OutputFormat::Table));
    }

    #[test]
    fn resolve_keeps_json() {
        let fmt = OutputFormat::Json;
        let resolved = fmt.resolve(false);
        assert!(matches!(resolved, OutputFormat::Json));
    }

    #[test]
    fn resolve_keeps_yaml() {
        let fmt = OutputFormat::Yaml;
        let resolved = fmt.resolve(false);
        assert!(matches!(resolved, OutputFormat::Yaml));
    }

    #[test]
    fn resolve_keeps_quiet() {
        let fmt = OutputFormat::Quiet;
        let resolved = fmt.resolve(false);
        assert!(matches!(resolved, OutputFormat::Quiet));
    }

    // ---- sanitize_terminal ----

    #[test]
    fn sanitize_leaves_plain_text_untouched() {
        let s = "artifact-1.2.3.tar.gz";
        assert_eq!(sanitize_terminal(s), s);
    }

    #[test]
    fn sanitize_preserves_tab_and_newline() {
        let s = "col1\tcol2\nrow2";
        assert_eq!(sanitize_terminal(s), s);
    }

    #[test]
    fn sanitize_neutralizes_ansi_color_escape() {
        // ESC [ 31 m ... ESC [ 0 m
        let s = "\x1b[31;1mSYSTEM_OK\x1b[0m";
        let out = sanitize_terminal(s);
        assert!(!out.contains('\x1b'), "raw ESC (0x1b) must be gone");
        assert!(out.contains("SYSTEM_OK"), "readable text must survive");
        assert!(out.contains("\\u{1b}"), "ESC should be shown escaped");
    }

    #[test]
    fn sanitize_neutralizes_osc_title_and_bel() {
        // OSC 0 ; PWNED BEL — rewrites the terminal title
        let s = "\x1b]0;PWNED\x07";
        let out = sanitize_terminal(s);
        assert!(!out.contains('\x1b'), "raw ESC must be gone");
        assert!(!out.contains('\x07'), "raw BEL (0x07) must be gone");
        assert!(out.contains("PWNED"));
    }

    #[test]
    fn sanitize_neutralizes_carriage_return_and_c1() {
        let s = "visible\rHIDDEN\u{85}tail";
        let out = sanitize_terminal(s);
        assert!(!out.contains('\r'), "CR must be neutralized");
        assert!(!out.contains('\u{85}'), "C1 control must be neutralized");
        assert!(out.contains("visible"));
        assert!(out.contains("HIDDEN"));
    }

    #[test]
    fn sanitize_is_stable_when_applied_twice() {
        let once = sanitize_terminal("\x1b[31mx\x1b[0m");
        let twice = sanitize_terminal(&once);
        assert_eq!(once, twice, "sanitizing already-safe text is a no-op");
    }

    #[test]
    fn render_table_sanitizes_embedded_escape() {
        let data = serde_json::json!({"k": "v"});
        let table = "PATH\n\x1b[31mrtansi\x1b]0;PWNED\x07".to_string();
        let out = render(&data, &OutputFormat::Table, Some(table));
        assert!(!out.contains('\x1b'), "table path must strip raw ESC");
        assert!(!out.contains('\x07'), "table path must strip raw BEL");
        assert!(out.contains("rtansi"));
    }

    #[test]
    fn render_json_does_not_alter_serde_escaping() {
        // JSON is the machine-readable safe path: serde already escapes controls.
        let data = serde_json::json!({"name": "\x1b[31mx"});
        let out = render(&data, &OutputFormat::Json, None);
        assert!(!out.contains('\x1b'), "serde emits no raw ESC");
        // serde renders the control byte as , not our \u{1b} form.
        assert!(out.contains("\\u001b"));
    }
}
