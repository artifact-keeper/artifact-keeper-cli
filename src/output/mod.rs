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

/// Render any serializable data in the requested format.
/// For table output, the caller should provide a pre-formatted table string.
pub fn render<T: Serialize>(data: &T, format: &OutputFormat, table: Option<String>) -> String {
    match format {
        OutputFormat::Table => {
            table.unwrap_or_else(|| serde_json::to_string_pretty(data).unwrap_or_default())
        }
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
}
