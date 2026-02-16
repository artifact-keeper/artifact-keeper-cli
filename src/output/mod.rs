use serde::Serialize;

#[derive(Clone, Debug, clap::ValueEnum)]
pub enum OutputFormat {
    Table,
    Json,
    Yaml,
    Quiet,
}

/// Render any serializable data in the requested format.
/// For table output, the caller should provide a pre-formatted table string.
pub fn render<T: Serialize>(data: &T, format: &OutputFormat, table: Option<String>) -> String {
    match format {
        OutputFormat::Table => table.unwrap_or_else(|| {
            // Fallback: pretty JSON if no table provided
            serde_json::to_string_pretty(data).unwrap_or_default()
        }),
        OutputFormat::Json => {
            if console::Term::stdout().is_term() {
                serde_json::to_string_pretty(data).unwrap_or_default()
            } else {
                serde_json::to_string(data).unwrap_or_default()
            }
        }
        OutputFormat::Yaml => serde_yaml::to_string(data).unwrap_or_default(),
        OutputFormat::Quiet => String::new(), // Caller handles quiet mode
    }
}

/// Detect if we're in a non-interactive (piped) context.
pub fn is_interactive() -> bool {
    console::Term::stdout().is_term() && console::Term::stderr().is_term()
}
