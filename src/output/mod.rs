use serde::Serialize;

#[derive(Clone, Debug, clap::ValueEnum)]
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
    pub fn resolve(&self, explicitly_set: bool) -> &Self {
        if !explicitly_set && matches!(self, Self::Table) && !console::Term::stdout().is_term() {
            &Self::Json
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

/// Detect if stdout is a terminal (interactive context).
pub fn is_interactive() -> bool {
    console::Term::stdout().is_term()
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
