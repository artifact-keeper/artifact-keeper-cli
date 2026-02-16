use clap::{Parser, Subcommand};
use clap_complete::Shell;
use miette::Result;

use crate::commands;
use crate::output::OutputFormat;

/// Global options extracted before command dispatch.
#[derive(Debug)]
pub struct GlobalArgs {
    pub format: OutputFormat,
    pub instance: Option<String>,
    pub no_input: bool,
}

#[derive(Parser)]
#[command(
    name = "ak",
    about = "Artifact Keeper CLI — manage artifacts, repositories, and registries",
    version,
    long_about = None,
    propagate_version = true
)]
pub struct Cli {
    /// Output format
    #[arg(long, global = true, default_value = "table", env = "AK_FORMAT")]
    pub format: OutputFormat,

    /// Target instance (overrides default)
    #[arg(long, global = true, env = "AK_INSTANCE")]
    pub instance: Option<String>,

    /// Disable interactive prompts
    #[arg(long, global = true, env = "AK_NO_INPUT")]
    pub no_input: bool,

    /// Color output
    #[arg(long, global = true, default_value = "auto", env = "AK_COLOR")]
    pub color: ColorMode,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Clone, clap::ValueEnum)]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}

#[derive(Subcommand)]
pub enum Command {
    /// Authenticate with an Artifact Keeper instance
    Auth {
        #[command(subcommand)]
        command: commands::auth::AuthCommand,
    },

    /// Manage Artifact Keeper instances (servers)
    Instance {
        #[command(subcommand)]
        command: commands::instance::InstanceCommand,
    },

    /// Browse and manage repositories
    Repo {
        #[command(subcommand)]
        command: commands::repo::RepoCommand,
    },

    /// Upload, download, search, and manage artifacts
    Artifact {
        #[command(subcommand)]
        command: commands::artifact::ArtifactCommand,
    },

    /// Configure local package managers to use Artifact Keeper
    Setup {
        #[command(subcommand)]
        command: commands::setup::SetupCommand,
    },

    /// Trigger and view security scan results
    Scan {
        #[command(subcommand)]
        command: commands::scan::ScanCommand,
    },

    /// Diagnose configuration and connectivity issues
    Doctor,

    /// Administrative operations (backup, cleanup, users, plugins)
    Admin {
        #[command(subcommand)]
        command: commands::admin::AdminCommand,
    },

    /// Manage CLI configuration
    Config {
        #[command(subcommand)]
        command: commands::config::ConfigCommand,
    },

    /// Launch interactive TUI dashboard
    Tui,

    /// Generate shell completions
    Completion {
        /// Shell to generate completions for
        shell: Shell,
    },
}

impl Cli {
    pub async fn execute(self) -> Result<()> {
        // Respect NO_COLOR env var
        if std::env::var("NO_COLOR").is_ok() || matches!(self.color, ColorMode::Never) {
            console::set_colors_enabled(false);
            console::set_colors_enabled_stderr(false);
        }

        let global = GlobalArgs {
            format: self.format,
            instance: self.instance,
            no_input: self.no_input,
        };

        match self.command {
            Command::Auth { command } => command.execute(&global).await,
            Command::Instance { command } => command.execute(&global).await,
            Command::Repo { command } => command.execute(&global).await,
            Command::Artifact { command } => command.execute(&global).await,
            Command::Setup { command } => command.execute(&global).await,
            Command::Scan { command } => command.execute(&global).await,
            Command::Doctor => commands::doctor::execute(&global).await,
            Command::Admin { command } => command.execute(&global).await,
            Command::Config { command } => command.execute(&global).await,
            Command::Tui => commands::tui::execute(&global).await,
            Command::Completion { shell } => commands::completion::execute(shell),
        }
    }
}
