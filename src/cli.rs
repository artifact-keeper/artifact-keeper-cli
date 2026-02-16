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
    /// Output format (auto-detects: table for TTY, json for pipes)
    #[arg(long, global = true, default_value = "table", env = "AK_FORMAT")]
    pub format: OutputFormat,

    /// Suppress all output except primary identifiers (shorthand for --format quiet)
    #[arg(short, long, global = true)]
    pub quiet: bool,

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
    #[command(
        after_help = "Examples:\n  ak auth login\n  ak auth login https://registry.company.com\n  ak auth login --token\n  ak auth whoami\n  ak auth logout"
    )]
    Auth {
        #[command(subcommand)]
        command: commands::auth::AuthCommand,
    },

    /// Manage Artifact Keeper instances (servers)
    #[command(
        after_help = "Examples:\n  ak instance add prod https://registry.company.com\n  ak instance list\n  ak instance use prod\n  ak instance info"
    )]
    Instance {
        #[command(subcommand)]
        command: commands::instance::InstanceCommand,
    },

    /// Browse and manage repositories
    #[command(
        after_help = "Examples:\n  ak repo list\n  ak repo list --pkg-format npm\n  ak repo show my-npm-repo\n  ak repo create my-pypi --pkg-format pypi --type local"
    )]
    Repo {
        #[command(subcommand)]
        command: commands::repo::RepoCommand,
    },

    /// Upload, download, search, and manage artifacts
    #[command(
        after_help = "Examples:\n  ak artifact push my-repo ./package-1.0.tar.gz\n  ak artifact pull my-repo org/pkg/1.0/pkg-1.0.jar -o pkg.jar\n  ak artifact list my-repo\n  ak artifact search \"log4j\" --pkg-format maven\n  ak artifact copy src-repo/path dst-repo/path\n  ak artifact copy src/path dst/path --from-instance staging --to-instance prod"
    )]
    Artifact {
        #[command(subcommand)]
        command: commands::artifact::ArtifactCommand,
    },

    /// Configure local package managers to use Artifact Keeper
    #[command(
        after_help = "Examples:\n  ak setup auto\n  ak setup npm --repo my-npm-repo\n  ak setup pip\n  ak setup docker\n  ak setup maven --repo libs-release"
    )]
    Setup {
        #[command(subcommand)]
        command: commands::setup::SetupCommand,
    },

    /// Trigger and view security scan results
    #[command(
        after_help = "Examples:\n  ak scan run my-repo org/pkg/1.0/pkg.jar\n  ak scan list --repo my-repo\n  ak scan show <scan-id>"
    )]
    Scan {
        #[command(subcommand)]
        command: commands::scan::ScanCommand,
    },

    /// Diagnose configuration and connectivity issues
    #[command(
        after_help = "Runs diagnostics:\n  - Config file readability\n  - Instance connectivity\n  - Auth token validity\n  - Package manager detection"
    )]
    Doctor,

    /// Migrate artifacts between instances in bulk
    #[command(
        after_help = "Examples:\n  ak migrate --from-instance staging --from-repo libs --to-repo libs-prod --dry-run\n  ak migrate --from-instance old --from-repo npm --to-instance new --to-repo npm"
    )]
    Migrate {
        /// Source instance name
        #[arg(long)]
        from_instance: String,

        /// Source repository key
        #[arg(long)]
        from_repo: String,

        /// Destination instance (defaults to current instance)
        #[arg(long)]
        to_instance: Option<String>,

        /// Destination repository key
        #[arg(long)]
        to_repo: String,

        /// Preview what would be migrated without transferring
        #[arg(long)]
        dry_run: bool,
    },

    /// Administrative operations (backup, cleanup, users, plugins)
    #[command(
        after_help = "Examples:\n  ak admin backup list\n  ak admin backup create --type full\n  ak admin cleanup --audit-logs --old-backups\n  ak admin metrics\n  ak admin users list\n  ak admin plugins list"
    )]
    Admin {
        #[command(subcommand)]
        command: commands::admin::AdminCommand,
    },

    /// Manage CLI configuration
    #[command(
        after_help = "Examples:\n  ak config list\n  ak config get default_instance\n  ak config set default_instance prod"
    )]
    Config {
        #[command(subcommand)]
        command: commands::config::ConfigCommand,
    },

    /// Launch interactive TUI dashboard
    #[command(
        after_help = "Navigation:\n  hjkl/arrows  Move between panels and items\n  Tab          Next panel\n  Enter        Select / drill down\n  i            Toggle detail view\n  /            Search\n  r            Refresh\n  ?            Help\n  q            Quit"
    )]
    Tui,

    /// Generate shell completions
    #[command(
        after_help = "Examples:\n  ak completion bash > ~/.bash_completion.d/ak\n  ak completion zsh > ~/.zfunc/_ak\n  ak completion fish > ~/.config/fish/completions/ak.fish\n  ak completion powershell > ak.ps1"
    )]
    Completion {
        /// Shell to generate completions for
        shell: Shell,
    },

    /// Generate man pages
    #[command(
        after_help = "Examples:\n  ak man-pages ./man\n  sudo cp man/*.1 /usr/local/share/man/man1/"
    )]
    ManPages {
        /// Output directory for man pages
        #[arg(default_value = ".")]
        dir: String,
    },
}

impl Cli {
    pub async fn execute(self) -> Result<()> {
        // Respect NO_COLOR env var
        if std::env::var("NO_COLOR").is_ok() || matches!(self.color, ColorMode::Never) {
            console::set_colors_enabled(false);
            console::set_colors_enabled_stderr(false);
        }

        // --quiet flag overrides --format
        let format = if self.quiet {
            OutputFormat::Quiet
        } else {
            // Auto-detect: when stdout is piped and format wasn't explicitly set
            // via CLI or env, switch from table to JSON.
            let explicitly_set = std::env::var("AK_FORMAT").is_ok()
                || std::env::args().any(|a| a == "--format" || a.starts_with("--format="));
            self.format.resolve(explicitly_set)
        };

        let global = GlobalArgs {
            format,
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
            Command::Migrate {
                from_instance,
                from_repo,
                to_instance,
                to_repo,
                dry_run,
            } => {
                commands::migrate::execute(
                    &from_instance,
                    &from_repo,
                    to_instance.as_deref(),
                    &to_repo,
                    dry_run,
                    &global,
                )
                .await
            }
            Command::Admin { command } => command.execute(&global).await,
            Command::Config { command } => command.execute(&global).await,
            Command::Tui => commands::tui::execute(&global).await,
            Command::Completion { shell } => commands::completion::execute(shell),
            Command::ManPages { dir } => commands::completion::generate_man_pages(&dir),
        }
    }
}
