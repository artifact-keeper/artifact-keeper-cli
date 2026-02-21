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

    /// Manage user groups
    #[command(
        after_help = "Examples:\n  ak group list\n  ak group show <group-id>\n  ak group create dev-team --description \"Development team\"\n  ak group add-member <group-id> <user-id>"
    )]
    Group {
        #[command(subcommand)]
        command: commands::group::GroupCommand,
    },

    /// Manage promotion approval workflows
    #[command(
        after_help = "Examples:\n  ak approval list\n  ak approval list --status pending\n  ak approval show <approval-id>\n  ak approval approve <approval-id> --comment \"Looks good\"\n  ak approval reject <approval-id> --comment \"Needs fixes\""
    )]
    Approval {
        #[command(subcommand)]
        command: commands::approval::ApprovalCommand,
    },

    /// Promote artifacts between repositories
    #[command(
        after_help = "Examples:\n  ak promotion promote <artifact-id> --from staging --to production\n  ak promotion rule list\n  ak promotion rule create my-rule --from <repo-id> --to <repo-id> --auto\n  ak promotion history --repo my-repo"
    )]
    Promotion {
        #[command(subcommand)]
        command: commands::promotion::PromotionCommand,
    },

    /// Manage artifact quality gates
    #[command(
        alias = "qg",
        after_help = "Examples:\n  ak quality-gate list\n  ak quality-gate show <gate-id>\n  ak quality-gate create strict --max-critical 0 --max-high 5 --action block\n  ak quality-gate check <artifact-id>\n  ak quality-gate delete <gate-id>"
    )]
    QualityGate {
        #[command(subcommand)]
        command: commands::quality_gate::QualityGateCommand,
    },

    /// Tag repositories with key-value labels
    #[command(
        after_help = "Examples:\n  ak label repo list my-repo\n  ak label repo add my-repo env=production\n  ak label repo remove my-repo env"
    )]
    Label {
        #[command(subcommand)]
        command: commands::label::LabelCommand,
    },

    /// Manage lifecycle and retention policies
    #[command(
        after_help = "Examples:\n  ak lifecycle list\n  ak lifecycle show <policy-id>\n  ak lifecycle create my-policy --max-severity high --block-on-fail\n  ak lifecycle preview <policy-id>\n  ak lifecycle execute <policy-id>"
    )]
    Lifecycle {
        #[command(subcommand)]
        command: commands::lifecycle::LifecycleCommand,
    },

    /// Manage fine-grained permission rules
    #[command(
        after_help = "Examples:\n  ak permission list\n  ak permission create --principal <user-id> --principal-type user --target <repo-id> --target-type repository --actions read,write\n  ak permission delete <permission-id>"
    )]
    Permission {
        #[command(subcommand)]
        command: commands::permission::PermissionCommand,
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
            Command::Group { command } => command.execute(&global).await,
            Command::Approval { command } => command.execute(&global).await,
            Command::Promotion { command } => command.execute(&global).await,
            Command::QualityGate { command } => command.execute(&global).await,
            Command::Label { command } => command.execute(&global).await,
            Command::Lifecycle { command } => command.execute(&global).await,
            Command::Permission { command } => command.execute(&global).await,
            Command::Admin { command } => command.execute(&global).await,
            Command::Config { command } => command.execute(&global).await,
            Command::Tui => commands::tui::execute(&global).await,
            Command::Completion { shell } => commands::completion::execute(shell),
            Command::ManPages { dir } => commands::completion::generate_man_pages(&dir),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> std::result::Result<Cli, clap::Error> {
        Cli::try_parse_from(args)
    }

    // ---- Basic command parsing ----

    #[test]
    fn parse_auth_login() {
        let cli = parse(&["ak", "auth", "login"]).unwrap();
        assert!(matches!(cli.command, Command::Auth { .. }));
    }

    #[test]
    fn parse_auth_login_with_url() {
        let cli = parse(&["ak", "auth", "login", "https://example.com"]).unwrap();
        assert!(matches!(cli.command, Command::Auth { .. }));
    }

    #[test]
    fn parse_auth_login_token_flag() {
        let cli = parse(&["ak", "auth", "login", "--token"]).unwrap();
        assert!(matches!(cli.command, Command::Auth { .. }));
    }

    #[test]
    fn parse_auth_logout() {
        let cli = parse(&["ak", "auth", "logout"]).unwrap();
        assert!(matches!(cli.command, Command::Auth { .. }));
    }

    #[test]
    fn parse_auth_whoami() {
        let cli = parse(&["ak", "auth", "whoami"]).unwrap();
        assert!(matches!(cli.command, Command::Auth { .. }));
    }

    #[test]
    fn parse_auth_switch() {
        let cli = parse(&["ak", "auth", "switch"]).unwrap();
        assert!(matches!(cli.command, Command::Auth { .. }));
    }

    #[test]
    fn parse_auth_token_create() {
        let cli = parse(&["ak", "auth", "token", "create"]).unwrap();
        assert!(matches!(cli.command, Command::Auth { .. }));
    }

    #[test]
    fn parse_auth_token_list() {
        let cli = parse(&["ak", "auth", "token", "list"]).unwrap();
        assert!(matches!(cli.command, Command::Auth { .. }));
    }

    #[test]
    fn parse_instance_add() {
        let cli = parse(&["ak", "instance", "add", "prod", "https://prod.com"]).unwrap();
        assert!(matches!(cli.command, Command::Instance { .. }));
    }

    #[test]
    fn parse_instance_remove() {
        let cli = parse(&["ak", "instance", "remove", "prod"]).unwrap();
        assert!(matches!(cli.command, Command::Instance { .. }));
    }

    #[test]
    fn parse_instance_list() {
        let cli = parse(&["ak", "instance", "list"]).unwrap();
        assert!(matches!(cli.command, Command::Instance { .. }));
    }

    #[test]
    fn parse_instance_use() {
        let cli = parse(&["ak", "instance", "use", "prod"]).unwrap();
        assert!(matches!(cli.command, Command::Instance { .. }));
    }

    #[test]
    fn parse_instance_info() {
        let cli = parse(&["ak", "instance", "info"]).unwrap();
        assert!(matches!(cli.command, Command::Instance { .. }));
    }

    #[test]
    fn parse_repo_list() {
        let cli = parse(&["ak", "repo", "list"]).unwrap();
        assert!(matches!(cli.command, Command::Repo { .. }));
    }

    #[test]
    fn parse_repo_show() {
        let cli = parse(&["ak", "repo", "show", "my-repo"]).unwrap();
        assert!(matches!(cli.command, Command::Repo { .. }));
    }

    #[test]
    fn parse_repo_create() {
        let cli = parse(&["ak", "repo", "create", "my-repo", "--pkg-format", "npm"]).unwrap();
        assert!(matches!(cli.command, Command::Repo { .. }));
    }

    #[test]
    fn parse_repo_delete() {
        let cli = parse(&["ak", "repo", "delete", "my-repo"]).unwrap();
        assert!(matches!(cli.command, Command::Repo { .. }));
    }

    #[test]
    fn parse_artifact_push() {
        let cli = parse(&["ak", "artifact", "push", "my-repo", "file.tar.gz"]).unwrap();
        assert!(matches!(cli.command, Command::Artifact { .. }));
    }

    #[test]
    fn parse_artifact_pull() {
        let cli = parse(&["ak", "artifact", "pull", "my-repo", "org/pkg/1.0"]).unwrap();
        assert!(matches!(cli.command, Command::Artifact { .. }));
    }

    #[test]
    fn parse_artifact_list() {
        let cli = parse(&["ak", "artifact", "list", "my-repo"]).unwrap();
        assert!(matches!(cli.command, Command::Artifact { .. }));
    }

    #[test]
    fn parse_artifact_search() {
        let cli = parse(&["ak", "artifact", "search", "log4j"]).unwrap();
        assert!(matches!(cli.command, Command::Artifact { .. }));
    }

    #[test]
    fn parse_artifact_copy() {
        let cli = parse(&["ak", "artifact", "copy", "src/path", "dst/path"]).unwrap();
        assert!(matches!(cli.command, Command::Artifact { .. }));
    }

    #[test]
    fn parse_setup_auto() {
        let cli = parse(&["ak", "setup", "auto"]).unwrap();
        assert!(matches!(cli.command, Command::Setup { .. }));
    }

    #[test]
    fn parse_setup_npm() {
        let cli = parse(&["ak", "setup", "npm"]).unwrap();
        assert!(matches!(cli.command, Command::Setup { .. }));
    }

    #[test]
    fn parse_setup_npm_with_repo() {
        let cli = parse(&["ak", "setup", "npm", "--repo", "my-npm"]).unwrap();
        assert!(matches!(cli.command, Command::Setup { .. }));
    }

    #[test]
    fn parse_scan_run() {
        let cli = parse(&["ak", "scan", "run", "my-repo", "artifact/path"]).unwrap();
        assert!(matches!(cli.command, Command::Scan { .. }));
    }

    #[test]
    fn parse_scan_list() {
        let cli = parse(&["ak", "scan", "list"]).unwrap();
        assert!(matches!(cli.command, Command::Scan { .. }));
    }

    #[test]
    fn parse_scan_show() {
        let cli = parse(&["ak", "scan", "show", "scan-id"]).unwrap();
        assert!(matches!(cli.command, Command::Scan { .. }));
    }

    #[test]
    fn parse_doctor() {
        let cli = parse(&["ak", "doctor"]).unwrap();
        assert!(matches!(cli.command, Command::Doctor));
    }

    #[test]
    fn parse_tui() {
        let cli = parse(&["ak", "tui"]).unwrap();
        assert!(matches!(cli.command, Command::Tui));
    }

    #[test]
    fn parse_config_list() {
        let cli = parse(&["ak", "config", "list"]).unwrap();
        assert!(matches!(cli.command, Command::Config { .. }));
    }

    #[test]
    fn parse_config_get() {
        let cli = parse(&["ak", "config", "get", "output_format"]).unwrap();
        assert!(matches!(cli.command, Command::Config { .. }));
    }

    #[test]
    fn parse_config_set() {
        let cli = parse(&["ak", "config", "set", "color", "never"]).unwrap();
        assert!(matches!(cli.command, Command::Config { .. }));
    }

    #[test]
    fn parse_config_path() {
        let cli = parse(&["ak", "config", "path"]).unwrap();
        assert!(matches!(cli.command, Command::Config { .. }));
    }

    #[test]
    fn parse_admin_backup_list() {
        let cli = parse(&["ak", "admin", "backup", "list"]).unwrap();
        assert!(matches!(cli.command, Command::Admin { .. }));
    }

    #[test]
    fn parse_admin_metrics() {
        let cli = parse(&["ak", "admin", "metrics"]).unwrap();
        assert!(matches!(cli.command, Command::Admin { .. }));
    }

    #[test]
    fn parse_admin_users_list() {
        let cli = parse(&["ak", "admin", "users", "list"]).unwrap();
        assert!(matches!(cli.command, Command::Admin { .. }));
    }

    #[test]
    fn parse_admin_users_update() {
        let cli = parse(&[
            "ak",
            "admin",
            "users",
            "update",
            "some-id",
            "--email",
            "alice@new.com",
        ])
        .unwrap();
        assert!(matches!(cli.command, Command::Admin { .. }));
    }

    #[test]
    fn parse_admin_users_reset_password() {
        let cli = parse(&["ak", "admin", "users", "reset-password", "some-id"]).unwrap();
        assert!(matches!(cli.command, Command::Admin { .. }));
    }

    #[test]
    fn parse_admin_plugins_list() {
        let cli = parse(&["ak", "admin", "plugins", "list"]).unwrap();
        assert!(matches!(cli.command, Command::Admin { .. }));
    }

    #[test]
    fn parse_completion_bash() {
        let cli = parse(&["ak", "completion", "bash"]).unwrap();
        assert!(matches!(cli.command, Command::Completion { .. }));
    }

    #[test]
    fn parse_completion_zsh() {
        let cli = parse(&["ak", "completion", "zsh"]).unwrap();
        assert!(matches!(cli.command, Command::Completion { .. }));
    }

    #[test]
    fn parse_completion_fish() {
        let cli = parse(&["ak", "completion", "fish"]).unwrap();
        assert!(matches!(cli.command, Command::Completion { .. }));
    }

    #[test]
    fn parse_man_pages() {
        let cli = parse(&["ak", "man-pages", "/tmp/man"]).unwrap();
        assert!(matches!(cli.command, Command::ManPages { .. }));
    }

    #[test]
    fn parse_migrate() {
        let cli = parse(&[
            "ak",
            "migrate",
            "--from-instance",
            "staging",
            "--from-repo",
            "libs",
            "--to-repo",
            "libs-prod",
        ])
        .unwrap();
        assert!(matches!(cli.command, Command::Migrate { .. }));
    }

    // ---- Global flags ----

    #[test]
    fn parse_format_json() {
        let cli = parse(&["ak", "--format", "json", "doctor"]).unwrap();
        assert!(matches!(cli.format, OutputFormat::Json));
    }

    #[test]
    fn parse_format_yaml() {
        let cli = parse(&["ak", "--format", "yaml", "doctor"]).unwrap();
        assert!(matches!(cli.format, OutputFormat::Yaml));
    }

    #[test]
    fn parse_format_quiet() {
        let cli = parse(&["ak", "--format", "quiet", "doctor"]).unwrap();
        assert!(matches!(cli.format, OutputFormat::Quiet));
    }

    #[test]
    fn parse_quiet_flag() {
        let cli = parse(&["ak", "-q", "doctor"]).unwrap();
        assert!(cli.quiet);
    }

    #[test]
    fn parse_instance_flag() {
        let cli = parse(&["ak", "--instance", "prod", "doctor"]).unwrap();
        assert_eq!(cli.instance, Some("prod".into()));
    }

    #[test]
    fn parse_no_input_flag() {
        let cli = parse(&["ak", "--no-input", "doctor"]).unwrap();
        assert!(cli.no_input);
    }

    #[test]
    fn parse_color_never() {
        let cli = parse(&["ak", "--color", "never", "doctor"]).unwrap();
        assert!(matches!(cli.color, ColorMode::Never));
    }

    #[test]
    fn parse_color_always() {
        let cli = parse(&["ak", "--color", "always", "doctor"]).unwrap();
        assert!(matches!(cli.color, ColorMode::Always));
    }

    // ---- Group command parsing ----

    #[test]
    fn parse_group_list() {
        let cli = parse(&["ak", "group", "list"]).unwrap();
        assert!(matches!(cli.command, Command::Group { .. }));
    }

    #[test]
    fn parse_group_show() {
        let cli = parse(&["ak", "group", "show", "some-id"]).unwrap();
        assert!(matches!(cli.command, Command::Group { .. }));
    }

    #[test]
    fn parse_group_create() {
        let cli = parse(&["ak", "group", "create", "dev-team"]).unwrap();
        assert!(matches!(cli.command, Command::Group { .. }));
    }

    #[test]
    fn parse_group_delete() {
        let cli = parse(&["ak", "group", "delete", "some-id"]).unwrap();
        assert!(matches!(cli.command, Command::Group { .. }));
    }

    #[test]
    fn parse_group_add_member() {
        let cli = parse(&["ak", "group", "add-member", "group-id", "user-id"]).unwrap();
        assert!(matches!(cli.command, Command::Group { .. }));
    }

    #[test]
    fn parse_group_remove_member() {
        let cli = parse(&["ak", "group", "remove-member", "group-id", "user-id"]).unwrap();
        assert!(matches!(cli.command, Command::Group { .. }));
    }

    // ---- Label command parsing ----

    #[test]
    fn parse_label_repo_list() {
        let cli = parse(&["ak", "label", "repo", "list", "my-repo"]).unwrap();
        assert!(matches!(cli.command, Command::Label { .. }));
    }

    #[test]
    fn parse_label_repo_add() {
        let cli = parse(&["ak", "label", "repo", "add", "my-repo", "env=prod"]).unwrap();
        assert!(matches!(cli.command, Command::Label { .. }));
    }

    #[test]
    fn parse_label_repo_remove() {
        let cli = parse(&["ak", "label", "repo", "remove", "my-repo", "env"]).unwrap();
        assert!(matches!(cli.command, Command::Label { .. }));
    }

    // ---- Lifecycle command parsing ----

    #[test]
    fn parse_lifecycle_list() {
        let cli = parse(&["ak", "lifecycle", "list"]).unwrap();
        assert!(matches!(cli.command, Command::Lifecycle { .. }));
    }

    #[test]
    fn parse_lifecycle_show() {
        let cli = parse(&["ak", "lifecycle", "show", "policy-id"]).unwrap();
        assert!(matches!(cli.command, Command::Lifecycle { .. }));
    }

    #[test]
    fn parse_lifecycle_create() {
        let cli = parse(&[
            "ak",
            "lifecycle",
            "create",
            "my-policy",
            "--max-severity",
            "high",
            "--block-on-fail",
        ])
        .unwrap();
        assert!(matches!(cli.command, Command::Lifecycle { .. }));
    }

    #[test]
    fn parse_lifecycle_delete() {
        let cli = parse(&["ak", "lifecycle", "delete", "policy-id"]).unwrap();
        assert!(matches!(cli.command, Command::Lifecycle { .. }));
    }

    #[test]
    fn parse_lifecycle_preview() {
        let cli = parse(&["ak", "lifecycle", "preview", "policy-id"]).unwrap();
        assert!(matches!(cli.command, Command::Lifecycle { .. }));
    }

    #[test]
    fn parse_lifecycle_execute() {
        let cli = parse(&["ak", "lifecycle", "execute", "policy-id"]).unwrap();
        assert!(matches!(cli.command, Command::Lifecycle { .. }));
    }

    // ---- Quality gate command parsing ----

    #[test]
    fn parse_quality_gate_list() {
        let cli = parse(&["ak", "quality-gate", "list"]).unwrap();
        assert!(matches!(cli.command, Command::QualityGate { .. }));
    }

    #[test]
    fn parse_quality_gate_show() {
        let cli = parse(&["ak", "quality-gate", "show", "gate-id"]).unwrap();
        assert!(matches!(cli.command, Command::QualityGate { .. }));
    }

    #[test]
    fn parse_quality_gate_create() {
        let cli = parse(&[
            "ak",
            "quality-gate",
            "create",
            "strict",
            "--max-critical",
            "0",
            "--action",
            "block",
        ])
        .unwrap();
        assert!(matches!(cli.command, Command::QualityGate { .. }));
    }

    #[test]
    fn parse_quality_gate_update() {
        let cli = parse(&[
            "ak",
            "quality-gate",
            "update",
            "gate-id",
            "--max-critical",
            "1",
        ])
        .unwrap();
        assert!(matches!(cli.command, Command::QualityGate { .. }));
    }

    #[test]
    fn parse_quality_gate_delete() {
        let cli = parse(&["ak", "quality-gate", "delete", "gate-id"]).unwrap();
        assert!(matches!(cli.command, Command::QualityGate { .. }));
    }

    #[test]
    fn parse_quality_gate_check() {
        let cli = parse(&["ak", "quality-gate", "check", "artifact-id"]).unwrap();
        assert!(matches!(cli.command, Command::QualityGate { .. }));
    }

    // ---- Approval command parsing ----

    #[test]
    fn parse_approval_list() {
        let cli = parse(&["ak", "approval", "list"]).unwrap();
        assert!(matches!(cli.command, Command::Approval { .. }));
    }

    #[test]
    fn parse_approval_show() {
        let cli = parse(&["ak", "approval", "show", "some-id"]).unwrap();
        assert!(matches!(cli.command, Command::Approval { .. }));
    }

    #[test]
    fn parse_approval_approve() {
        let cli = parse(&["ak", "approval", "approve", "some-id", "--comment", "LGTM"]).unwrap();
        assert!(matches!(cli.command, Command::Approval { .. }));
    }

    #[test]
    fn parse_approval_reject() {
        let cli = parse(&["ak", "approval", "reject", "some-id"]).unwrap();
        assert!(matches!(cli.command, Command::Approval { .. }));
    }

    // ---- Promotion command parsing ----

    #[test]
    fn parse_promotion_promote() {
        let cli = parse(&[
            "ak",
            "promotion",
            "promote",
            "artifact-id",
            "--from",
            "staging",
            "--to",
            "prod",
        ])
        .unwrap();
        assert!(matches!(cli.command, Command::Promotion { .. }));
    }

    #[test]
    fn parse_promotion_rule_list() {
        let cli = parse(&["ak", "promotion", "rule", "list"]).unwrap();
        assert!(matches!(cli.command, Command::Promotion { .. }));
    }

    #[test]
    fn parse_promotion_rule_create() {
        let cli = parse(&[
            "ak",
            "promotion",
            "rule",
            "create",
            "my-rule",
            "--from",
            "src-id",
            "--to",
            "dst-id",
        ])
        .unwrap();
        assert!(matches!(cli.command, Command::Promotion { .. }));
    }

    #[test]
    fn parse_promotion_rule_delete() {
        let cli = parse(&["ak", "promotion", "rule", "delete", "rule-id"]).unwrap();
        assert!(matches!(cli.command, Command::Promotion { .. }));
    }

    #[test]
    fn parse_promotion_history() {
        let cli = parse(&["ak", "promotion", "history", "--repo", "my-repo"]).unwrap();
        assert!(matches!(cli.command, Command::Promotion { .. }));
    }

    // ---- Permission command parsing ----

    #[test]
    fn parse_permission_list() {
        let cli = parse(&["ak", "permission", "list"]).unwrap();
        assert!(matches!(cli.command, Command::Permission { .. }));
    }

    #[test]
    fn parse_permission_create() {
        let cli = parse(&[
            "ak",
            "permission",
            "create",
            "--principal",
            "00000000-0000-0000-0000-000000000001",
            "--principal-type",
            "user",
            "--target",
            "00000000-0000-0000-0000-000000000002",
            "--target-type",
            "repository",
            "--actions",
            "read,write",
        ])
        .unwrap();
        assert!(matches!(cli.command, Command::Permission { .. }));
    }

    #[test]
    fn parse_permission_delete() {
        let cli = parse(&["ak", "permission", "delete", "some-id"]).unwrap();
        assert!(matches!(cli.command, Command::Permission { .. }));
    }

    // ---- Error cases ----

    #[test]
    fn parse_no_command_fails() {
        assert!(parse(&["ak"]).is_err());
    }

    #[test]
    fn parse_unknown_command_fails() {
        assert!(parse(&["ak", "unknown-command"]).is_err());
    }

    #[test]
    fn parse_invalid_format_fails() {
        assert!(parse(&["ak", "--format", "xml", "doctor"]).is_err());
    }

    #[test]
    fn parse_missing_required_arg_fails() {
        // instance add requires name and url
        assert!(parse(&["ak", "instance", "add"]).is_err());
        assert!(parse(&["ak", "instance", "add", "name"]).is_err());
    }

    #[test]
    fn parse_repo_create_requires_format() {
        assert!(parse(&["ak", "repo", "create", "key"]).is_err());
    }

    // ---- Global args extraction ----

    #[test]
    fn default_format_is_table() {
        let cli = parse(&["ak", "doctor"]).unwrap();
        assert!(matches!(cli.format, OutputFormat::Table));
    }

    #[test]
    fn default_no_input_is_false() {
        let cli = parse(&["ak", "doctor"]).unwrap();
        assert!(!cli.no_input);
    }

    #[test]
    fn default_quiet_is_false() {
        let cli = parse(&["ak", "doctor"]).unwrap();
        assert!(!cli.quiet);
    }

    #[test]
    fn default_instance_is_none() {
        let cli = parse(&["ak", "doctor"]).unwrap();
        assert!(cli.instance.is_none());
    }

    #[test]
    fn default_color_is_auto() {
        let cli = parse(&["ak", "doctor"]).unwrap();
        assert!(matches!(cli.color, ColorMode::Auto));
    }
}
