use clap::Subcommand;
use miette::Result;

use crate::cli::GlobalArgs;

#[derive(Subcommand)]
pub enum AdminCommand {
    /// Manage backups
    Backup {
        #[command(subcommand)]
        command: BackupCommand,
    },

    /// Run storage cleanup
    Cleanup {
        /// Preview changes without executing
        #[arg(long)]
        dry_run: bool,
    },

    /// Show server metrics
    Metrics,

    /// Manage users
    Users {
        #[command(subcommand)]
        command: UsersCommand,
    },

    /// Manage WASM plugins
    Plugins {
        #[command(subcommand)]
        command: PluginsCommand,
    },
}

#[derive(Subcommand)]
pub enum BackupCommand {
    /// List available backups
    List,
    /// Create a new backup
    Create,
    /// Restore from a backup
    Restore {
        /// Backup ID
        id: String,
    },
}

#[derive(Subcommand)]
pub enum UsersCommand {
    /// List users
    List,
    /// Create a user
    Create {
        /// Username
        username: String,
    },
    /// Delete a user
    Delete {
        /// Username
        username: String,
    },
}

#[derive(Subcommand)]
pub enum PluginsCommand {
    /// List installed plugins
    List,
    /// Install a plugin
    Install {
        /// Plugin source (URL or path)
        source: String,
    },
    /// Remove a plugin
    Remove {
        /// Plugin name
        name: String,
    },
}

impl AdminCommand {
    pub async fn execute(self, _global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Backup { command } => match command {
                BackupCommand::List => {
                    eprintln!("ak admin backup list (not yet implemented)");
                }
                BackupCommand::Create => {
                    eprintln!("ak admin backup create (not yet implemented)");
                }
                BackupCommand::Restore { id } => {
                    eprintln!("ak admin backup restore: {} (not yet implemented)", id);
                }
            },
            Self::Cleanup { dry_run } => {
                eprintln!(
                    "ak admin cleanup: dry_run={} (not yet implemented)",
                    dry_run
                );
            }
            Self::Metrics => {
                eprintln!("ak admin metrics (not yet implemented)");
            }
            Self::Users { command } => match command {
                UsersCommand::List => {
                    eprintln!("ak admin users list (not yet implemented)");
                }
                UsersCommand::Create { username } => {
                    eprintln!("ak admin users create: {} (not yet implemented)", username);
                }
                UsersCommand::Delete { username } => {
                    eprintln!("ak admin users delete: {} (not yet implemented)", username);
                }
            },
            Self::Plugins { command } => match command {
                PluginsCommand::List => {
                    eprintln!("ak admin plugins list (not yet implemented)");
                }
                PluginsCommand::Install { source } => {
                    eprintln!("ak admin plugins install: {} (not yet implemented)", source);
                }
                PluginsCommand::Remove { name } => {
                    eprintln!("ak admin plugins remove: {} (not yet implemented)", name);
                }
            },
        }
        Ok(())
    }
}
