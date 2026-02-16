use clap::Subcommand;
use miette::Result;

use crate::cli::GlobalArgs;

#[derive(Subcommand)]
pub enum InstanceCommand {
    /// Add an Artifact Keeper server
    Add {
        /// Friendly name for this instance
        name: String,

        /// Server URL (e.g., https://registry.company.com)
        url: String,
    },

    /// Remove a configured instance
    Remove {
        /// Instance name to remove
        name: String,
    },

    /// List all configured instances
    List,

    /// Set the default instance
    Use {
        /// Instance name to set as default
        name: String,
    },

    /// Show details about an instance
    Info {
        /// Instance name (uses default if omitted)
        name: Option<String>,
    },
}

impl InstanceCommand {
    pub async fn execute(self, _global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Add { name, url } => {
                eprintln!("ak instance add: {}={} (not yet implemented)", name, url);
            }
            Self::Remove { name } => {
                eprintln!("ak instance remove: {} (not yet implemented)", name);
            }
            Self::List => {
                eprintln!("ak instance list (not yet implemented)");
            }
            Self::Use { name } => {
                eprintln!("ak instance use: {} (not yet implemented)", name);
            }
            Self::Info { name } => {
                eprintln!("ak instance info: {:?} (not yet implemented)", name);
            }
        }
        Ok(())
    }
}
