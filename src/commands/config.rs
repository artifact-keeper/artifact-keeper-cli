use clap::Subcommand;
use miette::Result;

use crate::cli::GlobalArgs;

#[derive(Subcommand)]
pub enum ConfigCommand {
    /// Get a configuration value
    Get {
        /// Configuration key
        key: String,
    },

    /// Set a configuration value
    Set {
        /// Configuration key
        key: String,
        /// Configuration value
        value: String,
    },

    /// List all configuration values
    List,
}

impl ConfigCommand {
    pub async fn execute(self, _global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Get { key } => {
                eprintln!("ak config get: {} (not yet implemented)", key);
            }
            Self::Set { key, value } => {
                eprintln!("ak config set: {}={} (not yet implemented)", key, value);
            }
            Self::List => {
                eprintln!("ak config list (not yet implemented)");
            }
        }
        Ok(())
    }
}
