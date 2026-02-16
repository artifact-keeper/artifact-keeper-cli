use clap::Subcommand;
use miette::Result;

use crate::cli::GlobalArgs;

#[derive(Subcommand)]
pub enum AuthCommand {
    /// Log in to an Artifact Keeper instance
    Login {
        /// Instance URL (uses default instance if omitted)
        url: Option<String>,

        /// Authenticate with an API token instead of browser flow
        #[arg(long)]
        token: bool,
    },

    /// Log out and remove stored credentials
    Logout {
        /// Instance to log out from (uses default if omitted)
        instance: Option<String>,
    },

    /// Manage API tokens
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },

    /// Show current authenticated user and instance
    Whoami,

    /// Switch between accounts on the same instance
    Switch,
}

#[derive(Subcommand)]
pub enum TokenCommand {
    /// Create a new API token
    Create {
        /// Token description
        #[arg(long)]
        description: Option<String>,

        /// Expiration in days
        #[arg(long, default_value = "90")]
        expires_in: u32,
    },

    /// List active API tokens
    List,
}

impl AuthCommand {
    pub async fn execute(self, _global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Login { url, token } => {
                let method = if token { "token" } else { "browser" };
                eprintln!(
                    "ak auth login: {} auth for {:?} (not yet implemented)",
                    method, url
                );
            }
            Self::Logout { instance } => {
                eprintln!("ak auth logout: {:?} (not yet implemented)", instance);
            }
            Self::Token { command } => match command {
                TokenCommand::Create {
                    description,
                    expires_in,
                } => {
                    eprintln!(
                        "ak auth token create: desc={:?} expires={}d (not yet implemented)",
                        description, expires_in
                    );
                }
                TokenCommand::List => {
                    eprintln!("ak auth token list (not yet implemented)");
                }
            },
            Self::Whoami => {
                eprintln!("ak auth whoami (not yet implemented)");
            }
            Self::Switch => {
                eprintln!("ak auth switch (not yet implemented)");
            }
        }
        Ok(())
    }
}
