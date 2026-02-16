use clap::Subcommand;
use miette::Result;

use crate::cli::GlobalArgs;

#[derive(Subcommand)]
pub enum RepoCommand {
    /// List repositories (filtered by your permissions)
    List {
        /// Filter by package format (npm, pypi, maven, docker, etc.)
        #[arg(long)]
        format: Option<String>,

        /// Filter by repository type (local, remote, virtual)
        #[arg(long, name = "type")]
        repo_type: Option<String>,

        /// Search by name
        #[arg(long)]
        search: Option<String>,
    },

    /// Show repository details
    Show {
        /// Repository key
        key: String,
    },

    /// Create a new repository
    Create {
        /// Repository key (URL slug)
        key: String,

        /// Package format
        #[arg(long)]
        format: String,

        /// Repository type
        #[arg(long, default_value = "local")]
        repo_type: String,

        /// Description
        #[arg(long)]
        description: Option<String>,
    },

    /// Delete a repository
    Delete {
        /// Repository key
        key: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Interactively browse artifacts in a repository
    Browse {
        /// Repository key
        key: String,
    },
}

impl RepoCommand {
    pub async fn execute(self, _global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List {
                format,
                repo_type,
                search,
            } => {
                eprintln!(
                    "ak repo list: format={:?} type={:?} search={:?} (not yet implemented)",
                    format, repo_type, search
                );
            }
            Self::Show { key } => {
                eprintln!("ak repo show: {} (not yet implemented)", key);
            }
            Self::Create {
                key,
                format,
                repo_type,
                description,
            } => {
                eprintln!(
                    "ak repo create: {} format={} type={} desc={:?} (not yet implemented)",
                    key, format, repo_type, description
                );
            }
            Self::Delete { key, yes } => {
                eprintln!("ak repo delete: {} yes={} (not yet implemented)", key, yes);
            }
            Self::Browse { key } => {
                eprintln!("ak repo browse: {} (not yet implemented)", key);
            }
        }
        Ok(())
    }
}
