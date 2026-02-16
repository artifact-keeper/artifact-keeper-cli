use clap::Subcommand;
use miette::Result;

use crate::cli::GlobalArgs;

#[derive(Subcommand)]
pub enum ScanCommand {
    /// Trigger a security scan on an artifact
    Run {
        /// Repository key
        repo: String,
        /// Artifact path
        path: String,
    },

    /// List recent scan results
    List {
        /// Filter by repository
        #[arg(long)]
        repo: Option<String>,
    },

    /// Show scan findings
    Show {
        /// Scan ID
        id: String,

        /// Filter by minimum severity
        #[arg(long)]
        severity: Option<String>,
    },
}

impl ScanCommand {
    pub async fn execute(self, _global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Run { repo, path } => {
                eprintln!(
                    "ak scan run: repo={} path={} (not yet implemented)",
                    repo, path
                );
            }
            Self::List { repo } => {
                eprintln!("ak scan list: repo={:?} (not yet implemented)", repo);
            }
            Self::Show { id, severity } => {
                eprintln!(
                    "ak scan show: id={} severity={:?} (not yet implemented)",
                    id, severity
                );
            }
        }
        Ok(())
    }
}
