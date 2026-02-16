use clap::Subcommand;
use miette::Result;

use crate::cli::GlobalArgs;

#[derive(Subcommand)]
pub enum SetupCommand {
    /// Auto-detect project toolchain and configure all package managers
    Auto,

    /// Configure npm/pnpm/yarn to use Artifact Keeper
    Npm {
        /// Repository key (auto-detected if only one npm repo exists)
        #[arg(long)]
        repo: Option<String>,
    },

    /// Configure pip/poetry/pipenv to use Artifact Keeper
    Pip {
        #[arg(long)]
        repo: Option<String>,
    },

    /// Configure Cargo to use Artifact Keeper
    Cargo {
        #[arg(long)]
        repo: Option<String>,
    },

    /// Configure Docker to use Artifact Keeper
    Docker {
        #[arg(long)]
        repo: Option<String>,
    },

    /// Configure Maven to use Artifact Keeper
    Maven {
        #[arg(long)]
        repo: Option<String>,
    },

    /// Configure Gradle to use Artifact Keeper
    Gradle {
        #[arg(long)]
        repo: Option<String>,
    },

    /// Configure Go modules to use Artifact Keeper
    Go {
        #[arg(long)]
        repo: Option<String>,
    },

    /// Configure Helm to use Artifact Keeper
    Helm {
        #[arg(long)]
        repo: Option<String>,
    },

    /// Configure NuGet to use Artifact Keeper
    Nuget {
        #[arg(long)]
        repo: Option<String>,
    },

    /// Configure yum/dnf to use Artifact Keeper (requires sudo)
    Yum {
        #[arg(long)]
        repo: Option<String>,
    },

    /// Configure apt to use Artifact Keeper (requires sudo)
    Apt {
        #[arg(long)]
        repo: Option<String>,
    },
}

impl SetupCommand {
    pub async fn execute(self, _global: &GlobalArgs) -> Result<()> {
        let ecosystem = match &self {
            Self::Auto => "auto-detect",
            Self::Npm { .. } => "npm",
            Self::Pip { .. } => "pip",
            Self::Cargo { .. } => "cargo",
            Self::Docker { .. } => "docker",
            Self::Maven { .. } => "maven",
            Self::Gradle { .. } => "gradle",
            Self::Go { .. } => "go",
            Self::Helm { .. } => "helm",
            Self::Nuget { .. } => "nuget",
            Self::Yum { .. } => "yum",
            Self::Apt { .. } => "apt",
        };
        eprintln!("ak setup {}: (not yet implemented)", ecosystem);
        Ok(())
    }
}
