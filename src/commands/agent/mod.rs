//! `ak agent`: what AI coding agents load from a repository. Plugins today; the group
//! leaves room for skills.

mod bundle;
mod harness;
mod plugins;

use clap::Subcommand;
use miette::Result;

use crate::cli::GlobalArgs;

#[derive(Subcommand)]
pub enum AgentCommand {
    /// Agent plugin bundles for Claude Code, Cursor, Codex and Copilot / VS Code
    #[command(subcommand, after_help = plugins::AFTER_HELP)]
    Plugins(plugins::PluginsCommand),
}

impl AgentCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Plugins(command) => plugins::execute(command, global).await,
        }
    }
}
