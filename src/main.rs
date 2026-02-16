use clap::Parser;
use miette::Result;

mod cli;
mod commands;
mod config;
mod error;
mod output;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = cli::Cli::parse();
    cli.execute().await
}

/// Shared test utilities — single ENV_LOCK for all modules that touch AK_CONFIG_DIR.
#[cfg(test)]
pub(crate) mod test_utils {
    use std::sync::Mutex;
    pub static ENV_LOCK: Mutex<()> = Mutex::new(());
}
