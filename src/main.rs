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
