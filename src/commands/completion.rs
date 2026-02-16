use clap::CommandFactory;
use clap_complete::Shell;
use miette::Result;

use crate::cli::Cli;

pub fn execute(shell: Shell) -> Result<()> {
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, "ak", &mut std::io::stdout());
    Ok(())
}
