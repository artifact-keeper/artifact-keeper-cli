use std::fs;
use std::path::Path;

use clap::CommandFactory;
use clap_complete::Shell;
use miette::{IntoDiagnostic, Result};

use crate::cli::Cli;

pub fn execute(shell: Shell) -> Result<()> {
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, "ak", &mut std::io::stdout());
    Ok(())
}

pub fn generate_man_pages(dir: &str) -> Result<()> {
    let out = Path::new(dir);
    fs::create_dir_all(out).into_diagnostic()?;

    let cmd = Cli::command();

    write_man_page(&cmd, out, "ak.1")?;

    for sub in cmd.get_subcommands() {
        let filename = format!("ak-{}.1", sub.get_name());
        write_man_page(sub, out, &filename)?;

        for nested in sub.get_subcommands() {
            let filename = format!("ak-{}-{}.1", sub.get_name(), nested.get_name());
            write_man_page(nested, out, &filename)?;
        }
    }

    eprintln!("\nMan pages written to {}/", out.display());
    Ok(())
}

fn write_man_page(cmd: &clap::Command, dir: &Path, filename: &str) -> Result<()> {
    let man = clap_mangen::Man::new(cmd.clone());
    let mut buf = Vec::new();
    man.render(&mut buf).into_diagnostic()?;
    let path = dir.join(filename);
    fs::write(&path, buf).into_diagnostic()?;
    eprintln!("Generated {}", path.display());
    Ok(())
}
