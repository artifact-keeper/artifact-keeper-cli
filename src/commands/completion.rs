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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_man_pages_creates_files() {
        let dir = tempfile::tempdir().unwrap();
        generate_man_pages(&dir.path().to_string_lossy()).unwrap();

        // Should have at least the root man page
        let root = dir.path().join("ak.1");
        assert!(root.exists(), "ak.1 should exist");

        // Should have subcommand man pages
        let auth = dir.path().join("ak-auth.1");
        assert!(auth.exists(), "ak-auth.1 should exist");

        let instance = dir.path().join("ak-instance.1");
        assert!(instance.exists(), "ak-instance.1 should exist");

        let repo = dir.path().join("ak-repo.1");
        assert!(repo.exists(), "ak-repo.1 should exist");

        let artifact = dir.path().join("ak-artifact.1");
        assert!(artifact.exists(), "ak-artifact.1 should exist");

        let doctor = dir.path().join("ak-doctor.1");
        assert!(doctor.exists(), "ak-doctor.1 should exist");

        let tui = dir.path().join("ak-tui.1");
        assert!(tui.exists(), "ak-tui.1 should exist");

        let config = dir.path().join("ak-config.1");
        assert!(config.exists(), "ak-config.1 should exist");
    }

    #[test]
    fn generate_man_pages_nested_commands() {
        let dir = tempfile::tempdir().unwrap();
        generate_man_pages(&dir.path().to_string_lossy()).unwrap();

        // Nested subcommands should also have man pages
        let auth_login = dir.path().join("ak-auth-login.1");
        assert!(auth_login.exists(), "ak-auth-login.1 should exist");

        let instance_add = dir.path().join("ak-instance-add.1");
        assert!(instance_add.exists(), "ak-instance-add.1 should exist");

        let config_get = dir.path().join("ak-config-get.1");
        assert!(config_get.exists(), "ak-config-get.1 should exist");
    }

    #[test]
    fn generate_man_pages_creates_dir() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("nested").join("man");
        generate_man_pages(&nested.to_string_lossy()).unwrap();

        assert!(nested.join("ak.1").exists());
    }
}
