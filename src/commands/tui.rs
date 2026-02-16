use miette::Result;

use crate::cli::GlobalArgs;

pub async fn execute(_global: &GlobalArgs) -> Result<()> {
    eprintln!("ak tui (not yet implemented — will use ratatui)");
    Ok(())
}
