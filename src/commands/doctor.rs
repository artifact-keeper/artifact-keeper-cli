use miette::Result;

use crate::cli::GlobalArgs;

pub async fn execute(_global: &GlobalArgs) -> Result<()> {
    eprintln!("ak doctor (not yet implemented)");
    Ok(())
}
