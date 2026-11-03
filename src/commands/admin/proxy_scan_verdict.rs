//! `ak admin proxy-scan-verdict`: stored scan verdicts for proxied content.

use artifact_keeper_sdk::ClientAdminExt;
use artifact_keeper_sdk::types::ProxyScanVerdictListResponse;
use clap::Subcommand;
use miette::Result;

use crate::cli::GlobalArgs;
use crate::commands::client::client_for;
use crate::commands::helpers::{confirm_action, new_table, sdk_err};
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum ProxyScanVerdictCommand {
    /// Show the stored verdicts for a digest
    Show {
        /// sha256:<64 hex> or bare 64 hex
        digest: String,
    },

    /// Delete the stored verdicts for a digest, so the content is scanned again
    Delete {
        /// sha256:<64 hex> or bare 64 hex
        digest: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}

impl ProxyScanVerdictCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        let client = client_for(global)?;
        match self {
            Self::Show { digest } => {
                let spinner = output::spinner("Fetching proxy scan verdicts...");
                let (resp, raw) = artifact_keeper_sdk::raw::capture(
                    client.get_proxy_scan_verdicts().digest(digest).send(),
                )
                .await;
                let resp = resp
                    .map_err(|e| sdk_err("get proxy scan verdicts", e))?
                    .into_inner();
                spinner.finish_and_clear();
                print_verdicts(&resp, raw.as_deref(), global);
            }
            Self::Delete { digest, yes } => {
                let prompt = format!(
                    "Delete the stored proxy scan verdicts for {digest}? Content a verdict was \
                     blocking can be served until it is scanned again."
                );
                if !confirm_action(&prompt, yes, global.no_input)? {
                    return Ok(());
                }
                let spinner = output::spinner("Deleting proxy scan verdicts...");
                let (resp, raw) = artifact_keeper_sdk::raw::capture(
                    client.delete_proxy_scan_verdicts().digest(digest).send(),
                )
                .await;
                let resp = resp
                    .map_err(|e| sdk_err("delete proxy scan verdicts", e))?
                    .into_inner();
                spinner.finish_and_clear();
                if matches!(global.format, OutputFormat::Table) {
                    eprintln!(
                        "Deleted {} verdict(s) for {}:",
                        resp.verdicts.len(),
                        resp.digest
                    );
                }
                print_verdicts(&resp, raw.as_deref(), global);
            }
        }
        Ok(())
    }
}

fn print_verdicts(resp: &ProxyScanVerdictListResponse, raw: Option<&[u8]>, global: &GlobalArgs) {
    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", resp.digest);
        return;
    }
    let mut table = new_table(vec![
        "SCAN TYPE",
        "VERDICT",
        "FINDINGS",
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "MAX SEVERITY",
        "SCANNER",
        "SCANNED",
        "SHA256",
    ]);
    for v in &resp.verdicts {
        table.add_row(vec![
            v.scan_type.clone(),
            v.verdict.clone(),
            v.findings_count.to_string(),
            v.critical_count.to_string(),
            v.high_count.to_string(),
            v.medium_count.to_string(),
            v.low_count.to_string(),
            v.max_severity.clone().unwrap_or_else(|| "-".into()),
            v.scanner_version.clone().unwrap_or_else(|| "-".into()),
            v.scanned_at.format("%Y-%m-%d %H:%M").to_string(),
            v.checksum_sha256.clone(),
        ]);
    }
    println!(
        "{}",
        output::render_raw(raw, resp, &global.format, Some(table.to_string()))
    );
}
