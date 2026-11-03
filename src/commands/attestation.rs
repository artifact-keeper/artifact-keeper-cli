use artifact_keeper_sdk::ClientAttestationsExt;
use artifact_keeper_sdk::raw::capture;
use artifact_keeper_sdk::types::AttestationPolicyResponse;
use clap::Subcommand;
use miette::Result;

use super::client::client_for;
use super::helpers::{new_table, since_1_11};
use crate::cli::GlobalArgs;
use crate::output;

#[derive(Subcommand)]
pub enum AttestationCommand {
    /// Show which publishers and keys this server trusts for attestations
    Policy,
}

impl AttestationCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Policy => show_policy(global).await,
        }
    }
}

async fn show_policy(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching attestation policy...");

    let (resp, raw) = capture(client.get_attestation_policy().send()).await;
    let policy = match resp {
        Ok(resp) => resp.into_inner(),
        Err(e) => {
            return Err(
                since_1_11(e, "get attestation policy", "attestation policy", global)
                    .await
                    .into(),
            );
        }
    };

    spinner.finish_and_clear();

    println!(
        "{}",
        output::render_raw(
            raw.as_deref(),
            &policy,
            &global.format,
            Some(policy_table(&policy))
        )
    );

    Ok(())
}

fn or_none(items: &[String]) -> String {
    if items.is_empty() {
        "(none)".to_string()
    } else {
        items.join(", ")
    }
}

fn policy_table(policy: &AttestationPolicyResponse) -> String {
    let mut lines = vec![
        format!("Require verified: {}", policy.require_verified),
        format!("Issuers:          {}", or_none(&policy.issuers)),
        format!("Identities:       {}", or_none(&policy.identities)),
    ];
    if policy.keys.is_empty() {
        lines.push("Keys:             (none)".to_string());
    } else {
        let mut table = new_table(vec!["ID", "NAME", "ALGORITHM", "FINGERPRINT"]);
        for key in &policy.keys {
            table.add_row(vec![
                key.id.as_str(),
                key.name.as_str(),
                key.algorithm.as_str(),
                key.fingerprint.as_str(),
            ]);
        }
        lines.push(table.to_string());
    }
    lines.join("\n")
}
