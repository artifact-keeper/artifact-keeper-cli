//! `ak admin npm-feed`: the npm upstream change feed consumer.

use artifact_keeper_sdk::ClientAdminExt;
use clap::Subcommand;
use miette::Result;

use crate::cli::GlobalArgs;
use crate::commands::client::client_for;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum NpmFeedCommand {
    /// Show this replica's view of the npm upstream feed consumer
    Status,
}

impl NpmFeedCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        let Self::Status = self;
        let client = client_for(global)?;
        let spinner = output::spinner("Fetching npm feed status...");
        let (resp, raw) =
            artifact_keeper_sdk::raw::capture(client.get_npm_upstream_feed_status().send()).await;
        let status = match resp {
            Ok(resp) => resp.into_inner(),
            Err(e) => {
                let action = "get npm feed status";
                return Err(super::since_1_11(e, action, "admin npm-feed", global)
                    .await
                    .into());
            }
        };
        spinner.finish_and_clear();

        if matches!(global.format, OutputFormat::Quiet) {
            println!("{}", status.enabled);
            return Ok(());
        }

        let table = format!(
            "Enabled:           {}\n\
             Feed URL:          {}\n\
             Replica:           {}\n\
             Consumer running:  {}\n\
             Leader:            {}\n\
             A leader active:   {}\n\
             Leader term (s):   {}\n\
             Cursor:            {}\n\
             Last poll:         {}\n\
             Last error:        {}",
            status.enabled,
            status.feed_url,
            status.replica_id,
            status.consumer_running,
            status.is_leader,
            status.cluster_leader_active,
            status.leader_term_secs,
            status.cursor.as_deref().unwrap_or("-"),
            status
                .last_poll_at
                .map(|t| t.to_rfc3339())
                .unwrap_or_else(|| "-".into()),
            status.last_error.as_deref().unwrap_or("-"),
        );
        println!(
            "{}",
            output::render_raw(raw.as_deref(), &status, &global.format, Some(table))
        );
        Ok(())
    }
}
