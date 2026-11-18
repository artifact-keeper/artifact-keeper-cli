//! `ak admin repo`: repairs to one repository's records.

use artifact_keeper_sdk::ClientAdminExt;
use artifact_keeper_sdk::types::DebianBackfillRequest;
use clap::Subcommand;
use miette::Result;

use crate::cli::GlobalArgs;
use crate::commands::client::client_for_slow;
use crate::commands::helpers::{
    confirm_action, ensure_can_confirm, fail_on_errors, or_since, parse_optional_uuid,
    require_since,
};
use crate::error::AkError;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum RepoCommand {
    /// Register the packages of a hosted Debian repository migrated without their
    /// control data, from its own storage. A package outside `pool/<component>/` is
    /// moved under `pool/main/`, and copies of migrated `dists/` indexes are removed
    /// from the artifact list. Safe to run again
    BackfillDebian {
        /// Repository key
        repo: String,

        /// Report what would be registered, moved and removed without changing anything
        #[arg(long)]
        dry_run: bool,

        /// Examine at most this many packages (the server's default is 1000, at most 10000)
        #[arg(long)]
        limit: Option<u64>,

        /// Continue a walk that stopped at --limit: the `next_after` it printed
        #[arg(long)]
        after: Option<String>,

        /// Skip confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

impl RepoCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        let Self::BackfillDebian {
            repo,
            dry_run,
            limit,
            after,
            yes,
        } = self;
        let after = parse_optional_uuid(after.as_deref(), "--after")?;
        let limit = limit
            .map(i64::try_from)
            .transpose()
            .map_err(|_| AkError::Usage("--limit is too large".into()))?;
        let prompt = format!(
            "Register the Debian packages repository '{repo}' has no control data for, move \
             any outside pool/<component>/ under pool/main/, and remove migrated dists/ \
             copies from its artifact list? --dry-run reports them instead."
        );
        // --no-input without --yes sends nothing, not even the version check, and a
        // 1.11 user isn't asked for what can't run.
        if !dry_run {
            ensure_can_confirm(&prompt, yes, global.no_input)?;
        }
        require_since((1, 12), "admin repo backfill-debian", global).await?;
        if !dry_run && !confirm_action(&prompt, yes, global.no_input)? {
            return Ok(());
        }

        let client = client_for_slow(global)?;
        let spinner = output::spinner("Backfilling Debian packages...");
        let (resp, raw) = artifact_keeper_sdk::raw::capture(
            client
                .backfill_debian_packages()
                .key(repo)
                .body(DebianBackfillRequest {
                    after,
                    dry_run,
                    limit,
                })
                .send(),
        )
        .await;
        spinner.finish_and_clear();
        let result = or_since(
            (1, 12),
            resp,
            "backfill Debian packages",
            "admin repo backfill-debian",
            global,
        )
        .await?
        .into_inner();

        if matches!(global.format, OutputFormat::Quiet) {
            for path in &result.registered_paths {
                println!("{path}");
            }
            return fail_on_errors("Backfill", &result.errors);
        }
        let mut text = format!(
            "Dry run:              {}\n\
             Scanned:              {}\n\
             Registered:           {}\n\
             Moved to pool/main/:  {}\n\
             Skipped:              {}\n\
             Failed:               {}\n\
             dists/ removed:       {}\n\
             Truncated:            {}",
            result.dry_run,
            result.artifacts_scanned,
            result.packages_registered,
            result.packages_relocated,
            result.artifacts_skipped,
            result.artifacts_failed,
            result.dists_removed,
            result.truncated,
        );
        if let Some(next) = result.next_after {
            text.push_str(&format!("\nContinue with: --after {next}"));
        }
        for (label, items) in [
            ("Registered", &result.registered_paths),
            ("Error", &result.errors),
        ] {
            for item in items {
                text.push_str(&format!("\n{label}: {item}"));
            }
        }
        println!(
            "{}",
            output::render_raw(raw.as_deref(), &result, &global.format, Some(text))
        );
        fail_on_errors("Backfill", &result.errors)
    }
}
