//! `ak admin storage-scrub`, `reindex-storage` and `storage ledger-backfill`:
//! checking stored objects and repairing what the database says about them.

use artifact_keeper_sdk::ClientAdminExt;
use artifact_keeper_sdk::types::{ScrubFinding, StorageReindexRequest, StorageScrubRequest};
use clap::{Args, Subcommand, ValueEnum};
use miette::Result;

use crate::cli::GlobalArgs;
use crate::commands::client::{client_for, client_for_slow};
use crate::commands::helpers::{confirm_action, new_table, or_since_1_11, sdk_err};
use crate::output::{self, OutputFormat, format_bytes};

#[derive(Subcommand)]
pub enum StorageScrubCommand {
    /// Read stored objects and compare each with its recorded SHA-256. A run the
    /// server's admin request timeout cuts short may already have repaired
    /// objects, so bound a large run with --max-objects or --max-bytes
    Run {
        /// Also replace a bad object when a verified good copy exists
        #[arg(long)]
        repair: bool,

        /// Only this repository, by key
        #[arg(long)]
        repository: Option<String>,

        /// Check at most this many objects
        #[arg(long)]
        max_objects: Option<i64>,

        /// Read at most this many bytes
        #[arg(long)]
        max_bytes: Option<i64>,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// List what earlier runs found
    Findings {
        /// Only findings in this state
        #[arg(long, value_enum)]
        status: Option<FindingStatus>,

        /// At most this many findings
        #[arg(long)]
        limit: Option<i64>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum FindingStatus {
    Corrupt,
    Missing,
    Repaired,
}

impl FindingStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Corrupt => "corrupt",
            Self::Missing => "missing",
            Self::Repaired => "repaired",
        }
    }
}

/// Flags for `ak admin reindex-storage`.
#[derive(Args)]
pub struct ReindexStorageArgs {
    /// Repository key
    repo: String,

    /// Report what would be registered without changing anything
    #[arg(long)]
    dry_run: bool,

    /// Register at most this many objects
    #[arg(long)]
    limit: Option<i64>,

    /// Skip confirmation prompt
    #[arg(long)]
    yes: bool,
}

#[derive(Subcommand)]
pub enum StorageCommand {
    /// Recompute every repository's storage usage ledger and report the drift
    LedgerBackfill,
}

impl StorageScrubCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Run {
                repair,
                repository,
                max_objects,
                max_bytes,
                yes,
            } => {
                let body = StorageScrubRequest {
                    repair,
                    repository,
                    max_objects,
                    max_bytes,
                };
                run_scrub(body, yes, global).await
            }
            Self::Findings { status, limit } => list_findings(status, limit, global).await,
        }
    }
}

async fn run_scrub(body: StorageScrubRequest, yes: bool, global: &GlobalArgs) -> Result<()> {
    let scope = match &body.repository {
        Some(key) => format!("repository '{key}'"),
        None => "all repositories".to_string(),
    };
    let prompt = if body.repair {
        format!(
            "Scrub {scope} and overwrite bad objects with verified good copies? \
             This reads the objects from storage."
        )
    } else {
        format!("Scrub {scope}? This reads the objects from storage.")
    };
    if !confirm_action(&prompt, yes, global.no_input)? {
        return Ok(());
    }

    let client = client_for_slow(global)?;
    let spinner = output::spinner("Scrubbing storage...");
    let (resp, raw) =
        artifact_keeper_sdk::raw::capture(client.run_storage_scrub().body(body).send()).await;
    let result = or_since_1_11(resp, "run storage scrub", "admin storage-scrub", global)
        .await?
        .into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        for finding in &result.findings {
            println!("{}", finding.object_id);
        }
        return Ok(());
    }
    let mut text = format!(
        "Objects checked:    {}\n\
         Bytes read:         {}\n\
         Intact:             {}\n\
         Corrupt:            {}\n\
         Missing:            {}\n\
         Repaired:           {}\n\
         Unverifiable:       {}\n\
         Skipped (in use):   {}\n\
         Cycle completed:    {}",
        result.objects_checked,
        format_bytes(result.bytes_read),
        result.intact,
        result.corrupt,
        result.missing,
        result.repaired,
        result.unverifiable,
        result.skipped_concurrent,
        result.cycle_completed,
    );
    if !result.findings.is_empty() {
        text.push_str(&format!("\n\n{}", findings_table(&result.findings)));
    }
    for error in &result.errors {
        text.push_str(&format!("\nError: {error}"));
    }
    println!(
        "{}",
        output::render_raw(raw.as_deref(), &result, &global.format, Some(text))
    );
    Ok(())
}

async fn list_findings(
    status: Option<FindingStatus>,
    limit: Option<i64>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let mut req = client.list_storage_scrub_findings();
    if let Some(status) = status {
        req = req.status(status.as_str());
    }
    if let Some(limit) = limit {
        req = req.limit(limit);
    }
    let spinner = output::spinner("Fetching scrub findings...");
    let (resp, raw) = artifact_keeper_sdk::raw::capture(req.send()).await;
    let findings = or_since_1_11(resp, "list scrub findings", "admin storage-scrub", global)
        .await?
        .into_inner();
    spinner.finish_and_clear();

    if findings.is_empty() && !output::is_machine_format(&global.format) {
        eprintln!("No scrub findings.");
        return Ok(());
    }
    if matches!(global.format, OutputFormat::Quiet) {
        for finding in &findings {
            println!("{}", finding.object_id);
        }
        return Ok(());
    }
    println!(
        "{}",
        output::render_raw(
            raw.as_deref(),
            &findings,
            &global.format,
            Some(findings_table(&findings))
        )
    );
    Ok(())
}

fn findings_table(findings: &[ScrubFinding]) -> String {
    let mut table = new_table(vec![
        "STATUS",
        "KIND",
        "OBJECT ID",
        "REPOSITORY ID",
        "STORAGE KEY",
        "EXPECTED SHA256",
        "ACTUAL SHA256",
        "DETECTED",
        "DETAIL",
    ]);
    for f in findings {
        table.add_row(vec![
            f.status.clone(),
            f.object_kind.to_string(),
            f.object_id.to_string(),
            f.repository_id.to_string(),
            f.storage_key.clone(),
            f.expected_sha256.clone(),
            f.actual_sha256.clone().unwrap_or_else(|| "-".into()),
            f.detected_at
                .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| "-".into()),
            f.detail.clone().unwrap_or_else(|| "-".into()),
        ]);
    }
    table.to_string()
}

pub async fn reindex_storage(args: ReindexStorageArgs, global: &GlobalArgs) -> Result<()> {
    let ReindexStorageArgs {
        repo,
        dry_run,
        limit,
        yes,
    } = args;
    if !dry_run {
        let prompt = format!(
            "Register objects in storage that repository '{repo}' has no record of, as \
             artifacts? They become visible and downloadable. --dry-run reports them instead."
        );
        if !confirm_action(&prompt, yes, global.no_input)? {
            return Ok(());
        }
    }

    let client = client_for_slow(global)?;
    let spinner = output::spinner("Reindexing repository storage...");
    let (resp, raw) = artifact_keeper_sdk::raw::capture(
        client
            .reindex_repository_storage()
            .key(repo)
            .body(StorageReindexRequest { dry_run, limit })
            .send(),
    )
    .await;
    let result = or_since_1_11(
        resp,
        "reindex repository storage",
        "admin reindex-storage",
        global,
    )
    .await?
    .into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        for path in &result.registered_paths {
            println!("{path}");
        }
        return Ok(());
    }
    let mut text = format!(
        "Dry run:              {}\n\
         Scanned:              {}\n\
         Registered:           {}\n\
         Skipped:              {}\n\
         Skipped (recent):     {}\n\
         Skipped (no age):     {}\n\
         Missing objects:      {}\n\
         Truncated:            {}",
        result.dry_run,
        result.scanned,
        result.registered,
        result.skipped,
        result.skipped_recent,
        result.skipped_unknown_age,
        result.missing_objects,
        result.truncated,
    );
    for (label, items) in [
        ("Registered", &result.registered_paths),
        ("Missing", &result.missing_object_paths),
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
    Ok(())
}

impl StorageCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        let Self::LedgerBackfill = self;
        let client = client_for_slow(global)?;
        let spinner = output::spinner("Recomputing storage ledgers...");
        let (resp, raw) =
            artifact_keeper_sdk::raw::capture(client.backfill_storage_ledger().send()).await;
        let report = resp
            .map_err(|e| sdk_err("backfill storage ledger", e))?
            .into_inner();
        spinner.finish_and_clear();

        if matches!(global.format, OutputFormat::Quiet) {
            println!("{}", report.total_drift_bytes);
            return Ok(());
        }
        let mut table = new_table(vec![
            "REPOSITORY",
            "ID",
            "BEFORE",
            "AFTER",
            "HOSTED",
            "PROXY",
            "OCI",
            "DRIFT",
        ]);
        for repo in &report.repositories {
            table.add_row(vec![
                repo.repository_key.clone(),
                repo.repository_id.to_string(),
                repo.before_total_bytes
                    .map(format_bytes)
                    .unwrap_or_else(|| "-".into()),
                format_bytes(repo.after_total_bytes),
                format_bytes(repo.after_hosted_bytes),
                format_bytes(repo.after_proxy_bytes),
                format_bytes(repo.after_oci_bytes),
                repo.drift_bytes.to_string(),
            ]);
        }
        let text = format!(
            "Repositories checked:  {}\n\
             Repositories repaired: {}\n\
             Repositories skipped:  {}\n\
             Total before:          {}\n\
             Total after:           {}\n\
             Total drift (bytes):   {}\n\n{table}",
            report.repositories_checked,
            report.repositories_repaired,
            report.repositories_skipped,
            format_bytes(report.before_total_storage_bytes),
            format_bytes(report.after_total_storage_bytes),
            report.total_drift_bytes,
        );
        println!(
            "{}",
            output::render_raw(raw.as_deref(), &report, &global.format, Some(text))
        );
        Ok(())
    }
}
