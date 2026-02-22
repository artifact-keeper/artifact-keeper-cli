use artifact_keeper_sdk::ClientAnalyticsExt;
use artifact_keeper_sdk::types::{
    DownloadTrend, GrowthSummary, RepositorySnapshot, RepositoryStorageBreakdown, StaleArtifact,
    StorageSnapshot,
};
use clap::Subcommand;
use miette::Result;
use serde_json::Value;

use super::client::client_for;
use super::helpers::{new_table, parse_uuid, sdk_err, short_id};
use crate::cli::GlobalArgs;
use crate::output::{self, OutputFormat, format_bytes};

#[derive(Subcommand)]
pub enum AnalyticsCommand {
    /// Show download trends over time
    Downloads {
        /// Start date (YYYY-MM-DD)
        #[arg(long)]
        from: Option<String>,

        /// End date (YYYY-MM-DD)
        #[arg(long)]
        to: Option<String>,
    },

    /// Show storage breakdown by repository
    Storage,

    /// Show growth summary (artifacts, storage, downloads)
    Growth {
        /// Start date (YYYY-MM-DD)
        #[arg(long)]
        from: Option<String>,

        /// End date (YYYY-MM-DD)
        #[arg(long)]
        to: Option<String>,
    },

    /// Show storage trend over time
    StorageTrend {
        /// Start date (YYYY-MM-DD)
        #[arg(long)]
        from: Option<String>,

        /// End date (YYYY-MM-DD)
        #[arg(long)]
        to: Option<String>,
    },

    /// Show stale artifacts with no recent downloads
    TopStale {
        /// Number of days since last download to consider stale
        #[arg(long, default_value = "90")]
        days: i32,

        /// Maximum number of results to return
        #[arg(long, default_value = "20")]
        limit: i64,
    },

    /// Show download trend for a specific repository
    RepoTrend {
        /// Repository ID
        id: String,

        /// Start date (YYYY-MM-DD)
        #[arg(long)]
        from: Option<String>,

        /// End date (YYYY-MM-DD)
        #[arg(long)]
        to: Option<String>,
    },

    /// Capture an analytics snapshot
    Snapshot,
}

impl AnalyticsCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Downloads { from, to } => downloads(from.as_deref(), to.as_deref(), global).await,
            Self::Storage => storage_breakdown(global).await,
            Self::Growth { from, to } => {
                growth_summary(from.as_deref(), to.as_deref(), global).await
            }
            Self::StorageTrend { from, to } => {
                storage_trend(from.as_deref(), to.as_deref(), global).await
            }
            Self::TopStale { days, limit } => top_stale(days, limit, global).await,
            Self::RepoTrend { id, from, to } => {
                repo_trend(&id, from.as_deref(), to.as_deref(), global).await
            }
            Self::Snapshot => capture_snapshot(global).await,
        }
    }
}

// ---------------------------------------------------------------------------
// Handler functions
// ---------------------------------------------------------------------------

async fn downloads(from: Option<&str>, to: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching download trends...");

    let mut req = client.get_download_trends();
    if let Some(f) = from {
        req = req.from(f.to_string());
    }
    if let Some(t) = to {
        req = req.to(t.to_string());
    }

    let resp = req
        .send()
        .await
        .map_err(|e| sdk_err("get download trends", e))?;
    let items = resp.into_inner();
    spinner.finish_and_clear();

    if items.is_empty() {
        eprintln!("No download trend data found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for item in &items {
            println!("{}\t{}", item.date, item.download_count);
        }
        return Ok(());
    }

    let (entries, table_str) = format_downloads_table(&items);
    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn storage_breakdown(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching storage breakdown...");

    let resp = client
        .get_storage_breakdown()
        .send()
        .await
        .map_err(|e| sdk_err("get storage breakdown", e))?;
    let items = resp.into_inner();
    spinner.finish_and_clear();

    if items.is_empty() {
        eprintln!("No storage breakdown data found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for item in &items {
            println!("{}\t{}", item.repository_key, item.storage_bytes);
        }
        return Ok(());
    }

    let (entries, table_str) = format_storage_table(&items);
    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn growth_summary(from: Option<&str>, to: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching growth summary...");

    let mut req = client.get_growth_summary();
    if let Some(f) = from {
        req = req.from(f.to_string());
    }
    if let Some(t) = to {
        req = req.to(t.to_string());
    }

    let resp = req
        .send()
        .await
        .map_err(|e| sdk_err("get growth summary", e))?;
    let summary = resp.into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!(
            "{}\t{}\t{}",
            summary.artifacts_added, summary.storage_growth_bytes, summary.downloads_in_period
        );
        return Ok(());
    }

    let (info, table_str) = format_growth_detail(&summary);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn storage_trend(from: Option<&str>, to: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching storage trend...");

    let mut req = client.get_storage_trend();
    if let Some(f) = from {
        req = req.from(f.to_string());
    }
    if let Some(t) = to {
        req = req.to(t.to_string());
    }

    let resp = req
        .send()
        .await
        .map_err(|e| sdk_err("get storage trend", e))?;
    let items = resp.into_inner();
    spinner.finish_and_clear();

    if items.is_empty() {
        eprintln!("No storage trend data found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for item in &items {
            println!("{}\t{}", item.snapshot_date, item.total_storage_bytes);
        }
        return Ok(());
    }

    let (entries, table_str) = format_storage_trend_table(&items);
    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn top_stale(days: i32, limit: i64, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching stale artifacts...");

    let resp = client
        .get_stale_artifacts()
        .days(days)
        .limit(limit)
        .send()
        .await
        .map_err(|e| sdk_err("get stale artifacts", e))?;
    let items = resp.into_inner();
    spinner.finish_and_clear();

    if items.is_empty() {
        eprintln!("No stale artifacts found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for item in &items {
            println!("{}", item.artifact_id);
        }
        return Ok(());
    }

    let (entries, table_str) = format_stale_table(&items);
    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn repo_trend(
    id: &str,
    from: Option<&str>,
    to: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let repo_id = parse_uuid(id, "repository")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching repository trend...");

    let mut req = client.get_repository_trend().id(repo_id);
    if let Some(f) = from {
        req = req.from(f.to_string());
    }
    if let Some(t) = to {
        req = req.to(t.to_string());
    }

    let resp = req
        .send()
        .await
        .map_err(|e| sdk_err("get repository trend", e))?;
    let items = resp.into_inner();
    spinner.finish_and_clear();

    if items.is_empty() {
        eprintln!("No repository trend data found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for item in &items {
            println!(
                "{}\t{}\t{}",
                item.snapshot_date, item.download_count, item.storage_bytes
            );
        }
        return Ok(());
    }

    let (entries, table_str) = format_repo_trend_table(&items);
    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn capture_snapshot(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Capturing analytics snapshot...");

    let resp = client
        .capture_snapshot()
        .send()
        .await
        .map_err(|e| sdk_err("capture snapshot", e))?;
    let snapshot = resp.into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", snapshot.snapshot_date);
        return Ok(());
    }

    let (info, table_str) = format_snapshot_detail(&snapshot);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

// ---------------------------------------------------------------------------
// Formatting helpers (pure functions, testable without HTTP)
// ---------------------------------------------------------------------------

fn format_downloads_table(items: &[DownloadTrend]) -> (Vec<Value>, String) {
    let entries: Vec<_> = items
        .iter()
        .map(|t| {
            serde_json::json!({
                "date": t.date.to_string(),
                "download_count": t.download_count,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["DATE", "DOWNLOADS"]);

        for t in items {
            let date = t.date.to_string();
            let count = t.download_count.to_string();
            table.add_row(vec![&date, &count]);
        }

        table.to_string()
    };

    (entries, table_str)
}

fn format_storage_table(items: &[RepositoryStorageBreakdown]) -> (Vec<Value>, String) {
    let entries: Vec<_> = items
        .iter()
        .map(|r| {
            serde_json::json!({
                "repository_id": r.repository_id.to_string(),
                "repository_key": r.repository_key,
                "repository_name": r.repository_name,
                "format": r.format,
                "artifact_count": r.artifact_count,
                "storage_bytes": r.storage_bytes,
                "download_count": r.download_count,
                "last_upload_at": r.last_upload_at.map(|t| t.to_rfc3339()),
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec![
            "REPO",
            "FORMAT",
            "ARTIFACTS",
            "STORAGE",
            "DOWNLOADS",
            "LAST UPLOAD",
        ]);

        for r in items {
            let repo = format!("{} ({})", r.repository_key, short_id(&r.repository_id));
            let artifacts = r.artifact_count.to_string();
            let storage = format_bytes(r.storage_bytes);
            let downloads = r.download_count.to_string();
            let last_upload = r
                .last_upload_at
                .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
                .unwrap_or_else(|| "-".to_string());
            table.add_row(vec![
                &repo,
                &r.format,
                &artifacts,
                &storage,
                &downloads,
                &last_upload,
            ]);
        }

        table.to_string()
    };

    (entries, table_str)
}

fn format_growth_detail(summary: &GrowthSummary) -> (Value, String) {
    let info = serde_json::json!({
        "period_start": summary.period_start.to_string(),
        "period_end": summary.period_end.to_string(),
        "artifacts_start": summary.artifacts_start,
        "artifacts_end": summary.artifacts_end,
        "artifacts_added": summary.artifacts_added,
        "storage_bytes_start": summary.storage_bytes_start,
        "storage_bytes_end": summary.storage_bytes_end,
        "storage_growth_bytes": summary.storage_growth_bytes,
        "storage_growth_percent": summary.storage_growth_percent,
        "downloads_in_period": summary.downloads_in_period,
    });

    let table_str = format!(
        "Period:           {} to {}\n\
         Artifacts:        {} -> {} (+{})\n\
         Storage:          {} -> {} (+{})\n\
         Storage Growth:   {:.1}%\n\
         Downloads:        {}",
        summary.period_start,
        summary.period_end,
        summary.artifacts_start,
        summary.artifacts_end,
        summary.artifacts_added,
        format_bytes(summary.storage_bytes_start),
        format_bytes(summary.storage_bytes_end),
        format_bytes(summary.storage_growth_bytes),
        summary.storage_growth_percent,
        summary.downloads_in_period,
    );

    (info, table_str)
}

fn format_storage_trend_table(items: &[StorageSnapshot]) -> (Vec<Value>, String) {
    let entries: Vec<_> = items
        .iter()
        .map(|s| {
            serde_json::json!({
                "snapshot_date": s.snapshot_date.to_string(),
                "total_storage_bytes": s.total_storage_bytes,
                "total_artifacts": s.total_artifacts,
                "total_downloads": s.total_downloads,
                "total_repositories": s.total_repositories,
                "total_users": s.total_users,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec![
            "DATE",
            "STORAGE",
            "ARTIFACTS",
            "DOWNLOADS",
            "REPOS",
            "USERS",
        ]);

        for s in items {
            let date = s.snapshot_date.to_string();
            let storage = format_bytes(s.total_storage_bytes);
            let artifacts = s.total_artifacts.to_string();
            let downloads = s.total_downloads.to_string();
            let repos = s.total_repositories.to_string();
            let users = s.total_users.to_string();
            table.add_row(vec![
                &date, &storage, &artifacts, &downloads, &repos, &users,
            ]);
        }

        table.to_string()
    };

    (entries, table_str)
}

fn format_stale_table(items: &[StaleArtifact]) -> (Vec<Value>, String) {
    let entries: Vec<_> = items
        .iter()
        .map(|a| {
            serde_json::json!({
                "artifact_id": a.artifact_id.to_string(),
                "name": a.name,
                "repository_key": a.repository_key,
                "size_bytes": a.size_bytes,
                "download_count": a.download_count,
                "days_since_download": a.days_since_download,
                "last_downloaded_at": a.last_downloaded_at.map(|t| t.to_rfc3339()),
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec![
            "NAME",
            "REPO",
            "SIZE",
            "DOWNLOADS",
            "DAYS STALE",
            "LAST DOWNLOADED",
        ]);

        for a in items {
            let size = format_bytes(a.size_bytes);
            let downloads = a.download_count.to_string();
            let days = a.days_since_download.to_string();
            let last_dl = a
                .last_downloaded_at
                .map(|t| t.format("%Y-%m-%d").to_string())
                .unwrap_or_else(|| "never".to_string());
            table.add_row(vec![
                &a.name,
                &a.repository_key,
                &size,
                &downloads,
                &days,
                &last_dl,
            ]);
        }

        table.to_string()
    };

    (entries, table_str)
}

fn format_repo_trend_table(items: &[RepositorySnapshot]) -> (Vec<Value>, String) {
    let entries: Vec<_> = items
        .iter()
        .map(|s| {
            serde_json::json!({
                "snapshot_date": s.snapshot_date.to_string(),
                "repository_id": s.repository_id.to_string(),
                "repository_key": s.repository_key,
                "artifact_count": s.artifact_count,
                "download_count": s.download_count,
                "storage_bytes": s.storage_bytes,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["DATE", "ARTIFACTS", "DOWNLOADS", "STORAGE"]);

        for s in items {
            let date = s.snapshot_date.to_string();
            let artifacts = s.artifact_count.to_string();
            let downloads = s.download_count.to_string();
            let storage = format_bytes(s.storage_bytes);
            table.add_row(vec![&date, &artifacts, &downloads, &storage]);
        }

        table.to_string()
    };

    (entries, table_str)
}

fn format_snapshot_detail(snapshot: &StorageSnapshot) -> (Value, String) {
    let info = serde_json::json!({
        "snapshot_date": snapshot.snapshot_date.to_string(),
        "total_artifacts": snapshot.total_artifacts,
        "total_storage_bytes": snapshot.total_storage_bytes,
        "total_downloads": snapshot.total_downloads,
        "total_repositories": snapshot.total_repositories,
        "total_users": snapshot.total_users,
    });

    let table_str = format!(
        "Snapshot Date:    {}\n\
         Artifacts:        {}\n\
         Storage:          {}\n\
         Downloads:        {}\n\
         Repositories:     {}\n\
         Users:            {}",
        snapshot.snapshot_date,
        snapshot.total_artifacts,
        format_bytes(snapshot.total_storage_bytes),
        snapshot.total_downloads,
        snapshot.total_repositories,
        snapshot.total_users,
    );

    (info, table_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{NaiveDate, Utc};
    use clap::Parser;
    use uuid::Uuid;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: AnalyticsCommand,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).unwrap()
    }

    // ---- Parsing tests ----

    #[test]
    fn parse_downloads() {
        let cli = parse(&["test", "downloads"]);
        if let AnalyticsCommand::Downloads { from, to } = cli.command {
            assert!(from.is_none());
            assert!(to.is_none());
        } else {
            panic!("Expected Downloads");
        }
    }

    #[test]
    fn parse_downloads_with_dates() {
        let cli = parse(&[
            "test",
            "downloads",
            "--from",
            "2026-01-01",
            "--to",
            "2026-01-31",
        ]);
        if let AnalyticsCommand::Downloads { from, to } = cli.command {
            assert_eq!(from.unwrap(), "2026-01-01");
            assert_eq!(to.unwrap(), "2026-01-31");
        } else {
            panic!("Expected Downloads with dates");
        }
    }

    #[test]
    fn parse_storage() {
        let cli = parse(&["test", "storage"]);
        assert!(matches!(cli.command, AnalyticsCommand::Storage));
    }

    #[test]
    fn parse_growth() {
        let cli = parse(&["test", "growth"]);
        if let AnalyticsCommand::Growth { from, to } = cli.command {
            assert!(from.is_none());
            assert!(to.is_none());
        } else {
            panic!("Expected Growth");
        }
    }

    #[test]
    fn parse_storage_trend() {
        let cli = parse(&["test", "storage-trend"]);
        if let AnalyticsCommand::StorageTrend { from, to } = cli.command {
            assert!(from.is_none());
            assert!(to.is_none());
        } else {
            panic!("Expected StorageTrend");
        }
    }

    #[test]
    fn parse_top_stale() {
        let cli = parse(&["test", "top-stale"]);
        if let AnalyticsCommand::TopStale { days, limit } = cli.command {
            assert_eq!(days, 90);
            assert_eq!(limit, 20);
        } else {
            panic!("Expected TopStale with defaults");
        }
    }

    #[test]
    fn parse_top_stale_custom() {
        let cli = parse(&["test", "top-stale", "--days", "30", "--limit", "10"]);
        if let AnalyticsCommand::TopStale { days, limit } = cli.command {
            assert_eq!(days, 30);
            assert_eq!(limit, 10);
        } else {
            panic!("Expected TopStale with custom values");
        }
    }

    #[test]
    fn parse_repo_trend() {
        let cli = parse(&["test", "repo-trend", "00000000-0000-0000-0000-000000000000"]);
        if let AnalyticsCommand::RepoTrend { id, from, to } = cli.command {
            assert_eq!(id, "00000000-0000-0000-0000-000000000000");
            assert!(from.is_none());
            assert!(to.is_none());
        } else {
            panic!("Expected RepoTrend");
        }
    }

    #[test]
    fn parse_snapshot() {
        let cli = parse(&["test", "snapshot"]);
        assert!(matches!(cli.command, AnalyticsCommand::Snapshot));
    }

    // ---- Format function tests ----

    #[test]
    fn format_downloads_table_empty() {
        let (entries, table_str) = format_downloads_table(&[]);
        assert!(entries.is_empty());
        assert!(table_str.contains("DATE"));
        assert!(table_str.contains("DOWNLOADS"));
    }

    #[test]
    fn format_downloads_table_with_data() {
        let items = vec![
            DownloadTrend {
                date: NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(),
                download_count: 42,
            },
            DownloadTrend {
                date: NaiveDate::from_ymd_opt(2026, 1, 2).unwrap(),
                download_count: 100,
            },
        ];
        let (entries, table_str) = format_downloads_table(&items);

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["date"], "2026-01-01");
        assert_eq!(entries[0]["download_count"], 42);
        assert_eq!(entries[1]["download_count"], 100);

        assert!(table_str.contains("2026-01-01"));
        assert!(table_str.contains("42"));
        assert!(table_str.contains("100"));
    }

    #[test]
    fn format_storage_table_empty() {
        let (entries, table_str) = format_storage_table(&[]);
        assert!(entries.is_empty());
        assert!(table_str.contains("REPO"));
        assert!(table_str.contains("FORMAT"));
    }

    #[test]
    fn format_storage_table_with_data() {
        let items = vec![RepositoryStorageBreakdown {
            repository_id: Uuid::nil(),
            repository_key: "my-npm-repo".to_string(),
            repository_name: "My NPM Repo".to_string(),
            format: "npm".to_string(),
            artifact_count: 150,
            storage_bytes: 1024 * 1024 * 512,
            download_count: 5000,
            last_upload_at: Some(Utc::now()),
        }];
        let (entries, table_str) = format_storage_table(&items);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["repository_key"], "my-npm-repo");
        assert_eq!(entries[0]["format"], "npm");
        assert_eq!(entries[0]["artifact_count"], 150);
        assert_eq!(entries[0]["download_count"], 5000);

        assert!(table_str.contains("my-npm-repo"));
        assert!(table_str.contains("npm"));
        assert!(table_str.contains("150"));
        assert!(table_str.contains("512.0 MB"));
        assert!(table_str.contains("5000"));
    }

    #[test]
    fn format_growth_detail_populated() {
        let summary = GrowthSummary {
            period_start: NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(),
            period_end: NaiveDate::from_ymd_opt(2026, 1, 31).unwrap(),
            artifacts_start: 100,
            artifacts_end: 150,
            artifacts_added: 50,
            storage_bytes_start: 1024 * 1024 * 100,
            storage_bytes_end: 1024 * 1024 * 200,
            storage_growth_bytes: 1024 * 1024 * 100,
            storage_growth_percent: 100.0,
            downloads_in_period: 2500,
        };
        let (info, table_str) = format_growth_detail(&summary);

        assert_eq!(info["artifacts_start"], 100);
        assert_eq!(info["artifacts_end"], 150);
        assert_eq!(info["artifacts_added"], 50);
        assert_eq!(info["downloads_in_period"], 2500);

        assert!(table_str.contains("2026-01-01"));
        assert!(table_str.contains("2026-01-31"));
        assert!(table_str.contains("100 -> 150 (+50)"));
        assert!(table_str.contains("100.0 MB -> 200.0 MB (+100.0 MB)"));
        assert!(table_str.contains("100.0%"));
        assert!(table_str.contains("2500"));
    }

    #[test]
    fn format_stale_table_empty() {
        let (entries, table_str) = format_stale_table(&[]);
        assert!(entries.is_empty());
        assert!(table_str.contains("NAME"));
        assert!(table_str.contains("DAYS STALE"));
    }

    #[test]
    fn format_stale_table_with_data() {
        let items = vec![StaleArtifact {
            artifact_id: Uuid::nil(),
            name: "old-package".to_string(),
            path: "artifacts/old-package-1.0.tar.gz".to_string(),
            repository_key: "npm-local".to_string(),
            size_bytes: 1024 * 1024 * 5,
            download_count: 3,
            days_since_download: 120,
            last_downloaded_at: Some(Utc::now()),
            created_at: Utc::now(),
        }];
        let (entries, table_str) = format_stale_table(&items);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["name"], "old-package");
        assert_eq!(entries[0]["repository_key"], "npm-local");
        assert_eq!(entries[0]["download_count"], 3);
        assert_eq!(entries[0]["days_since_download"], 120);

        assert!(table_str.contains("old-package"));
        assert!(table_str.contains("npm-local"));
        assert!(table_str.contains("5.0 MB"));
        assert!(table_str.contains("120"));
    }

    #[test]
    fn format_stale_table_never_downloaded() {
        let items = vec![StaleArtifact {
            artifact_id: Uuid::nil(),
            name: "unused-pkg".to_string(),
            path: "artifacts/unused-pkg-0.1.tar.gz".to_string(),
            repository_key: "pypi-local".to_string(),
            size_bytes: 512,
            download_count: 0,
            days_since_download: 365,
            last_downloaded_at: None,
            created_at: Utc::now(),
        }];
        let (_, table_str) = format_stale_table(&items);
        assert!(table_str.contains("never"));
    }

    // ---- Storage trend format tests ----

    #[test]
    fn format_storage_trend_table_with_data() {
        let items = vec![StorageSnapshot {
            snapshot_date: NaiveDate::from_ymd_opt(2026, 1, 15).unwrap(),
            total_artifacts: 500,
            total_downloads: 10000,
            total_repositories: 10,
            total_storage_bytes: 1024 * 1024 * 1024,
            total_users: 25,
        }];
        let (entries, table_str) = format_storage_trend_table(&items);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["total_artifacts"], 500);
        assert!(table_str.contains("2026-01-15"));
        assert!(table_str.contains("1.0 GB"));
    }

    // ---- Repo trend format tests ----

    #[test]
    fn format_repo_trend_table_with_data() {
        let items = vec![RepositorySnapshot {
            snapshot_date: NaiveDate::from_ymd_opt(2026, 2, 1).unwrap(),
            repository_id: Uuid::nil(),
            repository_key: Some("my-repo".to_string()),
            repository_name: Some("My Repo".to_string()),
            artifact_count: 200,
            download_count: 3000,
            storage_bytes: 1024 * 1024 * 256,
        }];
        let (entries, table_str) = format_repo_trend_table(&items);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["artifact_count"], 200);
        assert!(table_str.contains("2026-02-01"));
        assert!(table_str.contains("256.0 MB"));
    }

    // ---- Snapshot format tests ----

    #[test]
    fn format_snapshot_detail_populated() {
        let snapshot = StorageSnapshot {
            snapshot_date: NaiveDate::from_ymd_opt(2026, 2, 21).unwrap(),
            total_artifacts: 1000,
            total_downloads: 50000,
            total_repositories: 20,
            total_storage_bytes: 1024_i64 * 1024 * 1024 * 5,
            total_users: 100,
        };
        let (info, table_str) = format_snapshot_detail(&snapshot);

        assert_eq!(info["total_artifacts"], 1000);
        assert_eq!(info["total_downloads"], 50000);
        assert_eq!(info["total_users"], 100);
        assert!(table_str.contains("2026-02-21"));
        assert!(table_str.contains("5.0 GB"));
        assert!(table_str.contains("1000"));
        assert!(table_str.contains("50000"));
    }

    // ---- wiremock handler tests ----

    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    static NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

    #[tokio::test]
    async fn handler_downloads() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/admin/analytics/downloads/trend"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"date": "2026-01-01", "download_count": 42}
            ])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = downloads(None, None, &global).await;
        assert!(result.is_ok());

        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_storage_breakdown() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/admin/analytics/storage/breakdown"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
                "repository_id": NIL_UUID,
                "repository_key": "npm-local",
                "repository_name": "NPM Local",
                "format": "npm",
                "artifact_count": 100,
                "storage_bytes": 1048576,
                "download_count": 500,
                "last_upload_at": "2026-01-15T12:00:00Z"
            }])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = storage_breakdown(&global).await;
        assert!(result.is_ok());

        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_growth_summary() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/admin/analytics/storage/growth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "period_start": "2026-01-01",
                "period_end": "2026-01-31",
                "artifacts_start": 100,
                "artifacts_end": 150,
                "artifacts_added": 50,
                "storage_bytes_start": 104857600,
                "storage_bytes_end": 209715200,
                "storage_growth_bytes": 104857600,
                "storage_growth_percent": 100.0,
                "downloads_in_period": 2500
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = growth_summary(None, None, &global).await;
        assert!(result.is_ok());

        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_stale_artifacts() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/admin/analytics/artifacts/stale"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
                "artifact_id": NIL_UUID,
                "name": "old-pkg",
                "path": "artifacts/old-pkg-1.0.tar.gz",
                "repository_key": "npm-local",
                "size_bytes": 1048576,
                "download_count": 2,
                "days_since_download": 120,
                "last_downloaded_at": "2025-10-01T00:00:00Z",
                "created_at": "2025-06-01T00:00:00Z"
            }])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = top_stale(90, 20, &global).await;
        assert!(result.is_ok());

        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_snapshot() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/admin/analytics/snapshot"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "snapshot_date": "2026-02-21",
                "total_artifacts": 1000,
                "total_downloads": 50000,
                "total_repositories": 20,
                "total_storage_bytes": 5368709120_i64,
                "total_users": 100
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = capture_snapshot(&global).await;
        assert!(result.is_ok());

        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_downloads_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/admin/analytics/downloads/trend"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"date": "2026-01-01", "download_count": 42}
            ])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = downloads(None, None, &global).await;
        assert!(result.is_ok());

        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_storage_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/admin/analytics/storage/breakdown"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
                "repository_id": NIL_UUID,
                "repository_key": "npm-local",
                "repository_name": "NPM Local",
                "format": "npm",
                "artifact_count": 100,
                "storage_bytes": 1048576,
                "download_count": 500,
                "last_upload_at": null
            }])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = storage_breakdown(&global).await;
        assert!(result.is_ok());

        crate::test_utils::teardown_env();
    }

    // ---- insta snapshot tests ----

    #[test]
    fn snapshot_analytics_summary_json() {
        let data = json!({
            "total_artifacts": 1250,
            "total_downloads": 45000,
            "total_storage_bytes": 10737418240_i64,
            "total_repositories": 12,
            "active_users_30d": 42,
            "top_format": "npm",
            "period": "30d"
        });
        let output = crate::output::render(&data, &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("analytics_summary_json", parsed);
    }
}
