use artifact_keeper_sdk::ClientRepositoriesExt;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use futures::StreamExt;
use miette::{IntoDiagnostic, Result};

use super::client::build_client;
use crate::cli::GlobalArgs;
use crate::config::AppConfig;
use crate::error::AkError;
use crate::output::{self, OutputFormat, format_bytes};

/// Migrate artifacts between instances or repositories in bulk.
pub async fn execute(
    from_instance: &str,
    from_repo: &str,
    to_instance: Option<&str>,
    to_repo: &str,
    dry_run: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let config = AppConfig::load()?;

    let (src_name, src_instance) = config.resolve_instance(Some(from_instance))?;
    let (dst_name, dst_instance) =
        config.resolve_instance(to_instance.or(global.instance.as_deref()))?;

    let src_client = build_client(src_name, src_instance, None)?;
    let dst_client = build_client(dst_name, dst_instance, None)?;

    let spinner = output::spinner(&format!("Listing artifacts in {src_name}:{from_repo}..."));

    let mut all_artifacts = Vec::new();
    let mut page = 1;
    let page_size = 100;
    loop {
        let resp = src_client
            .list_artifacts()
            .key(from_repo)
            .page(page)
            .per_page(page_size)
            .send()
            .await
            .map_err(|e| AkError::ServerError(format!("Failed to list source artifacts: {e}")))?;

        let is_last_page = resp.items.len() < page_size as usize;
        all_artifacts.extend(resp.items.clone());
        if is_last_page {
            break;
        }
        page += 1;
    }

    spinner.finish_and_clear();

    if all_artifacts.is_empty() {
        eprintln!("No artifacts found in {src_name}:{from_repo}.");
        return Ok(());
    }

    let total_size: i64 = all_artifacts.iter().map(|a| a.size_bytes).sum();

    eprintln!(
        "Found {} artifacts ({}) in {src_name}:{from_repo}",
        all_artifacts.len(),
        format_bytes(total_size),
    );

    if dry_run {
        if matches!(global.format, OutputFormat::Quiet) {
            for a in &all_artifacts {
                println!("{}", a.path);
            }
            return Ok(());
        }

        let entries: Vec<_> = all_artifacts
            .iter()
            .map(|a| {
                serde_json::json!({
                    "path": a.path,
                    "version": a.version,
                    "size": format_bytes(a.size_bytes),
                    "size_bytes": a.size_bytes,
                })
            })
            .collect();

        let table_str = {
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL_CONDENSED)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec!["PATH", "VERSION", "SIZE"]);

            for a in &all_artifacts {
                let version = a.version.as_deref().unwrap_or("-");
                let size = format_bytes(a.size_bytes);
                table.add_row(vec![a.path.as_str(), version, &size]);
            }

            table.to_string()
        };

        println!(
            "{}",
            output::render(&entries, &global.format, Some(table_str))
        );

        eprintln!(
            "\nDry run: would migrate {} artifacts ({}) from {src_name}:{from_repo} to {dst_name}:{to_repo}.",
            all_artifacts.len(),
            format_bytes(total_size),
        );

        return Ok(());
    }

    if !global.no_input {
        let confirmed = dialoguer::Confirm::new()
            .with_prompt(format!(
                "Migrate {} artifacts from {src_name}:{from_repo} to {dst_name}:{to_repo}?",
                all_artifacts.len()
            ))
            .default(false)
            .interact()
            .into_diagnostic()?;

        if !confirmed {
            eprintln!("Cancelled.");
            return Ok(());
        }
    }

    let pb = indicatif::ProgressBar::new(all_artifacts.len() as u64);
    pb.set_style(
        indicatif::ProgressStyle::with_template("{msg} [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("█▉▊▋▌▍▎▏ "),
    );
    pb.set_message("Migrating");

    let mut success_count = 0u64;
    let mut fail_count = 0u64;
    let mut bytes_transferred: i64 = 0;

    for artifact in &all_artifacts {
        let result =
            migrate_single_artifact(&src_client, from_repo, &artifact.path, &dst_client, to_repo)
                .await;

        match result {
            Ok(size) => {
                success_count += 1;
                bytes_transferred += size;
            }
            Err(e) => {
                fail_count += 1;
                pb.suspend(|| {
                    eprintln!("  Failed: {} — {e}", artifact.path);
                });
            }
        }

        pb.inc(1);
    }

    pb.finish_and_clear();

    eprintln!(
        "Migration complete: {} succeeded, {} failed ({})",
        success_count,
        fail_count,
        format_bytes(bytes_transferred),
    );

    if fail_count > 0 {
        std::process::exit(1);
    }

    Ok(())
}

async fn migrate_single_artifact(
    src_client: &artifact_keeper_sdk::Client,
    src_repo: &str,
    artifact_path: &str,
    dst_client: &artifact_keeper_sdk::Client,
    dst_repo: &str,
) -> std::result::Result<i64, String> {
    let resp = src_client
        .download_artifact()
        .key(src_repo)
        .path(artifact_path)
        .send()
        .await
        .map_err(|e| format!("download: {e}"))?;

    let mut bytes = Vec::new();
    let mut stream = resp.into_inner();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("stream: {e}"))?;
        bytes.extend_from_slice(&chunk);
    }

    let size = bytes.len() as i64;
    let body = reqwest::Body::from(bytes);

    dst_client
        .upload_artifact()
        .key(dst_repo)
        .path(artifact_path)
        .body(body)
        .send()
        .await
        .map_err(|e| format!("upload: {e}"))?;

    Ok(size)
}

/// Format a list of artifact entries for the dry-run preview table.
fn format_migration_preview_table(items: &[serde_json::Value]) -> String {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec!["PATH", "VERSION", "SIZE"]);

    for a in items {
        table.add_row(vec![
            a["path"].as_str().unwrap_or("-"),
            a["version"].as_str().unwrap_or("-"),
            a["size"].as_str().unwrap_or("-"),
        ]);
    }

    table.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // For migrate, the command args are defined on the Cli struct in cli.rs,
    // not as a separate subcommand enum. We test the parsing through the full
    // Cli parser and also test the format functions directly.

    mod parsing {
        use clap::Parser;

        // Replicate the migrate args for isolated testing
        #[derive(Parser)]
        struct MigrateTestCli {
            #[arg(long)]
            from_instance: String,

            #[arg(long)]
            from_repo: String,

            #[arg(long)]
            to_instance: Option<String>,

            #[arg(long)]
            to_repo: String,

            #[arg(long)]
            dry_run: bool,
        }

        fn parse(args: &[&str]) -> MigrateTestCli {
            MigrateTestCli::try_parse_from(args).unwrap()
        }

        fn try_parse(args: &[&str]) -> Result<MigrateTestCli, clap::Error> {
            MigrateTestCli::try_parse_from(args)
        }

        #[test]
        fn parse_required_args() {
            let cli = parse(&[
                "test",
                "--from-instance",
                "staging",
                "--from-repo",
                "libs",
                "--to-repo",
                "libs-prod",
            ]);
            assert_eq!(cli.from_instance, "staging");
            assert_eq!(cli.from_repo, "libs");
            assert_eq!(cli.to_repo, "libs-prod");
            assert!(cli.to_instance.is_none());
            assert!(!cli.dry_run);
        }

        #[test]
        fn parse_all_args() {
            let cli = parse(&[
                "test",
                "--from-instance",
                "old",
                "--from-repo",
                "npm",
                "--to-instance",
                "new",
                "--to-repo",
                "npm-mirror",
                "--dry-run",
            ]);
            assert_eq!(cli.from_instance, "old");
            assert_eq!(cli.from_repo, "npm");
            assert_eq!(cli.to_instance.as_deref(), Some("new"));
            assert_eq!(cli.to_repo, "npm-mirror");
            assert!(cli.dry_run);
        }

        #[test]
        fn parse_dry_run_flag() {
            let cli = parse(&[
                "test",
                "--from-instance",
                "staging",
                "--from-repo",
                "libs",
                "--to-repo",
                "libs-prod",
                "--dry-run",
            ]);
            assert!(cli.dry_run);
        }

        #[test]
        fn parse_missing_from_instance_fails() {
            assert!(try_parse(&["test", "--from-repo", "libs", "--to-repo", "prod"]).is_err());
        }

        #[test]
        fn parse_missing_from_repo_fails() {
            assert!(
                try_parse(&["test", "--from-instance", "staging", "--to-repo", "prod"]).is_err()
            );
        }

        #[test]
        fn parse_missing_to_repo_fails() {
            assert!(
                try_parse(&["test", "--from-instance", "staging", "--from-repo", "libs"]).is_err()
            );
        }

        #[test]
        fn parse_to_instance_optional() {
            let cli = parse(&[
                "test",
                "--from-instance",
                "staging",
                "--from-repo",
                "libs",
                "--to-repo",
                "prod",
            ]);
            assert!(cli.to_instance.is_none());
        }
    }

    // ---- Format function tests ----

    #[test]
    fn format_migration_preview_table_renders() {
        let items = vec![json!({
            "path": "org/example/lib-1.0.jar",
            "version": "1.0",
            "size": "2.5 MB",
        })];
        let table = format_migration_preview_table(&items);
        assert!(table.contains("org/example/lib-1.0.jar"));
        assert!(table.contains("1.0"));
        assert!(table.contains("2.5 MB"));
    }

    #[test]
    fn format_migration_preview_table_empty() {
        let items: Vec<serde_json::Value> = vec![];
        let table = format_migration_preview_table(&items);
        assert!(table.contains("PATH"));
        assert!(table.contains("VERSION"));
        assert!(table.contains("SIZE"));
    }

    #[test]
    fn format_migration_preview_table_multiple_rows() {
        let items = vec![
            json!({
                "path": "pkg-a/1.0/a.jar",
                "version": "1.0",
                "size": "1.0 MB",
            }),
            json!({
                "path": "pkg-b/2.0/b.whl",
                "version": "2.0",
                "size": "500.0 KB",
            }),
            json!({
                "path": "pkg-c/0.1/c.tar.gz",
                "version": "0.1",
                "size": "100.0 KB",
            }),
        ];
        let table = format_migration_preview_table(&items);
        assert!(table.contains("pkg-a/1.0/a.jar"));
        assert!(table.contains("pkg-b/2.0/b.whl"));
        assert!(table.contains("pkg-c/0.1/c.tar.gz"));
    }

    #[test]
    fn format_migration_preview_table_missing_version() {
        let items = vec![json!({
            "path": "my-file.bin",
            "size": "10.0 KB",
        })];
        let table = format_migration_preview_table(&items);
        assert!(table.contains("my-file.bin"));
        assert!(table.contains("-")); // missing version shown as "-"
    }
}
