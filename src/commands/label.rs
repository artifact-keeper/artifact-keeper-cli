use artifact_keeper_sdk::ClientRepositoryLabelsExt;
use clap::Subcommand;
use miette::Result;

use super::client::client_for;
use super::helpers::{new_table, sdk_err};
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum LabelCommand {
    /// Manage repository labels
    Repo {
        #[command(subcommand)]
        command: RepoLabelCommand,
    },
}

#[derive(Subcommand)]
pub enum RepoLabelCommand {
    /// List labels on a repository
    List {
        /// Repository key
        key: String,
    },

    /// Add a label to a repository
    Add {
        /// Repository key
        key: String,

        /// Label in key=value format
        label: String,
    },

    /// Remove a label from a repository
    Remove {
        /// Repository key
        key: String,

        /// Label key to remove
        label_key: String,
    },
}

impl LabelCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Repo { command } => match command {
                RepoLabelCommand::List { key } => list_labels(&key, global).await,
                RepoLabelCommand::Add { key, label } => add_label(&key, &label, global).await,
                RepoLabelCommand::Remove { key, label_key } => {
                    remove_label(&key, &label_key, global).await
                }
            },
        }
    }
}

async fn list_labels(repo_key: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching labels...");

    let resp = client
        .list_repo_labels()
        .key(repo_key)
        .send()
        .await
        .map_err(|e| sdk_err("list labels", e))?;

    spinner.finish_and_clear();

    if resp.items.is_empty() {
        eprintln!("No labels on repository '{repo_key}'.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for l in &resp.items {
            println!("{}={}", l.key, l.value);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp
        .items
        .iter()
        .map(|l| {
            serde_json::json!({
                "id": l.id.to_string(),
                "key": l.key,
                "value": l.value,
                "created_at": l.created_at.to_rfc3339(),
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["KEY", "VALUE", "CREATED"]);

        for l in &resp.items {
            let created = l.created_at.format("%Y-%m-%d").to_string();
            table.add_row(vec![&l.key, &l.value, &created]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn add_label(repo_key: &str, label: &str, global: &GlobalArgs) -> Result<()> {
    let (label_key, label_value) = label
        .split_once('=')
        .ok_or_else(|| AkError::ConfigError("Label must be in key=value format".to_string()))?;

    let client = client_for(global)?;
    let spinner = output::spinner("Adding label...");

    let body = artifact_keeper_sdk::types::AddLabelRequest {
        value: Some(label_value.to_string()),
    };

    client
        .add_repo_label()
        .key(repo_key)
        .label_key(label_key)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("add label", e))?;

    spinner.finish_and_clear();
    eprintln!("Label '{label_key}={label_value}' added to repository '{repo_key}'.");

    Ok(())
}

fn format_label_table(items: &[serde_json::Value]) -> String {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec!["KEY", "VALUE", "CREATED"]);

    for l in items {
        table.add_row(vec![
            l["key"].as_str().unwrap_or("-"),
            l["value"].as_str().unwrap_or("-"),
            l["created_at"].as_str().unwrap_or("-"),
        ]);
    }

    table.to_string()
}

async fn remove_label(repo_key: &str, label_key: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Removing label...");

    client
        .delete_repo_label()
        .key(repo_key)
        .label_key(label_key)
        .send()
        .await
        .map_err(|e| sdk_err("remove label", e))?;

    spinner.finish_and_clear();
    eprintln!("Label '{label_key}' removed from repository '{repo_key}'.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use serde_json::json;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: LabelCommand,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).unwrap()
    }

    fn try_parse(args: &[&str]) -> Result<TestCli, clap::Error> {
        TestCli::try_parse_from(args)
    }

    // ---- parsing: repo list ----

    #[test]
    fn parse_repo_list() {
        let cli = parse(&["test", "repo", "list", "maven-releases"]);
        match cli.command {
            LabelCommand::Repo {
                command: RepoLabelCommand::List { key },
            } => {
                assert_eq!(key, "maven-releases");
            }
            _ => panic!("expected Repo List"),
        }
    }

    #[test]
    fn parse_repo_list_missing_key() {
        let result = try_parse(&["test", "repo", "list"]);
        assert!(result.is_err());
    }

    // ---- parsing: repo add ----

    #[test]
    fn parse_repo_add() {
        let cli = parse(&["test", "repo", "add", "maven-releases", "env=production"]);
        match cli.command {
            LabelCommand::Repo {
                command: RepoLabelCommand::Add { key, label },
            } => {
                assert_eq!(key, "maven-releases");
                assert_eq!(label, "env=production");
            }
            _ => panic!("expected Repo Add"),
        }
    }

    #[test]
    fn parse_repo_add_missing_label() {
        let result = try_parse(&["test", "repo", "add", "maven-releases"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_repo_add_missing_both() {
        let result = try_parse(&["test", "repo", "add"]);
        assert!(result.is_err());
    }

    // ---- parsing: repo remove ----

    #[test]
    fn parse_repo_remove() {
        let cli = parse(&["test", "repo", "remove", "maven-releases", "env"]);
        match cli.command {
            LabelCommand::Repo {
                command: RepoLabelCommand::Remove { key, label_key },
            } => {
                assert_eq!(key, "maven-releases");
                assert_eq!(label_key, "env");
            }
            _ => panic!("expected Repo Remove"),
        }
    }

    #[test]
    fn parse_repo_remove_missing_label_key() {
        let result = try_parse(&["test", "repo", "remove", "maven-releases"]);
        assert!(result.is_err());
    }

    // ---- parsing: missing nested subcommand ----

    #[test]
    fn parse_repo_missing_subcommand() {
        let result = try_parse(&["test", "repo"]);
        assert!(result.is_err());
    }

    // ---- format functions ----

    #[test]
    fn format_label_table_renders() {
        let items = vec![json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "key": "env",
            "value": "production",
            "created_at": "2026-01-15",
        })];
        let table = format_label_table(&items);
        assert!(table.contains("env"));
        assert!(table.contains("production"));
        assert!(table.contains("2026-01-15"));
    }

    #[test]
    fn format_label_table_multiple_rows() {
        let items = vec![
            json!({
                "id": "00000000-0000-0000-0000-000000000001",
                "key": "env",
                "value": "production",
                "created_at": "2026-01-15",
            }),
            json!({
                "id": "11111111-1111-1111-1111-111111111111",
                "key": "team",
                "value": "platform",
                "created_at": "2026-02-01",
            }),
        ];
        let table = format_label_table(&items);
        assert!(table.contains("env"));
        assert!(table.contains("production"));
        assert!(table.contains("team"));
        assert!(table.contains("platform"));
    }

    #[test]
    fn format_label_table_empty() {
        let items: Vec<serde_json::Value> = vec![];
        let table = format_label_table(&items);
        // Should still contain the header
        assert!(table.contains("KEY"));
        assert!(table.contains("VALUE"));
    }

    #[test]
    fn format_label_table_null_values() {
        let items = vec![json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "key": null,
            "value": null,
            "created_at": null,
        })];
        let table = format_label_table(&items);
        assert!(table.contains("-"));
    }
}
