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
