use artifact_keeper_sdk::{ClientAdminExt, ClientPluginsExt, ClientUsersExt};
use clap::Subcommand;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use miette::{IntoDiagnostic, Result};

use super::client::client_for;
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat, format_bytes};

#[derive(Subcommand)]
pub enum AdminCommand {
    /// Manage backups
    Backup {
        #[command(subcommand)]
        command: BackupCommand,
    },

    /// Run storage cleanup
    Cleanup {
        /// Clean up old audit logs
        #[arg(long)]
        audit_logs: bool,

        /// Clean up old backups
        #[arg(long)]
        old_backups: bool,

        /// Mark stale peers as offline
        #[arg(long)]
        stale_peers: bool,
    },

    /// Show server metrics
    Metrics,

    /// Manage users
    Users {
        #[command(subcommand)]
        command: UsersCommand,
    },

    /// Manage WASM plugins
    Plugins {
        #[command(subcommand)]
        command: PluginsCommand,
    },
}

#[derive(Subcommand)]
pub enum BackupCommand {
    /// List available backups
    List {
        /// Page number
        #[arg(long, default_value = "1")]
        page: i32,

        /// Results per page
        #[arg(long, default_value = "20")]
        per_page: i32,
    },
    /// Create a new backup
    Create {
        /// Backup type (full, incremental)
        #[arg(long, default_value = "full")]
        r#type: String,
    },
    /// Restore from a backup
    Restore {
        /// Backup ID
        id: String,

        /// Restore database tables
        #[arg(long)]
        database: bool,

        /// Restore artifact files
        #[arg(long)]
        artifacts: bool,
    },
}

#[derive(Subcommand)]
pub enum UsersCommand {
    /// List users
    List {
        /// Search by username or email
        #[arg(long)]
        search: Option<String>,

        /// Page number
        #[arg(long, default_value = "1")]
        page: i32,

        /// Results per page
        #[arg(long, default_value = "20")]
        per_page: i32,
    },
    /// Create a user
    Create {
        /// Username
        username: String,

        /// Email address
        #[arg(long)]
        email: String,

        /// Display name
        #[arg(long)]
        display_name: Option<String>,

        /// Grant admin privileges
        #[arg(long)]
        admin: bool,
    },
    /// Delete a user
    Delete {
        /// User ID
        id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
pub enum PluginsCommand {
    /// List installed plugins
    List,
    /// Install a plugin from a git repository
    Install {
        /// Git repository URL
        url: String,

        /// Git ref (tag, branch, or commit)
        #[arg(long)]
        r#ref: Option<String>,
    },
    /// Remove a plugin
    Remove {
        /// Plugin ID
        id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}

impl AdminCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Backup { command } => match command {
                BackupCommand::List { page, per_page } => {
                    list_backups(page, per_page, global).await
                }
                BackupCommand::Create { r#type } => create_backup(&r#type, global).await,
                BackupCommand::Restore {
                    id,
                    database,
                    artifacts,
                } => restore_backup(&id, database, artifacts, global).await,
            },
            Self::Cleanup {
                audit_logs,
                old_backups,
                stale_peers,
            } => run_cleanup(audit_logs, old_backups, stale_peers, global).await,
            Self::Metrics => show_metrics(global).await,
            Self::Users { command } => match command {
                UsersCommand::List {
                    search,
                    page,
                    per_page,
                } => list_users(search.as_deref(), page, per_page, global).await,
                UsersCommand::Create {
                    username,
                    email,
                    display_name,
                    admin,
                } => create_user(&username, &email, display_name.as_deref(), admin, global).await,
                UsersCommand::Delete { id, yes } => delete_user(&id, yes, global).await,
            },
            Self::Plugins { command } => match command {
                PluginsCommand::List => list_plugins(global).await,
                PluginsCommand::Install { url, r#ref } => {
                    install_plugin(&url, r#ref.as_deref(), global).await
                }
                PluginsCommand::Remove { id, yes } => remove_plugin(&id, yes, global).await,
            },
        }
    }
}

async fn list_backups(page: i32, per_page: i32, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching backups...");

    let resp = client
        .list_backups()
        .page(page)
        .per_page(per_page)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to list backups: {e}")))?;

    spinner.finish_and_clear();

    if resp.items.is_empty() {
        eprintln!("No backups found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for b in &resp.items {
            println!("{}", b.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp
        .items
        .iter()
        .map(|b| {
            serde_json::json!({
                "id": b.id.to_string(),
                "status": b.status,
                "type": b.type_,
                "artifacts": b.artifact_count,
                "size": format_bytes(b.size_bytes),
                "size_bytes": b.size_bytes,
                "created_at": b.created_at.to_rfc3339(),
                "completed_at": b.completed_at.map(|t| t.to_rfc3339()),
                "error": b.error_message,
            })
        })
        .collect();

    let table_str = {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec!["ID", "STATUS", "TYPE", "ARTIFACTS", "SIZE", "CREATED"]);

        for b in &resp.items {
            let id_short = &b.id.to_string()[..8];
            let size = format_bytes(b.size_bytes);
            let created = b.created_at.format("%Y-%m-%d %H:%M").to_string();
            table.add_row(vec![
                id_short,
                &b.status,
                &b.type_,
                &b.artifact_count.to_string(),
                &size,
                &created,
            ]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    eprintln!("{} backups total.", resp.total);

    Ok(())
}

async fn create_backup(backup_type: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Creating backup...");

    let body = artifact_keeper_sdk::types::CreateBackupRequest {
        repository_ids: None,
        type_: Some(backup_type.to_string()),
    };

    let backup = client
        .create_backup()
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to create backup: {e}")))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", backup.id);
        return Ok(());
    }

    let info = serde_json::json!({
        "id": backup.id.to_string(),
        "status": backup.status,
        "type": backup.type_,
    });

    let table_str = format!(
        "Backup created: {} ({})\nStatus: {}",
        backup.id, backup.type_, backup.status
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn restore_backup(
    backup_id: &str,
    database: bool,
    artifacts: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;

    let id: uuid::Uuid = backup_id
        .parse()
        .map_err(|_| AkError::ConfigError(format!("Invalid backup ID: {backup_id}")))?;

    if !global.no_input {
        let confirmed = dialoguer::Confirm::new()
            .with_prompt(format!(
                "Restore from backup {backup_id}? This may overwrite existing data"
            ))
            .default(false)
            .interact()
            .into_diagnostic()?;

        if !confirmed {
            eprintln!("Cancelled.");
            return Ok(());
        }
    }

    let spinner = output::spinner("Restoring backup...");

    let body = artifact_keeper_sdk::types::RestoreRequest {
        restore_database: database.then_some(true),
        restore_artifacts: artifacts.then_some(true),
        target_repository_id: None,
    };

    let resp = client
        .restore_backup()
        .id(id)
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to restore backup: {e}")))?;

    spinner.finish_and_clear();

    eprintln!(
        "Restore complete: {} artifacts restored, {} tables restored.",
        resp.artifacts_restored,
        resp.tables_restored.len()
    );

    if !resp.errors.is_empty() {
        eprintln!("Errors:");
        for err in &resp.errors {
            eprintln!("  - {err}");
        }
    }

    Ok(())
}

async fn run_cleanup(
    audit_logs: bool,
    old_backups: bool,
    stale_peers: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Running cleanup...");

    let body = artifact_keeper_sdk::types::CleanupRequest {
        cleanup_audit_logs: audit_logs.then_some(true),
        cleanup_old_backups: old_backups.then_some(true),
        cleanup_stale_peers: stale_peers.then_some(true),
    };

    let resp = client
        .run_cleanup()
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Cleanup failed: {e}")))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Json | OutputFormat::Yaml) {
        let info = serde_json::json!({
            "audit_logs_deleted": resp.audit_logs_deleted,
            "backups_deleted": resp.backups_deleted,
            "peers_marked_offline": resp.peers_marked_offline,
        });
        println!("{}", output::render(&info, &global.format, None));
    } else {
        eprintln!("Cleanup complete:");
        eprintln!("  Audit logs deleted:    {}", resp.audit_logs_deleted);
        eprintln!("  Old backups deleted:   {}", resp.backups_deleted);
        eprintln!("  Peers marked offline:  {}", resp.peers_marked_offline);
    }

    Ok(())
}

async fn show_metrics(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching metrics...");

    let stats = client
        .get_system_stats()
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to get metrics: {e}")))?;

    spinner.finish_and_clear();

    let info = serde_json::json!({
        "total_artifacts": stats.total_artifacts,
        "total_downloads": stats.total_downloads,
        "total_repositories": stats.total_repositories,
        "total_storage": format_bytes(stats.total_storage_bytes),
        "total_storage_bytes": stats.total_storage_bytes,
        "total_users": stats.total_users,
        "active_peers": stats.active_peers,
        "pending_sync_tasks": stats.pending_sync_tasks,
    });

    let table_str = format!(
        "Artifacts:      {}\n\
         Downloads:      {}\n\
         Repositories:   {}\n\
         Storage:        {}\n\
         Users:          {}\n\
         Active Peers:   {}\n\
         Pending Syncs:  {}",
        stats.total_artifacts,
        stats.total_downloads,
        stats.total_repositories,
        format_bytes(stats.total_storage_bytes),
        stats.total_users,
        stats.active_peers,
        stats.pending_sync_tasks,
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn list_users(
    search: Option<&str>,
    page: i32,
    per_page: i32,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching users...");

    let mut req = client.list_users().page(page).per_page(per_page);
    if let Some(q) = search {
        req = req.search(q);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to list users: {e}")))?;

    spinner.finish_and_clear();

    if resp.items.is_empty() {
        eprintln!("No users found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for u in &resp.items {
            println!("{}", u.username);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp
        .items
        .iter()
        .map(|u| {
            serde_json::json!({
                "id": u.id.to_string(),
                "username": u.username,
                "email": u.email,
                "display_name": u.display_name,
                "is_admin": u.is_admin,
                "is_active": u.is_active,
                "auth_provider": u.auth_provider,
            })
        })
        .collect();

    let table_str = {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                "ID",
                "USERNAME",
                "EMAIL",
                "DISPLAY NAME",
                "ADMIN",
                "ACTIVE",
                "AUTH",
            ]);

        for u in &resp.items {
            let id_short = &u.id.to_string()[..8];
            let display = u.display_name.as_deref().unwrap_or("-");
            let admin = if u.is_admin { "yes" } else { "no" };
            let active = if u.is_active { "yes" } else { "no" };
            table.add_row(vec![
                id_short,
                &u.username,
                &u.email,
                display,
                admin,
                active,
                &u.auth_provider,
            ]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    if resp.pagination.total_pages > 1 {
        eprintln!(
            "Page {} of {} ({} total users)",
            resp.pagination.page, resp.pagination.total_pages, resp.pagination.total
        );
    }

    Ok(())
}

async fn create_user(
    username: &str,
    email: &str,
    display_name: Option<&str>,
    admin: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Creating user...");

    let body = artifact_keeper_sdk::types::CreateUserRequest {
        username: username.to_string(),
        email: email.to_string(),
        password: None,
        display_name: display_name.map(|s| s.to_string()),
        is_admin: admin.then_some(true),
    };

    let resp = client
        .create_user()
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to create user: {e}")))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", resp.user.id);
        return Ok(());
    }

    eprintln!(
        "User '{}' created (ID: {}).",
        resp.user.username, resp.user.id
    );

    if let Some(password) = &resp.generated_password {
        eprintln!("Generated password: {password}");
        eprintln!("(User will be prompted to change on first login.)");
    }

    Ok(())
}

async fn delete_user(user_id: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;

    let id: uuid::Uuid = user_id
        .parse()
        .map_err(|_| AkError::ConfigError(format!("Invalid user ID: {user_id}")))?;

    let needs_confirmation = !skip_confirm && !global.no_input;
    if needs_confirmation {
        let confirmed = dialoguer::Confirm::new()
            .with_prompt(format!("Delete user {user_id}? This cannot be undone"))
            .default(false)
            .interact()
            .into_diagnostic()?;

        if !confirmed {
            eprintln!("Cancelled.");
            return Ok(());
        }
    }

    let spinner = output::spinner("Deleting user...");

    client
        .delete_user()
        .id(id)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to delete user: {e}")))?;

    spinner.finish_and_clear();
    eprintln!("User {user_id} deleted.");

    Ok(())
}

async fn list_plugins(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching plugins...");

    let resp = client
        .list_plugins()
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to list plugins: {e}")))?;

    spinner.finish_and_clear();

    if resp.items.is_empty() {
        eprintln!("No plugins installed.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for p in &resp.items {
            println!("{}", p.name);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp
        .items
        .iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id.to_string(),
                "name": p.name,
                "display_name": p.display_name,
                "version": p.version,
                "type": p.plugin_type,
                "status": p.status,
                "author": p.author,
                "installed_at": p.installed_at.to_rfc3339(),
            })
        })
        .collect();

    let table_str = {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                "NAME",
                "VERSION",
                "TYPE",
                "STATUS",
                "AUTHOR",
                "INSTALLED",
            ]);

        for p in &resp.items {
            let author = p.author.as_deref().unwrap_or("-");
            let installed = p.installed_at.format("%Y-%m-%d").to_string();
            table.add_row(vec![
                p.display_name.as_str(),
                p.version.as_str(),
                p.plugin_type.as_str(),
                p.status.as_str(),
                author,
                &installed,
            ]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn install_plugin(url: &str, git_ref: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Installing plugin...");

    let body = artifact_keeper_sdk::types::InstallFromGitRequest {
        url: url.to_string(),
        ref_: git_ref.map(|s| s.to_string()),
    };

    let resp = client
        .install_from_git()
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to install plugin: {e}")))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", resp.plugin_id);
        return Ok(());
    }

    eprintln!(
        "Plugin '{}' v{} installed (format: {}).",
        resp.name, resp.version, resp.format_key
    );
    eprintln!("{}", resp.message);

    Ok(())
}

async fn remove_plugin(plugin_id: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;

    let id: uuid::Uuid = plugin_id
        .parse()
        .map_err(|_| AkError::ConfigError(format!("Invalid plugin ID: {plugin_id}")))?;

    let needs_confirmation = !skip_confirm && !global.no_input;
    if needs_confirmation {
        let confirmed = dialoguer::Confirm::new()
            .with_prompt(format!(
                "Remove plugin {plugin_id}? This will unload the format handler"
            ))
            .default(false)
            .interact()
            .into_diagnostic()?;

        if !confirmed {
            eprintln!("Cancelled.");
            return Ok(());
        }
    }

    let spinner = output::spinner("Removing plugin...");

    client
        .uninstall_plugin()
        .id(id)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to remove plugin: {e}")))?;

    spinner.finish_and_clear();
    eprintln!("Plugin {plugin_id} removed.");

    Ok(())
}
