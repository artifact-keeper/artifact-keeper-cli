use artifact_keeper_sdk::{ClientAdminExt, ClientPluginsExt, ClientUsersExt};
use clap::Subcommand;
use miette::Result;

use super::client::client_for;
use super::helpers::{confirm_action, new_table, parse_uuid, sdk_err, short_id};
use crate::cli::GlobalArgs;
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
    /// Update a user's details
    Update {
        /// User ID
        id: String,

        /// New email address
        #[arg(long)]
        email: Option<String>,

        /// New display name
        #[arg(long)]
        display_name: Option<String>,

        /// Set admin status
        #[arg(long)]
        admin: Option<bool>,

        /// Set active status
        #[arg(long)]
        active: Option<bool>,
    },

    /// Delete a user
    Delete {
        /// User ID
        id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Reset a user's password (generates a temporary password)
    ResetPassword {
        /// User ID
        id: String,
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
                UsersCommand::Update {
                    id,
                    email,
                    display_name,
                    admin,
                    active,
                } => {
                    update_user(
                        &id,
                        email.as_deref(),
                        display_name.as_deref(),
                        admin,
                        active,
                        global,
                    )
                    .await
                }
                UsersCommand::Delete { id, yes } => delete_user(&id, yes, global).await,
                UsersCommand::ResetPassword { id } => reset_password(&id, global).await,
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
        .map_err(|e| sdk_err("list backups", e))?;

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
        let mut table = new_table(vec!["ID", "STATUS", "TYPE", "ARTIFACTS", "SIZE", "CREATED"]);

        for b in &resp.items {
            let id_short = short_id(&b.id);
            let size = format_bytes(b.size_bytes);
            let created = b.created_at.format("%Y-%m-%d %H:%M").to_string();
            table.add_row(vec![
                &id_short,
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
        .map_err(|e| sdk_err("create backup", e))?;

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

    let id = parse_uuid(backup_id, "backup")?;

    if !confirm_action(
        &format!("Restore from backup {backup_id}? This may overwrite existing data"),
        false,
        global.no_input,
    )? {
        return Ok(());
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
        .map_err(|e| sdk_err("restore backup", e))?;

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
        .map_err(|e| sdk_err("run cleanup", e))?;

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
        .map_err(|e| sdk_err("get metrics", e))?;

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

    let resp = req.send().await.map_err(|e| sdk_err("list users", e))?;

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
        let mut table = new_table(vec![
            "ID",
            "USERNAME",
            "EMAIL",
            "DISPLAY NAME",
            "ADMIN",
            "ACTIVE",
            "AUTH",
        ]);

        for u in &resp.items {
            let id_short = short_id(&u.id);
            let display = u.display_name.as_deref().unwrap_or("-");
            let admin = if u.is_admin { "yes" } else { "no" };
            let active = if u.is_active { "yes" } else { "no" };
            table.add_row(vec![
                &id_short,
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
        .map_err(|e| sdk_err("create user", e))?;

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

async fn update_user(
    user_id: &str,
    email: Option<&str>,
    display_name: Option<&str>,
    admin: Option<bool>,
    active: Option<bool>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;

    let id = parse_uuid(user_id, "user")?;

    let spinner = output::spinner("Updating user...");

    let body = artifact_keeper_sdk::types::UpdateUserRequest {
        email: email.map(|s| s.to_string()),
        display_name: display_name.map(|s| s.to_string()),
        is_admin: admin,
        is_active: active,
    };

    let user = client
        .update_user()
        .id(id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("update user", e))?;

    spinner.finish_and_clear();
    eprintln!("User '{}' updated (ID: {}).", user.username, user.id);

    Ok(())
}

async fn delete_user(user_id: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;

    let id = parse_uuid(user_id, "user")?;

    if !confirm_action(
        &format!("Delete user {user_id}? This cannot be undone"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let spinner = output::spinner("Deleting user...");

    client
        .delete_user()
        .id(id)
        .send()
        .await
        .map_err(|e| sdk_err("delete user", e))?;

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
        .map_err(|e| sdk_err("list plugins", e))?;

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
        let mut table = new_table(vec![
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
        .map_err(|e| sdk_err("install plugin", e))?;

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

    let id = parse_uuid(plugin_id, "plugin")?;

    if !confirm_action(
        &format!("Remove plugin {plugin_id}? This will unload the format handler"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let spinner = output::spinner("Removing plugin...");

    client
        .uninstall_plugin()
        .id(id)
        .send()
        .await
        .map_err(|e| sdk_err("remove plugin", e))?;

    spinner.finish_and_clear();
    eprintln!("Plugin {plugin_id} removed.");

    Ok(())
}

async fn reset_password(user_id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;

    let id = parse_uuid(user_id, "user")?;

    let spinner = output::spinner("Resetting password...");

    let resp = client
        .reset_password()
        .id(id)
        .send()
        .await
        .map_err(|e| sdk_err("reset password", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", resp.temporary_password);
        return Ok(());
    }

    eprintln!("Password reset for user {user_id}.");
    eprintln!("Temporary password: {}", resp.temporary_password);
    eprintln!("(User will be prompted to change on first login.)");

    Ok(())
}

/// Format a list of backup entries as a table string.
fn format_backups_table(items: &[serde_json::Value]) -> String {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec!["ID", "STATUS", "TYPE", "ARTIFACTS", "SIZE", "CREATED"]);

    for b in items {
        let id = b["id"].as_str().unwrap_or("-");
        let id_short = if id.len() >= 8 { &id[..8] } else { id };
        table.add_row(vec![
            id_short,
            b["status"].as_str().unwrap_or("-"),
            b["type"].as_str().unwrap_or("-"),
            &b["artifacts"]
                .as_i64()
                .map(|n| n.to_string())
                .unwrap_or_else(|| "-".into()),
            b["size"].as_str().unwrap_or("-"),
            b["created_at"].as_str().unwrap_or("-"),
        ]);
    }

    table.to_string()
}

/// Format a list of user entries as a table string.
fn format_users_table(items: &[serde_json::Value]) -> String {
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

    for u in items {
        let id = u["id"].as_str().unwrap_or("-");
        let id_short = if id.len() >= 8 { &id[..8] } else { id };
        let admin = if u["is_admin"].as_bool().unwrap_or(false) {
            "yes"
        } else {
            "no"
        };
        let active = if u["is_active"].as_bool().unwrap_or(false) {
            "yes"
        } else {
            "no"
        };
        table.add_row(vec![
            id_short,
            u["username"].as_str().unwrap_or("-"),
            u["email"].as_str().unwrap_or("-"),
            u["display_name"].as_str().unwrap_or("-"),
            admin,
            active,
            u["auth_provider"].as_str().unwrap_or("-"),
        ]);
    }

    table.to_string()
}

/// Format a list of plugin entries as a table string.
fn format_plugins_table(items: &[serde_json::Value]) -> String {
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

    for p in items {
        table.add_row(vec![
            p["display_name"].as_str().unwrap_or("-"),
            p["version"].as_str().unwrap_or("-"),
            p["type"].as_str().unwrap_or("-"),
            p["status"].as_str().unwrap_or("-"),
            p["author"].as_str().unwrap_or("-"),
            p["installed_at"].as_str().unwrap_or("-"),
        ]);
    }

    table.to_string()
}

/// Format system metrics as a human-readable string.
fn format_metrics_display(info: &serde_json::Value) -> String {
    format!(
        "Artifacts:      {}\n\
         Downloads:      {}\n\
         Repositories:   {}\n\
         Storage:        {}\n\
         Users:          {}\n\
         Active Peers:   {}\n\
         Pending Syncs:  {}",
        info["total_artifacts"].as_i64().unwrap_or(0),
        info["total_downloads"].as_i64().unwrap_or(0),
        info["total_repositories"].as_i64().unwrap_or(0),
        info["total_storage"].as_str().unwrap_or("0 B"),
        info["total_users"].as_i64().unwrap_or(0),
        info["active_peers"].as_i64().unwrap_or(0),
        info["pending_sync_tasks"].as_i64().unwrap_or(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use serde_json::json;

    // ---- TestCli wrapper for parsing ----

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: AdminCommand,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).unwrap()
    }

    fn try_parse(args: &[&str]) -> Result<TestCli, clap::Error> {
        TestCli::try_parse_from(args)
    }

    // ---- Backup subcommand parsing ----

    #[test]
    fn parse_backup_list() {
        let cli = parse(&["test", "backup", "list"]);
        assert!(matches!(
            cli.command,
            AdminCommand::Backup {
                command: BackupCommand::List { .. }
            }
        ));
    }

    #[test]
    fn parse_backup_list_defaults() {
        let cli = parse(&["test", "backup", "list"]);
        if let AdminCommand::Backup {
            command: BackupCommand::List { page, per_page },
        } = cli.command
        {
            assert_eq!(page, 1);
            assert_eq!(per_page, 20);
        } else {
            panic!("Expected BackupCommand::List");
        }
    }

    #[test]
    fn parse_backup_list_custom_page() {
        let cli = parse(&["test", "backup", "list", "--page", "3", "--per-page", "10"]);
        if let AdminCommand::Backup {
            command: BackupCommand::List { page, per_page },
        } = cli.command
        {
            assert_eq!(page, 3);
            assert_eq!(per_page, 10);
        } else {
            panic!("Expected BackupCommand::List");
        }
    }

    #[test]
    fn parse_backup_create() {
        let cli = parse(&["test", "backup", "create"]);
        if let AdminCommand::Backup {
            command: BackupCommand::Create { r#type },
        } = cli.command
        {
            assert_eq!(r#type, "full");
        } else {
            panic!("Expected BackupCommand::Create");
        }
    }

    #[test]
    fn parse_backup_create_incremental() {
        let cli = parse(&["test", "backup", "create", "--type", "incremental"]);
        if let AdminCommand::Backup {
            command: BackupCommand::Create { r#type },
        } = cli.command
        {
            assert_eq!(r#type, "incremental");
        } else {
            panic!("Expected BackupCommand::Create");
        }
    }

    #[test]
    fn parse_backup_restore() {
        let cli = parse(&["test", "backup", "restore", "abc123"]);
        if let AdminCommand::Backup {
            command:
                BackupCommand::Restore {
                    id,
                    database,
                    artifacts,
                },
        } = cli.command
        {
            assert_eq!(id, "abc123");
            assert!(!database);
            assert!(!artifacts);
        } else {
            panic!("Expected BackupCommand::Restore");
        }
    }

    #[test]
    fn parse_backup_restore_with_flags() {
        let cli = parse(&[
            "test",
            "backup",
            "restore",
            "abc123",
            "--database",
            "--artifacts",
        ]);
        if let AdminCommand::Backup {
            command:
                BackupCommand::Restore {
                    id,
                    database,
                    artifacts,
                },
        } = cli.command
        {
            assert_eq!(id, "abc123");
            assert!(database);
            assert!(artifacts);
        } else {
            panic!("Expected BackupCommand::Restore");
        }
    }

    #[test]
    fn parse_backup_restore_missing_id_fails() {
        assert!(try_parse(&["test", "backup", "restore"]).is_err());
    }

    // ---- Cleanup subcommand parsing ----

    #[test]
    fn parse_cleanup_no_flags() {
        let cli = parse(&["test", "cleanup"]);
        if let AdminCommand::Cleanup {
            audit_logs,
            old_backups,
            stale_peers,
        } = cli.command
        {
            assert!(!audit_logs);
            assert!(!old_backups);
            assert!(!stale_peers);
        } else {
            panic!("Expected AdminCommand::Cleanup");
        }
    }

    #[test]
    fn parse_cleanup_all_flags() {
        let cli = parse(&[
            "test",
            "cleanup",
            "--audit-logs",
            "--old-backups",
            "--stale-peers",
        ]);
        if let AdminCommand::Cleanup {
            audit_logs,
            old_backups,
            stale_peers,
        } = cli.command
        {
            assert!(audit_logs);
            assert!(old_backups);
            assert!(stale_peers);
        } else {
            panic!("Expected AdminCommand::Cleanup");
        }
    }

    #[test]
    fn parse_cleanup_partial_flags() {
        let cli = parse(&["test", "cleanup", "--audit-logs"]);
        if let AdminCommand::Cleanup {
            audit_logs,
            old_backups,
            stale_peers,
        } = cli.command
        {
            assert!(audit_logs);
            assert!(!old_backups);
            assert!(!stale_peers);
        } else {
            panic!("Expected AdminCommand::Cleanup");
        }
    }

    // ---- Metrics subcommand parsing ----

    #[test]
    fn parse_metrics() {
        let cli = parse(&["test", "metrics"]);
        assert!(matches!(cli.command, AdminCommand::Metrics));
    }

    // ---- Users subcommand parsing ----

    #[test]
    fn parse_users_list() {
        let cli = parse(&["test", "users", "list"]);
        assert!(matches!(
            cli.command,
            AdminCommand::Users {
                command: UsersCommand::List { .. }
            }
        ));
    }

    #[test]
    fn parse_users_list_defaults() {
        let cli = parse(&["test", "users", "list"]);
        if let AdminCommand::Users {
            command:
                UsersCommand::List {
                    search,
                    page,
                    per_page,
                },
        } = cli.command
        {
            assert!(search.is_none());
            assert_eq!(page, 1);
            assert_eq!(per_page, 20);
        } else {
            panic!("Expected UsersCommand::List");
        }
    }

    #[test]
    fn parse_users_list_with_search() {
        let cli = parse(&["test", "users", "list", "--search", "alice"]);
        if let AdminCommand::Users {
            command: UsersCommand::List { search, .. },
        } = cli.command
        {
            assert_eq!(search.as_deref(), Some("alice"));
        } else {
            panic!("Expected UsersCommand::List");
        }
    }

    #[test]
    fn parse_users_create() {
        let cli = parse(&[
            "test",
            "users",
            "create",
            "alice",
            "--email",
            "alice@example.com",
        ]);
        if let AdminCommand::Users {
            command:
                UsersCommand::Create {
                    username,
                    email,
                    display_name,
                    admin,
                },
        } = cli.command
        {
            assert_eq!(username, "alice");
            assert_eq!(email, "alice@example.com");
            assert!(display_name.is_none());
            assert!(!admin);
        } else {
            panic!("Expected UsersCommand::Create");
        }
    }

    #[test]
    fn parse_users_create_with_all_options() {
        let cli = parse(&[
            "test",
            "users",
            "create",
            "alice",
            "--email",
            "alice@example.com",
            "--display-name",
            "Alice Smith",
            "--admin",
        ]);
        if let AdminCommand::Users {
            command:
                UsersCommand::Create {
                    username,
                    email,
                    display_name,
                    admin,
                },
        } = cli.command
        {
            assert_eq!(username, "alice");
            assert_eq!(email, "alice@example.com");
            assert_eq!(display_name.as_deref(), Some("Alice Smith"));
            assert!(admin);
        } else {
            panic!("Expected UsersCommand::Create");
        }
    }

    #[test]
    fn parse_users_create_missing_email_fails() {
        assert!(try_parse(&["test", "users", "create", "alice"]).is_err());
    }

    #[test]
    fn parse_users_create_missing_username_fails() {
        assert!(try_parse(&["test", "users", "create", "--email", "a@b.com"]).is_err());
    }

    #[test]
    fn parse_users_update() {
        let cli = parse(&[
            "test",
            "users",
            "update",
            "some-id",
            "--email",
            "new@example.com",
        ]);
        if let AdminCommand::Users {
            command:
                UsersCommand::Update {
                    id,
                    email,
                    display_name,
                    admin,
                    active,
                },
        } = cli.command
        {
            assert_eq!(id, "some-id");
            assert_eq!(email.as_deref(), Some("new@example.com"));
            assert!(display_name.is_none());
            assert!(admin.is_none());
            assert!(active.is_none());
        } else {
            panic!("Expected UsersCommand::Update");
        }
    }

    #[test]
    fn parse_users_update_all_options() {
        let cli = parse(&[
            "test",
            "users",
            "update",
            "user-id",
            "--email",
            "new@test.com",
            "--display-name",
            "New Name",
            "--admin",
            "true",
            "--active",
            "false",
        ]);
        if let AdminCommand::Users {
            command:
                UsersCommand::Update {
                    id,
                    email,
                    display_name,
                    admin,
                    active,
                },
        } = cli.command
        {
            assert_eq!(id, "user-id");
            assert_eq!(email.as_deref(), Some("new@test.com"));
            assert_eq!(display_name.as_deref(), Some("New Name"));
            assert_eq!(admin, Some(true));
            assert_eq!(active, Some(false));
        } else {
            panic!("Expected UsersCommand::Update");
        }
    }

    #[test]
    fn parse_users_update_missing_id_fails() {
        assert!(try_parse(&["test", "users", "update"]).is_err());
    }

    #[test]
    fn parse_users_delete() {
        let cli = parse(&["test", "users", "delete", "user-id"]);
        if let AdminCommand::Users {
            command: UsersCommand::Delete { id, yes },
        } = cli.command
        {
            assert_eq!(id, "user-id");
            assert!(!yes);
        } else {
            panic!("Expected UsersCommand::Delete");
        }
    }

    #[test]
    fn parse_users_delete_with_yes() {
        let cli = parse(&["test", "users", "delete", "user-id", "--yes"]);
        if let AdminCommand::Users {
            command: UsersCommand::Delete { id, yes },
        } = cli.command
        {
            assert_eq!(id, "user-id");
            assert!(yes);
        } else {
            panic!("Expected UsersCommand::Delete");
        }
    }

    #[test]
    fn parse_users_reset_password() {
        let cli = parse(&["test", "users", "reset-password", "user-id"]);
        if let AdminCommand::Users {
            command: UsersCommand::ResetPassword { id },
        } = cli.command
        {
            assert_eq!(id, "user-id");
        } else {
            panic!("Expected UsersCommand::ResetPassword");
        }
    }

    #[test]
    fn parse_users_reset_password_missing_id_fails() {
        assert!(try_parse(&["test", "users", "reset-password"]).is_err());
    }

    // ---- Plugins subcommand parsing ----

    #[test]
    fn parse_plugins_list() {
        let cli = parse(&["test", "plugins", "list"]);
        assert!(matches!(
            cli.command,
            AdminCommand::Plugins {
                command: PluginsCommand::List
            }
        ));
    }

    #[test]
    fn parse_plugins_install() {
        let cli = parse(&[
            "test",
            "plugins",
            "install",
            "https://github.com/example/plugin.git",
        ]);
        if let AdminCommand::Plugins {
            command: PluginsCommand::Install { url, r#ref },
        } = cli.command
        {
            assert_eq!(url, "https://github.com/example/plugin.git");
            assert!(r#ref.is_none());
        } else {
            panic!("Expected PluginsCommand::Install");
        }
    }

    #[test]
    fn parse_plugins_install_with_ref() {
        let cli = parse(&[
            "test",
            "plugins",
            "install",
            "https://github.com/example/plugin.git",
            "--ref",
            "v1.0.0",
        ]);
        if let AdminCommand::Plugins {
            command: PluginsCommand::Install { url, r#ref },
        } = cli.command
        {
            assert_eq!(url, "https://github.com/example/plugin.git");
            assert_eq!(r#ref.as_deref(), Some("v1.0.0"));
        } else {
            panic!("Expected PluginsCommand::Install");
        }
    }

    #[test]
    fn parse_plugins_install_missing_url_fails() {
        assert!(try_parse(&["test", "plugins", "install"]).is_err());
    }

    #[test]
    fn parse_plugins_remove() {
        let cli = parse(&["test", "plugins", "remove", "plugin-id"]);
        if let AdminCommand::Plugins {
            command: PluginsCommand::Remove { id, yes },
        } = cli.command
        {
            assert_eq!(id, "plugin-id");
            assert!(!yes);
        } else {
            panic!("Expected PluginsCommand::Remove");
        }
    }

    #[test]
    fn parse_plugins_remove_with_yes() {
        let cli = parse(&["test", "plugins", "remove", "plugin-id", "--yes"]);
        if let AdminCommand::Plugins {
            command: PluginsCommand::Remove { id, yes },
        } = cli.command
        {
            assert_eq!(id, "plugin-id");
            assert!(yes);
        } else {
            panic!("Expected PluginsCommand::Remove");
        }
    }

    #[test]
    fn parse_plugins_remove_missing_id_fails() {
        assert!(try_parse(&["test", "plugins", "remove"]).is_err());
    }

    // ---- Missing subcommand fails ----

    #[test]
    fn parse_no_subcommand_fails() {
        assert!(try_parse(&["test"]).is_err());
    }

    #[test]
    fn parse_backup_no_subcommand_fails() {
        assert!(try_parse(&["test", "backup"]).is_err());
    }

    #[test]
    fn parse_users_no_subcommand_fails() {
        assert!(try_parse(&["test", "users"]).is_err());
    }

    #[test]
    fn parse_plugins_no_subcommand_fails() {
        assert!(try_parse(&["test", "plugins"]).is_err());
    }

    // ---- Format function tests ----

    #[test]
    fn format_backups_table_renders() {
        let items = vec![json!({
            "id": "12345678-abcd-1234-abcd-123456789012",
            "status": "completed",
            "type": "full",
            "artifacts": 42,
            "size": "1.5 GB",
            "created_at": "2026-01-15T10:30:00Z",
        })];
        let table = format_backups_table(&items);
        assert!(table.contains("12345678"));
        assert!(table.contains("completed"));
        assert!(table.contains("full"));
        assert!(table.contains("42"));
        assert!(table.contains("1.5 GB"));
    }

    #[test]
    fn format_backups_table_empty() {
        let items: Vec<serde_json::Value> = vec![];
        let table = format_backups_table(&items);
        // Should still contain headers
        assert!(table.contains("ID"));
        assert!(table.contains("STATUS"));
    }

    #[test]
    fn format_backups_table_multiple_rows() {
        let items = vec![
            json!({
                "id": "aaaa1111-bbbb-2222-cccc-333344445555",
                "status": "completed",
                "type": "full",
                "artifacts": 10,
                "size": "500.0 MB",
                "created_at": "2026-01-01",
            }),
            json!({
                "id": "bbbb2222-cccc-3333-dddd-444455556666",
                "status": "in_progress",
                "type": "incremental",
                "artifacts": 5,
                "size": "200.0 MB",
                "created_at": "2026-01-02",
            }),
        ];
        let table = format_backups_table(&items);
        assert!(table.contains("aaaa1111"));
        assert!(table.contains("bbbb2222"));
        assert!(table.contains("completed"));
        assert!(table.contains("in_progress"));
    }

    #[test]
    fn format_users_table_renders() {
        let items = vec![json!({
            "id": "12345678-abcd-1234-abcd-123456789012",
            "username": "alice",
            "email": "alice@example.com",
            "display_name": "Alice Smith",
            "is_admin": true,
            "is_active": true,
            "auth_provider": "local",
        })];
        let table = format_users_table(&items);
        assert!(table.contains("12345678"));
        assert!(table.contains("alice"));
        assert!(table.contains("alice@example.com"));
        assert!(table.contains("Alice Smith"));
        assert!(table.contains("yes"));
        assert!(table.contains("local"));
    }

    #[test]
    fn format_users_table_non_admin_inactive() {
        let items = vec![json!({
            "id": "12345678-0000-0000-0000-000000000000",
            "username": "bob",
            "email": "bob@example.com",
            "is_admin": false,
            "is_active": false,
            "auth_provider": "ldap",
        })];
        let table = format_users_table(&items);
        assert!(table.contains("bob"));
        // Should contain "no" for both admin and active
        let no_count = table.matches("no").count();
        assert!(no_count >= 2);
    }

    #[test]
    fn format_users_table_empty() {
        let items: Vec<serde_json::Value> = vec![];
        let table = format_users_table(&items);
        assert!(table.contains("USERNAME"));
        assert!(table.contains("EMAIL"));
    }

    #[test]
    fn format_plugins_table_renders() {
        let items = vec![json!({
            "display_name": "Unity Format",
            "version": "1.0.0",
            "type": "format",
            "status": "active",
            "author": "AK Team",
            "installed_at": "2026-01-15",
        })];
        let table = format_plugins_table(&items);
        assert!(table.contains("Unity Format"));
        assert!(table.contains("1.0.0"));
        assert!(table.contains("format"));
        assert!(table.contains("active"));
        assert!(table.contains("AK Team"));
    }

    #[test]
    fn format_plugins_table_missing_author() {
        let items = vec![json!({
            "display_name": "Custom Plugin",
            "version": "0.1.0",
            "type": "format",
            "status": "active",
        })];
        let table = format_plugins_table(&items);
        assert!(table.contains("Custom Plugin"));
        assert!(table.contains("0.1.0"));
    }

    #[test]
    fn format_plugins_table_empty() {
        let items: Vec<serde_json::Value> = vec![];
        let table = format_plugins_table(&items);
        assert!(table.contains("NAME"));
        assert!(table.contains("VERSION"));
    }

    #[test]
    fn format_metrics_display_renders() {
        let info = json!({
            "total_artifacts": 1500,
            "total_downloads": 50000,
            "total_repositories": 25,
            "total_storage": "12.5 GB",
            "total_users": 100,
            "active_peers": 3,
            "pending_sync_tasks": 0,
        });
        let display = format_metrics_display(&info);
        assert!(display.contains("1500"));
        assert!(display.contains("50000"));
        assert!(display.contains("25"));
        assert!(display.contains("12.5 GB"));
        assert!(display.contains("100"));
        assert!(display.contains("Artifacts:"));
        assert!(display.contains("Downloads:"));
        assert!(display.contains("Repositories:"));
        assert!(display.contains("Storage:"));
        assert!(display.contains("Users:"));
        assert!(display.contains("Active Peers:"));
        assert!(display.contains("Pending Syncs:"));
    }

    #[test]
    fn format_metrics_display_zeros() {
        let info = json!({
            "total_artifacts": 0,
            "total_downloads": 0,
            "total_repositories": 0,
            "total_storage": "0 B",
            "total_users": 0,
            "active_peers": 0,
            "pending_sync_tasks": 0,
        });
        let display = format_metrics_display(&info);
        assert!(display.contains("Artifacts:      0"));
        assert!(display.contains("Downloads:      0"));
    }
}
