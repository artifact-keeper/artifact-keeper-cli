use artifact_keeper_sdk::{ClientAdminExt, ClientPluginsExt, ClientTelemetryExt, ClientUsersExt};
use clap::Subcommand;
use miette::Result;

use super::client::{client_for, resolve_base_url_and_auth};
use super::helpers::{confirm_action, emit_mutation, new_table, parse_uuid, sdk_err, short_id};
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

    /// Manage format handlers (core and WASM)
    Formats {
        #[command(subcommand)]
        command: FormatHandlerCommand,
    },

    /// Trigger search index rebuild
    Reindex,

    /// Show system statistics
    Stats,

    /// Manage server settings
    Settings {
        #[command(subcommand)]
        command: SettingsCommand,
    },

    /// Manage telemetry and crash reports
    Telemetry {
        #[command(subcommand)]
        command: TelemetryCommand,
    },

    /// Manage CI OIDC providers and identity mappings
    CiOidc {
        #[command(subcommand)]
        command: CiOidcCommand,
    },

    /// Run storage garbage collection and view storage reports
    StorageGc {
        #[command(subcommand)]
        command: StorageGcCommand,
    },

    /// List configured storage backends
    StorageBackends,

    /// Trigger an OpenSearch reindex of all artifacts and repositories
    SearchReindex,

    /// Rescan existing artifacts to enqueue inventory processing
    Rescan {
        /// Maximum number of artifacts to enqueue
        #[arg(long)]
        limit: Option<i64>,
    },

    /// Send a test email to verify SMTP configuration
    SmtpTest {
        /// Recipient email address
        to: String,
    },

    /// Manage remote instances and proxy requests to them
    Instance {
        #[command(subcommand)]
        command: RemoteInstanceCommand,
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
    /// Show a backup's details
    Get {
        /// Backup ID
        id: String,
    },
    /// Delete a backup
    Delete {
        /// Backup ID
        id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
    /// Cancel a running backup
    Cancel {
        /// Backup ID
        id: String,
    },
    /// Execute a pending backup
    Execute {
        /// Backup ID
        id: String,
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

    /// Show a single user by ID
    Show {
        /// User ID
        id: String,
    },

    /// Force a user to change their password on next login
    ForcePasswordChange {
        /// User ID
        id: String,
    },

    /// List the roles assigned to a user
    Roles {
        /// User ID
        id: String,
    },

    /// Assign or revoke a user's roles
    Role {
        #[command(subcommand)]
        command: RoleCommand,
    },

    /// Manage a user's API tokens (admin)
    Tokens {
        #[command(subcommand)]
        command: UserTokenCommand,
    },
}

#[derive(Subcommand)]
pub enum RoleCommand {
    /// Assign a role to a user
    Assign {
        /// User ID
        user: String,

        /// Role ID
        role: String,
    },

    /// Revoke a role from a user
    Revoke {
        /// User ID
        user: String,

        /// Role ID
        role: String,
    },
}

#[derive(Subcommand)]
pub enum UserTokenCommand {
    /// List a user's API tokens
    List {
        /// User ID
        user: String,
    },

    /// Create an API token for a user
    Create {
        /// User ID
        user: String,

        /// Token name
        name: String,

        /// Comma-separated scopes (e.g. read,write)
        #[arg(long)]
        scopes: Option<String>,

        /// Number of days until the token expires
        #[arg(long)]
        expires_in_days: Option<i64>,
    },

    /// Revoke a user's API token
    Revoke {
        /// User ID
        user: String,

        /// Token ID
        token_id: String,
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
    /// Show details for a single plugin
    Show {
        /// Plugin ID
        id: String,
    },
    /// Manage plugin configuration
    Config {
        #[command(subcommand)]
        command: PluginConfigCommand,
    },
    /// Enable a plugin
    Enable {
        /// Plugin ID
        id: String,
    },
    /// Disable a plugin
    Disable {
        /// Plugin ID
        id: String,
    },
    /// Reload a plugin (hot-reload)
    Reload {
        /// Plugin ID
        id: String,
    },
    /// Show recent lifecycle events for a plugin
    Events {
        /// Plugin ID
        id: String,

        /// Maximum number of events to return
        #[arg(long)]
        limit: Option<i64>,
    },
    /// Install a plugin from a local filesystem path (development use only)
    InstallLocal {
        /// Local filesystem path to the plugin directory
        path: String,
    },
    /// Install a plugin from a ZIP package
    InstallZip {
        /// Path to the plugin ZIP file
        path: String,
    },
}

#[derive(Subcommand)]
pub enum PluginConfigCommand {
    /// Get the current configuration for a plugin
    Get {
        /// Plugin ID
        id: String,
    },
    /// Update a plugin's configuration
    Set {
        /// Plugin ID
        id: String,

        /// Configuration entries as key=value pairs (values parsed as JSON,
        /// falling back to a string literal)
        #[arg(value_name = "KEY=VALUE")]
        values: Vec<String>,

        /// Load the full configuration object from a JSON file (merged under
        /// any key=value pairs, which take precedence)
        #[arg(long, value_name = "PATH")]
        config_file: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum FormatHandlerCommand {
    /// List format handlers
    List {
        /// Filter by handler type (Core or Wasm)
        #[arg(long)]
        r#type: Option<String>,

        /// Filter by enabled state
        #[arg(long)]
        enabled: Option<bool>,
    },

    /// Show a format handler by key
    Show {
        /// Format handler key (e.g. maven, npm, docker)
        name: String,
    },

    /// Enable a format handler
    Enable {
        /// Format handler key
        name: String,
    },

    /// Disable a format handler
    Disable {
        /// Format handler key
        name: String,
    },

    /// Test a format handler against sample content
    Test {
        /// Format handler key
        name: String,

        /// Path to a sample file whose contents are tested (base64-encoded)
        #[arg(long)]
        sample: Option<String>,

        /// Raw string content to test (alternative to --sample)
        #[arg(long, conflicts_with = "sample")]
        content: Option<String>,

        /// Path to simulate for the artifact (defaults to the sample file name)
        #[arg(long)]
        path: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum SettingsCommand {
    /// Show current server settings
    Show,
    /// Update server settings (provide JSON body)
    Update {
        /// Settings JSON
        #[arg(long)]
        json: String,
    },
}

#[derive(Subcommand)]
pub enum TelemetryCommand {
    /// Show telemetry settings
    Show,
    /// Update telemetry settings
    Update {
        /// Enable or disable telemetry
        #[arg(long)]
        enabled: Option<bool>,

        /// Include logs in telemetry data
        #[arg(long)]
        include_logs: Option<bool>,

        /// Review telemetry data before sending
        #[arg(long)]
        review_before_send: Option<bool>,

        /// Scrub level for sensitive data
        #[arg(long)]
        scrub_level: Option<String>,
    },
    /// List crash reports
    Crashes {
        /// Show only pending (unsubmitted) crash reports
        #[arg(long)]
        pending: bool,

        /// Page number
        #[arg(long, default_value = "1")]
        page: i32,

        /// Results per page
        #[arg(long, default_value = "20")]
        per_page: i32,
    },
    /// Submit crash reports
    Submit {
        /// Crash report IDs (comma-separated)
        ids: String,
    },
    /// Show a single crash report
    Crash {
        /// Crash report ID
        id: String,
    },
    /// Delete a crash report
    DeleteCrash {
        /// Crash report ID
        id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
pub enum CiOidcCommand {
    /// List CI OIDC providers
    List,
    /// Create a CI OIDC provider
    Create {
        /// Provider name
        name: String,

        /// OIDC issuer URL
        issuer_url: String,

        /// Expected audience claim
        #[arg(long)]
        audience: Option<String>,

        /// Provider type (e.g. github, gitlab)
        #[arg(long)]
        provider_type: Option<String>,

        /// Enable the provider on creation
        #[arg(long)]
        enabled: bool,
    },
    /// Show a CI OIDC provider
    Get {
        /// Provider ID
        id: String,
    },
    /// Update a CI OIDC provider
    Update {
        /// Provider ID
        id: String,

        /// New provider name
        #[arg(long)]
        name: Option<String>,

        /// New issuer URL
        #[arg(long)]
        issuer_url: Option<String>,

        /// New expected audience claim
        #[arg(long)]
        audience: Option<String>,

        /// New provider type
        #[arg(long)]
        provider_type: Option<String>,

        /// Set enabled state
        #[arg(long)]
        enabled: Option<bool>,
    },
    /// Delete a CI OIDC provider
    Delete {
        /// Provider ID
        id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
    /// Enable or disable a CI OIDC provider
    Toggle {
        /// Provider ID
        id: String,

        /// Enabled state to set (true/false)
        #[arg(long, action = clap::ArgAction::Set)]
        enabled: bool,
    },
    /// Manage identity mappings for a provider
    Mapping {
        #[command(subcommand)]
        command: CiOidcMappingCommand,
    },
}

#[derive(Subcommand)]
pub enum CiOidcMappingCommand {
    /// List identity mappings for a provider
    List {
        /// Provider ID
        provider_id: String,
    },
    /// Create an identity mapping
    Create {
        /// Provider ID
        provider_id: String,

        /// Mapping name
        name: String,

        /// Claim filters as a JSON object
        #[arg(long, default_value = "{}")]
        claim_filters: String,

        /// Match priority (lower runs first)
        #[arg(long)]
        priority: Option<i32>,

        /// Comma-separated repository UUIDs the mapping grants access to
        #[arg(long)]
        allowed_repo_ids: Option<String>,

        /// Enable the mapping on creation
        #[arg(long)]
        enabled: bool,
    },
    /// Show an identity mapping
    Get {
        /// Provider ID
        provider_id: String,

        /// Mapping ID
        mapping_id: String,
    },
    /// Update an identity mapping
    Update {
        /// Provider ID
        provider_id: String,

        /// Mapping ID
        mapping_id: String,

        /// New mapping name
        #[arg(long)]
        name: Option<String>,

        /// New claim filters as a JSON object
        #[arg(long)]
        claim_filters: Option<String>,

        /// New match priority
        #[arg(long)]
        priority: Option<i32>,

        /// New comma-separated repository UUIDs
        #[arg(long)]
        allowed_repo_ids: Option<String>,

        /// Set enabled state
        #[arg(long)]
        enabled: Option<bool>,
    },
    /// Delete an identity mapping
    Delete {
        /// Provider ID
        provider_id: String,

        /// Mapping ID
        mapping_id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
    /// Enable or disable an identity mapping
    Toggle {
        /// Provider ID
        provider_id: String,

        /// Mapping ID
        mapping_id: String,

        /// Enabled state to set (true/false)
        #[arg(long, action = clap::ArgAction::Set)]
        enabled: bool,
    },
}

#[derive(Subcommand)]
pub enum StorageGcCommand {
    /// Run the storage garbage collector
    Run {
        /// Report what would be removed without deleting anything
        #[arg(long)]
        dry_run: bool,
    },
    /// Show the OCI blob storage footprint report
    OciReport {
        /// Grace window in hours used to compute aged figures
        #[arg(long)]
        grace_hours: Option<i64>,
    },
}

#[derive(Subcommand)]
pub enum RemoteInstanceCommand {
    /// List remote instances
    List,
    /// Register a new remote instance
    Create {
        /// Instance name
        name: String,

        /// Instance base URL
        url: String,

        /// API key for the remote instance
        #[arg(long)]
        api_key: String,
    },
    /// Delete a remote instance
    Delete {
        /// Remote instance ID
        id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
    /// Proxy a request through a remote instance
    Proxy {
        #[command(subcommand)]
        command: ProxyCommand,
    },
}

#[derive(Subcommand)]
pub enum ProxyCommand {
    /// Proxy a GET request
    Get {
        /// Remote instance ID
        id: String,

        /// Sub-path to proxy
        path: String,
    },
    /// Proxy a PUT request
    Put {
        /// Remote instance ID
        id: String,

        /// Sub-path to proxy
        path: String,

        /// Request body
        #[arg(long)]
        body: Option<String>,
    },
    /// Proxy a POST request
    Post {
        /// Remote instance ID
        id: String,

        /// Sub-path to proxy
        path: String,

        /// Request body
        #[arg(long)]
        body: Option<String>,
    },
    /// Proxy a DELETE request
    Delete {
        /// Remote instance ID
        id: String,

        /// Sub-path to proxy
        path: String,
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
                BackupCommand::Get { id } => get_backup(&id, global).await,
                BackupCommand::Delete { id, yes } => delete_backup(&id, yes, global).await,
                BackupCommand::Cancel { id } => cancel_backup(&id, global).await,
                BackupCommand::Execute { id } => execute_backup(&id, global).await,
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
                UsersCommand::Show { id } => show_user(&id, global).await,
                UsersCommand::ForcePasswordChange { id } => {
                    force_password_change(&id, global).await
                }
                UsersCommand::Roles { id } => list_user_roles(&id, global).await,
                UsersCommand::Role { command } => match command {
                    RoleCommand::Assign { user, role } => assign_role(&user, &role, global).await,
                    RoleCommand::Revoke { user, role } => revoke_role(&user, &role, global).await,
                },
                UsersCommand::Tokens { command } => match command {
                    UserTokenCommand::List { user } => list_user_tokens(&user, global).await,
                    UserTokenCommand::Create {
                        user,
                        name,
                        scopes,
                        expires_in_days,
                    } => {
                        create_user_token(&user, &name, scopes.as_deref(), expires_in_days, global)
                            .await
                    }
                    UserTokenCommand::Revoke { user, token_id } => {
                        revoke_user_token(&user, &token_id, global).await
                    }
                },
            },
            Self::Plugins { command } => match command {
                PluginsCommand::List => list_plugins(global).await,
                PluginsCommand::Install { url, r#ref } => {
                    install_plugin(&url, r#ref.as_deref(), global).await
                }
                PluginsCommand::Remove { id, yes } => remove_plugin(&id, yes, global).await,
                PluginsCommand::Show { id } => show_plugin(&id, global).await,
                PluginsCommand::Config { command } => match command {
                    PluginConfigCommand::Get { id } => get_plugin_config(&id, global).await,
                    PluginConfigCommand::Set {
                        id,
                        values,
                        config_file,
                    } => set_plugin_config(&id, &values, config_file.as_deref(), global).await,
                },
                PluginsCommand::Enable { id } => set_plugin_enabled(&id, true, global).await,
                PluginsCommand::Disable { id } => set_plugin_enabled(&id, false, global).await,
                PluginsCommand::Reload { id } => reload_plugin(&id, global).await,
                PluginsCommand::Events { id, limit } => plugin_events(&id, limit, global).await,
                PluginsCommand::InstallLocal { path } => install_plugin_local(&path, global).await,
                PluginsCommand::InstallZip { path } => install_plugin_zip(&path, global).await,
            },
            Self::Formats { command } => match command {
                FormatHandlerCommand::List { r#type, enabled } => {
                    list_format_handlers(r#type.as_deref(), enabled, global).await
                }
                FormatHandlerCommand::Show { name } => show_format_handler(&name, global).await,
                FormatHandlerCommand::Enable { name } => {
                    set_format_handler_enabled(&name, true, global).await
                }
                FormatHandlerCommand::Disable { name } => {
                    set_format_handler_enabled(&name, false, global).await
                }
                FormatHandlerCommand::Test {
                    name,
                    sample,
                    content,
                    path,
                } => {
                    test_format_handler(
                        &name,
                        sample.as_deref(),
                        content.as_deref(),
                        path.as_deref(),
                        global,
                    )
                    .await
                }
            },
            Self::Reindex => trigger_reindex(global).await,
            Self::Stats => show_stats(global).await,
            Self::Settings { command } => match command {
                SettingsCommand::Show => show_settings(global).await,
                SettingsCommand::Update { json } => update_settings(&json, global).await,
            },
            Self::Telemetry { command } => match command {
                TelemetryCommand::Show => show_telemetry(global).await,
                TelemetryCommand::Update {
                    enabled,
                    include_logs,
                    review_before_send,
                    scrub_level,
                } => {
                    update_telemetry(
                        enabled,
                        include_logs,
                        review_before_send,
                        scrub_level,
                        global,
                    )
                    .await
                }
                TelemetryCommand::Crashes {
                    pending,
                    page,
                    per_page,
                } => list_crashes(pending, page, per_page, global).await,
                TelemetryCommand::Submit { ids } => submit_crashes(&ids, global).await,
                TelemetryCommand::Crash { id } => get_crash(&id, global).await,
                TelemetryCommand::DeleteCrash { id, yes } => delete_crash(&id, yes, global).await,
            },
            Self::CiOidc { command } => match command {
                CiOidcCommand::List => list_ci_oidc_providers(global).await,
                CiOidcCommand::Create {
                    name,
                    issuer_url,
                    audience,
                    provider_type,
                    enabled,
                } => {
                    create_ci_oidc_provider(
                        &name,
                        &issuer_url,
                        audience.as_deref(),
                        provider_type.as_deref(),
                        enabled,
                        global,
                    )
                    .await
                }
                CiOidcCommand::Get { id } => get_ci_oidc_provider(&id, global).await,
                CiOidcCommand::Update {
                    id,
                    name,
                    issuer_url,
                    audience,
                    provider_type,
                    enabled,
                } => {
                    update_ci_oidc_provider(
                        &id,
                        name.as_deref(),
                        issuer_url.as_deref(),
                        audience.as_deref(),
                        provider_type.as_deref(),
                        enabled,
                        global,
                    )
                    .await
                }
                CiOidcCommand::Delete { id, yes } => {
                    delete_ci_oidc_provider(&id, yes, global).await
                }
                CiOidcCommand::Toggle { id, enabled } => {
                    toggle_ci_oidc_provider(&id, enabled, global).await
                }
                CiOidcCommand::Mapping { command } => match command {
                    CiOidcMappingCommand::List { provider_id } => {
                        list_ci_oidc_mappings(&provider_id, global).await
                    }
                    CiOidcMappingCommand::Create {
                        provider_id,
                        name,
                        claim_filters,
                        priority,
                        allowed_repo_ids,
                        enabled,
                    } => {
                        create_ci_oidc_mapping(
                            &provider_id,
                            &name,
                            &claim_filters,
                            priority,
                            allowed_repo_ids.as_deref(),
                            enabled,
                            global,
                        )
                        .await
                    }
                    CiOidcMappingCommand::Get {
                        provider_id,
                        mapping_id,
                    } => get_ci_oidc_mapping(&provider_id, &mapping_id, global).await,
                    CiOidcMappingCommand::Update {
                        provider_id,
                        mapping_id,
                        name,
                        claim_filters,
                        priority,
                        allowed_repo_ids,
                        enabled,
                    } => {
                        update_ci_oidc_mapping(
                            &provider_id,
                            &mapping_id,
                            name.as_deref(),
                            claim_filters.as_deref(),
                            priority,
                            allowed_repo_ids.as_deref(),
                            enabled,
                            global,
                        )
                        .await
                    }
                    CiOidcMappingCommand::Delete {
                        provider_id,
                        mapping_id,
                        yes,
                    } => delete_ci_oidc_mapping(&provider_id, &mapping_id, yes, global).await,
                    CiOidcMappingCommand::Toggle {
                        provider_id,
                        mapping_id,
                        enabled,
                    } => toggle_ci_oidc_mapping(&provider_id, &mapping_id, enabled, global).await,
                },
            },
            Self::StorageGc { command } => match command {
                StorageGcCommand::Run { dry_run } => run_storage_gc(dry_run, global).await,
                StorageGcCommand::OciReport { grace_hours } => {
                    oci_blob_report(grace_hours, global).await
                }
            },
            Self::StorageBackends => list_storage_backends(global).await,
            Self::SearchReindex => trigger_search_reindex(global).await,
            Self::Rescan { limit } => rescan_for_inventory(limit, global).await,
            Self::SmtpTest { to } => send_test_email(&to, global).await,
            Self::Instance { command } => match command {
                RemoteInstanceCommand::List => list_instances(global).await,
                RemoteInstanceCommand::Create { name, url, api_key } => {
                    create_instance(&name, &url, &api_key, global).await
                }
                RemoteInstanceCommand::Delete { id, yes } => {
                    delete_instance(&id, yes, global).await
                }
                RemoteInstanceCommand::Proxy { command } => match command {
                    ProxyCommand::Get { id, path } => {
                        proxy_request(&id, "GET", &path, None, global).await
                    }
                    ProxyCommand::Put { id, path, body } => {
                        proxy_request(&id, "PUT", &path, body, global).await
                    }
                    ProxyCommand::Post { id, path, body } => {
                        proxy_request(&id, "POST", &path, body, global).await
                    }
                    ProxyCommand::Delete { id, path } => {
                        proxy_request(&id, "DELETE", &path, None, global).await
                    }
                },
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
        cleanup_stale_uploads: None,
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

    emit_mutation(
        &*resp,
        &resp.user.id.to_string(),
        &format!(
            "User '{}' created (ID: {}).",
            resp.user.username, resp.user.id
        ),
        global,
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
    emit_mutation(
        &*user,
        &user.id.to_string(),
        &format!("User '{}' updated (ID: {}).", user.username, user.id),
        global,
    );

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
    emit_mutation(
        &serde_json::json!({ "id": user_id, "status": "deleted" }),
        user_id,
        &format!("User {user_id} deleted."),
        global,
    );

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
    emit_mutation(
        &serde_json::json!({ "id": plugin_id, "status": "removed" }),
        plugin_id,
        &format!("Plugin {plugin_id} removed."),
        global,
    );

    Ok(())
}

/// Build a JSON representation of a format handler for structured output.
fn format_handler_json(h: &artifact_keeper_sdk::types::FormatHandlerResponse) -> serde_json::Value {
    serde_json::json!({
        "id": h.id.to_string(),
        "format_key": h.format_key,
        "handler_type": h.handler_type.to_string(),
        "display_name": h.display_name,
        "description": h.description,
        "extensions": h.extensions,
        "is_enabled": h.is_enabled,
        "priority": h.priority,
        "plugin_id": h.plugin_id.map(|p| p.to_string()),
        "repository_count": h.repository_count,
        "capabilities": h.capabilities,
        "created_at": h.created_at.to_rfc3339(),
        "updated_at": h.updated_at.to_rfc3339(),
    })
}

/// Render a single format handler as a key/value detail block.
fn format_handler_detail_table(h: &artifact_keeper_sdk::types::FormatHandlerResponse) -> String {
    let description = h.description.as_deref().unwrap_or("-");
    let extensions = if h.extensions.is_empty() {
        "-".to_string()
    } else {
        h.extensions.join(", ")
    };
    let plugin_id = h
        .plugin_id
        .map(|p| p.to_string())
        .unwrap_or_else(|| "-".to_string());
    let repos = h
        .repository_count
        .map(|c| c.to_string())
        .unwrap_or_else(|| "-".to_string());
    format!(
        "ID:            {}\n\
         Key:           {}\n\
         Display Name:  {}\n\
         Type:          {}\n\
         Description:   {}\n\
         Extensions:    {}\n\
         Enabled:       {}\n\
         Priority:      {}\n\
         Plugin ID:     {}\n\
         Repositories:  {}\n\
         Created:       {}\n\
         Updated:       {}",
        h.id,
        h.format_key,
        h.display_name,
        h.handler_type,
        description,
        extensions,
        if h.is_enabled { "yes" } else { "no" },
        h.priority,
        plugin_id,
        repos,
        h.created_at.to_rfc3339(),
        h.updated_at.to_rfc3339(),
    )
}

async fn list_format_handlers(
    handler_type: Option<&str>,
    enabled: Option<bool>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching format handlers...");

    let mut req = client.list_format_handlers();
    if let Some(t) = handler_type {
        req = req.type_(t);
    }
    if let Some(e) = enabled {
        req = req.enabled(e);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| sdk_err("list format handlers", e))?;
    let handlers = resp.into_inner();
    spinner.finish_and_clear();

    if handlers.is_empty() {
        eprintln!("No format handlers found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for h in &handlers {
            println!("{}", h.format_key);
        }
        return Ok(());
    }

    let entries: Vec<_> = handlers.iter().map(format_handler_json).collect();

    let table_str = {
        let mut table = new_table(vec![
            "KEY",
            "TYPE",
            "DISPLAY NAME",
            "ENABLED",
            "PRIORITY",
            "EXTENSIONS",
            "REPOS",
        ]);

        for h in &handlers {
            let handler_type = h.handler_type.to_string();
            let enabled = if h.is_enabled { "yes" } else { "no" };
            let priority = h.priority.to_string();
            let extensions = if h.extensions.is_empty() {
                "-".to_string()
            } else {
                h.extensions.join(", ")
            };
            let repos = h
                .repository_count
                .map(|c| c.to_string())
                .unwrap_or_else(|| "-".to_string());
            table.add_row(vec![
                h.format_key.as_str(),
                handler_type.as_str(),
                h.display_name.as_str(),
                enabled,
                priority.as_str(),
                extensions.as_str(),
                repos.as_str(),
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

async fn show_format_handler(format_key: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching format handler...");

    let resp = client
        .get_format_handler()
        .format_key(format_key)
        .send()
        .await
        .map_err(|e| sdk_err("get format handler", e))?;
    let handler = resp.into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", handler.format_key);
        return Ok(());
    }

    let info = format_handler_json(&handler);
    let table_str = format_handler_detail_table(&handler);

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn show_plugin(plugin_id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(plugin_id, "plugin")?;
    let spinner = output::spinner("Fetching plugin...");

    let resp = client
        .get_plugin()
        .id(id)
        .send()
        .await
        .map_err(|e| sdk_err("get plugin", e))?;
    let p = resp.into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", p.name);
        return Ok(());
    }

    let info = serde_json::json!({
        "id": p.id.to_string(),
        "name": p.name,
        "display_name": p.display_name,
        "version": p.version,
        "type": p.plugin_type,
        "status": p.status,
        "author": p.author,
        "description": p.description,
        "homepage": p.homepage,
        "installed_at": p.installed_at.to_rfc3339(),
        "enabled_at": p.enabled_at.map(|t| t.to_rfc3339()),
        "config_schema": p.config_schema,
    });

    let table_str = format!(
        "ID:            {}\n\
         Name:          {}\n\
         Display Name:  {}\n\
         Version:       {}\n\
         Type:          {}\n\
         Status:        {}\n\
         Author:        {}\n\
         Homepage:      {}\n\
         Description:   {}\n\
         Installed:     {}\n\
         Enabled:       {}",
        p.id,
        p.name,
        p.display_name,
        p.version,
        p.plugin_type,
        p.status,
        p.author.as_deref().unwrap_or("-"),
        p.homepage.as_deref().unwrap_or("-"),
        p.description.as_deref().unwrap_or("-"),
        p.installed_at.format("%Y-%m-%d %H:%M:%S"),
        p.enabled_at
            .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| "-".to_string()),
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn set_format_handler_enabled(
    format_key: &str,
    enable: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let (verb, gerund) = if enable {
        ("enable", "Enabling")
    } else {
        ("disable", "Disabling")
    };

    let spinner = output::spinner(&format!("{gerund} format handler..."));

    let resp = if enable {
        client
            .enable_format_handler()
            .format_key(format_key)
            .send()
            .await
    } else {
        client
            .disable_format_handler()
            .format_key(format_key)
            .send()
            .await
    };

    let handler = resp
        .map_err(|e| sdk_err(&format!("{verb} format handler"), e))?
        .into_inner();
    spinner.finish_and_clear();

    let state = if handler.is_enabled {
        "enabled"
    } else {
        "disabled"
    };
    emit_mutation(
        &format_handler_json(&handler),
        &handler.format_key,
        &format!("Format handler '{}' {}.", handler.format_key, state),
        global,
    );

    Ok(())
}

async fn get_plugin_config(plugin_id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(plugin_id, "plugin")?;
    let spinner = output::spinner("Fetching plugin config...");

    let resp = client
        .get_plugin_config()
        .id(id)
        .send()
        .await
        .map_err(|e| sdk_err("get plugin config", e))?;
    let cfg = resp.into_inner();
    spinner.finish_and_clear();

    let info = serde_json::json!({
        "plugin_id": cfg.plugin_id.to_string(),
        "config": cfg.config,
        "schema": cfg.schema,
    });

    let table_str = format_plugin_config(&cfg.config);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn set_plugin_config(
    plugin_id: &str,
    values: &[String],
    config_file: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(plugin_id, "plugin")?;

    let mut config = serde_json::Map::new();

    if let Some(path) = config_file {
        let contents = std::fs::read_to_string(path).map_err(|e| {
            crate::error::AkError::ConfigError(format!("Failed to read config file {path}: {e}"))
        })?;
        let parsed: serde_json::Value = serde_json::from_str(&contents).map_err(|e| {
            crate::error::AkError::ConfigError(format!("Invalid JSON in config file {path}: {e}"))
        })?;
        match parsed {
            serde_json::Value::Object(map) => config = map,
            _ => {
                return Err(crate::error::AkError::ConfigError(
                    "Config file must contain a JSON object".to_string(),
                )
                .into());
            }
        }
    }

    for entry in values {
        let (key, raw) = entry.split_once('=').ok_or_else(|| {
            crate::error::AkError::ConfigError(format!(
                "Invalid config entry '{entry}': expected KEY=VALUE"
            ))
        })?;
        // Parse the value as JSON so numbers/bools/objects are typed; fall back
        // to a plain string literal when it is not valid JSON.
        let value = serde_json::from_str::<serde_json::Value>(raw)
            .unwrap_or_else(|_| serde_json::Value::String(raw.to_string()));
        config.insert(key.to_string(), value);
    }

    if config.is_empty() {
        return Err(crate::error::AkError::ConfigError(
            "No configuration provided: pass KEY=VALUE pairs or --config-file".to_string(),
        )
        .into());
    }

    let body = artifact_keeper_sdk::types::UpdatePluginConfigRequest { config };

    let spinner = output::spinner("Updating plugin config...");
    let resp = client
        .update_plugin_config()
        .id(id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("update plugin config", e))?;
    let cfg = resp.into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Json | OutputFormat::Yaml) {
        let info = serde_json::json!({
            "plugin_id": cfg.plugin_id.to_string(),
            "config": cfg.config,
            "schema": cfg.schema,
        });
        println!("{}", output::render(&info, &global.format, None));
    } else if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", cfg.plugin_id);
    } else {
        eprintln!("Plugin {plugin_id} configuration updated.");
    }

    Ok(())
}

async fn set_plugin_enabled(plugin_id: &str, enable: bool, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(plugin_id, "plugin")?;

    let (action, verb) = if enable {
        ("enable plugin", "enabled")
    } else {
        ("disable plugin", "disabled")
    };

    let spinner = output::spinner(if enable {
        "Enabling plugin..."
    } else {
        "Disabling plugin..."
    });

    if enable {
        client
            .enable_plugin()
            .id(id)
            .send()
            .await
            .map_err(|e| sdk_err(action, e))?;
    } else {
        client
            .disable_plugin()
            .id(id)
            .send()
            .await
            .map_err(|e| sdk_err(action, e))?;
    }

    spinner.finish_and_clear();
    emit_mutation(
        &serde_json::json!({ "id": plugin_id, "status": verb }),
        plugin_id,
        &format!("Plugin {plugin_id} {verb}."),
        global,
    );

    Ok(())
}

async fn test_format_handler(
    format_key: &str,
    sample: Option<&str>,
    content: Option<&str>,
    path: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    use base64::Engine;

    let client = client_for(global)?;

    // Prefer --sample (a file whose bytes are base64-encoded); fall back to
    // --content (raw string). One of the two is required.
    let (body_content, is_base64, default_path) = if let Some(sample_path) = sample {
        let bytes = std::fs::read(sample_path).map_err(|e| {
            crate::error::AkError::ConfigError(format!(
                "Failed to read sample file '{sample_path}': {e}"
            ))
        })?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
        let name = std::path::Path::new(sample_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(sample_path)
            .to_string();
        (encoded, true, name)
    } else if let Some(raw) = content {
        (raw.to_string(), false, "test-artifact".to_string())
    } else {
        return Err(crate::error::AkError::ConfigError(
            "Provide either --sample <file> or --content <string> to test".to_string(),
        )
        .into());
    };

    let sim_path = path.map(|p| p.to_string()).unwrap_or(default_path);

    let body = artifact_keeper_sdk::types::TestFormatRequest {
        base64: Some(is_base64),
        content: body_content,
        path: sim_path,
    };

    let spinner = output::spinner("Testing format handler...");

    let resp = client
        .test_format_handler()
        .format_key(format_key)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("test format handler", e))?;
    let result = resp.into_inner();
    spinner.finish_and_clear();

    let info = serde_json::json!({
        "valid": result.valid,
        "parse_error": result.parse_error,
        "validation_error": result.validation_error,
        "metadata": result.metadata.as_ref().map(|m| serde_json::json!({
            "path": m.path,
            "content_type": m.content_type,
            "size_bytes": m.size_bytes,
            "version": m.version,
        })),
    });

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", if result.valid { "valid" } else { "invalid" });
        return Ok(());
    }

    let mut lines = vec![format!(
        "Valid:            {}",
        if result.valid { "yes" } else { "no" }
    )];
    if let Some(ref e) = result.validation_error {
        lines.push(format!("Validation Error: {e}"));
    }
    if let Some(ref e) = result.parse_error {
        lines.push(format!("Parse Error:      {e}"));
    }
    if let Some(ref m) = result.metadata {
        lines.push(format!("Path:             {}", m.path));
        lines.push(format!("Content Type:     {}", m.content_type));
        lines.push(format!("Size:             {}", format_bytes(m.size_bytes)));
        if let Some(ref v) = m.version {
            lines.push(format!("Version:          {v}"));
        }
    }
    let table_str = lines.join("\n");

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn reload_plugin(plugin_id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(plugin_id, "plugin")?;
    let spinner = output::spinner("Reloading plugin...");

    let resp = client
        .reload_plugin()
        .id(id)
        .send()
        .await
        .map_err(|e| sdk_err("reload plugin", e))?;
    let p = resp.into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Json | OutputFormat::Yaml) {
        let info = serde_json::json!({
            "id": p.id.to_string(),
            "name": p.name,
            "version": p.version,
            "status": p.status,
        });
        println!("{}", output::render(&info, &global.format, None));
    } else if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", p.id);
    } else {
        eprintln!(
            "Plugin '{}' v{} reloaded (status: {}).",
            p.name, p.version, p.status
        );
    }

    Ok(())
}

async fn plugin_events(plugin_id: &str, limit: Option<i64>, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(plugin_id, "plugin")?;
    let spinner = output::spinner("Fetching plugin events...");

    let mut req = client.get_plugin_events().id(id);
    if let Some(limit) = limit {
        req = req.limit(limit);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| sdk_err("get plugin events", e))?;
    let events = resp.into_inner();
    spinner.finish_and_clear();

    if events.is_empty() {
        eprintln!("No events for plugin {plugin_id}.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Json | OutputFormat::Yaml) {
        println!("{}", output::render(&events, &global.format, None));
        return Ok(());
    }

    let table_str = format_plugin_events(&events);
    println!(
        "{}",
        output::render(&events, &global.format, Some(table_str))
    );

    Ok(())
}

async fn install_plugin_local(path: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Installing plugin from local path...");

    let body = artifact_keeper_sdk::types::InstallFromLocalRequest {
        path: path.to_string(),
    };

    let resp = client
        .install_from_local()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("install plugin from local path", e))?;
    let resp = resp.into_inner();
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

async fn install_plugin_zip(path: &str, global: &GlobalArgs) -> Result<()> {
    // The `install_from_zip` endpoint uses multipart/form-data, which the
    // generated SDK does not model (Progenitor skips multipart operations), so
    // this is wired via a raw multipart HTTP request — the same raw-HTTP
    // workaround used by chunked upload and migration streaming.
    let bytes = std::fs::read(path).map_err(|e| {
        crate::error::AkError::ConfigError(format!("Failed to read ZIP file {path}: {e}"))
    })?;

    let file_name = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("plugin.zip")
        .to_string();

    let (base_url, auth_header) = resolve_base_url_and_auth(global)?;
    let url = format!(
        "{}/api/v1/plugins/install/zip",
        base_url.trim_end_matches('/')
    );

    let part = reqwest::multipart::Part::bytes(bytes)
        .file_name(file_name)
        .mime_str("application/zip")
        .map_err(|e| sdk_err("build ZIP upload", e))?;
    let form = reqwest::multipart::Form::new().part("file", part);

    let spinner = output::spinner("Installing plugin from ZIP...");
    let http = super::client::raw_http_client()?;
    let resp = http
        .post(&url)
        .header(reqwest::header::AUTHORIZATION, auth_header)
        .multipart(form)
        .send()
        .await
        .map_err(|e| sdk_err("install plugin from ZIP", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        spinner.finish_and_clear();
        return Err(crate::error::AkError::ServerError(format!(
            "Failed to install plugin from ZIP: HTTP {status}: {body}"
        ))
        .into());
    }

    let parsed: artifact_keeper_sdk::types::PluginInstallResponse = resp
        .json()
        .await
        .map_err(|e| sdk_err("parse ZIP install response", e))?;
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", parsed.plugin_id);
        return Ok(());
    }

    eprintln!(
        "Plugin '{}' v{} installed (format: {}).",
        parsed.name, parsed.version, parsed.format_key
    );
    eprintln!("{}", parsed.message);

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

fn user_detail_json(u: &artifact_keeper_sdk::types::AdminUserResponse) -> serde_json::Value {
    serde_json::json!({
        "id": u.id.to_string(),
        "username": u.username,
        "email": u.email,
        "display_name": u.display_name,
        "is_admin": u.is_admin,
        "is_active": u.is_active,
        "auth_provider": u.auth_provider,
        "must_change_password": u.must_change_password,
        "created_at": u.created_at.to_rfc3339(),
        "last_login_at": u.last_login_at.map(|t| t.to_rfc3339()),
    })
}

async fn show_user(user_id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(user_id, "user")?;

    let spinner = output::spinner("Fetching user...");
    let user = client
        .get_user()
        .id(id)
        .send()
        .await
        .map_err(|e| sdk_err("get user", e))?;
    let user = user.into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", user.id);
        return Ok(());
    }

    let info = user_detail_json(&user);

    let display = user.display_name.as_deref().unwrap_or("-");
    let last_login = user
        .last_login_at
        .map(|t| t.to_rfc3339())
        .unwrap_or_else(|| "never".to_string());
    let table_str = format!(
        "ID:                    {}\n\
         Username:              {}\n\
         Email:                 {}\n\
         Display Name:          {}\n\
         Admin:                 {}\n\
         Active:                {}\n\
         Auth Provider:         {}\n\
         Must Change Password:  {}\n\
         Last Login:            {}",
        user.id,
        user.username,
        user.email,
        display,
        if user.is_admin { "yes" } else { "no" },
        if user.is_active { "yes" } else { "no" },
        user.auth_provider,
        if user.must_change_password {
            "yes"
        } else {
            "no"
        },
        last_login,
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn force_password_change(user_id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(user_id, "user")?;

    let spinner = output::spinner("Forcing password change...");
    let resp = client
        .force_password_change()
        .id(id)
        .send()
        .await
        .map_err(|e| sdk_err("force password change", e))?;
    spinner.finish_and_clear();

    emit_mutation(
        &serde_json::json!({ "id": user_id, "status": "force_password_change" }),
        user_id,
        &resp.message,
        global,
    );

    Ok(())
}

async fn list_user_roles(user_id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(user_id, "user")?;

    let spinner = output::spinner("Fetching user roles...");
    let resp = client
        .get_user_roles()
        .id(id)
        .send()
        .await
        .map_err(|e| sdk_err("get user roles", e))?;
    let roles = resp.into_inner();
    spinner.finish_and_clear();

    if roles.items.is_empty() {
        eprintln!("No roles assigned.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for r in &roles.items {
            println!("{}", r.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = roles
        .items
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id.to_string(),
                "name": r.name,
                "description": r.description,
                "permissions": r.permissions,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["ID", "NAME", "DESCRIPTION", "PERMISSIONS"]);
        for r in &roles.items {
            let id_short = short_id(&r.id);
            let desc = r.description.as_deref().unwrap_or("-");
            let perms = if r.permissions.is_empty() {
                "-".to_string()
            } else {
                r.permissions.join(", ")
            };
            table.add_row(vec![&id_short, &r.name, desc, &perms]);
        }
        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn assign_role(user_id: &str, role_id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(user_id, "user")?;
    let role = parse_uuid(role_id, "role")?;

    let spinner = output::spinner("Assigning role...");
    let body = artifact_keeper_sdk::types::AssignRoleRequest { role_id: role };
    client
        .assign_role()
        .id(id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("assign role", e))?;
    spinner.finish_and_clear();

    emit_mutation(
        &serde_json::json!({ "user_id": user_id, "role_id": role_id, "status": "assigned" }),
        user_id,
        &format!("Role {role_id} assigned to user {user_id}."),
        global,
    );

    Ok(())
}

async fn revoke_role(user_id: &str, role_id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(user_id, "user")?;
    let role = parse_uuid(role_id, "role")?;

    let spinner = output::spinner("Revoking role...");
    client
        .revoke_role()
        .id(id)
        .role_id(role)
        .send()
        .await
        .map_err(|e| sdk_err("revoke role", e))?;
    spinner.finish_and_clear();

    emit_mutation(
        &serde_json::json!({ "user_id": user_id, "role_id": role_id, "status": "revoked" }),
        user_id,
        &format!("Role {role_id} revoked from user {user_id}."),
        global,
    );

    Ok(())
}

async fn list_user_tokens(user_id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(user_id, "user")?;

    let spinner = output::spinner("Fetching user tokens...");
    let resp = client
        .list_user_tokens()
        .id(id)
        .send()
        .await
        .map_err(|e| sdk_err("list user tokens", e))?;
    let list = resp.into_inner();
    spinner.finish_and_clear();

    if list.items.is_empty() {
        eprintln!("No API tokens found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for t in &list.items {
            println!("{}", t.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = list
        .items
        .iter()
        .map(|t| {
            serde_json::json!({
                "id": t.id.to_string(),
                "name": t.name,
                "token_prefix": t.token_prefix,
                "scopes": t.scopes,
                "created_at": t.created_at.to_rfc3339(),
                "expires_at": t.expires_at.map(|e| e.to_rfc3339()),
                "last_used_at": t.last_used_at.map(|l| l.to_rfc3339()),
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["ID", "NAME", "SCOPES", "CREATED", "EXPIRES"]);
        for t in &list.items {
            let id_short = short_id(&t.id);
            let scopes = if t.scopes.is_empty() {
                "-".to_string()
            } else {
                t.scopes.join(", ")
            };
            let created = t.created_at.format("%Y-%m-%d").to_string();
            let expires = t
                .expires_at
                .map(|e| e.format("%Y-%m-%d").to_string())
                .unwrap_or_else(|| "never".to_string());
            table.add_row(vec![&id_short, &t.name, &scopes, &created, &expires]);
        }
        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn create_user_token(
    user_id: &str,
    name: &str,
    scopes: Option<&str>,
    expires_in_days: Option<i64>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(user_id, "user")?;

    let scope_list: Vec<String> = scopes
        .map(|s| s.split(',').map(|v| v.trim().to_string()).collect())
        .unwrap_or_default();

    let body = artifact_keeper_sdk::types::CreateApiTokenRequest {
        name: name.to_string(),
        scopes: scope_list,
        expires_in_days,
    };

    let spinner = output::spinner("Creating API token...");
    let resp = client
        .create_user_api_token()
        .id(id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("create user token", e))?;
    let created = resp.into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", created.token);
        return Ok(());
    }

    let info = serde_json::json!({
        "id": created.id.to_string(),
        "name": created.name,
        "token": created.token,
    });
    let table_str = format!(
        "Token created successfully.\n\n\
         ID:    {}\n\
         Name:  {}\n\
         Token: {}\n\n\
         Save this token now. It will not be shown again.",
        created.id, created.name, created.token,
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn revoke_user_token(user_id: &str, token_id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(user_id, "user")?;
    let tid = parse_uuid(token_id, "token")?;

    let spinner = output::spinner("Revoking API token...");
    client
        .revoke_user_api_token()
        .id(id)
        .token_id(tid)
        .send()
        .await
        .map_err(|e| sdk_err("revoke user token", e))?;
    spinner.finish_and_clear();

    emit_mutation(
        &serde_json::json!({ "id": token_id, "status": "revoked" }),
        token_id,
        &format!("Token {token_id} revoked."),
        global,
    );

    Ok(())
}

async fn trigger_reindex(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Triggering search reindex...");

    let resp = client
        .trigger_reindex()
        .send()
        .await
        .map_err(|e| sdk_err("trigger reindex", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Json | OutputFormat::Yaml) {
        let info = serde_json::json!({
            "message": resp.message,
            "status": resp.status,
        });
        println!("{}", output::render(&info, &global.format, None));
    } else {
        eprintln!("{}", resp.message);
        eprintln!("Status: {}", resp.status);
    }

    Ok(())
}

async fn show_stats(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching system stats...");

    let stats = client
        .get_system_stats()
        .send()
        .await
        .map_err(|e| sdk_err("get system stats", e))?;

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

async fn show_settings(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching settings...");

    let settings = client
        .get_settings()
        .send()
        .await
        .map_err(|e| sdk_err("get settings", e))?;

    spinner.finish_and_clear();

    let info = serde_json::json!({
        "allow_anonymous_download": settings.allow_anonymous_download,
        "audit_retention_days": settings.audit_retention_days,
        "backup_retention_count": settings.backup_retention_count,
        "edge_stale_threshold_minutes": settings.edge_stale_threshold_minutes,
        "max_upload_size_bytes": settings.max_upload_size_bytes,
        "retention_days": settings.retention_days,
    });

    let table_str = format!(
        "Allow Anonymous Download:    {}\n\
         Audit Retention (days):      {}\n\
         Backup Retention (count):    {}\n\
         Edge Stale Threshold (min):  {}\n\
         Max Upload Size:             {}\n\
         Retention (days):            {}",
        settings.allow_anonymous_download,
        settings.audit_retention_days,
        settings.backup_retention_count,
        settings.edge_stale_threshold_minutes,
        format_bytes(settings.max_upload_size_bytes),
        settings.retention_days,
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn update_settings(json_str: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;

    let body: artifact_keeper_sdk::types::SystemSettings = serde_json::from_str(json_str)
        .map_err(|e| crate::error::AkError::ConfigError(format!("Invalid settings JSON: {e}")))?;

    let spinner = output::spinner("Updating settings...");

    let settings = client
        .update_settings()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("update settings", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Json | OutputFormat::Yaml) {
        let info = serde_json::json!({
            "allow_anonymous_download": settings.allow_anonymous_download,
            "audit_retention_days": settings.audit_retention_days,
            "backup_retention_count": settings.backup_retention_count,
            "edge_stale_threshold_minutes": settings.edge_stale_threshold_minutes,
            "max_upload_size_bytes": settings.max_upload_size_bytes,
            "retention_days": settings.retention_days,
        });
        println!("{}", output::render(&info, &global.format, None));
    } else {
        eprintln!("Settings updated.");
    }

    Ok(())
}

async fn show_telemetry(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching telemetry settings...");

    let settings = client
        .get_telemetry_settings()
        .send()
        .await
        .map_err(|e| sdk_err("get telemetry settings", e))?;

    spinner.finish_and_clear();

    let info = serde_json::json!({
        "enabled": settings.enabled,
        "include_logs": settings.include_logs,
        "review_before_send": settings.review_before_send,
        "scrub_level": settings.scrub_level,
    });

    let table_str = format_telemetry_settings(&settings);

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn update_telemetry(
    enabled: Option<bool>,
    include_logs: Option<bool>,
    review_before_send: Option<bool>,
    scrub_level: Option<String>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;

    // First fetch current settings so we can merge partial updates.
    let current = client
        .get_telemetry_settings()
        .send()
        .await
        .map_err(|e| sdk_err("get telemetry settings", e))?;

    let body = artifact_keeper_sdk::types::TelemetrySettings {
        enabled: enabled.unwrap_or(current.enabled),
        include_logs: include_logs.unwrap_or(current.include_logs),
        review_before_send: review_before_send.unwrap_or(current.review_before_send),
        scrub_level: scrub_level.unwrap_or_else(|| current.scrub_level.clone()),
    };

    let spinner = output::spinner("Updating telemetry settings...");

    let settings = client
        .update_telemetry_settings()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("update telemetry settings", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Json | OutputFormat::Yaml) {
        let info = serde_json::json!({
            "enabled": settings.enabled,
            "include_logs": settings.include_logs,
            "review_before_send": settings.review_before_send,
            "scrub_level": settings.scrub_level,
        });
        println!("{}", output::render(&info, &global.format, None));
    } else {
        eprintln!("Telemetry settings updated.");
        eprintln!("{}", format_telemetry_settings(&settings));
    }

    Ok(())
}

async fn list_crashes(pending: bool, page: i32, per_page: i32, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching crash reports...");

    if pending {
        let items = client
            .list_pending_crashes()
            .send()
            .await
            .map_err(|e| sdk_err("list pending crashes", e))?;
        let items = items.into_inner();

        spinner.finish_and_clear();

        if items.is_empty() {
            eprintln!("No pending crash reports.");
            return Ok(());
        }

        if matches!(global.format, OutputFormat::Quiet) {
            for c in &items {
                println!("{}", c.id);
            }
            return Ok(());
        }

        let entries: Vec<_> = items.iter().map(crash_report_json).collect();

        let table_str = format_crashes_table(&items);

        println!(
            "{}",
            output::render(&entries, &global.format, Some(table_str))
        );

        eprintln!("{} pending crash reports.", items.len());
    } else {
        let resp = client
            .list_crashes()
            .page(page)
            .per_page(per_page)
            .send()
            .await
            .map_err(|e| sdk_err("list crashes", e))?;

        spinner.finish_and_clear();

        if resp.items.is_empty() {
            eprintln!("No crash reports found.");
            return Ok(());
        }

        if matches!(global.format, OutputFormat::Quiet) {
            for c in &resp.items {
                println!("{}", c.id);
            }
            return Ok(());
        }

        let entries: Vec<_> = resp.items.iter().map(crash_report_json).collect();

        let table_str = format_crashes_table(&resp.items);

        println!(
            "{}",
            output::render(&entries, &global.format, Some(table_str))
        );

        eprintln!("{} crash reports total.", resp.total);
    }

    Ok(())
}

async fn submit_crashes(ids_str: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;

    let ids: Vec<uuid::Uuid> = ids_str
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse()
                .map_err(|_| crate::error::AkError::ConfigError(format!("Invalid crash ID: {s}")))
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;

    if ids.is_empty() {
        return Err(crate::error::AkError::ConfigError(
            "No crash report IDs provided.".to_string(),
        )
        .into());
    }

    let spinner = output::spinner("Submitting crash reports...");

    let body = artifact_keeper_sdk::types::SubmitCrashesRequest { ids };

    let resp = client
        .submit_crashes()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("submit crashes", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Json | OutputFormat::Yaml) {
        let info = serde_json::json!({
            "marked_submitted": resp.marked_submitted,
        });
        println!("{}", output::render(&info, &global.format, None));
    } else {
        eprintln!("{} crash report(s) submitted.", resp.marked_submitted);
    }

    Ok(())
}

fn crash_report_json(c: &artifact_keeper_sdk::types::CrashReport) -> serde_json::Value {
    serde_json::json!({
        "id": c.id.to_string(),
        "severity": c.severity,
        "error_type": c.error_type,
        "error_message": c.error_message,
        "component": c.component,
        "app_version": c.app_version,
        "occurrence_count": c.occurrence_count,
        "submitted": c.submitted,
        "created_at": c.created_at.to_rfc3339(),
        "last_seen_at": c.last_seen_at.to_rfc3339(),
    })
}

async fn get_crash(id: &str, global: &GlobalArgs) -> Result<()> {
    let crash_id = parse_uuid(id, "crash report")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching crash report...");

    let crash = client
        .get_crash()
        .id(crash_id)
        .send()
        .await
        .map_err(|e| sdk_err("get crash report", e))?;

    spinner.finish_and_clear();

    let info = crash_report_json(&crash);

    let table_str = format!(
        "ID:             {}\n\
         Severity:       {}\n\
         Error Type:     {}\n\
         Error Message:  {}\n\
         Component:      {}\n\
         App Version:    {}\n\
         Occurrences:    {}\n\
         Submitted:      {}\n\
         Created:        {}\n\
         First Seen:     {}\n\
         Last Seen:      {}",
        crash.id,
        crash.severity,
        crash.error_type,
        crash.error_message,
        crash.component,
        crash.app_version,
        crash.occurrence_count,
        if crash.submitted { "yes" } else { "no" },
        crash.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
        crash.first_seen_at.format("%Y-%m-%d %H:%M:%S UTC"),
        crash.last_seen_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn delete_crash(id: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    let crash_id = parse_uuid(id, "crash report")?;

    if !confirm_action(
        &format!("Delete crash report {id}?"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Deleting crash report...");

    client
        .delete_crash()
        .id(crash_id)
        .send()
        .await
        .map_err(|e| sdk_err("delete crash report", e))?;

    spinner.finish_and_clear();
    emit_mutation(
        &serde_json::json!({ "id": id, "status": "deleted" }),
        id,
        &format!("Crash report {id} deleted."),
        global,
    );

    Ok(())
}

fn format_telemetry_settings(s: &artifact_keeper_sdk::types::TelemetrySettings) -> String {
    format!(
        "Enabled:              {}\n\
         Include Logs:         {}\n\
         Review Before Send:   {}\n\
         Scrub Level:          {}",
        s.enabled, s.include_logs, s.review_before_send, s.scrub_level,
    )
}

fn format_crashes_table(items: &[artifact_keeper_sdk::types::CrashReport]) -> String {
    let mut table = new_table(vec![
        "ID",
        "SEVERITY",
        "TYPE",
        "COMPONENT",
        "COUNT",
        "SUBMITTED",
        "LAST SEEN",
    ]);

    for c in items {
        let id_short = short_id(&c.id);
        let count = c.occurrence_count.to_string();
        let submitted = if c.submitted { "yes" } else { "no" };
        let last_seen = c.last_seen_at.format("%Y-%m-%d %H:%M").to_string();
        table.add_row(vec![
            &id_short,
            &c.severity,
            &c.error_type,
            &c.component,
            &count,
            submitted,
            &last_seen,
        ]);
    }

    table.to_string()
}

/// Format a list of backup entries as a table string.
fn format_backups_table(items: &[serde_json::Value]) -> String {
    let mut table = new_table(vec!["ID", "STATUS", "TYPE", "ARTIFACTS", "SIZE", "CREATED"]);

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
    let mut table = new_table(vec![
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
    let mut table = new_table(vec![
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

/// Format a plugin configuration map as a KEY/VALUE table string.
fn format_plugin_config(config: &serde_json::Map<String, serde_json::Value>) -> String {
    if config.is_empty() {
        return "(no configuration set)".to_string();
    }
    let mut table = new_table(vec!["KEY", "VALUE"]);
    for (key, value) in config {
        let rendered = match value {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        table.add_row(vec![key.as_str(), rendered.as_str()]);
    }
    table.to_string()
}

/// Format a list of plugin lifecycle events as a table string.
fn format_plugin_events(events: &[serde_json::Value]) -> String {
    let mut table = new_table(vec!["EVENT", "STATUS", "MESSAGE", "TIMESTAMP"]);
    for e in events {
        let event_type = e["event_type"]
            .as_str()
            .or_else(|| e["type"].as_str())
            .unwrap_or("-");
        let status = e["status"].as_str().unwrap_or("-");
        let message = e["message"].as_str().unwrap_or("-");
        let ts = e["created_at"]
            .as_str()
            .or_else(|| e["timestamp"].as_str())
            .unwrap_or("-");
        table.add_row(vec![event_type, status, message, ts]);
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

// ---- Backup detail operations ----

fn render_backup(b: &artifact_keeper_sdk::types::BackupResponse, global: &GlobalArgs) {
    let info = serde_json::json!({
        "id": b.id.to_string(),
        "status": b.status,
        "type": b.type_,
        "artifacts": b.artifact_count,
        "size": format_bytes(b.size_bytes),
        "size_bytes": b.size_bytes,
        "storage_path": b.storage_path,
        "created_at": b.created_at.to_rfc3339(),
        "started_at": b.started_at.map(|t| t.to_rfc3339()),
        "completed_at": b.completed_at.map(|t| t.to_rfc3339()),
        "error": b.error_message,
    });

    let completed = b
        .completed_at
        .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| "-".to_string());

    let table_str = format!(
        "ID:          {}\n\
         Status:      {}\n\
         Type:        {}\n\
         Artifacts:   {}\n\
         Size:        {}\n\
         Created:     {}\n\
         Completed:   {}",
        b.id,
        b.status,
        b.type_,
        b.artifact_count,
        format_bytes(b.size_bytes),
        b.created_at.format("%Y-%m-%d %H:%M"),
        completed,
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));
}

async fn get_backup(backup_id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(backup_id, "backup")?;
    let spinner = output::spinner("Fetching backup...");

    let backup = client
        .get_backup()
        .id(id)
        .send()
        .await
        .map_err(|e| sdk_err("get backup", e))?;

    spinner.finish_and_clear();
    render_backup(&backup, global);
    Ok(())
}

async fn delete_backup(backup_id: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(backup_id, "backup")?;

    if !confirm_action(
        &format!("Delete backup {backup_id}? This cannot be undone"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let spinner = output::spinner("Deleting backup...");
    client
        .delete_backup()
        .id(id)
        .send()
        .await
        .map_err(|e| sdk_err("delete backup", e))?;

    spinner.finish_and_clear();
    emit_mutation(
        &serde_json::json!({ "id": backup_id, "status": "deleted" }),
        backup_id,
        &format!("Backup {backup_id} deleted."),
        global,
    );
    Ok(())
}

async fn cancel_backup(backup_id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(backup_id, "backup")?;
    let spinner = output::spinner("Cancelling backup...");

    client
        .cancel_backup()
        .id(id)
        .send()
        .await
        .map_err(|e| sdk_err("cancel backup", e))?;

    spinner.finish_and_clear();
    emit_mutation(
        &serde_json::json!({ "id": backup_id, "status": "cancelled" }),
        backup_id,
        &format!("Backup {backup_id} cancelled."),
        global,
    );
    Ok(())
}

async fn execute_backup(backup_id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(backup_id, "backup")?;
    let spinner = output::spinner("Executing backup...");

    let backup = client
        .execute_backup()
        .id(id)
        .send()
        .await
        .map_err(|e| sdk_err("execute backup", e))?;

    spinner.finish_and_clear();
    render_backup(&backup, global);
    Ok(())
}

// ---- CI OIDC providers ----

fn provider_json(p: &artifact_keeper_sdk::types::CiOidcProviderResponse) -> serde_json::Value {
    serde_json::json!({
        "id": p.id.to_string(),
        "name": p.name,
        "issuer_url": p.issuer_url,
        "audience": p.audience,
        "provider_type": p.provider_type,
        "is_enabled": p.is_enabled,
        "mapping_count": p.mapping_count,
        "created_at": p.created_at.to_rfc3339(),
        "updated_at": p.updated_at.to_rfc3339(),
    })
}

fn provider_table(p: &artifact_keeper_sdk::types::CiOidcProviderResponse) -> String {
    format!(
        "ID:            {}\n\
         Name:          {}\n\
         Issuer URL:    {}\n\
         Audience:      {}\n\
         Provider Type: {}\n\
         Enabled:       {}\n\
         Mappings:      {}",
        p.id, p.name, p.issuer_url, p.audience, p.provider_type, p.is_enabled, p.mapping_count,
    )
}

async fn list_ci_oidc_providers(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching CI OIDC providers...");

    let resp = client
        .ci_oidc_list_providers()
        .send()
        .await
        .map_err(|e| sdk_err("list CI OIDC providers", e))?;

    spinner.finish_and_clear();

    if resp.is_empty() {
        eprintln!("No CI OIDC providers found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for p in resp.iter() {
            println!("{}", p.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp.iter().map(provider_json).collect();

    let table_str = {
        let mut table = new_table(vec!["ID", "NAME", "ISSUER", "ENABLED", "MAPPINGS"]);
        for p in resp.iter() {
            let id_short = short_id(&p.id);
            table.add_row(vec![
                &id_short,
                &p.name,
                &p.issuer_url,
                &p.is_enabled.to_string(),
                &p.mapping_count.to_string(),
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

async fn get_ci_oidc_provider(provider_id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(provider_id, "provider")?;
    let spinner = output::spinner("Fetching CI OIDC provider...");

    let p = client
        .get_provider()
        .id(id)
        .send()
        .await
        .map_err(|e| sdk_err("get CI OIDC provider", e))?;

    spinner.finish_and_clear();
    let info = provider_json(&p);
    println!(
        "{}",
        output::render(&info, &global.format, Some(provider_table(&p)))
    );
    Ok(())
}

async fn create_ci_oidc_provider(
    name: &str,
    issuer_url: &str,
    audience: Option<&str>,
    provider_type: Option<&str>,
    enabled: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Creating CI OIDC provider...");

    let body = artifact_keeper_sdk::types::CreateCiOidcProviderRequest {
        name: name.to_string(),
        issuer_url: issuer_url.to_string(),
        audience: audience.map(|s| s.to_string()),
        provider_type: provider_type.map(|s| s.to_string()),
        is_enabled: enabled.then_some(true),
    };

    let p = client
        .create_provider()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("create CI OIDC provider", e))?;

    spinner.finish_and_clear();
    emit_mutation(
        &provider_json(&p),
        &p.id.to_string(),
        &format!("CI OIDC provider '{}' created (ID: {}).", p.name, p.id),
        global,
    );
    Ok(())
}

async fn update_ci_oidc_provider(
    provider_id: &str,
    name: Option<&str>,
    issuer_url: Option<&str>,
    audience: Option<&str>,
    provider_type: Option<&str>,
    enabled: Option<bool>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(provider_id, "provider")?;
    let spinner = output::spinner("Updating CI OIDC provider...");

    let body = artifact_keeper_sdk::types::UpdateCiOidcProviderRequest {
        name: name.map(|s| s.to_string()),
        issuer_url: issuer_url.map(|s| s.to_string()),
        audience: audience.map(|s| s.to_string()),
        provider_type: provider_type.map(|s| s.to_string()),
        is_enabled: enabled,
    };

    let p = client
        .update_provider()
        .id(id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("update CI OIDC provider", e))?;

    spinner.finish_and_clear();
    emit_mutation(
        &provider_json(&p),
        &p.id.to_string(),
        &format!("CI OIDC provider '{}' updated (ID: {}).", p.name, p.id),
        global,
    );
    Ok(())
}

async fn delete_ci_oidc_provider(
    provider_id: &str,
    skip_confirm: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(provider_id, "provider")?;

    if !confirm_action(
        &format!("Delete CI OIDC provider {provider_id}? This cannot be undone"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let spinner = output::spinner("Deleting CI OIDC provider...");
    client
        .delete_provider()
        .id(id)
        .send()
        .await
        .map_err(|e| sdk_err("delete CI OIDC provider", e))?;

    spinner.finish_and_clear();
    emit_mutation(
        &serde_json::json!({ "id": provider_id, "status": "deleted" }),
        provider_id,
        &format!("CI OIDC provider {provider_id} deleted."),
        global,
    );
    Ok(())
}

async fn toggle_ci_oidc_provider(
    provider_id: &str,
    enabled: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(provider_id, "provider")?;
    let spinner = output::spinner("Toggling CI OIDC provider...");

    let body = artifact_keeper_sdk::types::CiOidcToggleRequest { enabled };

    let p = client
        .toggle_provider()
        .id(id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("toggle CI OIDC provider", e))?;

    spinner.finish_and_clear();
    emit_mutation(
        &provider_json(&p),
        &p.id.to_string(),
        &format!(
            "CI OIDC provider '{}' {} (ID: {}).",
            p.name,
            if p.is_enabled { "enabled" } else { "disabled" },
            p.id
        ),
        global,
    );
    Ok(())
}

// ---- CI OIDC identity mappings ----

fn parse_repo_ids(csv: Option<&str>) -> Result<Option<Vec<uuid::Uuid>>> {
    match csv {
        None => Ok(None),
        Some(s) => {
            let mut ids = Vec::new();
            for part in s.split(',') {
                let trimmed = part.trim();
                if trimmed.is_empty() {
                    continue;
                }
                ids.push(parse_uuid(trimmed, "repository")?);
            }
            Ok(Some(ids))
        }
    }
}

fn mapping_json(m: &artifact_keeper_sdk::types::CiOidcMappingResponse) -> serde_json::Value {
    serde_json::json!({
        "id": m.id.to_string(),
        "provider_id": m.provider_id.to_string(),
        "name": m.name,
        "priority": m.priority,
        "is_enabled": m.is_enabled,
        "allowed_repo_ids": m
            .allowed_repo_ids
            .as_ref()
            .map(|v| v.iter().map(|u| u.to_string()).collect::<Vec<_>>()),
        "claim_filters": m.claim_filters,
        "created_at": m.created_at.to_rfc3339(),
        "updated_at": m.updated_at.to_rfc3339(),
    })
}

fn mapping_table(m: &artifact_keeper_sdk::types::CiOidcMappingResponse) -> String {
    let repos = m
        .allowed_repo_ids
        .as_ref()
        .map(|v| v.len().to_string())
        .unwrap_or_else(|| "all".to_string());
    format!(
        "ID:            {}\n\
         Provider ID:   {}\n\
         Name:          {}\n\
         Priority:      {}\n\
         Enabled:       {}\n\
         Allowed Repos: {}\n\
         Claim Filters: {}",
        m.id, m.provider_id, m.name, m.priority, m.is_enabled, repos, m.claim_filters,
    )
}

async fn list_ci_oidc_mappings(provider_id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(provider_id, "provider")?;
    let spinner = output::spinner("Fetching identity mappings...");

    let resp = client
        .list_mappings()
        .id(id)
        .send()
        .await
        .map_err(|e| sdk_err("list identity mappings", e))?;

    spinner.finish_and_clear();

    if resp.is_empty() {
        eprintln!("No identity mappings found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for m in resp.iter() {
            println!("{}", m.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp.iter().map(mapping_json).collect();

    let table_str = {
        let mut table = new_table(vec!["ID", "NAME", "PRIORITY", "ENABLED", "REPOS"]);
        for m in resp.iter() {
            let id_short = short_id(&m.id);
            let repos = m
                .allowed_repo_ids
                .as_ref()
                .map(|v| v.len().to_string())
                .unwrap_or_else(|| "all".to_string());
            table.add_row(vec![
                &id_short,
                &m.name,
                &m.priority.to_string(),
                &m.is_enabled.to_string(),
                &repos,
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

async fn get_ci_oidc_mapping(
    provider_id: &str,
    mapping_id: &str,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(provider_id, "provider")?;
    let mid = parse_uuid(mapping_id, "mapping")?;
    let spinner = output::spinner("Fetching identity mapping...");

    let m = client
        .get_mapping()
        .id(id)
        .mid(mid)
        .send()
        .await
        .map_err(|e| sdk_err("get identity mapping", e))?;

    spinner.finish_and_clear();
    println!(
        "{}",
        output::render(&mapping_json(&m), &global.format, Some(mapping_table(&m)))
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn create_ci_oidc_mapping(
    provider_id: &str,
    name: &str,
    claim_filters: &str,
    priority: Option<i32>,
    allowed_repo_ids: Option<&str>,
    enabled: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(provider_id, "provider")?;

    let filters: serde_json::Value = serde_json::from_str(claim_filters).map_err(|e| {
        crate::error::AkError::ConfigError(format!("Invalid claim-filters JSON: {e}"))
    })?;
    let allowed = parse_repo_ids(allowed_repo_ids)?;

    let spinner = output::spinner("Creating identity mapping...");

    let body = artifact_keeper_sdk::types::CreateCiOidcMappingRequest {
        name: name.to_string(),
        claim_filters: filters,
        priority,
        allowed_repo_ids: allowed,
        is_enabled: enabled.then_some(true),
    };

    let m = client
        .create_mapping()
        .id(id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("create identity mapping", e))?;

    spinner.finish_and_clear();
    emit_mutation(
        &mapping_json(&m),
        &m.id.to_string(),
        &format!("Identity mapping '{}' created (ID: {}).", m.name, m.id),
        global,
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn update_ci_oidc_mapping(
    provider_id: &str,
    mapping_id: &str,
    name: Option<&str>,
    claim_filters: Option<&str>,
    priority: Option<i32>,
    allowed_repo_ids: Option<&str>,
    enabled: Option<bool>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(provider_id, "provider")?;
    let mid = parse_uuid(mapping_id, "mapping")?;

    let filters = match claim_filters {
        None => None,
        Some(s) => Some(serde_json::from_str::<serde_json::Value>(s).map_err(|e| {
            crate::error::AkError::ConfigError(format!("Invalid claim-filters JSON: {e}"))
        })?),
    };
    let allowed = parse_repo_ids(allowed_repo_ids)?;

    let spinner = output::spinner("Updating identity mapping...");

    let body = artifact_keeper_sdk::types::UpdateCiOidcMappingRequest {
        name: name.map(|s| s.to_string()),
        claim_filters: filters,
        priority,
        allowed_repo_ids: allowed,
        is_enabled: enabled,
    };

    let m = client
        .update_mapping()
        .id(id)
        .mid(mid)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("update identity mapping", e))?;

    spinner.finish_and_clear();
    emit_mutation(
        &mapping_json(&m),
        &m.id.to_string(),
        &format!("Identity mapping '{}' updated (ID: {}).", m.name, m.id),
        global,
    );
    Ok(())
}

async fn delete_ci_oidc_mapping(
    provider_id: &str,
    mapping_id: &str,
    skip_confirm: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(provider_id, "provider")?;
    let mid = parse_uuid(mapping_id, "mapping")?;

    if !confirm_action(
        &format!("Delete identity mapping {mapping_id}? This cannot be undone"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let spinner = output::spinner("Deleting identity mapping...");
    client
        .delete_mapping()
        .id(id)
        .mid(mid)
        .send()
        .await
        .map_err(|e| sdk_err("delete identity mapping", e))?;

    spinner.finish_and_clear();
    emit_mutation(
        &serde_json::json!({ "id": mapping_id, "status": "deleted" }),
        mapping_id,
        &format!("Identity mapping {mapping_id} deleted."),
        global,
    );
    Ok(())
}

async fn toggle_ci_oidc_mapping(
    provider_id: &str,
    mapping_id: &str,
    enabled: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(provider_id, "provider")?;
    let mid = parse_uuid(mapping_id, "mapping")?;
    let spinner = output::spinner("Toggling identity mapping...");

    let body = artifact_keeper_sdk::types::CiOidcToggleRequest { enabled };

    let m = client
        .toggle_mapping()
        .id(id)
        .mid(mid)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("toggle identity mapping", e))?;

    spinner.finish_and_clear();
    emit_mutation(
        &mapping_json(&m),
        &m.id.to_string(),
        &format!(
            "Identity mapping '{}' {} (ID: {}).",
            m.name,
            if m.is_enabled { "enabled" } else { "disabled" },
            m.id
        ),
        global,
    );
    Ok(())
}

// ---- Storage GC and reports ----

async fn run_storage_gc(dry_run: bool, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Running storage garbage collection...");

    let body = artifact_keeper_sdk::types::StorageGcRequest {
        dry_run: dry_run.then_some(true),
    };

    let r = client
        .run_storage_gc()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("run storage GC", e))?;

    spinner.finish_and_clear();

    let info = serde_json::json!({
        "dry_run": r.dry_run,
        "artifacts_removed": r.artifacts_removed,
        "storage_keys_deleted": r.storage_keys_deleted,
        "bytes_freed": r.bytes_freed,
        "bytes_freed_human": format_bytes(r.bytes_freed),
        "errors": r.errors,
    });

    if matches!(global.format, OutputFormat::Json | OutputFormat::Yaml) {
        println!("{}", output::render(&info, &global.format, None));
    } else {
        eprintln!(
            "Storage GC complete{}:",
            if r.dry_run { " (dry run)" } else { "" }
        );
        eprintln!("  Artifacts removed:     {}", r.artifacts_removed);
        eprintln!("  Storage keys deleted:  {}", r.storage_keys_deleted);
        eprintln!("  Bytes freed:           {}", format_bytes(r.bytes_freed));
        if !r.errors.is_empty() {
            eprintln!("  Errors:");
            for e in &r.errors {
                eprintln!("    - {e}");
            }
        }
    }
    Ok(())
}

async fn oci_blob_report(grace_hours: Option<i64>, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching OCI blob footprint report...");

    let mut req = client.oci_blob_report();
    if let Some(h) = grace_hours {
        req = req.grace_hours(h);
    }

    let r = req
        .send()
        .await
        .map_err(|e| sdk_err("get OCI blob report", e))?;

    spinner.finish_and_clear();

    let info = serde_json::json!({
        "grace_hours": r.grace_hours,
        "total_blob_rows": r.total_blob_rows,
        "distinct_digests": r.distinct_digests,
        "logical_bytes": r.logical_bytes,
        "physical_bytes": r.physical_bytes,
        "aged_distinct_digests": r.aged_distinct_digests,
        "aged_physical_bytes": r.aged_physical_bytes,
        "per_repository": r.per_repository.iter().map(|p| serde_json::json!({
            "repository_id": p.repository_id.to_string(),
            "blob_rows": p.blob_rows,
            "logical_bytes": p.logical_bytes,
        })).collect::<Vec<_>>(),
    });

    let table_str = format!(
        "Grace Window (hrs):     {}\n\
         Total Blob Rows:        {}\n\
         Distinct Digests:       {}\n\
         Logical Bytes:          {}\n\
         Physical Bytes:         {}\n\
         Aged Distinct Digests:  {}\n\
         Aged Physical Bytes:    {}\n\
         Repositories:           {}",
        r.grace_hours,
        r.total_blob_rows,
        r.distinct_digests,
        format_bytes(r.logical_bytes),
        format_bytes(r.physical_bytes),
        r.aged_distinct_digests,
        format_bytes(r.aged_physical_bytes),
        r.per_repository.len(),
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));
    Ok(())
}

async fn list_storage_backends(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching storage backends...");

    let resp = client
        .list_storage_backends()
        .send()
        .await
        .map_err(|e| sdk_err("list storage backends", e))?;

    spinner.finish_and_clear();

    if resp.is_empty() {
        eprintln!("No storage backends configured.");
        return Ok(());
    }

    match global.format {
        OutputFormat::Quiet | OutputFormat::Table => {
            for b in resp.iter() {
                println!("{b}");
            }
        }
        OutputFormat::Json | OutputFormat::Yaml => {
            println!("{}", output::render(&*resp, &global.format, None));
        }
    }
    Ok(())
}

// ---- Search reindex / rescan ----

async fn trigger_search_reindex(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Triggering OpenSearch reindex...");

    let resp = client
        .trigger_search_reindex()
        .send()
        .await
        .map_err(|e| sdk_err("trigger search reindex", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Json | OutputFormat::Yaml) {
        let info = serde_json::json!({ "message": resp.message, "status": resp.status });
        println!("{}", output::render(&info, &global.format, None));
    } else {
        eprintln!("{}", resp.message);
        eprintln!("Status: {}", resp.status);
    }
    Ok(())
}

async fn rescan_for_inventory(limit: Option<i64>, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Enqueuing artifacts for rescan...");

    let body = artifact_keeper_sdk::types::RescanForInventoryRequest { limit };

    let resp = client
        .rescan_for_inventory()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("rescan for inventory", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Json | OutputFormat::Yaml) {
        let info = serde_json::json!({
            "artifacts_enqueued": resp.artifacts_enqueued,
            "limit": resp.limit,
        });
        println!("{}", output::render(&info, &global.format, None));
    } else {
        eprintln!(
            "Enqueued {} artifact(s) for rescan (limit {}).",
            resp.artifacts_enqueued, resp.limit
        );
    }
    Ok(())
}

// ---- SMTP test ----

async fn send_test_email(to: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Sending test email...");

    let body = artifact_keeper_sdk::types::SmtpTestRequest { to: to.to_string() };

    let resp = client
        .send_test_email()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("send test email", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Json | OutputFormat::Yaml) {
        let info = serde_json::json!({ "success": resp.success, "message": resp.message });
        println!("{}", output::render(&info, &global.format, None));
    } else if resp.success {
        eprintln!("Test email sent to {to}: {}", resp.message);
    } else {
        eprintln!("Test email failed: {}", resp.message);
    }
    Ok(())
}

// ---- Remote instances and proxy ----

fn instance_json(i: &artifact_keeper_sdk::types::RemoteInstanceResponse) -> serde_json::Value {
    serde_json::json!({
        "id": i.id.to_string(),
        "name": i.name,
        "url": i.url,
        "created_at": i.created_at.to_rfc3339(),
    })
}

async fn list_instances(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching remote instances...");

    let resp = client
        .list_instances()
        .send()
        .await
        .map_err(|e| sdk_err("list remote instances", e))?;

    spinner.finish_and_clear();

    if resp.is_empty() {
        eprintln!("No remote instances found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for i in resp.iter() {
            println!("{}", i.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp.iter().map(instance_json).collect();

    let table_str = {
        let mut table = new_table(vec!["ID", "NAME", "URL", "CREATED"]);
        for i in resp.iter() {
            let id_short = short_id(&i.id);
            let created = i.created_at.format("%Y-%m-%d %H:%M").to_string();
            table.add_row(vec![&id_short, &i.name, &i.url, &created]);
        }
        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );
    Ok(())
}

async fn create_instance(name: &str, url: &str, api_key: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Registering remote instance...");

    let body = artifact_keeper_sdk::types::CreateInstanceRequest {
        name: name.to_string(),
        url: url.to_string(),
        api_key: api_key.to_string(),
    };

    let i = client
        .create_instance()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("create remote instance", e))?;

    spinner.finish_and_clear();
    emit_mutation(
        &instance_json(&i),
        &i.id.to_string(),
        &format!("Remote instance '{}' registered (ID: {}).", i.name, i.id),
        global,
    );
    Ok(())
}

async fn delete_instance(instance_id: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(instance_id, "instance")?;

    if !confirm_action(
        &format!("Delete remote instance {instance_id}?"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let spinner = output::spinner("Deleting remote instance...");
    client
        .delete_instance()
        .id(id)
        .send()
        .await
        .map_err(|e| sdk_err("delete remote instance", e))?;

    spinner.finish_and_clear();
    emit_mutation(
        &serde_json::json!({ "id": instance_id, "status": "deleted" }),
        instance_id,
        &format!("Remote instance {instance_id} deleted."),
        global,
    );
    Ok(())
}

async fn proxy_request(
    instance_id: &str,
    method: &str,
    path: &str,
    body: Option<String>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let id = parse_uuid(instance_id, "instance")?;
    let spinner = output::spinner("Proxying request...");

    let status = match method {
        "GET" => client
            .proxy_get()
            .id(id)
            .path(path)
            .send()
            .await
            .map_err(|e| sdk_err("proxy request", e))?
            .status(),
        "DELETE" => client
            .proxy_delete()
            .id(id)
            .path(path)
            .send()
            .await
            .map_err(|e| sdk_err("proxy request", e))?
            .status(),
        "PUT" => client
            .proxy_put()
            .id(id)
            .path(path)
            .body(body.unwrap_or_default())
            .send()
            .await
            .map_err(|e| sdk_err("proxy request", e))?
            .status(),
        "POST" => client
            .proxy_post()
            .id(id)
            .path(path)
            .body(body.unwrap_or_default())
            .send()
            .await
            .map_err(|e| sdk_err("proxy request", e))?
            .status(),
        other => {
            return Err(crate::error::AkError::ConfigError(format!(
                "Unsupported proxy method: {other}"
            ))
            .into());
        }
    };

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Json | OutputFormat::Yaml) {
        let info = serde_json::json!({
            "method": method,
            "path": path,
            "status": status.as_u16(),
        });
        println!("{}", output::render(&info, &global.format, None));
    } else {
        eprintln!("Proxied {method} /{path} -> {status}");
    }
    Ok(())
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

    #[test]
    fn parse_users_show() {
        let cli = parse(&["test", "users", "show", "user-id"]);
        if let AdminCommand::Users {
            command: UsersCommand::Show { id },
        } = cli.command
        {
            assert_eq!(id, "user-id");
        } else {
            panic!("Expected UsersCommand::Show");
        }
    }

    #[test]
    fn parse_users_force_password_change() {
        let cli = parse(&["test", "users", "force-password-change", "user-id"]);
        if let AdminCommand::Users {
            command: UsersCommand::ForcePasswordChange { id },
        } = cli.command
        {
            assert_eq!(id, "user-id");
        } else {
            panic!("Expected UsersCommand::ForcePasswordChange");
        }
    }

    #[test]
    fn parse_users_roles() {
        let cli = parse(&["test", "users", "roles", "user-id"]);
        if let AdminCommand::Users {
            command: UsersCommand::Roles { id },
        } = cli.command
        {
            assert_eq!(id, "user-id");
        } else {
            panic!("Expected UsersCommand::Roles");
        }
    }

    #[test]
    fn parse_users_role_assign() {
        let cli = parse(&["test", "users", "role", "assign", "user-id", "role-id"]);
        if let AdminCommand::Users {
            command:
                UsersCommand::Role {
                    command: RoleCommand::Assign { user, role },
                },
        } = cli.command
        {
            assert_eq!(user, "user-id");
            assert_eq!(role, "role-id");
        } else {
            panic!("Expected RoleCommand::Assign");
        }
    }

    #[test]
    fn parse_users_role_revoke() {
        let cli = parse(&["test", "users", "role", "revoke", "user-id", "role-id"]);
        if let AdminCommand::Users {
            command:
                UsersCommand::Role {
                    command: RoleCommand::Revoke { user, role },
                },
        } = cli.command
        {
            assert_eq!(user, "user-id");
            assert_eq!(role, "role-id");
        } else {
            panic!("Expected RoleCommand::Revoke");
        }
    }

    #[test]
    fn parse_users_role_assign_missing_role_fails() {
        assert!(try_parse(&["test", "users", "role", "assign", "user-id"]).is_err());
    }

    #[test]
    fn parse_users_tokens_list() {
        let cli = parse(&["test", "users", "tokens", "list", "user-id"]);
        if let AdminCommand::Users {
            command:
                UsersCommand::Tokens {
                    command: UserTokenCommand::List { user },
                },
        } = cli.command
        {
            assert_eq!(user, "user-id");
        } else {
            panic!("Expected UserTokenCommand::List");
        }
    }

    #[test]
    fn parse_users_tokens_create() {
        let cli = parse(&[
            "test",
            "users",
            "tokens",
            "create",
            "user-id",
            "ci-token",
            "--scopes",
            "read,write",
            "--expires-in-days",
            "30",
        ]);
        if let AdminCommand::Users {
            command:
                UsersCommand::Tokens {
                    command:
                        UserTokenCommand::Create {
                            user,
                            name,
                            scopes,
                            expires_in_days,
                        },
                },
        } = cli.command
        {
            assert_eq!(user, "user-id");
            assert_eq!(name, "ci-token");
            assert_eq!(scopes.as_deref(), Some("read,write"));
            assert_eq!(expires_in_days, Some(30));
        } else {
            panic!("Expected UserTokenCommand::Create");
        }
    }

    #[test]
    fn parse_users_tokens_revoke() {
        let cli = parse(&["test", "users", "tokens", "revoke", "user-id", "token-id"]);
        if let AdminCommand::Users {
            command:
                UsersCommand::Tokens {
                    command: UserTokenCommand::Revoke { user, token_id },
                },
        } = cli.command
        {
            assert_eq!(user, "user-id");
            assert_eq!(token_id, "token-id");
        } else {
            panic!("Expected UserTokenCommand::Revoke");
        }
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

    // ---- Format handler subcommand parsing ----

    #[test]
    fn parse_formats_list() {
        let cli = parse(&["test", "formats", "list"]);
        if let AdminCommand::Formats {
            command: FormatHandlerCommand::List { r#type, enabled },
        } = cli.command
        {
            assert!(r#type.is_none());
            assert!(enabled.is_none());
        } else {
            panic!("Expected FormatHandlerCommand::List");
        }
    }

    #[test]
    fn parse_formats_list_with_filters() {
        let cli = parse(&[
            "test",
            "formats",
            "list",
            "--type",
            "Wasm",
            "--enabled",
            "true",
        ]);
        if let AdminCommand::Formats {
            command: FormatHandlerCommand::List { r#type, enabled },
        } = cli.command
        {
            assert_eq!(r#type.as_deref(), Some("Wasm"));
            assert_eq!(enabled, Some(true));
        } else {
            panic!("Expected FormatHandlerCommand::List");
        }
    }

    #[test]
    fn parse_formats_show() {
        let cli = parse(&["test", "formats", "show", "maven"]);
        if let AdminCommand::Formats {
            command: FormatHandlerCommand::Show { name },
        } = cli.command
        {
            assert_eq!(name, "maven");
        } else {
            panic!("Expected FormatHandlerCommand::Show");
        }
    }

    #[test]
    fn parse_formats_show_missing_name_fails() {
        assert!(try_parse(&["test", "formats", "show"]).is_err());
    }

    #[test]
    fn parse_formats_enable() {
        let cli = parse(&["test", "formats", "enable", "npm"]);
        if let AdminCommand::Formats {
            command: FormatHandlerCommand::Enable { name },
        } = cli.command
        {
            assert_eq!(name, "npm");
        } else {
            panic!("Expected FormatHandlerCommand::Enable");
        }
    }

    #[test]
    fn parse_formats_disable() {
        let cli = parse(&["test", "formats", "disable", "npm"]);
        if let AdminCommand::Formats {
            command: FormatHandlerCommand::Disable { name },
        } = cli.command
        {
            assert_eq!(name, "npm");
        } else {
            panic!("Expected FormatHandlerCommand::Disable");
        }
    }

    #[test]
    fn parse_formats_test_with_sample() {
        let cli = parse(&[
            "test",
            "formats",
            "test",
            "maven",
            "--sample",
            "/tmp/pom.xml",
            "--path",
            "com/example/app/1.0/app-1.0.pom",
        ]);
        if let AdminCommand::Formats {
            command:
                FormatHandlerCommand::Test {
                    name,
                    sample,
                    content,
                    path,
                },
        } = cli.command
        {
            assert_eq!(name, "maven");
            assert_eq!(sample.as_deref(), Some("/tmp/pom.xml"));
            assert!(content.is_none());
            assert_eq!(path.as_deref(), Some("com/example/app/1.0/app-1.0.pom"));
        } else {
            panic!("Expected FormatHandlerCommand::Test");
        }
    }

    #[test]
    fn parse_formats_test_with_content() {
        let cli = parse(&[
            "test",
            "formats",
            "test",
            "npm",
            "--content",
            "{\"name\":\"x\"}",
        ]);
        if let AdminCommand::Formats {
            command:
                FormatHandlerCommand::Test {
                    name,
                    sample,
                    content,
                    path,
                },
        } = cli.command
        {
            assert_eq!(name, "npm");
            assert!(sample.is_none());
            assert_eq!(content.as_deref(), Some("{\"name\":\"x\"}"));
            assert!(path.is_none());
        } else {
            panic!("Expected FormatHandlerCommand::Test");
        }
    }

    #[test]
    fn parse_formats_test_sample_and_content_conflict() {
        assert!(
            try_parse(&[
                "test",
                "formats",
                "test",
                "maven",
                "--sample",
                "/tmp/pom.xml",
                "--content",
                "raw",
            ])
            .is_err()
        );
    }

    #[test]
    fn parse_formats_test_missing_name_fails() {
        assert!(try_parse(&["test", "formats", "test"]).is_err());
    }

    #[test]
    fn format_handler_json_shape() {
        use artifact_keeper_sdk::types::{FormatHandlerResponse, FormatHandlerType};

        let handler = FormatHandlerResponse {
            capabilities: None,
            created_at: "2026-01-01T00:00:00Z".parse().unwrap(),
            description: Some("Maven repositories".to_string()),
            display_name: "Maven".to_string(),
            extensions: vec!["jar".to_string(), "pom".to_string()],
            format_key: "maven".to_string(),
            handler_type: FormatHandlerType::Core,
            id: uuid::Uuid::nil(),
            is_enabled: true,
            plugin_id: None,
            priority: 10,
            repository_count: Some(3),
            updated_at: "2026-01-02T00:00:00Z".parse().unwrap(),
        };

        let json = format_handler_json(&handler);
        assert_eq!(json["format_key"], "maven");
        assert_eq!(json["handler_type"], "Core");
        assert_eq!(json["is_enabled"], true);
        assert_eq!(json["priority"], 10);
        assert_eq!(json["repository_count"], 3);
        assert_eq!(json["extensions"][0], "jar");

        let table = format_handler_detail_table(&handler);
        assert!(table.contains("Key:           maven"));
        assert!(table.contains("Type:          Core"));
        assert!(table.contains("Enabled:       yes"));
        assert!(table.contains("Extensions:    jar, pom"));
    }

    #[test]
    fn parse_plugins_remove_missing_id_fails() {
        assert!(try_parse(&["test", "plugins", "remove"]).is_err());
    }

    #[test]
    fn parse_plugins_show() {
        let cli = parse(&["test", "plugins", "show", "plugin-id"]);
        if let AdminCommand::Plugins {
            command: PluginsCommand::Show { id },
        } = cli.command
        {
            assert_eq!(id, "plugin-id");
        } else {
            panic!("expected plugins show");
        }
    }

    #[test]
    fn parse_plugins_show_missing_id_fails() {
        assert!(try_parse(&["test", "plugins", "show"]).is_err());
    }

    #[test]
    fn parse_plugins_config_get() {
        let cli = parse(&["test", "plugins", "config", "get", "plugin-id"]);
        if let AdminCommand::Plugins {
            command:
                PluginsCommand::Config {
                    command: PluginConfigCommand::Get { id },
                },
        } = cli.command
        {
            assert_eq!(id, "plugin-id");
        } else {
            panic!("expected plugins config get");
        }
    }

    #[test]
    fn parse_plugins_config_set() {
        let cli = parse(&[
            "test",
            "plugins",
            "config",
            "set",
            "plugin-id",
            "key=value",
            "n=1",
        ]);
        if let AdminCommand::Plugins {
            command:
                PluginsCommand::Config {
                    command:
                        PluginConfigCommand::Set {
                            id,
                            values,
                            config_file,
                        },
                },
        } = cli.command
        {
            assert_eq!(id, "plugin-id");
            assert_eq!(values, vec!["key=value".to_string(), "n=1".to_string()]);
            assert!(config_file.is_none());
        } else {
            panic!("expected plugins config set");
        }
    }

    #[test]
    fn parse_plugins_config_set_with_file() {
        let cli = parse(&[
            "test",
            "plugins",
            "config",
            "set",
            "plugin-id",
            "--config-file",
            "cfg.json",
        ]);
        if let AdminCommand::Plugins {
            command:
                PluginsCommand::Config {
                    command:
                        PluginConfigCommand::Set {
                            id,
                            values,
                            config_file,
                        },
                },
        } = cli.command
        {
            assert_eq!(id, "plugin-id");
            assert!(values.is_empty());
            assert_eq!(config_file.as_deref(), Some("cfg.json"));
        } else {
            panic!("expected plugins config set");
        }
    }

    #[test]
    fn parse_plugins_enable() {
        let cli = parse(&["test", "plugins", "enable", "plugin-id"]);
        assert!(matches!(
            cli.command,
            AdminCommand::Plugins {
                command: PluginsCommand::Enable { .. }
            }
        ));
    }

    #[test]
    fn parse_plugins_disable() {
        let cli = parse(&["test", "plugins", "disable", "plugin-id"]);
        assert!(matches!(
            cli.command,
            AdminCommand::Plugins {
                command: PluginsCommand::Disable { .. }
            }
        ));
    }

    #[test]
    fn parse_plugins_reload() {
        let cli = parse(&["test", "plugins", "reload", "plugin-id"]);
        assert!(matches!(
            cli.command,
            AdminCommand::Plugins {
                command: PluginsCommand::Reload { .. }
            }
        ));
    }

    #[test]
    fn parse_plugins_events() {
        let cli = parse(&["test", "plugins", "events", "plugin-id", "--limit", "5"]);
        if let AdminCommand::Plugins {
            command: PluginsCommand::Events { id, limit },
        } = cli.command
        {
            assert_eq!(id, "plugin-id");
            assert_eq!(limit, Some(5));
        } else {
            panic!("expected plugins events");
        }
    }

    #[test]
    fn parse_plugins_events_default_limit() {
        let cli = parse(&["test", "plugins", "events", "plugin-id"]);
        if let AdminCommand::Plugins {
            command: PluginsCommand::Events { limit, .. },
        } = cli.command
        {
            assert!(limit.is_none());
        } else {
            panic!("expected plugins events");
        }
    }

    #[test]
    fn parse_plugins_install_local() {
        let cli = parse(&["test", "plugins", "install-local", "/path/to/plugin"]);
        if let AdminCommand::Plugins {
            command: PluginsCommand::InstallLocal { path },
        } = cli.command
        {
            assert_eq!(path, "/path/to/plugin");
        } else {
            panic!("expected plugins install-local");
        }
    }

    #[test]
    fn parse_plugins_install_zip() {
        let cli = parse(&["test", "plugins", "install-zip", "/path/plugin.zip"]);
        if let AdminCommand::Plugins {
            command: PluginsCommand::InstallZip { path },
        } = cli.command
        {
            assert_eq!(path, "/path/plugin.zip");
        } else {
            panic!("expected plugins install-zip");
        }
    }

    #[test]
    fn parse_plugins_install_local_missing_path_fails() {
        assert!(try_parse(&["test", "plugins", "install-local"]).is_err());
    }

    #[test]
    fn parse_plugins_install_zip_missing_path_fails() {
        assert!(try_parse(&["test", "plugins", "install-zip"]).is_err());
    }

    // ---- Reindex subcommand parsing ----

    #[test]
    fn parse_reindex() {
        let cli = parse(&["test", "reindex"]);
        assert!(matches!(cli.command, AdminCommand::Reindex));
    }

    // ---- Stats subcommand parsing ----

    #[test]
    fn parse_stats() {
        let cli = parse(&["test", "stats"]);
        assert!(matches!(cli.command, AdminCommand::Stats));
    }

    // ---- Settings subcommand parsing ----

    #[test]
    fn parse_settings_show() {
        let cli = parse(&["test", "settings", "show"]);
        assert!(matches!(
            cli.command,
            AdminCommand::Settings {
                command: SettingsCommand::Show
            }
        ));
    }

    #[test]
    fn parse_settings_update() {
        let cli = parse(&[
            "test",
            "settings",
            "update",
            "--json",
            "{\"retention_days\": 30}",
        ]);
        if let AdminCommand::Settings {
            command: SettingsCommand::Update { json },
        } = cli.command
        {
            assert_eq!(json, "{\"retention_days\": 30}");
        } else {
            panic!("Expected SettingsCommand::Update");
        }
    }

    #[test]
    fn parse_settings_update_missing_json_fails() {
        assert!(try_parse(&["test", "settings", "update"]).is_err());
    }

    #[test]
    fn parse_settings_no_subcommand_fails() {
        assert!(try_parse(&["test", "settings"]).is_err());
    }

    // ---- Telemetry subcommand parsing ----

    #[test]
    fn parse_telemetry_show() {
        let cli = parse(&["test", "telemetry", "show"]);
        assert!(matches!(
            cli.command,
            AdminCommand::Telemetry {
                command: TelemetryCommand::Show
            }
        ));
    }

    #[test]
    fn parse_telemetry_update_no_flags() {
        let cli = parse(&["test", "telemetry", "update"]);
        if let AdminCommand::Telemetry {
            command:
                TelemetryCommand::Update {
                    enabled,
                    include_logs,
                    review_before_send,
                    scrub_level,
                },
        } = cli.command
        {
            assert!(enabled.is_none());
            assert!(include_logs.is_none());
            assert!(review_before_send.is_none());
            assert!(scrub_level.is_none());
        } else {
            panic!("Expected TelemetryCommand::Update");
        }
    }

    #[test]
    fn parse_telemetry_update_all_flags() {
        let cli = parse(&[
            "test",
            "telemetry",
            "update",
            "--enabled",
            "true",
            "--include-logs",
            "false",
            "--review-before-send",
            "true",
            "--scrub-level",
            "full",
        ]);
        if let AdminCommand::Telemetry {
            command:
                TelemetryCommand::Update {
                    enabled,
                    include_logs,
                    review_before_send,
                    scrub_level,
                },
        } = cli.command
        {
            assert_eq!(enabled, Some(true));
            assert_eq!(include_logs, Some(false));
            assert_eq!(review_before_send, Some(true));
            assert_eq!(scrub_level.as_deref(), Some("full"));
        } else {
            panic!("Expected TelemetryCommand::Update");
        }
    }

    #[test]
    fn parse_telemetry_crashes_defaults() {
        let cli = parse(&["test", "telemetry", "crashes"]);
        if let AdminCommand::Telemetry {
            command:
                TelemetryCommand::Crashes {
                    pending,
                    page,
                    per_page,
                },
        } = cli.command
        {
            assert!(!pending);
            assert_eq!(page, 1);
            assert_eq!(per_page, 20);
        } else {
            panic!("Expected TelemetryCommand::Crashes");
        }
    }

    #[test]
    fn parse_telemetry_crashes_with_pending() {
        let cli = parse(&["test", "telemetry", "crashes", "--pending"]);
        if let AdminCommand::Telemetry {
            command:
                TelemetryCommand::Crashes {
                    pending,
                    page,
                    per_page,
                },
        } = cli.command
        {
            assert!(pending);
            assert_eq!(page, 1);
            assert_eq!(per_page, 20);
        } else {
            panic!("Expected TelemetryCommand::Crashes");
        }
    }

    #[test]
    fn parse_telemetry_submit() {
        let cli = parse(&[
            "test",
            "telemetry",
            "submit",
            "00000000-0000-0000-0000-000000000001,00000000-0000-0000-0000-000000000002",
        ]);
        if let AdminCommand::Telemetry {
            command: TelemetryCommand::Submit { ids },
        } = cli.command
        {
            assert!(ids.contains("00000000-0000-0000-0000-000000000001"));
            assert!(ids.contains("00000000-0000-0000-0000-000000000002"));
        } else {
            panic!("Expected TelemetryCommand::Submit");
        }
    }

    #[test]
    fn parse_telemetry_submit_missing_ids_fails() {
        assert!(try_parse(&["test", "telemetry", "submit"]).is_err());
    }

    #[test]
    fn parse_telemetry_no_subcommand_fails() {
        assert!(try_parse(&["test", "telemetry"]).is_err());
    }

    #[test]
    fn parse_telemetry_crash() {
        let cli = parse(&[
            "test",
            "telemetry",
            "crash",
            "00000000-0000-0000-0000-000000000001",
        ]);
        if let AdminCommand::Telemetry {
            command: TelemetryCommand::Crash { id },
        } = cli.command
        {
            assert_eq!(id, "00000000-0000-0000-0000-000000000001");
        } else {
            panic!("Expected TelemetryCommand::Crash");
        }
    }

    #[test]
    fn parse_telemetry_crash_missing_id_fails() {
        assert!(try_parse(&["test", "telemetry", "crash"]).is_err());
    }

    #[test]
    fn parse_telemetry_delete_crash() {
        let cli = parse(&[
            "test",
            "telemetry",
            "delete-crash",
            "00000000-0000-0000-0000-000000000001",
            "--yes",
        ]);
        if let AdminCommand::Telemetry {
            command: TelemetryCommand::DeleteCrash { id, yes },
        } = cli.command
        {
            assert_eq!(id, "00000000-0000-0000-0000-000000000001");
            assert!(yes);
        } else {
            panic!("Expected TelemetryCommand::DeleteCrash");
        }
    }

    #[test]
    fn parse_telemetry_delete_crash_missing_id_fails() {
        assert!(try_parse(&["test", "telemetry", "delete-crash"]).is_err());
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
    fn format_plugin_config_renders() {
        let mut config = serde_json::Map::new();
        config.insert("api_key".to_string(), json!("secret"));
        config.insert("retries".to_string(), json!(3));
        let table = format_plugin_config(&config);
        assert!(table.contains("KEY"));
        assert!(table.contains("api_key"));
        assert!(table.contains("secret"));
        assert!(table.contains("retries"));
        assert!(table.contains('3'));
    }

    #[test]
    fn format_plugin_config_empty() {
        let config = serde_json::Map::new();
        let table = format_plugin_config(&config);
        assert!(table.contains("no configuration"));
    }

    #[test]
    fn format_plugin_events_renders() {
        let events = vec![
            json!({
                "event_type": "installed",
                "status": "success",
                "message": "Plugin installed",
                "created_at": "2026-01-15T10:00:00Z"
            }),
            json!({
                "type": "reloaded",
                "status": "success",
                "message": "hot reload",
                "timestamp": "2026-01-16T10:00:00Z"
            }),
        ];
        let table = format_plugin_events(&events);
        assert!(table.contains("EVENT"));
        assert!(table.contains("installed"));
        assert!(table.contains("reloaded"));
        assert!(table.contains("hot reload"));
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

    // ========================================================================
    // Wiremock-based handler tests
    // ========================================================================

    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, ResponseTemplate};

    #[tokio::test]
    async fn handler_list_backups_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/admin/backups"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [],
                "total": 0
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list_backups(1, 20, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_backups_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/admin/backups"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{
                    "id": "00000000-0000-0000-0000-000000000001",
                    "status": "completed",
                    "type": "full",
                    "artifact_count": 42,
                    "size_bytes": 1073741824_i64,
                    "created_at": "2026-01-15T10:00:00Z",
                    "completed_at": "2026-01-15T10:30:00Z",
                    "error_message": null
                }],
                "total": 1_i64
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list_backups(1, 20, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_create_backup() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/admin/backups"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "00000000-0000-0000-0000-000000000001",
                "status": "in_progress",
                "type": "full",
                "artifact_count": 0_i64,
                "size_bytes": 0_i64,
                "created_at": "2026-01-15T10:00:00Z",
                "completed_at": null,
                "error_message": null
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = create_backup("full", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_run_cleanup() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/admin/cleanup"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "audit_logs_deleted": 100,
                "backups_deleted": 3,
                "peers_marked_offline": 1,
                "stale_uploads_deleted": 0
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = run_cleanup(true, true, true, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_metrics() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/admin/stats"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "total_artifacts": 1500,
                "total_downloads": 50000,
                "total_repositories": 25,
                "total_storage_bytes": 13421772800_i64,
                "total_users": 100,
                "active_peers": 3,
                "pending_sync_tasks": 0
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = show_metrics(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_users_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/users"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [],
                "pagination": { "page": 1, "per_page": 20, "total": 0_i64, "total_pages": 0 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list_users(None, 1, 20, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_users_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/users"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{
                    "id": "00000000-0000-0000-0000-000000000001",
                    "username": "alice",
                    "email": "alice@example.com",
                    "display_name": "Alice Smith",
                    "is_admin": true,
                    "is_active": true,
                    "must_change_password": false,
                    "auth_provider": "local",
                    "created_at": "2026-01-15T10:00:00Z"
                }],
                "pagination": { "page": 1, "per_page": 20, "total": 1_i64, "total_pages": 1 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list_users(None, 1, 20, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_create_user() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/users"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "user": {
                    "id": "00000000-0000-0000-0000-000000000001",
                    "username": "bob",
                    "email": "bob@example.com",
                    "display_name": null,
                    "is_admin": false,
                    "is_active": true,
                    "must_change_password": true,
                    "auth_provider": "local",
                    "created_at": "2026-01-15T10:00:00Z"
                },
                "generated_password": "temp-pass-123"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = create_user("bob", "bob@example.com", None, false, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_update_user() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("PATCH"))
            .and(path_regex("/api/v1/users/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "00000000-0000-0000-0000-000000000001",
                "username": "alice",
                "email": "new@example.com",
                "display_name": "Alice Updated",
                "is_admin": true,
                "is_active": true,
                "must_change_password": false,
                "auth_provider": "local",
                "created_at": "2026-01-15T10:00:00Z"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = update_user(
            "00000000-0000-0000-0000-000000000001",
            Some("new@example.com"),
            None,
            None,
            None,
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_delete_user() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path_regex("/api/v1/users/.+"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = delete_user("00000000-0000-0000-0000-000000000001", true, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_reset_password() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path_regex("/api/v1/users/.+/password/reset"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "temporary_password": "new-temp-pass-456"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = reset_password("00000000-0000-0000-0000-000000000001", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_user() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/users/00000000-0000-0000-0000-000000000001"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "00000000-0000-0000-0000-000000000001",
                "username": "bob",
                "email": "bob@example.com",
                "display_name": "Bob",
                "is_admin": false,
                "is_active": true,
                "auth_provider": "local",
                "must_change_password": false,
                "created_at": "2026-01-01T00:00:00Z",
                "last_login_at": null
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = show_user("00000000-0000-0000-0000-000000000001", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_force_password_change() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path_regex("/api/v1/users/.+/force-password-change"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": "User will be prompted to change password on next login."
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = force_password_change("00000000-0000-0000-0000-000000000001", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_user_roles() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/users/.+/roles"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{
                    "id": "00000000-0000-0000-0000-000000000002",
                    "name": "admin",
                    "description": "Administrator",
                    "permissions": ["users:read", "users:write"]
                }]
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list_user_roles("00000000-0000-0000-0000-000000000001", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_assign_role() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path_regex("/api/v1/users/.+/roles"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = assign_role(
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_revoke_role() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path_regex("/api/v1/users/.+/roles/.+"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = revoke_role(
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_user_tokens() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/users/.+/tokens"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{
                    "id": "00000000-0000-0000-0000-000000000003",
                    "name": "ci-token",
                    "token_prefix": "ak_",
                    "scopes": ["read"],
                    "created_at": "2026-01-01T00:00:00Z",
                    "expires_at": null,
                    "last_used_at": null
                }]
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list_user_tokens("00000000-0000-0000-0000-000000000001", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_create_user_token() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path_regex("/api/v1/users/.+/tokens"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "00000000-0000-0000-0000-000000000003",
                "name": "ci-token",
                "token": "ak_secret789"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = create_user_token(
            "00000000-0000-0000-0000-000000000001",
            "ci-token",
            Some("read"),
            None,
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_revoke_user_token() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path_regex("/api/v1/users/.+/tokens/.+"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = revoke_user_token(
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000003",
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_plugins_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/plugins"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": []
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list_plugins(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_plugins_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/plugins"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{
                    "id": "00000000-0000-0000-0000-000000000001",
                    "name": "unity-format",
                    "display_name": "Unity Format",
                    "version": "1.0.0",
                    "plugin_type": "format",
                    "status": "active",
                    "config_schema": {},
                    "author": "AK Team",
                    "installed_at": "2026-01-15T10:00:00Z"
                }]
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list_plugins(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_install_plugin() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/plugins/install/git"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "plugin_id": "00000000-0000-0000-0000-000000000001",
                "name": "unity-format",
                "version": "1.0.0",
                "format_key": "unity",
                "message": "Plugin installed successfully"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = install_plugin("https://github.com/example/plugin.git", None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_remove_plugin() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path_regex("/api/v1/plugins/.+"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = remove_plugin("00000000-0000-0000-0000-000000000001", true, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_plugin() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/plugins/[^/]+$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "00000000-0000-0000-0000-000000000001",
                "name": "unity-format",
                "display_name": "Unity Format",
                "version": "1.0.0",
                "plugin_type": "format",
                "status": "active",
                "config_schema": {},
                "author": "AK Team",
                "installed_at": "2026-01-15T10:00:00Z"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = show_plugin("00000000-0000-0000-0000-000000000001", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_get_plugin_config() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/plugins/.+/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "plugin_id": "00000000-0000-0000-0000-000000000001",
                "config": { "api_key": "secret", "retries": 3 },
                "schema": {}
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = get_plugin_config("00000000-0000-0000-0000-000000000001", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_set_plugin_config() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path_regex("/api/v1/plugins/.+/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "plugin_id": "00000000-0000-0000-0000-000000000001",
                "config": { "api_key": "new", "retries": 5 },
                "schema": {}
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let values = vec!["api_key=new".to_string(), "retries=5".to_string()];
        let result = set_plugin_config(
            "00000000-0000-0000-0000-000000000001",
            &values,
            None,
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_set_plugin_config_no_input_fails() {
        let (_server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result =
            set_plugin_config("00000000-0000-0000-0000-000000000001", &[], None, &global).await;
        assert!(result.is_err());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_enable_plugin() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path_regex("/api/v1/plugins/.+/enable"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result =
            set_plugin_enabled("00000000-0000-0000-0000-000000000001", true, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_disable_plugin() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path_regex("/api/v1/plugins/.+/disable"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result =
            set_plugin_enabled("00000000-0000-0000-0000-000000000001", false, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_reload_plugin() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path_regex("/api/v1/plugins/.+/reload"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "00000000-0000-0000-0000-000000000001",
                "name": "unity-format",
                "display_name": "Unity Format",
                "version": "1.0.0",
                "plugin_type": "format",
                "status": "active",
                "source_type": "git",
                "capabilities": {},
                "resource_limits": {},
                "installed_at": "2026-01-15T10:00:00Z",
                "updated_at": "2026-01-16T10:00:00Z"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = reload_plugin("00000000-0000-0000-0000-000000000001", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_plugin_events() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/plugins/.+/events"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {
                    "event_type": "installed",
                    "status": "success",
                    "message": "Plugin installed",
                    "created_at": "2026-01-15T10:00:00Z"
                }
            ])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Table);
        let result = plugin_events("00000000-0000-0000-0000-000000000001", Some(10), &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_plugin_events_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/plugins/.+/events"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = plugin_events("00000000-0000-0000-0000-000000000001", None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_install_plugin_local() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/plugins/install/local"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "plugin_id": "00000000-0000-0000-0000-000000000001",
                "name": "unity-format",
                "version": "1.0.0",
                "format_key": "unity",
                "message": "Plugin installed successfully"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = install_plugin_local("/opt/plugins/unity", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_install_plugin_zip() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/plugins/install/zip"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "plugin_id": "00000000-0000-0000-0000-000000000001",
                "name": "unity-format",
                "version": "1.0.0",
                "format_key": "unity",
                "message": "Plugin installed successfully from ZIP"
            })))
            .mount(&server)
            .await;

        let zip_path = tmp.path().join("plugin.zip");
        std::fs::write(&zip_path, b"PK\x03\x04 fake zip bytes").unwrap();

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = install_plugin_zip(zip_path.to_str().unwrap(), &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_install_plugin_zip_missing_file_fails() {
        let (_server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = install_plugin_zip("/nonexistent/path/plugin.zip", &global).await;
        assert!(result.is_err());
        crate::test_utils::teardown_env();
    }

    // ---- Format function tests for telemetry / crashes ----

    #[test]
    fn format_telemetry_settings_renders() {
        let settings = artifact_keeper_sdk::types::TelemetrySettings {
            enabled: true,
            include_logs: false,
            review_before_send: true,
            scrub_level: "full".to_string(),
        };
        let output = format_telemetry_settings(&settings);
        assert!(output.contains("Enabled:"));
        assert!(output.contains("true"));
        assert!(output.contains("Include Logs:"));
        assert!(output.contains("false"));
        assert!(output.contains("Review Before Send:"));
        assert!(output.contains("Scrub Level:"));
        assert!(output.contains("full"));
    }

    #[test]
    fn format_telemetry_settings_disabled() {
        let settings = artifact_keeper_sdk::types::TelemetrySettings {
            enabled: false,
            include_logs: false,
            review_before_send: false,
            scrub_level: "none".to_string(),
        };
        let output = format_telemetry_settings(&settings);
        assert!(output.contains("Enabled:"));
        // The "false" for enabled should appear
        let false_count = output.matches("false").count();
        assert!(false_count >= 3);
        assert!(output.contains("none"));
    }

    #[test]
    fn format_crashes_table_empty() {
        let items: Vec<artifact_keeper_sdk::types::CrashReport> = vec![];
        let table = format_crashes_table(&items);
        assert!(table.contains("ID"));
        assert!(table.contains("SEVERITY"));
        assert!(table.contains("TYPE"));
        assert!(table.contains("COMPONENT"));
    }

    #[test]
    fn format_crashes_table_with_data() {
        use chrono::Utc;
        let items = vec![artifact_keeper_sdk::types::CrashReport {
            id: uuid::Uuid::parse_str("12345678-abcd-1234-abcd-123456789012").unwrap(),
            severity: "critical".to_string(),
            error_type: "panic".to_string(),
            error_message: "index out of bounds".to_string(),
            component: "storage".to_string(),
            app_version: "1.0.0".to_string(),
            occurrence_count: 5,
            submitted: false,
            created_at: Utc::now(),
            first_seen_at: Utc::now(),
            last_seen_at: Utc::now(),
            error_signature: "abc123".to_string(),
            context: serde_json::Map::new(),
            os_info: None,
            stack_trace: None,
            submission_error: None,
            submitted_at: None,
            uptime_seconds: None,
        }];
        let table = format_crashes_table(&items);
        assert!(table.contains("12345678"));
        assert!(table.contains("critical"));
        assert!(table.contains("panic"));
        assert!(table.contains("storage"));
        assert!(table.contains("5"));
        assert!(table.contains("no"));
    }

    #[test]
    fn format_crashes_table_submitted() {
        use chrono::Utc;
        let items = vec![artifact_keeper_sdk::types::CrashReport {
            id: uuid::Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap(),
            severity: "warning".to_string(),
            error_type: "timeout".to_string(),
            error_message: "request timed out".to_string(),
            component: "api".to_string(),
            app_version: "1.1.0".to_string(),
            occurrence_count: 1,
            submitted: true,
            created_at: Utc::now(),
            first_seen_at: Utc::now(),
            last_seen_at: Utc::now(),
            error_signature: "def456".to_string(),
            context: serde_json::Map::new(),
            os_info: Some("Linux 5.15".to_string()),
            stack_trace: None,
            submission_error: None,
            submitted_at: Some(Utc::now()),
            uptime_seconds: Some(3600),
        }];
        let table = format_crashes_table(&items);
        assert!(table.contains("aaaaaaaa"));
        assert!(table.contains("warning"));
        assert!(table.contains("yes"));
    }

    // ---- Wiremock handler tests for new subcommands ----

    #[tokio::test]
    async fn handler_trigger_reindex() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/admin/reindex"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": "Reindex completed",
                "status": "completed"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = trigger_reindex(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_stats() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/admin/stats"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "total_artifacts": 1500,
                "total_downloads": 50000,
                "total_repositories": 25,
                "total_storage_bytes": 13421772800_i64,
                "total_users": 100,
                "active_peers": 3,
                "pending_sync_tasks": 0
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = show_stats(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_settings() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/admin/settings"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "allow_anonymous_download": false,
                "audit_retention_days": 90,
                "backup_retention_count": 5,
                "edge_stale_threshold_minutes": 30,
                "max_upload_size_bytes": 1073741824_i64,
                "retention_days": 365,
                "storage_backend": "filesystem",
                "storage_path": "/data/artifacts"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = show_settings(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_update_settings() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/admin/settings"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "allow_anonymous_download": true,
                "audit_retention_days": 60,
                "backup_retention_count": 3,
                "edge_stale_threshold_minutes": 15,
                "max_upload_size_bytes": 536870912_i64,
                "retention_days": 180,
                "storage_backend": "filesystem",
                "storage_path": "/data/artifacts"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let json_str = r#"{"allow_anonymous_download":true,"audit_retention_days":60,"backup_retention_count":3,"edge_stale_threshold_minutes":15,"max_upload_size_bytes":536870912,"retention_days":180,"storage_backend":"filesystem","storage_path":"/data/artifacts"}"#;
        let result = update_settings(json_str, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_telemetry() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/admin/telemetry/settings"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "enabled": true,
                "include_logs": false,
                "review_before_send": true,
                "scrub_level": "full"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = show_telemetry(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_update_telemetry() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        // The update handler first fetches current settings, then posts the update
        Mock::given(method("GET"))
            .and(path("/api/v1/admin/telemetry/settings"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "enabled": true,
                "include_logs": false,
                "review_before_send": true,
                "scrub_level": "full"
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/v1/admin/telemetry/settings"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "enabled": false,
                "include_logs": true,
                "review_before_send": false,
                "scrub_level": "minimal"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = update_telemetry(
            Some(false),
            Some(true),
            Some(false),
            Some("minimal".to_string()),
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_crashes() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/admin/telemetry/crashes"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{
                    "id": "00000000-0000-0000-0000-000000000001",
                    "severity": "critical",
                    "error_type": "panic",
                    "error_message": "index out of bounds",
                    "error_signature": "abc123",
                    "component": "storage",
                    "app_version": "1.0.0",
                    "occurrence_count": 5,
                    "submitted": false,
                    "context": {},
                    "created_at": "2026-01-15T10:00:00Z",
                    "first_seen_at": "2026-01-15T10:00:00Z",
                    "last_seen_at": "2026-01-15T12:00:00Z"
                }],
                "total": 1_i64
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list_crashes(false, 1, 20, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_submit_crashes() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/admin/telemetry/crashes/submit"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "marked_submitted": 2
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = submit_crashes(
            "00000000-0000-0000-0000-000000000001,00000000-0000-0000-0000-000000000002",
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    // ---- Backup detail subcommand parsing ----

    #[test]
    fn parse_backup_get() {
        let cli = parse(&["test", "backup", "get", "abc123"]);
        assert!(matches!(
            cli.command,
            AdminCommand::Backup {
                command: BackupCommand::Get { .. }
            }
        ));
    }

    #[test]
    fn parse_backup_delete_with_yes() {
        let cli = parse(&["test", "backup", "delete", "abc123", "--yes"]);
        if let AdminCommand::Backup {
            command: BackupCommand::Delete { id, yes },
        } = cli.command
        {
            assert_eq!(id, "abc123");
            assert!(yes);
        } else {
            panic!("Expected BackupCommand::Delete");
        }
    }

    #[test]
    fn parse_backup_cancel() {
        let cli = parse(&["test", "backup", "cancel", "abc123"]);
        assert!(matches!(
            cli.command,
            AdminCommand::Backup {
                command: BackupCommand::Cancel { .. }
            }
        ));
    }

    #[test]
    fn parse_backup_execute() {
        let cli = parse(&["test", "backup", "execute", "abc123"]);
        assert!(matches!(
            cli.command,
            AdminCommand::Backup {
                command: BackupCommand::Execute { .. }
            }
        ));
    }

    // ---- CI OIDC provider parsing ----

    #[test]
    fn parse_ci_oidc_list() {
        let cli = parse(&["test", "ci-oidc", "list"]);
        assert!(matches!(
            cli.command,
            AdminCommand::CiOidc {
                command: CiOidcCommand::List
            }
        ));
    }

    #[test]
    fn parse_ci_oidc_create() {
        let cli = parse(&[
            "test",
            "ci-oidc",
            "create",
            "gh",
            "https://token.actions.githubusercontent.com",
            "--audience",
            "ak",
            "--provider-type",
            "github",
            "--enabled",
        ]);
        if let AdminCommand::CiOidc {
            command:
                CiOidcCommand::Create {
                    name,
                    issuer_url,
                    audience,
                    provider_type,
                    enabled,
                },
        } = cli.command
        {
            assert_eq!(name, "gh");
            assert_eq!(issuer_url, "https://token.actions.githubusercontent.com");
            assert_eq!(audience.as_deref(), Some("ak"));
            assert_eq!(provider_type.as_deref(), Some("github"));
            assert!(enabled);
        } else {
            panic!("Expected CiOidcCommand::Create");
        }
    }

    #[test]
    fn parse_ci_oidc_create_missing_issuer_fails() {
        let result = try_parse(&["test", "ci-oidc", "create", "gh"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_ci_oidc_get() {
        let cli = parse(&["test", "ci-oidc", "get", "pid"]);
        assert!(matches!(
            cli.command,
            AdminCommand::CiOidc {
                command: CiOidcCommand::Get { .. }
            }
        ));
    }

    #[test]
    fn parse_ci_oidc_update() {
        let cli = parse(&[
            "test",
            "ci-oidc",
            "update",
            "pid",
            "--name",
            "new",
            "--enabled",
            "false",
        ]);
        if let AdminCommand::CiOidc {
            command: CiOidcCommand::Update {
                id, name, enabled, ..
            },
        } = cli.command
        {
            assert_eq!(id, "pid");
            assert_eq!(name.as_deref(), Some("new"));
            assert_eq!(enabled, Some(false));
        } else {
            panic!("Expected CiOidcCommand::Update");
        }
    }

    #[test]
    fn parse_ci_oidc_delete() {
        let cli = parse(&["test", "ci-oidc", "delete", "pid", "--yes"]);
        assert!(matches!(
            cli.command,
            AdminCommand::CiOidc {
                command: CiOidcCommand::Delete { .. }
            }
        ));
    }

    #[test]
    fn parse_ci_oidc_toggle_requires_value() {
        let cli = parse(&["test", "ci-oidc", "toggle", "pid", "--enabled", "true"]);
        if let AdminCommand::CiOidc {
            command: CiOidcCommand::Toggle { id, enabled },
        } = cli.command
        {
            assert_eq!(id, "pid");
            assert!(enabled);
        } else {
            panic!("Expected CiOidcCommand::Toggle");
        }
        // --enabled with no value must fail (ArgAction::Set)
        assert!(try_parse(&["test", "ci-oidc", "toggle", "pid", "--enabled"]).is_err());
    }

    // ---- CI OIDC mapping parsing ----

    #[test]
    fn parse_ci_oidc_mapping_list() {
        let cli = parse(&["test", "ci-oidc", "mapping", "list", "pid"]);
        assert!(matches!(
            cli.command,
            AdminCommand::CiOidc {
                command: CiOidcCommand::Mapping {
                    command: CiOidcMappingCommand::List { .. }
                }
            }
        ));
    }

    #[test]
    fn parse_ci_oidc_mapping_create() {
        let cli = parse(&[
            "test",
            "ci-oidc",
            "mapping",
            "create",
            "pid",
            "ci-map",
            "--claim-filters",
            "{\"repository\":\"acme/app\"}",
            "--priority",
            "10",
            "--allowed-repo-ids",
            "00000000-0000-0000-0000-000000000001,00000000-0000-0000-0000-000000000002",
            "--enabled",
        ]);
        if let AdminCommand::CiOidc {
            command:
                CiOidcCommand::Mapping {
                    command:
                        CiOidcMappingCommand::Create {
                            provider_id,
                            name,
                            claim_filters,
                            priority,
                            allowed_repo_ids,
                            enabled,
                        },
                },
        } = cli.command
        {
            assert_eq!(provider_id, "pid");
            assert_eq!(name, "ci-map");
            assert_eq!(claim_filters, "{\"repository\":\"acme/app\"}");
            assert_eq!(priority, Some(10));
            assert!(allowed_repo_ids.is_some());
            assert!(enabled);
        } else {
            panic!("Expected CiOidcMappingCommand::Create");
        }
    }

    #[test]
    fn parse_ci_oidc_mapping_create_default_filters() {
        let cli = parse(&["test", "ci-oidc", "mapping", "create", "pid", "m"]);
        if let AdminCommand::CiOidc {
            command:
                CiOidcCommand::Mapping {
                    command: CiOidcMappingCommand::Create { claim_filters, .. },
                },
        } = cli.command
        {
            assert_eq!(claim_filters, "{}");
        } else {
            panic!("Expected CiOidcMappingCommand::Create");
        }
    }

    #[test]
    fn parse_ci_oidc_mapping_toggle() {
        let cli = parse(&[
            "test",
            "ci-oidc",
            "mapping",
            "toggle",
            "pid",
            "mid",
            "--enabled",
            "false",
        ]);
        if let AdminCommand::CiOidc {
            command:
                CiOidcCommand::Mapping {
                    command: CiOidcMappingCommand::Toggle { enabled, .. },
                },
        } = cli.command
        {
            assert!(!enabled);
        } else {
            panic!("Expected CiOidcMappingCommand::Toggle");
        }
    }

    // ---- parse_repo_ids helper ----

    #[test]
    fn parse_repo_ids_none() {
        assert!(parse_repo_ids(None).unwrap().is_none());
    }

    #[test]
    fn parse_repo_ids_valid_csv() {
        let out = parse_repo_ids(Some(
            "00000000-0000-0000-0000-000000000001, 00000000-0000-0000-0000-000000000002",
        ))
        .unwrap()
        .unwrap();
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn parse_repo_ids_skips_empty() {
        let out = parse_repo_ids(Some("00000000-0000-0000-0000-000000000001,,"))
            .unwrap()
            .unwrap();
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn parse_repo_ids_invalid_fails() {
        assert!(parse_repo_ids(Some("not-a-uuid")).is_err());
    }

    // ---- Storage GC / backends parsing ----

    #[test]
    fn parse_storage_gc_run() {
        let cli = parse(&["test", "storage-gc", "run", "--dry-run"]);
        if let AdminCommand::StorageGc {
            command: StorageGcCommand::Run { dry_run },
        } = cli.command
        {
            assert!(dry_run);
        } else {
            panic!("Expected StorageGcCommand::Run");
        }
    }

    #[test]
    fn parse_storage_gc_oci_report() {
        let cli = parse(&["test", "storage-gc", "oci-report", "--grace-hours", "48"]);
        if let AdminCommand::StorageGc {
            command: StorageGcCommand::OciReport { grace_hours },
        } = cli.command
        {
            assert_eq!(grace_hours, Some(48));
        } else {
            panic!("Expected StorageGcCommand::OciReport");
        }
    }

    #[test]
    fn parse_storage_backends() {
        let cli = parse(&["test", "storage-backends"]);
        assert!(matches!(cli.command, AdminCommand::StorageBackends));
    }

    // ---- Reindex / rescan / smtp parsing ----

    #[test]
    fn parse_search_reindex() {
        let cli = parse(&["test", "search-reindex"]);
        assert!(matches!(cli.command, AdminCommand::SearchReindex));
    }

    #[test]
    fn parse_rescan_with_limit() {
        let cli = parse(&["test", "rescan", "--limit", "500"]);
        if let AdminCommand::Rescan { limit } = cli.command {
            assert_eq!(limit, Some(500));
        } else {
            panic!("Expected AdminCommand::Rescan");
        }
    }

    #[test]
    fn parse_smtp_test() {
        let cli = parse(&["test", "smtp-test", "ops@example.com"]);
        if let AdminCommand::SmtpTest { to } = cli.command {
            assert_eq!(to, "ops@example.com");
        } else {
            panic!("Expected AdminCommand::SmtpTest");
        }
    }

    #[test]
    fn parse_smtp_test_missing_recipient_fails() {
        assert!(try_parse(&["test", "smtp-test"]).is_err());
    }

    // ---- Remote instance / proxy parsing ----

    #[test]
    fn parse_instance_list() {
        let cli = parse(&["test", "instance", "list"]);
        assert!(matches!(
            cli.command,
            AdminCommand::Instance {
                command: RemoteInstanceCommand::List
            }
        ));
    }

    #[test]
    fn parse_instance_create() {
        let cli = parse(&[
            "test",
            "instance",
            "create",
            "east",
            "https://east.example.com",
            "--api-key",
            "secret",
        ]);
        if let AdminCommand::Instance {
            command: RemoteInstanceCommand::Create { name, url, api_key },
        } = cli.command
        {
            assert_eq!(name, "east");
            assert_eq!(url, "https://east.example.com");
            assert_eq!(api_key, "secret");
        } else {
            panic!("Expected RemoteInstanceCommand::Create");
        }
    }

    #[test]
    fn parse_instance_create_missing_api_key_fails() {
        let result = try_parse(&[
            "test",
            "instance",
            "create",
            "east",
            "https://east.example.com",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_instance_delete() {
        let cli = parse(&["test", "instance", "delete", "iid", "--yes"]);
        assert!(matches!(
            cli.command,
            AdminCommand::Instance {
                command: RemoteInstanceCommand::Delete { .. }
            }
        ));
    }

    #[test]
    fn parse_instance_proxy_get() {
        let cli = parse(&["test", "instance", "proxy", "get", "iid", "v1/repositories"]);
        if let AdminCommand::Instance {
            command:
                RemoteInstanceCommand::Proxy {
                    command: ProxyCommand::Get { id, path },
                },
        } = cli.command
        {
            assert_eq!(id, "iid");
            assert_eq!(path, "v1/repositories");
        } else {
            panic!("Expected ProxyCommand::Get");
        }
    }

    #[test]
    fn parse_instance_proxy_post_with_body() {
        let cli = parse(&[
            "test",
            "instance",
            "proxy",
            "post",
            "iid",
            "v1/x",
            "--body",
            "{\"k\":1}",
        ]);
        if let AdminCommand::Instance {
            command:
                RemoteInstanceCommand::Proxy {
                    command: ProxyCommand::Post { body, .. },
                },
        } = cli.command
        {
            assert_eq!(body.as_deref(), Some("{\"k\":1}"));
        } else {
            panic!("Expected ProxyCommand::Post");
        }
    }

    #[tokio::test]
    async fn handler_get_crash() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path(
                "/api/v1/admin/telemetry/crashes/00000000-0000-0000-0000-000000000001",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "00000000-0000-0000-0000-000000000001",
                "severity": "critical",
                "error_type": "panic",
                "error_message": "index out of bounds",
                "error_signature": "abc123",
                "component": "storage",
                "app_version": "1.0.0",
                "occurrence_count": 5,
                "submitted": false,
                "context": {},
                "created_at": "2026-01-15T10:00:00Z",
                "first_seen_at": "2026-01-15T10:00:00Z",
                "last_seen_at": "2026-01-15T12:00:00Z"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = get_crash("00000000-0000-0000-0000-000000000001", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_get_crash_invalid_id() {
        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = get_crash("not-a-uuid", &global).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handler_delete_crash() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path(
                "/api/v1/admin/telemetry/crashes/00000000-0000-0000-0000-000000000001",
            ))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = delete_crash("00000000-0000-0000-0000-000000000001", true, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_delete_crash_invalid_id() {
        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = delete_crash("not-a-uuid", true, &global).await;
        assert!(result.is_err());
    }

    // ---- insta snapshot tests ----

    #[test]
    fn snapshot_admin_user_list_json() {
        let data = json!([{
            "id": "00000000-0000-0000-0000-000000000001",
            "username": "alice",
            "email": "alice@example.com",
            "display_name": "Alice Smith",
            "is_admin": true,
            "is_active": true,
            "created_at": "2026-01-01T00:00:00Z",
            "last_login_at": "2026-01-20T10:30:00Z"
        }]);
        let output = crate::output::render(&data, &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("admin_user_list_json", parsed);
    }

    #[test]
    fn snapshot_admin_user_list_table() {
        let items = vec![json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "username": "alice",
            "email": "alice@example.com",
            "display_name": "Alice Smith",
            "is_admin": true,
            "is_active": true,
            "created_at": "2026-01-01T00:00:00Z",
            "last_login_at": "2026-01-20T10:30:00Z"
        })];
        let table = format_users_table(&items);
        insta::assert_snapshot!("admin_user_list_table", table);
    }
}
