//! Import artifacts into Artifact Keeper from a legacy registry.
//!
//! This drives the **migration/import** subsystem (`/api/v1/migrations`), which
//! imports content from an external legacy registry such as JFrog Artifactory or
//! Sonatype Nexus. It is distinct from the top-level `ak migrate` command, which
//! bulk-copies artifacts between two Artifact Keeper *instances*.
//!
//! The workflow is: register a source connection, create an import job against
//! that connection, run a pre-migration assessment, start/pause/resume/cancel the
//! job, watch progress, and finally review the reconciliation report.

use artifact_keeper_sdk::ClientMigrationExt;
use clap::Subcommand;
use futures::StreamExt;
use miette::Result;
use reqwest::header::AUTHORIZATION;
use serde::de::DeserializeOwned;

use super::client::{client_for, resolve_base_url_and_auth};
use super::helpers::{confirm_action, new_table, parse_uuid, sdk_err, short_id};
use crate::cli::GlobalArgs;
use crate::output::{self, OutputFormat, format_bytes};

#[derive(Subcommand)]
pub enum ImportCommand {
    /// Manage legacy source connections (Artifactory / Nexus)
    Source {
        #[command(subcommand)]
        command: ImportSourceCommand,
    },

    /// Manage import jobs
    Job {
        #[command(subcommand)]
        command: ImportJobCommand,
    },

    /// Run a pre-migration assessment for a job
    Assess {
        /// Import job ID
        job_id: String,
    },

    /// Show the results of a completed assessment
    Assessment {
        /// Import job ID
        job_id: String,
    },

    /// Show the reconciliation report for a job
    Reconcile {
        /// Import job ID
        job_id: String,

        /// Report format (e.g. json, html)
        #[arg(long = "report-format", id = "report_format")]
        format: Option<String>,
    },

    /// Stream live progress events for a running job (Server-Sent Events)
    Progress {
        /// Import job ID
        job_id: String,
    },
}

#[derive(Subcommand)]
pub enum ImportSourceCommand {
    /// Register a new source connection
    Add {
        /// Human-readable connection name
        name: String,

        /// Base URL of the legacy registry
        url: String,

        /// Authentication type: api_token (default) or basic_auth
        #[arg(long, default_value = "api_token")]
        auth_type: String,

        /// Source registry type: artifactory (default) or nexus
        #[arg(long)]
        source_type: Option<String>,

        /// Username for basic auth
        #[arg(long)]
        username: Option<String>,

        /// Password for basic auth
        #[arg(long)]
        password: Option<String>,

        /// API token for token auth
        #[arg(long)]
        token: Option<String>,
    },

    /// List all source connections
    List,

    /// Show a source connection
    Show {
        /// Connection ID
        id: String,
    },

    /// Test connectivity to a source connection
    Test {
        /// Connection ID
        id: String,
    },

    /// List repositories available on the source registry
    Repos {
        /// Connection ID
        id: String,
    },

    /// Delete a source connection
    Delete {
        /// Connection ID
        id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
pub enum ImportJobCommand {
    /// Create a new import job
    Create {
        /// Source connection ID
        source: String,

        /// Job type (e.g. full, incremental)
        #[arg(long)]
        job_type: Option<String>,

        /// Job configuration as a JSON object (defaults to `{}`)
        #[arg(long, default_value = "{}")]
        config: String,
    },

    /// List import jobs
    List {
        /// Filter by status
        #[arg(long)]
        status: Option<String>,

        /// Page number
        #[arg(long, default_value = "1")]
        page: i32,

        /// Results per page
        #[arg(long, default_value = "50")]
        per_page: i32,
    },

    /// Show an import job
    Show {
        /// Import job ID
        id: String,
    },

    /// Delete an import job
    Delete {
        /// Import job ID
        id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Start an import job
    Start {
        /// Import job ID
        id: String,
    },

    /// Pause a running import job
    Pause {
        /// Import job ID
        id: String,
    },

    /// Resume a paused import job
    Resume {
        /// Import job ID
        id: String,
    },

    /// Cancel an import job
    Cancel {
        /// Import job ID
        id: String,
    },

    /// List the individual items in an import job
    Items {
        /// Import job ID
        id: String,

        /// Filter by item type
        #[arg(long)]
        item_type: Option<String>,

        /// Filter by status
        #[arg(long)]
        status: Option<String>,

        /// Page number
        #[arg(long, default_value = "1")]
        page: i32,

        /// Results per page
        #[arg(long, default_value = "50")]
        per_page: i32,
    },
}

impl ImportCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Source { command } => command.execute(global).await,
            Self::Job { command } => command.execute(global).await,
            Self::Assess { job_id } => run_assessment(&job_id, global).await,
            Self::Assessment { job_id } => get_assessment(&job_id, global).await,
            Self::Reconcile { job_id, format } => {
                reconcile(&job_id, format.as_deref(), global).await
            }
            Self::Progress { job_id } => progress(&job_id, global).await,
        }
    }
}

impl ImportSourceCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Add {
                name,
                url,
                auth_type,
                source_type,
                username,
                password,
                token,
            } => {
                source_add(
                    &name,
                    &url,
                    &auth_type,
                    source_type.as_deref(),
                    username.as_deref(),
                    password.as_deref(),
                    token.as_deref(),
                    global,
                )
                .await
            }
            Self::List => source_list(global).await,
            Self::Show { id } => source_show(&id, global).await,
            Self::Test { id } => source_test(&id, global).await,
            Self::Repos { id } => source_repos(&id, global).await,
            Self::Delete { id, yes } => source_delete(&id, yes, global).await,
        }
    }
}

impl ImportJobCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Create {
                source,
                job_type,
                config,
            } => job_create(&source, job_type.as_deref(), &config, global).await,
            Self::List {
                status,
                page,
                per_page,
            } => job_list(status.as_deref(), page, per_page, global).await,
            Self::Show { id } => job_show(&id, global).await,
            Self::Delete { id, yes } => job_delete(&id, yes, global).await,
            Self::Start { id } => job_transition(&id, JobAction::Start, global).await,
            Self::Pause { id } => job_transition(&id, JobAction::Pause, global).await,
            Self::Resume { id } => job_transition(&id, JobAction::Resume, global).await,
            Self::Cancel { id } => job_transition(&id, JobAction::Cancel, global).await,
            Self::Items {
                id,
                item_type,
                status,
                page,
                per_page,
            } => {
                job_items(
                    &id,
                    item_type.as_deref(),
                    status.as_deref(),
                    page,
                    per_page,
                    global,
                )
                .await
            }
        }
    }
}

// ---- Source connections ----

#[allow(clippy::too_many_arguments)]
async fn source_add(
    name: &str,
    url: &str,
    auth_type: &str,
    source_type: Option<&str>,
    username: Option<&str>,
    password: Option<&str>,
    token: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Creating source connection...");

    let body = artifact_keeper_sdk::types::CreateConnectionRequest {
        name: name.to_string(),
        url: url.to_string(),
        auth_type: auth_type.to_string(),
        source_type: source_type.map(|s| s.to_string()),
        credentials: artifact_keeper_sdk::types::ConnectionCredentials {
            username: username.map(|s| s.to_string()),
            password: password.map(|s| s.to_string()),
            token: token.map(|s| s.to_string()),
        },
    };

    let conn = client
        .create_connection()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("create source connection", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", conn.id);
        return Ok(());
    }

    eprintln!(
        "Source connection '{}' created (ID: {}, type: {}).",
        conn.name, conn.id, conn.source_type
    );

    Ok(())
}

async fn source_list(global: &GlobalArgs) -> Result<()> {
    let spinner = output::spinner("Fetching source connections...");

    let conns: Vec<artifact_keeper_sdk::types::ConnectionResponse> =
        fetch_list(global, "/api/v1/migrations/connections", &[]).await?;

    spinner.finish_and_clear();

    if conns.is_empty() {
        eprintln!("No source connections found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for c in &conns {
            println!("{}", c.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = conns
        .iter()
        .map(|c| {
            serde_json::json!({
                "id": c.id.to_string(),
                "name": c.name,
                "url": c.url,
                "source_type": c.source_type,
                "auth_type": c.auth_type,
                "verified": c.verified_at.is_some(),
                "created_at": c.created_at.to_rfc3339(),
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["ID", "NAME", "TYPE", "URL", "VERIFIED"]);
        for c in &conns {
            let id_short = short_id(&c.id);
            let verified = if c.verified_at.is_some() { "yes" } else { "no" };
            table.add_row(vec![
                &id_short,
                &c.name,
                &c.source_type,
                &c.url,
                &verified.to_string(),
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

async fn source_show(id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let conn_id = parse_uuid(id, "connection")?;

    let spinner = output::spinner("Fetching source connection...");
    let conn = client
        .get_connection()
        .id(conn_id)
        .send()
        .await
        .map_err(|e| sdk_err("get source connection", e))?;
    spinner.finish_and_clear();

    let info = serde_json::json!({
        "id": conn.id.to_string(),
        "name": conn.name,
        "url": conn.url,
        "source_type": conn.source_type,
        "auth_type": conn.auth_type,
        "verified_at": conn.verified_at.map(|d| d.to_rfc3339()),
        "created_at": conn.created_at.to_rfc3339(),
    });

    let table_str = format!(
        "ID:           {}\n\
         Name:         {}\n\
         URL:          {}\n\
         Source Type:  {}\n\
         Auth Type:    {}\n\
         Verified:     {}\n\
         Created:      {}",
        conn.id,
        conn.name,
        conn.url,
        conn.source_type,
        conn.auth_type,
        conn.verified_at
            .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "never".into()),
        conn.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn source_test(id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let conn_id = parse_uuid(id, "connection")?;

    let spinner = output::spinner("Testing source connection...");
    let result = client
        .test_connection()
        .id(conn_id)
        .send()
        .await
        .map_err(|e| sdk_err("test source connection", e))?;
    spinner.finish_and_clear();

    let info = serde_json::json!({
        "success": result.success,
        "message": result.message,
        "artifactory_version": result.artifactory_version,
        "license_type": result.license_type,
    });

    let table_str = format!(
        "Success:      {}\n\
         Message:      {}\n\
         Version:      {}\n\
         License:      {}",
        result.success,
        result.message,
        result.artifactory_version.as_deref().unwrap_or("-"),
        result.license_type.as_deref().unwrap_or("-"),
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    if !result.success {
        std::process::exit(1);
    }

    Ok(())
}

async fn source_repos(id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let conn_id = parse_uuid(id, "connection")?;

    let spinner = output::spinner("Listing source repositories...");
    let repos = client
        .list_source_repositories()
        .id(conn_id)
        .send()
        .await
        .map_err(|e| sdk_err("list source repositories", e))?
        .into_inner();
    spinner.finish_and_clear();

    if repos.is_empty() {
        eprintln!("No repositories found on source.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for r in &repos {
            println!("{}", r.key);
        }
        return Ok(());
    }

    let entries: Vec<_> = repos
        .iter()
        .map(|r| {
            serde_json::json!({
                "key": r.key,
                "type": r.type_,
                "package_type": r.package_type,
                "url": r.url,
                "description": r.description,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["KEY", "TYPE", "PACKAGE", "URL"]);
        for r in &repos {
            table.add_row(vec![
                r.key.as_str(),
                r.type_.as_str(),
                r.package_type.as_str(),
                r.url.as_str(),
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

async fn source_delete(id: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    let conn_id = parse_uuid(id, "connection")?;

    if !confirm_action(
        &format!("Delete source connection {id}?"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Deleting source connection...");

    client
        .delete_connection()
        .id(conn_id)
        .send()
        .await
        .map_err(|e| sdk_err("delete source connection", e))?;

    spinner.finish_and_clear();
    eprintln!("Deleted source connection {id}.");

    Ok(())
}

// ---- Import jobs ----

async fn job_create(
    source: &str,
    job_type: Option<&str>,
    config: &str,
    global: &GlobalArgs,
) -> Result<()> {
    let source_id = parse_uuid(source, "connection")?;
    let config_map = parse_config(config)?;

    let client = client_for(global)?;
    let spinner = output::spinner("Creating import job...");

    let body = artifact_keeper_sdk::types::CreateMigrationRequest {
        source_connection_id: source_id,
        job_type: job_type.map(|s| s.to_string()),
        config: config_map,
    };

    let job = client
        .create_migration()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("create import job", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", job.id);
        return Ok(());
    }

    eprintln!(
        "Import job created (ID: {}, type: {}, status: {}).",
        job.id, job.job_type, job.status
    );

    Ok(())
}

async fn job_list(
    status: Option<&str>,
    page: i32,
    per_page: i32,
    global: &GlobalArgs,
) -> Result<()> {
    let spinner = output::spinner("Fetching import jobs...");

    let mut query = vec![
        ("page", page.to_string()),
        ("per_page", per_page.to_string()),
    ];
    if let Some(s) = status {
        query.push(("status", s.to_string()));
    }

    let jobs: Vec<artifact_keeper_sdk::types::MigrationJobResponse> =
        fetch_list(global, "/api/v1/migrations", &query).await?;

    spinner.finish_and_clear();

    if jobs.is_empty() {
        eprintln!("No import jobs found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for j in &jobs {
            println!("{}", j.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = jobs.iter().map(job_summary_json).collect();

    let table_str = format_jobs_table(&entries);

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn job_show(id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let job_id = parse_uuid(id, "job")?;

    let spinner = output::spinner("Fetching import job...");
    let job = client
        .get_migration()
        .id(job_id)
        .send()
        .await
        .map_err(|e| sdk_err("get import job", e))?;
    spinner.finish_and_clear();

    let info = job_detail_json(&job);

    let table_str = format!(
        "ID:              {}\n\
         Type:            {}\n\
         Status:          {}\n\
         Progress:        {:.1}%\n\
         Items:           {} total / {} done / {} failed / {} skipped\n\
         Transferred:     {} of {}\n\
         Source Conn:     {}\n\
         Created:         {}",
        job.id,
        job.job_type,
        job.status,
        job.progress_percent,
        job.total_items,
        job.completed_items,
        job.failed_items,
        job.skipped_items,
        format_bytes(job.transferred_bytes),
        format_bytes(job.total_bytes),
        job.source_connection_id,
        job.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn job_delete(id: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    let job_id = parse_uuid(id, "job")?;

    if !confirm_action(
        &format!("Delete import job {id}?"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Deleting import job...");

    client
        .delete_migration()
        .id(job_id)
        .send()
        .await
        .map_err(|e| sdk_err("delete import job", e))?;

    spinner.finish_and_clear();
    eprintln!("Deleted import job {id}.");

    Ok(())
}

#[derive(Clone, Copy)]
enum JobAction {
    Start,
    Pause,
    Resume,
    Cancel,
}

impl JobAction {
    fn verb(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Cancel => "cancel",
        }
    }
}

async fn job_transition(id: &str, action: JobAction, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let job_id = parse_uuid(id, "job")?;

    let verb = action.verb();
    let spinner = output::spinner(&format!("Sending {verb} to import job..."));

    let job = match action {
        JobAction::Start => client.start_migration().id(job_id).send().await,
        JobAction::Pause => client.pause_migration().id(job_id).send().await,
        JobAction::Resume => client.resume_migration().id(job_id).send().await,
        JobAction::Cancel => client.cancel_migration().id(job_id).send().await,
    }
    .map_err(|e| sdk_err(&format!("{verb} import job"), e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", job.status);
        return Ok(());
    }

    eprintln!("Import job {} is now '{}'.", job.id, job.status);

    Ok(())
}

async fn job_items(
    id: &str,
    item_type: Option<&str>,
    status: Option<&str>,
    page: i32,
    per_page: i32,
    global: &GlobalArgs,
) -> Result<()> {
    let job_id = parse_uuid(id, "job")?;

    let spinner = output::spinner("Fetching import items...");

    let mut query = vec![
        ("page", page.to_string()),
        ("per_page", per_page.to_string()),
    ];
    if let Some(t) = item_type {
        query.push(("item_type", t.to_string()));
    }
    if let Some(s) = status {
        query.push(("status", s.to_string()));
    }

    let items: Vec<artifact_keeper_sdk::types::MigrationItemResponse> = fetch_list(
        global,
        &format!("/api/v1/migrations/{job_id}/items"),
        &query,
    )
    .await?;

    spinner.finish_and_clear();

    if items.is_empty() {
        eprintln!("No items found for import job {id}.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for i in &items {
            println!("{}", i.source_path);
        }
        return Ok(());
    }

    let entries: Vec<_> = items
        .iter()
        .map(|i| {
            serde_json::json!({
                "id": i.id.to_string(),
                "item_type": i.item_type,
                "status": i.status,
                "source_path": i.source_path,
                "target_path": i.target_path,
                "size": format_bytes(i.size_bytes),
                "size_bytes": i.size_bytes,
                "retry_count": i.retry_count,
                "error_message": i.error_message,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["TYPE", "STATUS", "SOURCE", "SIZE"]);
        for i in &items {
            let size = format_bytes(i.size_bytes);
            table.add_row(vec![
                i.item_type.as_str(),
                i.status.as_str(),
                i.source_path.as_str(),
                &size,
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

// ---- Assessment ----

async fn run_assessment(id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let job_id = parse_uuid(id, "job")?;

    let spinner = output::spinner("Running pre-migration assessment...");
    let job = client
        .run_assessment()
        .id(job_id)
        .send()
        .await
        .map_err(|e| sdk_err("run assessment", e))?;
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", job.status);
        return Ok(());
    }

    eprintln!(
        "Assessment started for job {} (status: {}). \
         Use 'ak import assessment {}' to view results.",
        job.id, job.status, job.id
    );

    Ok(())
}

async fn get_assessment(id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let job_id = parse_uuid(id, "job")?;

    let spinner = output::spinner("Fetching assessment results...");
    let result = client
        .get_assessment()
        .id(job_id)
        .send()
        .await
        .map_err(|e| sdk_err("get assessment", e))?;
    spinner.finish_and_clear();

    let info = serde_json::json!({
        "job_id": result.job_id.to_string(),
        "status": result.status,
        "total_artifacts": result.total_artifacts,
        "total_size": format_bytes(result.total_size_bytes),
        "total_size_bytes": result.total_size_bytes,
        "users_count": result.users_count,
        "groups_count": result.groups_count,
        "permissions_count": result.permissions_count,
        "estimated_duration_seconds": result.estimated_duration_seconds,
        "blockers": result.blockers,
        "warnings": result.warnings,
        "repositories": result.repositories.iter().map(|r| serde_json::json!({
            "key": r.key,
            "type": r.type_,
            "package_type": r.package_type,
            "artifact_count": r.artifact_count,
            "total_size": format_bytes(r.total_size_bytes),
            "compatibility": r.compatibility,
            "warnings": r.warnings,
        })).collect::<Vec<_>>(),
    });

    let table_str = {
        let mut summary = format!(
            "Status:          {}\n\
             Artifacts:       {}\n\
             Total Size:      {}\n\
             Users:           {}\n\
             Groups:          {}\n\
             Permissions:     {}\n\
             Est. Duration:   {}s\n\
             Blockers:        {}\n\
             Warnings:        {}",
            result.status,
            result.total_artifacts,
            format_bytes(result.total_size_bytes),
            result.users_count,
            result.groups_count,
            result.permissions_count,
            result.estimated_duration_seconds,
            result.blockers.len(),
            result.warnings.len(),
        );

        if !result.repositories.is_empty() {
            let mut table = new_table(vec!["REPO", "TYPE", "ARTIFACTS", "SIZE", "COMPAT"]);
            for r in &result.repositories {
                let count = r.artifact_count.to_string();
                let size = format_bytes(r.total_size_bytes);
                table.add_row(vec![
                    r.key.as_str(),
                    r.package_type.as_str(),
                    &count,
                    &size,
                    r.compatibility.as_str(),
                ]);
            }
            summary.push_str("\n\n");
            summary.push_str(&table.to_string());
        }

        summary
    };

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

// ---- Reconciliation report ----

async fn reconcile(id: &str, format: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let job_id = parse_uuid(id, "job")?;

    // Fetched raw rather than via the SDK: the backend returns the report's
    // `errors`/`warnings`/`recommendations` as arrays, while the generated SDK
    // models them as maps, so SDK deserialization fails.
    let (base_url, auth_header) = resolve_base_url_and_auth(global)?;
    let http = reqwest::Client::new();

    let spinner = output::spinner("Fetching reconciliation report...");
    let mut req = http
        .get(format!("{base_url}/api/v1/migrations/{job_id}/report"))
        .header(AUTHORIZATION, auth_header);
    if let Some(f) = format {
        req = req.query(&[("format", f)]);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| sdk_err("get reconciliation report", e))?;
    if !resp.status().is_success() {
        spinner.finish_and_clear();
        return Err(sdk_err(
            "get reconciliation report",
            format!("server returned {}", resp.status()),
        )
        .into());
    }
    let report: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| sdk_err("parse reconciliation report", e))?;
    spinner.finish_and_clear();

    let count = |key: &str| {
        report
            .get(key)
            .and_then(|v| v.as_array())
            .map_or(0, |a| a.len())
    };

    let table_str = format!(
        "Report ID:    {}\n\
         Job ID:       {}\n\
         Generated:    {}\n\
         Summary:      {}\n\
         Errors:       {}\n\
         Warnings:     {}\n\
         Recommend.:   {}",
        report["id"].as_str().unwrap_or("-"),
        report["job_id"].as_str().unwrap_or("-"),
        report["generated_at"].as_str().unwrap_or("-"),
        serde_json::to_string(&report["summary"]).unwrap_or_default(),
        count("errors"),
        count("warnings"),
        count("recommendations"),
    );

    println!(
        "{}",
        output::render(&report, &global.format, Some(table_str))
    );

    Ok(())
}

// ---- Progress streaming (SSE) ----

async fn progress(id: &str, global: &GlobalArgs) -> Result<()> {
    // The SDK models this endpoint as an empty-body response, so we make a raw
    // request to stream the Server-Sent Events as they arrive.
    let job_id = parse_uuid(id, "job")?;
    let (base_url, auth_header) = resolve_base_url_and_auth(global)?;

    let http = reqwest::Client::new();
    let resp = http
        .get(format!("{base_url}/api/v1/migrations/{job_id}/stream"))
        .header(AUTHORIZATION, auth_header)
        .send()
        .await
        .map_err(|e| sdk_err("stream progress", e))?;

    if !resp.status().is_success() {
        return Err(sdk_err(
            "stream progress",
            format!("server returned {}", resp.status()),
        )
        .into());
    }

    eprintln!("Streaming progress for job {job_id} (Ctrl-C to stop)...");

    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| sdk_err("read progress stream", e))?;
        print!("{}", String::from_utf8_lossy(&chunk));
        use std::io::Write;
        let _ = std::io::stdout().flush();
    }

    Ok(())
}

// ---- Helpers ----

/// Fetch a list endpoint and return the items as a typed vector.
///
/// The v1.4.0 backend returns list responses wrapped as `{ "items": [...],
/// "pagination": ... }`, whereas the published OpenAPI spec (and therefore the
/// generated SDK) models them as bare arrays. Fetching raw here keeps the
/// list subcommands working regardless of which shape the server returns.
async fn fetch_list<T: DeserializeOwned>(
    global: &GlobalArgs,
    path: &str,
    query: &[(&str, String)],
) -> Result<Vec<T>> {
    let (base_url, auth_header) = resolve_base_url_and_auth(global)?;
    let http = reqwest::Client::new();

    let mut req = http
        .get(format!("{base_url}{path}"))
        .header(AUTHORIZATION, auth_header);
    for (k, v) in query {
        req = req.query(&[(*k, v.as_str())]);
    }

    let resp = req.send().await.map_err(|e| sdk_err("fetch list", e))?;
    if !resp.status().is_success() {
        return Err(sdk_err("fetch list", format!("server returned {}", resp.status())).into());
    }

    let value: serde_json::Value = resp.json().await.map_err(|e| sdk_err("parse list", e))?;

    // Accept either a bare array or an `{ items: [...] }` wrapper.
    let items = match value {
        serde_json::Value::Array(_) => value,
        serde_json::Value::Object(mut map) => map
            .remove("items")
            .unwrap_or(serde_json::Value::Array(vec![])),
        _ => serde_json::Value::Array(vec![]),
    };

    serde_json::from_value(items).map_err(|e| sdk_err("decode list items", e).into())
}

fn parse_config(config: &str) -> Result<serde_json::Map<String, serde_json::Value>> {
    let value: serde_json::Value = serde_json::from_str(config)
        .map_err(|e| crate::error::AkError::ConfigError(format!("Invalid --config JSON: {e}")))?;
    match value {
        serde_json::Value::Object(map) => Ok(map),
        _ => Err(
            crate::error::AkError::ConfigError("--config must be a JSON object".to_string()).into(),
        ),
    }
}

fn job_summary_json(job: &artifact_keeper_sdk::types::MigrationJobResponse) -> serde_json::Value {
    serde_json::json!({
        "id": job.id.to_string(),
        "job_type": job.job_type,
        "status": job.status,
        "progress_percent": job.progress_percent,
        "total_items": job.total_items,
        "completed_items": job.completed_items,
        "failed_items": job.failed_items,
        "created_at": job.created_at.to_rfc3339(),
    })
}

fn job_detail_json(job: &artifact_keeper_sdk::types::MigrationJobResponse) -> serde_json::Value {
    serde_json::json!({
        "id": job.id.to_string(),
        "job_type": job.job_type,
        "status": job.status,
        "progress_percent": job.progress_percent,
        "total_items": job.total_items,
        "completed_items": job.completed_items,
        "failed_items": job.failed_items,
        "skipped_items": job.skipped_items,
        "total_bytes": job.total_bytes,
        "transferred_bytes": job.transferred_bytes,
        "source_connection_id": job.source_connection_id.to_string(),
        "error_summary": job.error_summary,
        "created_at": job.created_at.to_rfc3339(),
        "started_at": job.started_at.map(|d| d.to_rfc3339()),
        "finished_at": job.finished_at.map(|d| d.to_rfc3339()),
    })
}

fn format_jobs_table(items: &[serde_json::Value]) -> String {
    let mut table = new_table(vec!["ID", "TYPE", "STATUS", "PROGRESS", "ITEMS", "CREATED"]);
    for j in items {
        let id_full = j["id"].as_str().unwrap_or("-");
        let id_short = id_full.get(..8).unwrap_or(id_full);
        let progress = format!("{:.1}%", j["progress_percent"].as_f64().unwrap_or(0.0));
        let items_col = format!(
            "{}/{}",
            j["completed_items"].as_i64().unwrap_or(0),
            j["total_items"].as_i64().unwrap_or(0),
        );
        let created = j["created_at"]
            .as_str()
            .and_then(|s| s.get(..10))
            .unwrap_or("-");
        table.add_row(vec![
            id_short,
            j["job_type"].as_str().unwrap_or("-"),
            j["status"].as_str().unwrap_or("-"),
            &progress,
            &items_col,
            created,
        ]);
    }
    table.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use serde_json::json;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: ImportCommand,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).unwrap()
    }

    fn try_parse(args: &[&str]) -> Result<TestCli, clap::Error> {
        TestCli::try_parse_from(args)
    }

    // ---- Top-level parsing ----

    #[test]
    fn parse_source_list() {
        let cli = parse(&["test", "source", "list"]);
        assert!(matches!(
            cli.command,
            ImportCommand::Source {
                command: ImportSourceCommand::List
            }
        ));
    }

    #[test]
    fn parse_source_add_required() {
        let cli = parse(&["test", "source", "add", "legacy", "https://art.example.com"]);
        if let ImportCommand::Source {
            command:
                ImportSourceCommand::Add {
                    name,
                    url,
                    auth_type,
                    source_type,
                    ..
                },
        } = cli.command
        {
            assert_eq!(name, "legacy");
            assert_eq!(url, "https://art.example.com");
            assert_eq!(auth_type, "api_token");
            assert!(source_type.is_none());
        } else {
            panic!("Expected Source::Add");
        }
    }

    #[test]
    fn parse_source_add_all_options() {
        let cli = parse(&[
            "test",
            "source",
            "add",
            "nx",
            "https://nexus.example.com",
            "--auth-type",
            "basic",
            "--source-type",
            "nexus",
            "--username",
            "svc",
            "--password",
            "pw",
        ]);
        if let ImportCommand::Source {
            command:
                ImportSourceCommand::Add {
                    source_type,
                    auth_type,
                    username,
                    password,
                    ..
                },
        } = cli.command
        {
            assert_eq!(auth_type, "basic");
            assert_eq!(source_type.as_deref(), Some("nexus"));
            assert_eq!(username.as_deref(), Some("svc"));
            assert_eq!(password.as_deref(), Some("pw"));
        } else {
            panic!("Expected Source::Add");
        }
    }

    #[test]
    fn parse_source_add_missing_url_fails() {
        assert!(try_parse(&["test", "source", "add", "legacy"]).is_err());
    }

    #[test]
    fn parse_source_test() {
        let cli = parse(&["test", "source", "test", "abc"]);
        assert!(matches!(
            cli.command,
            ImportCommand::Source {
                command: ImportSourceCommand::Test { .. }
            }
        ));
    }

    #[test]
    fn parse_source_repos() {
        let cli = parse(&["test", "source", "repos", "abc"]);
        assert!(matches!(
            cli.command,
            ImportCommand::Source {
                command: ImportSourceCommand::Repos { .. }
            }
        ));
    }

    #[test]
    fn parse_source_delete_with_yes() {
        let cli = parse(&["test", "source", "delete", "abc", "--yes"]);
        if let ImportCommand::Source {
            command: ImportSourceCommand::Delete { yes, .. },
        } = cli.command
        {
            assert!(yes);
        } else {
            panic!("Expected Source::Delete");
        }
    }

    #[test]
    fn parse_job_create_defaults() {
        let cli = parse(&["test", "job", "create", "conn-id"]);
        if let ImportCommand::Job {
            command:
                ImportJobCommand::Create {
                    source,
                    job_type,
                    config,
                },
        } = cli.command
        {
            assert_eq!(source, "conn-id");
            assert!(job_type.is_none());
            assert_eq!(config, "{}");
        } else {
            panic!("Expected Job::Create");
        }
    }

    #[test]
    fn parse_job_create_all_options() {
        let cli = parse(&[
            "test",
            "job",
            "create",
            "conn-id",
            "--job-type",
            "full",
            "--config",
            "{\"repos\":[\"a\"]}",
        ]);
        if let ImportCommand::Job {
            command: ImportJobCommand::Create {
                job_type, config, ..
            },
        } = cli.command
        {
            assert_eq!(job_type.as_deref(), Some("full"));
            assert_eq!(config, "{\"repos\":[\"a\"]}");
        } else {
            panic!("Expected Job::Create");
        }
    }

    #[test]
    fn parse_job_list_defaults() {
        let cli = parse(&["test", "job", "list"]);
        if let ImportCommand::Job {
            command:
                ImportJobCommand::List {
                    status,
                    page,
                    per_page,
                },
        } = cli.command
        {
            assert!(status.is_none());
            assert_eq!(page, 1);
            assert_eq!(per_page, 50);
        } else {
            panic!("Expected Job::List");
        }
    }

    #[test]
    fn parse_job_transitions() {
        for action in ["start", "pause", "resume", "cancel"] {
            let cli = parse(&["test", "job", action, "id"]);
            assert!(matches!(cli.command, ImportCommand::Job { .. }));
        }
    }

    #[test]
    fn parse_job_items_filters() {
        let cli = parse(&[
            "test",
            "job",
            "items",
            "id",
            "--item-type",
            "artifact",
            "--status",
            "failed",
        ]);
        if let ImportCommand::Job {
            command: ImportJobCommand::Items {
                item_type, status, ..
            },
        } = cli.command
        {
            assert_eq!(item_type.as_deref(), Some("artifact"));
            assert_eq!(status.as_deref(), Some("failed"));
        } else {
            panic!("Expected Job::Items");
        }
    }

    #[test]
    fn parse_assess() {
        let cli = parse(&["test", "assess", "job-id"]);
        assert!(matches!(cli.command, ImportCommand::Assess { .. }));
    }

    #[test]
    fn parse_assessment() {
        let cli = parse(&["test", "assessment", "job-id"]);
        assert!(matches!(cli.command, ImportCommand::Assessment { .. }));
    }

    #[test]
    fn parse_reconcile_with_format() {
        let cli = parse(&["test", "reconcile", "job-id", "--report-format", "html"]);
        if let ImportCommand::Reconcile { format, .. } = cli.command {
            assert_eq!(format.as_deref(), Some("html"));
        } else {
            panic!("Expected Reconcile");
        }
    }

    #[test]
    fn parse_progress() {
        let cli = parse(&["test", "progress", "job-id"]);
        assert!(matches!(cli.command, ImportCommand::Progress { .. }));
    }

    // ---- parse_config ----

    #[test]
    fn parse_config_empty_object() {
        let map = parse_config("{}").unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn parse_config_with_keys() {
        let map = parse_config("{\"repos\":[\"a\",\"b\"],\"dry_run\":true}").unwrap();
        assert!(map.contains_key("repos"));
        assert_eq!(map["dry_run"], json!(true));
    }

    #[test]
    fn parse_config_rejects_array() {
        assert!(parse_config("[1,2,3]").is_err());
    }

    #[test]
    fn parse_config_rejects_invalid_json() {
        assert!(parse_config("not json").is_err());
    }

    // ---- Table formatting ----

    #[test]
    fn format_jobs_table_renders() {
        let items = vec![json!({
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "job_type": "full",
            "status": "running",
            "progress_percent": 42.5,
            "total_items": 100,
            "completed_items": 42,
            "created_at": "2026-07-08T12:00:00+00:00",
        })];
        let table = format_jobs_table(&items);
        assert!(table.contains("550e8400"));
        assert!(table.contains("full"));
        assert!(table.contains("running"));
        assert!(table.contains("42.5%"));
        assert!(table.contains("42/100"));
        assert!(table.contains("2026-07-08"));
    }

    #[test]
    fn format_jobs_table_empty() {
        let items: Vec<serde_json::Value> = vec![];
        let table = format_jobs_table(&items);
        assert!(table.contains("STATUS"));
        assert!(table.contains("PROGRESS"));
    }

    #[test]
    fn job_action_verbs() {
        assert_eq!(JobAction::Start.verb(), "start");
        assert_eq!(JobAction::Pause.verb(), "pause");
        assert_eq!(JobAction::Resume.verb(), "resume");
        assert_eq!(JobAction::Cancel.verb(), "cancel");
    }

    // ---- insta snapshot tests ----

    #[test]
    fn snapshot_import_source_list_json() {
        let entries = vec![
            json!({
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "name": "legacy-artifactory",
                "url": "https://art.example.com",
                "source_type": "artifactory",
                "auth_type": "token",
                "verified": true,
                "created_at": "2026-07-08T12:00:00+00:00",
            }),
            json!({
                "id": "550e8400-e29b-41d4-a716-446655440001",
                "name": "legacy-nexus",
                "url": "https://nexus.example.com",
                "source_type": "nexus",
                "auth_type": "basic",
                "verified": false,
                "created_at": "2026-07-08T13:00:00+00:00",
            }),
        ];
        let output = crate::output::render(&entries, &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("import_source_list_json", parsed);
    }

    #[test]
    fn snapshot_import_job_list_json() {
        let items = vec![json!({
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "job_type": "full",
            "status": "running",
            "progress_percent": 42.5,
            "total_items": 100,
            "completed_items": 42,
            "failed_items": 0,
            "created_at": "2026-07-08T12:00:00+00:00",
        })];
        let output = crate::output::render(&items, &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("import_job_list_json", parsed);
    }

    #[test]
    fn snapshot_import_job_list_table() {
        let items = vec![json!({
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "job_type": "full",
            "status": "running",
            "progress_percent": 42.5,
            "total_items": 100,
            "completed_items": 42,
            "created_at": "2026-07-08T12:00:00+00:00",
        })];
        let table = format_jobs_table(&items);
        insta::assert_snapshot!("import_job_list_table", table);
    }
}
