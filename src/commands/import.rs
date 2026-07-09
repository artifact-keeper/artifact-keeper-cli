//! `ak import` — import artifacts from a legacy registry (Artifactory / Nexus).
//!
//! This drives the backend migration/import subsystem (`/api/v1/migrations`):
//! source connections to a legacy registry, pre-migration assessment, and
//! import-job lifecycle (create/start/pause/resume/cancel), item listing,
//! reconciliation reporting, and live progress streaming.
//!
//! Note: this is distinct from the top-level `ak migrate` command, which copies
//! artifacts between two Artifact Keeper *instances*. `ak import` pulls from an
//! external legacy registry into the current instance.

use artifact_keeper_sdk::ClientMigrationExt;
use artifact_keeper_sdk::types::{
    AssessmentResult, ConnectionCredentials, ConnectionResponse, ConnectionTestResult,
    CreateConnectionRequest, CreateMigrationRequest, MigrationItemResponse, MigrationJobResponse,
    MigrationReportResponse, SourceRepository,
};
use clap::Subcommand;
use futures::StreamExt;
use miette::Result;
use serde_json::Value;

use super::client::{client_for, resolve_base_url_and_auth};
use super::helpers::{new_table, parse_uuid, resolve_secret, sdk_err, short_id};
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat, format_bytes};

// ---------------------------------------------------------------------------
// Command tree
// ---------------------------------------------------------------------------

#[derive(Subcommand)]
pub enum ImportCommand {
    /// Manage source connections to a legacy registry (Artifactory/Nexus)
    #[command(subcommand)]
    Source(SourceCommand),

    /// Manage import jobs (create, run, monitor, reconcile)
    #[command(subcommand)]
    Job(JobCommand),

    /// Run and inspect the pre-migration assessment for a job
    #[command(subcommand)]
    Assess(AssessCommand),
}

#[derive(Subcommand)]
pub enum SourceCommand {
    /// List source connections for the current user
    List,

    /// Add a new source connection to a legacy registry
    Add {
        /// Human-readable connection name
        name: String,

        /// Base URL of the legacy registry (e.g. https://artifactory.corp)
        url: String,

        /// Authentication type (one of: basic_auth, api_token)
        #[arg(long, default_value = "basic_auth")]
        auth_type: String,

        /// Source registry type (e.g. artifactory, nexus)
        #[arg(long)]
        source_type: Option<String>,

        /// Username for basic auth
        #[arg(long)]
        username: Option<String>,

        /// Password for basic auth (omit to be prompted, or pipe it to stdin)
        #[arg(long, env = "AK_IMPORT_PASSWORD", hide_env_values = true)]
        password: Option<String>,

        /// Read the basic-auth password from stdin (avoids exposing it on the
        /// command line)
        #[arg(long)]
        password_stdin: bool,

        /// API token / access token (omit to be prompted, or pipe it to stdin)
        #[arg(long, env = "AK_IMPORT_TOKEN", hide_env_values = true)]
        token: Option<String>,

        /// Read the API token from stdin (avoids exposing it on the command
        /// line)
        #[arg(long)]
        token_stdin: bool,
    },

    /// Show a specific source connection
    Show {
        /// Connection ID
        id: String,
    },

    /// Delete a source connection
    Delete {
        /// Connection ID
        id: String,

        /// Skip the confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Test connectivity to a source connection
    Test {
        /// Connection ID
        id: String,
    },

    /// List repositories discovered on the source registry
    Repos {
        /// Connection ID
        id: String,
    },
}

#[derive(Subcommand)]
pub enum JobCommand {
    /// Create a new import job for a source connection
    Create {
        /// Source connection ID to import from
        #[arg(long)]
        source: String,

        /// Job type (e.g. full, incremental, repositories)
        #[arg(long)]
        job_type: Option<String>,

        /// Job configuration as a JSON object (e.g. '{"repositories":["libs"]}')
        #[arg(long)]
        config: Option<String>,
    },

    /// List import jobs
    List {
        /// Filter by status (e.g. pending, running, completed, failed)
        #[arg(long)]
        status: Option<String>,

        /// Page number
        #[arg(long)]
        page: Option<i64>,

        /// Results per page
        #[arg(long)]
        per_page: Option<i64>,
    },

    /// Show the status and progress of an import job
    Status {
        /// Job ID
        id: String,
    },

    /// Start (run) an import job
    #[command(alias = "run")]
    Start {
        /// Job ID
        id: String,
    },

    /// Pause a running import job
    Pause {
        /// Job ID
        id: String,
    },

    /// Resume a paused import job
    Resume {
        /// Job ID
        id: String,
    },

    /// Cancel an import job
    Cancel {
        /// Job ID
        id: String,
    },

    /// Delete an import job
    Delete {
        /// Job ID
        id: String,

        /// Skip the confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// List the individual items (artifacts/metadata) for a job
    Items {
        /// Job ID
        id: String,

        /// Filter by item status
        #[arg(long)]
        status: Option<String>,

        /// Filter by item type
        #[arg(long)]
        item_type: Option<String>,

        /// Page number
        #[arg(long)]
        page: Option<i64>,

        /// Results per page
        #[arg(long)]
        per_page: Option<i64>,
    },

    /// Show the reconciliation report for a completed job
    Report {
        /// Job ID
        id: String,

        /// Report format requested from the server (e.g. json, summary)
        #[arg(long = "report-format")]
        report_format: Option<String>,
    },

    /// Stream live progress for a job (Server-Sent Events)
    Stream {
        /// Job ID
        id: String,
    },
}

#[derive(Subcommand)]
pub enum AssessCommand {
    /// Run a pre-migration assessment for a job
    Run {
        /// Job ID
        id: String,
    },

    /// Show the results of a pre-migration assessment
    Result {
        /// Job ID
        id: String,
    },
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

impl ImportCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Source(cmd) => cmd.execute(global).await,
            Self::Job(cmd) => cmd.execute(global).await,
            Self::Assess(cmd) => cmd.execute(global).await,
        }
    }
}

impl SourceCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List => source_list(global).await,
            Self::Add {
                name,
                url,
                auth_type,
                source_type,
                username,
                password,
                password_stdin,
                token,
                token_stdin,
            } => {
                // Resolve secrets off the command line: prompt on a TTY (or
                // read piped stdin) for the credential matching the auth type.
                let password = resolve_secret(
                    password,
                    password_stdin,
                    "--password",
                    (auth_type == "basic_auth").then_some("Source password (leave empty for none)"),
                    global.no_input,
                )?;
                let token = resolve_secret(
                    token,
                    token_stdin,
                    "--token",
                    (auth_type == "api_token").then_some("Source API token (leave empty for none)"),
                    global.no_input,
                )?;
                source_add(
                    &name,
                    &url,
                    &auth_type,
                    source_type.as_deref(),
                    username,
                    password,
                    token,
                    global,
                )
                .await
            }
            Self::Show { id } => source_show(&id, global).await,
            Self::Delete { id, yes } => source_delete(&id, yes, global).await,
            Self::Test { id } => source_test(&id, global).await,
            Self::Repos { id } => source_repos(&id, global).await,
        }
    }
}

impl JobCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Create {
                source,
                job_type,
                config,
            } => job_create(&source, job_type.as_deref(), config.as_deref(), global).await,
            Self::List {
                status,
                page,
                per_page,
            } => job_list(status.as_deref(), page, per_page, global).await,
            Self::Status { id } => job_status(&id, global).await,
            Self::Start { id } => job_start(&id, global).await,
            Self::Pause { id } => job_pause(&id, global).await,
            Self::Resume { id } => job_resume(&id, global).await,
            Self::Cancel { id } => job_cancel(&id, global).await,
            Self::Delete { id, yes } => job_delete(&id, yes, global).await,
            Self::Items {
                id,
                status,
                item_type,
                page,
                per_page,
            } => {
                job_items(
                    &id,
                    status.as_deref(),
                    item_type.as_deref(),
                    page,
                    per_page,
                    global,
                )
                .await
            }
            Self::Report { id, report_format } => {
                job_report(&id, report_format.as_deref(), global).await
            }
            Self::Stream { id } => job_stream(&id, global).await,
        }
    }
}

impl AssessCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Run { id } => assess_run(&id, global).await,
            Self::Result { id } => assess_result(&id, global).await,
        }
    }
}

// ---------------------------------------------------------------------------
// Source connection operations
// ---------------------------------------------------------------------------

async fn source_list(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;

    let spinner = output::spinner("Fetching source connections...");
    let resp = client
        .list_connections()
        .send()
        .await
        .map_err(|e| sdk_err("list source connections", e))?;
    let connections = resp.into_inner();
    spinner.finish_and_clear();

    if connections.is_empty() {
        eprintln!("No source connections found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for c in &connections {
            println!("{}", c.id);
        }
        return Ok(());
    }

    let (entries, table_str) = format_connections_table(&connections);
    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn source_add(
    name: &str,
    url: &str,
    auth_type: &str,
    source_type: Option<&str>,
    username: Option<String>,
    password: Option<String>,
    token: Option<String>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;

    let body = CreateConnectionRequest {
        name: name.to_string(),
        url: url.to_string(),
        auth_type: auth_type.to_string(),
        source_type: source_type.map(|s| s.to_string()),
        credentials: ConnectionCredentials {
            username,
            password,
            token,
        },
    };

    let spinner = output::spinner("Creating source connection...");
    let resp = client
        .create_connection()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("create source connection", e))?;
    let created = resp.into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", created.id);
        return Ok(());
    }

    let (info, table_str) = format_connection_detail(&created);
    println!("{}", output::render(&info, &global.format, Some(table_str)));
    Ok(())
}

async fn source_show(id: &str, global: &GlobalArgs) -> Result<()> {
    let conn_id = parse_uuid(id, "connection")?;
    let client = client_for(global)?;

    let spinner = output::spinner("Fetching source connection...");
    let resp = client
        .get_connection()
        .id(conn_id)
        .send()
        .await
        .map_err(|e| sdk_err("get source connection", e))?;
    let conn = resp.into_inner();
    spinner.finish_and_clear();

    let (info, table_str) = format_connection_detail(&conn);
    println!("{}", output::render(&info, &global.format, Some(table_str)));
    Ok(())
}

async fn source_delete(id: &str, yes: bool, global: &GlobalArgs) -> Result<()> {
    let conn_id = parse_uuid(id, "connection")?;

    if !yes && !global.no_input {
        let confirmed = dialoguer::Confirm::new()
            .with_prompt(format!("Delete source connection {id}?"))
            .default(false)
            .interact()
            .map_err(|e| AkError::ConfigError(format!("prompt failed: {e}")))?;
        if !confirmed {
            eprintln!("Cancelled.");
            return Ok(());
        }
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

    eprintln!("Source connection {id} deleted.");
    Ok(())
}

async fn source_test(id: &str, global: &GlobalArgs) -> Result<()> {
    let conn_id = parse_uuid(id, "connection")?;
    let client = client_for(global)?;

    let spinner = output::spinner("Testing source connection...");
    let resp = client
        .test_connection()
        .id(conn_id)
        .send()
        .await
        .map_err(|e| sdk_err("test source connection", e))?;
    let result = resp.into_inner();
    spinner.finish_and_clear();

    let (info, table_str) = format_test_result(&result);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    if !result.success {
        std::process::exit(1);
    }
    Ok(())
}

async fn source_repos(id: &str, global: &GlobalArgs) -> Result<()> {
    let conn_id = parse_uuid(id, "connection")?;
    let client = client_for(global)?;

    let spinner = output::spinner("Listing source repositories...");
    let resp = client
        .list_source_repositories()
        .id(conn_id)
        .send()
        .await
        .map_err(|e| sdk_err("list source repositories", e))?;
    let repos = resp.into_inner();
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

    let (entries, table_str) = format_source_repos_table(&repos);
    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Import job operations
// ---------------------------------------------------------------------------

async fn job_create(
    source: &str,
    job_type: Option<&str>,
    config: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let source_id = parse_uuid(source, "source connection")?;
    let config_map = parse_config(config)?;
    let client = client_for(global)?;

    let body = CreateMigrationRequest {
        source_connection_id: source_id,
        job_type: job_type.map(|s| s.to_string()),
        config: config_map,
    };

    let spinner = output::spinner("Creating import job...");
    let resp = client
        .create_migration()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("create import job", e))?;
    let job = resp.into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", job.id);
        return Ok(());
    }

    let (info, table_str) = format_job_detail(&job);
    println!("{}", output::render(&info, &global.format, Some(table_str)));
    Ok(())
}

async fn job_list(
    status: Option<&str>,
    page: Option<i64>,
    per_page: Option<i64>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;

    let mut builder = client.list_migrations();
    if let Some(s) = status {
        builder = builder.status(s.to_string());
    }
    if let Some(p) = page {
        builder = builder.page(p);
    }
    if let Some(pp) = per_page {
        builder = builder.per_page(pp);
    }

    let spinner = output::spinner("Fetching import jobs...");
    let resp = builder
        .send()
        .await
        .map_err(|e| sdk_err("list import jobs", e))?;
    let jobs = resp.into_inner();
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

    let (entries, table_str) = format_jobs_table(&jobs);
    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );
    Ok(())
}

async fn job_status(id: &str, global: &GlobalArgs) -> Result<()> {
    let job_id = parse_uuid(id, "job")?;
    let client = client_for(global)?;

    let spinner = output::spinner("Fetching import job...");
    let resp = client
        .get_migration()
        .id(job_id)
        .send()
        .await
        .map_err(|e| sdk_err("get import job", e))?;
    let job = resp.into_inner();
    spinner.finish_and_clear();

    let (info, table_str) = format_job_detail(&job);
    println!("{}", output::render(&info, &global.format, Some(table_str)));
    Ok(())
}

async fn job_start(id: &str, global: &GlobalArgs) -> Result<()> {
    let job_id = parse_uuid(id, "job")?;
    let client = client_for(global)?;

    let spinner = output::spinner("Starting import job...");
    let resp = client
        .start_migration()
        .id(job_id)
        .send()
        .await
        .map_err(|e| sdk_err("start import job", e))?;
    let job = resp.into_inner();
    spinner.finish_and_clear();

    eprintln!("Import job {id} started (status: {}).", job.status);
    if !matches!(global.format, OutputFormat::Quiet) {
        let (info, table_str) = format_job_detail(&job);
        println!("{}", output::render(&info, &global.format, Some(table_str)));
    }
    Ok(())
}

async fn job_pause(id: &str, global: &GlobalArgs) -> Result<()> {
    let job_id = parse_uuid(id, "job")?;
    let client = client_for(global)?;

    let spinner = output::spinner("Pausing import job...");
    let resp = client
        .pause_migration()
        .id(job_id)
        .send()
        .await
        .map_err(|e| sdk_err("pause import job", e))?;
    let job = resp.into_inner();
    spinner.finish_and_clear();

    eprintln!("Import job {id} paused (status: {}).", job.status);
    Ok(())
}

async fn job_resume(id: &str, global: &GlobalArgs) -> Result<()> {
    let job_id = parse_uuid(id, "job")?;
    let client = client_for(global)?;

    let spinner = output::spinner("Resuming import job...");
    let resp = client
        .resume_migration()
        .id(job_id)
        .send()
        .await
        .map_err(|e| sdk_err("resume import job", e))?;
    let job = resp.into_inner();
    spinner.finish_and_clear();

    eprintln!("Import job {id} resumed (status: {}).", job.status);
    Ok(())
}

async fn job_cancel(id: &str, global: &GlobalArgs) -> Result<()> {
    let job_id = parse_uuid(id, "job")?;
    let client = client_for(global)?;

    let spinner = output::spinner("Cancelling import job...");
    let resp = client
        .cancel_migration()
        .id(job_id)
        .send()
        .await
        .map_err(|e| sdk_err("cancel import job", e))?;
    let job = resp.into_inner();
    spinner.finish_and_clear();

    eprintln!("Import job {id} cancelled (status: {}).", job.status);
    Ok(())
}

async fn job_delete(id: &str, yes: bool, global: &GlobalArgs) -> Result<()> {
    let job_id = parse_uuid(id, "job")?;

    if !yes && !global.no_input {
        let confirmed = dialoguer::Confirm::new()
            .with_prompt(format!("Delete import job {id}?"))
            .default(false)
            .interact()
            .map_err(|e| AkError::ConfigError(format!("prompt failed: {e}")))?;
        if !confirmed {
            eprintln!("Cancelled.");
            return Ok(());
        }
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

    eprintln!("Import job {id} deleted.");
    Ok(())
}

async fn job_items(
    id: &str,
    status: Option<&str>,
    item_type: Option<&str>,
    page: Option<i64>,
    per_page: Option<i64>,
    global: &GlobalArgs,
) -> Result<()> {
    let job_id = parse_uuid(id, "job")?;
    let client = client_for(global)?;

    let mut builder = client.list_migration_items().id(job_id);
    if let Some(s) = status {
        builder = builder.status(s.to_string());
    }
    if let Some(t) = item_type {
        builder = builder.item_type(t.to_string());
    }
    if let Some(p) = page {
        builder = builder.page(p);
    }
    if let Some(pp) = per_page {
        builder = builder.per_page(pp);
    }

    let spinner = output::spinner("Fetching import items...");
    let resp = builder
        .send()
        .await
        .map_err(|e| sdk_err("list import items", e))?;
    let items = resp.into_inner();
    spinner.finish_and_clear();

    if items.is_empty() {
        eprintln!("No import items found for job {id}.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for i in &items {
            println!("{}", i.id);
        }
        return Ok(());
    }

    let (entries, table_str) = format_items_table(&items);
    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );
    Ok(())
}

async fn job_report(id: &str, format: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let job_id = parse_uuid(id, "job")?;
    let client = client_for(global)?;

    let mut builder = client.get_migration_report().id(job_id);
    if let Some(f) = format {
        builder = builder.format(f.to_string());
    }

    let spinner = output::spinner("Fetching reconciliation report...");
    let resp = builder
        .send()
        .await
        .map_err(|e| sdk_err("get reconciliation report", e))?;
    let report = resp.into_inner();
    spinner.finish_and_clear();

    let (info, table_str) = format_report_detail(&report);
    println!("{}", output::render(&info, &global.format, Some(table_str)));
    Ok(())
}

async fn job_stream(id: &str, global: &GlobalArgs) -> Result<()> {
    // The SDK's typed `stream_migration_progress` op discards the SSE body, so
    // stream the endpoint directly (same pattern as chunked upload's raw HTTP).
    let job_id = parse_uuid(id, "job")?;
    let (base_url, auth_header) = resolve_base_url_and_auth(global)?;

    let url = format!(
        "{}/api/v1/migrations/{}/stream",
        base_url.trim_end_matches('/'),
        job_id
    );

    let http = super::client::raw_http_client()?;
    let resp = http
        .get(&url)
        .header(reqwest::header::AUTHORIZATION, auth_header)
        .header(reqwest::header::ACCEPT, "text/event-stream")
        .send()
        .await
        .map_err(|e| sdk_err("stream import progress", e))?;

    if !resp.status().is_success() {
        return Err(AkError::ServerError(format!(
            "Failed to stream import progress: HTTP {}",
            resp.status()
        ))
        .into());
    }

    eprintln!("Streaming progress for job {id} (Ctrl-C to stop)...");
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| sdk_err("read progress stream", e))?;
        print!("{}", String::from_utf8_lossy(&chunk));
        use std::io::Write;
        let _ = std::io::stdout().flush();
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Assessment operations
// ---------------------------------------------------------------------------

async fn assess_run(id: &str, global: &GlobalArgs) -> Result<()> {
    let job_id = parse_uuid(id, "job")?;
    let client = client_for(global)?;

    let spinner = output::spinner("Starting pre-migration assessment...");
    let resp = client
        .run_assessment()
        .id(job_id)
        .send()
        .await
        .map_err(|e| sdk_err("run assessment", e))?;
    let job = resp.into_inner();
    spinner.finish_and_clear();

    eprintln!(
        "Assessment started for job {id} (status: {}). Use `ak import assess result {id}`.",
        job.status
    );
    Ok(())
}

async fn assess_result(id: &str, global: &GlobalArgs) -> Result<()> {
    let job_id = parse_uuid(id, "job")?;
    let client = client_for(global)?;

    let spinner = output::spinner("Fetching assessment results...");
    let resp = client
        .get_assessment()
        .id(job_id)
        .send()
        .await
        .map_err(|e| sdk_err("get assessment", e))?;
    let assessment = resp.into_inner();
    spinner.finish_and_clear();

    let (info, table_str) = format_assessment_detail(&assessment);
    println!("{}", output::render(&info, &global.format, Some(table_str)));
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse the optional `--config` JSON argument into an object map.
fn parse_config(config: Option<&str>) -> Result<serde_json::Map<String, Value>> {
    match config {
        None => Ok(serde_json::Map::new()),
        Some(raw) => {
            let value: Value = serde_json::from_str(raw)
                .map_err(|e| AkError::ConfigError(format!("Invalid --config JSON: {e}")))?;
            match value {
                Value::Object(map) => Ok(map),
                _ => Err(AkError::ConfigError("--config must be a JSON object".to_string()).into()),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Formatting (pure functions, testable without HTTP)
// ---------------------------------------------------------------------------

fn format_connections_table(connections: &[ConnectionResponse]) -> (Vec<Value>, String) {
    let entries: Vec<_> = connections
        .iter()
        .map(|c| {
            serde_json::json!({
                "id": c.id.to_string(),
                "name": c.name,
                "url": c.url,
                "auth_type": c.auth_type,
                "source_type": c.source_type,
                "verified_at": c.verified_at.map(|v| v.to_rfc3339()),
                "created_at": c.created_at.to_rfc3339(),
            })
        })
        .collect();

    let mut table = new_table(vec!["ID", "NAME", "SOURCE", "URL", "AUTH", "VERIFIED"]);
    for c in connections {
        let verified = c
            .verified_at
            .map(|v| v.format("%Y-%m-%d").to_string())
            .unwrap_or_else(|| "never".to_string());
        table.add_row(vec![
            short_id(&c.id),
            c.name.clone(),
            c.source_type.clone(),
            c.url.clone(),
            c.auth_type.clone(),
            verified,
        ]);
    }
    (entries, table.to_string())
}

fn format_connection_detail(c: &ConnectionResponse) -> (Value, String) {
    let info = serde_json::json!({
        "id": c.id.to_string(),
        "name": c.name,
        "url": c.url,
        "auth_type": c.auth_type,
        "source_type": c.source_type,
        "verified_at": c.verified_at.map(|v| v.to_rfc3339()),
        "created_at": c.created_at.to_rfc3339(),
    });

    let table_str = format!(
        "ID:          {}\n\
         Name:        {}\n\
         Source Type: {}\n\
         URL:         {}\n\
         Auth Type:   {}\n\
         Verified:    {}\n\
         Created:     {}",
        c.id,
        c.name,
        c.source_type,
        c.url,
        c.auth_type,
        c.verified_at
            .map(|v| v.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "never".to_string()),
        c.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );
    (info, table_str)
}

fn format_test_result(r: &ConnectionTestResult) -> (Value, String) {
    let info = serde_json::json!({
        "success": r.success,
        "message": r.message,
        "artifactory_version": r.artifactory_version,
        "license_type": r.license_type,
    });

    let table_str = format!(
        "Result:   {}\n\
         Message:  {}\n\
         Version:  {}\n\
         License:  {}",
        if r.success { "success" } else { "failure" },
        r.message,
        r.artifactory_version.as_deref().unwrap_or("-"),
        r.license_type.as_deref().unwrap_or("-"),
    );
    (info, table_str)
}

fn format_source_repos_table(repos: &[SourceRepository]) -> (Vec<Value>, String) {
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

    let mut table = new_table(vec!["KEY", "TYPE", "PACKAGE", "URL"]);
    for r in repos {
        table.add_row(vec![
            r.key.clone(),
            r.type_.clone(),
            r.package_type.clone(),
            r.url.clone(),
        ]);
    }
    (entries, table.to_string())
}

fn job_entry(j: &MigrationJobResponse) -> Value {
    serde_json::json!({
        "id": j.id.to_string(),
        "source_connection_id": j.source_connection_id.to_string(),
        "status": j.status,
        "job_type": j.job_type,
        "progress_percent": j.progress_percent,
        "total_items": j.total_items,
        "completed_items": j.completed_items,
        "failed_items": j.failed_items,
        "skipped_items": j.skipped_items,
        "total_bytes": j.total_bytes,
        "transferred_bytes": j.transferred_bytes,
        "error_summary": j.error_summary,
        "created_at": j.created_at.to_rfc3339(),
        "started_at": j.started_at.map(|s| s.to_rfc3339()),
        "finished_at": j.finished_at.map(|f| f.to_rfc3339()),
    })
}

fn format_jobs_table(jobs: &[MigrationJobResponse]) -> (Vec<Value>, String) {
    let entries: Vec<_> = jobs.iter().map(job_entry).collect();

    let mut table = new_table(vec![
        "ID", "STATUS", "TYPE", "PROGRESS", "ITEMS", "FAILED", "CREATED",
    ]);
    for j in jobs {
        table.add_row(vec![
            short_id(&j.id),
            j.status.clone(),
            j.job_type.clone(),
            format!("{:.0}%", j.progress_percent),
            format!("{}/{}", j.completed_items, j.total_items),
            j.failed_items.to_string(),
            j.created_at.format("%Y-%m-%d").to_string(),
        ]);
    }
    (entries, table.to_string())
}

fn format_job_detail(j: &MigrationJobResponse) -> (Value, String) {
    let info = job_entry(j);

    let table_str = format!(
        "ID:             {}\n\
         Source Conn:    {}\n\
         Status:         {}\n\
         Type:           {}\n\
         Progress:       {:.1}%\n\
         Items:          {} completed / {} total ({} failed, {} skipped)\n\
         Data:           {} / {}\n\
         Error:          {}\n\
         Created:        {}\n\
         Started:        {}\n\
         Finished:       {}",
        j.id,
        j.source_connection_id,
        j.status,
        j.job_type,
        j.progress_percent,
        j.completed_items,
        j.total_items,
        j.failed_items,
        j.skipped_items,
        format_bytes(j.transferred_bytes),
        format_bytes(j.total_bytes),
        j.error_summary.as_deref().unwrap_or("-"),
        j.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
        j.started_at
            .map(|s| s.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "-".to_string()),
        j.finished_at
            .map(|f| f.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "-".to_string()),
    );
    (info, table_str)
}

fn format_items_table(items: &[MigrationItemResponse]) -> (Vec<Value>, String) {
    let entries: Vec<_> = items
        .iter()
        .map(|i| {
            serde_json::json!({
                "id": i.id.to_string(),
                "item_type": i.item_type,
                "source_path": i.source_path,
                "target_path": i.target_path,
                "status": i.status,
                "size_bytes": i.size_bytes,
                "retry_count": i.retry_count,
                "checksum_source": i.checksum_source,
                "checksum_target": i.checksum_target,
                "error_message": i.error_message,
            })
        })
        .collect();

    let mut table = new_table(vec![
        "ID",
        "TYPE",
        "SOURCE PATH",
        "STATUS",
        "SIZE",
        "RETRIES",
    ]);
    for i in items {
        table.add_row(vec![
            short_id(&i.id),
            i.item_type.clone(),
            i.source_path.clone(),
            i.status.clone(),
            format_bytes(i.size_bytes),
            i.retry_count.to_string(),
        ]);
    }
    (entries, table.to_string())
}

fn format_report_detail(r: &MigrationReportResponse) -> (Value, String) {
    let info = serde_json::json!({
        "id": r.id.to_string(),
        "job_id": r.job_id.to_string(),
        "generated_at": r.generated_at.to_rfc3339(),
        "summary": r.summary,
        "warnings": r.warnings,
        "errors": r.errors,
        "recommendations": r.recommendations,
    });

    let table_str = format!(
        "Report ID:       {}\n\
         Job ID:          {}\n\
         Generated:       {}\n\
         Summary:         {}\n\
         Warnings:        {}\n\
         Errors:          {}\n\
         Recommendations: {}",
        r.id,
        r.job_id,
        r.generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
        Value::Object(r.summary.clone()),
        Value::Object(r.warnings.clone()),
        Value::Object(r.errors.clone()),
        Value::Object(r.recommendations.clone()),
    );
    (info, table_str)
}

fn format_assessment_detail(a: &AssessmentResult) -> (Value, String) {
    let info = serde_json::json!({
        "job_id": a.job_id.to_string(),
        "status": a.status,
        "users_count": a.users_count,
        "groups_count": a.groups_count,
        "permissions_count": a.permissions_count,
        "total_artifacts": a.total_artifacts,
        "total_size_bytes": a.total_size_bytes,
        "estimated_duration_seconds": a.estimated_duration_seconds,
        "warnings": a.warnings,
        "blockers": a.blockers,
        "repositories": a.repositories.iter().map(|r| serde_json::json!({
            "key": r.key,
            "type": r.type_,
            "package_type": r.package_type,
            "artifact_count": r.artifact_count,
            "total_size_bytes": r.total_size_bytes,
            "compatibility": r.compatibility,
            "warnings": r.warnings,
        })).collect::<Vec<_>>(),
    });

    let repos_summary = if a.repositories.is_empty() {
        "none".to_string()
    } else {
        a.repositories
            .iter()
            .map(|r| {
                format!(
                    "{} ({}, {} artifacts)",
                    r.key, r.package_type, r.artifact_count
                )
            })
            .collect::<Vec<_>>()
            .join("\n                 ")
    };

    let table_str = format!(
        "Job ID:          {}\n\
         Status:          {}\n\
         Repositories:    {}\n\
         Users:           {}\n\
         Groups:          {}\n\
         Permissions:     {}\n\
         Total Artifacts: {}\n\
         Total Size:      {}\n\
         Est. Duration:   {}s\n\
         Warnings:        {}\n\
         Blockers:        {}",
        a.job_id,
        a.status,
        repos_summary,
        a.users_count,
        a.groups_count,
        a.permissions_count,
        a.total_artifacts,
        format_bytes(a.total_size_bytes),
        a.estimated_duration_seconds,
        if a.warnings.is_empty() {
            "-".to_string()
        } else {
            a.warnings.join("; ")
        },
        if a.blockers.is_empty() {
            "-".to_string()
        } else {
            a.blockers.join("; ")
        },
    );
    (info, table_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use clap::Parser;
    use uuid::Uuid;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: ImportCommand,
    }

    fn sample_connection() -> ConnectionResponse {
        ConnectionResponse {
            auth_type: "basic".to_string(),
            created_at: Utc::now(),
            id: Uuid::new_v4(),
            name: "legacy-artifactory".to_string(),
            source_type: "artifactory".to_string(),
            url: "https://artifactory.corp".to_string(),
            verified_at: None,
        }
    }

    fn sample_job() -> MigrationJobResponse {
        MigrationJobResponse {
            completed_items: 5,
            config: serde_json::Map::new(),
            created_at: Utc::now(),
            error_summary: None,
            estimated_time_remaining: None,
            failed_items: 1,
            finished_at: None,
            id: Uuid::new_v4(),
            job_type: "full".to_string(),
            progress_percent: 50.0,
            skipped_items: 0,
            source_connection_id: Uuid::new_v4(),
            started_at: None,
            status: "running".to_string(),
            total_bytes: 1024,
            total_items: 10,
            transferred_bytes: 512,
        }
    }

    #[test]
    fn parses_source_add() {
        let cli = TestCli::parse_from([
            "ak",
            "source",
            "add",
            "legacy",
            "https://artifactory.corp",
            "--source-type",
            "artifactory",
            "--username",
            "admin",
        ]);
        match cli.command {
            ImportCommand::Source(SourceCommand::Add {
                name,
                url,
                source_type,
                username,
                ..
            }) => {
                assert_eq!(name, "legacy");
                assert_eq!(url, "https://artifactory.corp");
                assert_eq!(source_type.as_deref(), Some("artifactory"));
                assert_eq!(username.as_deref(), Some("admin"));
            }
            _ => panic!("expected Source Add"),
        }
    }

    #[test]
    fn parses_source_add_password_stdin() {
        let cli = TestCli::parse_from([
            "ak",
            "source",
            "add",
            "legacy",
            "https://artifactory.corp",
            "--username",
            "admin",
            "--password-stdin",
        ]);
        match cli.command {
            ImportCommand::Source(SourceCommand::Add {
                password,
                password_stdin,
                token,
                token_stdin,
                ..
            }) => {
                assert!(password.is_none());
                assert!(password_stdin);
                assert!(token.is_none());
                assert!(!token_stdin);
            }
            _ => panic!("expected Source Add"),
        }
    }

    #[test]
    fn parses_source_add_token_stdin() {
        let cli = TestCli::parse_from([
            "ak",
            "source",
            "add",
            "legacy",
            "https://nexus.corp",
            "--auth-type",
            "api_token",
            "--token-stdin",
        ]);
        match cli.command {
            ImportCommand::Source(SourceCommand::Add {
                auth_type,
                token,
                token_stdin,
                password_stdin,
                ..
            }) => {
                assert_eq!(auth_type, "api_token");
                assert!(token.is_none());
                assert!(token_stdin);
                assert!(!password_stdin);
            }
            _ => panic!("expected Source Add"),
        }
    }

    #[test]
    fn parses_source_list() {
        let cli = TestCli::parse_from(["ak", "source", "list"]);
        assert!(matches!(
            cli.command,
            ImportCommand::Source(SourceCommand::List)
        ));
    }

    #[test]
    fn parses_job_create() {
        let cli = TestCli::parse_from([
            "ak",
            "job",
            "create",
            "--source",
            "abc",
            "--job-type",
            "full",
            "--config",
            "{\"repositories\":[\"libs\"]}",
        ]);
        match cli.command {
            ImportCommand::Job(JobCommand::Create {
                source,
                job_type,
                config,
            }) => {
                assert_eq!(source, "abc");
                assert_eq!(job_type.as_deref(), Some("full"));
                assert_eq!(config.as_deref(), Some("{\"repositories\":[\"libs\"]}"));
            }
            _ => panic!("expected Job Create"),
        }
    }

    #[test]
    fn parses_job_run_alias() {
        let cli = TestCli::parse_from(["ak", "job", "run", "some-id"]);
        assert!(matches!(
            cli.command,
            ImportCommand::Job(JobCommand::Start { .. })
        ));
    }

    #[test]
    fn parses_assess_run() {
        let cli = TestCli::parse_from(["ak", "assess", "run", "some-id"]);
        assert!(matches!(
            cli.command,
            ImportCommand::Assess(AssessCommand::Run { .. })
        ));
    }

    #[test]
    fn parse_config_defaults_empty() {
        let map = parse_config(None).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn parse_config_parses_object() {
        let map = parse_config(Some("{\"a\":1}")).unwrap();
        assert_eq!(map.get("a").and_then(|v| v.as_i64()), Some(1));
    }

    #[test]
    fn parse_config_rejects_non_object() {
        assert!(parse_config(Some("[1,2,3]")).is_err());
        assert!(parse_config(Some("not json")).is_err());
    }

    #[test]
    fn connection_table_renders() {
        let conn = sample_connection();
        let (_entries, table) = format_connections_table(std::slice::from_ref(&conn));
        assert!(table.contains("legacy-artifactory"));
        assert!(table.contains("artifactory"));
        assert!(table.contains("never"));
    }

    #[test]
    fn connection_detail_renders() {
        let conn = sample_connection();
        let (_info, table) = format_connection_detail(&conn);
        assert!(table.contains("https://artifactory.corp"));
        assert!(table.contains("basic"));
    }

    #[test]
    fn job_table_shows_progress() {
        let job = sample_job();
        let (_entries, table) = format_jobs_table(std::slice::from_ref(&job));
        assert!(table.contains("running"));
        assert!(table.contains("50%"));
        assert!(table.contains("5/10"));
    }

    #[test]
    fn job_detail_shows_items() {
        let job = sample_job();
        let (_info, table) = format_job_detail(&job);
        assert!(table.contains("running"));
        assert!(table.contains("full"));
    }

    #[test]
    fn test_result_reports_failure() {
        let r = ConnectionTestResult {
            success: false,
            message: "unauthorized".to_string(),
            artifactory_version: None,
            license_type: None,
        };
        let (_info, table) = format_test_result(&r);
        assert!(table.contains("failure"));
        assert!(table.contains("unauthorized"));
    }
}
