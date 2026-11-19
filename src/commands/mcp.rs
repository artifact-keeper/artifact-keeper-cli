//! `ak mcp`: the management API of MCP Registry repositories (format `mcp`), new in
//! 1.12. Namespace proofs, a Remote registry's catalog and its approvals, its sync and
//! seed jobs, a server version's health, and the approval queue across registries.
//!
//! Publishing and installing MCP servers isn't here: `mcp-publisher` speaks the
//! registry's own `/mcp/{repo}/v0.1` API, and the clients read it directly. An
//! administrator's writes to one version on that API are `ak mcp version`, in
//! `mcp_version.rs`.

use artifact_keeper_sdk::ClientMcpExt;
use artifact_keeper_sdk::raw::capture;
use artifact_keeper_sdk::types::{
    ApprovalRequestBody, BulkAction, BulkApproveRequest, BulkBlockRequest, BulkDecideRequest,
    CatalogItem, CreateProof, Decision, DecisionRequest, DecisionResult, PinRequest, SeedRequest,
    SeedServer,
};
use clap::Subcommand;
use miette::Result;
use serde_json::{Map, Value};

use super::client::{client_for, raw_http_client, resolve_base_url_and_auth};
use super::helpers::{
    Minor, confirm_action, emit_mutation, emit_mutation_raw, new_table, or_since, parse_uuid,
    reported_failure, since, since_raw,
};
use super::repo::{Polled, poll_job};
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat};

const V1_12: Minor = (1, 12);

#[derive(Subcommand)]
pub enum McpCommand {
    /// Proofs that a domain's owner controls a reverse-DNS namespace (instance
    /// administrators)
    #[command(subcommand)]
    NamespaceProof(ProofCommand),

    /// A Remote MCP registry's catalog: the upstream servers and what's approved
    #[command(subcommand)]
    Catalog(CatalogCommand),

    /// Sync a Remote MCP registry's catalog from its upstream
    #[command(subcommand)]
    Sync(SyncCommand),

    /// Pin named server versions without waiting for the sync to reach them
    #[command(subcommand)]
    Seed(SeedCommand),

    /// Show a server version's health: its packages' scans and gates, and its lint
    Health {
        /// MCP repository key (Local, Staging or Remote)
        #[arg(long)]
        repo: String,

        /// Server name, such as io.github.acme/weather
        server: String,

        /// Exact version
        version: String,

        /// Answer for a soft-deleted version too
        #[arg(long)]
        include_deleted: bool,
    },

    /// Count the approval queue across every Remote MCP registry you can read
    Pending,

    /// Change one server version on a Local or Staging registry: its status, a soft
    /// delete and purge, an administrator's edit, and a probe of its tools
    #[command(subcommand)]
    Version(super::mcp_version::VersionCommand),
}

#[derive(Subcommand)]
pub enum ProofCommand {
    /// List namespace proofs
    List,

    /// Start a proof, and print the record or file the domain has to publish
    Create {
        /// Reverse-DNS namespace, such as com.acme (acme.com) or io.github.acme
        /// (acme.github.io)
        namespace: String,

        /// How the domain proves it: dns (a TXT record) or http (a well-known file)
        #[arg(long, value_parser = ["dns", "http"])]
        method: String,
    },

    /// Show a proof and its challenge
    Show {
        /// Proof ID
        id: String,
    },

    /// Check the proof now: the server looks up the record or fetches the file
    Verify {
        /// Proof ID
        id: String,
    },

    /// Delete a proof
    Delete {
        /// Proof ID
        id: String,

        /// Skip the confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

#[derive(Subcommand)]
pub enum CatalogCommand {
    /// List the catalog's server names
    List {
        /// Remote MCP repository key
        #[arg(long)]
        repo: String,

        /// Only names containing this text
        #[arg(long)]
        search: Option<String>,

        /// Only names in this state
        #[arg(long, value_parser = ["pending", "approved", "blocked", "review"])]
        status: Option<String>,

        /// Only this namespace (the part before the slash)
        #[arg(long)]
        namespace: Option<String>,

        /// Only names someone asked to have approved
        #[arg(long)]
        requested: bool,

        /// The approval queue: names, or versions of them, waiting for a decision
        #[arg(long)]
        queue: bool,

        /// Continue from the cursor a previous page printed
        #[arg(long)]
        cursor: Option<String>,

        /// Names per page (the server's default is 50, at most 200)
        #[arg(long)]
        limit: Option<i64>,
    },

    /// Show one server name: its status, versions, pins and risk summary
    Show {
        /// Remote MCP repository key
        #[arg(long)]
        repo: String,

        /// Server name, such as io.github.acme/weather
        server: String,
    },

    /// Approve a name, or a name@version row: it's ingested and served
    Approve {
        /// Remote MCP repository key
        #[arg(long)]
        repo: String,

        /// Catalog row ID
        id: String,

        /// Why, for the audit log
        #[arg(long)]
        reason: Option<String>,

        /// Skip the confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Block a name, or a name@version row: it isn't served
    Block {
        /// Remote MCP repository key
        #[arg(long)]
        repo: String,

        /// Catalog row ID
        id: String,

        /// Why, for the audit log
        #[arg(long)]
        reason: Option<String>,

        /// Skip the confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Put a name, or a name@version row, back up for review
    Reopen {
        /// Remote MCP repository key
        #[arg(long)]
        repo: String,

        /// Catalog row ID
        id: String,

        /// Why, for the audit log
        #[arg(long)]
        reason: Option<String>,

        /// Accepted and ignored: reopening asks nothing. Scripts that pass --yes to
        /// every decision keep working
        #[arg(long, short = 'y', hide = true)]
        yes: bool,
    },

    /// Ask the repository's administrators to approve a name
    RequestApproval {
        /// Remote MCP repository key
        #[arg(long)]
        repo: String,

        /// Catalog row ID of the name
        id: String,

        /// Why you need it (the server keeps 500 characters)
        #[arg(long)]
        note: Option<String>,
    },

    /// Approve every name matching a glob over the full server name
    BulkApprove {
        /// Remote MCP repository key
        #[arg(long)]
        repo: String,

        /// io.github.acme/* (one namespace), com.acme.*/* (its sub-namespaces) or
        /// io.github.acme/weather (one server)
        pattern: String,

        /// Also approve names flagged for review
        #[arg(long)]
        include_review: bool,

        /// Why, for the audit log
        #[arg(long)]
        reason: Option<String>,

        /// Change nothing: list what would be approved
        #[arg(long)]
        dry_run: bool,

        /// Skip the confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Block every name matching a glob over the full server name
    BulkBlock {
        /// Remote MCP repository key
        #[arg(long)]
        repo: String,

        /// A glob over the full server name, as for bulk-approve
        pattern: String,

        /// Why, for the audit log
        #[arg(long)]
        reason: Option<String>,

        /// Change nothing: list what would be blocked
        #[arg(long)]
        dry_run: bool,

        /// Skip the confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Approve or block catalog rows by ID (1 to 500)
    BulkDecide {
        /// Remote MCP repository key
        #[arg(long)]
        repo: String,

        /// approve or block
        #[arg(long, value_parser = ["approve", "block"])]
        action: String,

        /// Catalog row IDs: names or name@version rows
        #[arg(required = true, num_args = 1..)]
        ids: Vec<String>,

        /// Why, for the audit log
        #[arg(long)]
        reason: Option<String>,

        /// Skip the confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Approve one version of a name already in the catalog, and ingest it
    Pin {
        /// Remote MCP repository key
        #[arg(long)]
        repo: String,

        /// Server name, such as io.github.acme/weather
        server: String,

        /// Exact version
        version: String,

        /// Why, for the audit log
        #[arg(long)]
        reason: Option<String>,

        /// Skip the confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

#[derive(Subcommand)]
pub enum SyncCommand {
    /// Start a sync pass in the background
    Start {
        /// Remote MCP repository key
        #[arg(long)]
        repo: String,

        /// Wait for the pass to end, and fail if it recorded an error
        #[arg(long)]
        wait: bool,

        /// How long --wait waits, in seconds
        #[arg(long = "wait-timeout", default_value = "1800", requires = "wait")]
        wait_timeout: u64,
    },

    /// Show whether a pass is running, and how the last one ended
    Status {
        /// Remote MCP repository key
        #[arg(long)]
        repo: String,

        /// Wait for a running pass to end, and fail if it recorded an error
        #[arg(long)]
        wait: bool,

        /// How long --wait waits, in seconds
        #[arg(long = "wait-timeout", default_value = "1800", requires = "wait")]
        wait_timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum SeedCommand {
    /// Approve and pin server versions, fetching their names from the upstream
    Start {
        /// Remote MCP repository key
        #[arg(long)]
        repo: String,

        /// Server versions as NAME@VERSION, such as io.github.acme/weather@1.2.0 (1 to 500)
        #[arg(required = true, num_args = 1.., value_name = "NAME@VERSION")]
        servers: Vec<String>,

        /// Why, recorded as the approval reason of every pin
        #[arg(long)]
        reason: Option<String>,

        /// Wait for the job to end, and fail if any version wasn't pinned
        #[arg(long)]
        wait: bool,

        /// How long --wait waits, in seconds
        #[arg(long = "wait-timeout", default_value = "1800", requires = "wait")]
        wait_timeout: u64,

        /// Skip the confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Show a seed job and what happened to each version
    Status {
        /// Remote MCP repository key
        #[arg(long)]
        repo: String,

        /// Seed job ID
        job_id: String,

        /// Wait for the job to end, and fail if any version wasn't pinned
        #[arg(long)]
        wait: bool,

        /// How long --wait waits, in seconds
        #[arg(long = "wait-timeout", default_value = "1800", requires = "wait")]
        wait_timeout: u64,
    },
}

impl McpCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::NamespaceProof(command) => command.execute(global).await,
            Self::Catalog(command) => command.execute(global).await,
            Self::Sync(command) => command.execute(global).await,
            Self::Seed(command) => command.execute(global).await,
            Self::Health {
                repo,
                server,
                version,
                include_deleted,
            } => health(&repo, &server, &version, include_deleted, global).await,
            Self::Pending => pending(global).await,
            Self::Version(command) => command.execute(global).await,
        }
    }
}

impl ProofCommand {
    async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List => list_proofs(global).await,
            Self::Create { namespace, method } => create_proof(namespace, method, global).await,
            Self::Show { id } => show_proof(&id, global).await,
            Self::Verify { id } => verify_proof(&id, global).await,
            Self::Delete { id, yes } => delete_proof(&id, yes, global).await,
        }
    }
}

impl CatalogCommand {
    async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List {
                repo,
                search,
                status,
                namespace,
                requested,
                queue,
                cursor,
                limit,
            } => {
                let filter = CatalogFilter {
                    search,
                    status,
                    namespace,
                    requested,
                    queue,
                    cursor,
                    limit,
                };
                list_catalog(&repo, filter, global).await
            }
            Self::Show { repo, server } => show_server(&repo, &server, global).await,
            Self::Approve {
                repo,
                id,
                reason,
                yes,
            } => decide(&repo, &id, Decision::Approve, reason, yes, global).await,
            Self::Block {
                repo,
                id,
                reason,
                yes,
            } => decide(&repo, &id, Decision::Block, reason, yes, global).await,
            Self::Reopen {
                repo, id, reason, ..
            } => decide(&repo, &id, Decision::Reopen, reason, true, global).await,
            Self::RequestApproval { repo, id, note } => {
                request_approval(&repo, &id, note, global).await
            }
            Self::BulkApprove {
                repo,
                pattern,
                include_review,
                reason,
                dry_run,
                yes,
            } => {
                let body = BulkApproveRequest {
                    pattern,
                    include_review: include_review.then_some(true),
                    reason,
                    dry_run: dry_run.then_some(true),
                };
                bulk_approve(&repo, body, yes, global).await
            }
            Self::BulkBlock {
                repo,
                pattern,
                reason,
                dry_run,
                yes,
            } => {
                let body = BulkBlockRequest {
                    pattern,
                    reason,
                    dry_run: dry_run.then_some(true),
                };
                bulk_block(&repo, body, yes, global).await
            }
            Self::BulkDecide {
                repo,
                action,
                ids,
                reason,
                yes,
            } => bulk_decide(&repo, &action, &ids, reason, yes, global).await,
            Self::Pin {
                repo,
                server,
                version,
                reason,
                yes,
            } => pin(&repo, server, version, reason, yes, global).await,
        }
    }
}

impl SyncCommand {
    async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Start {
                repo,
                wait,
                wait_timeout,
            } => start_sync(&repo, wait.then_some(wait_timeout), global).await,
            Self::Status {
                repo,
                wait,
                wait_timeout,
            } => sync_status(&repo, wait.then_some(wait_timeout), global).await,
        }
    }
}

impl SeedCommand {
    async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Start {
                repo,
                servers,
                reason,
                wait,
                wait_timeout,
                yes,
            } => {
                start_seed(
                    &repo,
                    &servers,
                    reason,
                    (yes, wait.then_some(wait_timeout)),
                    global,
                )
                .await
            }
            Self::Status {
                repo,
                job_id,
                wait,
                wait_timeout,
            } => seed_status(&repo, &job_id, wait.then_some(wait_timeout), global).await,
        }
    }
}

// ---- small helpers ----

pub(super) fn text(value: &Value) -> String {
    match value {
        Value::Null => "-".to_string(),
        Value::String(s) if s.is_empty() => "-".to_string(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn day(value: &Value) -> String {
    match value.as_str() {
        Some(at) => at.get(..16).unwrap_or(at).replace('T', " "),
        None => "-".to_string(),
    }
}

fn opt(value: Option<&str>) -> String {
    value.filter(|s| !s.is_empty()).unwrap_or("-").to_string()
}

/// A server name as the two path segments of the split routes, when it has the
/// usual one slash. A name sent that way survives a proxy in front of the server
/// that refuses an encoded slash. Any other name goes URL-encoded, as one segment.
pub(super) fn split_name(server: &str) -> Option<(&str, &str)> {
    let (ns, name) = server.split_once('/')?;
    (!ns.is_empty() && !name.is_empty() && !name.contains('/')).then_some((ns, name))
}

/// Refuse a server name or version the request path can't carry as given: the
/// generated client doesn't escape `%`, and an empty, `.` or `..` segment would
/// reach another route.
pub(super) fn check_path_parts(server: &str, version: Option<&str>) -> Result<()> {
    let bad = |part: &str| part.is_empty() || part == "." || part == ".." || part.contains('%');
    let parts: Vec<&str> = match split_name(server) {
        Some((ns, name)) => vec![ns, name],
        None => vec![server],
    };
    if parts.iter().any(|p| bad(p)) {
        return Err(AkError::Usage(format!(
            "'{server}' isn't a server name ak can send: a namespace or name can't be empty, \
             '.' or '..', or contain '%'"
        ))
        .into());
    }
    if let Some(version) = version.filter(|v| bad(v)) {
        return Err(AkError::Usage(format!(
            "'{version}' isn't a version ak can send: it can't be empty, '.' or '..', or \
             contain '%'"
        ))
        .into());
    }
    Ok(())
}

/// `NAME@VERSION`, split at the last `@`.
fn parse_server_version(value: &str) -> Result<SeedServer> {
    match value.rsplit_once('@') {
        Some((name, version)) if !name.is_empty() && !version.is_empty() => Ok(SeedServer {
            name: name.to_string(),
            version: version.to_string(),
        }),
        _ => Err(AkError::Usage(format!(
            "'{value}' isn't NAME@VERSION, such as io.github.acme/weather@1.2.0"
        ))
        .into()),
    }
}

// ---- namespace proofs ----

fn proof_table(items: &[Value]) -> String {
    let mut table = new_table(vec![
        "ID",
        "NAMESPACE",
        "DOMAIN",
        "METHOD",
        "STATUS",
        "CHECKED",
        "VERIFIED",
    ]);
    for p in items {
        table.add_row(vec![
            text(&p["id"]),
            text(&p["namespace"]),
            text(&p["domain"]),
            text(&p["method"]),
            text(&p["status"]),
            day(&p["last_checked_at"]),
            day(&p["verified_at"]),
        ]);
    }
    table.to_string()
}

/// What the domain has to publish, in words.
fn challenge_lines(p: &Map<String, Value>) -> Vec<String> {
    let c = &p.get("challenge").cloned().unwrap_or_default();
    if let Some(name) = c["name"].as_str() {
        vec![
            format!(
                "Publish a {} record at {name}",
                c["type"].as_str().unwrap_or("TXT")
            ),
            format!("with the value:    {}", text(&c["value"])),
        ]
    } else if let Some(url) = c["url"].as_str() {
        vec![
            format!("Serve {url}"),
            format!("with this line:    {}", text(&c["content"])),
        ]
    } else {
        Vec::new()
    }
}

fn proof_detail(p: &Map<String, Value>) -> String {
    let get = |k: &str| p.get(k).cloned().unwrap_or_default();
    let mut out = vec![
        format!("ID:           {}", text(&get("id"))),
        format!("Namespace:    {}", text(&get("namespace"))),
        format!("Domain:       {}", text(&get("domain"))),
        format!("Method:       {}", text(&get("method"))),
        format!("Status:       {}", text(&get("status"))),
        format!("Last error:   {}", text(&get("last_error"))),
        format!("Created:      {}", day(&get("created_at"))),
        format!("Last checked: {}", day(&get("last_checked_at"))),
        format!("Verified:     {}", day(&get("verified_at"))),
    ];
    let challenge = challenge_lines(p);
    if !challenge.is_empty() {
        out.push(String::new());
        out.extend(challenge);
    }
    out.join("\n")
}

fn print_proof(p: &Map<String, Value>, raw: Option<&[u8]>, global: &GlobalArgs) {
    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", text(&p.get("id").cloned().unwrap_or_default()));
        return;
    }
    println!(
        "{}",
        output::render_raw(raw, p, &global.format, Some(proof_detail(p)))
    );
}

async fn list_proofs(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching namespace proofs...");
    let (resp, raw) = capture(client.mcp_list_namespace_proofs().send()).await;
    let proofs = or_since(
        V1_12,
        resp,
        "list namespace proofs",
        "mcp namespace-proof list",
        global,
    )
    .await?
    .into_inner();
    spinner.finish_and_clear();

    let items = proofs
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if matches!(global.format, OutputFormat::Quiet) {
        for p in &items {
            println!("{}", text(&p["id"]));
        }
        return Ok(());
    }
    if items.is_empty() && !output::is_machine_format(&global.format) {
        eprintln!("No namespace proofs.");
        return Ok(());
    }
    println!(
        "{}",
        output::render_raw(
            raw.as_deref(),
            &proofs,
            &global.format,
            Some(proof_table(&items))
        )
    );
    Ok(())
}

async fn create_proof(namespace: String, method: String, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Creating namespace proof...");
    let (resp, raw) = capture(
        client
            .mcp_create_namespace_proof()
            .body(CreateProof { method, namespace })
            .send(),
    )
    .await;
    let proof = or_since(
        V1_12,
        resp,
        "create namespace proof",
        "mcp namespace-proof create",
        global,
    )
    .await?
    .into_inner();
    spinner.finish_and_clear();
    print_proof(&proof, raw.as_deref(), global);
    if matches!(global.format, OutputFormat::Table) {
        eprintln!(
            "Then check it: ak mcp namespace-proof verify {}",
            text(&proof.get("id").cloned().unwrap_or_default())
        );
    }
    Ok(())
}

async fn show_proof(id: &str, global: &GlobalArgs) -> Result<()> {
    let proof_id = parse_uuid(id, "namespace proof")?;
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching namespace proof...");
    let (resp, raw) = capture(client.mcp_get_namespace_proof().id(proof_id).send()).await;
    let proof = or_since(
        V1_12,
        resp,
        "get namespace proof",
        "mcp namespace-proof show",
        global,
    )
    .await?
    .into_inner();
    spinner.finish_and_clear();
    print_proof(&proof, raw.as_deref(), global);
    Ok(())
}

async fn verify_proof(id: &str, global: &GlobalArgs) -> Result<()> {
    let proof_id = parse_uuid(id, "namespace proof")?;
    let client = client_for(global)?;
    let spinner = output::spinner("Checking namespace proof...");
    let (resp, raw) = capture(client.mcp_verify_namespace_proof().id(proof_id).send()).await;
    let proof = or_since(
        V1_12,
        resp,
        "verify namespace proof",
        "mcp namespace-proof verify",
        global,
    )
    .await?
    .into_inner();
    spinner.finish_and_clear();
    print_proof(&proof, raw.as_deref(), global);
    match proof.get("status").and_then(Value::as_str) {
        Some("verified") | None => Ok(()),
        Some(status) => Err(reported_failure(&format!(
            "Namespace proof {id} is {status}: {}",
            proof
                .get("last_error")
                .and_then(Value::as_str)
                .unwrap_or("no reason given")
        ))),
    }
}

async fn delete_proof(id: &str, yes: bool, global: &GlobalArgs) -> Result<()> {
    let proof_id = parse_uuid(id, "namespace proof")?;
    if !confirm_action(
        &format!("Delete namespace proof {id}?"),
        yes,
        global.no_input,
    )? {
        return Ok(());
    }
    let client = client_for(global)?;
    let spinner = output::spinner("Deleting namespace proof...");
    let resp = client
        .mcp_delete_namespace_proof()
        .id(proof_id)
        .send()
        .await;
    or_since(
        V1_12,
        resp,
        "delete namespace proof",
        "mcp namespace-proof delete",
        global,
    )
    .await?;
    spinner.finish_and_clear();
    emit_mutation(
        &serde_json::json!({ "id": id, "status": "deleted" }),
        id,
        &format!("Namespace proof {id} deleted."),
        global,
    );
    Ok(())
}

// ---- the catalog ----

struct CatalogFilter {
    search: Option<String>,
    status: Option<String>,
    namespace: Option<String>,
    requested: bool,
    queue: bool,
    cursor: Option<String>,
    limit: Option<i64>,
}

fn status_of(item: &CatalogItem) -> String {
    if item.denied == Some(true) {
        format!("{} (denied)", item.status)
    } else {
        item.status.clone()
    }
}

fn request_count(item: &CatalogItem) -> String {
    item.approval_requests
        .get("count")
        .and_then(Value::as_i64)
        .unwrap_or(0)
        .to_string()
}

fn flag_names(item: &CatalogItem) -> String {
    if item.flags.is_empty() {
        "-".to_string()
    } else {
        item.flags.keys().cloned().collect::<Vec<_>>().join(", ")
    }
}

async fn list_catalog(repo: &str, filter: CatalogFilter, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching the catalog...");
    let mut req = client.mcp_remote_list_catalog().key(repo);
    if let Some(search) = filter.search {
        req = req.search(search);
    }
    if let Some(status) = filter.status {
        req = req.status(status);
    }
    if let Some(namespace) = filter.namespace {
        req = req.namespace(namespace);
    }
    if filter.requested {
        req = req.requested(true);
    }
    if filter.queue {
        req = req.queue(true);
    }
    if let Some(cursor) = filter.cursor {
        req = req.cursor(cursor);
    }
    if let Some(limit) = filter.limit {
        req = req.limit(limit);
    }
    let (resp, raw) = capture(req.send()).await;
    let page = or_since(V1_12, resp, "list the catalog", "mcp catalog list", global)
        .await?
        .into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        for item in &page.items {
            println!("{}", item.id);
        }
        return Ok(());
    }
    if page.items.is_empty() && !output::is_machine_format(&global.format) {
        eprintln!("No servers in the catalog match.");
        return Ok(());
    }
    let mut table = new_table(vec![
        "ID", "NAME", "STATUS", "LATEST", "INGESTED", "FLAGS", "REQUESTS",
    ]);
    for item in &page.items {
        let ingested: Vec<&str> = item.ingested.iter().map(|v| v.version.as_str()).collect();
        table.add_row(vec![
            item.id.to_string(),
            item.name.clone(),
            status_of(item),
            opt(item.latest_version.as_deref()),
            if ingested.is_empty() {
                "-".to_string()
            } else {
                ingested.join(", ")
            },
            flag_names(item),
            request_count(item),
        ]);
    }
    println!(
        "{}",
        output::render_raw(
            raw.as_deref(),
            &page,
            &global.format,
            Some(table.to_string())
        )
    );
    if matches!(global.format, OutputFormat::Table) {
        if !page.counts.is_empty() {
            let counts: Vec<String> = page
                .counts
                .iter()
                .map(|(status, n)| format!("{status} {n}"))
                .collect();
            eprintln!("In the repository: {}", counts.join(", "));
        }
        if let Some(cursor) = &page.next_cursor {
            eprintln!("More: ak mcp catalog list --repo {repo} --cursor {cursor}");
        }
    }
    Ok(())
}

fn server_detail(item: &CatalogItem) -> String {
    let mut out = vec![
        format!("Name:            {}", item.name),
        format!("ID:              {}", item.id),
        format!("Status:          {}", status_of(item)),
        format!("Title:           {}", opt(item.title.as_deref())),
        format!("Description:     {}", opt(item.description.as_deref())),
        format!("Latest upstream: {}", opt(item.latest_version.as_deref())),
        format!("Upstream status: {}", opt(item.upstream_status.as_deref())),
        format!(
            "First seen:      {}",
            item.first_seen_at.format("%Y-%m-%d %H:%M")
        ),
        format!("Flags:           {}", flag_names(item)),
        format!("Requests:        {}", request_count(item)),
    ];
    if let Some(at) = item.evaluated_at {
        out.push(format!(
            "Decided:         {}{}",
            at.format("%Y-%m-%d %H:%M"),
            item.evaluation_reason
                .as_deref()
                .map(|r| format!(" ({r})"))
                .unwrap_or_default()
        ));
    }
    if let Some(summary) = &item.summary {
        out.push(format!(
            "Transports:      {}",
            if summary.transports.is_empty() {
                "-".to_string()
            } else {
                summary.transports.join(", ")
            }
        ));
        out.push(format!(
            "Packages:        {} ({})",
            summary.packages_count,
            if summary.registry_types.is_empty() {
                "-".to_string()
            } else {
                summary.registry_types.join(", ")
            }
        ));
        out.push(format!("Remotes:         {}", summary.remotes_count));
        out.push(format!("Secrets:         {}", summary.secrets_count));
        if let Some(lint) = &summary.lint {
            out.push(format!(
                "Lint ({}):     {} block, {} review, {} warn",
                lint.version, lint.block, lint.review, lint.warn
            ));
        }
    }
    if !item.ingested.is_empty() {
        let mut table = new_table(vec!["INGESTED", "ARTIFACT", "UPSTREAM", "UNRESOLVED"]);
        for v in &item.ingested {
            table.add_row(vec![
                v.version.clone(),
                v.artifact_id.to_string(),
                v.upstream_status.clone(),
                v.unresolved.len().to_string(),
            ]);
        }
        out.push(String::new());
        out.push(table.to_string());
    }
    if !item.pins.is_empty() {
        let mut table = new_table(vec!["PIN", "ID", "STATUS", "DRIFT", "REASON"]);
        for p in &item.pins {
            table.add_row(vec![
                p.version.clone(),
                p.id.to_string(),
                p.status.clone(),
                if p.content_drift.is_some() {
                    "yes"
                } else {
                    "no"
                }
                .to_string(),
                opt(p.evaluation_reason.as_deref()),
            ]);
        }
        out.push(String::new());
        out.push(table.to_string());
    }
    out.join("\n")
}

async fn show_server(repo: &str, server: &str, global: &GlobalArgs) -> Result<()> {
    check_path_parts(server, None)?;
    let spinner = output::spinner("Fetching the server...");
    let (item, raw) = match split_name(server) {
        Some((ns, name)) => get_server_split(repo, ns, name, global).await?,
        None => {
            let client = client_for(global)?;
            let (resp, raw) = capture(
                client
                    .mcp_remote_get_server_encoded()
                    .key(repo)
                    .server_name(server)
                    .send(),
            )
            .await;
            let item = or_since(V1_12, resp, "get the server", "mcp catalog show", global)
                .await?
                .into_inner();
            (item, raw)
        }
    };
    spinner.finish_and_clear();
    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", item.id);
        return Ok(());
    }
    println!(
        "{}",
        output::render_raw(
            raw.as_deref(),
            &item,
            &global.format,
            Some(server_detail(&item))
        )
    );
    Ok(())
}

/// `GET .../mcp/catalog/servers/{ns}/{name}`, which the spec doesn't describe: the
/// same handler as the URL-encoded route.
async fn get_server_split(
    repo: &str,
    ns: &str,
    name: &str,
    global: &GlobalArgs,
) -> Result<(CatalogItem, Option<Vec<u8>>)> {
    let action = "Failed to get the server";
    let (base_url, auth_header) = resolve_base_url_and_auth(global)?;
    let mut url = reqwest::Url::parse(&base_url)
        .map_err(|e| AkError::ConfigError(format!("Invalid instance URL {base_url}: {e}")))?;
    url.path_segments_mut()
        .map_err(|_| AkError::ConfigError(format!("Invalid instance URL: {base_url}")))?
        .pop_if_empty()
        .extend([
            "api",
            "v1",
            "repositories",
            repo,
            "mcp",
            "catalog",
            "servers",
            ns,
            name,
        ]);
    let response = raw_http_client()?
        .get(url)
        .header(reqwest::header::AUTHORIZATION, auth_header)
        .send()
        .await
        .map_err(|e| AkError::NetworkError(format!("{action}: {e}")))?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|e| AkError::NetworkError(format!("{action}: {e}")))?;
    if !status.is_success() {
        let body = String::from_utf8_lossy(&bytes);
        return Err(
            since_raw(V1_12, status, &body, action, "mcp catalog show", global)
                .await
                .into(),
        );
    }
    let item: CatalogItem =
        serde_json::from_slice(&bytes).map_err(|e| super::helpers::bad_response(action, e))?;
    Ok((item, Some(bytes.to_vec())))
}

fn decision_words(decision: Decision) -> (&'static str, &'static str, &'static str) {
    match decision {
        Decision::Approve => ("Approving", "approve", "Approved"),
        Decision::Block => ("Blocking", "block", "Blocked"),
        Decision::Reopen => ("Reopening", "reopen", "Reopened"),
    }
}

/// Print a decision's answer, and warn when the approval's ingest waits for the
/// next sync.
fn print_decision(result: &DecisionResult, raw: Option<&[u8]>, human: String, global: &GlobalArgs) {
    emit_mutation_raw(raw, result, &result.item.id.to_string(), &human, global);
    if let Some(error) = &result.ingest_error {
        eprintln!(
            "Warning: approved, but not ingested yet: {}. The next sync ingests it.",
            output::sanitize_terminal(error)
        );
    }
}

async fn decide(
    repo: &str,
    id: &str,
    decision: Decision,
    reason: Option<String>,
    yes: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let row_id = parse_uuid(id, "catalog row")?;
    let (doing, verb, done) = decision_words(decision);
    let prompt = match decision {
        Decision::Approve => format!(
            "Approve {id} in '{repo}'? It's ingested, and served to every reader of the registry."
        ),
        Decision::Block => format!("Block {id} in '{repo}'? It stops being served."),
        Decision::Reopen => String::new(),
    };
    if !matches!(decision, Decision::Reopen) && !confirm_action(&prompt, yes, global.no_input)? {
        return Ok(());
    }
    let client = client_for(global)?;
    let spinner = output::spinner(&format!("{doing} {id}..."));
    let (resp, raw) = capture(
        client
            .mcp_remote_decide()
            .key(repo)
            .id(row_id)
            .decision(decision)
            .body(DecisionRequest { reason })
            .send(),
    )
    .await;
    let result = or_since(
        V1_12,
        resp,
        &format!("{verb} {id}"),
        &format!("mcp catalog {verb}"),
        global,
    )
    .await?
    .into_inner();
    spinner.finish_and_clear();
    let human = format!(
        "{done} {} in '{repo}': now {}.",
        result.item.name, result.item.status
    );
    print_decision(&result, raw.as_deref(), human, global);
    Ok(())
}

async fn request_approval(
    repo: &str,
    id: &str,
    note: Option<String>,
    global: &GlobalArgs,
) -> Result<()> {
    let row_id = parse_uuid(id, "catalog row")?;
    let client = client_for(global)?;
    let spinner = output::spinner("Asking for approval...");
    let (resp, raw) = capture(
        client
            .mcp_remote_request_approval()
            .key(repo)
            .id(row_id)
            .body(ApprovalRequestBody { note })
            .send(),
    )
    .await;
    let item = or_since(
        V1_12,
        resp,
        "request approval",
        "mcp catalog request-approval",
        global,
    )
    .await?
    .into_inner();
    spinner.finish_and_clear();
    emit_mutation_raw(
        raw.as_deref(),
        &item,
        &item.id.to_string(),
        &format!(
            "Asked for approval of {} in '{repo}' ({} request(s) so far).",
            item.name,
            request_count(&item)
        ),
        global,
    );
    Ok(())
}

/// What a bulk approval or block did, or would do.
fn print_bulk(
    result: &artifact_keeper_sdk::types::BulkResult,
    raw: Option<&[u8]>,
    approving: bool,
    global: &GlobalArgs,
) {
    if matches!(global.format, OutputFormat::Quiet) {
        for name in &result.names {
            println!("{name}");
        }
        return;
    }
    let (count, verb) = if approving {
        (result.approved, "approved")
    } else {
        (result.blocked, "blocked")
    };
    let mut out = Vec::new();
    if !result.names.is_empty() {
        let mut table = new_table(vec!["NAME"]);
        for name in &result.names {
            table.add_row(vec![name.clone()]);
        }
        out.push(table.to_string());
    }
    if !out.is_empty() || output::is_machine_format(&global.format) {
        println!(
            "{}",
            output::render_raw(raw, result, &global.format, Some(out.join("\n")))
        );
    }
    if matches!(global.format, OutputFormat::Table) {
        let mut summary = if result.dry_run {
            format!("Dry run: {count} name(s) would be {verb}. Nothing was changed.")
        } else {
            format!("{count} name(s) {verb}.")
        };
        if result.names.len() < count as usize {
            summary.push_str(&format!(" The first {} are listed.", result.names.len()));
        }
        if result.skipped_review > 0 {
            summary.push_str(&format!(
                " {} flagged for review left alone (--include-review takes them).",
                result.skipped_review
            ));
        }
        if result.skipped_denied > 0 {
            summary.push_str(&format!(
                " {} denied by mcp_server_deny left alone.",
                result.skipped_denied
            ));
        }
        eprintln!("{summary}");
    }
}

async fn bulk_approve(
    repo: &str,
    body: BulkApproveRequest,
    yes: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let dry_run = body.dry_run == Some(true);
    if !dry_run
        && !confirm_action(
            &format!(
                "Approve every server matching '{}' in '{repo}'? They're ingested, and served \
                 to every reader of the registry.",
                body.pattern
            ),
            yes,
            global.no_input,
        )?
    {
        return Ok(());
    }
    let client = client_for(global)?;
    let spinner = output::spinner("Approving...");
    let (resp, raw) = capture(client.mcp_remote_bulk_approve().key(repo).body(body).send()).await;
    let result = or_since(
        V1_12,
        resp,
        "bulk approve",
        "mcp catalog bulk-approve",
        global,
    )
    .await?
    .into_inner();
    spinner.finish_and_clear();
    print_bulk(&result, raw.as_deref(), true, global);
    Ok(())
}

async fn bulk_block(
    repo: &str,
    body: BulkBlockRequest,
    yes: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let dry_run = body.dry_run == Some(true);
    if !dry_run
        && !confirm_action(
            &format!(
                "Block every server matching '{}' in '{repo}'? They stop being served.",
                body.pattern
            ),
            yes,
            global.no_input,
        )?
    {
        return Ok(());
    }
    let client = client_for(global)?;
    let spinner = output::spinner("Blocking...");
    let (resp, raw) = capture(client.mcp_remote_bulk_block().key(repo).body(body).send()).await;
    let result = or_since(V1_12, resp, "bulk block", "mcp catalog bulk-block", global)
        .await?
        .into_inner();
    spinner.finish_and_clear();
    print_bulk(&result, raw.as_deref(), false, global);
    Ok(())
}

async fn bulk_decide(
    repo: &str,
    action: &str,
    ids: &[String],
    reason: Option<String>,
    yes: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let ids = ids
        .iter()
        .map(|id| parse_uuid(id, "catalog row"))
        .collect::<Result<Vec<_>>>()?;
    let (bulk_action, verb, effect) = match action {
        "approve" => (
            BulkAction::Approve,
            "Approve",
            "They're ingested, and served to every reader of the registry.",
        ),
        _ => (BulkAction::Block, "Block", "They stop being served."),
    };
    if !confirm_action(
        &format!("{verb} {} catalog row(s) in '{repo}'? {effect}", ids.len()),
        yes,
        global.no_input,
    )? {
        return Ok(());
    }
    let client = client_for(global)?;
    let spinner = output::spinner(&format!("{verb}..."));
    let (resp, raw) = capture(
        client
            .mcp_remote_bulk_decide()
            .key(repo)
            .body(BulkDecideRequest {
                action: bulk_action,
                ids,
                reason,
            })
            .send(),
    )
    .await;
    let result = or_since(
        V1_12,
        resp,
        &format!("bulk {action}"),
        "mcp catalog bulk-decide",
        global,
    )
    .await?
    .into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        for id in &result.decided {
            println!("{id}");
        }
    } else {
        let mut table = new_table(vec!["ID", "OUTCOME"]);
        let groups = [
            (&result.decided, "decided"),
            (&result.unchanged, "unchanged"),
            (&result.skipped_denied, "skipped: denied"),
            (&result.not_found, "not found"),
        ];
        for (ids, outcome) in groups {
            for id in ids {
                table.add_row(vec![id.to_string(), outcome.to_string()]);
            }
        }
        println!(
            "{}",
            output::render_raw(
                raw.as_deref(),
                &result,
                &global.format,
                Some(table.to_string())
            )
        );
    }
    if !result.skipped_denied.is_empty() {
        eprintln!(
            "Warning: {} row(s) left alone: their names match mcp_server_deny.",
            result.skipped_denied.len()
        );
    }
    if !result.not_found.is_empty() {
        let missing: Vec<String> = result.not_found.iter().map(|id| id.to_string()).collect();
        return Err(reported_failure(&format!(
            "{} ID(s) aren't rows of the catalog of '{repo}': {}",
            missing.len(),
            missing.join(", ")
        )));
    }
    Ok(())
}

async fn pin(
    repo: &str,
    server: String,
    version: String,
    reason: Option<String>,
    yes: bool,
    global: &GlobalArgs,
) -> Result<()> {
    if !confirm_action(
        &format!(
            "Approve and pin {server}@{version} in '{repo}'? It's ingested, and served to every \
             reader of the registry."
        ),
        yes,
        global.no_input,
    )? {
        return Ok(());
    }
    let client = client_for(global)?;
    let spinner = output::spinner("Pinning...");
    let pinned = format!("{server}@{version}");
    let (resp, raw) = capture(
        client
            .mcp_remote_create_pin()
            .key(repo)
            .body(PinRequest {
                name: server,
                version,
                reason,
            })
            .send(),
    )
    .await;
    let result = or_since(V1_12, resp, "pin", "mcp catalog pin", global)
        .await?
        .into_inner();
    spinner.finish_and_clear();
    print_decision(
        &result,
        raw.as_deref(),
        format!("Pinned {pinned} in '{repo}'."),
        global,
    );
    Ok(())
}

// ---- sync ----

fn sync_detail(s: &Map<String, Value>) -> String {
    let get = |k: &str| s.get(k).cloned().unwrap_or_default();
    let summary = get("lastSummary");
    let mut out = vec![
        format!(
            "Running:        {}",
            if get("running").as_bool() == Some(true) {
                "yes"
            } else {
                "no"
            }
        ),
        format!("Last started:   {}", day(&get("lastStartedAt"))),
        format!("Last finished:  {}", day(&get("lastFinishedAt"))),
        format!("Last succeeded: {}", day(&get("lastSucceededAt"))),
        format!("Last error:     {}", text(&get("lastError"))),
    ];
    if summary.as_object().is_some_and(|m| !m.is_empty()) {
        let n = |k: &str| summary[k].as_i64().unwrap_or(0);
        out.push(format!(
            "Last pass:      {} page(s), {} entries, {} new name(s), {} auto-approved, {} \
             flagged, {} ingested, {} drifted, {} unresolved",
            n("pages"),
            n("entries"),
            n("namesNew"),
            n("autoApproved"),
            n("flagged"),
            n("ingested"),
            n("drifted"),
            n("unresolved")
        ));
        out.push(format!(
            "Reached the end: {}",
            if summary["complete"].as_bool() == Some(true) {
                "yes"
            } else {
                "no (the next pass resumes)"
            }
        ));
        if let Some(errors) = summary["errors"].as_array().filter(|e| !e.is_empty()) {
            out.push(format!("Errors:         {}", errors.len()));
            for e in errors.iter().take(5) {
                out.push(format!("  {}", text(e)));
            }
        }
    }
    out.join("\n")
}

fn print_sync(s: &Map<String, Value>, raw: Option<&[u8]>, global: &GlobalArgs) {
    if matches!(global.format, OutputFormat::Quiet) {
        println!(
            "{}",
            if s.get("running").and_then(Value::as_bool) == Some(true) {
                "running"
            } else {
                "idle"
            }
        );
        return;
    }
    println!(
        "{}",
        output::render_raw(raw, s, &global.format, Some(sync_detail(s)))
    );
}

/// The pass that just ended failed if it recorded an error.
fn sync_outcome(s: &Map<String, Value>, repo: &str) -> Result<()> {
    match s.get("lastError").and_then(Value::as_str) {
        Some(error) if !error.is_empty() => Err(reported_failure(&format!(
            "The last sync of '{repo}' failed: {error}"
        ))),
        _ => Ok(()),
    }
}

async fn start_sync(repo: &str, wait: Option<u64>, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    // With --wait, how the last pass ended, so the wait can tell this pass's end
    // from it.
    let before = match wait {
        Some(_) => {
            let (resp, raw) = capture(client.mcp_remote_sync_status().key(repo).send()).await;
            or_since(V1_12, resp, "read sync status", "mcp sync start", global).await?;
            let state: Value = raw
                .as_deref()
                .and_then(|b| serde_json::from_slice(b).ok())
                .unwrap_or_default();
            Some(state.get("lastFinishedAt").cloned().unwrap_or(Value::Null))
        }
        None => None,
    };
    let spinner = output::spinner("Starting a sync...");
    let (resp, raw) = capture(client.mcp_remote_trigger_sync().key(repo).send()).await;
    let accepted = or_since(V1_12, resp, "start a sync", "mcp sync start", global)
        .await?
        .into_inner();
    spinner.finish_and_clear();
    let Some(timeout) = wait else {
        emit_mutation_raw(
            raw.as_deref(),
            &accepted,
            &accepted.repository,
            &format!(
                "Sync of '{repo}' started. Follow it: ak mcp sync status --repo {repo} --wait"
            ),
            global,
        );
        return Ok(());
    };
    follow_sync(repo, before, timeout, global).await
}

async fn sync_status(repo: &str, wait: Option<u64>, global: &GlobalArgs) -> Result<()> {
    if let Some(timeout) = wait {
        return follow_sync(repo, None, timeout, global).await;
    }
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching sync status...");
    let (resp, raw) = capture(client.mcp_remote_sync_status().key(repo).send()).await;
    let state = or_since(V1_12, resp, "read sync status", "mcp sync status", global)
        .await?
        .into_inner();
    spinner.finish_and_clear();
    print_sync(&state, raw.as_deref(), global);
    Ok(())
}

/// How long `--wait` waits, after the lock is free, for the pass it follows to
/// record how it ended. The server lets go of the lock before it records a failure.
const SYNC_RECORD_GRACE: std::time::Duration = std::time::Duration::from_secs(30);

/// What `--wait` knows about the pass it follows.
#[derive(Default)]
struct SyncWatch {
    /// `lastFinishedAt` before the pass: once a pass is known to run, the state
    /// that ends the wait has to have moved past it. `None` until then.
    before: Option<Value>,
    /// When the lock was first seen free with nothing new recorded.
    idle_since: Option<std::time::Instant>,
    /// The wait ended at the grace limit with nothing new recorded.
    stale: bool,
}

/// One look at the sync state: still running, or done.
fn sync_step(watch: &mut SyncWatch, state: &Value, now: std::time::Instant) -> bool {
    let finished = state.get("lastFinishedAt").cloned().unwrap_or(Value::Null);
    if state["running"].as_bool() == Some(true) {
        watch.before.get_or_insert(finished);
        watch.idle_since = None;
        return false;
    }
    let Some(before) = &watch.before else {
        // Never seen a pass and none running: the state is the last pass's.
        return true;
    };
    if finished != *before && !finished.is_null() {
        return true;
    }
    let idle = *watch.idle_since.get_or_insert(now);
    if now.duration_since(idle) >= SYNC_RECORD_GRACE {
        watch.stale = true;
        return true;
    }
    false
}

/// Poll `GET .../mcp/sync` until the pass ends and records how, print that, and fail
/// if it recorded an error. `before` is `lastFinishedAt` from before a pass was
/// started, if this command started one.
async fn follow_sync(
    repo: &str,
    before: Option<Value>,
    timeout: u64,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let watch = std::cell::RefCell::new(SyncWatch {
        before,
        ..SyncWatch::default()
    });
    let bytes = poll_job(
        &format!("Syncing '{repo}'..."),
        &format!("the sync of '{repo}'"),
        &format!("ak mcp sync status --repo {repo}"),
        timeout,
        || async {
            let (resp, raw) = capture(client.mcp_remote_sync_status().key(repo).send()).await;
            match resp {
                Ok(_) => {
                    let bytes = raw.unwrap_or_default();
                    let state: Value = serde_json::from_slice(&bytes).unwrap_or_default();
                    let done =
                        sync_step(&mut watch.borrow_mut(), &state, std::time::Instant::now());
                    Ok(if done {
                        Polled::Done(bytes)
                    } else {
                        Polled::Running
                    })
                }
                Err(e) if e.status().is_some_and(|s| s.is_client_error()) => {
                    Err(
                        since(V1_12, e, "read sync status", "mcp sync status", global)
                            .await
                            .into(),
                    )
                }
                Err(_) => Ok(Polled::Unreadable),
            }
        },
    )
    .await?;
    let state: Map<String, Value> = serde_json::from_slice(&bytes).unwrap_or_default();
    print_sync(&state, Some(&bytes), global);
    if watch.borrow().stale {
        return Err(reported_failure(&format!(
            "The sync of '{repo}' ended without recording how: the state shown is from an \
             earlier pass. Check it: ak mcp sync status --repo {repo}"
        )));
    }
    sync_outcome(&state, repo)
}

// ---- seed ----

fn seed_table(job: &Value) -> String {
    let mut out = vec![format!(
        "Job {} in '{}': {}{}",
        text(&job["jobId"]),
        text(&job["repository"]),
        text(&job["status"]),
        job["error"]
            .as_str()
            .map(|e| format!(" ({e})"))
            .unwrap_or_default()
    )];
    if let Some(items) = job["items"].as_array().filter(|i| !i.is_empty()) {
        let mut table = new_table(vec!["NAME", "VERSION", "STATE", "REASON"]);
        for item in items {
            table.add_row(vec![
                text(&item["name"]),
                text(&item["version"]),
                text(&item["state"]),
                text(&item["reason"]),
            ]);
        }
        out.push(table.to_string());
    }
    out.join("\n")
}

/// A finished job failed, or left versions unpinned: say so in the exit code.
fn seed_outcome(job: &Value) -> Result<()> {
    if job["status"].as_str() != Some("completed") {
        return Err(reported_failure(&format!(
            "Seed job {} ended {}: {}",
            text(&job["jobId"]),
            text(&job["status"]),
            job["error"].as_str().unwrap_or("no reason given")
        )));
    }
    let missed: Vec<String> = job["items"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter(|i| !matches!(i["state"].as_str(), Some("pinned" | "already_pinned")))
                .map(|i| format!("{}@{}", text(&i["name"]), text(&i["version"])))
                .collect()
        })
        .unwrap_or_default();
    if missed.is_empty() {
        Ok(())
    } else {
        Err(reported_failure(&format!(
            "{} version(s) weren't pinned: {}",
            missed.len(),
            missed.join(", ")
        )))
    }
}

fn print_seed(job: &Value, raw: Option<&[u8]>, global: &GlobalArgs) {
    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", text(&job["status"]));
        return;
    }
    println!(
        "{}",
        output::render_raw(raw, job, &global.format, Some(seed_table(job)))
    );
}

async fn start_seed(
    repo: &str,
    servers: &[String],
    reason: Option<String>,
    (yes, wait): (bool, Option<u64>),
    global: &GlobalArgs,
) -> Result<()> {
    let servers = servers
        .iter()
        .map(|s| parse_server_version(s))
        .collect::<Result<Vec<_>>>()?;
    if !confirm_action(
        &format!(
            "Approve and pin {} server version(s) in '{repo}'? They're ingested, and served to \
             every reader of the registry.",
            servers.len()
        ),
        yes,
        global.no_input,
    )? {
        return Ok(());
    }
    let client = client_for(global)?;
    let spinner = output::spinner("Starting a seed job...");
    let (resp, raw) = capture(
        client
            .mcp_remote_start_seed()
            .key(repo)
            .body(SeedRequest { reason, servers })
            .send(),
    )
    .await;
    let accepted = or_since(V1_12, resp, "start a seed job", "mcp seed start", global)
        .await?
        .into_inner();
    spinner.finish_and_clear();
    let job_id = accepted.job_id.to_string();
    let Some(timeout) = wait else {
        emit_mutation_raw(
            raw.as_deref(),
            &accepted,
            &job_id,
            &format!(
                "Seed job {job_id} started for {} version(s). Follow it: ak mcp seed status \
                 --repo {repo} {job_id} --wait",
                accepted.total
            ),
            global,
        );
        return Ok(());
    };
    follow_seed(repo, accepted.job_id, timeout, global).await
}

async fn seed_status(
    repo: &str,
    job_id: &str,
    wait: Option<u64>,
    global: &GlobalArgs,
) -> Result<()> {
    let id = parse_uuid(job_id, "seed job")?;
    if let Some(timeout) = wait {
        return follow_seed(repo, id, timeout, global).await;
    }
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching the seed job...");
    let (resp, raw) = capture(client.mcp_remote_get_seed().key(repo).job_id(id).send()).await;
    let job = or_since(V1_12, resp, "read the seed job", "mcp seed status", global)
        .await?
        .into_inner();
    spinner.finish_and_clear();
    let value = serde_json::to_value(&job).unwrap_or_default();
    let value = raw
        .as_deref()
        .and_then(|b| serde_json::from_slice(b).ok())
        .unwrap_or(value);
    print_seed(&value, raw.as_deref(), global);
    Ok(())
}

async fn follow_seed(
    repo: &str,
    job_id: uuid::Uuid,
    timeout: u64,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let bytes = poll_job(
        "Seeding...",
        &format!("seed job {job_id} of '{repo}'"),
        &format!("ak mcp seed status --repo {repo} {job_id}"),
        timeout,
        || async {
            let (resp, raw) =
                capture(client.mcp_remote_get_seed().key(repo).job_id(job_id).send()).await;
            // The job is read from the body as sent, so a 2xx body the SDK's type
            // doesn't fit still counts.
            let bytes = match resp {
                Ok(_) => raw,
                Err(e) if e.status().is_some_and(|s| s.is_success()) => raw,
                Err(e) if e.status().is_some_and(|s| s.is_client_error()) => {
                    return Err(
                        since(V1_12, e, "read the seed job", "mcp seed status", global)
                            .await
                            .into(),
                    );
                }
                Err(_) => None,
            };
            let Some(bytes) = bytes else {
                return Ok(Polled::Unreadable);
            };
            let job: Value = serde_json::from_slice(&bytes).unwrap_or_default();
            // A status ak doesn't know ends the wait, and the outcome judges it.
            match job["status"].as_str() {
                Some("pending" | "running") => Ok(Polled::Running),
                Some(_) => Ok(Polled::Done(bytes)),
                None => Ok(Polled::Unreadable),
            }
        },
    )
    .await?;
    let job: Value = serde_json::from_slice(&bytes).unwrap_or_default();
    print_seed(&job, Some(&bytes), global);
    seed_outcome(&job)
}

// ---- health and the queue ----

fn health_detail(h: &Map<String, Value>) -> String {
    let get = |k: &str| h.get(k).cloned().unwrap_or_default();
    let lint = get("lint");
    let mut out = vec![
        format!(
            "Server:         {}@{}",
            text(&get("name")),
            text(&get("version"))
        ),
        format!("Status:         {}", text(&get("status"))),
        format!("Artifact:       {}", text(&get("artifactId"))),
        format!("Package policy: {}", text(&get("packagePolicy"))),
        if lint["ran"].as_bool() == Some(true) {
            format!(
                "Lint:           {} block, {} review, {} warn",
                lint["block"].as_i64().unwrap_or(0),
                lint["review"].as_i64().unwrap_or(0),
                lint["warn"].as_i64().unwrap_or(0)
            )
        } else {
            "Lint:           never ran".to_string()
        },
    ];
    if let Some(packages) = get("packages").as_array().filter(|p| !p.is_empty()) {
        let mut table = new_table(vec![
            "PACKAGE",
            "REPOSITORY",
            "GATE",
            "GRADE",
            "CRIT",
            "HIGH",
            "MED",
            "LOW",
            "STATUS",
        ]);
        for p in packages {
            table.add_row(vec![
                text(&p["package"]),
                text(&p["repository"]),
                text(&p["gate"]),
                text(&p["grade"]),
                text(&p["critical"]),
                text(&p["high"]),
                text(&p["medium"]),
                text(&p["low"]),
                text(&p["status"]),
            ]);
        }
        out.push(String::new());
        out.push(table.to_string());
    }
    if let Some(findings) = lint["findings"].as_array().filter(|f| !f.is_empty()) {
        let mut table = new_table(vec!["RULE", "ACTION", "SEVERITY", "PATH", "ACK"]);
        for f in findings {
            table.add_row(vec![
                text(&f["rule"]),
                text(&f["action"]),
                text(&f["severity"]),
                text(&f["path"]),
                if f["acknowledged"].as_bool() == Some(true) {
                    "yes"
                } else {
                    "no"
                }
                .to_string(),
            ]);
        }
        out.push(String::new());
        out.push(table.to_string());
    }
    out.join("\n")
}

async fn health(
    repo: &str,
    server: &str,
    version: &str,
    include_deleted: bool,
    global: &GlobalArgs,
) -> Result<()> {
    check_path_parts(server, Some(version))?;
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching server health...");
    let (resp, raw) = match split_name(server) {
        Some((ns, name)) => {
            let mut req = client
                .mcp_server_health_split()
                .key(repo)
                .ns(ns)
                .name(name)
                .version(version);
            if include_deleted {
                req = req.include_deleted(true);
            }
            capture(req.send()).await
        }
        None => {
            let mut req = client
                .mcp_server_health()
                .key(repo)
                .name(server)
                .version(version);
            if include_deleted {
                req = req.include_deleted(true);
            }
            capture(req.send()).await
        }
    };
    let health = or_since(V1_12, resp, "read server health", "mcp health", global)
        .await?
        .into_inner();
    spinner.finish_and_clear();
    if matches!(global.format, OutputFormat::Quiet) {
        println!(
            "{}",
            text(&health.get("status").cloned().unwrap_or_default())
        );
        return Ok(());
    }
    println!(
        "{}",
        output::render_raw(
            raw.as_deref(),
            &health,
            &global.format,
            Some(health_detail(&health))
        )
    );
    Ok(())
}

async fn pending(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Counting the approval queue...");
    let (resp, raw) = capture(client.mcp_pending_summary().send()).await;
    let summary = or_since(
        V1_12,
        resp,
        "count the approval queue",
        "mcp pending",
        global,
    )
    .await?
    .into_inner();
    spinner.finish_and_clear();
    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", summary.total);
        return Ok(());
    }
    let mut out = vec![format!(
        "{} waiting: {} pending, {} for review, {} drifted",
        summary.total, summary.pending, summary.review, summary.drifted
    )];
    if !summary.repositories.is_empty() {
        let mut table = new_table(vec!["REPOSITORY", "PENDING", "REVIEW", "DRIFTED"]);
        for r in &summary.repositories {
            table.add_row(vec![
                r.key.clone(),
                r.pending.to_string(),
                r.review.to_string(),
                r.drifted.to_string(),
            ]);
        }
        out.push(table.to_string());
    }
    println!(
        "{}",
        output::render_raw(
            raw.as_deref(),
            &summary,
            &global.format,
            Some(out.join("\n"))
        )
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_with_one_slash_goes_split() {
        assert_eq!(
            split_name("io.github.acme/weather"),
            Some(("io.github.acme", "weather"))
        );
        assert_eq!(split_name("weather"), None);
        assert_eq!(split_name("a/b/c"), None);
        assert_eq!(split_name("/weather"), None);
        assert_eq!(split_name("acme/"), None);
    }

    #[test]
    fn a_seed_entry_splits_at_the_last_at() {
        let s = parse_server_version("io.github.acme/weather@1.2.0").unwrap();
        assert_eq!(
            (s.name.as_str(), s.version.as_str()),
            ("io.github.acme/weather", "1.2.0")
        );
        let s = parse_server_version("@scope/x@2.0.0").unwrap();
        assert_eq!((s.name.as_str(), s.version.as_str()), ("@scope/x", "2.0.0"));
        assert!(parse_server_version("io.github.acme/weather").is_err());
        assert!(parse_server_version("io.github.acme/weather@").is_err());
    }

    #[test]
    fn a_seed_job_with_a_refused_version_fails() {
        let job = serde_json::json!({"jobId": "j", "status": "completed", "items": [
            {"name": "a/b", "version": "1", "state": "pinned"},
            {"name": "a/c", "version": "1", "state": "already_pinned"},
        ]});
        assert!(seed_outcome(&job).is_ok());
        let job = serde_json::json!({"jobId": "j", "status": "completed", "items": [
            {"name": "a/b", "version": "1", "state": "refused", "reason": "denied"},
        ]});
        assert!(format!("{:?}", seed_outcome(&job).unwrap_err()).contains("a/b@1"));
        let job = serde_json::json!({"jobId": "j", "status": "failed", "error": "x", "items": []});
        assert!(seed_outcome(&job).is_err());
    }

    #[test]
    fn a_sync_wait_ends_only_when_the_pass_is_recorded() {
        let t0 = std::time::Instant::now();
        let old = serde_json::json!({"running": false, "lastFinishedAt": "2026-01-01T00:00:00Z"});
        let new = serde_json::json!({"running": false, "lastFinishedAt": "2026-01-01T00:05:00Z"});
        let running =
            serde_json::json!({"running": true, "lastFinishedAt": "2026-01-01T00:00:00Z"});

        // Started here: the lock is free before the failure is recorded.
        let mut watch = SyncWatch {
            before: Some(old["lastFinishedAt"].clone()),
            ..SyncWatch::default()
        };
        assert!(!sync_step(&mut watch, &old, t0));
        assert!(!sync_step(
            &mut watch,
            &old,
            t0 + std::time::Duration::from_secs(5)
        ));
        assert!(sync_step(
            &mut watch,
            &new,
            t0 + std::time::Duration::from_secs(6)
        ));
        assert!(!watch.stale);

        // Nothing recorded within the grace: done, but stale.
        let mut watch = SyncWatch {
            before: Some(old["lastFinishedAt"].clone()),
            ..SyncWatch::default()
        };
        assert!(!sync_step(&mut watch, &old, t0));
        assert!(sync_step(&mut watch, &old, t0 + SYNC_RECORD_GRACE));
        assert!(watch.stale);

        // `status --wait` on an idle repository ends at once.
        let mut watch = SyncWatch::default();
        assert!(sync_step(&mut watch, &old, t0));
        assert!(!watch.stale);

        // `status --wait` during a pass takes the state it saw running as the baseline.
        let mut watch = SyncWatch::default();
        assert!(!sync_step(&mut watch, &running, t0));
        assert!(!sync_step(&mut watch, &old, t0));
        assert!(sync_step(&mut watch, &new, t0));

        // A first pass: nothing finished before, and still nothing recorded.
        let mut watch = SyncWatch {
            before: Some(Value::Null),
            ..SyncWatch::default()
        };
        assert!(!sync_step(
            &mut watch,
            &serde_json::json!({"running": false}),
            t0
        ));
    }

    #[test]
    fn a_path_part_that_would_reach_another_route_is_refused() {
        assert!(check_path_parts("io.github.acme/weather", Some("1.2.0")).is_ok());
        assert!(check_path_parts("weather", Some("1.2.0")).is_ok());
        for server in ["../x", "com.acme/..", "./x", "com.acme/w%2Fx", "..", "."] {
            assert!(check_path_parts(server, None).is_err(), "{server}");
        }
        for version in ["", ".", "..", "1%2F0"] {
            assert!(
                check_path_parts("com.acme/w", Some(version)).is_err(),
                "{version}"
            );
        }
    }

    #[test]
    fn a_sync_that_recorded_an_error_fails() {
        let ok: Map<String, Value> =
            serde_json::from_value(serde_json::json!({"running": false, "lastError": null}))
                .unwrap();
        assert!(sync_outcome(&ok, "r").is_ok());
        let failed: Map<String, Value> =
            serde_json::from_value(serde_json::json!({"running": false, "lastError": "boom"}))
                .unwrap();
        assert!(sync_outcome(&failed, "r").is_err());
    }
}
