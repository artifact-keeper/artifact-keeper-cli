use artifact_keeper_sdk::types::{
    ChunkAvailabilityResponse, ChunkManifestResponse, DiscoverablePeerResponse, IdentityResponse,
    PeerInstanceResponse, PeerLabelResponse, PeerResponse, RunNowResponse, ScoredPeerResponse,
    SubscriptionResponse, SyncTaskResponse, TransferSessionResponse,
};
use artifact_keeper_sdk::{ClientPeerInstanceLabelsExt, ClientPeersExt};
use clap::Subcommand;
use miette::Result;
use serde_json::Value;

use super::client::client_for;
use super::helpers::{confirm_action, emit_mutation, new_table, parse_uuid, sdk_err, short_id};
use crate::cli::GlobalArgs;
use crate::output::{self, OutputFormat, format_bytes};

#[derive(Subcommand)]
pub enum PeerCommand {
    /// List peer instances
    List {
        /// Filter by status (active, inactive, syncing, unreachable)
        #[arg(long)]
        status: Option<String>,

        /// Filter by region
        #[arg(long)]
        region: Option<String>,
    },

    /// Show peer instance details
    Show {
        /// Peer ID
        id: String,
    },

    /// Register a new peer instance
    Register {
        /// Peer name
        name: String,

        /// Peer endpoint URL
        #[arg(long)]
        url: String,

        /// API key for authenticating with the peer
        #[arg(long)]
        api_key: String,

        /// Geographic region of the peer
        #[arg(long)]
        region: Option<String>,
    },

    /// Unregister a peer instance
    Unregister {
        /// Peer ID
        id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Test connectivity to a peer
    Test {
        /// Peer ID
        id: String,
    },

    /// Trigger sync for a peer instance
    Sync {
        /// Peer ID
        id: String,
    },

    /// List sync tasks for a peer
    Tasks {
        /// Peer ID
        id: String,

        /// Filter by task status
        #[arg(long)]
        status: Option<String>,
    },

    /// Announce this instance to a federation (self-registration)
    Announce {
        /// Announced peer name
        name: String,

        /// Announced endpoint URL
        #[arg(long)]
        url: String,

        /// API key presented to the federation
        #[arg(long)]
        api_key: String,

        /// Peer instance ID being announced
        #[arg(long)]
        peer_id: String,
    },

    /// Show this instance's federation identity
    Identity,

    /// Send a heartbeat for a peer instance
    Heartbeat {
        /// Peer ID
        id: String,

        /// Current cache usage in bytes
        #[arg(long)]
        cache_used_bytes: i64,

        /// Reported status
        #[arg(long)]
        status: Option<String>,
    },

    /// Update a peer's network transfer profile
    NetworkProfile {
        /// Peer ID
        id: String,

        /// Maximum bandwidth in bits per second
        #[arg(long)]
        max_bandwidth_bps: Option<i64>,

        /// Concurrent transfer limit
        #[arg(long)]
        concurrent_transfers_limit: Option<i32>,

        /// Sync window start (HH:MM)
        #[arg(long)]
        sync_window_start: Option<String>,

        /// Sync window end (HH:MM)
        #[arg(long)]
        sync_window_end: Option<String>,

        /// Sync window timezone
        #[arg(long)]
        sync_window_timezone: Option<String>,
    },

    /// Manage peer connections
    Connection {
        #[command(subcommand)]
        command: PeerConnectionCommand,
    },

    /// Manage repository subscriptions assigned to a peer
    Subscription {
        #[command(subcommand)]
        command: PeerSubscriptionCommand,
    },

    /// Inspect artifact chunk availability across peers
    Chunk {
        #[command(subcommand)]
        command: PeerChunkCommand,
    },

    /// Manage peer instance labels
    Label {
        #[command(subcommand)]
        command: PeerLabelCommand,
    },

    /// Manage peer-to-peer artifact transfer sessions
    Transfer {
        #[command(subcommand)]
        command: PeerTransferCommand,
    },
}

#[derive(Subcommand)]
pub enum PeerConnectionCommand {
    /// List connections for a peer
    List {
        /// Peer ID
        id: String,

        /// Filter by connection status
        #[arg(long)]
        status: Option<String>,
    },

    /// Discover reachable peers from a peer
    Discover {
        /// Peer ID
        id: String,
    },

    /// Mark a target peer unreachable from a source peer
    Unreachable {
        /// Source peer ID
        id: String,

        /// Target peer ID
        target_id: String,
    },
}

#[derive(Subcommand)]
pub enum PeerSubscriptionCommand {
    /// List repositories assigned to a peer
    List {
        /// Peer ID
        id: String,
    },

    /// Show a repository subscription for a peer
    Show {
        /// Peer ID
        id: String,

        /// Repository ID
        repo_id: String,
    },

    /// Assign a repository to a peer
    Assign {
        /// Peer ID
        id: String,

        /// Repository ID
        repo_id: String,

        /// Replication mode (e.g. pull, push)
        #[arg(long)]
        mode: Option<String>,

        /// Replication schedule (cron expression)
        #[arg(long)]
        schedule: Option<String>,

        /// Enable sync for this subscription
        #[arg(long)]
        sync_enabled: Option<bool>,
    },

    /// Unassign a repository from a peer
    Unassign {
        /// Peer ID
        id: String,

        /// Repository ID
        repo_id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Run a repository subscription sync immediately
    Run {
        /// Peer ID
        id: String,

        /// Repository ID
        repo_id: String,
    },
}

#[derive(Subcommand)]
pub enum PeerChunkCommand {
    /// Show chunk availability for an artifact on a peer
    Show {
        /// Peer ID
        id: String,

        /// Artifact ID
        artifact_id: String,
    },

    /// Update chunk availability for an artifact on a peer
    Update {
        /// Peer ID
        id: String,

        /// Artifact ID
        artifact_id: String,

        /// Total number of chunks
        #[arg(long)]
        total_chunks: i32,

        /// Available chunk indexes (comma-separated)
        #[arg(long)]
        bitmap: String,
    },

    /// List peers that hold chunks of an artifact
    Peers {
        /// Peer ID
        id: String,

        /// Artifact ID
        artifact_id: String,
    },

    /// List peers scored for fetching an artifact's chunks
    ScoredPeers {
        /// Peer ID
        id: String,

        /// Artifact ID
        artifact_id: String,
    },
}

#[derive(Subcommand)]
pub enum PeerLabelCommand {
    /// List labels on a peer
    List {
        /// Peer ID
        id: String,
    },

    /// Replace all labels on a peer
    Set {
        /// Peer ID
        id: String,

        /// Label in key=value form (repeatable)
        #[arg(long = "label", value_name = "KEY=VALUE")]
        labels: Vec<String>,
    },

    /// Add or update a single label on a peer
    Add {
        /// Peer ID
        id: String,

        /// Label key
        key: String,

        /// Label value
        #[arg(long)]
        value: Option<String>,
    },

    /// Delete a label from a peer
    Delete {
        /// Peer ID
        id: String,

        /// Label key
        key: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
pub enum PeerTransferCommand {
    /// Initialize a transfer session for an artifact
    Init {
        /// Peer ID
        id: String,

        /// Artifact ID to transfer
        #[arg(long)]
        artifact_id: String,

        /// Chunk size in bytes
        #[arg(long)]
        chunk_size: Option<i32>,
    },

    /// Show a transfer session
    Show {
        /// Peer ID
        id: String,

        /// Transfer session ID
        session_id: String,
    },

    /// Show the chunk manifest for a transfer session
    Manifest {
        /// Peer ID
        id: String,

        /// Transfer session ID
        session_id: String,
    },

    /// Mark a transfer session complete
    Complete {
        /// Peer ID
        id: String,

        /// Transfer session ID
        session_id: String,
    },

    /// Mark a transfer session failed
    Fail {
        /// Peer ID
        id: String,

        /// Transfer session ID
        session_id: String,

        /// Failure reason
        #[arg(long)]
        error: String,
    },

    /// Mark a chunk complete within a session
    ChunkComplete {
        /// Peer ID
        id: String,

        /// Transfer session ID
        session_id: String,

        /// Chunk index
        chunk_index: i32,

        /// Chunk checksum
        #[arg(long)]
        checksum: String,

        /// Source peer ID the chunk was fetched from
        #[arg(long)]
        source_peer_id: Option<String>,
    },

    /// Mark a chunk failed within a session
    ChunkFail {
        /// Peer ID
        id: String,

        /// Transfer session ID
        session_id: String,

        /// Chunk index
        chunk_index: i32,

        /// Failure reason
        #[arg(long)]
        error: String,
    },

    /// Retry a failed chunk within a session
    ChunkRetry {
        /// Peer ID
        id: String,

        /// Transfer session ID
        session_id: String,

        /// Chunk index
        chunk_index: i32,
    },
}

impl PeerCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List { status, region } => {
                list_peers(status.as_deref(), region.as_deref(), global).await
            }
            Self::Show { id } => show_peer(&id, global).await,
            Self::Register {
                name,
                url,
                api_key,
                region,
            } => register_peer(&name, &url, &api_key, region.as_deref(), global).await,
            Self::Unregister { id, yes } => unregister_peer(&id, yes, global).await,
            Self::Test { id } => test_peer(&id, global).await,
            Self::Sync { id } => sync_peer(&id, global).await,
            Self::Tasks { id, status } => list_tasks(&id, status.as_deref(), global).await,
            Self::Announce {
                name,
                url,
                api_key,
                peer_id,
            } => announce_instance(&name, &url, &api_key, &peer_id, global).await,
            Self::Identity => show_identity(global).await,
            Self::Heartbeat {
                id,
                cache_used_bytes,
                status,
            } => send_heartbeat(&id, cache_used_bytes, status.as_deref(), global).await,
            Self::NetworkProfile {
                id,
                max_bandwidth_bps,
                concurrent_transfers_limit,
                sync_window_start,
                sync_window_end,
                sync_window_timezone,
            } => {
                update_network_profile(
                    &id,
                    max_bandwidth_bps,
                    concurrent_transfers_limit,
                    sync_window_start.as_deref(),
                    sync_window_end.as_deref(),
                    sync_window_timezone.as_deref(),
                    global,
                )
                .await
            }
            Self::Connection { command } => command.execute(global).await,
            Self::Subscription { command } => command.execute(global).await,
            Self::Chunk { command } => command.execute(global).await,
            Self::Label { command } => command.execute(global).await,
            Self::Transfer { command } => command.execute(global).await,
        }
    }
}

impl PeerConnectionCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List { id, status } => list_connections(&id, status.as_deref(), global).await,
            Self::Discover { id } => discover_peers(&id, global).await,
            Self::Unreachable { id, target_id } => mark_unreachable(&id, &target_id, global).await,
        }
    }
}

impl PeerSubscriptionCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List { id } => list_subscriptions(&id, global).await,
            Self::Show { id, repo_id } => show_subscription(&id, &repo_id, global).await,
            Self::Assign {
                id,
                repo_id,
                mode,
                schedule,
                sync_enabled,
            } => {
                assign_repo(
                    &id,
                    &repo_id,
                    mode.as_deref(),
                    schedule.as_deref(),
                    sync_enabled,
                    global,
                )
                .await
            }
            Self::Unassign { id, repo_id, yes } => unassign_repo(&id, &repo_id, yes, global).await,
            Self::Run { id, repo_id } => run_subscription(&id, &repo_id, global).await,
        }
    }
}

impl PeerChunkCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Show { id, artifact_id } => {
                show_chunk_availability(&id, &artifact_id, global).await
            }
            Self::Update {
                id,
                artifact_id,
                total_chunks,
                bitmap,
            } => update_chunk_availability(&id, &artifact_id, total_chunks, &bitmap, global).await,
            Self::Peers { id, artifact_id } => {
                list_peers_with_chunks(&id, &artifact_id, global).await
            }
            Self::ScoredPeers { id, artifact_id } => {
                list_scored_peers(&id, &artifact_id, global).await
            }
        }
    }
}

impl PeerLabelCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List { id } => list_labels(&id, global).await,
            Self::Set { id, labels } => set_labels(&id, &labels, global).await,
            Self::Add { id, key, value } => add_label(&id, &key, value.as_deref(), global).await,
            Self::Delete { id, key, yes } => delete_label(&id, &key, yes, global).await,
        }
    }
}

impl PeerTransferCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Init {
                id,
                artifact_id,
                chunk_size,
            } => init_transfer(&id, &artifact_id, chunk_size, global).await,
            Self::Show { id, session_id } => show_session(&id, &session_id, global).await,
            Self::Manifest { id, session_id } => show_manifest(&id, &session_id, global).await,
            Self::Complete { id, session_id } => complete_session(&id, &session_id, global).await,
            Self::Fail {
                id,
                session_id,
                error,
            } => fail_session(&id, &session_id, &error, global).await,
            Self::ChunkComplete {
                id,
                session_id,
                chunk_index,
                checksum,
                source_peer_id,
            } => {
                complete_chunk(
                    &id,
                    &session_id,
                    chunk_index,
                    &checksum,
                    source_peer_id.as_deref(),
                    global,
                )
                .await
            }
            Self::ChunkFail {
                id,
                session_id,
                chunk_index,
                error,
            } => fail_chunk(&id, &session_id, chunk_index, &error, global).await,
            Self::ChunkRetry {
                id,
                session_id,
                chunk_index,
            } => retry_chunk(&id, &session_id, chunk_index, global).await,
        }
    }
}

async fn list_peers(status: Option<&str>, region: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching peers...");

    let mut req = client.list_peers();
    if let Some(s) = status {
        req = req.status(s);
    }
    if let Some(r) = region {
        req = req.region(r);
    }

    let resp = req.send().await.map_err(|e| sdk_err("list peers", e))?;
    let list = resp.into_inner();
    spinner.finish_and_clear();

    if list.items.is_empty() {
        eprintln!("No peers found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for p in &list.items {
            println!("{}", p.id);
        }
        return Ok(());
    }

    let (entries, table_str) = format_peers_table(&list.items);
    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn show_peer(id: &str, global: &GlobalArgs) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching peer...");

    let peer = client
        .get_peer()
        .id(peer_id)
        .send()
        .await
        .map_err(|e| sdk_err("get peer", e))?;

    spinner.finish_and_clear();

    let (info, table_str) = format_peer_detail(&peer);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn register_peer(
    name: &str,
    url: &str,
    api_key: &str,
    region: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Registering peer...");

    let body = artifact_keeper_sdk::types::RegisterPeerRequest {
        name: name.to_string(),
        endpoint_url: url.to_string(),
        api_key: api_key.to_string(),
        region: region.map(|r| r.to_string()),
        sync_filter: serde_json::Map::new(),
        cache_size_bytes: None,
    };

    let peer = client
        .register_peer()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("register peer", e))?;

    spinner.finish_and_clear();

    emit_mutation(
        &*peer,
        &peer.id.to_string(),
        &format!("Peer '{}' registered (ID: {}).", peer.name, peer.id),
        global,
    );

    Ok(())
}

async fn unregister_peer(id: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;

    if !confirm_action(
        &format!("Unregister peer {id}?"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Unregistering peer...");

    client
        .unregister_peer()
        .id(peer_id)
        .send()
        .await
        .map_err(|e| sdk_err("unregister peer", e))?;

    spinner.finish_and_clear();
    emit_mutation(
        &serde_json::json!({ "id": id, "status": "unregistered" }),
        id,
        &format!("Peer {id} unregistered."),
        global,
    );

    Ok(())
}

async fn test_peer(id: &str, global: &GlobalArgs) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Testing peer connectivity...");

    let body = artifact_keeper_sdk::types::ProbeBody {
        target_peer_id: peer_id,
        latency_ms: 0,
        bandwidth_estimate_bps: None,
    };

    let probe = client
        .probe_peer()
        .id(peer_id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("test peer connectivity", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", probe.status);
        return Ok(());
    }

    let (info, table_str) = format_probe_result(&probe);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn sync_peer(id: &str, global: &GlobalArgs) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Triggering sync...");

    client
        .trigger_sync()
        .id(peer_id)
        .send()
        .await
        .map_err(|e| sdk_err("trigger sync", e))?;

    spinner.finish_and_clear();
    eprintln!("Sync triggered for peer {id}.");

    Ok(())
}

async fn list_tasks(id: &str, status: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching sync tasks...");

    let mut req = client.get_sync_tasks().id(peer_id);
    if let Some(s) = status {
        req = req.status(s);
    }

    let tasks = req
        .send()
        .await
        .map_err(|e| sdk_err("list sync tasks", e))?;

    let tasks = tasks.into_inner();
    spinner.finish_and_clear();

    if tasks.is_empty() {
        eprintln!("No sync tasks found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for t in &tasks {
            println!("{}", t.id);
        }
        return Ok(());
    }

    let (entries, table_str) = format_tasks_table(&tasks);
    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Instance identity / lifecycle
// ---------------------------------------------------------------------------

async fn announce_instance(
    name: &str,
    url: &str,
    api_key: &str,
    peer_id: &str,
    global: &GlobalArgs,
) -> Result<()> {
    let pid = parse_uuid(peer_id, "peer")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Announcing peer...");

    let body = artifact_keeper_sdk::types::AnnouncePeerRequest {
        api_key: api_key.to_string(),
        endpoint_url: url.to_string(),
        name: name.to_string(),
        peer_id: pid,
    };

    let resp = client
        .announce_peer()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("announce peer", e))?;

    spinner.finish_and_clear();

    let map = resp.into_inner();
    emit_mutation(
        &map,
        &pid.to_string(),
        &format!("Peer '{name}' announced ({pid})."),
        global,
    );

    Ok(())
}

async fn show_identity(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching identity...");

    let identity = client
        .get_identity()
        .send()
        .await
        .map_err(|e| sdk_err("get identity", e))?;

    spinner.finish_and_clear();

    let (info, table_str) = format_identity(&identity);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn send_heartbeat(
    id: &str,
    cache_used_bytes: i64,
    status: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Sending heartbeat...");

    let body = artifact_keeper_sdk::types::HeartbeatRequest {
        cache_used_bytes,
        status: status.map(|s| s.to_string()),
    };

    client
        .heartbeat()
        .id(peer_id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("send heartbeat", e))?;

    spinner.finish_and_clear();
    emit_mutation(
        &serde_json::json!({ "id": id, "status": "heartbeat_sent" }),
        id,
        &format!("Heartbeat sent for peer {id}."),
        global,
    );

    Ok(())
}

async fn update_network_profile(
    id: &str,
    max_bandwidth_bps: Option<i64>,
    concurrent_transfers_limit: Option<i32>,
    sync_window_start: Option<&str>,
    sync_window_end: Option<&str>,
    sync_window_timezone: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Updating network profile...");

    let body = artifact_keeper_sdk::types::NetworkProfileBody {
        concurrent_transfers_limit,
        max_bandwidth_bps,
        sync_window_end: sync_window_end.map(|s| s.to_string()),
        sync_window_start: sync_window_start.map(|s| s.to_string()),
        sync_window_timezone: sync_window_timezone.map(|s| s.to_string()),
    };

    client
        .update_network_profile()
        .id(peer_id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("update network profile", e))?;

    spinner.finish_and_clear();
    emit_mutation(
        &serde_json::json!({ "id": id, "status": "updated" }),
        id,
        &format!("Network profile updated for peer {id}."),
        global,
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Connections
// ---------------------------------------------------------------------------

async fn list_connections(id: &str, status: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching connections...");

    let mut req = client.list_peer_connections().id(peer_id);
    if let Some(s) = status {
        req = req.status(s);
    }

    let conns = req
        .send()
        .await
        .map_err(|e| sdk_err("list peer connections", e))?;
    let conns = conns.into_inner();
    spinner.finish_and_clear();

    if conns.is_empty() {
        eprintln!("No connections found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for c in &conns {
            println!("{}", c.id);
        }
        return Ok(());
    }

    let (entries, table_str) = format_connections_table(&conns);
    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn discover_peers(id: &str, global: &GlobalArgs) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Discovering peers...");

    let peers = client
        .discover_peers()
        .id(peer_id)
        .send()
        .await
        .map_err(|e| sdk_err("discover peers", e))?;
    let peers = peers.into_inner();
    spinner.finish_and_clear();

    if peers.is_empty() {
        eprintln!("No discoverable peers found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for p in &peers {
            println!("{}", p.peer_id);
        }
        return Ok(());
    }

    let (entries, table_str) = format_discoverable_table(&peers);
    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn mark_unreachable(id: &str, target_id: &str, global: &GlobalArgs) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;
    let target = parse_uuid(target_id, "target peer")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Marking peer unreachable...");

    client
        .mark_unreachable()
        .id(peer_id)
        .target_id(target)
        .send()
        .await
        .map_err(|e| sdk_err("mark peer unreachable", e))?;

    spinner.finish_and_clear();
    emit_mutation(
        &serde_json::json!({ "id": id, "target_id": target_id, "status": "unreachable" }),
        target_id,
        &format!("Peer {target_id} marked unreachable from {id}."),
        global,
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Repository subscriptions
// ---------------------------------------------------------------------------

async fn list_subscriptions(id: &str, global: &GlobalArgs) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching assigned repositories...");

    let repos = client
        .get_assigned_repos()
        .id(peer_id)
        .send()
        .await
        .map_err(|e| sdk_err("list assigned repositories", e))?;
    let repos = repos.into_inner();
    spinner.finish_and_clear();

    if repos.is_empty() {
        eprintln!("No repositories assigned.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for r in &repos {
            println!("{r}");
        }
        return Ok(());
    }

    let entries: Vec<Value> = repos
        .iter()
        .map(|r| serde_json::json!({ "repository_id": r.to_string() }))
        .collect();

    let table_str = {
        let mut table = new_table(vec!["REPOSITORY ID"]);
        for r in &repos {
            table.add_row(vec![r.to_string()]);
        }
        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn show_subscription(id: &str, repo_id: &str, global: &GlobalArgs) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;
    let repository_id = parse_uuid(repo_id, "repository")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching subscription...");

    let sub = client
        .get_subscription()
        .id(peer_id)
        .repo_id(repository_id)
        .send()
        .await
        .map_err(|e| sdk_err("get subscription", e))?;

    spinner.finish_and_clear();

    let (info, table_str) = format_subscription(&sub);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn assign_repo(
    id: &str,
    repo_id: &str,
    mode: Option<&str>,
    schedule: Option<&str>,
    sync_enabled: Option<bool>,
    global: &GlobalArgs,
) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;
    let repository_id = parse_uuid(repo_id, "repository")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Assigning repository...");

    let body = artifact_keeper_sdk::types::AssignRepoRequest {
        replication_filter: serde_json::Map::new(),
        replication_mode: mode.map(|s| s.to_string()),
        replication_schedule: schedule.map(|s| s.to_string()),
        repository_id,
        sync_enabled,
    };

    client
        .assign_repo()
        .id(peer_id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("assign repository", e))?;

    spinner.finish_and_clear();
    emit_mutation(
        &serde_json::json!({ "peer_id": id, "repository_id": repo_id, "status": "assigned" }),
        repo_id,
        &format!("Repository {repo_id} assigned to peer {id}."),
        global,
    );

    Ok(())
}

async fn unassign_repo(
    id: &str,
    repo_id: &str,
    skip_confirm: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;
    let repository_id = parse_uuid(repo_id, "repository")?;

    if !confirm_action(
        &format!("Unassign repository {repo_id} from peer {id}?"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Unassigning repository...");

    client
        .unassign_repo()
        .id(peer_id)
        .repo_id(repository_id)
        .send()
        .await
        .map_err(|e| sdk_err("unassign repository", e))?;

    spinner.finish_and_clear();
    emit_mutation(
        &serde_json::json!({ "peer_id": id, "repository_id": repo_id, "status": "unassigned" }),
        repo_id,
        &format!("Repository {repo_id} unassigned from peer {id}."),
        global,
    );

    Ok(())
}

async fn run_subscription(id: &str, repo_id: &str, global: &GlobalArgs) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;
    let repository_id = parse_uuid(repo_id, "repository")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Running subscription sync...");

    let result = client
        .run_subscription_now()
        .id(peer_id)
        .repo_id(repository_id)
        .send()
        .await
        .map_err(|e| sdk_err("run subscription", e))?;

    spinner.finish_and_clear();

    let result = result.into_inner();
    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", result.tasks_queued);
        return Ok(());
    }

    let (info, table_str) = format_run_now(&result);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

// ---------------------------------------------------------------------------
// Chunk availability
// ---------------------------------------------------------------------------

async fn show_chunk_availability(id: &str, artifact_id: &str, global: &GlobalArgs) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;
    let art_id = parse_uuid(artifact_id, "artifact")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching chunk availability...");

    let avail = client
        .get_chunk_availability()
        .id(peer_id)
        .artifact_id(art_id)
        .send()
        .await
        .map_err(|e| sdk_err("get chunk availability", e))?;

    spinner.finish_and_clear();

    let (info, table_str) = format_chunk_availability(&avail);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn update_chunk_availability(
    id: &str,
    artifact_id: &str,
    total_chunks: i32,
    bitmap: &str,
    global: &GlobalArgs,
) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;
    let art_id = parse_uuid(artifact_id, "artifact")?;
    let chunk_bitmap = parse_int_list(bitmap)?;

    let client = client_for(global)?;
    let spinner = output::spinner("Updating chunk availability...");

    let body = artifact_keeper_sdk::types::UpdateChunkAvailabilityBody {
        chunk_bitmap,
        total_chunks,
    };

    client
        .update_chunk_availability()
        .id(peer_id)
        .artifact_id(art_id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("update chunk availability", e))?;

    spinner.finish_and_clear();
    emit_mutation(
        &serde_json::json!({ "peer_id": id, "artifact_id": artifact_id, "status": "updated" }),
        artifact_id,
        &format!("Chunk availability updated for artifact {artifact_id}."),
        global,
    );

    Ok(())
}

async fn list_peers_with_chunks(id: &str, artifact_id: &str, global: &GlobalArgs) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;
    let art_id = parse_uuid(artifact_id, "artifact")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching peers with chunks...");

    let peers = client
        .get_peers_with_chunks()
        .id(peer_id)
        .artifact_id(art_id)
        .send()
        .await
        .map_err(|e| sdk_err("list peers with chunks", e))?;
    let peers = peers.into_inner();
    spinner.finish_and_clear();

    if peers.is_empty() {
        eprintln!("No peers hold chunks for this artifact.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for p in &peers {
            println!("{}", p.peer_instance_id);
        }
        return Ok(());
    }

    let (entries, table_str) = format_chunk_availability_table(&peers);
    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn list_scored_peers(id: &str, artifact_id: &str, global: &GlobalArgs) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;
    let art_id = parse_uuid(artifact_id, "artifact")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching scored peers...");

    let peers = client
        .get_scored_peers()
        .id(peer_id)
        .artifact_id(art_id)
        .send()
        .await
        .map_err(|e| sdk_err("list scored peers", e))?;
    let peers = peers.into_inner();
    spinner.finish_and_clear();

    if peers.is_empty() {
        eprintln!("No scored peers found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for p in &peers {
            println!("{}", p.peer_id);
        }
        return Ok(());
    }

    let (entries, table_str) = format_scored_peers_table(&peers);
    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Peer instance labels
// ---------------------------------------------------------------------------

async fn list_labels(id: &str, global: &GlobalArgs) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching labels...");

    let resp = client
        .list_labels()
        .id(peer_id)
        .send()
        .await
        .map_err(|e| sdk_err("list labels", e))?;
    let list = resp.into_inner();
    spinner.finish_and_clear();

    if list.items.is_empty() {
        eprintln!("No labels found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for l in &list.items {
            println!("{}", l.key);
        }
        return Ok(());
    }

    let (entries, table_str) = format_labels_table(&list.items);
    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn set_labels(id: &str, labels: &[String], global: &GlobalArgs) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;
    let entries = parse_label_entries(labels)?;

    let client = client_for(global)?;
    let spinner = output::spinner("Setting labels...");

    let body = artifact_keeper_sdk::types::SetPeerLabelsRequest { labels: entries };

    let resp = client
        .set_labels()
        .id(peer_id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("set labels", e))?;
    let list = resp.into_inner();
    spinner.finish_and_clear();

    emit_mutation(
        &list,
        id,
        &format!("Labels updated for peer {id} ({} total).", list.total),
        global,
    );

    Ok(())
}

async fn add_label(id: &str, key: &str, value: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Adding label...");

    let body = artifact_keeper_sdk::types::AddPeerLabelRequest {
        value: value.map(|s| s.to_string()),
    };

    let label = client
        .add_label()
        .id(peer_id)
        .label_key(key)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("add label", e))?;

    spinner.finish_and_clear();
    emit_mutation(
        &*label,
        &label.key,
        &format!("Label '{}' added to peer {id}.", label.key),
        global,
    );

    Ok(())
}

async fn delete_label(id: &str, key: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;

    if !confirm_action(
        &format!("Delete label '{key}' from peer {id}?"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Deleting label...");

    client
        .delete_label()
        .id(peer_id)
        .label_key(key)
        .send()
        .await
        .map_err(|e| sdk_err("delete label", e))?;

    spinner.finish_and_clear();
    emit_mutation(
        &serde_json::json!({ "id": id, "key": key, "status": "deleted" }),
        key,
        &format!("Label '{key}' deleted from peer {id}."),
        global,
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Peer-to-peer transfer sessions
// ---------------------------------------------------------------------------

async fn init_transfer(
    id: &str,
    artifact_id: &str,
    chunk_size: Option<i32>,
    global: &GlobalArgs,
) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;
    let art_id = parse_uuid(artifact_id, "artifact")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Initializing transfer...");

    let body = artifact_keeper_sdk::types::InitTransferBody {
        artifact_id: art_id,
        chunk_size,
    };

    let session = client
        .init_transfer()
        .id(peer_id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("initialize transfer", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", session.id);
        return Ok(());
    }

    let (info, table_str) = format_transfer_session(&session);
    if matches!(global.format, OutputFormat::Table) {
        eprintln!("Transfer session {} initialized.", session.id);
    }
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn show_session(id: &str, session_id: &str, global: &GlobalArgs) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;
    let sid = parse_uuid(session_id, "session")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching transfer session...");

    let session = client
        .get_session()
        .id(peer_id)
        .session_id(sid)
        .send()
        .await
        .map_err(|e| sdk_err("get transfer session", e))?;

    spinner.finish_and_clear();

    let (info, table_str) = format_transfer_session(&session);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn show_manifest(id: &str, session_id: &str, global: &GlobalArgs) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;
    let sid = parse_uuid(session_id, "session")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching chunk manifest...");

    let manifest = client
        .get_chunk_manifest()
        .id(peer_id)
        .session_id(sid)
        .send()
        .await
        .map_err(|e| sdk_err("get chunk manifest", e))?;

    spinner.finish_and_clear();

    let manifest = manifest.into_inner();
    let (entries, table_str) = format_manifest(&manifest);
    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn complete_session(id: &str, session_id: &str, global: &GlobalArgs) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;
    let sid = parse_uuid(session_id, "session")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Completing transfer session...");

    client
        .complete_session()
        .id(peer_id)
        .session_id(sid)
        .send()
        .await
        .map_err(|e| sdk_err("complete transfer session", e))?;

    spinner.finish_and_clear();
    emit_mutation(
        &serde_json::json!({ "session_id": session_id, "status": "completed" }),
        session_id,
        &format!("Transfer session {session_id} completed."),
        global,
    );

    Ok(())
}

async fn fail_session(id: &str, session_id: &str, error: &str, global: &GlobalArgs) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;
    let sid = parse_uuid(session_id, "session")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Failing transfer session...");

    let body = artifact_keeper_sdk::types::FailBody {
        error: error.to_string(),
    };

    client
        .fail_session()
        .id(peer_id)
        .session_id(sid)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("fail transfer session", e))?;

    spinner.finish_and_clear();
    emit_mutation(
        &serde_json::json!({ "session_id": session_id, "status": "failed" }),
        session_id,
        &format!("Transfer session {session_id} marked failed."),
        global,
    );

    Ok(())
}

async fn complete_chunk(
    id: &str,
    session_id: &str,
    chunk_index: i32,
    checksum: &str,
    source_peer_id: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;
    let sid = parse_uuid(session_id, "session")?;
    let source = match source_peer_id {
        Some(s) => Some(parse_uuid(s, "source peer")?),
        None => None,
    };

    let client = client_for(global)?;
    let spinner = output::spinner("Completing chunk...");

    let body = artifact_keeper_sdk::types::CompleteChunkBody {
        checksum: checksum.to_string(),
        source_peer_id: source,
    };

    client
        .complete_chunk()
        .id(peer_id)
        .session_id(sid)
        .chunk_index(chunk_index)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("complete chunk", e))?;

    spinner.finish_and_clear();
    emit_mutation(
        &serde_json::json!({ "session_id": session_id, "chunk_index": chunk_index, "status": "completed" }),
        session_id,
        &format!("Chunk {chunk_index} completed for session {session_id}."),
        global,
    );

    Ok(())
}

async fn fail_chunk(
    id: &str,
    session_id: &str,
    chunk_index: i32,
    error: &str,
    global: &GlobalArgs,
) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;
    let sid = parse_uuid(session_id, "session")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Failing chunk...");

    let body = artifact_keeper_sdk::types::FailBody {
        error: error.to_string(),
    };

    client
        .fail_chunk()
        .id(peer_id)
        .session_id(sid)
        .chunk_index(chunk_index)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("fail chunk", e))?;

    spinner.finish_and_clear();
    emit_mutation(
        &serde_json::json!({ "session_id": session_id, "chunk_index": chunk_index, "status": "failed" }),
        session_id,
        &format!("Chunk {chunk_index} marked failed for session {session_id}."),
        global,
    );

    Ok(())
}

async fn retry_chunk(
    id: &str,
    session_id: &str,
    chunk_index: i32,
    global: &GlobalArgs,
) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;
    let sid = parse_uuid(session_id, "session")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Retrying chunk...");

    client
        .retry_chunk()
        .id(peer_id)
        .session_id(sid)
        .chunk_index(chunk_index)
        .send()
        .await
        .map_err(|e| sdk_err("retry chunk", e))?;

    spinner.finish_and_clear();
    emit_mutation(
        &serde_json::json!({ "session_id": session_id, "chunk_index": chunk_index, "status": "retrying" }),
        session_id,
        &format!("Chunk {chunk_index} retry queued for session {session_id}."),
        global,
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Argument parsing helpers
// ---------------------------------------------------------------------------

fn parse_int_list(raw: &str) -> Result<Vec<i32>> {
    raw.split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<i32>().map_err(|_| {
                crate::error::AkError::ConfigError(format!("invalid integer in list: '{s}'")).into()
            })
        })
        .collect()
}

fn parse_label_entries(
    labels: &[String],
) -> Result<Vec<artifact_keeper_sdk::types::PeerLabelEntrySchema>> {
    labels
        .iter()
        .map(|pair| {
            let (key, value) = match pair.split_once('=') {
                Some((k, v)) => (k.trim().to_string(), Some(v.to_string())),
                None => (pair.trim().to_string(), None),
            };
            if key.is_empty() {
                return Err(crate::error::AkError::ConfigError(format!(
                    "invalid label (empty key): '{pair}'"
                ))
                .into());
            }
            Ok(artifact_keeper_sdk::types::PeerLabelEntrySchema { key, value })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Formatting helpers (pure functions, testable without HTTP)
// ---------------------------------------------------------------------------

fn format_peers_table(peers: &[PeerInstanceResponse]) -> (Vec<Value>, String) {
    let entries: Vec<_> = peers
        .iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id.to_string(),
                "name": p.name,
                "endpoint_url": p.endpoint_url,
                "status": p.status,
                "region": p.region.as_deref().unwrap_or("-"),
                "is_local": p.is_local,
                "cache_usage_percent": p.cache_usage_percent,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec![
            "ID", "NAME", "URL", "STATUS", "REGION", "LOCAL", "CACHE %",
        ]);

        for p in peers {
            let id_short = short_id(&p.id);
            let region = p.region.as_deref().unwrap_or("-");
            let is_local = if p.is_local { "yes" } else { "no" };
            let cache_pct = format!("{:.1}%", p.cache_usage_percent);
            table.add_row(vec![
                &id_short,
                &p.name,
                &p.endpoint_url,
                &p.status,
                region,
                is_local,
                &cache_pct,
            ]);
        }

        table.to_string()
    };

    (entries, table_str)
}

fn format_peer_detail(peer: &PeerInstanceResponse) -> (Value, String) {
    let info = serde_json::json!({
        "id": peer.id.to_string(),
        "name": peer.name,
        "endpoint_url": peer.endpoint_url,
        "status": peer.status,
        "region": peer.region.as_deref().unwrap_or("-"),
        "is_local": peer.is_local,
        "cache_size_bytes": peer.cache_size_bytes,
        "cache_used_bytes": peer.cache_used_bytes,
        "cache_usage_percent": peer.cache_usage_percent,
        "last_heartbeat_at": peer.last_heartbeat_at.map(|t| t.to_rfc3339()),
        "last_sync_at": peer.last_sync_at.map(|t| t.to_rfc3339()),
        "created_at": peer.created_at.to_rfc3339(),
    });

    let table_str = format!(
        "ID:             {}\n\
         Name:           {}\n\
         Endpoint:       {}\n\
         Status:         {}\n\
         Region:         {}\n\
         Local:          {}\n\
         Cache Size:     {}\n\
         Cache Used:     {}\n\
         Cache Usage:    {:.1}%\n\
         Last Heartbeat: {}\n\
         Last Sync:      {}\n\
         Created:        {}",
        peer.id,
        peer.name,
        peer.endpoint_url,
        peer.status,
        peer.region.as_deref().unwrap_or("-"),
        if peer.is_local { "yes" } else { "no" },
        format_bytes(peer.cache_size_bytes),
        format_bytes(peer.cache_used_bytes),
        peer.cache_usage_percent,
        peer.last_heartbeat_at
            .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "-".to_string()),
        peer.last_sync_at
            .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "-".to_string()),
        peer.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    (info, table_str)
}

fn format_probe_result(probe: &PeerResponse) -> (Value, String) {
    let info = serde_json::json!({
        "id": probe.id.to_string(),
        "target_peer_id": probe.target_peer_id.to_string(),
        "status": probe.status,
        "latency_ms": probe.latency_ms,
        "bandwidth_estimate_bps": probe.bandwidth_estimate_bps,
        "shared_artifacts_count": probe.shared_artifacts_count,
        "shared_chunks_count": probe.shared_chunks_count,
        "bytes_transferred_total": probe.bytes_transferred_total,
        "transfer_success_count": probe.transfer_success_count,
        "transfer_failure_count": probe.transfer_failure_count,
        "last_probed_at": probe.last_probed_at.map(|t| t.to_rfc3339()),
        "last_transfer_at": probe.last_transfer_at.map(|t| t.to_rfc3339()),
    });

    let table_str = format!(
        "ID:                  {}\n\
         Target Peer:         {}\n\
         Status:              {}\n\
         Latency:             {}\n\
         Bandwidth:           {}\n\
         Shared Artifacts:    {}\n\
         Shared Chunks:       {}\n\
         Bytes Transferred:   {}\n\
         Transfer Successes:  {}\n\
         Transfer Failures:   {}\n\
         Last Probed:         {}\n\
         Last Transfer:       {}",
        probe.id,
        probe.target_peer_id,
        probe.status,
        probe
            .latency_ms
            .map(|ms| format!("{ms} ms"))
            .unwrap_or_else(|| "-".to_string()),
        probe
            .bandwidth_estimate_bps
            .map(|bps| format!("{} bps", bps))
            .unwrap_or_else(|| "-".to_string()),
        probe.shared_artifacts_count,
        probe.shared_chunks_count,
        format_bytes(probe.bytes_transferred_total),
        probe.transfer_success_count,
        probe.transfer_failure_count,
        probe
            .last_probed_at
            .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "-".to_string()),
        probe
            .last_transfer_at
            .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "-".to_string()),
    );

    (info, table_str)
}

fn format_tasks_table(tasks: &[SyncTaskResponse]) -> (Vec<Value>, String) {
    let entries: Vec<_> = tasks
        .iter()
        .map(|t| {
            serde_json::json!({
                "id": t.id.to_string(),
                "artifact_id": t.artifact_id.to_string(),
                "artifact_size": t.artifact_size,
                "priority": t.priority,
                "storage_key": t.storage_key,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["ID", "ARTIFACT ID", "SIZE", "PRIORITY", "STORAGE KEY"]);

        for t in tasks {
            let id_short = short_id(&t.id);
            let artifact_short = short_id(&t.artifact_id);
            let size = format_bytes(t.artifact_size);
            let priority = t.priority.to_string();
            table.add_row(vec![
                &id_short,
                &artifact_short,
                &size,
                &priority,
                &t.storage_key,
            ]);
        }

        table.to_string()
    };

    (entries, table_str)
}

fn format_identity(identity: &IdentityResponse) -> (Value, String) {
    let info = serde_json::json!({
        "peer_id": identity.peer_id.to_string(),
        "name": identity.name,
        "endpoint_url": identity.endpoint_url,
    });

    let table_str = format!(
        "Peer ID:  {}\n\
         Name:     {}\n\
         Endpoint: {}",
        identity.peer_id, identity.name, identity.endpoint_url,
    );

    (info, table_str)
}

fn format_connections_table(conns: &[PeerResponse]) -> (Vec<Value>, String) {
    let entries: Vec<_> = conns
        .iter()
        .map(|c| {
            serde_json::json!({
                "id": c.id.to_string(),
                "target_peer_id": c.target_peer_id.to_string(),
                "status": c.status,
                "latency_ms": c.latency_ms,
                "transfer_success_count": c.transfer_success_count,
                "transfer_failure_count": c.transfer_failure_count,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["ID", "TARGET", "STATUS", "LATENCY", "OK", "FAIL"]);
        for c in conns {
            let id_short = short_id(&c.id);
            let target_short = short_id(&c.target_peer_id);
            let latency = c
                .latency_ms
                .map(|ms| format!("{ms} ms"))
                .unwrap_or_else(|| "-".to_string());
            let ok = c.transfer_success_count.to_string();
            let fail = c.transfer_failure_count.to_string();
            table.add_row(vec![
                &id_short,
                &target_short,
                &c.status,
                &latency,
                &ok,
                &fail,
            ]);
        }
        table.to_string()
    };

    (entries, table_str)
}

fn format_discoverable_table(peers: &[DiscoverablePeerResponse]) -> (Vec<Value>, String) {
    let entries: Vec<_> = peers
        .iter()
        .map(|p| {
            serde_json::json!({
                "peer_id": p.peer_id.to_string(),
                "name": p.name,
                "endpoint_url": p.endpoint_url,
                "status": p.status,
                "region": p.region.as_deref().unwrap_or("-"),
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["PEER ID", "NAME", "URL", "STATUS", "REGION"]);
        for p in peers {
            let id_short = short_id(&p.peer_id);
            let region = p.region.as_deref().unwrap_or("-");
            table.add_row(vec![&id_short, &p.name, &p.endpoint_url, &p.status, region]);
        }
        table.to_string()
    };

    (entries, table_str)
}

fn format_subscription(sub: &SubscriptionResponse) -> (Value, String) {
    let info = serde_json::json!({
        "id": sub.id.to_string(),
        "peer_instance_id": sub.peer_instance_id.to_string(),
        "repository_id": sub.repository_id.to_string(),
        "replication_mode": sub.replication_mode,
        "replication_schedule": sub.replication_schedule,
        "sync_enabled": sub.sync_enabled,
        "last_replicated_at": sub.last_replicated_at.map(|t| t.to_rfc3339()),
        "created_at": sub.created_at.to_rfc3339(),
    });

    let table_str = format!(
        "ID:              {}\n\
         Peer:            {}\n\
         Repository:      {}\n\
         Mode:            {}\n\
         Schedule:        {}\n\
         Sync Enabled:    {}\n\
         Last Replicated: {}\n\
         Created:         {}",
        sub.id,
        sub.peer_instance_id,
        sub.repository_id,
        sub.replication_mode.as_deref().unwrap_or("-"),
        sub.replication_schedule.as_deref().unwrap_or("-"),
        if sub.sync_enabled { "yes" } else { "no" },
        sub.last_replicated_at
            .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "-".to_string()),
        sub.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    (info, table_str)
}

fn format_run_now(result: &RunNowResponse) -> (Value, String) {
    let info = serde_json::json!({
        "status": result.status,
        "tasks_queued": result.tasks_queued,
    });

    let table_str = format!(
        "Status:       {}\n\
         Tasks Queued: {}",
        result.status, result.tasks_queued,
    );

    (info, table_str)
}

fn format_chunk_availability(avail: &ChunkAvailabilityResponse) -> (Value, String) {
    let info = serde_json::json!({
        "artifact_id": avail.artifact_id.to_string(),
        "peer_instance_id": avail.peer_instance_id.to_string(),
        "available_chunks": avail.available_chunks,
        "total_chunks": avail.total_chunks,
        "chunk_bitmap": avail.chunk_bitmap,
    });

    let table_str = format!(
        "Artifact:         {}\n\
         Peer:             {}\n\
         Available Chunks: {} / {}",
        avail.artifact_id, avail.peer_instance_id, avail.available_chunks, avail.total_chunks,
    );

    (info, table_str)
}

fn format_chunk_availability_table(peers: &[ChunkAvailabilityResponse]) -> (Vec<Value>, String) {
    let entries: Vec<_> = peers
        .iter()
        .map(|p| {
            serde_json::json!({
                "peer_instance_id": p.peer_instance_id.to_string(),
                "artifact_id": p.artifact_id.to_string(),
                "available_chunks": p.available_chunks,
                "total_chunks": p.total_chunks,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["PEER", "ARTIFACT", "AVAILABLE", "TOTAL"]);
        for p in peers {
            let peer_short = short_id(&p.peer_instance_id);
            let art_short = short_id(&p.artifact_id);
            let avail = p.available_chunks.to_string();
            let total = p.total_chunks.to_string();
            table.add_row(vec![&peer_short, &art_short, &avail, &total]);
        }
        table.to_string()
    };

    (entries, table_str)
}

fn format_scored_peers_table(peers: &[ScoredPeerResponse]) -> (Vec<Value>, String) {
    let entries: Vec<_> = peers
        .iter()
        .map(|p| {
            serde_json::json!({
                "peer_id": p.peer_id.to_string(),
                "endpoint_url": p.endpoint_url,
                "score": p.score,
                "available_chunks": p.available_chunks,
                "latency_ms": p.latency_ms,
                "bandwidth_estimate_bps": p.bandwidth_estimate_bps,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["PEER ID", "URL", "SCORE", "CHUNKS", "LATENCY"]);
        for p in peers {
            let id_short = short_id(&p.peer_id);
            let score = format!("{:.3}", p.score);
            let chunks = p.available_chunks.to_string();
            let latency = p
                .latency_ms
                .map(|ms| format!("{ms} ms"))
                .unwrap_or_else(|| "-".to_string());
            table.add_row(vec![&id_short, &p.endpoint_url, &score, &chunks, &latency]);
        }
        table.to_string()
    };

    (entries, table_str)
}

fn format_labels_table(labels: &[PeerLabelResponse]) -> (Vec<Value>, String) {
    let entries: Vec<_> = labels
        .iter()
        .map(|l| {
            serde_json::json!({
                "id": l.id.to_string(),
                "key": l.key,
                "value": l.value,
                "peer_instance_id": l.peer_instance_id.to_string(),
                "created_at": l.created_at.to_rfc3339(),
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["KEY", "VALUE", "CREATED"]);
        for l in labels {
            let created = l.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string();
            table.add_row(vec![&l.key, &l.value, &created]);
        }
        table.to_string()
    };

    (entries, table_str)
}

fn format_transfer_session(session: &TransferSessionResponse) -> (Value, String) {
    let info = serde_json::json!({
        "id": session.id.to_string(),
        "artifact_id": session.artifact_id.to_string(),
        "requesting_peer_id": session.requesting_peer_id.to_string(),
        "status": session.status,
        "artifact_checksum": session.artifact_checksum,
        "checksum_algo": session.checksum_algo,
        "chunk_size": session.chunk_size,
        "completed_chunks": session.completed_chunks,
        "total_chunks": session.total_chunks,
        "total_size": session.total_size,
    });

    let table_str = format!(
        "ID:               {}\n\
         Artifact:         {}\n\
         Requesting Peer:  {}\n\
         Status:           {}\n\
         Checksum:         {} ({})\n\
         Chunk Size:       {}\n\
         Progress:         {} / {} chunks\n\
         Total Size:       {}",
        session.id,
        session.artifact_id,
        session.requesting_peer_id,
        session.status,
        session.artifact_checksum,
        session.checksum_algo,
        format_bytes(session.chunk_size as i64),
        session.completed_chunks,
        session.total_chunks,
        format_bytes(session.total_size),
    );

    (info, table_str)
}

fn format_manifest(manifest: &ChunkManifestResponse) -> (Vec<Value>, String) {
    let entries: Vec<_> = manifest
        .chunks
        .iter()
        .map(|c| {
            serde_json::json!({
                "chunk_index": c.chunk_index,
                "byte_offset": c.byte_offset,
                "byte_length": c.byte_length,
                "checksum": c.checksum,
                "status": c.status,
                "source_peer_id": c.source_peer_id.map(|p| p.to_string()),
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["INDEX", "OFFSET", "LENGTH", "STATUS", "CHECKSUM"]);
        for c in &manifest.chunks {
            let idx = c.chunk_index.to_string();
            let offset = c.byte_offset.to_string();
            let length = c.byte_length.to_string();
            table.add_row(vec![&idx, &offset, &length, &c.status, &c.checksum]);
        }
        table.to_string()
    };

    (entries, table_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: PeerCommand,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).unwrap()
    }

    fn try_parse(args: &[&str]) -> std::result::Result<TestCli, clap::Error> {
        TestCli::try_parse_from(args)
    }

    // ---- Parsing tests ----

    #[test]
    fn parse_list_no_args() {
        let cli = parse(&["test", "list"]);
        if let PeerCommand::List { status, region } = cli.command {
            assert!(status.is_none());
            assert!(region.is_none());
        } else {
            panic!("Expected List");
        }
    }

    #[test]
    fn parse_list_with_status() {
        let cli = parse(&["test", "list", "--status", "active"]);
        if let PeerCommand::List { status, region } = cli.command {
            assert_eq!(status.unwrap(), "active");
            assert!(region.is_none());
        } else {
            panic!("Expected List with status");
        }
    }

    #[test]
    fn parse_list_with_region() {
        let cli = parse(&["test", "list", "--region", "us-east-1"]);
        if let PeerCommand::List { status, region } = cli.command {
            assert!(status.is_none());
            assert_eq!(region.unwrap(), "us-east-1");
        } else {
            panic!("Expected List with region");
        }
    }

    #[test]
    fn parse_list_with_both_filters() {
        let cli = parse(&[
            "test",
            "list",
            "--status",
            "active",
            "--region",
            "eu-west-1",
        ]);
        if let PeerCommand::List { status, region } = cli.command {
            assert_eq!(status.unwrap(), "active");
            assert_eq!(region.unwrap(), "eu-west-1");
        } else {
            panic!("Expected List with both filters");
        }
    }

    #[test]
    fn parse_show() {
        let cli = parse(&["test", "show", "peer-id-123"]);
        if let PeerCommand::Show { id } = cli.command {
            assert_eq!(id, "peer-id-123");
        } else {
            panic!("Expected Show");
        }
    }

    #[test]
    fn parse_show_missing_id() {
        let result = try_parse(&["test", "show"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_register_minimal() {
        let cli = parse(&[
            "test",
            "register",
            "my-peer",
            "--url",
            "https://peer.example.com",
            "--api-key",
            "secret-key",
        ]);
        if let PeerCommand::Register {
            name,
            url,
            api_key,
            region,
        } = cli.command
        {
            assert_eq!(name, "my-peer");
            assert_eq!(url, "https://peer.example.com");
            assert_eq!(api_key, "secret-key");
            assert!(region.is_none());
        } else {
            panic!("Expected Register");
        }
    }

    #[test]
    fn parse_register_with_region() {
        let cli = parse(&[
            "test",
            "register",
            "my-peer",
            "--url",
            "https://peer.example.com",
            "--api-key",
            "secret-key",
            "--region",
            "us-west-2",
        ]);
        if let PeerCommand::Register {
            name,
            url,
            api_key,
            region,
        } = cli.command
        {
            assert_eq!(name, "my-peer");
            assert_eq!(url, "https://peer.example.com");
            assert_eq!(api_key, "secret-key");
            assert_eq!(region.unwrap(), "us-west-2");
        } else {
            panic!("Expected Register with region");
        }
    }

    #[test]
    fn parse_register_missing_url() {
        let result = try_parse(&["test", "register", "my-peer", "--api-key", "key"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_register_missing_api_key() {
        let result = try_parse(&[
            "test",
            "register",
            "my-peer",
            "--url",
            "https://peer.example.com",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_register_missing_name() {
        let result = try_parse(&[
            "test",
            "register",
            "--url",
            "https://peer.example.com",
            "--api-key",
            "key",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_unregister() {
        let cli = parse(&["test", "unregister", "peer-id"]);
        if let PeerCommand::Unregister { id, yes } = cli.command {
            assert_eq!(id, "peer-id");
            assert!(!yes);
        } else {
            panic!("Expected Unregister");
        }
    }

    #[test]
    fn parse_unregister_with_yes() {
        let cli = parse(&["test", "unregister", "peer-id", "--yes"]);
        if let PeerCommand::Unregister { id, yes } = cli.command {
            assert_eq!(id, "peer-id");
            assert!(yes);
        } else {
            panic!("Expected Unregister with --yes");
        }
    }

    #[test]
    fn parse_unregister_missing_id() {
        let result = try_parse(&["test", "unregister"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_test() {
        let cli = parse(&["test", "test", "peer-id"]);
        if let PeerCommand::Test { id } = cli.command {
            assert_eq!(id, "peer-id");
        } else {
            panic!("Expected Test");
        }
    }

    #[test]
    fn parse_test_missing_id() {
        let result = try_parse(&["test", "test"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_sync() {
        let cli = parse(&["test", "sync", "peer-id"]);
        if let PeerCommand::Sync { id } = cli.command {
            assert_eq!(id, "peer-id");
        } else {
            panic!("Expected Sync");
        }
    }

    #[test]
    fn parse_sync_missing_id() {
        let result = try_parse(&["test", "sync"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_tasks() {
        let cli = parse(&["test", "tasks", "peer-id"]);
        if let PeerCommand::Tasks { id, status } = cli.command {
            assert_eq!(id, "peer-id");
            assert!(status.is_none());
        } else {
            panic!("Expected Tasks");
        }
    }

    #[test]
    fn parse_tasks_with_status() {
        let cli = parse(&["test", "tasks", "peer-id", "--status", "pending"]);
        if let PeerCommand::Tasks { id, status } = cli.command {
            assert_eq!(id, "peer-id");
            assert_eq!(status.unwrap(), "pending");
        } else {
            panic!("Expected Tasks with status");
        }
    }

    #[test]
    fn parse_tasks_missing_id() {
        let result = try_parse(&["test", "tasks"]);
        assert!(result.is_err());
    }

    // ---- Format function tests ----

    use chrono::Utc;
    use uuid::Uuid;

    fn make_test_peer(name: &str, status: &str, region: Option<&str>) -> PeerInstanceResponse {
        PeerInstanceResponse {
            id: Uuid::nil(),
            name: name.to_string(),
            endpoint_url: "https://peer.example.com".to_string(),
            status: status.to_string(),
            region: region.map(|r| r.to_string()),
            is_local: false,
            cache_size_bytes: 1024 * 1024 * 1024,
            cache_used_bytes: 512 * 1024 * 1024,
            cache_usage_percent: 50.0,
            last_heartbeat_at: Some(Utc::now()),
            last_sync_at: None,
            created_at: Utc::now(),
        }
    }

    fn make_test_probe() -> PeerResponse {
        PeerResponse {
            id: Uuid::nil(),
            target_peer_id: Uuid::nil(),
            status: "active".to_string(),
            latency_ms: Some(42),
            bandwidth_estimate_bps: Some(1_000_000),
            shared_artifacts_count: 10,
            shared_chunks_count: 50,
            bytes_transferred_total: 1024 * 1024 * 100,
            transfer_success_count: 95,
            transfer_failure_count: 5,
            last_probed_at: Some(Utc::now()),
            last_transfer_at: None,
        }
    }

    fn make_test_task(priority: i32, key: &str) -> SyncTaskResponse {
        SyncTaskResponse {
            id: Uuid::nil(),
            artifact_id: Uuid::nil(),
            artifact_size: 1024 * 1024,
            priority,
            storage_key: key.to_string(),
            status: "pending".to_string(),
            created_at: Utc::now(),
            started_at: None,
        }
    }

    // ---- format_peers_table ----

    #[test]
    fn format_peers_table_single() {
        let peers = vec![make_test_peer("us-east-peer", "active", Some("us-east-1"))];
        let (entries, table_str) = format_peers_table(&peers);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["name"], "us-east-peer");
        assert_eq!(entries[0]["status"], "active");
        assert_eq!(entries[0]["region"], "us-east-1");

        assert!(table_str.contains("NAME"));
        assert!(table_str.contains("STATUS"));
        assert!(table_str.contains("us-east-peer"));
        assert!(table_str.contains("active"));
    }

    #[test]
    fn format_peers_table_multiple() {
        let peers = vec![
            make_test_peer("peer-a", "active", Some("us-east-1")),
            make_test_peer("peer-b", "syncing", Some("eu-west-1")),
        ];
        let (entries, table_str) = format_peers_table(&peers);

        assert_eq!(entries.len(), 2);
        assert!(table_str.contains("peer-a"));
        assert!(table_str.contains("peer-b"));
        assert!(table_str.contains("active"));
        assert!(table_str.contains("syncing"));
    }

    #[test]
    fn format_peers_table_empty() {
        let (entries, table_str) = format_peers_table(&[]);
        assert!(entries.is_empty());
        assert!(table_str.contains("NAME"));
    }

    #[test]
    fn format_peers_table_no_region() {
        let peers = vec![make_test_peer("local-peer", "active", None)];
        let (entries, table_str) = format_peers_table(&peers);

        assert_eq!(entries[0]["region"], "-");
        assert!(table_str.contains("-"));
    }

    #[test]
    fn format_peers_table_local_peer() {
        let mut peer = make_test_peer("local", "active", None);
        peer.is_local = true;
        let (_, table_str) = format_peers_table(&[peer]);
        assert!(table_str.contains("yes"));
    }

    // ---- format_peer_detail ----

    #[test]
    fn format_peer_detail_full() {
        let peer = make_test_peer("detail-peer", "active", Some("ap-south-1"));
        let (info, table_str) = format_peer_detail(&peer);

        assert_eq!(info["name"], "detail-peer");
        assert_eq!(info["status"], "active");
        assert_eq!(info["region"], "ap-south-1");
        assert_eq!(info["is_local"], false);

        assert!(table_str.contains("detail-peer"));
        assert!(table_str.contains("active"));
        assert!(table_str.contains("ap-south-1"));
        assert!(table_str.contains("1.0 GB"));
        assert!(table_str.contains("512.0 MB"));
        assert!(table_str.contains("50.0%"));
    }

    #[test]
    fn format_peer_detail_no_region() {
        let peer = make_test_peer("bare-peer", "inactive", None);
        let (info, table_str) = format_peer_detail(&peer);

        assert_eq!(info["region"], "-");
        assert!(table_str.contains("Region:"));
    }

    #[test]
    fn format_peer_detail_no_sync() {
        let mut peer = make_test_peer("no-sync", "active", None);
        peer.last_sync_at = None;
        let (info, table_str) = format_peer_detail(&peer);

        assert!(info["last_sync_at"].is_null());
        assert!(table_str.contains("Last Sync:"));
    }

    #[test]
    fn format_peer_detail_local() {
        let mut peer = make_test_peer("local-peer", "active", None);
        peer.is_local = true;
        let (info, table_str) = format_peer_detail(&peer);

        assert_eq!(info["is_local"], true);
        assert!(table_str.contains("Local:"));
        assert!(table_str.contains("yes"));
    }

    // ---- format_probe_result ----

    #[test]
    fn format_probe_result_full() {
        let probe = make_test_probe();
        let (info, table_str) = format_probe_result(&probe);

        assert_eq!(info["status"], "active");
        assert_eq!(info["latency_ms"], 42);
        assert_eq!(info["shared_artifacts_count"], 10);
        assert_eq!(info["transfer_success_count"], 95);
        assert_eq!(info["transfer_failure_count"], 5);

        assert!(table_str.contains("active"));
        assert!(table_str.contains("42 ms"));
        assert!(table_str.contains("1000000 bps"));
        assert!(table_str.contains("100.0 MB"));
    }

    #[test]
    fn format_probe_result_no_latency() {
        let mut probe = make_test_probe();
        probe.latency_ms = None;
        probe.bandwidth_estimate_bps = None;
        probe.last_probed_at = None;
        probe.last_transfer_at = None;
        let (info, table_str) = format_probe_result(&probe);

        assert!(info["latency_ms"].is_null());
        assert!(info["bandwidth_estimate_bps"].is_null());
        assert!(table_str.contains("Latency:"));
        // Should show "-" for unknown values
        assert!(table_str.contains("-\n") || table_str.contains("- ") || table_str.contains("-"));
    }

    // ---- format_tasks_table ----

    #[test]
    fn format_tasks_table_single() {
        let tasks = vec![make_test_task(1, "artifacts/pkg-1.0.tar.gz")];
        let (entries, table_str) = format_tasks_table(&tasks);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["priority"], 1);
        assert_eq!(entries[0]["storage_key"], "artifacts/pkg-1.0.tar.gz");

        assert!(table_str.contains("PRIORITY"));
        assert!(table_str.contains("STORAGE KEY"));
        assert!(table_str.contains("artifacts/pkg-1.0.tar.gz"));
    }

    #[test]
    fn format_tasks_table_multiple() {
        let tasks = vec![
            make_test_task(1, "artifacts/a.tar.gz"),
            make_test_task(5, "artifacts/b.tar.gz"),
        ];
        let (entries, table_str) = format_tasks_table(&tasks);

        assert_eq!(entries.len(), 2);
        assert!(table_str.contains("artifacts/a.tar.gz"));
        assert!(table_str.contains("artifacts/b.tar.gz"));
    }

    #[test]
    fn format_tasks_table_empty() {
        let (entries, table_str) = format_tasks_table(&[]);
        assert!(entries.is_empty());
        assert!(table_str.contains("PRIORITY"));
    }

    #[test]
    fn format_tasks_table_size_formatting() {
        let tasks = vec![make_test_task(1, "key")];
        let (_, table_str) = format_tasks_table(&tasks);
        assert!(table_str.contains("1.0 MB"));
    }

    // ---- wiremock handler tests ----

    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    static NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

    fn peer_json() -> serde_json::Value {
        json!({
            "id": NIL_UUID,
            "name": "test-peer",
            "endpoint_url": "https://peer.example.com",
            "status": "active",
            "region": "us-east-1",
            "is_local": false,
            "cache_size_bytes": 1073741824,
            "cache_used_bytes": 536870912,
            "cache_usage_percent": 50.0,
            "last_heartbeat_at": "2026-01-15T12:00:00Z",
            "last_sync_at": null,
            "created_at": "2026-01-01T00:00:00Z"
        })
    }

    fn probe_json() -> serde_json::Value {
        json!({
            "id": NIL_UUID,
            "target_peer_id": NIL_UUID,
            "status": "active",
            "latency_ms": 42,
            "bandwidth_estimate_bps": 1000000,
            "shared_artifacts_count": 10,
            "shared_chunks_count": 50,
            "bytes_transferred_total": 104857600,
            "transfer_success_count": 95,
            "transfer_failure_count": 5,
            "last_probed_at": "2026-01-15T12:00:00Z",
            "last_transfer_at": null
        })
    }

    fn task_json() -> serde_json::Value {
        json!({
            "id": NIL_UUID,
            "artifact_id": NIL_UUID,
            "artifact_size": 1048576,
            "priority": 1,
            "storage_key": "artifacts/pkg-1.0.tar.gz",
            "status": "pending",
            "created_at": "2026-01-15T12:00:00Z",
            "started_at": null
        })
    }

    #[tokio::test]
    async fn handler_list_peers_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/peers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [],
                "total": 0
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_peers(None, None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_peers_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/peers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [peer_json()],
                "total": 1
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_peers(None, None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_peers_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/peers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [peer_json()],
                "total": 1
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = list_peers(None, None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_peer() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/peers/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(peer_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = show_peer(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_register_peer() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/peers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(peer_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = register_peer(
            "test-peer",
            "https://peer.example.com",
            "secret-key",
            Some("us-east-1"),
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_register_peer_no_region() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/peers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(peer_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = register_peer(
            "test-peer",
            "https://peer.example.com",
            "key",
            None,
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_unregister_peer() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/peers/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = unregister_peer(NIL_UUID, true, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_test_peer() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!("/api/v1/peers/{NIL_UUID}/connections/probe")))
            .respond_with(ResponseTemplate::new(200).set_body_json(probe_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = test_peer(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_test_peer_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!("/api/v1/peers/{NIL_UUID}/connections/probe")))
            .respond_with(ResponseTemplate::new(200).set_body_json(probe_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = test_peer(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_sync_peer() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!("/api/v1/peers/{NIL_UUID}/sync")))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = sync_peer(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_tasks_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/peers/{NIL_UUID}/sync/tasks")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_tasks(NIL_UUID, None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_tasks_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/peers/{NIL_UUID}/sync/tasks")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([task_json()])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_tasks(NIL_UUID, None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_tasks_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/peers/{NIL_UUID}/sync/tasks")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([task_json()])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = list_tasks(NIL_UUID, None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    // ---- insta snapshot tests ----

    #[test]
    fn snapshot_peer_list_json() {
        let data = json!([peer_json()]);
        let output = crate::output::render(&data, &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("peer_list_json", parsed);
    }

    // ---- Parsing tests: new subcommands ----

    #[test]
    fn parse_announce() {
        let cli = parse(&[
            "test",
            "announce",
            "peer-x",
            "--url",
            "https://x.example.com",
            "--api-key",
            "k",
            "--peer-id",
            NIL_UUID,
        ]);
        assert!(matches!(cli.command, PeerCommand::Announce { .. }));
    }

    #[test]
    fn parse_announce_missing_peer_id() {
        let result = try_parse(&["test", "announce", "peer-x", "--url", "u", "--api-key", "k"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_identity() {
        let cli = parse(&["test", "identity"]);
        assert!(matches!(cli.command, PeerCommand::Identity));
    }

    #[test]
    fn parse_heartbeat() {
        let cli = parse(&[
            "test",
            "heartbeat",
            "peer-id",
            "--cache-used-bytes",
            "1024",
            "--status",
            "active",
        ]);
        if let PeerCommand::Heartbeat {
            id,
            cache_used_bytes,
            status,
        } = cli.command
        {
            assert_eq!(id, "peer-id");
            assert_eq!(cache_used_bytes, 1024);
            assert_eq!(status.unwrap(), "active");
        } else {
            panic!("Expected Heartbeat");
        }
    }

    #[test]
    fn parse_heartbeat_missing_cache() {
        let result = try_parse(&["test", "heartbeat", "peer-id"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_network_profile() {
        let cli = parse(&[
            "test",
            "network-profile",
            "peer-id",
            "--max-bandwidth-bps",
            "5000",
            "--concurrent-transfers-limit",
            "3",
        ]);
        if let PeerCommand::NetworkProfile {
            id,
            max_bandwidth_bps,
            concurrent_transfers_limit,
            ..
        } = cli.command
        {
            assert_eq!(id, "peer-id");
            assert_eq!(max_bandwidth_bps.unwrap(), 5000);
            assert_eq!(concurrent_transfers_limit.unwrap(), 3);
        } else {
            panic!("Expected NetworkProfile");
        }
    }

    #[test]
    fn parse_connection_list() {
        let cli = parse(&[
            "test",
            "connection",
            "list",
            "peer-id",
            "--status",
            "active",
        ]);
        if let PeerCommand::Connection {
            command: PeerConnectionCommand::List { id, status },
        } = cli.command
        {
            assert_eq!(id, "peer-id");
            assert_eq!(status.unwrap(), "active");
        } else {
            panic!("Expected Connection::List");
        }
    }

    #[test]
    fn parse_connection_discover() {
        let cli = parse(&["test", "connection", "discover", "peer-id"]);
        assert!(matches!(
            cli.command,
            PeerCommand::Connection {
                command: PeerConnectionCommand::Discover { .. }
            }
        ));
    }

    #[test]
    fn parse_connection_unreachable() {
        let cli = parse(&["test", "connection", "unreachable", "peer-a", "peer-b"]);
        if let PeerCommand::Connection {
            command: PeerConnectionCommand::Unreachable { id, target_id },
        } = cli.command
        {
            assert_eq!(id, "peer-a");
            assert_eq!(target_id, "peer-b");
        } else {
            panic!("Expected Connection::Unreachable");
        }
    }

    #[test]
    fn parse_subscription_assign() {
        let cli = parse(&[
            "test",
            "subscription",
            "assign",
            "peer-id",
            "repo-id",
            "--mode",
            "pull",
            "--sync-enabled",
            "true",
        ]);
        if let PeerCommand::Subscription {
            command:
                PeerSubscriptionCommand::Assign {
                    id,
                    repo_id,
                    mode,
                    sync_enabled,
                    ..
                },
        } = cli.command
        {
            assert_eq!(id, "peer-id");
            assert_eq!(repo_id, "repo-id");
            assert_eq!(mode.unwrap(), "pull");
            assert_eq!(sync_enabled.unwrap(), true);
        } else {
            panic!("Expected Subscription::Assign");
        }
    }

    #[test]
    fn parse_subscription_unassign() {
        let cli = parse(&[
            "test",
            "subscription",
            "unassign",
            "peer-id",
            "repo-id",
            "--yes",
        ]);
        if let PeerCommand::Subscription {
            command: PeerSubscriptionCommand::Unassign { id, repo_id, yes },
        } = cli.command
        {
            assert_eq!(id, "peer-id");
            assert_eq!(repo_id, "repo-id");
            assert!(yes);
        } else {
            panic!("Expected Subscription::Unassign");
        }
    }

    #[test]
    fn parse_subscription_run_and_list_and_show() {
        assert!(matches!(
            parse(&["test", "subscription", "run", "p", "r"]).command,
            PeerCommand::Subscription {
                command: PeerSubscriptionCommand::Run { .. }
            }
        ));
        assert!(matches!(
            parse(&["test", "subscription", "list", "p"]).command,
            PeerCommand::Subscription {
                command: PeerSubscriptionCommand::List { .. }
            }
        ));
        assert!(matches!(
            parse(&["test", "subscription", "show", "p", "r"]).command,
            PeerCommand::Subscription {
                command: PeerSubscriptionCommand::Show { .. }
            }
        ));
    }

    #[test]
    fn parse_chunk_update() {
        let cli = parse(&[
            "test",
            "chunk",
            "update",
            "peer-id",
            "artifact-id",
            "--total-chunks",
            "4",
            "--bitmap",
            "0,1,2,3",
        ]);
        if let PeerCommand::Chunk {
            command:
                PeerChunkCommand::Update {
                    total_chunks,
                    bitmap,
                    ..
                },
        } = cli.command
        {
            assert_eq!(total_chunks, 4);
            assert_eq!(bitmap, "0,1,2,3");
        } else {
            panic!("Expected Chunk::Update");
        }
    }

    #[test]
    fn parse_chunk_show_peers_scored() {
        assert!(matches!(
            parse(&["test", "chunk", "show", "p", "a"]).command,
            PeerCommand::Chunk {
                command: PeerChunkCommand::Show { .. }
            }
        ));
        assert!(matches!(
            parse(&["test", "chunk", "peers", "p", "a"]).command,
            PeerCommand::Chunk {
                command: PeerChunkCommand::Peers { .. }
            }
        ));
        assert!(matches!(
            parse(&["test", "chunk", "scored-peers", "p", "a"]).command,
            PeerCommand::Chunk {
                command: PeerChunkCommand::ScoredPeers { .. }
            }
        ));
    }

    #[test]
    fn parse_label_set_multiple() {
        let cli = parse(&[
            "test",
            "label",
            "set",
            "peer-id",
            "--label",
            "env=prod",
            "--label",
            "tier=gold",
        ]);
        if let PeerCommand::Label {
            command: PeerLabelCommand::Set { id, labels },
        } = cli.command
        {
            assert_eq!(id, "peer-id");
            assert_eq!(labels, vec!["env=prod", "tier=gold"]);
        } else {
            panic!("Expected Label::Set");
        }
    }

    #[test]
    fn parse_label_add_and_delete_and_list() {
        assert!(matches!(
            parse(&["test", "label", "add", "p", "key", "--value", "v"]).command,
            PeerCommand::Label {
                command: PeerLabelCommand::Add { .. }
            }
        ));
        assert!(matches!(
            parse(&["test", "label", "delete", "p", "key", "--yes"]).command,
            PeerCommand::Label {
                command: PeerLabelCommand::Delete { .. }
            }
        ));
        assert!(matches!(
            parse(&["test", "label", "list", "p"]).command,
            PeerCommand::Label {
                command: PeerLabelCommand::List { .. }
            }
        ));
    }

    #[test]
    fn parse_transfer_init() {
        let cli = parse(&[
            "test",
            "transfer",
            "init",
            "peer-id",
            "--artifact-id",
            "art-id",
            "--chunk-size",
            "2048",
        ]);
        if let PeerCommand::Transfer {
            command:
                PeerTransferCommand::Init {
                    id,
                    artifact_id,
                    chunk_size,
                },
        } = cli.command
        {
            assert_eq!(id, "peer-id");
            assert_eq!(artifact_id, "art-id");
            assert_eq!(chunk_size.unwrap(), 2048);
        } else {
            panic!("Expected Transfer::Init");
        }
    }

    #[test]
    fn parse_transfer_chunk_complete() {
        let cli = parse(&[
            "test",
            "transfer",
            "chunk-complete",
            "peer-id",
            "session-id",
            "3",
            "--checksum",
            "abc",
            "--source-peer-id",
            NIL_UUID,
        ]);
        if let PeerCommand::Transfer {
            command:
                PeerTransferCommand::ChunkComplete {
                    chunk_index,
                    checksum,
                    source_peer_id,
                    ..
                },
        } = cli.command
        {
            assert_eq!(chunk_index, 3);
            assert_eq!(checksum, "abc");
            assert_eq!(source_peer_id.unwrap(), NIL_UUID);
        } else {
            panic!("Expected Transfer::ChunkComplete");
        }
    }

    #[test]
    fn parse_transfer_fail_and_retry_and_show() {
        assert!(matches!(
            parse(&["test", "transfer", "fail", "p", "s", "--error", "boom"]).command,
            PeerCommand::Transfer {
                command: PeerTransferCommand::Fail { .. }
            }
        ));
        assert!(matches!(
            parse(&["test", "transfer", "chunk-retry", "p", "s", "1"]).command,
            PeerCommand::Transfer {
                command: PeerTransferCommand::ChunkRetry { .. }
            }
        ));
        assert!(matches!(
            parse(&["test", "transfer", "show", "p", "s"]).command,
            PeerCommand::Transfer {
                command: PeerTransferCommand::Show { .. }
            }
        ));
        assert!(matches!(
            parse(&["test", "transfer", "manifest", "p", "s"]).command,
            PeerCommand::Transfer {
                command: PeerTransferCommand::Manifest { .. }
            }
        ));
        assert!(matches!(
            parse(&["test", "transfer", "complete", "p", "s"]).command,
            PeerCommand::Transfer {
                command: PeerTransferCommand::Complete { .. }
            }
        ));
        assert!(matches!(
            parse(&[
                "test",
                "transfer",
                "chunk-fail",
                "p",
                "s",
                "1",
                "--error",
                "x"
            ])
            .command,
            PeerCommand::Transfer {
                command: PeerTransferCommand::ChunkFail { .. }
            }
        ));
    }

    // ---- Argument parsing helper tests ----

    #[test]
    fn parse_int_list_ok() {
        assert_eq!(parse_int_list("0,1,2,3").unwrap(), vec![0, 1, 2, 3]);
        assert_eq!(parse_int_list(" 1 , 2 ").unwrap(), vec![1, 2]);
        assert!(parse_int_list("").unwrap().is_empty());
    }

    #[test]
    fn parse_int_list_invalid() {
        assert!(parse_int_list("1,x,3").is_err());
    }

    #[test]
    fn parse_label_entries_ok() {
        let entries = parse_label_entries(&["env=prod".to_string(), "flag".to_string()]).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "env");
        assert_eq!(entries[0].value.as_deref(), Some("prod"));
        assert_eq!(entries[1].key, "flag");
        assert!(entries[1].value.is_none());
    }

    #[test]
    fn parse_label_entries_empty_key() {
        assert!(parse_label_entries(&["=val".to_string()]).is_err());
    }

    // ---- Format function tests: new formatters ----

    fn make_identity() -> IdentityResponse {
        IdentityResponse {
            endpoint_url: "https://self.example.com".to_string(),
            name: "self-peer".to_string(),
            peer_id: Uuid::nil(),
        }
    }

    fn make_discoverable() -> DiscoverablePeerResponse {
        DiscoverablePeerResponse {
            endpoint_url: "https://d.example.com".to_string(),
            name: "disc-peer".to_string(),
            peer_id: Uuid::nil(),
            region: Some("eu-west-1".to_string()),
            status: "active".to_string(),
        }
    }

    fn make_subscription() -> SubscriptionResponse {
        SubscriptionResponse {
            created_at: Utc::now(),
            id: Uuid::nil(),
            last_replicated_at: None,
            peer_instance_id: Uuid::nil(),
            replication_filter: serde_json::Map::new(),
            replication_mode: Some("pull".to_string()),
            replication_schedule: None,
            repository_id: Uuid::nil(),
            sync_enabled: true,
        }
    }

    fn make_chunk_availability() -> ChunkAvailabilityResponse {
        ChunkAvailabilityResponse {
            artifact_id: Uuid::nil(),
            available_chunks: 3,
            chunk_bitmap: vec![0, 1, 2],
            peer_instance_id: Uuid::nil(),
            total_chunks: 4,
        }
    }

    fn make_scored_peer() -> ScoredPeerResponse {
        ScoredPeerResponse {
            available_chunks: 5,
            bandwidth_estimate_bps: Some(1_000_000),
            endpoint_url: "https://s.example.com".to_string(),
            latency_ms: Some(12),
            peer_id: Uuid::nil(),
            score: 0.875,
        }
    }

    fn make_label() -> PeerLabelResponse {
        PeerLabelResponse {
            created_at: Utc::now(),
            id: Uuid::nil(),
            key: "env".to_string(),
            peer_instance_id: Uuid::nil(),
            value: "prod".to_string(),
        }
    }

    fn make_session() -> TransferSessionResponse {
        TransferSessionResponse {
            artifact_checksum: "deadbeef".to_string(),
            artifact_id: Uuid::nil(),
            checksum_algo: "sha256".to_string(),
            chunk_size: 1024 * 1024,
            completed_chunks: 2,
            id: Uuid::nil(),
            requesting_peer_id: Uuid::nil(),
            status: "in_progress".to_string(),
            total_chunks: 8,
            total_size: 8 * 1024 * 1024,
        }
    }

    #[test]
    fn format_identity_ok() {
        let (info, table_str) = format_identity(&make_identity());
        assert_eq!(info["name"], "self-peer");
        assert!(table_str.contains("self-peer"));
        assert!(table_str.contains("Endpoint:"));
    }

    #[test]
    fn format_connections_table_ok() {
        let (entries, table_str) = format_connections_table(&[make_test_probe()]);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["status"], "active");
        assert!(table_str.contains("TARGET"));
        assert!(table_str.contains("42 ms"));
    }

    #[test]
    fn format_discoverable_table_ok() {
        let (entries, table_str) = format_discoverable_table(&[make_discoverable()]);
        assert_eq!(entries[0]["name"], "disc-peer");
        assert_eq!(entries[0]["region"], "eu-west-1");
        assert!(table_str.contains("disc-peer"));
    }

    #[test]
    fn format_subscription_ok() {
        let (info, table_str) = format_subscription(&make_subscription());
        assert_eq!(info["replication_mode"], "pull");
        assert_eq!(info["sync_enabled"], true);
        assert!(table_str.contains("pull"));
        assert!(table_str.contains("Sync Enabled:"));
    }

    #[test]
    fn format_run_now_ok() {
        let result = RunNowResponse {
            status: "queued".to_string(),
            tasks_queued: 7,
        };
        let (info, table_str) = format_run_now(&result);
        assert_eq!(info["tasks_queued"], 7);
        assert!(table_str.contains("queued"));
        assert!(table_str.contains("7"));
    }

    #[test]
    fn format_chunk_availability_ok() {
        let (info, table_str) = format_chunk_availability(&make_chunk_availability());
        assert_eq!(info["available_chunks"], 3);
        assert_eq!(info["total_chunks"], 4);
        assert!(table_str.contains("3 / 4"));
    }

    #[test]
    fn format_chunk_availability_table_ok() {
        let (entries, table_str) = format_chunk_availability_table(&[make_chunk_availability()]);
        assert_eq!(entries[0]["available_chunks"], 3);
        assert!(table_str.contains("AVAILABLE"));
    }

    #[test]
    fn format_scored_peers_table_ok() {
        let (entries, table_str) = format_scored_peers_table(&[make_scored_peer()]);
        assert_eq!(entries[0]["available_chunks"], 5);
        assert!(table_str.contains("0.875"));
        assert!(table_str.contains("12 ms"));
    }

    #[test]
    fn format_labels_table_ok() {
        let (entries, table_str) = format_labels_table(&[make_label()]);
        assert_eq!(entries[0]["key"], "env");
        assert_eq!(entries[0]["value"], "prod");
        assert!(table_str.contains("env"));
        assert!(table_str.contains("prod"));
    }

    #[test]
    fn format_transfer_session_ok() {
        let (info, table_str) = format_transfer_session(&make_session());
        assert_eq!(info["status"], "in_progress");
        assert_eq!(info["total_chunks"], 8);
        assert!(table_str.contains("in_progress"));
        assert!(table_str.contains("2 / 8 chunks"));
        assert!(table_str.contains("sha256"));
    }

    #[test]
    fn format_manifest_ok() {
        let manifest = ChunkManifestResponse {
            chunks: vec![artifact_keeper_sdk::types::ChunkEntry {
                byte_length: 1024,
                byte_offset: 0,
                checksum: "cafebabe".to_string(),
                chunk_index: 0,
                source_peer_id: Some(Uuid::nil()),
                status: "available".to_string(),
            }],
            session_id: Uuid::nil(),
        };
        let (entries, table_str) = format_manifest(&manifest);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["chunk_index"], 0);
        assert!(table_str.contains("cafebabe"));
        assert!(table_str.contains("available"));
    }

    #[test]
    fn format_manifest_empty() {
        let manifest = ChunkManifestResponse {
            chunks: vec![],
            session_id: Uuid::nil(),
        };
        let (entries, table_str) = format_manifest(&manifest);
        assert!(entries.is_empty());
        assert!(table_str.contains("INDEX"));
    }

    // ---- wiremock handler tests: new handlers ----

    static OTHER_UUID: &str = "11111111-1111-1111-1111-111111111111";

    fn identity_json() -> serde_json::Value {
        json!({
            "endpoint_url": "https://self.example.com",
            "name": "self-peer",
            "peer_id": NIL_UUID
        })
    }

    fn discoverable_json() -> serde_json::Value {
        json!({
            "endpoint_url": "https://d.example.com",
            "name": "disc-peer",
            "peer_id": NIL_UUID,
            "region": "eu-west-1",
            "status": "active"
        })
    }

    fn subscription_json() -> serde_json::Value {
        json!({
            "created_at": "2026-01-01T00:00:00Z",
            "id": NIL_UUID,
            "last_replicated_at": null,
            "peer_instance_id": NIL_UUID,
            "replication_filter": {},
            "replication_mode": "pull",
            "replication_schedule": null,
            "repository_id": NIL_UUID,
            "sync_enabled": true
        })
    }

    fn chunk_availability_json() -> serde_json::Value {
        json!({
            "artifact_id": NIL_UUID,
            "available_chunks": 3,
            "chunk_bitmap": [0, 1, 2],
            "peer_instance_id": NIL_UUID,
            "total_chunks": 4
        })
    }

    fn scored_peer_json() -> serde_json::Value {
        json!({
            "available_chunks": 5,
            "bandwidth_estimate_bps": 1000000,
            "endpoint_url": "https://s.example.com",
            "latency_ms": 12,
            "peer_id": NIL_UUID,
            "score": 0.875
        })
    }

    fn label_json() -> serde_json::Value {
        json!({
            "created_at": "2026-01-01T00:00:00Z",
            "id": NIL_UUID,
            "key": "env",
            "peer_instance_id": NIL_UUID,
            "value": "prod"
        })
    }

    fn labels_list_json() -> serde_json::Value {
        json!({ "items": [label_json()], "total": 1 })
    }

    fn session_json() -> serde_json::Value {
        json!({
            "artifact_checksum": "deadbeef",
            "artifact_id": NIL_UUID,
            "checksum_algo": "sha256",
            "chunk_size": 1048576,
            "completed_chunks": 2,
            "id": NIL_UUID,
            "requesting_peer_id": NIL_UUID,
            "status": "in_progress",
            "total_chunks": 8,
            "total_size": 8388608
        })
    }

    fn manifest_json() -> serde_json::Value {
        json!({
            "chunks": [{
                "byte_length": 1024,
                "byte_offset": 0,
                "checksum": "cafebabe",
                "chunk_index": 0,
                "source_peer_id": NIL_UUID,
                "status": "available"
            }],
            "session_id": NIL_UUID
        })
    }

    async fn mock(server: &wiremock::MockServer, m: &str, p: String, body: serde_json::Value) {
        mock_status(server, m, p, 200, body).await;
    }

    async fn mock_status(
        server: &wiremock::MockServer,
        m: &str,
        p: String,
        status: u16,
        body: serde_json::Value,
    ) {
        Mock::given(method(m))
            .and(path(p))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn handler_announce() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mock(
            &server,
            "POST",
            "/api/v1/peers/announce".into(),
            json!({"status":"accepted"}),
        )
        .await;
        let global = crate::test_utils::test_global(OutputFormat::Json);
        let r = announce_instance("p", "https://p", "k", NIL_UUID, &global).await;
        assert!(r.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_identity() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mock(
            &server,
            "GET",
            "/api/v1/peers/identity".into(),
            identity_json(),
        )
        .await;
        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(show_identity(&global).await.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_heartbeat() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mock(
            &server,
            "POST",
            format!("/api/v1/peers/{NIL_UUID}/heartbeat"),
            json!({}),
        )
        .await;
        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(
            send_heartbeat(NIL_UUID, 1024, Some("active"), &global)
                .await
                .is_ok()
        );
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_network_profile() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mock(
            &server,
            "PUT",
            format!("/api/v1/peers/{NIL_UUID}/network-profile"),
            json!({}),
        )
        .await;
        let global = crate::test_utils::test_global(OutputFormat::Json);
        let r =
            update_network_profile(NIL_UUID, Some(1000), Some(2), None, None, None, &global).await;
        assert!(r.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_connections() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mock(
            &server,
            "GET",
            format!("/api/v1/peers/{NIL_UUID}/connections"),
            json!([probe_json()]),
        )
        .await;
        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(list_connections(NIL_UUID, None, &global).await.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_discover_peers() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mock(
            &server,
            "GET",
            format!("/api/v1/peers/{NIL_UUID}/connections/discover"),
            json!([discoverable_json()]),
        )
        .await;
        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(discover_peers(NIL_UUID, &global).await.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_mark_unreachable() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mock(
            &server,
            "POST",
            format!("/api/v1/peers/{NIL_UUID}/connections/{OTHER_UUID}/unreachable"),
            json!({}),
        )
        .await;
        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(
            mark_unreachable(NIL_UUID, OTHER_UUID, &global)
                .await
                .is_ok()
        );
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_subscriptions() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mock(
            &server,
            "GET",
            format!("/api/v1/peers/{NIL_UUID}/repositories"),
            json!([OTHER_UUID]),
        )
        .await;
        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(list_subscriptions(NIL_UUID, &global).await.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_subscription() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mock(
            &server,
            "GET",
            format!("/api/v1/peers/{NIL_UUID}/repositories/{OTHER_UUID}"),
            subscription_json(),
        )
        .await;
        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(
            show_subscription(NIL_UUID, OTHER_UUID, &global)
                .await
                .is_ok()
        );
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_assign_repo() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mock(
            &server,
            "POST",
            format!("/api/v1/peers/{NIL_UUID}/repositories"),
            json!({}),
        )
        .await;
        let global = crate::test_utils::test_global(OutputFormat::Json);
        let r = assign_repo(
            NIL_UUID,
            OTHER_UUID,
            Some("pull"),
            None,
            Some(true),
            &global,
        )
        .await;
        assert!(r.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_unassign_repo() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mock(
            &server,
            "DELETE",
            format!("/api/v1/peers/{NIL_UUID}/repositories/{OTHER_UUID}"),
            json!({}),
        )
        .await;
        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(
            unassign_repo(NIL_UUID, OTHER_UUID, true, &global)
                .await
                .is_ok()
        );
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_run_subscription() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mock_status(
            &server,
            "POST",
            format!("/api/v1/peers/{NIL_UUID}/repositories/{OTHER_UUID}/sync"),
            202,
            json!({"status":"queued","tasks_queued":3}),
        )
        .await;
        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(
            run_subscription(NIL_UUID, OTHER_UUID, &global)
                .await
                .is_ok()
        );
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_chunk_availability() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mock(
            &server,
            "GET",
            format!("/api/v1/peers/{NIL_UUID}/chunks/{OTHER_UUID}"),
            chunk_availability_json(),
        )
        .await;
        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(
            show_chunk_availability(NIL_UUID, OTHER_UUID, &global)
                .await
                .is_ok()
        );
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_update_chunk_availability() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mock(
            &server,
            "PUT",
            format!("/api/v1/peers/{NIL_UUID}/chunks/{OTHER_UUID}"),
            json!({}),
        )
        .await;
        let global = crate::test_utils::test_global(OutputFormat::Json);
        let r = update_chunk_availability(NIL_UUID, OTHER_UUID, 4, "0,1,2,3", &global).await;
        assert!(r.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_peers_with_chunks() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mock(
            &server,
            "GET",
            format!("/api/v1/peers/{NIL_UUID}/chunks/{OTHER_UUID}/peers"),
            json!([chunk_availability_json()]),
        )
        .await;
        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(
            list_peers_with_chunks(NIL_UUID, OTHER_UUID, &global)
                .await
                .is_ok()
        );
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_scored_peers() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mock(
            &server,
            "GET",
            format!("/api/v1/peers/{NIL_UUID}/chunks/{OTHER_UUID}/scored-peers"),
            json!([scored_peer_json()]),
        )
        .await;
        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(
            list_scored_peers(NIL_UUID, OTHER_UUID, &global)
                .await
                .is_ok()
        );
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_labels() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mock(
            &server,
            "GET",
            format!("/api/v1/peers/{NIL_UUID}/labels"),
            labels_list_json(),
        )
        .await;
        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(list_labels(NIL_UUID, &global).await.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_set_labels() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mock(
            &server,
            "PUT",
            format!("/api/v1/peers/{NIL_UUID}/labels"),
            labels_list_json(),
        )
        .await;
        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let r = set_labels(NIL_UUID, &["env=prod".to_string()], &global).await;
        assert!(r.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_add_label() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mock(
            &server,
            "POST",
            format!("/api/v1/peers/{NIL_UUID}/labels/env"),
            label_json(),
        )
        .await;
        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(
            add_label(NIL_UUID, "env", Some("prod"), &global)
                .await
                .is_ok()
        );
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_delete_label() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mock_status(
            &server,
            "DELETE",
            format!("/api/v1/peers/{NIL_UUID}/labels/env"),
            204,
            json!({}),
        )
        .await;
        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(delete_label(NIL_UUID, "env", true, &global).await.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_init_transfer() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mock(
            &server,
            "POST",
            format!("/api/v1/peers/{NIL_UUID}/transfer/init"),
            session_json(),
        )
        .await;
        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(
            init_transfer(NIL_UUID, OTHER_UUID, Some(1024), &global)
                .await
                .is_ok()
        );
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_session() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mock(
            &server,
            "GET",
            format!("/api/v1/peers/{NIL_UUID}/transfer/{OTHER_UUID}"),
            session_json(),
        )
        .await;
        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(show_session(NIL_UUID, OTHER_UUID, &global).await.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_manifest() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mock(
            &server,
            "GET",
            format!("/api/v1/peers/{NIL_UUID}/transfer/{OTHER_UUID}/chunks"),
            manifest_json(),
        )
        .await;
        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(show_manifest(NIL_UUID, OTHER_UUID, &global).await.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_complete_session() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mock(
            &server,
            "POST",
            format!("/api/v1/peers/{NIL_UUID}/transfer/{OTHER_UUID}/complete"),
            json!({}),
        )
        .await;
        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(
            complete_session(NIL_UUID, OTHER_UUID, &global)
                .await
                .is_ok()
        );
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_fail_session() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mock(
            &server,
            "POST",
            format!("/api/v1/peers/{NIL_UUID}/transfer/{OTHER_UUID}/fail"),
            json!({}),
        )
        .await;
        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(
            fail_session(NIL_UUID, OTHER_UUID, "boom", &global)
                .await
                .is_ok()
        );
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_complete_chunk() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mock(
            &server,
            "POST",
            format!("/api/v1/peers/{NIL_UUID}/transfer/{OTHER_UUID}/chunk/0/complete"),
            json!({}),
        )
        .await;
        let global = crate::test_utils::test_global(OutputFormat::Json);
        let r = complete_chunk(NIL_UUID, OTHER_UUID, 0, "abc", Some(NIL_UUID), &global).await;
        assert!(r.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_fail_chunk() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mock(
            &server,
            "POST",
            format!("/api/v1/peers/{NIL_UUID}/transfer/{OTHER_UUID}/chunk/0/fail"),
            json!({}),
        )
        .await;
        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(
            fail_chunk(NIL_UUID, OTHER_UUID, 0, "boom", &global)
                .await
                .is_ok()
        );
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_retry_chunk() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mock(
            &server,
            "POST",
            format!("/api/v1/peers/{NIL_UUID}/transfer/{OTHER_UUID}/chunk/0/retry"),
            json!({}),
        )
        .await;
        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(retry_chunk(NIL_UUID, OTHER_UUID, 0, &global).await.is_ok());
        crate::test_utils::teardown_env();
    }
}
