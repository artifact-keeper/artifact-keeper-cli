use artifact_keeper_sdk::ClientPeersExt;
use artifact_keeper_sdk::types::{PeerInstanceResponse, PeerResponse, SyncTaskResponse};
use clap::Subcommand;
use miette::Result;
use serde_json::Value;

use super::client::client_for;
use super::helpers::{confirm_action, new_table, parse_uuid, sdk_err, short_id};
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

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", peer.id);
        return Ok(());
    }

    eprintln!("Peer '{}' registered (ID: {}).", peer.name, peer.id);

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
    eprintln!("Peer {id} unregistered.");

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
            "storage_key": "artifacts/pkg-1.0.tar.gz"
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
}
