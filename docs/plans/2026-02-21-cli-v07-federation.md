# v0.7 Federation & Replication Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add peer instance management, sync policies, and webhook commands to the CLI, plus a TUI replication status panel.

**Architecture:** Four new command modules (peer, sync_policy, webhook, replication) following the established pattern: clap derive enums, async handler functions calling the Progenitor SDK, format helper functions for table/detail output, wiremock-based tests. The TUI gets a new Replication panel.

**Tech Stack:** Rust, clap 4 (derive), artifact-keeper-sdk (Progenitor), comfy_table, wiremock 0.6, ratatui

---

## Task 1: `ak peer` command module

**Files:**
- Create: `src/commands/peer.rs`
- Modify: `src/commands/mod.rs`
- Modify: `src/cli.rs`

**Step 1: Create `src/commands/peer.rs` with clap enums and handler stubs**

```rust
use artifact_keeper_sdk::types::PeerInstanceResponse;
use artifact_keeper_sdk::ClientPeersExt;
use clap::Subcommand;
use miette::Result;
use serde_json::Value;

use super::client::client_for;
use super::helpers::{confirm_action, new_table, parse_uuid, sdk_err, short_id};
use crate::cli::GlobalArgs;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum PeerCommand {
    /// List registered peer instances
    List {
        /// Filter by status (online, offline, syncing)
        #[arg(long)]
        status: Option<String>,

        /// Filter by region
        #[arg(long)]
        region: Option<String>,
    },

    /// Show peer instance details
    Show {
        /// Peer instance ID
        id: String,
    },

    /// Register a new peer instance
    Register {
        /// Peer display name
        name: String,

        /// Peer endpoint URL
        #[arg(long)]
        url: String,

        /// API key for authenticating with the peer
        #[arg(long)]
        api_key: String,

        /// Geographic region identifier
        #[arg(long)]
        region: Option<String>,
    },

    /// Unregister a peer instance
    Unregister {
        /// Peer instance ID
        id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Test connectivity to a peer
    Test {
        /// Peer instance ID
        id: String,
    },

    /// Trigger sync with a peer
    Sync {
        /// Peer instance ID
        id: String,
    },

    /// List sync tasks for a peer
    Tasks {
        /// Peer instance ID
        id: String,

        /// Filter by status
        #[arg(long)]
        status: Option<String>,
    },
}

impl PeerCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List { status, region } => list_peers(status.as_deref(), region.as_deref(), global).await,
            Self::Show { id } => show_peer(&id, global).await,
            Self::Register { name, url, api_key, region } => {
                register_peer(&name, &url, &api_key, region.as_deref(), global).await
            }
            Self::Unregister { id, yes } => unregister_peer(&id, yes, global).await,
            Self::Test { id } => test_peer(&id, global).await,
            Self::Sync { id } => sync_peer(&id, global).await,
            Self::Tasks { id, status } => list_sync_tasks(&id, status.as_deref(), global).await,
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

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
    println!("{}", output::render(&entries, &global.format, Some(table_str)));
    Ok(())
}

async fn show_peer(id: &str, global: &GlobalArgs) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching peer details...");

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
        region: region.map(|s| s.to_string()),
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
    let spinner = output::spinner("Probing peer...");

    let body = artifact_keeper_sdk::types::ProbePeerRequest {
        target_peer_id: peer_id,
    };

    let result = client
        .probe_peer()
        .id(peer_id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("probe peer", e))?;

    let result = result.into_inner();
    spinner.finish_and_clear();

    let info = serde_json::json!({
        "peer_id": peer_id.to_string(),
        "status": result.status,
        "latency_ms": result.latency_ms,
    });

    if matches!(global.format, OutputFormat::Table) {
        eprintln!(
            "Peer {} is {} (latency: {}ms)",
            &id[..8.min(id.len())],
            result.status,
            result.latency_ms.unwrap_or(0),
        );
    } else {
        println!("{}", output::render(&info, &global.format, None));
    }

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

async fn list_sync_tasks(id: &str, status: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let peer_id = parse_uuid(id, "peer")?;
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching sync tasks...");

    let mut req = client.get_sync_tasks().id(peer_id);
    if let Some(s) = status {
        req = req.status(s);
    }

    let resp = req.send().await.map_err(|e| sdk_err("get sync tasks", e))?;
    let tasks = resp.into_inner();
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

    let (entries, table_str) = format_sync_tasks_table(&tasks);
    println!("{}", output::render(&entries, &global.format, Some(table_str)));
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
                "region": p.region,
                "is_local": p.is_local,
                "last_heartbeat_at": p.last_heartbeat_at.map(|t| t.to_rfc3339()),
                "last_sync_at": p.last_sync_at.map(|t| t.to_rfc3339()),
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec![
            "ID", "NAME", "ENDPOINT", "STATUS", "REGION", "LOCAL", "LAST HEARTBEAT", "LAST SYNC",
        ]);

        for p in peers {
            let id_short = short_id(&p.id);
            let region = p.region.as_deref().unwrap_or("-");
            let local = if p.is_local { "yes" } else { "no" };
            let heartbeat = p
                .last_heartbeat_at
                .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| "-".to_string());
            let sync = p
                .last_sync_at
                .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| "-".to_string());
            table.add_row(vec![
                &id_short,
                &p.name,
                &p.endpoint_url,
                &p.status,
                region,
                local,
                &heartbeat,
                &sync,
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
        "region": peer.region,
        "is_local": peer.is_local,
        "cache_size_bytes": peer.cache_size_bytes,
        "cache_used_bytes": peer.cache_used_bytes,
        "cache_usage_percent": peer.cache_usage_percent,
        "last_heartbeat_at": peer.last_heartbeat_at.map(|t| t.to_rfc3339()),
        "last_sync_at": peer.last_sync_at.map(|t| t.to_rfc3339()),
        "created_at": peer.created_at.to_rfc3339(),
    });

    let table_str = format!(
        "ID:            {}\n\
         Name:          {}\n\
         Endpoint:      {}\n\
         Status:        {}\n\
         Region:        {}\n\
         Local:         {}\n\
         Cache Size:    {}\n\
         Cache Used:    {} ({:.1}%)\n\
         Last Heartbeat:{}\n\
         Last Sync:     {}\n\
         Created:       {}",
        peer.id,
        peer.name,
        peer.endpoint_url,
        peer.status,
        peer.region.as_deref().unwrap_or("-"),
        if peer.is_local { "yes" } else { "no" },
        humanize_bytes(peer.cache_size_bytes),
        humanize_bytes(peer.cache_used_bytes),
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

fn format_sync_tasks_table(
    tasks: &[artifact_keeper_sdk::types::SyncTaskResponse],
) -> (Vec<Value>, String) {
    let entries: Vec<_> = tasks
        .iter()
        .map(|t| {
            serde_json::json!({
                "id": t.id.to_string(),
                "artifact_id": t.artifact_id.to_string(),
                "storage_key": t.storage_key,
                "priority": t.priority,
                "artifact_size": t.artifact_size,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["ID", "ARTIFACT", "STORAGE KEY", "PRIORITY", "SIZE"]);

        for t in tasks {
            let id_short = short_id(&t.id);
            let art_short = short_id(&t.artifact_id);
            table.add_row(vec![
                &id_short,
                &art_short,
                &t.storage_key,
                &t.priority.to_string(),
                &humanize_bytes(t.artifact_size),
            ]);
        }

        table.to_string()
    };

    (entries, table_str)
}

fn humanize_bytes(bytes: i64) -> String {
    const KB: i64 = 1024;
    const MB: i64 = 1024 * 1024;
    const GB: i64 = 1024 * 1024 * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}
```

**Step 2: Add `pub mod peer;` to `src/commands/mod.rs`**

Add `pub mod peer;` in alphabetical order after `pub mod permission;`.

**Step 3: Wire into `src/cli.rs`**

Add to the `Command` enum:

```rust
    /// Manage peer instances for federation and replication
    #[command(
        after_help = "Examples:\n  ak peer list\n  ak peer show <peer-id>\n  ak peer register edge-1 --url https://edge.company.com --api-key <key>\n  ak peer test <peer-id>\n  ak peer sync <peer-id>"
    )]
    Peer {
        #[command(subcommand)]
        command: commands::peer::PeerCommand,
    },
```

Add to the `match self.command` block:

```rust
    Command::Peer { command } => command.execute(&global).await,
```

**Step 4: Build and fix any compilation errors**

Run: `cargo build 2>&1 | head -50`

**Step 5: Add tests to `src/commands/peer.rs`**

Append the test module (parsing tests, format tests, wiremock handler tests). Follow the exact pattern from license.rs: TestCli wrapper, parse helper, format function tests with mock data, wiremock handler tests with mock_setup/setup_env/teardown_env.

**Step 6: Run tests**

Run: `cargo test --workspace --lib peer`
Expected: All pass

**Step 7: Commit**

```bash
git add src/commands/peer.rs src/commands/mod.rs src/cli.rs
git commit -m "feat(v0.7): add ak peer command for federation management"
```

---

## Task 2: `ak sync-policy` command module

**Files:**
- Create: `src/commands/sync_policy.rs`
- Modify: `src/commands/mod.rs`
- Modify: `src/cli.rs`

**Step 1: Create `src/commands/sync_policy.rs`**

```rust
use artifact_keeper_sdk::types::SyncPolicyResponse;
use artifact_keeper_sdk::ClientPeersExt;
use clap::Subcommand;
use miette::Result;
use serde_json::Value;

use super::client::client_for;
use super::helpers::{confirm_action, new_table, parse_uuid, sdk_err, short_id};
use crate::cli::GlobalArgs;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum SyncPolicyCommand {
    /// List all sync policies
    List,

    /// Show sync policy details
    Show {
        /// Sync policy ID
        id: String,
    },

    /// Create a sync policy
    Create {
        /// Policy name
        name: String,

        /// Replication mode (push, pull, mirror)
        #[arg(long, default_value = "push")]
        mode: String,

        /// Policy description
        #[arg(long)]
        description: Option<String>,

        /// Priority (higher = evaluated first)
        #[arg(long)]
        priority: Option<i32>,

        /// Enable on creation
        #[arg(long)]
        enabled: Option<bool>,

        /// Repo selector as JSON (e.g. '{"match_keys":["npm-*"]}')
        #[arg(long)]
        repo_selector: Option<String>,

        /// Peer selector as JSON (e.g. '{"match_region":"us-east"}')
        #[arg(long)]
        peer_selector: Option<String>,

        /// Artifact filter as JSON (e.g. '{"match_format":"npm"}')
        #[arg(long)]
        artifact_filter: Option<String>,
    },

    /// Update a sync policy
    Update {
        /// Sync policy ID
        id: String,

        /// Policy name
        #[arg(long)]
        name: Option<String>,

        /// Replication mode
        #[arg(long)]
        mode: Option<String>,

        /// Description
        #[arg(long)]
        description: Option<String>,

        /// Priority
        #[arg(long)]
        priority: Option<i32>,
    },

    /// Delete a sync policy
    Delete {
        /// Sync policy ID
        id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Enable or disable a sync policy
    Toggle {
        /// Sync policy ID
        id: String,

        /// Enable the policy
        #[arg(long, conflicts_with = "disable")]
        enable: bool,

        /// Disable the policy
        #[arg(long, conflicts_with = "enable")]
        disable: bool,
    },

    /// Force re-evaluate all sync policies
    Evaluate,

    /// Preview what a policy would match (dry-run)
    Preview {
        /// Repo selector as JSON
        #[arg(long)]
        repo_selector: Option<String>,

        /// Peer selector as JSON
        #[arg(long)]
        peer_selector: Option<String>,

        /// Artifact filter as JSON
        #[arg(long)]
        artifact_filter: Option<String>,
    },
}

impl SyncPolicyCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List => list_policies(global).await,
            Self::Show { id } => show_policy(&id, global).await,
            Self::Create {
                name, mode, description, priority, enabled,
                repo_selector, peer_selector, artifact_filter,
            } => {
                create_policy(
                    &name, &mode, description.as_deref(), priority, enabled,
                    repo_selector.as_deref(), peer_selector.as_deref(),
                    artifact_filter.as_deref(), global,
                ).await
            }
            Self::Update { id, name, mode, description, priority } => {
                update_policy(&id, name.as_deref(), mode.as_deref(), description.as_deref(), priority, global).await
            }
            Self::Delete { id, yes } => delete_policy(&id, yes, global).await,
            Self::Toggle { id, enable, disable } => toggle_policy(&id, enable, disable, global).await,
            Self::Evaluate => evaluate_policies(global).await,
            Self::Preview { repo_selector, peer_selector, artifact_filter } => {
                preview_policy(
                    repo_selector.as_deref(), peer_selector.as_deref(),
                    artifact_filter.as_deref(), global,
                ).await
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn list_policies(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching sync policies...");

    let resp = client
        .list_sync_policies()
        .send()
        .await
        .map_err(|e| sdk_err("list sync policies", e))?;

    let list = resp.into_inner();
    spinner.finish_and_clear();

    if list.items.is_empty() {
        eprintln!("No sync policies found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for p in &list.items {
            println!("{}", p.id);
        }
        return Ok(());
    }

    let (entries, table_str) = format_policies_table(&list.items);
    println!("{}", output::render(&entries, &global.format, Some(table_str)));
    Ok(())
}

async fn show_policy(id: &str, global: &GlobalArgs) -> Result<()> {
    let policy_id = parse_uuid(id, "sync policy")?;
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching sync policy...");

    let policy = client
        .get_sync_policy()
        .id(policy_id)
        .send()
        .await
        .map_err(|e| sdk_err("get sync policy", e))?;

    spinner.finish_and_clear();

    let (info, table_str) = format_policy_detail(&policy);
    println!("{}", output::render(&info, &global.format, Some(table_str)));
    Ok(())
}

fn parse_json_map(input: Option<&str>) -> Result<serde_json::Map<String, serde_json::Value>> {
    match input {
        Some(s) => {
            let val: serde_json::Value = serde_json::from_str(s)
                .map_err(|e| crate::error::AkError::ConfigError(format!("Invalid JSON: {e}")))?;
            match val {
                serde_json::Value::Object(m) => Ok(m),
                _ => Err(crate::error::AkError::ConfigError("Expected JSON object".to_string()).into()),
            }
        }
        None => Ok(serde_json::Map::new()),
    }
}

#[allow(clippy::too_many_arguments)]
async fn create_policy(
    name: &str,
    mode: &str,
    description: Option<&str>,
    priority: Option<i32>,
    enabled: Option<bool>,
    repo_selector: Option<&str>,
    peer_selector: Option<&str>,
    artifact_filter: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Creating sync policy...");

    let body = artifact_keeper_sdk::types::CreateSyncPolicyPayload {
        name: name.to_string(),
        replication_mode: Some(mode.to_string()),
        description: description.map(|s| s.to_string()),
        priority,
        precedence: None,
        enabled,
        repo_selector: parse_json_map(repo_selector)?,
        peer_selector: parse_json_map(peer_selector)?,
        artifact_filter: parse_json_map(artifact_filter)?,
    };

    let policy = client
        .create_sync_policy()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("create sync policy", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", policy.id);
        return Ok(());
    }

    eprintln!("Sync policy '{}' created (ID: {}).", policy.name, policy.id);
    Ok(())
}

async fn update_policy(
    id: &str,
    name: Option<&str>,
    mode: Option<&str>,
    description: Option<&str>,
    priority: Option<i32>,
    global: &GlobalArgs,
) -> Result<()> {
    let policy_id = parse_uuid(id, "sync policy")?;
    let client = client_for(global)?;
    let spinner = output::spinner("Updating sync policy...");

    let body = artifact_keeper_sdk::types::CreateSyncPolicyPayload {
        name: name.unwrap_or("").to_string(),
        replication_mode: mode.map(|s| s.to_string()),
        description: description.map(|s| s.to_string()),
        priority,
        precedence: None,
        enabled: None,
        repo_selector: serde_json::Map::new(),
        peer_selector: serde_json::Map::new(),
        artifact_filter: serde_json::Map::new(),
    };

    client
        .update_sync_policy()
        .id(policy_id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("update sync policy", e))?;

    spinner.finish_and_clear();
    eprintln!("Sync policy {id} updated.");
    Ok(())
}

async fn delete_policy(id: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    let policy_id = parse_uuid(id, "sync policy")?;

    if !confirm_action(
        &format!("Delete sync policy {id}?"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Deleting sync policy...");

    client
        .delete_sync_policy()
        .id(policy_id)
        .send()
        .await
        .map_err(|e| sdk_err("delete sync policy", e))?;

    spinner.finish_and_clear();
    eprintln!("Sync policy {id} deleted.");
    Ok(())
}

async fn toggle_policy(id: &str, enable: bool, disable: bool, global: &GlobalArgs) -> Result<()> {
    let policy_id = parse_uuid(id, "sync policy")?;

    let enabled = if enable {
        true
    } else if disable {
        false
    } else {
        return Err(crate::error::AkError::ConfigError(
            "Specify --enable or --disable".to_string(),
        ).into());
    };

    let client = client_for(global)?;
    let spinner = output::spinner(if enabled { "Enabling sync policy..." } else { "Disabling sync policy..." });

    let body = artifact_keeper_sdk::types::TogglePolicyRequest { enabled };

    client
        .toggle_policy()
        .id(policy_id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("toggle sync policy", e))?;

    spinner.finish_and_clear();

    if enabled {
        eprintln!("Sync policy {id} enabled.");
    } else {
        eprintln!("Sync policy {id} disabled.");
    }

    Ok(())
}

async fn evaluate_policies(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Evaluating sync policies...");

    client
        .evaluate_policies()
        .send()
        .await
        .map_err(|e| sdk_err("evaluate sync policies", e))?;

    spinner.finish_and_clear();
    eprintln!("All sync policies re-evaluated.");
    Ok(())
}

async fn preview_policy(
    repo_selector: Option<&str>,
    peer_selector: Option<&str>,
    artifact_filter: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Previewing sync policy...");

    let body = artifact_keeper_sdk::types::CreateSyncPolicyPayload {
        name: "preview".to_string(),
        replication_mode: None,
        description: None,
        priority: None,
        precedence: None,
        enabled: None,
        repo_selector: parse_json_map(repo_selector)?,
        peer_selector: parse_json_map(peer_selector)?,
        artifact_filter: parse_json_map(artifact_filter)?,
    };

    let result = client
        .preview_sync_policy()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("preview sync policy", e))?;

    let result = result.into_inner();
    spinner.finish_and_clear();

    println!("{}", output::render(&result, &global.format, None));
    Ok(())
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

fn format_policies_table(policies: &[SyncPolicyResponse]) -> (Vec<Value>, String) {
    let entries: Vec<_> = policies
        .iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id.to_string(),
                "name": p.name,
                "replication_mode": p.replication_mode,
                "enabled": p.enabled,
                "priority": p.priority,
                "description": p.description,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec![
            "ID", "NAME", "MODE", "ENABLED", "PRIORITY", "DESCRIPTION",
        ]);

        for p in policies {
            let id_short = short_id(&p.id);
            let enabled = if p.enabled { "yes" } else { "no" };
            table.add_row(vec![
                &id_short,
                &p.name,
                &p.replication_mode,
                enabled,
                &p.priority.to_string(),
                &p.description,
            ]);
        }

        table.to_string()
    };

    (entries, table_str)
}

fn format_policy_detail(policy: &SyncPolicyResponse) -> (Value, String) {
    let info = serde_json::json!({
        "id": policy.id.to_string(),
        "name": policy.name,
        "description": policy.description,
        "replication_mode": policy.replication_mode,
        "enabled": policy.enabled,
        "priority": policy.priority,
        "precedence": policy.precedence,
        "repo_selector": policy.repo_selector,
        "peer_selector": policy.peer_selector,
        "artifact_filter": policy.artifact_filter,
        "created_at": policy.created_at.to_rfc3339(),
        "updated_at": policy.updated_at.to_rfc3339(),
    });

    let table_str = format!(
        "ID:            {}\n\
         Name:          {}\n\
         Description:   {}\n\
         Mode:          {}\n\
         Enabled:       {}\n\
         Priority:      {}\n\
         Precedence:    {}\n\
         Repo Selector: {}\n\
         Peer Selector: {}\n\
         Art. Filter:   {}\n\
         Created:       {}\n\
         Updated:       {}",
        policy.id,
        policy.name,
        policy.description,
        policy.replication_mode,
        if policy.enabled { "yes" } else { "no" },
        policy.priority,
        policy.precedence,
        serde_json::to_string(&policy.repo_selector).unwrap_or_default(),
        serde_json::to_string(&policy.peer_selector).unwrap_or_default(),
        serde_json::to_string(&policy.artifact_filter).unwrap_or_default(),
        policy.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
        policy.updated_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    (info, table_str)
}
```

**Step 2: Add `pub mod sync_policy;` to `src/commands/mod.rs`**

**Step 3: Wire into `src/cli.rs`**

Add to Command enum:

```rust
    /// Manage sync policies for automated replication
    #[command(
        alias = "sp",
        after_help = "Examples:\n  ak sync-policy list\n  ak sync-policy create my-policy --mode push\n  ak sync-policy toggle <id> --enable\n  ak sync-policy preview --repo-selector '{\"match_keys\":[\"npm-*\"]}'"
    )]
    SyncPolicy {
        #[command(subcommand)]
        command: commands::sync_policy::SyncPolicyCommand,
    },
```

Add to match block:

```rust
    Command::SyncPolicy { command } => command.execute(&global).await,
```

**Step 4: Build and fix compilation errors**

Run: `cargo build 2>&1 | head -50`

**Step 5: Add tests (parsing + format + wiremock)**

**Step 6: Run tests**

Run: `cargo test --workspace --lib sync_policy`

**Step 7: Commit**

```bash
git add src/commands/sync_policy.rs src/commands/mod.rs src/cli.rs
git commit -m "feat(v0.7): add ak sync-policy command for replication policies"
```

---

## Task 3: `ak webhook` command module

**Files:**
- Create: `src/commands/webhook.rs`
- Modify: `src/commands/mod.rs`
- Modify: `src/cli.rs`

**Step 1: Create `src/commands/webhook.rs`**

```rust
use artifact_keeper_sdk::types::{DeliveryResponse, WebhookResponse};
use artifact_keeper_sdk::ClientWebhooksExt;
use clap::Subcommand;
use miette::Result;
use serde_json::Value;

use super::client::client_for;
use super::helpers::{confirm_action, new_table, parse_uuid, sdk_err, short_id};
use crate::cli::GlobalArgs;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum WebhookCommand {
    /// List webhooks
    List {
        /// Filter by repository ID
        #[arg(long)]
        repo: Option<String>,

        /// Filter by enabled status
        #[arg(long)]
        enabled: Option<bool>,
    },

    /// Show webhook details
    Show {
        /// Webhook ID
        id: String,
    },

    /// Create a webhook
    Create {
        /// Webhook name
        name: String,

        /// Delivery URL
        #[arg(long)]
        url: String,

        /// Event types to subscribe to (comma-separated)
        #[arg(long, value_delimiter = ',')]
        events: Vec<String>,

        /// HMAC secret for payload signing
        #[arg(long)]
        secret: Option<String>,

        /// Scope to a specific repository
        #[arg(long)]
        repo: Option<String>,
    },

    /// Delete a webhook
    Delete {
        /// Webhook ID
        id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Send a test event to a webhook
    Test {
        /// Webhook ID
        id: String,
    },

    /// Enable a webhook
    Enable {
        /// Webhook ID
        id: String,
    },

    /// Disable a webhook
    Disable {
        /// Webhook ID
        id: String,
    },

    /// List recent deliveries for a webhook
    Deliveries {
        /// Webhook ID
        id: String,

        /// Filter by delivery status
        #[arg(long)]
        status: Option<String>,
    },

    /// Redeliver a failed webhook delivery
    Redeliver {
        /// Webhook ID
        id: String,

        /// Delivery ID
        delivery_id: String,
    },
}

impl WebhookCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List { repo, enabled } => list_webhooks(repo.as_deref(), enabled, global).await,
            Self::Show { id } => show_webhook(&id, global).await,
            Self::Create { name, url, events, secret, repo } => {
                create_webhook(&name, &url, events, secret.as_deref(), repo.as_deref(), global).await
            }
            Self::Delete { id, yes } => delete_webhook(&id, yes, global).await,
            Self::Test { id } => test_webhook(&id, global).await,
            Self::Enable { id } => enable_webhook(&id, global).await,
            Self::Disable { id } => disable_webhook(&id, global).await,
            Self::Deliveries { id, status } => list_deliveries(&id, status.as_deref(), global).await,
            Self::Redeliver { id, delivery_id } => redeliver(&id, &delivery_id, global).await,
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn list_webhooks(repo: Option<&str>, enabled: Option<bool>, global: &GlobalArgs) -> Result<()> {
    let repository_id = super::helpers::parse_optional_uuid(repo, "repository")?;
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching webhooks...");

    let mut req = client.list_webhooks();
    if let Some(rid) = repository_id {
        req = req.repository_id(rid);
    }
    if let Some(e) = enabled {
        req = req.enabled(e);
    }

    let resp = req.send().await.map_err(|e| sdk_err("list webhooks", e))?;
    let list = resp.into_inner();
    spinner.finish_and_clear();

    if list.items.is_empty() {
        eprintln!("No webhooks found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for w in &list.items {
            println!("{}", w.id);
        }
        return Ok(());
    }

    let (entries, table_str) = format_webhooks_table(&list.items);
    println!("{}", output::render(&entries, &global.format, Some(table_str)));
    Ok(())
}

async fn show_webhook(id: &str, global: &GlobalArgs) -> Result<()> {
    let webhook_id = parse_uuid(id, "webhook")?;
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching webhook...");

    let webhook = client
        .get_webhook()
        .id(webhook_id)
        .send()
        .await
        .map_err(|e| sdk_err("get webhook", e))?;

    spinner.finish_and_clear();

    let (info, table_str) = format_webhook_detail(&webhook);
    println!("{}", output::render(&info, &global.format, Some(table_str)));
    Ok(())
}

async fn create_webhook(
    name: &str,
    url: &str,
    events: Vec<String>,
    secret: Option<&str>,
    repo: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let repository_id = super::helpers::parse_optional_uuid(repo, "repository")?;
    let client = client_for(global)?;
    let spinner = output::spinner("Creating webhook...");

    let body = artifact_keeper_sdk::types::CreateWebhookRequest {
        name: name.to_string(),
        url: url.to_string(),
        events,
        secret: secret.map(|s| s.to_string()),
        repository_id,
        headers: None,
    };

    let webhook = client
        .create_webhook()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("create webhook", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", webhook.id);
        return Ok(());
    }

    eprintln!("Webhook '{}' created (ID: {}).", webhook.name, webhook.id);
    Ok(())
}

async fn delete_webhook(id: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    let webhook_id = parse_uuid(id, "webhook")?;

    if !confirm_action(
        &format!("Delete webhook {id}?"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Deleting webhook...");

    client
        .delete_webhook()
        .id(webhook_id)
        .send()
        .await
        .map_err(|e| sdk_err("delete webhook", e))?;

    spinner.finish_and_clear();
    eprintln!("Webhook {id} deleted.");
    Ok(())
}

async fn test_webhook(id: &str, global: &GlobalArgs) -> Result<()> {
    let webhook_id = parse_uuid(id, "webhook")?;
    let client = client_for(global)?;
    let spinner = output::spinner("Sending test event...");

    client
        .test_webhook()
        .id(webhook_id)
        .send()
        .await
        .map_err(|e| sdk_err("test webhook", e))?;

    spinner.finish_and_clear();
    eprintln!("Test event sent to webhook {id}.");
    Ok(())
}

async fn enable_webhook(id: &str, global: &GlobalArgs) -> Result<()> {
    let webhook_id = parse_uuid(id, "webhook")?;
    let client = client_for(global)?;
    let spinner = output::spinner("Enabling webhook...");

    client
        .enable_webhook()
        .id(webhook_id)
        .send()
        .await
        .map_err(|e| sdk_err("enable webhook", e))?;

    spinner.finish_and_clear();
    eprintln!("Webhook {id} enabled.");
    Ok(())
}

async fn disable_webhook(id: &str, global: &GlobalArgs) -> Result<()> {
    let webhook_id = parse_uuid(id, "webhook")?;
    let client = client_for(global)?;
    let spinner = output::spinner("Disabling webhook...");

    client
        .disable_webhook()
        .id(webhook_id)
        .send()
        .await
        .map_err(|e| sdk_err("disable webhook", e))?;

    spinner.finish_and_clear();
    eprintln!("Webhook {id} disabled.");
    Ok(())
}

async fn list_deliveries(id: &str, status: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let webhook_id = parse_uuid(id, "webhook")?;
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching deliveries...");

    let mut req = client.list_deliveries().id(webhook_id);
    if let Some(s) = status {
        req = req.status(s);
    }

    let resp = req.send().await.map_err(|e| sdk_err("list deliveries", e))?;
    let list = resp.into_inner();
    spinner.finish_and_clear();

    if list.items.is_empty() {
        eprintln!("No deliveries found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for d in &list.items {
            println!("{}", d.id);
        }
        return Ok(());
    }

    let (entries, table_str) = format_deliveries_table(&list.items);
    println!("{}", output::render(&entries, &global.format, Some(table_str)));
    Ok(())
}

async fn redeliver(id: &str, delivery_id: &str, global: &GlobalArgs) -> Result<()> {
    let webhook_id = parse_uuid(id, "webhook")?;
    let did = parse_uuid(delivery_id, "delivery")?;
    let client = client_for(global)?;
    let spinner = output::spinner("Redelivering webhook...");

    client
        .redeliver()
        .id(webhook_id)
        .delivery_id(did)
        .send()
        .await
        .map_err(|e| sdk_err("redeliver webhook", e))?;

    spinner.finish_and_clear();
    eprintln!("Delivery {delivery_id} redelivered.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

fn format_webhooks_table(webhooks: &[WebhookResponse]) -> (Vec<Value>, String) {
    let entries: Vec<_> = webhooks
        .iter()
        .map(|w| {
            serde_json::json!({
                "id": w.id.to_string(),
                "name": w.name,
                "url": w.url,
                "enabled": w.is_enabled,
                "events": w.events,
                "last_triggered_at": w.last_triggered_at.map(|t| t.to_rfc3339()),
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec![
            "ID", "NAME", "URL", "ENABLED", "EVENTS", "LAST TRIGGERED",
        ]);

        for w in webhooks {
            let id_short = short_id(&w.id);
            let enabled = if w.is_enabled { "yes" } else { "no" };
            let events = w.events.join(", ");
            let last = w
                .last_triggered_at
                .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| "-".to_string());
            table.add_row(vec![&id_short, &w.name, &w.url, enabled, &events, &last]);
        }

        table.to_string()
    };

    (entries, table_str)
}

fn format_webhook_detail(webhook: &WebhookResponse) -> (Value, String) {
    let info = serde_json::json!({
        "id": webhook.id.to_string(),
        "name": webhook.name,
        "url": webhook.url,
        "enabled": webhook.is_enabled,
        "events": webhook.events,
        "repository_id": webhook.repository_id.map(|u| u.to_string()),
        "last_triggered_at": webhook.last_triggered_at.map(|t| t.to_rfc3339()),
        "created_at": webhook.created_at.to_rfc3339(),
    });

    let table_str = format!(
        "ID:             {}\n\
         Name:           {}\n\
         URL:            {}\n\
         Enabled:        {}\n\
         Events:         {}\n\
         Repository:     {}\n\
         Last Triggered: {}\n\
         Created:        {}",
        webhook.id,
        webhook.name,
        webhook.url,
        if webhook.is_enabled { "yes" } else { "no" },
        webhook.events.join(", "),
        webhook.repository_id
            .map(|u| u.to_string())
            .unwrap_or_else(|| "global".to_string()),
        webhook.last_triggered_at
            .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "-".to_string()),
        webhook.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    (info, table_str)
}

fn format_deliveries_table(deliveries: &[DeliveryResponse]) -> (Vec<Value>, String) {
    let entries: Vec<_> = deliveries
        .iter()
        .map(|d| {
            serde_json::json!({
                "id": d.id.to_string(),
                "event": d.event,
                "success": d.success,
                "attempts": d.attempts,
                "response_status": d.response_status,
                "created_at": d.created_at.to_rfc3339(),
                "delivered_at": d.delivered_at.map(|t| t.to_rfc3339()),
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec![
            "ID", "EVENT", "SUCCESS", "ATTEMPTS", "STATUS", "CREATED", "DELIVERED",
        ]);

        for d in deliveries {
            let id_short = short_id(&d.id);
            let success = if d.success { "yes" } else { "no" };
            let status = d
                .response_status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".to_string());
            let delivered = d
                .delivered_at
                .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| "-".to_string());
            table.add_row(vec![
                &id_short,
                &d.event,
                success,
                &d.attempts.to_string(),
                &status,
                &d.created_at.format("%Y-%m-%d %H:%M").to_string(),
                &delivered,
            ]);
        }

        table.to_string()
    };

    (entries, table_str)
}
```

**Step 2: Add `pub mod webhook;` to `src/commands/mod.rs`**

**Step 3: Wire into `src/cli.rs`**

Add to Command enum:

```rust
    /// Manage webhooks for event-driven integrations
    #[command(
        after_help = "Examples:\n  ak webhook list\n  ak webhook create deploy-hook --url https://ci.company.com/hook --events artifact.pushed,artifact.promoted\n  ak webhook test <id>\n  ak webhook deliveries <id>"
    )]
    Webhook {
        #[command(subcommand)]
        command: commands::webhook::WebhookCommand,
    },
```

Add to match block:

```rust
    Command::Webhook { command } => command.execute(&global).await,
```

**Step 4: Build and fix compilation errors**

Run: `cargo build 2>&1 | head -50`

**Step 5: Add tests (parsing + format + wiremock)**

**Step 6: Run tests**

Run: `cargo test --workspace --lib webhook`

**Step 7: Commit**

```bash
git add src/commands/webhook.rs src/commands/mod.rs src/cli.rs
git commit -m "feat(v0.7): add ak webhook command for event integrations"
```

---

## Task 4: Tests for all three modules

Each module needs three test categories appended in a `#[cfg(test)] mod tests` block:

**4a. Parsing tests** (TestCli wrapper, parse helper, test every subcommand variant and flag)

**4b. Format function tests** (construct mock SDK types, call format functions, assert on entries and table strings)

**4c. Wiremock handler tests** (mock_setup, setup_env, mount mocks, call handler functions, assert Ok)

Follow the exact pattern from `license.rs` tests. Each module should have 20-30 tests covering:

- Every subcommand parses correctly
- Required args missing causes error
- Format functions produce correct JSON entries
- Format functions produce correct table headers
- Every handler succeeds against wiremock mocks (list empty, list with data, show, create, delete, etc.)
- Quiet output mode prints IDs only

**Step 1: Add tests to peer.rs**

**Step 2: Run**: `cargo test --workspace --lib peer`

**Step 3: Add tests to sync_policy.rs**

**Step 4: Run**: `cargo test --workspace --lib sync_policy`

**Step 5: Add tests to webhook.rs**

**Step 6: Run**: `cargo test --workspace --lib webhook`

**Step 7: Run full test suite**: `cargo test --workspace --lib`

**Step 8: Commit**

```bash
git add src/commands/peer.rs src/commands/sync_policy.rs src/commands/webhook.rs
git commit -m "test(v0.7): add parsing, format, and wiremock tests for federation commands"
```

---

## Task 5: Version bump and cli.rs parsing tests

**Files:**
- Modify: `Cargo.toml` (root)
- Modify: `src/cli.rs` (add parsing tests for new commands)

**Step 1: Bump version in root `Cargo.toml` from 0.6.0 to 0.7.0**

**Step 2: Add parsing tests to `src/cli.rs` tests module**

Add tests for all new commands:

```rust
// ---- Peer command parsing ----

#[test]
fn parse_peer_list() {
    let cli = parse(&["ak", "peer", "list"]).unwrap();
    assert!(matches!(cli.command, Command::Peer { .. }));
}

#[test]
fn parse_peer_show() {
    let cli = parse(&["ak", "peer", "show", "some-id"]).unwrap();
    assert!(matches!(cli.command, Command::Peer { .. }));
}

#[test]
fn parse_peer_register() {
    let cli = parse(&[
        "ak", "peer", "register", "edge-1",
        "--url", "https://edge.example.com",
        "--api-key", "secret123",
    ]).unwrap();
    assert!(matches!(cli.command, Command::Peer { .. }));
}

#[test]
fn parse_peer_unregister() {
    let cli = parse(&["ak", "peer", "unregister", "some-id"]).unwrap();
    assert!(matches!(cli.command, Command::Peer { .. }));
}

#[test]
fn parse_peer_test() {
    let cli = parse(&["ak", "peer", "test", "some-id"]).unwrap();
    assert!(matches!(cli.command, Command::Peer { .. }));
}

#[test]
fn parse_peer_sync() {
    let cli = parse(&["ak", "peer", "sync", "some-id"]).unwrap();
    assert!(matches!(cli.command, Command::Peer { .. }));
}

#[test]
fn parse_peer_tasks() {
    let cli = parse(&["ak", "peer", "tasks", "some-id"]).unwrap();
    assert!(matches!(cli.command, Command::Peer { .. }));
}

// ---- Sync policy command parsing ----

#[test]
fn parse_sync_policy_list() {
    let cli = parse(&["ak", "sync-policy", "list"]).unwrap();
    assert!(matches!(cli.command, Command::SyncPolicy { .. }));
}

#[test]
fn parse_sync_policy_show() {
    let cli = parse(&["ak", "sync-policy", "show", "some-id"]).unwrap();
    assert!(matches!(cli.command, Command::SyncPolicy { .. }));
}

#[test]
fn parse_sync_policy_create() {
    let cli = parse(&["ak", "sync-policy", "create", "my-policy", "--mode", "push"]).unwrap();
    assert!(matches!(cli.command, Command::SyncPolicy { .. }));
}

#[test]
fn parse_sync_policy_delete() {
    let cli = parse(&["ak", "sync-policy", "delete", "some-id"]).unwrap();
    assert!(matches!(cli.command, Command::SyncPolicy { .. }));
}

#[test]
fn parse_sync_policy_toggle_enable() {
    let cli = parse(&["ak", "sync-policy", "toggle", "some-id", "--enable"]).unwrap();
    assert!(matches!(cli.command, Command::SyncPolicy { .. }));
}

#[test]
fn parse_sync_policy_evaluate() {
    let cli = parse(&["ak", "sync-policy", "evaluate"]).unwrap();
    assert!(matches!(cli.command, Command::SyncPolicy { .. }));
}

#[test]
fn parse_sync_policy_preview() {
    let cli = parse(&["ak", "sync-policy", "preview"]).unwrap();
    assert!(matches!(cli.command, Command::SyncPolicy { .. }));
}

#[test]
fn parse_sync_policy_alias_sp() {
    let cli = parse(&["ak", "sp", "list"]).unwrap();
    assert!(matches!(cli.command, Command::SyncPolicy { .. }));
}

// ---- Webhook command parsing ----

#[test]
fn parse_webhook_list() {
    let cli = parse(&["ak", "webhook", "list"]).unwrap();
    assert!(matches!(cli.command, Command::Webhook { .. }));
}

#[test]
fn parse_webhook_show() {
    let cli = parse(&["ak", "webhook", "show", "some-id"]).unwrap();
    assert!(matches!(cli.command, Command::Webhook { .. }));
}

#[test]
fn parse_webhook_create() {
    let cli = parse(&[
        "ak", "webhook", "create", "deploy",
        "--url", "https://ci.example.com/hook",
        "--events", "artifact.pushed,artifact.promoted",
    ]).unwrap();
    assert!(matches!(cli.command, Command::Webhook { .. }));
}

#[test]
fn parse_webhook_delete() {
    let cli = parse(&["ak", "webhook", "delete", "some-id"]).unwrap();
    assert!(matches!(cli.command, Command::Webhook { .. }));
}

#[test]
fn parse_webhook_test() {
    let cli = parse(&["ak", "webhook", "test", "some-id"]).unwrap();
    assert!(matches!(cli.command, Command::Webhook { .. }));
}

#[test]
fn parse_webhook_enable() {
    let cli = parse(&["ak", "webhook", "enable", "some-id"]).unwrap();
    assert!(matches!(cli.command, Command::Webhook { .. }));
}

#[test]
fn parse_webhook_disable() {
    let cli = parse(&["ak", "webhook", "disable", "some-id"]).unwrap();
    assert!(matches!(cli.command, Command::Webhook { .. }));
}

#[test]
fn parse_webhook_deliveries() {
    let cli = parse(&["ak", "webhook", "deliveries", "some-id"]).unwrap();
    assert!(matches!(cli.command, Command::Webhook { .. }));
}

#[test]
fn parse_webhook_redeliver() {
    let cli = parse(&["ak", "webhook", "redeliver", "wh-id", "delivery-id"]).unwrap();
    assert!(matches!(cli.command, Command::Webhook { .. }));
}
```

**Step 3: Run tests**

Run: `cargo test --workspace --lib`

**Step 4: Commit**

```bash
git add Cargo.toml src/cli.rs
git commit -m "feat(v0.7): bump version to 0.7.0, add cli parsing tests"
```

---

## Task 6: TUI Replication Status Panel

**Files:**
- Modify: `src/commands/tui.rs`

**Step 1: Add a Replication panel to the TUI**

Add a new panel showing peer status (online/offline/syncing), last sync times, and replication health. Follow the pattern used by the existing Security Findings panel added in v0.6.

This task modifies tui.rs which is excluded from SonarCloud coverage. The panel should:
- Show a table of peers with status, region, last heartbeat, last sync
- Color-code status: green for online, red for offline, yellow for syncing
- Show sync policy summary (count enabled, count disabled)

**Step 2: Build and verify**

Run: `cargo build`

**Step 3: Commit**

```bash
git add src/commands/tui.rs
git commit -m "feat(v0.7): add replication status panel to TUI"
```

---

## Task 7: Final verification and quality checks

**Step 1: Run full test suite**

Run: `cargo test --workspace --lib`
Expected: All tests pass

**Step 2: Run clippy**

Run: `cargo clippy --workspace -- -D warnings -A dead_code`
Expected: No warnings

**Step 3: Run fmt check**

Run: `cargo fmt --check`
Expected: No changes needed

**Step 4: Verify test count increased**

The v0.6 branch had ~935 tests. This should add ~100+ new tests across the three modules.

**Step 5: Commit any remaining fixes**

```bash
git add -A
git commit -m "chore(v0.7): final clippy and fmt cleanup"
```
