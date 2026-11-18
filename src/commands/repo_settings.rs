//! Per-repository settings with routes of their own, and storage accounting:
//! `ak repo allowlist`, `upstream-filter`, `egress-proxy`, `npm-scope-policy`,
//! `capabilities`, `storage` and `storage-gc`, and from 1.12 `proxy-cache-cap`,
//! `on-upstream-not-found`, `stale-if-error-grace`, `upstream-mode`, `cache seed`
//! and `rpm repodata rebuild`.

use artifact_keeper_sdk::ClientRepositoriesExt;
use artifact_keeper_sdk::raw::capture;
use artifact_keeper_sdk::types;
use clap::Subcommand;
use miette::Result;

use super::client::{client_for, client_for_optional_auth};
use super::helpers::{
    Minor, RawFailure, confirm_action, emit_mutation_raw, new_table, or_since,
    raw_json_call_with_query, read_inline_or_file, resolve_secret, sdk_err, since, since_raw,
};
use super::repo::{Polled, one_line, poll_job};
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat, format_bytes, render_raw};

/// The package allowlist of a virtual conda repository.
#[derive(Subcommand)]
pub enum AllowlistCommand {
    /// Show the allowlist
    Get {
        /// Repository key
        key: String,
    },

    /// Replace the allowlist
    Set {
        /// Repository key
        key: String,

        /// Enforce the list (true/false). An enforced empty list admits nothing
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        enabled: bool,

        /// Package to admit, as `name` or `name=version-spec`. The name can be a
        /// glob (repeatable)
        #[arg(long = "package")]
        packages: Vec<String>,

        /// Entries as a JSON array of `{name, version, subdirs}`: text, @file or @-
        #[arg(long)]
        entries: Option<String>,

        /// Which members the list applies to: all_members or remote_only
        #[arg(long, value_parser = ["all_members", "remote_only"])]
        scope: Option<String>,
    },

    /// Remove the allowlist
    Delete {
        /// Repository key
        key: String,

        /// Skip confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

/// Which paths a remote repository may fetch from its upstream.
#[derive(Subcommand)]
pub enum UpstreamFilterCommand {
    /// Show the filter
    Get {
        /// Repository key
        key: String,
    },

    /// Replace the filter
    Set {
        /// Repository key
        key: String,

        /// Fetch only paths matching one of these regexes (repeatable)
        #[arg(long = "include")]
        include: Vec<String>,

        /// Never fetch paths matching this regex. Wins over --include (repeatable)
        #[arg(long = "exclude")]
        exclude: Vec<String>,
    },

    /// Remove the filter
    Delete {
        /// Repository key
        key: String,

        /// Skip confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

/// The outbound proxy a remote repository uses to reach its upstream.
#[derive(Subcommand)]
pub enum EgressProxyCommand {
    /// Show the proxy settings
    Get {
        /// Repository key
        key: String,
    },

    /// Change the proxy settings
    Set {
        /// Repository key
        key: String,

        /// inherit (follow the server's environment), direct or explicit
        #[arg(long, value_parser = ["inherit", "direct", "explicit"])]
        mode: String,

        /// Proxy URL, needed for explicit mode. Prefer --proxy-url-stdin if it
        /// holds credentials
        #[arg(long = "proxy-url")]
        proxy_url: Option<String>,

        /// Read the proxy URL from stdin
        #[arg(long = "proxy-url-stdin", conflicts_with = "proxy_url")]
        proxy_url_stdin: bool,

        /// Comma-separated hosts, domain suffixes or CIDRs that bypass the proxy
        #[arg(long = "no-proxy")]
        no_proxy: Option<String>,
    },
}

/// Which npm names can resolve through a remote repository.
#[derive(Subcommand)]
pub enum NpmScopePolicyCommand {
    /// Show the policy
    Get {
        /// Repository key
        key: String,
    },

    /// Replace the policy
    Set {
        /// Repository key
        key: String,

        /// Allowed @scopes, comma separated ("" for none)
        #[arg(long = "allowed-scopes", value_delimiter = ',', required = true)]
        allowed_scopes: Vec<String>,

        /// Let unscoped names resolve too (true/false)
        #[arg(long = "allow-unscoped")]
        allow_unscoped: Option<bool>,
    },
}

/// The server minor the commands below need.
const V1_12: Minor = (1, 12);

/// The most bytes a remote repository's proxy cache may hold. Needs a 1.12 server.
#[derive(Subcommand)]
pub enum ProxyCacheCapCommand {
    /// Show the cap and what the cache holds now
    Show {
        /// Repository key
        key: String,
    },

    /// Cap the cache. Past the cap, the least recently used entries are evicted
    Set {
        /// Repository key
        key: String,

        /// The cap: bytes, or a size such as 500M or 20G
        cap: String,
    },

    /// Remove the cap
    Clear {
        /// Repository key
        key: String,
    },
}

/// What a remote repository does with its cached copy of a path when the upstream
/// answers 404 or 410 for it. Needs a 1.12 server.
#[derive(Subcommand)]
pub enum OnUpstreamNotFoundCommand {
    /// Show the setting
    Show {
        /// Repository key
        key: String,
    },

    /// Change it: keep goes on serving the cached copy, delete evicts it (the default)
    Set {
        /// Repository key
        key: String,

        /// keep or delete
        #[arg(value_parser = ["keep", "delete"])]
        action: String,
    },
}

/// How long a remote repository may serve a stale cached copy while its upstream
/// can't be reached. Needs a 1.12 server.
#[derive(Subcommand)]
pub enum StaleIfErrorGraceCommand {
    /// Show the grace window in force, and the repository's own override
    Show {
        /// Repository key
        key: String,
    },

    /// Set the repository's grace window
    Set {
        /// Repository key
        key: String,

        /// Seconds, 0 to 2592000 (30 days). 0 never serves a stale copy
        seconds: i64,
    },
}

/// Whether a remote repository may contact its upstream. Needs a 1.12 server.
#[derive(Subcommand)]
pub enum UpstreamModeCommand {
    /// Show the stored mode and the one in force
    Show {
        /// Repository key
        key: String,
    },

    /// Change the mode: online proxies as usual, cache_only serves only what is
    /// already cached
    Set {
        /// Repository key
        key: String,

        /// online or cache_only
        #[arg(value_parser = ["online", "cache_only"])]
        mode: String,
    },
}

/// Fetch a list of paths into a remote repository's proxy cache, as a background
/// job. Needs a 1.12 server.
#[derive(Subcommand)]
pub enum CacheSeedCommand {
    /// Start a seed job
    Start {
        /// Repository key
        key: String,

        /// Path to fetch, relative to the repository (repeatable)
        #[arg(long = "path")]
        paths: Vec<String>,

        /// Paths to fetch, one per line, from a file or `-` for stdin. Blank lines
        /// and `#` comments are skipped
        #[arg(long = "paths-file")]
        paths_file: Option<String>,

        /// Items fetched at once, 1 to 16 (the server's default is 4)
        #[arg(long)]
        concurrency: Option<i32>,

        /// Stop fetching after this many bytes: bytes, or a size such as 2G. The
        /// paths left are reported refused
        #[arg(long = "max-total-bytes")]
        max_total_bytes: Option<String>,

        /// Wait for the job to finish
        #[arg(long)]
        wait: bool,

        /// How long --wait waits, in seconds
        #[arg(long = "wait-timeout", default_value = "1800", requires = "wait")]
        wait_timeout: u64,
    },

    /// Show a seed job and what became of each path
    Status {
        /// Repository key
        key: String,

        /// Job ID, as `cache seed start` printed it
        job_id: uuid::Uuid,

        /// Wait for the job to finish
        #[arg(long)]
        wait: bool,

        /// How long --wait waits, in seconds
        #[arg(long = "wait-timeout", default_value = "1800", requires = "wait")]
        wait_timeout: u64,
    },
}

/// Hosted RPM repositories. Needs a 1.12 server.
#[derive(Subcommand)]
pub enum RpmCommand {
    /// Precomputed repodata
    Repodata {
        #[command(subcommand)]
        command: RpmRepodataCommand,
    },
}

/// Precomputed RPM repodata.
#[derive(Subcommand)]
pub enum RpmRepodataCommand {
    /// Build a metadata root's repodata now, rather than at the builder's next tick
    Rebuild {
        /// Repository key
        key: String,

        /// Metadata root, as in the repository URL (`el9/x86_64` at depth two).
        /// Leave it out at depth zero
        #[arg(long)]
        root: Option<String>,

        /// Return once the root serves a revision with every write made before
        /// this call
        #[arg(long)]
        wait: bool,
    },
}

/// `name` or `name=version-spec`. A conda version spec can hold anything after
/// the first `=`, including `,` and `|`.
fn parse_package(entry: &str) -> types::AllowlistEntry {
    let (name, version) = match entry.split_once('=') {
        Some((name, version)) => (name, Some(version.to_string())),
        None => (entry, None),
    };
    types::AllowlistEntry {
        name: name.to_string(),
        version,
        subdirs: Vec::new(),
    }
}

fn parse_entries(value: Option<&str>) -> Result<Vec<types::AllowlistEntry>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let bytes = read_inline_or_file(value, "--entries")?;
    serde_json::from_slice(&bytes).map_err(|e| AkError::Usage(format!("--entries: {e}")).into())
}

impl AllowlistCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        let client = client_for(global)?;
        match self {
            Self::Get { key } => {
                let (resp, raw) = capture(client.get_conda_allowlist().key(&key).send()).await;
                let resp = match resp {
                    Ok(resp) => resp,
                    Err(e) => {
                        return Err(sdk_err("get allowlist", e).into());
                    }
                };
                println!(
                    "{}",
                    render_raw(
                        raw.as_deref(),
                        &*resp,
                        &global.format,
                        Some(allowlist_table(&resp))
                    )
                );
            }
            Self::Set {
                key,
                enabled,
                packages,
                entries,
                scope,
            } => {
                let mut all = parse_entries(entries.as_deref())?;
                all.extend(packages.iter().map(|p| parse_package(p)));
                let scope = scope
                    .map(|s| {
                        s.parse::<types::AllowlistScope>()
                            .map_err(|e| AkError::Usage(format!("Invalid --scope: {e}")))
                    })
                    .transpose()?;
                let body = types::CondaAllowlist {
                    enabled,
                    entries: all,
                    scope,
                };
                let (resp, raw) =
                    capture(client.set_conda_allowlist().key(&key).body(body).send()).await;
                let resp = match resp {
                    Ok(resp) => resp,
                    Err(e) => {
                        return Err(sdk_err("set allowlist", e).into());
                    }
                };
                emit_mutation_raw(
                    raw.as_deref(),
                    &*resp,
                    &resp.repository_key,
                    &format!(
                        "Set the allowlist of '{}': {} entries, enforced: {}.",
                        resp.repository_key, resp.entry_count, resp.enabled
                    ),
                    global,
                );
            }
            Self::Delete { key, yes } => {
                if !confirm_action(
                    &format!("Remove the allowlist of '{key}'?"),
                    yes,
                    global.no_input,
                )? {
                    return Ok(());
                }
                let (resp, raw) = capture(client.delete_conda_allowlist().key(&key).send()).await;
                let resp = match resp {
                    Ok(resp) => resp,
                    Err(e) => {
                        return Err(sdk_err("delete allowlist", e).into());
                    }
                };
                emit_mutation_raw(
                    raw.as_deref(),
                    &*resp,
                    &resp.repository_key,
                    &format!("Removed the allowlist of '{}'.", resp.repository_key),
                    global,
                );
            }
        }
        Ok(())
    }
}

fn allowlist_table(resp: &types::CondaAllowlistResponse) -> String {
    let mut table = new_table(vec!["NAME", "VERSION", "SUBDIRS"]);
    for entry in &resp.entries {
        table.add_row(vec![
            entry.name.clone(),
            entry.version.clone().unwrap_or_else(|| "-".into()),
            if entry.subdirs.is_empty() {
                "-".to_string()
            } else {
                entry.subdirs.join(", ")
            },
        ]);
    }
    let mut text = format!(
        "Repository: {}\nEnforced:   {}\nScope:      {}\nEntries:    {}\n",
        resp.repository_key,
        yes_no(resp.enabled),
        resp.scope
            .map_or_else(|| "-".to_string(), |scope| scope.to_string()),
        resp.entry_count
    );
    if let Some(error) = &resp.error {
        text.push_str(&format!("Error:      {error}\n"));
    }
    if !resp.entries.is_empty() {
        text.push_str(&table.to_string());
    }
    text.trim_end().to_string()
}

impl UpstreamFilterCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        let client = client_for(global)?;
        match self {
            Self::Get { key } => {
                let (resp, raw) = capture(client.get_upstream_filter().key(&key).send()).await;
                let resp = match resp {
                    Ok(resp) => resp,
                    Err(e) => {
                        return Err(sdk_err("get upstream filter", e).into());
                    }
                };
                println!(
                    "{}",
                    render_raw(
                        raw.as_deref(),
                        &*resp,
                        &global.format,
                        Some(upstream_filter_text(&resp))
                    )
                );
            }
            Self::Set {
                key,
                include,
                exclude,
            } => {
                let body = types::UpstreamFilter {
                    include_patterns: include,
                    exclude_patterns: exclude,
                };
                let (resp, raw) =
                    capture(client.set_upstream_filter().key(&key).body(body).send()).await;
                let resp = match resp {
                    Ok(resp) => resp,
                    Err(e) => {
                        return Err(sdk_err("set upstream filter", e).into());
                    }
                };
                emit_mutation_raw(
                    raw.as_deref(),
                    &*resp,
                    &resp.repository_key,
                    &format!("Set the upstream filter of '{}'.", resp.repository_key),
                    global,
                );
            }
            Self::Delete { key, yes } => {
                if !confirm_action(
                    &format!("Remove the upstream filter of '{key}'?"),
                    yes,
                    global.no_input,
                )? {
                    return Ok(());
                }
                let (resp, raw) = capture(client.delete_upstream_filter().key(&key).send()).await;
                let resp = match resp {
                    Ok(resp) => resp,
                    Err(e) => {
                        return Err(sdk_err("delete upstream filter", e).into());
                    }
                };
                emit_mutation_raw(
                    raw.as_deref(),
                    &*resp,
                    &resp.repository_key,
                    &format!("Removed the upstream filter of '{}'.", resp.repository_key),
                    global,
                );
            }
        }
        Ok(())
    }
}

fn upstream_filter_text(resp: &types::UpstreamFilterResponse) -> String {
    let mut text = format!(
        "Repository: {}\nActive:     {}\nInclude:    {}\nExclude:    {}",
        resp.repository_key,
        yes_no(resp.active),
        joined_or_dash(&resp.include_patterns),
        joined_or_dash(&resp.exclude_patterns),
    );
    if let Some(error) = &resp.error {
        text.push_str(&format!("\nError:      {error}"));
    }
    text
}

impl EgressProxyCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Get { key } => {
                let client = client_for(global)?;
                let (resp, raw) = capture(client.get_egress_proxy().key(&key).send()).await;
                let resp = resp.map_err(|e| sdk_err("get egress proxy", e))?;
                println!(
                    "{}",
                    render_raw(
                        raw.as_deref(),
                        &*resp,
                        &global.format,
                        Some(egress_proxy_text(&resp))
                    )
                );
            }
            Self::Set {
                key,
                mode,
                proxy_url,
                proxy_url_stdin,
                no_proxy,
            } => {
                if proxy_url.as_deref().is_some_and(|url| url.contains('@')) {
                    eprintln!(
                        "warning: a URL with credentials on the command line ends up in shell \
                         history and process listings; prefer --proxy-url-stdin"
                    );
                }
                let proxy_url = if proxy_url_stdin {
                    resolve_secret(None, true, "--proxy-url", None, global.no_input)?
                } else {
                    proxy_url
                };
                let client = client_for(global)?;
                let body = types::EgressProxyRequest {
                    mode,
                    proxy_url,
                    no_proxy,
                };
                let (resp, raw) =
                    capture(client.set_egress_proxy().key(&key).body(body).send()).await;
                let resp = resp.map_err(|e| sdk_err("set egress proxy", e))?;
                emit_mutation_raw(
                    raw.as_deref(),
                    &*resp,
                    &key,
                    &format!("Set the egress proxy of '{key}' to {}.", resp.mode),
                    global,
                );
            }
        }
        Ok(())
    }
}

fn egress_proxy_text(resp: &types::EgressProxyResponse) -> String {
    format!(
        "Mode:        {}\nProxy URL:   {}\nCredentials: {}\nNo proxy:    {}",
        resp.mode,
        resp.proxy_url.as_deref().unwrap_or("-"),
        yes_no(resp.proxy_credentials_configured),
        resp.no_proxy.as_deref().unwrap_or("-"),
    )
}

impl NpmScopePolicyCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        let client = client_for(global)?;
        match self {
            Self::Get { key } => {
                let (resp, raw) = capture(client.get_npm_scope_policy().key(&key).send()).await;
                let resp = resp.map_err(|e| sdk_err("get npm scope policy", e))?;
                println!(
                    "{}",
                    render_raw(
                        raw.as_deref(),
                        &*resp,
                        &global.format,
                        Some(npm_policy_text(&resp))
                    )
                );
            }
            Self::Set {
                key,
                allowed_scopes,
                allow_unscoped,
            } => {
                let body = types::SetNpmScopePolicyRequest {
                    allowed_scopes: allowed_scopes
                        .into_iter()
                        .filter(|s| !s.is_empty())
                        .collect(),
                    allow_unscoped,
                };
                let (resp, raw) =
                    capture(client.set_npm_scope_policy().key(&key).body(body).send()).await;
                let resp = resp.map_err(|e| sdk_err("set npm scope policy", e))?;
                emit_mutation_raw(
                    raw.as_deref(),
                    &*resp,
                    &resp.repository_key,
                    &format!("Set the npm scope policy of '{}'.", resp.repository_key),
                    global,
                );
            }
        }
        Ok(())
    }
}

fn npm_policy_text(resp: &types::NpmScopePolicyResponse) -> String {
    format!(
        "Repository:     {}\nActive:         {}\nAllowed scopes: {}\nAllow unscoped: {}",
        resp.repository_key,
        yes_no(resp.active),
        joined_or_dash(&resp.allowed_scopes),
        yes_no(resp.allow_unscoped),
    )
}

/// `ak repo capabilities`
pub async fn capabilities(global: &GlobalArgs) -> Result<()> {
    let client = client_for_optional_auth(global)?;
    let (resp, raw) = capture(client.repository_capabilities().send()).await;
    let resp = match resp {
        Ok(resp) => resp,
        Err(e) => {
            return Err(sdk_err("get repository capabilities", e).into());
        }
    };
    let depth = &resp.rpm_repodata_depth;
    let text = format!(
        "RPM repodata depth: {} (min {}, max {}, default {})",
        if depth.supported {
            "supported"
        } else {
            "not supported"
        },
        depth.min,
        depth.max,
        depth.default
    );
    println!(
        "{}",
        render_raw(raw.as_deref(), &*resp, &global.format, Some(text))
    );
    Ok(())
}

/// `ak repo storage <key>`
pub async fn storage(key: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let (resp, raw) = capture(client.get_repository_storage().key(key).send()).await;
    let resp = resp.map_err(|e| sdk_err("get repository storage", e))?;
    let bytes = |value: Option<i64>| value.map_or_else(|| "-".to_string(), format_bytes);
    let text = format!(
        "Repository:      {}\nLogical:         {}\nPhysical:        {}\nUnique:          {}\n\
         Shared:          {}\nInstance unique: {}\nBlobs:           {}\nDedup ratio:     {}\n\
         Dedup scope:     {}\nComputed:        {}",
        resp.repository_key,
        format_bytes(resp.logical_bytes),
        bytes(resp.physical_bytes),
        bytes(resp.unique_bytes),
        bytes(resp.shared_bytes),
        bytes(resp.instance_unique_bytes),
        resp.blob_count,
        resp.dedup_ratio
            .map_or_else(|| "-".to_string(), |r| format!("{r:.2}")),
        resp.dedup_scope,
        resp.computed_at
            .map_or_else(|| "not yet".to_string(), |t| t.to_rfc3339()),
    );
    println!(
        "{}",
        render_raw(raw.as_deref(), &*resp, &global.format, Some(text))
    );
    Ok(())
}

/// `ak repo storage <key> --tree`
pub async fn storage_tree(
    key: &str,
    prefix: Option<&str>,
    depth: Option<i32>,
    limit: Option<i64>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let mut req = client.get_repository_storage_tree().key(key);
    if let Some(prefix) = prefix {
        req = req.prefix(prefix);
    }
    if let Some(depth) = depth {
        req = req.depth(depth);
    }
    if let Some(limit) = limit {
        req = req.limit(limit);
    }
    let (resp, raw) = capture(req.send()).await;
    let resp = resp.map_err(|e| sdk_err("get repository storage tree", e))?;

    if matches!(global.format, OutputFormat::Quiet) {
        for node in &resp.children {
            println!("{}", output::sanitize_terminal(&node.prefix));
        }
        return Ok(());
    }

    let mut table = new_table(vec!["PREFIX", "LOGICAL", "PHYSICAL", "FILES", "BLOBS"]);
    for node in std::iter::once(&resp.node).chain(&resp.children) {
        table.add_row(vec![
            if node.prefix.is_empty() {
                "/".to_string()
            } else {
                node.prefix.clone()
            },
            format_bytes(node.logical_bytes),
            format_bytes(node.physical_bytes),
            node.file_count.to_string(),
            node.blob_count.to_string(),
        ]);
    }
    let mut text = table.to_string();
    if resp.truncated {
        text.push_str("\nTruncated: raise --limit to see more.");
    }
    println!(
        "{}",
        render_raw(raw.as_deref(), &*resp, &global.format, Some(text))
    );
    Ok(())
}

/// `ak repo storage-gc <key>`
pub async fn storage_gc(key: &str, dry_run: bool, yes: bool, global: &GlobalArgs) -> Result<()> {
    if !dry_run
        && !confirm_action(
            &format!("Delete unreferenced storage objects of '{key}'? This cannot be undone"),
            yes,
            global.no_input,
        )?
    {
        return Ok(());
    }
    let client = client_for(global)?;
    let spinner = output::spinner("Running storage GC...");
    let (resp, raw) = capture(
        client
            .run_repository_storage_gc()
            .key(key)
            .body(types::StorageGcRequest { dry_run })
            .send(),
    )
    .await;
    spinner.finish_and_clear();
    let resp = resp.map_err(|e| sdk_err("run storage GC", e))?;

    let verb = if resp.dry_run {
        "Would delete"
    } else {
        "Deleted"
    };
    let mut human = format!(
        "{verb} {} storage keys and {} artifacts, freeing {}.",
        resp.storage_keys_deleted,
        resp.artifacts_removed,
        format_bytes(resp.bytes_freed)
    );
    for error in &resp.errors {
        human.push_str(&format!("\nError: {}", output::sanitize_terminal(error)));
    }
    emit_mutation_raw(raw.as_deref(), &*resp, key, &human, global);
    super::helpers::fail_on_errors("Storage GC", &resp.errors)
}

/// A setting as its route answered: shown as read, or reported as changed.
fn emit_setting<T: serde::Serialize>(
    raw: Option<&[u8]>,
    resp: &T,
    key: &str,
    changed: Option<String>,
    text: String,
    global: &GlobalArgs,
) {
    match changed {
        None => println!("{}", render_raw(raw, resp, &global.format, Some(text))),
        Some(human) => emit_mutation_raw(raw, resp, key, &human, global),
    }
}

/// A size flag in bytes, as the API takes it.
fn size_flag(value: &str, flag: &str) -> Result<i64> {
    let bytes = super::chunked_upload::parse_size(value)?;
    i64::try_from(bytes).map_err(|_| AkError::Usage(format!("{flag}: {value} is too big")).into())
}

impl ProxyCacheCapCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        let client = client_for(global)?;
        let (key, command, changed, (resp, raw)) = match self {
            Self::Show { key } => {
                let sent = capture(client.get_proxy_cache_cap().key(&key).send()).await;
                (key, "repo proxy-cache-cap show", None, sent)
            }
            Self::Set { key, cap } => {
                let body = types::SetProxyCacheCapRequest {
                    cap_bytes: size_flag(&cap, "the cap")?,
                };
                let sent = capture(client.set_proxy_cache_cap().key(&key).body(body).send()).await;
                (key, "repo proxy-cache-cap set", Some("Capped"), sent)
            }
            Self::Clear { key } => {
                let sent = capture(client.delete_proxy_cache_cap().key(&key).send()).await;
                (
                    key,
                    "repo proxy-cache-cap clear",
                    Some("Removed the cap of"),
                    sent,
                )
            }
        };
        let resp = or_since(V1_12, resp, "reach the proxy cache cap", command, global).await?;
        let changed = changed.map(|verb| match (verb, resp.cap_bytes) {
            ("Capped", Some(cap)) => format!(
                "Capped the proxy cache of '{key}' at {}.",
                format_bytes(cap)
            ),
            (verb, _) => format!("{verb} the proxy cache of '{key}'."),
        });
        let text = format!(
            "Repository:     {}\nCap:            {}\nAt cap:         {}\nUsage:          {} in \
             {} entries\nRefusing fills: {}",
            resp.repository_key,
            resp.cap_bytes
                .map_or_else(|| "none".to_string(), format_bytes),
            resp.at_cap,
            format_bytes(resp.usage.bytes),
            resp.usage.entries,
            yes_no(resp.refusing_fills),
        );
        emit_setting(raw.as_deref(), &*resp, &key, changed, text, global);
        Ok(())
    }
}

impl OnUpstreamNotFoundCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        let client = client_for(global)?;
        let (key, command, changed, (resp, raw)) = match self {
            Self::Show { key } => {
                let sent = capture(client.get_on_upstream_not_found().key(&key).send()).await;
                (key, "repo on-upstream-not-found show", false, sent)
            }
            Self::Set { key, action } => {
                let body = types::SetOnUpstreamNotFoundRequest {
                    on_upstream_not_found: action
                        .parse()
                        .map_err(|e| AkError::Usage(format!("Invalid action: {e}")))?,
                };
                let sent = capture(
                    client
                        .set_on_upstream_not_found()
                        .key(&key)
                        .body(body)
                        .send(),
                )
                .await;
                (key, "repo on-upstream-not-found set", true, sent)
            }
        };
        let resp = or_since(
            V1_12,
            resp,
            "reach the upstream-not-found setting",
            command,
            global,
        )
        .await?;
        let changed = changed.then(|| {
            format!(
                "Set what '{key}' does when the upstream no longer has a cached path: {}.",
                resp.on_upstream_not_found
            )
        });
        let text = format!(
            "Repository:            {}\nOn upstream not found: {}",
            resp.repository_key, resp.on_upstream_not_found
        );
        emit_setting(raw.as_deref(), &*resp, &key, changed, text, global);
        Ok(())
    }
}

impl StaleIfErrorGraceCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        let client = client_for(global)?;
        let (key, command, changed, (resp, raw)) = match self {
            Self::Show { key } => {
                let sent = capture(client.get_stale_if_error_grace().key(&key).send()).await;
                (key, "repo stale-if-error-grace show", false, sent)
            }
            Self::Set { key, seconds } => {
                let body = types::SetStaleIfErrorGraceRequest {
                    stale_if_error_grace_seconds: seconds,
                };
                let sent = capture(
                    client
                        .set_stale_if_error_grace()
                        .key(&key)
                        .body(body)
                        .send(),
                )
                .await;
                (key, "repo stale-if-error-grace set", true, sent)
            }
        };
        let resp = or_since(
            V1_12,
            resp,
            "reach the stale-if-error grace",
            command,
            global,
        )
        .await?;
        let changed = changed.then(|| {
            format!(
                "Set the stale-if-error grace of '{key}' to {}s.",
                resp.stale_if_error_grace_seconds
            )
        });
        let text = format!(
            "Repository:        {}\nGrace:             {}s\nOverride:          {}\nLast stale \
             served: {}",
            resp.repository_key,
            resp.stale_if_error_grace_seconds,
            resp.override_seconds.map_or_else(
                || "none, the instance default".to_string(),
                |s| format!("{s}s")
            ),
            resp.last_stale_served_at
                .map_or_else(|| "-".to_string(), |t| t.to_rfc3339()),
        );
        emit_setting(raw.as_deref(), &*resp, &key, changed, text, global);
        Ok(())
    }
}

impl UpstreamModeCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        let client = client_for(global)?;
        let (key, command, changed, (resp, raw)) = match self {
            Self::Show { key } => {
                let sent = capture(client.get_upstream_mode().key(&key).send()).await;
                (key, "repo upstream-mode show", false, sent)
            }
            Self::Set { key, mode } => {
                let body = types::SetUpstreamModeRequest {
                    upstream_mode: mode
                        .parse()
                        .map_err(|e| AkError::Usage(format!("Invalid mode: {e}")))?,
                };
                let sent = capture(client.set_upstream_mode().key(&key).body(body).send()).await;
                (key, "repo upstream-mode set", true, sent)
            }
        };
        let resp = or_since(V1_12, resp, "reach the upstream mode", command, global).await?;
        let mut changed = changed.then(|| {
            format!(
                "Set the upstream mode of '{key}' to {}.",
                resp.upstream_mode
            )
        });
        if resp.effective_upstream_mode != resp.upstream_mode {
            let note = format!(
                " The instance forces {} on every repository.",
                resp.effective_upstream_mode
            );
            if let Some(changed) = changed.as_mut() {
                changed.push_str(&note);
            }
        }
        let text = format!(
            "Repository:    {}\nUpstream mode: {}\nIn force:      {}",
            resp.repository_key, resp.upstream_mode, resp.effective_upstream_mode
        );
        emit_setting(raw.as_deref(), &*resp, &key, changed, text, global);
        Ok(())
    }
}

impl CacheSeedCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Start {
                key,
                paths,
                paths_file,
                concurrency,
                max_total_bytes,
                wait,
                wait_timeout,
            } => {
                let paths = seed_paths(paths, paths_file.as_deref())?;
                let max_total_bytes = max_total_bytes
                    .map(|v| size_flag(&v, "--max-total-bytes"))
                    .transpose()?;
                seed_start(
                    &key,
                    &paths,
                    concurrency,
                    max_total_bytes,
                    wait.then_some(wait_timeout),
                    global,
                )
                .await
            }
            Self::Status {
                key,
                job_id,
                wait,
                wait_timeout,
            } => {
                let (job, raw) = if wait {
                    let bytes = wait_for_seed(&key, job_id, wait_timeout, global).await?;
                    let job = serde_json::from_slice::<types::CacheSeedJobResponse>(&bytes)
                        .map_err(|e| AkError::ServerError(format!("Invalid seed job: {e}")))?;
                    (job, Some(bytes))
                } else {
                    let client = client_for(global)?;
                    let (resp, raw) =
                        capture(client.get_cache_seed().key(&key).job_id(job_id).send()).await;
                    let resp = or_since(
                        V1_12,
                        resp,
                        "get the cache seed job",
                        "repo cache seed status",
                        global,
                    )
                    .await?;
                    (resp.into_inner(), raw)
                };
                print_seed_job(&job, raw.as_deref(), global);
                seed_outcome(&job, wait)
            }
        }
    }
}

/// The paths of `--path` and `--paths-file`, in that order.
fn seed_paths(mut paths: Vec<String>, file: Option<&str>) -> Result<Vec<String>> {
    if let Some(file) = file {
        let bytes = if file == "-" {
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut std::io::stdin(), &mut bytes)
                .map_err(|e| AkError::Usage(format!("--paths-file: can't read stdin: {e}")))?;
            bytes
        } else {
            std::fs::read(file)
                .map_err(|e| AkError::Usage(format!("--paths-file: can't read {file}: {e}")))?
        };
        let text = String::from_utf8(bytes)
            .map_err(|_| AkError::Usage("--paths-file: the list isn't text".into()))?;
        paths.extend(
            text.lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .map(str::to_string),
        );
    }
    if paths.is_empty() {
        return Err(
            AkError::Usage("Give the paths to fetch with --path or --paths-file".into()).into(),
        );
    }
    Ok(paths)
}

/// `ak repo cache seed start`. The body goes over raw HTTP: the spec calls
/// `content` an object, and the server takes a list of paths.
async fn seed_start(
    key: &str,
    paths: &[String],
    concurrency: Option<i32>,
    max_total_bytes: Option<i64>,
    wait_secs: Option<u64>,
    global: &GlobalArgs,
) -> Result<()> {
    let mut options = serde_json::Map::new();
    if let Some(concurrency) = concurrency {
        options.insert("concurrency".into(), concurrency.into());
    }
    if let Some(max) = max_total_bytes {
        options.insert("max_total_bytes".into(), max.into());
    }
    let mut body = serde_json::json!({ "kind": "paths", "content": paths });
    if !options.is_empty() {
        body["options"] = serde_json::Value::Object(options);
    }
    let sent = raw_json_call_with_query(
        reqwest::Method::POST,
        &["repositories", key, "cache", "seed"],
        &[],
        Some(&body),
        "start a cache seed",
        global,
    )
    .await;
    let bytes = match sent {
        Ok(bytes) => bytes,
        Err(RawFailure::Status(status, text)) => {
            return Err(since_raw(
                V1_12,
                status,
                &text,
                "Failed to start a cache seed",
                "repo cache seed start",
                global,
            )
            .await
            .into());
        }
        Err(RawFailure::Other(report)) => return Err(report),
    };
    let accepted: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
    let Some(job_id) = accepted["job_id"]
        .as_str()
        .and_then(|id| id.parse::<uuid::Uuid>().ok())
    else {
        return Err(AkError::ServerError(format!(
            "The server took the seed of '{key}' but gave no job ID"
        ))
        .into());
    };

    let Some(timeout) = wait_secs else {
        let total = accepted["total_items"]
            .as_i64()
            .unwrap_or(paths.len() as i64);
        emit_mutation_raw(
            Some(&bytes),
            &accepted,
            &job_id.to_string(),
            &format!(
                "Seeding {total} paths into '{key}' in the background (job {job_id}). Check it \
                 with: ak repo cache seed status {key} {job_id}"
            ),
            global,
        );
        return Ok(());
    };

    let bytes = wait_for_seed(key, job_id, timeout, global).await?;
    let job = serde_json::from_slice::<types::CacheSeedJobResponse>(&bytes)
        .map_err(|e| AkError::ServerError(format!("Invalid seed job: {e}")))?;
    print_seed_job(&job, Some(&bytes), global);
    seed_outcome(&job, true)
}

/// Follow a seed job until it's `completed` or `failed`, returning its last body.
async fn wait_for_seed(
    key: &str,
    job_id: uuid::Uuid,
    timeout_secs: u64,
    global: &GlobalArgs,
) -> Result<Vec<u8>> {
    let client = client_for(global)?;
    poll_job(
        &format!("Seeding '{key}'..."),
        &format!("seed job {job_id} for '{key}'"),
        &format!("ak repo cache seed status {key} {job_id}"),
        timeout_secs,
        || async {
            let (result, raw) =
                capture(client.get_cache_seed().key(key).job_id(job_id).send()).await;
            let bytes = match result {
                Ok(_) => raw,
                Err(e) if e.status().is_some_and(|s| s.is_client_error()) => {
                    return Err(since(
                        V1_12,
                        e,
                        &format!("follow seed job {job_id}"),
                        "repo cache seed status",
                        global,
                    )
                    .await
                    .into());
                }
                Err(_) => None,
            };
            let Some(bytes) = bytes else {
                return Ok(Polled::Unreadable);
            };
            let job: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
            Ok(match job["status"].as_str() {
                Some("completed" | "failed") => Polled::Done(bytes),
                _ => Polled::Running,
            })
        },
    )
    .await
}

fn print_seed_job(job: &types::CacheSeedJobResponse, raw: Option<&[u8]>, global: &GlobalArgs) {
    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", job.status);
        return;
    }
    let summary = &job.summary;
    let mut text = format!(
        "Job:        {}\nRepository: {}\nStatus:     {}\nPaths:      {} (cached {}, already \
         cached {}, refused {}, failed {}, pending {})\nFetched:    {}",
        job.job_id,
        job.repository_key,
        job.status,
        job.total_items,
        summary.cached,
        summary.already_cached,
        summary.refused,
        summary.failed,
        summary.pending,
        format_bytes(summary.cached_bytes),
    );
    if let Some(error) = &job.error_summary {
        text.push_str(&format!("\nError:      {}", one_line(error)));
    }
    let unfinished: Vec<_> = job
        .items
        .iter()
        .filter(|item| matches!(item.state.as_str(), "refused" | "failed"))
        .collect();
    if !unfinished.is_empty() {
        let mut table = new_table(vec!["PATH", "STATE", "STATUS", "REASON"]);
        for item in unfinished {
            table.add_row(vec![
                item.path.clone(),
                item.state.clone(),
                item.status
                    .map_or_else(|| "-".to_string(), |s| s.to_string()),
                item.reason
                    .as_deref()
                    .map_or_else(|| "-".to_string(), one_line),
            ]);
        }
        text.push('\n');
        text.push_str(&table.to_string());
    }
    println!("{}", render_raw(raw, job, &global.format, Some(text)));
}

/// A job that `--wait` followed to its end fails the command if it failed, or if any
/// path couldn't be fetched. A refused path is a gate saying no, which isn't an error.
fn seed_outcome(job: &types::CacheSeedJobResponse, waited: bool) -> Result<()> {
    if job.status == "failed" {
        let reason = job.error_summary.as_deref().unwrap_or("no reason given");
        return Err(AkError::ReportedFailure(format!(
            "Seed job {} for '{}' failed: {}",
            job.job_id,
            job.repository_key,
            one_line(reason)
        ))
        .into());
    }
    if !waited {
        return Ok(());
    }
    let failed: Vec<String> = job
        .items
        .iter()
        .filter(|item| item.state == "failed")
        .map(|item| {
            let reason = item.reason.as_deref().map(one_line).unwrap_or_default();
            format!("{}: {reason}", output::sanitize_terminal(&item.path))
        })
        .collect();
    super::helpers::fail_on_errors("The seed", &failed)
}

impl RpmCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Repodata {
                command: RpmRepodataCommand::Rebuild { key, root, wait },
            } => {
                let client = client_for(global)?;
                let mut req = client.rebuild_repodata().key(&key);
                if let Some(root) = &root {
                    req = req.root(root);
                }
                if wait {
                    req = req.wait(true);
                }
                let spinner = wait.then(|| output::spinner("Building repodata..."));
                let (resp, raw) = capture(req.send()).await;
                if let Some(spinner) = spinner {
                    spinner.finish_and_clear();
                }
                let resp = or_since(
                    V1_12,
                    resp,
                    "rebuild repodata",
                    "repo rpm repodata rebuild",
                    global,
                )
                .await?;
                let root = if resp.root.is_empty() {
                    "the repository root".to_string()
                } else {
                    format!("root '{}'", resp.root)
                };
                let human = match resp.status {
                    types::RebuildStatus::Built => format!(
                        "Built the repodata of {root} in '{key}': revision {}, {} packages.",
                        resp.revision
                            .map_or_else(|| "-".to_string(), |r| r.to_string()),
                        resp.packages
                            .map_or_else(|| "-".to_string(), |p| p.to_string()),
                    ),
                    types::RebuildStatus::Empty => {
                        format!("{root} in '{key}' has no packages, so there's nothing to build.")
                    }
                    types::RebuildStatus::Queued => format!(
                        "Asked for a build of {root} in '{key}'. The builder runs it at its next \
                         tick; --wait waits for it."
                    ),
                };
                emit_mutation_raw(raw.as_deref(), &*resp, &key, &human, global);
                Ok(())
            }
        }
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn joined_or_dash(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        values.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_package_spec_keeps_everything_after_the_first_equals() {
        let plain = parse_package("numpy");
        assert_eq!(plain.name, "numpy");
        assert!(plain.version.is_none());

        let spec = parse_package("numpy=>=2,<3|1.0");
        assert_eq!(spec.name, "numpy");
        assert_eq!(spec.version.as_deref(), Some(">=2,<3|1.0"));
    }

    #[test]
    fn entries_must_be_a_list_of_entries() {
        assert!(parse_entries(Some(r#"[{"name":"a","subdirs":["noarch"]}]"#)).is_ok());
        assert!(parse_entries(Some(r#"{"name":"a"}"#)).is_err());
        assert!(parse_entries(None).unwrap().is_empty());
    }
}
