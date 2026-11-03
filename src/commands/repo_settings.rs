//! Per-repository settings with routes of their own, and storage accounting:
//! `ak repo allowlist`, `upstream-filter`, `egress-proxy`, `npm-scope-policy`,
//! `capabilities`, `storage` and `storage-gc`.

use artifact_keeper_sdk::ClientRepositoriesExt;
use artifact_keeper_sdk::raw::capture;
use artifact_keeper_sdk::types;
use clap::Subcommand;
use miette::Result;

use super::client::{client_for, client_for_optional_auth};
use super::helpers::{
    confirm_action, emit_mutation_raw, new_table, read_inline_or_file, resolve_secret, sdk_err,
    since_1_11,
};
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
                        return Err(since_1_11(e, "get allowlist", "repo allowlist", global)
                            .await
                            .into());
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
                        return Err(since_1_11(e, "set allowlist", "repo allowlist", global)
                            .await
                            .into());
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
                        return Err(since_1_11(e, "delete allowlist", "repo allowlist", global)
                            .await
                            .into());
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
        resp.scope,
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
                        return Err(since_1_11(
                            e,
                            "get upstream filter",
                            "repo upstream-filter",
                            global,
                        )
                        .await
                        .into());
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
                        return Err(since_1_11(
                            e,
                            "set upstream filter",
                            "repo upstream-filter",
                            global,
                        )
                        .await
                        .into());
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
                        return Err(since_1_11(
                            e,
                            "delete upstream filter",
                            "repo upstream-filter",
                            global,
                        )
                        .await
                        .into());
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
            return Err(since_1_11(
                e,
                "get repository capabilities",
                "repo capabilities",
                global,
            )
            .await
            .into());
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
