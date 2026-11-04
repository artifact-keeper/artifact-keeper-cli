//! `ak agent plugins`: publish a plugin bundle to an Agent Plugins repository, and
//! install it where each agent looks for plugins.
//!
//! Claude Code reads the repository's marketplace itself. Cursor, Codex and Copilot
//! take only a local directory, so this unpacks the bundle into each one's place,
//! records what it put there in `.ak/plugin-info.json`, and tells the agent.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use clap::Subcommand;
use miette::{IntoDiagnostic, Result};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::bundle;
use super::harness::{self, Harness, Installed, Location, PluginInfo, Step, UpdateStatus};
use crate::cli::GlobalArgs;
use crate::commands::helpers::{emit_mutation, emit_mutation_raw, network_err, new_table, raw_err};
use crate::commands::pkg::wire::Wire;
use crate::error::AkError;
use crate::output::{self, OutputFormat};

pub const AFTER_HELP: &str = "\
Claude Code can also read a repository directly:
  claude plugin marketplace add <instance>/agentplugins/<repo>/claude-marketplace.json

Examples:
  ak agent plugins publish ./deploy-tools --repo plugins
  ak agent plugins install deploy-tools --repo plugins --harness claude,cursor
  ak agent plugins list --check-updates
  ak agent plugins update --all
  ak agent plugins search deploy --repo plugins --harness codex";

#[derive(Subcommand)]
pub enum PluginsCommand {
    /// Zip a plugin directory and publish it as one version
    #[command(after_help = "\
The directory is the plugin root. Its manifests are found as the server finds them:
.claude-plugin/plugin.json, a plugin.json with an agent-plugins.org $schema,
.cursor-plugin/plugin.json, .codex-plugin/plugin.json and gemini-extension.json. The
name is --name or the first manifest's name, and the version is --version, the first
manifest's version, or 1.0.0. With --version, each manifest's version is set to it in
the upload. The directory itself isn't changed. A published version can't be replaced.

Examples:
  ak agent plugins publish ./deploy-tools --repo plugins
  ak agent plugins publish . --repo plugins --version 1.3.0
  ak agent plugins publish . --repo plugins --dry-run")]
    Publish {
        /// The plugin's directory
        dir: PathBuf,
        /// Repository key of an Agent Plugins repository
        #[arg(long)]
        repo: String,
        /// The plugin's name, when no manifest has one
        #[arg(long)]
        name: Option<String>,
        /// The version to publish, set in every manifest that has one
        #[arg(long)]
        version: Option<String>,
        /// List what would be uploaded, and send nothing
        #[arg(long)]
        dry_run: bool,
    },
    /// Download a plugin and install it for one or more agents
    #[command(after_help = "\
Where each agent gets it:
  claude  ~/.claude/plugins/local/ak/<repo>/<slug>, in the marketplace ak-<repo>
  cursor  ~/.cursor/plugins/local/<slug>
  codex   ~/.agents/plugins/local/ak/<repo>/<slug>, in the marketplace ak-<repo>
  vscode  ~/.copilot/installed-plugins/ak-<repo>/<slug>

When the agent's CLI (claude, codex, copilot) is on PATH, this runs the commands that
load the plugin. Otherwise it prints them. --path installs to <path>/<slug> and runs
nothing.

Examples:
  ak agent plugins install deploy-tools --repo plugins --harness claude
  ak agent plugins install deploy-tools --repo plugins --harness cursor,codex --version 1.2.0
  ak agent plugins install deploy-tools --repo plugins --harness claude --path ./vendor")]
    Install {
        /// The plugin's name
        slug: String,
        /// Repository key of an Agent Plugins repository
        #[arg(long)]
        repo: String,
        /// The agents to install for, separated by commas
        #[arg(long, value_enum, value_delimiter = ',', required = true)]
        harness: Vec<Harness>,
        /// `latest`, or an exact version
        #[arg(long, default_value = "latest")]
        version: String,
        /// Install to <path>/<slug>, and leave the agent alone
        #[arg(long)]
        path: Option<PathBuf>,
    },
    /// List the plugins ak installed
    #[command(after_help = "\
--check-updates asks the server each plugin came from for its newest version, and says
whether the install is current, behind, ahead or unknown.

Examples:
  ak agent plugins list
  ak agent plugins list --harness claude --check-updates")]
    List {
        /// Only these agents, separated by commas. Without it, every agent
        #[arg(long, value_enum, value_delimiter = ',')]
        harness: Vec<Harness>,
        /// Look in <path> rather than the agents' own places
        #[arg(long)]
        path: Option<PathBuf>,
        /// Compare each install with the newest version on the server
        #[arg(long)]
        check_updates: bool,
    },
    /// Install the newest version of a plugin where it's behind
    #[command(after_help = "\
Examples:
  ak agent plugins update deploy-tools
  ak agent plugins update --all --harness cursor")]
    Update {
        /// The plugin's name
        #[arg(required_unless_present = "all", conflicts_with = "all")]
        slug: Option<String>,
        /// Every plugin ak installed
        #[arg(long)]
        all: bool,
        /// Only these agents, separated by commas. Without it, every agent
        #[arg(long, value_enum, value_delimiter = ',')]
        harness: Vec<Harness>,
        /// Look in <path> rather than the agents' own places
        #[arg(long)]
        path: Option<PathBuf>,
    },
    /// Remove a plugin ak installed, and its entry in ak's marketplace
    #[command(after_help = "\
Examples:
  ak agent plugins uninstall deploy-tools --harness claude
  ak agent plugins uninstall deploy-tools --path ./vendor")]
    Uninstall {
        /// The plugin's name
        slug: String,
        /// Only these agents, separated by commas. Without it, every agent
        #[arg(long, value_enum, value_delimiter = ',')]
        harness: Vec<Harness>,
        /// Only the install from this repository
        #[arg(long)]
        repo: Option<String>,
        /// Look in <path> rather than the agents' own places
        #[arg(long)]
        path: Option<PathBuf>,
    },
    /// Find plugins in a repository by name, description or keyword
    #[command(after_help = "\
Examples:
  ak agent plugins search deploy --repo plugins
  ak agent plugins search --repo plugins --harness cursor")]
    Search {
        /// Text to look for. Without it, every plugin
        query: Option<String>,
        /// Repository key of an Agent Plugins repository
        #[arg(long)]
        repo: String,
        /// Only plugins meant for this agent
        #[arg(long, value_enum)]
        harness: Option<Harness>,
    },
    /// Delete one published version
    #[command(after_help = "\
The repository's marketplaces stop listing it at once. Installs aren't touched.

Examples:
  ak agent plugins delete deploy-tools --version 1.2.0 --repo plugins --yes")]
    Delete {
        /// The plugin's name
        slug: String,
        /// The version to delete
        #[arg(long)]
        version: String,
        /// Repository key
        #[arg(long)]
        repo: String,
        /// Skip confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

pub async fn execute(command: PluginsCommand, global: &GlobalArgs) -> Result<()> {
    match command {
        PluginsCommand::Publish {
            dir,
            repo,
            name,
            version,
            dry_run,
        } => {
            publish(
                &dir,
                &repo,
                name.as_deref(),
                version.as_deref(),
                dry_run,
                global,
            )
            .await
        }
        PluginsCommand::Install {
            slug,
            repo,
            harness,
            version,
            path,
        } => install(&slug, &repo, &harness, &version, path.as_deref(), global).await,
        PluginsCommand::List {
            harness,
            path,
            check_updates,
        } => list(&harness, path.as_deref(), check_updates, global).await,
        PluginsCommand::Update {
            slug,
            all: _,
            harness,
            path,
        } => update(slug.as_deref(), &harness, path.as_deref(), global).await,
        PluginsCommand::Uninstall {
            slug,
            harness,
            repo,
            path,
        } => uninstall(&slug, &harness, repo.as_deref(), path.as_deref(), global),
        PluginsCommand::Search {
            query,
            repo,
            harness,
        } => search(query.as_deref(), &repo, harness, global).await,
        PluginsCommand::Delete {
            slug,
            version,
            repo,
            yes,
        } => {
            bundle::validate_slug(&slug).map_err(AkError::Usage)?;
            bundle::validate_version(&version).map_err(AkError::Usage)?;
            let path = artifact_path(&slug, &version);
            crate::commands::artifact::delete(&repo, &path, yes, global).await
        }
    }
}

/// Where the server stores a version: `<slug>/<version>/<slug>-<version>.zip`.
fn artifact_path(slug: &str, version: &str) -> String {
    format!("{slug}/{version}/{slug}-{version}.zip")
}

fn zip_name(slug: &str, version: &str) -> String {
    format!("{slug}-{version}.zip")
}

/// Print what this command found or did on this machine. It isn't one server response,
/// so there's no body to print as received.
fn print_local(value: &Value, table: Option<String>, global: &GlobalArgs) {
    let text = output::render(value, &global.format, table);
    if !text.is_empty() {
        println!("{text}");
    }
}

fn home() -> Result<PathBuf> {
    dirs::home_dir()
        .ok_or_else(|| AkError::Local("Can't find your home directory".to_string()).into())
}

fn harnesses_or_all(harnesses: &[Harness]) -> Vec<Harness> {
    if harnesses.is_empty() {
        harness::ALL.to_vec()
    } else {
        let mut list = harnesses.to_vec();
        list.sort();
        list.dedup();
        list
    }
}

// ---- publish ----

async fn publish(
    dir: &Path,
    repo: &str,
    name: Option<&str>,
    version: Option<&str>,
    dry_run: bool,
    global: &GlobalArgs,
) -> Result<()> {
    if !dir.is_dir() {
        return Err(AkError::Usage(format!("{} isn't a directory", dir.display())).into());
    }
    let manifests = bundle::discover(dir).map_err(AkError::Usage)?;
    let identity = bundle::identify(&manifests, name, version).map_err(AkError::Usage)?;
    let files = bundle::collect_files(dir).map_err(AkError::Usage)?;
    let zip = bundle::build_zip(&files, &identity.overrides).map_err(AkError::Local)?;
    let sha256 = bundle::sha256_hex(&zip);
    let slug = &identity.slug;
    let version = &identity.version;

    if dry_run {
        let entries: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
        let summary = json!({
            "name": slug,
            "version": version,
            "harnesses": identity.harnesses,
            "manifest_paths": manifests.iter().map(|m| m.path).collect::<Vec<_>>(),
            "rewritten": identity.overrides.keys().collect::<Vec<_>>(),
            "sha256": sha256,
            "size_bytes": zip.len(),
            "entries": entries,
        });
        let table = format!(
            "{slug} {version} ({}), {} bytes, sha256 {sha256}\n{}{}\nNothing was sent.",
            identity.harnesses.join(", "),
            zip.len(),
            identity
                .overrides
                .keys()
                .map(|k| format!("version set in {k}\n"))
                .collect::<String>(),
            entries.join("\n"),
        );
        if matches!(global.format, OutputFormat::Quiet) {
            println!("{}", entries.join("\n"));
        } else {
            print_local(&summary, Some(table), global);
        }
        return Ok(());
    }

    let wire = Wire::new(global)?;
    let url = wire.url(&[
        "agentplugins",
        repo,
        slug,
        version,
        &zip_name(slug, version),
    ]);
    let response = wire
        .request(Method::PUT, url)
        .header(reqwest::header::CONTENT_TYPE, "application/zip")
        .header("X-Checksum-Sha256", &sha256)
        .body(zip)
        .send()
        .await
        .map_err(|e| network_err("upload the plugin", e))?;
    let status = response.status();
    let body = response.bytes().await.into_diagnostic()?.to_vec();
    if !status.is_success() {
        return Err(publish_error(status, &body, repo, slug, version).into());
    }

    let reply: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let fallback = json!({"name": slug, "version": version, "sha256": sha256});
    let human = publish_summary(&reply, repo, slug, version, &sha256);
    emit_mutation_raw(
        Some(&body),
        &fallback,
        &artifact_path(slug, version),
        &human,
        global,
    );
    Ok(())
}

/// What a person sees after a publish: the version, and how to point Claude Code at it.
fn publish_summary(reply: &Value, repo: &str, slug: &str, version: &str, sha256: &str) -> String {
    let mut out = format!("Published {slug} {version} to {repo}.\n  sha256: {sha256}");
    if let Some(tags) = reply["harnesses"].as_array() {
        let tags: Vec<&str> = tags.iter().filter_map(Value::as_str).collect();
        out.push_str(&format!("\n  harnesses: {}", tags.join(", ")));
    }
    if let Some(url) = reply["download_url"].as_str() {
        out.push_str(&format!("\n  download: {url}"));
    }
    if let Some(claude) = reply["marketplaces"]["claude"].as_str() {
        out.push_str(&format!(
            "\n\nAdd the repository to Claude Code:\n  claude plugin marketplace add {claude}"
        ));
        let market = reply["marketplace_name"].as_str().unwrap_or(repo);
        out.push_str(&format!("\n  claude plugin install {slug}@{market}"));
    }
    out.push_str(&format!(
        "\n\nInstall it for another agent:\n  ak agent plugins install {slug} --repo {repo} --harness cursor"
    ));
    output::sanitize_terminal(&out)
}

/// A refused publish, said in terms of what to do next.
fn publish_error(
    status: StatusCode,
    body: &[u8],
    repo: &str,
    slug: &str,
    version: &str,
) -> AkError {
    let message = artifact_keeper_sdk::error::server_message(body).unwrap_or_default();
    match status {
        StatusCode::CONFLICT => AkError::Usage(format!(
            "{slug} {version} is already in {repo}, and a published version can't be replaced. \
             Publish a new version with --version, or delete this one with `ak agent plugins \
             delete {slug} --version {version} --repo {repo}` first. The server said: {message}"
        )),
        StatusCode::BAD_REQUEST => {
            AkError::Usage(format!("The server refused the plugin: {message}"))
        }
        StatusCode::NOT_FOUND => AkError::NotFound(format!(
            "upload the plugin: {status}: {message}. Check that {repo} is an Agent Plugins \
             repository, and that the server supports them"
        )),
        _ => raw_err("upload the plugin", status, &String::from_utf8_lossy(body)),
    }
}

// ---- the server's index of a plugin ----

#[derive(Debug, Clone, Deserialize, Serialize)]
struct PluginIndex {
    #[serde(default)]
    latest: Option<String>,
    #[serde(default)]
    versions: Vec<IndexVersion>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct IndexVersion {
    version: String,
    sha256: String,
    #[serde(default)]
    harnesses: Vec<String>,
}

async fn fetch_index(wire: &Wire, repo: &str, slug: &str) -> Result<PluginIndex> {
    let url = wire.url(&["agentplugins", repo, slug, "index.json"]);
    let response = wire
        .request(Method::GET, url)
        .send()
        .await
        .map_err(|e| network_err("read the plugin's versions", e))?;
    let status = response.status();
    let body = response.bytes().await.into_diagnostic()?;
    if status == StatusCode::NOT_FOUND {
        return Err(AkError::NotFound(format!(
            "There's no plugin {slug} in {repo}, or {repo} isn't an Agent Plugins repository \
             on a server that has them"
        ))
        .into());
    }
    if !status.is_success() {
        return Err(raw_err(
            "read the plugin's versions",
            status,
            &String::from_utf8_lossy(&body),
        )
        .into());
    }
    serde_json::from_slice(&body).map_err(|e| {
        AkError::ServerError(format!("{slug}/index.json isn't the index ak expects: {e}")).into()
    })
}

/// The version `wanted` names: `latest`, or an exact one that's in the index.
fn pick_version<'a>(index: &'a PluginIndex, slug: &str, wanted: &str) -> Result<&'a IndexVersion> {
    let target = if wanted == "latest" {
        index
            .latest
            .clone()
            .or_else(|| index.versions.first().map(|v| v.version.clone()))
            .ok_or_else(|| AkError::NotFound(format!("{slug} has no versions")))?
    } else {
        wanted.to_string()
    };
    index
        .versions
        .iter()
        .find(|v| v.version == target)
        .ok_or_else(|| {
            let have: Vec<&str> = index.versions.iter().map(|v| v.version.as_str()).collect();
            AkError::NotFound(format!(
                "{slug} has no version {target}. It has: {}",
                if have.is_empty() {
                    "none".to_string()
                } else {
                    have.join(", ")
                }
            ))
            .into()
        })
}

/// The zip of one version, checked against the SHA-256 the index gives.
async fn download(wire: &Wire, repo: &str, slug: &str, chosen: &IndexVersion) -> Result<Vec<u8>> {
    let version = &chosen.version;
    let url = wire.url(&[
        "agentplugins",
        repo,
        slug,
        version,
        &zip_name(slug, version),
    ]);
    let reply = wire
        .send("download the plugin", wire.request(Method::GET, url))
        .await?;
    let found = bundle::sha256_hex(&reply.body);
    if !found.eq_ignore_ascii_case(&chosen.sha256) {
        return Err(AkError::ServerError(format!(
            "The download of {slug} {version} has SHA-256 {found}, and the index says {}. \
             Nothing was installed",
            chosen.sha256
        ))
        .into());
    }
    Ok(reply.body)
}

// ---- install ----

/// What one install did.
#[derive(Debug, Serialize)]
struct InstallReport {
    slug: String,
    version: String,
    harness: Harness,
    path: String,
    repo: String,
    instance: String,
    sha256: String,
    /// Commands run for the agent.
    ran: Vec<String>,
    /// Commands left for the user to run.
    to_run: Vec<String>,
    /// What else the agent needs, such as a reload.
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

async fn install(
    slug: &str,
    repo: &str,
    harnesses: &[Harness],
    version: &str,
    path: Option<&Path>,
    global: &GlobalArgs,
) -> Result<()> {
    bundle::validate_slug(slug).map_err(AkError::Usage)?;
    harness::check_repo_component(repo).map_err(AkError::Usage)?;
    if version != "latest" {
        bundle::validate_version(version).map_err(AkError::Usage)?;
    }
    let harnesses = harnesses_or_all(harnesses);
    if path.is_some() && harnesses.len() > 1 {
        return Err(AkError::Usage(
            "--path installs to one directory, so give it one --harness".to_string(),
        )
        .into());
    }
    let home = match path {
        Some(_) => PathBuf::new(),
        None => home()?,
    };
    let wire = Wire::new_optional_auth(global)?;
    let index = fetch_index(&wire, repo, slug).await?;
    let chosen = pick_version(&index, slug, version)?;
    let zip = download(&wire, repo, slug, chosen).await?;
    let instance = wire.base().as_str().trim_end_matches('/').to_string();

    let mut reports = Vec::new();
    for harness in harnesses {
        let location = harness::location(harness, &home, repo, slug, path);
        let report = install_one(&Target {
            harness,
            location,
            instance: &instance,
            repo,
            slug,
            chosen,
            zip: &zip,
            run_steps: path.is_none(),
        })?;
        reports.push(report);
    }
    print_installs(&reports, global);
    Ok(())
}

/// One place to install one downloaded version.
struct Target<'a> {
    harness: Harness,
    location: Location,
    instance: &'a str,
    repo: &'a str,
    slug: &'a str,
    chosen: &'a IndexVersion,
    zip: &'a [u8],
    run_steps: bool,
}

fn install_one(target: &Target) -> Result<InstallReport> {
    let Target {
        harness,
        location,
        slug,
        chosen,
        ..
    } = target;
    if !harness.accepts(&chosen.harnesses) {
        eprintln!(
            "Warning: {slug} {} is made for {}, not {harness}. Installing it anyway.",
            chosen.version,
            if chosen.harnesses.is_empty() {
                "no agent the server recognised".to_string()
            } else {
                chosen.harnesses.join(", ")
            }
        );
    }
    unpack(target)?;
    let known = register(target)?;

    let (steps, note) = harness::post_steps(*harness, location, target.repo, slug, known);
    let (ran, to_run) = if target.run_steps {
        run_steps(*harness, &steps)
    } else {
        (Vec::new(), Vec::new())
    };
    Ok(InstallReport {
        slug: slug.to_string(),
        version: chosen.version.clone(),
        harness: *harness,
        path: location.dir.display().to_string(),
        repo: target.repo.to_string(),
        instance: target.instance.to_string(),
        sha256: chosen.sha256.clone(),
        ran,
        to_run,
        note: note.filter(|_| target.run_steps),
    })
}

/// Unpack into a fresh directory next to the install, then swap it in, so a failed
/// unpack leaves the old install as it was.
fn unpack(target: &Target) -> Result<()> {
    let dir = &target.location.dir;
    let parent = dir
        .parent()
        .ok_or_else(|| AkError::Local(format!("{} has no parent", dir.display())))?;
    std::fs::create_dir_all(parent)
        .map_err(|e| AkError::Local(format!("Can't create {}: {e}", parent.display())))?;
    let staging = tempfile::Builder::new()
        .prefix(".ak-unpack-")
        .tempdir_in(parent)
        .map_err(|e| AkError::Local(format!("Can't unpack in {}: {e}", parent.display())))?;
    let unpacked = staging.path().join("plugin");
    bundle::extract(std::io::Cursor::new(target.zip), &unpacked).map_err(AkError::Local)?;
    let info = PluginInfo {
        instance: target.instance.to_string(),
        repo: target.repo.to_string(),
        slug: target.slug.to_string(),
        version: target.chosen.version.clone(),
        sha256: target.chosen.sha256.to_lowercase(),
        harness: target.harness,
        installed_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    };
    info.write(&unpacked).map_err(AkError::Local)?;
    if std::fs::symlink_metadata(dir).is_ok() {
        if PluginInfo::read(dir).is_none() {
            return Err(AkError::Local(format!(
                "{} is already there, and ak didn't install it. Move it away, or pick \
                 another --path",
                dir.display()
            ))
            .into());
        }
        std::fs::remove_dir_all(dir)
            .map_err(|e| AkError::Local(format!("Can't replace {}: {e}", dir.display())))?;
    }
    std::fs::rename(&unpacked, dir)
        .map_err(|e| AkError::Local(format!("Can't install to {}: {e}", dir.display())))?;
    Ok(())
}

/// List the install in ak's marketplace for its repository, for the agents that have
/// one. Returns whether that marketplace was already there.
fn register(target: &Target) -> Result<bool> {
    let Some(market_dir) = &target.location.marketplace_dir else {
        return Ok(false);
    };
    let Some(file) = harness::marketplace_file(target.harness, market_dir) else {
        return Ok(false);
    };
    let existing = read_json(&file);
    let known = existing.is_some();
    let doc = match target.harness {
        Harness::Claude => {
            let description = bundle::discover(&target.location.dir).ok().and_then(|ms| {
                ms.iter()
                    .find_map(|m| m.field("description").map(str::to_string))
            });
            harness::claude_marketplace(
                existing.as_ref(),
                target.repo,
                target.instance,
                target.slug,
                &target.chosen.version,
                description.as_deref(),
            )
        }
        _ => harness::codex_marketplace(existing.as_ref(), target.repo, target.slug),
    };
    write_json(&file, &doc)?;
    Ok(known)
}

fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

fn write_json(path: &Path, doc: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| AkError::Local(format!("Can't create {}: {e}", parent.display())))?;
    }
    let mut text = serde_json::to_string_pretty(doc).unwrap_or_default();
    text.push('\n');
    std::fs::write(path, text)
        .map_err(|e| AkError::Local(format!("Can't write {}: {e}", path.display())).into())
}

/// Run each step whose program is on PATH, in order, and stop at the first that fails.
/// Returns what ran and what's left for the user. Copilot's step is a convenience: the
/// files are already where Copilot looks, so without it there's nothing left to do.
fn run_steps(harness: Harness, steps: &[Step]) -> (Vec<String>, Vec<String>) {
    let path = std::env::var_os("PATH");
    let mut ran = Vec::new();
    let mut left = Vec::new();
    let mut stopped = false;
    for step in steps {
        let shown = step.display();
        let program = harness::find_on_path(step.program, path.as_deref());
        if stopped || program.is_none() {
            if harness != Harness::Vscode {
                left.push(shown);
            }
            continue;
        }
        eprintln!("Running: {shown}");
        let status = std::process::Command::new(program.expect("checked above"))
            .args(&step.args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::from(std::io::stderr()))
            .status();
        match status {
            Ok(s) if s.success() => ran.push(shown),
            Ok(s) => {
                eprintln!("Warning: `{shown}` exited with {s}");
                stopped = true;
                left.push(shown);
            }
            Err(e) => {
                eprintln!("Warning: couldn't run `{shown}`: {e}");
                stopped = true;
                left.push(shown);
            }
        }
    }
    (ran, left)
}

fn print_installs(reports: &[InstallReport], global: &GlobalArgs) {
    match global.format {
        OutputFormat::Quiet => {
            for r in reports {
                println!("{}", r.path);
            }
        }
        OutputFormat::Json | OutputFormat::Yaml => {
            print_local(
                &serde_json::to_value(reports).unwrap_or_default(),
                None,
                global,
            );
        }
        OutputFormat::Table => {
            for r in reports {
                let mut text = format!(
                    "Installed {} {} for {} in {}.",
                    r.slug, r.version, r.harness, r.path
                );
                if !r.to_run.is_empty() {
                    text.push_str("\nTo load it, run:");
                    for command in &r.to_run {
                        text.push_str(&format!("\n  {command}"));
                    }
                }
                if let Some(note) = &r.note {
                    text.push_str(&format!("\n{note}"));
                }
                eprintln!("{}", output::sanitize_terminal(&text));
            }
        }
    }
}

// ---- list and update ----

/// The newest version of each plugin, asked once per instance, repository and plugin.
#[derive(Default)]
struct Latest {
    seen: BTreeMap<(String, String, String), Option<PluginIndex>>,
}

impl Latest {
    /// The index for an install, from the instance it came from unless `--instance`
    /// says otherwise. A failure is a warning, and the status is unknown.
    async fn index(&mut self, info: &PluginInfo, global: &GlobalArgs) -> Option<PluginIndex> {
        let instance = global
            .instance
            .clone()
            .unwrap_or_else(|| info.instance.clone());
        let key = (instance.clone(), info.repo.clone(), info.slug.clone());
        if let Some(found) = self.seen.get(&key) {
            return found.clone();
        }
        let scoped = GlobalArgs {
            format: global.format,
            instance: Some(instance),
            no_input: global.no_input,
        };
        let found = match Wire::new_optional_auth(&scoped) {
            Ok(wire) => fetch_index(&wire, &info.repo, &info.slug).await,
            Err(e) => Err(e),
        };
        let found = match found {
            Ok(index) => Some(index),
            Err(e) => {
                eprintln!("Warning: can't check {} for updates: {e}", info.slug);
                None
            }
        };
        self.seen.insert(key, found.clone());
        found
    }
}

#[derive(Debug, Serialize)]
struct ListRow {
    harness: Harness,
    slug: String,
    version: String,
    repo: String,
    instance: String,
    path: String,
    installed_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    latest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<UpdateStatus>,
}

fn row(install: &Installed) -> ListRow {
    let info = &install.info;
    ListRow {
        harness: info.harness,
        slug: info.slug.clone(),
        version: info.version.clone(),
        repo: info.repo.clone(),
        instance: info.instance.clone(),
        path: install.dir.display().to_string(),
        installed_at: info.installed_at.clone(),
        latest: None,
        status: None,
    }
}

fn installs(harnesses: &[Harness], path: Option<&Path>) -> Result<Vec<Installed>> {
    let home = match path {
        Some(_) => PathBuf::new(),
        None => home()?,
    };
    Ok(harness::find_installs(
        &home,
        &harnesses_or_all(harnesses),
        path,
    ))
}

async fn list(
    harnesses: &[Harness],
    path: Option<&Path>,
    check_updates: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let found = installs(harnesses, path)?;
    let mut latest = Latest::default();
    let mut rows = Vec::new();
    for install in &found {
        let mut r = row(install);
        if check_updates {
            let index = latest.index(&install.info, global).await;
            let newest = index.and_then(|i| i.latest);
            r.status = Some(harness::compare(&install.info.version, newest.as_deref()));
            r.latest = Some(newest.unwrap_or_default());
        }
        rows.push(r);
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for r in &rows {
            println!("{}", r.slug);
        }
        return Ok(());
    }
    if rows.is_empty() && matches!(global.format, OutputFormat::Table) {
        eprintln!("No plugins installed by ak.");
        return Ok(());
    }
    let mut headers = vec!["HARNESS", "SLUG", "VERSION", "REPO"];
    if check_updates {
        headers.extend(["LATEST", "STATUS"]);
    }
    headers.push("PATH");
    let mut table = new_table(headers);
    for r in &rows {
        let mut cells = vec![
            r.harness.to_string(),
            r.slug.clone(),
            r.version.clone(),
            r.repo.clone(),
        ];
        if check_updates {
            cells.push(r.latest.clone().unwrap_or_default());
            cells.push(r.status.map(UpdateStatus::name).unwrap_or("").to_string());
        }
        cells.push(r.path.clone());
        table.add_row(cells);
    }
    print_local(
        &serde_json::to_value(&rows).unwrap_or_default(),
        Some(table.to_string()),
        global,
    );
    Ok(())
}

#[derive(Debug, Serialize)]
struct UpdateRow {
    harness: Harness,
    slug: String,
    path: String,
    from: String,
    to: Option<String>,
    status: &'static str,
}

async fn update(
    slug: Option<&str>,
    harnesses: &[Harness],
    path: Option<&Path>,
    global: &GlobalArgs,
) -> Result<()> {
    let found: Vec<Installed> = installs(harnesses, path)?
        .into_iter()
        .filter(|i| slug.is_none_or(|s| i.info.slug == s))
        .collect();
    if let Some(slug) = slug
        && found.is_empty()
    {
        return Err(AkError::NotFound(format!("ak hasn't installed {slug} here")).into());
    }
    let home = match path {
        Some(_) => PathBuf::new(),
        None => home()?,
    };
    let mut latest = Latest::default();
    let mut rows = Vec::new();
    for install in &found {
        let info = &install.info;
        let index = latest.index(info, global).await;
        let newest = index.as_ref().and_then(|i| i.latest.clone());
        let status = harness::compare(&info.version, newest.as_deref());
        let mut done = UpdateRow {
            harness: info.harness,
            slug: info.slug.clone(),
            path: install.dir.display().to_string(),
            from: info.version.clone(),
            to: newest.clone(),
            status: status.name(),
        };
        if status == UpdateStatus::Behind
            && let Some(index) = &index
        {
            reinstall(install, index, &home, global).await?;
            done.status = "updated";
        }
        rows.push(done);
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for r in rows.iter().filter(|r| r.status == "updated") {
            println!("{}", r.slug);
        }
        return Ok(());
    }
    if rows.is_empty() && matches!(global.format, OutputFormat::Table) {
        eprintln!("No plugins installed by ak.");
        return Ok(());
    }
    let mut table = new_table(vec!["HARNESS", "SLUG", "FROM", "TO", "STATUS", "PATH"]);
    for r in &rows {
        table.add_row(vec![
            r.harness.to_string(),
            r.slug.clone(),
            r.from.clone(),
            r.to.clone().unwrap_or_default(),
            r.status.to_string(),
            r.path.clone(),
        ]);
    }
    print_local(
        &serde_json::to_value(&rows).unwrap_or_default(),
        Some(table.to_string()),
        global,
    );
    Ok(())
}

/// Install the newest version where an older one is, and tell the agent again unless
/// it's an install in a `--path` of its own.
async fn reinstall(
    install: &Installed,
    index: &PluginIndex,
    home: &Path,
    global: &GlobalArgs,
) -> Result<()> {
    let info = &install.info;
    let chosen = pick_version(index, &info.slug, "latest")?;
    let instance = global
        .instance
        .clone()
        .unwrap_or_else(|| info.instance.clone());
    let scoped = GlobalArgs {
        format: global.format,
        instance: Some(instance),
        no_input: global.no_input,
    };
    let wire = Wire::new_optional_auth(&scoped)?;
    let zip = download(&wire, &info.repo, &info.slug, chosen).await?;
    let standard = harness::location(info.harness, home, &info.repo, &info.slug, None);
    let in_place = standard.dir == install.dir;
    let location = if in_place {
        standard
    } else {
        Location {
            dir: install.dir.clone(),
            marketplace_dir: None,
        }
    };
    let report = install_one(&Target {
        harness: info.harness,
        location,
        instance: &info.instance,
        repo: &info.repo,
        slug: &info.slug,
        chosen,
        zip: &zip,
        run_steps: in_place,
    })?;
    if matches!(global.format, OutputFormat::Table) && !report.to_run.is_empty() {
        eprintln!(
            "To load {} {} in {}, run:\n  {}",
            report.slug,
            report.version,
            report.harness,
            report.to_run.join("\n  ")
        );
    }
    if matches!(global.format, OutputFormat::Table)
        && let Some(note) = &report.note
    {
        eprintln!("{note}");
    }
    Ok(())
}

// ---- uninstall ----

fn uninstall(
    slug: &str,
    harnesses: &[Harness],
    repo: Option<&str>,
    path: Option<&Path>,
    global: &GlobalArgs,
) -> Result<()> {
    let home = match path {
        Some(_) => PathBuf::new(),
        None => home()?,
    };
    let found: Vec<Installed> = harness::find_installs(&home, &harnesses_or_all(harnesses), path)
        .into_iter()
        .filter(|i| i.info.slug == slug && repo.is_none_or(|r| i.info.repo == r))
        .collect();
    if found.is_empty() {
        return Err(AkError::NotFound(format!("ak hasn't installed {slug} here")).into());
    }
    let mut removed = Vec::new();
    for install in &found {
        let info = &install.info;
        std::fs::remove_dir_all(&install.dir)
            .map_err(|e| AkError::Local(format!("Can't remove {}: {e}", install.dir.display())))?;
        let standard = harness::location(info.harness, &home, &info.repo, slug, None);
        let mut hints = Vec::new();
        if path.is_none() && standard.dir == install.dir {
            if let Some(file) = standard
                .marketplace_dir
                .as_deref()
                .and_then(|d| harness::marketplace_file(info.harness, d))
                && let Some(doc) = read_json(&file).and_then(|d| harness::without_plugin(&d, slug))
            {
                write_json(&file, &doc)?;
            }
            hints = harness::uninstall_hints(info.harness, &info.repo, slug);
        }
        removed.push(json!({
            "slug": slug,
            "version": info.version,
            "harness": info.harness,
            "repo": info.repo,
            "path": install.dir.display().to_string(),
            "hints": hints,
        }));
        if matches!(global.format, OutputFormat::Table) {
            let mut text = format!(
                "Removed {slug} {} for {} from {}.",
                info.version,
                info.harness,
                install.dir.display()
            );
            if !hints.is_empty() {
                text.push_str(&format!("\nThen: {}", hints.join("; ")));
            }
            eprintln!("{}", output::sanitize_terminal(&text));
        }
    }
    let paths: Vec<&str> = removed.iter().filter_map(|r| r["path"].as_str()).collect();
    if !matches!(global.format, OutputFormat::Table) {
        emit_mutation(&removed, &paths.join("\n"), "", global);
    }
    Ok(())
}

// ---- search ----

/// Whether a marketplace entry matches the text, by name, description or keyword.
fn matches_query(plugin: &Value, query: &str) -> bool {
    let query = query.to_lowercase();
    let has = |v: Option<&str>| v.is_some_and(|s| s.to_lowercase().contains(&query));
    has(plugin["name"].as_str())
        || has(plugin["description"].as_str())
        || plugin["keywords"]
            .as_array()
            .is_some_and(|k| k.iter().any(|w| has(w.as_str())))
}

fn entry_tags(plugin: &Value) -> Vec<String> {
    plugin["metadata"]["harnesses"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|t| t.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// The marketplace's entries that match, as the server sent them.
fn filter_plugins(doc: &Value, query: Option<&str>, harness: Option<Harness>) -> Vec<Value> {
    doc["plugins"]
        .as_array()
        .map(|plugins| {
            plugins
                .iter()
                .filter(|p| query.is_none_or(|q| matches_query(p, q)))
                .filter(|p| harness.is_none_or(|h| h.accepts(&entry_tags(p))))
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

async fn search(
    query: Option<&str>,
    repo: &str,
    harness: Option<Harness>,
    global: &GlobalArgs,
) -> Result<()> {
    let wire = Wire::new_optional_auth(global)?;
    let url = wire.url(&["agentplugins", repo, "marketplace.json"]);
    let reply = wire
        .send(
            "read the repository's marketplace",
            wire.request(Method::GET, url),
        )
        .await?;
    let doc: Value = serde_json::from_slice(&reply.body)
        .map_err(|e| AkError::ServerError(format!("The marketplace isn't JSON: {e}")))?;
    let found = filter_plugins(&doc, query, harness);

    if matches!(global.format, OutputFormat::Quiet) {
        for p in &found {
            println!("{}", p["name"].as_str().unwrap_or_default());
        }
        return Ok(());
    }
    if found.is_empty() && matches!(global.format, OutputFormat::Table) {
        eprintln!("No plugins in {repo} match.");
        return Ok(());
    }
    let mut table = new_table(vec!["NAME", "VERSION", "HARNESSES", "DESCRIPTION"]);
    for p in &found {
        table.add_row(vec![
            p["name"].as_str().unwrap_or_default().to_string(),
            p["version"].as_str().unwrap_or_default().to_string(),
            entry_tags(p).join(", "),
            p["description"].as_str().unwrap_or_default().to_string(),
        ]);
    }
    print_local(&Value::Array(found), Some(table.to_string()), global);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index() -> PluginIndex {
        serde_json::from_value(json!({
            "name": "demo",
            "latest": "1.2.0",
            "versions": [
                {"version": "1.2.0", "sha256": "aa", "size_bytes": 1, "harnesses": ["claude"], "published_at": "x", "url": "u"},
                {"version": "1.1.0", "sha256": "bb", "harnesses": ["claude", "standard"]},
            ],
        }))
        .unwrap()
    }

    #[test]
    fn latest_and_exact_versions_come_from_the_index() {
        let index = index();
        assert_eq!(pick_version(&index, "demo", "latest").unwrap().sha256, "aa");
        assert_eq!(pick_version(&index, "demo", "1.1.0").unwrap().sha256, "bb");
        let e = pick_version(&index, "demo", "9.9.9")
            .unwrap_err()
            .to_string();
        assert!(e.contains("no version 9.9.9"), "{e}");
        assert!(e.contains("1.2.0, 1.1.0"), "{e}");
        let empty: PluginIndex = serde_json::from_value(json!({"versions": []})).unwrap();
        assert!(pick_version(&empty, "demo", "latest").is_err());
    }

    #[test]
    fn the_artifact_path_is_the_servers_layout() {
        assert_eq!(artifact_path("demo", "1.2.0"), "demo/1.2.0/demo-1.2.0.zip");
    }

    #[test]
    fn publish_errors_say_what_to_do() {
        let e =
            publish_error(StatusCode::CONFLICT, b"exists", "plugins", "demo", "1.0.0").to_string();
        assert!(e.contains("can't be replaced"), "{e}");
        assert!(
            e.contains("ak agent plugins delete demo --version 1.0.0 --repo plugins"),
            "{e}"
        );
        let e = publish_error(
            StatusCode::BAD_REQUEST,
            b"plugin.json version 1.0.0 doesn't match 2.0.0",
            "plugins",
            "demo",
            "2.0.0",
        )
        .to_string();
        assert!(
            e.ends_with("plugin.json version 1.0.0 doesn't match 2.0.0"),
            "{e}"
        );
        let e = publish_error(StatusCode::NOT_FOUND, b"", "plugins", "demo", "1.0.0").to_string();
        assert!(e.contains("Agent Plugins repository"), "{e}");
    }

    #[test]
    fn the_publish_summary_gives_the_claude_command() {
        let reply = json!({
            "harnesses": ["claude", "standard"],
            "download_url": "https://ak/agentplugins/plugins/demo/1.0.0/demo-1.0.0.zip",
            "marketplace_name": "plugins-ak",
            "marketplaces": {"claude": "https://ak/agentplugins/plugins/claude-marketplace.json"},
        });
        let text = publish_summary(&reply, "plugins", "demo", "1.0.0", "ab");
        assert!(text.contains("claude plugin marketplace add https://ak/agentplugins/plugins/claude-marketplace.json"), "{text}");
        assert!(text.contains("harnesses: claude, standard"), "{text}");
        assert!(
            text.contains("claude plugin install demo@plugins-ak"),
            "{text}"
        );
    }

    #[test]
    fn search_filters_by_text_and_agent() {
        let doc = json!({"plugins": [
            {"name": "deploy-tools", "description": "Ship it", "keywords": ["ci"], "metadata": {"harnesses": ["claude"]}},
            {"name": "rules", "description": "Lint rules", "metadata": {"harnesses": ["cursor", "standard"]}},
        ]});
        let names = |found: Vec<Value>| -> Vec<String> {
            found
                .iter()
                .map(|p| p["name"].as_str().unwrap().to_string())
                .collect()
        };
        assert_eq!(
            names(filter_plugins(&doc, Some("DEPLOY"), None)),
            ["deploy-tools"]
        );
        assert_eq!(
            names(filter_plugins(&doc, Some("ci"), None)),
            ["deploy-tools"]
        );
        assert_eq!(names(filter_plugins(&doc, Some("lint"), None)), ["rules"]);
        assert_eq!(
            names(filter_plugins(&doc, None, Some(Harness::Codex))),
            ["rules"]
        );
        assert_eq!(
            names(filter_plugins(&doc, None, Some(Harness::Claude))).len(),
            2
        );
        assert!(filter_plugins(&json!({}), None, None).is_empty());
    }

    fn zip_of(entries: &[(&str, &str)]) -> Vec<u8> {
        use std::io::Write;
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, content) in entries {
            writer
                .start_file(*name, zip::write::SimpleFileOptions::DEFAULT)
                .unwrap();
            writer.write_all(content.as_bytes()).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn install_one_unpacks_records_and_lists_it_in_the_marketplace() {
        let home = tempfile::TempDir::new().unwrap();
        let zip = zip_of(&[
            (
                "demo/.claude-plugin/plugin.json",
                r#"{"name":"demo","description":"Demo plugin"}"#,
            ),
            ("demo/skills/a/SKILL.md", "a"),
        ]);
        let chosen = IndexVersion {
            version: "1.0.0".to_string(),
            sha256: bundle::sha256_hex(&zip),
            harnesses: vec!["claude".to_string()],
        };
        let location = harness::location(Harness::Claude, home.path(), "plugins", "demo", None);
        let target = Target {
            harness: Harness::Claude,
            location: location.clone(),
            instance: "https://ak.example.com",
            repo: "plugins",
            slug: "demo",
            chosen: &chosen,
            zip: &zip,
            run_steps: false,
        };
        let report = install_one(&target).unwrap();
        assert_eq!(report.path, location.dir.display().to_string());
        assert!(location.dir.join("skills/a/SKILL.md").is_file());
        let info = PluginInfo::read(&location.dir).unwrap();
        assert_eq!(info.version, "1.0.0");
        assert_eq!(info.harness, Harness::Claude);
        let market = read_json(
            &location
                .marketplace_dir
                .as_ref()
                .unwrap()
                .join(".claude-plugin/marketplace.json"),
        )
        .unwrap();
        assert_eq!(market["name"], "ak-plugins");
        assert_eq!(market["plugins"][0]["source"], "./demo");
        assert_eq!(market["plugins"][0]["description"], "Demo plugin");
        // A second install over it replaces it, and knows the marketplace.
        assert!(register(&target).unwrap());
        install_one(&target).unwrap();
        assert!(location.dir.join(".claude-plugin/plugin.json").is_file());
        // Nothing left behind from unpacking.
        let parent = location.dir.parent().unwrap();
        let strays: Vec<_> = std::fs::read_dir(parent)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".ak-unpack-"))
            .collect();
        assert!(strays.is_empty());
    }

    #[test]
    fn install_one_wont_overwrite_a_directory_ak_didnt_make() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("demo")).unwrap();
        let zip = zip_of(&[(".cursor-plugin/plugin.json", "{}")]);
        let chosen = IndexVersion {
            version: "1.0.0".to_string(),
            sha256: bundle::sha256_hex(&zip),
            harnesses: vec!["cursor".to_string()],
        };
        let target = Target {
            harness: Harness::Cursor,
            location: harness::location(Harness::Cursor, dir.path(), "r", "demo", Some(dir.path())),
            instance: "https://ak",
            repo: "r",
            slug: "demo",
            chosen: &chosen,
            zip: &zip,
            run_steps: false,
        };
        let e = install_one(&target).unwrap_err().to_string();
        assert!(e.contains("ak didn't install it"), "{e}");
    }
}
