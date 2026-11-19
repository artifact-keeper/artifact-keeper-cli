//! `ak mcp version`: what an administrator does to one server version on an MCP
//! registry's own `/mcp/{repo}/v0.1` routes. Change its status, soft delete it, purge a
//! deleted one for good, replace its document, and ask for its tools to be probed.
//!
//! These routes aren't in the OpenAPI spec, so they go over raw HTTP. Publishing,
//! bundle uploads and capability reports stay with `mcp-publisher`.

use clap::Subcommand;
use miette::Result;
use reqwest::Method;
use serde_json::{Value, json};

use super::helpers::{
    Minor, confirm_action, emit_mutation_raw, network_err, new_table, read_inline_or_file,
    since_raw,
};
use super::mcp::{check_path_parts, split_name, text};
use super::pkg::wire::{Reply, Wire};
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat};

const V1_12: Minor = (1, 12);

/// The registry API version these commands send. `/v0` is an alias of the same
/// handlers.
const API: &str = "v0.1";

/// Where a version's state lives in a served entry.
const OFFICIAL: &str = "io.modelcontextprotocol.registry/official";

#[derive(Subcommand)]
pub enum VersionCommand {
    /// Set the status of one version, or of every version of a server
    Status {
        /// MCP repository key (Local or Staging)
        #[arg(long)]
        repo: String,

        /// Server name, such as io.github.acme/weather
        server: String,

        /// Exact version. Without it, every version of the server changes
        version: Option<String>,

        /// The new status. `deleted` is a soft delete, and asks first
        #[arg(long, value_parser = ["active", "deprecated", "deleted"])]
        status: String,

        /// Why, shown to clients next to the status (not with `active`)
        #[arg(long)]
        message: Option<String>,

        /// Skip the confirmation prompt (for `--status deleted`)
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Soft delete a version: it stops being served, and its number can't be
    /// published again
    Delete {
        /// MCP repository key (Local or Staging)
        #[arg(long)]
        repo: String,

        /// Server name, such as io.github.acme/weather
        server: String,

        /// Exact version
        version: String,

        /// Why, shown to clients next to the status
        #[arg(long)]
        message: Option<String>,

        /// Skip the confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Purge a soft-deleted version for good: its document and bundles go to the
    /// trash, and what it pinned is released (instance administrators)
    Purge {
        /// MCP repository key (Local or Staging)
        #[arg(long)]
        repo: String,

        /// Server name, such as io.github.acme/weather
        server: String,

        /// Exact version, already deleted
        version: String,

        /// Skip the confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Replace a published version's server.json (repository administrators). The
    /// name and version come from the document, and can't change
    Edit {
        /// MCP repository key (Local or Staging)
        #[arg(long)]
        repo: String,

        /// The new server.json: the text itself, @FILE, or @- for stdin
        #[arg(long, value_name = "JSON|@FILE|@-")]
        document: String,
    },

    /// Queue introspection jobs for a version now: a probe of its remotes, a sandbox
    /// run of its packages, as the repository allows (repository administrators)
    Probe {
        /// MCP repository key
        #[arg(long)]
        repo: String,

        /// Server name, such as io.github.acme/weather
        server: String,

        /// Exact version
        version: String,
    },
}

impl VersionCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Status {
                repo,
                server,
                version,
                status,
                message,
                yes,
            } => {
                let change = StatusChange {
                    status,
                    message,
                    yes,
                };
                set_status(&repo, &server, version.as_deref(), change, global).await
            }
            Self::Delete {
                repo,
                server,
                version,
                message,
                yes,
            } => delete(&repo, &server, &version, message, yes, global).await,
            Self::Purge {
                repo,
                server,
                version,
                yes,
            } => purge(&repo, &server, &version, yes, global).await,
            Self::Edit { repo, document } => edit(&repo, &document, global).await,
            Self::Probe {
                repo,
                server,
                version,
            } => probe(&repo, &server, &version, global).await,
        }
    }
}

/// The path of a server, or of one of its versions, plus `tail`. A name with one
/// slash goes as two segments, any other as one, URL-encoded.
fn segments<'a>(
    repo: &'a str,
    server: &'a str,
    version: Option<&'a str>,
    tail: &[&'a str],
) -> Vec<&'a str> {
    let mut out = vec!["mcp", repo, API, "servers"];
    match split_name(server) {
        Some((ns, name)) => out.extend([ns, name]),
        None => out.push(server),
    }
    if let Some(version) = version {
        out.extend(["versions", version]);
    }
    out.extend(tail);
    out
}

/// The message of a refusal from the registry's routes. They answer RFC 9457 problem
/// documents with the machine code in `error` and the explanation in `detail`, and
/// the generic reader would show only the code. Any other body is left as it is.
fn problem_message(body: &[u8]) -> Option<String> {
    let doc: Value = serde_json::from_slice(body).ok()?;
    if doc.get("message").is_some() {
        return None;
    }
    let detail = doc["detail"].as_str().filter(|d| !d.trim().is_empty())?;
    let message = match doc["error"].as_str() {
        Some(code)
            if !code.is_empty()
                && code
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') =>
        {
            format!("{code}: {detail}")
        }
        _ => detail.to_string(),
    };
    Some(json!({ "message": message }).to_string())
}

/// [`Wire::send_since`](super::pkg::wire::Wire::send_since) that words a registry refusal by its explanation, not only
/// its code. A 404 from a server older than 1.12 still says it needs 1.12.
async fn send(
    action: &str,
    command: &str,
    global: &GlobalArgs,
    request: reqwest::RequestBuilder,
) -> Result<Reply> {
    let response = request.send().await.map_err(|e| network_err(action, e))?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .bytes()
        .await
        .map_err(|e| network_err(action, e))?
        .to_vec();
    if !status.is_success() {
        let text =
            problem_message(&body).unwrap_or_else(|| String::from_utf8_lossy(&body).into_owned());
        return Err(since_raw(V1_12, status, &text, action, command, global)
            .await
            .into());
    }
    Ok(Reply {
        status,
        headers,
        body,
    })
}

/// The status a served entry reports.
fn status_of(entry: &Value) -> String {
    text(&entry["_meta"][OFFICIAL]["status"])
}

fn name_at(entry: &Value) -> String {
    format!(
        "{}@{}",
        text(&entry["server"]["name"]),
        text(&entry["server"]["version"])
    )
}

/// Print the answer to a write of one version: the served entry.
fn emit_entry(reply: &Reply, fallback_id: &str, human: impl Fn(&Value) -> String, g: &GlobalArgs) {
    let entry = reply.json().unwrap_or_default();
    let id = if entry["server"]["name"].is_string() {
        name_at(&entry)
    } else {
        fallback_id.to_string()
    };
    emit_mutation_raw(Some(&reply.body), &entry, &id, &human(&entry), g);
}

struct StatusChange {
    status: String,
    message: Option<String>,
    yes: bool,
}

async fn set_status(
    repo: &str,
    server: &str,
    version: Option<&str>,
    change: StatusChange,
    global: &GlobalArgs,
) -> Result<()> {
    check_path_parts(server, version)?;
    let StatusChange {
        status,
        message,
        yes,
    } = change;
    if status == "active" && message.is_some() {
        return Err(AkError::Usage(
            "--message goes with deprecated or deleted: an active version carries no status \
             message"
                .to_string(),
        )
        .into());
    }
    let what = match version {
        Some(v) => format!("{server}@{v}"),
        None => format!("every version of {server}"),
    };
    if status == "deleted"
        && !confirm_action(
            &format!(
                "Delete {what} in '{repo}'? It stops being served, and its version numbers \
                 can't be published again."
            ),
            yes,
            global.no_input,
        )?
    {
        return Ok(());
    }
    let wire = Wire::new(global)?;
    let mut body = json!({ "status": status });
    if let Some(message) = &message {
        body["statusMessage"] = json!(message);
    }
    let url = wire.url(&segments(repo, server, version, &["status"]));
    let spinner = output::spinner("Changing the status...");
    let reply = send(
        "change the status",
        "mcp version status",
        global,
        wire.request(Method::PATCH, url).json(&body),
    )
    .await?;
    spinner.finish_and_clear();
    match version {
        Some(v) => emit_entry(
            &reply,
            &format!("{server}@{v}"),
            |entry| {
                format!(
                    "{} in '{repo}' is now {}.",
                    name_at(entry),
                    status_of(entry)
                )
            },
            global,
        ),
        None => {
            let answer = reply.json().unwrap_or_default();
            let changed: Vec<String> = answer["servers"]
                .as_array()
                .map(|s| s.iter().map(name_at).collect())
                .unwrap_or_default();
            if matches!(global.format, OutputFormat::Quiet) {
                for id in &changed {
                    println!("{id}");
                }
                return Ok(());
            }
            let human = format!(
                "{} version(s) of {server} in '{repo}' are now {status}: {}",
                text(&answer["updatedCount"]),
                if changed.is_empty() {
                    "-".to_string()
                } else {
                    changed.join(", ")
                }
            );
            emit_mutation_raw(Some(&reply.body), &answer, server, &human, global);
        }
    }
    Ok(())
}

async fn delete(
    repo: &str,
    server: &str,
    version: &str,
    message: Option<String>,
    yes: bool,
    global: &GlobalArgs,
) -> Result<()> {
    check_path_parts(server, Some(version))?;
    if !confirm_action(
        &format!(
            "Delete {server}@{version} in '{repo}'? It stops being served, and the version \
             number can't be published again."
        ),
        yes,
        global.no_input,
    )? {
        return Ok(());
    }
    let wire = Wire::new(global)?;
    let url = wire.url(&segments(repo, server, Some(version), &[]));
    let mut request = wire.request(Method::DELETE, url);
    if let Some(message) = &message {
        request = request.json(&json!({ "statusMessage": message }));
    }
    let spinner = output::spinner("Deleting the version...");
    let reply = send("delete the version", "mcp version delete", global, request).await?;
    spinner.finish_and_clear();
    emit_entry(
        &reply,
        &format!("{server}@{version}"),
        |entry| {
            format!(
                "Deleted {} in '{repo}'. `ak mcp version purge` removes it for good.",
                name_at(entry)
            )
        },
        global,
    );
    Ok(())
}

/// What a purge says it trashed and released, for a person.
fn purge_human(answer: &Value, repo: &str) -> String {
    let trashed = answer["trashed"].as_array().map_or(0, Vec::len);
    let mut out = vec![format!(
        "Purged {}@{} from '{repo}': {trashed} file(s) moved to the trash. The version number \
         stays taken.",
        text(&answer["server"]),
        text(&answer["version"])
    )];
    for digest in answer["releasedDigests"].as_array().into_iter().flatten() {
        if digest["still_pinned"].as_bool() == Some(true) {
            out.push(format!(
                "Note: {}@{} is still pinned by another version, so it stays.",
                text(&digest["image"]),
                text(&digest["digest"])
            ));
        }
    }
    out.join("\n")
}

async fn purge(
    repo: &str,
    server: &str,
    version: &str,
    yes: bool,
    global: &GlobalArgs,
) -> Result<()> {
    check_path_parts(server, Some(version))?;
    if !confirm_action(
        &format!(
            "Purge {server}@{version} from '{repo}' for good? Its server.json and bundles go \
             to the trash, and what it pins is released."
        ),
        yes,
        global.no_input,
    )? {
        return Ok(());
    }
    let wire = Wire::new(global)?;
    let url = wire.url(&segments(repo, server, Some(version), &["purge"]));
    let spinner = output::spinner("Purging the version...");
    let reply = send(
        "purge the version",
        "mcp version purge",
        global,
        wire.request(Method::POST, url),
    )
    .await?;
    spinner.finish_and_clear();
    let answer = reply.json().unwrap_or_default();
    emit_mutation_raw(
        Some(&reply.body),
        &answer,
        &format!("{server}@{version}"),
        &purge_human(&answer, repo),
        global,
    );
    Ok(())
}

/// The `name` and `version` of a server.json, which pick the route.
fn identity(document: &[u8]) -> Result<(String, String)> {
    let doc: Value = serde_json::from_slice(document)
        .map_err(|e| AkError::Usage(format!("--document isn't JSON: {e}")))?;
    let field = |key: &str| {
        doc[key]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| AkError::Usage(format!("--document has no \"{key}\" string")))
    };
    Ok((field("name")?, field("version")?))
}

async fn edit(repo: &str, document: &str, global: &GlobalArgs) -> Result<()> {
    let bytes = read_inline_or_file(document, "--document")?;
    let (server, version) = identity(&bytes)?;
    check_path_parts(&server, Some(&version))?;
    let wire = Wire::new(global)?;
    let url = wire.url(&segments(repo, &server, Some(&version), &[]));
    let request = wire
        .request(Method::PUT, url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(bytes);
    let spinner = output::spinner("Replacing the document...");
    let reply = send("edit the version", "mcp version edit", global, request).await?;
    spinner.finish_and_clear();
    emit_entry(
        &reply,
        &format!("{server}@{version}"),
        |entry| format!("Replaced the document of {} in '{repo}'.", name_at(entry)),
        global,
    );
    Ok(())
}

fn probe_detail(answer: &Value, what: &str) -> String {
    let queued = answer["queued"].as_array().map_or(0, Vec::len);
    let mut out = vec![if queued == 0 {
        format!("No new job queued for {what}.")
    } else {
        format!("Queued {queued} introspection job(s) for {what}.")
    }];
    if let Some(jobs) = answer["jobs"].as_array().filter(|j| !j.is_empty()) {
        let mut table = new_table(vec!["JOB", "KIND", "TARGET", "STATUS", "ATTEMPTS"]);
        for j in jobs {
            table.add_row(vec![
                text(&j["id"]),
                text(&j["kind"]),
                text(&j["target"]),
                text(&j["status"]),
                format!("{}/{}", text(&j["attempts"]), text(&j["maxAttempts"])),
            ]);
        }
        out.push(table.to_string());
    }
    out.join("\n")
}

async fn probe(repo: &str, server: &str, version: &str, global: &GlobalArgs) -> Result<()> {
    check_path_parts(server, Some(version))?;
    let wire = Wire::new(global)?;
    let url = wire.url(&segments(
        repo,
        server,
        Some(version),
        &["capabilities", "probe"],
    ));
    let spinner = output::spinner("Requesting a probe...");
    let reply = send(
        "request a probe",
        "mcp version probe",
        global,
        wire.request(Method::POST, url),
    )
    .await?;
    spinner.finish_and_clear();
    let answer = reply.json().unwrap_or_default();
    if matches!(global.format, OutputFormat::Quiet) {
        for id in answer["queued"].as_array().into_iter().flatten() {
            println!("{}", text(id));
        }
        return Ok(());
    }
    let what = format!("{server}@{version}");
    println!(
        "{}",
        output::render_raw(
            Some(&reply.body),
            &answer,
            &global.format,
            Some(probe_detail(&answer, &what))
        )
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_with_one_slash_goes_as_two_segments() {
        assert_eq!(
            segments("r", "io.github.acme/weather", Some("1.0.0"), &["purge"]),
            vec![
                "mcp",
                "r",
                "v0.1",
                "servers",
                "io.github.acme",
                "weather",
                "versions",
                "1.0.0",
                "purge"
            ]
        );
        assert_eq!(
            segments("r", "a/b/c", None, &["status"]),
            vec!["mcp", "r", "v0.1", "servers", "a/b/c", "status"]
        );
    }

    #[test]
    fn the_document_names_the_version() {
        let (name, version) =
            identity(br#"{"name":"io.github.acme/weather","version":"1.2.0"}"#).expect("ok");
        assert_eq!(
            (name.as_str(), version.as_str()),
            ("io.github.acme/weather", "1.2.0")
        );
        assert!(identity(br#"{"name":"x"}"#).is_err());
        assert!(identity(b"not json").is_err());
    }

    #[test]
    fn a_purge_says_what_is_still_pinned() {
        let answer = json!({
            "server": "io.github.acme/weather", "version": "1.0.0", "purged": true,
            "trashed": ["a", "b"],
            "releasedDigests": [
                {"image": "acme/weather", "digest": "sha256:aa", "still_pinned": true},
                {"image": "acme/weather", "digest": "sha256:bb", "still_pinned": false}
            ]
        });
        let human = purge_human(&answer, "r");
        assert!(human.contains("2 file(s) moved to the trash"), "{human}");
        assert!(human.contains("sha256:aa is still pinned"), "{human}");
        assert!(!human.contains("sha256:bb"), "{human}");
    }

    #[test]
    fn a_registry_refusal_shows_its_explanation() {
        let body = br#"{"type":"about:blank","title":"Conflict","status":409,
            "detail":"Only a deleted server version can be purged","error":"mcp_version_not_deleted"}"#;
        let message: Value = serde_json::from_str(&problem_message(body).expect("mapped")).unwrap();
        assert_eq!(
            message["message"],
            "mcp_version_not_deleted: Only a deleted server version can be purged"
        );
        let not_found = br#"{"detail":"Server not found","status":404,"title":"Not Found"}"#;
        let message: Value =
            serde_json::from_str(&problem_message(not_found).expect("mapped")).unwrap();
        assert_eq!(message["message"], "Server not found");
        assert!(problem_message(br#"{"message":"m","detail":"d"}"#).is_none());
        assert!(problem_message(br#"{"error":"x"}"#).is_none());
        assert!(problem_message(b"plain").is_none());
    }

    #[test]
    fn a_probe_with_nothing_new_says_so() {
        let answer = json!({"queued": [], "jobs": [
            {"id": "j1", "kind": "remote_probe", "target": "https://x", "status": "pending",
             "attempts": 0, "maxAttempts": 3}
        ]});
        let detail = probe_detail(&answer, "a/b@1");
        assert!(
            detail.starts_with("No new job queued for a/b@1."),
            "{detail}"
        );
        assert!(detail.contains("remote_probe"), "{detail}");
    }
}
